import assert from "node:assert/strict";
import { createHash, createHmac } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";

const isolation = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const production = "https://subs-bot.lilyya.top";
const untrusted = "https://request-host.example.invalid";
const policy = { botId: "75601", adminId: "75602", memberId: "75603", groupId: "-10075604",
  botUsername: "OriginFixtureBot", botToken: "75601:synthetic-token", webhookSecret: "synthetic-origin-webhook-secret" };
const actor = { id: Number(policy.adminId), is_bot: false };
const chat = { id: actor.id, type: "private" };
const aggregateKey = Buffer.alloc(32, 0x74);
const share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Origin";
const digest = (bytes: Uint8Array | string) => createHash("sha256").update(bytes).digest("hex");

type Send = {
  id: number;
  text: string;
  replyTo: number;
  buttons: { text: string; callback_data: string }[];
};

test("emitted Worker changes only the configured public host and retains existing capability bytes", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8")) as {
    revision: string; compatibilityDate: string; bundleSha256: string; migrations: { name: string; sha256: string }[];
  };
  const script = await readFile(join(directory, "index.js"));
  assert.equal(digest(script), manifest.bundleSha256);
  const sends: Send[] = [];
  const fixture = {
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "public-origin-fixture" }, r2Buckets: { NODES: "public-origin-fixture" },
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
      TELEGRAM_AGGREGATE_KEY: aggregateKey.toString("base64url"),
      TELEGRAM_PRIVATE_SHARE_CREATION_KEY: Buffer.alloc(32, 0x75).toString("base64url") },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage");
      const body = await request.json() as {
        chat_id: string; text: string; reply_parameters: { message_id: number };
        reply_markup?: { inline_keyboard?: Send["buttons"][] }; link_preview_options: unknown;
      };
      assert.equal(body.chat_id, policy.adminId);
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.ok(!body.text.includes(untrusted));
      const replyTo = body.reply_parameters.message_id;
      const first = !sends.some((send) => send.replyTo === replyTo);
      const id = 18_000 + sends.length;
      sends.push({ id, replyTo, text: body.text, buttons: body.reply_markup?.inline_keyboard?.flat() ?? [] });
      if (replyTo === 3 && first) {
        return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 30 } }, { status: 429 });
      }
      return Response.json({ ok: true, result: { message_id: id, chat } });
    },
  };
  const runtime = new Miniflare({ workers: [
    { ...fixture, name: "isolation" },
    { ...fixture, name: "production", bindings: { ...fixture.bindings, PUBLIC_ORIGIN: production } },
    { ...fixture, name: "invalid", bindings: { ...fixture.bindings, PUBLIC_ORIGIN: production + "/" } },
  ] });
  t.after(() => runtime.dispose());
  const local = await runtime.getWorker("isolation");
  const configured = await runtime.getWorker("production");
  const invalid = await runtime.getWorker("invalid");
  const db = await runtime.getD1Database("DB", "isolation");
  const bucket = await runtime.getR2Bucket("NODES", "isolation");
  await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
  for (const [index, migration] of manifest.migrations.entries()) {
    const sql = await readFile(join(directory, migration.name));
    assert.equal(digest(sql), migration.sha256);
    await db.batch(sql.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')")
      .bind(index + 1, migration.name, migration.sha256).run();
  }
  const sub = await createSubscription(db, { ownerId: policy.adminId, name: "Origin fixture", sourceUrl: "uploaded://origin-fixture" });
  assert.equal(await publishNodeSnapshot(db, bucket, { id: sub.id, ownerId: policy.adminId, expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ name: "Origin node", type: "temp", share }]), true);

  const now = () => Math.floor(Date.now() / 1000);
  function post(worker: typeof local, update: unknown) {
    return worker.fetch(untrusted + "/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update) });
  }
  function message(worker: typeof local, id: number, text: string) {
    const command = /^\/[^ ]+/u.exec(text)?.[0];
    return post(worker, { update_id: id, message: { message_id: id, date: now(), from: actor, chat, text,
      ...(command ? { entities: [{ type: "bot_command", offset: 0, length: command.length }] } : {}) } });
  }
  async function reply(updateId: number, state = "sent") {
    for (let poll = 0; poll < 80; poll++) {
      const row = await db.prepare(`SELECT state,sent_message_id AS sentMessageId
        FROM telegram_inbox JOIN telegram_outbox USING(receipt_id) WHERE bot_id=? AND update_id=?`)
        .bind(policy.botId, updateId).first<{ state: string; sentMessageId: number | null }>();
      const send = row?.state === state ? sends.find((entry) =>
        state === "sent" ? entry.id === row.sentMessageId : entry.replyTo === updateId) : undefined;
      if (send) return send;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Expected an exact settled origin fixture reply.");
  }
  const links = (send: Send) => send.text.split("\n").filter((line) => line.startsWith("https://")).map((line) => new URL(line));
  const link = (send: Send) => links(send)[0];

  assert.equal((await message(local, 1, "/export")).status, 200);
  const priorAggregate = links(await reply(1));
  const nonce = await db.prepare("SELECT nonce FROM telegram_aggregate_slots WHERE bot_id=? AND actor_id=?")
    .bind(policy.botId, policy.adminId).first<string>("nonce");
  assert.ok(nonce);
  const code = createHmac("sha256", aggregateKey).update(JSON.stringify([
    "subs-bot/telegram-aggregate/all", 1, isolation, policy.botId, policy.adminId, nonce,
  ])).digest().subarray(0, 16).toString("base64url");
  const aggregatePaths = [`/agg/${code}/clash`, `/agg/${code}/base64`];
  assert.deepEqual(priorAggregate.map(({ href }) => href), aggregatePaths.map((path) => isolation + path));
  assert.equal((await message(configured, 2, "/export")).status, 200);
  const newAggregate = links(await reply(2));
  assert.deepEqual(newAggregate.map(({ href }) => href), aggregatePaths.map((path) => production + path));
  const encoded = await configured.fetch(untrusted + newAggregate[1].pathname);
  assert.equal(encoded.status, 200);
  assert.equal(await encoded.text(), Buffer.from(share).toString("base64"));

  assert.equal((await message(local, 3, "/short https://example.com/origin-fixture")).status, 200);
  const beforeRetry = link(await reply(3, "pending"));
  assert.equal(beforeRetry.origin, isolation);
  await db.prepare(`UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id IN
    (SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=3)`).bind(policy.botId).run();
  assert.equal((await invalid.fetch(untrusted + "/health")).status, 503);
  assert.equal((await message(invalid, 4, "/export")).status, 503);
  assert.equal((await invalid.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(sends.filter(({ replyTo }) => replyTo === 3).length, 1);
  assert.equal(await db.prepare("SELECT 1 FROM telegram_inbox WHERE bot_id=? AND update_id=4").bind(policy.botId).first(), null);
  assert.equal((await configured.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const afterRetry = link(await reply(3));
  assert.equal(afterRetry.origin, production);
  assert.equal(afterRetry.pathname, beforeRetry.pathname);
  assert.equal((await configured.fetch(untrusted + afterRetry.pathname, { redirect: "manual" })).headers.get("Location"),
    "https://example.com/origin-fixture");

  assert.equal((await message(configured, 5, "/o Origin fixture")).status, 200);
  const selected = link(await reply(5));
  assert.equal(selected.origin, production);
  const selection = await db.prepare(`SELECT owner.nonce,link.selected_ids AS ids FROM telegram_selected_links AS owner
    JOIN aggregate_links AS link USING(code_sha256) WHERE owner.bot_id=? AND owner.actor_id=?`)
    .bind(policy.botId, policy.adminId).first<{ nonce: string; ids: string }>();
  assert.ok(selection);
  const selectedCode = createHmac("sha256", aggregateKey).update(JSON.stringify([
    "subs-bot/telegram-aggregate/selected", 1, isolation, policy.botId, policy.adminId, selection.nonce, selection.ids,
  ])).digest().subarray(0, 16).toString("base64url");
  assert.equal(selected.pathname, `/agg/${selectedCode}/clash`);

  assert.equal((await message(configured, 6, "1")).status, 200);
  const detail = await reply(6);
  const ticket = detail.buttons.find(({ text }) => text === "Clash Meta")?.callback_data;
  assert.ok(ticket);
  assert.equal((await post(configured, { update_id: 7, callback_query: {
    id: "origin-format-7", from: actor, data: ticket,
    message: { message_id: detail.id, date: now(), from: { id: Number(policy.botId), is_bot: true }, chat },
  } })).status, 200);
  assert.equal(link(await reply(7)).href, `${production}/sub/${sub.token}/clash`);

  assert.equal((await message(configured, 8, `/share sub ${sub.id}`)).status, 200);
  assert.equal(link(await reply(8)).hostname, "t.me");
  const payloadId = await db.prepare("SELECT payload_id FROM private_shares WHERE sender_id=?").bind(policy.adminId).first<string>("payload_id");
  assert.ok(payloadId);
  const payload = await bucket.get(`private-shares/${payloadId}.txt`);
  assert.ok(payload);
  assert.ok((await payload.text()).split("\n").includes(`⚡ Clash 配置：${production}/sub/${sub.token}/clash`));

  const clashOnly = await createSubscription(db, { ownerId: policy.adminId, name: "Clash-only fixture", sourceUrl: "uploaded://origin-clash-only" });
  assert.equal(await publishNodeSnapshot(db, bucket, { id: clashOnly.id, ownerId: policy.adminId, expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ name: "Synthetic SOCKS", type: "socks5", server: "203.0.113.11", port: 1080 }]), true);
  assert.equal((await message(configured, 9, "/export")).status, 200);
  const fallback = await reply(9);
  assert.deepEqual(links(fallback).map(({ href }) => href), [newAggregate[0].href]);
  assert.match(fallback.text, /Base64：订阅内容不支持此格式。/u);
  assert.equal((await configured.fetch(untrusted + newAggregate[0].pathname)).status, 200);
  assert.equal((await configured.fetch(untrusted + newAggregate[1].pathname)).status, 422);
});

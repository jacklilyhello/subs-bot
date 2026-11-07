import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { parseTelegramAggregateKey } from "../src/telegram/aggregate-actions.ts";
import { acceptTelegramShortLink, confirmTelegramShortLinkSend, prepareTelegramShortLinkReply } from "../src/telegram/short-link-actions.ts";
import { beginTelegramShortLinkReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "75301", botUsername: "fixture_short_bot", adminId: "75302", memberId: "75303", groupId: "-10075304",
  botToken: "75301:synthetic-token", webhookSecret: "synthetic-short-link-webhook",
};
const key = Buffer.alloc(32, 0x57).toString("base64url");
const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const destination = "https://example.com/a%20b?cap=synthetic-destination-secret#example";
const legacyAggregate = "LegacyAgg_12";
const legacyExternal = "LegacyHttp12";
const sha256 = (input: string) => createHash("sha256").update(input).digest("hex");
type Send = { id: number; chat: string; replyTo: number; text: string };

test("emitted Worker issues, retries and revokes owned short links without overlapping aggregates", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sends: Send[] = [];
  let retryId = -1;
  let uncertainId = -1;
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_AGGREGATE_KEY: key },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      const body = await request.json() as {
        chat_id: string; text: string; reply_parameters: { message_id: number }; link_preview_options?: unknown;
      };
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.doesNotMatch(body.text, /synthetic-destination-secret|synthetic-password/u);
      assert.ok([policy.adminId, policy.memberId].includes(body.chat_id));
      const replyTo = body.reply_parameters.message_id;
      const prior = sends.filter((item) => item.replyTo === replyTo).length;
      const reply = { id: 1000 + sends.length, chat: body.chat_id, replyTo, text: body.text };
      sends.push(reply);
      if (replyTo === retryId && prior === 0) {
        return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 1 } }, { status: 429 });
      }
      if (replyTo === uncertainId) return Response.json({ ok: false, error_code: 500 }, { status: 500 });
      return Response.json({ ok: true, result: { message_id: reply.id, chat: { id: Number(reply.chat) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    async function apply(migration: { name: string; sha256: string }) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(createHash("sha256").update(bytes).digest("hex"), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    const migration = manifest.migrations.find((item: { name: string }) => item.name === "0019_telegram_short_links.sql");
    assert.ok(migration);
    for (const entry of manifest.migrations) if (entry !== migration) await apply(entry);
    let sequence = 0;
    const now = () => Math.floor(Date.now() / 1000);
    const event = (id: number, text: string, actor = policy.memberId, chat = actor) => ({
      update_id: id, message: {
        message_id: id, date: now(), from: { id: Number(actor), is_bot: false },
        chat: { id: Number(chat), type: chat === policy.groupId ? "supergroup" : "private" }, text,
        entities: text.startsWith("/") ? [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] : [],
      },
    });
    const post = (update: unknown) => runtime.dispatchFetch("https://worker.example.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update),
    });
    const outbox = (id: number) => db.prepare(`SELECT outbox.state FROM telegram_outbox AS outbox
      JOIN telegram_inbox AS inbox USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
      .bind(policy.botId, id).first<string>("state");
    async function waitForSend(id: number, state = "sent", attempt = 1): Promise<Send> {
      for (let i = 0; i < 50; i++) {
        const reply = sends.filter(({ replyTo }) => replyTo === id)[attempt - 1];
        if (reply && await outbox(id) === state) return reply;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Synthetic short link reply did not settle.");
    }
    async function send(text: string, actor = policy.memberId) {
      const update = event(++sequence, text, actor);
      assert.equal((await post(update)).status, 200);
      return { update, reply: await waitForSend(update.update_id) };
    }
    const request = (path: string, method = "GET") => runtime.dispatchFetch("https://worker.example.invalid" + path,
      { method, redirect: "manual" });
    async function checkRoute(path: string, expected: string | null) {
      for (const method of ["GET", "HEAD"]) {
        const response = await request(path, method);
        assert.equal(response.status, expected ? 302 : 404);
        assert.equal(response.headers.get("Location"), expected);
        assert.equal(response.headers.get("Cache-Control"), "private, no-store");
        assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
        assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
        assert.equal(await response.text(), expected || method === "HEAD" ? "" : "Not found.");
      }
    }
    const codeOf = (reply: Send) => {
      const code = reply.text.match(/\/s\/([A-Za-z0-9_-]{21}s)$/u)?.[1];
      assert.ok(code);
      return code;
    };
    const addLegacy = (code: string, url: string) => db.prepare(`INSERT INTO normal_short_links(code_sha256,code_length,bot_id,owner_id,target_url)
      VALUES (?,12,?,?,?)`).bind(sha256(code), policy.botId, policy.memberId, url).run();

    const sub = await createSubscription(db, { ownerId: policy.memberId, name: "Synthetic", sourceUrl: "https://example.com/list" });
    const uri = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Synthetic";
    assert.equal(await publishNodeSnapshot(db, bucket, { id: sub.id, ownerId: policy.memberId, expectedGeneration: 0,
      expectedLifecycleRevision: 0 }, [{ name: "Synthetic", type: "ss", share: uri }]), true);
    await db.prepare(`INSERT INTO aggregate_links(code_sha256,owner_id,kind,bot_id) VALUES (?,?,'all',?)`)
      .bind(sha256(legacyAggregate), policy.memberId, policy.botId).run();
    await checkRoute("/s/" + legacyAggregate, `/agg/${legacyAggregate}/clash`);
    assert.equal((await post(event(++sequence, "/short"))).status, 204);
    assert.equal(await outbox(sequence), null);
    await apply(migration);
    await checkRoute("/s/" + legacyAggregate, `/agg/${legacyAggregate}/clash`);
    assert.equal(await (await request(`/agg/${legacyAggregate}/base64`)).text(), Buffer.from(uri).toString("base64"));
    const help = await send("/short");
    assert.match(help.reply.text, /\/short revoke/u);
    const groupId = ++sequence;
    assert.equal((await post(event(groupId, "短链 " + destination, policy.memberId, policy.groupId))).status, 204);
    assert.equal(await outbox(groupId), null);
    const invalid = await send("/short https://synthetic-password@example.com/path");
    assert.match(invalid.reply.text, /无效/u);
    assert.equal(await db.prepare("SELECT count(*) AS count FROM normal_short_links").first("count"), 0);

    const first = await send("短链 " + destination.replace("https://example.com", "HTTPS://EXAMPLE.COM:443"));
    const code = codeOf(first.reply);
    const path = "/s/" + code;
    await checkRoute(path, destination);
    assert.equal((await request(`/agg/${code}/base64`)).status, 404);
    assert.equal((await post(first.update)).status, 200);
    assert.equal(sends.filter(({ replyTo }) => replyTo === first.update.update_id).length, 1);
    const own = await db.prepare("SELECT code_sha256,target_url,owner_id FROM normal_short_links").first();
    assert.deepEqual(own, { code_sha256: sha256(code), target_url: destination, owner_id: policy.memberId });

    const aggregate = await send("/export");
    const aggregateCode = aggregate.reply.text.match(/\/agg\/([A-Za-z0-9_-]{21}[AQgw])\/clash/u)?.[1];
    assert.ok(aggregateCode);
    await checkRoute("/s/" + aggregateCode, `/agg/${aggregateCode}/clash`);
    assert.equal((await send("/short revoke " + code, policy.adminId)).reply.text, "没有可撤销的短链。");
    await checkRoute(path, destination);
    const revoked = await send("/short revoke " + origin + path);
    assert.equal(revoked.reply.text, "短链已撤销。");
    assert.equal((await post(revoked.update)).status, 200);
    await checkRoute(path, null);
    assert.equal(await db.prepare("SELECT target_url FROM normal_short_links WHERE code_sha256=?").bind(sha256(code)).first("target_url"), null);

    retryId = ++sequence;
    assert.equal((await post(event(retryId, "ShOrT " + destination))).status, 200);
    const firstAttempt = await waitForSend(retryId, "pending");
    await db.prepare(`UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id IN (
      SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?)`).bind(policy.botId, retryId).run();
    const worker = await runtime.getWorker();
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    const retried = await waitForSend(retryId, "sent", 2);
    assert.equal(retried.text, firstAttempt.text);
    assert.notEqual(codeOf(retried), code);
    await checkRoute("/s/" + codeOf(retried), destination);

    uncertainId = ++sequence;
    const uncertain = event(uncertainId, "/short " + destination);
    assert.equal((await post(uncertain)).status, 200);
    const maybeSent = await waitForSend(uncertainId, "uncertain");
    assert.equal((await post(uncertain)).status, 200);
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.equal(sends.filter(({ replyTo }) => replyTo === uncertainId).length, 1);
    await checkRoute("/s/" + codeOf(maybeSent), destination);

    await addLegacy(legacyExternal, "http://example.org/legacy");
    await checkRoute("/s/" + legacyExternal, "http://example.org/legacy");
    assert.equal((await send("/short revoke " + legacyExternal)).reply.text, "短链已撤销。");
    await checkRoute("/s/" + legacyExternal, null);
    await addLegacy(legacyAggregate, destination);
    await checkRoute("/s/" + legacyAggregate, null);
    assert.equal((await request(`/agg/${legacyAggregate}/base64`)).status, 404);
    assert.equal((await send("/short revoke " + legacyAggregate)).reply.text, "短链已撤销。");
    await checkRoute("/s/" + legacyAggregate, null);
    assert.equal((await request(`/agg/${legacyAggregate}/base64`)).status, 404);
    await addLegacy("BadLegacy_12", "http://127.1/private");
    await checkRoute("/s/BadLegacy_12", null);

    const importedKey = await parseTelegramAggregateKey(key);
    assert.ok(importedKey);
    const intent = (args: string) => {
      const id = ++sequence;
      return { args, updateId: id, messageId: id, actorId: policy.memberId, chatId: policy.memberId,
        chatType: "private" as const, threadId: null, messageDate: now() };
    };
    assert.equal(await acceptTelegramShortLink(db, policy, intent(destination), importedKey), "accepted");
    const authLease = await claimTelegramReply(db, policy.botId, false, false, true);
    assert.ok(authLease?.shortLink);
    const authPrepared = await prepareTelegramShortLinkReply(db, policy, authLease, importedKey);
    assert.equal(authPrepared.kind, "link");
    if (authPrepared.kind !== "link") return;
    const authCode = codeOf({ id: 0, chat: policy.memberId, replyTo: 0, text: authPrepared.text });
    assert.equal(await beginTelegramShortLinkReply(db, policy, authLease, authPrepared.guard), true);
    await db.prepare("INSERT INTO telegram_auth(bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,1)")
      .bind(policy.botId, policy.memberId, now() - 1).run();
    assert.equal(await confirmTelegramShortLinkSend(db, policy, authLease, authPrepared.guard), false);
    await settleTelegramReply(db, policy, authLease, { kind: "failed" });
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    await checkRoute("/s/" + authCode, null);

    assert.equal(await acceptTelegramShortLink(db, policy, intent(destination), importedKey), "accepted");
    const lease = await claimTelegramReply(db, policy.botId, false, false, true);
    assert.ok(lease?.shortLink);
    const prepared = await prepareTelegramShortLinkReply(db, policy, lease, importedKey);
    assert.equal(prepared.kind, "link");
    if (prepared.kind !== "link") return;
    const unsent = codeOf({ id: 0, chat: policy.memberId, replyTo: 0, text: prepared.text });
    assert.equal(await beginTelegramShortLinkReply(db, policy, lease, prepared.guard), true);
    assert.equal(await acceptTelegramShortLink(db, policy, intent("revoke " + unsent), importedKey), "accepted");
    assert.equal(await confirmTelegramShortLinkSend(db, policy, lease, prepared.guard), false);
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    await checkRoute("/s/" + unsent, null);

    for (const table of ["telegram_inbox", "telegram_outbox", "telegram_short_link_actions"]) {
      const rows = await db.prepare(`SELECT * FROM ${table}`).all();
      const serialized = JSON.stringify(rows.results);
      assert.doesNotMatch(serialized, /https?:\/\/|synthetic-destination-secret|synthetic-password/u);
      for (const bearer of [code, codeOf(retried), codeOf(maybeSent), authCode, unsent]) assert.ok(!serialized.includes(bearer));
    }
  } finally {
    await runtime.dispose();
  }
});

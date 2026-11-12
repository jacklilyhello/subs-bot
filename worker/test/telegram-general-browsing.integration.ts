import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { PRODUCTION_PUBLIC_ORIGIN } from "../src/public-origin.ts";
import { parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { claimGeneralSharedTelegramReply, drainGeneralSharedTelegramReply } from "../src/telegram/general-auth-shared.ts";
import { acceptGeneralBrowsing, generalBrowsingGuard, GENERAL_RAW_FILE_MARKER } from "../src/telegram/general-browsing.ts";
import { confirmTelegramSubscriptionRawFileSend, prepareTelegramSubscriptionRawFile } from "../src/telegram/subscription-raw-file.ts";

type Wire = { chat_id: string; text: string; reply_parameters: { message_id: number };
  reply_markup?: { inline_keyboard?: { text: string; callback_data: string }[][] } };
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");

test("actual bundle general browsing keeps persisted origins, current authority and private payload fences", { timeout: 60_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8")) as {
    revision: string; compatibilityDate: string; bundleSha256: string; migrations: { name: string; sha256: string }[];
  };
  const script = await readFile(join(directory, "index.js"));
  assert.equal(digest(script), manifest.bundleSha256);
  const now = Math.floor(Date.now() / 1000), member = "97103", admin = "97102", group = "-10097104";
  const config = { botId: "97101", botUsername: "BrowsingFixtureBot", botToken: "97101:synthetic-browsing-token",
    webhookSecret: "synthetic-browsing-webhook", generation: 1, cutoverAt: now - 30, activationSha256: "c".repeat(64),
    outbox: "shared-private-management-formats-temp-node-document", subscriptionBrowsing: true };
  const pin = parseGeneralTelegramPin(JSON.stringify(config), manifest.revision);
  assert.ok(pin?.privateBrowsing && pin.privateFormats);
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...config, subscriptionBrowsing: false }), manifest.revision), null);
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...config, outbox: "shared" }), manifest.revision), null);
  const sent: { id: number; body: Wire; file?: string }[] = [];
  let retry = true, attempts = 0;
  const runtime = new Miniflare({ modules: true, script: script.toString(), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_GENERAL_CONFIG: JSON.stringify(config), PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN },
    outboundService: async (request: Request) => {
      const api = `https://api.telegram.org/bot${config.botToken}/`;
      assert.equal(request.method, "POST");
      if (request.url === api + "answerCallbackQuery") return Response.json({ ok: true, result: true });
      let body: Wire, file: string | undefined;
      if (request.url === api + "sendDocument") {
        const form = await request.formData(), payload = form.get("document");
        assert.ok(payload && typeof payload !== "string" && payload.name === "subscription-nodes.txt");
        body = { chat_id: String(form.get("chat_id")), text: String(form.get("caption")),
          reply_parameters: JSON.parse(String(form.get("reply_parameters"))) };
        file = await payload.text();
      } else {
        assert.equal(request.url, api + "sendMessage");
        body = await request.json() as Wire;
      }
      assert.ok([member, admin, group].includes(body.chat_id));
      if (body.reply_parameters.message_id === 1) {
        attempts++;
        if (retry) { retry = false; return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 1 } }, { status: 429 }); }
      }
      const id = 30_000 + sent.length;
      sent.push({ id, body, ...(file === undefined ? {} : { file }) });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB"), bucket = await runtime.getR2Bucket("NODES");
  for (const { name, sha256 } of manifest.migrations) {
    const sql = await readFile(join(directory, name), "utf8");
    assert.equal(digest(sql), sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  await db.batch(manifest.migrations.map(({ name, sha256 }, index) =>
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')").bind(index + 1, name, sha256)));
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES(?,?,?,?,?,1)").bind(pin.botId, 1, manifest.revision, pin.activationSha256, pin.cutoverAt),
    db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,1,?,'admin'),(?,?,?,1,?,'member')")
      .bind(pin.botId, 1, admin, pin.cutoverAt, pin.botId, 1, member, pin.cutoverAt),
    db.prepare("INSERT INTO telegram_general_groups VALUES(?,?,?,'group')").bind(pin.botId, 1, group),
  ]);
  const rows = [];
  for (let i = 1; i <= 10; i++) rows.push(await createSubscription(db, { ownerId: member, name: `Member ${i}`,
    sourceUrl: `https://private.fixture.invalid/sub/${i}?synthetic-key=hidden` }));
  await createSubscription(db, { ownerId: admin, name: "Admin own", sourceUrl: "https://private.fixture.invalid/admin" });
  const target = rows[9];
  const nodes = Array.from({ length: 16 }, (_, index) => ({ name: `Node ${index + 1}`,
    share: `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Node-${index + 1}` }));
  assert.equal(await publishNodeSnapshot(db, bucket, { id: target.id, ownerId: member,
    expectedGeneration: 0, expectedLifecycleRevision: 0 }, nodes), true);
  await db.prepare("UPDATE subscriptions SET expire_at=? WHERE id=?").bind(now + 86400, rows[0].id).run();
  const headers = { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret };
  const post = (update: object) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers, body: JSON.stringify(update),
  });
  const message = (id: number, text: string, actor = member, chat = actor) => post({ update_id: id, message: {
    message_id: id, date: now, from: { id: Number(actor), is_bot: false }, chat: { id: Number(chat), type: chat === group ? "group" : "private" },
    text, entities: text.startsWith("/") ? [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }] : [],
  } });
  const click = (id: number, card: { id: number; body: Wire }, token: string, actor = member, chat = card.body.chat_id, bot = pin.botId) => post({
    update_id: id, callback_query: { id: `fixture-${id}`, from: { id: Number(actor), is_bot: false }, data: token,
      message: { message_id: card.id, date: now, from: { id: Number(bot), is_bot: true },
        chat: { id: Number(chat), type: chat === group ? "group" : "private" } } },
  });
  const worker = await runtime.getWorker();
  const tick = async () => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const card = async (updateId: number) => {
    for (let i = 0; i < 80; i++) {
      const id = await db.prepare(`SELECT sent_message_id FROM telegram_inbox JOIN telegram_outbox USING(receipt_id)
        WHERE bot_id=? AND update_id=? AND state='sent'`).bind(pin.botId, updateId).first<number>("sent_message_id");
      const found = sent.find((item) => item.id === id);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    assert.fail(`Synthetic browsing reply was not sent for update ${updateId}.`);
  };
  const button = (value: { body: Wire }, text: string) => {
    const token = value.body.reply_markup?.inline_keyboard?.flat().find((item) => item.text === text)?.callback_data;
    assert.ok(token, `Missing synthetic button ${text}`); return token;
  };
  assert.equal((await message(1, "/list@BrowsingFixtureBot")).status, 200);
  for (let i = 0; i < 80; i++) {
    if (await db.prepare("SELECT 1 FROM telegram_inbox JOIN telegram_outbox USING(receipt_id) WHERE update_id=1 AND state='pending' AND attempts=1").first()) break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  await db.prepare("UPDATE telegram_outbox SET due_at=unixepoch() WHERE state='pending'").run();
  await tick();
  const first = await card(1), next = button(first, "下一页");
  assert.equal(attempts, 2);
  assert.equal((await message(1, "/list")).status, 204);
  assert.match(first.body.text, /1\. Member 1\n/u);
  assert.doesNotMatch(first.body.text, /Admin own|private\.fixture|hidden|\/sub\//u);
  assert.equal((await click(2, first, next, admin, admin)).status, 204);
  assert.equal((await click(3, first, next, member, member, "97199")).status, 204);
  assert.equal((await click(4, first, next)).status, 200);
  const second = await card(4);
  assert.match(second.body.text, /9\. Member 9\n10\. Member 10/u);
  assert.equal((await click(5, first, next)).status, 204);
  assert.equal((await click(6, second, button(second, "10 详情"), member, group)).status, 204);
  assert.equal((await click(7, second, button(second, "10 详情"))).status, 200);
  const detail = await card(7);
  assert.match(detail.body.text, /配置名称：Member 10/u);
  assert.equal((await message(8, "10")).status, 200);
  const numeric = await card(8);
  assert.match(numeric.body.text, /配置名称：Member 10/u);
  const anchor = await db.prepare(`SELECT inbox.receipt_nonce AS marker,anchor.kind,anchor.subscription_id AS id,
    EXISTS(SELECT 1 FROM telegram_subscription_read_ticket WHERE used_by_receipt_id=inbox.receipt_id) AS ticket
    FROM telegram_inbox AS inbox JOIN telegram_general_subscription_anchor AS anchor USING(receipt_id) WHERE update_id=8`).first();
  assert.deepEqual(anchor, { marker: "general-number-detail:v1", kind: "number", id: target.id, ticket: 0 });
  assert.equal((await click(9, numeric, button(numeric, "Clash Meta"))).status, 200);
  assert.match((await card(9)).body.text, /Clash/u);
  assert.equal((await click(10, detail, button(detail, "浏览节点"))).status, 200);
  const page1 = await card(10);
  assert.match(page1.body.text, /第 1\/2 页/u);
  assert.doesNotMatch(page1.body.text, /ss:\/\//u);
  assert.equal((await click(11, page1, button(page1, "下一页"))).status, 200);
  const page2 = await card(11);
  assert.match(page2.body.text, /第 2\/2 页/u);
  assert.equal((await click(12, page2, button(page2, "返回详情"))).status, 200);
  assert.match((await card(12)).body.text, /配置名称：Member 10/u);
  assert.equal((await click(13, numeric, button(numeric, "📦 导出节点"))).status, 200);
  const raw = await card(13);
  assert.equal(raw.body.chat_id, member);
  assert.equal(raw.file?.trim().split("\n").length, 16);
  assert.match(raw.file!, /^ss:\/\//u);
  assert.equal((await click(14, numeric, button(numeric, "📦 导出节点"))).status, 204);
  assert.equal((await message(15, "/list", admin)).status, 200);
  assert.equal((await card(15)).body.text, "你的订阅\n1. Admin own");
  assert.equal((await message(16, "/list", member, group)).status, 200);
  const group1 = await card(16);
  assert.deepEqual(group1.body.reply_markup?.inline_keyboard?.flat().map(({ text }) => text), ["下一页"]);
  assert.equal((await click(17, group1, button(group1, "下一页"))).status, 200);
  assert.match((await card(17)).body.text, /9\. Member 9/u);
  assert.equal((await message(18, "10", member, group)).status, 204);
  assert.equal((await message(19, "/expire")).status, 200);
  const expiry = await card(19);
  assert.ok(button(expiry, "1 重命名") && button(expiry, "1 删除"));
  assert.equal((await click(20, expiry, button(expiry, "1 删除"))).status, 200);
  assert.match((await card(20)).body.text, /删除/u);
  assert.equal((await message(21, "10")).status, 200);
  const fresh = await card(21);
  const fileToken = button(fresh, "📦 导出节点");
  const event = { updateId: 22, messageId: fresh.id, messageDate: now, actorId: member, chatId: member,
    chatType: "private" as const, threadId: null, callbackId: "fixture-22", ticket: fileToken };
  assert.equal(await acceptGeneralBrowsing(db, pin, { family: "file", event }), true);
  const lease = await claimGeneralSharedTelegramReply(db, pin);
  assert.ok(lease?.marker === GENERAL_RAW_FILE_MARKER);
  const typed = { ...lease, command: "help" as const, subscriptionRawFile: true as const };
  const prepared = await prepareTelegramSubscriptionRawFile(db, bucket, pin, typed, Date.now() + 5_000,
    generalBrowsingGuard(pin, GENERAL_RAW_FILE_MARKER));
  assert.equal(prepared?.kind, "document");
  await db.prepare("UPDATE telegram_outbox SET state='sending' WHERE receipt_id=?").bind(lease.receiptId).run();
  await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,2,?,'denied')").bind(pin.botId, 1, member, now - 1).run();
  assert.equal(await confirmTelegramSubscriptionRawFileSend(db, pin, typed, prepared!.guard), false, "revoke after preparation closes the final payload fence");
  assert.equal((await click(23, fresh, button(fresh, "浏览节点"))).status, 204);
  await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,3,?,'member')").bind(pin.botId, 1, member, now - 1).run();
  assert.equal((await click(24, fresh, button(fresh, "浏览节点"))).status, 204, "regrant does not revive old actor revisions");
  assert.equal(sent.filter(({ body }) => body.reply_parameters.message_id === 22).length, 0);
  await db.prepare("UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL WHERE receipt_id=?")
    .bind(lease.receiptId).run();
  assert.equal(await acceptGeneralBrowsing(db, pin, { family: "view", event: { kind: "list", updateId: 25, messageId: 25,
    messageDate: now, actorId: member, chatId: member, chatType: "private", threadId: null } }), true);
  await db.prepare(`CREATE TRIGGER ignore_general_view_anchors BEFORE INSERT ON telegram_general_subscription_anchor
    WHEN new.kind='view' BEGIN SELECT RAISE(IGNORE); END`).run();
  await assert.rejects(drainGeneralSharedTelegramReply(db, pin, bucket, PRODUCTION_PUBLIC_ORIGIN));
  assert.equal(await db.prepare(`SELECT state FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
    WHERE bot_id=? AND update_id=25`).bind(pin.botId).first("state"), "leased", "a short companion write rolls back begin");
  for (const table of ["telegram_general_subscription_anchor", "telegram_view_ticket", "telegram_subscription_read_ticket", "telegram_lifecycle_ticket"]) {
    const origin = table === "telegram_general_subscription_anchor" ? "receipt_id" : "origin_receipt_id";
    assert.equal(await db.prepare(`SELECT count(*) AS n FROM ${table} WHERE ${origin}=(
      SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=25)`).bind(pin.botId).first("n"), 0);
  }
  await db.prepare("DROP TRIGGER ignore_general_view_anchors").run();
  await db.prepare(`UPDATE telegram_outbox SET lease_until=unixepoch()-1 WHERE receipt_id=(
    SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=25)`).bind(pin.botId).run();
  await tick();
  assert.match((await card(25)).body.text, /1\. Member 1/u);
  await db.prepare(`UPDATE subs_bot_schema_migrations SET position=1054
    WHERE name='0054_telegram_general_subscription_anchors.sql'`).run();
  assert.equal((await message(26, "/list")).status, 204, "the exact browsing migration position is required");
  assert.equal((await message(27, "10")).status, 204, "numeric details must not queue without exact browsing evidence");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE bot_id=? AND update_id IN (26,27)")
    .bind(pin.botId).first("n"), 0);
});

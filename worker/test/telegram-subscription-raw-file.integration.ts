import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";

import { createSubscription, getSubscriptionSnapshot, publishNodeSnapshot } from "../src/storage.ts";
import { renameOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramSubscriptionRawFile, confirmTelegramSubscriptionRawFileSend,
  prepareTelegramSubscriptionRawFile } from "../src/telegram/subscription-raw-file.ts";
import { acceptTelegramCommand, beginTelegramReply, beginTelegramSubscriptionRawFileReply,
  claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";

const readinessFixture = `
  import worker from './index.js';
  function withRawFileReadinessFault(env) {
    const db = env.DB;
    return {...env, DB: {
      prepare(sql) {
        if (!sql.includes('sqlite_schema') || !sql.includes('telegram_subscription_raw_file_ticket')) return db.prepare(sql);
        return {async first() { throw new Error('Synthetic raw file readiness failure.'); }};
      },
      batch(statements) { return db.batch(statements); },
    }};
  }
  export default {
    fetch(request, env, ctx) { return worker.fetch(request, withRawFileReadinessFault(env), ctx); },
    scheduled(controller, env, ctx) { return worker.scheduled(controller, withRawFileReadinessFault(env), ctx); },
  };
`;

test("emitted Worker delivers the exact raw private file and fences its retries", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  const sha256 = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");
  assert.equal(sha256(script), manifest.bundleSha256);
  const policy: TelegramPolicy = {
    botId: "78401", botUsername: "FixtureRawFileBot", adminId: "78402", memberId: "78403", groupId: "-10078404",
    botToken: "78401:synthetic-token", webhookSecret: "synthetic-subscription-file-secret",
  };
  const ownerId = policy.memberId;
  type Sent = { id: number; replyTo: number; text?: string; file?: string; ticket?: string };
  const sent: Sent[] = [];
  let throttle = 0;
  let uncertain = 0;
  const common = {
    compatibilityDate: manifest.compatibilityDate, d1Databases: { DB: "raw-file-fixture" },
    r2Buckets: { NODES: "raw-file-fixture" },
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      assert.equal(request.method, "POST");
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      const id = 1000 + sent.length;
      if (request.url === api + "/sendDocument") {
        const form = await request.formData();
        const file = form.get("document");
        assert.ok(file && typeof file !== "string");
        assert.equal(file.name, "Base64.txt");
        assert.match(file.type, /^text\/plain(?:;\s*charset=utf-8)?$/iu);
        assert.equal(form.get("caption"), "📦 节点导出完成");
        assert.equal(form.get("chat_id"), ownerId);
        assert.equal(form.get("parse_mode"), null);
        assert.equal(form.get("message_thread_id"), null);
        const reply = JSON.parse(String(form.get("reply_parameters")));
        assert.equal(reply.allow_sending_without_reply, false);
        sent.push({ id, replyTo: reply.message_id, file: await file.text() });
        if (reply.message_id === throttle) {
          throttle = 0;
          return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 60 } }, { status: 429 });
        }
        if (reply.message_id === uncertain) return Response.json({ ok: false, error_code: 500 }, { status: 500 });
      } else {
        assert.equal(request.url, api + "/sendMessage");
        const body = await request.json() as { chat_id: string; text: string; reply_parameters: { message_id: number };
          reply_markup?: { inline_keyboard: { text: string; callback_data: string }[][] } };
        assert.equal(body.chat_id, ownerId);
        assert.doesNotMatch(body.text, /ss:\/\/|fixture-password|sbnf1_/u);
        sent.push({ id, replyTo: body.reply_parameters.message_id, text: body.text,
          ticket: body.reply_markup?.inline_keyboard.flat().find(({ text }) => text === "📦 导出节点")?.callback_data });
      }
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(ownerId) } } });
    },
  };
  const runtime = new Miniflare({ workers: [
    { ...common, name: "app", modules: true, script: script.toString("utf8") },
    { ...common, name: "readiness-fault", modules: [
      { type: "ESModule", path: "fixture.js", contents: readinessFixture },
      { type: "ESModule", path: "index.js", contents: script.toString("utf8") },
    ] },
  ] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB", "app");
  const bucket = await runtime.getR2Bucket("NODES", "app");
  const worker = await runtime.getWorker("app");
  const readinessFault = await runtime.getWorker("readiness-fault");
  const migrations = manifest.migrations as { name: string; sha256: string }[];
  const rawMigration = migrations.find(({ name }) => name === "0030_telegram_subscription_raw_file.sql");
  assert.ok(rawMigration);
  async function migrate(migration: (typeof migrations)[number]) {
    const sql = await readFile(join(directory!, migration.name), "utf8");
    assert.equal(sha256(sql), migration.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  for (const migration of migrations) if (migration !== rawMigration) await migrate(migration);

  const sourceUrl = "uploaded://synthetic.txt";
  const sub = await createSubscription(db, { ownerId, name: "Owned synthetic", sourceUrl });
  await createSubscription(db, { ownerId, name: "Unpublished synthetic", sourceUrl });
  const unsupported = await createSubscription(db, { ownerId, name: "Unsupported synthetic", sourceUrl });
  const target = { id: sub.id, ownerId, expectedLifecycleRevision: 0 };
  const auth = Buffer.from("aes-256-gcm:fixture-password").toString("base64url");
  const stored = `ss://${auth}@203.0.113.10:8388#原始🚀`;
  const nodes = [{ name: "Mapped raw", share: stored }, { name: "Mapped structured", type: "ss", server: "203.0.113.11",
    port: 8388, cipher: "aes-256-gcm", password: "fixture-password" }];
  const expected = `${stored}\nss://${auth}@203.0.113.11:8388#${encodeURIComponent("Mapped structured → 边缘")}`;
  assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 0 }, nodes), true);
  assert.equal(await publishNodeSnapshot(db, bucket, { ...target, id: unsupported.id, expectedGeneration: 0 },
    [nodes[0], { name: "Synthetic unsupported", type: "unsupported" }]), true);
  const addRule = (remark: string) => db.prepare("INSERT INTO path_rules (owner_id,keyword,remark) VALUES (?,'Mapped',?)")
    .bind(ownerId, remark).run();
  await addRule("边缘");
  const date = Math.floor(Date.now() / 1000);
  const post = (update: unknown, app = worker) => app.fetch("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify(update),
  });
  const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
  const event = (id: number, message: Sent, actor = ownerId, chatId = actor) => ({ update_id: id, callback_query: {
    id: `fixture-raw-file-${id}`, data: message.ticket, from: { id: Number(actor), is_bot: false }, message: {
      message_id: message.id, date, chat: chat(chatId), from: { id: Number(policy.botId), is_bot: true },
    },
  } });
  const state = (id: number) => db.prepare(`SELECT state,sent_message_id AS sentId,attempts FROM telegram_inbox
    JOIN telegram_outbox USING(receipt_id) WHERE bot_id=? AND update_id=?`).bind(policy.botId, id)
    .first<{ state: string; sentId: number | null; attempts: number }>();
  async function wait(id: number, desired = "sent", attempts?: number) {
    for (let attempt = 0; attempt < 60; attempt++) {
      const row = await state(id);
      if (row?.state === desired && (attempts === undefined || row.attempts === attempts)) return row;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.fail("Expected synthetic subscription file reply state was not reached.");
  }
  async function detail(id: number, position = "1", app = worker) {
    assert.equal((await post({ update_id: id, message: { message_id: id, date, chat: chat(ownerId), text: position,
      from: { id: Number(ownerId), is_bot: false } } }, app)).status, 200);
    const row = await wait(id);
    const message = sent.find(({ id: messageId }) => messageId === row.sentId);
    assert.ok(message);
    if (message.ticket) assert.match(message.ticket, /^sbnf1_[A-Za-z0-9_-]{21}[AQgw]$/u);
    return message;
  }
  const cron = async (app = worker) => assert.equal((await app.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const enqueueHelp = (id: number) => acceptTelegramCommand(db, policy, { updateId: id, messageId: id,
    messageDate: date, actorId: ownerId, chatId: ownerId, chatType: "private", threadId: null, command: "help" });
  const expectHelp = async (id: number) => {
    const row = await wait(id);
    assert.match(sent.find(({ id: sentId }) => sentId === row.sentId)?.text ?? "", /\/list/u);
  };
  const files = (replyTo: number) => sent.filter((item) => item.replyTo === replyTo && item.file !== undefined).map(({ file }) => file);

  assert.equal((await detail(1)).ticket, undefined);
  assert.equal((await post(event(2, { id: 1000, replyTo: 1, ticket: `sbnf1_${"A".repeat(22)}` }))).status, 204);
  await migrate(rawMigration);
  assert.equal((await detail(30, "1", readinessFault)).ticket, undefined);
  assert.equal((await post({ update_id: 31, message: { message_id: 31, date, chat: chat(ownerId), text: "/help",
    from: { id: Number(ownerId), is_bot: false }, entities: [{ type: "bot_command", offset: 0, length: 5 }] } },
  readinessFault)).status, 200);
  await expectHelp(31);
  assert.equal(await enqueueHelp(32), "accepted");
  await cron(readinessFault);
  await expectHelp(32);
  assert.equal((await detail(3, "2")).ticket, undefined);
  const retry = await detail(4);
  assert.ok(retry.ticket);
  assert.equal((await post(event(5, retry, policy.adminId))).status, 200);
  assert.equal((await post(event(6, retry, ownerId, policy.groupId))).status, 204);
  assert.equal((await post(event(7, { ...retry, id: retry.id + 1 }))).status, 200);
  for (const id of [5, 6, 7]) assert.equal(await state(id), null);
  throttle = retry.id;
  const responses = await Promise.all([post(event(8, retry)), post(event(9, retry))]);
  assert.ok(responses.every(({ status }) => status === 200));
  const one = await state(8);
  const two = await state(9);
  assert.notEqual(one === null, two === null);
  const accepted = one === null ? 9 : 8;
  await wait(accepted, "pending", 1);
  await cron();
  assert.deepEqual(files(retry.id), [expected]);
  await db.prepare(`UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id=(
    SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?)`).bind(policy.botId, accepted).run();
  await cron();
  assert.equal((await wait(accepted)).attempts, 2);
  assert.deepEqual(files(retry.id), [expected, expected]);
  assert.equal((await post(event(10, retry))).status, 200);
  assert.equal(await state(10), null);

  const unknown = await detail(11);
  uncertain = unknown.id;
  assert.equal((await post(event(12, unknown))).status, 200);
  await wait(12, "uncertain");
  assert.equal((await post(event(12, unknown))).status, 200);
  await cron();
  assert.deepEqual(files(unknown.id), [expected]);

  const bad = await detail(13, "3");
  assert.ok(bad.ticket);
  assert.equal((await post(event(14, bad))).status, 200);
  const unsupportedReply = await wait(14);
  assert.equal(sent.find(({ id }) => id === unsupportedReply.sentId)?.text, "部分节点或连接设置无法转换为此格式。");
  assert.deepEqual(files(bad.id), []);

  const pin = await detail(15);
  assert.ok(pin.ticket);
  assert.equal(await acceptTelegramSubscriptionRawFile(db, policy, { updateId: 16, actorId: ownerId, chatId: ownerId,
    chatType: "private", threadId: null, messageId: pin.id, messageDate: date, callbackId: "fixture-final-file", ticket: pin.ticket }), "accepted");
  const claimReply = (readiness: true | "unavailable") =>
    claimTelegramReply(db, policy.botId, false, false, true, true, true, true, undefined, false, false, undefined, readiness);
  assert.equal(await enqueueHelp(33), "accepted");
  const newer = await claimReply("unavailable");
  assert.equal(newer?.updateId, 33);
  assert.ok(newer);
  assert.equal(await beginTelegramReply(db, policy, newer, "allowed"), true);
  assert.equal(await claimReply(true), null);
  await settleTelegramReply(db, policy, newer, { kind: "failed" });
  const lease = await claimReply(true);
  assert.ok(lease?.subscriptionRawFile);
  const prepared = await prepareTelegramSubscriptionRawFile(db, bucket, policy, lease, Date.now() + 5000);
  assert.equal(prepared?.kind, "document");
  assert.ok(prepared);
  assert.equal(await beginTelegramSubscriptionRawFileReply(db, policy, lease, prepared.guard), true);
  assert.equal(await enqueueHelp(34), "accepted");
  await cron(readinessFault);
  assert.deepEqual(await state(34), { state: "pending", sentId: null, attempts: 0 });
  await db.prepare("DELETE FROM path_rules WHERE owner_id=?").bind(ownerId).run();
  await addRule("新路径");
  assert.equal(await confirmTelegramSubscriptionRawFileSend(db, policy, lease, prepared.guard), false);
  await settleTelegramReply(db, policy, lease, { kind: "failed" });
  await cron(readinessFault);
  await expectHelp(34);
  assert.deepEqual(files(pin.id), []);

  const staleAuth = await detail(17);
  assert.ok(staleAuth.ticket);
  await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,?)")
    .bind(policy.botId, ownerId, date - 1, 123).run();
  assert.equal((await post(event(18, staleAuth))).status, 200);
  assert.equal(await state(18), null);
  const staleLifecycle = await detail(19);
  assert.ok(staleLifecycle.ticket);
  assert.equal(await renameOwnedSubscription(db, target, "Renamed synthetic"), true);
  assert.equal((await post(event(20, staleLifecycle))).status, 200);
  assert.equal(await state(20), null);
  const staleSnapshot = await detail(21);
  assert.ok(staleSnapshot.ticket);
  assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 1, expectedLifecycleRevision: 1 }, nodes), true);
  assert.equal((await post(event(22, staleSnapshot))).status, 200);
  assert.equal(await state(22), null);

  const corrupt = await detail(23);
  const snapshot = await getSubscriptionSnapshot(db, sub.token);
  assert.ok(snapshot && corrupt.ticket);
  await bucket.put(`subscriptions/${sub.id}/${snapshot.snapshotId}/0.ndjson`, "corrupt");
  assert.equal((await post(event(24, corrupt))).status, 200);
  const corruptReply = await wait(24);
  assert.equal(sent.find(({ id }) => id === corruptReply.sentId)?.text, "暂时无法读取订阅节点。");
  assert.deepEqual(files(corrupt.id), []);
});

import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, test } from "node:test";
import { Miniflare } from "miniflare";
import { ISOLATION_PUBLIC_ORIGIN } from "../src/public-origin.ts";
import { fenceTelegramWebhookDatabase, readGeneralIsolationWindow } from "../src/telegram/general-isolation-window.ts";
import { acceptGeneralSharedTelegramCommand, drainGeneralSharedTelegramReply, recoverGeneralSharedTelegramReplies } from "../src/telegram/general-auth-shared.ts";
import { GENERAL_PAGE_JUMP_CALLBACK } from "../src/telegram/protocol.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const oldComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
Object.defineProperty(crypto.subtle, "timingSafeEqual", { configurable: true,
  value: (received: ArrayBuffer, expected: ArrayBuffer) => timingSafeEqual(new Uint8Array(received), new Uint8Array(expected)) });
after(() => {
  if (oldComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", oldComparison);
  else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
});

test("full-v1 is explicit, role scoped and atomically fenced across close and restore", async (t) => {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const bucket = await runtime.getR2Bucket("NODES");
  const directory = new URL("../migrations/", import.meta.url);
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  for (const name of (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
  const policy: TelegramPolicy = { botId: "8101", botUsername: "Synthetic_Test_Bot", adminId: "8102", memberId: "8103",
    groupId: "-8104", botToken: "8101:synthetic-token", webhookSecret: "synthetic-webhook-secret" };
  const revision = "a".repeat(40);
  const initial = await readGeneralIsolationWindow(db, policy, revision);
  assert.deepEqual(initial, { ready: true, epoch: null, mode: "isolated", pin: null });
  const oldIsolationRequest = fenceTelegramWebhookDatabase(db, policy.botId, initial);
  await db.prepare("CREATE TABLE synthetic_guard_changes(id INTEGER PRIMARY KEY,value INTEGER)").run();
  const changed = await oldIsolationRequest.batch([
    oldIsolationRequest.prepare("INSERT INTO synthetic_guard_changes VALUES(1,10)"),
    oldIsolationRequest.prepare("SELECT changes() AS changed"),
  ]);
  assert.equal(changed[0].meta.changes, 1);
  assert.deepEqual(changed[1].results, [{ changed: 1 }], "the leading SELECT fence preserves changes() semantics");
  const unchanged = await oldIsolationRequest.batch([
    oldIsolationRequest.prepare("UPDATE synthetic_guard_changes SET value=20 WHERE id=2"),
    oldIsolationRequest.prepare("SELECT changes() AS changed"),
  ]);
  assert.deepEqual(unchanged[1].results, [{ changed: 0 }]);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_read_lane(bot_id,epoch,mode) VALUES(?,1,'closed')").bind(policy.botId),
    db.prepare("INSERT INTO telegram_general_isolation_window VALUES(?,'full-v1',?,?,?,?,?,NULL,NULL)")
      .bind(policy.botId, revision, "b".repeat(64), policy.adminId, policy.memberId, policy.groupId),
  ]);
  const preserve = () => oldIsolationRequest.prepare("INSERT INTO path_rules(owner_id,keyword,remark) VALUES(?,'synthetic','synthetic')").bind(policy.memberId).run();
  await assert.rejects(preserve, "an isolation invocation admitted before close cannot commit afterward");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM path_rules").first("n"), 0);
  const closed = await readGeneralIsolationWindow(db, policy, revision);
  assert.equal(closed.mode, "closed");
  assert.equal(closed.pin, null);
  const now = Math.floor(Date.now() / 1000);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES(?,1,?,?,?,1)").bind(policy.botId, revision, "c".repeat(64), now - 10),
    db.prepare("INSERT INTO telegram_general_actors VALUES(?,1,?,1,?,'admin'),(?,1,?,1,?,'member')")
      .bind(policy.botId, policy.adminId, now - 10, policy.botId, policy.memberId, now - 10),
    db.prepare("INSERT INTO telegram_general_groups VALUES(?,1,?,'group')").bind(policy.botId, policy.groupId),
    db.prepare("UPDATE telegram_general_isolation_window SET generation=1,opened_epoch=2 WHERE bot_id=?").bind(policy.botId),
    db.prepare("UPDATE telegram_general_read_lane SET epoch=2,mode='general',generation=1 WHERE bot_id=?").bind(policy.botId),
  ]);
  const opened = await readGeneralIsolationWindow(db, policy, revision);
  assert.ok(opened.pin?.isolationWindow?.profile === "full-v1");
  assert.equal(opened.pin.rehearsal, undefined);
  assert.equal(opened.pin.privatePageJump, true);
  assert.ok(opened.pin.privateManagement && opened.pin.privateFormats && opened.pin.privateProvider && opened.pin.privateInline);
  const database = fenceTelegramWebhookDatabase(db, policy.botId, opened);
  const post = (actor: string, text: string, update: number) => new Request("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify({ update_id: update, message: { text, message_id: update, date: now,
      from: { id: Number(actor), is_bot: false }, chat: { id: Number(actor), type: "private" },
      entities: [{ type: "bot_command", offset: 0, length: text.split(" ")[0].length }] } }),
  });
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, post(policy.adminId, "/auth list", 1)), 200);
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, post(policy.memberId, "/auth list", 2)), 204);
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, post("8199", "/help", 3)), 204);
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, post(policy.adminId, "/auth add 8199", 4)), 204);
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, post(policy.memberId, "/help", 5)), 200);
  await db.prepare(`UPDATE telegram_outbox SET state='failed' WHERE state='pending' AND receipt_id IN (
    SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id IN (1,5))`).bind(policy.botId).run();
  const originalFetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = originalFetch; });
  const sent: Record<string, unknown>[] = [];
  let expectedMessage = 7;
  globalThis.fetch = async (input, init) => {
    const request = new Request(input, init);
    assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
    assert.equal(request.method, "POST");
    const body = await request.json() as Record<string, unknown>;
    assert.equal(body.chat_id, policy.adminId);
    assert.deepEqual(body.reply_parameters, { message_id: expectedMessage });
    sent.push(body);
    return Response.json({ ok: true, result: { message_id: 5000 + sent.length, chat: { id: Number(policy.adminId), type: "private" } } });
  };
  const helpPin = { ...opened.pin, commandFeatures: { authorizationScope: "general" as const, authorizationMemberId: "8199" } };
  assert.equal(await acceptGeneralSharedTelegramCommand(database, helpPin, post(policy.adminId, "/help", 7)), 200);
  assert.equal(await drainGeneralSharedTelegramReply(database, helpPin, bucket, ISOLATION_PUBLIC_ORIGIN), true);
  assert.equal(sent.length, 1);
  assert.equal(typeof sent[0].text, "string");
  const help = sent[0].text as string;
  assert.ok(help.includes(`/auth add ${policy.memberId} 授权固定测试用户`));
  assert.ok(help.includes(`/auth remove ${policy.memberId} 撤权固定测试用户`));
  assert.doesNotMatch(help, /新增或恢复授权|\/auth (?:add|remove) (?:用户ID|8199)/u);
  assert.equal(await db.prepare(`SELECT state FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
    WHERE bot_id=? AND update_id=7`).bind(policy.botId).first("state"), "sent");
  expectedMessage = 8;
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, post(policy.adminId, "/list", 8)), 200);
  assert.equal(await drainGeneralSharedTelegramReply(database, opened.pin, bucket, ISOLATION_PUBLIC_ORIGIN), true);
  assert.equal(sent.length, 2);
  const jump = new Request("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify({ update_id: 9, callback_query: { id: "full-window-jump", data: GENERAL_PAGE_JUMP_CALLBACK,
      from: { id: Number(policy.adminId), is_bot: false }, message: { message_id: 5002, date: now,
        from: { id: Number(policy.botId), is_bot: true }, chat: { id: Number(policy.adminId), type: "private" } } } }),
  });
  assert.equal(await acceptGeneralSharedTelegramCommand(database, opened.pin, jump), 200);
  await db.prepare("UPDATE telegram_general_read_lane SET epoch=3,mode='closed' WHERE bot_id=?").bind(policy.botId).run();
  await assert.rejects(acceptGeneralSharedTelegramCommand(database, opened.pin, post(policy.memberId, "/help", 6)));
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE update_id=6").first("n"), 0);
  assert.equal((await readGeneralIsolationWindow(db, policy, revision)).pin?.privateManagement, true,
    "the closed window keeps the same full runtime available to Cron for accepted work");
  const drainingClosed = await readGeneralIsolationWindow(db, policy, revision);
  assert.equal(drainingClosed.pin?.privatePageJump, false, "closed admission cannot send a new interactive prompt");
  assert.ok(drainingClosed.pin);
  await recoverGeneralSharedTelegramReplies(db, drainingClosed.pin, bucket, ISOLATION_PUBLIC_ORIGIN);
  assert.equal(await db.prepare(`SELECT state FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
    WHERE bot_id=? AND update_id=9`).bind(policy.botId).first("state"), "failed");
  assert.equal(sent.length, 2, "an unsent prompt is canceled rather than sent after close or held waiting for a reply");
  // Recovery is deliberately performed through the original binding, rather than the closed webhook facade.
  await db.prepare("UPDATE telegram_outbox SET state='failed' WHERE state='pending'").run();
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_outbox WHERE state='pending'").first("n"), 0);
  await db.batch([
    db.prepare("UPDATE telegram_general_policy SET active=0 WHERE bot_id=?").bind(policy.botId),
    db.prepare("DELETE FROM telegram_general_groups WHERE bot_id=?").bind(policy.botId),
    db.prepare("DELETE FROM telegram_general_isolation_window WHERE bot_id=?").bind(policy.botId),
    db.prepare("UPDATE telegram_general_read_lane SET epoch=4,mode='isolated',generation=NULL WHERE bot_id=?").bind(policy.botId),
  ]);
  assert.deepEqual(await readGeneralIsolationWindow(db, policy, revision), { ...initial, epoch: 4 });
  await assert.rejects(oldIsolationRequest.prepare("SELECT 1").first(), "the original isolation epoch cannot revive after restoration");
  await assert.rejects(database.prepare("SELECT 1").first(), "a stale full invocation stays fenced after restoration");
});

test("a registered full-v1 migration with a missing or replaced table fails closed", async (t) => {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const policy: TelegramPolicy = { botId: "8201", botUsername: "Synthetic_Test_Bot", adminId: "8202", memberId: "8203",
    groupId: "-8204", botToken: "8201:synthetic-token", webhookSecret: "synthetic-webhook-secret" };
  const revision = "a".repeat(40);
  assert.deepEqual(await readGeneralIsolationWindow(db, policy, revision), { ready: false, epoch: null, mode: "isolated", pin: null });
  const name = "0052_telegram_general_isolation_window.sql";
  const sql = await readFile(new URL(`../migrations/${name}`, import.meta.url), "utf8");
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(52,?,?,'applied')")
    .bind(name, createHash("sha256").update(sql).digest("hex")).run();
  await assert.rejects(readGeneralIsolationWindow(db, policy, revision), /could not be confirmed/u);
  await db.prepare("CREATE VIEW telegram_general_isolation_window AS SELECT 1 AS bot_id").run();
  await assert.rejects(readGeneralIsolationWindow(db, policy, revision), /could not be confirmed/u);
  await db.prepare("DROP VIEW telegram_general_isolation_window").run();
  await db.prepare("DELETE FROM subs_bot_schema_migrations").run();
  assert.deepEqual(await readGeneralIsolationWindow(db, policy, revision), { ready: false, epoch: null, mode: "isolated", pin: null });
});

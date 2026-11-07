import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { MAX_PATH_RULES, type PathRuleRow } from "../src/path-rules.ts";
import { sendTelegramReply } from "../src/telegram/delivery.ts";
import {
  acceptTelegramPath, parseTelegramPathArgs, renderTelegramPath, TELEGRAM_PATH_MARKER, type TelegramPathReply,
} from "../src/telegram/path-management.ts";
import type { TelegramPathUpdate, TelegramPolicy } from "../src/telegram/protocol.ts";
import { beginTelegramReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";

const miniflare = new Miniflare({
  modules: true, script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"],
});
let db: D1Database;

before(async () => {
  db = await miniflare.getD1Database("DB");
  const directory = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});
after(() => miniflare.dispose());

function policy(id: number): TelegramPolicy {
  return { botId: String(97000 + id), adminId: String(98000 + id), memberId: String(99000 + id),
    groupId: "-1001234567890", botUsername: "Synthetic_Path_Bot", webhookSecret: "synthetic-path-webhook-secret",
    botToken: `${97000 + id}:synthetic-path-token` };
}

async function now(): Promise<number> {
  const clock = await db.prepare("SELECT unixepoch() AS now").first<{ now: number }>();
  assert.ok(clock);
  return clock.now;
}

function event(config: TelegramPolicy, updateId: number, messageDate: number, args: string,
  overrides: Partial<TelegramPathUpdate> = {}): TelegramPathUpdate {
  return { kind: "path", args, updateId, messageDate, messageId: updateId, actorId: config.memberId, chatId: config.memberId,
    chatType: "private", threadId: null, ...overrides };
}

async function rules(ownerId: string) {
  return (await db.prepare("SELECT id, keyword, remark FROM path_rules WHERE owner_id = ? ORDER BY id")
    .bind(ownerId).all<PathRuleRow>()).results;
}

async function reply(config: TelegramPolicy, updateId: number) {
  return db.prepare(`SELECT inbox.receipt_nonce AS marker, outbox.state, reply.kind,
    reply.after_id AS afterId, reply.affected_count AS affectedCount FROM telegram_inbox AS inbox
    JOIN telegram_outbox AS outbox USING (receipt_id) JOIN telegram_path_reply AS reply USING (receipt_id)
    WHERE inbox.bot_id = ? AND inbox.update_id = ?`).bind(config.botId, updateId)
    .first<TelegramPathReply & { marker: string; state: string }>();
}

test("normalizes legacy forms and validates exact destructive commands and scalar bounds", () => {
  assert.deepEqual(parseTelegramPathArgs("\u0085港\u001c\u3000标签   一"), { kind: "upsert", keyword: "港", remark: "标签 一" });
  assert.deepEqual(parseTelegramPathArgs("north east = 边缘 节点"), { kind: "upsert", keyword: "north east", remark: "边缘 节点" });
  assert.deepEqual(parseTelegramPathArgs("HTTPS://example.invalid/?key=synthetic 标记"),
    { kind: "upsert", keyword: "HTTPS://example.invalid/?key=synthetic", remark: "标记" });
  assert.deepEqual(parseTelegramPathArgs("clear=marker"), { kind: "upsert", keyword: "clear", remark: "marker" });
  assert.deepEqual(parseTelegramPathArgs("\u0085"), { kind: "list", afterId: null });
  assert.deepEqual(parseTelegramPathArgs("list 42"), { kind: "list", afterId: 42 });
  assert.deepEqual(parseTelegramPathArgs("delete 42"), { kind: "delete", id: 42 });
  assert.deepEqual(parseTelegramPathArgs("clear"), { kind: "clear" });
  assert.equal(parseTelegramPathArgs(`${"🧪".repeat(128)} marker`).kind, "upsert");
  for (const invalid of ["clear extra", "delete +1", "delete 9007199254740992", "list 1e2", "list 01", "=x", "x=",
    "x\u202ey z", "x y\u0000", "x \ud800", `${"🧪".repeat(129)} marker`]) {
    assert.deepEqual(parseTelegramPathArgs(invalid), { kind: "usage" });
  }
});

test("deduplicates writes, keeps stable IDs and fences older changes and clear resurrection", async () => {
  const config = policy(1);
  const epoch = (await now()) - 5;
  const original = event(config, 1, epoch, "Straße=synthetic-private-remark", { messageId: 10 });
  assert.deepEqual((await Promise.all([acceptTelegramPath(db, config, original), acceptTelegramPath(db, config, original)])).sort(),
    ["accepted", "ignored"]);
  const [first] = await rules(config.memberId);
  const saved = await reply(config, 1);
  assert.deepEqual(saved, { marker: TELEGRAM_PATH_MARKER, kind: "saved", afterId: null, affectedCount: 1, state: "pending" });
  assert.doesNotMatch(JSON.stringify(saved), /Straße|synthetic-private-remark/u);
  assert.equal(await acceptTelegramPath(db, config, { ...original, args: "overwrite=replay" }), "ignored");
  assert.equal(await acceptTelegramPath(db, config, event(config, 2, epoch, "Straße=latest", { messageId: 12 })), "accepted");
  assert.deepEqual(await rules(config.memberId), [{ ...first, remark: "latest" }]);

  for (const [updateId, messageId, args] of [[3, 11, "clear"], [4, 10, "Straße=late"]] as const) {
    assert.equal(await acceptTelegramPath(db, config, event(config, updateId, epoch, args, { messageId })), "accepted");
    assert.equal((await reply(config, updateId))?.kind, "stale");
  }
  assert.equal(await acceptTelegramPath(db, config, event(config, 5, epoch, "clear", { messageId: 14 })), "accepted");
  assert.equal((await reply(config, 5))?.affectedCount, 1);
  assert.equal(await acceptTelegramPath(db, config, event(config, 6, epoch, "old=late", { messageId: 13 })), "accepted");
  assert.equal((await reply(config, 6))?.kind, "stale");
  assert.deepEqual(await rules(config.memberId), []);
});

test("enforces private ownership, time bounds and the latest authorization epoch", async () => {
  const config = policy(2);
  const epoch = await now();
  for (const invalid of [
    event(config, 1, epoch, "private=marker", { chatType: "group", chatId: config.groupId }),
    event(config, 2, epoch, "private=marker", { threadId: 1 }),
    event(config, 3, epoch, "private=marker", { actorId: "97112", chatId: "97112" }),
    event(config, 4, epoch, "private=marker", { chatId: config.adminId }),
  ]) {
    assert.equal(await acceptTelegramPath(db, config, invalid), "ignored");
    assert.equal(await reply(config, invalid.updateId), null);
  }
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 1)").bind(config.botId, config.memberId, epoch - 30).run();
  assert.equal(await acceptTelegramPath(db, config, event(config, 5, epoch - 20, "disabled=marker")), "ignored");
  await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=?,message_id=2 WHERE bot_id=? AND user_id=?")
    .bind(epoch - 10, config.botId, config.memberId).run();
  for (const [id, date] of [[6, epoch - 20], [7, epoch - 10], [8, epoch + 900], [9, epoch - 901]]) {
    assert.equal(await acceptTelegramPath(db, config, event(config, id, date, "stale=marker")), "accepted");
    assert.equal((await reply(config, id))?.kind, "stale");
  }
  await db.prepare("INSERT INTO path_rules (owner_id, keyword, remark) VALUES (?, 'foreign', 'protected')")
    .bind(config.adminId).run();
  const [foreign] = await rules(config.adminId);
  assert.equal(await acceptTelegramPath(db, config, event(config, 10, epoch - 5, `delete ${foreign.id}`)), "accepted");
  assert.equal((await reply(config, 10))?.kind, "missing");
  assert.deepEqual(await rules(config.adminId), [foreign]);
  assert.equal(await acceptTelegramPath(db, config, event(config, 11, epoch - 5, "mine=marker")), "accepted");
  assert.equal((await reply(config, 11))?.kind, "saved");
  const [mine] = await rules(config.memberId);
  assert.equal(await acceptTelegramPath(db, config, event(config, 12, epoch - 5, `delete ${mine.id}`)), "accepted");
  assert.equal((await reply(config, 12))?.kind, "deleted");
  assert.deepEqual(await rules(config.memberId), []);
});

test("keeps owner rule count bounded and pages private results without losing IDs", async () => {
  const config = policy(3);
  const epoch = await now();
  await db.prepare(`WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n < ?)
    INSERT INTO path_rules (owner_id, keyword, remark) SELECT ?, 'fixture-' || n, 'label' FROM seq`)
    .bind(MAX_PATH_RULES - 1, config.memberId).run();
  await Promise.all([1, 2].map((id) => acceptTelegramPath(db, config, event(config, id, epoch, `extra-${id}=fixture`))));
  const current = await rules(config.memberId);
  assert.equal(current.length, MAX_PATH_RULES);
  assert.equal(await acceptTelegramPath(db, config, event(config, 3, epoch, "extra-next=fixture")), "accepted");
  assert.equal((await reply(config, 3))?.kind, "capacity");
  assert.equal(await acceptTelegramPath(db, config, event(config, 4, epoch, "fixture-1=updated")), "accepted");
  const first = await renderTelegramPath(db, config.memberId, { kind: "list", afterId: null, affectedCount: 0 });
  assert.match(first, /fixture-1 → updated/u);
  assert.match(first, new RegExp(`下一页：/path list ${current[5].id}$`, "u"));
  const next = await renderTelegramPath(db, config.memberId, { kind: "list", afterId: current[5].id, affectedCount: 0 });
  assert.match(next, /fixture-7 → label/u);
  assert.doesNotMatch(next, /fixture-6 → label/u);
  assert.equal(await acceptTelegramPath(db, config, event(config, 5, epoch, "clear")), "accepted");
  assert.equal((await reply(config, 5))?.affectedCount, MAX_PATH_RULES);
  assert.deepEqual(await rules(config.memberId), []);
});

test("rolls back mutation, fence and receipt when outbox admission fails", async () => {
  const config = policy(4);
  const update = event(config, 1, await now(), "rule=synthetic-private-remark");
  await db.prepare(`CREATE TRIGGER reject_test_path_reply BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id = NEW.receipt_id AND bot_id = '${config.botId}')
    BEGIN SELECT RAISE(ABORT, 'synthetic-backend-detail'); END`).run();
  try {
    await assert.rejects(acceptTelegramPath(db, config, update), /Telegram path rule receipt could not be confirmed\./u);
    assert.deepEqual(await rules(config.memberId), []);
    assert.equal(await db.prepare("SELECT 1 FROM telegram_path_fence WHERE bot_id=?").bind(config.botId).first(), null);
    assert.equal(await db.prepare("SELECT 1 FROM telegram_inbox WHERE bot_id=?").bind(config.botId).first(), null);
  } finally {
    await db.prepare("DROP TRIGGER reject_test_path_reply").run();
  }
  assert.equal(await acceptTelegramPath(db, config, update), "accepted");
});

test("rechecks authorization at the durable send boundary and blocks a group destination", async () => {
  const config = policy(5);
  const epoch = await now();
  assert.equal(await acceptTelegramPath(db, config, event(config, 1, epoch, "")), "accepted");
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.path);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 1)").bind(config.botId, config.memberId, epoch).run();
  assert.equal(await beginTelegramReply(db, config, lease, "allowed"), false);
  assert.equal(await beginTelegramReply(db, config, lease, "denied"), true);
  const sent = await sendTelegramReply(config, lease, "当前账号没有使用权限。", 1000, async (_url, init) => {
    assert.deepEqual(JSON.parse(String(init?.body)), { chat_id: config.memberId, text: "当前账号没有使用权限。",
      reply_parameters: { message_id: 1, allow_sending_without_reply: true }, link_preview_options: { is_disabled: true } });
    return Response.json({ ok: true, result: { chat: { id: Number(config.memberId) }, message_id: 7 } });
  });
  await settleTelegramReply(db, config, lease, sent);
  assert.equal((await reply(config, 1))?.state, "sent");
  assert.deepEqual(await sendTelegramReply(config, { ...lease, chatType: "group", chatId: config.groupId }, "private", 1000,
    async () => assert.fail("An unexpected Bot API request escaped the private fence")), { kind: "failed" });
});

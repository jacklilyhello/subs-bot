import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import type { TelegramPolicy, TelegramTempUpdate } from "../src/telegram/protocol.ts";
import {
  acceptTelegramTemp, MAX_TEMP_BATCH_BYTES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, renderTelegramTemp,
  TELEGRAM_TEMP_MARKER, type TelegramTempReply,
} from "../src/telegram/temp-import.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
});
const migrationDir = new URL("../migrations/", import.meta.url);
const firstShare = "hy2://first.example.invalid#synthetic-first";
const secondShare = "ssr://synthetic-opaque-share#synthetic-second";
let db: D1Database;

before(async () => {
  db = await miniflare.getD1Database("DB");
  for (const name of (await readdir(migrationDir)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrationDir), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

after(() => miniflare.dispose());

function policy(botId: string): TelegramPolicy {
  return { botId, botUsername: "Synthetic_Temp_Bot", adminId: "87001", memberId: "87002", groupId: "-1001234567890",
    webhookSecret: "synthetic-webhook-secret", botToken: `${botId}:synthetic-token` };
}

function event(config: TelegramPolicy, updateId: number, messageId = updateId, actorId = config.memberId) {
  return { updateId, actorId, chatId: actorId, chatType: "private" as const, messageId,
    messageDate: 1_800_000_000, threadId: null };
}

function paste(config: TelegramPolicy, updateId: number, text = firstShare, messageId = updateId,
  actorId = config.memberId): TelegramTempUpdate {
  return { ...event(config, updateId, messageId, actorId), kind: "temp-text", text };
}

function submit(config: TelegramPolicy, update: TelegramTempUpdate) {
  return acceptTelegramTemp(db, config, update);
}

async function storedReply(config: TelegramPolicy, updateId: number) {
  return db.prepare(`
    SELECT inbox.receipt_nonce AS marker, outbox.state, reply.kind, reply.node_count AS nodeCount,
      reply.total_count AS totalCount, reply.malformed_count AS malformedCount,
      reply.unsupported_count AS unsupportedCount, reply.ignored_count AS ignoredCount
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS outbox USING (receipt_id)
    JOIN telegram_temp_reply AS reply USING (receipt_id) WHERE inbox.bot_id = ? AND inbox.update_id = ?
  `).bind(config.botId, updateId).first<TelegramTempReply & { marker: string; state: string }>();
}

async function totals(config: TelegramPolicy, actorId = config.memberId) {
  return db.prepare(`
    SELECT count(*) AS batches, coalesce(sum(node_count), 0) AS nodes, coalesce(sum(payload_bytes), 0) AS bytes
    FROM telegram_temp_batch WHERE bot_id = ? AND actor_id = ?
  `).bind(config.botId, actorId).first<{ batches: number; nodes: number; bytes: number }>();
}

test("stores whole authorized batches and emits only durable aggregate replies across replay", async () => {
  const config = policy("97001");
  const shares = [firstShare, secondShare, firstShare];
  const text = Buffer.from(shares.join("\n"), "utf8").toString("base64");
  const update = paste(config, 1, text);
  assert.deepEqual((await Promise.all([submit(config, update), submit(config, update)])).sort(), ["accepted", "ignored"]);
  const result = await storedReply(config, 1);
  assert.ok(result);
  assert.deepEqual(result, { marker: TELEGRAM_TEMP_MARKER, state: "pending", kind: "added", nodeCount: 3, totalCount: 3,
    malformedCount: 0, unsupportedCount: 0, ignoredCount: 0 });
  assert.match(renderTelegramTemp(result), /3 条节点/u);
  assert.doesNotMatch(JSON.stringify(result), /synthetic-first|synthetic-second/u);
  const payload = await db.prepare("SELECT nodes_json, payload_bytes FROM telegram_temp_batch WHERE bot_id = ? AND actor_id = ?")
    .bind(config.botId, config.memberId).first<{ nodes_json: string; payload_bytes: number }>();
  assert.ok(payload);
  assert.deepEqual(JSON.parse(payload.nodes_json).map((node: { share: string }) => node.share), shares);
  assert.equal(payload.payload_bytes, Buffer.byteLength(payload.nodes_json));
  assert.equal(await submit(config, paste(config, 1, "hy2://replacement.example.invalid")), "ignored");
  assert.deepEqual(await storedReply(config, 1), result);
  assert.equal((await totals(config))?.batches, 1);
});

test("reports rejected, empty, invalid encoding and over-limit inputs without a partial write", async () => {
  const config = policy("97002");
  const mixture = [firstShare, "hy2://", "hysteria2+realm+http://synthetic@realm.example.invalid/name", "# nodes"].join("\n");
  const fixtures = [
    [mixture, "rejected"],
    ["# just a header", "no-nodes"],
    [firstShare + "\ud800", "invalid-encoding"],
    [Array(501).fill(firstShare).join("\n"), "limit"],
    ["x".repeat(64 * 1024 + 1), "limit"],
  ] as const;
  for (const [index, [text, kind]] of fixtures.entries()) {
    const updateId = index + 1;
    assert.equal(await submit(config, paste(config, updateId, text)), "accepted");
    assert.equal((await storedReply(config, updateId))?.kind, kind);
  }
  assert.deepEqual(await storedReply(config, 1), { marker: TELEGRAM_TEMP_MARKER, state: "pending", kind: "rejected", nodeCount: 1,
    totalCount: 0, malformedCount: 1, unsupportedCount: 1, ignoredCount: 1 });
  assert.deepEqual(await totals(config), { batches: 0, nodes: 0, bytes: 0 });
});

test("fences private actor scope and rechecks revocation in the write transaction", async () => {
  const config = policy("97003");
  for (const invalid of [
    { ...paste(config, 1), chatId: config.groupId, chatType: "supergroup" as const },
    { ...paste(config, 2), actorId: "87003", chatId: "87003" },
    { ...paste(config, 3), chatId: config.adminId },
    { ...paste(config, 4), threadId: 21 },
  ]) {
    assert.equal(await submit(config, invalid), "ignored");
    assert.equal(await storedReply(config, invalid.updateId), null);
  }
  assert.equal(await submit(config, paste(config, 10)), "accepted");
  assert.equal(await submit(config, paste(config, 11, `${firstShare}\n${secondShare}`, 11, config.adminId)), "accepted");
  assert.equal(await submit(config, { ...event(config, 12), kind: "temp-summary" }), "accepted");
  assert.equal((await storedReply(config, 12))?.totalCount, 1);

  const revokedAtWrite = new Proxy(db, {
    get(target, property) {
      if (property === "prepare") return target.prepare.bind(target);
      if (property === "batch") return async (statements: D1PreparedStatement[]) => {
        await target.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, 1800000000, 12)")
          .bind(config.botId, config.memberId).run();
        return target.batch(statements);
      };
      return Reflect.get(target, property);
    },
  });
  assert.equal(await acceptTelegramTemp(revokedAtWrite, config, paste(config, 13)), "ignored");
  assert.equal(await storedReply(config, 13), null);
  for (const [updateId, kind] of [[14, "temp-summary"], [15, "temp-clear"]] as const) {
    assert.equal(await submit(config, { ...event(config, updateId), kind }), "ignored");
    assert.equal(await storedReply(config, updateId), null);
  }
  assert.equal(await submit(config, { ...event(config, 16, 16, config.adminId), kind: "temp-clear" }), "accepted");
  assert.equal((await storedReply(config, 16))?.nodeCount, 2);
  assert.equal((await totals(config, config.adminId))?.nodes, 0);
  assert.equal((await totals(config))?.nodes, 1);
});

test("a clear keeps newer pastes, fences delayed older pastes and preserves previous receipts", async () => {
  const config = policy("97004");
  const original = paste(config, 1, firstShare, 10);
  assert.equal(await submit(config, original), "accepted");
  assert.equal(await submit(config, paste(config, 2, secondShare, 30)), "accepted");
  const before = await storedReply(config, 2);
  assert.equal(before?.totalCount, 2);

  assert.equal(await submit(config, { ...event(config, 3, 20), kind: "temp-clear" }), "accepted");
  assert.equal((await storedReply(config, 3))?.kind, "cleared");
  assert.equal((await storedReply(config, 3))?.nodeCount, 1);
  assert.equal((await storedReply(config, 3))?.totalCount, 1);
  assert.equal(await submit(config, paste(config, 4, firstShare, 15)), "accepted");
  assert.equal((await storedReply(config, 4))?.kind, "stale");
  assert.equal(await submit(config, { ...event(config, 5, 19), kind: "temp-clear" }), "accepted");
  assert.equal((await storedReply(config, 5))?.kind, "stale");
  assert.equal(await submit(config, original), "ignored");
  assert.deepEqual(await storedReply(config, 2), before);
  assert.equal((await totals(config))?.nodes, 1);

  assert.equal(await submit(config, { ...event(config, 6, 40), kind: "temp-clear" }), "accepted");
  assert.equal((await storedReply(config, 6))?.nodeCount, 1);
  assert.equal((await storedReply(config, 6))?.totalCount, 0);
  assert.equal((await totals(config))?.nodes, 0);
  assert.equal(await db.prepare("SELECT message_id FROM telegram_temp_clear_fence WHERE bot_id = ? AND actor_id = ?")
    .bind(config.botId, config.memberId).first("message_id"), 40);
});

test("concurrent appends cannot pass the owner node cap", async () => {
  const config = policy("97005");
  const batch = Array(500).fill(firstShare).join("\n");
  for (let i = 1; i <= 9; i++) assert.equal(await submit(config, paste(config, i, batch)), "accepted");
  assert.equal((await totals(config))?.nodes, 4_500);
  assert.deepEqual(await Promise.all([10, 11].map((id) => submit(config, paste(config, id, batch)))), ["accepted", "accepted"]);
  const results = await Promise.all([10, 11].map((id) => storedReply(config, id)));
  assert.deepEqual(results.map((result) => result?.kind).sort(), ["added", "capacity"]);
  assert.ok(results.every((result) => result?.totalCount === MAX_TEMP_OWNER_NODES));
  assert.equal((await totals(config))?.nodes, MAX_TEMP_OWNER_NODES);
});

test("enforces the owner byte cap before writing another JSON batch", async () => {
  const config = policy("97006");
  const prefix = '[{"name":"';
  const suffix = `","type":"hysteria2","share":${JSON.stringify(firstShare)}}]`;
  const payload = prefix + "x".repeat(MAX_TEMP_BATCH_BYTES - prefix.length - suffix.length) + suffix;
  assert.equal(Buffer.byteLength(payload), MAX_TEMP_BATCH_BYTES);
  // Seed exact-capacity storage without making thousands of synthetic Telegram requests.
  for (let i = 1; i <= MAX_TEMP_OWNER_BYTES / MAX_TEMP_BATCH_BYTES; i++) {
    await db.batch([
      db.prepare(`
        INSERT INTO telegram_inbox (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, command)
        VALUES (?, ?, ?, ?, 'private', ?, 1800000000, 'help')
      `).bind(config.botId, i, config.memberId, config.memberId, i),
      db.prepare(`
        INSERT INTO telegram_temp_batch (receipt_id, bot_id, actor_id, message_date, message_id, nodes_json, node_count, payload_bytes)
        SELECT receipt_id, bot_id, actor_id, message_date, message_id, ?, 1, ? FROM telegram_inbox WHERE bot_id = ? AND update_id = ?
      `).bind(payload, MAX_TEMP_BATCH_BYTES, config.botId, i),
    ]);
  }
  assert.equal((await totals(config))?.bytes, MAX_TEMP_OWNER_BYTES);
  assert.equal(await submit(config, paste(config, 50)), "accepted");
  assert.equal((await storedReply(config, 50))?.kind, "capacity");
  assert.equal((await totals(config))?.bytes, MAX_TEMP_OWNER_BYTES);
});

test("a missing reply write rolls back deletion, clear fence, and inbox deduplication", async () => {
  const config = policy("97007");
  assert.equal(await submit(config, paste(config, 1)), "accepted");
  const clear = { ...event(config, 2), kind: "temp-clear" } as const;
  await db.prepare(`
    CREATE TRIGGER reject_fixture_temp_reply BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id = NEW.receipt_id AND bot_id = '97007' AND update_id = 2)
    BEGIN SELECT RAISE(IGNORE); END
  `).run();
  try {
    await assert.rejects(submit(config, clear), /receipt could not be confirmed/u);
    assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = 2")
      .bind(config.botId).first(), null);
    assert.equal(await db.prepare("SELECT message_id FROM telegram_temp_clear_fence WHERE bot_id = ?")
      .bind(config.botId).first(), null);
    assert.equal((await totals(config))?.nodes, 1);
  } finally {
    await db.prepare("DROP TRIGGER reject_fixture_temp_reply").run();
  }
  assert.equal(await submit(config, clear), "accepted");
  assert.equal((await storedReply(config, 2))?.kind, "cleared");
  assert.equal((await totals(config))?.nodes, 0);
});

test("does not admit first-seen pre-grant pastes after revocation and regrant", async () => {
  const config = policy("97008");
  const grantDate = 1_800_000_000;
  const baseline = { ...paste(config, 1), messageDate: grantDate - 10 };
  // The initial default-authorized member behavior is unchanged.
  assert.equal(await submit(config, baseline), "accepted");
  const before = await totals(config);
  const baselineReply = await storedReply(config, 1);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 49999)")
    .bind(config.botId, config.memberId, grantDate - 2).run();
  await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=?,message_id=50000 WHERE bot_id=? AND user_id=?")
    .bind(grantDate, config.botId, config.memberId).run();

  for (const [updateId, messageDate] of [[2, grantDate - 3], [3, grantDate - 1], [4, grantDate]] as const) {
    // Member and admin message IDs belong to different private chats. A larger member ID grants no authority.
    assert.equal(await submit(config, { ...paste(config, updateId, secondShare, 100000 + updateId), messageDate }), "ignored");
    assert.equal(await storedReply(config, updateId), null);
    assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
      .bind(config.botId, updateId).first(), null);
    assert.deepEqual(await totals(config), before);
    assert.deepEqual(await storedReply(config, 1), baselineReply);
  }
  // Conversely, a smaller member message ID is valid once its date is strictly after the grant.
  assert.equal(await submit(config, { ...paste(config, 5, secondShare, 1), messageDate: grantDate + 1 }), "accepted");
  assert.equal((await totals(config))?.nodes, 2);
  assert.equal((await storedReply(config, 5))?.kind, "added");
  assert.equal(await submit(config, { ...paste(config, 6, firstShare, 1, config.adminId),
    messageDate: grantDate - 100 }), "accepted");
  assert.equal((await totals(config, config.adminId))?.nodes, 1);
});

test("first-seen pre-grant clears cannot delete nodes or advance the clear fence after regrant", async () => {
  const config = policy("97009");
  const grantDate = 1_800_000_000;
  assert.equal(await submit(config, { ...paste(config, 1), messageDate: grantDate - 10 }), "accepted");
  const before = await totals(config);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 49999)")
    .bind(config.botId, config.memberId, grantDate - 2).run();
  await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=?,message_id=50000 WHERE bot_id=? AND user_id=?")
    .bind(grantDate, config.botId, config.memberId).run();

  for (const [updateId, messageDate] of [[2, grantDate - 3], [3, grantDate - 1], [4, grantDate]] as const) {
    assert.equal(await submit(config, { ...event(config, updateId, 100000 + updateId), kind: "temp-clear", messageDate }), "ignored");
    assert.equal(await storedReply(config, updateId), null);
    assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
      .bind(config.botId, updateId).first(), null);
    assert.equal(await db.prepare("SELECT message_date,message_id FROM telegram_temp_clear_fence WHERE bot_id=? AND actor_id=?")
      .bind(config.botId, config.memberId).first(), null);
    assert.deepEqual(await totals(config), before);
  }
  assert.equal(await submit(config, { ...event(config, 5, 1), kind: "temp-clear", messageDate: grantDate + 1 }), "accepted");
  assert.equal((await totals(config))?.nodes, 0);
  assert.equal((await storedReply(config, 5))?.kind, "cleared");
  assert.deepEqual(await db.prepare("SELECT message_date,message_id FROM telegram_temp_clear_fence WHERE bot_id=? AND actor_id=?")
    .bind(config.botId, config.memberId).first(), { message_date: grantDate + 1, message_id: 1 });
});

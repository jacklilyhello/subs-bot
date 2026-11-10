import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { readTelegramInlineTempNodes } from "../src/telegram/inline-temp-nodes.ts";
import type { TelegramPolicy, TelegramTempUpdate } from "../src/telegram/protocol.ts";
import {
  acceptTelegramTemp, MAX_TEMP_BATCH_BYTES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, renderTelegramTemp,
  TELEGRAM_TEMP_MARKER, TELEGRAM_TEMP_RAW_PREFIX, type TelegramTempReply,
} from "../src/telegram/temp-import.ts";
import { beginTelegramReply, beginTelegramTempRawReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import { confirmTelegramTempRawSend, prepareTelegramTempRawReply } from "../src/telegram/temp-raw.ts";
import { LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256, TELEGRAM_GENERAL_TEMP_MARKER } from "../src/telegram/temp-storage.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB", "RESTORED", "UNPINNED"],
});
const migrationDir = new URL("../migrations/", import.meta.url);
const firstShare = "hy2://first.example.invalid#synthetic-first";
const secondShare = "ssr://synthetic-opaque-share#synthetic-second";
let db: D1Database;
let restored: D1Database;
let unpinned: D1Database;

async function applyMigration(target: D1Database, name: string): Promise<void> {
  const sql = await readFile(new URL(name, migrationDir), "utf8");
  await target.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => target.prepare(statement)));
}

before(async () => {
  db = await miniflare.getD1Database("DB");
  for (const name of (await readdir(migrationDir)).filter((file) => file.endsWith(".sql")).sort()) {
    if (name !== LEGACY_TEMP_MIGRATION_NAME) await applyMigration(db, name);
  }
  restored = await miniflare.getD1Database("RESTORED");
  for (const name of ["0002_telegram.sql", "0008_telegram_temp_nodes.sql", LEGACY_TEMP_MIGRATION_NAME]) {
    await applyMigration(restored, name);
  }
  await restored.prepare(`CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)`).run();
  await restored.prepare("INSERT INTO subs_bot_schema_migrations VALUES (39,?,?,'applied')")
    .bind(LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256).run();
  unpinned = await miniflare.getD1Database("UNPINNED");
  await applyMigration(unpinned, LEGACY_TEMP_MIGRATION_NAME);
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

async function storedReply(config: TelegramPolicy, updateId: number, target = db) {
  return target.prepare(`
    SELECT inbox.receipt_nonce AS marker, outbox.state, reply.kind, reply.node_count AS nodeCount,
      reply.total_count AS totalCount, reply.malformed_count AS malformedCount,
      reply.unsupported_count AS unsupportedCount, reply.ignored_count AS ignoredCount
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS outbox USING (receipt_id)
    JOIN telegram_temp_reply AS reply USING (receipt_id) WHERE inbox.bot_id = ? AND inbox.update_id = ?
  `).bind(config.botId, updateId).first<TelegramTempReply & { marker: string; state: string }>();
}

async function install(botId: string, cutoff: number | null): Promise<void> {
  await restored.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,?)").bind(botId, "a".repeat(64), cutoff).run();
}

async function baseline(botId: string, actorId: string, first: number, count = 1): Promise<void> {
  const json = JSON.stringify(Array.from({ length: count }, () => ({ name: "old node", type: "temp", share: firstShare })));
  await restored.prepare("INSERT INTO legacy_temp_batches VALUES (?,?,?,?,?,?,?,?)")
    .bind(botId, actorId, first, first + count - 1, json, count, Buffer.byteLength(json), createHash("sha256").update(json).digest("hex")).run();
}

test("fails closed when legacy baseline tables exist without the exact ledger pin", async () => {
  const config = policy("97101");
  await assert.rejects(acceptTelegramTemp(unpinned, config, paste(config, 1)), /receipt could not be confirmed/u);
});

test("clears restored and older live data atomically while fencing delayed messages and other scopes", async () => {
  const config = policy("97102");
  const otherBot = "97103";
  const cutoff = 1_800_000_000;
  await install(config.botId, cutoff);
  await install(otherBot, cutoff);
  await baseline(config.botId, config.memberId, 1);
  await baseline(config.botId, config.adminId, 2);
  await baseline(otherBot, config.memberId, 1);
  for (const update of [paste(config, 1), { ...event(config, 2), kind: "temp-clear" as const }]) {
    assert.equal(await acceptTelegramTemp(restored, config, update), "ignored");
    assert.equal(await storedReply(config, update.updateId, restored), null);
  }
  const afterCutover = (updateId: number, messageId: number) => ({ ...event(config, updateId, messageId), messageDate: cutoff + 1 });
  for (const [id, messageId] of [[3, 10], [4, 30]]) {
    assert.equal(await acceptTelegramTemp(restored, config, { ...afterCutover(id, messageId), kind: "temp-text", text: firstShare }), "accepted");
  }
  assert.equal((await storedReply(config, 4, restored))?.totalCount, 3);
  const clear = { ...afterCutover(5, 20), kind: "temp-clear" } as const;
  await restored.prepare(`CREATE TRIGGER fixture_baseline_clear_abort BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id=NEW.receipt_id AND bot_id='97102' AND update_id=5)
    BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    await assert.rejects(acceptTelegramTemp(restored, config, clear), /receipt could not be confirmed/u);
    assert.equal(await storedReply(config, 5, restored), null);
    assert.equal(await restored.prepare("SELECT count(*) AS n FROM legacy_temp_batches").first("n"), 3);
    assert.equal(await restored.prepare("SELECT count(*) AS n FROM telegram_temp_batch WHERE bot_id=?")
      .bind(config.botId).first("n"), 2);
    assert.equal(await restored.prepare("SELECT count(*) AS n FROM telegram_temp_clear_fence WHERE bot_id=?")
      .bind(config.botId).first("n"), 0);
  } finally {
    await restored.prepare("DROP TRIGGER fixture_baseline_clear_abort").run();
  }
  assert.equal(await acceptTelegramTemp(restored, config, clear), "accepted");
  assert.equal(await acceptTelegramTemp(restored, config, clear), "ignored");
  const reply = await storedReply(config, 5, restored);
  assert.deepEqual([reply?.kind, reply?.nodeCount, reply?.totalCount], ["cleared", 2, 1]);
  assert.equal(await acceptTelegramTemp(restored, config, { ...afterCutover(6, 19), kind: "temp-clear" }), "accepted");
  assert.equal((await storedReply(config, 6, restored))?.kind, "stale");
  assert.equal(await restored.prepare("SELECT message_id FROM telegram_temp_batch WHERE bot_id=?").bind(config.botId).first("message_id"), 30);
  assert.deepEqual((await restored.prepare("SELECT bot_id,actor_id FROM legacy_temp_batches WHERE bot_id IN (?,?) ORDER BY bot_id")
    .bind(config.botId, otherBot).all()).results, [{ bot_id: config.botId, actor_id: config.adminId },
    { bot_id: otherBot, actor_id: config.memberId }]);
  assert.equal(await restored.prepare("SELECT cutover_epoch FROM legacy_temp_installations WHERE bot_id=?")
    .bind(config.botId).first("cutover_epoch"), cutoff);
});

test("restored nodes count against the same atomic admission quota while dormant data is excluded", async () => {
  const config = policy("97104");
  const cutoff = 1_800_000_000;
  await install(config.botId, null);
  await baseline(config.botId, config.memberId, 1, 499);
  for (let index = 1; index < 10; index++) await baseline(config.botId, config.memberId, 500 * index, 500);
  assert.equal(await acceptTelegramTemp(restored, config, { ...event(config, 1), kind: "temp-summary" }), "accepted");
  assert.equal((await storedReply(config, 1, restored))?.totalCount, 0);
  await restored.prepare("UPDATE legacy_temp_installations SET cutover_epoch=? WHERE bot_id=?")
    .bind(cutoff, config.botId).run();
  assert.deepEqual(await Promise.all([2, 3].map((id) => acceptTelegramTemp(restored, config,
    { ...paste(config, id), messageDate: cutoff + 1 }))), ["accepted", "accepted"]);
  const replies = await Promise.all([2, 3].map((id) => storedReply(config, id, restored)));
  assert.deepEqual(replies.map((reply) => reply?.kind).sort(), ["added", "capacity"]);
  assert.ok(replies.every((reply) => reply?.totalCount === MAX_TEMP_OWNER_NODES));
});

async function totals(config: TelegramPolicy, actorId = config.memberId) {
  return db.prepare(`
    SELECT count(*) AS batches, coalesce(sum(node_count), 0) AS nodes, coalesce(sum(payload_bytes), 0) AS bytes
    FROM telegram_temp_batch WHERE bot_id = ? AND actor_id = ?
  `).bind(config.botId, actorId).first<{ batches: number; nodes: number; bytes: number }>();
}

test("keeps a raw retry on the admitted batches and refuses final delivery after a clear", async () => {
  const config = policy("97011");
  const now = Math.floor(Date.now() / 1000);
  const current = (updateId: number, messageId = updateId) => ({ ...event(config, updateId, messageId), messageDate: now });
  assert.equal(await submit(config, { ...current(1), kind: "temp-text", text: firstShare }), "accepted");
  const added = await claimTelegramReply(db, config.botId);
  assert.ok(added);
  assert.equal(await beginTelegramReply(db, config, added, "allowed"), true);
  await settleTelegramReply(db, config, added, { kind: "sent", messageId: 101 });
  const raw = { ...current(2), kind: "temp-raw" as const };
  assert.deepEqual((await Promise.all([submit(config, raw), submit(config, raw)])).sort(), ["accepted", "ignored"]);
  const durable = await storedReply(config, 2);
  assert.equal(durable?.marker, TELEGRAM_TEMP_RAW_PREFIX + "[0,0]:[0,0]");
  assert.equal(durable?.totalCount, 1);
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.tempRaw);
  const prepared = await prepareTelegramTempRawReply(db, config, lease, Date.now() + 5_000);
  assert.equal(prepared.kind, "text");
  if (prepared.kind !== "text") return;
  assert.match(prepared.text, /synthetic-first$/u);
  assert.equal(await beginTelegramTempRawReply(db, config, lease, prepared.guard), true);
  assert.equal(await confirmTelegramTempRawSend(db, config, lease, prepared.guard), true);
  await settleTelegramReply(db, config, lease, { kind: "retry", delaySeconds: 1 });

  assert.equal(await submit(config, { ...current(3), kind: "temp-text", text: secondShare }), "accepted");
  await db.prepare("UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id=?").bind(lease.receiptId).run();
  const retry = await claimTelegramReply(db, config.botId);
  assert.ok(retry?.tempRaw);
  assert.equal(retry.receiptId, lease.receiptId);
  assert.equal(retry.attempts, 2);
  const repeated = await prepareTelegramTempRawReply(db, config, retry, Date.now() + 5_000);
  assert.equal(repeated.kind, "text");
  if (repeated.kind !== "text") return;
  assert.equal(repeated.text, prepared.text);
  assert.equal(await confirmTelegramTempRawSend(db, config, lease, prepared.guard), false);
  assert.equal(await beginTelegramTempRawReply(db, config, retry, repeated.guard), true);
  assert.equal(await submit(config, { ...current(4), kind: "temp-clear" }), "accepted");
  assert.equal(await confirmTelegramTempRawSend(db, config, retry, repeated.guard), false);
  await settleTelegramReply(db, config, retry, { kind: "failed" });
  assert.equal(await submit(config, { ...current(5, 3), kind: "temp-raw" }), "ignored");
  assert.equal(await storedReply(config, 5), null);
  assert.deepEqual(await totals(config), { batches: 0, nodes: 0, bytes: 0 });
});

test("rejects a changed grant even if the account is allowed again before the request timestamp", async () => {
  const config = policy("97012");
  const now = Math.floor(Date.now() / 1000);
  await db.prepare("INSERT INTO telegram_auth VALUES (?,?,1,?,?)").bind(config.botId, config.memberId, now - 60, 1).run();
  assert.equal(await submit(config, { ...event(config, 1), messageDate: now, kind: "temp-text", text: firstShare }), "accepted");
  const added = await claimTelegramReply(db, config.botId);
  assert.ok(added);
  assert.equal(await beginTelegramReply(db, config, added, "allowed"), true);
  await settleTelegramReply(db, config, added, { kind: "sent", messageId: 101 });
  assert.equal(await submit(config, { ...event(config, 2), messageDate: now, kind: "temp-raw" }), "accepted");
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.tempRaw);
  const prepared = await prepareTelegramTempRawReply(db, config, lease, Date.now() + 5_000);
  assert.equal(prepared.kind, "text");
  if (prepared.kind !== "text") return;
  await db.prepare("UPDATE telegram_auth SET message_date=?,message_id=? WHERE bot_id=? AND user_id=?")
    .bind(now - 30, 3, config.botId, config.memberId).run();
  assert.equal(await beginTelegramTempRawReply(db, config, lease, prepared.guard), false);
  assert.deepEqual(await prepareTelegramTempRawReply(db, config, lease, Date.now() + 5_000), { kind: "stale" });
});

test("refuses a whole raw reply when a stored batch contains an invalid share", async () => {
  const config = policy("97013");
  const now = Math.floor(Date.now() / 1000);
  assert.equal(await submit(config, { ...event(config, 1), messageDate: now, kind: "temp-text",
    text: firstShare + "\n" + secondShare }), "accepted");
  const added = await claimTelegramReply(db, config.botId);
  assert.ok(added);
  assert.equal(await beginTelegramReply(db, config, added, "allowed"), true);
  await settleTelegramReply(db, config, added, { kind: "sent", messageId: 101 });
  const corrupt = JSON.stringify([{ share: firstShare }, { share: "ss://invalid" }]);
  await db.prepare("UPDATE telegram_temp_batch SET nodes_json=?,payload_bytes=? WHERE receipt_id=?")
    .bind(corrupt, Buffer.byteLength(corrupt), added.receiptId).run();
  assert.equal(await submit(config, { ...event(config, 2), messageDate: now, kind: "temp-raw" }), "accepted");
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.tempRaw);
  assert.deepEqual(await prepareTelegramTempRawReply(db, config, lease, Date.now() + 5_000), { kind: "unavailable" });
});

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

test("verifies committed general batches after revoke and clears them with the original atomic owner watermark", async () => {
  const config = policy("97014");
  const now = Math.floor(Date.now() / 1000);
  const digest = "a".repeat(64);
  const release = "b".repeat(40);
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  const generalMigrations = [[44, "0044_telegram_general_runtime.sql"], [46, "0046_telegram_general_receipts.sql"]] as const;
  for (const [position, name] of generalMigrations) {
    const bytes = await readFile(new URL(name, migrationDir));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')")
      .bind(position, name, createHash("sha256").update(bytes).digest("hex")).run();
  }
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES (?,1,?,?,?,1)").bind(config.botId, release, digest, now - 60),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,1,?,'member')").bind(config.botId, config.memberId, now - 60),
  ]);
  const current = (updateId: number, messageId: number, date = now - 2, actorId = config.memberId) =>
    ({ ...event(config, updateId, messageId, actorId), messageDate: date });
  for (const [updateId, messageId, text] of [[1, 10, firstShare], [2, 20, secondShare], [3, 40, firstShare]] as const) {
    assert.equal(await submit(config, { ...current(updateId, messageId), kind: "temp-text", text }), "accepted");
  }

  // Model future atomically committed provenance. This patch adds no general ingress.
  const record = await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=2")
    .bind(config.botId).first<number>("receipt_id");
  assert.ok(record);
  const marked = await db.batch([
    db.prepare("UPDATE telegram_inbox SET receipt_nonce=? WHERE bot_id=? AND update_id IN (2,3)")
      .bind(TELEGRAM_GENERAL_TEMP_MARKER, config.botId),
    db.prepare(`INSERT INTO telegram_general_receipt
      SELECT receipt_id,1,1,'member',?,?,? FROM telegram_inbox WHERE bot_id=? AND update_id IN (2,3)`)
      .bind(release, digest, now - 60, config.botId),
    db.prepare(`UPDATE telegram_outbox SET state='sent',sent_message_id=100+receipt_id
      WHERE receipt_id IN (SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id IN (1,2,3))`).bind(config.botId),
  ]);
  assert.ok(marked.every(({ success }) => success));
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,2,?,'denied')").bind(config.botId, config.memberId, now - 1),
    db.prepare("UPDATE telegram_general_policy SET active=0,generation=2,activation_sha256=? WHERE bot_id=?")
      .bind("c".repeat(64), config.botId),
  ]);
  const inline = await readTelegramInlineTempNodes(db, config, {
    updateId: 9, actorId: config.memberId, chatType: "sender", queryId: "fixture-inline", query: "",
  }, "", 3, Date.now() + 5_000, now);
  assert.ok(inline);
  assert.equal(inline.results.length, 3);
  assert.match(inline.results[1].title, /synthetic-second/u);
  assert.doesNotMatch(JSON.stringify(inline.results), /ssr:\/\//u);

  assert.equal(await submit(config, { ...current(4, 50, now), kind: "temp-raw" }), "accepted");
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.tempRaw);
  const prepared = await prepareTelegramTempRawReply(db, config, lease, Date.now() + 5_000);
  assert.equal(prepared.kind, "text");
  if (prepared.kind !== "text") return;
  assert.match(prepared.text, /ssr:\/\/synthetic-opaque-share/u);

  const schemaDigest = createHash("sha256").update(await readFile(new URL(generalMigrations[1][1], migrationDir))).digest("hex");
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=46").bind("0".repeat(64)).run();
  assert.equal(await beginTelegramTempRawReply(db, config, lease, prepared.guard), false);
  assert.deepEqual(await prepareTelegramTempRawReply(db, config, lease, Date.now() + 5_000), { kind: "unavailable" });
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=46").bind(schemaDigest).run();
  await db.prepare("UPDATE telegram_general_receipt SET actor_revision=2 WHERE receipt_id=?").bind(record).run();
  assert.equal(await beginTelegramTempRawReply(db, config, lease, prepared.guard), false, "a denied historical row cannot prove ownership");
  await db.prepare("UPDATE telegram_general_receipt SET actor_revision=1 WHERE receipt_id=?").bind(record).run();
  assert.equal(await beginTelegramTempRawReply(db, config, lease, prepared.guard), true);

  assert.equal(await submit(config, { ...current(6, 15, now - 2, config.adminId), kind: "temp-text", text: firstShare }), "accepted");
  const clear = { ...current(5, 30), kind: "temp-clear" } as const;
  await db.prepare(`CREATE TRIGGER fixture_general_temp_clear_abort BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id=NEW.receipt_id AND bot_id='97014' AND update_id=5)
    BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    await assert.rejects(submit(config, clear), /receipt could not be confirmed/u);
    assert.equal((await totals(config))?.nodes, 3);
    assert.equal(await db.prepare("SELECT message_id FROM telegram_temp_clear_fence WHERE bot_id=? AND actor_id=?")
      .bind(config.botId, config.memberId).first("message_id"), null);
  } finally {
    await db.prepare("DROP TRIGGER fixture_general_temp_clear_abort").run();
  }
  assert.equal(await submit(config, clear), "accepted");
  assert.equal(await submit(config, clear), "ignored");
  const cleared = await storedReply(config, 5);
  assert.deepEqual([cleared?.kind, cleared?.nodeCount, cleared?.totalCount], ["cleared", 2, 1]);
  assert.equal(await confirmTelegramTempRawSend(db, config, lease, prepared.guard), false);
  assert.deepEqual((await db.prepare(`SELECT actor_id,message_id FROM telegram_temp_batch
    WHERE bot_id=? ORDER BY actor_id`).bind(config.botId).all()).results,
    [{ actor_id: config.adminId, message_id: 15 }, { actor_id: config.memberId, message_id: 40 }]);
});

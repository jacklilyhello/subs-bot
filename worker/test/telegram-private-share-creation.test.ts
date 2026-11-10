import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import { claimPrivateShare, createPrivateShare } from "../src/private-shares.ts";
import { parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import {
  acceptTelegramPrivateShareCreation, importTelegramPrivateShareCreationKey, parseTelegramPrivateShareArgs,
  recoverTelegramPrivateShareCreation, resolveTelegramPrivateShareCreationReply, retireAbandonedTelegramPrivateShareCreation,
  TELEGRAM_PRIVATE_SHARE_CREATION_MARKER, type TelegramPrivateShareCreationInput, type TelegramPrivateShareCreationKey,
} from "../src/telegram/private-share-creation.ts";

const miniflare = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default { fetch() { return new Response(null); } };" });
const encodedKey = Buffer.alloc(32, 0x4c).toString("base64url");
let db: D1Database;
let bucket: R2Bucket;
let context: TelegramPrivateShareCreationKey;
let date: number;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const migrations = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrations), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  const parsed = await importTelegramPrivateShareCreationKey(encodedKey, "synthetic-isolation");
  assert.ok(parsed);
  context = parsed;
  date = Number(await db.prepare("SELECT unixepoch() AS now").first<number>("now"));
});
after(() => miniflare.dispose());

function policy(botId: string): TelegramPolicy {
  return { botId, botUsername: "fixture_private_share_bot", adminId: "75101", memberId: "75102", groupId: "-1001234567890",
    botToken: `${botId}:synthetic-token`, webhookSecret: "synthetic-secret" };
}

function event(config: TelegramPolicy, updateId: number, overrides: Partial<TelegramPrivateShareCreationInput> = {}): TelegramPrivateShareCreationInput {
  return { updateId, messageId: updateId, actorId: config.adminId, chatId: config.adminId, chatType: "private", threadId: null,
    messageDate: date, content: "  synthetic α\r\nsecond line  ", maxClaims: 1, targetUserId: config.memberId,
    durationMinutes: 10, senderName: "  Fixture sender  ", ...overrides };
}

function stored(config: TelegramPolicy, updateId: number) {
  return db.prepare(`SELECT creation.*, inbox.receipt_nonce AS marker, reply.state AS reply_state, share.code_sha256
    FROM telegram_private_share_creations AS creation JOIN telegram_inbox AS inbox USING (receipt_id)
    LEFT JOIN telegram_outbox AS reply USING (receipt_id) LEFT JOIN private_shares AS share ON share.id = creation.share_id
    WHERE inbox.bot_id = ? AND inbox.update_id = ?`).bind(config.botId, updateId)
    .first<{ receipt_id: number; payload_id: string; payload_sha256: string; state: string; cleaned_at: number | null;
      marker: string; reply_state: string | null; share_id: number | null; code_sha256: string | null; sender_name: string }>();
}

function hash(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function d1Fault(fault: (statementCount: number) => "before" | "after" | null): D1Database {
  return {
    prepare: (sql: string) => db.prepare(sql),
    async batch(statements: D1PreparedStatement[]) {
      const stage = fault(statements.length);
      if (stage === "before") throw new Error("Synthetic D1 interruption.");
      const result = await db.batch(statements);
      if (stage === "after") throw new Error("Synthetic lost D1 acknowledgement.");
      return result;
    },
  } as unknown as D1Database;
}

function r2Put(put: R2Bucket["put"]): R2Bucket {
  return { put, get: (key: string) => bucket.get(key), head: (key: string) => bucket.head(key) } as R2Bucket;
}

const noPut = () => r2Put(async () => { throw new Error("Synthetic R2 interruption."); });

async function expire(receiptId: number) {
  await db.prepare(`UPDATE telegram_private_share_creations SET reservation_expires_at = unixepoch() - 60,
    cleanup_after = unixepoch() - 1, next_check_at = unixepoch() - 1 WHERE receipt_id = ?`).bind(receiptId).run();
}

test("parses prefix-only options and preserves bytes after the delimiter", async () => {
  assert.deepEqual(parseTelegramPrivateShareArgs(" -- sample x9 id5 s90  "), {
    content: "sample x9 id5 s90  ", maxClaims: 1, targetUserId: null, durationMinutes: 10,
  });
  assert.deepEqual(parseTelegramPrivateShareArgs(" ID75102 S10080 X100 --\r\n  x1\r\n含空格  "), {
    content: "  x1\r\n含空格  ", maxClaims: 100, targetUserId: "75102", durationMinutes: 10_080,
  });
  for (const invalid of ["x1 hello", "x0 -- sample", "x101 -- sample", "x1 X2 -- sample", "id00 -- sample",
    "id9223372036854775808 -- sample", "s10081 -- sample", "x1 --   ", "-- \ud800", `-- ${"x".repeat(4096)}`]) {
    assert.equal(parseTelegramPrivateShareArgs(invalid), null);
  }
  assert.equal(context.key.extractable, false);
  assert.equal(await importTelegramPrivateShareCreationKey(`${encodedKey}=`, "synthetic-isolation"), null);
  assert.equal(await importTelegramPrivateShareCreationKey(encodedKey, "invalid namespace"), null);
});

test("recovers lost R2 and D1 acknowledgements with one share, one receipt, and exact private payload", async () => {
  const config = policy("75201");
  const input = event(config, 1);
  let puts = 0;
  const lostR2 = r2Put(async (key, bytes, options) => {
    puts++;
    const reservation = await stored(config, 1);
    assert.equal(reservation?.state, "reserved");
    assert.equal(reservation?.reply_state, null);
    await bucket.put(key, bytes, options);
    throw new Error("Synthetic lost R2 acknowledgement.");
  });
  assert.equal(await acceptTelegramPrivateShareCreation(d1Fault(() => "after"), lostR2, config, input, context), "published");
  assert.equal(await acceptTelegramPrivateShareCreation(db, lostR2, config, input, context), "published");
  assert.equal(await acceptTelegramPrivateShareCreation(db, lostR2, config, { ...input, content: "conflicting replay" }, context), "ignored");
  assert.equal(puts, 1);
  const row = await stored(config, 1);
  assert.ok(row);
  assert.equal(row.marker, TELEGRAM_PRIVATE_SHARE_CREATION_MARKER);
  assert.equal(row.state, "published");
  assert.equal(row.reply_state, "pending");
  assert.equal(row.payload_sha256, hash(input.content));
  assert.equal(row.sender_name, "Fixture sender");
  const scope = { ...input, receiptId: row.receipt_id };
  const reply = await resolveTelegramPrivateShareCreationReply(db, config, scope, context);
  assert.ok(reply);
  assert.match(reply.code, /^[A-Za-z0-9_-]{22}$/u);
  assert.equal(row.code_sha256, hash(reply.code));
  assert.equal((await resolveTelegramPrivateShareCreationReply(db, config, scope, context))?.code, reply.code);
  assert.equal(await resolveTelegramPrivateShareCreationReply(db, config,
    { ...scope, actorId: config.memberId, chatId: config.memberId }, context), null);
  assert.equal((await claimPrivateShare(db, bucket, { botId: config.botId, actorId: config.adminId, code: reply.code })).kind, "target");
  for (const kind of ["claimed", "repeated"]) {
    const result = await claimPrivateShare(db, bucket, { botId: config.botId, actorId: config.memberId, code: reply.code });
    assert.equal(result.kind, kind);
    assert.ok("content" in result);
    assert.equal(result.content, input.content);
    assert.equal(result.claimCount, 1);
  }
});

test("resumes a verified reservation without a body and preserves same-actor order", async () => {
  const config = policy("75202");
  const first = event(config, 1);
  const second = event(config, 2, { content: "Second synthetic body" });
  await assert.rejects(acceptTelegramPrivateShareCreation(db, noPut(), config, first, context), /could not be confirmed/u);
  assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, second, context), "pending");
  assert.equal((await stored(config, 2))?.reply_state, null);
  assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, event(config, 3, { messageId: 1 }), context), "ignored");
  assert.equal(await recoverTelegramPrivateShareCreation(db, bucket, config, context), "ignored");
  assert.equal((await stored(config, 2))?.state, "reserved");

  await assert.rejects(acceptTelegramPrivateShareCreation(d1Fault((count) => count === 4 ? "before" : null), bucket,
    config, first, context), /could not be confirmed/u);
  const firstRow = await stored(config, 1);
  assert.ok(firstRow);
  assert.ok(await bucket.head(`private-shares/${firstRow.payload_id}.txt`));
  await db.prepare("UPDATE telegram_private_share_creations SET next_check_at = unixepoch() WHERE receipt_id = ?")
    .bind(firstRow.receipt_id).run();
  assert.equal(await recoverTelegramPrivateShareCreation(db, bucket, config, context), "published");
  assert.equal(await recoverTelegramPrivateShareCreation(db, bucket, config, context), "published");
  assert.equal((await stored(config, 1))?.reply_state, "pending");
  assert.equal((await stored(config, 2))?.reply_state, "pending");
});

test("fences private scope, time, target, and authorization changes at publication and reply", async () => {
  const config = policy("75203");
  const input = event(config, 1, { actorId: config.memberId, chatId: config.memberId, targetUserId: null });
  for (const overrides of [{ chatType: "group", chatId: config.groupId }, { threadId: 1 }, { targetUserId: "999" },
    { messageDate: date - 900 }, { messageDate: date + 900 }] satisfies Partial<TelegramPrivateShareCreationInput>[]) {
    assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, { ...input, ...overrides }, context), "ignored");
  }
  assert.equal(await stored(config, 1), null);
  assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, input, context), "published");
  const row = await stored(config, 1);
  assert.ok(row);
  const scope = { ...input, receiptId: row.receipt_id };
  const reply = await resolveTelegramPrivateShareCreationReply(db, config, scope, context);
  assert.ok(reply);
  const auth = (allowed: number, messageId: number) => db.prepare(`INSERT INTO telegram_auth VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (bot_id, user_id) DO UPDATE SET allowed = excluded.allowed, message_id = excluded.message_id`)
    .bind(config.botId, config.memberId, allowed, date, messageId).run();
  const changeDuringWrite = r2Put(async (key, bytes, options) => {
    const object = await bucket.put(key, bytes, options);
    await auth(0, 10);
    await auth(1, 11);
    return object;
  });
  assert.equal(await acceptTelegramPrivateShareCreation(db, changeDuringWrite, config,
    { ...input, updateId: 2, messageId: 2 }, context), "ignored");
  assert.equal((await stored(config, 2))?.state, "reserved");
  assert.equal(await recoverTelegramPrivateShareCreation(db, bucket, config, context), "ignored");
  assert.equal(await resolveTelegramPrivateShareCreationReply(db, config, scope, context), null);
  assert.equal(await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox WHERE ${reply.guard.sql}`)
    .bind(...reply.guard.bindings).first(), null);
});

test("does not adopt a delayed pre-regrant member command from the same second", async () => {
  const config = policy("75205");
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 10)").bind(config.botId, config.memberId, date).run();
  await db.prepare("UPDATE telegram_auth SET allowed = 1, message_id = 11 WHERE bot_id = ? AND user_id = ?")
    .bind(config.botId, config.memberId).run();
  let puts = 0;
  const observed = r2Put(async (key, bytes, options) => {
    puts++;
    return await bucket.put(key, bytes, options);
  });
  const input = event(config, 1, { actorId: config.memberId, chatId: config.memberId, targetUserId: null, messageId: 2 });
  assert.equal(await acceptTelegramPrivateShareCreation(db, observed, config, input, context), "ignored");
  assert.equal(await stored(config, 1), null);
  assert.equal(puts, 0);
  assert.equal(await acceptTelegramPrivateShareCreation(db, observed, config,
    { ...input, updateId: 2, messageId: 3, messageDate: date + 1 }, context), "published");
  assert.equal(puts, 1);
});

test("retires only expired owned abandoned objects and preserves unowned collisions and existing shares", async () => {
  const config = policy("75204");
  const legacy = await createPrivateShare(db, bucket, { botId: config.botId, senderId: config.adminId, senderName: "Fixture",
    content: "Existing synthetic share", maxClaims: 1, targetUserId: null, durationMinutes: 10 });
  await assert.rejects(acceptTelegramPrivateShareCreation(db, noPut(), config, event(config, 1), context), /could not be confirmed/u);
  const foreign = await stored(config, 1);
  assert.ok(foreign);
  const foreignKey = `private-shares/${foreign.payload_id}.txt`;
  // Even identical body bytes are not owned without the reservation metadata.
  await bucket.put(foreignKey, event(config, 1).content);
  await assert.rejects(acceptTelegramPrivateShareCreation(db, bucket, config, event(config, 1), context), /could not be confirmed/u);
  await expire(foreign.receipt_id);
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "blocked");
  assert.ok(await bucket.head(foreignKey));
  assert.equal((await stored(config, 1))?.cleaned_at, null);

  await assert.rejects(acceptTelegramPrivateShareCreation(d1Fault((count) => count === 4 ? "before" : null), bucket,
    config, event(config, 2), context), /could not be confirmed/u);
  const owned = await stored(config, 2);
  assert.ok(owned);
  const ownedKey = `private-shares/${owned.payload_id}.txt`;
  assert.ok(await bucket.head(ownedKey));
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "ignored");
  await expire(owned.receipt_id);
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "retired");
  assert.equal(await bucket.head(ownedKey), null);
  assert.ok((await stored(config, 2))?.cleaned_at);
  assert.ok(await bucket.head(foreignKey));
  assert.equal((await claimPrivateShare(db, bucket, { botId: config.botId, actorId: config.memberId, code: legacy.code })).kind, "claimed");
});

test("re-observes a cleaned tombstone when an unknown PUT commits after its original isolate is gone", async () => {
  const config = policy("75206");
  const pending: { commit?: () => Promise<unknown> } = {};
  const vanishedWriter = r2Put(async (key, bytes, options) => {
    pending.commit = async () => await bucket.put(key, bytes, options);
    throw new Error("Synthetic unknown PUT; original writer disappears.");
  });
  await assert.rejects(acceptTelegramPrivateShareCreation(db, vanishedWriter, config, event(config, 1), context), /could not be confirmed/u);
  const row = await stored(config, 1);
  assert.ok(row);
  const key = `private-shares/${row.payload_id}.txt`;
  await expire(row.receipt_id);
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "retired");
  assert.equal(await bucket.head(key), null);
  assert.ok((await stored(config, 1))?.cleaned_at);
  const due = await db.prepare("SELECT next_check_at - unixepoch() AS delay FROM telegram_private_share_creations WHERE receipt_id = ?")
    .bind(row.receipt_id).first<number>("delay");
  assert.ok(due !== null && due > 3500 && due <= 3600);

  // This commit is independent of the dead accept invocation; no writer callback reopens the row.
  assert.ok(pending.commit);
  await pending.commit();
  assert.ok(await bucket.head(key));
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "ignored");
  await db.prepare("UPDATE telegram_private_share_creations SET next_check_at = unixepoch() - 1 WHERE receipt_id = ?")
    .bind(row.receipt_id).run();
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "retired");
  assert.equal(await bucket.head(key), null);
  const retired = await stored(config, 1);
  assert.ok(retired);
  assert.equal(retired.state, "abandoned");
  assert.ok(retired.cleaned_at);
  assert.equal(retired.share_id, null);
  assert.equal(retired.reply_state, null);
  assert.equal(retired.marker, TELEGRAM_PRIVATE_SHARE_CREATION_MARKER);
});

test("a late unowned collision is retained without starving an older due candidate", async () => {
  const config = policy("75207");
  await assert.rejects(acceptTelegramPrivateShareCreation(db, noPut(), config, event(config, 1), context), /could not be confirmed/u);
  const row = await stored(config, 1);
  assert.ok(row);
  const key = `private-shares/${row.payload_id}.txt`;
  await expire(row.receipt_id);
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "retired");
  assert.ok((await stored(config, 1))?.cleaned_at);
  await bucket.put(key, event(config, 1).content);
  await db.prepare("UPDATE telegram_private_share_creations SET next_check_at = unixepoch() - 1 WHERE receipt_id = ?")
    .bind(row.receipt_id).run();
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "blocked");
  assert.ok(await bucket.head(key));
  assert.equal((await stored(config, 1))?.cleaned_at, null);

  await assert.rejects(acceptTelegramPrivateShareCreation(d1Fault((count) => count === 4 ? "before" : null), bucket,
    config, event(config, 2), context), /could not be confirmed/u);
  const other = await stored(config, 2);
  assert.ok(other);
  const otherKey = `private-shares/${other.payload_id}.txt`;
  await expire(other.receipt_id);
  await db.prepare(`UPDATE telegram_private_share_creations SET reservation_expires_at = unixepoch() - 2000,
    cleanup_after = unixepoch() - 1000, next_check_at = unixepoch() - 1 WHERE receipt_id = ?`).bind(row.receipt_id).run();
  await db.prepare("UPDATE telegram_private_share_creations SET next_check_at = unixepoch() - 120 WHERE receipt_id = ?")
    .bind(other.receipt_id).run();
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "retired");
  assert.equal(await bucket.head(otherKey), null);
  assert.ok(await bucket.head(key));
});


test("a general recipient revoked after R2 upload cannot publish or authorize cross-family cleanup", async () => {
  const config = policy("75250");
  const revision = "a".repeat(40);
  const messageDate = Number(await db.prepare("SELECT unixepoch() AS now").first<number>("now"));
  const general = parseGeneralTelegramPin(JSON.stringify({
    botId: config.botId, botUsername: config.botUsername, botToken: config.botToken, webhookSecret: config.webhookSecret,
    generation: 1, cutoverAt: messageDate - 10, activationSha256: "b".repeat(64),
    outbox: "shared-private-management-formats-temp-node-document-provider-claims-share",
  }), revision);
  assert.ok(general?.privateShareCreation);
  await db.prepare(`CREATE TABLE IF NOT EXISTS subs_bot_schema_migrations
    (position INTEGER PRIMARY KEY, name TEXT, sha256 TEXT, mode TEXT)`).run();
  for (const name of ["0016_telegram_private_share_creation.sql", "0044_telegram_general_runtime.sql", "0046_telegram_general_receipts.sql"]) {
    const bytes = await readFile(new URL("../migrations/" + name, import.meta.url));
    await db.prepare("INSERT OR IGNORE INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(bytes).digest("hex")).run();
  }
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES (?,1,?,?,?,1)")
      .bind(config.botId, revision, general.activationSha256, general.cutoverAt),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,1,?,'admin'),(?,1,?,1,?,'member')")
      .bind(config.botId, config.adminId, messageDate - 9, config.botId, config.memberId, messageDate - 9),
  ]);
  const upload = r2Put(async (key, bytes, options) => {
    const object = await bucket.put(key, bytes, options);
    await db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,2,?,'denied')")
      .bind(config.botId, config.memberId, messageDate).run();
    return object;
  });
  assert.equal(await acceptTelegramPrivateShareCreation(db, upload, general, event(config, 1, { messageDate }), context), "ignored");
  const stage = await stored(config, 1);
  assert.ok(stage);
  assert.equal(stage.marker, "general-share-create:v1");
  assert.equal(stage.state, "reserved");
  assert.equal(stage.share_id, null);
  assert.equal(stage.reply_state, null);
  const key = `private-shares/${stage.payload_id}.txt`;
  assert.ok(await bucket.head(key));
  await expire(stage.receipt_id);
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, config), "ignored");
  assert.ok(await bucket.head(key), "isolation cleanup cannot adopt a general reservation");
  assert.equal(await retireAbandonedTelegramPrivateShareCreation(db, bucket, general), "retired");
  assert.equal(await bucket.head(key), null);
  assert.ok((await stored(config, 1))?.cleaned_at);
});

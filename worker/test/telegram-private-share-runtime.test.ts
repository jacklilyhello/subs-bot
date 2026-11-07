import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import { drainTelegramReplies } from "../src/telegram/delivery.ts";
import {
  acceptTelegramPrivateShareCreation, resolveTelegramPrivateShareCreationReply,
} from "../src/telegram/private-share-creation.ts";
import {
  PRIVATE_SHARE_CREATION_INSTALLATION, PRIVATE_SHARE_CREATION_MIGRATION, PRIVATE_SHARE_CREATION_SCHEMA_SHA256,
  PRIVATE_SHARE_DISABLED, telegramPrivateShareRuntime,
} from "../src/telegram/private-share-runtime.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand, beginTelegramPrivateShareCreationReply, claimTelegramReply } from "../src/telegram/store.ts";

const encoded = Buffer.alloc(32, 0x51).toString("base64url");
const miniflare = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default { fetch() { return new Response(null); } };" });
let db: D1Database;
let bucket: R2Bucket;
let date: number;
before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const directory = new URL("../migrations/", import.meta.url);
  for (const file of (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(file, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  date = Number(await db.prepare("SELECT unixepoch() AS now").first("now"));
});
after(() => miniflare.dispose());

function policy(botId: string): TelegramPolicy {
  return { botId, botUsername: "fixture_share_bot", adminId: "74101", memberId: "74102", groupId: "-1001234567890",
    botToken: `${botId}:synthetic-token`, webhookSecret: "synthetic-secret" };
}
function input(config: TelegramPolicy, updateId: number, actorId = config.adminId) {
  return { updateId, messageId: updateId, actorId, chatId: actorId, chatType: "private" as const,
    messageDate: date, threadId: null, content: "  synthetic private body\r\n  ", maxClaims: 1, targetUserId: null, durationMinutes: 10 };
}
async function ready() {
  const runtime = await telegramPrivateShareRuntime(db, encoded);
  assert.equal(runtime.schemaReady, true);
  assert.ok(runtime.context);
  return runtime as typeof runtime & { context: NonNullable<typeof runtime.context> };
}
function transport(config: TelegramPolicy, uncertain = false) {
  const sent: string[] = [];
  const request: typeof fetch = async (url, init) => {
    assert.equal(String(url), `https://api.telegram.org/bot${config.botToken}/sendMessage`);
    assert.equal(init?.redirect, "manual");
    const body = JSON.parse(String(init?.body));
    assert.ok([config.adminId, config.memberId].includes(body.chat_id));
    assert.deepEqual(body.link_preview_options, { is_disabled: true });
    assert.doesNotMatch(body.text, /synthetic private body/u);
    sent.push(body.text);
    if (uncertain) throw new Error("synthetic lost acknowledgement");
    return Response.json({ ok: true, result: { message_id: sent.length + 100, chat: { id: Number(body.chat_id) } } });
  };
  return { sent, request };
}

test("pins exact migration bytes and requires the applied ledger before enabling any private-share SQL", async () => {
  const bytes = await readFile(new URL(`../migrations/${PRIVATE_SHARE_CREATION_MIGRATION}`, import.meta.url));
  assert.equal(createHash("sha256").update(bytes).digest("hex"), PRIVATE_SHARE_CREATION_SCHEMA_SHA256);
  assert.deepEqual(await telegramPrivateShareRuntime(db, encoded), PRIVATE_SHARE_DISABLED);
  await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
  await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (16,?,?,'applied')")
    .bind(PRIVATE_SHARE_CREATION_MIGRATION, "f".repeat(64)).run();
  assert.deepEqual(await telegramPrivateShareRuntime(db, encoded), PRIVATE_SHARE_DISABLED);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE name=?")
    .bind(PRIVATE_SHARE_CREATION_SCHEMA_SHA256, PRIVATE_SHARE_CREATION_MIGRATION).run();
  const runtime = await ready();
  assert.equal(runtime.context.installation, PRIVATE_SHARE_CREATION_INSTALLATION);
  assert.equal(runtime.context.key.extractable, false);
  assert.deepEqual(await telegramPrivateShareRuntime(db, undefined), { schemaReady: true, context: null });
  assert.deepEqual(await telegramPrivateShareRuntime(db, encoded + "="), { schemaReady: true, context: null });
  const failed = { prepare() { throw new Error("synthetic credential-bearing binding failure"); } } as unknown as D1Database;
  await assert.rejects(telegramPrivateShareRuntime(failed, encoded), /^Error: Telegram private share readiness could not be confirmed\.$/u);
});

test("a missing key skips published creation receipts and does not block ordinary replies", async () => {
  const config = policy("74201");
  const runtime = await ready();
  assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, input(config, 1), runtime.context), "published");
  await acceptTelegramCommand(db, config, { ...input(config, 2), command: "help" });
  const guarded = new Proxy(db, { get(target, property) {
    if (property === "prepare") return (sql: string) => {
      assert.doesNotMatch(sql, /telegram_private_share_creations/u);
      return target.prepare(sql);
    };
    const member = Reflect.get(target, property);
    return typeof member === "function" ? member.bind(target) : member;
  } });
  const { sent, request } = transport(config);
  await drainTelegramReplies(guarded, bucket, config, 4, 10_000, request);
  assert.equal(sent.length, 1);
  assert.doesNotMatch(sent[0], /claim_|\/share/u);
  const state = await db.prepare(`SELECT reply.state FROM telegram_outbox AS reply JOIN telegram_inbox USING(receipt_id)
    WHERE bot_id=? AND update_id=1`).bind(config.botId).first("state");
  assert.equal(state, "pending");
});

test("the returned publication guard is combined with the exact live reply lease and access epoch", async () => {
  const config = policy("74202");
  const runtime = await ready();
  assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, input(config, 1, config.memberId), runtime.context), "published");
  const lease = await claimTelegramReply(db, config.botId, false, true);
  assert.ok(lease?.privateShareCreation);
  const reply = await resolveTelegramPrivateShareCreationReply(db, config, lease, runtime.context);
  assert.ok(reply);
  assert.equal(await beginTelegramPrivateShareCreationReply(db, config, { ...lease, leaseId: crypto.randomUUID() }, reply), false);
  assert.equal(await beginTelegramPrivateShareCreationReply(db, config, { ...lease, attempts: lease.attempts + 1 }, reply), false);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 1)").bind(config.botId, config.memberId, date).run();
  await db.prepare("UPDATE telegram_auth SET allowed=1,message_id=2 WHERE bot_id=? AND user_id=?")
    .bind(config.botId, config.memberId).run();
  assert.equal(await beginTelegramPrivateShareCreationReply(db, config, lease, reply), false);
});

test("private links are sent once and ambiguous sends are never automatically repeated", async () => {
  const runtime = await ready();
  for (const uncertain of [false, true]) {
    const config = policy(uncertain ? "74204" : "74203");
    assert.equal(await acceptTelegramPrivateShareCreation(db, bucket, config, input(config, 1), runtime.context), "published");
    const { sent, request } = transport(config, uncertain);
    await drainTelegramReplies(db, bucket, config, 4, 10_000, request, null, runtime);
    await drainTelegramReplies(db, bucket, config, 4, 10_000, request, null, runtime);
    assert.equal(sent.length, 1);
    assert.match(sent[0], new RegExp(`https://t\\.me/${config.botUsername}\\?start=claim_[A-Za-z0-9_-]{22}`, "u"));
    const state = await db.prepare(`SELECT reply.state FROM telegram_outbox AS reply JOIN telegram_inbox USING(receipt_id)
      WHERE bot_id=? AND update_id=1`).bind(config.botId).first("state");
    assert.equal(state, uncertain ? "uncertain" : "sent");
  }
});

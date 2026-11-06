import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { createPrivateShare, MAX_PRIVATE_SHARE_BYTES } from "../src/private-shares.ts";
import { drainTelegramReplies } from "../src/telegram/delivery.ts";
import {
  acceptTelegramPrivateClaim, beginTelegramPrivateClaim, prepareTelegramPrivateClaim, TELEGRAM_PRIVATE_CLAIM_MARKER,
} from "../src/telegram/private-claims.ts";
import type { TelegramPolicy, TelegramPrivateClaimUpdate } from "../src/telegram/protocol.ts";
import {
  beginTelegramReply, claimTelegramReply, isTelegramMemberAllowed, prepareTelegramPrivateClaimBegin, settleTelegramReply,
} from "../src/telegram/store.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
  r2Buckets: ["NODES"],
});
const migrationDir = new URL("../migrations/", import.meta.url);
let db: D1Database;
let bucket: R2Bucket;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  for (const name of (await readdir(migrationDir)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrationDir), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

after(() => miniflare.dispose());

function policy(botId: string): TelegramPolicy {
  return { botId, botUsername: "Synthetic_Claim_Bot", adminId: "86001", memberId: "86002", groupId: "-1001234567890",
    webhookSecret: "synthetic-webhook-secret", botToken: `${botId}:synthetic-token` };
}

function claim(config: TelegramPolicy, updateId: number, code: string, actorId = config.memberId): TelegramPrivateClaimUpdate {
  return { kind: "private-claim", code, updateId, actorId, chatId: actorId, chatType: "private",
    threadId: null, messageId: 2_000 + updateId, messageDate: 1_800_000_000 };
}

function create(config: TelegramPolicy, options: Partial<Parameters<typeof createPrivateShare>[2]> = {}) {
  return createPrivateShare(db, bucket, { botId: config.botId, senderId: config.adminId, senderName: "Synthetic sender",
    content: "synthetic private content", maxClaims: 1, targetUserId: null, durationMinutes: 10, ...options });
}

function digest(code: string) {
  return createHash("sha256").update(code).digest("hex");
}

async function metadata(config: TelegramPolicy, code: string) {
  const row = await db.prepare("SELECT id, payload_id FROM private_shares WHERE bot_id = ? AND code_sha256 = ?")
    .bind(config.botId, digest(code)).first<{ id: number; payload_id: string }>();
  assert.ok(row);
  return row;
}

async function countClaims(shareId: number): Promise<number> {
  const row = await db.prepare("SELECT count(*) AS count FROM private_share_claims WHERE share_id = ?")
    .bind(shareId).first<{ count: number }>();
  assert.ok(row);
  return row.count;
}

function receipt(config: TelegramPolicy, updateId: number) {
  return db.prepare(`
    SELECT inbox.receipt_id AS id, inbox.receipt_nonce AS marker, claim.code_sha256 AS codeSha256, reply.state, reply.attempts
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
    LEFT JOIN telegram_private_claim AS claim USING (receipt_id)
    WHERE inbox.bot_id = ? AND inbox.update_id = ?
  `).bind(config.botId, updateId).first<{
    id: number; marker: string; codeSha256: string; state: string; attempts: number;
  }>();
}

async function leaseClaim(config: TelegramPolicy, updateId: number) {
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.privateClaim);
  assert.equal(lease.updateId, updateId);
  const begin = prepareTelegramPrivateClaimBegin(db, config, lease);
  assert.ok(begin);
  return { lease, begin };
}

test("admits only an approved ordinary private chat and exempts the claim alone from member revocation", async () => {
  const config = policy("95001");
  const created = await create(config, { targetUserId: config.memberId });
  const row = await metadata(config, created.code);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, 1800000000, 1)")
    .bind(config.botId, config.memberId).run();
  const event = claim(config, 10, created.code);
  for (const invalid of [
    { ...event, updateId: 1, chatId: config.groupId, chatType: "supergroup" as const },
    { ...event, updateId: 2, actorId: "86003", chatId: "86003" },
    { ...event, updateId: 3, threadId: 19 },
    { ...event, updateId: 4, chatId: config.adminId },
  ]) {
    assert.equal(await acceptTelegramPrivateClaim(db, config, invalid), "ignored");
    assert.equal(await receipt(config, invalid.updateId), null);
  }
  const accepted = await Promise.all([
    acceptTelegramPrivateClaim(db, config, event), acceptTelegramPrivateClaim(db, config, event),
  ]);
  assert.deepEqual(accepted.toSorted(), ["accepted", "ignored"]);
  const stored = await receipt(config, 10);
  assert.equal(stored?.marker, TELEGRAM_PRIVATE_CLAIM_MARKER);
  assert.equal(stored?.codeSha256, digest(created.code));
  assert.equal(JSON.stringify(stored).includes(created.code), false);
  assert.equal(await countClaims(row.id), 0);

  const { lease, begin } = await leaseClaim(config, 10);
  assert.equal(await beginTelegramReply(db, config, lease, "allowed"), false);
  const prepared = await prepareTelegramPrivateClaim(db, bucket, config, lease);
  const result = await beginTelegramPrivateClaim(db, config, lease, prepared, begin);
  assert.equal(result?.kind, "claimed");
  assert.equal(await countClaims(row.id), 1);
  assert.equal(await beginTelegramPrivateClaim(db, config, lease, prepared, begin), null);
  await settleTelegramReply(db, config, lease, { kind: "sent", messageId: 20 });
  assert.equal(await isTelegramMemberAllowed(db, config), false);
});

test("a stale lease, changed payload pointer, and invalid R2 body cannot reserve a portion", async () => {
  const config = policy("95002");
  const created = await create(config);
  const row = await metadata(config, created.code);
  assert.equal(await acceptTelegramPrivateClaim(db, config, claim(config, 10, created.code)), "accepted");
  const first = await leaseClaim(config, 10);
  const valid = await prepareTelegramPrivateClaim(db, bucket, config, first.lease);
  assert.equal(valid.kind, "verified");
  await db.prepare("UPDATE telegram_outbox SET lease_until = unixepoch() - 1 WHERE receipt_id = ?")
    .bind(first.lease.receiptId).run();
  assert.equal(await beginTelegramPrivateClaim(db, config, first.lease, valid, first.begin), null);
  assert.equal(await countClaims(row.id), 0);

  await db.prepare("UPDATE telegram_outbox SET state = 'pending', lease_id = NULL, lease_until = NULL WHERE receipt_id = ?")
    .bind(first.lease.receiptId).run();
  const second = await leaseClaim(config, 10);
  const verified = await prepareTelegramPrivateClaim(db, bucket, config, second.lease);
  assert.equal(verified.kind, "verified");
  await db.prepare("UPDATE private_shares SET payload_sha256 = ? WHERE id = ?").bind("a".repeat(64), row.id).run();
  assert.deepEqual(await beginTelegramPrivateClaim(db, config, second.lease, verified, second.begin), { kind: "unavailable" });
  await settleTelegramReply(db, config, second.lease, { kind: "sent", messageId: 20 });
  assert.equal(await countClaims(row.id), 0);

  assert.equal(await acceptTelegramPrivateClaim(db, config, claim(config, 11, created.code)), "accepted");
  const third = await leaseClaim(config, 11);
  const denied = await prepareTelegramPrivateClaim(db, bucket, config, third.lease);
  assert.equal(denied.kind, "unavailable");
  const wrong = { ...third.lease, privateClaim: { codeSha256: "b".repeat(64) } };
  assert.equal(await beginTelegramPrivateClaim(db, config, wrong, denied, third.begin), null);
  assert.deepEqual(await beginTelegramPrivateClaim(db, config, third.lease, denied, third.begin), { kind: "unavailable" });
  assert.equal(await countClaims(row.id), 0);
});

test("the reserve and transition roll back together and concurrent actors cannot overspend", async () => {
  const config = policy("95003");
  const created = await create(config);
  const row = await metadata(config, created.code);
  for (const [updateId, actorId] of [[10, config.memberId], [11, config.adminId]] as const) {
    assert.equal(await acceptTelegramPrivateClaim(db, config, claim(config, updateId, created.code, actorId)), "accepted");
  }
  const first = await leaseClaim(config, 10);
  const second = await leaseClaim(config, 11);
  const [firstPrep, secondPrep] = await Promise.all([
    prepareTelegramPrivateClaim(db, bucket, config, first.lease),
    prepareTelegramPrivateClaim(db, bucket, config, second.lease),
  ]);
  assert.equal(firstPrep.kind, "verified");
  assert.equal(secondPrep.kind, "verified");

  await db.prepare(`
    CREATE TRIGGER reject_fixture_claim BEFORE INSERT ON private_share_claims
    WHEN NEW.share_id = ${row.id}
    BEGIN SELECT RAISE(ABORT, 'synthetic private claim rollback'); END
  `).run();
  try {
    await assert.rejects(beginTelegramPrivateClaim(db, config, first.lease, firstPrep, first.begin), /could not be confirmed/u);
    assert.equal((await receipt(config, 10))?.state, "leased");
    assert.equal(await countClaims(row.id), 0);
  } finally {
    await db.prepare("DROP TRIGGER reject_fixture_claim").run();
  }
  const results = await Promise.all([
    beginTelegramPrivateClaim(db, config, first.lease, firstPrep, first.begin),
    beginTelegramPrivateClaim(db, config, second.lease, secondPrep, second.begin),
  ]);
  assert.deepEqual(results.map((result) => result?.kind).toSorted(), ["claimed", "exhausted"]);
  assert.equal(await countClaims(row.id), 1);
});

test("rechecks expiry at reservation after verifying the payload", async () => {
  const config = policy("95006");
  const created = await create(config);
  const row = await metadata(config, created.code);
  assert.equal(await acceptTelegramPrivateClaim(db, config, claim(config, 10, created.code)), "accepted");
  const { lease, begin } = await leaseClaim(config, 10);
  const prepared = await prepareTelegramPrivateClaim(db, bucket, config, lease);
  assert.equal(prepared.kind, "verified");
  await db.prepare("UPDATE private_shares SET created_at = unixepoch() - 120, expire_at = unixepoch() - 1 WHERE id = ?")
    .bind(row.id).run();
  assert.deepEqual(await beginTelegramPrivateClaim(db, config, lease, prepared, begin), { kind: "expired" });
  assert.equal(await countClaims(row.id), 0);
});

test("sends an exact 64 KiB document once when Telegram's outcome is uncertain", async () => {
  const config = policy("95004");
  const content = "🔒".repeat(MAX_PRIVATE_SHARE_BYTES / 4);
  const created = await create(config, { content });
  const row = await metadata(config, created.code);
  assert.equal(await acceptTelegramPrivateClaim(db, config, claim(config, 10, created.code)), "accepted");

  const requests: { url: string; init: RequestInit | undefined }[] = [];
  const unknown: typeof fetch = async (url, init) => {
    requests.push({ url: String(url), init });
    throw new Error("Synthetic uncertain Telegram response.");
  };
  await drainTelegramReplies(db, bucket, config, 4, 10_000, unknown);
  await drainTelegramReplies(db, bucket, config, 4, 10_000, unknown);
  assert.equal(requests.length, 1);
  assert.equal(requests[0].url, `https://api.telegram.org/bot${config.botToken}/sendDocument`);
  assert.equal(requests[0].init?.redirect, "manual");
  const form = requests[0].init?.body;
  assert.ok(form instanceof FormData);
  assert.equal(form.get("chat_id"), config.memberId);
  const document = form.get("document");
  assert.ok(document instanceof Blob);
  assert.equal(document.size, MAX_PRIVATE_SHARE_BYTES);
  assert.equal(await document.text(), content);
  assert.equal((await receipt(config, 10))?.state, "uncertain");
  assert.equal((await receipt(config, 10))?.attempts, 1);
  assert.equal(await countClaims(row.id), 1);
});

test("a verified Telegram rate limit retries without consuming a second portion", async () => {
  const config = policy("95005");
  const created = await create(config);
  const row = await metadata(config, created.code);
  assert.equal(await acceptTelegramPrivateClaim(db, config, claim(config, 10, created.code)), "accepted");
  const requests: string[] = [];
  const retry: typeof fetch = async (url) => {
    requests.push(String(url));
    if (requests.length === 1) {
      return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 3 } }, { status: 429 });
    }
    return Response.json({ ok: true, result: { chat: { id: Number(config.memberId) }, message_id: 99 } });
  };
  await drainTelegramReplies(db, bucket, config, 4, 10_000, retry);
  const pending = await receipt(config, 10);
  assert.equal(pending?.state, "pending");
  assert.equal(await countClaims(row.id), 1);
  await db.prepare("UPDATE telegram_outbox SET due_at = unixepoch() WHERE receipt_id = ?").bind(pending?.id).run();
  await drainTelegramReplies(db, bucket, config, 4, 10_000, retry);
  assert.deepEqual(requests, Array(2).fill(`https://api.telegram.org/bot${config.botToken}/sendMessage`));
  assert.equal((await receipt(config, 10))?.state, "sent");
  assert.equal((await receipt(config, 10))?.attempts, 2);
  assert.equal(await countClaims(row.id), 1);
});

import {
  legacyPrivateShareAvailable, preparePrivateShareClaim, privateShareClaimStatements, privateShareCodeDigest, readPrivateShareClaimResult,
  type PreparedPrivateShareClaim, type PrivateShareClaimResult,
} from "../private-shares.ts";
import {
  inTelegramScope, type TelegramEventScope, type TelegramLegacyInlineClaim, type TelegramPolicy, type TelegramPrivateClaimUpdate,
} from "./protocol.ts";
import { groupShareClaimGuard, TELEGRAM_GROUP_CLAIM_MARKER } from "./group-share-actions.ts";

export const TELEGRAM_PRIVATE_CLAIM_MARKER = "claim:v1";

interface ClaimLease extends TelegramEventScope {
  receiptId: number;
  leaseId: string;
  attempts: number;
  privateClaim?: { codeSha256: string; group?: true };
}

const sha256 = /^[0-9a-f]{64}(?![\s\S])/u;
const receiptError = "Telegram private claim receipt could not be confirmed.";
const deliveryError = "Telegram private claim delivery could not be confirmed.";

function inPrivateScope(policy: TelegramPolicy, event: TelegramEventScope): boolean {
  return event.chatType === "private" && event.threadId === null && inTelegramScope(policy, event);
}

export async function legacyInlineClaimUrl(
  db: D1Database, policy: TelegramPolicy, { actorId, code }: TelegramLegacyInlineClaim,
): Promise<string | undefined> {
  if (code.length !== 11 || (actorId !== policy.adminId && actorId !== policy.memberId)) return;
  const codeSha256 = await privateShareCodeDigest(code);
  if (codeSha256 === null || !await legacyPrivateShareAvailable(db, { botId: policy.botId, actorId, codeSha256 })) return;
  return `https://t.me/${policy.botUsername}?start=claim_${code}`;
}

export async function acceptTelegramPrivateClaim(
  db: D1Database,
  policy: TelegramPolicy,
  event: TelegramPrivateClaimUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inPrivateScope(policy, event)) return "ignored";
  try {
    const digest = await privateShareCodeDigest(event.code);
    if (digest === null) return "ignored";
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const steps = [
      db.prepare(`
        INSERT INTO telegram_inbox
          (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
        VALUES (?, ?, ?, ?, 'private', ?, ?, ?, 'help', ?)
        ON CONFLICT (bot_id, update_id) DO NOTHING
      `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId,
        event.messageDate, event.threadId, nonce),
      db.prepare(`
        INSERT INTO telegram_private_claim (receipt_id, code_sha256)
        SELECT receipt_id, ? FROM telegram_inbox WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
      `).bind(digest, ...key),
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
      `).bind(...key),
      // Missing companions abort through the existing command NOT NULL constraint.
      db.prepare(`
        UPDATE telegram_inbox SET receipt_nonce = ?, command = CASE WHEN EXISTS (
          SELECT 1 FROM telegram_private_claim JOIN telegram_outbox USING (receipt_id)
          WHERE receipt_id = telegram_inbox.receipt_id AND code_sha256 = ?
        ) THEN command END
        WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
        RETURNING receipt_id
      `).bind(TELEGRAM_PRIVATE_CLAIM_MARKER, digest, ...key),
    ];
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && receipt.results.length <= 1
      && results.every((result) => result.success)) {
      return receipt.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // Avoid exposing the code or private backend details.
  }
  throw new Error(receiptError);
}

export async function prepareTelegramPrivateClaim(
  db: D1Database,
  bucket: R2Bucket,
  policy: TelegramPolicy,
  lease: ClaimLease,
): Promise<PreparedPrivateShareClaim> {
  const codeSha256 = lease.privateClaim?.codeSha256;
  if (!inPrivateScope(policy, lease) || !codeSha256 || !sha256.test(codeSha256)) {
    throw new Error(deliveryError);
  }
  if (lease.privateClaim?.group) {
    const guard = groupShareClaimGuard(policy);
    const allowed = await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id=?
      AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.receipt_nonce=? AND (${guard.sql})`)
      .bind(lease.receiptId, policy.botId, lease.actorId, TELEGRAM_GROUP_CLAIM_MARKER, ...guard.bindings).first();
    if (allowed === null) return { kind: "unavailable", botId: policy.botId, actorId: lease.actorId, codeSha256 };
  }
  return preparePrivateShareClaim(db, bucket, { botId: policy.botId, actorId: lease.actorId, codeSha256 });
}

export async function beginTelegramPrivateClaim(
  db: D1Database,
  policy: TelegramPolicy,
  lease: ClaimLease,
  prepared: PreparedPrivateShareClaim,
  begin: D1PreparedStatement,
): Promise<PrivateShareClaimResult | null> {
  if (!inPrivateScope(policy, lease) || !lease.privateClaim || prepared.botId !== policy.botId
    || prepared.actorId !== lease.actorId || prepared.codeSha256 !== lease.privateClaim.codeSha256) return null;

  try {
    const scope = `SELECT inbox.receipt_id FROM telegram_inbox AS inbox
      JOIN telegram_outbox AS reply USING (receipt_id)
      JOIN telegram_private_claim AS claim USING (receipt_id)
      WHERE inbox.receipt_id = ? AND inbox.bot_id = ? AND inbox.update_id = ?
        AND inbox.actor_id = ? AND inbox.chat_id = inbox.actor_id AND inbox.chat_type = 'private'
        AND inbox.thread_id IS ? AND inbox.message_id = ? AND inbox.message_date = ?
        AND inbox.receipt_nonce = ? AND claim.code_sha256 = ?
        AND reply.state = 'sending' AND reply.lease_id = ? AND reply.attempts = ?`;
    const marker = lease.privateClaim.group ? TELEGRAM_GROUP_CLAIM_MARKER : TELEGRAM_PRIVATE_CLAIM_MARKER;
    const bindings = [lease.receiptId, policy.botId, lease.updateId, lease.actorId, lease.threadId, lease.messageId,
      lease.messageDate, marker, prepared.codeSha256, lease.leaseId, lease.attempts] as const;
    const shareSteps = prepared.kind === "verified"
      ? privateShareClaimStatements(db, prepared, {
        sql: `changes() = 1 AND EXISTS (${scope} AND reply.lease_until > unixepoch())`, bindings,
      }) : [];
    const steps = [begin, ...shareSteps, db.prepare(scope).bind(...bindings)];
    const results = await db.batch<{ receipt_id: number }>(steps);
    const [state] = results;
    const proof = results.at(-1);
    if (!state || !proof || results.length !== steps.length || !results.every((result) => result.success)) {
      throw new Error(deliveryError);
    }
    if (state.results.length === 0) {
      if (shareSteps.length > 0 && results[1].meta.changes !== 0) throw new Error(deliveryError);
      return null;
    }
    if (state.results.length !== 1 || proof.results.length !== 1
      || state.results[0].receipt_id !== lease.receiptId || proof.results[0].receipt_id !== lease.receiptId) {
      throw new Error(deliveryError);
    }
    return prepared.kind === "verified"
      ? readPrivateShareClaimResult(prepared, results[1], results[2]) : { kind: prepared.kind };
  } catch {
    throw new Error(deliveryError);
  }
}

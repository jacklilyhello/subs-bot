import {
  legacyPrivateShareAvailable, preparePrivateShareClaim, privateShareClaimStatements, privateShareCodeDigest, readPrivateShareClaimResult,
  type PreparedPrivateShareClaim, type PrivateShareClaimResult,
} from "../private-shares.ts";
import {
  inTelegramScope, type TelegramEventScope, type TelegramLegacyInlineClaim, type TelegramPolicy, type TelegramPrivateClaimUpdate,
} from "./protocol.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentReceiptSql, generalPolicyBindings,
  prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { generalGroupShareClaimGuard, groupShareClaimGuard, hasGeneralGroupShare, TELEGRAM_GENERAL_GROUP_CLAIM_MARKER,
  TELEGRAM_GROUP_CLAIM_MARKER } from "./group-share-actions.ts";

export const TELEGRAM_PRIVATE_CLAIM_MARKER = "claim:v1";
export const TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER = "general-private-claim:v1";
export const GENERAL_PRIVATE_CLAIM_SCHEMA = `(SELECT /* subs-bot:telegram-general-private-claim:v1 */ count(*)
    FROM subs_bot_schema_migrations WHERE mode='applied' AND (
      (position=5 AND name='0005_private_shares.sql' AND sha256='d7edd0fcd6d2e5223c95940c965ef1eb37d07c8399df111e7f48a719addcfc7f')
      OR (position=7 AND name='0007_telegram_private_claims.sql' AND sha256='d71f9a3f193b4572fce1526ad0d76ab0ebcbd1b28a1aae1504e946f95f913937')
    ))=2`;

type ClaimPolicy = TelegramPolicy | GeneralTelegramPin;

interface ClaimLease extends TelegramEventScope {
  receiptId: number;
  leaseId: string;
  attempts: number;
  privateClaim?: { codeSha256: string; group?: true };
}

const sha256 = /^[0-9a-f]{64}(?![\s\S])/u;
const receiptError = "Telegram private claim receipt could not be confirmed.";
const deliveryError = "Telegram private claim delivery could not be confirmed.";

function inPrivateScope(policy: ClaimPolicy, event: TelegramEventScope): boolean {
  return event.chatType === "private" && event.threadId === null && ("privateClaims" in policy
    ? policy.privateClaims && !policy.rehearsal && event.actorId !== policy.botId && event.chatId === event.actorId
    : inTelegramScope(policy, event));
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
  policy: ClaimPolicy,
  event: TelegramPrivateClaimUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inPrivateScope(policy, event)) return "ignored";
  try {
    const digest = await privateShareCodeDigest(event.code);
    if (digest === null) return "ignored";
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const general = "privateClaims" in policy ? policy : null;
    const origin = [policy.botId, event.updateId, event.actorId, event.chatId, event.messageId,
      event.messageDate, event.threadId, nonce] as const;
    const steps = [
      db.prepare(`
        INSERT INTO telegram_inbox
          (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
        ${general ? `SELECT ?, ?, ?, ?, 'private', ?, ?, ?, 'help', ?
          FROM ${GENERAL_POLICY_ACTORS_SQL}
          WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND ${GENERAL_PRIVATE_CLAIM_SCHEMA}
            AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}
            AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
            AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL})
            AND ?<=unixepoch()+60 AND ${GENERAL_ACTOR_QUEUE_CAPACITY}
            AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)`
          : "VALUES (?, ?, ?, ?, 'private', ?, ?, ?, 'help', ?)"}
        ON CONFLICT (bot_id, update_id) DO NOTHING
      `).bind(...origin, ...(general ? [...generalPolicyBindings(general), event.actorId,
        event.messageDate, event.messageDate, event.updateId] : [])),
      ...(general ? [prepareGeneralReceiptAuthority(db, general, key)] : []),
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
        ) ${general ? "AND EXISTS (SELECT 1 FROM telegram_general_receipt WHERE receipt_id=telegram_inbox.receipt_id)" : ""}
        THEN command END
        WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
        RETURNING receipt_id
      `).bind(general ? TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER : TELEGRAM_PRIVATE_CLAIM_MARKER, digest, ...key),
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
  policy: ClaimPolicy,
  lease: ClaimLease,
): Promise<PreparedPrivateShareClaim> {
  const codeSha256 = lease.privateClaim?.codeSha256;
  if (!inPrivateScope(policy, lease) || !codeSha256 || !sha256.test(codeSha256)) {
    throw new Error(deliveryError);
  }
  if ("privateClaims" in policy) {
    const group = lease.privateClaim?.group;
    if (group && !hasGeneralGroupShare(policy)) throw new Error(deliveryError);
    const marker = group ? TELEGRAM_GENERAL_GROUP_CLAIM_MARKER : TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER;
    const allowed = await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox
      JOIN telegram_outbox AS reply USING (receipt_id) JOIN telegram_private_claim AS claim USING(receipt_id)
      WHERE inbox.receipt_id=? AND inbox.bot_id=? AND inbox.update_id=? AND inbox.actor_id=? AND inbox.chat_id=inbox.actor_id
        AND inbox.chat_type='private' AND inbox.thread_id IS NULL AND inbox.message_id=? AND inbox.message_date=?
        AND inbox.receipt_nonce=? AND claim.code_sha256=? AND reply.state='leased' AND reply.lease_id=?
        AND reply.attempts=? AND reply.lease_until>unixepoch() AND ${GENERAL_PRIVATE_CLAIM_SCHEMA}
        AND ${generalCurrentReceiptSql("inbox")}`)
      .bind(lease.receiptId, policy.botId, lease.updateId, lease.actorId, lease.messageId, lease.messageDate,
        marker, codeSha256, lease.leaseId, lease.attempts, ...generalPolicyBindings(policy)).first();
    let groupAllowed = true;
    if (allowed && group && hasGeneralGroupShare(policy)) {
      const guard = generalGroupShareClaimGuard(policy);
      groupAllowed = Boolean(await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox
        WHERE inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.receipt_nonce=? AND (${guard.sql})`)
        .bind(lease.receiptId, policy.botId, lease.actorId, marker, ...guard.bindings).first());
    }
    if (!allowed || !groupAllowed) return { kind: "unavailable", botId: policy.botId, actorId: lease.actorId, codeSha256 };
  } else if (lease.privateClaim?.group) {
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
  policy: ClaimPolicy,
  lease: ClaimLease,
  prepared: PreparedPrivateShareClaim,
  begin: D1PreparedStatement,
): Promise<PrivateShareClaimResult | null> {
  const general = "privateClaims" in policy;
  if (!inPrivateScope(policy, lease) || !lease.privateClaim || (general && lease.privateClaim.group && !hasGeneralGroupShare(policy))
    || prepared.botId !== policy.botId || prepared.actorId !== lease.actorId || prepared.codeSha256 !== lease.privateClaim.codeSha256) return null;

  try {
    const scope = `SELECT inbox.receipt_id FROM telegram_inbox AS inbox
      JOIN telegram_outbox AS reply USING (receipt_id)
      JOIN telegram_private_claim AS claim USING (receipt_id)
      WHERE inbox.receipt_id = ? AND inbox.bot_id = ? AND inbox.update_id = ?
        AND inbox.actor_id = ? AND inbox.chat_id = inbox.actor_id AND inbox.chat_type = 'private'
        AND inbox.thread_id IS ? AND inbox.message_id = ? AND inbox.message_date = ?
        AND inbox.receipt_nonce = ? AND claim.code_sha256 = ?
        AND reply.state = 'sending' AND reply.lease_id = ? AND reply.attempts = ?`;
    const marker = general
      ? lease.privateClaim.group ? TELEGRAM_GENERAL_GROUP_CLAIM_MARKER : TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER
      : lease.privateClaim.group ? TELEGRAM_GROUP_CLAIM_MARKER : TELEGRAM_PRIVATE_CLAIM_MARKER;
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

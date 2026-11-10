import { digestHex, validInteger } from "../storage.ts";
import { ISOLATION_PUBLIC_ORIGIN } from "../public-origin.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_POLICY_SCHEMA, GENERAL_RECEIPT_SCHEMA } from "./general-receipt.ts";
import { GENERAL_SUBSCRIPTION_READ_MARKER, inTelegramScope, SUBSCRIPTION_READ_RECEIPT_MARKER,
  type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";

export const SUBSCRIPTION_SHORT_CODE = /^[A-Za-z0-9_-]{21}t(?![\s\S])/u;
export const SUBSCRIPTION_SHORT_MIGRATION = "0048_telegram_subscription_short_links.sql";
export const SUBSCRIPTION_SHORT_SHA256 = "166f858e11d4f705ec64ea35184b38ec688ace1b0a5d5ddc5ad4c683391437ad";
export const SUBSCRIPTION_SHORT_PIN = `EXISTS (SELECT 1 FROM subs_bot_schema_migrations
  WHERE position=48 AND mode='applied' AND name='${SUBSCRIPTION_SHORT_MIGRATION}' AND sha256='${SUBSCRIPTION_SHORT_SHA256}')`;
export const SUBSCRIPTION_SHORT_FORMATS = new Set(["clash", "singbox", "base64", "surge", "qx"]);
const MAX_ACTIVE_SHORTS = 128;
const TOKEN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
const NONCE = /^[A-Za-z0-9_-]{21}[AQgw](?![\s\S])/u;
const encoder = new TextEncoder();

type Guard = { sql: string; bindings: readonly (string | number | null)[] };
type Policy = TelegramPolicy | GeneralTelegramPin;
type Lease = { receiptId: number; actorId: string; chatId: string; chatType: TelegramEventScope["chatType"]; threadId: number | null;
  leaseId: string; attempts: number; subscriptionRead?: true };
export type SubscriptionShortTarget = { id: number; format: string; token: string };
export type SubscriptionShortCandidate = {
  code: string; digest: string; nonce: string; id: number; format: string; tokenDigest: string;
};

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function hash(value: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function telegramSubscriptionShortsReady(db: D1Database): Promise<boolean> {
  const count = await db.prepare(`SELECT count(*) AS n FROM sqlite_schema WHERE type='table' AND name IN (
    'telegram_subscription_short_links','telegram_subscription_read','legacy_subscription_short_links',
    'normal_short_links','aggregate_links','subs_bot_schema_migrations') OR (type='index'
    AND name='telegram_subscription_short_links_active' AND tbl_name='telegram_subscription_short_links')`).first<number>("n");
  return count === 7 && await db.prepare(`SELECT ${SUBSCRIPTION_SHORT_PIN} AS ready`).first<number>("ready") === 1;
}

function privateRead(lease: Lease, policy: Policy): boolean {
  return lease.subscriptionRead === true && lease.chatType === "private" && lease.threadId === null
    && ("adminId" in policy ? inTelegramScope(policy, lease)
      : policy.privateFormats && !policy.rehearsal && lease.chatId === lease.actorId && lease.actorId !== policy.botId);
}

const privateFormat = `inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id
  AND inbox.thread_id IS NULL AND action.kind='format'`;
const receiptScope = `inbox.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}' AND ${privateFormat}`;
const generalReadSchema = `${GENERAL_POLICY_SCHEMA} AND ${GENERAL_RECEIPT_SCHEMA}
  AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=18 AND mode='applied'
    AND name='0018_telegram_subscription_reads.sql' AND sha256='382e9e5e7a850e4f38aece8c2a9f0e98fd890203edf7aa83c37212f5ab038e62')`;

// A published bearer relies on its historical grant, including after a later grant changes.
const generalReceiptScope = `inbox.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND ${privateFormat}
  AND inbox.command='help' AND action.auth_message_date=0 AND action.auth_message_id=0 AND ${generalReadSchema}
  AND EXISTS (SELECT 1 FROM telegram_general_receipt AS recorded JOIN telegram_general_actors AS original
    ON original.bot_id=inbox.bot_id AND original.actor_id=inbox.actor_id
      AND original.generation=recorded.generation AND original.revision=recorded.actor_revision
      AND original.role=recorded.actor_role
    WHERE recorded.receipt_id=inbox.receipt_id AND inbox.message_date>MAX(recorded.cutover_at,original.effective_at))`;
function targetScope(general: boolean): string {
  return `${general ? generalReceiptScope : receiptScope} AND action.subscription_id=? AND action.format=?`;
}
const matchesRow = `link.origin_receipt_id=inbox.receipt_id AND link.bot_id=inbox.bot_id AND link.owner_id=inbox.actor_id
  AND link.code_sha256=? AND link.nonce=? AND link.subscription_id=? AND link.format=? AND link.token_sha256=?
  AND link.key_version=1 AND link.revoked_at IS NULL`;
const noConflicts = `NOT EXISTS(SELECT 1 FROM normal_short_links WHERE code_sha256=link.code_sha256)
  AND NOT EXISTS(SELECT 1 FROM legacy_subscription_short_links WHERE code_sha256=link.code_sha256)
  AND NOT EXISTS(SELECT 1 FROM aggregate_links WHERE code_sha256=link.code_sha256)`;

export function isolatedSubscriptionShortOrigin(link: "link" | "typed"): string {
  return `NOT EXISTS (SELECT 1 FROM telegram_inbox AS origin WHERE origin.receipt_id=${link}.origin_receipt_id
    AND origin.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}')`;
}

export function subscriptionShortRevocationOrigin(link: "link" | "typed", general: boolean): string {
  if (!general) return isolatedSubscriptionShortOrigin(link);
  return `EXISTS (SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_subscription_read AS action USING(receipt_id)
    WHERE inbox.receipt_id=${link}.origin_receipt_id AND inbox.bot_id=${link}.bot_id AND inbox.actor_id=${link}.owner_id
      AND action.subscription_id=${link}.subscription_id AND action.format=${link}.format AND (${generalReceiptScope}))`;
}

/** Preflight the format before calling. Only the normalized target and the exact read guard cross this boundary. */
export async function prepareTelegramSubscriptionShort(
  db: D1Database, policy: Policy, lease: Lease, target: SubscriptionShortTarget, guard: Guard,
  key: CryptoKey | null, admissionEnabled: boolean,
): Promise<SubscriptionShortCandidate | null> {
  if (!key || !privateRead(lease, policy) || !validInteger(target.id, 1) || !TOKEN.test(target.token)
    || !SUBSCRIPTION_SHORT_FORMATS.has(target.format)) return null;
  const general = !("adminId" in policy);
  const canIssue = admissionEnabled && ("adminId" in policy || policy.subscriptionShorts === "issue");
  try {
    if (!await telegramSubscriptionShortsReady(db)) return null;
    const row = await db.prepare(`SELECT link.nonce, link.code_sha256 AS digest
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      JOIN telegram_subscription_read AS action USING(receipt_id)
      JOIN subscriptions AS sub ON sub.id=action.subscription_id AND sub.owner_id=inbox.actor_id AND sub.token=? AND sub.generation>0
      LEFT JOIN telegram_subscription_short_links AS link ON link.origin_receipt_id=inbox.receipt_id
      WHERE inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.chat_id=?
        AND reply.state='leased' AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()
        AND ${targetScope(general)} AND (${guard.sql})`)
      .bind(target.token, lease.receiptId, policy.botId, lease.actorId, lease.chatId, lease.leaseId, lease.attempts,
        target.id, target.format, ...guard.bindings).first<{ nonce: string | null; digest: string | null }>();
    if (!row || (row.digest === null && !canIssue) || (row.digest !== null && (row.nonce === null || !NONCE.test(row.nonce)))) return null;
    const nonce = row.nonce ?? base64Url(crypto.getRandomValues(new Uint8Array(16)));
    const tokenDigest = await hash(target.token);
    const material = encoder.encode(JSON.stringify([
      "subs-bot/telegram-short/subscription", 1, ISOLATION_PUBLIC_ORIGIN,
      policy.botId, lease.actorId, target.id, target.format, tokenDigest, nonce,
    ]));
    const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, material));
    const code = base64Url(signature.subarray(0, 16)).slice(0, 21) + "t";
    const digest = await hash(code);
    if (row.digest !== null && digest !== row.digest) return null;
    return { code, digest, nonce, id: target.id, format: target.format, tokenDigest };
  } catch {
    throw new Error("Telegram subscription short link could not be prepared.");
  }
}

function pins(link: SubscriptionShortCandidate) {
  return [link.digest, link.nonce, link.id, link.format, link.tokenDigest] as const;
}

export function subscriptionShortPublicationGuard(candidate: SubscriptionShortCandidate, read: Guard, general = false): Guard {
  const { digest, id, format } = candidate;
  return { sql: `${general ? "/* subs-bot:general-subscription-short-issue:v1 */ " : ""}(${read.sql}) AND (${SUBSCRIPTION_SHORT_PIN}) AND EXISTS (
    SELECT 1 FROM telegram_subscription_read AS action WHERE action.receipt_id=inbox.receipt_id AND ${targetScope(general)})
    AND CASE
      WHEN EXISTS(SELECT 1 FROM telegram_subscription_short_links AS link WHERE ${matchesRow} AND ${noConflicts}) THEN 1
      WHEN EXISTS(SELECT 1 FROM telegram_subscription_short_links WHERE origin_receipt_id=inbox.receipt_id OR code_sha256=?) THEN 0
      WHEN EXISTS(SELECT 1 FROM normal_short_links WHERE code_sha256=?) THEN 0
      WHEN EXISTS(SELECT 1 FROM legacy_subscription_short_links WHERE code_sha256=?) THEN 0
      WHEN EXISTS(SELECT 1 FROM aggregate_links WHERE code_sha256=?) THEN 0
      WHEN EXISTS(SELECT 1 FROM telegram_subscription_short_links WHERE bot_id=inbox.bot_id AND owner_id=inbox.actor_id
        AND revoked_at IS NULL LIMIT 1 OFFSET ${MAX_ACTIVE_SHORTS - 1}) THEN 0 ELSE 1 END`,
  bindings: [...read.bindings, id, format, ...pins(candidate), digest, digest, digest, digest] };
}

export function subscriptionShortSendGuard(candidate: SubscriptionShortCandidate, read: Guard, general = false): Guard {
  return { sql: `(${read.sql}) AND (${SUBSCRIPTION_SHORT_PIN}) AND EXISTS (
    SELECT 1 FROM telegram_subscription_read AS action WHERE action.receipt_id=inbox.receipt_id AND ${targetScope(general)}) AND EXISTS (
    SELECT 1 FROM telegram_subscription_short_links AS link WHERE ${matchesRow} AND ${noConflicts})`,
  bindings: [...read.bindings, candidate.id, candidate.format, ...pins(candidate)] };
}

/** Must immediately follow the exact leased-to-sending update in one D1 batch. */
export function installTelegramSubscriptionShort(db: D1Database, lease: Lease, candidate: SubscriptionShortCandidate): D1PreparedStatement {
  return db.prepare(`INSERT /* subs-bot:subscription-short-write:v1 */ INTO telegram_subscription_short_links
    (code_sha256,nonce,subscription_id,format,token_sha256,origin_receipt_id,bot_id,owner_id,key_version)
    SELECT ?,?,?,?,?,inbox.receipt_id,inbox.bot_id,inbox.actor_id,1 FROM telegram_inbox AS inbox
    JOIN telegram_outbox AS reply USING(receipt_id) WHERE changes()=1 AND inbox.receipt_id=?
      AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'
    ON CONFLICT(origin_receipt_id) DO NOTHING`).bind(...pins(candidate), lease.receiptId, lease.leaseId, lease.attempts);
}

export async function beginSubscriptionShortDelivery(
  db: D1Database, lease: Lease, candidate: SubscriptionShortCandidate, begin: D1PreparedStatement, guard: Guard,
): Promise<boolean> {
  try {
    const [begun, inserted, confirmed] = await db.batch<{ receipt_id: number }>([
      begin, installTelegramSubscriptionShort(db, lease, candidate),
      db.prepare(`SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM telegram_outbox
        WHERE receipt_id=? AND lease_id=? AND attempts=? AND state='sending') OR EXISTS (
          SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id=? AND (${guard.sql})
        ) THEN 1 ELSE json_extract('subscription short guard failed','$') END`)
        .bind(lease.receiptId, lease.leaseId, lease.attempts, lease.receiptId, ...guard.bindings),
    ]);
    const count = begun?.results.length;
    if (!begun?.success || (count !== 0 && count !== 1) || (count === 1 && begun.results[0].receipt_id !== lease.receiptId)
      || !inserted?.success || !validInteger(inserted.meta.changes, 0, count) || !confirmed?.success) throw new Error();
    return count === 1;
  } catch {
    throw new Error("Telegram subscription short link reply could not begin.");
  }
}

export async function resolveSubscriptionShortLocation(db: D1Database, code: string): Promise<string | null> {
  if (!SUBSCRIPTION_SHORT_CODE.test(code)) return null;
  try {
    if (!await telegramSubscriptionShortsReady(db)) return null;
    const digest = await hash(code);
    const lookup = (marker: string, scope: string) => db.prepare(`SELECT ${marker}
        sub.token,link.token_sha256 AS tokenDigest,link.format,inbox.receipt_nonce AS origin
      FROM telegram_subscription_short_links AS link JOIN subscriptions AS sub
        ON sub.id=link.subscription_id AND sub.owner_id=link.owner_id AND sub.generation>0
      JOIN telegram_inbox AS inbox ON inbox.receipt_id=link.origin_receipt_id AND inbox.bot_id=link.bot_id AND inbox.actor_id=link.owner_id
      JOIN telegram_subscription_read AS action ON action.receipt_id=inbox.receipt_id
      JOIN telegram_outbox AS reply ON reply.receipt_id=inbox.receipt_id AND reply.state<>'failed'
      WHERE link.code_sha256=? AND link.key_version=1 AND link.revoked_at IS NULL AND ${SUBSCRIPTION_SHORT_PIN}
        AND (${scope}) AND action.subscription_id=link.subscription_id AND action.format=link.format
        AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id=sub.id OR token=sub.token)
        AND (${noConflicts})`).bind(digest).first<{ token: string; tokenDigest: string; format: string; origin: string }>();
    let row = await lookup("/* subs-bot:subscription-short-read:v1 */",
      `${privateFormat} AND inbox.receipt_nonce IN ('${SUBSCRIPTION_READ_RECEIPT_MARKER}','${GENERAL_SUBSCRIPTION_READ_MARKER}')`);
    if (row?.origin === GENERAL_SUBSCRIPTION_READ_MARKER) {
      row = await lookup("/* subs-bot:general-subscription-short-read:v1 */",
        `${generalReceiptScope} AND reply.state IN ('sending','sent','uncertain')`);
    }
    if (!row || !TOKEN.test(row.token) || !SUBSCRIPTION_SHORT_FORMATS.has(row.format) || await hash(row.token) !== row.tokenDigest) return null;
    return `/sub/${row.token}/${row.format}`;
  } catch {
    throw new Error("Telegram subscription short link could not be resolved.");
  }
}

export async function hasTelegramSubscriptionShort(db: D1Database, policy: Policy, lease: Lease): Promise<boolean> {
  if (!privateRead(lease, policy)) return false;
  return await db.prepare(`SELECT 1 FROM telegram_subscription_short_links AS link
    JOIN telegram_outbox AS reply ON reply.receipt_id=link.origin_receipt_id
    WHERE link.origin_receipt_id=? AND link.bot_id=? AND link.owner_id=?
      AND reply.state='leased' AND reply.lease_id=? AND reply.attempts=?`)
    .bind(lease.receiptId, policy.botId, lease.actorId, lease.leaseId, lease.attempts).first() !== null;
}

/** Use only when this exact attempt has made no Telegram request. */
export async function closeUnsentTelegramSubscriptionShort(db: D1Database, policy: Policy, lease: Lease): Promise<void> {
  if (!privateRead(lease, policy)) return;
  try {
    const result = await db.prepare(`UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL
      WHERE receipt_id=? AND lease_id=? AND attempts=? AND state IN ('leased','sending') AND EXISTS (
        SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_subscription_read AS action USING(receipt_id)
        WHERE inbox.receipt_id=telegram_outbox.receipt_id AND inbox.bot_id=? AND inbox.actor_id=?
          AND ${"adminId" in policy ? receiptScope : generalReceiptScope})`)
      .bind(lease.receiptId, lease.leaseId, lease.attempts, policy.botId, lease.actorId).run();
    if (result.success && validInteger(result.meta.changes, 0, 1)) return;
  } catch {
    // D1 diagnostics stay private.
  }
  throw new Error("Unsent Telegram subscription short link could not close.");
}

export const REVOKE_SUBSCRIPTION_SHORT = `/* subs-bot:subscription-short-retire:v1 */
  revoked_at=max(created_at,unixepoch()),subscription_id=NULL,token_sha256=NULL,format=NULL,nonce=NULL`;

export async function reapFailedTelegramSubscriptionShorts(db: D1Database, botId: string, general = false): Promise<void> {
  try {
    if (!await telegramSubscriptionShortsReady(db)) return;
    const marker = general ? "/* subs-bot:general-subscription-short-retire:v1 */" : "";
    const scope = general ? generalReceiptScope : receiptScope;
    const result = await db.prepare(`UPDATE ${marker} telegram_subscription_short_links SET ${REVOKE_SUBSCRIPTION_SHORT}
      WHERE code_sha256 IN (SELECT link.code_sha256 FROM telegram_subscription_short_links AS link
        JOIN telegram_inbox AS inbox ON inbox.receipt_id=link.origin_receipt_id AND inbox.bot_id=link.bot_id AND inbox.actor_id=link.owner_id
        JOIN telegram_subscription_read AS action USING(receipt_id) JOIN telegram_outbox AS reply USING(receipt_id)
        WHERE link.bot_id=? AND link.revoked_at IS NULL AND reply.state='failed' AND ${scope}
          AND action.subscription_id=link.subscription_id AND action.format=link.format AND ${SUBSCRIPTION_SHORT_PIN}
        ORDER BY link.origin_receipt_id LIMIT 40)`).bind(botId).run();
    if (result.success) return;
  } catch {
    // Only a known failed reply is eligible for retirement.
  }
  throw new Error("Failed Telegram subscription short links could not be retired.");
}

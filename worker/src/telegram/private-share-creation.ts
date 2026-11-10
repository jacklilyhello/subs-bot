import { MAX_PRIVATE_SHARE_BYTES, privateShareCodeDigest } from "../private-shares.ts";
import { ISOLATION_PUBLIC_ORIGIN, type PublicOrigin } from "../public-origin.ts";
import { checkOwnerId, digestHex, getOwnedSubscription, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger,
  type SubscriptionMetadata } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_POLICY_SCHEMA, GENERAL_RECEIPT_SCHEMA, generalCurrentAuthoritySql, generalPolicyBindings,
  generalRecordedOriginSql, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { inTelegramScope, type TelegramEventScope, type TelegramPolicy, type TelegramPrivateShareCreationUpdate } from "./protocol.ts";

export const TELEGRAM_PRIVATE_SHARE_CREATION_MARKER = "share-create:v1";
export const TELEGRAM_GENERAL_SHARE_CREATION_MARKER = "general-share-create:v1";
export const GENERAL_SHARE_CREATION_SCHEMA = `EXISTS (
  SELECT /* subs-bot:telegram-general-private-share-creation:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=16 AND name='0016_telegram_private_share_creation.sql' AND mode='applied'
    AND sha256='ad8be2d0034f2272d873cb6accc2927f73199a512447858a8aecd23b2b696a78')`;
type SharePolicy = TelegramPolicy | GeneralTelegramPin;
const KEY_VERSION = 1;
const MAX_CLAIMS = 100;
const MAX_DURATION_MINUTES = 10_080;
const MAX_COMMAND_UNITS = 4_096;
const MAX_SOURCE_BYTES = 16 * 1024;
const RESERVATION_SECONDS = 600;
const CLEANUP_GRACE_SECONDS = 20 * 60;
const MAX_PENDING_PER_ACTOR = 4;
const CHECK_DELAY_SECONDS = 60;
// Absent abandoned candidates become due again hourly; inspect one per call.
// R2 acknowledgements can be lost with the original isolate, so absence is not final.
const CLEANED_RECHECK_SECONDS = 60 * 60;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/u;
const SUBSCRIPTION_TOKEN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
// The legacy uploader used secrets.token_urlsafe(8).
const LEGACY_UPLOADED_SOURCE = /^uploaded:\/\/[A-Za-z0-9_-]{10}[AEIMQUYcgkosw048](?![\s\S])/u;
const ENCODER = new TextEncoder();
const safeError = "Telegram private share creation could not be confirmed.";

export interface PrivateShareCreationDraft {
  content: string;
  maxClaims: number;
  targetUserId: string | null;
  durationMinutes: number;
}

export type TelegramPrivateShareCreationInput = TelegramEventScope & PrivateShareCreationDraft & { senderName?: string };
export type PrivateShareCreationOutcome = "published" | "pending" | "ignored";
type PrivateShareOptions = Omit<PrivateShareCreationDraft, "content">;
export type TelegramSubscriptionShareSelection = PrivateShareOptions & { subscriptionId: number };
export type TelegramSubscriptionShareOutcome = PrivateShareCreationOutcome | "unavailable";
export interface TelegramPrivateShareCreationKey {
  readonly version: 1;
  readonly installation: string;
  readonly key: CryptoKey;
}

type CreationState = "reserved" | "published" | "abandoned";
interface CreationRow {
  receiptId: number;
  botId: string;
  actorId: string;
  state: CreationState;
  payloadId: string;
  payloadSha256: string;
  payloadBytes: number;
  senderName: string;
  maxClaims: number;
  targetUserId: string | null;
  durationMinutes: number;
  installation: string;
  keyVersion: number;
}

type ReceiptScope = Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId"> & { receiptId: number };
type Guard = { sql: string; bindings: readonly (string | number)[] };
type ReplyRow = { payloadId: string; codeSha256: string; shareId: number; expireAt: number; maxClaims: number };
export interface TelegramPrivateShareCreationReply {
  code: string;
  expireAt: number;
  maxClaims: number;
  guard: Guard;
}

function contentBytes(content: string): Uint8Array<ArrayBuffer> | null {
  if (typeof content !== "string" || content.length > MAX_PRIVATE_SHARE_BYTES || content.trim().length === 0 ||
      /[\ud800-\udfff]/u.test(content)) return null;
  const bytes = ENCODER.encode(content);
  return bytes.byteLength <= MAX_PRIVATE_SHARE_BYTES ? Uint8Array.from(bytes) : null;
}

function parsePrivateShareOptions(options: readonly string[]): PrivateShareOptions | null {
  const seen = new Set<string>();
  let maxClaims = 1;
  let targetUserId: string | null = null;
  let durationMinutes = 10;
  for (const option of options) {
    const match = /^(id|x|s)([0-9]{1,19})(?![\s\S])/iu.exec(option);
    if (!match) return null;
    const field = match[1].toLowerCase();
    const value = match[2];
    if (seen.has(field)) return null;
    seen.add(field);
    if (field === "id") {
      try { checkOwnerId(value); } catch { return null; }
      targetUserId = value;
    } else if (field === "x" && validInteger(Number(value), 1, MAX_CLAIMS)) {
      maxClaims = Number(value);
    } else if (field === "s" && validInteger(Number(value), 1, MAX_DURATION_MINUTES)) {
      durationMinutes = Number(value);
    } else return null;
  }
  return { maxClaims, targetUserId, durationMinutes };
}

/** Parse the argument string after a verified /share command entity. The delimiter owns one separator. */
export function parseTelegramPrivateShareArgs(args: string): PrivateShareCreationDraft | null {
  if (typeof args !== "string" || args.length > MAX_COMMAND_UNITS) return null;
  const separator = /(?:^|[ \t\r\n])--(?:\r\n|[ \t\r\n])/u.exec(args);
  if (!separator) return null;
  const content = args.slice(separator.index + separator[0].length);
  if (!contentBytes(content)) return null;
  const header = args.slice(0, separator.index).trim();
  const options = parsePrivateShareOptions(header === "" ? [] : header.split(/[ \t\r\n]+/u));
  return options ? { content, ...options } : null;
}

export function parseTelegramSubscriptionShareArgs(args: string): TelegramSubscriptionShareSelection | null {
  if (typeof args !== "string" || args.length > MAX_COMMAND_UNITS) return null;
  const [kind, id = "", ...header] = args.trim().split(/[ \t\r\n]+/u);
  if (kind.toLowerCase() !== "sub" || !/^[1-9][0-9]{0,15}(?![\s\S])/u.test(id)) return null;
  const subscriptionId = Number(id);
  if (!validInteger(subscriptionId, 1)) return null;
  const options = parsePrivateShareOptions(header);
  return options ? { subscriptionId, ...options } : null;
}

function subscriptionShareBody(row: SubscriptionMetadata, publicOrigin: PublicOrigin): string | null {
  if (typeof row.token !== "string" || !SUBSCRIPTION_TOKEN.test(row.token) ||
      typeof row.name !== "string" || row.name.length > 512 ||
      typeof row.sourceUrl !== "string" || row.sourceUrl.length > MAX_SOURCE_BYTES ||
      ENCODER.encode(row.sourceUrl).byteLength > MAX_SOURCE_BYTES) return null;
  const name = row.name.replace(/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/gu, " ");
  if (!name.trim()) return null;
  const source = row.sourceUrl;
  let sourceLine = "🌐 来源：本地导入";
  if (source !== "uploaded://telegram-document" && !LEGACY_UPLOADED_SOURCE.test(source)) {
    if (!/^https?:\/\/[^/?#\\]/iu.test(source) || source.trim() !== source ||
        /[\\\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(source)) return null;
    try {
      if (!new URL(source).hostname) return null;
    } catch {
      return null;
    }
    sourceLine = `🌐 原始链接：${source}`;
  }
  return `🏷️ 订阅名称：${name}\n${sourceLine}\n⚡ Clash 配置：${publicOrigin}/sub/${row.token}/clash`;
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export async function importTelegramPrivateShareCreationKey(
  encoded: unknown,
  installation: string,
): Promise<TelegramPrivateShareCreationKey | null> {
  if (typeof encoded !== "string" || !/^[A-Za-z0-9_-]{43}(?![\s\S])/u.test(encoded) ||
      typeof installation !== "string" || !/^[a-z0-9][a-z0-9_-]{0,63}(?![\s\S])/u.test(installation)) return null;
  try {
    const binary = atob(encoded.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (bytes.byteLength !== 32 || base64Url(bytes) !== encoded) return null;
    const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return Object.freeze({ version: KEY_VERSION, installation, key });
  } catch { return null; }
}

async function deriveCode(context: TelegramPrivateShareCreationKey, botId: string, actorId: string, payloadId: string): Promise<string> {
  const value = ENCODER.encode(JSON.stringify([
    "subs-bot/telegram-private-share/claim", context.version, context.installation, botId, actorId, payloadId,
  ]));
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", context.key, value)).subarray(0, 16));
}

function privateScope(policy: SharePolicy, scope: Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId">): boolean {
  return scope.chatType === "private" && scope.threadId === null && ("privateShareCreation" in policy
    ? policy.privateShareCreation && !policy.rehearsal && scope.actorId !== policy.botId && scope.chatId === scope.actorId
    : inTelegramScope(policy, scope));
}

function safeSenderName(value: string | undefined): string {
  if (typeof value !== "string" || value.length > 256 || /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u.test(value)) return "用户";
  const name = value.trim();
  return name && ENCODER.encode(name).byteLength <= 256 ? name : "用户";
}

const fields = `creation.receipt_id AS receiptId, creation.bot_id AS botId, creation.actor_id AS actorId, creation.state,
  creation.payload_id AS payloadId, creation.payload_sha256 AS payloadSha256, creation.payload_bytes AS payloadBytes,
  creation.sender_name AS senderName, creation.max_claims AS maxClaims, creation.target_user_id AS targetUserId,
  creation.duration_minutes AS durationMinutes, creation.installation, creation.key_version AS keyVersion`;
const joinedReceipt = `FROM telegram_private_share_creations AS creation JOIN telegram_inbox AS inbox USING (receipt_id)`;
const exactInbox = `inbox.bot_id = creation.bot_id AND inbox.actor_id = creation.actor_id
  AND inbox.chat_id = creation.actor_id AND inbox.chat_type = 'private' AND inbox.thread_id IS NULL
  AND inbox.message_date = creation.message_date AND inbox.message_id = creation.message_id AND inbox.command = 'help'`;
const authorized = `((creation.actor_id = ? AND creation.auth_message_date = 0 AND creation.auth_message_id = 0)
  OR (creation.actor_id = ? AND COALESCE((SELECT allowed = 1 AND message_date = creation.auth_message_date
    AND message_id = creation.auth_message_id FROM telegram_auth WHERE bot_id = creation.bot_id AND user_id = creation.actor_id
  ), creation.auth_message_date = 0 AND creation.auth_message_id = 0)))`;
function currentTarget(target: "?" | "creation.target_user_id"): string {
  return `COALESCE((SELECT recipient.role IN ('admin','member') AND recipient.effective_at<unixepoch() FROM telegram_general_actors AS recipient
    WHERE recipient.bot_id=policy.bot_id AND recipient.generation=policy.generation AND recipient.actor_id=${target}
    ORDER BY recipient.revision DESC LIMIT 1),0)=1`;
}

function creationAuthority(policy: SharePolicy) {
  if ("privateShareCreation" in policy) {
    const marker = TELEGRAM_GENERAL_SHARE_CREATION_MARKER;
    const matchingInbox = `${exactInbox} AND inbox.receipt_nonce='${marker}'
      AND creation.auth_message_date=0 AND creation.auth_message_id=0`;
    const current = generalCurrentAuthoritySql("inbox",
      `${GENERAL_SHARE_CREATION_SCHEMA} AND (creation.target_user_id IS NULL OR ${currentTarget("creation.target_user_id")})`);
    const bindings = generalPolicyBindings(policy);
    const recorded = `${GENERAL_POLICY_SCHEMA} AND ${GENERAL_RECEIPT_SCHEMA} AND ${GENERAL_SHARE_CREATION_SCHEMA}
      AND ${generalRecordedOriginSql("inbox")}`;
    return { marker, matchingInbox, current, bindings, recorded, recordedBindings: bindings };
  }
  return { marker: TELEGRAM_PRIVATE_SHARE_CREATION_MARKER,
    matchingInbox: `${exactInbox} AND inbox.receipt_nonce='${TELEGRAM_PRIVATE_SHARE_CREATION_MARKER}'`,
    current: authorized, bindings: [policy.adminId, policy.memberId],
    recorded: "creation.actor_id IN (?, ?)", recordedBindings: [policy.adminId, policy.memberId] };
}

const activeReservation = `creation.state = 'reserved' AND creation.reservation_expires_at > unixepoch()
  AND NOT EXISTS (SELECT 1 FROM private_shares WHERE payload_id = creation.payload_id)`;
const actorOrder = `NOT EXISTS (SELECT 1 FROM telegram_private_share_creations AS earlier
  WHERE earlier.bot_id = creation.bot_id AND earlier.actor_id = creation.actor_id AND earlier.state = 'reserved'
    AND earlier.reservation_expires_at > unixepoch() AND earlier.receipt_id < creation.receipt_id)`;
const fresh = "inbox.bot_id = ? AND inbox.update_id = ? AND inbox.receipt_nonce = ?";
const currentMember = `COALESCE((SELECT allowed = 1 AND message_date < ? FROM telegram_auth
  WHERE bot_id = ? AND user_id = ?), 1)`;

async function readEvent(db: D1Database, policy: SharePolicy, event: TelegramPrivateShareCreationInput): Promise<CreationRow | null> {
  const { matchingInbox, recorded, recordedBindings } = creationAuthority(policy);
  return await db.prepare(`SELECT ${fields} ${joinedReceipt} WHERE ${matchingInbox} AND inbox.bot_id = ?
    AND inbox.update_id = ? AND inbox.actor_id = ? AND inbox.message_date = ? AND inbox.message_id = ? AND (${recorded})
  `).bind(policy.botId, event.updateId, event.actorId, event.messageDate, event.messageId, ...recordedBindings).first<CreationRow>();
}

async function reserve(
  db: D1Database,
  policy: SharePolicy,
  event: TelegramPrivateShareCreationInput,
  payloadSha256: string,
  payloadBytes: number,
  senderName: string,
  installation: string,
  source?: SubscriptionMetadata,
): Promise<CreationRow | "unavailable" | null> {
  const receipt = [policy.botId, event.updateId, crypto.randomUUID()] as const;
  const sourceMatches = `EXISTS (SELECT 1 FROM subscriptions WHERE id=? AND owner_id=? AND name=? AND source_url=?
    AND token=? AND generation=? AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=?)`;
  const sourceBindings = source ? [source.id, event.actorId, source.name, source.sourceUrl, source.token,
    source.generation, source.lifecycleRevision] : [];
  const general = "privateShareCreation" in policy;
  const authority = creationAuthority(policy);
  const admit = general ? `EXISTS (SELECT 1 FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND ${GENERAL_SHARE_CREATION_SCHEMA}
      AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at) AND (? IS NULL OR ${currentTarget("?")})
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY}
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?))`
    : `(? = ? OR ${currentMember})`;
  const admitBindings = general ? [...generalPolicyBindings(policy), event.actorId, event.messageDate,
    event.targetUserId, event.targetUserId, event.updateId]
    : [event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId];
  const steps = [
    db.prepare(`
      INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
      SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
      WHERE ? BETWEEN unixepoch() - ${RESERVATION_SECONDS} AND unixepoch() + 60
        AND (${admit})
        AND NOT EXISTS (SELECT 1 FROM telegram_private_share_creations AS newer WHERE newer.bot_id = ?
          AND newer.actor_id = ? AND (newer.message_date, newer.message_id) >= (?, ?))
        AND NOT EXISTS (SELECT 1 FROM telegram_private_share_creations AS pending WHERE pending.bot_id = ?
          AND pending.actor_id = ? AND pending.state = 'reserved' AND pending.reservation_expires_at > unixepoch()
          LIMIT 1 OFFSET ${MAX_PENDING_PER_ACTOR - 1})
        ${source ? `AND ${sourceMatches}` : ""}
      ON CONFLICT (bot_id, update_id) DO NOTHING
    `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, receipt[2],
      event.messageDate, ...admitBindings, policy.botId, event.actorId, event.messageDate, event.messageId, policy.botId, event.actorId, ...sourceBindings),
    ...(general ? [prepareGeneralReceiptAuthority(db, policy, receipt)] : []),
    db.prepare(`
      INSERT INTO telegram_private_share_creations (receipt_id, bot_id, actor_id, message_date, message_id,
        auth_message_date, auth_message_id, state, payload_id, payload_sha256, payload_bytes, sender_name,
        max_claims, target_user_id, duration_minutes, installation, key_version, reservation_expires_at, next_check_at, cleanup_after)
      SELECT inbox.receipt_id, inbox.bot_id, inbox.actor_id, inbox.message_date, inbox.message_id,
        ${general ? "0,0" : `CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_date, 0) END,
        CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_id, 0) END`},
        'reserved', ?, ?, ?, ?, ?, ?, ?, ?, ${KEY_VERSION}, inbox.received_at + ${RESERVATION_SECONDS},
        inbox.received_at, inbox.received_at + ${RESERVATION_SECONDS + CLEANUP_GRACE_SECONDS}
      FROM telegram_inbox AS inbox ${general ? "" : "LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id"}
      WHERE ${fresh}
    `).bind(...(general ? [] : [policy.adminId, policy.adminId]), crypto.randomUUID(), payloadSha256, payloadBytes, senderName,
      event.maxClaims, event.targetUserId, event.durationMinutes, installation, ...receipt),
    db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce = ?, command = CASE WHEN EXISTS (
      SELECT 1 FROM telegram_private_share_creations WHERE receipt_id = inbox.receipt_id
    ) ${general ? "AND EXISTS (SELECT 1 FROM telegram_general_receipt WHERE receipt_id=inbox.receipt_id)" : ""}
      THEN command END WHERE ${fresh} RETURNING receipt_id`).bind(authority.marker, ...receipt),
  ];
  if (source) steps.push(db.prepare(`SELECT ${sourceMatches} AS matched`).bind(...sourceBindings));
  let refused = false;
  try {
    const results = await db.batch(steps);
    if (results.length !== steps.length || results.some(({ success }) => !success)
      || results[source ? results.length - 2 : results.length - 1].results.length > 1) {
      throw new Error(safeError);
    }
    if (source) {
      const rows = results.at(-1)!.results as { matched: number }[];
      if (rows.length !== 1 || (rows[0].matched !== 0 && rows[0].matched !== 1)) throw new Error(safeError);
      refused = rows[0].matched === 0;
    }
  } catch {
    const confirmed = await readEvent(db, policy, event);
    if (confirmed) return confirmed;
    throw new Error(safeError);
  }
  // A previously accepted request may still resume its exact journal even if new admission now fails.
  return await readEvent(db, policy, event) ?? (refused ? "unavailable" : null);
}

function payloadKey(row: CreationRow): string {
  if (!UUID.test(row.payloadId) || !validInteger(row.payloadBytes, 1, MAX_PRIVATE_SHARE_BYTES) ||
      !/^[a-f0-9]{64}(?![\s\S])/u.test(row.payloadSha256)) throw new Error(safeError);
  return `private-shares/${row.payloadId}.txt`;
}

const payloadPurpose = "telegram-private-share-creation-v1";

async function inspectPayload(bucket: R2Bucket, row: CreationRow): Promise<"verified" | "missing" | "unowned"> {
  const object = await bucket.get(payloadKey(row));
  if (!object) return "missing";
  const metadata = object.customMetadata;
  if (object.size !== row.payloadBytes || metadata?.purpose !== payloadPurpose || metadata?.receipt !== String(row.receiptId)) {
    void object.body.cancel().catch(() => {});
    return "unowned";
  }
  const bytes = new Uint8Array(row.payloadBytes);
  const reader = object.body.getReader();
  let offset = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      if (part.value.byteLength > bytes.byteLength - offset) {
        void reader.cancel().catch(() => {});
        return "unowned";
      }
      bytes.set(part.value, offset);
      offset += part.value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
  return offset === row.payloadBytes && digestHex(await crypto.subtle.digest("SHA-256", bytes)) === row.payloadSha256
    ? "verified" : "unowned";
}

function identity(row: CreationRow) {
  return [row.receiptId, row.botId, row.actorId, row.payloadId, row.payloadSha256, row.payloadBytes, row.installation, row.keyVersion] as const;
}

const matchingCreation = `creation.receipt_id = ? AND creation.bot_id = ? AND creation.actor_id = ? AND creation.payload_id = ?
  AND creation.payload_sha256 = ? AND creation.payload_bytes = ? AND creation.installation = ? AND creation.key_version = ?`;
const matchingPublishedShare = `share.id = creation.share_id AND share.bot_id = creation.bot_id AND share.sender_id = creation.actor_id
  AND share.payload_id = creation.payload_id AND share.payload_sha256 = creation.payload_sha256 AND share.payload_bytes = creation.payload_bytes
  AND share.sender_name = creation.sender_name AND share.max_claims = creation.max_claims
  AND share.target_user_id IS creation.target_user_id AND share.expire_at = share.created_at + 60 * creation.duration_minutes`;

async function readOutcome(db: D1Database, policy: SharePolicy, row: CreationRow, codeSha256: string): Promise<PrivateShareCreationOutcome> {
  const { matchingInbox, current, bindings } = creationAuthority(policy);
  const result = await db.prepare(`
    SELECT creation.state, (${activeReservation} AND (${current})) AS active,
      EXISTS (SELECT 1 FROM private_shares AS share JOIN telegram_outbox AS reply ON reply.receipt_id = creation.receipt_id
        WHERE ${matchingPublishedShare} AND share.code_sha256 = ?) AS published
    ${joinedReceipt} WHERE ${matchingInbox} AND ${matchingCreation}
  `).bind(...bindings, codeSha256, ...identity(row))
    .first<{ state: CreationState; active: number; published: number }>();
  if (!result) return "ignored";
  if (result.state === "published") {
    if (result.published !== 1) throw new Error(safeError);
    return "published";
  }
  return result.active === 1 ? "pending" : "ignored";
}

async function publish(
  db: D1Database,
  policy: SharePolicy,
  row: CreationRow,
  codeSha256: string,
): Promise<PrivateShareCreationOutcome> {
  const { matchingInbox, current, bindings } = creationAuthority(policy);
  const target = "privateShareCreation" in policy ? [] : [policy.adminId, policy.memberId];
  const steps = [
    db.prepare(`
      INSERT INTO private_shares (bot_id, code_sha256, sender_id, sender_name, payload_id, payload_sha256, payload_bytes,
        max_claims, target_user_id, expire_at, created_at)
      SELECT creation.bot_id, ?, creation.actor_id, creation.sender_name, creation.payload_id, creation.payload_sha256,
        creation.payload_bytes, creation.max_claims, creation.target_user_id, unixepoch() + 60 * creation.duration_minutes, unixepoch()
      ${joinedReceipt} WHERE ${matchingInbox} AND ${matchingCreation} AND ${activeReservation} AND (${current}) AND ${actorOrder}
        ${target.length ? "AND (creation.target_user_id IS NULL OR creation.target_user_id IN (?, ?))" : ""}
    `).bind(codeSha256, ...identity(row), ...bindings, ...target),
    db.prepare(`
      UPDATE telegram_private_share_creations AS creation SET state = 'published', share_id = (
        SELECT id FROM private_shares WHERE payload_id = creation.payload_id AND bot_id = creation.bot_id
          AND sender_id = creation.actor_id AND code_sha256 = ?
      ) WHERE ${matchingCreation} AND creation.state = 'reserved' AND changes() = 1 RETURNING share_id
    `).bind(codeSha256, ...identity(row)),
    db.prepare(`
      INSERT INTO telegram_outbox (receipt_id)
      SELECT receipt_id FROM telegram_private_share_creations WHERE receipt_id = ? AND state = 'published' AND changes() = 1
    `).bind(row.receiptId),
    db.prepare(`
      SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM private_shares WHERE payload_id = ? AND bot_id = ? AND code_sha256 = ?)
        OR EXISTS (SELECT 1 FROM telegram_private_share_creations AS creation JOIN private_shares AS share
          ON ${matchingPublishedShare} JOIN telegram_outbox AS reply ON reply.receipt_id = creation.receipt_id
          WHERE creation.receipt_id = ? AND creation.state = 'published' AND share.code_sha256 = ?)
        THEN 1 ELSE json_extract('private share publication guard failed', '$') END
    `).bind(row.payloadId, row.botId, codeSha256, row.receiptId, codeSha256),
  ];
  try {
    const results = await db.batch(steps);
    if (results.length !== steps.length || results.some(({ success }) => !success) || results[1].results.length > 1) {
      throw new Error(safeError);
    }
  } catch {
    if (await readOutcome(db, policy, row, codeSha256) === "published") return "published";
    throw new Error(safeError);
  }
  return await readOutcome(db, policy, row, codeSha256);
}

function validCreation(
  policy: SharePolicy,
  event: TelegramEventScope & PrivateShareOptions,
  context: TelegramPrivateShareCreationKey,
): boolean {
  return privateScope(policy, event) && validInteger(event.updateId, 1) && validInteger(event.messageId, 1) &&
    validInteger(event.messageDate, 1) && validInteger(event.maxClaims, 1, MAX_CLAIMS) &&
    validInteger(event.durationMinutes, 1, MAX_DURATION_MINUTES) && context.version === KEY_VERSION &&
    (event.targetUserId === null || ("privateShareCreation" in policy
      ? event.targetUserId !== policy.botId : event.targetUserId === policy.adminId || event.targetUserId === policy.memberId));
}

async function createShare(
  db: D1Database,
  bucket: R2Bucket,
  policy: SharePolicy,
  event: TelegramPrivateShareCreationInput,
  context: TelegramPrivateShareCreationKey,
  source?: SubscriptionMetadata,
): Promise<TelegramSubscriptionShareOutcome> {
  const bytes = contentBytes(event.content);
  if (!bytes) return source ? "unavailable" : "ignored";
  try {
    const payloadDigest = await crypto.subtle.digest("SHA-256", bytes);
    const senderName = safeSenderName(event.senderName);
    const payloadSha256 = digestHex(payloadDigest);
    const row = await reserve(db, policy, event, payloadSha256, bytes.byteLength, senderName, context.installation, source);
    if (row === "unavailable") return row;
    if (!row) return "ignored";
    if (row.payloadSha256 !== payloadSha256 || row.payloadBytes !== bytes.byteLength ||
        row.senderName !== senderName || row.maxClaims !== event.maxClaims || row.targetUserId !== event.targetUserId ||
        row.durationMinutes !== event.durationMinutes || row.installation !== context.installation ||
        row.keyVersion !== context.version) return source ? "unavailable" : "ignored";
    const codeSha256 = await privateShareCodeDigest(await deriveCode(context, row.botId, row.actorId, row.payloadId));
    if (!codeSha256) throw new Error(safeError);
    const outcome = await readOutcome(db, policy, row, codeSha256);
    if (outcome !== "pending") return outcome;

    try {
      await bucket.put(payloadKey(row), bytes, { onlyIf: { etagDoesNotMatch: "*" }, sha256: payloadDigest,
        customMetadata: { purpose: payloadPurpose, receipt: String(row.receiptId) } });
    } catch {
      // An acknowledgement can be lost after R2 stores the object.
    }
    if (await inspectPayload(bucket, row) !== "verified") throw new Error(safeError);
    const published = await publish(db, policy, row, codeSha256);
    if (published === "ignored") {
      // Accelerate the durable sweep when this writer survives a late commit.
      const reopened = await db.prepare(`UPDATE telegram_private_share_creations AS creation
        SET cleaned_at = NULL, next_check_at = min(next_check_at, unixepoch())
        WHERE ${matchingCreation} AND creation.state = 'abandoned' AND creation.cleaned_at IS NOT NULL
          AND NOT EXISTS (SELECT 1 FROM private_shares WHERE payload_id = creation.payload_id)`)
        .bind(...identity(row)).run();
      if (!reopened.success) throw new Error(safeError);
    }
    return published;
  } catch {
    throw new Error(safeError);
  }
}

export async function acceptTelegramPrivateShareCreation(
  db: D1Database,
  bucket: R2Bucket,
  policy: SharePolicy,
  event: TelegramPrivateShareCreationInput,
  context: TelegramPrivateShareCreationKey,
): Promise<PrivateShareCreationOutcome> {
  if (!validCreation(policy, event, context)) return "ignored";
  const outcome = await createShare(db, bucket, policy, event, context);
  return outcome === "unavailable" ? "ignored" : outcome;
}

export async function acceptTelegramSubscriptionShare(
  db: D1Database,
  bucket: R2Bucket,
  policy: TelegramPolicy,
  event: TelegramPrivateShareCreationUpdate & TelegramSubscriptionShareSelection,
  context: TelegramPrivateShareCreationKey,
  publicOrigin: PublicOrigin = ISOLATION_PUBLIC_ORIGIN,
): Promise<TelegramSubscriptionShareOutcome> {
  if (!validCreation(policy, event, context) || !validInteger(event.subscriptionId, 1)) return "ignored";
  try {
    if (event.actorId !== policy.adminId && await db.prepare(`SELECT ${currentMember} AS allowed`)
      .bind(event.messageDate, policy.botId, event.actorId).first<number>("allowed") !== 1) return "ignored";
    const row = await getOwnedSubscription(db, event.actorId, event.subscriptionId);
    if (!row || row.id !== event.subscriptionId || row.ownerId !== event.actorId ||
        !validInteger(row.generation, 0) || !validInteger(row.lifecycleRevision, 0)) return "unavailable";
    const content = subscriptionShareBody(row, publicOrigin);
    if (content === null) return "unavailable";
    return await createShare(db, bucket, policy, { ...event, content }, context, row);
  } catch {
    throw new Error(safeError);
  }
}

/** Resume one exact reservation with a durable body. A missing body still needs a Telegram replay. */
export async function recoverTelegramPrivateShareCreation(
  db: D1Database,
  bucket: R2Bucket,
  policy: SharePolicy,
  context: TelegramPrivateShareCreationKey,
): Promise<PrivateShareCreationOutcome> {
  if (context.version !== KEY_VERSION) return "ignored";
  const { matchingInbox, current, bindings } = creationAuthority(policy);
  try {
    const row = await db.prepare(`SELECT ${fields} ${joinedReceipt} WHERE ${matchingInbox} AND creation.bot_id = ?
      AND creation.installation = ? AND creation.key_version = ? AND creation.next_check_at <= unixepoch()
      AND ${activeReservation} AND (${current}) AND ${actorOrder}
      ORDER BY creation.next_check_at, creation.receipt_id LIMIT 1
    `).bind(policy.botId, context.installation, context.version, ...bindings).first<CreationRow>();
    if (!row) return "ignored";
    if (await inspectPayload(bucket, row) !== "verified") {
      await db.prepare(`UPDATE telegram_private_share_creations AS creation SET next_check_at = unixepoch() + ${CHECK_DELAY_SECONDS}
        WHERE ${matchingCreation} AND ${activeReservation}`).bind(...identity(row)).run();
      return "ignored";
    }
    const codeSha256 = await privateShareCodeDigest(await deriveCode(context, row.botId, row.actorId, row.payloadId));
    if (!codeSha256) throw new Error(safeError);
    return await publish(db, policy, row, codeSha256);
  } catch {
    throw new Error(safeError);
  }
}

/** Resolve only the creator's link and return a predicate for the final outbox send transition. */
export async function resolveTelegramPrivateShareCreationReply(
  db: D1Database,
  policy: SharePolicy,
  scope: ReceiptScope,
  context: TelegramPrivateShareCreationKey,
): Promise<TelegramPrivateShareCreationReply | null> {
  if (!privateScope(policy, scope) || !validInteger(scope.receiptId, 1) || context.version !== KEY_VERSION) return null;
  const { matchingInbox, current, bindings } = creationAuthority(policy);
  try {
    const row = await db.prepare(`SELECT share.payload_id AS payloadId, share.code_sha256 AS codeSha256,
      share.id AS shareId, share.expire_at AS expireAt, share.max_claims AS maxClaims
      ${joinedReceipt} JOIN private_shares AS share ON ${matchingPublishedShare}
      JOIN telegram_outbox AS reply ON reply.receipt_id = creation.receipt_id
      WHERE ${matchingInbox} AND creation.receipt_id = ? AND creation.bot_id = ? AND creation.actor_id = ?
        AND creation.state = 'published' AND creation.installation = ? AND creation.key_version = ${KEY_VERSION}
        AND share.expire_at >= unixepoch() AND (${current})
    `).bind(scope.receiptId, policy.botId, scope.actorId, context.installation, ...bindings).first<ReplyRow>();
    if (!row || !UUID.test(row.payloadId)) return null;
    const code = await deriveCode(context, policy.botId, scope.actorId, row.payloadId);
    if (await privateShareCodeDigest(code) !== row.codeSha256) return null;
    return {
      code, expireAt: row.expireAt, maxClaims: row.maxClaims,
      guard: {
        sql: `inbox.receipt_id = ? AND inbox.bot_id = ? AND inbox.actor_id = ? AND EXISTS (
          SELECT 1 FROM telegram_private_share_creations AS creation JOIN private_shares AS share ON ${matchingPublishedShare}
          WHERE creation.receipt_id = inbox.receipt_id AND ${matchingInbox} AND creation.state = 'published'
            AND creation.installation = ? AND creation.key_version = ${KEY_VERSION}
            AND share.id = ? AND share.payload_id = ? AND share.code_sha256 = ?
            AND share.expire_at = ? AND share.expire_at >= unixepoch() AND (${current})
        )`,
        bindings: [scope.receiptId, policy.botId, scope.actorId, context.installation, row.shareId, row.payloadId, row.codeSha256, row.expireAt,
          ...bindings],
      },
    };
  } catch {
    throw new Error("Telegram private share creation reply could not be resolved.");
  }
}

export function renderTelegramPrivateShareLink(botUsername: string, reply: TelegramPrivateShareCreationReply): string {
  return `私密分享已创建。\nhttps://t.me/${botUsername}?start=claim_${reply.code}\n份数上限：${reply.maxClaims}\n到期时间（UTC）：${new Date(reply.expireAt * 1000).toISOString()}`;
}

const cleanupReady = `creation.state = 'abandoned' AND creation.cleanup_after <= unixepoch()
  AND NOT EXISTS (SELECT 1 FROM private_shares WHERE payload_id = creation.payload_id)`;

/** Inspect at most one due candidate, including previously absent tombstones, with exact ownership and bytes. */
export async function retireAbandonedTelegramPrivateShareCreation(
  db: D1Database,
  bucket: R2Bucket,
  policy: SharePolicy,
): Promise<"retired" | "blocked" | "ignored"> {
  const { matchingInbox, current, bindings, recorded, recordedBindings } = creationAuthority(policy);
  try {
    const abandoned = await db.prepare(`UPDATE telegram_private_share_creations SET state = 'abandoned' WHERE receipt_id = (
      SELECT creation.receipt_id ${joinedReceipt} WHERE ${matchingInbox} AND creation.bot_id = ?
        AND (${recorded}) AND creation.state = 'reserved'
        AND (creation.reservation_expires_at <= unixepoch() OR NOT (${current}))
      ORDER BY creation.reservation_expires_at, creation.receipt_id LIMIT 1
    )`).bind(policy.botId, ...recordedBindings, ...bindings).run();
    if (!abandoned.success) throw new Error(safeError);
    const row = await db.prepare(`SELECT ${fields} ${joinedReceipt} WHERE ${matchingInbox} AND creation.bot_id = ?
      AND (${recorded}) AND ${cleanupReady} AND creation.next_check_at <= unixepoch()
      ORDER BY creation.next_check_at, creation.receipt_id LIMIT 1
    `).bind(policy.botId, ...recordedBindings).first<CreationRow>();
    if (!row) return "ignored";
    const status = await inspectPayload(bucket, row);
    if (status === "unowned") {
      const delayed = await db.prepare(`UPDATE telegram_private_share_creations AS creation
        SET cleaned_at = NULL, next_check_at = unixepoch() + ${CHECK_DELAY_SECONDS}
        WHERE ${matchingCreation} AND ${cleanupReady}`)
        .bind(...identity(row)).run();
      if (!delayed.success) throw new Error(safeError);
      return "blocked";
    }
    const eligible = await db.prepare(`UPDATE telegram_private_share_creations AS creation SET cleaned_at = NULL
      WHERE ${matchingCreation} AND ${cleanupReady} AND EXISTS (
        SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id = creation.receipt_id AND ${matchingInbox} AND (${recorded})
      )`).bind(...identity(row), ...recordedBindings).run();
    if (!eligible.success) throw new Error(safeError);
    if (eligible.meta.changes !== 1) return "ignored";
    const key = payloadKey(row);
    if (status === "verified") await bucket.delete(key);
    if (await bucket.head(key) !== null) throw new Error(safeError);
    const cleaned = await db.prepare(`UPDATE telegram_private_share_creations AS creation
      SET cleaned_at = unixepoch(), next_check_at = unixepoch() + ${CLEANED_RECHECK_SECONDS}
      WHERE ${matchingCreation} AND ${cleanupReady}`).bind(...identity(row)).run();
    if (!cleaned.success) throw new Error(safeError);
    return cleaned.meta.changes === 1 ? "retired" : "ignored";
  } catch {
    throw new Error("Telegram private share candidate retirement could not be confirmed.");
  }
}

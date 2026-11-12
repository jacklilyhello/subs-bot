import {
  canonicalShortDestination, LEGACY_SUBSCRIPTION_SHORT_PIN, NORMAL_CODE_SUFFIX, readShortLinkNamespaces,
  SHORT_CODE, shortCodeDigest, type ShortLinkNamespaces,
} from "../short-links.ts";
import { ISOLATION_PUBLIC_ORIGIN, PRODUCTION_PUBLIC_ORIGIN, type PublicOrigin } from "../public-origin.ts";
import { validInteger } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentAuthoritySql,
  generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { inTelegramScope, type TelegramEventScope, type TelegramPolicy, type TelegramShortLinkUpdate } from "./protocol.ts";
import { REVOKE_SUBSCRIPTION_SHORT, SUBSCRIPTION_SHORT_CODE, SUBSCRIPTION_SHORT_PIN,
  subscriptionShortRevocationOrigin, telegramSubscriptionShortsReady } from "./subscription-shorts.ts";

export const TELEGRAM_SHORT_LINK_MARKER = "short:v1";
export const GENERAL_TELEGRAM_SHORT_MARKER = "general-short:v1";
export const GENERAL_SHORT_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-private-short:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=19 AND name='0019_telegram_short_links.sql' AND mode='applied'
    AND sha256='44cda07068dd84435542771899824c1d4196a1ffdc18f990abcb723e5bdaa3c1')`;
const MAX_ACTIVE_LINKS = 128;
const ENCODER = new TextEncoder();
const NONCE = /^[A-Za-z0-9_-]{21}[AQgw](?![\s\S])/u;
const DIGEST = /^[a-f0-9]{64}(?![\s\S])/u;
const SHORT_PREFIXES = [ISOLATION_PUBLIC_ORIGIN + "/s/", PRODUCTION_PUBLIC_ORIGIN + "/s/"];
const HELP = "短链用法：发送「短链 https://example.com/xxx」或 /short 加链接。撤销时发送 /short revoke 加短码或本地短链。";
const GENERAL_HELP = "短链用法：发送 /short https://example.com/xxx。撤销时发送 /short revoke 加短码或本地短链。";
const fresh = "inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce=?";

type ShortRequest = { kind: "help" | "invalid" } | { kind: "issue"; destination: string } | { kind: "revoke"; code: string };
type Result = "help" | "invalid" | "issued" | "revoked" | "missing" | "limit" | "unavailable";
export type TelegramShortLinkGuard = { sql: string; bindings: readonly (string | number)[] };
export type TelegramShortLinkReply = { kind: "notice"; text: string } | { kind: "link"; text: string; localUrl: string; guard: TelegramShortLinkGuard };
type ShortPolicy = TelegramPolicy | GeneralTelegramPin;
interface ShortLease extends TelegramEventScope {
  receiptId: number;
  leaseId: string;
  attempts: number;
  shortLink?: true;
}

function shortMarker(policy: ShortPolicy): string {
  return "adminId" in policy ? TELEGRAM_SHORT_LINK_MARKER : GENERAL_TELEGRAM_SHORT_MARKER;
}

function ownPrivateScope(policy: ShortPolicy, scope: TelegramEventScope): boolean {
  return scope.chatType === "private" && scope.threadId === null && ("adminId" in policy ? inTelegramScope(policy, scope)
    : policy.privateShort && !policy.rehearsal && scope.chatId === scope.actorId && scope.actorId !== policy.botId);
}

function parseRequest(args: string): ShortRequest {
  if (args.length > 2304) return { kind: "invalid" };
  const text = args.replace(/^ +| +$/gu, "");
  if (!text || /^help$/iu.test(text)) return { kind: "help" };
  const revoke = /^revoke +([^ ]+)(?![\s\S])/iu.exec(text);
  if (revoke) {
    const prefix = SHORT_PREFIXES.find((value) => revoke[1].startsWith(value));
    const code = prefix ? revoke[1].slice(prefix.length) : revoke[1];
    return SHORT_CODE.test(code) ? { kind: "revoke", code } : { kind: "invalid" };
  }
  const destination = canonicalShortDestination(text);
  return destination ? { kind: "issue", destination } : { kind: "invalid" };
}

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function deriveCode(key: CryptoKey, botId: string, actorId: string, nonce: string): Promise<string> {
  // Existing v1 short codes retain their original derivation label.
  const material = ENCODER.encode(JSON.stringify([
    "subs-bot/telegram-short/external", 1, ISOLATION_PUBLIC_ORIGIN, botId, actorId, nonce,
  ]));
  const encoded = base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, material)).subarray(0, 16));
  // A canonical 16-byte Base64URL aggregate code ends in A, Q, g or w.
  // Keep 126 bits of the HMAC and reserve a different final character.
  return encoded.slice(0, 21) + NORMAL_CODE_SUFFIX;
}

export async function acceptTelegramShortLink(
  db: D1Database, policy: ShortPolicy, event: TelegramShortLinkUpdate, key: CryptoKey | null,
  namespaces?: ShortLinkNamespaces,
): Promise<"accepted" | "ignored"> {
  if (!ownPrivateScope(policy, event) ||
      !validInteger(event.updateId, 1) || !validInteger(event.messageDate, 1) || !validInteger(event.messageId, 1)) return "ignored";
  try {
    const isolated = "adminId" in policy ? policy : null;
    const general = "privateShort" in policy ? policy : null;
    const request = parseRequest(event.args);
    const schema = namespaces ?? await readShortLinkNamespaces(db);
    if (general && !schema.normal) return "ignored";
    const nonce = request.kind === "issue" && key ? base64Url(crypto.getRandomValues(new Uint8Array(16))) : null;
    const candidate = nonce && key ? await shortCodeDigest(await deriveCode(key, policy.botId, event.actorId, nonce)) : null;
    const target = request.kind === "issue" ? request.destination : null;
    const revoke = request.kind === "revoke" ? await shortCodeDigest(request.code) : null;
    const typedCode = request.kind === "revoke" && SUBSCRIPTION_SHORT_CODE.test(request.code);
    const typedRevoke = typedCode && Boolean(isolated || general?.subscriptionShorts) && await telegramSubscriptionShortsReady(db);
    const legacyRevoke = isolated && schema.legacySubscription && schema.migrationLedger && request.kind === "revoke" && request.code.length === 12;
    const noLegacyConflict = schema.legacySubscription ? `AND NOT EXISTS (SELECT 1 FROM legacy_subscription_short_links AS reserved
      WHERE reserved.code_sha256=owned.code_sha256)` : "";
    const legacyIssueConflict = schema.legacySubscription
      ? "OR EXISTS (SELECT 1 FROM legacy_subscription_short_links WHERE code_sha256=?)" : "";
    const receipt = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const admission = general ? db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
      FROM ${GENERAL_POLICY_ACTORS_SQL}
      WHERE (${GENERAL_POLICY_PIN_SQL}) AND (${GENERAL_RECEIPT_SCHEMA}) AND (${GENERAL_SHORT_SCHEMA})
        AND (policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}) AND (actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL})
        AND (?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+30)
        AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
        AND (${GENERAL_ACTOR_QUEUE_CAPACITY}) ON CONFLICT(bot_id,update_id) DO NOTHING`)
      .bind(event.updateId, event.messageId, event.messageDate, receipt[2], ...generalPolicyBindings(general),
        event.actorId, event.messageDate, event.messageDate, event.updateId) : db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,'private',?,?,NULL,'help',?
        WHERE ? BETWEEN unixepoch()-900 AND unixepoch()+30 AND (?=? OR COALESCE((
          SELECT allowed=1 AND message_date<? FROM telegram_auth WHERE bot_id=? AND user_id=?
        ),1)) ON CONFLICT(bot_id,update_id) DO NOTHING`)
        .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, receipt[2],
          event.messageDate, event.actorId, isolated!.adminId, event.messageDate, policy.botId, event.actorId);
    const steps = [admission, ...(general ? [prepareGeneralReceiptAuthority(db, general, receipt)] : []),
      db.prepare(`WITH scoped AS (
        SELECT inbox.receipt_id,inbox.bot_id,inbox.actor_id,
          ${typedRevoke ? "typed.code_sha256" : legacyRevoke ? "COALESCE(owned.code_sha256,legacy.code_sha256)" : "owned.code_sha256"} AS owned_hash,
          ${isolated ? `CASE WHEN inbox.actor_id=? THEN 0 ELSE COALESCE(auth.message_date,0) END AS auth_date,
          CASE WHEN inbox.actor_id=? THEN 0 ELSE COALESCE(auth.message_id,0) END AS auth_id` : "0 AS auth_date,0 AS auth_id"}
        FROM telegram_inbox AS inbox ${isolated ? "LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id" : ""}
        LEFT JOIN normal_short_links AS owned ON owned.code_sha256=? AND owned.owner_id=inbox.actor_id
          AND owned.bot_id=inbox.bot_id AND owned.revoked_at IS NULL AND owned.code_length=? ${noLegacyConflict}
        ${typedRevoke ? `LEFT JOIN telegram_subscription_short_links AS typed ON typed.code_sha256=?
          AND typed.owner_id=inbox.actor_id AND typed.bot_id=inbox.bot_id AND typed.revoked_at IS NULL
          AND ${SUBSCRIPTION_SHORT_PIN} AND (${subscriptionShortRevocationOrigin("typed", general !== null)})
          AND NOT EXISTS (SELECT 1 FROM normal_short_links WHERE code_sha256=typed.code_sha256)
          AND NOT EXISTS (SELECT 1 FROM legacy_subscription_short_links WHERE code_sha256=typed.code_sha256)
          AND NOT EXISTS (SELECT 1 FROM aggregate_links WHERE code_sha256=typed.code_sha256)` : ""}
        ${legacyRevoke ? `LEFT JOIN legacy_subscription_short_links AS legacy ON legacy.code_sha256=?
          AND legacy.owner_id=inbox.actor_id AND legacy.bot_id=inbox.bot_id AND legacy.revoked_at IS NULL
          AND ${LEGACY_SUBSCRIPTION_SHORT_PIN}
          AND NOT EXISTS (SELECT 1 FROM normal_short_links WHERE code_sha256=legacy.code_sha256)
          AND NOT EXISTS (SELECT 1 FROM aggregate_links WHERE code_sha256=legacy.code_sha256)` : ""}
        WHERE ${fresh}
      ), classified AS (
        SELECT scoped.*, CASE
          WHEN ? IN ('help','invalid') THEN ?
          WHEN ?='revoke' THEN CASE WHEN owned_hash IS NULL THEN 'missing' ELSE 'revoked' END
          WHEN ? IS NULL OR EXISTS (SELECT 1 FROM normal_short_links WHERE code_sha256=?)
            OR EXISTS (SELECT 1 FROM aggregate_links WHERE code_sha256=?) ${legacyIssueConflict} THEN 'unavailable'
          WHEN EXISTS (SELECT 1 FROM normal_short_links WHERE bot_id=scoped.bot_id AND owner_id=scoped.actor_id
            AND revoked_at IS NULL LIMIT 1 OFFSET ${MAX_ACTIVE_LINKS - 1}) THEN 'limit'
          ELSE 'issued' END AS result FROM scoped
      ) INSERT INTO telegram_short_link_actions (receipt_id,result,code_sha256,auth_message_date,auth_message_id)
      SELECT receipt_id,result,CASE WHEN result='issued' THEN ? WHEN result='revoked' THEN owned_hash END,auth_date,auth_id
      FROM classified`)
        .bind(...(isolated ? [isolated.adminId, isolated.adminId] : []), typedCode ? null : revoke, request.kind === "revoke" ? request.code.length : null,
          ...(typedRevoke || legacyRevoke ? [revoke] : []), ...receipt, request.kind, request.kind, request.kind, candidate, candidate, candidate,
          ...(schema.legacySubscription ? [candidate] : []), candidate),
      db.prepare(`INSERT INTO normal_short_links(code_sha256,code_length,bot_id,owner_id,origin_receipt_id,nonce,key_version,target_url)
        SELECT action.code_sha256,22,inbox.bot_id,inbox.actor_id,inbox.receipt_id,?,1,?
        FROM telegram_inbox AS inbox JOIN telegram_short_link_actions AS action USING(receipt_id)
        WHERE ${fresh} AND action.result='issued'`).bind(nonce, target, ...receipt),
      db.prepare(`UPDATE normal_short_links AS link SET revoked_at=max(created_at,unixepoch()),target_url=NULL
        FROM telegram_inbox AS inbox JOIN telegram_short_link_actions AS action USING(receipt_id)
        WHERE ${fresh} AND action.result='revoked' AND link.code_sha256=action.code_sha256
          AND link.bot_id=inbox.bot_id AND link.owner_id=inbox.actor_id AND link.revoked_at IS NULL`).bind(...receipt),
      ...(typedRevoke ? [db.prepare(`UPDATE telegram_subscription_short_links AS link SET ${REVOKE_SUBSCRIPTION_SHORT}
        FROM telegram_inbox AS inbox JOIN telegram_short_link_actions AS action USING(receipt_id)
        WHERE ${fresh} AND action.result='revoked' AND link.code_sha256=action.code_sha256
          AND link.bot_id=inbox.bot_id AND link.owner_id=inbox.actor_id AND link.revoked_at IS NULL
          AND ${SUBSCRIPTION_SHORT_PIN} AND (${subscriptionShortRevocationOrigin("link", general !== null)})`).bind(...receipt)] : []),
      ...(legacyRevoke ? [db.prepare(`UPDATE legacy_subscription_short_links AS link
        SET revoked_at=max(created_at,unixepoch()),subscription_id=NULL,token_sha256=NULL,format=NULL
        FROM telegram_inbox AS inbox JOIN telegram_short_link_actions AS action USING(receipt_id)
        WHERE ${fresh} AND action.result='revoked' AND link.code_sha256=action.code_sha256
          AND link.bot_id=inbox.bot_id AND link.owner_id=inbox.actor_id AND link.revoked_at IS NULL
          AND ${LEGACY_SUBSCRIPTION_SHORT_PIN}
          AND NOT EXISTS (SELECT 1 FROM normal_short_links WHERE code_sha256=link.code_sha256)
          AND NOT EXISTS (SELECT 1 FROM aggregate_links WHERE code_sha256=link.code_sha256)`).bind(...receipt)] : []),
      db.prepare(`INSERT INTO telegram_outbox(receipt_id) SELECT receipt_id FROM telegram_inbox AS inbox WHERE ${fresh}`).bind(...receipt),
      db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce=?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_short_link_actions AS action JOIN telegram_outbox USING(receipt_id)
        WHERE action.receipt_id=inbox.receipt_id
          AND (action.result NOT IN ('issued','revoked') OR EXISTS (SELECT 1 FROM normal_short_links AS link
            WHERE link.code_sha256=action.code_sha256 AND link.bot_id=inbox.bot_id AND link.owner_id=inbox.actor_id
              AND ((action.result='issued' AND link.origin_receipt_id=inbox.receipt_id AND link.revoked_at IS NULL)
                OR (action.result='revoked' AND link.revoked_at IS NOT NULL)))
            ${typedRevoke ? `OR (action.result='revoked' AND EXISTS (SELECT 1 FROM telegram_subscription_short_links AS typed
              WHERE typed.code_sha256=action.code_sha256 AND typed.bot_id=inbox.bot_id AND typed.owner_id=inbox.actor_id
                AND typed.revoked_at IS NOT NULL AND typed.subscription_id IS NULL AND typed.token_sha256 IS NULL
                AND typed.format IS NULL AND typed.nonce IS NULL))` : ""}
            ${legacyRevoke ? `OR (action.result='revoked' AND EXISTS (SELECT 1 FROM legacy_subscription_short_links AS legacy
              WHERE legacy.code_sha256=action.code_sha256 AND legacy.bot_id=inbox.bot_id AND legacy.owner_id=inbox.actor_id
                AND legacy.revoked_at IS NOT NULL AND legacy.subscription_id IS NULL AND legacy.token_sha256 IS NULL
                AND legacy.format IS NULL))` : ""})
      ) ${general ? `AND (${generalCurrentAuthoritySql("inbox")})` : ""}
      THEN command END WHERE ${fresh} RETURNING receipt_id`).bind(shortMarker(policy),
        ...(general ? generalPolicyBindings(general) : []), ...receipt),
    ];
    const results = await db.batch(steps);
    const confirmed = results.at(-1);
    if (confirmed && results.length === steps.length && results.every(({ success }) => success) && confirmed.results.length <= 1) {
      return confirmed.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // D1 and URL parsing diagnostics can contain the target or bearer.
  }
  throw new Error("Telegram short link receipt could not be confirmed.");
}

function scopeSql(policy: ShortPolicy): string {
  return `inbox.receipt_id=? AND inbox.bot_id=? AND inbox.update_id=? AND inbox.actor_id=? AND inbox.chat_id=?
  AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
  AND inbox.message_id=? AND inbox.message_date=? AND inbox.command='help'
  AND inbox.receipt_nonce='${shortMarker(policy)}'
  AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()`;
}
const exactGrant = `(inbox.actor_id=? OR COALESCE((
  SELECT allowed=1 AND message_date=action.auth_message_date AND message_id=action.auth_message_id
    AND message_date<inbox.message_date FROM telegram_auth WHERE bot_id=inbox.bot_id AND user_id=inbox.actor_id
),action.auth_message_date=0 AND action.auth_message_id=0))`;
const ownedIssuedLink = `link.code_sha256=action.code_sha256 AND link.bot_id=inbox.bot_id
  AND link.owner_id=inbox.actor_id AND link.origin_receipt_id=inbox.receipt_id AND link.code_length=22`;
const activeIssuedLink = `link.revoked_at IS NULL AND link.target_url IS NOT NULL AND NOT EXISTS (
  SELECT 1 FROM aggregate_links WHERE code_sha256=link.code_sha256
)`;

function scopeArgs(policy: ShortPolicy, lease: ShortLease) {
  return [lease.receiptId, policy.botId, lease.updateId, lease.actorId, lease.chatId, lease.messageId,
    lease.messageDate, lease.leaseId, lease.attempts] as const;
}

function privateScope(policy: ShortPolicy, lease: ShortLease): boolean {
  return lease.shortLink === true && ownPrivateScope(policy, lease);
}

const notices: Record<Result, string> = {
  help: HELP,
  invalid: "短链目标或撤销参数无效。\n" + HELP,
  issued: "短链或授权状态已变更，请重新生成。",
  revoked: "短链已撤销。",
  missing: "没有可撤销的短链。",
  limit: "已达到短链数量上限，请先撤销不再需要的链接。",
  unavailable: "暂时无法生成短链，请稍后重试。",
};

export async function prepareTelegramShortLinkReply(
  db: D1Database, policy: ShortPolicy, lease: ShortLease, key: CryptoKey | null,
  publicOrigin: PublicOrigin = ISOLATION_PUBLIC_ORIGIN,
): Promise<TelegramShortLinkReply> {
  if (!privateScope(policy, lease)) return { kind: "notice", text: notices.issued };
  try {
    const fields = `action.result,action.code_sha256 AS digest,link.nonce,link.key_version AS keyVersion,(${activeIssuedLink}) AS active`;
    const target = `FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      JOIN telegram_short_link_actions AS action USING(receipt_id)
      LEFT JOIN normal_short_links AS link ON ${ownedIssuedLink}
      WHERE ${scopeSql(policy)} AND reply.state='leased'`;
    const generalGrant = "action.auth_message_date=0 AND action.auth_message_id=0";
    const lookup = "adminId" in policy ? db.prepare(`SELECT ${fields} ${target} AND ${exactGrant}`)
      .bind(...scopeArgs(policy, lease), policy.adminId) : db.prepare(`WITH candidate AS MATERIALIZED (
        SELECT ${fields},(${generalCurrentAuthoritySql("inbox")}) AS allowed ${target} AND (${generalGrant}) AND (${GENERAL_SHORT_SCHEMA})
      ) SELECT result,digest,nonce,keyVersion,active FROM candidate WHERE allowed`)
      .bind(...generalPolicyBindings(policy), ...scopeArgs(policy, lease));
    const row = await lookup.first<{ result: Result; digest: string | null; nonce: string | null; keyVersion: number | null; active: number }>();
    if (!row) return { kind: "notice", text: notices.issued };
    if (row.result !== "issued") return { kind: "notice", text: "adminId" in policy ? notices[row.result]
      : row.result === "help" ? GENERAL_HELP : row.result === "invalid" ? "短链目标或撤销参数无效。\n" + GENERAL_HELP : notices[row.result] };
    if (!key || row.active !== 1 || row.keyVersion !== 1 || !row.nonce || !NONCE.test(row.nonce) || !row.digest || !DIGEST.test(row.digest)) {
      return { kind: "notice", text: notices.issued };
    }
    const code = await deriveCode(key, policy.botId, lease.actorId, row.nonce);
    if (await shortCodeDigest(code) !== row.digest) return { kind: "notice", text: notices.issued };
    return {
      kind: "link", text: `短链已生成。\n${publicOrigin}/s/${code}`, localUrl: `${publicOrigin}/s/${code}`,
      guard: { sql: `inbox.receipt_nonce='${shortMarker(policy)}' AND EXISTS (
        SELECT 1 FROM telegram_short_link_actions AS action JOIN normal_short_links AS link ON ${ownedIssuedLink}
        WHERE action.receipt_id=inbox.receipt_id AND action.result='issued' AND action.code_sha256=?
          AND link.nonce=? AND link.key_version=1 AND (${activeIssuedLink})
          AND (${"adminId" in policy ? exactGrant : generalGrant})
      )`, bindings: [row.digest, row.nonce, ...("adminId" in policy ? [policy.adminId] : [])] },
    };
  } catch {
    throw new Error("Telegram short link reply could not be confirmed.");
  }
}

export async function confirmTelegramShortLinkSend(
  db: D1Database, policy: TelegramPolicy, lease: ShortLease, guard: TelegramShortLinkGuard,
): Promise<boolean> {
  if (!privateScope(policy, lease)) return false;
  try {
    return await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE ${scopeSql(policy)} AND reply.state='sending' AND (${guard.sql})`).bind(...scopeArgs(policy, lease), ...guard.bindings).first() !== null;
  } catch {
    return false;
  }
}

/** This exact still-leased attempt has not made a Telegram send. */
export async function retireUnsentTelegramShortLink(db: D1Database, policy: ShortPolicy, lease: ShortLease): Promise<void> {
  if (!privateScope(policy, lease)) return;
  try {
    const result = await db.prepare(`UPDATE normal_short_links SET revoked_at=max(created_at,unixepoch()),target_url=NULL
      WHERE origin_receipt_id=? AND bot_id=? AND owner_id=? AND revoked_at IS NULL AND EXISTS (
        SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
        WHERE ${scopeSql(policy)} AND reply.state='leased'
      )`).bind(lease.receiptId, policy.botId, lease.actorId, ...scopeArgs(policy, lease)).run();
    if (result.success) return;
  } catch {
    // Keep D1 diagnostics out of delivery.
  }
  throw new Error("Unsent Telegram short link could not be retired.");
}

export async function reapFailedTelegramShortLinks(db: D1Database, botId: string, general = false): Promise<void> {
  try {
    const origin = `SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id=link.origin_receipt_id
      AND inbox.receipt_nonce='${GENERAL_TELEGRAM_SHORT_MARKER}'`;
    const family = general ? `EXISTS (${origin} AND inbox.bot_id=link.bot_id AND inbox.actor_id=link.owner_id)` : `NOT EXISTS (${origin})`;
    const result = await db.prepare(`UPDATE normal_short_links SET revoked_at=max(created_at,unixepoch()),target_url=NULL
      WHERE code_sha256 IN (SELECT link.code_sha256 FROM normal_short_links AS link
        JOIN telegram_outbox AS reply ON reply.receipt_id=link.origin_receipt_id
        WHERE link.bot_id=? AND link.revoked_at IS NULL AND reply.state='failed' AND (${family})
        ORDER BY link.origin_receipt_id LIMIT 40)`)
      .bind(botId).run();
    if (result.success) return;
  } catch {
    // Keep D1 diagnostics out of recovery.
  }
  throw new Error("Failed Telegram short links could not be retired.");
}

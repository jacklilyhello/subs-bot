import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, generalCurrentAuthoritySql, generalPolicyBindings,
  prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { validInteger } from "../storage.ts";
import { inTelegramScope, readPrivateTelegramCommand, type TelegramInlineConsentUpdate, type TelegramPolicy } from "./protocol.ts";

export const GENERAL_INLINE_CONSENT_MARKER = "general-inline-consent:v1";
export const GENERAL_INLINE_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-private-inline:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=25 AND name='0025_telegram_personal_inline.sql' AND mode='applied'
    AND sha256='2c504b14ca94597925b1703d2f50d211d29addaff8f139b5411be5fd2306b122')`;
export const TELEGRAM_INLINE_CONSENT_MARKER = "inline-consent:v1";
export const TELEGRAM_INLINE_TEMP_CONSENT_MARKER = "inline-consent-temp:v1";
export type TelegramInlineConsentMarker = typeof TELEGRAM_INLINE_CONSENT_MARKER | typeof TELEGRAM_INLINE_TEMP_CONSENT_MARKER;
export type TelegramInlineConsentReply = TelegramInlineConsentUpdate["kind"] | "stale";
const CONSENT_SECONDS = 900;
const COMMAND_FRESHNESS_SECONDS = 60;
type InlinePolicy = TelegramPolicy | GeneralTelegramPin;

export function readGeneralInlineConsent(
  update: Record<string, unknown>, updateId: number, pin: GeneralTelegramPin,
): TelegramInlineConsentUpdate | null {
  const event = readPrivateTelegramCommand(update, pin.botUsername);
  if (!pin.privateInline || pin.rehearsal || !event || event.name !== "inline" || event.actorId === pin.botId) return null;
  const command = event.remainder.trim().toLowerCase();
  if (command !== "" && command !== "on" && command !== "off") return null;
  return { updateId, actorId: event.actorId, chatId: event.actorId, chatType: "private", threadId: null,
    messageId: event.messageId, messageDate: event.messageDate, kind: command === "" ? "usage" : command };
}

function consentFamily(receipt: string, general: boolean): string {
  const hasGeneralOrigin = `EXISTS (SELECT 1 FROM telegram_inbox AS origin WHERE origin.receipt_id=${receipt}
    AND origin.receipt_nonce='${GENERAL_INLINE_CONSENT_MARKER}')`;
  return general ? hasGeneralOrigin : `NOT (${hasGeneralOrigin})`;
}

export function inlineSearchReceiptFamily(receipt: string, general: boolean): string {
  return consentFamily(`${receipt}.consent_receipt_id`, general);
}

export function telegramInlineConsentMarker(alias: string): string {
  return `${alias}.receipt_nonce IN ('${TELEGRAM_INLINE_CONSENT_MARKER}','${TELEGRAM_INLINE_TEMP_CONSENT_MARKER}')`;
}

export async function telegramInlineSearchReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table' AND name IN (
      'telegram_inline_sort_preferences','telegram_inline_search_consent','telegram_inline_search_receipts')`).first<number>("present");
    if (row !== null) return row === 3;
  } catch {
    // Preserve a generic webhook failure for a database error.
  }
  throw new Error("Telegram inline search schema could not be confirmed.");
}

export async function acceptTelegramInlineConsent(
  db: D1Database, policy: InlinePolicy, event: TelegramInlineConsentUpdate,
): Promise<"accepted" | "ignored"> {
  const isolated = "adminId" in policy ? policy : null;
  const general = "privateManagement" in policy ? policy : null;
  if (event.chatType !== "private" || event.threadId !== null || event.actorId !== event.chatId
    || (isolated ? !inTelegramScope(isolated, event) : !general?.privateInline || general.rehearsal
      || event.actorId === general.botId || event.kind === "temp-on")
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  try {
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    // An older opt-out can still close a live consent. The ordering guard below protects newer choices.
    const maxAge = COMMAND_FRESHNESS_SECONDS + (event.kind === "off" ? CONSENT_SECONDS : 0);
    const role = event.actorId === isolated?.adminId ? "admin" : "member";
    const temp = event.kind === "temp-on";
    const kind = temp ? "on" : event.kind;
    const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
    const insert = `INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)`;
    const admission = general ? db.prepare(`${insert}
      SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
      FROM ${GENERAL_POLICY_ACTORS_SQL}
      WHERE (${GENERAL_POLICY_PIN_SQL}) AND (${GENERAL_RECEIPT_SCHEMA}) AND (${GENERAL_INLINE_SCHEMA})
        AND (policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}) AND (actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL})
        AND (?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-?) AND ?<=unixepoch()+30)
        AND (${GENERAL_ACTOR_QUEUE_CAPACITY}) AND NOT EXISTS (
          SELECT 1 FROM telegram_inline_search_receipts WHERE bot_id=policy.bot_id AND update_id=?)
        AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(event.updateId, event.messageId, event.messageDate, key[2],
        ...generalPolicyBindings(general), event.actorId, event.messageDate, maxAge, event.messageDate, event.updateId, event.updateId)
      : db.prepare(`${insert}
      SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE ? BETWEEN unixepoch()-? AND unixepoch()+30
        AND (?=? OR COALESCE((SELECT allowed=1 AND message_date<? FROM telegram_auth WHERE bot_id=? AND user_id=?),1))
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(policy.botId, event.updateId, event.actorId, event.chatId,
        event.messageId, event.messageDate, key[2], event.messageDate, maxAge, event.actorId, isolated!.adminId,
        event.messageDate, policy.botId, event.actorId);
    const from = general ? `JOIN telegram_general_receipt AS recorded USING(receipt_id)`
      : `LEFT JOIN telegram_auth AS auth
          ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id AND incoming.actor_id<>?`;
    const auth = general ? "recorded.actor_role AS role,0 AS auth_date,0 AS auth_id"
      : "COALESCE(auth.message_date,0) AS auth_date,COALESCE(auth.message_id,0) AS auth_id";
    const steps = [admission, ...(general ? [prepareGeneralReceiptAuthority(db, general, key)] : []),
      db.prepare(`WITH classified AS (
        SELECT incoming.receipt_id,incoming.bot_id,incoming.actor_id,incoming.message_date,incoming.update_id,
          CASE WHEN ? IN ('on','off') AND EXISTS (SELECT 1 FROM telegram_inline_search_consent AS newer
            WHERE newer.bot_id=incoming.bot_id AND newer.actor_id=incoming.actor_id AND newer.kind IN ('on','off')
              AND ${consentFamily("newer.receipt_id", Boolean(general))}
              AND (newer.message_date,newer.update_id)>(incoming.message_date,incoming.update_id)) THEN 'stale' ELSE ? END AS kind,
          ${auth}
        FROM telegram_inbox AS incoming ${from} WHERE ${fresh}
      ) INSERT INTO telegram_inline_search_consent
        (receipt_id,bot_id,actor_id,kind,message_date,update_id,expires_at,actor_role,auth_message_date,auth_message_id)
        SELECT receipt_id,bot_id,actor_id,kind,message_date,update_id,CASE WHEN kind='on' THEN unixepoch()+${CONSENT_SECONDS} END,
          ${general ? "role" : "?"},auth_date,auth_id FROM classified`)
        .bind(kind, kind, ...(isolated ? [isolated.adminId] : []), ...key, ...(isolated ? [role] : [])),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming
        SET receipt_nonce=CASE WHEN ?=1 AND EXISTS (SELECT 1 FROM telegram_inline_search_consent
          WHERE receipt_id=incoming.receipt_id AND kind='on') THEN ? ELSE ? END,
        command=CASE WHEN EXISTS (SELECT 1 FROM telegram_inline_search_consent JOIN telegram_outbox USING(receipt_id)
          WHERE receipt_id=incoming.receipt_id) ${general ? `AND (${generalCurrentAuthoritySql("incoming")})` : ""}
          THEN command END WHERE ${fresh} RETURNING receipt_id`)
        .bind(Number(temp), TELEGRAM_INLINE_TEMP_CONSENT_MARKER, general ? GENERAL_INLINE_CONSENT_MARKER : TELEGRAM_INLINE_CONSENT_MARKER,
          ...(general ? generalPolicyBindings(general) : []), ...key)];
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && results.every(({ success }) => success) && receipt.results.length <= 1) {
      return receipt.results.length ? "accepted" : "ignored";
    }
  } catch {
    // Return only a fixed admission failure.
  }
  throw new Error("Telegram inline search consent could not be confirmed.");
}

export function activeInlineConsent(
  policy: InlinePolicy, marker?: TelegramInlineConsentMarker,
): { sql: string; bindings: readonly (string | number)[] } {
  const general = "privateManagement" in policy;
  const latest = `consent.kind='on' AND consent.expires_at>unixepoch()
    AND consent.receipt_id=(SELECT latest.receipt_id FROM telegram_inline_search_consent AS latest
      WHERE latest.bot_id=consent.bot_id AND latest.actor_id=consent.actor_id AND latest.kind IN ('on','off')
        AND ${consentFamily("latest.receipt_id", general)}
      ORDER BY latest.message_date DESC,latest.update_id DESC LIMIT 1)`;
  if (general) {
    return { sql: `(${latest}) AND (${GENERAL_INLINE_SCHEMA}) AND EXISTS (
      SELECT 1 FROM telegram_inbox AS origin JOIN telegram_general_receipt AS recorded USING(receipt_id)
      WHERE (origin.receipt_id=consent.receipt_id AND origin.bot_id=consent.bot_id AND origin.actor_id=consent.actor_id)
        AND (origin.chat_id=origin.actor_id AND origin.chat_type='private' AND origin.thread_id IS NULL AND origin.command='help')
        AND (origin.receipt_nonce='${GENERAL_INLINE_CONSENT_MARKER}' AND origin.update_id=consent.update_id AND origin.message_date=consent.message_date)
        AND (recorded.actor_role=consent.actor_role AND consent.auth_message_date=0 AND consent.auth_message_id=0)
        AND (${generalCurrentAuthoritySql("origin")})
    )`, bindings: generalPolicyBindings(policy) };
  }
  return { sql: `(${latest})
    AND EXISTS (SELECT 1 FROM telegram_inbox AS origin WHERE origin.receipt_id=consent.receipt_id
      AND origin.bot_id=consent.bot_id AND origin.actor_id=consent.actor_id AND origin.chat_id=origin.actor_id
      AND origin.chat_type='private' AND origin.thread_id IS NULL AND origin.command='help'
      AND ${marker === undefined ? telegramInlineConsentMarker("origin") : "origin.receipt_nonce=?"} AND origin.update_id=consent.update_id
      AND origin.message_date=consent.message_date)
    AND ((consent.actor_id=? AND consent.actor_role='admin' AND consent.auth_message_date=0 AND consent.auth_message_id=0) OR (
      consent.actor_id=? AND consent.actor_role='member' AND consent.message_date>consent.auth_message_date AND COALESCE((
        SELECT allowed=1 AND message_date=consent.auth_message_date AND message_id=consent.auth_message_id
        FROM telegram_auth WHERE bot_id=consent.bot_id AND user_id=consent.actor_id
      ),consent.auth_message_date=0 AND consent.auth_message_id=0)))`,
  bindings: marker === undefined ? [policy.adminId, policy.memberId] : [marker, policy.adminId, policy.memberId] };
}

export function renderTelegramInlineConsent(kind: TelegramInlineConsentReply): string {
  switch (kind) {
    case "on": return "已开启私聊内联搜索，有效期 15 分钟。可发送 /inline off 关闭。";
    case "temp-on": return "已开启私聊内联搜索及临时节点名称，有效期 15 分钟。可发送 /inline off 关闭。";
    case "off": return "已关闭私聊内联搜索。";
    case "stale": return "内联搜索设置已有更新。";
    case "usage": return "用法：/inline on 搜索订阅，/inline temp on 同时搜索临时节点，均有效 15 分钟。/inline off 关闭。用 /i 设置订阅排序。";
  }
}

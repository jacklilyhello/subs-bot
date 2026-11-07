import { validInteger } from "../storage.ts";
import { inTelegramScope, type TelegramInlineConsentUpdate, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_INLINE_CONSENT_MARKER = "inline-consent:v1";
export type TelegramInlineConsentReply = "on" | "off" | "usage" | "stale";
const CONSENT_SECONDS = 900;
const COMMAND_FRESHNESS_SECONDS = 60;

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
  db: D1Database, policy: TelegramPolicy, event: TelegramInlineConsentUpdate,
): Promise<"accepted" | "ignored"> {
  if (event.chatType !== "private" || event.threadId !== null || !inTelegramScope(policy, event)
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  try {
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    // An older opt-out can still close a live consent. The ordering guard below protects newer choices.
    const maxAge = COMMAND_FRESHNESS_SECONDS + (event.kind === "off" ? CONSENT_SECONDS : 0);
    const role = event.actorId === policy.adminId ? "admin" : "member";
    const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
    const steps = [db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE ? BETWEEN unixepoch()-? AND unixepoch()+30
        AND (?=? OR COALESCE((SELECT allowed=1 AND message_date<? FROM telegram_auth WHERE bot_id=? AND user_id=?),1))
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(policy.botId, event.updateId, event.actorId, event.chatId,
      event.messageId, event.messageDate, key[2], event.messageDate, maxAge, event.actorId, policy.adminId, event.messageDate,
      policy.botId, event.actorId), db.prepare(`WITH classified AS (
      SELECT incoming.receipt_id,incoming.bot_id,incoming.actor_id,incoming.message_date,incoming.update_id,
        CASE WHEN ? IN ('on','off') AND EXISTS (SELECT 1 FROM telegram_inline_search_consent AS newer
          WHERE newer.bot_id=incoming.bot_id AND newer.actor_id=incoming.actor_id AND newer.kind IN ('on','off')
            AND (newer.message_date,newer.update_id)>(incoming.message_date,incoming.update_id)) THEN 'stale' ELSE ? END AS kind,
        COALESCE(auth.message_date,0) AS auth_date,COALESCE(auth.message_id,0) AS auth_id
      FROM telegram_inbox AS incoming LEFT JOIN telegram_auth AS auth
        ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id AND incoming.actor_id<>? WHERE ${fresh}
    ) INSERT INTO telegram_inline_search_consent
      (receipt_id,bot_id,actor_id,kind,message_date,update_id,expires_at,actor_role,auth_message_date,auth_message_id)
      SELECT receipt_id,bot_id,actor_id,kind,message_date,update_id,CASE WHEN kind='on' THEN unixepoch()+${CONSENT_SECONDS} END,
        ?,auth_date,auth_id FROM classified`).bind(event.kind, event.kind, policy.adminId, ...key, role), db.prepare(`INSERT INTO telegram_outbox (receipt_id)
      SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key), db.prepare(`UPDATE telegram_inbox AS incoming
      SET receipt_nonce=?,command=CASE WHEN EXISTS (SELECT 1 FROM telegram_inline_search_consent JOIN telegram_outbox USING(receipt_id)
        WHERE receipt_id=incoming.receipt_id) THEN command END WHERE ${fresh} RETURNING receipt_id`)
      .bind(TELEGRAM_INLINE_CONSENT_MARKER, ...key)];
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

export function activeInlineConsent(policy: TelegramPolicy): { sql: string; bindings: readonly string[] } {
  return { sql: `consent.kind='on' AND consent.expires_at>unixepoch()
    AND consent.receipt_id=(SELECT latest.receipt_id FROM telegram_inline_search_consent AS latest
      WHERE latest.bot_id=consent.bot_id AND latest.actor_id=consent.actor_id AND latest.kind IN ('on','off')
      ORDER BY latest.message_date DESC,latest.update_id DESC LIMIT 1)
    AND EXISTS (SELECT 1 FROM telegram_inbox AS origin WHERE origin.receipt_id=consent.receipt_id
      AND origin.bot_id=consent.bot_id AND origin.actor_id=consent.actor_id AND origin.chat_id=origin.actor_id
      AND origin.chat_type='private' AND origin.thread_id IS NULL AND origin.command='help'
      AND origin.receipt_nonce='${TELEGRAM_INLINE_CONSENT_MARKER}' AND origin.update_id=consent.update_id
      AND origin.message_date=consent.message_date)
    AND ((consent.actor_id=? AND consent.actor_role='admin' AND consent.auth_message_date=0 AND consent.auth_message_id=0) OR (
      consent.actor_id=? AND consent.actor_role='member' AND consent.message_date>consent.auth_message_date AND COALESCE((
        SELECT allowed=1 AND message_date=consent.auth_message_date AND message_id=consent.auth_message_id
        FROM telegram_auth WHERE bot_id=consent.bot_id AND user_id=consent.actor_id
      ),consent.auth_message_date=0 AND consent.auth_message_id=0)))`, bindings: [policy.adminId, policy.memberId] };
}

export function renderTelegramInlineConsent(kind: TelegramInlineConsentReply): string {
  switch (kind) {
    case "on": return "已开启私聊内联搜索，有效期 15 分钟。可发送 /inline off 关闭。";
    case "off": return "已关闭私聊内联搜索。";
    case "stale": return "内联搜索设置已有更新。";
    case "usage": return "用法：/inline on 开启 15 分钟，/inline off 关闭。用 /i 设置排序。";
  }
}

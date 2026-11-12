import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { generalManagementAdmission, generalManagementScope } from "./general-management.ts";
import { generalCurrentReceiptSql, generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { validInteger } from "../storage.ts";
import { inTelegramScope, type TelegramInlineSortMode, type TelegramInlineSortUpdate, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_INLINE_SORT_MARKER = "inline-sort:v1";
export const GENERAL_INLINE_SORT_MARKER = "general-inline-sort:v1";
export const GENERAL_INLINE_SORT_SCHEMA = `EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=20
  AND name='0020_telegram_inline_sort.sql' AND mode='applied'
  AND sha256='b5cb5734a1251f4767df0758fceae4a73f2f64cdeea48cad4fd86d70ed946cd1')`;
type SortPolicy = TelegramPolicy | GeneralTelegramPin;

export type TelegramInlineSortReply = {
  kind: "current" | "saved" | "stale" | "usage";
  mode: TelegramInlineSortMode | null;
};

const USAGE = "用法：\n/i 默认 设置默认排序\n/i 流量 按剩余流量排序\n/i 到期 按到期时间排序\n/i 名称 按名称排序";
const MODE_LABELS: Record<TelegramInlineSortMode, string> = { default: "默认", traffic: "流量", expiry: "到期", name: "名称" };
const FRESH_RECEIPT = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";

export async function telegramInlineSortReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type = 'table'
      AND name IN ('telegram_inline_sort_preferences', 'telegram_inline_sort_reply')`).first<{ present: number }>();
    if (row) return row.present === 2;
  } catch {
    // A database failure differs from a deployment with the optional schema still absent.
  }
  throw new Error("Telegram inline sort schema could not be confirmed.");
}

export async function telegramGeneralInlineSortReady(db: D1Database): Promise<boolean> {
  return await telegramInlineSortReady(db)
    && await db.prepare(`SELECT 1 WHERE ${GENERAL_INLINE_SORT_SCHEMA}`).first() !== null;
}

export async function acceptTelegramInlineSort(
  db: D1Database, policy: SortPolicy, event: TelegramInlineSortUpdate,
): Promise<"accepted" | "ignored"> {
  const general = "privateManagement" in policy ? policy : null;
  const isolated = "adminId" in policy ? policy : null;
  if (event.chatType !== "private" || event.threadId !== null
    || (general ? !generalManagementScope(general, event) : !inTelegramScope(isolated!, event))
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  try {
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const order = "(preference.message_date, preference.update_id) = (incoming.message_date, incoming.update_id)";
    const admission = general ? generalManagementAdmission(general, event, GENERAL_INLINE_SORT_SCHEMA) : null;
    const statements = [general && admission ? db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',? ${admission.sql}
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(event.updateId, event.messageId, event.messageDate, nonce, ...admission.bindings)
      : db.prepare(`
      INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
      SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
      WHERE ? BETWEEN unixepoch() - 900 AND unixepoch() + 30
        AND (? = ? OR COALESCE((SELECT allowed = 1 AND message_date < ? FROM telegram_auth
          WHERE bot_id = ? AND user_id = ?), 1))
      ON CONFLICT (bot_id, update_id) DO NOTHING
    `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce,
      event.messageDate, event.actorId, isolated!.adminId, event.messageDate, policy.botId, event.actorId)];
    if (general) statements.push(prepareGeneralReceiptAuthority(db, general, key));

    if (event.kind === "set") {
      statements.push(db.prepare(`
        INSERT INTO telegram_inline_sort_preferences (bot_id, actor_id, mode, message_date, update_id)
        SELECT incoming.bot_id, incoming.actor_id, ?, incoming.message_date, incoming.update_id
        FROM telegram_inbox AS incoming WHERE ${FRESH_RECEIPT}
        ON CONFLICT (bot_id, actor_id) DO UPDATE SET
          mode = excluded.mode, message_date = excluded.message_date, update_id = excluded.update_id
        WHERE (excluded.message_date, excluded.update_id) >
          (telegram_inline_sort_preferences.message_date, telegram_inline_sort_preferences.update_id)
      `).bind(event.mode, ...key));
    }

    statements.push(db.prepare(`
      INSERT INTO telegram_inline_sort_reply (receipt_id, kind, mode, auth_message_date, auth_message_id)
      SELECT incoming.receipt_id,
        CASE WHEN ? = 'set' THEN CASE WHEN ${order} THEN 'saved' ELSE 'stale' END ELSE ? END,
        CASE WHEN ? = 'current' THEN COALESCE(preference.mode, 'default')
          WHEN ? = 'set' AND ${order} THEN preference.mode END,
        ${general ? "0,0" : "COALESCE(auth.message_date, 0), COALESCE(auth.message_id, 0)"}
      FROM telegram_inbox AS incoming
      LEFT JOIN telegram_inline_sort_preferences AS preference
        ON preference.bot_id = incoming.bot_id AND preference.actor_id = incoming.actor_id
      ${general ? "" : `LEFT JOIN telegram_auth AS auth
        ON auth.bot_id = incoming.bot_id AND auth.user_id = incoming.actor_id AND incoming.actor_id <> ?`}
      WHERE ${FRESH_RECEIPT}
    `).bind(event.kind, event.kind, event.kind, event.kind, ...(general ? [] : [isolated!.adminId]), ...key), db.prepare(`
      INSERT INTO telegram_outbox (receipt_id)
      SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${FRESH_RECEIPT}
    `).bind(...key), db.prepare(`
      UPDATE telegram_inbox AS incoming SET receipt_nonce = ?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_inline_sort_reply JOIN telegram_outbox USING(receipt_id) WHERE receipt_id=incoming.receipt_id)
        ${general ? `AND ${generalCurrentReceiptSql("incoming")}` : ""}
        THEN command END WHERE ${FRESH_RECEIPT} RETURNING receipt_id
    `).bind(general ? GENERAL_INLINE_SORT_MARKER : TELEGRAM_INLINE_SORT_MARKER, ...(general ? generalPolicyBindings(general) : []), ...key));

    const results = await db.batch(statements);
    const receipt = results.at(-1);
    if (receipt && results.length === statements.length && results.every((result) => result.success)
      && receipt.results.length <= 1) return receipt.results.length ? "accepted" : "ignored";
  } catch {
    // Only fixed error text crosses the webhook boundary.
  }
  throw new Error("Telegram inline sort receipt could not be confirmed.");
}

export function renderTelegramInlineSort(reply: TelegramInlineSortReply): string {
  switch (reply.kind) {
    case "saved": return `内联排序偏好已保存为：${MODE_LABELS[reply.mode!]}。`;
    case "current": return `当前内联排序偏好：${MODE_LABELS[reply.mode!]}。\n${USAGE}`;
    case "stale": return "已有更新的内联排序偏好。发送 /i 可查看当前设置。";
    case "usage": return USAGE;
  }
}

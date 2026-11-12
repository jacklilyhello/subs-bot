import { validInteger } from "../storage.ts";
import { parseDisplayTimeZone, readBotDisplayTimeZone, telegramDisplaySettingsReady } from "./display-time.ts";
export { telegramDisplaySettingsReady } from "./display-time.ts";
import { inTelegramScope, readPrivateTelegramCommand, type TelegramBotCredentials, type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";

type SettingsAction = { kind: "current" | "invalid" } | { kind: "set"; timeZone: string };
export type TelegramDisplaySettingsUpdate = TelegramEventScope & SettingsAction & { callbackId?: string };
type SettingsReply = { kind: "current" | "saved" | "stale" | "invalid" | "denied"; timezone: string | null };
const PREFIX = "timezone:v1:";
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
const positive = (value: unknown): value is number => typeof value === "number" && validInteger(value, 1, 2 ** 52 - 1);

function action(name: string, remainder: string): SettingsAction | null {
  if (name !== "settings" && name !== "timezone") return null;
  if (remainder.trim() === "") return { kind: "current" };
  if (name === "settings" || remainder.length > 110 || !/^\s/u.test(remainder)) return { kind: "invalid" };
  const zone = parseDisplayTimeZone(remainder.trim());
  return zone ? { kind: "set", timeZone: zone } : { kind: "invalid" };
}

/** Only human messages in their own private chat, or this Bot's private panel, are actionable. */
export function readTelegramDisplaySettingsUpdate(
  update: Record<string, unknown>, updateId: number, bot: Pick<TelegramBotCredentials, "botId" | "botUsername">,
): TelegramDisplaySettingsUpdate | null {
  if (!positive(updateId)) return null;
  const command = readPrivateTelegramCommand(update, bot.botUsername);
  if (command) {
    const parsed = action(command.name, command.remainder);
    return parsed ? { ...command, ...parsed, updateId, chatId: command.actorId, chatType: "private", threadId: null } : null;
  }
  if (Object.keys(update).length !== 2) return null;
  const callback = update.callback_query;
  if (!record(callback) || typeof callback.data !== "string" || !callback.data.startsWith(PREFIX)
    || typeof callback.id !== "string" || !/^[!-~]{1,128}$/u.test(callback.id) || "inline_message_id" in callback
    || "game_short_name" in callback || !record(callback.from) || callback.from.is_bot !== false || !positive(callback.from.id)) return null;
  const message = callback.message;
  if (!record(message) || !record(message.from) || message.from.is_bot !== true || !positive(message.from.id) || String(message.from.id) !== bot.botId
    || !record(message.chat) || message.chat.type !== "private" || message.chat.id !== callback.from.id
    || "message_thread_id" in message || !positive(message.message_id) || !positive(message.date)) return null;
  const zone = parseDisplayTimeZone(callback.data.slice(PREFIX.length));
  return { updateId, actorId: String(callback.from.id), chatId: String(callback.from.id), chatType: "private", threadId: null,
    messageId: message.message_id, messageDate: message.date, callbackId: callback.id,
    ...(zone ? { kind: "set", timeZone: zone } : { kind: "invalid" }) };
}

function settingsStatements(
  db: D1Database, key: readonly [string, number, string], event: TelegramDisplaySettingsUpdate,
  admin: { sql: string; bindings: readonly string[] },
): D1PreparedStatement[] {
  const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
  const zone = event.kind === "set" ? event.timeZone : null;
  return [
    ...(zone === null ? [] : [db.prepare(`INSERT INTO telegram_bot_display_settings(bot_id,timezone,update_id,message_date,updated_by)
      SELECT incoming.bot_id,?,incoming.update_id,incoming.message_date,incoming.actor_id FROM telegram_inbox AS incoming
      WHERE ${fresh} AND incoming.chat_type='private' AND incoming.chat_id=incoming.actor_id AND incoming.thread_id IS NULL AND (${admin.sql})
      ON CONFLICT(bot_id) DO UPDATE SET timezone=excluded.timezone,update_id=excluded.update_id,message_date=excluded.message_date,
        updated_by=excluded.updated_by,updated_at=unixepoch()
      WHERE (excluded.message_date,excluded.update_id)>(telegram_bot_display_settings.message_date,telegram_bot_display_settings.update_id)`)
      .bind(zone, ...key, ...admin.bindings)]),
    db.prepare(`INSERT INTO telegram_display_settings_replies(receipt_id,kind,timezone)
      SELECT incoming.receipt_id,CASE WHEN NOT (${admin.sql}) THEN 'denied'
        WHEN ?='set' THEN CASE WHEN setting.update_id=incoming.update_id THEN 'saved' ELSE 'stale' END ELSE ? END,
        CASE WHEN (${admin.sql}) AND ?='set' AND setting.update_id=incoming.update_id THEN setting.timezone END
      FROM telegram_inbox AS incoming LEFT JOIN telegram_bot_display_settings AS setting ON setting.bot_id=incoming.bot_id
      WHERE ${fresh}`).bind(...admin.bindings, event.kind, event.kind, ...admin.bindings, event.kind, ...key),
  ];
}

export async function acceptTelegramDisplaySettings(
  db: D1Database, policy: TelegramPolicy, event: TelegramDisplaySettingsUpdate, admissionGuard?: D1PreparedStatement,
): Promise<boolean> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.chatId !== event.actorId || event.threadId !== null
    || (event.kind === "set" && parseDisplayTimeZone(event.timeZone) !== event.timeZone)) return false;
  if (!await telegramDisplaySettingsReady(db)) return false;
  const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
  const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
  const admin = { sql: "incoming.actor_id=?", bindings: [policy.adminId] };
  const operationDate = event.callbackId ? Math.floor(Date.now() / 1000) : event.messageDate;
  const statements = [...(admissionGuard ? [admissionGuard] : []), db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE ? OR ? BETWEEN unixepoch()-900 AND unixepoch()+30
      ON CONFLICT(bot_id,update_id) DO NOTHING`)
    .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, operationDate, key[2],
      event.callbackId ? 1 : 0, operationDate),
    ...settingsStatements(db, key, event, admin),
    db.prepare(`INSERT INTO telegram_outbox(receipt_id) SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=NULL,command=CASE WHEN EXISTS (
      SELECT 1 FROM telegram_display_settings_replies JOIN telegram_outbox USING(receipt_id) WHERE receipt_id=incoming.receipt_id)
      THEN command END WHERE ${fresh} RETURNING receipt_id`).bind(...key)];
  const result = await db.batch(statements);
  if (result.length !== statements.length || !result.every(({ success }) => success) || !result.at(-1) || result.at(-1)!.results.length > 1) {
    throw new Error("Telegram display settings receipt could not be confirmed.");
  }
  return result.at(-1)!.results.length === 1;
}

export async function acceptGeneralTelegramDisplaySettings(
  db: D1Database, pin: GeneralTelegramPin, event: TelegramDisplaySettingsUpdate,
): Promise<number> {
  if (!pin.sharedOutbox || pin.rehearsal || event.actorId === pin.botId || event.chatType !== "private" || event.chatId !== event.actorId
    || event.threadId !== null || (event.kind === "set" && parseDisplayTimeZone(event.timeZone) !== event.timeZone)) return 204;
  if (!await telegramDisplaySettingsReady(db)) return 204;
  const key = [pin.botId, event.updateId, crypto.randomUUID()] as const;
  const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
  const admin = { sql: `EXISTS (SELECT 1 FROM telegram_general_receipt AS authority WHERE authority.receipt_id=incoming.receipt_id
    AND authority.actor_role='admin')`, bindings: [] };
  const now = event.callbackId ? Math.floor(Date.now() / 1000) : event.messageDate;
  const statements = [db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
      FROM ${GENERAL_POLICY_ACTORS_SQL} WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA}
        AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
        AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
        AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
        AND ${GENERAL_ACTOR_QUEUE_CAPACITY} ON CONFLICT(bot_id,update_id) DO NOTHING`)
    .bind(event.updateId, event.messageId, now, key[2], ...generalPolicyBindings(pin), event.actorId, now, now, event.updateId),
    prepareGeneralReceiptAuthority(db, pin, key), ...settingsStatements(db, key, event, admin),
    db.prepare(`INSERT INTO telegram_outbox(receipt_id) SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce='general-read:v1',command=CASE WHEN EXISTS (
      SELECT 1 FROM telegram_display_settings_replies JOIN telegram_outbox USING(receipt_id) WHERE receipt_id=incoming.receipt_id)
      AND EXISTS (SELECT 1 FROM telegram_general_receipt WHERE receipt_id=incoming.receipt_id) THEN command END
      WHERE ${fresh} RETURNING receipt_id`).bind(...key)];
  const result = await db.batch(statements);
  if (result.length !== statements.length || !result.every(({ success }) => success) || !result.at(-1) || result.at(-1)!.results.length > 1) {
    throw new Error("General Telegram display settings receipt could not be confirmed.");
  }
  return result.at(-1)!.results.length === 1 ? 200 : 204;
}

export async function renderTelegramDisplaySettings(
  db: D1Database, botId: string, receiptId: number, admin: boolean,
): Promise<{ text: string; keyboard?: { text: string; callback_data: string }[][] } | null> {
  if (!await telegramDisplaySettingsReady(db)) return null;
  const row = await db.prepare(`SELECT settings.kind,settings.timezone FROM telegram_display_settings_replies AS settings
    JOIN telegram_inbox AS inbox USING(receipt_id) WHERE receipt_id=? AND inbox.bot_id=?
      AND inbox.chat_type='private' AND inbox.actor_id=inbox.chat_id AND inbox.thread_id IS NULL`)
    .bind(receiptId, botId).first<SettingsReply>();
  if (!row) return null;
  if (!admin || row.kind === "denied") return { text: "只有管理员可以在机器人私聊中修改设置。" };
  const timeZone = await readBotDisplayTimeZone(db, botId);
  const notice = row.kind === "saved" ? "展示时区已保存。\n" : row.kind === "stale" ? "已有更新的时区设置。\n"
    : row.kind === "invalid" ? "时区无效，请使用 IANA 地区时区名称。\n" : "";
  return { text: `${notice}当前 Bot 展示时区：${timeZone}\n/timezone Asia/Singapore 切换时区\n/timezone UTC 恢复默认时区\n也可使用 /timezone America/New_York 等有效 IANA 名称。`,
    keyboard: [[{ text: "UTC（默认）", callback_data: `${PREFIX}UTC` }, { text: "Asia/Singapore", callback_data: `${PREFIX}Asia/Singapore` }]] };
}

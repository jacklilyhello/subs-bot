import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK,
  GENERAL_POLICY_ACTORS_SQL, GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL,
  generalPolicyBindings } from "./general-receipt.ts";
import type { TelegramEventScope } from "./protocol.ts";

export function generalPrivateScope(pin: GeneralTelegramPin, event: Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId">): boolean {
  return pin.sharedOutbox && !pin.rehearsal && event.actorId !== pin.botId && event.chatType === "private"
    && event.chatId === event.actorId && event.threadId === null;
}

/** Current policy, actor revision and queue capacity are checked in the admission batch. */
export function prepareGeneralPrivateAdmission(
  db: D1Database, pin: GeneralTelegramPin, event: TelegramEventScope, nonce: string,
  extra: { sql: string; bindings: readonly (string | number | null)[] } = { sql: "1", bindings: [] },
): D1PreparedStatement {
  return db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
    SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
    FROM ${GENERAL_POLICY_ACTORS_SQL} WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA}
      AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+30
      AND NOT EXISTS(SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY} AND (${extra.sql})
    ON CONFLICT(bot_id,update_id) DO NOTHING`)
    .bind(event.updateId, event.messageId, event.messageDate, nonce, ...generalPolicyBindings(pin),
      event.actorId, event.messageDate, event.messageDate, event.updateId, ...extra.bindings);
}

import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import type { TelegramEventScope } from "./protocol.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalPolicyBindings } from "./general-receipt.ts";

/** Management uses the current registered actor revision, never the isolation test pair. */
export function generalManagementScope(pin: GeneralTelegramPin, event: Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId">): boolean {
  return pin.sharedOutbox && pin.privateManagement && !pin.rehearsal && event.actorId !== pin.botId
    && event.chatType === "private" && event.chatId === event.actorId && event.threadId === null;
}

export function generalManagementAdmission(pin: GeneralTelegramPin, event: TelegramEventScope, schema: string) {
  return { sql: `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND (${schema})
      AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY}
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)`,
  bindings: [...generalPolicyBindings(pin), event.actorId, event.messageDate, event.messageDate, event.updateId, event.updateId] };
}

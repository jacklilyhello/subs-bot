import { isolatedTelegramRoleEpochSql } from "./authorization-sql.ts";
import type { TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_PROVIDER_DOCUMENT_MARKER = "provider-document:v1";

export function providerDocumentOrigin(
  policy: Readonly<Pick<TelegramPolicy, "botId" | "adminId" | "memberId">>,
  mode: "current" | "recorded" = "current",
  inbox: "inbox" | "earlier" = "inbox",
) {
  const epoch = isolatedTelegramRoleEpochSql(policy, inbox, mode);
  return {
    sql: `origin.bot_id=? AND ${inbox}.bot_id=origin.bot_id AND ${inbox}.actor_id=origin.actor_id
      AND ${inbox}.chat_id=${inbox}.actor_id AND ${inbox}.chat_type='private' AND ${inbox}.thread_id IS NULL
      AND ${inbox}.command='help' AND ${inbox}.receipt_nonce='${TELEGRAM_PROVIDER_DOCUMENT_MARKER}' AND ${epoch.sql}`,
    bindings: [policy.botId, ...epoch.bindings],
  };
}

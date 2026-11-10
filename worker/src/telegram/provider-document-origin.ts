import type { GeneralProviderAuthority } from "../provider-jobs.ts";
import { isolatedTelegramRoleEpochSql } from "./authorization-sql.ts";
import { GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_SCHEMA, GENERAL_RECEIPT_SCHEMA,
  generalPolicyBindings, generalRecordedIdentitySql } from "./general-receipt.ts";
import type { TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_PROVIDER_DOCUMENT_MARKER = "provider-document:v1";
export const GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER = "general-provider-document:v1";
export const PROVIDER_DOCUMENT_REPLY_SECONDS = 900;
export const GENERAL_PROVIDER_DOCUMENT_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-provider-documents:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=35 AND name='0035_telegram_provider_documents.sql'
    AND sha256='9a3fc29e9ea19abac2874a11a0152497eee63a54ecb401168c153fb838f92505' AND mode='applied')`;
export type ProviderDocumentPolicy = Readonly<Pick<TelegramPolicy, "botId" | "adminId" | "memberId">> | GeneralProviderAuthority;

export function providerDocumentOrigin(
  policy: ProviderDocumentPolicy,
  mode: "current" | "recorded" = "current",
  inbox: "inbox" | "earlier" = "inbox",
) {
  const scope = `${inbox}.bot_id=origin.bot_id AND ${inbox}.actor_id=origin.actor_id
    AND ${inbox}.chat_id=${inbox}.actor_id AND ${inbox}.chat_type='private' AND ${inbox}.thread_id IS NULL AND ${inbox}.command='help'`;
  if ("family" in policy) {
    const join = mode === "current" ? `JOIN telegram_general_policy AS policy
      ON (policy.bot_id=${inbox}.bot_id AND policy.generation=recorded.generation)
      AND (policy.release_revision=recorded.release_revision AND policy.activation_sha256=recorded.activation_sha256
        AND policy.cutover_at=recorded.cutover_at)` : "";
    const current = mode === "current" ? `AND (policy.active=1 AND (${GENERAL_LATEST_ACTOR_SQL}) AND (${GENERAL_NO_LEGACY_WORK}))` : "";
    return {
      sql: `(${scope}) AND ${inbox}.receipt_nonce='${GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER}'
        AND (origin.auth_message_date=0 AND origin.auth_message_id=0)
        AND EXISTS (SELECT 1 FROM telegram_general_receipt AS recorded
          JOIN telegram_general_actors AS actor ON (actor.bot_id=${inbox}.bot_id AND actor.actor_id=${inbox}.actor_id)
            AND (actor.generation=recorded.generation AND actor.revision=recorded.actor_revision AND actor.role=recorded.actor_role)
          ${join} WHERE recorded.receipt_id=${inbox}.receipt_id AND (${generalRecordedIdentitySql(inbox)})
            AND (recorded.actor_role=origin.actor_role AND ${inbox}.message_date>MAX(recorded.cutover_at,actor.effective_at))
            AND (${GENERAL_POLICY_SCHEMA} AND ${GENERAL_RECEIPT_SCHEMA} AND ${GENERAL_PROVIDER_DOCUMENT_SCHEMA}) ${current})`,
      bindings: generalPolicyBindings(policy),
    };
  }
  const epoch = isolatedTelegramRoleEpochSql(policy, inbox, mode);
  return {
    sql: `origin.bot_id=? AND ${scope} AND ${inbox}.receipt_nonce='${TELEGRAM_PROVIDER_DOCUMENT_MARKER}' AND ${epoch.sql}`,
    bindings: [policy.botId, ...epoch.bindings],
  };
}

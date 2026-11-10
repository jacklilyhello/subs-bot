import type { GeneralTelegramPin } from "./general-auth-runtime.ts";

type ReceiptAlias = "inbox" | "earlier" | "incoming" | "origin";

function pinIdentity(botColumn: string, row: "policy" | "recorded"): string {
  return `${botColumn}=? AND ${row}.generation=? AND ${row}.activation_sha256=? AND ${row}.release_revision=? AND ${row}.cutover_at=?`;
}

export const GENERAL_REPLY_TTL = 600;
const MIGRATION_SHA256 = "99ae19a1a0296bcf78598752c323571b3194c7b1e4bd1241c6f4960650fea75d";
export const GENERAL_POLICY_SCHEMA = `EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=44
  AND name='0044_telegram_general_runtime.sql' AND sha256='${MIGRATION_SHA256}' AND mode='applied')`;
export const GENERAL_POLICY_PIN_SQL = `${pinIdentity("policy.bot_id", "policy")} AND ${GENERAL_POLICY_SCHEMA}`;
export const GENERAL_LATEST_ACTOR_SQL = `actor.role IN ('admin','member') AND NOT EXISTS (
  SELECT 1 FROM telegram_general_actors AS newer
  WHERE newer.bot_id=actor.bot_id AND newer.generation=actor.generation AND newer.actor_id=actor.actor_id
    AND newer.revision>actor.revision)`;
export const GENERAL_POLICY_ACTORS_SQL = `telegram_general_policy AS policy JOIN telegram_general_actors AS actor
  ON actor.bot_id=policy.bot_id AND actor.generation=policy.generation`;
export const GENERAL_RECEIPT_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-shared-outbox:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=46 AND name='0046_telegram_general_receipts.sql'
  AND sha256='1f06d33b9cec5d7cd55c9d859ae04950a86484db92a17d49733defb116a47667' AND mode='applied')`;
export const GENERAL_NO_LEGACY_WORK = `NOT EXISTS (SELECT 1 FROM telegram_general_replies
  WHERE bot_id=policy.bot_id AND state IN ('pending','leased','sending'))`;

export const GENERAL_ACTOR_QUEUE_CAPACITY = `NOT EXISTS (
  SELECT 1 FROM telegram_inbox AS queued JOIN telegram_general_receipt AS recorded USING (receipt_id)
  JOIN telegram_outbox AS reply USING (receipt_id)
  WHERE queued.bot_id=policy.bot_id AND queued.actor_id=actor.actor_id
    AND recorded.generation=actor.generation AND recorded.actor_revision=actor.revision AND recorded.actor_role=actor.role
    AND recorded.release_revision=policy.release_revision AND recorded.activation_sha256=policy.activation_sha256
    AND recorded.cutover_at=policy.cutover_at AND reply.state IN ('pending','leased','sending')
    AND ${generalOrdinaryReplyEligibilitySql("queued")}
  LIMIT 1 OFFSET 3)`;

// Keep this order aligned with both exact pin predicates.
export function generalPolicyBindings(pin: GeneralTelegramPin, generation = pin.generation) {
  return [pin.botId, generation, pin.activationSha256, pin.releaseRevision, pin.cutoverAt] as const;
}

/** Pair the recorded identity with the caller's receipt family, actor, and destination. */
export function generalRecordedOriginSql(alias: ReceiptAlias): string {
  return `EXISTS (SELECT 1 FROM telegram_general_receipt AS recorded
    WHERE recorded.receipt_id=${alias}.receipt_id AND ${pinIdentity(`${alias}.bot_id`, "recorded")})`;
}

/** The active grant must still match the recorded actor epoch. Feature clocks are separate. */
export function generalCurrentAuthoritySql(alias: ReceiptAlias, extra = "1"): string {
  return `EXISTS (
    SELECT 1 FROM ${GENERAL_POLICY_ACTORS_SQL} JOIN telegram_general_receipt AS authority
      ON authority.generation=policy.generation AND authority.release_revision=policy.release_revision
      AND authority.activation_sha256=policy.activation_sha256 AND authority.cutover_at=policy.cutover_at
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}
      AND policy.bot_id=${alias}.bot_id AND authority.receipt_id=${alias}.receipt_id
      AND actor.actor_id=${alias}.actor_id AND actor.revision=authority.actor_revision AND actor.role=authority.actor_role
      AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ${alias}.message_date>MAX(policy.cutover_at,actor.effective_at) AND (${extra}))`;
}

export function generalOrdinaryReplyEligibilitySql(alias: ReceiptAlias | "receipt" | "queued"): string {
  return `${alias}.received_at+${GENERAL_REPLY_TTL}>unixepoch()`;
}

export function generalCurrentReceiptSql(alias: ReceiptAlias, extra = "1"): string {
  return `${generalOrdinaryReplyEligibilitySql(alias)} AND ${generalCurrentAuthoritySql(alias, extra)}`;
}

export function prepareGeneralReceiptAuthority(
  db: D1Database, pin: GeneralTelegramPin, key: readonly [string, number, string],
): D1PreparedStatement {
  return db.prepare(`INSERT INTO telegram_general_receipt
      (receipt_id,generation,actor_revision,actor_role,release_revision,activation_sha256,cutover_at)
    SELECT inbox.receipt_id,actor.generation,actor.revision,actor.role,?,?,?
    FROM telegram_inbox AS inbox JOIN telegram_general_actors AS actor
      ON actor.bot_id=inbox.bot_id AND actor.actor_id=inbox.actor_id AND actor.generation=?
    WHERE inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce=? AND ${GENERAL_LATEST_ACTOR_SQL}`)
    .bind(pin.releaseRevision, pin.activationSha256, pin.cutoverAt, pin.generation, ...key);
}

import { providerHost, type ProviderSql } from "../provider-jobs.ts";
import { digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { generalCurrentReceiptSql, generalPolicyBindings } from "./general-receipt.ts";
import { GENERAL_SUBSCRIPTION_READ_MARKER, PROVIDER_REFRESH_TICKET, SUBSCRIPTION_READ_RECEIPT_MARKER,
  type TelegramPolicy, type TelegramProviderRefreshUpdate } from "./protocol.ts";

const TICKET_SECONDS = 600;
const encoder = new TextEncoder();
export type TelegramProviderRefreshTarget = { id: number; generation: number; lifecycleRevision: number; sourceSha256: string };
export type TelegramProviderRefreshTicket = TelegramProviderRefreshTarget & { tokenSha256: string };
export const GENERAL_PROVIDER_REFRESH_SCHEMA = `EXISTS (
  SELECT /* subs-bot:telegram-general-provider-refresh:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=28 AND name='0028_telegram_provider_refresh_tickets.sql' AND mode='applied'
    AND sha256='ccbfe6d71864608b9a6d680d955c11af083aa34280b55845edef1296d87dab2e')`;

async function digest(value: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

export async function telegramProviderRefreshReady(db: D1Database): Promise<boolean> {
  try {
    return await db.prepare(`SELECT 1 FROM sqlite_schema WHERE type='table'
      AND name='telegram_provider_refresh_tickets'`).first() !== null;
  } catch {
    throw new Error("Telegram provider refresh readiness could not be confirmed.");
  }
}

export async function generalProviderRefreshReady(db: D1Database): Promise<boolean> {
  return Boolean(await db.prepare(`SELECT 1 FROM sqlite_schema WHERE type='table'
    AND name='telegram_provider_refresh_tickets' AND (${GENERAL_PROVIDER_REFRESH_SCHEMA})`).first());
}

export async function providerRefreshTarget(
  row: Omit<TelegramProviderRefreshTarget, "sourceSha256">, sourceUrl: string | null,
): Promise<TelegramProviderRefreshTarget | undefined> {
  if (sourceUrl === null || !providerHost(sourceUrl) || !validInteger(row.generation, 0, Number.MAX_SAFE_INTEGER - 1)) return;
  return { id: row.id, generation: row.generation, lifecycleRevision: row.lifecycleRevision, sourceSha256: await digest(sourceUrl) };
}

export async function prepareTelegramProviderRefreshButton(target: TelegramProviderRefreshTarget): Promise<{
  button: { text: string; callback_data: string }; ticket: TelegramProviderRefreshTicket;
}> {
  const token = "sbpr1_" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  return { button: { text: "刷新订阅", callback_data: token }, ticket: { ...target, tokenSha256: await digest(token) } };
}

export function insertTelegramProviderRefreshTicket(
  db: D1Database, policy: TelegramPolicy | GeneralTelegramPin, lease: { receiptId: number; leaseId: string; attempts: number },
  ticket: TelegramProviderRefreshTicket, previousChanges: number,
): D1PreparedStatement {
  if ("privateManagement" in policy) {
    return db.prepare(`INSERT INTO telegram_provider_refresh_tickets
      (token_sha256,origin_receipt_id,origin_attempt,actor_role,subscription_id,source_sha256,generation,lifecycle_revision,expires_at)
      SELECT ?,inbox.receipt_id,reply.attempts,recorded.actor_role,detail.subscription_id,?,?,?,unixepoch()+${TICKET_SECONDS}
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      JOIN telegram_general_receipt AS recorded USING(receipt_id) JOIN telegram_subscription_read AS detail USING(receipt_id)
      WHERE changes()=? AND reply.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'
        AND inbox.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND inbox.chat_type='private'
        AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL AND detail.kind='detail' AND detail.subscription_id=?
        AND (${GENERAL_PROVIDER_REFRESH_SCHEMA}) AND (${generalCurrentReceiptSql("inbox")})`)
      .bind(ticket.tokenSha256, ticket.sourceSha256, ticket.generation, ticket.lifecycleRevision, previousChanges,
        lease.receiptId, lease.leaseId, lease.attempts, ticket.id, ...generalPolicyBindings(policy));
  }
  return db.prepare(`INSERT INTO telegram_provider_refresh_tickets
    (token_sha256,origin_receipt_id,origin_attempt,actor_role,subscription_id,source_sha256,generation,lifecycle_revision,expires_at)
    SELECT ?,inbox.receipt_id,reply.attempts,
      CASE WHEN inbox.actor_id=? AND detail.auth_message_date=0 AND detail.auth_message_id=0 THEN 'admin'
        WHEN inbox.actor_id=? THEN 'member' END,
      CASE WHEN inbox.bot_id=? AND inbox.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}'
      AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
      AND detail.kind='detail' AND detail.subscription_id=? THEN detail.subscription_id END,
      ?,?,?,unixepoch()+${TICKET_SECONDS}
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_subscription_read AS detail USING(receipt_id)
    WHERE changes()=? AND reply.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'`)
    .bind(ticket.tokenSha256, policy.adminId, policy.memberId, policy.botId, ticket.id,
      ticket.sourceSha256, ticket.generation, ticket.lifecycleRevision,
      previousChanges, lease.receiptId, lease.leaseId, lease.attempts);
}

const ticketSource = `FROM telegram_provider_refresh_tickets AS ticket
  JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
  JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
  JOIN telegram_subscription_read AS detail ON detail.receipt_id=origin.receipt_id
  JOIN subscriptions ON subscriptions.id=ticket.subscription_id AND subscriptions.owner_id=origin.actor_id`;

export async function readGeneralProviderRefreshAdmission(
  db: D1Database, policy: GeneralTelegramPin, event: TelegramProviderRefreshUpdate,
): Promise<(TelegramProviderRefreshTicket & { guard: ProviderSql }) | null> {
  if (!policy.privateProvider || !PROVIDER_REFRESH_TICKET.test(event.ticket)) return null;
  const tokenSha256 = await digest(event.ticket);
  const pinned = `WITH confirmed AS MATERIALIZED (
    SELECT ticket.subscription_id AS id,ticket.generation,ticket.lifecycle_revision AS lifecycleRevision,
      ticket.source_sha256 AS sourceSha256,subscriptions.source_url AS sourceUrl,
      (${generalCurrentReceiptSql("origin")}) AS origin_current
    ${ticketSource} JOIN telegram_general_receipt AS recorded ON recorded.receipt_id=origin.receipt_id
    WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
      AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type='private' AND origin.thread_id IS NULL
      AND origin.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND detail.kind='detail' AND detail.subscription_id=ticket.subscription_id
      AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt AND ?>=origin.message_date
      AND ticket.actor_role=recorded.actor_role AND subscriptions.generation=ticket.generation
      AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=ticket.lifecycle_revision
  ) SELECT id,generation,lifecycleRevision,sourceSha256,sourceUrl FROM confirmed WHERE origin_current AND (${GENERAL_PROVIDER_REFRESH_SCHEMA})`;
  const bindings = [...generalPolicyBindings(policy), tokenSha256, policy.botId, event.actorId, event.chatId, event.messageId, event.messageDate];
  const target = await db.prepare(pinned).bind(...bindings).first<TelegramProviderRefreshTarget & { sourceUrl: string }>();
  if (!target || !providerHost(target.sourceUrl) || await digest(target.sourceUrl) !== target.sourceSha256) return null;
  const { id, generation, lifecycleRevision, sourceSha256, sourceUrl } = target;
  return { id, generation, lifecycleRevision, sourceSha256, tokenSha256, guard: {
    sql: `EXISTS (SELECT 1 FROM (${pinned}) AS target WHERE id=? AND generation=? AND lifecycleRevision=? AND sourceSha256=? AND sourceUrl=?)`,
    bindings: [...bindings, id, generation, lifecycleRevision, sourceSha256, sourceUrl],
  } };
}

/** Read a candidate, then hand back the exact SQL predicate to repeat in the admission batch. */
export async function readTelegramProviderRefreshAdmission(
  db: D1Database, policy: TelegramPolicy, event: TelegramProviderRefreshUpdate,
): Promise<(TelegramProviderRefreshTicket & { guard: ProviderSql }) | null> {
  if (!PROVIDER_REFRESH_TICKET.test(event.ticket)) return null;
  const tokenSha256 = await digest(event.ticket);
  const sql = `ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
    AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type='private' AND origin.thread_id IS NULL
    AND origin.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}' AND detail.kind='detail' AND detail.subscription_id=ticket.subscription_id
    AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt
    AND subscriptions.generation=ticket.generation AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=ticket.lifecycle_revision
    AND ((origin.actor_id=? AND ticket.actor_role='admin' AND detail.auth_message_date=0 AND detail.auth_message_id=0)
      OR (origin.actor_id=? AND ticket.actor_role='member' AND COALESCE(auth.allowed,1)=1
      AND detail.auth_message_date=COALESCE(auth.message_date,0)
      AND detail.auth_message_id=COALESCE(auth.message_id,0) AND origin.message_date>COALESCE(auth.message_date,0)
      AND ?>COALESCE(auth.message_date,0)))`;
  const bindings = [tokenSha256, policy.botId, event.actorId, event.chatId, event.messageId,
    policy.adminId, policy.memberId, event.messageDate];
  const pin = await db.prepare(`SELECT ticket.subscription_id AS id,ticket.generation,ticket.lifecycle_revision AS lifecycleRevision,
    ticket.source_sha256 AS sourceSha256,subscriptions.source_url AS sourceUrl ${ticketSource}
    LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id WHERE ${sql}`)
    .bind(...bindings).first<TelegramProviderRefreshTarget & { sourceUrl: string }>();
  if (!pin || !providerHost(pin.sourceUrl) || await digest(pin.sourceUrl) !== pin.sourceSha256) return null;
  const { id, generation, lifecycleRevision, sourceSha256, sourceUrl } = pin;
  const guard = {
    sql: `EXISTS (SELECT 1 ${ticketSource}
      LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id
      WHERE ${sql} AND ticket.subscription_id=? AND ticket.generation=?
      AND ticket.lifecycle_revision=? AND ticket.source_sha256=? AND subscriptions.source_url=?)`,
    bindings: [...bindings, id, generation, lifecycleRevision, sourceSha256, sourceUrl],
  };
  return { id, generation, lifecycleRevision, sourceSha256, tokenSha256, guard };
}

export async function reapTelegramProviderRefreshTickets(db: D1Database, generalBotId?: string): Promise<void> {
  try {
    const scope = generalBotId === undefined ? "" : `AND EXISTS (SELECT 1 FROM telegram_inbox AS origin
      WHERE origin.receipt_id=ticket.origin_receipt_id AND origin.bot_id=? AND origin.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}')`;
    const result = await db.prepare(`DELETE FROM telegram_provider_refresh_tickets WHERE token_sha256 IN (
      SELECT token_sha256 FROM telegram_provider_refresh_tickets AS ticket WHERE expires_at<=unixepoch() ${scope}
      ORDER BY expires_at,token_sha256 LIMIT 40)`).bind(...(generalBotId === undefined ? [] : [generalBotId])).run();
    if (result.success) return;
  } catch {
    // Keep callback and backend values out of diagnostics.
  }
  throw new Error("Telegram provider refresh ticket cleanup could not be confirmed.");
}

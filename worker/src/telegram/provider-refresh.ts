import { providerHost, type ProviderSql } from "../provider-jobs.ts";
import { digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { PROVIDER_REFRESH_TICKET, SUBSCRIPTION_READ_RECEIPT_MARKER,
  type TelegramPolicy, type TelegramProviderRefreshUpdate } from "./protocol.ts";

const TICKET_SECONDS = 600;
const encoder = new TextEncoder();
export type TelegramProviderRefreshTarget = { id: number; generation: number; lifecycleRevision: number; sourceSha256: string };
export type TelegramProviderRefreshTicket = TelegramProviderRefreshTarget & { tokenSha256: string };

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
  db: D1Database, lease: { receiptId: number; leaseId: string; attempts: number },
  ticket: TelegramProviderRefreshTicket, previousChanges: number,
): D1PreparedStatement {
  return db.prepare(`INSERT INTO telegram_provider_refresh_tickets
    (token_sha256,origin_receipt_id,origin_attempt,subscription_id,source_sha256,generation,lifecycle_revision,expires_at)
    SELECT ?,inbox.receipt_id,reply.attempts,CASE WHEN inbox.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}'
      AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
      AND detail.kind='detail' AND detail.subscription_id=? THEN detail.subscription_id END,
      ?,?,?,unixepoch()+${TICKET_SECONDS}
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_subscription_read AS detail USING(receipt_id)
    WHERE changes()=? AND reply.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'`)
    .bind(ticket.tokenSha256, ticket.id, ticket.sourceSha256, ticket.generation, ticket.lifecycleRevision,
      previousChanges, lease.receiptId, lease.leaseId, lease.attempts);
}

const ticketSource = `FROM telegram_provider_refresh_tickets AS ticket
  JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
  JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
  JOIN telegram_subscription_read AS detail ON detail.receipt_id=origin.receipt_id
  JOIN subscriptions ON subscriptions.id=ticket.subscription_id AND subscriptions.owner_id=origin.actor_id
  LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id`;

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
    AND (origin.actor_id=? OR (COALESCE(auth.allowed,1)=1 AND detail.auth_message_date=COALESCE(auth.message_date,0)
      AND detail.auth_message_id=COALESCE(auth.message_id,0) AND origin.message_date>COALESCE(auth.message_date,0)
      AND ?>COALESCE(auth.message_date,0)))`;
  const bindings = [tokenSha256, policy.botId, event.actorId, event.chatId, event.messageId, policy.adminId, event.messageDate];
  const pin = await db.prepare(`SELECT ticket.subscription_id AS id,ticket.generation,ticket.lifecycle_revision AS lifecycleRevision,
    ticket.source_sha256 AS sourceSha256,subscriptions.source_url AS sourceUrl ${ticketSource} WHERE ${sql}`)
    .bind(...bindings).first<TelegramProviderRefreshTarget & { sourceUrl: string }>();
  if (!pin || !providerHost(pin.sourceUrl) || await digest(pin.sourceUrl) !== pin.sourceSha256) return null;
  const { id, generation, lifecycleRevision, sourceSha256, sourceUrl } = pin;
  const guard = {
    sql: `EXISTS (SELECT 1 ${ticketSource} WHERE ${sql} AND ticket.subscription_id=? AND ticket.generation=?
      AND ticket.lifecycle_revision=? AND ticket.source_sha256=? AND subscriptions.source_url=?)`,
    bindings: [...bindings, id, generation, lifecycleRevision, sourceSha256, sourceUrl],
  };
  return { id, generation, lifecycleRevision, sourceSha256, tokenSha256, guard };
}

export async function reapTelegramProviderRefreshTickets(db: D1Database): Promise<void> {
  try {
    const result = await db.prepare(`DELETE FROM telegram_provider_refresh_tickets WHERE token_sha256 IN (
      SELECT token_sha256 FROM telegram_provider_refresh_tickets WHERE expires_at<=unixepoch()
      ORDER BY expires_at,token_sha256 LIMIT 40)`).run();
    if (result.success) return;
  } catch {
    // Keep callback and backend values out of diagnostics.
  }
  throw new Error("Telegram provider refresh ticket cleanup could not be confirmed.");
}

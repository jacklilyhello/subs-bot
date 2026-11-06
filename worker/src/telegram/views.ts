import { checkOwnerId, validInteger } from "../storage.ts";
import { listDeletedSubscriptions, listOwnedSubscriptions } from "../subscriptions.ts";
import { inTelegramScope, type TelegramPolicy, type TelegramViewKind, type TelegramViewUpdate } from "./protocol.ts";

export const TELEGRAM_VIEW_MARKER = "view:v1";

interface ViewCursor {
  afterId: number | null;
  afterEpoch: number | null;
}

export interface TelegramView extends ViewCursor {
  kind: TelegramViewKind;
}

export interface TelegramViewButton extends ViewCursor {
  text: string;
}

export interface TelegramViewTicket extends ViewCursor {
  sha256: string;
}

const PAGE_SIZE = 8;
const EXPIRY_SECONDS = 14 * 24 * 60 * 60;
const TICKET_SECONDS = 10 * 60;
const TICKET_REAP_LIMIT = 40;
const encoder = new TextEncoder();

async function ticketDigest(ticket: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(ticket));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function acceptTelegramView(
  db: D1Database,
  policy: TelegramPolicy,
  event: TelegramViewUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event)) return "ignored";

  const nonce = crypto.randomUUID();
  const key = [policy.botId, event.updateId, nonce] as const;
  const scope = [policy.botId, event.updateId, event.actorId, event.chatId, event.chatType,
    event.messageId, event.messageDate, event.threadId, nonce] as const;
  const fields = "bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce";
  const values = "?, ?, ?, ?, ?, ?, ?, ?, 'help', ?";
  const conflict = "ON CONFLICT (bot_id, update_id) DO NOTHING";
  const fresh = "bot_id = ? AND update_id = ? AND receipt_nonce = ?";
  try {
    const steps: D1PreparedStatement[] = [];
    if (event.kind === "callback") {
      const digest = await ticketDigest(event.ticket);
      steps.push(
        db.prepare(`
          INSERT INTO telegram_inbox (${fields})
          SELECT ${values}
          FROM telegram_view_ticket AS ticket
          JOIN telegram_view AS origin ON origin.receipt_id = ticket.origin_receipt_id
          JOIN telegram_inbox AS inbox ON inbox.receipt_id = origin.receipt_id
          JOIN telegram_outbox AS reply ON reply.receipt_id = inbox.receipt_id
          WHERE ticket.token_sha256 = ? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at > unixepoch()
            AND inbox.receipt_nonce = ? AND inbox.bot_id = ? AND inbox.actor_id = ?
            AND inbox.chat_id = ? AND inbox.chat_type = ? AND inbox.thread_id IS ?
            AND reply.state = 'sent' AND reply.sent_message_id = ? AND reply.attempts = ticket.origin_attempt
            AND (inbox.actor_id = ? OR COALESCE((
              SELECT allowed FROM telegram_auth WHERE bot_id = inbox.bot_id AND user_id = inbox.actor_id
            ), 1) = 1)
          ${conflict}
        `).bind(...scope, digest, TELEGRAM_VIEW_MARKER, policy.botId, event.actorId, event.chatId,
          event.chatType, event.threadId, event.messageId, policy.adminId),
        db.prepare(`
          UPDATE telegram_view_ticket AS ticket SET used_by_receipt_id = incoming.receipt_id
          FROM telegram_inbox AS incoming
          WHERE ticket.token_sha256 = ? AND ticket.used_by_receipt_id IS NULL AND ${fresh}
        `).bind(digest, ...key),
        db.prepare(`
          INSERT INTO telegram_view (receipt_id, kind, after_id, after_epoch)
          SELECT incoming.receipt_id, origin.kind, ticket.after_id, ticket.after_epoch
          FROM telegram_inbox AS incoming
          JOIN telegram_view_ticket AS ticket ON ticket.used_by_receipt_id = incoming.receipt_id
          JOIN telegram_view AS origin ON origin.receipt_id = ticket.origin_receipt_id
          WHERE ${fresh}
        `).bind(...key),
      );
    } else {
      steps.push(
        db.prepare(`INSERT INTO telegram_inbox (${fields}) VALUES (${values}) ${conflict}`).bind(...scope),
        db.prepare(`
          INSERT INTO telegram_view (receipt_id, kind)
          SELECT receipt_id, ? FROM telegram_inbox WHERE ${fresh}
        `).bind(event.kind, ...key),
      );
    }
    steps.push(
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT receipt_id FROM telegram_inbox WHERE ${fresh}
      `).bind(...key),
      // Missing companions violate command's NOT NULL constraint and roll back this batch.
      db.prepare(`
        UPDATE telegram_inbox SET receipt_nonce = ?, command = CASE
          WHEN EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id = telegram_inbox.receipt_id)
            AND EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id = telegram_inbox.receipt_id)
          THEN command END
        WHERE ${fresh}
        RETURNING receipt_id
      `).bind(TELEGRAM_VIEW_MARKER, ...key),
    );
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && receipt.results.length <= 1
      && results.every((result) => result.success)) {
      return receipt.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // Avoid exposing private parameters in a D1 error.
  }
  throw new Error("Telegram view receipt could not be confirmed.");
}

function displayName(name: string): string {
  const clean = name.replace(/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/gu, " ")
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/giu, "[链接已省略]").trim();
  return Array.from(clean).slice(0, 80).join("") || "未命名";
}

function displayDate(epoch: number): string {
  const date = new Date(epoch * 1000);
  if (!Number.isFinite(date.getTime())) return "日期未知";
  return date.toISOString().replace("T", " ").replace(/:\d{2}\.\d{3}Z$/u, " UTC");
}

async function expiryPage(db: D1Database, ownerId: string, view: TelegramView) {
  checkOwnerId(ownerId);
  try {
    const result = await db.prepare(`
      SELECT id, name, expire_at AS epoch FROM subscriptions
      WHERE owner_id = ? AND expire_at BETWEEN unixepoch() AND unixepoch() + ${EXPIRY_SECONDS}
        ${view.afterId === null ? "" : "AND (expire_at, id) > (?, ?)"}
      ORDER BY expire_at, id LIMIT ?
    `).bind(ownerId, ...(view.afterId === null ? [] : [view.afterEpoch, view.afterId]), PAGE_SIZE + 1)
      .all<{ id: number; name: string; epoch: number }>();
    if (result.success) return result.results;
  } catch {
    // Avoid exposing private parameters in a D1 error.
  }
  throw new Error("Telegram expiry page could not be read.");
}

export async function renderTelegramView(
  db: D1Database,
  ownerId: string,
  view: TelegramView,
): Promise<{ text: string; buttons: TelegramViewButton[] }> {
  if ((view.afterId !== null && !validInteger(view.afterId, 1))
    || (view.afterEpoch !== null && !validInteger(view.afterEpoch, 1))
    || (view.afterEpoch !== null) !== (view.kind !== "list" && view.afterId !== null)) {
    throw new RangeError("Invalid Telegram view cursor.");
  }

  let title: string;
  let items: { name: string; epoch?: number }[];
  let next: ViewCursor | null = null;
  switch (view.kind) {
    case "list": {
      title = "你的订阅";
      const page = await listOwnedSubscriptions(db, ownerId, { limit: PAGE_SIZE, afterId: view.afterId ?? undefined });
      items = page.items;
      if (page.nextAfterId !== null) next = { afterId: page.nextAfterId, afterEpoch: null };
      break;
    }
    case "expiry": {
      title = "未来 14 天内到期的订阅";
      const rows = await expiryPage(db, ownerId, view);
      items = rows.slice(0, PAGE_SIZE);
      if (rows.length > PAGE_SIZE) {
        const last = rows[PAGE_SIZE - 1];
        next = { afterId: last.id, afterEpoch: last.epoch };
      }
      break;
    }
    case "recycle": {
      title = "你的回收站（30 天内）";
      const after = view.afterId === null || view.afterEpoch === null
        ? undefined : { id: view.afterId, deletedAt: view.afterEpoch };
      const page = await listDeletedSubscriptions(db, ownerId, { limit: PAGE_SIZE, after });
      items = page.items.map((row) => ({ name: row.name, epoch: row.deletedAt }));
      if (page.nextCursor) next = { afterId: page.nextCursor.id, afterEpoch: page.nextCursor.deletedAt };
      break;
    }
  }

  const lines = items.map((item) => item.epoch === undefined
    ? `• ${displayName(item.name)}` : `• ${displayName(item.name)} · ${displayDate(item.epoch)}`);
  const buttons: TelegramViewButton[] = [];
  if (next) buttons.push({ text: "下一页", ...next });
  if (view.afterId !== null) buttons.push({ text: "第一页", afterId: null, afterEpoch: null });
  return { text: [title, ...(lines.length ? lines : ["当前没有记录。"])].join("\n"), buttons };
}

export async function prepareTelegramViewTickets(buttons: readonly TelegramViewButton[]): Promise<{
  keyboard: { text: string; callback_data: string }[][];
  tickets: TelegramViewTicket[];
}> {
  if (buttons.length > 2) throw new RangeError("Invalid Telegram view button count.");
  const entries = await Promise.all(buttons.map(async ({ text, afterId, afterEpoch }) => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const token = "sbv1_" + btoa(String.fromCharCode(...bytes)).replace(/\+/gu, "-").replace(/\//gu, "_")
      .replace(/=+$/u, "");
    return { button: { text, callback_data: token }, ticket: { sha256: await ticketDigest(token), afterId, afterEpoch } };
  }));
  return { keyboard: entries.length ? [entries.map(({ button }) => button)] : [], tickets: entries.map(({ ticket }) => ticket) };
}

// Append immediately after the lease's begin-sending UPDATE in the same D1 batch.
export function insertTelegramViewTickets(
  db: D1Database,
  receiptId: number,
  attempt: number,
  leaseId: string,
  tickets: readonly TelegramViewTicket[],
): D1PreparedStatement {
  if (tickets.length < 1 || tickets.length > 2) throw new RangeError("Invalid Telegram view ticket count.");
  return db.prepare(`
    WITH tickets (token_sha256, after_id, after_epoch) AS (VALUES ${tickets.map(() => "(?, ?, ?)").join(", ")})
    INSERT INTO telegram_view_ticket (token_sha256, origin_receipt_id, origin_attempt, after_id, after_epoch, expires_at)
    SELECT tickets.token_sha256, reply.receipt_id, reply.attempts, tickets.after_id, tickets.after_epoch,
      unixepoch() + ${TICKET_SECONDS}
    FROM telegram_outbox AS reply
    JOIN telegram_inbox AS inbox USING (receipt_id)
    JOIN telegram_view AS origin USING (receipt_id)
    CROSS JOIN tickets
    WHERE changes() = 1 AND reply.receipt_id = ? AND reply.attempts = ? AND reply.lease_id = ?
      AND reply.state = 'sending' AND inbox.receipt_nonce = ?
  `).bind(...tickets.flatMap(({ sha256, afterId, afterEpoch }) => [sha256, afterId, afterEpoch]),
    receiptId, attempt, leaseId, TELEGRAM_VIEW_MARKER);
}

export async function reapTelegramViewTickets(db: D1Database): Promise<void> {
  try {
    const result = await db.prepare(`
      DELETE FROM telegram_view_ticket WHERE token_sha256 IN (
        SELECT token_sha256 FROM telegram_view_ticket
        WHERE expires_at <= unixepoch() ORDER BY expires_at, token_sha256 LIMIT ${TICKET_REAP_LIMIT}
      )
    `).run();
    if (result.success) return;
  } catch {
    // Avoid exposing private parameters in a D1 error.
  }
  throw new Error("Telegram view ticket cleanup could not be confirmed.");
}

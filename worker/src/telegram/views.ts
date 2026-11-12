import { checkOwnerId, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { listDeletedSubscriptions, listOwnedSubscriptions } from "../subscriptions.ts";
import type { TelegramLifecycleButton } from "./lifecycle-actions.ts";
import type { TelegramSubscriptionReadButton } from "./subscription-read.ts";
import { displayTelegramDate } from "./display-time.ts";
export { displayTelegramDate } from "./display-time.ts";
import { inTelegramScope, TELEGRAM_PAGE_JUMP_RECEIPTS, type TelegramPolicy, type TelegramViewKind, type TelegramViewUpdate } from "./protocol.ts";

export const TELEGRAM_VIEW_MARKER = "view:v1";
export const TELEGRAM_VIEW_RECEIPTS = `'${TELEGRAM_VIEW_MARKER}',${TELEGRAM_PAGE_JUMP_RECEIPTS}`;

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

export const TELEGRAM_VIEW_PAGE_SIZE = 8;
const PAGE_SIZE = TELEGRAM_VIEW_PAGE_SIZE;
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
  admissionGuard?: D1PreparedStatement,
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
    const steps: D1PreparedStatement[] = admissionGuard ? [admissionGuard] : [];
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
            AND inbox.receipt_nonce IN (${TELEGRAM_VIEW_RECEIPTS}) AND inbox.bot_id = ? AND inbox.actor_id = ?
            AND inbox.chat_id = ? AND inbox.chat_type = ? AND inbox.thread_id IS ?
            AND reply.state = 'sent' AND reply.sent_message_id = ? AND reply.attempts = ticket.origin_attempt
            AND (inbox.actor_id = ? OR COALESCE((
              SELECT allowed=1 AND (inbox.receipt_nonce='${TELEGRAM_VIEW_MARKER}' OR message_date<inbox.message_date)
              FROM telegram_auth WHERE bot_id = inbox.bot_id AND user_id = inbox.actor_id
            ), 1) = 1)
          ${conflict}
        `).bind(...scope, digest, policy.botId, event.actorId, event.chatId,
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

export function displayTelegramName(name: string): string {
  const clean = name.replace(/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/gu, " ")
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/giu, "[链接已省略]").trim();
  return Array.from(clean).slice(0, 80).join("") || "未命名";
}

async function expiryPage(db: D1Database, ownerId: string, view: TelegramView) {
  checkOwnerId(ownerId);
  try {
    const result = await db.prepare(`
      SELECT id, name, expire_at AS epoch, ${SUBSCRIPTION_LIFECYCLE_REVISION} AS lifecycleRevision FROM subscriptions
      WHERE owner_id = ? AND expire_at BETWEEN unixepoch() AND unixepoch() + ${EXPIRY_SECONDS}
        ${view.afterId === null ? "" : "AND (expire_at, id) > (?, ?)"}
      ORDER BY expire_at, id LIMIT ?
    `).bind(ownerId, ...(view.afterId === null ? [] : [view.afterEpoch, view.afterId]), PAGE_SIZE + 1)
      .all<{ id: number; name: string; epoch: number; lifecycleRevision: number }>();
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
  includeReadButtons = false,
  absoluteOrdinals = includeReadButtons,
  timeZone = "UTC",
): Promise<{ text: string; buttons: TelegramViewButton[]; lifecycleButtons: TelegramLifecycleButton[];
  readButtons?: TelegramSubscriptionReadButton[]; readTargets?: { subscriptionId: number; lifecycleRevision: number }[] }> {
  if ((view.afterId !== null && !validInteger(view.afterId, 1))
    || (view.afterEpoch !== null && !validInteger(view.afterEpoch, 1))
    || (view.afterEpoch !== null) !== (view.kind !== "list" && view.afterId !== null)) {
    throw new RangeError("Invalid Telegram view cursor.");
  }

  let title: string;
  let items: { id: number; name: string; epoch?: number; lifecycleRevision: number }[];
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
      items = page.items.map((row) => ({ ...row, epoch: row.deletedAt }));
      if (page.nextCursor) next = { afterId: page.nextCursor.id, afterEpoch: page.nextCursor.deletedAt };
      break;
    }
  }

  let preceding = 0;
  if (absoluteOrdinals && view.kind === "list" && view.afterId !== null && items.length > 0) {
    const row = await db.prepare("SELECT count(*) AS preceding FROM subscriptions WHERE owner_id=? AND id<?")
      .bind(ownerId, items[0].id).first<{ preceding: number }>().catch(() => null);
    if (!row || !validInteger(row.preceding, 0)) throw new Error("Telegram subscription position could not be read.");
    preceding = row.preceding;
  }
  const ordinal = (index: number) => preceding + index + 1;
  const lines = items.map((item, index) => `${ordinal(index)}. ${displayTelegramName(item.name)}` +
    (item.epoch === undefined ? "" : ` · ${displayTelegramDate(item.epoch, timeZone)}`));
  const lifecycleButtons = items.flatMap<TelegramLifecycleButton>(({ id, lifecycleRevision }, index) => {
    const target = { subscriptionId: id, expectedLifecycleRevision: lifecycleRevision };
    return view.kind === "recycle"
      ? [{ ...target, text: `${ordinal(index)} 恢复`, action: "restore" }]
      : [{ ...target, text: `${ordinal(index)} 重命名`, action: "rename" },
        { ...target, text: `${ordinal(index)} 删除`, action: "trash-prompt" }];
  });
  const buttons: TelegramViewButton[] = [];
  if (next) buttons.push({ text: "下一页", ...next });
  if (view.afterId !== null) buttons.push({ text: "第一页", afterId: null, afterEpoch: null });
  const readButtons = includeReadButtons && view.kind !== "recycle"
    ? items.map<TelegramSubscriptionReadButton>(({ id }, index) => ({ text: `${ordinal(index)} 详情`, kind: "detail", subscriptionId: id }))
    : undefined;
  return { text: [title, ...(lines.length ? lines : ["当前没有记录。"])].join("\n"), buttons, lifecycleButtons,
    ...(readButtons ? { readButtons, readTargets: items.map(({ id, lifecycleRevision }) => ({ subscriptionId: id, lifecycleRevision })) } : {}) };
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
  general = false, previousChanges = 1,
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
    WHERE changes() = ? AND reply.receipt_id = ? AND reply.attempts = ? AND reply.lease_id = ?
      AND reply.state = 'sending' AND inbox.receipt_nonce ${general ? "='general-view:v1'" : `IN (${TELEGRAM_VIEW_RECEIPTS})`}
  `).bind(...tickets.flatMap(({ sha256, afterId, afterEpoch }) => [sha256, afterId, afterEpoch]),
    previousChanges, receiptId, attempt, leaseId);
}

export async function reapTelegramViewTickets(db: D1Database, generalBotId?: string): Promise<void> {
  try {
    const result = await db.prepare(`
      DELETE FROM telegram_view_ticket WHERE token_sha256 IN (
        SELECT token_sha256 FROM telegram_view_ticket AS ticket
        WHERE expires_at <= unixepoch() ${generalBotId === undefined ? "" : `AND EXISTS (SELECT 1 FROM telegram_inbox AS origin
          WHERE origin.receipt_id=ticket.origin_receipt_id AND origin.bot_id=? AND origin.receipt_nonce='general-view:v1')`}
        ORDER BY expires_at, token_sha256 LIMIT ${TICKET_REAP_LIMIT}
      )
    `).bind(...(generalBotId === undefined ? [] : [generalBotId])).run();
    if (result.success) return;
  } catch {
    // Avoid exposing private parameters in a D1 error.
  }
  throw new Error("Telegram view ticket cleanup could not be confirmed.");
}

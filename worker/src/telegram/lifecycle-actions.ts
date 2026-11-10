import { SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { normalizeSubscriptionName, prepareOwnedSubscriptionMutation, type SubscriptionMutation } from "../subscriptions.ts";
import { inTelegramScope, TELEGRAM_PAGE_JUMP_RECEIPTS, type TelegramLifecycleUpdate, type TelegramPolicy } from "./protocol.ts";
import { TELEGRAM_VIEW_RECEIPTS } from "./views.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_REPLY_TTL, generalCurrentReceiptSql, generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";

export const TELEGRAM_LIFECYCLE_MARKER = "lifecycle:v1";
export const GENERAL_LIFECYCLE_MARKER = "general-lifecycle:v1";
export const GENERAL_LIFECYCLE_VIEW_MARKER = "general-lifecycle-view:v1";

type LifecyclePolicy = TelegramPolicy | GeneralTelegramPin;

type Action = "rename" | "trash-prompt" | "trash" | "restore";
type ReplyKind = "rename-prompt" | "trash-prompt" | "renamed" | "trashed" | "restored" | "cancelled" | "invalid" | "stale";

interface Target {
  subscriptionId: number;
  expectedLifecycleRevision: number;
}

export interface TelegramLifecycleReply extends Target {
  kind: ReplyKind;
}

export interface TelegramLifecycleButton extends Target {
  action: Action;
  text: string;
}

export interface TelegramLifecycleTicket extends Target {
  action: Action;
  sha256: string;
}

interface Candidate extends Target {
  action: Action;
  originReceiptId: number;
}

interface AdmissionSource {
  sql: string;
  bindings: readonly (number | string | null)[];
  columns: string;
  match: string;
}

const TICKET_PREFIX = "sba1_";
const TICKET_PATTERN = /^sba1_[A-Za-z0-9_-]{22}(?![\s\S])/u;
const TICKET_SECONDS = 10 * 60;
const WAIT_SECONDS = 10 * 60;
const REAP_LIMIT = 40;
const MAX_BUTTONS = 16;
const encoder = new TextEncoder();

function actionOrigin(general: boolean): string {
  const viewOrigin = general ? `= '${GENERAL_LIFECYCLE_VIEW_MARKER}'` : `IN (${TELEGRAM_VIEW_RECEIPTS})`;
  return `(
  (inbox.receipt_nonce ${viewOrigin} AND EXISTS (
    SELECT 1 FROM telegram_view AS view WHERE view.receipt_id = inbox.receipt_id
      AND ((view.kind ${general ? "= 'list'" : "IN ('list', 'expiry')"} AND ticket.action IN ('rename', 'trash-prompt'))
        OR (view.kind = 'recycle' AND ticket.action = 'restore'))
  )) OR
  (inbox.receipt_nonce = '${general ? GENERAL_LIFECYCLE_MARKER : TELEGRAM_LIFECYCLE_MARKER}' AND ticket.action = 'trash' AND EXISTS (
    SELECT 1 FROM telegram_lifecycle_action AS prompt WHERE prompt.receipt_id = inbox.receipt_id
      AND prompt.kind = 'trash-prompt' AND prompt.subscription_id = ticket.subscription_id
      AND prompt.expected_revision = ticket.expected_revision
  ))
)`;
}

const originScope = `inbox.bot_id = ? AND inbox.actor_id = ? AND inbox.chat_id = ?
  AND inbox.chat_type = ? AND inbox.thread_id IS ? AND reply.state = 'sent' AND reply.sent_message_id = ?`;
const isolationOrigin = `(inbox.actor_id = ? OR COALESCE((
    SELECT allowed=1 AND (inbox.receipt_nonce NOT IN (${TELEGRAM_PAGE_JUMP_RECEIPTS}) OR message_date<inbox.message_date)
    FROM telegram_auth WHERE bot_id = inbox.bot_id AND user_id = inbox.actor_id
  ), 1) = 1)`;

const freshReceipt = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";

async function digestTicket(ticket: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(ticket));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function actionSource(
  policy: LifecyclePolicy,
  event: TelegramLifecycleUpdate,
  digest: string | null,
): AdmissionSource {
  const messageId = event.kind === "lifecycle-callback" ? event.messageId : event.promptMessageId;
  const general = "privateManagement" in policy;
  const marker = general ? GENERAL_LIFECYCLE_MARKER : TELEGRAM_LIFECYCLE_MARKER;
  const origin = [policy.botId, event.actorId, event.chatId, event.chatType, event.threadId, messageId,
    ...(general ? [...generalPolicyBindings(policy), event.messageDate, event.messageDate, event.messageDate, event.updateId]
      : [policy.adminId])];
  const eligibleOrigin = `${originScope} AND ${general ? `(${generalCurrentReceiptSql("inbox", GENERAL_ACTOR_QUEUE_CAPACITY)})
    AND ?>=inbox.message_date AND ?>unixepoch()-${GENERAL_REPLY_TTL} AND ?<=unixepoch()+60
    AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=inbox.bot_id AND update_id=?)` : isolationOrigin}`;
  if (event.kind === "lifecycle-callback") {
    return {
      sql: `FROM telegram_lifecycle_ticket AS ticket
        JOIN telegram_inbox AS inbox ON inbox.receipt_id = ticket.origin_receipt_id
        JOIN telegram_outbox AS reply ON reply.receipt_id = inbox.receipt_id
        WHERE ticket.token_sha256 = ? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at > unixepoch()
          AND reply.attempts = ticket.origin_attempt AND ${actionOrigin(general)} AND ${eligibleOrigin}
          AND (ticket.action <> 'rename' OR NOT EXISTS (
            SELECT 1 FROM telegram_rename_wait AS wait
            WHERE wait.bot_id = inbox.bot_id AND wait.actor_id = inbox.actor_id AND wait.chat_id = inbox.chat_id
              AND wait.chat_type = inbox.chat_type AND wait.thread_key = COALESCE(inbox.thread_id, 0)
              AND wait.last_update_id >= ? AND wait.expires_at > unixepoch() - ${WAIT_SECONDS}
          ))`,
      bindings: [digest, ...origin, event.updateId],
      columns: "ticket.action, ticket.subscription_id, ticket.expected_revision, ticket.origin_receipt_id",
      match: "ticket.action = ? AND ticket.subscription_id = ? AND ticket.expected_revision = ? AND ticket.origin_receipt_id = ?",
    };
  }
  return {
    sql: `FROM telegram_rename_wait AS wait
      JOIN telegram_lifecycle_action AS prompt ON prompt.receipt_id = wait.origin_receipt_id
      JOIN telegram_inbox AS inbox ON inbox.receipt_id = prompt.receipt_id
      JOIN telegram_outbox AS reply ON reply.receipt_id = inbox.receipt_id
      WHERE wait.used_by_receipt_id IS NULL AND wait.expires_at > unixepoch() AND wait.last_update_id < ?
        AND prompt.kind = 'rename-prompt' AND inbox.receipt_nonce = '${marker}'
        AND wait.bot_id = inbox.bot_id AND wait.actor_id = inbox.actor_id AND wait.chat_id = inbox.chat_id
        AND wait.chat_type = inbox.chat_type AND wait.thread_key = COALESCE(inbox.thread_id, 0)
        AND ${eligibleOrigin}`,
    bindings: [event.updateId, ...origin],
    columns: "'rename', prompt.subscription_id, prompt.expected_revision, wait.origin_receipt_id",
    match: "'rename' = ? AND prompt.subscription_id = ? AND prompt.expected_revision = ? AND wait.origin_receipt_id = ?",
  };
}

function actionReceiptSteps(
  db: D1Database,
  digest: string,
  key: readonly [string, number, string],
  action: Action,
): D1PreparedStatement[] {
  const steps = [
    db.prepare(`
      UPDATE telegram_lifecycle_ticket AS ticket SET used_by_receipt_id = incoming.receipt_id
      FROM telegram_inbox AS incoming
      WHERE ticket.token_sha256 = ? AND ticket.used_by_receipt_id IS NULL AND ${freshReceipt}
    `).bind(digest, ...key),
    db.prepare(`
      INSERT INTO telegram_lifecycle_action (receipt_id, kind, subscription_id, expected_revision)
      SELECT incoming.receipt_id, CASE WHEN ticket.action IN ('rename', 'trash-prompt') AND EXISTS (
        SELECT 1 FROM subscriptions WHERE id = ticket.subscription_id AND owner_id = incoming.actor_id
          AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ticket.expected_revision
          AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id = subscriptions.id)
      ) THEN CASE ticket.action WHEN 'rename' THEN 'rename-prompt' ELSE 'trash-prompt' END ELSE 'stale' END,
        ticket.subscription_id, ticket.expected_revision
      FROM telegram_inbox AS incoming
      JOIN telegram_lifecycle_ticket AS ticket ON ticket.used_by_receipt_id = incoming.receipt_id
      WHERE ${freshReceipt}
    `).bind(...key),
  ];
  if (action === "rename") {
    steps.push(db.prepare(`
      INSERT INTO telegram_rename_wait
        (bot_id, actor_id, chat_id, chat_type, thread_key, origin_receipt_id, last_update_id, expires_at)
      SELECT incoming.bot_id, incoming.actor_id, incoming.chat_id, incoming.chat_type, COALESCE(incoming.thread_id, 0),
        incoming.receipt_id, incoming.update_id, unixepoch() + ${WAIT_SECONDS}
      FROM telegram_inbox AS incoming
      JOIN telegram_lifecycle_action AS action USING (receipt_id)
      WHERE ${freshReceipt} AND action.kind = 'rename-prompt'
      ON CONFLICT (bot_id, actor_id, chat_id, chat_type, thread_key) DO UPDATE SET
        origin_receipt_id = excluded.origin_receipt_id, last_update_id = excluded.last_update_id,
        expires_at = excluded.expires_at, used_by_receipt_id = NULL
      WHERE telegram_rename_wait.last_update_id < excluded.last_update_id
        OR telegram_rename_wait.expires_at <= unixepoch() - ${WAIT_SECONDS}
    `).bind(...key));
  }
  return steps;
}

function renameReceiptSteps(
  db: D1Database,
  key: readonly [string, number, string],
  candidate: Candidate,
  kind: "cancelled" | "invalid" | "stale",
): D1PreparedStatement[] {
  return [
    db.prepare(`
      UPDATE telegram_rename_wait AS wait SET used_by_receipt_id = incoming.receipt_id, last_update_id = incoming.update_id
      FROM telegram_inbox AS incoming
      WHERE wait.origin_receipt_id = ? AND wait.used_by_receipt_id IS NULL
        AND wait.last_update_id < incoming.update_id AND ${freshReceipt}
    `).bind(candidate.originReceiptId, ...key),
    db.prepare(`
      INSERT INTO telegram_lifecycle_action (receipt_id, kind, subscription_id, expected_revision)
      SELECT incoming.receipt_id, ?, prompt.subscription_id, prompt.expected_revision
      FROM telegram_inbox AS incoming
      JOIN telegram_rename_wait AS wait ON wait.used_by_receipt_id = incoming.receipt_id
      JOIN telegram_lifecycle_action AS prompt ON prompt.receipt_id = wait.origin_receipt_id
      WHERE ${freshReceipt}
    `).bind(kind, ...key),
  ];
}

async function mutationSteps(
  db: D1Database,
  key: readonly [string, number, string],
  ownerId: string,
  candidate: Candidate,
  mutation: SubscriptionMutation,
  general: GeneralTelegramPin | null,
): Promise<D1PreparedStatement[]> {
  const prepared = await prepareOwnedSubscriptionMutation(db, {
    id: candidate.subscriptionId, ownerId, expectedLifecycleRevision: candidate.expectedLifecycleRevision,
  }, mutation, {
    sql: `EXISTS (SELECT 1 FROM telegram_inbox AS incoming
      JOIN telegram_lifecycle_action AS action USING (receipt_id)
      WHERE ${freshReceipt} AND incoming.actor_id = ? AND action.kind = 'stale'
        AND action.subscription_id = ? AND action.expected_revision = ?
        ${general ? `AND ${generalCurrentReceiptSql("incoming")}` : ""})`,
    bindings: [...key, ownerId, candidate.subscriptionId, candidate.expectedLifecycleRevision,
      ...(general ? generalPolicyBindings(general) : [])],
  });
  const outcome = { rename: "renamed", trash: "trashed", restore: "restored" }[mutation.kind];
  return [
    prepared.first,
    db.prepare(`
      UPDATE telegram_lifecycle_action SET kind = ?
      WHERE changes() = 1 AND kind = 'stale'
        AND receipt_id = (SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${freshReceipt})
    `).bind(outcome, ...key),
    ...prepared.followups,
  ];
}

export async function acceptTelegramLifecycle(
  db: D1Database,
  policy: TelegramPolicy,
  event: TelegramLifecycleUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event)) return "ignored";
  return acceptLifecycle(db, policy, event);
}

export async function acceptGeneralTelegramLifecycle(
  db: D1Database, pin: GeneralTelegramPin, event: TelegramLifecycleUpdate,
): Promise<"accepted" | "ignored"> {
  if (!pin.privateManagement || event.actorId === pin.botId || event.chatType !== "private"
    || event.chatId !== event.actorId || event.threadId !== null) return "ignored";
  return acceptLifecycle(db, pin, event);
}

async function acceptLifecycle(
  db: D1Database, policy: LifecyclePolicy, event: TelegramLifecycleUpdate,
): Promise<"accepted" | "ignored"> {
  const general = "privateManagement" in policy ? policy : null;
  if (event.kind === "lifecycle-callback" && !TICKET_PATTERN.test(event.ticket)) return "ignored";

  try {
    const digest = event.kind === "lifecycle-callback" ? await digestTicket(event.ticket) : null;
    const source = actionSource(policy, event, digest);
    const candidate = await db.prepare(`
      WITH candidate (action, subscriptionId, expectedLifecycleRevision, originReceiptId) AS (
        SELECT ${source.columns} ${source.sql}
      )
      SELECT * FROM candidate
    `).bind(...source.bindings).first<Candidate>();
    if (!candidate) return "ignored";

    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const steps = [db.prepare(`
      INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
      SELECT ?, ?, ?, ?, ?, ?, ?, ?, 'help', ? ${source.sql} AND ${source.match}
      ON CONFLICT (bot_id, update_id) DO NOTHING
    `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.chatType, event.messageId,
      event.messageDate, event.threadId, nonce, ...source.bindings, candidate.action, candidate.subscriptionId,
      candidate.expectedLifecycleRevision, candidate.originReceiptId)];
    if (general) steps.push(prepareGeneralReceiptAuthority(db, general, key));

    let mutation: SubscriptionMutation | undefined;
    if (digest !== null) {
      steps.push(...actionReceiptSteps(db, digest, key, candidate.action));
      if (candidate.action === "trash" || candidate.action === "restore") mutation = { kind: candidate.action };
    } else if (event.kind === "rename-reply") {
      let kind: "cancelled" | "invalid" | "stale" = "stale";
      if (/^(?:取消|\/cancel|cancel|退出)(?![\s\S])/iu.test(event.text.trim())) {
        kind = "cancelled";
      } else {
        try {
          mutation = { kind: "rename", name: normalizeSubscriptionName(event.text) };
        } catch {
          kind = "invalid";
        }
      }
      steps.push(...renameReceiptSteps(db, key, candidate, kind));
    }
    if (mutation) steps.push(...await mutationSteps(db, key, event.actorId, candidate, mutation, general));
    steps.push(
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${freshReceipt}
      `).bind(...key),
      // A missing companion or incomplete mutation rolls the batch back by
      // violating the inbox command's NOT NULL constraint.
      db.prepare(`
        UPDATE telegram_inbox AS incoming SET receipt_nonce = ?, command = CASE WHEN EXISTS (
          SELECT 1 FROM telegram_lifecycle_action AS action
          JOIN telegram_outbox AS reply USING (receipt_id)
          WHERE action.receipt_id = incoming.receipt_id
            ${general ? `AND ${generalCurrentReceiptSql("incoming")}` : ""}
            AND (action.kind <> 'rename-prompt' OR EXISTS (
              SELECT 1 FROM telegram_rename_wait WHERE origin_receipt_id = incoming.receipt_id
            ))
            AND (action.kind NOT IN ('renamed', 'trashed', 'restored') OR (
              EXISTS (SELECT 1 FROM subscription_lifecycle WHERE subscription_id = action.subscription_id
                AND revision = action.expected_revision + 1)
              AND (action.kind = 'trashed') = EXISTS (
                SELECT 1 FROM subscription_trash WHERE id = action.subscription_id AND owner_id = incoming.actor_id
                  AND lifecycle_revision = action.expected_revision + 1
              )
              AND (action.kind <> 'trashed') = EXISTS (
                SELECT 1 FROM subscriptions WHERE id = action.subscription_id AND owner_id = incoming.actor_id
              )
            ))
        ) THEN command END
        WHERE ${freshReceipt}
        RETURNING receipt_id
      `).bind(general ? GENERAL_LIFECYCLE_MARKER : TELEGRAM_LIFECYCLE_MARKER,
        ...(general ? generalPolicyBindings(general) : []), ...key),
    );
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && receipt.results.length <= 1
      && results.every((result) => result.success)) {
      return receipt.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // Avoid exposing private parameters in a backend error.
  }
  throw new Error("Telegram lifecycle receipt could not be confirmed.");
}

const replyText: Record<ReplyKind, string> = {
  "rename-prompt": "请回复这条消息，发送新的订阅名称。发送 /cancel 取消。",
  "trash-prompt": "确认将该订阅移入回收站？30 天内可通过 /recycle 恢复。",
  renamed: "订阅名称已更新。",
  trashed: "已移入回收站。30 天内可通过 /recycle 恢复。",
  restored: "已恢复订阅。",
  cancelled: "已取消重命名。",
  invalid: "名称无效。请重新发起重命名，输入最多 64 个字符。",
  stale: "订阅已变更或无法操作。请重新打开列表或回收站。",
};

export function renderTelegramLifecycle(
  { kind, subscriptionId, expectedLifecycleRevision }: TelegramLifecycleReply,
): { text: string; buttons: TelegramLifecycleButton[]; forceReply: boolean } {
  const buttons: TelegramLifecycleButton[] = kind === "trash-prompt"
    ? [{ text: "确认移入回收站", action: "trash", subscriptionId, expectedLifecycleRevision }] : [];
  return { text: replyText[kind], buttons, forceReply: kind === "rename-prompt" };
}

export async function prepareTelegramLifecycleTickets(buttons: readonly TelegramLifecycleButton[]): Promise<{
  keyboard: { text: string; callback_data: string }[][];
  tickets: TelegramLifecycleTicket[];
}> {
  if (buttons.length > MAX_BUTTONS) throw new RangeError("Invalid Telegram lifecycle button count.");
  const entries = await Promise.all(buttons.map(async ({ text, action, subscriptionId, expectedLifecycleRevision }) => {
    const bytes = crypto.getRandomValues(new Uint8Array(16));
    const token = TICKET_PREFIX + btoa(String.fromCharCode(...bytes)).replace(/\+/gu, "-").replace(/\//gu, "_")
      .replace(/=+$/u, "");
    return {
      button: { text, callback_data: token },
      ticket: { action, subscriptionId, expectedLifecycleRevision, sha256: await digestTicket(token) },
    };
  }));
  const keyboard = Array.from({ length: Math.ceil(entries.length / 2) }, (_, index) =>
    entries.slice(index * 2, index * 2 + 2).map(({ button }) => button));
  return { keyboard, tickets: entries.map(({ ticket }) => ticket) };
}

export function insertTelegramLifecycleTickets(
  db: D1Database,
  receiptId: number,
  attempt: number,
  leaseId: string,
  tickets: readonly TelegramLifecycleTicket[],
  previousChanges = 1,
  general = false,
): D1PreparedStatement {
  if (!validInteger(tickets.length, 1, MAX_BUTTONS) || !validInteger(previousChanges, 1, 2)) {
    throw new RangeError("Invalid Telegram lifecycle ticket count.");
  }
  return db.prepare(`
    WITH tickets (token_sha256, action, subscription_id, expected_revision) AS (
      VALUES ${tickets.map(() => "(?, ?, ?, ?)").join(", ")}
    )
    INSERT INTO telegram_lifecycle_ticket
      (token_sha256, origin_receipt_id, origin_attempt, action, subscription_id, expected_revision, expires_at)
    SELECT ticket.token_sha256, reply.receipt_id, reply.attempts, CASE WHEN ${actionOrigin(general)} THEN ticket.action END,
      ticket.subscription_id, ticket.expected_revision, unixepoch() + ${TICKET_SECONDS}
    FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
    CROSS JOIN tickets AS ticket
    WHERE changes() = ? AND reply.receipt_id = ? AND reply.attempts = ? AND reply.lease_id = ?
      AND reply.state = 'sending'
  `).bind(...tickets.flatMap(({ sha256, action, subscriptionId, expectedLifecycleRevision }) =>
    [sha256, action, subscriptionId, expectedLifecycleRevision]), previousChanges, receiptId, attempt, leaseId);
}

export async function reapTelegramLifecycle(db: D1Database, generalBotId?: string): Promise<void> {
  const scope = generalBotId === undefined ? "" : `AND EXISTS (SELECT 1 FROM telegram_inbox AS origin
    WHERE origin.receipt_id=expired.origin_receipt_id AND origin.bot_id=?
      AND origin.receipt_nonce IN ('${GENERAL_LIFECYCLE_VIEW_MARKER}','${GENERAL_LIFECYCLE_MARKER}'))`;
  const bindings = generalBotId === undefined ? [] : [generalBotId];
  try {
    const results = await db.batch([
      db.prepare(`
        DELETE FROM telegram_lifecycle_ticket WHERE token_sha256 IN (
          SELECT token_sha256 FROM telegram_lifecycle_ticket AS expired
          WHERE expires_at <= unixepoch() ${scope} ORDER BY expires_at, token_sha256 LIMIT ${REAP_LIMIT}
        )
      `).bind(...bindings),
      db.prepare(`
        DELETE FROM telegram_rename_wait WHERE origin_receipt_id IN (
          SELECT origin_receipt_id FROM telegram_rename_wait AS expired
          WHERE expires_at <= unixepoch() - ${WAIT_SECONDS} ${scope} ORDER BY expires_at, origin_receipt_id LIMIT ${REAP_LIMIT}
        )
      `).bind(...bindings),
    ]);
    if (results.length === 2 && results.every((result) => result.success)) return;
  } catch {
    // Avoid exposing private parameters in a backend error.
  }
  throw new Error("Telegram lifecycle cleanup could not be confirmed.");
}

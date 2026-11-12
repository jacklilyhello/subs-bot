import { digestHex, readSnapshotNodeRange, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger, type SubscriptionSnapshot } from "../storage.ts";
import { inTelegramScope, SUBSCRIPTION_NODE_TICKET, SUBSCRIPTION_READ_RECEIPT_MARKER,
  type TelegramPolicy, type TelegramSubscriptionNodeUpdate } from "./protocol.ts";
import { displayTelegramName } from "./views.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";

export const TELEGRAM_SUBSCRIPTION_NODE_MARKER = "subnodes:v1";
const PAGE_SIZE = 15;
const PAGE_TIMEOUT_MS = 5_000;
const TICKET_SECONDS = 600;
const encoder = new TextEncoder();

export type NodePageTarget = SubscriptionSnapshot & { lifecycleRevision: number; pageOffset: number };
export type TelegramNodePageButton = NodePageTarget & { text: string };
export type TelegramNodePageTicket = NodePageTarget & { sha256: string };
type Guard = { sql: string; bindings: readonly (string | number | null)[] };
type NodeLease = { receiptId: number; actorId: string; chatId: string; chatType: string; threadId: number | null;
  leaseId: string; attempts: number };

const PIN_FIELDS = "subscription_id,generation,lifecycle_revision,snapshot_id,manifest_sha256,node_count,page_offset";
const FRESH = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";

export async function telegramSubscriptionNodePagesReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
      AND name IN ('telegram_subscription_node_page','telegram_subscription_node_ticket')`).first<{ present: number }>();
    return row?.present === 2;
  } catch {
    throw new Error("Telegram subscription node page schema could not be confirmed.");
  }
}

async function ticketDigest(token: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(token)));
}

export async function acceptTelegramSubscriptionNodePage(
  db: D1Database, policy: TelegramPolicy, event: TelegramSubscriptionNodeUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.threadId !== null
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)
    || !SUBSCRIPTION_NODE_TICKET.test(event.ticket)) return "ignored";
  try {
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const digest = await ticketDigest(event.ticket);
    const fields = PIN_FIELDS.split(",").map((column) => `ticket.${column}`).join(",");
    const results = await db.batch([
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,'private',?,?,NULL,'help',?
        FROM telegram_subscription_node_ticket AS ticket
        JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
        JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
        LEFT JOIN telegram_subscription_read AS detail ON detail.receipt_id=origin.receipt_id
          AND origin.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}' AND detail.kind='detail'
        LEFT JOIN telegram_subscription_node_page AS page ON page.receipt_id=origin.receipt_id
          AND origin.receipt_nonce='${TELEGRAM_SUBSCRIPTION_NODE_MARKER}'
        LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id
        WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
          AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type='private' AND origin.thread_id IS NULL
          AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt
          AND ((detail.subscription_id=ticket.subscription_id AND ticket.page_offset=0) OR (
            page.subscription_id=ticket.subscription_id AND page.generation=ticket.generation
            AND page.lifecycle_revision=ticket.lifecycle_revision AND page.snapshot_id=ticket.snapshot_id
            AND page.manifest_sha256=ticket.manifest_sha256 AND page.node_count=ticket.node_count
            AND abs(page.page_offset-ticket.page_offset)=${PAGE_SIZE}))
          AND ? BETWEEN unixepoch()-900 AND unixepoch()+30
          AND (origin.actor_id=? OR (COALESCE(auth.allowed,1)=1
            AND COALESCE(detail.auth_message_date,page.auth_message_date)=COALESCE(auth.message_date,0)
            AND COALESCE(detail.auth_message_id,page.auth_message_id)=COALESCE(auth.message_id,0)
            AND origin.message_date>COALESCE(auth.message_date,0) AND ?>COALESCE(auth.message_date,0)))
        ON CONFLICT (bot_id,update_id) DO NOTHING`).bind(policy.botId, event.updateId, event.actorId, event.chatId,
        event.messageId, event.messageDate, nonce, digest, policy.botId, event.actorId, event.chatId,
        event.messageId, event.messageDate, policy.adminId, event.messageDate),
      db.prepare(`UPDATE telegram_subscription_node_ticket AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${FRESH}`)
        .bind(digest, ...key),
      db.prepare(`INSERT INTO telegram_subscription_node_page (receipt_id,${PIN_FIELDS},auth_message_date,auth_message_id)
        SELECT incoming.receipt_id,${fields},COALESCE(auth.message_date,0),COALESCE(auth.message_id,0)
        FROM telegram_inbox AS incoming JOIN telegram_subscription_node_ticket AS ticket ON ticket.used_by_receipt_id=incoming.receipt_id
        LEFT JOIN telegram_auth AS auth ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id AND incoming.actor_id<>?
        WHERE ${FRESH}`).bind(policy.adminId, ...key),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${FRESH}`)
        .bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_subscription_node_page AS page JOIN telegram_outbox USING(receipt_id)
        WHERE page.receipt_id=incoming.receipt_id) THEN command END WHERE ${FRESH} RETURNING receipt_id`)
        .bind(TELEGRAM_SUBSCRIPTION_NODE_MARKER, ...key),
    ]);
    const receipt = results[4];
    if (results.length === 5 && results.every(({ success }) => success) && receipt.results.length <= 1) {
      return receipt.results.length ? "accepted" : "ignored";
    }
  } catch {
    // The fixed webhook error must not expose the callback or backend values.
  }
  throw new Error("Telegram subscription node page receipt could not be confirmed.");
}

export async function prepareTelegramNodePageTickets(buttons: readonly TelegramNodePageButton[]): Promise<{
  keyboard: { text: string; callback_data: string }[][]; tickets: TelegramNodePageTicket[];
}> {
  if (!validInteger(buttons.length, 1, 2)) throw new RangeError("Invalid Telegram node page button count.");
  const entries = await Promise.all(buttons.map(async ({ text, ...pin }) => {
    const token = "sbn1_" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
      .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    return { button: { text, callback_data: token }, ticket: { ...pin, sha256: await ticketDigest(token) } };
  }));
  return { keyboard: entries.map(({ button }) => [button]), tickets: entries.map(({ ticket }) => ticket) };
}

export function insertTelegramNodePageTickets(
  db: D1Database, lease: NodeLease, tickets: readonly TelegramNodePageTicket[], previousChanges: number,
  general = false,
): D1PreparedStatement {
  if (!validInteger(tickets.length, 1, 2) || !validInteger(previousChanges, 1, 16)) {
    throw new RangeError("Invalid Telegram node page ticket count.");
  }
  return db.prepare(`WITH tickets (sha256,${PIN_FIELDS}) AS (VALUES ${tickets.map(() => "(?,?,?,?,?,?,?,?)").join(",")})
    INSERT INTO telegram_subscription_node_ticket (token_sha256,origin_receipt_id,origin_attempt,${PIN_FIELDS},expires_at)
    SELECT ticket.sha256,inbox.receipt_id,reply.attempts,
      CASE WHEN inbox.chat_type='private' AND inbox.actor_id=inbox.chat_id AND inbox.thread_id IS NULL AND (
        (detail.subscription_id=ticket.subscription_id AND ticket.page_offset=0) OR (
          page.subscription_id=ticket.subscription_id AND page.generation=ticket.generation
          AND page.lifecycle_revision=ticket.lifecycle_revision AND page.snapshot_id=ticket.snapshot_id
          AND page.manifest_sha256=ticket.manifest_sha256 AND page.node_count=ticket.node_count
          AND abs(page.page_offset-ticket.page_offset)=${PAGE_SIZE})) THEN ticket.subscription_id END,
      ticket.generation,ticket.lifecycle_revision,ticket.snapshot_id,ticket.manifest_sha256,ticket.node_count,
      ticket.page_offset,unixepoch()+${TICKET_SECONDS}
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    LEFT JOIN telegram_subscription_read AS detail ON detail.receipt_id=inbox.receipt_id
      AND inbox.receipt_nonce ${general ? "IN ('general-subscription-read:v1','general-number-detail:v1')" : `='${SUBSCRIPTION_READ_RECEIPT_MARKER}'`} AND detail.kind='detail'
    LEFT JOIN telegram_subscription_node_page AS page ON page.receipt_id=inbox.receipt_id
      AND inbox.receipt_nonce='${general ? "general-subnodes:v1" : TELEGRAM_SUBSCRIPTION_NODE_MARKER}'
    CROSS JOIN tickets AS ticket
    WHERE changes()=? AND reply.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'`)
    .bind(...tickets.flatMap((item) => [item.sha256, item.id, item.generation, item.lifecycleRevision, item.snapshotId,
      item.manifestSha256, item.nodeCount, item.pageOffset]), previousChanges, lease.receiptId, lease.leaseId, lease.attempts);
}

export async function renderTelegramSubscriptionNodePage(
  db: D1Database, bucket: R2Bucket, policy: TelegramPolicy | GeneralTelegramPin,
  lease: NodeLease, deadline: number, authority?: Guard,
): Promise<{ text: string; readGuard?: Guard; nodeButtons?: TelegramNodePageButton[]; backId?: number }> {
  if (lease.chatType !== "private" || lease.chatId !== lease.actorId || lease.threadId !== null) {
    return { text: "请在私聊浏览订阅节点。" };
  }
  if ("privateManagement" in policy && (!policy.privateBrowsing || policy.rehearsal || !authority))
    return { text: "此节点浏览暂不可用。" };
  const receiptGuard: Guard = authority ?? { sql: `inbox.receipt_nonce='${TELEGRAM_SUBSCRIPTION_NODE_MARKER}' AND EXISTS (
    SELECT 1 FROM telegram_subscription_node_page AS page LEFT JOIN telegram_auth AS auth
      ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id WHERE page.receipt_id=inbox.receipt_id
      AND (inbox.actor_id=? OR (COALESCE(auth.allowed,1)=1 AND page.auth_message_date=COALESCE(auth.message_date,0)
        AND page.auth_message_id=COALESCE(auth.message_id,0) AND inbox.message_date>COALESCE(auth.message_date,0))))`,
    bindings: "privateManagement" in policy ? [] : [policy.adminId] };
  const pin = await db.prepare(`SELECT page.subscription_id AS id,page.generation,page.lifecycle_revision AS lifecycleRevision,
    page.snapshot_id AS snapshotId,page.manifest_sha256 AS manifestSha256,page.node_count AS nodeCount,page.page_offset AS pageOffset
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_subscription_node_page AS page USING(receipt_id)
    WHERE reply.state='leased' AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()
      AND inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND inbox.chat_type='private'
      AND inbox.thread_id IS NULL AND (${receiptGuard.sql})`)
    .bind(lease.leaseId, lease.attempts, lease.receiptId, policy.botId, lease.actorId, lease.chatId, ...receiptGuard.bindings)
    .first<NodePageTarget>();
  if (!pin) return { text: "订阅或授权状态已变更，请重新打开详情。" };
  const matches = `id=? AND generation=? AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=?
    AND snapshot_id=? AND manifest_sha256=? AND node_count=?`;
  const pinBindings = [pin.id, pin.generation, pin.lifecycleRevision, pin.snapshotId, pin.manifestSha256, pin.nodeCount] as const;
  const row = await db.prepare(`SELECT name FROM subscriptions WHERE ${matches} AND owner_id=?`)
    .bind(...pinBindings, lease.actorId).first<{ name: string }>();
  if (!row) return { text: "订阅已更新或删除，请重新打开详情。", readGuard: receiptGuard, backId: pin.id };
  const readGuard: Guard = { sql: `(${receiptGuard.sql}) AND EXISTS (
    SELECT 1 FROM subscriptions WHERE ${matches} AND owner_id=inbox.actor_id)`,
    bindings: [...receiptGuard.bindings, ...pinBindings] };

  try {
    const signal = AbortSignal.timeout(Math.max(1, Math.min(PAGE_TIMEOUT_MS, deadline - Date.now())));
    const nodes = await readSnapshotNodeRange(bucket, pin, pin.pageOffset, Math.min(PAGE_SIZE, pin.nodeCount - pin.pageOffset), signal);
    const title = `节点浏览：${displayTelegramName(row.name)}\n共 ${pin.nodeCount} 个节点 · 第 ${pin.pageOffset / PAGE_SIZE + 1}/${Math.ceil(pin.nodeCount / PAGE_SIZE)} 页`;
    const lines = nodes.map((node, index) => {
      const type = typeof node.type === "string" && /^[A-Za-z0-9_-]{1,24}(?![\s\S])/u.test(node.type) ? node.type.toUpperCase() : "NODE";
      const name = typeof node.name === "string" ? node.name : typeof node.tag === "string" ? node.tag : "";
      return `#${String(pin.pageOffset + index + 1).padStart(2, "0")} [${type}] ${displayTelegramName(name)}`;
    });
    const nodeButtons: TelegramNodePageButton[] = [];
    if (pin.pageOffset > 0) nodeButtons.push({ ...pin, text: "上一页", pageOffset: pin.pageOffset - PAGE_SIZE });
    if (pin.pageOffset + PAGE_SIZE < pin.nodeCount) nodeButtons.push({ ...pin, text: "下一页", pageOffset: pin.pageOffset + PAGE_SIZE });
    return { text: [title, ...lines].join("\n"), readGuard, nodeButtons, backId: pin.id };
  } catch {
    return { text: "暂时无法读取这一页节点。", readGuard, backId: pin.id };
  }
}

export async function reapTelegramSubscriptionNodeTickets(db: D1Database, generalBotId?: string): Promise<void> {
  const result = await db.prepare(`DELETE FROM telegram_subscription_node_ticket WHERE token_sha256 IN (
    SELECT token_sha256 FROM telegram_subscription_node_ticket AS ticket WHERE expires_at<=unixepoch()
    ${generalBotId === undefined ? "" : `AND EXISTS (SELECT 1 FROM telegram_inbox AS origin
      WHERE origin.receipt_id=ticket.origin_receipt_id AND origin.bot_id=?
        AND origin.receipt_nonce IN ('general-subscription-read:v1','general-number-detail:v1','general-subnodes:v1'))`}
    ORDER BY expires_at,token_sha256 LIMIT 40)`).bind(...(generalBotId === undefined ? [] : [generalBotId])).run();
  if (!result.success) throw new Error("Telegram subscription node page tickets could not be cleaned up.");
}

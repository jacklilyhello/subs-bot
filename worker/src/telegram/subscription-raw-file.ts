import { ExportContentError, rawShareBytes, ShareByteLimitError } from "../base64-response.ts";
import { compilePathRules, MAX_PATH_RULES, pathRuleMapper, PathRuleContentError } from "../path-rules.ts";
import { digestHex, planSnapshotRead, readPlannedSnapshotNodes, SUBSCRIPTION_LIFECYCLE_REVISION,
  validInteger, type SubscriptionSnapshot } from "../storage.ts";
import { inTelegramScope, SUBSCRIPTION_RAW_FILE_TICKET, SUBSCRIPTION_READ_RECEIPT_MARKER,
  type TelegramCommand, type TelegramPolicy, type TelegramSubscriptionRawFileUpdate } from "./protocol.ts";

export const TELEGRAM_SUBSCRIPTION_RAW_FILE_MARKER = "subrawfile:v1";
export const MAX_RAW_FILE_BYTES = 4 * 1024 * 1024;
export const MAX_RAW_FILE_NODES = 5000;
export const MAX_RAW_FILE_SNAPSHOT_BYTES = 16 * 1024 * 1024;
const PREPARE_MS = 5000;
const TICKET_SECONDS = 600;
const encoder = new TextEncoder();
const PIN_FIELDS = "subscription_id,generation,lifecycle_revision,snapshot_id,manifest_sha256,node_count";
const FRESH = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
const LIMIT_TEXT = "节点文件超过导出上限。";
const STALE_TEXT = "订阅或路径规则已变更，请重新打开详情。";

export type TelegramRawFileTarget = SubscriptionSnapshot & { lifecycleRevision: number };
export type TelegramRawFileTicket = TelegramRawFileTarget & { sha256: string };
export type TelegramRawFileGuard = { sql: string; bindings: readonly (string | number)[] };
type RawFileLease = TelegramCommand & { receiptId: number; leaseId: string; attempts: number; subscriptionRawFile?: true };
type PreparedRawFile = { kind: "document"; file: Blob; guard: TelegramRawFileGuard }
  | { kind: "text"; text: string; guard: TelegramRawFileGuard };
type RawFileSelection = TelegramRawFileTarget & { rulesSha: string; rules: string; current: number };

async function digest(value: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

function pinBindings(pin: TelegramRawFileTarget) {
  return [pin.id, pin.generation, pin.lifecycleRevision, pin.snapshotId, pin.manifestSha256, pin.nodeCount] as const;
}

function matchesTarget(alias: "ticket" | "action", owner: "origin.actor_id" | "inbox.actor_id"): string {
  return `subscriptions.id=${alias}.subscription_id AND subscriptions.owner_id=${owner}
    AND subscriptions.generation=${alias}.generation AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=${alias}.lifecycle_revision
    AND subscriptions.snapshot_id=${alias}.snapshot_id AND subscriptions.manifest_sha256=${alias}.manifest_sha256
    AND subscriptions.node_count=${alias}.node_count`;
}

function rulesInventory(owner: "origin.actor_id" | "inbox.actor_id"): string {
  return `(SELECT json_group_array(json_array(id,keyword,remark)) FROM (
    SELECT id,keyword,remark FROM path_rules WHERE owner_id=${owner} ORDER BY id LIMIT ${MAX_PATH_RULES + 1}
  ))`;
}

export async function telegramSubscriptionRawFileReady(db: D1Database): Promise<boolean> {
  try {
    const count = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
      AND name IN ('telegram_subscription_raw_file','telegram_subscription_raw_file_ticket')`).first<number>("present");
    if (count !== 0 && count !== 2) throw new Error();
    return count === 2;
  } catch {
    throw new Error("Telegram subscription file schema could not be confirmed.");
  }
}

export async function prepareTelegramRawFileButton(pin: TelegramRawFileTarget): Promise<{
  button: { text: string; callback_data: string }; ticket: TelegramRawFileTicket;
}> {
  const token = "sbnf1_" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  return { button: { text: "📦 导出节点", callback_data: token }, ticket: { ...pin, sha256: await digest(token) } };
}

export function insertTelegramRawFileTicket(
  db: D1Database, policy: TelegramPolicy, lease: RawFileLease, ticket: TelegramRawFileTicket, previousChanges: number,
): D1PreparedStatement {
  return db.prepare(`INSERT INTO telegram_subscription_raw_file_ticket
    (token_sha256,origin_receipt_id,origin_attempt,actor_role,${PIN_FIELDS},expires_at)
    SELECT ?,inbox.receipt_id,reply.attempts,?,CASE WHEN inbox.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}'
      AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
      AND detail.kind='detail' AND detail.subscription_id=? THEN detail.subscription_id END,
      ?,?,?,?,?,unixepoch()+${TICKET_SECONDS}
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_subscription_read AS detail USING(receipt_id)
    WHERE changes()=? AND reply.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'`)
    .bind(ticket.sha256, lease.actorId === policy.adminId ? "admin" : "member", ...pinBindings(ticket),
      previousChanges, lease.receiptId, lease.leaseId, lease.attempts);
}

const ticketOrigin = `FROM telegram_subscription_raw_file_ticket AS ticket
  JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
  JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
  JOIN telegram_subscription_read AS detail ON detail.receipt_id=origin.receipt_id
  JOIN subscriptions ON ${matchesTarget("ticket", "origin.actor_id")}
  LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id`;

export async function acceptTelegramSubscriptionRawFile(
  db: D1Database, policy: TelegramPolicy, event: TelegramSubscriptionRawFileUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.threadId !== null
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)
    || !SUBSCRIPTION_RAW_FILE_TICKET.test(event.ticket)) return "ignored";
  try {
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const tokenSha = await digest(event.ticket);
    const origin = `ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
      AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type='private' AND origin.thread_id IS NULL
      AND origin.receipt_nonce='${SUBSCRIPTION_READ_RECEIPT_MARKER}' AND detail.kind='detail' AND detail.subscription_id=ticket.subscription_id
      AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt
      AND ? BETWEEN unixepoch()-900 AND unixepoch()+30
      AND ((origin.actor_id=? AND ticket.actor_role='admin' AND detail.auth_message_date=0 AND detail.auth_message_id=0)
        OR (origin.actor_id=? AND ticket.actor_role='member' AND COALESCE(auth.allowed,1)=1
          AND detail.auth_message_date=COALESCE(auth.message_date,0) AND detail.auth_message_id=COALESCE(auth.message_id,0)
          AND origin.message_date>COALESCE(auth.message_date,0) AND ?>COALESCE(auth.message_date,0)))`;
    const args = [tokenSha, policy.botId, event.actorId, event.chatId, event.messageId, event.messageDate,
      policy.adminId, policy.memberId, event.messageDate];
    const inventory = await db.prepare(`SELECT ${rulesInventory("origin.actor_id")} AS rules ${ticketOrigin} WHERE ${origin}`)
      .bind(...args).first<string>("rules");
    if (inventory === null) return "ignored";
    const rulesSha = await digest(inventory);
    const fields = PIN_FIELDS.split(",").map((field) => `ticket.${field}`).join(",");
    const result = await db.batch([
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,'private',?,?,NULL,'help',? ${ticketOrigin}
        WHERE ${origin} AND ${rulesInventory("origin.actor_id")}=? ON CONFLICT (bot_id,update_id) DO NOTHING`)
        .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, key[2], ...args, inventory),
      db.prepare(`UPDATE telegram_subscription_raw_file_ticket AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${FRESH}`)
        .bind(tokenSha, ...key),
      db.prepare(`INSERT INTO telegram_subscription_raw_file (receipt_id,${PIN_FIELDS},rules_sha256,actor_role,auth_message_date,auth_message_id)
        SELECT incoming.receipt_id,${fields},?,ticket.actor_role,COALESCE(auth.message_date,0),COALESCE(auth.message_id,0)
        FROM telegram_inbox AS incoming JOIN telegram_subscription_raw_file_ticket AS ticket ON ticket.used_by_receipt_id=incoming.receipt_id
        LEFT JOIN telegram_auth AS auth ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id AND incoming.actor_id<>?
        WHERE ${FRESH} AND ticket.token_sha256=?`).bind(rulesSha, policy.adminId, ...key, tokenSha),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${FRESH}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_subscription_raw_file AS action JOIN telegram_outbox USING(receipt_id)
        WHERE action.receipt_id=incoming.receipt_id) THEN command END WHERE ${FRESH} RETURNING receipt_id`)
        .bind(TELEGRAM_SUBSCRIPTION_RAW_FILE_MARKER, ...key),
    ]);
    const count = result[4]?.results.length;
    if (result.length === 5 && (count === 0 || count === 1) && result.every(({ success, meta }) => success && meta.changes === count)) {
      return count === 1 ? "accepted" : "ignored";
    }
  } catch {
    // Callback and storage values stay out of errors.
  }
  throw new Error("Telegram subscription file receipt could not be confirmed.");
}

function inRawFileScope(policy: TelegramPolicy, lease: RawFileLease): boolean {
  return lease.subscriptionRawFile === true && lease.chatType === "private" && lease.threadId === null && inTelegramScope(policy, lease);
}

const leaseScope = `reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()
  AND inbox.receipt_id=? AND inbox.bot_id=? AND inbox.update_id=? AND inbox.actor_id=? AND inbox.chat_id=?
  AND inbox.chat_type='private' AND inbox.actor_id=inbox.chat_id AND inbox.thread_id IS NULL AND inbox.command='help'
  AND inbox.message_id=? AND inbox.message_date=?`;

function leaseArgs(policy: TelegramPolicy, lease: RawFileLease) {
  return [lease.leaseId, lease.attempts, lease.receiptId, policy.botId, lease.updateId, lease.actorId, lease.chatId,
    lease.messageId, lease.messageDate] as const;
}

export async function prepareTelegramSubscriptionRawFile(
  db: D1Database, bucket: R2Bucket, policy: TelegramPolicy, lease: RawFileLease, deadline: number,
): Promise<PreparedRawFile | null> {
  if (!inRawFileScope(policy, lease) || Date.now() >= deadline) return null;
  const receipt: TelegramRawFileGuard = { sql: `inbox.receipt_nonce='${TELEGRAM_SUBSCRIPTION_RAW_FILE_MARKER}' AND EXISTS (
    SELECT 1 FROM telegram_subscription_raw_file AS action LEFT JOIN telegram_auth AS auth
      ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id WHERE action.receipt_id=inbox.receipt_id
      AND ((inbox.actor_id=? AND action.actor_role='admin' AND action.auth_message_date=0 AND action.auth_message_id=0)
        OR (inbox.actor_id=? AND action.actor_role='member' AND COALESCE(auth.allowed,1)=1
          AND action.auth_message_date=COALESCE(auth.message_date,0) AND action.auth_message_id=COALESCE(auth.message_id,0)
          AND inbox.message_date>COALESCE(auth.message_date,0))))`, bindings: [policy.adminId, policy.memberId] };
  let pin: RawFileSelection | null;
  try {
    pin = await db.prepare(`SELECT action.subscription_id AS id,action.generation,action.lifecycle_revision AS lifecycleRevision,
      action.snapshot_id AS snapshotId,action.manifest_sha256 AS manifestSha256,action.node_count AS nodeCount,
      action.rules_sha256 AS rulesSha,${rulesInventory("inbox.actor_id")} AS rules,
      EXISTS (SELECT 1 FROM subscriptions WHERE ${matchesTarget("action", "inbox.actor_id")}) AS current
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      JOIN telegram_subscription_raw_file AS action USING(receipt_id)
      WHERE reply.state='leased' AND ${leaseScope} AND (${receipt.sql})`)
      .bind(...leaseArgs(policy, lease), ...receipt.bindings).first<RawFileSelection>();
  } catch {
    throw new Error("Telegram subscription file scope could not be confirmed.");
  }
  if (!pin) return null;
  if (pin.current !== 1 || await digest(pin.rules) !== pin.rulesSha) return { kind: "text", text: STALE_TEXT, guard: receipt };
  const guard: TelegramRawFileGuard = { sql: `(${receipt.sql}) AND EXISTS (
    SELECT 1 FROM telegram_subscription_raw_file AS action JOIN subscriptions ON ${matchesTarget("action", "inbox.actor_id")}
    WHERE action.receipt_id=inbox.receipt_id AND action.subscription_id=? AND action.generation=? AND action.lifecycle_revision=?
      AND action.snapshot_id=? AND action.manifest_sha256=? AND action.node_count=? AND action.rules_sha256=?
      AND ${rulesInventory("inbox.actor_id")}=? )`, bindings: [...receipt.bindings, ...pinBindings(pin), pin.rulesSha, pin.rules] };
  const budget = Math.min(PREPARE_MS, deadline - Date.now());
  if (budget <= 0) return null;
  if (pin.nodeCount > MAX_RAW_FILE_NODES) return { kind: "text", text: LIMIT_TEXT, guard };
  const signal = AbortSignal.timeout(budget);
  try {
    const rows = JSON.parse(pin.rules) as [number, string, string][];
    const map = pathRuleMapper(compilePathRules(rows.map(([id, keyword, remark]) => ({ id, keyword, remark }))));
    const plan = await planSnapshotRead(bucket, pin);
    if (plan.bytes > MAX_RAW_FILE_SNAPSHOT_BYTES) return { kind: "text", text: LIMIT_TEXT, guard };
    const chunks: Uint8Array<ArrayBuffer>[] = [];
    let bytes = 0;
    const source = { nodeCount: pin.nodeCount, async *read(abort?: AbortSignal) {
      for await (const node of readPlannedSnapshotNodes(bucket, plan, abort)) yield map(node);
    } };
    for await (const chunk of rawShareBytes(source, signal, MAX_RAW_FILE_BYTES)) {
      chunks.push(Uint8Array.from(chunk));
      bytes += chunk.byteLength;
    }
    if (signal.aborted || bytes === 0) return { kind: "text", text: "暂时无法读取订阅节点。", guard };
    const file = new Blob(chunks, { type: "text/plain;charset=utf-8" });
    if (file.size !== bytes) throw new Error();
    return { kind: "document", file, guard };
  } catch (error) {
    const text = error instanceof ShareByteLimitError ? LIMIT_TEXT : error instanceof ExportContentError || error instanceof PathRuleContentError
      ? "部分节点或连接设置无法转换为此格式。" : "暂时无法读取订阅节点。";
    return { kind: "text", text, guard };
  }
}

export async function confirmTelegramSubscriptionRawFileSend(
  db: D1Database, policy: TelegramPolicy, lease: RawFileLease, guard: TelegramRawFileGuard,
): Promise<boolean> {
  if (!inRawFileScope(policy, lease)) return false;
  try {
    return await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE reply.state='sending' AND ${leaseScope} AND (${guard.sql})`)
      .bind(...leaseArgs(policy, lease), ...guard.bindings).first() !== null;
  } catch {
    return false;
  }
}

export async function reapTelegramRawFileTickets(db: D1Database): Promise<void> {
  try {
    const result = await db.prepare(`DELETE FROM telegram_subscription_raw_file_ticket WHERE token_sha256 IN (
      SELECT token_sha256 FROM telegram_subscription_raw_file_ticket WHERE expires_at<=unixepoch()
      ORDER BY expires_at,token_sha256 LIMIT 40)`).run();
    if (result.success) return;
  } catch {
    // Keep callback and backend values out of diagnostics.
  }
  throw new Error("Telegram subscription file ticket cleanup could not be confirmed.");
}

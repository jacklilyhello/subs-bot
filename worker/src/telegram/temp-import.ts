import { parseNodeText } from "../text-import.ts";
import { inTelegramScope, type TelegramGeneralTempUpdate, type TelegramPolicy, type TelegramTempUpdate } from "./protocol.ts";
import {
  MAX_TEMP_BATCH_BYTES, MAX_TEMP_BATCH_NODES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, TELEGRAM_TEMP_MARKER,
  ownedTempRowsSql, readTempStorage, tempCutoverAllows, tempSchemaGuard, type TempStorageMode,
} from "./temp-storage.ts";

export { MAX_TEMP_BATCH_BYTES, MAX_TEMP_BATCH_NODES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, TELEGRAM_TEMP_MARKER };
export const TELEGRAM_TEMP_RAW_PREFIX = "temp-raw:v1:";
export const TELEGRAM_GENERAL_TEMP_RAW_PREFIX = "general-temp-raw:v1:";
export const GENERAL_TEMP_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-temp-intake:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=8 AND name='0008_telegram_temp_nodes.sql'
    AND sha256='87ae872d0b04e49649e102adea9b00a2e5a24cd58b5236e561d0c85634c0a0ea' AND mode='applied')`;
const MAX_TEMP_TEXT_BYTES = 64 * 1024;

type TempReplyKind = "added" | "rejected" | "no-nodes" | "invalid-encoding" | "limit"
  | "capacity" | "stale" | "summary" | "cleared";

export interface TelegramTempReply {
  kind: TempReplyKind;
  nodeCount: number;
  totalCount: number;
  malformedCount: number;
  unsupportedCount: number;
  ignoredCount: number;
}

interface TextPlan {
  kind: "added" | "rejected" | "no-nodes" | "invalid-encoding" | "limit";
  nodeCount: number;
  malformedCount: number;
  unsupportedCount: number;
  ignoredCount: number;
  payload: { json: string; bytes: number } | null;
}

type ReceiptKey = readonly [botId: string, updateId: number, nonce: string];
const freshReceipt = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";
const sameOwner = "temp.bot_id = incoming.bot_id AND temp.actor_id = incoming.actor_id";
const atOrBefore = "(temp.message_date, temp.message_id) <= (incoming.message_date, incoming.message_id)";
const visibleAtOrBefore = "WHERE source=0 OR (date,message)<=(incoming.message_date,incoming.message_id)";
const olderThanClear = `EXISTS (
  SELECT 1 FROM telegram_temp_clear_fence AS fence
  WHERE fence.bot_id = incoming.bot_id AND fence.actor_id = incoming.actor_id
    AND (fence.message_date, fence.message_id) >= (incoming.message_date, incoming.message_id)
)`;
const currentClear = `EXISTS (
  SELECT 1 FROM telegram_temp_clear_fence AS fence
  WHERE fence.bot_id = incoming.bot_id AND fence.actor_id = incoming.actor_id
    AND (fence.message_date, fence.message_id) = (incoming.message_date, incoming.message_id)
)`;
const encoder = new TextEncoder();

function tempOwnerQuery(mode: TempStorageMode, select: string, where = ""): string {
  return `WITH temp_scope AS (SELECT incoming.bot_id AS bot_id,incoming.actor_id AS actor_id,NULL AS before_receipt,
    incoming.message_date AS visibility_epoch),
    temp_rows AS (${ownedTempRowsSql(mode, "temp_scope")}) SELECT ${select} FROM temp_rows ${where}`;
}

// The original receipt schema has space for a versioned marker. Store only
// the grant and clear epochs here. The receipt ID bounds the raw read.
export function tempRawStamp(alias: "incoming" | "inbox"): string {
  return `'${TELEGRAM_TEMP_RAW_PREFIX}' || (CASE WHEN ${alias}.actor_id=? THEN '[0,0]' ELSE COALESCE((
    SELECT json_array(auth.message_date,auth.message_id) FROM telegram_auth AS auth
    WHERE auth.bot_id=${alias}.bot_id AND auth.user_id=${alias}.actor_id
  ),'[0,0]') END) || ':' || COALESCE((
    SELECT json_array(fence.message_date,fence.message_id) FROM telegram_temp_clear_fence AS fence
    WHERE fence.bot_id=${alias}.bot_id AND fence.actor_id=${alias}.actor_id
  ),'[0,0]')`;
}

export function tempRawMarker(alias: "inbox" | "earlier"): string {
  return `substr(${alias}.receipt_nonce,1,${TELEGRAM_TEMP_RAW_PREFIX.length})='${TELEGRAM_TEMP_RAW_PREFIX}'`;
}

export function generalTempRawStamp(alias: "incoming" | "inbox"): string {
  return `'${TELEGRAM_GENERAL_TEMP_RAW_PREFIX}' || COALESCE((SELECT json_array(fence.message_date,fence.message_id)
    FROM telegram_temp_clear_fence AS fence WHERE fence.bot_id=${alias}.bot_id AND fence.actor_id=${alias}.actor_id),'[0,0]')`;
}

export function generalTempRawMarker(alias: "inbox" | "earlier"): string {
  return `substr(${alias}.receipt_nonce,1,${TELEGRAM_GENERAL_TEMP_RAW_PREFIX.length})='${TELEGRAM_GENERAL_TEMP_RAW_PREFIX}'`;
}

function planText(text: string): TextPlan {
  const parsed = parseNodeText(text, { maxInputBytes: MAX_TEMP_TEXT_BYTES, maxNodes: MAX_TEMP_BATCH_NODES });
  const counts = {
    nodeCount: parsed.nodes.length,
    malformedCount: parsed.rejected.malformed,
    unsupportedCount: parsed.rejected.unsupported,
    ignoredCount: parsed.ignored,
  };
  if (parsed.kind === "limit" || parsed.kind === "invalid-encoding") {
    return { kind: parsed.kind, ...counts, payload: null };
  }
  if (counts.malformedCount || counts.unsupportedCount) return { kind: "rejected", ...counts, payload: null };
  if (parsed.kind === "no-nodes") return { kind: "no-nodes", ...counts, payload: null };

  const json = JSON.stringify(parsed.nodes);
  const bytes = encoder.encode(json).byteLength;
  if (bytes > MAX_TEMP_BATCH_BYTES) return { kind: "limit", ...counts, payload: null };
  return { kind: "added", ...counts, payload: { json, bytes } };
}

function textSteps(db: D1Database, key: ReceiptKey, plan: TextPlan, mode: TempStorageMode): D1PreparedStatement[] {
  const steps: D1PreparedStatement[] = [];
  const payload = plan.payload;
  if (payload) {
    // A single bound value avoids SQL length and parameter fanout from nodes.
    steps.push(db.prepare(`
      INSERT INTO telegram_temp_batch (receipt_id, bot_id, actor_id, message_date, message_id,
        nodes_json, node_count, payload_bytes)
      SELECT incoming.receipt_id, incoming.bot_id, incoming.actor_id, incoming.message_date, incoming.message_id,
        ?, ?, ? FROM telegram_inbox AS incoming
      WHERE ${freshReceipt} AND NOT ${olderThanClear}
        AND (${tempOwnerQuery(mode, "COALESCE(sum(nodeCount),0)<=? AND COALESCE(sum(bytes),0)<=?")})
    `).bind(payload.json, plan.nodeCount, payload.bytes, ...key,
      MAX_TEMP_OWNER_NODES - plan.nodeCount, MAX_TEMP_OWNER_BYTES - payload.bytes));
  }
  const kind = payload ? `CASE
    WHEN EXISTS (SELECT 1 FROM telegram_temp_batch WHERE receipt_id = incoming.receipt_id) THEN 'added'
    WHEN ${olderThanClear} THEN 'stale' ELSE 'capacity' END` : "?";
  steps.push(db.prepare(`
    INSERT INTO telegram_temp_reply (receipt_id, kind, node_count, malformed_count, unsupported_count, ignored_count)
    SELECT incoming.receipt_id, ${kind}, ?, ?, ?, ? FROM telegram_inbox AS incoming WHERE ${freshReceipt}
  `).bind(...(payload ? [] : [plan.kind]), plan.nodeCount, plan.malformedCount, plan.unsupportedCount, plan.ignoredCount, ...key));
  return steps;
}

function clearSteps(db: D1Database, key: ReceiptKey, mode: TempStorageMode): D1PreparedStatement[] {
  const clearBaseline = mode === "legacy-ready" ? [db.prepare(`
    DELETE FROM legacy_temp_batches AS batch /* subs-bot:legacy-temp-mutate:v1 */ WHERE EXISTS (
      SELECT 1 FROM telegram_inbox AS incoming JOIN telegram_temp_reply AS reply USING (receipt_id)
      JOIN legacy_temp_installations AS installation ON installation.bot_id=incoming.bot_id
        AND installation.cutover_epoch<incoming.message_date
      WHERE ${freshReceipt} AND reply.kind='cleared' AND ${currentClear}
        AND batch.bot_id=incoming.bot_id AND batch.actor_id=incoming.actor_id
    )
  `).bind(...key)] : [];
  return [
    db.prepare(`
      INSERT INTO telegram_temp_clear_fence (bot_id, actor_id, message_date, message_id)
      SELECT incoming.bot_id, incoming.actor_id, incoming.message_date, incoming.message_id
      FROM telegram_inbox AS incoming WHERE ${freshReceipt}
      ON CONFLICT (bot_id, actor_id) DO UPDATE SET
        message_date = excluded.message_date, message_id = excluded.message_id
      WHERE (excluded.message_date, excluded.message_id) >
        (telegram_temp_clear_fence.message_date, telegram_temp_clear_fence.message_id)
    `).bind(...key),
    db.prepare(`
      INSERT INTO telegram_temp_reply (receipt_id, kind, node_count)
      SELECT incoming.receipt_id, CASE WHEN ${currentClear} THEN 'cleared' ELSE 'stale' END,
        CASE WHEN ${currentClear} THEN (${tempOwnerQuery(mode, "COALESCE(sum(nodeCount),0)", visibleAtOrBefore)}) ELSE 0 END
      FROM telegram_inbox AS incoming WHERE ${freshReceipt}
    `).bind(...key),
    ...clearBaseline,
    db.prepare(`
      DELETE FROM telegram_temp_batch WHERE receipt_id IN (
        SELECT temp.receipt_id FROM telegram_inbox AS incoming
        JOIN telegram_temp_reply AS reply USING (receipt_id)
        JOIN telegram_temp_batch AS temp ON ${sameOwner} AND ${atOrBefore}
        WHERE ${freshReceipt} AND reply.kind = 'cleared'
      )
    `).bind(...key),
  ];
}

function prepareTempReceipt(
  db: D1Database, key: ReceiptKey, mode: TempStorageMode, kind: TelegramTempUpdate["kind"], text: TextPlan | null,
) {
  const ownerTotal = tempOwnerQuery(mode, "COALESCE(sum(nodeCount),0)");
  const statements = text ? textSteps(db, key, text, mode) : kind === "temp-clear" ? clearSteps(db, key, mode) : [db.prepare(`
    INSERT INTO telegram_temp_reply (receipt_id, kind, node_count)
    SELECT incoming.receipt_id, 'summary', 0 FROM telegram_inbox AS incoming WHERE ${freshReceipt}
  `).bind(...key)];
  statements.push(db.prepare(`
    UPDATE telegram_temp_reply AS reply SET total_count = (${ownerTotal})
    FROM telegram_inbox AS incoming WHERE reply.receipt_id = incoming.receipt_id AND ${freshReceipt}
  `).bind(...key));

  return { statements, proof: `EXISTS (
    SELECT 1 FROM telegram_temp_reply AS reply JOIN telegram_outbox USING (receipt_id)
    WHERE reply.receipt_id = incoming.receipt_id AND reply.total_count = (${ownerTotal})
      AND (reply.kind <> 'added' OR EXISTS (
        SELECT 1 FROM telegram_temp_batch AS temp
        WHERE temp.receipt_id = incoming.receipt_id AND ${sameOwner} AND temp.node_count = reply.node_count
      ))
      AND (reply.kind <> 'cleared' OR NOT EXISTS (${tempOwnerQuery(mode, "1", visibleAtOrBefore)}))
  )` };
}

/** Build the same atomic write and count proof for a fresh general private receipt. */
export function prepareGeneralTelegramTempReceipt(
  db: D1Database, key: ReceiptKey, mode: TempStorageMode, event: TelegramGeneralTempUpdate,
) {
  const text = event.kind === "temp-text" ? planText(event.text) : null;
  return text?.kind === "no-nodes" ? null : prepareTempReceipt(db, key, mode, event.kind, text);
}

export async function acceptTelegramTemp(
  db: D1Database,
  policy: TelegramPolicy,
  event: TelegramTempUpdate,
): Promise<"accepted" | "ignored"> {
  if (event.chatType !== "private" || event.threadId !== null || !inTelegramScope(policy, event)) return "ignored";

  try {
    const mode = await readTempStorage(db);
    const raw = event.kind === "temp-raw";
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const steps = [db.prepare(`SELECT CASE WHEN (${tempSchemaGuard(mode)}) THEN 1
      ELSE json_extract('temporary storage schema changed','$') END AS ready`), db.prepare(`
      INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
      SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
      WHERE (? = ? OR COALESCE((SELECT allowed = 1 AND message_date < ?
        FROM telegram_auth WHERE bot_id = ? AND user_id = ?), 1))
      ${mode === "legacy-ready" ? `AND (${tempCutoverAllows(mode, "?", "?")})` : ""}
      ${raw ? `AND ? BETWEEN unixepoch()-900 AND unixepoch()+30
        AND NOT EXISTS (SELECT 1 FROM telegram_temp_clear_fence
          WHERE bot_id=? AND actor_id=? AND (message_date,message_id)>=(?,?))` : ""}
      ON CONFLICT (bot_id, update_id) DO NOTHING
    `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce,
      event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId,
      ...(mode === "legacy-ready" ? [policy.botId, event.messageDate] : []),
      ...(raw ? [event.messageDate, policy.botId, event.actorId, event.messageDate, event.messageId] : []))];
    const temp = prepareTempReceipt(db, key, mode, event.kind, event.kind === "temp-text" ? planText(event.text) : null);
    steps.push(...temp.statements, db.prepare(`
      INSERT INTO telegram_outbox (receipt_id)
      SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${freshReceipt}
    `).bind(...key), db.prepare(`
      UPDATE telegram_inbox AS incoming SET receipt_nonce = ${raw ? tempRawStamp("incoming") : "?"},
        command = CASE WHEN ${temp.proof} THEN command END
      WHERE ${freshReceipt} RETURNING receipt_id
    `).bind(raw ? policy.adminId : TELEGRAM_TEMP_MARKER, ...key));
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && receipt.results.length <= 1
      && results.every((result) => result.success)) {
      return receipt.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // D1 and decoding errors can contain node data.
  }
  throw new Error("Telegram temporary node receipt could not be confirmed.");
}

export function renderTelegramTemp(
  { kind, nodeCount, totalCount, malformedCount, unsupportedCount, ignoredCount }: TelegramTempReply,
): string {
  const ignored = ignoredCount ? `\n另有 ${ignoredCount} 行未识别为节点。` : "";
  switch (kind) {
    case "added":
      return `已加入临时列表 ${nodeCount} 条节点，当前共有 ${totalCount} 条。${ignored}`;
    case "rejected":
      return `本批未写入。有效节点 ${nodeCount} 条，格式错误 ${malformedCount} 条，不支持 ${unsupportedCount} 条。${ignored}`;
    case "no-nodes":
      return `未识别到节点。请发送节点链接或 Base64 节点列表。${ignored}`;
    case "invalid-encoding":
      return "文本编码无效，请使用 UTF-8。本批未写入。";
    case "limit":
      return "本批超过单次导入限制，未写入。";
    case "capacity":
      return `临时列表已达到数量或大小限制，本批未写入。当前共有 ${totalCount} 条节点。`;
    case "stale":
      return "该操作早于最近一次清空，临时列表未更改。";
    case "summary":
      return `临时列表共有 ${totalCount} 条节点。发送 /temp clear 清空。`;
    case "cleared":
      return `已移除 ${nodeCount} 条临时节点，当前共有 ${totalCount} 条。`;
  }
}

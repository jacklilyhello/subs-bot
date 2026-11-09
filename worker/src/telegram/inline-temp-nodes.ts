import { validInteger } from "../storage.ts";
import { isValidStoredShare } from "../stored-share.ts";
import type { InlineSearchArticle } from "./inline-search.ts";
import type { TelegramInlineQuery, TelegramPolicy } from "./protocol.ts";
import { unicode14Lower } from "./selected-search.ts";
import {
  MAX_TEMP_BATCH_BYTES, MAX_TEMP_BATCH_NODES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, TELEGRAM_TEMP_MARKER,
} from "./temp-import.ts";
import { displayTelegramName } from "./views.ts";

const PAGE_BYTES = 512 * 1024;
const PAGE_BATCHES = 256;
const encoder = new TextEncoder();

type Fence = { date: number; message: number };
type Batch = Fence & { id: number; nodeCount: number; bytes: number };
type BatchMetadata = Batch & { accepted: number };
type BatchContent = Batch & { json: string };

type TempScan = {
  results: InlineSearchArticle[];
  guard: { sql: string; bindings: readonly (number | string)[] };
};

const metadata = `batch.receipt_id AS id,batch.message_date AS date,batch.message_id AS message,
  batch.node_count AS nodeCount,batch.payload_bytes AS bytes`;
const batchIdentity = `batch.receipt_id=json_extract(expected.value,'$[0]')
  AND batch.message_date=json_extract(expected.value,'$[1]') AND batch.message_id=json_extract(expected.value,'$[2]')
  AND batch.node_count=json_extract(expected.value,'$[3]') AND batch.payload_bytes=json_extract(expected.value,'$[4]')`;
const acceptedPaste = `LEFT JOIN telegram_inbox AS paste ON paste.receipt_id=batch.receipt_id AND paste.bot_id=batch.bot_id
  AND paste.actor_id=batch.actor_id AND paste.chat_id=batch.actor_id AND paste.chat_type='private' AND paste.thread_id IS NULL
  AND paste.message_date=batch.message_date AND paste.message_id=batch.message_id AND paste.command='help'
  AND paste.receipt_nonce='${TELEGRAM_TEMP_MARKER}'
  LEFT JOIN telegram_temp_reply AS accepted ON accepted.receipt_id=paste.receipt_id AND accepted.kind='added'
  AND accepted.node_count=batch.node_count`;

function inventoryJSON(rows: readonly Batch[]): string {
  return JSON.stringify(rows.map(({ id, date, message, nodeCount, bytes }) => [id, date, message, nodeCount, bytes]));
}

function exactInventory(rows: readonly Batch[], fence: Fence | undefined): TempScan["guard"] {
  // Batch rows are immutable. A single numeric JSON vector keeps the bind count
  // fixed even for thousands of one-node pastes.
  return {
    sql: `(SELECT count(*) FROM telegram_temp_batch AS owned
      WHERE owned.bot_id=request.bot_id AND owned.actor_id=request.actor_id)=?
      AND COALESCE((SELECT json_array(message_date,message_id) FROM telegram_temp_clear_fence
        WHERE bot_id=request.bot_id AND actor_id=request.actor_id),'[0,0]')=?
      AND NOT EXISTS (SELECT 1 FROM json_each(?) AS expected LEFT JOIN telegram_temp_batch AS batch
        ON ${batchIdentity} AND batch.bot_id=request.bot_id AND batch.actor_id=request.actor_id
        ${acceptedPaste} WHERE accepted.receipt_id IS NULL)`,
    bindings: [rows.length, JSON.stringify(fence ? [fence.date, fence.message] : [0, 0]), inventoryJSON(rows)],
  };
}

/** Read temporary nodes for an admitted personal inline search. The caller owns the final consent fence. */
export async function readTelegramInlineTempNodes(
  db: D1Database, policy: TelegramPolicy, event: TelegramInlineQuery, needle: string, limit: number, deadline: number,
): Promise<TempScan | null> {
  if (event.chatType !== "sender" || (event.actorId !== policy.adminId && event.actorId !== policy.memberId)
    || !validInteger(event.updateId, 1) || !validInteger(limit, 1, 50) || Date.now() >= deadline) return null;

  try {
    const [inventory, clear] = await db.batch<BatchMetadata | Fence>([
      db.prepare(`SELECT ${metadata},accepted.receipt_id IS NOT NULL AS accepted
        FROM telegram_temp_batch AS batch ${acceptedPaste}
        WHERE batch.bot_id=? AND batch.actor_id=? ORDER BY batch.receipt_id LIMIT ?`)
        .bind(policy.botId, event.actorId, MAX_TEMP_OWNER_NODES + 1),
      db.prepare(`SELECT message_date AS date,message_id AS message FROM telegram_temp_clear_fence
        WHERE bot_id=? AND actor_id=?`).bind(policy.botId, event.actorId),
    ]);
    if (!inventory?.success || !clear?.success || inventory.results.length > MAX_TEMP_OWNER_NODES || clear.results.length > 1) return null;
    const fence = clear.results[0];
    if (fence && (!validInteger(fence.date, 1) || !validInteger(fence.message, 1))) return null;

    const rows = inventory.results as BatchMetadata[];
    let previousId = 0;
    let nodes = 0;
    let bytes = 0;
    for (const row of rows) {
      if (row.accepted !== 1 || !validInteger(row.id, previousId + 1) || !validInteger(row.date, 1)
        || !validInteger(row.message, 1) || !validInteger(row.nodeCount, 1, MAX_TEMP_BATCH_NODES)
        || !validInteger(row.bytes, 1, MAX_TEMP_BATCH_BYTES)
        || (fence && (row.date < fence.date || (row.date === fence.date && row.message <= fence.message)))) return null;
      previousId = row.id;
      nodes += row.nodeCount;
      bytes += row.bytes;
      if (nodes > MAX_TEMP_OWNER_NODES || bytes > MAX_TEMP_OWNER_BYTES) return null;
    }

    const results: InlineSearchArticle[] = [];
    let lowerBytes = 0;
    for (let start = 0; start < rows.length;) {
      if (Date.now() >= deadline) return null;
      let end = start;
      let size = 0;
      while (end < rows.length && end - start < PAGE_BATCHES && size + rows[end].bytes <= PAGE_BYTES) {
        size += rows[end++].bytes;
      }
      const expected = rows.slice(start, end);
      const page = await db.prepare(`SELECT ${metadata},batch.nodes_json AS json FROM telegram_temp_batch AS batch
        JOIN json_each(?) AS expected ON ${batchIdentity} ${acceptedPaste}
        WHERE batch.bot_id=? AND batch.actor_id=? AND accepted.receipt_id IS NOT NULL ORDER BY batch.receipt_id`)
        .bind(inventoryJSON(expected), policy.botId, event.actorId).all<BatchContent>();
      if (!page.success || page.results.length !== expected.length) return null;
      for (const [index, batch] of page.results.entries()) {
        const row = expected[index];
        if (batch.id !== row.id || batch.date !== row.date || batch.message !== row.message || batch.nodeCount !== row.nodeCount
          || batch.bytes !== row.bytes || typeof batch.json !== "string" || encoder.encode(batch.json).byteLength !== row.bytes) return null;
        const decoded: unknown = JSON.parse(batch.json);
        if (!Array.isArray(decoded) || decoded.length !== row.nodeCount) return null;
        for (const node of decoded) {
          if (Date.now() >= deadline || node === null || typeof node !== "object" || Array.isArray(node)
            || typeof node.name !== "string" || !isValidStoredShare(node.share)) return null;
          if (results.length === limit) continue;
          if (needle) {
            const searchable = `${node.name} ${node.share}`;
            lowerBytes += encoder.encode(searchable).byteLength;
            if (lowerBytes > MAX_TEMP_OWNER_BYTES) return null;
            if (!unicode14Lower(searchable).includes(needle)) continue;
          }
          results.push({
            type: "article", id: crypto.randomUUID(), title: `🧪 ${Array.from(displayTelegramName(node.name)).slice(0, 62).join("")}`,
            description: "临时节点 · 私聊 /temp 查看原文",
            input_message_content: {
              message_text: "临时节点仅在机器人私聊中查看。请发送 /temp。", link_preview_options: { is_disabled: true },
            },
          });
        }
      }
      start = end;
    }
    if (Date.now() >= deadline) return null;
    return { results, guard: exactInventory(rows, fence) };
  } catch {
    // D1 and JSON errors may include original node data.
    return null;
  }
}

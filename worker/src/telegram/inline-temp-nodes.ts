import { validInteger } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import type { InlineSearchArticle } from "./inline-search.ts";
import type { TelegramInlineQuery, TelegramPolicy } from "./protocol.ts";
import { unicode14Lower } from "./selected-search.ts";
import { GENERAL_TEMP_SCHEMA, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES } from "./temp-import.ts";
import {
  ownedTempRowsSql, readTempBatchNodes, readVerifiedTempStorage, tempInventoryGuard, verifyTempInventory,
  type TempBatchMeta,
} from "./temp-storage.ts";
import { displayTelegramName } from "./views.ts";

const PAGE_BYTES = 512 * 1024;
const PAGE_BATCHES = 256;
const encoder = new TextEncoder();

type Fence = { date: number; message: number };
type BatchContent = TempBatchMeta & { json: string };

type TempScan = {
  results: InlineSearchArticle[];
  guard: { sql: string; bindings: readonly (number | string)[] };
};

const scope = "SELECT ? AS bot_id,? AS actor_id,NULL AS before_receipt,? AS visibility_epoch";
const sendScope = `SELECT request.bot_id,request.actor_id,NULL AS before_receipt,
  request.received_at AS visibility_epoch`;

/** Read temporary nodes for an admitted personal inline search. The caller owns the final consent fence. */
export async function readTelegramInlineTempNodes(
  db: D1Database, policy: TelegramPolicy | GeneralTelegramPin, event: TelegramInlineQuery, needle: string, limit: number, deadline: number, receivedAt: number,
): Promise<TempScan | null> {
  const general = "privateTemp" in policy;
  if (event.chatType !== "sender" || (general ? !policy.privateTemp || !policy.privateInline || policy.rehearsal || event.actorId === policy.botId
    : event.actorId !== policy.adminId && event.actorId !== policy.memberId)
    || !validInteger(event.updateId, 1) || !validInteger(limit, 1, 50) || !validInteger(receivedAt, 1) || Date.now() >= deadline) return null;

  try {
    const storage = await readVerifiedTempStorage(db);
    const { mode, generalReceipts } = storage;
    if (general && (mode !== "legacy-ready" || !generalReceipts
      || await db.prepare(`SELECT 1 WHERE ${GENERAL_TEMP_SCHEMA}`).first() === null)) return null;
    const scopeArgs = [policy.botId, event.actorId, receivedAt] as const;
    const [inventory, clear] = await db.batch<TempBatchMeta | Fence>([
      db.prepare(`WITH temp_scope AS (${scope}), owned AS (${ownedTempRowsSql(mode, "temp_scope", { verifyLive: true, generalReceipts })})
        SELECT * FROM owned ORDER BY source,id LIMIT ?`).bind(...scopeArgs, MAX_TEMP_OWNER_NODES + 1),
      db.prepare(`SELECT message_date AS date,message_id AS message FROM telegram_temp_clear_fence
        WHERE bot_id=? AND actor_id=?`).bind(policy.botId, event.actorId),
    ]);
    if (!inventory?.success || !clear?.success || inventory.results.length > MAX_TEMP_OWNER_NODES || clear.results.length > 1) return null;
    const fence = clear.results[0];
    if (fence && (!validInteger(fence.date, 1) || !validInteger(fence.message, 1))) return null;

    const rows = inventory.results as TempBatchMeta[];
    verifyTempInventory(rows);
    for (const row of rows) {
      if (row.accepted !== 1 || (fence && (row.source === 0 ? row.date < fence.date
        : row.date < fence.date || (row.date === fence.date && row.message <= fence.message)))) return null;
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
      const page = await db.prepare(`WITH temp_scope AS (${scope}), page_keys AS (
        SELECT json_extract(value,'$[0]') AS source,json_extract(value,'$[1]') AS id FROM json_each(?)
      ), owned AS (${ownedTempRowsSql(mode, "temp_scope", { includePayload: true, verifyLive: true, generalReceipts, keysCte: "page_keys" })})
      SELECT * FROM owned WHERE accepted=1 ORDER BY source,id`)
        .bind(...scopeArgs, JSON.stringify(expected.map(({ source, id }) => [source, id]))).all<BatchContent>();
      if (!page.success || page.results.length !== expected.length) return null;
      for (const [index, batch] of page.results.entries()) {
        const row = expected[index];
        if (batch.source !== row.source || batch.id !== row.id || batch.lastId !== row.lastId || batch.date !== row.date
          || batch.message !== row.message || batch.nodeCount !== row.nodeCount || batch.bytes !== row.bytes
          || batch.sha256 !== row.sha256) return null;
        const decoded = await readTempBatchNodes(batch, { requireStoredShare: true });
        for (const node of decoded) {
          if (Date.now() >= deadline || typeof node.name !== "string" || typeof node.share !== "string") return null;
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
    const inventoryGuard = tempInventoryGuard(storage, sendScope, rows);
    return { results, guard: {
      sql: `${general ? `(${GENERAL_TEMP_SCHEMA}) AND ` : ""}(${inventoryGuard.sql}) AND COALESCE((SELECT json_array(message_date,message_id) FROM telegram_temp_clear_fence
        WHERE bot_id=request.bot_id AND actor_id=request.actor_id),'[0,0]')=?`,
      bindings: [...inventoryGuard.bindings, JSON.stringify(fence ? [fence.date, fence.message] : [0, 0])],
    } };
  } catch {
    // D1 and JSON errors may include original node data.
    return null;
  }
}

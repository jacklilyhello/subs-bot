import { validInteger } from "../storage.ts";
import { isValidStoredShare } from "../stored-share.ts";
import { inTelegramScope, type TelegramCommand, type TelegramPolicy } from "./protocol.ts";
import {
  MAX_TEMP_BATCH_BYTES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, renderTelegramTemp,
  TELEGRAM_TEMP_MARKER, tempRawStamp, type TelegramTempReply,
} from "./temp-import.ts";

const PAGE_BYTES = 512 * 1024;
const PAGE_BATCHES = 256;
const TEXT_UNITS = 3800;
const encoder = new TextEncoder();

interface RawLease extends TelegramCommand {
  receiptId: number;
  leaseId: string;
  attempts: number;
  tempRaw?: true;
  temp?: TelegramTempReply;
}

export type TelegramTempRawGuard = { sql: string; bindings: readonly (string | number)[] };
export type TelegramTempRawReply =
  | { kind: "text"; text: string; guard: TelegramTempRawGuard }
  | { kind: "document"; caption: string; file: Blob; guard: TelegramTempRawGuard }
  | { kind: "stale" | "unavailable" };

interface BatchMeta {
  id: number;
  date: number;
  message: number;
  nodeCount: number;
  bytes: number;
}
type RawBatch = BatchMeta & { json: string };

const scope = `inbox.receipt_id=? AND inbox.bot_id=? AND inbox.update_id=? AND inbox.actor_id=?
  AND inbox.chat_id=? AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
  AND inbox.message_id=? AND inbox.message_date=? AND inbox.command='help'
  AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()`;
const eligible = `inbox.receipt_nonce=(${tempRawStamp("inbox")}) AND (inbox.actor_id=? OR COALESCE((
  SELECT allowed=1 AND message_date<inbox.message_date FROM telegram_auth
  WHERE bot_id=inbox.bot_id AND user_id=inbox.actor_id
),1))`;
const metadata = "batch.receipt_id AS id,batch.message_date AS date,batch.message_id AS message,batch.node_count AS nodeCount,batch.payload_bytes AS bytes";
const ownPaste = `JOIN telegram_inbox AS paste ON paste.receipt_id=batch.receipt_id AND paste.bot_id=batch.bot_id
  AND paste.actor_id=batch.actor_id AND paste.chat_id=batch.actor_id AND paste.chat_type='private' AND paste.thread_id IS NULL
  AND paste.message_date=batch.message_date AND paste.message_id=batch.message_id AND paste.receipt_nonce='${TELEGRAM_TEMP_MARKER}'
  JOIN telegram_temp_reply AS accepted ON accepted.receipt_id=paste.receipt_id AND accepted.kind='added'
    AND accepted.node_count=batch.node_count`;

function scopeArgs(policy: TelegramPolicy, lease: RawLease) {
  return [lease.receiptId, policy.botId, lease.updateId, lease.actorId, lease.chatId, lease.messageId,
    lease.messageDate, lease.leaseId, lease.attempts] as const;
}

function readyScope(policy: TelegramPolicy, lease: RawLease): lease is RawLease & { tempRaw: true; temp: TelegramTempReply } {
  return lease.tempRaw === true && lease.temp?.kind === "summary" && lease.chatType === "private"
    && lease.threadId === null && inTelegramScope(policy, lease);
}

function exactInventory(policy: TelegramPolicy, rows: readonly BatchMeta[], nodeCount: number): TelegramTempRawGuard {
  const inventory = JSON.stringify(rows.map((row) => [row.id, row.date, row.message, row.nodeCount, row.bytes]));
  return {
    sql: `(${eligible}) AND EXISTS (SELECT 1 FROM telegram_temp_reply
      WHERE receipt_id=inbox.receipt_id AND kind='summary' AND total_count=?)
      AND (SELECT count(*) FROM telegram_temp_batch
        WHERE bot_id=inbox.bot_id AND actor_id=inbox.actor_id AND receipt_id<inbox.receipt_id)=?
      AND NOT EXISTS (SELECT 1 FROM json_each(?) AS expected
        LEFT JOIN telegram_temp_batch AS batch ON batch.receipt_id=json_extract(expected.value,'$[0]')
          AND batch.bot_id=inbox.bot_id AND batch.actor_id=inbox.actor_id AND batch.receipt_id<inbox.receipt_id
          AND batch.message_date=json_extract(expected.value,'$[1]') AND batch.message_id=json_extract(expected.value,'$[2]')
          AND batch.node_count=json_extract(expected.value,'$[3]') AND batch.payload_bytes=json_extract(expected.value,'$[4]')
        WHERE batch.receipt_id IS NULL)`,
    bindings: [policy.adminId, policy.adminId, nodeCount, rows.length, inventory],
  };
}

async function readPage(db: D1Database, policy: TelegramPolicy, lease: RawLease, expected: readonly BatchMeta[]) {
  return db.prepare(`WITH authorized AS (
    SELECT inbox.bot_id,inbox.actor_id,inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    WHERE ${scope} AND reply.state='leased' AND (${eligible})
  ) SELECT ${metadata},batch.nodes_json AS json FROM authorized
    JOIN telegram_temp_batch AS batch ON batch.bot_id=authorized.bot_id AND batch.actor_id=authorized.actor_id
      AND batch.receipt_id<authorized.receipt_id
    JOIN json_each(?) AS expected ON expected.value=batch.receipt_id
    ${ownPaste} ORDER BY batch.receipt_id`)
    .bind(...scopeArgs(policy, lease), policy.adminId, policy.adminId, JSON.stringify(expected.map((row) => row.id))).all<RawBatch>();
}

export async function prepareTelegramTempRawReply(
  db: D1Database, policy: TelegramPolicy, lease: RawLease, deadline: number,
): Promise<TelegramTempRawReply> {
  if (!readyScope(policy, lease)) return { kind: "stale" };
  try {
    // The first transaction reads only identities and declared byte counts. A
    // later retry sees the same immutable batches or refuses the old request.
    const [receipt, metadataRows] = await db.batch<BatchMeta | { totalCount: number }>([
      db.prepare(`SELECT action.total_count AS totalCount FROM telegram_inbox AS inbox
        JOIN telegram_outbox AS reply USING(receipt_id) JOIN telegram_temp_reply AS action USING(receipt_id)
        WHERE ${scope} AND reply.state='leased' AND action.kind='summary' AND (${eligible})`)
        .bind(...scopeArgs(policy, lease), policy.adminId, policy.adminId),
      db.prepare(`SELECT ${metadata} FROM telegram_temp_batch AS batch ${ownPaste}
        WHERE batch.bot_id=? AND batch.actor_id=? AND batch.receipt_id<? ORDER BY batch.receipt_id LIMIT ?`)
        .bind(policy.botId, lease.actorId, lease.receiptId, MAX_TEMP_OWNER_NODES + 1),
    ]);
    if (!receipt?.success || !metadataRows?.success) return { kind: "unavailable" };
    const admitted = receipt.results[0] as { totalCount: number } | undefined;
    if (!admitted || admitted.totalCount !== lease.temp.totalCount) return { kind: "stale" };
    const rows = metadataRows.results as BatchMeta[];
    if (!validInteger(admitted.totalCount, 0, MAX_TEMP_OWNER_NODES) || rows.length > MAX_TEMP_OWNER_NODES) {
      return { kind: "unavailable" };
    }
    let nodes = 0;
    let bytes = 0;
    let previousId = 0;
    for (const row of rows) {
      if (!validInteger(row.id, previousId + 1, lease.receiptId - 1) || !validInteger(row.date, 1)
        || !validInteger(row.message, 1) || !validInteger(row.nodeCount, 1, 500) || !validInteger(row.bytes, 1, MAX_TEMP_BATCH_BYTES)) {
        return { kind: "unavailable" };
      }
      previousId = row.id;
      nodes += row.nodeCount;
      bytes += row.bytes;
    }
    if (nodes !== admitted.totalCount || bytes > MAX_TEMP_OWNER_BYTES) return { kind: "unavailable" };

    const lines: string[] = [];
    let rawBytes = 0;
    let units = 0;
    let document = false;
    for (let start = 0; start < rows.length;) {
      if (Date.now() >= deadline) return { kind: "unavailable" };
      let end = start;
      let size = 0;
      while (end < rows.length && end - start < PAGE_BATCHES && size + rows[end].bytes <= PAGE_BYTES) {
        size += rows[end++].bytes;
      }
      const expected = rows.slice(start, end);
      const page = await readPage(db, policy, lease, expected);
      if (!page.success) return { kind: "unavailable" };
      if (page.results.length !== expected.length) return { kind: "stale" };
      for (const [index, batch] of page.results.entries()) {
        const reference = expected[index];
        if (batch.id !== reference.id || batch.date !== reference.date || batch.message !== reference.message
          || batch.nodeCount !== reference.nodeCount || batch.bytes !== reference.bytes || typeof batch.json !== "string"
          || encoder.encode(batch.json).byteLength !== batch.bytes) return { kind: "unavailable" };
        const parsed: unknown = JSON.parse(batch.json);
        if (!Array.isArray(parsed) || parsed.length !== batch.nodeCount) return { kind: "unavailable" };
        for (const node of parsed) {
          if (node === null || typeof node !== "object" || Array.isArray(node) || !isValidStoredShare(node.share)) {
            return { kind: "unavailable" };
          }
          const separator = lines.length ? 1 : 0;
          rawBytes += encoder.encode(node.share).byteLength + separator;
          units += node.share.length + separator;
          if (rawBytes > MAX_TEMP_OWNER_BYTES) return { kind: "unavailable" };
          document ||= /\p{Cf}/u.test(node.share);
          lines.push(node.share);
        }
      }
      start = end;
    }
    if (lines.length !== nodes || Date.now() >= deadline) return { kind: "unavailable" };
    const caption = renderTelegramTemp(lease.temp);
    const guard = exactInventory(policy, rows, nodes);
    if (!document && caption.length + (nodes ? 2 + units : 0) <= TEXT_UNITS) {
      return { kind: "text", text: nodes ? caption + "\n\n" + lines.join("\n") : caption, guard };
    }
    const file = new Blob(lines.flatMap((line, index) => index === 0 ? [line] : ["\n", line]), { type: "text/plain;charset=utf-8" });
    if (file.size !== rawBytes) return { kind: "unavailable" };
    return { kind: "document", caption, file, guard };
  } catch {
    // D1 and parsing errors can carry full node URIs.
    return { kind: "unavailable" };
  }
}

export async function confirmTelegramTempRawSend(
  db: D1Database, policy: TelegramPolicy, lease: RawLease, guard: TelegramTempRawGuard,
): Promise<boolean> {
  if (!readyScope(policy, lease)) return false;
  try {
    return await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE ${scope} AND reply.state='sending' AND (${guard.sql})`).bind(...scopeArgs(policy, lease), ...guard.bindings).first() !== null;
  } catch {
    return false;
  }
}

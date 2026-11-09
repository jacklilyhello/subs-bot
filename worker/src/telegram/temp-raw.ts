import { validInteger } from "../storage.ts";
import { inTelegramScope, type TelegramCommand, type TelegramPolicy } from "./protocol.ts";
import { renderTelegramTemp, tempRawStamp, type TelegramTempReply } from "./temp-import.ts";
import {
  MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, ownedTempRowsSql, readTempBatchNodes, readTempStorage, tempInventoryGuard,
  tempSchemaGuard, verifyTempInventory, type TempBatchMeta, type TempBatchRow, type TempStorageMode,
} from "./temp-storage.ts";

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

const scope = `inbox.receipt_id=? AND inbox.bot_id=? AND inbox.update_id=? AND inbox.actor_id=?
  AND inbox.chat_id=? AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
  AND inbox.message_id=? AND inbox.message_date=? AND inbox.command='help'
  AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()`;
const eligible = `inbox.receipt_nonce=(${tempRawStamp("inbox")}) AND (inbox.actor_id=? OR COALESCE((
  SELECT allowed=1 AND message_date<inbox.message_date FROM telegram_auth
  WHERE bot_id=inbox.bot_id AND user_id=inbox.actor_id
),1))`;
const tempScope = `SELECT inbox.bot_id,inbox.actor_id,inbox.receipt_id AS before_receipt,inbox.message_date AS visibility_epoch`;

function scopeArgs(policy: TelegramPolicy, lease: RawLease) {
  return [lease.receiptId, policy.botId, lease.updateId, lease.actorId, lease.chatId, lease.messageId,
    lease.messageDate, lease.leaseId, lease.attempts] as const;
}

function readyScope(policy: TelegramPolicy, lease: RawLease): lease is RawLease & { tempRaw: true; temp: TelegramTempReply } {
  return lease.tempRaw === true && lease.temp?.kind === "summary" && lease.chatType === "private"
    && lease.threadId === null && inTelegramScope(policy, lease);
}

function exactInventory(policy: TelegramPolicy, mode: TempStorageMode, rows: readonly TempBatchMeta[], nodeCount: number): TelegramTempRawGuard {
  const inventory = tempInventoryGuard(mode, tempScope, rows);
  return {
    sql: `(${eligible}) AND EXISTS (SELECT 1 FROM telegram_temp_reply
      WHERE receipt_id=inbox.receipt_id AND kind='summary' AND total_count=?)
      AND (${inventory.sql})`,
    bindings: [policy.adminId, policy.adminId, nodeCount, ...inventory.bindings],
  };
}

async function readPage(db: D1Database, policy: TelegramPolicy, lease: RawLease, mode: TempStorageMode, expected: readonly TempBatchMeta[]) {
  return db.prepare(`WITH authorized AS (
    ${tempScope} FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    WHERE ${scope} AND reply.state='leased' AND (${eligible}) AND (${tempSchemaGuard(mode)})
  ), wanted AS (
    SELECT json_extract(value,'$[0]') AS source,json_extract(value,'$[1]') AS id FROM json_each(?)
  ) SELECT * FROM (${ownedTempRowsSql(mode, "authorized", { includePayload: true, verifyLive: true, keysCte: "wanted" })})
    ORDER BY source,id`)
    .bind(...scopeArgs(policy, lease), policy.adminId, policy.adminId,
      JSON.stringify(expected.map(({ source, id }) => [source, id]))).all<TempBatchRow>();
}

export async function prepareTelegramTempRawReply(
  db: D1Database, policy: TelegramPolicy, lease: RawLease, deadline: number,
): Promise<TelegramTempRawReply> {
  if (!readyScope(policy, lease)) return { kind: "stale" };
  try {
    const mode = await readTempStorage(db);
    // The first transaction reads only identities and declared byte counts. A
    // later retry sees the same immutable batches or refuses the old request.
    const [receipt, metadataRows] = await db.batch<TempBatchMeta | { totalCount: number }>([
      db.prepare(`SELECT action.total_count AS totalCount FROM telegram_inbox AS inbox
        JOIN telegram_outbox AS reply USING(receipt_id) JOIN telegram_temp_reply AS action USING(receipt_id)
        WHERE ${scope} AND reply.state='leased' AND action.kind='summary' AND (${eligible}) AND (${tempSchemaGuard(mode)})`)
        .bind(...scopeArgs(policy, lease), policy.adminId, policy.adminId),
      db.prepare(`WITH owned AS (
        SELECT ? AS bot_id,? AS actor_id,? AS before_receipt,? AS visibility_epoch
      ) SELECT * FROM (${ownedTempRowsSql(mode, "owned", { verifyLive: true })}) ORDER BY source,id LIMIT ?`)
        .bind(policy.botId, lease.actorId, lease.receiptId, lease.messageDate, MAX_TEMP_OWNER_NODES + 1),
    ]);
    if (!receipt?.success || !metadataRows?.success) return { kind: "unavailable" };
    const admitted = receipt.results[0] as { totalCount: number } | undefined;
    if (!admitted || admitted.totalCount !== lease.temp.totalCount) return { kind: "stale" };
    const rows = metadataRows.results as TempBatchMeta[];
    if (!validInteger(admitted.totalCount, 0, MAX_TEMP_OWNER_NODES) || rows.length > MAX_TEMP_OWNER_NODES) {
      return { kind: "unavailable" };
    }
    const { nodeCount: nodes } = verifyTempInventory(rows);
    if (nodes !== admitted.totalCount) return { kind: "unavailable" };

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
      const page = await readPage(db, policy, lease, mode, expected);
      if (!page.success) return { kind: "unavailable" };
      if (page.results.length !== expected.length) return { kind: "stale" };
      for (const [index, batch] of page.results.entries()) {
        const reference = expected[index];
        if (batch.source !== reference.source || batch.id !== reference.id || batch.lastId !== reference.lastId
          || batch.date !== reference.date || batch.message !== reference.message || batch.accepted !== reference.accepted
          || batch.nodeCount !== reference.nodeCount || batch.bytes !== reference.bytes || batch.sha256 !== reference.sha256) {
          return { kind: "unavailable" };
        }
        for (const node of await readTempBatchNodes(batch, { requireStoredShare: true })) {
          const share = node.share;
          if (typeof share !== "string") return { kind: "unavailable" };
          const separator = lines.length ? 1 : 0;
          rawBytes += encoder.encode(share).byteLength + separator;
          units += share.length + separator;
          if (rawBytes > MAX_TEMP_OWNER_BYTES) return { kind: "unavailable" };
          document ||= /\p{Cf}/u.test(share);
          lines.push(share);
        }
      }
      start = end;
    }
    if (lines.length !== nodes || Date.now() >= deadline) return { kind: "unavailable" };
    const caption = renderTelegramTemp(lease.temp);
    const guard = exactInventory(policy, mode, rows, nodes);
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

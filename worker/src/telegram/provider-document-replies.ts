import { validInteger } from "../storage.ts";
import type { ProviderSql } from "../provider-jobs.ts";
import { MAX_TELEGRAM_DOCUMENT_NODES } from "./document-persistence.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "./document-transport.ts";
import { providerDocumentOrigin, TELEGRAM_PROVIDER_DOCUMENT_MARKER } from "./provider-document-origin.ts";
import { inTelegramScope, type TelegramPolicy } from "./protocol.ts";
import type { TelegramReplyLease } from "./store.ts";

type Alias = "inbox" | "earlier";
type Summary = { lineCount: number; overflow: number; finishedAt: number; saved: number; coalesced: number; localNodes: number; fromFile: number };
const REPLY_SECONDS = 900;
const RECONCILE_LIMIT = 16;
const ready = `origin.finished_at > unixepoch() - ${REPLY_SECONDS} AND origin.finished_at <= unixepoch()`;

function finishedOrigin(alias: Alias): string {
  return `origin.receipt_id=${alias}.receipt_id AND origin.bot_id=${alias}.bot_id
    AND origin.actor_id=${alias}.actor_id AND origin.finished_at IS NOT NULL`;
}

function countLines(result?: "saved" | "coalesced"): string {
  return `(SELECT count(*) FROM telegram_provider_document_lines AS line WHERE line.receipt_id=origin.receipt_id
    ${result === undefined ? "" : `AND line.result_code='${result}'`})`;
}

const localCount = `COALESCE((SELECT node_count FROM telegram_document_saved_counts WHERE receipt_id=origin.receipt_id),0)`;
const fileOrigin = `EXISTS (SELECT 1 FROM telegram_document_jobs WHERE receipt_id=origin.receipt_id)`;

const terminalLines = `${countLines()}=origin.line_count AND NOT EXISTS (
  SELECT 1 FROM telegram_provider_document_lines AS line WHERE line.receipt_id=origin.receipt_id
    AND (line.result_code IS NULL OR line.ordinal>=origin.line_count))`;

export function telegramProviderDocumentReplyMarker(alias: Alias): string {
  return `(${alias}.receipt_nonce='${TELEGRAM_PROVIDER_DOCUMENT_MARKER}' AND ${alias}.command='help'
    AND ${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL
    AND EXISTS (SELECT 1 FROM telegram_provider_documents AS origin WHERE ${finishedOrigin(alias)}))`;
}

export function telegramProviderDocumentReplyClock(alias: Alias, fallback: string): string {
  return `CASE WHEN ${alias}.receipt_nonce='${TELEGRAM_PROVIDER_DOCUMENT_MARKER}' THEN (
    SELECT origin.finished_at FROM telegram_provider_documents AS origin WHERE ${finishedOrigin(alias)}
  ) ELSE ${fallback} END`;
}

export function telegramProviderDocumentReplyEligible(policy: TelegramPolicy | undefined, alias: Alias): ProviderSql {
  if (!policy) return { sql: "1", bindings: [] };
  const origin = providerDocumentOrigin(policy, "current", alias);
  return { sql: `(${alias}.receipt_nonce IS NOT '${TELEGRAM_PROVIDER_DOCUMENT_MARKER}' OR EXISTS (
    SELECT 1 FROM telegram_provider_documents AS origin WHERE origin.receipt_id=${alias}.receipt_id AND ${ready} AND ${origin.sql}))`,
    bindings: origin.bindings };
}

/** Recover only the private terminal reply, using the original receipt as the outbox key. */
export async function reconcileTelegramProviderDocumentReplies(db: D1Database, policy: TelegramPolicy): Promise<number> {
  const origin = providerDocumentOrigin(policy);
  try {
    const result = await db.prepare(`INSERT INTO telegram_outbox (receipt_id)
      SELECT inbox.receipt_id FROM telegram_provider_documents AS origin JOIN telegram_inbox AS inbox USING (receipt_id)
      WHERE ${origin.sql} AND ${ready} AND ${terminalLines}
        AND NOT EXISTS (SELECT 1 FROM telegram_outbox AS reply WHERE reply.receipt_id=inbox.receipt_id)
      ORDER BY origin.finished_at,inbox.receipt_id LIMIT ${RECONCILE_LIMIT}
      ON CONFLICT (receipt_id) DO NOTHING`).bind(...origin.bindings).run();
    if (result.success && validInteger(result.meta.changes, 0, RECONCILE_LIMIT)) return result.meta.changes;
  } catch {
    throw new Error("Telegram provider document reply reconciliation could not be confirmed.");
  }
  throw new Error("Telegram provider document reply reconciliation could not be confirmed.");
}

export async function renderTelegramProviderDocumentReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease,
): Promise<{ text: string; guard: ProviderSql } | null> {
  if (!lease.providerDocument || !inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return null;
  const origin = providerDocumentOrigin(policy);
  const exact = `origin.receipt_id=inbox.receipt_id AND ${origin.sql} AND ${ready} AND ${terminalLines}`;
  const summary = await db.prepare(`SELECT origin.line_count AS lineCount,origin.overflow_count AS overflow,
    origin.finished_at AS finishedAt,${countLines("saved")} AS saved,${countLines("coalesced")} AS coalesced,
    ${localCount} AS localNodes,${fileOrigin} AS fromFile
    FROM telegram_provider_documents AS origin JOIN telegram_inbox AS inbox USING (receipt_id)
    JOIN telegram_outbox AS reply USING (receipt_id)
    WHERE inbox.receipt_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND reply.state='leased'
      AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch() AND ${exact}`)
    .bind(lease.receiptId, lease.actorId, lease.chatId, lease.leaseId, lease.attempts, ...origin.bindings).first<Summary>();
  if (!summary) return null;
  const { lineCount, overflow, finishedAt, saved, coalesced, localNodes, fromFile } = summary;
  if (!validInteger(lineCount, 1, 20) || !validInteger(overflow, 0, MAX_TELEGRAM_DOCUMENT_BYTES) || !validInteger(finishedAt, 1)
      || !validInteger(saved, 0, lineCount) || !validInteger(coalesced, 0, lineCount - saved)
      || !validInteger(localNodes, 0, MAX_TELEGRAM_DOCUMENT_NODES) || (fromFile !== 0 && fromFile !== 1)) return null;
  const failed = lineCount - saved - coalesced;
  const prefix = localNodes > 0 ? `混合文件已处理。\n本地节点已保存 ${localNodes} 个\n远程订阅`
    : fromFile ? "订阅链接文件已处理。\n" : "订阅链接消息已处理。\n";
  return {
    text: `${prefix}已保存 ${saved} 条\n已合并 ${coalesced} 条\n失败 ${failed} 条\n超出上限 ${overflow} 条`,
    guard: { sql: `EXISTS (SELECT 1 FROM telegram_provider_documents AS origin WHERE ${exact}
      AND origin.line_count=? AND origin.overflow_count=? AND origin.finished_at=?
      AND ${countLines("saved")}=? AND ${countLines("coalesced")}=? AND ${localCount}=? AND ${fileOrigin}=?)`,
      bindings: [...origin.bindings, lineCount, overflow, finishedAt, saved, coalesced, localNodes, fromFile] },
  };
}

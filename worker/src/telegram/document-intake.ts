import { parseSubscriptionDocument } from "../subscription-document.ts";
import { claimTelegramDocumentJob, prepareTelegramDocumentJobLeaseGuard } from "./document-jobs.ts";
import { finishTelegramDocumentJob, MAX_TELEGRAM_DOCUMENT_NODES, persistTelegramDocumentJob } from "./document-persistence.ts";
import { downloadTelegramDocument } from "./document-transport.ts";
import { stageTelegramProviderDocument } from "./provider-document.ts";
import { parseTelegramProviderDocument } from "./provider-document-input.ts";
import type { TelegramPolicy } from "./protocol.ts";

const DOWNLOAD_BUDGET_MS = 20_000;
const MIN_FINISH_WINDOW_MS = 5_000;

export async function runTelegramDocumentIntake(
  db: D1Database,
  bucket: R2Bucket,
  policy: TelegramPolicy,
  providerDocumentsReady = false,
): Promise<boolean> {
  const lease = await claimTelegramDocumentJob(db, policy);
  if (!lease) return false;
  const guard = prepareTelegramDocumentJobLeaseGuard(policy, lease);
  if (await db.prepare(`SELECT ${guard.sql} AS allowed`).bind(...guard.bindings).first<number>("allowed") !== 1) return true;
  const timeoutMs = Math.min(DOWNLOAD_BUDGET_MS, lease.leaseUntil * 1_000 - Date.now() - MIN_FINISH_WINDOW_MS);
  if (timeoutMs <= 0) {
    await finishTelegramDocumentJob(db, policy, lease, { kind: "retry" });
    return true;
  }

  const download = await downloadTelegramDocument(policy, {
    fileId: lease.fileId, expectedSize: lease.expectedSize ?? undefined,
  }, { timeoutMs });
  if (download.kind !== "downloaded") {
    await finishTelegramDocumentJob(db, policy, lease, download.kind === "retryable"
      ? { kind: "retry" } : { kind: "failed", reason: "download-rejected" });
    return true;
  }

  if (providerDocumentsReady && (lease.suffix === "txt" || lease.suffix === "log") &&
      await db.prepare("SELECT 1 AS opted FROM telegram_provider_document_opt_in WHERE receipt_id=?")
        .bind(lease.receiptId).first<number>("opted") === 1) {
    const urls = parseTelegramProviderDocument(download.bytes, lease.suffix);
    if (urls.kind === "invalid-url-list") {
      await finishTelegramDocumentJob(db, policy, lease, { kind: "failed", reason: "invalid-document" });
      return true;
    }
    if (urls.kind === "url-list") {
      try {
        if (!await stageTelegramProviderDocument(db, policy, lease, urls)) {
          await finishTelegramDocumentJob(db, policy, lease, { kind: "failed", reason: "coalesced" });
        }
      } catch {
        await finishTelegramDocumentJob(db, policy, lease, { kind: "retry" });
      }
      return true;
    }
  }

  const syntax = lease.suffix === "json" ? "json" : lease.suffix === "yaml" || lease.suffix === "yml" ? "yaml" : "auto";
  const parsed = parseSubscriptionDocument(download.bytes, { syntax, maxNodes: MAX_TELEGRAM_DOCUMENT_NODES });
  if (parsed.kind !== "parsed" || parsed.rejected.malformed !== 0 || parsed.rejected.unsupported !== 0) {
    await finishTelegramDocumentJob(db, policy, lease, { kind: "failed", reason: "invalid-document" });
    return true;
  }

  try {
    await persistTelegramDocumentJob(db, bucket, policy, lease, parsed.nodes, { parsed: parsed.nodes.length });
  } catch {
    // The publication may have committed. The exact lease makes retry a no-op for a saved receipt.
    try {
      await finishTelegramDocumentJob(db, policy, lease, { kind: "retry" });
    } catch {
      throw new Error("Telegram document publication recovery could not be confirmed.");
    }
  }
  return true;
}

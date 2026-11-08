import { validInteger } from "../storage.ts";
import { normalizeSubscriptionName } from "../subscriptions.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "./document-transport.ts";
import { inTelegramScope, type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_DOCUMENT_JOB_MARKER = "document-job:v1";
const JOB_TTL_SECONDS = 600;
const JOB_LEASE_SECONDS = 90;
const MAX_ATTEMPTS = 3;
const MAX_OWNER_ACTIVE_JOBS = 4;
const MAX_BOT_ACTIVE_JOBS = 16;
const REAP_LIMIT = 16;
const FILE_ID = /^[!-~]{1,512}(?![\s\S])/u;
const LEASE_ID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/u;
const FILE_SUFFIX = /\.(txt|log|yaml|yml|json)(?![\s\S])/iu;

export interface TelegramDocumentJobInput extends TelegramEventScope {
  fileId: string;
  fileName?: string;
  fileSize?: number;
}

type DocumentSuffix = "txt" | "log" | "yaml" | "yml" | "json";
type DocumentFields = { fileId: string; name: string; suffix: DocumentSuffix; expectedSize: number | null };
type LeaseKey = { receiptId: number; actorId: string; leaseId: string };

export type TelegramDocumentJobLease = DocumentFields & LeaseKey & {
  attempts: number;
  leaseUntil: number;
  expiresAt: number;
};

export type TelegramDocumentJobOutcome =
  | { kind: "retry" }
  | { kind: "failed"; reason: "invalid-document" | "download-rejected" | "coalesced" }
  | { kind: "saved" };

export type TelegramDocumentJobResult = "saved" | "invalid-document" | "download-rejected" | "coalesced" |
  "capacity" | "expired" | "access-changed" | "attempts-exhausted";

type JobGuard = { sql: string; bindings: readonly (string | number)[] };
const freshReceipt = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";

// The member's current epoch must match, and the original message must postdate that grant.
const eligibleJob = `(
  EXISTS (
    SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id = job.receipt_id AND inbox.bot_id = job.bot_id
      AND inbox.actor_id = job.actor_id AND inbox.chat_id = job.actor_id AND inbox.chat_type = 'private'
      AND inbox.thread_id IS NULL AND inbox.command = 'help' AND inbox.receipt_nonce = '${TELEGRAM_DOCUMENT_JOB_MARKER}'
      AND (
        job.actor_id = ? OR (job.actor_id = ? AND inbox.message_date > job.auth_message_date AND COALESCE((
          SELECT allowed = 1 AND message_date = job.auth_message_date AND message_id = job.auth_message_id
          FROM telegram_auth WHERE bot_id = job.bot_id AND user_id = job.actor_id
        ), job.auth_message_date = 0 AND job.auth_message_id = 0))
      )
  )
)`;

function canonicalId(value: string): boolean {
  return validInteger(Number(value), 1) && String(Number(value)) === value;
}

function documentFields(event: TelegramDocumentJobInput): DocumentFields | null {
  if (typeof event.fileId !== "string" || !FILE_ID.test(event.fileId) ||
      (event.fileSize !== undefined && !validInteger(event.fileSize, 0, MAX_TELEGRAM_DOCUMENT_BYTES))) return null;
  const rawName = event.fileName === undefined ? "" : event.fileName;
  if (typeof rawName !== "string" || rawName.length > 1024 || /[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(rawName)) return null;
  const basename = (rawName.trim() || "upload.txt").split(/[/\\]/u).at(-1) ?? "";
  const extension = FILE_SUFFIX.exec(basename);
  if (!extension) return null;
  const stem = basename.slice(0, extension.index).trim();
  const name = normalizeSubscriptionName(Array.from(stem || "导入配置").slice(0, 64).join(""));
  return { fileId: event.fileId, name, suffix: extension[1].toLowerCase() as DocumentSuffix,
    expectedSize: event.fileSize ?? null };
}

export async function acceptTelegramDocumentJob(
  db: D1Database,
  policy: TelegramPolicy,
  event: TelegramDocumentJobInput,
  providerUrlOptIn = false,
): Promise<"accepted" | "coalesced" | "capacity" | "invalid-document" | "ignored"> {
  if (!canonicalId(policy.botId) || !canonicalId(event.actorId) || event.chatType !== "private" ||
      event.threadId !== null || !inTelegramScope(policy, event) || !validInteger(event.updateId, 1) ||
      !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  const document = documentFields(event);
  try {
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const steps = [
      db.prepare(`
        INSERT INTO telegram_inbox
          (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
        SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
        WHERE ? = ? OR COALESCE((SELECT allowed = 1 AND message_date < ?
          FROM telegram_auth WHERE bot_id = ? AND user_id = ?), 1)
        ON CONFLICT (bot_id, update_id) DO NOTHING
      `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce,
        event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId),
      db.prepare(`
        WITH candidate AS (
          SELECT incoming.receipt_id, incoming.bot_id, incoming.actor_id, incoming.received_at,
            CASE WHEN incoming.actor_id = ? THEN 0 ELSE COALESCE(auth.message_date, 0) END AS auth_date,
            CASE WHEN incoming.actor_id = ? THEN 0 ELSE COALESCE(auth.message_id, 0) END AS auth_id,
            CASE
              WHEN ? = 1 THEN 'invalid-document'
              WHEN EXISTS (
                SELECT 1 FROM telegram_document_jobs AS active WHERE active.bot_id = incoming.bot_id
                  AND active.actor_id = incoming.actor_id AND active.name = ? AND active.state IN ('pending', 'leased')
              ) THEN 'coalesced'
              WHEN EXISTS (
                SELECT 1 FROM telegram_document_jobs AS active WHERE active.bot_id = incoming.bot_id
                  AND active.actor_id = incoming.actor_id AND active.state IN ('pending', 'leased')
                LIMIT 1 OFFSET ${MAX_OWNER_ACTIVE_JOBS - 1}
              ) OR EXISTS (
                SELECT 1 FROM telegram_document_jobs AS active WHERE active.bot_id = incoming.bot_id
                  AND active.state IN ('pending', 'leased')
                LIMIT 1 OFFSET ${MAX_BOT_ACTIVE_JOBS - 1}
              ) THEN 'capacity'
            END AS rejected
          FROM telegram_inbox AS incoming LEFT JOIN telegram_auth AS auth
            ON auth.bot_id = incoming.bot_id AND auth.user_id = incoming.actor_id
          WHERE ${freshReceipt}
        )
        INSERT INTO telegram_document_jobs (receipt_id, bot_id, actor_id, auth_message_date, auth_message_id,
          state, due_at, expires_at, file_id, name, suffix, expected_size, result_code, finished_at)
        SELECT receipt_id, bot_id, actor_id, auth_date, auth_id, CASE WHEN rejected IS NULL THEN 'pending' ELSE 'done' END,
          received_at, received_at + ${JOB_TTL_SECONDS}, CASE WHEN rejected IS NULL THEN ? END, CASE WHEN rejected IS NULL THEN ? END,
          CASE WHEN rejected IS NULL THEN ? END, CASE WHEN rejected IS NULL THEN ? END,
          rejected, CASE WHEN rejected IS NOT NULL THEN received_at END
        FROM candidate RETURNING result_code AS resultCode
      `).bind(policy.adminId, policy.adminId, document === null ? 1 : 0, document?.name ?? null, ...key,
        document?.fileId ?? null, document?.name ?? null, document?.suffix ?? null, document?.expectedSize ?? null),
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming JOIN telegram_document_jobs AS job USING (receipt_id)
        WHERE ${freshReceipt} AND job.state = 'done'
      `).bind(...key),
      ...(providerUrlOptIn && (document?.suffix === "txt" || document?.suffix === "log") ? [db.prepare(`
        INSERT INTO telegram_provider_document_opt_in (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming JOIN telegram_document_jobs AS job USING (receipt_id)
        WHERE ${freshReceipt} AND job.state='pending'
      `).bind(...key)] : []),
      db.prepare(`
        UPDATE telegram_inbox AS incoming SET receipt_nonce = ?, command = CASE WHEN EXISTS (
          SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id = incoming.receipt_id
            AND job.bot_id = incoming.bot_id AND job.actor_id = incoming.actor_id
        ) THEN command END
        WHERE ${freshReceipt} RETURNING receipt_id
      `).bind(TELEGRAM_DOCUMENT_JOB_MARKER, ...key),
    ];
    const results = await db.batch<{ resultCode: "coalesced" | "capacity" | "invalid-document" | null }>(steps);
    if (results.length === steps.length && results.every(({ success }) => success)) {
      const job = results[1];
      const receipt = results.at(-1)!;
      if (receipt.results.length === 1 && job.results.length === 1) {
        const { resultCode } = job.results[0];
        if (resultCode === "coalesced" || resultCode === "capacity" || resultCode === "invalid-document") return resultCode;
        if (resultCode === null) return "accepted";
      }
      if (receipt.results.length === 0 && job.results.length === 0) return "ignored";
    }
  } catch {
    // Binding errors can include the file identifier or name.
  }
  throw new Error("Telegram document job admission could not be confirmed.");
}

function prepareReap(db: D1Database, policy: TelegramPolicy): D1PreparedStatement {
  return db.prepare(`
    WITH classified AS (
      SELECT job.receipt_id, job.state, job.expires_at, CASE
        WHEN job.expires_at <= unixepoch() THEN 'expired'
        WHEN NOT ${eligibleJob} THEN 'access-changed'
        WHEN job.attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted'
      END AS result_code
      FROM telegram_document_jobs AS job WHERE job.bot_id = ? AND job.state IN ('pending', 'leased')
        AND (job.state = 'pending' OR (job.state = 'leased' AND job.lease_until <= unixepoch()))
    ), terminal AS (
      SELECT receipt_id, result_code FROM classified WHERE result_code IS NOT NULL
      ORDER BY (state = 'leased') DESC, expires_at, receipt_id LIMIT ${REAP_LIMIT}
    )
    UPDATE telegram_document_jobs SET state = 'done', result_code = terminal.result_code, finished_at = unixepoch(),
      lease_id = NULL, lease_until = NULL, file_id = NULL, name = NULL, suffix = NULL, expected_size = NULL
    FROM terminal WHERE telegram_document_jobs.receipt_id = terminal.receipt_id
  `).bind(policy.adminId, policy.memberId, policy.botId);
}

export async function claimTelegramDocumentJob(db: D1Database, policy: TelegramPolicy): Promise<TelegramDocumentJobLease | null> {
  try {
    const steps = [prepareReap(db, policy), db.prepare(`
      UPDATE telegram_document_jobs SET state = 'leased', attempts = attempts + 1, lease_id = ?,
        lease_until = min(unixepoch() + ${JOB_LEASE_SECONDS}, expires_at)
      WHERE receipt_id = (
        SELECT job.receipt_id FROM telegram_document_jobs AS job WHERE job.bot_id = ? AND job.state IN ('pending', 'leased')
          AND job.expires_at > unixepoch() AND job.attempts < ${MAX_ATTEMPTS} AND ${eligibleJob}
          AND ((job.state = 'leased' AND job.lease_until <= unixepoch()) OR (
            job.state = 'pending' AND job.due_at <= unixepoch() AND NOT EXISTS (
              SELECT 1 FROM telegram_document_jobs AS active WHERE active.bot_id = job.bot_id AND active.state = 'leased'
            )
          )) ORDER BY job.due_at, job.receipt_id LIMIT 1
      )
      RETURNING receipt_id AS receiptId, actor_id AS actorId, lease_id AS leaseId, lease_until AS leaseUntil,
        expires_at AS expiresAt, attempts, file_id AS fileId, name, suffix, expected_size AS expectedSize
    `).bind(crypto.randomUUID(), policy.botId, policy.adminId, policy.memberId)];
    const results = await db.batch<TelegramDocumentJobLease>(steps);
    if (results.length === steps.length && results.every(({ success }) => success) && results[1].results.length <= 1) {
      return results[1].results[0] ?? null;
    }
  } catch {
    // Avoid exposing private row contents from the binding.
  }
  throw new Error("Telegram document job claim could not be confirmed.");
}

/** Recheck the exact live lease and private actor in the statement that commits a side effect. */
export function prepareTelegramDocumentJobLeaseGuard(policy: TelegramPolicy, lease: LeaseKey): JobGuard {
  if (!validInteger(lease.receiptId, 1) || !LEASE_ID.test(lease.leaseId) ||
      (lease.actorId !== policy.adminId && lease.actorId !== policy.memberId)) {
    throw new RangeError("Invalid Telegram document job lease.");
  }
  return {
    sql: `EXISTS (
      SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id = ? AND job.bot_id = ? AND job.actor_id = ?
        AND job.lease_id = ? AND job.state = 'leased' AND job.lease_until > unixepoch() AND job.expires_at > unixepoch()
        AND ${eligibleJob}
    )`,
    bindings: [lease.receiptId, policy.botId, lease.actorId, lease.leaseId, policy.adminId, policy.memberId],
  };
}

/** A saved settlement requires a D1 batch that rolls back unless both the publication and settlement change one row. */
export function prepareTelegramDocumentJobSettlement(
  db: D1Database,
  policy: TelegramPolicy,
  lease: LeaseKey,
  outcome: TelegramDocumentJobOutcome,
  requirePublication = false,
): D1PreparedStatement {
  const guard = prepareTelegramDocumentJobLeaseGuard(policy, lease);
  const next = "(unixepoch() + CASE attempts WHEN 1 THEN 15 ELSE 45 END)";
  const retry = outcome.kind === "retry" ? `(attempts < ${MAX_ATTEMPTS} AND ${next} < expires_at)` : "0";
  const result = outcome.kind === "retry" ? `CASE WHEN attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted' ELSE 'expired' END` : "?";
  const code = outcome.kind === "saved" ? ["saved"] : outcome.kind === "failed" ? [outcome.reason] : [];
  return db.prepare(`
    UPDATE telegram_document_jobs SET state = CASE WHEN ${retry} THEN 'pending' ELSE 'done' END,
      due_at = CASE WHEN ${retry} THEN ${next} ELSE due_at END, lease_id = NULL, lease_until = NULL,
      file_id = CASE WHEN ${retry} THEN file_id END, name = CASE WHEN ${retry} THEN name END,
      suffix = CASE WHEN ${retry} THEN suffix END, expected_size = CASE WHEN ${retry} THEN expected_size END,
      result_code = CASE WHEN NOT ${retry} THEN ${result} END, finished_at = CASE WHEN NOT ${retry} THEN unixepoch() END
    WHERE receipt_id = ? AND ${guard.sql} ${requirePublication ? "AND changes() = 1" : ""} RETURNING state
  `).bind(...code, lease.receiptId, ...guard.bindings);
}

export async function settleTelegramDocumentJob(
  db: D1Database,
  policy: TelegramPolicy,
  lease: LeaseKey,
  outcome: Exclude<TelegramDocumentJobOutcome, { kind: "saved" }>,
): Promise<"retry" | "done" | "stale"> {
  try {
    const row = await prepareTelegramDocumentJobSettlement(db, policy, lease, outcome).first<{ state: "pending" | "done" }>();
    return row === null ? "stale" : row.state === "pending" ? "retry" : "done";
  } catch {
    throw new Error("Telegram document job settlement could not be confirmed.");
  }
}

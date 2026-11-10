import { validInteger } from "../storage.ts";
import { normalizeSubscriptionName } from "../subscriptions.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_POLICY_SCHEMA, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentAuthoritySql,
  generalPolicyBindings, generalRecordedOriginSql, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "./document-transport.ts";
import { inTelegramScope, type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_DOCUMENT_JOB_MARKER = "document-job:v1";
export const TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER = "general-document-job:v1";
const JOB_TTL_SECONDS = 600;
export const TELEGRAM_DOCUMENT_REPLY_TTL = 900;
const GENERAL_DOCUMENT_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-node-document:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=11 AND name='0011_telegram_document_jobs.sql'
    AND sha256='4b12335e134c70a2dae9c6ebfa7039a3b268960473004dd2bde579133359ce17' AND mode='applied')
  AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=12 AND name='0012_telegram_document_publication.sql'
    AND sha256='8ce295dced9e297eb590322baf1221395deedcf73f16ae530fc2fa761a9a4bdf' AND mode='applied')`;
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

export type TelegramDocumentPolicy = TelegramPolicy | GeneralTelegramPin;

export function isGeneralDocumentPolicy(policy: TelegramDocumentPolicy): policy is GeneralTelegramPin {
  return "privateDocument" in policy;
}

export function renderTelegramDocumentOutcome(kind: TelegramDocumentJobResult, nodeCount: number | null): string {
  return {
    saved: `文件已导入，共 ${nodeCount ?? 0} 个节点。`,
    "invalid-document": "文件未导入。请检查文件类型、大小和节点格式。已有订阅保持原样。",
    "download-rejected": "无法读取 Telegram 文件。已有订阅保持原样。",
    coalesced: "已有同名文件已处理或正在处理，请核对后再试。",
    capacity: "待处理文件已达上限，请稍后重试。",
    expired: "文件导入已超时。已有订阅保持原样。",
    "access-changed": "授权状态已变更，文件未导入。",
    "attempts-exhausted": "文件导入未完成，请重试。已有订阅保持原样。",
  }[kind];
}

type JobGuard = { sql: string; bindings: readonly (string | number)[] };
const freshReceipt = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";

// Reserve this exact marker for the general worker. Missing, NULL and unknown markers
// must still follow the existing cleanup path for orphaned isolated jobs.
export const ISOLATED_DOCUMENT_CLEANUP_SCOPE = `NOT EXISTS (
  SELECT 1 FROM telegram_inbox AS origin WHERE origin.receipt_id = job.receipt_id
    AND origin.receipt_nonce = '${TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER}'
)`;

// The member's current epoch must match, and the original message must postdate that grant.
const isolatedEligibleJob = `(
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

export function generalDocumentReplyScope(alias: "inbox" | "earlier"): string {
  return `${alias}.receipt_nonce='${TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER}' AND ${alias}.chat_type='private'
    AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL AND ${alias}.command='help'
    AND EXISTS (SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id=${alias}.receipt_id
      AND job.bot_id=${alias}.bot_id AND job.actor_id=${alias}.actor_id AND job.state='done'
      AND (job.result_code<>'saved' OR EXISTS (
        SELECT 1 FROM telegram_document_saved_counts WHERE receipt_id=job.receipt_id)))`;
}

export function generalDocumentReplyEligibility(alias: "inbox" | "earlier"): string {
  return `${alias}.received_at+${TELEGRAM_DOCUMENT_REPLY_TTL}>unixepoch() AND ${GENERAL_DOCUMENT_SCHEMA}`;
}

/** SQL callers must bind the exact job alias and Bot. Recorded scope can only close existing work. */
export function telegramDocumentJobOrigin(policy: TelegramDocumentPolicy, current: boolean): JobGuard {
  if (!isGeneralDocumentPolicy(policy)) return current
    ? { sql: isolatedEligibleJob, bindings: [policy.adminId, policy.memberId] }
    : { sql: ISOLATED_DOCUMENT_CLEANUP_SCOPE, bindings: [] };
  if (!policy.privateDocument) return { sql: "0", bindings: [] };
  const authority = current ? generalCurrentAuthoritySql("inbox") : generalRecordedOriginSql("inbox");
  return { sql: `EXISTS (
    SELECT 1 FROM telegram_inbox AS inbox WHERE (inbox.receipt_id=job.receipt_id AND inbox.bot_id=job.bot_id
      AND inbox.actor_id=job.actor_id AND inbox.chat_id=job.actor_id)
      AND (inbox.chat_type='private' AND inbox.thread_id IS NULL AND inbox.command='help'
        AND inbox.receipt_nonce='${TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER}')
      AND (job.auth_message_date=0 AND job.auth_message_id=0 AND (${GENERAL_DOCUMENT_SCHEMA}))
      AND (${authority})
      ${current ? "" : `AND (${GENERAL_POLICY_SCHEMA} AND ${GENERAL_RECEIPT_SCHEMA})
        AND EXISTS (SELECT 1 FROM telegram_general_receipt AS recorded JOIN telegram_general_actors AS original
          ON original.bot_id=inbox.bot_id AND original.actor_id=inbox.actor_id AND original.generation=recorded.generation
          AND original.revision=recorded.actor_revision AND original.role=recorded.actor_role
          WHERE recorded.receipt_id=inbox.receipt_id AND original.effective_at<inbox.message_date AND recorded.cutover_at<inbox.message_date)`}
  )`, bindings: generalPolicyBindings(policy) };
}

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
  policy: TelegramDocumentPolicy,
  event: TelegramDocumentJobInput,
  providerUrlOptIn = false,
  mixedOptIn = false,
): Promise<"accepted" | "coalesced" | "capacity" | "invalid-document" | "ignored"> {
  const general = isGeneralDocumentPolicy(policy) ? policy : null;
  const adminId = isGeneralDocumentPolicy(policy) ? null : policy.adminId;
  if (!canonicalId(policy.botId) || !canonicalId(event.actorId) || event.chatType !== "private" ||
      event.chatId !== event.actorId || event.threadId !== null || !validInteger(event.updateId, 1) ||
      !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  if (isGeneralDocumentPolicy(policy)) {
    if (!policy.privateDocument || event.actorId === policy.botId || providerUrlOptIn || mixedOptIn) return "ignored";
  } else if (!inTelegramScope(policy, event)) return "ignored";
  const document = documentFields(event);
  try {
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const admission = general ? db.prepare(`
      INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
      FROM ${GENERAL_POLICY_ACTORS_SQL}
      WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND ${GENERAL_DOCUMENT_SCHEMA}
        AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
        AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
        AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
        AND ${GENERAL_ACTOR_QUEUE_CAPACITY}
      ON CONFLICT (bot_id,update_id) DO NOTHING
    `).bind(event.updateId, event.messageId, event.messageDate, nonce, ...generalPolicyBindings(general),
      event.actorId, event.messageDate, event.messageDate, event.updateId) : db.prepare(`
        INSERT INTO telegram_inbox
          (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
        SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
        WHERE ? = ? OR COALESCE((SELECT allowed = 1 AND message_date < ?
          FROM telegram_auth WHERE bot_id = ? AND user_id = ?), 1)
        ON CONFLICT (bot_id, update_id) DO NOTHING
      `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce,
        event.actorId, adminId, event.messageDate, policy.botId, event.actorId);
    const auth = general ? "0 AS auth_date, 0 AS auth_id" : `
      CASE WHEN incoming.actor_id = ? THEN 0 ELSE COALESCE(auth.message_date, 0) END AS auth_date,
      CASE WHEN incoming.actor_id = ? THEN 0 ELSE COALESCE(auth.message_id, 0) END AS auth_id`;
    const authJoin = general ? "" : `LEFT JOIN telegram_auth AS auth
      ON auth.bot_id = incoming.bot_id AND auth.user_id = incoming.actor_id`;
    const steps = [admission, ...(general ? [prepareGeneralReceiptAuthority(db, general, key)] : []), db.prepare(`
        WITH candidate AS (
          SELECT incoming.receipt_id, incoming.bot_id, incoming.actor_id, incoming.received_at,
            ${auth},
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
          FROM telegram_inbox AS incoming ${authJoin}
          WHERE ${freshReceipt}
        )
        INSERT INTO telegram_document_jobs (receipt_id, bot_id, actor_id, auth_message_date, auth_message_id,
          state, due_at, expires_at, file_id, name, suffix, expected_size, result_code, finished_at)
        SELECT receipt_id, bot_id, actor_id, auth_date, auth_id, CASE WHEN rejected IS NULL THEN 'pending' ELSE 'done' END,
          received_at, received_at + ${JOB_TTL_SECONDS}, CASE WHEN rejected IS NULL THEN ? END, CASE WHEN rejected IS NULL THEN ? END,
          CASE WHEN rejected IS NULL THEN ? END, CASE WHEN rejected IS NULL THEN ? END,
          rejected, CASE WHEN rejected IS NOT NULL THEN received_at END
        FROM candidate RETURNING result_code AS resultCode
      `).bind(...(general ? [] : [adminId, adminId]),
        document === null ? 1 : 0, document?.name ?? null, ...key,
        document?.fileId ?? null, document?.name ?? null, document?.suffix ?? null, document?.expectedSize ?? null),
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming JOIN telegram_document_jobs AS job USING (receipt_id)
        WHERE ${freshReceipt} AND job.state = 'done'
      `).bind(...key),
      ...(providerUrlOptIn && (document?.suffix === "txt" || document?.suffix === "log") ? [db.prepare(`
        INSERT INTO telegram_provider_document_opt_in (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming JOIN telegram_document_jobs AS job USING (receipt_id)
        WHERE ${freshReceipt} AND job.state='pending' AND incoming.message_date BETWEEN unixepoch()-900 AND unixepoch()+30
      `).bind(...key)] : []),
      ...(mixedOptIn && providerUrlOptIn && (document?.suffix === "txt" || document?.suffix === "log") ? [db.prepare(`
        INSERT INTO telegram_mixed_document_opt_in (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming JOIN telegram_provider_document_opt_in USING (receipt_id)
        WHERE ${freshReceipt}
      `).bind(...key)] : []),
      db.prepare(`
        UPDATE telegram_inbox AS incoming SET receipt_nonce = ?, command = CASE WHEN EXISTS (
          SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id = incoming.receipt_id
            AND job.bot_id = incoming.bot_id AND job.actor_id = incoming.actor_id
            ${general ? `AND (job.state<>'done' OR EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=job.receipt_id))
              AND ${generalCurrentAuthoritySql("incoming")}` : ""}
        ) THEN command END
        WHERE ${freshReceipt} RETURNING receipt_id
      `).bind(general ? TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER : TELEGRAM_DOCUMENT_JOB_MARKER,
        ...(general ? generalPolicyBindings(general) : []), ...key),
    ];
    const results = await db.batch<{ resultCode: "coalesced" | "capacity" | "invalid-document" | null }>(steps);
    if (results.length === steps.length && results.every(({ success }) => success)) {
      const job = results[general ? 2 : 1];
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

function prepareReap(db: D1Database, policy: TelegramDocumentPolicy): D1PreparedStatement {
  const eligible = telegramDocumentJobOrigin(policy, true);
  const recorded = telegramDocumentJobOrigin(policy, false);
  const general = isGeneralDocumentPolicy(policy);
  const reapable = `job.bot_id = ? AND job.state IN ('pending', 'leased')
    AND (job.state = 'pending' OR (job.state = 'leased' AND job.lease_until <= unixepoch()))`;
  // Keep both exact authority predicates out of the terminal decision expression.
  const scoped = general ? `scoped AS MATERIALIZED (
    SELECT job.receipt_id,job.state,job.expires_at,job.attempts,
      (${eligible.sql}) AS eligible,(${recorded.sql}) AS recorded
    FROM telegram_document_jobs AS job WHERE ${reapable}
  ),` : "";
  return db.prepare(`
    WITH ${scoped} classified AS (
      SELECT job.receipt_id, job.state, job.expires_at, CASE
        WHEN job.expires_at <= unixepoch() THEN 'expired'
        WHEN NOT (${general ? "job.eligible" : eligible.sql}) THEN 'access-changed'
        WHEN job.attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted'
      END AS result_code
      ${general ? "FROM scoped AS job WHERE job.recorded"
        : `FROM telegram_document_jobs AS job WHERE ${reapable} AND (${recorded.sql})`}
    ), terminal AS (
      SELECT receipt_id, result_code FROM classified WHERE result_code IS NOT NULL
      ORDER BY (state = 'leased') DESC, expires_at, receipt_id LIMIT ${REAP_LIMIT}
    )
    UPDATE telegram_document_jobs SET state = 'done', result_code = terminal.result_code, finished_at = unixepoch(),
      lease_id = NULL, lease_until = NULL, file_id = NULL, name = NULL, suffix = NULL, expected_size = NULL
    FROM terminal WHERE telegram_document_jobs.receipt_id = terminal.receipt_id
  `).bind(...eligible.bindings, ...(general ? [...recorded.bindings, policy.botId] : [policy.botId, ...recorded.bindings]));
}

export async function claimTelegramDocumentJob(db: D1Database, policy: TelegramDocumentPolicy): Promise<TelegramDocumentJobLease | null> {
  try {
    const eligible = telegramDocumentJobOrigin(policy, true);
    const general = isGeneralDocumentPolicy(policy);
    const scope = `job.bot_id = ? AND job.state IN ('pending', 'leased')
      AND job.expires_at > unixepoch() AND job.attempts < ${MAX_ATTEMPTS}`;
    // The shared live-lease exclusion remains on the physical queue, regardless of family.
    const scoped = general ? `WITH scoped AS MATERIALIZED (
      SELECT job.receipt_id,job.bot_id,job.state,job.lease_until,job.due_at,(${eligible.sql}) AS eligible
      FROM telegram_document_jobs AS job WHERE ${scope}
    )` : "";
    const steps = [prepareReap(db, policy), db.prepare(`
      ${scoped}
      UPDATE telegram_document_jobs SET state = 'leased', attempts = attempts + 1, lease_id = ?,
        lease_until = min(unixepoch() + ${JOB_LEASE_SECONDS}, expires_at)
      WHERE receipt_id = (
        SELECT job.receipt_id ${general ? "FROM scoped AS job WHERE job.eligible"
          : `FROM telegram_document_jobs AS job WHERE ${scope} AND (${eligible.sql})`}
          AND ((job.state = 'leased' AND job.lease_until <= unixepoch()) OR (
            job.state = 'pending' AND job.due_at <= unixepoch() AND NOT EXISTS (
              SELECT 1 FROM telegram_document_jobs AS active WHERE active.bot_id = job.bot_id AND active.state = 'leased'
            )
          )) ORDER BY job.due_at, job.receipt_id LIMIT 1
      )
      RETURNING receipt_id AS receiptId, actor_id AS actorId, lease_id AS leaseId, lease_until AS leaseUntil,
        expires_at AS expiresAt, attempts, file_id AS fileId, name, suffix, expected_size AS expectedSize
    `).bind(...(general ? [...eligible.bindings, policy.botId, crypto.randomUUID()]
      : [crypto.randomUUID(), policy.botId, ...eligible.bindings]))];
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
export function prepareTelegramDocumentJobLeaseGuard(policy: TelegramDocumentPolicy, lease: LeaseKey): JobGuard {
  if (!validInteger(lease.receiptId, 1) || !LEASE_ID.test(lease.leaseId) ||
      (isGeneralDocumentPolicy(policy) ? !canonicalId(lease.actorId) || lease.actorId === policy.botId
        : lease.actorId !== policy.adminId && lease.actorId !== policy.memberId)) {
    throw new RangeError("Invalid Telegram document job lease.");
  }
  const eligible = telegramDocumentJobOrigin(policy, true);
  return {
    sql: `EXISTS (
      SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id = ? AND job.bot_id = ? AND job.actor_id = ?
        AND job.lease_id = ? AND job.state = 'leased' AND job.lease_until > unixepoch() AND job.expires_at > unixepoch()
        AND (${eligible.sql})
    )`,
    bindings: [lease.receiptId, policy.botId, lease.actorId, lease.leaseId, ...eligible.bindings],
  };
}

/** A saved settlement requires a D1 batch that rolls back unless both the publication and settlement change one row. */
export function prepareTelegramDocumentJobSettlement(
  db: D1Database,
  policy: TelegramDocumentPolicy,
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
  policy: TelegramDocumentPolicy,
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

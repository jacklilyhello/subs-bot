import {
  prepareTelegramProviderBatchQueue, providerHost, providerSourceDigest, telegramProviderBatchOrigin,
  GENERAL_TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, GENERAL_TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER,
  TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER, type ProviderQueuePolicy, type ProviderSql,
} from "../provider-jobs.ts";
import { SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import type { TelegramEventScope } from "./protocol.ts";
import { generalCurrentAuthoritySql, generalPolicyBindings } from "./general-receipt.ts";
import type { TelegramProviderRefreshTarget } from "./provider-refresh.ts";

export const PROVIDER_BATCH_MAX_TARGETS = 16;
// The minute Cron admits at most one lease per invocation. Retries and competing work share this deadline.
export const PROVIDER_BATCH_SECONDS = 45 * 60;
const MAX_INVENTORY = 100;
const MAX_GENERAL_BATCHES = 8;
const DIGEST = /^[0-9a-f]{64}(?![\s\S])/u;

export type TelegramProviderBatchInput = {
  previewReceiptId: number;
  confirmation: TelegramEventScope;
  originAttempt: number;
  epoch: { role: "admin" | "member"; messageDate: number; messageId: number };
  targets: readonly TelegramProviderRefreshTarget[];
  skippedCount: number;
};

export type TelegramProviderBatchProgress = {
  batchId: number;
  targetCount: number;
  skippedCount: number;
  finishedAt: number | null;
  waiting: number;
  pending: number;
  leased: number;
  saved: number;
  failed: number;
  stale: number;
  expired: number;
};

function previewScope(policy: ProviderQueuePolicy, input: TelegramProviderBatchInput): ProviderSql {
  const { confirmation, epoch, originAttempt, previewReceiptId } = input;
  const general = "family" in policy;
  const marker = general ? GENERAL_TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER : TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER;
  const authorization = general ? generalCurrentAuthoritySql("preview") : epoch.role === "admin" ? "1" : `preview.message_date>? AND ?>? AND COALESCE((
    SELECT allowed=1 AND message_date=? AND message_id=? FROM telegram_auth
    WHERE bot_id=preview.bot_id AND user_id=preview.actor_id
  ),?=0 AND ?=0)`;
  const bindings = general ? generalPolicyBindings(policy) : epoch.role === "admin" ? [] : [epoch.messageDate, confirmation.messageDate, epoch.messageDate,
    epoch.messageDate, epoch.messageId, epoch.messageDate, epoch.messageId];
  return { sql: `preview.receipt_id=? AND preview.bot_id=? AND preview.actor_id=? AND preview.chat_id=preview.actor_id
    AND preview.chat_type='private' AND preview.thread_id IS NULL AND preview.command='help'
    AND preview.receipt_nonce='${marker}'
    AND sent.state='sent' AND sent.sent_message_id=? AND sent.attempts=? AND (${authorization})
    AND ? BETWEEN unixepoch()-900 AND unixepoch()+30
    AND NOT EXISTS (SELECT 1 FROM telegram_inbox AS newer WHERE newer.bot_id=preview.bot_id
      AND newer.actor_id=preview.actor_id AND newer.chat_id=preview.chat_id AND newer.chat_type='private'
      AND newer.thread_id IS NULL AND newer.command='help' AND newer.receipt_nonce='${marker}'
      AND (newer.message_date,newer.message_id,newer.receipt_id)>(preview.message_date,preview.message_id,preview.receipt_id))`,
    bindings: [previewReceiptId, policy.botId, confirmation.actorId, confirmation.messageId, originAttempt, ...bindings,
      confirmation.messageDate] };
}

const previewFrom = "FROM telegram_inbox AS preview JOIN telegram_outbox AS sent USING(receipt_id)";
const targetMatch = `subscriptions.owner_id=? AND subscriptions.id=? AND subscriptions.generation=?
  AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=?`;

function validInput(policy: ProviderQueuePolicy, input: TelegramProviderBatchInput): boolean {
  const { confirmation: event, epoch, targets } = input;
  const general = "family" in policy;
  const scoped = general ? policy.includeBatch === true && event.actorId !== policy.botId
    : event.actorId === policy.adminId || event.actorId === policy.memberId;
  if (!scoped || event.chatType !== "private" || event.threadId !== null || event.chatId !== event.actorId
    || ![event.updateId, event.messageDate, event.messageId, input.previewReceiptId].every((value) => validInteger(value, 1))
    || !validInteger(input.originAttempt, 1, 4) || !validInteger(targets.length, 1, PROVIDER_BATCH_MAX_TARGETS)
    || !validInteger(input.skippedCount, 0, MAX_INVENTORY - targets.length)
    || (general ? epoch.messageDate !== 0 || epoch.messageId !== 0
      : epoch.role !== (event.actorId === policy.adminId ? "admin" : "member"))
    || !validInteger(epoch.messageDate, 0) || !validInteger(epoch.messageId, 0)
    || (epoch.messageDate === 0) !== (epoch.messageId === 0) || (epoch.role === "admin" && epoch.messageDate !== 0)) return false;
  return targets.every(({ id, generation, lifecycleRevision, sourceSha256 }, index) =>
    validInteger(id, index === 0 ? 1 : targets[index - 1].id + 1) && validInteger(generation, 0, Number.MAX_SAFE_INTEGER - 1)
    && validInteger(lifecycleRevision, 0) && DIGEST.test(sourceSha256));
}

export async function telegramProviderBatchReady(db: D1Database): Promise<boolean> {
  try {
    const count = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
      AND name IN ('telegram_provider_batches','telegram_provider_batch_jobs') AND tbl_name=name
      OR type='index' AND ((tbl_name='telegram_provider_batches'
        AND name IN ('telegram_provider_batches_running','telegram_provider_batches_latest'))
        OR (tbl_name='telegram_inbox' AND name='telegram_provider_batch_preview_order')
        OR (tbl_name='telegram_provider_batch_jobs' AND name IN (
          'telegram_provider_batch_jobs_active_target','telegram_provider_batch_jobs_global_lease',
          'telegram_provider_batch_jobs_due','telegram_provider_batch_jobs_unsettled')))`).first<number>("present");
    if (count !== 0 && count !== 9) throw new Error();
    return count === 9;
  } catch {
    throw new Error("Telegram provider batch schema could not be confirmed.");
  }
}

/**
 * The interaction layer supplies a persisted frozen preview and opaque-ticket predicates.
 * Apply these statements after inserting the real confirmation inbox row, in the same D1 batch as ticket consumption.
 * The read fence can refer to preview/sent, and the commit fence can also refer to confirmation.
 * The first statement returns the new batch ID, or no row when the confirmation did not start a batch.
 */
export async function prepareTelegramProviderBatchAdmission(
  db: D1Database, policy: ProviderQueuePolicy, input: TelegramProviderBatchInput,
  fence: { read: ProviderSql; commit: ProviderSql; confirmationNonce?: string },
): Promise<D1PreparedStatement[] | null> {
  const general = "family" in policy;
  if (!validInput(policy, input) || general !== (fence.confirmationNonce !== undefined)) return null;
  try {
    const { confirmation: event, epoch, targets } = input;
    const preview = previewScope(policy, input);
    const targetBindings = targets.map((target) => [event.actorId, target.id, target.generation, target.lifecycleRevision] as const);
    const reads = await db.batch<{ sourceUrl: string }>(targetBindings.map((bindings) => db.prepare(
      `SELECT source_url AS sourceUrl FROM subscriptions WHERE ${targetMatch}
       AND EXISTS (SELECT 1 ${previewFrom} WHERE ${preview.sql} AND (${fence.read.sql}))`)
      .bind(...bindings, ...preview.bindings, ...fence.read.bindings)));
    if (reads.length !== targets.length || reads.some(({ success, results }) => !success || results.length > 1)) throw new Error();
    const sources = reads.map(({ results }) => results[0]?.sourceUrl);
    const digests = await Promise.all(sources.map((source) =>
      source !== undefined && providerHost(source) ? providerSourceDigest(source) : null));
    if (targets.some(({ sourceSha256 }, index) => digests[index] !== sourceSha256)) return null;
    const nonce = crypto.randomUUID();
    const requests = await Promise.all(targets.map(({ id }) => providerSourceDigest(JSON.stringify(general
      ? ["subs-bot:telegram-general-provider-batch-job:v1", policy.botId, policy.generation, event.updateId, id]
      : ["subs-bot:telegram-provider-batch-job:v1", policy.botId, event.updateId, id]))));
    const steps = [db.prepare(`INSERT INTO telegram_provider_batches
      (batch_id,preview_receipt_id,origin_attempt,bot_id,actor_id,actor_role,auth_message_date,auth_message_id,
       admission_nonce,target_count,skipped_count,created_at,expires_at)
      SELECT confirmation.receipt_id,preview.receipt_id,?,confirmation.bot_id,confirmation.actor_id,?,?,?,?,?,?,unixepoch(),
        unixepoch()+${PROVIDER_BATCH_SECONDS}
      ${previewFrom} JOIN telegram_inbox AS confirmation ON confirmation.bot_id=preview.bot_id
        AND confirmation.actor_id=preview.actor_id AND confirmation.chat_id=preview.chat_id
      WHERE ${preview.sql} AND confirmation.update_id=? AND confirmation.message_id=? AND confirmation.message_date=?
        AND confirmation.chat_type='private' AND confirmation.thread_id IS NULL AND confirmation.command='help'
        AND confirmation.receipt_nonce=?
        AND confirmation.message_date BETWEEN unixepoch()-900 AND unixepoch()+30
        AND confirmation.received_at BETWEEN unixepoch()-900 AND unixepoch()+30
        AND confirmation.receipt_id>preview.receipt_id AND (${fence.commit.sql})
        ${general ? `AND NOT EXISTS (SELECT 1 FROM telegram_provider_batches WHERE bot_id=confirmation.bot_id
          AND finished_at IS NULL LIMIT 1 OFFSET ${MAX_GENERAL_BATCHES - 1})` : ""}
      ON CONFLICT DO NOTHING RETURNING batch_id AS batchId`)
      .bind(input.originAttempt, epoch.role, epoch.messageDate, epoch.messageId, nonce, targets.length, input.skippedCount,
        ...preview.bindings, event.updateId, event.messageId, event.messageDate,
        fence.confirmationNonce ?? TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, ...fence.commit.bindings)];
    for (const [index, target] of targets.entries()) {
      steps.push(db.prepare(`INSERT INTO telegram_provider_batch_jobs
        (batch_id,ordinal,owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,
         expected_lifecycle_revision,state,created_at,due_at,expires_at)
        SELECT batch.batch_id,?,batch.actor_id,?,'refresh',subscriptions.id,?,subscriptions.generation,
          ${SUBSCRIPTION_LIFECYCLE_REVISION},'waiting',batch.created_at,batch.created_at,batch.expires_at
        FROM telegram_provider_batches AS batch JOIN subscriptions ON subscriptions.owner_id=batch.actor_id
        WHERE batch.admission_nonce=? AND batch.finished_at IS NULL AND ${targetMatch} AND subscriptions.source_url=?
        ON CONFLICT DO NOTHING`)
        .bind(index + 1, requests[index], target.sourceSha256, nonce, ...targetBindings[index], sources[index]!));
    }
    // If a target changed after hashing, abort the caller's whole admission transaction.
    steps.push(db.prepare(`SELECT CASE WHEN NOT EXISTS (
      SELECT 1 FROM telegram_provider_batches AS batch WHERE admission_nonce=? AND (
        SELECT count(*) FROM telegram_provider_batch_jobs WHERE batch_id=batch.batch_id)<>batch.target_count
      ) THEN 1 ELSE json_extract('batch admission guard failed','$') END`).bind(nonce));
    return steps;
  } catch {
    throw new Error("Telegram provider batch admission could not be prepared.");
  }
}

export const PROVIDER_BATCH_FAILED_RESULTS_SQL = "('attempts-exhausted','invalid-document','fetch-rejected','storage-failed')";
const countState = (state: string) => `count(CASE WHEN job.state='${state}' THEN 1 END)`;
const countResult = (predicate: string) => `count(CASE WHEN job.state='done' AND job.result_code ${predicate} THEN 1 END)`;
const COUNTS = `${countResult("='saved'")} AS saved,${countResult("IN " + PROVIDER_BATCH_FAILED_RESULTS_SQL)} AS failed,
  ${countResult("='stale-target'")} AS stale,${countResult("='expired'")} AS expired`;

export async function readTelegramProviderBatchProgress(
  db: D1Database, policy: ProviderQueuePolicy, actorId: string, batchId?: number,
): Promise<TelegramProviderBatchProgress | null> {
  const actorAllowed = "family" in policy ? actorId !== policy.botId : actorId === policy.adminId || actorId === policy.memberId;
  if (!actorAllowed || (batchId !== undefined && !validInteger(batchId, 1))) return null;
  const scope = telegramProviderBatchOrigin(policy);
  const selected = batchId === undefined ? {
    sql: `(SELECT latest.batch_id FROM telegram_provider_batches AS latest WHERE latest.bot_id=? AND latest.actor_id=?
      ORDER BY latest.batch_id DESC LIMIT 1)`, bindings: [policy.botId, actorId],
  } : { sql: "?", bindings: [batchId] };
  try {
    const row = await db.prepare(`SELECT batch.batch_id AS batchId,batch.target_count AS targetCount,batch.skipped_count AS skippedCount,
      batch.finished_at AS finishedAt,${countState("waiting")} AS waiting,${countState("pending")} AS pending,
      ${countState("leased")} AS leased,${COUNTS},batch.saved_count AS frozenSaved,batch.failed_count AS frozenFailed,
      batch.stale_count AS frozenStale,batch.expired_count AS frozenExpired
      FROM telegram_provider_batches AS batch JOIN telegram_provider_batch_jobs AS job USING(batch_id)
      WHERE batch.actor_id=? AND batch.batch_id=${selected.sql} AND (${scope.sql})
      GROUP BY batch.batch_id HAVING count(*)=batch.target_count`)
      .bind(actorId, ...selected.bindings, ...scope.bindings)
      .first<TelegramProviderBatchProgress & Record<"frozenSaved" | "frozenFailed" | "frozenStale" | "frozenExpired", number | null>>();
    if (!row) return null;
    const { frozenSaved, frozenFailed, frozenStale, frozenExpired, ...progress } = row;
    if (row.waiting + row.pending + row.leased + row.saved + row.failed + row.stale + row.expired !== row.targetCount ||
      (row.finishedAt !== null && (frozenSaved !== row.saved || frozenFailed !== row.failed ||
        frozenStale !== row.stale || frozenExpired !== row.expired))) throw new Error();
    return progress;
  } catch {
    throw new Error("Telegram provider batch progress could not be confirmed.");
  }
}

/** Resume expired/stale work, optionally promote one child, and freeze every fully settled parent. */
export async function reconcileTelegramProviderBatches(
  db: D1Database, policy: ProviderQueuePolicy, promote = true,
): Promise<{ promoted: number; finished: number }> {
  const scope = telegramProviderBatchOrigin(policy, true);
  const finishLimit = "family" in policy ? MAX_GENERAL_BATCHES : 2;
  try {
    const steps = [...prepareTelegramProviderBatchQueue(db, policy, promote), db.prepare(`WITH terminal AS MATERIALIZED (
      SELECT batch.batch_id,max(job.finished_at) AS finished_at,${COUNTS}
      FROM telegram_provider_batches AS batch JOIN telegram_provider_batch_jobs AS job USING(batch_id)
      WHERE batch.finished_at IS NULL AND (${scope.sql})
      GROUP BY batch.batch_id HAVING count(*)=batch.target_count AND ${countState("done")}=batch.target_count
      ${"family" in policy ? `ORDER BY batch.batch_id LIMIT ${finishLimit}` : ""}
    ) UPDATE telegram_provider_batches SET finished_at=terminal.finished_at,saved_count=terminal.saved,
      failed_count=terminal.failed,stale_count=terminal.stale,expired_count=terminal.expired
    FROM terminal WHERE telegram_provider_batches.batch_id=terminal.batch_id`).bind(...scope.bindings)];
    const result = await db.batch(steps);
    if (result.length !== steps.length || result.some(({ success }) => !success)
      || (promote && !validInteger(result[1].meta.changes, 0, 1)) || !validInteger(result.at(-1)?.meta.changes, 0, finishLimit)) throw new Error();
    return { promoted: promote ? result[1].meta.changes : 0, finished: result.at(-1)!.meta.changes };
  } catch {
    throw new Error("Telegram provider batch reconciliation could not be confirmed.");
  }
}

import { providerHost, providerSourceDigest, telegramProviderBatchOrigin, type ProviderSql } from "../provider-jobs.ts";
import { validInteger } from "../storage.ts";
import { PROVIDER_BATCH_FAILED_RESULTS_SQL, PROVIDER_BATCH_MAX_TARGETS } from "./provider-batch.ts";
import type { TelegramPolicy } from "./protocol.ts";

type FailedJob = {
  jobId: number; ordinal: number; id: number; generation: number; lifecycle: number;
  result: string; sourceSha256: string; sourceUrl: string | null;
  currentGeneration: number | null; currentLifecycle: number; inTrash: number; failedCount: number;
};

export type FailedBatchTrashSelection = { targets: string; count: number; guard: ProviderSql };

function terminalBatchScope(policy: TelegramPolicy, actorId: string, batchId: number): ProviderSql {
  const origin = telegramProviderBatchOrigin(policy);
  return {
    sql: `batch.batch_id=? AND batch.actor_id=? AND batch.finished_at IS NOT NULL
      AND (${origin.sql}) AND EXISTS (SELECT 1 FROM telegram_provider_batch_interactions AS terminal
        WHERE terminal.receipt_id=batch.batch_id AND terminal.batch_id=batch.batch_id AND terminal.kind='terminal'
          AND terminal.ready_at=batch.finished_at AND terminal.actor_role=batch.actor_role
          AND terminal.auth_message_date=batch.auth_message_date AND terminal.auth_message_id=batch.auth_message_id)`,
    bindings: [batchId, actorId, ...origin.bindings],
  };
}

export function failedBatchTrashOrigin(policy: TelegramPolicy, actorId: string, batchId: number): ProviderSql {
  const scope = terminalBatchScope(policy, actorId, batchId);
  return { sql: `EXISTS (SELECT 1 FROM telegram_provider_batches AS batch WHERE ${scope.sql})`, bindings: scope.bindings };
}

const latest = `NOT EXISTS (SELECT 1 FROM telegram_provider_batches AS newer
  WHERE newer.bot_id=batch.bot_id AND newer.actor_id=batch.actor_id AND newer.batch_id>batch.batch_id)`;
const failed = `job.owner_id=batch.actor_id AND job.state='done' AND job.result_code IN ${PROVIDER_BATCH_FAILED_RESULTS_SQL}`;
const complete = `batch.target_count=(SELECT count(*) FROM telegram_provider_batch_jobs AS job WHERE job.batch_id=batch.batch_id)
  AND NOT EXISTS (SELECT 1 FROM telegram_provider_batch_jobs AS job
    WHERE job.batch_id=batch.batch_id AND (job.state<>'done' OR job.owner_id<>batch.actor_id))`;

// The receipt pins the batch. Finished parent and done child rows are never rewritten by the queue.
export async function readFailedBatchTrash(
  db: D1Database, policy: TelegramPolicy, actorId: string, batchId: number,
): Promise<FailedBatchTrashSelection | null> {
  const scope = terminalBatchScope(policy, actorId, batchId);
  const rows = await db.prepare(`SELECT job.job_id AS jobId,job.ordinal,job.subscription_id AS id,
      job.expected_generation AS generation,job.expected_lifecycle_revision AS lifecycle,job.result_code AS result,
      job.source_sha256 AS sourceSha256,sub.source_url AS sourceUrl,sub.generation AS currentGeneration,
      COALESCE(lifecycle.revision,0) AS currentLifecycle,
      EXISTS (SELECT 1 FROM subscription_trash WHERE id=job.subscription_id) AS inTrash,batch.failed_count AS failedCount
    FROM telegram_provider_batches AS batch JOIN telegram_provider_batch_jobs AS job USING(batch_id)
    LEFT JOIN subscriptions AS sub ON sub.id=job.subscription_id AND sub.owner_id=batch.actor_id
    LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
    WHERE ${scope.sql} AND ${latest} AND ${complete} AND ${failed}
    ORDER BY job.subscription_id LIMIT ${PROVIDER_BATCH_MAX_TARGETS + 1}`)
    .bind(...scope.bindings).all<FailedJob>();
  const count = rows.results.length;
  if (!rows.success || !validInteger(count, 1, PROVIDER_BATCH_MAX_TARGETS)) return null;
  const targets: [number, number, number][] = [];
  const checked: [id: number, generation: number, lifecycle: number, jobId: number, ordinal: number,
    result: string, sourceSha256: string, sourceUrl: string][] = [];
  let previous = 0;
  for (const row of rows.results) {
    const { jobId, ordinal, id, generation, lifecycle, result, sourceSha256, sourceUrl } = row;
    if (row.failedCount !== count || !validInteger(id, previous + 1) || !validInteger(jobId, 1)
      || !validInteger(ordinal, 1, PROVIDER_BATCH_MAX_TARGETS) || !validInteger(generation, 0)
      || !validInteger(lifecycle, 0, Number.MAX_SAFE_INTEGER - 1)
      || row.currentGeneration !== generation || row.currentLifecycle !== lifecycle || row.inTrash !== 0
      || sourceUrl === null || !providerHost(sourceUrl) || await providerSourceDigest(sourceUrl) !== sourceSha256) return null;
    targets.push([id, generation, lifecycle]);
    checked.push([id, generation, lifecycle, jobId, ordinal, result, sourceSha256, sourceUrl]);
    previous = id;
  }
  // D1 has no SHA-256 function. Compare the exact bytes hashed above in the transaction
  // alongside the full failed-job set. The raw sources are transient bind values only.
  const guard = { sql: `EXISTS (SELECT 1 FROM telegram_provider_batches AS batch
    WHERE ${scope.sql} AND ${latest} AND ${complete} AND batch.failed_count=?
      AND (SELECT count(*) FROM telegram_provider_batch_jobs AS job WHERE job.batch_id=batch.batch_id AND ${failed})=?
      AND NOT EXISTS (SELECT 1 FROM json_each(?) AS expected
        LEFT JOIN telegram_provider_batch_jobs AS job ON job.batch_id=batch.batch_id AND ${failed}
          AND job.subscription_id=json_extract(expected.value,'$[0]')
          AND job.expected_generation=json_extract(expected.value,'$[1]')
          AND job.expected_lifecycle_revision=json_extract(expected.value,'$[2]')
          AND job.job_id=json_extract(expected.value,'$[3]') AND job.ordinal=json_extract(expected.value,'$[4]')
          AND job.result_code=json_extract(expected.value,'$[5]') AND job.source_sha256=json_extract(expected.value,'$[6]')
        LEFT JOIN subscriptions AS sub ON sub.id=job.subscription_id AND sub.owner_id=batch.actor_id
          AND sub.generation=job.expected_generation AND sub.source_url COLLATE BINARY=json_extract(expected.value,'$[7]')
        LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
        WHERE sub.id IS NULL OR COALESCE(lifecycle.revision,0)<>job.expected_lifecycle_revision
          OR EXISTS (SELECT 1 FROM subscription_trash WHERE id=sub.id)))`,
  bindings: [...scope.bindings, count, count, JSON.stringify(checked)] };
  return { targets: JSON.stringify(targets), count, guard };
}

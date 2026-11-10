import { checkOwnerId, digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "./storage.ts";
import { normalizeSubscriptionName } from "./subscriptions.ts";
import { isolatedTelegramRoleEpochSql } from "./telegram/authorization-sql.ts";
import { providerDocumentOrigin } from "./telegram/provider-document-origin.ts";
import { providerInitialTitleReady } from "./provider-initial-title.ts";
import { GENERAL_POLICY_SCHEMA, GENERAL_RECEIPT_SCHEMA, generalCurrentAuthoritySql,
  generalPolicyBindings, generalRecordedOriginSql, type GeneralAuthorityPin } from "./telegram/general-receipt.ts";

export const PROVIDER_JOB_TTL_SECONDS = 3600;
const LEASE_SECONDS = 120;
const MAX_ATTEMPTS = 3;
const MAX_OWNER_JOBS = 4;
const MAX_GLOBAL_JOBS = 8;
export const MAX_PROVIDER_OWNER_SOURCES = 100;
export const PROVIDER_TRASH_SECONDS = 2_592_000;
const MAX_URL_BYTES = 8192;
const SHA256 = /^[0-9a-f]{64}(?![\s\S])/u;
const REVISION = /^[0-9a-f]{40}(?![\s\S])/u;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/u;
const encoder = new TextEncoder();

type AdmissionKey = { ownerId: string; requestKey: string };
type UrlImport = AdmissionKey & { sourceUrl: string; name?: string; initialTitle?: boolean };
type Refresh = AdmissionKey & { id: number; expectedGeneration?: number; expectedLifecycleRevision?: number };

export const TELEGRAM_PROVIDER_MARKER = "provider-request:v1";
export const GENERAL_TELEGRAM_PROVIDER_MARKER = "general-provider-request:v1";
export const TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER = "provider-batch-preview:v1";
export const TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER = "provider-batch-confirm:v1";
export type ProviderTelegramPolicy = {
  readonly botId: string; readonly adminId: string; readonly memberId: string; readonly includeDocuments?: true;
};
export type GeneralProviderAuthority = Readonly<GeneralAuthorityPin> & {
  readonly family: "general"; readonly includeDocuments?: never; readonly includeBatch?: never; readonly queue?: never;
};
export type ProviderQueuePolicy = ProviderTelegramPolicy | GeneralProviderAuthority;
type JobScope = (ProviderTelegramPolicy & { readonly includeBatch?: true; readonly queue?: "batch" })
  | GeneralProviderAuthority | "generic";
// A rollback to the older Telegram consumer must never see batch rows or their leases.
type JobTable = "subscription_provider_jobs" | "telegram_provider_jobs" | "telegram_provider_batch_jobs";

export type ProviderAdmission =
  | { kind: "queued" | "coalesced" | "duplicate"; jobId: number; subscriptionId: number }
  | { kind: "capacity" | "unavailable" | "conflict" };

export interface ProviderJobLease {
  readonly jobId: number;
  readonly id: number;
  readonly ownerId: string;
  readonly kind: "url-import" | "refresh";
  readonly requestKey: string;
  readonly expectedGeneration: number;
  readonly expectedLifecycleRevision: number;
  readonly sourceSha256: string;
  readonly leaseId: string;
  readonly leaseUntil: number;
  readonly expiresAt: number;
  readonly attempts: number;
  readonly sourceUrl: string;
  readonly scope: JobScope;
}

type TerminalFailure = "invalid-document" | "fetch-rejected" | "storage-failed";
type RetryFailure = "busy" | "timeout" | "dns-failed" | "unavailable" | "upstream-retryable" | "storage-failed";
export type ProviderFailureOutcome = { kind: "retry"; reason: RetryFailure } | { kind: "failed"; reason: TerminalFailure };
type ProviderJobOutcome = ProviderFailureOutcome | { kind: "saved"; snapshotId: string };
type Binding = string | number;
export type ProviderSql = { sql: string; bindings: readonly Binding[] };
type Guard = ProviderSql;
type Receipt = {
  jobId: number; subscriptionId: number; kind: ProviderJobLease["kind"]; sourceSha256: string;
  resultCode: string | null;
};
type AdmissionRow = Partial<Receipt> & { refused?: "capacity" | "unavailable" | "conflict" };
type ClaimedRow = Omit<ProviderJobLease, "sourceUrl" | "scope">;
type AdmissionPlan = { statements: D1PreparedStatement[]; insertIndex: number; refusal: Guard };
type SettlementRow = { state: "pending" | "done"; resultCode: string | null };

const receiptFields = `job_id AS jobId, subscription_id AS subscriptionId, kind,
  source_sha256 AS sourceSha256, result_code AS resultCode`;
const liveState = "state IN ('pending', 'leased')";
export const GENERAL_PROVIDER_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-provider-authority:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=21 AND name='0021_telegram_provider_admission.sql'
    AND sha256='c0557767395697de2d9c3073b4493759104f0eabd399b7391ba9204b7e6527bc' AND mode='applied')
  AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=33 AND name='0033_provider_snapshot_journal.sql'
    AND sha256='35873c62fd9482bc446fb2c80a675ddc22cf70d3f97d7632877b2ce28cbb3f7f' AND mode='applied')`;
function jobTable(scope: JobScope): JobTable {
  return scope === "generic" ? "subscription_provider_jobs"
    : scope.queue === "batch" ? "telegram_provider_batch_jobs" : "telegram_provider_jobs";
}

export function providerJobLeaseTable(lease: ProviderJobLease): JobTable {
  return jobTable(lease.scope);
}

function sameJob(scope: JobScope, table: JobTable): Guard {
  const authorization = scopeAuthorization(scope, "active");
  return { sql: `EXISTS (SELECT 1 FROM ${table} AS active
    WHERE active.owner_id = target.owner_id AND active.subscription_id = target.id AND active.${liveState}
      AND active.source_sha256 = ? AND active.expected_generation = target.generation
      AND active.expected_lifecycle_revision = target.lifecycle_revision
      ${scope === "generic" ? "" : `AND active.expires_at > unixepoch() AND (${authorization.sql})`})`,
    bindings: authorization.bindings };
}

function activeJobs(scope: JobScope): string {
  const columns = "owner_id,subscription_id";
  if (scope === "generic" || !scope.includeBatch) return `SELECT ${columns} FROM ${jobTable(scope)} WHERE ${liveState}`;
  return `SELECT ${columns} FROM telegram_provider_jobs WHERE ${liveState}
    UNION ALL SELECT ${columns} FROM telegram_provider_batch_jobs WHERE ${liveState}`;
}

function jobCapacity(owner: string, scope: JobScope): string {
  const active = activeJobs(scope);
  return `NOT EXISTS (SELECT 1 FROM (${active}) AS active WHERE active.owner_id = ${owner} LIMIT 1 OFFSET ${MAX_OWNER_JOBS - 1})
    AND NOT EXISTS (SELECT 1 FROM (${active}) LIMIT 1 OFFSET ${MAX_GLOBAL_JOBS - 1})`;
}

function validateKey({ ownerId, requestKey }: AdmissionKey): void {
  checkOwnerId(ownerId);
  if (typeof requestKey !== "string" || !SHA256.test(requestKey)) throw new RangeError("Invalid provider job request.");
}

export function providerHost(value: unknown): string | null {
  if (typeof value !== "string" || value.length > MAX_URL_BYTES ||
      /[\s\\\u0000-\u001f\u007f-\u009f\ud800-\udfff#]/u.test(value) ||
      /%(?![0-9a-f]{2})/iu.test(value) || encoder.encode(value).byteLength > MAX_URL_BYTES) return null;
  const authority = /^https?:\/\/([^/?#]+)/iu.exec(value)?.[1];
  if (!authority || /[@%]/u.test(authority) || authority.endsWith(":")) return null;
  try {
    const url = new URL(value);
    return url.hostname && !url.username && !url.password && !url.port ? url.hostname : null;
  } catch {
    return null;
  }
}

export async function providerSourceDigest(sourceUrl: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(sourceUrl)));
}

function ownedSource(ownerId: string, id: number, sourceUrl?: string): Guard {
  return sourceUrl === undefined
    ? { sql: "subscriptions.owner_id = ? AND subscriptions.id = ?", bindings: [ownerId, id] }
    : { sql: "subscriptions.owner_id = ? AND subscriptions.id = ? AND subscriptions.source_url = ?",
        bindings: [ownerId, id, sourceUrl] };
}

function previousAdmission(row: AdmissionRow, kind: ProviderJobLease["kind"], target: number | string): ProviderAdmission {
  if (!validInteger(row.jobId, 1) || !validInteger(row.subscriptionId, 1)) {
    throw new Error("Provider job receipt could not be confirmed.");
  }
  if (row.kind !== kind || (kind === "refresh" ? row.subscriptionId !== target : row.sourceSha256 !== target)) {
    return { kind: "conflict" };
  }
  return { kind: "duplicate", jobId: row.jobId, subscriptionId: row.subscriptionId };
}

function prepareAdmission(
  db: D1Database, key: AdmissionKey, kind: ProviderJobLease["kind"], target: Guard, digest: string, scope: JobScope,
): D1PreparedStatement {
  const table = jobTable(scope);
  const same = sameJob(scope, table);
  const general = scope !== "generic" && "family" in scope;
  const activeJob = `EXISTS (SELECT 1 FROM (${activeJobs(scope)}) AS active
    WHERE active.owner_id = target.owner_id AND active.subscription_id = target.id)`;
  const canStart = `NOT ${activeJob} AND ${jobCapacity("target.owner_id", scope)}`;
  return db.prepare(`
    WITH candidates AS (
      SELECT subscriptions.id, subscriptions.owner_id, subscriptions.generation,
        ${SUBSCRIPTION_LIFECYCLE_REVISION} AS lifecycle_revision
      FROM subscriptions WHERE ${target.sql} LIMIT 2
    ), classified AS ${general ? "MATERIALIZED " : ""}(
      SELECT target.*, ${same.sql} AS coalesced
      FROM candidates AS target WHERE (SELECT count(*) FROM candidates) = 1
        AND target.generation < 9007199254740991
        AND NOT EXISTS (SELECT 1 FROM ${table} WHERE owner_id = target.owner_id AND request_key = ?)
        ${general ? "" : `AND (${same.sql} OR (${canStart}))`}
    )
    INSERT INTO ${table}
      (owner_id, request_key, kind, subscription_id, source_sha256, expected_generation, expected_lifecycle_revision,
       state, created_at, due_at, expires_at, result_code, finished_at)
    SELECT owner_id, ?, ?, id, ?, generation, lifecycle_revision, CASE WHEN coalesced THEN 'done' ELSE 'pending' END,
      unixepoch(), unixepoch(), unixepoch() + ${PROVIDER_JOB_TTL_SECONDS}, CASE WHEN coalesced THEN 'coalesced' END,
      CASE WHEN coalesced THEN unixepoch() END FROM classified AS target WHERE ${general ? `coalesced OR (${canStart})` : "1"}
    ON CONFLICT (owner_id, request_key) DO NOTHING
    RETURNING ${receiptFields}
  `).bind(...target.bindings, digest, ...same.bindings, key.requestKey,
    ...(general ? [] : [digest, ...same.bindings]), key.requestKey, kind, digest);
}

function prepareAdmissionPlan(
  db: D1Database, key: AdmissionKey, kind: ProviderJobLease["kind"], target: Guard, digest: string,
  refusal: Guard, create?: { sourceUrl: string; name: string; initialTitle?: boolean }, fence?: Guard,
  authorization?: ProviderQueuePolicy, includeBatch = false,
): AdmissionPlan {
  const steps: D1PreparedStatement[] = [];
  const scope = jobScope(authorization, includeBatch);
  const table = jobTable(scope);
  const token = create ? crypto.randomUUID().replaceAll("-", "") : null;
  if (create && token) {
    steps.push(db.prepare(`
      INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at)
      SELECT ?, ?, ?, ?, unixepoch(), unixepoch()
      WHERE NOT EXISTS (SELECT 1 FROM ${table} WHERE owner_id = ? AND request_key = ?)
        AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id = ? AND source_url = ?)
        AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE owner_id = ? AND source_url = ?
          AND deleted_at >= unixepoch() - ${PROVIDER_TRASH_SECONDS})
        AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE token = ?)
        AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id = ?
          AND (lower(substr(source_url, 1, 7)) = 'http://' OR lower(substr(source_url, 1, 8)) = 'https://')
          LIMIT 1 OFFSET ${MAX_PROVIDER_OWNER_SOURCES - 1})
        AND ${jobCapacity("?", scope)}
        ${fence ? `AND (${fence.sql})` : ""}
    `).bind(key.ownerId, create.name, create.sourceUrl, token, key.ownerId, key.requestKey,
      key.ownerId, create.sourceUrl, key.ownerId, create.sourceUrl, token, key.ownerId, key.ownerId, ...(fence?.bindings ?? [])));
  }
  const insertIndex = steps.length;
  steps.push(prepareAdmission(db, key, kind, fence ? { sql: `(${target.sql}) AND (${fence.sql})`,
    bindings: [...target.bindings, ...fence.bindings] } : target, digest, scope));
  if (token) {
    if (create?.initialTitle) {
      steps.push(db.prepare(`DELETE FROM telegram_provider_initial_titles WHERE subscription_id IN (
        SELECT subscription_id FROM telegram_provider_initial_titles WHERE expires_at<=unixepoch()
        ORDER BY expires_at,subscription_id LIMIT 16)
        AND EXISTS (SELECT 1 FROM subscriptions WHERE token=?)`).bind(token),
      db.prepare(`INSERT INTO telegram_provider_initial_titles (subscription_id,request_key,source_sha256,expires_at)
        SELECT sub.id,job.request_key,job.source_sha256,job.expires_at FROM subscriptions AS sub
        JOIN ${table} AS job ON job.subscription_id=sub.id AND job.owner_id=sub.owner_id
        WHERE sub.token=? AND job.owner_id=? AND job.request_key=? AND job.source_sha256=? AND job.state='pending'
          AND job.kind='url-import' AND job.expected_generation=0 AND job.expected_lifecycle_revision=0`)
        .bind(token, key.ownerId, key.requestKey, digest));
    }
    // A new shell and its job must either both commit or both roll back.
    steps.push(db.prepare(`
      SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM subscriptions WHERE token = ?)
        OR EXISTS (SELECT 1 FROM ${table} AS job JOIN subscriptions AS sub ON sub.id = job.subscription_id
          WHERE sub.token = ? AND job.owner_id = ? AND job.request_key = ? AND job.state = 'pending'
          ${create?.initialTitle ? `AND EXISTS (SELECT 1 FROM telegram_provider_initial_titles AS initial
            WHERE initial.subscription_id=sub.id AND initial.request_key=job.request_key
              AND initial.source_sha256=job.source_sha256 AND initial.expires_at=job.expires_at)` : ""})
        THEN 1 ELSE json_extract('provider admission guard failed', '$') END
    `).bind(token, token, key.ownerId, key.requestKey));
  }
  return { statements: steps, insertIndex, refusal };
}

async function admit(
  db: D1Database, key: AdmissionKey, kind: ProviderJobLease["kind"], digest: string, originTarget: number | string,
  { statements, insertIndex, refusal }: AdmissionPlan,
): Promise<ProviderAdmission> {
  const steps = [...statements, db.prepare(`SELECT ${receiptFields} FROM subscription_provider_jobs WHERE owner_id = ? AND request_key = ?`)
    .bind(key.ownerId, key.requestKey), db.prepare(`SELECT ${refusal.sql} AS refused`).bind(...refusal.bindings)];
  const results = await db.batch<AdmissionRow>(steps);
  if (results.length !== steps.length || results.some(({ success }) => !success) ||
      results[insertIndex].results.length > 1 || results.at(-2)!.results.length > 1) {
    throw new Error("Provider job admission could not be confirmed.");
  }
  const inserted = results[insertIndex].results[0];
  const saved = results.at(-2)!.results[0];
  if (inserted) {
    if (!saved || inserted.jobId !== saved.jobId || !validInteger(inserted.jobId, 1) ||
        !validInteger(inserted.subscriptionId, 1) || inserted.subscriptionId !== saved.subscriptionId ||
        inserted.kind !== kind || inserted.sourceSha256 !== digest ||
        (inserted.resultCode !== null && inserted.resultCode !== "coalesced")) {
      throw new Error("Provider job receipt could not be confirmed.");
    }
    return { kind: inserted.resultCode === "coalesced" ? "coalesced" : "queued",
      jobId: inserted.jobId, subscriptionId: inserted.subscriptionId };
  }
  if (saved) return previousAdmission(saved, kind, originTarget);
  const reason = results.at(-1)!.results[0]?.refused;
  if (reason === "capacity" || reason === "unavailable" || reason === "conflict") return { kind: reason };
  throw new Error("Provider job admission could not be confirmed.");
}

export async function prepareProviderUrlImport(
  db: D1Database, input: UrlImport, fence?: Guard, authorization?: ProviderQueuePolicy, includeBatch = false,
): Promise<{ digest: string; plan: AdmissionPlan }> {
  validateKey(input);
  const host = providerHost(input.sourceUrl);
  if (!host) throw new RangeError("Invalid provider source URL.");
  const name = normalizeSubscriptionName(input.name ?? Array.from(host).slice(0, 64).join(""));
  const digest = await providerSourceDigest(input.sourceUrl);
  const target = { sql: "subscriptions.owner_id = ? AND subscriptions.source_url = ?",
    bindings: [input.ownerId, input.sourceUrl] };
  const refusal = {
    sql: `CASE WHEN (SELECT count(*) FROM (SELECT 1 FROM subscriptions WHERE ${target.sql} LIMIT 2)) > 1
      THEN 'conflict' WHEN NOT EXISTS (SELECT 1 FROM subscriptions WHERE ${target.sql}) AND EXISTS (
        SELECT 1 FROM subscription_trash WHERE owner_id = ? AND source_url = ? AND deleted_at >= unixepoch() - ${PROVIDER_TRASH_SECONDS}
      ) THEN 'unavailable' ELSE 'capacity' END`,
    bindings: [...target.bindings, ...target.bindings, input.ownerId, input.sourceUrl],
  };
  const initialTitle = input.initialTitle === true && authorization !== undefined && await providerInitialTitleReady(db);
  return { digest, plan: prepareAdmissionPlan(db, input, "url-import", target, digest, refusal,
    { sourceUrl: input.sourceUrl, name, initialTitle }, fence, authorization, includeBatch) };
}

export async function prepareOwnedProviderRefresh(
  db: D1Database, input: Refresh, fence?: Guard, readFence?: Guard, authorization?: ProviderQueuePolicy, includeBatch = false,
): Promise<{ digest: string; plan: AdmissionPlan } | null> {
  validateKey(input);
  const { id, expectedGeneration, expectedLifecycleRevision } = input;
  if (!validInteger(id, 1) || (expectedGeneration === undefined) !== (expectedLifecycleRevision === undefined) ||
      (expectedGeneration !== undefined && (!validInteger(expectedGeneration, 0) || !validInteger(expectedLifecycleRevision, 0)))) {
    throw new RangeError("Invalid subscription version.");
  }
  const version = expectedGeneration === undefined ? { sql: "", bindings: [] } : {
    sql: `AND subscriptions.generation = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?`,
    bindings: [expectedGeneration, expectedLifecycleRevision!],
  };
  const target = ownedSource(input.ownerId, id);
  const sourceUrl = await db.prepare(`SELECT source_url FROM subscriptions WHERE ${target.sql} ${version.sql}
    ${readFence ? `AND (${readFence.sql})` : ""}`).bind(...target.bindings, ...version.bindings, ...(readFence?.bindings ?? []))
    .first<string>("source_url");
  if (sourceUrl === null || !providerHost(sourceUrl)) return null;
  const owned = ownedSource(input.ownerId, id, sourceUrl);
  const exact = { sql: `${owned.sql} ${version.sql}`, bindings: [...owned.bindings, ...version.bindings] };
  const refusal = { sql: `CASE WHEN EXISTS (SELECT 1 FROM subscriptions WHERE ${exact.sql})
    THEN 'capacity' ELSE 'unavailable' END`, bindings: exact.bindings };
  const digest = await providerSourceDigest(sourceUrl);
  return { digest, plan: prepareAdmissionPlan(db, input, "refresh", exact, digest, refusal, undefined, fence, authorization, includeBatch) };
}

/** Internal admission for an already authorized owner. No network request occurs here. */
export async function enqueueProviderUrlImport(db: D1Database, input: UrlImport): Promise<ProviderAdmission> {
  validateKey(input);
  const host = providerHost(input.sourceUrl);
  if (!host) throw new RangeError("Invalid provider source URL.");
  const name = normalizeSubscriptionName(input.name ?? Array.from(host).slice(0, 64).join(""));
  try {
    const { digest, plan } = await prepareProviderUrlImport(db, { ...input, name });
    return await admit(db, input, "url-import", digest, digest, plan);
  } catch {
    // D1 failures may include bound source values.
    throw new Error("Provider URL import admission could not be confirmed.");
  }
}

/** Internal admission for an existing owned remote source. */
export async function enqueueOwnedProviderRefresh(db: D1Database, input: Refresh): Promise<ProviderAdmission> {
  validateKey(input);
  if (!validInteger(input.id, 1)) throw new RangeError("Invalid subscription ID.");
  try {
    const earlier = await db.prepare(`SELECT ${receiptFields} FROM subscription_provider_jobs
      WHERE owner_id = ? AND request_key = ?`).bind(input.ownerId, input.requestKey).first<Receipt>();
    if (earlier) return previousAdmission(earlier, "refresh", input.id);
    const prepared = await prepareOwnedProviderRefresh(db, input);
    if (!prepared) return { kind: "unavailable" };
    return await admit(db, input, "refresh", prepared.digest, input.id, prepared.plan);
  } catch {
    throw new Error("Provider refresh admission could not be confirmed.");
  }
}

const currentTarget = `EXISTS (
  SELECT 1 FROM subscriptions WHERE subscriptions.id = job.subscription_id AND subscriptions.owner_id = job.owner_id
    AND subscriptions.generation = job.expected_generation
    AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = job.expected_lifecycle_revision
)`;

/** The batch alias is fixed so the same provenance fence can protect work and readback. */
export function telegramProviderBatchOrigin(policy: ProviderTelegramPolicy, forRetirement = false): ProviderSql {
  // Only retirement may classify an old role of a still-approved actor as stale.
  const role = forRetirement ? `batch.actor_id IN (?,?) AND (
    (batch.actor_role='admin' AND batch.auth_message_date=0 AND batch.auth_message_id=0)
    OR (batch.actor_role='member' AND preview.message_date>batch.auth_message_date AND confirmation.message_date>batch.auth_message_date))`
    : `((batch.actor_id=? AND batch.actor_role='admin' AND batch.auth_message_date=0 AND batch.auth_message_id=0)
      OR (batch.actor_id=? AND batch.actor_role='member' AND preview.message_date>batch.auth_message_date
        AND confirmation.message_date>batch.auth_message_date AND COALESCE((
          SELECT allowed=1 AND message_date=batch.auth_message_date AND message_id=batch.auth_message_id
          FROM telegram_auth WHERE bot_id=batch.bot_id AND user_id=batch.actor_id
        ),batch.auth_message_date=0 AND batch.auth_message_id=0)))`;
  // Shallow guard groups keep this shared predicate within D1's expression-depth limit when nested.
  return { sql: `batch.bot_id=? AND EXISTS (
    SELECT 1 FROM telegram_inbox AS confirmation JOIN telegram_inbox AS preview ON preview.receipt_id=batch.preview_receipt_id
    JOIN telegram_outbox AS sent ON sent.receipt_id=preview.receipt_id
    WHERE confirmation.receipt_id=batch.batch_id AND CASE
      WHEN (confirmation.bot_id=batch.bot_id AND confirmation.actor_id=batch.actor_id
        AND confirmation.chat_type='private' AND confirmation.chat_id=confirmation.actor_id
        AND confirmation.thread_id IS NULL) IS NOT TRUE THEN 0
      WHEN (confirmation.command='help' AND confirmation.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER}'
        AND preview.bot_id=batch.bot_id AND preview.actor_id=batch.actor_id) IS NOT TRUE THEN 0
      WHEN (preview.chat_type='private' AND preview.chat_id=preview.actor_id AND preview.thread_id IS NULL
        AND preview.command='help' AND preview.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER}') IS NOT TRUE THEN 0
      WHEN (sent.state='sent' AND sent.sent_message_id=confirmation.message_id AND sent.attempts=batch.origin_attempt)
        IS NOT TRUE THEN 0
      ELSE (${role}) END)`,
    bindings: [policy.botId, policy.adminId, policy.memberId] };
}

function generalJobAuthorization(scope: GeneralProviderAuthority, alias: "job" | "active", forRetirement: boolean): Guard {
  // Job authority is independent of the shorter ordinary outbox reply clock.
  const epoch = forRetirement ? `(${generalRecordedOriginSql("inbox")}) AND ${GENERAL_POLICY_SCHEMA} AND ${GENERAL_RECEIPT_SCHEMA}
    AND EXISTS (SELECT 1 FROM telegram_general_actors AS original
      WHERE original.bot_id=inbox.bot_id AND original.actor_id=inbox.actor_id AND original.generation=recorded.generation
        AND original.revision=recorded.actor_revision AND original.role=recorded.actor_role
        AND original.effective_at<inbox.message_date AND recorded.cutover_at<inbox.message_date)`
    : generalCurrentAuthoritySql("inbox");
  return { sql: `EXISTS (SELECT 1 FROM telegram_provider_requests AS origin
    JOIN telegram_inbox AS inbox USING (receipt_id) JOIN telegram_general_receipt AS recorded USING (receipt_id)
    WHERE (origin.job_id=${alias}.job_id AND origin.kind=${alias}.kind AND origin.outcome='admitted'
      AND inbox.actor_id=${alias}.owner_id AND origin.actor_role=recorded.actor_role
      AND origin.auth_message_date=0 AND origin.auth_message_id=0)
      AND (inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
        AND inbox.command='help' AND inbox.receipt_nonce='${GENERAL_TELEGRAM_PROVIDER_MARKER}')
      AND (${GENERAL_PROVIDER_SCHEMA}) AND (${epoch}))`, bindings: generalPolicyBindings(scope) };
}

function scopeAuthorization(scope: JobScope, alias: "job" | "active" = "job", forRetirement = false): Guard {
  if (scope === "generic") return { sql: "1", bindings: [] };
  if ("family" in scope) return generalJobAuthorization(scope, alias, forRetirement);
  if (scope.queue === "batch") {
    const origin = telegramProviderBatchOrigin(scope, forRetirement);
    return { sql: `EXISTS (SELECT 1 FROM telegram_provider_batches AS batch WHERE batch.batch_id=${alias}.batch_id
      AND batch.actor_id=${alias}.owner_id AND batch.finished_at IS NULL AND batch.expires_at=${alias}.expires_at
      AND ${alias}.kind='refresh' AND (${origin.sql}))`, bindings: origin.bindings };
  }
  const epoch = isolatedTelegramRoleEpochSql(scope, "inbox", forRetirement ? "recorded" : "current");
  const direct = { sql: `EXISTS (SELECT 1 FROM telegram_provider_requests AS origin
    JOIN telegram_inbox AS inbox USING (receipt_id) WHERE origin.job_id = ${alias}.job_id AND origin.outcome = 'admitted'
      AND origin.kind = ${alias}.kind AND inbox.bot_id = ? AND inbox.actor_id = ${alias}.owner_id
      AND inbox.chat_id = inbox.actor_id AND inbox.chat_type = 'private' AND inbox.thread_id IS NULL
      AND inbox.command = 'help' AND inbox.receipt_nonce = '${TELEGRAM_PROVIDER_MARKER}'
      AND ${epoch.sql})`,
    bindings: [scope.botId, ...epoch.bindings] };
  if (!scope.includeDocuments) return direct;
  const document = providerDocumentOrigin(scope, forRetirement ? "recorded" : "current");
  return { sql: `(${direct.sql} OR EXISTS (
    SELECT 1 FROM telegram_provider_document_lines AS line
    JOIN telegram_provider_documents AS origin USING (receipt_id) JOIN telegram_inbox AS inbox USING (receipt_id)
    WHERE line.job_id=${alias}.job_id AND line.result_code IS NULL AND origin.finished_at IS NULL
      AND line.subscription_id=${alias}.subscription_id AND line.source_sha256=${alias}.source_sha256
      AND line.expected_generation=${alias}.expected_generation
      AND line.expected_lifecycle_revision=${alias}.expected_lifecycle_revision
      AND origin.actor_id=${alias}.owner_id AND ${alias}.kind='refresh'
      ${forRetirement ? "" : "AND origin.expires_at>unixepoch()"} AND (${document.sql})
  ))`, bindings: [...direct.bindings, ...document.bindings] };
}

function jobScope(policy?: ProviderQueuePolicy, includeBatch = false, queue?: "batch"): JobScope {
  if (!policy) {
    if (includeBatch || queue) throw new Error("Invalid provider authorization policy.");
    return "generic";
  }
  if ("family" in policy) {
    const { botId, generation, releaseRevision, activationSha256, cutoverAt } = policy;
    checkOwnerId(botId);
    if (policy.family !== "general" || includeBatch || queue || !validInteger(generation, 1) || !validInteger(cutoverAt, 1)
      || typeof releaseRevision !== "string" || !REVISION.test(releaseRevision)
      || typeof activationSha256 !== "string" || !SHA256.test(activationSha256)) {
      throw new Error("Invalid provider authorization policy.");
    }
    return Object.freeze({ family: "general" as const, botId, generation, releaseRevision, activationSha256, cutoverAt });
  }
  const { botId, adminId, memberId } = policy;
  [botId, adminId, memberId].forEach(checkOwnerId);
  if (new Set([botId, adminId, memberId]).size !== 3) throw new Error("Invalid provider authorization policy.");
  return Object.freeze({ botId, adminId, memberId, ...(includeBatch ? { includeBatch: true as const } : {}),
    ...(policy.includeDocuments ? { includeDocuments: true as const } : {}),
    ...(queue ? { queue } : {}) });
}

function validateClaim(row: ClaimedRow): void {
  validateKey(row);
  if (!validInteger(row.jobId, 1) || !validInteger(row.id, 1) ||
      !validInteger(row.expectedGeneration, 0, Number.MAX_SAFE_INTEGER - 1) ||
      !validInteger(row.expectedLifecycleRevision, 0) ||
      (row.kind !== "url-import" && row.kind !== "refresh") ||
      typeof row.sourceSha256 !== "string" || !SHA256.test(row.sourceSha256) ||
      typeof row.leaseId !== "string" || !UUID.test(row.leaseId) ||
      !validInteger(row.expiresAt, 1) || !validInteger(row.leaseUntil, 1, row.expiresAt) ||
      !validInteger(row.attempts, 1, MAX_ATTEMPTS)) throw new RangeError("Invalid provider job lease.");
}

function leaseGuard(lease: ClaimedRow, scope: JobScope, forRetirement = false): Guard {
  const authorization = scopeAuthorization(scope, "job", forRetirement);
  const exact = ["job.job_id = ? AND job.owner_id = ? AND job.request_key = ? AND job.kind = ?",
    "job.subscription_id = ? AND job.source_sha256 = ? AND job.expected_generation = ? AND job.expected_lifecycle_revision = ?",
    "job.state = 'leased' AND job.lease_id = ? AND job.attempts = ? AND job.lease_until = ? AND job.expires_at = ?",
    "job.lease_until > unixepoch() AND job.expires_at > unixepoch()"];
  // Keep the exact lease identity from adding depth to the general grant predicate.
  const fields = scope !== "generic" && "family" in scope ? exact.map((part) => `(${part})`) : exact;
  return {
    sql: `EXISTS (SELECT 1 FROM ${jobTable(scope)} AS job
      WHERE ${fields.join(" AND ")} AND (${authorization.sql}))`,
    bindings: [lease.jobId, lease.ownerId, lease.requestKey, lease.kind, lease.id, lease.sourceSha256,
      lease.expectedGeneration, lease.expectedLifecycleRevision, lease.leaseId, lease.attempts,
      lease.leaseUntil, lease.expiresAt, ...authorization.bindings],
  };
}

function exactTarget(lease: ProviderJobLease, snapshotId?: string): Guard {
  const generation = lease.expectedGeneration + (snapshotId === undefined ? 0 : 1);
  return {
    sql: `EXISTS (SELECT 1 FROM subscriptions WHERE id = ? AND owner_id = ? AND source_url = ?
      AND generation = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?
      ${snapshotId === undefined ? "" : "AND snapshot_id = ?"})`,
    bindings: [lease.id, lease.ownerId, lease.sourceUrl, generation, lease.expectedLifecycleRevision,
      ...(snapshotId === undefined ? [] : [snapshotId])],
  };
}

/** Add this guard to the SQL statement that publishes a provider result. */
export function prepareProviderJobLeaseGuard(lease: ProviderJobLease): Guard {
  validateClaim(lease);
  if (!providerHost(lease.sourceUrl)) throw new RangeError("Invalid provider job lease.");
  const live = leaseGuard(lease, lease.scope);
  const target = exactTarget(lease);
  return { sql: `${live.sql} AND ${target.sql}`, bindings: [...live.bindings, ...target.bindings] };
}

export async function isProviderJobCurrent(db: D1Database, lease: ProviderJobLease): Promise<boolean> {
  const guard = prepareProviderJobLeaseGuard(lease);
  try {
    return await db.prepare(`SELECT CASE WHEN ${guard.sql} THEN 1 ELSE 0 END AS current`)
      .bind(...guard.bindings).first<number>("current") === 1;
  } catch {
    throw new Error("Provider publication target could not be verified.");
  }
}

function terminalJobs(db: D1Database, scope: JobScope, includeWaiting = false): D1PreparedStatement {
  const table = jobTable(scope);
  const visible = scopeAuthorization(scope, "job", true);
  const authorized = scopeAuthorization(scope);
  const unsettled = includeWaiting ? "state IN ('waiting', 'pending', 'leased')" : liveState;
  return db.prepare(`
    WITH terminal AS ${scope !== "generic" && scope.queue === "batch" ? "MATERIALIZED " : ""}(
      SELECT job.job_id, CASE
        WHEN job.expires_at <= unixepoch() THEN 'expired'
        WHEN NOT (${currentTarget} AND ${authorized.sql}) THEN 'stale-target'
        WHEN job.attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted'
      END AS result_code
      FROM ${table} AS job WHERE job.${unsettled} AND (${visible.sql})
        AND (job.state = 'pending' OR (job.state='leased' AND job.lease_until <= unixepoch())
          ${includeWaiting ? "OR job.state='waiting'" : ""})
    )
    UPDATE ${table} SET state = 'done', result_code = terminal.result_code,
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL
    FROM terminal WHERE ${table}.job_id = terminal.job_id AND terminal.result_code IS NOT NULL
  `).bind(...authorized.bindings, ...visible.bindings);
}

/** Prepare a sweep and at most one quota-checked promotion for the Telegram family. */
export function prepareTelegramProviderBatchQueue(db: D1Database, policy: ProviderTelegramPolicy, promote: boolean): D1PreparedStatement[] {
  const scope = jobScope(policy, true, "batch");
  const steps = [terminalJobs(db, scope, true)];
  if (promote) {
    const authorized = scopeAuthorization(scope);
    steps.push(db.prepare(`UPDATE telegram_provider_batch_jobs SET state='pending',due_at=unixepoch()
      WHERE job_id=(SELECT job.job_id FROM telegram_provider_batch_jobs AS job JOIN telegram_provider_batches AS batch USING(batch_id)
        WHERE job.state IN ('waiting', 'pending', 'leased') AND job.state='waiting'
          AND job.expires_at>unixepoch() AND ${currentTarget} AND (${authorized.sql})
          AND ${jobCapacity("job.owner_id", scope)}
          AND NOT EXISTS (SELECT 1 FROM (${activeJobs(scope)}) AS active
            WHERE active.owner_id=job.owner_id AND active.subscription_id=job.subscription_id)
        ORDER BY batch.created_at,batch.batch_id,job.ordinal LIMIT 1)`).bind(...authorized.bindings));
  }
  return steps;
}

function claimCandidates(scopes: readonly JobScope[]): Guard {
  const noLease = scopes.map((scope) => `NOT EXISTS (SELECT 1 FROM ${jobTable(scope)} WHERE state='leased')`).join(" AND ");
  const noLiveLease = scopes.map((scope) =>
    `NOT EXISTS (SELECT 1 FROM ${jobTable(scope)} WHERE state='leased' AND lease_until>unixepoch())`).join(" AND ");
  const bindings: Binding[] = [];
  const candidates = scopes.map((scope) => {
    const table = jobTable(scope);
    const authorized = scopeAuthorization(scope);
    bindings.push(...authorized.bindings);
    return `SELECT '${table}' AS queue,job.job_id,job.due_at FROM ${table} AS job
      WHERE job.${liveState} AND job.expires_at>unixepoch() AND job.attempts<${MAX_ATTEMPTS}
        AND ${currentTarget} AND (${authorized.sql}) AND ${noLiveLease}
        AND ((job.state='leased' AND job.lease_until<=unixepoch())
          OR (job.state='pending' AND job.due_at<=unixepoch() AND ${noLease}))`;
  });
  return { sql: `${candidates.join(" UNION ALL ")} ORDER BY due_at,queue,job_id LIMIT 1`, bindings };
}

/** Include batch scope on every Telegram-family admission and claim while batch work can be live. */
export async function claimProviderJob(db: D1Database, policy?: ProviderQueuePolicy, includeBatch = false): Promise<ProviderJobLease | null> {
  try {
    const single = jobScope(policy, includeBatch);
    const scopes = includeBatch ? [single, jobScope(policy, true, "batch")] : [single];
    const leaseId = crypto.randomUUID();
    const candidates = claimCandidates(scopes);
    const steps = [...scopes.map((scope) => terminalJobs(db, scope)), ...scopes.map((scope) => {
      const table = jobTable(scope);
      return db.prepare(`
        UPDATE ${table} SET state = 'leased', attempts = attempts + 1, lease_id = ?,
          lease_until = min(unixepoch() + ${LEASE_SECONDS}, expires_at)
        WHERE job_id = (SELECT job_id FROM (${candidates.sql}) WHERE queue='${table}')
        RETURNING job_id AS jobId, subscription_id AS id, owner_id AS ownerId, kind, request_key AS requestKey,
          expected_generation AS expectedGeneration, expected_lifecycle_revision AS expectedLifecycleRevision,
          source_sha256 AS sourceSha256, lease_id AS leaseId, lease_until AS leaseUntil, expires_at AS expiresAt, attempts
      `).bind(leaseId, ...candidates.bindings);
    })];
    const results = await db.batch<ClaimedRow>(steps);
    if (results.length !== steps.length || results.some(({ success }) => !success)) {
      throw new Error("Provider job claim could not be confirmed.");
    }
    const claimed = scopes.flatMap((scope, index) => results[scopes.length + index].results.map((lease) => ({ scope, lease })));
    if (claimed.length === 0) return null;
    if (claimed.length !== 1) throw new Error("Provider job claim could not be confirmed.");
    const [{ scope, lease }] = claimed;
    const table = jobTable(scope);
    validateClaim(lease);
    if (lease.leaseId !== leaseId) throw new Error("Provider job claim could not be confirmed.");
    const live = leaseGuard(lease, scope);
    const sourceTarget = "id = ? AND owner_id = ? AND generation = ?";
    const sourceBindings = [lease.id, lease.ownerId, lease.expectedGeneration, lease.expectedLifecycleRevision];
    const source = scope !== "generic" && "family" in scope
      ? db.prepare(`WITH lease_authority AS MATERIALIZED (SELECT (${live.sql}) AS allowed)
        SELECT source_url FROM subscriptions CROSS JOIN lease_authority
        WHERE (${sourceTarget} AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?) AND lease_authority.allowed`)
        .bind(...live.bindings, ...sourceBindings)
      : db.prepare(`SELECT source_url FROM subscriptions WHERE ${sourceTarget}
        AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ? AND ${live.sql}`).bind(...sourceBindings, ...live.bindings);
    const sourceUrl = await source.first<string>("source_url");
    if (sourceUrl !== null && providerHost(sourceUrl) && await providerSourceDigest(sourceUrl) === lease.sourceSha256) {
      return Object.freeze({ ...lease, sourceUrl, scope });
    }
    const retire = leaseGuard(lease, scope, true);
    const retired = await db.prepare(`UPDATE ${table} SET state = 'done', result_code = 'stale-target',
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL WHERE job_id = ? AND ${retire.sql}`)
      .bind(lease.jobId, ...retire.bindings).run();
    if (!retired.success) throw new Error("Provider job claim could not be confirmed.");
    return null;
  } catch {
    throw new Error("Provider job claim could not be confirmed.");
  }
}

/** Require both the guarded publication and saved settlement to affect one row in the same D1 batch. */
export function prepareProviderJobSettlement(
  db: D1Database, lease: ProviderJobLease, outcome: ProviderJobOutcome, afterPublication = false,
): D1PreparedStatement {
  validateClaim(lease);
  if (!providerHost(lease.sourceUrl)) throw new RangeError("Invalid provider job lease.");
  const table = providerJobLeaseTable(lease);
  const live = leaseGuard(lease, lease.scope, outcome.kind !== "saved");
  if (outcome.kind === "saved") {
    if (typeof outcome.snapshotId !== "string" || !UUID.test(outcome.snapshotId)) {
      throw new RangeError("Invalid provider snapshot identity.");
    }
    const published = exactTarget(lease, outcome.snapshotId);
    return db.prepare(`UPDATE ${table} SET state = 'done', result_code = 'saved',
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL, failure_code = NULL
      WHERE job_id = ? AND ${live.sql} AND ${published.sql} ${afterPublication ? "AND changes() = 1" : ""}
      RETURNING state, result_code AS resultCode`).bind(lease.jobId, ...live.bindings, ...published.bindings);
  }
  const failure = outcome.kind === "failed" && ["invalid-document", "fetch-rejected", "storage-failed"].includes(outcome.reason);
  const retry = outcome.kind === "retry" &&
    ["busy", "timeout", "dns-failed", "unavailable", "upstream-retryable", "storage-failed"].includes(outcome.reason);
  if (!failure && !retry) throw new RangeError("Invalid provider job outcome.");
  const current = exactTarget(lease);
  const authorized = scopeAuthorization(lease.scope);
  const nextDue = "(unixepoch() + CASE attempts WHEN 1 THEN 60 ELSE 180 END)";
  const decision = retry
    ? `WHEN attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted' WHEN ${nextDue} >= expires_at THEN 'expired'`
    : "ELSE ?";
  return db.prepare(`
    WITH decision AS (
      SELECT job.job_id, ${nextDue} AS next_due, CASE WHEN NOT (${current.sql} AND ${authorized.sql}) THEN 'stale-target' ${decision} END AS code
      FROM ${table} AS job WHERE job.job_id = ? AND ${live.sql}
    )
    UPDATE ${table} SET state = CASE WHEN decision.code IS NULL THEN 'pending' ELSE 'done' END,
      due_at = CASE WHEN decision.code IS NULL THEN decision.next_due ELSE due_at END,
      lease_id = NULL, lease_until = NULL, failure_code = ?, result_code = decision.code,
      finished_at = CASE WHEN decision.code IS NOT NULL THEN unixepoch() END
    FROM decision WHERE ${table}.job_id = decision.job_id
    RETURNING state, result_code AS resultCode
  `).bind(...current.bindings, ...authorized.bindings, ...(retry ? [] : [outcome.reason]), lease.jobId, ...live.bindings, outcome.reason);
}

export async function settleProviderJob(
  db: D1Database, lease: ProviderJobLease, outcome: ProviderFailureOutcome,
): Promise<"retry" | "done" | "stale"> {
  if (outcome.kind !== "failed" && outcome.kind !== "retry") throw new RangeError("Invalid provider job outcome.");
  try {
    const settlement = prepareProviderJobSettlement(db, lease, outcome);
    let row: SettlementRow | null;
    if (lease.scope !== "generic") {
      const authorized = scopeAuthorization(lease.scope);
      const table = providerJobLeaseTable(lease);
      const [result, metadata] = await db.batch<SettlementRow>([settlement, db.prepare(`
        UPDATE subscriptions SET last_error = 'provider-refresh-failed'
        WHERE id = ? AND owner_id = ? AND source_url = ? AND generation = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?
          AND changes() = 1 AND EXISTS (SELECT 1 FROM ${table} AS job
            WHERE job.job_id = ? AND job.owner_id = subscriptions.owner_id AND job.request_key = ?
              AND job.state = 'done' AND job.result_code IN ('fetch-rejected','invalid-document','storage-failed','attempts-exhausted')
              AND (${authorized.sql}))`)
        .bind(lease.id, lease.ownerId, lease.sourceUrl, lease.expectedGeneration, lease.expectedLifecycleRevision,
          lease.jobId, lease.requestKey, ...authorized.bindings)]);
      if (!result?.success || !metadata?.success || result.results.length > 1) throw new Error();
      row = result.results[0] ?? null;
    } else {
      row = await settlement.first<SettlementRow>();
    }
    if (row?.resultCode === "stale-target" && lease.scope !== "generic") return "stale";
    return row === null ? "stale" : row.state === "pending" ? "retry" : "done";
  } catch {
    throw new Error("Provider job settlement could not be confirmed.");
  }
}

/** Release a live lease whose owned source or publication version changed. */
export async function retireStaleProviderJob(db: D1Database, lease: ProviderJobLease): Promise<void> {
  validateClaim(lease);
  if (!providerHost(lease.sourceUrl)) throw new RangeError("Invalid provider job lease.");
  const live = leaseGuard(lease, lease.scope, true);
  const target = exactTarget(lease);
  const authorized = scopeAuthorization(lease.scope);
  try {
    const result = await db.prepare(`UPDATE ${providerJobLeaseTable(lease)} AS job SET state = 'done', result_code = 'stale-target',
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL, failure_code = NULL
      WHERE job.job_id = ? AND ${live.sql} AND NOT (${target.sql} AND ${authorized.sql})`)
      .bind(lease.jobId, ...live.bindings, ...target.bindings, ...authorized.bindings).run();
    if (!result.success || ![0, 1].includes(result.meta.changes)) throw new Error();
  } catch {
    throw new Error("Stale provider job retirement could not be confirmed.");
  }
}

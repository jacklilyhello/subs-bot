import { checkOwnerId, digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "./storage.ts";
import { normalizeSubscriptionName } from "./subscriptions.ts";

const TTL_SECONDS = 3600;
const LEASE_SECONDS = 120;
const MAX_ATTEMPTS = 3;
const MAX_OWNER_JOBS = 4;
const MAX_GLOBAL_JOBS = 8;
const MAX_OWNER_SOURCES = 100;
const TRASH_SECONDS = 2_592_000;
const MAX_URL_BYTES = 8192;
const SHA256 = /^[0-9a-f]{64}(?![\s\S])/u;
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/u;
const encoder = new TextEncoder();

type AdmissionKey = { ownerId: string; requestKey: string };
type UrlImport = AdmissionKey & { sourceUrl: string; name?: string };
type Refresh = AdmissionKey & { id: number };

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
}

type TerminalFailure = "invalid-document" | "fetch-rejected" | "storage-failed";
type RetryFailure = "busy" | "timeout" | "dns-failed" | "unavailable" | "upstream-retryable" | "storage-failed";
export type ProviderFailureOutcome = { kind: "retry"; reason: RetryFailure } | { kind: "failed"; reason: TerminalFailure };
type ProviderJobOutcome = ProviderFailureOutcome | { kind: "saved"; snapshotId: string };
type Binding = string | number;
type Guard = { sql: string; bindings: readonly Binding[] };
type Receipt = {
  jobId: number; subscriptionId: number; kind: ProviderJobLease["kind"]; sourceSha256: string;
  resultCode: string | null;
};
type AdmissionRow = Partial<Receipt> & { refused?: "capacity" | "unavailable" | "conflict" };
type ClaimedRow = Omit<ProviderJobLease, "sourceUrl">;

const receiptFields = `job_id AS jobId, subscription_id AS subscriptionId, kind,
  source_sha256 AS sourceSha256, result_code AS resultCode`;
const liveState = "state IN ('pending', 'leased')";
const activeJob = `EXISTS (SELECT 1 FROM subscription_provider_jobs AS active
  WHERE active.owner_id = target.owner_id AND active.subscription_id = target.id AND active.${liveState})`;
const sameJob = `EXISTS (SELECT 1 FROM subscription_provider_jobs AS active
  WHERE active.owner_id = target.owner_id AND active.subscription_id = target.id AND active.${liveState}
    AND active.source_sha256 = ? AND active.expected_generation = target.generation
    AND active.expected_lifecycle_revision = target.lifecycle_revision)`;

function jobCapacity(owner: string): string {
  return `NOT EXISTS (SELECT 1 FROM subscription_provider_jobs AS active WHERE active.owner_id = ${owner}
    AND active.${liveState} LIMIT 1 OFFSET ${MAX_OWNER_JOBS - 1})
    AND NOT EXISTS (SELECT 1 FROM subscription_provider_jobs WHERE ${liveState} LIMIT 1 OFFSET ${MAX_GLOBAL_JOBS - 1})`;
}

function validateKey({ ownerId, requestKey }: AdmissionKey): void {
  checkOwnerId(ownerId);
  if (typeof requestKey !== "string" || !SHA256.test(requestKey)) throw new RangeError("Invalid provider job request.");
}

function providerHost(value: unknown): string | null {
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

async function sourceDigest(sourceUrl: string): Promise<string> {
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
  db: D1Database, key: AdmissionKey, kind: ProviderJobLease["kind"], target: Guard, digest: string,
): D1PreparedStatement {
  return db.prepare(`
    WITH candidates AS (
      SELECT subscriptions.id, subscriptions.owner_id, subscriptions.generation,
        ${SUBSCRIPTION_LIFECYCLE_REVISION} AS lifecycle_revision
      FROM subscriptions WHERE ${target.sql} LIMIT 2
    ), classified AS (
      SELECT target.*, ${sameJob} AS coalesced
      FROM candidates AS target WHERE (SELECT count(*) FROM candidates) = 1
        AND target.generation < 9007199254740991
        AND NOT EXISTS (SELECT 1 FROM subscription_provider_jobs WHERE owner_id = target.owner_id AND request_key = ?)
        AND (${sameJob} OR (NOT ${activeJob} AND ${jobCapacity("target.owner_id")}))
    )
    INSERT INTO subscription_provider_jobs
      (owner_id, request_key, kind, subscription_id, source_sha256, expected_generation, expected_lifecycle_revision,
       state, created_at, due_at, expires_at, result_code, finished_at)
    SELECT owner_id, ?, ?, id, ?, generation, lifecycle_revision, CASE WHEN coalesced THEN 'done' ELSE 'pending' END,
      unixepoch(), unixepoch(), unixepoch() + ${TTL_SECONDS}, CASE WHEN coalesced THEN 'coalesced' END,
      CASE WHEN coalesced THEN unixepoch() END FROM classified WHERE 1
    ON CONFLICT (owner_id, request_key) DO NOTHING
    RETURNING ${receiptFields}
  `).bind(...target.bindings, digest, key.requestKey, digest, key.requestKey, kind, digest);
}

async function admit(
  db: D1Database, key: AdmissionKey, kind: ProviderJobLease["kind"], target: Guard, digest: string,
  originTarget: number | string, refusal: D1PreparedStatement, create?: { sourceUrl: string; name: string },
): Promise<ProviderAdmission> {
  const steps: D1PreparedStatement[] = [];
  const token = create ? crypto.randomUUID().replaceAll("-", "") : null;
  if (create && token) {
    steps.push(db.prepare(`
      INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at)
      SELECT ?, ?, ?, ?, unixepoch(), unixepoch()
      WHERE NOT EXISTS (SELECT 1 FROM subscription_provider_jobs WHERE owner_id = ? AND request_key = ?)
        AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id = ? AND source_url = ?)
        AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE owner_id = ? AND source_url = ?
          AND deleted_at >= unixepoch() - ${TRASH_SECONDS})
        AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE token = ?)
        AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id = ?
          AND (lower(substr(source_url, 1, 7)) = 'http://' OR lower(substr(source_url, 1, 8)) = 'https://')
          LIMIT 1 OFFSET ${MAX_OWNER_SOURCES - 1})
        AND ${jobCapacity("?")}
    `).bind(key.ownerId, create.name, create.sourceUrl, token, key.ownerId, key.requestKey,
      key.ownerId, create.sourceUrl, key.ownerId, create.sourceUrl, token, key.ownerId, key.ownerId));
  }
  const insertIndex = steps.length;
  steps.push(prepareAdmission(db, key, kind, target, digest));
  if (token) {
    // A new shell and its job must either both commit or both roll back.
    steps.push(db.prepare(`
      SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM subscriptions WHERE token = ?)
        OR EXISTS (SELECT 1 FROM subscription_provider_jobs AS job JOIN subscriptions AS sub ON sub.id = job.subscription_id
          WHERE sub.token = ? AND job.owner_id = ? AND job.request_key = ? AND job.state = 'pending')
        THEN 1 ELSE json_extract('provider admission guard failed', '$') END
    `).bind(token, token, key.ownerId, key.requestKey));
  }
  steps.push(db.prepare(`SELECT ${receiptFields} FROM subscription_provider_jobs WHERE owner_id = ? AND request_key = ?`)
    .bind(key.ownerId, key.requestKey), refusal);
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

/** Internal admission for an already authorized owner. No network request occurs here. */
export async function enqueueProviderUrlImport(db: D1Database, input: UrlImport): Promise<ProviderAdmission> {
  validateKey(input);
  const host = providerHost(input.sourceUrl);
  if (!host) throw new RangeError("Invalid provider source URL.");
  const name = normalizeSubscriptionName(input.name ?? Array.from(host).slice(0, 64).join(""));
  try {
    const digest = await sourceDigest(input.sourceUrl);
    const target = { sql: "subscriptions.owner_id = ? AND subscriptions.source_url = ?",
      bindings: [input.ownerId, input.sourceUrl] };
    const refusal = db.prepare(`
      SELECT CASE WHEN (SELECT count(*) FROM (SELECT 1 FROM subscriptions WHERE ${target.sql} LIMIT 2)) > 1
        THEN 'conflict' WHEN NOT EXISTS (SELECT 1 FROM subscriptions WHERE ${target.sql}) AND EXISTS (
          SELECT 1 FROM subscription_trash WHERE owner_id = ? AND source_url = ? AND deleted_at >= unixepoch() - ${TRASH_SECONDS}
        ) THEN 'unavailable' ELSE 'capacity' END AS refused
    `).bind(...target.bindings, ...target.bindings, input.ownerId, input.sourceUrl);
    return await admit(db, input, "url-import", target, digest, digest, refusal, { sourceUrl: input.sourceUrl, name });
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
    const target = ownedSource(input.ownerId, input.id);
    const sourceUrl = await db.prepare(`SELECT source_url FROM subscriptions WHERE ${target.sql}`)
      .bind(...target.bindings).first<string>("source_url");
    if (sourceUrl === null || !providerHost(sourceUrl)) return { kind: "unavailable" };
    const exact = ownedSource(input.ownerId, input.id, sourceUrl);
    const refusal = db.prepare(`SELECT CASE WHEN EXISTS (SELECT 1 FROM subscriptions WHERE ${exact.sql})
      THEN 'capacity' ELSE 'unavailable' END AS refused`).bind(...exact.bindings);
    return await admit(db, input, "refresh", exact, await sourceDigest(sourceUrl), input.id, refusal);
  } catch {
    throw new Error("Provider refresh admission could not be confirmed.");
  }
}

const currentTarget = `EXISTS (
  SELECT 1 FROM subscriptions WHERE subscriptions.id = job.subscription_id AND subscriptions.owner_id = job.owner_id
    AND subscriptions.generation = job.expected_generation
    AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = job.expected_lifecycle_revision
)`;

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

function leaseGuard(lease: ClaimedRow): Guard {
  return {
    sql: `EXISTS (SELECT 1 FROM subscription_provider_jobs AS job
      WHERE job.job_id = ? AND job.owner_id = ? AND job.request_key = ? AND job.kind = ?
        AND job.subscription_id = ? AND job.source_sha256 = ? AND job.expected_generation = ?
        AND job.expected_lifecycle_revision = ? AND job.state = 'leased'
        AND job.lease_id = ? AND job.attempts = ? AND job.lease_until = ? AND job.expires_at = ?
        AND job.lease_until > unixepoch() AND job.expires_at > unixepoch())`,
    bindings: [lease.jobId, lease.ownerId, lease.requestKey, lease.kind, lease.id, lease.sourceSha256,
      lease.expectedGeneration, lease.expectedLifecycleRevision, lease.leaseId, lease.attempts,
      lease.leaseUntil, lease.expiresAt],
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
  const live = leaseGuard(lease);
  const target = exactTarget(lease);
  return { sql: `${live.sql} AND ${target.sql}`, bindings: [...live.bindings, ...target.bindings] };
}

/** Claim at most one current job globally and read its exact private source. */
export async function claimProviderJob(db: D1Database): Promise<ProviderJobLease | null> {
  try {
    const leaseId = crypto.randomUUID();
    const steps = [
      db.prepare(`
        WITH terminal AS (
          SELECT job.job_id, CASE
            WHEN job.expires_at <= unixepoch() THEN 'expired'
            WHEN NOT ${currentTarget} THEN 'stale-target'
            WHEN job.attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted'
          END AS result_code
          FROM subscription_provider_jobs AS job WHERE job.${liveState}
            AND (job.state = 'pending' OR job.lease_until <= unixepoch())
        )
        UPDATE subscription_provider_jobs SET state = 'done', result_code = terminal.result_code,
          finished_at = unixepoch(), lease_id = NULL, lease_until = NULL
        FROM terminal WHERE subscription_provider_jobs.job_id = terminal.job_id AND terminal.result_code IS NOT NULL
      `),
      db.prepare(`
        UPDATE subscription_provider_jobs SET state = 'leased', attempts = attempts + 1, lease_id = ?,
          lease_until = min(unixepoch() + ${LEASE_SECONDS}, expires_at)
        WHERE job_id = (
          SELECT job.job_id FROM subscription_provider_jobs AS job
          WHERE job.expires_at > unixepoch() AND job.attempts < ${MAX_ATTEMPTS}
            AND ${currentTarget}
            AND ((job.state = 'leased' AND job.lease_until <= unixepoch()) OR
              (job.state = 'pending' AND job.due_at <= unixepoch()
                AND NOT EXISTS (SELECT 1 FROM subscription_provider_jobs WHERE state = 'leased')))
          ORDER BY job.due_at, job.job_id LIMIT 1
        )
        RETURNING job_id AS jobId, subscription_id AS id, owner_id AS ownerId, kind, request_key AS requestKey,
          expected_generation AS expectedGeneration, expected_lifecycle_revision AS expectedLifecycleRevision,
          source_sha256 AS sourceSha256, lease_id AS leaseId, lease_until AS leaseUntil, expires_at AS expiresAt, attempts
      `).bind(leaseId),
    ];
    const results = await db.batch<ClaimedRow>(steps);
    if (results.length !== steps.length || results.some(({ success }) => !success) || results[1].results.length > 1) {
      throw new Error("Provider job claim could not be confirmed.");
    }
    const lease = results[1].results[0];
    if (!lease) return null;
    validateClaim(lease);
    if (lease.leaseId !== leaseId) throw new Error("Provider job claim could not be confirmed.");
    const live = leaseGuard(lease);
    const sourceUrl = await db.prepare(`SELECT source_url FROM subscriptions WHERE id = ? AND owner_id = ?
      AND generation = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ? AND ${live.sql}`)
      .bind(lease.id, lease.ownerId, lease.expectedGeneration, lease.expectedLifecycleRevision, ...live.bindings)
      .first<string>("source_url");
    if (sourceUrl !== null && providerHost(sourceUrl) && await sourceDigest(sourceUrl) === lease.sourceSha256) {
      return Object.freeze({ ...lease, sourceUrl });
    }
    const retired = await db.prepare(`UPDATE subscription_provider_jobs SET state = 'done', result_code = 'stale-target',
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL WHERE job_id = ? AND ${live.sql}`)
      .bind(lease.jobId, ...live.bindings).run();
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
  const live = leaseGuard(lease);
  if (outcome.kind === "saved") {
    if (typeof outcome.snapshotId !== "string" || !UUID.test(outcome.snapshotId)) {
      throw new RangeError("Invalid provider snapshot identity.");
    }
    const published = exactTarget(lease, outcome.snapshotId);
    return db.prepare(`UPDATE subscription_provider_jobs SET state = 'done', result_code = 'saved',
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL, failure_code = NULL
      WHERE job_id = ? AND ${live.sql} AND ${published.sql} ${afterPublication ? "AND changes() = 1" : ""}
      RETURNING state, result_code AS resultCode`).bind(lease.jobId, ...live.bindings, ...published.bindings);
  }
  const failure = outcome.kind === "failed" && ["invalid-document", "fetch-rejected", "storage-failed"].includes(outcome.reason);
  const retry = outcome.kind === "retry" &&
    ["busy", "timeout", "dns-failed", "unavailable", "upstream-retryable", "storage-failed"].includes(outcome.reason);
  if (!failure && !retry) throw new RangeError("Invalid provider job outcome.");
  const current = exactTarget(lease);
  const nextDue = "(unixepoch() + CASE attempts WHEN 1 THEN 60 ELSE 180 END)";
  const decision = retry
    ? `WHEN attempts >= ${MAX_ATTEMPTS} THEN 'attempts-exhausted' WHEN ${nextDue} >= expires_at THEN 'expired'`
    : "ELSE ?";
  return db.prepare(`
    WITH decision AS (
      SELECT job_id, ${nextDue} AS next_due, CASE WHEN NOT ${current.sql} THEN 'stale-target' ${decision} END AS code
      FROM subscription_provider_jobs WHERE job_id = ? AND ${live.sql}
    )
    UPDATE subscription_provider_jobs SET state = CASE WHEN decision.code IS NULL THEN 'pending' ELSE 'done' END,
      due_at = CASE WHEN decision.code IS NULL THEN decision.next_due ELSE due_at END,
      lease_id = NULL, lease_until = NULL, failure_code = ?, result_code = decision.code,
      finished_at = CASE WHEN decision.code IS NOT NULL THEN unixepoch() END
    FROM decision WHERE subscription_provider_jobs.job_id = decision.job_id
    RETURNING state, result_code AS resultCode
  `).bind(...current.bindings, ...(retry ? [] : [outcome.reason]), lease.jobId, ...live.bindings, outcome.reason);
}

export async function settleProviderJob(
  db: D1Database, lease: ProviderJobLease, outcome: ProviderFailureOutcome,
): Promise<"retry" | "done" | "stale"> {
  if (outcome.kind !== "failed" && outcome.kind !== "retry") throw new RangeError("Invalid provider job outcome.");
  try {
    const row = await prepareProviderJobSettlement(db, lease, outcome).first<{ state: "pending" | "done" }>();
    return row === null ? "stale" : row.state === "pending" ? "retry" : "done";
  } catch {
    throw new Error("Provider job settlement could not be confirmed.");
  }
}

/** Release a live lease whose owned source or publication version changed. */
export async function retireStaleProviderJob(db: D1Database, lease: ProviderJobLease): Promise<void> {
  validateClaim(lease);
  if (!providerHost(lease.sourceUrl)) throw new RangeError("Invalid provider job lease.");
  const live = leaseGuard(lease);
  const target = exactTarget(lease);
  try {
    const result = await db.prepare(`UPDATE subscription_provider_jobs SET state = 'done', result_code = 'stale-target',
      finished_at = unixepoch(), lease_id = NULL, lease_until = NULL, failure_code = NULL
      WHERE job_id = ? AND ${live.sql} AND NOT ${target.sql}`)
      .bind(lease.jobId, ...live.bindings, ...target.bindings).run();
    if (!result.success || ![0, 1].includes(result.meta.changes)) throw new Error();
  } catch {
    throw new Error("Stale provider job retirement could not be confirmed.");
  }
}

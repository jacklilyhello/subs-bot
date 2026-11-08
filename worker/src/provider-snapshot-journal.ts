import { prepareProviderJobLeaseGuard, prepareProviderJobSettlement, providerJobLeaseTable, type ProviderJobLease } from "./provider-jobs.ts";
import {
  prepareNodeSnapshotPublication, SNAPSHOT_MANIFEST_ORDINAL, stageNodeSnapshot,
  type NodeRecord, type SnapshotMetadataUpdate, type StagedNodeSnapshot,
} from "./storage.ts";

const identityColumns = `snapshot_id,queue,job_id,job_attempt,subscription_id,owner_id,request_key,source_sha256,
  expected_generation,expected_lifecycle_revision,lease_until,bot_id`;
const identity = `snapshot_id=? AND queue=? AND job_id=? AND job_attempt=? AND subscription_id=? AND owner_id=?
  AND request_key=? AND source_sha256=? AND expected_generation=? AND expected_lifecycle_revision=? AND lease_until=? AND bot_id=?`;
const summary = "manifest_sha256=? AND node_count=? AND object_count=?";
const failure = "Provider snapshot journal could not be verified.";

function attemptBindings(lease: ProviderJobLease): readonly (string | number)[] {
  return [lease.leaseId, providerJobLeaseTable(lease), lease.jobId, lease.attempts, lease.id, lease.ownerId, lease.requestKey,
    lease.sourceSha256, lease.expectedGeneration, lease.expectedLifecycleRevision, lease.leaseUntil,
    lease.scope === "generic" ? "" : lease.scope.botId];
}

export async function providerSnapshotJournalReady(db: D1Database): Promise<boolean> {
  try {
    return await db.prepare(`SELECT count(*) AS present FROM sqlite_schema
      WHERE (type='table' AND name IN ('provider_snapshot_attempts','provider_snapshot_object_intents'))
        OR (type='index' AND name='provider_snapshot_open_leases' AND tbl_name='provider_snapshot_attempts')`)
      .first<number>("present") === 3;
  } catch {
    return false;
  }
}

/** Reserve this lease's prefix, then confirm each exact object intent before its sole conditional PUT. */
export async function stageProviderSnapshot(
  db: D1Database, bucket: R2Bucket, lease: ProviderJobLease, nodes: readonly NodeRecord[],
): Promise<StagedNodeSnapshot | null> {
  try {
    const live = prepareProviderJobLeaseGuard(lease);
    const bindings = attemptBindings(lease);
    const begun = await db.prepare(`INSERT INTO provider_snapshot_attempts (${identityColumns},created_at,state)
      SELECT ?,?,?,?,?,?,?,?,?,?,?,?,unixepoch(),'open' WHERE ${live.sql}`)
      .bind(...bindings, ...live.bindings).run();
    if (!begun.success || ![0, 1].includes(begun.meta.changes)) throw new Error(failure);
    if (begun.meta.changes === 0) return null;
    const staged = await stageNodeSnapshot(bucket, lease.id, nodes, lease.leaseId, async ({ ordinal, bytes, sha256 }) => {
      const intent = await db.prepare(`INSERT INTO provider_snapshot_object_intents (snapshot_id,ordinal,byte_count,sha256)
        SELECT ?,?,?,? WHERE ${live.sql} AND EXISTS (
          SELECT 1 FROM provider_snapshot_attempts WHERE ${identity} AND state='open')`)
        .bind(lease.leaseId, ordinal, bytes, sha256, ...live.bindings, ...bindings).run();
      if (!intent.success || intent.meta.changes !== 1) throw new Error(failure);
    });
    // Each awaited immutable PUT succeeded. The manifest must close the same contiguous intent inventory.
    const sealed = await db.prepare(`UPDATE provider_snapshot_attempts SET state='sealed',manifest_sha256=?,node_count=?,object_count=?
      WHERE ${identity} AND state='open' AND ${live.sql}
        AND (SELECT count(*) FROM provider_snapshot_object_intents WHERE snapshot_id=?)=?
        AND (SELECT max(ordinal) FROM provider_snapshot_object_intents WHERE snapshot_id=? AND ordinal<?)=?
        AND EXISTS (SELECT 1 FROM provider_snapshot_object_intents WHERE snapshot_id=? AND ordinal=? AND sha256=?)`)
      .bind(staged.manifestSha256, staged.nodeCount, staged.objectCount, ...bindings, ...live.bindings,
        lease.leaseId, staged.objectCount, lease.leaseId, SNAPSHOT_MANIFEST_ORDINAL, staged.objectCount - 2,
        lease.leaseId, SNAPSHOT_MANIFEST_ORDINAL, staged.manifestSha256).run();
    if (!sealed.success || ![0, 1].includes(sealed.meta.changes)) throw new Error(failure);
    return sealed.meta.changes === 1 ? staged : null;
  } catch {
    // An unacknowledged intent or PUT remains recorded. No provider candidate is deleted here.
    throw new Error(failure);
  }
}

async function confirmPublished(db: D1Database, lease: ProviderJobLease, bindings: readonly (string | number)[]): Promise<boolean> {
  try {
    return await db.prepare(`SELECT CASE WHEN EXISTS (
      SELECT 1 FROM provider_snapshot_attempts WHERE ${identity} AND ${summary} AND state='published')
      AND EXISTS (SELECT 1 FROM ${providerJobLeaseTable(lease)}
        WHERE job_id=? AND owner_id=? AND request_key=? AND subscription_id=? AND source_sha256=? AND attempts=?
          AND expected_generation=? AND expected_lifecycle_revision=? AND kind=? AND state='done' AND result_code='saved')
      THEN 1 ELSE 0 END AS saved`)
      .bind(...bindings, lease.jobId, lease.ownerId, lease.requestKey, lease.id, lease.sourceSha256, lease.attempts,
        lease.expectedGeneration, lease.expectedLifecycleRevision, lease.kind).first<number>("saved") === 1;
  } catch {
    return false;
  }
}

/** The pointer, job result and permanent publication marker commit together. */
export async function publishProviderSnapshot(
  db: D1Database, lease: ProviderJobLease, staged: StagedNodeSnapshot, metadata: SnapshotMetadataUpdate,
): Promise<"saved" | "stale" | "uncertain"> {
  if (staged.id !== lease.id || staged.snapshotId !== lease.leaseId) throw new Error(failure);
  const bindings = [...attemptBindings(lease), staged.manifestSha256, staged.nodeCount, staged.objectCount];
  try {
    const live = prepareProviderJobLeaseGuard(lease);
    const sealed = `${identity} AND ${summary} AND state='sealed'`;
    const steps = [
      prepareNodeSnapshotPublication(db, lease, staged, {
        sql: `${live.sql} AND EXISTS (SELECT 1 FROM provider_snapshot_attempts WHERE ${sealed})`,
        bindings: [...live.bindings, ...bindings],
      }, metadata),
      prepareProviderJobSettlement(db, lease, { kind: "saved", snapshotId: staged.snapshotId }, true),
      db.prepare(`UPDATE provider_snapshot_attempts SET state='published',published_at=unixepoch()
        WHERE ${sealed} AND changes()=1`).bind(...bindings),
      db.prepare(`SELECT CASE WHEN changes()=1 OR NOT EXISTS (
        SELECT 1 FROM subscriptions WHERE id=? AND snapshot_id=?
        UNION ALL SELECT 1 FROM subscription_trash WHERE id=? AND snapshot_id=?)
        THEN 1 ELSE json_extract('provider publication guard failed', '$') END`)
        .bind(lease.id, staged.snapshotId, lease.id, staged.snapshotId),
      // Published prefixes stay protected by the permanent attempt marker even after supersession.
      db.prepare(`DELETE FROM provider_snapshot_object_intents WHERE snapshot_id=? AND EXISTS (
        SELECT 1 FROM provider_snapshot_attempts WHERE ${identity} AND ${summary} AND state='published')`)
        .bind(lease.leaseId, ...bindings),
    ];
    const results = await db.batch(steps);
    if (results.length === steps.length && results.every(({ success }) => success)) {
      const [publication, settlement, journal, , compacted] = results;
      if (publication.meta.changes === 1 && settlement.meta.changes === 1 && journal.meta.changes === 1
          && compacted.meta.changes === staged.objectCount) return "saved";
      if (publication.meta.changes === 0 && settlement.meta.changes === 0 && journal.meta.changes === 0
          && compacted.meta.changes === 0) return await confirmPublished(db, lease, bindings) ? "saved" : "stale";
    }
  } catch {
    // A lost D1 response may hide a commit even if a newer generation is already active.
  }
  return await confirmPublished(db, lease, bindings) ? "saved" : "uncertain";
}

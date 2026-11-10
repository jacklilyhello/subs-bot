import {
  digestHex, MAX_SNAPSHOT_CHUNKS, prepareNodeSnapshotPublication, stageNodeSnapshot, SUBSCRIPTION_LIFECYCLE_REVISION,
  validInteger, type NodeRecord, type StagedNodeSnapshot,
} from "../storage.ts";
import {
  ISOLATED_DOCUMENT_CLEANUP_SCOPE, prepareTelegramDocumentJobLeaseGuard, prepareTelegramDocumentJobSettlement,
  TELEGRAM_DOCUMENT_JOB_MARKER,
  type TelegramDocumentJobLease, type TelegramDocumentJobOutcome,
} from "./document-jobs.ts";
import { prepareTelegramProviderDocumentMarker, prepareTelegramProviderDocumentPlan,
  type TelegramProviderDocumentSources } from "./provider-document.ts";
import type { TelegramPolicy } from "./protocol.ts";
import { prepareLegacyAllAppend } from "../legacy-all-aggregates.ts";

export const MAX_TELEGRAM_DOCUMENT_NODES = 500;
const UPLOADED_SOURCE = "uploaded://telegram-document";
const MAX_REPLY_AGE_SECONDS = 900;
// A Cron invocation can run for 15 minutes. Never retire an abandoned candidate during that window.
const STAGE_CLEANUP_GRACE_SECONDS = 20 * 60;
const NO_NEWER_DOCUMENT = `NOT EXISTS (
  SELECT 1 FROM telegram_document_saved_counts AS saved
  JOIN telegram_inbox AS newer ON newer.receipt_id = saved.receipt_id
  JOIN telegram_inbox AS older ON older.receipt_id = ?
  WHERE saved.name_sha256 = ? AND newer.bot_id = older.bot_id AND newer.actor_id = older.actor_id
    AND (newer.message_date, newer.message_id) >= (older.message_date, older.message_id)
)`;

type Reservation = { id: number; newToken: string | null; generation: number; lifecycleRevision: number };
type Stage = { id: number; snapshotId: string };

function assertBatch(db: D1Database, condition: string): D1PreparedStatement {
  // SQLite CASE evaluates only the selected branch. A false invariant rolls back the D1 batch.
  return db.prepare(`SELECT CASE WHEN ${condition} THEN 1 ELSE json_extract('document transaction guard failed', '$') END`);
}

function verifyBatch(results: readonly D1Result[], expected: number): void {
  if (results.length !== expected || results.some((result) => !result.success)) {
    throw new Error("Telegram document transaction could not be confirmed.");
  }
}

async function reserveSubscription(db: D1Database, policy: TelegramPolicy, lease: TelegramDocumentJobLease): Promise<Reservation | null> {
  const guard = prepareTelegramDocumentJobLeaseGuard(policy, lease);
  const missing = `NOT EXISTS (SELECT 1 FROM telegram_document_reservations WHERE receipt_id = ?)`;
  const token = crypto.randomUUID().replaceAll("-", "");
  const steps = [
    db.prepare(`
      INSERT INTO telegram_document_reservations (receipt_id, subscription_id, generation, lifecycle_revision)
      SELECT ?, id, generation, ${SUBSCRIPTION_LIFECYCLE_REVISION} FROM subscriptions
      WHERE owner_id = ? AND name = ? AND source_url GLOB 'uploaded://*' AND ${missing} AND ${guard.sql}
      ORDER BY id LIMIT 1
    `).bind(lease.receiptId, lease.actorId, lease.name, lease.receiptId, ...guard.bindings),
    // Allocate an ID using the existing high-water mark. The transient row stays inside this transaction.
    db.prepare(`
      INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at)
      SELECT ?, ?, ?, ?, unixepoch(), unixepoch() WHERE ${missing} AND ${guard.sql}
        AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE token = ?)
    `).bind(lease.actorId, lease.name, UPLOADED_SOURCE, token, lease.receiptId, ...guard.bindings, token),
    db.prepare(`
      INSERT INTO telegram_document_reservations (receipt_id, subscription_id, new_token, generation, lifecycle_revision)
      SELECT ?, id, token, 0, 0 FROM subscriptions WHERE id = last_insert_rowid()
        AND changes() = 1 AND token = ? AND owner_id = ? AND generation = 0
    `).bind(lease.receiptId, token, lease.actorId),
    db.prepare(`
      DELETE FROM subscriptions WHERE token = ? AND owner_id = ? AND generation = 0
        AND id = (SELECT subscription_id FROM telegram_document_reservations WHERE receipt_id = ? AND new_token = ?)
    `).bind(token, lease.actorId, lease.receiptId, token),
    assertBatch(db, "NOT EXISTS (SELECT 1 FROM subscriptions WHERE token = ?)").bind(token),
    db.prepare(`
      SELECT subscription_id AS id, new_token AS newToken, generation, lifecycle_revision AS lifecycleRevision
      FROM telegram_document_reservations WHERE receipt_id = ? AND ${guard.sql}
    `).bind(lease.receiptId, ...guard.bindings),
  ];
  const results = await db.batch<Reservation>(steps);
  verifyBatch(results, steps.length);
  return results[5].results[0] ?? null;
}

function prepareTerminalOutbox(db: D1Database, receiptId: number): D1PreparedStatement {
  return db.prepare(`
    INSERT INTO telegram_outbox (receipt_id)
    SELECT job.receipt_id FROM telegram_document_jobs AS job JOIN telegram_inbox AS inbox USING (receipt_id)
    WHERE job.receipt_id = ? AND job.state = 'done' AND job.result_code <> 'saved' AND inbox.receipt_nonce = ?
    ON CONFLICT (receipt_id) DO NOTHING
  `).bind(receiptId, TELEGRAM_DOCUMENT_JOB_MARKER);
}

export async function finishTelegramDocumentJob(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramDocumentJobLease,
  outcome: Exclude<TelegramDocumentJobOutcome, { kind: "saved" }>,
): Promise<"retry" | "done" | "stale"> {
  try {
    const results = await db.batch<{ state: "done" | "pending" }>([
      prepareTelegramDocumentJobSettlement(db, policy, lease, outcome),
      prepareTerminalOutbox(db, lease.receiptId),
      db.prepare(`DELETE FROM telegram_document_reservations WHERE receipt_id = ?
        AND EXISTS (SELECT 1 FROM telegram_document_jobs WHERE receipt_id = ? AND state = 'done')`)
        .bind(lease.receiptId, lease.receiptId),
    ]);
    verifyBatch(results, 3);
    const row = results[0].results[0];
    return row === undefined ? "stale" : row.state === "pending" ? "retry" : "done";
  } catch {
    throw new Error("Telegram document outcome could not be confirmed.");
  }
}

function preparePublication(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramDocumentJobLease,
  reservation: Reservation,
  staged: StagedNodeSnapshot,
  nameSha256: string,
  companion?: { sql: string; bindings: readonly number[] },
): D1PreparedStatement {
  const leaseGuard = prepareTelegramDocumentJobLeaseGuard(policy, lease);
  const guard = {
    sql: `${leaseGuard.sql} AND ${NO_NEWER_DOCUMENT} AND EXISTS (SELECT 1 FROM telegram_document_stages
      WHERE receipt_id = ? AND lease_id = ? AND snapshot_id = ? AND subscription_id = ?)
      ${companion ? `AND (${companion.sql})` : ""}`,
    bindings: [...leaseGuard.bindings, lease.receiptId, nameSha256, lease.receiptId, lease.leaseId, staged.snapshotId, reservation.id,
      ...(companion?.bindings ?? [])],
  };
  const matching = "owner_id = ? AND name = ? AND source_url GLOB 'uploaded://*'";
  if (reservation.newToken === null) {
    return prepareNodeSnapshotPublication(db, { id: reservation.id, ownerId: lease.actorId,
      expectedGeneration: reservation.generation, expectedLifecycleRevision: reservation.lifecycleRevision }, staged, {
      sql: `${guard.sql} AND id = (SELECT min(id) FROM subscriptions WHERE ${matching})`,
      bindings: [...guard.bindings, lease.actorId, lease.name],
    });
  }
  return db.prepare(`
    INSERT INTO subscriptions (id, owner_id, name, source_url, token, created_at, updated_at,
      generation, snapshot_id, manifest_sha256, node_count)
    SELECT ?, ?, ?, ?, ?, unixepoch(), unixepoch(), 1, ?, ?, ? WHERE ${guard.sql}
      AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id = ? OR token = ?)
      AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE ${matching})
  `).bind(reservation.id, lease.actorId, lease.name, UPLOADED_SOURCE, reservation.newToken, staged.snapshotId,
    staged.manifestSha256, staged.nodeCount, ...guard.bindings, reservation.id, reservation.newToken, lease.actorId, lease.name);
}

export async function persistTelegramDocumentJob(
  db: D1Database,
  bucket: R2Bucket,
  policy: TelegramPolicy,
  lease: TelegramDocumentJobLease,
  nodes: readonly NodeRecord[],
  counts: { parsed: number },
  mixed?: TelegramProviderDocumentSources,
): Promise<"saved" | "stale"> {
  if (!validInteger(counts.parsed, 1, MAX_TELEGRAM_DOCUMENT_NODES) || counts.parsed !== nodes.length) {
    throw new RangeError("Invalid Telegram document node count.");
  }
  try {
    const nameSha256 = digestHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(lease.name)));
    const current = await db.prepare(`SELECT ${NO_NEWER_DOCUMENT} AS current`)
      .bind(lease.receiptId, nameSha256).first<number>("current");
    if (current !== 1) {
      await finishTelegramDocumentJob(db, policy, lease, { kind: "failed", reason: "coalesced" });
      return "stale";
    }
    const reservation = await reserveSubscription(db, policy, lease);
    if (!reservation) return "stale";
    const snapshotId = crypto.randomUUID();
    const guard = prepareTelegramDocumentJobLeaseGuard(policy, lease);
    const journal = await db.prepare(`
      INSERT INTO telegram_document_stages (snapshot_id, receipt_id, subscription_id, lease_id, cleanup_after)
      SELECT ?, ?, ?, ?, ? WHERE ${guard.sql} RETURNING snapshot_id
    `).bind(snapshotId, lease.receiptId, reservation.id, lease.leaseId,
      lease.leaseUntil + STAGE_CLEANUP_GRACE_SECONDS, ...guard.bindings).first<string>("snapshot_id");
    if (journal !== snapshotId) return "stale";

    const staged = await stageNodeSnapshot(bucket, reservation.id, nodes, snapshotId);
    const plan = mixed ? await prepareTelegramProviderDocumentPlan(db, policy, lease, mixed, true) : null;
    const pointer = "EXISTS (SELECT 1 FROM subscriptions WHERE id = ? AND owner_id = ? AND snapshot_id = ?)";
    const pointerKey = [reservation.id, lease.actorId, snapshotId] as const;
    const saved = "EXISTS (SELECT 1 FROM telegram_document_jobs WHERE receipt_id = ? AND state = 'done' AND result_code = 'saved')";
    const order = reservation.newToken === null ? null : await prepareLegacyAllAppend(db, reservation.id, lease.actorId, {
      sql: `${pointer} AND ${saved}`, bindings: [...pointerKey, lease.receiptId],
    }, { newShellTokens: plan?.newShellTokens, durableCommitGuard: true });
    const beforePlan = order?.beforeShells ? [order.beforeShells] : [];
    const steps = [
      ...beforePlan,
      ...(plan?.steps ?? []),
      preparePublication(db, policy, lease, reservation, staged, nameSha256, plan?.exists),
      prepareTelegramDocumentJobSettlement(db, policy, lease, { kind: "saved" }, true),
      assertBatch(db, `NOT ${pointer} OR changes() = 1`).bind(...pointerKey),
      ...(plan ? [assertBatch(db, `NOT ${plan.exists.sql} OR (${pointer} AND changes() = 1)`)
        .bind(...plan.exists.bindings, ...pointerKey)] : []),
      db.prepare(`INSERT INTO telegram_document_saved_counts (receipt_id, node_count, name_sha256)
        SELECT ?, ?, ? WHERE ${pointer} AND ${saved}`)
        .bind(lease.receiptId, counts.parsed, nameSha256, ...pointerKey, lease.receiptId),
      ...(plan ? [
        db.prepare(`DELETE FROM telegram_provider_document_opt_in WHERE receipt_id=? AND changes()=1
          AND EXISTS (SELECT 1 FROM telegram_mixed_document_opt_in WHERE receipt_id=?)`).bind(lease.receiptId, lease.receiptId),
        ...prepareTelegramProviderDocumentMarker(db, lease.receiptId),
      ] : [
        db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT ? WHERE changes() = 1`).bind(lease.receiptId),
        assertBatch(db, `NOT ${pointer} OR changes() = 1`).bind(...pointerKey),
      ]),
      db.prepare(`DELETE FROM telegram_document_stages WHERE snapshot_id = ? AND ${pointer}`)
        .bind(snapshotId, ...pointerKey),
      db.prepare(`DELETE FROM telegram_document_reservations WHERE receipt_id = ? AND ${pointer}`)
        .bind(lease.receiptId, ...pointerKey),
      ...(order ? [order.assert, ...(order.append ? [order.append] : []), ...(order.verify ? [order.verify] : [])] : []),
    ];
    const results = await db.batch(steps);
    verifyBatch(results, steps.length);
    if (results[beforePlan.length + (plan?.steps.length ?? 0) + 1].results.length === 1) return "saved";
    if (plan && results[beforePlan.length].meta.changes === 0) {
      await finishTelegramDocumentJob(db, policy, lease, { kind: "failed", reason: "coalesced" });
      return "stale";
    }
    // A live lease with a changed target gets the same bounded retry policy as storage failures.
    await finishTelegramDocumentJob(db, policy, lease, { kind: "retry" });
    return "stale";
  } catch {
    // The commit may have succeeded. The next attempt and the orphan sweeper both check D1 first.
    throw new Error("Telegram document publication could not be confirmed.");
  }
}

export async function reconcileTelegramDocumentJobReplies(db: D1Database, policy: TelegramPolicy): Promise<number> {
  try {
    const results = await db.batch([
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT job.receipt_id FROM telegram_document_jobs AS job JOIN telegram_inbox AS inbox USING (receipt_id)
        WHERE job.bot_id = ? AND job.state = 'done' AND job.finished_at > unixepoch() - ${MAX_REPLY_AGE_SECONDS}
          AND inbox.received_at > unixepoch() - ${MAX_REPLY_AGE_SECONDS} AND inbox.receipt_nonce = ?
          AND inbox.chat_type = 'private' AND inbox.chat_id = job.actor_id AND inbox.thread_id IS NULL
          AND job.actor_id IN (?, ?) AND job.result_code <> 'saved'
          AND NOT EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id = job.receipt_id)
        ORDER BY job.finished_at, job.receipt_id LIMIT 16
      `).bind(policy.botId, TELEGRAM_DOCUMENT_JOB_MARKER, policy.adminId, policy.memberId),
      db.prepare(`
        DELETE FROM telegram_document_reservations WHERE receipt_id IN (
          SELECT reservation.receipt_id FROM telegram_document_reservations AS reservation
          JOIN telegram_document_jobs AS job USING (receipt_id) WHERE job.bot_id = ? AND job.state = 'done'
            AND ${ISOLATED_DOCUMENT_CLEANUP_SCOPE}
          ORDER BY reservation.receipt_id LIMIT 16
        )
      `).bind(policy.botId),
    ]);
    verifyBatch(results, 2);
    return results[0].meta.changes;
  } catch {
    throw new Error("Telegram document reply reconciliation could not be confirmed.");
  }
}

const unreferencedStage = `stage.cleanup_after <= unixepoch()
  AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE id = stage.subscription_id AND snapshot_id = stage.snapshot_id)
  AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id = stage.subscription_id AND snapshot_id = stage.snapshot_id)
  AND NOT EXISTS (SELECT 1 FROM telegram_document_jobs WHERE receipt_id = stage.receipt_id
    AND state = 'leased' AND lease_id = stage.lease_id AND lease_until > unixepoch())`;

export async function retireTelegramDocumentStage(db: D1Database, bucket: R2Bucket, policy: TelegramPolicy): Promise<void> {
  try {
    const stage = await db.prepare(`SELECT stage.subscription_id AS id, stage.snapshot_id AS snapshotId
      FROM telegram_document_stages AS stage JOIN telegram_document_jobs AS job USING (receipt_id)
      WHERE job.bot_id = ? AND ${unreferencedStage} AND ${ISOLATED_DOCUMENT_CLEANUP_SCOPE}
      ORDER BY stage.cleanup_after, stage.snapshot_id LIMIT 1`)
      .bind(policy.botId).first<Stage>();
    if (!stage) return;
    if (!validInteger(stage.id, 1) || !/^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/u.test(stage.snapshotId)) {
      throw new Error("Invalid document stage identity.");
    }
    const prefix = `subscriptions/${stage.id}/${stage.snapshotId}/`;
    const objects = await bucket.list({ prefix, limit: MAX_SNAPSHOT_CHUNKS + 2 });
    const expected = new Set([`${prefix}manifest.json`, ...Array.from({ length: MAX_SNAPSHOT_CHUNKS },
      (_, index) => `${prefix}${index}.ndjson`)]);
    const keys = objects.objects.map(({ key }) => key);
    if (objects.truncated || keys.some((key) => !expected.has(key))) throw new Error("Unknown document stage object.");
    if (keys.length) await bucket.delete(keys);
    if ((await bucket.list({ prefix, limit: 1 })).objects.length !== 0) throw new Error("Document stage still exists.");
    await db.prepare(`DELETE FROM telegram_document_stages AS stage WHERE snapshot_id = ? AND subscription_id = ?
      AND EXISTS (SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id = stage.receipt_id
        AND job.bot_id = ? AND ${ISOLATED_DOCUMENT_CLEANUP_SCOPE})
      AND ${unreferencedStage}`).bind(stage.snapshotId, stage.id, policy.botId).run();
  } catch {
    throw new Error("Telegram document stage cleanup could not be confirmed.");
  }
}

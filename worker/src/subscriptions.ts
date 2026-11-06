import { checkOwnerId, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "./storage.ts";

export interface SubscriptionListItem {
  id: number;
  name: string;
  expireAt: number | null;
  trafficUsed: number | null;
  trafficTotal: number | null;
  nodeCount: number;
  lifecycleRevision: number;
}

export interface DeletedSubscriptionCursor {
  deletedAt: number;
  id: number;
}

export interface DeletedSubscriptionListItem extends SubscriptionListItem {
  deletedAt: number;
}

export interface SubscriptionLifecycleTarget {
  id: number;
  ownerId: string;
  expectedLifecycleRevision: number;
}

const MAX_PAGE_SIZE = 50;
const TRASH_SECONDS = 30 * 24 * 60 * 60;
const LIST_FIELDS = "id, name, expire_at AS expireAt, traffic_used AS trafficUsed, traffic_total AS trafficTotal, node_count AS nodeCount";
const RECORD_FIELDS = "id, owner_id, name, source_url, token, expire_at, traffic_used, traffic_total, last_error, created_at";
const SNAPSHOT_FIELDS = "generation, snapshot_id, manifest_sha256, node_count";
const STORED_FIELDS = `${RECORD_FIELDS}, updated_at, ${SNAPSHOT_FIELDS}`;

function checkPageSize(limit: number): void {
  if (!validInteger(limit, 1, MAX_PAGE_SIZE)) throw new RangeError("Invalid subscription page size.");
}

function checkTarget({ id, ownerId, expectedLifecycleRevision }: SubscriptionLifecycleTarget): void {
  checkOwnerId(ownerId);
  if (!validInteger(id, 1) || !validInteger(expectedLifecycleRevision, 0, Number.MAX_SAFE_INTEGER - 1)) {
    throw new RangeError("Invalid subscription lifecycle target.");
  }
}

async function readPage<T>(statement: D1PreparedStatement): Promise<T[]> {
  try {
    const result = await statement.all<T>();
    if (result.success) return result.results;
  } catch {
    // D1 errors can include SQL or private parameters.
  }
  throw new Error("Subscription list could not be read.");
}

export async function listOwnedSubscriptions(
  db: D1Database,
  ownerId: string,
  { limit, afterId }: { limit: number; afterId?: number },
): Promise<{ items: SubscriptionListItem[]; nextAfterId: number | null }> {
  checkOwnerId(ownerId);
  checkPageSize(limit);
  if (afterId !== undefined && !validInteger(afterId, 1)) throw new RangeError("Invalid subscription cursor.");
  const rows = await readPage<SubscriptionListItem>(db.prepare(`
    SELECT ${LIST_FIELDS}, ${SUBSCRIPTION_LIFECYCLE_REVISION} AS lifecycleRevision
    FROM subscriptions WHERE owner_id = ? AND id > ? ORDER BY id LIMIT ?
  `).bind(ownerId, afterId ?? 0, limit + 1));
  const items = rows.slice(0, limit);
  return { items, nextAfterId: rows.length > limit ? items[items.length - 1].id : null };
}

export async function listDeletedSubscriptions(
  db: D1Database,
  ownerId: string,
  { limit, after }: { limit: number; after?: DeletedSubscriptionCursor },
): Promise<{ items: DeletedSubscriptionListItem[]; nextCursor: DeletedSubscriptionCursor | null }> {
  checkOwnerId(ownerId);
  checkPageSize(limit);
  if (after !== undefined && (!after || !validInteger(after.deletedAt, 1) || !validInteger(after.id, 1))) {
    throw new RangeError("Invalid deleted subscription cursor.");
  }
  const rows = await readPage<DeletedSubscriptionListItem>(db.prepare(`
    SELECT ${LIST_FIELDS}, lifecycle_revision AS lifecycleRevision, deleted_at AS deletedAt
    FROM subscription_trash
    WHERE owner_id = ? AND deleted_at >= unixepoch() - ${TRASH_SECONDS}
      ${after ? "AND (deleted_at, id) < (?, ?)" : ""}
    ORDER BY deleted_at DESC, id DESC LIMIT ?
  `).bind(ownerId, ...(after ? [after.deletedAt, after.id] : []), limit + 1));
  const items = rows.slice(0, limit);
  const last = items[items.length - 1];
  return { items, nextCursor: rows.length > limit ? { deletedAt: last.deletedAt, id: last.id } : null };
}

async function mutate(db: D1Database, statements: D1PreparedStatement[], writes: number): Promise<boolean> {
  try {
    const results = await db.batch(statements);
    const changed = results[0]?.meta.changes;
    if ((changed === 0 || changed === 1) && results.length === statements.length
      && results.every((result, index) => result.success && result.meta.changes === (index < writes ? changed : 0))) {
      return changed === 1;
    }
  } catch {
    // Avoid exposing stored URLs, tokens or backend errors.
  }
  throw new Error("Subscription lifecycle operation could not be confirmed.");
}

function guardExclusiveRow(db: D1Database, id: number, ownerId: string): D1PreparedStatement {
  // Revision zero is reserved for absent lifecycle rows. A CHECK failure rolls back an incomplete move.
  return db.prepare(`
    INSERT INTO subscription_lifecycle (subscription_id, revision)
    SELECT ?, 0 WHERE EXISTS (SELECT 1 FROM subscriptions WHERE id = ? AND owner_id = ?)
      AND EXISTS (SELECT 1 FROM subscription_trash WHERE id = ?)
  `).bind(id, id, ownerId, id);
}

export async function renameOwnedSubscription(
  db: D1Database,
  target: SubscriptionLifecycleTarget,
  name: string,
): Promise<boolean> {
  checkTarget(target);
  const normalizedName = typeof name === "string" ? name.trim() : "";
  if (!normalizedName || Array.from(normalizedName).length > 64
    || /[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(normalizedName)) {
    throw new RangeError("Invalid subscription name.");
  }
  const { id, ownerId, expectedLifecycleRevision } = target;
  const eligible = `id = ? AND owner_id = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?
    AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id = subscriptions.id)`;
  return mutate(db, [
    db.prepare(`UPDATE subscriptions SET name = ?, updated_at = unixepoch() WHERE ${eligible}`)
      .bind(normalizedName, id, ownerId, expectedLifecycleRevision),
    db.prepare(`
      INSERT INTO subscription_lifecycle (subscription_id, revision)
      SELECT id, ? FROM subscriptions WHERE ${eligible}
      ON CONFLICT (subscription_id) DO UPDATE SET revision = excluded.revision
    `).bind(expectedLifecycleRevision + 1, id, ownerId, expectedLifecycleRevision),
  ], 2);
}

export async function trashOwnedSubscription(db: D1Database, target: SubscriptionLifecycleTarget): Promise<boolean> {
  checkTarget(target);
  const { id, ownerId, expectedLifecycleRevision } = target;
  const nextRevision = expectedLifecycleRevision + 1;
  return mutate(db, [
    db.prepare(`
      INSERT INTO subscription_trash (${STORED_FIELDS}, deleted_at, lifecycle_revision)
      SELECT ${STORED_FIELDS}, unixepoch(), ? FROM subscriptions
      WHERE id = ? AND owner_id = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?
    `).bind(nextRevision, id, ownerId, expectedLifecycleRevision),
    db.prepare(`
      INSERT INTO subscription_lifecycle (subscription_id, revision)
      SELECT id, lifecycle_revision FROM subscription_trash
      WHERE id = ? AND owner_id = ? AND lifecycle_revision = ? AND changes() = 1
      ON CONFLICT (subscription_id) DO UPDATE SET revision = excluded.revision
      WHERE subscription_lifecycle.revision = ?
    `).bind(id, ownerId, nextRevision, expectedLifecycleRevision),
    db.prepare(`
      DELETE FROM subscriptions WHERE id = ? AND owner_id = ? AND changes() = 1
        AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?
        AND EXISTS (SELECT 1 FROM subscription_trash WHERE id = subscriptions.id
          AND owner_id = subscriptions.owner_id AND lifecycle_revision = ?)
    `).bind(id, ownerId, nextRevision, nextRevision),
    guardExclusiveRow(db, id, ownerId),
  ], 3);
}

export async function restoreOwnedSubscription(db: D1Database, target: SubscriptionLifecycleTarget): Promise<boolean> {
  checkTarget(target);
  const { id, ownerId, expectedLifecycleRevision } = target;
  const nextRevision = expectedLifecycleRevision + 1;
  return mutate(db, [
    db.prepare(`
      INSERT INTO subscriptions (${STORED_FIELDS})
      SELECT ${RECORD_FIELDS}, unixepoch(), ${SNAPSHOT_FIELDS} FROM subscription_trash
      WHERE id = ? AND owner_id = ? AND lifecycle_revision = ?
        AND deleted_at >= unixepoch() - ${TRASH_SECONDS}
        AND EXISTS (SELECT 1 FROM subscription_lifecycle
          WHERE subscription_id = subscription_trash.id AND revision = subscription_trash.lifecycle_revision)
    `).bind(id, ownerId, expectedLifecycleRevision),
    db.prepare(`
      UPDATE subscription_lifecycle SET revision = ?
      WHERE subscription_id = ? AND revision = ? AND changes() = 1
        AND EXISTS (SELECT 1 FROM subscription_trash WHERE id = ? AND owner_id = ? AND lifecycle_revision = ?)
    `).bind(nextRevision, id, expectedLifecycleRevision, id, ownerId, expectedLifecycleRevision),
    db.prepare(`
      DELETE FROM subscription_trash WHERE id = ? AND owner_id = ? AND lifecycle_revision = ?
        AND changes() = 1
        AND EXISTS (SELECT 1 FROM subscription_lifecycle
          WHERE subscription_id = subscription_trash.id AND revision = ?)
        AND EXISTS (SELECT 1 FROM subscriptions WHERE id = subscription_trash.id
          AND owner_id = subscription_trash.owner_id AND token = subscription_trash.token)
    `).bind(id, ownerId, expectedLifecycleRevision, nextRevision),
    guardExclusiveRow(db, id, ownerId),
  ], 3);
}

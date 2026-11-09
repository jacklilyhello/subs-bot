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

export type SubscriptionMutation = { kind: "rename"; name: string } | { kind: "trash" | "restore" };

interface SubscriptionMutationGuard {
  // Only an internal SQL predicate belongs here. Values must be bound.
  sql: string;
  bindings: readonly (string | number | null)[];
}

interface PreparedSubscriptionMutation {
  first: D1PreparedStatement;
  followups: D1PreparedStatement[];
  writes: number;
  watchWrite?: boolean;
}

type LegacySelectedRetirement = "absent" | "unregistered" | "ready";
const RETIREMENT_MIGRATION = "0038_legacy_selected_aggregates.sql";
const RETIREMENT_SHA256 = "29ddd93dc46120614c4837268ac2c0a0c5b4c48af9d7e4fe4de1e5e24451b74f";
const RETIREMENT_TABLES = "name IN ('legacy_selected_aggregates','legacy_selected_members')";
export const LEGACY_SELECTED_RETIREMENT_PIN = `EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=38
  AND name='${RETIREMENT_MIGRATION}' AND sha256='${RETIREMENT_SHA256}' AND mode='applied')`;
const MUTATION_ERROR = "Subscription lifecycle operation could not be confirmed.";

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

export async function readLegacySelectedRetirement(db: D1Database): Promise<LegacySelectedRetirement> {
  try {
    const schema = await db.prepare(`SELECT /* subs-bot:legacy-selected-retirement:v1 */
      count(CASE WHEN ${RETIREMENT_TABLES} THEN 1 END) AS watched,
      count(CASE WHEN name='subs_bot_schema_migrations' THEN 1 END) AS ledger
      FROM sqlite_schema WHERE type='table' AND (${RETIREMENT_TABLES} OR name='subs_bot_schema_migrations')`)
      .first<{ watched: number; ledger: number }>();
    if (schema && (schema.watched === 0 || schema.watched === 2) && (schema.ledger === 0 || schema.ledger === 1)) {
      const pin = schema.ledger === 1 ? await db.prepare(`SELECT position,name,sha256,mode FROM subs_bot_schema_migrations
        WHERE position=38 OR name=? LIMIT 2`).bind(RETIREMENT_MIGRATION).all<{
          position: number; name: string; sha256: string; mode: string;
        }>() : null;
      if (pin === null || (pin.success && pin.results.length === 0)) return schema.watched === 0 ? "absent" : "unregistered";
      const row = pin.results[0];
      if (pin.success && pin.results.length === 1 && schema.watched === 2 && row.position === 38
        && row.name === RETIREMENT_MIGRATION && row.sha256 === RETIREMENT_SHA256 && row.mode === "applied") return "ready";
    }
  } catch {
    // Treat unexpected schema or ledger state as an unconfirmed operation.
  }
  throw new Error(MUTATION_ERROR);
}

async function mutate(db: D1Database, { first, followups, writes, watchWrite }: PreparedSubscriptionMutation): Promise<boolean> {
  try {
    const statements = [first, ...followups];
    const results = await db.batch(statements);
    const changed = results[0]?.meta.changes;
    if ((changed === 0 || changed === 1) && results.length === statements.length) {
      const confirmed = results.every(({ success, meta }, index) => success
        && (watchWrite && index === writes ? meta.changes === 0 || meta.changes === changed
          : meta.changes === (index < writes ? changed : 0)));
      if (confirmed) return changed === 1;
    }
  } catch {
    // Avoid exposing stored URLs, tokens or backend errors.
  }
  throw new Error(MUTATION_ERROR);
}

function guardExclusiveRow(db: D1Database, id: number, ownerId: string, retirement?: SubscriptionMutationGuard): D1PreparedStatement {
  // Revision zero is reserved for absent lifecycle rows. A CHECK failure rolls back an incomplete move.
  return db.prepare(`
    INSERT INTO subscription_lifecycle (subscription_id, revision)
    SELECT ?, 0 WHERE (EXISTS (SELECT 1 FROM subscriptions WHERE id = ? AND owner_id = ?)
      AND EXISTS (SELECT 1 FROM subscription_trash WHERE id = ?)) ${retirement ? `OR (${retirement.sql})` : ""}
  `).bind(id, id, ownerId, id, ...(retirement?.bindings ?? []));
}

function retirementFence(readiness: LegacySelectedRetirement, id: number, ownerId: string, nextRevision: number): SubscriptionMutationGuard {
  // The mutation and this assertion share one batch. Never skip a watch that
  // appeared after a preflight on the older schema or on empty unregistered tables.
  if (readiness === "absent") return { sql: `EXISTS (SELECT 1 FROM sqlite_schema WHERE ${RETIREMENT_TABLES})`, bindings: [] };
  if (readiness === "unregistered") return {
    sql: "EXISTS (SELECT 1 FROM legacy_selected_members) OR EXISTS (SELECT 1 FROM legacy_selected_aggregates)", bindings: [],
  };
  return { sql: `NOT ${LEGACY_SELECTED_RETIREMENT_PIN} OR EXISTS (
    SELECT 1 FROM subscription_trash AS trash
    JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=trash.id AND lifecycle.revision=trash.lifecycle_revision
    JOIN legacy_selected_members AS watched ON watched.id=trash.id AND watched.retired=0
    WHERE trash.id=? AND trash.owner_id=? AND trash.lifecycle_revision=?)`,
  bindings: [id, ownerId, nextRevision] };
}

export function normalizeSubscriptionName(name: string): string {
  const normalizedName = typeof name === "string" ? name.trim() : "";
  if (!normalizedName || Array.from(normalizedName).length > 64
    || /[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(normalizedName)) {
    throw new RangeError("Invalid subscription name.");
  }
  return normalizedName;
}

// The first statement determines whether the operation started. If a caller
// records that result before the followups, its write must preserve changes().
export async function prepareOwnedSubscriptionMutation(
  db: D1Database,
  target: SubscriptionLifecycleTarget,
  mutation: SubscriptionMutation,
  guard?: SubscriptionMutationGuard,
  retirement?: LegacySelectedRetirement,
): Promise<PreparedSubscriptionMutation> {
  checkTarget(target);
  const { id, ownerId, expectedLifecycleRevision } = target;
  const nextRevision = expectedLifecycleRevision + 1;
  const condition = guard ? `AND (${guard.sql})` : "";
  const bindings = guard?.bindings ?? [];
  const active = `id = ? AND owner_id = ? AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = ?`;

  if (mutation.kind === "rename") {
    const name = normalizeSubscriptionName(mutation.name);
    const eligible = `${active} AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id = subscriptions.id)`;
    return {
      first: db.prepare(`UPDATE subscriptions SET name = ?, updated_at = unixepoch() WHERE ${eligible} ${condition}`)
        .bind(name, id, ownerId, expectedLifecycleRevision, ...bindings),
      followups: [db.prepare(`
        INSERT INTO subscription_lifecycle (subscription_id, revision)
        SELECT id, ? FROM subscriptions WHERE changes() = 1 AND ${eligible}
        ON CONFLICT (subscription_id) DO UPDATE SET revision = excluded.revision
      `).bind(nextRevision, id, ownerId, expectedLifecycleRevision)],
      writes: 2,
    };
  }
  if (mutation.kind === "trash") {
    const readiness = retirement ?? await readLegacySelectedRetirement(db);
    const watchWrite = readiness === "ready";
    return {
      first: db.prepare(`
        INSERT INTO subscription_trash (${STORED_FIELDS}, deleted_at, lifecycle_revision)
        SELECT ${STORED_FIELDS}, unixepoch(), ? FROM subscriptions WHERE ${active} ${condition}
      `).bind(nextRevision, id, ownerId, expectedLifecycleRevision, ...bindings),
      followups: [
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
        // This must immediately follow the guarded physical delete.
        ...(watchWrite ? [db.prepare(`UPDATE legacy_selected_members SET retired=1
          WHERE id=? AND retired=0 AND changes()=1`).bind(id)] : []),
        guardExclusiveRow(db, id, ownerId, retirementFence(readiness, id, ownerId, nextRevision)),
      ],
      writes: 3,
      watchWrite,
    };
  }
  return {
    first: db.prepare(`
      INSERT INTO subscriptions (${STORED_FIELDS})
      SELECT ${RECORD_FIELDS}, unixepoch(), ${SNAPSHOT_FIELDS} FROM subscription_trash
      WHERE id = ? AND owner_id = ? AND lifecycle_revision = ?
        AND deleted_at >= unixepoch() - ${TRASH_SECONDS}
        AND EXISTS (SELECT 1 FROM subscription_lifecycle
          WHERE subscription_id = subscription_trash.id AND revision = subscription_trash.lifecycle_revision)
        ${condition}
    `).bind(id, ownerId, expectedLifecycleRevision, ...bindings),
    followups: [
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
    ],
    writes: 3,
  };
}

async function performMutation(db: D1Database, target: SubscriptionLifecycleTarget, mutation: SubscriptionMutation) {
  return mutate(db, await prepareOwnedSubscriptionMutation(db, target, mutation));
}

export async function renameOwnedSubscription(
  db: D1Database, target: SubscriptionLifecycleTarget, name: string,
): Promise<boolean> {
  return performMutation(db, target, { kind: "rename", name });
}

export async function trashOwnedSubscription(db: D1Database, target: SubscriptionLifecycleTarget): Promise<boolean> {
  return performMutation(db, target, { kind: "trash" });
}

export async function restoreOwnedSubscription(db: D1Database, target: SubscriptionLifecycleTarget): Promise<boolean> {
  return performMutation(db, target, { kind: "restore" });
}

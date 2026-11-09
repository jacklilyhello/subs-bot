import { tempSchemaGuard } from "./telegram/temp-storage.ts";

export const LEGACY_ALL_MIGRATION = "0040_legacy_all_aggregates.sql";
export const LEGACY_ALL_MIGRATION_SHA256 = "55a3de863e8b05eff6a25c52f5fe1b2e8be8f246f6b2e23348b6ef2a4456e3ed";

const markerTable = "legacy_all_aggregates";
const orderTable = "legacy_all_subscription_order";
const tableNames = `'${markerTable}','${orderTable}'`;
const ledger = "subs_bot_schema_migrations";
const migration = `position=40 OR name='${LEGACY_ALL_MIGRATION}'`;

export const LEGACY_ALL_SCHEMA_PIN = `
  (SELECT count(*) FROM main.sqlite_schema WHERE type='table' AND name IN (${tableNames}))=2
  AND EXISTS (SELECT 1 FROM main.sqlite_schema WHERE type='index' AND name='legacy_all_aggregates_owner' AND tbl_name='${markerTable}')
  AND (SELECT count(*) FROM ${ledger} WHERE ${migration})=1
  AND EXISTS (SELECT 1 FROM ${ledger} WHERE position=40 AND name='${LEGACY_ALL_MIGRATION}'
    AND sha256='${LEGACY_ALL_MIGRATION_SHA256}' AND mode='applied')`;

const schemaReady = `(${LEGACY_ALL_SCHEMA_PIN}) AND (${tempSchemaGuard("legacy-ready")})`;

// The aggregate link alias is supplied only by callers assembling static SQL.
function exactScope(link: string): string {
  return `${link}.kind='all' AND ${link}.selected_ids IS NULL AND marker.bot_id=${link}.bot_id
    AND marker.owner_id=${link}.owner_id AND marker.inventory_sha256=installation.inventory_sha256`;
}

const activeInstallation = "installation.cutover_epoch BETWEEN 1 AND unixepoch()";

function activeOwner(ownerSql: string): string {
  return `EXISTS (SELECT 1 FROM ${markerTable} AS marker
    JOIN aggregate_links AS link ON link.code_sha256=marker.code_sha256
    JOIN legacy_temp_installations AS installation ON installation.bot_id=marker.bot_id
    WHERE marker.owner_id=${ownerSql} AND ${exactScope("link")} AND link.revoked_at IS NULL AND ${activeInstallation})`;
}

/** Called only when the physical 0040 and 0039 tables and ledger are present. */
export function legacyAllActiveMarkerSql(linkAlias: string): string {
  return `(${schemaReady}) AND EXISTS (SELECT 1 FROM ${markerTable} AS marker
    JOIN legacy_temp_installations AS installation ON installation.bot_id=marker.bot_id
    WHERE marker.code_sha256=${linkAlias}.code_sha256 AND ${exactScope(linkAlias)} AND ${activeInstallation})`;
}

interface SqlGuard { sql: string; bindings: readonly (number | string | null)[] }

/** The caller adds these after its own changes()-dependent writes, in the same batch. */
export async function prepareLegacyAllAppend(
  db: D1Database, id: number, ownerId: string, committed: SqlGuard,
  options: { newShellTokens?: readonly string[]; durableCommitGuard?: boolean } = {},
): Promise<{ assert: D1PreparedStatement; append?: D1PreparedStatement; beforeShells?: D1PreparedStatement;
  verify?: D1PreparedStatement }> {
  const shape = await db.prepare(`SELECT name,type FROM main.sqlite_schema
    WHERE name IN (${tableNames},'${ledger}','legacy_temp_installations','legacy_temp_batches')`)
    .all<{ name: string; type: string }>();
  if (!shape.success || shape.results.some(({ type }) => type !== "table")) throw new Error("Legacy aggregate order could not be confirmed.");
  const names = new Set(shape.results.map(({ name }) => name));
  const marker = names.has(markerTable);
  const order = names.has(orderTable);
  const complete = marker && order && names.has(ledger) && names.has("legacy_temp_installations") && names.has("legacy_temp_batches");
  // A concurrent additive migration must not bypass ordering for a newly
  // installed marker. The caller can retry using the new shape.
  const sameShape = `(SELECT count(*) FROM main.sqlite_schema WHERE name IN (${tableNames}))=${Number(marker) + Number(order)}`;
  const ownerMarker = marker ? `EXISTS (SELECT 1 FROM ${markerTable} WHERE owner_id=?)` : "0";
  const ranked = order ? `EXISTS (SELECT 1 FROM ${orderTable} WHERE subscription_id=?)` : "0";
  const valid = complete ? `(${schemaReady}) AND ${ownerMarker} AND NOT EXISTS (
    SELECT 1 FROM ${markerTable} AS marker
    LEFT JOIN aggregate_links AS link ON link.code_sha256=marker.code_sha256
    LEFT JOIN legacy_temp_installations AS installation ON installation.bot_id=marker.bot_id
    WHERE marker.owner_id=? AND ((${exactScope("link")}) IS NOT TRUE
      OR (link.revoked_at IS NULL AND (${activeInstallation}) IS NOT TRUE))
  ) AND NOT EXISTS (SELECT 1 FROM ${orderTable} WHERE subscription_id=? AND owner_id<>?)` : "0";
  const assertion = db.prepare(`SELECT CASE WHEN NOT (${committed.sql}) OR (
    ${sameShape} AND (NOT (${ownerMarker} OR ${ranked}) OR (${valid}))) THEN 1
    ELSE json_extract('legacy aggregate order guard failed', '$') END`)
    .bind(...committed.bindings, ...(marker ? [ownerId] : []), ...(order ? [id] : []),
      ...(complete ? [ownerId, ownerId, id, ownerId] : []));
  if (!complete) return { assert: assertion };

  const tokens = options.newShellTokens === undefined ? null : JSON.stringify(options.newShellTokens);
  // A mixed document creates its local item before its URL subscriptions in
  // the legacy order. Prove that every matched token is new in this batch.
  const matchedShells = `FROM json_each(?) AS planned JOIN subscriptions AS shell ON shell.token=planned.value WHERE shell.owner_id=?`;
  const beforeShells = tokens === null ? undefined : db.prepare(`SELECT CASE
    WHEN NOT (${ownerMarker}) OR NOT EXISTS (SELECT 1 ${matchedShells}) THEN 1
    ELSE json_extract('legacy aggregate shell guard failed', '$') END`).bind(ownerId, tokens, ownerId);

  // New normal subscriptions retain their monotonically allocated ID order.
  // A restored stable ID or a previously reserved document ID joins the tail
  // at the current allocator anchor, after any prior appends at that anchor.
  const append = db.prepare(`WITH allocator AS (
    SELECT CASE WHEN count(*)=1 THEN min(seq) END AS id FROM sqlite_sequence WHERE name='subscriptions'
  ), current_anchor AS (
    SELECT ${tokens === null ? "id" : `min(id,COALESCE((SELECT min(shell.id)-1 ${matchedShells}),id))`} AS id FROM allocator
  ) INSERT /* subs-bot:legacy-dynamic-all-order:v1 */ INTO ${orderTable} (subscription_id,owner_id,anchor,tie)
  SELECT sub.id,sub.owner_id,current_anchor.id,COALESCE((SELECT max(ranked.tie) FROM ${orderTable} AS ranked
    WHERE ranked.owner_id=sub.owner_id AND ranked.anchor=current_anchor.id),0)+1
  FROM subscriptions AS sub CROSS JOIN current_anchor
  WHERE sub.id=? AND sub.owner_id=? AND (${committed.sql}) AND ${activeOwner("sub.owner_id")}
  ON CONFLICT(subscription_id) DO UPDATE SET anchor=excluded.anchor,tie=excluded.tie`)
    .bind(...(tokens === null ? [] : [tokens, ownerId]), id, ownerId, ...committed.bindings);
  // The document's fresh snapshot identity remains observable after the rank
  // statement. It can therefore assert the rank write before the batch commits.
  const verify = options.durableCommitGuard ? db.prepare(`SELECT CASE
    WHEN NOT (${committed.sql}) OR NOT (${activeOwner("?")}) OR changes()=1 THEN 1
    ELSE json_extract('legacy aggregate append guard failed', '$') END`).bind(...committed.bindings, ownerId) : undefined;
  return { assert: assertion, append, beforeShells, verify };
}

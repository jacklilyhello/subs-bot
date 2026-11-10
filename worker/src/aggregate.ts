import {
  digestHex, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_CHUNKS, MAX_SNAPSHOT_NODES,
  planSnapshotRead, readPlannedSnapshotNodes, SnapshotIntegrityError, validInteger,
  type ExportNodeSource, type NodeRecord, type SnapshotReadPlan, type SubscriptionSnapshot,
} from "./storage.ts";
import {
  MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, ownedTempRowsSql, readTempBatchNodes, readTempStorage, tempSchemaGuard,
  verifyTempInventory, TempStorageLimitError, type TempBatchRow,
} from "./telegram/temp-storage.ts";
import { compilePathRules, MAX_PATH_RULES, pathRuleMapper, type PathRuleRow } from "./path-rules.ts";
import {
  aggregateNamespace, legacyAllStatusSql, legacySelectedStatusSql, readShortLinkNamespaces, SHORT_CODE, shortCodeDigest,
  type ShortLinkNamespaces,
} from "./short-links.ts";
import { LEGACY_EMPTY_EXPORT_PIN } from "./legacy-empty-export.ts";
import { SUBSCRIPTION_SHORT_CODE } from "./telegram/subscription-shorts.ts";

const EMPTY_TOKEN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
export const MAX_AGGREGATE_MEMBERS = 128;
const encoder = new TextEncoder();
const activeLink = "FROM aggregate_links WHERE code_sha256 = ? AND revoked_at IS NULL";
const pointerColumns = `sub.id, sub.generation, sub.snapshot_id AS snapshotId,
  sub.manifest_sha256 AS manifestSha256, sub.node_count AS nodeCount`;

interface LinkRow {
  kind: "all" | "selected";
  ownerId: string;
  selectedIds: string | null;
  legacySelected: number;
  legacyAll: number;
  tempReady: number;
  rankHighWater: number | null;
}
interface LegacyAllPointer extends SubscriptionSnapshot {
  rankOwner: string | null;
  anchor: number | null;
  tie: number | null;
  hasTrash: number;
}
interface TempTotals { batchCount: number; nodeCount: number; bytes: number }
interface LegacyMember {
  position: number;
  selectedId: number;
  retired: number | null;
  id: number | null;
  generation: number | null;
  snapshotId: string | null;
  manifestSha256: string | null;
  nodeCount: number | null;
  emptyToken: string | null;
  emptyTokenSha256: string | null;
}
type Row = LinkRow | SubscriptionSnapshot | LegacyAllPointer | TempTotals | TempBatchRow | PathRuleRow | LegacyMember;
interface AggregateNodeSource extends ExportNodeSource { readonly legacyAggregate: boolean }

export class AggregateLimitError extends Error {}

async function codeDigest(code: string): Promise<string | null> {
  return typeof code === "string" && SHORT_CODE.test(code) && !SUBSCRIPTION_SHORT_CODE.test(code) ? shortCodeDigest(code) : null;
}

export async function hasAggregateLink(db: D1Database, code: string): Promise<boolean> {
  const digest = await codeDigest(code);
  if (digest === null) return false;
  const schema = await readShortLinkNamespaces(db);
  const row = await db.prepare(`SELECT ${legacySelectedStatusSql(schema)} AS selected,${legacyAllStatusSql(schema)} AS allStatus
    ${aggregateLinkSql(schema)}`).bind(digest).first<{ selected: number; allStatus: number }>();
  return row !== null && aggregateNamespace(code.length, row.selected, row.allStatus) !== null;
}

function aggregateLinkSql(schema: ShortLinkNamespaces): string {
  return `${activeLink}
    ${schema.normal ? "AND NOT EXISTS (SELECT 1 FROM normal_short_links AS normal WHERE normal.code_sha256=aggregate_links.code_sha256)" : ""}
    ${schema.legacySubscription ? `AND NOT EXISTS (SELECT 1 FROM legacy_subscription_short_links AS legacy
      WHERE legacy.code_sha256=aggregate_links.code_sha256)` : ""}`;
}

function selectionIds(selection: string | null): number[] | null {
  if (selection === null) return null;
  try {
    const ids: unknown = JSON.parse(selection);
    return Array.isArray(ids) && ids.length > 0 && ids.length <= MAX_AGGREGATE_MEMBERS && ids.every((id) => validInteger(id, 1))
      ? ids : null;
  } catch {
    return null;
  }
}

async function legacySnapshots(ids: number[], members: LegacyMember[]): Promise<SubscriptionSnapshot[]> {
  if (members.length !== ids.length) throw new SnapshotIntegrityError();
  const snapshots: SubscriptionSnapshot[] = [];
  for (const [position, member] of members.entries()) {
    if (member.position !== position || member.selectedId !== ids[position]) throw new SnapshotIntegrityError();
    if (member.retired === 1) continue;
    const { id, generation, snapshotId, manifestSha256, nodeCount, emptyToken, emptyTokenSha256 } = member;
    if (member.retired !== 0 || id === null || id !== member.selectedId) throw new SnapshotIntegrityError();
    if (generation === 0) {
      if (snapshotId !== null || manifestSha256 !== null || nodeCount !== 0 || !emptyToken || !EMPTY_TOKEN.test(emptyToken)
        || digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(emptyToken))) !== emptyTokenSha256) {
        throw new SnapshotIntegrityError();
      }
      continue;
    }
    if (!validInteger(generation, 1) || !validInteger(nodeCount, 1, MAX_SNAPSHOT_NODES)
      || typeof snapshotId !== "string" || typeof manifestSha256 !== "string") throw new SnapshotIntegrityError();
    snapshots.push({ id, generation, snapshotId, manifestSha256, nodeCount });
  }
  return snapshots;
}

function legacyAllSnapshots(link: LinkRow, rows: LegacyAllPointer[]): SubscriptionSnapshot[] {
  if (rows.length > MAX_AGGREGATE_MEMBERS) throw new AggregateLimitError();
  const keys = new Set<string>();
  const ranked = rows.map((row) => {
    if (!validInteger(row.id, 1) || row.hasTrash !== 0) throw new SnapshotIntegrityError();
    let anchor = row.id;
    let tie = 0;
    if (row.rankOwner !== null || row.anchor !== null || row.tie !== null) {
      if (row.rankOwner !== link.ownerId || !validInteger(link.rankHighWater, 1)
          || !validInteger(row.anchor, row.id, link.rankHighWater) || !validInteger(row.tie, 1)) {
        throw new SnapshotIntegrityError();
      }
      anchor = row.anchor;
      tie = row.tie;
    }
    const key = `${anchor}:${tie}`;
    if (keys.has(key)) throw new SnapshotIntegrityError();
    keys.add(key);
    return { row, anchor, tie };
  });
  // Read at most 129 indexed owner rows before sorting a legacy order in memory.
  ranked.sort((left, right) => left.anchor - right.anchor || left.tie - right.tie);
  return ranked.map(({ row }) => row);
}

function verifyTemp(totals: TempTotals, rows: TempBatchRow[]): void {
  if (!validInteger(totals.batchCount, 0) || !validInteger(totals.nodeCount, 0) || !validInteger(totals.bytes, 0)) {
    throw new SnapshotIntegrityError();
  }
  if (totals.nodeCount > MAX_TEMP_OWNER_NODES || totals.bytes > MAX_TEMP_OWNER_BYTES) throw new AggregateLimitError();
  try {
    const checked = verifyTempInventory(rows);
    if (checked.nodeCount === totals.nodeCount && checked.bytes === totals.bytes && rows.length === totals.batchCount) return;
  } catch (error) {
    if (error instanceof TempStorageLimitError) throw new AggregateLimitError();
  }
  throw new SnapshotIntegrityError();
}

export async function getAggregateNodeSource(
  db: D1Database, bucket: R2Bucket, code: string, legacyOnly = false, signal?: AbortSignal,
): Promise<AggregateNodeSource | null> {
  const digest = await codeDigest(code);
  if (digest === null) return null;
  if (signal?.aborted) throw new SnapshotIntegrityError();
  const [schema, tempStorage] = await Promise.all([readShortLinkNamespaces(db), readTempStorage(db).catch(() => null)]);
  if (signal?.aborted) throw new SnapshotIntegrityError();
  const withLink = `WITH link AS (SELECT owner_id, kind, bot_id, selected_ids,
    ${legacySelectedStatusSql(schema)} AS legacySelected,${legacyAllStatusSql(schema)} AS legacyAll ${aggregateLinkSql(schema)})`;
  const readLegacy = code.length === 12 && schema.selectedMarker && schema.selectedMembers
    && schema.migrationLedger && schema.normal && schema.legacySubscription;
  const readLegacyAll = code.length === 12 && schema.allMarker && schema.allOrder;
  const readEmpty = schema.legacyEmpty && schema.migrationLedger;
  const mode = tempStorage ?? "live-only";
  const tempReady = tempStorage === null ? "0" : tempSchemaGuard(mode);
  const withTemp = `${withLink}, temp_scope AS (
    SELECT bot_id,owner_id AS actor_id,NULL AS before_receipt,NULL AS visibility_epoch
    FROM link WHERE kind='all' AND legacyAll>=0 AND (legacyAll=0 OR ${code.length === 12 ? 1 : 0}) AND (${tempReady})
  )`;
  const tempTotals = `SELECT count(*) AS batchCount,COALESCE(sum(nodeCount),0) AS nodeCount,COALESCE(sum(bytes),0) AS bytes
    FROM (${ownedTempRowsSql(mode, "temp_scope", { verifyLive: false })})`;
  const ownedAll = `FROM link JOIN subscriptions AS sub ON sub.owner_id=link.owner_id
    WHERE link.kind='all' AND link.legacyAll>=0 AND sub.generation>0 ORDER BY sub.id LIMIT ?`;
  const allPointers = readLegacyAll ? `${withLink}, owned AS (
    SELECT ${pointerColumns},sub.token,link.legacyAll ${ownedAll}
  ) SELECT owned.id,owned.generation,owned.snapshotId,owned.manifestSha256,owned.nodeCount,
    rank.owner_id AS rankOwner,rank.anchor,rank.tie,
    CASE WHEN owned.legacyAll=1 THEN EXISTS (SELECT 1 FROM subscription_trash AS trash
      WHERE trash.id=owned.id OR trash.token=owned.token) ELSE 0 END AS hasTrash
    FROM owned LEFT JOIN legacy_all_subscription_order AS rank /* subs-bot:legacy-dynamic-all-read:v1 */
      ON owned.legacyAll=1 AND rank.subscription_id=owned.id ORDER BY owned.id`
    : `${withLink} SELECT ${pointerColumns} ${ownedAll}`;
  // All inputs come from one D1 transaction. Each statement starts at the same digest
  // and only the matching owner can contribute a subscription or temporary batch.
  const results = await db.batch<Row>([
    db.prepare(`${withLink} SELECT kind,owner_id AS ownerId,selected_ids AS selectedIds,legacySelected,legacyAll,
      CASE WHEN kind='all' THEN (${tempReady}) ELSE 1 END AS tempReady,
      CASE WHEN legacyAll=1 THEN (SELECT CASE WHEN count(*)=1 AND typeof(min(seq))='integer' THEN min(seq) END
        FROM sqlite_sequence WHERE name='subscriptions') END AS rankHighWater FROM link`).bind(digest),
    db.prepare(allPointers).bind(digest, MAX_AGGREGATE_MEMBERS + 1),
    db.prepare(`${withLink}
      SELECT ${pointerColumns} FROM link JOIN json_each(link.selected_ids) AS member
      JOIN subscriptions AS sub ON sub.owner_id = link.owner_id AND sub.id = member.value
      WHERE link.kind = 'selected' AND link.legacySelected=0 AND member.type = 'integer' AND sub.generation > 0
      ORDER BY CAST(member.key AS INTEGER) LIMIT ?
    `).bind(digest, MAX_AGGREGATE_MEMBERS + 1),
    db.prepare(`${withTemp} ${tempTotals}`).bind(digest),
    db.prepare(`${withTemp}, totals AS (${tempTotals})
      SELECT temp.* FROM totals CROSS JOIN (${ownedTempRowsSql(mode, "temp_scope", { includePayload: true, verifyLive: false })}) AS temp
      WHERE totals.nodeCount <= ? AND totals.bytes <= ? ORDER BY temp.source,temp.id LIMIT ?
    `).bind(digest, MAX_TEMP_OWNER_NODES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES + 1),
    db.prepare(`${withLink}
      SELECT rule.id, rule.keyword, rule.remark FROM link
      JOIN path_rules AS rule ON rule.owner_id = link.owner_id ORDER BY rule.id LIMIT ?
    `).bind(digest, MAX_PATH_RULES + 1),
    ...(readLegacy ? [db.prepare(`${withLink}
      SELECT /* subs-bot:legacy-selected-http:v1 */ CAST(member.key AS INTEGER) AS position,
        member.value AS selectedId,watch.retired,${pointerColumns},
        ${readEmpty ? "CASE WHEN legacy_empty.token_sha256 IS NOT NULL THEN sub.token END" : "NULL"} AS emptyToken,
        ${readEmpty ? "legacy_empty.token_sha256" : "NULL"} AS emptyTokenSha256
      FROM link JOIN json_each(link.selected_ids) AS member
      LEFT JOIN legacy_selected_members AS watch ON watch.id=member.value
      LEFT JOIN subscriptions AS sub ON watch.retired=0 AND sub.owner_id=link.owner_id AND sub.id=member.value
        AND NOT EXISTS (SELECT 1 FROM subscription_trash AS trash WHERE trash.id=sub.id)
        AND NOT EXISTS (SELECT 1 FROM subscription_trash AS trash WHERE trash.token=sub.token)
      ${readEmpty ? `LEFT JOIN legacy_empty_subscription_exports AS legacy_empty ON sub.generation=0
        AND legacy_empty.subscription_id=sub.id AND legacy_empty.owner_id=sub.owner_id AND ${LEGACY_EMPTY_EXPORT_PIN}` : ""}
      WHERE link.legacySelected=1 AND member.type='integer'
      ORDER BY CAST(member.key AS INTEGER) LIMIT ?`).bind(digest, MAX_AGGREGATE_MEMBERS + 1)] : []),
  ]);
  if (signal?.aborted) throw new SnapshotIntegrityError();
  if (results.length !== (readLegacy ? 7 : 6) || results.some(({ success }) => !success)) throw new SnapshotIntegrityError();
  const [linkResult, allResult, selectedResult, totalsResult, tempResult, ruleResult, legacyResult] = results;
  const link = linkResult.results[0] as LinkRow | undefined;
  if (!link) return null;
  const namespace = aggregateNamespace(code.length, link.legacySelected, link.legacyAll);
  if (namespace === null || (namespace === "legacy-selected" && !readLegacy)
      || (namespace === "legacy-all" && !readLegacyAll)) return null;
  const legacyAggregate = namespace !== "native";
  if (legacyOnly && !legacyAggregate) return null;
  if (link.tempReady !== 1) throw new SnapshotIntegrityError();
  const ids = link.kind === "selected" ? selectionIds(link.selectedIds) : null;
  if (link.kind !== "all" && ids === null) throw new SnapshotIntegrityError();
  const snapshots = namespace === "legacy-selected" && ids ? await legacySnapshots(ids, legacyResult.results as LegacyMember[])
    : namespace === "legacy-all" ? legacyAllSnapshots(link, allResult.results as LegacyAllPointer[])
    : (link.kind === "all" ? allResult.results : selectedResult.results) as SubscriptionSnapshot[];
  const totals = totalsResult.results[0] as TempTotals | undefined;
  const temp = tempResult.results as TempBatchRow[];
  if (!totals) throw new SnapshotIntegrityError();
  verifyTemp(totals, temp);

  if (snapshots.length > MAX_AGGREGATE_MEMBERS) throw new AggregateLimitError();
  let nodeCount = totals.nodeCount;
  for (const snapshot of snapshots) {
    if (!validInteger(snapshot.nodeCount, 1, MAX_SNAPSHOT_NODES)) throw new SnapshotIntegrityError();
    nodeCount += snapshot.nodeCount;
  }
  if (nodeCount > MAX_SNAPSHOT_NODES) throw new AggregateLimitError();
  if (nodeCount === 0 && !legacyAggregate) return null;
  const rules = snapshots.length > 0 ? compilePathRules(ruleResult.results as PathRuleRow[]) : [];

  const plans: SnapshotReadPlan[] = [];
  let bytes = totals.bytes;
  let chunks = 0;
  for (const snapshot of snapshots) {
    if (signal?.aborted) throw new SnapshotIntegrityError();
    const plan = await planSnapshotRead(bucket, snapshot);
    bytes += plan.bytes;
    chunks += plan.chunks.length;
    if (bytes > MAX_SNAPSHOT_BYTES || chunks > MAX_SNAPSHOT_CHUNKS) throw new AggregateLimitError();
    plans.push(plan);
  }
  if (signal?.aborted) throw new SnapshotIntegrityError();

  return {
    nodeCount,
    legacyAggregate,
    async *read(signal) {
      // Process sources sequentially so their R2 read-ahead windows never multiply.
      const map = pathRuleMapper(rules);
      for (const plan of plans) {
        if (signal?.aborted) return;
        for await (const node of readPlannedSnapshotNodes(bucket, plan, signal)) yield map(node);
      }
      for (const batch of temp) {
        if (signal?.aborted) return;
        let nodes: NodeRecord[];
        try {
          nodes = await readTempBatchNodes(batch);
        } catch {
          throw new SnapshotIntegrityError();
        }
        for (const node of nodes) {
          if (signal?.aborted) return;
          yield node;
        }
      }
    },
  };
}

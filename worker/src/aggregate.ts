import {
  digestHex, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_CHUNKS, MAX_SNAPSHOT_NODES,
  planSnapshotRead, readPlannedSnapshotNodes, SnapshotIntegrityError, validInteger,
  type ExportNodeSource, type NodeRecord, type SnapshotReadPlan, type SubscriptionSnapshot,
} from "./storage.ts";
import { MAX_TEMP_BATCH_BYTES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES } from "./telegram/temp-import.ts";
import { compilePathRules, MAX_PATH_RULES, pathRuleMapper, type PathRuleRow } from "./path-rules.ts";
import { legacySelectedStatusSql, readShortLinkNamespaces, SHORT_CODE, shortCodeDigest } from "./short-links.ts";
import { LEGACY_EMPTY_EXPORT_PIN } from "./legacy-empty-export.ts";

const EMPTY_TOKEN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
export const MAX_AGGREGATE_MEMBERS = 128;
const encoder = new TextEncoder();
const activeLink = "FROM aggregate_links WHERE code_sha256 = ? AND revoked_at IS NULL";
const ownerTemp = `FROM link JOIN telegram_temp_batch AS temp
  ON temp.bot_id = link.bot_id AND temp.actor_id = link.owner_id WHERE link.kind = 'all'`;
const tempTotals = `SELECT count(*) AS batchCount, COALESCE(sum(node_count), 0) AS nodeCount,
  COALESCE(sum(payload_bytes), 0) AS bytes ${ownerTemp}`;
const pointerColumns = `sub.id, sub.generation, sub.snapshot_id AS snapshotId,
  sub.manifest_sha256 AS manifestSha256, sub.node_count AS nodeCount`;

interface LinkRow { kind: "all" | "selected"; selectedIds: string | null; legacySelected: number }
interface TempTotals { batchCount: number; nodeCount: number; bytes: number }
interface TempRow { json: string; nodeCount: number; bytes: number }
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
type Row = LinkRow | SubscriptionSnapshot | TempTotals | TempRow | PathRuleRow | LegacyMember;
interface AggregateNodeSource extends ExportNodeSource { readonly legacySelected: boolean }

export class AggregateLimitError extends Error {}

async function codeDigest(code: string): Promise<string | null> {
  return typeof code === "string" && SHORT_CODE.test(code) ? shortCodeDigest(code) : null;
}

export async function hasAggregateLink(db: D1Database, code: string): Promise<boolean> {
  const digest = await codeDigest(code);
  if (digest === null) return false;
  return await db.prepare(`SELECT 1 ${activeLink}`).bind(digest).first() !== null;
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

function verifyTemp(totals: TempTotals, rows: TempRow[]): void {
  if (!validInteger(totals.batchCount, 0) || !validInteger(totals.nodeCount, 0) || !validInteger(totals.bytes, 0)) {
    throw new SnapshotIntegrityError();
  }
  if (totals.nodeCount > MAX_TEMP_OWNER_NODES || totals.bytes > MAX_TEMP_OWNER_BYTES) throw new AggregateLimitError();
  let nodes = 0;
  let bytes = 0;
  for (const row of rows) {
    if (typeof row.json !== "string" || !validInteger(row.nodeCount, 1, 500) ||
        !validInteger(row.bytes, 1, MAX_TEMP_BATCH_BYTES) || encoder.encode(row.json).length !== row.bytes) {
      throw new SnapshotIntegrityError();
    }
    nodes += row.nodeCount;
    bytes += row.bytes;
  }
  if (nodes !== totals.nodeCount || bytes !== totals.bytes || rows.length !== totals.batchCount) {
    throw new SnapshotIntegrityError();
  }
}

function* readTemp({ json, nodeCount }: TempRow): Generator<NodeRecord> {
  try {
    const nodes: unknown = JSON.parse(json);
    if (!Array.isArray(nodes) || nodes.length !== nodeCount) throw new SnapshotIntegrityError();
    for (const node of nodes) {
      if (typeof node !== "object" || node === null || Array.isArray(node)) throw new SnapshotIntegrityError();
      yield node as NodeRecord;
    }
  } catch {
    throw new SnapshotIntegrityError();
  }
}

export async function getAggregateNodeSource(
  db: D1Database, bucket: R2Bucket, code: string, legacyOnly = false,
): Promise<AggregateNodeSource | null> {
  const digest = await codeDigest(code);
  if (digest === null) return null;
  const schema = await readShortLinkNamespaces(db);
  const availableLink = `${activeLink}
    ${schema.normal ? "AND NOT EXISTS (SELECT 1 FROM normal_short_links AS normal WHERE normal.code_sha256=aggregate_links.code_sha256)" : ""}
    ${schema.legacySubscription ? `AND NOT EXISTS (SELECT 1 FROM legacy_subscription_short_links AS legacy
      WHERE legacy.code_sha256=aggregate_links.code_sha256)` : ""}`;
  const withLink = `WITH link AS (SELECT owner_id, kind, bot_id, selected_ids,
    ${legacySelectedStatusSql(schema)} AS legacySelected ${availableLink})`;
  const readLegacy = code.length === 12 && schema.selectedMarker && schema.selectedMembers
    && schema.migrationLedger && schema.normal && schema.legacySubscription;
  const readEmpty = schema.legacyEmpty && schema.migrationLedger;
  // All inputs come from one D1 transaction. Each statement starts at the same digest
  // and only the matching owner can contribute a subscription or temporary batch.
  const results = await db.batch<Row>([
    db.prepare(`${withLink} SELECT kind, selected_ids AS selectedIds, legacySelected FROM link`).bind(digest),
    db.prepare(`${withLink}
      SELECT ${pointerColumns} FROM link JOIN subscriptions AS sub ON sub.owner_id = link.owner_id
      WHERE link.kind = 'all' AND sub.generation > 0 ORDER BY sub.id LIMIT ?
    `).bind(digest, MAX_AGGREGATE_MEMBERS + 1),
    db.prepare(`${withLink}
      SELECT ${pointerColumns} FROM link JOIN json_each(link.selected_ids) AS member
      JOIN subscriptions AS sub ON sub.owner_id = link.owner_id AND sub.id = member.value
      WHERE link.kind = 'selected' AND link.legacySelected=0 AND member.type = 'integer' AND sub.generation > 0
      ORDER BY CAST(member.key AS INTEGER) LIMIT ?
    `).bind(digest, MAX_AGGREGATE_MEMBERS + 1),
    db.prepare(`${withLink} ${tempTotals}`).bind(digest),
    db.prepare(`${withLink}, totals AS (${tempTotals})
      SELECT temp.nodes_json AS json, temp.node_count AS nodeCount, temp.payload_bytes AS bytes
      FROM link JOIN telegram_temp_batch AS temp
        ON temp.bot_id = link.bot_id AND temp.actor_id = link.owner_id
      CROSS JOIN totals
      WHERE link.kind = 'all' AND totals.nodeCount <= ? AND totals.bytes <= ?
      ORDER BY temp.receipt_id LIMIT ?
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
        AND NOT EXISTS (SELECT 1 FROM subscription_trash AS trash WHERE trash.id=sub.id OR trash.token=sub.token)
      ${readEmpty ? `LEFT JOIN legacy_empty_subscription_exports AS legacy_empty ON sub.generation=0
        AND legacy_empty.subscription_id=sub.id AND legacy_empty.owner_id=sub.owner_id AND ${LEGACY_EMPTY_EXPORT_PIN}` : ""}
      WHERE link.legacySelected=1 AND member.type='integer'
      ORDER BY CAST(member.key AS INTEGER) LIMIT ?`).bind(digest, MAX_AGGREGATE_MEMBERS + 1)] : []),
  ]);
  if (results.length !== (readLegacy ? 7 : 6) || results.some(({ success }) => !success)) throw new SnapshotIntegrityError();
  const [linkResult, allResult, selectedResult, totalsResult, tempResult, ruleResult, legacyResult] = results;
  const link = linkResult.results[0] as LinkRow | undefined;
  if (!link) return null;
  const legacySelected = link.legacySelected === 1 && readLegacy;
  if (link.legacySelected !== 0 && !legacySelected) return null;
  if (legacyOnly && !legacySelected) return null;
  const ids = link.kind === "selected" ? selectionIds(link.selectedIds) : null;
  if (link.kind !== "all" && ids === null) throw new SnapshotIntegrityError();
  const snapshots = legacySelected && ids ? await legacySnapshots(ids, legacyResult.results as LegacyMember[])
    : (link.kind === "all" ? allResult.results : selectedResult.results) as SubscriptionSnapshot[];
  const totals = totalsResult.results[0] as TempTotals | undefined;
  const temp = tempResult.results as TempRow[];
  if (!totals) throw new SnapshotIntegrityError();
  verifyTemp(totals, temp);

  if (snapshots.length > MAX_AGGREGATE_MEMBERS) throw new AggregateLimitError();
  let nodeCount = totals.nodeCount;
  for (const snapshot of snapshots) {
    if (!validInteger(snapshot.nodeCount, 1, MAX_SNAPSHOT_NODES)) throw new SnapshotIntegrityError();
    nodeCount += snapshot.nodeCount;
  }
  if (nodeCount > MAX_SNAPSHOT_NODES) throw new AggregateLimitError();
  if (nodeCount === 0 && !legacySelected) return null;
  const rules = snapshots.length > 0 ? compilePathRules(ruleResult.results as PathRuleRow[]) : [];

  const plans: SnapshotReadPlan[] = [];
  let bytes = totals.bytes;
  let chunks = 0;
  for (const snapshot of snapshots) {
    const plan = await planSnapshotRead(bucket, snapshot);
    bytes += plan.bytes;
    chunks += plan.chunks.length;
    if (bytes > MAX_SNAPSHOT_BYTES || chunks > MAX_SNAPSHOT_CHUNKS) throw new AggregateLimitError();
    plans.push(plan);
  }

  return {
    nodeCount,
    legacySelected,
    async *read(signal) {
      // Process sources sequentially so their R2 read-ahead windows never multiply.
      const map = pathRuleMapper(rules);
      for (const plan of plans) {
        if (signal?.aborted) return;
        for await (const node of readPlannedSnapshotNodes(bucket, plan, signal)) yield map(node);
      }
      for (const batch of temp) {
        if (signal?.aborted) return;
        for (const node of readTemp(batch)) {
          if (signal?.aborted) return;
          yield node;
        }
      }
    },
  };
}

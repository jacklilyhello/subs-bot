import {
  digestHex, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_CHUNKS, MAX_SNAPSHOT_NODES,
  planSnapshotRead, readPlannedSnapshotNodes, SnapshotIntegrityError, validInteger,
  type ExportNodeSource, type NodeRecord, type SnapshotReadPlan, type SubscriptionSnapshot,
} from "./storage.ts";
import { MAX_TEMP_BATCH_BYTES, MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES } from "./telegram/temp-import.ts";
import { compilePathRules, MAX_PATH_RULES, pathRuleMapper, type PathRuleRow } from "./path-rules.ts";

const CODE = /^(?:[A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{22})(?![\s\S])/u;
const MAX_MEMBERS = 128;
const encoder = new TextEncoder();
const activeLink = "FROM aggregate_links WHERE code_sha256 = ? AND revoked_at IS NULL";
const ownerTemp = `FROM link JOIN telegram_temp_batch AS temp
  ON temp.bot_id = link.bot_id AND temp.actor_id = link.owner_id WHERE link.kind = 'all'`;
const tempTotals = `SELECT count(*) AS batchCount, COALESCE(sum(node_count), 0) AS nodeCount,
  COALESCE(sum(payload_bytes), 0) AS bytes ${ownerTemp}`;
const pointerColumns = `sub.id, sub.generation, sub.snapshot_id AS snapshotId,
  sub.manifest_sha256 AS manifestSha256, sub.node_count AS nodeCount`;

interface LinkRow { kind: "all" | "selected"; selectedIds: string | null }
interface TempTotals { batchCount: number; nodeCount: number; bytes: number }
interface TempRow { json: string; nodeCount: number; bytes: number }
type Row = LinkRow | SubscriptionSnapshot | TempTotals | TempRow | PathRuleRow;

export class AggregateLimitError extends Error {}

async function codeDigest(code: string): Promise<string | null> {
  if (typeof code !== "string" || !CODE.test(code)) return null;
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(code)));
}

export async function hasAggregateLink(db: D1Database, code: string): Promise<boolean> {
  const digest = await codeDigest(code);
  if (digest === null) return false;
  return await db.prepare(`SELECT 1 ${activeLink}`).bind(digest).first() !== null;
}

function validSelection(selection: string | null): boolean {
  if (selection === null) return false;
  try {
    const ids: unknown = JSON.parse(selection);
    return Array.isArray(ids) && ids.length > 0 && ids.length <= MAX_MEMBERS && ids.every((id) => validInteger(id, 1));
  } catch {
    return false;
  }
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

export async function getAggregateNodeSource(db: D1Database, bucket: R2Bucket, code: string): Promise<ExportNodeSource | null> {
  const digest = await codeDigest(code);
  if (digest === null) return null;
  const withLink = `WITH link AS (SELECT owner_id, kind, bot_id, selected_ids ${activeLink})`;
  // All inputs come from one D1 transaction. Each statement starts at the same digest
  // and only the matching owner can contribute a subscription or temporary batch.
  const results = await db.batch<Row>([
    db.prepare(`SELECT kind, selected_ids AS selectedIds ${activeLink}`).bind(digest),
    db.prepare(`${withLink}
      SELECT ${pointerColumns} FROM link JOIN subscriptions AS sub ON sub.owner_id = link.owner_id
      WHERE link.kind = 'all' AND sub.generation > 0 ORDER BY sub.id LIMIT ?
    `).bind(digest, MAX_MEMBERS + 1),
    db.prepare(`${withLink}
      SELECT ${pointerColumns} FROM link JOIN json_each(link.selected_ids) AS member
      JOIN subscriptions AS sub ON sub.owner_id = link.owner_id AND sub.id = member.value
      WHERE link.kind = 'selected' AND member.type = 'integer' AND sub.generation > 0
      ORDER BY CAST(member.key AS INTEGER) LIMIT ?
    `).bind(digest, MAX_MEMBERS + 1),
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
  ]);
  if (results.length !== 6 || results.some(({ success }) => !success)) throw new SnapshotIntegrityError();
  const [linkResult, allResult, selectedResult, totalsResult, tempResult, ruleResult] = results;
  const link = linkResult.results[0] as LinkRow | undefined;
  if (!link) return null;
  if (link.kind !== "all" && (link.kind !== "selected" || !validSelection(link.selectedIds))) {
    throw new SnapshotIntegrityError();
  }
  const snapshots = (link.kind === "all" ? allResult.results : selectedResult.results) as SubscriptionSnapshot[];
  const totals = totalsResult.results[0] as TempTotals | undefined;
  const temp = tempResult.results as TempRow[];
  if (!totals) throw new SnapshotIntegrityError();
  verifyTemp(totals, temp);

  if (snapshots.length > MAX_MEMBERS) throw new AggregateLimitError();
  let nodeCount = totals.nodeCount;
  for (const snapshot of snapshots) {
    if (!validInteger(snapshot.nodeCount, 1, MAX_SNAPSHOT_NODES)) throw new SnapshotIntegrityError();
    nodeCount += snapshot.nodeCount;
  }
  if (nodeCount > MAX_SNAPSHOT_NODES) throw new AggregateLimitError();
  if (nodeCount === 0) return null;
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

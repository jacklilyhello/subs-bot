import { readSnapshotNodes, SnapshotIntegrityError, validInteger,
  type ExportNodeSource, type NodeRecord, type SubscriptionSnapshot } from "./storage.ts";
import { FULL_CASE_FOLD } from "./unicode14-casefold.ts";

export const MAX_PATH_RULES = 64;
const MAX_PATH_RULE_WORK = 64 * 1024 * 1024;
const MAX_RULE_SCALARS = 128;
const pythonWhitespace = "[\u0009-\u000d\u001c-\u0020\u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]";
const pythonTrim = new RegExp(`^${pythonWhitespace}+|${pythonWhitespace}+$`, "gu");
const nonScalar = /[\u0000\ud800-\udfff]/u;
const caseFoldScalars = new RegExp("[" + Object.keys(FULL_CASE_FOLD)
  .map((character) => "\\u{" + character.codePointAt(0)!.toString(16) + "}").join("") + "]", "gu");

export interface PathRuleRow { id: number; keyword: string; remark: string }
interface PathRule { keyword: string; remark: string; length: number; id: number }

export class PathRuleContentError extends Error {}

export function foldPathText(value: string): string {
  return value.replace(caseFoldScalars, (character) => FULL_CASE_FOLD[character]);
}

function ruleText(value: unknown): string {
  if (typeof value !== "string" || nonScalar.test(value) || Array.from(value).length > MAX_RULE_SCALARS) {
    throw new SnapshotIntegrityError();
  }
  const trimmed = value.replace(pythonTrim, "");
  if (!trimmed) throw new SnapshotIntegrityError();
  return trimmed;
}

export function compilePathRules(rows: readonly PathRuleRow[]): readonly PathRule[] {
  if (rows.length > MAX_PATH_RULES) throw new PathRuleContentError();
  let lastId = 0;
  const rules = rows.map(({ id, keyword, remark }) => {
    if (!validInteger(id, lastId + 1)) throw new SnapshotIntegrityError();
    lastId = id;
    const folded = foldPathText(ruleText(keyword));
    return { id, keyword: folded, length: Array.from(folded).length, remark: ruleText(remark) };
  });
  return rules.sort((left, right) => right.length - left.length || left.id - right.id);
}

function matchField(value: unknown): string {
  if (value === undefined || value === null) return "";
  if (typeof value !== "string") throw new PathRuleContentError();
  return value;
}

// Each replay has its own budget. An aggregate uses one budget across all its
// subscription snapshots and never passes temporary nodes to this mapper.
export function pathRuleMapper(rules: readonly PathRule[]): (node: NodeRecord) => NodeRecord {
  if (rules.length === 0) return (node) => node;
  let work = 0;
  const charge = (units: number) => {
    work += units;
    if (work > MAX_PATH_RULE_WORK) throw new PathRuleContentError();
  };
  return (node) => {
    const name = matchField(node.name);
    const server = matchField(node.server);
    const share = matchField(node.share);
    charge(name.length + server.length + share.length + 2);
    const folded = foldPathText(`${name} ${server} ${share}`);
    for (const rule of rules) {
      charge(folded.length);
      if (!folded.includes(rule.keyword)) continue;
      const label = `${name} → ${rule.remark}`;
      // The structured Base64 serializer treats a valid native tag as an alias.
      // Preserve its validity and leave previously conflicting aliases visible.
      if (typeof node.tag === "string" && node.tag !== "" && !nonScalar.test(node.tag) && (!name || name === node.tag)) {
        return { ...node, name: label, tag: label };
      }
      return { ...node, name: label };
    }
    return node;
  };
}

export async function getSubscriptionNodeSource(
  db: D1Database, bucket: R2Bucket, token: string,
): Promise<ExportNodeSource | null> {
  const results = await db.batch<SubscriptionSnapshot | PathRuleRow>([
    db.prepare(`SELECT id, generation, snapshot_id AS snapshotId, manifest_sha256 AS manifestSha256, node_count AS nodeCount
      FROM subscriptions WHERE token = ? AND generation > 0`).bind(token),
    db.prepare(`SELECT rule.id, rule.keyword, rule.remark FROM subscriptions AS sub
      JOIN path_rules AS rule ON rule.owner_id = sub.owner_id
      WHERE sub.token = ? AND sub.generation > 0 ORDER BY rule.id LIMIT ?`).bind(token, MAX_PATH_RULES + 1),
  ]);
  if (results.length !== 2 || results.some(({ success }) => !success)) throw new SnapshotIntegrityError();
  const snapshot = results[0].results[0] as SubscriptionSnapshot | undefined;
  if (!snapshot) return null;
  const rules = compilePathRules(results[1].results as PathRuleRow[]);
  return {
    nodeCount: snapshot.nodeCount,
    async *read(signal) {
      const map = pathRuleMapper(rules);
      for await (const node of readSnapshotNodes(bucket, snapshot, signal)) yield map(node);
    },
  };
}

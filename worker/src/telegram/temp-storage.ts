import { digestHex, validInteger, type NodeRecord } from "../storage.ts";
import { isValidStoredShare } from "../stored-share.ts";

export const TELEGRAM_TEMP_MARKER = "temp:v1";
export const MAX_TEMP_BATCH_BYTES = 256 * 1024;
export const MAX_TEMP_OWNER_NODES = 5_000;
export const MAX_TEMP_OWNER_BYTES = 4 * 1024 * 1024;
export const MAX_TEMP_BATCH_NODES = 500;
export const LEGACY_TEMP_MIGRATION_NAME = "0039_legacy_temp_baseline.sql";
export const LEGACY_TEMP_MIGRATION_SHA256 = "4a5253618caf42baf997301d4e27c1d11f15166dadf48740d1c7d60da3af82d6";

const tables = "'legacy_temp_installations','legacy_temp_batches'";
const migration = `position=39 OR name='${LEGACY_TEMP_MIGRATION_NAME}'`;
const exactPin = `position=39 AND name='${LEGACY_TEMP_MIGRATION_NAME}' AND sha256='${LEGACY_TEMP_MIGRATION_SHA256}' AND mode='applied'`;
const digest = /^[a-f0-9]{64}(?![\s\S])/u;
const encoder = new TextEncoder();

export type TempStorageMode = "live-only" | "legacy-ready";

export class TempStorageIntegrityError extends Error {}
export class TempStorageLimitError extends Error {}

export interface TempBatchMeta {
  source: 0 | 1;
  id: number;
  lastId: number;
  date: number;
  message: number;
  nodeCount: number;
  bytes: number;
  sha256: string | null;
  accepted: number;
}

export interface TempBatchRow extends TempBatchMeta { json: string }

/** Detect absent, current and partial schemas without preparing SQL against absent tables. */
export async function readTempStorage(db: D1Database): Promise<TempStorageMode> {
  const schema = await db.prepare(`SELECT count(CASE WHEN name IN (${tables}) THEN 1 END) AS objects,
    count(CASE WHEN name IN (${tables}) AND type='table' THEN 1 END) AS tables,
    count(CASE WHEN name='subs_bot_schema_migrations' AND type='table' THEN 1 END) AS ledger
    FROM main.sqlite_schema WHERE name IN (${tables},'subs_bot_schema_migrations')`)
    .first<{ objects: number; tables: number; ledger: number }>();
  if (!schema || ![0, 2].includes(schema.tables) || schema.objects !== schema.tables
    || ![0, 1].includes(schema.ledger) || (schema.tables === 2 && schema.ledger !== 1)) throw new TempStorageIntegrityError();
  if (schema.ledger === 0) return "live-only";
  const pin = await db.prepare(`SELECT count(*) AS pins,COALESCE(sum(${exactPin}),0) AS exact
    FROM subs_bot_schema_migrations WHERE ${migration}`).first<{ pins: number; exact: number }>();
  if (schema.tables === 0 && pin?.pins === 0) return "live-only";
  if (schema.tables === 2 && pin?.pins === 1 && pin.exact === 1) return "legacy-ready";
  throw new TempStorageIntegrityError();
}

/** Same-snapshot readiness predicate for callers that prepared an optional branch. */
export function tempSchemaGuard(mode: TempStorageMode): string {
  if (mode === "live-only") return `NOT EXISTS (SELECT 1 FROM main.sqlite_schema WHERE name IN (${tables}))`;
  return `(SELECT count(*) FROM main.sqlite_schema WHERE type='table' AND name IN (${tables}))=2
    AND (SELECT count(*) FROM subs_bot_schema_migrations WHERE ${migration})=1
    AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE ${exactPin})`;
}

/** Message epochs at or before the protected activation cannot access its baseline. */
export function tempCutoverAllows(mode: TempStorageMode, botSql: string, dateSql: string): string {
  return mode === "legacy-ready" ? `NOT EXISTS (SELECT 1 FROM legacy_temp_installations AS installation
    WHERE installation.bot_id=${botSql} AND installation.cutover_epoch>=${dateSql})` : "1";
}

/** The trusted scope CTE exposes bot_id, actor_id, before_receipt and visibility_epoch. */
export function ownedTempRowsSql(mode: TempStorageMode, scopeCte: string, options: {
  includePayload?: boolean; verifyLive?: boolean; keysCte?: string;
} = {}): string {
  const payload = options.includePayload ? ",batch.nodes_json AS json" : "";
  const keyJoin = (source: 0 | 1, id: string) => options.keysCte
    ? `JOIN ${options.keysCte} AS keys ON keys.source=${source} AND keys.id=${id}` : "";
  const proof = options.verifyLive ? `LEFT JOIN telegram_inbox AS paste ON paste.receipt_id=batch.receipt_id
    AND paste.bot_id=batch.bot_id AND paste.actor_id=batch.actor_id AND paste.chat_id=batch.actor_id
    AND paste.chat_type='private' AND paste.thread_id IS NULL AND paste.command='help'
    AND paste.message_date=batch.message_date AND paste.message_id=batch.message_id AND paste.receipt_nonce='${TELEGRAM_TEMP_MARKER}'
    LEFT JOIN telegram_temp_reply AS added ON added.receipt_id=paste.receipt_id AND added.kind='added'
    AND added.node_count=batch.node_count` : "";
  const live = `SELECT 1 AS source,batch.receipt_id AS id,batch.receipt_id AS lastId,batch.message_date AS date,
    batch.message_id AS message,batch.node_count AS nodeCount,batch.payload_bytes AS bytes,NULL AS sha256,
    ${options.verifyLive ? "added.receipt_id IS NOT NULL" : "1"} AS accepted${payload}
    FROM ${scopeCte} AS scope JOIN telegram_temp_batch AS batch ON batch.bot_id=scope.bot_id AND batch.actor_id=scope.actor_id
    AND (scope.before_receipt IS NULL OR batch.receipt_id<scope.before_receipt)
    ${keyJoin(1, "batch.receipt_id")} ${proof}`;
  if (mode === "live-only") return live;
  return `SELECT /* subs-bot:legacy-temp-read:v1 */ 0 AS source,batch.first_legacy_id AS id,batch.last_legacy_id AS lastId,
    installation.cutover_epoch AS date,0 AS message,batch.node_count AS nodeCount,batch.payload_bytes AS bytes,
    batch.payload_sha256 AS sha256,1 AS accepted${payload}
    FROM ${scopeCte} AS scope JOIN legacy_temp_installations AS installation ON installation.bot_id=scope.bot_id
    AND installation.cutover_epoch IS NOT NULL AND (scope.visibility_epoch IS NULL OR installation.cutover_epoch<scope.visibility_epoch)
    JOIN legacy_temp_batches AS batch ON batch.bot_id=installation.bot_id AND batch.actor_id=scope.actor_id
    ${keyJoin(0, "batch.first_legacy_id")} UNION ALL ${live}`;
}

export function verifyTempInventory(rows: readonly TempBatchMeta[]): { nodeCount: number; bytes: number } {
  if (rows.length > MAX_TEMP_OWNER_NODES) throw new TempStorageLimitError();
  let previous: TempBatchMeta | undefined;
  let nodeCount = 0;
  let bytes = 0;
  for (const row of rows) {
    if ((row.source !== 0 && row.source !== 1) || row.accepted !== 1
      || !validInteger(row.id, 1) || !validInteger(row.lastId, row.id) || !validInteger(row.date, 1)
      || !validInteger(row.nodeCount, 1, MAX_TEMP_BATCH_NODES) || !validInteger(row.bytes, 1, MAX_TEMP_BATCH_BYTES)
      || (previous && (previous.source > row.source || (previous.source === row.source && previous.lastId >= row.id)))) {
      throw new TempStorageIntegrityError();
    }
    if (row.source === 0 ? (row.message !== 0 || typeof row.sha256 !== "string" || !digest.test(row.sha256)
        || row.nodeCount > row.lastId - row.id + 1 || (previous?.source === 0 && previous.date !== row.date))
      : (row.lastId !== row.id || !validInteger(row.message, 1) || row.sha256 !== null)) throw new TempStorageIntegrityError();
    nodeCount += row.nodeCount;
    bytes += row.bytes;
    if (nodeCount > MAX_TEMP_OWNER_NODES || bytes > MAX_TEMP_OWNER_BYTES) throw new TempStorageLimitError();
    previous = row;
  }
  return { nodeCount, bytes };
}

export async function readTempBatchNodes(row: TempBatchRow, { requireStoredShare = false } = {}): Promise<NodeRecord[]> {
  if (typeof row.json !== "string") throw new TempStorageIntegrityError();
  const body = encoder.encode(row.json);
  if (body.length !== row.bytes || (row.source === 0 && digestHex(await crypto.subtle.digest("SHA-256", body)) !== row.sha256)) {
    throw new TempStorageIntegrityError();
  }
  try {
    const nodes: unknown = JSON.parse(row.json);
    if (!Array.isArray(nodes) || nodes.length !== row.nodeCount
      || (row.source === 0 && JSON.stringify(nodes) !== row.json)) throw new TempStorageIntegrityError();
    for (const node of nodes) {
      if (typeof node !== "object" || node === null || Array.isArray(node)
        || ((row.source === 0 || requireStoredShare) && !isValidStoredShare(node.share))
        || (row.source === 0 && (typeof node.name !== "string" || node.type !== "temp" || Object.keys(node).length !== 3))) {
        throw new TempStorageIntegrityError();
      }
    }
    return nodes as NodeRecord[];
  } catch {
    throw new TempStorageIntegrityError();
  }
}

/** Recheck the exact owner inventory before a private raw or inline send starts. */
export function tempInventoryGuard(mode: TempStorageMode, scopeSelect: string, rows: readonly TempBatchMeta[]) {
  const expected = JSON.stringify(rows.map((row) => [row.source, row.id, row.lastId, row.date, row.message, row.nodeCount, row.bytes, row.sha256]));
  return {
    sql: `(${tempSchemaGuard(mode)}) AND EXISTS (WITH temp_scope AS (${scopeSelect}),
      temp_rows AS (${ownedTempRowsSql(mode, "temp_scope", { verifyLive: true })})
      SELECT 1 WHERE (SELECT count(*) FROM temp_rows)=? AND NOT EXISTS (SELECT 1 FROM json_each(?) AS expected
        LEFT JOIN temp_rows AS batch ON batch.source=json_extract(expected.value,'$[0]')
        AND batch.id=json_extract(expected.value,'$[1]') AND batch.lastId=json_extract(expected.value,'$[2]')
        AND batch.date=json_extract(expected.value,'$[3]') AND batch.message=json_extract(expected.value,'$[4]')
        AND batch.nodeCount=json_extract(expected.value,'$[5]') AND batch.bytes=json_extract(expected.value,'$[6]')
        AND batch.sha256 IS json_extract(expected.value,'$[7]') AND batch.accepted=1 WHERE batch.id IS NULL))`,
    bindings: [rows.length, expected] as const,
  };
}

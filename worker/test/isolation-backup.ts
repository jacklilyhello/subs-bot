import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";

import { MAX_PRIVATE_SHARE_BYTES } from "../src/private-shares.ts";
import { MAX_CHUNK_BYTES, MAX_SNAPSHOT_NODES } from "../src/storage.ts";

// Only for ephemeral, wholly synthetic Workerd fixtures. Live capture, archive
// storage/authentication, and production restore are separate operations.
const SUBSCRIPTION = ["id", "owner_id", "name", "source_url", "token", "expire_at", "traffic_used", "traffic_total",
  "last_error", "created_at", "updated_at", "generation", "snapshot_id", "manifest_sha256", "node_count"];
const TABLES = {
  subscriptions: SUBSCRIPTION,
  subscription_trash: [...SUBSCRIPTION, "deleted_at", "lifecycle_revision"],
  subscription_lifecycle: ["subscription_id", "revision"],
  private_shares: ["id", "bot_id", "code_sha256", "sender_id", "sender_name", "payload_id", "payload_sha256", "payload_bytes",
    "max_claims", "target_user_id", "expire_at", "created_at"],
  private_share_claims: ["share_id", "actor_id", "claimed_at"],
  telegram_bot_display_settings: ["bot_id", "timezone", "update_id", "message_date", "updated_by", "updated_at"],
} as const;
type Table = keyof typeof TABLES;
type Cell = string | number | null;
type Row = Cell[];
type Rows = Record<Table, Row[]>;
type Sequences = Record<"subscriptions" | "private_shares", number | null>;
type ReadObject = (key: string, maxBytes: number) => Promise<Buffer>;
type ObjectData = { key: string; sha256: string; body: Buffer };

interface BackupDocument {
  version: 1;
  schemaSha256: string;
  rows: Rows;
  sequences: Sequences;
  objects: { key: string; bytes: number; sha256: string; base64: string }[];
}

export interface SealedSyntheticBackup { body: Buffer; sha256: string }

const tableNames = Object.keys(TABLES) as Table[];
const sequenceNames = ["subscriptions", "private_shares"] as const;
const MAX_ROWS = 32;
const MAX_OBJECTS = 32;
const MAX_OBJECT_BYTES = 2 * 1024 * 1024;
const MAX_ENVELOPE_BYTES = 4 * 1024 * 1024;
const MAX_MANIFEST_BYTES = 64 * 1024;
const SHA256 = /^[a-f0-9]{64}(?![\s\S])/u;
const UUID = /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}(?![\s\S])/u;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });

function requireBackup(condition: unknown): asserts condition {
  if (!condition) throw new Error("Invalid synthetic backup.");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: unknown, keys: readonly string[]): value is Record<string, unknown> {
  return isRecord(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function integer(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function sha256(body: Buffer): string {
  return createHash("sha256").update(body).digest("hex");
}

export function sealSyntheticBackup(document: unknown): SealedSyntheticBackup {
  const body = Buffer.from(JSON.stringify(document, (_key, value) => isRecord(value)
    ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, value[key]])) : value), "utf8");
  requireBackup(body.length <= MAX_ENVELOPE_BYTES);
  return { body, sha256: sha256(body) };
}

function metadata(value: unknown): asserts value is BackupDocument {
  requireBackup(exactKeys(value, ["version", "schemaSha256", "rows", "sequences", "objects"]) && value.version === 1
    && typeof value.schemaSha256 === "string" && SHA256.test(value.schemaSha256));
  requireBackup(exactKeys(value.rows, tableNames) && exactKeys(value.sequences, sequenceNames));
  requireBackup(Array.isArray(value.objects) && value.objects.length <= MAX_OBJECTS);
  let rowCount = 0;
  for (const table of tableNames) {
    const rows = value.rows[table];
    requireBackup(Array.isArray(rows) && (rowCount += rows.length) <= MAX_ROWS);
    for (const row of rows) {
      requireBackup(Array.isArray(row) && row.length === TABLES[table].length && row.every((cell) =>
        cell === null || typeof cell === "string" || (typeof cell === "number" && Number.isFinite(cell))));
    }
  }
  for (const table of sequenceNames) requireBackup(value.sequences[table] === null || integer(value.sequences[table], 1));
}

function insertStatements({ rows, sequences }: BackupDocument): Array<{ sql: string; values: Row }> {
  const statements: Array<{ sql: string; values: Row }> = [];
  for (const table of tableNames) {
    const columns = TABLES[table];
    const sql = `INSERT INTO ${table} (${columns.join(", ")}) VALUES (${columns.map(() => "?").join(", ")})`;
    for (const values of rows[table]) statements.push({ sql, values });
  }
  // Explicit inserts update SQLite's counter automatically, but the original
  // high-water mark can exceed the largest active ID (including trashed IDs).
  for (const table of sequenceNames) {
    statements.push({ sql: "DELETE FROM sqlite_sequence WHERE name = ?", values: [table] });
    if (sequences[table] !== null) {
      statements.push({ sql: "INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", values: [table, sequences[table]] });
    }
  }
  return statements;
}

function checkMetadata(document: BackupDocument, migrations: readonly string[]): void {
  const { rows, sequences } = document;
  const subscriptions = [...rows.subscriptions, ...rows.subscription_trash];
  for (const [ids, sequence] of [[subscriptions, sequences.subscriptions], [rows.private_shares, sequences.private_shares]] as const) {
    requireBackup(ids.every(([id]) => integer(id, 1) && sequence !== null && id <= sequence));
  }
  const scratch = new DatabaseSync(":memory:");
  try {
    scratch.exec("PRAGMA foreign_keys = ON;");
    for (const sql of migrations) scratch.exec(sql);
    for (const { sql, values } of insertStatements(document)) scratch.prepare(sql).run(...values);
    requireBackup(scratch.prepare("PRAGMA quick_check").get()?.quick_check === "ok");
    requireBackup(scratch.prepare("PRAGMA foreign_key_check").all().length === 0);
    for (const sql of [
      `SELECT 1 FROM subscriptions AS active JOIN subscription_trash AS trash ON active.id = trash.id OR active.token = trash.token`,
      `SELECT 1 FROM subscription_trash AS trash LEFT JOIN subscription_lifecycle AS lifecycle ON trash.id = lifecycle.subscription_id
       WHERE trash.lifecycle_revision IS NOT lifecycle.revision`,
      `SELECT 1 FROM subscription_lifecycle AS lifecycle
       WHERE NOT EXISTS (SELECT 1 FROM subscriptions WHERE id = lifecycle.subscription_id)
       AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id = lifecycle.subscription_id)`,
      `SELECT 1 FROM private_shares AS share WHERE share.max_claims <
       (SELECT count(*) FROM private_share_claims AS claim WHERE claim.share_id = share.id)`,
      `SELECT 1 FROM private_share_claims AS claim JOIN private_shares AS share ON claim.share_id = share.id
       WHERE claim.claimed_at NOT BETWEEN share.created_at AND share.expire_at
       OR (share.target_user_id IS NOT NULL AND claim.actor_id <> share.target_user_id)`,
    ]) requireBackup(scratch.prepare(sql).get() === undefined);
  } finally {
    scratch.close();
  }
}

async function referencedObjects(rows: Rows, read: ReadObject): Promise<ObjectData[]> {
  const found = new Map<string, ObjectData>();
  let totalBytes = 0;
  async function object(key: string, max: number, hash: unknown, bytes?: number): Promise<Buffer> {
    requireBackup(typeof hash === "string" && SHA256.test(hash) && !found.has(key) && found.size < MAX_OBJECTS);
    const body = await read(key, max);
    requireBackup(integer(body.length, 1, max) && (bytes === undefined || body.length === bytes)
      && (totalBytes += body.length) <= MAX_OBJECT_BYTES && sha256(body) === hash);
    found.set(key, { key, sha256: hash, body });
    return body;
  }

  for (const row of [...rows.subscriptions, ...rows.subscription_trash]) {
    const id = row[0];
    const [generation, snapshotId, manifestHash, nodeCount] = row.slice(11, 15);
    requireBackup(integer(id, 1) && integer(generation, 0));
    if (!generation) {
      requireBackup(snapshotId === null && manifestHash === null && nodeCount === 0);
      continue;
    }
    requireBackup(typeof snapshotId === "string" && UUID.test(snapshotId) && integer(nodeCount, 1, MAX_SNAPSHOT_NODES));
    const prefix = `subscriptions/${id}/${snapshotId}/`;
    const manifest: unknown = JSON.parse(decoder.decode(await object(`${prefix}manifest.json`, MAX_MANIFEST_BYTES, manifestHash)));
    requireBackup(exactKeys(manifest, ["version", "chunks"]) && manifest.version === 1 && Array.isArray(manifest.chunks)
      && integer(manifest.chunks.length, 1, MAX_OBJECTS));
    let count = 0;
    for (const [index, chunk] of manifest.chunks.entries()) {
      requireBackup(exactKeys(chunk, ["bytes", "sha256", "count"]) && integer(chunk.bytes, 1, MAX_CHUNK_BYTES)
        && integer(chunk.count, 1, nodeCount) && (count += chunk.count) <= nodeCount);
      const text = decoder.decode(await object(`${prefix}${index}.ndjson`, MAX_CHUNK_BYTES, chunk.sha256, chunk.bytes));
      const lines = text.split("\n");
      requireBackup(lines.pop() === "" && lines.length === chunk.count && lines.every((line) => isRecord(JSON.parse(line))));
    }
    requireBackup(count === nodeCount);
  }
  for (const row of rows.private_shares) {
    const [id, hash, bytes] = row.slice(5, 8);
    requireBackup(typeof id === "string" && UUID.test(id) && integer(bytes, 1, MAX_PRIVATE_SHARE_BYTES));
    decoder.decode(await object(`private-shares/${id}.txt`, MAX_PRIVATE_SHARE_BYTES, hash, bytes));
  }
  return [...found.values()].sort((left, right) => left.key < right.key ? -1 : left.key === right.key ? 0 : 1);
}

async function readCohort(db: D1Database): Promise<Pick<BackupDocument, "rows" | "sequences">> {
  const results = await db.batch<Record<string, Cell>>([
    ...tableNames.map((table) => db.prepare(`SELECT ${TABLES[table].join(", ")} FROM ${table}
      ORDER BY ${table === "private_share_claims" ? "share_id, actor_id" : TABLES[table][0]} LIMIT ${MAX_ROWS + 1}`)),
    db.prepare("SELECT name, seq FROM sqlite_sequence WHERE name IN ('subscriptions', 'private_shares')"),
  ]);
  requireBackup(results.length === tableNames.length + 1 && results.every(({ success }) => success));
  const rows = Object.fromEntries(tableNames.map((table, index) =>
    [table, results[index].results.map((row) => TABLES[table].map((column) => row[column]))])) as Rows;
  const sequenceRows = results[tableNames.length].results;
  const sequences = Object.fromEntries(sequenceNames.map((name) =>
    [name, sequenceRows.find((row) => row.name === name)?.seq ?? null])) as Sequences;
  return { rows, sequences };
}

export async function captureSyntheticBackup(
  db: D1Database, bucket: R2Bucket, migrations: readonly string[],
): Promise<SealedSyntheticBackup> {
  try {
    const schemaSha256 = sha256(Buffer.from(JSON.stringify(migrations)));
    const document: BackupDocument = { version: 1, schemaSha256, ...await readCohort(db), objects: [] };
    metadata(document);
    checkMetadata(document, migrations);
    const objects = await referencedObjects(document.rows, async (key, max) => {
      const source = await bucket.get(key);
      requireBackup(source);
      if (!integer(source.size, 1, max)) {
        await source.body.cancel();
        throw new Error("Invalid synthetic backup.");
      }
      const body = Buffer.from(await source.arrayBuffer());
      requireBackup(body.length === source.size);
      return body;
    });
    document.objects = objects.map(({ key, sha256, body }) => ({ key, bytes: body.length, sha256, base64: body.toString("base64") }));
    return sealSyntheticBackup(document);
  } catch {
    throw new Error("Synthetic backup capture could not be verified.");
  }
}

async function openSyntheticBackup(backup: SealedSyntheticBackup, migrations: readonly string[]) {
  requireBackup(Buffer.isBuffer(backup.body) && integer(backup.body.length, 1, MAX_ENVELOPE_BYTES)
    && sha256(backup.body) === backup.sha256);
  const document: unknown = JSON.parse(decoder.decode(backup.body));
  metadata(document);
  requireBackup(sealSyntheticBackup(document).body.equals(backup.body)
    && document.schemaSha256 === sha256(Buffer.from(JSON.stringify(migrations))));
  checkMetadata(document, migrations);
  const entries = new Map<string, BackupDocument["objects"][number]>();
  let previous = "";
  for (const entry of document.objects) {
    requireBackup(exactKeys(entry, ["key", "bytes", "sha256", "base64"]) && typeof entry.key === "string" && entry.key > previous
      && integer(entry.bytes, 1, MAX_CHUNK_BYTES) && typeof entry.sha256 === "string" && SHA256.test(entry.sha256)
      && typeof entry.base64 === "string" && entry.base64.length === 4 * Math.ceil(entry.bytes / 3));
    entries.set(entry.key, entry);
    previous = entry.key;
  }
  const objects = await referencedObjects(document.rows, async (key, max) => {
    const entry = entries.get(key);
    requireBackup(entry && entry.bytes <= max);
    const body = Buffer.from(entry.base64, "base64");
    requireBackup(body.length === entry.bytes && body.toString("base64") === entry.base64 && sha256(body) === entry.sha256);
    return body;
  });
  requireBackup(objects.length === entries.size);
  return { document, objects };
}

export async function restoreSyntheticBackup(
  backup: SealedSyntheticBackup, migrations: readonly string[], db: D1Database, bucket: R2Bucket,
): Promise<void> {
  try {
    const { document, objects } = await openSyntheticBackup(backup, migrations);
    const { rows, sequences } = await readCohort(db);
    requireBackup(tableNames.every((table) => rows[table].length === 0)
      && sequenceNames.every((table) => sequences[table] === null) && (await bucket.list({ limit: 1 })).objects.length === 0);
    for (const { key, body, sha256 } of objects) {
      const stored = await bucket.put(key, Uint8Array.from(body), {
        onlyIf: { etagDoesNotMatch: "*" }, sha256: Uint8Array.from(Buffer.from(sha256, "hex")).buffer,
      });
      requireBackup(stored);
    }
    const statements = insertStatements(document);
    const results = await db.batch(statements.map(({ sql, values }) => db.prepare(sql).bind(...values)));
    requireBackup(results.length === statements.length && results.every(({ success }) => success));
  } catch {
    throw new Error("Synthetic backup restore could not be verified.");
  }
}

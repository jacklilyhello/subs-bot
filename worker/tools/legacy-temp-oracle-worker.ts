/** Verify synthetic legacy temp batches through the exact emitted Worker in hosted loopback. */

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Log, LogLevel, Miniflare } from "miniflare";
import { recordTempFixtureMigration } from "../test/temp-migration-fixture.ts";

const DIGEST = /^[a-f0-9]{64}(?![\s\S])/u;
const REVISION = /^[a-f0-9]{40}(?![\s\S])/u;
const DATE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}(?![\s\S])/u;
const ID = /^[1-9][0-9]{0,15}(?![\s\S])/u;
const MIGRATION = /^[0-9]{4}_[a-z][a-z0-9_]*\.sql(?![\s\S])/u;
const OWNER_LABELS = ["supported", "malformed", "realm"] as const;
const CODES = {
  supported: "tporacle0001", malformed: "tporacle0002", realm: "tporacle0003",
  wrongBot: "tporacle0004", wrongOwner: "tporacle0005", selected: "tporacle0006",
};
const ORIGIN = "https://legacy-temp-oracle.fixture.invalid";
const TEXT = "text/plain; charset=utf-8";
const ERROR_BODY = "Subscription content cannot be exported.";
const MAX_INPUT = 2 * 1024 * 1024;
const MAX_BATCH_BYTES = 256 * 1024;
const MAX_MIGRATION_BYTES = 256 * 1024;
const MAX_EXPORT_BYTES = 1024 * 1024;
const STAMP = 1_800_000_000;
const NONCE = "legacy-temp-oracle:v1";
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const sha = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");

type RecordValue = Record<string, unknown>;
type TempNode = { name: string; type: "temp"; share: string };
type Batch = { nodesJson: string; nodeCount: number; payloadBytes: number };
type Owner = { label: (typeof OWNER_LABELS)[number]; ownerId: string; batches: Batch[] };
type FixtureScope = { botId: string; ownerId: string; batches: Batch[] };
type Stage = "sandbox" | "input" | "artifact" | "migrations" | "d1-seed" | "d1-readback" | "http" | "r2-empty" | "dispose";
let stage: Stage = "sandbox";

function requireOracle(condition: unknown): asserts condition {
  if (!condition) throw new Error("Invalid isolated temporary-node oracle state.");
}

function exact(value: unknown, keys: string[]): value is RecordValue {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function matches(regex: RegExp, value: unknown): value is string {
  return typeof value === "string" && regex.test(value);
}

function integer(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function syntheticId(value: unknown): value is string {
  return matches(ID, value) && integer(Number(value), 1);
}

function sandbox(): number {
  const interfaces = networkInterfaces();
  const uid = process.getuid?.();
  requireOracle(process.platform === "linux" && uid !== undefined && uid !== 0 && Object.keys(interfaces).join() === "lo"
    && interfaces.lo?.some(({ address, internal }) => internal && address === "127.0.0.1") && process.argv.length === 2);
  return uid;
}

async function inputBytes(): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    requireOracle(Buffer.isBuffer(chunk) && (size += chunk.length) <= MAX_INPUT);
    chunks.push(chunk);
  }
  return Buffer.concat(chunks, size);
}

async function pinnedFile(path: string, digest: unknown, maximum: number, uid: number): Promise<Buffer> {
  requireOracle(matches(DIGEST, digest) && await realpath(path) === path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    requireOracle(info.isFile() && info.uid === uid && info.nlink === 1 && (info.mode & 0o077) === 0
      && integer(info.size, 1, maximum));
    const bytes = Buffer.alloc(info.size + 1);
    let read = 0;
    while (read < bytes.length) {
      const { bytesRead } = await file.read(bytes, read, bytes.length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    const body = bytes.subarray(0, read);
    requireOracle(read === info.size && sha(body) === digest);
    return body;
  } finally {
    await file.close();
  }
}

function nodes(batch: Batch): TempNode[] {
  const value: unknown = JSON.parse(batch.nodesJson);
  requireOracle(Array.isArray(value) && value.length === batch.nodeCount);
  return value.map((node) => {
    requireOracle(exact(node, ["name", "type", "share"]) && node.type === "temp"
      && typeof node.name === "string" && node.name.isWellFormed() && typeof node.share === "string"
      && node.share.length > 0 && node.share.isWellFormed());
    return { name: node.name, type: node.type, share: node.share };
  });
}

function owner(value: unknown, label: Owner["label"]): Owner {
  requireOracle(exact(value, ["label", "ownerId", "batches"]) && value.label === label && syntheticId(value.ownerId)
    && Array.isArray(value.batches) && integer(value.batches.length, 1, 10));
  const batches = value.batches.map((row) => {
    requireOracle(exact(row, ["nodesJson", "nodeCount", "payloadBytes"]) && typeof row.nodesJson === "string" && row.nodesJson.isWellFormed()
      && integer(row.nodeCount, 1, 500) && integer(row.payloadBytes, 1, MAX_BATCH_BYTES)
      && Buffer.byteLength(row.nodesJson) === row.payloadBytes);
    const batch = { nodesJson: row.nodesJson, nodeCount: row.nodeCount, payloadBytes: row.payloadBytes };
    nodes(batch);
    return batch;
  });
  requireOracle(batches.reduce((sum, batch) => sum + batch.payloadBytes, 0) <= 4 * 1024 * 1024);
  return { label, ownerId: value.ownerId, batches };
}

async function readInputs(uid: number) {
  const input: unknown = JSON.parse(decoder.decode(await inputBytes()));
  requireOracle(exact(input, ["workerDir", "workerManifestSha256", "revision", "botId", "owners"])
    && matches(REVISION, input.revision) && syntheticId(input.botId) && Array.isArray(input.owners)
    && input.owners.length === OWNER_LABELS.length);
  const ownerInputs = input.owners;
  const owners = OWNER_LABELS.map((label, index) => owner(ownerInputs[index], label));
  requireOracle(new Set([input.botId, ...owners.map((item) => item.ownerId)]).size === OWNER_LABELS.length + 1);
  stage = "artifact";
  const directory = input.workerDir;
  requireOracle(typeof directory === "string" && isAbsolute(directory) && resolve(directory) === directory && await realpath(directory) === directory);
  const info = await lstat(directory);
  requireOracle(info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0);
  const manifest = JSON.parse(decoder.decode(await pinnedFile(join(directory, "isolation.json"), input.workerManifestSha256, 256 * 1024, uid)));
  requireOracle(manifest?.version === 2 && manifest.revision === input.revision && matches(DATE, manifest.compatibilityDate)
    && Array.isArray(manifest.migrations) && integer(manifest.migrations.length, 38, 100));
  const script = decoder.decode(await pinnedFile(join(directory, "index.js"), manifest.bundleSha256, 1024 * 1024, uid));
  stage = "migrations";
  let bytes = 0;
  const migrations = [];
  for (const [index, entry] of manifest.migrations.entries()) {
    requireOracle(exact(entry, ["name", "sha256"]) && matches(MIGRATION, entry.name) && Number(entry.name.slice(0, 4)) === index + 1);
    const body = await pinnedFile(join(directory, entry.name), entry.sha256, MAX_MIGRATION_BYTES - bytes, uid);
    bytes += body.length;
    migrations.push({ name: entry.name, sha256: sha(body), sql: decoder.decode(body) });
  }
  requireOracle(migrations[1].name === "0002_telegram.sql" && migrations[7].name === "0008_telegram_temp_nodes.sql"
    && migrations[8].name === "0009_aggregate_links.sql");
  return { revision: input.revision, botId: input.botId, owners, compatibilityDate: manifest.compatibilityDate, script, migrations };
}

async function setup(db: D1Database, fixture: Awaited<ReturnType<typeof readInputs>>) {
  stage = "migrations";
  for (const migration of fixture.migrations) {
    const statements = migration.sql.trim().split(/;\s*/u).filter(Boolean);
    const result = await db.batch(statements.map((sql) => db.prepare(sql)));
    requireOracle(result.length === statements.length && result.every((entry) => entry.success === true));
    await recordTempFixtureMigration(db, migration);
  }
  stage = "d1-seed";
  const { botId, owners } = fixture;
  const used = new Set([botId, ...owners.map((item) => item.ownerId)]);
  const [foreignBot, foreignOwner, absentBot, absentOwner] = ["999000000001", "999000000002", "999000000003", "999000000004"];
  requireOracle([foreignBot, foreignOwner, absentBot, absentOwner].every((id) => !used.has(id)));
  const ownerId = owners[0].ownerId;
  const sentinel = (suffix: string): Batch => {
    const nodesJson = JSON.stringify([{ name: suffix, type: "temp", share: `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.50:8388#${suffix}` }]);
    return { nodesJson, nodeCount: 1, payloadBytes: Buffer.byteLength(nodesJson) };
  };
  const scopes: FixtureScope[] = [
    ...owners.map((item) => ({ botId, ownerId: item.ownerId, batches: item.batches })),
    { botId: foreignBot, ownerId, batches: [sentinel("foreign-bot")] },
    { botId, ownerId: foreignOwner, batches: [sentinel("foreign-owner")] },
  ];
  let serial = 0;
  for (const scope of scopes) {
    const statements = scope.batches.flatMap((row) => {
      const id = ++serial;
      return [db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
        VALUES (?,?,?,?,'private',?,?,'help',?)`).bind(scope.botId, id, scope.ownerId, scope.ownerId, id, STAMP - id, NONCE),
      db.prepare(`INSERT INTO telegram_temp_batch (receipt_id,bot_id,actor_id,message_date,message_id,nodes_json,node_count,payload_bytes)
        SELECT receipt_id,bot_id,actor_id,message_date,message_id,?,?,? FROM telegram_inbox WHERE bot_id=? AND update_id=? AND receipt_nonce=?`)
        .bind(row.nodesJson, row.nodeCount, row.payloadBytes, scope.botId, id, NONCE)];
    });
    const result = await db.batch(statements);
    requireOracle(result.length === statements.length && result.every((entry) => entry.success === true && entry.meta.changes === 1));
  }
  const shell = await db.prepare(`INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
    VALUES (?,'Synthetic selected shell','uploaded://temp-oracle','temporary-oracle-selected-shell',?,?) RETURNING id`)
    .bind(ownerId, STAMP, STAMP).first<number>("id");
  requireOracle(integer(shell, 1));
  const links: Array<readonly [code: string, owner: string, kind: "all" | "selected", bot: string | null, ids: string | null]> = [
    ...owners.map((item) => [CODES[item.label], item.ownerId, "all", botId, null] as const),
    [CODES.wrongBot, ownerId, "all", absentBot, null],
    [CODES.wrongOwner, absentOwner, "all", botId, null],
    [CODES.selected, ownerId, "selected", null, JSON.stringify([shell])],
  ];
  const result = await db.batch(links.map(([code, owner, kind, bot, ids]) => db.prepare(`INSERT INTO aggregate_links
    (code_sha256,owner_id,kind,bot_id,selected_ids,created_at) VALUES (?,?,?,?,?,?)`)
    .bind(sha(code), owner, kind, bot, ids, STAMP)));
  requireOracle(result.length === links.length && result.every((entry) => entry.success === true && entry.meta.changes === 1));
  return { scopes, serial };
}

type StoredBatch = Batch & { receiptId: number; messageDate: number };

async function readback(db: D1Database, scopes: FixtureScope[], serial: number) {
  stage = "d1-readback";
  const evidence = [];
  let expectedReceipt = 0;
  for (const scope of scopes) {
    const read = await db.prepare(`SELECT temp.receipt_id AS receiptId,temp.message_date AS messageDate,
      temp.nodes_json AS nodesJson,temp.node_count AS nodeCount,temp.payload_bytes AS payloadBytes
      FROM telegram_temp_batch AS temp JOIN telegram_inbox AS inbox USING(receipt_id)
      WHERE temp.bot_id=? AND temp.actor_id=? AND inbox.bot_id=temp.bot_id AND inbox.actor_id=temp.actor_id
        AND inbox.message_date=temp.message_date AND inbox.message_id=temp.message_id AND inbox.receipt_nonce=?
      ORDER BY temp.receipt_id`).bind(scope.botId, scope.ownerId, NONCE).all<StoredBatch>();
    requireOracle(read.success && read.results.length === scope.batches.length);
    const batches = read.results.map((actual, index) => {
      const expected = scope.batches[index];
      expectedReceipt += 1;
      requireOracle(actual.receiptId === expectedReceipt && actual.messageDate === STAMP - expectedReceipt
        && actual.nodeCount === expected.nodeCount && actual.payloadBytes === expected.payloadBytes
        && actual.nodesJson === expected.nodesJson && Buffer.byteLength(actual.nodesJson) === actual.payloadBytes);
      return { nodeCount: actual.nodeCount, payloadBytes: actual.payloadBytes, payloadSha256: sha(actual.nodesJson),
        namesSha256: sha(JSON.stringify(nodes(actual).map((node) => node.name))) };
    });
    evidence.push(batches);
  }
  const counts = await db.prepare(`SELECT (SELECT count(*) FROM telegram_temp_batch) AS batches,
    (SELECT count(*) FROM telegram_inbox) AS receipts,(SELECT count(*) FROM telegram_outbox) AS outbox`).first();
  const foreign = await db.prepare("PRAGMA foreign_key_check").all();
  requireOracle(counts?.batches === serial && counts.receipts === serial && counts.outbox === 0
    && expectedReceipt === serial && foreign.success && foreign.results.length === 0);
  return { supported: evidence[0], malformed: evidence[1], realm: evidence[2] };
}

async function digestBody(response: Response, maximum: number) {
  const digest = createHash("sha256");
  let bytes = 0;
  if (response.body) {
    const reader = response.body.getReader();
    try {
      while (true) {
        const next = await reader.read();
        if (next.done) break;
        if ((bytes += next.value.byteLength) > maximum) {
          await reader.cancel();
          throw new Error("Synthetic HTTP response exceeds its bound.");
        }
        digest.update(next.value);
      }
    } finally {
      reader.releaseLock();
    }
  }
  return { bytes, sha256: digest.digest("hex") };
}

async function httpPair(runtime: Miniflare, path: string, status: number, body: Buffer, location: string | null = null) {
  let headContentLength: number | null = null;
  let bodyBytes = 0;
  let bodySha256 = sha("");
  let getStatus = 0;
  let headStatus = 0;
  const expectedDigest = sha(body);
  for (const method of ["GET", "HEAD"] as const) {
    const response = await runtime.dispatchFetch(ORIGIN + path, { method, redirect: "manual", headers: { "Accept-Encoding": "identity" } });
    const headers = response.headers;
    requireOracle(response.status === status && headers.get("Content-Type") === (status === 302 ? null : TEXT)
      && headers.get("Cache-Control") === "private, no-store" && headers.get("Referrer-Policy") === "no-referrer"
      && headers.get("X-Content-Type-Options") === "nosniff" && headers.get("Location") === location
      && !headers.has("Age") && !headers.has("Set-Cookie") && (headers.get("Content-Encoding") ?? "identity") === "identity");
    const length = headers.get("Content-Length");
    if (method === "GET") {
      requireOracle(length === null ? status !== 200 : length === String(body.length));
      const actual = await digestBody(response, MAX_EXPORT_BYTES);
      requireOracle(actual.bytes === body.length && actual.sha256 === expectedDigest);
      getStatus = response.status;
      bodyBytes = actual.bytes;
      bodySha256 = actual.sha256;
    } else {
      requireOracle(length === null || length === String(body.length));
      const actual = await digestBody(response, 0);
      requireOracle(actual.bytes === 0);
      headStatus = response.status;
      headContentLength = length === null ? null : Number(length);
    }
  }
  return { getStatus, headStatus, bodyBytes, bodySha256, headContentLength };
}

async function probe(runtime: Miniflare, supported: Owner) {
  stage = "http";
  const raw = supported.batches.flatMap((batch) => nodes(batch).map((node) => node.share)).join("\n");
  const body = Buffer.from(Buffer.from(raw).toString("base64"), "ascii");
  requireOracle(body.length > 0 && body.length <= MAX_EXPORT_BYTES);
  const denied = Buffer.from("Not found.");
  const unsupported = Buffer.from(ERROR_BODY);
  const aggregate = (code: string) => `/agg/${code}/base64`;
  return {
    supported: await httpPair(runtime, aggregate(CODES.supported), 200, body),
    malformed: await httpPair(runtime, aggregate(CODES.malformed), 422, unsupported),
    realm: await httpPair(runtime, aggregate(CODES.realm), 422, unsupported),
    wrongBot: await httpPair(runtime, aggregate(CODES.wrongBot), 404, denied),
    wrongOwner: await httpPair(runtime, aggregate(CODES.wrongOwner), 404, denied),
    selected: await httpPair(runtime, aggregate(CODES.selected), 404, denied),
    short: await httpPair(runtime, `/s/${CODES.supported}`, 302, Buffer.alloc(0), `/agg/${CODES.supported}/clash`),
  };
}

async function main() {
  const uid = sandbox();
  stage = "input";
  const fixture = await readInputs(uid);
  const runtime = new Miniflare({
    modules: true, script: fixture.script, compatibilityDate: fixture.compatibilityDate, host: "127.0.0.1",
    log: new Log(LogLevel.NONE), d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: fixture.revision },
    outboundService: () => { throw new Error("Isolated temp oracle outbound denied."); },
  });
  let report;
  try {
    const db = await runtime.getD1Database("DB");
    const { scopes, serial } = await setup(db, fixture);
    const batches = await readback(db, scopes, serial);
    const http = await probe(runtime, fixture.owners[0]);
    stage = "r2-empty";
    const bucket = await runtime.getR2Bucket("NODES");
    const listing = await bucket.list({ limit: 1 });
    requireOracle(!listing.truncated && listing.objects.length === 0);
    report = { revision: fixture.revision, batches, http, r2ObjectCount: listing.objects.length };
  } finally {
    try {
      await runtime.dispose();
    } catch {
      stage = "dispose";
      throw new Error("Isolated temp oracle could not dispose its runtime.");
    }
  }
  process.stdout.write(JSON.stringify(report) + "\n");
}

try {
  await main();
} catch {
  process.stderr.write(`The isolated temp Worker oracle could not be confirmed (${stage}).\n`);
  process.exitCode = 2;
}

/** Replay a sealed synthetic V6 candidate into the exact emitted Worker in hosted loopback. */

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Log, LogLevel, Miniflare } from "miniflare";

const DIGEST = /^[a-f0-9]{64}(?![\s\S])/u;
const REVISION = /^[a-f0-9]{40}(?![\s\S])/u;
const DATE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}(?![\s\S])/u;
const CODE = /^[A-Za-z0-9_-]{12}(?![\s\S])/u;
const UUID = "[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}";
const KEY = new RegExp(`^subscriptions/[1-9][0-9]{0,15}/${UUID}/(?:manifest\\.json|(?:0|[1-9][0-9]{0,2})\\.ndjson)(?![\\s\\S])`, "u");
const MIGRATION = "0038_legacy_selected_aggregates.sql";
const MIGRATION_SHA = "29ddd93dc46120614c4837268ac2c0a0c5b4c48af9d7e4fe4de1e5e24451b74f";
const MAX_INPUT = 1024 * 1024;
const MAX_SQL = 256 * 1024;
const MAX_OBJECTS = 64;
const MAX_OBJECT_BYTES = 1024 * 1024;
const MAX_BODY = 64 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const ORIGIN = "https://legacy-selected-oracle.fixture.invalid";
const TEXT = "text/plain; charset=utf-8";
const YAML = "text/yaml; charset=utf-8";
const JSON_MEDIA = "application/json; charset=utf-8";
const MEDIA = new Map([
  ["clash", YAML], ["unknown-format", YAML], ["singbox", JSON_MEDIA], ["sing-box", JSON_MEDIA],
  ...["base64", "v2ray", "mixed", "surge", "qx", "quantumult", "quantumultx"].map((format) => [format, TEXT] as const),
]);
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const sha = (data: Buffer | string) => createHash("sha256").update(data).digest("hex");

type RecordValue = Record<string, unknown>;
type Migration = { name: string; sha256: string };
type ProbeRequest = { method: "GET" | "HEAD"; route: "short" | "aggregate"; code: string; format: string | null };
type Stage = "sandbox" | "input" | "request-shape" | "artifact" | "sql-replay" | "d1-readback" | "r2-replay"
  | "health" | "request" | "dispose";
let stage: Stage = "sandbox";
let caseNumber = 0;

function requireOracle(condition: unknown): asserts condition {
  if (!condition) throw new Error("Invalid isolated V6 oracle input or response.");
}

function record(value: unknown): value is RecordValue {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exact(value: unknown, keys: string[]): value is RecordValue {
  return record(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}

function matches(regex: RegExp, value: unknown): value is string {
  return typeof value === "string" && regex.test(value);
}

function integer(value: unknown, minimum: number, maximum = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && minimum <= value && value <= maximum;
}

function parsed(bytes: Buffer): RecordValue {
  const value: unknown = JSON.parse(decoder.decode(bytes));
  requireOracle(record(value));
  return value;
}

function sandbox(): number {
  const interfaces = networkInterfaces();
  const uid = process.getuid?.();
  requireOracle(process.platform === "linux" && uid !== undefined && uid !== 0 && Object.keys(interfaces).join() === "lo"
    && interfaces.lo?.some(({ address, internal }) => internal && address === "127.0.0.1") && process.argv.length === 2);
  return uid;
}

async function readInput(): Promise<RecordValue> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of process.stdin) {
    requireOracle(Buffer.isBuffer(chunk) && (size += chunk.length) <= MAX_INPUT);
    chunks.push(chunk);
  }
  return parsed(Buffer.concat(chunks, size));
}

async function privateRoot(value: unknown, uid: number): Promise<string> {
  requireOracle(typeof value === "string" && isAbsolute(value) && resolve(value) === value && await realpath(value) === value);
  const info = await lstat(value);
  requireOracle(info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0);
  return value;
}

async function privateFile(path: string, maximum: number, uid: number): Promise<Buffer> {
  requireOracle(await realpath(path) === path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    requireOracle(info.isFile() && info.uid === uid && info.nlink === 1 && (info.mode & 0o077) === 0
      && integer(info.size, 0, maximum));
    const data = Buffer.alloc(info.size + 1);
    let read = 0;
    while (read < data.length) {
      const { bytesRead } = await file.read(data, read, data.length - read, read);
      if (!bytesRead) break;
      read += bytesRead;
    }
    requireOracle(read === info.size);
    return data.subarray(0, read);
  } finally {
    await file.close();
  }
}

async function pinnedFile(path: string, maximum: number, expected: unknown, uid: number): Promise<Buffer> {
  requireOracle(matches(DIGEST, expected));
  const bytes = await privateFile(path, maximum, uid);
  requireOracle(sha(bytes) === expected);
  return bytes;
}

function migrations(value: unknown): Migration[] {
  requireOracle(Array.isArray(value) && integer(value.length, 38, 100));
  const result = value.map((entry, index) => {
    requireOracle(exact(entry, ["name", "sha256"]) && matches(/^[0-9]{4}_[a-z][a-z0-9_]*\.sql(?![\s\S])/u, entry.name)
      && Number(entry.name.slice(0, 4)) === index + 1 && matches(DIGEST, entry.sha256));
    return { name: entry.name, sha256: entry.sha256 };
  });
  requireOracle(result[37].name === MIGRATION && result[37].sha256 === MIGRATION_SHA);
  return result;
}

function requests(value: unknown): ProbeRequest[] {
  requireOracle(Array.isArray(value) && integer(value.length, 1, 64));
  return value.map((item) => {
    requireOracle(exact(item, ["method", "route", "code", "format"]) && (item.method === "GET" || item.method === "HEAD")
      && (item.route === "short" || item.route === "aggregate") && matches(CODE, item.code)
      && (item.format === null || (item.route === "aggregate" && typeof item.format === "string" && MEDIA.has(item.format))));
    return { method: item.method, route: item.route, code: item.code, format: item.format };
  });
}

async function descriptor(root: string, path: string, details: unknown, cap: number, uid: number): Promise<Buffer> {
  requireOracle(record(details) && details.path === path && integer(details.bytes, 0, cap));
  const bytes = await pinnedFile(join(root, path), cap, details.sha256, uid);
  requireOracle(bytes.length === details.bytes);
  return bytes;
}

async function checkInventory(root: string, names: Set<string>, uid: number): Promise<void> {
  const remaining = new Set(names);
  const directories = new Set([...names].flatMap((name) => {
    const parts = name.split("/");
    return parts.slice(0, -1).map((_, i) => parts.slice(0, i + 1).join("/"));
  }));
  async function walk(prefix: string) {
    const path = join(root, prefix);
    const info = await lstat(path);
    requireOracle(info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0);
    for await (const entry of await opendir(path)) {
      const name = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isDirectory() && directories.has(name)) await walk(name);
      else requireOracle(entry.isFile() && remaining.delete(name));
    }
  }
  await walk("");
  requireOracle(remaining.size === 0);
}

function statements(value: unknown, bytes: Buffer): string[] {
  requireOracle(Array.isArray(value) && integer(value.length, 1, 512));
  let length = 0;
  for (const sql of value) {
    requireOracle(typeof sql === "string" && sql.endsWith(";\n") && !sql.includes("\0")
      && (sql.startsWith("CREATE TABLE ") || sql.startsWith("CREATE INDEX ") || sql.startsWith("CREATE UNIQUE INDEX ")
        || sql.startsWith("INSERT INTO ") || /^DELETE FROM sqlite_sequence WHERE name='(?:subscriptions|path_rules)';\n$/u.test(sql)));
    const size = Buffer.byteLength(sql);
    requireOracle(integer(size, 1, 100_000) && (length += size) <= MAX_SQL);
  }
  requireOracle(bytes.length === length && bytes.equals(Buffer.from(value.join(""))));
  return value as string[];
}

async function load(input: RecordValue, uid: number) {
  requireOracle(exact(input, ["workerDir", "workerManifestSha256", "candidateDir", "candidateManifestSha256", "revision",
    "sqlStatements", "requests"]) && matches(REVISION, input.revision));
  stage = "request-shape";
  const probes = requests(input.requests);
  stage = "artifact";
  const worker = await privateRoot(input.workerDir, uid);
  const candidate = await privateRoot(input.candidateDir, uid);
  const build = parsed(await pinnedFile(join(worker, "isolation.json"), 256 * 1024, input.workerManifestSha256, uid));
  requireOracle(build.version === 2 && build.ref === "refs/heads/main" && build.revision === input.revision
    && matches(DATE, build.compatibilityDate));
  const chain = migrations(build.migrations);
  const script = decoder.decode(await pinnedFile(join(worker, "index.js"), 1024 * 1024, build.bundleSha256, uid));
  requireOracle(script.includes("subs-bot:legacy-selected-http:v1") && script.includes("subs-bot:legacy-selected-retirement:v1"));
  const manifest = parsed(await pinnedFile(join(candidate, "manifest.json"), 256 * 1024, input.candidateManifestSha256, uid));
  const marker = await privateFile(join(candidate, "manifest.sha256"), 65, uid);
  requireOracle(marker.equals(Buffer.from(`${input.candidateManifestSha256}\n`, "ascii")) && manifest.version === 6
    && manifest.scope === "fresh-unbound-d1-r2" && record(manifest.workerArtifact) && record(manifest.selectedAggregateLinks)
    && record(manifest.shortLinkCompatibility) && manifest.shortLinkCompatibility.selected === "not-validated"
    && manifest.selectedAggregateLinks.migrationSha256 === MIGRATION_SHA && integer(manifest.selectedAggregateLinks.rows, 1, 64)
    && manifest.workerArtifact.manifestSha256 === input.workerManifestSha256 && manifest.workerArtifact.revision === input.revision
    && manifest.workerArtifact.bundleSha256 === build.bundleSha256 && manifest.workerArtifact.compatibilityDate === build.compatibilityDate
    && manifest.workerArtifact.runId === build.runId && manifest.workerArtifact.runAttempt === build.runAttempt
    && JSON.stringify(migrations(manifest.workerArtifact.migrations)) === JSON.stringify(chain));
  const sql = statements(input.sqlStatements, await descriptor(candidate, "restore.sql", manifest.sql, MAX_SQL, uid));
  await descriptor(candidate, "lineage.ndjson", manifest.lineage, MAX_INPUT, uid);
  requireOracle(Array.isArray(manifest.objects) && integer(manifest.objects.length, 0, MAX_OBJECTS)
    && manifest.objectCount === manifest.objects.length);
  const objects = new Map<string, Buffer>();
  const inventory = new Set(["manifest.json", "manifest.sha256", "restore.sql", "lineage.ndjson"]);
  let objectBytes = 0;
  for (const item of manifest.objects) {
    requireOracle(exact(item, ["key", "bytes", "sha256", "metadata"]) && matches(KEY, item.key) && !objects.has(item.key)
      && integer(item.bytes, 1, MAX_OBJECT_BYTES) && (objectBytes += item.bytes) <= MAX_OBJECT_BYTES
      && exact(item.metadata, ["custom", "http"]) && exact(item.metadata.custom, []) && exact(item.metadata.http, []));
    const path = `objects/${item.key}`;
    const body = await pinnedFile(join(candidate, path), item.bytes, item.sha256, uid);
    requireOracle(body.length === item.bytes);
    inventory.add(path);
    objects.set(item.key, body);
  }
  requireOracle(objectBytes === manifest.objectBytes);
  await checkInventory(candidate, inventory, uid);
  return { script, revision: input.revision, compatibilityDate: build.compatibilityDate, chain, manifest, sql, objects, probes };
}

type Pointer = { id: number; generation: number; snapshot: string | null; manifest: string | null; nodes: number };

async function verifyReferences(db: D1Database, objects: Map<string, Buffer>): Promise<void> {
  const { success, results } = await db.prepare(`SELECT id,generation,snapshot_id AS snapshot,manifest_sha256 AS manifest,node_count AS nodes
    FROM subscriptions UNION ALL SELECT id,generation,snapshot_id,manifest_sha256,node_count FROM subscription_trash LIMIT 65`).all<Pointer>();
  requireOracle(success && results.length <= 64);
  const referenced = new Set<string>();
  function object(key: string, digest: string): Buffer {
    const body = objects.get(key);
    requireOracle(body && !referenced.has(key) && sha(body) === digest);
    referenced.add(key);
    return body;
  }
  for (const row of results) {
    requireOracle(integer(row.id, 1) && integer(row.generation, 0));
    if (row.generation === 0) {
      requireOracle(row.snapshot === null && row.manifest === null && row.nodes === 0);
      continue;
    }
    requireOracle(matches(new RegExp(`^${UUID}(?![\\s\\S])`, "u"), row.snapshot) && matches(DIGEST, row.manifest)
      && integer(row.nodes, 1, 100_000));
    const prefix = `subscriptions/${row.id}/${row.snapshot}/`;
    const manifest = parsed(object(prefix + "manifest.json", row.manifest));
    requireOracle(exact(manifest, ["version", "chunks"]) && manifest.version === 1 && Array.isArray(manifest.chunks)
      && integer(manifest.chunks.length, 1, MAX_OBJECTS));
    let nodes = 0;
    for (const [index, chunk] of manifest.chunks.entries()) {
      requireOracle(exact(chunk, ["bytes", "sha256", "count"]) && matches(DIGEST, chunk.sha256)
        && integer(chunk.bytes, 1, 512 * 1024) && integer(chunk.count, 1, row.nodes));
      const body = object(prefix + `${index}.ndjson`, chunk.sha256);
      requireOracle(body.length === chunk.bytes && (nodes += chunk.count) <= row.nodes);
    }
    requireOracle(nodes === row.nodes);
  }
  requireOracle(referenced.size === objects.size);
}

async function replay(runtime: Miniflare, loaded: Awaited<ReturnType<typeof load>>): Promise<void> {
  stage = "sql-replay";
  const db = await runtime.getD1Database("DB");
  for (let index = 0; index < loaded.sql.length; index += 64) {
    const statements = loaded.sql.slice(index, index + 64);
    const results = await db.batch(statements.map((sql) => db.prepare(sql)));
    requireOracle(results.length === statements.length && results.every(({ success }) => success === true));
  }
  stage = "d1-readback";
  const expected = loaded.manifest.ledger;
  requireOracle(Array.isArray(expected) && expected.length === loaded.chain.length);
  const ledger = await db.prepare("SELECT position,name,sha256,mode,applied_at FROM subs_bot_schema_migrations ORDER BY position")
    .all<{ position: number; name: string; sha256: string; mode: string; applied_at: number }>();
  requireOracle(ledger.success && ledger.results.length === loaded.chain.length);
  for (const [index, actual] of ledger.results.entries()) {
    const pin = loaded.chain[index];
    const sealed = expected[index];
    requireOracle(exact(sealed, ["position", "name", "sha256", "mode", "applied_at"]) && integer(sealed.applied_at, 1)
      && actual.position === index + 1 && actual.position === sealed.position && actual.name === pin.name && actual.name === sealed.name
      && actual.sha256 === pin.sha256 && actual.sha256 === sealed.sha256 && actual.mode === "applied" && actual.mode === sealed.mode
      && actual.applied_at === sealed.applied_at);
  }
  const foreign = await db.prepare("PRAGMA foreign_key_check").all();
  requireOracle(foreign.success && foreign.results.length === 0);
  const sequence = await db.prepare("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'").all<{ seq: number }>();
  requireOracle(sequence.success && sequence.results.length === 1 && sequence.results[0].seq === loaded.manifest.targetSequenceHighWater);
  const summary = loaded.manifest.summary;
  requireOracle(record(summary) && record(summary.tableCounts));
  const tables = ["subscriptions", "subscription_trash", "subscription_lifecycle", "path_rules", "legacy_empty_subscription_exports",
    "normal_short_links", "legacy_subscription_short_links", "aggregate_links", "legacy_selected_aggregates", "legacy_selected_members",
    "telegram_inbox"];
  const counts = await db.batch<{ count: number }>(tables.map((table) => db.prepare(`SELECT count(*) AS count FROM ${table}`)));
  requireOracle(counts.length === tables.length && counts.every((row, index) => row.success && row.results.length === 1
    && integer(row.results[0].count, 0, 512) && row.results[0].count === (summary.tableCounts as RecordValue)[tables[index]])
    && summary.tableCounts.telegram_inbox === 0);
  await verifyReferences(db, loaded.objects);
  stage = "r2-replay";
  const bucket = await runtime.getR2Bucket("NODES");
  for (const [key, body] of loaded.objects) {
    const object = await bucket.put(key, body, { onlyIf: { etagDoesNotMatch: "*" } });
    requireOracle(object && object.size === body.length);
  }
  const listing = await bucket.list({ limit: MAX_OBJECTS + 1 });
  requireOracle(!listing.truncated && listing.objects.length === loaded.objects.size
    && listing.objects.every(({ key, size }) => loaded.objects.get(key)?.length === size));
}

async function bodyBytes(response: Response, maximum: number): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let size = 0;
  try {
    while (true) {
      const result = await reader.read();
      if (result.done) return Buffer.concat(chunks, size);
      if ((size += result.value.byteLength) > maximum) {
        await reader.cancel();
        throw new Error("Isolated V6 response exceeds its bound.");
      }
      chunks.push(Buffer.from(result.value));
    }
  } finally {
    reader.releaseLock();
  }
}

async function probe(runtime: Miniflare, request: ProbeRequest, remaining: number) {
  const { method, route, code, format } = request;
  const path = route === "short" ? `/s/${code}` : `/agg/${code}${format === null ? "" : `/${format}`}`;
  const response = await runtime.dispatchFetch(ORIGIN + path, { method, redirect: "manual", headers: { "Accept-Encoding": "identity" } });
  const { status, headers } = response;
  const contentType = headers.get("Content-Type");
  const cacheControl = headers.get("Cache-Control");
  const referrerPolicy = headers.get("Referrer-Policy");
  const noSniff = headers.get("X-Content-Type-Options");
  const contentLength = headers.get("Content-Length");
  const location = headers.get("Location");
  requireOracle(cacheControl === "private, no-store" && referrerPolicy === "no-referrer" && noSniff === "nosniff"
    && !headers.has("Set-Cookie") && !headers.has("Age") && (headers.get("Content-Encoding") ?? "identity") === "identity"
    && (contentLength === null || (/^(?:0|[1-9][0-9]{0,5})$/u.test(contentLength) && Number(contentLength) <= MAX_BODY)));
  if (status === 302) {
    requireOracle(route === "short" && contentType === null && matches(/^[\x21-\x7e]{1,512}(?![\s\S])/u, location));
  } else if (status === 200) {
    requireOracle(route === "aggregate" && format !== null && contentType === MEDIA.get(format) && location === null);
  } else {
    requireOracle([404, 406, 422, 503].includes(status) && contentType === TEXT && location === null);
  }
  const body = await bodyBytes(response, Math.min(MAX_BODY, remaining));
  requireOracle((method === "GET" && status !== 302) || body.length === 0);
  if (method === "GET") {
    requireOracle(contentLength === null || Number(contentLength) === body.length);
    requireOracle(status !== 200 || !body.length || contentLength !== null);
  }
  return { status, contentType, cacheControl, referrerPolicy, noSniff, contentLength, location, bodyBase64: body.toString("base64") };
}

async function main() {
  const uid = sandbox();
  stage = "input";
  const loaded = await load(await readInput(), uid);
  const runtime = new Miniflare({
    modules: true, script: loaded.script, compatibilityDate: loaded.compatibilityDate, host: "127.0.0.1",
    log: new Log(LogLevel.NONE), d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: loaded.revision },
    outboundService: () => { throw new Error("Isolated V6 oracle outbound denied."); },
  });
  const responses = [];
  try {
    await replay(runtime, loaded);
    stage = "health";
    const health = await runtime.dispatchFetch(ORIGIN + "/health", { redirect: "manual" });
    const state = parsed(await bodyBytes(health, 1024));
    requireOracle(health.status === 200 && exact(state, ["ok", "service", "revision"]) && state.ok === true
      && state.service === "subs-bot" && state.revision === loaded.revision);
    let remaining = MAX_RESPONSE_BYTES;
    for (const request of loaded.probes) {
      stage = "request";
      caseNumber += 1;
      const result = await probe(runtime, request, remaining);
      remaining -= Buffer.byteLength(result.bodyBase64, "base64");
      responses.push(result);
    }
  } finally {
    try {
      await runtime.dispose();
    } catch {
      stage = "dispose";
      throw new Error("Could not dispose isolated V6 runtime.");
    }
  }
  process.stdout.write(JSON.stringify({ responses }) + "\n");
}

try {
  await main();
} catch {
  // Capability strings, package paths, SQL and body bytes stay off stderr.
  const detail = (stage as Stage) === "request" ? `request, case ${caseNumber}` : stage;
  process.stderr.write(`The isolated V6 Worker oracle could not be confirmed (${detail}).\n`);
  process.exitCode = 2;
}

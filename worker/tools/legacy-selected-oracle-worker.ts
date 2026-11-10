/** Replay sealed synthetic aggregate candidates into the exact emitted Worker in hosted loopback. */

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, opendir, realpath } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Log, LogLevel, Miniflare } from "miniflare";
import { parse as parseYaml } from "yaml";
import { makeUnifiedClaimOracle } from "./legacy-unified-claim-oracle.ts";
import { GENERAL_RUNTIME_MIGRATION, makeUnifiedAuthActivationOracle } from "./legacy-unified-auth-activation-oracle.ts";
import { LEGACY_ALL_MIGRATION, LEGACY_ALL_MIGRATION_SHA256 } from "../src/legacy-all-aggregates.ts";
import { LEGACY_SUBSCRIPTION_SHORT_MIGRATION, LEGACY_SUBSCRIPTION_SHORT_SHA256 } from "../src/short-links.ts";
import { restoreOwnedSubscription } from "../src/subscriptions.ts";
import { LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256 } from "../src/telegram/temp-storage.ts";

const DIGEST = /^[a-f0-9]{64}(?![\s\S])/u;
const REVISION = /^[a-f0-9]{40}(?![\s\S])/u;
const DATE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}(?![\s\S])/u;
const CODE = /^[A-Za-z0-9_-]{12}(?![\s\S])/u;
const UUID = "[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}";
const KEY = new RegExp(`^subscriptions/[1-9][0-9]{0,15}/${UUID}/(?:manifest\\.json|(?:0|[1-9][0-9]{0,2})\\.ndjson)(?![\\s\\S])`, "u");
const PRIVATE_SHARE_KEY = new RegExp(`^private-shares/${UUID}\\.txt(?![\\s\\S])`, "u");
const MIGRATION = "0038_legacy_selected_aggregates.sql";
const MIGRATION_SHA = "29ddd93dc46120614c4837268ac2c0a0c5b4c48af9d7e4fe4de1e5e24451b74f";
const DYNAMIC_PROFILE = "dynamic-all-v8";
const UNIFIED_PROFILE = "unified-shares-v10";
const UNIFIED_AUTH_PROFILE = "unified-auth-v11";
const DYNAMIC_BOT = "74111";
const DYNAMIC_OWNER = "74112";
const DYNAMIC_FOREIGN = "74115";
const DYNAMIC_TRASH = 71;
const DYNAMIC_CODES = { DynAllA00001: DYNAMIC_OWNER, DynAllB00002: "74113", DynAllC00003: "74114" };
const DYNAMIC_PHASES = ["dormant", "active", "restored"] as const;
const DYNAMIC_COUNTS = { subscriptions: 4, subscription_trash: 1, path_rules: 1, legacy_empty_subscription_exports: 1,
  aggregate_links: 3, legacy_all_aggregates: 3, legacy_all_subscription_order: 0, legacy_temp_installations: 1,
  legacy_temp_batches: 3, normal_short_links: 0, legacy_subscription_short_links: 0, legacy_selected_aggregates: 0,
  legacy_selected_members: 0, telegram_inbox: 0, telegram_outbox: 0, telegram_temp_batch: 0, telegram_aggregate_slots: 0 };
const UNIFIED_COUNTS = { ...DYNAMIC_COUNTS, aggregate_links: 4, normal_short_links: 1, legacy_subscription_short_links: 2,
  legacy_selected_aggregates: 1, legacy_selected_members: 3, private_shares: 2, private_share_claims: 1 };
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
type DynamicPhase = (typeof DYNAMIC_PHASES)[number];
type Stage = "sandbox" | "input" | "request-shape" | "artifact" | "sql-replay" | "d1-readback" | "r2-replay"
  | "health" | "request" | "cutoff" | "restore" | "historical-claim" | "general-auth" | "dispose";
let stage: Stage = "sandbox";
let caseNumber = 0;
let dynamic = false;
let unified = false;
let unifiedAuth = false;

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

function dynamicRequests(value: unknown): Record<DynamicPhase, ProbeRequest[]> {
  requireOracle(exact(value, [...DYNAMIC_PHASES]));
  const phases = { dormant: requests(value.dormant), active: requests(value.active), restored: requests(value.restored) };
  const all = Object.values(phases).flat();
  requireOracle(all.length <= 64 && all.every(({ code }) => Object.hasOwn(DYNAMIC_CODES, code) || code === "DynAllX00004"));
  return phases;
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

function verifyDynamicManifest(manifest: RecordValue) {
  const links = manifest.dynamicAll, temp = manifest.legacyTempBaseline, summary = manifest.summary, source = manifest.source;
  const compatibility = manifest.shortLinkCompatibility;
  requireOracle(manifest.version === (unifiedAuth ? 11 : unified ? 10 : 8) && manifest.objectCount === (unified ? 10 : 8)
    && manifest.targetSequenceHighWater === DYNAMIC_TRASH
    && exact(compatibility, unified ? ["typed", "external", "selected", "dynamicAll"] : ["dynamicAll"])
    && compatibility.dynamicAll === "not-validated"
    && record(source) && source.legacyBotId === DYNAMIC_BOT && matches(DIGEST, source.tempInventoryManifestSha256)
    && record(links) && links.rows === 3 && links.markers === 3 && links.orderRows === 0
    && links.state === "dormant" && links.migrationSha256 === LEGACY_ALL_MIGRATION_SHA256
    && record(temp) && temp.installations === 1 && temp.batches === 3 && temp.nodes === 4 && temp.owners === 3
    && temp.state === "dormant" && temp.migrationSha256 === LEGACY_TEMP_MIGRATION_SHA256 && integer(temp.payloadBytes, 1, MAX_SQL)
    && record(summary) && record(summary.tableCounts) && record(summary.tableSha256));
  const counts = summary.tableCounts;
  requireOracle(Object.entries(unified ? UNIFIED_COUNTS : DYNAMIC_COUNTS).every(([table, expected]) => counts[table] === expected));
  if (unified) {
    requireOracle(compatibility.typed === "not-validated" && compatibility.external === "offline-equivalent"
      && compatibility.selected === "not-validated" && manifest.shareCompatibility === "not-validated");
  }
  const hashes = summary.tableSha256;
  for (const [detail, tables] of [[links, ["aggregate_links", "legacy_all_aggregates", "legacy_all_subscription_order"]],
    [temp, ["legacy_temp_installations", "legacy_temp_batches"]]] as const) {
    const expected = detail.tableSha256;
    requireOracle(exact(expected, [...tables]) && tables.every((table) => matches(DIGEST, expected[table])
      && expected[table] === hashes[table]));
  }
}

async function load(input: RecordValue, uid: number) {
  dynamic = input.profile === DYNAMIC_PROFILE;
  unifiedAuth = input.profile === UNIFIED_AUTH_PROFILE;
  unified = input.profile === UNIFIED_PROFILE || unifiedAuth;
  requireOracle(exact(input, ["workerDir", "workerManifestSha256", "candidateDir", "candidateManifestSha256", "revision",
    "sqlStatements", ...(unified ? [] : ["requests"]), ...(dynamic || unified ? ["profile"] : [])]) && matches(REVISION, input.revision));
  stage = "request-shape";
  const probes = unified ? null : dynamic ? dynamicRequests(input.requests) : requests(input.requests);
  stage = "artifact";
  const worker = await privateRoot(input.workerDir, uid);
  const candidate = await privateRoot(input.candidateDir, uid);
  const build = parsed(await pinnedFile(join(worker, "isolation.json"), 256 * 1024, input.workerManifestSha256, uid));
  requireOracle(build.version === 2 && build.ref === "refs/heads/main" && build.revision === input.revision
    && matches(DATE, build.compatibilityDate));
  const chain = migrations(build.migrations);
  if (unifiedAuth) {
    const migration = chain[43];
    requireOracle(migration?.name === GENERAL_RUNTIME_MIGRATION.name && migration.sha256 === GENERAL_RUNTIME_MIGRATION.sha256);
    await pinnedFile(join(worker, migration.name), 4096, migration.sha256, uid);
  }
  const script = decoder.decode(await pinnedFile(join(worker, "index.js"), 1024 * 1024, build.bundleSha256, uid));
  requireOracle(script.includes("subs-bot:legacy-selected-http:v1") && script.includes("subs-bot:legacy-selected-retirement:v1"));
  const manifest = parsed(await pinnedFile(join(candidate, "manifest.json"), 256 * 1024, input.candidateManifestSha256, uid));
  const marker = await privateFile(join(candidate, "manifest.sha256"), 65, uid);
  requireOracle(marker.equals(Buffer.from(`${input.candidateManifestSha256}\n`, "ascii"))
    && manifest.scope === "fresh-unbound-d1-r2" && record(manifest.workerArtifact)
    && manifest.workerArtifact.manifestSha256 === input.workerManifestSha256 && manifest.workerArtifact.revision === input.revision
    && manifest.workerArtifact.bundleSha256 === build.bundleSha256 && manifest.workerArtifact.compatibilityDate === build.compatibilityDate
    && manifest.workerArtifact.runId === build.runId && manifest.workerArtifact.runAttempt === build.runAttempt
    && JSON.stringify(migrations(manifest.workerArtifact.migrations)) === JSON.stringify(chain));
  if (dynamic || unified) {
    verifyDynamicManifest(manifest);
    requireOracle(chain[38]?.name === LEGACY_TEMP_MIGRATION_NAME && chain[38].sha256 === LEGACY_TEMP_MIGRATION_SHA256
      && chain[39]?.name === LEGACY_ALL_MIGRATION && chain[39].sha256 === LEGACY_ALL_MIGRATION_SHA256
      && script.includes("subs-bot:legacy-dynamic-all-read:v1") && script.includes("subs-bot:legacy-dynamic-all-order:v1"));
    if (unified) {
      requireOracle(chain[28]?.name === LEGACY_SUBSCRIPTION_SHORT_MIGRATION
        && chain[28].sha256 === LEGACY_SUBSCRIPTION_SHORT_SHA256);
    }
  } else {
    requireOracle(manifest.version === 6 && record(manifest.selectedAggregateLinks)
      && record(manifest.shortLinkCompatibility) && manifest.shortLinkCompatibility.selected === "not-validated"
      && manifest.selectedAggregateLinks.migrationSha256 === MIGRATION_SHA && integer(manifest.selectedAggregateLinks.rows, 1, 64));
  }
  const sql = statements(input.sqlStatements, await descriptor(candidate, "restore.sql", manifest.sql, MAX_SQL, uid));
  await descriptor(candidate, "lineage.ndjson", manifest.lineage, MAX_INPUT, uid);
  requireOracle(Array.isArray(manifest.objects) && integer(manifest.objects.length, 0, MAX_OBJECTS)
    && manifest.objectCount === manifest.objects.length);
  const objects = new Map<string, Buffer>();
  const inventory = new Set(["manifest.json", "manifest.sha256", "restore.sql", "lineage.ndjson"]);
  if (unified) {
    const source = manifest.source;
    requireOracle(record(source));
    const oracle = parsed(await pinnedFile(join(candidate, "oracle/manifest.json"), 4096, source.oracleManifestSha256, uid));
    const seal = await privateFile(join(candidate, "oracle/manifest.sha256"), 65, uid);
    requireOracle(seal.equals(Buffer.from(`${source.oracleManifestSha256}\n`, "ascii")) && oracle.externalRows === 1
      && oracle.sourceSha256 === source.sqliteSha256 && Array.isArray(oracle.files) && oracle.files.length === 1);
    const entry = oracle.files[0];
    requireOracle(exact(entry, ["file", "bytes", "sha256"]) && entry.file === "external.ndjson" && integer(entry.bytes, 1, 1024));
    const rows = await pinnedFile(join(candidate, "oracle/external.ndjson"), 1024, entry.sha256, uid);
    requireOracle(rows.length === entry.bytes);
    for (const name of ["manifest.json", "manifest.sha256", "external.ndjson"]) inventory.add(`oracle/${name}`);
  }
  let objectBytes = 0;
  for (const item of manifest.objects) {
    requireOracle(exact(item, ["key", "bytes", "sha256", "metadata"]));
    const privateShare = unified && matches(PRIVATE_SHARE_KEY, item.key);
    requireOracle((matches(KEY, item.key) || (privateShare && typeof item.key === "string")) && !objects.has(item.key)
      && integer(item.bytes, 1, privateShare ? 64 * 1024 : MAX_OBJECT_BYTES) && (objectBytes += item.bytes) <= MAX_OBJECT_BYTES
      && exact(item.metadata, ["custom", "http"]) && exact(item.metadata.custom, []) && exact(item.metadata.http, []));
    const path = `objects/${item.key}`;
    const body = await pinnedFile(join(candidate, path), item.bytes, item.sha256, uid);
    requireOracle(body.length === item.bytes);
    inventory.add(path);
    objects.set(item.key, body);
  }
  requireOracle(objectBytes === manifest.objectBytes);
  if (unified) requireOracle(inventory.size === 17 && [...objects.keys()].filter((key) => PRIVATE_SHARE_KEY.test(key)).length === 2);
  await checkInventory(candidate, inventory, uid);
  requireOracle(matches(DIGEST, input.workerManifestSha256) && matches(DIGEST, input.candidateManifestSha256));
  return { script, revision: input.revision, compatibilityDate: build.compatibilityDate, chain, manifest, sql, objects, probes,
    workerManifestSha256: input.workerManifestSha256, candidateManifestSha256: input.candidateManifestSha256 };
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
  if (unified) {
    const shares = await db.prepare(`SELECT payload_id,payload_bytes,payload_sha256 FROM private_shares ORDER BY id LIMIT 3`).all<{
      payload_id: string; payload_bytes: number; payload_sha256: string;
    }>();
    requireOracle(shares.success && shares.results.length === 2);
    for (const row of shares.results) {
      const key = `private-shares/${row.payload_id}.txt`;
      requireOracle(PRIVATE_SHARE_KEY.test(key) && matches(DIGEST, row.payload_sha256) && integer(row.payload_bytes, 1, 64 * 1024)
        && object(key, row.payload_sha256).length === row.payload_bytes);
    }
  }
  requireOracle(referenced.size === objects.size);
}

async function replay(runtime: Miniflare, loaded: Awaited<ReturnType<typeof load>>, workerName?: string): Promise<void> {
  stage = "sql-replay";
  const db = await runtime.getD1Database("DB", workerName);
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
    "telegram_inbox", ...(dynamic || unified ? ["telegram_outbox", "telegram_temp_batch", "telegram_aggregate_slots",
      "legacy_temp_installations", "legacy_temp_batches", "legacy_all_aggregates", "legacy_all_subscription_order"] : []),
    ...(unified ? ["private_shares", "private_share_claims"] : [])];
  const counts = await db.batch<{ count: number }>(tables.map((table) => db.prepare(`SELECT count(*) AS count FROM ${table}`)));
  requireOracle(counts.length === tables.length && counts.every((row, index) => row.success && row.results.length === 1
    && integer(row.results[0].count, 0, 512) && row.results[0].count === (summary.tableCounts as RecordValue)[tables[index]])
    && summary.tableCounts.telegram_inbox === 0);
  await verifyReferences(db, loaded.objects);
  stage = "r2-replay";
  const bucket = await runtime.getR2Bucket("NODES", workerName);
  for (const [key, body] of loaded.objects) {
    const object = await bucket.put(key, body, { onlyIf: { etagDoesNotMatch: "*" } });
    requireOracle(object && object.size === body.length);
  }
  const listing = await bucket.list({ limit: MAX_OBJECTS + 1 });
  requireOracle(!listing.truncated && listing.objects.length === loaded.objects.size
    && listing.objects.every(({ key, size }) => loaded.objects.get(key)?.length === size));
}

async function activateDynamic(runtime: Miniflare, manifest: RecordValue) {
  const db = await runtime.getD1Database("DB");
  requireOracle(record(manifest.source) && record(manifest.legacyTempBaseline));
  const installation = await db.prepare(`SELECT bot_id AS bot,inventory_sha256 AS inventory,cutover_epoch AS cutover
    FROM legacy_temp_installations LIMIT 2`).all();
  const state = installation.results[0];
  requireOracle(installation.success && installation.results.length === 1 && state.bot === DYNAMIC_BOT
    && state.cutover === null && matches(DIGEST, state.inventory) && state.inventory === manifest.source.tempInventoryManifestSha256);
  const links = await db.prepare(`SELECT marker.code_sha256 AS digest,marker.bot_id AS bot,marker.owner_id AS owner,
    marker.inventory_sha256 AS inventory,link.kind,link.selected_ids AS selection,link.revoked_at AS revoked,
    link.owner_id AS linkOwner,link.bot_id AS linkBot FROM legacy_all_aggregates AS marker
    JOIN aggregate_links AS link USING(code_sha256) ORDER BY marker.owner_id LIMIT 4`).all();
  const expected = Object.entries(DYNAMIC_CODES);
  requireOracle(links.success && links.results.length === expected.length && links.results.every((link, index) => {
    const [code, owner] = expected[index];
    return link.digest === sha(code) && link.bot === DYNAMIC_BOT && link.linkBot === DYNAMIC_BOT && link.owner === owner
      && link.linkOwner === owner && link.inventory === state.inventory && link.kind === "all" && link.selection === null && link.revoked === null;
  }));
  const batches = await db.prepare(`SELECT bot_id AS bot,actor_id AS owner,first_legacy_id AS first,last_legacy_id AS last,
    node_count AS count,payload_bytes AS bytes,payload_sha256 AS digest,nodes_json AS json
    FROM legacy_temp_batches ORDER BY actor_id LIMIT 4`).all();
  const expectedBatches = [
    [DYNAMIC_OWNER, 2, 8, 2, "alpha", "temporary"],
    [DYNAMIC_CODES.DynAllB00002, 6, 6, 1, "temporary-only", "temporary-only"],
    [DYNAMIC_FOREIGN, 3, 3, 1, "foreign temporary", "foreign-temporary"],
  ] as const;
  let totalBytes = 0;
  requireOracle(batches.success && batches.results.length === expectedBatches.length && batches.results.every((batch, index) => {
    const [owner, first, last, count, name, label] = expectedBatches[index];
    const share = `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#${label}`;
    const json = JSON.stringify(Array.from({ length: count }, () => ({ name, type: "temp", share })));
    const bytes = Buffer.byteLength(json);
    totalBytes += bytes;
    return batch.bot === DYNAMIC_BOT && batch.owner === owner && batch.first === first && batch.last === last
      && batch.count === count && batch.json === json && batch.bytes === bytes && batch.digest === sha(json);
  }) && totalBytes === manifest.legacyTempBaseline.payloadBytes);
  // The sealed candidate remains dormant. Only this disposable runtime is activated.
  const changed = await db.prepare(`UPDATE legacy_temp_installations SET cutover_epoch=unixepoch()-1
    WHERE bot_id=? AND inventory_sha256=? AND cutover_epoch IS NULL`).bind(DYNAMIC_BOT, state.inventory).run();
  requireOracle(changed.success && changed.meta.changes === 1);
}

async function restoreDynamic(runtime: Miniflare) {
  const db = await runtime.getD1Database("DB");
  const trash = await db.prepare(`SELECT token,generation,snapshot_id AS snapshot,lifecycle_revision AS revision
    FROM subscription_trash WHERE id=? AND owner_id=?`).bind(DYNAMIC_TRASH, DYNAMIC_OWNER).first();
  requireOracle(trash && trash.token === "legacy-dynamic-token-trash" && trash.generation === 1 && integer(trash.revision, 1));
  requireOracle(!await restoreOwnedSubscription(db, { id: DYNAMIC_TRASH, ownerId: DYNAMIC_FOREIGN, expectedLifecycleRevision: trash.revision }));
  requireOracle(await restoreOwnedSubscription(db, { id: DYNAMIC_TRASH, ownerId: DYNAMIC_OWNER, expectedLifecycleRevision: trash.revision }));
  const active = await db.prepare(`SELECT sub.token,sub.snapshot_id AS snapshot,lifecycle.revision,rank.anchor,rank.tie
    FROM subscriptions AS sub JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
    JOIN legacy_all_subscription_order AS rank ON rank.subscription_id=sub.id AND rank.owner_id=sub.owner_id
    WHERE sub.id=? AND sub.owner_id=? AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id=sub.id)`)
    .bind(DYNAMIC_TRASH, DYNAMIC_OWNER).first();
  requireOracle(active !== null && active.token === trash.token && active.snapshot === trash.snapshot && active.revision === trash.revision + 1
    && active.anchor === DYNAMIC_TRASH && active.tie === 1);
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
  return probePath(runtime, method, path, route === "short" ? null : format === null ? undefined : MEDIA.get(format), remaining);
}

async function probePath(runtime: Miniflare, method: "GET" | "HEAD", path: string, media: string | null | undefined, remaining: number) {
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
    requireOracle(media === null && contentType === null && matches(/^[\x21-\x7e]{1,512}(?![\s\S])/u, location));
  } else if (status === 200) {
    requireOracle(typeof media === "string" && contentType === media && location === null);
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

async function verifyUnifiedRoutes(runtime: Miniflare, manifest: RecordValue) {
  const selected = "UnifiedSel01", typedActive = "UnifiedAct01", typedTrash = "UnifiedDel01", external = "UnifiedExt01";
  const all = Object.keys(DYNAMIC_CODES), [owner, tempOnly, empty] = all;
  const alphaPath = "/sub/legacy-dynamic-token-alpha/clash", trashPath = "/sub/legacy-dynamic-token-trash/v2ray";
  const rawBase64 = (...labels: string[]) => Buffer.from(labels.map(
    (label) => `ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#${label}`).join("\n")).toString("base64");
  let remaining = MAX_RESPONSE_BYTES;
  let routePairs = 0;
  async function pair(path: string, status: number, media: string | null, location: string | null = null) {
    const responses = [];
    for (const method of ["GET", "HEAD"] as const) {
      stage = "request";
      caseNumber += 1;
      const response = await probePath(runtime, method, path, media, remaining);
      requireOracle(response.status === status && response.location === location);
      remaining -= Buffer.byteLength(response.bodyBase64, "base64");
      responses.push(response);
    }
    const [get, head] = responses;
    const bytes = Buffer.from(get.bodyBase64, "base64");
    requireOracle(head.bodyBase64 === "" && head.contentType === get.contentType);
    if (status === 200 && media === TEXT && path.startsWith("/agg/") && bytes.length > 0) {
      requireOracle(head.contentLength === String(bytes.length));
    } else {
      requireOracle(head.contentLength === null || head.contentLength === String(bytes.length));
    }
    if (status === 404) requireOracle(bytes.equals(Buffer.from("Not found.")));
    routePairs += 1;
    return bytes;
  }
  const redirect = (code: string, location: string) => pair(`/s/${code}`, 302, null, location);
  const missing = (path: string) => pair(path, 404, null);
  async function exportBase64(path: string, ...labels: string[]) {
    const bytes = await pair(path, 200, TEXT);
    requireOracle(bytes.equals(Buffer.from(rawBase64(...labels), "ascii")));
  }
  const exportAggregate = (code: string, ...labels: string[]) => exportBase64(`/agg/${code}/base64`, ...labels);

  await redirect(typedActive, alphaPath);
  const clash: unknown = parseYaml(decoder.decode(await pair(alphaPath, 200, YAML)));
  requireOracle(record(clash) && Array.isArray(clash.proxies) && clash.proxies.length === 1);
  const [proxy] = clash.proxies;
  requireOracle(exact(proxy, ["name", "type", "server", "port", "cipher", "password"])
    && proxy.name === "alpha → mapped" && proxy.type === "ss" && proxy.server === "203.0.113.10" && proxy.port === 8388
    && proxy.cipher === "aes-256-gcm" && proxy.password === "fixture");
  await missing(`/s/${typedTrash}`);
  await redirect(external, "https://example.org/fixture?mode=exact#keep");
  await redirect(selected, `/agg/${selected}/clash`);
  await exportAggregate(selected, "beta", "alpha", "beta");
  await missing("/s/DynAllX00004");
  for (const code of all) {
    await missing(`/s/${code}`);
    await missing(`/agg/${code}/base64`);
  }

  stage = "cutoff";
  await activateDynamic(runtime, manifest);
  for (const code of all) await redirect(code, `/agg/${code}/clash`);
  await exportAggregate(owner, "alpha", "beta", "temporary", "temporary");
  await exportAggregate(tempOnly, "temporary-only");
  await exportAggregate(empty);
  await exportAggregate(selected, "beta", "alpha", "beta");

  stage = "restore";
  await restoreDynamic(runtime);
  await redirect(typedTrash, trashPath);
  await exportBase64(trashPath, "trash");
  await exportAggregate(selected, "beta", "alpha", "beta");
  await exportAggregate(owner, "alpha", "beta", "trash", "temporary", "temporary");
  return { routePairs };
}

async function main() {
  const uid = sandbox();
  stage = "input";
  const loaded = await load(await readInput(), uid);
  const claim = unified && !unifiedAuth ? makeUnifiedClaimOracle() : null;
  const auth = unifiedAuth
    ? makeUnifiedAuthActivationOracle(loaded.revision, loaded.workerManifestSha256, loaded.candidateManifestSha256) : null;
  const shared = { modules: true, script: loaded.script, compatibilityDate: loaded.compatibilityDate };
  const runtime = auth ? new Miniflare({ host: "127.0.0.1", log: new Log(LogLevel.NONE),
    workers: [
      { name: "general", isolation: undefined },
      { name: "isolation", isolation: auth.isolationConfig },
      { name: "malformed-isolation", isolation: "invalid" },
    ].map(({ name, isolation }) => ({
      ...shared, name, d1Databases: { DB: "v11-activation-fixture" }, r2Buckets: { NODES: "v11-activation-fixture" },
      bindings: { BUILD_REVISION: loaded.revision, TELEGRAM_GENERAL_CONFIG: auth.generalConfig,
        ...(isolation === undefined ? {} : { TELEGRAM_ISOLATION_CONFIG: isolation }) },
      outboundService: auth.outboundService,
    })),
  }) : new Miniflare({
    ...shared, host: "127.0.0.1", log: new Log(LogLevel.NONE), d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: loaded.revision, ...(claim ? { LEGACY_SUBSCRIPTION_SHORTS: "1",
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(claim.policy) } : {}) },
    outboundService: claim?.outboundService ?? (() => { throw new Error("Isolated restore oracle outbound denied."); }),
  });
  let responses: unknown;
  try {
    await replay(runtime, loaded, auth ? "general" : undefined);
    stage = "health";
    const health = auth
      ? await (await runtime.getWorker("general")).fetch(ORIGIN + "/health", { redirect: "manual" })
      : await runtime.dispatchFetch(ORIGIN + "/health", { redirect: "manual" });
    const state = parsed(await bodyBytes(health, 1024));
    requireOracle(health.status === 200 && exact(state, ["ok", "service", "revision"]) && state.ok === true
      && state.service === "subs-bot" && state.revision === loaded.revision);
    let remaining = MAX_RESPONSE_BYTES;
    const runProbes = async (requests: ProbeRequest[]) => {
      const results = [];
      for (const request of requests) {
        stage = "request";
        caseNumber += 1;
        const result = await probe(runtime, request, remaining);
        remaining -= Buffer.byteLength(result.bodyBase64, "base64");
        results.push(result);
      }
      return results;
    };
    if (auth) {
      stage = "general-auth";
      responses = await auth.verify(runtime, ORIGIN, loaded.manifest);
    } else if (loaded.probes === null) {
      requireOracle(claim);
      const routes = await verifyUnifiedRoutes(runtime, loaded.manifest);
      stage = "historical-claim";
      responses = { ...routes, historicalClaimReplies: await claim.verify(runtime, ORIGIN) };
    } else if (Array.isArray(loaded.probes)) {
      responses = await runProbes(loaded.probes);
    } else {
      const dormant = await runProbes(loaded.probes.dormant);
      stage = "cutoff";
      await activateDynamic(runtime, loaded.manifest);
      const active = await runProbes(loaded.probes.active);
      stage = "restore";
      await restoreDynamic(runtime);
      responses = { dormant, active, restored: await runProbes(loaded.probes.restored) };
    }
  } finally {
    try {
      await runtime.dispose();
    } catch {
      stage = "dispose";
      throw new Error("Could not dispose isolated V6 runtime.");
    }
  }
  process.stdout.write(JSON.stringify(unifiedAuth ? { activation: responses } : unified ? { continuity: responses } : { responses }) + "\n");
}

try {
  await main();
} catch {
  // Capability strings, package paths, SQL and body bytes stay off stderr.
  const detail = (stage as Stage) === "request" ? `request, case ${caseNumber}` : stage;
  process.stderr.write(`The isolated ${unifiedAuth ? "V11" : unified ? "V10" : dynamic ? "V8" : "V6"} Worker oracle could not be confirmed (${detail}).\n`);
  process.exitCode = 2;
}

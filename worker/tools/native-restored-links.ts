/** Hosted, no-egress HTTP readback of the exact restored native data and bundle.
 * Private tokens and object contents never enter the public report or errors.
 */
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, writeFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Log, LogLevel, Miniflare } from "miniflare";
import { isValidStoredShare } from "../src/stored-share.ts";
import { parseDisplayTimeZone } from "../src/telegram/display-time.ts";
import { ISOLATION_PUBLIC_ORIGIN } from "../src/public-origin.ts";

const sha = (raw: Uint8Array | string) => createHash("sha256").update(raw).digest("hex");
const DIGEST = /^[a-f0-9]{64}$/u;
const TOKEN = /^[A-Za-z0-9_-]{16,128}$/u;
// dispatchFetch stays inside the loopback-only runtime. Its origin must still
// satisfy the exact emitted Worker's public-origin admission guard.
const ORIGIN = ISOLATION_PUBLIC_ORIGIN;
const MAX_SQL = 32 * 1024 * 1024;
const MAX_RESPONSE = 24 * 1024 * 1024;
const CONTENT_DENIAL = Buffer.from("Subscription content cannot be exported.", "utf8");
const KEY = /^(?:subscriptions\/[1-9][0-9]{0,15}\/[a-f0-9-]{36}\/(?:[0-9]{1,3}\.ndjson|manifest\.json)|private-shares\/[a-f0-9-]{36}\.txt)$/u;
let stage = "sandbox";
let failure: Record<string, string | number | boolean> | null = null;
function requireSafe(value: unknown): asserts value {
  if (!value) throw new Error("Native restored-link validation failed.");
}
function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function integer(value: unknown, max: number): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= max;
}
const IDENTIFIER = /^[a-z][a-z0-9_]*$/u;
function identifier(value: unknown): string {
  requireSafe(typeof value === "string" && IDENTIFIER.test(value));
  return `"${value}"`;
}
function cell(value: unknown): string | number | null {
  requireSafe(Array.isArray(value));
  if (value.length === 1 && value[0] === "null") return null;
  requireSafe(value.length === 2 && typeof value[1] === "string");
  if (value[0] === "text") { requireSafe(Buffer.byteLength(value[1]) <= 2_000_000); return value[1]; }
  if (value[0] === "integer") {
    requireSafe(/^-?[0-9]+$/u.test(value[1]) && Number.isSafeInteger(Number(value[1])));
    return Number(value[1]);
  }
  requireSafe(value[0] === "real");
  // Python's exact float.hex encoding avoids JSON decimal/negative-zero drift.
  const parsed = /^(-?)0x([01])\.([a-f0-9]{1,13})p([+-][0-9]{1,4})$/u.exec(value[1]);
  requireSafe(parsed);
  const number = (parsed[1] ? -1 : 1) * (Number(parsed[2]) + Number.parseInt(parsed[3], 16) / 16 ** parsed[3].length) * 2 ** Number(parsed[4]);
  requireSafe(Number.isFinite(number));
  return number;
}
async function privateRoot(path: string, uid: number) {
  requireSafe(isAbsolute(path) && resolve(path) === path && await realpath(path) === path);
  const info = await lstat(path);
  requireSafe(info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0);
  return path;
}
async function privateFile(path: string, max: number, uid: number) {
  requireSafe(await realpath(path) === path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    requireSafe(info.isFile() && info.uid === uid && info.nlink === 1 && (info.mode & 0o077) === 0 && integer(info.size, max));
    const raw = Buffer.alloc(info.size + 1);
    let size = 0;
    while (size < raw.length) {
      const part = await file.read(raw, size, raw.length - size, size);
      if (!part.bytesRead) break;
      size += part.bytesRead;
    }
    requireSafe(size === info.size);
    return raw.subarray(0, size);
  } finally { await file.close(); }
}
async function bytes(response: Response, max = MAX_RESPONSE) {
  const reader = response.body?.getReader();
  const hash = createHash("sha256");
  let size = 0;
  if (reader) for (;;) {
    const next = await reader.read();
    if (next.done) break;
    size += next.value.byteLength;
    requireSafe(size <= max);
    hash.update(next.value);
  }
  return { bytes: size, sha256: hash.digest("hex") };
}
async function main() {
  const uid = process.getuid?.();
  const interfaces = networkInterfaces();
  requireSafe(process.platform === "linux" && uid !== undefined && uid !== 0 && Object.keys(interfaces).join() === "lo"
    && interfaces.lo?.some(({ address, internal }) => internal && address === "127.0.0.1") && process.argv.length === 5);
  stage = "private-input";
  const root = await privateRoot(process.argv[2], uid);
  const bundle = process.argv[3];
  requireSafe(isAbsolute(bundle) && await realpath(bundle) === bundle);
  const input: unknown = JSON.parse((await privateFile(join(root, "input.json"), 6 * MAX_SQL + 1024 * 1024, uid)).toString("utf8"));
  requireSafe(record(input) && input.version === 2 && typeof input.revision === "string" && /^[a-f0-9]{40}$/u.test(input.revision)
    && typeof input.moduleSha256 === "string" && DIGEST.test(input.moduleSha256) && typeof input.dataSha256 === "string"
    && DIGEST.test(input.dataSha256) && typeof input.compatibilityDate === "string" && /^\d{4}-\d{2}-\d{2}$/u.test(input.compatibilityDate)
    && record(input.replay) && Array.isArray(input.replay.schema) && input.replay.schema.length <= 2000
    && Array.isArray(input.replay.tables) && input.replay.tables.length <= 500 && typeof input.replaySha256 === "string"
    && DIGEST.test(input.replaySha256) && sha(JSON.stringify(input.replay)) === input.replaySha256 && record(input.tableCounts)
    && Object.entries(input.tableCounts).every(([name, count]) => /^[a-z][a-z0-9_]*$/u.test(name) && integer(count, 20_000))
    && Array.isArray(input.objects) && input.objects.length <= 512
    && Array.isArray(input.aggregateProbes) && input.aggregateProbes.length <= 32);
  const scriptFile = await open(join(bundle, "index.js"), constants.O_RDONLY | constants.O_NOFOLLOW);
  let script: Buffer;
  try {
    const info = await scriptFile.stat();
    requireSafe(info.isFile() && info.size <= 4 * 1024 * 1024);
    script = await scriptFile.readFile();
  } finally { await scriptFile.close(); }
  requireSafe(sha(script) === input.moduleSha256);
  const objects = new Map<string, Buffer>();
  for (const [ordinal, value] of input.objects.entries()) {
    requireSafe(record(value) && typeof value.key === "string" && KEY.test(value.key) && !objects.has(value.key)
      && value.file === `object-${ordinal}.bin` && integer(value.bytes, 512 * 1024)
      && typeof value.sha256 === "string" && DIGEST.test(value.sha256));
    const raw = await privateFile(join(root, value.file), 512 * 1024, uid);
    requireSafe(raw.length === value.bytes && sha(raw) === value.sha256);
    objects.set(value.key, raw);
  }
  let outboundAttempts = 0;
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"), compatibilityDate: input.compatibilityDate,
    host: "127.0.0.1", log: new Log(LogLevel.NONE), d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: input.revision, PUBLIC_ORIGIN: ORIGIN },
    outboundService: () => { outboundAttempts += 1; throw new Error("Native restored-link egress denied."); },
  });
  const counts = { storedShareExports: 0, legacyEmptyExports: 0, unpublishedDenials: 0, trashDenials: 0, oversizeDenials: 0, activeAllAggregatePairs: 0,
    activeAllAggregateSuccessPairs: 0, activeAllAggregateContentDenialPairs: 0,
    missingDenials: 0, omittedStructuredOrInvalidShare: 0, omittedResponseLimit: 0, omittedHashedCapabilities: 0 };
  let migrationCount = 0;
  let restoredEffectiveDisplayTimezones: string[] = [];
  try {
    let checkNumber = 0;
    const checkExpected = async (response: Response, method: "GET" | "HEAD", status: number, expectedBytes: number, expectedSha256: string, category: string) => {
      checkNumber += 1;
      failure = { category, check: checkNumber, method, expectedStatus: status, actualStatus: response.status };
      stage = "native-http-status";
      requireSafe(response.status === status);
      stage = "native-http-headers";
      failure = { ...failure, cacheControlMatches: response.headers.get("cache-control") === "private, no-store",
        referrerPolicyMatches: response.headers.get("referrer-policy") === "no-referrer",
        nosniffMatches: response.headers.get("x-content-type-options") === "nosniff" };
      requireSafe(failure.cacheControlMatches && failure.referrerPolicyMatches && failure.nosniffMatches);
      stage = "native-http-body";
      failure = { category, check: checkNumber, method, expectedBytes, expectedSha256 };
      const actual = await bytes(response);
      failure = { ...failure, actualBytes: actual.bytes, actualSha256: actual.sha256 };
      requireSafe(actual.bytes === expectedBytes && actual.sha256 === expectedSha256);
      failure = null;
    };
    const checkResponse = async (response: Response, method: "GET" | "HEAD", status: number, body: Buffer, category: string) => {
      const expected = method === "HEAD" ? Buffer.alloc(0) : body;
      await checkExpected(response, method, status, expected.length, sha(expected), category);
    };
    stage = "runtime-health";
    const health = await runtime.dispatchFetch(ORIGIN + "/health", { redirect: "manual" });
    await checkResponse(health, "GET", 200, Buffer.from(JSON.stringify({ ok: true, service: "subs-bot", revision: input.revision })), "health");
    stage = "private-replay";
    const db = await runtime.getD1Database("DB");
    // Schema comes from the exact validated scratch database, not a SQL dump
    // parser. Values use bindings, including valid cells above 100KB.
    const statements = [db.prepare("PRAGMA defer_foreign_keys=ON")];
    for (const entry of input.replay.schema) {
      requireSafe(Array.isArray(entry) && entry.length === 3 && (entry[0] === "table" || entry[0] === "index")
        && typeof entry[1] === "string" && IDENTIFIER.test(entry[1]) && typeof entry[2] === "string"
        && Buffer.byteLength(entry[2]) < 100_000 && /^CREATE (?:TABLE|(?:UNIQUE )?INDEX) /u.test(entry[2]));
      statements.push(db.prepare(entry[2]));
    }
    const tables: { name: string; columns: string[]; primary: string[]; rows: (string | number | null)[][] }[] = [];
    let rowCount = 0;
    for (const entry of input.replay.tables) {
      requireSafe(record(entry) && typeof entry.name === "string" && IDENTIFIER.test(entry.name)
        && Array.isArray(entry.columns) && entry.columns.length > 0 && entry.columns.length <= 100
        && Array.isArray(entry.primary) && entry.primary.length > 0 && Array.isArray(entry.rows));
      const columns = entry.columns.map((column) => {
        requireSafe(Array.isArray(column) && column.length === 2 && typeof column[0] === "string" && IDENTIFIER.test(column[0])
          && ["TEXT", "INTEGER", "REAL"].includes(column[1]));
        return column[0];
      });
      requireSafe(new Set(columns).size === columns.length && entry.primary.every((key) => typeof key === "string" && columns.includes(key)));
      const rows = entry.rows.map((row) => {
        requireSafe(Array.isArray(row) && row.length === columns.length);
        rowCount += 1;
        requireSafe(rowCount <= 20_000);
        return row.map(cell);
      });
      tables.push({ name: entry.name, columns, primary: entry.primary, rows });
    }
    requireSafe(new Set(tables.map(({ name }) => name)).size === tables.length);
    // AUTOINCREMENT creates sqlite_sequence implicitly. Restore its exact final
    // high water only after ordinary rows have performed their normal inserts.
    for (const table of [...tables.filter(({ name }) => name !== "sqlite_sequence"), ...tables.filter(({ name }) => name === "sqlite_sequence")]) {
      if (table.name === "sqlite_sequence") statements.push(db.prepare("DELETE FROM sqlite_sequence"));
      const sql = `INSERT INTO ${identifier(table.name)} (${table.columns.map(identifier).join(",")}) VALUES (${table.columns.map(() => "?").join(",")})`;
      for (const row of table.rows) statements.push(db.prepare(sql).bind(...row));
    }
    // Child-before-parent rows are permitted only inside this deferred, checked
    // transaction. No triggers/views are present in the validated source schema.
    const results = await db.batch(statements);
    requireSafe(results.every((result) => result.success));
    requireSafe((await db.prepare("PRAGMA foreign_key_check").all()).results.length === 0);
    for (const [table, count] of Object.entries(input.tableCounts)) {
      const found = await db.prepare(`SELECT count(*) AS count FROM "${table}"`).first<number>("count");
      requireSafe(found === count);
    }
    // Compare every cell, including large temporary TEXT and sequence state.
    for (const table of tables) {
      const sql = `SELECT ${table.columns.map(identifier).join(",")} FROM ${identifier(table.name)} ORDER BY ${table.primary.map(identifier).join(",")} LIMIT ? OFFSET ?`;
      const pageSize = table.rows.some((row) => row.some((value) => typeof value === "string" && Buffer.byteLength(value) > 100_000)) ? 1 : 16;
      for (let offset = 0; offset < table.rows.length; offset += pageSize) {
        const found = await db.prepare(sql).bind(Math.min(pageSize, table.rows.length - offset), offset).raw();
        requireSafe(found.length === Math.min(pageSize, table.rows.length - offset));
        for (const [ordinal, row] of found.entries()) requireSafe(row.length === table.columns.length
          && row.every((value, column) => value === table.rows[offset + ordinal][column]));
      }
    }
    migrationCount = await db.prepare("SELECT count(*) AS count FROM subs_bot_schema_migrations").first<number>("count") ?? 0;
    const settings = await db.prepare("SELECT DISTINCT timezone FROM telegram_bot_display_settings ORDER BY timezone").all<{ timezone: string }>();
    restoredEffectiveDisplayTimezones = [...new Set(settings.results.map(({ timezone }) => parseDisplayTimeZone(timezone) ?? "UTC"))];
    if (restoredEffectiveDisplayTimezones.length === 0) restoredEffectiveDisplayTimezones = ["UTC"];
    const bucket = await runtime.getR2Bucket("NODES");
    for (const [key, raw] of objects) requireSafe((await bucket.put(key, raw))?.size === raw.length);
    const check = async (token: string, status: number, body: Buffer, category: keyof typeof counts) => {
      requireSafe(TOKEN.test(token));
      for (const method of ["GET", "HEAD"] as const) {
        stage = "native-http-request";
        failure = { category, check: checkNumber + 1, method, expectedStatus: status };
        const response = await runtime.dispatchFetch(ORIGIN + "/sub/" + token + "/base64", { method, redirect: "manual" });
        await checkResponse(response, method, status, body, category);
      }
      counts[category] += 1;
    };
    stage = "native-http-links";
    const subscriptions = await db.prepare("SELECT id,owner_id,token,generation,snapshot_id FROM subscriptions ORDER BY id")
      .all<{ id: number; owner_id: string; token: string; generation: number; snapshot_id: string | null }>();
    for (const row of subscriptions.results) {
      if (row.generation === 0) {
        const legacy = await db.prepare("SELECT token_sha256 FROM legacy_empty_subscription_exports WHERE subscription_id=? AND owner_id=?").bind(row.id, row.owner_id)
          .first<string>("token_sha256");
        const empty = legacy === sha(row.token);
        await check(row.token, empty ? 200 : 404, Buffer.from(empty ? "" : "Not found."), empty ? "legacyEmptyExports" : "unpublishedDenials");
        continue;
      }
      const prefix = `subscriptions/${row.id}/${row.snapshot_id}/`;
      const manifest = JSON.parse(objects.get(prefix + "manifest.json")!.toString("utf8"));
      const nodes = manifest.chunks.flatMap((_chunk: unknown, ordinal: number) => objects.get(prefix + ordinal + ".ndjson")!
        .toString("utf8").trimEnd().split("\n").map((line) => JSON.parse(line)));
      if (!nodes.every((node: unknown) => record(node) && isValidStoredShare(node.share))) {
        counts.omittedStructuredOrInvalidShare += 1;
        continue;
      }
      const raw = Buffer.from(nodes.map((node: { share: string }) => node.share).join("\n"), "utf8");
      if (raw.length > 16 * 1024 * 1024) {
        await check(row.token, 422, Buffer.from("Subscription content cannot be exported."), "oversizeDenials");
        continue;
      }
      const encoded = raw.toString("base64");
      if (encoded.length > MAX_RESPONSE) { counts.omittedResponseLimit += 1; continue; }
      await check(row.token, 200, Buffer.from(encoded, "ascii"), "storedShareExports");
    }
    const trash = await db.prepare("SELECT token FROM subscription_trash ORDER BY id").all<{ token: string }>();
    for (const row of trash.results) await check(row.token, 404, Buffer.from("Not found."), "trashDenials");
    const missing = "NativeRestoreMissingToken0001";
    requireSafe(!subscriptions.results.some((row) => row.token === missing) && !trash.results.some((row) => row.token === missing));
    await check(missing, 404, Buffer.from("Not found."), "missingDenials");
    const allSlots = await db.prepare("SELECT count(*) AS count FROM telegram_aggregate_slots WHERE code_sha256 IS NOT NULL").first<number>("count");
    requireSafe(allSlots === input.aggregateProbes.length);
    const seenAggregateCodes = new Set<string>();
    for (const probe of input.aggregateProbes) {
      requireSafe(record(probe) && typeof probe.code === "string" && /^[A-Za-z0-9_-]{22}$/u.test(probe.code)
        && !seenAggregateCodes.has(probe.code) && probe.codeSha256 === sha(probe.code));
      seenAggregateCodes.add(probe.code);
      const match = await db.prepare(`SELECT count(*) AS count FROM telegram_aggregate_slots AS slot
        JOIN aggregate_links AS link USING(code_sha256) WHERE slot.code_sha256=? AND link.kind='all'
          AND link.revoked_at IS NULL AND link.owner_id=slot.actor_id AND link.bot_id=slot.bot_id
          AND NOT EXISTS(SELECT 1 FROM legacy_all_aggregates WHERE code_sha256=slot.code_sha256)`)
        .bind(probe.codeSha256).first<number>("count");
      requireSafe(match === 1);
      requireSafe(record(probe.get) && record(probe.head) && (probe.get.status === 200 || probe.get.status === 422)
        && probe.get.status === probe.head.status);
      for (const [method, key] of [["GET", "get"], ["HEAD", "head"]] as const) {
        const expected = probe[key];
        requireSafe(record(expected) && (expected.status === 200 || expected.status === 422) && integer(expected.bytes, MAX_RESPONSE)
          && (method === "GET" ? expected.bytes > 0 : expected.bytes === 0)
          && typeof expected.sha256 === "string" && DIGEST.test(expected.sha256)
          && (method !== "HEAD" || expected.sha256 === sha(Buffer.alloc(0)))
          && (expected.status !== 422 || method === "HEAD"
            || expected.bytes === CONTENT_DENIAL.length && expected.sha256 === sha(CONTENT_DENIAL)));
        stage = "native-http-request";
        failure = { category: "activeAllAggregatePairs", check: checkNumber + 1, method, expectedStatus: expected.status };
        const response = await runtime.dispatchFetch(ORIGIN + "/agg/" + probe.code + "/base64", { method, redirect: "manual" });
        stage = "native-http-content-type";
        failure = { ...failure, contentTypeMatches: response.headers.get("content-type") === "text/plain; charset=utf-8" };
        requireSafe(failure.contentTypeMatches);
        await checkExpected(response, method, expected.status, expected.bytes, expected.sha256, "activeAllAggregatePairs");
      }
      counts.activeAllAggregatePairs += 1;
      if (probe.get.status === 200) counts.activeAllAggregateSuccessPairs += 1;
      else counts.activeAllAggregateContentDenialPairs += 1;
    }
    for (const table of ["normal_short_links", "aggregate_links", "private_shares"]) {
      counts.omittedHashedCapabilities += await db.prepare(`SELECT count(*) AS count FROM ${table}`).first<number>("count") ?? 0;
    }
    counts.omittedHashedCapabilities -= counts.activeAllAggregatePairs;
    requireSafe(counts.omittedHashedCapabilities >= 0);
    requireSafe(outboundAttempts === 0);
  } finally { await runtime.dispose(); }
  stage = "safe-evidence";
  const report = { version: 1, evidenceKind: "hosted-restored-data-http-replay", revision: input.revision,
    moduleSha256: input.moduleSha256, restoredDataSha256: input.dataSha256,
    consumerBound: false, telegramConfigSupplied: false, outboundAttempts, counts, migrationCount, restoredEffectiveDisplayTimezones,
    limitations: ["Only active native all-slots proven by the protected source key and matching source HTTP baseline are probed; other hashed capabilities remain omitted.",
      "Matching known 422 content denials are counted separately and do not prove a successful export or its failure cause.",
      "Structured or invalid stored-share exports and responses above the bound are reported as omitted.",
      "Scratch runtime replays the sealed SQL proven equal to restored D1 and bytes read from restored R2; this is not a public target deployment."] };
  await writeFile(process.argv[4], JSON.stringify(report) + "\n", { mode: 0o600, flag: "wx" });
  process.stdout.write(JSON.stringify(report) + "\n");
}
try { await main(); }
catch {
  process.stderr.write(`Native restored-link validation failed [stage=${stage}]${failure === null ? "" : " " + JSON.stringify(failure)}.\n`);
  process.exitCode = 1;
}

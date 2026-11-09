/** Replay a dormant synthetic candidate through the exact hosted Worker bundle. */

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { Log, LogLevel, Miniflare } from "miniflare";

const BOT = "73111";
const FIRST = "73112";
const SECOND = "73113";
const OWNERS = [FIRST, SECOND] as const;
const GROUP = "-10073114";
const ORIGIN = "https://legacy-temp-candidate.fixture.invalid";
const AGGREGATE_ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const POLICY = { botId: BOT, memberId: FIRST, adminId: SECOND, groupId: GROUP, botUsername: "fixture_temp_candidate_bot",
  webhookSecret: "synthetic-temp-candidate-webhook", botToken: BOT + ":synthetic-token" };
const DIGEST = /^[a-f0-9]{64}$/u;
const REVISION = /^[a-f0-9]{40}$/u;
const MIGRATION_NAME = "0039_legacy_temp_baseline.sql";
const MIGRATION_SHA = "4a5253618caf42baf997301d4e27c1d11f15166dadf48740d1c7d60da3af82d6";
const TEXT = "text/plain; charset=utf-8";
const MAX_SQL = 256 * 1024;
const MAX_BODY = 512 * 1024;
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const digest = (data: string | Uint8Array) => createHash("sha256").update(data).digest("hex");

type Wire = { bytes: number; sha256: string };
type Batch = { ownerId: string; firstId: number; lastId: number; nodeCount: number; payloadBytes: number;
  payloadSha256: string; namesSha256: string };
type Reply = { chat: string; replyTo: number; text: string; file?: Uint8Array };
let stage = "sandbox";

function requireOracle(condition: unknown): asserts condition {
  if (!condition) throw new Error("Dormant temporary-node oracle check failed.");
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function integer(value: unknown, min: number, max = Number.MAX_SAFE_INTEGER): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= min && value <= max;
}

function hash(value: unknown): value is string {
  return typeof value === "string" && value.length === 64 && DIGEST.test(value);
}

async function pinnedDirectory(value: unknown, uid: number): Promise<string> {
  requireOracle(typeof value === "string" && isAbsolute(value) && resolve(value) === value && await realpath(value) === value);
  const info = await lstat(value);
  requireOracle(info.isDirectory() && info.uid === uid && (info.mode & 0o077) === 0);
  return value;
}

async function pinnedFile(directory: string, name: string, sha256: unknown, maximum: number, uid: number) {
  const path = join(directory, name);
  requireOracle(hash(sha256) && await realpath(path) === path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat();
    requireOracle(info.isFile() && info.uid === uid && info.nlink === 1 && (info.mode & 0o077) === 0 && integer(info.size, 1, maximum));
    const bytes = Buffer.alloc(info.size + 1);
    let read = 0;
    while (read < bytes.length) {
      const { bytesRead } = await file.read(bytes, read, bytes.length - read, read);
      if (bytesRead === 0) break;
      read += bytesRead;
    }
    const body = bytes.subarray(0, read);
    requireOracle(read === info.size && digest(body) === sha256);
    return body;
  } finally {
    await file.close();
  }
}

async function load(uid: number) {
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of process.stdin) {
    requireOracle(Buffer.isBuffer(chunk) && (length += chunk.length) <= 1024 * 1024);
    chunks.push(chunk);
  }
  const input = JSON.parse(decoder.decode(Buffer.concat(chunks, length)));
  requireOracle(record(input) && typeof input.revision === "string" && input.revision.length === 40 && REVISION.test(input.revision)
    && hash(input.inventorySha256) && hash(input.sqlSha256) && Array.isArray(input.batches) && input.batches.length === 3
    && Array.isArray(input.legacyBase64) && input.legacyBase64.length === 2
    && Array.isArray(input.sqlStatements) && integer(input.sqlStatements.length, 1, 512));
  const batches: Batch[] = input.batches.map((batch, index) => {
    requireOracle(record(batch) && batch.ownerId === (index < 2 ? FIRST : SECOND)
      && integer(batch.firstId, 1) && integer(batch.lastId, batch.firstId)
      && batch.nodeCount === [500, 1, 2][index] && integer(batch.payloadBytes, 1, MAX_SQL)
      && hash(batch.payloadSha256) && hash(batch.namesSha256));
    return batch as Batch;
  });
  const legacyBase64: Wire[] = input.legacyBase64.map((wire) => {
    requireOracle(record(wire) && integer(wire.bytes, 1, MAX_BODY) && hash(wire.sha256));
    return { bytes: wire.bytes, sha256: wire.sha256 };
  });
  let sqlBytes = 0;
  const statements: string[] = input.sqlStatements.map((sql) => {
    requireOracle(typeof sql === "string" && sql.endsWith(";\n") && !sql.includes("\0")
      && (/^(?:CREATE (?:TABLE|(?:UNIQUE )?INDEX)|INSERT INTO) /u.test(sql)
        || sql === "DELETE FROM sqlite_sequence WHERE name='subscriptions';\n"));
    const size = Buffer.byteLength(sql);
    requireOracle(integer(size, 1, 100_000) && (sqlBytes += size) <= MAX_SQL);
    return sql;
  });

  stage = "artifact";
  const workerDir = await pinnedDirectory(input.workerDir, uid);
  const worker = JSON.parse(decoder.decode(await pinnedFile(workerDir, "isolation.json", input.workerManifestSha256, MAX_SQL, uid)));
  requireOracle(worker?.version === 2 && worker.revision === input.revision
    && typeof worker.compatibilityDate === "string" && /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/u.test(worker.compatibilityDate)
    && worker.migrations?.[38]?.name === MIGRATION_NAME && worker.migrations[38].sha256 === MIGRATION_SHA);
  const script = decoder.decode(await pinnedFile(workerDir, "index.js", worker.bundleSha256, 1024 * 1024, uid));
  const candidateDir = await pinnedDirectory(input.candidateDir, uid);
  const candidate = JSON.parse(decoder.decode(await pinnedFile(candidateDir, "manifest.json", input.candidateManifestSha256, MAX_SQL, uid)));
  const sql = await pinnedFile(candidateDir, "restore.sql", input.sqlSha256, MAX_SQL, uid);
  requireOracle(candidate?.profile === "synthetic-legacy-temp-nodes" && candidate.scope === "fresh-unbound-d1"
    && candidate.legacyTempBaseline?.state === "dormant" && candidate.objectCount === 0
    && Array.isArray(candidate.objects) && candidate.objects.length === 0
    && candidate.source?.inventoryManifestSha256 === input.inventorySha256
    && candidate.workerArtifact?.revision === input.revision && candidate.workerArtifact.bundleSha256 === worker.bundleSha256
    && candidate.workerArtifact.runId === worker.runId && candidate.workerArtifact.runAttempt === worker.runAttempt
    && candidate.sql?.path === "restore.sql" && candidate.sql.sha256 === input.sqlSha256 && candidate.sql.bytes === sql.length
    && sql.equals(Buffer.from(statements.join(""))));
  return { revision: input.revision, compatibilityDate: worker.compatibilityDate, script, statements,
    inventorySha256: input.inventorySha256, batches, legacyBase64 };
}

async function replay(db: D1Database, fixture: Awaited<ReturnType<typeof load>>) {
  for (let start = 0; start < fixture.statements.length; start += 32) {
    const statements = fixture.statements.slice(start, start + 32);
    const results = await db.batch(statements.map((sql) => db.prepare(sql)));
    requireOracle(results.length === statements.length && results.every(({ success }) => success));
  }
  const state = await db.prepare(`SELECT
    (SELECT count(*) FROM legacy_temp_installations) AS installs,
    (SELECT count(*) FROM legacy_temp_installations WHERE bot_id=? AND inventory_sha256=? AND cutover_epoch IS NULL) AS dormant,
    (SELECT count(*) FROM telegram_temp_batch) AS modern,
    (SELECT count(*) FROM telegram_inbox) AS inbox,
    (SELECT count(*) FROM telegram_outbox) AS outbox,
    (SELECT count(*) FROM aggregate_links) AS links,
    (SELECT count(*) FROM subscriptions) AS subscriptions,
    (SELECT count(*) FROM subscription_trash) AS trash,
    (SELECT count(*) FROM subs_bot_schema_migrations WHERE position=39 AND name=? AND sha256=? AND mode='applied') AS migration`)
    .bind(BOT, fixture.inventorySha256, MIGRATION_NAME, MIGRATION_SHA).first();
  requireOracle(state?.installs === 1 && state.dormant === 1 && state.modern === 0 && state.inbox === 0 && state.outbox === 0
    && state.links === 0 && state.subscriptions === 0 && state.trash === 0 && state.migration === 1);
  const fk = await db.prepare("PRAGMA foreign_key_check").all();
  requireOracle(fk.success && fk.results.length === 0);
  const rows = await db.prepare(`SELECT bot_id AS bot,actor_id AS owner,first_legacy_id AS first,last_legacy_id AS last,
    node_count AS count,payload_bytes AS bytes,payload_sha256 AS sha256,nodes_json AS json
    FROM legacy_temp_batches ORDER BY actor_id,first_legacy_id LIMIT 4`).all();
  requireOracle(rows.success && rows.results.length === fixture.batches.length);
  const shares = new Map<string, string[]>(OWNERS.map((owner) => [owner, []]));
  for (const [index, row] of rows.results.entries()) {
    const expected = fixture.batches[index];
    requireOracle(row.bot === BOT && row.owner === expected.ownerId && row.first === expected.firstId && row.last === expected.lastId
      && row.count === expected.nodeCount && row.bytes === expected.payloadBytes && row.sha256 === expected.payloadSha256
      && typeof row.json === "string" && Buffer.byteLength(row.json) === row.bytes && digest(row.json) === row.sha256);
    const nodes: unknown = JSON.parse(row.json);
    requireOracle(Array.isArray(nodes) && nodes.length === row.count);
    const names = nodes.map((node) => {
      requireOracle(record(node) && Object.keys(node).length === 3 && node.type === "temp" && typeof node.name === "string"
        && typeof node.share === "string" && node.share.length > 0);
      shares.get(expected.ownerId)!.push(node.share);
      return node.name;
    });
    requireOracle(digest(JSON.stringify(names)) === expected.namesSha256);
  }
  const first = shares.get(FIRST)!;
  requireOracle(first.length === 501 && first[499] === first[500] && shares.get(SECOND)?.length === 2);
  return shares;
}

async function captureReply(request: Request, replies: Reply[]) {
  const api = `https://api.telegram.org/bot${POLICY.botToken}`;
  requireOracle(request.method === "POST" && (request.url === api + "/sendMessage" || request.url === api + "/sendDocument"));
  let reply: Reply;
  if (request.url === api + "/sendMessage") {
    const body = await request.json() as Record<string, unknown>;
    requireOracle(typeof body.chat_id === "string" && typeof body.text === "string" && body.parse_mode === undefined
      && body.message_thread_id === undefined && record(body.link_preview_options) && body.link_preview_options.is_disabled === true
      && record(body.reply_parameters) && integer(body.reply_parameters.message_id, 1));
    reply = { chat: body.chat_id, text: body.text, replyTo: body.reply_parameters.message_id };
  } else {
    const form = await request.formData();
    const file = form.get("document"), chat = form.get("chat_id"), caption = form.get("caption");
    const target = JSON.parse(String(form.get("reply_parameters")));
    requireOracle(file !== null && typeof file !== "string" && file.name === "temporary-nodes.txt" && integer(file.size, 1, MAX_BODY)
      && /^text\/plain(?:;\s*charset=utf-8)?$/iu.test(file.type) && typeof chat === "string" && typeof caption === "string"
      && form.get("parse_mode") === null && form.get("message_thread_id") === null && integer(target?.message_id, 1));
    reply = { chat, text: caption, replyTo: target.message_id, file: new Uint8Array(await file.arrayBuffer()) };
  }
  requireOracle(OWNERS.some((owner) => owner === reply.chat) && replies.length < 12);
  replies.push(reply);
  return Response.json({ ok: true, result: { message_id: 100 + replies.length, chat: { id: Number(reply.chat) } } });
}

async function confirmWire(runtime: Miniflare, code: string, expected: Wire) {
  for (const method of ["GET", "HEAD"] as const) {
    const options = { method, redirect: "manual" as const, headers: { "Accept-Encoding": "identity" } };
    const response = await runtime.dispatchFetch(ORIGIN + `/agg/${code}/base64`, options);
    const length = response.headers.get("Content-Length");
    requireOracle(response.status === 200 && response.headers.get("Content-Type") === TEXT
      && response.headers.get("Cache-Control") === "private, no-store" && response.headers.get("Referrer-Policy") === "no-referrer"
      && response.headers.get("X-Content-Type-Options") === "nosniff"
      && (response.headers.get("Content-Encoding") ?? "identity") === "identity"
      && (length === String(expected.bytes) || (method === "HEAD" && length === null)));
    const body = new Uint8Array(await response.arrayBuffer());
    requireOracle(method === "GET" ? body.length === expected.bytes && digest(body) === expected.sha256 : body.length === 0);
    const short = await runtime.dispatchFetch(ORIGIN + `/s/${code}`, options);
    requireOracle(short.status === 302 && short.headers.get("Location") === `/agg/${code}/clash`
      && short.headers.get("Cache-Control") === "private, no-store" && (await short.arrayBuffer()).byteLength === 0);
  }
}

async function exercise(runtime: Miniflare, fixture: Awaited<ReturnType<typeof load>>, replies: Reply[]) {
  const db = await runtime.getD1Database("DB");
  stage = "replay";
  const raw = await replay(db, fixture);
  const health = await runtime.dispatchFetch(ORIGIN + "/health");
  requireOracle(health.status === 200 && (await health.json() as { revision: string }).revision === fixture.revision);
  const cutover = await db.prepare("SELECT unixepoch()-3 AS epoch").first<number>("epoch");
  requireOracle(integer(cutover, 1));
  const summary = (count: number) => `临时列表共有 ${count} 条节点。发送 /temp clear 清空。`;

  const post = async (id: number, owner: string, text: string, date: number, chat = owner) => {
    const length = text.indexOf(" ");
    const update = { update_id: id, message: { message_id: id, date, text, from: { id: Number(owner), is_bot: false },
      chat: { id: Number(chat), type: chat === GROUP ? "supergroup" : "private" },
      entities: [{ type: "bot_command", offset: 0, length: length < 0 ? text.length : length }] } };
    return runtime.dispatchFetch(ORIGIN + "/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": POLICY.webhookSecret },
      body: JSON.stringify(update) });
  };
  const receipt = (id: number) => db.prepare(`SELECT inbox.actor_id AS actor,inbox.chat_id AS chat,outbox.state,outbox.sent_message_id AS sent
    FROM telegram_inbox AS inbox LEFT JOIN telegram_outbox AS outbox USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(BOT, id).first();
  const send = async (id: number, owner: string, text: string, date: number) => {
    requireOracle((await post(id, owner, text, date)).status === 200);
    for (let attempt = 0; attempt < 50; attempt++) {
      const state = await receipt(id);
      if (state?.state === "sent") {
        const matches = replies.filter((reply) => reply.replyTo === id);
        requireOracle(matches.length === 1 && matches[0].chat === owner && state.actor === owner && state.chat === owner
          && state.sent === 101 + replies.indexOf(matches[0]));
        return matches[0];
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    throw new Error("Synthetic temporary-node reply did not settle.");
  };

  stage = "dormant";
  for (const [index, owner] of OWNERS.entries()) {
    const reply = await send(index + 1, owner, "/temp", cutover - 1);
    requireOracle(reply.file === undefined && reply.text === summary(0));
  }
  requireOracle((await db.prepare("SELECT count(*) AS total FROM legacy_temp_batches").first("total")) === 3);
  stage = "cutoff";
  // This is a fixture-only transition inside this disposable D1. The sealed SQL stays dormant.
  const activated = await db.prepare(`UPDATE legacy_temp_installations SET cutover_epoch=?
    WHERE bot_id=? AND inventory_sha256=? AND cutover_epoch IS NULL`).bind(cutover, BOT, fixture.inventorySha256).run();
  requireOracle(activated.success && activated.meta.changes === 1);
  requireOracle((await post(3, FIRST, "/temp", cutover)).status === 200 && await receipt(3) === null);
  requireOracle((await post(4, FIRST, "/temp clear", cutover)).status === 200 && await receipt(4) === null);
  requireOracle((await post(5, FIRST, "/temp", cutover + 1, GROUP)).status === 204 && await receipt(5) === null);

  stage = "private";
  const first = await send(6, FIRST, "/temp", cutover + 1);
  const firstBytes = Buffer.from(raw.get(FIRST)!.join("\n"));
  requireOracle(first.text === summary(501) && first.file && Buffer.from(first.file).equals(firstBytes));
  const second = await send(7, SECOND, "/temp", cutover + 1);
  requireOracle(second.file === undefined && second.text === summary(2) + "\n\n" + raw.get(SECOND)!.join("\n"));

  stage = "aggregate";
  const codes = [];
  for (const [index, owner] of OWNERS.entries()) {
    const reply = await send(index + 8, owner, "/export", cutover + 1);
    const url = new URL(reply.text.split("\n")[1]);
    const code = /^\/agg\/([A-Za-z0-9_-]{22})\/clash$/u.exec(url.pathname)?.[1];
    requireOracle(reply.file === undefined && url.origin === AGGREGATE_ORIGIN && !url.search && !url.hash && code);
    const link = await db.prepare(`SELECT count(*) AS matches FROM aggregate_links
      WHERE code_sha256=? AND owner_id=? AND bot_id=? AND kind='all' AND revoked_at IS NULL`)
      .bind(digest(code), owner, BOT).first("matches");
    requireOracle(link === 1);
    await confirmWire(runtime, code, fixture.legacyBase64[index]);
    codes.push(code);
  }

  stage = "clear";
  const clear = await send(10, FIRST, "/temp clear", cutover + 1);
  requireOracle(clear.file === undefined && clear.text === "已移除 501 条临时节点，当前共有 0 条。");
  requireOracle((await post(10, FIRST, "/temp clear", cutover + 1)).status === 200);
  const cleared = await send(11, FIRST, "/temp", cutover + 1);
  const unaffected = await send(12, SECOND, "/temp", cutover + 1);
  requireOracle(cleared.file === undefined && cleared.text === summary(0) && unaffected.file === undefined && unaffected.text === second.text
    && replies.filter((reply) => reply.replyTo === 10).length === 1);
  const remaining = await db.prepare(`SELECT (SELECT count(*) FROM legacy_temp_batches WHERE bot_id=? AND actor_id=?) AS cleared,
    (SELECT count(*) FROM legacy_temp_batches WHERE bot_id=? AND actor_id=?) AS remaining,
    (SELECT count(*) FROM telegram_temp_batch) AS live`).bind(BOT, FIRST, BOT, SECOND).first();
  requireOracle(remaining?.cleared === 0 && remaining.remaining === 1 && remaining.live === 0
    && (await runtime.dispatchFetch(ORIGIN + `/agg/${codes[0]}/base64`)).status === 404);
  await confirmWire(runtime, codes[1], fixture.legacyBase64[1]);
  return { sourceRows: 503, batchRows: 3, dormantOwnerChecks: 2, rawOwnerChecks: 2,
    aggregateWireChecks: 4, relativeRedirectChecks: 4, cutoffChecks: 2, clearOwnerChecks: 2, noR2: true };
}

async function main() {
  const interfaces = networkInterfaces(), uid = process.getuid?.();
  requireOracle(process.platform === "linux" && uid !== undefined && uid !== 0 && process.argv.length === 2
    && Object.keys(interfaces).join() === "lo" && interfaces.lo?.some(({ address, internal }) => internal && address === "127.0.0.1"));
  stage = "input";
  const fixture = await load(uid);
  const replies: Reply[] = [];
  const runtime = new Miniflare({ modules: true, script: fixture.script, compatibilityDate: fixture.compatibilityDate, host: "127.0.0.1",
    log: new Log(LogLevel.NONE), d1Databases: ["DB"], bindings: { BUILD_REVISION: fixture.revision,
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(POLICY), TELEGRAM_AGGREGATE_KEY: Buffer.alloc(32, 25).toString("base64url") },
    outboundService: (request: Request) => captureReply(request, replies) });
  let report;
  try {
    report = await exercise(runtime, fixture, replies);
  } finally {
    try {
      await runtime.dispose();
    } catch {
      stage = "dispose";
      throw new Error("Dormant temporary-node oracle could not dispose its runtime.");
    }
  }
  process.stdout.write(JSON.stringify(report) + "\n");
}

try {
  await main();
} catch {
  process.stderr.write(`The dormant temp Worker oracle could not be confirmed (${stage}).\n`);
  process.exitCode = 2;
}

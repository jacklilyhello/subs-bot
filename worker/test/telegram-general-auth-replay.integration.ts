import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";
import { PRODUCTION_PUBLIC_ORIGIN } from "../src/public-origin.ts";
import { publishNodeSnapshot } from "../src/storage.ts";
import { parseSubscriptionDocument } from "../src/subscription-document.ts";
import { claimTelegramDocumentJob } from "../src/telegram/document-jobs.ts";
import { persistTelegramDocumentJob, reconcileTelegramDocumentJobReplies, retireTelegramDocumentStage } from "../src/telegram/document-persistence.ts";
import { GENERAL_AUTH_LEGACY_ROLE, type GeneralAuthReplayMessage, type GeneralAuthReplayPin } from "../src/telegram/general-auth-replay.ts";
import { beginGeneralTelegramReply, claimGeneralTelegramReply, parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { acceptGeneralSharedTelegramCommand, beginGeneralSharedTelegramReply, claimGeneralSharedTelegramReply,
  recoverGeneralSharedTelegramReplies } from "../src/telegram/general-auth-shared.ts";
import { generalCurrentAuthoritySql, generalCurrentReceiptSql, generalOrdinaryReplyEligibilitySql, generalPolicyBindings,
  generalRecordedOriginSql } from "../src/telegram/general-receipt.ts";
import { acceptTelegramCommand, claimTelegramReply } from "../src/telegram/store.ts";
import { acceptTelegramView } from "../src/telegram/views.ts";
import { assertGeneralReadLane, readGeneralReadLane } from "../src/telegram/general-read-lane.ts";
import { MAX_TEMP_BATCH_NODES, MAX_TEMP_OWNER_NODES } from "../src/telegram/temp-storage.ts";

type Fixture = Omit<GeneralAuthReplayPin, "botUsername" | "webhookSecret" | "generation" | "cutoverAt"> & {
  bundleSha256: string; compatibilityDate: string; statements: string[];
};

function diagnosticError(error: unknown): string {
  for (let depth = 0; depth < 4 && error instanceof Error; depth++, error = error.cause) {
    if (/expression tree is too large|maximum (expression )?depth/iu.test(error.message)) return "expression-depth";
    if (/too many (sql )?variables|wrong number of parameter bindings/iu.test(error.message)) return "bindings";
    if (/no such (table|column)|ambiguous column/iu.test(error.message)) return "schema";
    if (/near .*syntax error/iu.test(error.message)) return "syntax";
    if (/constraint failed/iu.test(error.message)) return "constraint";
  }
  return "unclassified";
}

test("closed general authorization replays a sealed candidate in a separate emitted Worker", { timeout: 60_000 }, async (t) => {
  assert.equal(process.platform, "linux");
  assert.notEqual(process.getuid?.(), 0);
  assert.deepEqual(Object.keys(networkInterfaces()), ["lo"]);
  // Direct admission calls let the test revoke a leased reply before the emitted Worker drains it.
  // Keep the Worker comparison semantics when those calls run in the Node fixture process.
  const oldComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
  Object.defineProperty(crypto.subtle, "timingSafeEqual", {
    configurable: true,
    value: (received: ArrayBuffer, expected: ArrayBuffer) => {
      assert.equal(received.byteLength, 32);
      assert.equal(expected.byteLength, 32);
      return timingSafeEqual(new Uint8Array(received), new Uint8Array(expected));
    },
  });
  t.after(() => {
    if (oldComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", oldComparison);
    else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
  });
  const { SUBS_BOT_LEGACY_PYTHON, WORKER_TEST_BUNDLE_DIR, WORKER_TEST_REVISION } = process.env;
  assert.ok(SUBS_BOT_LEGACY_PYTHON && WORKER_TEST_BUNDLE_DIR && WORKER_TEST_REVISION);
  const generated = spawnSync(SUBS_BOT_LEGACY_PYTHON, ["-B", fileURLToPath(new URL("./telegram-general-auth-replay-fixture.py", import.meta.url))], {
    env: { PATH: "/usr/bin:/bin", TMPDIR: process.env.TMPDIR, WORKER_TEST_BUNDLE_DIR, WORKER_TEST_REVISION },
    maxBuffer: 512 * 1024, timeout: 15_000,
  });
  if (generated.status !== 0) {
    const diagnostic = /^Synthetic general authorization fixture could not be confirmed \((sandbox|artifact|candidate)\)\.\n$/u
      .exec(generated.stderr?.toString() ?? "");
    assert.fail(`Synthetic replay fixture was not verified (${diagnostic?.[1] ?? "unconfirmed"}).`);
  }
  const { bundleSha256, compatibilityDate, statements, ...fixture } = JSON.parse(generated.stdout.toString()) as Fixture;
  assert.equal(fixture.releaseRevision, WORKER_TEST_REVISION);
  assert.equal(fixture.botId, "105");
  const servingScript = await readFile(join(WORKER_TEST_BUNDLE_DIR, "index.js"));
  assert.equal(createHash("sha256").update(servingScript).digest("hex"), bundleSha256);
  const entry = await build({ entryPoints: [fileURLToPath(new URL("./telegram-general-auth-replay-entry.ts", import.meta.url))],
    bundle: true, format: "esm", platform: "browser", target: "es2022", write: false });
  assert.equal(entry.outputFiles.length, 1);
  const now = Math.floor(Date.now() / 1000);
  const pin: GeneralAuthReplayPin = { ...fixture, botUsername: "GeneralFixtureBot", webhookSecret: "fixture-general-only",
    generation: 1, cutoverAt: now - 20 };
  const isolation = { botId: "151", botUsername: "IsolationFixtureBot", webhookSecret: "fixture-isolation-only",
    botToken: "151:fixture-isolation-token", adminId: "181", memberId: "182", groupId: "-100300" };
  const sent: GeneralAuthReplayMessage[] = [];
  const generalSent: GeneralAuthReplayMessage[] = [];
  const laneSent: GeneralAuthReplayMessage[] = [];
  const sharedSent: (GeneralAuthReplayMessage & { message_thread_id?: number })[] = [];
  const lifecycleSent: (GeneralAuthReplayMessage & { reply_markup?: {
    force_reply?: boolean; inline_keyboard?: { text: string; callback_data: string }[][];
  } })[] = [];
  const lifecycleMessagesById = new Map<number, (typeof lifecycleSent)[number]>();
  const lifecycleAcks = new Set<string>();
  const fixtureDocuments = new Map<string, string>();
  const fileRequests: string[] = [];
  let lifecycleAckCalls = 0;
  let failTransport = false;
  let failGeneralTransport = false;
  const generalToken = `${fixture.botId}:fixture-general-token`;
  const generalConfig = JSON.stringify({ botId: pin.botId, botUsername: pin.botUsername,
    webhookSecret: pin.webhookSecret, botToken: generalToken, generation: pin.generation, cutoverAt: pin.cutoverAt,
    activationSha256: pin.candidateManifestSha256 });
  const generalPin = parseGeneralTelegramPin(generalConfig, fixture.releaseRevision);
  assert.ok(generalPin && !generalPin.sharedOutbox);
  const sharedConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared" });
  const sharedPin = parseGeneralTelegramPin(sharedConfig, fixture.releaseRevision);
  assert.ok(sharedPin?.sharedOutbox && !sharedPin.privateManagement);
  const lifecycleConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management" });
  const privatePin = parseGeneralTelegramPin(lifecycleConfig, fixture.releaseRevision);
  assert.ok(privatePin?.sharedOutbox && privatePin.privateManagement && !privatePin.privateFormats && !privatePin.privateTemp);
  const formatsConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management-formats" });
  const formatsPin = parseGeneralTelegramPin(formatsConfig, fixture.releaseRevision);
  assert.ok(formatsPin?.sharedOutbox && formatsPin.privateManagement && formatsPin.privateFormats && !formatsPin.privateTemp);
  const tempConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-temp" });
  const tempPin = parseGeneralTelegramPin(tempConfig, fixture.releaseRevision);
  assert.ok(tempPin?.sharedOutbox && tempPin.privateManagement && tempPin.privateTemp && !tempPin.privateFormats && !tempPin.privateDocument);
  const cumulativeConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management-formats-temp" });
  const cumulativePin = parseGeneralTelegramPin(cumulativeConfig, fixture.releaseRevision);
  assert.ok(cumulativePin?.sharedOutbox && cumulativePin.privateManagement && cumulativePin.privateFormats
    && cumulativePin.privateTemp && !cumulativePin.privateDocument);
  const documentConfig = JSON.stringify({ ...JSON.parse(generalConfig), outbox: "shared-private-management-formats-temp-node-document" });
  const documentPin = parseGeneralTelegramPin(documentConfig, fixture.releaseRevision);
  assert.ok(documentPin?.sharedOutbox && documentPin.privateManagement && documentPin.privateFormats
    && documentPin.privateTemp && documentPin.privateDocument);
  for (const outbox of ["legacy", "shared-lifecycle", "shared-path", ["shared-private-management"]]) {
    assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...JSON.parse(generalConfig), outbox }),
      fixture.releaseRevision), null);
  }
  const d1Databases = { DB: "sealed-general-auth-replay" };
  const privateTransport = async (request: Request) => {
    const api = `https://api.telegram.org/bot${generalToken}/`;
    const files = `https://api.telegram.org/file/bot${generalToken}/documents/`;
    if (request.url === api + "getFile") {
      assert.equal(request.method, "POST");
      const { file_id: fileId } = await request.json() as { file_id: string };
      const fixture = fixtureDocuments.get(fileId);
      assert.ok(fixture);
      fileRequests.push(fileId);
      return Response.json({ ok: true, result: { file_path: `documents/${fileId}`, file_size: Buffer.byteLength(fixture) } });
    }
    if (request.url.startsWith(files)) {
      assert.equal(request.method, "GET");
      const fileId = request.url.slice(files.length);
      const fixture = fixtureDocuments.get(fileId);
      assert.ok(fixture);
      fileRequests.push(fileId);
      return new Response(fixture);
    }
    assert.equal(request.method, "POST");
    if (request.url === api + "answerCallbackQuery") {
      lifecycleAckCalls++;
      const ack = await request.json() as { callback_query_id: string };
      assert.ok(/^fixture-7[0-9]{3}$/u.test(ack.callback_query_id) && !lifecycleAcks.has(ack.callback_query_id));
      lifecycleAcks.add(ack.callback_query_id);
      return Response.json({ ok: true, result: true });
    }
    assert.equal(request.url, api + "sendMessage");
    const message = await request.json() as (typeof lifecycleSent)[number];
    lifecycleSent.push(message);
    const messageId = 9400 + lifecycleSent.length;
    lifecycleMessagesById.set(messageId, message);
    return Response.json({ ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: messageId } });
  };
  const runtime = new Miniflare({ log: new Log(LogLevel.NONE), workers: [
    { name: "serving", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(isolation),
        TELEGRAM_GENERAL_CONFIG: generalConfig, REPLAY_PIN: pin },
      outboundService: () => { throw new Error("Unexpected serving transport."); } },
    { name: "rehearsal", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(isolation) },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${isolation.botToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const message = await request.json() as GeneralAuthReplayMessage;
        laneSent.push(message);
        return Response.json({ ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: 9500 + laneSent.length } });
      } },
    { name: "general", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: generalConfig },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${generalToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const message = await request.json() as GeneralAuthReplayMessage;
        generalSent.push(message);
        return failGeneralTransport ? new Response(null, { status: 503 }) : Response.json({
          ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: generalSent.length },
        });
      } },
    { name: "shared", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: sharedConfig },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${generalToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const message = await request.json() as (typeof sharedSent)[number];
        sharedSent.push(message);
        return Response.json({ ok: true, result: { chat: { id: Number(message.chat_id) }, message_id: 9300 + sharedSent.length,
          message_thread_id: message.reply_parameters.message_id === 7204 ? 45 : message.message_thread_id } });
      } },
    { name: "lifecycle", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: lifecycleConfig },
      outboundService: privateTransport },
    { name: "formats", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_GENERAL_CONFIG: documentConfig, PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN },
      outboundService: privateTransport },
    { name: "replay", modules: true, script: entry.outputFiles[0].text, compatibilityDate, d1Databases, bindings: { REPLAY_PIN: pin },
      outboundService: async (request: Request) => {
        assert.equal(request.url, "https://transport.fixture.invalid/sendMessage");
        assert.equal(request.method, "POST");
        sent.push(await request.json() as GeneralAuthReplayMessage);
        return new Response(null, { status: failTransport ? 503 : 200 });
      } },
  ] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB", "replay");
  assert.ok(statements.length > 0 && statements.length <= 256);
  for (let index = 0; index < statements.length; index += 64) {
    const slice = statements.slice(index, index + 64);
    const results = await db.batch(slice.map((sql) => db.prepare(sql)));
    assert.equal(results.length, slice.length);
    assert.ok(results.every(({ success }) => success));
  }
  assert.deepEqual((await db.prepare("PRAGMA foreign_key_check").all()).results, []);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM general_auth_principals").first("n"), 5);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM general_auth_groups").first("n"), 2);

  // Deliberately fixture-local. The candidate and serving migrations have no such DDL or activation.
  await db.batch([
    db.prepare(`CREATE TABLE general_auth_replay_fence (
      bot_id TEXT PRIMARY KEY REFERENCES general_auth_installation,worker_manifest_sha256 TEXT NOT NULL,
      candidate_manifest_sha256 TEXT NOT NULL,release_revision TEXT NOT NULL,generation INTEGER NOT NULL,
      cutover_at INTEGER NOT NULL) STRICT`),
    db.prepare(`CREATE TABLE general_auth_replay_receipts (
      receipt_id INTEGER PRIMARY KEY,bot_id TEXT NOT NULL REFERENCES general_auth_replay_fence,
      update_id INTEGER NOT NULL,generation INTEGER NOT NULL,actor_id TEXT NOT NULL,chat_id TEXT NOT NULL CHECK (chat_id=actor_id),
      message_id INTEGER NOT NULL,message_date INTEGER NOT NULL,role TEXT NOT NULL CHECK (role IN ('admin','member')),
      command TEXT NOT NULL CHECK (command IN ('help','list')),received_at INTEGER NOT NULL,
      state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','sending','sent','uncertain')),
      UNIQUE(bot_id,update_id)) STRICT`),
    ...["101", "102", "103", "104", "106", "107"].map((actor) => db.prepare(`
      INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at) VALUES (?,?,?,?,?,?)
    `).bind(actor, `Own ${actor} https://display.fixture.invalid/hidden`, "https://source.fixture.invalid/hidden",
      `fixture-token-${actor}-only`, now, now)),
  ]);

  const replay = await runtime.getWorker("replay");
  const serving = await runtime.getWorker("serving");
  const general = await runtime.getWorker("general");
  let sequence = 1000;
  type PostOptions = { updateId?: number; chatId?: number; chatType?: string; date?: number; secret?: string;
    message?: Record<string, unknown>; worker?: typeof replay };
  const post = (actor: number, text: string, options: PostOptions = {}) => (options.worker ?? replay).fetch(
    "https://app.fixture.invalid/telegram/webhook", { method: "POST", headers: { "Content-Type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": options.secret ?? pin.webhookSecret },
    body: JSON.stringify({ update_id: options.updateId ?? ++sequence, message: {
      from: { id: actor, is_bot: false }, chat: { id: options.chatId ?? actor, type: options.chatType ?? "private" },
      date: options.date ?? now - 5, message_id: options.updateId ?? sequence, text,
      entities: [{ type: "bot_command", offset: 0, length: text.split(" ")[0].length }], ...options.message,
    } }),
  });
  const drain = async () => {
    const response = await replay.fetch("https://app.fixture.invalid/test/drain", { method: "POST" });
    assert.equal(response.status, 200);
    return (await response.json() as { outcome: string }).outcome;
  };
  const generalPost = (actor: number, text: string, options: PostOptions = {}) => post(actor, text, { ...options, worker: general });
  const generalState = (updateId: number) =>
    db.prepare("SELECT state FROM telegram_general_replies WHERE update_id=?").bind(updateId).first<string>("state");
  const waitForGeneral = async (updateId: number, expected: string) => {
    const end = Date.now() + 4000;
    while (await generalState(updateId) !== expected && Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.equal(await generalState(updateId), expected);
  };
  assert.equal((await generalPost(101, "/help")).status, 204);
  await db.batch([
    db.prepare(`INSERT INTO telegram_general_policy (bot_id,generation,release_revision,activation_sha256,cutover_at)
      VALUES (?,?,?,?,?)`).bind(generalPin.botId, generalPin.generation, generalPin.releaseRevision,
      generalPin.activationSha256, generalPin.cutoverAt),
    db.prepare(`INSERT INTO telegram_general_actors (bot_id,generation,actor_id,revision,effective_at,role)
      SELECT principal.bot_id,?,principal.user_id,1,?,COALESCE((${GENERAL_AUTH_LEGACY_ROLE}),'denied')
      FROM general_auth_principals AS principal WHERE principal.bot_id=?`)
      .bind(generalPin.generation, generalPin.cutoverAt, generalPin.botId),
  ]);
  assert.equal((await generalPost(101, "/help")).status, 204, "seeded roles are closed before activation");
  await db.prepare("UPDATE telegram_general_policy SET active=1,cutover_at=cutover_at+1 WHERE bot_id=?").bind(pin.botId).run();
  assert.equal((await generalPost(101, "/help")).status, 204, "a different cutover cannot activate the binding");
  await db.prepare("UPDATE telegram_general_policy SET cutover_at=? WHERE bot_id=?").bind(pin.cutoverAt, pin.botId).run();
  assert.equal((await post(101, "/help", { worker: serving, secret: isolation.webhookSecret })).status, 204,
    "existing isolation policy wins even when the general policy is active");
  assert.equal((await generalPost(102, "/list")).status, 204);
  assert.equal((await generalPost(107, "/list")).status, 204);
  assert.equal((await generalPost(104, "/list", { chatType: "supergroup", chatId: -100100 })).status, 204);
  assert.equal((await generalPost(104, "/list", { date: pin.cutoverAt })).status, 204);
  assert.equal((await generalPost(104, "/auth")).status, 204);
  assert.equal(generalSent.length, 0);
  assert.equal((await generalPost(104, "/list", { updateId: 7001 })).status, 200);
  await waitForGeneral(7001, "sent");
  assert.deepEqual(generalSent[0], { chat_id: "104", text: "你的订阅\n1. Own 104 [链接已省略]",
    reply_parameters: { message_id: 7001 }, link_preview_options: { is_disabled: true } });
  assert.equal((await generalPost(104, "/list", { updateId: 7001 })).status, 204);

  failGeneralTransport = true;
  assert.equal((await generalPost(103, "/help", { updateId: 7002 })).status, 200);
  await waitForGeneral(7002, "uncertain");
  assert.equal((await generalPost(103, "/help", { updateId: 7002 })).status, 204);

  await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    VALUES (?,?,'104',1,7003,7003,?,'list')`).bind(pin.botId, pin.generation, now - 5).run();
  const lease = await claimGeneralTelegramReply(db, generalPin);
  assert.ok(lease);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',2,?,'denied')").bind(pin.botId, pin.generation, now - 4),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',3,?,'member')").bind(pin.botId, pin.generation, now - 3),
  ]);
  assert.equal(await beginGeneralTelegramReply(db, generalPin, lease), false, "same-role regrant cannot inherit an old lease");
  assert.equal((await generalPost(104, "/list", { date: now - 3 })).status, 204, "a grant's exact second stays closed");
  await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    VALUES (?,?,'104',3,7004,7004,?,'list')`).bind(pin.botId, pin.generation, now - 2).run();
  const interruptedSend = await claimGeneralTelegramReply(db, generalPin);
  assert.ok(interruptedSend);
  assert.equal(await beginGeneralTelegramReply(db, generalPin, interruptedSend), true);
  await db.prepare("UPDATE telegram_general_replies SET lease_until=unixepoch()-1 WHERE update_id=7004").run();
  assert.equal((await general.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await generalState(7003), "discarded");
  assert.equal(await generalState(7004), "uncertain", "expired sending work cannot be delivered twice");
  await db.prepare("UPDATE telegram_general_policy SET generation=generation+1 WHERE bot_id=?").bind(pin.botId).run();
  assert.equal((await generalPost(101, "/help")).status, 204, "a stale configured generation cannot admit");
  assert.equal(generalSent.length, 2);

  assert.equal((await post(101, "/help")).status, 204);
  assert.equal(await drain(), "empty");
  assert.equal((await post(101, "/help", { secret: "wrong" })).status, 401);

  await db.prepare("INSERT INTO general_auth_replay_fence VALUES (?,?,?,?,?,?)")
    .bind(pin.botId, pin.workerManifestSha256, pin.candidateManifestSha256, "0".repeat(40), pin.generation, pin.cutoverAt).run();
  assert.equal((await post(101, "/help")).status, 204);
  await db.prepare("UPDATE general_auth_replay_fence SET release_revision=?").bind(pin.releaseRevision).run();
  await db.prepare("UPDATE general_auth_installation SET target_sha256=?").bind("0".repeat(64)).run();
  assert.equal((await post(101, "/help")).status, 204);
  await db.prepare("UPDATE general_auth_installation SET target_sha256=?").bind(pin.targetSha256).run();
  assert.equal((await post(101, "/help", { worker: serving, secret: isolation.webhookSecret })).status, 204);
  assert.equal((await serving.fetch("https://app.fixture.invalid/test/drain", { method: "POST" })).status, 404);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox").first("n"), 0);

  const denied: Array<[number, string, PostOptions]> = [
    [102, "/list", {}], [107, "/help", {}], [105, "/help", {}], [104, "/list", { chatId: 103 }],
    [104, "/list", { chatId: -100100, chatType: "supergroup" }],
    [104, "/list", { chatId: -100999, chatType: "group" }], [104, "/help", { message: { message_thread_id: 9 } }],
    [104, "/help", { message: { sender_chat: { id: -100100 } } }], [104, "/help", { date: pin.cutoverAt }],
    [104, "/help@DifferentBot", {}], [104, "/list 103", {}], [104, "/auth", {}], [104, "/start", {}],
  ];
  for (const [actor, command, options] of denied) assert.equal((await post(actor, command, options)).status, 204);
  assert.equal(await drain(), "empty");

  assert.equal((await post(101, "/help", { updateId: 100 })).status, 200);
  assert.equal((await post(101, "/help", { updateId: 100 })).status, 204);
  assert.deepEqual((await Promise.all([drain(), drain()])).sort(), ["empty", "sent"]);
  assert.deepEqual(sent, [{ chat_id: "101", text: "可用命令\n/help 帮助\n/list 查看你的订阅",
    reply_parameters: { message_id: 100 }, link_preview_options: { is_disabled: true } }]);
  for (const actor of [106, 103, 104]) {
    assert.equal((await post(actor, "/list@GeneralFixtureBot")).status, 200);
    assert.equal(await drain(), "sent");
    assert.deepEqual(sent.at(-1), { chat_id: String(actor), text: `你的订阅\n1. Own ${actor} [链接已省略]`, reply_parameters: { message_id: sequence },
      link_preview_options: { is_disabled: true } });
  }

  failTransport = true;
  assert.equal((await post(103, "/help", { updateId: 101 })).status, 200);
  assert.equal(await drain(), "uncertain");
  assert.equal((await post(103, "/help", { updateId: 101 })).status, 204);
  assert.equal(await drain(), "empty");
  assert.equal(await db.prepare("SELECT state FROM general_auth_replay_receipts WHERE update_id=101").first("state"), "uncertain");

  assert.equal((await post(104, "/list")).status, 200);
  await db.prepare("UPDATE general_auth_principals SET is_admin=1 WHERE bot_id=? AND user_id='104'").bind(pin.botId).run();
  assert.equal(await drain(), "empty");
  assert.equal((await post(106, "/list")).status, 200);
  await db.prepare("UPDATE general_auth_replay_fence SET generation=generation+1").run();
  assert.equal(await drain(), "empty");
  assert.equal((await post(106, "/list")).status, 204);
  assert.equal(sent.length, 5);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_outbox").first("n"), 0);

  const shared = await runtime.getWorker("shared");
  const sharedPost = (actor: number, text: string, options: PostOptions = {}) =>
    post(actor, text, { date: now - 2, ...options, worker: shared });
  await db.prepare("UPDATE telegram_general_policy SET generation=? WHERE bot_id=?").bind(pin.generation, pin.botId).run();
  const migration = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=46").first<string>("sha256");
  assert.ok(migration);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=46").bind("0".repeat(64)).run();
  assert.equal((await sharedPost(101, "/help")).status, 204, "wrong shared schema pin keeps admission closed");
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=46").bind(migration).run();

  await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    VALUES (?,?,'101',1,7100,7100,?,'help')`).bind(pin.botId, pin.generation, now - 2).run();
  assert.equal((await sharedPost(104, "/list")).status, 204, "an open 0044 queue keeps the new family closed");
  await db.prepare("UPDATE telegram_general_replies SET state='discarded' WHERE update_id=7100").run();
  assert.equal((await sharedPost(104, "/list", { updateId: 7001 })).status, 204, "old-family receipt remains a tombstone");
  assert.equal((await sharedPost(102, "/list")).status, 204);
  assert.equal((await sharedPost(104, "/list", { chatId: -100100, chatType: "group" })).status, 204);

  assert.deepEqual((await Promise.all([sharedPost(104, "/list", { updateId: 7101 }),
    sharedPost(104, "/list", { updateId: 7101 })])).map(({ status }) => status).sort(), [200, 204]);
  const findReply = (id: number) => db.prepare(`SELECT inbox.receipt_nonce AS marker,reply.state,reply.sent_message_id AS messageId,
    origin.generation,origin.actor_revision AS actorRevision,page.kind
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
    JOIN telegram_general_receipt AS origin USING (receipt_id) LEFT JOIN telegram_view AS page USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(pin.botId, id).first();
  const sharedEnd = Date.now() + 4000;
  while ((await findReply(7101))?.state !== "sent" && Date.now() < sharedEnd) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.deepEqual(await findReply(7101), { marker: "general-read:v1", state: "sent", messageId: 9301,
    generation: pin.generation, actorRevision: 3, kind: "list" });
  assert.deepEqual(sharedSent, [{ chat_id: "104", text: "你的订阅\n1. Own 104 [链接已省略]",
    reply_parameters: { message_id: 7101 }, link_preview_options: { is_disabled: true } }]);
  assert.equal((await generalPost(104, "/list", { updateId: 7101, date: now - 2 })).status, 204,
    "seven-key compatibility path also respects a shared receipt");

  assert.equal((await sharedPost(101, "/help", { updateId: 7104 })).status, 200);
  const helpEnd = Date.now() + 4000;
  while ((await findReply(7104))?.state !== "sent" && Date.now() < helpEnd) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.deepEqual(await findReply(7104), { marker: "general-read:v1", state: "sent", messageId: 9302,
    generation: pin.generation, actorRevision: 1, kind: null });
  assert.deepEqual(sharedSent[1], { chat_id: "101", text: "可用命令\n/help 帮助\n/list 查看你的订阅",
    reply_parameters: { message_id: 7104 }, link_preview_options: { is_disabled: true } });

  const receiptFacts = (updateId: number, proof = sharedPin) => {
    const pins = generalPolicyBindings(proof);
    return db.prepare(`SELECT (${generalRecordedOriginSql("inbox")}) AS recorded,
      (${generalCurrentAuthoritySql("inbox")}) AS currentAuthority,
      (${generalOrdinaryReplyEligibilitySql("inbox")}) AS fresh,
      (${generalCurrentReceiptSql("inbox")}) AS deliverable
      FROM telegram_inbox AS inbox WHERE inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce='general-read:v1'`)
      .bind(...pins, ...pins, ...pins, pin.botId, updateId).first();
  };
  assert.deepEqual(await receiptFacts(7101), { recorded: 1, currentAuthority: 1, fresh: 1, deliverable: 1 });
  assert.deepEqual(await receiptFacts(7101, { ...sharedPin, activationSha256: "0".repeat(64) }),
    { recorded: 0, currentAuthority: 0, fresh: 1, deliverable: 0 });

  const seedInbox = (id: number, marker: string | null) => db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
    VALUES (?,?,'104','104','private',?,?,'help',?) RETURNING receipt_id`)
    .bind(pin.botId, id, id, now - 2, marker).first<number>("receipt_id");
  const generalReceipt = await seedInbox(7102, "general-read:v1");
  const ordinaryReceipt = await seedInbox(7103, null);
  assert.ok(generalReceipt && ordinaryReceipt);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,?,3,'member',?,?,?)")
      .bind(generalReceipt, pin.generation, sharedPin.releaseRevision, sharedPin.activationSha256, sharedPin.cutoverAt),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?),(?)").bind(generalReceipt, ordinaryReceipt),
  ]);
  assert.equal((await claimTelegramReply(db, pin.botId))?.receiptId, ordinaryReceipt,
    "the isolation queue neither claims the new family nor lets it block ordinary FIFO");
  const sharedLease = await claimGeneralSharedTelegramReply(db, sharedPin);
  assert.equal(sharedLease?.receiptId, generalReceipt);
  assert.ok(sharedLease);
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch()-600 WHERE receipt_id=?").bind(generalReceipt).run();
  assert.deepEqual(await receiptFacts(7102), { recorded: 1, currentAuthority: 1, fresh: 0, deliverable: 0 });
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, sharedLease), false, "the ordinary clock still closes at 600 seconds");
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch() WHERE receipt_id=?").bind(generalReceipt).run();
  const changedPin = { ...sharedPin, activationSha256: "b".repeat(64) };
  await db.prepare("UPDATE telegram_general_policy SET activation_sha256=? WHERE bot_id=?")
    .bind(changedPin.activationSha256, pin.botId).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, changedPin, sharedLease), false, "same generation cannot inherit an old activation");
  await db.prepare("UPDATE telegram_general_policy SET activation_sha256=? WHERE bot_id=?")
    .bind(sharedPin.activationSha256, pin.botId).run();
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',4,?,'denied')")
    .bind(pin.botId, pin.generation, now - 2).run();
  assert.deepEqual(await receiptFacts(7102), { recorded: 1, currentAuthority: 0, fresh: 1, deliverable: 0 });
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, sharedLease), false);
  assert.equal((await shared.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(7102))?.state, "failed");
  assert.equal(sharedSent.length, 2);

  const groupId = "-100100";
  const groupEvent: PostOptions = { chatId: Number(groupId), chatType: "supergroup", date: now,
    message: { is_topic_message: true, message_thread_id: 44, reply_to_message: { message_id: 44 } } };
  const addressed = "/list@GeneralFixtureBot";
  const groupPost = (actor: number, text: string, options: PostOptions = {}) => sharedPost(actor, text, { ...groupEvent, ...options });
  assert.equal((await groupPost(101, addressed)).status, 204, "an imported dormant group grants no runtime access");
  const grantGroup = () => db.prepare("INSERT INTO telegram_general_groups VALUES (?,?,?,'supergroup')")
    .bind(pin.botId, pin.generation, groupId).run();
  await grantGroup();
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=47").bind("0".repeat(64)).run();
  assert.equal((await groupPost(101, addressed)).status, 204, "wrong 0047 pin leaves the group path closed");
  assert.equal((await sharedPost(101, "/help", { updateId: 7200 })).status, 200);
  const privateEnd = Date.now() + 4000;
  while ((await findReply(7200))?.state !== "sent" && Date.now() < privateEnd) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal((await findReply(7200))?.state, "sent");
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=47")
    .bind("442b9f1e52ad961aac41ee9416760863984646a96570bd22f26474d329ee626e").run();

  for (const rejected of [
    groupPost(102, addressed), groupPost(101, "/list"), groupPost(101, "/list@DifferentBot"),
    groupPost(101, addressed, { chatId: -100200 }), groupPost(101, addressed, { chatType: "group" }),
    groupPost(101, addressed, { message: { message_thread_id: 44 } }),
    groupPost(101, "/help@GeneralFixtureBot"), groupPost(101, addressed, { date: pin.cutoverAt }),
  ]) assert.equal((await rejected).status, 204);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',5,?,'member')")
    .bind(pin.botId, pin.generation, now - 1).run();
  for (const [id, actor, state] of [[7201, 101, "sent"], [7202, 104, "sent"], [7204, 101, "uncertain"]] as const) {
    assert.equal((await groupPost(actor, addressed, { updateId: id })).status, 200);
    assert.equal((await groupPost(actor, addressed, { updateId: id })).status, 204);
    const end = Date.now() + 4000;
    while ((await findReply(id))?.state !== state && Date.now() < end) await new Promise((resolve) => setTimeout(resolve, 10));
    assert.equal((await findReply(id))?.state, state);
    assert.deepEqual(sharedSent.find(({ reply_parameters }) => reply_parameters.message_id === id), {
      chat_id: groupId, text: `你的订阅\n1. Own ${actor} [链接已省略]`, message_thread_id: 44,
      reply_parameters: { message_id: id, allow_sending_without_reply: false }, link_preview_options: { is_disabled: true },
    });
  }

  const groupReceipt = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
    VALUES (?,7203,'101',?,'supergroup',7203,?,44,'list','general-group-read:v1') RETURNING receipt_id`)
    .bind(pin.botId, groupId, now).first<number>("receipt_id");
  assert.ok(groupReceipt);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,?,1,'admin',?,?,?)")
      .bind(groupReceipt, pin.generation, sharedPin.releaseRevision, sharedPin.activationSha256, sharedPin.cutoverAt),
    db.prepare("INSERT INTO telegram_view (receipt_id,kind) VALUES (?,'list')").bind(groupReceipt),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(groupReceipt),
  ]);
  const groupLease = await claimGeneralSharedTelegramReply(db, sharedPin);
  assert.equal(groupLease?.receiptId, groupReceipt);
  assert.ok(groupLease);
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, { ...groupLease, threadId: 45 }), false);
  await db.prepare("DELETE FROM telegram_general_groups WHERE bot_id=? AND generation=? AND chat_id=?")
    .bind(pin.botId, pin.generation, groupId).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, sharedPin, groupLease), false);
  assert.equal((await shared.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.deepEqual(await findReply(7203), { marker: "general-group-read:v1", state: "failed", messageId: null,
    generation: pin.generation, actorRevision: 1, kind: "list" });
  assert.equal(sharedSent.length, 6);

  const lifecycle = await runtime.getWorker("lifecycle");
  const lifecyclePost = (id: number, actor: number, text: string, message?: Record<string, unknown>) =>
    post(actor, text, { updateId: id, date: now, worker: lifecycle, message });
  const awaitLifecycle = async (id: number) => {
    const end = Date.now() + 4000;
    let row = await findReply(id);
    while (row?.state !== "sent" && Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 10));
      row = await findReply(id);
    }
    assert.equal(row?.state, "sent");
    const messageId = row?.messageId;
    assert.ok(typeof messageId === "number");
    const message = lifecycleMessagesById.get(messageId);
    assert.ok(message);
    return { message, messageId };
  };
  const button = (message: (typeof lifecycleSent)[number], label: string) => {
    const ticket = message.reply_markup?.inline_keyboard?.flat().find(({ text }) => text.includes(label))?.callback_data;
    assert.ok(ticket && /^sba1_[A-Za-z0-9_-]{22}$/u.test(ticket));
    return ticket;
  };
  const origin = (id: number, chatId: number, chatType = "private", botId = Number(pin.botId)) => ({
    message_id: id, date: now, chat: { id: chatId, type: chatType }, from: { id: botId, is_bot: true },
  });
  const callback = (id: number, actor: number, source: ReturnType<typeof origin>, ticket: string, worker = lifecycle) => worker.fetch(
    "https://app.fixture.invalid/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify({ update_id: id, callback_query: {
        id: `fixture-${id}`, from: { id: actor, is_bot: false }, message: source, data: ticket,
      } }),
    });
  const owned = () => db.prepare("SELECT id,token,name FROM subscriptions WHERE owner_id='101'").first<{ id: number; token: string; name: string }>();
  const initial = await owned();
  assert.ok(initial);
  assert.equal((await sharedPost(101, "/recycle")).status, 204, "the read-only config cannot enter lifecycle");
  assert.equal((await lifecyclePost(7301, 101, "/list")).status, 200);
  const listed = await awaitLifecycle(7301);
  const rename = button(listed.message, "重命名");
  assert.equal((await callback(7310, 104, origin(listed.messageId, 104), rename)).status, 204);
  assert.equal((await callback(7311, 101, origin(listed.messageId, -100100, "supergroup"), rename)).status, 204);
  assert.equal((await callback(7312, 101, origin(listed.messageId, 101, "private", 123), rename)).status, 204);
  assert.equal((await callback(7302, 101, origin(listed.messageId, 101), rename)).status, 200);
  assert.equal((await callback(7302, 101, origin(listed.messageId, 101), rename)).status, 204);
  const prompt = await awaitLifecycle(7302);
  assert.equal(prompt.message.reply_parameters.message_id, listed.messageId);
  assert.deepEqual(prompt.message.reply_markup, { force_reply: true });
  assert.equal((await lifecyclePost(7303, 101, "Renamed lifecycle fixture", { message_id: 20_001,
    reply_to_message: origin(prompt.messageId, 101), entities: [] })).status, 200);
  assert.equal((await awaitLifecycle(7303)).message.text, "订阅名称已更新。");
  assert.deepEqual(await owned(), { ...initial, name: "Renamed lifecycle fixture" });

  assert.equal((await lifecyclePost(7304, 101, "/list")).status, 200);
  const renamed = await awaitLifecycle(7304);
  assert.equal((await callback(7305, 101, origin(renamed.messageId, 101), button(renamed.message, "删除"))).status, 200);
  const confirm = await awaitLifecycle(7305);
  assert.equal((await callback(7306, 101, origin(confirm.messageId, 101), button(confirm.message, "确认移入回收站"))).status, 200);
  await awaitLifecycle(7306);
  assert.equal(await owned(), null);
  assert.equal(await db.prepare("SELECT token FROM subscription_trash WHERE id=? AND owner_id='101'")
    .bind(initial.id).first("token"), initial.token);

  assert.equal((await lifecyclePost(7307, 101, "/recycle")).status, 200);
  const recycle = await awaitLifecycle(7307);
  assert.equal((await callback(7308, 101, origin(recycle.messageId, 101), button(recycle.message, "恢复"))).status, 200);
  assert.equal((await awaitLifecycle(7308)).message.text, "已恢复订阅。");
  assert.deepEqual(await owned(), { ...initial, name: "Renamed lifecycle fixture" });
  assert.equal(await db.prepare("SELECT revision FROM subscription_lifecycle WHERE subscription_id=?").bind(initial.id).first("revision"), 3);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subscription_trash WHERE id=?").bind(initial.id).first("n"), 0);

  assert.equal((await lifecyclePost(7309, 104, "/list")).status, 200);
  const memberList = await awaitLifecycle(7309);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',6,?,'denied')")
    .bind(pin.botId, pin.generation, now).run();
  assert.equal((await callback(7313, 104, origin(memberList.messageId, 104), button(memberList.message, "删除"))).status, 204);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subscriptions WHERE owner_id='104'").first("n"), 1);
  assert.equal(lifecycleSent.length, 9);
  const ackDeadline = Date.now() + 1000;
  while (lifecycleAcks.size < 4 && Date.now() < ackDeadline) await new Promise((resolve) => setTimeout(resolve, 10));
  assert.deepEqual([...lifecycleAcks].sort(), ["fixture-7302", "fixture-7305", "fixture-7306", "fixture-7308"]);
  assert.equal(lifecycleAckCalls, 4);

  const detailTicket = (message: (typeof lifecycleSent)[number]) => {
    const ticket = message.reply_markup?.inline_keyboard?.flat()[0]?.callback_data;
    assert.ok(ticket && /^sbr1_[A-Za-z0-9_-]{22}$/u.test(ticket));
    return ticket;
  };
  assert.equal((await sharedPost(101, "/s Renamed")).status, 204);
  await grantGroup();
  assert.equal((await post(101, "/s@GeneralFixtureBot Renamed", { ...groupEvent, worker: lifecycle })).status, 204);
  assert.equal((await lifecyclePost(7320, 101, "/s Renamed")).status, 200);
  const searched = await awaitLifecycle(7320);
  assert.match(searched.message.text, /Renamed lifecycle fixture/u);
  const firstTicket = detailTicket(searched.message);
  const frozen = await db.prepare(`SELECT search.matches FROM telegram_subscription_read AS search
    JOIN telegram_inbox AS inbox USING (receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=7320`)
    .bind(pin.botId).first<string>("matches");
  assert.deepEqual(JSON.parse(frozen!), [[initial.id, 1, 3]]);
  assert.equal((await callback(7321, 103, origin(searched.messageId, 103), firstTicket)).status, 204);
  await db.batch([
    db.prepare("UPDATE subscriptions SET name='Renamed current fixture' WHERE id=? AND owner_id='101'").bind(initial.id),
    db.prepare("UPDATE subscription_lifecycle SET revision=4 WHERE subscription_id=? AND revision=3").bind(initial.id),
  ]);
  assert.equal((await callback(7322, 101, origin(searched.messageId, 101), firstTicket)).status, 204, "a stale detail ticket stays closed");
  assert.equal((await lifecyclePost(7323, 101, "/s source.fixture.invalid")).status, 200);
  const sourceSearch = await awaitLifecycle(7323);
  assert.equal(sourceSearch.message.text, "没有匹配订阅。");
  assert.equal(sourceSearch.message.reply_markup, undefined);

  assert.equal((await lifecyclePost(7324, 101, "/s Renamed")).status, 200);
  const freshSearch = await awaitLifecycle(7324);
  const freshTicket = detailTicket(freshSearch.message);
  assert.equal((await callback(7325, 101, origin(freshSearch.messageId, 101), freshTicket)).status, 200);
  assert.equal((await callback(7325, 101, origin(freshSearch.messageId, 101), freshTicket)).status, 204);
  const detail = await awaitLifecycle(7325);
  assert.match(detail.message.text, /配置名称：Renamed current fixture/u);
  assert.match(detail.message.text, /节点数量：0/u);
  assert.equal(detail.message.reply_markup, undefined);
  assert.doesNotMatch(detail.message.text, /https?:|\/sub\/|fixture-token|source\.fixture/u);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs").first("n"), 0);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_subscription_read_ticket WHERE kind='format'").first("n"), 0);

  assert.equal((await lifecyclePost(7326, 103, "/s Own")).status, 200);
  const previousGrant = await awaitLifecycle(7326);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'103',2,?,'denied')").bind(pin.botId, pin.generation, now),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'103',3,?,'member')").bind(pin.botId, pin.generation, now + 1),
  ]);
  assert.equal((await callback(7327, 103, { ...origin(previousGrant.messageId, 103), date: now + 2 },
    detailTicket(previousGrant.message))).status, 204, "a fresh callback date cannot carry an old grant into a new revision");

  const pathStart = lifecycleSent.length;
  const pathSent = () => lifecycleSent.slice(pathStart);
  const pathPost = (actor: number, command: string, options: PostOptions = {}) =>
    post(actor, command, { date: now + 2, ...options, worker: lifecycle });
  const awaitPath = async (updateId: number) => {
    const end = Date.now() + 4000;
    while ((await findReply(updateId))?.state !== "sent" && Date.now() < end) {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    const reply = await findReply(updateId);
    assert.ok(reply);
    assert.equal(reply.state, "sent");
    assert.equal(reply.marker, "general-path:v1");
  };
  assert.equal((await sharedPost(101, "/path same-key Disabled")).status, 204);
  assert.equal((await pathPost(102, "/path same-key Denied")).status, 204);
  assert.equal((await pathPost(101, "/path same-key Old", { date: pin.cutoverAt })).status, 204);
  assert.equal((await pathPost(101, "/path@GeneralFixtureBot same-key Group", groupEvent)).status, 204);
  const pathMigration = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=13").first<string>("sha256");
  assert.ok(pathMigration);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=13").bind("0".repeat(64)).run();
  assert.equal((await pathPost(101, "/path same-key Invalid pin")).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=13").bind(pathMigration).run();
  assert.equal(pathSent().length, 0);

  assert.equal((await pathPost(101, "/path same-key Admin only", { updateId: 7341 })).status, 200);
  await awaitPath(7341);
  assert.equal((await pathPost(101, "/path same-key Duplicate", { updateId: 7341 })).status, 204);
  assert.equal((await pathPost(103, "/path same-key Member only", { updateId: 7342 })).status, 200);
  await awaitPath(7342);
  assert.equal((await pathPost(103, "/path", { updateId: 7343 })).status, 200);
  await awaitPath(7343);
  assert.equal(pathSent().length, 3);
  assert.equal(pathSent()[2].chat_id, "103");
  assert.match(pathSent()[2].text, /^你的路径规则\n#\d+ same-key → Member only$/u);

  assert.equal((await pathPost(101, "/path clear", { updateId: 7344, date: now + 1 })).status, 200);
  await awaitPath(7344);
  assert.equal(pathSent()[3].text, "此路径命令已过期或已有更新的操作，请重发。");
  assert.deepEqual((await db.prepare("SELECT owner_id,remark FROM path_rules WHERE keyword='same-key' ORDER BY owner_id").all()).results,
    [{ owner_id: "101", remark: "Admin only" }, { owner_id: "103", remark: "Member only" }]);
  assert.equal((await pathPost(101, "/path clear", { updateId: 7345, date: now + 3 })).status, 200);
  await awaitPath(7345);
  assert.equal(pathSent()[4].chat_id, "101");
  assert.equal(pathSent()[4].text, "已清空 1 条路径规则。");
  assert.deepEqual((await db.prepare("SELECT owner_id,remark FROM path_rules WHERE keyword='same-key'").all()).results,
    [{ owner_id: "103", remark: "Member only" }]);

  const pendingPaths: number[] = [];
  for (const id of [7346, 7347, 7348, 7349]) {
    const receiptId = await db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
      VALUES (?,?,'103','103','private',?,?,'help','general-path:v1') RETURNING receipt_id`)
      .bind(pin.botId, id, id, now + 2).first<number>("receipt_id");
    assert.ok(receiptId);
    pendingPaths.push(receiptId);
    await db.batch([
      db.prepare("INSERT INTO telegram_general_receipt VALUES (?,?,3,'member',?,?,?)")
        .bind(receiptId, pin.generation, privatePin.releaseRevision, privatePin.activationSha256, privatePin.cutoverAt),
      db.prepare("INSERT INTO telegram_path_reply (receipt_id,kind) VALUES (?,'list')").bind(receiptId),
      db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(receiptId),
    ]);
  }
  assert.equal((await pathPost(103, "/list")).status, 204, "path replies consume the common admission quota");
  assert.equal((await pathPost(103, "/s Own")).status, 204);
  const pathLease = await claimGeneralSharedTelegramReply(db, privatePin);
  assert.equal(pathLease?.receiptId, pendingPaths[0]);
  assert.ok(pathLease);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'103',4,?,'denied')")
    .bind(pin.botId, pin.generation, now + 2).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, privatePin, pathLease), false);
  assert.equal((await lifecycle.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await findReply(7346))?.state, "failed");
  assert.equal(pathSent().length, 5);

  const formats = await runtime.getWorker("formats");
  const bucket = await runtime.getR2Bucket("NODES", "formats");
  const fixtureShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture";
  assert.equal(await publishNodeSnapshot(db, bucket, { id: initial.id, ownerId: "101", expectedGeneration: 0,
    expectedLifecycleRevision: 4 }, [{ type: "temp", name: "fixture", share: fixtureShare }]), true);
  const formatDetail = async (firstId: number, worker = formats) => {
    assert.equal((await post(101, "/s Renamed", { updateId: firstId, date: now, worker })).status, 200);
    const search = await awaitLifecycle(firstId);
    assert.equal((await callback(firstId + 1, 101, origin(search.messageId, 101), detailTicket(search.message), worker)).status, 200);
    return awaitLifecycle(firstId + 1);
  };
  const disabledDetail = await formatDetail(7370, lifecycle);
  assert.equal(disabledDetail.message.reply_markup, undefined);
  const enabledDetail = await formatDetail(7372);
  assert.match(enabledDetail.message.text, /节点数量：1/u);
  assert.doesNotMatch(enabledDetail.message.text, /https?:|fixture-token|source\.fixture/u);
  const choices = enabledDetail.message.reply_markup?.inline_keyboard?.flat();
  assert.deepEqual(choices?.map(({ text }) => text), ["Clash Meta", "Sing-box", "Base64", "Surge", "QX"]);
  const formatTicket = (label: string) => {
    const ticket = choices?.find(({ text }) => text === label)?.callback_data;
    assert.ok(ticket && /^sbr1_[A-Za-z0-9_-]{22}$/u.test(ticket));
    return ticket;
  };
  const base64 = formatTicket("Base64");
  assert.equal((await callback(7374, 101, origin(enabledDetail.messageId, 101), base64)).status, 204, "old private mode stays closed");
  assert.equal((await callback(7375, 101, origin(enabledDetail.messageId, -100100, "supergroup"), base64, formats)).status, 204);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',7,?,'member')")
    .bind(pin.botId, pin.generation, now + 1).run();
  assert.equal((await callback(7376, 104, { ...origin(enabledDetail.messageId, 104), date: now + 2 }, base64, formats)).status, 204);
  assert.equal((await callback(7377, 101, origin(disabledDetail.messageId, 101), base64, formats)).status, 204);
  assert.equal((await callback(7378, 101, origin(enabledDetail.messageId, 101), base64, formats)).status, 200);
  const exported = await awaitLifecycle(7378);
  assert.deepEqual(exported.message, { chat_id: "101", text: `Base64\n${PRODUCTION_PUBLIC_ORIGIN}/sub/${initial.token}/base64`,
    reply_parameters: { message_id: enabledDetail.messageId }, link_preview_options: { is_disabled: true } });
  const served = await formats.fetch(`https://app.fixture.invalid/sub/${initial.token}/base64`);
  assert.equal(served.status, 200);
  assert.equal(await served.text(), Buffer.from(fixtureShare).toString("base64"));
  assert.equal((await callback(7378, 101, origin(enabledDetail.messageId, 101), base64, formats)).status, 204);
  assert.equal((await callback(7379, 101, origin(enabledDetail.messageId, 101), base64, formats)).status, 204);
  await db.prepare("UPDATE subscription_lifecycle SET revision=5 WHERE subscription_id=? AND revision=4").bind(initial.id).run();
  assert.equal((await callback(7380, 101, origin(enabledDetail.messageId, 101), formatTicket("Clash Meta"), formats)).status, 204);
  assert.equal(await findReply(7380), null);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs").first("n"), 0);

  const firstShare = "hy2://first.example.invalid#synthetic-temp-first";
  const secondShare = "ssr://synthetic-temp-opaque#synthetic-temp-second";
  const tempPost = (id: number, actor: number, text: string, options: PostOptions = {}) => post(actor, text, {
    worker: formats, updateId: id, date: now + 4, ...options,
    message: text.startsWith("/") ? options.message : { entities: [], ...options.message },
  });
  await db.batch([
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',8,?,'member')")
      .bind(pin.botId, pin.generation, now + 3),
    db.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,?)").bind(pin.botId, "d".repeat(64), now + 3),
  ]);
  const legacy = JSON.stringify([{ name: "Fixture baseline", type: "temp", share: firstShare }]);
  await db.prepare("INSERT INTO legacy_temp_batches VALUES (?,'104',1,1,?,1,?,?)")
    .bind(pin.botId, legacy, Buffer.byteLength(legacy), createHash("sha256").update(legacy).digest("hex")).run();
  assert.equal((await sharedPost(101, "/temp summary")).status, 204);
  assert.equal((await tempPost(7400, 101, "/temp clear", { date: now + 3 })).status, 204,
    "the restored baseline cutoff is strict even for an administrator");
  assert.equal((await tempPost(7401, 102, firstShare)).status, 204);
  assert.equal((await tempPost(7402, 101, firstShare, groupEvent)).status, 204);
  assert.equal((await tempPost(7403, 101, firstShare, { message: { reply_to_message: origin(10, 101) } })).status, 204);
  assert.equal((await tempPost(7404, 101, "ordinary fixture text")).status, 204);
  assert.equal((await tempPost(7405, 101, "https://provider.fixture.invalid/ordinary")).status, 204);
  const tempMigration = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=8").first<string>("sha256");
  assert.ok(tempMigration);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=8").bind("0".repeat(64)).run();
  assert.equal((await tempPost(7406, 101, firstShare)).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=8").bind(tempMigration).run();
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_temp_reply").first("n"), 0);

  assert.equal((await tempPost(7410, 101, firstShare)).status, 200);
  const administrator = await awaitLifecycle(7410);
  assert.equal(administrator.message.text, "已加入临时列表 1 条节点，当前共有 1 条。");
  assert.equal((await tempPost(7410, 101, secondShare)).status, 204);
  const tempBase64 = Buffer.from(secondShare, "utf8").toString("base64");
  assert.equal((await tempPost(7411, 104, tempBase64)).status, 200);
  assert.equal((await awaitLifecycle(7411)).message.text, "已加入临时列表 1 条节点，当前共有 2 条。");
  assert.deepEqual(await db.prepare(`SELECT inbox.receipt_nonce AS marker,authority.actor_role AS role,
    authority.actor_revision AS revision,reply.kind AS kind
    FROM telegram_inbox AS inbox JOIN telegram_general_receipt AS authority USING (receipt_id)
    JOIN telegram_temp_reply AS reply USING (receipt_id) JOIN telegram_temp_batch AS batch USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=7411 AND batch.bot_id=inbox.bot_id AND batch.actor_id=inbox.actor_id`)
    .bind(pin.botId).first(), { marker: "general-temp:v1", role: "member", revision: 8, kind: "added" });

  assert.equal((await tempPost(7412, 104, "/temp")).status, 200);
  const summary = await awaitLifecycle(7412);
  assert.equal(summary.message.text, "临时列表共有 2 条节点。发送 /temp clear 清空。");
  assert.equal(summary.message.reply_markup, undefined);
  assert.equal((await tempPost(7413, 104, firstShare + "\nhy2://")).status, 200);
  assert.match((await awaitLifecycle(7413)).message.text, /^本批未写入。/u);
  assert.equal((await tempPost(7415, 104, firstShare, { date: now + 5 })).status, 200);
  await awaitLifecycle(7415);
  const totals = () => db.prepare(`SELECT actor_id AS owner,count(*) AS batches FROM telegram_temp_batch
    WHERE bot_id=? GROUP BY actor_id ORDER BY actor_id`).bind(pin.botId).all();
  await db.prepare(`CREATE TRIGGER fixture_general_temp_intake_abort BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id=NEW.receipt_id AND bot_id='105' AND update_id=7414)
    BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    assert.equal((await tempPost(7414, 104, "/temp clear")).status, 503);
    assert.deepEqual((await totals()).results, [{ owner: "101", batches: 1 }, { owner: "104", batches: 2 }]);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM legacy_temp_batches").first("n"), 1);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_temp_clear_fence").first("n"), 0);
    assert.equal(await findReply(7414), null);
  } finally {
    await db.prepare("DROP TRIGGER fixture_general_temp_intake_abort").run();
  }
  assert.equal((await tempPost(7414, 104, "/temp clear")).status, 200);
  assert.equal((await awaitLifecycle(7414)).message.text, "已移除 2 条临时节点，当前共有 1 条。");
  assert.equal((await tempPost(7414, 104, "/temp clear")).status, 204);
  assert.deepEqual((await totals()).results, [{ owner: "101", batches: 1 }, { owner: "104", batches: 1 }]);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM legacy_temp_batches").first("n"), 0);
  assert.equal((await tempPost(7416, 104, firstShare, { message: { message_id: 7413 } })).status, 200);
  assert.match((await awaitLifecycle(7416)).message.text, /^该操作早于最近一次清空/u);
  assert.doesNotMatch(JSON.stringify(lifecycleSent.filter(({ reply_parameters }) => reply_parameters.message_id >= 7410)),
    /(?:hy2|ssr):|synthetic-temp-/u);

  const queuedSummary = new Request("https://app.fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify({ update_id: 7417, message: {
      from: { id: 104, is_bot: false }, chat: { id: 104, type: "private" }, date: now + 5, message_id: 7417,
      text: "/temp summary", entities: [{ type: "bot_command", offset: 0, length: 5 }],
    } }),
  });
  assert.equal(await acceptGeneralSharedTelegramCommand(db, formatsPin, queuedSummary.clone()), 204);
  assert.equal(await acceptGeneralSharedTelegramCommand(db, cumulativePin, queuedSummary), 200);
  const tempLease = await claimGeneralSharedTelegramReply(db, cumulativePin);
  assert.equal(tempLease?.updateId, 7417);
  assert.ok(tempLease);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',9,?,'denied')")
    .bind(pin.botId, pin.generation, now + 6).run();
  assert.equal(await beginGeneralSharedTelegramReply(db, cumulativePin, tempLease), false);
  const firstDocumentCron = await formats.scheduled({ cron: "* * * * *" });
  if (firstDocumentCron.outcome !== "ok") {
    // Reproduce only storage phases after the emitted check failed. This fixture
    // has no queued documents yet and the shared probe stops before delivery.
    let backendClass = "unclassified";
    const probeDb = (beforeBatch?: () => void) => ({
      prepare: db.prepare.bind(db),
      async batch(statements: D1PreparedStatement[]) {
        beforeBatch?.();
        try { return await db.batch(statements); } catch (error) {
          backendClass = diagnosticError(error);
          throw error;
        }
      },
    }) as D1Database;
    const stopBeforeClaim = new Error("Synthetic recovery reached the delivery boundary.");
    let sharedBatches = 0;
    const noDelivery = probeDb(() => {
      // The first batch reaps lifecycle tickets, the second would claim a reply.
      if (++sharedBatches > 1) throw stopBeforeClaim;
    });
    const stages = {
      "document-claim": () => claimTelegramDocumentJob(probeDb(), documentPin),
      "document-replies": () => reconcileTelegramDocumentJobReplies(probeDb(), documentPin),
      "document-stage": () => retireTelegramDocumentStage(probeDb(), bucket, documentPin),
      "shared-reaper": () => recoverGeneralSharedTelegramReplies(noDelivery, documentPin, bucket, PRODUCTION_PUBLIC_ORIGIN),
      "shared-claim": () => claimGeneralSharedTelegramReply(probeDb(), documentPin),
    };
    const results = [];
    for (const [stage, probe] of Object.entries(stages)) {
      backendClass = "unclassified";
      try { await probe(); results.push(`${stage}=ok`); } catch (error) {
        const direct = diagnosticError(error);
        results.push(`${stage}=${error === stopBeforeClaim ? "ok" : direct === "unclassified" ? backendClass : direct}`);
      }
    }
    assert.fail(`Emitted general Cron failed (${results.join(", ")}).`);
  }
  assert.equal(firstDocumentCron.outcome, "ok");
  assert.equal((await findReply(7417))?.state, "failed");
  assert.equal((await tempPost(7418, 104, "/temp clear", { date: now + 7 })).status, 204);
  assert.deepEqual((await totals()).results, [{ owner: "101", batches: 1 }, { owner: "104", batches: 1 }]);

  const quotaRows = JSON.stringify(Array.from({ length: MAX_TEMP_BATCH_NODES }, () =>
    ({ name: "Fixture quota", type: "temp", share: firstShare })));
  const quotaSha = createHash("sha256").update(quotaRows).digest("hex");
  const quotaSteps = [];
  for (let start = 1; start <= MAX_TEMP_OWNER_NODES; start += MAX_TEMP_BATCH_NODES) {
    quotaSteps.push(db.prepare("INSERT INTO legacy_temp_batches VALUES (?,'106',?,?,?,?,?,?)")
      .bind(pin.botId, start, start + MAX_TEMP_BATCH_NODES - 1, quotaRows, MAX_TEMP_BATCH_NODES,
        Buffer.byteLength(quotaRows), quotaSha));
  }
  assert.ok((await db.batch(quotaSteps)).every(({ success }) => success));
  assert.equal((await tempPost(7419, 106, firstShare)).status, 200);
  assert.match((await awaitLifecycle(7419)).message.text, new RegExp(`达到数量或大小限制.*${MAX_TEMP_OWNER_NODES}`, "u"));
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_temp_batch WHERE bot_id=? AND actor_id='106'")
    .bind(pin.botId).first("n"), 0);

  const documentWebhookUrl = "https://app.fixture.invalid/telegram/webhook";
  const documentRequest = (updateId: number, actor: number, fileId: string, options: PostOptions = {}): RequestInit =>
    ({ method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify({ update_id: updateId, message: {
        from: { id: actor, is_bot: false }, chat: { id: options.chatId ?? actor, type: options.chatType ?? "private" },
        message_id: updateId, date: options.date ?? now + 8,
        document: { file_id: fileId, file_name: "Fixture node upload.txt", file_size: Buffer.byteLength(fixtureDocuments.get(fileId)!) },
      } }),
    });
  const submitDocument = (id: number, actor: number, file: string, options: PostOptions = {}) =>
    formats.fetch(documentWebhookUrl, documentRequest(id, actor, file, options));
  const documentRow = (id: number) => db.prepare(`SELECT inbox.receipt_nonce AS marker,job.state,job.result_code AS outcome,
    job.file_id IS NULL AS scrubbed,origin.actor_revision AS revision
    FROM telegram_document_jobs AS job JOIN telegram_inbox AS inbox USING (receipt_id)
    JOIN telegram_general_receipt AS origin USING (receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(pin.botId, id).first();
  const uploaded = () => db.prepare(`SELECT owner_id AS owner,generation,token FROM subscriptions
    WHERE name='Fixture node upload' AND source_url='uploaded://telegram-document' ORDER BY owner_id`).all<{ owner: string; generation: number; token: string }>();
  fixtureDocuments.set("fixture-doc-admin", firstShare);
  fixtureDocuments.set("fixture-doc-member", secondShare);
  fixtureDocuments.set("fixture-doc-mixed", firstShare + "\nhttps://provider.fixture.invalid/private");
  fixtureDocuments.set("fixture-doc-revoked", firstShare);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',10,?,'member')")
    .bind(pin.botId, pin.generation, now + 7).run();
  assert.equal(await acceptGeneralSharedTelegramCommand(db, cumulativePin,
    new Request(documentWebhookUrl, documentRequest(7500, 101, "fixture-doc-admin"))), 204);
  assert.equal((await submitDocument(7501, 102, "fixture-doc-admin")).status, 204);
  assert.equal((await submitDocument(7502, 101, "fixture-doc-admin", groupEvent)).status, 204);
  assert.equal((await submitDocument(7510, 101, "fixture-doc-admin")).status, 200);
  assert.equal((await submitDocument(7510, 101, "fixture-doc-admin")).status, 204);
  assert.equal((await submitDocument(7511, 104, "fixture-doc-member")).status, 200);
  assert.equal((await documentRow(7510))?.state, "pending");
  assert.equal(await findReply(7510), null);
  assert.deepEqual(fileRequests, [], "webhook admission cannot download files");

  for (const [id, actor] of [[7510, 101], [7511, 104]] as const) {
    assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
    if (await findReply(id) === null) {
      const failed = await documentRow(id);
      const requestCount = fileRequests.filter((file) => file === (actor === 101 ? "fixture-doc-admin" : "fixture-doc-member")).length;
      let cause = "unclassified";
      let phase = "none";
      if (failed?.state === "pending" && requestCount === 2) {
        // Reproduce the storage path only in this disposable fixture. Never send or download again.
        await db.prepare(`UPDATE telegram_document_jobs SET due_at=unixepoch()
          WHERE receipt_id=(SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?)
          AND state='pending'`).bind(pin.botId, id).run();
        const lease = await claimTelegramDocumentJob(db, documentPin);
        assert.ok(lease && lease.actorId === String(actor));
        const parsed = parseSubscriptionDocument(new TextEncoder().encode(actor === 101 ? firstShare : secondShare));
        assert.equal(parsed.kind, "parsed");
        const storageDb = {
          prepare: db.prepare.bind(db),
          async batch(statements: D1PreparedStatement[]) {
            phase = phase === "none" ? "reserve" : "publish";
            try { return await db.batch(statements); } catch (error) {
              cause = diagnosticError(error);
              throw error;
            }
          },
        } as D1Database;
        try {
          const result = await persistTelegramDocumentJob(storageDb, bucket, documentPin, lease, parsed.nodes,
            { parsed: parsed.nodes.length });
          cause = result;
        } catch (error) {
          if (cause === "unclassified") cause = diagnosticError(error);
        }
      }
      assert.fail(`Synthetic document reply missing (state=${failed?.state}, outcome=${failed?.outcome}, fetches=${requestCount}, ${phase}=${cause}).`);
    }
    const saved = await awaitLifecycle(id);
    assert.equal(saved.message.chat_id, String(actor));
    assert.equal(saved.message.text, "文件已导入，共 1 个节点。");
    assert.deepEqual(await documentRow(id), { marker: "general-document-job:v1", state: "done",
      outcome: "saved", scrubbed: 1, revision: actor === 101 ? 1 : 10 });
  }
  assert.deepEqual(fileRequests, ["fixture-doc-admin", "fixture-doc-admin", "fixture-doc-member", "fixture-doc-member"]);
  const original = (await uploaded()).results;
  assert.deepEqual(original.map(({ owner, generation }) => ({ owner, generation })),
    [{ owner: "101", generation: 1 }, { owner: "104", generation: 1 }]);
  for (const [index, share] of [firstShare, secondShare].entries()) {
    const response = await formats.fetch(`https://app.fixture.invalid/sub/${original[index].token}/base64`);
    assert.equal(response.status, 200);
    assert.equal(Buffer.from(await response.text(), "base64").toString("utf8"), share);
  }

  assert.equal((await submitDocument(7512, 104, "fixture-doc-mixed", { date: now + 9 })).status, 200);
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await awaitLifecycle(7512)).message.text, "文件未导入。请检查文件类型、大小和节点格式。已有订阅保持原样。");
  assert.deepEqual((await uploaded()).results, original);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents").first("n"), 0);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_jobs").first("n"), 0);

  assert.equal((await submitDocument(7513, 104, "fixture-doc-revoked", { date: now + 9 })).status, 200);
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,'104',11,?,'denied')")
    .bind(pin.botId, pin.generation, now + 10).run();
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.deepEqual(await documentRow(7513), { marker: "general-document-job:v1", state: "done",
    outcome: "access-changed", scrubbed: 1, revision: 10 });
  assert.equal((await findReply(7513))?.state, "failed");
  assert.equal(fileRequests.includes("fixture-doc-revoked"), false);
  assert.deepEqual((await uploaded()).results, original);

  const abandonedSnapshot = "33333333-3333-4333-8333-333333333333";
  const memberSubscriptionId = await db.prepare("SELECT id FROM subscriptions WHERE owner_id='104' AND token=?")
    .bind(original[1].token).first<number>("id");
  assert.ok(memberSubscriptionId);
  const abandonedObject = `subscriptions/${memberSubscriptionId}/${abandonedSnapshot}/0.ndjson`;
  await db.prepare(`INSERT INTO telegram_document_stages (snapshot_id,receipt_id,subscription_id,lease_id,cleanup_after)
    SELECT ?,receipt_id,?,'44444444-4444-4444-8444-444444444444',unixepoch()-1
    FROM telegram_inbox WHERE bot_id=? AND update_id=7513`).bind(abandonedSnapshot, memberSubscriptionId, pin.botId).run();
  await bucket.put(abandonedObject, "synthetic retired document object");
  assert.equal((await formats.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await bucket.head(abandonedObject), null);
  assert.equal(await db.prepare("SELECT snapshot_id FROM telegram_document_stages WHERE snapshot_id=?")
    .bind(abandonedSnapshot).first(), null);
  assert.deepEqual((await uploaded()).results, original);

  const rehearsal = await runtime.getWorker("rehearsal");
  const lanePost = (actor: number, command: string, options: PostOptions = {}) =>
    post(actor, command, { secret: isolation.webhookSecret, date: now - 3, ...options, worker: rehearsal });
  const laneRow = (updateId: number) => db.prepare(`SELECT inbox.actor_id AS actor, inbox.receipt_nonce AS marker, reply.state
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
      WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(isolation.botId, updateId).first();
  const waitForLane = async (updateId: number) => {
    const end = Date.now() + 4000;
    for (let row = await laneRow(updateId); Date.now() < end; row = await laneRow(updateId)) {
      if (row?.state === "sent") return row;
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    assert.fail("The synthetic read rehearsal reply did not settle.");
  };
  await db.batch([
    db.prepare(`INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
      VALUES (181,'Rehearsal admin only','https://source.fixture.invalid/hidden','rehearsal-admin-token',?,?),
             (182,'Rehearsal member only','https://source.fixture.invalid/hidden','rehearsal-member-token',?,?)`).bind(now, now, now, now),
    db.prepare("INSERT INTO telegram_general_read_lane (bot_id,epoch,mode) VALUES (?,1,'closed')").bind(isolation.botId),
  ]);
  const staleScope = { updateId: 8100, actorId: isolation.adminId, chatId: isolation.adminId,
    chatType: "private" as const, threadId: null, messageId: 8100, messageDate: now - 3 };
  await assert.rejects(acceptTelegramCommand(db, isolation, { ...staleScope, command: "help" }, undefined,
    assertGeneralReadLane(db, isolation.botId, "isolated", null)));
  await assert.rejects(acceptTelegramView(db, isolation, { ...staleScope, kind: "list" },
    assertGeneralReadLane(db, isolation.botId, "isolated", null)));
  assert.equal(await laneRow(8100), null, "a stale admission cannot commit on either isolation anchor");
  assert.equal((await lanePost(181, "/help", { updateId: 8101 })).status, 503);
  assert.equal((await lanePost(182, "/list", { updateId: 8102, date: now - 21 })).status, 503);
  assert.equal((await lanePost(181, "/help", { updateId: 8103, secret: pin.webhookSecret })).status, 401);
  assert.equal(await laneRow(8101), null);
  assert.equal(await laneRow(8102), null);
  assert.equal(laneSent.length, 0);

  await db.batch([
    db.prepare(`INSERT INTO telegram_general_policy (bot_id,generation,release_revision,activation_sha256,cutover_at,active)
      VALUES (?,1,?,?,?,1)`).bind(isolation.botId, fixture.releaseRevision, pin.candidateManifestSha256, now - 20),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,1,?,'admin'),(?,1,?,1,?,'member')")
      .bind(isolation.botId, isolation.adminId, now - 20, isolation.botId, isolation.memberId, now - 20),
    db.prepare("UPDATE telegram_general_read_lane SET mode='general',epoch=2,generation=1 WHERE bot_id=?")
      .bind(isolation.botId),
  ]);
  const open = await readGeneralReadLane(db, isolation, fixture.releaseRevision);
  assert.ok(open?.pin?.rehearsal && open.mode === "general");
  assert.deepEqual([open.pin.privateManagement, open.pin.privateFormats, open.pin.privateTemp, open.pin.privateDocument],
    [false, false, false, false], "the rehearsal enables only private reads");
  assert.equal((await lanePost(182, "/list", { updateId: 8102, date: now - 21 })).status, 503,
    "uncommitted pre-cutover delivery is held for the original lane");
  assert.equal((await lanePost(183, "/list", { updateId: 8104 })).status, 204);
  assert.equal(await laneRow(8104), null);
  assert.equal((await lanePost(181, "/help", { updateId: 8105 })).status, 200);
  assert.deepEqual(await waitForLane(8105), { actor: "181", marker: "general-read:v1", state: "sent" });
  assert.equal((await lanePost(182, "/list", { updateId: 8106 })).status, 200);
  assert.deepEqual(await waitForLane(8106), { actor: "182", marker: "general-read:v1", state: "sent" });
  assert.equal((await lanePost(182, "/list", { updateId: 8106 })).status, 204);
  assert.deepEqual(laneSent.map((message) => message.chat_id), ["181", "182"]);
  assert.match(laneSent[1].text, /Rehearsal member only/u);
  assert.doesNotMatch(laneSent[1].text, /Rehearsal admin only|fixture\.invalid|rehearsal-member-token/u);

  const pending = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
    VALUES (?,8107,?,?,'private',8107,?,'help','general-read:v1') RETURNING receipt_id`)
    .bind(isolation.botId, isolation.memberId, isolation.memberId, now - 3).first<number>("receipt_id");
  assert.ok(pending);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,1,1,'member',?,?,?)")
      .bind(pending, fixture.releaseRevision, pin.candidateManifestSha256, now - 20),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(pending),
  ]);
  const laneLease = await claimGeneralSharedTelegramReply(db, open.pin);
  assert.ok(laneLease);
  assert.equal(laneLease.receiptId, pending);
  await db.batch([
    db.prepare("UPDATE telegram_general_read_lane SET mode='closed',epoch=3 WHERE bot_id=?").bind(isolation.botId),
    db.prepare("INSERT INTO telegram_auth VALUES (?,?,0,?,8108)").bind(isolation.botId, isolation.memberId, now - 2),
  ]);
  assert.equal(await beginGeneralSharedTelegramReply(db, open.pin, laneLease), false, "member revocation fences the send");
  const draining = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
    VALUES (?,8110,?,?,'private',8110,?,'help','general-read:v1') RETURNING receipt_id`)
    .bind(isolation.botId, isolation.adminId, isolation.adminId, now - 3).first<number>("receipt_id");
  assert.ok(draining);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_receipt VALUES (?,1,1,'admin',?,?,?)")
      .bind(draining, fixture.releaseRevision, pin.candidateManifestSha256, now - 20),
    db.prepare("INSERT INTO telegram_outbox (receipt_id) VALUES (?)").bind(draining),
  ]);
  assert.equal((await rehearsal.scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal((await laneRow(8107))?.state, "failed");
  assert.equal((await laneRow(8110))?.state, "sent", "closing ingress preserves the current grant for draining");
  assert.equal((await lanePost(181, "/help", { updateId: 8105 })).status, 204, "known committed retries can settle while closed");
  assert.equal((await lanePost(181, "/help", { updateId: 8109 })).status, 503);
  assert.equal(laneSent.length, 3);

  await db.batch([
    db.prepare("UPDATE telegram_general_policy SET active=0 WHERE bot_id=? AND generation=1").bind(isolation.botId),
    db.prepare("UPDATE telegram_general_read_lane SET mode='isolated',epoch=4,generation=NULL WHERE bot_id=?").bind(isolation.botId),
  ]);
  assert.equal((await lanePost(181, "/help", { updateId: 8109 })).status, 200);
  assert.deepEqual(await waitForLane(8109), { actor: "181", marker: null, state: "sent" });
  assert.equal((await lanePost(182, "/list", { updateId: 8102, date: now - 21 })).status, 200);
  assert.equal((await laneRow(8102))?.marker, "view:v1", "the delayed delivery retains its original receipt family");
});

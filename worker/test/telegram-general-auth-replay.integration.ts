import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { networkInterfaces } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";
import { build } from "esbuild";
import { Log, LogLevel, Miniflare } from "miniflare";
import { GENERAL_AUTH_LEGACY_ROLE, type GeneralAuthReplayMessage, type GeneralAuthReplayPin } from "../src/telegram/general-auth-replay.ts";
import { beginGeneralTelegramReply, claimGeneralTelegramReply, parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { beginGeneralSharedTelegramReply, claimGeneralSharedTelegramReply } from "../src/telegram/general-auth-shared.ts";
import { generalCurrentAuthoritySql, generalCurrentReceiptSql, generalOrdinaryReplyEligibilitySql, generalPolicyBindings,
  generalRecordedOriginSql } from "../src/telegram/general-receipt.ts";
import { claimTelegramReply } from "../src/telegram/store.ts";

type Fixture = Omit<GeneralAuthReplayPin, "botUsername" | "webhookSecret" | "generation" | "cutoverAt"> & {
  bundleSha256: string; compatibilityDate: string; statements: string[];
};

test("closed general authorization replays a sealed candidate in a separate emitted Worker", { timeout: 60_000 }, async (t) => {
  assert.equal(process.platform, "linux");
  assert.notEqual(process.getuid?.(), 0);
  assert.deepEqual(Object.keys(networkInterfaces()), ["lo"]);
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
  const sharedSent: (GeneralAuthReplayMessage & { message_thread_id?: number })[] = [];
  const lifecycleSent: (GeneralAuthReplayMessage & { reply_markup?: {
    force_reply?: boolean; inline_keyboard?: { text: string; callback_data: string }[][];
  } })[] = [];
  const lifecycleMessagesById = new Map<number, (typeof lifecycleSent)[number]>();
  const lifecycleAcks = new Set<string>();
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
  assert.ok(privatePin?.sharedOutbox && privatePin.privateManagement);
  for (const outbox of ["legacy", "shared-lifecycle", "shared-path", ["shared-private-management"]]) {
    assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...JSON.parse(generalConfig), outbox }),
      fixture.releaseRevision), null);
  }
  const d1Databases = { DB: "sealed-general-auth-replay" };
  const runtime = new Miniflare({ log: new Log(LogLevel.NONE), workers: [
    { name: "serving", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(isolation),
        TELEGRAM_GENERAL_CONFIG: generalConfig, REPLAY_PIN: pin },
      outboundService: () => { throw new Error("Unexpected serving transport."); } },
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
      outboundService: async (request: Request) => {
        assert.equal(request.method, "POST");
        const api = `https://api.telegram.org/bot${generalToken}/`;
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
      } },
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
  const callback = (id: number, actor: number, source: ReturnType<typeof origin>, ticket: string) => lifecycle.fetch(
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
});

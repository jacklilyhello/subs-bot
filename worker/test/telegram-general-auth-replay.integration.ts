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
import type { GeneralAuthReplayMessage, GeneralAuthReplayPin } from "../src/telegram/general-auth-replay.ts";

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
  let failTransport = false;
  const d1Databases = { DB: "sealed-general-auth-replay" };
  const runtime = new Miniflare({ log: new Log(LogLevel.NONE), workers: [
    { name: "serving", modules: true, script: servingScript.toString(), compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.releaseRevision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(isolation), REPLAY_PIN: pin },
      outboundService: () => { throw new Error("Unexpected serving transport."); } },
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
});

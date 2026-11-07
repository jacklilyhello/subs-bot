import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { acceptTelegramPrivateShareCreation, importTelegramPrivateShareCreationKey } from "../src/telegram/private-share-creation.ts";
import {
  PRIVATE_SHARE_CREATION_INSTALLATION, PRIVATE_SHARE_CREATION_MIGRATION, PRIVATE_SHARE_CREATION_SCHEMA_SHA256,
} from "../src/telegram/private-share-runtime.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const key = Buffer.alloc(32, 0x52).toString("base64url");
const policy: TelegramPolicy = { botId: "74301", botUsername: "fixture_private_create_bot", adminId: "74302", memberId: "74303",
  groupId: "-10074304", botToken: "74301:synthetic-token", webhookSecret: "synthetic-private-share-secret" };

test("the emitted Worker admits private creation once, sends only its guarded link, and recovers durable payloads", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sent: Array<{ text: string; replyTo: number }> = [];
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_PRIVATE_SHARE_CREATION_KEY: key },
    outboundService: async (request: Request) => {
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      assert.equal(request.method, "POST");
      const body = await request.json() as { chat_id: string; text: string; reply_parameters: { message_id: number }; link_preview_options: unknown };
      assert.equal(body.chat_id, policy.adminId);
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.doesNotMatch(body.text, /synthetic secret body|durable recovery body/u);
      sent.push({ text: body.text, replyTo: body.reply_parameters.message_id });
      return Response.json({ ok: true, result: { message_id: 100 + sent.length, chat: { id: Number(body.chat_id) } } });
    } });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    for (const migration of manifest.migrations) {
      if (migration.name === PRIVATE_SHARE_CREATION_MIGRATION) continue;
      const bytes = await readFile(join(directory, migration.name));
      assert.equal(createHash("sha256").update(bytes).digest("hex"), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    const date = Number(await db.prepare("SELECT unixepoch() AS now").first("now"));
    const post = (id: number, text: string, chatId = policy.adminId) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify({ update_id: id, message: { message_id: id, date, text,
        from: { id: Number(policy.adminId), is_bot: false },
        chat: { id: Number(chatId), type: chatId === policy.groupId ? "group" : "private" },
        entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }],
      } }),
    });
    const worker = await runtime.getWorker();
    const tick = async () => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    const waitForReply = async (messageId: number) => {
      for (let i = 0; i < 50; i++) {
        if (sent.some(({ replyTo }) => replyTo === messageId)) return;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Synthetic private-share reply did not arrive.");
    };
    const text = `/share x2 id${policy.memberId} s10 --\r\n  synthetic secret body  `;
    assert.equal((await post(1, text, policy.groupId)).status, 204);
    // The key alone cannot enable references to a missing/old 0016 ledger.
    assert.equal((await post(1, text)).status, 204);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox").first("n"), 0);
    assert.equal((await post(9, "/help")).status, 200);
    await tick();
    await waitForReply(9);
    const creationSql = await readFile(join(directory, PRIVATE_SHARE_CREATION_MIGRATION), "utf8");
    assert.equal(createHash("sha256").update(creationSql).digest("hex"), PRIVATE_SHARE_CREATION_SCHEMA_SHA256);
    assert.equal(manifest.migrations.find((migration: { name: string }) => migration.name === PRIVATE_SHARE_CREATION_MIGRATION)?.sha256,
                 PRIVATE_SHARE_CREATION_SCHEMA_SHA256);
    await db.batch(creationSql.trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (16,?,?,'applied')")
      .bind(PRIVATE_SHARE_CREATION_MIGRATION, PRIVATE_SHARE_CREATION_SCHEMA_SHA256).run();
    assert.deepEqual((await Promise.all([post(1, text), post(1, text)])).map(({ status }) => status), [200, 200]);
    await tick();
    await waitForReply(1);
    assert.equal(sent.filter(({ replyTo }) => replyTo === 1).length, 1);
    const row = await db.prepare(`SELECT creation.payload_id,share.code_sha256 FROM telegram_private_share_creations AS creation
      JOIN private_shares AS share ON share.id=creation.share_id`).first<{ payload_id: string; code_sha256: string }>();
    assert.ok(row);
    const code = sent.find(({ replyTo }) => replyTo === 1)!.text.match(/start=claim_([A-Za-z0-9_-]{22})/u)?.[1];
    assert.ok(code);
    assert.equal(createHash("sha256").update(code).digest("hex"), row.code_sha256);
    assert.equal(await (await bucket.get(`private-shares/${row.payload_id}.txt`))!.text(), "  synthetic secret body  ");
    const metadata = await db.prepare("SELECT * FROM telegram_private_share_creations").all();
    assert.doesNotMatch(JSON.stringify(metadata.results), /synthetic secret body|start=claim_/u);
    assert.equal((await post(2, "/share x0 -- synthetic secret body")).status, 200);
    await tick();
    await waitForReply(2);
    assert.match(sent.find(({ replyTo }) => replyTo === 2)!.text, /\/share/u);

    const context = await importTelegramPrivateShareCreationKey(key, PRIVATE_SHARE_CREATION_INSTALLATION);
    assert.ok(context);
    const interrupted = { prepare: (sql: string) => db.prepare(sql), async batch(steps: D1PreparedStatement[]) {
      if (steps.length === 4) throw new Error("Synthetic publication interruption.");
      return db.batch(steps);
    } } as unknown as D1Database;
    await assert.rejects(acceptTelegramPrivateShareCreation(interrupted, bucket, policy, { updateId: 3, messageId: 3,
      messageDate: date, actorId: policy.adminId, chatId: policy.adminId, chatType: "private", threadId: null,
      content: "durable recovery body", maxClaims: 1, targetUserId: null, durationMinutes: 10 }, context), /could not be confirmed/u);
    await tick();
    await waitForReply(3);
    assert.equal(sent.filter(({ replyTo }) => replyTo === 3).length, 1);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM private_shares").first("n"), 2);
  } finally { await runtime.dispose(); }
});

test("the emitted Cron retires an owned abandoned candidate without a creation key", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService() { throw new Error("An abandoned private candidate must not send a Telegram request."); } });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    for (const migration of manifest.migrations) {
      const bytes = await readFile(join(directory, migration.name));
      assert.equal(createHash("sha256").update(bytes).digest("hex"), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (16,?,?,'applied')")
      .bind(PRIVATE_SHARE_CREATION_MIGRATION, PRIVATE_SHARE_CREATION_SCHEMA_SHA256).run();
    const context = await importTelegramPrivateShareCreationKey(key, PRIVATE_SHARE_CREATION_INSTALLATION);
    assert.ok(context);
    const interrupted = { prepare: (sql: string) => db.prepare(sql), async batch(steps: D1PreparedStatement[]) {
      if (steps.length === 4) throw new Error("Synthetic publication interruption.");
      return db.batch(steps);
    } } as unknown as D1Database;
    await assert.rejects(acceptTelegramPrivateShareCreation(interrupted, bucket, policy, {
      updateId: 1, messageId: 1, messageDate: Number(await db.prepare("SELECT unixepoch() AS now").first("now")),
      actorId: policy.adminId, chatId: policy.adminId, chatType: "private", threadId: null,
      content: "synthetic candidate cleanup", maxClaims: 1, targetUserId: null, durationMinutes: 10 }, context), /could not be confirmed/u);
    const candidate = await db.prepare("SELECT payload_id FROM telegram_private_share_creations").first<string>("payload_id");
    assert.ok(candidate);
    assert.ok(await bucket.head(`private-shares/${candidate}.txt`));
    await db.prepare(`UPDATE telegram_private_share_creations SET reservation_expires_at=unixepoch()-60,
      cleanup_after=unixepoch()-1,next_check_at=unixepoch()-1`).run();
    assert.equal((await (await runtime.getWorker()).scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.equal(await bucket.head(`private-shares/${candidate}.txt`), null);
    const row = await db.prepare("SELECT state,cleaned_at FROM telegram_private_share_creations").first<{ state: string; cleaned_at: number }>();
    assert.ok(row && row.state === "abandoned" && row.cleaned_at > 0);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM private_shares").first("n"), 0);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_outbox").first("n"), 0);
  } finally { await runtime.dispose(); }
});

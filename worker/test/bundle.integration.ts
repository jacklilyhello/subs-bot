import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Miniflare } from "miniflare";
import { parse as parseYaml } from "yaml";

import { renderTelegramHelp } from "../src/telegram/command-catalog.ts";
import { createPrivateShare } from "../src/private-shares.ts";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { enqueueOwnedProviderRefresh } from "../src/provider-jobs.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import { createSubscription, getOwnedSubscription, publishNodeSnapshot } from "../src/storage.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand } from "../src/telegram/store.ts";
import { verifyIsolation } from "../tools/verify-isolation.mjs";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";
import "./backup-rehearsal.integration.ts";
import "./telegram-private-share-command.integration.ts";
import "./telegram-subscription-share.integration.ts";
import "./telegram-group-share.integration.ts";
import "./provider-job-consumer.integration.ts";
import "./telegram-provider-url-import.integration.ts";
import "./telegram-provider-refresh.integration.ts";
import "./telegram-provider-batch.integration.ts";
import "./telegram-api-status.integration.ts";
import "./telegram-subscription-read.integration.ts";
import "./telegram-subscription-node-pages.integration.ts";
import "./telegram-subscription-raw-file.integration.ts";
import "./telegram-temp-raw.integration.ts";
import "./telegram-short-links.integration.ts";
import "./external-shortlinks.integration.ts";
import "./external-shortlink-paths.integration.ts";
import "./public-origin.integration.ts";
import "./telegram-inline-sort.integration.ts";
import "./telegram-bulk-trash.integration.ts";
import "./telegram-general-management.integration.ts";
import "./telegram-personal-inline.integration.ts";
import "./telegram-general-inline.integration.ts";
import "./telegram-github-search.integration.ts";
import "./legacy-subscription-short-links.integration.ts";
import "./legacy-selected-aggregate.integration.ts";

test("emitted Worker /o freezes owned subscription membership and excludes temporary nodes", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const bundle = await readFile(join(directory, "index.js"), "utf8");
  const policy: TelegramPolicy = {
    botId: "94001", adminId: "94101", memberId: "94201", groupId: "-1001234567890",
    botUsername: "ArtifactSelectedBot", botToken: "94001:synthetic-selected-token", webhookSecret: "synthetic-selected-artifact-secret",
  };
  const date = Math.floor(Date.now() / 1000) - 5;
  const sent: Array<{ text: string; reply_markup?: { inline_keyboard: Array<Array<{ callback_data: string }>> } }> = [];
  const worker = new Miniflare({
    modules: true, script: bundle, compatibilityDate: fixture.compatibilityDate, d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: fixture.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
      TELEGRAM_AGGREGATE_KEY: Buffer.alloc(32, 0x19).toString("base64url") },
    outboundService: async (request: Request) => {
      if (request.url.endsWith("/answerCallbackQuery")) return Response.json({ ok: true, result: true });
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      const body = await request.json() as { text: string; chat_id: string };
      assert.equal(body.chat_id, policy.memberId);
      sent.push(body);
      return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(policy.memberId) } } });
    },
  });
  try {
    const db = await worker.getD1Database("DB");
    const bucket = await worker.getR2Bucket("NODES");
    await applyMigrations(db, directory, fixture.migrations);
    const stored = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#stored";
    const temporary = stored.replace("#stored", "#temporary");
    const sub = await createSubscription(db, { ownerId: policy.memberId, name: "Selected artifact", sourceUrl: "https://example.invalid/private" });
    assert.equal(await publishNodeSnapshot(db, bucket, { id: sub.id, ownerId: policy.memberId,
      expectedGeneration: 0, expectedLifecycleRevision: 0 }, [{ share: stored }]), true);
    const post = (updateId: number, text: string) => worker.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify({ update_id: updateId, message: { message_id: updateId + 10, date, text,
        from: { id: Number(policy.memberId), is_bot: false }, chat: { id: Number(policy.memberId), type: "private" },
        entities: text.startsWith("/") ? [{ type: "bot_command", offset: 0, length: 2 }] : [] } }),
    });
    const waitForSent = async (count: number) => {
      for (let attempt = 0; attempt < 100 && sent.length < count; attempt += 1) {
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.equal(sent.length, count);
    };
    assert.equal((await post(1, temporary)).status, 200);
    await waitForSent(1);
    assert.equal((await post(2, "/o")).status, 200);
    await waitForSent(2);
    const url = sent[1].text.match(/https:\/\/[^\s]+\/clash/u)?.[0];
    assert.ok(url);
    const response = await worker.dispatchFetch(url.replace(/clash$/u, "base64"));
    assert.equal(response.status, 200);
    assert.equal(await response.text(), Buffer.from(stored).toString("base64"));
    assert.equal(response.headers.get("Cache-Control"), "private, no-store");
    const token = sent[1].reply_markup?.inline_keyboard[0][0].callback_data;
    assert.match(token!, /^sbo1_[A-Za-z0-9_-]{22}$/u);
    const result = await worker.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify({ update_id: 3, callback_query: { id: "artifact-revoke", data: token,
        from: { id: Number(policy.memberId), is_bot: false }, message: { message_id: 1002, date,
          from: { id: Number(policy.botId), is_bot: true }, chat: { id: Number(policy.memberId), type: "private" } } } }),
    });
    assert.equal(result.status, 200);
    assert.equal((await worker.dispatchFetch(url, { method: "HEAD" })).status, 404);
  } finally {
    await worker.dispose();
  }
});

const digest = (body: Buffer) => createHash("sha256").update(body).digest("hex");

async function applyMigrations(db: D1Database, directory: string, migrations: Array<{ name: string; sha256: string }>) {
  for (const { name, sha256 } of migrations) {
    const migration = await readFile(join(directory, name));
    assert.equal(digest(migration), sha256);
    const statements = migration.toString("utf8").trim().split(/;\s*/u).filter(Boolean);
    await db.batch(statements.map((statement) => db.prepare(statement)));
    await recordTempFixtureMigration(db, { name, sha256 });
  }
}

test("emitted Worker acknowledges the exact authorization operation and distinguishes stale or unconfirmed commands",
  { timeout: 60_000 }, async (t) => {
    const directory = process.env.WORKER_TEST_BUNDLE_DIR;
    assert.ok(directory);
    const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
    const script = await readFile(join(directory, "index.js"));
    assert.equal(digest(script), fixture.bundleSha256);
    const policy: TelegramPolicy = {
      botId: "77901", botUsername: "Fixture_Auth_Bot", adminId: "77902", memberId: "77903", groupId: "-10077904",
      botToken: "77901:synthetic-token", webhookSecret: "synthetic-auth-ack-webhook",
    };
    const sent: Array<{ chatId: string; replyTo: number; text: string }> = [];
    const runtime = new Miniflare({
      modules: [
        { type: "ESModule", path: "fixture.js", contents: `
          import worker from './index.js';
          export default {
            // Commit webhook admission now and let the real scheduled handler drain explicitly.
            fetch(request, env) { return worker.fetch(request, env); },
            scheduled: worker.scheduled,
          };
        ` },
        { type: "ESModule", path: "index.js", contents: script.toString("utf8") },
      ],
      compatibilityDate: fixture.compatibilityDate, d1Databases: ["DB"], r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: fixture.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
      outboundService: async (request: Request) => {
        assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const { chat_id: chatId, text, reply_parameters: { message_id: replyTo } } = await request.json() as {
          chat_id: string; text: string; reply_parameters: { message_id: number };
        };
        sent.push({ chatId, replyTo, text });
        return Response.json({ ok: true, result: { message_id: 1000 + replyTo, chat: { id: Number(chatId) } } });
      },
    });
    t.after(() => runtime.dispose());
    const db = await runtime.getD1Database("DB");
    await applyMigrations(db, directory, fixture.migrations);
    const worker = await runtime.getWorker();
    const date = Math.floor(Date.now() / 1000) - 10;
    const authRow = () => db.prepare(`SELECT allowed, message_date AS date, message_id AS messageId
      FROM telegram_auth WHERE bot_id=? AND user_id=?`).bind(policy.botId, policy.memberId).first();
    const outbox = () => db.prepare(`SELECT inbox.update_id AS updateId, reply.state
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
      WHERE inbox.bot_id=? ORDER BY inbox.receipt_id`).bind(policy.botId).all();
    const reply = (replyTo: number, text: string, chatId = policy.adminId) => ({ chatId, replyTo, text });
    const drain = async (expected: typeof sent) => {
      assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
      assert.deepEqual(sent.splice(0), expected);
      assert.ok((await outbox()).results.every(({ state }) => state === "sent"));
    };
    const post = async (updateId: number, messageDate: number, args: string, actorId = policy.adminId, group = false) => {
      const command = group ? `/auth@${policy.botUsername}` : "/auth";
      const response = await runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
        body: JSON.stringify({ update_id: updateId, message: {
          message_id: 100 + updateId, date: messageDate, text: `${command} ${args}`,
          from: { id: Number(actorId), is_bot: false }, chat: { id: Number(group ? policy.groupId : actorId), type: group ? "group" : "private" },
          entities: [{ type: "bot_command", offset: 0, length: command.length }],
        } }),
      });
      assert.equal(response.status, 200);
    };
    const grant = `add ${policy.memberId}`;
    const revoke = `remove ${policy.memberId}`;
    const superseded = "收到更新的授权操作。请用 /auth list 查看当前状态。";
    const unconfirmed = "无法核对这次授权操作。请用 /auth list 查看当前状态。";

    await post(1, date, revoke);
    assert.deepEqual(await authRow(), { allowed: 0, date, messageId: 101 });
    await post(3, date, grant);
    const regranted = { allowed: 1, date, messageId: 103 };
    assert.deepEqual(await authRow(), regranted);
    assert.equal(sent.length, 0);
    assert.deepEqual((await outbox()).results, [{ updateId: 1, state: "pending" }, { updateId: 3, state: "pending" }]);
    await drain([reply(101, superseded), reply(103, `用户 ${policy.memberId}：已授权。`)]);

    await post(1, date, revoke); // Same update delivered again after the regrant.
    await post(2, date, revoke); // Older Telegram message first reaches this Worker after the regrant.
    assert.deepEqual(await authRow(), regranted);
    await drain([reply(102, superseded)]);
    assert.deepEqual((await outbox()).results.map(({ updateId }) => updateId), [1, 3, 2]);

    await post(4, date + 1, revoke);
    await drain([reply(104, `用户 ${policy.memberId}：已撤权。`)]);
    await post(5, date + 1, grant);
    const latest = { allowed: 1, date: date + 1, messageId: 105 };
    await drain([reply(105, `用户 ${policy.memberId}：已授权。`)]);

    await post(6, date + 2, "list");
    await drain([reply(106, `管理员 ${policy.adminId}\n用户 ${policy.memberId}：已授权`)]);
    await post(7, date + 2, revoke, policy.memberId);
    await drain([reply(107, "只有管理员可以管理授权。", policy.memberId)]);
    await post(8, date + 2, revoke, policy.adminId, true);
    await drain([reply(108, "请在私聊中管理授权。", policy.groupId)]);
    assert.deepEqual(await authRow(), latest);

    // Inject readback states that a normally committed admin operation cannot produce.
    await post(9, date + 3, grant);
    await db.prepare("DELETE FROM telegram_auth WHERE bot_id=? AND user_id=?").bind(policy.botId, policy.memberId).run();
    await drain([reply(109, unconfirmed)]);
    await post(10, date + 4, grant);
    await db.prepare("UPDATE telegram_auth SET message_date=?,message_id=? WHERE bot_id=? AND user_id=?")
      .bind(date + 3, 109, policy.botId, policy.memberId).run();
    await drain([reply(110, unconfirmed)]);
    await post(11, date + 5, revoke);
    await db.prepare("UPDATE telegram_auth SET allowed=1 WHERE bot_id=? AND user_id=?").bind(policy.botId, policy.memberId).run();
    await drain([reply(111, unconfirmed)]);
  });

test("emitted Sing-box guards raw HTTP request fields", { timeout: 60_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  const runtime = new Miniflare({ modules: true, script, compatibilityDate: fixture.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: fixture.revision },
    outboundService: () => { throw new Error("HTTP field fixture attempted network access."); } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const bucket = await runtime.getR2Bucket("NODES");
  await applyMigrations(db, directory, fixture.migrations);

  const node = { type: "vmess", server: "203.0.113.41", server_port: 443, alter_id: 0,
    uuid: "12345678-1234-4234-8234-123456789012", security: "aes-128-gcm" };
  const http1 = { ...node, name: "Synthetic HTTP1", transport: { type: "http", method: "PUT",
    host: ["front.example.invalid:8443", "[2001:db8::41]:8443"], path: "/escaped%2Fpath",
    headers: { "X-Fixture": ["one", "two"] } } };
  const http2 = { ...node, name: "Synthetic HTTP2", tls: { enabled: true, server_name: "tls.example.invalid" },
    transport: { type: "http", method: "", path: "", headers: { "Accept-Encoding": "identity" } } };
  const ownerId = "94073";
  const publish = async (nodes: Array<Record<string, unknown>>) => {
    const sub = await createSubscription(db, { ownerId, name: "HTTP request fields", sourceUrl: "https://provider.example.invalid/synthetic" });
    assert.equal(await publishNodeSnapshot(db, bucket, { id: sub.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 }, nodes), true);
    return `https://fixture.invalid/sub/${sub.token}/singbox`;
  };

  const headers = { "Accept-Encoding": "identity" };
  const valid = await runtime.dispatchFetch(await publish([http1, http2]), { headers });
  assert.equal(valid.status, 200);
  const body = Buffer.from(await valid.arrayBuffer());
  assert.deepEqual(JSON.parse(body.toString()).outbounds.slice(2), [http1, http2].map(({ name, ...fields }) => ({ tag: name, ...fields })));
  const binary = process.env.SINGBOX_TEST_BINARY;
  assert.ok(binary);
  const scratch = await mkdtemp(join(tmpdir(), "subs-bot-singbox-http-"));
  t.after(() => rm(scratch, { recursive: true, force: true }));
  const config = join(scratch, "synthetic.json");
  await writeFile(config, body, { mode: 0o600 });
  const check = spawnSync(binary, ["check", "-c", config], { stdio: "ignore", timeout: 15_000 });
  assert.equal(check.status, 0, "Pinned Sing-box must accept the safe HTTP transport fields.");

  for (const [label, options] of Object.entries({
    method: { method: "GET\r\nX-Fixture: marker" },
    "method-space": { method: "GET /" },
    host: { host: ["front.example.invalid", "front.example.invalid\r\nX-Fixture: marker"] },
    path: { path: "/fixture\r\nX-Fixture: marker" },
    header: { headers: { "X-Fixture": "one\r\nX-Extra: marker" } },
    "duplicate-host": { headers: { Host: "front.example.invalid", host: "other.example.invalid" } },
    "multi-value-host": { headers: { Host: ["front.example.invalid", "other.example.invalid"] } },
    "content-length": { headers: { "Content-Length": "0" } },
    "transfer-encoding": { headers: { "Transfer-Encoding": "chunked" } },
  })) {
    await t.test(label, async () => {
      const url = await publish([http1, { ...node, name: "Synthetic refused", transport: { type: "http", ...options } }]);
      for (const method of ["GET", "HEAD"]) {
        const response = await runtime.dispatchFetch(url, { method, headers });
        assert.equal(response.status, 422);
        assert.equal(await response.text(), method === "GET" ? "Subscription content cannot be exported." : "");
      }
    });
  }
});

test("emitted Worker serves only marked active legacy empty subscriptions", { timeout: 60_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(digest(script), fixture.bundleSha256);
  const migration = fixture.migrations[25];
  assert.equal(migration?.name, "0026_legacy_empty_subscription_exports.sql");
  const runtime = new Miniflare({ modules: true, script: script.toString("utf8"),
    compatibilityDate: fixture.compatibilityDate, d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: fixture.revision } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const bucket = await runtime.getR2Bucket("NODES");
  await applyMigrations(db, directory, fixture.migrations.slice(0, 25));

  const ownerId = "94071";
  const sourceUrl = "https://provider.example.invalid/empty-legacy-fixture";
  const legacy = await createSubscription(db, { ownerId, name: "Legacy empty", sourceUrl });
  const shell = await createSubscription(db, { ownerId, name: "Provider shell", sourceUrl });
  const read = (suffix: string, method = "GET", token = legacy.token) =>
    runtime.dispatchFetch(`https://fixture.invalid/sub/${token}${suffix}`, { method });
  const checkPrivate = (response: Response) => {
    assert.equal(response.headers.get("Cache-Control"), "private, no-store");
    assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
    assert.equal(response.headers.get("X-Content-Type-Options"), "nosniff");
  };
  const unavailable = async (token = legacy.token) => {
    for (const method of ["GET", "HEAD"]) {
      const response = await read("/base64", method, token);
      assert.equal(response.status, 404);
      checkPrivate(response);
      assert.equal(await response.text(), method === "HEAD" ? "" : "Not found.");
    }
  };
  await unavailable();
  await applyMigrations(db, directory, [migration]);
  const tokenSha = digest(Buffer.from(legacy.token));
  await db.prepare("INSERT INTO legacy_empty_subscription_exports VALUES (?, ?, ?)")
    .bind(legacy.id, ownerId, tokenSha).run();
  await unavailable();
  // The emitted artifact test applies SQL directly. The protected release supplies the actual ledger.
  await db.batch([
    db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER PRIMARY KEY, name TEXT, sha256 TEXT, mode TEXT) STRICT"),
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (26, ?, ?, 'applied')").bind(migration.name, "0".repeat(64)),
  ]);
  await unavailable();
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256 = ? WHERE position = 26").bind(migration.sha256).run();
  const setMarkerId = (id: number) => db.prepare("UPDATE legacy_empty_subscription_exports SET subscription_id = ? WHERE token_sha256 = ?")
    .bind(id, tokenSha).run();
  await setMarkerId(legacy.id + 1000);
  await unavailable();
  await setMarkerId(legacy.id);
  const setMarker = (markerOwner: string, markerDigest: string) => db.prepare(
    "UPDATE legacy_empty_subscription_exports SET owner_id = ?, token_sha256 = ? WHERE subscription_id = ?",
  ).bind(markerOwner, markerDigest, legacy.id).run();
  await setMarker("94072", tokenSha);
  await unavailable();
  await setMarker(ownerId, digest(Buffer.from(shell.token)));
  await unavailable();
  await unavailable(shell.token);
  await setMarker(ownerId, tokenSha);
  await unavailable("wrong-legacy-empty-token");
  await unavailable(shell.token);

  const clash = { proxies: [], "proxy-groups": [
    { name: "🚀 节点选择", type: "select", proxies: ["DIRECT"] },
    { name: "♻️ 自动选择", type: "url-test", proxies: ["DIRECT"], url: "http://www.gstatic.com/generate_204", interval: 300 },
  ], rules: ["MATCH,🚀 节点选择"] };
  const singbox = { outbounds: [
    { type: "selector", tag: "proxy", outbounds: ["direct"] }, { type: "direct", tag: "direct" },
  ] };
  for (const suffix of ["", "/clash", "/base64", "/v2ray", "/mixed", "/singbox", "/sing-box",
    "/surge", "/qx", "/quantumult", "/quantumultx"]) {
    const response = await read(suffix);
    const head = await read(suffix, "HEAD");
    const type = !suffix || suffix === "/clash" ? "text/yaml; charset=utf-8"
      : suffix.startsWith("/sing") ? "application/json" : "text/plain; charset=utf-8";
    for (const result of [response, head]) {
      assert.equal(result.status, 200);
      assert.equal(result.headers.get("Content-Type"), type);
      checkPrivate(result);
    }
    assert.equal(await head.text(), "");
    const body = await response.text();
    if (type.startsWith("text/yaml")) assert.deepEqual(parseYaml(body), clash);
    else if (type === "application/json") assert.deepEqual(JSON.parse(body), singbox);
    else assert.equal(body, suffix === "/surge" ? "[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n" : "");
  }
  assert.equal((await read("/unsupported")).status, 406);
  assert.equal((await bucket.list()).objects.length, 0);
  const target = { id: legacy.id, ownerId, expectedLifecycleRevision: 0 };
  assert.equal(await trashOwnedSubscription(db, target), true);
  await unavailable();
  assert.equal(await restoreOwnedSubscription(db, { ...target, expectedLifecycleRevision: 1 }), true);

  const journal = fixture.migrations.find(({ name }: { name: string }) => name === "0033_provider_snapshot_journal.sql");
  assert.ok(journal);
  await applyMigrations(db, directory, [journal]);
  const stored = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#legacy-refresh";
  const refresh = async (key: string, text: string) => {
    const admission = await enqueueOwnedProviderRefresh(db, { id: legacy.id, ownerId, requestKey: key.repeat(64) });
    assert.equal(admission.kind, "queued");
    const body = new TextEncoder().encode(text).buffer;
    return runOneProviderJob(db, bucket, {
      async fetchSubscription() { return { ok: true, body, bodySha256: digest(Buffer.from(body)) }; },
    }, { providerRevision: "c".repeat(40), imageSha256: "d".repeat(64) });
  };
  assert.equal(await refresh("a", " \n"), "done");
  const stillEmpty = await read("/base64");
  assert.equal(stillEmpty.status, 200);
  assert.equal(await stillEmpty.text(), "");
  assert.equal((await getOwnedSubscription(db, ownerId, legacy.id))?.generation, 0);
  assert.equal(await refresh("b", stored), "saved");
  const published = await read("/base64");
  assert.equal(published.status, 200);
  assert.equal(await published.text(), Buffer.from(stored).toString("base64"));
  const manifest = (await bucket.list({ prefix: `subscriptions/${legacy.id}/` })).objects.find(({ key }) => key.endsWith("/manifest.json"));
  assert.ok(manifest);
  await bucket.delete(manifest.key);
  const corrupted = await read("/base64");
  assert.equal(corrupted.status, 503);
  assert.equal(await corrupted.text(), "Subscription temporarily unavailable.");
  checkPrivate(corrupted);
});

test("the hosted deployment artifact exports small and large snapshots in workerd", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert(directory, "Missing hosted artifact directory");
  const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const bundle = await readFile(join(directory, "index.js"));
  assert.equal(digest(bundle), fixture.bundleSha256);
  assert.equal(fixture.version, 2);
  assert.equal(fixture.ref, process.env.GITHUB_REF);
  assert.equal(fixture.runId, process.env.GITHUB_RUN_ID);
  assert.equal(fixture.runAttempt, process.env.GITHUB_RUN_ATTEMPT);
  assert.equal(fixture.migrations[0].name, "0001_subscriptions.sql");

  const miniflare = new Miniflare({
    modules: true,
    script: bundle.toString("utf8"),
    compatibilityDate: fixture.compatibilityDate,
    bindings: { BUILD_REVISION: fixture.revision },
    d1Databases: ["DB"],
    r2Buckets: ["NODES"],
  });
  try {
    const db = await miniflare.getD1Database("DB");
    const bucket = await miniflare.getR2Bucket("NODES");
    await applyMigrations(db, directory, fixture.migrations);

    for (const snapshot of fixture.snapshots) {
      for (const item of snapshot.objects) {
        const body = await readFile(join(directory, item.file));
        assert.equal(body.byteLength, item.bytes);
        assert.equal(digest(body), item.sha256);
        await bucket.put(item.key, body);
      }
      await db.prepare(`
        INSERT INTO subscriptions
          (id, owner_id, name, source_url, token, created_at, updated_at,
           generation, snapshot_id, manifest_sha256, node_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
      `).bind(
        snapshot.id, "900000001", "Synthetic snapshot", "https://provider.example.invalid/synthetic",
        snapshot.token, 1785456000, 1785456000, snapshot.snapshotId, snapshot.manifestSha256, snapshot.nodeCount,
      ).run();
    }

    const request = (path: string, init?: RequestInit) => miniflare.dispatchFetch("https://subs-bot.example" + path, init);
    await verifyIsolation(fixture, process.env.BUILD_REVISION, request);

    const snapshot = fixture.snapshots[0];
    const path = `/sub/${snapshot.token}/base64`;
    const target = { id: snapshot.id, ownerId: "900000001", expectedLifecycleRevision: 0 };
    const original = await request(path);
    assert.equal(original.status, 200);
    const originalDigest = digest(Buffer.from(await original.arrayBuffer()));
    assert.equal(await trashOwnedSubscription(db, target), true);
    for (const method of ["GET", "HEAD"]) {
      const hidden = await request(path, { method });
      assert.equal(hidden.status, 404);
      assert.equal(hidden.headers.get("cache-control"), "private, no-store");
    }
    assert.equal(await restoreOwnedSubscription(db, { ...target, expectedLifecycleRevision: 1 }), true);
    const restored = await request(path);
    assert.equal(restored.status, 200);
    assert.equal(digest(Buffer.from(await restored.arrayBuffer())), originalDigest);

    const mappedOwner = "900000041";
    const mapped = await createSubscription(db, {
      ownerId: mappedOwner, name: "Synthetic mapped export", sourceUrl: "uploaded://mapped-fixture",
    });
    const mappedShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Stored";
    assert.equal(await publishNodeSnapshot(db, bucket, {
      id: mapped.id, ownerId: mappedOwner, expectedGeneration: 0, expectedLifecycleRevision: 0,
    }, [{ type: "ss", name: "Straße", share: mappedShare }]), true);
    await db.prepare("INSERT INTO path_rules (owner_id, keyword, remark) VALUES (?, ?, ?)")
      .bind(mappedOwner, "STRASSE", "fixture").run();
    const mappedPath = `/sub/${mapped.token}`;
    const mappedHead = await request(mappedPath, { method: "HEAD" });
    assert.equal(mappedHead.status, 200);
    assert.equal(mappedHead.body, null);
    const mappedClash = await request(mappedPath);
    assert.equal(mappedClash.status, 200);
    assert.match(await mappedClash.text(), /"name":"Straße → fixture"/u);
    const mappedBase64 = await request(mappedPath + "/base64");
    assert.equal(mappedBase64.status, 200);
    assert.equal(Buffer.from(await mappedBase64.text(), "base64").toString("utf8"), mappedShare);

    const vmessEnvelope = JSON.stringify({ add: "proxy.example.invalid", port: 443, id: "synthetic-client" });
    const vmess = "vmess://" + Buffer.from(vmessEnvelope, "utf16le").toString("base64");
    const idna = "vless://synthetic-client@bücher.example:443#Früh 😀";
    const hopping = "hy2://fixture@[2001:db8::5]:443,8443-8445/?ech=AAT-DQAA#港";
    const invalidEch = "hy2://fixture@proxy.example.invalid?ech=%2Fpath%2Fto%2Fsynthetic-fixture";
    const sip002 = "ss://aes-256-gcm:fixture@proxy.example.invalid:8388/?plugin=v2ray-plugin%3Btls%3Bhost%3Dtls.example.invalid#港";
    const unsafeInner = "aes-256-gcm:fixture@proxy.example.invalid:8388/?plugin=%2Fpath%2Fsynthetic-program#@shadow.example.invalid:8388";
    const unsafePlugin = "ss://" + Buffer.from(unsafeInner).toString("base64url");
    const structured = { type: "ss", name: "港 字", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture-only" };
    const generated = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#%E6%B8%AF%20%E5%AD%97";
    const valid = [vmess, idna, hopping, sip002];
    for (const { nodes, expectedShares, status } of [
      { nodes: [...valid.map((share) => ({ share })), structured], expectedShares: [...valid, generated], status: 200 },
      { nodes: [{ share: vmess }, { share: invalidEch }], expectedShares: [], status: 422 },
      { nodes: [{ share: vmess }, { share: unsafePlugin }], expectedShares: [], status: 422 },
      { nodes: [{ share: vmess }, { ...structured, share: "ss://malformed-fixture" }], expectedShares: [], status: 422 },
      { nodes: [{ share: vmess }, { ...structured, unsupported: true }], expectedShares: [], status: 422 },
    ]) {
      const ownerId = "900000003";
      const subscription = await createSubscription(db, {
        ownerId, name: "Stored share validation", sourceUrl: "https://provider.example.invalid/synthetic",
      });
      const publication = { id: subscription.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 };
      assert.equal(await publishNodeSnapshot(db, bucket, publication, nodes), true);
      const exportResult = await request(`/sub/${subscription.token}/base64`);
      assert.equal(exportResult.status, status);
      const expected = status === 200
        ? Buffer.from(expectedShares.join("\n")).toString("base64") : "Subscription content cannot be exported.";
      assert.equal(await exportResult.text(), expected);
    }

    const corpus = JSON.parse(await readFile(new URL("./singbox-corpus.json", import.meta.url), "utf8"));
    const ownerId = "900000004";
    const subscription = await createSubscription(db, {
      ownerId, name: "Synthetic Sing-box configuration", sourceUrl: "https://provider.example.invalid/synthetic",
    });
    const nodes = corpus.map(({ node, vmess }: { node: Record<string, unknown>; vmess?: Record<string, unknown> }) =>
      vmess ? { ...node, share: "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64") } : node);
    assert.equal(await publishNodeSnapshot(db, bucket, {
      id: subscription.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0,
    }, nodes), true);
    const singboxPath = "/sub/" + subscription.token + "/sing-box";
    // Match the isolation smoke probe: dynamic compression may omit Content-Length.
    const headers = { "Accept-Encoding": "identity" };
    const head = await request(singboxPath, { method: "HEAD", headers });
    assert.equal(head.status, 200);
    assert.equal(head.body, null);
    const response = await request(singboxPath, { headers });
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("content-type"), "application/json");
    assert.equal(response.headers.get("cache-control"), "private, no-store");
    const emitted = Buffer.from(await response.arrayBuffer());
    assert.equal(response.headers.get("content-length"), String(emitted.length));
    const { outbounds } = JSON.parse(emitted.toString("utf8"));
    const tags = ['港 "字" 🌐', "proxy (2)", "VMess", "VMess (3)", "VMess (2)", "Reality", "direct (2)",
      "Hysteria", "港", "TUIC", "AnyTLS", "SOCKS", "HTTPS", "Hysteria peer", "Gecko"];
    assert.deepEqual(outbounds, [
      { type: "selector", tag: "proxy", outbounds: tags }, { type: "direct", tag: "direct" },
      ...corpus.map(({ outbound }: { outbound: Record<string, unknown> }, index: number) => ({
        tag: tags[index], ...outbound,
      })),
    ]);
    const binary = process.env.SINGBOX_TEST_BINARY;
    assert(binary, "Missing checksum-verified Sing-box binary");
    const scratch = await mkdtemp(join(tmpdir(), "subs-bot-singbox-"));
    try {
      const config = join(scratch, "synthetic.json");
      await writeFile(config, emitted, { mode: 0o600 });
      const check = spawnSync(binary, ["check", "-c", config], { timeout: 15_000, encoding: "utf8" });
      assert.equal(check.status, 0, check.stderr || check.error?.message || "Sing-box config check failed");
    } finally {
      await rm(scratch, { recursive: true, force: true });
    }

    const clashCorpus = JSON.parse(await readFile(new URL("./clash-corpus.json", import.meta.url), "utf8"));
    const clashSub = await createSubscription(db, {
      ownerId, name: "Synthetic Clash configuration", sourceUrl: "https://provider.example.invalid/synthetic",
    });
    const clashNodes = clashCorpus.map(({ node, vmess }: { node: Record<string, unknown>; vmess?: Record<string, unknown> }) =>
      vmess ? { ...node, share: "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64") } : node);
    assert.equal(await publishNodeSnapshot(db, bucket, {
      id: clashSub.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0,
    }, clashNodes), true);
    const defaultPath = "/sub/" + clashSub.token;
    const explicitPath = defaultPath + "/Clash";
    const defaultHead = await request(defaultPath, { method: "HEAD", headers });
    assert.equal(defaultHead.status, 200);
    assert.equal(defaultHead.body, null);
    const defaultExport = await request(defaultPath, { headers });
    const explicitExport = await request(explicitPath, { headers });
    for (const variant of [defaultExport, explicitExport]) {
      assert.equal(variant.status, 200);
      assert.equal(variant.headers.get("content-type"), "text/yaml; charset=utf-8");
      assert.equal(variant.headers.get("cache-control"), "private, no-store");
    }
    const clashBytes = Buffer.from(await defaultExport.arrayBuffer());
    assert.equal(defaultExport.headers.get("content-length"), String(clashBytes.length));
    assert.equal(explicitExport.headers.get("content-length"), String(clashBytes.length));
    assert.deepEqual(Buffer.from(await explicitExport.arrayBuffer()), clashBytes);
    const [proxies, groups, rules] = clashBytes.toString("utf8").split(/(?:proxy-groups|rules):\n/u);
    const entries = (value: string) => value.split("\n").filter((line) => line.startsWith("  - "))
      .map((line) => JSON.parse(line.slice(4)));
    const names = ['港 "字" 🌐', "DIRECT (2)", "VMess", "VMess (3)", "VMess (2)", "GLOBAL (2)", "Trojan",
      "Hysteria", "🚀 节点选择 (2)", "港", "TUIC", "AnyTLS", "SOCKS", "HTTPS", "Gecko"];
    assert(proxies.startsWith("proxies:\n"));
    assert.deepEqual(entries(proxies), clashCorpus.map(({ proxy }: { proxy: Record<string, unknown> }, index: number) => ({
      name: names[index], ...proxy,
    })));
    assert.deepEqual(entries(groups), [
      { name: "🚀 节点选择", type: "select", proxies: names },
      { name: "♻️ 自动选择", type: "url-test", proxies: names, url: "http://www.gstatic.com/generate_204", interval: 300 },
    ]);
    assert.deepEqual(entries(rules), ["MATCH,🚀 节点选择"]);

    const mihomo = process.env.MIHOMO_TEST_BINARY;
    assert(mihomo, "Missing checksum-verified Mihomo binary");
    const clashScratch = await mkdtemp(join(tmpdir(), "subs-bot-mihomo-"));
    try {
      const config = join(clashScratch, "synthetic.yaml");
      await writeFile(config, clashBytes, { mode: 0o600 });
      const check = spawnSync(mihomo, ["-t", "-d", clashScratch, "-f", config], {
        timeout: 15_000, encoding: "utf8", env: { HOME: clashScratch },
      });
      assert.equal(check.status, 0, check.stderr || check.stdout || check.error?.message || "Mihomo config check failed");
    } finally {
      await rm(clashScratch, { recursive: true, force: true });
    }

    type TextFixture = {
      node: Record<string, unknown>; vmess?: Record<string, unknown>; surge: string | null; qx: string | null;
    };
    const textCorpus: TextFixture[] = JSON.parse(await readFile(new URL("./text-export-corpus.json", import.meta.url), "utf8"));
    for (const format of ["surge", "qx"] as const) {
      const sub = await createSubscription(db, {
        ownerId, name: "Synthetic text export", sourceUrl: "https://provider.example.invalid/synthetic",
      });
      const selected = textCorpus.filter((item) => item[format] !== null);
      const nodes = selected.map(({ node, vmess }) => vmess
        ? { ...node, share: "vmess://" + Buffer.from(JSON.stringify(vmess)).toString("base64") } : node);
      assert.equal(await publishNodeSnapshot(db, bucket, {
        id: sub.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0,
      }, nodes), true);
      const expected = selected.map((item) => item[format]).join("\n") + "\n";
      const body = format === "surge"
        ? "[Proxy]\n" + expected + "\n[Proxy Group]\nProxy = select, " + selected.map((item) => item.node.name).join(", ")
          + "\n\n[Rule]\nFINAL,Proxy\n"
        : expected;
      for (const suffix of format === "surge" ? ["surge"] : ["qx", "quantumult", "quantumultx"]) {
        const path = "/sub/" + sub.token + "/" + suffix;
        const response = await request(path, { headers });
        assert.equal(response.status, 200);
        assert.equal(response.headers.get("content-type"), "text/plain; charset=utf-8");
        assert.equal(response.headers.get("cache-control"), "private, no-store");
        assert.equal(response.headers.get("content-length"), String(Buffer.byteLength(body)));
        assert.deepEqual(Buffer.from(await response.arrayBuffer()), Buffer.from(body));
        const head = await request(path, { method: "HEAD", headers });
        assert.equal(head.status, 200);
        assert.equal(head.body, null);
      }
    }
  } finally {
    await miniflare.dispose();
  }
});

test("the deployed bundle admits webhook replays once and recovers a queued reply on its scheduled handler", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert(directory, "Missing hosted artifact directory");
  const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const bundle = await readFile(join(directory, "index.js"));
  assert.equal(digest(bundle), fixture.bundleSha256);
  const policy: TelegramPolicy = {
    botId: "123456789", botUsername: "fixture_subs_bot", adminId: "1001", memberId: "1002", groupId: "-1003",
    botToken: `123456789:${"a".repeat(35)}`, webhookSecret: "fixture-webhook-secret-00000000000000",
  };
  const replies: Array<{ chatId: string; messageId: number; replyTo: number; text: string; button?: string; actions?: number;
    menu?: string[][] }> = [];
  const sentBodies: unknown[] = [];
  const outboundErrors: unknown[] = [];
  const callbackId = "fixture-page-callback";
  let acknowledged = 0;
  let nextTicket: string | undefined;
  let renameTicket: string | undefined;
  const botPath = `/bot${policy.botToken}/sendMessage`;
  const miniflare = new Miniflare({
    modules: true,
    script: bundle.toString("utf8"),
    compatibilityDate: fixture.compatibilityDate,
    bindings: { BUILD_REVISION: fixture.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
      TELEGRAM_AGGREGATE_KEY: Buffer.alloc(32, 0x19).toString("base64url") },
    d1Databases: ["DB"],
    r2Buckets: ["NODES"],
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      if (request.url === `https://api.telegram.org/bot${policy.botToken}/answerCallbackQuery`) {
        assert.deepEqual(await request.json(), { callback_query_id: callbackId });
        acknowledged += 1;
        return Response.json({ ok: true, result: true });
      }
      assert.equal(request.url, `https://api.telegram.org${botPath}`);
      const expected = replies.shift();
      assert.ok(expected, "Unexpected outbound request");
      const payload = await request.json() as {
        chat_id: string;
        text: string;
        reply_parameters: { message_id: number };
        reply_markup?: { inline_keyboard?: Array<Array<{ text: string; callback_data: string }>> };
      };
      const observed = { chatId: payload.chat_id, text: payload.text, replyTo: payload.reply_parameters?.message_id };
      sentBodies.push(observed);
      try { assert.deepEqual(observed, { chatId: expected.chatId, text: expected.text, replyTo: expected.replyTo }); }
      catch (error) { outboundErrors.push(error); throw error; }
      if (expected.menu) {
        assert.deepEqual(payload.reply_markup, {
          keyboard: expected.menu.map((row) => row.map((text) => ({ text }))), resize_keyboard: true,
        });
      } else if (expected.button) {
        const [button, ...actions] = payload.reply_markup?.inline_keyboard?.flat() ?? [];
        assert.ok(button);
        assert.equal(button.text, expected.button);
        assert.match(button.callback_data, /^sbv1_[A-Za-z0-9_-]{22}$/u);
        if (button.text === "下一页") nextTicket = button.callback_data;
        const expectedLabels = Array.from({ length: expected.actions ?? 0 }, (_, index) =>
          [`${index + 1} 重命名`, `${index + 1} 删除`]).flat();
        assert.deepEqual(actions.map(({ text }) => text), expectedLabels);
        for (const action of actions) assert.match(action.callback_data, /^sba1_[A-Za-z0-9_-]{22}$/u);
        renameTicket = actions[0]?.callback_data;
      } else {
        assert.equal(payload.reply_markup, undefined);
      }
      return Response.json({ ok: true, result: { message_id: expected.messageId, chat: { id: Number(expected.chatId) } } });
    },
  });
  try {
    const db = await miniflare.getD1Database("DB");
    assert.deepEqual(fixture.migrations.slice(0, 4).map(({ name }: { name: string }) => name), [
      "0001_subscriptions.sql", "0002_telegram.sql", "0003_subscription_lifecycle.sql", "0004_telegram_views.sql",
    ]);
    assert.equal(fixture.migrations[5]?.name, "0006_telegram_lifecycle.sql");
    assert.equal(fixture.migrations[6]?.name, "0007_telegram_private_claims.sql");
    assert.equal(fixture.migrations[7]?.name, "0008_telegram_temp_nodes.sql");
    await applyMigrations(db, directory, fixture.migrations.slice(0, 2));
    const url = "https://provider.example.invalid/synthetic";
    await db.prepare(`
      INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at)
      VALUES (?, 'Member fixture', ?, 'legacy-member-fixture-token', unixepoch(), unixepoch())
    `).bind(policy.memberId, url).run();
    await db.prepare(`
      INSERT INTO telegram_auth (bot_id, user_id, allowed, message_date, message_id)
      VALUES (?, ?, 1, unixepoch(), 1)
    `).bind(policy.botId, policy.memberId).run();
    const date = Math.floor(Date.now() / 1000);
    const text = `/list@${policy.botUsername}`;
    const message = {
      date, text, message_id: 7, from: { id: Number(policy.memberId), is_bot: false },
      chat: { id: Number(policy.groupId), type: "group" },
      entities: [{ type: "bot_command", offset: 0, length: text.length }],
    };
    function expectSend(chatId: string, messageId: number, replyTo: number, expectedText: string, button?: string, actions?: number,
      menu?: string[][]) {
      replies.push({ chatId, messageId, replyTo, text: expectedText, button, actions, menu });
      return { chatId, text: expectedText, replyTo };
    }
    const webhook = "https://subs-bot.example/telegram/webhook";
    const post = (event: unknown, secret = policy.webhookSecret) => miniflare.dispatchFetch(webhook, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
      body: JSON.stringify(event),
    });
    await acceptTelegramCommand(db, policy, {
      updateId: 12, actorId: policy.memberId, chatId: policy.memberId, chatType: "private",
      messageId: 9, messageDate: date, threadId: null, command: "list",
    });
    const tables = ["subscriptions", "telegram_auth", "telegram_inbox", "telegram_outbox"];
    const readExistingRows = () => Promise.all(tables.map(async (table) =>
      (await db.prepare(`SELECT * FROM ${table}`).all()).results));
    const existingRows = await readExistingRows();
    await applyMigrations(db, directory, fixture.migrations.slice(2));
    assert.deepEqual(await readExistingRows(), existingRows);
    await createSubscription(db, { ownerId: policy.adminId, name: "Admin fixture", sourceUrl: url });
    const trashed = await createSubscription(db, { ownerId: policy.memberId, name: "Trashed fixture", sourceUrl: url });
    assert.equal(await trashOwnedSubscription(db, {
      id: trashed.id, ownerId: policy.memberId, expectedLifecycleRevision: 0,
    }), true);
    const expectedPrivate = expectSend(policy.memberId, 10, 9, "你的订阅\n1. Member fixture");
    const worker = await miniflare.getWorker();
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    const outbox = "SELECT state, sent_message_id FROM telegram_outbox ORDER BY receipt_id";
    assert.deepEqual((await db.prepare(outbox).all()).results, [{ state: "sent", sent_message_id: 10 }]);
    assert.deepEqual(sentBodies, [expectedPrivate]);
    for (let index = 2; index <= 9; index += 1) {
      await createSubscription(db, { ownerId: policy.memberId, name: `Member fixture ${index}`, sourceUrl: url });
    }

    assert.equal((await post({ update_id: 10, message }, "invalid")).status, 401);
    assert.equal((await post({ update_id: 10, message: { ...message, chat: { ...message.chat, id: -2000 } } })).status, 204);
    const firstPage = ["你的订阅", "1. Member fixture", ...Array.from({ length: 7 }, (_, index) =>
      `${index + 2}. Member fixture ${index + 2}`)].join("\n");
    const expectedGroup = expectSend(policy.groupId, 8, 7, firstPage, "下一页", 8);
    const update = { update_id: 11, message };
    assert.deepEqual((await Promise.all([post(update), post(update)])).map((result) => result.status), [200, 200]);

    async function waitForReplies(messageIds: number[], acknowledgements = 0) {
      for (let attempt = 0; attempt < 50; attempt += 1) {
        if (outboundErrors.length) throw outboundErrors[0];
        const rows = await db.prepare(outbox).all();
        if (rows.results.every((row) => row.state === "sent") && rows.results.length === messageIds.length &&
            acknowledged === acknowledgements) break;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.deepEqual((await db.prepare(outbox).all()).results,
        messageIds.map((id) => ({ state: "sent", sent_message_id: id })));
    }
    await waitForReplies([10, 8]);
    assert.ok(nextTicket);
    const expectedNext = expectSend(policy.groupId, 9, 8, "你的订阅\n1. Member fixture 9", "第一页", 1);
    const callback = { update_id: 13, callback_query: {
      id: callbackId, data: nextTicket, chat_instance: "synthetic-instance", from: message.from,
      message: { date, message_id: 8, chat: message.chat, from: { id: Number(policy.botId), is_bot: true } },
    } };
    assert.deepEqual((await Promise.all([post(callback), post(callback)])).map((result) => result.status), [200, 200]);
    await waitForReplies([10, 8, 9], 2);
    assert.equal(acknowledged, 2);

    assert.ok(renameTicket);
    const prompt = expectSend(policy.groupId, 18, 9, "请回复这条消息，发送新的订阅名称。发送 /cancel 取消。");
    const botMessage = { ...callback.callback_query.message, message_id: 9 };
    assert.equal((await post({ update_id: 14, callback_query: {
      ...callback.callback_query, data: renameTicket, message: botMessage,
    } })).status, 200);
    await waitForReplies([10, 8, 9, 18], 3);
    const confirmation = expectSend(policy.groupId, 20, 19, "订阅名称已更新。");
    const rename = { update_id: 15, message: {
      ...message, message_id: 19, text: "❓ 帮助菜单", entities: [],
      reply_to_message: { ...botMessage, message_id: 18 },
    } };
    assert.deepEqual((await Promise.all([post(rename), post(rename)])).map((result) => result.status), [200, 200]);
    await waitForReplies([10, 8, 9, 18, 20], 3);
    assert.deepEqual(await db.prepare(`
      SELECT owner_id, name, revision
      FROM subscriptions JOIN subscription_lifecycle ON id = subscription_id
      WHERE owner_id = ?
    `).bind(policy.memberId).first(), { owner_id: policy.memberId, name: "❓ 帮助菜单", revision: 1 });

    const bucket = await miniflare.getR2Bucket("NODES");
    const share = await createPrivateShare(db, bucket, {
      botId: policy.botId, senderId: policy.adminId, senderName: "Synthetic sender", content: "Synthetic private share",
      maxClaims: 1, targetUserId: policy.memberId, durationMinutes: 10,
    });
    await db.prepare("UPDATE telegram_auth SET allowed = 0 WHERE bot_id = ? AND user_id = ?")
      .bind(policy.botId, policy.memberId).run();
    const deepLink = `/start claim_${share.code}`;
    const claimMessage = { ...message, message_id: 21, text: deepLink,
      entities: [{ type: "bot_command", offset: 0, length: 6 }] };
    assert.equal((await post({ update_id: 16, message: claimMessage })).status, 204);
    const claimReply = expectSend(policy.memberId, 22, 21, "私密分享\n来自：Synthetic sender\n领取进度：1/1\n\nSynthetic private share");
    const privateClaim = { update_id: 17, message: { ...claimMessage, chat: { id: Number(policy.memberId), type: "private" } } };
    assert.deepEqual((await Promise.all([post(privateClaim), post(privateClaim)])).map((result) => result.status), [200, 200]);
    await waitForReplies([10, 8, 9, 18, 20, 22], 3);
    const expectedCodeDigest = digest(Buffer.from(share.code));
    const claimState = await db.prepare(`
      SELECT receipt.code_sha256 AS code, (SELECT count(*) FROM private_share_claims) AS portions
      FROM telegram_private_claim AS receipt
    `).first();
    assert.deepEqual(claimState, { code: expectedCodeDigest, portions: 1 });

    await db.prepare("UPDATE telegram_auth SET allowed = 1 WHERE bot_id = ? AND user_id = ?")
      .bind(policy.botId, policy.memberId).run();
    const importedShare = "hy2://user:fixture@[2001:db8::5]:443,5000-6000/?sni=proxy.example.invalid#Fixture";
    const grantDate = await db.prepare("SELECT message_date FROM telegram_auth WHERE bot_id = ? AND user_id = ?")
      .bind(policy.botId, policy.memberId).first<number>("message_date");
    assert.ok(grantDate !== null);
    const memberPrivate = { ...claimMessage, date: grantDate + 1,
      chat: { id: Number(policy.memberId), type: "private" } };
    const delayed = { update_id: 1800, message: { ...memberPrivate, date: grantDate, message_id: 2300,
      text: Buffer.from(importedShare).toString("base64"), entities: [] } };
    assert.equal((await post(delayed)).status, 200);
    assert.equal(await db.prepare("SELECT 1 FROM telegram_inbox WHERE bot_id = ? AND update_id = ?")
      .bind(policy.botId, delayed.update_id).first(), null);
    assert.deepEqual(await db.prepare("SELECT count(*) AS total FROM telegram_temp_batch").first(), { total: 0 });
    const tempEvent = { update_id: 18, message: { ...memberPrivate, message_id: 23,
      text: Buffer.from(importedShare).toString("base64"), entities: [] } };
    const added = expectSend(policy.memberId, 24, 23, "已加入临时列表 1 条节点，当前共有 1 条。");
    assert.deepEqual((await Promise.all([post(tempEvent), post(tempEvent)])).map((result) => result.status), [200, 200]);
    await waitForReplies([10, 8, 9, 18, 20, 22, 24], 3);
    const batch = await db.prepare("SELECT actor_id, node_count, json_extract(nodes_json,'$[0].share') AS share FROM telegram_temp_batch")
      .first();
    assert.deepEqual(batch, { actor_id: policy.memberId, node_count: 1, share: importedShare });

    const summary = expectSend(policy.adminId, 26, 25, "临时列表共有 0 条节点。发送 /temp clear 清空。");
    assert.equal((await post({ update_id: 19, message: {
      ...memberPrivate, message_id: 25, text: "/temp",
      from: { id: Number(policy.adminId), is_bot: false }, chat: { id: Number(policy.adminId), type: "private" },
      entities: [{ type: "bot_command", offset: 0, length: 5 }],
    } })).status, 200);
    await waitForReplies([10, 8, 9, 18, 20, 22, 24, 26], 3);
    const cleared = expectSend(policy.memberId, 28, 27, "已移除 1 条临时节点，当前共有 0 条。");
    assert.equal((await post({ update_id: 20, message: {
      ...memberPrivate, message_id: 27, text: "/temp clear", entities: [{ type: "bot_command", offset: 0, length: 5 }],
    } })).status, 200);
    await waitForReplies([10, 8, 9, 18, 20, 22, 24, 26, 28], 3);
    assert.deepEqual(await db.prepare("SELECT count(*) AS total FROM telegram_temp_batch").first(), { total: 0 });
    assert.deepEqual(sentBodies, [expectedPrivate, expectedGroup, expectedNext, prompt, confirmation, claimReply,
      added, summary, cleared]);
    assert.deepEqual(replies, []);

    const ruleArgs = "Straße=合成路径标签";
    const pathEvent = { update_id: 310, message: {
      ...memberPrivate, message_id: 311, date: Math.floor(Date.now() / 1000), text: `/path ${ruleArgs}`,
      from: { id: Number(policy.adminId), is_bot: false }, chat: { id: Number(policy.adminId), type: "private" },
      entities: [{ type: "bot_command", offset: 0, length: 5 }],
    } };
    assert.equal((await post({ ...pathEvent, message: { ...pathEvent.message, chat: message.chat } })).status, 204);
    const ruleSaved = expectSend(policy.adminId, 312, 311, "已保存路径规则。");
    assert.deepEqual((await Promise.all([post(pathEvent), post(pathEvent)])).map((response) => response.status), [200, 200]);
    await waitForReplies([10, 8, 9, 18, 20, 22, 24, 26, 28, 312], 3);
    const rule = await db.prepare("SELECT id, owner_id, keyword, remark FROM path_rules").first<{
      id: number; owner_id: string; keyword: string; remark: string;
    }>();
    assert.ok(rule);
    assert.deepEqual(rule, { id: rule.id, owner_id: policy.adminId, keyword: "Straße", remark: "合成路径标签" });
    const ruleList = expectSend(policy.adminId, 314, 313, `你的路径规则\n#${rule.id} Straße → 合成路径标签`);
    assert.equal((await post({ update_id: 311, message: { ...pathEvent.message, message_id: 313, text: "🧭 路径对应",
      entities: [] } })).status, 200);
    await waitForReplies([10, 8, 9, 18, 20, 22, 24, 26, 28, 312, 314], 3);
    assert.deepEqual(sentBodies.slice(-2), [ruleSaved, ruleList]);

    const ids = [10, 8, 9, 18, 20, 22, 24, 26, 28, 312, 314];
    const menu = [["📦 订阅列表", "🟠 临期列表"], ["📤 导出链接"], ["♻️ 撤销删除", "🔢 重置编号"], ["🧭 路径对应", "❓ 帮助菜单"]];
    const helpFeatures = { management: true, subscriptionRead: true, temp: true, tempRawDefault: true, path: true,
      aggregate: true, selected: true, short: true, bulkTrash: true, inlineSort: true, authorization: true, batchStatus: true,
      authorizationScope: "fixed" as const, authorizationMemberId: policy.memberId, documentImport: true };
    const publicHelp = renderTelegramHelp({ privateChat: false, role: "member", features: helpFeatures });
    const privateHelp = renderTelegramHelp({ privateChat: true, role: "member", features: helpFeatures });
    const adminHelp = renderTelegramHelp({ privateChat: true, role: "admin", features: helpFeatures });
    const adminStart = expectSend(policy.adminId, 316, 315, `欢迎使用 subs-bot。\n${adminHelp}`, undefined, undefined, menu);
    const memberHelp = expectSend(policy.memberId, 318, 317, privateHelp, undefined, undefined, menu);
    assert.equal((await post({ update_id: 312, message: { ...pathEvent.message, message_id: 315, text: "/start",
      entities: [{ type: "bot_command", offset: 0, length: 6 }] } })).status, 200);
    await waitForReplies([...ids, 316], 3);
    const helpEvent = { update_id: 313, message: { ...memberPrivate, message_id: 317, text: "/help",
      entities: [{ type: "bot_command", offset: 0, length: 5 }] } };
    assert.deepEqual((await Promise.all([post(helpEvent), post(helpEvent)])).map((result) => result.status), [200, 200]);
    await waitForReplies([...ids, 316, 318], 3);
    const groupHelp = expectSend(policy.groupId, 320, 319, publicHelp);
    assert.equal((await post({ update_id: 314, message: { ...message, message_id: 319, text: "❓ 帮助菜单", entities: [] } })).status, 200);
    await waitForReplies([...ids, 316, 318, 320], 3);
    const groupAlias = expectSend(policy.groupId, 322, 321, firstPage, "下一页", 8);
    assert.equal((await post({ update_id: 315, message: { ...message, message_id: 321, text: "📦 订阅列表", entities: [] } })).status, 200);
    await waitForReplies([...ids, 316, 318, 320, 322], 3);
    for (const [index, label] of ["📤 导出链接", "🧭 路径对应", "🔄 更新所有", "群里随便聊聊"].entries()) {
      assert.equal((await post({ update_id: 323 + index, message: { ...message, message_id: 323 + index, text: label, entities: [] } })).status, 204);
    }
    await db.prepare("UPDATE telegram_auth SET allowed = 0 WHERE bot_id = ? AND user_id = ?")
      .bind(policy.botId, policy.memberId).run();
    const denied = expectSend(policy.memberId, 328, 327, "当前账号没有使用权限。");
    assert.equal((await post({ update_id: 327, message: { ...memberPrivate, message_id: 327, text: "帮助", entities: [] } })).status, 200);
    await waitForReplies([...ids, 316, 318, 320, 322, 328], 3);
    assert.deepEqual(sentBodies.slice(-5), [adminStart, memberHelp, groupHelp, groupAlias, denied]);
    assert.deepEqual(replies, []);
  } finally {
    await miniflare.dispose();
  }
});

test("the deployed bundle imports private documents through Cron without blocking ordinary replies", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert(directory, "Missing hosted artifact directory");
  const fixture = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const bundle = await readFile(join(directory, "index.js"));
  assert.equal(digest(bundle), fixture.bundleSha256);

  const policy: TelegramPolicy = {
    botId: "123456788", botUsername: "fixture_document_bot", adminId: "1001", memberId: "1002", groupId: "-1003",
    botToken: `123456788:${"a".repeat(35)}`, webhookSecret: "fixture-document-webhook-secret",
  };
  const filename = "Synthetic private filename";
  const uri = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388";
  const oldLink = `${uri}#old`;
  const newLink = `${uri}#new`;
  const files = new Map([
    ["fixture-old", Buffer.from(`${oldLink}\n`)],
    ["fixture-bad", Buffer.from(`${newLink}\nss://wrong\n`)],
    ["fixture-new", Buffer.from(`${newLink}\n`)],
  ]);
  const fileCalls: string[] = [];
  const replies: Array<{ text: string; replyTo: number }> = [];
  const downloadStarted = Promise.withResolvers<void>();
  const releaseDownload = Promise.withResolvers<void>();
  const ordinaryReply = Promise.withResolvers<void>();
  const miniflare = new Miniflare({
    modules: true, script: bundle.toString("utf8"), compatibilityDate: fixture.compatibilityDate,
    bindings: { BUILD_REVISION: fixture.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    outboundService: async (request: Request) => {
      const url = new URL(request.url);
      assert.equal(url.origin, "https://api.telegram.org");
      assert.equal(url.search, "");
      if (url.pathname === `/bot${policy.botToken}/getFile`) {
        assert.equal(request.method, "POST");
        const { file_id: fileId } = await request.json() as { file_id: string };
        const body = files.get(fileId);
        assert.ok(body, "Unexpected file lookup");
        fileCalls.push(`lookup:${fileId}`);
        if (fileId === "fixture-old") {
          downloadStarted.resolve();
          await releaseDownload.promise;
        }
        return Response.json({ ok: true, result: { file_path: `documents/${fileId}.txt`, file_size: body.length } });
      }
      const filePath = `/file/bot${policy.botToken}/documents/`;
      if (url.pathname.startsWith(filePath)) {
        assert.equal(request.method, "GET");
        assert.ok(url.pathname.endsWith(".txt"));
        const fileId = url.pathname.slice(filePath.length, -4);
        const body = files.get(fileId);
        assert.ok(body, "Unexpected file download");
        fileCalls.push(`read:${fileId}`);
        return new Response(body, { headers: { "Content-Length": String(body.length) } });
      }
      assert.equal(url.pathname, `/bot${policy.botToken}/sendMessage`);
      assert.equal(request.method, "POST");
      const payload = await request.json() as { chat_id: string; text: string; reply_parameters: { message_id: number } };
      assert.equal(payload.chat_id, policy.memberId);
      const replyTo = payload.reply_parameters.message_id;
      replies.push({ text: payload.text, replyTo });
      if (replyTo === 21) ordinaryReply.resolve();
      else assert.doesNotMatch(payload.text, /Synthetic private filename|fixture-|203\.0\.113\.10|ss:\/\//u);
      return Response.json({ ok: true, result: { message_id: 100 + replyTo, chat: { id: Number(payload.chat_id) } } });
    },
  });
  try {
    const db = await miniflare.getD1Database("DB");
    const bucket = await miniflare.getR2Bucket("NODES");
    await applyMigrations(db, directory, fixture.migrations);
    const worker = await miniflare.getWorker();
    const date = Math.floor(Date.now() / 1_000);
    const actor = { id: Number(policy.memberId), is_bot: false };
    const chat = { id: actor.id, type: "private" };
    const post = (update: unknown, secret = policy.webhookSecret) => miniflare.dispatchFetch("https://subs-bot.example/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
      body: JSON.stringify(update),
    });
    const upload = (id: number, fileId: string, extension = "txt") => ({ update_id: id, message: {
      date, from: actor, chat, message_id: 19 + id, caption: "/auth remove ignored",
      document: { file_id: fileId, file_name: `${filename}.${extension}`, file_size: files.get(fileId)?.length ?? 0 },
    } });
    const job = (id: number) => db.prepare(`
      SELECT job.state, job.result_code, job.file_id, job.name, job.expected_size, reply.state AS reply_state
      FROM telegram_inbox AS inbox JOIN telegram_document_jobs AS job USING (receipt_id)
      LEFT JOIN telegram_outbox AS reply USING (receipt_id) WHERE inbox.bot_id = ? AND inbox.update_id = ?
    `).bind(policy.botId, id).first();
    const subscription = () => db.prepare(`
      SELECT id, token, generation, snapshot_id, source_url FROM subscriptions WHERE owner_id = ? AND name = ?
    `).bind(policy.memberId, filename).first<{ id: number; token: string; generation: number; snapshot_id: string; source_url: string }>();
    const exportBase64 = async (token: string) => {
      const response = await miniflare.dispatchFetch(`https://subs-bot.example/sub/${token}/base64`);
      assert.equal(response.status, 200);
      return await response.text();
    };
    const terminal = (result: string) => ({ state: "done", result_code: result, file_id: null, name: null,
      expected_size: null, reply_state: "sent" });

    const first = upload(1, "fixture-old");
    assert.equal((await post(first, "wrong")).status, 401);
    assert.equal((await post({ ...first, message: { ...first.message, chat: { id: Number(policy.groupId), type: "group" } } })).status, 204);
    assert.deepEqual((await Promise.all([post(first), post(first)])).map(({ status }) => status), [200, 200]);
    assert.deepEqual(await job(1), { state: "pending", result_code: null, file_id: "fixture-old", name: filename,
      expected_size: files.get("fixture-old")?.length, reply_state: null });
    assert.deepEqual(fileCalls, []);
    assert.equal(await subscription(), null);

    await acceptTelegramCommand(db, policy, { updateId: 2, actorId: policy.memberId, chatId: policy.memberId,
      chatType: "private", messageId: 21, messageDate: date, threadId: null, command: "list" });
    const tick = worker.scheduled({ cron: "* * * * *" });
    const wait = Promise.withResolvers<never>();
    const timer = setTimeout(() => wait.reject(new Error("Scheduled document blocked an ordinary reply.")), 10_000);
    try {
      await Promise.race([Promise.all([downloadStarted.promise, ordinaryReply.promise]), wait.promise,
        tick.then(() => { throw new Error("Scheduled work ended before observing both paths."); })]);
      assert.deepEqual(replies, [{ replyTo: 21, text: "你的订阅列表为空。" }]);
      assert.equal(await subscription(), null);
    } finally {
      clearTimeout(timer);
      releaseDownload.resolve();
    }
    assert.equal((await tick).outcome, "ok");
    assert.deepEqual(await job(1), terminal("saved"));
    const original = await subscription();
    assert.ok(original);
    assert.equal(original.generation, 1);
    assert.match(original.source_url, /^uploaded:\/\//u);
    assert.equal(await exportBase64(original.token), Buffer.from(oldLink).toString("base64"));

    assert.equal((await post(upload(3, "fixture-bad"))).status, 200);
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.deepEqual(await job(3), terminal("invalid-document"));
    assert.deepEqual(await subscription(), original);
    assert.equal(await exportBase64(original.token), Buffer.from(oldLink).toString("base64"));

    assert.equal((await post(upload(4, "fixture-new"))).status, 200);
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.deepEqual(await job(4), terminal("saved"));
    const replacement = await subscription();
    assert.ok(replacement);
    assert.equal(replacement.id, original.id);
    assert.equal(replacement.token, original.token);
    assert.equal(replacement.generation, 2);
    assert.notEqual(replacement.snapshot_id, original.snapshot_id);
    assert.ok(await bucket.head(`subscriptions/${original.id}/${original.snapshot_id}/manifest.json`));
    assert.equal(await exportBase64(original.token), Buffer.from(newLink).toString("base64"));

    assert.equal((await post(upload(5, "fixture-invalid-type", "exe"))).status, 200);
    const longName = upload(6, "fixture-invalid-name");
    longName.message.document.file_name = `${"x".repeat(1025)}.txt`;
    assert.equal((await post(longName)).status, 200);
    assert.equal((await post(upload(7, "fixture-new"))).status, 200);
    await db.prepare("INSERT INTO telegram_auth (bot_id, user_id, allowed, message_date, message_id) VALUES (?, ?, 0, ?, 1)")
      .bind(policy.botId, policy.memberId, date).run();
    await db.prepare("UPDATE telegram_auth SET allowed = 1, message_id = 2 WHERE bot_id = ? AND user_id = ?")
      .bind(policy.botId, policy.memberId).run();
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.deepEqual(await job(5), terminal("invalid-document"));
    assert.deepEqual(await job(6), terminal("invalid-document"));
    assert.deepEqual(await job(7), terminal("access-changed"));
    assert.deepEqual(await subscription(), replacement);
    assert.equal((await post(first)).status, 200);
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.deepEqual(fileCalls, ["lookup:fixture-old", "read:fixture-old", "lookup:fixture-bad", "read:fixture-bad",
      "lookup:fixture-new", "read:fixture-new"]);
    const saved = "文件已导入，共 1 个节点。";
    const invalid = "文件未导入。请检查文件类型、大小和节点格式。已有订阅保持原样。";
    assert.deepEqual(replies, [
      { replyTo: 21, text: "你的订阅列表为空。" }, { replyTo: 20, text: saved }, { replyTo: 22, text: invalid },
      { replyTo: 23, text: saved }, { replyTo: 24, text: invalid }, { replyTo: 25, text: invalid },
      { replyTo: 26, text: "授权状态已变更，文件未导入。" },
    ]);
  } finally {
    releaseDownload.resolve();
    await miniflare.dispose();
  }
});

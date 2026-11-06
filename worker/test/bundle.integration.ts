import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import { Miniflare } from "miniflare";

import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand } from "../src/telegram/store.ts";
import { verifyIsolation } from "../tools/verify-isolation.mjs";

const digest = (body: Buffer) => createHash("sha256").update(body).digest("hex");

async function applyMigrations(db: D1Database, directory: string, migrations: Array<{ name: string; sha256: string }>) {
  for (const { name, sha256 } of migrations) {
    const migration = await readFile(join(directory, name));
    assert.equal(digest(migration), sha256);
    const statements = migration.toString("utf8").trim().split(/;\s*/u).filter(Boolean);
    await db.batch(statements.map((statement) => db.prepare(statement)));
  }
}

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

    await verifyIsolation(fixture, process.env.BUILD_REVISION,
      (path, init) => miniflare.dispatchFetch("https://subs-bot.example" + path, init));

    const vmessEnvelope = JSON.stringify({ add: "proxy.example.invalid", port: 443, id: "synthetic-client" });
    const vmess = "vmess://" + Buffer.from(vmessEnvelope, "utf16le").toString("base64");
    const idna = "vless://synthetic-client@bücher.example:443#Früh 😀";
    const hopping = "hy2://fixture@[2001:db8::5]:443,8443-8445/?ech=AAT-DQAA#港";
    const invalidEch = "hy2://fixture@proxy.example.invalid?ech=%2Fpath%2Fto%2Fsynthetic-fixture";
    for (const { links, status } of [
      { links: [vmess, idna, hopping], status: 200 },
      { links: [vmess, invalidEch], status: 422 },
    ]) {
      const ownerId = "900000003";
      const subscription = await createSubscription(db, {
        ownerId, name: "Stored share validation", sourceUrl: "https://provider.example.invalid/synthetic",
      });
      const publication = { id: subscription.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 };
      assert.equal(await publishNodeSnapshot(db, bucket, publication, links.map((share) => ({ share }))), true);
      const exportResult = await miniflare.dispatchFetch("https://subs-bot.example/sub/" + subscription.token + "/base64");
      assert.equal(exportResult.status, status);
      const expected = status === 200
        ? Buffer.from(links.join("\n")).toString("base64") : "Subscription content cannot be exported.";
      assert.equal(await exportResult.text(), expected);
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
  const replies: Array<{ chatId: string; messageId: number; replyTo: number; text: string }> = [];
  const sentBodies: unknown[] = [];
  const botPath = `/bot${policy.botToken}/sendMessage`;
  const miniflare = new Miniflare({
    modules: true,
    script: bundle.toString("utf8"),
    compatibilityDate: fixture.compatibilityDate,
    bindings: { BUILD_REVISION: fixture.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    d1Databases: ["DB"],
    r2Buckets: ["NODES"],
    outboundService: async (request: Request) => {
      assert.equal(request.url, `https://api.telegram.org${botPath}`);
      assert.equal(request.method, "POST");
      const expected = replies.shift();
      assert.ok(expected, "Unexpected outbound request");
      const payload = await request.json() as { chat_id: string; text: string; reply_parameters: { message_id: number } };
      const observed = { chatId: payload.chat_id, text: payload.text, replyTo: payload.reply_parameters?.message_id };
      sentBodies.push(observed);
      assert.deepEqual(observed, { chatId: expected.chatId, text: expected.text, replyTo: expected.replyTo });
      return Response.json({ ok: true, result: { message_id: expected.messageId, chat: { id: Number(expected.chatId) } } });
    },
  });
  try {
    const db = await miniflare.getD1Database("DB");
    await applyMigrations(db, directory, fixture.migrations);
    const url = "https://provider.example.invalid/synthetic";
    await createSubscription(db, { ownerId: policy.adminId, name: "Admin fixture", sourceUrl: url });
    await createSubscription(db, { ownerId: policy.memberId, name: "Member fixture", sourceUrl: url });
    const date = Math.floor(Date.now() / 1000);
    const text = `/list@${policy.botUsername}`;
    const message = {
      date, text, message_id: 7, from: { id: Number(policy.memberId), is_bot: false },
      chat: { id: Number(policy.groupId), type: "group" },
      entities: [{ type: "bot_command", offset: 0, length: text.length }],
    };
    function expectSend(chatId: string, messageId: number, replyTo: number, expectedText: string) {
      replies.push({ chatId, messageId, replyTo, text: expectedText });
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
    const expectedPrivate = expectSend(policy.memberId, 10, 9, "你的订阅\n1. Member fixture");
    const worker = await miniflare.getWorker();
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    const outbox = "SELECT state, sent_message_id FROM telegram_outbox ORDER BY receipt_id";
    assert.deepEqual((await db.prepare(outbox).all()).results, [{ state: "sent", sent_message_id: 10 }]);
    assert.deepEqual(sentBodies, [expectedPrivate]);

    assert.equal((await post({ update_id: 10, message }, "invalid")).status, 401);
    assert.equal((await post({ update_id: 10, message: { ...message, chat: { ...message.chat, id: -2000 } } })).status, 204);
    const expectedGroup = expectSend(policy.groupId, 8, 7, "你的订阅\n1. Member fixture");
    const update = { update_id: 11, message };
    assert.deepEqual((await Promise.all([post(update), post(update)])).map((result) => result.status), [200, 200]);

    for (let attempt = 0; attempt < 50; attempt += 1) {
      const rows = await db.prepare(outbox).all();
      if (rows.results.every((row) => row.state === "sent") && rows.results.length === 2) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    const results = await db.prepare(outbox).all();
    assert.deepEqual(results.results, [{ state: "sent", sent_message_id: 10 }, { state: "sent", sent_message_id: 8 }]);
    assert.deepEqual(sentBodies, [expectedPrivate, expectedGroup]);
    assert.deepEqual(replies, []);
  } finally {
    await miniflare.dispose();
  }
});

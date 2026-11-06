import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import { Miniflare } from "miniflare";

import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import { createSubscription } from "../src/storage.ts";
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
  const replies: Array<{ chatId: string; messageId: number; replyTo: number; text: string; button?: string }> = [];
  const sentBodies: unknown[] = [];
  const callbackId = "fixture-page-callback";
  let acknowledged = 0;
  let nextTicket: string | undefined;
  const botPath = `/bot${policy.botToken}/sendMessage`;
  const miniflare = new Miniflare({
    modules: true,
    script: bundle.toString("utf8"),
    compatibilityDate: fixture.compatibilityDate,
    bindings: { BUILD_REVISION: fixture.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
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
        reply_markup?: { inline_keyboard: Array<Array<{ text: string; callback_data: string }>> };
      };
      const observed = { chatId: payload.chat_id, text: payload.text, replyTo: payload.reply_parameters?.message_id };
      sentBodies.push(observed);
      assert.deepEqual(observed, { chatId: expected.chatId, text: expected.text, replyTo: expected.replyTo });
      if (expected.button) {
        const keyboard = payload.reply_markup?.inline_keyboard;
        assert.equal(keyboard?.length, 1);
        assert.equal(keyboard?.[0]?.length, 1);
        const button = keyboard![0][0];
        assert.equal(button.text, expected.button);
        assert.match(button.callback_data, /^sbv1_[A-Za-z0-9_-]{22}$/u);
        if (button.text === "下一页") nextTicket = button.callback_data;
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
    function expectSend(chatId: string, messageId: number, replyTo: number, expectedText: string, button?: string) {
      replies.push({ chatId, messageId, replyTo, text: expectedText, button });
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
    const firstPage = ["你的订阅", "• Member fixture", ...Array.from({ length: 7 }, (_, index) => `• Member fixture ${index + 2}`)].join("\n");
    const expectedGroup = expectSend(policy.groupId, 8, 7, firstPage, "下一页");
    const update = { update_id: 11, message };
    assert.deepEqual((await Promise.all([post(update), post(update)])).map((result) => result.status), [200, 200]);

    async function waitForReplies(messageIds: number[], acknowledgements = 0) {
      for (let attempt = 0; attempt < 50; attempt += 1) {
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
    const expectedNext = expectSend(policy.groupId, 9, 8, "你的订阅\n• Member fixture 9", "第一页");
    const callback = { update_id: 13, callback_query: {
      id: callbackId, data: nextTicket, chat_instance: "synthetic-instance", from: message.from,
      message: { date, message_id: 8, chat: message.chat, from: { id: Number(policy.botId), is_bot: true } },
    } };
    assert.deepEqual((await Promise.all([post(callback), post(callback)])).map((result) => result.status), [200, 200]);
    await waitForReplies([10, 8, 9], 2);
    assert.equal(acknowledged, 2);
    assert.deepEqual(sentBodies, [expectedPrivate, expectedGroup, expectedNext]);
    assert.deepEqual(replies, []);
  } finally {
    await miniflare.dispose();
  }
});

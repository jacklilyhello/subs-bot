import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { Miniflare } from "miniflare";

import { createPrivateShare } from "../src/private-shares.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
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
  const replies: Array<{ chatId: string; messageId: number; replyTo: number; text: string; button?: string; actions?: number }> = [];
  const sentBodies: unknown[] = [];
  const callbackId = "fixture-page-callback";
  let acknowledged = 0;
  let nextTicket: string | undefined;
  let renameTicket: string | undefined;
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
        const [button, ...actions] = payload.reply_markup?.inline_keyboard.flat() ?? [];
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
    function expectSend(chatId: string, messageId: number, replyTo: number, expectedText: string, button?: string, actions?: number) {
      replies.push({ chatId, messageId, replyTo, text: expectedText, button, actions });
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
      ...message, message_id: 19, text: "Renamed in compiled Worker", entities: [],
      reply_to_message: { ...botMessage, message_id: 18 },
    } };
    assert.deepEqual((await Promise.all([post(rename), post(rename)])).map((result) => result.status), [200, 200]);
    await waitForReplies([10, 8, 9, 18, 20], 3);
    assert.deepEqual(await db.prepare(`
      SELECT owner_id, name, revision
      FROM subscriptions JOIN subscription_lifecycle ON id = subscription_id
      WHERE owner_id = ?
    `).bind(policy.memberId).first(), { owner_id: policy.memberId, name: "Renamed in compiled Worker", revision: 1 });

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
    const memberPrivate = { ...claimMessage, chat: { id: Number(policy.memberId), type: "private" } };
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
  } finally {
    await miniflare.dispose();
  }
});

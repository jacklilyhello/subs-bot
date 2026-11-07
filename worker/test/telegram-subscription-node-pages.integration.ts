import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, getSubscriptionSnapshot, publishNodeSnapshot } from "../src/storage.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { beginTelegramReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import { acceptTelegramSubscriptionNodePage, renderTelegramSubscriptionNodePage } from "../src/telegram/subscription-node-pages.ts";
import { confirmTelegramSubscriptionReadSend } from "../src/telegram/subscription-read.ts";

test("emitted Worker browses pinned private 15-node pages and safely reopens current details", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
  assert.equal(sha256(script), manifest.bundleSha256);
  const policy: TelegramPolicy = {
    botId: "77401", botUsername: "Fixture_Node_Bot", adminId: "77402", memberId: "77403", groupId: "-10077404",
    botToken: "77401:synthetic-token", webhookSecret: "synthetic-node-page-secret",
  };
  type Button = { text: string; callback_data: string };
  type Sent = { id: number; text: string; chat: string; buttons: Button[]; replyTo: number };
  const sent: Sent[] = [];
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage");
      const body = await request.json() as { chat_id: string; text: string; reply_parameters: { message_id: number };
        link_preview_options: unknown; reply_markup?: { inline_keyboard: Button[][] } };
      assert.equal(body.chat_id, policy.memberId);
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.doesNotMatch(body.text, /synthetic-provider-secret|synthetic-node-secret|203\.0\.113\.7|https:\/\//u);
      const id = 1000 + sent.length;
      sent.push({ id, text: body.text, chat: body.chat_id, buttons: body.reply_markup?.inline_keyboard.flat() ?? [],
        replyTo: body.reply_parameters.message_id });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    const migrations = manifest.migrations as { name: string; sha256: string }[];
    const browse = migrations.find(({ name }) => name === "0022_telegram_subscription_node_pages.sql");
    assert.ok(browse);
    async function applyMigration(migration: (typeof migrations)[number]) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(sha256(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    for (const migration of migrations) if (migration !== browse) await applyMigration(migration);
    const sub = await createSubscription(db, { ownerId: policy.memberId, name: "Owned synthetic",
      sourceUrl: "https://example.invalid/synthetic-provider-secret" });
    const nodes = Array.from({ length: 32 }, (_, index) => ({
      name: index === 15 ? "第二页 🚀 https://example.invalid/synthetic-node-secret" : `Node ${index + 1}`,
      type: index === 16 ? "ss\nsynthetic-node-secret" : "ss", server: "203.0.113.7", password: "synthetic-node-secret",
    }));
    const target = { id: sub.id, ownerId: policy.memberId, expectedLifecycleRevision: 0 };
    assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 0 }, nodes), true);
    const date = Math.floor(Date.now() / 1000);
    const post = (update: unknown) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update),
    });
    const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
    const details = (id: number) => post({ update_id: id, message: { message_id: id, date, text: "1",
      from: { id: Number(policy.memberId), is_bot: false }, chat: chat(policy.memberId) } });
    const click = (updateId: number, messageId: number, ticket: string, owner = policy.memberId, chatId = owner) =>
      post({ update_id: updateId, callback_query: { id: `fixture-node-${updateId}`, data: ticket,
        from: { id: Number(owner), is_bot: false }, message: { message_id: messageId, date,
          from: { id: Number(policy.botId), is_bot: true }, chat: chat(chatId) } } });
    const state = (updateId: number) => db.prepare(`SELECT state,sent_message_id AS id FROM telegram_inbox
      JOIN telegram_outbox USING (receipt_id) WHERE bot_id=? AND update_id=?`).bind(policy.botId, updateId)
      .first<{ state: string; id: number | null }>();
    async function reply(updateId: number) {
      for (let attempt = 0; attempt < 60; attempt++) {
        const confirmed = await state(updateId);
        const outgoing = confirmed?.state === "sent" && sent.find(({ id }) => id === confirmed.id);
        if (outgoing) return outgoing;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Expected private subscription node reply did not settle.");
    }
    function token(message: Sent, label: string, prefix = "sbn1_") {
      const data = message.buttons.find(({ text }) => text === label)?.callback_data;
      assert.match(data ?? "", new RegExp(`^${prefix}[A-Za-z0-9_-]{22}$`, "u"));
      return data!;
    }
    const pageNumbers = (text: string) => [...text.matchAll(/^#(\d+) \[/gmu)].map((match) => Number(match[1]));

    assert.equal((await details(1)).status, 200);
    assert.ok(!(await reply(1)).buttons.some(({ text }) => text === "浏览全部节点"));
    assert.equal((await click(2, 1000, `sbn1_${"a".repeat(22)}`)).status, 204);
    await applyMigration(browse);
    assert.equal((await details(3)).status, 200);
    const detail = await reply(3);
    const firstToken = token(detail, "浏览全部节点");
    assert.equal((await click(4, detail.id, firstToken, policy.adminId)).status, 200);
    assert.equal((await click(5, detail.id, firstToken, policy.memberId, policy.groupId)).status, 204);
    assert.equal((await click(6, detail.id + 1, firstToken)).status, 200);
    for (const updateId of [2, 4, 5, 6]) assert.equal(await state(updateId), null);
    assert.equal((await click(7, detail.id, firstToken)).status, 200);
    const first = await reply(7);
    assert.match(first.text, /32 个节点 · 第 1\/3 页/u);
    assert.deepEqual(pageNumbers(first.text), Array.from({ length: 15 }, (_, i) => i + 1));
    assert.deepEqual(first.buttons.map(({ text }) => text), ["下一页", "返回订阅详情"]);
    assert.equal((await click(8, detail.id, firstToken)).status, 200);
    assert.equal(await state(8), null);

    assert.equal((await click(9, first.id, token(first, "下一页"))).status, 200);
    const second = await reply(9);
    assert.deepEqual(pageNumbers(second.text), Array.from({ length: 15 }, (_, i) => i + 16));
    assert.match(second.text, /#16 \[SS\] 第二页 🚀 \[链接已省略\]/u);
    assert.match(second.text, /#17 \[NODE\] Node 17/u);
    assert.equal((await click(10, second.id, token(second, "下一页"))).status, 200);
    const third = await reply(10);
    assert.deepEqual(pageNumbers(third.text), [31, 32]);
    assert.deepEqual(third.buttons.map(({ text }) => text), ["上一页", "返回订阅详情"]);
    assert.equal((await click(11, third.id, token(third, "上一页"))).status, 200);
    const previous = await reply(11);
    assert.deepEqual(pageNumbers(previous.text), pageNumbers(second.text));

    const snapshot = await getSubscriptionSnapshot(db, sub.token);
    assert.ok(snapshot);
    await bucket.put(`subscriptions/${sub.id}/${snapshot.snapshotId}/0.ndjson`, '{"name":"tampered"}\n');
    assert.equal((await click(12, previous.id, token(previous, "上一页"))).status, 200);
    const corrupt = await reply(12);
    assert.equal(corrupt.text, "暂时无法读取这一页节点。");
    assert.deepEqual(corrupt.buttons.map(({ text }) => text), ["返回订阅详情"]);

    assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 1 }, [{ name: "New snapshot", type: "ss" }]), true);
    assert.equal((await click(13, previous.id, token(previous, "下一页"))).status, 200);
    const stale = await reply(13);
    assert.match(stale.text, /订阅已更新或删除/u);
    assert.deepEqual(stale.buttons.map(({ text }) => text), ["返回订阅详情"]);
    assert.equal((await click(14, stale.id, token(stale, "返回订阅详情", "sbr1_"))).status, 200);
    const back = await reply(14);
    assert.match(back.text, /节点数量：1\n节点预览\n• New snapshot/u);
    assert.ok(back.buttons.some(({ text }) => text === "Clash Meta"));
    assert.ok(back.buttons.some(({ text }) => text === "浏览全部节点"));
    assert.equal(await acceptTelegramSubscriptionNodePage(db, policy, { actorId: policy.memberId, chatId: policy.memberId,
      chatType: "private", threadId: null, updateId: 15, callbackId: "fixture-late-node-page", messageDate: date,
      messageId: back.id, ticket: token(back, "浏览全部节点") }), "accepted");
    assert.equal(await claimTelegramReply(db, policy.botId, false, false, true, true), null);
    const lease = await claimTelegramReply(db, policy.botId, false, false, true, true, true);
    assert.ok(lease?.subscriptionNodes);
    const prepared = await renderTelegramSubscriptionNodePage(db, bucket, policy, lease, Date.now() + 5_000);
    assert.ok(prepared.readGuard);
    assert.equal(await beginTelegramReply(db, policy, lease, "allowed", [], [], [], prepared.readGuard), true);
    assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 2 }, [{ name: "Final snapshot", type: "ss" }]), true);
    assert.equal(await confirmTelegramSubscriptionReadSend(db, policy, lease, prepared.readGuard), false);
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    assert.equal((await state(15))?.state, "failed");
    for (const table of ["telegram_subscription_node_page", "telegram_subscription_node_ticket"]) {
      const rows = await db.prepare(`SELECT * FROM ${table}`).all();
      assert.doesNotMatch(JSON.stringify(rows.results), /sbn1_|synthetic-(?:provider|node)-secret|第二页|New snapshot/u);
    }
  } finally {
    await runtime.dispose();
  }
});

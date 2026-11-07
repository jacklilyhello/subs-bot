import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { trashOwnedSubscription } from "../src/subscriptions.ts";
import { beginTelegramReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import {
  acceptTelegramSubscriptionRead, confirmTelegramSubscriptionReadSend, renderTelegramSubscriptionRead,
} from "../src/telegram/subscription-read.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "76001", botUsername: "fixture_read_bot", adminId: "76002", memberId: "76003", groupId: "-10076004",
  botToken: "76001:synthetic-token", webhookSecret: "synthetic-subscription-read",
};
const share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Synthetic";
const needle = "STRAẞE-Aς";
const expectedFormats = { "Clash Meta": "clash", "Sing-box": "singbox", Base64: "base64", Surge: "surge", QX: "qx" };

type Sent = {
  id: number;
  chat: string;
  replyTo: number;
  text: string;
  buttons: { text: string; callback_data: string }[];
};

test("emitted Worker searches personal subscriptions and sends only guarded private format links", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sent: Sent[] = [];
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage", "The subscription read never calls a provider or an HTTP export URL.");
      const body = await request.json() as {
        chat_id: string; text: string; reply_parameters: { message_id: number };
        reply_markup?: { inline_keyboard: Sent["buttons"][] }; link_preview_options?: unknown;
      };
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.doesNotMatch(body.text, /provider\.example\.invalid|provider-secret|node-password|refresh-secret/u);
      const entry = { id: 1000 + sent.length, chat: body.chat_id, replyTo: body.reply_parameters.message_id, text: body.text,
        buttons: body.reply_markup?.inline_keyboard.flat() ?? [] };
      sent.push(entry);
      return Response.json({ ok: true, result: { message_id: entry.id, chat: { id: Number(entry.chat) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    async function applyMigration(migration: { name: string; sha256: string }) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(createHash("sha256").update(bytes).digest("hex"), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    const readMigration = manifest.migrations.find((item: { name: string }) => item.name === "0018_telegram_subscription_reads.sql");
    assert.ok(readMigration);
    for (const migration of manifest.migrations) if (migration !== readMigration) await applyMigration(migration);
    let sequence = 0;
    const now = () => Math.floor(Date.now() / 1000);
    const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
    const actor = (id: string) => ({ id: Number(id), is_bot: false });
    const post = (update: unknown) => runtime.dispatchFetch("https://worker.example.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update),
    });
    async function message(text: string, owner = policy.adminId, chatId = owner) {
      const id = ++sequence;
      const command = /^\/[^ ]+/u.exec(text)?.[0];
      const response = await post({ update_id: id, message: {
        message_id: id, date: now(), from: actor(owner), chat: chat(chatId), text,
        ...(command ? { entities: [{ type: "bot_command", offset: 0, length: command.length }] } : {}),
      } });
      return { id, response };
    }
    async function click(origin: Sent, ticket: string, owner = policy.adminId, chatId = owner) {
      const updateId = ++sequence;
      const response = await post({ update_id: updateId, callback_query: {
        id: `synthetic-read-${updateId}`, data: ticket, from: actor(owner), message: {
          message_id: origin.id, date: now(), from: { id: Number(policy.botId), is_bot: true }, chat: chat(chatId),
        },
      } });
      assert.equal(response.status, 200);
      return updateId;
    }
    async function waitForReply(chatId: string, replyTo: number, after = 0): Promise<Sent> {
      for (let i = 0; i < 50; i++) {
        const reply = sent.slice(after).find((entry) => entry.chat === chatId && entry.replyTo === replyTo);
        if (reply) {
          const state = await db.prepare(`SELECT state FROM telegram_outbox WHERE sent_message_id=?
            AND receipt_id IN (SELECT receipt_id FROM telegram_inbox WHERE chat_id=?)`).bind(reply.id, chatId).first("state");
          if (state === "sent") return reply;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Expected synthetic subscription read reply did not settle.");
    }
    const ticket = (reply: Sent, text: string) => {
      const value = reply.buttons.find((button) => button.text === text)?.callback_data;
      assert.match(value ?? "", /^sbr1_[A-Za-z0-9_-]{22}$/u);
      return value!;
    };
    const noReceipt = async (id: number) =>
      assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE update_id=?").bind(id).first(), null);
    const preMigration = await message(`/s ${needle}`);
    assert.equal(preMigration.response.status, 204);
    await noReceipt(preMigration.id);
    await applyMigration(readMigration);
    async function seed(ownerId: string, name: string, sourceUrl: string, nodes: Record<string, unknown>[] = []) {
      const sub = await createSubscription(db, { ownerId, name, sourceUrl });
      if (nodes.length) {
        assert.equal(await publishNodeSnapshot(db, bucket,
          { id: sub.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0 }, nodes), true);
      }
      return sub;
    }
    await seed(policy.memberId, "Member-only Straße-AΣ", "https://provider.example.invalid/member", [{ name: "Member node", share }]);
    const ready = await seed(policy.adminId, "Admin URL match", "https://provider.example.invalid/straße-aς?provider-secret=fixture",
      [{ name: "Synthetic node https://provider.example.invalid/node-password", type: "ss", share }]);
    await seed(policy.adminId, "STRASSE-AΣ decoy", "https://provider.example.invalid/decoy");
    await seed(policy.adminId, "Admin Straße-AΣ match", "https://provider.example.invalid/unsupported",
      [{ name: "Unsupported fixture", type: "fixture-unsupported" }]);
    await db.prepare("UPDATE subscriptions SET traffic_used=?,traffic_total=?,expire_at=?,last_error=? WHERE id=?")
      .bind(1.25, 4.5, now() + 86400, "refresh-secret", ready.id).run();

    const first = await message(`/s ${needle}`);
    assert.equal(first.response.status, 200);
    const search = await waitForReply(policy.adminId, first.id);
    assert.match(search.text, /#1 Admin URL match · 剩余 3\.25 GB/u);
    assert.match(search.text, /#3 Admin Straße-AΣ match/u);
    assert.doesNotMatch(search.text, /Member-only|decoy/u);
    const groupUpdate = await message(`/s@${policy.botUsername} ${needle}`, policy.memberId, policy.groupId);
    assert.equal(groupUpdate.response.status, 200);
    const group = await waitForReply(policy.groupId, groupUpdate.id);
    assert.equal(group.text, "搜索结果\n#1 Member-only Straße-AΣ");
    assert.deepEqual(group.buttons, []);
    await noReceipt(await click(search, ticket(search, "#1 详情"), policy.memberId));
    await noReceipt(await click(search, ticket(search, "#1 详情"), policy.adminId, policy.groupId));

    const listUpdate = await message("/list");
    const list = await waitForReply(policy.adminId, listUpdate.id);
    await click(list, ticket(list, "1 详情"));
    const fromList = await waitForReply(policy.adminId, list.id);
    assert.match(fromList.text, /Admin URL match/u);
    const number = await message("١");
    const detail = await waitForReply(policy.adminId, number.id);
    assert.match(detail.text, /流量详情：1\.25 GB \/ 4\.50 GB/u);
    assert.match(detail.text, /Synthetic node \[链接已省略\]/u);
    assert.match(detail.text, /上次刷新未成功/u);
    assert.deepEqual(detail.buttons.map(({ text }) => text), Object.keys(expectedFormats));
    for (const [label, format] of Object.entries(expectedFormats)) {
      const before = sent.length;
      const value = ticket(detail, label);
      await click(detail, value);
      const link = await waitForReply(policy.adminId, detail.id, before);
      assert.equal(link.text, `${label}\nhttps://subs-bot-cf-dev-01.lilyya.workers.dev/sub/${ready.token}/${format}`);
      await noReceipt(await click(detail, value));
    }
    const encoded = await runtime.dispatchFetch(`https://worker.example.invalid/sub/${ready.token}/base64`);
    assert.equal(encoded.status, 200);
    assert.equal(await encoded.text(), Buffer.from(share).toString("base64"));

    await click(search, ticket(search, "#3 详情"));
    const unsupported = await waitForReply(policy.adminId, search.id);
    const unavailable = ticket(unsupported, "Base64");
    await click(unsupported, unavailable);
    const denied = await waitForReply(policy.adminId, unsupported.id);
    assert.equal(denied.text, "订阅内容不支持此格式。");

    for (let i = 1; i <= 9; i++) await seed(policy.adminId, `Page cohort ${i}`, "https://provider.example.invalid/page");
    const pageUpdate = await message("/s page cohort", policy.adminId, policy.groupId);
    const page = await waitForReply(policy.groupId, pageUpdate.id);
    assert.match(page.text, /#4 Page cohort 1/u);
    assert.match(page.text, /#11 Page cohort 8/u);
    assert.doesNotMatch(page.text, /Page cohort 9/u);
    assert.deepEqual(page.buttons.map(({ text }) => text), ["下一页"]);
    await noReceipt(await click(page, ticket(page, "下一页"), policy.memberId, policy.groupId));
    await click(page, ticket(page, "下一页"), policy.adminId, policy.groupId);
    const nextPage = await waitForReply(policy.groupId, page.id);
    assert.equal(nextPage.text, "搜索结果\n#12 Page cohort 9");

    const raceTicket = ticket(fromList, "Clash Meta");
    assert.equal(await acceptTelegramSubscriptionRead(db, policy, {
      kind: "callback", callbackId: "synthetic-read-race", ticket: raceTicket, updateId: ++sequence,
      actorId: policy.adminId, chatId: policy.adminId, chatType: "private", threadId: null,
      messageId: fromList.id, messageDate: now(),
    }), "accepted");
    const lease = await claimTelegramReply(db, policy.botId, false, false, true);
    assert.ok(lease?.subscriptionRead);
    const prepared = await renderTelegramSubscriptionRead(db, bucket, policy, lease, Date.now() + 5_000);
    assert.ok(prepared.readGuard);
    assert.equal(await beginTelegramReply(db, policy, lease, "allowed", [], [], [], prepared.readGuard), true);
    assert.equal(await trashOwnedSubscription(db, { id: ready.id, ownerId: policy.adminId, expectedLifecycleRevision: 0 }), true);
    assert.equal(await confirmTelegramSubscriptionReadSend(db, policy, lease, prepared.readGuard), false);
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    assert.equal((await runtime.dispatchFetch(`https://worker.example.invalid/sub/${ready.token}/base64`, { method: "HEAD" })).status, 404);

    const memberNumber = await message("1", policy.memberId);
    const memberDetail = await waitForReply(policy.memberId, memberNumber.id);
    assert.equal(await acceptTelegramSubscriptionRead(db, policy, {
      kind: "callback", callbackId: "synthetic-read-auth", ticket: ticket(memberDetail, "Clash Meta"), updateId: ++sequence,
      actorId: policy.memberId, chatId: policy.memberId, chatType: "private", threadId: null,
      messageId: memberDetail.id, messageDate: now(),
    }), "accepted");
    const memberLease = await claimTelegramReply(db, policy.botId, false, false, true);
    assert.ok(memberLease?.subscriptionRead);
    const memberLink = await renderTelegramSubscriptionRead(db, bucket, policy, memberLease, Date.now() + 5_000);
    assert.match(memberLink.text, /\/sub\/[A-Za-z0-9_-]+\/clash/u);
    assert.ok(memberLink.readGuard);
    assert.equal(await beginTelegramReply(db, policy, memberLease, "allowed", [], [], [], memberLink.readGuard), true);
    await db.prepare("INSERT INTO telegram_auth(bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,0,unixepoch(),1)")
      .bind(policy.botId, policy.memberId).run();
    assert.equal(await confirmTelegramSubscriptionReadSend(db, policy, memberLease, memberLink.readGuard), false);
    await settleTelegramReply(db, policy, memberLease, { kind: "failed" });

    for (const table of ["telegram_subscription_read", "telegram_subscription_read_ticket", "telegram_outbox", "telegram_inbox"]) {
      const rows = await db.prepare(`SELECT * FROM ${table}`).all();
      const serialized = JSON.stringify(rows.results);
      assert.doesNotMatch(serialized, /STRAẞE|provider-secret|refresh-secret|sbr1_|https:\/\//u);
      assert.ok(!serialized.includes(ready.token));
    }
  } finally {
    await runtime.dispose();
  }
});

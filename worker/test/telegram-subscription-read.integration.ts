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
import { TELEGRAM_PAGE_JUMP_CALLBACK, TELEGRAM_PAGE_JUMP_PROMPT, type TelegramPolicy } from "../src/telegram/protocol.ts";

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
  threadId: number | null;
  forceReply: boolean;
};

test("emitted Worker searches personal subscriptions and sends only guarded private format links", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sent: Sent[] = [];
  const fixture = {
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "telegram-read-fixture" }, r2Buckets: { NODES: "telegram-read-fixture" },
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage", "The subscription read never calls a provider or an HTTP export URL.");
      const body = await request.json() as {
        chat_id: string; text: string; reply_parameters: { message_id: number };
        message_thread_id?: number; reply_markup?: { inline_keyboard?: Sent["buttons"][]; force_reply?: boolean };
        link_preview_options?: unknown;
      };
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.doesNotMatch(body.text, /provider\.example\.invalid|provider-secret|node-password|refresh-secret/u);
      const entry = { id: 1000 + sent.length, chat: body.chat_id, replyTo: body.reply_parameters.message_id, text: body.text,
        buttons: body.reply_markup?.inline_keyboard?.flat() ?? [], threadId: body.message_thread_id ?? null,
        forceReply: body.reply_markup?.force_reply === true };
      sent.push(entry);
      return Response.json({ ok: true, result: { message_id: entry.id, chat: { id: Number(entry.chat) } } });
    },
  };
  const runtime = new Miniflare({ workers: [
    { ...fixture, name: "enabled", bindings: { ...fixture.bindings, TELEGRAM_PAGE_JUMP: "1" } },
    { ...fixture, name: "dormant" },
  ] });
  try {
    const db = await runtime.getD1Database("DB", "enabled");
    const bucket = await runtime.getR2Bucket("NODES", "enabled");
    const enabled = await runtime.getWorker("enabled");
    const dormant = await runtime.getWorker("dormant");
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
    const post = (update: unknown, inactive = false) => {
      const url = "https://worker.example.invalid/telegram/webhook";
      const options = {
        method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
        body: JSON.stringify(update),
      };
      return (inactive ? dormant : enabled).fetch(url, options);
    };
    async function message(text: string, owner = policy.adminId, chatId = owner, threadId?: number, inactive = false) {
      const id = ++sequence;
      const command = /^\/[^ ]+/u.exec(text)?.[0];
      const response = await post({ update_id: id, message: {
        message_id: id, date: now(), from: actor(owner), chat: chat(chatId), text,
        ...(threadId === undefined ? {} : { message_thread_id: threadId }),
        ...(command ? { entities: [{ type: "bot_command", offset: 0, length: command.length }] } : {}),
      } }, inactive);
      return { id, response };
    }
    async function click(origin: Sent, ticket: string, owner = policy.adminId, chatId = owner, threadId = origin.threadId, inactive = false) {
      const updateId = ++sequence;
      const response = await post({ update_id: updateId, callback_query: {
        id: `synthetic-read-${updateId}`, data: ticket, from: actor(owner), message: {
          message_id: origin.id, date: now(), from: { id: Number(policy.botId), is_bot: true }, chat: chat(chatId),
          ...(threadId === null ? {} : { message_thread_id: threadId }),
        },
      } }, inactive);
      assert.equal(response.status, inactive ? 204 : 200);
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
    assert.ok(!list.buttons.some(({ callback_data }) => callback_data === TELEGRAM_PAGE_JUMP_CALLBACK));
    await click(list, ticket(list, "1 详情"));
    const fromList = await waitForReply(policy.adminId, list.id);
    assert.match(fromList.text, /Admin URL match/u);
    const number = await message("١");
    const detail = await waitForReply(policy.adminId, number.id);
    assert.match(detail.text, /流量详情：1\.25 GB \/ 4\.50 GB/u);
    assert.match(detail.text, /Synthetic node \[链接已省略\]/u);
    assert.match(detail.text, /上次刷新未成功/u);
    assert.deepEqual(detail.buttons.map(({ text }) => text), ["浏览全部节点", ...Object.keys(expectedFormats), "📦 导出节点"]);
    for (const [label, format] of Object.entries(expectedFormats)) {
      const before = sent.length;
      const value = ticket(detail, label);
      await click(detail, value);
      const link = await waitForReply(policy.adminId, detail.id, before);
      assert.equal(link.text, `${label}\nhttps://subs-bot-cf-dev-01.lilyya.workers.dev/sub/${ready.token}/${format}`);
      await noReceipt(await click(detail, value));
    }
    const encoded = await enabled.fetch(`https://worker.example.invalid/sub/${ready.token}/base64`);
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
    assert.equal((await enabled.fetch(`https://worker.example.invalid/sub/${ready.token}/base64`, { method: "HEAD" })).status, 404);

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

    const jumpMigration = manifest.migrations.find((item: { name: string }) => item.name === "0042_telegram_page_jumps.sql");
    assert.ok(jumpMigration);
    await db.batch([
      db.prepare("CREATE TABLE IF NOT EXISTS subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT) STRICT"),
      db.prepare("INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode) VALUES (42,?,?,'applied')")
        .bind(jumpMigration.name, jumpMigration.sha256),
    ]);
    const dormantUpdate = await message("/list", policy.adminId, policy.adminId, undefined, true);
    const dormantList = await waitForReply(policy.adminId, dormantUpdate.id);
    assert.ok(!dormantList.buttons.some(({ callback_data }) => callback_data === TELEGRAM_PAGE_JUMP_CALLBACK));
    await noReceipt(await click(dormantList, TELEGRAM_PAGE_JUMP_CALLBACK, policy.adminId, policy.adminId, null, true));
    const jumpList = await waitForReply(policy.adminId, (await message("/list")).id);
    assert.ok(jumpList.buttons.some(({ callback_data }) => callback_data === TELEGRAM_PAGE_JUMP_CALLBACK));
    async function openJump(source: Sent, owner = policy.adminId) {
      const after = sent.length;
      await click(source, TELEGRAM_PAGE_JUMP_CALLBACK, owner, source.chat);
      const prompt = await waitForReply(source.chat, source.id, after);
      assert.equal(prompt.text, TELEGRAM_PAGE_JUMP_PROMPT);
      assert.equal(prompt.threadId, source.threadId);
      assert.equal(prompt.forceReply, source.chat !== policy.groupId);
      return prompt;
    }
    async function answerJump(prompt: Sent, text: string, owner = policy.adminId, threadId = prompt.threadId, inactive = false) {
      const updateId = ++sequence;
      const messageId = 2000 + updateId;
      const topic = threadId === null ? {} : { message_thread_id: threadId };
      const response = await post({ update_id: updateId, message: {
        message_id: messageId, date: now(), from: actor(owner), chat: chat(prompt.chat), text, ...topic,
        reply_to_message: { message_id: prompt.id, text: prompt.text, date: now(),
          from: { id: Number(policy.botId), is_bot: true }, chat: chat(prompt.chat), ...topic },
      } }, inactive);
      assert.equal(response.status, inactive ? 204 : 200);
      return { updateId, messageId };
    }
    const prompt = await openJump(jumpList);
    await noReceipt((await answerJump(prompt, "2", policy.adminId, null, true)).updateId);
    await noReceipt(await click(jumpList, TELEGRAM_PAGE_JUMP_CALLBACK));
    const ordinary = await message("2");
    assert.match((await waitForReply(policy.adminId, ordinary.id)).text, /Admin Straße-AΣ match/u);
    const pageTwo = await answerJump(prompt, "٢");
    const jumped = await waitForReply(policy.adminId, pageTwo.messageId);
    assert.match(jumped.text, /^你的订阅\n9\. Page cohort 7/u);
    assert.doesNotMatch(jumped.text, /Member-only|Page cohort 6/u);
    await noReceipt((await answerJump(prompt, "1")).updateId);
    const firstKey = jumped.buttons.find(({ text }) => text === "第一页")?.callback_data;
    assert.match(firstKey ?? "", /^sbv1_/u);
    await click(jumped, firstKey!);
    assert.match((await waitForReply(policy.adminId, jumped.id)).text, /^你的订阅\n1\. STRASSE-AΣ decoy/u);

    await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=unixepoch()-10,message_id=2 WHERE bot_id=? AND user_id=?")
      .bind(policy.botId, policy.memberId).run();
    const topicList = await waitForReply(policy.groupId, (await message("/list", policy.adminId, policy.groupId, 100)).id);
    await noReceipt(await click(topicList, TELEGRAM_PAGE_JUMP_CALLBACK, policy.memberId, policy.groupId));
    await noReceipt(await click(topicList, TELEGRAM_PAGE_JUMP_CALLBACK, policy.adminId, policy.groupId, 101));
    const topicPrompt = await openJump(topicList);
    await noReceipt((await answerJump(topicPrompt, "2", policy.memberId)).updateId);
    await noReceipt((await answerJump(topicPrompt, "2", policy.adminId, 101)).updateId);
    const topicNumber = await answerJump(topicPrompt, "2");
    const topicPage = await waitForReply(policy.groupId, topicNumber.messageId);
    assert.equal(topicPage.threadId, 100);
    assert.match(topicPage.text, /^你的订阅\n9\. Page cohort 7/u);
    assert.doesNotMatch(topicPage.text, /Member-only|Page cohort 6/u);
    await noReceipt((await answerJump(topicPrompt, "2")).updateId);
    const invalid = await answerJump(await openJump(topicPage), "fixture-page-input-sensitive");
    assert.match((await waitForReply(policy.groupId, invalid.messageId)).text, /页码必须是数字/u);

    const anotherList = await waitForReply(policy.adminId, (await message("/list")).id);
    const range = await answerJump(await openJump(anotherList), "9999999999999999999999");
    assert.match((await waitForReply(policy.adminId, range.messageId)).text, /最大 2/u);
    const replacedList = await waitForReply(policy.adminId, (await message("/list")).id);
    const replaced = await openJump(replacedList);
    const currentList = await waitForReply(policy.adminId, (await message("/list")).id);
    const current = await openJump(currentList);
    await noReceipt((await answerJump(replaced, "2")).updateId);
    const pageZero = await answerJump(current, "0");
    assert.match((await waitForReply(policy.adminId, pageZero.messageId)).text, /^你的订阅\n1\. STRASSE-AΣ decoy/u);
    const expiringList = await waitForReply(policy.adminId, (await message("/list")).id);
    const expiring = await openJump(expiringList);
    await db.prepare(`UPDATE telegram_page_jumps SET expires_at=unixepoch() WHERE receipt_id=(
      SELECT receipt_id FROM telegram_outbox WHERE sent_message_id=?)`).bind(expiring.id).run();
    await noReceipt((await answerJump(expiring, "1")).updateId);

    const memberList = await waitForReply(policy.memberId, (await message("/list", policy.memberId)).id);
    const memberPrompt = await openJump(memberList, policy.memberId);
    await db.prepare("UPDATE telegram_auth SET allowed=0,message_date=unixepoch()-5,message_id=3 WHERE bot_id=? AND user_id=?")
      .bind(policy.botId, policy.memberId).run();
    await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=unixepoch()-3,message_id=4 WHERE bot_id=? AND user_id=?")
      .bind(policy.botId, policy.memberId).run();
    await noReceipt((await answerJump(memberPrompt, "1", policy.memberId)).updateId);

    async function seedPageRange(first: number, last: number) {
      await db.prepare(`WITH RECURSIVE positions(n) AS (SELECT ? UNION ALL SELECT n+1 FROM positions WHERE n<?)
        INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
        SELECT ?,printf('Long page fixture %d',n),'uploaded://jump-test',printf('jump-fixture-token-%d',n),unixepoch(),unixepoch()
        FROM positions`).bind(first, last, policy.adminId).run();
    }
    async function jumpTo(number: string) {
      const origin = await waitForReply(policy.adminId, (await message("/list")).id);
      return waitForReply(policy.adminId, (await answerJump(await openJump(origin), number)).messageId);
    }
    await seedPageRange(1, 19_989);
    assert.match((await jumpTo("65")).text, /^你的订阅\n513\. Long page fixture 502\n/u);
    assert.match((await jumpTo("2500")).text, /^你的订阅\n19993\. Long page fixture 19982\n/u);
    assert.match((await jumpTo("2501")).text, /最大 2500/u);
    await seedPageRange(19_990, 19_990);
    assert.equal((await jumpTo("2501")).text, "此页超出直接跳转上限，请使用“下一页”继续。");

    for (const table of ["telegram_subscription_read", "telegram_subscription_read_ticket", "telegram_outbox", "telegram_inbox",
      "telegram_page_jumps"]) {
      const rows = await db.prepare(`SELECT * FROM ${table}`).all();
      const serialized = JSON.stringify(rows.results);
      assert.doesNotMatch(serialized, /STRAẞE|provider-secret|refresh-secret|sbr1_|https:\/\/|fixture-page-input-sensitive/u);
      assert.ok(!serialized.includes(ready.token));
    }
  } finally {
    await runtime.dispose();
  }
});

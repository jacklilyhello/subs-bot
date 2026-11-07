import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { acceptTelegramInlineSort } from "../src/telegram/inline-sort.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { claimTelegramReply } from "../src/telegram/store.ts";

test("emitted Worker saves private inline sort preferences and fences queued replies", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  const sha256 = (value: Buffer) => createHash("sha256").update(value).digest("hex");
  assert.equal(sha256(script), manifest.bundleSha256);
  const policy: TelegramPolicy = {
    botId: "76801", botUsername: "Fixture_Sort_Bot", adminId: "76802", memberId: "76803", groupId: "-10076804",
    botToken: "76801:synthetic-token", webhookSecret: "synthetic-inline-sort-secret",
  };
  type Sent = { chat_id: string; text: string; reply_parameters: { message_id: number } };
  const sent: Sent[] = [];
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      const body = await request.json() as Sent;
      assert.ok(body.chat_id === policy.memberId || body.chat_id === policy.adminId);
      assert.doesNotMatch(body.text, /synthetic-hidden-argument|https:\/\//u);
      sent.push(body);
      return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(body.chat_id) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    const migrations = manifest.migrations as { name: string; sha256: string }[];
    const sortMigration = migrations.find(({ name }) => name === "0020_telegram_inline_sort.sql");
    assert.ok(sortMigration);
    async function applyMigration(migration: (typeof migrations)[number]) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(sha256(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    for (const migration of migrations) if (migration !== sortMigration) await applyMigration(migration);
    const now = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
    assert.ok(now);
    const date = now - 5;
    const post = (updateId: number, text: string, actorId = policy.memberId, chatId = actorId, messageDate = date, messageId = updateId) =>
      runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
        body: JSON.stringify({ update_id: updateId, message: { date: messageDate, message_id: messageId, text,
          from: { id: Number(actorId), is_bot: false }, chat: { id: Number(chatId), type: chatId === policy.groupId ? "supergroup" : "private" },
          entities: [{ type: "bot_command", offset: 0, length: 2 }] } }),
      });
    const state = (id: number) => db.prepare(`SELECT state FROM telegram_inbox JOIN telegram_outbox USING (receipt_id)
      WHERE bot_id = ? AND update_id = ?`).bind(policy.botId, id).first<string>("state");
    async function expectReply(id: number, text: RegExp, owner = policy.memberId, messageId = id) {
      for (let attempt = 0; attempt < 60; attempt++) {
        if (await state(id) === "sent") {
          const reply = sent.find((item) => item.chat_id === owner && item.reply_parameters.message_id === messageId);
          assert.ok(reply);
          assert.match(reply.text, text);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Expected inline sort reply did not settle.");
    }

    assert.equal((await post(1, "/i 流量")).status, 204);
    assert.equal(await state(1), null);
    await applyMigration(sortMigration);
    assert.equal((await post(2, "/i 流量", policy.memberId, policy.groupId)).status, 204);
    assert.equal(await state(2), null);
    assert.equal((await post(3, "/i")).status, 200);
    await expectReply(3, /当前内联排序偏好：默认.*\n用法/u);
    assert.equal((await post(10, "/i 流量")).status, 200);
    await expectReply(10, /已保存为：流量/u);
    assert.equal((await post(10, "/i 到期")).status, 200);
    assert.equal((await post(9, "/i 默认", policy.memberId, policy.memberId, date, 50)).status, 200);
    await expectReply(9, /已有更新/u, policy.memberId, 50);
    assert.equal((await post(11, "/i 名称", policy.adminId)).status, 200);
    await expectReply(11, /已保存为：名称/u, policy.adminId);
    assert.equal((await post(12, "/i synthetic-hidden-argument")).status, 200);
    await expectReply(12, /^用法/u);
    assert.equal((await post(13, "/i 默认", policy.memberId, policy.memberId, now - 901)).status, 200);
    assert.equal(await state(13), null);
    const owners = await db.prepare("SELECT actor_id, mode FROM telegram_inline_sort_preferences ORDER BY actor_id").all();
    assert.deepEqual(owners.results, [{ actor_id: policy.adminId, mode: "name" }, { actor_id: policy.memberId, mode: "traffic" }]);
    assert.equal(sent.filter((item) => item.reply_parameters.message_id === 10).length, 1);

    const grant = (grantDate: number, messageId: number) => db.prepare(`
      INSERT INTO telegram_auth (bot_id, user_id, allowed, message_date, message_id) VALUES (?, ?, 1, ?, ?)
      ON CONFLICT (bot_id, user_id) DO UPDATE SET allowed = 1, message_date = excluded.message_date, message_id = excluded.message_id
    `).bind(policy.botId, policy.memberId, grantDate, messageId).run();
    await grant(now - 120, 1);
    assert.equal((await post(14, "/i 到期", policy.memberId, policy.memberId, now - 120)).status, 200);
    assert.equal(await state(14), null);
    assert.equal(await acceptTelegramInlineSort(db, policy, { updateId: 15, messageDate: date, messageId: 15,
      actorId: policy.memberId, chatId: policy.memberId, chatType: "private", threadId: null, kind: "current" }), "accepted");
    assert.equal(await state(15), "pending");
    assert.equal(await claimTelegramReply(db, policy.botId), null);
    // A different grant can arrive after admission with an event date still earlier than the command.
    await grant(now - 60, 2);
    const worker = await runtime.getWorker();
    assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.equal(await state(15), "failed");
    assert.ok(!sent.some((item) => item.reply_parameters.message_id === 15));
    assert.equal((await post(16, "/i")).status, 200);
    await expectReply(16, /当前内联排序偏好：流量/u);
    assert.equal((await post(17, "/i 默认", policy.memberId, policy.memberId, date - 1)).status, 200);
    await expectReply(17, /已有更新/u);
    assert.equal((await post(18, "/i 默认", policy.memberId, policy.memberId, now + 600)).status, 200);
    assert.equal(await state(18), null);
    await db.prepare("UPDATE telegram_auth SET allowed = 0 WHERE bot_id = ? AND user_id = ?")
      .bind(policy.botId, policy.memberId).run();
    assert.equal((await post(19, "/i 默认")).status, 200);
    assert.equal(await state(19), null);
    assert.equal(await db.prepare(`SELECT mode FROM telegram_inline_sort_preferences WHERE bot_id = ? AND actor_id = ?`)
      .bind(policy.botId, policy.memberId).first("mode"), "traffic");
    for (const table of ["telegram_inbox", "telegram_inline_sort_reply", "telegram_inline_sort_preferences"]) {
      const rows = await db.prepare(`SELECT * FROM ${table}`).all();
      assert.doesNotMatch(JSON.stringify(rows.results), /synthetic-hidden-argument/u);
    }
  } finally {
    await runtime.dispose();
  }
});

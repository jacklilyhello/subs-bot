import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription } from "../src/storage.ts";
import type { InlineSearchArticle } from "../src/telegram/inline-search.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

test("emitted Worker answers opted-in sender queries using the owner's durable sort and safe metadata", { timeout: 90_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  const sha256 = (bytes: Buffer | string) => createHash("sha256").update(bytes).digest("hex");
  assert.equal(sha256(script), manifest.bundleSha256);
  const policy: TelegramPolicy = {
    botId: "79801", botUsername: "Fixture_Inline_Bot", adminId: "79802", memberId: "79803", groupId: "-10079804",
    botToken: "79801:synthetic-token", webhookSecret: "synthetic-inline-search-secret",
  };
  const sent: { id: number; text: string; origin: number }[] = [];
  type Answer = { inline_query_id: string; results: InlineSearchArticle[]; is_personal: boolean; cache_time: number; next_offset: string };
  const answers: Answer[] = [];
  const started = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  const common = {
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "personal-inline-fixture" }, r2Buckets: { NODES: "personal-inline-fixture" },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const url = `https://api.telegram.org/bot${policy.botToken}`;
      if (request.url === url + "/answerInlineQuery") {
        const answer = await request.json() as Answer;
        assert.equal(answer.is_personal, true);
        assert.equal(answer.cache_time, 0);
        assert.equal(answer.next_offset, "");
        assert.ok(answer.results.length <= 50);
        for (const article of answer.results) {
          assert.deepEqual(Object.keys(article).sort(), ["id", "input_message_content", "title", "type"]);
          assert.match(article.id, /^[a-f0-9-]{36}$/u);
          assert.deepEqual(article.input_message_content, { message_text: "在此私聊发送 /list 或 /s 关键词查看订阅详情。",
            link_preview_options: { is_disabled: true } });
        }
        assert.doesNotMatch(JSON.stringify(answer.results), /https?:\/\/|synthetic-source-secret|synthetic-title-secret|FOREIGN/u);
        answers.push(answer);
        if (answer.inline_query_id === "fixture-uncertain") return Response.json({ ok: true, result: false });
        if (answer.inline_query_id === "fixture-held") {
          started.resolve();
          await release.promise;
        }
        return Response.json({ ok: true, result: true });
      }
      assert.equal(request.url, url + "/sendMessage");
      const body = await request.json() as { chat_id: string; text: string; reply_parameters: { message_id: number } };
      assert.ok(body.chat_id === policy.memberId || body.chat_id === policy.adminId);
      const id = 1000 + sent.length;
      sent.push({ id, text: body.text, origin: body.reply_parameters.message_id });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    },
  };
  const bindings = { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) };
  const swapped = { ...policy, adminId: policy.memberId, memberId: policy.adminId };
  const runtime = new Miniflare({ workers: [
    { ...common, name: "app", bindings: { ...bindings, TELEGRAM_INLINE_SEARCH: "1" } },
    { ...common, name: "disabled", bindings },
    { ...common, name: "swapped", bindings: { ...bindings, TELEGRAM_INLINE_SEARCH: "1", TELEGRAM_ISOLATION_CONFIG: JSON.stringify(swapped) } },
  ] });
  try {
    const app = await runtime.getWorker("app");
    const disabled = await runtime.getWorker("disabled");
    const changedRoles = await runtime.getWorker("swapped");
    const db = await runtime.getD1Database("DB", "app");
    const migrations = manifest.migrations as { name: string; sha256: string }[];
    const inline = migrations.find(({ name }) => name === "0025_telegram_personal_inline.sql");
    assert.ok(inline);
    async function applyMigration(migration: (typeof migrations)[number]) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(sha256(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    for (const migration of migrations) if (migration !== inline) await applyMigration(migration);
    const post = (update: unknown, worker = app) => worker.fetch("https://fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update),
    });
    const command = (updateId: number, text: string, worker = app,
      { actorId = policy.memberId, date = Math.floor(Date.now() / 1000) } = {}) => post({ update_id: updateId, message: {
      message_id: updateId, date, text,
      from: { id: Number(actorId), is_bot: false }, chat: { id: Number(actorId), type: "private" },
      entities: [{ type: "bot_command", offset: 0, length: text.indexOf(" ") }],
    } }, worker);
    const query = (updateId: number, text = "", fields: Record<string, unknown> = {}, worker = app) => post({ update_id: updateId,
      inline_query: { id: `fixture-inline-${updateId}`, from: { id: Number(policy.memberId), is_bot: false },
        chat_type: "sender", offset: "", query: text, ...fields } }, worker);
    const receipt = (updateId: number) => db.prepare(`SELECT state,sort_mode,result_count,query_id_sha256 FROM telegram_inline_search_receipts
      WHERE bot_id=? AND update_id=?`).bind(policy.botId, updateId).first();
    async function expectCommand(id: number, pattern: RegExp) {
      for (let attempt = 0; attempt < 60; attempt++) {
        const row = await db.prepare(`SELECT state FROM telegram_inbox JOIN telegram_outbox USING (receipt_id)
          WHERE bot_id=? AND update_id=?`).bind(policy.botId, id).first("state");
        if (row === "sent") {
          const message = sent.find(({ origin }) => origin === id);
          assert.ok(message);
          assert.match(message.text, pattern);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Expected inline preference or consent reply did not settle.");
    }
    const titles = () => answers.at(-1)?.results.map(({ title }) => title);
    async function setSort(id: number, label: string) {
      assert.equal((await command(id, `/i ${label}`)).status, 200);
      await expectCommand(id, /内联排序偏好已保存/u);
    }

    assert.equal((await command(1, "/inline on")).status, 204);
    assert.equal((await query(2)).status, 204);
    await applyMigration(inline);
    assert.equal((await command(3, "/inline on", disabled)).status, 204);
    assert.equal((await query(4)).status, 204);
    assert.equal(await receipt(4), null);
    assert.equal((await command(5, "/inline on")).status, 200);
    assert.equal((await command(6, "/inline on", app, { actorId: policy.adminId })).status, 200);
    await expectCommand(5, /已开启私聊内联搜索/u);
    await expectCommand(6, /已开启私聊内联搜索/u);
    for (const [id, actor] of [[7, policy.memberId], [8, policy.adminId]] as const) {
      assert.equal((await query(id, "", { from: { id: Number(actor), is_bot: false } }, changedRoles)).status, 204);
      assert.equal(await receipt(id), null, "a role change invalidates old consent in either direction");
    }
    assert.equal((await command(96, "/inline off", app, { actorId: policy.adminId })).status, 200);
    await expectCommand(96, /已关闭私聊内联搜索/u);
    const clock = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
    assert.ok(clock);
    await db.batch([
      db.prepare("UPDATE telegram_inbox SET message_date=? WHERE bot_id=? AND update_id=5").bind(clock - 120, policy.botId),
      db.prepare("UPDATE telegram_inline_search_consent SET message_date=?,expires_at=? WHERE bot_id=? AND update_id=5")
        .bind(clock - 120, clock + 780, policy.botId),
    ]);
    assert.equal((await command(9, "/inline off", app, { date: clock - 75 })).status, 200);
    await expectCommand(9, /已关闭私聊内联搜索/u);
    assert.equal((await query(99)).status, 204);
    assert.equal(await receipt(99), null, "delayed opt-out closes the previously active consent");
    assert.equal((await command(98, "/inline on", app, { date: clock - 75 })).status, 200);
    assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=98").bind(policy.botId).first(), null);
    assert.equal((await command(10, "/inline on")).status, 200);
    await expectCommand(10, /已开启私聊内联搜索/u);
    assert.equal((await command(97, "/inline off", app, { date: clock - 70 })).status, 200);
    await expectCommand(97, /内联搜索设置已有更新/u);
    for (const [id, fields] of [[11, { chat_type: undefined }], [12, { chat_type: "private" }], [13, { chat_type: "group" }],
      [14, { chat_type: "supergroup" }], [15, { offset: "unexpected" }], [16, { from: { id: Number(policy.adminId), is_bot: false } }],
      [17, { from: { id: 79805, is_bot: false } }], [18, { from: { id: Number(policy.memberId), is_bot: true } }]] as const) {
      assert.equal((await query(id, "", fields)).status, 204);
      assert.equal(await receipt(id), null);
    }
    assert.equal((await query(19, "😀".repeat(257))).status, 204);
    assert.equal((await query(4)).status, 204, "a delayed update predating consent has no effect");
    assert.equal((await query(20, "", {}, disabled)).status, 204);
    assert.deepEqual(answers, []);

    const names = ["Z", "A", "Straße-AΣ https://example.invalid/synthetic-title-secret", "\ue000", "😀"];
    const visible = ["Z", "A", "Straße-AΣ [链接已省略]", "\ue000", "😀"];
    for (const [index, name] of names.entries()) {
      const sub = await createSubscription(db, { ownerId: policy.memberId, name,
        sourceUrl: index === 0 ? "https://example.invalid/DOUBLE  SPACE?synthetic-source-secret" : `https://example.invalid/item-${index}` });
      await db.prepare("UPDATE subscriptions SET traffic_total=?,traffic_used=?,expire_at=? WHERE id=?")
        .bind([1, null, 3, 3, null][index], [2, null, 1, 1, null][index], [null, 100, 0, 100, 200][index], sub.id).run();
    }
    await createSubscription(db, { ownerId: policy.adminId, name: "FOREIGN", sourceUrl: "https://example.invalid/foreign" });
    assert.equal((await query(21)).status, 204);
    assert.deepEqual(titles(), visible);
    assert.deepEqual(await receipt(21), { state: "sent", sort_mode: "default", result_count: 5, query_id_sha256: sha256("fixture-inline-21") });
    await setSort(22, "流量");
    assert.equal((await query(23)).status, 204);
    assert.deepEqual(titles(), [visible[2], visible[3], visible[1], visible[4], visible[0]]);
    await setSort(24, "到期");
    assert.equal((await query(25)).status, 204);
    assert.deepEqual(titles(), [visible[1], visible[3], visible[4], visible[0], visible[2]]);
    await setSort(26, "名称");
    assert.equal((await query(27)).status, 204);
    assert.deepEqual(titles(), [visible[1], visible[2], visible[0], visible[3], visible[4]]);
    assert.equal((await query(28, "\u0085STRAẞE-Aς\u3000")).status, 204);
    assert.deepEqual(titles(), [visible[2]]);
    assert.equal((await query(29, "DOUBLE  SPACE")).status, 204);
    assert.deepEqual(titles(), [visible[0]]);
    assert.equal((await query(30, "DOUBLE SPACE")).status, 204);
    assert.deepEqual(titles(), []);
    const afterSearch = answers.length;
    assert.equal((await query(30, "changed-synthetic-text", { id: "other-fixture-id" })).status, 204);
    assert.equal((await query(31, "", { id: "fixture-inline-21" })).status, 204);
    assert.equal((await query(32, "Share fixture-raw-text")).status, 204);
    assert.equal(answers.length, afterSearch);

    assert.equal((await query(33, "", { id: "fixture-uncertain" })).status, 204);
    assert.equal((await receipt(33))?.state, "uncertain");
    assert.equal((await query(33, "", { id: "fixture-uncertain" })).status, 204);
    assert.equal(answers.filter(({ inline_query_id }) => inline_query_id === "fixture-uncertain").length, 1);
    const held = query(34, "", { id: "fixture-held" });
    try {
      await Promise.race([started.promise, held.then(() => assert.fail("Expected the inline request to reach its answer."))]);
      assert.equal((await query(35)).status, 204);
      assert.equal(await receipt(35), null);
    } finally {
      release.resolve();
    }
    assert.equal((await held).status, 204);
    assert.equal((await receipt(34))?.state, "sent");

    async function seedMany(count: number, start: number, title: string) {
      await db.prepare(`WITH RECURSIVE sequence(n) AS (SELECT ? UNION ALL SELECT n+1 FROM sequence WHERE n<?)
        INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
        SELECT ?,? || printf('%04d',n),'https://example.invalid/cap/' || printf('%d',n),'inline-cap-fixture-' || printf('%04d',n),unixepoch(),unixepoch()
        FROM sequence`).bind(start, start + count - 1, policy.memberId, title).run();
    }
    await seedMany(51, 1, "Cap ");
    assert.equal((await query(36, "Cap")).status, 204);
    assert.equal(titles()?.length, 50);
    assert.equal(titles()?.at(-1), "Cap 0050");
    await seedMany(457, 52, "Overflow ");
    assert.equal((await query(37, "DOUBLE  SPACE")).status, 204);
    assert.deepEqual(titles(), [], "a bounded scan never returns a partial inventory");
    assert.equal((await query(38)).status, 204);
    const limited = answers.length;
    assert.equal((await query(39)).status, 204);
    assert.equal(answers.length, limited, "the thirteenth admitted query in the window is suppressed");
    assert.equal(await receipt(39), null);

    assert.equal((await command(40, "/inline off")).status, 200);
    await expectCommand(40, /已关闭私聊内联搜索/u);
    assert.equal((await query(41)).status, 204);
    assert.equal(await receipt(41), null);
    assert.equal((await command(42, "/inline on")).status, 200);
    await expectCommand(42, /已开启私聊内联搜索/u);
    await db.prepare(`INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,unixepoch()-60,1)`)
      .bind(policy.botId, policy.memberId).run();
    assert.equal((await query(43)).status, 204);
    assert.equal(await receipt(43), null);
    const stored = await db.prepare("SELECT * FROM telegram_inline_search_receipts").all();
    assert.doesNotMatch(JSON.stringify(stored.results), /fixture-inline-|fixture-uncertain|DOUBLE|synthetic-|Straße|链接已省略/u);
    assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_inbox WHERE update_id IN (21,23,25,27,33,34)").first("count"), 0);
    await db.batch([
      db.prepare("UPDATE telegram_inline_search_receipts SET received_at=unixepoch()-93600,lease_until=unixepoch()-93592 WHERE update_id=21"),
      db.prepare("UPDATE telegram_inline_search_receipts SET state='sending',received_at=unixepoch()-30,lease_until=unixepoch()-22 WHERE update_id=33"),
    ]);
    const beforeRecovery = answers.length;
    assert.equal((await disabled.scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.equal(await receipt(21), null);
    assert.equal((await receipt(33))?.state, "uncertain");
    assert.equal(answers.length, beforeRecovery, "Cron never retries an inline answer");
  } finally {
    release.resolve();
    await runtime.dispose();
  }
});

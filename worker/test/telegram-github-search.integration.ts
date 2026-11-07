import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { TELEGRAM_GITHUB_SEARCH_MIGRATION, TELEGRAM_GITHUB_SEARCH_SCHEMA_SHA256 } from "../src/telegram/github-search.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

test("emitted Worker searches GitHub privately and preserves the outbox through a delayed lookup and send ambiguity",
  { timeout: 60_000 }, async () => {
    const directory = process.env.WORKER_TEST_BUNDLE_DIR;
    assert.ok(directory);
    const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
    const script = await readFile(join(directory, "index.js"));
    const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
    assert.equal(sha256(script), manifest.bundleSha256);
    const policy: TelegramPolicy = {
      botId: "77801", botUsername: "Fixture_Github_Bot", adminId: "77802", memberId: "77803", groupId: "-10077804",
      botToken: "77801:synthetic-token", webhookSecret: "synthetic-github-search-webhook",
    };
    const releaseLookup = Promise.withResolvers<void>();
    const releaseHelp = Promise.withResolvers<void>();
    const upstreamUrls: URL[] = [];
    type Sent = {
      chat_id: string; text: string; reply_parameters: { message_id: number };
      link_preview_options: unknown; reply_markup?: { inline_keyboard: Array<Array<{ text: string; url: string }>> };
    };
    const sent: Sent[] = [];
    let fallbackAttempts = 0;
    const runtime = new Miniflare({
      modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
      d1Databases: ["DB"], r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
      outboundService: async (request: Request) => {
        const url = new URL(request.url);
        if (url.origin !== "https://api.telegram.org") {
          upstreamUrls.push(url);
          assert.equal(url.origin + url.pathname, "https://api.github.com/search/repositories");
          assert.equal(request.method, "GET");
          assert.equal(request.headers.get("Authorization"), null);
          assert.equal(request.headers.get("Cookie"), null);
          assert.equal(request.headers.get("X-GitHub-Api-Version"), "2026-03-10");
          assert.equal(request.headers.get("Accept"), "application/vnd.github+json");
          if (url.searchParams.get("q") === "redirect-demo is:public") {
            return new Response(null, { status: 302, headers: { Location: "https://grep.app/api/search" } });
          }
          await releaseLookup.promise;
          return Response.json({ items: [
            { full_name: "octocat/Hello-World", private: false, visibility: "public", stargazers_count: 10,
              html_url: "https://github.com/octocat/Hello-World" },
            { full_name: "excluded/Private", private: true, stargazers_count: 20, html_url: "https://github.com/excluded/Private" },
          ] });
        }
        assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
        assert.equal(request.method, "POST");
        const body = await request.json() as Sent;
        assert.deepEqual(body.link_preview_options, { is_disabled: true });
        sent.push(body);
        const replyId = body.reply_parameters.message_id;
        if (replyId === 5) await releaseHelp.promise;
        if (replyId === 8) {
          fallbackAttempts++;
          if (fallbackAttempts === 1) {
            return Response.json({ ok: false, error_code: 429, parameters: { retry_after: 60 } }, { status: 429 });
          }
          return new Response("synthetic ambiguity", { status: 502 });
        }
        return Response.json({ ok: true, result: { message_id: 1000 + replyId, chat: { id: Number(body.chat_id) } } });
      },
    });
    try {
      const db = await runtime.getD1Database("DB");
      const migrations = manifest.migrations as { name: string; sha256: string }[];
      const search = migrations.find(({ name }) => name === TELEGRAM_GITHUB_SEARCH_MIGRATION);
      assert.equal(search?.sha256, TELEGRAM_GITHUB_SEARCH_SCHEMA_SHA256);
      assert.ok(search);
      for (const migration of migrations) {
        const bytes = await readFile(join(directory, migration.name));
        assert.equal(sha256(bytes), migration.sha256);
        await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
      }
      await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
      const now = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
      assert.ok(now);
      const date = now - 5;
      const post = (updateId: number, text: string, actorId = policy.memberId, chatId = actorId, messageDate = date,
        secret = policy.webhookSecret) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
        body: JSON.stringify({ update_id: updateId, message: { date: messageDate, message_id: updateId, text,
          from: { id: Number(actorId), is_bot: false }, chat: { id: Number(chatId), type: chatId === policy.groupId ? "supergroup" : "private" },
          entities: [{ type: "bot_command", offset: 0, length: text.split(" ")[0].length }] } }),
      });
      const state = (updateId: number) => db.prepare(`SELECT reply.state FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
        WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(policy.botId, updateId).first<string>("state");
      async function waitFor(ready: () => boolean | Promise<boolean>) {
        for (let attempt = 0; attempt < 100; attempt++) {
          if (await ready()) return;
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        assert.fail("The expected GitHub search stage was not observed.");
      }
      const publicQuery = "/g private-fixture-argument user:octocat in:name";
      assert.equal((await post(1, publicQuery)).status, 204, "unregistered migration must fail closed");
      await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (27,?,?,'applied')")
        .bind(search.name, "0".repeat(64)).run();
      assert.equal((await post(1, publicQuery)).status, 204, "unmatched migration digest must fail closed");
      await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE name=?").bind(search.sha256, search.name).run();
      assert.equal((await post(2, publicQuery, policy.memberId, policy.groupId)).status, 204);
      assert.equal((await post(2, publicQuery, "77999")).status, 204);
      assert.equal((await post(2, publicQuery, policy.memberId, policy.memberId, date, "wrong-secret")).status, 401);
      assert.equal((await post(2, publicQuery, policy.memberId, policy.memberId, now - 301)).status, 204);
      assert.equal((await post(3, "/g https://synthetic.invalid/with-credential")).status, 200);
      await waitFor(async () => await state(3) === "sent");
      assert.match(sent[0].text, /^用法/u);
      assert.equal(upstreamUrls.length, 0);

      assert.equal((await post(4, publicQuery)).status, 200);
      await waitFor(() => upstreamUrls.length === 1);
      assert.equal((await post(4, publicQuery)).status, 204);
      assert.equal(await state(4), null);
      assert.equal((await post(5, "/help")).status, 200);
      await waitFor(async () => await state(5) === "sending");
      releaseLookup.resolve();
      await waitFor(async () => await state(4) === "pending");
      assert.equal(sent.filter((item) => item.reply_parameters.message_id === 4).length, 0);
      releaseHelp.resolve();
      await waitFor(async () => await state(4) === "sent");
      const answer = sent.find((item) => item.reply_parameters.message_id === 4);
      assert.equal(answer?.chat_id, policy.memberId);
      assert.equal(answer?.text, "GitHub 公开仓库\noctocat/Hello-World · ★ 10");
      assert.deepEqual(answer.reply_markup?.inline_keyboard.flat().map(({ url }) => url),
        ["https://github.com/octocat/Hello-World", "https://github.com/search?type=code"]);
      assert.equal(upstreamUrls[0].searchParams.get("q"), "private-fixture-argument user:octocat in:name is:public");
      assert.equal(upstreamUrls[0].searchParams.get("order"), "desc");

      assert.equal((await post(8, "/g redirect-demo", policy.adminId)).status, 200);
      await waitFor(async () => fallbackAttempts === 1 && await state(8) === "pending");
      assert.equal((await post(8, "/g redirect-demo", policy.adminId)).status, 204);
      await db.prepare("UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id=(SELECT receipt_id FROM telegram_inbox WHERE update_id=8)").run();
      const worker = await runtime.getWorker();
      assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
      assert.equal(await state(8), "uncertain");
      assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
      assert.equal(fallbackAttempts, 2);
      assert.deepEqual(upstreamUrls.map(({ origin, pathname }) => origin + pathname),
        ["https://api.github.com/search/repositories", "https://api.github.com/search/repositories"]);
      const fallback = sent.filter((item) => item.reply_parameters.message_id === 8);
      assert.ok(fallback.every((item) => item.chat_id === policy.adminId && item.text === "暂时无法获取 GitHub 搜索结果。"));
      assert.ok(fallback.every((item) => item.reply_markup?.inline_keyboard[0][0].url === "https://github.com/search?type=code"));
      const stored = JSON.stringify((await db.prepare("SELECT * FROM telegram_github_search").all()).results);
      assert.doesNotMatch(stored, /private-fixture-argument|with-credential|redirect-demo|excluded|Hello-World/u);
    } finally {
      releaseLookup.resolve();
      releaseHelp.resolve();
      await runtime.dispose();
    }
  });

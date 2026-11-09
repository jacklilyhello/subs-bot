import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

const policy: TelegramPolicy = {
  botId: "75101", botUsername: "fixture_temp_raw_bot", adminId: "75102", memberId: "75103", groupId: "-10075104",
  botToken: "75101:synthetic-token", webhookSecret: "synthetic-temp-raw-webhook",
};
const first = "hy2://synthetic-auth@example.invalid:443#节点一";
const second = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Synthetic-Two";
const summary = (count: number) => `临时列表共有 ${count} 条节点。发送 /temp clear 清空。`;
type Send = { replyTo: number; chat: string; text?: string; caption?: string; file?: string };

test("emitted Worker returns exact private temporary URIs and one bounded plain document", { timeout: 60_000 }, async () => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sends: Send[] = [];
  let uncertainReplyTo = -1;
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy) },
    outboundService: async (request: Request) => {
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      assert.equal(request.method, "POST");
      let send: Send;
      if (request.url === api + "/sendMessage") {
        const body = await request.json() as {
          chat_id: string; text: string; reply_parameters: { message_id: number }; link_preview_options: unknown;
          parse_mode?: string; message_thread_id?: number;
        };
        assert.deepEqual(body.link_preview_options, { is_disabled: true });
        assert.equal(body.parse_mode, undefined);
        assert.equal(body.message_thread_id, undefined);
        send = { chat: body.chat_id, replyTo: body.reply_parameters.message_id, text: body.text };
      } else {
        assert.equal(request.url, api + "/sendDocument");
        const form = await request.formData();
        const file = form.get("document");
        assert.ok(file && typeof file !== "string");
        assert.equal(file.name, "temporary-nodes.txt");
        assert.match(file.type, /^text\/plain(?:;\s*charset=utf-8)?$/iu);
        assert.equal(form.get("parse_mode"), null);
        assert.equal(form.get("message_thread_id"), null);
        send = { chat: String(form.get("chat_id")), replyTo: JSON.parse(String(form.get("reply_parameters"))).message_id,
          caption: String(form.get("caption")), file: await file.text() };
      }
      sends.push(send);
      if (send.replyTo === uncertainReplyTo) return Response.json({ ok: false, error_code: 500 }, { status: 500 });
      return Response.json({ ok: true, result: { message_id: 100 + sends.length, chat: { id: Number(send.chat) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    for (const migration of manifest.migrations) {
      const bytes = await readFile(join(directory, migration.name));
      assert.equal(createHash("sha256").update(bytes).digest("hex"), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
      await recordTempFixtureMigration(db, migration);
    }
    const date = Math.floor(Date.now() / 1000);
    const event = (id: number, text: string, owner = policy.memberId, chat = owner) => ({
      update_id: id, message: { message_id: id, date, text, from: { id: Number(owner), is_bot: false },
        chat: { id: Number(chat), type: chat === policy.groupId ? "supergroup" : "private" },
        entities: text.startsWith("/temp") ? [{ type: "bot_command", offset: 0, length: 5 }] : [],
      },
    });
    const post = (update: unknown) => runtime.dispatchFetch("https://worker.example.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify(update),
    });
    const outbox = (id: number) => db.prepare(`SELECT outbox.state FROM telegram_outbox AS outbox
      JOIN telegram_inbox AS inbox USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
      .bind(policy.botId, id).first<string>("state");
    async function waitForSend(id: number, state = "sent"): Promise<Send> {
      for (let i = 0; i < 50; i++) {
        const row = sends.find(({ replyTo }) => replyTo === id);
        if (row && await outbox(id) === state) return row;
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
      assert.fail("Synthetic temporary-node reply did not settle.");
    }
    async function send(id: number, text: string, owner = policy.memberId) {
      assert.equal((await post(event(id, text, owner))).status, 200);
      return waitForSend(id);
    }

    const short = [first, second, first];
    await send(1, Buffer.from(short.join("\n"), "utf8").toString("base64"));
    assert.equal((await post(event(2, "/temp", policy.memberId, policy.groupId))).status, 204);
    assert.equal(await outbox(2), null);
    assert.deepEqual(await send(3, "/temp", policy.adminId), { replyTo: 3, chat: policy.adminId, text: summary(0) });
    assert.deepEqual(await send(4, "/temp summary"), { replyTo: 4, chat: policy.memberId, text: summary(short.length) });
    assert.deepEqual(await send(5, "/temp"), { replyTo: 5, chat: policy.memberId, text: summary(short.length) + "\n\n" + short.join("\n") });

    const more = ["A", "B"].map((suffix) => Array.from({ length: 35 }, () => second + "-fixture-" + suffix));
    for (const [index, lines] of more.entries()) {
      assert.ok(lines.join("\n").length <= 4096);
      await send(6 + index, lines.join("\n"));
    }
    const all = [...short, ...more.flat()];
    const doc = await send(8, "/temp");
    assert.deepEqual(doc, { replyTo: 8, chat: policy.memberId, caption: summary(all.length), file: all.join("\n") });
    const uncertain = event(9, "/temp");
    uncertainReplyTo = 9;
    assert.equal((await post(uncertain)).status, 200);
    await waitForSend(9, "uncertain");
    assert.equal((await post(uncertain)).status, 200);
    assert.equal((await (await runtime.getWorker()).scheduled({ cron: "* * * * *" })).outcome, "ok");
    assert.equal(sends.filter(({ replyTo }) => replyTo === 9).length, 1);
    assert.equal(await outbox(9), "uncertain");
    await send(10, "/temp clear");
    assert.deepEqual(await send(11, "/temp"), { replyTo: 11, chat: policy.memberId, text: summary(0) });
    assert.equal(await db.prepare("SELECT count(*) AS total FROM telegram_temp_batch").first("total"), 0);
    for (const table of ["telegram_inbox", "telegram_outbox", "telegram_temp_reply"]) {
      const result = await db.prepare(`SELECT * FROM ${table}`).all();
      assert.doesNotMatch(JSON.stringify(result.results), /synthetic-auth|203\.0\.113\.10|fixture-A|temporary-nodes\.txt/u);
    }
  } finally {
    await runtime.dispose();
  }
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";

import { enqueueProviderUrlImport } from "../src/provider-jobs.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "76201", adminId: "76202", memberId: "76203", groupId: "-10076204",
  botUsername: "FixtureProviderBot", botToken: "76201:synthetic-token", webhookSecret: "synthetic-provider-webhook",
};
const sourceUrl = "https://provider.example.invalid/path/%2F?z=synthetic-secret%2Bvalue&a=1";
const share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Synthetic";
const providerRevision = "a".repeat(40);
const imageSha256 = "b".repeat(64);

test("emitted Worker admits private provider URLs only after opt-in and delivers durable terminal replies", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sent: { id: number; chat: string; origin: number; text: string }[] = [];
  const common = {
    modules: true, script, compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "telegram-provider-fixture" }, r2Buckets: { NODES: "telegram-provider-fixture" },
    serviceBindings: { PROVIDER_FETCH: { name: "provider", entrypoint: "ProviderFetch" } },
    outboundService: async (request: Request) => {
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      const body = await request.json() as { chat_id: string; reply_parameters: { message_id: number }; text: string };
      assert.doesNotMatch(body.text, /provider\.example\.invalid|synthetic-secret|private label|ss:\/\//u);
      const message = { id: 1000 + sent.length, chat: body.chat_id, origin: body.reply_parameters.message_id, text: body.text };
      sent.push(message);
      return Response.json({ ok: true, result: { message_id: message.id, chat: { id: Number(message.chat) } } });
    },
  };
  const bindings = { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_INLINE_SEARCH: "1",
    PROVIDER_REVISION: providerRevision, PROVIDER_IMAGE_SHA256: imageSha256 };
  const runtime = new Miniflare({ workers: [
    { ...common, name: "app", bindings: { ...bindings, TELEGRAM_PROVIDER_URL_IMPORT: "1" } },
    { ...common, name: "disabled", bindings },
    { name: "provider", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases: common.d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderFetch extends WorkerEntrypoint {
          async fetchSubscription(input) {
            if (Object.keys(input).length !== 3 || input.url !== ${JSON.stringify(sourceUrl)}
                || input.providerRevision !== ${JSON.stringify(providerRevision)} || input.imageSha256 !== ${JSON.stringify(imageSha256)}) {
              throw new Error('Unexpected synthetic provider input.');
            }
            await this.env.DB.prepare('UPDATE provider_url_fixture SET calls=calls+1').run();
            const body = new TextEncoder().encode(${JSON.stringify(share)}).buffer;
            const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
            return {ok:true,body,bodySha256:Array.from(hash, byte => byte.toString(16).padStart(2,'0')).join('')};
          }
        }
        export default {fetch(){return new Response(null,{status:404})}};` },
  ] });
  t.after(() => runtime.dispose());

  const db = await runtime.getD1Database("DB", "app");
  const app = await runtime.getWorker("app");
  const disabled = await runtime.getWorker("disabled");
  async function migration(entry: { name: string; sha256: string }) {
    const sql = await readFile(join(directory!, entry.name), "utf8");
    assert.equal(createHash("sha256").update(sql).digest("hex"), entry.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  const providerMigration = manifest.migrations.find((entry: { name: string }) => entry.name === "0023_telegram_provider_replies.sql");
  assert.ok(providerMigration);
  for (const entry of manifest.migrations) if (entry !== providerMigration) await migration(entry);
  await db.batch([db.prepare("CREATE TABLE provider_url_fixture (calls INTEGER NOT NULL)"),
    db.prepare("INSERT INTO provider_url_fixture VALUES (0)")]);

  let sequence = 0;
  const calls = () => db.prepare("SELECT calls FROM provider_url_fixture").first<number>("calls");
  const scopedCount = () => db.prepare("SELECT count(*) AS total FROM telegram_provider_jobs").first<number>("total");
  const originCount = () => db.prepare("SELECT count(*) AS total FROM telegram_provider_requests").first<number>("total");
  const now = () => Math.floor(Date.now() / 1000);
  const message = (text: string, actor = policy.adminId, chatId = actor) => {
    const id = ++sequence;
    return { update_id: id, message: { message_id: id, date: now(), from: { id: Number(actor), is_bot: false },
      chat: { id: Number(chatId), type: chatId === policy.groupId ? "supergroup" : "private" }, text } };
  };
  const post = (body: unknown, worker = app) => worker.fetch("https://worker.example.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify(body),
  });
  const cron = async (worker = app) => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  async function expectSent(id: number, owner: string, expected: string) {
    for (let attempt = 0; attempt < 50; attempt++) {
      const reply = sent.find((entry) => entry.origin === id);
      if (reply && await db.prepare("SELECT state FROM telegram_outbox WHERE sent_message_id=?")
        .bind(reply.id).first("state") === "sent") {
        assert.deepEqual({ chat: reply.chat, text: reply.text }, { chat: owner, text: expected });
        return;
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.fail("Synthetic provider terminal reply did not settle.");
  }

  assert.equal((await post(message(sourceUrl))).status, 200);
  assert.equal(await originCount(), 0, "0023 schema is required despite a valid named binding and flag");
  await migration(providerMigration);
  assert.equal((await post(message(sourceUrl), disabled)).status, 200);
  assert.equal(await originCount(), 0, "binding alone never enables Telegram intake");
  const generic = await enqueueProviderUrlImport(db, { ownerId: "76205", requestKey: "c".repeat(64), sourceUrl });
  assert.equal(generic.kind, "queued");
  await cron(disabled);
  assert.equal(await calls(), 1, "disabled Telegram intake keeps the generic consumer running");

  assert.equal((await post(message(sourceUrl, policy.adminId, policy.groupId))).status, 204);
  assert.equal((await post(message(sourceUrl, "76205"))).status, 204);
  assert.equal((await post(message(`${sourceUrl}\n${share}`))).status, 200);
  const rename = message(sourceUrl);
  assert.equal((await post({ ...rename, message: { ...rename.message, reply_to_message: {
    message_id: rename.update_id - 1, date: rename.message.date, chat: rename.message.chat,
    from: { id: Number(policy.botId), is_bot: true },
  } } })).status, 200);
  assert.equal(await originCount(), 0, "group, multiline text and explicit rename replies never admit provider work");

  const admin = message(sourceUrl);
  const member = message(`private label | ${sourceUrl}`, policy.memberId);
  for (const update of [admin, admin, member]) assert.equal((await post(update)).status, 200);
  assert.equal(await originCount(), 2);
  assert.equal(await scopedCount(), 2);
  assert.equal(await calls(), 1, "webhook does not invoke the provider");
  assert.equal((await post(message(sourceUrl), disabled)).status, 200);
  assert.equal(await originCount(), 2, "switching off admission does not create another provider origin");
  assert.equal(await scopedCount(), 2, "switching off admission preserves already-queued jobs");
  await db.prepare("UPDATE telegram_inbox SET received_at=unixepoch()-901 WHERE update_id=?").bind(admin.update_id).run();
  await cron(disabled);
  await expectSent(admin.update_id, policy.adminId, "远程订阅已导入。发送 /list 查看。");
  await cron(disabled);
  await expectSent(member.update_id, policy.memberId, "远程订阅已导入。发送 /list 查看。");
  assert.equal(await calls(), 3);
  const sub = await db.prepare("SELECT source_url AS source,name,token FROM subscriptions WHERE owner_id=?")
    .bind(policy.memberId).first<{ source: string; name: string; token: string }>();
  assert.equal(sub?.source, sourceUrl);
  assert.equal(sub?.name, "private label");
  const exported = await app.fetch(`https://worker.example.invalid/sub/${sub!.token}/base64`);
  assert.equal(exported.status, 200);
  assert.equal(await exported.text(), Buffer.from(share).toString("base64"));

  const invalid = message("https://synthetic-secret@provider.example.invalid/config");
  assert.equal((await post(invalid)).status, 200);
  await expectSent(invalid.update_id, policy.adminId, "订阅链接无效。请发送单条 HTTP 或 HTTPS 链接。");
  assert.equal(await scopedCount(), 2);

  const revoked = message(sourceUrl, policy.memberId);
  assert.equal((await post(revoked)).status, 200);
  await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,0,?,?)")
    .bind(policy.botId, policy.memberId, now(), revoked.update_id + 1).run();
  await cron();
  assert.equal(await calls(), 3);
  assert.equal(await db.prepare(`SELECT job.result_code FROM telegram_inbox JOIN telegram_provider_requests USING (receipt_id)
    JOIN telegram_provider_jobs AS job USING (job_id) WHERE update_id=?`).bind(revoked.update_id).first("result_code"), "stale-target");
  assert.ok(!sent.some(({ origin }) => origin === revoked.update_id));
  assert.equal(sent.filter(({ origin }) => origin === admin.update_id).length, 1);
});

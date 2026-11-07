import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";

import { createSubscription, getSubscriptionSnapshot, publishNodeSnapshot } from "../src/storage.ts";
import { renameOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "78201", adminId: "78202", memberId: "78203", groupId: "-10078204",
  botUsername: "FixtureRefreshBot", botToken: "78201:synthetic-token", webhookSecret: "synthetic-provider-refresh-webhook",
};
const sourceUrl = "https://provider.example.invalid/path/%2F?z=synthetic-refresh-secret%2Bvalue&a=1";
const initialShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Initial";
const refreshedShare = initialShare.replace("#Initial", "#Refreshed");
const providerRevision = "a".repeat(40);
const imageSha256 = "b".repeat(64);
const digest = (value: Buffer | string) => createHash("sha256").update(value).digest("hex");

test("emitted Worker refreshes only the owned version pinned by a private sent detail", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  assert.equal(digest(script), manifest.bundleSha256);
  type Button = { text: string; callback_data: string };
  const sent: { id: number; text: string; buttons: Button[] }[] = [];
  const common = {
    modules: true, script, compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "provider-refresh-fixture" }, r2Buckets: { NODES: "provider-refresh-fixture" },
    serviceBindings: { PROVIDER_FETCH: { name: "provider", entrypoint: "ProviderFetch" } },
    outboundService: async (request: Request) => {
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      assert.equal(request.method, "POST");
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage");
      const body = await request.json() as { chat_id: string; text: string; reply_markup?: { inline_keyboard: Button[][] } };
      assert.equal(body.chat_id, policy.memberId);
      assert.doesNotMatch(body.text, /provider\.example\.invalid|synthetic-refresh-secret|ss:\/\//u);
      const id = 1000 + sent.length;
      sent.push({ id, text: body.text, buttons: body.reply_markup?.inline_keyboard.flat() ?? [] });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    },
  };
  const bindings = { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
    PROVIDER_REVISION: providerRevision, PROVIDER_IMAGE_SHA256: imageSha256 };
  const runtime = new Miniflare({ workers: [
    { ...common, name: "app", bindings: { ...bindings, TELEGRAM_PROVIDER_URL_IMPORT: "1" } },
    { ...common, name: "disabled", bindings },
    { name: "provider", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases: common.d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderFetch extends WorkerEntrypoint {
          async fetchSubscription(input) {
            if (input.url !== ${JSON.stringify(sourceUrl)} || input.providerRevision !== ${JSON.stringify(providerRevision)}
              || input.imageSha256 !== ${JSON.stringify(imageSha256)}) throw new Error('Unexpected synthetic refresh input.');
            const calls = await this.env.DB.prepare('UPDATE provider_refresh_fixture SET calls=calls+1 RETURNING calls').first('calls');
            if (calls === 1) return {ok:false,code:'http-status',retryable:false,upstreamStatus:404};
            const body = new TextEncoder().encode(${JSON.stringify(refreshedShare)}).buffer;
            const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
            return {ok:true,body,bodySha256:Array.from(hash, byte => byte.toString(16).padStart(2,'0')).join('')};
          }
        }
        export default {fetch(){return new Response(null,{status:404})}};` },
  ] });
  t.after(() => runtime.dispose());
  const app = await runtime.getWorker("app");
  const disabled = await runtime.getWorker("disabled");
  const db = await runtime.getD1Database("DB", "app");
  const bucket = await runtime.getR2Bucket("NODES", "app");
  const migrations = manifest.migrations as { name: string; sha256: string }[];
  const refreshMigration = migrations.find(({ name }) => name === "0028_telegram_provider_refresh_tickets.sql");
  assert.ok(refreshMigration);
  async function applyMigration(migration: (typeof migrations)[number]) {
    const sql = await readFile(join(directory!, migration.name), "utf8");
    assert.equal(digest(sql), migration.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  for (const migration of migrations) if (migration !== refreshMigration) await applyMigration(migration);
  await db.batch([db.prepare("CREATE TABLE provider_refresh_fixture (calls INTEGER NOT NULL)"),
    db.prepare("INSERT INTO provider_refresh_fixture VALUES (0)")]);
  const ownerId = policy.memberId;
  const sub = await createSubscription(db, { ownerId, name: "Owned synthetic", sourceUrl });
  const uploaded = await createSubscription(db, { ownerId, name: "Static synthetic", sourceUrl: "uploaded://fixture.txt" });
  for (const row of [sub, uploaded]) assert.equal(await publishNodeSnapshot(db, bucket, {
    id: row.id, ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0,
  }, [{ name: "Synthetic node", share: initialShare }]), true);
  const initial = await getSubscriptionSnapshot(db, sub.token);
  const date = Math.floor(Date.now() / 1000);
  const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
  const post = (update: unknown, worker = app) => worker.fetch("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify(update),
  });
  const click = (updateId: number, sentId: number, ticket: string, worker = app, actor = ownerId, chatId = actor) =>
    post({ update_id: updateId, callback_query: { id: `fixture-refresh-${updateId}`, data: ticket,
      from: { id: Number(actor), is_bot: false }, message: { message_id: sentId, date, chat: chat(chatId),
        from: { id: Number(policy.botId), is_bot: true } } } }, worker);
  const receipt = (updateId: number) => db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
    .bind(policy.botId, updateId).first<number>("receipt_id");
  const calls = () => db.prepare("SELECT calls FROM provider_refresh_fixture").first<number>("calls");
  const cron = async () => assert.equal((await app.scheduled({ cron: "* * * * *" })).outcome, "ok");
  async function reply(updateId: number) {
    for (let attempt = 0; attempt < 60; attempt++) {
      const id = await db.prepare(`SELECT sent_message_id FROM telegram_inbox JOIN telegram_outbox USING (receipt_id)
        WHERE bot_id=? AND update_id=? AND state='sent'`).bind(policy.botId, updateId).first<number>("sent_message_id");
      const found = sent.find((item) => item.id === id);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.fail("Expected synthetic refresh reply did not settle.");
  }
  async function detail(updateId: number, position = "1", worker = app) {
    const response = await post({ update_id: updateId, message: { message_id: updateId, date, chat: chat(ownerId),
      from: { id: Number(ownerId), is_bot: false }, text: position } }, worker);
    assert.equal(response.status, 200);
    const message = await reply(updateId);
    const ticket = message.buttons.find(({ text }) => text === "刷新订阅")?.callback_data;
    if (ticket) assert.match(ticket, /^sbpr1_[A-Za-z0-9_-]{21}[AQgw]$/u);
    return { ...message, ticket };
  }

  assert.equal((await detail(1)).ticket, undefined);
  await applyMigration(refreshMigration);
  assert.equal((await detail(2, "1", disabled)).ticket, undefined);
  assert.equal((await detail(3, "2")).ticket, undefined);
  const oldGrant = await detail(4);
  assert.ok(oldGrant.ticket);
  await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,?)")
    .bind(policy.botId, ownerId, date - 1, 100).run();
  assert.equal((await click(5, oldGrant.id, oldGrant.ticket)).status, 200);
  assert.equal(await receipt(5), null);

  const failed = await detail(6);
  assert.ok(failed.ticket);
  const ticket = failed.ticket;
  assert.equal((await click(7, failed.id, ticket, disabled)).status, 204);
  assert.equal((await click(8, failed.id, ticket, app, policy.adminId)).status, 200);
  assert.equal((await click(9, failed.id, ticket, app, ownerId, policy.groupId)).status, 204);
  assert.equal((await click(10, failed.id + 1, ticket)).status, 200);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(sourceUrl + "&changed=1", sub.id).run();
  assert.equal((await click(11, failed.id, ticket)).status, 200);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(sourceUrl, sub.id).run();
  const setAttempt = (attempt: number) => db.prepare("UPDATE telegram_outbox SET attempts=? WHERE sent_message_id=?")
    .bind(attempt, failed.id).run();
  await setAttempt(2);
  assert.equal((await click(12, failed.id, ticket)).status, 200);
  await setAttempt(1);
  const expire = (offset: number) => db.prepare("UPDATE telegram_provider_refresh_tickets SET expires_at=unixepoch()+? WHERE token_sha256=?")
    .bind(offset, digest(ticket)).run();
  await expire(-1);
  assert.equal((await click(13, failed.id, ticket)).status, 200);
  await expire(600);
  for (const updateId of [7, 8, 9, 10, 11, 12, 13]) assert.equal(await receipt(updateId), null);
  for (const response of await Promise.all([click(14, failed.id, ticket), click(15, failed.id, ticket)])) {
    assert.equal(response.status, 200);
  }
  const firstReceipt = await receipt(14);
  const secondReceipt = await receipt(15);
  assert.notEqual(firstReceipt === null, secondReceipt === null);
  const accepted = firstReceipt === null ? 15 : 14;
  assert.equal((await click(accepted, failed.id, ticket)).status, 200);
  assert.equal(await calls(), 0, "the webhook queues without invoking the private provider");
  assert.deepEqual(await db.prepare(`SELECT source_sha256 AS sourceSha,used_by_receipt_id AS consumed
    FROM telegram_provider_refresh_tickets WHERE token_sha256=?`).bind(digest(ticket)).first(),
    { sourceSha: digest(sourceUrl), consumed: firstReceipt ?? secondReceipt });
  await cron();
  assert.equal((await reply(accepted)).text, "无法获取远程订阅。");
  assert.deepEqual(await getSubscriptionSnapshot(db, sub.token), initial);

  const stale = await detail(16);
  assert.ok(stale.ticket);
  assert.equal(await renameOwnedSubscription(db, { id: sub.id, ownerId, expectedLifecycleRevision: 0 }, "Renamed synthetic"), true);
  assert.equal((await click(17, stale.id, stale.ticket)).status, 200);
  assert.equal(await receipt(17), null);
  const generation = await detail(18);
  const good = await detail(19);
  assert.ok(generation.ticket && good.ticket);
  assert.equal((await click(20, good.id, good.ticket)).status, 200);
  await cron();
  assert.equal((await reply(20)).text, "远程订阅已刷新。发送 /list 查看。");
  assert.equal((await click(21, generation.id, generation.ticket)).status, 200);
  assert.equal(await receipt(21), null);
  assert.equal(await calls(), 2);
  assert.equal((await getSubscriptionSnapshot(db, sub.token))?.generation, 2);
  const exported = await app.fetch(`https://fixture.invalid/sub/${sub.token}/base64`);
  assert.equal(exported.status, 200);
  assert.equal(await exported.text(), Buffer.from(refreshedShare).toString("base64"));
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_provider_jobs WHERE kind='refresh'").first("count"), 2);
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";

import { TELEGRAM_API_STATUS_PROMPT } from "../src/telegram/api-status-input.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "79301", adminId: "79302", memberId: "79303", groupId: "-10079304",
  botUsername: "FixtureApiStatusBot", botToken: "79301:synthetic-token", webhookSecret: "synthetic-api-status-webhook",
};
const first = "https://api.example.invalid/first/models";
const second = "https://api.example.invalid/second/models";
const key = "synthetic-api-status-key";
const providerRevision = "a".repeat(40);
const imageSha256 = "b".repeat(64);
const subscriptionRevision = "c".repeat(40);
const subscriptionImage = "d".repeat(64);
const subscriptionBinding = { PROVIDER_FETCH: { name: "provider", entrypoint: "ProviderFetch" } };

const faultyWorker = `
  import worker from './index.js';
  function instrument(env) {
    const db = env.DB;
    return {...env, DB: {
      prepare(sql) {
        if ((env.FAULT === 'schema' && sql.includes('sqlite_schema') && sql.includes('telegram_api_status'))
          || (env.FAULT === 'before-rpc' && sql.includes('UPDATE telegram_api_status AS action'))) {
          return {bind() { return this; }, async first() { throw new Error('Synthetic API status interruption.'); }};
        }
        if (env.FAULT === 'short-lease' && sql.includes('UPDATE telegram_api_status AS action SET row_one=')) {
          sql = sql.replace('SET row_one=?', 'SET row_one=?,expires_at=min(expires_at,unixepoch()+8)');
        }
        return db.prepare(sql);
      },
      batch(statements) { return db.batch(statements); },
    }};
  }
  export default {
    fetch(request,env,ctx) { return worker.fetch(request,instrument(env),env.FAULT === 'hold-replies' ? undefined : ctx); },
    scheduled(controller,env,ctx) { return worker.scheduled(controller,instrument(env),ctx); },
  };
`;

test("emitted Worker scopes private API prompts and recovers without replaying credentials", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  const digest = (text: string) => createHash("sha256").update(text).digest("hex");
  assert.equal(digest(script), manifest.bundleSha256);
  type Sent = { id: number; chat_id: string; text: string; reply_markup?: { force_reply: boolean }; reply_parameters?: unknown };
  const sent: Sent[] = [];
  const common = {
    compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "api-status-fixture" }, r2Buckets: { NODES: "api-status-fixture" },
    serviceBindings: { ...subscriptionBinding, PROVIDER_API_STATUS: { name: "status-provider", entrypoint: "ProviderApiStatus" } },
    outboundService: async (request: Request) => {
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      assert.equal(request.method, "POST");
      const body = await request.json() as Omit<Sent, "id">;
      assert.ok([policy.adminId, policy.memberId].includes(body.chat_id));
      assert.doesNotMatch(JSON.stringify(body), /api\.example\.invalid|synthetic-api-status-key/u);
      const id = 3000 + sent.length;
      sent.push({ ...body, id });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    },
  };
  const bindings = { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
    PROVIDER_REVISION: subscriptionRevision, PROVIDER_IMAGE_SHA256: subscriptionImage, TELEGRAM_PROVIDER_URL_IMPORT: "1",
    PROVIDER_API_STATUS_REVISION: providerRevision, PROVIDER_API_STATUS_IMAGE_SHA256: imageSha256,
    TELEGRAM_PROVIDER_REFRESH: "1", TELEGRAM_PROVIDER_BATCH_REFRESH: "1" };
  const enabled = { ...bindings, TELEGRAM_API_STATUS: "1" };
  const faultModules = [{ type: "ESModule" as const, path: "fixture.js", contents: faultyWorker },
    { type: "ESModule" as const, path: "index.js", contents: script }];
  const runtime = new Miniflare({ workers: [
    { ...common, name: "app", modules: true, script, bindings: enabled },
    { ...common, name: "off", modules: true, script, bindings },
    { ...common, name: "no-v2", modules: true, script, bindings: enabled, serviceBindings: subscriptionBinding },
    ...(["schema", "before-rpc", "hold-replies", "short-lease"] as const).map((fault) => ({ ...common, name: fault, modules: faultModules,
      bindings: { ...enabled, FAULT: fault } })),
    { name: "provider", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases: common.d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderFetch extends WorkerEntrypoint {
          async fetchSubscription() { throw new Error('Unexpected synthetic subscription RPC.'); }
          async probeApiStatus() { throw new Error('Unexpected V1 API status fallback.'); }
        }
        export default {fetch(){return new Response(null,{status:404})}};` },
    { name: "status-provider", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases: common.d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderApiStatus extends WorkerEntrypoint {
          async probeApiStatusV2(input) {
            const ordinal = input.url === ${JSON.stringify(first)} ? 1 : input.url === ${JSON.stringify(second)} ? 2 : 0;
            if (!ordinal || input.key !== ${JSON.stringify(key)}
              || input.providerRevision !== ${JSON.stringify(providerRevision)} || input.imageSha256 !== ${JSON.stringify(imageSha256)}
              || !Number.isSafeInteger(input.dispatchBeforeMs) || input.dispatchBeforeMs <= Date.now()
              || input.dispatchBeforeMs > Date.now() + 20_000) {
              throw new Error('Unexpected synthetic API status input.');
            }
            await this.env.DB.prepare('INSERT INTO api_status_fixture_calls (ordinal,dispatch_before_ms) VALUES (?,?)')
              .bind(ordinal,input.dispatchBeforeMs).run();
            return {ok:true,status:ordinal === 1 ? 200 : 401,elapsedMs:ordinal * 10};
          }
        }
        export default {fetch(){return new Response(null,{status:404})}};` },
  ] });
  t.after(() => runtime.dispose());
  const app = await runtime.getWorker("app");
  const off = await runtime.getWorker("off");
  const fault = await runtime.getWorker("schema");
  const interrupted = await runtime.getWorker("before-rpc");
  const held = await runtime.getWorker("hold-replies");
  const noV2 = await runtime.getWorker("no-v2");
  const shortLease = await runtime.getWorker("short-lease");
  const db = await runtime.getD1Database("DB", "app");
  const migrations = manifest.migrations as { name: string; sha256: string }[];
  const api = migrations.find(({ name }) => name === "0034_telegram_api_status.sql");
  assert.ok(api);
  async function migrate(migration: (typeof migrations)[number]) {
    const sql = await readFile(join(directory!, migration.name), "utf8");
    assert.equal(digest(sql), migration.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  for (const migration of migrations) if (migration !== api) await migrate(migration);
  await db.prepare("CREATE TABLE api_status_fixture_calls (id INTEGER PRIMARY KEY, ordinal INTEGER NOT NULL, dispatch_before_ms INTEGER NOT NULL)").run();
  const owner = policy.memberId;
  const date = Math.floor(Date.now() / 1000);
  const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
  const send = (id: number, text: string, worker = app, actor = owner, chatId = actor, replied?: Sent) =>
    worker.fetch("https://fixture.invalid/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
      body: JSON.stringify({ update_id: id, message: {
        message_id: 10_000 + id, date, text, chat: chat(chatId), from: { id: Number(actor), is_bot: false },
        ...(text.startsWith("/") ? { entities: [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] } : {}),
        ...(replied ? { reply_to_message: { message_id: replied.id, date, text: replied.text,
          chat: chat(replied.chat_id), from: { id: Number(policy.botId), is_bot: true } } } : {}),
      } }) });
  const receipt = (id: number) => db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
    .bind(policy.botId, id).first<number>("receipt_id");
  const calls = async () => (await db.prepare("SELECT ordinal FROM api_status_fixture_calls ORDER BY id").all())
    .results.map(({ ordinal }) => ordinal);
  const cron = async (worker = off) => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  async function reply(id: number) {
    for (let attempt = 0; attempt < 60; attempt++) {
      const sentId = await db.prepare(`SELECT sent_message_id FROM telegram_inbox JOIN telegram_outbox USING(receipt_id)
        WHERE bot_id=? AND update_id=? AND state='sent'`).bind(policy.botId, id).first<number>("sent_message_id");
      const message = sent.find(({ id: value }) => value === sentId);
      if (message) return message;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.fail("Synthetic API status reply was not sent.");
  }
  async function prompt(id: number, actor = owner) {
    assert.equal((await send(id, "/ai", app, actor)).status, 200);
    const message = await reply(id);
    assert.equal(message.text, TELEGRAM_API_STATUS_PROMPT);
    assert.deepEqual(message.reply_markup, { force_reply: true });
    return message;
  }

  assert.equal((await send(1, "/ai")).status, 204);
  await migrate(api);
  assert.equal((await send(2, "/ai", off)).status, 204);
  assert.equal((await send(3, "/ai", app, owner, policy.groupId)).status, 204);
  assert.equal((await send(4, `/ai ${first}|${key}`)).status, 204);
  assert.equal((await send(5, `${first} | ${key}`, off)).status, 204);
  assert.equal((await send(6, "/ai", fault)).status, 204);
  for (const id of [1, 2, 3, 4, 5, 6]) assert.equal(await receipt(id), null);
  assert.equal((await send(7, "/help", fault)).status, 200);
  assert.match((await reply(7)).text, /\/list/u);
  await cron(fault);
  const outdated = await prompt(8);
  const open = await prompt(9);
  assert.equal((await send(10, `${first}|${key}`, app, owner, owner, outdated)).status, 200);
  assert.equal((await send(11, `${first}|${key}`, app, policy.adminId, policy.adminId,
    { ...open, chat_id: policy.adminId })).status, 200);
  assert.equal((await send(12, `${first}|${key}`, app, owner, owner, { ...open, id: open.id + 1 })).status, 200);
  for (const id of [10, 11, 12]) assert.equal(await receipt(id), null);
  const text = `${first}|${key}\r\n${second} ${key}`;
  assert.deepEqual((await Promise.all([send(13, text, app, owner, owner, open), send(14, text, app, owner, owner, open)]))
    .map(({ status }) => status), [200, 200]);
  const admitted = await Promise.all([receipt(13), receipt(14)]);
  assert.notEqual(admitted[0] === null, admitted[1] === null);
  const acceptedId = admitted[0] === null ? 14 : 13;
  const result = await reply(acceptedId);
  assert.equal(result.text, "API 状态\n1. HTTP 200 · 10 ms\n2. HTTP 401 · 20 ms");
  assert.equal(result.reply_parameters, undefined);
  assert.equal(result.reply_markup, undefined);
  assert.equal((await send(acceptedId, text, app, owner, owner, open)).status, 200);
  assert.deepEqual(await calls(), [1, 2]);

  const abandoned = await prompt(15);
  assert.equal((await send(16, text, interrupted, owner, owner, abandoned)).status, 200);
  const abandonedId = await receipt(16);
  assert.ok(abandonedId);
  await db.prepare("UPDATE telegram_api_status SET row_one=-2,expires_at=unixepoch()-1 WHERE receipt_id=?").bind(abandonedId).run();
  await cron();
  assert.equal((await reply(16)).text, "API 状态\n1. 暂时无法确认。\n2. 暂时无法确认。");
  await cron();
  assert.deepEqual(await calls(), [1, 2]);

  const revoked = await prompt(17);
  await db.prepare("INSERT INTO telegram_auth VALUES (?,?,1,?,1)").bind(policy.botId, owner, date).run();
  assert.equal((await send(18, text, app, owner, owner, revoked)).status, 200);
  assert.equal(await receipt(18), null);
  const adminPrompt = await prompt(19, policy.adminId);
  assert.equal((await send(20, "/cancel", app, policy.adminId, policy.adminId, adminPrompt)).status, 200);
  assert.equal((await reply(20)).text, "API 状态\n1. 已取消。");

  // Real prompt admission with delivery paused leaves a valid older API outbox row.
  const admin = policy.adminId;
  assert.equal((await send(21, "/ai", held, admin)).status, 200);
  const heldId = await receipt(21);
  assert.ok(heldId);
  const outbox = (id: number) => db.prepare(`SELECT state,attempts FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
    WHERE bot_id=? AND update_id=?`).bind(policy.botId, id).first();
  assert.deepEqual(await outbox(21), { state: "pending", attempts: 0 });
  assert.equal((await send(22, "/help", fault, admin)).status, 200);
  assert.match((await reply(22)).text, /\/list/u);
  assert.deepEqual(await outbox(21), { state: "pending", attempts: 0 });
  for (const [id, state] of [[23, "leased"], [24, "sending"]] as const) {
    await db.prepare("UPDATE telegram_outbox SET state=?,attempts=1,lease_id=?,lease_until=unixepoch()+90 WHERE receipt_id=?")
      .bind(state, `synthetic-api-status-${state}`, heldId).run();
    assert.equal((await send(id, "/help", fault, admin)).status, 200);
    await cron(fault);
    assert.deepEqual(await outbox(id), { state: "pending", attempts: 0 });
    await db.prepare("UPDATE telegram_outbox SET lease_until=unixepoch()-1 WHERE receipt_id=?").bind(heldId).run();
    await cron(fault);
    assert.match((await reply(id)).text, /\/list/u);
    assert.deepEqual(await outbox(21), { state, attempts: 1 });
  }

  const named = "https://subscription.example.invalid/path?signature=fixture|value";
  assert.equal((await send(25, `Synthetic fixture | ${named}`, app, admin)).status, 200);
  assert.equal(await db.prepare("SELECT source_url FROM subscriptions WHERE owner_id=?").bind(policy.adminId)
    .first("source_url"), named);
  assert.equal((await send(26, "/ai", noV2, admin)).status, 204);
  assert.equal(await receipt(26), null);
  const deadlinePrompt = await prompt(27, admin);
  assert.equal((await send(28, `${first}|${key}`, shortLease, admin, admin, deadlinePrompt)).status, 200);
  assert.equal((await reply(28)).text, "API 状态\n1. HTTP 200 · 10 ms");
  const expiry = await db.prepare("SELECT expires_at FROM telegram_api_status WHERE receipt_id=?")
    .bind(await receipt(28)).first<number>("expires_at");
  assert.ok(expiry);
  assert.equal(await db.prepare("SELECT dispatch_before_ms FROM api_status_fixture_calls ORDER BY id DESC LIMIT 1")
    .first<number>("dispatch_before_ms"), expiry * 1000);
  const bare = "https://subscription.example.invalid/bare?signature=fixture|second";
  assert.equal((await send(29, bare, app, admin)).status, 200);
  assert.equal(await db.prepare("SELECT count(*) AS present FROM subscriptions WHERE owner_id=? AND source_url=?")
    .bind(admin, bare).first<number>("present"), 1);
  for (const table of ["telegram_api_status", "telegram_inbox", "telegram_outbox", "subscriptions", "telegram_provider_jobs"]) {
    const rows = await db.prepare(`SELECT * FROM ${table}`).all();
    assert.doesNotMatch(JSON.stringify(rows.results), /api\.example\.invalid|synthetic-api-status-key/u);
  }
  assert.deepEqual(await calls(), [1, 2, 1]);
});

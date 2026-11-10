import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";

import { createSubscription, getSubscriptionSnapshot, publishNodeSnapshot } from "../src/storage.ts";
import { renameOwnedSubscription } from "../src/subscriptions.ts";
import { readFailedBatchTrash } from "../src/telegram/provider-batch-failed-trash.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "79201", adminId: "79202", memberId: "79203", groupId: "-10079204",
  botUsername: "FixtureBatchBot", botToken: "79201:synthetic-token", webhookSecret: "synthetic-provider-batch-webhook",
};
const source = "https://provider.example.invalid/path/%2F?secret=synthetic-batch-source";
const failing = source + "&fail=1";
const secondFailing = source + "&fail=2";
const oldShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Initial";
const newShare = oldShare.replace("#Initial", "#Refreshed");
const providerRevision = "a".repeat(40);
const imageSha256 = "b".repeat(64);
const digest = (value: string) => createHash("sha256").update(value).digest("hex");

const readinessFaultModule = `
  import worker from './index.js';
  function instrument(env) {
    const db = env.DB;
    return {...env, DB: {
      prepare(sql) {
        if (sql.includes('sqlite_schema') && sql.includes(env.READINESS_FAULT)) {
          return {async first() { throw new Error('Synthetic provider batch readiness failure.'); }};
        }
        if (env.READINESS_FAULT === 'report-grant' && sql.includes('SELECT job.ordinal,job.subscription_id AS id')) {
          return {bind(...args) { return {async all() {
            const result = await db.prepare(sql).bind(...args).all();
            const {botId,memberId} = JSON.parse(env.TELEGRAM_ISOLATION_CONFIG);
            await db.prepare('INSERT INTO telegram_auth VALUES (?,?,0,unixepoch(),1)').bind(botId,memberId).run();
            return result;
          }}; }};
        }
        return db.prepare(sql);
      },
      batch(statements) { return db.batch(statements); },
    }};
  }
  export default {
    fetch(request, env, ctx) { return worker.fetch(request, instrument(env), ctx); },
    scheduled(controller, env, ctx) { return worker.scheduled(controller, instrument(env), ctx); },
  };
`;

test("emitted Worker confirms a private frozen batch and drains it after intake is disabled", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  assert.equal(digest(script), manifest.bundleSha256);
  type Button = { text: string; callback_data: string };
  const sent: { id: number; text: string; buttons: Button[]; menu: string[] }[] = [];
  const common = {
    compatibilityDate: manifest.compatibilityDate,
    d1Databases: { DB: "provider-batch-controls-fixture" }, r2Buckets: { NODES: "provider-batch-controls-fixture" },
    serviceBindings: { PROVIDER_FETCH: { name: "provider", entrypoint: "ProviderFetch" } },
    outboundService: async (request: Request) => {
      const api = `https://api.telegram.org/bot${policy.botToken}`;
      assert.equal(request.method, "POST");
      if (request.url === api + "/answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "/sendMessage");
      const body = await request.json() as { chat_id: string; text: string;
        reply_markup?: { inline_keyboard?: Button[][]; keyboard?: { text: string }[][] } };
      assert.ok([policy.adminId, policy.memberId].includes(body.chat_id));
      assert.doesNotMatch(body.text, /provider\.example\.invalid|synthetic-batch-source|ss:\/\//u);
      const id = 2000 + sent.length;
      sent.push({ id, text: body.text, buttons: body.reply_markup?.inline_keyboard?.flat() ?? [],
        menu: body.reply_markup?.keyboard?.flat().map(({ text }) => text) ?? [] });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    },
  };
  const bindings = { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
    PROVIDER_REVISION: providerRevision, PROVIDER_IMAGE_SHA256: imageSha256, TELEGRAM_PROVIDER_URL_IMPORT: "1",
    TELEGRAM_PROVIDER_REFRESH: "1" };
  const faultModules = [{ type: "ESModule" as const, path: "fixture.js", contents: readinessFaultModule },
    { type: "ESModule" as const, path: "index.js", contents: script }];
  const runtime = new Miniflare({ workers: [
    { ...common, name: "app", modules: true, script, bindings: { ...bindings, TELEGRAM_PROVIDER_BATCH_REFRESH: "1" } },
    { ...common, name: "drain", modules: true, script, bindings },
    ...([["jobs", "telegram_provider_batch_jobs"], ["interactions", "telegram_provider_batch_interactions"],
      ["journal", "provider_snapshot_attempts"], ["report-grant", "report-grant"]] as const).map(([name, table]) => ({
      ...common, name: `fault-${name}`, modules: faultModules,
      bindings: { ...bindings, TELEGRAM_PROVIDER_BATCH_REFRESH: "1", READINESS_FAULT: table },
    })),
    { name: "provider", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases: common.d1Databases,
      script: `import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ProviderFetch extends WorkerEntrypoint {
          async fetchSubscription(input) {
            if (![ ${JSON.stringify(source)}, ${JSON.stringify(failing)}, ${JSON.stringify(secondFailing)} ].includes(input.url)
              || input.providerRevision !== ${JSON.stringify(providerRevision)} || input.imageSha256 !== ${JSON.stringify(imageSha256)}) {
              throw new Error('Unexpected synthetic batch provider input.');
            }
            await this.env.DB.prepare('UPDATE provider_batch_fixture SET calls=calls+1').run();
            if (input.url !== ${JSON.stringify(source)}) return {ok:false,code:'http-status',retryable:false,upstreamStatus:404};
            const body = new TextEncoder().encode(${JSON.stringify(newShare)}).buffer;
            const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', body));
            return {ok:true,body,bodySha256:Array.from(hash, byte => byte.toString(16).padStart(2,'0')).join('')};
          }
        }
        export default {fetch(){return new Response(null,{status:404})}};` },
  ] });
  t.after(() => runtime.dispose());
  const app = await runtime.getWorker("app");
  const drainOnly = await runtime.getWorker("drain");
  const queueFault = await runtime.getWorker("fault-jobs");
  const controlsFault = await runtime.getWorker("fault-interactions");
  const journalFault = await runtime.getWorker("fault-journal");
  const reportGrantFault = await runtime.getWorker("fault-report-grant");
  const db = await runtime.getD1Database("DB", "app");
  const bucket = await runtime.getR2Bucket("NODES", "app");
  const migrations = manifest.migrations as { name: string; sha256: string }[];
  const controls = migrations.find(({ name }) => name === "0032_telegram_provider_batch_controls.sql");
  const journal = migrations.find(({ name }) => name === "0033_provider_snapshot_journal.sql");
  assert.ok(controls && journal);
  async function apply(migration: (typeof migrations)[number]) {
    const sql = await readFile(join(directory!, migration.name), "utf8");
    assert.equal(digest(sql), migration.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  for (const migration of migrations) if (migration !== controls && migration !== journal) await apply(migration);
  await db.batch([db.prepare("CREATE TABLE provider_batch_fixture (calls INTEGER NOT NULL)"),
    db.prepare("INSERT INTO provider_batch_fixture VALUES (0)")]);
  const ownerId = policy.memberId;
  const rows = [];
  for (const [actor, name, url] of [[ownerId, "Saved fixture", source], [ownerId, `Failed fixture ${failing}`, failing],
    [ownerId, "Changed fixture", source + "&stale=1"], [ownerId, "Second failed fixture", secondFailing],
    [ownerId, "Local fixture", "uploaded://fixture.txt"],
    [policy.adminId, "Foreign fixture", source]]) {
    const row = await createSubscription(db, { ownerId: actor, name, sourceUrl: url });
    rows.push(row);
    assert.equal(await publishNodeSnapshot(db, bucket, {
      id: row.id, ownerId: actor, expectedGeneration: 0, expectedLifecycleRevision: 0,
    }, [{ name: "Synthetic", share: oldShare }]), true);
  }
  const [good, failed, stale, secondFailed, uploaded, foreign] = rows;
  const previous = await getSubscriptionSnapshot(db, failed.token);
  assert.ok(previous);
  const previousManifest = `subscriptions/${previous.id}/${previous.snapshotId}/manifest.json`;
  const previousBytes = await (await bucket.get(previousManifest))?.text();
  assert.ok(previousBytes);
  const date = Math.floor(Date.now() / 1000);
  const chat = (id: string) => ({ id: Number(id), type: id === policy.groupId ? "supergroup" : "private" });
  const post = (update: unknown, worker = app) => worker.fetch("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify(update),
  });
  const message = (updateId: number, text: string, worker = app, actor = ownerId, chatId = actor, messageDate = date) =>
    post({ update_id: updateId, message: { message_id: updateId, date: messageDate, chat: chat(chatId),
      from: { id: Number(actor), is_bot: false }, text,
      ...(text.startsWith("/") ? { entities: [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] } : {}) } }, worker);
  const click = (updateId: number, sentId: number, ticket: string, worker = app, actor = ownerId, chatId = actor) =>
    post({ update_id: updateId, callback_query: { id: `fixture-batch-${updateId}`, data: ticket,
      from: { id: Number(actor), is_bot: false }, message: { message_id: sentId, date, chat: chat(chatId),
        from: { id: Number(policy.botId), is_bot: true } } } }, worker);
  const receipt = (updateId: number) => db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
    .bind(policy.botId, updateId).first<number>("receipt_id");
  const calls = () => db.prepare("SELECT calls FROM provider_batch_fixture").first<number>("calls");
  const cron = async (worker = drainOnly) => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  async function reply(updateId: number) {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const id = await db.prepare(`SELECT sent_message_id FROM telegram_inbox JOIN telegram_outbox USING(receipt_id)
        WHERE bot_id=? AND update_id=? AND state='sent'`).bind(policy.botId, updateId).first<number>("sent_message_id");
      const found = sent.find((item) => item.id === id);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    assert.fail("Synthetic batch reply did not settle.");
  }

  assert.equal((await message(1, "/updateall")).status, 204);
  await apply(controls);
  assert.equal((await message(45, "/updateall")).status, 204);
  assert.equal(await receipt(45), null, "missing journal prevents new batch admission");
  await apply(journal);
  assert.equal((await message(2, "/updateall", drainOnly)).status, 204);
  assert.equal((await message(3, "/updateall status", drainOnly)).status, 204);
  assert.equal((await message(4, "/updateall", app, ownerId, policy.groupId)).status, 204);
  for (const updateId of [1, 2, 3, 4]) assert.equal(await receipt(updateId), null);
  assert.equal((await message(40, "/updateall", queueFault)).status, 503);
  assert.equal((await message(41, source, queueFault)).status, 503);
  assert.equal((await message(42, "/updateall", controlsFault)).status, 503);
  for (const updateId of [40, 41, 42]) assert.equal(await receipt(updateId), null);
  assert.equal((await message(43, "/help", queueFault)).status, 200);
  const queueFaultHelp = await reply(43);
  assert.match(queueFaultHelp.text, /\/list/u);
  assert.ok(!queueFaultHelp.menu.includes("🔄 更新所有"));
  assert.equal((await message(44, "/help", controlsFault)).status, 200);
  const controlsFaultHelp = await reply(44);
  assert.match(controlsFaultHelp.text, /\/list/u);
  assert.ok(!controlsFaultHelp.menu.includes("🔄 更新所有"));
  assert.equal((await message(46, "/help", drainOnly)).status, 200);
  assert.ok(!(await reply(46)).menu.includes("🔄 更新所有"));
  assert.equal((await message(47, "/help")).status, 200);
  const enabledHelp = await reply(47);
  assert.ok(enabledHelp.menu.includes("🔄 更新所有"));
  assert.ok(!enabledHelp.menu.includes("📤 导出链接"));

  assert.equal((await message(5, "/updateall")).status, 200);
  const oldPreview = await reply(5);
  assert.equal((await message(6, "🔄 更新所有")).status, 200);
  const preview = await reply(6);
  assert.match(preview.text, /确认刷新 4 条/u);
  assert.match(preview.text, /未纳入 1 条/u);
  const ticket = preview.buttons[0]?.callback_data;
  assert.ok(ticket);
  assert.match(ticket, /^sbpb1_[A-Za-z0-9_-]{21}[AQgw]$/u);
  const companion = await db.prepare("SELECT * FROM telegram_provider_batch_interactions WHERE token_sha256=?").bind(digest(ticket)).first();
  assert.ok(companion);
  assert.equal(JSON.stringify(companion).includes(ticket), false);
  assert.equal(JSON.stringify(companion).includes(source), false);

  assert.equal((await click(7, oldPreview.id, oldPreview.buttons[0].callback_data)).status, 200);
  assert.equal((await click(8, preview.id, ticket, app, policy.adminId)).status, 200);
  assert.equal((await click(9, preview.id + 1, ticket)).status, 200);
  assert.equal((await click(10, preview.id, ticket, drainOnly)).status, 204);
  for (const updateId of [7, 8, 9, 10]) assert.equal(await receipt(updateId), null);

  const confirmations = await Promise.all([click(11, preview.id, ticket), click(12, preview.id, ticket)]);
  assert.deepEqual(confirmations.map(({ status }) => status), [200, 200]);
  const ids = await Promise.all([receipt(11), receipt(12)]);
  assert.notEqual(ids[0] === null, ids[1] === null);
  const accepted = ids[0] === null ? 12 : 11;
  const batchId = ids[0] ?? ids[1];
  assert.ok(batchId);
  assert.equal(await calls(), 0);
  assert.equal((await click(accepted, preview.id, ticket)).status, 200);
  const jobs = await db.prepare("SELECT subscription_id,state FROM telegram_provider_batch_jobs ORDER BY ordinal").all();
  assert.deepEqual(jobs.results, [good, failed, stale, secondFailed].map(({ id }) => ({ subscription_id: id, state: "waiting" })));
  await cron(journalFault);
  assert.equal(await calls(), 0);
  assert.equal(await db.prepare("SELECT count(*) AS waiting FROM telegram_provider_batch_jobs WHERE state='waiting'").first("waiting"), 4);
  assert.equal((await message(13, "/updateall status", journalFault)).status, 200);
  const running = await reply(13);
  assert.match(running.text, /进度：0\/4/u);
  assert.doesNotMatch(running.text, /本次订阅结果/u);
  assert.equal(await renameOwnedSubscription(db, { id: stale.id, ownerId, expectedLifecycleRevision: 0 }, "New private name"), true);
  await cron(queueFault);
  assert.equal(await calls(), 0);
  await cron(controlsFault);
  assert.equal(await calls(), 1);
  assert.equal((await message(14, "/updateall status", drainOnly)).status, 200);
  assert.match((await reply(14)).text, /进度：2\/4/u);

  // Emulate a newer ordinary send already in flight when the older batch finishes.
  const newer = await db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command) VALUES (?,?,?,?,'private',?,?,'help')
    RETURNING receipt_id`).bind(policy.botId, 15, ownerId, ownerId, 15, date).first<number>("receipt_id");
  assert.ok(newer);
  await db.batch([
    db.prepare("INSERT INTO telegram_outbox (receipt_id,state,attempts,lease_id,lease_until) VALUES (?,'sending',1,'synthetic-newer',unixepoch()+300)").bind(newer),
    db.prepare("UPDATE telegram_inbox SET received_at=unixepoch()-1000 WHERE receipt_id=?").bind(batchId),
  ]);
  await cron();
  assert.equal(await calls(), 2);
  await cron();
  assert.equal(await calls(), 3);
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?").bind(batchId).first("state"), "pending");
  await db.prepare("UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL WHERE receipt_id=?").bind(newer).run();
  await cron();
  const terminal = await reply(accepted);
  assert.match(terminal.text, /完成：4\/4/u);
  assert.match(terminal.text, /已保存 1 · 失败 2 · 已变更 1 · 超时 0/u);
  assert.deepEqual(terminal.text.split("\n").slice(-5), ["本次订阅结果",
    `订阅 ID ${good.id} · Saved fixture：已保存`,
    `订阅 ID ${failed.id} · Failed fixture [链接已省略]：失败`,
    `订阅 ID ${stale.id}：已变更`,
    `订阅 ID ${secondFailed.id} · Second failed fixture：失败`,
  ]);
  assert.doesNotMatch(terminal.text, /New private name|Local fixture|Foreign fixture/u);
  await cron();
  assert.equal(sent.filter(({ text }) => text.includes("完成：4/4")).length, 1);
  assert.equal((await message(48, "/updateall status", drainOnly)).status, 200);
  const historical = await reply(48);
  assert.equal(historical.text, terminal.text);
  assert.deepEqual(historical.buttons, []);
  assert.equal((await message(49, "/updateall status", app, policy.adminId)).status, 200);
  assert.equal((await reply(49)).text, "暂无批量刷新记录。");
  assert.equal((await getSubscriptionSnapshot(db, good.token))?.generation, 2);
  assert.deepEqual(await getSubscriptionSnapshot(db, failed.token), previous);
  for (const row of [stale, uploaded, foreign]) assert.equal((await getSubscriptionSnapshot(db, row.token))?.generation, 1);
  const exported = await app.fetch(`https://fixture.invalid/sub/${good.token}/base64`);
  assert.equal(exported.status, 200);
  assert.equal(await exported.text(), Buffer.from(newShare).toString("base64"));
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscription_provider_jobs").first("count"), 0);

  // The terminal origin, rather than last_error or the status reply, owns this ticket.
  await db.prepare("UPDATE subscriptions SET last_error='unrelated' WHERE id=?").bind(uploaded.id).run();
  assert.equal(terminal.buttons.length, 1);
  assert.equal(terminal.buttons[0].text, "确认将本批 2 条失败订阅移入回收站");
  const cleanup = terminal.buttons[0].callback_data;
  assert.match(cleanup, /^sbd1_[A-Za-z0-9_-]{22}$/u);
  const storedTicket = () => db.prepare(`SELECT inbox.receipt_nonce AS marker,trash.targets,
    trash.confirmed_by_receipt_id AS used FROM telegram_bulk_trash AS trash
    JOIN telegram_inbox AS inbox USING(receipt_id) WHERE trash.token_sha256=?`)
    .bind(digest(cleanup)).first<{ marker: string; targets: string; used: number | null }>();
  const unused = { marker: "provider-batch-confirm:v1",
    targets: JSON.stringify([[failed.id, 1, 0], [secondFailed.id, 1, 0]]), used: null };
  assert.deepEqual(await storedTicket(), unused);
  assert.equal((await click(52, terminal.id, cleanup, app, policy.adminId)).status, 200);
  assert.equal((await click(53, terminal.id, cleanup, app, ownerId, policy.groupId)).status, 204);
  assert.equal((await click(54, historical.id, cleanup)).status, 200);
  for (const updateId of [52, 53, 54]) assert.equal(await receipt(updateId), null);
  const expiry = await db.prepare("SELECT expires_at FROM telegram_bulk_trash WHERE receipt_id=?")
    .bind(batchId).first<number>("expires_at");
  assert.ok(expiry);
  await db.prepare("UPDATE telegram_bulk_trash SET expires_at=1 WHERE receipt_id=?").bind(batchId).run();
  assert.equal((await click(58, terminal.id, cleanup)).status, 200);
  await db.prepare("UPDATE telegram_bulk_trash SET expires_at=? WHERE receipt_id=?").bind(expiry, batchId).run();
  await db.prepare("INSERT INTO telegram_auth VALUES (?,?,0,unixepoch(),1)").bind(policy.botId, ownerId).run();
  assert.equal((await click(59, terminal.id, cleanup)).status, 200);
  await db.prepare("DELETE FROM telegram_auth WHERE bot_id=? AND user_id=?").bind(policy.botId, ownerId).run();
  assert.equal(await receipt(58), null);
  assert.equal(await receipt(59), null);
  assert.deepEqual(await storedTicket(), unused);

  const selection = await readFailedBatchTrash(db, policy, ownerId, batchId);
  assert.ok(selection);
  const stillExact = () => db.prepare(`SELECT ${selection.guard.sql} AS exact`)
    .bind(...selection.guard.bindings).first<number>("exact");
  assert.equal(await stillExact(), 1);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(secondFailing + "&changed=1", secondFailed.id).run();
  assert.equal(await stillExact(), 0, "source-only drift must invalidate the exact in-transaction guard");
  assert.equal(await readFailedBatchTrash(db, policy, ownerId, batchId), null);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(secondFailing, secondFailed.id).run();

  // Suppress the second move after the first has run. The transaction assertion
  // must undo both the first move and the ticket consumption.
  await db.prepare(`CREATE TRIGGER ignore_fixture_second_failed_trash BEFORE INSERT ON subscription_trash
    WHEN NEW.id=${secondFailed.id} BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    assert.equal((await click(55, terminal.id, cleanup)).status, 503);
    assert.equal(await receipt(55), null);
    assert.deepEqual(await storedTicket(), unused);
    assert.deepEqual(await getSubscriptionSnapshot(db, failed.token), previous);
    assert.equal((await getSubscriptionSnapshot(db, secondFailed.token))?.generation, 1);
  } finally {
    await db.prepare("DROP TRIGGER ignore_fixture_second_failed_trash").run();
  }
  assert.equal((await click(56, terminal.id, cleanup, drainOnly)).status, 200);
  assert.match((await reply(56)).text, /已将 2 条订阅移入回收站/u);
  assert.equal((await click(57, terminal.id, cleanup)).status, 200);
  assert.equal(await receipt(57), null);
  assert.equal((await storedTicket())?.used, await receipt(56));
  const moved = await db.prepare("SELECT id,generation,lifecycle_revision FROM subscription_trash ORDER BY id").all();
  assert.deepEqual(moved.results, [failed, secondFailed].map(({ id }) => ({ id, generation: 1, lifecycle_revision: 1 })));
  assert.equal(await getSubscriptionSnapshot(db, failed.token), null);
  assert.equal(await (await bucket.get(previousManifest))?.text(), previousBytes);
  for (const row of [good, stale, uploaded, foreign]) assert.ok(await getSubscriptionSnapshot(db, row.token));

  assert.equal((await message(16, "/updateall")).status, 200);
  const revoked = await reply(16);
  assert.ok(revoked.buttons[0]);
  const priorSends = sent.length;
  assert.equal((await message(51, "/updateall status", reportGrantFault)).status, 200);
  const revokedReport = await receipt(51);
  assert.ok(revokedReport);
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?").bind(revokedReport).first("state") === "failed") break;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?").bind(revokedReport).first("state"), "failed");
  assert.equal(sent.length, priorSends);
  assert.equal((await click(17, revoked.id, revoked.buttons[0].callback_data)).status, 200);
  assert.equal(await receipt(17), null);
  assert.equal((await message(18, "/updateall status", drainOnly)).status, 204);
  const newEpoch = await db.prepare(`UPDATE telegram_auth SET allowed=1,message_id=2 WHERE bot_id=? AND user_id=?
    RETURNING message_date`).bind(policy.botId, ownerId).first<number>("message_date");
  assert.ok(newEpoch);
  assert.equal((await message(50, "/updateall status", app, ownerId, ownerId, newEpoch + 1)).status, 200);
  assert.equal((await reply(50)).text, "暂无批量刷新记录。");
  await cron();
  assert.equal(await calls(), 3);

  await Promise.all(Array.from({ length: 16 }, (_, index) => createSubscription(db, {
    ownerId: policy.adminId, name: "Synthetic extra", sourceUrl: source + "&extra=" + index,
  })));
  assert.equal((await message(19, "/updateall", app, policy.adminId)).status, 200);
  const limit = await reply(19);
  assert.match(limit.text, /超过 16 条/u);
  assert.deepEqual(limit.buttons, []);
});

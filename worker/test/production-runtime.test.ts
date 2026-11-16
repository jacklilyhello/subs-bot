import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { CONTROL_REHEARSAL_PUBLIC_ORIGIN } from "../src/public-origin.ts";

test("emitted production runtime preserves pre-initialization updates, deduplicates, pauses admission and drains accepted sends", { timeout: 45_000 }, async (t) => {
  const target = "e".repeat(64), revision = "f".repeat(40), admin = "92002", member = "92003";
  const config = { botId: "92001", botUsername: "ProductionFixtureBot", botToken: "92001:synthetic-token",
    webhookSecret: "synthetic-hook", generation: 1, cutoverAt: 1, activationSha256: target,
    outbox: "shared-private-management", authManagement: true };
  const sending = Promise.withResolvers<void>(), release = Promise.withResolvers<void>();
  let sends = 0;
  const runtime = new Miniflare({ modules: true,
    script: await readFile(new URL("../dist/index.js", import.meta.url), "utf8"), compatibilityDate: "2026-07-30",
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: revision,
      PUBLIC_ORIGIN: CONTROL_REHEARSAL_PUBLIC_ORIGIN, TELEGRAM_GENERAL_CONFIG: JSON.stringify(config),
      TELEGRAM_PRODUCTION_CONTROL_SHA256: target },
    outboundService: async (request: Request) => {
      assert.equal(request.url, `https://api.telegram.org/bot${config.botToken}/sendMessage`);
      sends++;
      if (sends === 1) { sending.resolve(); await release.promise; }
      const body = await request.json() as { chat_id: string };
      return Response.json({ ok: true, result: { message_id: 1000 + sends, chat: { id: Number(body.chat_id) } } });
    } });
  t.after(async () => { release.resolve(); await runtime.dispose(); });
  const db = await runtime.getD1Database("DB");
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  const directory = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(directory)).filter((value) => value.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((value) => db.prepare(value)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES(?,?,?, ?,1,1)").bind(config.botId, 1, revision, target),
    db.prepare("INSERT INTO telegram_general_actors VALUES(?,1,?,1,1,'admin'),(?,1,?,1,1,'member')")
      .bind(config.botId, admin, config.botId, member),
    db.prepare("INSERT INTO subs_bot_production_control VALUES(1,?,?,?,1,1,'closed','run')")
      .bind(target, config.botId, revision),
  ]);
  const payload = (id: number, actor = member, text = "/help") => ({ update_id: id,
    message: { message_id: id, date: 20, text, from: { id: Number(actor), is_bot: false },
      chat: { id: Number(actor), type: "private" }, entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u)[0].length }] } });
  const post = (id: number, actor = member, text = "/help", secret = config.webhookSecret) =>
    runtime.dispatchFetch(CONTROL_REHEARSAL_PUBLIC_ORIGIN + "/telegram/webhook", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
      body: JSON.stringify(payload(id, actor, text)) });
  const receipts = () => db.prepare("SELECT count(*) AS n FROM telegram_inbox").first<number>("n");
  const calls = () => db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations").first<number>("n");
  assert.equal((await post(1)).status, 503);
  assert.equal(await receipts(), 0);
  assert.equal(await calls(), 0);
  assert.equal((await post(1, member, "/help", "wrong-secret")).status, 401);
  assert.equal(await calls(), 0);
  await db.prepare("UPDATE subs_bot_production_control SET admission='open',epoch=2").run();
  assert.equal((await post(1)).status, 200, "a pending update predating initialization remains eligible");
  await sending.promise;
  assert.equal(await receipts(), 1, "HTTP success follows durable acceptance");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE state='running'").first("n"), 1);
  await db.prepare("UPDATE subs_bot_production_control SET admission='closed',epoch=3").run();
  assert.equal((await post(2)).status, 503);
  assert.equal(await receipts(), 1);
  release.resolve();
  for (let attempt = 0; attempt < 160; attempt++) {
    const unfinished = await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE state<>'finished'").first("n");
    if (unfinished === 0) break;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=1").first("state"), "sent");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE state<>'finished'").first("n"), 0);
  await db.prepare("UPDATE subs_bot_production_control SET admission='open',epoch=4").run();
  assert.equal((await post(1)).status, 204);
  assert.equal(await receipts(), 1);
  assert.equal(sends, 1, "redelivery must not repeat the send");
  assert.equal((await post(3, "92004")).status, 204, "an unapproved actor is not enrolled by the control tool");
  assert.equal(await receipts(), 1);
  assert.equal((await post(4, member, "/auth add 92005")).status, 204);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_general_actors WHERE actor_id='92005'").first("n"), 0);
  await db.prepare("UPDATE subs_bot_production_control SET admission='closed',workers='frozen',epoch=5").run();
  const before = await calls();
  assert.equal((await (await runtime.getWorker()).scheduled({ cron: "* * * * *" })).outcome, "ok");
  assert.equal(await calls(), before, "a frozen Cron cannot acquire a write invocation");
  assert.equal((await post(5)).status, 503);
  await db.prepare("UPDATE subs_bot_production_control SET target_sha256=?").bind("a".repeat(64)).run();
  assert.equal((await runtime.dispatchFetch(CONTROL_REHEARSAL_PUBLIC_ORIGIN + "/health")).status, 503);
  assert.equal((await post(6)).status, 503);
  assert.equal(await receipts(), 1);
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription } from "../src/storage.ts";
import { PRODUCTION_PUBLIC_ORIGIN } from "../src/public-origin.ts";
import { parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { GENERAL_PAGE_JUMP_MARKER } from "../src/telegram/general-page-jump.ts";
import { GENERAL_PAGE_JUMP_CALLBACK, TELEGRAM_PAGE_JUMP_PROMPT } from "../src/telegram/protocol.ts";

type Wire = { chat_id: string; text: string; reply_parameters: { message_id: number };
  reply_markup?: { inline_keyboard?: { text: string; callback_data: string }[][]; force_reply?: boolean } };
type Card = { id: number; body: Wire };
type Options = { actor?: string; chat?: string; bot?: string; thread?: number };
type Update = { update_id: number; message?: object; callback_query?: object };
const digest = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");

test("actual bundle general page jumps retain causal receipts, current grants and private payload boundaries", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8")) as {
    revision: string; compatibilityDate: string; bundleSha256: string; migrations: { name: string; sha256: string }[];
  };
  const script = await readFile(join(directory, "index.js"));
  assert.equal(digest(script), manifest.bundleSha256);
  const now = Math.floor(Date.now() / 1000), member = "97303", admin = "97302", group = "-10097304";
  const config = { botId: "97301", botUsername: "JumpFixtureBot", botToken: "97301:synthetic-jump-token",
    webhookSecret: "synthetic-jump-webhook", generation: 1, cutoverAt: now - 30, activationSha256: "d".repeat(64),
    outbox: "shared-private-management-formats-temp-node-document", subscriptionBrowsing: true, pageJump: true };
  const pin = parseGeneralTelegramPin(JSON.stringify(config), manifest.revision);
  assert.ok(pin?.privateBrowsing && pin.privatePageJump);
  const { pageJump: _enabled, ...defaultConfig } = config;
  const defaultPin = parseGeneralTelegramPin(JSON.stringify(defaultConfig), manifest.revision);
  assert.ok(defaultPin?.privateBrowsing && !defaultPin.privatePageJump, "page jumps remain an explicit general opt-in");
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...config, subscriptionBrowsing: undefined }), manifest.revision), null);
  const sent: Card[] = [];
  let firstPromptAttempts = 0, retryFirstPrompt = true, wireMessageSequence = 40_000;
  const runtime = new Miniflare({ modules: true, script: script.toString(), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_GENERAL_CONFIG: JSON.stringify(config), PUBLIC_ORIGIN: PRODUCTION_PUBLIC_ORIGIN },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${config.botToken}/`;
      if (request.url === api + "answerCallbackQuery") return Response.json({ ok: true, result: true });
      assert.equal(request.url, api + "sendMessage");
      const body = await request.json() as Wire;
      assert.ok([member, admin, group].includes(body.chat_id));
      if (body.text === TELEGRAM_PAGE_JUMP_PROMPT && retryFirstPrompt) {
        firstPromptAttempts++;
        if (firstPromptAttempts === 1) return Response.json({ ok: false, error_code: 429,
          parameters: { retry_after: 1 } }, { status: 429 });
        retryFirstPrompt = false;
      }
      const id = ++wireMessageSequence;
      sent.push({ id, body });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  for (const { name, sha256 } of manifest.migrations) {
    const sql = await readFile(join(directory, name), "utf8");
    assert.equal(digest(sql), sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  await db.batch(manifest.migrations.map(({ name, sha256 }, index) =>
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')").bind(index + 1, name, sha256)));
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES(?,?,?,?,?,1)")
      .bind(pin.botId, 1, manifest.revision, pin.activationSha256, pin.cutoverAt),
    db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,1,?,'admin'),(?,?,?,1,?,'member')")
      .bind(pin.botId, 1, admin, pin.cutoverAt, pin.botId, 1, member, pin.cutoverAt),
    db.prepare("INSERT INTO telegram_general_groups VALUES(?,?,?,'group')").bind(pin.botId, 1, group),
  ]);
  const subscriptions = [];
  for (let i = 1; i <= 17; i++) subscriptions.push(await createSubscription(db, { ownerId: member,
    name: `Jump member ${i}`, sourceUrl: `https://private.fixture.invalid/jump/${i}?synthetic=hidden` }));
  await createSubscription(db, { ownerId: admin, name: "Jump administrator own",
    sourceUrl: "https://private.fixture.invalid/jump/admin" });
  const headers = { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret };
  let sequence = 0;
  const updates = new Map<number, Update>();
  const post = (update: Update) => {
    updates.set(update.update_id, update);
    return runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", { method: "POST", headers, body: JSON.stringify(update) });
  };
  const message = async (text: string, options: Options = {}, origin?: Card) => {
    const id = ++sequence, actor = options.actor ?? member, chat = options.chat ?? actor, messageId = ++wireMessageSequence;
    const response = await post({ update_id: id, message: { message_id: messageId, date: now,
      from: { id: Number(actor), is_bot: false }, chat: { id: Number(chat), type: chat === group ? "group" : "private" },
      ...(options.thread === undefined ? {} : { message_thread_id: options.thread, is_topic_message: true }),
      ...(origin ? { reply_to_message: { message_id: origin.id, date: now,
        from: { id: Number(options.bot ?? pin.botId), is_bot: true },
        chat: { id: Number(chat), type: chat === group ? "group" : "private" }, text: origin.body.text,
        ...(options.thread === undefined ? {} : { message_thread_id: options.thread, is_topic_message: true }) } } : {}),
      text, entities: text.startsWith("/") ? [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }] : [] } });
    return { id, status: response.status };
  };
  const click = async (origin: Card, token: string, options: Options = {}) => {
    const id = ++sequence, actor = options.actor ?? member, chat = options.chat ?? origin.body.chat_id;
    const response = await post({ update_id: id, callback_query: { id: `jump-fixture-${id}`,
      from: { id: Number(actor), is_bot: false }, data: token, message: { message_id: origin.id, date: now,
        from: { id: Number(options.bot ?? pin.botId), is_bot: true },
        chat: { id: Number(chat), type: chat === group ? "group" : "private" },
        ...(options.thread === undefined ? {} : { message_thread_id: options.thread, is_topic_message: true }) } } });
    return { id, status: response.status };
  };
  const worker = await runtime.getWorker();
  const tick = async () => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const state = async (id: number) => await db.prepare(`SELECT state,attempts FROM telegram_inbox JOIN telegram_outbox USING(receipt_id)
    WHERE bot_id=? AND update_id=?`).bind(pin.botId, id).first<{ state: string; attempts: number }>();
  const card = async (id: number) => {
    for (let i = 0; i < 80; i++) {
      const messageId = await db.prepare(`SELECT sent_message_id FROM telegram_inbox JOIN telegram_outbox USING(receipt_id)
        WHERE bot_id=? AND update_id=? AND state='sent'`).bind(pin.botId, id).first<number>("sent_message_id");
      const found = sent.find((item) => item.id === messageId);
      if (found) return found;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    const value = await state(id);
    assert.ok(!value || ["pending", "leased", "sending", "sent", "failed", "uncertain"].includes(value.state));
    assert.fail(`Synthetic jump reply missing: ${JSON.stringify({ state: value?.state ?? "missing",
      attempts: value?.attempts ?? 0, sent: sent.length })}.`);
  };
  const button = (value: Card, text: string) => {
    const token = value.body.reply_markup?.inline_keyboard?.flat().find((item) => item.text === text)?.callback_data;
    assert.ok(token, `Missing synthetic jump button ${text}`);
    return token;
  };
  const list = async (options: Options = {}) => {
    const event = await message("/list@JumpFixtureBot", options);
    assert.equal(event.status, 200);
    return card(event.id);
  };
  const prompt = async (options: Options = {}) => {
    const origin = await list(options);
    assert.equal(button(origin, "🔢 跳转页"), GENERAL_PAGE_JUMP_CALLBACK);
    const event = await click(origin, GENERAL_PAGE_JUMP_CALLBACK, options);
    assert.equal(event.status, 200);
    const value = await card(event.id);
    assert.equal(value.body.text, TELEGRAM_PAGE_JUMP_PROMPT);
    return value;
  };
  const assertNoPrivatePayload = (value: Card) => assert.doesNotMatch(value.body.text,
    /Jump administrator own|private\.fixture|synthetic=|\/sub\/|ss:\/\//u);

  const first = await list();
  assert.match(first.body.text, /1\. Jump member 1\n/u);
  assertNoPrivatePayload(first);
  assert.equal(button(first, "🔢 跳转页"), GENERAL_PAGE_JUMP_CALLBACK);
  assert.equal((await click(first, GENERAL_PAGE_JUMP_CALLBACK, { actor: admin, chat: admin })).status, 204);
  assert.equal((await click(first, GENERAL_PAGE_JUMP_CALLBACK, { bot: "97399" })).status, 204);
  assert.equal((await click(first, GENERAL_PAGE_JUMP_CALLBACK, { chat: group })).status, 204);
  assert.equal((await click(first, GENERAL_PAGE_JUMP_CALLBACK, { thread: 1 })).status, 204);
  const opened = await click(first, GENERAL_PAGE_JUMP_CALLBACK);
  assert.equal(opened.status, 200);
  let retryObserved = false;
  for (let i = 0; i < 80; i++) {
    const value = await state(opened.id);
    if (value?.state === "pending" && value.attempts === 1) { retryObserved = true; break; }
    if (value?.state === "failed" || value?.state === "uncertain") break;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(retryObserved, true, "a definitive prompt 429 queues one bounded retry");
  const retryTiming = await db.prepare(`SELECT reply.due_at AS dueAt,inbox.received_at AS receivedAt,jump.expires_at AS expiresAt
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_page_jumps AS jump USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(pin.botId, opened.id).first<{ dueAt: number; receivedAt: number; expiresAt: number }>();
  assert.ok(retryTiming && retryTiming.dueAt >= retryTiming.receivedAt + 1
    && retryTiming.dueAt < retryTiming.expiresAt && retryTiming.expiresAt - retryTiming.receivedAt >= 599
    && retryTiming.expiresAt - retryTiming.receivedAt <= 601, "Retry-After remains inside the persistent ten-minute prompt lifetime");
  await db.prepare(`UPDATE telegram_outbox SET due_at=unixepoch() WHERE receipt_id=(
    SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?)`).bind(pin.botId, opened.id).run();
  await tick();
  const firstPrompt = await card(opened.id);
  assert.equal(firstPromptAttempts, 2);
  assert.equal(firstPrompt.body.text, TELEGRAM_PAGE_JUMP_PROMPT);
  assert.equal(firstPrompt.body.reply_markup?.force_reply, true);
  assert.equal((await post(updates.get(opened.id)!)).status, 204);
  assert.equal((await click(first, GENERAL_PAGE_JUMP_CALLBACK)).status, 204, "one list origin authorizes only one prompt");
  assert.equal((await message("2", { bot: "97399" }, firstPrompt)).status, 204);
  assert.equal((await message("2", { actor: admin, chat: admin }, firstPrompt)).status, 204);
  assert.equal((await message("2", { chat: group }, firstPrompt)).status, 204);
  assert.equal((await message("2", { thread: 1 }, firstPrompt)).status, 204);
  const selected = await message("2", {}, firstPrompt);
  assert.equal(selected.status, 200);
  const second = await card(selected.id);
  assert.match(second.body.text, /9\. Jump member 9\n/u);
  assert.match(second.body.text, /16\. Jump member 16/u);
  assert.doesNotMatch(second.body.text, /(?:^|\n)1\. Jump member 1(?:\n|$)|17\. Jump member 17/u);
  assertNoPrivatePayload(second);
  for (let number = 9; number <= 16; number++) assert.ok(button(second, `${number} 详情`));
  assert.equal(await db.prepare(`SELECT count(*) AS n FROM telegram_general_subscription_anchor WHERE receipt_id=(
    SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?) AND kind='view'`)
    .bind(pin.botId, selected.id).first("n"), 8);
  const provenance = await db.prepare(`SELECT inbox.receipt_nonce AS marker,jump.kind,recorded.generation,
    EXISTS(SELECT 1 FROM telegram_page_jumps AS origin WHERE origin.receipt_id=jump.origin_receipt_id
      AND origin.kind='prompt') AS promptOrigin
    FROM telegram_inbox AS inbox JOIN telegram_page_jumps AS jump USING(receipt_id)
    JOIN telegram_general_receipt AS recorded USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(pin.botId, selected.id).first();
  assert.deepEqual(provenance, { marker: "general-view:v1", kind: "page", generation: 1, promptOrigin: 1 });
  assert.equal((await post(updates.get(selected.id)!)).status, 204);
  assert.equal((await message("3", {}, firstPrompt)).status, 204, "a confirmed prompt is consumed only once");
  const detailEvent = await click(second, button(second, "9 详情"));
  assert.equal(detailEvent.status, 200);
  assert.match((await card(detailEvent.id)).body.text, /配置名称：Jump member 9/u);
  const nextEvent = await click(second, button(second, "下一页"));
  assert.equal(nextEvent.status, 200);
  assert.match((await card(nextEvent.id)).body.text, /17\. Jump member 17/u);

  for (const [input, expected] of [["٢", /9\. Jump member 9/u], ["0", /1\. Jump member 1\n/u],
    ["/cancel@JumpFixtureBot", /已取消/u], ["not-a-page", /页码必须是数字/u], ["99", /最大 3/u]] as const) {
    const origin = await prompt();
    const event = await message(input, {}, origin);
    assert.equal(event.status, 200);
    assert.match((await card(event.id)).body.text, expected);
  }
  const addressed = await prompt();
  assert.equal((await message("/cancel@OtherFixtureBot", {}, addressed)).status, 204);
  const correctCancel = await message("/cancel@JumpFixtureBot", {}, addressed);
  assert.equal(correctCancel.status, 200);
  assert.match((await card(correctCancel.id)).body.text, /已取消/u);
  const older = await prompt(), newer = await prompt();
  assert.equal((await message("2", {}, older)).status, 204, "a newer prompt supersedes only its older current-actor prompt");
  const newerReply = await message("2", {}, newer);
  assert.equal(newerReply.status, 200);
  await card(newerReply.id);
  const agedList = await list();
  const freshPromptEvent = await click(agedList, GENERAL_PAGE_JUMP_CALLBACK);
  assert.equal(freshPromptEvent.status, 200);
  const freshPrompt = await card(freshPromptEvent.id);
  await db.prepare(`UPDATE telegram_inbox SET received_at=unixepoch()-601 WHERE receipt_id=(
    SELECT receipt_id FROM telegram_outbox WHERE sent_message_id=?)`).bind(agedList.id).run();
  const freshPromptReply = await message("2", {}, freshPrompt);
  assert.equal(freshPromptReply.status, 200, "the prompt has its own lifetime after its parent list ages out");
  await card(freshPromptReply.id);

  await db.prepare(`WITH RECURSIVE fixture(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM fixture WHERE n<20000)
    INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
    SELECT ?,'Bounded jump fixture '||n,'https://fixture.invalid/jump-budget/'||n,
      printf('generaljumpbudget%08d',n),?,? FROM fixture`).bind(admin, now, now).run();
  const budgetPrompt = await prompt({ actor: admin });
  const budgetReply = await message("2501", { actor: admin }, budgetPrompt);
  assert.equal(budgetReply.status, 200);
  assert.match((await card(budgetReply.id)).body.text, /此页超出直接跳转上限/u);

  const groupPrompt = await prompt({ chat: group });
  const groupReply = await message("2", { chat: group }, groupPrompt);
  assert.equal(groupReply.status, 200);
  const groupPage = await card(groupReply.id);
  assert.match(groupPage.body.text, /9\. Jump member 9/u);
  assertNoPrivatePayload(groupPage);
  assert.ok(groupPage.body.reply_markup?.inline_keyboard?.flat().every(({ text }) =>
    ["下一页", "第一页", "🔢 跳转页"].includes(text)));
  const removedGroupPrompt = await prompt({ chat: group });
  await db.prepare("DELETE FROM telegram_general_groups WHERE bot_id=? AND generation=1 AND chat_id=?").bind(pin.botId, group).run();
  assert.equal((await message("2", { chat: group }, removedGroupPrompt)).status, 204);
  await db.prepare("INSERT INTO telegram_general_groups VALUES(?,?,?,'group')").bind(pin.botId, 1, group).run();

  const revokedPrompt = await prompt();
  await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,2,?,'denied')").bind(pin.botId, 1, member, now - 1).run();
  assert.equal((await message("2", {}, revokedPrompt)).status, 204);
  await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,3,?,'member')").bind(pin.botId, 1, member, now - 1).run();
  assert.equal((await message("2", {}, revokedPrompt)).status, 204, "regrant cannot revive a prompt from an older actor revision");
  const regrantedPrompt = await prompt();
  const regrantedReply = await message("2", {}, regrantedPrompt);
  assert.equal(regrantedReply.status, 200);
  await card(regrantedReply.id);

  const expiredPrompt = await prompt();
  await db.prepare(`UPDATE telegram_page_jumps SET expires_at=unixepoch()-1 WHERE receipt_id=(
    SELECT receipt_id FROM telegram_outbox WHERE sent_message_id=?)`).bind(expiredPrompt.id).run();
  assert.equal((await message("2", {}, expiredPrompt)).status, 204);
  const schemaPrompt = await prompt();
  await db.prepare("UPDATE subs_bot_schema_migrations SET position=1042 WHERE name='0042_telegram_page_jumps.sql'").run();
  assert.equal((await message("2", {}, schemaPrompt)).status, 204, "exact migration 42 is required even for an already-sent prompt");
  const schemaList = await list();
  assert.equal(schemaList.body.reply_markup?.inline_keyboard?.flat().some(({ callback_data }) => callback_data === GENERAL_PAGE_JUMP_CALLBACK), false);
  assert.equal((await click(schemaList, GENERAL_PAGE_JUMP_CALLBACK)).status, 204);
  await db.prepare("UPDATE subs_bot_schema_migrations SET position=42 WHERE name='0042_telegram_page_jumps.sql'").run();

  const atomicList = await list();
  await db.prepare(`CREATE TRIGGER ignore_general_jump BEFORE INSERT ON telegram_page_jumps
    WHEN new.origin_receipt_id=(SELECT receipt_id FROM telegram_outbox WHERE sent_message_id=${atomicList.id})
    BEGIN SELECT RAISE(IGNORE); END`).run();
  const ignoredJump = await click(atomicList, GENERAL_PAGE_JUMP_CALLBACK);
  assert.equal(ignoredJump.status, 503);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE bot_id=? AND update_id=?")
    .bind(pin.botId, ignoredJump.id).first("n"), 0, "an ignored jump companion rolls back its entire admission");
  await db.prepare("DROP TRIGGER ignore_general_jump").run();
  const retriedJump = await click(atomicList, GENERAL_PAGE_JUMP_CALLBACK);
  assert.equal(retriedJump.status, 200, "a rolled-back source remains available for a new legitimate attempt");
  const retriedPrompt = await card(retriedJump.id);
  const retriedCancel = await message("/cancel@JumpFixtureBot", {}, retriedPrompt);
  assert.equal(retriedCancel.status, 200);
  await card(retriedCancel.id);

  const fencedList = await list(), fencedUpdate = sequence + 1, beforeFence = sent.length;
  await db.prepare(`CREATE TRIGGER revoke_general_jump_before_send AFTER UPDATE OF state ON telegram_outbox
    WHEN new.state='sending' AND EXISTS(SELECT 1 FROM telegram_inbox WHERE receipt_id=new.receipt_id
      AND update_id=${fencedUpdate} AND receipt_nonce='${GENERAL_PAGE_JUMP_MARKER}')
    BEGIN INSERT INTO telegram_general_actors VALUES('${pin.botId}',1,'${member}',4,${now - 1},'denied'); END`).run();
  const fenced = await click(fencedList, GENERAL_PAGE_JUMP_CALLBACK);
  assert.equal(fenced.id, fencedUpdate);
  assert.equal(fenced.status, 200);
  let failed = false;
  for (let i = 0; i < 80; i++) {
    if ((await state(fenced.id))?.state === "failed") { failed = true; break; }
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  assert.equal(failed, true, "revocation after sending transition is confirmed before the Telegram call");
  assert.equal(sent.length, beforeFence, "the stale prompt never reaches the actual Telegram API boundary");
  await db.prepare("DROP TRIGGER revoke_general_jump_before_send").run();
  await db.prepare("UPDATE telegram_general_policy SET active=0 WHERE bot_id=?").bind(pin.botId).run();
  assert.equal((await message("2", {}, schemaPrompt)).status, 204);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_page_jump_controls").first("n"), 0,
    "general jumps never create or enable isolated page-jump controls");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE receipt_nonce IN ('view-jump:v1','view-jump:v2')")
    .first("n"), 0, "general jumps never forge isolated receipt families");
});

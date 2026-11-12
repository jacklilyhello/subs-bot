import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, getOwnedSubscription } from "../src/storage.ts";
import { listDeletedSubscriptions, renameOwnedSubscription } from "../src/subscriptions.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

type Button = { text: string; callback_data: string };
type Message = { chat_id: string; text: string; reply_parameters: { message_id: number };
  reply_markup?: { inline_keyboard?: Button[][] } };

test("emitted general /d and /i keep actor epochs, owned targets, atomic moves and final send fences", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  const digest = (value: string) => createHash("sha256").update(value).digest("hex");
  assert.equal(digest(script), manifest.bundleSha256);
  const now = Math.floor(Date.now() / 1000);
  const bot = { botId: "76401", botUsername: "Fixture_General_Management_Bot", botToken: "76401:synthetic-token",
    webhookSecret: "synthetic-general-management-secret" };
  const admin = "76402", member = "76403", denied = "76404", group = "-10076405";
  const config = { ...bot, generation: 1, cutoverAt: now - 100, activationSha256: "c".repeat(64),
    outbox: "shared-private-management", inlineSearch: true };
  const sent: { id: number; body: Message }[] = [];
  const answers = new Map<string, { title: string }[]>();
  const runtime = new Miniflare({ modules: true, script, compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_GENERAL_CONFIG: JSON.stringify(config), TELEGRAM_INLINE_SEARCH: "1" },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      const api = `https://api.telegram.org/bot${bot.botToken}/`;
      if (request.url === api + "answerCallbackQuery") return Response.json({ ok: true, result: true });
      if (request.url === api + "answerInlineQuery") {
        const body = await request.json() as { inline_query_id: string; results: { title: string }[] };
        assert.equal(answers.has(body.inline_query_id), false);
        answers.set(body.inline_query_id, body.results);
        return Response.json({ ok: true, result: true });
      }
      assert.equal(request.url, api + "sendMessage");
      const body = await request.json() as Message;
      assert.ok([admin, member, group].includes(body.chat_id));
      assert.doesNotMatch(body.text, /synthetic-(?:source|name|hidden)-secret|https:\/\//u);
      const id = 10000 + sent.length;
      sent.push({ id, body });
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const migrations = manifest.migrations as { name: string; sha256: string }[];
  for (const entry of migrations) {
    const sql = await readFile(join(directory, entry.name), "utf8");
    assert.equal(digest(sql), entry.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((part) => db.prepare(part)));
    await recordTempFixtureMigration(db, entry);
  }
  for (const entry of migrations) await db.prepare(`INSERT OR IGNORE INTO subs_bot_schema_migrations
    (position,name,sha256,mode) VALUES (?,?,?,'applied')`).bind(Number(entry.name.slice(0, 4)), entry.name, entry.sha256).run();
  await db.prepare("INSERT INTO telegram_general_policy VALUES (?,1,?,?,?,1)")
    .bind(bot.botId, manifest.revision, config.activationSha256, config.cutoverAt).run();
  const grant = (actor: string, revision: number, role: "admin" | "member" | "denied", effectiveAt = now - 100) =>
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,?,?,?)").bind(bot.botId, actor, revision, effectiveAt, role).run();
  await grant(admin, 1, "admin");
  await grant(member, 1, "member");
  await grant(denied, 1, "denied");
  await db.prepare("INSERT INTO telegram_general_groups VALUES (?,1,?,'supergroup')").bind(bot.botId, group).run();
  let sequence = 100;
  let date = now - 30;
  const dispatch = (update: unknown) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", { method: "POST",
    headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": bot.webhookSecret }, body: JSON.stringify(update) });
  const command = (text: string, actor = member, id = ++sequence, chat = actor, messageDate = date) => dispatch({ update_id: id,
    message: { message_id: id, date: messageDate, text, from: { id: Number(actor), is_bot: false },
      chat: { id: Number(chat), type: chat === group ? "supergroup" : "private" },
      entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }] } });
  const click = (source: { id: number }, ticket: string, actor = member, id = ++sequence, chat = actor, botId = bot.botId) =>
    dispatch({ update_id: id, callback_query: { id: `synthetic-general-management-${id}`, data: ticket,
      from: { id: Number(actor), is_bot: false }, message: { message_id: source.id, date,
        from: { id: Number(botId), is_bot: true }, chat: { id: Number(chat), type: chat === group ? "supergroup" : "private" } } } });
  const state = (id: number) => db.prepare(`SELECT state,sent_message_id AS messageId FROM telegram_inbox
    JOIN telegram_outbox USING(receipt_id) WHERE bot_id=? AND update_id=?`).bind(bot.botId, id)
    .first<{ state: string; messageId: number | null }>();
  async function settled(id = sequence, expected = "sent") {
    for (let attempt = 0; attempt < 100; attempt++) {
      const row = await state(id);
      if (row?.state === expected) return row;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Synthetic general management reply did not settle.");
  }
  async function reply(id = sequence) {
    const row = await settled(id);
    const found = sent.find(({ id: messageId }) => row.messageId === messageId);
    assert.ok(found);
    return found;
  }
  const ticket = ({ body }: { body: Message }) => {
    const buttons = body.reply_markup?.inline_keyboard?.flat();
    assert.ok(buttons);
    assert.equal(buttons.length, 1);
    assert.equal(buttons[0].text, "确认移入回收站");
    assert.match(buttons[0].callback_data, /^sbd1_[A-Za-z0-9_-]{22}$/u);
    return buttons[0].callback_data;
  };
  const seed = (ownerId: string, name: string, path: string) => createSubscription(db,
    { ownerId, name, sourceUrl: `https://example.invalid/${path}` });
  const trash = async (actor = member) => (await listDeletedSubscriptions(db, actor, { limit: 50 })).items;

  assert.equal((await command("/i")).status, 200);
  assert.match((await reply()).body.text, /当前内联排序偏好：默认/u);
  for (const [label, mode] of [["默认", "default"], ["流量", "traffic"], ["到期", "expiry"], ["名称", "name"]]) {
    const updateId = ++sequence;
    assert.equal((await command(`/i@${bot.botUsername} ${label}`, member, updateId)).status, 200);
    assert.match((await reply(updateId)).body.text, new RegExp(`已保存为：${label}`, "u"));
    assert.equal(await db.prepare("SELECT mode FROM telegram_inline_sort_preferences WHERE bot_id=? AND actor_id=?")
      .bind(bot.botId, member).first("mode"), mode);
    assert.equal((await command("/i 流量", member, updateId)).status, 204, "redelivery is a tombstone");
  }
  assert.equal((await command("/i 默认", member, 50)).status, 200);
  assert.match((await reply(50)).body.text, /已有更新/u);
  assert.equal((await command("/i 流量", admin)).status, 200);
  await reply();
  assert.deepEqual((await db.prepare("SELECT actor_id,mode FROM telegram_inline_sort_preferences ORDER BY actor_id").all()).results,
    [{ actor_id: admin, mode: "traffic" }, { actor_id: member, mode: "name" }]);
  assert.equal((await command("/i synthetic-hidden-secret")).status, 200);
  assert.match((await reply()).body.text, /^用法：\n\/i 默认/u);
  for (const text of ["/d match", "/i 名称"]) {
    assert.equal((await command(text, member, ++sequence, group)).status, 204);
    assert.equal((await command(text, denied)).status, 204);
    assert.equal((await command(text, bot.botId)).status, 204);
    assert.equal((await command(text, member, ++sequence, admin)).status, 204);
  }
  assert.equal((await command("/help")).status, 200);
  const help = (await reply()).body.text;
  assert.match(help, /\n\/d 关键词 /u);
  assert.match(help, /\n\/i 名称 /u);
  assert.equal((await command("/help", member, ++sequence, group)).status, 200);
  assert.doesNotMatch((await reply()).body.text, /\n\/d|\n\/i(?: |\n)/u);
  const optional = migrations.filter(({ name }) => /^(0020|0024)_/u.test(name));
  assert.equal(optional.length, 2);
  await db.prepare("DELETE FROM subs_bot_schema_migrations WHERE position IN (20,24)").run();
  assert.equal((await command("/help")).status, 200);
  assert.doesNotMatch((await reply()).body.text, /\n\/d|\n\/i(?: |\n)/u);
  assert.equal((await command("/d match")).status, 204);
  assert.equal((await command("/i 名称")).status, 204);
  for (const entry of optional) await db.prepare("INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode) VALUES (?,?,?,'applied')")
    .bind(Number(entry.name.slice(0, 4)), entry.name, entry.sha256).run();
  const z = await seed(member, "sort-fixture Z", "sort-z");
  const a = await seed(member, "sort-fixture A", "sort-a");
  assert.ok(z.id < a.id);
  assert.equal((await command("/inline on")).status, 200);
  await reply();
  const inlineId = ++sequence, queryId = "synthetic-general-sort";
  assert.equal((await dispatch({ update_id: inlineId, inline_query: { id: queryId, query: "sort-fixture", offset: "", chat_type: "sender",
    from: { id: Number(member), is_bot: false } } })).status, 204);
  assert.deepEqual(answers.get(queryId)?.map(({ title }) => title), ["sort-fixture A", "sort-fixture Z"]);
  assert.equal(await db.prepare("SELECT sort_mode FROM telegram_inline_search_receipts WHERE bot_id=? AND update_id=?")
    .bind(bot.botId, inlineId).first("sort_mode"), "name");

  const first = await seed(member, "bulk-key A https://example.invalid/synthetic-name-secret", "first");
  const second = await seed(member, "Source match", "bulk-key/synthetic-source-secret");
  const decoy = await seed(member, "Decoy", "decoy");
  const foreign = await seed(admin, "bulk-key foreign", "foreign");
  await db.prepare("INSERT INTO legacy_selected_members VALUES (?,0),(?,0),(?,0),(?,0)")
    .bind(first.id, second.id, decoy.id, foreign.id).run();
  assert.equal((await command("/d")).status, 200);
  assert.match((await reply()).body.text, /^用法/u);
  assert.equal((await command("/d no-fixture-match")).status, 200);
  assert.equal((await reply()).body.text, "没有匹配订阅。");
  assert.equal((await command("/d bulk-key")).status, 200);
  const preview = await reply(), code = ticket(preview);
  assert.match(preview.body.text, /以下 2 条订阅/u);
  assert.doesNotMatch(preview.body.text, /foreign|Decoy/u);
  assert.deepEqual(await trash(), []);
  assert.equal((await click(preview, code, admin)).status, 204);
  assert.equal((await click(preview, code, member, ++sequence, group)).status, 204);
  assert.equal((await click(preview, code, member, ++sequence, member, "76409")).status, 204);
  assert.equal((await click({ id: preview.id + 1 }, code)).status, 204);
  assert.equal((await click(preview, "sbd1_" + "x".repeat(22))).status, 204);
  await db.prepare("UPDATE telegram_inbox SET receipt_nonce='bulktrash:v1' WHERE update_id=? AND bot_id=?")
    .bind(preview.body.reply_parameters.message_id, bot.botId).run();
  assert.equal((await click(preview, code)).status, 204, "an isolation callback cannot enter general management");
  await db.prepare("UPDATE telegram_inbox SET receipt_nonce='general-bulktrash:v1' WHERE update_id=? AND bot_id=?")
    .bind(preview.body.reply_parameters.message_id, bot.botId).run();
  assert.equal(await renameOwnedSubscription(db, { id: second.id, ownerId: member, expectedLifecycleRevision: 0 }, "bulk-key changed"), true);
  assert.equal((await click(preview, code)).status, 200);
  assert.match((await reply()).body.text, /本次未移动任何订阅/u);
  assert.deepEqual(await trash(), []);
  assert.equal((await command("/d bulk-key")).status, 200);
  const atomic = await reply(), atomicCode = ticket(atomic);
  const confirmId = ++sequence;
  await db.prepare(`CREATE TRIGGER ignore_general_second_trash BEFORE INSERT ON subscription_trash
    WHEN new.id=${second.id} BEGIN SELECT RAISE(IGNORE); END`).run();
  assert.equal((await click(atomic, atomicCode, member, confirmId)).status, 503);
  assert.equal(await state(confirmId), null);
  assert.deepEqual(await trash(), []);
  assert.equal(await db.prepare("SELECT confirmed_by_receipt_id FROM telegram_bulk_trash WHERE token_sha256=?")
    .bind(digest(atomicCode)).first("confirmed_by_receipt_id"), null);
  assert.deepEqual((await db.prepare("SELECT retired FROM legacy_selected_members ORDER BY id").all()).results.map((row) => row.retired), [0, 0, 0, 0]);
  await db.prepare("DROP TRIGGER ignore_general_second_trash").run();
  assert.equal((await click(atomic, atomicCode, member, confirmId)).status, 200);
  assert.match((await reply(confirmId)).body.text, /已将 2 条订阅移入回收站/u);
  assert.deepEqual((await trash()).map(({ id }) => id).sort((x, y) => x - y), [first.id, second.id]);
  assert.deepEqual((await db.prepare("SELECT retired FROM legacy_selected_members ORDER BY id").all()).results.map((row) => row.retired), [1, 1, 0, 0]);
  assert.ok(await getOwnedSubscription(db, member, decoy.id));
  assert.ok(await getOwnedSubscription(db, admin, foreign.id));
  assert.equal((await click(atomic, atomicCode)).status, 204);
  assert.equal((await command("/d bulk-key", admin)).status, 200);
  const adminPreview = await reply();
  assert.match(adminPreview.body.text, /以下 1 条订阅/u);
  assert.equal((await click(adminPreview, ticket(adminPreview), admin)).status, 200);
  await reply();
  assert.deepEqual((await trash(admin)).map(({ id }) => id), [foreign.id]);

  const revokedTarget = await seed(member, "revoke-only", "revoke-only");
  assert.equal((await command("/d revoke-only")).status, 200);
  const old = await reply(), oldCode = ticket(old);
  await grant(member, 2, "denied", now - 20);
  assert.equal((await click(old, oldCode)).status, 204);
  assert.equal((await command("/i 名称")).status, 204);
  await grant(member, 3, "member", now - 15);
  date = now - 10;
  assert.equal((await click(old, oldCode)).status, 204, "regrant cannot revive an old actor revision");
  assert.equal((await command("/d revoke-only")).status, 200);
  const expired = await reply();
  await db.prepare("UPDATE telegram_bulk_trash SET expires_at=unixepoch()-1 WHERE token_sha256=?").bind(digest(ticket(expired))).run();
  assert.equal((await click(expired, ticket(expired))).status, 204);
  assert.equal((await command("/i")).status, 200);
  assert.match((await reply()).body.text, /当前内联排序偏好：名称/u);
  assert.ok(await getOwnedSubscription(db, member, revokedTarget.id));
  const receipt = await db.prepare(`SELECT recorded.actor_revision AS revision,recorded.actor_role AS role,
    reply.auth_message_date AS authDate,reply.auth_message_id AS authId FROM telegram_inbox
    JOIN telegram_general_receipt AS recorded USING(receipt_id) JOIN telegram_inline_sort_reply AS reply USING(receipt_id)
    WHERE bot_id=? AND update_id=?`).bind(bot.botId, sequence).first();
  assert.deepEqual(receipt, { revision: 3, role: "member", authDate: 0, authId: 0 });

  async function revokeDuringBegin(id: number, revision: number, effectiveAt: number) {
    await db.prepare(`CREATE TRIGGER revoke_general_during_begin AFTER UPDATE OF state ON telegram_outbox
      WHEN new.state='sending' AND old.state='leased' AND EXISTS (
        SELECT 1 FROM telegram_inbox WHERE receipt_id=new.receipt_id AND bot_id='${bot.botId}' AND update_id=${id})
      BEGIN INSERT INTO telegram_general_actors VALUES ('${bot.botId}',1,'${member}',${revision},${effectiveAt},'denied'); END`).run();
  }
  const fencedSort = ++sequence, beforeSort = sent.length;
  await revokeDuringBegin(fencedSort, 4, now - 8);
  assert.equal((await command("/i 流量", member, fencedSort)).status, 200);
  await settled(fencedSort, "failed");
  assert.equal(sent.length, beforeSort, "revocation after leasing must suppress the final Bot API send");
  await db.prepare("DROP TRIGGER revoke_general_during_begin").run();
  await grant(member, 5, "member", now - 7);
  date = now - 5;
  const fencedPreview = ++sequence, beforePreview = sent.length;
  await revokeDuringBegin(fencedPreview, 6, now - 4);
  assert.equal((await command("/d revoke-only", member, fencedPreview)).status, 200);
  await settled(fencedPreview, "failed");
  assert.equal(sent.length, beforePreview, "revocation must suppress the preview and its confirmation token");
  assert.ok(await getOwnedSubscription(db, member, revokedTarget.id));
  await db.prepare("DROP TRIGGER revoke_general_during_begin").run();
  await grant(member, 7, "member", now - 3);
  date = now - 2;
  // /list uses the common reply path, including lifecycle ticket installation in begin.
  // Revoke at that transition so the rendered private names and buttons must never reach Telegram.
  const fencedList = ++sequence, beforeList = sent.length;
  await revokeDuringBegin(fencedList, 8, now - 1);
  assert.equal((await command("/list", member, fencedList)).status, 200);
  await settled(fencedList, "failed");
  assert.equal(sent.length, beforeList, "the common reply must recheck authority after its sending transition");
  assert.equal(await db.prepare(`SELECT recorded.actor_revision FROM telegram_inbox AS inbox
    JOIN telegram_general_receipt AS recorded USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(bot.botId, fencedList).first("actor_revision"), 7);
  assert.equal(await db.prepare("SELECT max(revision) FROM telegram_general_actors WHERE bot_id=? AND actor_id=?")
    .bind(bot.botId, member).first("max(revision)"), 8);
  await db.prepare("DROP TRIGGER revoke_general_during_begin").run();
  await grant(member, 9, "member", now);
  date = now + 1;
  await db.prepare("UPDATE telegram_general_policy SET active=0 WHERE bot_id=?").bind(bot.botId).run();
  assert.equal((await command("/i 名称")).status, 204);
  assert.equal((await command("/d revoke-only")).status, 204);
  await db.prepare("UPDATE telegram_general_policy SET active=1,generation=2 WHERE bot_id=?").bind(bot.botId).run();
  assert.equal((await command("/i 名称")).status, 204);
  assert.equal((await command("/d revoke-only")).status, 204);
});

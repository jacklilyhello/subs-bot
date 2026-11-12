import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription } from "../src/storage.ts";
import { acceptTelegramDisplaySettings, readTelegramDisplaySettingsUpdate, renderTelegramDisplaySettings,
  telegramDisplaySettingsReady, type TelegramDisplaySettingsUpdate } from "../src/telegram/display-settings.ts";
import { displayTelegramDate, parseDisplayTimeZone, readBotDisplayTimeZone } from "../src/telegram/display-time.ts";
import { acceptGeneralSharedTelegramCommand } from "../src/telegram/general-auth-shared.ts";
import type { GeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { renderTelegramPrivateShareLink } from "../src/telegram/private-share-creation.ts";
import { renderTelegramView } from "../src/telegram/views.ts";

const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
let db: D1Database;
const policy: TelegramPolicy = { botId: "950100", botUsername: "fixture_timezone_bot", adminId: "950101", memberId: "950102",
  groupId: "-950103", botToken: `950100:${"a".repeat(35)}`, webhookSecret: "fixture-timezone-secret" };
const now = () => Math.floor(Date.now() / 1000);
const date = (value: string) => Date.parse(value) / 1000;

before(async () => {
  db = await runtime.getD1Database("DB");
  await db.prepare(`CREATE TABLE subs_bot_schema_migrations
    (position INTEGER PRIMARY KEY,name TEXT NOT NULL,sha256 TEXT NOT NULL,mode TEXT NOT NULL) STRICT`).run();
  const directory = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
});
after(() => runtime.dispose());

function event(updateId: number, timeZone: string, actorId = policy.adminId): TelegramDisplaySettingsUpdate {
  return { updateId, actorId, chatId: actorId, chatType: "private", messageId: updateId, messageDate: now(), threadId: null,
    kind: "set", timeZone };
}
async function receipt(botId: string, updateId: number) {
  const id = await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
    .bind(botId, updateId).first<number>("receipt_id");
  assert.ok(id);
  return id;
}
function update(text: string, actorId = policy.adminId) {
  return { update_id: 1, message: { from: { id: Number(actorId), is_bot: false }, chat: { id: Number(actorId), type: "private" },
    message_id: 1, date: now(), text, entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u)[0].length }] } };
}
function callback(actorId = policy.adminId, chatType = "private", botId = policy.botId) {
  return { update_id: 1, callback_query: { id: "fixture-panel-action", from: { id: Number(actorId), is_bot: false },
    data: "timezone:v1:Asia/Singapore", message: { message_id: 1, date: now() - 30,
      from: { id: Number(botId), is_bot: true }, chat: { id: Number(actorId), type: chatType } } } };
}

test("presentation uses IANA rules across UTC day boundaries and DST without guessing epoch units", () => {
  assert.equal(parseDisplayTimeZone("Asia/Singapore"), "Asia/Singapore");
  assert.equal(parseDisplayTimeZone("America/New_York"), "America/New_York");
  for (const invalid of ["+08:00", "8", "Asia/Not_A_Zone", " UTC ", "UTC\n", "", null, 8]) assert.equal(parseDisplayTimeZone(invalid), null);
  const instant = date("2026-12-31T20:30:00Z");
  assert.equal(displayTelegramDate(instant), "2026-12-31 20:30:00");
  assert.equal(displayTelegramDate(instant, "Asia/Singapore"), "2027-01-01 04:30:00");
  assert.equal(displayTelegramDate(instant, "invalid"), "2026-12-31 20:30:00");
  assert.equal(displayTelegramDate(date("2026-03-08T06:59:00Z"), "America/New_York"), "2026-03-08 01:59:00");
  assert.equal(displayTelegramDate(date("2026-03-08T07:00:00Z"), "America/New_York"), "2026-03-08 03:00:00");
  assert.equal(displayTelegramDate(date("2026-11-01T05:30:00Z"), "America/New_York"), "2026-11-01 01:30:00");
  assert.equal(displayTelegramDate(date("2026-11-01T06:30:00Z"), "America/New_York"), "2026-11-01 01:30:00");
  assert.equal(displayTelegramDate(0), "1970-01-01 00:00:00");
  assert.equal(displayTelegramDate(-1), "1969-12-31 23:59:59");
  for (const invalid of [null, undefined, NaN, Infinity, 1.1, instant * 1000]) assert.equal(displayTelegramDate(invalid), "日期未知");
});

test("private settings commands accept bot addressing and panels reject other chats, bots and forged sender scope", () => {
  assert.equal(readTelegramDisplaySettingsUpdate(update("/timezone@fixture_timezone_bot Asia/Singapore"), 1, policy)?.kind, "set");
  assert.equal(readTelegramDisplaySettingsUpdate(update("/settings"), 1, policy)?.kind, "current");
  assert.equal(readTelegramDisplaySettingsUpdate(update("/timezone Not/AZone"), 1, policy)?.kind, "invalid");
  assert.equal(readTelegramDisplaySettingsUpdate(update("/timezone@different_bot UTC"), 1, policy), null);
  assert.ok(readTelegramDisplaySettingsUpdate(callback(), 1, policy));
  assert.equal(readTelegramDisplaySettingsUpdate(callback(policy.adminId, "group"), 1, policy), null);
  assert.equal(readTelegramDisplaySettingsUpdate(callback(policy.adminId, "private", "999999"), 1, policy), null);
  const forged = callback();
  forged.callback_query.message.chat.id = Number(policy.memberId);
  assert.equal(readTelegramDisplaySettingsUpdate(forged, 1, policy), null);
  const group = update("/timezone UTC");
  group.message.chat.type = "group";
  assert.equal(readTelegramDisplaySettingsUpdate(group, 1, policy), null);
});

test("Bot-wide settings persist, replay once, order concurrent updates, restore UTC and reject member mutation", async () => {
  assert.equal(await telegramDisplaySettingsReady(db), true);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "UTC");
  assert.equal(await acceptTelegramDisplaySettings(db, policy, event(101, "Asia/Singapore")), true);
  assert.equal(await acceptTelegramDisplaySettings(db, policy, event(101, "Asia/Singapore")), false);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "Asia/Singapore");
  const panel = await renderTelegramDisplaySettings(db, policy.botId, await receipt(policy.botId, 101), true);
  assert.match(panel!.text, /当前 Bot 展示时区：Asia\/Singapore/u);
  assert.equal(panel!.keyboard!.flat().length, 2);
  assert.equal(await acceptTelegramDisplaySettings(db, policy, event(102, "UTC", policy.memberId)), true);
  const denial = await renderTelegramDisplaySettings(db, policy.botId, await receipt(policy.botId, 102), false);
  assert.match(denial!.text, /只有管理员/u);
  assert.equal(denial!.keyboard, undefined);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "Asia/Singapore");
  const memberCallback = readTelegramDisplaySettingsUpdate(callback(policy.memberId), 103, policy)!;
  assert.equal(await acceptTelegramDisplaySettings(db, policy, memberCallback), true);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "Asia/Singapore");
  assert.equal(await acceptTelegramDisplaySettings(db, policy, { ...event(104, "UTC"), chatType: "group", chatId: policy.groupId }), false);
  const operationDate = now();
  await Promise.all([acceptTelegramDisplaySettings(db, policy, { ...event(106, "UTC"), messageDate: operationDate }),
    acceptTelegramDisplaySettings(db, policy, { ...event(105, "America/New_York"), messageDate: operationDate })]);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "UTC");
  assert.equal(await acceptTelegramDisplaySettings(db, policy, { ...event(100, "Asia/Singapore"), messageDate: operationDate - 1 }), true);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "UTC");
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_bot_display_settings WHERE bot_id=?").bind(policy.botId).first<number>("count"), 1);
  assert.equal(await readBotDisplayTimeZone(db, "another-bot"), "UTC");
  // Telegram can choose a new update sequence after a week without updates.
  await db.prepare("UPDATE telegram_bot_display_settings SET message_date=? WHERE bot_id=?").bind(now() - 7 * 86400, policy.botId).run();
  assert.equal(await acceptTelegramDisplaySettings(db, policy, event(1, "Asia/Singapore")), true);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "Asia/Singapore");
  assert.equal(await acceptTelegramDisplaySettings(db, policy, event(2, "UTC")), true);
  assert.equal(await readBotDisplayTimeZone(db, policy.botId), "UTC");
});

test("two owners use the same new display while expiry instants, selection boundaries and sharing TTL remain unchanged", async () => {
  const bot = { ...policy, botId: "950200" };
  const expiry = now() + 3600;
  const rows = await Promise.all([policy.adminId, policy.memberId].map((ownerId) => createSubscription(db,
    { ownerId, name: "Timezone synthetic", sourceUrl: "uploaded://timezone-fixture" })));
  await db.batch(rows.map((row) => db.prepare("UPDATE subscriptions SET expire_at=? WHERE id=?").bind(expiry, row.id)));
  await acceptTelegramDisplaySettings(db, bot, event(201, "Asia/Singapore"));
  for (const row of rows) {
    const zone = await readBotDisplayTimeZone(db, bot.botId);
    const view = await renderTelegramView(db, row.ownerId, { kind: "expiry", afterId: null, afterEpoch: null }, false, false, zone);
    assert.ok(view.text.includes(displayTelegramDate(expiry, "Asia/Singapore")));
    assert.equal(await db.prepare("SELECT expire_at FROM subscriptions WHERE id=?").bind(row.id).first<number>("expire_at"), expiry);
  }
  const link = renderTelegramPrivateShareLink(policy.botUsername,
    { code: "synthetic-code", expireAt: expiry, maxClaims: 1, guard: { sql: "1", bindings: [] } }, "Asia/Singapore");
  assert.ok(link.includes(`到期时间：${displayTelegramDate(expiry, "Asia/Singapore")}`));
  assert.doesNotMatch(link, /UTC|\+08/u);
  await db.prepare("UPDATE telegram_bot_display_settings SET timezone='not-an-iana-zone' WHERE bot_id=?").bind(bot.botId).run();
  assert.equal(await readBotDisplayTimeZone(db, bot.botId), "UTC");
});

test("the general webhook admission checks current administrator authority and keeps member commands and callbacks read-only", async () => {
  const pin: GeneralTelegramPin = { ...policy, botId: "950300", generation: 1, releaseRevision: "a".repeat(40), activationSha256: "b".repeat(64),
    cutoverAt: now() - 1200, sharedOutbox: true, privateManagement: true, privateFormats: false, privateTemp: false,
    privateDocument: false, privateProvider: false, privateClaims: false, privateShareCreation: false,
    privateAggregate: false, privateSelected: false, privateShort: false };
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy(bot_id,generation,release_revision,activation_sha256,cutover_at,active) VALUES(?,?,?,?,?,1)")
      .bind(pin.botId, 1, pin.releaseRevision, pin.activationSha256, pin.cutoverAt),
    ...[[policy.adminId, "admin"], [policy.memberId, "member"]].map(([actor, role]) =>
      db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,1,?,?)").bind(pin.botId, 1, actor, pin.cutoverAt, role)),
  ]);
  const send = (updateId: number, body: Record<string, unknown>, selected = pin) => acceptGeneralSharedTelegramCommand(db, selected,
    new Request("https://synthetic.invalid/telegram/webhook", { method: "POST", headers: { "Content-Type": "application/json",
      "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret }, body: JSON.stringify({ ...body, update_id: updateId }) }));
  assert.equal(await send(301, update("/timezone Asia/Singapore")), 200);
  assert.equal(await send(301, update("/timezone Asia/Singapore")), 204);
  assert.equal(await readBotDisplayTimeZone(db, pin.botId), "Asia/Singapore");
  assert.equal(await send(302, update("/timezone UTC", policy.memberId)), 200);
  assert.equal(await readBotDisplayTimeZone(db, pin.botId), "Asia/Singapore");
  const memberPanel = callback(policy.memberId, "private", pin.botId);
  assert.equal(await send(303, memberPanel), 200);
  assert.equal(await readBotDisplayTimeZone(db, pin.botId), "Asia/Singapore");
  assert.equal(await send(304, update("/timezone UTC"), { ...pin, activationSha256: "c".repeat(64) }), 204);
  assert.equal(await send(305, update("/timezone UTC")), 200);
  assert.equal(await readBotDisplayTimeZone(db, pin.botId), "UTC");
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,2,?,'member')").bind(pin.botId, 1, policy.adminId, pin.cutoverAt).run();
  assert.equal(await send(306, update("/timezone Asia/Singapore")), 200);
  assert.equal(await readBotDisplayTimeZone(db, pin.botId), "UTC");
  const denied = await renderTelegramDisplaySettings(db, pin.botId, await receipt(pin.botId, 306), false);
  assert.match(denied!.text, /只有管理员/u);
});

test("settings refuse a modified migration ledger", async () => {
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=51").bind("0".repeat(64)).run();
  try {
    await assert.rejects(telegramDisplaySettingsReady(db), /migration differs/u);
    await assert.rejects(acceptTelegramDisplaySettings(db, policy, event(901, "Asia/Singapore")), /migration differs/u);
  } finally {
    const sql = await readFile(new URL("../migrations/0051_telegram_display_settings.sql", import.meta.url));
    await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=51").bind(createHash("sha256").update(sql).digest("hex")).run();
  }
});

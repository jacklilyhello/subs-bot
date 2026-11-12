import assert from "node:assert/strict";
import { test } from "node:test";
import { renderTelegramHelp, syncTelegramCommandMenu, telegramBotCommands, telegramCommandEntries,
  type TelegramCommandFeatures } from "../src/telegram/command-catalog.ts";
import { generalReadEvent } from "../src/telegram/general-auth-runtime.ts";
import { telegramMainMenuKeyboard } from "../src/telegram/main-menu.ts";
import { readGeneralPrivateMenuCommand, readGeneralPrivateSubscriptionRead } from "../src/telegram/protocol.ts";

const all: TelegramCommandFeatures = { management: true, subscriptionRead: true, temp: true, path: true,
  aggregate: true, selected: true, batchRefresh: true, short: true, share: true, inline: true, inlineTemp: true,
  inlineSort: true, bulkTrash: true, github: true, apiStatus: true, authorization: true, displayTimezone: true };

test("group help and Bot commands contain only the five safe commands for either role", () => {
  for (const role of ["admin", "member"] as const) {
    const context = { privateChat: false, role, features: all };
    assert.equal(renderTelegramHelp(context), "/help 发送帮助\n/list 查看你的订阅\n/expire 查看临期\n/recycle 查看回收站\n/s 关键词 搜索订阅\n订阅详情、导出、节点和设置请回到机器人私聊。");
    assert.deepEqual(telegramBotCommands(context).map(({ command }) => command), ["help", "list", "expire", "recycle", "s"]);
  }
});

test("private catalogs list each real subcommand on its own line and restrict administration", () => {
  const member = { privateChat: true, role: "member" as const, features: all };
  const admin = { ...member, role: "admin" as const };
  const memberHelp = renderTelegramHelp(member);
  assert.doesNotMatch(memberHelp, /\/auth|\/settings|\/timezone|\/renumber/u);
  for (const expected of ["/temp clear 清空临时节点", "/export revoke 撤销全部订阅链接", "/short revoke 短码或本地短链 撤销自己的短链",
    "/inline temp on 开启临时节点内联搜索（15 分钟）", "/updateall status 查看批量任务历史", "/i 到期 设置内联排序"]) {
    assert.ok(memberHelp.split("\n").includes(expected));
  }
  assert.deepEqual(telegramBotCommands(admin).filter(({ command }) => ["auth", "settings", "timezone"].includes(command))
    .map(({ command }) => command), ["auth", "settings", "timezone"]);
  for (const { syntax } of telegramCommandEntries(admin)) assert.equal((syntax.match(/\//gu) ?? []).length, 1);
  assert.equal(new Set(telegramBotCommands(admin).map(({ command }) => command)).size, telegramBotCommands(admin).length);
});

test("paused capabilities keep only their available status and opt-out commands", () => {
  const context = { privateChat: true, role: "admin" as const,
    features: { management: true, inlineOff: true, batchStatus: true } };
  assert.deepEqual(telegramCommandEntries(context).map(({ syntax }) => syntax),
    ["/help", "/list", "/expire", "/recycle", "/start", "/updateall status", "/inline off"]);
  assert.deepEqual(telegramMainMenuKeyboard({ management: false, path: false, aggregate: false, batchRefresh: false }),
    [[{ text: "📦 订阅列表" }], [{ text: "❓ 帮助菜单" }]]);
});

function update(text: string, group = false, actor = 101) {
  return { update_id: 42, message: { message_id: 12, date: 1_800_000_000, from: { id: actor, is_bot: false },
    chat: { id: group ? -10020 : actor, type: group ? "supergroup" : "private" }, text,
    entities: text.startsWith("/") ? [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] : [] } };
}
const pin = { botId: "105", botUsername: "FixtureBot", privateManagement: true };

test("general start, expiry and safe group commands accept the addressed command form", () => {
  for (const group of [false, true]) {
    assert.equal(generalReadEvent(pin, update("/start@FixtureBot", group), 42, true)?.command, "start");
    assert.equal(generalReadEvent(pin, update("/help@fixturebot", group), 42, true)?.command, "help");
    assert.equal(generalReadEvent(pin, update("/expire@FixtureBot", group), 42, true)?.viewKind, "expiry");
    assert.equal(generalReadEvent(pin, update("/help@DifferentBot", group), 42, true), null);
    assert.equal(generalReadEvent(pin, update("/auth list", group), 42, true), null);
  }
  const search = readGeneralPrivateSubscriptionRead(update("/s@FixtureBot Fixture", true), 42, pin.botId, pin.botUsername);
  assert.equal(search?.kind, "search");
  assert.equal(search?.chatType, "supergroup");
  assert.equal(search?.actorId, "101");
  assert.equal(generalReadEvent({ ...pin, privateManagement: false }, update("/expire", true), 42, true), null);
});

test("private reply-keyboard labels go through the same scoped command parsers", () => {
  for (const [label, name] of [["📦 订阅列表", "list"], ["🟠 临期列表", "expire"], ["📤 导出链接", "export"],
    ["🔄 更新所有", "updateall"], ["♻️ 撤销删除", "recycle"], ["🧭 路径对应", "path"], ["❓ 帮助菜单", "help"]]) {
    assert.equal(readGeneralPrivateMenuCommand(update(label), pin.botUsername)?.name, name);
    assert.equal(readGeneralPrivateMenuCommand(update(label, true), pin.botUsername), null);
  }
});

test("explicit menu synchronization uses chat scope, validates Telegram's result, and never emits credentials", async () => {
  let calls = 0;
  const context = { privateChat: false, role: "admin" as const, features: all };
  assert.equal(await syncTelegramCommandMenu("fixture-token", "-10020", context, async (url, init) => {
    calls++;
    assert.equal(String(url), "https://api.telegram.org/botfixture-token/setMyCommands");
    assert.equal(init?.redirect, "manual");
    const body = JSON.parse(String(init?.body));
    assert.deepEqual(body.scope, { type: "chat", chat_id: "-10020" });
    assert.deepEqual(body.commands.map(({ command }: { command: string }) => command), ["help", "list", "expire", "recycle", "s"]);
    assert.doesNotMatch(String(init?.body), /fixture-token|\/sub\/|\/agg\//u);
    return Response.json({ ok: true, result: true });
  }), true);
  assert.equal(calls, 1);
  assert.equal(await syncTelegramCommandMenu("fixture-token", "", context, async () => { calls++; return new Response(); }), false);
  assert.equal(calls, 1);
  assert.equal(await syncTelegramCommandMenu("fixture-token", "-10020", context, async () => Response.json({ ok: true, result: {} })), false);
  assert.equal(await syncTelegramCommandMenu("fixture-token", "-10020", context, async () => { throw new Error("fixture timeout"); }), false);
});

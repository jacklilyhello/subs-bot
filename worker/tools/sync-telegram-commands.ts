import { readFile } from "node:fs/promises";
import { telegramBotCommands, syncTelegramCommandMenu, type TelegramCommandContext } from "../src/telegram/command-catalog.ts";

async function main() {
  const config = JSON.parse(process.env.SUBS_BOT_TELEGRAM_TEST_CONFIG ?? "null");
  if (!config || config.botUsername !== "test_cfsubs_bot" || config.adminId !== "8813701954" || config.memberId !== "8653767757"
    || config.groupId !== "-5114255828" || typeof config.botToken !== "string") throw new Error();
  const features = JSON.parse(await readFile(process.env.RUNNER_TEMP + "/subs-bot-command-features.json", "utf8"));
  const scopes: Array<[string, TelegramCommandContext]> = [
    [config.adminId, { privateChat: true, role: "admin", features }],
    [config.memberId, { privateChat: true, role: "member", features }],
    [config.groupId, { privateChat: false, role: "member", features }],
  ];
  for (const [chat, context] of scopes) {
    if (!await syncTelegramCommandMenu(config.botToken, chat, context)) throw new Error();
    const response = await fetch(`https://api.telegram.org/bot${config.botToken}/getMyCommands`, {
      method: "POST", redirect: "manual", signal: AbortSignal.timeout(3000), headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scope: { type: "chat", chat_id: chat }, language_code: "" }),
    });
    if (!response.ok) { await response.body?.cancel(); throw new Error(); }
    const result = await response.json() as { ok?: unknown; result?: unknown };
    if (result.ok !== true || JSON.stringify(result.result) !== JSON.stringify(telegramBotCommands(context))) throw new Error();
  }
  console.log("Synchronized and independently read back administrator, member and test-group command menus.");
}
main().catch(() => { console.error("Telegram command-menu synchronization or readback failed."); process.exitCode = 1; });

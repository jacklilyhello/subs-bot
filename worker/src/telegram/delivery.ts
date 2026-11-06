import { listOwnedSubscriptions } from "../subscriptions.ts";
import {
  prepareTelegramLifecycleTickets, renderTelegramLifecycle, type TelegramLifecycleButton,
} from "./lifecycle-actions.ts";
import { inTelegramScope, type TelegramPolicy } from "./protocol.ts";
import {
  beginTelegramReply, claimTelegramReply, isTelegramMemberAllowed,
  reapExpiredTelegramReplies, settleTelegramReply,
  type TelegramReplyLease, type TelegramReplyOutcome,
} from "./store.ts";
import { prepareTelegramViewTickets, renderTelegramView, type TelegramViewButton } from "./views.ts";

const BOT_API = "https://api.telegram.org";
const MAX_RESPONSE_BYTES = 64 * 1024;
const SEND_TIMEOUT_MS = 10_000;
const CALLBACK_TIMEOUT_MS = 3_000;
const LIST_LIMIT = 20;

type ReplyAccess = "allowed" | "denied" | "none";
type InlineKeyboard = { text: string; callback_data: string }[][];

async function readBotReply(response: Response): Promise<unknown> {
  if (!response.body) return null;
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let total = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode()) as unknown;
  } finally {
    reader.releaseLock();
  }
}

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function positiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export async function sendTelegramReply(
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  text: string,
  timeoutMs: number,
  request: typeof fetch = fetch,
  keyboard?: InlineKeyboard,
  forceReply = false,
): Promise<TelegramReplyOutcome> {
  if (!inTelegramScope(policy, lease)) return { kind: "failed" };
  try {
    const response = await request(`${BOT_API}/bot${policy.botToken}/sendMessage`, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(Math.min(SEND_TIMEOUT_MS, timeoutMs)),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: lease.chatId,
        ...(lease.threadId === null ? {} : { message_thread_id: lease.threadId }),
        reply_parameters: { message_id: lease.messageId, allow_sending_without_reply: true },
        link_preview_options: { is_disabled: true },
        ...(keyboard?.length ? { reply_markup: { inline_keyboard: keyboard } }
          : forceReply && lease.chatType === "private" ? { reply_markup: { force_reply: true } } : {}),
        text,
      }),
    });
    const payload = record(await readBotReply(response));
    if (response.ok && payload?.ok === true) {
      const result = record(payload.result);
      const chat = record(result?.chat);
      if (positiveInteger(result?.message_id) && typeof chat?.id === "number" &&
          Number.isSafeInteger(chat.id) && String(chat.id) === lease.chatId) {
        return { kind: "sent", messageId: result.message_id };
      }
    } else if (payload?.ok === false && payload.error_code === response.status &&
        response.status >= 400 && response.status < 500 && response.status !== 408) {
      if (response.status === 429) {
        const delay = record(payload.parameters)?.retry_after;
        if (positiveInteger(delay) && delay <= 900) return { kind: "retry", delaySeconds: delay };
      }
      return { kind: "failed" };
    }
  } catch {
    // A transport or malformed response cannot prove Telegram did not deliver.
  }
  return { kind: "uncertain" };
}

export async function answerTelegramCallback(policy: TelegramPolicy, callbackId: string): Promise<void> {
  try {
    const response = await fetch(`${BOT_API}/bot${policy.botToken}/answerCallbackQuery`, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(CALLBACK_TIMEOUT_MS),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callback_query_id: callbackId }),
    });
    await response.body?.cancel();
  } catch {
    // Acknowledgement is best effort. The callback's durable admission decides whether it has effects.
  }
}

async function renderReply(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
): Promise<{
  text: string;
  access: ReplyAccess;
  buttons?: TelegramViewButton[];
  lifecycleButtons?: TelegramLifecycleButton[];
  forceReply?: boolean;
}> {
  if (lease.command.startsWith("auth-")) {
    if (lease.actorId !== policy.adminId) return { text: "只有管理员可以管理授权。", access: "none" };
    if (lease.chatType !== "private") return { text: "请在私聊中管理授权。", access: "none" };
    if (lease.command === "auth-usage") return { text: "用法：/auth list、/auth add 用户ID、/auth remove 用户ID。", access: "none" };
    const memberAllowed = await isTelegramMemberAllowed(db, policy);
    return {
      text: `管理员 ${policy.adminId}\n用户 ${policy.memberId}：${memberAllowed ? "已授权" : "已撤权"}`,
      access: "none",
    };
  }
  const allowed = lease.actorId === policy.adminId || await isTelegramMemberAllowed(db, policy);
  if (!allowed) return { text: "当前账号没有使用权限。", access: "denied" };
  if (lease.lifecycle) {
    const { text, buttons, forceReply } = renderTelegramLifecycle(lease.lifecycle);
    return { text, lifecycleButtons: buttons, forceReply, access: "allowed" };
  }
  if (lease.view) return { ...await renderTelegramView(db, lease.actorId, lease.view), access: "allowed" };
  if (lease.command === "list") {
    const page = await listOwnedSubscriptions(db, lease.actorId, { limit: LIST_LIMIT });
    const names = page.items.map((row, index) => {
      const name = Array.from(row.name.replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ")).slice(0, 80).join("");
      return `${index + 1}. ${name}`;
    });
    if (page.nextAfterId !== null) names.push(`仅显示前 ${LIST_LIMIT} 条。`);
    return { text: names.length ? `你的订阅\n${names.join("\n")}` : "你的订阅列表为空。", access: "allowed" };
  }
  const help = "使用 /list 查看你的订阅，/expire 查看临期，/recycle 查看回收站，/help 查看命令。";
  return { text: lease.command === "start" ? `欢迎使用 subs-bot。\n${help}` : help, access: "allowed" };
}

export async function drainTelegramReplies(
  db: D1Database,
  policy: TelegramPolicy,
  limit: number,
  budgetMs: number,
  request: typeof fetch = fetch,
): Promise<void> {
  const deadline = Date.now() + budgetMs;
  await reapExpiredTelegramReplies(db, policy.botId);
  for (let processed = 0; processed < limit && Date.now() < deadline; processed += 1) {
    const lease = await claimTelegramReply(db, policy.botId);
    if (!lease) return;
    if (!inTelegramScope(policy, lease)) continue;
    const reply = await renderReply(db, policy, lease);
    const [view, lifecycle] = await Promise.all([
      reply.buttons?.length ? prepareTelegramViewTickets(reply.buttons) : undefined,
      reply.lifecycleButtons?.length ? prepareTelegramLifecycleTickets(reply.lifecycleButtons) : undefined,
    ]);
    if (Date.now() >= deadline ||
      !await beginTelegramReply(db, policy, lease, reply.access, view?.tickets, lifecycle?.tickets)) continue;
    const keyboard = [...(view?.keyboard ?? []), ...(lifecycle?.keyboard ?? [])];
    const outcome = await sendTelegramReply(policy, lease, reply.text, Math.max(1, deadline - Date.now()), request,
      keyboard, reply.forceReply);
    await settleTelegramReply(db, policy, lease, outcome);
  }
}

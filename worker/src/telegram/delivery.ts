import { listOwnedSubscriptions } from "../subscriptions.ts";
import type { PrivateShareClaimResult } from "../private-shares.ts";
import {
  prepareTelegramLifecycleTickets, renderTelegramLifecycle, type TelegramLifecycleButton,
} from "./lifecycle-actions.ts";
import { inTelegramScope, type TelegramPolicy } from "./protocol.ts";
import { beginTelegramPrivateClaim, prepareTelegramPrivateClaim } from "./private-claims.ts";
import {
  beginTelegramReply, claimTelegramReply, isTelegramMemberAllowed,
  prepareTelegramPrivateClaimBegin, reapExpiredTelegramReplies, settleTelegramReply,
  type TelegramReplyLease, type TelegramReplyOutcome,
} from "./store.ts";
import { prepareTelegramViewTickets, renderTelegramView, type TelegramViewButton } from "./views.ts";
import { renderTelegramTemp } from "./temp-import.ts";

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

async function sendTelegram(
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  method: "sendMessage" | "sendDocument",
  body: Record<string, unknown> | FormData,
  timeoutMs: number,
  request: typeof fetch,
): Promise<TelegramReplyOutcome> {
  if (!inTelegramScope(policy, lease)) return { kind: "failed" };
  try {
    const multipart = body instanceof FormData;
    const response = await request(`${BOT_API}/bot${policy.botToken}/${method}`, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(Math.min(SEND_TIMEOUT_MS, timeoutMs)),
      ...(multipart ? {} : { headers: { "Content-Type": "application/json" } }),
      body: multipart ? body : JSON.stringify(body),
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

function replyParameters(lease: TelegramReplyLease) {
  return { message_id: lease.messageId, allow_sending_without_reply: true };
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
  return sendTelegram(policy, lease, "sendMessage", {
    chat_id: lease.chatId,
    ...(lease.threadId === null ? {} : { message_thread_id: lease.threadId }),
    reply_parameters: replyParameters(lease),
    link_preview_options: { is_disabled: true },
    ...(keyboard?.length ? { reply_markup: { inline_keyboard: keyboard } }
      : forceReply && lease.chatType === "private" ? { reply_markup: { force_reply: true } } : {}),
    text,
  }, timeoutMs, request);
}

export async function sendTelegramPrivateClaimReply(
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  result: PrivateShareClaimResult,
  timeoutMs: number,
  request: typeof fetch = fetch,
): Promise<TelegramReplyOutcome> {
  if (!lease.privateClaim || !inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) {
    return { kind: "failed" };
  }
  if (!("content" in result)) {
    const reason = {
      unavailable: "分享不可用。",
      expired: "分享已过期。",
      target: "此分享指定了其他领取人。",
      exhausted: "分享份数已领完。",
    }[result.kind];
    return sendTelegramReply(policy, lease, `私密分享领取失败。\n${reason}`, timeoutMs, request);
  }
  const sender = result.senderName.replace(/[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/gu, " ")
    .replace(/[a-z][a-z0-9+.-]*:\/\/\S+/giu, "[链接已省略]").trim() || "用户";
  const caption = `私密分享\n来自：${sender}\n领取进度：${result.claimCount}/${result.maxClaims}`;
  const text = `${caption}\n\n${result.content}`;
  if (text.length <= 3800 && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/u.test(result.content)) {
    return sendTelegramReply(policy, lease, text, timeoutMs, request);
  }

  const form = new FormData();
  form.set("chat_id", lease.chatId);
  form.set("reply_parameters", JSON.stringify(replyParameters(lease)));
  form.set("caption", caption);
  form.set("document", new Blob([result.content], { type: "text/plain;charset=utf-8" }), "private-share.txt");
  return sendTelegram(policy, lease, "sendDocument", form, timeoutMs, request);
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
  if (lease.temp) return { text: renderTelegramTemp(lease.temp), access: "allowed" };
  if (lease.command === "list") {
    const page = await listOwnedSubscriptions(db, lease.actorId, { limit: LIST_LIMIT });
    const names = page.items.map((row, index) => {
      const name = Array.from(row.name.replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ")).slice(0, 80).join("");
      return `${index + 1}. ${name}`;
    });
    if (page.nextAfterId !== null) names.push(`仅显示前 ${LIST_LIMIT} 条。`);
    return { text: names.length ? `你的订阅\n${names.join("\n")}` : "你的订阅列表为空。", access: "allowed" };
  }
  const help = "使用 /list 查看你的订阅，/expire 查看临期，/recycle 查看回收站，/temp 查看临时节点，/help 查看命令。";
  return { text: lease.command === "start" ? `欢迎使用 subs-bot。\n${help}` : help, access: "allowed" };
}

export async function drainTelegramReplies(
  db: D1Database,
  bucket: R2Bucket,
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
    if (lease.privateClaim) {
      const begin = prepareTelegramPrivateClaimBegin(db, policy, lease);
      if (!begin) continue;
      const prepared = await prepareTelegramPrivateClaim(db, bucket, policy, lease);
      if (Date.now() >= deadline) continue;
      const result = await beginTelegramPrivateClaim(db, policy, lease, prepared, begin);
      if (result === null) continue;
      const outcome = await sendTelegramPrivateClaimReply(policy, lease, result,
        Math.max(1, deadline - Date.now()), request);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
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

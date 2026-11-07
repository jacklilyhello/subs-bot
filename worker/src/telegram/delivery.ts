import { listOwnedSubscriptions } from "../subscriptions.ts";
import { resolveTelegramAggregateCode, TELEGRAM_AGGREGATE_ORIGIN } from "./aggregate-actions.ts";
import { prepareSelectedLimitTickets, prepareSelectedRevokeTicket, renderTelegramSelected,
  resolveTelegramSelectedCode, retireUnsentSelectedLink } from "./selected-export.ts";
import type { PrivateShareClaimResult } from "../private-shares.ts";
import {
  prepareTelegramLifecycleTickets, renderTelegramLifecycle, type TelegramLifecycleButton,
} from "./lifecycle-actions.ts";
import { inTelegramScope, type TelegramPolicy } from "./protocol.ts";
import { renderTelegramInlineSort } from "./inline-sort.ts";
import { renderTelegramInlineConsent } from "./inline-search-consent.ts";
import type { InlineSearchArticle, InlineSearchOutcome } from "./inline-search.ts";
import { renderTelegramPath } from "./path-management.ts";
import { beginTelegramPrivateClaim, prepareTelegramPrivateClaim } from "./private-claims.ts";
import { resolveTelegramPrivateShareCreationReply } from "./private-share-creation.ts";
import { PRIVATE_SHARE_DISABLED, type TelegramPrivateShareRuntime } from "./private-share-runtime.ts";
import { confirmTelegramShortLinkSend, prepareTelegramShortLinkReply, retireUnsentTelegramShortLink } from "./short-link-actions.ts";
import {
  confirmTelegramSubscriptionReadSend, prepareTelegramSubscriptionReadTickets, renderTelegramSubscriptionRead,
  type TelegramSubscriptionReadButton,
} from "./subscription-read.ts";
import { prepareTelegramNodePageTickets, renderTelegramSubscriptionNodePage, type TelegramNodePageButton } from "./subscription-node-pages.ts";
import {
  beginTelegramAggregateLinkReply, beginTelegramInlineConsentReply, beginTelegramInlineSortReply, beginTelegramPrivateShareCreationReply,
  beginTelegramSelectedLinkReply, beginTelegramShortLinkReply, beginTelegramReply, claimTelegramReply, isTelegramMemberAllowed,
  beginTelegramTempRawReply,
  prepareTelegramPrivateClaimBegin, reapExpiredTelegramReplies, settleTelegramReply,
  type TelegramReplyLease, type TelegramReplyOutcome,
} from "./store.ts";
import { prepareTelegramViewTickets, renderTelegramView, type TelegramViewButton } from "./views.ts";
import { renderTelegramTemp } from "./temp-import.ts";
import { confirmTelegramTempRawSend, prepareTelegramTempRawReply } from "./temp-raw.ts";
import { renderTelegramProviderReply } from "./provider-replies.ts";

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
  if ((lease.path || lease.privateShareCreation || lease.tempRaw || lease.shortLink || lease.subscriptionNodes
    || lease.providerOutcome !== undefined)
    && (lease.chatType !== "private" || lease.threadId !== null)) {
    return { kind: "failed" };
  }
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

export async function sendTelegramInlineAnswer(
  policy: TelegramPolicy, queryId: string, results: readonly InlineSearchArticle[], timeoutMs: number,
): Promise<InlineSearchOutcome> {
  try {
    const response = await fetch(`${BOT_API}/bot${policy.botToken}/answerInlineQuery`, {
      method: "POST", redirect: "manual", signal: AbortSignal.timeout(timeoutMs),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ inline_query_id: queryId, results, is_personal: true, cache_time: 0, next_offset: "" }),
    });
    const payload = record(await readBotReply(response));
    if (response.ok && payload?.ok === true && payload.result === true) return "sent";
    if (response.status >= 400 && response.status < 500 && response.status !== 408
      && payload?.ok === false && payload.error_code === response.status) return "failed";
  } catch {
    // Transport and malformed outcomes cannot prove whether Telegram displayed a result.
  }
  return "uncertain";
}

async function renderReply(
  db: D1Database,
  bucket: R2Bucket,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  deadline: number,
  privateShareEnabled = false,
  subscriptionReadEnabled = false,
  subscriptionNodesEnabled = false,
): Promise<{
  text: string;
  access: ReplyAccess;
  buttons?: TelegramViewButton[];
  lifecycleButtons?: TelegramLifecycleButton[];
  readButtons?: TelegramSubscriptionReadButton[];
  nodeButtons?: TelegramNodePageButton[];
  readGuard?: { sql: string; bindings: readonly (string | number | null)[] };
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
  if (lease.subscriptionRead) return { ...await renderTelegramSubscriptionRead(db, bucket, policy, lease, deadline,
    subscriptionNodesEnabled), access: "allowed" };
  if (lease.subscriptionNodes) {
    const { backId, ...page } = await renderTelegramSubscriptionNodePage(db, bucket, policy, lease, deadline);
    return { ...page, access: "allowed", ...(backId === undefined ? {} : {
      readButtons: [{ text: "返回订阅详情", kind: "detail" as const, subscriptionId: backId }],
    }) };
  }
  if (lease.privateShareCreation) return { text: "分享链接已失效或授权已变更，请重新创建。", access: "allowed" };
  if (lease.aggregate) {
    const text = {
      issued: "聚合链接已变更，请重新发送 /export。",
      ready: "聚合链接已变更，请重新发送 /export。",
      empty: "暂无可导出节点。",
      limit: "聚合内容超过导出上限。",
      revoked: "聚合导出链接已撤销。",
      "already-revoked": "没有可撤销的聚合导出链接。",
      stale: "这条聚合操作已失效。",
    }[lease.aggregate.result];
    return { text, access: "allowed" };
  }
  if (lease.lifecycle) {
    const { text, buttons, forceReply } = renderTelegramLifecycle(lease.lifecycle);
    return { text, lifecycleButtons: buttons, forceReply, access: "allowed" };
  }
  if (lease.view) {
    const privateDetails = subscriptionReadEnabled && lease.chatType === "private" && lease.threadId === null;
    return { ...await renderTelegramView(db, lease.actorId, lease.view, privateDetails), access: "allowed" };
  }
  if (lease.temp) return { text: renderTelegramTemp(lease.temp), access: "allowed" };
  if (lease.path && lease.chatType === "private" && lease.threadId === null) {
    return { text: await renderTelegramPath(db, lease.actorId, lease.path), access: "allowed" };
  }
  if (lease.selected) return { text: renderTelegramSelected(lease.selected), access: "allowed" };
  if (lease.document) {
    const { kind, nodeCount } = lease.document;
    const text = {
      saved: `文件已导入，共 ${nodeCount ?? 0} 个节点。`,
      "invalid-document": "文件未导入。请检查文件类型、大小和节点格式。已有订阅保持原样。",
      "download-rejected": "无法读取 Telegram 文件。已有订阅保持原样。",
      coalesced: "已有同名文件已处理或正在处理，请核对后再试。",
      capacity: "待处理文件已达上限，请稍后重试。",
      expired: "文件导入已超时。已有订阅保持原样。",
      "access-changed": "授权状态已变更，文件未导入。",
      "attempts-exhausted": "文件导入未完成，请重试。已有订阅保持原样。",
    }[kind];
    return { text, access: "allowed" };
  }
  if (lease.command === "list") {
    const page = await listOwnedSubscriptions(db, lease.actorId, { limit: LIST_LIMIT });
    const names = page.items.map((row, index) => {
      const name = Array.from(row.name.replace(/[\u0000-\u001f\u007f-\u009f]/gu, " ")).slice(0, 80).join("");
      return `${index + 1}. ${name}`;
    });
    if (page.nextAfterId !== null) names.push(`仅显示前 ${LIST_LIMIT} 条。`);
    return { text: names.length ? `你的订阅\n${names.join("\n")}` : "你的订阅列表为空。", access: "allowed" };
  }
  const help = "使用 /list 查看你的订阅，/expire 查看临期，/recycle 查看回收站，/temp 查看临时节点，私聊 /path 管理路径规则，/o 关键词导出所选订阅。"
    + (subscriptionReadEnabled ? "\n/s 关键词搜索订阅，私聊发送列表编号可查看订阅详情。" : "")
    + (privateShareEnabled ? "\n私聊创建私密分享：/share [x份数] [id领取人ID] [s分钟] -- 正文。" : "");
  return { text: lease.command === "start" ? `欢迎使用 subs-bot。\n${help}` : help, access: "allowed" };
}

async function deliverTelegramShortLink(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, key: CryptoKey | null, deadline: number, request: typeof fetch,
): Promise<void> {
  if (lease.chatType !== "private" || lease.threadId !== null || !inTelegramScope(policy, lease)) return;
  const allowed = lease.actorId === policy.adminId || await isTelegramMemberAllowed(db, policy);
  const reply = allowed ? await prepareTelegramShortLinkReply(db, policy, lease, key)
    : { kind: "notice" as const, text: "当前账号没有使用权限。" };
  if (Date.now() >= deadline) return;
  if (reply.kind === "link") {
    if (!await beginTelegramShortLinkReply(db, policy, lease, reply.guard)) return;
    if (!await confirmTelegramShortLinkSend(db, policy, lease, reply.guard) || Date.now() >= deadline) {
      await settleTelegramReply(db, policy, lease, { kind: "failed" });
      return;
    }
  } else {
    await retireUnsentTelegramShortLink(db, policy, lease);
    if (!await beginTelegramReply(db, policy, lease, allowed ? "allowed" : "denied")) return;
  }
  if (Date.now() >= deadline) {
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    return;
  }
  const outcome = await sendTelegramReply(policy, lease, reply.text, Math.max(1, deadline - Date.now()), request);
  await settleTelegramReply(db, policy, lease, outcome);
}

async function deliverTelegramTempRaw(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, deadline: number, request: typeof fetch,
): Promise<void> {
  if (lease.chatType !== "private" || lease.threadId !== null || !inTelegramScope(policy, lease)) return;
  const allowed = lease.actorId === policy.adminId || await isTelegramMemberAllowed(db, policy);
  const prepared = allowed ? await prepareTelegramTempRawReply(db, policy, lease, deadline) : { kind: "stale" as const };
  if (Date.now() >= deadline) return;
  if (prepared.kind === "text" || prepared.kind === "document") {
    let send: (timeout: number) => Promise<TelegramReplyOutcome>;
    if (prepared.kind === "document") {
      const form = new FormData();
      form.set("chat_id", lease.chatId);
      form.set("reply_parameters", JSON.stringify(replyParameters(lease)));
      form.set("caption", prepared.caption);
      form.set("document", prepared.file, "temporary-nodes.txt");
      send = (timeout) => sendTelegram(policy, lease, "sendDocument", form, timeout, request);
    } else {
      send = (timeout) => sendTelegramReply(policy, lease, prepared.text, timeout, request);
    }
    if (!await beginTelegramTempRawReply(db, policy, lease, prepared.guard)) return;
    if (!await confirmTelegramTempRawSend(db, policy, lease, prepared.guard) || Date.now() >= deadline) {
      await settleTelegramReply(db, policy, lease, { kind: "failed" });
      return;
    }
    const outcome = await send(Math.max(1, deadline - Date.now()));
    await settleTelegramReply(db, policy, lease, outcome);
    return;
  }
  const text = !allowed ? "当前账号没有使用权限。"
    : prepared.kind === "stale" ? "临时列表或授权已变更，请重新发送 /temp。" : "暂时无法读取临时节点，请稍后重试。";
  if (!await beginTelegramReply(db, policy, lease, allowed ? "allowed" : "denied")) return;
  if (Date.now() >= deadline) {
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    return;
  }
  const outcome = await sendTelegramReply(policy, lease, text, Math.max(1, deadline - Date.now()), request);
  await settleTelegramReply(db, policy, lease, outcome);
}

export async function drainTelegramReplies(
  db: D1Database,
  bucket: R2Bucket,
  policy: TelegramPolicy,
  limit: number,
  budgetMs: number,
  request: typeof fetch = fetch,
  aggregateKey: CryptoKey | null = null,
  privateShareRuntime: TelegramPrivateShareRuntime = PRIVATE_SHARE_DISABLED,
  subscriptionReadEnabled = false,
  shortLinksEnabled = false,
  inlineSortEnabled = false,
  subscriptionNodesEnabled = false,
  providerEnabled = false,
  inlineConsentEnabled = false,
): Promise<void> {
  const deadline = Date.now() + budgetMs;
  const privateShareEnabled = privateShareRuntime.schemaReady && privateShareRuntime.context !== null;
  await reapExpiredTelegramReplies(db, policy.botId, aggregateKey !== null, privateShareEnabled, subscriptionReadEnabled,
    shortLinksEnabled, inlineSortEnabled, subscriptionNodesEnabled, providerEnabled, inlineConsentEnabled);
  for (let processed = 0; processed < limit && Date.now() < deadline; processed += 1) {
    const lease = await claimTelegramReply(db, policy.botId, aggregateKey !== null, privateShareEnabled, subscriptionReadEnabled,
      shortLinksEnabled, inlineSortEnabled, subscriptionNodesEnabled, providerEnabled ? policy : undefined, inlineConsentEnabled);
    if (!lease) return;
    if (!inTelegramScope(policy, lease)) continue;
    if (lease.providerOutcome !== undefined) {
      const text = renderTelegramProviderReply(lease.providerOutcome);
      if (Date.now() >= deadline || !await beginTelegramReply(db, policy, lease, "allowed")) continue;
      const outcome = await sendTelegramReply(policy, lease, text, Math.max(1, deadline - Date.now()), request);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.tempRaw) {
      await deliverTelegramTempRaw(db, policy, lease, deadline, request);
      continue;
    }
    if (lease.shortLink) {
      await deliverTelegramShortLink(db, policy, lease, aggregateKey, deadline, request);
      continue;
    }
    if (lease.inlineSort) {
      if (Date.now() < deadline && await beginTelegramInlineSortReply(db, policy, lease)) {
        const outcome = await sendTelegramReply(policy, lease, renderTelegramInlineSort(lease.inlineSort),
          Math.max(1, deadline - Date.now()), request);
        await settleTelegramReply(db, policy, lease, outcome);
      }
      continue;
    }
    if (lease.inlineConsent) {
      if (Date.now() < deadline && await beginTelegramInlineConsentReply(db, policy, lease)) {
        const outcome = await sendTelegramReply(policy, lease, renderTelegramInlineConsent(lease.inlineConsent),
          Math.max(1, deadline - Date.now()), request);
        await settleTelegramReply(db, policy, lease, outcome);
      }
      continue;
    }
    if (lease.privateShareCreation && privateShareRuntime.context) {
      const reply = await resolveTelegramPrivateShareCreationReply(db, policy, lease, privateShareRuntime.context);
      if (reply && Date.now() < deadline && await beginTelegramPrivateShareCreationReply(db, policy, lease, reply)) {
        const text = `私密分享已创建。\nhttps://t.me/${policy.botUsername}?start=claim_${reply.code}\n份数上限：${reply.maxClaims}\n到期时间（UTC）：${new Date(reply.expireAt * 1000).toISOString()}`;
        const outcome = await sendTelegramReply(policy, lease, text, Math.max(1, deadline - Date.now()), request);
        await settleTelegramReply(db, policy, lease, outcome);
        continue;
      }
    }
    if (lease.selected?.result === "issued" && lease.chatType === "private" && lease.threadId === null) {
      const scope = { ...lease, selected: lease.selected };
      const code = await resolveTelegramSelectedCode(db, policy, scope, aggregateKey);
      if (code !== null && Date.now() < deadline) {
        const ticket = await prepareSelectedRevokeTicket();
        if (await beginTelegramSelectedLinkReply(db, policy, lease, [{ ...ticket, codeSha256: lease.selected.codeSha256! }])) {
          const confirmed = await resolveTelegramSelectedCode(db, policy, scope, aggregateKey, true);
          if (confirmed !== code) await retireUnsentSelectedLink(db, policy, lease, "sending");
          const outcome = confirmed === code && Date.now() < deadline
            ? await sendTelegramReply(policy, lease, `Clash 所选订阅聚合链接\n${TELEGRAM_AGGREGATE_ORIGIN}/agg/${code}/clash`,
              Math.max(1, deadline - Date.now()), request, [[{ text: "撤销此链接", callback_data: ticket.token }]])
            : { kind: "failed" as const };
          await settleTelegramReply(db, policy, lease, outcome);
          continue;
        }
      }
      if (!await retireUnsentSelectedLink(db, policy, lease, "leased")) continue;
      lease.selected = { result: "stale", codeSha256: null };
    }
    if (lease.selected?.result === "limit" && lease.chatType === "private" && lease.threadId === null) {
      const tickets = await prepareSelectedLimitTickets(db, policy, lease.actorId);
      if (Date.now() >= deadline || !await beginTelegramSelectedLinkReply(db, policy, lease, tickets)) continue;
      const keyboard = tickets.map((ticket, index) => [{ text: `撤销最近第${index + 1}条链接`, callback_data: ticket.token }]);
      const outcome = await sendTelegramReply(policy, lease, renderTelegramSelected(lease.selected),
        Math.max(1, deadline - Date.now()), request, keyboard);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.aggregate && lease.chatType === "private" && lease.threadId === null) {
      const code = await resolveTelegramAggregateCode(db, policy, { ...lease, aggregate: lease.aggregate }, aggregateKey);
      if (code !== null && Date.now() < deadline && await beginTelegramAggregateLinkReply(db, policy, lease)) {
        const text = `Clash 聚合订阅链接\n${TELEGRAM_AGGREGATE_ORIGIN}/agg/${code}/clash\n发送 /export revoke 可撤销链接。`;
        const outcome = await sendTelegramReply(policy, lease, text, Math.max(1, deadline - Date.now()), request);
        await settleTelegramReply(db, policy, lease, outcome);
        continue;
      }
    }
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
    const reply = await renderReply(db, bucket, policy, lease, deadline, privateShareEnabled, subscriptionReadEnabled, subscriptionNodesEnabled);
    const [view, lifecycle, read, nodes] = await Promise.all([
      reply.buttons?.length ? prepareTelegramViewTickets(reply.buttons) : undefined,
      reply.lifecycleButtons?.length ? prepareTelegramLifecycleTickets(reply.lifecycleButtons) : undefined,
      reply.readButtons?.length ? prepareTelegramSubscriptionReadTickets(reply.readButtons) : undefined,
      reply.nodeButtons?.length ? prepareTelegramNodePageTickets(reply.nodeButtons) : undefined,
    ]);
    if (Date.now() >= deadline ||
      !await beginTelegramReply(db, policy, lease, reply.access, view?.tickets, lifecycle?.tickets, read?.tickets, reply.readGuard,
        nodes?.tickets)) continue;
    if (reply.readGuard) {
      const confirmed = await confirmTelegramSubscriptionReadSend(db, policy, lease, reply.readGuard).catch(() => false);
      if (!confirmed || Date.now() >= deadline) {
        await settleTelegramReply(db, policy, lease, { kind: "failed" });
        continue;
      }
    }
    const keyboard = [...(view?.keyboard ?? []), ...(lifecycle?.keyboard ?? []), ...(nodes?.keyboard ?? []), ...(read?.keyboard ?? [])];
    const outcome = await sendTelegramReply(policy, lease, reply.text, Math.max(1, deadline - Date.now()), request,
      keyboard, reply.forceReply);
    await settleTelegramReply(db, policy, lease, outcome);
  }
}

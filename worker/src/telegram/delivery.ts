import { AggregateLimitError, getAggregateNodeSource } from "../aggregate.ts";
import { ExportContentError, planBase64 } from "../base64-response.ts";
import { PathRuleContentError } from "../path-rules.ts";
import { ISOLATION_PUBLIC_ORIGIN, type PublicOrigin } from "../public-origin.ts";
import { listOwnedSubscriptions } from "../subscriptions.ts";
import { resolveTelegramAggregateCode } from "./aggregate-actions.ts";
import { prepareSelectedLimitTickets, prepareSelectedRevokeTicket, renderTelegramSelected,
  resolveTelegramSelectedCode, retireUnsentSelectedLink } from "./selected-export.ts";
import type { PrivateShareClaimResult } from "../private-shares.ts";
import {
  prepareTelegramLifecycleTickets, renderTelegramLifecycle, type TelegramLifecycleButton,
} from "./lifecycle-actions.ts";
import { GROUP_SHARE_PUBLISH_CALLBACK, inTelegramScope, TELEGRAM_PAGE_JUMP_CALLBACK, type TelegramPolicy } from "./protocol.ts";
import { confirmTelegramPageJumpSend, currentTelegramPageJumpEpoch, renderTelegramPageJump, telegramPageJumpSendGuard } from "./page-jump.ts";
import { closeUnsentTelegramBulkTrashReply, confirmTelegramBulkTrashSend, renderTelegramBulkTrash } from "./bulk-trash.ts";
import { renderTelegramInlineSort } from "./inline-sort.ts";
import { renderTelegramInlineConsent } from "./inline-search-consent.ts";
import type { InlineSearchArticle, InlineSearchOutcome } from "./inline-search.ts";
import { renderTelegramPath } from "./path-management.ts";
import { beginTelegramPrivateClaim, prepareTelegramPrivateClaim } from "./private-claims.ts";
import { resolveTelegramPrivateShareCreationReply } from "./private-share-creation.ts";
import { PRIVATE_SHARE_DISABLED, type TelegramPrivateShareRuntime } from "./private-share-runtime.ts";
import { telegramGroupShareReady } from "./group-share-actions.ts";
import { confirmTelegramShortLinkSend, prepareTelegramShortLinkReply, retireUnsentTelegramShortLink } from "./short-link-actions.ts";
import {
  confirmTelegramSubscriptionReadSend, prepareTelegramSubscriptionReadTickets, renderTelegramSubscriptionRead,
  type TelegramSubscriptionReadButton,
} from "./subscription-read.ts";
import { closeUnsentTelegramSubscriptionShort, hasTelegramSubscriptionShort, prepareTelegramSubscriptionShort,
  subscriptionShortSendGuard, telegramSubscriptionShortsReady, type SubscriptionShortCandidate,
  type SubscriptionShortTarget } from "./subscription-shorts.ts";
import { prepareTelegramNodePageTickets, renderTelegramSubscriptionNodePage, type TelegramNodePageButton } from "./subscription-node-pages.ts";
import { renderTelegramGitHubReply } from "./github-search.ts";
import { confirmTelegramSubscriptionRawFileSend, prepareTelegramRawFileButton, prepareTelegramSubscriptionRawFile,
  type TelegramRawFileTarget } from "./subscription-raw-file.ts";
import {
  beginTelegramAggregateLinkReply, beginTelegramBulkTrashReply, beginTelegramInlineConsentReply, beginTelegramInlineSortReply,
  beginTelegramPrivateShareCreationReply,
  beginTelegramSelectedLinkReply, beginTelegramShortLinkReply, beginTelegramReply, claimTelegramReply, closeUnsentTelegramPageJump, isTelegramMemberAllowed,
  beginTelegramSubscriptionShortReply, readTelegramAuthChangeOutcome,
  beginTelegramGitHubSearchReply, beginTelegramTempRawReply,
  beginTelegramSubscriptionRawFileReply, failLeasedTelegramSubscriptionRawFileReply,
  beginTelegramApiStatusReply, beginTelegramProviderBatchReply, beginTelegramProviderDocumentReply,
  closeUnsentTelegramGroupClaim, prepareTelegramPrivateClaimBegin, reapExpiredTelegramReplies, settleTelegramReply,
  type TelegramReplyLease, type TelegramReplyOutcome,
} from "./store.ts";
import { prepareTelegramViewTickets, renderTelegramView, type TelegramViewButton } from "./views.ts";
import { renderTelegramTemp } from "./temp-import.ts";
import { confirmTelegramTempRawSend, prepareTelegramTempRawReply } from "./temp-raw.ts";
import { renderTelegramProviderReply } from "./provider-replies.ts";
import { prepareTelegramProviderRefreshButton, type TelegramProviderRefreshTarget } from "./provider-refresh.ts";
import { renderTelegramProviderBatchReply } from "./provider-batch-controls.ts";
import { renderTelegramProviderDocumentReply } from "./provider-document-replies.ts";
import { renderTelegramApiStatus } from "./api-status.ts";
import { telegramMainMenuKeyboard, type TelegramMainMenuFeatures } from "./main-menu.ts";

const BOT_API = "https://api.telegram.org";
const MAX_RESPONSE_BYTES = 64 * 1024;
const SEND_TIMEOUT_MS = 10_000;
const CALLBACK_TIMEOUT_MS = 3_000;
const AGGREGATE_BASE64_TIMEOUT_MS = 2_500;
const LIST_LIMIT = 20;

type ReplyAccess = "allowed" | "denied" | "none";
type InlineKeyboard = ({ text: string; callback_data: string } | { text: string; url: string })[][];

async function aggregateBase64Section(
  db: D1Database, bucket: R2Bucket, code: string, deadline: number, publicOrigin: PublicOrigin,
): Promise<string> {
  const unavailable = "Base64：暂时无法验证，请稍后重试。";
  const start = Date.now();
  const budget = Math.min(AGGREGATE_BASE64_TIMEOUT_MS, deadline - start - SEND_TIMEOUT_MS);
  if (budget <= 0) return unavailable;
  const controller = new AbortController();
  const { signal } = controller;
  let timer: ReturnType<typeof setTimeout> | undefined;

  async function preflight(): Promise<string> {
    try {
      const source = await getAggregateNodeSource(db, bucket, code, false, signal);
      if (!source) return unavailable;
      await planBase64(source, signal);
      if (Date.now() >= start + budget) return unavailable;
      return `Base64 聚合订阅链接\n${publicOrigin}/agg/${code}/base64`;
    } catch (error) {
      return error instanceof ExportContentError || error instanceof PathRuleContentError || error instanceof AggregateLimitError
        ? "Base64：订阅内容不支持此格式。" : unavailable;
    }
  }

  // An in-flight binding read can outlast the timer. Cancel further reads without holding up the Clash reply.
  try {
    return await Promise.race([
      preflight(),
      new Promise<string>((resolve) => {
        timer = setTimeout(() => {
          controller.abort();
          resolve(unavailable);
        }, budget);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

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

async function postTelegram(
  botToken: string,
  chatId: string,
  method: "sendMessage" | "sendDocument" | "editMessageText",
  body: Record<string, unknown> | FormData,
  timeoutMs: number,
  request: typeof fetch,
  expectedThread?: number,
): Promise<TelegramReplyOutcome> {
  try {
    const multipart = body instanceof FormData;
    const editId = method === "editMessageText" && !multipart ? body.message_id : undefined;
    const response = await request(`${BOT_API}/bot${botToken}/${method}`, {
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
      if (positiveInteger(result?.message_id) && (method !== "editMessageText" || result.message_id === editId) &&
          typeof chat?.id === "number" && Number.isSafeInteger(chat.id) && String(chat.id) === chatId &&
          (expectedThread === undefined || result.message_thread_id === expectedThread)) {
        return { kind: "sent", messageId: result.message_id };
      }
    } else if (payload?.ok === false && payload.error_code === response.status &&
        response.status >= 400 && response.status < 500 && response.status !== 408) {
      if (response.status === 400 && positiveInteger(editId) && typeof payload.description === "string" &&
          (payload.description === "Bad Request: message is not modified" ||
            payload.description.startsWith("Bad Request: message is not modified:"))) return { kind: "sent", messageId: editId };
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

function sendTelegram(
  policy: TelegramPolicy,
  scope: Pick<TelegramReplyLease, "actorId" | "chatId" | "chatType">,
  method: "sendMessage" | "sendDocument" | "editMessageText",
  body: Record<string, unknown> | FormData,
  timeoutMs: number,
  request: typeof fetch,
): Promise<TelegramReplyOutcome> {
  return inTelegramScope(policy, scope)
    ? postTelegram(policy.botToken, scope.chatId, method, body, timeoutMs, request)
    : Promise.resolve({ kind: "failed" });
}

export function sendGeneralTelegramPrivateReply(
  botToken: string, actorId: string, messageId: number, text: string, keyboard?: InlineKeyboard, forceReply = false,
): Promise<TelegramReplyOutcome> {
  return postTelegram(botToken, actorId, "sendMessage", {
    chat_id: actorId, text, reply_parameters: { message_id: messageId }, link_preview_options: { is_disabled: true },
    ...(keyboard?.length ? { reply_markup: { inline_keyboard: keyboard } }
      : forceReply ? { reply_markup: { force_reply: true } } : {}),
  }, 5_000, fetch);
}

export function sendGeneralTelegramGroupListReply(
  botToken: string, chatId: string, messageId: number, threadId: number | null, text: string,
): Promise<TelegramReplyOutcome> {
  return postTelegram(botToken, chatId, "sendMessage", {
    chat_id: chatId, text, ...(threadId === null ? {} : { message_thread_id: threadId }),
    reply_parameters: { message_id: messageId, allow_sending_without_reply: false }, link_preview_options: { is_disabled: true },
  }, 5_000, fetch, threadId ?? undefined);
}

export function sendTelegramGroupShareCard(
  policy: TelegramPolicy, actorId: string, method: "sendMessage" | "editMessageText", body: Record<string, unknown>,
): Promise<TelegramReplyOutcome> {
  if (body.chat_id !== policy.groupId || (method === "editMessageText" && !positiveInteger(body.message_id))) {
    return Promise.resolve({ kind: "failed" });
  }
  return sendTelegram(policy, { actorId, chatId: policy.groupId, chatType: "group" }, method, body, 5_000, fetch);
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
  mainMenu?: TelegramMainMenuFeatures,
): Promise<TelegramReplyOutcome> {
  if ((lease.path || lease.privateShareCreation || lease.tempRaw || lease.shortLink || lease.subscriptionNodes || lease.subscriptionRawFile
    || lease.providerOutcome !== undefined || lease.bulkTrash || lease.githubSearch || lease.providerBatch || lease.apiStatus || lease.providerDocument)
    && (lease.chatType !== "private" || lease.threadId !== null)) {
    return { kind: "failed" };
  }
  return sendTelegram(policy, lease, "sendMessage", {
    chat_id: lease.chatId,
    ...(lease.threadId === null ? {} : { message_thread_id: lease.threadId }),
    reply_parameters: replyParameters(lease),
    link_preview_options: { is_disabled: true },
    ...(keyboard?.length ? { reply_markup: { inline_keyboard: keyboard } }
      : forceReply && lease.chatType === "private" ? { reply_markup: { force_reply: true } }
      : mainMenu && lease.chatType === "private" && lease.threadId === null && (lease.command === "start" || lease.command === "help")
        ? { reply_markup: { keyboard: telegramMainMenuKeyboard(mainMenu), resize_keyboard: true } } : {}),
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

export async function answerTelegramCallback(
  policy: Pick<TelegramPolicy, "botToken">, callbackId: string, answer?: string | { url: string },
): Promise<void> {
  try {
    const response = await fetch(`${BOT_API}/bot${policy.botToken}/answerCallbackQuery`, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(CALLBACK_TIMEOUT_MS),
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ callback_query_id: callbackId,
        ...(answer === undefined ? {} : { ...(typeof answer === "string" ? { text: answer } : answer), cache_time: 0 }) }),
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
  menuFeatures: TelegramMainMenuFeatures,
  publicOrigin: PublicOrigin,
  privateShareEnabled = false,
  subscriptionReadEnabled = false,
  subscriptionNodesEnabled = false,
  providerRefreshEnabled = false,
  subscriptionRawFileEnabled = false,
): Promise<{
  text: string;
  access: ReplyAccess;
  buttons?: TelegramViewButton[];
  lifecycleButtons?: TelegramLifecycleButton[];
  readButtons?: TelegramSubscriptionReadButton[];
  nodeButtons?: TelegramNodePageButton[];
  refreshTarget?: TelegramProviderRefreshTarget;
  rawFileTarget?: TelegramRawFileTarget;
  readGuard?: { sql: string; bindings: readonly (string | number | null)[] };
  shortTarget?: SubscriptionShortTarget & { label: string };
  forceReply?: boolean;
  mainMenu?: TelegramMainMenuFeatures;
}> {
  if (lease.command.startsWith("auth-")) {
    if (lease.actorId !== policy.adminId) return { text: "只有管理员可以管理授权。", access: "none" };
    if (lease.chatType !== "private") return { text: "请在私聊中管理授权。", access: "none" };
    if (lease.command === "auth-usage") return { text: "用法：/auth list、/auth add 用户ID、/auth remove 用户ID。", access: "none" };
    if (lease.command === "auth-add" || lease.command === "auth-remove") {
      const allowed = lease.command === "auth-add";
      const outcome = await readTelegramAuthChangeOutcome(db, policy, lease, allowed);
      if (outcome === "confirmed") return { text: `用户 ${policy.memberId}：${allowed ? "已授权" : "已撤权"}。`, access: "none" };
      const text = outcome === "superseded" ? "收到更新的授权操作。请用 /auth list 查看当前状态。"
        : "无法核对这次授权操作。请用 /auth list 查看当前状态。";
      return { text, access: "none" };
    }
    const memberAllowed = await isTelegramMemberAllowed(db, policy);
    return {
      text: `管理员 ${policy.adminId}\n用户 ${policy.memberId}：${memberAllowed ? "已授权" : "已撤权"}`,
      access: "none",
    };
  }
  const allowed = lease.actorId === policy.adminId || await isTelegramMemberAllowed(db, policy);
  if (!allowed) return { text: "当前账号没有使用权限。", access: "denied" };
  if (lease.subscriptionShareUnavailable) return { text: "无法分享此订阅。请在私聊打开自己的订阅详情后重试。", access: "allowed" };
  if (lease.subscriptionRead) return { ...await renderTelegramSubscriptionRead(db, bucket, policy, lease, deadline,
    subscriptionNodesEnabled, providerRefreshEnabled, subscriptionRawFileEnabled, privateShareEnabled, publicOrigin), access: "allowed" };
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
    return { ...await renderTelegramView(db, lease.actorId, lease.view, privateDetails, privateDetails || lease.pageJump === true),
      access: "allowed" };
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
  const privateChat = lease.chatType === "private" && lease.threadId === null;
  const help = "使用 /list 查看你的订阅，/expire 查看临期，/recycle 查看回收站。"
    + (subscriptionReadEnabled ? "\n/s 关键词搜索订阅。" : "")
    + (privateChat ? "\n/temp 查看临时节点，/path 管理路径规则。"
      + (subscriptionReadEnabled ? "\n发送列表编号查看订阅详情。" : "")
      + (menuFeatures.aggregate ? "\n/export 导出全部订阅，/o 关键词导出所选订阅。" : "")
      + (menuFeatures.batchRefresh ? "\n/updateall 预览批量刷新。" : "")
      + (privateShareEnabled ? "\n创建私密分享：/share [x份数] [id领取人ID] [s分钟] -- 正文。"
        + "\n分享自己的订阅：/share sub 订阅ID [x份数] [id领取人ID] [s分钟]。" : "") : "");
  return {
    text: lease.command === "start" ? `欢迎使用 subs-bot。\n${help}` : help,
    access: "allowed",
    ...(privateChat && (lease.command === "start" || lease.command === "help") ? { mainMenu: menuFeatures } : {}),
  };
}

async function deliverTelegramShortLink(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, key: CryptoKey | null, deadline: number, request: typeof fetch,
  publicOrigin: PublicOrigin,
): Promise<void> {
  if (lease.chatType !== "private" || lease.threadId !== null || !inTelegramScope(policy, lease)) return;
  const allowed = lease.actorId === policy.adminId || await isTelegramMemberAllowed(db, policy);
  const reply = allowed ? await prepareTelegramShortLinkReply(db, policy, lease, key, publicOrigin)
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

async function deliverTelegramSubscriptionRawFile(
  db: D1Database, bucket: R2Bucket, policy: TelegramPolicy, lease: TelegramReplyLease, deadline: number, request: typeof fetch,
): Promise<void> {
  const prepared = await prepareTelegramSubscriptionRawFile(db, bucket, policy, lease, deadline);
  if (Date.now() >= deadline) return;
  if (!prepared) {
    await failLeasedTelegramSubscriptionRawFileReply(db, policy, lease);
    return;
  }
  let send: (timeout: number) => Promise<TelegramReplyOutcome>;
  if (prepared.kind === "document") {
    const form = new FormData();
    form.set("chat_id", lease.chatId);
    form.set("reply_parameters", JSON.stringify({ message_id: lease.messageId, allow_sending_without_reply: false }));
    form.set("caption", "📦 节点导出完成");
    form.set("document", prepared.file, "Base64.txt");
    send = (timeout) => sendTelegram(policy, lease, "sendDocument", form, timeout, request);
  } else {
    send = (timeout) => sendTelegramReply(policy, lease, prepared.text, timeout, request);
  }
  if (!await beginTelegramSubscriptionRawFileReply(db, policy, lease, prepared.guard)) {
    await failLeasedTelegramSubscriptionRawFileReply(db, policy, lease);
    return;
  }
  if (!await confirmTelegramSubscriptionRawFileSend(db, policy, lease, prepared.guard) || Date.now() >= deadline) {
    await settleTelegramReply(db, policy, lease, { kind: "failed" });
    return;
  }
  await settleTelegramReply(db, policy, lease, await send(Math.max(1, deadline - Date.now())));
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
  bulkTrashEnabled = false,
  inlineConsentEnabled = false,
  gitHubSearchReadiness: boolean | "unavailable" = false,
  providerRefreshEnabled = false,
  subscriptionRawFileReadiness: boolean | "unavailable" = false,
  providerBatchReadiness: boolean | "unavailable" = false,
  apiStatusReadiness: boolean | "unavailable" = false,
  apiStatusPromptsEnabled = false,
  providerDocumentReadiness: boolean | "unavailable" = false,
  providerBatchAdmissionEnabled = false,
  pageJumpEpoch: number | null = null,
  publicOrigin: PublicOrigin = ISOLATION_PUBLIC_ORIGIN,
  subscriptionShortsEnabled = false,
): Promise<void> {
  const deadline = Date.now() + budgetMs;
  let subscriptionShortsReady: Promise<boolean> | undefined;
  const privateShareEnabled = privateShareRuntime.schemaReady && privateShareRuntime.context !== null;
  const gitHubSearchEnabled = gitHubSearchReadiness === true;
  const gitHubSearch = gitHubSearchEnabled ? policy : gitHubSearchReadiness === "unavailable" ? "unavailable" : undefined;
  const subscriptionRawFileEnabled = subscriptionRawFileReadiness === true;
  const providerBatchEnabled = providerBatchReadiness === true;
  const providerBatch = providerBatchEnabled ? policy : providerBatchReadiness === "unavailable" ? "unavailable" : undefined;
  const menuFeatures = { aggregate: aggregateKey !== null, batchRefresh: providerBatchEnabled && providerBatchAdmissionEnabled };
  const apiStatusEnabled = apiStatusReadiness === true;
  const apiStatus = apiStatusEnabled ? policy : apiStatusReadiness === "unavailable" ? "unavailable" : undefined;
  const providerDocumentEnabled = providerDocumentReadiness === true;
  const providerDocument = providerDocumentEnabled ? policy : providerDocumentReadiness === "unavailable" ? "unavailable" : undefined;
  await reapExpiredTelegramReplies(db, policy.botId, aggregateKey !== null, privateShareEnabled, subscriptionReadEnabled,
    shortLinksEnabled, inlineSortEnabled, subscriptionNodesEnabled, providerEnabled, bulkTrashEnabled, inlineConsentEnabled,
    gitHubSearchEnabled, subscriptionRawFileEnabled, providerBatchEnabled, apiStatusEnabled, providerDocumentEnabled);
  for (let processed = 0; processed < limit && Date.now() < deadline; processed += 1) {
    const lease = await claimTelegramReply(db, policy.botId, aggregateKey !== null, privateShareEnabled, subscriptionReadEnabled,
      shortLinksEnabled, inlineSortEnabled, subscriptionNodesEnabled, providerEnabled ? policy : undefined,
      bulkTrashEnabled, inlineConsentEnabled, gitHubSearch, subscriptionRawFileReadiness, providerBatch, apiStatus, providerDocument);
    if (!lease) return;
    if (!inTelegramScope(policy, lease)) continue;
    if (lease.apiStatus) {
      const presentation = await renderTelegramApiStatus(db, policy, lease);
      const guard = presentation?.forceReply && !apiStatusPromptsEnabled ? undefined : presentation?.guard;
      if (Date.now() >= deadline || !await beginTelegramApiStatusReply(db, policy, lease, guard) || !presentation) continue;
      const timeout = Math.max(1, deadline - Date.now());
      const outcome = presentation.forceReply
        ? await sendTelegramReply(policy, lease, presentation.text, timeout, request, undefined, true)
        : await sendTelegram(policy, lease, "sendMessage", { chat_id: lease.chatId, text: presentation.text,
          link_preview_options: { is_disabled: true } }, timeout, request);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.providerBatch) {
      const prepared = await renderTelegramProviderBatchReply(db, policy, lease);
      if (Date.now() >= deadline) continue;
      const begun = await beginTelegramProviderBatchReply(db, policy, lease, prepared);
      if (begun === "closed" || !prepared) continue;
      let buttons: InlineKeyboard | undefined;
      if (prepared.ticket) buttons = [[{ text: "确认刷新", callback_data: prepared.ticket.value }]];
      if (begun === "cleanup-installed" && prepared.cleanup) {
        buttons = [[{ text: `确认将本批 ${prepared.cleanup.count} 条失败订阅移入回收站`, callback_data: prepared.cleanup.token }]];
      }
      const outcome = await sendTelegramReply(policy, lease, prepared.text, Math.max(1, deadline - Date.now()), request, buttons);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.providerDocument) {
      const presentation = await renderTelegramProviderDocumentReply(db, policy, lease);
      if (Date.now() >= deadline || !await beginTelegramProviderDocumentReply(db, policy, lease, presentation?.guard) || !presentation) continue;
      const outcome = await sendTelegramReply(policy, lease, presentation.text, Math.max(1, deadline - Date.now()), request);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.providerOutcome !== undefined) {
      if (lease.providerRequestKind === undefined) continue;
      const text = renderTelegramProviderReply(lease.providerOutcome, lease.providerRequestKind);
      if (Date.now() >= deadline || !await beginTelegramReply(db, policy, lease, "allowed")) continue;
      const outcome = await sendTelegramReply(policy, lease, text, Math.max(1, deadline - Date.now()), request);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.bulkTrash) {
      const prepared = await renderTelegramBulkTrash(db, policy, lease);
      if (Date.now() >= deadline) continue;
      if (!prepared || !await beginTelegramBulkTrashReply(db, policy, lease, prepared.guard, prepared.ticket?.sha256)) {
        await closeUnsentTelegramBulkTrashReply(db, policy, lease);
        continue;
      }
      if (!await confirmTelegramBulkTrashSend(db, policy, lease, prepared.guard, prepared.ticket?.sha256) || Date.now() >= deadline) {
        await settleTelegramReply(db, policy, lease, { kind: "failed" });
        continue;
      }
      const keyboard = prepared.ticket ? [[{ text: "确认移入回收站", callback_data: prepared.ticket.token }]] : undefined;
      const outcome = await sendTelegramReply(policy, lease, prepared.text, Math.max(1, deadline - Date.now()), request, keyboard);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    if (lease.tempRaw) {
      await deliverTelegramTempRaw(db, policy, lease, deadline, request);
      continue;
    }
    if (lease.subscriptionRawFile) {
      await deliverTelegramSubscriptionRawFile(db, bucket, policy, lease, deadline, request);
      continue;
    }
    if (lease.shortLink) {
      await deliverTelegramShortLink(db, policy, lease, aggregateKey, deadline, request, publicOrigin);
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
    if (lease.githubSearch) {
      const reply = renderTelegramGitHubReply(lease.githubSearch);
      if (Date.now() < deadline && await beginTelegramGitHubSearchReply(db, policy, lease)) {
        const outcome = Date.now() < deadline
          ? await sendTelegramReply(policy, lease, reply.text, Math.max(1, deadline - Date.now()), request, reply.keyboard)
          : { kind: "failed" as const };
        await settleTelegramReply(db, policy, lease, outcome);
      }
      continue;
    }
    if (lease.privateShareCreation && privateShareRuntime.context) {
      const reply = await resolveTelegramPrivateShareCreationReply(db, policy, lease, privateShareRuntime.context);
      const groupButton = reply && privateShareRuntime.groupCardsEnabled && await telegramGroupShareReady(db)
        ? [[{ text: "发到指定群", callback_data: GROUP_SHARE_PUBLISH_CALLBACK }]] : undefined;
      if (reply && Date.now() < deadline && await beginTelegramPrivateShareCreationReply(db, policy, lease, reply)) {
        const text = `私密分享已创建。\nhttps://t.me/${policy.botUsername}?start=claim_${reply.code}\n份数上限：${reply.maxClaims}\n到期时间（UTC）：${new Date(reply.expireAt * 1000).toISOString()}`;
        const outcome = await sendTelegramReply(policy, lease, text, Math.max(1, deadline - Date.now()), request, groupButton);
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
            ? await sendTelegramReply(policy, lease, `Clash 所选订阅聚合链接\n${publicOrigin}/agg/${code}/clash`,
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
      if (code !== null && Date.now() < deadline) {
        const base64 = await aggregateBase64Section(db, bucket, code, deadline, publicOrigin);
        if (Date.now() < deadline && await beginTelegramAggregateLinkReply(db, policy, lease)) {
          const text = `Clash 聚合订阅链接\n${publicOrigin}/agg/${code}/clash\n${base64}\n发送 /export revoke 可撤销链接。`;
          const remaining = deadline - Date.now();
          const outcome = remaining > 0 ? await sendTelegramReply(policy, lease, text, remaining, request) : { kind: "failed" as const };
          await settleTelegramReply(db, policy, lease, outcome);
          continue;
        }
      }
    }
    if (lease.privateClaim) {
      const begin = prepareTelegramPrivateClaimBegin(db, policy, lease);
      if (!begin) continue;
      const prepared = await prepareTelegramPrivateClaim(db, bucket, policy, lease);
      if (Date.now() >= deadline) continue;
      const result = await beginTelegramPrivateClaim(db, policy, lease, prepared, begin);
      if (result === null) {
        await closeUnsentTelegramGroupClaim(db, policy, lease);
        continue;
      }
      const outcome = await sendTelegramPrivateClaimReply(policy, lease, result,
        Math.max(1, deadline - Date.now()), request);
      await settleTelegramReply(db, policy, lease, outcome);
      continue;
    }
    const jump = lease.pageJump ? await renderTelegramPageJump(db, lease.receiptId) : null;
    const prompt = jump !== null && jump !== "page" && jump.forceReply;
    const promptEpoch = prompt ? await currentTelegramPageJumpEpoch(db, policy.botId, lease.receiptId) : null;
    if (lease.pageJump && (!jump || (prompt && promptEpoch === null))) {
      await closeUnsentTelegramPageJump(db, policy, lease);
      continue;
    }
    const reply: Awaited<ReturnType<typeof renderReply>> = jump && jump !== "page" ? { ...jump, access: "allowed" }
      : await renderReply(db, bucket, policy, lease, deadline, menuFeatures, publicOrigin, privateShareEnabled, subscriptionReadEnabled,
        subscriptionNodesEnabled, providerRefreshEnabled, subscriptionRawFileEnabled);
    // A default-off first attempt cannot already own a typed short. A retry can.
    if (lease.subscriptionRead && lease.chatType === "private" && lease.threadId === null
      && (lease.attempts > 1 || (subscriptionShortsEnabled && reply.shortTarget))) {
      const { readGuard, shortTarget } = reply;
      let started: SubscriptionShortCandidate | null = null;
      let beginning = false;
      try {
        subscriptionShortsReady ??= telegramSubscriptionShortsReady(db);
        if (await subscriptionShortsReady) {
          if (readGuard && shortTarget && aggregateKey) {
            const candidate = await prepareTelegramSubscriptionShort(db, policy, lease, shortTarget, readGuard,
              aggregateKey, subscriptionShortsEnabled);
            if (Date.now() >= deadline) continue;
            if (candidate) {
              beginning = true;
              if (await beginTelegramSubscriptionShortReply(db, policy, lease, candidate, readGuard)) started = candidate;
            }
          }
          if (!started && await hasTelegramSubscriptionShort(db, policy, lease)) {
            await closeUnsentTelegramSubscriptionShort(db, policy, lease);
            continue;
          }
        }
      } catch {
        if (beginning) await closeUnsentTelegramSubscriptionShort(db, policy, lease);
        continue;
      }
      if (started && readGuard && shortTarget) {
        const guard = subscriptionShortSendGuard(started, readGuard);
        const confirmed = await confirmTelegramSubscriptionReadSend(db, policy, lease, guard).catch(() => false);
        const remaining = deadline - Date.now();
        const outcome = confirmed && remaining > 0
          ? await sendTelegramReply(policy, lease, `${shortTarget.label}\n${publicOrigin}/s/${started.code}`, remaining, request)
          : { kind: "failed" as const };
        await settleTelegramReply(db, policy, lease, outcome);
        continue;
      }
      if (subscriptionShortsEnabled && shortTarget) reply.text = "暂时无法生成订阅短链，请重新打开订阅详情后重试。";
    }
    const jumpButton = pageJumpEpoch !== null && lease.view?.kind === "list" && (!jump || jump === "page") && reply.access === "allowed"
      && await currentTelegramPageJumpEpoch(db, policy.botId, lease.receiptId) === pageJumpEpoch;
    const [view, lifecycle, read, nodes, refresh, rawFile] = await Promise.all([
      reply.buttons?.length ? prepareTelegramViewTickets(reply.buttons) : undefined,
      reply.lifecycleButtons?.length ? prepareTelegramLifecycleTickets(reply.lifecycleButtons) : undefined,
      reply.readButtons?.length ? prepareTelegramSubscriptionReadTickets(reply.readButtons) : undefined,
      reply.nodeButtons?.length ? prepareTelegramNodePageTickets(reply.nodeButtons) : undefined,
      reply.refreshTarget ? prepareTelegramProviderRefreshButton(reply.refreshTarget) : undefined,
      reply.rawFileTarget ? prepareTelegramRawFileButton(reply.rawFileTarget) : undefined,
    ]);
    if (Date.now() >= deadline) continue;
    const jumpGuard = jump ? telegramPageJumpSendGuard(policy, promptEpoch) : undefined;
    if (!await beginTelegramReply(db, policy, lease, reply.access, view?.tickets, lifecycle?.tickets, read?.tickets, reply.readGuard,
      nodes?.tickets, refresh?.ticket, rawFile?.ticket, jumpGuard)) {
      if (jump) await closeUnsentTelegramPageJump(db, policy, lease);
      continue;
    }
    if (jumpGuard && (!await confirmTelegramPageJumpSend(db, policy, lease, jumpGuard) || Date.now() >= deadline)) {
      await settleTelegramReply(db, policy, lease, { kind: "failed" });
      continue;
    }
    if (reply.readGuard) {
      const confirmed = await confirmTelegramSubscriptionReadSend(db, policy, lease, reply.readGuard).catch(() => false);
      if (!confirmed || Date.now() >= deadline) {
        await settleTelegramReply(db, policy, lease, { kind: "failed" });
        continue;
      }
    }
    const keyboard = [...(view?.keyboard ?? []), ...(jumpButton ? [[{ text: "🔢 跳转页", callback_data: TELEGRAM_PAGE_JUMP_CALLBACK }]] : []),
      ...(lifecycle?.keyboard ?? []), ...(nodes?.keyboard ?? []), ...(read?.keyboard ?? []),
      ...(refresh ? [[refresh.button]] : []), ...(rawFile ? [[rawFile.button]] : [])];
    const outcome = await sendTelegramReply(policy, lease, reply.text, Math.max(1, deadline - Date.now()), request,
      keyboard, reply.forceReply, reply.mainMenu);
    await settleTelegramReply(db, policy, lease, outcome);
  }
}

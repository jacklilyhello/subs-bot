import { collapsePathRuleWhitespace, PATH_RULE_WHITESPACE_PREFIX } from "../path-rules.ts";
import type { TelegramDocumentJobInput } from "./document-jobs.ts";

export interface TelegramPolicy {
  botId: string;
  botUsername: string;
  adminId: string;
  memberId: string;
  groupId: string;
  webhookSecret: string;
  botToken: string;
}

export interface TelegramEventScope {
  updateId: number;
  actorId: string;
  chatId: string;
  chatType: "private" | "group" | "supergroup";
  messageId: number;
  messageDate: number;
  threadId: number | null;
}

export interface TelegramCommand extends TelegramEventScope {
  command: "start" | "help" | "list" | "auth-list" | "auth-add" | "auth-remove" | "auth-usage";
}

export type TelegramViewKind = "list" | "expiry" | "recycle";

export type TelegramViewUpdate = TelegramEventScope & (
  | { kind: TelegramViewKind }
  | { kind: "callback"; callbackId: string; ticket: string }
);

export type TelegramLifecycleUpdate = TelegramEventScope & (
  | { kind: "lifecycle-callback"; callbackId: string; ticket: string }
  | { kind: "rename-reply"; promptMessageId: number; text: string }
);

export type TelegramPrivateClaimUpdate = TelegramEventScope & { kind: "private-claim"; code: string };
export type TelegramAggregateUpdate = TelegramEventScope & { kind: "show" | "revoke" };
export type TelegramSelectedUpdate = TelegramEventScope & (
  | { kind: "selected"; query: string }
  | { kind: "selected-revoke"; callbackId: string; ticket: string }
);

export type TelegramTempUpdate = TelegramEventScope & (
  | { kind: "temp-text"; text: string }
  | { kind: "temp-raw" | "temp-summary" | "temp-clear" }
);

export type TelegramPathUpdate = TelegramEventScope & { kind: "path"; args: string };
export type TelegramPrivateShareCreationUpdate = TelegramEventScope & { args: string; senderName?: string };
export type TelegramShortLinkUpdate = TelegramEventScope & { args: string };
export type TelegramSubscriptionReadUpdate = TelegramEventScope & (
  | { kind: "search"; query: string }
  | { kind: "number"; position: number }
  | { kind: "callback"; callbackId: string; ticket: string }
);

export type TelegramInlineSortMode = "default" | "traffic" | "expiry" | "name";
type TelegramInlineSortAction = { kind: "current" | "usage" } | { kind: "set"; mode: TelegramInlineSortMode };
export type TelegramInlineSortUpdate = TelegramEventScope & TelegramInlineSortAction;

type ExistingUpdate =
  | { command: TelegramCommand; view?: never; lifecycle?: never; privateClaim?: never; temp?: never; aggregate?: never; path?: never; document?: never; selected?: never }
  | { view: TelegramViewUpdate; command?: never; lifecycle?: never; privateClaim?: never; temp?: never; aggregate?: never; path?: never; document?: never; selected?: never }
  | { lifecycle: TelegramLifecycleUpdate; command?: never; view?: never; privateClaim?: never; temp?: never; aggregate?: never; path?: never; document?: never; selected?: never }
  | { privateClaim: TelegramPrivateClaimUpdate; command?: never; view?: never; lifecycle?: never; temp?: never; aggregate?: never; path?: never; document?: never; selected?: never }
  | { temp: TelegramTempUpdate; command?: never; view?: never; lifecycle?: never; privateClaim?: never; aggregate?: never; path?: never; document?: never; selected?: never }
  | { aggregate: TelegramAggregateUpdate; command?: never; view?: never; lifecycle?: never; privateClaim?: never; temp?: never; path?: never; document?: never; selected?: never }
  | { path: TelegramPathUpdate; command?: never; view?: never; lifecycle?: never; privateClaim?: never; temp?: never; aggregate?: never; document?: never; selected?: never }
  | { document: TelegramDocumentJobInput; command?: never; view?: never; lifecycle?: never; privateClaim?: never; temp?: never; aggregate?: never; path?: never; selected?: never }
  | { selected: TelegramSelectedUpdate; command?: never; view?: never; lifecycle?: never; privateClaim?: never; temp?: never; aggregate?: never; path?: never; document?: never };

type CurrentUpdate = (ExistingUpdate & { privateShareCreation?: never })
  | ({ privateShareCreation: TelegramPrivateShareCreationUpdate } & Partial<Record<keyof ExistingUpdate, never>>);
type SubscriptionUpdate = (CurrentUpdate & { subscriptionRead?: never })
  | ({ subscriptionRead: TelegramSubscriptionReadUpdate } & Partial<Record<keyof CurrentUpdate, never>>);
type ShortLinkUpdate = (SubscriptionUpdate & { shortLink?: never })
  | ({ shortLink: TelegramShortLinkUpdate } & Partial<Record<keyof SubscriptionUpdate, never>>);

type NormalizedUpdate = (ShortLinkUpdate & { inlineSort?: never })
  | ({ inlineSort: TelegramInlineSortUpdate } & Partial<Record<keyof ShortLinkUpdate, never>>);

type DecodedTelegramRequest =
  | ({ status: 200 } & NormalizedUpdate)
  | ({ status: 204 | 400 | 401 | 413 | 415 } & Partial<Record<keyof NormalizedUpdate, never>>);

const MAX_UPDATE_BYTES = 64 * 1024;
const USERNAME = /^[A-Za-z0-9_]{5,32}(?![\s\S])/;
const WEBHOOK_SECRET = /^[A-Za-z0-9_-]{1,256}(?![\s\S])/;
const BOT_TOKEN = /^[1-9][0-9]*:[A-Za-z0-9_-]{1,128}(?![\s\S])/;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset\s*=\s*(?:"utf-8"|utf-8))?$/i;
const BOT_COMMAND = /^\/([A-Za-z0-9_]{1,32})(?:@([A-Za-z0-9_]{5,32}))?(?![\s\S])/;
const CALLBACK_ID = /^[\u0021-\u007e]{1,128}(?![\s\S])/u;
const DOCUMENT_FILE_ID = /^[!-~]{1,512}(?![\s\S])/u;
const MAX_DOCUMENT_FILENAME = 1024;
const VIEW_TICKET = /^sbv1_[A-Za-z0-9_-]{22}(?![\s\S])/;
const LIFECYCLE_TICKET = /^sba1_[A-Za-z0-9_-]{22}(?![\s\S])/;
const SELECTED_TICKET = /^sbo1_[A-Za-z0-9_-]{22}(?![\s\S])/;
export const SUBSCRIPTION_READ_TICKET = /^sbr1_[A-Za-z0-9_-]{22}(?![\s\S])/;
const RENAME_CANCEL = /^(?:\/cancel|cancel|取消|退出)(?![\s\S])/iu;
const PRIVATE_CLAIM = /^claim_([A-Za-z0-9_-]{11}|[A-Za-z0-9_-]{22})(?![\s\S])/u;
const NON_HUMAN_MESSAGE_FIELDS = [
  "sender_chat", "sender_business_bot", "via_bot", "forward_origin", "forward_date",
  "forward_from", "forward_from_chat", "forward_from_message_id", "forward_sender_name", "forward_signature",
];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isPositiveInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function matches(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

function canonicalId(value: unknown, negative = false): value is string {
  const pattern = negative ? /^-[1-9][0-9]{0,15}$/ : /^[1-9][0-9]{0,15}$/;
  return matches(value, pattern) && Number.isSafeInteger(Number(value)) && String(Number(value)) === value;
}

export function parseTelegramPolicy(input: unknown): TelegramPolicy | null {
  if (typeof input !== "string" || input.length > 4096) return null;
  let value: unknown;
  try {
    value = JSON.parse(input);
  } catch {
    return null;
  }
  if (!isRecord(value) || Object.keys(value).length !== 7) return null;
  const { botId, botUsername, adminId, memberId, groupId, webhookSecret, botToken } = value;
  if (
    !canonicalId(botId) || !canonicalId(adminId) || !canonicalId(memberId) || !canonicalId(groupId, true)
    || new Set([botId, adminId, memberId]).size !== 3
    || !matches(botUsername, USERNAME) || !matches(webhookSecret, WEBHOOK_SECRET)
    || !matches(botToken, BOT_TOKEN) || !botToken.startsWith(`${botId}:`)
  ) return null;
  return { botId, botUsername, adminId, memberId, groupId, webhookSecret, botToken };
}

export function inTelegramScope(policy: TelegramPolicy, event: Pick<TelegramEventScope, "actorId" | "chatId" | "chatType">): boolean {
  if (event.actorId !== policy.adminId && event.actorId !== policy.memberId) return false;
  if (event.chatType === "private") return event.chatId === event.actorId;
  return (event.chatType === "group" || event.chatType === "supergroup") && event.chatId === policy.groupId;
}

async function verifyWebhookSecret(header: string | null, secret: string): Promise<boolean> {
  if (!matches(header, WEBHOOK_SECRET)) return false;
  const encoder = new TextEncoder();
  const [received, expected] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(header)),
    crypto.subtle.digest("SHA-256", encoder.encode(secret)),
  ]);
  return crypto.subtle.timingSafeEqual(received, expected);
}

function humanSender(message: Record<string, unknown>): string | null {
  if (message.is_automatic_forward === true || NON_HUMAN_MESSAGE_FIELDS.some((field) => field in message)) {
    return null;
  }
  const actor = message.from;
  return isRecord(actor) && actor.is_bot === false && isPositiveInteger(actor.id) ? String(actor.id) : null;
}

function authCommand(args: string[], reply: unknown, memberId: string): TelegramCommand["command"] {
  const [actionName = "list", target, ...extra] = args;
  const action = actionName.toLowerCase();
  switch (action) {
    case "list":
    case "ls":
      return target === undefined ? "auth-list" : "auth-usage";
    case "add":
    case "remove":
    case "del":
    case "rm": {
      const targetId = target ?? (isRecord(reply) ? humanSender(reply) : null);
      if (extra.length !== 0 || targetId !== memberId) return "auth-usage";
      return action === "add" ? "auth-add" : "auth-remove";
    }
    default:
      return "auth-usage";
  }
}

function messageCommand(
  message: Record<string, unknown>, policy: TelegramPolicy,
): TelegramCommand["command"] | TelegramViewKind | "temp-raw" | "temp-summary" | "temp-clear" | "aggregate-show" | "aggregate-revoke" |
  { code: string } | { args: string } | { shareArgs: string } | { selectedQuery: string } | { subscriptionQuery: string } | { shortArgs: string } |
  { inlineSort: TelegramInlineSortAction } | null {
  const { text, entities } = message;
  if (typeof text !== "string" || !Array.isArray(entities)) return null;
  const commands = entities.filter((entity) => isRecord(entity) && entity.type === "bot_command" && entity.offset === 0);
  if (commands.length !== 1) return null;
  const { length } = commands[0];
  if (!isPositiveInteger(length) || length > text.length) return null;
  // Telegram offsets and JavaScript string slicing both use UTF-16 code units.
  const entity = BOT_COMMAND.exec(text.slice(0, length));
  const remainder = text.slice(length);
  if (!entity) return null;
  const [, name, addressedTo] = entity;
  if (addressedTo && addressedTo.toLowerCase() !== policy.botUsername.toLowerCase()) return null;
  const commandName = name.toLowerCase();
  const separator = commandName === "path" || commandName === "o" || commandName === "s" || commandName === "i" ? PATH_RULE_WHITESPACE_PREFIX
    : commandName === "share" ? /^[ \t\r\n]/u : /^\s/u;
  if (remainder !== "" && !separator.test(remainder)) return null;
  if (commandName === "path") return { args: remainder };
  if (commandName === "o") return { selectedQuery: remainder };
  if (commandName === "short") return { shortArgs: remainder };
  if (commandName === "s") return { subscriptionQuery: remainder };
  if (commandName === "share") return remainder.length <= 4096 ? { shareArgs: remainder } : null;
  if (commandName === "i") {
    switch (remainder.length <= 4096 ? collapsePathRuleWhitespace(remainder) : null) {
      case "": return { inlineSort: { kind: "current" } };
      case "默认": return { inlineSort: { kind: "set", mode: "default" } };
      case "流量": return { inlineSort: { kind: "set", mode: "traffic" } };
      case "到期": return { inlineSort: { kind: "set", mode: "expiry" } };
      case "名称": return { inlineSort: { kind: "set", mode: "name" } };
      default: return { inlineSort: { kind: "usage" } };
    }
  }
  const args = remainder.trim().split(/\s+/u).filter(Boolean);
  switch (commandName) {
    case "start": {
      if (!args[0]?.startsWith("claim_")) return "start";
      const claim = args.length === 1 ? PRIVATE_CLAIM.exec(args[0]) : null;
      return claim ? { code: claim[1] } : null;
    }
    case "help":
      return "help";
    case "list":
      return "list";
    case "expire":
      return "expiry";
    case "recycle":
      return "recycle";
    case "temp":
      if (args.length === 0) return "temp-raw";
      if (args.length !== 1) return null;
      if (args[0].toLowerCase() === "summary") return "temp-summary";
      return args[0].toLowerCase() === "clear" ? "temp-clear" : null;
    case "export":
      if (args.length === 0) return "aggregate-show";
      return args.length === 1 && args[0].toLowerCase() === "revoke" ? "aggregate-revoke" : null;
    case "auth":
      return authCommand(args, message.reply_to_message, policy.memberId);
    default:
      return null;
  }
}

function messageScope(
  message: Record<string, unknown>, actorId: string, updateId: number, policy: TelegramPolicy,
): TelegramEventScope | null {
  const { chat, message_id: messageId, date: messageDate, message_thread_id: threadId } = message;
  if (
    !isRecord(chat) || typeof chat.id !== "number" || !Number.isSafeInteger(chat.id)
    || !isPositiveInteger(messageId) || !isPositiveInteger(messageDate)
    || (threadId !== undefined && !isPositiveInteger(threadId))
  ) return null;
  const chatId = String(chat.id);
  const chatType = chat.type;
  if (chatType !== "private" && chatType !== "group" && chatType !== "supergroup") return null;
  const scope: TelegramEventScope = { updateId, actorId, chatId, chatType, messageId, messageDate, threadId: threadId ?? null };
  return inTelegramScope(policy, scope) ? scope : null;
}

function ownBotMessage(value: unknown, policy: TelegramPolicy): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const bot = value.from;
  return isRecord(bot) && bot.is_bot === true && isPositiveInteger(bot.id) && String(bot.id) === policy.botId;
}

function renameReply(
  message: Record<string, unknown>, scope: TelegramEventScope, policy: TelegramPolicy,
): TelegramLifecycleUpdate | null {
  const { reply_to_message: repliedTo, text, entities } = message;
  if (typeof text !== "string" || text.length === 0 || !ownBotMessage(repliedTo, policy)) return null;
  if (Array.isArray(entities) && entities.some((entity) =>
    isRecord(entity) && entity.type === "bot_command" && entity.offset === 0) && !RENAME_CANCEL.test(text.trim())) {
    return null;
  }
  const prompt = messageScope(repliedTo, scope.actorId, scope.updateId, policy);
  if (!prompt || prompt.chatId !== scope.chatId || prompt.chatType !== scope.chatType ||
      prompt.threadId !== scope.threadId || prompt.messageId >= scope.messageId || prompt.messageDate > scope.messageDate) {
    return null;
  }
  return { ...scope, kind: "rename-reply", promptMessageId: prompt.messageId, text };
}

function normalizeDocument(message: Record<string, unknown>, scope: TelegramEventScope): NormalizedUpdate | null {
  if (scope.chatType !== "private" || scope.threadId !== null || !isRecord(message.document) ||
      "text" in message || "entities" in message || "animation" in message) return null;
  const { file_id: fileId, file_name: reportedName, file_size: fileSize } = message.document;
  if (!matches(fileId, DOCUMENT_FILE_ID) || (reportedName !== undefined && typeof reportedName !== "string") ||
      (fileSize !== undefined && fileSize !== 0 && !isPositiveInteger(fileSize))) return null;
  // Preserve a durable rejection without carrying the unbounded filename into admission.
  const fileName = reportedName !== undefined && reportedName.length > MAX_DOCUMENT_FILENAME ? "." : reportedName;
  return { document: { ...scope, fileId, fileName, fileSize } };
}

const DECIMAL_DIGIT = /^\p{Nd}$/u;

function subscriptionPosition(text: string): number | null {
  const value = collapsePathRuleWhitespace(text);
  if (!/^\p{Nd}+(?![\s\S])/u.test(value)) return null;
  if (value.length > 64) return Number.MAX_SAFE_INTEGER;
  let position = 0;
  for (const digit of value) {
    const point = digit.codePointAt(0)!;
    // Decimal digit blocks are ordered in runs of ten. Adjacent blocks can
    // form a longer run, so count backward to the first decimal digit.
    let start = point;
    while (start > 0 && DECIMAL_DIGIT.test(String.fromCodePoint(start - 1))) start--;
    position = position * 10 + (point - start) % 10;
    if (!Number.isSafeInteger(position)) return Number.MAX_SAFE_INTEGER;
  }
  return position;
}

function normalizeMessage(
  message: Record<string, unknown>, updateId: number, policy: TelegramPolicy,
): NormalizedUpdate | null {
  if ("edit_date" in message) return null;
  const actorId = humanSender(message);
  if (actorId === null) return null;
  const scope = messageScope(message, actorId, updateId, policy);
  if (!scope) return null;
  if ("document" in message) return normalizeDocument(message, scope);
  const command = messageCommand(message, policy);
  if (command && typeof command === "object") {
    if ("subscriptionQuery" in command) return { subscriptionRead: { ...scope, kind: "search", query: command.subscriptionQuery } };
    if (scope.chatType !== "private" || scope.threadId !== null) return null;
    if ("inlineSort" in command) return { inlineSort: { ...scope, ...command.inlineSort } };
    if ("shortArgs" in command) return { shortLink: { ...scope, args: command.shortArgs } };
    if ("shareArgs" in command) {
      const sender = isRecord(message.from) ? [message.from.first_name, message.from.last_name]
        .filter((part): part is string => typeof part === "string" && part.length <= 128).join(" ") : "";
      return { privateShareCreation: { ...scope, args: command.shareArgs, ...(sender ? { senderName: sender } : {}) } };
    }
    if ("code" in command) return { privateClaim: { ...scope, kind: "private-claim", code: command.code } };
    return "selectedQuery" in command ? { selected: { ...scope, kind: "selected", query: command.selectedQuery } }
      : { path: { ...scope, kind: "path", args: command.args } };
  }
  if (command === "temp-raw" || command === "temp-summary" || command === "temp-clear") {
    return scope.chatType === "private" && scope.threadId === null ? { temp: { ...scope, kind: command } } : null;
  }
  if (command === "aggregate-show" || command === "aggregate-revoke") {
    return scope.chatType === "private" && scope.threadId === null
      ? { aggregate: { ...scope, kind: command === "aggregate-show" ? "show" : "revoke" } } : null;
  }
  if (command === "list" || command === "expiry" || command === "recycle") return { view: { ...scope, kind: command } };
  if (command) return { command: { ...scope, command } };
  const lifecycle = renameReply(message, scope, policy);
  if (lifecycle) return { lifecycle };
  const { text, entities } = message;
  const hasCommandEntity = Array.isArray(entities) && entities.some((entity) => isRecord(entity) && entity.type === "bot_command");
  if (scope.chatType === "private" && scope.threadId === null && typeof text === "string" && !hasCommandEntity) {
    const position = subscriptionPosition(text);
    if (position !== null) return { subscriptionRead: { ...scope, kind: "number", position } };
    const short = /^(?:短链|short)(?: +([\s\S]*))?(?![\s\S])/iu.exec(text.replace(/^ +| +$/gu, ""));
    if (short || text === "🔗 短链") return { shortLink: { ...scope, args: short?.[1] ?? "" } };
  }
  return scope.chatType === "private" && scope.threadId === null && typeof text === "string"
    && text.trim() !== "" && !text.trimStart().startsWith("/")
    && !hasCommandEntity
    ? { temp: { ...scope, kind: "temp-text", text } } : null;
}

function normalizeCallback(
  callback: Record<string, unknown>, updateId: number, policy: TelegramPolicy,
): NormalizedUpdate | null {
  const { id: callbackId, from: actor, message, data: ticket } = callback;
  if (!matches(callbackId, CALLBACK_ID) || typeof ticket !== "string" ||
      !isRecord(actor) || actor.is_bot !== false || !isPositiveInteger(actor.id) ||
      !ownBotMessage(message, policy) || "inline_message_id" in callback || "game_short_name" in callback) return null;
  const scope = messageScope(message, String(actor.id), updateId, policy);
  if (!scope) return null;
  if (SUBSCRIPTION_READ_TICKET.test(ticket)) return { subscriptionRead: { ...scope, kind: "callback", callbackId, ticket } };
  if (SELECTED_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { selected: { ...scope, kind: "selected-revoke", callbackId, ticket } } : null;
  if (VIEW_TICKET.test(ticket)) return { view: { ...scope, kind: "callback", callbackId, ticket } };
  return LIFECYCLE_TICKET.test(ticket)
    ? { lifecycle: { ...scope, kind: "lifecycle-callback", callbackId, ticket } }
    : null;
}

function normalizeUpdate(
  update: Record<string, unknown>, updateId: number, policy: TelegramPolicy,
): NormalizedUpdate | null {
  // An Update contains at most one event.
  if (Object.keys(update).length !== 2) return null;
  if (isRecord(update.message)) return normalizeMessage(update.message, updateId, policy);
  return isRecord(update.callback_query) ? normalizeCallback(update.callback_query, updateId, policy) : null;
}

export async function decodeTelegramRequest(
  request: Request, policy: TelegramPolicy,
): Promise<DecodedTelegramRequest> {
  if (!await verifyWebhookSecret(request.headers.get("X-Telegram-Bot-Api-Secret-Token"), policy.webhookSecret)) {
    return { status: 401 };
  }
  const encoding = request.headers.get("Content-Encoding");
  if (!matches(request.headers.get("Content-Type"), JSON_CONTENT_TYPE)
    || (encoding !== null && encoding.toLowerCase() !== "identity")) return { status: 415 };
  const contentLength = request.headers.get("Content-Length");
  if (contentLength !== null) {
    if (!/^[0-9]+$/.test(contentLength)) return { status: 400 };
    if (Number(contentLength) > MAX_UPDATE_BYTES) return { status: 413 };
  }
  if (request.body === null) return { status: 400 };

  const bytes = new Uint8Array(MAX_UPDATE_BYTES);
  let size = 0;
  const reader = request.body.getReader();
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > MAX_UPDATE_BYTES - size) {
        void reader.cancel().catch(() => {});
        return { status: 413 };
      }
      bytes.set(value, size);
      size += value.byteLength;
    }
    const text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes.subarray(0, size));
    const update: unknown = JSON.parse(text);
    if (!isRecord(update) || !isPositiveInteger(update.update_id)) return { status: 400 };
    const event = normalizeUpdate(update, update.update_id, policy);
    return event ? { status: 200, ...event } : { status: 204 };
  } catch {
    return { status: 400 };
  } finally {
    reader.releaseLock();
  }
}

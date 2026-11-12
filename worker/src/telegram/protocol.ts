import { collapsePathRuleWhitespace, PATH_RULE_WHITESPACE_PREFIX } from "../path-rules.ts";
import type { TelegramDocumentJobInput } from "./document-jobs.ts";
import { classifyTelegramApiStatusInput, TELEGRAM_API_STATUS_PROMPT } from "./api-status-input.ts";
import { telegramMainMenuAction } from "./main-menu.ts";

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

export const TELEGRAM_PAGE_JUMP_CALLBACK = "list:jump:v1";
export const TELEGRAM_PAGE_JUMP_PROMPT = "🔢 请回复这条消息，输入要跳转的页码数字（如 2）。";
export const TELEGRAM_PAGE_JUMP_MARKER = "view-jump:v2";
export const TELEGRAM_PAGE_JUMP_RECEIPTS = `'view-jump:v1','${TELEGRAM_PAGE_JUMP_MARKER}'`;
export type TelegramPageJumpUpdate = TelegramEventScope & (
  | { kind: "open"; callbackId: string }
  | { kind: "reply"; promptMessageId: number; page: number | null; cancelled: boolean }
);

export type TelegramLifecycleUpdate = TelegramEventScope & (
  | { kind: "lifecycle-callback"; callbackId: string; ticket: string }
  | { kind: "rename-reply"; promptMessageId: number; text: string }
);

export type TelegramPrivateClaimUpdate = TelegramEventScope & { kind: "private-claim"; code: string };
export type TelegramLegacyInlineClaim = { actorId: string; callbackId: string; code: string };
export type TelegramAggregateUpdate = TelegramEventScope & { kind: "show" | "revoke" };
export type TelegramSelectedUpdate = TelegramEventScope & (
  | { kind: "selected"; query: string }
  | { kind: "selected-revoke"; callbackId: string; ticket: string }
);

export type TelegramTempUpdate = TelegramEventScope & (
  | { kind: "temp-text"; text: string }
  | { kind: "temp-raw" | "temp-summary" | "temp-clear" }
);
export type TelegramGeneralTempUpdate = TelegramTempUpdate;

export type TelegramPathUpdate = TelegramEventScope & { kind: "path"; args: string };
export type TelegramPrivateShareCreationUpdate = TelegramEventScope & { args: string; senderName?: string };
export type TelegramGroupShareUpdate = TelegramEventScope & (
  { kind: "publish"; callbackId: string } | { kind: "pick"; callbackId: string } | { kind: "handoff" }
);
export type TelegramGroupShareDestination = { chatId: string; chatType: "group" | "supergroup" };
export const GROUP_SHARE_PUBLISH_CALLBACK = "group-share:publish:v1";
export const GROUP_SHARE_PICK_CALLBACK = "group-share:pick:v1";
export type TelegramShortLinkUpdate = TelegramEventScope & { args: string };
export type TelegramSubscriptionReadUpdate = TelegramEventScope & (
  | { kind: "search"; query: string }
  | { kind: "number"; position: number }
  | { kind: "callback"; callbackId: string; ticket: string }
);
export type TelegramBulkTrashUpdate = TelegramEventScope & (
  | { kind: "preview"; query: string }
  | { kind: "confirm"; callbackId: string; ticket: string }
);
export type TelegramSubscriptionNodeUpdate = TelegramEventScope & { callbackId: string; ticket: string };
export type TelegramProviderRefreshUpdate = TelegramEventScope & { callbackId: string; ticket: string };
export type TelegramSubscriptionRawFileUpdate = TelegramEventScope & { callbackId: string; ticket: string };
export type TelegramProviderBatchUpdate = TelegramEventScope & (
  { kind: "preview" | "status" | "usage" } | { kind: "confirm"; callbackId: string; ticket: string }
);
export type TelegramApiStatusUpdate = TelegramEventScope & (
  { kind: "prompt" } | { kind: "reply"; promptMessageId: number; text: string }
);

export type TelegramInlineSortMode = "default" | "traffic" | "expiry" | "name";
type TelegramInlineSortAction = { kind: "current" | "usage" } | { kind: "set"; mode: TelegramInlineSortMode };
export type TelegramInlineSortUpdate = TelegramEventScope & TelegramInlineSortAction;
export type TelegramInlineConsentUpdate = TelegramEventScope & { kind: "on" | "temp-on" | "off" | "usage" };
export type TelegramInlineQuery = { updateId: number; actorId: string; chatType: "sender"; queryId: string; query: string };
export type TelegramGitHubSearchUpdate = TelegramEventScope & { args: string };

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

type InlineSortUpdate = (ShortLinkUpdate & { inlineSort?: never })
  | ({ inlineSort: TelegramInlineSortUpdate } & Partial<Record<keyof ShortLinkUpdate, never>>);
type SubscriptionNodeUpdate = (InlineSortUpdate & { subscriptionNodes?: never })
  | ({ subscriptionNodes: TelegramSubscriptionNodeUpdate } & Partial<Record<keyof InlineSortUpdate, never>>);
type BulkTrashUpdate = (SubscriptionNodeUpdate & { bulkTrash?: never })
  | ({ bulkTrash: TelegramBulkTrashUpdate } & Partial<Record<keyof SubscriptionNodeUpdate, never>>);
type InlineConsentUpdate = (BulkTrashUpdate & { inlineConsent?: never })
  | ({ inlineConsent: TelegramInlineConsentUpdate } & Partial<Record<keyof BulkTrashUpdate, never>>);
type InlineQueryUpdate = (InlineConsentUpdate & { inlineQuery?: never })
  | ({ inlineQuery: TelegramInlineQuery } & Partial<Record<keyof InlineConsentUpdate, never>>);
type GitHubSearchUpdate = (InlineQueryUpdate & { githubSearch?: never })
  | ({ githubSearch: TelegramGitHubSearchUpdate } & Partial<Record<keyof InlineQueryUpdate, never>>);
type ProviderRefreshUpdate = (GitHubSearchUpdate & { providerRefresh?: never })
  | ({ providerRefresh: TelegramProviderRefreshUpdate } & Partial<Record<keyof GitHubSearchUpdate, never>>);
type SubscriptionRawFileUpdate = (ProviderRefreshUpdate & { subscriptionRawFile?: never })
  | ({ subscriptionRawFile: TelegramSubscriptionRawFileUpdate } & Partial<Record<keyof ProviderRefreshUpdate, never>>);
type ProviderBatchUpdate = (SubscriptionRawFileUpdate & { providerBatch?: never })
  | ({ providerBatch: TelegramProviderBatchUpdate } & Partial<Record<keyof SubscriptionRawFileUpdate, never>>);
type ApiStatusUpdate = (ProviderBatchUpdate & { apiStatus?: never })
  | ({ apiStatus: TelegramApiStatusUpdate } & Partial<Record<keyof ProviderBatchUpdate, never>>);
type GroupShareUpdate = (ApiStatusUpdate & { groupShare?: never })
  | ({ groupShare: TelegramGroupShareUpdate } & Partial<Record<keyof ApiStatusUpdate, never>>);
type LegacyInlineClaimUpdate = (GroupShareUpdate & { legacyInlineClaim?: never })
  | ({ legacyInlineClaim: TelegramLegacyInlineClaim } & Partial<Record<keyof GroupShareUpdate, never>>);
type NormalizedUpdate = (LegacyInlineClaimUpdate & { pageJump?: never })
  | ({ pageJump: TelegramPageJumpUpdate } & Partial<Record<keyof LegacyInlineClaimUpdate, never>>);

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
export const BULK_TRASH_TICKET = /^sbd1_[A-Za-z0-9_-]{22}(?![\s\S])/;
export const SUBSCRIPTION_READ_RECEIPT_MARKER = "subread:v1";
export const GENERAL_SUBSCRIPTION_READ_MARKER = "general-subscription-read:v1";
export const SUBSCRIPTION_NODE_TICKET = /^sbn1_[A-Za-z0-9_-]{22}(?![\s\S])/;
export const PROVIDER_REFRESH_TICKET = /^sbpr1_[A-Za-z0-9_-]{21}[AQgw](?![\s\S])/;
export const SUBSCRIPTION_RAW_FILE_TICKET = /^sbnf1_[A-Za-z0-9_-]{21}[AQgw](?![\s\S])/;
export const PROVIDER_BATCH_TICKET = /^sbpb1_[A-Za-z0-9_-]{21}[AQgw](?![\s\S])/;
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

export type TelegramBotCredentials = Pick<TelegramPolicy, "botId" | "botUsername" | "webhookSecret" | "botToken">;

export function readTelegramBotCredentials(value: Record<string, unknown>): TelegramBotCredentials | null {
  const { botId, botUsername, webhookSecret, botToken } = value;
  return canonicalId(botId) && matches(botUsername, USERNAME) && matches(webhookSecret, WEBHOOK_SECRET)
    && matches(botToken, BOT_TOKEN) && botToken.startsWith(`${botId}:`)
    ? { botId, botUsername, webhookSecret, botToken } : null;
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
  const credentials = readTelegramBotCredentials(value);
  const { adminId, memberId, groupId } = value;
  if (!credentials || !canonicalId(adminId) || !canonicalId(memberId) || !canonicalId(groupId, true)
    || new Set([credentials.botId, adminId, memberId]).size !== 3) return null;
  return { ...credentials, adminId, memberId, groupId };
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

function readLeadingTelegramCommand(message: Record<string, unknown>, botUsername: string, requireAddress = false): {
  name: string; remainder: string;
} | null {
  const { text, entities } = message;
  if (typeof text !== "string" || !Array.isArray(entities)) return null;
  const commands = entities.filter((entity) => isRecord(entity) && entity.type === "bot_command" && entity.offset === 0);
  if (commands.length !== 1) return null;
  const { length } = commands[0];
  if (!isPositiveInteger(length) || length > text.length) return null;
  // Telegram offsets and JavaScript string slicing both use UTF-16 code units.
  const entity = BOT_COMMAND.exec(text.slice(0, length));
  if (!entity) return null;
  const [, name, addressedTo] = entity;
  if ((requireAddress && !addressedTo) || (addressedTo && addressedTo.toLowerCase() !== botUsername.toLowerCase())) return null;
  return { name: name.toLowerCase(), remainder: text.slice(length) };
}

export function readPrivateTelegramCommand(update: Record<string, unknown>, botUsername: string): {
  actorId: string; messageId: number; messageDate: number; name: string; remainder: string;
} | null {
  const { message } = update;
  if (Object.keys(update).length !== 2 || !isRecord(message) || "edit_date" in message || "document" in message
    || "message_thread_id" in message || "reply_to_message" in message) return null;
  const actorId = humanSender(message);
  const { chat, message_id: messageId, date: messageDate } = message;
  if (actorId === null || !isRecord(chat) || chat.type !== "private" || !isPositiveInteger(chat.id)
    || String(chat.id) !== actorId || !isPositiveInteger(messageId) || !isPositiveInteger(messageDate)) return null;
  const command = readLeadingTelegramCommand(message, botUsername);
  return command ? { actorId, messageId, messageDate, ...command } : null;
}

export function readGeneralPrivateShareCreation(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramPrivateShareCreationUpdate | null {
  const command = readPrivateTelegramCommand(update, botUsername);
  if (!command || command.actorId === botId || command.name !== "share" || command.remainder.length > 4096) return null;
  const message = update.message;
  const senderName = isRecord(message) && isRecord(message.from) ? [message.from.first_name, message.from.last_name]
    .filter((part): part is string => typeof part === "string" && part.length <= 128).join(" ") : "";
  const { actorId, messageId, messageDate, remainder } = command;
  return { updateId, actorId, chatId: actorId, chatType: "private", threadId: null,
    messageId, messageDate, args: remainder, ...(senderName ? { senderName } : {}) };
}

export function readGeneralGroupShare(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
  destination: TelegramGroupShareDestination,
): TelegramGroupShareUpdate | null {
  if (Object.keys(update).length !== 2) return null;
  const callback = update.callback_query;
  if (isRecord(callback)) {
    const { id: callbackId, from: actor, message, data } = callback;
    if ("inline_message_id" in callback || "game_short_name" in callback || !matches(callbackId, CALLBACK_ID)
        || !isRecord(actor) || actor.is_bot !== false || !isPositiveInteger(actor.id)
        || String(actor.id) === botId || !ownBotMessage(message, { botId })) return null;
    const scope = telegramMessageScope(message, String(actor.id), updateId);
    if (!scope || scope.threadId !== null || message.is_topic_message === true) return null;
    if (data === GROUP_SHARE_PUBLISH_CALLBACK && scope.chatType === "private" && scope.chatId === scope.actorId) {
      return { ...scope, kind: "publish", callbackId };
    }
    if (data === GROUP_SHARE_PICK_CALLBACK && scope.chatId === destination.chatId && scope.chatType === destination.chatType) {
      return { ...scope, kind: "pick", callbackId };
    }
    return null;
  }
  const command = readPrivateTelegramCommand(update, botUsername);
  if (!command || command.actorId === botId || command.name !== "start"
    || !/^[ \t]+group[ \t]*(?![\s\S])/u.test(command.remainder)) return null;
  const { actorId, messageId, messageDate } = command;
  return { updateId, actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate, kind: "handoff" };
}

export function readGeneralPrivateShareClaim(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramPrivateClaimUpdate | null {
  const command = readPrivateTelegramCommand(update, botUsername);
  if (!command || command.actorId === botId || command.name !== "start") return null;
  const match = PRIVATE_CLAIM.exec(command.remainder.trim());
  if (!match) return null;
  const { actorId, messageId, messageDate } = command;
  return { kind: "private-claim", updateId, actorId, chatId: actorId, chatType: "private", threadId: null,
    messageId, messageDate, code: match[1] };
}

export function readGeneralGroupCommand(update: Record<string, unknown>, botUsername: string):
  (Omit<TelegramEventScope, "updateId"> & { name: string; remainder: string }) | null {
  const { message } = update;
  if (Object.keys(update).length !== 2 || !isRecord(message) || "edit_date" in message || "document" in message) return null;
  const actorId = humanSender(message);
  const { chat, message_id: messageId, date: messageDate, message_thread_id: thread } = message;
  if (!actorId || !isRecord(chat) || (chat.type !== "group" && chat.type !== "supergroup")
    || typeof chat.id !== "number" || !Number.isSafeInteger(chat.id) || chat.id >= 0 || chat.id <= -(2 ** 52)
    || !isPositiveInteger(messageId) || !isPositiveInteger(messageDate)) return null;
  const topic = message.is_topic_message === true;
  if (thread === undefined ? topic : (!topic || chat.type !== "supergroup" || !isPositiveInteger(thread))) return null;
  const command = readLeadingTelegramCommand(message, botUsername);
  return command && ["start", "help", "list", "expire", "recycle", "s"].includes(command.name)
    && (command.name === "s" || command.remainder.trim() === "") ? { ...command,
    actorId, chatId: String(chat.id), chatType: chat.type, messageId, messageDate,
    threadId: typeof thread === "number" ? thread : null,
  } : null;
}

export function readGeneralGroupListCommand(update: Record<string, unknown>, botUsername: string):
  Omit<TelegramEventScope, "updateId"> | null {
  const command = readGeneralGroupCommand(update, botUsername);
  if (!command || command.name !== "list") return null;
  const { name: _name, remainder: _remainder, ...scope } = command;
  return scope;
}

/** Existing reply-keyboard labels share the exact private command parsers. */
export function readGeneralPrivateMenuCommand(update: Record<string, unknown>, botUsername: string) {
  const command = readPrivateTelegramCommand(update, botUsername);
  if (command) return command;
  const { message } = update;
  if (!isRecord(message) || typeof message.text !== "string" || (Array.isArray(message.entities)
    && message.entities.some((entity) => isRecord(entity) && entity.type === "bot_command"))) return null;
  const action = telegramMainMenuAction(message.text);
  const name = action === "expiry" ? "expire" : action === "aggregate" ? "export"
    : action === "batchRefresh" ? "updateall" : action;
  if (!name) return null;
  const text = `/${name}`;
  return readPrivateTelegramCommand({ ...update, message: { ...message, text,
    entities: [{ type: "bot_command", offset: 0, length: text.length }] } }, botUsername);
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
  { inlineSort: TelegramInlineSortAction } | { bulkTrashQuery: string } |
  { inlineConsent: TelegramInlineConsentUpdate["kind"] } | { githubArgs: string } |
  { providerBatch: "preview" | "status" | "usage" } | { apiStatusArgs: string } | "group-share-handoff" | null {
  const command = readLeadingTelegramCommand(message, policy.botUsername);
  if (!command) return null;
  const { name: commandName, remainder } = command;
  const separator = commandName === "path" || commandName === "o" || commandName === "s" || commandName === "i" || commandName === "d"
    ? PATH_RULE_WHITESPACE_PREFIX
    : commandName === "share" ? /^[ \t\r\n]/u : /^\s/u;
  if (remainder !== "" && !separator.test(remainder)) return null;
  if (commandName === "path") return { args: remainder };
  if (commandName === "o") return { selectedQuery: remainder };
  if (commandName === "short") return { shortArgs: remainder };
  if (commandName === "g") return { githubArgs: remainder };
  if (commandName === "ai") return { apiStatusArgs: remainder };
  if (commandName === "s") return { subscriptionQuery: remainder };
  if (commandName === "d") return { bulkTrashQuery: remainder };
  if (commandName === "share") return remainder.length <= 4096 ? { shareArgs: remainder } : null;
  if (commandName === "inline") {
    const mode = remainder.trim().toLowerCase();
    if (mode === "temp on") return { inlineConsent: "temp-on" };
    return { inlineConsent: mode === "on" || mode === "off" ? mode : "usage" };
  }
  if (commandName === "updateall") {
    const mode = remainder.trim().toLowerCase();
    return { providerBatch: mode === "" ? "preview" : mode === "status" ? "status" : "usage" };
  }
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
      if (args.length === 1 && args[0] === "group") return "group-share-handoff";
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

function telegramMessageScope(
  message: Record<string, unknown>, actorId: string, updateId: number,
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
  return { updateId, actorId, chatId, chatType, messageId, messageDate, threadId: threadId ?? null };
}

function messageScope(
  message: Record<string, unknown>, actorId: string, updateId: number, policy: TelegramPolicy,
): TelegramEventScope | null {
  const scope = telegramMessageScope(message, actorId, updateId);
  return scope && inTelegramScope(policy, scope) ? scope : null;
}

function ownBotMessage(value: unknown, policy: Pick<TelegramPolicy, "botId">): value is Record<string, unknown> {
  if (!isRecord(value)) return false;
  const bot = value.from;
  return isRecord(bot) && bot.is_bot === true && isPositiveInteger(bot.id) && String(bot.id) === policy.botId;
}

function renameReply(
  message: Record<string, unknown>, scope: TelegramEventScope, policy: Pick<TelegramPolicy, "botId">,
): TelegramLifecycleUpdate | null {
  const { reply_to_message: repliedTo, text, entities } = message;
  if (typeof text !== "string" || text.length === 0 || !ownBotMessage(repliedTo, policy)) return null;
  if (Array.isArray(entities) && entities.some((entity) =>
    isRecord(entity) && entity.type === "bot_command" && entity.offset === 0) && !RENAME_CANCEL.test(text.trim())) {
    return null;
  }
  const prompt = telegramMessageScope(repliedTo, scope.actorId, scope.updateId);
  if (!prompt || prompt.chatId !== scope.chatId || prompt.chatType !== scope.chatType ||
      prompt.threadId !== scope.threadId || prompt.messageId >= scope.messageId || prompt.messageDate > scope.messageDate) {
    return null;
  }
  return { ...scope, kind: "rename-reply", promptMessageId: prompt.messageId, text };
}

function readGeneralPrivateTicket(
  callback: Record<string, unknown>, updateId: number, botId: string, pattern: RegExp,
): (TelegramEventScope & { callbackId: string; ticket: string }) | null {
  const { id: callbackId, from: actor, message: origin, data: ticket } = callback;
  if ("inline_message_id" in callback || "game_short_name" in callback || !matches(callbackId, CALLBACK_ID)
    || !matches(ticket, pattern) || !isRecord(actor) || actor.is_bot !== false || !isPositiveInteger(actor.id)
    || !ownBotMessage(origin, { botId })) return null;
  const scope = telegramMessageScope(origin, String(actor.id), updateId);
  return scope && scope.chatType === "private" && scope.chatId === scope.actorId && scope.threadId === null
    ? { ...scope, callbackId, ticket } : null;
}

export function readGeneralPrivateProviderBatch(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramProviderBatchUpdate | null {
  if (Object.keys(update).length !== 2) return null;
  if (isRecord(update.callback_query)) {
    const ticket = readGeneralPrivateTicket(update.callback_query, updateId, botId, PROVIDER_BATCH_TICKET);
    return ticket && ticket.actorId !== botId ? { ...ticket, kind: "confirm" } : null;
  }
  const command = readGeneralPrivateMenuCommand(update, botUsername);
  if (!command || command.actorId === botId || command.name !== "updateall"
    || (command.remainder && !/^[ \t]/u.test(command.remainder))) return null;
  const { actorId, messageId, messageDate, remainder } = command;
  const mode = remainder.trim().toLowerCase();
  return { updateId, actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate,
    kind: mode === "" ? "preview" : mode === "status" ? "status" : "usage" };
}

export function readGeneralPrivateSubscriptionRead(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramSubscriptionReadUpdate | null {
  if (Object.keys(update).length !== 2) return null;
  if (isRecord(update.callback_query)) {
    const ticket = readGeneralPrivateTicket(update.callback_query, updateId, botId, SUBSCRIPTION_READ_TICKET);
    return ticket ? { ...ticket, kind: "callback" } : null;
  }
  const group = readGeneralGroupCommand(update, botUsername);
  if (group?.name === "s" && group.actorId !== botId) {
    const { name: _name, remainder: query, ...scope } = group;
    return { ...scope, updateId, kind: "search", query };
  }
  const command = readPrivateTelegramCommand(update, botUsername);
  if (!command) {
    const message = update.message;
    if (!isRecord(message) || "edit_date" in message || "reply_to_message" in message || "document" in message) return null;
    const actorId = humanSender(message);
    const scope = actorId && actorId !== botId ? telegramMessageScope(message, actorId, updateId) : null;
    const position = typeof message.text === "string" && /^[1-9][0-9]{0,6}$/u.test(message.text.trim()) ? Number(message.text.trim()) : null;
    return scope && scope.chatType === "private" && scope.chatId === actorId && scope.threadId === null && position !== null
      ? { ...scope, kind: "number", position } : null;
  }
  if (command.actorId === botId || command.name !== "s") return null;
  return { kind: "search", actorId: command.actorId, chatId: command.actorId, chatType: "private", threadId: null,
    updateId, messageId: command.messageId, messageDate: command.messageDate, query: command.remainder };
}

export type GeneralBrowsingUpdate =
  | { family: "view"; event: TelegramViewUpdate }
  | { family: "nodes"; event: TelegramSubscriptionNodeUpdate }
  | { family: "file"; event: TelegramSubscriptionRawFileUpdate };

/** Parse only owned Bot messages; tickets still require transactional authority proof. */
export function readGeneralSubscriptionBrowsing(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): GeneralBrowsingUpdate | null {
  if (Object.keys(update).length !== 2) return null;
  const callback = update.callback_query;
  if (isRecord(callback)) {
    const { id: callbackId, from: actor, message: origin, data: ticket } = callback;
    if ("inline_message_id" in callback || "game_short_name" in callback || !matches(callbackId, CALLBACK_ID)
      || !isRecord(actor) || actor.is_bot !== false || !isPositiveInteger(actor.id) || String(actor.id) === botId
      || !ownBotMessage(origin, { botId }) || typeof ticket !== "string") return null;
    const scope = telegramMessageScope(origin, String(actor.id), updateId);
    if (!scope || (scope.chatType === "private" ? scope.chatId !== scope.actorId || scope.threadId !== null
      : scope.chatType === "group" && scope.threadId !== null)) return null;
    if (VIEW_TICKET.test(ticket)) return { family: "view", event: { ...scope, kind: "callback", callbackId, ticket } };
    if (scope.chatType !== "private") return null;
    if (SUBSCRIPTION_NODE_TICKET.test(ticket)) return { family: "nodes", event: { ...scope, callbackId, ticket } };
    if (SUBSCRIPTION_RAW_FILE_TICKET.test(ticket)) return { family: "file", event: { ...scope, callbackId, ticket } };
    return null;
  }
  const command = readGeneralGroupCommand(update, botUsername) ?? readGeneralPrivateMenuCommand(update, botUsername);
  if (!command || command.actorId === botId || command.remainder.trim() !== "") return null;
  const kind = command.name === "list" ? "list" : command.name === "expire" ? "expiry" : command.name === "recycle" ? "recycle" : null;
  if (!kind) return null;
  const { actorId, messageId, messageDate } = command;
  const scope: TelegramEventScope = "chatId" in command ? { ...command, updateId } : {
    updateId, actorId, messageId, messageDate, chatId: actorId, chatType: "private", threadId: null,
  };
  return { family: "view", event: { ...scope, kind } };
}

export function readGeneralPrivateTempUpdate(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramGeneralTempUpdate | null {
  const { message } = update;
  if (Object.keys(update).length !== 2 || !isRecord(message) || "edit_date" in message || "document" in message
    || "message_thread_id" in message || "reply_to_message" in message || message.is_topic_message === true) return null;
  const actorId = humanSender(message);
  const scope = actorId && actorId !== botId ? telegramMessageScope(message, actorId, updateId) : null;
  if (!scope || scope.chatType !== "private" || scope.chatId !== scope.actorId || scope.threadId !== null) return null;

  const command = readLeadingTelegramCommand(message, botUsername);
  if (command) {
    if (command.name !== "temp") return null;
    const argument = command.remainder.trim().toLowerCase();
    if (argument === "clear") return { ...scope, kind: "temp-clear" };
    if (argument === "raw") return { ...scope, kind: "temp-raw" };
    return argument === "" || argument === "summary" ? { ...scope, kind: "temp-summary" } : null;
  }

  const { text, entities } = message;
  const hasCommand = Array.isArray(entities) && entities.some((entity) => isRecord(entity) && entity.type === "bot_command");
  return !hasCommand && typeof text === "string" && telegramMainMenuAction(text) === null && text.trim() !== "" && !text.trimStart().startsWith("/")
    && classifyTelegramApiStatusInput({ kind: "ordinary", text }).kind === "pass-through"
    ? { ...scope, kind: "temp-text", text } : null;
}

export function readGeneralPrivateProviderRefresh(
  update: Record<string, unknown>, updateId: number, botId: string,
): TelegramProviderRefreshUpdate | null {
  return Object.keys(update).length === 2 && isRecord(update.callback_query)
    ? readGeneralPrivateTicket(update.callback_query, updateId, botId, PROVIDER_REFRESH_TICKET) : null;
}

export function readGeneralPrivateSelectedRevoke(
  update: Record<string, unknown>, updateId: number, botId: string,
): Extract<TelegramSelectedUpdate, { kind: "selected-revoke" }> | null {
  const ticket = Object.keys(update).length === 2 && isRecord(update.callback_query)
    ? readGeneralPrivateTicket(update.callback_query, updateId, botId, SELECTED_TICKET) : null;
  return ticket ? { ...ticket, kind: "selected-revoke" } : null;
}

export function readGeneralPrivateLifecycleUpdate(
  update: Record<string, unknown>, updateId: number, botId: string,
): TelegramLifecycleUpdate | null {
  if (Object.keys(update).length !== 2) return null;
  const { callback_query: callback, message } = update;
  if (isRecord(callback)) {
    const ticket = readGeneralPrivateTicket(callback, updateId, botId, LIFECYCLE_TICKET);
    return ticket ? { ...ticket, kind: "lifecycle-callback" } : null;
  }
  if (!isRecord(message) || "edit_date" in message || "document" in message) return null;
  const actorId = humanSender(message);
  const scope = actorId ? telegramMessageScope(message, actorId, updateId) : null;
  return scope && scope.chatType === "private" && scope.chatId === scope.actorId && scope.threadId === null
    ? renameReply(message, scope, { botId }) : null;
}

function documentInput(message: Record<string, unknown>, scope: TelegramEventScope): TelegramDocumentJobInput | null {
  if (scope.chatType !== "private" || scope.threadId !== null || !isRecord(message.document) ||
      "text" in message || "entities" in message || "animation" in message) return null;
  const { file_id: fileId, file_name: reportedName, file_size: fileSize } = message.document;
  if (!matches(fileId, DOCUMENT_FILE_ID) || (reportedName !== undefined && typeof reportedName !== "string") ||
      (fileSize !== undefined && fileSize !== 0 && !isPositiveInteger(fileSize))) return null;
  const fileName = reportedName !== undefined && reportedName.length > MAX_DOCUMENT_FILENAME ? "." : reportedName;
  return { ...scope, fileId, fileName, fileSize };
}

export function readGeneralPrivateDocumentUpdate(
  update: Record<string, unknown>, updateId: number, botId: string,
): TelegramDocumentJobInput | null {
  const { message } = update;
  if (Object.keys(update).length !== 2 || !isRecord(message) || "edit_date" in message || !("document" in message)
    || "reply_to_message" in message || "message_thread_id" in message || message.is_topic_message === true) return null;
  const actorId = humanSender(message);
  const scope = actorId && actorId !== botId ? telegramMessageScope(message, actorId, updateId) : null;
  return scope && scope.chatId === scope.actorId ? documentInput(message, scope) : null;
}

export function readGeneralPrivateGitHubSearch(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramGitHubSearchUpdate | null {
  const command = readPrivateTelegramCommand(update, botUsername);
  if (!command || command.actorId === botId || command.name !== "g"
    || (command.remainder !== "" && !/^\s/u.test(command.remainder))) return null;
  const { actorId, messageId, messageDate } = command;
  return { updateId, actorId, chatId: actorId, chatType: "private", threadId: null,
    messageId, messageDate, args: command.remainder };
}

export function readGeneralPrivateApiStatus(
  update: Record<string, unknown>, updateId: number, botId: string, botUsername: string,
): TelegramApiStatusUpdate | null {
  const { message } = update;
  if (Object.keys(update).length !== 2 || !isRecord(message) || "edit_date" in message || "document" in message
    || "message_thread_id" in message || message.is_topic_message === true) return null;
  const actorId = humanSender(message);
  const scope = actorId && actorId !== botId ? telegramMessageScope(message, actorId, updateId) : null;
  if (!scope || scope.chatType !== "private" || scope.chatId !== scope.actorId || scope.threadId !== null) return null;
  const origin = message.reply_to_message;
  if (ownBotMessage(origin, { botId }) && origin.text === TELEGRAM_API_STATUS_PROMPT) {
    const prompt = telegramMessageScope(origin, actorId!, updateId);
    return typeof message.text === "string" && prompt?.chatType === "private" && prompt.chatId === scope.chatId
      && prompt.threadId === null && prompt.messageId < scope.messageId && prompt.messageDate <= scope.messageDate
      ? { ...scope, kind: "reply", promptMessageId: prompt.messageId, text: message.text } : null;
  }
  const command = readPrivateTelegramCommand(update, botUsername);
  return command?.name === "ai" && classifyTelegramApiStatusInput({ kind: "ai-command", args: command.remainder }).kind === "open-prompt"
    ? { ...scope, kind: "prompt" } : null;
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
  const { reply_to_message: origin, text, entities } = message;
  if (ownBotMessage(origin, policy) && origin.text === TELEGRAM_API_STATUS_PROMPT) {
    const prompt = messageScope(origin, actorId, updateId, policy);
    if (typeof text !== "string" || "document" in message || scope.chatType !== "private" || scope.threadId !== null
      || prompt?.chatType !== "private" || prompt.chatId !== scope.chatId || prompt.threadId !== null
      || prompt.messageId >= scope.messageId || prompt.messageDate > scope.messageDate) return null;
    return { apiStatus: { ...scope, kind: "reply", promptMessageId: prompt.messageId, text } };
  }
  if ("document" in message) {
    const document = documentInput(message, scope);
    return document ? { document } : null;
  }
  const command = messageCommand(message, policy);
  if (command && typeof command === "object") {
    if ("subscriptionQuery" in command) return { subscriptionRead: { ...scope, kind: "search", query: command.subscriptionQuery } };
    if (scope.chatType !== "private" || scope.threadId !== null) return null;
    if ("apiStatusArgs" in command) return classifyTelegramApiStatusInput({ kind: "ai-command", args: command.apiStatusArgs }).kind === "open-prompt"
      ? { apiStatus: { ...scope, kind: "prompt" } } : null;
    if ("bulkTrashQuery" in command) return { bulkTrash: { ...scope, kind: "preview", query: command.bulkTrashQuery } };
    if ("inlineSort" in command) return { inlineSort: { ...scope, ...command.inlineSort } };
    if ("inlineConsent" in command) return { inlineConsent: { ...scope, kind: command.inlineConsent } };
    if ("githubArgs" in command) return { githubSearch: { ...scope, args: command.githubArgs } };
    if ("providerBatch" in command) return { providerBatch: { ...scope, kind: command.providerBatch } };
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
  if (command === "group-share-handoff") return scope.chatType === "private" && scope.threadId === null
    ? { groupShare: { ...scope, kind: "handoff" } } : null;
  if (command === "aggregate-show" || command === "aggregate-revoke") {
    return scope.chatType === "private" && scope.threadId === null
      ? { aggregate: { ...scope, kind: command === "aggregate-show" ? "show" : "revoke" } } : null;
  }
  if (command === "list" || command === "expiry" || command === "recycle") return { view: { ...scope, kind: command } };
  if (command) return { command: { ...scope, command } };
  if (ownBotMessage(origin, policy) && origin.text === TELEGRAM_PAGE_JUMP_PROMPT) {
    const prompt = messageScope(origin, actorId, updateId, policy);
    if (typeof text !== "string" || prompt?.chatId !== scope.chatId || prompt.chatType !== scope.chatType
        || prompt.threadId !== scope.threadId || prompt.messageId >= scope.messageId || prompt.messageDate > scope.messageDate) return null;
    const position = subscriptionPosition(text);
    return { pageJump: { ...scope, kind: "reply", promptMessageId: prompt.messageId,
      page: position === null ? null : Math.max(1, position), cancelled: RENAME_CANCEL.test(text.trim()) } };
  }
  if (typeof text === "string" && classifyTelegramApiStatusInput({ kind: "ordinary", text }).kind !== "pass-through") return null;
  const lifecycle = renameReply(message, scope, policy);
  if (lifecycle) return { lifecycle };
  const hasCommandEntity = Array.isArray(entities) && entities.some((entity) => isRecord(entity) && entity.type === "bot_command");
  const privateChat = scope.chatType === "private" && scope.threadId === null;
  const menu = typeof text === "string" && !hasCommandEntity ? telegramMainMenuAction(text) : null;
  if (menu === "list" || menu === "expiry" || menu === "recycle") return { view: { ...scope, kind: menu } };
  if (menu === "help") return { command: { ...scope, command: "help" } };
  if (menu === "aggregate") return privateChat ? { aggregate: { ...scope, kind: "show" } } : null;
  if (menu === "batchRefresh") return privateChat ? { providerBatch: { ...scope, kind: "preview" } } : null;
  if (menu === "path") return privateChat ? { path: { ...scope, kind: "path", args: "" } } : null;
  if (privateChat && typeof text === "string" && !hasCommandEntity) {
    const position = subscriptionPosition(text);
    if (position !== null) return { subscriptionRead: { ...scope, kind: "number", position } };
    const short = /^(?:短链|short)(?: +([\s\S]*))?(?![\s\S])/iu.exec(text.replace(/^ +| +$/gu, ""));
    if (short || text === "🔗 短链") return { shortLink: { ...scope, args: short?.[1] ?? "" } };
  }
  return privateChat && typeof text === "string"
    && text.trim() !== "" && !text.trimStart().startsWith("/")
    && !hasCommandEntity
    ? { temp: { ...scope, kind: "temp-text", text } } : null;
}

function normalizeCallback(
  callback: Record<string, unknown>, updateId: number, policy: TelegramPolicy,
): NormalizedUpdate | null {
  const { id: callbackId, from: actor, message, data: ticket } = callback;
  if (!matches(callbackId, CALLBACK_ID) || typeof ticket !== "string" ||
      !isRecord(actor) || actor.is_bot !== false || !isPositiveInteger(actor.id) || "game_short_name" in callback) return null;
  if ("inline_message_id" in callback) {
    if ("message" in callback || !matches(callback.inline_message_id, /^[!-~]{1,256}(?![\s\S])/u)) return null;
    const legacy = /^share:c:([A-Za-z0-9_-]{11})(?![\s\S])/u.exec(ticket);
    const actorId = String(actor.id);
    return legacy && (actorId === policy.adminId || actorId === policy.memberId)
      ? { legacyInlineClaim: { actorId, callbackId, code: legacy[1] } } : null;
  }
  if (!ownBotMessage(message, policy)) return null;
  const scope = messageScope(message, String(actor.id), updateId, policy);
  if (!scope) return null;
  if (ticket === TELEGRAM_PAGE_JUMP_CALLBACK) return { pageJump: { ...scope, kind: "open", callbackId } };
  if (ticket === GROUP_SHARE_PUBLISH_CALLBACK) return scope.chatType === "private" && scope.threadId === null
    ? { groupShare: { ...scope, kind: "publish", callbackId } } : null;
  if (ticket === GROUP_SHARE_PICK_CALLBACK) return scope.chatType !== "private" && scope.threadId === null
    ? { groupShare: { ...scope, kind: "pick", callbackId } } : null;
  if (SUBSCRIPTION_READ_TICKET.test(ticket)) return { subscriptionRead: { ...scope, kind: "callback", callbackId, ticket } };
  if (BULK_TRASH_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { bulkTrash: { ...scope, kind: "confirm", callbackId, ticket } } : null;
  if (SUBSCRIPTION_NODE_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { subscriptionNodes: { ...scope, callbackId, ticket } } : null;
  if (PROVIDER_REFRESH_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { providerRefresh: { ...scope, callbackId, ticket } } : null;
  if (SUBSCRIPTION_RAW_FILE_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { subscriptionRawFile: { ...scope, callbackId, ticket } } : null;
  if (PROVIDER_BATCH_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { providerBatch: { ...scope, kind: "confirm", callbackId, ticket } } : null;
  if (SELECTED_TICKET.test(ticket)) return scope.chatType === "private" && scope.threadId === null
    ? { selected: { ...scope, kind: "selected-revoke", callbackId, ticket } } : null;
  if (VIEW_TICKET.test(ticket)) return { view: { ...scope, kind: "callback", callbackId, ticket } };
  return LIFECYCLE_TICKET.test(ticket)
    ? { lifecycle: { ...scope, kind: "lifecycle-callback", callbackId, ticket } }
    : null;
}

function readSenderInlineQuery(value: Record<string, unknown>, updateId: number): TelegramInlineQuery | null {
  const { id, from, chat_type, offset, query } = value;
  if (chat_type !== "sender" || offset !== "" || !matches(id, CALLBACK_ID)
    || !isRecord(from) || from.is_bot !== false || !isPositiveInteger(from.id)
    || typeof query !== "string" || query.length > 512 || /[\u0000\ud800-\udfff]/u.test(query)
    || Array.from(query).length > 256 || new TextEncoder().encode(query).byteLength > 1024) return null;
  return { updateId, actorId: String(from.id), chatType: "sender", queryId: id, query };
}

function normalizeInlineQuery(value: Record<string, unknown>, updateId: number, policy: TelegramPolicy): NormalizedUpdate | null {
  const query = readSenderInlineQuery(value, updateId);
  return query && (query.actorId === policy.adminId || query.actorId === policy.memberId) ? { inlineQuery: query } : null;
}

export function readGeneralInlineQuery(update: Record<string, unknown>, updateId: number, botId: string): TelegramInlineQuery | null {
  const query = Object.keys(update).length === 2 && isRecord(update.inline_query) ? readSenderInlineQuery(update.inline_query, updateId) : null;
  return query && query.actorId !== botId ? query : null;
}

function normalizeUpdate(
  update: Record<string, unknown>, updateId: number, policy: TelegramPolicy, inlineSearchEnabled: boolean,
): NormalizedUpdate | null {
  // An Update contains at most one event.
  if (Object.keys(update).length !== 2) return null;
  if (isRecord(update.message)) return normalizeMessage(update.message, updateId, policy);
  if (isRecord(update.callback_query)) return normalizeCallback(update.callback_query, updateId, policy);
  return inlineSearchEnabled && isRecord(update.inline_query) ? normalizeInlineQuery(update.inline_query, updateId, policy) : null;
}

export async function readTelegramUpdate(request: Request, webhookSecret: string): Promise<
  { status: 200; update: Record<string, unknown>; updateId: number } | { status: 400 | 401 | 413 | 415 }
> {
  if (!await verifyWebhookSecret(request.headers.get("X-Telegram-Bot-Api-Secret-Token"), webhookSecret)) {
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
    return { status: 200, update, updateId: update.update_id };
  } catch {
    return { status: 400 };
  } finally {
    reader.releaseLock();
  }
}

export async function decodeTelegramRequest(
  request: Request, policy: TelegramPolicy, inlineSearchEnabled = false,
): Promise<DecodedTelegramRequest> {
  return decodeAuthenticatedTelegramUpdate(await readTelegramUpdate(request, policy.webhookSecret), policy, inlineSearchEnabled);
}

export function decodeAuthenticatedTelegramUpdate(
  decoded: Awaited<ReturnType<typeof readTelegramUpdate>>, policy: TelegramPolicy, inlineSearchEnabled = false,
): DecodedTelegramRequest {
  if (decoded.status !== 200) return decoded;
  try {
    const event = normalizeUpdate(decoded.update, decoded.updateId, policy, inlineSearchEnabled);
    return event ? { status: 200, ...event } : { status: 204 };
  } catch {
    return { status: 400 };
  }
}

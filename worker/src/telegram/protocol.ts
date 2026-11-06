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

type NormalizedUpdate =
  | { command: TelegramCommand; view?: never; lifecycle?: never }
  | { view: TelegramViewUpdate; command?: never; lifecycle?: never }
  | { lifecycle: TelegramLifecycleUpdate; command?: never; view?: never };

type DecodedTelegramRequest =
  | ({ status: 200 } & NormalizedUpdate)
  | { status: 204 | 400 | 401 | 413 | 415; command?: never; view?: never; lifecycle?: never };

const MAX_UPDATE_BYTES = 64 * 1024;
const USERNAME = /^[A-Za-z0-9_]{5,32}(?![\s\S])/;
const WEBHOOK_SECRET = /^[A-Za-z0-9_-]{1,256}(?![\s\S])/;
const BOT_TOKEN = /^[1-9][0-9]*:[A-Za-z0-9_-]{1,128}(?![\s\S])/;
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset\s*=\s*(?:"utf-8"|utf-8))?$/i;
const BOT_COMMAND = /^\/([A-Za-z0-9_]{1,32})(?:@([A-Za-z0-9_]{5,32}))?(?![\s\S])/;
const CALLBACK_ID = /^[\u0021-\u007e]{1,128}(?![\s\S])/u;
const VIEW_TICKET = /^sbv1_[A-Za-z0-9_-]{22}(?![\s\S])/;
const LIFECYCLE_TICKET = /^sba1_[A-Za-z0-9_-]{22}(?![\s\S])/;
const RENAME_CANCEL = /^(?:\/cancel|cancel|取消|退出)(?![\s\S])/iu;
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
): TelegramCommand["command"] | TelegramViewKind | null {
  const { text, entities } = message;
  if (typeof text !== "string" || !Array.isArray(entities)) return null;
  const commands = entities.filter((entity) => isRecord(entity) && entity.type === "bot_command" && entity.offset === 0);
  if (commands.length !== 1) return null;
  const { length } = commands[0];
  if (!isPositiveInteger(length) || length > text.length) return null;
  // Telegram offsets and JavaScript string slicing both use UTF-16 code units.
  const entity = BOT_COMMAND.exec(text.slice(0, length));
  const remainder = text.slice(length);
  if (!entity || (remainder !== "" && !/^\s/u.test(remainder))) return null;
  const [, name, addressedTo] = entity;
  if (addressedTo && addressedTo.toLowerCase() !== policy.botUsername.toLowerCase()) return null;
  const args = remainder.trim().split(/\s+/u).filter(Boolean);
  switch (name.toLowerCase()) {
    case "start":
      return args[0]?.startsWith("claim_") ? null : "start";
    case "help":
      return "help";
    case "list":
      return "list";
    case "expire":
      return "expiry";
    case "recycle":
      return "recycle";
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

function normalizeMessage(
  message: Record<string, unknown>, updateId: number, policy: TelegramPolicy,
): NormalizedUpdate | null {
  if ("edit_date" in message) return null;
  const actorId = humanSender(message);
  if (actorId === null) return null;
  const scope = messageScope(message, actorId, updateId, policy);
  if (!scope) return null;
  const command = messageCommand(message, policy);
  if (command === "list" || command === "expiry" || command === "recycle") return { view: { ...scope, kind: command } };
  if (command) return { command: { ...scope, command } };
  const lifecycle = renameReply(message, scope, policy);
  return lifecycle ? { lifecycle } : null;
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

import assert from "node:assert/strict";
import { timingSafeEqual } from "node:crypto";
import { after, test } from "node:test";

import { decodeTelegramRequest, parseTelegramPolicy, type TelegramPolicy } from "../src/telegram/protocol.ts";

// Workers exposes a native timing-safe Web Crypto comparison. Node's equivalent
// lets these tests exercise the same digest inputs without changing production code.
const oldComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
Object.defineProperty(crypto.subtle, "timingSafeEqual", {
  configurable: true,
  value: (received: ArrayBuffer, expected: ArrayBuffer) => {
    assert.equal(received.byteLength, 32);
    assert.equal(expected.byteLength, 32);
    return timingSafeEqual(new Uint8Array(received), new Uint8Array(expected));
  },
});
after(() => {
  if (oldComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", oldComparison);
  else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
});

const policy: TelegramPolicy = {
  botId: "1234567890",
  botUsername: "SubscriptionFixtureBot",
  adminId: "123456789001",
  memberId: "123456789002",
  groupId: "-1001234567890",
  webhookSecret: "synthetic-webhook-secret",
  botToken: "1234567890:replace-with-synthetic-token",
};
const updateId = 5182026;
const messageDate = 1794000000;
const callbackId = "456789012345678901";
const viewTicket = "sbv1_ABCDEFGHIJKLMNOPQRSTUA";

function message(text = "/list", fields: Record<string, unknown> = {}) {
  return {
    message_id: 15,
    date: messageDate,
    from: { id: Number(policy.adminId), is_bot: false },
    chat: { id: Number(policy.adminId), type: "private" },
    text,
    entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }],
    ...fields,
  };
}

function request(body: BodyInit | null, overrides: Record<string, string> = {}) {
  const init = {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-telegram-bot-api-secret-token": policy.webhookSecret,
      ...overrides,
    },
    body,
    duplex: "half" as const,
  };
  return new Request("https://isolated.example.invalid/telegram/webhook", init);
}

function decode(payload: unknown) {
  return decodeTelegramRequest(request(JSON.stringify(payload)), policy);
}

function decodeMessage(text: string, fields: Record<string, unknown> = {}) {
  return decode({ update_id: updateId, message: message(text, fields) });
}

function callback(fields: Record<string, unknown> = {}, original: Record<string, unknown> = {}) {
  return {
    id: callbackId,
    from: { id: Number(policy.adminId), is_bot: false },
    chat_instance: "562789012345678901",
    data: viewTicket,
    message: {
      message_id: 32,
      date: messageDate,
      from: { id: Number(policy.botId), is_bot: true },
      chat: { id: Number(policy.adminId), type: "private" },
      text: "Synthetic bot reply",
      ...original,
    },
    ...fields,
  };
}

test("validates exact secret policy schema and canonical safe identities", () => {
  assert.deepEqual(parseTelegramPolicy(JSON.stringify(policy)), policy);
  for (const invalid of [
    null, policy, "[]", "{", JSON.stringify({ ...policy, extra: "fixture" }),
    JSON.stringify({ ...policy, botUsername: "@FixtureBot" }),
    JSON.stringify({ ...policy, webhookSecret: "secret with spaces" }),
    JSON.stringify({ ...policy, webhookSecret: "secret\n" }),
    JSON.stringify({ ...policy, webhookSecret: "x".repeat(257) }),
    JSON.stringify({ ...policy, botToken: "1234567891:synthetic-token" }),
    JSON.stringify({ ...policy, botToken: "1234567890:synthetic-token/path" }),
    JSON.stringify({ ...policy, adminId: Number(policy.adminId) }),
    JSON.stringify({ ...policy, adminId: "090" }),
    JSON.stringify({ ...policy, adminId: "9007199254740992" }),
    JSON.stringify({ ...policy, memberId: policy.adminId }),
    JSON.stringify({ ...policy, memberId: policy.botId }),
    JSON.stringify({ ...policy, groupId: "100" }),
    JSON.stringify({ ...policy, groupId: "-0" }),
  ]) assert.equal(parseTelegramPolicy(invalid), null);
});

test("rejects missing and incorrect webhook secrets before reading or checking the body", async () => {
  const wrong = request("not-json", {
    "content-type": "text/plain",
    "content-length": "999999",
    "x-telegram-bot-api-secret-token": "synthetic-webhook-wrongx",
  });
  assert.deepEqual(await decodeTelegramRequest(wrong, policy), { status: 401 });
  assert.equal(wrong.bodyUsed, false);
  const missing = new Request("https://isolated.example.invalid/telegram/webhook", { method: "POST", body: "{}" });
  assert.deepEqual(await decodeTelegramRequest(missing, policy), { status: 401 });
  assert.equal(missing.bodyUsed, false);
});

test("enforces media type, fatal UTF-8 and declared and streamed size limits", async () => {
  const valid = JSON.stringify({ update_id: updateId, message: message() });
  const media = request(valid, { "content-type": "application/json; Charset=\"utf-8\"" });
  assert.equal((await decodeTelegramRequest(media, policy)).status, 200);
  for (const headers of [
    { "content-type": "text/plain" },
    { "content-type": "application/json; charset=iso-8859-1" },
    { "content-encoding": "gzip" },
  ]) {
    const unsupported = request(valid, headers);
    assert.deepEqual(await decodeTelegramRequest(unsupported, policy), { status: 415 });
    assert.equal(unsupported.bodyUsed, false);
  }
  const oversized = request(valid, { "content-length": String(65537) });
  assert.deepEqual(await decodeTelegramRequest(oversized, policy), { status: 413 });
  assert.equal(oversized.bodyUsed, false);
  assert.deepEqual(await decodeTelegramRequest(request(valid, { "content-length": "4, 4" }), policy), { status: 400 });
  assert.deepEqual(await decodeTelegramRequest(request(Uint8Array.of(0xc3, 0x28)), policy), { status: 400 });
  assert.deepEqual(await decodeTelegramRequest(request("{"), policy), { status: 400 });
  assert.deepEqual(await decodeTelegramRequest(request(null), policy), { status: 400 });

  const padded = valid.padEnd(65536, " ");
  assert.equal((await decodeTelegramRequest(request(padded), policy)).status, 200);
  let cancelled = false;
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(padded));
      controller.enqueue(Uint8Array.of(0x20));
    },
    cancel() {
      cancelled = true;
    },
  });
  assert.deepEqual(await decodeTelegramRequest(request(stream, { "content-length": "1" }), policy), { status: 413 });
  assert.equal(cancelled, true);
});

test("normalizes commands and direct views without retaining message text or names", async () => {
  assert.deepEqual(await decodeMessage("/START@subscriptionfixturebot payload-fixture"), {
    status: 200,
    command: {
      updateId, actorId: policy.adminId, chatId: policy.adminId, chatType: "private",
      messageId: 15, messageDate, threadId: null, command: "start",
    },
  });
  for (const [text, kind] of [["/list", "list"], ["/EXPIRE@subscriptionfixturebot", "expiry"], ["/recycle", "recycle"]]) {
    assert.deepEqual(await decodeMessage(text), {
      status: 200,
      view: {
        updateId, actorId: policy.adminId, chatId: policy.adminId, chatType: "private",
        messageId: 15, messageDate, threadId: null, kind,
      },
    });
  }
  for (const chatType of ["group", "supergroup"]) {
    assert.deepEqual(await decodeMessage("/list", {
      from: { id: Number(policy.memberId), is_bot: false, username: "hidden-fixture" },
      chat: { id: Number(policy.groupId), type: chatType, title: "hidden-fixture" },
      message_thread_id: 212,
    }), {
      status: 200,
      view: {
        updateId, actorId: policy.memberId, chatId: policy.groupId, chatType,
        messageId: 15, messageDate, threadId: 212, kind: "list",
      },
    });
  }
  assert.equal((await decodeMessage("/help", { message_thread_id: 44 })).command?.threadId, 44);
});

test("normalizes scoped callbacks from the exact bot message without retaining reply text", async () => {
  assert.deepEqual(await decode({ update_id: updateId, callback_query: callback() }), {
    status: 200,
    view: {
      updateId, actorId: policy.adminId, chatId: policy.adminId, chatType: "private",
      messageId: 32, messageDate, threadId: null, kind: "callback", callbackId, ticket: viewTicket,
    },
  });
  assert.deepEqual(await decode({
    update_id: updateId,
    callback_query: callback({ from: { id: Number(policy.memberId), is_bot: false } }, {
      chat: { id: Number(policy.groupId), type: "supergroup" }, message_thread_id: 212,
    }),
  }), {
    status: 200,
    view: {
      updateId, actorId: policy.memberId, chatId: policy.groupId, chatType: "supergroup",
      messageId: 32, messageDate, threadId: 212, kind: "callback", callbackId, ticket: viewTicket,
    },
  });
});

test("drops malformed, inaccessible, inline and out-of-scope view callbacks", async () => {
  for (const invalid of [
    callback({ id: "" }),
    callback({ id: Number(callbackId) }),
    callback({ id: "bad\ncallback" }),
    callback({ data: viewTicket.slice(0, -1) }),
    callback({ data: `${viewTicket}\n` }),
    callback({ data: "legacy-callback" }),
    callback({ data: undefined, game_short_name: "fixture" }),
    callback({ from: { id: Number(policy.adminId), is_bot: true } }),
    callback({ from: { id: 123, is_bot: false } }),
    callback({ inline_message_id: "fixture-inline", message: undefined }),
    callback({ inline_message_id: "fixture-inline" }),
    callback({}, { from: { id: Number(policy.botId) + 1, is_bot: true } }),
    callback({}, { from: { id: Number(policy.botId), is_bot: false } }),
    callback({}, { date: 0 }),
    callback({}, { message_id: 0 }),
    callback({}, { message_id: Number.MAX_SAFE_INTEGER + 1 }),
    callback({}, { message_thread_id: 0 }),
    callback({}, { chat: { id: Number(policy.memberId), type: "private" } }),
    callback({}, { chat: { id: -42, type: "group" } }),
    callback({}, { chat: { id: Number(policy.groupId), type: "channel" } }),
  ]) {
    assert.deepEqual(await decode({ update_id: updateId, callback_query: invalid }), { status: 204 });
  }
  assert.deepEqual(await decode({ update_id: updateId, callback_query: callback(), message: message() }), { status: 204 });
});

test("dispatches an action callback only for the scoped bot and fixed token namespace", async () => {
  const ticket = "sba1_ABCDEFGHIJKLMNOPQRSTUA";
  const event = callback({ data: ticket });
  assert.deepEqual(await decode({ update_id: updateId, callback_query: event }), {
    status: 200,
    lifecycle: {
      updateId, actorId: policy.adminId, chatId: policy.adminId, chatType: "private",
      messageId: 32, messageDate, threadId: null, kind: "lifecycle-callback", callbackId, ticket,
    },
  });
  assert.deepEqual(await decode({ update_id: updateId, callback_query: { ...event, data: ticket + "\n" } }), {
    status: 204,
  });
});

test("normalizes only an explicit reply to an earlier own-bot message in the same group topic", async () => {
  const chat = { id: Number(policy.groupId), type: "supergroup" };
  const prompt = callback({}, { chat, message_id: 14, message_thread_id: 212 }).message;
  const fields = { chat, message_thread_id: 212, entities: [], reply_to_message: prompt };
  assert.deepEqual(await decodeMessage("新名称", fields), {
    status: 200,
    lifecycle: {
      updateId, actorId: policy.adminId, chatId: policy.groupId, chatType: "supergroup", threadId: 212,
      messageId: 15, messageDate, kind: "rename-reply", promptMessageId: 14, text: "新名称",
    },
  });
  assert.equal((await decodeMessage("/cancel", {
    ...fields, entities: [{ type: "bot_command", offset: 0, length: 7 }],
  })).lifecycle?.kind, "rename-reply");
  assert.equal((await decodeMessage("/list", {
    ...fields, entities: [{ type: "bot_command", offset: 0, length: 5 }],
  })).view?.kind, "list");
  for (const reply of [
    undefined, { ...prompt, chat: { ...chat, id: -42 } }, { ...prompt, message_thread_id: 213 },
    { ...prompt, date: messageDate + 1 }, { ...prompt, message_id: 15 },
    { ...prompt, from: { id: Number(policy.adminId), is_bot: false } },
  ]) {
    assert.deepEqual(await decodeMessage("新名称", { ...fields, reply_to_message: reply }), { status: 204 });
  }
  assert.deepEqual(await decodeMessage("/another@Other_Bot", {
    ...fields, entities: [{ type: "bot_command", offset: 0, length: 18 }],
  }), { status: 204 });
});

test("drops unknown actors and chats, channel posts, bots, anonymous, forwarded and edited events", async () => {
  for (const fields of [
    { from: { id: 123, is_bot: false } },
    { from: { id: policy.adminId, is_bot: false } },
    { from: { id: Number(policy.adminId), is_bot: true } },
    { from: { id: Number(policy.adminId) } },
    { sender_chat: { id: Number(policy.groupId) } },
    { via_bot: { id: Number(policy.botId), is_bot: true } },
    { forward_origin: { type: "user" } },
    { forward_date: messageDate },
    { is_automatic_forward: true },
    { edit_date: messageDate },
    { chat: { id: Number(policy.memberId), type: "private" } },
    { chat: { id: -42, type: "supergroup" } },
    { chat: { id: Number(policy.groupId), type: "channel" } },
    { message_id: 0 },
    { date: "1794000000" },
    { message_thread_id: 0 },
  ]) assert.deepEqual(await decodeMessage("/list", fields), { status: 204 });
  for (const event of ["edited_message", "channel_post", "edited_business_message", "callback_query"]) {
    assert.deepEqual(await decode({ update_id: updateId, [event]: message() }), { status: 204 });
    assert.deepEqual(await decode({ update_id: updateId, [event]: message(), message: message() }), { status: 204 });
  }
  assert.deepEqual(await decode({ update_id: "5182026", message: message() }), { status: 400 });
  assert.deepEqual(await decode([]), { status: 400 });
});

test("requires a leading whole command entity and exact bot address", async () => {
  for (const [text, entities] of [
    ["/list", []],
    [" /list", [{ type: "bot_command", offset: 1, length: 5 }]],
    ["😀/list", [{ type: "bot_command", offset: 2, length: 5 }]],
    ["/list@OtherFixtureBot", [{ type: "bot_command", offset: 0, length: 5 }]],
    ["/list🙂", [{ type: "bot_command", offset: 0, length: 5 }]],
    ["/list\n", [{ type: "bot_command", offset: 0, length: 6 }]],
    ["/list", [{ type: "bot_command", offset: 0, length: 6 }]],
    ["/list", [{ type: "bot_command", offset: 0, length: 5 }, { type: "bot_command", offset: 0, length: 5 }]],
  ]) assert.deepEqual(await decodeMessage(text as string, { entities }), { status: 204 });
  for (const text of ["/help@OtherFixtureBot", "/help@SubscriptionFixtureBotExtra", "/unsupported", "/start claim_fixture"]) {
    assert.deepEqual(await decodeMessage(text), { status: 204 });
  }
  assert.equal((await decodeMessage("/help@SubscriptionFixtureBot 😀")).command?.command, "help");
});

test("normalizes the legacy auth aliases and only the configured member target", async () => {
  for (const [text, expected] of [
    ["/auth", "auth-list"], ["/auth LIST", "auth-list"], ["/auth ls", "auth-list"],
    [`/auth add ${policy.memberId}`, "auth-add"], [`/auth remove ${policy.memberId}`, "auth-remove"],
    [`/auth del ${policy.memberId}`, "auth-remove"], [`/auth rm ${policy.memberId}`, "auth-remove"],
    [`/auth add ${policy.adminId}`, "auth-usage"], [`/auth add 0${policy.memberId}`, "auth-usage"],
    [`/auth add ${policy.memberId} extra`, "auth-usage"], ["/auth add", "auth-usage"],
    ["/auth ls extra", "auth-usage"], ["/auth unsupported", "auth-usage"],
  ]) assert.equal((await decodeMessage(text)).command?.command, expected);
  const reply_to_message = { from: { id: Number(policy.memberId), is_bot: false } };
  const group = { chat: { id: Number(policy.groupId), type: "group" }, reply_to_message };
  assert.equal((await decodeMessage("/auth add", group)).command?.command, "auth-add");
  assert.equal((await decodeMessage("/auth rm", group)).command?.command, "auth-remove");
  assert.equal((await decodeMessage("/auth add", {
    reply_to_message: { ...reply_to_message, forward_origin: { type: "user" } },
  })).command?.command, "auth-usage");
  assert.equal((await decodeMessage("/auth list", {
    from: { id: Number(policy.memberId), is_bot: false },
    chat: { id: Number(policy.memberId), type: "private" },
  })).command?.command, "auth-list");
});

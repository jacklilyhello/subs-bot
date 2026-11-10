import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test, type TestContext } from "node:test";
import { Miniflare } from "miniflare";
import { createPrivateShare } from "../src/private-shares.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "75301", botUsername: "FixtureGroupShareBot", adminId: "75302", memberId: "75303",
  groupId: "-10075304", botToken: "75301:synthetic-token", webhookSecret: "synthetic-group-share-secret",
};
const groupMigration = "0037_telegram_group_share_cards.sql";
const publishButton = "group-share:publish:v1";
const pickButton = "group-share:pick:v1";
const privateBody = "  Synthetic group share body\nPrivate continuation.  ";
const hash = (value: Buffer) => createHash("sha256").update(value).digest("hex");

type WireMessage = {
  chat_id: string;
  text: string;
  message_id?: number;
  reply_parameters?: { message_id: number };
  reply_markup?: { inline_keyboard: Array<Array<{ text: string; callback_data?: string; url?: string }>> };
};
type Delivery = { method: "sendMessage" | "editMessageText"; body: WireMessage; id: number };
type CallbackAnswer = { callback_query_id: string; text?: string; url?: string; cache_time?: number };

async function fixture(t: TestContext, enabled: boolean) {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8")) as {
    compatibilityDate: string; revision: string; bundleSha256: string; migrations: { name: string; sha256: string }[];
  };
  const bundle = await readFile(join(directory, "index.js"));
  assert.equal(hash(bundle), manifest.bundleSha256);
  assert.ok(manifest.migrations.some(({ name }) => name === groupMigration));
  const messages: Delivery[] = [];
  const answers: CallbackAnswer[] = [];
  let ambiguousNextCard = false;
  const runtime = new Miniflare({ modules: true, script: bundle.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"], bindings: { BUILD_REVISION: manifest.revision,
      TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_PRIVATE_SHARE_CREATION_KEY: Buffer.alloc(32, 0x57).toString("base64url"),
      ...(enabled ? { TELEGRAM_GROUP_SHARE_CARDS: "1" } : {}),
    }, outboundService: async (request: Request) => {
      const prefix = `https://api.telegram.org/bot${policy.botToken}/`;
      assert.ok(request.url.startsWith(prefix));
      assert.equal(request.method, "POST");
      const method = request.url.slice(prefix.length);
      if (method === "answerCallbackQuery") {
        answers.push(await request.json() as CallbackAnswer);
        return Response.json({ ok: true, result: true });
      }
      assert.ok(method === "sendMessage" || method === "editMessageText");
      const body = await request.json() as WireMessage;
      assert.ok([policy.adminId, policy.memberId, policy.groupId].includes(body.chat_id));
      const id = method === "editMessageText" ? body.message_id! : 20_000 + messages.length;
      messages.push({ method, body, id });
      if (ambiguousNextCard && method === "sendMessage" && body.chat_id === policy.groupId) {
        ambiguousNextCard = false;
        return Response.json({ ok: true, result: { message_id: id } });
      }
      return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(body.chat_id) } } });
    } });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const bucket = await runtime.getR2Bucket("NODES");
  for (const migration of manifest.migrations) {
    const bytes = await readFile(join(directory, migration.name));
    assert.equal(hash(bytes), migration.sha256);
    await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
  }
  await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
  await db.batch(manifest.migrations.map(({ name, sha256 }, index) =>
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')").bind(index + 1, name, sha256)));
  const date = Number(await db.prepare("SELECT unixepoch() AS now").first("now"));
  const worker = await runtime.getWorker();
  const tick = async () => assert.equal((await worker.scheduled({ cron: "* * * * *" })).outcome, "ok");
  const post = (update: unknown) => runtime.dispatchFetch("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
    body: JSON.stringify(update),
  });
  const message = (id: number, actor: string, text: string, chatId = actor) => post({ update_id: id,
    message: { message_id: id, date, text, from: { id: Number(actor), is_bot: false },
      chat: { id: Number(chatId), type: chatId.startsWith("-") ? "group" : "private" },
      entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u, 1)[0].length }],
    } });
  const callback = (id: number, actor: string, data: string, messageId: number, chatId = actor, options = {}) => post({ update_id: id,
    callback_query: { id: `fixture-group-${id}`, from: { id: Number(actor), is_bot: false }, data,
      message: { message_id: messageId, date, from: { id: Number(policy.botId), is_bot: true },
        chat: { id: Number(chatId), type: chatId.startsWith("-") ? "group" : "private" } }, ...options,
    } });
  const count = (table: "telegram_group_share_cards" | "telegram_group_share_scopes" | "telegram_private_claim" | "private_share_claims") =>
    db.prepare(`SELECT count(*) AS n FROM ${table}`).first<number>("n");
  const groupDeliveries = () => messages.filter(({ body }) => body.chat_id === policy.groupId);
  const privateDelivery = async (requestId: number) => {
    await tick();
    for (let attempt = 0; attempt < 50; attempt++) {
      const sent = await db.prepare(`SELECT sent_message_id FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
        WHERE bot_id=? AND update_id=? AND state='sent'`).bind(policy.botId, requestId).first<number>("sent_message_id");
      if (sent !== null) {
        const reply = messages.find(({ id, body }) => id === sent && body.reply_parameters?.message_id === requestId);
        assert.ok(reply);
        return reply;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Expected a confirmed private reply.");
  };
  const card = (creationUpdateId: number) => db.prepare(`SELECT card.state,card.message_id AS messageId,card.shown
    FROM telegram_group_share_cards AS card JOIN telegram_inbox AS origin USING(receipt_id)
    WHERE origin.bot_id=? AND origin.update_id=?`).bind(policy.botId, creationUpdateId)
    .first<{ state: string; messageId: number | null; shown: number }>();
  const waitForCard = async (creationUpdateId: number, state: string, shown = 0) => {
    await tick();
    for (let attempt = 0; attempt < 50; attempt++) {
      const row = await card(creationUpdateId);
      if (row?.state === state && row.shown === shown) return row;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Expected a settled group card.");
  };
  return { db, bucket, messages, answers, tick, post, message, callback, count, groupDeliveries, privateDelivery, waitForCard,
    makeNextPublicationAmbiguous() { ambiguousNextCard = true; } };
}

const draft = `/share x1 id${policy.memberId} s10 --\n${privateBody}`;

test("the emitted Worker hands off old inline cards to the existing private claim without claiming on click", { timeout: 45_000 }, async (t) => {
  const f = await fixture(t, false);
  const code = "legacyCode8";
  const created = await createPrivateShare(f.db, f.bucket, { botId: policy.botId, senderId: policy.adminId, senderName: "Synthetic sender",
    content: privateBody, maxClaims: 1, targetUserId: policy.memberId, durationMinutes: 10 });
  const updated = await f.db.prepare("UPDATE private_shares SET code_sha256=? WHERE bot_id=? AND code_sha256=?")
    .bind(hash(Buffer.from(code)), policy.botId, hash(Buffer.from(created.code))).run();
  assert.equal(updated.meta.changes, 1);
  const inline = (id: number, actor: string, shareCode: string, inlineId = "legacy-inline-fixture") => f.post({
    update_id: id, callback_query: { id: `legacy-${id}`, from: { id: Number(actor), is_bot: false },
      inline_message_id: inlineId, data: `share:c:${shareCode}` },
  });
  const answer = async (id: number) => {
    for (let attempt = 0; attempt < 50; attempt++) {
      const result = f.answers.find(({ callback_query_id }) => callback_query_id === `legacy-${id}`);
      if (result) return result;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Expected a legacy card acknowledgement.");
  };
  assert.equal((await inline(1, policy.memberId, code)).status, 204);
  assert.deepEqual(await answer(1), { callback_query_id: "legacy-1", cache_time: 0,
    url: `https://t.me/${policy.botUsername}?start=claim_${code}` });
  assert.equal((await inline(2, policy.adminId, code)).status, 204);
  assert.equal((await inline(3, policy.memberId, "unknown0000")).status, 204);
  for (const id of [2, 3]) assert.deepEqual(await answer(id), {
    callback_query_id: `legacy-${id}`, text: "此旧卡片暂不可用。", cache_time: 0,
  });
  assert.equal((await inline(4, "75309", code)).status, 204);
  assert.equal((await inline(5, policy.memberId, created.code)).status, 204);
  assert.equal((await inline(6, policy.memberId, code, "x".repeat(257))).status, 204);
  assert.equal(await f.count("telegram_private_claim"), 0);
  assert.equal(await f.count("private_share_claims"), 0);
  assert.equal(f.messages.length, 0);
  assert.equal(f.answers.length, 3);

  assert.equal((await f.message(7, policy.memberId, `/start claim_${code}`)).status, 200);
  const delivery = await f.privateDelivery(7);
  assert.equal(delivery.body.chat_id, policy.memberId);
  assert.ok(delivery.body.text.includes(privateBody));
  assert.equal(await f.count("private_share_claims"), 1);
  await inline(8, policy.memberId, code);
  assert.equal((await answer(8)).url, `https://t.me/${policy.botUsername}?start=claim_${code}`);
  assert.equal(await f.count("private_share_claims"), 1);
  await f.db.prepare("UPDATE private_shares SET expire_at=created_at-1, created_at=created_at-2").run();
  await inline(9, policy.memberId, code);
  assert.deepEqual(await answer(9), { callback_query_id: "legacy-9", text: "此旧卡片暂不可用。", cache_time: 0 });
  assert.equal(f.groupDeliveries().length, 0);
});

test("the emitted Worker does not offer or publish group cards while disabled", { timeout: 45_000 }, async (t) => {
  const f = await fixture(t, false);
  assert.equal((await f.message(1, policy.adminId, draft)).status, 200);
  const reply = await f.privateDelivery(1);
  assert.match(reply.body.text, /\?start=claim_[A-Za-z0-9_-]{22}/u);
  assert.equal(reply.body.reply_markup, undefined);
  assert.equal((await f.callback(2, policy.adminId, publishButton, reply.id)).status, 200);
  await f.tick();
  assert.equal(await f.count("telegram_group_share_cards"), 0);
  assert.deepEqual(f.groupDeliveries(), []);
});

test("the emitted Worker publishes one protected group card and sends the designated member's claim privately", { timeout: 60_000 }, async (t) => {
  const f = await fixture(t, true);
  assert.equal((await f.message(1, policy.adminId, draft)).status, 200);
  const creation = await f.privateDelivery(1);
  assert.deepEqual(creation.body.reply_markup?.inline_keyboard, [[{ text: "发到指定群", callback_data: publishButton }]]);
  const code = creation.body.text.match(/\?start=claim_([A-Za-z0-9_-]{22})/u)?.[1];
  assert.ok(code);

  assert.equal((await f.callback(2, policy.memberId, publishButton, creation.id, policy.adminId)).status, 204);
  assert.equal((await f.callback(3, policy.adminId, publishButton, creation.id, policy.groupId)).status, 204);
  assert.equal((await f.callback(4, policy.adminId, publishButton, creation.id, policy.adminId, { inline_message_id: "fixture-inline" })).status, 204);
  await f.callback(5, policy.adminId, publishButton, creation.id + 1);
  assert.equal((await f.message(19, policy.adminId, draft, policy.groupId)).status, 204);
  assert.equal(await f.count("telegram_group_share_cards"), 0);
  const publication = () => f.callback(6, policy.adminId, publishButton, creation.id);
  assert.ok((await Promise.all([publication(), publication()])).some(({ status }) => status === 200));
  await f.callback(7, policy.adminId, publishButton, creation.id);
  const card = await f.waitForCard(1, "sent");
  assert.equal(await f.count("telegram_group_share_cards"), 1);
  const [publicMessage] = f.groupDeliveries();
  assert.ok(publicMessage);
  assert.equal(card.messageId, publicMessage.id);
  assert.deepEqual(f.groupDeliveries().map(({ method }) => method), ["sendMessage"]);
  assert.equal(publicMessage.body.text, "私密分享\n领取进度：0/1");
  assert.deepEqual(publicMessage.body.reply_markup?.inline_keyboard, [
    [{ text: "领取", callback_data: pickButton }],
    [{ text: "打开 Bot 私聊", url: `https://t.me/${policy.botUsername}?start=group` }],
  ]);

  assert.equal((await f.callback(8, policy.memberId, pickButton, publicMessage.id, "-10075305")).status, 204);
  await f.callback(9, policy.memberId, pickButton, publicMessage.id + 1, policy.groupId);
  await f.callback(10, policy.adminId, pickButton, publicMessage.id, policy.groupId);
  await f.message(11, policy.adminId, "/start group");
  await f.message(12, policy.memberId, "/start group");
  assert.equal(await f.count("telegram_group_share_scopes"), 0);
  assert.equal(await f.count("telegram_private_claim"), 0);

  const pick = () => f.callback(13, policy.memberId, pickButton, publicMessage.id, policy.groupId);
  assert.ok((await Promise.all([pick(), pick()])).some(({ status }) => status === 200));
  assert.equal(await f.count("telegram_group_share_scopes"), 1);
  assert.equal(await f.count("private_share_claims"), 0);
  const handoff = () => f.message(14, policy.memberId, "/start group");
  assert.ok((await Promise.all([handoff(), handoff()])).some(({ status }) => status === 200));
  const claimed = await f.privateDelivery(14);
  assert.equal(claimed.body.chat_id, policy.memberId);
  assert.equal(claimed.body.text.split("\n\n", 2)[1], privateBody);
  assert.equal(await f.count("private_share_claims"), 1);
  assert.equal(await f.count("telegram_private_claim"), 1);
  const stored = await f.db.prepare(`SELECT payload_id AS payloadId,code_sha256 AS codeSha256 FROM private_shares`)
    .first<{ payloadId: string; codeSha256: string }>();
  assert.ok(stored);
  assert.equal(stored.codeSha256, hash(Buffer.from(code)));
  assert.equal(await (await f.bucket.get(`private-shares/${stored.payloadId}.txt`))!.text(), privateBody);
  await f.waitForCard(1, "sent", 1);
  const progress = f.groupDeliveries().filter(({ method }) => method === "editMessageText");
  assert.equal(progress.length, 1);
  assert.equal(progress[0].body.message_id, publicMessage.id);
  assert.equal(progress[0].body.text, "私密分享\n领取进度：1/1");

  assert.equal((await f.message(15, policy.memberId, "/start group")).status, 200);
  assert.equal((await f.privateDelivery(15)).body.text.split("\n\n", 2)[1], privateBody);
  assert.equal(await f.count("private_share_claims"), 1);
  assert.equal(f.groupDeliveries().length, 2);
  assert.equal((await f.message(16, policy.adminId, `/auth remove ${policy.memberId}`)).status, 200);
  await f.privateDelivery(16);
  await f.message(17, policy.memberId, "/start group");
  await f.tick();
  assert.equal(await f.count("telegram_private_claim"), 2);
  assert.equal(f.messages.some(({ body }) => body.reply_parameters?.message_id === 17), false);

  await f.db.prepare(`UPDATE private_shares AS share SET expire_at=unixepoch()-1,
    created_at=unixepoch()-1-60*(SELECT duration_minutes FROM telegram_private_share_creations WHERE share_id=share.id)`).run();
  await f.waitForCard(1, "sent", 101);
  const expired = f.groupDeliveries().at(-1)!;
  assert.equal(expired.body.message_id, publicMessage.id);
  assert.equal(expired.body.text, "私密分享已过期。\n领取进度：1/1");
  assert.deepEqual(expired.body.reply_markup?.inline_keyboard, []);

  const publicWire = JSON.stringify([...f.groupDeliveries(), ...f.answers]);
  assert.ok(f.answers.some(({ callback_query_id, text, cache_time }) => callback_query_id === "fixture-group-13" &&
    text === "已选中。请打开机器人私聊领取。" && cache_time === 0));
  for (const secret of [code, stored.codeSha256, stored.payloadId, "Synthetic group share body", "Private continuation.", "claim_"]) {
    assert.equal(publicWire.includes(secret), false);
  }
});

test("the emitted Worker records an unconfirmed publication and does not publish it twice", { timeout: 45_000 }, async (t) => {
  const f = await fixture(t, true);
  assert.equal((await f.message(1, policy.adminId, draft)).status, 200);
  const creation = await f.privateDelivery(1);
  f.makeNextPublicationAmbiguous();
  assert.equal((await f.callback(2, policy.adminId, publishButton, creation.id)).status, 200);
  const unknown = await f.waitForCard(1, "uncertain");
  assert.equal(unknown.messageId, null);
  await f.callback(3, policy.adminId, publishButton, creation.id);
  await f.tick();
  assert.equal(f.groupDeliveries().length, 1);
  await f.callback(4, policy.memberId, pickButton, f.groupDeliveries()[0].id, policy.groupId);
  await f.message(5, policy.memberId, "/start group");
  assert.equal(await f.count("telegram_group_share_scopes"), 0);
  assert.equal(await f.count("private_share_claims"), 0);
});

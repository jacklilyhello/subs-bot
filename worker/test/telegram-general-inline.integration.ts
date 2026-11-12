import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createPrivateShare, privateShareCodeDigest } from "../src/private-shares.ts";
import { createSubscription } from "../src/storage.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

type Message = { chat_id: string; text: string; reply_parameters: { message_id: number } };
type Answer = { inline_query_id: string; is_personal: boolean; cache_time: number; next_offset: string;
  results: { title: string; description?: string; input_message_content: { message_text: string } }[] };
type Callback = { callback_query_id: string; text?: string; url?: string; cache_time: number };

test("emitted general inline temp consent and historic share cards preserve private ownership and current authority", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  const hash = (value: string) => createHash("sha256").update(value).digest("hex");
  assert.equal(hash(script), manifest.bundleSha256);
  const now = Math.floor(Date.now() / 1000);
  const bot = { botId: "78201", botUsername: "Fixture_General_Inline_Bot", botToken: "78201:synthetic-token",
    webhookSecret: "synthetic-general-inline-secret" };
  const member = "78202", admin = "78203", denied = "78204", foreignBot = "78205", group = "-10078206";
  const config = { ...bot, generation: 1, cutoverAt: now - 100, activationSha256: "b".repeat(64), inlineSearch: true,
    outbox: "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected-short" };
  const messages: Message[] = [], answers = new Map<string, Answer>(), callbacks = new Map<string, Callback>();
  const files: { actor: string; content: string }[] = [];
  const request = async (input: Request) => {
    assert.equal(input.method, "POST");
    const api = `https://api.telegram.org/bot${bot.botToken}/`;
    if (input.url === api + "answerInlineQuery") {
      const body = await input.json() as Answer;
      assert.equal(body.is_personal, true);
      assert.equal(body.cache_time, 0);
      assert.equal(body.next_offset, "");
      assert.equal(answers.has(body.inline_query_id), false);
      assert.doesNotMatch(JSON.stringify(body), /ss:\/\/|provider\.example|synthetic-node-secret|archived-private-content|\/sub\/|\/agg\//u);
      answers.set(body.inline_query_id, body);
      return Response.json({ ok: true, result: true });
    }
    if (input.url === api + "answerCallbackQuery") {
      const body = await input.json() as Callback;
      assert.doesNotMatch(JSON.stringify(body), /archived-private-content|ss:\/\/|\/sub\/|\/agg\//u);
      callbacks.set(body.callback_query_id, body);
      return Response.json({ ok: true, result: true });
    }
    if (input.url === api + "sendDocument") {
      const body = await input.formData();
      const document = body.get("document");
      assert.ok(document instanceof Blob);
      const actor = String(body.get("chat_id"));
      assert.ok([member, admin].includes(actor));
      files.push({ actor, content: await document.text() });
      return Response.json({ ok: true, result: { message_id: 30000 + files.length, chat: { id: Number(actor) } } });
    }
    assert.equal(input.url, api + "sendMessage");
    const body = await input.json() as Message;
    assert.ok([member, admin].includes(body.chat_id), "callbacks and inline queries must not send private content into a group");
    assert.doesNotMatch(body.text, /ss:\/\/|provider\.example|synthetic-node-secret/u);
    messages.push(body);
    return Response.json({ ok: true, result: { message_id: 20000 + messages.length, chat: { id: Number(body.chat_id) } } });
  };
  const d1Databases = { DB: "general-inline" }, r2Buckets = { NODES: "general-inline" };
  const runtime = new Miniflare({ workers: ["app", "disabled"].map((name) => ({ name, modules: true, script,
    compatibilityDate: manifest.compatibilityDate, d1Databases, r2Buckets, outboundService: request,
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_GENERAL_CONFIG: JSON.stringify(config),
      ...(name === "app" ? { TELEGRAM_INLINE_SEARCH: "1" } : {}),
      TELEGRAM_PRIVATE_SHARE_CREATION_KEY: Buffer.alloc(32, 0x39).toString("base64url") } })) });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB", "app"), bucket = await runtime.getR2Bucket("NODES", "app");
  const app = await runtime.getWorker("app"), disabled = await runtime.getWorker("disabled");
  for (const entry of manifest.migrations as { name: string; sha256: string }[]) {
    const sql = await readFile(join(directory, entry.name), "utf8");
    assert.equal(hash(sql), entry.sha256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((part) => db.prepare(part)));
    await recordTempFixtureMigration(db, entry);
  }
  for (const entry of manifest.migrations) await db.prepare(`INSERT OR IGNORE INTO subs_bot_schema_migrations
    (position,name,sha256,mode) VALUES (?,?,?,'applied')`).bind(Number(entry.name.slice(0, 4)), entry.name, entry.sha256).run();
  await db.prepare("INSERT INTO telegram_general_policy VALUES (?,1,?,?,?,1)")
    .bind(bot.botId, manifest.revision, config.activationSha256, config.cutoverAt).run();
  const grant = (actor: string, revision: number, role: "member" | "admin" | "denied", effective = now - 100) =>
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,?,?,?)").bind(bot.botId, actor, revision, effective, role).run();
  await grant(member, 1, "member");
  await grant(admin, 1, "admin");
  await grant(denied, 1, "denied");
  let sequence = 100, date = now - 5;
  const dispatch = (update: unknown, worker = app) => worker.fetch("https://fixture.invalid/telegram/webhook", { method: "POST",
    headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": bot.webhookSecret }, body: JSON.stringify(update) });
  const command = (text: string, actor = member, id = ++sequence, chat = actor, worker = app) => dispatch({ update_id: id,
    message: { message_id: id, date, text, from: { id: Number(actor), is_bot: false },
      chat: { id: Number(chat), type: chat === group ? "supergroup" : "private" },
      ...(text.startsWith("/") ? { entities: [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] } : {}) } }, worker);
  const state = (id: number) => db.prepare(`SELECT reply.state FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(bot.botId, id).first<string>("state");
  async function reply(id = sequence) {
    for (let attempt = 0; attempt < 100; attempt++) {
      if (await state(id) === "sent") {
        const body = messages.find((body) => body.reply_parameters.message_id === id);
        assert.ok(body);
        return body;
      }
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Synthetic general inline command did not settle.");
  }
  const query = (text = "", actor = member, id = ++sequence, chatType = "sender", worker = app) => {
    const queryId = `synthetic-inline-${id}`;
    return dispatch({ update_id: id, inline_query: { id: queryId, query: text, offset: "", chat_type: chatType,
      from: { id: Number(actor), is_bot: false } } }, worker);
  };
  const titles = (id = sequence) => answers.get(`synthetic-inline-${id}`)?.results.map(({ title }) => title);
  const callback = (code: string, actor = member, id = ++sequence, source: "inline" | "group" | "private" | "foreign" = "inline") =>
    dispatch({ update_id: id, callback_query: { id: `synthetic-card-${id}`, data: `share:c:${code}`,
      from: { id: Number(actor), is_bot: false }, ...(source === "inline" ? { inline_message_id: `synthetic-inline-card-${id}` }
        : { message: { message_id: 99, date: now - 10000, from: { id: Number(source === "foreign" ? foreignBot : bot.botId), is_bot: true },
          chat: { id: Number(source === "private" ? actor : group), type: source === "private" ? "private" : "supergroup" } } }) } });
  async function acknowledged(id = sequence) {
    for (let attempt = 0; attempt < 100; attempt++) {
      const answer = callbacks.get(`synthetic-card-${id}`);
      if (answer) return answer;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
    assert.fail("Synthetic historic card was not acknowledged.");
  }
  const countClaims = async (code: string) => db.prepare(`SELECT count(*) AS n FROM private_share_claims AS claim
    JOIN private_shares AS share ON share.id=claim.share_id WHERE share.bot_id=? AND share.code_sha256=?`)
    .bind(bot.botId, await privateShareCodeDigest(code)).first<number>("n");
  async function archive(code: string, options: { target?: string; botId?: string; maxClaims?: number } = {}) {
    const ownerBot = options.botId ?? bot.botId;
    const share = await createPrivateShare(db, bucket, { botId: ownerBot, senderId: admin, senderName: "Synthetic sender",
      content: "archived-private-content", targetUserId: options.target ?? null, maxClaims: options.maxClaims ?? 1, durationMinutes: 5 });
    await db.prepare("UPDATE private_shares SET code_sha256=? WHERE bot_id=? AND code_sha256=?")
      .bind(await privateShareCodeDigest(code), ownerBot, await privateShareCodeDigest(share.code)).run();
    return code;
  }

  await createSubscription(db, { ownerId: member, name: "Owned subscription", sourceUrl: "https://provider.example/owned" });
  await createSubscription(db, { ownerId: admin, name: "Foreign subscription", sourceUrl: "https://provider.example/foreign" });
  const rawAuthentication = Buffer.from("aes-256-gcm:synthetic-node-secret").toString("base64url");
  const raw = "ss://" + rawAuthentication
    + "@203.0.113.71:8388#Live%20https%3A%2F%2Fexample.invalid%2Fhidden";
  const baseline = JSON.stringify([{ type: "temp", name: "Baseline temporary", share: raw }]);
  await db.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,?)").bind(bot.botId, "a".repeat(64), now - 60).run();
  await db.prepare("INSERT INTO legacy_temp_batches VALUES (?,?,1,1,?,1,?,?)")
    .bind(bot.botId, member, baseline, Buffer.byteLength(baseline), hash(baseline)).run();
  assert.equal((await command(raw)).status, 200);
  await reply();
  assert.equal((await command("ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.72:8388#Foreign%20temp", admin)).status, 200);
  await reply();
  assert.equal((await query()).status, 204);
  assert.equal(titles(), undefined, "personal data requires an explicit private consent");
  assert.equal((await command("/inline on")).status, 200);
  await reply();
  assert.equal((await query()).status, 204);
  assert.deepEqual(titles(), ["Owned subscription"]);
  assert.equal((await command(`/inline@${bot.botUsername} temp on`)).status, 200);
  const tempConsent = sequence;
  assert.match((await reply()).text, /及临时节点名称/u);
  assert.equal((await command("/inline temp on", member, tempConsent)).status, 204);
  assert.deepEqual(await db.prepare(`SELECT inbox.receipt_nonce AS marker,recorded.actor_revision AS revision,consent.kind
    FROM telegram_inbox AS inbox JOIN telegram_general_receipt AS recorded USING(receipt_id)
    JOIN telegram_inline_search_consent AS consent USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(bot.botId, tempConsent).first(), { marker: "general-inline-consent-temp:v1", revision: 1, kind: "on" });
  assert.equal((await query()).status, 204);
  assert.deepEqual(titles(), ["Owned subscription", "🧪 Baseline temporary", "🧪 Live [链接已省略]"]);
  assert.equal((await query(rawAuthentication)).status, 204);
  assert.deepEqual(titles(), ["🧪 Baseline temporary", "🧪 Live [链接已省略]"]);
  assert.equal((await command("/inline temp on", admin)).status, 200);
  await reply();
  assert.equal((await query("", admin)).status, 204);
  assert.deepEqual(titles(), ["Foreign subscription", "🧪 Foreign temp"], "the administrator also searches only their own inventory");
  for (const chatType of ["group", "supergroup", "private"]) {
    assert.equal((await query("", member, ++sequence, chatType)).status, 204);
    assert.equal(titles(), undefined);
  }
  assert.equal((await command("/inline temp on", member, ++sequence, group)).status, 204);
  assert.equal((await query("", denied)).status, 204);
  assert.equal(titles(), undefined);
  await db.prepare(`UPDATE telegram_inline_search_consent SET expires_at=unixepoch()-1
    WHERE receipt_id=(SELECT max(receipt_id) FROM telegram_inline_search_consent WHERE bot_id=? AND actor_id=? AND kind='on')`)
    .bind(bot.botId, member).run();
  assert.equal((await query()).status, 204);
  assert.equal(titles(), undefined, "expiry closes both personal inventories");
  assert.equal((await command("/inline temp on")).status, 200);
  await reply();
  assert.equal((await command("/help")).status, 200);
  assert.match((await reply()).text, /\/inline temp on/u);
  assert.equal((await query("Share synthetic-inline-private-text")).status, 204);
  const handoff = answers.get(`synthetic-inline-${sequence}`)!;
  assert.equal(handoff.results.length, 1);
  assert.match(handoff.results[0].input_message_content.message_text, /私聊.*\/share/u);
  assert.doesNotMatch(JSON.stringify(handoff), /synthetic-inline-private-text|claim_|\/s\//u);
  assert.equal((await command("/inline off", member, ++sequence, member, disabled)).status, 200);
  await reply();
  assert.equal((await query()).status, 204);
  assert.equal(titles(), undefined);
  assert.equal((await command("/inline temp on", member, ++sequence, member, disabled)).status, 204);
  assert.equal((await command("/inline temp on")).status, 200);
  await reply();
  assert.equal((await query("", member, ++sequence, "sender", disabled)).status, 204);
  assert.equal(titles(), undefined);
  assert.equal((await command("/temp clear")).status, 200);
  await reply();
  assert.equal((await query()).status, 204);
  assert.deepEqual(titles(), ["Owned subscription"]);

  // Historic callback cards hand off to private /start; none of these callbacks consume a share.
  const code = await archive("LegacyCard1", { target: member });
  for (const source of ["inline", "group", "private"] as const) {
    assert.equal((await callback(code, member, ++sequence, source)).status, 204);
    const answer = await acknowledged();
    assert.equal(answer.url, `https://t.me/${bot.botUsername}?start=claim_${code}`);
    assert.equal(answer.cache_time, 0);
    assert.equal(await countClaims(code), 0);
  }
  assert.equal((await callback(code, admin)).status, 204);
  assert.equal((await acknowledged()).url, undefined, "recipient restrictions apply before the private handoff");
  assert.equal((await callback(code, denied)).status, 204);
  assert.equal((await acknowledged()).url, undefined);
  const foreignCallback = ++sequence;
  assert.equal((await callback(code, member, foreignCallback, "foreign")).status, 204);
  assert.equal(callbacks.has(`synthetic-card-${foreignCallback}`), false);
  const foreignCode = await archive("ForeignCard", { botId: foreignBot });
  assert.equal((await callback(foreignCode)).status, 204);
  assert.equal((await acknowledged()).url, undefined);
  const expiredCode = await archive("ExpiredCard");
  await db.prepare("UPDATE private_shares SET created_at=unixepoch()-2,expire_at=unixepoch()-1 WHERE bot_id=? AND code_sha256=?")
    .bind(bot.botId, await privateShareCodeDigest(expiredCode)).run();
  assert.equal((await callback(expiredCode)).status, 204);
  assert.equal((await acknowledged()).url, undefined);
  assert.equal((await command(`/start claim_${code}`, member, ++sequence, group)).status, 204);
  assert.equal(await countClaims(code), 0);
  assert.equal((await command(`/start claim_${code}`)).status, 200);
  await reply();
  assert.equal(await countClaims(code), 1);
  assert.equal((await callback(code)).status, 204);
  assert.ok((await acknowledged()).url, "an existing recipient can reopen without spending another claim");
  assert.equal(await countClaims(code), 1);
  const exhausted = await archive("LimitedCard");
  assert.equal((await command(`/start claim_${exhausted}`)).status, 200);
  await reply();
  assert.equal((await callback(exhausted, admin)).status, 204);
  assert.equal((await acknowledged()).url, undefined, "another actor cannot exceed the original claim count");
  const waiting = await archive("WaitingCard", { target: member });
  assert.equal((await callback(waiting)).status, 204);
  assert.ok((await acknowledged()).url);
  await grant(member, 2, "denied", now - 4);
  assert.equal((await command(`/start claim_${waiting}`)).status, 204);
  assert.equal(await countClaims(waiting), 0);
  assert.equal((await callback(waiting)).status, 204);
  assert.equal((await acknowledged()).url, undefined);
  assert.equal((await query()).status, 204);
  assert.equal(titles(), undefined);
  await grant(member, 3, "member", now - 3);
  date = now - 2;
  assert.equal((await query()).status, 204);
  assert.equal(titles(), undefined, "regrant cannot restore the previous consent epoch");
  assert.equal((await command("/inline temp on")).status, 200);
  await reply();
  const fencedClaim = await archive("GuardedCard", { target: member });
  const claimUpdate = ++sequence, beforeMessages = messages.length;
  await db.prepare(`CREATE TRIGGER revoke_general_claim_before_send AFTER UPDATE OF state ON telegram_outbox
    WHEN new.state='sending' AND old.state='leased' AND EXISTS (
      SELECT 1 FROM telegram_inbox WHERE receipt_id=new.receipt_id AND bot_id='${bot.botId}' AND update_id=${claimUpdate})
    BEGIN INSERT INTO telegram_general_actors VALUES ('${bot.botId}',1,'${member}',4,${now - 2},'denied'); END`).run();
  assert.equal((await command(`/start claim_${fencedClaim}`, member, claimUpdate)).status, 200);
  for (let attempt = 0; attempt < 100 && await state(claimUpdate) !== "failed"; attempt++) {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  assert.equal(await state(claimUpdate), "failed");
  assert.equal(messages.length, beforeMessages, "a claim cannot deliver after the general actor is revoked");
  await db.prepare("DROP TRIGGER revoke_general_claim_before_send").run();
  await grant(member, 5, "member", now - 1);
  date = now;
  assert.equal((await command("/inline temp on")).status, 200);
  await reply();
  // An actor revision inserted by the sending transition must be seen by the final answer fence.
  const fenced = ++sequence, before = answers.size;
  await db.prepare(`CREATE TRIGGER revoke_general_inline_before_answer AFTER UPDATE OF state ON telegram_inline_search_receipts
    WHEN new.bot_id='${bot.botId}' AND new.update_id=${fenced} AND new.state='sending' AND old.state='preflight'
    BEGIN INSERT INTO telegram_general_actors VALUES ('${bot.botId}',1,'${member}',6,${now},'denied'); END`).run();
  assert.equal((await query("", member, fenced)).status, 204);
  assert.equal(answers.size, before);
  assert.equal(await db.prepare("SELECT state FROM telegram_inline_search_receipts WHERE bot_id=? AND update_id=?")
    .bind(bot.botId, fenced).first("state"), "dropped");
  assert.doesNotMatch(JSON.stringify((await db.prepare("SELECT * FROM telegram_inline_search_receipts").all()).results),
    /synthetic-node-secret|synthetic-inline-private-text|provider\.example|archived-private-content/u);
});

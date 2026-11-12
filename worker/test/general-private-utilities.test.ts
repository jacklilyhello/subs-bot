import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, test } from "node:test";
import { Miniflare } from "miniflare";
import { acceptGeneralSharedTelegramCommand, beginGeneralSharedTelegramReply, claimGeneralSharedTelegramReply } from "../src/telegram/general-auth-shared.ts";
import { parseGeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { acceptTelegramGitHubSearch, GENERAL_GITHUB_SEARCH_MARKER, recoverTelegramGitHubSearch, runTelegramGitHubSearch } from "../src/telegram/github-search.ts";
import { acceptTelegramApiStatusPrompt, acceptTelegramApiStatusReply, GENERAL_API_STATUS_MARKER,
  reconcileTelegramApiStatus, renderTelegramApiStatus, runTelegramApiStatus } from "../src/telegram/api-status.ts";
import { TELEGRAM_API_STATUS_PROMPT } from "../src/telegram/api-status-input.ts";
import { readGeneralPrivateApiStatus, readGeneralPrivateGitHubSearch, type TelegramEventScope } from "../src/telegram/protocol.ts";
import { renderTelegramHelp } from "../src/telegram/command-catalog.ts";
import type { ProviderApiStatusV2Prober } from "../src/provider-fetch-contract.ts";

// Match Workers' native extension in the Node-hosted test process only.
const previousComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
Object.defineProperty(crypto.subtle, "timingSafeEqual", { configurable: true,
  value: (received: ArrayBuffer, expected: ArrayBuffer) => {
    assert.equal(received.byteLength, 32);
    assert.equal(expected.byteLength, 32);
    return timingSafeEqual(new Uint8Array(received), new Uint8Array(expected));
  },
});
after(() => {
  if (previousComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", previousComparison);
  else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
});

const base = { botId: "96101", botUsername: "UtilityFixtureBot", botToken: "96101:synthetic-token",
  webhookSecret: "synthetic-utility-webhook", generation: 1, cutoverAt: 1, activationSha256: "a".repeat(64),
  outbox: "shared-private-management", githubSearch: true, apiStatus: true };
const revision = "b".repeat(40), admin = "96102", member = "96103";

function event(updateId: number, now: number, actorId = member): TelegramEventScope {
  return { updateId, messageId: updateId, messageDate: now, actorId, chatId: actorId, chatType: "private", threadId: null };
}

function update(scope: TelegramEventScope, text: string, extra: object = {}) {
  const leading = text.split(/\s/u)[0];
  return { update_id: scope.updateId, message: { message_id: scope.messageId, date: scope.messageDate,
    from: { id: Number(scope.actorId), is_bot: false }, chat: { id: Number(scope.chatId), type: scope.chatType }, text,
    entities: text.startsWith("/") ? [{ type: "bot_command", offset: 0, length: leading.length }] : [], ...extra } };
}

async function database(t: { after(fn: () => Promise<void>): void }) {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  const directory = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
  const now = await db.prepare("SELECT unixepoch() AS n").first<number>("n");
  assert.ok(now);
  const pin = parseGeneralTelegramPin(JSON.stringify({ ...base, cutoverAt: now - 20 }), revision);
  assert.ok(pin?.privateGitHub && pin.privateApiStatus);
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES(?,?,?,?,?,1)")
      .bind(pin.botId, pin.generation, revision, pin.activationSha256, pin.cutoverAt),
    db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,1,?,'admin'),(?,?,?,1,?,'member')")
      .bind(pin.botId, pin.generation, admin, pin.cutoverAt, pin.botId, pin.generation, member, pin.cutoverAt),
  ]);
  return { db, now, pin };
}

test("general utility configuration and private parsers expose only enabled real operations", () => {
  assert.ok(parseGeneralTelegramPin(JSON.stringify(base), revision)?.privateApiStatus);
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...base, githubSearch: false }), revision), null);
  assert.equal(parseGeneralTelegramPin(JSON.stringify({ ...base, outbox: "shared" }), revision), null);
  const scope = event(1, 100);
  assert.equal(readGeneralPrivateGitHubSearch(update(scope, "/g@UtilityFixtureBot clash"), 1, base.botId, base.botUsername)?.args, " clash");
  assert.equal(readGeneralPrivateGitHubSearch(update({ ...scope, chatId: "-100", chatType: "group" }, "/g clash"), 1, base.botId, base.botUsername), null);
  assert.equal(readGeneralPrivateApiStatus(update(scope, "/ai secret-argument"), 1, base.botId, base.botUsername), null);
  const help = renderTelegramHelp({ privateChat: true, role: "member", features: { github: true, apiStatus: true } });
  assert.match(help, /^\/g 关键词 搜索 GitHub 公开代码$/mu);
  assert.match(help, /^\/ai 测试 API 地址和 Key$/mu);
  assert.match(help, /^\/cancel 回复 API 提示时取消$/mu);
  const group = renderTelegramHelp({ privateChat: false, role: "admin", features: { github: true, apiStatus: true } });
  assert.doesNotMatch(group, /\/g |\/ai|\/cancel/u);
});

test("general GitHub uses the real bounded search engine with durable deduplication and current grants", async (t) => {
  const { db, now, pin } = await database(t);
  const scope = event(10, now);
  const lookup = await acceptTelegramGitHubSearch(db, pin, { ...scope, args: "clash" });
  assert.equal(lookup.kind, "lookup");
  if (lookup.kind !== "lookup") return;
  assert.equal((await acceptTelegramGitHubSearch(db, pin, { ...scope, args: "clash" })).kind, "ignored");
  assert.equal((await acceptTelegramGitHubSearch(db, pin, { ...event(11, now), args: "clash" })).kind, "reply");
  let repositories = 0;
  const request = (async (input: string | URL | Request) => {
    const url = String(input instanceof Request ? input.url : input);
    if (url.startsWith("https://api.github.com/search/repositories")) {
      repositories++;
      return Response.json({ items: [], total_count: 0, incomplete_results: false });
    }
    throw new Error("Synthetic Grep unavailable");
  }) as typeof fetch;
  const outcomes = await Promise.all([runTelegramGitHubSearch(db, pin, lookup, request), runTelegramGitHubSearch(db, pin, lookup, request)]);
  assert.equal(outcomes.filter(Boolean).length, 1);
  assert.equal(repositories, 1);
  const row = await db.prepare("SELECT inbox.receipt_nonce AS marker,authority.actor_revision AS revision,search.state FROM telegram_inbox AS inbox JOIN telegram_general_receipt AS authority USING(receipt_id) JOIN telegram_github_search AS search USING(receipt_id) WHERE inbox.update_id=10").first();
  assert.deepEqual(row, { marker: GENERAL_GITHUB_SEARCH_MARKER, revision: 1, state: "empty" });
  const adminLookup = await acceptTelegramGitHubSearch(db, pin, { ...event(12, now, admin), args: "clash" });
  assert.equal(adminLookup.kind, "lookup");
  if (adminLookup.kind === "lookup") {
    await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,2,?,'denied')").bind(pin.botId, pin.generation, admin, now).run();
    assert.equal(await runTelegramGitHubSearch(db, pin, adminLookup, request), false);
    assert.equal(repositories, 1, "revocation prevents every outbound lookup");
  }
  assert.equal((await acceptTelegramGitHubSearch(db, pin, { ...event(13, now, "96999"), args: "clash" })).kind, "ignored");
  assert.equal((await acceptTelegramGitHubSearch(db, pin, { ...event(14, now), args: "clash", chatType: "group", chatId: "-100" })).kind, "ignored");
  const lease = await claimGeneralSharedTelegramReply(db, pin);
  assert.ok(lease && lease.marker === GENERAL_GITHUB_SEARCH_MARKER);
  assert.equal(await beginGeneralSharedTelegramReply(db, pin, lease), true);
  await db.prepare("UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL WHERE receipt_id=?").bind(lease.receiptId).run();
  await recoverTelegramGitHubSearch(db, pin);
  const saved = await db.prepare("SELECT public_results FROM telegram_github_search WHERE receipt_id=?").bind(lookup.receiptId).first("public_results");
  assert.equal(saved, null);
});

test("general API probes bind sent prompts, keep credentials transient and never replay RPC", async (t) => {
  const { db, now, pin } = await database(t);
  const sendPrompt = async (id: number, actor = member) => {
    assert.equal(await acceptTelegramApiStatusPrompt(db, pin, event(id, now, actor)), true);
    const row = await db.prepare("SELECT receipt_id AS id FROM telegram_inbox WHERE bot_id=? AND update_id=?").bind(pin.botId, id).first<{ id: number }>();
    assert.ok(row);
    await db.prepare("UPDATE telegram_outbox SET state='sent',attempts=1,sent_message_id=? WHERE receipt_id=?").bind(id + 1000, row.id).run();
    return id + 1000;
  };
  const promptId = await sendPrompt(100);
  const replyEvent = { ...event(1101, now), kind: "reply" as const, promptMessageId: promptId,
    text: "https://api.example.invalid/models | synthetic-private-key" };
  const origin = { message_id: promptId, date: now, text: TELEGRAM_API_STATUS_PROMPT,
    from: { id: Number(pin.botId), is_bot: true }, chat: { id: Number(member), type: "private" } };
  assert.equal(readGeneralPrivateApiStatus(update(replyEvent, replyEvent.text, { reply_to_message: origin }), replyEvent.updateId, pin.botId, pin.botUsername)?.kind, "reply");
  assert.equal(readGeneralPrivateApiStatus(update(replyEvent, replyEvent.text, { reply_to_message: { ...origin, from: { id: 99, is_bot: true } } }), replyEvent.updateId, pin.botId, pin.botUsername), null);
  assert.equal(await acceptTelegramApiStatusReply(db, pin, { ...replyEvent, actorId: admin, chatId: admin }), null);
  const accepted = await acceptTelegramApiStatusReply(db, pin, replyEvent);
  assert.ok(accepted);
  assert.equal(await acceptTelegramApiStatusReply(db, pin, replyEvent), null);
  let rpc = 0;
  const provider = { probeApiStatusV2: async () => { rpc++; return { ok: true, status: 200, elapsedMs: 12 }; } } as unknown as ProviderApiStatusV2Prober;
  const providerPin = { providerRevision: "c".repeat(40), imageSha256: "d".repeat(64) };
  await runTelegramApiStatus(db, pin, provider, providerPin, accepted);
  await runTelegramApiStatus(db, pin, provider, providerPin, accepted);
  assert.equal(rpc, 1);
  await reconcileTelegramApiStatus(db, pin);
  const lease = await claimGeneralSharedTelegramReply(db, pin);
  assert.ok(lease && lease.marker === GENERAL_API_STATUS_MARKER);
  const presentation = await renderTelegramApiStatus(db, pin, lease);
  assert.match(presentation?.text ?? "", /HTTP 200 · 12 ms/u);
  assert.doesNotMatch(JSON.stringify(await db.prepare("SELECT * FROM telegram_api_status").all()), /example\.invalid|synthetic-private-key/u);
  await db.prepare("UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL WHERE receipt_id=?").bind(lease.receiptId).run();
  const nextPrompt = await sendPrompt(1200);
  const revoked = await acceptTelegramApiStatusReply(db, pin, { ...event(2300, now), kind: "reply", promptMessageId: nextPrompt, text: replyEvent.text });
  assert.ok(revoked);
  await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,2,?,'denied')").bind(pin.botId, pin.generation, member, now).run();
  await runTelegramApiStatus(db, pin, provider, providerPin, revoked);
  assert.equal(rpc, 1);
  await db.prepare("UPDATE telegram_api_status SET expires_at=unixepoch()-1 WHERE receipt_id=?").bind(revoked.receiptId).run();
  await reconcileTelegramApiStatus(db, pin);
  assert.equal(await db.prepare("SELECT 1 FROM telegram_outbox WHERE receipt_id=?").bind(revoked.receiptId).first(), null);
  assert.equal(await acceptTelegramApiStatusPrompt(db, { ...pin, privateApiStatus: false }, event(2400, now, admin)), false);
  assert.equal(await acceptTelegramApiStatusPrompt(db, pin, event(2500, now)), false);
  const adminPrompt = await sendPrompt(2600, admin);
  const cancelled = await acceptTelegramApiStatusReply(db, pin, { ...event(3700, now, admin), kind: "reply", promptMessageId: adminPrompt, text: "/cancel" });
  assert.ok(cancelled && cancelled.rows.length === 0);
  await runTelegramApiStatus(db, pin, provider, providerPin, cancelled);
  await reconcileTelegramApiStatus(db, pin);
  assert.equal(rpc, 1, "administrator cancellation never dispatches credentials");
  assert.equal(await db.prepare("SELECT row_one FROM telegram_api_status WHERE receipt_id=?").bind(cancelled.receiptId).first("row_one"), -5);
});

test("shared router sends utility commands only through explicitly supplied runtime bindings", async (t) => {
  const { db, now, pin } = await database(t);
  const request = (id: number, text: string) => new Request("https://fixture.invalid/telegram/webhook", {
    method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
    body: JSON.stringify(update(event(id, now), text)),
  });
  assert.equal(await acceptGeneralSharedTelegramCommand(db, pin, request(3000, "/g")), 204);
  const jobs: (() => Promise<void>)[] = [];
  const utilities = { github: true, schedule: async (job: () => Promise<void>) => { jobs.push(job); } };
  assert.equal(await acceptGeneralSharedTelegramCommand(db, pin, request(3001, "/g"), undefined, undefined, undefined, undefined, undefined, false, false, false, utilities), 200);
  assert.equal(jobs.length, 0, "usage does not perform external lookup");
  assert.equal(await acceptGeneralSharedTelegramCommand(db, pin, request(3002, "/g clash"), undefined, undefined, undefined, undefined, undefined, false, false, false, utilities), 200);
  assert.equal(jobs.length, 1);
  assert.equal(await acceptGeneralSharedTelegramCommand(db, pin, request(3003, "/ai"), undefined, undefined, undefined, undefined, undefined, false, false, false, utilities), 204);
});

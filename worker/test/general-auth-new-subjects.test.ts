import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import { acceptGeneralAuthAction, readGeneralAuthAction, renderGeneralAuthActionReply } from "../src/telegram/general-auth-actions.ts";
import { acceptGeneralSharedTelegramCommand } from "../src/telegram/general-auth-shared.ts";
import type { GeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { renderTelegramHelp } from "../src/telegram/command-catalog.ts";

// Exercise the Worker's native constant-time comparison through Node's equivalent.
const oldComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");
Object.defineProperty(crypto.subtle, "timingSafeEqual", { configurable: true,
  value: (received: ArrayBuffer, expected: ArrayBuffer) => timingSafeEqual(new Uint8Array(received), new Uint8Array(expected)) });
after(() => {
  if (oldComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", oldComparison);
  else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
});

const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
let db: D1Database;
const now = () => Math.floor(Date.now() / 1000);
before(async () => {
  db = await runtime.getD1Database("DB");
  await db.prepare(`CREATE TABLE subs_bot_schema_migrations
    (position INTEGER PRIMARY KEY,name TEXT NOT NULL,sha256 TEXT NOT NULL,mode TEXT NOT NULL) STRICT`).run();
  const directory = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
});
after(() => runtime.dispose());

async function fixture(botId: string) {
  const stamp = now();
  const admin = `${botId}1`, member = `${botId}2`, otherAdmin = `${botId}3`, target = `${botId}4`;
  const pin: GeneralTelegramPin = { botId, botUsername: "fixture_authorization_bot", botToken: `${botId}:${"a".repeat(35)}`,
    webhookSecret: "fixture-auth-secret", generation: 1, releaseRevision: "a".repeat(40), activationSha256: "b".repeat(64),
    cutoverAt: stamp - 1200, sharedOutbox: true, privateManagement: true, privateFormats: false, privateTemp: false,
    privateDocument: false, privateProvider: false, privateClaims: false, privateShareCreation: false,
    privateAggregate: false, privateSelected: false, privateShort: false, privateAuthorization: true };
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy(bot_id,generation,release_revision,activation_sha256,cutover_at,active) VALUES(?,?,?,?,?,1)")
      .bind(botId, 1, pin.releaseRevision, pin.activationSha256, pin.cutoverAt),
    ...[[admin, "admin"], [otherAdmin, "admin"], [member, "member"]].map(([actor, role]) =>
      db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,1,?,?)").bind(botId, 1, actor, pin.cutoverAt, role)),
  ]);
  function update(id: number, text: string, actor = admin, date = stamp, group = false) {
    return { update_id: id, message: { message_id: id, date, text, from: { id: Number(actor), is_bot: false },
      chat: { id: group ? -100100 : Number(actor), type: group ? "group" : "private" },
      entities: [{ type: "bot_command", offset: 0, length: text.split(/\s/u)[0].length }] } };
  }
  async function action(id: number, text: string, actor = admin, date = stamp, selected = pin) {
    const parsed = readGeneralAuthAction(selected, update(id, text, actor, date), id);
    assert.ok(parsed);
    return acceptGeneralAuthAction(db, selected, parsed);
  }
  async function webhook(id: number, text: string, actor = admin, group = false, selected = pin) {
    return payload(update(id, text, actor, stamp, group), selected);
  }
  async function payload(value: object, selected = pin) {
    return acceptGeneralSharedTelegramCommand(db, selected, new Request("https://synthetic.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify(value),
    }));
  }
  const state = (actor = target) => db.prepare(`SELECT revision,role,effective_at AS effectiveAt FROM telegram_general_actors
    WHERE bot_id=? AND generation=1 AND actor_id=? ORDER BY revision DESC LIMIT 1`)
    .bind(botId, actor).first<{ revision: number; role: string; effectiveAt: number }>();
  const rows = () => db.prepare("SELECT count(*) AS n FROM telegram_general_actors WHERE bot_id=? AND generation=1 AND actor_id=?")
    .bind(botId, target).first<number>("n");
  const result = (id: number) => db.prepare(`SELECT auth.result,auth.revision,auth.target_id AS target FROM telegram_general_auth_actions AS auth
    JOIN telegram_inbox AS inbox USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(botId, id).first<{ result: string; revision: number | null; target: string }>();
  async function settle() {
    await db.prepare(`UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL
      WHERE receipt_id IN (SELECT receipt_id FROM telegram_inbox WHERE bot_id=?)`).bind(botId).run();
  }
  return { pin, admin, member, otherAdmin, target, stamp, update, action, webhook, payload, state, rows, result, settle };
}

test("synthetic legacy reply-target selection retains numeric precedence, canonical IDs and the current-admin gate", async () => {
  const f = await fixture("960800");
  const replied = (id: number, text: string, target: unknown = Number(f.target), actor = f.admin) => {
    const value = f.update(id, text, actor);
    return { ...value, message: { ...value.message, reply_to_message: { message_id: 1, date: f.stamp - 10,
      chat: value.message.chat, from: { id: target, is_bot: false }, text: "Synthetic quoted message" } } };
  };
  assert.equal(await f.payload(replied(801, "/auth add")), 200);
  assert.equal((await f.state())?.role, "member");
  assert.ok((await f.state())!.effectiveAt >= f.stamp + 60);
  assert.equal(await f.payload(replied(802, "/auth remove")), 200);
  assert.equal((await f.state())?.role, "denied");
  await f.settle();
  const explicit = readGeneralAuthAction(f.pin, replied(803, `/auth add ${f.target}`, Number(f.otherAdmin)), 803);
  assert.ok(explicit && explicit.action === "auth-add");
  assert.equal(explicit.targetId, f.target, "a quoted sender cannot override an explicit canonical ID");
  for (const text of ["/auth add 00", "/auth add +1", "/auth add 1 extra"]) {
    assert.equal(readGeneralAuthAction(f.pin, replied(804, text), 804), null, "invalid arguments never fall back to the quote");
  }
  for (const target of [true, "9608004", 0, -1, 2 ** 52, 1.5]) {
    assert.equal(readGeneralAuthAction(f.pin, replied(805, "/auth add", target), 805), null);
  }
  assert.equal(await f.payload(replied(806, "/auth add", Number(f.target), f.member)), 204);
  assert.equal((await f.state())?.role, "denied");
  const full = { ...f.pin, isolationWindow: { profile: "full-v1" as const, adminId: f.admin, memberId: f.member } };
  const outside = readGeneralAuthAction(full, replied(807, "/auth add"), 807);
  assert.ok(outside);
  assert.equal(await acceptGeneralAuthAction(db, full, outside), 204, "the fixed full window does not enroll a quoted outside subject");
  let protectedId = 808;
  for (const target of [f.pin.botId, f.admin, f.otherAdmin]) {
    const id = protectedId++;
    const selected = readGeneralAuthAction(f.pin, replied(id, "/auth remove", Number(target)), id);
    assert.ok(selected);
    assert.equal(await acceptGeneralAuthAction(db, f.pin, selected), 200);
    assert.equal((await f.result(id))?.result, "unavailable");
    await f.settle();
  }
  assert.equal((await f.state(f.admin))?.role, "admin");
  assert.equal((await f.state(f.otherAdmin))?.role, "admin");
});

test("an administrator can enroll a new member once and the new grant retains the activation hold", async () => {
  const f = await fixture("960100");
  assert.equal(await f.webhook(101, `/auth add ${f.target}`), 200);
  const first = await f.state();
  assert.equal(first?.revision, 1);
  assert.equal(first?.role, "member");
  assert.ok(first && first.effectiveAt >= f.stamp + 60);
  assert.equal(await f.webhook(101, `/auth add ${f.target}`), 204);
  assert.equal(await f.rows(), 1);
  assert.equal(await f.action(102, `/auth add ${f.target}`), 200);
  assert.equal((await f.result(102))?.result, "unchanged");
  assert.deepEqual(await f.state(), first);
  assert.equal(renderGeneralAuthActionReply([{ result: "changed", targetId: f.target, current: 1 }], "auth-add"), `用户 ${f.target}：已授权。`);
});

test("concurrent first grants create one revision and an older revoke cannot replace a newer grant", async () => {
  const f = await fixture("960200");
  assert.deepEqual(await Promise.all([f.action(202, `/auth add ${f.target}`), f.action(203, `/auth add ${f.target}`, f.otherAdmin)]), [200, 200]);
  assert.equal(await f.rows(), 1);
  assert.equal((await f.state())?.role, "member");
  assert.equal(await f.action(201, `/auth remove ${f.target}`), 200);
  assert.equal((await f.result(201))?.result, "stale");
  assert.equal((await f.state())?.role, "member");
});

test("a first revoke records default denial and fences a delayed earlier enrollment", async () => {
  const f = await fixture("960300");
  assert.equal(await f.action(302, `/auth remove ${f.target}`), 200);
  assert.equal((await f.state())?.role, "denied");
  assert.equal((await f.state())?.revision, 1);
  assert.equal(await f.action(301, `/auth add ${f.target}`, f.otherAdmin), 200);
  assert.equal((await f.result(301))?.result, "stale");
  assert.equal((await f.state())?.role, "denied");
  assert.equal(await f.action(303, `/auth add ${f.target}`), 200);
  assert.equal((await f.state())?.revision, 2);
  assert.equal((await f.state())?.role, "member");
  assert.ok((await f.state())!.effectiveAt >= f.stamp + 60);
});

test("parallel first grant and revoke settle to the newer command regardless of request arrival order", async () => {
  const f = await fixture("960400");
  assert.deepEqual(await Promise.all([f.action(401, `/auth add ${f.target}`), f.action(402, `/auth remove ${f.target}`, f.otherAdmin)]), [200, 200]);
  assert.equal((await f.state())?.role, "denied");
  const latest = await f.state();
  await f.settle();
  assert.equal(await f.action(401, `/auth add ${f.target}`), 204);
  assert.deepEqual(await f.state(), latest);
});

test("ordinary users, groups, stale policy pins and inactive generations cannot enroll a subject", async () => {
  const f = await fixture("960500");
  assert.equal(await f.webhook(501, `/auth add ${f.target}`, f.member), 204);
  assert.equal(await f.webhook(502, `/auth add ${f.target}`, f.admin, true), 204);
  assert.equal(await f.action(503, `/auth add ${f.target}`, f.admin, f.pin.cutoverAt), 204);
  assert.equal(await f.action(504, `/auth add ${f.target}`, f.admin, f.stamp, { ...f.pin, activationSha256: "c".repeat(64) }), 204);
  assert.equal(await f.action(505, `/auth add ${f.target}`, f.admin, f.stamp, { ...f.pin, generation: 2 }), 204);
  assert.equal(await f.rows(), 0);
  await db.prepare("UPDATE telegram_general_policy SET active=0 WHERE bot_id=?").bind(f.pin.botId).run();
  assert.equal(await f.action(506, `/auth add ${f.target}`), 204);
  assert.equal(await f.rows(), 0);
});

test("commands protect the bot, the acting administrator and every current administrator", async () => {
  const f = await fixture("960600");
  let id = 601;
  for (const target of [f.pin.botId, f.admin, f.otherAdmin]) {
    for (const verb of ["add", "remove"]) {
      assert.equal(await f.action(id, `/auth ${verb} ${target}`), 200);
      assert.equal((await f.result(id++))?.result, "unavailable");
      await f.settle();
    }
  }
  assert.equal((await f.state(f.admin))?.role, "admin");
  assert.equal((await f.state(f.otherAdmin))?.role, "admin");
  assert.equal(await f.state(f.pin.botId), null);
  assert.equal(await f.rows(), 0);
});

test("new enrollment is scoped to this Bot and generation and never rewrites another Bot's history", async () => {
  const f = await fixture("960700");
  const foreign = await fixture("960701");
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,2,?,1,?,'admin')")
    .bind(f.pin.botId, f.target, f.pin.cutoverAt).run();
  await db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,1,?,'admin')")
    .bind(foreign.pin.botId, f.target, foreign.pin.cutoverAt).run();
  assert.equal(await f.action(701, `/auth add ${f.target}`), 200);
  assert.equal((await f.state())?.role, "member");
  assert.equal(await db.prepare("SELECT role FROM telegram_general_actors WHERE bot_id=? AND generation=2 AND actor_id=?")
    .bind(f.pin.botId, f.target).first<string>("role"), "admin");
  assert.equal(await db.prepare("SELECT role FROM telegram_general_actors WHERE bot_id=? AND generation=1 AND actor_id=?")
    .bind(foreign.pin.botId, f.target).first<string>("role"), "admin");
  assert.equal(await foreign.rows(), 0);
  assert.equal(await f.webhook(702, `/auth add ${f.target}`, f.target), 204, "a member cannot turn its new grant into administration");
});

test("help describes new enrollment only on the general administrator path", () => {
  const general = renderTelegramHelp({ privateChat: true, role: "admin", features: { management: true, authorization: true } });
  assert.ok(general.includes("/auth add 用户ID 新增或恢复授权"));
  assert.ok(general.includes("/auth remove 用户ID 撤销用户授权"));
  const isolated = renderTelegramHelp({ privateChat: true, role: "admin", features: {
    management: true, authorization: true, authorizationScope: "fixed", authorizationMemberId: "1002" } });
  assert.ok(isolated.includes("/auth add 1002 授权固定测试用户"));
  assert.doesNotMatch(isolated, /新增或恢复/u);
  assert.doesNotMatch(renderTelegramHelp({ privateChat: true, role: "member", features: { authorization: true } }), /\/auth/u);
});

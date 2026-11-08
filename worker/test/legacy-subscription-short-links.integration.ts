import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { LEGACY_SUBSCRIPTION_SHORT_MIGRATION, LEGACY_SUBSCRIPTION_SHORT_SHA256 } from "../src/short-links.ts";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const policy: TelegramPolicy = {
  botId: "78101", botUsername: "Fixture_Legacy_Short_Bot", adminId: "78102", memberId: "78103", groupId: "-10078104",
  botToken: "78101:synthetic-token", webhookSecret: "synthetic-legacy-short-secret",
};
const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const code = (value: number) => "compat_" + String(value).padStart(5, "0");
const external = "https://example.com/short-fixture?next=%2Fproject#anchor";
const share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#legacy-short-fixture";
type Send = { chat_id: string; text: string; reply_parameters: { message_id: number }; link_preview_options: unknown };

async function withFixture(serve: boolean, verify: (setup: Awaited<ReturnType<typeof fixture>>) => Promise<void>) {
  const testFixture = await fixture(serve);
  try {
    await verify(testFixture);
  } finally {
    await testFixture.runtime.dispose();
  }
}

async function fixture(serve: boolean) {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"));
  assert.equal(sha(script), manifest.bundleSha256);
  const sent: Send[] = [];
  const runtime = new Miniflare({
    modules: true, script: script.toString("utf8"), compatibilityDate: manifest.compatibilityDate,
    d1Databases: ["DB"], r2Buckets: ["NODES"],
    bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy),
      ...(serve ? { LEGACY_SUBSCRIPTION_SHORTS: "1" } : {}) },
    outboundService: async (request: Request) => {
      assert.equal(request.method, "POST");
      assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
      const body = await request.json() as Send;
      assert.deepEqual(body.link_preview_options, { is_disabled: true });
      assert.ok(body.chat_id === policy.adminId || body.chat_id === policy.memberId);
      sent.push(body);
      return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(body.chat_id) } } });
    },
  });
  try {
    const db = await runtime.getD1Database("DB");
    const bucket = await runtime.getR2Bucket("NODES");
    const migrations = manifest.migrations as Array<{ name: string; sha256: string }>;
    const compatibility = migrations.find(({ name }) => name === LEGACY_SUBSCRIPTION_SHORT_MIGRATION);
    assert.ok(compatibility);
    assert.equal(compatibility.sha256, LEGACY_SUBSCRIPTION_SHORT_SHA256);
    async function apply(migration: (typeof migrations)[number]) {
      const bytes = await readFile(join(directory!, migration.name));
      assert.equal(sha(bytes), migration.sha256);
      await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
    }
    for (const migration of migrations) if (migration !== compatibility) await apply(migration);
    await db.prepare("CREATE TABLE subs_bot_schema_migrations (position INTEGER, name TEXT PRIMARY KEY, sha256 TEXT, mode TEXT)").run();
    const empty = migrations.find(({ name }) => name === "0026_legacy_empty_subscription_exports.sql");
    assert.ok(empty);
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (26,?,?,'applied')").bind(empty.name, empty.sha256).run();
    const sub = await createSubscription(db, { ownerId: policy.memberId, name: "Owned short fixture", sourceUrl: "uploaded://fixture" });
    const target = { id: sub.id, ownerId: sub.ownerId };
    assert.equal(await publishNodeSnapshot(db, bucket, { ...target, expectedGeneration: 0, expectedLifecycleRevision: 0 },
      [{ share }]), true);
    const now = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
    assert.ok(now);
    const request = (path: string, method = "GET") => runtime.dispatchFetch("https://short.fixture.invalid" + path, {
      method, redirect: "manual",
    });
    const get = (value: number, method = "GET") => request(`/s/${code(value)}`, method);
    async function redirect(value: number, location: string, method = "GET") {
      const response = await get(value, method);
      assert.equal(response.status, 302);
      assert.equal(response.headers.get("Location"), location);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
      assert.equal(await response.text(), "");
    }
    const install = () => apply(compatibility);
    const register = (digest = compatibility.sha256, mode = "applied") => db.prepare(
      `INSERT INTO subs_bot_schema_migrations VALUES (29,?,?,?)
        ON CONFLICT(name) DO UPDATE SET sha256=excluded.sha256,mode=excluded.mode`)
      .bind(compatibility.name, digest, mode).run();
    const compat = (value: number, format: string, id = sub.id, owner = sub.ownerId, bot = policy.botId, token = sub.token) =>
      db.prepare(`INSERT INTO legacy_subscription_short_links
        (code_sha256,bot_id,owner_id,subscription_id,token_sha256,format,created_at) VALUES (?,?,?,?,?,?,?)`)
        .bind(sha(code(value)), bot, owner, id, sha(token), format, now - 100).run();
    const normal = (value: number, revoked = false) => db.prepare(`INSERT INTO normal_short_links
      (code_sha256,code_length,bot_id,owner_id,target_url,created_at,revoked_at) VALUES (?,12,?,?,?,?,?)`)
      .bind(sha(code(value)), policy.botId, policy.memberId, revoked ? null : external, now - 100, revoked ? now : null).run();
    const aggregate = (value: number) => db.prepare(`INSERT INTO aggregate_links (code_sha256,owner_id,kind,bot_id)
      VALUES (?,?,'all',?)`).bind(sha(code(value)), sub.ownerId, policy.botId).run();
    const revoke = (updateId: number, value: number, actorId = policy.memberId, chatId = actorId, date = now - 5,
      secret = policy.webhookSecret) => runtime.dispatchFetch("https://short.fixture.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
      body: JSON.stringify({ update_id: updateId, message: {
        text: `/short revoke ${code(value)}`, message_id: updateId, date, from: { id: Number(actorId), is_bot: false },
        chat: { id: Number(chatId), type: chatId === policy.groupId ? "supergroup" : "private" },
        entities: [{ type: "bot_command", offset: 0, length: 6 }],
      } }),
    });
    async function reply(id: number, text: string, actor = policy.memberId) {
      for (let i = 0; i < 100; i++) {
        const state = await db.prepare(`SELECT reply.state FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
          WHERE inbox.bot_id=? AND inbox.update_id=?`).bind(policy.botId, id).first("state");
        if (state === "sent") {
          const send = sent.find((item) => item.reply_parameters.message_id === id);
          assert.equal(send?.chat_id, actor);
          assert.equal(send?.text, text);
          return;
        }
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      assert.fail("Expected compatibility revoke reply did not settle.");
    }
    return { runtime, db, sub, target, now, sent, request, get, redirect, install, register, compat, normal, aggregate, revoke, reply };
  } catch (error) {
    await runtime.dispose();
    throw error;
  }
}

test("emitted Worker preserves first-party legacy short destinations and blocks all ambiguous digests",
  { timeout: 60_000 }, () => withFixture(true, async (f) => {
    await f.normal(1);
    await f.aggregate(2);
    await f.redirect(1, external);
    await f.redirect(2, `/agg/${code(2)}/clash`);
    assert.equal((await f.get(3)).status, 404);

    await f.install();
    await f.compat(3, "mixed");
    await f.compat(4, "");
    await f.compat(5, "sing-box");
    await f.compat(6, "quantumultx");
    await f.compat(7, "clash", f.sub.id, policy.adminId);
    await f.compat(8, "clash", f.sub.id, f.sub.ownerId, policy.botId, "changed-fixture-token");
    await f.compat(1, "clash");
    await f.compat(2, "clash");
    await f.normal(9, true);
    await f.compat(9, "clash");
    await assert.rejects(f.compat(10, "../../health"));
    assert.equal((await f.get(3)).status, 404, "a table without exact ledger is reservation only");
    assert.equal((await f.get(1)).status, 404);
    assert.equal((await f.get(2)).status, 404);
    assert.equal((await f.request(`/agg/${code(2)}/base64`)).status, 404);

    await f.register("0".repeat(64));
    assert.equal((await f.get(3)).status, 404);
    await f.register(LEGACY_SUBSCRIPTION_SHORT_SHA256, "adopted");
    assert.equal((await f.get(3)).status, 404);
    await f.register();
    await f.redirect(3, `/sub/${f.sub.token}/mixed`);
    await f.redirect(3, `/sub/${f.sub.token}/mixed`, "HEAD");
    await f.redirect(4, `/sub/${f.sub.token}`);
    await f.redirect(5, `/sub/${f.sub.token}/sing-box`);
    await f.redirect(6, `/sub/${f.sub.token}/quantumultx`);
    assert.equal((await f.request(`/s/${code(3).toUpperCase()}`)).status, 404);
    for (const value of [1, 2, 7, 8, 9, 10]) assert.equal((await f.get(value)).status, 404);
    assert.equal((await f.request(`/agg/${code(2)}/base64`, "HEAD")).status, 404);
    const follow = await f.request(`/sub/${f.sub.token}/mixed`);
    assert.equal(follow.status, 200);
    assert.equal(await follow.text(), Buffer.from(share).toString("base64"));

    const empty = await createSubscription(f.db, { ownerId: policy.memberId, name: "Empty", sourceUrl: "uploaded://empty" });
    await f.db.prepare("INSERT INTO legacy_empty_subscription_exports VALUES (?,?,?)").bind(empty.id, empty.ownerId, sha(empty.token)).run();
    await f.compat(11, "v2ray", empty.id, empty.ownerId, policy.botId, empty.token);
    await f.redirect(11, `/sub/${empty.token}/v2ray`);
    const emptyBody = await f.request(`/sub/${empty.token}/v2ray`);
    assert.equal(emptyBody.status, 200);
    assert.equal(await emptyBody.text(), "");

    assert.equal(await trashOwnedSubscription(f.db, { ...f.target, expectedLifecycleRevision: 0 }), true);
    assert.equal((await f.get(3)).status, 404);
    assert.equal(await restoreOwnedSubscription(f.db, { ...f.target, expectedLifecycleRevision: 1 }), true);
    await f.redirect(3, `/sub/${f.sub.token}/mixed`);
    await f.db.prepare("UPDATE subscriptions SET token=? WHERE id=?").bind("fixture-token-replaced", f.sub.id).run();
    assert.equal((await f.get(3)).status, 404);
    assert.deepEqual(f.sent, []);
  }));

test("emitted Worker defaults legacy serving off and authorizes exact tombstoning independently of serving",
  { timeout: 60_000 }, () => withFixture(false, async (f) => {
    await f.install();
    await f.register();
    await f.compat(20, "clash");
    await f.compat(21, "clash", f.sub.id, f.sub.ownerId, "78999");
    await f.compat(22, "clash");
    await f.aggregate(22);
    await f.normal(23);
    assert.equal((await f.get(20)).status, 404);
    assert.equal((await f.get(22)).status, 404);
    assert.equal((await f.request(`/agg/${code(22)}/base64`)).status, 404);
    await f.redirect(23, external);

    assert.equal((await f.revoke(1, 20, policy.memberId, policy.groupId)).status, 204);
    assert.equal((await f.revoke(1, 20, policy.memberId, policy.memberId, f.now - 5, "wrong-secret")).status, 401);
    assert.equal((await f.revoke(2, 20, policy.adminId)).status, 200);
    await f.reply(2, "没有可撤销的短链。", policy.adminId);
    assert.equal((await f.revoke(3, 21)).status, 200);
    await f.reply(3, "没有可撤销的短链。");
    assert.equal((await f.revoke(4, 22)).status, 200);
    await f.reply(4, "没有可撤销的短链。");
    await f.db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,1)")
      .bind(policy.botId, policy.memberId, f.now - 10).run();
    assert.equal((await f.revoke(5, 20, policy.memberId, policy.memberId, f.now - 10)).status, 200);
    assert.equal(await f.db.prepare("SELECT 1 AS found FROM telegram_inbox WHERE update_id=5").first("found"), null);

    assert.equal((await f.revoke(6, 20)).status, 200);
    await f.reply(6, "短链已撤销。");
    const row = await f.db.prepare(`SELECT revoked_at AS revokedAt,subscription_id AS subscriptionId,
      token_sha256 AS tokenSha256,format FROM legacy_subscription_short_links WHERE code_sha256=?`)
      .bind(sha(code(20))).first<{ revokedAt: number; subscriptionId: number | null; tokenSha256: string | null; format: string | null }>();
    assert.ok(row && row.revokedAt >= f.now);
    assert.deepEqual([row.subscriptionId, row.tokenSha256, row.format], [null, null, null]);
    assert.equal((await f.revoke(6, 20)).status, 200);
    assert.equal((await f.revoke(7, 20)).status, 200);
    await f.reply(7, "没有可撤销的短链。");
    assert.equal(f.sent.filter((item) => item.reply_parameters.message_id === 6).length, 1);
    assert.equal((await f.get(20)).status, 404);
    // A tombstone remains a reservation even if a conflicting native link is inserted.
    await f.aggregate(20);
    assert.equal((await f.request(`/agg/${code(20)}/base64`)).status, 404);
    await f.normal(20);
    assert.equal((await f.get(20)).status, 404);
    for (const value of [21, 22]) assert.equal(await f.db.prepare("SELECT revoked_at FROM legacy_subscription_short_links WHERE code_sha256=?")
      .bind(sha(code(value))).first("revoked_at"), null);
    const durable = JSON.stringify((await f.db.prepare("SELECT * FROM telegram_short_link_actions").all()).results);
    assert.ok(!durable.includes(code(20)) && !durable.includes(f.sub.token));
  }));

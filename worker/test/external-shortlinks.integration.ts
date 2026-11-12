import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";
import { wrapAuthorizedLocalShortlink } from "../src/telegram/external-shortlinks.ts";

const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const token = "sl_" + "b".repeat(64);
const policy = { botId: "75311", botUsername: "fixture_external_bot", adminId: "75312", memberId: "75313", groupId: "-75314",
  botToken: "75311:synthetic-token", webhookSecret: "synthetic-external-webhook" };

test("emitted Worker uses named RPC, preserves one local/external mapping on redelivery, and revokes local access", { timeout: 90_000 }, async (t) => {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert.ok(directory);
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
  const script = await readFile(join(directory, "index.js"), "utf8");
  assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
  const sent: { text: string; chat_id: string }[] = [];
  const d1Databases = { DB: "external-shortlink-fixture" };
  const runtime = new Miniflare({ workers: [
    { name: "app", modules: true, script, compatibilityDate: manifest.compatibilityDate, d1Databases, r2Buckets: ["NODES"],
      serviceBindings: { SHORTLINK: { name: "shortlink", entrypoint: "ShortlinkService" } },
      bindings: { BUILD_REVISION: manifest.revision, TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_EXTERNAL_SHORTLINKS: "1",
        SHORTLINK_BUSINESS_TOKEN: token, TELEGRAM_AGGREGATE_KEY: Buffer.alloc(32, 0x24).toString("base64url") },
      outboundService: async (request: Request) => {
        // The RPC metadata URL must never become an outbound HTTP call.
        assert.equal(request.url, `https://api.telegram.org/bot${policy.botToken}/sendMessage`);
        const body = await request.json() as (typeof sent)[number];
        assert.equal(body.chat_id, policy.memberId);
        assert.doesNotMatch(body.text, /synthetic-source-secret|Bearer|sl_bbbb/u);
        sent.push(body);
        return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(body.chat_id) } } });
      } },
    { name: "shortlink", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases,
      script: String.raw`import { WorkerEntrypoint } from 'cloudflare:workers';
        export class ShortlinkService extends WorkerEntrypoint {
          async createShortlink(request) {
            const body=await request.json(), key=request.headers.get('Idempotency-Key');
            if(request.url!=='https://link-admin.lily.lat/api/shorten' || request.method!=='POST'
              || request.headers.get('Authorization')!==${JSON.stringify("Bearer " + token)}
              || body.domain!=='gfw.mom' || !/^https:\/\/subs-bot-cf-dev-01.lilyya.workers.dev\/s\/[A-Za-z0-9_-]+$/.test(body.url)
              || Object.keys(body).sort().join(',')!=='domain,url' || !/^[a-f0-9-]{36}$/.test(key)) throw new Error('Invalid fixture RPC');
            await this.env.DB.prepare('INSERT INTO fixture_external_calls(operation_id,target) VALUES (?,?)').bind(key,body.url).run();
            return Response.json({ok:true,data:{domain:'gfw.mom',slug:'FixtureOuter',short_url:'https://gfw.mom/FixtureOuter'}},{status:201});
          }
        }
        export default {fetch(){throw new Error('Public HTTP is prohibited')}};` },
  ] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB", "app");
  const app = await runtime.getWorker("app");
  for (const entry of manifest.migrations) {
    const sql = await readFile(join(directory, entry.name), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((part) => db.prepare(part)));
    await recordTempFixtureMigration(db, entry);
  }
  await db.prepare("CREATE TABLE fixture_external_calls(operation_id TEXT,target TEXT)").run();
  const update = (id: number, text: string) => ({ update_id: id, message: { message_id: id, date: Math.floor(Date.now() / 1000),
    from: { id: Number(policy.memberId), is_bot: false }, chat: { id: Number(policy.memberId), type: "private" }, text,
    entities: [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] } });
  const post = (body: unknown) => app.fetch(origin + "/telegram/webhook", { method: "POST", headers: { "Content-Type": "application/json",
    "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret }, body: JSON.stringify(body) });
  async function waitFor(count: number) {
    for (let attempt = 0; sent.length < count && attempt < 100; attempt++) await new Promise((resolve) => setTimeout(resolve, 50));
    assert.equal(sent.length, count);
  }
  const issue = update(1, "/short https://example.com/synthetic-source-secret");
  assert.equal((await post(issue)).status, 200);
  await waitFor(1);
  assert.match(sent[0].text, /https:\/\/gfw\.mom\/FixtureOuter/u);
  const code = sent[0].text.match(/\/short revoke ([A-Za-z0-9_-]+)/u)?.[1];
  assert.ok(code);
  assert.equal((await post(issue)).status, 200);
  const calls = await db.prepare("SELECT operation_id,target FROM fixture_external_calls").all<{ operation_id: string; target: string }>();
  assert.equal(calls.results.length, 1);
  assert.equal(calls.results[0].target, origin + "/s/" + code);
  assert.doesNotMatch(calls.results[0].operation_id, /75313|synthetic|http/u);
  assert.equal((await app.fetch(origin + "/s/" + code, { redirect: "manual" })).status, 302);
  assert.equal((await post(update(2, "/short revoke " + code))).status, 200);
  await waitFor(2);
  assert.equal((await app.fetch(calls.results[0].target, { redirect: "manual" })).status, 404);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_external_shortlinks").first<number>("n"), 1);

  const concurrentLocal = origin + "/s/" + "z".repeat(22);
  let rpcCalls = 0;
  const rpc = { token, service: { async createShortlink() { rpcCalls++; return Response.json({ ok: true,
    data: { domain: "gfw.mom", slug: "Concurrent", short_url: "https://gfw.mom/Concurrent" } }, { status: 201 }); } } };
  const results = await Promise.all(Array.from({ length: 5 }, () => wrapAuthorizedLocalShortlink(db, policy.botId,
    concurrentLocal, origin, rpc, async () => true)));
  assert.equal(rpcCalls, 1);

  const retryLocal = origin + "/s/" + "t".repeat(22);
  const retryKeys: string[] = [];
  const transient = { token, service: { async createShortlink(request: Request) {
    retryKeys.push(request.headers.get("Idempotency-Key")!);
    return retryKeys.length === 1 ? new Response(null, { status: 503 }) : Response.json({ ok: true,
      data: { domain: "gfw.mom", slug: "Retried", short_url: "https://gfw.mom/Retried" } }, { status: 201 });
  } } };
  assert.deepEqual(await wrapAuthorizedLocalShortlink(db, policy.botId, retryLocal, origin, transient, async () => true),
    { url: "https://gfw.mom/Retried", external: true });
  assert.equal(retryKeys.length, 2);
  assert.equal(new Set(retryKeys).size, 1);
  assert.ok(results.every((value) => value?.url === concurrentLocal || value?.url === "https://gfw.mom/Concurrent"));
  assert.equal((await wrapAuthorizedLocalShortlink(db, policy.botId, concurrentLocal, origin, rpc, async () => true))?.external, true);
  assert.equal(rpcCalls, 1);

  const limitedLocal = origin + "/s/" + "q".repeat(22);
  const keys: string[] = [];
  const limited = { token, service: { async createShortlink(request: Request) {
    keys.push(request.headers.get("Idempotency-Key")!);
    return new Response(null, { status: 429, headers: { "Retry-After": "3600" } });
  } } };
  assert.deepEqual(await wrapAuthorizedLocalShortlink(db, policy.botId, limitedLocal, origin, limited, async () => true),
    { url: limitedLocal, external: false });
  assert.deepEqual(await wrapAuthorizedLocalShortlink(db, policy.botId, limitedLocal, origin, limited, async () => true),
    { url: limitedLocal, external: false });
  assert.equal(keys.length, 1);
  assert.equal(await db.prepare("SELECT retry_at>unixepoch()+3500 AS respected FROM telegram_external_shortlinks WHERE local_sha256=?")
    .bind(createHash("sha256").update(limitedLocal).digest("hex")).first<number>("respected"), 1);
  for (let i = 0; i < 4; i++) {
    await db.prepare("UPDATE telegram_external_shortlinks SET retry_at=0 WHERE local_sha256=?")
      .bind(createHash("sha256").update(limitedLocal).digest("hex")).run();
    assert.deepEqual(await wrapAuthorizedLocalShortlink(db, policy.botId, limitedLocal, origin, limited, async () => true),
      { url: limitedLocal, external: false });
  }
  assert.equal(keys.length, 3);
  assert.equal(new Set(keys).size, 1);
  assert.deepEqual(await wrapAuthorizedLocalShortlink(db, policy.botId, limitedLocal, origin, { token }, async () => true),
    { url: limitedLocal, external: false });

  let allowed = true;
  const revokedLocal = origin + "/s/" + "r".repeat(22);
  const revokeDuringRpc = { token, service: { async createShortlink() {
    allowed = false;
    return Response.json({ ok: true, data: { domain: "gfw.mom", slug: "Revoked", short_url: "https://gfw.mom/Revoked" } }, { status: 201 });
  } } };
  assert.equal(await wrapAuthorizedLocalShortlink(db, policy.botId, revokedLocal, origin, revokeDuringRpc, async () => allowed), null);
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const businessToken = "sl_" + "c".repeat(64);
const sourceSecret = "synthetic-path-source-only";
type Message = { chat_id: string; text: string; reply_parameters: { message_id: number };
  reply_markup?: { inline_keyboard?: { text: string; callback_data: string }[][] } };

for (const lane of ["isolated", "general"] as const) {
  test(`emitted ${lane} normal, aggregate, selected and typed exits retain RPC ownership, local revocation and final fences`,
    { timeout: 90_000 }, async (t) => {
      const directory = process.env.WORKER_TEST_BUNDLE_DIR;
      assert.ok(directory);
      const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8"));
      const script = await readFile(join(directory, "index.js"), "utf8");
      assert.equal(createHash("sha256").update(script).digest("hex"), manifest.bundleSha256);
      const now = Math.floor(Date.now() / 1000);
      const policy = { botId: lane === "isolated" ? "75321" : "75331", botUsername: "fixture_path_bot", adminId: "75322", memberId: "75323",
        groupId: "-75324", botToken: "75321:" + "a".repeat(35), webhookSecret: "synthetic-path-webhook" };
      if (lane === "general") policy.botToken = policy.botId + ":" + "a".repeat(35);
      const generalConfig = { botId: policy.botId, botUsername: policy.botUsername, botToken: policy.botToken,
        webhookSecret: policy.webhookSecret, generation: 1, cutoverAt: now - 100, activationSha256: "a".repeat(64),
        outbox: "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected-short",
        subscriptionShorts: "issue" };
      const sent: { id: number; message: Message }[] = [];
      const d1Databases = { DB: "external-paths" };
      const runtime = new Miniflare({ workers: [
        { name: "app", modules: true, script, compatibilityDate: manifest.compatibilityDate, d1Databases, r2Buckets: ["NODES"],
          serviceBindings: { SHORTLINK: { name: "shortlink", entrypoint: "ShortlinkService" } },
          bindings: { BUILD_REVISION: manifest.revision,
            ...(lane === "isolated" ? { TELEGRAM_ISOLATION_CONFIG: JSON.stringify(policy), TELEGRAM_SUBSCRIPTION_SHORTS: "1" }
              : { TELEGRAM_GENERAL_CONFIG: JSON.stringify(generalConfig) }),
            TELEGRAM_EXTERNAL_SHORTLINKS: "1", SHORTLINK_BUSINESS_TOKEN: businessToken,
            TELEGRAM_AGGREGATE_KEY: Buffer.alloc(32, 0x27).toString("base64url") },
          outboundService: async (request: Request) => {
            assert.equal(request.method, "POST");
            const api = `https://api.telegram.org/bot${policy.botToken}/`;
            if (request.url === api + "answerCallbackQuery") return Response.json({ ok: true, result: true });
            assert.equal(request.url, api + "sendMessage", "RPC metadata must never become a public fetch");
            const message = await request.json() as Message;
            assert.equal(message.chat_id, policy.memberId);
            assert.doesNotMatch(message.text, new RegExp(sourceSecret + "|Bearer|sl_cccc", "u"));
            const id = 1000 + sent.length;
            sent.push({ id, message });
            return Response.json({ ok: true, result: { message_id: id, chat: { id: Number(message.chat_id) } } });
          } },
        { name: "shortlink", modules: true, compatibilityDate: manifest.compatibilityDate, d1Databases,
          script: String.raw`import { WorkerEntrypoint } from 'cloudflare:workers';
            export class ShortlinkService extends WorkerEntrypoint {
              async createShortlink(request) {
                const value=await request.json(), key=request.headers.get('Idempotency-Key');
                if(request.url!=='https://link-admin.lily.lat/api/shorten'||request.method!=='POST'
                  ||request.headers.get('Authorization')!==${JSON.stringify("Bearer " + businessToken)}
                  ||value.domain!=='gfw.mom'||Object.keys(value).sort().join(',')!=='domain,url'
                  ||!/^https:\/\/subs-bot-cf-dev-01.lilyya.workers.dev\/s\/[A-Za-z0-9_-]{22}$/.test(value.url)
                  ||!/^[a-f0-9-]{36}$/.test(key)) throw new Error('Invalid fixture RPC');
                await this.env.DB.prepare('INSERT INTO fixture_rpc_attempts VALUES (?,?)').bind(key,value.url).run();
                const countForKey=await this.env.DB.prepare('SELECT count(*) AS n FROM fixture_rpc_attempts WHERE operation_id=?').bind(key).first('n');
                const control=await this.env.DB.prepare('SELECT mode FROM fixture_rpc_control').first('mode');
                if(control==='transient'&&countForKey===1)return Response.json({ok:false,error:{code:'INTERNAL_ERROR'}},{status:503});
                if(control==='limited')return new Response(null,{status:429,headers:{'Retry-After':'3600'}});
                if(control==='forbidden')return Response.json({ok:false,error:{code:'DOMAIN_FORBIDDEN'}},{status:403});
                let stored=await this.env.DB.prepare('SELECT target,slug FROM fixture_rpc_maps WHERE operation_id=?').bind(key).first();
                let replay=Boolean(stored);
                if(stored&&stored.target!==value.url)throw new Error('Changed idempotent body');
                if(!stored){
                  const count=await this.env.DB.prepare('SELECT count(*) AS n FROM fixture_rpc_maps').first('n');
                  stored={target:value.url,slug:'Outer'+String(count+1)};
                  await this.env.DB.prepare('INSERT INTO fixture_rpc_maps VALUES (?,?,?)').bind(key,stored.target,stored.slug).run();
                }
                if(control==='expire')await this.env.DB.prepare("UPDATE telegram_outbox SET state='uncertain',lease_until=NULL WHERE state='sending'").run();
                return Response.json({ok:true,data:{domain:'gfw.mom',slug:stored.slug,short_url:'https://gfw.mom/'+stored.slug}},
                  {status:replay?200:201,headers:replay?{'Idempotency-Replayed':'true'}:{}});
              }
            }
            export default {fetch(){throw new Error('Public HTTP prohibited')}};` },
      ] });
      t.after(() => runtime.dispose());
      const db = await runtime.getD1Database("DB", "app");
      const bucket = await runtime.getR2Bucket("NODES", "app");
      const app = await runtime.getWorker("app");
      for (const entry of manifest.migrations) {
        const sql = await readFile(join(directory, entry.name), "utf8");
        assert.equal(createHash("sha256").update(sql).digest("hex"), entry.sha256);
        await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((part) => db.prepare(part)));
        await recordTempFixtureMigration(db, entry);
      }
      for (const entry of manifest.migrations) {
        await db.prepare("INSERT OR IGNORE INTO subs_bot_schema_migrations(position,name,sha256,mode) VALUES (?,?,?,'applied')")
          .bind(Number(entry.name.slice(0, 4)), entry.name, entry.sha256).run();
      }
      await db.batch([
        db.prepare("CREATE TABLE fixture_rpc_control(mode TEXT NOT NULL)"),
        db.prepare("INSERT INTO fixture_rpc_control VALUES ('success')"),
        db.prepare("CREATE TABLE fixture_rpc_maps(operation_id TEXT PRIMARY KEY,target TEXT NOT NULL,slug TEXT NOT NULL UNIQUE)"),
        db.prepare("CREATE TABLE fixture_rpc_attempts(operation_id TEXT NOT NULL,target TEXT NOT NULL)"),
      ]);
      if (lane === "general") {
        await db.prepare("INSERT INTO telegram_general_policy VALUES (?,1,?,?,?,1)")
          .bind(policy.botId, manifest.revision, generalConfig.activationSha256, generalConfig.cutoverAt).run();
        for (const [actor, role] of [[policy.adminId, "admin"], [policy.memberId, "member"]]) {
          await db.prepare("INSERT INTO telegram_general_actors VALUES (?,1,?,1,?,?)")
            .bind(policy.botId, actor, generalConfig.cutoverAt, role).run();
        }
      }
      const sub = await createSubscription(db, { ownerId: policy.memberId, name: "Fixture owned subscription",
        sourceUrl: "https://provider.example.invalid/" + sourceSecret });
      assert.equal(await publishNodeSnapshot(db, bucket, { id: sub.id, ownerId: policy.memberId, expectedGeneration: 0,
        expectedLifecycleRevision: 0 }, [{ type: "ss", name: "Synthetic RPC path node",
        share: "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#synthetic" }]), true);
      let sequence = 500;
      const post = (text: string, id = ++sequence) => app.fetch(origin + "/telegram/webhook", { method: "POST",
        headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
        body: JSON.stringify({ update_id: id, message: { message_id: id, date: now, text,
          from: { id: Number(policy.memberId), is_bot: false }, chat: { id: Number(policy.memberId), type: "private" },
          entities: [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }] } }) });
      const callback = (source: { id: number }, ticket: string, actor = policy.memberId, id = ++sequence) => app.fetch(origin + "/telegram/webhook", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": policy.webhookSecret },
        body: JSON.stringify({ update_id: id, callback_query: { id: "synthetic-" + id, from: { id: Number(actor), is_bot: false }, data: ticket,
          message: { message_id: source.id, date: now, from: { id: Number(policy.botId), is_bot: true }, chat: { id: Number(actor), type: "private" } } } }) });
      async function reply(id = sequence) {
        for (let tries = 0; tries < 100; tries++) {
          const found = sent.find(({ message }) => message.reply_parameters?.message_id === id);
          if (found) return found;
          await new Promise((resolve) => setTimeout(resolve, 50));
        }
        assert.fail("Synthetic RPC path reply was not observed.");
      }
      const ticket = (message: Message, contains: string) => {
        const value = message.reply_markup?.inline_keyboard?.flat().find(({ text }) => text.includes(contains))?.callback_data;
        assert.ok(value, "Missing scoped synthetic button.");
        return value;
      };
      async function outerTarget(message: Message) {
        const slug = /https:\/\/gfw\.mom\/(Outer[0-9]+)/u.exec(message.text)?.[1];
        assert.ok(slug, "Expected the external result from named RPC.");
        const result = await db.prepare("SELECT operation_id,target FROM fixture_rpc_maps WHERE slug=?").bind(slug)
          .first<{ operation_id: string; target: string }>();
        assert.ok(result);
        assert.doesNotMatch(result.operation_id, /7532|7533|http|synthetic/u);
        assert.match(result.target, /^https:\/\/subs-bot-cf-dev-01\.lilyya\.workers\.dev\/s\/[A-Za-z0-9_-]{22}$/u);
        return result;
      }
      const mapCount = () => db.prepare("SELECT count(*) AS n FROM fixture_rpc_maps").first<number>("n");
      // Ordinary short links retain a visible owner-scoped local revocation command.
      const normalId = ++sequence;
      assert.equal((await post("/short https://example.com/synthetic", normalId)).status, 200);
      const normal = await reply(normalId);
      const normalMap = await outerTarget(normal.message);
      const normalCode = /\/short revoke ([A-Za-z0-9_-]{22})/u.exec(normal.message.text)?.[1];
      assert.ok(normalCode);
      assert.equal((await post("/short https://example.com/synthetic", normalId)).status, lane === "isolated" ? 200 : 204);
      assert.equal(await mapCount(), 1);
      assert.equal((await app.fetch(normalMap.target, { redirect: "manual" })).status, 302);
      assert.equal((await post("/short revoke " + normalCode)).status, 200);
      await reply();
      assert.equal((await app.fetch(normalMap.target, { redirect: "manual" })).status, 404);
      // Full aggregates re-show the same local code and external operation, then revoke locally.
      assert.equal((await post("/export")).status, 200);
      const aggregate = await reply();
      const aggregateMap = await outerTarget(aggregate.message);
      assert.equal((await post("/export")).status, 200);
      assert.equal((await outerTarget((await reply()).message)).operation_id, aggregateMap.operation_id);
      assert.equal((await post("/export revoke")).status, 200);
      await reply();
      assert.equal((await app.fetch(aggregateMap.target, { redirect: "manual" })).status, 404);
      // Selected aggregates keep their original one-time revoke button after external wrapping.
      assert.equal((await post("/o Fixture")).status, 200);
      const selected = await reply();
      const selectedMap = await outerTarget(selected.message);
      assert.equal((await callback(selected, ticket(selected.message, "撤销此链接"))).status, 200);
      await reply(selected.id);
      assert.equal((await app.fetch(selectedMap.target, { redirect: "manual" })).status, 404);
      // A different actor cannot consume the private search ticket or cause an RPC.
      assert.equal((await post("/s Fixture")).status, 200);
      const search = await reply();
      const detail = ticket(search.message, "详情");
      const beforeSpoof = await mapCount();
      assert.equal((await callback(search, detail, policy.adminId)).status, lane === "isolated" ? 200 : 204);
      assert.equal(await mapCount(), beforeSpoof);
      assert.equal((await callback(search, detail)).status, 200);
      const metadata = await reply(search.id);
      assert.equal((await callback(metadata, ticket(metadata.message, "Clash"))).status, 200);
      const typed = await reply(metadata.id);
      const typedMap = await outerTarget(typed.message);
      const typedCode = /\/short revoke ([A-Za-z0-9_-]{22})/u.exec(typed.message.text)?.[1];
      assert.ok(typedCode, "External typed links must preserve the local revocation operation.");
      assert.equal((await post("/short revoke " + typedCode)).status, 200);
      await reply();
      assert.equal((await app.fetch(typedMap.target, { redirect: "manual" })).status, 404);
      // Domain denial falls back to the same published local link and never claims external success.
      await db.prepare("UPDATE fixture_rpc_control SET mode='forbidden'").run();
      assert.equal((await post("/short https://example.com/fallback")).status, 200);
      const fallback = (await reply()).message;
      assert.match(fallback.text, /外部短链暂不可用，已使用本地链接/u);
      assert.doesNotMatch(fallback.text, /https:\/\/gfw\.mom/u);
      const local = /https:\/\/subs-bot-cf-dev-01\.lilyya\.workers\.dev\/s\/[A-Za-z0-9_-]{22}/u.exec(fallback.text)?.[0];
      assert.ok(local);
      assert.equal((await app.fetch(local, { redirect: "manual" })).status, 302);
      // A bounded retry actually occurs in the invocation, with the persisted key and identical local body.
      await db.prepare("UPDATE fixture_rpc_control SET mode='transient'").run();
      assert.equal((await post("/short https://example.com/transient")).status, 200);
      const transient = await outerTarget((await reply()).message);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM fixture_rpc_attempts WHERE operation_id=? AND target=?")
        .bind(transient.operation_id, transient.target).first<number>("n"), 2);
      // A wait beyond the invocation budget produces one truthful local fallback, without an early retry.
      await db.prepare("UPDATE fixture_rpc_control SET mode='limited'").run();
      const attemptsBeforeLimit = await db.prepare("SELECT count(*) AS n FROM fixture_rpc_attempts").first<number>("n");
      assert.equal((await post("/short https://example.com/limited")).status, 200);
      const limited = (await reply()).message;
      assert.match(limited.text, /外部短链暂不可用，已使用本地链接/u);
      assert.doesNotMatch(limited.text, /https:\/\/gfw\.mom/u);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM fixture_rpc_attempts").first<number>("n"), attemptsBeforeLimit! + 1);
      // Expiring the aggregate sending lease inside RPC must suppress the final Telegram send.
      await db.prepare("UPDATE fixture_rpc_control SET mode='expire'").run();
      const sendCount = sent.length;
      const mapsBeforeExpiry = await mapCount();
      const expireId = ++sequence;
      assert.equal((await post("/export", expireId)).status, 200);
      for (let tries = 0; tries < 100; tries++) {
        const state = await db.prepare("SELECT state FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id=? AND update_id=?")
          .bind(policy.botId, expireId).first<string>("state");
        if (state === "uncertain" || state === "failed") break;
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      await new Promise((resolve) => setTimeout(resolve, 100));
      assert.equal(await mapCount(), mapsBeforeExpiry! + 1, "The expiry hook must have run inside a successful RPC.");
      assert.equal(await db.prepare("SELECT state FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id=? AND update_id=?")
        .bind(policy.botId, expireId).first<string>("state"), "uncertain");
      assert.equal(sent.length, sendCount);
      assert.equal(sent.some(({ message }) => message.reply_parameters.message_id === expireId), false);
    });
}

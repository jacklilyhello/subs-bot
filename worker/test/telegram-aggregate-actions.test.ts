import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";
import { Miniflare } from "miniflare";
import { getAggregateNodeSource, hasAggregateLink } from "../src/aggregate.ts";
import { createSubscription, publishNodeSnapshot } from "../src/storage.ts";
import {
  acceptTelegramAggregate, parseTelegramAggregateKey, resolveTelegramAggregateCode,
  TELEGRAM_AGGREGATE_MARKER, TELEGRAM_AGGREGATE_ORIGIN,
} from "../src/telegram/aggregate-actions.ts";
import { drainTelegramReplies } from "../src/telegram/delivery.ts";
import { acceptTelegramDocumentJob } from "../src/telegram/document-jobs.ts";
import { acceptTelegramPath } from "../src/telegram/path-management.ts";
import { beginTelegramAggregateLinkReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import type { TelegramAggregateUpdate, TelegramPolicy } from "../src/telegram/protocol.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

const migrationDir = new URL("../migrations/", import.meta.url);
const encodedKey = Buffer.alloc(32, 0x47).toString("base64url");
const fixtureDate = Math.floor(Date.now() / 1000) - 5;
const sampleShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388";
const runtime = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default { fetch() { return new Response(null); } };" });
let db: D1Database;
let bucket: R2Bucket;
let key: CryptoKey;

async function migrate(database: D1Database, throughAggregate = true) {
  for (const name of (await readdir(migrationDir)).filter((file) => file.endsWith(".sql")).sort()) {
    if (!throughAggregate && name.startsWith("0014_")) break;
    const bytes = await readFile(new URL(name, migrationDir));
    await database.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((statement) => database.prepare(statement)));
    await recordTempFixtureMigration(database, { name, sha256: createHash("sha256").update(bytes).digest("hex") });
  }
}

before(async () => {
  db = await runtime.getD1Database("DB");
  bucket = await runtime.getR2Bucket("NODES");
  const parsed = await parseTelegramAggregateKey(encodedKey);
  assert.ok(parsed);
  key = parsed;
  await migrate(db);
});
after(() => runtime.dispose());

function policy(botId: string, adminId: string, memberId: string): TelegramPolicy {
  return { botId, botUsername: "fixture_aggregate_bot", adminId, memberId, groupId: "-1001234567890",
    botToken: `${botId}:synthetic-token`, webhookSecret: "synthetic-aggregate-webhook-secret" };
}

function event(config: TelegramPolicy, updateId: number, messageId: number, kind: TelegramAggregateUpdate["kind"] = "show",
  actorId = config.memberId): TelegramAggregateUpdate {
  return { updateId, actorId, chatId: actorId, chatType: "private", messageId,
    messageDate: fixtureDate, threadId: null, kind };
}

function digest(code: string): string {
  return createHash("sha256").update(code).digest("hex");
}

async function seed(database: D1Database, nodes: R2Bucket, ownerId: string, label: string) {
  const row = await createSubscription(database, { ownerId, name: label, sourceUrl: "https://provider.example.invalid/" });
  const share = `${sampleShare}#${label}`;
  assert.equal(await publishNodeSnapshot(database, nodes, { id: row.id, ownerId, expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ name: label, type: "ss", share }]), true);
  return share;
}

async function action(config: TelegramPolicy, updateId: number) {
  return db.prepare(`SELECT action.result, action.revision, action.code_sha256 AS codeSha256, inbox.receipt_nonce AS marker
    FROM telegram_aggregate_actions AS action JOIN telegram_inbox AS inbox USING (receipt_id)
    WHERE inbox.bot_id = ? AND inbox.update_id = ?`).bind(config.botId, updateId)
    .first<{ result: string; revision: number | null; codeSha256: string | null; marker: string }>();
}

function telegramReplies(config: TelegramPolicy) {
  const sent: Array<{ chatId: string; text: string }> = [];
  const request: typeof fetch = async (input, init) => {
    assert.equal(String(input), `https://api.telegram.org/bot${config.botToken}/sendMessage`);
    assert.equal(init?.redirect, "manual");
    const body = JSON.parse(String(init?.body));
    assert.deepEqual(body.link_preview_options, { is_disabled: true });
    sent.push({ chatId: body.chat_id, text: body.text });
    return Response.json({ ok: true, result: { message_id: 1000 + sent.length, chat: { id: Number(body.chat_id) } } });
  };
  return { sent, request };
}

test("requires a canonical unpadded 32-byte key and imports it as nonextractable", async () => {
  assert.equal(key.extractable, false);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const last = alphabet.indexOf(encodedKey.at(-1)!);
  for (const invalid of [null, "", encodedKey + "=", ` ${encodedKey}`, encodedKey.slice(1), `${encodedKey}\n`,
    encodedKey.slice(0, -1) + alphabet[last + 1], Buffer.alloc(33, 0x47).toString("base64url")]) {
    assert.equal(await parseTelegramAggregateKey(invalid), null);
  }
});

test("old and future commands cannot issue or revoke a managed capability", async () => {
  const config = policy("82009", "82901", "82902");
  await seed(db, bucket, config.memberId, "age-fence");
  for (const [update, messageDate] of [[1, fixtureDate - 3600], [2, fixtureDate + 120]] as const) {
    assert.equal(await acceptTelegramAggregate(db, config, { ...event(config, update, update), messageDate }, key), "accepted");
    assert.equal((await action(config, update))?.result, "stale");
  }
  assert.equal(await db.prepare("SELECT count(*) AS n FROM aggregate_links WHERE owner_id = ?")
    .bind(config.memberId).first<number>("n"), 0);
});

test("issues one stable per-actor link, rejects replay, and revokes by mutation order", async () => {
  const config = policy("82001", "82101", "82102");
  const memberShare = await seed(db, bucket, config.memberId, "member");
  const adminShare = await seed(db, bucket, config.adminId, "admin");
  const initial = event(config, 1, 10);
  assert.deepEqual((await Promise.all([initial, initial].map((input) => acceptTelegramAggregate(db, config, input, key)))).sort(),
    ["accepted", "ignored"]);
  const first = await claimTelegramReply(db, config.botId, true);
  assert.ok(first?.aggregate);
  assert.equal(first.aggregate.result, "issued");
  const code = await resolveTelegramAggregateCode(db, config, { ...first, aggregate: first.aggregate }, key);
  assert.ok(code);
  assert.match(code, /^[A-Za-z0-9_-]{22}$/u);
  assert.deepEqual(await action(config, 1), { result: "issued", revision: 1, codeSha256: digest(code), marker: TELEGRAM_AGGREGATE_MARKER });
  const slot = await db.prepare("SELECT code_sha256, nonce, key_version FROM telegram_aggregate_slots WHERE bot_id = ? AND actor_id = ?")
    .bind(config.botId, config.memberId).first();
  assert.equal(slot?.code_sha256, digest(code));
  assert.notEqual(slot?.nonce, code);
  assert.equal(slot?.key_version, 1);
  assert.equal(await beginTelegramAggregateLinkReply(db, config, first), true);
  await settleTelegramReply(db, config, first, { kind: "sent", messageId: 701 });

  assert.equal(await acceptTelegramAggregate(db, config, event(config, 2, 30), key), "accepted");
  const repeat = await claimTelegramReply(db, config.botId, true);
  assert.ok(repeat?.aggregate);
  assert.equal(await resolveTelegramAggregateCode(db, config, { ...repeat, aggregate: repeat.aggregate }, key), code);
  assert.equal(repeat.aggregate.revision, 1);
  assert.equal(await beginTelegramAggregateLinkReply(db, config, repeat), true);
  await settleTelegramReply(db, config, repeat, { kind: "uncertain" });

  assert.equal(await acceptTelegramAggregate(db, config, event(config, 3, 31, "show", config.adminId), key), "accepted");
  const admin = await claimTelegramReply(db, config.botId, true);
  assert.ok(admin?.aggregate);
  const adminCode = await resolveTelegramAggregateCode(db, config, { ...admin, aggregate: admin.aggregate }, key);
  assert.ok(adminCode && adminCode !== code);
  for (const [bearer, share] of [[code, memberShare], [adminCode, adminShare]]) {
    const source = await getAggregateNodeSource(db, bucket, bearer);
    assert.ok(source);
    const rows = [];
    for await (const node of source.read()) rows.push(node.share);
    assert.deepEqual(rows, [share]);
  }
  assert.equal(await beginTelegramAggregateLinkReply(db, config, admin), true);
  await settleTelegramReply(db, config, admin, { kind: "sent", messageId: 702 });

  const legacy = "LegacyLink01";
  await db.prepare("INSERT INTO aggregate_links (code_sha256, owner_id, kind, bot_id) VALUES (?, ?, 'all', ?)")
    .bind(digest(legacy), config.memberId, config.botId).run();
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 4, 32), key), "accepted");
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 5, 20, "revoke"), key), "accepted");
  assert.equal(await hasAggregateLink(db, code), false);
  assert.equal(await hasAggregateLink(db, adminCode), true);
  assert.equal(await hasAggregateLink(db, legacy), true);
  assert.equal((await action(config, 5))?.result, "revoked");
  const { sent, request } = telegramReplies(config);
  await drainTelegramReplies(db, bucket, config, 4, 10_000, request, key);
  assert.deepEqual(sent, [
    { chatId: config.memberId, text: "聚合链接已变更，请重新发送 /export。" },
    { chatId: config.memberId, text: "聚合导出链接已撤销。" },
  ]);
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 6, 19), key), "accepted");
  assert.equal((await action(config, 6))?.result, "stale");
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 7, 33), key), "accepted");
  assert.equal((await action(config, 7))?.revision, 3);
  assert.notEqual((await action(config, 7))?.codeSha256, digest(code));
});

test("rechecks the exact access epoch at the link send boundary and keeps notices private", async () => {
  const config = policy("82002", "82201", "82202");
  await seed(db, bucket, config.memberId, "scope");
  const input = event(config, 1, 10);
  assert.equal(await acceptTelegramAggregate(db, config, { ...input, chatType: "group", chatId: config.groupId }, key), "ignored");
  assert.equal(await acceptTelegramAggregate(db, config, { ...input, actorId: "999", chatId: "999" }, key), "ignored");
  assert.equal(await acceptTelegramAggregate(db, config, input, key), "accepted");
  const lease = await claimTelegramReply(db, config.botId, true);
  assert.ok(lease?.aggregate);
  const code = await resolveTelegramAggregateCode(db, config, { ...lease, aggregate: lease.aggregate }, key);
  assert.ok(code);
  const auth = (allowed: number, messageId: number) => db.prepare(`INSERT INTO telegram_auth VALUES (?, ?, ?, ?, ?)
    ON CONFLICT (bot_id, user_id) DO UPDATE SET allowed = excluded.allowed, message_id = excluded.message_id`)
    .bind(config.botId, config.memberId, allowed, fixtureDate, messageId).run();
  await auth(0, 21);
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 2, 11), key), "ignored");
  await auth(1, 22);
  assert.equal(await beginTelegramAggregateLinkReply(db, config, lease), false);
  assert.equal(await resolveTelegramAggregateCode(db, config, { ...lease, aggregate: lease.aggregate }, key), null);
  assert.equal(await hasAggregateLink(db, code), true);
  await db.prepare("UPDATE telegram_outbox SET lease_until = unixepoch() - 1 WHERE receipt_id = ?").bind(lease.receiptId).run();
  const { sent, request } = telegramReplies(config);
  assert.equal(await acceptTelegramAggregate(db, config, { ...event(config, 3, 12), messageDate: fixtureDate + 1 }, key), "accepted");
  await drainTelegramReplies(db, bucket, config, 4, 10_000, request, key);
  assert.equal(sent[0]?.text, "聚合链接已变更，请重新发送 /export。");
  assert.ok(sent[1]?.text.includes(`${TELEGRAM_AGGREGATE_ORIGIN}/agg/${code}/clash`));
  assert.ok(sent.every(({ chatId }) => chatId === config.memberId));
});

test("records an empty or over-limit result without minting a capability", async () => {
  const config = policy("82003", "82301", "82302");
  await createSubscription(db, { ownerId: config.memberId, name: "Unpublished", sourceUrl: "https://provider.example.invalid/" });
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 1, 10), key), "accepted");
  assert.equal((await action(config, 1))?.result, "empty");
  for (const suffix of [1, 2]) {
    await db.prepare(`INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at, generation,
      snapshot_id, manifest_sha256, node_count) VALUES (?, 'Bounded fixture', 'https://example.invalid/', ?,
      unixepoch(), unixepoch(), 1, '00000000-0000-4000-8000-000000000001', ?, 50001)`)
      .bind(config.memberId, `fixture-capacity-token-${suffix}`, "a".repeat(64)).run();
  }
  assert.equal(await acceptTelegramAggregate(db, config, event(config, 2, 11), key), "accepted");
  assert.equal((await action(config, 2))?.result, "limit");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM aggregate_links WHERE owner_id = ?")
    .bind(config.memberId).first<number>("n"), 0);
});

test("rolls back issuance and its receipt when the D1 transaction fails", async () => {
  const config = policy("82005", "82501", "82502");
  await seed(db, bucket, config.memberId, "rollback");
  const failure = {
    prepare: (sql: string) => db.prepare(sql),
    batch: (statements: D1PreparedStatement[]) => db.batch([
      ...statements, db.prepare("SELECT json_extract('synthetic transaction failure', '$')"),
    ]),
  } as unknown as D1Database;
  const input = event(config, 1, 10);
  await assert.rejects(acceptTelegramAggregate(failure, config, input, key), /Telegram aggregate receipt could not be confirmed/u);
  assert.equal(await action(config, 1), null);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM aggregate_links WHERE owner_id = ?")
    .bind(config.memberId).first<number>("n"), 0);
  assert.equal(await acceptTelegramAggregate(db, config, input, key), "accepted");
  assert.equal((await action(config, 1))?.result, "issued");
});

test("path and terminal document replies survive aggregate gating without head-of-line blocking", async () => {
  for (const enabled of [false, true]) {
    const config = enabled ? policy("82011", "83101", "83102") : policy("82010", "83001", "83002");
    await seed(db, bucket, config.memberId, `mixed-replies-${enabled}`);
    assert.equal(await acceptTelegramAggregate(db, config, event(config, 1, 10), key), "accepted");
    assert.equal(await acceptTelegramPath(db, config, { ...event(config, 2, 11), kind: "path", args: "" }), "accepted");
    assert.equal(await acceptTelegramDocumentJob(db, config, { ...event(config, 3, 12),
      fileId: "synthetic-invalid-document", fileName: "Fixture.exe", fileSize: 1 }), "invalid-document");
    const { sent, request } = telegramReplies(config);
    await drainTelegramReplies(db, bucket, config, 3, 10_000, request, enabled ? key : null);
    assert.equal(sent.length, enabled ? 3 : 2);
    assert.ok(sent.every(({ chatId }) => chatId === config.memberId));
    assert.match(sent.at(-1)!.text, /文件未导入/u);
    assert.equal(sent.filter(({ text }) => text.includes("/agg/")).length, enabled ? 1 : 0);
    const rows = await db.prepare(`SELECT inbox.update_id AS updateId, reply.state FROM telegram_inbox AS inbox
      JOIN telegram_outbox AS reply USING (receipt_id) WHERE inbox.bot_id = ? ORDER BY inbox.update_id`)
      .bind(config.botId).all<{ updateId: number; state: string }>();
    assert.deepEqual(rows.results, [{ updateId: 1, state: enabled ? "sent" : "pending" },
      { updateId: 2, state: "sent" }, { updateId: 3, state: "sent" }]);
  }
});

test("the bundled Worker gates private issuance by the optional key and pins the link origin", { timeout: 60_000 }, async () => {
  const result = await build({ entryPoints: [fileURLToPath(new URL("../src/index.ts", import.meta.url))],
    bundle: true, format: "esm", platform: "browser", target: "es2022", write: false });
  const script = result.outputFiles[0].text;
  const config = policy("82004", "82401", "82402");
  for (const enabled of [false, true]) {
    const { sent, request } = telegramReplies(config);
    const worker = new Miniflare({ modules: true, script, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
      bindings: { BUILD_REVISION: "a".repeat(40), TELEGRAM_ISOLATION_CONFIG: JSON.stringify(config),
        ...(enabled ? { TELEGRAM_AGGREGATE_KEY: encodedKey } : {}) },
      outboundService: async (incoming: Request) => request(incoming.url, { method: incoming.method,
        redirect: "manual", body: await incoming.text() }),
    });
    try {
      const database = await worker.getD1Database("DB");
      const nodes = await worker.getR2Bucket("NODES");
      await migrate(database, enabled);
      const share = await seed(database, nodes, config.memberId, "bundle");
      const post = (updateId: number, text: string, chatId = config.memberId) => worker.dispatchFetch("https://fixture.invalid/telegram/webhook", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": config.webhookSecret },
        body: JSON.stringify({ update_id: updateId, message: { message_id: updateId, date: fixtureDate, text,
          from: { id: Number(config.memberId), is_bot: false },
          chat: { id: Number(chatId), type: chatId === config.groupId ? "group" : "private" },
          entities: [{ type: "bot_command", offset: 0, length: text.split(" ", 1)[0].length }],
        } }),
      });
      const scheduled = async () => assert.equal((await (await worker.getWorker()).scheduled({ cron: "* * * * *" })).outcome, "ok");
      const waitForSent = async (updateId: number) => {
        for (let attempt = 0; attempt < 50; attempt++) {
          const state = await database.prepare(`SELECT reply.state FROM telegram_outbox AS reply
            JOIN telegram_inbox AS inbox USING (receipt_id) WHERE inbox.bot_id = ? AND inbox.update_id = ?`)
            .bind(config.botId, updateId).first<string>("state");
          if (state === "sent") return;
          await new Promise((resolve) => setTimeout(resolve, 100));
        }
        assert.fail("Synthetic Telegram reply did not settle.");
      };
      assert.equal((await post(1, "/export", config.groupId)).status, 204);
      assert.equal((await post(2, "/export https://fixture.invalid/")).status, 204);
      assert.equal((await post(3, "/export")).status, enabled ? 200 : 204);
      if (!enabled) {
        assert.equal((await post(4, "/help")).status, 200);
        await scheduled();
        await waitForSent(4);
        assert.equal(sent.length, 1);
        assert.doesNotMatch(sent[0].text, /\/agg\//u);
        continue;
      }
      await scheduled();
      await waitForSent(3);
      const url = sent[0]?.text.match(/https:\/\/[^\s]+\/clash/u)?.[0];
      assert.ok(url?.startsWith(`${TELEGRAM_AGGREGATE_ORIGIN}/agg/`));
      assert.doesNotMatch(sent[0].text, /\/base64|fixture\.invalid|203\.0\.113\.10/u);
      const base64 = url.replace(/\/clash$/u, "/base64");
      const response = await worker.dispatchFetch(base64);
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("Cache-Control"), "private, no-store");
      assert.equal(await response.text(), Buffer.from(share).toString("base64"));

      assert.equal((await post(4, "/export revoke")).status, 200);
      assert.equal((await worker.dispatchFetch(base64, { method: "HEAD" })).status, 404);
      const shortcut = new URL(url);
      shortcut.pathname = `/s/${shortcut.pathname.split("/")[2]}`;
      assert.equal((await worker.dispatchFetch(shortcut, { redirect: "manual" })).status, 404);
      await scheduled();
      await waitForSent(4);
      assert.equal(sent.at(-1)?.text, "聚合导出链接已撤销。");
    } finally {
      await worker.dispose();
    }
  }
});

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";

import { AggregateLimitError, getAggregateNodeSource } from "../src/aggregate.ts";
import { createSubscription, publishNodeSnapshot, SnapshotIntegrityError, type ExportNodeSource } from "../src/storage.ts";
import {
  acceptTelegramAggregate, parseTelegramAggregateKey, resolveTelegramAggregateCode,
} from "../src/telegram/aggregate-actions.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import {
  beginTelegramAggregateLinkReply, beginTelegramReply, beginTelegramTempRawReply, claimTelegramReply, settleTelegramReply,
} from "../src/telegram/store.ts";
import { acceptTelegramTemp } from "../src/telegram/temp-import.ts";
import { confirmTelegramTempRawSend, prepareTelegramTempRawReply } from "../src/telegram/temp-raw.ts";
import { LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256 } from "../src/telegram/temp-storage.ts";

const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"] });
let db: D1Database;
let bucket: R2Bucket;
const sha = (text: string) => createHash("sha256").update(text).digest("hex");
const share = (name: string) => `hy2://${name}.fixture.invalid#${name}`;
const now = () => Math.floor(Date.now() / 1000);

before(async () => {
  db = await runtime.getD1Database("DB");
  bucket = await runtime.getR2Bucket("NODES");
  const directory = new URL("../migrations/", import.meta.url);
  for (const file of (await readdir(directory)).filter((name) => name.endsWith(".sql")).sort()) {
    const text = await readFile(new URL(file, directory), "utf8");
    if (file === LEGACY_TEMP_MIGRATION_NAME) assert.equal(sha(text), LEGACY_TEMP_MIGRATION_SHA256);
    await db.batch(text.trim().split(/;\s*/u).filter(Boolean).map((sql) => db.prepare(sql)));
  }
  await db.batch([
    db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT) STRICT"),
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (39,?,?,'applied')")
      .bind(LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256),
  ]);
});

after(async () => runtime.dispose());

function policy(botId: string, memberId: string): TelegramPolicy {
  return { botId, memberId, adminId: "87999", groupId: "-1001234567890", botUsername: "fixture_temp_legacy_bot",
    botToken: `${botId}:synthetic-token`, webhookSecret: "fixture-temp-legacy-webhook" };
}

function event(config: TelegramPolicy, messageId: number, messageDate: number) {
  return { actorId: config.memberId, chatId: config.memberId, chatType: "private" as const, threadId: null,
    updateId: messageId, messageId, messageDate };
}

async function install(config: TelegramPolicy, cutover: number | null) {
  await db.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,?)")
    .bind(config.botId, sha("synthetic legacy inventory"), cutover).run();
}

async function baseline(config: TelegramPolicy, id: number, names: string[], owner = config.memberId) {
  const payload = JSON.stringify(names.map((name) => ({ name: `Stored ${name}`, type: "temp", share: share(name) })));
  await db.prepare("INSERT INTO legacy_temp_batches VALUES (?,?,?,?,?,?,?,?)")
    .bind(config.botId, owner, id, id + names.length - 1, payload, names.length, Buffer.byteLength(payload), sha(payload)).run();
}

async function paste(config: TelegramPolicy, id: number, date: number, name: string) {
  assert.equal(await acceptTelegramTemp(db, config, { ...event(config, id, date), kind: "temp-text", text: share(name) }), "accepted");
  const lease = await claimTelegramReply(db, config.botId);
  assert.equal(lease?.temp?.kind, "added");
  assert.ok(lease);
  assert.equal(await beginTelegramReply(db, config, lease, "allowed"), true);
  await settleTelegramReply(db, config, lease, { kind: "sent", messageId: id + 100 });
}

async function link(code: string, config: TelegramPolicy, selected?: number[]) {
  await db.prepare("INSERT INTO aggregate_links(code_sha256,owner_id,kind,bot_id,selected_ids) VALUES (?,?,?,?,?)")
    .bind(sha(code), config.memberId, selected ? "selected" : "all", selected ? null : config.botId,
      selected ? JSON.stringify(selected) : null).run();
}

test("orders legacy rows before live rows for all exports and pins the verified payload", async () => {
  const config = policy("97811", "87811");
  const otherBot = policy("97812", config.memberId);
  const cutover = now() - 4;
  await install(config, cutover);
  await install(otherBot, cutover);
  await baseline(config, 20, ["legacy-first", "legacy-first"]);
  await baseline(config, 40, ["legacy-last"]);
  await baseline(config, 20, ["foreign-owner"], config.adminId);
  await baseline(otherBot, 20, ["foreign-bot"]);
  await paste(config, 1, cutover + 1, "live-last");
  const sub = await createSubscription(db, { ownerId: config.memberId, name: "fixture", sourceUrl: "uploaded://fixture" });
  assert.equal(await publishNodeSnapshot(db, bucket, { id: sub.id, ownerId: sub.ownerId, expectedGeneration: 0,
    expectedLifecycleRevision: 0 }, [{ name: "Subscription", type: "temp", share: share("subscription") }]), true);
  const all = "A".repeat(22);
  const selected = "B".repeat(22);
  await link(all, config);
  await link(selected, config, [sub.id]);

  const captured = await getAggregateNodeSource(db, bucket, all);
  assert.ok(captured);
  const collect = async (source: ExportNodeSource) => {
    const values = [];
    for await (const node of source.read()) values.push(node);
    return values;
  };
  const expected = ["subscription", "legacy-first", "legacy-first", "legacy-last", "live-last"].map(share);
  assert.deepEqual((await collect(captured)).map((node) => node.share), expected);
  assert.equal((await collect(captured))[1].name, "Stored legacy-first");
  const selectedSource = await getAggregateNodeSource(db, bucket, selected);
  assert.ok(selectedSource);
  assert.deepEqual((await collect(selectedSource)).map((node) => node.share), [share("subscription")]);

  await db.prepare("UPDATE legacy_temp_batches SET payload_sha256=? WHERE bot_id=? AND actor_id=? AND first_legacy_id=20")
    .bind("0".repeat(64), config.botId, config.memberId).run();
  const corrupted = await getAggregateNodeSource(db, bucket, all);
  assert.ok(corrupted);
  await assert.rejects(() => collect(corrupted), SnapshotIntegrityError);
  assert.deepEqual((await collect(captured)).map((node) => node.share), expected);
});

test("an aggregate admitted before activation cannot deliver a capability after cutover", async () => {
  const config = policy("97813", "87813");
  const cutover = now() - 4;
  await install(config, null);
  await baseline(config, 1, ["legacy-aggregate"]);
  await paste(config, 1, cutover - 1, "live-aggregate");
  const key = await parseTelegramAggregateKey(Buffer.alloc(32, 5).toString("base64url"));
  assert.ok(key);
  assert.equal(await acceptTelegramAggregate(db, config, { ...event(config, 2, cutover), kind: "show" }, key), "accepted");
  const old = await claimTelegramReply(db, config.botId, true);
  assert.ok(old?.aggregate);
  assert.equal(old.aggregate.result, "issued");
  const oldScope = { ...old, aggregate: old.aggregate };
  const code = await resolveTelegramAggregateCode(db, config, oldScope, key);
  assert.ok(code);

  await db.prepare("UPDATE legacy_temp_installations SET cutover_epoch=? WHERE bot_id=?").bind(cutover, config.botId).run();
  assert.equal(await resolveTelegramAggregateCode(db, config, oldScope, key), null);
  assert.equal(await beginTelegramAggregateLinkReply(db, config, old), false);
  assert.equal(await beginTelegramReply(db, config, old, "allowed"), true);
  await settleTelegramReply(db, config, old, { kind: "sent", messageId: 301 });
  assert.equal(await acceptTelegramAggregate(db, config, { ...event(config, 3, cutover + 1), kind: "show" }, key), "accepted");
  const current = await claimTelegramReply(db, config.botId, true);
  assert.ok(current?.aggregate);
  assert.equal(current.aggregate.result, "ready");
  assert.equal(await resolveTelegramAggregateCode(db, config, { ...current, aggregate: current.aggregate }, key), code);
  assert.equal(await beginTelegramAggregateLinkReply(db, config, current), true);

  const onlyLegacy = policy("97814", "87814");
  await install(onlyLegacy, cutover);
  await baseline(onlyLegacy, 1, ["legacy-only"]);
  assert.equal(await acceptTelegramAggregate(db, onlyLegacy, { ...event(onlyLegacy, 1, cutover + 1), kind: "show" }, key), "accepted");
  assert.equal((await claimTelegramReply(db, onlyLegacy.botId, true))?.aggregate?.result, "issued");
});

test("applies the aggregate cap to combined legacy and live temporary rows", async () => {
  const config = policy("97816", "87816");
  const cutover = now() - 4;
  await install(config, null);
  await paste(config, 1, cutover - 1, "existing-live");
  for (let batch = 0; batch < 10; batch++) {
    await baseline(config, 1 + batch * 500, Array.from({ length: 500 }, () => "legacy-at-cap"));
  }
  await db.prepare("UPDATE legacy_temp_installations SET cutover_epoch=? WHERE bot_id=?").bind(cutover, config.botId).run();
  const code = "C".repeat(22);
  await link(code, config);
  await assert.rejects(() => getAggregateNodeSource(db, bucket, code), AggregateLimitError);
  const key = await parseTelegramAggregateKey(Buffer.alloc(32, 5).toString("base64url"));
  assert.ok(key);
  assert.equal(await acceptTelegramAggregate(db, config, { ...event(config, 2, cutover + 1), kind: "show" }, key), "accepted");
  assert.equal((await claimTelegramReply(db, config.botId, true))?.aggregate?.result, "limit");
});

test("private raw preparation keeps exact legacy and authentic live lines and fences a clear at send", async () => {
  const config = policy("97815", "87815");
  const cutover = now() - 4;
  await install(config, cutover);
  await baseline(config, 10, ["legacy-raw", "legacy-raw"]);
  await baseline(config, 10, ["other-owner"], config.adminId);
  await paste(config, 1, cutover + 1, "live-raw");
  assert.equal(await acceptTelegramTemp(db, config, { ...event(config, 2, cutover + 2), kind: "temp-raw" }), "accepted");
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease?.tempRaw);
  const prepared = await prepareTelegramTempRawReply(db, config, lease, Date.now() + 10_000);
  assert.equal(prepared.kind, "text");
  if (prepared.kind !== "text") return;
  assert.equal(prepared.text.split("\n\n")[1], ["legacy-raw", "legacy-raw", "live-raw"].map(share).join("\n"));
  assert.equal(await beginTelegramTempRawReply(db, config, lease, prepared.guard), true);
  assert.equal(await confirmTelegramTempRawSend(db, config, lease, prepared.guard), true);

  assert.equal(await acceptTelegramTemp(db, config, { ...event(config, 3, cutover + 3), kind: "temp-clear" }), "accepted");
  assert.equal(await confirmTelegramTempRawSend(db, config, lease, prepared.guard), false);
  assert.deepEqual((await db.prepare("SELECT actor_id AS owner FROM legacy_temp_batches WHERE bot_id=?")
    .bind(config.botId).all()).results, [{ owner: config.adminId }]);
  await settleTelegramReply(db, config, lease, { kind: "failed" });
});

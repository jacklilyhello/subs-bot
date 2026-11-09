import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { getAggregateNodeSource } from "../src/aggregate.ts";
import worker from "../src/index.ts";
import { LEGACY_ALL_MIGRATION, LEGACY_ALL_MIGRATION_SHA256 } from "../src/legacy-all-aggregates.ts";
import { MAX_PATH_RULES } from "../src/path-rules.ts";
import { createSubscription, MAX_CHUNK_BYTES, publishNodeSnapshot, type ExportNodeSource,
  type SubscriptionMetadata } from "../src/storage.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy, TelegramTempUpdate } from "../src/telegram/protocol.ts";
import { acceptTelegramTemp } from "../src/telegram/temp-import.ts";
import { recordTempFixtureMigration } from "./temp-migration-fixture.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"], r2Buckets: ["NODES"],
});
const migrations = new URL("../migrations/", import.meta.url);
const previousFixedLength = Object.getOwnPropertyDescriptor(globalThis, "FixedLengthStream");
let db: D1Database;
let bucket: R2Bucket;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  for (const name of (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort()) {
    const bytes = await readFile(new URL(name, migrations));
    await db.batch(bytes.toString("utf8").trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await recordTempFixtureMigration(db, { name, sha256: createHash("sha256").update(bytes).digest("hex") });
    if (name === LEGACY_ALL_MIGRATION) {
      assert.equal(createHash("sha256").update(bytes).digest("hex"), LEGACY_ALL_MIGRATION_SHA256);
      await db.prepare("INSERT INTO subs_bot_schema_migrations (position,name,sha256,mode) VALUES (40,?,?,'applied')")
        .bind(LEGACY_ALL_MIGRATION, LEGACY_ALL_MIGRATION_SHA256).run();
    }
  }
  // The emitted Worker tests cover native response framing.
  class FixedLengthStreamShim extends TransformStream<Uint8Array, Uint8Array> {
    constructor(_length: number) {
      super();
    }
  }
  Object.defineProperty(globalThis, "FixedLengthStream", { value: FixedLengthStreamShim, configurable: true });
});

after(async () => {
  if (previousFixedLength) Object.defineProperty(globalThis, "FixedLengthStream", previousFixedLength);
  else Reflect.deleteProperty(globalThis, "FixedLengthStream");
  await miniflare.dispose();
});

const sha256 = (text: string) => createHash("sha256").update(text).digest("hex");
const share = (name: string) => `hy2://${name}.fixture.invalid#${name}`;

function policy(botId: string, memberId: string): TelegramPolicy {
  return { botId, memberId, adminId: "88999", groupId: "-1001234567890", botUsername: "Synthetic_Agg_Bot",
    webhookSecret: "synthetic-webhook-secret", botToken: `${botId}:synthetic-token` };
}

async function temp(config: TelegramPolicy, id: number, name?: string, actorId = config.memberId): Promise<void> {
  const scope = { updateId: id, actorId, chatId: actorId, chatType: "private" as const,
    messageId: id, messageDate: 1_800_000_000, threadId: null };
  const update: TelegramTempUpdate = name ? { ...scope, kind: "temp-text", text: share(name) }
    : { ...scope, kind: "temp-clear" };
  assert.equal(await acceptTelegramTemp(db, config, update), "accepted");
}

async function link(code: string, config: TelegramPolicy, selection?: number[]): Promise<void> {
  await db.prepare(`INSERT INTO aggregate_links (code_sha256, owner_id, kind, bot_id, selected_ids) VALUES (?, ?, ?, ?, ?)`)
    .bind(sha256(code), config.memberId, selection ? "selected" : "all", selection ? null : config.botId,
      selection ? JSON.stringify(selection) : null).run();
}

async function publish(sub: SubscriptionMetadata, names: string[], generation = sub.generation): Promise<void> {
  assert.equal(await publishNodeSnapshot(db, bucket, {
    id: sub.id, ownerId: sub.ownerId, expectedGeneration: generation, expectedLifecycleRevision: sub.lifecycleRevision,
  }, names.map((name) => ({ type: "hysteria2", name, share: share(name) }))), true);
}

async function subscription(ownerId: string, name: string, names?: string[]): Promise<SubscriptionMetadata> {
  const sub = await createSubscription(db, { ownerId, name, sourceUrl: "uploaded://aggregate-fixture" });
  if (names) await publish(sub, names);
  return sub;
}

function request(path: string, method = "GET") {
  return worker.fetch(new Request(`https://fixture.invalid${path}`, { method }), { DB: db, NODES: bucket });
}

async function sourceShares(source: ExportNodeSource | null) {
  assert.ok(source);
  const shares = [];
  for await (const node of source.read()) shares.push(node.share);
  assert.equal(source.nodeCount, shares.length);
  return shares;
}

async function encodedShares(code: string, kind = "base64") {
  const response = await request(`/agg/${code}/${kind}`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "private, no-store");
  assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
  return Buffer.from(await response.text(), "base64").toString("utf8").split("\n");
}

test("keeps all membership dynamic and selected order frozen with no foreign or temporary nodes in selection", async () => {
  const config = policy("98001", "88001");
  const all = "SyntheticAll";
  const selected = "SyntheticSelectedCodeA";
  const first = await subscription(config.memberId, "First", ["first", "first"]);
  const foreign = await subscription(config.adminId, "Foreign", ["foreign"]);
  const unpublished = await subscription(config.memberId, "Unpublished");
  const second = await subscription(config.memberId, "Second", ["second"]);
  await link(all, config);
  await link(selected, config, [second.id, foreign.id, unpublished.id, first.id]);
  await temp(config, 30, "temporary-a");
  await temp(config, 20, "temporary-b");
  await temp(config, 40, "foreign-actor", config.adminId);
  await temp(policy("98002", config.memberId), 30, "foreign-bot");

  assert.deepEqual(await encodedShares(all, "v2ray"), ["first", "first", "second", "temporary-a", "temporary-b"].map(share));
  assert.deepEqual(await encodedShares(selected, "mixed"), ["second", "first", "first"].map(share));
  const third = await subscription(config.memberId, "Third", ["third"]);
  assert.ok(third.id > second.id);
  assert.deepEqual(await encodedShares(all), ["first", "first", "second", "third", "temporary-a", "temporary-b"].map(share));
  assert.deepEqual(await encodedShares(selected), ["second", "first", "first"].map(share));

  const mutation = { id: second.id, ownerId: second.ownerId, expectedLifecycleRevision: 0 };
  assert.equal(await trashOwnedSubscription(db, mutation), true);
  assert.deepEqual(await encodedShares(selected), ["first", "first"].map(share));
  assert.equal(await restoreOwnedSubscription(db, { ...mutation, expectedLifecycleRevision: 1 }), true);
  assert.deepEqual(await encodedShares(selected), ["second", "first", "first"].map(share));
});

test("a replayable source pins publication and temp values across concurrent changes", async () => {
  const config = policy("98003", "88003");
  const code = "SyntheticPin";
  const sub = await subscription(config.memberId, "Pinned", ["before-refresh"]);
  await temp(config, 1, "before-clear");
  await link(code, config);
  const captured = await getAggregateNodeSource(db, bucket, code);
  const before = ["before-refresh", "before-clear"].map(share);
  assert.deepEqual(await sourceShares(captured), before);
  await publish(sub, ["after-refresh"], 1);
  await temp(config, 2);
  assert.deepEqual(await sourceShares(captured), before);
  assert.deepEqual(await encodedShares(code), [share("after-refresh")]);
});

test("serves only pinned legacy all links with legacy ordering, aliases and empty exports", async () => {
  const config = policy("98043", "88043");
  const legacy = "T".repeat(12);
  const native = "T".repeat(22);
  const inventory = sha256("synthetic legacy dynamic inventory");
  await db.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,NULL)").bind(config.botId, inventory).run();
  await link(legacy, config);
  await link(native, config);
  await db.prepare("INSERT INTO legacy_all_aggregates (code_sha256,bot_id,owner_id,inventory_sha256) VALUES (?,?,?,?)")
    .bind(sha256(legacy), config.botId, config.memberId, inventory).run();
  const first = await subscription(config.memberId, "First", ["first-ranked"]);
  const second = await subscription(config.memberId, "Second", ["second-ranked"]);
  await subscription(config.adminId, "Foreign", ["foreign-rank"]);
  await db.prepare("INSERT INTO legacy_all_subscription_order (subscription_id,owner_id,anchor,tie) VALUES (?,?,?,1)")
    .bind(first.id, config.memberId, second.id).run();
  for (const path of [`/agg/${legacy}/base64`, `/s/${legacy}`]) assert.equal((await request(path)).status, 404);
  assert.equal((await request(`/agg/${legacy}/unknown-format`)).status, 406);
  assert.deepEqual(await encodedShares(native), ["first-ranked", "second-ranked"].map(share));

  await db.prepare("UPDATE legacy_temp_installations SET cutover_epoch=unixepoch()-1 WHERE bot_id=?").bind(config.botId).run();
  assert.deepEqual(await encodedShares(legacy, "MIXED"), ["second-ranked", "first-ranked"].map(share));
  const clash = await request(`/agg/${legacy}/unknown-format`);
  assert.equal(clash.status, 200);
  assert.equal(clash.headers.get("Content-Type"), "text/yaml; charset=utf-8");
  assert.match(await clash.text(), /"name":"second-ranked"[^\n]+\n  - \{"name":"first-ranked"/u);
  const short = await request(`/s/${legacy}`, "HEAD");
  assert.equal(short.status, 302);
  assert.equal(short.headers.get("Location"), `/agg/${legacy}/clash`);
  assert.equal(await short.text(), "");
  assert.equal((await request(`/agg/${legacy}`)).status, 404);

  await db.prepare("INSERT INTO normal_short_links (code_sha256,code_length,bot_id,owner_id,target_url) VALUES (?,12,?,?,?)")
    .bind(sha256(legacy), config.botId, config.memberId, "https://example.org/ambiguous").run();
  for (const path of [`/agg/${legacy}/base64`, `/s/${legacy}`]) assert.equal((await request(path)).status, 404);
  await db.prepare("DELETE FROM normal_short_links WHERE code_sha256=?").bind(sha256(legacy)).run();
  await db.prepare("UPDATE legacy_all_aggregates SET inventory_sha256=? WHERE code_sha256=?")
    .bind("a".repeat(64), sha256(legacy)).run();
  for (const path of [`/agg/${legacy}/base64`, `/s/${legacy}`]) assert.equal((await request(path)).status, 404);
  await db.prepare("UPDATE legacy_all_aggregates SET inventory_sha256=? WHERE code_sha256=?").bind(inventory, sha256(legacy)).run();

  await db.prepare("UPDATE legacy_all_subscription_order SET owner_id=? WHERE subscription_id=?").bind(config.adminId, first.id).run();
  assert.equal((await request(`/agg/${legacy}/base64`)).status, 503);
  assert.deepEqual(await encodedShares(native), ["first-ranked", "second-ranked"].map(share));
  await db.prepare("UPDATE legacy_all_subscription_order SET owner_id=? WHERE subscription_id=?").bind(config.memberId, first.id).run();
  for (const row of [first, second]) {
    assert.equal(await trashOwnedSubscription(db, { id: row.id, ownerId: row.ownerId, expectedLifecycleRevision: 0 }), true);
  }
  for (const method of ["GET", "HEAD"]) {
    const empty = await request(`/agg/${legacy}/v2ray`, method);
    assert.equal(empty.status, 200);
    assert.equal(empty.headers.get("Content-Type"), "text/plain; charset=utf-8");
    assert.equal(await empty.text(), "");
  }
  assert.equal((await request(`/agg/${native}/base64`)).status, 404);
});

test("maps only owned subscription nodes and pins rules across selected and all replays", async () => {
  const config = policy("98013", "88013");
  const all = "SyntheticMap";
  const selected = "SyntheticSel";
  const first = await subscription(config.memberId, "First mapped subscription", ["Raw"]);
  const second = await subscription(config.memberId, "Second mapped subscription");
  const structured = { name: "Straße", type: "ss", server: "203.0.113.10", port: 8388,
    cipher: "aes-256-gcm", password: "fixture" };
  assert.equal(await publishNodeSnapshot(db, bucket, {
    id: second.id, ownerId: second.ownerId, expectedGeneration: 0, expectedLifecycleRevision: 0,
  }, [structured]), true);
  await link(all, config);
  await link(selected, config, [second.id, first.id]);
  await temp(config, 1, "temporary");
  const insert = "INSERT INTO path_rules (owner_id, keyword, remark) VALUES (?, ?, ?)";
  await db.batch([
    db.prepare(insert).bind(config.adminId, "STRASSE", "foreign"),
    db.prepare(insert).bind(config.memberId, "STRASSE", "mapped"),
    db.prepare(insert).bind(config.memberId, "#raw", "stored"),
    db.prepare(insert).bind(config.memberId, "temporary", "excluded"),
  ]);

  const singbox = await request(`/sub/${second.token}/singbox`);
  assert.equal(singbox.status, 200);
  const { outbounds } = await singbox.json() as { outbounds: { tag: string }[] };
  assert.equal(outbounds[2].tag, "Straße → mapped");
  const raw = await request(`/sub/${first.token}/mixed`);
  assert.equal(raw.status, 200);
  assert.equal(Buffer.from(await raw.text(), "base64").toString("utf8"), share("Raw"));

  const generated = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Stra%C3%9Fe%20%E2%86%92%20mapped";
  assert.deepEqual(await encodedShares(all), [share("Raw"), generated, share("temporary")]);
  assert.deepEqual(await encodedShares(selected), [generated, share("Raw")]);
  const selectedClash = await request(`/agg/${selected}/clash`);
  assert.equal(selectedClash.status, 200);
  const clashText = await selectedClash.text();
  assert.match(clashText, /"name":"Straße → mapped"[^\n]+\n  - \{"name":"Raw → stored"/u);
  assert.doesNotMatch(clashText, /temporary|foreign/u);
  const allClash = await request(`/agg/${all}/clash`);
  assert.equal(allClash.status, 200);
  const allText = await allClash.text();
  assert.match(allText, /"name":"Raw → stored"[^\n]+\n  - \{"name":"Straße → mapped"[^\n]+\n  - \{"name":"temporary"/u);
  assert.doesNotMatch(allText, /excluded|foreign/u);

  const capture = await getAggregateNodeSource(db, bucket, selected);
  assert.ok(capture);
  await db.prepare("UPDATE path_rules SET remark = 'later' WHERE owner_id = ? AND keyword = 'STRASSE'")
    .bind(config.memberId).run();
  for (const _pass of [1, 2]) {
    const names = [];
    for await (const { name } of capture.read()) names.push(name);
    assert.deepEqual(names, ["Straße → mapped", "Raw → stored"]);
  }
  const fresh = await request(`/agg/${selected}/clash`);
  assert.equal(fresh.status, 200);
  assert.match(await fresh.text(), /Straße → later/u);
});

test("rejects excess and corrupt owned rules before GET or HEAD export succeeds", async () => {
  const config = policy("98014", "88014");
  const selected = "SyntheticCapRulesCodeA";
  const owned = await subscription(config.memberId, "Owned", ["owned"]);
  const foreign = await subscription(config.adminId, "Foreign", ["foreign"]);
  await link(selected, config, [owned.id]);
  await db.prepare(`WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n + 1 FROM seq WHERE n < ?)
    INSERT INTO path_rules (owner_id, keyword, remark) SELECT ?, 'rule-' || n, 'fixture' FROM seq`)
    .bind(MAX_PATH_RULES + 1, config.memberId).run();

  for (const path of [`/sub/${owned.token}/clash`, `/agg/${selected}/base64`]) {
    const get = await request(path);
    assert.equal(get.status, 422);
    assert.equal(await get.text(), "Subscription content cannot be exported.");
    const head = await request(path, "HEAD");
    assert.equal(head.status, 422);
    assert.equal(await head.text(), "");
  }
  const other = await request(`/sub/${foreign.token}/base64`);
  assert.equal(other.status, 200);
  assert.equal(Buffer.from(await other.text(), "base64").toString("utf8"), share("foreign"));

  await db.prepare("DELETE FROM path_rules WHERE owner_id = ?").bind(config.memberId).run();
  await db.prepare("INSERT INTO path_rules (owner_id, keyword, remark) VALUES (?, ?, ?)")
    .bind(config.memberId, "\u0085", "fixture").run();
  const corrupt = await request(`/sub/${owned.token}/base64`);
  assert.equal(corrupt.status, 503);
  assert.equal(await corrupt.text(), "Subscription temporarily unavailable.");
});

test("uses the existing format planners and fixed private redirect for an active aggregate", async () => {
  const config = policy("98004", "88004");
  const code = "SyntheticTry";
  await subscription(config.memberId, "Formats", ["formats"]);
  await temp(config, 1, "format-temp");
  await link(code, config);
  const clash = await request(`/agg/${code}/clash`);
  assert.equal(clash.status, 200);
  assert.match(clash.headers.get("Content-Type") ?? "", /^text\/yaml/u);
  assert.match(await clash.text(), /"name":"formats"[^\n]+\n  - \{"name":"format-temp"/u);
  const singbox = await request(`/agg/${code}/sing-box`);
  assert.equal(singbox.status, 200);
  const { outbounds } = await singbox.json() as { outbounds: { tag: string }[] };
  assert.deepEqual(outbounds.slice(2).map(({ tag }) => tag), ["formats", "format-temp"]);
  for (const kind of ["clash", "singbox", "base64"]) {
    const head = await request(`/agg/${code}/${kind}`, "HEAD");
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
  }
  for (const method of ["GET", "HEAD"]) {
    const redirect = await request(`/s/${code}`, method);
    assert.equal(redirect.status, 302);
    assert.equal(redirect.headers.get("Location"), `/agg/${code}/clash`);
    assert.equal(redirect.headers.get("Cache-Control"), "private, no-store");
    assert.equal(redirect.headers.get("Referrer-Policy"), "no-referrer");
    assert.equal(await redirect.text(), "");
  }
  assert.equal((await request(`/agg/${code}/unavailable`)).status, 406);
  assert.equal((await request(`/s/${code}`, "POST")).status, 405);
  assert.equal((await request("/s/SyntheticMis")).status, 404);
  assert.equal((await request("/agg/invalid/base64")).status, 404);
  await db.prepare("UPDATE aggregate_links SET revoked_at = unixepoch() WHERE code_sha256 = ?").bind(sha256(code)).run();
  for (const path of [`/s/${code}`, `/agg/${code}/base64`]) {
    const revoked = await request(path);
    assert.equal(revoked.status, 404);
    assert.doesNotMatch(await revoked.text(), /SyntheticTry|format-temp/u);
  }
});

test("exports selected subscriptions through the Surge and Quantumult X renderers", async () => {
  const config = policy("98007", "88007");
  const code = "SyntheticTxt";
  const first = await subscription(config.memberId, "First text subscription");
  const second = await subscription(config.memberId, "Second text subscription");
  for (const [sub, name] of [[first, "First proxy"], [second, "Second proxy"]] as const) {
    assert.equal(await publishNodeSnapshot(db, bucket, {
      id: sub.id, ownerId: sub.ownerId, expectedGeneration: 0, expectedLifecycleRevision: sub.lifecycleRevision,
    }, [{ name, type: "ss", server: "203.0.113.10", port: 8388, cipher: "aes-256-gcm", password: "fixture" }]), true);
  }
  await link(code, config, [second.id, first.id]);
  const surge = await request(`/agg/${code}/surge`);
  assert.equal(surge.status, 200);
  assert.match(await surge.text(), /^\[Proxy\]\nSecond proxy = ss,[^\n]+\nFirst proxy = ss,/u);
  for (const format of ["qx", "quantumult", "quantumultx"]) {
    const response = await request(`/agg/${code}/${format}`);
    assert.equal(response.status, 200);
    assert.match(await response.text(), /tag=Second proxy\nshadowsocks=[^\n]+tag=First proxy\n$/u);
    const head = await request(`/agg/${code}/${format}`, "HEAD");
    assert.equal(head.status, 200);
    assert.equal(await head.text(), "");
  }
});

test("rejects aggregate-wide storage overflow before reading chunks", async () => {
  const config = policy("98005", "88005");
  const code = "SyntheticCap";
  const descriptors = Array.from({ length: 65 }, () => ({ bytes: MAX_CHUNK_BYTES, sha256: "a".repeat(64), count: 1 }));
  const manifest = JSON.stringify({ version: 1, chunks: descriptors });
  for (const name of ["over-one", "over-two"]) {
    const sub = await subscription(config.memberId, name);
    const snapshotId = randomUUID();
    await bucket.put(`subscriptions/${sub.id}/${snapshotId}/manifest.json`, manifest);
    await db.prepare("UPDATE subscriptions SET generation = 1, snapshot_id = ?, manifest_sha256 = ?, node_count = ? WHERE id = ?")
      .bind(snapshotId, sha256(manifest), descriptors.length, sub.id).run();
  }
  await link(code, config);
  // The manifests each describe 32.5 MiB, and no chunk exists. A 422 proves
  // the combined budget was rejected before chunk integrity checks.
  const response = await request(`/agg/${code}/base64`);
  assert.equal(response.status, 422);
  assert.equal(response.headers.get("Cache-Control"), "private, no-store");
});

test("reports corrupt sources and unsupported settings without returning a partial export", async () => {
  const config = policy("98006", "88006");
  const code = "SyntheticBad";
  const sub = await subscription(config.memberId, "Corrupt", ["synthetic-canary"]);
  await link(code, config);
  const snapshotId = await db.prepare("SELECT snapshot_id FROM subscriptions WHERE id = ?").bind(sub.id).first<string>("snapshot_id");
  assert.ok(snapshotId);
  await bucket.delete(`subscriptions/${sub.id}/${snapshotId}/0.ndjson`);
  const missing = await request(`/agg/${code}/base64`);
  assert.equal(missing.status, 503);
  assert.doesNotMatch(await missing.text(), /synthetic-canary|SyntheticBad/u);

  const unsupported = "ssr://synthetic-opaque-share#synthetic-canary";
  assert.equal(await publishNodeSnapshot(db, bucket, {
    id: sub.id, ownerId: sub.ownerId, expectedGeneration: 1, expectedLifecycleRevision: 0,
  }, [{ share: unsupported }]), true);
  assert.deepEqual(await encodedShares(code), [unsupported]);
  const response = await request(`/agg/${code}/clash`);
  assert.equal(response.status, 422);
  assert.doesNotMatch(await response.text(), /synthetic-canary|SyntheticBad/u);
});

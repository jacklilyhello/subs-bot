import assert from "node:assert/strict";
import { createHash, randomUUID } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { getAggregateNodeSource } from "../src/aggregate.ts";
import worker from "../src/index.ts";
import { createSubscription, MAX_CHUNK_BYTES, publishNodeSnapshot, type ExportNodeSource,
  type SubscriptionMetadata } from "../src/storage.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy, TelegramTempUpdate } from "../src/telegram/protocol.ts";
import { acceptTelegramTemp } from "../src/telegram/temp-import.ts";

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
    const sql = await readFile(new URL(name, migrations), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
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

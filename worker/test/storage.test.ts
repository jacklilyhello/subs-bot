import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import {
  createSubscription, getOwnedSubscription, getSubscriptionSnapshot, MAX_CHUNK_BYTES,
  publishNodeSnapshot, readSnapshotNodes, SnapshotIntegrityError,
} from "../src/storage.ts";
import type { NodeRecord, SubscriptionSnapshot } from "../src/storage.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
  r2Buckets: ["NODES"],
});

let db: D1Database;
let bucket: R2Bucket;
const owner = "9007199254740993";
const otherOwner = "9007199254740992";
const sourceUrl = "https://provider.example.invalid/subscription";

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const sql = await readFile(new URL("../migrations/0001_subscriptions.sql", import.meta.url), "utf8");
  const statements = sql.trim().split(/;\s*/u).filter(Boolean);
  await db.batch(statements.map((statement) => db.prepare(statement)));
});

after(() => miniflare.dispose());

async function create() {
  return createSubscription(db, { ownerId: owner, name: "Synthetic", sourceUrl });
}

async function loadPublished(token: string): Promise<SubscriptionSnapshot> {
  const snapshot = await getSubscriptionSnapshot(db, token);
  assert.ok(snapshot);
  return snapshot;
}

async function collect(snapshot: SubscriptionSnapshot): Promise<NodeRecord[]> {
  const records = [];
  for await (const node of readSnapshotNodes(bucket, snapshot)) {
    records.push(node);
  }
  return records;
}

test("uses exact owner IDs and hides unpublished or invalid capabilities", async () => {
  const subscription = await create();
  assert.deepEqual(await getOwnedSubscription(db, owner, subscription.id), subscription);
  assert.equal(await getOwnedSubscription(db, otherOwner, subscription.id), null);
  assert.equal(await getSubscriptionSnapshot(db, subscription.token), null);
  assert.equal(await getSubscriptionSnapshot(db, `${subscription.token}\n`), null);
  assert.equal(await publishNodeSnapshot(db, bucket, {
    id: subscription.id, ownerId: otherOwner, expectedGeneration: 0,
  }, [{ name: "Unauthorized" }]), false);
  for (const ownerId of ["012", "0", "1\n", "9223372036854775808"]) {
    await assert.rejects(createSubscription(db, { ownerId, name: "Invalid", sourceUrl }), /Invalid subscription owner/u);
  }
});

test("provider expiry is metadata and does not revoke a published capability", async () => {
  const { id, token } = await create();
  const node = { name: "Published" };
  assert.equal(await publishNodeSnapshot(db, bucket, { id, ownerId: owner, expectedGeneration: 0 }, [node]), true);
  const snapshot = await loadPublished(token);
  const now = Math.floor(Date.now() / 1000);
  for (const expiry of [now - 3600, now, now + 3600, null]) {
    await db.prepare("UPDATE subscriptions SET expire_at = ? WHERE id = ?").bind(expiry, id).run();
    assert.equal((await getOwnedSubscription(db, owner, id))?.expireAt, expiry);
    assert.deepEqual(await loadPublished(token), snapshot);
  }
  assert.deepEqual(await collect(snapshot), [node]);
});

test("publishes and reads more than 2 MB as bounded R2 chunks", async () => {
  const { id, token } = await create();
  const item = "测".repeat(100_000);
  async function* nodes() {
    for (let index = 0; index < 8; index += 1) {
      yield { name: `Node ${index}`, options: item };
    }
  }
  assert.equal(await publishNodeSnapshot(db, bucket, { id, ownerId: owner, expectedGeneration: 0 }, nodes()), true);
  const snapshot = await loadPublished(token);
  assert.equal(snapshot.generation, 1);
  assert.equal(snapshot.nodeCount, 8);
  assert.deepEqual(Object.keys(snapshot).sort(), ["generation", "id", "manifestSha256", "nodeCount", "snapshotId"]);
  const prefix = `subscriptions/${id}/${snapshot.snapshotId}/`;
  const objects = (await bucket.list({ prefix })).objects;
  const chunks = objects.filter((object) => object.key.endsWith(".ndjson"));
  assert.ok(chunks.length > 1);
  assert.ok(chunks.every((chunk) => chunk.size <= MAX_CHUNK_BYTES));
  assert.ok(chunks.reduce((total, chunk) => total + chunk.size, 0) > 2_000_000);
  let index = 0;
  for await (const node of readSnapshotNodes(bucket, snapshot)) {
    assert.equal(node.name, `Node ${index}`);
    assert.equal(node.options, item);
    index += 1;
  }
  assert.equal(index, 8);
});

test("preserves the current snapshot when a refresh is empty, oversized, or fails in R2", async () => {
  const { id, token } = await create();
  const previous = { name: "Previous" };
  assert.equal(await publishNodeSnapshot(db, bucket, { id, ownerId: owner, expectedGeneration: 0 }, [previous]), true);
  const current = await loadPublished(token);
  const target = { id, ownerId: owner, expectedGeneration: 1 };
  await assert.rejects(publishNodeSnapshot(db, bucket, target, []), /empty subscription snapshot/u);
  await assert.rejects(publishNodeSnapshot(db, bucket, target, [{ name: "x".repeat(MAX_CHUNK_BYTES) }]), /exceeds storage limits/u);
  const failedManifest = {
    put: (key: string, value: Uint8Array<ArrayBuffer>, options: R2PutOptions) => {
      if (key.endsWith("manifest.json")) {
        throw new Error("Synthetic R2 failure");
      }
      return bucket.put(key, value, options);
    },
    delete: (keys: string[]) => bucket.delete(keys),
  } as R2Bucket;
  await assert.rejects(publishNodeSnapshot(db, failedManifest, target, [{ name: "Failed" }]), /Synthetic R2 failure/u);
  assert.deepEqual(await loadPublished(token), current);
  assert.deepEqual(await collect(current), [previous]);
  assert.equal((await bucket.list({ prefix: `subscriptions/${id}/` })).objects.length, 2);
});

test("concurrent publishers use a single D1 CAS winner and keep the previous immutable version", { timeout: 20_000 }, async () => {
  const { id, token } = await create();
  assert.equal(await publishNodeSnapshot(db, bucket, { id, ownerId: owner, expectedGeneration: 0 }, [{ name: "Previous" }]), true);
  const previous = await loadPublished(token);
  const { promise, resolve } = Promise.withResolvers<void>();
  let waiting = 0;
  const racingBucket = {
    put: async (key: string, value: Uint8Array<ArrayBuffer>, options: R2PutOptions) => {
      if (key.endsWith(".ndjson")) {
        waiting += 1;
        if (waiting === 2) resolve();
        await promise;
      }
      return bucket.put(key, value, options);
    },
    delete: (keys: string[]) => bucket.delete(keys),
  } as R2Bucket;
  const target = { id, ownerId: owner, expectedGeneration: 1 };
  const names = ["First", "Second"];
  const results = await Promise.all(names.map((name) => publishNodeSnapshot(db, racingBucket, target, [{ name }])));
  assert.equal(results.filter(Boolean).length, 1);
  const winner = await loadPublished(token);
  assert.equal(winner.generation, 2);
  assert.deepEqual(await collect(winner), [{ name: names[results.indexOf(true)] }]);
  assert.deepEqual(await collect(previous), [{ name: "Previous" }]);
  assert.equal((await bucket.list({ prefix: `subscriptions/${id}/` })).objects.length, 4);
});

test("rejects missing and same-size corrupted published objects", async () => {
  const { id, token } = await create();
  assert.equal(await publishNodeSnapshot(db, bucket, {
    id, ownerId: owner, expectedGeneration: 0,
  }, [{ name: "original" }]), true);
  const snapshot = await loadPublished(token);
  const prefix = `subscriptions/${id}/${snapshot.snapshotId}/`;
  await bucket.put(`${prefix}0.ndjson`, '{"name":"tampered"}\n');
  await assert.rejects(collect(snapshot), SnapshotIntegrityError);
  await bucket.delete(`${prefix}manifest.json`);
  await assert.rejects(collect(snapshot), SnapshotIntegrityError);
});

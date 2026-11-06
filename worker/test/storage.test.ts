import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import {
  createSubscription, getOwnedSubscription, getSubscriptionSnapshot, MAX_CHUNK_BYTES, MAX_SNAPSHOT_BYTES,
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
  for (const migration of ["0001_subscriptions.sql", "0003_subscription_lifecycle.sql"]) {
    const sql = await readFile(new URL(`../migrations/${migration}`, import.meta.url), "utf8");
    const statements = sql.trim().split(/;\s*/u).filter(Boolean);
    await db.batch(statements.map((statement) => db.prepare(statement)));
  }
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
    id: subscription.id, ownerId: otherOwner, expectedGeneration: 0, expectedLifecycleRevision: 0,
  }, [{ name: "Unauthorized" }]), false);
  for (const ownerId of ["012", "0", "1\n", "9223372036854775808"]) {
    await assert.rejects(createSubscription(db, { ownerId, name: "Invalid", sourceUrl }), /Invalid subscription owner/u);
  }
});

test("provider expiry is metadata and does not revoke a published capability", async () => {
  const { id, token } = await create();
  const node = { name: "Published" };
  const target = { id, ownerId: owner, expectedGeneration: 0, expectedLifecycleRevision: 0 };
  assert.equal(await publishNodeSnapshot(db, bucket, target, [node]), true);
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
  const target = { id, ownerId: owner, expectedGeneration: 0, expectedLifecycleRevision: 0 };
  assert.equal(await publishNodeSnapshot(db, bucket, target, nodes()), true);
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
  const initial = { id, ownerId: owner, expectedGeneration: 0, expectedLifecycleRevision: 0 };
  assert.equal(await publishNodeSnapshot(db, bucket, initial, [previous]), true);
  const current = await loadPublished(token);
  const target = { ...initial, expectedGeneration: 1 };
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
  const initial = { id, ownerId: owner, expectedGeneration: 0, expectedLifecycleRevision: 0 };
  assert.equal(await publishNodeSnapshot(db, bucket, initial, [{ name: "Previous" }]), true);
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
  const target = { ...initial, expectedGeneration: 1 };
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
    id, ownerId: owner, expectedGeneration: 0, expectedLifecycleRevision: 0,
  }, [{ name: "original" }]), true);
  const snapshot = await loadPublished(token);
  const prefix = `subscriptions/${id}/${snapshot.snapshotId}/`;
  await bucket.put(`${prefix}0.ndjson`, '{"name":"tampered"}\n');
  await assert.rejects(collect(snapshot), SnapshotIntegrityError);
  await bucket.delete(`${prefix}manifest.json`);
  await assert.rejects(collect(snapshot), SnapshotIntegrityError);
});

test("rejects a manifest one byte over the snapshot limit before requesting any chunk", async () => {
  const sha256 = "a".repeat(64);
  const sizes = [...Array<number>(127).fill(MAX_CHUNK_BYTES), MAX_CHUNK_BYTES - 2, 3];
  assert.equal(sizes.reduce((total, size) => total + size, 0), MAX_SNAPSHOT_BYTES + 1);
  const manifest = new TextEncoder().encode(JSON.stringify({
    version: 1, chunks: sizes.map((bytes) => ({ bytes, sha256, count: 1 })),
  }));
  const snapshot: SubscriptionSnapshot = {
    id: 123, generation: 1, snapshotId: "11111111-1111-4111-8111-111111111111",
    manifestSha256: createHash("sha256").update(manifest).digest("hex"), nodeCount: sizes.length,
  };
  const manifestKey = `subscriptions/${snapshot.id}/${snapshot.snapshotId}/manifest.json`;
  const reads: string[] = [];
  const syntheticBucket = {
    get: async (key: string) => {
      reads.push(key);
      return key === manifestKey ? { size: manifest.byteLength, arrayBuffer: async () => manifest.buffer } : null;
    },
  } as unknown as R2Bucket;
  await assert.rejects(async () => readSnapshotNodes(syntheticBucket, snapshot).next(), SnapshotIntegrityError);
  assert.deepEqual(reads, [manifestKey]);
});

function delayedSnapshot() {
  const bodies = Array.from({ length: 8 }, (_, index) => new TextEncoder().encode(`{"name":"Node ${index}"}\n`));
  const hash = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
  const manifest = new TextEncoder().encode(JSON.stringify({
    version: 1, chunks: bodies.map((bytes) => ({ bytes: bytes.byteLength, sha256: hash(bytes), count: 1 })),
  }));
  const snapshot: SubscriptionSnapshot = {
    id: 123, generation: 1, snapshotId: "11111111-1111-4111-8111-111111111111",
    manifestSha256: hash(manifest), nodeCount: bodies.length,
  };
  const prefix = `subscriptions/${snapshot.id}/${snapshot.snapshotId}/`;
  const firstStarted = Promise.withResolvers<void>();
  const gates = bodies.map(() => Promise.withResolvers<boolean>());
  const finished = bodies.map(() => Promise.withResolvers<void>());
  const reads: number[] = [];
  let active = 0;
  let peak = 0;
  const delayedBucket = {
    async get(key: string) {
      if (key === `${prefix}manifest.json`) {
        return { size: manifest.byteLength, arrayBuffer: async () => manifest.buffer };
      }
      assert.ok(key.startsWith(prefix) && key.endsWith(".ndjson"));
      const index = Number(key.slice(prefix.length, -".ndjson".length));
      const bytes = bodies[index];
      assert.ok(bytes);
      reads.push(index);
      if (reads.length === 1) firstStarted.resolve();
      active += 1;
      peak = Math.max(peak, active);
      return {
        size: bytes.byteLength,
        async arrayBuffer() {
          try {
            if (await gates[index].promise) throw new Error("Synthetic read failure");
            return bytes.buffer;
          } finally {
            active -= 1;
            finished[index].resolve();
          }
        },
      };
    },
  } as unknown as R2Bucket;
  return {
    snapshot, delayedBucket, firstStarted, gates, finished, reads,
    get active() { return active; },
    get peak() { return peak; },
  };
}

test("reads ahead four chunks and refills in order despite out-of-order reads", async () => {
  const fixture = delayedSnapshot();
  const nodes = readSnapshotNodes(fixture.delayedBucket, fixture.snapshot);
  const first = nodes.next();
  try {
    await fixture.firstStarted.promise;
    assert.deepEqual(fixture.reads, [0, 1, 2, 3]);
    assert.equal(fixture.active, 4);

    for (const index of [3, 2, 1]) {
      fixture.gates[index].resolve(false);
      await fixture.finished[index].promise;
    }
    assert.deepEqual(fixture.reads, [0, 1, 2, 3]);
    assert.equal(fixture.active, 1);
    fixture.gates[0].resolve(false);
    assert.deepEqual(await first, { done: false, value: { name: "Node 0" } });
    assert.deepEqual(fixture.reads, [0, 1, 2, 3]);
    assert.deepEqual(await nodes.next(), { done: false, value: { name: "Node 1" } });
    assert.deepEqual(fixture.reads, [0, 1, 2, 3, 4]);

    for (const gate of fixture.gates) gate.resolve(false);
    const remaining = [];
    for await (const node of nodes) remaining.push(node.name);
    assert.deepEqual(remaining, ["Node 2", "Node 3", "Node 4", "Node 5", "Node 6", "Node 7"]);
    assert.equal(fixture.peak, 4);
    assert.equal(fixture.active, 0);
  } finally {
    for (const gate of fixture.gates) gate.resolve(false);
    await first.catch(() => {});
    await nodes.return(undefined);
  }
});

test("aborting a snapshot drains read-ahead failures without scheduling another chunk", async () => {
  const fixture = delayedSnapshot();
  const cancellation = new AbortController();
  const nodes = readSnapshotNodes(fixture.delayedBucket, fixture.snapshot, cancellation.signal);
  const first = nodes.next();
  try {
    await fixture.firstStarted.promise;
    assert.deepEqual(fixture.reads, [0, 1, 2, 3]);
    fixture.gates[0].resolve(false);
    assert.deepEqual(await first, { done: false, value: { name: "Node 0" } });
    cancellation.abort();
    let stopped = false;
    const closing = nodes.next().then((result) => {
      stopped = true;
      return result;
    });
    await new Promise<void>((resolve) => setImmediate(resolve));
    assert.equal(stopped, false);

    fixture.gates[3].resolve(true);
    fixture.gates[2].resolve(false);
    fixture.gates[1].resolve(false);
    assert.deepEqual(await closing, { done: true, value: undefined });
    assert.deepEqual(fixture.reads, [0, 1, 2, 3]);
    assert.equal(fixture.active, 0);
  } finally {
    for (const gate of fixture.gates) gate.resolve(false);
    await first.catch(() => {});
    await nodes.return(undefined);
  }
});

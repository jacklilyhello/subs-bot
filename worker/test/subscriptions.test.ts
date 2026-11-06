import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import {
  createSubscription, getOwnedSubscription, getSubscriptionSnapshot, publishNodeSnapshot, readSnapshotNodes,
  type SubscriptionMetadata,
} from "../src/storage.ts";
import {
  listDeletedSubscriptions, listOwnedSubscriptions, renameOwnedSubscription,
  restoreOwnedSubscription, trashOwnedSubscription,
} from "../src/subscriptions.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
  r2Buckets: ["NODES"],
});
let db: D1Database;
let bucket: R2Bucket;
const sourceUrl = "https://provider.example.invalid/subscription?token=synthetic-private-source";
const node = { name: "Synthetic node", share: "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.12:8388#synthetic" };
const THIRTY_DAYS = 2_592_000;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  for (const file of ["0001_subscriptions.sql", "0002_telegram.sql", "0003_subscription_lifecycle.sql"]) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

after(() => miniflare.dispose());

function create(ownerId: string, name: string): Promise<SubscriptionMetadata> {
  return createSubscription(db, { ownerId, name, sourceUrl });
}

function target(row: SubscriptionMetadata, expectedLifecycleRevision = row.lifecycleRevision) {
  return { id: row.id, ownerId: row.ownerId, expectedLifecycleRevision };
}

async function published(ownerId: string, name: string) {
  const row = await create(ownerId, name);
  assert.equal(await publishNodeSnapshot(db, bucket, { ...target(row), expectedGeneration: row.generation }, [node]), true);
  const current = await getOwnedSubscription(db, ownerId, row.id);
  const snapshot = await getSubscriptionSnapshot(db, row.token);
  assert.ok(current);
  assert.ok(snapshot);
  return { row: current, snapshot };
}

async function deletedRevision(row: SubscriptionMetadata): Promise<number> {
  const { items } = await listDeletedSubscriptions(db, row.ownerId, { limit: 10 });
  const deleted = items.find(({ id }) => id === row.id);
  assert.ok(deleted);
  return deleted.lifecycleRevision;
}

test("lists only owned metadata with bounded keyset pages and no bearer or provider fields", async () => {
  const owner = "9007199254740993";
  const neighbor = "9007199254740992";
  const first = await create(owner, "First");
  const foreign = await create(neighbor, "Foreign");
  const second = await create(owner, "Second");
  const third = await create(owner, "Third");
  await db.prepare("UPDATE subscriptions SET expire_at = ?, traffic_used = ?, traffic_total = ?, last_error = ? WHERE id = ?")
    .bind(1794000000, 1.25, 8.5, "synthetic-private-failure", first.id).run();

  const page = await listOwnedSubscriptions(db, owner, { limit: 2 });
  assert.deepEqual(page, {
    items: [
      { id: first.id, name: "First", expireAt: 1794000000, trafficUsed: 1.25, trafficTotal: 8.5,
        nodeCount: 0, lifecycleRevision: 0 },
      { id: second.id, name: "Second", expireAt: null, trafficUsed: null, trafficTotal: null,
        nodeCount: 0, lifecycleRevision: 0 },
    ],
    nextAfterId: second.id,
  });
  const next = await listOwnedSubscriptions(db, owner, { limit: 2, afterId: page.nextAfterId! });
  assert.deepEqual(next.items.map(({ id }) => id), [third.id]);
  assert.equal(next.nextAfterId, null);
  assert.deepEqual(await listOwnedSubscriptions(db, owner, { limit: 2, afterId: third.id }),
    { items: [], nextAfterId: null });
  assert.deepEqual((await listOwnedSubscriptions(db, neighbor, { limit: 1 })).items.map(({ id }) => id), [foreign.id]);
  assert.equal((await listOwnedSubscriptions(db, owner, { limit: 50 })).items.length, 3);
  for (const invalid of [0, 1.5, 51]) {
    await assert.rejects(listOwnedSubscriptions(db, owner, { limit: invalid }), RangeError);
  }
  await assert.rejects(listOwnedSubscriptions(db, owner, { limit: 1, afterId: Number.MAX_SAFE_INTEGER + 1 }), RangeError);
  await assert.rejects(listOwnedSubscriptions(db, "090", { limit: 1 }), RangeError);
});

test("renames only the owner at the observed lifecycle revision and fences concurrent stale writes", async () => {
  const row = await create("9007199254740994", "Before");
  const initial = target(row);
  for (const invalid of ["   ", "😀".repeat(65), "bad\nname", "\ud800"]) {
    await assert.rejects(renameOwnedSubscription(db, initial, invalid), RangeError);
  }
  assert.equal(await renameOwnedSubscription(db, { ...initial, ownerId: "9007199254740995" }, "Foreign"), false);
  const results = await Promise.all([
    renameOwnedSubscription(db, initial, "After"),
    trashOwnedSubscription(db, initial),
  ]);
  assert.deepEqual(results.toSorted(), [false, true]);
  if (results[0]) {
    const renamed = await getOwnedSubscription(db, row.ownerId, row.id);
    assert.equal(renamed?.name, "After");
    assert.equal(renamed?.lifecycleRevision, row.lifecycleRevision + 1);
    assert.equal(await trashOwnedSubscription(db, initial), false);
  } else {
    assert.equal(await getOwnedSubscription(db, row.ownerId, row.id), null);
    assert.equal(await deletedRevision(row), row.lifecycleRevision + 1);
    assert.equal(await renameOwnedSubscription(db, initial, "Stale"), false);
  }
});

test("moves deleted rows out of legacy reads and restores the same capability and immutable snapshot", async () => {
  const { row, snapshot } = await published("9007199254740996", "Original");
  const scope = target(row);
  const renamedName = "A".repeat(63) + "😀";
  assert.equal(await renameOwnedSubscription(db, scope, `  ${renamedName}  `), true);
  const renamed = await getOwnedSubscription(db, row.ownerId, row.id);
  assert.equal(renamed?.name, renamedName);
  assert.ok(renamed);
  assert.equal(renamed.token, row.token);
  assert.equal(renamed.lifecycleRevision, row.lifecycleRevision + 1);
  assert.equal(await trashOwnedSubscription(db, scope), false);
  assert.equal(await trashOwnedSubscription(db, { ...target(renamed), ownerId: "9007199254740995" }), false);

  const prefix = `subscriptions/${row.id}/${snapshot.snapshotId}/`;
  const objectKeys = (await bucket.list({ prefix })).objects.map(({ key }) => key).sort();
  assert.deepEqual(objectKeys, [`${prefix}0.ndjson`, `${prefix}manifest.json`]);
  assert.equal(await trashOwnedSubscription(db, target(renamed)), true);
  assert.equal(await getOwnedSubscription(db, row.ownerId, row.id), null);
  assert.equal(await getSubscriptionSnapshot(db, row.token), null);
  assert.equal(await db.prepare("SELECT id FROM subscriptions WHERE token = ? AND generation > 0")
    .bind(row.token).first(), null);
  const oldList = await db.prepare("SELECT name FROM subscriptions WHERE owner_id = ? ORDER BY id LIMIT ?")
    .bind(row.ownerId, 21).all();
  assert.deepEqual(oldList.results, []);
  assert.deepEqual((await bucket.list({ prefix })).objects.map(({ key }) => key).sort(), objectKeys);

  const inTrash = await listDeletedSubscriptions(db, row.ownerId, { limit: 1 });
  assert.equal(inTrash.items.length, 1);
  const [deleted] = inTrash.items;
  assert.deepEqual(deleted, {
    id: row.id, name: renamedName, expireAt: null, trafficUsed: null, trafficTotal: null,
    nodeCount: 1, lifecycleRevision: row.lifecycleRevision + 2, deletedAt: deleted.deletedAt,
  });
  assert.ok(Number.isSafeInteger(deleted.deletedAt) && deleted.deletedAt > 0);
  assert.deepEqual(await listDeletedSubscriptions(db, "9007199254740995", { limit: 1 }), { items: [], nextCursor: null });
  const restore = target(row, deleted.lifecycleRevision);
  assert.equal(await restoreOwnedSubscription(db, { ...restore, ownerId: "9007199254740995" }), false);
  assert.equal(await restoreOwnedSubscription(db, scope), false);
  const restored = await Promise.all([restoreOwnedSubscription(db, restore), restoreOwnedSubscription(db, restore)]);
  assert.deepEqual(restored.toSorted(), [false, true]);
  assert.equal(await trashOwnedSubscription(db, target(renamed)), false);
  const active = await getOwnedSubscription(db, row.ownerId, row.id);
  assert.equal(active?.id, row.id);
  assert.equal(active?.token, row.token);
  assert.equal(active?.sourceUrl, row.sourceUrl);
  assert.equal(active?.createdAt, row.createdAt);
  assert.equal(active?.lifecycleRevision, row.lifecycleRevision + 3);
  assert.deepEqual(await getSubscriptionSnapshot(db, row.token), snapshot);
  const records = [];
  for await (const record of readSnapshotNodes(bucket, snapshot)) records.push(record);
  assert.deepEqual(records, [node]);
  assert.deepEqual((await bucket.list({ prefix })).objects.map(({ key }) => key).sort(), objectKeys);
  assert.deepEqual(await listDeletedSubscriptions(db, row.ownerId, { limit: 1 }), { items: [], nextCursor: null });
});

test("paginates trash deterministically on tied dates and enforces the 30-day restore boundary", async () => {
  const owner = "9007199254740997";
  const first = await create(owner, "First");
  const second = await create(owner, "Second");
  const expired = await create(owner, "Expired");
  for (const row of [first, second, expired]) assert.equal(await trashOwnedSubscription(db, target(row)), true);
  await db.batch([
    db.prepare("UPDATE subscription_trash SET deleted_at = unixepoch() - ? WHERE id IN (?, ?)")
      .bind(THIRTY_DAYS - 60, first.id, second.id),
    db.prepare("UPDATE subscription_trash SET deleted_at = unixepoch() - ? WHERE id = ?")
      .bind(THIRTY_DAYS + 1, expired.id),
  ]);

  const page = await listDeletedSubscriptions(db, owner, { limit: 1 });
  assert.deepEqual(page.items.map(({ id }) => id), [second.id]);
  assert.deepEqual(page.nextCursor, { deletedAt: page.items[0].deletedAt, id: second.id });
  const next = await listDeletedSubscriptions(db, owner, { limit: 1, after: page.nextCursor! });
  assert.deepEqual(next.items.map(({ id }) => id), [first.id]);
  assert.equal(next.nextCursor, null);
  await assert.rejects(listDeletedSubscriptions(db, owner, { limit: 51 }), RangeError);
  await assert.rejects(listDeletedSubscriptions(db, owner, { limit: 1, after: { deletedAt: 0, id: first.id } }), RangeError);
  assert.equal(await restoreOwnedSubscription(db, target(expired, expired.lifecycleRevision + 1)), false);
  assert.equal(await getOwnedSubscription(db, owner, expired.id), null);

  // Retry only if the D1 clock crossed a second while issuing the boundary query.
  let restored = false;
  for (let attempt = 0; attempt < 3 && !restored; attempt += 1) {
    const boundary = await db.prepare(`
      UPDATE subscription_trash SET deleted_at = unixepoch() - ?
      WHERE id = ? RETURNING deleted_at + ? AS testedAt
    `).bind(THIRTY_DAYS, first.id, THIRTY_DAYS).first<{ testedAt: number }>();
    assert.ok(boundary);
    restored = await restoreOwnedSubscription(db, target(first, first.lifecycleRevision + 1));
    if (!restored) {
      const after = await db.prepare("SELECT unixepoch() AS now").first<{ now: number }>();
      assert.ok(after && after.now > boundary.testedAt, "The exact 30-day cutoff must be inclusive.");
    }
  }
  assert.ok(restored);
});

test("keeps the active row and revision if the transactional trash move aborts", async () => {
  const row = await create("9007199254740999", "Transactional fixture");
  await db.prepare(`
    CREATE TRIGGER reject_test_trash BEFORE DELETE ON subscriptions
    WHEN OLD.id = ${row.id}
    BEGIN SELECT RAISE(ABORT, 'synthetic trash error'); END
  `).run();
  try {
    await assert.rejects(trashOwnedSubscription(db, target(row)));
    assert.deepEqual(await getOwnedSubscription(db, row.ownerId, row.id), row);
    assert.deepEqual(await listDeletedSubscriptions(db, row.ownerId, { limit: 1 }), { items: [], nextCursor: null });
  } finally {
    await db.prepare("DROP TRIGGER reject_test_trash").run();
  }
  assert.equal(await trashOwnedSubscription(db, target(row)), true);
  assert.equal(await deletedRevision(row), row.lifecycleRevision + 1);
});

test("rejects a snapshot publication that straddles a delete and restore", { timeout: 10_000 }, async () => {
  const { row, snapshot } = await published("9007199254740998", "Snapshot race");
  let entered!: () => void;
  let unblock!: () => void;
  const enteredPut = new Promise<void>((resolve) => { entered = resolve; });
  const unblockPut = new Promise<void>((resolve) => { unblock = resolve; });
  let stalled = false;
  const delayedBucket = {
    async put(key: string, bytes: Uint8Array<ArrayBuffer>, options: R2PutOptions) {
      if (!stalled) {
        stalled = true;
        entered();
        await unblockPut;
      }
      return bucket.put(key, bytes, options);
    },
    delete: (keys: string[]) => bucket.delete(keys),
  } as unknown as R2Bucket;
  const stalePublication = publishNodeSnapshot(
    db, delayedBucket, { ...target(row), expectedGeneration: row.generation }, [{ name: "Stale snapshot" }],
  );
  try {
    await Promise.race([
      enteredPut,
      stalePublication.then(() => assert.fail("Publication stopped before reaching the controlled R2 write.")),
    ]);
    assert.equal(await trashOwnedSubscription(db, target(row)), true);
    assert.equal(await restoreOwnedSubscription(db, target(row, await deletedRevision(row))), true);
  } finally {
    unblock();
  }
  assert.equal(await stalePublication, false);
  assert.deepEqual(await getSubscriptionSnapshot(db, row.token), snapshot);
  const kept = (await bucket.list({ prefix: `subscriptions/${row.id}/` })).objects.map(({ key }) => key);
  assert.ok(kept.length === 2 && kept.every((key) => key.startsWith(`subscriptions/${row.id}/${snapshot.snapshotId}/`)));
});

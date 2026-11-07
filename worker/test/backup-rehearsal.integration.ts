import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";

import { Miniflare } from "miniflare";

import { claimPrivateShare, createPrivateShare } from "../src/private-shares.ts";
import { createSubscription, getOwnedSubscription, publishNodeSnapshot, type SubscriptionMetadata } from "../src/storage.ts";
import { renameOwnedSubscription, restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import { captureSyntheticBackup, restoreSyntheticBackup, sealSyntheticBackup } from "./isolation-backup.ts";

const sha256 = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const ownerA = "900005101";
const ownerB = "900005102";
const botId = "900005103";
const activeShare = "hy2://synthetic@active.example.invalid#港";
const trashedShare = "hy2://synthetic@trashed.example.invalid#回收";
const privateContent = "Synthetic private content · 仅用于演练";

async function fixtureInputs() {
  const directory = process.env.WORKER_TEST_BUNDLE_DIR;
  assert(directory, "Missing hosted artifact directory");
  const manifest = JSON.parse(await readFile(join(directory, "isolation.json"), "utf8")) as {
    revision: string; compatibilityDate: string; bundleSha256: string;
    migrations: { name: string; sha256: string }[];
  };
  const module = await readFile(join(directory, "index.js"));
  assert.equal(sha256(module), manifest.bundleSha256);
  assert.equal(manifest.revision, process.env.BUILD_REVISION);
  const migrations = await Promise.all(manifest.migrations.map(async ({ name, sha256: expected }) => {
    assert.match(name, /^\d{4}_[a-z0-9_]+\.sql$/u);
    const sql = await readFile(join(directory, name));
    assert.equal(sha256(sql), expected);
    return sql.toString("utf8");
  }));
  return {
    migrations,
    runtime: () => new Miniflare({
      modules: true,
      script: module.toString("utf8"),
      compatibilityDate: manifest.compatibilityDate,
      bindings: { BUILD_REVISION: manifest.revision },
      d1Databases: ["DB"], r2Buckets: ["NODES"],
    }),
  };
}

async function setup(db: D1Database, migrations: readonly string[]): Promise<void> {
  for (const sql of migrations) {
    const statements = sql.trim().split(/;\s*/u).filter(Boolean);
    const results = await db.batch(statements.map((statement) => db.prepare(statement)));
    assert(results.every(({ success }) => success));
  }
}

function lifecycle({ id, ownerId, lifecycleRevision }: SubscriptionMetadata) {
  return { id, ownerId, expectedLifecycleRevision: lifecycleRevision };
}

async function seed(db: D1Database, bucket: R2Bucket) {
  const sourceUrl = "uploaded://synthetic-backup-rehearsal";
  const active = await createSubscription(db, { ownerId: ownerA, name: "Synthetic active", sourceUrl });
  const trashed = await createSubscription(db, { ownerId: ownerB, name: "Synthetic trash", sourceUrl });
  for (const [sub, share] of [[active, activeShare], [trashed, trashedShare]] as const) {
    assert.equal(await publishNodeSnapshot(db, bucket, { ...lifecycle(sub), expectedGeneration: 0 }, [{ share }]), true);
  }
  await db.prepare("UPDATE subscriptions SET expire_at = 1893456000, traffic_used = 1.25, traffic_total = 9.5 WHERE id = ?")
    .bind(active.id).run();
  assert.equal(await renameOwnedSubscription(db, lifecycle(active), "Synthetic renamed"), true);
  assert.equal(await trashOwnedSubscription(db, lifecycle(trashed)), true);
  assert(trashed.id > active.id);
  const privateShare = await createPrivateShare(db, bucket, { botId, senderId: ownerB, senderName: "Synthetic sender",
    content: privateContent, maxClaims: 1, targetUserId: null, durationMinutes: 15 });
  assert.equal((await claimPrivateShare(db, bucket, { botId, actorId: ownerA, code: privateShare.code })).kind, "claimed");
  await bucket.put("unreferenced-synthetic-object", "not part of the sealed backup");
  return { active, trashed, privateShare };
}

async function request(runtime: Miniflare, token: string, method = "GET") {
  return runtime.dispatchFetch(`https://restore-fixture.invalid/sub/${token}/base64`, {
    method, headers: { "Accept-Encoding": "identity" },
  });
}

async function exported(runtime: Miniflare, token: string): Promise<Buffer> {
  const response = await request(runtime, token);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("Cache-Control"), "private, no-store");
  assert.equal(response.headers.get("Referrer-Policy"), "no-referrer");
  const body = Buffer.from(await response.arrayBuffer());
  assert.equal(response.headers.get("Content-Length"), String(body.length));
  return body;
}

test("the emitted Worker reads an independently restored synthetic D1 and R2 backup", { timeout: 60_000 }, async () => {
  const { migrations, runtime } = await fixtureInputs();
  const source = runtime();
  const target = runtime();
  try {
    const sourceDb = await source.getD1Database("DB");
    const sourceBucket = await source.getR2Bucket("NODES");
    const targetDb = await target.getD1Database("DB");
    const targetBucket = await target.getR2Bucket("NODES");
    await setup(sourceDb, migrations);
    await setup(targetDb, migrations);
    const { active, trashed, privateShare } = await seed(sourceDb, sourceBucket);

    const original = await exported(source, active.token);
    assert.equal(original.toString("utf8"), Buffer.from(activeShare).toString("base64"));
    const backup = await captureSyntheticBackup(sourceDb, sourceBucket, migrations);
    assert.equal((await captureSyntheticBackup(sourceDb, sourceBucket, migrations)).sha256, backup.sha256);
    const parseBackup = () => JSON.parse(backup.body.toString("utf8"));
    assert.equal(parseBackup().objects.length, 5);
    assert.equal(backup.body.includes(Buffer.from(privateShare.code)), false);

    const changed = Buffer.concat([backup.body, Buffer.from(" ")]);
    const missingObject = parseBackup();
    missingObject.objects.pop();
    const changedObject = parseBackup();
    const stored = changedObject.objects[0];
    stored.base64 = (stored.base64.startsWith("A") ? "B" : "A") + stored.base64.slice(1);
    const orphanClaim = parseBackup();
    orphanClaim.rows.private_share_claims[0][0] += 10;
    const mismatchedTrash = parseBackup();
    mismatchedTrash.rows.subscription_trash[0][16] += 1;
    const wrongSchema = parseBackup();
    wrongSchema.schemaSha256 = "0".repeat(64);
    for (const rejected of [{ body: changed, sha256: backup.sha256 },
      ...[missingObject, changedObject, orphanClaim, mismatchedTrash, wrongSchema].map(sealSyntheticBackup)]) {
      await assert.rejects(restoreSyntheticBackup(rejected, migrations, targetDb, targetBucket), /restore could not be verified/u);
      assert.equal((await targetBucket.list()).objects.length, 0);
      assert.equal(await targetDb.prepare("SELECT count(*) AS n FROM subscriptions").first("n"), 0);
      assert.equal(await targetDb.prepare("SELECT count(*) AS n FROM subscription_trash").first("n"), 0);
    }

    // Inject a failure during the R2 phase to show D1 pointers are still absent.
    let writes = 0;
    const failSecondWrite = new Proxy(targetBucket, {
      get(bucket, field) {
        if (field === "list") return bucket.list.bind(bucket);
        if (field === "put") return async (key: string, body: Uint8Array, options: R2PutOptions) => {
          if (++writes === 2) return null;
          return bucket.put(key, body, options);
        };
        return Reflect.get(bucket, field);
      },
    });
    await assert.rejects(restoreSyntheticBackup(backup, migrations, targetDb, failSecondWrite), /restore could not be verified/u);
    assert.equal(writes, 2);
    assert.equal((await request(target, active.token)).status, 404);
    const partialObjects = (await targetBucket.list()).objects;
    assert.equal(partialObjects.length, 1);
    await targetBucket.delete(partialObjects[0].key);

    await restoreSyntheticBackup(backup, migrations, targetDb, targetBucket);
    assert.deepEqual((await targetDb.prepare("PRAGMA foreign_key_check").all()).results, []);
    assert.equal((await captureSyntheticBackup(targetDb, targetBucket, migrations)).sha256, backup.sha256);
    assert.equal(await targetBucket.get("unreferenced-synthetic-object"), null);
    assert.deepEqual(await exported(target, active.token), original);
    const head = await request(target, active.token, "HEAD");
    assert.equal(head.status, 200);
    assert.equal(head.body, null);
    assert.equal((await request(target, trashed.token)).status, 404);
    assert.equal(await getOwnedSubscription(targetDb, ownerB, active.id), null);
    assert.deepEqual(await getOwnedSubscription(targetDb, ownerA, active.id), await getOwnedSubscription(sourceDb, ownerA, active.id));
    assert.equal(await restoreOwnedSubscription(targetDb, { ...lifecycle(trashed), ownerId: ownerA, expectedLifecycleRevision: 1 }), false);

    // This insert happens while the source's largest ID is still in the trash.
    const next = await createSubscription(targetDb, { ownerId: ownerA, name: "After restore", sourceUrl: "uploaded://synthetic-new" });
    assert(next.id > trashed.id);
    assert.equal(await restoreOwnedSubscription(targetDb, { ...lifecycle(trashed), expectedLifecycleRevision: 1 }), true);
    assert.equal((await exported(target, trashed.token)).toString("utf8"), Buffer.from(trashedShare).toString("base64"));
    assert.equal((await getOwnedSubscription(targetDb, ownerB, trashed.id))?.lifecycleRevision, 2);

    const claim = { botId, actorId: ownerA, code: privateShare.code };
    const repeated = await claimPrivateShare(targetDb, targetBucket, claim);
    assert.equal(repeated.kind, "repeated");
    assert.equal(repeated.content, privateContent);
    assert.equal(repeated.claimCount, 1);
    assert.equal((await claimPrivateShare(targetDb, targetBucket, { ...claim, actorId: ownerB })).kind, "exhausted");
    assert.equal((await claimPrivateShare(targetDb, targetBucket, { ...claim, botId: "900005104" })).kind, "unavailable");
  } finally {
    await Promise.all([source.dispose(), target.dispose()]);
  }
});

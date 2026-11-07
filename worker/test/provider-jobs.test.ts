import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, beforeEach, test } from "node:test";

import { Miniflare } from "miniflare";

import {
  claimProviderJob, enqueueOwnedProviderRefresh, enqueueProviderUrlImport, prepareProviderJobLeaseGuard,
  prepareProviderJobSettlement, settleProviderJob, type ProviderAdmission, type ProviderJobLease,
} from "../src/provider-jobs.ts";
import { createSubscription, getOwnedSubscription } from "../src/storage.ts";
import { renameOwnedSubscription, restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";

const miniflare = new Miniflare({
  modules: true, script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"],
});
let db: D1Database;
const ownerId = "9007199254740993";
const neighborId = "9007199254740994";
const sourceUrl = "https://provider.example.invalid/source%2f?z=fixture%2Bvalue&a=1";
const snapshotId = "01010101-0101-0101-0101-010101010101";
let request = 0;

// Synthetic request keys exercise the same internal admission functions a trusted caller uses.
function key() {
  return (++request).toString(16).padStart(64, "0");
}

before(async () => {
  db = await miniflare.getD1Database("DB");
  for (const file of ["0001_subscriptions.sql", "0003_subscription_lifecycle.sql", "0015_subscription_provider_jobs.sql"]) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

beforeEach(async () => {
  await db.batch(["subscription_provider_jobs", "subscriptions", "subscription_trash", "subscription_lifecycle"]
    .map((table) => db.prepare(`DELETE FROM ${table}`)));
});
after(() => miniflare.dispose());

function hasJob(result: ProviderAdmission) {
  assert.ok("jobId" in result);
  return result;
}

async function importSource(url = sourceUrl, owner = ownerId) {
  return hasJob(await enqueueProviderUrlImport(db, { ownerId: owner, requestKey: key(), sourceUrl: url }));
}

async function claim() {
  const lease = await claimProviderJob(db);
  assert.ok(lease);
  return lease;
}

async function guardCurrent(lease: ProviderJobLease) {
  const guard = prepareProviderJobLeaseGuard(lease);
  return await db.prepare(`SELECT CASE WHEN ${guard.sql} THEN 1 ELSE 0 END AS current`)
    .bind(...guard.bindings).first<number>("current");
}

test("atomically creates a private generation-zero shell and preserves exact URL bytes and identity", async () => {
  const input = { ownerId, requestKey: key(), sourceUrl, name: "  Synthetic provider  " };
  const results = await Promise.all([enqueueProviderUrlImport(db, input), enqueueProviderUrlImport(db, input)]);
  assert.deepEqual(results.map(({ kind }) => kind).toSorted(), ["duplicate", "queued"]);
  const [first, replay] = results.map(hasJob);
  assert.equal(first.jobId, replay.jobId);
  assert.equal(first.subscriptionId, replay.subscriptionId);
  const subscription = await getOwnedSubscription(db, ownerId, first.subscriptionId);
  assert.ok(subscription);
  assert.equal(subscription.sourceUrl, sourceUrl);
  assert.equal(subscription.name, "Synthetic provider");
  assert.equal(subscription.generation, 0);
  assert.equal(subscription.nodeCount, 0);
  assert.equal(subscription.token.length, 32);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscriptions").first("count"), 1);
  const storedJob = await db.prepare("SELECT * FROM subscription_provider_jobs").first();
  assert.ok(storedJob);
  assert.equal(JSON.stringify(storedJob).includes(sourceUrl), false);
  assert.equal(JSON.stringify(storedJob).includes(subscription.token), false);
  assert.equal(JSON.stringify(results).includes(sourceUrl), false);

  assert.deepEqual(await enqueueProviderUrlImport(db, { ...input, sourceUrl: sourceUrl + "&different=1" }),
    { kind: "conflict" });
  const coalescedInput = { ownerId, requestKey: key(), sourceUrl };
  const coalesced = hasJob(await enqueueProviderUrlImport(db, coalescedInput));
  assert.equal(coalesced.kind, "coalesced");
  assert.equal(coalesced.subscriptionId, subscription.id);
  const lease = await claim();
  assert.equal(lease.sourceUrl, sourceUrl);
  assert.equal(await settleProviderJob(db, lease, { kind: "failed", reason: "fetch-rejected" }), "done");
  assert.equal((await enqueueProviderUrlImport(db, coalescedInput)).kind, "duplicate");
  const subsequent = await importSource();
  assert.equal(subsequent.kind, "queued");
  assert.equal(subsequent.subscriptionId, subscription.id);
  assert.deepEqual(await getOwnedSubscription(db, ownerId, subscription.id), subscription);
});

test("does not normalize signed source paths or merge sources across owners", async () => {
  const noSlash = await importSource("https://example.invalid/signed?z=1&a=%2f");
  const slash = await importSource("https://example.invalid/signed/?z=1&a=%2f");
  const foreign = await importSource("https://example.invalid/signed?z=1&a=%2f", neighborId);
  assert.equal(new Set([noSlash.subscriptionId, slash.subscriptionId, foreign.subscriptionId]).size, 3);
  assert.equal((await getOwnedSubscription(db, ownerId, noSlash.subscriptionId))?.sourceUrl,
    "https://example.invalid/signed?z=1&a=%2f");
  assert.equal((await getOwnedSubscription(db, ownerId, slash.subscriptionId))?.sourceUrl,
    "https://example.invalid/signed/?z=1&a=%2f");
  assert.deepEqual(await enqueueOwnedProviderRefresh(db, { ownerId, requestKey: key(), id: foreign.subscriptionId }),
    { kind: "unavailable" });
});

test("rejects ambiguous legacy duplicate sources, non-URL imports and malformed input", async () => {
  for (const name of ["First legacy", "Second legacy"]) {
    await createSubscription(db, { ownerId, name, sourceUrl });
  }
  assert.deepEqual(await enqueueProviderUrlImport(db, { ownerId, requestKey: key(), sourceUrl }), { kind: "conflict" });
  const file = await createSubscription(db, { ownerId, name: "Static", sourceUrl: "uploaded://telegram-document" });
  assert.deepEqual(await enqueueOwnedProviderRefresh(db, { ownerId, requestKey: key(), id: file.id }),
    { kind: "unavailable" });
  for (const invalid of ["file:///private", "https://user:pw@example.invalid/s", "https://@example.invalid",
    "https://example.invalid:8443/", "https://example.invalid/\u0000", "https://example.invalid/%x0",
    "https://example.invalid/#fragment", "https://example.invalid/" + "界".repeat(3000)]) {
    await assert.rejects(enqueueProviderUrlImport(db, { ownerId, requestKey: key(), sourceUrl: invalid }),
      /^RangeError: Invalid provider source URL\.$/u);
  }
  await assert.rejects(enqueueProviderUrlImport(db, { ownerId, requestKey: "not-stable", sourceUrl }), RangeError);
});

test("enforces concurrent owner and global queue caps without leaving extra shells", async () => {
  const requests = await Promise.all(Array.from({ length: 6 }, (_, index) =>
    enqueueProviderUrlImport(db, { ownerId, requestKey: key(), sourceUrl: `${sourceUrl}&owner=${index}` })));
  assert.equal(requests.filter(({ kind }) => kind === "queued").length, 4);
  assert.equal(requests.filter(({ kind }) => kind === "capacity").length, 2);
  for (let index = 0; index < 4; index++) {
    assert.equal((await importSource(`${sourceUrl}&neighbor=${index}`, neighborId)).kind, "queued");
  }
  assert.deepEqual(await enqueueProviderUrlImport(db, { ownerId: "9007199254740995", requestKey: key(), sourceUrl }),
    { kind: "capacity" });
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscriptions").first("count"), 8);
  const claims = await Promise.all([claimProviderJob(db), claimProviderJob(db), claimProviderJob(db)]);
  assert.equal(claims.filter(Boolean).length, 1);
});

test("new source cap does not prevent refresh of an already owned source", async () => {
  const existing = await createSubscription(db, { ownerId, sourceUrl, name: "Existing" });
  await db.prepare(`WITH RECURSIVE numbers(n) AS (VALUES(1) UNION ALL SELECT n + 1 FROM numbers WHERE n < 99)
    INSERT INTO subscriptions (owner_id, name, source_url, token, created_at, updated_at)
    SELECT ?, 'Synthetic', 'https://example.invalid/' || n, printf('%032d', n), unixepoch(), unixepoch() FROM numbers`)
    .bind(ownerId).run();
  assert.deepEqual(await enqueueProviderUrlImport(db, { ownerId, requestKey: key(), sourceUrl: sourceUrl + "&new=1" }),
    { kind: "capacity" });
  const refresh = hasJob(await enqueueOwnedProviderRefresh(db, { ownerId, requestKey: key(), id: existing.id }));
  assert.equal(refresh.kind, "queued");
  assert.equal(refresh.subscriptionId, existing.id);
  assert.equal((await getOwnedSubscription(db, ownerId, existing.id))?.token, existing.token);
});

test("blocks import while exact deleted source remains recoverable and keeps restore identity", async () => {
  const original = await createSubscription(db, { ownerId, sourceUrl, name: "Previous" });
  assert.equal(await trashOwnedSubscription(db, { id: original.id, ownerId, expectedLifecycleRevision: 0 }), true);
  assert.deepEqual(await enqueueProviderUrlImport(db, { ownerId, requestKey: key(), sourceUrl }), { kind: "unavailable" });
  assert.equal(await restoreOwnedSubscription(db, { id: original.id, ownerId, expectedLifecycleRevision: 1 }), true);
  const imported = await importSource();
  assert.equal(imported.subscriptionId, original.id);
  assert.equal((await getOwnedSubscription(db, ownerId, original.id))?.token, original.token);
});

test("a lost admission response reconciles by the same request without a second shell", async () => {
  const input = { ownerId, requestKey: key(), sourceUrl };
  const uncertain = new Proxy(db, {
    get(target, property) {
      if (property === "batch") return async (steps: D1PreparedStatement[]) => {
        await target.batch(steps);
        throw new Error("synthetic failure " + sourceUrl);
      };
      const member = Reflect.get(target, property);
      return typeof member === "function" ? member.bind(target) : member;
    },
  });
  await assert.rejects(enqueueProviderUrlImport(uncertain, input), /^Error: Provider URL import admission could not be confirmed\.$/u);
  assert.equal((await enqueueProviderUrlImport(db, input)).kind, "duplicate");
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscriptions").first("count"), 1);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscription_provider_jobs").first("count"), 1);
});

test("lease reclaim and SQL clock bound retries and fence the previous lease", async () => {
  await importSource();
  const first = await claim();
  assert.equal(first.attempts, 1);
  assert.equal(await guardCurrent(first), 1);
  assert.equal(await claimProviderJob(db), null);
  await db.prepare("UPDATE subscription_provider_jobs SET lease_until = unixepoch() - 1 WHERE job_id = ?")
    .bind(first.jobId).run();
  const second = await claim();
  assert.equal(second.jobId, first.jobId);
  assert.equal(second.attempts, 2);
  assert.notEqual(second.leaseId, first.leaseId);
  assert.equal(await guardCurrent(first), 0);
  assert.equal(await settleProviderJob(db, first, { kind: "failed", reason: "fetch-rejected" }), "stale");
  assert.equal(await settleProviderJob(db, second, { kind: "retry", reason: "timeout" }), "retry");
  const delay = await db.prepare("SELECT due_at - unixepoch() AS delay FROM subscription_provider_jobs WHERE job_id = ?")
    .bind(first.jobId).first<number>("delay");
  assert.ok(delay !== null && delay >= 175 && delay <= 180);
  assert.equal(await claimProviderJob(db), null);
  await db.prepare("UPDATE subscription_provider_jobs SET due_at = unixepoch() WHERE job_id = ?").bind(first.jobId).run();
  const third = await claim();
  assert.equal(third.attempts, 3);
  assert.equal(await settleProviderJob(db, third, { kind: "retry", reason: "busy" }), "done");
  assert.equal(await db.prepare("SELECT result_code FROM subscription_provider_jobs WHERE job_id = ?")
    .bind(first.jobId).first("result_code"), "attempts-exhausted");
});

test("reaps expired pending jobs and never returns a mismatched source", async () => {
  const expired = await importSource(sourceUrl + "&expired=1");
  await db.prepare(`UPDATE subscription_provider_jobs SET created_at = unixepoch() - 3601,
    due_at = unixepoch() - 3600, expires_at = unixepoch() - 1 WHERE job_id = ?`).bind(expired.jobId).run();
  assert.equal(await claimProviderJob(db), null);
  assert.equal(await db.prepare("SELECT result_code FROM subscription_provider_jobs WHERE job_id = ?")
    .bind(expired.jobId).first("result_code"), "expired");

  const changed = await importSource();
  await db.prepare("UPDATE subscriptions SET source_url = ? WHERE id = ?")
    .bind(sourceUrl + "&replacement=1", changed.subscriptionId).run();
  assert.equal(await claimProviderJob(db), null);
  assert.equal(await db.prepare("SELECT result_code FROM subscription_provider_jobs WHERE job_id = ?")
    .bind(changed.jobId).first("result_code"), "stale-target");
});

test("rename, trash and restore fence the original target and preserve its metadata", async () => {
  const imported = await importSource();
  const lease = await claim();
  await db.prepare("UPDATE subscriptions SET traffic_used = 1.25, traffic_total = 8, expire_at = 2000000000 WHERE id = ?")
    .bind(imported.subscriptionId).run();
  assert.equal(await renameOwnedSubscription(db, { id: lease.id, ownerId, expectedLifecycleRevision: 0 }, "My name"), true);
  assert.equal(await trashOwnedSubscription(db, { id: lease.id, ownerId, expectedLifecycleRevision: 1 }), true);
  assert.equal(await restoreOwnedSubscription(db, { id: lease.id, ownerId, expectedLifecycleRevision: 2 }), true);
  assert.equal(await guardCurrent(lease), 0);
  assert.equal(await settleProviderJob(db, lease, { kind: "retry", reason: "storage-failed" }), "done");
  assert.equal(await db.prepare("SELECT result_code FROM subscription_provider_jobs WHERE job_id = ?")
    .bind(lease.jobId).first("result_code"), "stale-target");
  const restored = await getOwnedSubscription(db, ownerId, lease.id);
  assert.ok(restored);
  assert.deepEqual([restored.name, restored.lifecycleRevision, restored.generation, restored.trafficUsed,
    restored.trafficTotal, restored.expireAt, restored.lastError], ["My name", 3, 0, 1.25, 8, 2000000000, null]);
});

test("saved settlement requires the same live lease and exact pointer in the publication batch", async () => {
  await importSource();
  const lease = await claim();
  assert.equal(await prepareProviderJobSettlement(db, lease, { kind: "saved", snapshotId }).first(), null);
  const guard = prepareProviderJobLeaseGuard(lease);
  // Synthetic D1 pointer simulates a caller's guarded publication without staging R2 objects.
  const results = await db.batch([
    db.prepare(`UPDATE subscriptions SET generation = 1, snapshot_id = ?, manifest_sha256 = ?, node_count = 1
      WHERE id = ? AND ${guard.sql}`).bind(snapshotId, "a".repeat(64), lease.id, ...guard.bindings),
    prepareProviderJobSettlement(db, lease, { kind: "saved", snapshotId }),
  ]);
  assert.equal(results[0].meta.changes, 1);
  assert.deepEqual(results[1].results, [{ state: "done", resultCode: "saved" }]);
  assert.equal(await guardCurrent(lease), 0);
});

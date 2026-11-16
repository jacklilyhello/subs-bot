import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test, type TestContext } from "node:test";
import { Miniflare } from "miniflare";

import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { claimProviderJob, enqueueProviderUrlImport, prepareProviderJobLeaseGuard } from "../src/provider-jobs.ts";
import type { ProviderFetcher } from "../src/provider-fetch-contract.ts";
import { getOwnedSubscription } from "../src/storage.ts";
import {
  PROVIDER_FETCH_MS, PROVIDER_FORCE_CLEANUP_MS, PROVIDER_LEASE_HEADROOM_MS, PROVIDER_LEASE_SECONDS,
  PROVIDER_RPC_TIMEOUT_MS, PROVIDER_STARTUP_MS, PROVIDER_STOP_MS,
  RELEASE_EGRESS_SECONDS, RELEASE_POLL_SECONDS, RELEASE_RPC_SECONDS,
} from "../src/provider-lifecycle-budgets.ts";

const ownerId = "9007199254740993";
const pin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };

async function fixture(t: TestContext) {
  const miniflare = new Miniflare({
    modules: true, script: "export default { fetch() { return new Response(null); } };",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  });
  t.after(() => miniflare.dispose());
  const db = await miniflare.getD1Database("DB");
  const bucket = await miniflare.getR2Bucket("NODES");
  for (const file of ["0001_subscriptions.sql", "0003_subscription_lifecycle.sql",
    "0015_subscription_provider_jobs.sql", "0033_provider_snapshot_journal.sql"]) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  const admission = await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64),
    sourceUrl: "https://provider.example.invalid/source?fixture=lifecycle-budget" });
  assert.equal(admission.kind, "queued");
  assert.ok("jobId" in admission);
  return { db, bucket, admission };
}

test("cross-layer budgets retain room for cleanup, publication and both non-retrying release steps", () => {
  const lifecycle = PROVIDER_STARTUP_MS + PROVIDER_FETCH_MS + PROVIDER_STOP_MS + PROVIDER_FORCE_CLEANUP_MS;
  assert.ok(lifecycle < PROVIDER_RPC_TIMEOUT_MS);
  assert.ok(PROVIDER_RPC_TIMEOUT_MS < PROVIDER_LEASE_HEADROOM_MS);
  assert.ok(PROVIDER_LEASE_HEADROOM_MS < PROVIDER_LEASE_SECONDS * 1000);
  // The release egress step makes a health fetch and three address refusals.
  assert.ok(PROVIDER_STARTUP_MS + 4 * PROVIDER_FETCH_MS + PROVIDER_STOP_MS + PROVIDER_FORCE_CLEANUP_MS
    < RELEASE_EGRESS_SECONDS * 1000);
  assert.ok(lifecycle < RELEASE_RPC_SECONDS * 1000);
  assert.ok(RELEASE_EGRESS_SECONDS + RELEASE_RPC_SECONDS < RELEASE_POLL_SECONDS);
});

test("actual Workflow steps and both Python pollers cover the shared lifecycle budgets", async () => {
  const [worker, release, legacy] = await Promise.all([
    readFile(new URL("../provider_fetch/worker.ts", import.meta.url), "utf8"),
    readFile(new URL("../tools/production_provider.py", import.meta.url), "utf8"),
    readFile(new URL("../tools/activate_provider_isolation.py", import.meta.url), "utf8"),
  ]);
  const steps = [...worker.matchAll(/timeout: "([0-9]+) seconds"/gu)].map((match) => Number(match[1]));
  assert.deepEqual(steps, [RELEASE_EGRESS_SECONDS, RELEASE_RPC_SECONDS, RELEASE_EGRESS_SECONDS]);
  const outer = Number(release.match(/deadline = monotonic\(\) \+ ([0-9]+)/u)?.[1]);
  const legacyOuter = Number(legacy.match(/deadline = monotonic\(\) \+ ([0-9]+)/u)?.[1]);
  assert.equal(outer, RELEASE_POLL_SECONDS);
  assert.ok(outer > steps[0] + steps[1]);
  assert.equal(legacyOuter, 360);
  assert.ok(legacyOuter > steps[2]);
});

test("real D1 leases cover the lifecycle and still expire at the admission deadline", { timeout: 30_000 }, async (t) => {
  const { db, admission } = await fixture(t);
  const before = (await db.prepare("SELECT unixepoch() AS now").first<number>("now"))!;
  const lease = await claimProviderJob(db);
  assert.ok(lease);
  const after = (await db.prepare("SELECT unixepoch() AS now").first<number>("now"))!;
  assert.ok(lease.leaseUntil >= before + PROVIDER_LEASE_SECONDS && lease.leaseUntil <= after + PROVIDER_LEASE_SECONDS);
  const guard = prepareProviderJobLeaseGuard(lease);
  assert.equal(await db.prepare(`SELECT CASE WHEN ${guard.sql} THEN 1 ELSE 0 END AS live`).bind(...guard.bindings).first("live"), 1);
  await db.prepare("UPDATE subscription_provider_jobs SET lease_until=unixepoch()-1 WHERE job_id=?").bind(admission.jobId).run();
  assert.equal(await db.prepare(`SELECT CASE WHEN ${guard.sql} THEN 1 ELSE 0 END AS live`).bind(...guard.bindings).first("live"), 0);
  await db.prepare("UPDATE subscription_provider_jobs SET expires_at=unixepoch()+220 WHERE job_id=?").bind(admission.jobId).run();
  const bounded = await claimProviderJob(db);
  assert.ok(bounded);
  assert.equal(bounded.leaseUntil, bounded.expiresAt, "Extending the lease must never extend the original work deadline.");
  assert.equal(bounded.attempts, 2);
});

for (const remaining of [PROVIDER_LEASE_HEADROOM_MS - 1, PROVIDER_LEASE_HEADROOM_MS]) {
  test(`real claim with ${remaining}ms headroom ${remaining < PROVIDER_LEASE_HEADROOM_MS ? "rejects" : "allows"} dispatch`,
    { timeout: 30_000 }, async (t) => {
      const { db, bucket, admission } = await fixture(t);
      const originalNow = Date.now.bind(Date);
      let consumerNow: number | undefined, calls = 0;
      const wrapped = {
        prepare: db.prepare.bind(db),
        async batch(statements: D1PreparedStatement[]) {
          const results = await db.batch<Record<string, unknown>>(statements);
          const claim = results.flatMap(({ results: rows }) => rows).find((row) => typeof row.leaseUntil === "number");
          if (claim) consumerNow = (claim.leaseUntil as number) * 1000 - remaining;
          return results;
        },
      } as D1Database;
      t.mock.method(Date, "now", () => consumerNow ?? originalNow());
      const provider: ProviderFetcher = { async fetchSubscription() {
        calls++;
        return { ok: false, code: "blocked-address", retryable: false };
      } };
      assert.equal(await runOneProviderJob(wrapped, bucket, provider, pin), remaining < PROVIDER_LEASE_HEADROOM_MS ? "retry" : "done");
      assert.equal(calls, remaining < PROVIDER_LEASE_HEADROOM_MS ? 0 : 1);
      const row = await db.prepare("SELECT attempts,state,failure_code,result_code FROM subscription_provider_jobs WHERE job_id=?")
        .bind(admission.jobId).first();
      assert.deepEqual(row, remaining < PROVIDER_LEASE_HEADROOM_MS
        ? { attempts: 1, state: "pending", failure_code: "timeout", result_code: null }
        : { attempts: 1, state: "done", failure_code: "fetch-rejected", result_code: "fetch-rejected" });
      assert.equal((await getOwnedSubscription(db, ownerId, admission.subscriptionId))?.generation, 0);
      assert.equal((await bucket.list()).objects.length, 0);
    });
}

test("72 seconds no longer consumes an attempt; 180-second RPC expiry settles once and ignores late success",
  { timeout: 30_000 }, async (t) => {
    const { db, bucket, admission } = await fixture(t);
    const entered = Promise.withResolvers<void>();
    const remote = Promise.withResolvers<Awaited<ReturnType<ProviderFetcher["fetchSubscription"]>>>();
    const set = setTimeout.bind(globalThis);
    let virtualNow = 0, deadline = -1, fire: (() => void) | undefined, finished = false;
    t.mock.method(globalThis, "setTimeout", (callback, delay, ...args) => {
      if (delay === 72_000 || delay === PROVIDER_RPC_TIMEOUT_MS) {
        deadline = virtualNow + delay;
        fire = () => callback(...args);
        return set(() => {}, 5000);
      }
      return set(callback, delay, ...args);
    });
    const provider: ProviderFetcher = { async fetchSubscription() { entered.resolve(); return remote.promise; } };
    const work = runOneProviderJob(db, bucket, provider, pin).then((result) => { finished = true; return result; });
    await entered.promise;
    assert.equal(deadline, 180_000);
    virtualNow = 72_000;
    if (deadline <= virtualNow) fire!();
    await new Promise<void>((resolve) => set(resolve, 10));
    assert.equal(finished, false);
    assert.deepEqual(await db.prepare("SELECT state,attempts FROM subscription_provider_jobs WHERE job_id=?").bind(admission.jobId).first(),
      { state: "leased", attempts: 1 });
    virtualNow = 180_000;
    assert.ok(deadline <= virtualNow);
    fire!();
    assert.equal(await work, "retry");
    const body = new TextEncoder().encode("ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#late").buffer;
    const bodySha256 = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", body)),
      (byte) => byte.toString(16).padStart(2, "0")).join("");
    remote.resolve({ ok: true, body, bodySha256 });
    await new Promise<void>((resolve) => set(resolve, 10));
    assert.deepEqual(await db.prepare("SELECT state,attempts,failure_code FROM subscription_provider_jobs WHERE job_id=?")
      .bind(admission.jobId).first(), { state: "pending", attempts: 1, failure_code: "timeout" });
    assert.equal((await getOwnedSubscription(db, ownerId, admission.subscriptionId))?.generation, 0);
    assert.equal((await bucket.list()).objects.length, 0);
  });

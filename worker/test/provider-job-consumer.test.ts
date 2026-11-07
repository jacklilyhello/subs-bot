import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { Miniflare } from "miniflare";

import type { ProviderFetcher, ProviderPin } from "../src/provider-fetch-contract.ts";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { enqueueProviderUrlImport } from "../src/provider-jobs.ts";
import { digestHex, getOwnedSubscription } from "../src/storage.ts";

const ownerId = "9007199254740993";
const pin: ProviderPin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const sourceUrl = "https://provider.example.invalid/signed?opaque=synthetic";
const provider: ProviderFetcher = {
  async fetchSubscription(input) {
    assert.deepEqual(input, { url: sourceUrl, ...pin });
    const body = new TextEncoder().encode("ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture").buffer;
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  },
};

for (const failure of ["lease-race", "missed-settlement", "committed", "uncommitted"] as const) {
  test(`provider publication ${failure} fences its exact R2 candidate`, { timeout: 30_000 }, async (t) => {
    const miniflare = new Miniflare({
      modules: true, script: "export default { fetch() { return new Response(null); } };", compatibilityDate: "2026-07-30",
      d1Databases: ["DB"], r2Buckets: ["NODES"],
    });
    t.after(() => miniflare.dispose());
    const db = await miniflare.getD1Database("DB");
    const bucket = await miniflare.getR2Bucket("NODES");
    for (const file of ["0001_subscriptions.sql", "0003_subscription_lifecycle.sql", "0015_subscription_provider_jobs.sql"]) {
      const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
      await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    }
    const admission = await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64), sourceUrl });
    assert.equal(admission.kind, "queued");
    assert.ok("jobId" in admission);
    const getJob = () => db.prepare("SELECT state,result_code AS result,lease_id AS lease FROM subscription_provider_jobs WHERE job_id=?")
      .bind(admission.jobId).first<{ state: string; result: string | null; lease: string | null }>();
    let stagedPrefix = "";
    const injected = {
      prepare: db.prepare.bind(db),
      batch: async (statements: D1PreparedStatement[]) => {
        if (statements.length !== 3) return db.batch(statements);
        const lease = (await getJob())?.lease;
        assert.ok(lease);
        stagedPrefix = `subscriptions/${admission.subscriptionId}/${lease}/`;
        assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
        if (failure === "lease-race") {
          await db.prepare("INSERT INTO subscription_lifecycle VALUES (?, 1)").bind(admission.subscriptionId).run();
          return db.batch(statements);
        }
        if (failure === "missed-settlement") {
          return db.batch([statements[0], db.prepare("UPDATE subscription_provider_jobs SET state='pending' WHERE 0"), statements[2]]);
        }
        if (failure === "committed") await db.batch(statements);
        throw new Error(`Synthetic D1 failure containing ${sourceUrl}`);
      },
    } as D1Database;

    const outcome = await runOneProviderJob(injected, bucket, provider, pin);
    const subscription = await getOwnedSubscription(db, ownerId, admission.subscriptionId);
    assert.ok(subscription);
    if (failure === "lease-race") {
      assert.equal(outcome, "stale");
      assert.equal(subscription.generation, 0);
      assert.deepEqual(await getJob(), { state: "done", result: "stale-target", lease: null });
      assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 0);
    } else if (failure === "committed") {
      assert.equal(outcome, "saved");
      assert.equal(subscription.generation, 1);
      assert.deepEqual(await getJob(), { state: "done", result: "saved", lease: null });
      assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
    } else {
      assert.equal(outcome, "uncertain");
      assert.equal(subscription.generation, 0);
      assert.equal((await getJob())?.state, "leased");
      assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
      await db.prepare("UPDATE subscription_provider_jobs SET lease_until=unixepoch()-1 WHERE job_id=?").bind(admission.jobId).run();
      assert.equal(await runOneProviderJob(db, bucket, provider, pin), "saved");
      assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
      assert.equal((await bucket.list()).objects.length, 4);
    }
  });
}

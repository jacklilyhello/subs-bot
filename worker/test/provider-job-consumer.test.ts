import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test, type TestContext } from "node:test";

import { Miniflare } from "miniflare";

import type { ProviderFetcher, ProviderPin } from "../src/provider-fetch-contract.ts";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { enqueueOwnedProviderRefresh, enqueueProviderUrlImport } from "../src/provider-jobs.ts";
import {
  digestHex, getOwnedSubscription, getSubscriptionSnapshot, publishNodeSnapshot, readSnapshotNodes,
  SNAPSHOT_MANIFEST_ORDINAL, type SubscriptionSnapshot,
} from "../src/storage.ts";

const ownerId = "9007199254740993";
const pin: ProviderPin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const sourceUrl = "https://provider.example.invalid/signed?opaque=synthetic";
const originalShare = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture";
const replacementShare = originalShare.replace("#fixture", "#replacement");

function syntheticProvider(share: string): ProviderFetcher {
  return { async fetchSubscription(input) {
    assert.deepEqual(input, { url: sourceUrl, ...pin });
    const body = new TextEncoder().encode(share).buffer;
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } };
}

const provider = syntheticProvider(originalShare);

async function fixture(t: TestContext, journal = true) {
  const miniflare = new Miniflare({
    modules: true, script: "export default { fetch() { return new Response(null); } };", compatibilityDate: "2026-07-30",
    d1Databases: ["DB"], r2Buckets: ["NODES"],
  });
  t.after(() => miniflare.dispose());
  const db = await miniflare.getD1Database("DB");
  const bucket = await miniflare.getR2Bucket("NODES");
  const files = ["0001_subscriptions.sql", "0003_subscription_lifecycle.sql", "0015_subscription_provider_jobs.sql"];
  if (journal) files.push("0033_provider_snapshot_journal.sql");
  for (const file of files) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  return { db, bucket };
}

for (const failure of ["lease-race", "missed-settlement", "missed-journal", "committed", "superseded", "uncommitted"] as const) {
  test(`provider publication ${failure} fences its exact journal and R2 candidate`, { timeout: 30_000 }, async (t) => {
    const { db, bucket } = await fixture(t);
    const admission = await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64), sourceUrl });
    assert.equal(admission.kind, "queued");
    assert.ok("jobId" in admission);
    const getJob = () => db.prepare("SELECT state,result_code AS result,lease_id AS lease FROM subscription_provider_jobs WHERE job_id=?")
      .bind(admission.jobId).first<{ state: string; result: string | null; lease: string | null }>();
    let stagedPrefix = "";
    let snapshot = "";
    let publicationGuardRejected = false;
    const injected = {
      prepare: db.prepare.bind(db),
      batch: async (statements: D1PreparedStatement[]) => {
        if (statements.length !== 5) return db.batch(statements);
        const lease = (await getJob())?.lease;
        assert.ok(lease);
        snapshot = lease;
        stagedPrefix = `subscriptions/${admission.subscriptionId}/${lease}/`;
        assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
        assert.equal(await db.prepare("SELECT state FROM provider_snapshot_attempts WHERE snapshot_id=?").bind(lease).first("state"),
          "sealed");
        if (failure === "lease-race") {
          await db.prepare("INSERT INTO subscription_lifecycle VALUES (?, 1)").bind(admission.subscriptionId).run();
          return db.batch(statements);
        }
        if (failure === "missed-settlement" || failure === "missed-journal") {
          const changed = [...statements];
          changed[failure === "missed-settlement" ? 1 : 2] = db.prepare("UPDATE provider_snapshot_attempts SET state='sealed' WHERE 0");
          try {
            return await db.batch(changed);
          } catch (error) {
            publicationGuardRejected = [error, error instanceof Error ? error.cause : undefined]
              .some((cause) => cause instanceof Error && /\bmalformed JSON\b/u.test(cause.message));
            throw error;
          }
        }
        if (failure === "committed" || failure === "superseded") {
          await db.batch(statements);
          if (failure === "superseded") {
            assert.equal(await publishNodeSnapshot(db, bucket, { id: admission.subscriptionId, ownerId,
              expectedGeneration: 1, expectedLifecycleRevision: 0 }, [{ name: "Later synthetic node" }]), true);
          }
        }
        throw new Error(`Synthetic D1 failure containing ${sourceUrl}`);
      },
    } as D1Database;

    const outcome = await runOneProviderJob(injected, bucket, provider, pin);
    const subscription = await getOwnedSubscription(db, ownerId, admission.subscriptionId);
    assert.ok(subscription);
    const journal = () => db.prepare("SELECT state FROM provider_snapshot_attempts WHERE snapshot_id=?").bind(snapshot).first("state");
    const intents = () => db.prepare("SELECT count(*) AS count FROM provider_snapshot_object_intents WHERE snapshot_id=?")
      .bind(snapshot).first("count");
    assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
    if (failure === "lease-race") {
      assert.equal(outcome, "stale");
      assert.equal(subscription.generation, 0);
      assert.deepEqual(await getJob(), { state: "done", result: "stale-target", lease: null });
      assert.equal(await journal(), "sealed");
      assert.equal(await intents(), 2);
    } else if (failure === "committed" || failure === "superseded") {
      assert.equal(outcome, "saved");
      assert.equal(subscription.generation, failure === "superseded" ? 2 : 1);
      assert.deepEqual(await getJob(), { state: "done", result: "saved", lease: null });
      assert.equal(await journal(), "published");
      assert.equal(await intents(), 0);
    } else {
      assert.equal(outcome, "uncertain");
      if (failure !== "uncommitted") assert.equal(publicationGuardRejected, true, "The D1 publication guard must abort the batch.");
      assert.equal(subscription.generation, 0);
      assert.equal((await getJob())?.state, "leased");
      assert.equal(await journal(), "sealed");
      assert.equal(await intents(), 2);
      await db.prepare("UPDATE subscription_provider_jobs SET lease_until=unixepoch()-1 WHERE job_id=?").bind(admission.jobId).run();
      assert.equal(await runOneProviderJob(db, bucket, provider, pin), "saved");
      assert.equal((await bucket.list({ prefix: stagedPrefix })).objects.length, 2);
      assert.equal((await bucket.list()).objects.length, 4);
      assert.equal(await journal(), "sealed");
      assert.equal(await intents(), 2);
    }
  });
}

test("a missing provider journal prevents claim and fetch on the old schema", { timeout: 30_000 }, async (t) => {
  const { db, bucket } = await fixture(t, false);
  assert.equal((await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64), sourceUrl })).kind, "queued");
  const unreachable: ProviderFetcher = { async fetchSubscription() { return assert.fail("Unexpected provider call"); } };
  assert.equal(await runOneProviderJob(db, bucket, unreachable, pin), "disabled");
  assert.deepEqual(await db.prepare("SELECT state,attempts FROM subscription_provider_jobs").first(),
    { state: "pending", attempts: 0 });
  assert.equal((await bucket.list()).objects.length, 0);
});

test("a committed but unacknowledged object intent never authorizes a PUT", { timeout: 30_000 }, async (t) => {
  const { db, bucket } = await fixture(t);
  assert.equal((await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64), sourceUrl })).kind, "queued");
  const lost = {
    prepare(sql: string) {
      const statement = db.prepare(sql);
      if (!sql.startsWith("INSERT INTO provider_snapshot_object_intents")) return statement;
      return {
        bind(...values: (string | number)[]) {
          const bound = statement.bind(...values);
          return { async run() {
            assert.equal((await bound.run()).meta.changes, 1);
            throw new Error("Synthetic lost journal acknowledgement");
          } };
        },
      } as unknown as D1PreparedStatement;
    },
    batch: db.batch.bind(db),
  } as D1Database;
  let puts = 0;
  const unreachable = { async put() { puts++; return null; } } as unknown as R2Bucket;
  assert.equal(await runOneProviderJob(lost, unreachable, provider, pin), "retry");
  assert.equal(puts, 0);
  assert.equal((await bucket.list()).objects.length, 0);
  assert.equal(await db.prepare("SELECT state FROM provider_snapshot_attempts").first("state"), "open");
  assert.deepEqual(await db.prepare("SELECT ordinal FROM provider_snapshot_object_intents").all().then((rows) => rows.results),
    [{ ordinal: 0 }]);
});

for (const [failAt, failure] of [
  ["0.ndjson", "late"], ["manifest.json", "late"], ["manifest.json", "lost-ack"], ["0.ndjson", "conflict"],
] as const) {
  test(`provider ${failAt} PUT ${failure} preserves the serving snapshot and exact journal evidence`,
    { timeout: 30_000 }, async (t) => {
      const { db, bucket } = await fixture(t);
      const admitted = await enqueueProviderUrlImport(db, { ownerId, requestKey: "c".repeat(64), sourceUrl });
      assert.ok("subscriptionId" in admitted);
      assert.equal(await runOneProviderJob(db, bucket, provider, pin), "saved");
      const subscription = await getOwnedSubscription(db, ownerId, admitted.subscriptionId);
      assert.ok(subscription);
      const before = await getSubscriptionSnapshot(db, subscription.token);
      assert.ok(before?.snapshotId);
      const shares = async (snapshot: SubscriptionSnapshot) => {
        const values = [];
        for await (const node of readSnapshotNodes(bucket, snapshot)) values.push(node.share);
        return values;
      };
      const refresh = await enqueueOwnedProviderRefresh(db, { ownerId, requestKey: "d".repeat(64), id: admitted.subscriptionId,
        expectedGeneration: 1, expectedLifecycleRevision: 0 });
      assert.ok("jobId" in refresh);
      const pending: { put?: () => Promise<R2Object | null>; key?: string; snapshotId?: string; bytes?: number; sha256?: string } = {};
      const ordinal = failAt === "manifest.json" ? SNAPSHOT_MANIFEST_ORDINAL : 0;
      const readIntent = (snapshotId: string, objectOrdinal: number) => db.prepare(
        "SELECT byte_count AS bytes,sha256 FROM provider_snapshot_object_intents WHERE snapshot_id=? AND ordinal=?")
        .bind(snapshotId, objectOrdinal).first();
      const conflictBody = new TextEncoder().encode("Preexisting synthetic object");
      let observedConflict = false;
      let deletes = 0;
      const injected = {
        async put(key: string, body: Uint8Array<ArrayBuffer>, options: R2PutOptions) {
          const [, , snapshotId, name] = key.split("/");
          const objectOrdinal = name === "manifest.json" ? SNAPSHOT_MANIFEST_ORDINAL : 0;
          const hash = digestHex(await crypto.subtle.digest("SHA-256", body));
          assert.deepEqual(await readIntent(snapshotId, objectOrdinal), { bytes: body.byteLength, sha256: hash });
          if (name !== failAt) return bucket.put(key, body, options);
          pending.key = key;
          pending.snapshotId = snapshotId;
          pending.bytes = body.byteLength;
          pending.sha256 = hash;
          if (failure === "conflict") {
            assert.ok(await bucket.put(key, conflictBody, { onlyIf: { etagDoesNotMatch: "*" } }));
            const result = await bucket.put(key, body, options);
            observedConflict = result === null;
            return result;
          }
          if (failure === "late") {
            const savedBody = Uint8Array.from(body);
            pending.put = () => bucket.put(key, savedBody, options);
          } else {
            assert.ok(await bucket.put(key, body, options));
          }
          throw new Error("Synthetic lost R2 response");
        },
        async delete() { deletes++; },
      } as unknown as R2Bucket;
      const replacement = syntheticProvider(replacementShare);
      assert.equal(await runOneProviderJob(db, injected, replacement, pin), "retry");
      assert.equal(deletes, 0);
      assert.deepEqual(await getSubscriptionSnapshot(db, subscription.token), before);
      assert.deepEqual(await shares(before), [originalShare]);
      assert.ok(pending.key && pending.snapshotId && pending.bytes && pending.sha256);
      const readState = () => db.prepare("SELECT state FROM provider_snapshot_attempts WHERE snapshot_id=?")
        .bind(pending.snapshotId).first("state");
      assert.equal(await readState(), "open");
      if (failure === "late") assert.equal(await bucket.head(pending.key), null);
      if (failure === "lost-ack") assert.ok(await bucket.head(pending.key));
      if (failure === "conflict") assert.equal(observedConflict, true);
      await db.prepare("UPDATE subscription_provider_jobs SET due_at=unixepoch() WHERE job_id=?").bind(refresh.jobId).run();
      assert.equal(await runOneProviderJob(db, bucket, replacement, pin), "saved");
      const after = await getSubscriptionSnapshot(db, subscription.token);
      assert.ok(after);
      assert.equal(after.generation, 2);
      assert.notEqual(after.snapshotId, pending.snapshotId);
      if (failure === "late") {
        assert.ok(pending.put);
        assert.equal(await bucket.head(pending.key), null);
        assert.ok(await pending.put());
      }
      const failedObject = await bucket.get(pending.key);
      assert.ok(failedObject);
      const failedBytes = await failedObject.arrayBuffer();
      if (failure === "conflict") assert.deepEqual(new Uint8Array(failedBytes), conflictBody);
      else assert.equal(digestHex(await crypto.subtle.digest("SHA-256", failedBytes)), pending.sha256);
      assert.equal(await readState(), "open");
      assert.deepEqual(await readIntent(pending.snapshotId, ordinal), { bytes: pending.bytes, sha256: pending.sha256 });
      assert.deepEqual(await getSubscriptionSnapshot(db, subscription.token), after);
      assert.deepEqual(await shares(before), [originalShare]);
      assert.deepEqual(await shares(after), [replacementShare]);
    });
}

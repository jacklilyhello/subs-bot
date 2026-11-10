import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { after, before, beforeEach, test } from "node:test";

import { Miniflare } from "miniflare";

import type { ProviderFetcher } from "../src/provider-fetch-contract.ts";
import { initialProviderTitle, PROVIDER_INITIAL_TITLE_MIGRATION, PROVIDER_INITIAL_TITLE_SHA256 } from "../src/provider-initial-title.ts";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { claimProviderJob, enqueueProviderUrlImport } from "../src/provider-jobs.ts";
import { digestHex, getOwnedSubscription, getSubscriptionSnapshot, SUBSCRIPTION_LIFECYCLE_REVISION } from "../src/storage.ts";
import { renameOwnedSubscription } from "../src/subscriptions.ts";
import {
  acceptTelegramProviderRequest, type TelegramProviderAdmission, type TelegramProviderEvent,
} from "../src/telegram/provider-admission.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";

const miniflare = new Miniflare({
  modules: true, script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
});
let db: D1Database;
let bucket: R2Bucket;
let update = 0;
const policy: TelegramPolicy = { botId: "999", botUsername: "synthetic_bot", adminId: "111", memberId: "222", groupId: "-333",
  webhookSecret: "synthetic-webhook-secret", botToken: "999:synthetic-token" };
const sourceUrl = "https://provider.example.invalid/signed/%2f/?second=opaque%2Bfixture&first=1";
const pin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const now = () => Math.floor(Date.now() / 1000);

function scope(actorId = policy.memberId, messageDate = now()) {
  const updateId = ++update;
  return { updateId, actorId, chatId: actorId, chatType: "private" as const, messageId: updateId, messageDate, threadId: null };
}

function source(actorId = policy.memberId, messageDate = now()): TelegramProviderEvent {
  return { ...scope(actorId, messageDate), kind: "url-import", sourceUrl };
}

function admit(event: TelegramProviderEvent, database = db) {
  return acceptTelegramProviderRequest(database, policy, event);
}

function job(result: TelegramProviderAdmission) {
  assert.ok("jobId" in result);
  return result;
}

function auth(allowed: number, date: number, messageId: number) {
  return db.prepare(`INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,?,?,?)
    ON CONFLICT (bot_id,user_id) DO UPDATE SET allowed=excluded.allowed,message_date=excluded.message_date,message_id=excluded.message_id`)
    .bind(policy.botId, policy.memberId, allowed, date, messageId).run();
}

const provider: ProviderFetcher = { async fetchSubscription(input) {
  assert.deepEqual(input, { url: sourceUrl, ...pin });
  const body = new TextEncoder().encode("ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture").buffer;
  return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)),
    metadata: { "subscription-userinfo": "upload=1073741824; download=0; total=2147483648; expire=1900000000",
      "profile-title": "Example%20Provider.yaml" } };
} };

const titleCount = () => db.prepare("SELECT count(*) AS count FROM telegram_provider_initial_titles").first<number>("count");
const pinTitle = () => db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (41,?,?,'applied')")
  .bind(PROVIDER_INITIAL_TITLE_MIGRATION, PROVIDER_INITIAL_TITLE_SHA256).run();

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  for (const file of ["0001_subscriptions.sql", "0002_telegram.sql", "0003_subscription_lifecycle.sql",
    "0015_subscription_provider_jobs.sql", "0021_telegram_provider_admission.sql", "0033_provider_snapshot_journal.sql",
    PROVIDER_INITIAL_TITLE_MIGRATION]) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    if (file === PROVIDER_INITIAL_TITLE_MIGRATION) assert.equal(createHash("sha256").update(sql).digest("hex"), PROVIDER_INITIAL_TITLE_SHA256);
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT) STRICT").run();
});

beforeEach(async () => {
  await db.batch(["provider_snapshot_object_intents", "provider_snapshot_attempts",
    "telegram_provider_initial_titles", "subs_bot_schema_migrations",
    "telegram_provider_requests", "telegram_provider_jobs", "telegram_inbox", "telegram_auth",
    "subscription_provider_jobs", "subscriptions", "subscription_trash", "subscription_lifecycle"]
    .map((table) => db.prepare(`DELETE FROM ${table}`)));
  const { objects } = await bucket.list();
  if (objects.length) await bucket.delete(objects.map(({ key }) => key));
});
after(() => miniflare.dispose());

test("private admission atomically deduplicates, protects URL bytes, and retains the same owner token", async () => {
  const event = source();
  const outcomes = await Promise.all([admit(event), admit(event)]);
  assert.deepEqual(outcomes.map(({ kind }) => kind).toSorted(), ["duplicate", "queued"]);
  const queued = job(outcomes.find(({ kind }) => kind === "queued")!);
  const coalesced = job(await admit(source()));
  assert.equal(coalesced.kind, "coalesced");
  assert.equal(coalesced.subscriptionId, queued.subscriptionId);
  const row = await getOwnedSubscription(db, policy.memberId, queued.subscriptionId);
  assert.equal(row?.name, "远程订阅");
  assert.equal(row?.sourceUrl, sourceUrl);
  assert.equal(row?.generation, 0);
  assert.equal(await getOwnedSubscription(db, policy.adminId, queued.subscriptionId), null);
  const privateState = await db.batch(["telegram_inbox", "telegram_provider_requests", "telegram_provider_jobs", "subscription_provider_jobs"]
    .map((table) => db.prepare(`SELECT * FROM ${table}`)));
  assert.equal(JSON.stringify(privateState).includes(sourceUrl), false);
  assert.equal(JSON.stringify(privateState).includes(row!.token), false);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscriptions").first("count"), 1);
});

test("group, foreign target, and old/equal grant messages do not admit work", async () => {
  const epoch = now() - 10;
  await auth(1, epoch, 900);
  assert.deepEqual(await admit({ ...source(), chatId: policy.groupId, chatType: "group" }), { kind: "ignored" });
  assert.deepEqual(await admit(source(policy.memberId, epoch - 1)), { kind: "ignored" });
  assert.deepEqual(await admit(source(policy.memberId, epoch)), { kind: "ignored" });
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_inbox").first("count"), 0);
  const admin = job(await admit(source(policy.adminId)));
  assert.deepEqual(await admit({ ...scope(), kind: "refresh", id: admin.subscriptionId, expectedGeneration: 0,
    expectedLifecycleRevision: 0 }), { kind: "unavailable" });
  assert.equal((await admit(source(policy.memberId, epoch + 1))).kind, "queued");
});

test("an unconfirmed admission cannot create a second shell or receipt on replay", async () => {
  const event = source();
  const injected = { prepare: db.prepare.bind(db), batch: async (statements: D1PreparedStatement[]) => {
    await db.batch(statements);
    throw new Error(sourceUrl);
  } } as D1Database;
  await assert.rejects(admit(event, injected), { message: "Telegram provider admission could not be confirmed." });
  assert.deepEqual(await admit(event), { kind: "duplicate" });
  for (const table of ["subscriptions", "telegram_inbox", "telegram_provider_requests", "telegram_provider_jobs"]) {
    assert.equal(await db.prepare(`SELECT count(*) AS count FROM ${table}`).first("count"), 1);
  }
});

test("the pre-0021 lease statement only claims generic jobs", async () => {
  const scoped = job(await admit(source()));
  const oldClaim = () => db.prepare(`
    UPDATE subscription_provider_jobs SET state = 'leased', attempts = attempts + 1, lease_id = ?,
      lease_until = min(unixepoch() + 120, expires_at)
    WHERE job_id = (
      SELECT job.job_id FROM subscription_provider_jobs AS job
      WHERE job.expires_at > unixepoch() AND job.attempts < 3 AND EXISTS (
        SELECT 1 FROM subscriptions WHERE subscriptions.id = job.subscription_id AND subscriptions.owner_id = job.owner_id
          AND subscriptions.generation = job.expected_generation
          AND ${SUBSCRIPTION_LIFECYCLE_REVISION} = job.expected_lifecycle_revision
      ) AND ((job.state = 'leased' AND job.lease_until <= unixepoch()) OR
        (job.state = 'pending' AND job.due_at <= unixepoch()
          AND NOT EXISTS (SELECT 1 FROM subscription_provider_jobs WHERE state = 'leased')))
      ORDER BY job.due_at, job.job_id LIMIT 1
    ) RETURNING job_id AS jobId
  `).bind(crypto.randomUUID()).first<number>("jobId");
  assert.equal(await oldClaim(), null);
  assert.equal(await claimProviderJob(db), null);
  const generic = await enqueueProviderUrlImport(db, { ownerId: policy.adminId, requestKey: "a".repeat(64), sourceUrl });
  assert.ok("jobId" in generic);
  assert.equal(await oldClaim(), generic.jobId);
  assert.deepEqual(await db.prepare("SELECT state, attempts FROM telegram_provider_jobs WHERE job_id=?")
    .bind(scoped.jobId).first(), { state: "pending", attempts: 0 });
  assert.equal((await claimProviderJob(db, policy))?.jobId, scoped.jobId);
});

test("generic consumer does not take a scoped job, and a fresh grant does not coalesce onto a revoked epoch", async () => {
  const clock = now();
  await auth(1, clock - 20, 900);
  const prior = job(await admit(source(policy.memberId, clock - 10)));
  const generic = await enqueueProviderUrlImport(db, { ownerId: policy.adminId, requestKey: "a".repeat(64), sourceUrl });
  assert.ok("jobId" in generic);
  const genericLease = await claimProviderJob(db);
  assert.equal(genericLease?.jobId, generic.jobId);
  await db.prepare("UPDATE subscription_provider_jobs SET lease_until=unixepoch()-1, attempts=3 WHERE job_id=?").bind(generic.jobId).run();
  await auth(0, clock - 8, 901);
  await auth(1, clock - 6, 902);
  assert.deepEqual(await admit(source(policy.memberId, clock - 5)), { kind: "capacity" });
  assert.equal(await claimProviderJob(db, policy), null);
  assert.equal(await db.prepare("SELECT result_code FROM telegram_provider_jobs WHERE job_id=?").bind(prior.jobId).first("result_code"), "stale-target");
  const fresh = job(await admit(source(policy.memberId, clock - 4)));
  assert.equal(fresh.kind, "queued");
  assert.equal(fresh.subscriptionId, prior.subscriptionId);
});

test("only the exact bot and actor role may retire a denied job without calling the provider", async () => {
  const scoped = job(await admit(source()));
  await auth(0, now(), 900);
  assert.equal(await claimProviderJob(db, { ...policy, botId: "888" }), null);
  assert.equal(await claimProviderJob(db, { ...policy, memberId: "444" }), null);
  assert.equal(await claimProviderJob(db, { ...policy, adminId: policy.memberId, memberId: policy.adminId }), null);
  assert.equal(await db.prepare("SELECT state FROM telegram_provider_jobs WHERE job_id=?").bind(scoped.jobId).first("state"), "pending");
  const unreachable: ProviderFetcher = { async fetchSubscription() { return assert.fail("Provider RPC must not run"); } };
  assert.equal(await runOneProviderJob(db, bucket, unreachable, pin, policy), "idle");
  assert.equal(await db.prepare("SELECT result_code FROM telegram_provider_jobs WHERE job_id=?").bind(scoped.jobId).first("result_code"), "stale-target");
});

test("authorized terminal refresh failure updates only the fixed warning and preserves the published snapshot", async () => {
  const initial = job(await admit(source()));
  assert.equal(await runOneProviderJob(db, bucket, provider, pin, policy), "saved");
  const saved = await getOwnedSubscription(db, policy.memberId, initial.subscriptionId);
  assert.ok(saved);
  assert.equal(saved.generation, 1);
  assert.equal(saved.trafficUsed, 1);
  const pointer = await getSubscriptionSnapshot(db, saved.token);
  assert.ok(pointer);
  const stale = await admit({ ...scope(), kind: "refresh", id: initial.subscriptionId, expectedGeneration: 0, expectedLifecycleRevision: 0 });
  assert.equal(stale.kind, "unavailable");
  const refresh = job(await admit({ ...scope(), kind: "refresh", id: initial.subscriptionId, expectedGeneration: 1, expectedLifecycleRevision: 0 }));
  assert.equal(refresh.kind, "queued");
  const rejected: ProviderFetcher = { async fetchSubscription() { return { ok: false, code: "http-status", retryable: false, upstreamStatus: 404 }; } };
  assert.equal(await runOneProviderJob(db, bucket, rejected, pin, policy), "done");
  assert.deepEqual(await getOwnedSubscription(db, policy.memberId, initial.subscriptionId), { ...saved, lastError: "provider-refresh-failed" });
  assert.deepEqual(await getSubscriptionSnapshot(db, saved.token), pointer);
  assert.equal((await bucket.list()).objects.length, 2);
});

test("authorization changing after R2 staging prevents publication and preserves the journaled candidate", async () => {
  await pinTitle();
  const initial = job(await admit(source()));
  assert.equal(await titleCount(), 1);
  const injected = { prepare: db.prepare.bind(db), batch: async (statements: D1PreparedStatement[]) => {
    if (statements.length === 8) {
      assert.equal((await bucket.list()).objects.length, 2);
      await auth(0, now(), 900);
    }
    return db.batch(statements);
  } } as D1Database;
  assert.equal(await runOneProviderJob(injected, bucket, provider, pin, policy), "stale");
  const row = await getOwnedSubscription(db, policy.memberId, initial.subscriptionId);
  assert.equal(row?.generation, 0);
  assert.equal(row?.name, "远程订阅");
  assert.equal(row?.lifecycleRevision, 0);
  assert.equal(row?.lastError, null);
  assert.equal(await db.prepare("SELECT result_code FROM telegram_provider_jobs WHERE job_id=?").bind(initial.jobId).first("result_code"), "stale-target");
  assert.equal((await bucket.list()).objects.length, 2);
  assert.equal(await db.prepare("SELECT state FROM provider_snapshot_attempts WHERE queue='telegram_provider_jobs' AND job_id=?")
    .bind(initial.jobId).first("state"), "sealed");
  assert.equal(await db.prepare("SELECT count(*) AS count FROM provider_snapshot_object_intents").first("count"), 2);
});

test("an explicit rename racing initial publication wins the lifecycle CAS", async () => {
  await pinTitle();
  const initial = job(await admit(source()));
  const injected = { prepare: db.prepare.bind(db), batch: async (statements: D1PreparedStatement[]) => {
    if (statements.length === 8) {
      assert.equal(await renameOwnedSubscription(db, { id: initial.subscriptionId, ownerId: policy.memberId,
        expectedLifecycleRevision: 0 }, "Manual choice"), true);
    }
    return db.batch(statements);
  } } as D1Database;
  assert.equal(await runOneProviderJob(injected, bucket, provider, pin, policy), "stale");
  const row = await getOwnedSubscription(db, policy.memberId, initial.subscriptionId);
  assert.equal(row?.name, "Manual choice");
  assert.equal(row?.generation, 0);
  assert.equal(row?.lifecycleRevision, 1);
  assert.equal(await titleCount(), 1);
});

test("a lost publication reply still commits one first title, stable token, snapshot and settlement", async () => {
  await pinTitle();
  const event = source();
  const initial = job(await admit(event));
  const before = await getOwnedSubscription(db, policy.memberId, initial.subscriptionId);
  assert.equal(before?.name, "远程订阅");
  let unconfirmedWrites = 0;
  const injected = { prepare: db.prepare.bind(db), batch: async (statements: D1PreparedStatement[]) => {
    const result = await db.batch(statements);
    if (statements.length === 8) {
      unconfirmedWrites++;
      throw new Error("Unconfirmed synthetic transaction.");
    }
    return result;
  } } as D1Database;
  assert.equal(await runOneProviderJob(injected, bucket, provider, pin, policy), "saved");
  assert.equal(unconfirmedWrites, 1);
  const saved = await getOwnedSubscription(db, policy.memberId, initial.subscriptionId);
  assert.equal(saved?.name, "Example Provider");
  assert.equal(saved?.generation, 1);
  assert.equal(saved?.lifecycleRevision, 1);
  assert.equal(saved?.token, before?.token);
  assert.equal(await titleCount(), 0);
  assert.deepEqual(await admit(event), { kind: "duplicate" });
  assert.equal(await runOneProviderJob(db, bucket, provider, pin, policy), "idle");
  assert.equal((await bucket.list()).objects.length, 2);
  assert.deepEqual(await getOwnedSubscription(db, policy.memberId, initial.subscriptionId), saved);
});

test("first publication with unusable title consumes eligibility and leaves the name alone", async () => {
  await pinTitle();
  const initial = job(await admit(source()));
  assert.equal(await titleCount(), 1);
  const malformed: ProviderFetcher = { async fetchSubscription(input) {
    const fetched = await provider.fetchSubscription(input);
    assert.ok(fetched.ok);
    return { ...fetched, metadata: { "profile-title": "opaque%2Bfixture" } };
  } };
  assert.equal(await runOneProviderJob(db, bucket, malformed, pin, policy), "saved");
  assert.equal(await titleCount(), 0);
  const saved = await getOwnedSubscription(db, policy.memberId, initial.subscriptionId);
  assert.equal(saved?.name, "远程订阅");
  assert.equal(saved?.generation, 1);
  assert.equal(saved?.lifecycleRevision, 0);
});

test("provider titles use bounded display metadata and never copy URL components or malformed filenames", () => {
  assert.equal(initialProviderTitle({ "profile-title": "base64:5rivIFBsYW4ueW1s",
    "content-disposition": "attachment; filename=unused.txt" }, sourceUrl), "港 Plan");
  assert.equal(initialProviderTitle({ "profile-title": "opaque%2Bfixture", "content-disposition":
    "attachment; filename*=UTF-8''%E6%B8%AF%20Provider.txt; filename=fallback.yaml" }, sourceUrl), "港 Provider");
  assert.equal(initialProviderTitle({ "profile-title": "https%3A%2F%2Fprovider.example.invalid",
    "content-disposition": 'attachment; filename="cut;truncated.txt"' }, sourceUrl), null);
  assert.equal(initialProviderTitle({ "profile-title": "Hidden%E2%80%AEText" }, sourceUrl), null);
  assert.equal(initialProviderTitle({ "profile-title": "港".repeat(65) }, sourceUrl), "港".repeat(64));
});

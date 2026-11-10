import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import type { ProviderFetcher } from "../src/provider-fetch-contract.ts";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { claimProviderJob, GENERAL_TELEGRAM_PROVIDER_MARKER, providerSourceDigest,
  TELEGRAM_PROVIDER_MARKER, type GeneralProviderAuthority } from "../src/provider-jobs.ts";
import { createSubscription, digestHex, getOwnedSubscription, getSubscriptionSnapshot, readSnapshotNodes } from "../src/storage.ts";

function backendClass(error: unknown): string {
  for (let depth = 0; depth < 4 && error instanceof Error; depth++, error = error.cause) {
    if (/expression tree is too large|maximum (expression )?depth/iu.test(error.message)) return "expression-depth";
    if (/too many (sql )?variables|wrong number of parameter bindings|wrong number of arguments/iu.test(error.message)) return "bindings";
    if (/no such (table|column)|ambiguous column/iu.test(error.message)) return "schema";
    if (/near .*syntax error/iu.test(error.message)) return "syntax";
    if (/constraint failed/iu.test(error.message)) return "constraint";
  }
  return "unclassified";
}

test("general provider leases are isolated by receipt family and exact authority through publication and retirement", async (t) => {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}}",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const bucket = await runtime.getR2Bucket("NODES");
  await db.prepare(`CREATE TABLE subs_bot_schema_migrations
    (position INTEGER PRIMARY KEY,name TEXT NOT NULL,sha256 TEXT NOT NULL,mode TEXT NOT NULL) STRICT`).run();
  for (const name of ["0001_subscriptions.sql", "0002_telegram.sql", "0003_subscription_lifecycle.sql",
    "0015_subscription_provider_jobs.sql", "0021_telegram_provider_admission.sql", "0033_provider_snapshot_journal.sql",
    "0044_telegram_general_runtime.sql", "0046_telegram_general_receipts.sql"]) {
    const sql = await readFile(new URL(`../migrations/${name}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
  const now = Math.floor(Date.now() / 1000);
  const ownerId = "84103";
  const general: GeneralProviderAuthority = { family: "general", botId: "84101", generation: 1,
    releaseRevision: "a".repeat(40), activationSha256: "b".repeat(64), cutoverAt: now - 1200 };
  const isolated = { botId: general.botId, adminId: "84102", memberId: ownerId };
  const pin = { providerRevision: "c".repeat(40), imageSha256: "d".repeat(64) };
  const sourceUrl = "https://provider.example.invalid/sub/%2f?fixture=opaque%2Bvalue";
  const share = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#provider-fixture";
  const sub = await createSubscription(db, { ownerId, sourceUrl, name: "Explicit fixture name" });
  await db.batch([
    db.prepare(`INSERT INTO telegram_general_policy (bot_id,generation,release_revision,activation_sha256,cutover_at,active)
      VALUES (?,?,?,?,?,1)`).bind(general.botId, general.generation, general.releaseRevision, general.activationSha256, general.cutoverAt),
    db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,1,?,'member')")
      .bind(general.botId, general.generation, ownerId, general.cutoverAt),
  ]);

  // These fixtures seed the eventual admission contract. There is no general webhook entry yet.
  const seed = async (updateId: number, kind: "url-import" | "refresh", generation: number,
    marker = GENERAL_TELEGRAM_PROVIDER_MARKER, receivedAt = now - 800) => {
    const receiptId = await db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce,received_at)
      VALUES (?,?,?,?,'private',?,?,'help',?,?) RETURNING receipt_id`)
      .bind(general.botId, updateId, ownerId, ownerId, updateId, receivedAt, marker, receivedAt).first<number>("receipt_id");
    const jobId = await db.prepare(`INSERT INTO telegram_provider_jobs
      (owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,expected_lifecycle_revision,
        state,created_at,due_at,expires_at)
      VALUES (?,?,?,?,?,?,0,'pending',?,?,?) RETURNING job_id`)
      .bind(ownerId, updateId.toString(16).padStart(64, "0"), kind, sub.id, await providerSourceDigest(sourceUrl), generation,
        receivedAt, receivedAt, receivedAt + 3600).first<number>("job_id");
    assert.ok(receiptId && jobId);
    await db.batch([
      db.prepare(`INSERT INTO telegram_provider_requests VALUES (?,?,?,'admitted','member',0,0)`).bind(receiptId, jobId, kind),
      ...(marker === GENERAL_TELEGRAM_PROVIDER_MARKER ? [db.prepare(`INSERT INTO telegram_general_receipt
        VALUES (?,?,1,'member',?,?,?)`).bind(receiptId, general.generation, general.releaseRevision,
        general.activationSha256, general.cutoverAt)] : []),
    ]);
    return jobId;
  };
  const state = (jobId: number) => db.prepare("SELECT state,result_code AS result,attempts FROM telegram_provider_jobs WHERE job_id=?")
    .bind(jobId).first();

  const firstJob = await seed(101, "url-import", 0);
  assert.equal(await claimProviderJob(db), null);
  assert.equal(await claimProviderJob(db, isolated), null);
  assert.equal(await claimProviderJob(db, { ...general, generation: 2 }), null);
  assert.equal(await claimProviderJob(db, { ...general, releaseRevision: "e".repeat(40) }), null);
  assert.equal(await claimProviderJob(db, { ...general, activationSha256: "e".repeat(64) }), null);
  assert.equal(await claimProviderJob(db, { ...general, cutoverAt: general.cutoverAt + 1 }), null);
  const journalSha = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=33").first<string>("sha256");
  assert.ok(journalSha);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=33").bind("0".repeat(64)).run();
  assert.equal(await claimProviderJob(db, general), null);
  await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=33").bind(journalSha).run();
  assert.deepEqual(await state(firstJob), { state: "pending", result: null, attempts: 0 });

  let calls = 0;
  const provider: ProviderFetcher = { async fetchSubscription(input) {
    calls++;
    assert.deepEqual(input, { url: sourceUrl, ...pin });
    const body = new TextEncoder().encode(share).buffer;
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } };
  let phase = "before-claim";
  let failure = "none";
  const observed = {
    prepare(sql: string) {
      const statement = db.prepare(sql);
      if (!sql.includes("lease_authority AS MATERIALIZED")) return statement;
      phase = "source-prepare";
      return { bind(...values: unknown[]) {
        const query = statement.bind(...values);
        return { async first(column: string) {
          phase = "source-reload";
          try {
            const value = await query.first(column);
            phase = value === null ? "source-missing" : "source-loaded";
            return value;
          } catch (error) {
            failure = backendClass(error);
            throw error;
          }
        } };
      } };
    },
    async batch(statements: D1PreparedStatement[]) {
      phase = phase === "before-claim" ? "claim-batch" : "later-batch";
      try {
        const rows = await db.batch(statements);
        if (phase === "claim-batch") phase = "lease-result";
        return rows;
      } catch (error) {
        failure = backendClass(error);
        throw error;
      }
    },
  } as D1Database;
  const first = await runOneProviderJob(observed, bucket, provider, pin, general).catch(async () => {
    const result = await state(firstJob);
    const status = result?.state === "leased" ? "leased" : result?.state === "pending" ? "pending" : "other";
    assert.fail(`Synthetic provider claim failed (${phase}, ${failure}, ${status}).`);
  });
  assert.equal(first, "saved", `job outlives the ordinary reply clock (${phase}, ${failure})`);
  assert.equal(calls, 1);
  assert.deepEqual(await state(firstJob), { state: "done", result: "saved", attempts: 1 });
  const snapshot = await getSubscriptionSnapshot(db, sub.token);
  assert.ok(snapshot && snapshot.generation === 1);
  assert.deepEqual((await Array.fromAsync(readSnapshotNodes(bucket, snapshot))).map((node) => node.share), [share]);
  assert.equal((await getOwnedSubscription(db, ownerId, sub.id))?.name, sub.name);
  assert.deepEqual(await db.prepare("SELECT queue,bot_id AS botId,state FROM provider_snapshot_attempts").first(),
    { queue: "telegram_provider_jobs", botId: general.botId, state: "published" });

  const changedSource = await seed(105, "refresh", 1, GENERAL_TELEGRAM_PROVIDER_MARKER, now);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(sourceUrl.replace("%2f", "%2F"), sub.id).run();
  assert.equal(await runOneProviderJob(db, bucket, provider, pin, general), "idle");
  assert.equal(calls, 1, "source reload requires the exact admitted digest before egress");
  assert.deepEqual(await state(changedSource), { state: "done", result: "stale-target", attempts: 1 });
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(sourceUrl, sub.id).run();

  const failed = await seed(102, "refresh", 1, GENERAL_TELEGRAM_PROVIDER_MARKER, now);
  assert.equal(await runOneProviderJob(db, bucket, { async fetchSubscription() {
    return { ok: false, code: "http-status", retryable: false, upstreamStatus: 403 };
  } }, pin, general), "done");
  assert.deepEqual(await state(failed), { state: "done", result: "fetch-rejected", attempts: 1 });
  assert.deepEqual(await getSubscriptionSnapshot(db, sub.token), snapshot);

  const revoked = await seed(103, "refresh", 1, GENERAL_TELEGRAM_PROVIDER_MARKER, now);
  assert.equal(await runOneProviderJob(db, bucket, { async fetchSubscription(input) {
    await db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,2,?,'denied')")
      .bind(general.botId, general.generation, ownerId, now).run();
    return provider.fetchSubscription(input);
  } }, pin, general), "stale");
  assert.deepEqual(await state(revoked), { state: "done", result: "stale-target", attempts: 1 });
  assert.deepEqual(await getSubscriptionSnapshot(db, sub.token), snapshot);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM provider_snapshot_attempts").first("n"), 1);

  const isolatedJob = await seed(104, "refresh", 1, TELEGRAM_PROVIDER_MARKER, now);
  assert.equal(await claimProviderJob(db, general), null);
  assert.deepEqual(await state(isolatedJob), { state: "pending", result: null, attempts: 0 });
  assert.equal((await claimProviderJob(db, isolated))?.jobId, isolatedJob);
});

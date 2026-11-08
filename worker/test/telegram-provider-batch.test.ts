import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, beforeEach, test } from "node:test";

import { Miniflare } from "miniflare";

import type { ProviderFetcher } from "../src/provider-fetch-contract.ts";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import {
  claimProviderJob, enqueueOwnedProviderRefresh, isProviderJobCurrent, providerJobLeaseTable, providerSourceDigest,
  settleProviderJob, TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER,
} from "../src/provider-jobs.ts";
import { createSubscription, digestHex, getOwnedSubscription, getSubscriptionSnapshot } from "../src/storage.ts";
import { acceptTelegramProviderRequest } from "../src/telegram/provider-admission.ts";
import {
  prepareTelegramProviderBatchAdmission, readTelegramProviderBatchProgress, reconcileTelegramProviderBatches,
  telegramProviderBatchReady, type TelegramProviderBatchInput,
} from "../src/telegram/provider-batch.ts";
import type { TelegramEventScope, TelegramPolicy } from "../src/telegram/protocol.ts";

const miniflare = new Miniflare({
  modules: true, script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
});
const policy: TelegramPolicy = { botId: "999", botUsername: "synthetic_bot", adminId: "111", memberId: "222", groupId: "-333",
  webhookSecret: "synthetic-webhook-secret", botToken: "999:synthetic-token" };
const pin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const allowed = { sql: "1", bindings: [] };
const fences = { read: allowed, commit: allowed };
const now = () => Math.floor(Date.now() / 1000);
let db: D1Database;
let bucket: R2Bucket;
let update = 0;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  for (const file of ["0001_subscriptions.sql", "0002_telegram.sql", "0003_subscription_lifecycle.sql",
    "0015_subscription_provider_jobs.sql", "0021_telegram_provider_admission.sql", "0031_telegram_provider_batch_queue.sql"]) {
    if (file.startsWith("0031_")) assert.equal(await telegramProviderBatchReady(db), false);
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((part) => db.prepare(part)));
  }
});
beforeEach(async () => {
  await db.batch(["telegram_provider_batch_jobs", "telegram_provider_batches", "telegram_provider_requests", "telegram_provider_jobs",
    "telegram_outbox", "telegram_inbox", "telegram_auth", "subscription_provider_jobs", "subscriptions", "subscription_trash",
    "subscription_lifecycle"].map((table) => db.prepare(`DELETE FROM ${table}`)));
  const { objects } = await bucket.list();
  if (objects.length) await bucket.delete(objects.map(({ key }) => key));
});
after(() => miniflare.dispose());

function event(actorId: string): TelegramEventScope {
  const updateId = ++update;
  return { updateId, actorId, chatId: actorId, chatType: "private", messageId: updateId, messageDate: now(), threadId: null };
}

function inbox(value: TelegramEventScope, marker: string) {
  return db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
    VALUES (?,?,?,?,?,?,?,?,'help',?) ON CONFLICT(bot_id,update_id) DO NOTHING RETURNING receipt_id`)
    .bind(policy.botId, value.updateId, value.actorId, value.chatId, value.chatType, value.messageId, value.messageDate, value.threadId, marker);
}

async function targets(actorId: string, count: number) {
  const result = [];
  for (let i = 0; i < count; i += 1) {
    const sourceUrl = `https://provider.example.invalid/%2f?fixture=${update}-${i}`;
    const created = await createSubscription(db, { ownerId: actorId, sourceUrl, name: "Synthetic" });
    result.push({ id: created.id, generation: 0, lifecycleRevision: 0, sourceSha256: await providerSourceDigest(sourceUrl), sourceUrl });
  }
  return result;
}

async function preview(actorId: string, items: TelegramProviderBatchInput["targets"]): Promise<TelegramProviderBatchInput> {
  const original = event(actorId);
  const previewReceiptId = await inbox(original, TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER).first<number>("receipt_id");
  assert.ok(previewReceiptId);
  const messageId = 100_000 + original.messageId;
  await db.prepare("INSERT INTO telegram_outbox (receipt_id,state,attempts,sent_message_id) VALUES (?,'sent',1,?)")
    .bind(previewReceiptId, messageId).run();
  return { previewReceiptId, confirmation: { ...event(actorId), messageId }, originAttempt: 1,
    epoch: { role: actorId === policy.adminId ? "admin" : "member", messageDate: 0, messageId: 0 }, targets: items, skippedCount: 2 };
}

async function start(input: TelegramProviderBatchInput) {
  const steps = await prepareTelegramProviderBatchAdmission(db, policy, input, fences);
  assert.ok(steps);
  const result = await db.batch([inbox(input.confirmation, TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER), ...steps]);
  return (result[1].results[0] as { batchId: number } | undefined)?.batchId ?? null;
}

async function queue(queuePolicy = policy, promote = true) {
  let failure: unknown;
  let outcomes: { success: boolean; changes: number }[] = [];
  const observed = {
    prepare: db.prepare.bind(db),
    async batch<T>(statements: D1PreparedStatement[]) {
      try {
        const results = await db.batch<T>(statements);
        outcomes = results.map(({ success, meta }) => ({ success, changes: meta.changes }));
        return results;
      } catch (error) {
        failure = error;
        throw error;
      }
    },
  } as D1Database;
  try {
    return await reconcileTelegramProviderBatches(observed, queuePolicy, promote);
  } catch (error) {
    throw new Error(`Synthetic reconciliation statement outcomes ${JSON.stringify(outcomes)}`, { cause: failure ?? error });
  }
}

async function status(actorId = policy.memberId, batchId?: number) {
  return readTelegramProviderBatchProgress(db, policy, actorId, batchId);
}

async function count(table: "telegram_provider_batch_jobs" | "telegram_provider_batches") {
  return db.prepare(`SELECT count(*) AS n FROM ${table}`).first<number>("n");
}

test("admits exactly sixteen frozen targets once and keeps source URLs out of durable records", async () => {
  assert.equal(await telegramProviderBatchReady(db), true);
  const items = await targets(policy.memberId, 17);
  const input = await preview(policy.memberId, items.slice(0, 16));
  assert.equal(await prepareTelegramProviderBatchAdmission(db, policy, { ...input, targets: items }, fences), null);
  assert.equal(await prepareTelegramProviderBatchAdmission(db, policy, { ...input, targets: [] }, fences), null);
  const results = await Promise.all([start(input), start(input)]);
  const batchId = results.find((value) => value !== null);
  assert.ok(batchId);
  assert.equal(results.filter((value) => value !== null).length, 1);
  assert.equal(await count("telegram_provider_batches"), 1);
  const stored = await db.prepare("SELECT * FROM telegram_provider_batch_jobs ORDER BY ordinal").all();
  assert.deepEqual(stored.results.map(({ subscription_id }) => subscription_id), items.slice(0, 16).map(({ id }) => id));
  assert.equal(JSON.stringify(stored).includes(items[0].sourceUrl), false);
  assert.deepEqual(await status(policy.memberId, batchId), { batchId, targetCount: 16, skippedCount: 2, finishedAt: null,
    waiting: 16, pending: 0, leased: 0, saved: 0, failed: 0, stale: 0, expired: 0 });
  assert.equal(await status(policy.adminId, batchId), null);
});

test("wrong message, attempt, role, ticket fence and superseded previews cannot admit work", async () => {
  const items = await targets(policy.memberId, 1);
  const old = await preview(policy.memberId, items);
  const current = await preview(policy.memberId, items);
  for (const input of [old, { ...current, originAttempt: 2 }, { ...current, confirmation: { ...current.confirmation, messageId: 1 } },
    { ...current, epoch: { ...current.epoch, role: "admin" as const } },
    { ...current, confirmation: { ...current.confirmation, chatType: "group" as const, chatId: policy.groupId } },
    { ...current, confirmation: { ...current.confirmation, actorId: policy.adminId, chatId: policy.adminId } }]) {
    assert.equal(await prepareTelegramProviderBatchAdmission(db, policy, input, fences), null);
  }
  assert.equal(await prepareTelegramProviderBatchAdmission(db, policy, current, { ...fences, read: { sql: "0", bindings: [] } }), null);
  const staleAtCommit = await prepareTelegramProviderBatchAdmission(db, policy, current, { ...fences, commit: { sql: "0", bindings: [] } });
  assert.ok(staleAtCommit);
  await db.batch([inbox(current.confirmation, TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER), ...staleAtCommit]);
  assert.equal(await count("telegram_provider_batches"), 0);
});

test("a source race rolls back the real confirmation and all children", async () => {
  const items = await targets(policy.adminId, 2);
  const input = await preview(policy.adminId, items);
  const steps = await prepareTelegramProviderBatchAdmission(db, policy, input, fences);
  assert.ok(steps);
  await db.prepare("UPDATE subscriptions SET source_url=? WHERE id=?").bind(items[1].sourceUrl + "&changed=1", items[1].id).run();
  await assert.rejects(db.batch([inbox(input.confirmation, TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER), ...steps]));
  assert.equal(await db.prepare("SELECT 1 FROM telegram_inbox WHERE update_id=?").bind(input.confirmation.updateId).first(), null);
  assert.equal(await count("telegram_provider_batches"), 0);
  assert.equal(await count("telegram_provider_batch_jobs"), 0);
});

test("single and batch Telegram work share capacity, same-target exclusion and one lease while generic stays separate", async () => {
  const items = await targets(policy.memberId, 6);
  const input = await preview(policy.memberId, items);
  assert.ok(await start(input));
  const single = (id: number) => acceptTelegramProviderRequest(db, policy, {
    ...event(policy.memberId), kind: "refresh", id, expectedGeneration: 0, expectedLifecycleRevision: 0,
  }, true);
  assert.equal((await single(items[0].id)).kind, "queued");
  const promotions = await Promise.all(Array.from({ length: 5 }, () => queue()));
  assert.equal(promotions.reduce((total, { promoted }) => total + promoted, 0), 3);
  assert.equal((await status())?.pending, 3);
  assert.equal((await single(items[4].id)).kind, "capacity");
  assert.equal(await db.prepare("SELECT state FROM telegram_provider_batch_jobs WHERE subscription_id=?").bind(items[0].id)
    .first("state"), "waiting");

  const olderScoped = await claimProviderJob(db, policy);
  assert.ok(olderScoped);
  assert.equal(providerJobLeaseTable(olderScoped), "telegram_provider_jobs");
  assert.equal(await claimProviderJob(db, policy, true), null);
  const generic = await enqueueOwnedProviderRefresh(db, { ownerId: policy.memberId, id: items[4].id, requestKey: "c".repeat(64) });
  assert.equal(generic.kind, "queued");
  assert.equal((await claimProviderJob(db))?.scope, "generic");
  await settleProviderJob(db, olderScoped, { kind: "failed", reason: "fetch-rejected" });
  assert.equal(await claimProviderJob(db, policy), null);
  const claims = await Promise.all([claimProviderJob(db, policy, true), claimProviderJob(db, policy, true)]);
  const leased = claims.find((value) => value !== null);
  assert.ok(leased);
  assert.equal(claims.filter(Boolean).length, 1);
  assert.equal(providerJobLeaseTable(leased), "telegram_provider_batch_jobs");
  assert.equal((await status())?.leased, 1);
  assert.equal(await claimProviderJob(db, policy), null);
});

test("revoke and role change fence live work and freeze the exact stale and deadline outcomes", async () => {
  const items = await targets(policy.memberId, 2);
  const input = await preview(policy.memberId, items);
  assert.ok(await start(input));
  await queue();
  const lease = await claimProviderJob(db, policy, true);
  assert.ok(lease);
  await db.prepare("INSERT INTO telegram_auth VALUES (?,?,0,?,1)").bind(policy.botId, policy.memberId, now()).run();
  assert.equal(await isProviderJobCurrent(db, lease), false);
  assert.equal(await status(), null);
  const swapped = { ...policy, adminId: policy.memberId, memberId: policy.adminId };
  assert.equal(await settleProviderJob(db, lease, { kind: "retry", reason: "timeout" }), "stale");
  assert.deepEqual(await queue(swapped), { promoted: 0, finished: 1 });
  assert.equal(await status(), null);
  assert.equal(await db.prepare("SELECT stale_count FROM telegram_provider_batches").first("stale_count"), 2);

  const adminTargets = await targets(policy.adminId, 1);
  assert.ok(await start(await preview(policy.adminId, adminTargets)));
  const past = now() - 2701;
  await db.batch([
    db.prepare("UPDATE telegram_provider_batches SET created_at=?,expires_at=? WHERE actor_id=?")
      .bind(past, past + 2700, policy.adminId),
    db.prepare("UPDATE telegram_provider_batch_jobs SET created_at=?,due_at=?,expires_at=? WHERE owner_id=?")
      .bind(past, past, past + 2700, policy.adminId),
  ]);
  assert.deepEqual(await queue(policy, false), { promoted: 0, finished: 1 });
  assert.equal((await status(policy.adminId))?.expired, 1);
});

test("a role swap can retire old work but cannot read, promote or lease it", async () => {
  const items = await targets(policy.memberId, 1);
  const batchId = await start(await preview(policy.memberId, items));
  assert.ok(batchId);
  const swapped = { ...policy, adminId: policy.memberId, memberId: policy.adminId };
  assert.equal(await readTelegramProviderBatchProgress(db, swapped, policy.memberId, batchId), null);
  assert.deepEqual(await queue(swapped), { promoted: 0, finished: 1 });
  assert.equal(await claimProviderJob(db, swapped, true), null);
  assert.equal(await db.prepare("SELECT stale_count FROM telegram_provider_batches").first("stale_count"), 1);
});

test("a partial or failed schema probe cannot enable the batch queue", async () => {
  const partial = { prepare: () => ({ first: async () => 1 }) } as unknown as D1Database;
  const failed = { prepare: () => { throw new Error("Synthetic readiness failure."); } } as unknown as D1Database;
  for (const connection of [partial, failed]) {
    await assert.rejects(telegramProviderBatchReady(connection), {
      message: "Telegram provider batch schema could not be confirmed.",
    });
  }
});

test("the existing publication transaction handles ambiguous batch success and later failure retains the snapshot", async () => {
  const [target] = await targets(policy.adminId, 1);
  assert.ok(await start(await preview(policy.adminId, [target])));
  await queue();
  const good: ProviderFetcher = { async fetchSubscription(input) {
    assert.deepEqual(input, { url: target.sourceUrl, ...pin });
    const body = new TextEncoder().encode("ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#fixture").buffer;
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } };
  const lost = {
    prepare: db.prepare.bind(db),
    batch: async (statements: D1PreparedStatement[]) => {
      const result = await db.batch(statements);
      if (statements.length === 3) throw new Error("Synthetic lost publication response");
      return result;
    },
  } as D1Database;
  assert.equal(await runOneProviderJob(lost, bucket, good, pin, policy, true), "saved");
  assert.deepEqual(await queue(), { promoted: 0, finished: 1 });
  assert.equal((await status(policy.adminId))?.saved, 1);
  const subscription = await getOwnedSubscription(db, policy.adminId, target.id);
  assert.ok(subscription);
  const before = await getSubscriptionSnapshot(db, subscription.token);
  assert.ok(before?.snapshotId);

  const denied: ProviderFetcher = { async fetchSubscription() { return { ok: false, code: "blocked-address", retryable: false }; } };
  const invalid: ProviderFetcher = { async fetchSubscription() {
    const body = new TextEncoder().encode("not a subscription document").buffer;
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } };
  for (const [provider, failure] of [[denied, "fetch-rejected"], [invalid, "invalid-document"]] as const) {
    const batchId = await start(await preview(policy.adminId, [{ ...target, generation: 1 }]));
    assert.ok(batchId);
    await queue();
    assert.equal(await runOneProviderJob(db, bucket, provider, pin, policy, true), "done");
    assert.deepEqual(await queue(), { promoted: 0, finished: 1 });
    const finished = await status(policy.adminId);
    assert.equal(finished?.failed, 1);
    assert.equal(finished?.saved, 0);
    assert.deepEqual(await db.prepare("SELECT failure_code,result_code FROM telegram_provider_batch_jobs WHERE batch_id=?")
      .bind(batchId).first(), { failure_code: failure, result_code: failure });
    assert.deepEqual(await getSubscriptionSnapshot(db, subscription.token), before);
    assert.deepEqual(await queue(), { promoted: 0, finished: 0 });
    assert.deepEqual(await status(policy.adminId), finished);
  }
});

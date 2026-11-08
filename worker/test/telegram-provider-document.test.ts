import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { after, before, beforeEach, test } from "node:test";
import { Miniflare } from "miniflare";

import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { claimProviderJob, providerSourceDigest, settleProviderJob } from "../src/provider-jobs.ts";
import { createSubscription, digestHex } from "../src/storage.ts";
import {
  acceptTelegramDocumentJob, claimTelegramDocumentJob, type TelegramDocumentJobInput,
} from "../src/telegram/document-jobs.ts";
import { acceptTelegramProviderRequest } from "../src/telegram/provider-admission.ts";
import { promoteTelegramProviderDocument, settleTelegramProviderDocuments, stageTelegramProviderDocument } from "../src/telegram/provider-document.ts";
import { TELEGRAM_PROVIDER_DOCUMENT_MARKER } from "../src/telegram/provider-document-origin.ts";
import { reconcileTelegramProviderDocumentReplies, renderTelegramProviderDocumentReply } from "../src/telegram/provider-document-replies.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import {
  acceptTelegramCommand, beginTelegramProviderDocumentReply, claimTelegramReply, reapExpiredTelegramReplies, settleTelegramReply,
} from "../src/telegram/store.ts";

const miniflare = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"],
  r2Buckets: ["NODES"], script: "export default { fetch() { return new Response(null); } };" });
const policy: TelegramPolicy = { botId: "76101", botUsername: "Fixture_Provider_Document_Bot",
  adminId: "75101", memberId: "75102", groupId: "-1001234567890",
  webhookSecret: "synthetic-webhook-secret", botToken: "76101:synthetic-token" };
const documents = { ...policy, includeDocuments: true } as const;
const pin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const now = () => Math.floor(Date.now() / 1000);
let db: D1Database;
let bucket: R2Bucket;
let updateId = 0;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const migrations = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrations), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});
beforeEach(async () => {
  await db.batch(["provider_snapshot_object_intents", "provider_snapshot_attempts",
    "telegram_provider_document_lines", "telegram_provider_documents", "telegram_provider_document_opt_in",
    "telegram_provider_requests", "telegram_provider_jobs", "telegram_document_jobs", "telegram_outbox",
    "telegram_inbox", "telegram_auth", "subscriptions", "subscription_lifecycle"].map((table) => db.prepare(`DELETE FROM ${table}`)));
});
after(() => miniflare.dispose());

function event(): TelegramDocumentJobInput {
  const id = ++updateId;
  return { updateId: id, actorId: policy.memberId, chatId: policy.memberId, chatType: "private", messageId: id,
    messageDate: now(), threadId: null, fileId: `synthetic-file-${id}`, fileName: "Fixture.txt", fileSize: 123 };
}

function urls(count: number, label = "document") {
  return Array.from({ length: count }, (_, ordinal) => `https://provider.example.invalid/${label}/${ordinal}?fixture=%2f`);
}

async function stage(input: TelegramDocumentJobInput, values: string[], overflow = 0) {
  assert.equal(await acceptTelegramDocumentJob(db, policy, input, true), "accepted");
  const lease = await claimTelegramDocumentJob(db, policy);
  assert.ok(lease);
  assert.equal(await stageTelegramProviderDocument(db, policy, lease, { kind: "url-list", urls: values, overflow }), true);
  return lease.receiptId;
}

function lines(receiptId: number) {
  return db.prepare(`SELECT ordinal,due_at,source_sha256,subscription_id,expected_generation,expected_lifecycle_revision,job_id,result_code
    FROM telegram_provider_document_lines WHERE receipt_id=? ORDER BY ordinal`).bind(receiptId).all<{
    ordinal: number; due_at: number; source_sha256: string; subscription_id: number;
    expected_generation: number; expected_lifecycle_revision: number; job_id: number | null; result_code: string | null;
  }>();
}

test("only fresh opted-in private files can stage URL work", async () => {
  for (const messageDate of [now() - 1200, now() + 60]) {
    assert.equal(await acceptTelegramDocumentJob(db, policy, { ...event(), messageDate, fileName: `${messageDate}.txt` }, true), "accepted");
  }
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_provider_document_opt_in").first("count"), 0);
  const lease = await claimTelegramDocumentJob(db, policy);
  assert.ok(lease);
  assert.equal(await stageTelegramProviderDocument(db, policy, lease, { kind: "url-list", urls: urls(1), overflow: 0 }), false);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM subscriptions").first("count"), 0);
});

test("the complete reply schema still claims ordinary private commands", async () => {
  const input = event();
  await acceptTelegramCommand(db, policy, { ...input, command: "help" });
  await reapExpiredTelegramReplies(db, policy.botId, true, true, true, true, true, true, false, true, false, true, true, true, true, true);
  const lease = await claimTelegramReply(db, policy.botId, true, true, true, true, true, true, undefined, true, false,
    policy, true, policy, policy, policy);
  assert.equal(lease?.command, "help");
});

test("seals twenty exact owned targets in order and settles one summary after all jobs", { timeout: 60_000 }, async () => {
  const values = urls(20);
  const existing = await createSubscription(db, { ownerId: policy.memberId, sourceUrl: values[0], name: "Existing" });
  await db.prepare("INSERT INTO subscription_lifecycle VALUES (?,7)").bind(existing.id).run();
  const foreign = await createSubscription(db, { ownerId: policy.adminId, sourceUrl: values[0], name: "Foreign" });
  const input = event();
  const receipt = await stage(input, values, 2);
  assert.equal(await acceptTelegramDocumentJob(db, policy, input, true), "ignored");
  assert.deepEqual(await db.prepare(`SELECT inbox.receipt_nonce AS marker,origin.line_count,origin.overflow_count,
    origin.actor_role,job.file_id,job.lease_id,
    EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=inbox.receipt_id) AS outbox
    FROM telegram_provider_documents AS origin JOIN telegram_document_jobs AS job USING (receipt_id)
    JOIN telegram_inbox AS inbox USING (receipt_id) WHERE origin.receipt_id=?`).bind(receipt).first(),
  { marker: TELEGRAM_PROVIDER_DOCUMENT_MARKER, line_count: 20, overflow_count: 2, actor_role: "member",
    file_id: null, lease_id: null, outbox: 0 });
  const staged = (await lines(receipt)).results;
  assert.deepEqual(staged.map(({ ordinal }) => ordinal), values.map((_, ordinal) => ordinal));
  assert.deepEqual(staged.map(({ source_sha256 }) => source_sha256), await Promise.all(values.map(providerSourceDigest)));
  assert.equal(staged[0].subscription_id, existing.id);
  assert.equal(staged[0].expected_lifecycle_revision, 7);
  assert(staged.every((line) => line.subscription_id !== foreign.id && line.job_id === null && line.result_code === null
    && line.expected_generation === 0));
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_provider_jobs").first("count"), 0);

  await promoteTelegramProviderDocument(db, policy, false);
  assert.equal(await claimProviderJob(db, policy, false), null);
  const body = new TextEncoder().encode("ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.4:8388#fixture").buffer;
  assert.equal(await runOneProviderJob(db, bucket, { async fetchSubscription(input) {
    assert.deepEqual(input, { url: values[0], ...pin });
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } }, pin, documents, false), "saved");
  await settleTelegramProviderDocuments(db, policy);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, policy), 0);
  assert.deepEqual(await db.prepare("SELECT generation,owner_id FROM subscriptions WHERE id=?").bind(existing.id).first(),
    { generation: 1, owner_id: policy.memberId });

  for (const sourceUrl of values.slice(1)) {
    await promoteTelegramProviderDocument(db, policy, false);
    const lease = await claimProviderJob(db, documents, false);
    assert.ok(lease);
    assert.equal(lease.sourceUrl, sourceUrl);
    assert.equal(await settleProviderJob(db, lease, { kind: "failed", reason: "fetch-rejected" }), "done");
  }
  await settleTelegramProviderDocuments(db, policy);
  const finished = (await lines(receipt)).results;
  assert.deepEqual(finished.map(({ result_code }) => result_code), ["saved", ...Array(19).fill("fetch-rejected")]);
  assert.equal(new Set(finished.map(({ job_id }) => job_id)).size, 20);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, policy), 1);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, policy), 0);
  assert.deepEqual(await db.prepare("SELECT receipt_id FROM telegram_outbox").first(), { receipt_id: receipt });
  const reply = await claimTelegramReply(db, policy.botId, true, true, true, true, true, true, policy, true, true,
    policy, true, policy, policy, policy);
  assert.equal(reply?.receiptId, receipt);
  assert.ok(reply?.providerDocument);
  const summary = await renderTelegramProviderDocumentReply(db, policy, reply);
  assert.equal(summary?.text, "订阅链接文件已处理。\n已保存 1 条\n已合并 0 条\n失败 19 条\n超出上限 2 条");
  assert.equal(await beginTelegramProviderDocumentReply(db, policy, reply, summary?.guard), true);
  await settleTelegramReply(db, policy, reply, { kind: "sent", messageId: 55501 });
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, policy), 0);
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox").first("state"), "sent");
});

test("shared owner quota defers an exact line and allows a later due line to progress", { timeout: 30_000 }, async () => {
  for (const sourceUrl of urls(4, "ordinary")) {
    assert.equal((await acceptTelegramProviderRequest(db, policy, { ...event(), sourceUrl, kind: "url-import" })).kind, "queued");
  }
  const values = urls(2);
  const receipt = await stage(event(), values);
  const original = (await lines(receipt)).results;
  await promoteTelegramProviderDocument(db, policy, false);
  const deferred = (await lines(receipt)).results;
  assert(deferred[0].due_at > original[0].due_at);
  assert.equal(deferred[0].job_id, null);
  assert.equal(deferred[0].result_code, null);
  assert.equal(deferred[1].due_at, original[1].due_at);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_provider_jobs WHERE state='pending'").first("count"), 4);
  const ordinary = await claimProviderJob(db, documents, false);
  assert.ok(ordinary);
  assert.equal(ordinary.kind, "url-import");
  assert.equal(await settleProviderJob(db, ordinary, { kind: "failed", reason: "fetch-rejected" }), "done");
  await promoteTelegramProviderDocument(db, policy, false);
  const promoted = (await lines(receipt)).results;
  assert.equal(promoted[0].job_id, null);
  assert.ok(promoted[1].job_id);
});

test("stale lifecycle and revoked epoch never create another provider job", { timeout: 30_000 }, async () => {
  const input = event();
  const receipt = await stage(input, urls(3));
  const staged = (await lines(receipt)).results;
  await db.prepare("INSERT INTO subscription_lifecycle VALUES (?,1)").bind(staged[0].subscription_id).run();
  await promoteTelegramProviderDocument(db, policy, false);
  assert.equal((await lines(receipt)).results[0].result_code, "stale-target");
  await promoteTelegramProviderDocument(db, policy, false);
  assert.ok((await lines(receipt)).results[1].job_id);
  await db.prepare("INSERT INTO telegram_auth VALUES (?,?,0,?,?)")
    .bind(policy.botId, policy.memberId, input.messageDate + 1, input.messageId + 1).run();
  assert.equal(await claimProviderJob(db, documents, false), null);
  await promoteTelegramProviderDocument(db, policy, false);
  await settleTelegramProviderDocuments(db, policy);
  assert.deepEqual((await lines(receipt)).results.map(({ result_code }) => result_code), ["stale-target", "stale-target", "access-changed"]);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_provider_jobs").first("count"), 1);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, policy), 0);
});

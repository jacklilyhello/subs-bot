import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";

import { claimProviderJob, providerSourceDigest, settleProviderJob } from "../src/provider-jobs.ts";
import { getSubscriptionSnapshot, readSnapshotNodes } from "../src/storage.ts";
import { acceptTelegramDocumentJob, claimTelegramDocumentJob, type TelegramDocumentJobInput } from "../src/telegram/document-jobs.ts";
import {
  finishTelegramDocumentJob, persistTelegramDocumentJob, reconcileTelegramDocumentJobReplies, retireTelegramDocumentStage,
} from "../src/telegram/document-persistence.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { promoteTelegramProviderDocument, settleTelegramProviderDocuments, stageTelegramProviderDocument } from "../src/telegram/provider-document.ts";
import { TELEGRAM_PROVIDER_DOCUMENT_MARKER } from "../src/telegram/provider-document-origin.ts";
import { reconcileTelegramProviderDocumentReplies, renderTelegramProviderDocumentReply } from "../src/telegram/provider-document-replies.ts";
import { beginTelegramProviderDocumentReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";

const miniflare = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default { fetch() { return new Response(null); } };" });
let db: D1Database;
let bucket: R2Bucket;

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const migrations = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrations), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});
after(() => miniflare.dispose());

function policy(cohort: number): TelegramPolicy {
  const botId = String(76120 + cohort);
  return { botId, botUsername: "Fixture_Mixed_Document_Bot", adminId: String(75600 + 2 * cohort),
    memberId: String(75601 + 2 * cohort), groupId: "-1001234567890", webhookSecret: "synthetic-webhook-secret",
    botToken: `${botId}:synthetic-token` };
}

function event(config: TelegramPolicy, id: number, fileName = "Mixed.txt"): TelegramDocumentJobInput {
  return { updateId: id, actorId: config.memberId, chatId: config.memberId, chatType: "private", messageId: id,
    messageDate: Math.floor(Date.now() / 1000), threadId: null, fileId: `synthetic-file-${id}`, fileName, fileSize: 123 };
}

const raw = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.4:8388#fixture";
const node = { type: "ss", name: "fixture", server: "203.0.113.4", port: 8388, share: raw };
const remoteUrl = "https://provider.example.invalid/mixed?fixture=%2f";
const mixed = { urls: [remoteUrl], overflow: 0 };

async function claim(config: TelegramPolicy, input: TelegramDocumentJobInput, mixedOptIn = true) {
  assert.equal(await acceptTelegramDocumentJob(db, config, input, true, mixedOptIn), "accepted");
  const lease = await claimTelegramDocumentJob(db, config);
  assert.ok(lease);
  return lease;
}

function pointer(config: TelegramPolicy) {
  return db.prepare(`SELECT id,token,generation,snapshot_id,node_count FROM subscriptions
    WHERE owner_id=? AND name='Mixed' AND source_url='uploaded://telegram-document'`)
    .bind(config.memberId).first<{ id: number; token: string; generation: number; snapshot_id: string; node_count: number }>();
}

function effects(config: TelegramPolicy, receiptId: number) {
  return db.prepare(`SELECT
    (SELECT count(*) FROM telegram_provider_documents WHERE receipt_id=?) AS parents,
    (SELECT count(*) FROM telegram_provider_document_lines WHERE receipt_id=?) AS lines,
    (SELECT count(*) FROM subscriptions WHERE owner_id=? AND source_url=?) AS remote,
    (SELECT count(*) FROM telegram_document_saved_counts WHERE receipt_id=?) AS saved,
    (SELECT count(*) FROM telegram_outbox WHERE receipt_id=?) AS outbox`)
    .bind(receiptId, receiptId, config.memberId, remoteUrl, receiptId, receiptId).first();
}

function beforeFirstPut(operation: () => Promise<unknown>): R2Bucket {
  let first = true;
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "put") return async (key: string, value: Uint8Array, options: R2PutOptions) => {
        if (first) {
          first = false;
          await operation();
        }
        return target.put(key, value, options);
      };
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

async function original(config: TelegramPolicy) {
  const lease = await claim(config, event(config, 1), false);
  assert.equal(await persistTelegramDocumentJob(db, bucket, config, lease, [node], { parsed: 1 }), "saved");
  const prior = await pointer(config);
  assert.ok(prior);
  return prior;
}

test("mixed publication commits the owned local snapshot and exact URL plan, then emits one private summary", async () => {
  const config = policy(1);
  const foreign = policy(5);
  const foreignLease = await claim(foreign, event(foreign, 1, "Foreign.txt"), false);
  assert.equal(await stageTelegramProviderDocument(db, foreign, foreignLease, { kind: "url-list", ...mixed }), true);
  const input = event(config, 1);
  const lease = await claim(config, input);
  assert.equal(await persistTelegramDocumentJob(db, bucket, config, lease, [node], { parsed: 1 }, mixed), "saved");
  assert.equal(await acceptTelegramDocumentJob(db, config, input, true, true), "ignored");
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  assert.deepEqual(await effects(config, lease.receiptId), { parents: 1, lines: 1, remote: 1, saved: 1, outbox: 0 });
  assert.deepEqual(await db.prepare(`SELECT inbox.receipt_nonce AS marker,job.state,job.result_code,job.file_id,
    (SELECT count(*) FROM telegram_provider_document_opt_in WHERE receipt_id=job.receipt_id) AS urlOptIn,
    (SELECT count(*) FROM telegram_mixed_document_opt_in WHERE receipt_id=job.receipt_id) AS mixedOptIn,
    (SELECT count(*) FROM telegram_document_stages WHERE receipt_id=job.receipt_id) AS stages
    FROM telegram_inbox AS inbox JOIN telegram_document_jobs AS job USING (receipt_id) WHERE job.receipt_id=?`)
    .bind(lease.receiptId).first(),
  { marker: TELEGRAM_PROVIDER_DOCUMENT_MARKER, state: "done", result_code: "saved", file_id: null, urlOptIn: 0, mixedOptIn: 0, stages: 0 });

  const local = await pointer(config);
  assert.ok(local);
  const snapshot = await getSubscriptionSnapshot(db, local.token);
  assert.ok(snapshot);
  assert.equal(snapshot.generation, 1);
  const restored = [];
  for await (const record of readSnapshotNodes(bucket, snapshot)) restored.push(record);
  assert.deepEqual(restored, [node]);
  assert.deepEqual(await db.prepare(`SELECT line.ordinal,line.source_sha256,line.expected_generation,
    line.expected_lifecycle_revision,line.job_id,line.result_code,sub.owner_id,sub.source_url
    FROM telegram_provider_document_lines AS line JOIN subscriptions AS sub ON sub.id=line.subscription_id
    WHERE line.receipt_id=?`).bind(lease.receiptId).first(),
  { ordinal: 0, source_sha256: await providerSourceDigest(remoteUrl), expected_generation: 0, expected_lifecycle_revision: 0,
    job_id: null, result_code: null, owner_id: config.memberId, source_url: remoteUrl });
  assert.equal(await reconcileTelegramDocumentJobReplies(db, config), 0);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, config), 0);

  await promoteTelegramProviderDocument(db, config, false);
  const job = await claimProviderJob(db, { ...config, includeDocuments: true }, false);
  assert.ok(job);
  assert.equal(job.sourceUrl, remoteUrl);
  assert.equal(await settleProviderJob(db, job, { kind: "failed", reason: "fetch-rejected" }), "done");
  await settleTelegramProviderDocuments(db, config);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, config), 1);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, config), 0);
  const reply = await claimTelegramReply(db, config.botId, true, true, true, true, true, true, config, true, true,
    config, true, config, config, config);
  assert.equal(reply?.receiptId, lease.receiptId);
  assert.ok(reply?.providerDocument);
  const summary = await renderTelegramProviderDocumentReply(db, config, reply);
  assert.ok(summary);
  assert.equal(summary.text, "混合文件已处理。\n本地节点已保存 1 个\n远程订阅已保存 0 条\n已合并 0 条\n失败 1 条\n超出上限 0 条");
  assert.equal(await beginTelegramProviderDocumentReply(db, config, reply, summary.guard), true);
  await settleTelegramReply(db, config, reply, { kind: "sent", messageId: 55501 });
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, config), 0);
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?").bind(lease.receiptId).first("state"), "sent");
});

test("an outstanding URL document blocks mixed replacement and creates no second URL shell", async () => {
  const config = policy(2);
  const prior = await original(config);
  const outstanding = await claim(config, event(config, 2, "Outstanding.txt"), false);
  assert.equal(await stageTelegramProviderDocument(db, config, outstanding, {
    kind: "url-list", urls: ["https://provider.example.invalid/outstanding"], overflow: 0,
  }), true);
  const replacement = await claim(config, event(config, 3));
  assert.equal(await persistTelegramDocumentJob(db, bucket, config, replacement, [node], { parsed: 1 }, mixed), "stale");
  assert.deepEqual(await pointer(config), prior);
  assert.deepEqual(await effects(config, replacement.receiptId), { parents: 0, lines: 0, remote: 0, saved: 0, outbox: 1 });
  assert.deepEqual(await db.prepare("SELECT state,result_code FROM telegram_document_jobs WHERE receipt_id=?")
    .bind(replacement.receiptId).first(), { state: "done", result_code: "coalesced" });
  assert.deepEqual(await db.prepare("SELECT finished_at FROM telegram_provider_documents WHERE receipt_id=?")
    .bind(outstanding.receiptId).first(), { finished_at: null });
});

test("a lifecycle CAS change during R2 staging rolls back URL shells and preserves the prior snapshot", async () => {
  const config = policy(3);
  const prior = await original(config);
  const replacement = await claim(config, event(config, 2));
  const raced = beforeFirstPut(() => db.prepare("INSERT INTO subscription_lifecycle VALUES (?,1)").bind(prior.id).run());
  await assert.rejects(persistTelegramDocumentJob(db, raced, config, replacement, [node], { parsed: 1 }, mixed),
    /Telegram document publication could not be confirmed/u);
  assert.deepEqual(await pointer(config), prior);
  assert.deepEqual(await effects(config, replacement.receiptId), { parents: 0, lines: 0, remote: 0, saved: 0, outbox: 0 });
  const candidate = await db.prepare("SELECT snapshot_id FROM telegram_document_stages WHERE receipt_id=?")
    .bind(replacement.receiptId).first<string>("snapshot_id");
  assert.ok(candidate);
  const candidateKey = `subscriptions/${prior.id}/${candidate}/manifest.json`;
  const priorKey = `subscriptions/${prior.id}/${prior.snapshot_id}/manifest.json`;
  assert.ok(await bucket.head(candidateKey));
  assert.equal(await finishTelegramDocumentJob(db, config, replacement, { kind: "retry" }), "retry");
  await db.prepare("UPDATE telegram_document_stages SET cleanup_after=unixepoch()-1 WHERE receipt_id=?").bind(replacement.receiptId).run();
  await retireTelegramDocumentStage(db, bucket, config);
  assert.equal(await bucket.head(candidateKey), null);
  assert.ok(await bucket.head(priorKey));
});

test("losing the committed mixed batch response cannot duplicate work or create an ordinary reply", async () => {
  const config = policy(4);
  const input = event(config, 1);
  const lease = await claim(config, input);
  let loseCommit = false;
  let lost = false;
  const watchedBucket = beforeFirstPut(async () => { loseCommit = true; });
  const responseLost = new Proxy(db, {
    get(target, property) {
      if (property === "batch") return async (steps: D1PreparedStatement[]) => {
        const result = await target.batch(steps);
        if (loseCommit && !lost) {
          lost = true;
          throw new Error("Synthetic committed D1 response loss");
        }
        return result;
      };
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  await assert.rejects(persistTelegramDocumentJob(responseLost, watchedBucket, config, lease, [node], { parsed: 1 }, mixed),
    /Telegram document publication could not be confirmed/u);
  assert.equal(lost, true);
  assert.equal(await finishTelegramDocumentJob(db, config, lease, { kind: "retry" }), "stale");
  assert.equal(await acceptTelegramDocumentJob(db, config, input, true, true), "ignored");
  assert.equal(await reconcileTelegramDocumentJobReplies(db, config), 0);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, config), 0);
  assert.deepEqual(await effects(config, lease.receiptId), { parents: 1, lines: 1, remote: 1, saved: 1, outbox: 0 });
  assert.equal((await pointer(config))?.generation, 1);
});

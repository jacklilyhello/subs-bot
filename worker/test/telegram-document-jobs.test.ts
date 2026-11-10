import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import {
  acceptTelegramDocumentJob, claimTelegramDocumentJob, prepareTelegramDocumentJobLeaseGuard,
  settleTelegramDocumentJob, TELEGRAM_DOCUMENT_JOB_MARKER, TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER, type TelegramDocumentJobInput,
  type TelegramDocumentJobLease,
} from "../src/telegram/document-jobs.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { persistTelegramDocumentJob, reconcileTelegramDocumentJobReplies, retireTelegramDocumentStage } from "../src/telegram/document-persistence.ts";

const miniflare = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"],
  r2Buckets: ["NODES"],
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

function policy(botId: string): TelegramPolicy {
  return { botId, botUsername: "Fixture_Document_Bot", adminId: "75001", memberId: "75002", groupId: "-1001234567890",
    webhookSecret: "synthetic-secret", botToken: `${botId}:synthetic-token` };
}

function event(config: TelegramPolicy, updateId: number, options: Partial<TelegramDocumentJobInput> = {}): TelegramDocumentJobInput {
  return { updateId, actorId: config.memberId, chatId: config.memberId, chatType: "private", messageId: updateId,
    messageDate: 1_800_000_000, threadId: null, fileId: `synthetic-file-${updateId}`, fileName: "Fixture.txt", fileSize: 123,
    ...options };
}

function admin(config: TelegramPolicy, updateId: number, fileName = "Fixture.txt"): TelegramDocumentJobInput {
  return event(config, updateId, { actorId: config.adminId, chatId: config.adminId, fileName });
}

function stored(config: TelegramPolicy, updateId: number) {
  return db.prepare(`
    SELECT inbox.receipt_nonce AS marker, inbox.received_at AS receivedAt, job.*,
      EXISTS (SELECT 1 FROM telegram_outbox AS reply WHERE reply.receipt_id = job.receipt_id) AS hasOutbox
    FROM telegram_inbox AS inbox JOIN telegram_document_jobs AS job USING (receipt_id)
    WHERE inbox.bot_id = ? AND inbox.update_id = ?
  `).bind(config.botId, updateId).first<Record<string, unknown>>();
}

async function assertScrubbed(config: TelegramPolicy, updateId: number, reason: string, hasOutbox = 0,
  marker: string | null = TELEGRAM_DOCUMENT_JOB_MARKER) {
  const row = await stored(config, updateId);
  assert.ok(row);
  assert.equal(row.marker, marker);
  assert.equal(row.state, "done");
  assert.equal(row.result_code, reason);
  assert.ok(Number.isSafeInteger(row.finished_at));
  assert.equal(row.hasOutbox, hasOutbox);
  for (const field of ["file_id", "name", "suffix", "expected_size", "lease_id", "lease_until"]) {
    assert.equal(row[field], null);
  }
}

function setFixtureDocumentMarker(config: TelegramPolicy, updateId: number, marker: string | null) {
  return db.prepare("UPDATE telegram_inbox SET receipt_nonce = ? WHERE bot_id = ? AND update_id = ?")
    .bind(marker, config.botId, updateId);
}

async function checkLease(config: TelegramPolicy, lease: TelegramDocumentJobLease): Promise<number | null> {
  const guard = prepareTelegramDocumentJobLeaseGuard(config, lease);
  return db.prepare(`SELECT ${guard.sql} AS allowed`).bind(...guard.bindings).first<number>("allowed");
}

function expireLease(lease: TelegramDocumentJobLease) {
  return db.prepare("UPDATE telegram_document_jobs SET lease_until = unixepoch() - 1 WHERE receipt_id = ?")
    .bind(lease.receiptId).run();
}

async function leaseDocument(config: TelegramPolicy, update: number, input: Partial<TelegramDocumentJobInput> = {}) {
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, update, input)), "accepted");
  const lease = await claimTelegramDocumentJob(db, config);
  assert.ok(lease);
  return lease;
}

const node = { type: "ss", name: "synthetic", server: "203.0.113.4", port: 8388 };

function onFirstPut(operation: () => Promise<void>): R2Bucket {
  let first = true;
  return new Proxy(bucket, {
    get(target, method) {
      if (method === "put") return async (key: string, value: Uint8Array, options: R2PutOptions) => {
        if (first) {
          first = false;
          await operation();
        }
        return target.put(key, value, options);
      };
      const value = Reflect.get(target, method) as unknown;
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

test("publication blocks reordered replacement and ties the saved pointer, count and reply to one receipt", async () => {
  const config = { ...policy("76119"), memberId: "75119" };
  const current = await leaseDocument(config, 2);
  assert.equal(await persistTelegramDocumentJob(db, bucket, config, current, [node], { parsed: 1 }), "saved");
  const pointer = () => db.prepare("SELECT id, token, generation, snapshot_id FROM subscriptions WHERE owner_id = ?")
    .bind(config.memberId).first<{ id: number; snapshot_id: string }>();
  const saved = await pointer();
  assert.ok(saved);
  assert.ok(await bucket.head(`subscriptions/${saved.id}/${saved.snapshot_id}/manifest.json`));
  assert.deepEqual(await db.prepare(`SELECT node_count FROM telegram_document_saved_counts AS saved
    JOIN telegram_outbox AS reply USING (receipt_id) WHERE saved.receipt_id = ?`).bind(current.receiptId).first(), { node_count: 1 });
  await assertScrubbed(config, 2, "saved", 1);

  const older = await leaseDocument(config, 1);
  assert.equal(await persistTelegramDocumentJob(db, bucket, config, older, [{ ...node, name: "older" }], { parsed: 1 }), "stale");
  await assertScrubbed(config, 1, "coalesced", 1);
  assert.deepEqual(await pointer(), saved);
});

test("a lost lease cannot publish or delete the last valid snapshot and its journal can be retired", async () => {
  const config = { ...policy("76120"), memberId: "75120" };
  const original = await leaseDocument(config, 1);
  assert.equal(await persistTelegramDocumentJob(db, bucket, config, original, [node], { parsed: 1 }), "saved");
  const storedPointer = () => db.prepare("SELECT id, generation, snapshot_id FROM subscriptions WHERE owner_id = ?")
    .bind(config.memberId).first<{ id: number; snapshot_id: string }>();
  const prior = await storedPointer();
  assert.ok(prior);
  const replacement = await leaseDocument(config, 2);
  const expired = onFirstPut(async () => { await expireLease(replacement); });
  assert.equal(await persistTelegramDocumentJob(db, expired, config, replacement, [node], { parsed: 1 }), "stale");
  assert.deepEqual(await storedPointer(), prior);
  const stage = await db.prepare("SELECT snapshot_id FROM telegram_document_stages WHERE receipt_id = ?")
    .bind(replacement.receiptId).first<string>("snapshot_id");
  assert.ok(stage);
  const stageKey = `subscriptions/${prior.id}/${stage}/manifest.json`;
  assert.ok(await bucket.head(stageKey));
  await retireTelegramDocumentStage(db, bucket, config);
  assert.ok(await bucket.head(stageKey));
  await db.prepare("UPDATE telegram_document_stages SET cleanup_after = unixepoch() - 1 WHERE receipt_id = ?")
    .bind(replacement.receiptId).run();
  await retireTelegramDocumentStage(db, bucket, config);
  assert.equal(await bucket.head(stageKey), null);
  assert.ok(await bucket.head(`subscriptions/${prior.id}/${prior.snapshot_id}/manifest.json`));
  assert.equal((await stored(config, 2))?.hasOutbox, 0);
});

test("admits only canonical private actors and records bounded normalized file metadata without an outbox", async () => {
  const config = policy("76101");
  for (const overrides of [
    { actorId: "999999", chatId: "999999" }, { chatId: config.adminId }, { chatType: "group", chatId: config.groupId },
    { chatType: "supergroup", chatId: config.groupId }, { threadId: 1 }, { messageId: 0 },
  ] satisfies Partial<TelegramDocumentJobInput>[]) {
    assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1, overrides)), "ignored");
  }
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE bot_id = ?")
    .bind(config.botId).first<number>("n"), 0);
  const malformed = [
    { fileId: "has space" }, { fileId: "a".repeat(513) }, { fileName: "fixture.exe" },
    { fileName: "evil\nname.yaml" }, { fileSize: -1 }, { fileSize: 10 * 1024 * 1024 + 1 },
  ];
  for (const [index, overrides] of malformed.entries()) {
    const update = 10 + index;
    assert.equal(await acceptTelegramDocumentJob(db, config, event(config, update, overrides)), "invalid-document");
    await assertScrubbed(config, update, "invalid-document", 1);
  }

  const long = "测试".repeat(40);
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1, {
    fileName: `C:\\synthetic\\${long}.YAML`, fileSize: 10 * 1024 * 1024,
  })), "accepted");
  const row = await stored(config, 1);
  assert.ok(row);
  assert.equal(row.marker, TELEGRAM_DOCUMENT_JOB_MARKER);
  assert.equal(row.name, "测试".repeat(32));
  assert.equal(row.suffix, "yaml");
  assert.equal(row.expected_size, 10 * 1024 * 1024);
  assert.equal(row.file_id, "synthetic-file-1");
  assert.equal(row.hasOutbox, 0);
  assert.equal(Number(row.expires_at) - Number(row.receivedAt), 600);
});

test("deduplicates inbox updates and coalesces active exact owner names with scrubbed tombstones", async () => {
  const config = policy("76102");
  const outcomes = await Promise.all([1, 1, 2].map((id) => acceptTelegramDocumentJob(db, config, event(config, id))));
  assert.deepEqual(outcomes.sort(), ["accepted", "coalesced", "ignored"]);
  const first = await stored(config, 1);
  const second = await stored(config, 2);
  assert.ok(first && second);
  const busy = first.state === "done" ? 1 : 2;
  await assertScrubbed(config, busy, "coalesced", 1);

  assert.equal(await acceptTelegramDocumentJob(db, config, admin(config, 3)), "accepted");
  assert.equal(await acceptTelegramDocumentJob(db, policy("76103"), event(policy("76103"), 1)), "accepted");
  const claims = await Promise.all([claimTelegramDocumentJob(db, config), claimTelegramDocumentJob(db, config)]);
  const lease = claims.find((item) => item !== null);
  assert.ok(lease);
  assert.equal(claims.filter(Boolean).length, 1);
  assert.equal(lease.actorId, config.memberId);
  assert.equal(await checkLease(policy("76103"), lease), 0);
  assert.equal(await settleTelegramDocumentJob(db, config, lease, { kind: "failed", reason: "invalid-document" }), "done");
  await assertScrubbed(config, busy === 1 ? 2 : 1, "invalid-document");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, busy)), "ignored");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 4)), "accepted");
});

test("caps active jobs per owner and Bot while preserving same-name coalescing", async () => {
  const config = policy("76107");
  const submit = (id: number) => acceptTelegramDocumentJob(db, config, event(config, id, { fileName: `Owner ${id}.txt` }));
  for (const id of [1, 2, 3]) assert.equal(await submit(id), "accepted");
  const leased = await claimTelegramDocumentJob(db, config);
  assert.ok(leased);
  const racing = await Promise.all([submit(4), submit(5)]);
  assert.deepEqual([...racing].sort(), ["accepted", "capacity"]);
  const rejected = 4 + racing.indexOf("capacity");
  await assertScrubbed(config, rejected, "capacity", 1);
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 6, { fileName: "Owner 1.yaml" })), "coalesced");
  await assertScrubbed(config, 6, "coalesced", 1);
  assert.equal(await settleTelegramDocumentJob(db, config, leased, { kind: "failed", reason: "invalid-document" }), "done");
  assert.equal(await submit(rejected), "ignored");
  assert.equal(await submit(7), "accepted");

  // Prior configured actors can leave rows that have not yet been reaped after a policy change.
  let nextId = 20;
  for (const actor of ["75003", "75004", "75005"]) {
    const previous = { ...config, memberId: actor };
    for (const number of [1, 2, 3, 4]) {
      assert.equal(await acceptTelegramDocumentJob(db, previous,
        event(previous, nextId++, { fileName: `Previous ${number}.txt` })), "accepted");
    }
  }
  assert.equal(await acceptTelegramDocumentJob(db, config, admin(config, 50)), "capacity");
  await assertScrubbed(config, 50, "capacity", 1);
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 51, { fileName: "Owner 2.json" })), "coalesced");
  await assertScrubbed(config, 51, "coalesced", 1);
  assert.equal(await db.prepare(`SELECT count(*) AS n FROM telegram_document_jobs
    WHERE bot_id = ? AND state IN ('pending', 'leased')`).bind(config.botId).first<number>("n"), 16);
});

test("recovers an expired lease, fences its former holder, and limits fixed retries to three attempts", async () => {
  const config = policy("76104");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1)), "accepted");
  const first = await claimTelegramDocumentJob(db, config);
  assert.ok(first);
  assert.equal(first.attempts, 1);
  assert.equal(await checkLease(config, first), 1);
  await expireLease(first);
  assert.equal(await checkLease(config, first), 0);

  const second = await claimTelegramDocumentJob(db, config);
  assert.ok(second);
  assert.equal(second.receiptId, first.receiptId);
  assert.notEqual(second.leaseId, first.leaseId);
  assert.equal(second.attempts, 2);
  assert.equal(await settleTelegramDocumentJob(db, config, first, { kind: "retry" }), "stale");
  const before = Number(await db.prepare("SELECT unixepoch() AS now").first<number>("now"));
  assert.equal(await settleTelegramDocumentJob(db, config, second, { kind: "retry" }), "retry");
  const after = Number(await db.prepare("SELECT unixepoch() AS now").first<number>("now"));
  const pending = await stored(config, 1);
  assert.ok(pending);
  assert.equal(pending.file_id, "synthetic-file-1");
  assert.ok(Number(pending.due_at) >= before + 45 && Number(pending.due_at) <= after + 45);
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  await db.prepare("UPDATE telegram_document_jobs SET due_at = unixepoch() - 1 WHERE receipt_id = ?")
    .bind(first.receiptId).run();
  const third = await claimTelegramDocumentJob(db, config);
  assert.ok(third);
  assert.equal(third.attempts, 3);
  await expireLease(third);
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  await assertScrubbed(config, 1, "attempts-exhausted");
});

test("revocation and regrant invalidate admitted work while preserving a live lease lane until expiry", async () => {
  const config = policy("76105");
  const setAccess = (allowed: number, version: number) => db.prepare(`
    INSERT INTO telegram_auth (bot_id, user_id, allowed, message_date, message_id) VALUES (?, ?, ?, 1000, ?)
    ON CONFLICT (bot_id, user_id) DO UPDATE SET allowed = excluded.allowed, message_id = excluded.message_id
  `).bind(config.botId, config.memberId, allowed, version).run();

  await setAccess(1, 1);
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1)), "accepted");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 2, { fileName: "Pending.yml" })), "accepted");
  const lease = await claimTelegramDocumentJob(db, config);
  assert.ok(lease);
  assert.equal(await checkLease(config, lease), 1);
  await setAccess(0, 2);
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 3)), "ignored");
  assert.equal(await checkLease(config, lease), 0);
  assert.equal(await settleTelegramDocumentJob(db, config, lease, { kind: "failed", reason: "download-rejected" }), "stale");
  assert.equal(await acceptTelegramDocumentJob(db, config, admin(config, 4)), "accepted");
  await setAccess(1, 3);
  assert.equal(await checkLease(config, lease), 0);
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  await assertScrubbed(config, 2, "access-changed");
  await expireLease(lease);
  assert.equal((await claimTelegramDocumentJob(db, config))?.actorId, config.adminId);
  await assertScrubbed(config, 1, "access-changed");
});

test("terminalizes expired work and retains deduplication without retaining opaque fields", async () => {
  const config = policy("76106");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1)), "accepted");
  const lease = await claimTelegramDocumentJob(db, config);
  assert.ok(lease);
  await db.prepare(`UPDATE telegram_document_jobs SET due_at = unixepoch() - 2,
    expires_at = unixepoch() - 1, lease_until = unixepoch() - 1 WHERE receipt_id = ?`).bind(lease.receiptId).run();
  assert.equal(await checkLease(config, lease), 0);
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  await assertScrubbed(config, 1, "expired");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1)), "ignored");
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 2)), "accepted");
});

test("isolated reaping leaves the exact general document family alone and still scrubs isolated orphans", async () => {
  const config = policy("76110");
  const generalLease = await leaseDocument(config, 1, { fileName: "General leased.txt" });
  for (const [updateId, name] of [[2, "General pending"], [3, "Null marker"], [4, "Unknown marker"]] as const) {
    assert.equal(await acceptTelegramDocumentJob(db, config, event(config, updateId, { fileName: name + ".txt" })), "accepted");
  }
  assert.equal(await acceptTelegramDocumentJob(db, config, admin(config, 5, "Isolated expired.txt")), "accepted");
  const unknown = "general-document-job:v2";
  const expired = await stored(config, 5);
  assert.ok(expired);
  await db.batch([
    setFixtureDocumentMarker(config, 1, TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER),
    setFixtureDocumentMarker(config, 2, TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER),
    setFixtureDocumentMarker(config, 3, null),
    setFixtureDocumentMarker(config, 4, unknown),
    db.prepare(`UPDATE telegram_document_jobs SET due_at = unixepoch() - 2, expires_at = unixepoch() - 1,
      lease_until = CASE WHEN state = 'leased' THEN unixepoch() - 1 END WHERE receipt_id IN (?, ?)`)
      .bind(generalLease.receiptId, expired.receipt_id),
  ]);

  const general = await Promise.all([1, 2].map((updateId) => stored(config, updateId)));
  assert.ok(general[0] && general[1]);
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  assert.deepEqual(await Promise.all([1, 2].map((updateId) => stored(config, updateId))), general);
  await assertScrubbed(config, 3, "access-changed", 0, null);
  await assertScrubbed(config, 4, "access-changed", 0, unknown);
  await assertScrubbed(config, 5, "expired");
});

test("isolated cleanup retains general terminal reservations and R2 stages", async () => {
  const config = policy("76111");
  const journals = [];
  for (const [updateId, subscriptionId, age] of [[1, 960001, 1], [2, 960002, 60]] as const) {
    const lease = await leaseDocument(config, updateId);
    assert.equal(await settleTelegramDocumentJob(db, config, lease, { kind: "failed", reason: "invalid-document" }), "done");
    const snapshotId = crypto.randomUUID();
    const key = `subscriptions/${subscriptionId}/${snapshotId}/manifest.json`;
    await db.batch([
      db.prepare(`INSERT INTO telegram_document_reservations
        (receipt_id,subscription_id,generation,lifecycle_revision) VALUES (?,?,0,0)`).bind(lease.receiptId, subscriptionId),
      db.prepare(`INSERT INTO telegram_document_stages
        (snapshot_id,receipt_id,subscription_id,lease_id,cleanup_after) VALUES (?,?,?,?,unixepoch()-?)`)
        .bind(snapshotId, lease.receiptId, subscriptionId, lease.leaseId, age),
    ]);
    await bucket.put(key, "synthetic-stage");
    journals.push({ receiptId: lease.receiptId, key });
  }
  await setFixtureDocumentMarker(config, 2, TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER).run();
  const [isolated, general] = journals;
  assert.equal(await reconcileTelegramDocumentJobReplies(db, config), 1);
  await assertScrubbed(config, 1, "invalid-document", 1);
  await assertScrubbed(config, 2, "invalid-document", 0, TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER);
  const remaining = async (table: "telegram_document_reservations" | "telegram_document_stages") =>
    (await db.prepare(`SELECT receipt_id FROM ${table} WHERE receipt_id IN (?, ?) ORDER BY receipt_id`)
      .bind(isolated.receiptId, general.receiptId).all<{ receipt_id: number }>()).results;
  assert.deepEqual(await remaining("telegram_document_reservations"), [{ receipt_id: general.receiptId }]);
  await retireTelegramDocumentStage(db, bucket, config);
  await retireTelegramDocumentStage(db, bucket, config);
  assert.equal(await bucket.head(isolated.key), null);
  assert.equal(await (await bucket.get(general.key))?.text(), "synthetic-stage");
  assert.deepEqual(await remaining("telegram_document_stages"), [{ receipt_id: general.receiptId }]);
});

test("first-seen pre-grant documents do not acquire the new epoch after revocation and regrant", async () => {
  const config = policy("76108");
  const grantDate = 1_800_000_000;
  // Preserve the initial member default and its original durable receipt.
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 1,
    { fileName: "Baseline.txt", messageDate: grantDate - 10 })), "accepted");
  const baseline = await stored(config, 1);
  assert.ok(baseline);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 49999)")
    .bind(config.botId, config.memberId, grantDate - 2).run();
  await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=?,message_id=50000 WHERE bot_id=? AND user_id=?")
    .bind(grantDate, config.botId, config.memberId).run();

  for (const [updateId, messageDate] of [[2, grantDate - 3], [3, grantDate - 1], [4, grantDate]] as const) {
    // No cross-chat message-ID comparison can authorize an older or equal-date member event.
    assert.equal(await acceptTelegramDocumentJob(db, config, event(config, updateId,
      { fileName: `Delayed ${updateId}.txt`, messageDate, messageId: 100000 + updateId })), "ignored");
    assert.equal(await stored(config, updateId), null);
    assert.equal(await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?")
      .bind(config.botId, updateId).first(), null);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_document_jobs WHERE bot_id=?")
      .bind(config.botId).first<number>("n"), 1);
    assert.equal(await db.prepare(`SELECT count(*) AS n FROM telegram_outbox JOIN telegram_inbox USING(receipt_id)
      WHERE bot_id=?`).bind(config.botId).first<number>("n"), 0);
    assert.deepEqual(await stored(config, 1), baseline);
  }
  assert.equal(await acceptTelegramDocumentJob(db, config, event(config, 5,
    { fileName: "Fresh.txt", messageDate: grantDate + 1, messageId: 1 })), "accepted");
  const fresh = await stored(config, 5);
  assert.ok(fresh);
  assert.equal(fresh.auth_message_date, grantDate);
  assert.equal(fresh.auth_message_id, 50000);
  // The member's auth epoch does not gate the administrator's own private document.
  assert.equal(await acceptTelegramDocumentJob(db, config,
    { ...admin(config, 6, "Admin baseline.txt"), messageDate: grantDate - 100 }), "accepted");
  const administrator = await stored(config, 6);
  assert.ok(administrator);
  assert.equal(administrator.auth_message_date, 0);
  assert.equal(administrator.auth_message_id, 0);
  const lease = await claimTelegramDocumentJob(db, config);
  assert.ok(lease);
  assert.equal(lease.receiptId, fresh.receipt_id);
  assert.equal(await checkLease(config, lease), 1);
});

test("reaps legacy queued documents that captured a grant newer than their original messages", async () => {
  const config = policy("76109");
  const grantDate = 1_800_000_000;
  for (const [updateId, messageDate] of [[1, grantDate - 1], [2, grantDate]] as const) {
    assert.equal(await acceptTelegramDocumentJob(db, config, event(config, updateId,
      { fileName: `Legacy ${updateId}.txt`, messageDate })), "accepted");
  }
  const lease = await claimTelegramDocumentJob(db, config);
  assert.ok(lease);
  await db.prepare("INSERT INTO telegram_auth VALUES (?, ?, 0, ?, 49999)")
    .bind(config.botId, config.memberId, grantDate - 2).run();
  await db.prepare("UPDATE telegram_auth SET allowed=1,message_date=?,message_id=50000 WHERE bot_id=? AND user_id=?")
    .bind(grantDate, config.botId, config.memberId).run();
  // Model the prior version's bad first-admission state: current epoch, but a pre/equal-grant message.
  await db.prepare("UPDATE telegram_document_jobs SET auth_message_date=?,auth_message_id=50000 WHERE bot_id=?")
    .bind(grantDate, config.botId).run();
  assert.equal(await checkLease(config, lease), 0);
  await expireLease(lease);
  assert.equal(await claimTelegramDocumentJob(db, config), null);
  for (const updateId of [1, 2]) await assertScrubbed(config, updateId, "access-changed");
});

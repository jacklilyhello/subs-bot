import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { LEGACY_ALL_MIGRATION, LEGACY_ALL_MIGRATION_SHA256 } from "../src/legacy-all-aggregates.ts";
import { createSubscription, getOwnedSubscription, type SubscriptionMetadata } from "../src/storage.ts";
import { restoreOwnedSubscription, trashOwnedSubscription } from "../src/subscriptions.ts";
import { acceptTelegramDocumentJob, claimTelegramDocumentJob } from "../src/telegram/document-jobs.ts";
import { persistTelegramDocumentJob } from "../src/telegram/document-persistence.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256 } from "../src/telegram/temp-storage.ts";

const miniflare = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default { fetch() { return new Response(null); } };" });
let db: D1Database;
let bucket: R2Bucket;
const inventorySha = "4".repeat(64);

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const migrations = new URL("../migrations/", import.meta.url);
  for (const file of (await readdir(migrations)).filter((name) => name.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(file, migrations), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  await db.batch([
    db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT) STRICT"),
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (39,?,?,'applied')")
      .bind(LEGACY_TEMP_MIGRATION_NAME, LEGACY_TEMP_MIGRATION_SHA256),
    db.prepare("INSERT INTO subs_bot_schema_migrations VALUES (40,?,?,'applied')")
      .bind(LEGACY_ALL_MIGRATION, LEGACY_ALL_MIGRATION_SHA256),
  ]);
});
after(() => miniflare.dispose());

async function marked(bot: string, owner: string, code: string, active = true) {
  await db.batch([
    db.prepare("INSERT INTO legacy_temp_installations VALUES (?,?,CASE WHEN ?=1 THEN unixepoch()-1 END)")
      .bind(bot, inventorySha, Number(active)),
    db.prepare("INSERT INTO aggregate_links(code_sha256,bot_id,owner_id,kind) VALUES (?,?,?,'all')").bind(code, bot, owner),
    db.prepare("INSERT INTO legacy_all_aggregates VALUES (?,?,?,?)").bind(code, bot, owner, inventorySha),
  ]);
}

function create(ownerId: string, name: string) {
  return createSubscription(db, { ownerId, name, sourceUrl: "https://provider.example.invalid/fixed" });
}

function target(row: SubscriptionMetadata, expectedLifecycleRevision = row.lifecycleRevision) {
  return { id: row.id, ownerId: row.ownerId, expectedLifecycleRevision };
}

function rank(id: number) {
  return db.prepare("SELECT anchor,tie FROM legacy_all_subscription_order WHERE subscription_id=?")
    .bind(id).first<{ anchor: number; tie: number }>();
}

function ordered(owner: string) {
  return db.prepare(`SELECT sub.id FROM subscriptions AS sub LEFT JOIN legacy_all_subscription_order AS rank ON rank.subscription_id=sub.id
    WHERE sub.owner_id=? ORDER BY COALESCE(rank.anchor,sub.id),COALESCE(rank.tie,0),sub.id`).bind(owner).all<{ id: number }>();
}

test("restores stable IDs and tokens at the allocator tail, with monotonic per-owner ties and no stale rewrite", async () => {
  const owner = "87001";
  await marked("87101", owner, "a".repeat(64));
  const first = await create(owner, "First");
  const second = await create(owner, "Second");
  const other = await create("87002", "Unmarked");
  assert.equal(await trashOwnedSubscription(db, target(first)), true);
  assert.equal(await trashOwnedSubscription(db, target(second)), true);
  assert.equal(await restoreOwnedSubscription(db, target(first, 1)), true);
  assert.equal(await restoreOwnedSubscription(db, target(second, 1)), true);
  assert.deepEqual(await rank(first.id), { anchor: other.id, tie: 1 });
  assert.deepEqual(await rank(second.id), { anchor: other.id, tie: 2 });
  assert.equal(await restoreOwnedSubscription(db, target(first, 1)), false);
  assert.deepEqual(await rank(first.id), { anchor: other.id, tie: 1 });

  const newest = await create(owner, "Newest");
  assert.equal(await rank(newest.id), null);
  assert.equal(await trashOwnedSubscription(db, target(first, 2)), true);
  assert.equal(await restoreOwnedSubscription(db, target(first, 3)), true);
  assert.deepEqual(await rank(first.id), { anchor: newest.id, tie: 1 });
  assert.deepEqual((await ordered(owner)).results.map(({ id }) => id), [second.id, newest.id, first.id]);
  assert.equal((await getOwnedSubscription(db, owner, first.id))?.token, first.token);

  assert.equal(await trashOwnedSubscription(db, target(other)), true);
  assert.equal(await restoreOwnedSubscription(db, target(other, 1)), true);
  assert.equal(await rank(other.id), null);
});

test("rejects affected marked restores under a wrong ledger or dormant installation", async () => {
  await marked("87102", "87003", "b".repeat(64));
  await marked("87103", "87004", "c".repeat(64), false);
  const affected = await create("87003", "Affected");
  const dormant = await create("87004", "Dormant");
  const unmarked = await create("87005", "Unmarked");
  for (const row of [affected, dormant, unmarked]) assert.equal(await trashOwnedSubscription(db, target(row)), true);
  await assert.rejects(restoreOwnedSubscription(db, target(dormant, 1)), /could not be confirmed/u);
  assert.equal(await getOwnedSubscription(db, dormant.ownerId, dormant.id), null);
  assert.equal(await rank(dormant.id), null);

  const changePin = (sha: string) => db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=40").bind(sha).run();
  await changePin("0".repeat(64));
  try {
    await assert.rejects(restoreOwnedSubscription(db, target(affected, 1)), /could not be confirmed/u);
    assert.equal(await getOwnedSubscription(db, affected.ownerId, affected.id), null);
    assert.equal(await rank(affected.id), null);
    assert.equal(await restoreOwnedSubscription(db, target(unmarked, 1)), true);
  } finally {
    await changePin(LEGACY_ALL_MIGRATION_SHA256);
  }
  assert.equal(await restoreOwnedSubscription(db, target(affected, 1)), true);
  await db.prepare("UPDATE legacy_temp_installations SET cutover_epoch=unixepoch()-1 WHERE bot_id='87103'").run();
  assert.equal(await restoreOwnedSubscription(db, target(dormant, 1)), true);
});

test("orders delayed mixed document publication after intervening subscriptions and before its new URL shells", async () => {
  const policy: TelegramPolicy = { botId: "87104", botUsername: "Fixture_Order_Bot", adminId: "87006", memberId: "87007",
    groupId: "-1001234567890", webhookSecret: "synthetic-secret", botToken: "87104:synthetic-token" };
  const owner = policy.memberId;
  await marked(policy.botId, owner, "d".repeat(64));
  const claim = async (updateId: number, mixed = false, fileName = "Ordered.txt") => {
    assert.equal(await acceptTelegramDocumentJob(db, policy, { updateId, actorId: owner, chatId: owner, chatType: "private",
      messageId: updateId, messageDate: Math.floor(Date.now() / 1000), threadId: null,
      fileId: `synthetic-file-${updateId}`, fileName, fileSize: 123 }, mixed, mixed), "accepted");
    const lease = await claimTelegramDocumentJob(db, policy);
    assert.ok(lease);
    return lease;
  };
  const nodes = [{ name: "Fixture", share: "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.4:8388#fixture" }];
  let intervening: SubscriptionMetadata | undefined;
  const delayed = new Proxy(bucket, {
    get(target, property) {
      if (property === "put") return async (key: string, bytes: Uint8Array, options: R2PutOptions) => {
        intervening ??= await create(owner, "Intervening");
        return target.put(key, bytes, options);
      };
      const value: unknown = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const lease = await claim(1, true);
  const source = "https://provider.example.invalid/mixed";
  assert.equal(await persistTelegramDocumentJob(db, delayed, policy, lease, nodes, { parsed: 1 },
    { urls: [source], overflow: 0 }), "saved");
  assert.ok(intervening);
  const saved = await db.prepare("SELECT id,token,generation FROM subscriptions WHERE owner_id=? AND name='Ordered'")
    .bind(owner).first<{ id: number; token: string; generation: number }>();
  assert.ok(saved);
  const shell = await db.prepare("SELECT id FROM subscriptions WHERE owner_id=? AND source_url=?").bind(owner, source).first<number>("id");
  assert.ok(shell);
  assert.ok(saved.id < intervening.id);
  assert.ok(shell > intervening.id);
  assert.deepEqual(await rank(saved.id), { anchor: intervening.id, tie: 1 });
  assert.deepEqual((await ordered(owner)).results.map(({ id }) => id), [intervening.id, saved.id, shell]);

  const later = await create(owner, "Later");
  assert.equal(await persistTelegramDocumentJob(db, bucket, policy, await claim(2), nodes, { parsed: 1 }), "saved");
  assert.equal((await getOwnedSubscription(db, owner, saved.id))?.token, saved.token);
  assert.equal((await getOwnedSubscription(db, owner, saved.id))?.generation, 2);
  assert.deepEqual(await rank(saved.id), { anchor: intervening.id, tie: 1 });
  assert.deepEqual((await ordered(owner)).results.map(({ id }) => id), [intervening.id, saved.id, shell, later.id]);

  const blocked = await claim(3, false, "Blocked.txt");
  await db.prepare(`CREATE TRIGGER suppress_fixture_order BEFORE INSERT ON legacy_all_subscription_order
    BEGIN SELECT RAISE(IGNORE); END`).run();
  try {
    await assert.rejects(persistTelegramDocumentJob(db, bucket, policy, blocked, nodes, { parsed: 1 }), /could not be confirmed/u);
    assert.equal(await db.prepare("SELECT id FROM subscriptions WHERE owner_id=? AND name='Blocked'").bind(owner).first(), null);
    assert.equal(await db.prepare("SELECT state FROM telegram_document_jobs WHERE receipt_id=?")
      .bind(blocked.receiptId).first("state"), "leased");
    assert.equal(await db.prepare("SELECT receipt_id FROM telegram_outbox WHERE receipt_id=?").bind(blocked.receiptId).first(), null);
  } finally {
    await db.prepare("DROP TRIGGER suppress_fixture_order").run();
  }
});

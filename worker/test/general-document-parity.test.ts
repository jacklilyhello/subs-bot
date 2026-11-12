import assert from "node:assert/strict";
import { createHash, timingSafeEqual } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";
import { Miniflare } from "miniflare";
import { runOneProviderJob } from "../src/provider-job-consumer.ts";
import { claimProviderJob } from "../src/provider-jobs.ts";
import { digestHex, getSubscriptionSnapshot, readSnapshotNodes } from "../src/storage.ts";
import { acceptTelegramDocumentJob, claimTelegramDocumentJob, type TelegramDocumentJobInput } from "../src/telegram/document-jobs.ts";
import { runTelegramDocumentIntake } from "../src/telegram/document-intake.ts";
import { persistTelegramDocumentJob, reconcileTelegramDocumentJobReplies } from "../src/telegram/document-persistence.ts";
import type { GeneralTelegramPin } from "../src/telegram/general-auth-runtime.ts";
import { acceptGeneralSharedTelegramCommand, beginGeneralSharedTelegramReply, claimGeneralSharedTelegramReply } from "../src/telegram/general-auth-shared.ts";
import { generalProviderAuthority } from "../src/telegram/general-provider.ts";
import { promoteTelegramProviderDocument, settleTelegramProviderDocuments, telegramGeneralProviderDocumentsReady } from "../src/telegram/provider-document.ts";
import { reconcileTelegramProviderDocumentReplies, renderTelegramProviderDocumentReply } from "../src/telegram/provider-document-replies.ts";

const runtime = new Miniflare({ modules: true, compatibilityDate: "2026-07-30", d1Databases: ["DB"], r2Buckets: ["NODES"],
  script: "export default {fetch(){return new Response(null)}}" });
let db: D1Database;
let bucket: R2Bucket;
const raw = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.4:8388#fixture";
const node = { type: "ss", name: "fixture", server: "203.0.113.4", port: 8388, share: raw };
const remote = "https://provider.example.invalid/general-document?token=synthetic-only";
const providerPin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const oldComparison = Object.getOwnPropertyDescriptor(crypto.subtle, "timingSafeEqual");

before(async () => {
  Object.defineProperty(crypto.subtle, "timingSafeEqual", { configurable: true,
    value: (received: ArrayBuffer, expected: ArrayBuffer) => timingSafeEqual(new Uint8Array(received), new Uint8Array(expected)) });
  db = await runtime.getD1Database("DB");
  bucket = await runtime.getR2Bucket("NODES");
  await db.prepare("CREATE TABLE subs_bot_schema_migrations(position INTEGER PRIMARY KEY,name TEXT,sha256 TEXT,mode TEXT)").run();
  const directory = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(directory)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, directory), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    await db.prepare("INSERT INTO subs_bot_schema_migrations VALUES(?,?,?,'applied')")
      .bind(Number(name.slice(0, 4)), name, createHash("sha256").update(sql).digest("hex")).run();
  }
});
after(async () => {
  if (oldComparison) Object.defineProperty(crypto.subtle, "timingSafeEqual", oldComparison);
  else Reflect.deleteProperty(crypto.subtle, "timingSafeEqual");
  await runtime.dispose();
});

async function fixture(botId: string) {
  const stamp = Math.floor(Date.now() / 1000);
  const admin = `${botId}1`, member = `${botId}2`;
  const pin: GeneralTelegramPin = { botId, botUsername: "Synthetic_Document_Bot", botToken: `${botId}:synthetic-token`,
    webhookSecret: "synthetic-document-secret", generation: 1, releaseRevision: "c".repeat(40), activationSha256: "d".repeat(64),
    cutoverAt: stamp - 1200, sharedOutbox: true, privateManagement: true, privateFormats: true, privateTemp: true,
    privateDocument: true, privateProvider: true, providerDocumentReplies: true, privateClaims: false,
    privateShareCreation: false, privateAggregate: false, privateSelected: false, privateShort: false };
  await db.batch([
    db.prepare("INSERT INTO telegram_general_policy VALUES(?,?,?,?,?,1)").bind(botId, 1, pin.releaseRevision, pin.activationSha256, pin.cutoverAt),
    ...[[admin, "admin"], [member, "member"]].map(([actor, role]) => db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,1,?,?)")
      .bind(botId, 1, actor, pin.cutoverAt, role)),
  ]);
  function input(id: number, text = remote, actorId = member, fileName = "General.txt"): TelegramDocumentJobInput {
    return { updateId: id, messageId: id, messageDate: stamp, actorId, chatId: actorId, chatType: "private", threadId: null,
      fileId: `synthetic-file-${id}`, fileName, fileSize: new TextEncoder().encode(text).byteLength };
  }
  async function post(event: TelegramDocumentJobInput, options: { urls?: boolean; mixed?: boolean; available?: boolean; selected?: GeneralTelegramPin } = {}) {
    const selected = options.selected ?? pin;
    const update = { update_id: event.updateId, message: { message_id: event.messageId, date: event.messageDate,
      from: { id: Number(event.actorId), is_bot: false }, chat: { id: Number(event.chatId), type: event.chatType },
      document: { file_id: event.fileId, file_name: event.fileName, file_size: event.fileSize } } };
    return acceptGeneralSharedTelegramCommand(db, selected, new Request("https://synthetic.invalid/telegram/webhook", {
      method: "POST", headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": pin.webhookSecret },
      body: JSON.stringify(update),
    }), undefined, async () => options.available !== false, undefined, undefined, null, false, options.urls ?? true, false, options.mixed ?? true);
  }
  async function receipt(id: number) {
    const value = await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id=? AND update_id=?").bind(botId, id).first<number>("receipt_id");
    assert.ok(value);
    return value;
  }
  const state = (id: number) => db.prepare(`SELECT inbox.receipt_nonce AS marker,job.state,job.result_code AS outcome
    FROM telegram_inbox AS inbox JOIN telegram_document_jobs AS job USING(receipt_id) WHERE inbox.bot_id=? AND inbox.update_id=?`)
    .bind(botId, id).first<{ marker: string; state: string; outcome: string | null }>();
  const local = (ownerId = member) => db.prepare(`SELECT id,token,generation,snapshot_id FROM subscriptions
    WHERE owner_id=? AND source_url='uploaded://telegram-document' ORDER BY id`).bind(ownerId)
    .all<{ id: number; token: string; generation: number; snapshot_id: string }>();
  async function revoke() {
    await db.prepare("INSERT INTO telegram_general_actors VALUES(?,?,?,2,?,'denied')").bind(botId, 1, member, stamp + 1).run();
  }
  return { pin, stamp, admin, member, input, post, receipt, state, local, revoke };
}

function transport(text: string, calls: string[] = []): typeof fetch {
  const bytes = new TextEncoder().encode(text);
  return async (url, init) => {
    const destination = new URL(String(url));
    assert.equal(destination.origin, "https://api.telegram.org");
    calls.push(destination.pathname.endsWith("/getFile") ? "metadata" : "file");
    if (destination.pathname.endsWith("/getFile")) {
      assert.equal(init?.method, "POST");
      return Response.json({ ok: true, result: { file_path: "documents/synthetic.txt", file_size: bytes.byteLength } });
    }
    assert.match(destination.pathname, /\/file\/bot[0-9]+:synthetic-token\/documents\/synthetic\.txt$/u);
    return new Response(bytes, { headers: { "Content-Length": String(bytes.byteLength) } });
  };
}

test("general URL files traverse download classification, owned provider queue, snapshot publication and one private summary", async () => {
  const f = await fixture("970100");
  const event = f.input(101);
  assert.equal(await f.post(event), 200);
  assert.equal(await f.post(event), 204);
  const calls: string[] = [];
  assert.equal(await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(remote, calls)), true);
  assert.deepEqual(calls, ["metadata", "file"]);
  assert.deepEqual(await f.state(101), { marker: "general-provider-document:v1", state: "done", outcome: "saved" });
  const id = await f.receipt(101);
  assert.deepEqual(await db.prepare("SELECT actor_id,actor_role,line_count FROM telegram_provider_documents WHERE receipt_id=?").bind(id).first(),
    { actor_id: f.member, actor_role: "member", line_count: 1 });
  assert.equal(await reconcileTelegramDocumentJobReplies(db, f.pin), 0, "the file cannot produce a second ordinary document reply");
  const authority = generalProviderAuthority(f.pin);
  await promoteTelegramProviderDocument(db, authority, false);
  const body = new TextEncoder().encode(raw).buffer;
  assert.equal(await runOneProviderJob(db, bucket, { async fetchSubscription(request) {
    assert.deepEqual(request, { url: remote, ...providerPin });
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } }, providerPin, authority, false), "saved");
  await settleTelegramProviderDocuments(db, authority);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, authority), 1);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, authority), 0);
  const reply = await claimGeneralSharedTelegramReply(db, f.pin);
  assert.equal(reply?.receiptId, id);
  const summary = await renderTelegramProviderDocumentReply(db, authority, { ...reply!, providerDocument: true });
  assert.equal(summary?.text, "订阅链接文件已处理。\n已保存 1 条\n已合并 0 条\n失败 0 条\n超出上限 0 条");
  assert.doesNotMatch(summary!.text, /provider\.example|synthetic-only|\/sub\/|\/agg\//u);
  await f.revoke();
  assert.equal(await renderTelegramProviderDocumentReply(db, authority, { ...reply!, providerDocument: true }), null,
    "a queued summary cannot survive revocation before sending");
  assert.equal(await beginGeneralSharedTelegramReply(db, f.pin, reply!), false,
    "the atomic send boundary also rejects the revoked receipt");
});

test("admin and member mixed uploads remain separate and commit local nodes with their own URL plan", async () => {
  const f = await fixture("970200");
  const content = `${raw}\n${remote}`;
  for (const [id, actor] of [[201, f.admin], [202, f.member]] as const) {
    assert.equal(await f.post(f.input(id, content, actor)), 200);
    assert.equal(await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(content)), true);
    const local = (await f.local(actor)).results;
    assert.equal(local.length, 1);
    const snapshot = await getSubscriptionSnapshot(db, local[0].token);
    assert.ok(snapshot);
    const restored = [];
    for await (const entry of readSnapshotNodes(bucket, snapshot)) restored.push(entry);
    assert.equal(restored.length, 1);
    assert.equal(restored[0].share, raw);
    const receiptId = await f.receipt(id);
    assert.equal(await db.prepare("SELECT actor_role FROM telegram_provider_documents WHERE receipt_id=?").bind(receiptId).first("actor_role"),
      actor === f.admin ? "admin" : "member");
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_outbox WHERE receipt_id=?").bind(receiptId).first("n"), 0);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_document_opt_in WHERE receipt_id=?").bind(receiptId).first("n"), 0);
  }
  assert.notEqual((await f.local(f.admin)).results[0].id, (await f.local()).results[0].id);
});

test("disabled opt-ins reject remote/mixed parsing while plain node documents retain their existing behavior", async () => {
  const f = await fixture("970300");
  assert.equal(await f.post(f.input(301), { urls: false, mixed: false }), 200);
  await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(remote));
  assert.equal((await f.state(301))?.outcome, "invalid-document");
  const mixed = `${raw}\n${remote}`;
  assert.equal(await f.post(f.input(302, mixed), { mixed: false }), 200);
  await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(mixed));
  assert.equal((await f.state(302))?.outcome, "invalid-document");
  assert.equal((await f.local()).results.length, 0);
  assert.equal(await f.post(f.input(303, raw), { urls: false, mixed: false }), 200);
  await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(raw));
  assert.equal((await f.state(303))?.outcome, "saved");
  assert.equal((await f.local()).results.length, 1);
});

test("private feature gates, queue readiness, group scope and ordinary ownership remain enforced", async () => {
  const f = await fixture("970400");
  const event = f.input(401);
  assert.equal(await f.post(event, { available: false }), 503);
  assert.equal(await f.post(event, { selected: { ...f.pin, privateDocument: false } }), 204);
  assert.equal(await f.post({ ...event, chatType: "group", chatId: "-100100" }), 204);
  assert.equal(await f.post({ ...event, actorId: "979999", chatId: "979999" }), 204);
  assert.equal(await acceptTelegramDocumentJob(db, { ...f.pin, privateProvider: false }, event, true, true), "ignored");
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE bot_id=?").bind(f.pin.botId).first("n"), 0);
});

test("local YAML and JSON uploads remain available while provider health and optional migration evidence are unavailable", async () => {
  const f = await fixture("970401");
  const ledger = (await db.prepare("SELECT position,sha256 FROM subs_bot_schema_migrations WHERE position IN (35,36)")
    .all<{ position: number; sha256: string }>()).results;
  assert.equal(ledger.length, 2);
  try {
    await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position IN (35,36)").bind("0".repeat(64)).run();
    const yaml = "proxies:\n  - name: Local YAML\n    type: ss\n    server: 203.0.113.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: fixture\n";
    const json = JSON.stringify({ proxies: [{ name: "Local JSON", type: "ss", server: "203.0.113.4", port: 8388,
      cipher: "aes-256-gcm", password: "fixture" }] });
    for (const [id, text, fileName] of [[411, yaml, "Local YAML.YAML"], [412, json, "Local JSON.json"]] as const) {
      assert.equal(await f.post(f.input(id, text, f.member, fileName), { available: false }), 200);
      assert.equal(await runTelegramDocumentIntake(db, bucket, f.pin, false, false, transport(text)), true);
      assert.deepEqual(await f.state(id), { marker: "general-document-job:v1", state: "done", outcome: "saved" });
      const receiptId = await f.receipt(id);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_document_opt_in WHERE receipt_id=?").bind(receiptId).first("n"), 0);
    }
    const localOnly = { ...f.pin, privateProvider: false };
    assert.equal(await acceptTelegramDocumentJob(db, localOnly, f.input(413, json, f.member, "Direct JSON.json"), true, true), "accepted");
    assert.equal(await runTelegramDocumentIntake(db, bucket, localOnly, false, false, transport(json)), true);
    assert.equal((await f.state(413))?.outcome, "saved");
    assert.equal((await f.local()).results.length, 3);
    assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents WHERE bot_id=?").bind(f.pin.botId).first("n"), 0);
  } finally {
    await db.batch(ledger.map(({ position, sha256 }) => db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=?")
      .bind(sha256, position)));
  }
});

test("persisted upload opt-in survives closing the new-upload flag and revocation before download prevents all egress", async () => {
  const f = await fixture("970500");
  assert.equal(await f.post(f.input(501)), 200);
  assert.equal(await telegramGeneralProviderDocumentsReady(db, f.pin.botId, false), true);
  await runTelegramDocumentIntake(db, bucket, { ...f.pin, providerDocumentReplies: false }, true, true, transport(remote));
  assert.equal((await f.state(501))?.marker, "general-provider-document:v1");
  const revoked = await fixture("970501");
  assert.equal(await revoked.post(revoked.input(502)), 200);
  await revoked.revoke();
  const calls: string[] = [];
  assert.equal(await runTelegramDocumentIntake(db, bucket, revoked.pin, true, true, transport(remote, calls)), false);
  assert.deepEqual(calls, []);
  assert.equal((await revoked.state(502))?.outcome, "access-changed");
});

test("revocation during mixed staging cannot publish either partition or replace the earlier local snapshot", async () => {
  const f = await fixture("970600");
  const first = f.input(601, raw);
  assert.equal(await acceptTelegramDocumentJob(db, f.pin, first), "accepted");
  const firstLease = await claimTelegramDocumentJob(db, f.pin);
  assert.ok(firstLease);
  assert.equal(await persistTelegramDocumentJob(db, bucket, f.pin, firstLease, [node], { parsed: 1 }), "saved");
  const prior = (await f.local()).results;
  const event = { ...f.input(602, `${raw}\n${remote}`), messageDate: f.stamp + 1 };
  assert.equal(await acceptTelegramDocumentJob(db, f.pin, event, true, true), "accepted");
  const lease = await claimTelegramDocumentJob(db, f.pin);
  assert.ok(lease);
  let revoked = false;
  const watched = new Proxy(bucket, { get(target, field) {
    if (field === "put") return async (key: string, value: Uint8Array, options: R2PutOptions) => {
      if (!revoked) { revoked = true; await f.revoke(); }
      return target.put(key, value, options);
    };
    const value = Reflect.get(target, field, target);
    return typeof value === "function" ? value.bind(target) : value;
  } });
  assert.equal(await persistTelegramDocumentJob(db, watched, f.pin, lease, [node], { parsed: 1 }, { urls: [remote], overflow: 0 }), "stale");
  assert.deepEqual((await f.local()).results, prior);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents WHERE bot_id=?").bind(f.pin.botId).first("n"), 0);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subscriptions WHERE owner_id=? AND source_url=?").bind(f.member, remote).first("n"), 0);
});

test("a lost mixed-publication response cannot create another local generation, URL plan or ordinary reply", async () => {
  const f = await fixture("970700");
  const input = f.input(701, `${raw}\n${remote}`);
  assert.equal(await acceptTelegramDocumentJob(db, f.pin, input, true, true), "accepted");
  const lease = await claimTelegramDocumentJob(db, f.pin);
  assert.ok(lease);
  const lost = { prepare: db.prepare.bind(db), async batch(statements: D1PreparedStatement[]) {
    const results = await db.batch(statements);
    const marker = await f.state(701);
    if (marker?.marker === "general-provider-document:v1") throw new Error("Synthetic lost publication acknowledgment");
    return results;
  } } as D1Database;
  await assert.rejects(persistTelegramDocumentJob(lost, bucket, f.pin, lease, [node], { parsed: 1 }, { urls: [remote], overflow: 0 }),
    /publication could not be confirmed/u);
  assert.equal(await acceptTelegramDocumentJob(db, f.pin, input, true, true), "ignored");
  assert.equal(await claimTelegramDocumentJob(db, f.pin), null);
  assert.equal((await f.local()).results[0].generation, 1);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents WHERE bot_id=?").bind(f.pin.botId).first("n"), 1);
  assert.equal(await reconcileTelegramDocumentJobReplies(db, f.pin), 0);
});

for (const [ordinal, fault] of ["settlement", "marker", "saved_counts"].entries()) {
  test(`an ignored mixed ${fault} write rolls back the local pointer and complete provider plan`, async () => {
    const f = await fixture(String(970710 + ordinal));
    assert.equal(await acceptTelegramDocumentJob(db, f.pin, f.input(711, raw)), "accepted");
    const original = await claimTelegramDocumentJob(db, f.pin);
    assert.ok(original);
    assert.equal(await persistTelegramDocumentJob(db, bucket, f.pin, original, [node], { parsed: 1 }), "saved");
    const prior = (await f.local()).results;
    const input = { ...f.input(712, `${raw}\n${remote}`), messageDate: f.stamp + 1 };
    assert.equal(await acceptTelegramDocumentJob(db, f.pin, input, true, true), "accepted");
    const lease = await claimTelegramDocumentJob(db, f.pin);
    assert.ok(lease);
    const trigger = `synthetic_ignore_mixed_${fault}`;
    const target = fault === "settlement" ? `UPDATE OF state ON telegram_document_jobs
      WHEN OLD.receipt_id=${lease.receiptId} AND NEW.state='done'`
      : fault === "marker" ? `UPDATE OF receipt_nonce ON telegram_inbox
        WHEN OLD.receipt_id=${lease.receiptId} AND NEW.receipt_nonce='general-provider-document:v1'`
      : `INSERT ON telegram_document_saved_counts WHEN NEW.receipt_id=${lease.receiptId}`;
    await db.prepare(`CREATE TRIGGER ${trigger} BEFORE ${target} BEGIN SELECT RAISE(IGNORE); END`).run();
    try {
      await assert.rejects(persistTelegramDocumentJob(db, bucket, f.pin, lease, [node], { parsed: 1 }, { urls: [remote], overflow: 0 }),
        /publication could not be confirmed/u);
      assert.deepEqual((await f.local()).results, prior);
      assert.deepEqual(await f.state(712), { marker: "general-document-job:v1", state: "leased", outcome: null });
      assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents WHERE bot_id=?").bind(f.pin.botId).first("n"), 0);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM subscriptions WHERE owner_id=? AND source_url=?").bind(f.member, remote).first("n"), 0);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_document_saved_counts WHERE receipt_id=?").bind(lease.receiptId).first("n"), 0);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_document_opt_in WHERE receipt_id=?").bind(lease.receiptId).first("n"), 1);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_mixed_document_opt_in WHERE receipt_id=?").bind(lease.receiptId).first("n"), 1);
      assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_outbox WHERE receipt_id=?").bind(lease.receiptId).first("n"), 0);
    } finally {
      await db.prepare(`DROP TRIGGER ${trigger}`).run();
    }
  });
}

test("revocation after URL staging prevents promotion and private result delivery", async () => {
  const f = await fixture("970800");
  assert.equal(await f.post(f.input(801)), 200);
  await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(remote));
  await f.revoke();
  const authority = generalProviderAuthority(f.pin);
  await promoteTelegramProviderDocument(db, authority, false);
  assert.equal(await claimProviderJob(db, authority, false), null);
  await settleTelegramProviderDocuments(db, authority);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, authority), 0);
  assert.equal(await claimGeneralSharedTelegramReply(db, f.pin), null);
});

test("concurrent Telegram retries reserve one source job and one provider plan", async () => {
  const f = await fixture("970900");
  const event = f.input(901);
  const statuses = await Promise.all([f.post(event), f.post(event), f.post(event)]);
  assert.deepEqual(statuses.sort(), [200, 204, 204]);
  assert.equal(await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(remote)), true);
  assert.equal(await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(remote)), false);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_document_jobs WHERE bot_id=?").bind(f.pin.botId).first("n"), 1);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_provider_documents WHERE bot_id=?").bind(f.pin.botId).first("n"), 1);
  assert.equal(await db.prepare("SELECT count(*) AS n FROM subscriptions WHERE owner_id=? AND source_url=?").bind(f.member, remote).first("n"), 1);
});

test("general file opt-ins fail closed without exact provider and mixed migration evidence", async () => {
  const f = await fixture("971000");
  for (const position of [35, 36]) {
    const sha = await db.prepare("SELECT sha256 FROM subs_bot_schema_migrations WHERE position=?").bind(position).first<string>("sha256");
    assert.ok(sha);
    try {
      await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=?").bind("0".repeat(64), position).run();
      assert.equal(await f.post(f.input(1001 + position)), 503);
      assert.equal(await acceptTelegramDocumentJob(db, f.pin, f.input(1101 + position), true, true), "ignored");
    } finally {
      await db.prepare("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=?").bind(sha, position).run();
    }
  }
  assert.equal(await db.prepare("SELECT count(*) AS n FROM telegram_inbox WHERE bot_id=?").bind(f.pin.botId).first("n"), 0);
});

test("revocation while the provider fetch is in flight prevents file-origin snapshot publication", async () => {
  const f = await fixture("971100");
  assert.equal(await f.post(f.input(1101)), 200);
  await runTelegramDocumentIntake(db, bucket, f.pin, true, true, transport(remote));
  const authority = generalProviderAuthority(f.pin);
  await promoteTelegramProviderDocument(db, authority, false);
  const body = new TextEncoder().encode(raw).buffer;
  assert.equal(await runOneProviderJob(db, bucket, { async fetchSubscription() {
    await f.revoke();
    return { ok: true, body, bodySha256: digestHex(await crypto.subtle.digest("SHA-256", body)) };
  } }, providerPin, authority, false), "stale");
  assert.equal(await db.prepare("SELECT generation FROM subscriptions WHERE owner_id=? AND source_url=?").bind(f.member, remote).first("generation"), 0);
  await settleTelegramProviderDocuments(db, authority);
  assert.equal(await reconcileTelegramProviderDocumentReplies(db, authority), 0);
});

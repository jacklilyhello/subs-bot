import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { test, type TestContext } from "node:test";
import { Miniflare } from "miniflare";

import { claimProviderJob, settleProviderJob } from "../src/provider-jobs.ts";
import { acceptTelegramProviderRequest } from "../src/telegram/provider-admission.ts";
import { parseTelegramProviderText, reconcileTelegramProviderReplies } from "../src/telegram/provider-replies.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand, beginTelegramReply, claimTelegramReply, reapExpiredTelegramReplies, settleTelegramReply } from "../src/telegram/store.ts";

test("provider text preserves opaque URL bytes and leaves mixed text to existing intake", () => {
  const sourceUrl = "HtTpS://provider.example.invalid/path/%2F?z=x|y&a=1";
  assert.deepEqual(parseTelegramProviderText(`  ${sourceUrl}  `), { sourceUrl });
  assert.deepEqual(parseTelegramProviderText(`  订阅名称 | ${sourceUrl}  `), { name: "订阅名称", sourceUrl });
  for (const text of [`${sourceUrl}\n`, `prose ${sourceUrl}`, `${sourceUrl} prose`, `ss://node#name|${sourceUrl}`,
    `名称 https://another.example.invalid/path|${sourceUrl}`,
    `说明|${sourceUrl}\u2028ss://node`, "ftp://provider.example.invalid/source"]) {
    assert.equal(parseTelegramProviderText(text), null);
  }
});

async function replyFixture(t: TestContext) {
  const runtime = new Miniflare({ modules: true, script: "export default {fetch(){return new Response(null)}};",
    compatibilityDate: "2026-07-30", d1Databases: ["DB"] });
  t.after(() => runtime.dispose());
  const db = await runtime.getD1Database("DB");
  const migrations = new URL("../migrations/", import.meta.url);
  for (const name of (await readdir(migrations)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrations), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
  const policy: TelegramPolicy = { botId: "77701", adminId: "77702", memberId: "77703", groupId: "-10077704",
    botUsername: "FixtureProviderBot", botToken: "77701:synthetic-token", webhookSecret: "synthetic-webhook" };
  const scope = { actorId: policy.memberId, chatId: policy.memberId, chatType: "private" as const, threadId: null,
    messageDate: Math.floor(Date.now() / 1000) };
  const ordinary = (id: number) => acceptTelegramCommand(db, policy, { ...scope, updateId: id, messageId: id, command: "help" });
  const claim = () => claimTelegramReply(db, policy.botId, false, false, false, false, false, false, policy);
  return { db, policy, scope, ordinary, claim };
}

test("ambiguous terminal enqueue is idempotent and authorization changes fence delivery without FIFO blocking", async (t) => {
  const { db, policy, scope, ordinary, claim } = await replyFixture(t);
  assert.deepEqual(await acceptTelegramProviderRequest(db, policy, { ...scope, kind: "url-import", updateId: 1,
    messageId: 1, sourceUrl: "https://synthetic-secret@provider.example.invalid/source" }), { kind: "invalid-url" });
  const injected = { prepare: db.prepare.bind(db), batch: async (steps: D1PreparedStatement[]) => {
    await db.batch(steps);
    throw new Error("Synthetic committed D1 response loss");
  } } as D1Database;
  await assert.rejects(reconcileTelegramProviderReplies(injected, policy), {
    message: "Telegram provider reply reconciliation could not be confirmed.",
  });
  assert.equal(await reconcileTelegramProviderReplies(db, policy), 0);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_provider_replies").first("count"), 1);
  assert.equal(await db.prepare("SELECT count(*) AS count FROM telegram_outbox").first("count"), 1);

  assert.equal(await ordinary(2), "accepted");
  const legacy = await claimTelegramReply(db, policy.botId);
  assert.equal(legacy?.updateId, 2, "a disabled or older drain skips the marked receipt without FIFO blocking");
  assert.ok(await beginTelegramReply(db, policy, legacy!, "allowed"));
  await settleTelegramReply(db, policy, legacy!, { kind: "failed" });

  const provider = await claim();
  assert.equal(provider?.providerOutcome, "invalid-url");
  await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,?)")
    .bind(policy.botId, policy.memberId, scope.messageDate, 100).run();
  assert.equal(await beginTelegramReply(db, policy, provider!, "allowed"), false, "an allowed but newer epoch cannot send an old reply");
  assert.equal(await ordinary(3), "accepted");
  assert.equal((await claim())?.updateId, 3, "an ineligible earlier provider receipt does not block later normal replies");

  await db.prepare("UPDATE telegram_provider_replies SET ready_at=unixepoch()-901").run();
  await reapExpiredTelegramReplies(db, policy.botId, false, false, false, false, false, false, true);
  assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?").bind(provider!.receiptId).first("state"), "failed");
});

test("a delayed provider reply waits for the later same-chat lease and in-flight send", async (t) => {
  const { db, policy, scope, ordinary, claim } = await replyFixture(t);
  assert.equal((await acceptTelegramProviderRequest(db, policy, { ...scope, kind: "url-import", updateId: 1,
    messageId: 1, sourceUrl: "https://provider.example.invalid/source" })).kind, "queued");
  const job = await claimProviderJob(db, policy);
  assert.ok(job);
  assert.equal(await reconcileTelegramProviderReplies(db, policy), 0);
  assert.equal(await ordinary(2), "accepted");
  const later = await claim();
  assert.equal(later?.updateId, 2, "the earlier fetch does not block an ordinary reply");

  assert.equal(await settleProviderJob(db, job, { kind: "failed", reason: "fetch-rejected" }), "done");
  assert.equal(await reconcileTelegramProviderReplies(db, policy), 1);
  assert.equal(await claim(), null, "an older reply that becomes ready cannot overtake a later live lease");
  assert.ok(await beginTelegramReply(db, policy, later!, "allowed"));
  assert.equal(await claim(), null, "the same-chat send remains exclusive until settlement");
  await settleTelegramReply(db, policy, later!, { kind: "sent", messageId: 100 });

  const provider = await claim();
  assert.equal(provider?.updateId, 1);
  assert.equal(provider?.providerOutcome, "fetch-rejected");
  assert.ok(await beginTelegramReply(db, policy, provider!, "allowed"));
  await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,?)")
    .bind(policy.botId, policy.memberId, scope.messageDate, 100).run();
  assert.equal(await ordinary(3), "accepted");
  assert.equal(await claim(), null, "a changed grant cannot interrupt an already in-flight send's serialization");
  await settleTelegramReply(db, policy, provider!, { kind: "sent", messageId: 101 });
  assert.equal((await claim())?.updateId, 3);
});

test("an expired provider predecessor cannot block the next reply before reaping", async (t) => {
  const { db, policy, scope, ordinary, claim } = await replyFixture(t);
  assert.equal((await acceptTelegramProviderRequest(db, policy, { ...scope, kind: "url-import", updateId: 1,
    messageId: 1, sourceUrl: "https://fixture@provider.example.invalid/source" })).kind, "invalid-url");
  assert.equal(await reconcileTelegramProviderReplies(db, policy), 1);
  await db.prepare("UPDATE telegram_outbox SET due_at=unixepoch()+60").run();
  assert.equal(await ordinary(2), "accepted");
  assert.equal(await claim(), null, "an unexpired predecessor keeps FIFO order during its retry delay");

  await db.prepare("UPDATE telegram_provider_replies SET ready_at=unixepoch()-901").run();
  assert.equal((await claim())?.updateId, 2);
  assert.equal(await db.prepare(`SELECT outbox.state FROM telegram_outbox AS outbox JOIN telegram_inbox USING (receipt_id)
    WHERE bot_id=? AND update_id=1`).bind(policy.botId).first("state"), "pending", "the claim does not depend on prior reaping");
});

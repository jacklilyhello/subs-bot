import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import type { TelegramCommand, TelegramPolicy } from "../src/telegram/protocol.ts";
import {
  acceptTelegramCommand, beginTelegramReply, claimTelegramReply, isTelegramMemberAllowed,
  reapExpiredTelegramReplies, settleTelegramReply,
} from "../src/telegram/store.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
});
let db: D1Database;

before(async () => {
  db = await miniflare.getD1Database("DB");
  for (const file of ["0001_subscriptions.sql", "0002_telegram.sql"]) {
    const sql = await readFile(new URL(`../migrations/${file}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

after(() => miniflare.dispose());

function policy(botId: string): TelegramPolicy {
  return {
    botId, botUsername: "Synthetic_Test_Bot", adminId: "42", memberId: "43", groupId: "-1001234567890",
    webhookSecret: "example-webhook-secret", botToken: `${botId}:example-token`,
  };
}

function command(scope: TelegramPolicy, updateId: number, overrides: Partial<TelegramCommand> = {}): TelegramCommand {
  return {
    updateId, actorId: scope.memberId, chatId: scope.memberId, chatType: "private",
    messageId: updateId, messageDate: 1_785_456_000, threadId: null, command: "list", ...overrides,
  };
}

async function outbox(scope: TelegramPolicy, updateId: number) {
  return db.prepare(`
    SELECT state, attempts, lease_id AS leaseId, sent_message_id AS sentMessageId
    FROM telegram_outbox JOIN telegram_inbox USING (receipt_id) WHERE bot_id = ? AND update_id = ?
  `).bind(scope.botId, updateId).first<{ state: string; attempts: number; leaseId: string | null; sentMessageId: number | null }>();
}

async function expireLease(leaseId: string) {
  await db.prepare("UPDATE telegram_outbox SET lease_until = unixepoch() - 1 WHERE lease_id = ?").bind(leaseId).run();
}

test("atomically accepts one normalized inbox and reply for concurrent deliveries", async () => {
  const scope = policy("101");
  const accepted = command(scope, 1);
  const results = await Promise.all([
    acceptTelegramCommand(db, scope, accepted), acceptTelegramCommand(db, scope, accepted),
  ]);
  assert.deepEqual(results.sort(), ["accepted", "duplicate"]);
  assert.equal(await acceptTelegramCommand(db, scope, { ...accepted, command: "help" }), "duplicate");
  const rows = await db.prepare(`
    SELECT command, receipt_nonce AS nonce, telegram_outbox.state
    FROM telegram_inbox JOIN telegram_outbox USING (receipt_id) WHERE bot_id = ? AND update_id = ?
  `).bind(scope.botId, accepted.updateId).all();
  assert.deepEqual(rows.results, [{ command: "list", nonce: null, state: "pending" }]);
  await assert.rejects(acceptTelegramCommand(db, scope, command(scope, 2, { chatId: scope.adminId })), /isolation scope/u);
  assert.equal(await acceptTelegramCommand(db, policy("102"), accepted), "accepted");
});

test("only newer private commands from the exact administrator change the configured member", async () => {
  const scope = policy("103");
  const admin = { actorId: scope.adminId, chatId: scope.adminId };
  assert.equal(await isTelegramMemberAllowed(db, scope), true);
  await acceptTelegramCommand(db, scope, command(scope, 10, { ...admin, messageId: 30, command: "auth-remove" }));
  await acceptTelegramCommand(db, scope, command(scope, 11, { ...admin, messageId: 29, command: "auth-add" }));
  await acceptTelegramCommand(db, scope, command(scope, 12, {
    ...admin, messageId: 31, messageDate: 1_785_455_999, command: "auth-add",
  }));
  await acceptTelegramCommand(db, scope, command(scope, 13, { messageId: 32, command: "auth-add" }));
  await acceptTelegramCommand(db, scope, command(scope, 14, {
    ...admin, chatId: scope.groupId, chatType: "supergroup", messageId: 33, command: "auth-add",
  }));
  assert.equal(await isTelegramMemberAllowed(db, scope), false);
  assert.equal(await isTelegramMemberAllowed(db, policy("104")), true);
  await acceptTelegramCommand(db, scope, command(scope, 15, { ...admin, messageId: 31, command: "auth-add" }));
  assert.equal(await isTelegramMemberAllowed(db, scope), true);
  assert.equal(await acceptTelegramCommand(db, scope, command(scope, 10, {
    ...admin, messageId: 34, command: "auth-remove",
  })), "duplicate");
  assert.equal(await isTelegramMemberAllowed(db, scope), true);
});

test("rolls back both the receipt and authorization if reply intent cannot be committed", async () => {
  const scope = policy("105");
  const revoke = command(scope, 20, { actorId: scope.adminId, chatId: scope.adminId, command: "auth-remove" });
  await db.prepare(`
    CREATE TRIGGER reject_test_outbox BEFORE INSERT ON telegram_outbox
    WHEN (SELECT bot_id FROM telegram_inbox WHERE receipt_id = NEW.receipt_id) = '105'
    BEGIN SELECT RAISE(ABORT, 'synthetic outbox error'); END
  `).run();
  try {
    await assert.rejects(acceptTelegramCommand(db, scope, revoke));
    const receipt = await db.prepare("SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = ?")
      .bind(scope.botId, revoke.updateId).first();
    assert.equal(receipt, null);
    assert.equal(await isTelegramMemberAllowed(db, scope), true);
  } finally {
    await db.prepare("DROP TRIGGER reject_test_outbox").run();
  }
  assert.equal(await acceptTelegramCommand(db, scope, revoke), "accepted");
  assert.equal(await isTelegramMemberAllowed(db, scope), false);
});

test("claims in receipt order per actor and chat and rechecks current authorization before sending", async () => {
  const scope = policy("106");
  await acceptTelegramCommand(db, scope, command(scope, 90));
  await acceptTelegramCommand(db, scope, command(scope, 30));
  const simultaneous = await Promise.all([claimTelegramReply(db, scope.botId), claimTelegramReply(db, scope.botId)]);
  const claims = simultaneous.filter((lease) => lease !== null);
  assert.equal(claims.length, 1);
  const first = claims[0];
  assert.equal(first.updateId, 90);
  assert.equal(await beginTelegramReply(db, scope, { ...first, messageId: 91 }, "allowed"), false);
  assert.equal(await beginTelegramReply(db, scope, first, "none"), false);

  await acceptTelegramCommand(db, scope, command(scope, 31, {
    actorId: scope.adminId, chatId: scope.adminId, command: "auth-remove",
  }));
  assert.equal(await beginTelegramReply(db, scope, first, "allowed"), false);
  assert.equal(await beginTelegramReply(db, scope, first, "denied"), true);
  assert.equal(await beginTelegramReply(db, scope, first, "denied"), false);
  assert.equal((await claimTelegramReply(db, scope.botId))?.updateId, 31);
  await acceptTelegramCommand(db, scope, command(scope, 32, {
    chatId: scope.groupId, chatType: "supergroup", threadId: 7,
  }));
  const group = await claimTelegramReply(db, scope.botId);
  assert.equal(group?.updateId, 32);
  assert.equal(group?.threadId, 7);
  assert.equal(await claimTelegramReply(db, scope.botId), null);
  await settleTelegramReply(db, scope, first, { kind: "sent", messageId: 999 });
  assert.equal((await claimTelegramReply(db, scope.botId))?.updateId, 30);
  assert.equal((await outbox(scope, 90))?.sentMessageId, 999);
});

test("reclaims expired pre-send leases and never replays an ambiguous send", async () => {
  const scope = policy("107");
  await acceptTelegramCommand(db, scope, command(scope, 40));
  await acceptTelegramCommand(db, scope, command(scope, 41));
  const first = await claimTelegramReply(db, scope.botId);
  assert.ok(first);
  await expireLease(first.leaseId);
  assert.equal(await beginTelegramReply(db, scope, first, "allowed"), false);
  await reapExpiredTelegramReplies(db, scope.botId);
  const second = await claimTelegramReply(db, scope.botId);
  assert.ok(second);
  assert.equal(second.updateId, 40);
  assert.equal(second.attempts, 2);
  assert.notEqual(second.leaseId, first.leaseId);
  assert.equal(await beginTelegramReply(db, scope, first, "allowed"), false);
  assert.equal(await beginTelegramReply(db, scope, second, "allowed"), true);
  await settleTelegramReply(db, scope, first, { kind: "sent", messageId: 998 });
  assert.equal((await outbox(scope, 40))?.state, "sending");
  await expireLease(second.leaseId);
  await reapExpiredTelegramReplies(db, scope.botId);
  assert.equal((await outbox(scope, 40))?.state, "uncertain");
  assert.equal((await claimTelegramReply(db, scope.botId))?.updateId, 41);
  assert.equal(await claimTelegramReply(db, scope.botId), null);
  await settleTelegramReply(db, scope, second, { kind: "sent", messageId: 999 });
  assert.deepEqual(await outbox(scope, 40), { state: "sent", attempts: 2, leaseId: null, sentMessageId: 999 });
});

test("honors retry delays, caps attempts, and expires old pending replies", async () => {
  const scope = policy("108");
  await acceptTelegramCommand(db, scope, command(scope, 50));
  await acceptTelegramCommand(db, scope, command(scope, 51));
  for (let attempt = 1; attempt <= 4; attempt += 1) {
    const lease = await claimTelegramReply(db, scope.botId);
    assert.ok(lease);
    assert.equal(lease.updateId, 50);
    assert.equal(lease.attempts, attempt);
    assert.equal(await beginTelegramReply(db, scope, lease, "allowed"), true);
    await settleTelegramReply(db, scope, lease, { kind: "retry", delaySeconds: 60 });
    if (attempt < 4) {
      assert.equal(await claimTelegramReply(db, scope.botId), null);
      await db.prepare(`
        UPDATE telegram_outbox SET due_at = unixepoch() - 1 WHERE receipt_id = (
          SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = ?
        )
      `).bind(scope.botId, 50).run();
    }
  }
  assert.equal((await outbox(scope, 50))?.state, "failed");
  await db.prepare("UPDATE telegram_inbox SET received_at = unixepoch() - 901 WHERE bot_id = ? AND update_id = ?")
    .bind(scope.botId, 51).run();
  await reapExpiredTelegramReplies(db, scope.botId);
  assert.equal((await outbox(scope, 51))?.state, "failed");
  assert.equal(await claimTelegramReply(db, scope.botId), null);
});

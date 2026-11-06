import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { createSubscription, getOwnedSubscription } from "../src/storage.ts";
import {
  acceptTelegramLifecycle, prepareTelegramLifecycleTickets, reapTelegramLifecycle, renderTelegramLifecycle,
  TELEGRAM_LIFECYCLE_MARKER, type TelegramLifecycleButton,
} from "../src/telegram/lifecycle-actions.ts";
import type { TelegramEventScope, TelegramLifecycleUpdate, TelegramPolicy, TelegramViewKind } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand, beginTelegramReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import { acceptTelegramView } from "../src/telegram/views.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
});
const migrationDir = new URL("../migrations/", import.meta.url);
let db: D1Database;

before(async () => {
  db = await miniflare.getD1Database("DB");
  for (const name of (await readdir(migrationDir)).filter((file) => file.endsWith(".sql")).sort()) {
    const sql = await readFile(new URL(name, migrationDir), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

after(() => miniflare.dispose());

function policy(botId: string): TelegramPolicy {
  return { botId, botUsername: "Synthetic_Action_Bot", adminId: "81001", memberId: "81002", groupId: "-1001234567890",
    webhookSecret: "synthetic-webhook-secret", botToken: `${botId}:synthetic-token` };
}

function scope(config: TelegramPolicy, updateId: number): TelegramEventScope {
  return { updateId, actorId: config.memberId, chatId: config.groupId, chatType: "supergroup", threadId: 17,
    messageId: 2_000 + updateId, messageDate: 1_800_000_000 };
}

function click(config: TelegramPolicy, updateId: number, ticket: string, messageId: number): TelegramLifecycleUpdate {
  return { ...scope(config, updateId), kind: "lifecycle-callback", callbackId: `fixture-${updateId}`, ticket, messageId };
}

function reply(config: TelegramPolicy, updateId: number, promptMessageId: number, text: string): TelegramLifecycleUpdate {
  return { ...scope(config, updateId), kind: "rename-reply", promptMessageId, text };
}

function create(ownerId: string, name: string) {
  return createSubscription(db, { ownerId, name, sourceUrl: "https://provider.example.invalid/fixture-secret" });
}

function button(action: TelegramLifecycleButton["action"], subscriptionId: number, expectedLifecycleRevision = 0) {
  return { action, text: action, subscriptionId, expectedLifecycleRevision };
}

async function deliver(config: TelegramPolicy, updateId: number, sentMessageId: number,
  buttons: readonly TelegramLifecycleButton[] = []) {
  const lease = await claimTelegramReply(db, config.botId);
  assert.ok(lease);
  assert.equal(lease.updateId, updateId);
  const prepared = await prepareTelegramLifecycleTickets(buttons);
  const access = lease.command.startsWith("auth-") ? "none" : "allowed";
  assert.equal(await beginTelegramReply(db, config, lease, access, [], prepared.tickets), true);
  await settleTelegramReply(db, config, lease, { kind: "sent", messageId: sentMessageId });
  return { lease, codes: prepared.keyboard.flat().map(({ callback_data }) => callback_data) };
}

async function view(config: TelegramPolicy, updateId: number, sentMessageId: number, kind: TelegramViewKind,
  buttons: readonly TelegramLifecycleButton[]) {
  assert.equal(await acceptTelegramView(db, config, { ...scope(config, updateId), kind }), "accepted");
  return (await deliver(config, updateId, sentMessageId, buttons)).codes;
}

async function action(config: TelegramPolicy, updateId: number) {
  return db.prepare(`
    SELECT inbox.receipt_id AS receiptId, inbox.receipt_nonce AS marker, action.kind,
      action.subscription_id AS subscriptionId, action.expected_revision AS expectedLifecycleRevision, reply.state
    FROM telegram_inbox AS inbox JOIN telegram_lifecycle_action AS action USING (receipt_id)
    JOIN telegram_outbox AS reply USING (receipt_id)
    WHERE inbox.bot_id = ? AND inbox.update_id = ?
  `).bind(config.botId, updateId).first<{
    receiptId: number; marker: string; kind: string; subscriptionId: number; expectedLifecycleRevision: number; state: string;
  }>();
}

function digest(code: string) {
  return createHash("sha256").update(code).digest("hex");
}

function ticket(code: string) {
  return db.prepare("SELECT used_by_receipt_id FROM telegram_lifecycle_ticket WHERE token_sha256 = ?")
    .bind(digest(code)).first<{ used_by_receipt_id: number | null }>();
}

test("binds a rename wait to the last confirmed prompt and fences delayed callbacks after consumption", async () => {
  const config = policy("90001");
  const first = await create(config.memberId, "First fixture");
  const second = await create(config.memberId, "Second fixture");
  const [firstCode, secondCode, lateCode] = await view(config, 10, 100, "list", [
    button("rename", first.id), button("rename", second.id), button("rename", first.id),
  ]);
  assert.match(firstCode, /^sba1_[A-Za-z0-9_-]{22}$/u);
  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 20, firstCode, 100)), "accepted");
  assert.equal((await action(config, 20))?.kind, "rename-prompt");
  await deliver(config, 20, 101);
  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 40, secondCode, 100)), "accepted");
  await deliver(config, 40, 102);

  const proper = reply(config, 50, 102, "  renamed fixture  ");
  for (const bad of [
    reply(config, 49, 101, "wrong prompt"),
    { ...proper, updateId: 47, actorId: config.adminId },
    { ...proper, updateId: 48, threadId: 18 },
    { ...proper, updateId: 46, chatId: config.memberId, chatType: "private" as const, threadId: null },
  ]) {
    assert.equal(await acceptTelegramLifecycle(db, config, bad), "ignored");
    assert.equal(await action(config, bad.updateId), null);
  }
  assert.equal(await acceptTelegramLifecycle(db, config, proper), "accepted");
  assert.equal(await acceptTelegramLifecycle(db, config, proper), "ignored");
  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 45, lateCode, 100)), "ignored");
  assert.equal((await ticket(lateCode))?.used_by_receipt_id, null);
  const renamed = await action(config, 50);
  assert.equal(renamed?.kind, "renamed");
  assert.equal(renamed?.marker, TELEGRAM_LIFECYCLE_MARKER);
  assert.equal(renamed?.subscriptionId, second.id);
  assert.equal((await getOwnedSubscription(db, config.memberId, second.id))?.name, "renamed fixture");
  assert.equal((await getOwnedSubscription(db, config.memberId, second.id))?.lifecycleRevision, 1);
  assert.equal((await getOwnedSubscription(db, config.memberId, first.id))?.name, first.name);
  assert.equal(renderTelegramLifecycle({ kind: "renamed", subscriptionId: second.id,
    expectedLifecycleRevision: 0 }).text, "订阅名称已更新。");
});

test("requires confirmation, rolls back a failed delete receipt, and restores the original capability", async () => {
  const config = policy("90002");
  const owned = await create(config.memberId, "Owned fixture");
  const foreign = await create(config.adminId, "Foreign fixture");
  const [ask, foreignAsk] = await view(config, 10, 200, "list", [
    button("trash-prompt", owned.id), button("trash-prompt", foreign.id),
  ]);
  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 15, foreignAsk, 200)), "accepted");
  assert.equal((await action(config, 15))?.kind, "stale");
  assert.ok(await getOwnedSubscription(db, config.adminId, foreign.id));
  await deliver(config, 15, 201);

  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 20, ask, 200)), "accepted");
  assert.equal((await action(config, 20))?.kind, "trash-prompt");
  assert.ok(await getOwnedSubscription(db, config.memberId, owned.id));
  const confirmation = renderTelegramLifecycle({ kind: "trash-prompt", subscriptionId: owned.id,
    expectedLifecycleRevision: 0 });
  const { codes: [confirm] } = await deliver(config, 20, 202, confirmation.buttons);
  const request = click(config, 30, confirm, 202);
  await db.prepare(`
    CREATE TRIGGER reject_fixture_action_reply BEFORE INSERT ON telegram_outbox
    WHEN EXISTS (SELECT 1 FROM telegram_inbox WHERE receipt_id = NEW.receipt_id AND bot_id = '90002' AND update_id = 30)
    BEGIN SELECT RAISE(ABORT, 'synthetic lifecycle rollback'); END
  `).run();
  try {
    await assert.rejects(acceptTelegramLifecycle(db, config, request), /could not be confirmed/u);
    assert.equal((await getOwnedSubscription(db, config.memberId, owned.id))?.lifecycleRevision, 0);
    assert.equal((await ticket(confirm))?.used_by_receipt_id, null);
    assert.equal(await action(config, 30), null);
  } finally {
    await db.prepare("DROP TRIGGER reject_fixture_action_reply").run();
  }
  const replies = await Promise.all([
    acceptTelegramLifecycle(db, config, request), acceptTelegramLifecycle(db, config, click(config, 31, confirm, 202)),
  ]);
  assert.deepEqual(replies.toSorted(), ["accepted", "ignored"]);
  const applied = replies[0] === "accepted" ? 30 : 31;
  assert.equal((await action(config, applied))?.kind, "trashed");
  assert.equal(await getOwnedSubscription(db, config.memberId, owned.id), null);
  const trash = await db.prepare("SELECT token, lifecycle_revision FROM subscription_trash WHERE id = ?")
    .bind(owned.id).first();
  assert.deepEqual(trash, { token: owned.token, lifecycle_revision: 1 });
  await deliver(config, applied, 203);

  const [restore] = await view(config, 40, 204, "recycle", [button("restore", owned.id, 1)]);
  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 41, restore, 204)), "accepted");
  assert.equal((await action(config, 41))?.kind, "restored");
  const restored = await getOwnedSubscription(db, config.memberId, owned.id);
  assert.equal(restored?.token, owned.token);
  assert.equal(restored?.lifecycleRevision, 2);
  assert.equal(await db.prepare("SELECT id FROM subscription_trash WHERE id = ?").bind(owned.id).first(), null);
});

test("rechecks authorization inside admission and keeps expired waits only as bounded ordering fences", async () => {
  const config = policy("90003");
  const owned = await create(config.memberId, "Auth race fixture");
  const [rename] = await view(config, 10, 300, "list", [button("rename", owned.id)]);
  const attempt = click(config, 20, rename, 300);
  const revoke = {
    ...scope(config, 19), actorId: config.adminId, chatId: config.adminId, chatType: "private" as const,
    threadId: null, command: "auth-remove" as const,
  };
  const raced = new Proxy(db, {
    get(target, property) {
      if (property === "batch") return async (statements: D1PreparedStatement[]) => {
        assert.equal(await acceptTelegramCommand(target, config, revoke), "accepted");
        return target.batch(statements);
      };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  assert.equal(await acceptTelegramLifecycle(raced, config, attempt), "ignored");
  assert.equal((await ticket(rename))?.used_by_receipt_id, null);
  assert.equal(await action(config, 20), null);

  assert.equal(await acceptTelegramCommand(db, config, { ...revoke, updateId: 21, messageId: 3_000,
    command: "auth-add" }), "accepted");
  assert.equal(await acceptTelegramLifecycle(db, config, click(config, 22, rename, 300)), "accepted");
  // Deliver the two admin acknowledgements before the member's prompt.
  await deliver(config, 19, 301);
  await deliver(config, 21, 302);
  await deliver(config, 22, 303);
  await db.prepare("UPDATE telegram_rename_wait SET expires_at = unixepoch() - 1 WHERE bot_id = ?").bind(config.botId).run();
  assert.equal(await acceptTelegramLifecycle(db, config, reply(config, 23, 303, "too late")), "ignored");
  await reapTelegramLifecycle(db);
  assert.ok(await db.prepare("SELECT 1 FROM telegram_rename_wait WHERE bot_id = ?").bind(config.botId).first());
  await db.prepare("UPDATE telegram_rename_wait SET expires_at = unixepoch() - 601 WHERE bot_id = ?").bind(config.botId).run();
  await reapTelegramLifecycle(db);
  assert.equal(await db.prepare("SELECT 1 FROM telegram_rename_wait WHERE bot_id = ?").bind(config.botId).first(), null);
});

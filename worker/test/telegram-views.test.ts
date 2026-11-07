import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { createSubscription } from "../src/storage.ts";
import { trashOwnedSubscription } from "../src/subscriptions.ts";
import type { TelegramPolicy, TelegramViewUpdate } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand, beginTelegramReply, claimTelegramReply, settleTelegramReply } from "../src/telegram/store.ts";
import {
  acceptTelegramView, prepareTelegramViewTickets, renderTelegramView, TELEGRAM_VIEW_MARKER,
  type TelegramView,
} from "../src/telegram/views.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
});
let db: D1Database;
const sourceUrl = "https://provider.example.invalid/sub?token=synthetic-source-credential";
const errorText = "synthetic-unredacted-provider-error";
const fourteenDays = 14 * 24 * 60 * 60;
const thirtyDays = 30 * 24 * 60 * 60;

before(async () => {
  db = await miniflare.getD1Database("DB");
  for (const name of [
    "0001_subscriptions.sql", "0002_telegram.sql", "0003_subscription_lifecycle.sql", "0004_telegram_views.sql",
    "0005_private_shares.sql", "0006_telegram_lifecycle.sql", "0007_telegram_private_claims.sql",
    "0008_telegram_temp_nodes.sql",
  ]) {
    const sql = await readFile(new URL(`../migrations/${name}`, import.meta.url), "utf8");
    await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
  }
});

after(() => miniflare.dispose());

function create(ownerId: string, name: string) {
  return createSubscription(db, { ownerId, name, sourceUrl });
}

function firstPage(kind: TelegramView["kind"]): TelegramView {
  return { kind, afterId: null, afterEpoch: null };
}

function assertNameOrder(text: string, names: string[]): void {
  let previous = -1;
  for (const name of names) {
    const offset = text.indexOf(name);
    assert.ok(offset > previous, `Expected ${name} in the intended order.`);
    previous = offset;
  }
}

async function now(): Promise<number> {
  const row = await db.prepare("SELECT unixepoch() AS timestamp").first<{ timestamp: number }>();
  assert.ok(row);
  return row.timestamp;
}

test("list views use bounded owner-keyset pages and redact sensitive or unsafe fields", async () => {
  const owner = "81001";
  const foreign = await create("81002", "Foreign account fixture");
  const rows = [];
  for (let index = 1; index <= 10; index += 1) {
    rows.push(await create(owner, `List fixture ${String(index).padStart(2, "0")}`));
  }
  await db.prepare("UPDATE subscriptions SET last_error = ? WHERE id = ?").bind(errorText, rows[0].id).run();
  await create(owner, "Clean\u202e title\n https://name.example.invalid/synthetic-url");
  await create(owner, "🔷".repeat(110));

  const first = await renderTelegramView(db, owner, firstPage("list"));
  assertNameOrder(first.text, rows.slice(0, 8).map(({ name }) => name));
  assert.equal(first.text.includes(rows[8].name), false);
  assert.equal(first.text.includes(foreign.name), false);
  for (const sensitive of [sourceUrl, "synthetic-source-credential", errorText, rows[0].token]) {
    assert.equal(first.text.includes(sensitive), false);
  }
  assert.deepEqual(first.buttons.map(({ afterId, afterEpoch }) => ({ afterId, afterEpoch })), [
    { afterId: rows[7].id, afterEpoch: null },
  ]);
  assert.deepEqual(first.lifecycleButtons.map(({ action, subscriptionId, expectedLifecycleRevision }) =>
    ({ action, subscriptionId, expectedLifecycleRevision })), rows.slice(0, 8).flatMap(({ id: subscriptionId }) =>
    ["rename", "trash-prompt"].map((action) => ({ action, subscriptionId, expectedLifecycleRevision: 0 }))));

  const second = await renderTelegramView(db, owner, { ...firstPage("list"), ...first.buttons[0] });
  assertNameOrder(second.text, [rows[8].name, rows[9].name, "Clean", "title"]);
  assert.equal(second.text.includes(rows[7].name), false);
  assert.doesNotMatch(second.text, /\u202e|name\.example\.invalid/u);
  assert.equal(Array.from(second.text).filter((character) => character === "🔷").length, 80);
  assert.deepEqual(second.buttons.map(({ afterId, afterEpoch }) => ({ afterId, afterEpoch })), [
    { afterId: null, afterEpoch: null },
  ]);
  const empty = await renderTelegramView(db, "81003", firstPage("list"));
  assert.deepEqual(empty.buttons, []);
  assert.equal(empty.text.includes(rows[0].name), false);
});

test("expiry views exclude stale and far dates and continue through equal-expiry ties", async () => {
  const owner = "81004";
  const rows = [];
  for (let index = 1; index <= 9; index += 1) rows.push(await create(owner, `Expiry tie ${index}`));
  const boundary = await create(owner, "Fourteen day fixture");
  const stale = await create(owner, "Stale expiry fixture");
  const far = await create(owner, "Far expiry fixture");
  const unknown = await create(owner, "Unknown expiry fixture");
  const foreign = await create("81005", "Foreign expiry fixture");
  const captured = await now();
  const tie = captured + 3600;
  await db.batch([
    ...[...rows, foreign].map(({ id }) => db.prepare("UPDATE subscriptions SET expire_at = ? WHERE id = ?").bind(tie, id)),
    db.prepare("UPDATE subscriptions SET expire_at = ? WHERE id = ?").bind(captured + fourteenDays, boundary.id),
    db.prepare("UPDATE subscriptions SET expire_at = ? WHERE id = ?").bind(captured - 60, stale.id),
    db.prepare("UPDATE subscriptions SET expire_at = ? WHERE id = ?").bind(captured + fourteenDays + 60, far.id),
  ]);

  const first = await renderTelegramView(db, owner, firstPage("expiry"));
  assertNameOrder(first.text, rows.slice(0, 8).map(({ name }) => name));
  assert.equal(first.text.includes(rows[8].name), false);
  assert.deepEqual(first.buttons.map(({ afterId, afterEpoch }) => ({ afterId, afterEpoch })), [
    { afterId: rows[7].id, afterEpoch: tie },
  ]);
  const second = await renderTelegramView(db, owner, { ...firstPage("expiry"), ...first.buttons[0] });
  assertNameOrder(second.text, [rows[8].name, boundary.name]);
  assert.equal(second.text.includes(rows[7].name), false);
  for (const { name } of [stale, far, unknown, foreign]) {
    assert.equal(first.text.includes(name), false);
    assert.equal(second.text.includes(name), false);
  }
});

test("recycle views paginate tied deletion times in reverse order and enforce the 30-day window", async () => {
  const owner = "81006";
  const rows = [];
  for (let index = 1; index <= 9; index += 1) rows.push(await create(owner, `Recycle tie ${index}`));
  const boundary = await create(owner, "Thirty day fixture");
  const expired = await create(owner, "Expired recycle fixture");
  const foreign = await create("81007", "Foreign recycle fixture");
  const active = await create(owner, "Active recycle fixture");
  for (const row of [...rows, boundary, expired, foreign]) {
    assert.equal(await trashOwnedSubscription(db, { ...row, expectedLifecycleRevision: row.lifecycleRevision }), true);
  }
  const captured = await now();
  const tie = captured - thirtyDays + 60;
  await db.batch([
    ...[...rows, foreign].map(({ id }) => db.prepare("UPDATE subscription_trash SET deleted_at = ? WHERE id = ?").bind(tie, id)),
    db.prepare("UPDATE subscription_trash SET deleted_at = ? WHERE id = ?").bind(captured - thirtyDays - 1, boundary.id),
    db.prepare("UPDATE subscription_trash SET deleted_at = ? WHERE id = ?").bind(captured - thirtyDays - 1, expired.id),
  ]);

  const first = await renderTelegramView(db, owner, firstPage("recycle"));
  assertNameOrder(first.text, rows.slice(1).reverse().map(({ name }) => name));
  assert.equal(first.text.includes(rows[0].name), false);
  assert.deepEqual(first.buttons.map(({ afterId, afterEpoch }) => ({ afterId, afterEpoch })), [
    { afterId: rows[1].id, afterEpoch: tie },
  ]);
  assert.deepEqual(first.lifecycleButtons.map(({ action, subscriptionId, expectedLifecycleRevision }) =>
    ({ action, subscriptionId, expectedLifecycleRevision })), rows.slice(1).reverse().map(({ id: subscriptionId }) =>
    ({ action: "restore", subscriptionId, expectedLifecycleRevision: 1 })));
  const second = await renderTelegramView(db, owner, { ...firstPage("recycle"), ...first.buttons[0] });
  assert.match(second.text, /Recycle tie 1/u);
  assert.equal(second.text.includes(rows[1].name), false);
  for (const { name } of [expired, foreign, active]) {
    assert.equal(first.text.includes(name), false);
    assert.equal(second.text.includes(name), false);
  }

  // Test equality only when the SQLite clock has not ticked between the write and view.
  let testedBoundary = false;
  for (let attempt = 0; attempt < 3 && !testedBoundary; attempt += 1) {
    const set = await db.prepare(`
      UPDATE subscription_trash SET deleted_at = unixepoch() - ? WHERE id = ?
      RETURNING deleted_at + ? AS timestamp
    `).bind(thirtyDays, boundary.id, thirtyDays).first<{ timestamp: number }>();
    assert.ok(set);
    const atBoundary = await renderTelegramView(db, owner, { ...firstPage("recycle"), ...first.buttons[0] });
    if (await now() === set.timestamp) {
      assert.match(atBoundary.text, /Thirty day fixture/u);
      testedBoundary = true;
    }
  }
  assert.equal(testedBoundary, true);
});

function policy(botId: string): TelegramPolicy {
  return {
    botId, botUsername: "Synthetic_View_Bot", adminId: "42001", memberId: "42002", groupId: "-1001234567890",
    webhookSecret: "synthetic-webhook-secret", botToken: `${botId}:synthetic-token`,
  };
}

function directView(scope: TelegramPolicy, updateId: number) {
  return {
    updateId, actorId: scope.memberId, chatId: scope.groupId, chatType: "supergroup", threadId: 51,
    messageId: updateId, messageDate: 1_795_000_000, kind: "list",
  } as const satisfies TelegramViewUpdate;
}

function legacyCommand(scope: TelegramPolicy, updateId: number, command: "help" | "auth-add" | "auth-remove") {
  return {
    updateId, actorId: scope.adminId, chatId: scope.adminId, chatType: "private" as const, threadId: null,
    messageId: updateId, messageDate: 1_795_000_000, command,
  };
}

type CallbackUpdate = Extract<TelegramViewUpdate, { kind: "callback" }>;

function callback(scope: TelegramPolicy, updateId: number, ticket: string, messageId: number): CallbackUpdate {
  return {
    ...directView(scope, updateId), kind: "callback", callbackId: `fixture-${updateId}`, ticket,
    messageId, messageDate: 1_795_000_002,
  };
}

async function receipt(scope: TelegramPolicy, updateId: number) {
  return db.prepare(`
    SELECT receipt_id AS receiptId, receipt_nonce AS marker, state, kind, after_id AS afterId, after_epoch AS afterEpoch
    FROM telegram_inbox LEFT JOIN telegram_view USING (receipt_id) LEFT JOIN telegram_outbox USING (receipt_id)
    WHERE bot_id = ? AND update_id = ?
  `).bind(scope.botId, updateId).first<{
    receiptId: number; marker: string | null; state: string | null; kind: string | null;
    afterId: number | null; afterEpoch: number | null;
  }>();
}

function ticketHash(ticket: string): string {
  return createHash("sha256").update(ticket).digest("hex");
}

async function storedTicket(ticket: string) {
  return db.prepare(`
    SELECT token_sha256 AS tokenHash, origin_receipt_id AS originReceiptId, origin_attempt AS originAttempt,
      expires_at AS expiresAt, used_by_receipt_id AS usedByReceiptId
    FROM telegram_view_ticket WHERE token_sha256 = ?
  `).bind(ticketHash(ticket)).first<{
    tokenHash: string; originReceiptId: number; originAttempt: number; expiresAt: number; usedByReceiptId: number | null;
  }>();
}

async function preparePage() {
  const { keyboard, tickets } = await prepareTelegramViewTickets([{ text: "Next fixture page", afterId: 123, afterEpoch: null }]);
  const ticket = keyboard[0][0].callback_data;
  assert.match(ticket, /^sbv1_[A-Za-z0-9_-]{22}$/u);
  assert.deepEqual(tickets, [{ sha256: ticketHash(ticket), afterId: 123, afterEpoch: null }]);
  return { ticket, tickets };
}

async function claimOrigin(scope: TelegramPolicy, updateId: number) {
  assert.equal(await acceptTelegramView(db, scope, directView(scope, updateId)), "accepted");
  const lease = await claimTelegramReply(db, scope.botId);
  assert.ok(lease);
  assert.equal(lease.updateId, updateId);
  assert.deepEqual(lease.view, firstPage("list"));
  return lease;
}

test("view and legacy events share one durable receipt and reply per update", async () => {
  const scope = policy("51001");
  const first = directView(scope, 100);
  const repeated = await Promise.all([acceptTelegramView(db, scope, first), acceptTelegramView(db, scope, first)]);
  assert.deepEqual(repeated.sort(), ["accepted", "ignored"]);
  assert.equal(await acceptTelegramCommand(db, scope, legacyCommand(scope, first.updateId, "help")), "duplicate");
  const stored = await receipt(scope, first.updateId);
  assert.ok(stored);
  assert.deepEqual(stored, { receiptId: stored.receiptId, marker: TELEGRAM_VIEW_MARKER, state: "pending", ...firstPage("list") });

  assert.equal(await acceptTelegramCommand(db, scope, legacyCommand(scope, 101, "help")), "accepted");
  assert.equal(await acceptTelegramView(db, scope, directView(scope, 101)), "ignored");
  assert.equal((await receipt(scope, 101))?.kind, null);
  assert.equal((await receipt(scope, 101))?.marker, null);
  const legacyEligible = await db.prepare(`
    SELECT update_id AS updateId FROM telegram_inbox JOIN telegram_outbox USING (receipt_id)
    WHERE bot_id = ? AND receipt_nonce IS NULL AND state = 'pending' ORDER BY receipt_id
  `).bind(scope.botId).all();
  assert.deepEqual(legacyEligible.results, [{ updateId: 101 }]);
});

test("uses one confirmed group ticket only for its actor, chat, thread, sent message and bot", async () => {
  const scope = policy("51002");
  const lease = await claimOrigin(scope, 200);
  const { ticket, tickets } = await preparePage();
  const sentId = 1357;
  const wrongReceipt = { ...lease, receiptId: lease.receiptId + 1 };
  assert.equal(await beginTelegramReply(db, scope, wrongReceipt, "allowed", tickets), false);
  assert.equal((await receipt(scope, 200))?.state, "leased");
  assert.equal(await storedTicket(ticket), null);
  assert.equal(await beginTelegramReply(db, scope, lease, "allowed", tickets), true);
  const stored = await storedTicket(ticket);
  assert.ok(stored);
  assert.equal(stored.originReceiptId, lease.receiptId);
  assert.equal(stored.originAttempt, lease.attempts);
  assert.equal(stored.tokenHash, ticketHash(ticket));
  assert.equal(stored.usedByReceiptId, null);
  const clock = await now();
  assert.ok(stored.expiresAt > clock && stored.expiresAt <= clock + 600);

  const early = callback(scope, 201, ticket, sentId);
  assert.equal(await acceptTelegramView(db, scope, early), "ignored");
  assert.equal(await receipt(scope, early.updateId), null);
  assert.equal((await storedTicket(ticket))?.usedByReceiptId, null);
  await settleTelegramReply(db, scope, wrongReceipt, { kind: "sent", messageId: sentId });
  assert.equal((await receipt(scope, 200))?.state, "sending");
  await settleTelegramReply(db, scope, lease, { kind: "sent", messageId: sentId });

  for (const invalid of [
    { ...early, updateId: 202, actorId: scope.adminId },
    { ...early, updateId: 203, chatId: scope.memberId, chatType: "private" as const, threadId: null },
    { ...early, updateId: 204, threadId: 52 },
    { ...early, updateId: 205, chatType: "group" as const },
    { ...early, updateId: 206, messageId: sentId + 1 },
  ]) {
    assert.equal(await acceptTelegramView(db, scope, invalid), "ignored");
    assert.equal(await receipt(scope, invalid.updateId), null);
  }
  const anotherBot = policy("51003");
  assert.equal(await acceptTelegramView(db, anotherBot, early), "ignored");
  assert.equal(await receipt(anotherBot, early.updateId), null);
  assert.equal((await storedTicket(ticket))?.usedByReceiptId, null);

  const revoke = legacyCommand(scope, 207, "auth-remove");
  assert.equal(await acceptTelegramCommand(db, scope, revoke), "accepted");
  const denied = callback(scope, 208, ticket, sentId);
  assert.equal(await acceptTelegramView(db, scope, denied), "ignored");
  assert.equal(await receipt(scope, denied.updateId), null);
  assert.equal((await storedTicket(ticket))?.usedByReceiptId, null);
  assert.equal(await acceptTelegramCommand(db, scope, legacyCommand(scope, 209, "auth-add")), "accepted");

  const clicks = [callback(scope, 210, ticket, sentId), callback(scope, 211, ticket, sentId)];
  const results = await Promise.all(clicks.map((click) => acceptTelegramView(db, scope, click)));
  assert.deepEqual(results.toSorted(), ["accepted", "ignored"]);
  const accepted = await receipt(scope, clicks[results.indexOf("accepted")].updateId);
  assert.ok(accepted);
  assert.deepEqual(accepted, {
    receiptId: accepted.receiptId, marker: TELEGRAM_VIEW_MARKER, state: "pending", kind: "list", afterId: 123, afterEpoch: null,
  });
  assert.equal((await storedTicket(ticket))?.usedByReceiptId, accepted.receiptId);
  assert.equal(await receipt(scope, clicks[results.indexOf("ignored")].updateId), null);
  assert.equal(await acceptTelegramView(db, scope, clicks[results.indexOf("accepted")]), "ignored");
  assert.equal(await acceptTelegramView(db, scope, callback(scope, 212, ticket, sentId)), "ignored");
});

test("rejects tickets from an earlier send attempt and tickets at the expiry cutoff", async () => {
  const scope = policy("51004");
  const first = await claimOrigin(scope, 300);
  const firstPageTicket = await preparePage();
  assert.equal(await beginTelegramReply(db, scope, first, "allowed", firstPageTicket.tickets), true);
  await settleTelegramReply(db, scope, first, { kind: "retry", delaySeconds: 1 });
  await db.prepare("UPDATE telegram_outbox SET due_at = unixepoch() WHERE receipt_id = ?").bind(first.receiptId).run();

  const second = await claimTelegramReply(db, scope.botId);
  assert.ok(second);
  assert.equal(second.attempts, 2);
  assert.equal(second.receiptId, first.receiptId);
  const secondPageTicket = await preparePage();
  assert.equal(await beginTelegramReply(db, scope, second, "allowed", secondPageTicket.tickets), true);
  const sentId = 1358;
  await settleTelegramReply(db, scope, second, { kind: "sent", messageId: sentId });
  assert.equal(await acceptTelegramView(db, scope, callback(scope, 301, firstPageTicket.ticket, sentId)), "ignored");
  assert.equal(await receipt(scope, 301), null);

  await db.prepare("UPDATE telegram_view_ticket SET expires_at = unixepoch() WHERE token_sha256 = ?")
    .bind(ticketHash(secondPageTicket.ticket)).run();
  assert.equal(await acceptTelegramView(db, scope, callback(scope, 302, secondPageTicket.ticket, sentId)), "ignored");
  assert.equal(await receipt(scope, 302), null);
});

test("rolls back send state and callback consumption when the corresponding D1 batches fail", async () => {
  const scope = policy("51005");
  const lease = await claimOrigin(scope, 400);
  const { ticket, tickets } = await preparePage();
  await db.prepare(`
    CREATE TRIGGER reject_test_view_ticket BEFORE INSERT ON telegram_view_ticket
    BEGIN SELECT RAISE(ABORT, 'synthetic ticket failure'); END
  `).run();
  try {
    await assert.rejects(beginTelegramReply(db, scope, lease, "allowed", tickets));
    assert.equal((await receipt(scope, 400))?.state, "leased");
    assert.equal(await storedTicket(ticket), null);
  } finally {
    await db.prepare("DROP TRIGGER reject_test_view_ticket").run();
  }

  assert.equal(await beginTelegramReply(db, scope, lease, "allowed", tickets), true);
  const sentId = 1359;
  await settleTelegramReply(db, scope, lease, { kind: "sent", messageId: sentId });
  const click = callback(scope, 401, ticket, sentId);
  await db.prepare(`
    CREATE TRIGGER reject_test_view_outbox BEFORE INSERT ON telegram_outbox
    BEGIN SELECT RAISE(ABORT, 'synthetic outbox failure'); END
  `).run();
  try {
    await assert.rejects(acceptTelegramView(db, scope, click));
    assert.equal(await receipt(scope, click.updateId), null);
    assert.equal((await storedTicket(ticket))?.usedByReceiptId, null);
  } finally {
    await db.prepare("DROP TRIGGER reject_test_view_outbox").run();
  }
  assert.equal(await acceptTelegramView(db, scope, click), "accepted");
  assert.equal((await storedTicket(ticket))?.usedByReceiptId, (await receipt(scope, click.updateId))?.receiptId);
});

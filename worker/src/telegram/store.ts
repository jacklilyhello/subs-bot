import type { TelegramCommand, TelegramPolicy } from "./protocol.ts";

export interface TelegramReplyLease extends TelegramCommand {
  leaseId: string;
  attempts: number;
}

export type TelegramReplyOutcome =
  | { kind: "sent"; messageId: number }
  | { kind: "retry"; delaySeconds: number }
  | { kind: "failed" | "uncertain" };

const LEASE_SECONDS = 30;
const MAX_REPLY_AGE_SECONDS = 15 * 60;
const MAX_ATTEMPTS = 4;
const REAP_LIMIT = 40;

function inScope(policy: TelegramPolicy, command: TelegramCommand): boolean {
  if (command.actorId !== policy.adminId && command.actorId !== policy.memberId) return false;
  if (command.chatType === "private") return command.chatId === command.actorId;
  return (command.chatType === "group" || command.chatType === "supergroup") && command.chatId === policy.groupId;
}

export async function acceptTelegramCommand(
  db: D1Database,
  policy: TelegramPolicy,
  command: TelegramCommand,
): Promise<"accepted" | "duplicate"> {
  if (!inScope(policy, command)) throw new RangeError("Telegram command is outside the isolation scope.");

  const receipt = crypto.randomUUID();
  const key = [policy.botId, command.updateId, receipt] as const;
  const steps = [db.prepare(`
    INSERT INTO telegram_inbox
      (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (bot_id, update_id) DO NOTHING
  `).bind(policy.botId, command.updateId, command.actorId, command.chatId, command.chatType,
    command.messageId, command.messageDate, command.threadId, command.command, receipt)];

  if (command.command === "auth-add" || command.command === "auth-remove") {
    // Only the explicit admin's own private command can change the configured member.
    // A delayed older grant cannot undo a newer revocation from that same chat.
    steps.push(db.prepare(`
      INSERT INTO telegram_auth (bot_id, user_id, allowed, message_date, message_id)
      SELECT bot_id, ?, ?, message_date, message_id FROM telegram_inbox
      WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
        AND chat_type = 'private' AND actor_id = ? AND chat_id = actor_id
      ON CONFLICT (bot_id, user_id) DO UPDATE SET
        allowed = excluded.allowed, message_date = excluded.message_date, message_id = excluded.message_id
      WHERE (excluded.message_date, excluded.message_id) > (telegram_auth.message_date, telegram_auth.message_id)
    `).bind(policy.memberId, command.command === "auth-add" ? 1 : 0, ...key, policy.adminId));
  }

  steps.push(
    db.prepare(`
      INSERT INTO telegram_outbox (receipt_id)
      SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
    `).bind(...key),
    db.prepare(`
      UPDATE telegram_inbox SET receipt_nonce = NULL
      WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
      RETURNING receipt_id
    `).bind(...key),
  );
  // Clearing the nonce in the same transaction fences even a replay of the identical batch.
  const results = await db.batch(steps);
  const receiptResult = results.at(-1);
  if (!receiptResult || results.length !== steps.length || results.some((result) => !result.success)) {
    throw new Error("Telegram command receipt could not be confirmed.");
  }
  return receiptResult.results.length ? "accepted" : "duplicate";
}

export async function isTelegramMemberAllowed(db: D1Database, policy: TelegramPolicy): Promise<boolean> {
  const row = await db.prepare("SELECT allowed FROM telegram_auth WHERE bot_id = ? AND user_id = ?")
    .bind(policy.botId, policy.memberId).first<{ allowed: number }>();
  return row === null || row.allowed === 1;
}

export async function claimTelegramReply(db: D1Database, botId: string): Promise<TelegramReplyLease | null> {
  const leaseId = crypto.randomUUID();
  const [write, read] = await db.batch<TelegramReplyLease>([
    db.prepare(`
      UPDATE telegram_outbox
      SET state = 'leased', attempts = attempts + 1, lease_id = ?, lease_until = unixepoch() + ${LEASE_SECONDS}
      WHERE receipt_id = (
        SELECT inbox.receipt_id FROM telegram_outbox AS reply
        JOIN telegram_inbox AS inbox USING (receipt_id)
        WHERE inbox.bot_id = ? AND inbox.receipt_nonce IS NULL AND reply.state = 'pending'
          AND reply.due_at <= unixepoch() AND reply.attempts < ${MAX_ATTEMPTS}
          AND inbox.received_at + ${MAX_REPLY_AGE_SECONDS} > unixepoch()
          AND NOT EXISTS (
            SELECT 1 FROM telegram_inbox AS earlier
            JOIN telegram_outbox AS earlier_reply USING (receipt_id)
            WHERE earlier.bot_id = inbox.bot_id AND earlier.actor_id = inbox.actor_id AND earlier.chat_id = inbox.chat_id
              AND earlier.receipt_id < inbox.receipt_id AND earlier_reply.state IN ('pending', 'leased', 'sending')
          )
        ORDER BY inbox.receipt_id LIMIT 1
      )
    `).bind(leaseId, botId),
    db.prepare(`
      SELECT inbox.update_id AS updateId, inbox.actor_id AS actorId, inbox.chat_id AS chatId, inbox.chat_type AS chatType,
        inbox.message_id AS messageId, inbox.message_date AS messageDate, inbox.thread_id AS threadId,
        inbox.command, reply.lease_id AS leaseId, reply.attempts
      FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
      WHERE reply.lease_id = ? AND reply.state = 'leased' AND inbox.bot_id = ?
    `).bind(leaseId, botId),
  ]);
  if (!write?.success || !read?.success) throw new Error("Telegram reply claim could not be confirmed.");
  return read.results[0] ?? null;
}

export async function beginTelegramReply(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  access: "allowed" | "denied" | "none",
): Promise<boolean> {
  if (!inScope(policy, lease)) return false;

  const row = await db.prepare(`
    UPDATE telegram_outbox SET state = 'sending', lease_until = unixepoch() + ${LEASE_SECONDS}
    WHERE state = 'leased' AND lease_id = ? AND attempts = ? AND lease_until > unixepoch()
      AND receipt_id = (
        SELECT inbox.receipt_id FROM telegram_inbox AS inbox
        WHERE inbox.bot_id = ? AND inbox.update_id = ? AND inbox.actor_id = ? AND inbox.chat_id = ?
          AND inbox.chat_type = ? AND inbox.message_id = ? AND inbox.message_date = ? AND inbox.thread_id IS ?
          AND inbox.command = ? AND inbox.received_at + ${MAX_REPLY_AGE_SECONDS} > unixepoch()
          AND ((? = 'none' AND inbox.command IN ('auth-list', 'auth-add', 'auth-remove', 'auth-usage')) OR (
            CASE WHEN inbox.actor_id = ? THEN 1 ELSE COALESCE((
              SELECT allowed FROM telegram_auth WHERE bot_id = inbox.bot_id AND user_id = inbox.actor_id
            ), 1) END = CASE ? WHEN 'allowed' THEN 1 WHEN 'denied' THEN 0 ELSE -1 END
          ))
      )
    RETURNING receipt_id
  `).bind(lease.leaseId, lease.attempts, policy.botId, lease.updateId, lease.actorId, lease.chatId, lease.chatType,
    lease.messageId, lease.messageDate, lease.threadId, lease.command, access, policy.adminId, access).first();
  return row !== null;
}

export async function settleTelegramReply(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  outcome: TelegramReplyOutcome,
): Promise<void> {
  const identity = [lease.leaseId, lease.attempts, policy.botId, lease.updateId] as const;
  const sameReply = `lease_id = ? AND attempts = ? AND receipt_id = (
    SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = ?
  )`;
  if (outcome.kind === "sent") {
    if (!Number.isSafeInteger(outcome.messageId) || outcome.messageId <= 0) {
      throw new RangeError("Telegram delivery confirmation is invalid.");
    }
    // A late confirmed success may settle the same uncertain attempt, without resending.
    await db.prepare(`
      UPDATE telegram_outbox SET state = 'sent', sent_message_id = ?, lease_id = NULL, lease_until = NULL
      WHERE ${sameReply} AND state IN ('sending', 'uncertain')
    `).bind(outcome.messageId, ...identity).run();
    return;
  }

  if (outcome.kind === "retry" && Number.isSafeInteger(outcome.delaySeconds) && outcome.delaySeconds > 0
      && outcome.delaySeconds < MAX_REPLY_AGE_SECONDS) {
    // Never shorten Telegram's requested wait to fit the retry lifetime.
    await db.prepare(`
      UPDATE telegram_outbox SET state = CASE
        WHEN attempts < ${MAX_ATTEMPTS} AND unixepoch() + ? < (
          SELECT received_at FROM telegram_inbox WHERE receipt_id = telegram_outbox.receipt_id
        ) + ${MAX_REPLY_AGE_SECONDS} THEN 'pending' ELSE 'failed' END,
        due_at = unixepoch() + ?, lease_id = NULL, lease_until = NULL
      WHERE ${sameReply} AND state = 'sending'
    `).bind(outcome.delaySeconds, outcome.delaySeconds, ...identity).run();
    return;
  }

  const state = outcome.kind === "uncertain" ? "uncertain" : "failed";
  await db.prepare(`
    UPDATE telegram_outbox SET state = ?, lease_id = CASE WHEN ? = 'uncertain' THEN lease_id ELSE NULL END,
      lease_until = NULL
    WHERE ${sameReply} AND state = 'sending'
  `).bind(state, state, ...identity).run();
}

export async function reapExpiredTelegramReplies(db: D1Database, botId: string): Promise<void> {
  await db.prepare(`
    UPDATE telegram_outbox SET state = CASE
      WHEN state = 'sending' THEN 'uncertain'
      WHEN state = 'leased' AND attempts < ${MAX_ATTEMPTS} AND (
        SELECT received_at FROM telegram_inbox WHERE receipt_id = telegram_outbox.receipt_id
      ) + ${MAX_REPLY_AGE_SECONDS} > unixepoch() THEN 'pending' ELSE 'failed' END,
      lease_id = CASE WHEN state = 'sending' THEN lease_id ELSE NULL END, lease_until = NULL
    WHERE receipt_id IN (
      SELECT reply.receipt_id FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
      WHERE inbox.bot_id = ? AND (
        (reply.state IN ('leased', 'sending') AND reply.lease_until <= unixepoch())
        OR (reply.state IN ('pending', 'leased') AND inbox.received_at + ${MAX_REPLY_AGE_SECONDS} <= unixepoch())
      )
      ORDER BY reply.receipt_id LIMIT ${REAP_LIMIT}
    )
  `).bind(botId).run();
}

import { validInteger } from "../storage.ts";
import { isolatedTelegramRoleEpochSql } from "./authorization-sql.ts";
import {
  inTelegramScope, TELEGRAM_PAGE_JUMP_MARKER, TELEGRAM_PAGE_JUMP_PROMPT,
  type TelegramPageJumpUpdate, type TelegramPolicy,
} from "./protocol.ts";
import { TELEGRAM_VIEW_PAGE_SIZE, TELEGRAM_VIEW_RECEIPTS } from "./views.ts";

const MIGRATION = "0042_telegram_page_jumps.sql";
const MIGRATION_SHA256 = "195fdd3611d9f380e86d9b30983fff306d4218c2ae7899d7dcf49fa275f9c288";
const TTL_SECONDS = 600;
// Cover every subscription count admitted by the sealed legacy restore package.
const MAX_ROWS = 20_000;
const MAX_PAGE = Math.ceil(MAX_ROWS / TELEGRAM_VIEW_PAGE_SIZE);
const failure = "Telegram page jump could not be confirmed.";
type Guard = { sql: string; bindings: readonly (string | number | null)[] };
type Kind = "prompt" | "page" | "invalid" | "range" | "limit" | "cancelled";
type Presentation = { kind: Kind; maximum: number | null };

export async function telegramPageJumpReady(db: D1Database): Promise<boolean> {
  try {
    return await db.prepare(`SELECT /* subs-bot:telegram-page-jump:v1 */ 1 AS ready FROM subs_bot_schema_migrations
      WHERE position=42 AND name=? AND sha256=? AND mode='applied'
        AND (SELECT count(*) FROM sqlite_schema WHERE tbl_name='telegram_page_jumps' AND (
          (type='table' AND name='telegram_page_jumps') OR (type='index' AND name='telegram_page_jumps_expiry')))=2`)
      .bind(MIGRATION, MIGRATION_SHA256).first<number>("ready") === 1;
  } catch {
    return false;
  }
}

const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
const newerPrompt = `EXISTS (
  SELECT 1 FROM telegram_inbox AS newer JOIN telegram_page_jumps AS pending USING(receipt_id)
  WHERE newer.bot_id=inbox.bot_id AND newer.actor_id=inbox.actor_id AND newer.chat_id=inbox.chat_id
    AND newer.chat_type=inbox.chat_type AND newer.thread_id IS inbox.thread_id
    AND newer.update_id>inbox.update_id AND pending.kind='prompt'
)`;

function candidateSource(policy: TelegramPolicy, event: TelegramPageJumpUpdate): Guard {
  const matchScope = `inbox.bot_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND inbox.chat_type=? AND inbox.thread_id IS ?
    AND inbox.update_id<? AND reply.state='sent' AND reply.sent_message_id=?
    AND NOT EXISTS (SELECT 1 FROM telegram_page_jumps WHERE origin_receipt_id=inbox.receipt_id)`;
  const scope = [policy.botId, event.actorId, event.chatId, event.chatType, event.threadId, event.updateId,
    event.kind === "open" ? event.messageId : event.promptMessageId];
  if (event.kind === "open") {
    return {
      sql: `SELECT inbox.receipt_id,CASE WHEN inbox.actor_id=? THEN 'admin' ELSE 'member' END AS actor_role,
        CASE WHEN inbox.actor_id=? THEN 0 ELSE COALESCE(auth.message_date,0) END AS auth_message_date,
        CASE WHEN inbox.actor_id=? THEN 0 ELSE COALESCE(auth.message_id,0) END AS auth_message_id
        FROM telegram_inbox AS inbox JOIN telegram_view AS view USING(receipt_id) JOIN telegram_outbox AS reply USING(receipt_id)
        LEFT JOIN telegram_page_jumps AS prior USING(receipt_id)
        LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id
        WHERE ${matchScope} AND view.kind='list' AND inbox.receipt_nonce IN (${TELEGRAM_VIEW_RECEIPTS})
          AND (CASE WHEN inbox.receipt_nonce='${TELEGRAM_PAGE_JUMP_MARKER}' THEN prior.kind='page'
            AND prior.actor_role=CASE WHEN inbox.actor_id=? THEN 'admin' ELSE 'member' END
            AND prior.auth_message_date=CASE WHEN inbox.actor_id=? THEN 0 ELSE COALESCE(auth.message_date,0) END
            AND prior.auth_message_id=CASE WHEN inbox.actor_id=? THEN 0 ELSE COALESCE(auth.message_id,0) END
            ELSE prior.receipt_id IS NULL END)
          AND inbox.received_at>unixepoch()-${TTL_SECONDS}
          AND ? BETWEEN unixepoch()-${TTL_SECONDS} AND unixepoch()+30
          AND (inbox.actor_id=? OR (COALESCE(auth.allowed,1)=1 AND COALESCE(auth.message_date,0)<inbox.message_date
            AND COALESCE(auth.message_date,0)<?))
        LIMIT 1`,
      bindings: [policy.adminId, policy.adminId, policy.adminId, ...scope, policy.adminId, policy.adminId, policy.adminId,
        event.messageDate, policy.adminId, event.messageDate],
    };
  }
  const epoch = isolatedTelegramRoleEpochSql(policy, "inbox");
  return {
    sql: `SELECT inbox.receipt_id,origin.actor_role,origin.auth_message_date,origin.auth_message_id
      FROM telegram_inbox AS inbox JOIN telegram_page_jumps AS origin USING(receipt_id)
      JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE ${matchScope} AND inbox.receipt_nonce='${TELEGRAM_PAGE_JUMP_MARKER}' AND origin.kind='prompt'
        AND origin.expires_at>unixepoch() AND NOT ${newerPrompt} AND ${epoch.sql}
        AND ? BETWEEN unixepoch()-${TTL_SECONDS} AND unixepoch()+30 AND ?>=inbox.message_date
        AND (origin.actor_role='admin' OR ?>origin.auth_message_date)
      LIMIT 1`,
    bindings: [...scope, ...epoch.bindings, event.messageDate, event.messageDate, event.messageDate],
  };
}

/** A normal list receipt authorizes one prompt, and only its exact confirmed reply is consumable. */
export async function acceptTelegramPageJump(db: D1Database, policy: TelegramPolicy, event: TelegramPageJumpUpdate): Promise<boolean> {
  if (event.kind === "reply" && event.page !== null && !validInteger(event.page, 1)) return false;
  if (!inTelegramScope(policy, event) || !await telegramPageJumpReady(db)) return false;
  const source = candidateSource(policy, event);
  const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
  const requested = event.kind === "reply" && !event.cancelled ? event.page : null;
  const fixedKind = event.kind === "open" ? "prompt" : event.cancelled ? "cancelled" : "invalid";
  const offset = requested === null ? 0 : (Math.min(MAX_PAGE + 1, requested) - 1) * TELEGRAM_VIEW_PAGE_SIZE - 1;
  // Only scan through the first row on the requested page. One extra row distinguishes a true maximum from a seek limit.
  const count = `SELECT count(*) AS tally, max(1,(count(*)+${TELEGRAM_VIEW_PAGE_SIZE - 1})/${TELEGRAM_VIEW_PAGE_SIZE}) AS maximum
    FROM (SELECT id FROM subscriptions WHERE owner_id=? ORDER BY id LIMIT ?)`;
  const result = requested === null ? "SELECT ? AS kind, NULL AS maximum" : `SELECT
    CASE WHEN tally>${MAX_ROWS} THEN 'limit' WHEN ?>maximum THEN 'range' ELSE 'page' END AS kind,
    CASE WHEN tally<=${MAX_ROWS} AND ?>maximum THEN maximum END AS maximum FROM (${count})`;
  const resultBindings = requested === null ? [fixedKind] : [requested, requested, event.actorId, offset + 2];
  try {
    const steps = [
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,?,?,?,?,'help',? FROM (${source.sql}) WHERE 1
        ON CONFLICT(bot_id,update_id) DO NOTHING`)
        .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.chatType, event.messageId,
          event.messageDate, event.threadId, key[2], ...source.bindings),
      db.prepare(`INSERT INTO telegram_page_jumps
        (receipt_id,origin_receipt_id,kind,max_page,actor_role,auth_message_date,auth_message_id,expires_at)
        SELECT incoming.receipt_id,source.receipt_id,result.kind,result.maximum,
          source.actor_role,source.auth_message_date,source.auth_message_id,unixepoch()+${TTL_SECONDS}
        FROM telegram_inbox AS incoming CROSS JOIN (${source.sql}) AS source CROSS JOIN (${result}) AS result WHERE ${fresh}`)
        .bind(...source.bindings, ...resultBindings, ...key),
      db.prepare(`INSERT INTO telegram_view (receipt_id,kind,after_id)
        SELECT incoming.receipt_id,'list',CASE WHEN jump.kind='page' AND ?>=0 THEN (
          SELECT id FROM subscriptions WHERE owner_id=incoming.actor_id ORDER BY id LIMIT 1 OFFSET ?
        ) END FROM telegram_inbox AS incoming JOIN telegram_page_jumps AS jump USING(receipt_id) WHERE ${fresh}`)
        .bind(offset, Math.max(0, offset), ...key),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?, command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_view WHERE receipt_id=incoming.receipt_id AND (?<0 OR after_id IS NOT NULL OR NOT EXISTS (
          SELECT 1 FROM telegram_page_jumps WHERE receipt_id=incoming.receipt_id AND kind='page'))
      ) AND EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=incoming.receipt_id)
      THEN command END WHERE ${fresh} RETURNING receipt_id`).bind(TELEGRAM_PAGE_JUMP_MARKER, offset, ...key),
    ];
    const rows = await db.batch(steps);
    if (rows.length === steps.length && rows.every(({ success }) => success) && rows.at(-1)!.results.length <= 1) {
      return rows.at(-1)!.results.length === 1;
    }
  } catch {
    // No raw reply text or D1 error leaves admission.
  }
  throw new Error(failure);
}

export function telegramPageJumpSendGuard(policy: TelegramPolicy): Guard {
  const epoch = isolatedTelegramRoleEpochSql(policy, "inbox");
  return { sql: `EXISTS (SELECT 1 FROM telegram_page_jumps AS origin WHERE origin.receipt_id=inbox.receipt_id
    AND origin.expires_at>unixepoch() AND (origin.kind<>'prompt' OR NOT ${newerPrompt}) AND ${epoch.sql})`, bindings: epoch.bindings };
}

export async function confirmTelegramPageJumpSend(db: D1Database, policy: TelegramPolicy,
  lease: { receiptId: number; leaseId: string; attempts: number }, guard: Guard): Promise<boolean> {
  try {
    return await db.prepare(`SELECT 1 AS confirmed FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE inbox.receipt_id=? AND inbox.bot_id=? AND inbox.receipt_nonce='${TELEGRAM_PAGE_JUMP_MARKER}'
        AND reply.state='sending' AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()
        AND ${guard.sql}`).bind(lease.receiptId, policy.botId, lease.leaseId, lease.attempts, ...guard.bindings)
      .first<number>("confirmed") === 1;
  } catch {
    return false;
  }
}

export async function renderTelegramPageJump(db: D1Database, receiptId: number):
Promise<{ text: string; forceReply: boolean } | "page" | null> {
  if (!await telegramPageJumpReady(db)) return null;
  try {
    const row = await db.prepare("SELECT kind,max_page AS maximum FROM telegram_page_jumps WHERE receipt_id=?")
      .bind(receiptId).first<Presentation>();
    switch (row?.kind) {
      case "prompt": return { text: TELEGRAM_PAGE_JUMP_PROMPT, forceReply: true };
      case "page": return "page";
      case "invalid": return { text: "页码必须是数字，已取消跳转。", forceReply: false };
      case "cancelled": return { text: "已取消当前操作。", forceReply: false };
      case "range": return validInteger(row.maximum, 1)
        ? { text: `页码超出范围（最大 ${row.maximum}），已取消。`, forceReply: false } : null;
      case "limit": return { text: "此页超出直接跳转上限，请使用“下一页”继续。", forceReply: false };
      default: return null;
    }
  } catch {
    return null;
  }
}

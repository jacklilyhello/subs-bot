import { validInteger } from "../storage.ts";
import { TELEGRAM_PRIVATE_SHARE_CREATION_MARKER } from "./private-share-creation.ts";
import { inTelegramScope, type TelegramGroupShareUpdate, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_GROUP_CLAIM_MARKER = "group-claim:v1";
const PUBLISH_MARKER = "group-share-publish:v1";
const PICK_MARKER = "group-share-pick:v1";
const PICK_SECONDS = 600;
const SAFE_ERROR = "Telegram group share action could not be confirmed.";
const MIGRATION_NAME = "0037_telegram_group_share_cards.sql";
const MIGRATION_SHA256 = "8754268cb362e54c6a4ad249baa556682c998ddbc8b43c4fbd2c93c3781adef2";
type Sql = { sql: string; bindings: readonly (string | number)[] };

export async function telegramGroupShareReady(db: D1Database): Promise<boolean> {
  try {
    return await db.prepare(`SELECT /* subs-bot:telegram-group-share-cards:v1 */ count(*) AS present FROM sqlite_schema
      WHERE type='table' AND name IN ('telegram_group_share_cards','telegram_group_share_scopes')
      AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=37 AND name=? AND sha256=? AND mode='applied')`)
      .bind(MIGRATION_NAME, MIGRATION_SHA256).first<number>("present") === 2;
  } catch {
    // Optional readiness must not block existing private creation or claims.
    return false;
  }
}

// Bind the configured admin ID and member ID, in that order.
export const groupShareCreatorAuthorized = `((creation.actor_id=? AND creation.auth_message_date=0 AND creation.auth_message_id=0)
  OR (creation.actor_id=? AND creation.message_date>creation.auth_message_date AND COALESCE((
    SELECT allowed=1 AND message_date=creation.auth_message_date AND message_id=creation.auth_message_id
    FROM telegram_auth WHERE bot_id=creation.bot_id AND user_id=creation.actor_id
  ),creation.auth_message_date=0 AND creation.auth_message_id=0)))`;

const publishedShare = `JOIN private_shares AS share ON share.id=creation.share_id AND share.bot_id=creation.bot_id
  AND share.sender_id=creation.actor_id AND share.payload_id=creation.payload_id AND share.payload_sha256=creation.payload_sha256
  AND share.payload_bytes=creation.payload_bytes AND share.sender_name=creation.sender_name AND share.max_claims=creation.max_claims
  AND share.target_user_id IS creation.target_user_id AND share.expire_at=share.created_at+60*creation.duration_minutes`;
const cardShare = `JOIN telegram_private_share_creations AS creation ON creation.receipt_id=card.receipt_id ${publishedShare}`;
const fresh = "bot_id=? AND update_id=? AND receipt_nonce=?";
const incoming = `INSERT INTO telegram_inbox(bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
  SELECT ?,?,?,?,?,?,?,NULL,'help',?`;

// A negative date distinguishes a recorded admin from an initially allowed member's zero epoch.
function authorizedScope(policy: TelegramPolicy, scope: "selected" | "handoff", actor: "pick" | "inbox"): Sql {
  return { sql: `((${actor}.actor_id=? AND ${scope}.auth_date=-1 AND ${scope}.auth_id=0) OR
    (${actor}.actor_id=? AND ${scope}.auth_date>=0 AND ${actor}.message_date>${scope}.auth_date AND COALESCE((
      SELECT allowed=1 AND message_date=${scope}.auth_date AND message_id=${scope}.auth_id
      FROM telegram_auth WHERE bot_id=${actor}.bot_id AND user_id=${actor}.actor_id
    ),${scope}.auth_date=0 AND ${scope}.auth_id=0)))`, bindings: [policy.adminId, policy.memberId] };
}

function publishCandidate(policy: TelegramPolicy, event: TelegramGroupShareUpdate): Sql {
  return { sql: `SELECT creation.receipt_id AS card_id
    FROM telegram_private_share_creations AS creation ${publishedShare}
    JOIN telegram_inbox AS origin ON origin.receipt_id=creation.receipt_id
    JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
    WHERE creation.bot_id=? AND creation.actor_id=? AND creation.state='published' AND share.expire_at>=unixepoch()
      AND origin.bot_id=creation.bot_id AND origin.actor_id=creation.actor_id AND origin.chat_id=creation.actor_id
      AND origin.chat_type='private' AND origin.thread_id IS NULL AND origin.command='help'
      AND origin.receipt_nonce='${TELEGRAM_PRIVATE_SHARE_CREATION_MARKER}'
      AND origin.message_id=creation.message_id AND origin.message_date=creation.message_date
      AND origin.update_id<?
      AND reply.state='sent' AND reply.sent_message_id=? AND ${groupShareCreatorAuthorized}
      AND NOT EXISTS (SELECT 1 FROM telegram_group_share_cards WHERE receipt_id=creation.receipt_id)
    LIMIT 2`, bindings: [policy.botId, event.actorId, event.updateId, event.messageId, policy.adminId, policy.memberId] };
}

function pickCandidate(policy: TelegramPolicy, event: TelegramGroupShareUpdate): Sql {
  return { sql: `SELECT card.receipt_id AS card_id,
      CASE WHEN ?=? THEN -1 ELSE COALESCE(auth.message_date,0) END AS auth_date,
      CASE WHEN ?=? THEN 0 ELSE COALESCE(auth.message_id,0) END AS auth_id,unixepoch() AS picked_at
    FROM telegram_group_share_cards AS card ${cardShare}
    LEFT JOIN telegram_auth AS auth ON auth.bot_id=creation.bot_id AND auth.user_id=?
    WHERE card.group_id=? AND card.state='sent' AND card.message_id=?
      AND creation.bot_id=? AND creation.state='published' AND share.expire_at>=unixepoch()
      AND (share.target_user_id IS NULL OR share.target_user_id=?)
      AND (?=? OR (?=? AND COALESCE(auth.allowed=1 AND auth.message_date<?,1)))`,
    bindings: [event.actorId, policy.adminId, event.actorId, policy.adminId, event.actorId, policy.groupId, event.messageId,
      policy.botId, event.actorId, event.actorId, policy.adminId, event.actorId, policy.memberId, event.messageDate] };
}

const pickedCard = `pick.bot_id=creation.bot_id AND pick.chat_id=card.group_id AND pick.chat_type IN ('group','supergroup')
  AND pick.thread_id IS NULL AND pick.command='help' AND pick.receipt_nonce='${PICK_MARKER}'
  AND pick.message_id=card.message_id`;

function handoffCandidate(policy: TelegramPolicy, event: TelegramGroupShareUpdate): Sql {
  const epoch = authorizedScope(policy, "selected", "pick");
  return { sql: `SELECT selected.card_id,selected.auth_date,selected.auth_id,selected.picked_at,share.code_sha256
    FROM telegram_group_share_scopes AS selected JOIN telegram_inbox AS pick ON pick.receipt_id=selected.receipt_id
    JOIN telegram_group_share_cards AS card ON card.receipt_id=selected.card_id ${cardShare}
    WHERE pick.bot_id=? AND pick.actor_id=? AND pick.update_id<? AND card.group_id=? AND ${pickedCard}
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox AS newer
        JOIN telegram_group_share_scopes AS newer_scope USING(receipt_id)
        WHERE newer.bot_id=pick.bot_id AND newer.actor_id=pick.actor_id AND newer.chat_id=pick.chat_id
          AND newer.receipt_nonce='${PICK_MARKER}' AND newer.update_id>pick.update_id AND newer.update_id<?)
      AND selected.picked_at BETWEEN unixepoch()-${PICK_SECONDS} AND unixepoch()
      AND card.state='sent' AND creation.state='published' AND share.expire_at>=unixepoch()
      AND (share.target_user_id IS NULL OR share.target_user_id=pick.actor_id) AND ${epoch.sql}
      AND (?=? OR ?>selected.auth_date)
    ORDER BY pick.update_id DESC LIMIT 1`, bindings: [policy.botId, event.actorId, event.updateId, policy.groupId, event.updateId,
      ...epoch.bindings, event.actorId, policy.adminId, event.messageDate] };
}

/** This predicate is used only for the group's private outbox send, including repeat claims. */
export function groupShareClaimGuard(policy: TelegramPolicy): Sql {
  const epoch = authorizedScope(policy, "handoff", "inbox");
  return { sql: `EXISTS (SELECT 1 FROM telegram_group_share_scopes AS handoff
    JOIN telegram_group_share_cards AS card ON card.receipt_id=handoff.card_id ${cardShare}
    JOIN telegram_private_claim AS claim ON claim.receipt_id=handoff.receipt_id AND claim.code_sha256=share.code_sha256
    WHERE handoff.receipt_id=inbox.receipt_id AND inbox.bot_id=? AND creation.bot_id=inbox.bot_id AND card.group_id=?
      AND inbox.receipt_nonce='${TELEGRAM_GROUP_CLAIM_MARKER}' AND inbox.command='help'
      AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
      AND card.state='sent' AND creation.state='published' AND share.expire_at>=unixepoch()
      AND (share.target_user_id IS NULL OR share.target_user_id=inbox.actor_id) AND ${epoch.sql}
      AND handoff.picked_at BETWEEN unixepoch()-${PICK_SECONDS} AND unixepoch()
      AND EXISTS (SELECT 1 FROM telegram_group_share_scopes AS picked
        JOIN telegram_inbox AS pick ON pick.receipt_id=picked.receipt_id
        WHERE picked.card_id=handoff.card_id AND pick.actor_id=inbox.actor_id AND pick.update_id<inbox.update_id
          AND ${pickedCard} AND picked.auth_date=handoff.auth_date AND picked.auth_id=handoff.auth_id
          AND picked.picked_at=handoff.picked_at))`, bindings: [policy.botId, policy.groupId, ...epoch.bindings] };
}

export async function acceptTelegramGroupShare(
  db: D1Database, policy: TelegramPolicy, event: TelegramGroupShareUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event) || event.threadId !== null ||
      (event.kind === "pick" ? event.chatType === "private" : event.chatType !== "private") ||
      !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  try {
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const values = [policy.botId, event.updateId, event.actorId, event.chatId, event.chatType, event.messageId,
      event.messageDate, key[2]] as const;
    const candidate = event.kind === "publish" ? publishCandidate(policy, event)
      : event.kind === "pick" ? pickCandidate(policy, event) : handoffCandidate(policy, event);
    const source = `WITH candidate AS (${candidate.sql})`;
    const steps = [db.prepare(`${source} ${incoming} WHERE (SELECT count(*) FROM candidate)=1
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(...candidate.bindings, ...values)];
    if (event.kind === "publish") {
      steps.push(db.prepare(`${source} INSERT INTO telegram_group_share_cards(receipt_id,group_id,state,due_at)
        SELECT card_id,?,'pending',unixepoch() FROM candidate WHERE EXISTS(SELECT 1 FROM telegram_inbox WHERE ${fresh})`)
        .bind(...candidate.bindings, policy.groupId, ...key));
    } else {
      steps.push(db.prepare(`${source} INSERT INTO telegram_group_share_scopes(receipt_id,card_id,auth_date,auth_id,picked_at)
        SELECT inbox.receipt_id,candidate.card_id,candidate.auth_date,candidate.auth_id,candidate.picked_at
        FROM telegram_inbox AS inbox CROSS JOIN candidate WHERE ${fresh}`)
        .bind(...candidate.bindings, ...key));
      if (event.kind === "handoff") {
        steps.push(db.prepare(`${source} INSERT INTO telegram_private_claim(receipt_id,code_sha256)
          SELECT inbox.receipt_id,candidate.code_sha256 FROM telegram_inbox AS inbox
          JOIN telegram_group_share_scopes AS scope ON scope.receipt_id=inbox.receipt_id
          JOIN candidate ON candidate.card_id=scope.card_id AND candidate.auth_date=scope.auth_date
            AND candidate.auth_id=scope.auth_id AND candidate.picked_at=scope.picked_at
          WHERE inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce=? AND changes()=1`)
          .bind(...candidate.bindings, ...key), db.prepare(`INSERT INTO telegram_outbox(receipt_id)
          SELECT receipt_id FROM telegram_inbox WHERE ${fresh} AND changes()=1`).bind(...key));
      }
    }
    const marker = event.kind === "publish" ? PUBLISH_MARKER : event.kind === "pick" ? PICK_MARKER : TELEGRAM_GROUP_CLAIM_MARKER;
    // A newly accepted inbox row always has its exact durable companion, or the batch rolls back.
    steps.push(db.prepare(`UPDATE telegram_inbox SET receipt_nonce=?,command=CASE WHEN changes()=1 THEN command END
      WHERE ${fresh} RETURNING receipt_id`).bind(marker, ...key));
    const result = await db.batch(steps);
    const final = result.at(-1);
    if (final && result.length === steps.length && result.every(({ success }) => success) && final.results.length <= 1) {
      return final.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // D1 failures return a fixed retryable webhook failure.
  }
  throw new Error(SAFE_ERROR);
}

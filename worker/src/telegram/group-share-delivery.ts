import { validInteger } from "../storage.ts";
import { generalPolicyBindings, generalRecordedOriginSql } from "./general-receipt.ts";
import { generalGroupShareCreatorGuard, generalGroupSharePermission, groupShareCreatorAuthorized, type GeneralGroupSharePin } from "./group-share-actions.ts";
import { TELEGRAM_GENERAL_SHARE_CREATION_MARKER, TELEGRAM_PRIVATE_SHARE_CREATION_MARKER } from "./private-share-creation.ts";
import type { TelegramPolicy } from "./protocol.ts";
import type { TelegramReplyOutcome } from "./store.ts";

const MAX_ATTEMPTS = 4;
const LEASE_SECONDS = 30;
const REAP_LIMIT = 40;
const EXPIRED = 101;

type GroupCardPolicy = TelegramPolicy | GeneralGroupSharePin;
type SendCard = (actorId: string, method: "sendMessage" | "editMessageText", body: Record<string, unknown>) =>
  Promise<TelegramReplyOutcome>;
type Card = {
  receiptId: number;
  actorId: string;
  messageId: number | null;
  attempts: number;
  shown: number;
  expired: number;
  claimCount: number;
  maxClaims: number;
};

function groupChatId(policy: GroupCardPolicy): string {
  return "privateShareCreation" in policy ? policy.groupShare.chatId : policy.groupId;
}

function deliveryOrigin(policy: GroupCardPolicy) {
  return "privateShareCreation" in policy
    ? { sql: `inbox.receipt_nonce='${TELEGRAM_GENERAL_SHARE_CREATION_MARKER}' AND ${generalRecordedOriginSql("inbox")}`,
      bindings: generalPolicyBindings(policy) }
    : { sql: `inbox.receipt_nonce='${TELEGRAM_PRIVATE_SHARE_CREATION_MARKER}'`, bindings: [] };
}

function cardAuthority(policy: GroupCardPolicy, edit: boolean) {
  if ("privateShareCreation" in policy) {
    return edit ? generalGroupSharePermission(policy) : generalGroupShareCreatorGuard(policy, "inbox");
  }
  return { sql: edit ? "creation.actor_id IN (?,?)" : groupShareCreatorAuthorized, bindings: [policy.adminId, policy.memberId] };
}

const cardSource = `FROM telegram_group_share_cards AS card
  JOIN telegram_private_share_creations AS creation ON creation.receipt_id=card.receipt_id AND creation.state='published'
  JOIN telegram_inbox AS inbox ON inbox.receipt_id=creation.receipt_id AND inbox.bot_id=creation.bot_id
    AND inbox.actor_id=creation.actor_id AND inbox.chat_id=creation.actor_id AND inbox.chat_type='private'
    AND inbox.thread_id IS NULL AND inbox.command='help'
    AND inbox.message_date=creation.message_date AND inbox.message_id=creation.message_id
  JOIN telegram_outbox AS origin ON origin.receipt_id=inbox.receipt_id AND origin.state='sent' AND origin.sent_message_id>0
  JOIN private_shares AS share ON share.id=creation.share_id AND share.bot_id=creation.bot_id AND share.sender_id=creation.actor_id
    AND share.payload_id=creation.payload_id AND share.payload_sha256=creation.payload_sha256 AND share.payload_bytes=creation.payload_bytes
    AND share.sender_name=creation.sender_name AND share.max_claims=creation.max_claims AND share.target_user_id IS creation.target_user_id
    AND share.expire_at=share.created_at+60*creation.duration_minutes`;
const cardScope = "creation.bot_id=? AND card.group_id=?";
const claimCount = "(SELECT count(*) FROM private_share_claims WHERE share_id=share.id)";

async function reapCardDelivery(db: D1Database, policy: GroupCardPolicy): Promise<void> {
  const groupId = groupChatId(policy);
  const origin = deliveryOrigin(policy);
  const creator = cardAuthority(policy, false);
  const result = await db.prepare(`UPDATE telegram_group_share_cards SET
    state=CASE WHEN state='sending' THEN 'uncertain' WHEN state='pending' THEN 'failed' ELSE state END,
    attempts=CASE WHEN state='sent' THEN ${MAX_ATTEMPTS} ELSE attempts END,
    lease_id=CASE WHEN state='sending' THEN lease_id ELSE NULL END,
    lease_until=CASE WHEN state='sending' THEN lease_until ELSE NULL END
    WHERE receipt_id IN (SELECT /* subs-bot:telegram-group-share-origin-fence:v1 */ card.receipt_id
      FROM telegram_group_share_cards AS card
      JOIN telegram_private_share_creations AS creation USING(receipt_id)
      JOIN telegram_inbox AS inbox ON inbox.receipt_id=creation.receipt_id AND inbox.bot_id=creation.bot_id
        AND inbox.actor_id=creation.actor_id
      WHERE creation.bot_id=? AND card.group_id=? AND (${origin.sql}) AND (
        (card.state IN ('sending','sent') AND card.lease_until<=unixepoch()) OR
        (card.state='pending' AND (NOT (${creator.sql}) OR EXISTS (SELECT 1 FROM private_shares AS share
          WHERE share.id=creation.share_id AND share.bot_id=creation.bot_id AND share.expire_at<unixepoch())))
      ) ORDER BY card.receipt_id LIMIT ${REAP_LIMIT})`).bind(policy.botId, groupId, ...origin.bindings, ...creator.bindings).run();
  if (!result.success) throw new Error();
}

async function leaseCard(db: D1Database, policy: GroupCardPolicy, leaseId: string, edit: boolean): Promise<Card | null> {
  const groupId = groupChatId(policy);
  const origin = deliveryOrigin(policy);
  // A confirmed card can still display progress for a valid share after the creator loses access.
  const creator = cardAuthority(policy, edit);
  const scope = [policy.botId, groupId, ...origin.bindings, ...creator.bindings];
  const ready = edit ? `card.state='sent' AND card.shown < CASE WHEN share.expire_at<unixepoch() THEN ${EXPIRED} ELSE ${claimCount} END`
    : "card.state='pending' AND share.expire_at>=unixepoch()";
  const [leased, read] = await db.batch<Card | { receiptId: number }>([
    db.prepare(`UPDATE telegram_group_share_cards SET ${edit ? "" : "state='sending',"}
      attempts=attempts+1,lease_id=?,lease_until=unixepoch()+${LEASE_SECONDS}
      WHERE receipt_id=(SELECT card.receipt_id ${cardSource}
        WHERE ${cardScope} AND (${origin.sql}) AND (${creator.sql}) AND ${ready} AND card.attempts<${MAX_ATTEMPTS}
          AND card.due_at<=unixepoch() AND card.lease_id IS NULL
        ORDER BY card.due_at,card.receipt_id LIMIT 1) RETURNING receipt_id AS receiptId`).bind(leaseId, ...scope),
    db.prepare(`SELECT card.receipt_id AS receiptId,creation.actor_id AS actorId,card.message_id AS messageId,
      card.attempts,card.shown,share.expire_at<unixepoch() AS expired,share.max_claims AS maxClaims,${claimCount} AS claimCount
      ${cardSource} WHERE ${cardScope} AND (${origin.sql}) AND (${creator.sql}) AND card.lease_id=? AND card.state='${edit ? "sent" : "sending"}'`)
      .bind(...scope, leaseId),
  ]);
  if (!leased?.success || !read?.success || leased.results.length !== read.results.length || read.results.length > 1) throw new Error();
  const row = read.results[0] as Card | undefined;
  if (!row) return null;
  if (!validInteger(row.receiptId, 1) || row.receiptId !== leased.results[0].receiptId
    || (!("privateShareCreation" in policy) && row.actorId !== policy.adminId && row.actorId !== policy.memberId)
    || (edit ? !validInteger(row.messageId, 1) : row.messageId !== null)
    || !validInteger(row.attempts, 1, MAX_ATTEMPTS) || !validInteger(row.shown, 0, EXPIRED)
    || !validInteger(row.expired, 0, 1) || !validInteger(row.maxClaims, 1, 100)
    || !validInteger(row.claimCount, 0, row.maxClaims)) throw new Error();
  return row;
}

async function settleCard(
  db: D1Database, policy: GroupCardPolicy, row: Card, leaseId: string, shown: number, outcome: TelegramReplyOutcome,
): Promise<void> {
  const edit = row.messageId !== null;
  const groupId = groupChatId(policy);
  const origin = deliveryOrigin(policy);
  const identity = `receipt_id=? AND group_id=? AND attempts=? AND lease_id=? AND message_id IS ? AND shown=?
    AND EXISTS (SELECT 1 FROM telegram_private_share_creations AS creation
      JOIN telegram_inbox AS inbox ON inbox.receipt_id=creation.receipt_id AND inbox.bot_id=creation.bot_id
        AND inbox.actor_id=creation.actor_id
      WHERE creation.receipt_id=telegram_group_share_cards.receipt_id AND creation.bot_id=? AND creation.actor_id=?
        AND (${origin.sql}))`;
  const bindings = [row.receiptId, groupId, row.attempts, leaseId, row.messageId, row.shown, policy.botId, row.actorId,
    ...origin.bindings] as const;
  let write: D1PreparedStatement;
  if (outcome.kind === "sent" && validInteger(outcome.messageId, 1) && (!edit || outcome.messageId === row.messageId)) {
    // A late confirmed publication may settle this exact uncertain attempt.
    write = db.prepare(`UPDATE telegram_group_share_cards SET state='sent',message_id=?,shown=?,attempts=0,due_at=unixepoch(),
      lease_id=NULL,lease_until=NULL WHERE ${identity} AND ${edit ? "state='sent'" : "state IN ('sending','uncertain')"}`)
      .bind(outcome.messageId, shown, ...bindings);
  } else if (outcome.kind === "retry" && validInteger(outcome.delaySeconds, 1, 900) && row.attempts < MAX_ATTEMPTS) {
    write = db.prepare(`UPDATE telegram_group_share_cards SET state='${edit ? "sent" : "pending"}',due_at=unixepoch()+?,
      lease_id=NULL,lease_until=NULL WHERE ${identity} AND state='${edit ? "sent" : "sending"}'`)
      .bind(outcome.delaySeconds, ...bindings);
  } else if (edit) {
    // A delayed ambiguous edit must never be allowed to overtake a newer one.
    write = db.prepare(`UPDATE telegram_group_share_cards SET attempts=${MAX_ATTEMPTS},lease_id=NULL,lease_until=NULL
      WHERE ${identity} AND state='sent'`).bind(...bindings);
  } else {
    const uncertain = outcome.kind === "uncertain" || outcome.kind === "sent";
    write = db.prepare(`UPDATE telegram_group_share_cards SET state='${uncertain ? "uncertain" : "failed"}'
      ${uncertain ? "" : ",lease_id=NULL,lease_until=NULL"} WHERE ${identity} AND state='sending'`).bind(...bindings);
  }
  if (!(await write.run()).success) throw new Error();
}

/** Send one card and update one known card per drain. Group text and buttons contain no private share data. */
export async function drainTelegramGroupShareCards(db: D1Database, policy: GroupCardPolicy, send: SendCard): Promise<void> {
  try {
    await reapCardDelivery(db, policy);
    for (const edit of [false, true]) {
      const leaseId = crypto.randomUUID();
      const row = await leaseCard(db, policy, leaseId, edit);
      if (!row) continue;
      const shown = row.expired === 1 ? EXPIRED : row.claimCount;
      if ((!edit && shown === EXPIRED) || (edit && shown <= row.shown)) {
        await settleCard(db, policy, row, leaseId, row.shown, { kind: "failed" });
        continue;
      }

      const expired = shown === EXPIRED;
      const body = {
        chat_id: groupChatId(policy),
        ...(edit ? { message_id: row.messageId } : {}),
        text: `${expired ? "私密分享已过期。" : "私密分享"}\n领取进度：${row.claimCount}/${row.maxClaims}`,
        link_preview_options: { is_disabled: true },
        reply_markup: { inline_keyboard: expired ? [] : [
          [{ text: "领取", callback_data: "group-share:pick:v1" }],
          [{ text: "打开 Bot 私聊", url: `https://t.me/${policy.botUsername}?start=group` }],
        ] },
      };
      let outcome: TelegramReplyOutcome;
      try {
        outcome = await send(row.actorId, edit ? "editMessageText" : "sendMessage", body);
      } catch {
        outcome = { kind: "uncertain" };
      }
      await settleCard(db, policy, row, leaseId, shown, outcome);
    }
  } catch {
    throw new Error("Telegram group share card delivery could not be confirmed.");
  }
}

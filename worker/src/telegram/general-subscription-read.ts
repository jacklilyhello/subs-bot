import { digestHex, validInteger } from "../storage.ts";
import type { PublicOrigin } from "../public-origin.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL, GENERAL_POLICY_PIN_SQL,
  GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentReceiptSql, generalPolicyBindings,
  prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { SUBSCRIPTION_READ_TICKET, type TelegramSubscriptionReadUpdate } from "./protocol.ts";
import { GENERAL_SUBSCRIPTION_READ_MARKER, prepareTelegramSubscriptionSearchReceipt, renderGeneralSubscriptionFormat, renderGeneralSubscriptionMetadata,
  renderTelegramSearchResults, scanTelegramSubscriptionSearch, type TelegramSubscriptionReadReceipt } from "./subscription-read.ts";

type ReadEvent = Extract<TelegramSubscriptionReadUpdate, { kind: "search" | "callback" }>;
type ReadLease = {
  receiptId: number; actorId: string; chatId: string; chatType: string; threadId: number | null;
  messageId: number; leaseId: string; attempts: number;
};

const freshness = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
const FORMAT_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-private-formats:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=18 AND name='0018_telegram_subscription_reads.sql' AND mode='applied'
    AND sha256='382e9e5e7a850e4f38aece8c2a9f0e98fd890203edf7aa83c37212f5ab038e62')`;
const DETAIL_JOINS = `JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
  JOIN telegram_outbox AS delivered ON delivered.receipt_id=origin.receipt_id
  JOIN telegram_subscription_read AS root ON root.receipt_id=origin.receipt_id
  JOIN json_each(root.matches) AS item
  JOIN subscriptions AS sub ON sub.id=ticket.subscription_id AND sub.owner_id=origin.actor_id
  LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id`;
const DETAIL_SCOPE = `ticket.kind='detail' AND ticket.expires_at>unixepoch() AND root.kind='search' AND root.search_receipt_id IS NULL
    AND delivered.state='sent' AND delivered.attempts=ticket.origin_attempt AND origin.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}'
    AND origin.chat_type='private' AND origin.actor_id=origin.chat_id AND origin.thread_id IS NULL
    AND json_extract(item.value,'$[0]')=ticket.subscription_id
    AND json_extract(item.value,'$[2]')=COALESCE(lifecycle.revision,0)`;
const DETAIL_PROOF = `FROM telegram_subscription_read_ticket AS ticket ${DETAIL_JOINS}
  WHERE (${DETAIL_SCOPE}) AND (${generalCurrentReceiptSql("origin")})`;
// A format ticket inherits the exact lifecycle revision of its confirmed detail's
// consumed search ticket. Expiry of either ancestor closes the entire chain.
function formatProof(condition: string): string {
  return `WITH confirmed_format AS MATERIALIZED (
    SELECT COALESCE(lifecycle.revision,0) AS revision,(${generalCurrentReceiptSql("earlier")}) AS detail_current,
      (${generalCurrentReceiptSql("origin")}) AS search_current
    FROM telegram_subscription_read_ticket AS format_ticket
    JOIN telegram_inbox AS earlier ON earlier.receipt_id=format_ticket.origin_receipt_id
    JOIN telegram_outbox AS format_origin ON format_origin.receipt_id=earlier.receipt_id
    JOIN telegram_subscription_read AS detail ON detail.receipt_id=earlier.receipt_id
    JOIN telegram_subscription_read_ticket AS ticket ON ticket.used_by_receipt_id=earlier.receipt_id
      AND ticket.subscription_id=detail.subscription_id
    ${DETAIL_JOINS}
    WHERE (${FORMAT_SCHEMA}) AND (${DETAIL_SCOPE}) AND (${condition})
      AND (format_ticket.kind='format' AND format_ticket.expires_at>unixepoch()
        AND format_origin.state='sent' AND format_origin.attempts=format_ticket.origin_attempt
        AND earlier.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND earlier.chat_type='private'
        AND earlier.chat_id=earlier.actor_id AND earlier.thread_id IS NULL
        AND detail.kind='detail' AND detail.subscription_id=format_ticket.subscription_id
        AND origin.bot_id=earlier.bot_id AND origin.actor_id=earlier.actor_id)
  ) SELECT revision FROM confirmed_format WHERE detail_current AND search_current`;
}

function eventAuthorization(pin: GeneralTelegramPin, event: ReadEvent) {
  return { sql: `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}
      AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY}`,
  bindings: [...generalPolicyBindings(pin), event.actorId, event.messageDate, event.messageDate, event.updateId, event.updateId] };
}

export async function acceptGeneralTelegramSubscriptionRead(
  db: D1Database, pin: GeneralTelegramPin, event: ReadEvent,
): Promise<boolean> {
  if (!pin.privateManagement || event.actorId === pin.botId || event.chatType !== "private" || event.chatId !== event.actorId
    || event.threadId !== null || (event.kind === "callback" && !SUBSCRIPTION_READ_TICKET.test(event.ticket))) return false;
  try {
    const auth = eventAuthorization(pin, event);
    const key = [pin.botId, event.updateId, crypto.randomUUID()] as const;
    if (event.kind === "search" && !await db.prepare(`SELECT 1 ${auth.sql}`).bind(...auth.bindings).first()) return false;
    const scan = event.kind === "search" ? await scanTelegramSubscriptionSearch(db, event.actorId, event.query, true) : null;
    const digest = event.kind === "callback"
      ? digestHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(event.ticket))) : null;
    // Pick only the query shape here. The selected proof rechecks the exact
    // ticket and current authority inside the same write as its consumption.
    const kind = digest !== null && pin.privateFormats ? await db.prepare(`SELECT kind FROM telegram_subscription_read_ticket
      WHERE token_sha256=? AND used_by_receipt_id IS NULL`).bind(digest).first<string>("kind") : "detail";
    if (kind !== "detail" && kind !== "format") return false;
    const format = kind === "format";
    const proof = digest === null ? "" : format ? `AND EXISTS (${formatProof(`format_ticket.token_sha256=?
      AND format_ticket.used_by_receipt_id IS NULL AND earlier.bot_id=? AND earlier.actor_id=?
      AND format_origin.sent_message_id=? AND ?>=earlier.message_date`)})` : `AND EXISTS (SELECT 1 ${DETAIL_PROOF}
      AND ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND origin.bot_id=policy.bot_id
      AND origin.actor_id=actor.actor_id AND delivered.sent_message_id=? AND ?>=origin.message_date)`;
    const proofBindings = digest === null ? [] : format
      ? [...generalPolicyBindings(pin), ...generalPolicyBindings(pin), digest, pin.botId, event.actorId, event.messageId, event.messageDate]
      : [...generalPolicyBindings(pin), digest, event.messageId, event.messageDate];
    const steps = [
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',? ${auth.sql}
        ${proof}
        ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(event.updateId, event.messageId, event.messageDate, key[2], ...auth.bindings,
        ...proofBindings),
      prepareGeneralReceiptAuthority(db, pin, key),
    ];
    if (scan) steps.push(prepareTelegramSubscriptionSearchReceipt(db, key, scan));
    else {
      steps.push(
        db.prepare(`UPDATE telegram_subscription_read_ticket AS ticket SET used_by_receipt_id=incoming.receipt_id
          FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${freshness}`)
          .bind(digest, ...key),
        db.prepare(`INSERT INTO telegram_subscription_read (receipt_id,kind,subscription_id,format,auth_message_date,auth_message_id)
          SELECT incoming.receipt_id,ticket.kind,ticket.subscription_id,ticket.format,0,0
          FROM telegram_inbox AS incoming JOIN telegram_subscription_read_ticket AS ticket ON ticket.used_by_receipt_id=incoming.receipt_id
          WHERE ${freshness}`).bind(...key),
      );
    }
    steps.push(
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${freshness}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}',command=CASE WHEN
        EXISTS (SELECT 1 FROM telegram_subscription_read AS detail JOIN telegram_outbox AS reply USING (receipt_id)
          WHERE detail.receipt_id=incoming.receipt_id AND detail.kind${format ? "=" : "<>"}'format')
        AND ${generalCurrentReceiptSql("incoming")} THEN command END WHERE ${freshness} RETURNING receipt_id`)
        .bind(...generalPolicyBindings(pin), ...key),
    );
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && results.every(({ success }) => success) && receipt.results.length <= 1) {
      return receipt.results.length === 1;
    }
  } catch {
    // Binding diagnostics can include private data.
  }
  throw new Error("General Telegram subscription read could not be confirmed.");
}

export async function renderGeneralSubscriptionRead(
  db: D1Database, pin: GeneralTelegramPin, lease: ReadLease, bucket: R2Bucket, publicOrigin: PublicOrigin,
): Promise<Awaited<ReturnType<typeof renderTelegramSearchResults>> | null> {
  const guard = { sql: `inbox.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND ${generalCurrentReceiptSql("inbox")}`,
    bindings: generalPolicyBindings(pin) };
  const row = await db.prepare(`SELECT detail.kind,detail.subscription_id AS subscriptionId,detail.format,
      detail.search_receipt_id AS searchReceiptId,detail.search_offset AS searchOffset
    FROM telegram_inbox AS inbox JOIN telegram_subscription_read AS detail USING (receipt_id)
    JOIN telegram_outbox AS reply USING (receipt_id)
    WHERE inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.message_id=? AND inbox.chat_id=inbox.actor_id
      AND inbox.chat_type='private' AND inbox.thread_id IS NULL AND reply.state='leased'
      AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch() AND ${guard.sql}`)
    .bind(lease.receiptId, pin.botId, lease.actorId, lease.messageId, lease.leaseId, lease.attempts, ...guard.bindings)
    .first<TelegramSubscriptionReadReceipt>();
  if (!row) return null;
  if (row.kind === "format" && row.subscriptionId !== null && row.format !== null) {
    if (!pin.privateFormats) return { text: "此格式的订阅链接暂不可用。", readGuard: guard };
    const chain = `format_ticket.subscription_id=? AND format_ticket.format=?`;
    const bindings = [...generalPolicyBindings(pin), ...generalPolicyBindings(pin), row.subscriptionId, row.format];
    const revision = await db.prepare(formatProof(`${chain} AND format_ticket.used_by_receipt_id=?
      AND earlier.bot_id=? AND earlier.actor_id=? AND format_origin.sent_message_id=?`))
      .bind(...bindings, lease.receiptId, pin.botId, lease.actorId, lease.messageId).first<number>("revision");
    if (!validInteger(revision, 0)) return { text: "订阅或授权状态已变更，请重新查询。", readGuard: guard };
    return renderGeneralSubscriptionFormat(db, bucket, lease.actorId, row.subscriptionId, revision, row.format, {
      sql: `CASE WHEN (${guard.sql}) IS NOT TRUE THEN 0
        WHEN EXISTS (${formatProof(`${chain} AND format_ticket.used_by_receipt_id=inbox.receipt_id
          AND earlier.bot_id=inbox.bot_id AND earlier.actor_id=inbox.actor_id AND format_origin.sent_message_id=inbox.message_id`)})
        THEN 1 ELSE 0 END`,
      bindings: [...guard.bindings, ...bindings],
    }, publicOrigin);
  }
  if (row.kind === "search" && row.searchReceiptId === null && row.searchOffset === 0) {
    return renderTelegramSearchResults(db, pin, lease, row, guard, true);
  }
  if (row.kind === "detail" && row.subscriptionId !== null) {
    const proof = `SELECT COALESCE(lifecycle.revision,0) AS revision ${DETAIL_PROOF}
      AND ticket.subscription_id=? AND ticket.used_by_receipt_id=? AND origin.bot_id=? AND origin.actor_id=?`;
    const revision = await db.prepare(proof).bind(...generalPolicyBindings(pin), row.subscriptionId,
      lease.receiptId, pin.botId, lease.actorId).first<number>("revision");
    if (!validInteger(revision, 0)) return { text: "订阅不存在或已被更改。", readGuard: guard };
    const formats = pin.privateFormats && Boolean(await db.prepare(`SELECT 1 WHERE ${FORMAT_SCHEMA}`).first());
    return renderGeneralSubscriptionMetadata(db, lease.actorId, row.subscriptionId, revision, {
      sql: `CASE WHEN (${guard.sql}) IS NOT TRUE THEN 0
        WHEN EXISTS (SELECT 1 ${DETAIL_PROOF} AND ticket.subscription_id=?
          AND ticket.used_by_receipt_id=inbox.receipt_id AND origin.bot_id=inbox.bot_id AND origin.actor_id=inbox.actor_id)
        THEN 1 ELSE 0 END`,
      bindings: [...guard.bindings, ...generalPolicyBindings(pin), row.subscriptionId],
    }, formats);
  }
  const text = row.kind === "usage" ? "用法：/s 名称关键词"
    : row.kind === "limit" ? "查询达到处理上限，请缩短关键词或从 /list 选择订阅。"
    : "订阅或授权状态已变更，请重新查询。";
  return { text, readGuard: guard };
}

import { MAX_PATH_RULES } from "../path-rules.ts";
import { digestHex, SUBSCRIPTION_LIFECYCLE_REVISION } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, approvedGroup, generalCurrentReceiptSql,
  generalPolicyBindings, groupSchemaReady, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { GENERAL_SUBSCRIPTION_READ_MARKER, type GeneralBrowsingUpdate, type TelegramEventScope } from "./protocol.ts";
import type { TelegramView } from "./views.ts";

export const GENERAL_VIEW_MARKER = "general-view:v1";
export const GENERAL_NUMBER_MARKER = "general-number-detail:v1";
export const GENERAL_NODE_MARKER = "general-subnodes:v1";
export const GENERAL_RAW_FILE_MARKER = "general-subrawfile:v1";
export const GENERAL_BROWSING_SCHEMA = `EXISTS (SELECT 1 FROM subs_bot_schema_migrations
  WHERE position=54 AND name='0054_telegram_general_subscription_anchors.sql' AND mode='applied'
    AND sha256='e2a46ff9769a9fd5081b8d622b876af6ea65a0aad6cfb78257bb27db000be81d')`;
const FRESH = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
type Guard = { sql: string; bindings: readonly (string | number | null)[] };
const NODE_FIELDS = "subscription_id,generation,lifecycle_revision,snapshot_id,manifest_sha256,node_count,page_offset";
const RAW_FIELDS = "subscription_id,generation,lifecycle_revision,snapshot_id,manifest_sha256,node_count";

export function generalBrowsingAuthorization(pin: GeneralTelegramPin, event: TelegramEventScope): Guard {
  return { sql: `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND (${GENERAL_BROWSING_SCHEMA})
      AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      ${event.chatType === "private" ? "" : `AND ${approvedGroup()}`}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY}`,
  bindings: [...generalPolicyBindings(pin), event.actorId, ...(event.chatType === "private" ? [] : [event.chatId, event.chatType]),
    event.messageDate, event.messageDate, event.updateId, event.updateId] };
}

export function generalBrowsingGuard(pin: GeneralTelegramPin, marker: string, group = false): Guard {
  return { sql: `inbox.receipt_nonce=? AND (${GENERAL_BROWSING_SCHEMA})
    AND ${generalCurrentReceiptSql("inbox", group ? approvedGroup("inbox") : "1")}`,
  bindings: [marker, ...generalPolicyBindings(pin)] };
}

/** Each receipt family has its own persisted business row and explicit marker. */
export function generalBrowsingFamily(alias: "inbox" | "earlier", group: boolean): string {
  const privateScope = `${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL`;
  return `(${GENERAL_BROWSING_SCHEMA}) AND (
    (${alias}.receipt_nonce='${GENERAL_VIEW_MARKER}' AND ${alias}.command='list'
      AND (${privateScope}${group ? ` OR ${alias}.chat_type IN ('group','supergroup')` : ""})
      AND EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id=${alias}.receipt_id))
    OR (${privateScope} AND ${alias}.command='help' AND (
      (${alias}.receipt_nonce='${GENERAL_NUMBER_MARKER}' AND EXISTS (
        SELECT 1 FROM telegram_subscription_read WHERE receipt_id=${alias}.receipt_id AND kind IN ('detail','missing')))
      OR (${alias}.receipt_nonce='${GENERAL_NODE_MARKER}' AND EXISTS (
        SELECT 1 FROM telegram_subscription_node_page WHERE receipt_id=${alias}.receipt_id))
      OR (${alias}.receipt_nonce='${GENERAL_RAW_FILE_MARKER}' AND EXISTS (
        SELECT 1 FROM telegram_subscription_raw_file WHERE receipt_id=${alias}.receipt_id)))))`;
}

export async function acceptGeneralBrowsing(
  db: D1Database, pin: GeneralTelegramPin, input: GeneralBrowsingUpdate,
): Promise<boolean> {
  const event = input.event;
  if (!pin.privateBrowsing || !pin.privateManagement || pin.rehearsal || event.actorId === pin.botId
    || (event.chatType === "private" ? event.chatId !== event.actorId || event.threadId !== null
      : input.family !== "view" || !await groupSchemaReady(db))) return false;
  const auth = generalBrowsingAuthorization(pin, event);
  const key = [pin.botId, event.updateId, crypto.randomUUID()] as const;
  const callback = "ticket" in event;
  const digest = callback ? digestHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(event.ticket))) : null;
  let proof = "", args: (string | number | null)[] = [], marker = GENERAL_VIEW_MARKER;
  let inventory: string | null = null;
  const scope = `origin.bot_id=policy.bot_id AND origin.actor_id=actor.actor_id AND origin.chat_id=? AND origin.chat_type=?
    AND origin.thread_id IS ? AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt
    AND ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
    AND ?>=origin.message_date AND ${generalCurrentReceiptSql("origin")}`;
  const scopeArgs = [event.chatId, event.chatType, event.threadId, event.messageId, digest, event.messageDate,
    ...generalPolicyBindings(pin)];
  let origin = "";
  if (input.family === "view" && callback) {
    origin = `FROM telegram_view_ticket AS ticket JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
      JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id JOIN telegram_view AS view ON view.receipt_id=origin.receipt_id`;
    proof = `AND EXISTS (SELECT 1 ${origin} WHERE ${scope} AND origin.receipt_nonce='${GENERAL_VIEW_MARKER}')`;
    args = scopeArgs;
  } else if (input.family === "nodes" || input.family === "file") {
    marker = input.family === "nodes" ? GENERAL_NODE_MARKER : GENERAL_RAW_FILE_MARKER;
    const node = input.family === "nodes";
    const table = node ? "telegram_subscription_node_ticket" : "telegram_subscription_raw_file_ticket";
    origin = `FROM ${table} AS ticket JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
      JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
      LEFT JOIN telegram_subscription_read AS detail ON detail.receipt_id=origin.receipt_id
        AND origin.receipt_nonce IN ('${GENERAL_SUBSCRIPTION_READ_MARKER}','${GENERAL_NUMBER_MARKER}') AND detail.kind='detail'
      ${node ? `LEFT JOIN telegram_subscription_node_page AS page ON page.receipt_id=origin.receipt_id
        AND origin.receipt_nonce='${GENERAL_NODE_MARKER}'` : ""}
      JOIN subscriptions AS sub ON sub.id=ticket.subscription_id AND sub.owner_id=origin.actor_id
        AND sub.generation=ticket.generation AND ${SUBSCRIPTION_LIFECYCLE_REVISION.replaceAll("subscriptions.", "sub.")}=ticket.lifecycle_revision
        AND sub.snapshot_id=ticket.snapshot_id AND sub.manifest_sha256=ticket.manifest_sha256 AND sub.node_count=ticket.node_count`;
    proof = `AND EXISTS (SELECT 1 ${origin} WHERE ${scope} AND origin.chat_type='private'
      AND origin.chat_id=origin.actor_id AND origin.thread_id IS NULL AND (
        (detail.subscription_id=ticket.subscription_id ${node ? "AND ticket.page_offset=0" : `AND ticket.actor_role=(SELECT actor_role FROM telegram_general_receipt WHERE receipt_id=origin.receipt_id)`})
        ${node ? `OR (page.subscription_id=ticket.subscription_id AND page.generation=ticket.generation
          AND page.lifecycle_revision=ticket.lifecycle_revision AND page.snapshot_id=ticket.snapshot_id
          AND page.manifest_sha256=ticket.manifest_sha256 AND page.node_count=ticket.node_count
          AND abs(page.page_offset-ticket.page_offset)=15)` : ""}))`;
    args = scopeArgs;
    if (!node) {
      // Capture the exact rule inventory and recheck it in the admission write.
      const row = await db.prepare(`SELECT (SELECT json_group_array(json_array(id,keyword,remark)) FROM (
        SELECT id,keyword,remark FROM path_rules WHERE owner_id=actor.actor_id ORDER BY id LIMIT ${MAX_PATH_RULES + 1})) AS rules
        ${auth.sql} ${proof}`).bind(...auth.bindings, ...args).first<string>("rules");
      if (row === null) return false;
      inventory = row;
      proof += ` AND (SELECT json_group_array(json_array(id,keyword,remark)) FROM (
        SELECT id,keyword,remark FROM path_rules WHERE owner_id=actor.actor_id ORDER BY id LIMIT ${MAX_PATH_RULES + 1}))=?`;
      args.push(inventory);
    }
  }
  try {
    const steps = [db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,?,?,?,?,?, ?,? ${auth.sql} ${proof}
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(event.updateId, event.chatId, event.chatType,
      event.messageId, event.messageDate, event.threadId, input.family === "view" ? "list" : "help", key[2], ...auth.bindings, ...args),
    prepareGeneralReceiptAuthority(db, pin, key)];
    if (input.family === "view") {
      if (callback) steps.push(db.prepare(`UPDATE telegram_view_ticket AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${FRESH}`).bind(digest, ...key));
      steps.push(callback ? db.prepare(`INSERT INTO telegram_view (receipt_id,kind,after_id,after_epoch)
        SELECT incoming.receipt_id,view.kind,ticket.after_id,ticket.after_epoch FROM telegram_inbox AS incoming
        JOIN telegram_view_ticket AS ticket ON ticket.used_by_receipt_id=incoming.receipt_id
        JOIN telegram_view AS view ON view.receipt_id=ticket.origin_receipt_id WHERE ${FRESH}`).bind(...key)
        : db.prepare(`INSERT INTO telegram_view (receipt_id,kind) SELECT incoming.receipt_id,? FROM telegram_inbox AS incoming
          WHERE ${FRESH}`).bind(input.event.kind, ...key));
    } else {
      const node = input.family === "nodes", table = node ? "telegram_subscription_node_ticket" : "telegram_subscription_raw_file_ticket";
      steps.push(db.prepare(`UPDATE ${table} AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${FRESH}`).bind(digest, ...key));
      const fields = node ? NODE_FIELDS : RAW_FIELDS;
      const hash = inventory === null ? null : digestHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(inventory)));
      steps.push(db.prepare(`INSERT INTO ${node ? "telegram_subscription_node_page" : "telegram_subscription_raw_file"}
        (receipt_id,${fields},${node ? "" : "rules_sha256,actor_role,"}auth_message_date,auth_message_id)
        SELECT incoming.receipt_id,${fields.split(",").map((field) => `ticket.${field}`).join(",")},
          ${node ? "" : "?,ticket.actor_role,"}0,0 FROM telegram_inbox AS incoming JOIN ${table} AS ticket
          ON ticket.used_by_receipt_id=incoming.receipt_id WHERE ${FRESH}`).bind(...(node ? [] : [hash]), ...key));
    }
    steps.push(db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT incoming.receipt_id FROM telegram_inbox AS incoming
      WHERE ${FRESH}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?,command=CASE WHEN
      EXISTS (SELECT 1 FROM telegram_general_receipt WHERE receipt_id=incoming.receipt_id)
      AND EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=incoming.receipt_id)
      AND ${generalCurrentReceiptSql("incoming", event.chatType === "private" ? "1" : approvedGroup("incoming"))}
      THEN command END WHERE ${FRESH} RETURNING receipt_id`).bind(marker, ...generalPolicyBindings(pin), ...key));
    const results = await db.batch(steps);
    if (results.length === steps.length && results.every(({ success }) => success) && results.at(-1)!.results.length <= 1)
      return results.at(-1)!.results.length === 1;
  } catch { /* D1 diagnostics may contain private ticket values. */ }
  throw new Error("General Telegram browsing admission could not be confirmed.");
}

export async function readGeneralView(db: D1Database, receiptId: number): Promise<TelegramView | null> {
  return db.prepare("SELECT kind,after_id AS afterId,after_epoch AS afterEpoch FROM telegram_view WHERE receipt_id=?")
    .bind(receiptId).first<TelegramView>();
}

export function generalViewAnchorGuard(targets: readonly { subscriptionId: number; lifecycleRevision: number }[]): Guard {
  return { sql: `NOT EXISTS (SELECT 1 FROM json_each(?) AS expected LEFT JOIN subscriptions AS sub
    ON sub.id=json_extract(expected.value,'$[0]') AND sub.owner_id=inbox.actor_id
    LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
    WHERE sub.id IS NULL OR COALESCE(lifecycle.revision,0)<>json_extract(expected.value,'$[1]'))`,
  bindings: [JSON.stringify(targets.map(({ subscriptionId, lifecycleRevision }) => [subscriptionId, lifecycleRevision]))] };
}

export function insertGeneralViewAnchors(
  db: D1Database, receiptId: number, leaseId: string, attempts: number,
  targets: readonly { subscriptionId: number; lifecycleRevision: number }[], previousChanges: number,
): D1PreparedStatement {
  return db.prepare(`WITH targets (id,revision) AS (VALUES ${targets.map(() => "(?,?)").join(",")})
    INSERT INTO telegram_general_subscription_anchor (receipt_id,subscription_id,kind,lifecycle_revision)
    SELECT inbox.receipt_id,targets.id,'view',targets.revision FROM telegram_inbox AS inbox
    JOIN telegram_outbox AS reply USING(receipt_id) CROSS JOIN targets
    WHERE changes()=? AND inbox.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'
      AND inbox.receipt_nonce='${GENERAL_VIEW_MARKER}' AND inbox.chat_type='private'
      AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL
    ON CONFLICT(receipt_id,subscription_id) DO UPDATE SET lifecycle_revision=excluded.lifecycle_revision
      WHERE telegram_general_subscription_anchor.kind='view'`)
    .bind(...targets.flatMap(({ subscriptionId, lifecycleRevision }) => [subscriptionId, lifecycleRevision]),
      previousChanges, receiptId, leaseId, attempts);
}

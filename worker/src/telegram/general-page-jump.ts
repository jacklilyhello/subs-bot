import { validInteger } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_BROWSING_SCHEMA, GENERAL_VIEW_MARKER, generalBrowsingAuthorization } from "./general-browsing.ts";
import { generalCurrentReceiptSql, generalPolicyBindings, prepareGeneralReceiptAuthority, approvedGroup, groupSchemaReady } from "./general-receipt.ts";
import { TELEGRAM_PAGE_JUMP_SCHEMA } from "./page-jump.ts";
import type { TelegramPageJumpUpdate } from "./protocol.ts";
import { TELEGRAM_VIEW_PAGE_SIZE } from "./views.ts";

export const GENERAL_PAGE_JUMP_MARKER = "general-view-jump:v1";
const TTL_SECONDS = 600;
const MAX_ROWS = 20_000;
const MAX_PAGE = Math.ceil(MAX_ROWS / TELEGRAM_VIEW_PAGE_SIZE);
const SCHEMA = `(${GENERAL_BROWSING_SCHEMA}) AND (${TELEGRAM_PAGE_JUMP_SCHEMA})`;
type Guard = { sql: string; bindings: readonly (string | number | null)[] };
const FRESH = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";

export async function telegramGeneralPageJumpReady(db: D1Database): Promise<boolean> {
  try { return await db.prepare(`SELECT (${SCHEMA}) AS ready`).first<number>("ready") === 1; }
  catch { return false; }
}

/** Supersession is confined to the same recorded general actor and policy identity. */
function newerPrompt(alias: "inbox" | "origin" | "earlier"): string {
  return `EXISTS (SELECT 1 FROM telegram_inbox AS pick JOIN telegram_page_jumps AS newer USING(receipt_id)
    JOIN telegram_general_receipt AS picked USING(receipt_id)
    JOIN telegram_general_receipt AS prior ON prior.receipt_id=${alias}.receipt_id
    WHERE pick.bot_id=${alias}.bot_id AND pick.actor_id=${alias}.actor_id AND pick.chat_id=${alias}.chat_id
      AND pick.chat_type=${alias}.chat_type AND pick.thread_id IS ${alias}.thread_id
      AND pick.update_id>${alias}.update_id AND pick.receipt_nonce='${GENERAL_PAGE_JUMP_MARKER}' AND newer.kind='prompt'
      AND (picked.generation,picked.actor_revision,picked.actor_role,picked.release_revision,picked.activation_sha256,picked.cutover_at)
        =(prior.generation,prior.actor_revision,prior.actor_role,prior.release_revision,prior.activation_sha256,prior.cutover_at))`;
}

export function generalPageJumpFamily(alias: "inbox" | "earlier", group: boolean): string {
  return `(${SCHEMA}) AND ${alias}.command='help'
    AND ((${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL)
      ${group ? `OR (${alias}.chat_type IN ('group','supergroup') AND (${alias}.chat_type='supergroup' OR ${alias}.thread_id IS NULL))` : ""})
    AND EXISTS (SELECT 1 FROM telegram_page_jumps WHERE receipt_id=${alias}.receipt_id AND kind<>'page')`;
}

/** Closing admission cancels unsent prompts; already accepted notices and pages can drain. */
export function generalPageJumpEligibility(alias: "inbox" | "earlier", enabled: boolean): string {
  return `(${SCHEMA}) AND EXISTS (SELECT 1 FROM telegram_page_jumps AS jump
    WHERE jump.receipt_id=${alias}.receipt_id AND jump.expires_at>unixepoch()
      AND (jump.kind<>'prompt' OR (${enabled ? 1 : 0}=1 AND NOT ${newerPrompt(alias)})))`;
}

function source(pin: GeneralTelegramPin, event: TelegramPageJumpUpdate): Guard {
  const scope = `origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type=?
    AND origin.thread_id IS ? AND origin.update_id<? AND reply.state='sent' AND reply.sent_message_id=?
    AND NOT EXISTS (SELECT 1 FROM telegram_page_jumps WHERE origin_receipt_id=origin.receipt_id)
    AND (${generalCurrentReceiptSql("origin")})`;
  const bindings = [pin.botId, event.actorId, event.chatId, event.chatType, event.threadId, event.updateId,
    event.kind === "open" ? event.messageId : event.promptMessageId, ...generalPolicyBindings(pin)];
  const origin = event.kind === "open"
    ? `JOIN telegram_view AS view USING(receipt_id)
      LEFT JOIN telegram_page_jumps AS prior USING(receipt_id)
      WHERE ${scope} AND origin.receipt_nonce='${GENERAL_VIEW_MARKER}' AND view.kind='list'
        AND (prior.receipt_id IS NULL OR prior.kind='page')`
    : `JOIN telegram_page_jumps AS prompt USING(receipt_id)
      WHERE ${scope} AND origin.receipt_nonce='${GENERAL_PAGE_JUMP_MARKER}' AND prompt.kind='prompt'
        AND prompt.expires_at>unixepoch() AND NOT ${newerPrompt("origin")}`;
  return { sql: `SELECT origin.receipt_id,recorded.actor_role
    FROM telegram_inbox AS origin JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_general_receipt AS recorded USING(receipt_id) ${origin}`, bindings };
}

/** A genuine general list opens one prompt; only its exact sent reply can select a page. */
export async function acceptGeneralPageJump(
  db: D1Database, pin: GeneralTelegramPin, event: TelegramPageJumpUpdate,
): Promise<boolean> {
  if (!pin.privatePageJump || !pin.privateBrowsing || !pin.privateManagement || !pin.sharedOutbox || pin.rehearsal
    || event.actorId === pin.botId || (event.chatType === "private" ? event.chatId !== event.actorId || event.threadId !== null
      : !await groupSchemaReady(db)) || event.kind === "reply" && event.page !== null && !validInteger(event.page, 1)
    || !await telegramGeneralPageJumpReady(db)) return false;
  const authority = generalBrowsingAuthorization(pin, event);
  const origin = source(pin, event);
  const key = [pin.botId, event.updateId, crypto.randomUUID()] as const;
  const requested = event.kind === "reply" && !event.cancelled ? event.page : null;
  const fixed = event.kind === "open" ? "prompt" : event.cancelled ? "cancelled" : "invalid";
  const offset = requested === null ? 0 : (Math.min(MAX_PAGE + 1, requested) - 1) * TELEGRAM_VIEW_PAGE_SIZE - 1;
  const result = requested === null ? "SELECT ? AS kind,NULL AS maximum" : `SELECT
    CASE WHEN tally>${MAX_ROWS} THEN 'limit' WHEN ?>maximum THEN 'range' ELSE 'page' END AS kind,
    CASE WHEN tally<=${MAX_ROWS} AND ?>maximum THEN maximum END AS maximum FROM (
      SELECT count(*) AS tally,max(1,(count(*)+${TELEGRAM_VIEW_PAGE_SIZE - 1})/${TELEGRAM_VIEW_PAGE_SIZE}) AS maximum
      FROM (SELECT id FROM subscriptions WHERE owner_id=? ORDER BY id LIMIT ?))`;
  const resultBindings = requested === null ? [fixed] : [requested, requested, event.actorId, offset + 2];
  try {
    const steps = [
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT policy.bot_id,?,actor.actor_id,?,?,?,?,?,'help',? ${authority.sql}
          AND (${SCHEMA}) AND EXISTS (${origin.sql}) ON CONFLICT(bot_id,update_id) DO NOTHING`)
        .bind(event.updateId, event.chatId, event.chatType, event.messageId, event.messageDate, event.threadId, key[2],
          ...authority.bindings, ...origin.bindings),
      prepareGeneralReceiptAuthority(db, pin, key),
      db.prepare(`INSERT INTO telegram_page_jumps
        (receipt_id,origin_receipt_id,kind,max_page,actor_role,auth_message_date,auth_message_id,expires_at)
        SELECT incoming.receipt_id,source.receipt_id,result.kind,result.maximum,source.actor_role,0,0,unixepoch()+${TTL_SECONDS}
        FROM telegram_inbox AS incoming CROSS JOIN (${origin.sql}) AS source CROSS JOIN (${result}) AS result WHERE ${FRESH}`)
        .bind(...origin.bindings, ...resultBindings, ...key),
      db.prepare(`INSERT INTO telegram_view (receipt_id,kind,after_id)
        SELECT incoming.receipt_id,'list',CASE WHEN ?>=0 THEN (
          SELECT id FROM subscriptions WHERE owner_id=incoming.actor_id ORDER BY id LIMIT 1 OFFSET ?)
          END FROM telegram_inbox AS incoming JOIN telegram_page_jumps AS jump USING(receipt_id)
        WHERE ${FRESH} AND jump.kind='page'`).bind(offset, Math.max(0, offset), ...key),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT incoming.receipt_id
        FROM telegram_inbox AS incoming JOIN telegram_page_jumps USING(receipt_id) WHERE ${FRESH}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET
        receipt_nonce=CASE WHEN EXISTS (SELECT 1 FROM telegram_page_jumps WHERE receipt_id=incoming.receipt_id AND kind='page')
          THEN '${GENERAL_VIEW_MARKER}' ELSE '${GENERAL_PAGE_JUMP_MARKER}' END,
        command=(SELECT CASE WHEN jump.kind='page' THEN 'list' ELSE 'help' END FROM telegram_page_jumps AS jump
          WHERE jump.receipt_id=incoming.receipt_id AND EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=incoming.receipt_id)
          AND (jump.kind<>'page' OR EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id=incoming.receipt_id
            AND (?<0 OR after_id IS NOT NULL))) AND (${SCHEMA})
          AND (${generalCurrentReceiptSql("incoming", event.chatType === "private" ? "1" : approvedGroup("incoming"))}))
        WHERE ${FRESH} RETURNING receipt_id`).bind(offset, ...generalPolicyBindings(pin), ...key),
    ];
    const rows = await db.batch(steps);
    if (rows.length === steps.length && rows.every(({ success }) => success) && rows.at(-1)!.results.length <= 1)
      return rows.at(-1)!.results.length === 1;
  } catch {
    // Neither raw reply text nor SQL parameters leave the admission boundary.
  }
  throw new Error("General Telegram page jump could not be confirmed.");
}

import { MAX_AGGREGATE_MEMBERS } from "../aggregate.ts";
import { MAX_PATH_RULES } from "../path-rules.ts";
import { digestHex, MAX_SNAPSHOT_NODES, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { TELEGRAM_AGGREGATE_ORIGIN } from "./aggregate-actions.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentAuthoritySql,
  generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { inTelegramScope, type TelegramPolicy, type TelegramSelectedUpdate } from "./protocol.ts";
import { selectedQuery, unicode14Lower } from "./selected-search.ts";

export const TELEGRAM_SELECTED_MARKER = "selected:v1";
export const GENERAL_TELEGRAM_SELECTED_MARKER = "general-selected:v1";
export const GENERAL_SELECTED_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-private-selected:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=17 AND name='0017_telegram_selected_export.sql' AND mode='applied'
    AND sha256='821a0426a55249aeded0e0bd604e2362bac42231a9447f68db353d12ba27111c')`;
export const MAX_SELECTED_LINKS = 32;
const MAX_SCAN_ROWS = 512;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const MAX_INVENTORY_BYTES = 1024 * 1024;
const PAGE_SIZE = 16;
const TICKET_SECONDS = 600;
const encoder = new TextEncoder();
const DIGEST = /^[a-f0-9]{64}(?![\s\S])/u;
const NONCE = /^[A-Za-z0-9_-]{22}(?![\s\S])/u;
const REVOKE_TICKET = /^sbo1_[A-Za-z0-9_-]{22}(?![\s\S])/u;
const fresh = "inbox.bot_id = ? AND inbox.update_id = ? AND inbox.receipt_nonce = ?";

export interface TelegramSelectedReply {
  result: "issued" | "nomatch" | "empty" | "limit" | "stale" | "revoked" | "already-revoked";
  codeSha256: string | null;
}

interface SearchRow { id: number; revision: number; name: string; sourceUrl: string }
interface Selection { inventory: string; ids: string; limited: boolean }

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

async function hash(value: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(value)));
}

async function deriveCode(key: CryptoKey, botId: string, actorId: string, nonce: string, ids: string): Promise<string> {
  const input = encoder.encode(JSON.stringify([
    "subs-bot/telegram-aggregate/selected", 1, TELEGRAM_AGGREGATE_ORIGIN, botId, actorId, nonce, ids,
  ]));
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, input)).subarray(0, 16));
}

async function scanSelection(db: D1Database, ownerId: string, query: string): Promise<Selection> {
  const needle = selectedQuery(query);
  const inventory: number[][] = [];
  const ids: number[] = [];
  let bytes = 0;
  let after = 0;
  const deadline = Date.now() + 5000;
  if (needle === null) return { inventory: "[]", ids: "[]", limited: true };
  for (;;) {
    if (Date.now() >= deadline) return { inventory: "[]", ids: "[]", limited: true };
    const page = await db.prepare(`SELECT id, name, source_url AS sourceUrl, ${SUBSCRIPTION_LIFECYCLE_REVISION} AS revision
      FROM subscriptions WHERE owner_id = ? AND id > ? ORDER BY id LIMIT ${PAGE_SIZE}
    `).bind(ownerId, after).all<SearchRow>();
    if (!page.success) throw new Error("Selected export inventory could not be read.");
    for (const row of page.results) {
      if (!validInteger(row.id, after + 1) || !validInteger(row.revision, 0) || typeof row.name !== "string"
        || typeof row.sourceUrl !== "string") throw new Error("Selected export inventory is invalid.");
      after = row.id;
      bytes += encoder.encode(row.name).byteLength + encoder.encode(row.sourceUrl).byteLength;
      if (inventory.length === MAX_SCAN_ROWS || bytes > MAX_SCAN_BYTES || Date.now() >= deadline) {
        return { inventory: "[]", ids: "[]", limited: true };
      }
      inventory.push([row.id, row.revision]);
      if (unicode14Lower(`${row.name} ${row.sourceUrl}`).includes(needle)) ids.push(row.id);
      if (ids.length > MAX_AGGREGATE_MEMBERS) return { inventory: "[]", ids: "[]", limited: true };
    }
    if (page.results.length < PAGE_SIZE) break;
  }
  const serialized = JSON.stringify(inventory);
  return encoder.encode(serialized).byteLength > MAX_INVENTORY_BYTES
    ? { inventory: "[]", ids: "[]", limited: true } : { inventory: serialized, ids: JSON.stringify(ids), limited: false };
}

const authEpoch = "CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_date, 0) END";
type SelectedPolicy = TelegramPolicy | GeneralTelegramPin;
type SelectedGuard = { sql: string; bindings: readonly (string | number)[] };

function selectedMarker(policy: SelectedPolicy): string {
  return "adminId" in policy ? TELEGRAM_SELECTED_MARKER : GENERAL_TELEGRAM_SELECTED_MARKER;
}

function generalSelectedAdmission(pin: GeneralTelegramPin, event: TelegramSelectedUpdate): SelectedGuard {
  return { sql: `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE (${GENERAL_POLICY_PIN_SQL}) AND (${GENERAL_RECEIPT_SCHEMA}) AND (${GENERAL_SELECTED_SCHEMA})
      AND (policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}) AND (actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL})
      AND (?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+30)
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND (${GENERAL_ACTOR_QUEUE_CAPACITY})`,
  bindings: [...generalPolicyBindings(pin), event.actorId, event.messageDate, event.messageDate, event.updateId] };
}

export async function acceptTelegramSelected(
  db: D1Database, policy: SelectedPolicy, event: TelegramSelectedUpdate, key: CryptoKey,
): Promise<"accepted" | "ignored"> {
  const isolated = "adminId" in policy ? policy : null;
  const general = "privateSelected" in policy ? policy : null;
  if ((isolated ? !inTelegramScope(isolated, event) : !general?.privateSelected || general.rehearsal
      || event.actorId === general.botId || event.chatId !== event.actorId) || event.chatType !== "private" || event.threadId !== null
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)
    || (event.kind !== "selected" && event.kind !== "selected-revoke")
    || (event.kind === "selected" && typeof event.query !== "string")
    || (event.kind === "selected-revoke" && !REVOKE_TICKET.test(event.ticket))) return "ignored";
  const receipt = [policy.botId, event.updateId, crypto.randomUUID()] as const;
  const scope = [policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, receipt[2]] as const;
  try {
    const admission = general ? generalSelectedAdmission(general, event) : null;
    if (isolated && event.actorId !== isolated.adminId && await db.prepare("SELECT allowed FROM telegram_auth WHERE bot_id=? AND user_id=?")
      .bind(policy.botId,event.actorId).first<number>("allowed") === 0) return "ignored";
    if (admission && event.kind === "selected" && !await db.prepare(`SELECT 1 ${admission.sql}
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)`)
      .bind(...admission.bindings, event.updateId).first()) return "ignored";
    const selection = event.kind === "selected" ? await scanSelection(db, event.actorId, event.query) : null;
    const nonce = selection && !selection.limited && selection.ids !== "[]" ? base64Url(crypto.getRandomValues(new Uint8Array(16))) : null;
    const candidate = nonce === null || selection === null ? null : await hash(await deriveCode(key, policy.botId, event.actorId, nonce, selection.ids));
    const steps: D1PreparedStatement[] = [];
    if (event.kind === "selected-revoke") {
      const ticketHash = await hash(event.ticket);
      const insert = `INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)`;
      steps.push(general && admission ? db.prepare(`WITH ticket_origin AS MATERIALIZED (
        SELECT (${generalCurrentAuthoritySql("origin")}) AS allowed
        FROM telegram_selected_revoke_ticket AS ticket JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
        JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
        WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
          AND (origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.receipt_nonce='${GENERAL_TELEGRAM_SELECTED_MARKER}')
          AND (origin.chat_type='private' AND origin.thread_id IS NULL AND origin.command='help')
          AND (reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt)
      ) ${insert} SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
      ${admission.sql} AND EXISTS (SELECT 1 FROM ticket_origin WHERE allowed)
      ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(...generalPolicyBindings(general), ticketHash, policy.botId,
        event.actorId, event.chatId, event.messageId, event.updateId, event.messageId, event.messageDate, receipt[2], ...admission.bindings)
        : db.prepare(`${insert}
        SELECT ?,?,?,?,'private',?,?,NULL,'help',? FROM telegram_selected_revoke_ticket AS ticket
        JOIN telegram_inbox AS origin ON origin.receipt_id = ticket.origin_receipt_id
        JOIN telegram_outbox AS reply ON reply.receipt_id = origin.receipt_id
        WHERE ticket.token_sha256 = ? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at > unixepoch()
          AND origin.receipt_nonce = ? AND origin.bot_id = ? AND origin.actor_id = ?
          AND origin.chat_id = ? AND origin.chat_type = 'private' AND origin.thread_id IS NULL
          AND reply.state = 'sent' AND reply.sent_message_id = ? AND reply.attempts = ticket.origin_attempt
          AND (? = ? OR COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id=? AND user_id=?),1)=1)
        ON CONFLICT(bot_id,update_id) DO NOTHING
      `).bind(...scope, ticketHash, TELEGRAM_SELECTED_MARKER, policy.botId, event.actorId, event.chatId,
        event.messageId, event.actorId, isolated!.adminId, policy.botId, event.actorId));
      if (general) steps.push(prepareGeneralReceiptAuthority(db, general, receipt));
      steps.push(db.prepare(`UPDATE telegram_selected_revoke_ticket AS ticket SET used_by_receipt_id = inbox.receipt_id
        FROM telegram_inbox AS inbox WHERE ticket.token_sha256 = ? AND ticket.used_by_receipt_id IS NULL AND ${fresh}
      `).bind(ticketHash, ...receipt));
      steps.push(db.prepare(`INSERT INTO telegram_selected_actions
        (receipt_id,result,code_sha256,auth_message_date,auth_message_id)
        SELECT inbox.receipt_id, CASE ${isolated ? `WHEN ${authEpoch} >= inbox.message_date AND inbox.actor_id <> ? THEN 'stale'` : ""}
            WHEN link.revoked_at IS NULL THEN 'revoked' ELSE 'already-revoked' END,
          ${isolated ? `CASE WHEN ${authEpoch} >= inbox.message_date AND inbox.actor_id <> ? THEN NULL ELSE link.code_sha256 END,
          ${authEpoch}, CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_id,0) END` : "link.code_sha256, 0, 0"}
        FROM telegram_inbox AS inbox JOIN telegram_selected_revoke_ticket AS ticket ON ticket.used_by_receipt_id=inbox.receipt_id
        JOIN telegram_selected_links AS selected ON selected.code_sha256=ticket.code_sha256
          AND selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id
        JOIN aggregate_links AS link ON link.code_sha256=selected.code_sha256 AND link.owner_id=inbox.actor_id AND link.kind='selected'
        ${isolated ? "LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id" : ""}
        WHERE ${fresh}
      `).bind(...(isolated ? Array<string>(6).fill(isolated.adminId) : []), ...receipt));
      steps.push(db.prepare(`UPDATE aggregate_links AS link SET revoked_at=max(created_at,unixepoch())
        FROM telegram_selected_actions AS action JOIN telegram_inbox AS inbox USING(receipt_id)
        WHERE ${fresh} AND action.result='revoked' AND action.code_sha256=link.code_sha256 AND link.revoked_at IS NULL
      `).bind(...receipt));
    } else {
      steps.push(admission ? db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',? ${admission.sql}
        ON CONFLICT(bot_id,update_id) DO NOTHING
      `).bind(event.updateId, event.messageId, event.messageDate, receipt[2], ...admission.bindings) : db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,'private',?,?,NULL,'help',?
        WHERE ?=? OR COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id=? AND user_id=?),1)=1
        ON CONFLICT(bot_id,update_id) DO NOTHING
      `).bind(...scope, event.actorId, isolated!.adminId, policy.botId, event.actorId));
      if (general) steps.push(prepareGeneralReceiptAuthority(db, general, receipt));
      steps.push(db.prepare(`WITH scoped AS (
        SELECT inbox.*, ${isolated ? `${authEpoch} AS auth_date,
          CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_id,0) END AS auth_id` : "0 AS auth_date, 0 AS auth_id"}
        FROM telegram_inbox AS inbox ${isolated ? "LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id" : ""}
        WHERE ${fresh}
      ), classified AS (
        SELECT scoped.*, CASE
          WHEN message_date <= unixepoch()-900 OR message_date > unixepoch()+30
            ${isolated ? "OR (actor_id <> ? AND auth_date >= message_date)" : ""} THEN 'stale'
          WHEN ? THEN 'limit'
          WHEN (SELECT count(*) FROM subscriptions WHERE owner_id=scoped.actor_id) <> json_array_length(?)
            OR EXISTS (SELECT 1 FROM json_each(?) AS item LEFT JOIN subscriptions AS sub
              ON sub.owner_id=scoped.actor_id AND sub.id=json_extract(item.value,'$[0]')
              LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
              WHERE sub.id IS NULL OR COALESCE(lifecycle.revision,0) <> json_extract(item.value,'$[1]')) THEN 'stale'
          WHEN json_array_length(?)=0 THEN 'nomatch'
          WHEN (SELECT count(*) FROM telegram_selected_links AS selected JOIN aggregate_links AS link USING(code_sha256)
            WHERE selected.bot_id=scoped.bot_id AND selected.actor_id=scoped.actor_id AND link.revoked_at IS NULL) >= ${MAX_SELECTED_LINKS}
            OR (SELECT COALESCE(sum(sub.node_count),0) FROM json_each(?) AS item JOIN subscriptions AS sub
              ON sub.owner_id=scoped.actor_id AND sub.id=item.value) > ${MAX_SNAPSHOT_NODES}
            OR EXISTS (SELECT 1 FROM path_rules WHERE owner_id=scoped.actor_id LIMIT 1 OFFSET ${MAX_PATH_RULES}) THEN 'limit'
          WHEN NOT EXISTS (SELECT 1 FROM json_each(?) AS item JOIN subscriptions AS sub
            ON sub.owner_id=scoped.actor_id AND sub.id=item.value AND sub.generation>0) THEN 'empty'
          ELSE 'issued' END AS result
        FROM scoped
      ) INSERT INTO telegram_selected_actions (receipt_id,result,code_sha256,auth_message_date,auth_message_id)
      SELECT receipt_id,result,CASE WHEN result='issued' THEN ? END,auth_date,auth_id FROM classified
      `).bind(...(isolated ? [isolated.adminId, isolated.adminId] : []), ...receipt, ...(isolated ? [isolated.adminId] : []),
        Number(selection!.limited), selection!.inventory,
        selection!.inventory, selection!.ids, selection!.ids, selection!.ids, candidate));
      steps.push(db.prepare(`INSERT INTO aggregate_links(code_sha256,owner_id,kind,bot_id,selected_ids)
        SELECT action.code_sha256,inbox.actor_id,'selected',NULL,? FROM telegram_selected_actions AS action
        JOIN telegram_inbox AS inbox USING(receipt_id) WHERE ${fresh} AND action.result='issued'
      `).bind(selection!.ids, ...receipt));
      steps.push(db.prepare(`INSERT INTO telegram_selected_links(code_sha256,bot_id,actor_id,origin_receipt_id,nonce,key_version,generations)
        SELECT action.code_sha256,inbox.bot_id,inbox.actor_id,inbox.receipt_id,?,1,
          (SELECT json_group_array(json_array(id,generation,revision)) FROM (
            SELECT sub.id,sub.generation,COALESCE(lifecycle.revision,0) AS revision FROM json_each(?) AS item
            JOIN subscriptions AS sub ON sub.owner_id=inbox.actor_id AND sub.id=item.value
            LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id ORDER BY CAST(item.key AS INTEGER)))
        FROM telegram_selected_actions AS action JOIN telegram_inbox AS inbox USING(receipt_id)
        WHERE ${fresh} AND action.result='issued'
      `).bind(nonce, selection!.ids, ...receipt));
    }
    steps.push(db.prepare(`INSERT INTO telegram_outbox(receipt_id) SELECT receipt_id FROM telegram_inbox AS inbox WHERE ${fresh}`).bind(...receipt));
    steps.push(db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce=?,command=CASE WHEN EXISTS (
      SELECT 1 FROM telegram_selected_actions AS action JOIN telegram_outbox USING(receipt_id)
      WHERE action.receipt_id=inbox.receipt_id AND (action.result<>'issued' OR EXISTS (
        SELECT 1 FROM telegram_selected_links AS selected JOIN aggregate_links AS link USING(code_sha256)
        WHERE selected.origin_receipt_id=inbox.receipt_id AND selected.code_sha256=action.code_sha256 AND link.revoked_at IS NULL))
        ${general && event.kind === "selected-revoke" ? `AND EXISTS (SELECT 1 FROM telegram_selected_revoke_ticket AS ticket
          JOIN aggregate_links AS link USING(code_sha256) WHERE ticket.used_by_receipt_id=inbox.receipt_id
            AND ticket.code_sha256=action.code_sha256 AND link.revoked_at IS NOT NULL)` : ""})
      ${general ? `AND (${generalCurrentAuthoritySql("inbox")})` : ""}
      THEN command END WHERE ${fresh} RETURNING receipt_id
    `).bind(selectedMarker(policy), ...(general ? generalPolicyBindings(general) : []), ...receipt));
    const results = await db.batch(steps);
    const confirmed = results.at(-1);
    if (confirmed && results.length === steps.length && results.every(({ success }) => success) && confirmed.results.length <= 1) {
      return confirmed.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // Query text, provider metadata, cryptographic inputs and SQL remain private.
  }
  throw new Error("Selected export receipt could not be confirmed.");
}

export function selectedDeliveryGuard(policy: SelectedPolicy, reply: TelegramSelectedReply): SelectedGuard | null {
  const isolated = "adminId" in policy ? policy : null;
  const scope = `inbox.receipt_nonce='${selectedMarker(policy)}' AND inbox.chat_type='private'
    AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL ${isolated ? "" : `AND (${GENERAL_SELECTED_SCHEMA})`}`;
  const auth = isolated ? `((inbox.actor_id=? AND action.auth_message_date=0 AND action.auth_message_id=0)
    OR (inbox.actor_id=? AND COALESCE(auth.allowed,1)=1 AND action.auth_message_date=COALESCE(auth.message_date,0)
      AND action.auth_message_id=COALESCE(auth.message_id,0)))` : "(action.auth_message_date=0 AND action.auth_message_id=0)";
  const authJoin = isolated ? "LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id" : "";
  const bindings = isolated ? [isolated.adminId, isolated.memberId] : [];
  if (reply.result === "limit") return { sql: `${scope} AND EXISTS (
    SELECT 1 FROM telegram_selected_actions AS action ${authJoin}
    WHERE action.receipt_id=inbox.receipt_id AND action.result='limit' AND ${auth})`, bindings };
  if (reply.result !== "issued" || reply.codeSha256 === null || !DIGEST.test(reply.codeSha256)) return null;
  return { sql: `${scope} AND inbox.command='help'
    AND EXISTS (SELECT 1 FROM telegram_selected_actions AS action JOIN telegram_selected_links AS selected USING(code_sha256)
      JOIN aggregate_links AS link USING(code_sha256) ${authJoin}
      WHERE action.receipt_id=inbox.receipt_id AND action.result='issued' AND action.code_sha256=?
        AND selected.origin_receipt_id=inbox.receipt_id AND selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id
        AND selected.key_version=1 AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.revoked_at IS NULL
        AND ${auth}
        AND NOT EXISTS (SELECT 1 FROM json_each(selected.generations) AS item LEFT JOIN subscriptions AS sub
          ON sub.owner_id=inbox.actor_id AND sub.id=json_extract(item.value,'$[0]')
          LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
          WHERE sub.id IS NULL OR sub.generation<>json_extract(item.value,'$[1]')
            OR COALESCE(lifecycle.revision,0)<>json_extract(item.value,'$[2]')))`,
    bindings: [reply.codeSha256, ...bindings] };
}

export async function resolveTelegramSelectedCode(
  db: D1Database, policy: SelectedPolicy,
  lease: { receiptId: number; actorId: string; leaseId: string; attempts: number; selected: TelegramSelectedReply }, key: CryptoKey | null,
  sending = false,
): Promise<string | null> {
  const guard = selectedDeliveryGuard(policy, lease.selected);
  if (!guard || !key || lease.selected.result !== "issued") return null;
  try {
    const target = `FROM telegram_inbox AS inbox
      JOIN telegram_outbox AS reply USING(receipt_id) JOIN telegram_selected_links AS selected ON selected.origin_receipt_id=inbox.receipt_id
      JOIN aggregate_links AS link USING(code_sha256)
      WHERE inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND reply.lease_id=? AND reply.attempts=?
        AND reply.state=? AND reply.lease_until>unixepoch()`;
    const identity = [lease.receiptId, policy.botId, lease.actorId, lease.leaseId, lease.attempts, sending ? "sending" : "leased"];
    const lookup = "adminId" in policy
      ? db.prepare(`SELECT selected.nonce,link.selected_ids AS ids ${target} AND ${guard.sql}`).bind(...identity, ...guard.bindings)
      : db.prepare(`WITH candidate AS MATERIALIZED (
        SELECT selected.nonce,link.selected_ids AS ids,(${guard.sql}) AS ready,(${generalCurrentAuthoritySql("inbox")}) AS allowed
        ${target}
      ) SELECT nonce,ids FROM candidate WHERE ready AND allowed`).bind(...guard.bindings, ...generalPolicyBindings(policy), ...identity);
    const row = await lookup.first<{ nonce: string; ids: string }>();
    if (!row || !NONCE.test(row.nonce)) return null;
    const code = await deriveCode(key, policy.botId, lease.actorId, row.nonce, row.ids);
    return await hash(code) === lease.selected.codeSha256 ? code : null;
  } catch {
    throw new Error("Selected export link could not be resolved.");
  }
}

export async function prepareSelectedRevokeTicket(): Promise<{ token: string; sha256: string }> {
  const token = "sbo1_" + base64Url(crypto.getRandomValues(new Uint8Array(16)));
  return { token, sha256: await hash(token) };
}

export interface SelectedRevokeTicket { token: string; sha256: string; codeSha256: string }

export async function prepareSelectedLimitTickets(
  db: D1Database, policy: Pick<TelegramPolicy, "botId">, actorId: string,
): Promise<SelectedRevokeTicket[]> {
  const result = await db.prepare(`SELECT selected.code_sha256 AS digest FROM telegram_selected_links AS selected
    JOIN aggregate_links AS link USING(code_sha256) WHERE selected.bot_id=? AND selected.actor_id=? AND link.revoked_at IS NULL
      AND link.owner_id=selected.actor_id AND link.kind='selected' AND link.bot_id IS NULL
    ORDER BY selected.origin_receipt_id DESC LIMIT ${MAX_SELECTED_LINKS + 1}
  `).bind(policy.botId, actorId).all<{ digest: string }>();
  if (!result.success || result.results.length > MAX_SELECTED_LINKS) {
    throw new Error("Selected export revoke inventory could not be read.");
  }
  return Promise.all(result.results.map(async ({ digest }) => ({
    ...await prepareSelectedRevokeTicket(), codeSha256: digest,
  })));
}

export async function retireUnsentSelectedLink(
  db: D1Database, policy: SelectedPolicy,
  lease: { receiptId: number; actorId: string; leaseId: string; attempts: number }, state: "leased" | "sending",
): Promise<boolean> {
  const scope = `inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.receipt_nonce=?
    AND reply.lease_id=? AND reply.attempts=? AND reply.state=? AND reply.lease_until>unixepoch()`;
  const bindings = [lease.receiptId, policy.botId, lease.actorId, selectedMarker(policy), lease.leaseId, lease.attempts, state];
  const results = await db.batch([
    db.prepare(`UPDATE aggregate_links AS link SET revoked_at=COALESCE(revoked_at,max(created_at,unixepoch()))
      FROM telegram_selected_actions AS action JOIN telegram_inbox AS inbox USING(receipt_id)
      JOIN telegram_outbox AS reply USING(receipt_id) JOIN telegram_selected_links AS selected USING(code_sha256)
      WHERE ${scope} AND action.result='issued' AND action.code_sha256=link.code_sha256
        AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.bot_id IS NULL
        AND selected.origin_receipt_id=inbox.receipt_id AND selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id
    `).bind(...bindings),
    db.prepare(`UPDATE telegram_selected_actions AS action SET result='stale',code_sha256=NULL
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE changes()=1 AND action.receipt_id=inbox.receipt_id AND action.result='issued' AND ${scope}
    `).bind(...bindings),
  ]);
  if (results.length !== 2 || results.some(({ success }) => !success) || results[0].meta.changes !== results[1].meta.changes
    || ![0, 1].includes(results[0].meta.changes)) throw new Error("Unsent selected export could not be retired.");
  return results[0].meta.changes === 1;
}

export function insertSelectedRevokeTickets(
  db: D1Database, receiptId: number, attempt: number, leaseId: string, tickets: readonly SelectedRevokeTicket[], general = false,
): D1PreparedStatement {
  if (tickets.length > MAX_SELECTED_LINKS || tickets.some((ticket) => !DIGEST.test(ticket.sha256) || !DIGEST.test(ticket.codeSha256))) {
    throw new RangeError("Invalid selected revoke tickets.");
  }
  if (new Set(tickets.map(({ sha256 }) => sha256)).size !== tickets.length
    || new Set(tickets.map(({ codeSha256 }) => codeSha256)).size !== tickets.length) {
    throw new RangeError("Duplicate selected revoke tickets.");
  }
  return db.prepare(`INSERT INTO telegram_selected_revoke_ticket(token_sha256,origin_receipt_id,code_sha256,origin_attempt,expires_at)
    SELECT json_extract(item.value,'$.sha256'),reply.receipt_id,selected.code_sha256,reply.attempts,unixepoch()+${TICKET_SECONDS}
    FROM telegram_outbox AS reply
    JOIN telegram_inbox AS inbox USING(receipt_id) JOIN telegram_selected_actions AS action USING(receipt_id)
    JOIN json_each(?) AS item JOIN telegram_selected_links AS selected
      ON selected.code_sha256=json_extract(item.value,'$.codeSha256') AND selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id
    JOIN aggregate_links AS link ON link.code_sha256=selected.code_sha256 AND link.revoked_at IS NULL
    WHERE changes()=1 AND reply.receipt_id=? AND reply.attempts=? AND reply.lease_id=? AND reply.state='sending'
      AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.bot_id IS NULL
      AND inbox.receipt_nonce=? AND (action.result='limit' OR (action.result='issued' AND action.code_sha256=selected.code_sha256))
  `).bind(JSON.stringify(tickets.map(({ sha256, codeSha256 }) => ({ sha256, codeSha256 }))),
    receiptId, attempt, leaseId, general ? GENERAL_TELEGRAM_SELECTED_MARKER : TELEGRAM_SELECTED_MARKER);
}

export function selectedTicketTargetGuard(policy: SelectedPolicy, reply: TelegramSelectedReply,
  tickets: readonly SelectedRevokeTicket[]): SelectedGuard | null {
  const guard = selectedDeliveryGuard(policy, reply);
  if (guard === null || (reply.result === "issued" && tickets.length !== 1)) return null;
  const targets = JSON.stringify(tickets.map(({ codeSha256 }) => codeSha256));
  return {
    sql: `(${guard.sql}) AND ? = (
      SELECT count(*) FROM json_each(?) AS item JOIN telegram_selected_links AS selected ON selected.code_sha256=item.value
      JOIN aggregate_links AS link USING(code_sha256)
      JOIN telegram_selected_actions AS action ON action.receipt_id=inbox.receipt_id
      WHERE selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id
        AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.bot_id IS NULL AND link.revoked_at IS NULL
        AND (action.result='limit' OR (action.result='issued' AND action.code_sha256=selected.code_sha256))
    ) ${reply.result === "limit" ? `AND ? = (
      SELECT count(*) FROM telegram_selected_links AS selected JOIN aggregate_links AS link USING(code_sha256)
      WHERE selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id AND link.revoked_at IS NULL
        AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.bot_id IS NULL
    )` : ""}`,
    bindings: [...guard.bindings, tickets.length, targets, ...(reply.result === "limit" ? [tickets.length] : [])],
  };
}

export async function reapTelegramSelected(db: D1Database, generalBotId?: string): Promise<void> {
  const generalOrigin = `SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id=selected.origin_receipt_id
    AND inbox.receipt_nonce='${GENERAL_TELEGRAM_SELECTED_MARKER}'`;
  const scope = generalBotId === undefined ? `AND NOT EXISTS (${generalOrigin})`
    : `AND selected.bot_id=? AND EXISTS (${generalOrigin} AND inbox.bot_id=selected.bot_id AND inbox.actor_id=selected.actor_id)`;
  const retire = db.prepare(`UPDATE aggregate_links SET revoked_at=max(created_at,unixepoch()) WHERE revoked_at IS NULL
    AND code_sha256 IN (SELECT selected.code_sha256 FROM telegram_selected_links AS selected
      JOIN telegram_outbox AS reply ON reply.receipt_id=selected.origin_receipt_id
      JOIN aggregate_links AS active ON active.code_sha256=selected.code_sha256
      WHERE reply.state='failed' AND active.revoked_at IS NULL AND active.owner_id=selected.actor_id
        AND active.kind='selected' AND active.bot_id IS NULL ${scope}
      ORDER BY selected.origin_receipt_id LIMIT 40)
  `);
  await (generalBotId === undefined ? retire : retire.bind(generalBotId)).run();
  if (generalBotId !== undefined) {
    await db.prepare(`DELETE FROM telegram_selected_revoke_ticket WHERE token_sha256 IN (
      SELECT ticket.token_sha256 FROM telegram_selected_revoke_ticket AS ticket
      JOIN telegram_inbox AS inbox ON inbox.receipt_id=ticket.origin_receipt_id
      WHERE inbox.bot_id=? AND inbox.receipt_nonce='${GENERAL_TELEGRAM_SELECTED_MARKER}' AND ticket.expires_at<=unixepoch()
      ORDER BY ticket.expires_at LIMIT 40)`).bind(generalBotId).run();
  } else await db.prepare(`DELETE FROM telegram_selected_revoke_ticket WHERE token_sha256 IN (
    SELECT ticket.token_sha256 FROM telegram_selected_revoke_ticket AS ticket WHERE ticket.expires_at<=unixepoch()
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id=ticket.origin_receipt_id
        AND inbox.receipt_nonce='${GENERAL_TELEGRAM_SELECTED_MARKER}')
    ORDER BY ticket.expires_at LIMIT 40
  )`).run();
}

export function renderTelegramSelected(reply: TelegramSelectedReply): string {
  return { issued: "所选订阅已变更，链接未发送。请重新发送 /o。", nomatch: "没有匹配订阅。", empty: "匹配订阅暂无可导出节点。",
    limit: "搜索或所选订阅达到上限。请缩小关键词，或使用旧链接消息上的按钮撤销不再需要的链接。",
    stale: "订阅或授权状态已变更，请重新发送 /o。", revoked: "所选聚合链接已撤销。", "already-revoked": "所选聚合链接已撤销。" }[reply.result];
}

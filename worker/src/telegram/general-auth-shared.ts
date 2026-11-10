import type { PublicOrigin } from "../public-origin.ts";
import { acceptTelegramDocumentJob, generalDocumentReplyEligibility, generalDocumentReplyScope, renderTelegramDocumentOutcome,
  TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER, type TelegramDocumentJobResult } from "./document-jobs.ts";
import { sendGeneralTelegramGroupListReply, sendGeneralTelegramPrivateReply } from "./delivery.ts";
import {
  generalReadEvent, renderGeneralReadReply,
  type GeneralReadCommand, type GeneralReadEvent, type GeneralTelegramPin,
} from "./general-auth-runtime.ts";
import { GENERAL_READ_LANE_ROLE, generalReadLaneRoleBindings } from "./general-read-lane.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL, GENERAL_POLICY_PIN_SQL,
  GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentAuthoritySql, generalOrdinaryReplyEligibilitySql, generalPolicyBindings, generalRecordedOriginSql,
  prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { acceptGeneralTelegramLifecycle, GENERAL_LIFECYCLE_MARKER, GENERAL_LIFECYCLE_VIEW_MARKER,
  insertTelegramLifecycleTickets, prepareTelegramLifecycleTickets, reapTelegramLifecycle, renderTelegramLifecycle,
  type TelegramLifecycleReply, type TelegramLifecycleTicket } from "./lifecycle-actions.ts";
import { acceptGeneralTelegramSubscriptionRead, renderGeneralSubscriptionRead } from "./general-subscription-read.ts";
import { GENERAL_PATH_MARKER, prepareTelegramPathReceipt, renderTelegramPath, type TelegramPathReply } from "./path-management.ts";
import { readGeneralPrivateDocumentUpdate, readGeneralPrivateLifecycleUpdate, readGeneralPrivateSubscriptionRead,
  readGeneralPrivateTempUpdate, readPrivateTelegramCommand, readTelegramUpdate } from "./protocol.ts";
import { confirmTelegramSubscriptionReadSend, GENERAL_SUBSCRIPTION_READ_MARKER, insertTelegramSubscriptionReadTickets,
  prepareTelegramSubscriptionReadTickets, reapTelegramSubscriptionReadTickets,
  type TelegramSubscriptionReadTicket } from "./subscription-read.ts";
import { prepareGeneralTelegramTempReceipt, renderTelegramTemp, type TelegramTempReply } from "./temp-import.ts";
import { readVerifiedTempStorage, TELEGRAM_GENERAL_TEMP_MARKER, tempCutoverAllows, tempSchemaGuard } from "./temp-storage.ts";
import { renderTelegramView } from "./views.ts";
import { prepareTelegramOutboxBegin, settleTelegramOutboxReply, TELEGRAM_OUTBOX_LEASE_SECONDS,
  TELEGRAM_OUTBOX_MAX_ATTEMPTS } from "./store.ts";

const MARKER = "general-read:v1";
const GROUP_MARKER = "general-group-read:v1";
const GROUP_SCHEMA_SHA256 = "442b9f1e52ad961aac41ee9416760863984646a96570bd22f26474d329ee626e";
const GROUP_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-group-reads:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=47 AND name='0047_telegram_general_groups.sql' AND sha256='${GROUP_SCHEMA_SHA256}' AND mode='applied')`;
const PATH_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-private-path:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=13 AND name='0013_telegram_path.sql'
    AND sha256='8375e89be0cf3fe1e23b4107f538927a85d2d3ebf9b49eab0bf700ad2c023f15' AND mode='applied')`;
const TEMP_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-temp-intake:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=8 AND name='0008_telegram_temp_nodes.sql'
    AND sha256='87ae872d0b04e49649e102adea9b00a2e5a24cd58b5236e561d0c85634c0a0ea' AND mode='applied')`;
type MetadataReply = { sql: string; bindings: readonly (string | number | null)[]; tickets: readonly TelegramSubscriptionReadTicket[] };

interface SharedReadLease {
  receiptId: number;
  updateId: number;
  actorId: string;
  chatId: string;
  chatType: "private" | "group" | "supergroup";
  threadId: number | null;
  messageId: number;
  messageDate: number;
  generation: number;
  actorRevision: number;
  actorRole: "admin" | "member";
  command: GeneralReadCommand;
  marker: string;
  viewKind: "list" | "recycle" | null;
  actionKind: TelegramLifecycleReply["kind"] | null;
  actionSubscriptionId: number | null;
  actionRevision: number | null;
  leaseId: string;
  attempts: number;
}

async function groupSchemaReady(db: D1Database): Promise<boolean> {
  try {
    const definition = await db.prepare(`SELECT sql FROM sqlite_schema
      WHERE name='telegram_general_groups' AND type='table' AND ${GROUP_SCHEMA}`).first<string>("sql");
    if (typeof definition !== "string" || definition.length > 400) return false;
    const bytes = new TextEncoder().encode(definition + ";\n");
    const hash = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("") === GROUP_SCHEMA_SHA256;
  } catch {
    // The private family can still operate when the optional group schema cannot be confirmed.
    return false;
  }
}

function approvedGroup(alias?: "inbox" | "earlier"): string {
  return `${GROUP_SCHEMA} AND EXISTS (SELECT 1 FROM telegram_general_groups AS approved
    WHERE approved.bot_id=policy.bot_id AND approved.generation=policy.generation
      AND approved.chat_id=${alias ? alias + ".chat_id" : "?"} AND approved.chat_type=${alias ? alias + ".chat_type" : "?"})`;
}

function family(alias: "inbox" | "earlier", group: boolean, pin: GeneralTelegramPin): string {
  const privateScope = `${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL`;
  const groupScope = group ? ` OR (${alias}.receipt_nonce='${GROUP_MARKER}' AND ${alias}.chat_type IN ('group','supergroup')
    AND ${alias}.command='list' AND (${alias}.chat_type='supergroup' OR ${alias}.thread_id IS NULL))` : "";
  const view = `EXISTS (SELECT 1 FROM telegram_view AS page WHERE page.receipt_id=${alias}.receipt_id
    AND page.after_id IS NULL AND page.after_epoch IS NULL AND page.kind`;
  const ordinary = `((${alias}.receipt_nonce='${MARKER}' AND ${privateScope})${groupScope})
    AND ((${alias}.command='list' AND ${view}='list'))
      OR (${alias}.command='help' AND NOT EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id=${alias}.receipt_id)))`;
  const temp = pin.privateTemp ? `OR (${alias}.receipt_nonce='${TELEGRAM_GENERAL_TEMP_MARKER}' AND ${alias}.command='help'
    AND EXISTS (SELECT 1 FROM telegram_temp_reply WHERE receipt_id=${alias}.receipt_id))` : "";
  const document = pin.privateDocument ? `OR (${generalDocumentReplyScope(alias)})` : "";
  return pin.privateManagement ? `((${ordinary}) OR (/* subs-bot:telegram-general-private-lifecycle:v1 */ ${privateScope} AND (
    (${alias}.receipt_nonce='${GENERAL_LIFECYCLE_VIEW_MARKER}' AND ${alias}.command='list' AND ${view} IN ('list','recycle')))
    OR (${alias}.receipt_nonce='${GENERAL_LIFECYCLE_MARKER}' AND ${alias}.command='help'
      AND EXISTS (SELECT 1 FROM telegram_lifecycle_action WHERE receipt_id=${alias}.receipt_id))
    OR (${alias}.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND ${alias}.command='help'
      AND EXISTS (SELECT /* subs-bot:telegram-general-subscription-read:v1 */ 1 FROM telegram_subscription_read
        WHERE receipt_id=${alias}.receipt_id))
    OR (${alias}.receipt_nonce='${GENERAL_PATH_MARKER}' AND ${alias}.command='help'
      AND EXISTS (SELECT 1 FROM telegram_path_reply WHERE receipt_id=${alias}.receipt_id)) ${temp} ${document})))` : ordinary;
}

function queueMarkers(group: boolean, pin: GeneralTelegramPin): string {
  const markers: string[] = [MARKER];
  if (group) markers.push(GROUP_MARKER);
  if (pin.privateManagement) markers.push(GENERAL_LIFECYCLE_MARKER, GENERAL_LIFECYCLE_VIEW_MARKER,
    GENERAL_SUBSCRIPTION_READ_MARKER, GENERAL_PATH_MARKER);
  if (pin.privateTemp) markers.push(TELEGRAM_GENERAL_TEMP_MARKER);
  if (pin.privateDocument) markers.push(TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER);
  return markers.map((marker) => `'${marker}'`).join(",");
}

function current(alias: "inbox" | "earlier", group: boolean, pin: GeneralTelegramPin): string {
  const groupScope = group ? `(${alias}.receipt_nonce<>'${GROUP_MARKER}' OR (${approvedGroup(alias)}))` : "1";
  const pathScope = pin.privateManagement ? `(${alias}.receipt_nonce<>'${GENERAL_PATH_MARKER}' OR ${PATH_SCHEMA})` : "1";
  const tempScope = pin.privateTemp ? ` AND (${alias}.receipt_nonce<>'${TELEGRAM_GENERAL_TEMP_MARKER}' OR (${TEMP_SCHEMA}
    AND ${tempSchemaGuard("legacy-ready")}))` : "";
  const laneScope = pin.rehearsal ? ` AND ${GENERAL_READ_LANE_ROLE}` : "";
  const ordinaryClock = generalOrdinaryReplyEligibilitySql(alias);
  const clock = pin.privateDocument ? `(CASE WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER}'
    THEN (${generalDocumentReplyEligibility(alias)}) ELSE (${ordinaryClock}) END)` : ordinaryClock;
  return `${clock} AND ${generalCurrentAuthoritySql(alias, `${groupScope} AND ${pathScope}${tempScope}${laneScope}`)}`;
}

function currentBindings(pin: GeneralTelegramPin) {
  return [...generalPolicyBindings(pin), ...generalReadLaneRoleBindings(pin)];
}

export async function acceptGeneralSharedTelegramCommand(
  db: D1Database, pin: GeneralTelegramPin, request: Request, acknowledge?: (callbackId: string) => void,
): Promise<number> {
  const decoded = await readTelegramUpdate(request, pin.webhookSecret);
  if (decoded.status !== 200) return decoded.status;
  if (!pin.sharedOutbox || pin.rehearsal) return 204;
  const document = pin.privateDocument ? readGeneralPrivateDocumentUpdate(decoded.update, decoded.updateId, pin.botId) : null;
  if (document) return await acceptTelegramDocumentJob(db, pin, document) === "ignored" ? 204 : 200;
  const action = pin.privateManagement ? readGeneralPrivateLifecycleUpdate(decoded.update, decoded.updateId, pin.botId) : null;
  if (action) {
    const accepted = await acceptGeneralTelegramLifecycle(db, pin, action) === "accepted";
    if (accepted && action.kind === "lifecycle-callback") acknowledge?.(action.callbackId);
    return accepted ? 200 : 204;
  }
  const search = pin.privateManagement
    ? readGeneralPrivateSubscriptionRead(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  if (search) {
    const accepted = await acceptGeneralTelegramSubscriptionRead(db, pin, search);
    if (accepted && search.kind === "callback") acknowledge?.(search.callbackId);
    return accepted ? 200 : 204;
  }
  const tempEvent = pin.privateTemp ? readGeneralPrivateTempUpdate(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  const command = pin.privateManagement && !tempEvent ? readPrivateTelegramCommand(decoded.update, pin.botUsername) : null;
  const pathCommand = command?.name === "path" && command.actorId !== pin.botId ? command : null;
  const event = tempEvent ? { ...tempEvent, command: "help" as const, viewKind: null }
    : pathCommand ? {
      command: "help" as const, viewKind: null, updateId: decoded.updateId, actorId: pathCommand.actorId,
      chatId: pathCommand.actorId, chatType: "private" as const, threadId: null,
      messageId: pathCommand.messageId, messageDate: pathCommand.messageDate,
    } : generalReadEvent(pin, decoded.update, decoded.updateId, true);
  return event ? acceptSharedRead(db, pin, event, pathCommand, tempEvent) : 204;
}

export function acceptGeneralReadLaneCommand(
  db: D1Database, pin: GeneralTelegramPin, event: GeneralReadEvent, guard: D1PreparedStatement,
): Promise<number> {
  if (!pin.rehearsal || pin.privateManagement || pin.privateFormats || pin.privateTemp || pin.privateDocument
    || event.chatType !== "private" || event.chatId !== event.actorId
    || event.threadId !== null || event.viewKind === "recycle") return Promise.resolve(204);
  return acceptSharedRead(db, pin, event, null, null, guard);
}

async function acceptSharedRead(
  db: D1Database, pin: GeneralTelegramPin, event: GeneralReadEvent,
  pathCommand: ReturnType<typeof readPrivateTelegramCommand>, tempEvent: ReturnType<typeof readGeneralPrivateTempUpdate>,
  admissionGuard?: D1PreparedStatement,
): Promise<number> {
  const group = event.chatType !== "private";
  if (group && !await groupSchemaReady(db)) return 204;

  const storage = tempEvent ? await readVerifiedTempStorage(db).catch(() => null) : null;
  const mode = storage?.generalReceipts && storage.mode === "legacy-ready" ? storage.mode : null;
  if (tempEvent && mode === null) return 204;
  const tempScope = mode ? `AND ${TEMP_SCHEMA} AND (${tempSchemaGuard(mode)})
    AND (${tempCutoverAllows(mode, "policy.bot_id", "?")})` : "";
  const admission = `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}
      AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      ${group ? `AND ${approvedGroup()}` : ""} ${pathCommand ? `AND ${PATH_SCHEMA}` : ""} ${tempScope}
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY} ${pin.rehearsal ? `AND ${GENERAL_READ_LANE_ROLE}` : ""}`;
  const bindings = [...generalPolicyBindings(pin), event.actorId, event.messageDate, event.messageDate,
    ...(group ? [event.chatId, event.chatType] : []), ...(mode ? [event.messageDate] : []), event.updateId,
    ...generalReadLaneRoleBindings(pin)];
  // Bound the parser to current authorized candidates; the same gate runs again in the write batch.
  if (tempEvent && !await db.prepare(`SELECT 1 ${admission}
    AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)`)
    .bind(...bindings, event.updateId).first()) return 204;
  const nonce = crypto.randomUUID();
  const key = [pin.botId, event.updateId, nonce] as const;
  const path = pathCommand ? prepareTelegramPathReceipt(db, key, { general: pin }, pathCommand.remainder) : null;
  const temp = tempEvent && mode ? prepareGeneralTelegramTempReceipt(db, key, mode, tempEvent) : null;
  if (tempEvent && !temp) return 204;
  const marker = temp ? TELEGRAM_GENERAL_TEMP_MARKER : path ? GENERAL_PATH_MARKER : group ? GROUP_MARKER
    : pin.privateManagement && event.viewKind !== null ? GENERAL_LIFECYCLE_VIEW_MARKER : MARKER;
  const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
  const proof = temp ? `(${temp.proof}) AND ${generalCurrentAuthoritySql("incoming")}` : path?.proof
    ?? `incoming.command='help' OR EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id=incoming.receipt_id AND kind=?)`;
  const proofBindings = temp ? generalPolicyBindings(pin) : path?.verification ?? [event.viewKind];
  const steps = [
    ...(admissionGuard ? [admissionGuard] : []),
    db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,?,?,?,?,?,?,? ${admission}
      ON CONFLICT (bot_id,update_id) DO NOTHING`)
      .bind(event.updateId, event.chatId, event.chatType, event.messageId, event.messageDate, event.threadId, event.command, nonce, ...bindings),
    prepareGeneralReceiptAuthority(db, pin, key),
    ...(temp?.statements ?? path?.statements ?? [db.prepare(`INSERT INTO telegram_view (receipt_id,kind)
      SELECT incoming.receipt_id,? FROM telegram_inbox AS incoming WHERE ${fresh} AND incoming.command='list'`).bind(event.viewKind, ...key)]),
    db.prepare(`INSERT INTO telegram_outbox (receipt_id)
      SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?, command=CASE WHEN
        EXISTS (SELECT 1 FROM telegram_general_receipt WHERE receipt_id=incoming.receipt_id)
        AND EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=incoming.receipt_id)
        AND (${proof})
      THEN incoming.command END WHERE ${fresh} RETURNING receipt_id`).bind(marker, ...proofBindings, ...key),
  ];
  const results = await db.batch(steps);
  const receipt = results.at(-1);
  if (!receipt || results.length !== steps.length || !results.every(({ success }) => success) || receipt.results.length > 1) {
    throw new Error("General Telegram receipt could not be confirmed.");
  }
  return receipt.results.length === 1 ? 200 : 204;
}

export async function claimGeneralSharedTelegramReply(db: D1Database, pin: GeneralTelegramPin): Promise<SharedReadLease | null> {
  if (!pin.sharedOutbox) return null;
  const group = !pin.rehearsal && await groupSchemaReady(db);
  const leaseId = crypto.randomUUID();
  // Evaluate authorization once per active row, outside the FIFO subquery's expression tree.
  const [claimed, read] = await db.batch<SharedReadLease>([
    db.prepare(`UPDATE telegram_outbox
      SET state='leased',attempts=attempts+1,lease_id=?,lease_until=unixepoch()+${TELEGRAM_OUTBOX_LEASE_SECONDS}
      WHERE receipt_id=(
        WITH active AS MATERIALIZED (
          SELECT inbox.receipt_id,inbox.actor_id,inbox.chat_id,reply.state,reply.attempts,reply.lease_until,reply.due_at,
            (${family("inbox", group, pin)}) AS supported,
            (${current("inbox", group, pin)}) AS eligible
          FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
          WHERE inbox.bot_id=? AND reply.state IN ('pending','leased','sending')
        )
        SELECT candidate.receipt_id FROM active AS candidate
        WHERE candidate.supported AND candidate.eligible AND candidate.attempts<${TELEGRAM_OUTBOX_MAX_ATTEMPTS}
          AND ((candidate.state='pending' AND candidate.due_at<=unixepoch())
            OR (candidate.state='leased' AND candidate.lease_until<=unixepoch()))
          AND NOT EXISTS (
            SELECT 1 FROM active AS earlier
            WHERE earlier.actor_id=candidate.actor_id AND earlier.chat_id=candidate.chat_id
              AND earlier.receipt_id<>candidate.receipt_id AND earlier.supported
              AND ((earlier.state='sending' AND earlier.lease_until>unixepoch()) OR (earlier.eligible
                AND ((earlier.state='leased' AND earlier.lease_until>unixepoch()) OR (
                  earlier.receipt_id<candidate.receipt_id AND earlier.state IN ('pending','leased')
                  AND earlier.attempts<${TELEGRAM_OUTBOX_MAX_ATTEMPTS})))))
        ORDER BY candidate.receipt_id LIMIT 1)`)
      .bind(leaseId, ...currentBindings(pin), pin.botId),
    db.prepare(`SELECT inbox.receipt_id AS receiptId,inbox.update_id AS updateId,inbox.actor_id AS actorId,
      inbox.chat_id AS chatId,inbox.chat_type AS chatType,inbox.thread_id AS threadId,
      inbox.message_id AS messageId,inbox.message_date AS messageDate,inbox.command,inbox.receipt_nonce AS marker,authority.generation,
      authority.actor_revision AS actorRevision,authority.actor_role AS actorRole,reply.attempts,reply.lease_id AS leaseId,
      page.kind AS viewKind,action.kind AS actionKind,action.subscription_id AS actionSubscriptionId,
      action.expected_revision AS actionRevision
      FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
      JOIN telegram_general_receipt AS authority USING (receipt_id)
      LEFT JOIN telegram_view AS page USING (receipt_id)
      LEFT JOIN telegram_lifecycle_action AS action ON action.receipt_id=inbox.receipt_id
        AND inbox.receipt_nonce='${GENERAL_LIFECYCLE_MARKER}'
      WHERE reply.lease_id=? AND reply.state='leased' AND inbox.bot_id=? AND ${family("inbox", group, pin)}`).bind(leaseId, pin.botId),
  ]);
  if (!claimed?.success || !read?.success || claimed.meta.changes > 1 || read.results.length !== claimed.meta.changes) {
    throw new Error("General Telegram lease could not be confirmed.");
  }
  return read.results[0] ?? null;
}

function selectLease(pin: GeneralTelegramPin, lease: SharedReadLease, authorizing: boolean, metadata?: MetadataReply) {
  const group = !pin.rehearsal && lease.chatType !== "private";
  const exact = `FROM telegram_inbox AS inbox JOIN telegram_general_receipt AS authority USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.receipt_id=? AND inbox.update_id=? AND inbox.actor_id=?
      AND inbox.chat_id=? AND inbox.chat_type=? AND inbox.thread_id IS ? AND inbox.message_id=? AND inbox.message_date=?
      AND inbox.command=? AND inbox.receipt_nonce=? AND authority.actor_revision=? AND authority.actor_role=?
      AND ${generalRecordedOriginSql("inbox")} AND ${family("inbox", group, pin)}`;
  const exactBindings = [pin.botId, lease.receiptId, lease.updateId, lease.actorId, lease.chatId, lease.chatType, lease.threadId,
    lease.messageId, lease.messageDate, lease.command, lease.marker, lease.actorRevision, lease.actorRole,
    ...generalPolicyBindings(pin, lease.generation)];
  const eligible = current("inbox", group, pin);
  if (authorizing && metadata) {
    // Keep the current grant and the origin/target proof separate inside the atomic begin.
    return { sql: `WITH candidate AS MATERIALIZED (
      SELECT inbox.receipt_id,(${eligible}) AS eligible,(${metadata.sql}) AS prepared ${exact}
    ) SELECT receipt_id FROM candidate WHERE eligible AND prepared`,
    bindings: [...currentBindings(pin), ...metadata.bindings, ...exactBindings] };
  }
  return { sql: `SELECT inbox.receipt_id ${exact} ${authorizing ? `AND ${eligible}` : ""}`,
    bindings: [...exactBindings, ...(authorizing ? currentBindings(pin) : [])] };
}

export async function beginGeneralSharedTelegramReply(
  db: D1Database, pin: GeneralTelegramPin, lease: SharedReadLease, tickets: readonly TelegramLifecycleTicket[] = [],
  metadata?: MetadataReply,
): Promise<boolean> {
  if (!pin.sharedOutbox || Boolean(metadata) !== (lease.marker === GENERAL_SUBSCRIPTION_READ_MARKER)) return false;
  if ((tickets.length > 0 || metadata) && (!pin.privateManagement || lease.chatType !== "private" || lease.threadId !== null)) return false;
  if (!pin.privateFormats && metadata?.tickets.some(({ kind }) => kind === "format")) return false;
  const begin = prepareTelegramOutboxBegin(db, lease, selectLease(pin, lease, true, metadata));
  const count = metadata?.tickets.length ?? tickets.length;
  if (count === 0) return await begin.first() !== null;
  if (!metadata && lease.marker !== GENERAL_LIFECYCLE_VIEW_MARKER && lease.marker !== GENERAL_LIFECYCLE_MARKER) return false;
  const write = metadata ? insertTelegramSubscriptionReadTickets(db, lease, metadata.tickets, 1, false, true)
    : insertTelegramLifecycleTickets(db, lease.receiptId, lease.attempts, lease.leaseId, tickets, 1, true);
  const results = await db.batch([begin, write]);
  const changed = results[0]?.results.length;
  if (results.length !== 2 || !results.every(({ success }) => success) || (changed !== 0 && changed !== 1)
    || results[1].meta.changes !== changed * count) throw new Error("General Telegram reply tickets could not be confirmed.");
  return changed === 1;
}

export async function drainGeneralSharedTelegramReply(
  db: D1Database, pin: GeneralTelegramPin, bucket: R2Bucket, publicOrigin: PublicOrigin,
): Promise<boolean> {
  const lease = await claimGeneralSharedTelegramReply(db, pin);
  if (!lease) return false;
  if (lease.marker === GENERAL_SUBSCRIPTION_READ_MARKER) {
    const presentation = await renderGeneralSubscriptionRead(db, pin, lease, bucket, publicOrigin);
    if (!presentation?.readGuard) return false;
    const prepared = presentation.readButtons?.length ? await prepareTelegramSubscriptionReadTickets(presentation.readButtons) : undefined;
    if (!await beginGeneralSharedTelegramReply(db, pin, lease, [], { ...presentation.readGuard, tickets: prepared?.tickets ?? [] })) return false;
    const confirmed = await confirmTelegramSubscriptionReadSend(db, pin, lease, presentation.readGuard).catch(() => false);
    const outcome = confirmed
      ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, presentation.text, prepared?.keyboard)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  let presentation: ReturnType<typeof renderTelegramLifecycle>;
  if (lease.marker === GENERAL_LIFECYCLE_MARKER && lease.actionKind !== null && lease.actionSubscriptionId !== null
    && lease.actionRevision !== null) {
    presentation = renderTelegramLifecycle({ kind: lease.actionKind, subscriptionId: lease.actionSubscriptionId,
      expectedLifecycleRevision: lease.actionRevision });
  } else if (lease.marker === GENERAL_LIFECYCLE_VIEW_MARKER && lease.viewKind !== null) {
    const view = await renderTelegramView(db, lease.actorId, { kind: lease.viewKind, afterId: null, afterEpoch: null });
    presentation = { text: view.text, buttons: view.lifecycleButtons, forceReply: false };
  } else if (lease.marker === GENERAL_PATH_MARKER) {
    const path = await db.prepare(`SELECT kind,after_id AS afterId,affected_count AS affectedCount
      FROM telegram_path_reply WHERE receipt_id=?`).bind(lease.receiptId).first<TelegramPathReply>();
    if (!path) throw new Error("General Telegram path reply could not be confirmed.");
    presentation = { text: await renderTelegramPath(db, lease.actorId, path), buttons: [], forceReply: false };
  } else if (lease.marker === TELEGRAM_GENERAL_TEMP_MARKER) {
    const temp = await db.prepare(`SELECT kind,node_count AS nodeCount,total_count AS totalCount,malformed_count AS malformedCount,
      unsupported_count AS unsupportedCount,ignored_count AS ignoredCount FROM telegram_temp_reply WHERE receipt_id=?`)
      .bind(lease.receiptId).first<TelegramTempReply>();
    if (!temp) throw new Error("General Telegram temporary node reply could not be confirmed.");
    presentation = { text: renderTelegramTemp(temp), buttons: [], forceReply: false };
  } else if (lease.marker === TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER) {
    const document = await db.prepare(`SELECT job.result_code AS kind,saved.node_count AS nodeCount
      FROM telegram_document_jobs AS job LEFT JOIN telegram_document_saved_counts AS saved USING (receipt_id)
      WHERE job.receipt_id=? AND job.bot_id=? AND job.actor_id=? AND job.state='done'`)
      .bind(lease.receiptId, pin.botId, lease.actorId).first<{ kind: TelegramDocumentJobResult; nodeCount: number | null }>();
    if (!document || (document.kind === "saved" && document.nodeCount === null)) {
      throw new Error("General Telegram document reply could not be confirmed.");
    }
    presentation = { text: renderTelegramDocumentOutcome(document.kind, document.nodeCount), buttons: [], forceReply: false };
  } else {
    const text = await renderGeneralReadReply(db, lease.actorId, lease.command);
    const privateHelp = pin.privateManagement && lease.command === "help";
    const help = privateHelp ? text + "\n/recycle 查看你的回收站\n/s 名称关键词 搜索你的订阅\n/path 管理你的路径规则" : text;
    presentation = { text: privateHelp && pin.privateTemp ? help + "\n/temp 查看临时节点数量" : help, buttons: [], forceReply: false };
  }
  const prepared = presentation.buttons.length ? await prepareTelegramLifecycleTickets(presentation.buttons) : undefined;
  if (!await beginGeneralSharedTelegramReply(db, pin, lease, prepared?.tickets)) return false;
  const outcome = lease.chatType === "private"
    ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, presentation.text,
      prepared?.keyboard, presentation.forceReply)
    : await sendGeneralTelegramGroupListReply(pin.botToken, lease.chatId, lease.messageId, lease.threadId, presentation.text);
  await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
  return true;
}

export async function recoverGeneralSharedTelegramReplies(
  db: D1Database, pin: GeneralTelegramPin, bucket: R2Bucket, publicOrigin: PublicOrigin,
): Promise<void> {
  if (!pin.sharedOutbox) return;
  const group = !pin.rehearsal && await groupSchemaReady(db);
  const markers = queueMarkers(group, pin);
  await db.prepare(`UPDATE telegram_outbox SET state=CASE WHEN state='sending' THEN 'uncertain' ELSE 'failed' END,
      lease_id=CASE WHEN state='sending' THEN lease_id ELSE NULL END,lease_until=NULL
    WHERE receipt_id IN (SELECT inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
      WHERE inbox.bot_id=? AND inbox.receipt_nonce IN (${markers}) AND ((reply.state='sending' AND reply.lease_until<=unixepoch())
        OR (reply.state IN ('pending','leased') AND (NOT (${current("inbox", group, pin)})
          OR (reply.attempts>=${TELEGRAM_OUTBOX_MAX_ATTEMPTS} AND (reply.state='pending' OR reply.lease_until<=unixepoch())))))
      ORDER BY inbox.receipt_id LIMIT 16)
      AND EXISTS (SELECT 1 FROM telegram_general_policy AS policy WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA})`)
    .bind(pin.botId, ...currentBindings(pin), ...generalPolicyBindings(pin)).run();
  if (pin.privateManagement) {
    await reapTelegramLifecycle(db, pin.botId);
    await reapTelegramSubscriptionReadTickets(db, pin.botId);
  }
  for (let i = 0; i < 4 && await drainGeneralSharedTelegramReply(db, pin, bucket, publicOrigin); i++) {
    // Bound scheduled work and preserve the ordinary outbox's lease and settlement semantics.
  }
}

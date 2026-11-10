import { TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER } from "../provider-jobs.ts";
import { digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { prepareOwnedSubscriptionMutation, readLegacySelectedRetirement } from "../subscriptions.ts";
import { inTelegramScope, BULK_TRASH_TICKET, type TelegramBulkTrashUpdate, type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";
import { failedBatchTrashOrigin, readFailedBatchTrash, type FailedBatchTrashSelection } from "./provider-batch-failed-trash.ts";
import { selectedQuery, unicode14Lower } from "./selected-search.ts";
import { displayTelegramName } from "./views.ts";

export const TELEGRAM_BULK_TRASH_MARKER = "bulktrash:v1";
const MAX_TARGETS = 16;
const MAX_SCAN_ROWS = 512;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const SCAN_PAGE_SIZE = 16;
const TICKET_SECONDS = 600;
const encoder = new TextEncoder();
const FRESH = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
const CARRIER = "(bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)";
const CARRIER_VALUES = "?,?,?,?,'private',?,?,NULL,'help',?";
const FRESH_ACTION = "? BETWEEN unixepoch()-900 AND unixepoch()+30 AND (?=? OR COALESCE((SELECT allowed=1 AND message_date<? FROM telegram_auth WHERE bot_id=? AND user_id=?),1))";
const DEDUP = "ON CONFLICT(bot_id,update_id) DO NOTHING";
const AUTH_JOIN = "LEFT JOIN telegram_auth AS auth ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id AND incoming.actor_id<>?";
const ACTION_FIELDS = "receipt_id,kind,target_count,targets,actor_role,auth_message_date,auth_message_id";

type Target = [id: number, generation: number, revision: number];
type Scan = { kind: "usage" | "limit" } | { kind: "scanned"; inventory: string; targets: string; count: number };
type ReplyKind = "usage" | "empty" | "limit" | "preview" | "stale" | "trashed";
type Lease = Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId">
  & { receiptId: number; leaseId: string; attempts: number };
export type BulkTrashGuard = { sql: string; bindings: readonly (string | number)[] };
type Rendered = { text: string; guard: BulkTrashGuard; ticket?: { token: string; sha256: string } };
type TrashTicket = NonNullable<Rendered["ticket"]>;
export type FailedBatchTrashOffer = FailedBatchTrashSelection & TrashTicket;

function targetsFrom(value: string): Target[] {
  const targets: unknown = JSON.parse(value);
  if (!Array.isArray(targets) || !validInteger(targets.length, 1, MAX_TARGETS) || JSON.stringify(targets) !== value) {
    throw new Error("Invalid bulk trash targets.");
  }
  let previous = 0;
  for (const target of targets) {
    if (!Array.isArray(target) || target.length !== 3 || !validInteger(target[0], previous + 1)
      || !validInteger(target[1], 0) || !validInteger(target[2], 0, Number.MAX_SAFE_INTEGER - 1)) {
      throw new Error("Invalid bulk trash target.");
    }
    previous = target[0];
  }
  return targets as Target[];
}

function currentTargets(targets: string, owner: string): string {
  return `NOT EXISTS (SELECT 1 FROM json_each(${targets}) AS expected
    LEFT JOIN subscriptions AS sub ON sub.id=json_extract(expected.value,'$[0]') AND sub.owner_id=${owner}
    LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
    WHERE sub.id IS NULL OR sub.generation<>json_extract(expected.value,'$[1]')
      OR COALESCE(lifecycle.revision,0)<>json_extract(expected.value,'$[2]')
      OR EXISTS (SELECT 1 FROM subscription_trash WHERE id=sub.id))`;
}

function currentRole(inbox: "origin" | "inbox", action: "preview" | "action", callback = false): string {
  return `((${inbox}.actor_id=? AND ${action}.actor_role='admin') OR (
    ${inbox}.actor_id=? AND ${action}.actor_role='member' AND COALESCE(auth.allowed,1)=1
    AND ${action}.auth_message_date=COALESCE(auth.message_date,0) AND ${action}.auth_message_id=COALESCE(auth.message_id,0)
    AND ${inbox}.message_date>COALESCE(auth.message_date,0) ${callback ? "AND ?>COALESCE(auth.message_date,0)" : ""}))`;
}

async function scanTargets(db: D1Database, owner: string, query: string): Promise<Scan> {
  const needle = selectedQuery(query);
  if (needle === "") return { kind: "usage" };
  if (needle === null) return { kind: "limit" };
  const inventory: Target[] = [];
  const targets: Target[] = [];
  const deadline = Date.now() + 5_000;
  let bytes = 0;
  let after = 0;
  for (;;) {
    if (Date.now() >= deadline) return { kind: "limit" };
    const page = await db.prepare(`SELECT id,name,source_url AS sourceUrl,generation,${SUBSCRIPTION_LIFECYCLE_REVISION} AS revision
      FROM subscriptions WHERE owner_id=? AND id>? ORDER BY id LIMIT ${SCAN_PAGE_SIZE}`)
      .bind(owner, after).all<{ id: number; name: string; sourceUrl: string; generation: number; revision: number }>();
    if (!page.success) throw new Error("Bulk trash inventory unavailable.");
    for (const { id, name, sourceUrl, generation, revision } of page.results) {
      if (!validInteger(id, after + 1) || !validInteger(generation, 0) || !validInteger(revision, 0)
        || typeof name !== "string" || typeof sourceUrl !== "string") throw new Error("Invalid bulk trash inventory.");
      after = id;
      bytes += encoder.encode(name).byteLength + encoder.encode(sourceUrl).byteLength;
      if (inventory.length === MAX_SCAN_ROWS || bytes > MAX_SCAN_BYTES || Date.now() >= deadline) return { kind: "limit" };
      const target: Target = [id, generation, revision];
      inventory.push(target);
      if (unicode14Lower(`${name} ${sourceUrl}`).includes(needle)) {
        if (targets.length === MAX_TARGETS || revision === Number.MAX_SAFE_INTEGER) return { kind: "limit" };
        targets.push(target);
      }
    }
    if (page.results.length < SCAN_PAGE_SIZE) break;
  }
  return { kind: "scanned", inventory: JSON.stringify(inventory), targets: JSON.stringify(targets), count: targets.length };
}

export async function telegramBulkTrashReady(db: D1Database): Promise<boolean> {
  try {
    return await db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='telegram_bulk_trash'").first() !== null;
  } catch {
    throw new Error("Telegram bulk trash schema could not be confirmed.");
  }
}

function digestTicket(token: string): Promise<string> {
  return crypto.subtle.digest("SHA-256", encoder.encode(token)).then(digestHex);
}

async function mintTrashTicket(): Promise<TrashTicket> {
  const token = "sbd1_" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  return { token, sha256: await digestTicket(token) };
}

export async function prepareFailedBatchTrashOffer(
  db: D1Database, policy: TelegramPolicy, lease: Lease,
): Promise<FailedBatchTrashOffer | null> {
  try {
    if (!await telegramBulkTrashReady(db)) return null;
    const selection = await readFailedBatchTrash(db, policy, lease.actorId, lease.receiptId);
    return selection ? { ...selection, ...await mintTrashTicket() } : null;
  } catch {
    // A failed cleanup proof must not prevent the terminal report.
    return null;
  }
}

export function installFailedBatchTrashTicket(db: D1Database, lease: Lease, offer: FailedBatchTrashOffer): D1PreparedStatement {
  return db.prepare(`INSERT INTO telegram_bulk_trash
    (${ACTION_FIELDS},token_sha256,origin_attempt,expires_at)
    SELECT terminal.receipt_id,'preview',?,?,terminal.actor_role,terminal.auth_message_date,terminal.auth_message_id,
      ?,reply.attempts,min(unixepoch()+${TICKET_SECONDS},terminal.ready_at+900)
    FROM telegram_provider_batch_interactions AS terminal JOIN telegram_outbox AS reply USING(receipt_id)
    WHERE changes()=1 AND terminal.receipt_id=? AND terminal.kind='terminal' AND terminal.batch_id=terminal.receipt_id
      AND terminal.ready_at+900>unixepoch() AND reply.state='sending' AND reply.lease_id=? AND reply.attempts=?
      AND (${offer.guard.sql})
    ON CONFLICT(receipt_id) DO UPDATE SET token_sha256=excluded.token_sha256,
      origin_attempt=excluded.origin_attempt,expires_at=excluded.expires_at
    WHERE telegram_bulk_trash.kind='preview' AND telegram_bulk_trash.confirmed_by_receipt_id IS NULL
      AND telegram_bulk_trash.targets=excluded.targets`)
    .bind(offer.count, offer.targets, offer.sha256, lease.receiptId, lease.leaseId, lease.attempts, ...offer.guard.bindings);
}

export async function acceptTelegramBulkTrash(
  db: D1Database, policy: TelegramPolicy, event: TelegramBulkTrashUpdate,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.threadId !== null
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)
    || (event.kind === "confirm" && !BULK_TRASH_TICKET.test(event.ticket))) return "ignored";
  const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
  const scope = [policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, key[2]] as const;
  const auth = [event.messageDate, event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId] as const;
  const statements: D1PreparedStatement[] = [];
  try {
    if (event.kind === "preview") {
      if (!await db.prepare(`SELECT 1 WHERE ${FRESH_ACTION} AND NOT EXISTS (
        SELECT 1 FROM telegram_inbox WHERE bot_id=? AND update_id=?)`).bind(...auth, policy.botId, event.updateId).first()) return "ignored";
      const scan = await scanTargets(db, event.actorId, event.query);
      const actorRole = event.actorId === policy.adminId ? "admin" : "member";
      statements.push(db.prepare(`INSERT INTO telegram_inbox ${CARRIER} SELECT ${CARRIER_VALUES} WHERE ${FRESH_ACTION} ${DEDUP}`)
        .bind(...scope, ...auth));
      if (scan.kind === "scanned") {
        statements.push(db.prepare(`WITH checked AS (
          SELECT incoming.receipt_id, (SELECT count(*) FROM subscriptions WHERE owner_id=incoming.actor_id)=json_array_length(?)
            AND ${currentTargets("?", "incoming.actor_id")} AS stable,
            COALESCE(auth.message_date,0) AS auth_date,COALESCE(auth.message_id,0) AS auth_id
          FROM telegram_inbox AS incoming ${AUTH_JOIN} WHERE ${FRESH}
        ) INSERT INTO telegram_bulk_trash (${ACTION_FIELDS})
        SELECT receipt_id,CASE WHEN NOT stable THEN 'stale' WHEN ?=0 THEN 'empty' ELSE 'preview' END,
          CASE WHEN stable THEN ? ELSE 0 END,CASE WHEN stable AND ?>0 THEN ? END,?,auth_date,auth_id FROM checked`)
          .bind(scan.inventory, scan.inventory, policy.adminId, ...key, scan.count, scan.count, scan.count, scan.targets, actorRole));
      } else {
        statements.push(db.prepare(`INSERT INTO telegram_bulk_trash (${ACTION_FIELDS})
          SELECT incoming.receipt_id,?,0,NULL,?,COALESCE(auth.message_date,0),COALESCE(auth.message_id,0)
          FROM telegram_inbox AS incoming ${AUTH_JOIN} WHERE ${FRESH}`).bind(scan.kind, actorRole, policy.adminId, ...key));
      }
    } else {
      const digest = await digestTicket(event.ticket);
      const origin = `FROM telegram_bulk_trash AS preview JOIN telegram_inbox AS origin USING(receipt_id)
        JOIN telegram_outbox AS reply USING(receipt_id)
        LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id
        WHERE preview.kind='preview' AND preview.token_sha256=? AND preview.confirmed_by_receipt_id IS NULL
          AND preview.expires_at>unixepoch()
          AND origin.receipt_nonce IN ('${TELEGRAM_BULK_TRASH_MARKER}','${TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER}')
          AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type='private' AND origin.thread_id IS NULL
          AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=preview.origin_attempt
          AND ? BETWEEN unixepoch()-900 AND unixepoch()+30
          AND ${currentRole("origin", "preview", true)}`;
      const originArgs = [digest, policy.botId, event.actorId, event.chatId, event.messageId,
        event.messageDate, policy.adminId, policy.memberId, event.messageDate] as const;
      const candidate = await db.prepare(`SELECT preview.targets,preview.target_count AS count,
        origin.receipt_id AS receiptId,origin.receipt_nonce AS marker ${origin}`)
        .bind(...originArgs).first<{ targets: string; count: number; receiptId: number; marker: string }>();
      if (!candidate) return "ignored";
      const targets = targetsFrom(candidate.targets);
      if (targets.length !== candidate.count) throw new Error("Invalid bulk trash target count.");
      const fromBatch = candidate.marker === TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER;
      const batchOrigin = fromBatch ? failedBatchTrashOrigin(policy, event.actorId, candidate.receiptId) : null;
      const selection = fromBatch ? await readFailedBatchTrash(db, policy, event.actorId, candidate.receiptId) : null;
      const stable = fromBatch
        ? (selection?.targets === candidate.targets ? selection.guard : { sql: "0", bindings: [] })
        : { sql: "1", bindings: [] };
      statements.push(
        db.prepare(`INSERT INTO telegram_inbox ${CARRIER} SELECT ${CARRIER_VALUES} ${origin}
          AND origin.receipt_id=? AND origin.receipt_nonce=? AND preview.targets=? AND preview.target_count=?
          ${batchOrigin ? `AND (${batchOrigin.sql})` : ""} ${DEDUP}`)
          .bind(...scope, ...originArgs, candidate.receiptId, candidate.marker, candidate.targets, candidate.count,
            ...(batchOrigin?.bindings ?? [])),
        db.prepare(`UPDATE telegram_bulk_trash AS preview SET confirmed_by_receipt_id=incoming.receipt_id
          FROM telegram_inbox AS incoming WHERE preview.token_sha256=? AND preview.confirmed_by_receipt_id IS NULL AND ${FRESH}`)
          .bind(digest, ...key),
        db.prepare(`WITH checked AS (
          SELECT incoming.receipt_id,preview.target_count,
            ${currentTargets("preview.targets", "incoming.actor_id")} AND (${stable.sql}) AS stable,
            preview.actor_role,preview.auth_message_date,preview.auth_message_id
          FROM telegram_inbox AS incoming JOIN telegram_bulk_trash AS preview ON preview.confirmed_by_receipt_id=incoming.receipt_id
          WHERE ${FRESH}
        ) INSERT INTO telegram_bulk_trash (${ACTION_FIELDS})
        SELECT receipt_id,CASE WHEN stable THEN 'trashed' ELSE 'stale' END,CASE WHEN stable THEN target_count ELSE 0 END,
          NULL,actor_role,auth_message_date,auth_message_id FROM checked`).bind(...stable.bindings, ...key),
      );
      const retirement = await readLegacySelectedRetirement(db);
      for (const [id, generation, revision] of targets) {
        const move = await prepareOwnedSubscriptionMutation(db, { id, ownerId: event.actorId, expectedLifecycleRevision: revision },
          { kind: "trash" }, {
            sql: `generation=? AND EXISTS (SELECT 1 FROM telegram_inbox AS incoming JOIN telegram_bulk_trash AS action USING(receipt_id)
              WHERE ${FRESH} AND action.kind='trashed')`,
            bindings: [generation, ...key],
          }, retirement);
        statements.push(move.first, ...move.followups);
      }
    }

    // The inbox command is NOT NULL. A partial or unverified move fails inside the D1 transaction.
    statements.push(
      db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT receipt_id FROM telegram_inbox AS incoming WHERE ${FRESH}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_bulk_trash AS action JOIN telegram_outbox USING(receipt_id)
        LEFT JOIN telegram_bulk_trash AS preview ON preview.confirmed_by_receipt_id=action.receipt_id
        WHERE action.receipt_id=incoming.receipt_id AND (action.kind<>'trashed' OR (
          action.target_count=preview.target_count AND NOT EXISTS (
            SELECT 1 FROM json_each(preview.targets) AS expected
            LEFT JOIN subscription_trash AS trash ON trash.id=json_extract(expected.value,'$[0]') AND trash.owner_id=incoming.actor_id
            LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=trash.id
            WHERE trash.id IS NULL OR trash.generation<>json_extract(expected.value,'$[1]')
              OR trash.lifecycle_revision<>json_extract(expected.value,'$[2]')+1
              OR lifecycle.revision IS NOT trash.lifecycle_revision
              OR EXISTS (SELECT 1 FROM subscriptions WHERE id=trash.id)
          )))
      ) THEN command END WHERE ${FRESH} RETURNING receipt_id`).bind(TELEGRAM_BULK_TRASH_MARKER, ...key),
    );
    const results = await db.batch(statements);
    const receipt = results.at(-1);
    if (receipt && results.length === statements.length && results.every(({ success }) => success) && receipt.results.length <= 1) {
      return receipt.results.length ? "accepted" : "ignored";
    }
  } catch {
    // Backend errors may contain private subscription data.
  }
  throw new Error("Telegram bulk trash receipt could not be confirmed.");
}

const notices: Record<Exclude<ReplyKind, "preview" | "trashed">, string> = {
  usage: "用法：/d 关键词或订阅链接。",
  empty: "没有匹配订阅。",
  limit: "查询超过处理上限或匹配超过 16 条订阅。请缩小范围后重新查询。",
  stale: "订阅已变更，本次未移动任何订阅。请重新发送 /d。",
};

function replyScope(state: "leased" | "sending"): string {
  return `inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND inbox.chat_type='private'
    AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL AND inbox.receipt_nonce='${TELEGRAM_BULK_TRASH_MARKER}'
    AND reply.state='${state}' AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()`;
}

function replyArgs(policy: TelegramPolicy, lease: Lease) {
  return [lease.receiptId, policy.botId, lease.actorId, lease.chatId, lease.leaseId, lease.attempts] as const;
}

export async function renderTelegramBulkTrash(db: D1Database, policy: TelegramPolicy, lease: Lease): Promise<Rendered | null> {
  if (!inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return null;
  const guard: BulkTrashGuard = { sql: `inbox.receipt_nonce='${TELEGRAM_BULK_TRASH_MARKER}' AND EXISTS (
    SELECT 1 FROM telegram_bulk_trash AS action LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id
    WHERE action.receipt_id=inbox.receipt_id AND ${currentRole("inbox", "action")})`, bindings: [policy.adminId, policy.memberId] };
  const action = await db.prepare(`SELECT action.kind,action.targets,action.target_count AS count,
    EXISTS (SELECT 1 FROM telegram_bulk_trash AS preview JOIN telegram_inbox AS origin USING(receipt_id)
      WHERE preview.confirmed_by_receipt_id=action.receipt_id
        AND origin.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER}') AS fromBatch
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
    JOIN telegram_bulk_trash AS action USING(receipt_id)
    WHERE ${replyScope("leased")} AND (${guard.sql})`).bind(...replyArgs(policy, lease), ...guard.bindings)
    .first<{ kind: ReplyKind; targets: string | null; count: number; fromBatch: number }>();
  if (!action) return null;
  if (action.kind === "trashed") return { text: `已将 ${action.count} 条订阅移入回收站。30 天内可通过 /recycle 恢复。`, guard };
  if (action.kind === "stale" && action.fromBatch === 1) {
    return { text: "本批失败项已变更，本次未移动任何订阅。", guard };
  }
  if (action.kind !== "preview") return { text: notices[action.kind], guard };
  if (action.targets === null || targetsFrom(action.targets).length !== action.count) throw new Error("Invalid bulk trash preview.");
  const rows = await db.prepare(`SELECT sub.name FROM json_each(?) AS expected
    JOIN subscriptions AS sub ON sub.id=json_extract(expected.value,'$[0]') AND sub.owner_id=?
    LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
    WHERE sub.generation=json_extract(expected.value,'$[1]') AND COALESCE(lifecycle.revision,0)=json_extract(expected.value,'$[2]')
      AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE id=sub.id) ORDER BY CAST(expected.key AS INTEGER)`)
    .bind(action.targets, lease.actorId).all<{ name: string }>();
  if (!rows.success) throw new Error("Telegram bulk trash preview could not be read.");
  if (rows.results.length !== action.count) return { text: notices.stale, guard };
  return {
    text: [`确认将以下 ${action.count} 条订阅移入回收站？`, ...rows.results.map(({ name }, i) => `${i + 1}. ${displayTelegramName(name)}`),
      "30 天内可通过 /recycle 恢复。"].join("\n"),
    guard: { sql: `(${guard.sql}) AND EXISTS (SELECT 1 FROM telegram_bulk_trash AS preview WHERE preview.receipt_id=inbox.receipt_id
      AND preview.kind='preview' AND preview.targets=? AND preview.confirmed_by_receipt_id IS NULL
      AND ${currentTargets("preview.targets", "inbox.actor_id")})`, bindings: [...guard.bindings, action.targets] },
    ticket: await mintTrashTicket(),
  };
}

export function installTelegramBulkTrashTicket(db: D1Database, lease: Lease, sha256: string): D1PreparedStatement {
  return db.prepare(`UPDATE telegram_bulk_trash SET token_sha256=?,origin_attempt=?,expires_at=unixepoch()+${TICKET_SECONDS}
    WHERE changes()=1 AND receipt_id=? AND kind='preview' AND confirmed_by_receipt_id IS NULL
      AND EXISTS (SELECT 1 FROM telegram_outbox AS reply WHERE reply.receipt_id=telegram_bulk_trash.receipt_id
        AND reply.state='sending' AND reply.lease_id=? AND reply.attempts=?)`).bind(sha256, lease.attempts, lease.receiptId, lease.leaseId, lease.attempts);
}

export async function confirmTelegramBulkTrashSend(
  db: D1Database, policy: TelegramPolicy, lease: Lease, guard: BulkTrashGuard, ticketSha256?: string,
): Promise<boolean> {
  try {
    const ticket = ticketSha256 ? `AND EXISTS (SELECT 1 FROM telegram_bulk_trash AS preview
      WHERE preview.receipt_id=inbox.receipt_id AND preview.token_sha256=? AND preview.origin_attempt=reply.attempts
        AND preview.expires_at>unixepoch() AND preview.confirmed_by_receipt_id IS NULL)` : "";
    return await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE ${replyScope("sending")} AND (${guard.sql}) ${ticket}`)
      .bind(...replyArgs(policy, lease), ...guard.bindings, ...(ticketSha256 ? [ticketSha256] : [])).first() !== null;
  } catch {
    return false;
  }
}

export async function closeUnsentTelegramBulkTrashReply(db: D1Database, policy: TelegramPolicy, lease: Lease): Promise<void> {
  const result = await db.prepare(`UPDATE telegram_outbox SET state='failed',lease_id=NULL,lease_until=NULL WHERE receipt_id=(
    SELECT inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id) WHERE ${replyScope("leased")}
  )`).bind(...replyArgs(policy, lease)).run();
  if (!result.success) throw new Error("Telegram bulk trash reply could not be closed.");
}

import {
  PROVIDER_API_STATUS_MAX_ELAPSED_MS, type ProviderApiStatusV2Prober, type ProviderPin,
} from "../provider-fetch-contract.ts";
import { classifyTelegramApiStatusInput, TELEGRAM_API_STATUS_PROMPT, type TelegramApiStatusRow } from "./api-status-input.ts";
import { isolatedTelegramRoleEpochSql } from "./authorization-sql.ts";
import { inTelegramScope, type TelegramApiStatusUpdate, type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_API_STATUS_MARKER = "api-status:v1";
const PROMPT_SECONDS = 300;
const WORK_SECONDS = 90;
const REPLY_SECONDS = 900;
const BUDGET_MS = 26_000;
const RPC_MS = 20_000;
const RECOVERY_LIMIT = 12;
const STRIDE = 16_000;
const PENDING = -1, STARTED = -2, UNAVAILABLE = -3, INVALID = -4, CANCELLED = -5, TIMEOUT = -6, REJECTED = -7;
type Column = "row_one" | "row_two";
type Alias = "inbox" | "earlier";
type Guard = { sql: string; bindings: readonly (string | number | null)[] };
type Scope = Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId">;
type Lease = Scope & { receiptId: number; leaseId: string; attempts: number };
type Reply = Extract<TelegramApiStatusUpdate, { kind: "reply" }>;
type Prompt = { receiptId: number; role: "admin" | "member"; authDate: number; authId: number };
type Accepted = { receiptId: number; rows: readonly TelegramApiStatusRow[] };
type Presentation = { promptId: number | null; first: number | null; second: number | null; readyAt: number; expiresAt: number };

function isPrivate(policy: TelegramPolicy, event: Scope): boolean {
  return event.chatType === "private" && event.threadId === null && inTelegramScope(policy, event);
}

function scopeSql(alias: Alias): string {
  return `${alias}.receipt_nonce='${TELEGRAM_API_STATUS_MARKER}' AND ${alias}.command='help'
    AND ${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL`;
}

function readySql(alias: Alias): string {
  return `origin.receipt_id=${alias}.receipt_id AND origin.ready_at IS NOT NULL
    AND (origin.prompt_receipt_id IS NOT NULL OR origin.expires_at>unixepoch())`;
}

export function telegramApiStatusReceipt(alias: Alias): string {
  return `(${scopeSql(alias)} AND EXISTS (SELECT 1 FROM telegram_api_status AS origin
    WHERE origin.receipt_id=${alias}.receipt_id AND origin.ready_at IS NOT NULL))`;
}

export function telegramApiStatusClock(alias: Alias, fallback: string): string {
  return `CASE WHEN ${alias}.receipt_nonce='${TELEGRAM_API_STATUS_MARKER}' THEN
    (SELECT ready_at FROM telegram_api_status WHERE receipt_id=${alias}.receipt_id) ELSE ${fallback} END`;
}

export function telegramApiStatusEligible(policy: TelegramPolicy | undefined, alias: Alias): Guard {
  if (!policy) return { sql: "1", bindings: [] };
  const epoch = isolatedTelegramRoleEpochSql(policy, alias);
  return { sql: `(${alias}.receipt_nonce IS NOT '${TELEGRAM_API_STATUS_MARKER}' OR EXISTS (
    SELECT 1 FROM telegram_api_status AS origin WHERE ${readySql(alias)} AND ${epoch.sql}))`, bindings: epoch.bindings };
}

export async function telegramApiStatusReady(db: D1Database): Promise<boolean> {
  try {
    const count = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE tbl_name='telegram_api_status'
      AND ((type='table' AND name=tbl_name)
        OR (type='index' AND name IN ('telegram_api_status_expiry','telegram_api_status_ready')))`).first<number>("present");
    if (count !== 0 && count !== 3) throw new Error();
    return count === 3;
  } catch {
    throw new Error("Telegram API status schema could not be confirmed.");
  }
}

const fresh = "bot_id=? AND update_id=? AND receipt_nonce=?";
const age = "? BETWEEN unixepoch()-900 AND unixepoch()+30";
const latestPrompt = `NOT EXISTS (SELECT 1 FROM telegram_inbox AS newer JOIN telegram_api_status AS other USING(receipt_id)
    WHERE newer.bot_id=inbox.bot_id AND newer.actor_id=inbox.actor_id AND newer.chat_id=inbox.chat_id
      AND newer.receipt_nonce='${TELEGRAM_API_STATUS_MARKER}' AND other.prompt_receipt_id IS NULL
      AND (newer.message_date,newer.message_id)>(inbox.message_date,inbox.message_id))`;

function inboxInsert(db: D1Database, policy: TelegramPolicy, event: TelegramEventScope, nonce: string, guard: Guard) {
  return db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
    SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE ${guard.sql}
    ON CONFLICT(bot_id,update_id) DO NOTHING`)
    .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce, ...guard.bindings);
}

function finishAdmission(db: D1Database, key: readonly [string, number, string]) {
  return db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce=?,command=CASE WHEN EXISTS (
    SELECT 1 FROM telegram_api_status WHERE receipt_id=inbox.receipt_id
  ) THEN command END WHERE ${fresh} RETURNING receipt_id AS receiptId`).bind(TELEGRAM_API_STATUS_MARKER, ...key);
}

async function accept(db: D1Database, steps: D1PreparedStatement[]): Promise<number | null> {
  const result = await db.batch<{ receiptId: number }>(steps);
  const rows = result.at(-1)?.results;
  if (result.length !== steps.length || !rows || rows.length > 1
    || result.some(({ success, meta }) => !success || meta.changes !== rows.length)) throw new Error();
  return rows[0]?.receiptId ?? null;
}

export async function acceptTelegramApiStatusPrompt(db: D1Database, policy: TelegramPolicy, event: TelegramEventScope): Promise<boolean> {
  if (!isPrivate(policy, event)) return false;
  try {
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const guard = {
      sql: `${age} AND (?=? OR COALESCE((SELECT allowed=1 AND message_date<? FROM telegram_auth
        WHERE bot_id=? AND user_id=?),1)) AND NOT EXISTS (SELECT 1 FROM telegram_inbox AS previous
        JOIN telegram_api_status AS prompt USING(receipt_id) WHERE previous.bot_id=? AND previous.actor_id=?
        AND previous.chat_id=? AND previous.receipt_nonce='${TELEGRAM_API_STATUS_MARKER}' AND prompt.prompt_receipt_id IS NULL
        AND (previous.message_date,previous.message_id)>=(?,?))`,
      bindings: [event.messageDate, event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId,
        policy.botId, event.actorId, event.chatId, event.messageDate, event.messageId],
    };
    return await accept(db, [
      inboxInsert(db, policy, event, key[2], guard),
      db.prepare(`INSERT INTO telegram_api_status (receipt_id,actor_role,auth_message_date,auth_message_id,expires_at,ready_at)
        SELECT inbox.receipt_id,?,COALESCE(auth.message_date,0),COALESCE(auth.message_id,0),unixepoch()+${PROMPT_SECONDS},unixepoch()
        FROM telegram_inbox AS inbox LEFT JOIN telegram_auth AS auth
          ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id AND inbox.actor_id<>?
        WHERE inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce=?`)
        .bind(event.actorId === policy.adminId ? "admin" : "member", policy.adminId, ...key),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT receipt_id FROM telegram_inbox WHERE ${fresh}`).bind(...key),
      finishAdmission(db, key),
    ]) !== null;
  } catch {
    throw new Error("Telegram API status prompt could not be confirmed.");
  }
}

function promptGuard(policy: TelegramPolicy, event: Reply): Guard {
  const epoch = isolatedTelegramRoleEpochSql(policy, "inbox");
  return { sql: `inbox.bot_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND ${scopeSql("inbox")}
    AND origin.prompt_receipt_id IS NULL AND origin.expires_at>unixepoch()
    AND sent.state='sent' AND sent.sent_message_id=? AND sent.attempts>0
    AND ${age} AND ?>=inbox.message_date AND (origin.actor_role='admin' OR ?>origin.auth_message_date)
    AND ${epoch.sql} AND ${latestPrompt}
    AND NOT EXISTS(SELECT 1 FROM telegram_api_status AS consumed WHERE consumed.prompt_receipt_id=inbox.receipt_id)`,
  bindings: [policy.botId, event.actorId, event.chatId, event.promptMessageId, event.messageDate, event.messageDate,
    event.messageDate, ...epoch.bindings] };
}

const promptFrom = "FROM telegram_inbox AS inbox JOIN telegram_api_status AS origin USING(receipt_id) JOIN telegram_outbox AS sent USING(receipt_id)";

export async function acceptTelegramApiStatusReply(db: D1Database, policy: TelegramPolicy, event: Reply): Promise<Accepted | null> {
  if (!isPrivate(policy, event)) return null;
  try {
    const guard = promptGuard(policy, event);
    const prompt = await db.prepare(`SELECT inbox.receipt_id AS receiptId,origin.actor_role AS role,
      origin.auth_message_date AS authDate,origin.auth_message_id AS authId ${promptFrom} WHERE ${guard.sql}`)
      .bind(...guard.bindings).first<Prompt>();
    if (!prompt) return null;
    const decision = classifyTelegramApiStatusInput({ kind: "verified-prompt-reply", text: event.text });
    const rows = decision.kind === "batch" ? decision.rows : [];
    const rowCode = (row: TelegramApiStatusRow) => row.kind === "probe" ? PENDING : INVALID;
    const first = rows[0] ? rowCode(rows[0]) : decision.kind === "cancelled" ? CANCELLED : INVALID;
    const second = rows[1] ? rowCode(rows[1]) : null;
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const receiptId = await accept(db, [
      inboxInsert(db, policy, event, key[2], {
        sql: `EXISTS (SELECT 1 ${promptFrom} WHERE ${guard.sql} AND inbox.receipt_id=?)
          AND NOT EXISTS (SELECT 1 FROM telegram_api_status AS pending JOIN telegram_inbox AS earlier USING(receipt_id)
            WHERE earlier.bot_id=? AND earlier.actor_id=? AND pending.prompt_receipt_id IS NOT NULL
              AND pending.ready_at IS NULL AND pending.expires_at>unixepoch())`,
        bindings: [...guard.bindings, prompt.receiptId, policy.botId, event.actorId],
      }),
      db.prepare(`INSERT INTO telegram_api_status
        (receipt_id,prompt_receipt_id,actor_role,auth_message_date,auth_message_id,expires_at,row_one,row_two)
        SELECT receipt_id,?,?,?,?,unixepoch()+${WORK_SECONDS},?,? FROM telegram_inbox WHERE ${fresh}`)
        .bind(prompt.receiptId, prompt.role, prompt.authDate, prompt.authId, first, second, ...key),
      finishAdmission(db, key),
    ]);
    return receiptId === null ? null : { receiptId, rows };
  } catch {
    throw new Error("Telegram API status admission could not be confirmed.");
  }
}

function updateRow(db: D1Database, policy: TelegramPolicy, receiptId: number, column: Column, before: number, after: number) {
  const epoch = isolatedTelegramRoleEpochSql(policy, "inbox");
  return db.prepare(`UPDATE telegram_api_status AS action SET ${column}=?
    WHERE action.receipt_id=? AND action.prompt_receipt_id IS NOT NULL AND action.ready_at IS NULL
      AND action.expires_at>unixepoch() AND action.${column}=? AND EXISTS (
        SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_api_status AS origin USING(receipt_id)
        WHERE inbox.receipt_id=action.receipt_id AND inbox.bot_id=? AND ${scopeSql("inbox")} AND ${epoch.sql})
    RETURNING expires_at AS expiresAt`).bind(after, receiptId, before, policy.botId, ...epoch.bindings);
}

async function probe(provider: ProviderApiStatusV2Prober, row: Extract<TelegramApiStatusRow, { kind: "probe" }>,
  pin: ProviderPin, dispatchBeforeMs: number): Promise<number> {
  const timeout = dispatchBeforeMs - Date.now();
  if (timeout <= 0) return TIMEOUT;
  const timedOut = Symbol();
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result: unknown = await Promise.race([
      provider.probeApiStatusV2(row.credentials.toProviderInput(pin, dispatchBeforeMs)),
      new Promise((resolve) => { timer = setTimeout(() => resolve(timedOut), timeout); }),
    ]);
    if (result === timedOut) return TIMEOUT;
    if (typeof result !== "object" || Array.isArray(result) || !result) return UNAVAILABLE;
    const value = result as Record<string, unknown>;
    if (value.ok === true && Object.keys(value).length === 3 && typeof value.status === "number"
      && Number.isInteger(value.status) && value.status >= 100 && value.status <= 599
      && typeof value.elapsedMs === "number" && Number.isInteger(value.elapsedMs)
      && value.elapsedMs >= 0 && value.elapsedMs <= PROVIDER_API_STATUS_MAX_ELAPSED_MS) return value.status * STRIDE + value.elapsedMs;
    if (value.ok === false && Object.keys(value).length === 2) {
      if (value.code === "timeout") return TIMEOUT;
      if (value.code === "invalid-request" || value.code === "invalid-url" || value.code === "invalid-auth"
        || value.code === "blocked-address") return REJECTED;
    }
    return UNAVAILABLE;
  } catch {
    return UNAVAILABLE;
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export async function runTelegramApiStatus(db: D1Database, policy: TelegramPolicy, provider: ProviderApiStatusV2Prober, pin: ProviderPin,
  accepted: Accepted): Promise<void> {
  const deadline = Date.now() + BUDGET_MS;
  for (const [index, row] of accepted.rows.entries()) {
    if (row.kind !== "probe") continue;
    const column = index === 0 ? "row_one" : "row_two";
    if (Date.now() >= deadline) break;
    const expiresAt = await updateRow(db, policy, accepted.receiptId, column, PENDING, STARTED).first<number>("expiresAt");
    if (expiresAt === null) break;
    const dispatchBeforeMs = Math.min(expiresAt * 1000, deadline, Date.now() + RPC_MS);
    const outcome = await probe(provider, row, pin, dispatchBeforeMs);
    if (await updateRow(db, policy, accepted.receiptId, column, STARTED, outcome).first() === null) break;
  }
}

export async function reconcileTelegramApiStatus(db: D1Database, policy: TelegramPolicy): Promise<number> {
  const epoch = isolatedTelegramRoleEpochSql(policy, "inbox");
  const current = `inbox.bot_id=? AND ${scopeSql("inbox")} AND inbox.actor_id IN (?,?)`;
  const scope = [policy.botId, policy.adminId, policy.memberId];
  try {
    const result = await db.batch([
      db.prepare(`UPDATE telegram_api_status SET
        row_one=CASE WHEN row_one IN (${PENDING},${STARTED}) THEN ${UNAVAILABLE} ELSE row_one END,
        row_two=CASE WHEN row_two IN (${PENDING},${STARTED}) THEN ${UNAVAILABLE} ELSE row_two END
        WHERE receipt_id IN (SELECT origin.receipt_id FROM telegram_api_status AS origin JOIN telegram_inbox AS inbox USING(receipt_id)
          WHERE origin.ready_at IS NULL AND origin.expires_at<=unixepoch() AND ${current}
          ORDER BY origin.expires_at,origin.receipt_id LIMIT ${RECOVERY_LIMIT})`).bind(...scope),
      db.prepare(`UPDATE telegram_api_status SET ready_at=min(unixepoch(),expires_at) WHERE receipt_id IN (
        SELECT origin.receipt_id FROM telegram_api_status AS origin JOIN telegram_inbox AS inbox USING(receipt_id)
        WHERE origin.ready_at IS NULL AND origin.prompt_receipt_id IS NOT NULL AND ${current}
          AND origin.row_one NOT IN (${PENDING},${STARTED}) AND COALESCE(origin.row_two,0) NOT IN (${PENDING},${STARTED})
        ORDER BY origin.expires_at,origin.receipt_id LIMIT ${RECOVERY_LIMIT})`).bind(...scope),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT origin.receipt_id FROM telegram_api_status AS origin JOIN telegram_inbox AS inbox USING(receipt_id)
        WHERE origin.prompt_receipt_id IS NOT NULL AND origin.ready_at>unixepoch()-${REPLY_SECONDS}
          AND ${current} AND ${epoch.sql} AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=origin.receipt_id)
        ORDER BY origin.ready_at,origin.receipt_id LIMIT ${RECOVERY_LIMIT}`).bind(...scope, ...epoch.bindings),
    ]);
    if (result.length === 3 && result.every(({ success }) => success)) return result[2].meta.changes;
  } catch {
    // Recovery never reads or retries the transient request.
  }
  throw new Error("Telegram API status recovery could not be confirmed.");
}

function describe(code: number | null): string {
  switch (code) {
    case UNAVAILABLE: return "暂时无法确认。";
    case INVALID: return "格式无效。";
    case CANCELLED: return "已取消。";
    case TIMEOUT: return "请求超时。";
    case REJECTED: return "请求被拒绝。";
  }
  if (code === null || !Number.isInteger(code)) return "暂时无法确认。";
  const status = Math.floor(code / STRIDE), elapsed = code % STRIDE;
  return status >= 100 && status <= 599 && elapsed <= PROVIDER_API_STATUS_MAX_ELAPSED_MS
    ? `HTTP ${status} · ${elapsed} ms` : "暂时无法确认。";
}

export async function renderTelegramApiStatus(db: D1Database, policy: TelegramPolicy, lease: Lease): Promise<{
  text: string; forceReply: boolean; guard: Guard;
} | null> {
  if (!isPrivate(policy, lease)) return null;
  const epoch = isolatedTelegramRoleEpochSql(policy, "inbox");
  const exact = `${scopeSql("inbox")} AND ${readySql("inbox")} AND ${epoch.sql}
    AND (origin.prompt_receipt_id IS NOT NULL OR (${latestPrompt}))`;
  const presentation = await db.prepare(`SELECT origin.prompt_receipt_id AS promptId,origin.row_one AS first,origin.row_two AS second,
      origin.ready_at AS readyAt,origin.expires_at AS expiresAt FROM telegram_inbox AS inbox
    JOIN telegram_api_status AS origin USING(receipt_id) JOIN telegram_outbox AS reply USING(receipt_id)
    WHERE inbox.bot_id=? AND inbox.receipt_id=? AND inbox.actor_id=? AND inbox.chat_id=?
      AND reply.state='leased' AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch() AND ${exact}`)
    .bind(policy.botId, lease.receiptId, lease.actorId, lease.chatId, lease.leaseId, lease.attempts, ...epoch.bindings).first<Presentation>();
  if (!presentation) return null;
  const { promptId, first, second, readyAt, expiresAt } = presentation;
  return {
    forceReply: promptId === null,
    text: promptId === null ? TELEGRAM_API_STATUS_PROMPT
      : `API 状态\n1. ${describe(first)}${second === null ? "" : `\n2. ${describe(second)}`}`,
    guard: { sql: `EXISTS (SELECT 1 FROM telegram_api_status AS origin WHERE ${exact}
      AND origin.prompt_receipt_id IS ? AND origin.row_one IS ? AND origin.row_two IS ?
      AND origin.ready_at=? AND origin.expires_at=?)`, bindings: [...epoch.bindings, promptId, first, second, readyAt, expiresAt] },
  };
}

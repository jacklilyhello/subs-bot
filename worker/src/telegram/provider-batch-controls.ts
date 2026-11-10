import {
  providerHost, providerSourceDigest, telegramProviderBatchOrigin,
  TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER, type ProviderSql,
} from "../provider-jobs.ts";
import { SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { prepareFailedBatchTrashOffer, type FailedBatchTrashOffer } from "./bulk-trash.ts";
import {
  prepareTelegramProviderBatchAdmission, PROVIDER_BATCH_MAX_TARGETS, readTelegramProviderBatchProgress,
  type TelegramProviderBatchInput, type TelegramProviderBatchProgress,
} from "./provider-batch.ts";
import {
  inTelegramScope, PROVIDER_BATCH_TICKET, type TelegramEventScope, type TelegramPolicy, type TelegramProviderBatchUpdate,
} from "./protocol.ts";
import { displayTelegramName } from "./views.ts";

const STATUS_MARKER = "provider-batch-status:v1";
const MAX_INVENTORY = 100;
const TICKET_SECONDS = 600;
const REPLY_SECONDS = 900;
const RECONCILE_LIMIT = 8;
const DIGEST = /^[0-9a-f]{64}(?![\s\S])/u;
export const TELEGRAM_PROVIDER_BATCH_REPLY_MARKERS = [TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER, TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, STATUS_MARKER]
  .map((marker) => `'${marker}'`).join(",");
const markers = TELEGRAM_PROVIDER_BATCH_REPLY_MARKERS;
type InboxAlias = "inbox" | "earlier";
type Kind = "preview" | "empty" | "limit" | "usage" | "idle" | "status" | "terminal" | "unavailable";
type Epoch = TelegramProviderBatchInput["epoch"];
type Targets = TelegramProviderBatchInput["targets"];
type Confirmation = Extract<TelegramProviderBatchUpdate, { kind: "confirm" }>;
type Lease = Pick<TelegramEventScope, "actorId" | "chatId" | "chatType" | "threadId"> &
  { receiptId: number; leaseId: string; attempts: number };
type Presentation = { kind: Kind; targets: string | null; skippedCount: number; batchId: number | null };

export async function telegramProviderBatchControlsReady(db: D1Database): Promise<boolean> {
  try {
    const count = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema
      WHERE (type='table' AND name='telegram_provider_batch_interactions' AND tbl_name=name)
         OR (type='index' AND tbl_name='telegram_provider_batch_interactions'
             AND name IN ('telegram_provider_batch_tickets_expiry','telegram_provider_batch_terminal_ready'))
         OR (type='index' AND tbl_name='telegram_provider_batches' AND name='telegram_provider_batches_finished')`).first<number>("present");
    if (count !== 0 && count !== 4) throw new Error();
    return count === 4;
  } catch {
    throw new Error("Telegram provider batch controls schema could not be confirmed.");
  }
}

function privateInbox(alias: InboxAlias | "preview"): string {
  return `${alias}.command='help' AND ${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL`;
}

function replyScope(alias: InboxAlias): string {
  return `(${privateInbox(alias)} AND interaction.receipt_id=${alias}.receipt_id AND (
    (${alias}.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER}' AND interaction.kind IN ('preview','empty','limit'))
    OR (${alias}.receipt_nonce='${STATUS_MARKER}' AND interaction.kind IN ('status','idle','usage'))
    OR (${alias}.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER}' AND interaction.kind IN ('terminal','unavailable'))))`;
}

function epochScope(policy: TelegramPolicy, alias: InboxAlias | "preview"): ProviderSql {
  return { sql: `${alias}.bot_id=? AND ((${alias}.actor_id=? AND interaction.actor_role='admin'
    AND interaction.auth_message_date=0 AND interaction.auth_message_id=0) OR (${alias}.actor_id=?
    AND interaction.actor_role='member' AND ${alias}.message_date>interaction.auth_message_date AND COALESCE((
      SELECT allowed=1 AND message_date=interaction.auth_message_date AND message_id=interaction.auth_message_id
      FROM telegram_auth WHERE bot_id=${alias}.bot_id AND user_id=${alias}.actor_id
    ),interaction.auth_message_date=0 AND interaction.auth_message_id=0)))`,
  bindings: [policy.botId, policy.adminId, policy.memberId] };
}

export function telegramProviderBatchReplyMarker(alias: InboxAlias): string {
  return `(${alias}.receipt_nonce IN (${markers}) AND EXISTS (
    SELECT 1 FROM telegram_provider_batch_interactions AS interaction WHERE ${replyScope(alias)}))`;
}

export function telegramProviderBatchReplyClock(alias: InboxAlias, fallback: string): string {
  return `COALESCE((SELECT ready_at FROM telegram_provider_batch_interactions AS interaction
    WHERE ${alias}.receipt_nonce IN (${markers}) AND ${replyScope(alias)}),${fallback})`;
}

export function telegramProviderBatchReplyEligible(policy: TelegramPolicy | undefined, alias: InboxAlias): ProviderSql {
  if (!policy) return { sql: "1", bindings: [] };
  const epoch = epochScope(policy, alias);
  return { sql: `(${alias}.receipt_nonce IS NULL OR ${alias}.receipt_nonce NOT IN (${markers}) OR EXISTS (
    SELECT 1 FROM telegram_provider_batch_interactions AS interaction WHERE ${replyScope(alias)} AND (${epoch.sql})))`,
  bindings: epoch.bindings };
}

function latestPreview(alias: InboxAlias | "preview"): string {
  return `NOT EXISTS(SELECT 1 FROM telegram_inbox AS newer WHERE newer.bot_id=${alias}.bot_id AND newer.actor_id=${alias}.actor_id
    AND newer.chat_id=${alias}.chat_id AND newer.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER}'
    AND (newer.message_date,newer.message_id,newer.receipt_id)>(${alias}.message_date,${alias}.message_id,${alias}.receipt_id))`;
}

function activeEpoch(policy: TelegramPolicy, event: TelegramEventScope, epoch: Epoch): ProviderSql {
  const fresh = "? BETWEEN unixepoch()-900 AND unixepoch()+30";
  if (epoch.role === "admin") return { sql: fresh, bindings: [event.messageDate] };
  return { sql: `${fresh} AND ?>? AND COALESCE((
    SELECT allowed=1 AND message_date=? AND message_id=? FROM telegram_auth WHERE bot_id=? AND user_id=?
  ),?=0 AND ?=0)`, bindings: [event.messageDate, event.messageDate, epoch.messageDate, epoch.messageDate, epoch.messageId,
    policy.botId, event.actorId, epoch.messageDate, epoch.messageId] };
}

async function readEpoch(db: D1Database, policy: TelegramPolicy, event: TelegramEventScope): Promise<Epoch | null> {
  if (event.actorId === policy.adminId) return { role: "admin", messageDate: 0, messageId: 0 };
  const auth = await db.prepare("SELECT allowed,message_date AS messageDate,message_id AS messageId FROM telegram_auth WHERE bot_id=? AND user_id=?")
    .bind(policy.botId, event.actorId).first<{ allowed: number; messageDate: number; messageId: number }>();
  if (auth === null) return { role: "member", messageDate: 0, messageId: 0 };
  return auth.allowed === 1 && event.messageDate > auth.messageDate ? {
    role: "member", messageDate: auth.messageDate, messageId: auth.messageId,
  } : null;
}

function inbox(db: D1Database, policy: TelegramPolicy, event: TelegramEventScope, nonce: string, guard: ProviderSql): D1PreparedStatement {
  return db.prepare(`INSERT INTO telegram_inbox
    (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
    SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE ${guard.sql}
    ON CONFLICT (bot_id,update_id) DO NOTHING`)
    .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce, ...guard.bindings);
}

function targetsFrom(value: string): Targets {
  const targets: unknown = JSON.parse(value);
  if (!Array.isArray(targets) || !validInteger(targets.length, 1, PROVIDER_BATCH_MAX_TARGETS)
    || JSON.stringify(targets) !== value) throw new Error("Invalid Telegram provider batch preview.");
  let after = 0;
  return targets.map((item: unknown) => {
    if (!Array.isArray(item) || item.length !== 4 || !validInteger(item[0], after + 1)
      || !validInteger(item[1], 0, Number.MAX_SAFE_INTEGER - 1) || !validInteger(item[2], 0)
      || typeof item[3] !== "string" || !DIGEST.test(item[3])) throw new Error("Invalid Telegram provider batch preview.");
    const [id, generation, lifecycleRevision, sourceSha256] = item as [number, number, number, string];
    after = id;
    return { id, generation, lifecycleRevision, sourceSha256 };
  });
}

async function capturePreview(db: D1Database, event: TelegramEventScope, guard: ProviderSql): Promise<Presentation> {
  const rows = await db.prepare(`SELECT id,generation,${SUBSCRIPTION_LIFECYCLE_REVISION} AS lifecycleRevision,source_url AS sourceUrl
    FROM subscriptions WHERE owner_id=? AND (${guard.sql}) ORDER BY id LIMIT ${MAX_INVENTORY + 1}`)
    .bind(event.actorId, ...guard.bindings).all<{ id: number; generation: number; lifecycleRevision: number; sourceUrl: string }>();
  if (!rows.success) throw new Error("Telegram provider batch preview could not be captured.");
  if (rows.results.length > MAX_INVENTORY) return { kind: "limit", targets: null, skippedCount: 0, batchId: null };
  const eligible = rows.results.filter(({ generation, sourceUrl }) =>
    validInteger(generation, 0, Number.MAX_SAFE_INTEGER - 1) && providerHost(sourceUrl));
  const skippedCount = rows.results.length - eligible.length;
  if (eligible.length === 0) return { kind: "empty", targets: null, skippedCount, batchId: null };
  if (eligible.length > PROVIDER_BATCH_MAX_TARGETS) return { kind: "limit", targets: null, skippedCount, batchId: null };
  const targets = await Promise.all(eligible.map(async ({ id, generation, lifecycleRevision, sourceUrl }) =>
    [id, generation, lifecycleRevision, await providerSourceDigest(sourceUrl)]));
  return { kind: "preview", targets: JSON.stringify(targets), skippedCount, batchId: null };
}

async function acceptMessage(
  db: D1Database, policy: TelegramPolicy, event: TelegramProviderBatchUpdate, admissionEnabled: boolean,
): Promise<"accepted" | "ignored"> {
  if (!admissionEnabled && event.kind !== "status") return "ignored";
  const epoch = await readEpoch(db, policy, event);
  if (!epoch) return "ignored";
  const guard = activeEpoch(policy, event, epoch);
  let reply: Presentation;
  if (event.kind === "status") {
    const progress = await readTelegramProviderBatchProgress(db, policy, event.actorId);
    if (!progress && !admissionEnabled) return "ignored";
    reply = { kind: progress ? "status" : "idle", batchId: progress?.batchId ?? null, targets: null, skippedCount: 0 };
  } else {
    reply = event.kind === "usage" ? { kind: "usage", targets: null, skippedCount: 0, batchId: null }
      : await capturePreview(db, event, guard);
  }
  const nonce = crypto.randomUUID();
  const key = [policy.botId, event.updateId, nonce] as const;
  const fresh = "bot_id=? AND update_id=? AND receipt_nonce=?";
  const result = await db.batch([
    inbox(db, policy, event, nonce, guard),
    db.prepare(`INSERT INTO telegram_provider_batch_interactions
      (receipt_id,kind,batch_id,actor_role,auth_message_date,auth_message_id,ready_at,targets,skipped_count)
      SELECT receipt_id,?,?,?,?,?,received_at,?,? FROM telegram_inbox WHERE ${fresh}`)
      .bind(reply.kind, reply.batchId, epoch.role, epoch.messageDate, epoch.messageId, reply.targets, reply.skippedCount, ...key),
    db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT receipt_id FROM telegram_inbox WHERE ${fresh}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce=?,command=CASE WHEN EXISTS (
      SELECT 1 FROM telegram_provider_batch_interactions JOIN telegram_outbox USING(receipt_id) WHERE receipt_id=inbox.receipt_id
    ) THEN command END WHERE ${fresh}`).bind(event.kind === "preview" ? TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER : STATUS_MARKER, ...key),
  ]);
  if (result.length !== 4 || result.some(({ success, meta }) => !success || meta.changes !== result[0].meta.changes)
    || !validInteger(result[0].meta.changes, 0, 1)) throw new Error("Telegram provider batch receipt could not be recorded.");
  return result[0].meta.changes === 1 ? "accepted" : "ignored";
}

const ticketFrom = `FROM telegram_provider_batch_interactions AS interaction
  JOIN telegram_inbox AS preview USING(receipt_id) JOIN telegram_outbox AS sent USING(receipt_id)`;

function ticketScope(policy: TelegramPolicy, event: Confirmation, digest: string): ProviderSql {
  const epoch = epochScope(policy, "preview");
  return { sql: `interaction.token_sha256=? AND interaction.kind='preview' AND interaction.used_by_receipt_id IS NULL
    AND interaction.expires_at>unixepoch() AND preview.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_PREVIEW_MARKER}'
    AND ${privateInbox("preview")} AND preview.actor_id=? AND sent.state='sent' AND sent.sent_message_id=?
    AND sent.attempts=interaction.origin_attempt AND ${latestPreview("preview")}
    AND ? BETWEEN unixepoch()-900 AND unixepoch()+30 AND ?>interaction.auth_message_date AND (${epoch.sql})`,
  bindings: [digest, event.actorId, event.messageId, event.messageDate, event.messageDate, ...epoch.bindings] };
}

async function acceptConfirmation(db: D1Database, policy: TelegramPolicy, event: Confirmation): Promise<"accepted" | "ignored"> {
  if (!PROVIDER_BATCH_TICKET.test(event.ticket)) return "ignored";
  const digest = await providerSourceDigest(event.ticket);
  const ticket = ticketScope(policy, event, digest);
  const origin = await db.prepare(`SELECT preview.receipt_id AS previewReceiptId,interaction.targets,interaction.skipped_count AS skippedCount,
    interaction.origin_attempt AS originAttempt,interaction.actor_role AS role,interaction.auth_message_date AS messageDate,
    interaction.auth_message_id AS messageId ${ticketFrom} WHERE ${ticket.sql}`)
    .bind(...ticket.bindings).first<{ previewReceiptId: number; targets: string; skippedCount: number; originAttempt: number } & Epoch>();
  if (!origin) return "ignored";
  const guard = { sql: `EXISTS(SELECT 1 ${ticketFrom} WHERE ${ticket.sql} AND preview.receipt_id=? AND interaction.targets=?
    AND interaction.skipped_count=? AND interaction.origin_attempt=? AND interaction.actor_role=?
    AND interaction.auth_message_date=? AND interaction.auth_message_id=?)`,
    bindings: [...ticket.bindings, origin.previewReceiptId, origin.targets, origin.skippedCount, origin.originAttempt,
      origin.role, origin.messageDate, origin.messageId] };
  const core = await prepareTelegramProviderBatchAdmission(db, policy, {
    previewReceiptId: origin.previewReceiptId, confirmation: event, originAttempt: origin.originAttempt,
    epoch: { role: origin.role, messageDate: origin.messageDate, messageId: origin.messageId },
    targets: targetsFrom(origin.targets), skippedCount: origin.skippedCount,
  }, { read: guard, commit: { sql: `changes()=1 AND ${guard.sql}`, bindings: guard.bindings } });
  const exact = `inbox.bot_id=? AND inbox.update_id=? AND inbox.actor_id=? AND inbox.chat_id=?
    AND inbox.message_id=? AND inbox.message_date=? AND ${privateInbox("inbox")}
    AND inbox.receipt_nonce='${TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER}'`;
  const key = [policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate];
  const result = await db.batch([
    inbox(db, policy, event, TELEGRAM_PROVIDER_BATCH_CONFIRM_MARKER, guard),
    ...(core ?? []),
    db.prepare(`UPDATE telegram_provider_batch_interactions SET used_by_receipt_id=(
      SELECT inbox.receipt_id FROM telegram_inbox AS inbox WHERE ${exact}
    ) WHERE receipt_id=? AND ${guard.sql} AND EXISTS(SELECT 1 FROM telegram_inbox AS inbox WHERE ${exact})`)
      .bind(...key, origin.previewReceiptId, ...guard.bindings, ...key),
    db.prepare(`INSERT INTO telegram_provider_batch_interactions
      (receipt_id,kind,actor_role,auth_message_date,auth_message_id,ready_at)
      SELECT inbox.receipt_id,'unavailable',preview.actor_role,preview.auth_message_date,preview.auth_message_id,inbox.received_at
      FROM telegram_inbox AS inbox JOIN telegram_provider_batch_interactions AS preview ON preview.used_by_receipt_id=inbox.receipt_id
      WHERE ${exact} AND preview.receipt_id=? AND NOT EXISTS(SELECT 1 FROM telegram_provider_batches WHERE batch_id=inbox.receipt_id)
      ON CONFLICT DO NOTHING`).bind(...key, origin.previewReceiptId),
    db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT inbox.receipt_id FROM telegram_inbox AS inbox
      JOIN telegram_provider_batch_interactions AS reply USING(receipt_id) WHERE ${exact} AND reply.kind='unavailable'
      ON CONFLICT DO NOTHING`).bind(...key),
    db.prepare(`SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM telegram_inbox AS inbox WHERE ${exact} AND NOT (
      EXISTS(SELECT 1 FROM telegram_provider_batch_interactions WHERE receipt_id=? AND used_by_receipt_id=inbox.receipt_id)
      AND (EXISTS(SELECT 1 FROM telegram_provider_batches WHERE batch_id=inbox.receipt_id AND preview_receipt_id=?)
        OR EXISTS(SELECT 1 FROM telegram_provider_batch_interactions JOIN telegram_outbox USING(receipt_id)
          WHERE receipt_id=inbox.receipt_id AND kind='unavailable'))
    )) THEN 1 ELSE json_extract('batch confirmation guard failed','$') END`)
      .bind(...key, origin.previewReceiptId, origin.previewReceiptId),
  ]);
  if (result.length !== (core?.length ?? 0) + 5 || result.some(({ success }) => !success)
    || !validInteger(result[0].meta.changes, 0, 1)) throw new Error("Telegram provider batch confirmation could not be recorded.");
  return result[0].meta.changes === 1 ? "accepted" : "ignored";
}

export async function acceptTelegramProviderBatchControl(
  db: D1Database, policy: TelegramPolicy, event: TelegramProviderBatchUpdate, admissionEnabled: boolean,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.threadId !== null || event.chatId !== event.actorId
    || ![event.updateId, event.messageId, event.messageDate].every((value) => validInteger(value, 1))) return "ignored";
  try {
    if (event.kind === "confirm") return admissionEnabled ? await acceptConfirmation(db, policy, event) : "ignored";
    return await acceptMessage(db, policy, event, admissionEnabled);
  } catch {
    throw new Error("Telegram provider batch control could not be confirmed.");
  }
}

export type TelegramProviderBatchDelivery = { text: string; guard: ProviderSql } & (
  { ticket?: { value: string; sha256: string }; cleanup?: never } | { ticket?: never; cleanup: FailedBatchTrashOffer }
);

const notices: Record<Exclude<Kind, "preview" | "status" | "terminal">, string> = {
  empty: "没有可远程刷新的订阅。",
  limit: "可刷新订阅超过 16 条，或订阅清单超过 100 条。请使用单条刷新。",
  usage: "用法：/updateall 预览，/updateall status 查看进度。",
  idle: "暂无批量刷新记录。",
  unavailable: "无法开始批量刷新。订阅可能已变更，或已有批次在运行。请查看 /updateall status。",
};

function renderProgress(progress: TelegramProviderBatchProgress): string {
  const { batchId, targetCount, skippedCount, waiting, pending, leased, saved, failed, stale, expired, finishedAt } = progress;
  const done = saved + failed + stale + expired;
  return [
    finishedAt === null ? `批量刷新 #${batchId} 进度：${done}/${targetCount}` : `批量刷新 #${batchId} 完成：${done}/${targetCount}`,
    `已保存 ${saved} · 失败 ${failed} · 已变更 ${stale} · 超时 ${expired}`,
    ...(finishedAt === null ? [`等待 ${waiting} · 排队 ${pending} · 处理中 ${leased}`] : []),
    ...(skippedCount > 0 ? [`未纳入 ${skippedCount} 条本地或不支持的订阅。`] : []),
  ].join("\n");
}

const resultCategories = {
  saved: "saved", "stale-target": "stale", expired: "expired", "attempts-exhausted": "failed",
  "invalid-document": "failed", "fetch-rejected": "failed", "storage-failed": "failed",
} as const;
const resultLabels = { saved: "已保存", failed: "失败", stale: "已变更", expired: "超时" } as const;

async function renderTerminalResults(
  db: D1Database, policy: TelegramPolicy, actorId: string, progress: TelegramProviderBatchProgress,
): Promise<string | null> {
  if (!validInteger(progress.targetCount, 1, PROVIDER_BATCH_MAX_TARGETS)) return null;
  const origin = telegramProviderBatchOrigin(policy);
  try {
    const rows = await db.prepare(`SELECT job.ordinal,job.subscription_id AS id,job.result_code AS result,
      CASE WHEN job.result_code<>'stale-target' AND COALESCE(lifecycle.revision,0)=job.expected_lifecycle_revision
        AND sub.generation=job.expected_generation+CASE WHEN job.result_code='saved' THEN 1 ELSE 0 END
        THEN sub.name END AS name
      FROM telegram_provider_batches AS batch JOIN telegram_provider_batch_jobs AS job USING(batch_id)
      LEFT JOIN subscriptions AS sub ON sub.id=job.subscription_id AND sub.owner_id=batch.actor_id
      LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
      WHERE batch.batch_id=? AND batch.actor_id=? AND batch.finished_at=? AND job.owner_id=batch.actor_id
        AND job.state='done' AND (${origin.sql}) ORDER BY job.ordinal LIMIT ${PROVIDER_BATCH_MAX_TARGETS + 1}`)
      .bind(progress.batchId, actorId, progress.finishedAt, ...origin.bindings)
      .all<{ ordinal: number; id: number; result: keyof typeof resultCategories; name: string | null }>();
    if (!rows.success || rows.results.length !== progress.targetCount) return null;
    const counts = { saved: 0, failed: 0, stale: 0, expired: 0 };
    const lines: string[] = [];
    for (const [index, { ordinal, id, result, name }] of rows.results.entries()) {
      if (ordinal !== index + 1 || !validInteger(id, 1) || !Object.hasOwn(resultCategories, result)) return null;
      const category = resultCategories[result];
      counts[category] += 1;
      const label = typeof name === "string" ? ` · ${displayTelegramName(name)}` : "";
      lines.push(`订阅 ID ${id}${label}：${resultLabels[category]}`);
    }
    if (counts.saved !== progress.saved || counts.failed !== progress.failed
      || counts.stale !== progress.stale || counts.expired !== progress.expired) return null;
    return `\n\n本次订阅结果\n${lines.join("\n")}`;
  } catch {
    return null;
  }
}

export async function renderTelegramProviderBatchReply(
  db: D1Database, policy: TelegramPolicy, lease: Lease,
): Promise<TelegramProviderBatchDelivery | null> {
  if (!inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return null;
  const epoch = epochScope(policy, "inbox");
  const reply = await db.prepare(`SELECT interaction.kind,interaction.targets,interaction.batch_id AS batchId,
    interaction.skipped_count AS skippedCount,(${latestPreview("inbox")}) AS newest
    FROM telegram_inbox AS inbox JOIN telegram_outbox AS delivery USING(receipt_id)
    JOIN telegram_provider_batch_interactions AS interaction USING(receipt_id)
    WHERE inbox.receipt_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND delivery.state='leased'
      AND delivery.lease_id=? AND delivery.attempts=? AND delivery.lease_until>unixepoch()
      AND ${replyScope("inbox")} AND (${epoch.sql})`)
    .bind(lease.receiptId, lease.actorId, lease.chatId, lease.leaseId, lease.attempts, ...epoch.bindings)
    .first<Presentation & { newest: number }>();
  if (!reply || (reply.kind === "preview" && reply.newest !== 1)) return null;
  const guard = { sql: `EXISTS(SELECT 1 FROM telegram_provider_batch_interactions AS interaction
    WHERE ${replyScope("inbox")} AND (${epoch.sql}) AND interaction.kind=? AND COALESCE(interaction.batch_id,-1)=?
      AND interaction.skipped_count=?
      ${reply.kind === "preview" ? `AND interaction.targets=? AND interaction.used_by_receipt_id IS NULL AND ${latestPreview("inbox")}` : ""})`,
    bindings: [...epoch.bindings, reply.kind, reply.batchId ?? -1, reply.skippedCount,
      ...(reply.kind === "preview" ? [reply.targets!] : [])] };
  if (reply.kind === "status" || reply.kind === "terminal") {
    const progress = await readTelegramProviderBatchProgress(db, policy, lease.actorId, reply.batchId!);
    if (!progress || (reply.kind === "terminal" && progress.finishedAt === null)) return null;
    const text = renderProgress(progress);
    if (progress.finishedAt === null) return { text, guard };
    const details = await renderTerminalResults(db, policy, lease.actorId, progress);
    const cleanup = reply.kind === "terminal" && details !== null && progress.failed > 0
      ? await prepareFailedBatchTrashOffer(db, policy, lease) : null;
    const presentation = { text: text + (details ?? "\n暂时无法核对逐条结果。"), guard: {
      sql: `(${guard.sql}) AND EXISTS (SELECT 1 FROM telegram_provider_batches AS batch
        WHERE batch.batch_id=? AND batch.bot_id=inbox.bot_id AND batch.actor_id=inbox.actor_id AND batch.finished_at=?)`,
      bindings: [...guard.bindings, progress.batchId, progress.finishedAt],
    } };
    return cleanup !== null && cleanup.count === progress.failed ? { ...presentation, cleanup } : presentation;
  }
  if (reply.kind !== "preview") {
    const excluded = reply.kind === "empty" && reply.skippedCount > 0 ? `已跳过 ${reply.skippedCount} 条本地或不支持的订阅。` : "";
    return { text: notices[reply.kind] + excluded, guard };
  }
  const targets = targetsFrom(reply.targets!);
  const value = "sbpb1_" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))))
    .replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  const skipped = reply.skippedCount > 0 ? `未纳入 ${reply.skippedCount} 条本地或不支持的订阅。\n` : "";
  return { text: `确认刷新 ${targets.length} 条远程订阅？\n${skipped}请在十分钟内确认，或发送 /updateall status 查看进度。`, guard,
    ticket: { value, sha256: await providerSourceDigest(value) } };
}

export function installTelegramProviderBatchTicket(db: D1Database, lease: Lease, sha256: string): D1PreparedStatement {
  return db.prepare(`UPDATE telegram_provider_batch_interactions SET token_sha256=?,origin_attempt=?,expires_at=unixepoch()+${TICKET_SECONDS}
    WHERE changes()=1 AND receipt_id=? AND kind='preview' AND used_by_receipt_id IS NULL AND EXISTS (
      SELECT 1 FROM telegram_outbox WHERE receipt_id=? AND lease_id=? AND attempts=? AND state='sending')`)
    .bind(sha256, lease.attempts, lease.receiptId, lease.receiptId, lease.leaseId, lease.attempts);
}

export async function reconcileTelegramProviderBatchReplies(db: D1Database, policy: TelegramPolicy): Promise<number> {
  const origin = telegramProviderBatchOrigin(policy);
  const epoch = epochScope(policy, "inbox");
  try {
    const steps = [
      db.prepare(`INSERT INTO telegram_provider_batch_interactions
        (receipt_id,kind,batch_id,actor_role,auth_message_date,auth_message_id,ready_at)
        SELECT batch.batch_id,'terminal',batch.batch_id,batch.actor_role,batch.auth_message_date,batch.auth_message_id,batch.finished_at
        FROM telegram_provider_batches AS batch WHERE batch.finished_at>unixepoch()-${REPLY_SECONDS} AND (${origin.sql})
          AND NOT EXISTS(SELECT 1 FROM telegram_provider_batch_interactions WHERE receipt_id=batch.batch_id)
          AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=batch.batch_id)
        ORDER BY batch.finished_at,batch.batch_id LIMIT ${RECONCILE_LIMIT}`).bind(...origin.bindings),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_provider_batch_interactions AS interaction USING(receipt_id)
        WHERE interaction.kind='terminal' AND interaction.ready_at>unixepoch()-${REPLY_SECONDS}
          AND ${replyScope("inbox")} AND (${epoch.sql}) AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=inbox.receipt_id)
        ORDER BY interaction.ready_at,inbox.receipt_id LIMIT ${RECONCILE_LIMIT}`).bind(...epoch.bindings),
    ];
    const result = await db.batch(steps);
    if (result.length !== 2 || result.some(({ success, meta }) => !success || !validInteger(meta.changes, 0, RECONCILE_LIMIT))) throw new Error();
    return result[1].meta.changes;
  } catch {
    throw new Error("Telegram provider batch replies could not be reconciled.");
  }
}

export async function reapTelegramProviderBatchTickets(db: D1Database): Promise<void> {
  try {
    const result = await db.prepare(`UPDATE telegram_provider_batch_interactions SET token_sha256=NULL,origin_attempt=NULL,expires_at=NULL
      WHERE receipt_id IN (SELECT receipt_id FROM telegram_provider_batch_interactions
        WHERE token_sha256 IS NOT NULL AND used_by_receipt_id IS NULL AND expires_at<=unixepoch()
        ORDER BY expires_at,receipt_id LIMIT 40)`).run();
    if (result.success) return;
  } catch {
    // Diagnostics do not expose capability or backend values.
  }
  throw new Error("Telegram provider batch ticket cleanup could not be confirmed.");
}

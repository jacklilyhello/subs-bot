import {
  MAX_PROVIDER_OWNER_SOURCES, prepareOwnedProviderRefresh, providerHost, providerSourceDigest, PROVIDER_TRASH_SECONDS,
  type ProviderSql,
} from "../provider-jobs.ts";
import { providerHostnameLabel, providerInitialTitleReady } from "../provider-initial-title.ts";
import { digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import { normalizeSubscriptionName } from "../subscriptions.ts";
import {
  prepareTelegramDocumentJobLeaseGuard, prepareTelegramDocumentJobSettlement, TELEGRAM_DOCUMENT_JOB_MARKER,
  type TelegramDocumentJobLease,
} from "./document-jobs.ts";
import { TELEGRAM_PROVIDER_DOCUMENT_MAX_URLS, type TelegramProviderDocumentInput,
  type TelegramProviderUrlMessage } from "./provider-document-input.ts";
import { providerDocumentOrigin, TELEGRAM_PROVIDER_DOCUMENT_MARKER } from "./provider-document-origin.ts";
import { telegramProviderMessageAdmission } from "./provider-admission.ts";
import { inTelegramScope, type TelegramEventScope, type TelegramPolicy } from "./protocol.ts";

const PARENT_TTL_SECONDS = 7_200;
const BACKPRESSURE_SECONDS = 60;
const PROMOTION_HEADROOM_SECONDS = 120;
const encoder = new TextEncoder();

type UrlList = Extract<TelegramProviderDocumentInput, { kind: "url-list" }>;
export type TelegramProviderDocumentSources = Pick<UrlList, "urls" | "overflow">;
type WaitingLine = {
  receiptId: number; ordinal: number; sourceSha256: string; ownerId: string;
  subscriptionId: number; expectedGeneration: number; expectedLifecycleRevision: number;
  updateId: number; message: number; parentExpiresAt: number;
};

async function pendingMessageTitleKey(botId: string, updateId: number, ordinal: number): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(
    `subs-bot:telegram-provider-message-title-pending:v1\n${botId}\n${updateId}\n${ordinal}`)));
}

function assertBatch(result: readonly D1Result[], steps: readonly D1PreparedStatement[]): void {
  if (result.length !== steps.length || result.some(({ success }) => !success)) {
    throw new Error("Telegram provider document transaction could not be confirmed.");
  }
}

export async function telegramProviderDocumentReady(db: D1Database): Promise<boolean> {
  const present = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
    AND name IN ('telegram_provider_documents','telegram_provider_document_lines','telegram_provider_document_opt_in')`)
    .first<number>("present");
  if (present === 0 || present === 3) return present === 3;
  throw new Error("Telegram provider document schema could not be confirmed.");
}

async function prepareProviderLines(
  db: D1Database, ownerId: string, entries: TelegramProviderUrlMessage["entries"], receipt: ProviderSql, staged: ProviderSql,
) {
  if (entries.length < 1 || entries.length > TELEGRAM_PROVIDER_DOCUMENT_MAX_URLS) {
    throw new RangeError("Invalid provider document line count.");
  }
  const inputs = await Promise.all(entries.map(async ({ sourceUrl, name }) => {
    const host = providerHost(sourceUrl);
    if (!host) throw new Error();
    return { sourceUrl, name: name === undefined ? providerHostnameLabel(host) : normalizeSubscriptionName(name),
      digest: await providerSourceDigest(sourceUrl), token: crypto.randomUUID().replaceAll("-", "") };
  }));
  const steps = [
    ...inputs.flatMap(({ sourceUrl, name, digest, token }, ordinal) => {
      const trashed = `EXISTS (SELECT 1 FROM subscription_trash WHERE owner_id=? AND source_url=?
        AND deleted_at>=unixepoch()-${PROVIDER_TRASH_SECONDS})`;
      return [
        db.prepare(`INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
          SELECT ?,?,?,?,unixepoch(),unixepoch() WHERE (${staged.sql})
          AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id=? AND source_url=?)
          AND NOT ${trashed} AND NOT EXISTS (SELECT 1 FROM subscription_trash WHERE token=?)
          AND NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id=? AND
            (lower(substr(source_url,1,7))='http://' OR lower(substr(source_url,1,8))='https://')
            LIMIT 1 OFFSET ${MAX_PROVIDER_OWNER_SOURCES - 1})`)
          .bind(ownerId, name, sourceUrl, token, ...staged.bindings, ownerId, sourceUrl,
            ownerId, sourceUrl, token, ownerId),
        db.prepare(`WITH matching AS (
            SELECT id,generation,${SUBSCRIPTION_LIFECYCLE_REVISION} AS revision FROM subscriptions
            WHERE owner_id=? AND source_url=? LIMIT 2
          )
          INSERT INTO telegram_provider_document_lines (receipt_id,ordinal,due_at,source_sha256,
            subscription_id,expected_generation,expected_lifecycle_revision,result_code)
          SELECT ${receipt.sql},?,unixepoch(),?,target.id,target.generation,target.revision,CASE
            WHEN target.id IS NOT NULL THEN NULL WHEN (SELECT count(*) FROM matching)>1 THEN 'conflict'
            WHEN (SELECT count(*) FROM matching)=1 THEN 'stale-target'
            WHEN ${trashed} THEN 'unavailable' ELSE 'capacity' END
          FROM (SELECT 1) LEFT JOIN matching AS target ON (SELECT count(*) FROM matching)=1 AND target.generation<9007199254740991
          WHERE (${staged.sql})`)
          .bind(ownerId, sourceUrl, ...receipt.bindings, ordinal, digest, ownerId, sourceUrl, ...staged.bindings),
      ];
    }),
    db.prepare(`SELECT CASE WHEN NOT (${staged.sql}) OR (SELECT count(*) FROM telegram_provider_document_lines
      WHERE receipt_id=${receipt.sql})=? THEN 1 ELSE json_extract('provider document line guard failed','$') END`)
      .bind(...staged.bindings, ...receipt.bindings, inputs.length),
  ];
  return { steps, newShellTokens: inputs.map(({ token }) => token) };
}

export async function prepareTelegramProviderDocumentPlan(
  db: D1Database, policy: TelegramPolicy, lease: TelegramDocumentJobLease, input: TelegramProviderDocumentSources,
  mixed = false,
) {
  const guard = prepareTelegramDocumentJobLeaseGuard(policy, lease);
  const receipt = { sql: "?", bindings: [lease.receiptId] };
  const exists = { sql: "EXISTS (SELECT 1 FROM telegram_provider_documents WHERE receipt_id=?)", bindings: receipt.bindings };
  const staged = { sql: `${exists.sql} AND (${guard.sql})`, bindings: [...exists.bindings, ...guard.bindings] };
  const parent = db.prepare(`INSERT INTO telegram_provider_documents
    (receipt_id,bot_id,actor_id,actor_role,auth_message_date,auth_message_id,expires_at,line_count,overflow_count)
    SELECT receipt_id,bot_id,actor_id,?,auth_message_date,auth_message_id,unixepoch()+${PARENT_TTL_SECONDS},?,?
    FROM telegram_document_jobs AS source WHERE source.receipt_id=? AND (${guard.sql})
      AND EXISTS (SELECT 1 FROM telegram_provider_document_opt_in WHERE receipt_id=source.receipt_id)
      ${mixed ? "AND EXISTS (SELECT 1 FROM telegram_mixed_document_opt_in WHERE receipt_id=source.receipt_id)" : ""}
      AND NOT EXISTS (SELECT 1 FROM telegram_provider_documents AS active WHERE active.bot_id=source.bot_id
        AND active.actor_id=source.actor_id AND active.finished_at IS NULL)`)
    .bind(lease.actorId === policy.adminId ? "admin" : "member", input.urls.length, input.overflow, lease.receiptId, ...guard.bindings);
  const lines = await prepareProviderLines(db, lease.actorId, input.urls.map((sourceUrl) => ({ sourceUrl })), receipt, staged);
  return { ...lines, steps: [parent, ...lines.steps], exists, staged };
}

export async function acceptTelegramProviderUrlMessage(
  db: D1Database, policy: TelegramPolicy, event: TelegramEventScope, input: TelegramProviderUrlMessage,
): Promise<"queued" | "busy" | "ignored"> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.threadId !== null || event.chatId !== event.actorId ||
      !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";
  const current = telegramProviderMessageAdmission(policy, event);
  const origin = [policy.botId, event.updateId, crypto.randomUUID()] as const;
  const fresh = "inbox.bot_id=? AND inbox.update_id=? AND inbox.receipt_nonce=?";
  const receipt = { sql: `(SELECT inbox.receipt_id FROM telegram_inbox AS inbox WHERE ${fresh})`, bindings: origin };
  const staged = { sql: `EXISTS (SELECT 1 FROM telegram_provider_documents WHERE receipt_id=${receipt.sql})`, bindings: origin };
  const active = "EXISTS (SELECT 1 FROM telegram_provider_documents WHERE bot_id=? AND actor_id=? AND finished_at IS NULL)";
  const activeBindings = [policy.botId, event.actorId] as const;
  const role = event.actorId === policy.adminId ? "admin" : "member";
  try {
    const lines = await prepareProviderLines(db, event.actorId, input.entries, receipt, staged);
    const titleChecks: D1PreparedStatement[] = [];
    const titles: D1PreparedStatement[] = [];
    if (input.entries.some(({ name }) => name === undefined) && await providerInitialTitleReady(db, true)) {
      const candidates = JSON.stringify(await Promise.all(input.entries.flatMap(({ name }, ordinal) => name === undefined
        ? [pendingMessageTitleKey(policy.botId, event.updateId, ordinal).then((key) => [ordinal, lines.newShellTokens[ordinal], key])]
        : [])));
      // A candidate token must be absent before the shell INSERT, so its presence
      // afterward proves this exact batch created the row, even on a token collision.
      titleChecks.push(db.prepare(`SELECT CASE WHEN NOT (${staged.sql}) OR NOT EXISTS (
        SELECT 1 FROM json_each(?) AS candidate JOIN subscriptions AS sub ON sub.token=json_extract(candidate.value,'$[1]'))
        THEN 1 ELSE json_extract('provider title token guard failed','$') END`).bind(...staged.bindings, candidates));
      titles.push(db.prepare(`DELETE FROM telegram_provider_initial_titles WHERE subscription_id IN (
        SELECT subscription_id FROM telegram_provider_initial_titles WHERE expires_at<=unixepoch()
        ORDER BY expires_at,subscription_id LIMIT 16) AND (${staged.sql})`).bind(...staged.bindings),
      db.prepare(`INSERT INTO telegram_provider_initial_titles (subscription_id,request_key,source_sha256,expires_at)
        SELECT sub.id,json_extract(candidate.value,'$[2]'),line.source_sha256,origin.expires_at
        FROM json_each(?) AS candidate JOIN telegram_provider_document_lines AS line ON line.ordinal=json_extract(candidate.value,'$[0]')
        JOIN telegram_provider_documents AS origin USING (receipt_id)
        JOIN subscriptions AS sub ON sub.id=line.subscription_id AND sub.owner_id=origin.actor_id
          AND sub.token=json_extract(candidate.value,'$[1]') AND sub.generation=0
        WHERE line.receipt_id=${receipt.sql} AND line.expected_generation=0 AND line.expected_lifecycle_revision=0
          AND line.job_id IS NULL AND line.result_code IS NULL`).bind(candidates, ...receipt.bindings));
    }
    const steps = [
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE (${current.sql}) AND NOT ${active}
        ON CONFLICT (bot_id,update_id) DO NOTHING`)
        .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, origin[2],
          ...current.bindings, ...activeBindings),
      db.prepare(`INSERT INTO telegram_provider_documents
        (receipt_id,bot_id,actor_id,actor_role,auth_message_date,auth_message_id,expires_at,line_count,overflow_count)
        SELECT inbox.receipt_id,inbox.bot_id,inbox.actor_id,?,
          CASE WHEN ?='admin' THEN 0 ELSE COALESCE(auth.message_date,0) END,
          CASE WHEN ?='admin' THEN 0 ELSE COALESCE(auth.message_id,0) END,
          unixepoch()+${PARENT_TTL_SECONDS},?,?
        FROM telegram_inbox AS inbox LEFT JOIN telegram_auth AS auth ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id
        WHERE ${fresh}`)
        .bind(role, role, role, input.entries.length, input.overflow, ...origin),
      ...titleChecks,
      ...lines.steps,
      ...titles,
      db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce=? WHERE ${fresh} AND ${staged.sql}`)
        .bind(TELEGRAM_PROVIDER_DOCUMENT_MARKER, ...origin, ...staged.bindings),
      db.prepare(`SELECT CASE WHEN ${receipt.sql} IS NULL THEN 1 ELSE json_extract('provider message marker failed','$') END`)
        .bind(...receipt.bindings),
      db.prepare(`SELECT NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=? AND update_id=?)
        AND (${current.sql}) AND ${active} AS busy`).bind(policy.botId, event.updateId, ...current.bindings, ...activeBindings),
    ];
    const results = await db.batch(steps);
    assertBatch(results, steps);
    const busy = results.at(-1)?.results[0] as { busy: number } | undefined;
    if (!busy || (busy.busy !== 0 && busy.busy !== 1)) throw new Error();
    return results[0].meta.changes === 1 ? "queued" : busy.busy === 1 ? "busy" : "ignored";
  } catch {
    throw new Error("Telegram provider URL message staging could not be confirmed.");
  }
}

export function prepareTelegramProviderDocumentMarker(db: D1Database, receiptId: number): D1PreparedStatement[] {
  return [
    db.prepare(`UPDATE telegram_inbox SET receipt_nonce=? WHERE receipt_id=? AND receipt_nonce=? AND changes()=1`)
      .bind(TELEGRAM_PROVIDER_DOCUMENT_MARKER, receiptId, TELEGRAM_DOCUMENT_JOB_MARKER),
    db.prepare(`SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM telegram_provider_documents WHERE receipt_id=?)
      OR changes()=1 THEN 1 ELSE json_extract('provider document settlement guard failed','$') END`).bind(receiptId),
  ];
}

export async function stageTelegramProviderDocument(
  db: D1Database, policy: TelegramPolicy, lease: TelegramDocumentJobLease, input: UrlList,
): Promise<boolean> {
  try {
    const plan = await prepareTelegramProviderDocumentPlan(db, policy, lease, input);
    const steps = [
      ...plan.steps,
      // Settlement retains the standard document replay identity while scrubbing the Telegram file fields.
      db.prepare(`DELETE FROM telegram_provider_document_opt_in WHERE (${plan.staged.sql}) AND receipt_id=?`)
        .bind(...plan.staged.bindings, lease.receiptId),
      prepareTelegramDocumentJobSettlement(db, policy, lease, { kind: "saved" }, true),
      ...prepareTelegramProviderDocumentMarker(db, lease.receiptId),
    ];
    const result = await db.batch(steps);
    assertBatch(result, steps);
    return result[0].meta.changes === 1;
  } catch {
    // D1 binding errors may contain credentials embedded in source URLs.
    throw new Error("Telegram provider document staging could not be confirmed.");
  }
}

const waiting = "line.job_id IS NULL AND line.result_code IS NULL";

function promotionFence(policy: TelegramPolicy, line: WaitingLine): ProviderSql {
  const current = providerDocumentOrigin(policy);
  return { sql: `EXISTS (SELECT 1 FROM telegram_provider_document_lines AS line
    JOIN telegram_provider_documents AS origin USING (receipt_id) JOIN telegram_inbox AS inbox USING (receipt_id)
    WHERE line.receipt_id=? AND line.ordinal=? AND line.source_sha256=? AND ${waiting}
      AND line.due_at<=unixepoch() AND origin.finished_at IS NULL
      AND origin.expires_at>unixepoch()+${PROMOTION_HEADROOM_SECONDS} AND (${current.sql}))`,
    bindings: [line.receiptId, line.ordinal, line.sourceSha256, ...current.bindings] };
}

export async function promoteTelegramProviderDocument(db: D1Database, policy: TelegramPolicy, includeBatch: boolean): Promise<void> {
  const current = providerDocumentOrigin(policy);
  try {
    const line = await db.prepare(`SELECT line.receipt_id AS receiptId,line.ordinal,line.source_sha256 AS sourceSha256,
      origin.actor_id AS ownerId,line.subscription_id AS subscriptionId,
      line.expected_generation AS expectedGeneration,line.expected_lifecycle_revision AS expectedLifecycleRevision,
      inbox.update_id AS updateId,origin.expires_at AS parentExpiresAt,
      NOT EXISTS(SELECT 1 FROM telegram_document_jobs WHERE receipt_id=inbox.receipt_id) AS message
      FROM telegram_provider_document_lines AS line JOIN telegram_provider_documents AS origin USING (receipt_id)
      JOIN telegram_inbox AS inbox USING (receipt_id)
      WHERE ${waiting} AND line.due_at<=unixepoch() AND origin.finished_at IS NULL
        AND origin.expires_at>unixepoch()+${PROMOTION_HEADROOM_SECONDS} AND (${current.sql})
      ORDER BY line.due_at,line.receipt_id,line.ordinal LIMIT 1`).bind(...current.bindings).first<WaitingLine>();
    if (!line) return;
    const requestKey = digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(
      `subs-bot:telegram-provider-document:v1\n${policy.botId}\n${line.receiptId}\n${line.ordinal}`)));
    const fence = promotionFence(policy, line);
    const prepared = await prepareOwnedProviderRefresh(db, { ownerId: line.ownerId, requestKey, id: line.subscriptionId,
      expectedGeneration: line.expectedGeneration, expectedLifecycleRevision: line.expectedLifecycleRevision },
    fence, fence, { ...policy, includeDocuments: true }, includeBatch);
    if (!prepared || prepared.digest !== line.sourceSha256) {
      const changed = await db.prepare(`UPDATE telegram_provider_document_lines AS line SET result_code='stale-target'
        WHERE line.receipt_id=? AND line.ordinal=? AND (${fence.sql})`)
        .bind(line.receiptId, line.ordinal, ...fence.bindings).run();
      if (!changed.success) throw new Error();
      return;
    }
    const exactJob = `job.owner_id=? AND job.request_key=? AND job.kind='refresh' AND job.subscription_id=?
      AND job.source_sha256=? AND job.expected_generation=? AND job.expected_lifecycle_revision=?`;
    const jobBindings = [line.ownerId, requestKey, line.subscriptionId, line.sourceSha256,
      line.expectedGeneration, line.expectedLifecycleRevision];
    const titles: D1PreparedStatement[] = [];
    if (line.message === 1 && line.expectedGeneration === 0 && line.expectedLifecycleRevision === 0
        && await providerInitialTitleReady(db, true)) {
      const pending = "initial.subscription_id=? AND initial.request_key=? AND initial.source_sha256=? AND initial.expires_at=?";
      const pendingBindings = [line.subscriptionId, await pendingMessageTitleKey(policy.botId, line.updateId, line.ordinal),
        line.sourceSha256, line.parentExpiresAt];
      const linked = `job.state='pending' AND (${exactJob}) AND EXISTS (SELECT 1 FROM telegram_provider_document_lines AS linked_line
        WHERE linked_line.receipt_id=? AND linked_line.ordinal=? AND linked_line.job_id=job.job_id)`;
      const linkedBindings = [...jobBindings, line.receiptId, line.ordinal];
      titles.push(db.prepare(`UPDATE telegram_provider_initial_titles AS initial SET request_key=job.request_key,expires_at=job.expires_at
        FROM telegram_provider_jobs AS job WHERE ${pending} AND ${linked}`).bind(...pendingBindings, ...linkedBindings),
      db.prepare(`SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM telegram_provider_initial_titles AS initial
        WHERE ${pending}) OR NOT EXISTS (SELECT 1 FROM telegram_provider_jobs AS job WHERE ${linked})
        THEN 1 ELSE json_extract('provider title promotion guard failed','$') END`).bind(...pendingBindings, ...linkedBindings));
    }
    const steps = [
      ...prepared.plan.statements,
      db.prepare(`UPDATE telegram_provider_document_lines AS line SET job_id=(
        SELECT job_id FROM telegram_provider_jobs AS job WHERE ${exactJob})
        WHERE line.receipt_id=? AND line.ordinal=? AND (${fence.sql})
          AND EXISTS (SELECT 1 FROM telegram_provider_jobs AS job WHERE ${exactJob})`)
        .bind(...jobBindings, line.receiptId, line.ordinal, ...fence.bindings, ...jobBindings),
      db.prepare(`SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM telegram_provider_jobs AS job
        WHERE job.owner_id=? AND job.request_key=?) OR EXISTS (
          SELECT 1 FROM telegram_provider_document_lines AS line JOIN telegram_provider_jobs AS job USING (job_id)
          WHERE line.receipt_id=? AND line.ordinal=? AND ${exactJob})
        THEN 1 ELSE json_extract('provider document job linkage failed','$') END`)
        .bind(line.ownerId, requestKey, line.receiptId, line.ordinal, ...jobBindings),
      ...titles,
      db.prepare(`UPDATE telegram_provider_document_lines AS line
        SET due_at=unixepoch()+${BACKPRESSURE_SECONDS},
          result_code=CASE WHEN (${prepared.plan.refusal.sql})='unavailable' THEN 'stale-target' END
        WHERE line.receipt_id=? AND line.ordinal=? AND (${fence.sql})`)
        .bind(...prepared.plan.refusal.bindings, line.receiptId, line.ordinal, ...fence.bindings),
    ];
    assertBatch(await db.batch(steps), steps);
  } catch {
    throw new Error("Telegram provider document promotion could not be confirmed.");
  }
}

export async function settleTelegramProviderDocuments(db: D1Database, policy: TelegramPolicy): Promise<void> {
  const current = providerDocumentOrigin(policy);
  const recorded = providerDocumentOrigin(policy, "recorded");
  const steps = [
    db.prepare(`UPDATE telegram_provider_document_lines AS line
      SET result_code=CASE WHEN origin.expires_at<=unixepoch() THEN 'expired' ELSE 'access-changed' END
      FROM telegram_provider_documents AS origin JOIN telegram_inbox AS inbox USING (receipt_id)
      WHERE line.receipt_id=origin.receipt_id AND ${waiting} AND origin.finished_at IS NULL
        AND (${recorded.sql}) AND (origin.expires_at<=unixepoch() OR NOT (${current.sql}))`)
      .bind(...recorded.bindings, ...current.bindings),
    db.prepare(`UPDATE telegram_provider_document_lines AS line SET result_code=job.result_code
      FROM telegram_provider_documents AS origin JOIN telegram_inbox AS inbox USING (receipt_id)
      JOIN telegram_provider_jobs AS job ON job.owner_id=origin.actor_id
      WHERE line.receipt_id=origin.receipt_id AND line.job_id=job.job_id AND line.result_code IS NULL
        AND job.kind='refresh' AND job.subscription_id=line.subscription_id AND job.source_sha256=line.source_sha256
        AND job.expected_generation=line.expected_generation AND job.expected_lifecycle_revision=line.expected_lifecycle_revision
        AND job.state='done' AND origin.finished_at IS NULL AND (${recorded.sql})`).bind(...recorded.bindings),
    db.prepare(`UPDATE telegram_provider_documents AS origin SET finished_at=unixepoch()
      FROM telegram_inbox AS inbox WHERE inbox.receipt_id=origin.receipt_id AND origin.finished_at IS NULL
        AND (${recorded.sql}) AND NOT EXISTS (SELECT 1 FROM telegram_provider_document_lines AS line
          WHERE line.receipt_id=origin.receipt_id AND line.result_code IS NULL)`).bind(...recorded.bindings),
    db.prepare(`DELETE FROM telegram_provider_document_opt_in WHERE receipt_id IN (
      SELECT opted.receipt_id FROM telegram_provider_document_opt_in AS opted
      JOIN telegram_document_jobs AS document USING (receipt_id)
      WHERE document.bot_id=? AND document.state='done' ORDER BY opted.receipt_id LIMIT 16)`).bind(policy.botId),
  ];
  try {
    assertBatch(await db.batch(steps), steps);
  } catch {
    throw new Error("Telegram provider document settlement could not be confirmed.");
  }
}

import { PROVIDER_JOB_TTL_SECONDS, TELEGRAM_PROVIDER_MARKER, type ProviderSql } from "../provider-jobs.ts";
import type { TelegramProviderEvent } from "./provider-admission.ts";
import type { TelegramPolicy } from "./protocol.ts";

const REPLY_SECONDS = 900;
const RECONCILE_LIMIT = 16;
const URL_TOKEN = /^https?:\/\/\S*(?![\s\S])/iu;
const LINE_BREAK = /[\n\r\v\f\u001c-\u001e\u0085\u2028\u2029]/u;
const URI_IN_NAME = /[a-z][a-z0-9+.-]*:\/\//iu;

const OUTCOMES = {
  "invalid-url": "订阅链接无效。请发送单条 HTTP 或 HTTPS 链接。",
  unavailable: "这条订阅暂时无法导入。",
  conflict: "找到多条匹配的订阅，无法确定导入目标。",
  capacity: "待处理订阅已达上限，请稍后重试。",
  saved: "远程订阅已导入。发送 /list 查看。",
  coalesced: "相同订阅已在处理中。",
  "stale-target": "订阅状态已变更，本次导入未保存。",
  expired: "订阅导入已超时，请重新发送链接。",
  "attempts-exhausted": "订阅导入未完成，请稍后重试。",
  "invalid-document": "未能识别远程订阅中的节点。",
  "fetch-rejected": "无法获取远程订阅。",
  "storage-failed": "暂时无法保存远程订阅。",
} as const;

export type TelegramProviderReply = keyof typeof OUTCOMES;
type UrlInput = Pick<Extract<TelegramProviderEvent, { kind: "url-import" }>, "sourceUrl" | "name">;
type InboxAlias = "inbox" | "earlier";

/** Run only after the authenticated decoder classified a private non-command as temp text. */
export function parseTelegramProviderText(text: string): UrlInput | null {
  if (LINE_BREAK.test(text)) return null;
  const trimmed = text.trim();
  if (URL_TOKEN.test(trimmed)) return { sourceUrl: trimmed };
  const divider = trimmed.indexOf("|");
  if (divider < 0) return null;
  const name = trimmed.slice(0, divider).trim();
  const sourceUrl = trimmed.slice(divider + 1).trim();
  return !URI_IN_NAME.test(name) && URL_TOKEN.test(sourceUrl) ? { name, sourceUrl } : null;
}

export function renderTelegramProviderReply(outcome: TelegramProviderReply): string {
  if (!Object.hasOwn(OUTCOMES, outcome)) throw new Error("Unknown Telegram provider outcome.");
  return OUTCOMES[outcome];
}

export async function telegramProviderRepliesReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
      AND name IN ('telegram_provider_jobs','telegram_provider_requests','telegram_provider_replies')`)
      .first<number>("present");
    return row === 3;
  } catch {
    throw new Error("Telegram provider reply schema could not be confirmed.");
  }
}

function providerPrivateInbox(alias: InboxAlias): string {
  return `${alias}.receipt_nonce = '${TELEGRAM_PROVIDER_MARKER}' AND ${alias}.command = 'help'
    AND ${alias}.chat_type = 'private' AND ${alias}.chat_id = ${alias}.actor_id AND ${alias}.thread_id IS NULL`;
}

export function telegramProviderReplyMarker(alias: InboxAlias): string {
  return `(${providerPrivateInbox(alias)} AND EXISTS (
    SELECT 1 FROM telegram_provider_replies WHERE receipt_id = ${alias}.receipt_id))`;
}

export function telegramProviderReplyClock(alias: InboxAlias): string {
  return `COALESCE((SELECT ready_at FROM telegram_provider_replies WHERE receipt_id = ${alias}.receipt_id
    AND ${alias}.receipt_nonce = '${TELEGRAM_PROVIDER_MARKER}'), ${alias}.received_at)`;
}

function exactProviderEpoch(policy: TelegramPolicy, alias: InboxAlias = "inbox"): ProviderSql {
  return { sql: `${providerPrivateInbox(alias)} AND origin.kind = 'url-import'
    AND ((${alias}.actor_id = ? AND origin.actor_role = 'admin' AND origin.auth_message_date = 0 AND origin.auth_message_id = 0)
      OR (${alias}.actor_id = ? AND origin.actor_role = 'member' AND ${alias}.message_date > origin.auth_message_date
        AND COALESCE((SELECT allowed = 1 AND message_date = origin.auth_message_date AND message_id = origin.auth_message_id
          FROM telegram_auth WHERE bot_id = ${alias}.bot_id AND user_id = ${alias}.actor_id),
          origin.auth_message_date = 0 AND origin.auth_message_id = 0)))`, bindings: [policy.adminId, policy.memberId] };
}

export function telegramProviderReplyEligible(policy: TelegramPolicy | undefined, alias: InboxAlias): ProviderSql {
  if (!policy) return { sql: "1", bindings: [] };
  const epoch = exactProviderEpoch(policy, alias);
  return { sql: `(${alias}.receipt_nonce IS NOT '${TELEGRAM_PROVIDER_MARKER}' OR EXISTS (
    SELECT 1 FROM telegram_provider_requests AS origin WHERE origin.receipt_id = ${alias}.receipt_id AND ${epoch.sql}))`,
    bindings: epoch.bindings };
}

export function telegramProviderReplySendGuard(policy: TelegramPolicy, outcome: TelegramProviderReply): ProviderSql {
  const epoch = exactProviderEpoch(policy);
  return { sql: `EXISTS (SELECT 1 FROM telegram_provider_replies AS provider
    JOIN telegram_provider_requests AS origin USING (receipt_id)
    WHERE provider.receipt_id = inbox.receipt_id AND provider.outcome = ? AND ${epoch.sql})`,
    bindings: [outcome, ...epoch.bindings] };
}

/** Repair notification after an ambiguous or delayed terminal commit without making an outbound call. */
export async function reconcileTelegramProviderReplies(db: D1Database, policy: TelegramPolicy): Promise<number> {
  const epoch = exactProviderEpoch(policy);
  try {
    const results = await db.batch([
      db.prepare(`WITH terminal AS (
        SELECT inbox.receipt_id, COALESCE(job.result_code, origin.outcome) AS outcome,
          COALESCE(min(job.finished_at, job.expires_at), inbox.received_at) AS ready_at
        FROM telegram_inbox AS inbox JOIN telegram_provider_requests AS origin USING (receipt_id)
        LEFT JOIN telegram_provider_jobs AS job ON job.job_id = origin.job_id
        WHERE inbox.bot_id = ? AND ${epoch.sql} AND inbox.received_at > unixepoch() - ${PROVIDER_JOB_TTL_SECONDS + REPLY_SECONDS}
          AND ((origin.job_id IS NULL AND origin.outcome <> 'admitted') OR
            (origin.outcome = 'admitted' AND job.owner_id = inbox.actor_id AND job.kind = origin.kind AND job.state = 'done'))
          AND NOT EXISTS (SELECT 1 FROM telegram_provider_replies WHERE receipt_id = inbox.receipt_id)
          AND NOT EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id = inbox.receipt_id)
      ) INSERT INTO telegram_provider_replies (receipt_id, outcome, ready_at)
      SELECT receipt_id, outcome, ready_at FROM terminal WHERE ready_at > unixepoch() - ${REPLY_SECONDS}
      ORDER BY ready_at, receipt_id LIMIT ${RECONCILE_LIMIT}`).bind(policy.botId, ...epoch.bindings),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT provider.receipt_id FROM telegram_provider_replies AS provider
        JOIN telegram_inbox AS inbox USING (receipt_id) JOIN telegram_provider_requests AS origin USING (receipt_id)
        WHERE inbox.bot_id = ? AND ${epoch.sql} AND provider.ready_at > unixepoch() - ${REPLY_SECONDS}
          AND NOT EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id = provider.receipt_id)
        ORDER BY provider.ready_at, provider.receipt_id LIMIT ${RECONCILE_LIMIT}`).bind(policy.botId, ...epoch.bindings),
    ]);
    if (results.length !== 2 || results.some(({ success, meta }) => !success || meta.changes < 0 || meta.changes > RECONCILE_LIMIT)) {
      throw new Error();
    }
    return results[1].meta.changes;
  } catch {
    throw new Error("Telegram provider reply reconciliation could not be confirmed.");
  }
}

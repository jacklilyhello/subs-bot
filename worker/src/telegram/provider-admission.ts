import {
  prepareOwnedProviderRefresh, prepareProviderUrlImport, providerHost, TELEGRAM_PROVIDER_MARKER, type ProviderSql, type ProviderTelegramPolicy,
} from "../provider-jobs.ts";
import { digestHex, validInteger } from "../storage.ts";
import { normalizeSubscriptionName } from "../subscriptions.ts";
import { inTelegramScope, type TelegramEventScope, type TelegramPolicy, type TelegramProviderRefreshUpdate } from "./protocol.ts";
import { readTelegramProviderRefreshAdmission } from "./provider-refresh.ts";

export type TelegramProviderEvent = TelegramEventScope & (
  | { kind: "url-import"; sourceUrl: string; name?: string }
  | { kind: "refresh"; id: number; expectedGeneration: number; expectedLifecycleRevision: number }
  | ({ kind: "refresh-ticket" } & Pick<TelegramProviderRefreshUpdate, "callbackId" | "ticket">)
);

type Refusal = "invalid-url" | "unavailable" | "conflict" | "capacity";
export type TelegramProviderAdmission =
  | { kind: "ignored" | "duplicate" | Refusal }
  | { kind: "queued" | "coalesced"; jobId: number; subscriptionId: number };
type Receipt = { outcome: "admitted" | Refusal; jobId: number | null; subscriptionId: number | null; jobResult: string | null };

const encoder = new TextEncoder();
const fresh = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";
const freshInbox = `EXISTS (SELECT 1 FROM telegram_inbox AS incoming WHERE ${fresh})`;

function currentAdmission(policy: TelegramPolicy, event: TelegramEventScope): ProviderSql {
  return {
    sql: `? BETWEEN unixepoch() - 900 AND unixepoch() + 30 AND (? = ? OR COALESCE((
      SELECT allowed = 1 AND message_date < ? FROM telegram_auth WHERE bot_id = ? AND user_id = ?
    ), 1))`,
    bindings: [event.messageDate, event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId],
  };
}

function fixedRefusal(kind: Refusal): ProviderSql {
  return { sql: "?", bindings: [kind] };
}

function cleanName(value: string | undefined): string | null {
  try {
    return normalizeSubscriptionName(value ?? "远程订阅");
  } catch {
    return null;
  }
}

/** Stage only an already decoded, private event. The consumer performs the fetch. */
export async function acceptTelegramProviderRequest(
  db: D1Database, policy: TelegramPolicy & ProviderTelegramPolicy, event: TelegramProviderEvent,
  includeBatch = false,
): Promise<TelegramProviderAdmission> {
  if (!inTelegramScope(policy, event) || event.chatType !== "private" || event.threadId !== null || event.chatId !== event.actorId ||
      !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return { kind: "ignored" };
  try {
    const kind = event.kind === "refresh-ticket" ? "refresh" : event.kind;
    const refresh = event.kind === "refresh-ticket" ? await readTelegramProviderRefreshAdmission(db, policy, event) : null;
    if (event.kind === "refresh-ticket" && refresh === null) return { kind: "ignored" };
    const requestKey = digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(
      `subs-bot:telegram-provider-request:v1\n${policy.botId}\n${event.updateId}`)));
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const current = currentAdmission(policy, event);
    const gate = refresh ? { sql: `(${current.sql}) AND (${refresh.guard.sql})`,
      bindings: [...current.bindings, ...refresh.guard.bindings] } : current;
    const fence = { sql: freshInbox, bindings: key };
    const input = { ownerId: event.actorId, requestKey };
    let refusal: ProviderSql;
    let admission: D1PreparedStatement[] = [];
    if (event.kind === "url-import") {
      const name = cleanName(event.name);
      if (!name || !providerHost(event.sourceUrl)) {
        refusal = fixedRefusal("invalid-url");
      } else {
        const { plan } = await prepareProviderUrlImport(db, { ...input, sourceUrl: event.sourceUrl, name }, fence, policy, includeBatch);
        admission = plan.statements;
        refusal = plan.refusal;
      }
    } else {
      const target = event.kind === "refresh-ticket" ? refresh && { id: refresh.id,
        expectedGeneration: refresh.generation, expectedLifecycleRevision: refresh.lifecycleRevision } : event;
      const prepared = target && validInteger(target.id, 1) && validInteger(target.expectedGeneration, 0)
        && validInteger(target.expectedLifecycleRevision, 0) ? await prepareOwnedProviderRefresh(db, {
          ...input, id: target.id, expectedGeneration: target.expectedGeneration,
          expectedLifecycleRevision: target.expectedLifecycleRevision,
        }, fence, gate, policy, includeBatch) : null;
      if (refresh && prepared?.digest !== refresh.sourceSha256) return { kind: "ignored" };
      admission = prepared?.plan.statements ?? [];
      refusal = prepared?.plan.refusal ?? fixedRefusal("unavailable");
    }
    const steps = [
      db.prepare(`INSERT INTO telegram_inbox (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT ?,?,?,?,'private',?,?,NULL,'help',? WHERE ${gate.sql}
        ON CONFLICT (bot_id,update_id) DO NOTHING`)
        .bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce, ...gate.bindings),
      db.prepare(`SELECT CASE WHEN NOT ${fence.sql} OR NOT EXISTS (
        SELECT 1 FROM telegram_provider_jobs WHERE owner_id=? AND request_key=?)
        THEN 1 ELSE json_extract('provider request key collision', '$') END`)
        .bind(...key, event.actorId, requestKey),
      ...admission,
      ...(refresh ? [db.prepare(`UPDATE telegram_provider_refresh_tickets AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${fresh}`)
        .bind(refresh.tokenSha256, ...key)] : []),
      db.prepare(`INSERT INTO telegram_provider_requests (receipt_id,job_id,kind,outcome,actor_role,auth_message_date,auth_message_id)
        SELECT incoming.receipt_id,job.job_id,?,CASE WHEN job.job_id IS NULL THEN (${refusal.sql}) ELSE 'admitted' END,?,
          CASE WHEN incoming.actor_id=? THEN 0 ELSE COALESCE(auth.message_date,0) END,
          CASE WHEN incoming.actor_id=? THEN 0 ELSE COALESCE(auth.message_id,0) END
        FROM telegram_inbox AS incoming
        LEFT JOIN telegram_auth AS auth ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id
        LEFT JOIN telegram_provider_jobs AS job ON job.owner_id=incoming.actor_id AND job.request_key=? AND job.kind=?
        WHERE ${fresh}`).bind(kind, ...refusal.bindings, event.actorId === policy.adminId ? "admin" : "member",
        policy.adminId, policy.adminId, requestKey, kind, ...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?, command=CASE WHEN EXISTS (
          SELECT 1 FROM telegram_provider_requests WHERE receipt_id=incoming.receipt_id)
          ${refresh ? `AND EXISTS (SELECT 1 FROM telegram_provider_refresh_tickets
            WHERE token_sha256=? AND used_by_receipt_id=incoming.receipt_id)` : ""} THEN command END
        WHERE ${fresh}`).bind(TELEGRAM_PROVIDER_MARKER, ...(refresh ? [refresh.tokenSha256] : []), ...key),
      db.prepare(`SELECT origin.outcome,origin.job_id AS jobId,job.subscription_id AS subscriptionId,job.result_code AS jobResult
        FROM telegram_inbox AS incoming JOIN telegram_provider_requests AS origin USING (receipt_id)
        LEFT JOIN telegram_provider_jobs AS job ON job.job_id=origin.job_id
        WHERE incoming.bot_id=? AND incoming.update_id=? AND incoming.actor_id=? AND incoming.chat_id=?
          AND incoming.chat_type='private' AND incoming.thread_id IS NULL AND incoming.receipt_nonce=?`)
        .bind(policy.botId, event.updateId, event.actorId, event.chatId, TELEGRAM_PROVIDER_MARKER),
    ];
    const results = await db.batch<Receipt>(steps);
    if (results.length !== steps.length || results.some(({ success }) => !success) || results.at(-1)!.results.length > 1) throw new Error();
    const stored = results.at(-1)!.results[0];
    if (results[0].meta.changes === 0) return { kind: stored ? "duplicate" : "ignored" };
    if (results[0].meta.changes !== 1 || results.at(-2)!.meta.changes !== 1 || results.at(-3)!.meta.changes !== 1 || !stored) throw new Error();
    if (stored.outcome !== "admitted") return { kind: stored.outcome };
    if (!validInteger(stored.jobId, 1) || !validInteger(stored.subscriptionId, 1) ||
        (stored.jobResult !== null && stored.jobResult !== "coalesced")) throw new Error();
    return { kind: stored.jobResult === "coalesced" ? "coalesced" : "queued", jobId: stored.jobId, subscriptionId: stored.subscriptionId };
  } catch {
    throw new Error("Telegram provider admission could not be confirmed.");
  }
}

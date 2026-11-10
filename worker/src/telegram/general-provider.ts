import { UNNAMED_PROVIDER_SUBSCRIPTION } from "../provider-initial-title.ts";
import { GENERAL_TELEGRAM_PROVIDER_MARKER, prepareOwnedProviderRefresh, prepareProviderUrlImport, providerHost, type GeneralProviderAuthority,
  type ProviderSql } from "../provider-jobs.ts";
import { digestHex, validInteger } from "../storage.ts";
import { normalizeSubscriptionName } from "../subscriptions.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL,
  GENERAL_POLICY_PIN_SQL, GENERAL_POLICY_SCHEMA, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentAuthoritySql,
  generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import type { TelegramEventScope, TelegramProviderRefreshUpdate } from "./protocol.ts";
import { telegramGeneralProviderDocumentsReady } from "./provider-document.ts";
import { readGeneralProviderRefreshAdmission } from "./provider-refresh.ts";
import { GENERAL_PROVIDER_REPLY_SCHEMA } from "./provider-replies.ts";

type ProviderEvent = (TelegramEventScope & { kind: "url-import"; sourceUrl: string; name?: string })
  | (TelegramProviderRefreshUpdate & { kind: "refresh" });
const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
const encoder = new TextEncoder();

export function generalProviderAuthority(pin: GeneralTelegramPin): GeneralProviderAuthority {
  const { botId, generation, cutoverAt, activationSha256, releaseRevision } = pin;
  return { family: "general", botId, generation, cutoverAt, activationSha256, releaseRevision,
    ...(pin.providerDocumentReplies ? { includeDocuments: true as const } : {}) };
}

export async function generalProviderSchemaReady(db: D1Database): Promise<boolean> {
  return Boolean(await db.prepare(`SELECT 1 WHERE (${GENERAL_POLICY_SCHEMA}) AND (${GENERAL_RECEIPT_SCHEMA})
    AND (${GENERAL_PROVIDER_REPLY_SCHEMA})`).first());
}

/** Admit one private provider request without performing any egress in the webhook. */
export async function acceptGeneralProviderRequest(db: D1Database, pin: GeneralTelegramPin, event: ProviderEvent): Promise<boolean> {
  if (!pin.privateProvider || event.actorId === pin.botId || event.chatType !== "private" || event.actorId !== event.chatId
    || event.threadId !== null || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1)
    || !validInteger(event.messageDate, 1)) return false;
  try {
    const requestKey = digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(
      `subs-bot:telegram-general-provider-${event.kind === "refresh" ? "refresh" : "url"}:v1\n${pin.botId}\n${pin.generation}\n${event.updateId}`)));
    const nonce = crypto.randomUUID();
    const key = [pin.botId, event.updateId, nonce] as const;
    const fence = { sql: `EXISTS (SELECT 1 FROM telegram_inbox AS incoming WHERE ${fresh})`, bindings: key };
    const documents = pin.providerDocumentReplies || await telegramGeneralProviderDocumentsReady(db, pin.botId, false).catch(() => false);
    const authority = generalProviderAuthority(documents ? { ...pin, providerDocumentReplies: true } : pin);
    const input = { ownerId: event.actorId, requestKey };
    const refresh = event.kind === "refresh" ? await readGeneralProviderRefreshAdmission(db, pin, event) : null;
    let plan: Awaited<ReturnType<typeof prepareProviderUrlImport>>["plan"] | null = null;
    if (event.kind === "refresh") {
      if (!refresh) return false;
      const prepared = await prepareOwnedProviderRefresh(db, { ...input, id: refresh.id,
        expectedGeneration: refresh.generation, expectedLifecycleRevision: refresh.lifecycleRevision }, fence, refresh.guard, authority);
      if (!prepared || prepared.digest !== refresh.sourceSha256) return false;
      plan = prepared.plan;
    } else {
      let name: string | null;
      try { name = normalizeSubscriptionName(event.name ?? UNNAMED_PROVIDER_SUBSCRIPTION); } catch { name = null; }
      if (name && providerHost(event.sourceUrl)) {
        plan = (await prepareProviderUrlImport(db, { ...input, sourceUrl: event.sourceUrl, name,
          initialTitle: event.name === undefined }, fence, authority)).plan;
      }
    }
    const refusal: ProviderSql = plan?.refusal ?? { sql: "?", bindings: ["invalid-url"] };
    const steps = [
      db.prepare(`INSERT INTO telegram_inbox
        (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
        SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,NULL,'help',?
        FROM ${GENERAL_POLICY_ACTORS_SQL}
        WHERE (${GENERAL_POLICY_PIN_SQL}) AND (${GENERAL_RECEIPT_SCHEMA}) AND (${GENERAL_PROVIDER_REPLY_SCHEMA})
          AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK} AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
          AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
          AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
          AND ${GENERAL_ACTOR_QUEUE_CAPACITY} ${refresh ? `AND (${refresh.guard.sql})` : ""}
        ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(event.updateId, event.messageId, event.messageDate, nonce,
        ...generalPolicyBindings(pin), event.actorId, event.messageDate, event.messageDate, event.updateId, ...(refresh?.guard.bindings ?? [])),
      prepareGeneralReceiptAuthority(db, pin, key),
      db.prepare(`SELECT CASE WHEN NOT ${fence.sql} OR NOT EXISTS (
        SELECT 1 FROM telegram_provider_jobs WHERE owner_id=? AND request_key=?)
        THEN 1 ELSE json_extract('general provider request key collision','$') END`).bind(...key, event.actorId, requestKey),
      ...(plan?.statements ?? []),
      ...(refresh ? [db.prepare(`UPDATE telegram_provider_refresh_tickets AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${fresh}`)
        .bind(refresh.tokenSha256, ...key)] : []),
      db.prepare(`INSERT INTO telegram_provider_requests
        (receipt_id,job_id,kind,outcome,actor_role,auth_message_date,auth_message_id)
        SELECT incoming.receipt_id,job.job_id,?,CASE WHEN job.job_id IS NULL THEN (${refusal.sql}) ELSE 'admitted' END,
          recorded.actor_role,0,0 FROM telegram_inbox AS incoming JOIN telegram_general_receipt AS recorded USING(receipt_id)
        LEFT JOIN telegram_provider_jobs AS job ON job.owner_id=incoming.actor_id AND job.request_key=? AND job.kind=?
        WHERE ${fresh}`).bind(event.kind, ...refusal.bindings, requestKey, event.kind, ...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?, command=CASE WHEN
        EXISTS (SELECT 1 FROM telegram_provider_requests WHERE receipt_id=incoming.receipt_id)
        ${refresh ? `AND EXISTS (SELECT 1 FROM telegram_provider_refresh_tickets
          WHERE token_sha256=? AND used_by_receipt_id=incoming.receipt_id)` : ""}
        AND (${generalCurrentAuthoritySql("incoming")}) THEN command END
        WHERE ${fresh} RETURNING receipt_id`).bind(GENERAL_TELEGRAM_PROVIDER_MARKER, ...(refresh ? [refresh.tokenSha256] : []),
        ...generalPolicyBindings(pin), ...key),
    ];
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && results.every(({ success }) => success)
      && receipt.results.length <= 1 && results[0].meta.changes === receipt.results.length) return receipt.results.length === 1;
  } catch {
    // Keep source URL, chosen name and D1 diagnostics private.
  }
  throw new Error("General Telegram provider admission could not be confirmed.");
}

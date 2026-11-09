import { MAX_AGGREGATE_MEMBERS } from "../aggregate.ts";
import { MAX_PATH_RULES } from "../path-rules.ts";
import { ISOLATION_PUBLIC_ORIGIN } from "../short-links.ts";
import { digestHex, MAX_SNAPSHOT_NODES, validInteger } from "../storage.ts";
import { inTelegramScope, type TelegramAggregateUpdate, type TelegramPolicy } from "./protocol.ts";
import {
  MAX_TEMP_OWNER_BYTES, MAX_TEMP_OWNER_NODES, ownedTempRowsSql, readTempStorage, tempCutoverAllows, tempSchemaGuard,
  type TempStorageMode,
} from "./temp-storage.ts";

export const TELEGRAM_AGGREGATE_MARKER = "aggregate:v1";
export const TELEGRAM_AGGREGATE_ORIGIN = ISOLATION_PUBLIC_ORIGIN;
const KEY_VERSION = 1;
const MAX_COMMAND_AGE_SECONDS = 900;
const FUTURE_SKEW_SECONDS = 30;
const ENCODER = new TextEncoder();
const NONCE = /^[A-Za-z0-9_-]{22}(?![\s\S])/u;
const KEY = /^[A-Za-z0-9_-]{43}(?![\s\S])/u;
const DIGEST = /^[a-f0-9]{64}(?![\s\S])/u;
const fresh = "inbox.bot_id = ? AND inbox.update_id = ? AND inbox.receipt_nonce = ?";

export type TelegramAggregateResult = "issued" | "ready" | "empty" | "limit" | "revoked" | "already-revoked" | "stale";
export interface TelegramAggregateReply {
  result: TelegramAggregateResult;
  revision: number | null;
  codeSha256: string | null;
}

type AggregateGuard = { sql: string; bindings: readonly (string | number)[] };

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

export async function parseTelegramAggregateKey(value: unknown): Promise<CryptoKey | null> {
  if (typeof value !== "string" || !KEY.test(value)) return null;
  try {
    const binary = atob(value.replaceAll("-", "+").replaceAll("_", "/"));
    const bytes = Uint8Array.from(binary, (char) => char.charCodeAt(0));
    if (bytes.byteLength !== 32 || base64Url(bytes) !== value) return null;
    return await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  } catch {
    return null;
  }
}

async function deriveCode(key: CryptoKey, botId: string, actorId: string, nonce: string): Promise<string> {
  const input = ENCODER.encode(JSON.stringify([
    "subs-bot/telegram-aggregate/all", KEY_VERSION, TELEGRAM_AGGREGATE_ORIGIN, botId, actorId, nonce,
  ]));
  return base64Url(new Uint8Array(await crypto.subtle.sign("HMAC", key, input)).subarray(0, 16));
}

async function codeDigest(code: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", ENCODER.encode(code)));
}

export async function acceptTelegramAggregate(
  db: D1Database,
  policy: TelegramPolicy,
  event: TelegramAggregateUpdate,
  key: CryptoKey,
): Promise<"accepted" | "ignored"> {
  if (event.chatType !== "private" || event.threadId !== null || !inTelegramScope(policy, event) ||
      !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1) ||
      (event.kind !== "show" && event.kind !== "revoke")) return "ignored";
  try {
    const show = event.kind === "show";
    const tempMode = show ? await readTempStorage(db) : "live-only";
    const tempCutover = show ? `OR NOT (${tempSchemaGuard(tempMode)})
      OR NOT (${tempCutoverAllows(tempMode, "scoped.bot_id", "scoped.message_date")})` : "";
    const nonce = show ? base64Url(crypto.getRandomValues(new Uint8Array(16))) : null;
    const candidateHash = nonce === null ? null : await codeDigest(await deriveCode(key, policy.botId, event.actorId, nonce));
    const receipt = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const steps = [
      db.prepare(`
        INSERT INTO telegram_inbox
          (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
        SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
        WHERE ? = ? OR COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id = ? AND user_id = ?), 1) = 1
        ON CONFLICT (bot_id, update_id) DO NOTHING
      `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, receipt[2],
        event.actorId, policy.adminId, policy.botId, event.actorId),
      db.prepare(`
        WITH scoped AS (
          SELECT inbox.receipt_id, inbox.bot_id, inbox.actor_id, inbox.message_date, inbox.message_id,
            slot.revision, slot.message_date AS last_date, slot.message_id AS last_id, link.code_sha256 AS current_hash,
            CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_date, 0) END AS auth_date,
            CASE WHEN inbox.actor_id = ? THEN 0 ELSE COALESCE(auth.message_id, 0) END AS auth_id
          FROM telegram_inbox AS inbox LEFT JOIN telegram_aggregate_slots AS slot USING (bot_id, actor_id)
          LEFT JOIN aggregate_links AS link ON link.code_sha256 = slot.code_sha256 AND link.owner_id = inbox.actor_id
            AND link.bot_id = inbox.bot_id AND link.kind = 'all' AND link.revoked_at IS NULL
          LEFT JOIN telegram_auth AS auth ON auth.bot_id = inbox.bot_id AND auth.user_id = inbox.actor_id
          WHERE ${fresh}
        ), snapshots AS (
          SELECT count(*) AS members, COALESCE(sum(node_count), 0) AS nodes FROM (
            SELECT sub.node_count FROM scoped JOIN subscriptions AS sub ON sub.owner_id = scoped.actor_id
            WHERE sub.generation > 0 ORDER BY sub.id LIMIT ${MAX_AGGREGATE_MEMBERS + 1}
          )
        ), temp_scope AS (
          SELECT bot_id,actor_id,NULL AS before_receipt,message_date AS visibility_epoch FROM scoped WHERE ${show ? 1 : 0}
        ), temp_totals AS (
          SELECT COALESCE(sum(nodeCount),0) AS nodes,COALESCE(sum(bytes),0) AS bytes FROM (
            SELECT nodeCount,bytes FROM (${ownedTempRowsSql(tempMode, "temp_scope", { verifyLive: false })})
            ORDER BY source,id LIMIT ${MAX_TEMP_OWNER_NODES + 1}
          )
        ), classified AS (
          SELECT scoped.*, CASE
            WHEN message_date <= unixepoch() - ${MAX_COMMAND_AGE_SECONDS}
              OR message_date > unixepoch() + ${FUTURE_SKEW_SECONDS}
              OR (message_date, message_id) <= (last_date, last_id)
              OR (actor_id <> ? AND auth_date >= message_date) ${tempCutover} THEN 'stale'
            WHEN ? = 'revoke' THEN CASE WHEN current_hash IS NULL THEN 'already-revoked' ELSE 'revoked' END
            WHEN snapshots.members > ${MAX_AGGREGATE_MEMBERS} OR temp_totals.nodes > ${MAX_TEMP_OWNER_NODES}
              OR temp_totals.bytes > ${MAX_TEMP_OWNER_BYTES} OR snapshots.nodes + temp_totals.nodes > ${MAX_SNAPSHOT_NODES}
              OR (snapshots.members > 0 AND EXISTS (SELECT 1 FROM path_rules WHERE owner_id = scoped.actor_id
                LIMIT 1 OFFSET ${MAX_PATH_RULES})) THEN 'limit'
            WHEN snapshots.nodes + temp_totals.nodes = 0 THEN 'empty'
            WHEN current_hash IS NULL THEN 'issued'
            ELSE 'ready'
          END AS result
          FROM scoped CROSS JOIN snapshots CROSS JOIN temp_totals
        )
        INSERT INTO telegram_aggregate_actions (receipt_id, result, revision, code_sha256, auth_message_date, auth_message_id)
        SELECT receipt_id, result, CASE WHEN result = 'ready' THEN revision
          WHEN result IN ('issued', 'revoked', 'already-revoked') THEN COALESCE(revision, 0) + 1 END,
          CASE WHEN result = 'issued' THEN ? WHEN result IN ('ready', 'revoked') THEN current_hash END, auth_date, auth_id
        FROM classified
      `).bind(policy.adminId, policy.adminId, ...receipt, policy.adminId, event.kind, candidateHash),
      db.prepare(`
        INSERT INTO aggregate_links (code_sha256, owner_id, kind, bot_id)
        SELECT action.code_sha256, inbox.actor_id, 'all', inbox.bot_id
        FROM telegram_inbox AS inbox JOIN telegram_aggregate_actions AS action USING (receipt_id)
        WHERE ${fresh} AND action.result = 'issued'
      `).bind(...receipt),
      db.prepare(`
        UPDATE aggregate_links AS link SET revoked_at = max(created_at, unixepoch())
        FROM telegram_inbox AS inbox JOIN telegram_aggregate_actions AS action USING (receipt_id)
        WHERE ${fresh} AND action.result = 'revoked' AND link.code_sha256 = action.code_sha256
          AND link.owner_id = inbox.actor_id AND link.bot_id = inbox.bot_id AND link.kind = 'all' AND link.revoked_at IS NULL
      `).bind(...receipt),
      db.prepare(`
        INSERT INTO telegram_aggregate_slots (bot_id, actor_id, revision, code_sha256, nonce, key_version, message_date, message_id)
        SELECT inbox.bot_id, inbox.actor_id, action.revision, CASE WHEN action.result = 'issued' THEN action.code_sha256 END,
          CASE WHEN action.result = 'issued' THEN ? END, CASE WHEN action.result = 'issued' THEN ${KEY_VERSION} END,
          inbox.message_date, inbox.message_id
        FROM telegram_inbox AS inbox JOIN telegram_aggregate_actions AS action USING (receipt_id)
        WHERE ${fresh} AND action.result IN ('issued', 'revoked', 'already-revoked')
        ON CONFLICT (bot_id, actor_id) DO UPDATE SET revision = excluded.revision, code_sha256 = excluded.code_sha256,
          nonce = excluded.nonce, key_version = excluded.key_version, message_date = excluded.message_date, message_id = excluded.message_id
        WHERE telegram_aggregate_slots.revision = excluded.revision - 1
          AND (excluded.message_date, excluded.message_id) > (telegram_aggregate_slots.message_date, telegram_aggregate_slots.message_id)
      `).bind(nonce, ...receipt),
      db.prepare(`
        INSERT INTO telegram_outbox (receipt_id)
        SELECT inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_aggregate_actions AS action USING (receipt_id)
        WHERE ${fresh}
      `).bind(...receipt),
      db.prepare(`
        UPDATE telegram_inbox AS inbox SET receipt_nonce = ?, command = CASE WHEN EXISTS (
          SELECT 1 FROM telegram_aggregate_actions AS action JOIN telegram_outbox USING (receipt_id)
          LEFT JOIN telegram_aggregate_slots AS slot ON slot.bot_id = inbox.bot_id AND slot.actor_id = inbox.actor_id
          LEFT JOIN aggregate_links AS link ON link.code_sha256 = action.code_sha256 AND link.owner_id = inbox.actor_id
            AND link.bot_id = inbox.bot_id AND link.kind = 'all'
          WHERE action.receipt_id = inbox.receipt_id AND CASE action.result
            WHEN 'issued' THEN slot.revision = action.revision AND slot.code_sha256 = link.code_sha256 AND link.revoked_at IS NULL
            WHEN 'ready' THEN slot.revision = action.revision AND slot.code_sha256 = link.code_sha256 AND link.revoked_at IS NULL
            WHEN 'revoked' THEN slot.revision = action.revision AND slot.code_sha256 IS NULL AND link.revoked_at IS NOT NULL
            WHEN 'already-revoked' THEN slot.revision = action.revision AND slot.code_sha256 IS NULL
            ELSE 1 END
        ) THEN command END WHERE ${fresh} RETURNING receipt_id
      `).bind(TELEGRAM_AGGREGATE_MARKER, ...receipt),
    ];
    const results = await db.batch(steps);
    const confirmed = results.at(-1);
    if (confirmed && results.length === steps.length && results.every(({ success }) => success) && confirmed.results.length <= 1) {
      return confirmed.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // Database or crypto exceptions must not expose private identifiers or derivation inputs.
  }
  throw new Error("Telegram aggregate receipt could not be confirmed.");
}

export function aggregateLinkDeliveryGuard(policy: TelegramPolicy, reply: TelegramAggregateReply, mode: TempStorageMode): AggregateGuard | null {
  if ((reply.result !== "ready" && reply.result !== "issued") || !validInteger(reply.revision, 1) ||
      reply.codeSha256 === null || !DIGEST.test(reply.codeSha256)) return null;
  return {
    sql: `inbox.receipt_nonce = '${TELEGRAM_AGGREGATE_MARKER}' AND inbox.command = 'help'
      AND inbox.chat_type = 'private' AND inbox.chat_id = inbox.actor_id AND inbox.thread_id IS NULL
      AND (${tempSchemaGuard(mode)}) AND (${tempCutoverAllows(mode, "inbox.bot_id", "inbox.message_date")})
      AND EXISTS (
        SELECT 1 FROM telegram_aggregate_actions AS aggregate
        JOIN telegram_aggregate_slots AS slot ON slot.bot_id = inbox.bot_id AND slot.actor_id = inbox.actor_id
        JOIN aggregate_links AS link ON link.code_sha256 = slot.code_sha256 AND link.owner_id = inbox.actor_id
          AND link.bot_id = inbox.bot_id AND link.kind = 'all' AND link.revoked_at IS NULL
        WHERE aggregate.receipt_id = inbox.receipt_id AND aggregate.result IN ('issued', 'ready')
          AND aggregate.revision = ? AND aggregate.code_sha256 = ?
          AND slot.revision = aggregate.revision AND slot.code_sha256 = aggregate.code_sha256 AND slot.key_version = ${KEY_VERSION}
          AND ((inbox.actor_id = ? AND aggregate.auth_message_date = 0 AND aggregate.auth_message_id = 0)
          OR (inbox.actor_id = ? AND COALESCE((
            SELECT allowed = 1 AND message_date = aggregate.auth_message_date AND message_id = aggregate.auth_message_id
            FROM telegram_auth WHERE bot_id = inbox.bot_id AND user_id = inbox.actor_id
          ), aggregate.auth_message_date = 0 AND aggregate.auth_message_id = 0)))
      )`,
    bindings: [reply.revision, reply.codeSha256, policy.adminId, policy.memberId],
  };
}

export async function resolveTelegramAggregateCode(
  db: D1Database,
  policy: TelegramPolicy,
  scope: { receiptId: number; actorId: string; aggregate: TelegramAggregateReply },
  key: CryptoKey | null,
): Promise<string | null> {
  if (!key || (scope.aggregate.result !== "ready" && scope.aggregate.result !== "issued")) return null;
  try {
    const mode = await readTempStorage(db).catch(() => null);
    if (mode === null) return null;
    const guard = aggregateLinkDeliveryGuard(policy, scope.aggregate, mode);
    if (!guard) return null;
    const nonce = await db.prepare(`SELECT slot.nonce FROM telegram_inbox AS inbox
      JOIN telegram_aggregate_slots AS slot ON slot.bot_id = inbox.bot_id AND slot.actor_id = inbox.actor_id
      WHERE inbox.receipt_id = ? AND inbox.bot_id = ? AND inbox.actor_id = ? AND inbox.receipt_nonce = ? AND ${guard.sql}
    `).bind(scope.receiptId, policy.botId, scope.actorId, TELEGRAM_AGGREGATE_MARKER, ...guard.bindings).first<string>("nonce");
    if (nonce === null || !NONCE.test(nonce)) return null;
    const code = await deriveCode(key, policy.botId, scope.actorId, nonce);
    return await codeDigest(code) === scope.aggregate.codeSha256 ? code : null;
  } catch {
    throw new Error("Telegram aggregate reply could not be resolved.");
  }
}

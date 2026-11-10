import { sendGeneralTelegramPrivateReply } from "./delivery.ts";
import { readPrivateTelegramCommand, readTelegramBotCredentials, readTelegramUpdate, type TelegramBotCredentials } from "./protocol.ts";
import { renderTelegramView } from "./views.ts";

export interface GeneralTelegramPin extends TelegramBotCredentials {
  generation: number;
  cutoverAt: number;
  activationSha256: string;
  releaseRevision: string;
}

interface Lease {
  id: number;
  actorId: string;
  actorRevision: number;
  messageId: number;
  messageDate: number;
  command: "help" | "list";
  leaseId: string;
}

const TTL = 600;
const LEASE_SECONDS = 15;
const MIGRATION_SHA256 = "99ae19a1a0296bcf78598752c323571b3194c7b1e4bd1241c6f4960650fea75d";
const POLICY = `policy.bot_id=? AND policy.generation=? AND policy.activation_sha256=? AND policy.release_revision=? AND policy.cutover_at=?
  AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=44
    AND name='0044_telegram_general_runtime.sql' AND sha256='${MIGRATION_SHA256}' AND mode='applied')`;
const LATEST_ACTOR = `actor.role IN ('admin','member') AND NOT EXISTS (
  SELECT 1 FROM telegram_general_actors AS newer
  WHERE newer.bot_id=actor.bot_id AND newer.generation=actor.generation AND newer.actor_id=actor.actor_id
    AND newer.revision>actor.revision)`;
const ACTORS = `telegram_general_policy AS policy JOIN telegram_general_actors AS actor
  ON actor.bot_id=policy.bot_id AND actor.generation=policy.generation`;
const CURRENT = `receipt.received_at+${TTL}>unixepoch() AND EXISTS (
  SELECT 1 FROM ${ACTORS} WHERE ${POLICY} AND policy.active=1
    AND receipt.bot_id=policy.bot_id AND receipt.generation=policy.generation
    AND actor.actor_id=receipt.actor_id AND actor.revision=receipt.actor_revision AND ${LATEST_ACTOR}
    AND receipt.message_date>MAX(policy.cutover_at,actor.effective_at))`;
const EXACT_LEASE = `receipt_id=? AND bot_id=? AND generation=? AND actor_id=? AND actor_revision=?
  AND message_id=? AND message_date=? AND command=? AND lease_id=?`;

export function parseGeneralTelegramPin(input: unknown, releaseRevision: unknown): GeneralTelegramPin | null {
  if (typeof input !== "string" || input.length > 4096 || typeof releaseRevision !== "string"
    || !/^[0-9a-f]{40}(?![\s\S])/u.test(releaseRevision)) return null;
  try {
    const value = JSON.parse(input) as Record<string, unknown> | null;
    if (value === null || typeof value !== "object" || Array.isArray(value) || Object.keys(value).length !== 7) return null;
    const credentials = readTelegramBotCredentials(value);
    const { generation, cutoverAt, activationSha256 } = value;
    if (!credentials || Number(credentials.botId) >= 2 ** 52 || typeof generation !== "number"
      || !Number.isSafeInteger(generation) || generation < 1 || typeof cutoverAt !== "number"
      || !Number.isSafeInteger(cutoverAt) || cutoverAt < 1 || typeof activationSha256 !== "string"
      || !/^[0-9a-f]{64}(?![\s\S])/u.test(activationSha256)) return null;
    return { ...credentials, generation, cutoverAt, activationSha256, releaseRevision };
  } catch {
    return null;
  }
}

function policyBindings(pin: GeneralTelegramPin) {
  return [pin.botId, pin.generation, pin.activationSha256, pin.releaseRevision, pin.cutoverAt];
}

function leaseBindings(pin: GeneralTelegramPin, lease: Lease) {
  return [lease.id, pin.botId, pin.generation, lease.actorId, lease.actorRevision,
    lease.messageId, lease.messageDate, lease.command, lease.leaseId];
}

export async function acceptGeneralTelegramCommand(db: D1Database, pin: GeneralTelegramPin, request: Request): Promise<number> {
  const decoded = await readTelegramUpdate(request, pin.webhookSecret);
  if (decoded.status !== 200) return decoded.status;
  const event = readPrivateTelegramCommand(decoded.update, pin.botUsername);
  if (!event || event.actorId === pin.botId || event.remainder.trim() !== ""
    || (event.name !== "help" && event.name !== "list")) return 204;
  const accepted = await db.prepare(`INSERT INTO telegram_general_replies
    (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command)
    SELECT policy.bot_id,policy.generation,actor.actor_id,actor.revision,?,?,?,?
    FROM ${ACTORS}
    WHERE ${POLICY} AND policy.active=1 AND actor.actor_id=? AND ${LATEST_ACTOR}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${TTL}) AND ?<=unixepoch()+60
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies AS queued
        WHERE queued.bot_id=actor.bot_id AND queued.generation=actor.generation
          AND queued.actor_id=actor.actor_id AND queued.actor_revision=actor.revision
          AND queued.state IN ('pending','leased','sending') AND queued.received_at+${TTL}>unixepoch()
        LIMIT 1 OFFSET 3)
    ON CONFLICT (bot_id,update_id) DO NOTHING RETURNING receipt_id`)
    .bind(decoded.updateId, event.messageId, event.messageDate, event.name, ...policyBindings(pin),
      event.actorId, event.messageDate, event.messageDate).first();
  return accepted ? 200 : 204;
}

export async function claimGeneralTelegramReply(db: D1Database, pin: GeneralTelegramPin): Promise<Lease | null> {
  return db.prepare(`UPDATE telegram_general_replies SET state='leased',lease_id=?,lease_until=unixepoch()+${LEASE_SECONDS}
    WHERE receipt_id=(SELECT receipt.receipt_id FROM telegram_general_replies AS receipt
      WHERE receipt.bot_id=? AND receipt.generation=? AND ${CURRENT}
        AND (receipt.state='pending' OR (receipt.state='leased' AND receipt.lease_until<=unixepoch()))
        AND NOT EXISTS (SELECT 1 FROM telegram_general_replies AS earlier
          WHERE earlier.bot_id=receipt.bot_id AND earlier.actor_id=receipt.actor_id AND earlier.receipt_id<receipt.receipt_id
            AND earlier.state IN ('pending','leased','sending')
            AND ((earlier.state='sending' AND earlier.lease_until>unixepoch()) OR (
              earlier.state IN ('pending','leased') AND earlier.generation=receipt.generation
              AND earlier.actor_revision=receipt.actor_revision AND earlier.received_at+${TTL}>unixepoch())))
      ORDER BY receipt.receipt_id LIMIT 1)
    RETURNING receipt_id AS id,actor_id AS actorId,actor_revision AS actorRevision,message_id AS messageId,
      message_date AS messageDate,command,lease_id AS leaseId`)
    .bind(crypto.randomUUID(), pin.botId, pin.generation, ...policyBindings(pin)).first<Lease>();
}

export async function beginGeneralTelegramReply(db: D1Database, pin: GeneralTelegramPin, lease: Lease): Promise<boolean> {
  const row = await db.prepare(`UPDATE telegram_general_replies AS receipt
    SET state='sending',lease_until=unixepoch()+${LEASE_SECONDS}
    WHERE state='leased' AND lease_until>unixepoch() AND ${EXACT_LEASE} AND ${CURRENT} RETURNING receipt_id`)
    .bind(...leaseBindings(pin, lease), ...policyBindings(pin)).first();
  return row !== null;
}

export async function drainGeneralTelegramReply(db: D1Database, pin: GeneralTelegramPin): Promise<boolean> {
  const lease = await claimGeneralTelegramReply(db, pin);
  if (!lease) return false;
  const text = lease.command === "list"
    ? (await renderTelegramView(db, lease.actorId, { kind: "list", afterId: null, afterEpoch: null })).text
    : "可用命令\n/help 帮助\n/list 查看你的订阅";
  if (!await beginGeneralTelegramReply(db, pin, lease)) return false;
  const outcome = await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text);
  const state = outcome.kind === "retry" ? "failed" : outcome.kind;
  await db.prepare(`UPDATE telegram_general_replies SET state=?,lease_id=NULL,lease_until=NULL
    WHERE state='sending' AND ${EXACT_LEASE}`).bind(state, ...leaseBindings(pin, lease)).run();
  return true;
}

export async function recoverGeneralTelegramReplies(db: D1Database, pin: GeneralTelegramPin): Promise<void> {
  await db.prepare(`UPDATE telegram_general_replies
    SET state=CASE WHEN state='sending' THEN 'uncertain' ELSE 'discarded' END,lease_id=NULL,lease_until=NULL
    WHERE receipt_id IN (SELECT receipt.receipt_id FROM telegram_general_replies AS receipt
      WHERE receipt.bot_id=? AND ((receipt.state='sending' AND receipt.lease_until<=unixepoch())
        OR (receipt.state IN ('pending','leased') AND NOT (${CURRENT})))
      ORDER BY receipt.receipt_id LIMIT 16)
    AND EXISTS (SELECT 1 FROM telegram_general_policy AS policy WHERE ${POLICY})`)
    .bind(pin.botId, ...policyBindings(pin), ...policyBindings(pin)).run();
  for (let i = 0; i < 4 && await drainGeneralTelegramReply(db, pin); i++) {
    // Bound scheduled work while allowing the next pending receipt to advance.
  }
}

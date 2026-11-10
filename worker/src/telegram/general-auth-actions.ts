import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK,
  GENERAL_POLICY_ACTORS_SQL, GENERAL_POLICY_PIN_SQL, GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL,
  generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { readPrivateTelegramCommand } from "./protocol.ts";

export const GENERAL_AUTH_ACTION_MARKER = "general-auth-action:v1";
export const GENERAL_AUTH_ACTION_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-auth-actions:v1 */ 1
  FROM subs_bot_schema_migrations WHERE position=50 AND name='0050_telegram_general_auth_actions.sql'
    AND sha256='369be22ccf8c0a30dfb7823e8ac2c402c65e2c404d655af360d7e88806aa0fe0' AND mode='applied')`;
const GENERAL_AUTH_NON_REHEARSAL = `EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=49
  AND name='0049_telegram_general_read_lane.sql'
  AND sha256='5b1220f36273d74fb14f333066ae70f26022c5abf8a60f2d236c6a23e3bcce88' AND mode='applied')
  AND NOT EXISTS (SELECT 1 FROM telegram_general_read_lane WHERE bot_id=policy.bot_id)`;
const REGRANT_HOLD_SECONDS = 60;
const ACTOR_ID = /^[1-9][0-9]{0,15}$/u;

export function readGeneralAuthAction(pin: GeneralTelegramPin, update: Record<string, unknown>, updateId: number) {
  if (!pin.privateAuthorization || !pin.privateManagement || !pin.sharedOutbox || pin.rehearsal) return null;
  const command = readPrivateTelegramCommand(update, pin.botUsername);
  if (!command || command.name !== "auth" || command.actorId === pin.botId) return null;
  const match = /^\s+(add|remove|del|rm)\s+([1-9][0-9]{0,15})\s*$/iu.exec(command.remainder);
  if (!match || Number(match[2]) >= 2 ** 52) return null;
  const targetId = match[2];
  const action = match[1].toLowerCase() === "add" ? "auth-add" as const : "auth-remove" as const;
  return { updateId, actorId: command.actorId, messageId: command.messageId, messageDate: command.messageDate, targetId, action };
}

type Action = NonNullable<ReturnType<typeof readGeneralAuthAction>>;

export async function acceptGeneralAuthAction(db: D1Database, pin: GeneralTelegramPin, action: Action): Promise<number> {
  if (!pin.privateAuthorization || !pin.privateManagement || !pin.sharedOutbox || pin.rehearsal) return 204;
  const nonce = crypto.randomUUID();
  const key = [pin.botId, action.updateId, nonce] as const;
  const grant = action.action === "auth-add";
  const desired = grant ? "member" : "denied";
  const incoming = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
  const authority = `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND ${GENERAL_AUTH_ACTION_SCHEMA}
      AND ${GENERAL_AUTH_NON_REHEARSAL} AND ${GENERAL_NO_LEGACY_WORK} AND policy.active=1
      AND actor.actor_id=? AND actor.role='admin' AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)`;
  const bindings = [...generalPolicyBindings(pin), action.actorId, action.messageDate, action.messageDate, action.updateId];
  const steps = [
    db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,actor.actor_id,'private',?,?,?,? ${authority} AND ${GENERAL_ACTOR_QUEUE_CAPACITY}
      ON CONFLICT(bot_id,update_id) DO NOTHING`)
      .bind(action.updateId, action.messageId, action.messageDate, action.action, nonce, ...bindings),
    prepareGeneralReceiptAuthority(db, pin, key),
    db.prepare(`WITH candidate AS MATERIALIZED (
        SELECT incoming.receipt_id,incoming.bot_id,incoming.message_date,incoming.update_id,recorded.generation
        FROM telegram_inbox AS incoming JOIN telegram_general_receipt AS recorded USING(receipt_id)
        WHERE ${incoming} AND recorded.actor_role='admin'
      ), target AS MATERIALIZED (
        SELECT actor.* FROM candidate JOIN telegram_general_actors AS actor USING(bot_id,generation)
        WHERE actor.actor_id=? ORDER BY actor.revision DESC LIMIT 1
      ), decision AS MATERIALIZED (
        SELECT candidate.*,target.revision,CASE
          WHEN target.role NOT IN ('member','denied') OR NOT EXISTS (
            SELECT 1 FROM telegram_general_actors AS enrolled WHERE enrolled.bot_id=target.bot_id
              AND enrolled.generation=target.generation AND enrolled.actor_id=target.actor_id
              AND enrolled.revision=1 AND enrolled.role IN ('member','denied'))
            OR (target.revision>1 AND NOT EXISTS (SELECT 1 FROM telegram_general_auth_actions AS prior
              WHERE prior.bot_id=target.bot_id AND prior.generation=target.generation AND prior.target_id=target.actor_id
                AND prior.revision=target.revision)) THEN 'unavailable'
          WHEN EXISTS (SELECT 1 FROM telegram_general_auth_actions AS prior
            WHERE prior.bot_id=candidate.bot_id AND prior.generation=candidate.generation AND prior.target_id=target.actor_id
              AND prior.revision IS NOT NULL AND (prior.message_date,prior.update_id)>(candidate.message_date,candidate.update_id))
            THEN 'stale'
          WHEN target.role=? THEN 'unchanged'
          WHEN target.revision<9007199254740991 THEN 'changed'
          ELSE 'unavailable' END AS result FROM candidate LEFT JOIN target ON 1
      ) INSERT INTO telegram_general_auth_actions
        (receipt_id,bot_id,generation,target_id,message_date,update_id,result,revision)
      SELECT receipt_id,bot_id,generation,CASE WHEN result='unavailable' THEN '' ELSE ? END,message_date,update_id,result,
        CASE result WHEN 'changed' THEN revision+1 WHEN 'unchanged' THEN revision END FROM decision`)
      .bind(...key, action.targetId, desired, action.targetId),
    db.prepare(`INSERT INTO telegram_general_actors (bot_id,generation,actor_id,revision,effective_at,role)
      SELECT auth.bot_id,auth.generation,auth.target_id,auth.revision,MAX(target.effective_at,unixepoch()+?),?
      FROM telegram_inbox AS incoming JOIN telegram_general_auth_actions AS auth USING(receipt_id)
      JOIN telegram_general_actors AS target ON target.bot_id=auth.bot_id AND target.generation=auth.generation
        AND target.actor_id=auth.target_id AND target.revision=auth.revision-1
      WHERE ${incoming} AND auth.result='changed'`)
      .bind(grant ? REGRANT_HOLD_SECONDS : 0, desired, ...key),
    db.prepare(`INSERT INTO telegram_outbox (receipt_id) SELECT incoming.receipt_id
      FROM telegram_inbox AS incoming WHERE ${incoming}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_general_auth_actions AS auth JOIN telegram_outbox USING(receipt_id)
        WHERE auth.receipt_id=incoming.receipt_id AND (auth.result<>'changed' OR EXISTS (
          SELECT 1 FROM telegram_general_actors AS actor WHERE actor.bot_id=auth.bot_id AND actor.generation=auth.generation
            AND actor.actor_id=auth.target_id AND actor.revision=auth.revision AND actor.role=?))
      ) THEN incoming.command END WHERE ${incoming} RETURNING receipt_id`)
      .bind(GENERAL_AUTH_ACTION_MARKER, desired, ...key),
    // Telegram may retry a fresh authorized action that the bounded queue could not admit.
    db.prepare(`SELECT 1 ${authority}
      AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)`)
      .bind(...bindings, action.updateId),
  ];
  const results = await db.batch(steps);
  const receipt = results.at(-2)?.results.length;
  const retry = results.at(-1)?.results.length;
  if (results.length !== steps.length || !results.every(({ success }) => success) || receipt === undefined || retry === undefined
    || receipt + retry > 1) {
    throw new Error("General Telegram authorization receipt could not be confirmed.");
  }
  return receipt === 1 ? 200 : retry === 1 ? 503 : 204;
}

export interface GeneralAuthActionReply {
  result: string;
  targetId: string;
  current: number;
}

export function prepareGeneralAuthActionReply(db: D1Database, lease: {
  receiptId: number; leaseId: string; attempts: number; command: string;
}): D1PreparedStatement {
  const desired = lease.command === "auth-add" ? "member" : "denied";
  return db.prepare(`SELECT auth.result,auth.target_id AS targetId,EXISTS (
      SELECT 1 FROM telegram_general_actors AS actor WHERE actor.bot_id=auth.bot_id AND actor.generation=auth.generation
        AND actor.actor_id=auth.target_id AND actor.role=? AND actor.revision=auth.revision
        AND actor.revision=(SELECT MAX(latest.revision) FROM telegram_general_actors AS latest
          WHERE latest.bot_id=auth.bot_id AND latest.generation=auth.generation AND latest.actor_id=auth.target_id)
    ) AS current FROM telegram_general_auth_actions AS auth JOIN telegram_outbox USING(receipt_id)
    WHERE receipt_id=? AND state='sending' AND lease_id=? AND attempts=?
      AND NOT EXISTS (SELECT 1 FROM telegram_general_read_lane WHERE bot_id=auth.bot_id)`)
    .bind(desired, lease.receiptId, lease.leaseId, lease.attempts);
}

export function renderGeneralAuthActionReply(reply: GeneralAuthActionReply, command: string): string | null {
  if (reply.result === "unavailable") return "只能管理已登记的普通用户。";
  if (reply.result === "stale" || ((reply.result === "changed" || reply.result === "unchanged") && reply.current === 0)) {
    return "这次授权操作已被较新的状态取代。";
  }
  if ((reply.result !== "changed" && reply.result !== "unchanged") || reply.current !== 1
    || !ACTOR_ID.test(reply.targetId) || Number(reply.targetId) >= 2 ** 52) return null;
  return command === "auth-add" ? `用户 ${reply.targetId}：已授权。` : `用户 ${reply.targetId}：已撤权。`;
}

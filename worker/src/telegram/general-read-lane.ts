import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import type { TelegramPolicy } from "./protocol.ts";

const TABLE = "telegram_general_read_lane";
const MIGRATION = "0049_telegram_general_read_lane.sql";
const SHA256 = "5b1220f36273d74fb14f333066ae70f26022c5abf8a60f2d236c6a23e3bcce88";
const error = "The Telegram read rehearsal lane could not be confirmed.";

export type GeneralReadLaneScope = { adminId: string; memberId: string };
export type GeneralReadLane = { epoch: number | null; mode: "isolated" | "closed" | "general"; pin: GeneralTelegramPin | null };
type LaneRow = { epoch: number; mode: GeneralReadLane["mode"]; generation: number | null;
  cutoverAt: number | null; releaseRevision: string | null; activationSha256: string | null; active: number | null };

export async function readGeneralReadLane(
  db: D1Database, policy: TelegramPolicy, revision: unknown,
): Promise<GeneralReadLane | null> {
  const schema = await db.prepare(`SELECT name,type,CASE WHEN name='telegram_general_read_lane'
      AND length(CAST(sql AS BLOB))<=1024 THEN sql END AS definition
    FROM sqlite_schema WHERE name IN ('telegram_general_read_lane','subs_bot_schema_migrations')`)
    .all<{ name: string; type: string; definition: string | null }>();
  if (!schema.success || schema.results.some(({ type }) => type !== "table")) throw new Error(error);
  const names = new Set(schema.results.map(({ name }) => name));
  const ledger = names.has("subs_bot_schema_migrations") ? await db.prepare(`SELECT name,sha256,mode
    FROM subs_bot_schema_migrations WHERE position=49 OR name=?`).bind(MIGRATION).all<{ name: string; sha256: string; mode: string }>()
    : null;
  if (ledger && (!ledger.success || ledger.results.length > 1)) throw new Error(error);
  const record = ledger?.results[0];
  if (!names.has(TABLE)) {
    if (record) throw new Error(error);
    return null;
  }
  const definition = schema.results.find(({ name }) => name === TABLE)?.definition;
  if (!definition) throw new Error(error);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(definition + ";\n"));
  if (Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("") !== SHA256) {
    throw new Error(error);
  }
  if (!record) {
    // A complete empty table can be present before the ledger is sealed. It cannot open the lane.
    if (await db.prepare(`SELECT 1 FROM ${TABLE} LIMIT 1`).first()) throw new Error(error);
    return { epoch: null, mode: "isolated", pin: null };
  }
  if (record.name !== MIGRATION || record.sha256 !== SHA256 || record.mode !== "applied") throw new Error(error);
  const row = await db.prepare(`SELECT /* subs-bot:telegram-general-read-lane:v1 */ lane.epoch,lane.mode,lane.generation,
      policy.cutover_at AS cutoverAt,policy.release_revision AS releaseRevision,
      policy.activation_sha256 AS activationSha256,policy.active
    FROM ${TABLE} AS lane LEFT JOIN telegram_general_policy AS policy
      ON policy.bot_id=lane.bot_id AND policy.generation=lane.generation
    WHERE lane.bot_id=?`).bind(policy.botId).first<LaneRow>();
  if (!row) return { epoch: null, mode: "isolated", pin: null };
  if ((row.mode !== "isolated" && row.mode !== "closed" && row.mode !== "general")
    || !Number.isSafeInteger(row.epoch) || row.epoch < 1) throw new Error(error);
  if (row.generation === null) {
    if (row.mode === "general") throw new Error(error);
    return { epoch: row.epoch, mode: row.mode, pin: null };
  }
  const { generation, cutoverAt, releaseRevision, activationSha256 } = row;
  if (row.mode === "isolated" || row.active !== 1 || !Number.isSafeInteger(generation) || generation < 1
    || cutoverAt === null || !Number.isSafeInteger(cutoverAt) || cutoverAt < 1 || releaseRevision === null
    || !/^[0-9a-f]{40}$/u.test(releaseRevision) || releaseRevision !== revision
    || activationSha256 === null || !/^[0-9a-f]{64}$/u.test(activationSha256)) throw new Error(error);
  const { botId, botUsername, webhookSecret, botToken, adminId, memberId } = policy;
  return { epoch: row.epoch, mode: row.mode, pin: { botId, botUsername, webhookSecret, botToken, generation,
    cutoverAt, releaseRevision, activationSha256, sharedOutbox: true, privateManagement: false, privateFormats: false,
    privateTemp: false, privateDocument: false, privateProvider: false, privateClaims: false, privateShareCreation: false,
    privateAggregate: false,
    rehearsal: { adminId, memberId } } };
}

export function assertGeneralReadLane(
  db: D1Database, botId: string, mode: "isolated" | "general", epoch: number | null,
): D1PreparedStatement {
  const check = epoch === null ? `NOT EXISTS (SELECT 1 FROM ${TABLE} WHERE bot_id=?)`
    : `EXISTS (SELECT 1 FROM ${TABLE} WHERE bot_id=? AND mode='${mode}' AND epoch=?)`;
  // The assertion and all receipt writes must run in the same D1 batch.
  return db.prepare(`SELECT CASE WHEN ${check} THEN 1
    ELSE json_extract('telegram read lane changed', '$') END`).bind(...(epoch === null ? [botId] : [botId, epoch]));
}

export const GENERAL_READ_LANE_ROLE = `EXISTS (SELECT 1 FROM ${TABLE} AS lane
  WHERE lane.bot_id=policy.bot_id AND lane.generation=policy.generation AND lane.mode IN ('closed','general') AND
    ((actor.actor_id=? AND actor.role='admin') OR (actor.actor_id=? AND actor.role='member' AND CASE WHEN lane.member_date IS NULL THEN
      NOT EXISTS (SELECT 1 FROM telegram_auth AS live WHERE live.bot_id=lane.bot_id AND live.user_id=actor.actor_id)
    ELSE EXISTS (SELECT 1 FROM telegram_auth AS live WHERE live.bot_id=lane.bot_id AND live.user_id=actor.actor_id
      AND live.allowed=1 AND live.message_date=lane.member_date AND live.message_id=lane.member_message) END)))`;

export function generalReadLaneRoleBindings(pin: GeneralTelegramPin): readonly string[] {
  return pin.rehearsal ? [pin.rehearsal.adminId, pin.rehearsal.memberId] : [];
}

import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { readGeneralReadLane } from "./general-read-lane.ts";
import type { TelegramPolicy } from "./protocol.ts";

const TABLE = "telegram_general_isolation_window";
export const GENERAL_WINDOW_MIGRATION = "0052_telegram_general_isolation_window.sql";
export const GENERAL_WINDOW_SHA256 = "2f31fc9792828fb115f58be7840304ce561c6def36ba92180262ea012b6c2bd7";
const ERROR = "The isolated general Telegram window could not be confirmed.";
export type GeneralIsolationWindow = { ready: boolean; epoch: number | null; mode: "isolated" | "closed" | "general";
  pin: GeneralTelegramPin | null };

/** A profile is a separate persisted contract. A read-only lane never implies full capability. */
export async function readGeneralIsolationWindow(
  db: D1Database, policy: TelegramPolicy, revision: unknown, options: { groupCards?: boolean; subscriptionShorts?: boolean } = {},
): Promise<GeneralIsolationWindow> {
  const definition = await db.prepare(`SELECT type,sql FROM sqlite_schema WHERE name=?`)
    .bind(TABLE).first<{ type: string; sql: string | null }>();
  if (definition === null) {
    const ledger = await db.prepare("SELECT type FROM sqlite_schema WHERE name='subs_bot_schema_migrations'")
      .first<{ type: string }>();
    if (ledger && ledger.type !== "table") throw new Error(ERROR);
    if (ledger && await db.prepare("SELECT 1 FROM subs_bot_schema_migrations WHERE position=52 OR name=?")
      .bind(GENERAL_WINDOW_MIGRATION).first()) throw new Error(ERROR);
    return { ready: false, epoch: null, mode: "isolated", pin: null };
  }
  if (definition.type !== "table") throw new Error(ERROR);
  const schema = definition.sql;
  if (typeof schema !== "string" || schema.length > 2048) throw new Error(ERROR);
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(schema + ";\n"));
  if (Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("") !== GENERAL_WINDOW_SHA256) throw new Error(ERROR);
  const hasLedger = await db.prepare("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='subs_bot_schema_migrations'").first();
  if (!hasLedger) {
    if (await db.prepare(`SELECT 1 FROM ${TABLE} LIMIT 1`).first()) throw new Error(ERROR);
    return { ready: false, epoch: null, mode: "isolated", pin: null };
  }
  const ledger = await db.prepare(`SELECT position,name,sha256,mode FROM subs_bot_schema_migrations
    WHERE position=52 OR name=?`).bind(GENERAL_WINDOW_MIGRATION).all<{
      position: number; name: string; sha256: string; mode: string;
    }>();
  if (ledger.success && ledger.results.length === 0) {
    if (await db.prepare(`SELECT 1 FROM ${TABLE} LIMIT 1`).first()) throw new Error(ERROR);
    return { ready: false, epoch: null, mode: "isolated", pin: null };
  }
  if (!ledger.success || ledger.results.length !== 1 || ledger.results[0]?.position !== 52
    || ledger.results[0]?.name !== GENERAL_WINDOW_MIGRATION || ledger.results[0]?.sha256 !== GENERAL_WINDOW_SHA256
    || ledger.results[0]?.mode !== "applied") throw new Error(ERROR);
  const row = await db.prepare(`SELECT /* subs-bot:telegram-general-isolation-window:full-v1 */ * FROM ${TABLE} WHERE bot_id=?`)
    .bind(policy.botId).first<{ profile: string; release_revision: string; active_sha256: string;
      admin_id: string; member_id: string; group_id: string; generation: number | null; opened_epoch: number | null }>();
  if (!row) {
    const lane = await readGeneralReadLane(db, policy, revision);
    return { ready: true, epoch: lane?.epoch ?? null, mode: "isolated", pin: null };
  }
  if (row.profile !== "full-v1" || row.release_revision !== revision || row.admin_id !== policy.adminId
    || row.member_id !== policy.memberId || row.group_id !== policy.groupId || !/^[0-9a-f]{64}$/u.test(row.active_sha256)) throw new Error(ERROR);
  const lane = await readGeneralReadLane(db, policy, revision);
  if (!lane || lane.epoch === null || lane.mode === "isolated") throw new Error(ERROR);
  if (row.generation === null) {
    if (row.opened_epoch !== null || lane.mode !== "closed" || lane.pin !== null) throw new Error(ERROR);
    return { ready: true, epoch: lane.epoch, mode: "closed", pin: null };
  }
  if (!lane.pin || lane.pin.generation !== row.generation || !Number.isSafeInteger(row.opened_epoch)
    || row.opened_epoch === null || row.opened_epoch > lane.epoch) throw new Error(ERROR);
  const scope = await db.prepare(`SELECT
    (SELECT count(*) FROM telegram_general_actors WHERE bot_id=? AND generation=?
      AND actor_id NOT IN (?,?)) AS foreignActors,
    (SELECT count(*) FROM telegram_general_groups WHERE bot_id=? AND generation=?) AS groups,
    EXISTS(SELECT 1 FROM telegram_general_groups WHERE bot_id=? AND generation=? AND chat_id=? AND chat_type='group') AS fixedGroup`)
    .bind(policy.botId, row.generation, policy.adminId, policy.memberId, policy.botId, row.generation,
      policy.botId, row.generation, policy.groupId).first<{ foreignActors: number; groups: number; fixedGroup: number }>();
  if (!scope || scope.foreignActors !== 0 || scope.groups !== 1 || scope.fixedGroup !== 1) throw new Error(ERROR);
  const { rehearsal: _readOnly, ...pin } = lane.pin;
  return { ready: true, epoch: lane.epoch, mode: lane.mode, pin: { ...pin,
    privateManagement: true, privateFormats: true, privateTemp: true, privateDocument: true, privateProvider: true,
    privateClaims: true, privateShareCreation: true, privateAggregate: true, privateSelected: true, privateShort: true,
    privateAuthorization: true, privateInline: true, providerBatch: true,
    isolationWindow: { profile: "full-v1", adminId: policy.adminId, memberId: policy.memberId },
    subscriptionShorts: options.subscriptionShorts ? "issue" : "drain",
    ...(options.groupCards ? { groupShare: { chatId: policy.groupId, chatType: "group" as const } } : {}),
  } };
}

/** Every webhook D1 operation is fenced in the same batch as its actual query or mutation.
 * This covers commands, documents, callbacks and inline queries, including an invocation
 * that was already running when the protected control workflow closed the window.
 * Cron intentionally uses the original binding so accepted work can finish while closed.
 */
export function fenceTelegramWebhookDatabase(
  db: D1Database, botId: string, window: GeneralIsolationWindow,
): D1Database {
  if (!window.ready) return db;
  const originals = new WeakMap<object, D1PreparedStatement>();
  const guard = () => window.mode === "isolated"
    ? db.prepare(`SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM ${TABLE} WHERE bot_id=?)
        AND ${window.epoch === null ? "NOT EXISTS(SELECT 1 FROM telegram_general_read_lane WHERE bot_id=?)"
          : "EXISTS(SELECT 1 FROM telegram_general_read_lane WHERE bot_id=? AND epoch=?)"}
        THEN 1 ELSE json_extract('Telegram admission changed','$') END`)
      .bind(botId, botId, ...(window.epoch === null ? [] : [window.epoch]))
    : db.prepare(`SELECT CASE WHEN EXISTS(SELECT 1 FROM ${TABLE} AS profile
        JOIN telegram_general_read_lane AS lane USING(bot_id) WHERE profile.bot_id=? AND profile.profile='full-v1'
          AND lane.mode='general' AND lane.epoch=? AND profile.generation=lane.generation
          AND NOT EXISTS(SELECT 1 FROM telegram_general_actors AS actor WHERE actor.bot_id=profile.bot_id
            AND actor.generation=profile.generation AND actor.actor_id NOT IN(profile.admin_id,profile.member_id))
          AND (SELECT count(*) FROM telegram_general_groups WHERE bot_id=profile.bot_id AND generation=profile.generation)=1
          AND EXISTS(SELECT 1 FROM telegram_general_groups WHERE bot_id=profile.bot_id AND generation=profile.generation
            AND chat_id=profile.group_id AND chat_type='group'))
        THEN 1 ELSE json_extract('Telegram admission changed','$') END`).bind(botId, window.epoch);
  const execute = async <T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> => {
    const result = await db.batch<T>([guard(), ...statements]);
    if (result.length !== statements.length + 1 || result.some(({ success }) => !success)) throw new Error(ERROR);
    return result.slice(1);
  };
  const wrap = (statement: D1PreparedStatement): D1PreparedStatement => {
    const wrapped = {
      bind: (...values: unknown[]) => wrap(statement.bind(...values)),
      all: async <T>() => (await execute<T>([statement]))[0],
      run: async <T>() => (await execute<T>([statement]))[0],
      first: async <T>(column?: string): Promise<T | null> => {
        const row = (await execute<Record<string, unknown>>([statement]))[0]?.results[0];
        return (row ? column === undefined ? row : row[column] : null) as T | null;
      },
      raw: () => { throw new Error(ERROR); },
    } as D1PreparedStatement;
    originals.set(wrapped, statement);
    return wrapped;
  };
  return {
    prepare: (sql: string) => wrap(db.prepare(sql)),
    batch: <T>(statements: D1PreparedStatement[]) => execute<T>(statements.map((statement) => {
      const original = originals.get(statement);
      if (!original) throw new Error(ERROR);
      return original;
    })),
    exec: () => { throw new Error(ERROR); },
    dump: () => { throw new Error(ERROR); },
    withSession: () => { throw new Error(ERROR); },
  } as D1Database;
}

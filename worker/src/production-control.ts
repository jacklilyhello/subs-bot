import type { GeneralTelegramPin } from "./telegram/general-auth-runtime.ts";

export const PRODUCTION_CONTROL_MIGRATION = "0055_production_control.sql";
export const PRODUCTION_CONTROL_SHA256 = "e353b427b1a2bb2f0d092959f322525523301f3a68a26ca2da714a1e07e76c55";
const ERROR = "The production runtime identity could not be confirmed.";
const TABLE = "subs_bot_production_control";
const INVOCATIONS = "subs_bot_production_invocations";
export const PRODUCTION_INVOCATION_SECONDS = 960;
export type ProductionControl = {
  targetSha256: string; botId: string; releaseRevision: string; generation: number; epoch: number;
  admission: "closed" | "open"; workers: "run" | "frozen";
};
export type ProductionInvocation = { id: string; control: ProductionControl; kind: "webhook" | "scheduled" };

const SCHEMA = `EXISTS(SELECT /* subs-bot:production-control:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=55 AND name='${PRODUCTION_CONTROL_MIGRATION}' AND sha256='${PRODUCTION_CONTROL_SHA256}' AND mode='applied')`;

/** Configuration names an immutable target; a deployment revision is independently pinned. */
export async function readProductionControl(
  db: D1Database, targetSha256: unknown, pin: GeneralTelegramPin,
): Promise<ProductionControl> {
  if (typeof targetSha256 !== "string" || !/^[0-9a-f]{64}$/u.test(targetSha256)) throw new Error(ERROR);
  const rows = await db.prepare(`SELECT target_sha256 AS targetSha256,bot_id AS botId,
      release_revision AS releaseRevision,generation,epoch,admission,workers
    FROM ${TABLE} WHERE singleton=1 AND ${SCHEMA}`).all<ProductionControl>();
  const row = rows.results?.[0];
  if (!rows.success || rows.results.length !== 1 || !row || row.targetSha256 !== targetSha256
    || row.botId !== pin.botId || row.releaseRevision !== pin.releaseRevision || row.generation !== pin.generation
    || !Number.isSafeInteger(row.epoch) || row.epoch < 1
    || (row.admission !== "closed" && row.admission !== "open") || (row.workers !== "run" && row.workers !== "frozen")
    || (row.admission === "open" && row.workers !== "run")) throw new Error(ERROR);
  return row;
}

function identitySql(control: ProductionControl, kind: ProductionInvocation["kind"]) {
  return `EXISTS(SELECT 1 FROM ${TABLE} WHERE singleton=1 AND target_sha256=? AND bot_id=?
    AND release_revision=? AND generation=? ${kind === "webhook" ? "AND epoch=?" : ""} AND workers='run'
    ${kind === "webhook" ? "AND admission='open'" : ""} AND ${SCHEMA})`;
}

function identityBindings(control: ProductionControl, kind: ProductionInvocation["kind"]) {
  return [control.targetSha256, control.botId, control.releaseRevision, control.generation,
    ...(kind === "webhook" ? [control.epoch] : [])];
}

function assertion(db: D1Database, control: ProductionControl, kind: ProductionInvocation["kind"], invocationId?: string) {
  const invocation = invocationId === undefined ? "" : ` AND EXISTS(SELECT 1 FROM ${INVOCATIONS}
    WHERE invocation_id=? AND target_sha256=? AND bot_id=? AND epoch=? AND state='running' AND lease_until>unixepoch())`;
  return db.prepare(`SELECT CASE WHEN ${identitySql(control, kind)}${invocation}
    THEN 1 ELSE json_extract('Production runtime changed','$') END`)
    .bind(...identityBindings(control, kind), ...(invocationId === undefined ? [] : [
      invocationId, control.targetSha256, control.botId, control.epoch,
    ]));
}

/** Atomic admission makes a close observable even to an invocation that already started. */
export async function beginProductionInvocation(
  db: D1Database, control: ProductionControl, kind: ProductionInvocation["kind"],
): Promise<ProductionInvocation> {
  const id = crypto.randomUUID().replaceAll("-", "");
  const results = await db.batch([
    assertion(db, control, kind),
    db.prepare(`INSERT INTO ${INVOCATIONS}
      (invocation_id,target_sha256,bot_id,epoch,kind,lease_until,state) VALUES(?,?,?,?,?,unixepoch()+?,'running')`)
      .bind(id, control.targetSha256, control.botId, control.epoch, kind, PRODUCTION_INVOCATION_SECONDS),
  ]);
  if (results.length !== 2 || results.some(({ success }) => !success)) throw new Error(ERROR);
  return { id, control, kind };
}

/** Completion is recorded only after the handler and every registered background task ended.
 * An interrupted runtime leaves a running/expired lease. It is never silently discarded.
 */
export async function finishProductionInvocation(
  db: D1Database, invocation: ProductionInvocation, complete: boolean,
): Promise<void> {
  const { id, control } = invocation;
  const result = await db.prepare(`UPDATE ${INVOCATIONS}
    SET state=CASE WHEN ?=1 AND lease_until>unixepoch() THEN 'finished' ELSE 'uncertain' END,finished_at=unixepoch()
    WHERE invocation_id=? AND target_sha256=? AND bot_id=? AND epoch=? AND state='running'`)
    .bind(complete ? 1 : 0, id, control.targetSha256, control.botId, control.epoch).run();
  if (!result.success || result.meta.changes !== 1) throw new Error(ERROR);
}

/** All business statements share a transaction with the current runtime/lease assertion.
 * Raw SQL and unguarded D1 sessions cannot escape this adapter. R2 and external I/O are
 * covered by the invocation lifetime: freeze must require no unfinished invocation.
 */
export function fenceProductionDatabase(db: D1Database, invocation: ProductionInvocation): D1Database {
  const originals = new WeakMap<object, D1PreparedStatement>();
  const execute = async <T>(statements: D1PreparedStatement[]): Promise<D1Result<T>[]> => {
    const results = await db.batch<T>([assertion(db, invocation.control, invocation.kind, invocation.id), ...statements]);
    if (results.length !== statements.length + 1 || results.some(({ success }) => !success)) throw new Error(ERROR);
    return results.slice(1);
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

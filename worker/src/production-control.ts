import type { GeneralTelegramPin } from "./telegram/general-auth-runtime.ts";

export const PRODUCTION_CONTROL_MIGRATION = "0055_production_control.sql";
export const PRODUCTION_CONTROL_SHA256 = "4ac1fcc966f3567fa66bdd0e6a3e4e2f88d07c36ebb215753c393ae71cd4e2ee";
export const PRODUCTION_UPDATES_MIGRATION = "0056_production_update_dispositions.sql";
export const PRODUCTION_UPDATES_SHA256 = "5e45bf740c6f7748a6fa5439535bab77da565e1b6151b35d73bb646301eaa38c";
const ERROR = "The production runtime identity could not be confirmed.";
const TABLE = "subs_bot_production_control";
const INVOCATIONS = "subs_bot_production_invocations";
const UPDATES = "subs_bot_production_updates";
export const PRODUCTION_INVOCATION_SECONDS = 960;
export type ProductionControl = {
  targetSha256: string; botId: string; releaseRevision: string; generation: number; epoch: number;
  admission: "closed" | "open"; workers: "run" | "frozen";
};
export type ProductionInvocation = { id: string; control: ProductionControl; kind: "webhook" | "scheduled" };
export type ProductionUpdate = { targetSha256: string; payloadSha256: string; invocationId: string;
  state: "processing" | "retryable" | "completed" | "uncertain"; httpStatus: 200 | 204 | null };

const SCHEMA = `EXISTS(SELECT /* subs-bot:production-control:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=55 AND name='${PRODUCTION_CONTROL_MIGRATION}' AND sha256='${PRODUCTION_CONTROL_SHA256}' AND mode='applied')`;
const UPDATE_SCHEMA = `EXISTS(SELECT 1 FROM subs_bot_schema_migrations WHERE position=56
  AND name='${PRODUCTION_UPDATES_MIGRATION}' AND sha256='${PRODUCTION_UPDATES_SHA256}' AND mode='applied')`;

/** Reordered JSON object keys do not turn a Telegram retry into a different payload. */
export async function productionUpdateDigest(update: Record<string, unknown>): Promise<string> {
  const encoded = JSON.stringify(update, (_key, value: unknown) => value !== null && typeof value === "object" && !Array.isArray(value)
    ? Object.fromEntries(Object.entries(value).sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)) : value);
  const hashed = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(encoded));
  return Array.from(new Uint8Array(hashed), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function readProductionUpdate(
  db: D1Database, control: ProductionControl, updateId: number,
): Promise<ProductionUpdate | null> {
  if (!Number.isSafeInteger(updateId) || updateId < 1) throw new Error(ERROR);
  const rows = await db.prepare(`SELECT target_sha256 AS targetSha256,payload_sha256 AS payloadSha256,
      invocation_id AS invocationId,state,http_status AS httpStatus FROM ${UPDATES}
    WHERE bot_id=? AND update_id=? AND ${UPDATE_SCHEMA}`).bind(control.botId, updateId).all<ProductionUpdate>();
  if (!rows.success || rows.results.length > 1) throw new Error(ERROR);
  const row = rows.results[0];
  if (!row) {
    // A missing migration cannot be mistaken for a new, safe update.
    if (!await db.prepare(`SELECT 1 WHERE ${UPDATE_SCHEMA}`).first()) throw new Error(ERROR);
    return null;
  }
  if (row.targetSha256 !== control.targetSha256 || !/^[0-9a-f]{64}$/u.test(row.payloadSha256)
    || !/^[0-9a-f]{32}$/u.test(row.invocationId)
    || !["processing", "retryable", "completed", "uncertain"].includes(row.state)
    || (row.state === "completed" ? row.httpStatus !== 200 && row.httpStatus !== 204 : row.httpStatus !== null)) throw new Error(ERROR);
  return row;
}

/** Reserve before executing business code. A concurrent delivery never owns the same update. */
export async function reserveProductionUpdate(
  db: D1Database, invocation: ProductionInvocation, updateId: number, payloadSha256: string,
): Promise<boolean> {
  if (invocation.kind !== "webhook" || !Number.isSafeInteger(updateId) || updateId < 1
    || !/^[0-9a-f]{64}$/u.test(payloadSha256)) throw new Error(ERROR);
  const fenced = fenceProductionDatabase(db, invocation);
  const values = [invocation.control.botId, updateId, invocation.control.targetSha256, payloadSha256, invocation.id];
  const results = await fenced.batch([
    fenced.prepare(`SELECT CASE WHEN ${UPDATE_SCHEMA} THEN 1 ELSE json_extract('Production update schema changed','$') END`),
    fenced.prepare(`INSERT INTO ${UPDATES}(bot_id,update_id,target_sha256,payload_sha256,invocation_id,state)
      VALUES(?,?,?,?,?,'processing') ON CONFLICT(bot_id,update_id) DO NOTHING`).bind(...values),
    fenced.prepare(`UPDATE ${UPDATES} SET invocation_id=?,state='processing'
      WHERE bot_id=? AND update_id=? AND target_sha256=? AND payload_sha256=? AND state='retryable'`)
      .bind(invocation.id, ...values.slice(0, 4)),
    fenced.prepare(`SELECT invocation_id FROM ${UPDATES} WHERE bot_id=? AND update_id=? AND target_sha256=?
      AND payload_sha256=? AND state='processing'`).bind(...values.slice(0, 4)),
  ]);
  return (results[3]?.results[0] as { invocation_id?: string } | undefined)?.invocation_id === invocation.id;
}

/** Successful/ignored delivery is acknowledged only after its disposition is durable.
 * A 503 remains retryable at Telegram; no raw update payload or automatic replay is stored.
 */
export async function settleProductionUpdate(
  db: D1Database, invocation: ProductionInvocation, updateId: number, payloadSha256: string, status: number,
): Promise<void> {
  const fenced = fenceProductionDatabase(db, { ...invocation, kind: "scheduled" });
  const acknowledged = status === 200 || status === 204;
  const result = await fenced.prepare(`UPDATE ${UPDATES} SET state=?,http_status=?,completed_at=${acknowledged ? "unixepoch()" : "NULL"}
    WHERE bot_id=? AND update_id=? AND target_sha256=? AND payload_sha256=? AND invocation_id=? AND state='processing'`)
    .bind(acknowledged ? "completed" : "retryable", acknowledged ? status : null,
      invocation.control.botId, updateId, invocation.control.targetSha256, payloadSha256, invocation.id).run();
  if (!result.success || result.meta.changes !== 1) throw new Error(ERROR);
}

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

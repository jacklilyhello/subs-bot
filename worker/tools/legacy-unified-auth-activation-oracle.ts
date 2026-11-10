/** Hosted-only activation and rollback of the sealed synthetic V11 authorization. */

import { createHash } from "node:crypto";
import type { Miniflare } from "miniflare";
import { GENERAL_AUTH_LEGACY_ROLE } from "../src/telegram/general-auth-replay.ts";

export const GENERAL_RUNTIME_MIGRATION = {
  name: "0044_telegram_general_runtime.sql",
  sha256: "99ae19a1a0296bcf78598752c323571b3194c7b1e4bd1241c6f4960650fea75d",
};
const BOT = "74111";
const ADMIN = "74112";
const MEMBER = "74113";
const OUTSIDE = "74115";
const GROUP = -100100;
const GENERATION = 1;
const GENERAL_SECRET = "synthetic-v11-general-webhook-secret";
const BOT_TOKEN = `${BOT}:${"g".repeat(35)}`;
const BOT_USERNAME = "synthetic_unified_bot";
const DIGEST = /^[0-9a-f]{64}$/u;
const APPROVED = [[ADMIN, "admin"], [MEMBER, "member"]] as const;
const TABLES = [
  { name: "general_auth_installation", columns: [["bot_id", "TEXT"], ["source_sha256", "TEXT"],
    ["source_revision", "TEXT"], ["source_deployment_sha256", "TEXT"], ["inventory_manifest_sha256", "TEXT"],
    ["config_sha256", "TEXT"], ["target_sha256", "TEXT"], ["preview_manifest_sha256", "TEXT"],
    ["admin_mode", "TEXT"], ["unlisted_default", "TEXT"]], primary: ["bot_id"], count: 1 },
  { name: "general_auth_principals", columns: [["bot_id", "TEXT"], ["user_id", "TEXT"], ["is_admin", "INTEGER"],
    ["is_allowlisted", "INTEGER"], ["override_allowed", "INTEGER"], ["override_created_at", "INTEGER"],
    ["override_updated_at", "INTEGER"]], primary: ["bot_id", "user_id"], count: 3 },
  { name: "general_auth_groups", columns: [["bot_id", "TEXT"], ["chat_id", "TEXT"]],
    primary: ["bot_id", "chat_id"], count: 2 },
] as const;
const HELP = "可用命令\n/help 帮助\n/list 查看你的订阅";
const REPLIES = new Map<number, { actor: string; text: string }>([
  [801, { actor: ADMIN, text: "你的订阅\n1. alpha\n2. empty\n3. beta" }],
  [802, { actor: MEMBER, text: HELP }],
  [803, { actor: MEMBER, text: "你的订阅\n当前没有记录。" }],
]);

function requireAuth(condition: unknown): asserts condition {
  if (!condition) throw new Error("The synthetic general authorization activation could not be confirmed.");
}

function record(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

async function verifyDormantAuth(db: D1Database, manifest: Record<string, unknown>): Promise<void> {
  const authorization = manifest.generalAuthorization;
  const source = manifest.source;
  const summary = manifest.summary;
  requireAuth(record(authorization) && authorization.activationAllowed === false && record(authorization.tableSha256)
    && record(source) && source.legacyBotId === BOT && record(source.generalAuthorization)
    && source.generalAuthorization.sourceSha256 === source.sqliteSha256
    && record(summary) && record(summary.tableSha256) && record(summary.tableCounts));
  for (const { name, columns, primary, count } of TABLES) {
    const names = columns.map(([column]) => column);
    const rows = await db.prepare(`SELECT ${names.join(",")} FROM ${name} ORDER BY ${primary.join(",")} LIMIT ?`)
      .bind(count + 1).all<Record<string, unknown>>();
    requireAuth(rows.success && rows.results.length === count && summary.tableCounts[name] === count);
    const hash = createHash("sha256").update(JSON.stringify({ columns, primary }) + "\n");
    for (const row of rows.results) {
      requireAuth(row.bot_id === BOT);
      const cells = columns.map(([column, kind]) => {
        const value = row[column];
        if (value === null) return ["null"];
        if (kind === "TEXT") {
          requireAuth(typeof value === "string");
          return ["text", value];
        }
        requireAuth(typeof value === "number" && Number.isSafeInteger(value));
        return ["integer", String(value)];
      });
      hash.update(JSON.stringify(cells) + "\n");
    }
    const expected = authorization.tableSha256[name];
    requireAuth(typeof expected === "string" && DIGEST.test(expected) && summary.tableSha256[name] === expected
      && hash.digest("hex") === expected);
  }
  const roles = await db.prepare(`SELECT user_id AS actor,${GENERAL_AUTH_LEGACY_ROLE} AS role,is_admin,
      is_allowlisted,override_allowed FROM general_auth_principals AS principal
    WHERE bot_id=? ORDER BY user_id LIMIT 4`).bind(BOT).all();
  requireAuth(roles.success && roles.results.length === 3
    && roles.results[0].actor === ADMIN && roles.results[0].role === "admin"
    && roles.results[0].is_admin === 1 && roles.results[0].override_allowed === 0
    && roles.results[1].actor === MEMBER && roles.results[1].role === "member"
    && roles.results[1].is_allowlisted === 0 && roles.results[1].override_allowed === 1
    && roles.results[2].actor === OUTSIDE && roles.results[2].role === "member"
    && roles.results[2].is_allowlisted === 1 && roles.results[2].override_allowed === null);
}

export function makeUnifiedAuthActivationOracle(revision: string, workerSha: string, candidateSha: string) {
  const cutoverAt = Math.floor(Date.now() / 1000);
  const activationSha256 = digest(JSON.stringify({ revision, workerSha, candidateSha, bot: BOT,
    approved: APPROVED, generation: GENERATION, cutoverAt, scope: "hosted-synthetic-private-only" }));
  const generalConfig = JSON.stringify({ botId: BOT, botUsername: BOT_USERNAME, webhookSecret: GENERAL_SECRET,
    botToken: BOT_TOKEN, generation: GENERATION, cutoverAt, activationSha256 });
  const isolationConfig = JSON.stringify({ botId: BOT, botUsername: BOT_USERNAME, adminId: ADMIN, memberId: MEMBER,
    groupId: String(GROUP), webhookSecret: "synthetic-v11-isolation-webhook-secret", botToken: `${BOT}:${"i".repeat(35)}` });
  const seen = new Set<number>();
  let unexpected = false;

  async function outboundService(request: Request): Promise<Response> {
    try {
      requireAuth(request.url === `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage` && request.method === "POST");
      const body: unknown = await request.json();
      requireAuth(record(body) && Object.keys(body).length === 4 && record(body.reply_parameters)
        && Object.keys(body.reply_parameters).length === 1 && record(body.link_preview_options)
        && Object.keys(body.link_preview_options).length === 1 && body.link_preview_options.is_disabled === true);
      const id = body.reply_parameters.message_id;
      requireAuth(typeof id === "number" && !seen.has(id));
      const expected = REPLIES.get(id);
      requireAuth(expected && body.chat_id === expected.actor && body.text === expected.text);
      seen.add(id);
      return Response.json({ ok: true, result: { message_id: id + 1000, chat: { id: Number(expected.actor) } } });
    } catch {
      unexpected = true;
      throw new Error("Unexpected synthetic authorization transport.");
    }
  }

  async function verify(runtime: Miniflare, origin: string, manifest: Record<string, unknown>) {
    const db = await runtime.getD1Database("DB", "general");
    const general = await runtime.getWorker("general");
    const isolation = await runtime.getWorker("isolation");
    const malformed = await runtime.getWorker("malformed-isolation");
    const now = () => db.prepare("SELECT unixepoch() AS epoch").first<number>("epoch");
    let date = await now();
    for (let i = 0; date !== null && date <= cutoverAt && i < 20; i++) {
      await new Promise((resolve) => setTimeout(resolve, 100));
      date = await now();
    }
    requireAuth(typeof date === "number" && date > cutoverAt && date - cutoverAt < 60);
    const freshDate = date;
    const post = async (id: number, actor: string, text: string, { worker = general, eventDate = freshDate,
      secret = GENERAL_SECRET, group = false } = {}) => (await worker.fetch(origin + "/telegram/webhook", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Telegram-Bot-Api-Secret-Token": secret },
      body: JSON.stringify({ update_id: id, message: { message_id: id, date: eventDate, text,
        from: { id: Number(actor), is_bot: false }, chat: { id: group ? GROUP : Number(actor), type: group ? "group" : "private" },
        entities: [{ type: "bot_command", offset: 0, length: text.split(" ")[0].length }] } }),
    })).status;
    const totals = () => db.prepare(`SELECT (SELECT count(*) FROM telegram_general_policy) AS policies,
      (SELECT count(*) FROM telegram_general_actors) AS actors,
      (SELECT count(*) FROM telegram_general_replies) AS replies,
      (SELECT count(*) FROM telegram_inbox) AS inbox,(SELECT count(*) FROM telegram_outbox) AS outbox`).first();
    const state = (id: number) => db.prepare("SELECT state FROM telegram_general_replies WHERE bot_id=? AND update_id=?")
      .bind(BOT, id).first<string>("state");
    const exactPin = "bot_id=? AND generation=? AND release_revision=? AND activation_sha256=? AND cutover_at=?";
    const pin = [BOT, GENERATION, revision, activationSha256, cutoverAt];

    await verifyDormantAuth(db, manifest);
    let counts = await totals();
    requireAuth(counts?.policies === 0 && counts.actors === 0 && counts.replies === 0);
    requireAuth(await post(800, ADMIN, "/list") === 204);
    const staged = await db.batch([
      db.prepare(`INSERT INTO telegram_general_policy (bot_id,generation,release_revision,activation_sha256,cutover_at)
        VALUES (?,?,?,?,?)`).bind(...pin),
      ...APPROVED.map(([actor, expected]) => db.prepare(`INSERT INTO telegram_general_actors
        (bot_id,generation,actor_id,revision,effective_at,role)
        VALUES (?,?,?,1,?,(SELECT CASE WHEN (${GENERAL_AUTH_LEGACY_ROLE})=? THEN ? END
          FROM general_auth_principals AS principal WHERE bot_id=? AND user_id=?))`)
        .bind(BOT, GENERATION, actor, cutoverAt, expected, expected, BOT, actor)),
    ]);
    requireAuth(staged.length === 3 && staged.every(({ success, meta }) => success && meta.changes === 1));
    requireAuth(await post(800, ADMIN, "/list") === 204);

    const activate = (bindings: typeof pin) => db.prepare(`UPDATE telegram_general_policy SET active=1
      WHERE ${exactPin} AND active=0 AND EXISTS (
        SELECT 1 FROM general_auth_installation WHERE bot_id=? AND unlisted_default='denied')
      AND (SELECT count(*) FROM telegram_general_actors WHERE bot_id=?)=2
      AND EXISTS (SELECT 1 FROM telegram_general_actors WHERE bot_id=? AND generation=? AND actor_id=?
        AND revision=1 AND effective_at=? AND role='admin')
      AND EXISTS (SELECT 1 FROM telegram_general_actors WHERE bot_id=? AND generation=? AND actor_id=?
        AND revision=1 AND effective_at=? AND role='member')
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=?)
      RETURNING active`).bind(...bindings, BOT, BOT, BOT, GENERATION, ADMIN, cutoverAt,
      BOT, GENERATION, MEMBER, cutoverAt, BOT).first<number>("active");
    requireAuth(await activate([BOT, GENERATION, revision, "0".repeat(64), cutoverAt]) === null
      && await activate(pin) === 1 && await activate(pin) === null);
    requireAuth(await post(804, ADMIN, "/list", { eventDate: cutoverAt }) === 204
      && await post(805, OUTSIDE, "/list") === 204 && await post(806, MEMBER, "/list", { group: true }) === 204
      && await post(807, MEMBER, "/auth") === 204 && await post(808, MEMBER, "/list " + ADMIN) === 204
      && await post(809, ADMIN, "/list", { worker: isolation }) === 401
      && await post(810, ADMIN, "/list", { worker: malformed }) === 503);

    for (const [id, { actor }] of REPLIES) {
      const command = id === 802 ? "/help" : "/list";
      const response = id === 801 ? await Promise.all([post(id, actor, command), post(id, actor, command)])
        : [await post(id, actor, command), await post(id, actor, command)];
      requireAuth(response.sort().join(",") === "200,204");
      let settled = false;
      for (let i = 0; i < 50 && !settled; i++) {
        requireAuth(!unexpected);
        settled = await state(id) === "sent";
        if (!settled) await new Promise((resolve) => setTimeout(resolve, 50));
      }
      requireAuth(settled && seen.has(id));
    }

    // Represent interrupted states directly in the fresh fixture. No production failpoint or outbound call is used.
    const revoked = await db.batch([
      db.prepare(`INSERT INTO telegram_general_replies
        (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command,state,lease_id,lease_until)
        VALUES (?,?,?,1,811,811,?,'list','leased','synthetic-revoked-lease',unixepoch()+15)`)
        .bind(BOT, GENERATION, ADMIN, freshDate),
      db.prepare("INSERT INTO telegram_general_actors VALUES (?,?,?,2,?,'denied')").bind(BOT, GENERATION, ADMIN, freshDate),
    ]);
    requireAuth(revoked.every(({ success, meta }) => success && meta.changes === 1));
    requireAuth(await post(813, ADMIN, "/list", { eventDate: freshDate + 1 }) === 204);
    requireAuth((await isolation.scheduled({ cron: "* * * * *" })).outcome === "ok"
      && (await malformed.scheduled({ cron: "* * * * *" })).outcome === "ok" && await state(811) === "leased");
    requireAuth((await general.scheduled({ cron: "* * * * *" })).outcome === "ok" && await state(811) === "discarded");

    const rolledBack = await db.batch([
      db.prepare(`INSERT INTO telegram_general_replies
        (bot_id,generation,actor_id,actor_revision,update_id,message_id,message_date,command,state,lease_id,lease_until)
        VALUES (?,?,?,1,812,812,?,'list','sending','synthetic-interrupted-send',unixepoch()-1),
          (?,?,?,1,814,814,?,'list','pending',NULL,NULL)`).bind(BOT, GENERATION, MEMBER, freshDate, BOT, GENERATION, MEMBER, freshDate),
      db.prepare(`UPDATE telegram_general_policy SET active=0 WHERE ${exactPin} AND active=1`).bind(...pin),
    ]);
    requireAuth(rolledBack.length === 2 && rolledBack.every(({ success }) => success)
      && rolledBack[0].meta.changes === 2 && rolledBack[1].meta.changes === 1);
    requireAuth(await post(815, MEMBER, "/list") === 204 && (await general.scheduled({ cron: "* * * * *" })).outcome === "ok"
      && await state(811) === "discarded" && await state(812) === "uncertain" && await state(814) === "discarded");
    requireAuth((await general.scheduled({ cron: "* * * * *" })).outcome === "ok" && await state(812) === "uncertain");
    counts = await totals();
    requireAuth(!unexpected && seen.size === 3 && counts?.policies === 1 && counts.actors === 3 && counts.replies === 6
      && counts.inbox === 0 && counts.outbox === 0);
    requireAuth(await db.prepare(`SELECT active FROM telegram_general_policy WHERE ${exactPin}`).bind(...pin).first("active") === 0);
    await verifyDormantAuth(db, manifest);
    return { admittedActors: 2, confirmedReplies: 3, discardedReplies: 2, uncertainReplies: 1 };
  }

  return { generalConfig, isolationConfig, outboundService, verify };
}

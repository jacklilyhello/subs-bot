import { collapsePathRuleWhitespace, MAX_PATH_RULES, pathRuleText, type PathRuleRow } from "../path-rules.ts";
import { SnapshotIntegrityError, validInteger } from "../storage.ts";
import { inTelegramScope, type TelegramPathUpdate, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_PATH_MARKER = "path:v1";
const PAGE_SIZE = 6;
const MAX_MUTATION_AGE_SECONDS = 15 * 60;
const FUTURE_SKEW_SECONDS = 30;
const MAX_COMMAND_UNITS = 8192;
const displayControls = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu;

type PathMutation = { kind: "upsert"; keyword: string; remark: string } | { kind: "delete"; id: number } | { kind: "clear" };
type PathAction = PathMutation | { kind: "list"; afterId: number | null } | { kind: "usage" };
export interface TelegramPathReply {
  kind: "list" | "usage" | "saved" | "deleted" | "cleared" | "missing" | "capacity" | "stale";
  afterId: number | null;
  affectedCount: number;
}

type ReceiptKey = readonly [botId: string, updateId: number, nonce: string];
const fresh = "incoming.bot_id = ? AND incoming.update_id = ? AND incoming.receipt_nonce = ?";
const owner = "rule.owner_id = incoming.actor_id";
const sameFence = "fence.bot_id = incoming.bot_id AND fence.actor_id = incoming.actor_id";
const eventOrder = "(incoming.message_date, incoming.message_id)";
const fenceOrder = "(fence.message_date, fence.message_id)";
const changesRules = "reply.kind IN ('saved', 'deleted', 'cleared')";

function positiveId(value: string): number | null {
  const id = Number(value);
  return validInteger(id, 1) && String(id) === value ? id : null;
}

export function parseTelegramPathArgs(args: string): PathAction {
  if (typeof args !== "string" || args.length > MAX_COMMAND_UNITS) return { kind: "usage" };
  const input = collapsePathRuleWhitespace(args);
  if (!input) return { kind: "list", afterId: null };
  const space = input.indexOf(" ");
  const verb = (space === -1 ? input : input.slice(0, space)).toLowerCase();
  const rest = space === -1 ? "" : input.slice(space + 1);
  if (verb === "list") {
    const afterId = positiveId(rest);
    return rest === "" || afterId !== null ? { kind: "list", afterId } : { kind: "usage" };
  }
  if (verb === "clear") return rest === "" ? { kind: "clear" } : { kind: "usage" };
  if (verb === "delete") {
    const id = positiveId(rest);
    return id === null ? { kind: "usage" } : { kind: "delete", id };
  }

  // The legacy command treats '=' in an HTTP(S) URL as part of the keyword.
  const equal = input.indexOf("=");
  const delimiter = equal !== -1 && !/^https?:\/\//iu.test(input) ? equal : space;
  if (delimiter === -1) return { kind: "usage" };
  const keyword = pathRuleText(input.slice(0, delimiter).replace(/ +$/u, ""));
  const remark = pathRuleText(input.slice(delimiter + 1).replace(/^ +/u, ""));
  if (keyword === null || remark === null || [keyword, remark].some((text) => text.replace(displayControls, "") !== text)) {
    return { kind: "usage" };
  }
  return { kind: "upsert", keyword, remark };
}

function planMutation(db: D1Database, key: ReceiptKey, policy: TelegramPolicy, action: PathMutation) {
  const scope = `FROM telegram_inbox AS incoming JOIN telegram_path_reply AS reply USING (receipt_id)
    WHERE ${fresh} AND ${changesRules}`;
  let outcome: string;
  let values: (number | string)[];
  let apply: D1PreparedStatement;
  let verify: string;
  let verification: (number | string)[];

  switch (action.kind) {
    case "upsert":
      outcome = `CASE WHEN owner_count < ${MAX_PATH_RULES} OR EXISTS (
        SELECT 1 FROM path_rules AS rule WHERE rule.owner_id = candidate.actor_id AND rule.keyword = ?
      ) THEN 'saved' ELSE 'capacity' END`;
      values = [action.keyword];
      apply = db.prepare(`
        INSERT INTO path_rules (owner_id, keyword, remark) SELECT incoming.actor_id, ?, ? ${scope}
        ON CONFLICT (owner_id, keyword) DO UPDATE SET remark = excluded.remark
      `).bind(action.keyword, action.remark, ...key);
      verify = `EXISTS (SELECT 1 FROM path_rules AS rule WHERE ${owner} AND rule.keyword = ? AND rule.remark = ?)`;
      verification = [action.keyword, action.remark];
      break;
    case "delete":
      outcome = `CASE WHEN EXISTS (
        SELECT 1 FROM path_rules AS rule WHERE rule.owner_id = candidate.actor_id AND rule.id = ?
      ) THEN 'deleted' ELSE 'missing' END`;
      values = [action.id];
      apply = db.prepare(`DELETE FROM path_rules WHERE id = ?
        AND owner_id = (SELECT incoming.actor_id ${scope})`).bind(action.id, ...key);
      verify = `NOT EXISTS (SELECT 1 FROM path_rules AS rule WHERE ${owner} AND rule.id = ?)`;
      verification = [action.id];
      break;
    case "clear":
      outcome = `CASE WHEN owner_count <= ${MAX_PATH_RULES} THEN 'cleared' ELSE 'capacity' END`;
      values = [];
      apply = db.prepare(`DELETE FROM path_rules WHERE owner_id = (SELECT incoming.actor_id ${scope})`).bind(...key);
      verify = `NOT EXISTS (SELECT 1 FROM path_rules AS rule WHERE ${owner})`;
      verification = [];
      break;
  }

  const statements = [db.prepare(`
    WITH candidate AS (
      SELECT incoming.receipt_id, incoming.actor_id,
        (SELECT count(*) FROM (SELECT 1 FROM path_rules AS rule WHERE ${owner} LIMIT ${MAX_PATH_RULES + 1})) AS owner_count,
        (incoming.message_date <= unixepoch() - ${MAX_MUTATION_AGE_SECONDS}
          OR incoming.message_date > unixepoch() + ${FUTURE_SKEW_SECONDS}
          OR EXISTS (SELECT 1 FROM telegram_path_fence AS fence WHERE ${sameFence} AND ${fenceOrder} >= ${eventOrder})
          OR (incoming.actor_id <> ? AND EXISTS (
            SELECT 1 FROM telegram_auth AS auth WHERE auth.bot_id = incoming.bot_id AND auth.user_id = incoming.actor_id
            AND auth.message_date >= incoming.message_date
          ))) AS stale
      FROM telegram_inbox AS incoming WHERE ${fresh}
    ), outcome AS (
      SELECT receipt_id, owner_count, CASE WHEN stale THEN 'stale' ELSE ${outcome} END AS kind FROM candidate
    )
    INSERT INTO telegram_path_reply (receipt_id, kind, affected_count)
    SELECT receipt_id, kind, CASE WHEN kind = 'cleared' THEN owner_count WHEN kind IN ('saved', 'deleted') THEN 1 ELSE 0 END
    FROM outcome
  `).bind(policy.adminId, ...key, ...values), apply, db.prepare(`
    INSERT INTO telegram_path_fence (bot_id, actor_id, message_date, message_id)
    SELECT incoming.bot_id, incoming.actor_id, incoming.message_date, incoming.message_id ${scope}
    ON CONFLICT (bot_id, actor_id) DO UPDATE SET message_date = excluded.message_date, message_id = excluded.message_id
    WHERE (excluded.message_date, excluded.message_id) > (telegram_path_fence.message_date, telegram_path_fence.message_id)
  `).bind(...key)];
  return { statements, verify: `${verify} AND EXISTS (
    SELECT 1 FROM telegram_path_fence AS fence WHERE ${sameFence} AND ${fenceOrder} = ${eventOrder}
  )`, verification };
}

export async function acceptTelegramPath(
  db: D1Database, policy: TelegramPolicy, event: TelegramPathUpdate,
): Promise<"accepted" | "ignored"> {
  if (event.chatType !== "private" || event.threadId !== null || !inTelegramScope(policy, event)
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) return "ignored";

  try {
    const nonce = crypto.randomUUID();
    const key = [policy.botId, event.updateId, nonce] as const;
    const action = parseTelegramPathArgs(event.args);
    const statements = [db.prepare(`
      INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
      SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
      WHERE ? = ? OR COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id = ? AND user_id = ?), 1) = 1
      ON CONFLICT (bot_id, update_id) DO NOTHING
    `).bind(policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce,
      event.actorId, policy.adminId, policy.botId, event.actorId)];

    let verify = "0";
    let verification: (number | string)[] = [];
    if (action.kind === "list" || action.kind === "usage") {
      statements.push(db.prepare(`
        INSERT INTO telegram_path_reply (receipt_id, kind, after_id)
        SELECT incoming.receipt_id, ?, ? FROM telegram_inbox AS incoming WHERE ${fresh}
      `).bind(action.kind, action.kind === "list" ? action.afterId : null, ...key));
    } else {
      const mutation = planMutation(db, key, policy, action);
      statements.push(...mutation.statements);
      ({ verify, verification } = mutation);
    }

    statements.push(db.prepare(`
      INSERT INTO telegram_outbox (receipt_id) SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}
    `).bind(...key), db.prepare(`
      UPDATE telegram_inbox AS incoming SET receipt_nonce = ?, command = CASE WHEN EXISTS (
        SELECT 1 FROM telegram_path_reply AS reply JOIN telegram_outbox USING (receipt_id)
        WHERE reply.receipt_id = incoming.receipt_id AND (NOT (${changesRules}) OR (${verify}))
      ) THEN command END WHERE ${fresh} RETURNING receipt_id
    `).bind(TELEGRAM_PATH_MARKER, ...verification, ...key));

    const results = await db.batch(statements);
    const receipt = results.at(-1);
    if (receipt && results.length === statements.length && results.every((result) => result.success)
      && receipt.results.length <= 1) return receipt.results.length ? "accepted" : "ignored";
  } catch {
    // Bound values and backend details can contain private rule text.
  }
  throw new Error("Telegram path rule receipt could not be confirmed.");
}

export async function renderTelegramPath(db: D1Database, actorId: string, reply: TelegramPathReply): Promise<string> {
  switch (reply.kind) {
    case "usage": return "用法：/path 查看，/path 关键词 备注 添加，/path delete 编号 删除，/path clear 清空。";
    case "saved": return "已保存路径规则。";
    case "deleted": return "已删除路径规则。";
    case "cleared": return `已清空 ${reply.affectedCount} 条路径规则。`;
    case "missing": return "路径规则不存在。";
    case "capacity": return "路径规则已达上限，请按编号删除现有规则后重试。";
    case "stale": return "此路径命令已过期或已有更新的操作，请重发。";
    case "list": {
      const page = await db.prepare(`
        SELECT id, keyword, remark FROM path_rules WHERE owner_id = ? AND id > ? ORDER BY id LIMIT ?
      `).bind(actorId, reply.afterId ?? 0, PAGE_SIZE + 1).all<PathRuleRow>();
      if (!page.success) throw new SnapshotIntegrityError();
      if (page.results.length === 0) return "没有更多路径规则。";
      const lines = page.results.slice(0, PAGE_SIZE).map(({ id, keyword, remark }) => {
        const needle = pathRuleText(keyword);
        const label = pathRuleText(remark);
        if (!validInteger(id, 1) || needle === null || label === null) throw new SnapshotIntegrityError();
        return `#${id} ${needle.replace(displayControls, " ")} → ${label.replace(displayControls, " ")}`;
      });
      if (page.results.length > PAGE_SIZE) lines.push(`下一页：/path list ${page.results[PAGE_SIZE - 1].id}`);
      return ["你的路径规则", ...lines].join("\n");
    }
  }
}

import { ExportContentError, planBase64 } from "../base64-response.ts";
import { getSubscriptionNodeSource, PathRuleContentError } from "../path-rules.ts";
import { SingBoxContentError } from "../singbox-export.ts";
import { planSingBox } from "../singbox-response.ts";
import { digestHex, readSnapshotNodes, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger, type SubscriptionSnapshot } from "../storage.ts";
import { providerRefreshTarget, type TelegramProviderRefreshTarget } from "./provider-refresh.ts";
import type { TelegramRawFileTarget } from "./subscription-raw-file.ts";
import { TELEGRAM_AGGREGATE_ORIGIN } from "./aggregate-actions.ts";
import { inTelegramScope, SUBSCRIPTION_READ_RECEIPT_MARKER, SUBSCRIPTION_READ_TICKET,
  type TelegramPolicy, type TelegramSubscriptionReadUpdate } from "./protocol.ts";
import { selectedQuery, unicode14Lower } from "./selected-search.ts";
import { displayTelegramName, displayTelegramDate, TELEGRAM_VIEW_MARKER } from "./views.ts";
import { TELEGRAM_SUBSCRIPTION_NODE_MARKER, type TelegramNodePageButton } from "./subscription-node-pages.ts";

export const TELEGRAM_SUBSCRIPTION_READ_MARKER = SUBSCRIPTION_READ_RECEIPT_MARKER;
export const MAX_SUBSCRIPTION_SEARCH_ROWS = 512;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const PAGE_SIZE = 8;
const SCAN_PAGE_SIZE = 16;
const MAX_BUTTONS = PAGE_SIZE + 2;
const TICKET_SECONDS = 600;
const PREVIEW_NODES = 8;
const READ_BUDGET_MS = 5_000;
const TOKEN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
const FORMAT_LABELS = { clash: "Clash Meta", singbox: "Sing-box", base64: "Base64", surge: "Surge", qx: "QX" } as const;
type Format = keyof typeof FORMAT_LABELS;
const encoder = new TextEncoder();

type ReadTarget = { kind: "detail"; subscriptionId: number }
  | { kind: "format"; subscriptionId: number; format: Format }
  | { kind: "search"; searchReceiptId: number; searchOffset: number };
export type TelegramSubscriptionReadButton = ReadTarget & { text: string };
export type TelegramSubscriptionReadTicket = ReadTarget & { sha256: string };

type ReadKind = ReadTarget["kind"] | "usage" | "limit" | "missing" | "stale";
type Receipt = {
  kind: ReadKind;
  subscriptionId: number | null;
  format: Format | null;
  searchReceiptId: number | null;
  searchOffset: number | null;
};
type ReadLease = {
  receiptId: number; actorId: string; chatId: string; chatType: string; threadId: number | null;
  leaseId: string; attempts: number;
};
type Guard = { sql: string; bindings: readonly (string | number | null)[] };
interface RenderedRead {
  text: string;
  readButtons?: TelegramSubscriptionReadButton[];
  readGuard?: Guard;
  nodeButtons?: TelegramNodePageButton[];
  refreshTarget?: TelegramProviderRefreshTarget;
  rawFileTarget?: TelegramRawFileTarget;
}

const privateScope = (event: Pick<ReadLease, "actorId" | "chatId" | "chatType" | "threadId">): boolean =>
  event.chatType === "private" && event.chatId === event.actorId && event.threadId === null;

export async function telegramSubscriptionReadReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
      AND name IN ('telegram_subscription_read','telegram_subscription_read_ticket')`).first<{ present: number }>();
    return row?.present === 2;
  } catch {
    throw new Error("Telegram subscription read schema could not be confirmed.");
  }
}

async function digestTicket(ticket: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(ticket)));
}

type SearchScan = { kind: "usage" | "limit" } | { kind: "search"; matches: string; inventory: string };

async function scanSearch(db: D1Database, ownerId: string, query: string): Promise<SearchScan> {
  const needle = selectedQuery(query);
  if (needle === "") return { kind: "usage" };
  if (needle === null) return { kind: "limit" };
  const deadline = Date.now() + READ_BUDGET_MS;
  const inventory: [number, number][] = [];
  const matches: [number, number][] = [];
  let afterId = 0;
  let bytes = 0;
  for (;;) {
    if (Date.now() >= deadline) return { kind: "limit" };
    const result = await db.prepare(`SELECT id,name,source_url AS sourceUrl,${SUBSCRIPTION_LIFECYCLE_REVISION} AS revision
      FROM subscriptions WHERE owner_id=? AND id>? ORDER BY id LIMIT ?`).bind(ownerId, afterId, SCAN_PAGE_SIZE)
      .all<{ id: number; name: string; sourceUrl: string; revision: number }>();
    if (!result.success) throw new Error("Telegram subscription search could not be read.");
    for (const row of result.results) {
      if (!validInteger(row.id, afterId + 1) || !validInteger(row.revision, 0) || typeof row.name !== "string"
        || typeof row.sourceUrl !== "string") throw new Error("Telegram subscription metadata is invalid.");
      bytes += encoder.encode(row.name).byteLength + encoder.encode(row.sourceUrl).byteLength;
      if (inventory.length === MAX_SUBSCRIPTION_SEARCH_ROWS || bytes > MAX_SCAN_BYTES || Date.now() >= deadline) return { kind: "limit" };
      afterId = row.id;
      inventory.push([row.id, row.revision]);
      if (unicode14Lower(`${row.name} ${row.sourceUrl}`).includes(needle)) matches.push([row.id, inventory.length]);
    }
    if (result.results.length < SCAN_PAGE_SIZE) return { kind: "search", matches: JSON.stringify(matches), inventory: JSON.stringify(inventory) };
  }
}

const authEpochFields = `CASE WHEN incoming.actor_id=? THEN 0 ELSE COALESCE(auth.message_date,0) END,
  CASE WHEN incoming.actor_id=? THEN 0 ELSE COALESCE(auth.message_id,0) END`;
const receiptFields = "receipt_id,kind,subscription_id,format,search_receipt_id,search_offset,matches,auth_message_date,auth_message_id";
const authJoin = "LEFT JOIN telegram_auth AS auth ON auth.bot_id=incoming.bot_id AND auth.user_id=incoming.actor_id";

export async function acceptTelegramSubscriptionRead(
  db: D1Database, policy: TelegramPolicy, event: TelegramSubscriptionReadUpdate, nodePagesEnabled = false,
): Promise<"accepted" | "ignored"> {
  if (!inTelegramScope(policy, event) || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1)
    || !validInteger(event.messageDate, 1) || (event.kind === "number" && !privateScope(event))
    || (event.kind === "callback" && !SUBSCRIPTION_READ_TICKET.test(event.ticket))) return "ignored";
  try {
    if (event.actorId !== policy.adminId) {
      const auth = await db.prepare("SELECT allowed,message_date AS date FROM telegram_auth WHERE bot_id=? AND user_id=?")
        .bind(policy.botId, event.actorId).first<{ allowed: number; date: number }>();
      if (auth && (auth.allowed !== 1 || auth.date >= event.messageDate)) return "ignored";
    }
    const scan = event.kind === "search" ? await scanSearch(db, event.actorId, event.query) : null;
    const key = [policy.botId, event.updateId, crypto.randomUUID()] as const;
    const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
    const fields = "(bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)";
    const values = "?,?,?,?,?,?,?,?,'help',?";
    const scope = [policy.botId, event.updateId, event.actorId, event.chatId, event.chatType, event.messageId, event.messageDate,
      event.threadId, key[2]] as const;
    const timeAndAuth = `? BETWEEN unixepoch()-900 AND unixepoch()+30 AND (?=? OR COALESCE((
      SELECT allowed=1 AND message_date<? FROM telegram_auth WHERE bot_id=? AND user_id=?
    ),1))`;
    const auth = [event.messageDate, event.actorId, policy.adminId, event.messageDate, policy.botId, event.actorId] as const;
    const conflict = "ON CONFLICT(bot_id,update_id) DO NOTHING";
    const steps: D1PreparedStatement[] = [];
    if (event.kind === "callback") {
      const digest = await digestTicket(event.ticket);
      const nodePageOrigin = nodePagesEnabled ? `OR (origin.receipt_nonce='${TELEGRAM_SUBSCRIPTION_NODE_MARKER}'
        AND ticket.kind='detail' AND EXISTS (SELECT 1 FROM telegram_subscription_node_page AS page
          LEFT JOIN telegram_auth AS auth ON auth.bot_id=origin.bot_id AND auth.user_id=origin.actor_id
          WHERE page.receipt_id=origin.receipt_id AND page.subscription_id=ticket.subscription_id
            AND (${event.actorId === policy.adminId ? "1" : `page.auth_message_date=COALESCE(auth.message_date,0)
              AND page.auth_message_id=COALESCE(auth.message_id,0)`})))` : "";
      steps.push(db.prepare(`INSERT INTO telegram_inbox ${fields} SELECT ${values}
        FROM telegram_subscription_read_ticket AS ticket
        JOIN telegram_inbox AS origin ON origin.receipt_id=ticket.origin_receipt_id
        JOIN telegram_outbox AS reply ON reply.receipt_id=origin.receipt_id
        LEFT JOIN telegram_subscription_read AS read_origin ON read_origin.receipt_id=origin.receipt_id
        WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ticket.expires_at>unixepoch()
          AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type=? AND origin.thread_id IS ?
          AND reply.state='sent' AND reply.sent_message_id=? AND reply.attempts=ticket.origin_attempt
          AND ((origin.receipt_nonce=? AND ticket.kind='detail') OR (origin.receipt_nonce=? AND (
            (read_origin.kind='search' AND ticket.kind IN ('search','detail'))
            OR (read_origin.kind='detail' AND ticket.kind='format' AND ticket.subscription_id=read_origin.subscription_id))) ${nodePageOrigin})
          AND (ticket.kind='search' OR (origin.chat_type='private' AND origin.chat_id=origin.actor_id AND origin.thread_id IS NULL))
          AND (origin.actor_id=? OR COALESCE((SELECT allowed=1 AND message_date<origin.message_date
            FROM telegram_auth WHERE bot_id=origin.bot_id AND user_id=origin.actor_id),1))
          AND ${timeAndAuth} ${conflict}`).bind(...scope, digest, policy.botId, event.actorId, event.chatId, event.chatType, event.threadId,
        event.messageId, TELEGRAM_VIEW_MARKER, TELEGRAM_SUBSCRIPTION_READ_MARKER, policy.adminId, ...auth));
      steps.push(db.prepare(`UPDATE telegram_subscription_read_ticket AS ticket SET used_by_receipt_id=incoming.receipt_id
        FROM telegram_inbox AS incoming WHERE ticket.token_sha256=? AND ticket.used_by_receipt_id IS NULL AND ${fresh}`)
        .bind(digest, ...key));
      steps.push(db.prepare(`INSERT INTO telegram_subscription_read(${receiptFields})
        SELECT incoming.receipt_id,ticket.kind,ticket.subscription_id,ticket.format,ticket.search_receipt_id,ticket.search_offset,
          NULL,${authEpochFields}
        FROM telegram_inbox AS incoming JOIN telegram_subscription_read_ticket AS ticket ON ticket.used_by_receipt_id=incoming.receipt_id
        ${authJoin} WHERE ${fresh}`).bind(policy.adminId, policy.adminId, ...key));
    } else {
      steps.push(db.prepare(`INSERT INTO telegram_inbox ${fields} SELECT ${values} WHERE ${timeAndAuth} ${conflict}`).bind(...scope, ...auth));
      if (scan?.kind === "search") {
        steps.push(db.prepare(`WITH checked AS (
          SELECT incoming.receipt_id,(
            (SELECT count(*) FROM subscriptions WHERE owner_id=incoming.actor_id)=json_array_length(?)
            AND NOT EXISTS (SELECT 1 FROM json_each(?) AS expected LEFT JOIN subscriptions AS sub
              ON sub.owner_id=incoming.actor_id AND sub.id=json_extract(expected.value,'$[0]')
              LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
              WHERE sub.id IS NULL OR COALESCE(lifecycle.revision,0)<>json_extract(expected.value,'$[1]'))
          ) AS stable,
          CASE WHEN incoming.actor_id=? THEN 0 ELSE COALESCE(auth.message_date,0) END AS authDate,
          CASE WHEN incoming.actor_id=? THEN 0 ELSE COALESCE(auth.message_id,0) END AS authId
          FROM telegram_inbox AS incoming ${authJoin} WHERE ${fresh}
        ) INSERT INTO telegram_subscription_read(${receiptFields})
        SELECT receipt_id,CASE WHEN stable THEN 'search' ELSE 'stale' END,NULL,NULL,NULL,
          CASE WHEN stable THEN 0 END,CASE WHEN stable THEN ? END,authDate,authId FROM checked`)
          .bind(scan.inventory, scan.inventory, policy.adminId, policy.adminId, ...key, scan.matches));
      } else if (event.kind === "number" && validInteger(event.position, 1, MAX_SUBSCRIPTION_SEARCH_ROWS)) {
        steps.push(db.prepare(`INSERT INTO telegram_subscription_read(${receiptFields})
          SELECT incoming.receipt_id,CASE WHEN sub.id IS NULL THEN 'missing' ELSE 'detail' END,
            sub.id,NULL,NULL,NULL,NULL,${authEpochFields}
          FROM telegram_inbox AS incoming LEFT JOIN subscriptions AS sub ON sub.id=(
            SELECT id FROM subscriptions WHERE owner_id=? ORDER BY id LIMIT 1 OFFSET ?
          ) ${authJoin} WHERE ${fresh}`).bind(policy.adminId, policy.adminId, event.actorId, event.position - 1, ...key));
      } else {
        steps.push(db.prepare(`INSERT INTO telegram_subscription_read(${receiptFields})
          SELECT incoming.receipt_id,?,NULL,NULL,NULL,NULL,NULL,${authEpochFields}
          FROM telegram_inbox AS incoming ${authJoin} WHERE ${fresh}`)
          .bind(scan?.kind ?? (event.kind === "number" && event.position === 0 ? "missing" : "limit"), policy.adminId, policy.adminId, ...key));
      }
    }
    steps.push(
      db.prepare(`INSERT INTO telegram_outbox(receipt_id) SELECT receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=?,command=CASE WHEN EXISTS (
        SELECT 1 FROM telegram_subscription_read AS detail JOIN telegram_outbox AS reply USING(receipt_id)
        WHERE detail.receipt_id=incoming.receipt_id) THEN command END
        WHERE ${fresh} RETURNING receipt_id`).bind(TELEGRAM_SUBSCRIPTION_READ_MARKER, ...key),
    );
    const results = await db.batch(steps);
    const receipt = results.at(-1);
    if (receipt && results.length === steps.length && results.every(({ success }) => success) && receipt.results.length <= 1) {
      return receipt.results.length === 1 ? "accepted" : "ignored";
    }
  } catch {
    // D1 errors may include search or subscription data.
  }
  throw new Error("Telegram subscription read receipt could not be confirmed.");
}

function receiptGuard(policy: TelegramPolicy): Guard {
  return { sql: `inbox.receipt_nonce='${TELEGRAM_SUBSCRIPTION_READ_MARKER}' AND EXISTS (
    SELECT 1 FROM telegram_subscription_read AS action LEFT JOIN telegram_auth AS auth
      ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id WHERE action.receipt_id=inbox.receipt_id
      AND (inbox.actor_id=? OR (COALESCE(auth.allowed,1)=1 AND action.auth_message_date=COALESCE(auth.message_date,0)
        AND action.auth_message_id=COALESCE(auth.message_id,0) AND inbox.message_date>COALESCE(auth.message_date,0)))
  )`, bindings: [policy.adminId] };
}

function leaseScopeSql(state: "leased" | "sending"): string {
  return `reply.state='${state}' AND reply.lease_id=? AND reply.attempts=? AND reply.lease_until>unixepoch()
    AND inbox.receipt_id=? AND inbox.bot_id=? AND inbox.actor_id=? AND inbox.chat_id=? AND inbox.chat_type=? AND inbox.thread_id IS ?`;
}

function leaseScopeArgs(policy: TelegramPolicy, lease: ReadLease) {
  return [lease.leaseId, lease.attempts, lease.receiptId, policy.botId, lease.actorId, lease.chatId, lease.chatType, lease.threadId] as const;
}

export async function confirmTelegramSubscriptionReadSend(db: D1Database, policy: TelegramPolicy, lease: ReadLease, guard: Guard): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      WHERE ${leaseScopeSql("sending")} AND (${guard.sql})`).bind(...leaseScopeArgs(policy, lease), ...guard.bindings).first();
    return row !== null;
  } catch {
    throw new Error("Telegram subscription read delivery could not be confirmed.");
  }
}

type Metadata = {
  id: number;
  name: string;
  expireAt: number | null;
  trafficUsed: number | null;
  trafficTotal: number | null;
  refreshFailed: number;
  nodeCount: number;
  generation: number;
  lifecycleRevision: number;
  snapshotId: string | null;
  manifestSha256: string | null;
  token: string | null;
  sourceUrl: string | null;
};

function subscriptionGuard(guard: Guard, row: Metadata, token?: string, refreshSource?: string | null): Guard {
  return { sql: `(${guard.sql}) AND EXISTS (SELECT 1 FROM subscriptions
    WHERE id=? AND owner_id=inbox.actor_id AND generation=? AND ${SUBSCRIPTION_LIFECYCLE_REVISION}=?
      AND snapshot_id IS ? AND manifest_sha256 IS ? AND node_count=? ${token ? "AND token=?" : ""}
      ${refreshSource ? "AND source_url=?" : ""})`,
    bindings: [...guard.bindings, row.id, row.generation, row.lifecycleRevision, row.snapshotId, row.manifestSha256, row.nodeCount,
      ...(token ? [token] : []), ...(refreshSource ? [refreshSource] : [])] };
}

function gb(value: number | null): string {
  // Legacy storage and the provider publisher already use GiB.
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? `${value.toFixed(2)} GB` : "未知";
}

function remaining(used: number | null, total: number | null): string {
  return used !== null && total !== null && Number.isFinite(used) && Number.isFinite(total) && used >= 0 && total >= 0
    ? gb(Math.max(0, total - used)) : "未知";
}

function expiry(value: number | null): string {
  return value === null ? "未知" : displayTelegramDate(value);
}

async function renderSearch(
  db: D1Database, policy: TelegramPolicy, lease: ReadLease, receipt: Receipt, guard: Guard,
): Promise<RenderedRead> {
  const root = receipt.searchReceiptId ?? lease.receiptId;
  const showPrivate = privateScope(lease);
  const metadata = showPrivate
    ? "sub.traffic_used AS trafficUsed,sub.traffic_total AS trafficTotal,sub.expire_at AS expireAt"
    : "NULL AS trafficUsed,NULL AS trafficTotal,NULL AS expireAt";
  const rows = await db.prepare(`SELECT CAST(item.key AS INTEGER) AS position,json_extract(item.value,'$[1]') AS rank,
    sub.id,sub.name,${metadata}
    FROM telegram_subscription_read AS search JOIN telegram_inbox AS origin USING(receipt_id)
    JOIN json_each(search.matches) AS item JOIN subscriptions AS sub
      ON sub.id=json_extract(item.value,'$[0]') AND sub.owner_id=origin.actor_id
    WHERE search.receipt_id=? AND search.kind='search' AND search.matches IS NOT NULL
      AND origin.bot_id=? AND origin.actor_id=? AND origin.chat_id=? AND origin.chat_type=? AND origin.thread_id IS ?
      AND CAST(item.key AS INTEGER)>=? ORDER BY CAST(item.key AS INTEGER) LIMIT ?`)
    .bind(root, policy.botId, lease.actorId, lease.chatId, lease.chatType, lease.threadId, receipt.searchOffset, PAGE_SIZE + 1)
    .all<{ position: number; rank: number; id: number; name: string; expireAt: number | null; trafficUsed: number | null; trafficTotal: number | null }>();
  if (!rows.success) throw new Error("Telegram subscription search results could not be read.");
  const items = rows.results.slice(0, PAGE_SIZE);
  const lines = items.map((row) => `#${row.rank} ${displayTelegramName(row.name)}` +
    (showPrivate ? ` · 剩余 ${remaining(row.trafficUsed, row.trafficTotal)} · 到期 ${expiry(row.expireAt)}` : ""));
  const readButtons: TelegramSubscriptionReadButton[] = showPrivate
    ? items.map((row) => ({ text: `#${row.rank} 详情`, kind: "detail", subscriptionId: row.id })) : [];
  if (rows.results.length > PAGE_SIZE) readButtons.push({ text: "下一页", kind: "search", searchReceiptId: root,
    searchOffset: items[items.length - 1].position + 1 });
  if (receipt.searchOffset) readButtons.push({ text: "第一页", kind: "search", searchReceiptId: root, searchOffset: 0 });
  return { text: lines.length ? ["搜索结果", ...lines].join("\n") : "没有匹配订阅。", readButtons, readGuard: guard };
}

async function renderDetail(
  bucket: R2Bucket, row: Metadata, guard: Guard, deadline: number, nodePagesEnabled: boolean, rawFileEnabled: boolean,
): Promise<RenderedRead> {
  const lines = [
    `配置名称：${displayTelegramName(row.name)}`,
    `流量详情：${gb(row.trafficUsed)} / ${gb(row.trafficTotal)}`,
    `剩余可用：${remaining(row.trafficUsed, row.trafficTotal)}`,
    `过期时间：${expiry(row.expireAt)}`,
    `节点数量：${row.nodeCount}`,
  ];
  if (row.refreshFailed === 1) lines.push("上次刷新未成功。");
  const readButtons: TelegramSubscriptionReadButton[] = [];
  const nodeButtons: TelegramNodePageButton[] = [];
  let rawFileTarget: TelegramRawFileTarget | undefined;
  if (row.generation > 0) {
    try {
      const signal = AbortSignal.timeout(Math.max(1, Math.min(READ_BUDGET_MS, deadline - Date.now())));
      if (row.snapshotId === null || row.manifestSha256 === null) throw new Error();
      const snapshot: SubscriptionSnapshot = { id: row.id, generation: row.generation, snapshotId: row.snapshotId,
        manifestSha256: row.manifestSha256, nodeCount: row.nodeCount };
      const preview: string[] = [];
      for await (const node of readSnapshotNodes(bucket, snapshot, signal)) {
        preview.push(displayTelegramName(typeof node.name === "string" ? node.name : typeof node.tag === "string" ? node.tag : ""));
        if (preview.length === PREVIEW_NODES) break;
      }
      if (signal.aborted || preview.length !== Math.min(PREVIEW_NODES, row.nodeCount)) throw new Error();
      lines.push("节点预览", ...preview.map((name) => `• ${name}`));
      if (row.nodeCount > PREVIEW_NODES) lines.push(`仅展示前 ${PREVIEW_NODES} 个节点名称。`);
      for (const format of Object.keys(FORMAT_LABELS) as Format[]) {
        readButtons.push({ text: FORMAT_LABELS[format], kind: "format", subscriptionId: row.id, format });
      }
      if (nodePagesEnabled) nodeButtons.push({ ...snapshot, lifecycleRevision: row.lifecycleRevision, pageOffset: 0, text: "浏览全部节点" });
      if (rawFileEnabled) rawFileTarget = { ...snapshot, lifecycleRevision: row.lifecycleRevision };
    } catch {
      lines.push("暂时无法读取节点预览。");
    }
  } else {
    lines.push("当前没有已发布的节点。");
  }
  const refreshTarget = await providerRefreshTarget(row, row.sourceUrl);
  return { text: lines.join("\n"), readButtons, refreshTarget, rawFileTarget,
    readGuard: subscriptionGuard(guard, row, undefined, refreshTarget ? row.sourceUrl : null),
    ...(nodeButtons.length ? { nodeButtons } : {}) };
}

async function renderFormat(db: D1Database, bucket: R2Bucket, row: Metadata, format: Format, guard: Guard, deadline: number): Promise<RenderedRead> {
  const baseGuard = subscriptionGuard(guard, row);
  if (row.generation === 0) return { text: "当前没有已发布的节点。", readGuard: baseGuard };
  if (!row.token || !TOKEN.test(row.token) || !Object.hasOwn(FORMAT_LABELS, format)) {
    return { text: "暂时无法生成此格式的订阅链接。", readGuard: baseGuard };
  }
  if (format === "base64" || format === "singbox") {
    try {
      const signal = AbortSignal.timeout(Math.max(1, Math.min(READ_BUDGET_MS, deadline - Date.now())));
      const source = await getSubscriptionNodeSource(db, bucket, row.token);
      if (!source || signal.aborted) throw new Error();
      if (format === "base64") await planBase64(source, signal);
      else await planSingBox(source, signal);
    } catch (error) {
      const unsupported = error instanceof ExportContentError || error instanceof SingBoxContentError || error instanceof PathRuleContentError;
      return { text: unsupported ? "订阅内容不支持此格式。" : "暂时无法验证此格式，请稍后重试。", readGuard: baseGuard };
    }
  }
  return { text: `${FORMAT_LABELS[format]}\n${TELEGRAM_AGGREGATE_ORIGIN}/sub/${row.token}/${format}`,
    readGuard: subscriptionGuard(guard, row, row.token) };
}

export async function renderTelegramSubscriptionRead(
  db: D1Database, bucket: R2Bucket, policy: TelegramPolicy, lease: ReadLease, deadline: number, nodePagesEnabled = false,
  providerRefreshEnabled = false, rawFileEnabled = false,
): Promise<RenderedRead> {
  const guard = receiptGuard(policy);
  try {
    const receipt = await db.prepare(`SELECT action.kind,action.subscription_id AS subscriptionId,action.format,
        action.search_receipt_id AS searchReceiptId,action.search_offset AS searchOffset
      FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
      JOIN telegram_subscription_read AS action USING(receipt_id)
      WHERE ${leaseScopeSql("leased")} AND (${guard.sql})`)
      .bind(...leaseScopeArgs(policy, lease), ...guard.bindings).first<Receipt>();
    if (!receipt || receipt.kind === "stale") return { text: "订阅或授权状态已变更，请重新查询。" };
    if (receipt.kind === "usage") return { text: "用法：/s 关键词", readGuard: guard };
    if (receipt.kind === "limit") return { text: "查询达到处理上限，请缩短关键词或从 /list 选择订阅。", readGuard: guard };
    if (receipt.kind === "missing") return { text: "编号不存在。", readGuard: guard };
    if (receipt.kind === "search") return await renderSearch(db, policy, lease, receipt, guard);
    if (!privateScope(lease)) return { text: "请在私聊查看订阅详情。" };
    const row = await db.prepare(`SELECT id,name,expire_at AS expireAt,traffic_used AS trafficUsed,traffic_total AS trafficTotal,
      (last_error IS NOT NULL) AS refreshFailed,generation,${SUBSCRIPTION_LIFECYCLE_REVISION} AS lifecycleRevision,
      node_count AS nodeCount,snapshot_id AS snapshotId,manifest_sha256 AS manifestSha256,
      ${receipt.kind === "format" ? "token" : "NULL"} AS token,
      ${providerRefreshEnabled && receipt.kind === "detail" ? "source_url" : "NULL"} AS sourceUrl
      FROM subscriptions WHERE id=? AND owner_id=?`).bind(receipt.subscriptionId, lease.actorId).first<Metadata>();
    if (!row) return { text: "订阅不存在或已被删除。", readGuard: guard };
    if (receipt.kind === "detail") return await renderDetail(bucket, row, guard, deadline, nodePagesEnabled, rawFileEnabled);
    if (receipt.format) return await renderFormat(db, bucket, row, receipt.format, guard, deadline);
  } catch {
    // Do not expose source URLs, node data, tokens or D1/R2 diagnostics.
    throw new Error("Telegram subscription read reply could not be rendered.");
  }
  return { text: "订阅操作已失效。" };
}

export async function prepareTelegramSubscriptionReadTickets(buttons: readonly TelegramSubscriptionReadButton[]): Promise<{
  keyboard: { text: string; callback_data: string }[][];
  tickets: TelegramSubscriptionReadTicket[];
}> {
  if (buttons.length > MAX_BUTTONS) throw new RangeError("Too many Telegram subscription read buttons.");
  const entries = await Promise.all(buttons.map(async ({ text, ...target }) => {
    const raw = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
    const token = "sbr1_" + raw.replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
    return { button: { text, callback_data: token }, ticket: { ...target, sha256: await digestTicket(token) } };
  }));
  return { keyboard: entries.map(({ button }) => [button]), tickets: entries.map(({ ticket }) => ticket) };
}

export function insertTelegramSubscriptionReadTickets(
  db: D1Database, lease: ReadLease, tickets: readonly TelegramSubscriptionReadTicket[], previousChanges: number, nodePageOrigin = false,
): D1PreparedStatement {
  if (!validInteger(tickets.length, 1, MAX_BUTTONS) || !validInteger(previousChanges, 1, 16)) {
    throw new RangeError("Invalid Telegram subscription read ticket count.");
  }
  return db.prepare(`WITH tickets (sha256,kind,subscription_id,format,search_receipt_id,search_offset) AS (
    VALUES ${tickets.map(() => "(?,?,?,?,?,?)").join(",")}
  ) INSERT INTO telegram_subscription_read_ticket
    (token_sha256,origin_receipt_id,origin_attempt,kind,subscription_id,format,search_receipt_id,search_offset,expires_at)
    SELECT ticket.sha256,inbox.receipt_id,reply.attempts,
      CASE WHEN ((inbox.receipt_nonce=? AND ticket.kind='detail') OR inbox.receipt_nonce=?
        ${nodePageOrigin ? `OR (inbox.receipt_nonce='${TELEGRAM_SUBSCRIPTION_NODE_MARKER}' AND ticket.kind='detail'
          AND EXISTS (SELECT 1 FROM telegram_subscription_node_page AS page
            WHERE page.receipt_id=inbox.receipt_id AND page.subscription_id=ticket.subscription_id))` : ""})
        AND (ticket.kind='search' OR (inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL))
        THEN ticket.kind END,
      ticket.subscription_id,ticket.format,ticket.search_receipt_id,ticket.search_offset,unixepoch()+${TICKET_SECONDS}
    FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id) CROSS JOIN tickets AS ticket
    WHERE changes()=? AND reply.receipt_id=? AND reply.lease_id=? AND reply.attempts=? AND reply.state='sending'`)
    .bind(...tickets.flatMap((ticket) => [ticket.sha256, ticket.kind, "subscriptionId" in ticket ? ticket.subscriptionId : null,
      ticket.kind === "format" ? ticket.format : null, ticket.kind === "search" ? ticket.searchReceiptId : null,
      ticket.kind === "search" ? ticket.searchOffset : null]),
    TELEGRAM_VIEW_MARKER, TELEGRAM_SUBSCRIPTION_READ_MARKER, previousChanges, lease.receiptId, lease.leaseId, lease.attempts);
}

export async function reapTelegramSubscriptionReadTickets(db: D1Database): Promise<void> {
  try {
    const result = await db.prepare(`DELETE FROM telegram_subscription_read_ticket WHERE token_sha256 IN (
      SELECT token_sha256 FROM telegram_subscription_read_ticket WHERE expires_at<=unixepoch()
      ORDER BY expires_at,token_sha256 LIMIT 40)`).run();
    if (result.success) return;
  } catch {
    // D1 errors may include private state.
  }
  throw new Error("Telegram subscription read ticket cleanup could not be confirmed.");
}

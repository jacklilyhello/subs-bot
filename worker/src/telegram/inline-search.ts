import { trimPathRuleWhitespace } from "../path-rules.ts";
import { digestHex, SUBSCRIPTION_LIFECYCLE_REVISION, validInteger } from "../storage.ts";
import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { activeInlineConsent, GENERAL_INLINE_CONSENT_MARKER, GENERAL_INLINE_TEMP_CONSENT_MARKER, inlineSearchReceiptFamily,
  TELEGRAM_INLINE_CONSENT_MARKER, TELEGRAM_INLINE_TEMP_CONSENT_MARKER } from "./inline-search-consent.ts";
import { readTelegramInlineTempNodes } from "./inline-temp-nodes.ts";
import type { TelegramBotCredentials, TelegramInlineQuery, TelegramInlineSortMode, TelegramPolicy } from "./protocol.ts";
import { unicode14Lower } from "./selected-search.ts";
import { displayTelegramName } from "./views.ts";

const MAX_RESULTS = 50;
const MAX_SCAN_ROWS = 512;
const MAX_SCAN_BYTES = 8 * 1024 * 1024;
const PAGE_SIZE = 16;
const SCAN_MS = 2_000;
const LEASE_SECONDS = 8;
const ANSWER_SECONDS = 3;
const QUERY_LIMIT_PER_MINUTE = 12;
const RETENTION_SECONDS = 25 * 60 * 60;
const REAP_LIMIT = 64;
const encoder = new TextEncoder();

export type InlineSearchArticle = {
  type: "article";
  id: string;
  title: string;
  description?: string;
  input_message_content: { message_text: string; link_preview_options: { is_disabled: true } };
};
export type InlineSearchOutcome = "sent" | "failed" | "uncertain";
type SendAnswer = (policy: TelegramBotCredentials, id: string, results: readonly InlineSearchArticle[], timeoutMs: number) => Promise<InlineSearchOutcome>;
type Row = { id: number; name: string; sourceUrl: string; generation: number; revision: number;
  trafficUsed: number | null; trafficTotal: number | null; expireAt: number | null };
type Match = Pick<Row, "id" | "name" | "trafficUsed" | "trafficTotal" | "expireAt">;
type Scan = { inventory: string; results: InlineSearchArticle[] };

function comparePythonNames(left: string, right: string): number {
  let i = 0;
  let j = 0;
  while (i < left.length && j < right.length) {
    const a = left.codePointAt(i)!;
    const b = right.codePointAt(j)!;
    if (a !== b) return a - b;
    i += a > 0xffff ? 2 : 1;
    j += b > 0xffff ? 2 : 1;
  }
  return left.length - right.length;
}

function order(mode: TelegramInlineSortMode, left: Match, right: Match): number {
  if (mode === "traffic") {
    const a = (left.trafficTotal ?? 0) - (left.trafficUsed ?? 0);
    const b = (right.trafficTotal ?? 0) - (right.trafficUsed ?? 0);
    if (a !== b) return a > b ? -1 : 1;
  } else if (mode === "expiry") {
    const expiry = (left.expireAt || 99_999_999_999) - (right.expireAt || 99_999_999_999);
    if (expiry !== 0) return expiry;
  } else if (mode === "name") {
    const name = comparePythonNames(left.name, right.name);
    if (name !== 0) return name;
  }
  return left.id - right.id;
}

async function scanOwned(db: D1Database, owner: string, needle: string, mode: TelegramInlineSortMode, deadline: number): Promise<Scan | null> {
  const inventory: (number | null)[][] = [];
  const matches: Match[] = [];
  let after = 0;
  let bytes = 0;
  for (;;) {
    if (Date.now() >= deadline) return null;
    const limit = Math.min(PAGE_SIZE, MAX_SCAN_ROWS - inventory.length + 1);
    const page = await db.prepare(`SELECT id,name,source_url AS sourceUrl,generation,${SUBSCRIPTION_LIFECYCLE_REVISION} AS revision,
      traffic_used AS trafficUsed,traffic_total AS trafficTotal,expire_at AS expireAt
      FROM subscriptions WHERE owner_id=? AND id>? ORDER BY id LIMIT ?`).bind(owner, after, limit).all<Row>();
    if (!page.success) throw new Error("Telegram inline search inventory is unavailable.");
    for (const row of page.results) {
      if (!validInteger(row.id, after + 1) || !validInteger(row.generation, 0) || !validInteger(row.revision, 0)
        || typeof row.name !== "string" || typeof row.sourceUrl !== "string"
        || (row.expireAt !== null && !Number.isSafeInteger(row.expireAt))
        || [row.trafficUsed, row.trafficTotal].some((value) => value !== null && !Number.isFinite(value))) {
        throw new Error("Invalid Telegram inline search inventory.");
      }
      after = row.id;
      bytes += encoder.encode(row.name).byteLength + encoder.encode(row.sourceUrl).byteLength;
      if (inventory.length === MAX_SCAN_ROWS || bytes > MAX_SCAN_BYTES || Date.now() >= deadline) return null;
      inventory.push([row.id, row.generation, row.revision, row.trafficUsed, row.trafficTotal, row.expireAt]);
      if (!needle || unicode14Lower(`${row.name} ${row.sourceUrl}`).includes(needle)) {
        matches.push({ id: row.id, name: row.name, trafficUsed: row.trafficUsed, trafficTotal: row.trafficTotal, expireAt: row.expireAt });
      }
    }
    if (page.results.length < limit) break;
  }
  matches.sort((left, right) => order(mode, left, right));
  if (Date.now() >= deadline) return null;
  return { inventory: JSON.stringify(inventory), results: matches.slice(0, MAX_RESULTS).map((row) => ({
    type: "article", id: crypto.randomUUID(), title: Array.from(displayTelegramName(row.name)).slice(0, 64).join(""),
    input_message_content: { message_text: "在此私聊发送 /list 或 /s 关键词查看订阅详情。", link_preview_options: { is_disabled: true } },
  })) };
}

const activeStates = "state IN ('preflight','sending')";
const expiredState = "CASE WHEN state='sending' THEN 'uncertain' ELSE 'dropped' END";
const requestKey = "request.bot_id=? AND request.update_id=? AND request.actor_id=? AND request.query_id_sha256=?";
const inventoryGuard = `(SELECT count(*) FROM subscriptions WHERE owner_id=request.actor_id)=json_array_length(?) AND NOT EXISTS (
  SELECT 1 FROM json_each(?) AS expected LEFT JOIN subscriptions AS sub
    ON sub.id=json_extract(expected.value,'$[0]') AND sub.owner_id=request.actor_id
  LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=sub.id
  WHERE sub.id IS NULL OR sub.generation<>json_extract(expected.value,'$[1]') OR COALESCE(lifecycle.revision,0)<>json_extract(expected.value,'$[2]')
    OR sub.traffic_used IS NOT json_extract(expected.value,'$[3]') OR sub.traffic_total IS NOT json_extract(expected.value,'$[4]')
    OR sub.expire_at IS NOT json_extract(expected.value,'$[5]'))`;

/** The authenticated request owns the raw query and answer ID until one bounded attempt ends. */
export async function answerTelegramInlineSearch(
  db: D1Database, policy: TelegramPolicy | GeneralTelegramPin, event: TelegramInlineQuery, send: SendAnswer,
): Promise<void> {
  const isolated = "adminId" in policy ? policy : null;
  const general = "privateManagement" in policy ? policy : null;
  if (event.chatType !== "sender" || !validInteger(event.updateId, 1)
    || (isolated ? event.actorId !== isolated.adminId && event.actorId !== isolated.memberId
      : !general?.privateInline || general.rehearsal || event.actorId === general.botId)) return;
  const query = trimPathRuleWhitespace(event.query);
  const needle = unicode14Lower(query);
  const shareQuery = /^share(?:\s|$)/u.test(needle);
  if (shareQuery && !general) return;
  const queryDigest = digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(event.queryId)));
  const key = [policy.botId, event.updateId, event.actorId, queryDigest] as const;
  const consent = activeInlineConsent(policy);
  let state: "new" | "preflight" | "sending" = "new";
  try {
    const [cleanup, admitted] = await db.batch<{ mode: TelegramInlineSortMode; consentMarker: string; receivedAt: number }>([
      db.prepare(`UPDATE telegram_inline_search_receipts AS request SET state=${expiredState}
        WHERE bot_id=? AND actor_id=? AND ${activeStates} AND lease_until<=unixepoch()
          AND (${inlineSearchReceiptFamily("request", Boolean(general))})`).bind(policy.botId, event.actorId),
      db.prepare(`INSERT INTO telegram_inline_search_receipts
        (bot_id,update_id,actor_id,query_id_sha256,consent_receipt_id,sort_mode,sort_update_id,received_at,lease_until,state)
        SELECT consent.bot_id,?,consent.actor_id,?,consent.receipt_id,COALESCE(pref.mode,'default'),COALESCE(pref.update_id,0),
          unixepoch(),unixepoch()+${LEASE_SECONDS},'preflight'
        FROM telegram_inline_search_consent AS consent LEFT JOIN telegram_inline_sort_preferences AS pref
          ON pref.bot_id=consent.bot_id AND pref.actor_id=consent.actor_id
        WHERE consent.bot_id=? AND consent.actor_id=? AND consent.update_id<? AND ${consent.sql}
          AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=consent.bot_id AND update_id=?)
          AND NOT EXISTS (SELECT 1 FROM telegram_inline_search_receipts WHERE bot_id=consent.bot_id AND actor_id=consent.actor_id
            AND received_at>unixepoch()-60 LIMIT 1 OFFSET ${QUERY_LIMIT_PER_MINUTE - 1})
        ON CONFLICT DO NOTHING RETURNING sort_mode AS mode, received_at AS receivedAt,
          (SELECT receipt_nonce FROM telegram_inbox WHERE receipt_id=telegram_inline_search_receipts.consent_receipt_id) AS consentMarker`)
        .bind(event.updateId, queryDigest, policy.botId, event.actorId,
        event.updateId, ...consent.bindings, event.updateId),
    ]);
    if (!cleanup?.success || !admitted?.success || admitted.results.length > 1) throw new Error();
    const receipt = admitted.results[0];
    if (!receipt) return;
    state = "preflight";
    const marker = receipt.consentMarker;
    const isolatedMarker = marker === TELEGRAM_INLINE_CONSENT_MARKER || marker === TELEGRAM_INLINE_TEMP_CONSENT_MARKER
      ? marker : undefined;
    const generalMarker = marker === GENERAL_INLINE_CONSENT_MARKER || marker === GENERAL_INLINE_TEMP_CONSENT_MARKER
      ? marker : undefined;
    if (general ? !generalMarker : !isolatedMarker) throw new Error();
    const sendConsent = activeInlineConsent(policy, general ? generalMarker : isolatedMarker);
    const deadline = Date.now() + SCAN_MS;
    const scan = shareQuery ? null : await scanOwned(db, event.actorId, needle, receipt.mode, deadline);
    const results: InlineSearchArticle[] = shareQuery ? [{ type: "article", id: crypto.randomUUID(), title: "在机器人私聊创建私密分享",
      input_message_content: { message_text: `请打开 @${policy.botUsername} 的私聊，发送 ${general?.privateShareCreation ? "/share" : "/help"} 查看可用的私密分享入口。`,
        link_preview_options: { is_disabled: true } } }] : scan?.results ?? [];
    const temp = (marker === TELEGRAM_INLINE_TEMP_CONSENT_MARKER || marker === GENERAL_INLINE_TEMP_CONSENT_MARKER)
      && scan && results.length < MAX_RESULTS
      ? await readTelegramInlineTempNodes(db, policy, event, needle, MAX_RESULTS - results.length, deadline, receipt.receivedAt) : undefined;
    if (temp === null) results.length = 0;
    else if (temp) results.push(...temp.results);
    const authorization = `EXISTS (SELECT 1 FROM telegram_inline_search_consent AS consent
      WHERE consent.receipt_id=request.consent_receipt_id AND consent.bot_id=request.bot_id
        AND consent.actor_id=request.actor_id AND consent.update_id<request.update_id AND (${sendConsent.sql}))`;
    const proof = general ? `WITH eligible AS MATERIALIZED (
      SELECT (${authorization}) AS allowed FROM telegram_inline_search_receipts AS request WHERE ${requestKey}
    )` : "";
    const prepared = `request.sort_mode=COALESCE((SELECT mode FROM telegram_inline_sort_preferences
          WHERE bot_id=request.bot_id AND actor_id=request.actor_id),'default')
        AND request.sort_update_id=COALESCE((SELECT update_id FROM telegram_inline_sort_preferences
          WHERE bot_id=request.bot_id AND actor_id=request.actor_id),0)
        ${scan ? `AND (${inventoryGuard})` : ""}
        ${temp ? `AND (${temp.guard.sql})` : ""}`;
    const preparedBindings = [...(scan ? [scan.inventory, scan.inventory] : []), ...(temp?.guard.bindings ?? [])];
    const begin = await db.prepare(`${proof} UPDATE telegram_inline_search_receipts AS request SET state='sending',result_count=?
      WHERE ${requestKey} AND request.state='preflight' AND request.lease_until>=unixepoch()+${ANSWER_SECONDS + 1}
        AND ${general ? "EXISTS (SELECT 1 FROM eligible WHERE allowed)" : authorization}
        AND (${prepared}) RETURNING update_id`)
      .bind(...(general ? [...sendConsent.bindings, ...key] : []), results.length, ...key,
        ...(general ? [] : sendConsent.bindings), ...preparedBindings).first();
    if (begin === null) {
      await finish(db, key, "preflight", "dropped");
      return;
    }
    state = "sending";
    const confirmed = await db.prepare(`${proof} SELECT 1 FROM telegram_inline_search_receipts AS request
      WHERE ${requestKey} AND request.state='sending' AND request.result_count=?
        AND request.lease_until>=unixepoch()+${ANSWER_SECONDS}
        AND ${general ? "EXISTS (SELECT 1 FROM eligible WHERE allowed)" : authorization} AND (${prepared})`)
      .bind(...(general ? [...sendConsent.bindings, ...key] : []), ...key, results.length,
        ...(general ? [] : sendConsent.bindings), ...preparedBindings).first();
    if (!confirmed) { await finish(db, key, "sending", "dropped"); return; }
    const outcome = await send(policy, event.queryId, results, ANSWER_SECONDS * 1_000);
    await finish(db, key, "sending", outcome);
  } catch {
    if (state !== "new") {
      await finish(db, key, state, state === "sending" ? "uncertain" : "dropped").catch(() => undefined);
    }
    throw new Error("Telegram inline search could not be confirmed.");
  }
}

async function finish(
  db: D1Database, key: readonly (string | number)[], from: "preflight" | "sending", outcome: InlineSearchOutcome | "dropped",
): Promise<void> {
  const result = await db.prepare(`UPDATE telegram_inline_search_receipts AS request SET state=? WHERE ${requestKey}
    AND (request.state=? OR (?='sent' AND request.state='uncertain'))`).bind(outcome, ...key, from, outcome).run();
  if (!result.success) throw new Error("Telegram inline search outcome could not be stored.");
}

export async function reapTelegramInlineSearch(db: D1Database, botId: string, general = false): Promise<void> {
  const family = inlineSearchReceiptFamily("request", general);
  const results = await db.batch([
    db.prepare(`UPDATE telegram_inline_search_receipts AS request SET state=${expiredState}
      WHERE bot_id=? AND ${activeStates} AND lease_until<=unixepoch() AND (${family})`).bind(botId),
    db.prepare(`DELETE FROM telegram_inline_search_receipts WHERE bot_id=? AND update_id IN (
      SELECT update_id FROM telegram_inline_search_receipts AS request WHERE bot_id=? AND received_at<=unixepoch()-${RETENTION_SECONDS}
        AND NOT (${activeStates}) AND (${family}) ORDER BY received_at,update_id LIMIT ${REAP_LIMIT})`).bind(botId, botId),
  ]);
  if (results.length !== 2 || results.some(({ success }) => !success)) throw new Error("Telegram inline search cleanup could not be confirmed.");
}

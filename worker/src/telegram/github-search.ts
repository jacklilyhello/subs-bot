import type { GeneralTelegramPin } from "./general-auth-runtime.ts";
import { generalPrivateScope, prepareGeneralPrivateAdmission } from "./general-private-admission.ts";
import { generalCurrentAuthoritySql, generalPolicyBindings, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { validInteger } from "../storage.ts";
import { grepCodeContent, type GrepSearchObservation } from "./grep-search.ts";
import { inTelegramScope, type TelegramGitHubSearchUpdate, type TelegramPolicy } from "./protocol.ts";

export const TELEGRAM_GITHUB_SEARCH_MARKER = "github-search:v1";
export const GENERAL_GITHUB_SEARCH_MARKER = "general-github-search:v1";
type Policy = TelegramPolicy | GeneralTelegramPin;
const generalPolicy = (policy: Policy): policy is GeneralTelegramPin => "privateManagement" in policy;
export const TELEGRAM_GITHUB_SEARCH_MIGRATION = "0027_telegram_github_search.sql";
export const TELEGRAM_GITHUB_SEARCH_SCHEMA_SHA256 = "189751e07f92b8616de22cfc8593e642426fb6a074be52f09b635e31efe8a0d4";

const LOOKUP_SECONDS = 12;
const COOLDOWN_SECONDS = 15;
const LOOKUP_TIMEOUT_MS = 5000;
const CODE_LOOKUP_TIMEOUT_MS = 8000;
const MAX_REPLY_AGE_SECONDS = 900;
const REAP_LIMIT = 16;
const MAX_REPOSITORIES = 5;
const MAX_CODE_MATCHES = 2;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_PROJECTION_BYTES = 1024;
const GITHUB_API = "https://api.github.com/search/repositories";
const GITHUB_HEADERS = { Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10",
  "User-Agent": "subs-bot-public-search/1.0" };
const GITHUB_BROWSER = "https://github.com/search?type=code";
const GITHUB_ORIGIN = "https://github.com";
const OWNER = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u;
const REPOSITORY = /^[A-Za-z0-9_.-]{1,100}$/u;
const KEYWORD = /^[\p{L}\p{M}\p{N}_.+#-]+$/u;
const NON_TEXT = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029]/u;
const FRESH_INBOX = "inbox.bot_id = ? AND inbox.update_id = ? AND inbox.receipt_nonce = ?";

type InboxAlias = "inbox" | "earlier";
type ReplyState = "usage" | "limited" | "found" | "empty" | "unavailable";
export type TelegramGitHubReply = { state: ReplyState; publicResults: string | null };
type Repository = { name: string; stars: number };
type RepositorySearch = { state: "found" | "empty" | "unavailable"; repos: Repository[] };
type CodeMatch = { repo: string; ref: string; path: string };
type CodeSearch = { files: CodeMatch[]; verificationUnavailable: boolean };
type SearchBudget = { blocked: boolean };
type Admission = { kind: "ignored" | "reply" } | { kind: "lookup"; receiptId: number; nonce: string; query: string };
type Receipt = { receiptId: number; state: "looking" | "usage" | "limited" };

interface VisibilityObservation {
  status: number | null;
  outcome: "pending" | "public" | "unconfirmed" | "deadline" | "transport-or-body";
}

export interface GitHubSearchObservation {
  remainingMs: number;
  repositoryStatus: number | null;
  repositoryState: RepositorySearch["state"] | null;
  grep: GrepSearchObservation;
  candidates: number;
  codeTimedOut: boolean;
  visibility: VisibilityObservation[];
  verifiedFiles: number;
  settled: ReplyState | null;
}

export function newGitHubSearchObservation(): GitHubSearchObservation {
  return { remainingMs: 0, repositoryStatus: null, repositoryState: null,
    grep: { phase: "not-started", initializeStatus: null, initializedStatus: null, toolStatus: null, timedOut: false, contentBlocks: 0 },
    candidates: 0, codeTimedOut: false, visibility: [], verifiedFiles: 0, settled: null };
}


function record(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : null;
}

function repositoryName(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const [owner, name, ...extra] = value.split("/");
  return extra.length === 0 && OWNER.test(owner) && typeof name === "string"
    && REPOSITORY.test(name) && name !== "." && name !== ".." && !NON_TEXT.test(value);
}

export function normalizeGitHubSearchQuery(raw: string): string | null {
  if (raw.length > 256 || NON_TEXT.test(raw)) return null;
  const query = raw.trim().replace(/ +/gu, " ");
  if (query.length === 0 || [...query].length > 120 || new TextEncoder().encode(query).byteLength > 256) return null;
  let keyword = false;
  for (const token of query.split(" ")) {
    if (KEYWORD.test(token) && /[\p{L}\p{N}]/u.test(token) && !/^(?:and|or|not)$/iu.test(token)) {
      keyword = true;
      continue;
    }
    const [field, value, ...extra] = token.split(":");
    if (extra.length || !value) return null;
    switch (field) {
      case "user":
      case "org":
        if (!OWNER.test(value)) return null;
        break;
      case "repo":
        if (!repositoryName(value)) return null;
        break;
      case "in":
        if (!/^(?:name|description|readme)(?:,(?:name|description|readme))*$/u.test(value)) return null;
        break;
      case "language":
      case "topic":
        if (!KEYWORD.test(value)) return null;
        break;
      default:
        return null;
    }
  }
  return keyword ? query : null;
}

export async function telegramGitHubSearchReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE
      (type = 'table' AND name = 'subs_bot_schema_migrations') OR (tbl_name = 'telegram_github_search' AND (
        (type = 'table' AND name = 'telegram_github_search') OR
        (type = 'index' AND name IN ('telegram_github_search_cooldown', 'telegram_github_search_expiring',
          'telegram_github_search_recovery', 'telegram_github_search_payload'))))`).first<{ present: number }>();
    if (row) {
      if (row.present !== 6) return false;
      const ledger = await db.prepare("SELECT position, sha256, mode FROM subs_bot_schema_migrations WHERE name = ?")
        .bind(TELEGRAM_GITHUB_SEARCH_MIGRATION).first<{ position: number; sha256: string; mode: string }>();
      return ledger?.position === 27 && ledger.sha256 === TELEGRAM_GITHUB_SEARCH_SCHEMA_SHA256 && ledger.mode === "applied";
    }
  } catch {
    // Absence of the additive migration and a database failure have different webhook behavior.
  }
  throw new Error("Telegram GitHub search schema could not be confirmed.");
}

function privateReceipt(alias: InboxAlias, general = false): string {
  return `${alias}.receipt_nonce = '${general ? GENERAL_GITHUB_SEARCH_MARKER : TELEGRAM_GITHUB_SEARCH_MARKER}' AND ${alias}.command = 'help'
    AND ${alias}.chat_type = 'private' AND ${alias}.actor_id = ${alias}.chat_id AND ${alias}.thread_id IS NULL`;
}

function ownSearch(alias: InboxAlias): string {
  return `search.receipt_id = ${alias}.receipt_id AND search.bot_id = ${alias}.bot_id AND search.actor_id = ${alias}.actor_id`;
}

function epoch(policy: Policy, alias: InboxAlias = "inbox") {
  if (generalPolicy(policy)) return { sql: `search.auth_message_date=0 AND search.auth_message_id=0 AND ${generalCurrentAuthoritySql(alias)}`,
    bindings: generalPolicyBindings(policy) };
  return { sql: `((${alias}.actor_id = ? AND search.auth_message_date = 0 AND search.auth_message_id = 0)
    OR (${alias}.actor_id = ? AND ${alias}.message_date > search.auth_message_date
      AND COALESCE((SELECT allowed = 1 AND message_date = search.auth_message_date AND message_id = search.auth_message_id
        FROM telegram_auth WHERE bot_id = ${alias}.bot_id AND user_id = ${alias}.actor_id),
        search.auth_message_date = 0 AND search.auth_message_id = 0)))`,
  bindings: [policy.adminId, policy.memberId] };
}

const REPLY_READY = "search.state IN ('usage', 'limited', 'found', 'empty', 'unavailable')";

export function telegramGitHubSearchMarker(alias: InboxAlias, general = false): string {
  return `(${privateReceipt(alias, general)} AND EXISTS (
    SELECT 1 FROM telegram_github_search AS search WHERE ${ownSearch(alias)} AND ${REPLY_READY}))`;
}

export function telegramGitHubSearchEligible(policy: TelegramPolicy | undefined, alias: InboxAlias) {
  if (!policy) return { sql: "1", bindings: [] };
  const current = epoch(policy, alias);
  return { sql: `(${alias}.receipt_nonce IS NOT '${TELEGRAM_GITHUB_SEARCH_MARKER}' OR EXISTS (
    SELECT 1 FROM telegram_github_search AS search WHERE ${ownSearch(alias)} AND ${current.sql}))`,
  bindings: current.bindings };
}

export function telegramGitHubSendGuard(policy: Policy, reply: TelegramGitHubReply) {
  const current = epoch(policy);
  return { sql: `EXISTS (SELECT 1 FROM telegram_github_search AS search
    WHERE ${ownSearch("inbox")} AND search.state = ? AND search.public_results IS ? AND ${current.sql})`,
  bindings: [reply.state, reply.publicResults, ...current.bindings] };
}

export async function acceptTelegramGitHubSearch(
  db: D1Database, policy: Policy, event: TelegramGitHubSearchUpdate,
): Promise<Admission> {
  const general = generalPolicy(policy) ? policy : null;
  if (!(general ? general.privateGitHub && generalPrivateScope(general, event) : inTelegramScope(policy as TelegramPolicy, event)) || event.chatType !== "private" || event.threadId !== null
    || !validInteger(event.updateId, 1) || !validInteger(event.messageId, 1) || !validInteger(event.messageDate, 1)) {
    return { kind: "ignored" };
  }
  const query = normalizeGitHubSearchQuery(event.args);
  const nonce = crypto.randomUUID();
  const key = [policy.botId, event.updateId, nonce] as const;
  try {
    const statements = [
      ...(general ? [prepareGeneralPrivateAdmission(db, general, event, nonce), prepareGeneralReceiptAuthority(db, general, key)] : [db.prepare(`INSERT INTO telegram_inbox
        (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
        SELECT ?, ?, ?, ?, 'private', ?, ?, NULL, 'help', ?
        WHERE ? BETWEEN unixepoch() - 300 AND unixepoch() + 30
          AND (? = ? OR COALESCE((SELECT allowed = 1 AND message_date < ? FROM telegram_auth
            WHERE bot_id = ? AND user_id = ?), 1))
        ON CONFLICT (bot_id, update_id) DO NOTHING`).bind(
        policy.botId, event.updateId, event.actorId, event.chatId, event.messageId, event.messageDate, nonce,
        event.messageDate, event.actorId, (policy as TelegramPolicy).adminId, event.messageDate, policy.botId, event.actorId)]),
      db.prepare(`WITH admitted AS (
        SELECT inbox.receipt_id, inbox.bot_id, inbox.actor_id,
          ${general ? "0" : "COALESCE(auth.message_date, 0)"} AS grant_date, ${general ? "0" : "COALESCE(auth.message_id, 0)"} AS grant_id,
          CASE WHEN ? = 0 THEN 'usage' WHEN EXISTS (
            SELECT 1 FROM telegram_github_search AS prior WHERE prior.bot_id = inbox.bot_id
              AND prior.actor_id = inbox.actor_id AND prior.started_at > unixepoch() - ${COOLDOWN_SECONDS}
          ) THEN 'limited' ELSE 'looking' END AS next_state
        FROM telegram_inbox AS inbox
        LEFT JOIN telegram_auth AS auth ON auth.bot_id = inbox.bot_id AND auth.user_id = inbox.actor_id
          AND inbox.actor_id <> ?
        WHERE ${FRESH_INBOX}
      ) INSERT INTO telegram_github_search (receipt_id, bot_id, actor_id, state, auth_message_date, auth_message_id,
          started_at, lookup_nonce, lookup_until)
        SELECT receipt_id, bot_id, actor_id, next_state, grant_date, grant_id,
          CASE WHEN next_state = 'looking' THEN unixepoch() END,
          CASE WHEN next_state = 'looking' THEN ? END,
          CASE WHEN next_state = 'looking' THEN unixepoch() + ${LOOKUP_SECONDS} END
        FROM admitted`).bind(query === null ? 0 : 1, general ? "" : (policy as TelegramPolicy).adminId, ...key, nonce),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_github_search AS search USING (receipt_id)
        WHERE ${FRESH_INBOX} AND search.state IN ('usage', 'limited')`).bind(...key),
      db.prepare(`SELECT inbox.receipt_id AS receiptId, search.state FROM telegram_inbox AS inbox
        JOIN telegram_github_search AS search USING (receipt_id) WHERE ${FRESH_INBOX}`).bind(...key),
      db.prepare(`UPDATE telegram_inbox AS inbox SET receipt_nonce = ? WHERE ${FRESH_INBOX}`)
        .bind(general ? GENERAL_GITHUB_SEARCH_MARKER : TELEGRAM_GITHUB_SEARCH_MARKER, ...key),
    ];
    const result = await db.batch<Receipt>(statements);
    const offset = general ? 1 : 0;
    const row = result[3 + offset]?.results[0];
    if (result.length !== statements.length || result.some(({ success }) => !success)) throw new Error();
    if (result[0].meta.changes === 0 && !row && result[4 + offset].meta.changes === 0) return { kind: "ignored" };
    if (result[0].meta.changes !== 1 || result[1 + offset].meta.changes !== 1 || result[4 + offset].meta.changes !== 1 || !row) throw new Error();
    if (row.state === "looking" && query !== null && result[2 + offset].meta.changes === 0) {
      return { kind: "lookup", receiptId: row.receiptId, nonce, query };
    }
    if ((row.state === "usage" || row.state === "limited") && result[2 + offset].meta.changes === 1) return { kind: "reply" };
  } catch {
    // Never propagate SQL, query text or request information from this boundary.
  }
  throw new Error("Telegram GitHub search receipt could not be confirmed.");
}

async function readGitHubResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get("Content-Type");
  const length = response.headers.get("Content-Length");
  if (response.status !== 200 || response.redirected || !response.body
    || !/^application\/(?:json|vnd\.github\+json)(?:\s*;|$)/iu.test(contentType ?? "")
    || (length !== null && (!/^\d+$/u.test(length) || Number(length) > MAX_RESPONSE_BYTES))) {
    void response.body?.cancel().catch(() => {});
    return null;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  let total = 0;
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        void reader.cancel().catch(() => {});
        return null;
      }
      text += decoder.decode(value, { stream: true });
    }
    return JSON.parse(text + decoder.decode()) as unknown;
  } catch (error) {
    void reader.cancel().catch(() => {});
    throw error;
  } finally {
    reader.releaseLock();
  }
}

function observeSearchBudget(response: Response, budget: SearchBudget): void {
  if (response.status === 403 || response.status === 429 || response.headers.has("Retry-After")
    || response.headers.get("X-RateLimit-Remaining") === "0") budget.blocked = true;
}

async function searchPublicRepositories(query: string, request: typeof fetch, timeoutMs: number, budget: SearchBudget,
  observation?: GitHubSearchObservation): Promise<RepositorySearch> {
  const unavailable: RepositorySearch = { state: "unavailable", repos: [] };
  try {
    const url = new URL(GITHUB_API);
    url.search = new URLSearchParams({ q: `${query} is:public`, sort: "stars", order: "desc", per_page: "5" }).toString();
    const response = await request(url, {
      method: "GET", redirect: "manual", signal: AbortSignal.timeout(timeoutMs), cache: "no-store", headers: GITHUB_HEADERS,
    });
    observeSearchBudget(response, budget);
    if (observation) observation.repositoryStatus = response.status;
    const data = record(await readGitHubResponse(response));
    if (!data || !Array.isArray(data.items) || data.items.length > MAX_REPOSITORIES) return unavailable;
    const repos: Repository[] = [];
    const seen = new Set<string>();
    for (const raw of data.items) {
      const item = record(raw);
      if (!item || item.private !== false || (item.visibility !== undefined && item.visibility !== "public")
        || !repositoryName(item.full_name) || item.html_url !== `${GITHUB_ORIGIN}/${item.full_name}`
        || !validInteger(item.stargazers_count, 0)) continue;
      const key = item.full_name.toLowerCase();
      if (seen.has(key)) continue;
      seen.add(key);
      repos.push({ name: item.full_name, stars: item.stargazers_count });
    }
    if (!repos.length) return data.items.length === 0 && data.incomplete_results === false
      ? { state: "empty", repos } : unavailable;
    return { state: "found", repos };
  } catch {
    return unavailable;
  }
}

function codeQuery(query: string): { query: string; repo?: string } | null {
  const terms: string[] = [];
  let repo: string | undefined;
  for (const token of query.split(" ")) {
    if (!token.includes(":")) terms.push(token);
    else if (token.startsWith("repo:") && repo === undefined && repositoryName(token.slice(5))) repo = token.slice(5);
    else return null; // A repository-only qualifier must not broaden the code search.
  }
  return terms.length ? { query: terms.join(" "), repo } : null;
}

function codeMatch(value: unknown): CodeMatch | null {
  const item = record(value);
  if (!item || !repositoryName(item.repo) || typeof item.ref !== "string" || typeof item.path !== "string"
    || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}(?![\s\S])/u.test(item.ref)
    || !/^[A-Za-z0-9_./-]{1,160}(?![\s\S])/u.test(item.path)
    || item.path.split("/").some((part) => part === "" || part === "." || part === "..")) return null;
  return { repo: item.repo, ref: item.ref, path: item.path };
}

function codeUrl({ repo, ref, path }: CodeMatch): string {
  return `${GITHUB_ORIGIN}/${repo}/blob/${ref}/${path}`;
}

function grepMatch(raw: unknown, repoFilter: string | undefined): CodeMatch | null {
  const item = record(raw);
  if (item?.type !== "text" || typeof item.text !== "string") return null;
  // Only read the leading metadata, even when a snippet contains the same labels.
  const match = /^Repository: ([^\r\n]+)\r?\nPath: ([^\r\n]+)\r?\nURL: ([^\r\n]+)\r?\nLicense: [^\r\n]*\r?\n(?:\r?\n){0,2}Snippets:(?:\r?\n|$)/u.exec(item.text);
  if (!match) return null;
  const [, repo, path, url] = match;
  if (!repositoryName(repo) || (repoFilter && repo.toLowerCase() !== repoFilter.toLowerCase())) return null;
  const prefix = `${GITHUB_ORIGIN}/${repo}/blob/`;
  if (!url.startsWith(prefix) || !url.endsWith(`/${path}`)) return null;
  const candidate = codeMatch({ repo, path, ref: url.slice(prefix.length, -(path.length + 1)) });
  return candidate && url === codeUrl(candidate) ? candidate : null;
}

async function verifyPublicRepository(repo: string, request: typeof fetch, signal: AbortSignal, budget: SearchBudget,
  observation?: GitHubSearchObservation): Promise<boolean> {
  const check: VisibilityObservation = { status: null, outcome: "pending" };
  observation?.visibility.push(check);
  try {
    const url = new URL(GITHUB_API);
    url.search = new URLSearchParams({ q: `repo:${repo} is:public fork:true`, per_page: "1" }).toString();
    const response = await request(url, { method: "GET", redirect: "manual", cache: "no-store", signal, headers: GITHUB_HEADERS });
    observeSearchBudget(response, budget);
    check.status = response.status;
    const data = record(await readGitHubResponse(response));
    if (signal.aborted) {
      check.outcome = "deadline";
      return false;
    }
    const item = data?.total_count === 1 && data.incomplete_results === false && Array.isArray(data.items) && data.items.length === 1
      ? record(data.items[0]) : null;
    const confirmed = item?.private === false && item.visibility === "public" && item.full_name === repo
      && item.html_url === `${GITHUB_ORIGIN}/${repo}`;
    check.outcome = confirmed ? "public" : "unconfirmed";
    return confirmed;
  } catch {
    check.outcome = signal.aborted ? "deadline" : "transport-or-body";
    return false;
  }
}

async function searchPublicCode(query: string, request: typeof fetch, signal: AbortSignal,
  stillAuthorized: () => Promise<boolean>, repositories: Promise<RepositorySearch>, budget: SearchBudget,
  observation?: GitHubSearchObservation): Promise<CodeSearch> {
  const empty: CodeSearch = { files: [], verificationUnavailable: false };
  const code = codeQuery(query);
  if (!code || signal.aborted) return empty;
  const publicFromSearch = new Set<string>();
  const repositoryProof = repositories.then(({ repos }) => {
    for (const { name } of repos) publicFromSearch.add(name);
  });
  const matches = new Map<string, CodeMatch>();
  for (const item of await grepCodeContent(request, signal, code.query, code.repo, stillAuthorized, observation?.grep)) {
    const candidate = grepMatch(item, code.repo);
    if (candidate) matches.set(codeUrl(candidate), candidate);
    if (matches.size === MAX_CODE_MATCHES) break;
  }
  if (observation) observation.candidates = matches.size;
  if (!matches.size) return empty;
  const verified = new Set<string>();
  const codeMatches = [...matches.values()];
  // Start the exact checks even while keyword search is pending. Keep the
  // checks serial so a throttle can stop the remaining candidate lookup.
  for (const repo of new Set(codeMatches.map(({ repo }) => repo))) {
    if (signal.aborted || budget.blocked) break;
    if (!publicFromSearch.has(repo) && await verifyPublicRepository(repo, request, signal, budget, observation)) verified.add(repo);
  }
  await repositoryProof;
  const files = codeMatches.filter(({ repo }) => verified.has(repo) || publicFromSearch.has(repo));
  return { files, verificationUnavailable: files.length !== codeMatches.length };
}

function packSearchReply(repositorySearch: RepositorySearch, { files, verificationUnavailable }: CodeSearch): TelegramGitHubReply {
  const { state, repos } = repositorySearch;
  for (let count = files.length; count > 0; count--) {
    const publicResults = JSON.stringify({ v: 2, repos, code: files.slice(0, count) });
    // Both repository names and accepted file metadata are ASCII.
    if (publicResults.length <= MAX_PROJECTION_BYTES) return { state: "found", publicResults };
  }
  if (state !== "found") return { state: verificationUnavailable ? "unavailable" : state, publicResults: null };
  const publicResults = JSON.stringify(repos);
  return publicResults.length <= MAX_PROJECTION_BYTES ? { state, publicResults } : { state: "unavailable", publicResults: null };
}

/** The winning webhook owns the ephemeral query. A recovered lookup sends the fixed fallback instead of replaying egress. */
export async function runTelegramGitHubSearch(
  db: D1Database, policy: Policy, admission: Extract<Admission, { kind: "lookup" }>,
  request: typeof fetch = fetch, observation?: GitHubSearchObservation,
): Promise<boolean> {
  const current = epoch(policy);
  const lookup = `SELECT 1 FROM telegram_inbox AS inbox
    WHERE inbox.bot_id = ? AND ${privateReceipt("inbox", generalPolicy(policy))} AND ${ownSearch("inbox")} AND ${current.sql}`;
  const active = `search.receipt_id = ? AND search.lookup_nonce = ? AND search.state = 'looking'
    AND search.lookup_until > unixepoch() AND EXISTS (${lookup})`;
  try {
    const fetchNonce = crypto.randomUUID();
    const claimed = await db.prepare(`UPDATE telegram_github_search AS search SET lookup_nonce = ?
      WHERE ${active} RETURNING receipt_id AS receiptId, lookup_until AS lookupUntil`)
      .bind(fetchNonce, admission.receiptId, admission.nonce, policy.botId, ...current.bindings)
      .first<{ receiptId: number; lookupUntil: number }>();
    if (claimed?.receiptId !== admission.receiptId) return false;
    const remaining = Math.min(CODE_LOOKUP_TIMEOUT_MS, claimed.lookupUntil * 1000 - Date.now() - 500);
    if (remaining <= 0) return false;
    if (observation) observation.remainingMs = remaining;
    const bindings = [admission.receiptId, fetchNonce, policy.botId, ...current.bindings];
    const stillAuthorized = async () => await db.prepare(`SELECT 1 FROM telegram_github_search AS search WHERE ${active}`)
      .bind(...bindings).first() !== null;
    const searchBudget: SearchBudget = { blocked: false };
    const repositorySearch = searchPublicRepositories(admission.query, request, Math.min(LOOKUP_TIMEOUT_MS, remaining), searchBudget, observation);
    const codeSignal = AbortSignal.timeout(remaining);
    const code = await searchPublicCode(admission.query, request, codeSignal, stillAuthorized, repositorySearch, searchBudget, observation);
    if (observation) {
      observation.codeTimedOut = codeSignal.aborted;
      observation.verifiedFiles = code.files.length;
    }
    const repository = await repositorySearch;
    if (observation) observation.repositoryState = repository.state;
    const result = packSearchReply(repository, code);
    const [updated, queued] = await db.batch([
      db.prepare(`UPDATE telegram_github_search AS search
        SET state = ?, public_results = ?, lookup_nonce = NULL, lookup_until = NULL WHERE ${active}`)
        .bind(result.state, result.publicResults, ...bindings),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT receipt_id FROM telegram_github_search WHERE receipt_id = ? AND changes() = 1`).bind(admission.receiptId),
    ]);
    if (!updated?.success || !queued?.success || updated.meta.changes !== queued.meta.changes) throw new Error();
    if (observation && queued.meta.changes === 1) observation.settled = result.state;
    return queued.meta.changes === 1;
  } catch {
    throw new Error("Telegram GitHub search completion could not be confirmed.");
  }
}

export async function recoverTelegramGitHubSearch(db: D1Database, policy: Policy): Promise<number> {
  const current = epoch(policy);
  const nonce = `recover:${crypto.randomUUID()}`;
  const candidate = "search.bot_id = ? AND search.state = 'looking' AND search.lookup_nonce = ?";
  try {
    const results = await db.batch([
      db.prepare(`UPDATE telegram_github_search SET lookup_nonce = ?
        WHERE receipt_id IN (SELECT receipt_id FROM telegram_github_search
          WHERE bot_id = ? AND state = 'looking' AND lookup_until <= unixepoch() AND EXISTS (
            SELECT 1 FROM telegram_inbox AS inbox WHERE inbox.receipt_id=telegram_github_search.receipt_id
              AND ${privateReceipt('inbox', generalPolicy(policy))})
          ORDER BY lookup_until, receipt_id LIMIT ${REAP_LIMIT})`).bind(nonce, policy.botId),
      db.prepare(`INSERT INTO telegram_outbox (receipt_id)
        SELECT search.receipt_id FROM telegram_github_search AS search JOIN telegram_inbox AS inbox USING (receipt_id)
        WHERE ${candidate} AND ${privateReceipt("inbox", generalPolicy(policy))} AND ${ownSearch("inbox")}
          AND inbox.received_at + ${MAX_REPLY_AGE_SECONDS} > unixepoch() AND ${current.sql}`)
        .bind(policy.botId, nonce, ...current.bindings),
      db.prepare(`UPDATE telegram_github_search AS search SET state = CASE WHEN EXISTS (
          SELECT 1 FROM telegram_outbox WHERE receipt_id = search.receipt_id) THEN 'unavailable' ELSE 'discarded' END,
        lookup_nonce = NULL, lookup_until = NULL WHERE ${candidate}`).bind(policy.botId, nonce),
      db.prepare(`UPDATE telegram_github_search SET public_results = NULL WHERE receipt_id IN (
        SELECT search.receipt_id FROM telegram_github_search AS search
        JOIN telegram_inbox AS inbox USING (receipt_id) LEFT JOIN telegram_outbox AS reply USING (receipt_id)
        WHERE search.bot_id = ? AND ${privateReceipt("inbox", generalPolicy(policy))} AND search.public_results IS NOT NULL AND (
          reply.state IN ('sent', 'failed', 'uncertain') OR inbox.received_at + ${MAX_REPLY_AGE_SECONDS} <= unixepoch()
          OR NOT (${current.sql}))
        ORDER BY search.receipt_id LIMIT ${REAP_LIMIT})`).bind(policy.botId, ...current.bindings),
    ]);
    if (results.length !== 4 || results.some(({ success, meta }) => !success || meta.changes > REAP_LIMIT)
      || results[0].meta.changes !== results[2].meta.changes || results[1].meta.changes > results[0].meta.changes) throw new Error();
    return results[1].meta.changes;
  } catch {
    throw new Error("Telegram GitHub search recovery could not finish.");
  }
}

export function renderTelegramGitHubReply(reply: TelegramGitHubReply): {
  text: string;
  keyboard?: { text: string; url: string }[][];
} {
  if (reply.state === "usage") return { text: "用法：/g 关键词或开源项目名称，例如 /g clash。搜索词会发给 GitHub 查找公开仓库，纯关键词或带 repo: 的查询也会发给 Grep 查找公开代码。请勿发送凭据或私密内容。" };
  const browser = [{ text: "在 GitHub 网页搜索代码", url: GITHUB_BROWSER }];
  if (reply.state === "found" && reply.publicResults && reply.publicResults.length <= MAX_PROJECTION_BYTES) {
    try {
      const value: unknown = JSON.parse(reply.publicResults);
      const projection = record(value);
      const repos = Array.isArray(value) ? value : projection?.v === 2 ? projection.repos : null;
      const code = Array.isArray(value) ? [] : projection?.v === 2 ? projection.code : null;
      if (Array.isArray(repos) && repos.length <= MAX_REPOSITORIES && Array.isArray(code) && code.length <= MAX_CODE_MATCHES
        && (repos.length > 0 || code.length > 0)) {
        const text: string[] = repos.length ? ["GitHub 公开仓库"] : [];
        const keyboard = [];
        for (const item of repos) {
          const repo = record(item);
          if (!repo || !repositoryName(repo.name) || !validInteger(repo.stars, 0)) throw new Error();
          text.push(`${repo.name} · ★ ${repo.stars}`);
          keyboard.push([{ text: repo.name, url: `${GITHUB_ORIGIN}/${repo.name}` }]);
        }
        if (code.length) text.push("Grep 公开代码");
        for (const item of code) {
          const match = codeMatch(item);
          if (!match) throw new Error();
          text.push(`${match.repo}/${match.path}`);
          const fileName = match.path.slice(match.path.lastIndexOf("/") + 1);
          keyboard.push([{ text: fileName.slice(0, 64), url: codeUrl(match) }]);
        }
        return { text: text.join("\n"), keyboard: [...keyboard, browser] };
      }
    } catch {
      // A damaged projection uses the fixed fallback.
    }
  }
  const text = reply.state === "limited" ? "搜索请求过于频繁，请稍后再试。"
    : reply.state === "empty" ? "没有找到匹配的公开仓库。" : "暂时无法获取 GitHub 搜索结果。";
  return { text, keyboard: [browser] };
}

import { grepCodeContent } from "../src/telegram/grep-search.ts";

const ENDPOINT = "https://mcp.grep.app/";
const REPO = "jquery/jquery";
const QUERY = "addClass";
const REPO_API = `https://api.github.com/repos/${REPO}`;
const PROTOCOL = "2025-06-18";
const MAX_REPO_BYTES = 256 * 1024;
const RPC = [
  { id: 1, method: "initialize", params: { protocolVersion: PROTOCOL, capabilities: {},
    clientInfo: { name: "subs-bot-public-search", version: "1.0.0" } } },
  { method: "notifications/initialized" },
  { id: 2, method: "tools/call", params: { name: "searchGitHub", arguments: { query: QUERY, repo: REPO, useRegexp: false } } },
];

function mediaType(response: Response): "sse" | "json" | "other" {
  const type = response.headers.get("Content-Type")?.split(";", 1)[0]?.trim().toLowerCase();
  return type === "text/event-stream" ? "sse"
    : type === "application/json" || type === "application/vnd.github+json" ? "json" : "other";
}

function counts(content: unknown[]) {
  let textBlocks = 0;
  let fixtureMetadata = 0;
  let canonicalLinks = 0;
  let knownPathMatches = 0;
  for (const value of content) {
    const item = value as { type?: unknown; text?: unknown } | null;
    if (item?.type !== "text" || typeof item.text !== "string") continue;
    textBlocks++;
    const match = /^Repository: ([^\r\n]+)\r?\nPath: ([^\r\n]+)\r?\nURL: ([^\r\n]+)\r?\nLicense: [^\r\n]*\r?\n(?:\r?\n){0,2}Snippets:(?:\r?\n|$)/u.exec(item.text);
    if (!match || match[1].toLowerCase() !== REPO) continue;
    fixtureMetadata++;
    const [, repo, path, url] = match;
    const prefix = `https://github.com/${repo}/blob/`;
    if (!url.startsWith(prefix) || !url.endsWith(`/${path}`)) continue;
    const ref = url.slice(prefix.length, -(path.length + 1));
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u.test(ref) || !/^[A-Za-z0-9_./-]{1,160}$/u.test(path)
      || path.split("/").some((part) => part === "" || part === "." || part === "..") || url !== `${prefix}${ref}/${path}`) continue;
    canonicalLinks++;
    if (path === "src/attributes/classes.js") knownPathMatches++;
  }
  return { blocks: content.length, textBlocks, fixtureMetadata, canonicalLinks, knownPathMatches };
}

async function verifyPublicRepo(signal: AbortSignal) {
  const start = Date.now();
  const result = { status: null as number | null, outcome: "timeout", elapsedMs: 0 };
  try {
    if (signal.aborted) return result;
    const response = await fetch(REPO_API, { method: "GET", redirect: "manual", cache: "no-store", signal, headers: {
      Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2026-03-10", "User-Agent": "subs-bot-public-search/1.0",
    } });
    result.status = response.status;
    const declared = response.headers.get("Content-Length");
    if (response.status !== 200 || response.redirected || mediaType(response) !== "json" || !response.body
      || (declared !== null && (!/^\d+$/u.test(declared) || Number(declared) > MAX_REPO_BYTES))) {
      void response.body?.cancel().catch(() => {});
      result.outcome = "response-rejected";
      return result;
    }
    const reader = response.body.getReader();
    const decoder = new TextDecoder("utf-8", { fatal: true });
    let length = 0;
    let text = "";
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        length += value.byteLength;
        if (length > MAX_REPO_BYTES) {
          result.outcome = "body-limit";
          return result;
        }
        text += decoder.decode(value, { stream: true });
      }
      const data = JSON.parse(text + decoder.decode()) as { private?: unknown; visibility?: unknown; full_name?: unknown; html_url?: unknown } | null;
      result.outcome = data?.private === false && data.visibility === "public" && data.full_name === REPO
        && data.html_url === `https://github.com/${REPO}` ? "confirmed-public" : "public-not-confirmed";
      return result;
    } finally {
      void reader.cancel().catch(() => {});
      reader.releaseLock();
    }
  } catch {
    result.outcome = signal.aborted ? "timeout" : "transport-or-body-error";
    return result;
  } finally {
    result.elapsedMs = Date.now() - start;
  }
}

export async function probeGrepRuntimeShape() {
  const start = Date.now();
  const signal = AbortSignal.timeout(8000);
  let authorizationCheck = false;
  let requestGuardFailed = false;
  const phases: { stage: string; status: number | null; media: string | null; sessionHeader: boolean; headersMs: number; outcome: string }[] = [];
  const request: typeof fetch = async (input, init) => {
    const expected = RPC[phases.length];
    const headers = new Headers(init?.headers);
    if (!expected || input !== ENDPOINT || init?.method !== "POST" || init.redirect !== "manual" || init.cache !== "no-store"
      || init.signal !== signal || init.body !== JSON.stringify({ jsonrpc: "2.0", ...expected })
      || headers.get("Content-Type") !== "application/json" || headers.get("Accept") !== "application/json, text/event-stream"
      || headers.get("User-Agent") !== "subs-bot-public-search/1.0"
      || headers.get("MCP-Protocol-Version") !== (phases.length ? PROTOCOL : null)
      || ["Authorization", "Cookie", "Mcp-Session-Id"].some((header) => headers.has(header))) {
      requestGuardFailed = true;
      throw new Error("Unexpected probe request shape.");
    }
    const phase = { stage: expected.method, status: null as number | null, media: null as string | null, sessionHeader: false,
      headersMs: 0, outcome: "response" };
    phases.push(phase);
    const sent = Date.now();
    try {
      const response = await fetch(input, init);
      phase.status = response.status;
      phase.media = mediaType(response);
      phase.sessionHeader = response.headers.has("Mcp-Session-Id");
      return response;
    } catch {
      phase.outcome = signal.aborted ? "timeout" : "transport-error";
      throw new Error("Probe request could not be confirmed.");
    } finally {
      phase.headersMs = Date.now() - sent;
    }
  };
  const content = await grepCodeContent(request, signal, QUERY, REPO, async () => { authorizationCheck = true; return true; });
  if (requestGuardFailed) throw new Error("Unexpected probe request shape.");
  const grepElapsedMs = Date.now() - start;
  const projection = counts(content);
  // Verify anonymous visibility even if the adapter returned no candidate, using the same deadline.
  const repository = await verifyPublicRepo(signal);
  return { version: 1, mode: "worker-runtime-shape", phases, authorizationCheck,
    grepElapsedMs, projection, repository, elapsedMs: Date.now() - start };
}

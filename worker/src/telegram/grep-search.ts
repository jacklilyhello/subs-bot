const ENDPOINT = "https://mcp.grep.app/";
const PROTOCOL = "2025-06-18";
const MAX_SSE_BYTES = 256 * 1024;
const MAX_SSE_CHUNKS = 512;

export interface GrepSearchObservation {
  phase: "not-started" | "initialize" | "initialize-response" | "initialized" | "initialized-response"
    | "authorization" | "authorization-denied" | "tool" | "tool-response" | "tool-shape" | "complete";
  initializeStatus: number | null;
  initializedStatus: number | null;
  toolStatus: number | null;
  timedOut: boolean;
  contentBlocks: number;
}


async function readEvent(response: Response, id: number): Promise<Record<string, unknown> | null> {
  if (response.status !== 200 || response.redirected || response.headers.has("Mcp-Session-Id") || !response.body
    || !/^text\/event-stream(?:\s*;|$)/iu.test(response.headers.get("Content-Type") ?? "")) {
    void response.body?.cancel().catch(() => {});
    return null;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
  let total = 0;
  let tail = "";
  let event = "message";
  let data: string[] = [];
  try {
    for (let chunks = 0; chunks < MAX_SSE_CHUNKS; chunks++) {
      const { done, value } = await reader.read();
      if (done) return null;
      total += value.byteLength;
      if (total > MAX_SSE_BYTES) return null;
      let next = tail.length;
      tail += decoder.decode(value, { stream: true });
      let start = 0;
      for (; (next = tail.indexOf("\n", next)) !== -1; next = start) {
        const line = tail.slice(start, next).replace(/\r$/u, "");
        start = next + 1;
        if (line === "") {
          if (data.some(Boolean)) {
            if (event !== "message") return null;
            const frame = JSON.parse(data.join("\n")) as unknown;
            if (frame === null || typeof frame !== "object" || Array.isArray(frame)) return null;
            const { jsonrpc, id: responseId, result } = frame as Record<string, unknown>;
            return jsonrpc === "2.0" && responseId === id && !Object.hasOwn(frame, "error")
              && result !== null && typeof result === "object" && !Array.isArray(result)
              ? result as Record<string, unknown> : null;
          }
          event = "message";
          data = [];
        } else if (line.startsWith("data:")) {
          data.push(line.slice(5).replace(/^ /u, ""));
        } else if (line.startsWith("event:")) {
          event = line.slice(6).replace(/^ /u, "") || "message";
        }
      }
      tail = tail.slice(start);
    }
    return null;
  } finally {
    void reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** Only the stateless SSE handshake observed in the hosted capability probe is supported. */
export async function grepCodeContent(
  request: typeof fetch, signal: AbortSignal, query: string, repo: string | undefined,
  stillAuthorized: () => Promise<boolean>, observation?: GrepSearchObservation,
): Promise<unknown[]> {
  const post = (message: Record<string, unknown>, initialized: boolean) => request(ENDPOINT, {
    method: "POST", redirect: "manual", cache: "no-store", signal,
    headers: { "Content-Type": "application/json", Accept: "application/json, text/event-stream",
      "User-Agent": "subs-bot-public-search/1.0", ...(initialized ? { "MCP-Protocol-Version": PROTOCOL } : {}) },
    body: JSON.stringify({ jsonrpc: "2.0", ...message }),
  });
  try {
    if (observation) observation.phase = "initialize";
    const initialResponse = await post({ id: 1, method: "initialize", params: { protocolVersion: PROTOCOL,
      capabilities: {}, clientInfo: { name: "subs-bot-public-search", version: "1.0.0" } } }, false);
    if (observation) {
      observation.phase = "initialize-response";
      observation.initializeStatus = initialResponse.status;
    }
    const initial = await readEvent(initialResponse, 1);
    if (initial?.protocolVersion !== PROTOCOL || signal.aborted) return [];
    if (observation) observation.phase = "initialized";
    const notice = await post({ method: "notifications/initialized" }, true);
    if (observation) {
      observation.phase = "initialized-response";
      observation.initializedStatus = notice.status;
    }
    if (notice.status !== 202 || notice.redirected || notice.headers.has("Mcp-Session-Id")) {
      void notice.body?.cancel().catch(() => {});
      return [];
    }
    if (notice.body) {
      const reader = notice.body.getReader();
      try {
        if (!(await reader.read()).done) return [];
      } finally {
        void reader.cancel().catch(() => {});
        reader.releaseLock();
      }
    }
    if (signal.aborted) return [];
    if (observation) observation.phase = "authorization";
    if (!await stillAuthorized()) {
      if (observation) observation.phase = "authorization-denied";
      return [];
    }
    if (signal.aborted) return [];
    if (observation) observation.phase = "tool";
    const toolResponse = await post({ id: 2, method: "tools/call", params: {
      name: "searchGitHub", arguments: { query, ...(repo ? { repo } : {}), useRegexp: false },
    } }, true);
    if (observation) {
      observation.phase = "tool-response";
      observation.toolStatus = toolResponse.status;
    }
    const result = await readEvent(toolResponse, 2);
    if (result && (result.isError === undefined || result.isError === false) && !Object.hasOwn(result, "structuredContent")
      && Array.isArray(result.content) && result.content.length <= 20) {
      if (observation) {
        observation.phase = "complete";
        observation.contentBlocks = result.content.length;
      }
      return result.content;
    }
    if (observation && result) observation.phase = "tool-shape";
    return [];
  } catch {
    return [];
  } finally {
    if (observation) observation.timedOut = signal.aborted;
  }
}

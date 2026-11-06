import { getSubscriptionSnapshot, readSnapshotNodes, type SubscriptionSnapshot } from "./storage.ts";

export interface Env {
  DB: D1Database;
  NODES: R2Bucket;
  BUILD_REVISION?: string;
}

const MAX_SHARE_BYTES = 16 * 1024 * 1024;
// Every complete chunk ends on a Base64 group boundary.
const SHARE_CHUNK_BYTES = 24 * 1024;
const EXPORT_KINDS = new Set(["base64", "v2ray", "mixed"]);
const SUBSCRIPTION_PATH = /^\/sub\/([A-Za-z0-9_-]{16,128})(?:\/([A-Za-z0-9-]{1,32}))?$/;
const SHARE_LINE = /^(?:ss|ssr|vmess|vless|trojan|hysteria2?|hy2|tuic|snell|wireguard|anytls|socks5(?:-tls)?):\/\/[^\s#]+(?:#[^\r\n\u2028\u2029]*)?$/i;
const UNSAFE_SHARE_CHARACTER = /[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u;
const HEADERS = {
  "Cache-Control": "private, no-store",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

function plain(text: string, status: number, head: boolean, headers?: HeadersInit): Response {
  const responseHeaders = new Headers(headers);
  for (const [name, value] of Object.entries(HEADERS)) responseHeaders.set(name, value);
  responseHeaders.set("Content-Type", "text/plain; charset=utf-8");
  return new Response(head ? null : text, { status, headers: responseHeaders });
}

async function collectShares(bucket: R2Bucket, snapshot: SubscriptionSnapshot): Promise<Uint8Array[] | null> {
  const encoder = new TextEncoder();
  const chunks: Uint8Array[] = [];
  let chunk = new Uint8Array(SHARE_CHUNK_BYTES);
  let offset = 0;
  let total = 0;

  for await (const node of readSnapshotNodes(bucket, snapshot)) {
    const share = node.share;
    if (typeof share !== "string" || UNSAFE_SHARE_CHARACTER.test(share) || !SHARE_LINE.test(share)) return null;
    const line = encoder.encode(total === 0 ? share : `\n${share}`);
    total += line.length;
    if (total > MAX_SHARE_BYTES) return null;

    for (let start = 0; start < line.length;) {
      const length = Math.min(line.length - start, chunk.length - offset);
      chunk.set(line.subarray(start, start + length), offset);
      start += length;
      offset += length;
      if (offset === chunk.length) {
        chunks.push(chunk);
        chunk = new Uint8Array(SHARE_CHUNK_BYTES);
        offset = 0;
      }
    }
  }
  if (offset !== 0) chunks.push(chunk.subarray(0, offset));
  return chunks;
}

function base64Body(chunks: Uint8Array[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  const pending = chunks.reverse();
  return new ReadableStream({
    pull(controller) {
      const chunk = pending.pop();
      if (!chunk) {
        controller.close();
        return;
      }
      controller.enqueue(encoder.encode(btoa(String.fromCharCode(...chunk))));
    },
    cancel() {
      pending.length = 0;
    },
  });
}

async function fetchRequest(request: Request, env: Env): Promise<Response> {
  const path = new URL(request.url).pathname;
  const subscription = SUBSCRIPTION_PATH.exec(path);
  const head = request.method === "HEAD";
  if (path !== "/health" && !subscription) return plain("Not found.", 404, head);
  if (request.method !== "GET" && !head) return plain("Method not allowed.", 405, false, { Allow: "GET, HEAD" });

  if (!subscription) {
    const revision = env.BUILD_REVISION;
    if (typeof revision !== "string" || revision.length !== 40 || !/^[0-9a-f]+$/.test(revision)) {
      return plain("Service unavailable.", 503, head);
    }
    const body = head ? null : JSON.stringify({ ok: true, service: "subs-bot", revision });
    return new Response(body, { headers: { ...HEADERS, "Content-Type": "application/json" } });
  }

  const [, token, kind = ""] = subscription;
  if (!EXPORT_KINDS.has(kind.toLowerCase())) return plain("Export format unavailable.", 406, head);

  try {
    const snapshot = await getSubscriptionSnapshot(env.DB, token);
    if (!snapshot) return plain("Not found.", 404, head);
    // Check all referenced chunks before sending any success bytes.
    const chunks = await collectShares(env.NODES, snapshot);
    if (!chunks) return plain("Subscription content cannot be exported.", 422, head);
    if (chunks.length === 0) return plain("Subscription temporarily unavailable.", 503, head);
    return new Response(head ? null : base64Body(chunks), {
      headers: { ...HEADERS, "Content-Type": "text/plain; charset=utf-8" },
    });
  } catch {
    return plain("Subscription temporarily unavailable.", 503, head);
  }
}

export default { fetch: fetchRequest } satisfies ExportedHandler<Env>;

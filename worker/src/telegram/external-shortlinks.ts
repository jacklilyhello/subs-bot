import { ISOLATION_PUBLIC_ORIGIN, PRODUCTION_PUBLIC_ORIGIN, type PublicOrigin } from "../public-origin.ts";

/** This is an RPC entrypoint, deliberately not a Fetcher/public HTTP client. */
export interface ShortlinkService {
  createShortlink(request: Request): Promise<Response>;
}
export type ExternalShortlinkRuntime = { service?: ShortlinkService; token?: string };
type Result = { kind: "created" | "replayed"; url: string }
  | { kind: "fallback"; retryAfter: number | null; terminal: boolean };
const DOMAIN = "gfw.mom";
const METADATA_URL = "https://link-admin.lily.lat/api/shorten";
const CODE = /^[A-Za-z0-9_-]{12,64}(?![\s\S])/u;
const TOKEN = /^sl_[A-Za-z0-9_-]{32,128}(?![\s\S])/u;
const MAX_BODY = 8192;

export function localShortlink(value: string, origin: PublicOrigin): boolean {
  return (origin === ISOLATION_PUBLIC_ORIGIN || origin === PRODUCTION_PUBLIC_ORIGIN)
    && value.startsWith(origin + "/s/") && CODE.test(value.slice(origin.length + 3));
}

async function jsonBody(response: Response): Promise<unknown> {
  if (!response.body || !/^application\/json(?:;|$)/iu.test(response.headers.get("content-type") ?? "")) return null;
  const reader = response.body.getReader();
  let bytes = 0;
  let text = "";
  const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
  try {
    for (;;) {
      const chunk = await reader.read();
      if (chunk.done) break;
      bytes += chunk.value.byteLength;
      if (bytes > MAX_BODY) { await reader.cancel(); return null; }
      text += decoder.decode(chunk.value, { stream: true });
    }
    return JSON.parse(text + decoder.decode());
  } catch { return null; }
  finally { reader.releaseLock(); }
}

/** One bounded RPC attempt. Retry timing and the same operation identity survive redelivery. */
export async function callShortlinkService(
  runtime: ExternalShortlinkRuntime, local: string, origin: PublicOrigin, operationId: string, timeoutMs = 2500,
): Promise<Result> {
  const fallback = { kind: "fallback", retryAfter: null, terminal: true } as const;
  if (!localShortlink(local, origin) || !/^[a-f0-9-]{36}(?![\s\S])/u.test(operationId)
    || !runtime.service || !TOKEN.test(runtime.token ?? "")) return fallback;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const result = await Promise.race([
      (async (): Promise<Result> => {
        const response = await runtime.service!.createShortlink(new Request(METADATA_URL, {
          method: "POST", headers: { Authorization: `Bearer ${runtime.token}`, "Content-Type": "application/json",
            "Idempotency-Key": operationId }, body: JSON.stringify({ url: local, domain: DOMAIN }),
        }));
        if (!(response instanceof Response)) return fallback;
        if (response.status === 429) {
          const value = response.headers.get("Retry-After") ?? "";
          // A longer valid wait is retained rather than shortened to our retry window.
          const delay = /^[0-9]{1,9}(?![\s\S])/u.test(value) ? Number(value) : null;
          await response.body?.cancel();
          return { kind: "fallback", retryAfter: delay, terminal: delay === null };
        }
        if (response.status === 500 || response.status === 503) {
          const header = response.headers.get("Retry-After");
          const delay = header === null ? 1 : /^[0-9]{1,9}(?![\s\S])/u.test(header) ? Number(header) : null;
          await response.body?.cancel();
          return { kind: "fallback", retryAfter: delay, terminal: delay === null };
        }
        if (response.status !== 201 && response.status !== 200) { await response.body?.cancel(); return fallback; }
        const body = await jsonBody(response) as { ok?: unknown; data?: { domain?: unknown; slug?: unknown; short_url?: unknown } } | null;
        const data = body?.data;
        if (body?.ok !== true || data?.domain !== DOMAIN || typeof data.slug !== "string" || !/^[A-Za-z0-9_-]{1,64}(?![\s\S])/u.test(data.slug)
          || data.short_url !== `https://${DOMAIN}/${data.slug}`
          || (response.status === 200 && response.headers.get("Idempotency-Replayed") !== "true")) return fallback;
        return { kind: response.status === 201 ? "created" : "replayed", url: data.short_url as string };
      })(),
      new Promise<Result>((resolve) => { timer = setTimeout(() => resolve({ kind: "fallback", retryAfter: 1, terminal: false }),
        Math.max(1, Math.min(2500, timeoutMs))); }),
    ]);
    return result;
  } catch { return { kind: "fallback", retryAfter: 1, terminal: false }; }
  finally { if (timer !== undefined) clearTimeout(timer); }
}

/** Only call after local publication; the supplied fence is rechecked before RPC and final delivery. */
export async function wrapAuthorizedLocalShortlink(
  db: D1Database, botId: string, local: string, origin: PublicOrigin, runtime: ExternalShortlinkRuntime | undefined,
  authorized: () => Promise<boolean>, deadline = Date.now() + 3000,
): Promise<{ url: string; external: boolean } | null> {
  if (!localShortlink(local, origin) || !await authorized()) return null;
  if (!runtime?.service || !TOKEN.test(runtime.token ?? "")) return { url: local, external: false };
  try {
    const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(local));
    const digest = Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
    // No identity, URL, token or derived capability is included in the external idempotency key.
    await db.prepare(`INSERT /* subs-bot:external-shortlinks:v1 */ INTO telegram_external_shortlinks (bot_id,local_sha256,operation_id,domain)
      VALUES (?,?,?,'gfw.mom') ON CONFLICT(bot_id,local_sha256) DO NOTHING`).bind(botId, digest, crypto.randomUUID()).run();
    const attemptDeadline = Math.min(deadline, Date.now() + 3500);
    // Retry inside this invocation only when the complete requested wait fits the finite budget.
    // A longer Retry-After immediately falls back locally; no unimplemented Cron retry is implied.
    for (let attempt = 0; attempt < 3 && Date.now() < attemptDeadline; attempt++) {
      const lease = crypto.randomUUID();
      const row = await db.prepare(`UPDATE telegram_external_shortlinks SET lease_id=?,lease_until=unixepoch()+5,attempts=attempts+1
      WHERE bot_id=? AND local_sha256=? AND terminal=0 AND attempts<3 AND retry_at<=unixepoch()
        AND (lease_id IS NULL OR lease_until<=unixepoch())
      RETURNING operation_id AS operationId,attempts`).bind(lease, botId, digest).first<{ operationId: string; attempts: number }>();
      if (!row || !await authorized()) break;
      const result = await callShortlinkService(runtime, local, origin, row.operationId, attemptDeadline - Date.now());
      await db.prepare(`UPDATE telegram_external_shortlinks SET short_url=?,terminal=?,retry_at=unixepoch()+?,lease_id=NULL,lease_until=NULL
        WHERE bot_id=? AND local_sha256=? AND lease_id=?`).bind(
        result.kind === "fallback" ? null : result.url,
        result.kind === "fallback" ? Number(result.terminal || row.attempts >= 3) : 1,
        result.kind === "fallback" ? (result.retryAfter ?? 0) : 0, botId, digest, lease).run();
      if (result.kind !== "fallback" || result.terminal || row.attempts >= 3 || result.retryAfter === null) break;
      const delay = result.retryAfter * 1000;
      if (delay + 100 >= attemptDeadline - Date.now()) break;
      await new Promise<void>((resolve) => setTimeout(resolve, delay));
    }
    const saved = await db.prepare(`SELECT short_url AS url FROM telegram_external_shortlinks WHERE bot_id=? AND local_sha256=?`)
      .bind(botId, digest).first<{ url: string | null }>();
    if (!await authorized()) return null;
    return saved?.url && /^https:\/\/gfw\.mom\/[A-Za-z0-9_-]{1,64}(?![\s\S])/u.test(saved.url)
      ? { url: saved.url, external: true } : { url: local, external: false };
  } catch {
    // Transport/SQL errors may contain capabilities or request headers. Never log them.
    return await authorized().catch(() => false) ? { url: local, external: false } : null;
  }
}

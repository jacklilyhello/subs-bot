import { digestHex } from "./storage.ts";

export const ISOLATION_PUBLIC_ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
export const SHORT_CODE = /^(?:[A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{22})(?![\s\S])/u;
export const NORMAL_CODE_SUFFIX = "s";
const MAX_TARGET_BYTES = 2048;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const LOCAL_SUFFIXES = [".localhost", ".localdomain", ".local", ".internal", ".home.arpa", ".test", ".invalid", ".example",
  ".onion", ".lan", ".home", ".corp", ".svc"];
const PROJECT_HOSTS = new Set([new URL(ISOLATION_PUBLIC_ORIGIN).hostname, "subs-bot.lilyya.top"]);
const CONTROL_OR_BACKSLASH = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029\\]/u;
const encoder = new TextEncoder();

function publicIpv4(host: string): boolean {
  const [a, b, c] = host.split(".").map(Number);
  // Block private, special-use, documentation, multicast and reserved ranges.
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if ((a === 100 && b >= 64 && b <= 127) || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)) return false;
  if (a === 192 && (b === 168 || (b === 0 && (c === 0 || c === 2)) || (b === 88 && c === 99))) return false;
  if (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) return false;
  return a !== 203 || b !== 0 || c !== 113;
}

function publicIpv6(host: string): boolean {
  // URL has already validated the brackets and serialized the literal.
  const [first, second] = host.slice(1, -1).split(":");
  const a = Number.parseInt(first, 16);
  const b = second ? Number.parseInt(second, 16) : 0;
  return a >= 0x2000 && a <= 0x3fff
    && !(a === 0x2001 && (b <= 0x1ff || b === 0xdb8))
    && a !== 0x2002 && !(a === 0x3fff && b <= 0xfff);
}

/** Validate a browser redirect destination without DNS resolution or an upstream request. */
export function canonicalShortDestination(value: unknown): string | null {
  if (typeof value !== "string" || value.length === 0 || value.length > MAX_TARGET_BYTES
    || CONTROL_OR_BACKSLASH.test(value) || /[\s<>"]/u.test(value)) return null;
  const match = /^https?:\/\/([^/?#]+)(?:[/?#]|$)/iu.exec(value);
  if (!match || /[@%]/u.test(match[1])) return null;
  const authority = /^(\[[^\]]+\]|[^:]+)(?::([0-9]{1,5}))?$/u.exec(match[1]);
  if (!authority || (authority[2] !== undefined && (Number(authority[2]) < 1 || Number(authority[2]) > 65_535))) return null;
  try {
    if (CONTROL_OR_BACKSLASH.test(decodeURIComponent(value))) return null;
    const url = new URL(value);
    if ((url.protocol !== "https:" && url.protocol !== "http:") || url.username || url.password) return null;
    const host = url.hostname.replace(/\.$/u, "").toLowerCase();
    if (PROJECT_HOSTS.has(host) || host === "home.arpa" || LOCAL_SUFFIXES.some((suffix) => host.endsWith(suffix))) return null;
    if (host.startsWith("[")) {
      if (!publicIpv6(host)) return null;
    } else if (/^[0-9]+(?:\.[0-9]+){3}$/u.test(host)) {
      // Refuse octal, hexadecimal, truncated, integer and other IPv4 spellings.
      if (authority[1] !== host || !publicIpv4(host)) return null;
    } else if (host.length > 253 || !host.includes(".") || !host.split(".").every((label) => HOST_LABEL.test(label))) {
      return null;
    }
    if (!/^[!-~]+$/u.test(url.href) || encoder.encode(url.href).byteLength > MAX_TARGET_BYTES) return null;
    return url.href;
  } catch {
    return null;
  }
}

export async function shortCodeDigest(code: string): Promise<string> {
  return digestHex(await crypto.subtle.digest("SHA-256", encoder.encode(code)));
}

export async function normalShortLinksReady(db: D1Database): Promise<boolean> {
  try {
    const row = await db.prepare(`SELECT count(*) AS present FROM sqlite_schema WHERE type='table'
      AND name IN ('normal_short_links','telegram_short_link_actions')`).first<{ present: number }>();
    if (row?.present === 0 || row?.present === 2) return row.present === 2;
  } catch {
    // Fail closed when namespace state cannot be read.
  }
  throw new Error("Short link schema could not be confirmed.");
}

type ShortRow = {
  kind: "aggregate" | "external";
  codeLength: number | null;
  targetUrl: string | null;
  revokedAt: number | null;
};

/** Both namespaces, including tombstones, are read from a single SQLite snapshot. */
export async function resolveShortLocation(db: D1Database, code: string): Promise<string | null> {
  if (!SHORT_CODE.test(code)) return null;
  const digest = await shortCodeDigest(code);
  const result = await db.prepare(`SELECT 'aggregate' AS kind,NULL AS codeLength,NULL AS targetUrl,revoked_at AS revokedAt
    FROM aggregate_links WHERE code_sha256=?
    UNION ALL SELECT 'external',code_length,target_url,revoked_at FROM normal_short_links WHERE code_sha256=?`)
    .bind(digest, digest).all<ShortRow>();
  if (!result.success) throw new Error("Short link state could not be read.");
  if (result.results.length !== 1 || result.results[0].revokedAt !== null) return null;
  const row = result.results[0];
  if (row.kind === "aggregate") return `/agg/${code}/clash`;
  if (row.kind !== "external" || row.codeLength !== code.length || (code.length === 22 && !code.endsWith(NORMAL_CODE_SUFFIX))) return null;
  return canonicalShortDestination(row.targetUrl);
}

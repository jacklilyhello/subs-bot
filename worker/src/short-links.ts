import { digestHex } from "./storage.ts";
import { LEGACY_SELECTED_RETIREMENT_PIN } from "./subscriptions.ts";
import { legacyAllActiveMarkerSql } from "./legacy-all-aggregates.ts";
import { ISOLATION_PUBLIC_ORIGIN, PRODUCTION_PUBLIC_ORIGIN } from "./public-origin.ts";
import { resolveSubscriptionShortLocation, SUBSCRIPTION_SHORT_CODE } from "./telegram/subscription-shorts.ts";

export { ISOLATION_PUBLIC_ORIGIN };
export const SHORT_CODE = /^(?:[A-Za-z0-9_-]{12}|[A-Za-z0-9_-]{22})(?![\s\S])/u;
export const NORMAL_CODE_SUFFIX = "s";
export const LEGACY_SUBSCRIPTION_SHORT_MIGRATION = "0029_legacy_subscription_short_links.sql";
export const LEGACY_SUBSCRIPTION_SHORT_SHA256 = "1a0da8aa8aedde095b3e1a4bc71b5e03376587882288c4e276c9a1f9afa1297d";
export const LEGACY_SUBSCRIPTION_SHORT_PIN = `EXISTS (
  SELECT 1 FROM subs_bot_schema_migrations WHERE position=29 AND mode='applied'
    AND name='${LEGACY_SUBSCRIPTION_SHORT_MIGRATION}' AND sha256='${LEGACY_SUBSCRIPTION_SHORT_SHA256}'
)`;
const LEGACY_SUBSCRIPTION_TOKEN = /^[A-Za-z0-9_-]{16,128}(?![\s\S])/u;
const LEGACY_SUBSCRIPTION_FORMATS = new Set(["", "clash", "base64", "v2ray", "mixed", "singbox", "sing-box", "surge",
  "qx", "quantumult", "quantumultx"]);
const MAX_TARGET_BYTES = 2048;
const HOST_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/u;
const LOCAL_SUFFIXES = [".localhost", ".localdomain", ".local", ".internal", ".home.arpa", ".test", ".invalid", ".example",
  ".onion", ".lan", ".home", ".corp", ".svc"];
const PROJECT_HOSTS = new Set([new URL(ISOLATION_PUBLIC_ORIGIN).hostname, new URL(PRODUCTION_PUBLIC_ORIGIN).hostname]);
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

export interface ShortLinkNamespaces {
  normal: boolean;
  legacySubscription: boolean;
  migrationLedger: boolean;
  selectedMarker: boolean;
  selectedMembers: boolean;
  legacyEmpty: boolean;
  allMarker: boolean;
  allOrder: boolean;
  tempInstallations: boolean;
  tempBatches: boolean;
}

export async function readShortLinkNamespaces(db: D1Database): Promise<ShortLinkNamespaces> {
  try {
    const row = await db.prepare(`SELECT
      count(CASE WHEN name IN ('normal_short_links','telegram_short_link_actions') THEN 1 END) AS normal,
      count(CASE WHEN name='legacy_subscription_short_links' THEN 1 END) AS legacySubscription,
      count(CASE WHEN name='subs_bot_schema_migrations' THEN 1 END) AS migrationLedger,
      count(CASE WHEN name='legacy_selected_aggregates' THEN 1 END) AS selectedMarker,
      count(CASE WHEN name='legacy_selected_members' THEN 1 END) AS selectedMembers,
      count(CASE WHEN name='legacy_empty_subscription_exports' THEN 1 END) AS legacyEmpty,
      count(CASE WHEN name='legacy_all_aggregates' THEN 1 END) AS allMarker,
      count(CASE WHEN name='legacy_all_subscription_order' THEN 1 END) AS allOrder,
      count(CASE WHEN name='legacy_temp_installations' THEN 1 END) AS tempInstallations,
      count(CASE WHEN name='legacy_temp_batches' THEN 1 END) AS tempBatches
      FROM sqlite_schema WHERE type='table' AND name IN ('normal_short_links','telegram_short_link_actions',
        'legacy_subscription_short_links','subs_bot_schema_migrations','legacy_selected_aggregates',
        'legacy_selected_members','legacy_empty_subscription_exports','legacy_all_aggregates',
        'legacy_all_subscription_order','legacy_temp_installations','legacy_temp_batches')`)
      .first<Record<keyof ShortLinkNamespaces, number>>();
    if (row && (row.normal === 0 || row.normal === 2)) {
      return { normal: row.normal === 2, legacySubscription: row.legacySubscription === 1,
        migrationLedger: row.migrationLedger === 1, selectedMarker: row.selectedMarker === 1,
        selectedMembers: row.selectedMembers === 1, legacyEmpty: row.legacyEmpty === 1,
        allMarker: row.allMarker === 1, allOrder: row.allOrder === 1,
        tempInstallations: row.tempInstallations === 1, tempBatches: row.tempBatches === 1 };
    }
  } catch {
    // Fail closed when namespace state cannot be read.
  }
  throw new Error("Short link schema could not be confirmed.");
}

export async function normalShortLinksReady(db: D1Database): Promise<boolean> {
  return (await readShortLinkNamespaces(db)).normal;
}

// 0 is ordinary, 1 is marked and readable, and -1 reserves an invalid or
// unverified marker. An observed older schema must never read a newly marked row.
export function legacySelectedStatusSql(schema: ShortLinkNamespaces): string {
  if (!schema.selectedMarker) return `CASE WHEN EXISTS (SELECT 1 FROM main.sqlite_schema
    WHERE name IN ('legacy_selected_aggregates','legacy_selected_members')) THEN -1 ELSE 0 END`;
  const ready = schema.selectedMembers && schema.migrationLedger && schema.normal && schema.legacySubscription
    ? `aggregate_links.kind='selected' AND ${LEGACY_SELECTED_RETIREMENT_PIN}` : "0";
  return `CASE WHEN NOT EXISTS (SELECT 1 FROM legacy_selected_aggregates WHERE code_sha256=aggregate_links.code_sha256)
    THEN 0 WHEN ${ready} THEN 1 ELSE -1 END`;
}

export function legacyAllStatusSql(schema: ShortLinkNamespaces): string {
  if (!schema.allMarker) return `CASE WHEN aggregate_links.kind='all' AND EXISTS (SELECT 1 FROM main.sqlite_schema
    WHERE name IN ('legacy_all_aggregates','legacy_all_subscription_order')) THEN -1 ELSE 0 END`;
  const ready = schema.allOrder && schema.migrationLedger && schema.normal && schema.legacySubscription
    && schema.tempInstallations && schema.tempBatches ? legacyAllActiveMarkerSql("aggregate_links") : "0";
  return `CASE WHEN NOT EXISTS (SELECT 1 FROM legacy_all_aggregates WHERE code_sha256=aggregate_links.code_sha256)
    THEN 0 WHEN (${ready}) THEN 1 ELSE -1 END`;
}

export function aggregateNamespace(codeLength: number, selected: number, all: number): "native" | "legacy-selected" | "legacy-all" | null {
  if (selected === 0 && all === 0) return "native";
  if (codeLength !== 12) return null;
  if (selected === 1 && all === 0) return "legacy-selected";
  if (selected === 0 && all === 1) return "legacy-all";
  return null;
}

type ShortRow = {
  kind: "aggregate" | "external" | "legacy-subscription";
  codeLength: number | null;
  targetUrl: string | null;
  revokedAt: number | null;
  token: string | null;
  tokenSha256: string | null;
  format: string | null;
  legacySelected: number;
  legacyAll: number;
};

/** Even a disabled compatibility namespace reserves its digests. */
export async function resolveShortLocation(db: D1Database, code: string, serveLegacy = false): Promise<string | null> {
  if (!SHORT_CODE.test(code)) return null;
  if (SUBSCRIPTION_SHORT_CODE.test(code)) return resolveSubscriptionShortLocation(db, code);
  const namespaces = await readShortLinkNamespaces(db);
  const digest = await shortCodeDigest(code);
  const legacyEnabled = serveLegacy && code.length === 12 && namespaces.normal && namespaces.legacySubscription && namespaces.migrationLedger;
  const legacyTarget = legacyEnabled ? `sub.token, link.token_sha256, link.format,0,0
    FROM legacy_subscription_short_links AS link
    LEFT JOIN subscriptions AS sub ON sub.id=link.subscription_id AND sub.owner_id=link.owner_id
      AND link.revoked_at IS NULL AND ${LEGACY_SUBSCRIPTION_SHORT_PIN}
      AND NOT EXISTS (SELECT 1 FROM subscription_trash AS trash WHERE trash.id=sub.id OR trash.token=sub.token)
    WHERE link.code_sha256=?` : "NULL,NULL,NULL,0,0 FROM legacy_subscription_short_links AS link WHERE link.code_sha256=?";
  const result = await db.prepare(`SELECT 'aggregate' AS kind,NULL AS codeLength,NULL AS targetUrl,revoked_at AS revokedAt,
      NULL AS token,NULL AS tokenSha256,NULL AS format,${legacySelectedStatusSql(namespaces)} AS legacySelected,
      ${legacyAllStatusSql(namespaces)} AS legacyAll
      FROM aggregate_links WHERE code_sha256=?
    ${namespaces.normal ? `UNION ALL SELECT 'external',code_length,target_url,revoked_at,NULL,NULL,NULL,0,0
      FROM normal_short_links WHERE code_sha256=?` : ""}
    ${namespaces.legacySubscription ? `UNION ALL SELECT 'legacy-subscription',12,NULL,link.revoked_at,${legacyTarget}` : ""}`)
    .bind(digest, ...(namespaces.normal ? [digest] : []), ...(namespaces.legacySubscription ? [digest] : [])).all<ShortRow>();
  if (!result.success) throw new Error("Short link state could not be read.");
  if (result.results.length !== 1 || result.results[0].revokedAt !== null) return null;
  const row = result.results[0];
  if (row.kind === "aggregate") return aggregateNamespace(code.length, row.legacySelected, row.legacyAll) !== null
    ? `/agg/${code}/clash` : null;
  if (row.kind === "legacy-subscription") {
    if (!legacyEnabled || row.token === null || !LEGACY_SUBSCRIPTION_TOKEN.test(row.token)
      || row.format === null || !LEGACY_SUBSCRIPTION_FORMATS.has(row.format)
      || await shortCodeDigest(row.token) !== row.tokenSha256) return null;
    return row.format === "" ? `/sub/${row.token}` : `/sub/${row.token}/${row.format}`;
  }
  if (row.kind !== "external" || row.codeLength !== code.length || (code.length === 22 && !code.endsWith(NORMAL_CODE_SUFFIX))) return null;
  return canonicalShortDestination(row.targetUrl);
}

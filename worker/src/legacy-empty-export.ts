import { digestHex } from "./storage.ts";

const MIGRATION_NAME = "0026_legacy_empty_subscription_exports.sql";
const MIGRATION_SHA256 = "124eb153b8f8d1fc01165d2ba0db1adee8948cd6bffe8a8ad2465afa62da3976";

export async function legacyEmptyExportState(db: D1Database, token: string): Promise<"empty" | "published" | null> {
  // An older schema still serves published subscriptions without this feature.
  const candidate = await db.prepare(`
    SELECT generation, (SELECT count(*) FROM sqlite_schema WHERE type = 'table'
      AND name IN ('subs_bot_schema_migrations', 'legacy_empty_subscription_exports')) AS schemaTables
    FROM subscriptions WHERE token = ?
  `).bind(token).first<{ generation: number; schemaTables: number }>();
  if (!candidate) return null;
  if (candidate.generation > 0) return "published";
  if (candidate.schemaTables !== 2) return null;

  const digest = digestHex(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token)));
  // Match marker, active identity, empty state and applied migration in the same read.
  const current = await db.prepare(`
    SELECT sub.generation, (
      sub.generation = 0 AND sub.snapshot_id IS NULL AND sub.manifest_sha256 IS NULL AND sub.node_count = 0
      AND EXISTS (SELECT 1 FROM legacy_empty_subscription_exports AS marker
        WHERE marker.subscription_id = sub.id AND marker.owner_id = sub.owner_id AND marker.token_sha256 = ?)
      AND EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position = 26
        AND name = ? AND sha256 = ? AND mode = 'applied')
      AND NOT EXISTS (SELECT 1 FROM subscription_trash AS trash WHERE trash.id = sub.id OR trash.token = sub.token)
    ) AS marked
    FROM subscriptions AS sub WHERE sub.token = ?
  `).bind(digest, MIGRATION_NAME, MIGRATION_SHA256, token).first<{ generation: number; marked: number }>();
  if (!current) return null;
  if (current.generation > 0) return "published";
  return current.marked === 1 ? "empty" : null;
}

const EMPTY_CLASH = `proxies: []
proxy-groups:
- name: 🚀 节点选择
  type: select
  proxies:
  - DIRECT
- name: ♻️ 自动选择
  type: url-test
  proxies:
  - DIRECT
  url: http://www.gstatic.com/generate_204
  interval: 300
rules:
- MATCH,🚀 节点选择
`;
const EMPTY_SINGBOX = JSON.stringify({ outbounds: [
  { type: "selector", tag: "proxy", outbounds: ["direct"] },
  { type: "direct", tag: "direct" },
] }, null, 2);
const EMPTY_SURGE = "[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n";

export function legacyEmptyExportResponse(format: string, head: boolean, privacyHeaders: Record<string, string>): Response {
  let body: string;
  let contentType = "text/plain; charset=utf-8";
  switch (format) {
    case "clash":
      body = EMPTY_CLASH;
      contentType = "text/yaml; charset=utf-8";
      break;
    case "singbox":
    case "sing-box":
      body = EMPTY_SINGBOX;
      contentType = "application/json";
      break;
    case "surge":
      body = EMPTY_SURGE;
      break;
    case "base64":
    case "v2ray":
    case "mixed":
    case "qx":
    case "quantumult":
    case "quantumultx":
      body = "";
      break;
    default:
      throw new Error("Legacy empty export format unavailable.");
  }
  return new Response(head ? null : body, { headers: { ...privacyHeaders, "Content-Type": contentType } });
}

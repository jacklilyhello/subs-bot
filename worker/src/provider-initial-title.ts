import type { ProviderMetadata } from "./provider-fetch-contract.ts";

export const PROVIDER_INITIAL_TITLE_MIGRATION = "0041_telegram_provider_initial_titles.sql";
export const PROVIDER_INITIAL_TITLE_SHA256 = "e3b73a4584b38b0fa6fb9a4fe86705aa47193b1410094e740a771f977df410bf";
export const UNNAMED_PROVIDER_SUBSCRIPTION = "远程订阅";

const forbidden = /[\p{Cc}\p{Cf}\p{Cs}\u2028\u2029/\\]/u;

export async function providerInitialTitleReady(db: D1Database): Promise<boolean> {
  try {
    return await db.prepare(`SELECT 1 AS ready FROM subs_bot_schema_migrations
      WHERE position=41 AND name=? AND sha256=? AND mode='applied'
        AND (SELECT count(*) FROM sqlite_schema WHERE tbl_name='telegram_provider_initial_titles' AND (
          (type='table' AND name='telegram_provider_initial_titles') OR
          (type='index' AND name='telegram_provider_initial_titles_expiry')))=2`)
      .bind(PROVIDER_INITIAL_TITLE_MIGRATION, PROVIDER_INITIAL_TITLE_SHA256).first<number>("ready") === 1;
  } catch {
    return false;
  }
}

function unquote(value: string): string | null {
  const trimmed = value.trim();
  if (!/^["']/u.test(trimmed)) return trimmed;
  const quote = trimmed[0];
  const content = trimmed.slice(1, -1);
  return trimmed.length > 1 && trimmed.endsWith(quote) && !content.includes(quote) ? content : null;
}

function decodeTitle(value: string): string | null {
  try {
    if (!/^base64:/iu.test(value)) return decodeURIComponent(value);
    const encoded = value.slice(7);
    if (!/^[A-Za-z0-9+/_-]+={0,2}$/u.test(encoded)) return null;
    const decoded = atob(encoded.replace(/-/gu, "+").replace(/_/gu, "/"));
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(Uint8Array.from(decoded, (character) => character.charCodeAt(0)));
  } catch {
    return null;
  }
}

function dispositionTitle(value: string): string[] {
  const filename = new Map<string, string>();
  for (const part of value.split(";").slice(1)) {
    const match = /^\s*(filename\*?)\s*=\s*(.*?)\s*$/iu.exec(part);
    if (!match) continue;
    const key = match[1].toLowerCase();
    if (filename.has(key)) return [];
    const name = unquote(match[2]);
    if (name === null) return [];
    filename.set(key, name);
  }
  const utf8 = /^utf-8''(.*)$/iu.exec(filename.get("filename*") ?? "")?.[1] ?? "";
  return [utf8, filename.get("filename") ?? ""];
}

/** Only a bounded display label is eligible, never the transport header itself. */
export function initialProviderTitle(metadata: ProviderMetadata | undefined, sourceUrl: string): string | null {
  if (!metadata) return null;
  const source = new URL(sourceUrl);
  const sourceParts = [...source.searchParams.values(), ...source.pathname.split("/").map(decodeTitle)];
  const raw = [unquote(metadata["profile-title"] ?? ""), ...dispositionTitle(metadata["content-disposition"] ?? "")];
  for (const value of raw) {
    if (!value) continue;
    const title = decodeTitle(value)?.trim().replace(/\.(?:ya?ml|txt)$/iu, "").trim();
    if (!title || forbidden.test(title) || /[?&#=]|[A-Za-z0-9_-]{24,}/u.test(title)
        || sourceParts.some((part) => part && part.length >= 8 && title.includes(part))) continue;
    return Array.from(title).slice(0, 64).join("").trimEnd();
  }
  return null;
}

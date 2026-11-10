import { providerHost } from "../provider-jobs.ts";
import { normalizeSubscriptionName } from "../subscriptions.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "./document-transport.ts";
import { parseTelegramProviderText } from "./provider-replies.ts";

export const TELEGRAM_PROVIDER_DOCUMENT_MAX_URLS = 20;
const MAX_DISTINCT_URLS = 4096;
const HTTP_START = /^https?:\/\//iu;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export type TelegramProviderDocumentInput =
  | { kind: "url-list"; urls: string[]; overflow: number }
  | { kind: "invalid-url-list" }
  | { kind: "not-url-list" };

export type TelegramProviderUrlMessage = {
  entries: readonly { sourceUrl: string; name?: string }[];
  overflow: number;
};

function horizontalSpace(code: number): boolean {
  return code === 0x20 || code === 0x09;
}

/** Classify standalone URLs while leaving other document formats to node intake. */
export function parseTelegramProviderDocument(bytes: Uint8Array, suffix: string): TelegramProviderDocumentInput {
  if ((suffix !== "txt" && suffix !== "log") || bytes.byteLength > MAX_TELEGRAM_DOCUMENT_BYTES) {
    return { kind: "not-url-list" };
  }
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    return { kind: "not-url-list" };
  }

  const seen = new Set<string>();
  const urls: string[] = [];
  let invalid = false;
  let start = 0;
  while (start < text.length) {
    const newline = text.indexOf("\n", start);
    let from = start;
    let to = newline === -1 ? text.length : newline;
    start = to + 1;
    if (newline !== -1 && text.charCodeAt(to - 1) === 0x0d) to--;
    while (from < to && horizontalSpace(text.charCodeAt(from))) from++;
    while (from < to && horizontalSpace(text.charCodeAt(to - 1))) to--;
    if (from === to) continue;

    const url = text.slice(from, to);
    if (!HTTP_START.test(url)) return { kind: "not-url-list" };
    if (invalid || seen.has(url)) continue;
    if (seen.size >= MAX_DISTINCT_URLS || !providerHost(url)) {
      invalid = true;
      seen.clear();
      continue;
    }
    seen.add(url);
    if (urls.length < TELEGRAM_PROVIDER_DOCUMENT_MAX_URLS) urls.push(url);
  }
  if (invalid) return { kind: "invalid-url-list" };
  return urls.length === 0 ? { kind: "not-url-list" } : { kind: "url-list", urls, overflow: seen.size - urls.length };
}

/** Only the private multi-line message supports an explicit display name on each row. */
export function parseTelegramProviderUrlMessage(text: string): TelegramProviderUrlMessage | null {
  if (text.length > 4096 || !text.includes("\n") || /[\ud800-\udfff]/u.test(text)) return null;
  const rows = text.replace(/^\ufeff/u, "").split(/\r?\n/u).map((line) => line.replace(/^[ \t]+|[ \t]+$/gu, "")).filter(Boolean);
  if (rows.length < 2) return null;
  const seen = new Set<string>();
  const entries: TelegramProviderUrlMessage["entries"][number][] = [];
  for (const row of rows) {
    if (row.trim() !== row) return null;
    const parsed = parseTelegramProviderText(row);
    if (!parsed || !providerHost(parsed.sourceUrl) || (parsed.name === undefined && row.includes("|"))) return null;
    let name: string | undefined;
    try {
      if (parsed.name !== undefined) name = normalizeSubscriptionName(parsed.name);
    } catch {
      return null;
    }
    // The first exact URL owns its naming choice, including a bare first occurrence.
    if (seen.has(parsed.sourceUrl)) continue;
    seen.add(parsed.sourceUrl);
    if (entries.length < TELEGRAM_PROVIDER_DOCUMENT_MAX_URLS) entries.push(name === undefined
      ? { sourceUrl: parsed.sourceUrl } : { sourceUrl: parsed.sourceUrl, name });
  }
  return { entries, overflow: seen.size - entries.length };
}

import { providerHost } from "../provider-jobs.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "./document-transport.ts";

export const TELEGRAM_PROVIDER_DOCUMENT_MAX_URLS = 20;
const MAX_DISTINCT_URLS = 4096;
const HTTP_START = /^https?:\/\//iu;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

export type TelegramProviderDocumentInput =
  | { kind: "url-list"; urls: string[]; overflow: number }
  | { kind: "invalid-url-list" }
  | { kind: "not-url-list" };

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

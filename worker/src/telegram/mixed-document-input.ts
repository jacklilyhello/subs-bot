import type { NodeRecord } from "../storage.ts";
import { inspectPlainNodeText, parseNodeText } from "../text-import.ts";
import { MAX_TELEGRAM_DOCUMENT_NODES } from "./document-persistence.ts";
import { MAX_TELEGRAM_DOCUMENT_BYTES } from "./document-transport.ts";
import { parseTelegramProviderDocument } from "./provider-document-input.ts";

export type TelegramMixedDocumentInput =
  | { kind: "mixed"; nodes: readonly NodeRecord[]; urls: string[]; overflow: number }
  | { kind: "invalid-mixed" }
  | { kind: "not-mixed" };

const HTTP_ROW = /^https?:\//iu;
const SHARE_ROW = /^([A-Za-z][A-Za-z0-9+.-]{0,31}):\//u;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const encoder = new TextEncoder();

function horizontalSpace(code: number): boolean {
  return code === 0x20 || code === 0x09;
}

function* lines(text: string): Iterable<string> {
  let start = 0;
  while (start < text.length) {
    const newline = text.indexOf("\n", start);
    const end = newline === -1 ? text.length : newline;
    let from = start;
    let to = newline !== -1 && text.charCodeAt(end - 1) === 0x0d ? end - 1 : end;
    while (from < to && horizontalSpace(text.charCodeAt(from))) from++;
    while (from < to && horizontalSpace(text.charCodeAt(to - 1))) to--;
    yield text.slice(from, to);
    start = end + 1;
  }
}

/** Classify whole plain rows before either import path can persist a partial file. */
export function parseTelegramMixedDocument(bytes: Uint8Array, suffix: string): TelegramMixedDocumentInput {
  if ((suffix !== "txt" && suffix !== "log") || bytes.byteLength > MAX_TELEGRAM_DOCUMENT_BYTES) {
    return { kind: "not-mixed" };
  }
  let text: string;
  try {
    text = utf8.decode(bytes);
  } catch {
    return { kind: "not-mixed" };
  }

  const nodeRows: string[] = [];
  let hasNode = false;
  let hasUrl = false;
  let invalid = false;
  for (const line of lines(text)) {
    const nodeLine = line.trim();
    if (line.includes("\r")) invalid = true;
    if (!nodeLine || nodeLine.startsWith("#")) continue;
    if (HTTP_ROW.test(line)) {
      hasUrl = true;
    } else {
      const scheme = SHARE_ROW.exec(nodeLine)?.[1];
      if (scheme === undefined || nodeRows.length === MAX_TELEGRAM_DOCUMENT_NODES) invalid = true;
      else nodeRows.push(nodeLine);
      // Use the node parser's scheme inventory even when a candidate row is malformed.
      if (!hasNode && scheme !== undefined) {
        hasNode = inspectPlainNodeText(`${scheme}://fixture`)?.unsupported === 0;
      }
    }
    if (invalid && hasNode && hasUrl) return { kind: "invalid-mixed" };
  }
  if (!hasNode || !hasUrl) return { kind: "not-mixed" };
  if (invalid) return { kind: "invalid-mixed" };

  const nodeText = nodeRows.join("\n");
  const shape = inspectPlainNodeText(nodeText);
  if (!shape || shape.unsupported !== 0 || shape.rows !== nodeRows.length) return { kind: "invalid-mixed" };
  const parsed = parseNodeText(nodeText, {
    maxInputBytes: MAX_TELEGRAM_DOCUMENT_BYTES, maxNodes: MAX_TELEGRAM_DOCUMENT_NODES,
  });
  if (parsed.kind !== "parsed" || parsed.rejected.malformed || parsed.rejected.unsupported || parsed.ignored ||
      parsed.nodes.length !== nodeRows.length) return { kind: "invalid-mixed" };

  // The URL partition cannot grow except for one final LF. Keep its allocation
  // bounded by the original file rather than retaining an array of all rows.
  const urlBytes = new Uint8Array(bytes.byteLength + 1);
  let end = 0;
  for (const line of lines(text)) {
    if (!HTTP_ROW.test(line)) continue;
    end += encoder.encodeInto(line, urlBytes.subarray(end)).written;
    urlBytes[end++] = 0x0a;
  }
  const urls = parseTelegramProviderDocument(urlBytes.subarray(0, end), suffix);
  if (urls.kind !== "url-list") return { kind: "invalid-mixed" };
  return { kind: "mixed", nodes: parsed.nodes, urls: urls.urls, overflow: urls.overflow };
}

import { validInteger, type NodeRecord } from "./storage.ts";
import {
  MAX_STRUCTURED_DEPTH, MAX_STRUCTURED_INPUT_BYTES, MAX_STRUCTURED_NODES,
  parseStructuredNodeDocument, type StructuredImportResult,
} from "./structured-import.ts";
import { decodeCanonicalNodeDocumentBase64, inspectPlainNodeText, parseNodeText } from "./text-import.ts";

type Syntax = "auto" | "yaml" | "json";
type Envelope = "plain" | "base64";
type Limit = Extract<StructuredImportResult, { kind: "limit" }>["limit"];

interface DocumentReport {
  format: "text" | StructuredImportResult["format"];
  envelope: Envelope;
  nodes: NodeRecord[];
  rejected: { malformed: number; unsupported: number };
  ignored: number;
  ndjsonBytes: number;
}

export type SubscriptionDocumentResult = DocumentReport & (
  | { kind: "parsed" | "no-nodes" | "invalid-encoding" | "malformed" | "unsupported" }
  | { kind: "limit"; limit: Limit }
);

const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ENCODER = new TextEncoder();

function empty(envelope: Envelope, format: DocumentReport["format"] = null): DocumentReport {
  return { envelope, format, nodes: [], rejected: { malformed: 0, unsupported: 0 }, ignored: 0, ndjsonBytes: 0 };
}

function decodeBytes(input: Uint8Array): string | null {
  const [a, b, c, d] = input;
  if ((a === 0xff && b === 0xfe && c === 0 && d === 0) || (a === 0 && b === 0 && c === 0xfe && d === 0xff)) return null;
  const utf16 = a === 0xff && b === 0xfe ? "utf-16le" : a === 0xfe && b === 0xff ? "utf-16be" : null;
  const utf8Bom = a === 0xef && b === 0xbb && c === 0xbf;
  try {
    if (utf16) return new TextDecoder(utf16, { fatal: true, ignoreBOM: true }).decode(input.subarray(2));
    return UTF8.decode(utf8Bom ? input.subarray(3) : input);
  } catch {
    if (utf16 || utf8Bom) return null;
  }
  try {
    return new TextDecoder("gb18030", { fatal: true, ignoreBOM: true }).decode(input);
  } catch {
    return null;
  }
}

/** Admit one subscription document without reinterpreting structured metadata as URI rows. */
export function parseSubscriptionDocument(
  input: string | Uint8Array,
  { syntax = "auto", maxInputBytes = MAX_STRUCTURED_INPUT_BYTES, maxNodes = MAX_STRUCTURED_NODES,
    maxDepth = MAX_STRUCTURED_DEPTH }: { syntax?: Syntax; maxInputBytes?: number; maxNodes?: number; maxDepth?: number } = {},
): SubscriptionDocumentResult {
  if ((syntax !== "auto" && syntax !== "yaml" && syntax !== "json") ||
      !validInteger(maxInputBytes, 1, MAX_STRUCTURED_INPUT_BYTES) || !validInteger(maxNodes, 1, MAX_STRUCTURED_NODES) ||
      !validInteger(maxDepth, 1, MAX_STRUCTURED_DEPTH)) throw new RangeError("Invalid subscription document limits.");

  if ((typeof input === "string" ? input.length : input.byteLength) > maxInputBytes) {
    return { kind: "limit", limit: "input-bytes", ...empty("plain") };
  }
  let text = typeof input === "string" ? input : decodeBytes(input);
  if (text === null || /[\ud800-\udfff]/u.test(text)) return { kind: "invalid-encoding", ...empty("plain") };
  if (typeof input === "string" && input.length * 3 > maxInputBytes &&
      ENCODER.encodeInto(input, new Uint8Array(maxInputBytes)).read !== input.length) {
    return { kind: "limit", limit: "input-bytes", ...empty("plain") };
  }
  text = text.replace(/^\ufeff/u, "");
  let envelope: Envelope = "plain";
  const decoded = decodeCanonicalNodeDocumentBase64(text);
  if (decoded) {
    envelope = "base64";
    text = decodeBytes(decoded);
    if (text === null || /[\ud800-\udfff]/u.test(text)) return { kind: "invalid-encoding", ...empty(envelope) };
    text = text.replace(/^\ufeff/u, "");
  }

  if (!text.trim()) return { kind: "no-nodes", ...empty(envelope) };
  const uriList = syntax === "auto" ? inspectPlainNodeText(text) : null;
  if (!uriList) return { ...parseStructuredNodeDocument(text, { syntax: syntax === "json" ? "json" : "yaml",
    maxInputBytes, maxNodes, maxDepth }), envelope };
  if (uriList.rows > maxNodes) return { kind: "limit", limit: "nodes", ...empty(envelope, "text") };
  const parsed = parseNodeText(text, { maxInputBytes, maxNodes });
  if (parsed.kind === "limit") return { kind: "limit", limit: parsed.limit, ...empty(envelope, "text") };
  if (parsed.kind === "invalid-encoding") return { kind: "invalid-encoding", ...empty(envelope, "text") };
  const rejected = { malformed: parsed.rejected.malformed, unsupported: parsed.rejected.unsupported + uriList.unsupported };
  const kind = parsed.nodes.length ? "parsed" : rejected.malformed ? "malformed" : rejected.unsupported ? "unsupported" : "no-nodes";
  return { kind, format: "text", envelope, nodes: parsed.nodes, rejected, ignored: parsed.ignored - uriList.unsupported,
    ndjsonBytes: parsed.ndjsonBytes };
}

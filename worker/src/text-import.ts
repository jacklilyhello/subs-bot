import { MAX_CHUNK_BYTES, MAX_SNAPSHOT_BYTES, validInteger } from "./storage.ts";
import { isValidStoredShare, numberInRange, parseStoredVmessJson, splitOnce } from "./stored-share.ts";

export interface ImportedTextNode extends Record<string, unknown> {
  name: string;
  type: string;
  share: string;
}

type InputFormat = "text" | "base64";
type Limit = "input-bytes" | "nodes" | "node-bytes" | "snapshot-bytes";

interface ImportReport {
  format: InputFormat;
  nodes: ImportedTextNode[];
  rejected: { malformed: number; unsupported: number };
  ignored: number;
  rawOnly: number;
  ndjsonBytes: number;
}

export type TextImportResult =
  | (ImportReport & { kind: "parsed" | "no-nodes" | "invalid-encoding" })
  | (ImportReport & { kind: "limit"; limit: Limit });

export const MAX_NODE_TEXT_INPUT_BYTES = 10 * 1024 * 1024;
export const MAX_NODE_TEXT_NODES = 5_000;
const DEFAULT_INPUT_BYTES = 64 * 1024;
const DEFAULT_NODE_COUNT = 500;
// Include currently supported passthroughs and detect the legacy explicitly
// unsupported Realm variants as candidates, even when their payload is empty.
const SHARE_SCHEMES = new Set([
  "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2",
  "tuic", "snell", "wireguard", "anytls", "socks5", "socks5-tls",
  "hysteria2+realm", "hysteria2+realm+http",
]);
const HY2_OPTIONS = new Set(["auth", "mport", "sni", "insecure", "obfs", "obfs-password", "pinSHA256", "ech"]);
const BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const INVALID_ENCODED_TEXT = Symbol("invalid-encoded-node-text");
const encoder = new TextEncoder();
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const displayUtf8 = new TextDecoder("utf-8", { fatal: false, ignoreBOM: true });

function base64Binary(input: string): string | null {
  const match = /^([A-Za-z0-9+/_-]+)(={0,2})(?![\s\S])/u.exec(input);
  if (!match) return null;
  const [, encoded, padding] = match;
  const remainder = encoded.length % 4;
  if (remainder === 1 || (padding && padding.length !== (4 - remainder) % 4)
    || (/[-_]/u.test(encoded) && /[+/]/u.test(encoded))) return null;
  const standard = encoded.replaceAll("-", "+").replaceAll("_", "/");
  const last = BASE64.indexOf(standard[standard.length - 1]);
  if ((remainder === 2 && (last & 15) !== 0) || (remainder === 3 && (last & 3) !== 0)) return null;
  return atob(standard);
}

function binaryBytes(binary: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Decode a canonical document envelope, including ASCII whitespace folding. */
export function decodeCanonicalNodeDocumentBase64(text: string): Uint8Array<ArrayBuffer> | null {
  if (/[^A-Za-z0-9+/_=\- \t\r\n]/u.test(text)) return null;
  const compact = text.replace(/[ \t\r\n]/gu, "");
  if (compact.length < 16 && !compact.endsWith("=")) return null;
  const binary = base64Binary(compact);
  return binary === null ? null : binaryBytes(binary);
}

function decodedText(input: string): string | typeof INVALID_ENCODED_TEXT | null {
  if (input.length < 6) return null;
  let binary: string | null;
  try {
    binary = base64Binary(input);
  } catch {
    return null;
  }
  if (binary === null) return null;
  try {
    return utf8.decode(binaryBytes(binary));
  } catch {
    // A known URI prefix makes the encoding failure reportable. Arbitrary
    // Base64-looking prose need not decode as a subscription.
    return hasCandidate(binary.replace(/^\xef\xbb\xbf/u, "")) ? INVALID_ENCODED_TEXT : null;
  }
}

function uriLabel(fragment: string | undefined, scheme: string): string {
  if (fragment === undefined) return `${scheme.toUpperCase()} 节点`;
  // Legacy labels replace invalid UTF-8 runs while keeping the URI itself exact.
  const decoded = fragment.replace(/(?:%[a-f0-9]{2})+/giu, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(run.slice(i * 3 + 1, i * 3 + 3), 16);
    return displayUtf8.decode(bytes);
  });
  return decoded || "未命名";
}

function vmessLabel(address: string): string | null {
  if (address.includes("@")) return null;
  const label = parseStoredVmessJson(address)?.ps;
  return typeof label === "string" && label && !/[\ud800-\udfff]/u.test(label) ? label : null;
}

function validRanges(value: string): boolean {
  for (const span of value.split(",")) {
    const [from, to] = splitOnce(span, "-");
    const first = numberInRange(from, 1, 65535);
    if (first === null || (to !== undefined && numberInRange(to, first, 65535) === null)) return false;
  }
  return true;
}

type Rejected = keyof ImportReport["rejected"];

function hysteria2Fields(address: string): Record<string, unknown> | Rejected {
  if (/%(?![a-f0-9]{2})/iu.test(address)) return "malformed";
  const [hostPath, query] = splitOnce(address, "?");
  const [authority, path] = splitOnce(hostPath, "/");
  if (path !== undefined && path !== "") return "malformed";
  const at = authority.lastIndexOf("@");
  const endpoint = authority.slice(at + 1);
  // The stored-share validator checked the address, including IPv6 syntax.
  // Read the port list ourselves because URL rejects multi-port authorities.
  const host = endpoint.startsWith("[")
    ? /^\[([^\]]+)\](?::([^:]+))?(?![\s\S])/u.exec(endpoint)?.slice(1)
    : splitOnce(endpoint, ":");
  if (!host?.[0]) return "malformed";
  const [hostName, ports] = host;
  const [ipOrName, zone] = splitOnce(hostName, "%");
  const server = ipOrName.toLowerCase() + (zone === undefined ? "" : `%${zone}`);

  try {
    const options = new Map<string, string>();
    const fields = (query ?? "").split("&", 101);
    if (fields.length > 100) return "malformed";
    for (const field of fields) {
      if (!field) continue;
      const [key, value = ""] = splitOnce(field.replaceAll("+", " "), "=");
      const name = decodeURIComponent(key);
      if (!HY2_OPTIONS.has(name)) return "unsupported";
      if (options.has(name)) return "malformed";
      options.set(name, decodeURIComponent(value));
    }
    const auth = at < 0 ? "" : decodeURIComponent(authority.slice(0, at));
    const legacyAuth = options.get("auth") ?? "";
    const insecure = (options.get("insecure") ?? "0").toLowerCase();
    if ((auth && legacyAuth && auth !== legacyAuth) || !["0", "1", "false", "true"].includes(insecure)) return "malformed";

    const hopping = ports !== undefined && /[,-]/u.test(ports);
    const legacyPorts = options.get("mport");
    if (hopping && legacyPorts !== undefined) return "malformed";
    const ranges = hopping ? ports : legacyPorts;
    if (ranges !== undefined && !validRanges(ranges)) return "malformed";
    const node: Record<string, unknown> = {
      server, ...(ranges === undefined ? { port: ports === undefined ? 443 : Number(ports) } : { ports: ranges }),
      password: auth || legacyAuth, sni: options.get("sni") ?? "", "skip-cert-verify": insecure === "1" || insecure === "true",
    };
    const obfs = options.get("obfs");
    const password = options.get("obfs-password");
    if (obfs || password) {
      if (!obfs || !password) return "malformed";
      if (obfs !== "salamander" && obfs !== "gecko") return "unsupported";
      node.obfs = obfs;
      node["obfs-password"] = password;
    }
    const pin = options.get("pinSHA256")?.replaceAll(":", "");
    if (options.get("pinSHA256")) {
      if (!pin || !/^[a-f0-9]{64}(?![\s\S])/iu.test(pin)) return "malformed";
      node.fingerprint = pin.toLowerCase();
    }
    const ech = options.get("ech");
    if (ech) {
      // The raw validator already rejects non-inline ECH and its file fallback.
      const binary = base64Binary(ech);
      if (binary === null) return "malformed";
      node["ech-opts"] = { enable: true, config: btoa(binary) };
    }
    return node;
  } catch {
    return "malformed";
  }
}

function candidateScheme(line: string): string | null {
  const scheme = /^([A-Za-z][A-Za-z0-9+.-]{0,31}):\//u.exec(line)?.[1].toLowerCase();
  return scheme && SHARE_SCHEMES.has(scheme) ? scheme : null;
}

function* documentLines(text: string): Iterable<string> {
  let start = 0;
  for (const match of text.matchAll(/\r\n|\r|\n/gu)) {
    yield text.slice(start, match.index).trim();
    start = match.index + match[0].length;
  }
  yield text.slice(start).trim();
}

/** Recognize a complete URI list before allowing extraction from an ambiguous document. */
export function inspectPlainNodeText(text: string): { rows: number; unsupported: number } | null {
  let rows = 0;
  let unsupported = 0;
  for (const line of documentLines(text)) {
    if (!line || line.startsWith("#")) continue;
    const [address] = splitOnce(line, "#");
    // URI-shaped YAML keys can introduce a nested URI or block scalar.
    if (/\s/u.test(address) || /:\s/u.test(line) || line.endsWith(":")) return null;
    if (!candidateScheme(line)) {
      if (!/^[A-Za-z][A-Za-z0-9+.-]{0,31}:\/\//u.test(line)) return null;
      unsupported++;
    }
    rows++;
  }
  return { rows, unsupported };
}

function hasCandidate(text: string): boolean {
  for (const line of documentLines(text)) {
    if (candidateScheme(line)) return true;
  }
  return false;
}

function* logicalLines(text: string): Iterable<string | typeof INVALID_ENCODED_TEXT> {
  for (const line of documentLines(text)) {
    if (!line) continue;
    if (!candidateScheme(line)) {
      const decoded = decodedText(line);
      if (decoded === INVALID_ENCODED_TEXT) {
        yield decoded;
        continue;
      }
      if (typeof decoded === "string" && hasCandidate(decoded)) {
        for (const item of documentLines(decoded)) if (item) yield item;
        continue;
      }
    }
    yield line;
  }
}

function parseCandidate(share: string, scheme: string): ImportedTextNode | Rejected {
  if (scheme === "hysteria2+realm" || scheme === "hysteria2+realm+http") return "unsupported";
  if (!isValidStoredShare(share)) return "malformed";
  const [, payload = ""] = splitOnce(share, "://");
  const [address, fragment] = splitOnce(payload, "#");
  const name = (scheme === "vmess" ? vmessLabel(address) : null) ?? uriLabel(fragment, scheme);
  if (scheme !== "hy2" && scheme !== "hysteria2") {
    // The raw URI is authoritative. A minimal record does not imply that
    // arbitrary options are portable to a structured export.
    return { name, type: scheme, share };
  }
  const fields = hysteria2Fields(address);
  return typeof fields === "string" ? fields : { name, type: "hysteria2", share, ...fields };
}

function empty(format: InputFormat): ImportReport {
  return { format, nodes: [], rejected: { malformed: 0, unsupported: 0 }, ignored: 0, rawOnly: 0, ndjsonBytes: 0 };
}

function overLimit(format: InputFormat, limit: Limit): TextImportResult {
  return { kind: "limit", limit, ...empty(format) };
}

function scan(text: string, format: InputFormat, maxNodes: number): TextImportResult {
  const report = empty(format);
  for (const line of logicalLines(text)) {
    if (line === INVALID_ENCODED_TEXT) return { kind: "invalid-encoding", ...empty(format) };
    const scheme = candidateScheme(line);
    if (scheme === null) {
      report.ignored++;
      continue;
    }
    if (line.length >= MAX_CHUNK_BYTES) return overLimit(format, "node-bytes");
    const node = parseCandidate(line, scheme);
    if (typeof node === "string") {
      report.rejected[node]++;
      continue;
    }
    if (report.nodes.length === maxNodes) return overLimit(format, "nodes");
    const bytes = encoder.encode(JSON.stringify(node)).byteLength + 1;
    if (bytes > MAX_CHUNK_BYTES) return overLimit(format, "node-bytes");
    report.ndjsonBytes += bytes;
    if (report.ndjsonBytes > MAX_SNAPSHOT_BYTES) return overLimit(format, "snapshot-bytes");
    report.nodes.push(node);
    if (node.type !== "hysteria2") report.rawOnly++;
  }
  return { kind: report.nodes.length > 0 ? "parsed" : "no-nodes", ...report };
}

// Accept ordinary URI lists and canonical Base64 forms without guessing
// unknown binary encodings or parsing YAML and JSON documents as configuration.
export function parseNodeText(
  input: string | Uint8Array,
  { maxInputBytes = DEFAULT_INPUT_BYTES, maxNodes = DEFAULT_NODE_COUNT }: {
    maxInputBytes?: number; maxNodes?: number;
  } = {},
): TextImportResult {
  if (!validInteger(maxInputBytes, 1, MAX_NODE_TEXT_INPUT_BYTES) || !validInteger(maxNodes, 1, MAX_NODE_TEXT_NODES)) {
    throw new RangeError("Invalid node text import limits.");
  }
  let text: string;
  if (typeof input === "string") {
    if (input.length > maxInputBytes) return overLimit("text", "input-bytes");
    if (/[\ud800-\udfff]/u.test(input)) return { kind: "invalid-encoding", ...empty("text") };
    if (encoder.encode(input).byteLength > maxInputBytes) return overLimit("text", "input-bytes");
    text = input;
  } else {
    if (input.byteLength > maxInputBytes) return overLimit("text", "input-bytes");
    try {
      text = utf8.decode(input);
    } catch {
      return { kind: "invalid-encoding", ...empty("text") };
    }
  }
  text = text.trim();
  if (/^[A-Za-z0-9+/_=\- \t\r\n]+(?![\s\S])/u.test(text)) {
    // Folded documents get first refusal. Individual folds can decode to
    // partial URI strings and must never win over a complete document.
    const decoded = decodedText(text.replace(/[ \t\r\n]/gu, ""));
    if (decoded === INVALID_ENCODED_TEXT) return { kind: "invalid-encoding", ...empty("base64") };
    if (typeof decoded === "string") {
      const report = scan(decoded, "base64", maxNodes);
      if (report.kind !== "no-nodes" || report.rejected.malformed || report.rejected.unsupported) return report;
    }
  }
  return scan(text, "text", maxNodes);
}

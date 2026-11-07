import { Composer, CST, isMap, isScalar, isSeq, Lexer, Parser } from "yaml";
import { CONTROL, expandedHoppingPorts, ports, server } from "./proxy-input.ts";
import { MAX_CHUNK_BYTES, MAX_SNAPSHOT_BYTES, validInteger, type NodeRecord } from "./storage.ts";
import { numberInRange } from "./stored-share.ts";

type Format = "clash" | "singbox";
type Syntax = "yaml" | "json";
type Limit = "input-bytes" | "depth" | "complexity" | "nodes" | "node-bytes" | "snapshot-bytes";
type Rejection = "malformed" | "unsupported";
type JsonValue = null | string | number | boolean | JsonValue[] | { [key: string]: JsonValue };

export interface StructuredNode extends NodeRecord {
  name: string;
  type: string;
  share: "";
}

interface ImportReport {
  format: Format | null;
  nodes: StructuredNode[];
  rejected: Record<Rejection, number>;
  ignored: number;
  ndjsonBytes: number;
}

export type StructuredImportResult = ImportReport & (
  | { kind: "parsed" | "no-nodes" | "invalid-encoding" | Rejection }
  | { kind: "limit"; limit: Limit }
);

export const MAX_STRUCTURED_INPUT_BYTES = 10 * 1024 * 1024;
export const MAX_STRUCTURED_NODES = 5_000;
export const MAX_STRUCTURED_DEPTH = 32;
const MAX_LEXEMES = 250_000;
const MAX_NUMERIC_CHARS = 128;
const MAX_HOPPING_RANGES = 256;
const CLASH_TYPES = new Set([
  "ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks5", "http", "https",
]);
const SINGBOX_TYPES = new Set([
  "shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "anytls", "socks", "http",
]);
const SINGBOX_CONTROLS = new Set(["direct", "block", "dns", "selector", "urltest"]);
const UNSAFE_KEYS = new Set(["__proto__", "constructor", "prototype", "<<"]);
const SURROGATE = /[\ud800-\udfff]/u;
const NUMBER_TOKEN = /^(?:[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|0x[0-9a-fA-F]+|0o[0-7]+)(?![\s\S])/u;
const UTF8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const ENCODER = new TextEncoder();

class RejectedDocument extends Error {
  readonly reason: Rejection | Limit;

  constructor(reason: Rejection | Limit) {
    super();
    this.reason = reason;
  }
}

function reject(reason: Rejection | Limit): never {
  throw new RejectedDocument(reason);
}

function empty(format: Format | null = null): ImportReport {
  return { format, nodes: [], rejected: { malformed: 0, unsupported: 0 }, ignored: 0, ndjsonBytes: 0 };
}

function checkDepth(token: CST.Token, depth: number, maxDepth: number): void {
  if (!CST.isCollection(token)) return;
  if (depth === maxDepth) reject("depth");
  for (const { key, value } of token.items) {
    if (key) checkDepth(key, depth + 1, maxDepth);
    if (value) checkDepth(value, depth + 1, maxDepth);
  }
}

function* boundedTokens(text: string, maxDepth: number): Generator<CST.Token> {
  const parser = new Parser();
  let count = 0;
  let scalar = false;
  let documents = 0;
  function* check(tokens: Iterable<CST.Token>): Generator<CST.Token> {
    for (const token of tokens) {
      if (token.type === "error") reject("malformed");
      if (token.type === "document") {
        if (++documents > 1) reject("malformed");
        if (token.value) checkDepth(token.value, 0, maxDepth);
      }
      if (token.type === "comment" || token.type === "space" || token.type === "newline") continue;
      yield token;
    }
  }
  for (const lexeme of new Lexer().lex(text)) {
    if (++count > MAX_LEXEMES) reject("complexity");
    if (scalar) {
      scalar = false;
      // Avoid constructing a huge BigInt for an unquoted numeric scalar.
      if (lexeme.length > MAX_NUMERIC_CHARS && NUMBER_TOKEN.test(lexeme.trim())) reject("malformed");
    } else {
      const kind = CST.tokenType(lexeme);
      if (kind === "alias" || kind === "anchor" || kind === "tag" || kind === "directive-line") reject("unsupported");
      scalar = kind === "scalar";
    }
    yield* check(parser.next(lexeme));
    // Bound the parser's in-progress stack before composition as well as checking completed CSTs.
    if (parser.stack.length > maxDepth + 3) reject("depth");
  }
  yield* check(parser.end());
}

function* entries(node: { items: readonly { key: unknown; value: unknown }[] }): Generator<[string, unknown]> {
  const seen = new Set<string>();
  for (const { key, value } of node.items) {
    if (!isScalar(key) || typeof key.value !== "string" || !key.value || CONTROL.test(key.value)
      || SURROGATE.test(key.value) || UNSAFE_KEYS.has(key.value) || seen.has(key.value)) reject("malformed");
    seen.add(key.value);
    yield [key.value, value];
  }
}

function exactInteger(value: number, source: string | undefined): boolean {
  if (!Number.isSafeInteger(value) || source === undefined) return false;
  // Decimal/exponent forms resolving to an integer must not round a fraction into an endpoint number.
  const match = /^([+-]?)([0-9]*)(?:\.([0-9]*))?(?:[eE]([+-]?[0-9]+))?(?![\s\S])/u.exec(source);
  if (!match) return false;
  const fraction = match[3] ?? "";
  const digits = (match[2] + fraction).replace(/^0+/u, "");
  if (!digits) return value === 0;
  if (value === 0) return false;
  const power = Number(match[4] ?? 0) - fraction.length;
  if (!Number.isSafeInteger(power) || power > 15 || -power >= digits.length) return false;
  if (power < 0 && /[^0]/u.test(digits.slice(power))) return false;
  const whole = power < 0 ? digits.slice(0, power) : digits + "0".repeat(power);
  return whole.length <= 16 && Number(match[1] + whole) === value;
}

function readValue(node: unknown, retain: boolean, depth: number): JsonValue {
  if (node === null || node === undefined) return null;
  if (isScalar(node)) {
    const value = node.value;
    if (typeof value === "bigint") {
      const number = Number(value);
      if (!Number.isSafeInteger(number)) reject("malformed");
      return number;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value) || (Number.isInteger(value) && !exactInteger(value, node.source))) reject("malformed");
      return value;
    }
    if (typeof value === "string" && !SURROGATE.test(value)) return value;
    if (value === null || typeof value === "boolean") return value;
    return reject("malformed");
  }
  if (isMap(node)) {
    if (depth <= 0) reject("depth");
    const result: Record<string, JsonValue> | null = retain ? Object.create(null) : null;
    for (const [key, child] of entries(node)) {
      const value = readValue(child, retain, depth - 1);
      if (result) result[key] = value;
    }
    return result;
  }
  if (isSeq(node)) {
    if (depth <= 0) reject("depth");
    if (retain) return node.items.map((item) => readValue(item, true, depth - 1));
    for (const item of node.items) readValue(item, false, depth - 1);
    return null;
  }
  return reject("unsupported");
}

function label(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "" && !CONTROL.test(value);
}

function validPort(record: NodeRecord, format: Format, type: string): boolean {
  const port = format === "singbox" ? record.server_port : record.port;
  const ranges = format === "singbox" ? record.server_ports : record.ports;
  if (ranges === undefined || ranges === null || ranges === "") return numberInRange(port, 1, 65535) !== null;
  if (type !== "hysteria" && type !== "hysteria2" && type !== "hy2") return false;
  if (format === "singbox" ? Object.hasOwn(record, "server_port") : port != null && numberInRange(port, 1, 65535) === null) return false;
  const entries = typeof ranges === "string"
    ? format === "clash" ? ranges.split(",", MAX_HOPPING_RANGES + 1) : [ranges] : ranges;
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_HOPPING_RANGES) return false;
  try {
    expandedHoppingPorts(format === "clash" ? ports(entries) : entries);
    return true;
  } catch {
    return false;
  }
}

function classify(value: JsonValue, format: Format): StructuredNode | Rejection | "ignored" {
  if (!value || typeof value !== "object" || Array.isArray(value) || !label(value.type)) return "malformed";
  const type = value.type;
  if (format === "singbox" && SINGBOX_CONTROLS.has(type)) return "ignored";
  if (!(format === "clash" ? CLASH_TYPES : SINGBOX_TYPES).has(type)) return "unsupported";
  const name = format === "singbox" ? (value.tag === "" ? type : value.tag ?? type) : value.name;
  if (!label(name) || !validPort(value, format, type)) return "malformed";
  // These are internal URI overrides, never part of a native structured node.
  if ([value.share, value.raw].some((item) => item !== undefined && item !== null && item !== "")) return "unsupported";
  try {
    server(value.server);
  } catch {
    return "malformed";
  }
  const node: StructuredNode = { ...value, name, type, share: "" };
  if (format === "singbox") delete node.tag;
  return node;
}

interface Inventory {
  format: Format;
  items: unknown[];
  depth: number;
}

function inventory(root: unknown, maxDepth: number): Inventory | null {
  if (isSeq(root)) return { format: "clash", items: root.items, depth: maxDepth - 1 };
  if (!isMap(root)) {
    readValue(root, false, maxDepth);
    return null;
  }
  let result: Inventory | null = null;
  for (const [key, node] of entries(root)) {
    if (key !== "proxies" && key !== "outbounds") {
      readValue(node, false, maxDepth - 1);
      continue;
    }
    if (result || !isSeq(node)) reject("malformed");
    if (maxDepth < 2) reject("depth");
    result = { format: key === "proxies" ? "clash" : "singbox", items: node.items, depth: maxDepth - 2 };
  }
  return result;
}

/** Parse one structured provider document without falling back to URI extraction. */
export function parseStructuredNodeDocument(
  input: string | Uint8Array,
  { syntax = "yaml", maxInputBytes = MAX_STRUCTURED_INPUT_BYTES, maxNodes = MAX_STRUCTURED_NODES,
    maxDepth = MAX_STRUCTURED_DEPTH }: { syntax?: Syntax; maxInputBytes?: number; maxNodes?: number; maxDepth?: number } = {},
): StructuredImportResult {
  if ((syntax !== "yaml" && syntax !== "json") || !validInteger(maxInputBytes, 1, MAX_STRUCTURED_INPUT_BYTES)
    || !validInteger(maxNodes, 1, MAX_STRUCTURED_NODES) || !validInteger(maxDepth, 1, MAX_STRUCTURED_DEPTH)) {
    throw new RangeError("Invalid structured node import limits.");
  }
  let text;
  if (typeof input === "string") {
    if (input.length > maxInputBytes) return { kind: "limit", limit: "input-bytes", ...empty() };
    if (SURROGATE.test(input)) return { kind: "invalid-encoding", ...empty() };
    if (ENCODER.encodeInto(input, new Uint8Array(Math.min(maxInputBytes, input.length * 3))).read !== input.length) {
      return { kind: "limit", limit: "input-bytes", ...empty() };
    }
    text = input;
  } else {
    if (input.byteLength > maxInputBytes) return { kind: "limit", limit: "input-bytes", ...empty() };
    try {
      text = UTF8.decode(input);
    } catch {
      return { kind: "invalid-encoding", ...empty() };
    }
  }
  text = text.replace(/^\ufeff/u, "");
  let format: Format | null = null;
  try {
    if (/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/u.test(text)) reject("malformed");
    const docs = Array.from(new Composer({ version: "1.2", schema: "core", intAsBigInt: true, merge: false,
      resolveKnownTags: false, strict: true, prettyErrors: false, logLevel: "silent", uniqueKeys: false })
      .compose(boundedTokens(text, maxDepth)));
    if (syntax === "json") JSON.parse(text);
    if (docs.length === 0) return { kind: "no-nodes", ...empty() };
    const [doc] = docs;
    if (doc.errors.some((error) => error.code === "RESOURCE_EXHAUSTION")) reject("depth");
    if (docs.length !== 1 || doc.errors.length || doc.warnings.length) reject("malformed");
    const source = inventory(doc.contents, maxDepth);
    if (!source) return { kind: "no-nodes", ...empty() };
    format = source.format;
    if (source.items.length > maxNodes) reject("nodes");
    const report = empty(format);
    for (const item of source.items) {
      const value = classify(readValue(item, true, source.depth), format);
      if (value === "ignored") report.ignored++;
      else if (typeof value === "string") report.rejected[value]++;
      else {
        const json = JSON.stringify(value);
        if (json.length >= MAX_CHUNK_BYTES) reject("node-bytes");
        const size = ENCODER.encode(json).byteLength + 1;
        if (size > MAX_CHUNK_BYTES) reject("node-bytes");
        report.ndjsonBytes += size;
        if (report.ndjsonBytes > MAX_SNAPSHOT_BYTES) reject("snapshot-bytes");
        report.nodes.push(value);
      }
    }
    const kind = report.nodes.length ? "parsed" : report.rejected.malformed ? "malformed"
      : report.rejected.unsupported ? "unsupported" : "no-nodes";
    return { kind, ...report };
  } catch (error) {
    // Parser diagnostics can contain arbitrary provider credentials and must never escape.
    const reason = error instanceof RejectedDocument ? error.reason : "malformed";
    return reason === "malformed" || reason === "unsupported" ? { kind: reason, ...empty(format) }
      : { kind: "limit", limit: reason, ...empty(format) };
  }
}

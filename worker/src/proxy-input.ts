import {
  isValidStoredShare, normalizeInlineEch, numberInRange, parseStoredShadowsocks, parseStoredVmessJson, splitOnce, validIpv6,
} from "./stored-share.ts";
import type { NodeRecord } from "./storage.ts";

export type Fields = NodeRecord;
type ProxyExportFormat = "singbox" | "clash" | "surge" | "qx";
const ALIASES = new Map([["ss", "shadowsocks"], ["hy2", "hysteria2"], ["socks5", "socks"], ["https", "http"]]);
const RAW_SCHEMES = new Set(["ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks5"]);
const CLASH_HYSTERIA2_QUERY = new Set(["auth", "mport", "sni", "insecure", "obfs", "obfs-password", "pinSHA256", "ech"]);
export const TLS_REQUIRED = new Set(["hysteria", "hysteria2", "tuic", "anytls"]);
export const TRANSPORT_PROTOCOLS = new Set(["vmess", "vless", "trojan"]);
export const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const SURROGATE = /[\ud800-\udfff]/u;
const LEGACY_METADATA = new Set(["name", "tag", "type", "share", "raw"]);
const MAX_HOPPING_PORTS_PER_OUTBOUND = 65535;
const MIN_HYSTERIA1_BYTES_PER_SECOND = 16384n;
const MAX_UINT64 = 2n ** 64n - 1n;

export class ProxyInputError extends Error {}

export function unsupported(): never {
  throw new ProxyInputError();
}

export function isRecord(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function fields(value: unknown): Fields {
  return isRecord(value) ? Object.assign(Object.create(null), value) as Fields : unsupported();
}

export function take(source: Fields, key: string, fallback: unknown = undefined): unknown {
  if (!Object.hasOwn(source, key)) return fallback;
  const value = source[key];
  delete source[key];
  return value;
}

export function scalarAlias(source: Fields, keys: string[], fallback?: unknown): unknown {
  let value: unknown;
  for (const key of keys) {
    if (!Object.hasOwn(source, key)) continue;
    const next = take(source, key);
    if (value !== undefined && value !== next) unsupported();
    value = next;
  }
  return value === undefined ? fallback : value;
}

export function empty(value: unknown): boolean {
  return value === undefined || value === null || value === ""
    || (Array.isArray(value) && value.length === 0) || (isRecord(value) && Object.keys(value).length === 0);
}

export function requireConsumed(source: Fields): void {
  if (Object.values(source).some((value) => !empty(value))) unsupported();
}

export function copy(source: Fields, output: Fields, names: Record<string, string>): void {
  for (const [from, to] of Object.entries(names)) {
    if (Object.hasOwn(source, from)) output[to] = take(source, from);
  }
}

export const isString = (value: unknown): value is string => typeof value === "string" && !SURROGATE.test(value);
export const isNonempty = (value: unknown): value is string => isString(value) && value.trim() !== "";

export function string(value: unknown, allowEmpty = false): string {
  return (allowEmpty ? isString(value) : isNonempty(value)) ? value as string : unsupported();
}

export function integer(value: unknown, minimum: number, maximum: number): number {
  return numberInRange(value, minimum, maximum) ?? unsupported();
}

export function flag(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === 0 || typeof value === "string") {
    const candidate = String(value).toLowerCase();
    if (candidate === "1" || candidate === "true") return true;
    if (candidate === "0" || candidate === "false") return false;
  }
  return unsupported();
}

export function server(value: unknown): string {
  let host = string(value);
  if (host.startsWith("[") && host.endsWith("]")) host = host.slice(1, -1);
  if (host.includes(":")) return validIpv6(host) ? host : unsupported();
  // Require an ASCII hostname or its explicit A-label. WHATWG and Python
  // normalize some Unicode domains to different destinations.
  const name = host.endsWith(".") ? host.slice(0, -1) : host;
  if (name.length > 253 || !name.split(".").every((label) =>
    /^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?(?![\s\S])/u.test(label))) unsupported();
  return host;
}

export function normalizeList(value: unknown): string[] {
  const values: unknown = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(values)) return unsupported();
  return values.map((item: unknown) => string(item).trim());
}

export function ports(value: unknown): string[] {
  const items = normalizeList(value);
  if (items.length === 0) unsupported();
  return items.map((item) => {
    const match = /^([0-9]{1,5})(?:[-:]([0-9]{1,5}))?(?![\s\S])/u.exec(item);
    if (!match) return unsupported();
    const start = integer(match[1], 1, 65535);
    const end = integer(match[2] ?? match[1], start, 65535);
    return start + ":" + end;
  });
}

export function expandedHoppingPorts(value: unknown): number {
  const ranges: unknown[] = Array.isArray(value) ? value : [value];
  if (ranges.length === 0) unsupported();
  let total = 0;
  for (const range of ranges) {
    const match = typeof range === "string" && /^([0-9]{1,5}):([0-9]{1,5})(?![\s\S])/u.exec(range);
    if (!match) return unsupported();
    const start = integer(match[1], 1, 65535);
    const end = integer(match[2], start, 65535);
    // The client expands each range, including duplicates and overlaps.
    total += end - start + 1;
    if (total > MAX_HOPPING_PORTS_PER_OUTBOUND) unsupported();
  }
  return total;
}

export function validHysteria1Bandwidth(value: unknown, mbps: unknown): boolean {
  if (value === undefined) return typeof mbps === "number" && mbps > 0;
  if (!isString(value)) return false;
  const match = /^([0-9]{1,20}) *([KMGT]?)([bB])ps(?![\s\S])/u.exec(value);
  if (!match) return false;
  const exponent = match[2] ? "KMGT".indexOf(match[2]) + 1 : 0;
  const count = BigInt(match[1]) * 1000n ** BigInt(exponent);
  return count <= MAX_UINT64 && count / (match[3] === "b" ? 8n : 1n) >= MIN_HYSTERIA1_BYTES_PER_SECOND;
}

function uriParts(address: string): [string, Fields] {
  const [unlabeled] = splitOnce(address, "#");
  const [hierarchy, query] = splitOnce(unlabeled, "?");
  const [authority, path] = splitOnce(hierarchy, "/");
  if ((path !== undefined && path !== "") || /[\\\p{White_Space}]/u.test(authority)) unsupported();
  const options: Fields = Object.create(null);
  if (!query) return [authority, options];
  const parameters = query.split("&", 101);
  if (parameters.length > 100) unsupported();
  for (const parameter of parameters) {
    if (!parameter) continue;
    const [rawKey, rawValue = ""] = splitOnce(parameter, "=");
    const key = decodeURIComponent(rawKey.replaceAll("+", " "));
    if (Object.hasOwn(options, key)) unsupported();
    options[key] = decodeURIComponent(rawValue.replaceAll("+", " "));
  }
  return [authority, options];
}

function uriEndpoint(endpoint: string): [string, string | undefined] {
  const parsed = endpoint.startsWith("[") ? /^\[([^\]]+)\](?::([^:]+))?(?![\s\S])/u.exec(endpoint)
    : /^([^:[\]]+)(?::([^:]+))?(?![\s\S])/u.exec(endpoint);
  if (!parsed) return unsupported();
  return [server(parsed[1]).toLowerCase(), parsed[2]];
}

function uriTransport(source: Fields, options: Fields, kind: string): void {
  const header = take(options, "headerType", "none");
  if (header !== "" && header !== "none") unsupported();
  source.network = kind;
  if (kind === "grpc") {
    const mode = take(options, "mode", "gun");
    if (mode !== "" && mode !== "gun") unsupported();
    source["grpc-opts"] = { "grpc-service-name": take(options, "serviceName", "") };
  } else if (["ws", "http", "h2", "httpupgrade"].includes(kind)) {
    const settings: Fields = {};
    const host = take(options, "host", "");
    let path = string(take(options, "path", ""), true);
    if (kind === "ws") {
      if (!empty(host)) settings.headers = { Host: host };
      const earlyData = /^(.*)\?ed=([0-9]+)(?![\s\S])/u.exec(path);
      if (earlyData) {
        path = earlyData[1];
        settings["max-early-data"] = earlyData[2];
        settings["early-data-header-name"] = "Sec-WebSocket-Protocol";
      }
    } else if (!empty(host)) settings.host = kind === "httpupgrade" ? host : normalizeList(host);
    if (path) settings.path = path;
    source[kind + "-opts"] = settings;
  }
}

function uriTls(source: Fields, options: Fields, protocol: string): void {
  const security = take(options, "security", TLS_REQUIRED.has(protocol) || protocol === "trojan" ? "tls" : "none");
  if (security !== "" && security !== "none" && security !== "tls" && security !== "reality") unsupported();
  source.tls = security === "tls" || security === "reality";
  copy(options, source, { sni: "sni", alpn: "alpn", fp: "client-fingerprint", disable_sni: "disable-sni" });
  const insecure = scalarAlias(options, ["allowInsecure", "allow_insecure", "insecure"]);
  if (!empty(insecure)) source["skip-cert-verify"] = insecure;
  if (security === "reality") {
    source["reality-opts"] = { "public-key": take(options, "pbk"), "short-id": take(options, "sid", "") };
    source["client-fingerprint"] ??= "chrome";
  }
}

function vmessUri(address: string): Fields {
  const data = fields(parseStoredVmessJson(address));
  const alterId = take(data, "aid", 0);
  const cipher = take(data, "scy", "auto");
  const source: Fields = {
    server: take(data, "add"), port: take(data, "port"), uuid: take(data, "id"),
    alterId: empty(alterId) ? 0 : alterId, cipher: empty(cipher) ? "auto" : cipher,
  };
  for (const key of ["v", "ps"]) delete data[key];
  const network = take(data, "net", "tcp");
  const kind = empty(network) ? "tcp" : string(network);
  const options: Fields = {};
  copy(data, options, {
    host: "host", path: "path", sni: "sni", alpn: "alpn", fp: "fp", type: "headerType",
    allowInsecure: "allowInsecure", insecure: "insecure",
  });
  const security = take(data, "tls", "");
  if (security === "tls" || security === true || security === "1") options.security = "tls";
  else if (security !== "" && security !== "none" && security !== false && security !== "0" && security !== null) unsupported();
  if (kind === "grpc") copy(options, options, { path: "serviceName" });
  uriTransport(source, options, kind);
  uriTls(source, options, "vmess");
  requireConsumed(options);
  requireConsumed(data);
  return source;
}

function uriSource(share: string, scheme: string, protocol: string, address: string, format: ProxyExportFormat): Fields {
  if (/[\p{White_Space}\\]/u.test(address)) unsupported();
  if (protocol === "vmess") return vmessUri(address);
  if (protocol === "shadowsocks") {
    const parsed = parseStoredShadowsocks(address, true);
    if (!parsed) return unsupported();
    const [endpoint, port] = uriEndpoint(parsed.endpoint);
    const [, options] = uriParts(parsed.address);
    const plugin = take(options, "plugin", "");
    const source: Fields = { server: endpoint, port, cipher: parsed.method, password: parsed.password };
    if (plugin) {
      const [name, settings = ""] = splitOnce(string(plugin), ";");
      source.plugin = name;
      source["plugin-opts"] = settings;
    }
    requireConsumed(options);
    return source;
  }

  if (!TLS_REQUIRED.has(protocol) && !TRANSPORT_PROTOCOLS.has(protocol) && scheme !== "socks5") unsupported();
  const [authority, options] = uriParts(address);
  const [first, second] = splitOnce(authority, "@");
  const endpoint = second ?? first;
  const auth = second === undefined ? undefined : first;
  if (auth !== undefined && (!auth || endpoint.includes("@"))) unsupported();
  const [host, port] = uriEndpoint(endpoint);
  if (port !== undefined && protocol !== "hysteria" && protocol !== "hysteria2") integer(port, 1, 65535);
  const hopping = port !== undefined && /[,-]/u.test(port) && (protocol === "hysteria" || protocol === "hysteria2");
  if (!isValidStoredShare(share)) {
    // Legacy Sing-box uses 443 for Hysteria 1 and Trojan. The Base64
    // forwarder also has a narrower Hysteria 1 hopping policy.
    if (protocol === "hysteria" && hopping) ports(port);
    else if (port !== undefined || (protocol !== "hysteria" && protocol !== "trojan")
      || !isValidStoredShare(scheme + "://" + authority + ":443")) unsupported();
  }
  const source: Fields = { server: host };
  if (protocol === "hysteria2" && format !== "singbox") {
    if (Object.keys(options).some((key) => !CLASH_HYSTERIA2_QUERY.has(key))
      || options.pinSHA256 || (Object.hasOwn(options, "mport") && (hopping || options.mport === ""))) unsupported();
    if (Object.hasOwn(options, "insecure")) flag(options.insecure);
    if (Object.hasOwn(options, "mport") && !/^[0-9]+(?:-[0-9]+)?(?:,[0-9]+(?:-[0-9]+)?)*(?![\s\S])/u.test(string(options.mport))) unsupported();
    const ech = take(options, "ech");
    if (!empty(ech)) {
      const config = normalizeInlineEch(string(ech));
      if (config === null) unsupported();
      source["ech-opts"] = { enable: true, config };
    }
  }
  if (hopping) {
    if (!empty(take(options, "mport"))) unsupported();
    source.ports = port;
  } else source.port = port ?? (TLS_REQUIRED.has(protocol) || protocol === "trojan" ? 443 : undefined);
  if (TRANSPORT_PROTOCOLS.has(protocol)) uriTransport(source, options, string(take(options, "type", "tcp"), true));
  if (protocol === "hysteria") {
    // The Hysteria v1 URI uses peer for TLS SNI.
    const sni = scalarAlias(options, ["sni", "peer"]);
    if (sni !== undefined) options.sni = sni;
  }
  if (TLS_REQUIRED.has(protocol) || TRANSPORT_PROTOCOLS.has(protocol)) uriTls(source, options, protocol);

  const [rawUser, rawPassword] = splitOnce(auth ?? "", ":");
  const user = decodeURIComponent(rawUser);
  const password = rawPassword === undefined ? undefined : decodeURIComponent(rawPassword);
  const combined = password === undefined ? user : user + ":" + password;
  if (protocol === "vless") {
    if (password || !["", "none"].includes(string(take(options, "encryption", "none"), true))) unsupported();
    source.uuid = user;
    copy(options, source, { flow: "flow", packetEncoding: "packet-encoding" });
  } else if (protocol === "tuic") {
    source.uuid = user;
    source.password = password ?? "";
    copy(options, source, {
      congestion_control: "congestion-controller", udp_relay_mode: "udp-relay-mode", zero_rtt_handshake: "reduce-rtt",
    });
  } else if (protocol === "hysteria2") {
    const legacyAuth = string(take(options, "auth", ""), true);
    if (combined && legacyAuth && combined !== legacyAuth) unsupported();
    source.password = combined || legacyAuth;
    copy(options, source, { obfs: "obfs", "obfs-password": "obfs-password", mport: "ports" });
  } else if (protocol === "hysteria") {
    const obfs = take(options, "obfs", "xplus");
    if (auth !== undefined || take(options, "protocol", "udp") !== "udp" || (obfs !== "" && obfs !== "xplus")) unsupported();
    copy(options, source, { auth: "auth-str", upmbps: "up", downmbps: "down", obfsParam: "obfs" });
  } else if (protocol === "socks") {
    source.username = user;
    source.password = password ?? "";
  } else source.password = combined;
  requireConsumed(options);
  return source;
}

export function proxyInput(node: NodeRecord, format: ProxyExportFormat): {
  name: string; type: string | undefined; protocol: string; source: Fields; fromUri: boolean;
} {
  const name = node.name === undefined || node.name === null || node.name === "" ? "node" : string(node.name, true);
  if (CONTROL.test(name)) unsupported();
  const type = node.type === undefined ? undefined : string(node.type).toLowerCase();
  const protocol = type === undefined ? undefined : ALIASES.get(type) ?? type;
  const raw = node.share === undefined || node.share === null || node.share === "" ? node.raw : node.share;
  if (raw !== undefined && raw !== null && raw !== "") {
    const share = string(raw);
    if (CONTROL.test(share)) unsupported();
    const [schemeText, payload] = splitOnce(share, "://");
    if (!payload) return unsupported();
    const [address] = splitOnce(payload, "#");
    const scheme = schemeText.toLowerCase();
    const sharedProtocol = ALIASES.get(scheme) ?? scheme;
    if ((type !== undefined && type !== "temp" && protocol !== sharedProtocol) || !RAW_SCHEMES.has(scheme)) unsupported();
    return { name, type, protocol: sharedProtocol, source: uriSource(share, scheme, sharedProtocol, address, format), fromUri: true };
  }
  if (protocol === undefined) return unsupported();
  const source: Fields = Object.create(null);
  for (const [key, value] of Object.entries(node)) if (!LEGACY_METADATA.has(key)) source[key] = value;
  return { name, type, protocol, source, fromUri: false };
}

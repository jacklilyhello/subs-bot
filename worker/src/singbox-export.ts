import {
  isValidStoredShare, numberInRange, parseStoredShadowsocks, parseStoredVmessJson, splitOnce,
  validInlineEch, validIpv6, validShadowsocks2022Keys, validShadowsocksPlugin,
} from "./stored-share.ts";
import type { NodeRecord } from "./storage.ts";

type Fields = NodeRecord;
type Rule = (value: unknown) => boolean;
type Schema = Record<string, Rule>;

const ALIASES = new Map([["ss", "shadowsocks"], ["hy2", "hysteria2"], ["socks5", "socks"], ["https", "http"]]);
const RAW_SCHEMES = new Set(["ss", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks5"]);
const TLS_REQUIRED = new Set(["hysteria", "hysteria2", "tuic", "anytls"]);
const NETWORK_PROTOCOLS = new Set(["shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "socks"]);
const TRANSPORT_PROTOCOLS = new Set(["vmess", "vless", "trojan"]);
const SS_METHODS = new Set([
  "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
  "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
  "rc4-md5", "chacha20-ietf", "xchacha20",
]);
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/u;
const SURROGATE = /[\ud800-\udfff]/u;
const LEGACY_METADATA = new Set(["name", "tag", "type", "share", "raw"]);
const MAX_UINT32 = 2 ** 32 - 1;
const MAX_INT32 = 2 ** 31 - 1;
const MAX_HOPPING_PORTS_PER_OUTBOUND = 65535;
const MIN_HYSTERIA1_BYTES_PER_SECOND = 16384n;
const MAX_UINT64 = 2n ** 64n - 1n;
const GECKO_DEFAULT_MIN_PACKET_SIZE = 512;
const GECKO_DEFAULT_MAX_PACKET_SIZE = 1200;
const GECKO_MAX_PACKET_SIZE = 2048;

export class SingBoxContentError extends Error {}

function unsupported(): never {
  throw new SingBoxContentError();
}

function isRecord(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fields(value: unknown): Fields {
  return isRecord(value) ? Object.assign(Object.create(null), value) as Fields : unsupported();
}

function take(source: Fields, key: string, fallback: unknown = undefined): unknown {
  if (!Object.hasOwn(source, key)) return fallback;
  const value = source[key];
  delete source[key];
  return value;
}

function scalarAlias(source: Fields, keys: string[], fallback?: unknown): unknown {
  let value: unknown;
  for (const key of keys) {
    if (!Object.hasOwn(source, key)) continue;
    const next = take(source, key);
    if (value !== undefined && value !== next) unsupported();
    value = next;
  }
  return value === undefined ? fallback : value;
}

function empty(value: unknown): boolean {
  return value === undefined || value === null || value === ""
    || (Array.isArray(value) && value.length === 0) || (isRecord(value) && Object.keys(value).length === 0);
}

function requireConsumed(source: Fields): void {
  if (Object.values(source).some((value) => !empty(value))) unsupported();
}

function copy(source: Fields, output: Fields, names: Record<string, string>): void {
  for (const [from, to] of Object.entries(names)) {
    if (Object.hasOwn(source, from)) output[to] = take(source, from);
  }
}

const isString = (value: unknown): value is string => typeof value === "string" && !SURROGATE.test(value);
const isNonempty = (value: unknown): value is string => isString(value) && value.trim() !== "";
const isBool = (value: unknown): boolean => typeof value === "boolean";
const isUint = (value: unknown): boolean => typeof value === "number" && numberInRange(value, 0, MAX_UINT32) !== null;
const isInt = (value: unknown): boolean => typeof value === "number" && numberInRange(value, 0, MAX_INT32) !== null;
const duration = (value: unknown): boolean => isString(value)
  && /^(?:0|(?:[0-9]+(?:\.[0-9]+)?(?:ns|us|µs|μs|ms|s|m|h))+)(?![\s\S])/u.test(value);
const oneOf = (...options: unknown[]): Rule => (value) => options.includes(value);
const listable = (rule: Rule): Rule => (value) => Array.isArray(value) ? value.every(rule) : rule(value);
const strings = listable(isString);
const safeHeader = (value: unknown): boolean => isString(value) && !CONTROL.test(value);
const headers = (value: unknown): boolean => isRecord(value) && Object.entries(value).every(([name, item]) =>
  /^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+(?![\s\S])/u.test(name) && listable(safeHeader)(item));
const uuid = (value: unknown): boolean => isString(value)
  && /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/iu.test(value);

function matches(value: unknown, schema: Schema): value is Fields {
  return isRecord(value) && Object.entries(value).every(([key, item]) =>
    Object.hasOwn(schema, key) && schema[key](item));
}

function string(value: unknown, allowEmpty = false): string {
  return (allowEmpty ? isString(value) : isNonempty(value)) ? value as string : unsupported();
}

function integer(value: unknown, minimum: number, maximum: number): number {
  return numberInRange(value, minimum, maximum) ?? unsupported();
}

function flag(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (value === 1 || value === 0 || typeof value === "string") {
    const candidate = String(value).toLowerCase();
    if (candidate === "1" || candidate === "true") return true;
    if (candidate === "0" || candidate === "false") return false;
  }
  return unsupported();
}

function server(value: unknown): string {
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

function normalizeList(value: unknown): string[] {
  const values: unknown = typeof value === "string" ? value.split(",") : value;
  if (!Array.isArray(values)) return unsupported();
  return values.map((item: unknown) => string(item).trim());
}

function ports(value: unknown): string[] {
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

function expandedHoppingPorts(value: unknown): number {
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

function validHysteria1Bandwidth(value: unknown, mbps: unknown): boolean {
  if (value === undefined) return typeof mbps === "number" && mbps > 0;
  if (!isString(value)) return false;
  const match = /^([0-9]{1,20}) *([KMGT]?)([bB])ps(?![\s\S])/u.exec(value);
  if (!match) return false;
  const exponent = match[2] ? "KMGT".indexOf(match[2]) + 1 : 0;
  const count = BigInt(match[1]) * 1000n ** BigInt(exponent);
  return count <= MAX_UINT64 && count / (match[3] === "b" ? 8n : 1n) >= MIN_HYSTERIA1_BYTES_PER_SECOND;
}

function inlineEch(value: unknown): boolean {
  if (!strings(value)) return false;
  const pem = Array.isArray(value) ? value.join("\n") : value as string;
  if (pem === "") return true;
  const match = /^-----BEGIN ECH CONFIGS-----\r?\n([A-Za-z0-9+/=\r\n]+)\r?\n-----END ECH CONFIGS-----(?:\r?\n)?(?![\s\S])/u.exec(pem);
  return match !== null && validInlineEch(match[1].replace(/[\r\n]/gu, ""));
}

const TLS_SCHEMA: Schema = {
  enabled: isBool, engine: oneOf("", "go"), disable_sni: isBool, server_name: safeHeader, insecure: isBool, alpn: strings,
  min_version: oneOf("", "1.0", "1.1", "1.2", "1.3"), max_version: oneOf("", "1.0", "1.1", "1.2", "1.3"),
  cipher_suites: strings, curve_preferences: strings, certificate: strings,
  certificate_public_key_sha256: listable((value) => isString(value) && /^[A-Za-z0-9+/]{43}=(?![\s\S])/u.test(value)),
  client_certificate: strings, client_key: strings, fragment: isBool, fragment_fallback_delay: duration,
  record_fragment: isBool, kernel_tx: isBool, kernel_rx: isBool, handshake_timeout: duration,
  ech: (value) => matches(value, { enabled: isBool, config: inlineEch, query_server_name: safeHeader }),
  utls: (value) => matches(value, {
    enabled: isBool,
    fingerprint: oneOf("", "chrome", "firefox", "edge", "safari", "360", "qq", "ios", "android", "random", "randomized"),
  }),
  reality: (value) => matches(value, {
    enabled: isBool,
    public_key: (key) => isString(key) && /^[A-Za-z0-9_-]{43}(?![\s\S])/u.test(key),
    short_id: (id) => isString(id) && /^(?:[0-9a-f]{2}){0,8}(?![\s\S])/iu.test(id),
  }),
};
const TRANSPORT_SCHEMAS = new Map<string, Schema>([
  ["ws", { path: isString, headers, max_early_data: isUint, early_data_header_name: safeHeader }],
  ["grpc", { service_name: isString, idle_timeout: duration, ping_timeout: duration, permit_without_stream: isBool }],
  ["http", { host: strings, path: isString, method: isString, headers, idle_timeout: duration, ping_timeout: duration }],
  ["httpupgrade", { host: isString, path: isString, headers }],
  ["quic", {}],
]);
const isTransport: Rule = (value) => {
  if (!isRecord(value) || typeof value.type !== "string") return false;
  const schema = TRANSPORT_SCHEMAS.get(value.type);
  return schema !== undefined && matches(value, { type: isString, ...schema });
};
const multiplex: Rule = (value) => matches(value, {
  enabled: isBool, protocol: oneOf("", "smux", "yamux", "h2mux"), max_connections: isInt,
  min_streams: isInt, max_streams: isInt, padding: isBool,
  brutal: (options) => matches(options, { enabled: isBool, up_mbps: isInt, down_mbps: isInt }),
});
const udpOverTcp: Rule = (value) => isBool(value) || matches(value, { enabled: isBool, version: oneOf(0, 1, 2) });
const QUIC: Schema = {
  idle_timeout: duration, keep_alive_period: duration, stream_receive_window: isUint,
  connection_receive_window: isUint, max_concurrent_streams: isInt,
  initial_packet_size: isInt, disable_path_mtu_discovery: isBool,
};
const HYSTERIA: Schema = {
  ...QUIC, server_ports: (value) => typeof value === "string" || Array.isArray(value),
  hop_interval: duration, up_mbps: isInt, down_mbps: isInt,
};
const TRANSPORT: Schema = { transport: isTransport, tls: (value) => matches(value, TLS_SCHEMA), multiplex };
const NATIVE_SCHEMAS = new Map<string, Schema>([
  ["shadowsocks", { method: (value) => isString(value) && SS_METHODS.has(value),
    password: isString, plugin: isString, plugin_opts: isString, udp_over_tcp: udpOverTcp, multiplex }],
  ["vmess", { ...TRANSPORT, uuid: isNonempty,
    security: oneOf("", "auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"),
    alter_id: (value) => typeof value === "number" && numberInRange(value, 0, 65535) !== null,
    global_padding: isBool, authenticated_length: isBool, packet_encoding: oneOf("", "packetaddr", "xudp") }],
  ["vless", { ...TRANSPORT, uuid: isNonempty, flow: oneOf("", "xtls-rprx-vision"),
    packet_encoding: oneOf("", "packetaddr", "xudp") }],
  ["trojan", { ...TRANSPORT, password: isNonempty }],
  ["hysteria", { ...HYSTERIA, tls: TRANSPORT.tls, up: isString, down: isString, obfs: isString,
    auth: (value) => isString(value) && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![\s\S])/u.test(value),
    auth_str: isString, recv_window_conn: isUint, recv_window: isUint, disable_mtu_discovery: isBool }],
  ["hysteria2", { ...HYSTERIA, tls: TRANSPORT.tls, hop_interval_max: duration, password: isString,
    obfs: (value) => matches(value, { type: oneOf("salamander", "gecko"), password: isNonempty,
      min_packet_size: isInt, max_packet_size: isInt }),
    bbr_profile: oneOf("", "standard", "conservative", "aggressive"), brutal_debug: isBool, disable_chrome_parrot: isBool }],
  ["tuic", { ...QUIC, tls: TRANSPORT.tls, uuid, password: isString,
    congestion_control: oneOf("", "cubic", "new_reno", "bbr"), udp_relay_mode: oneOf("", "native", "quic"),
    udp_over_stream: isBool, zero_rtt_handshake: isBool, heartbeat: duration }],
  ["anytls", { tls: TRANSPORT.tls, password: isNonempty, idle_session_check_interval: duration,
    idle_session_timeout: duration, min_idle_session: isInt, client_metadata: isString }],
  ["socks", { version: oneOf("", "4", "4a", "5"), username: isString, password: isString, udp_over_tcp: udpOverTcp }],
  ["http", { username: isString, password: isString, tls: TRANSPORT.tls, path: isString, headers }],
]);
const COMMON: Schema = {
  server: isNonempty, server_port: (value) => typeof value === "number" && numberInRange(value, 1, 65535) !== null,
  tcp_fast_open: isBool, tcp_multi_path: isBool, disable_tcp_keep_alive: isBool, connect_timeout: duration,
  tcp_keep_alive: duration, tcp_keep_alive_interval: duration, udp_fragment: isBool, reuse_addr: isBool,
};

function validate(protocol: string, output: Fields): number {
  const schema = NATIVE_SCHEMAS.get(protocol);
  const network: Schema = NETWORK_PROTOCOLS.has(protocol) ? { network: listable(oneOf("tcp", "udp")) } : {};
  if (!schema || !matches(output, { type: isString, ...COMMON, ...network, ...schema })) unsupported();
  if (protocol === "shadowsocks") {
    const method = string(output.method);
    const password = string(output.password ?? "", method === "none");
    if (!validShadowsocks2022Keys(method, password)) unsupported();
    if (output.plugin) {
      if (!validShadowsocksPlugin(string(output.plugin) + ";" + string(output.plugin_opts ?? "", true))) unsupported();
    } else if (output.plugin_opts) unsupported();
  }
  if (["vmess", "vless", "tuic"].includes(protocol) && !output.uuid) unsupported();
  if (["trojan", "anytls"].includes(protocol) && !output.password) unsupported();
  if (protocol === "tuic" && output.udp_over_stream && output.udp_relay_mode) unsupported();
  if (protocol === "hysteria" && ((output.auth && output.auth_str)
    || !validHysteria1Bandwidth(output.up, output.up_mbps)
    || !validHysteria1Bandwidth(output.down, output.down_mbps))) unsupported();
  if (protocol === "hysteria2" && isRecord(output.obfs)) {
    const { type, password, min_packet_size: min, max_packet_size: max } = output.obfs;
    if (!type || !password) unsupported();
    if (type === "gecko") {
      const effectiveMin = typeof min === "number" && min !== 0 ? min : GECKO_DEFAULT_MIN_PACKET_SIZE;
      const effectiveMax = typeof max === "number" && max !== 0 ? max : GECKO_DEFAULT_MAX_PACKET_SIZE;
      if (effectiveMin > effectiveMax || effectiveMax > GECKO_MAX_PACKET_SIZE) unsupported();
    } else if (min !== undefined || max !== undefined) unsupported();
  }
  const tls = isRecord(output.tls) ? output.tls : {};
  if (TLS_REQUIRED.has(protocol) && tls.enabled !== true) unsupported();
  if (isRecord(tls.reality) && tls.reality.enabled === true
    && (!tls.reality.public_key || !isRecord(tls.utls) || tls.utls.enabled !== true || tls.insecure)) unsupported();
  return output.server_ports === undefined ? 0 : expandedHoppingPorts(output.server_ports);
}

function native(source: Fields, protocol: string): Fields {
  source.server = server(source.server);
  if (Object.hasOwn(source, "server_ports")) {
    if (Object.hasOwn(source, "server_port")) unsupported();
  } else source.server_port = integer(source.server_port, 1, 65535);
  return { type: protocol, ...source };
}

function clashTls(source: Fields, protocol: string, https: boolean): Fields | null {
  const defaultEnabled = https || protocol === "trojan" || TLS_REQUIRED.has(protocol);
  const setting = take(source, "tls", defaultEnabled);
  const tls = isRecord(setting) ? fields(setting) : { enabled: flag(setting) };
  const sni = scalarAlias(source, ["sni", "servername"]);
  const insecure = take(source, "skip-cert-verify");
  const disableSni = take(source, "disable-sni");
  const alpn = take(source, "alpn");
  function set(key: string, value: unknown): void {
    if (Object.hasOwn(tls, key)) {
      const previous: unknown = tls[key];
      if (previous !== value && !(Array.isArray(previous) && Array.isArray(value)
        && previous.length === value.length && previous.every((item, i) => item === value[i]))) unsupported();
    }
    tls[key] = value;
  }
  if (!empty(sni)) set("server_name", server(sni));
  if (!empty(alpn)) set("alpn", normalizeList(alpn));
  for (const [key, value] of [["insecure", insecure], ["disable_sni", disableSni]] as const) {
    if (!empty(value) && (tls.enabled || flag(value))) set(key, flag(value));
  }
  const fingerprint = take(source, "client-fingerprint");
  if (!empty(fingerprint) && fingerprint !== "none") {
    if (Object.hasOwn(tls, "utls")) unsupported();
    tls.utls = { enabled: true, fingerprint: string(fingerprint) };
  }
  const reality = take(source, "reality-opts");
  if (reality !== undefined && reality !== null) {
    if (Object.hasOwn(tls, "reality")) unsupported();
    const options = fields(reality);
    const publicKey = string(take(options, "public-key"));
    const shortId = take(options, "short-id");
    tls.reality = { enabled: true, public_key: publicKey, ...(shortId === undefined ? {} : { short_id: shortId }) };
    requireConsumed(options);
  }
  if (tls.enabled === true) return tls;
  if (TLS_REQUIRED.has(protocol) || tls.enabled !== false || Object.keys(tls).length > 1) unsupported();
  return null;
}

function clashTransport(source: Fields): Fields | null {
  const network = take(source, "network");
  if (Object.hasOwn(source, "transport")) {
    if (!empty(network)) unsupported();
    return fields(take(source, "transport"));
  }
  if (empty(network) || network === "tcp" || network === "raw") return null;
  const kind = network === "h2" ? "http" : string(network);
  if (!TRANSPORT_SCHEMAS.has(kind)) unsupported();
  const output: Fields = { type: kind };
  const settings = fields(take(source, String(network) + "-opts", {}));
  if (kind === "grpc") copy(settings, output, { "grpc-service-name": "service_name" });
  if (kind === "ws") {
    copy(settings, output, { path: "path", headers: "headers", "early-data-header-name": "early_data_header_name" });
    if (Object.hasOwn(settings, "max-early-data")) output.max_early_data = integer(take(settings, "max-early-data"), 0, MAX_UINT32);
  }
  if (kind === "http" || kind === "httpupgrade") {
    copy(settings, output, { path: "path", headers: "headers", host: "host" });
    if (kind === "http") {
      copy(settings, output, { method: "method" });
      if (Array.isArray(output.path)) {
        if (output.path.length !== 1) unsupported();
        output.path = output.path[0];
      }
    }
  }
  requireConsumed(settings);
  return output;
}

function clashPlugin(source: Fields, output: Fields): void {
  let plugin = take(source, "plugin");
  const setting = take(source, "plugin-opts");
  if (empty(plugin)) {
    if (!empty(setting)) unsupported();
    return;
  }
  if (plugin === "obfs" || plugin === "simple-obfs") plugin = "obfs-local";
  if (plugin !== "obfs-local" && plugin !== "v2ray-plugin") unsupported();
  output.plugin = plugin;
  if (typeof setting === "string") output.plugin_opts = setting;
  else if (!empty(setting)) {
    const options: string[] = [];
    const settings = fields(setting);
    const names = plugin === "obfs-local" ? { mode: "obfs", host: "obfs-host" }
      : { mode: "mode", host: "host", path: "path", tls: "tls", mux: "mux" };
    for (const [key, target] of Object.entries(names)) {
      if (!Object.hasOwn(settings, key)) continue;
      const value = take(settings, key);
      if (key === "tls") {
        if (flag(value)) options.push("tls");
      } else if (key === "mux") {
        options.push("mux=" + Number(flag(value)));
      } else {
        const text = string(value);
        if (/[;\\]/u.test(text) || CONTROL.test(text)) unsupported();
        options.push(target + "=" + text);
      }
    }
    requireConsumed(settings);
    if (options.length) output.plugin_opts = options.join(";");
  }
}

function clash(source: Fields, protocol: string, https: boolean): Fields {
  const output: Fields = { type: protocol, server: server(take(source, "server")) };
  const port = take(source, "port");
  const range = protocol === "hysteria" || protocol === "hysteria2" ? take(source, "ports") : undefined;
  // Mihomo carries a base port alongside hopping ranges. sing-box uses the ranges.
  if (!empty(range)) {
    if (!empty(port)) integer(port, 1, 65535);
    output.server_ports = ports(range);
  } else output.server_port = integer(port, 1, 65535);

  if (TRANSPORT_PROTOCOLS.has(protocol)) {
    const transport = clashTransport(source);
    if (transport) output.transport = transport;
  }
  if (TLS_REQUIRED.has(protocol) || TRANSPORT_PROTOCOLS.has(protocol) || protocol === "http") {
    const tls = clashTls(source, protocol, https);
    if (tls) output.tls = tls;
  }
  if (NETWORK_PROTOCOLS.has(protocol)) {
    const udp = take(source, "udp");
    if (udp !== undefined && !flag(udp)) output.network = "tcp";
  }
  for (const [from, to] of [["tfo", "tcp_fast_open"], ["mptcp", "tcp_multi_path"]]) {
    if (Object.hasOwn(source, from)) output[to] = flag(take(source, from));
  }
  if (["vmess", "vless", "tuic"].includes(protocol)) output.uuid = string(take(source, "uuid"));
  if (protocol === "shadowsocks") {
    const method = string(scalarAlias(source, ["cipher", "method"]));
    output.method = method;
    output.password = string(take(source, "password", ""), method === "none");
    clashPlugin(source, output);
    copy(source, output, { "udp-over-tcp": "udp_over_tcp" });
  }
  if (protocol === "vmess") {
    output.security = scalarAlias(source, ["cipher", "security"], "auto");
    output.alter_id = integer(scalarAlias(source, ["alterId", "alter_id"], 0), 0, 65535);
    for (const key of ["global-padding", "authenticated-length"]) {
      if (Object.hasOwn(source, key)) output[key.replace("-", "_")] = flag(take(source, key));
    }
  }
  if (["trojan", "anytls", "hysteria2", "tuic"].includes(protocol)) {
    const optional = protocol === "hysteria2" || protocol === "tuic";
    output.password = string(take(source, "password", optional ? "" : undefined), optional);
  }
  if (protocol === "vless") {
    if (!["", "none"].includes(string(take(source, "encryption", "none"), true))) unsupported();
    const flow = take(source, "flow");
    if (!empty(flow)) output.flow = flow;
  }
  if (protocol === "vmess" || protocol === "vless") {
    const encoding = scalarAlias(source, ["packet-encoding", "packet_encoding"]);
    if (encoding !== undefined && encoding !== null) {
      output.packet_encoding = encoding === "packet" ? "packetaddr" : encoding === "none" ? "" : encoding;
    }
  }
  if (protocol === "hysteria" || protocol === "hysteria2") {
    for (const key of ["up", "down"]) {
      const value = take(source, key);
      if (value !== undefined && value !== null) {
        output[key + "_mbps"] = integer(typeof value === "string" ? value.replace(/\s*Mbps$/iu, "") : value, 0, MAX_INT32);
      }
    }
    if (Object.hasOwn(source, "hop-interval")) output.hop_interval = integer(take(source, "hop-interval"), 1, MAX_INT32) + "s";
    const obfs = take(source, "obfs");
    if (protocol === "hysteria") {
      if (!empty(obfs)) output.obfs = string(obfs);
      copy(source, output, { "auth-str": "auth_str", auth: "auth" });
    } else if (!empty(obfs)) {
      const settings: Fields = { type: string(obfs), password: string(take(source, "obfs-password")) };
      if (obfs === "gecko") {
        for (const key of ["min", "max"]) {
          const from = "obfs-" + key + "-packet-size";
          if (Object.hasOwn(source, from)) settings[key + "_packet_size"] = integer(take(source, from), 1, MAX_INT32);
        }
      }
      output.obfs = settings;
    }
  }
  if (protocol === "tuic") {
    copy(source, output, { "congestion-controller": "congestion_control", "udp-relay-mode": "udp_relay_mode" });
    if (Object.hasOwn(source, "reduce-rtt")) output.zero_rtt_handshake = flag(take(source, "reduce-rtt"));
    if (Object.hasOwn(source, "heartbeat-interval")) output.heartbeat = integer(take(source, "heartbeat-interval"), 1, MAX_INT32) + "ms";
  }
  if (protocol === "socks" || protocol === "http") copy(source, output, { username: "username", password: "password" });
  requireConsumed(source);
  return output;
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

function uriSource(share: string, scheme: string, protocol: string, address: string): Fields {
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

export function serializeSingBoxOutbound(node: NodeRecord): { name: string; json: string; hoppingPorts: number } {
  try {
    const name = node.name === undefined || node.name === null || node.name === "" ? "node" : string(node.name, true);
    if (CONTROL.test(name)) unsupported();
    const type = node.type === undefined ? undefined : string(node.type).toLowerCase();
    let protocol = type === undefined ? undefined : ALIASES.get(type) ?? type;
    let source: Fields = Object.create(null);
    const raw = node.share === undefined || node.share === null || node.share === "" ? node.raw : node.share;
    if (raw !== undefined && raw !== null && raw !== "") {
      const share = string(raw);
      if (CONTROL.test(share)) unsupported();
      const [schemeText, payload] = splitOnce(share, "://");
      if (!payload) return unsupported();
      const [address] = splitOnce(payload, "#");
      const scheme = schemeText.toLowerCase();
      const sharedProtocol = ALIASES.get(scheme) ?? scheme;
      if (type !== undefined && type !== "temp" && protocol !== sharedProtocol) unsupported();
      if (!RAW_SCHEMES.has(scheme)) unsupported();
      protocol = sharedProtocol;
      source = uriSource(share, scheme, protocol, address);
    } else {
      for (const [key, value] of Object.entries(node)) if (!LEGACY_METADATA.has(key)) source[key] = value;
    }
    if (protocol === undefined || !NATIVE_SCHEMAS.has(protocol)) return unsupported();
    const output = type === protocol && (Object.hasOwn(source, "server_port") || Object.hasOwn(source, "server_ports"))
      ? native(source, protocol) : clash(source, protocol, type === "https");
    const hoppingPorts = validate(protocol, output);
    return { name, json: JSON.stringify(output), hoppingPorts };
  } catch {
    // URI/JSON parsers may include input values in their errors.
    return unsupported();
  }
}

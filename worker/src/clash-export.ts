import {
  CONTROL, empty, expandedHoppingPorts, fields, flag, integer, normalizeList, ports,
  proxyInput, requireConsumed, scalarAlias, server, string, take, TLS_REQUIRED, TRANSPORT_PROTOCOLS,
  unsupported, validHysteria1Bandwidth, type Fields,
} from "./proxy-input.ts";
import { portableNativeSource } from "./proxy-native.ts";
import { normalizeInlineEch, parseShadowsocksPlugin, splitOnce, validShadowsocks2022Keys } from "./stored-share.ts";
import type { NodeRecord } from "./storage.ts";

const CLASH_TYPES = new Map([
  ["shadowsocks", "ss"], ["vmess", "vmess"], ["vless", "vless"], ["trojan", "trojan"],
  ["hysteria", "hysteria"], ["hysteria2", "hysteria2"], ["tuic", "tuic"], ["anytls", "anytls"],
  ["socks", "socks5"], ["http", "http"],
]);
const UDP_TOGGLE = new Set(["shadowsocks", "vmess", "vless", "trojan", "socks", "anytls"]);
const SS_CIPHERS = new Set([
  "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
  "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
  "2022-blake3-chacha8-poly1305", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "aes-128-cfb",
  "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20", "chacha20-ietf", "xchacha20",
  "aes-128-ccm", "aes-192-ccm", "aes-256-ccm", "aes-128-gcm-siv", "aes-256-gcm-siv",
  "lea-128-gcm", "lea-192-gcm", "lea-256-gcm",
]);
const VMESS_CIPHERS = new Set(["auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"]);
const TLS_FINGERPRINTS = new Set(["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random"]);
const MAX_INT32 = 2 ** 31 - 1;
const HEADER_NAME = /^[!#$%&'*+.^_\x60|~0-9A-Za-z-]+(?![\s\S])/u;

export class ClashContentError extends Error {}

function safeText(value: unknown, allowEmpty = false): string {
  const text = string(value, allowEmpty);
  if (CONTROL.test(text)) unsupported();
  return text;
}

function option(
  source: Fields, output: Fields, key: string, convert: (value: unknown) => unknown, target = key,
): void {
  const value = take(source, key);
  if (!empty(value)) output[target] = convert(value);
}

function headerMap(value: unknown, multiple = false): Fields {
  const input = fields(value);
  const seen = new Set<string>();
  for (const [name, entry] of Object.entries(input)) {
    if (!HEADER_NAME.test(name) || seen.has(name.toLowerCase())) unsupported();
    seen.add(name.toLowerCase());
    input[name] = multiple
      ? (Array.isArray(entry) ? entry : [entry]).map((item: unknown) => safeText(item, true))
      : safeText(entry, true);
  }
  return input;
}

function clashTls(source: Fields, output: Fields, protocol: string, https: boolean): void {
  const required = TLS_REQUIRED.has(protocol) || protocol === "trojan";
  const enabled = flag(take(source, "tls", required || https));
  if (!enabled && required) unsupported();
  const settings: Fields = {};
  const sni = scalarAlias(source, ["servername", "sni"]);
  if (!empty(sni)) {
    if (protocol === "socks") unsupported();
    settings[protocol === "vmess" || protocol === "vless" ? "servername" : "sni"] = server(sni);
  }
  option(source, settings, "skip-cert-verify", flag);
  const alpn = take(source, "alpn");
  if (alpn !== undefined && alpn !== null && alpn !== "") {
    if (protocol === "http" || protocol === "socks") unsupported();
    settings.alpn = normalizeList(alpn).map((value) => safeText(value));
  }
  const disableSni = take(source, "disable-sni");
  if (!empty(disableSni) && flag(disableSni)) {
    if (protocol !== "tuic") unsupported();
    settings["disable-sni"] = true;
  }
  const fingerprint = take(source, "client-fingerprint");
  if (!empty(fingerprint) && fingerprint !== "none") {
    if ((!TRANSPORT_PROTOCOLS.has(protocol) && protocol !== "anytls") || !TLS_FINGERPRINTS.has(string(fingerprint))) unsupported();
    settings["client-fingerprint"] = fingerprint;
  }
  const reality = take(source, "reality-opts");
  if (!empty(reality)) {
    if (!TRANSPORT_PROTOCOLS.has(protocol) || settings["skip-cert-verify"] === true || !settings["client-fingerprint"]) unsupported();
    const opts = fields(reality);
    const key = string(take(opts, "public-key"));
    const id = string(take(opts, "short-id", ""), true);
    if (!/^[A-Za-z0-9_-]{43}(?![\s\S])/u.test(key) || !/^(?:[0-9a-f]{2}){0,8}(?![\s\S])/iu.test(id)) unsupported();
    requireConsumed(opts);
    settings["reality-opts"] = { "public-key": key, "short-id": id };
  }
  const ech = take(source, "ech-opts");
  if (!empty(ech)) {
    if (protocol === "http" || protocol === "socks" || settings["reality-opts"]) unsupported();
    const opts = fields(ech);
    const enable = flag(take(opts, "enable"));
    const data = take(opts, "config");
    const query = take(opts, "query-server-name");
    requireConsumed(opts);
    const result: Fields = { enable };
    if (!empty(data)) {
      const config = normalizeInlineEch(string(data));
      if (!enable || config === null) unsupported();
      result.config = config;
    }
    if (!empty(query)) {
      if (!enable) unsupported();
      result["query-server-name"] = server(query);
    }
    settings["ech-opts"] = result;
  }
  if (!enabled && Object.entries(settings).some(([key, value]) => key !== "skip-cert-verify" || value !== false)) unsupported();
  if (enabled) Object.assign(output, settings);
  if (!required && (enabled || https)) output.tls = enabled;
}

function clashTransport(source: Fields, output: Fields, protocol: string, fromUri: boolean): void {
  const network = take(source, "network");
  if (empty(network) || network === "tcp" || network === "raw") return;
  const kind = string(network);
  if (!["ws", "grpc", "h2", "http"].includes(kind)
    || (protocol === "trojan" && kind !== "ws" && kind !== "grpc")
    || (kind === "http" && fromUri)) unsupported();
  const key = kind + "-opts";
  const opts = fields(take(source, key, {}));
  const result: Fields = {};
  if (kind === "ws") {
    option(opts, result, "path", safeText);
    option(opts, result, "headers", (value) => headerMap(value));
    option(opts, result, "max-early-data", (value) => integer(value, 0, MAX_INT32));
    option(opts, result, "early-data-header-name", (value) => {
      const name = string(value);
      return HEADER_NAME.test(name) ? name : unsupported();
    });
    option(opts, result, "v2ray-http-upgrade", flag);
    option(opts, result, "v2ray-http-upgrade-fast-open", flag);
    // Mihomo otherwise takes the WS Host header as TLS SNI for VMess/VLESS.
    if (fromUri && output.tls === true && protocol === "vless" && !output.servername
      && result.headers && Object.keys(fields(result.headers)).some((header) => header.toLowerCase() === "host")) {
      output.servername = output.server;
    }
  } else if (kind === "grpc") {
    option(opts, result, "grpc-service-name", safeText);
    option(opts, result, "grpc-user-agent", safeText);
  } else if (kind === "h2") {
    option(opts, result, "host", (value) => normalizeList(value).map((item) => safeText(item)));
    option(opts, result, "path", safeText);
  } else {
    option(opts, result, "path", (value) => (Array.isArray(value) ? value : [value]).map((item) => safeText(item)));
    option(opts, result, "method", safeText);
    option(opts, result, "headers", (value) => headerMap(value, true));
  }
  requireConsumed(opts);
  output.network = kind;
  if (Object.keys(result).length) output[key] = result;
}

function shadowsocksPlugin(source: Fields, output: Fields, fromUri: boolean): void {
  const name = take(source, "plugin");
  const value = take(source, "plugin-opts");
  if (empty(name)) {
    if (!empty(value)) unsupported();
    return;
  }
  const plugin = name === "obfs" || name === "obfs-local" || name === "simple-obfs" ? "obfs"
    : name === "v2ray-plugin" ? name : unsupported();
  output.plugin = plugin;
  const result: Fields = {};
  if (typeof value === "string" || fromUri) {
    const parsed = parseShadowsocksPlugin((plugin === "obfs" ? "obfs-local" : plugin) + ";" + string(value ?? "", true));
    if (!parsed) return unsupported();
    const options = parsed.options;
    if (plugin === "obfs") {
      // An external simple-obfs URI without mode/host is ambiguous across clients.
      if (!options.has("obfs") || !options.has("obfs-host")) unsupported();
      result.mode = options.get("obfs");
      result.host = safeText(options.get("obfs-host"));
    } else {
      result.mode = options.get("mode") ?? "websocket";
      result.host = safeText(options.get("host") ?? (fromUri ? "cloudfront.com" : output.server));
      result.path = safeText(options.get("path") ?? "/");
      result.tls = options.has("tls");
      result.mux = integer(options.get("mux") ?? 1, 0, 1) === 1;
    }
  } else {
    const opts = fields(value);
    const mode = take(opts, "mode");
    if (plugin === "obfs" ? mode !== "tls" && mode !== "http" : mode !== "websocket") unsupported();
    result.mode = mode;
    option(opts, result, "host", safeText);
    if (plugin === "v2ray-plugin") {
      option(opts, result, "path", safeText);
      option(opts, result, "tls", flag);
      option(opts, result, "mux", flag);
      option(opts, result, "headers", (item) => headerMap(item));
      option(opts, result, "skip-cert-verify", flag);
      option(opts, result, "v2ray-http-upgrade", flag);
      option(opts, result, "v2ray-http-upgrade-fast-open", flag);
    }
    requireConsumed(opts);
  }
  output["plugin-opts"] = result;
}

function hysteriaOptions(source: Fields, output: Fields, protocol: string): void {
  for (const key of ["up", "down"]) {
    const value = take(source, key);
    if (empty(value) && protocol === "hysteria2") continue;
    const mbps = typeof value === "number" || (typeof value === "string" && /^[0-9]+(?![\s\S])/u.test(value));
    if (mbps) output[key] = integer(value, protocol === "hysteria" ? 1 : 0, MAX_INT32);
    else {
      // Mihomo accepts the same bounded decimal bitrate units here.
      if (!validHysteria1Bandwidth(value, undefined)) unsupported();
      output[key] = value;
    }
  }
  option(source, output, "hop-interval", (value) => integer(value, 5, MAX_INT32));
  if (protocol === "hysteria") {
    const transport = take(source, "protocol", "udp");
    if (transport !== "udp") unsupported();
    const auth = take(source, "auth");
    const authString = take(source, "auth-str");
    if (!empty(auth) && !empty(authString)) unsupported();
    if (!empty(auth)) {
      const text = string(auth);
      if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![\s\S])/u.test(text)) unsupported();
      output.auth = text;
    }
    if (!empty(authString)) output["auth-str"] = string(authString);
    option(source, output, "obfs", string);
  } else {
    const kind = take(source, "obfs");
    const password = take(source, "obfs-password");
    const min = take(source, "obfs-min-packet-size");
    const max = take(source, "obfs-max-packet-size");
    if (!empty(kind)) {
      if (kind !== "salamander" && kind !== "gecko") unsupported();
      output.obfs = kind;
      output["obfs-password"] = string(password);
      if (kind === "gecko") {
        const lower = min === undefined ? 0 : integer(min, 0, 2048);
        const upper = max === undefined ? 0 : integer(max, 0, 2048);
        if ((lower || 512) > (upper || 1200)) unsupported();
        if (min !== undefined) output["obfs-min-packet-size"] = lower;
        if (max !== undefined) output["obfs-max-packet-size"] = upper;
      } else if (!empty(min) || !empty(max)) unsupported();
    } else if (!empty(password) || !empty(min) || !empty(max)) unsupported();
    option(source, output, "bbr-profile", (value) =>
      ["standard", "conservative", "aggressive"].includes(string(value)) ? value : unsupported());
  }
}

export function serializeClashProxy(node: NodeRecord): { name: string; proxy: Fields; hoppingPorts: number } {
  try {
    const { name, type, protocol, source: original, fromUri } = proxyInput(node, "clash");
    const clashType = CLASH_TYPES.get(protocol);
    if (!clashType) return unsupported();
    const fromNative = !fromUri && type === protocol
      && (Object.hasOwn(original, "server_port") || Object.hasOwn(original, "server_ports"));
    const source = fromNative ? portableNativeSource(original, protocol, "clash") : original;
    const output: Fields = { type: clashType, server: server(take(source, "server")) };
    const port = take(source, "port");
    let hoppingPorts = 0;
    if (protocol === "hysteria" || protocol === "hysteria2") {
      const range = take(source, "ports");
      if (!empty(range)) {
        const normalized = ports(range);
        hoppingPorts = expandedHoppingPorts(normalized);
        output.ports = normalized.map((item) => {
          const [start, end] = splitOnce(item, ":");
          return start === end ? start : start + "-" + end;
        }).join(",");
        if (protocol === "hysteria" && empty(port)) output.port = integer(splitOnce(normalized[0], ":")[0], 1, 65535);
        else if (!empty(port) && !(fromUri && protocol === "hysteria2")) output.port = integer(port, 1, 65535);
      }
    }
    if (hoppingPorts === 0) output.port = integer(port, 1, 65535);
    if (UDP_TOGGLE.has(protocol)) {
      option(source, output, "udp", flag);
    } else if (protocol === "hysteria2" && !fromUri && source.udp === true) {
      // Mihomo Hysteria 2 already enables UDP and has no UDP toggle.
      take(source, "udp");
    }
    if (protocol !== "hysteria" && protocol !== "hysteria2" && protocol !== "tuic") {
      option(source, output, "tfo", flag);
      option(source, output, "mptcp", flag);
    }
    if (TLS_REQUIRED.has(protocol) || TRANSPORT_PROTOCOLS.has(protocol) || protocol === "http" || protocol === "socks") {
      clashTls(source, output, protocol, type === "https");
    }
    if (TRANSPORT_PROTOCOLS.has(protocol)) clashTransport(source, output, protocol, fromUri);
    if (protocol === "shadowsocks") {
      const cipher = string(scalarAlias(source, ["cipher", "method"]));
      const password = string(take(source, "password", ""), cipher === "none");
      if (!SS_CIPHERS.has(cipher) || !validShadowsocks2022Keys(cipher, password)) unsupported();
      output.cipher = cipher;
      output.password = password;
      shadowsocksPlugin(source, output, fromUri);
      option(source, output, "udp-over-tcp", flag);
      option(source, output, "udp-over-tcp-version", (value) => integer(value, 1, 2));
    }
    if (protocol === "vmess" || protocol === "vless" || protocol === "tuic") {
      const id = string(take(source, "uuid"));
      if (protocol === "tuic" && !/^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/iu.test(id)) unsupported();
      output.uuid = id;
    }
    if (protocol === "vmess") {
      const cipher = string(scalarAlias(source, ["cipher", "security"], "auto"));
      if (!VMESS_CIPHERS.has(cipher)) unsupported();
      // Sing-box uses zero for its default VMess cipher when TLS is enabled.
      output.cipher = fromNative && output.tls === true && cipher === "auto" ? "zero" : cipher;
      output.alterId = integer(scalarAlias(source, ["alterId", "alter_id"], 0), 0, 65535);
      option(source, output, "global-padding", flag);
      option(source, output, "authenticated-length", flag);
    }
    if (protocol === "vless") {
      option(source, output, "flow", (value) => value === "xtls-rprx-vision" ? value : unsupported());
      if (!["", "none"].includes(string(take(source, "encryption", "none"), true))) unsupported();
    }
    if (protocol === "vmess" || protocol === "vless") {
      option(source, output, "packet-encoding", (value) =>
        ["packet", "packetaddr", "xudp"].includes(string(value)) ? value : unsupported());
    }
    if (protocol === "trojan" || protocol === "anytls") output.password = string(take(source, "password"));
    if (protocol === "hysteria2" || protocol === "tuic" || protocol === "http" || protocol === "socks") {
      option(source, output, "password", string);
    }
    if (protocol === "http" || protocol === "socks") {
      option(source, output, "username", string);
      if (output.password && !output.username) unsupported();
      if (protocol === "http") option(source, output, "headers", (value) => headerMap(value));
    }
    if (protocol === "hysteria" || protocol === "hysteria2") {
      hysteriaOptions(source, output, protocol);
      if (fromUri && protocol === "hysteria2") output["skip-cert-verify"] ??= false;
    }
    if (protocol === "tuic") {
      option(source, output, "congestion-controller", (value) =>
        ["cubic", "new_reno", "bbr"].includes(string(value)) ? value : unsupported());
      option(source, output, "udp-relay-mode", (value) =>
        ["native", "quic"].includes(string(value)) ? value : unsupported());
      option(source, output, "reduce-rtt", flag);
      option(source, output, "heartbeat-interval", (value) => integer(value, 1, MAX_INT32));
    }
    requireConsumed(source);
    return { name, proxy: output, hoppingPorts };
  } catch {
    throw new ClashContentError();
  }
}

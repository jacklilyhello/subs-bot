import {
  CONTROL, empty, expandedHoppingPorts, fields, flag, integer, normalizeList, ports, proxyInput,
  requireConsumed, scalarAlias, server, string, take, unsupported, TLS_REQUIRED, TRANSPORT_PROTOCOLS, type Fields,
} from "./proxy-input.ts";
import { portableNativeSource } from "./proxy-native.ts";
import { parseShadowsocksPlugin, splitOnce, validShadowsocks2022Keys } from "./stored-share.ts";
import type { NodeRecord } from "./storage.ts";

export type TextExportFormat = "surge" | "qx";
export class TextExportError extends Error {}

interface TextProxy {
  name: string;
  kind: string;
  host: string;
  port: number;
  options: string[];
  hoppingPorts: number;
}

const COMMON_PROTOCOLS = new Set(["shadowsocks", "vmess", "trojan", "anytls", "http", "socks"]);
const SURGE_ONLY = new Set(["hysteria2", "tuic"]);
const SURGE_SS = new Set([
  "none", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm",
  "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305", "rc4", "rc4-md5", "aes-128-cfb", "aes-192-cfb",
  "aes-256-cfb", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr", "salsa20", "chacha20", "chacha20-ietf",
]);
const QX_SS = new Set([
  "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
  "chacha20",
]);
const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}(?![\s\S])/iu;
const UNSAFE_VALUE = /["'\\#;[\]\ufeff]/u;
const HEADER_NAME = /^[A-Za-z0-9!#$%&'*+.^_\x60|~-]+(?![\s\S])/u;
const MAX_INT32 = 2 ** 31 - 1;

function scalar(value: unknown, format: TextExportFormat, allowEmpty = false): string {
  const text = string(value, allowEmpty);
  if (text.trim() !== text || CONTROL.test(text) || UNSAFE_VALUE.test(text) || /\s\/\//u.test(text)
    || !/^[^=]*={0,2}(?![\s\S])/u.test(text)) unsupported();
  if (!text.includes(",")) return text;
  return format === "surge" ? '"' + text + '"' : unsupported();
}

function label(value: string): string {
  if (/[=,]/u.test(value) || value.startsWith("//")) unsupported();
  return scalar(value, "qx");
}

function pair(options: string[], key: string, value: string | boolean | number): void {
  options.push(key + "=" + value);
}

function webPath(value: unknown, format: TextExportFormat): string {
  const path = string(value);
  const [, query] = splitOnce(path, "?");
  if (!path.startsWith("/") || path.startsWith("//") || (query && new URLSearchParams(query).has("ed"))) unsupported();
  return scalar(path, format);
}

interface TlsSettings {
  enabled: boolean;
  sni: string | null;
  insecure: boolean | null;
  alpn: string[];
}

function tlsSettings(source: Fields, protocol: string, originalType: string | undefined): TlsSettings {
  const required = TLS_REQUIRED.has(protocol) || protocol === "trojan" || originalType === "https";
  const enabled = flag(take(source, "tls", required));
  const sni = scalarAlias(source, ["servername", "sni"]);
  const insecure = take(source, "skip-cert-verify");
  const alpn = take(source, "alpn");
  const disable = take(source, "disable-sni");
  const fingerprint = take(source, "client-fingerprint");
  if ((!empty(disable) && flag(disable)) || (!empty(fingerprint) && fingerprint !== "none")) unsupported();
  if (enabled && Array.isArray(alpn) && alpn.length === 0) unsupported();
  if (!enabled && (required || !empty(sni) || !empty(alpn) || (!empty(insecure) && flag(insecure)))) unsupported();
  return {
    enabled, sni: empty(sni) ? null : server(sni),
    insecure: empty(insecure) ? null : flag(insecure), alpn: empty(alpn) ? [] : normalizeList(alpn),
  };
}

function tlsOptions(options: string[], tls: TlsSettings, format: TextExportFormat, qxSniKey: string): void {
  if (!tls.enabled) return;
  if (tls.sni) {
    // Surge interprets this token as a directive, not a literal hostname.
    if (format === "surge" && tls.sni.toLowerCase() === "off") unsupported();
    pair(options, format === "surge" ? "sni" : qxSniKey, scalar(tls.sni, format));
  }
  if (format === "qx") pair(options, "tls-verification", !tls.insecure);
  else if (tls.insecure !== null) pair(options, "skip-cert-verify", tls.insecure);
  if (tls.alpn.length === 0) return;
  for (const item of tls.alpn) {
    if (item.length > 255 || !/^[\x21-\x7e]+(?![\s\S])/u.test(item) || /[,=]/u.test(item)) unsupported();
    scalar(item, format);
  }
  if (format === "surge") pair(options, "alpn", scalar(tls.alpn.join(","), format));
  else {
    // Quantumult X represents the one-byte-length-prefixed ALPN strings in hex.
    const hex = tls.alpn.map((item) => item.length.toString(16).padStart(2, "0")
      + [...item].map((char) => char.charCodeAt(0).toString(16).padStart(2, "0")).join("")).join("");
    if (hex.length > 2 * 65535) unsupported();
    pair(options, "tls-alpn", hex);
  }
}

function wsOptions(
  source: Fields, options: string[], format: TextExportFormat, protocol: string, host: string,
  tls: TlsSettings, fromUri: boolean,
): boolean {
  const network = take(source, "network");
  if (empty(network) || network === "tcp" || network === "raw") return false;
  if (network !== "ws") return unsupported();
  const settings = fields(take(source, "ws-opts", {}));
  const path = take(settings, "path");
  const headers = take(settings, "headers");
  // Neither target documents the v2rayN early-data header or byte limit.
  requireConsumed(settings);
  let hostHeader: string | null = null;
  const renderedHeaders: string[] = [];
  if (!empty(headers)) {
    const seen = new Set<string>();
    for (const [key, value] of Object.entries(fields(headers))) {
      const name = key.toLowerCase();
      const text = string(value);
      if (!HEADER_NAME.test(key) || /['#|]/u.test(key) || seen.has(name) || /[:|,]/u.test(text)) unsupported();
      seen.add(name);
      if (name === "host") hostHeader = server(text);
      if (format === "surge") renderedHeaders.push(key + ":" + scalar(text, format));
      else if (name !== "host") unsupported();
    }
  }
  if (fromUri && protocol === "vmess" && tls.enabled && !tls.sni && hostHeader) tls.sni = hostHeader;
  if (format === "surge") {
    pair(options, "ws", true);
    if (!empty(path)) pair(options, "ws-path", webPath(path, format));
    if (renderedHeaders.length) pair(options, "ws-headers", renderedHeaders.join("|"));
  } else {
    if (tls.enabled && (tls.sni ?? host) !== (hostHeader ?? host)) unsupported();
    if (tls.enabled) tls.sni = hostHeader ?? tls.sni;
    pair(options, "obfs", tls.enabled ? "wss" : "ws");
    if (!tls.enabled && hostHeader) pair(options, "obfs-host", scalar(hostHeader, format));
    if (!empty(path)) pair(options, "obfs-uri", webPath(path, format));
  }
  return true;
}

function shadowsocks(source: Fields, options: string[], format: TextExportFormat, fromUri: boolean): void {
  const cipher = string(scalarAlias(source, ["cipher", "method"]));
  const password = string(take(source, "password", ""), format === "surge" && cipher === "none");
  if (!(format === "surge" ? SURGE_SS : QX_SS).has(cipher) || !validShadowsocks2022Keys(cipher, password)) unsupported();
  pair(options, format === "surge" ? "encrypt-method" : "method", cipher);
  let renderedPassword: string;
  if (cipher.startsWith("2022-")) {
    // Surge documents one optional user key. Quantumult X shows single keys.
    const keys = password.split(":");
    if (keys.length > (format === "surge" ? 2 : 1)) unsupported();
    renderedPassword = keys.map((key) => scalar(key, format)).join(":");
  } else renderedPassword = scalar(password, format, cipher === "none");
  pair(options, "password", renderedPassword);
  const plugin = take(source, "plugin");
  const pluginOptions = take(source, "plugin-opts");
  if (empty(plugin)) {
    if (!empty(pluginOptions)) unsupported();
    return;
  }
  const kind = plugin === "obfs" || plugin === "obfs-local" || plugin === "simple-obfs" ? "obfs-local" : plugin;
  if (kind !== "obfs-local" && (kind !== "v2ray-plugin" || format !== "qx")) unsupported();
  if (typeof pluginOptions === "string" || fromUri) {
    const parsed = parseShadowsocksPlugin(kind + ";" + string(pluginOptions ?? "", true));
    if (!parsed) return unsupported();
    if (kind === "obfs-local") {
      pair(options, "obfs", string(parsed.options.get("obfs")));
      pair(options, "obfs-host", scalar(server(parsed.options.get("obfs-host")), format));
    } else {
      // Quantumult X's WebSocket obfuscation has no SIP003 multiplex toggle.
      if (integer(parsed.options.get("mux") ?? 1, 0, 65535) !== 0) unsupported();
      const tls = parsed.options.has("tls");
      pair(options, "obfs", tls ? "wss" : "ws");
      pair(options, "obfs-host", scalar(server(parsed.options.get("host") ?? (fromUri ? "cloudfront.com" : "")), format));
      pair(options, "obfs-uri", webPath(parsed.options.get("path") ?? "/", format));
      if (tls) pair(options, "tls-verification", true);
    }
    return;
  }
  const settings = fields(pluginOptions);
  const mode = take(settings, "mode");
  const host = take(settings, "host", "bing.com");
  if (kind === "obfs-local") {
    if (mode !== "tls" && mode !== "http") unsupported();
    pair(options, "obfs", mode);
    const path = take(settings, "path");
    if (!empty(path)) {
      if (mode !== "http") unsupported();
      pair(options, "obfs-uri", webPath(path, format));
    }
  } else {
    if (mode !== "websocket" || flag(take(settings, "mux", true))) unsupported();
    const tls = flag(take(settings, "tls", false));
    pair(options, "obfs", tls ? "wss" : "ws");
    pair(options, "obfs-uri", webPath(take(settings, "path", "/"), format));
    const insecure = take(settings, "skip-cert-verify");
    if (!tls && !empty(insecure)) unsupported();
    if (tls) pair(options, "tls-verification", empty(insecure) || !flag(insecure));
  }
  pair(options, "obfs-host", scalar(server(host), format));
  requireConsumed(settings);
}

function vmess(source: Fields, options: string[], format: TextExportFormat): void {
  const id = string(take(source, "uuid"));
  const method = string(scalarAlias(source, ["cipher", "security"]));
  const chacha = method === "chacha20-poly1305" || method === "chacha20-ietf-poly1305";
  if (!UUID.test(id) || integer(scalarAlias(source, ["alterId", "alter_id"], 0), 0, 65535) !== 0
    || (!chacha && method !== "aes-128-gcm" && !(format === "qx" && method === "none"))) unsupported();
  pair(options, format === "surge" ? "username" : "password", id);
  pair(options, format === "surge" ? "encrypt-method" : "method",
    chacha ? (format === "surge" ? "chacha20-ietf-poly1305" : "chacha20-poly1305") : method);
  pair(options, format === "surge" ? "vmess-aead" : "aead", true);
}

function vless(source: Fields, options: string[]): void {
  const id = string(take(source, "uuid"));
  const encryption = take(source, "encryption", "none");
  if (!UUID.test(id) || (encryption !== "none" && encryption !== "")) unsupported();
  pair(options, "method", "none");
  pair(options, "password", id);
  const flow = take(source, "flow");
  if (!empty(flow)) {
    if (flow !== "xtls-rprx-vision") unsupported();
    pair(options, "vless-flow", flow);
  }
}

function hysteria2(source: Fields, options: string[]): void {
  const bandwidth = take(source, "down");
  if (!empty(bandwidth)) {
    const raw = typeof bandwidth === "string" ? bandwidth.replace(/\s*Mbps$/iu, "") : bandwidth;
    pair(options, "download-bandwidth", integer(raw, 1, MAX_INT32));
  }
  const obfs = take(source, "obfs");
  const obfsPassword = take(source, "obfs-password");
  if (!empty(obfs)) {
    if (obfs !== "salamander" && obfs !== "gecko") unsupported();
    pair(options, obfs + "-password", scalar(obfsPassword, "surge"));
  } else if (!empty(obfsPassword)) unsupported();
}

function networkOptions(source: Fields, options: string[], protocol: string, format: TextExportFormat): void {
  const udp = take(source, "udp");
  if (!empty(udp)) {
    const enabled = flag(udp);
    if (protocol === "http") {
      if (enabled) unsupported();
    } else if (format === "qx" || protocol === "shadowsocks" || protocol === "socks") pair(options, "udp-relay", enabled);
    else if (!enabled) unsupported();
  }
  const tfo = take(source, "tfo");
  if (!empty(tfo)) {
    if (protocol === "hysteria2" || protocol === "tuic") unsupported();
    pair(options, format === "surge" ? "tfo" : "fast-open", flag(tfo));
  }
  const uot = take(source, "udp-over-tcp");
  const uotVersion = take(source, "udp-over-tcp-version");
  if (!empty(uot) && flag(uot)) {
    if (format !== "qx" || protocol !== "shadowsocks" || udp === undefined || !flag(udp)) unsupported();
    pair(options, "udp-over-tcp", "sp.v" + integer(uotVersion ?? 1, 1, 2));
  } else if (!empty(uotVersion)) unsupported();
}

export function parseTextProxy(node: NodeRecord, format: TextExportFormat): TextProxy {
  try {
    const { name, type, protocol, source: input, fromUri } = proxyInput(node, format);
    if (!COMMON_PROTOCOLS.has(protocol) && !(format === "surge" ? SURGE_ONLY.has(protocol) : protocol === "vless")) unsupported();
    const source = !fromUri && type === protocol && (Object.hasOwn(input, "server_port") || Object.hasOwn(input, "server_ports"))
      ? portableNativeSource(input, protocol, format) : input;
    const host = server(take(source, "server"));
    const options: string[] = [];
    const portValue = take(source, "port");
    let port: number;
    let hoppingPorts = 0;
    const ranges = protocol === "hysteria2" || protocol === "tuic" ? take(source, "ports") : undefined;
    if (empty(ranges)) port = integer(portValue, 1, 65535);
    else {
      const normalized = ports(ranges);
      hoppingPorts = expandedHoppingPorts(normalized);
      port = empty(portValue) ? integer(splitOnce(normalized[0], ":")[0], 1, 65535) : integer(portValue, 1, 65535);
      pair(options, "port-hopping", normalized.map((range) => {
        const [start, end] = splitOnce(range, ":");
        return start === end ? start : start + "-" + end;
      }).join(";"));
      const interval = take(source, "hop-interval");
      if (!empty(interval)) pair(options, "port-hopping-interval", integer(interval, 1, MAX_INT32));
    }
    const tls = tlsSettings(source, protocol, type);
    let kind = protocol;
    if (protocol === "shadowsocks") {
      if (tls.enabled) unsupported();
      kind = format === "surge" ? "ss" : "shadowsocks";
      shadowsocks(source, options, format, fromUri);
    } else if (protocol === "vmess") vmess(source, options, format);
    else if (protocol === "vless") vless(source, options);
    else if (protocol === "http" || protocol === "socks") {
      kind = protocol === "http" ? "http" : "socks5";
      if (format === "surge" && tls.enabled) kind = protocol === "http" ? "https" : "socks5-tls";
      const username = take(source, "username");
      const password = take(source, "password");
      if (!empty(username) || !empty(password)) {
        pair(options, "username", scalar(username, format));
        pair(options, "password", scalar(password, format));
      }
      if (protocol === "http" && format === "surge") pair(options, "always-use-connect", true);
    } else {
      if (protocol === "tuic") {
        kind = "tuic-v5";
        const id = string(take(source, "uuid"));
        if (!UUID.test(id)) unsupported();
        pair(options, "uuid", id);
      }
      pair(options, "password", scalar(take(source, "password"), format));
      if (protocol === "hysteria2") hysteria2(source, options);
    }
    const ws = TRANSPORT_PROTOCOLS.has(protocol) && wsOptions(source, options, format, protocol, host, tls, fromUri);
    if (options.includes("vless-flow=xtls-rprx-vision") && (!tls.enabled || ws)) unsupported();
    if (format === "surge") {
      if (protocol === "vmess") pair(options, "tls", tls.enabled);
      if (protocol === "trojan" && !tls.sni) tls.sni = host;
    } else if (tls.enabled && !ws) {
      if (protocol === "vmess" || protocol === "vless") pair(options, "obfs", "over-tls");
      else pair(options, "over-tls", true);
    }
    tlsOptions(options, tls, format, ws || protocol === "vmess" || protocol === "vless" ? "obfs-host" : "tls-host");
    networkOptions(source, options, protocol, format);
    // These clients do not expose compatible transport, ECH, pinning, or
    // fingerprint knobs for all source protocols. Do not drop a supplied one.
    requireConsumed(source);
    return { name: label(name), kind, host, port, options, hoppingPorts };
  } catch {
    throw new TextExportError();
  }
}

export function textProxyLine(proxy: TextProxy, name: string, format: TextExportFormat): string {
  if (format === "surge") return name + " = " + [proxy.kind, proxy.host, proxy.port, ...proxy.options].join(", ") + "\n";
  const endpoint = (proxy.host.includes(":") ? "[" + proxy.host + "]" : proxy.host) + ":" + proxy.port;
  return [proxy.kind + "=" + endpoint, ...proxy.options, "tag=" + name].join(", ") + "\n";
}

import {
  numberInRange, splitOnce, validIpv6, validServer, validShadowsocks2022Keys, validShadowsocksPlugin,
} from "./stored-share.ts";

type Fields = Record<string, unknown>;
type Query = Record<string, string>;
const encoder = new TextEncoder();
const BASE64_CHUNK_BYTES = 24 * 1024;

class UnsupportedShareError extends Error {}

function unsupported(): never {
  throw new UnsupportedShareError();
}

function isRecord(value: unknown): value is Fields {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function fieldsOf(value: unknown): Fields {
  if (!isRecord(value)) return unsupported();
  return Object.assign(Object.create(null), value) as Fields;
}

function sameValue(left: unknown, right: unknown, depth = 0): boolean {
  if (left === right) return true;
  // Known nested settings are shallow. Do not recurse through a hostile alias.
  if (depth >= 16) return false;
  if (Array.isArray(left) && Array.isArray(right)) {
    return left.length === right.length && left.every((value, index) => sameValue(value, right[index], depth + 1));
  }
  if (!isRecord(left) || !isRecord(right)) return false;
  const keys = Object.keys(left);
  return keys.length === Object.keys(right).length
    && keys.every((key) => Object.hasOwn(right, key) && sameValue(left[key], right[key], depth + 1));
}

function take(fields: Fields, keys: string | readonly string[], fallback: unknown = null): unknown {
  let first: unknown;
  for (const key of typeof keys === "string" ? [keys] : keys) {
    if (!Object.hasOwn(fields, key)) continue;
    const value = fields[key];
    delete fields[key];
    if (value === undefined || value === null || value === "") continue;
    if (first === undefined) first = value;
    else if (!sameValue(first, value)) return unsupported();
  }
  return first === undefined ? fallback : first;
}

function requireConsumed(fields: Fields): void {
  if (Object.keys(fields).length !== 0) unsupported();
}

function text(value: unknown): string {
  if (typeof value !== "string" || !value || /[\ud800-\udfff]/u.test(value)) return unsupported();
  return value;
}

function flag(value: unknown): boolean {
  if (typeof value !== "boolean") return unsupported();
  return value;
}

function integer(value: unknown, minimum: number, maximum: number): number {
  return numberInRange(value, minimum, maximum) ?? unsupported();
}

function truthy(value: unknown): boolean {
  if (Array.isArray(value)) return value.length > 0;
  if (isRecord(value)) return Object.keys(value).length > 0;
  return Boolean(value);
}

function quote(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/gu, (character) => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);
}

function base64(value: string): string {
  const bytes = encoder.encode(value);
  const chunks: string[] = [];
  // Multiples of three avoid padding in intermediate chunks.
  for (let offset = 0; offset < bytes.length; offset += BASE64_CHUNK_BYTES) {
    chunks.push(btoa(String.fromCharCode(...bytes.subarray(offset, offset + BASE64_CHUNK_BYTES))));
  }
  return chunks.join("");
}

function queryString(query: Query): string {
  const fields = Object.entries(query).map(([key, value]) => `${quote(key)}=${quote(value)}`);
  return fields.length ? `?${fields.join("&")}` : "";
}

function serverAddress(value: unknown): [string, string] {
  const host = text(value);
  // Python Nameprep and the Worker's URL domain conversion can choose
  // different destinations. Use only explicit ASCII or IP addresses here.
  if (/[^\x00-\x7f]/u.test(host)) return unsupported();
  const address = host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
  if (validIpv6(address)) return [address, `[${address}]`];
  if (!validServer(host)) return unsupported();
  return [host, host];
}

function tlsQuery(fields: Fields, defaultEnabled = false): Query {
  const tls = take(fields, "tls", defaultEnabled);
  const options = isRecord(tls) ? fieldsOf(tls) : fieldsOf({});
  const enabled = isRecord(tls) ? flag(take(options, "enabled", false)) : flag(tls);
  for (const key of ["sni", "servername", "skip-cert-verify", "alpn", "client-fingerprint", "reality-opts"]) {
    if (!Object.hasOwn(fields, key)) continue;
    if (Object.hasOwn(options, key) && !sameValue(options[key], fields[key])) return unsupported();
    options[key] = fields[key];
    delete fields[key];
  }

  const query: Query = { security: enabled ? "tls" : "none" };
  const sni = take(options, ["sni", "servername", "server_name"]);
  if (sni !== null) query.sni = text(sni);
  if (flag(take(options, ["skip-cert-verify", "insecure"], false))) query.allowInsecure = "1";
  const rawAlpn = take(options, "alpn", []);
  const alpn = typeof rawAlpn === "string" ? [rawAlpn] : rawAlpn;
  if (!Array.isArray(alpn)) return unsupported();
  const protocols = alpn.map(text);
  if (protocols.some((protocol) => protocol.includes(","))) return unsupported();
  if (protocols.length) query.alpn = protocols.join(",");

  let fingerprint = take(options, "client-fingerprint");
  const utls = fieldsOf(take(options, "utls", {}));
  if (flag(take(utls, "enabled", false))) {
    if (fingerprint !== null) return unsupported();
    fingerprint = take(utls, "fingerprint", "chrome");
  }
  requireConsumed(utls);
  if (fingerprint !== null) query.fp = text(fingerprint);

  const reality = fieldsOf(take(options, ["reality", "reality-opts"], {}));
  if (flag(take(reality, "enabled", Object.keys(reality).length !== 0))) {
    query.security = "reality";
    query.pbk = text(take(reality, ["public-key", "public_key"]));
    const shortId = take(reality, ["short-id", "short_id"]);
    if (shortId !== null) query.sid = text(shortId);
    const spider = take(reality, ["spider-x", "spider_x"]);
    if (spider !== null) query.spx = text(spider);
    query.fp ??= "chrome";
  }
  requireConsumed(reality);
  requireConsumed(options);
  if (!enabled && (query.security !== "none" || Object.keys(query).length !== 1)) return unsupported();
  return query;
}

function transportQuery(fields: Fields, native: boolean): [string, Query] {
  let transport: Fields;
  let kind: string;
  if (native) {
    transport = fieldsOf(take(fields, "transport", {}));
    kind = text(take(transport, "type", "tcp"));
  } else {
    kind = text(take(fields, "network", "tcp"));
    transport = fieldsOf(take(fields, `${kind}-opts`, {}));
  }
  const query: Query = {};
  if (kind === "tcp" || kind === "raw") {
    kind = "tcp";
  } else if (kind === "ws" || kind === "httpupgrade") {
    const headers = fieldsOf(take(transport, "headers", {}));
    let host = take(transport, "host");
    for (const [header, value] of Object.entries(headers)) {
      if (header.toLowerCase() !== "host" || host !== null) return unsupported();
      host = value;
    }
    if (Array.isArray(host) && host.length === 1) [host] = host;
    if (host !== null) query.host = text(host);
    const path = take(transport, "path");
    const earlyData = take(transport, ["max-early-data", "max_early_data"], 0);
    const earlyHeader = take(transport, ["early-data-header-name", "early_data_header_name"]);
    if (truthy(earlyData) || truthy(earlyHeader)) return unsupported();
    if (path !== null) query.path = text(path);
  } else if (kind === "grpc") {
    const service = take(transport, ["grpc-service-name", "service_name"]);
    if (service !== null) query.serviceName = text(service);
  } else if (kind === "h2" || kind === "http") {
    kind = "http";
    const rawHost = take(transport, "host");
    const host = Array.isArray(rawHost) ? rawHost.map(text).join(",") : rawHost;
    if (truthy(host)) query.host = text(host);
    const path = take(transport, "path");
    if (path !== null) query.path = text(path);
  } else {
    return unsupported();
  }
  requireConsumed(transport);
  return [kind, query];
}

function escapePlugin(value: unknown): string {
  return text(value).replace(/[:;=\\]/gu, (character) => `\\${character}`);
}

function shadowsocksPlugin(fields: Fields): string | null {
  const choice = take(fields, "plugin");
  if (choice === null) return null;
  const plugin = choice === "obfs" ? "obfs-local" : choice;
  if (plugin !== "obfs-local" && plugin !== "v2ray-plugin") return unsupported();
  const rawOptions = take(fields, ["plugin-opts", "plugin_opts"], {});
  if (typeof rawOptions === "string") {
    const value = `${plugin};${rawOptions}`;
    return validShadowsocksPlugin(value) ? value : unsupported();
  }
  const options = fieldsOf(rawOptions);
  const params: string[] = [plugin];
  const mode = take(options, "mode");
  const host = take(options, "host");
  if (plugin === "obfs-local") {
    if (mode !== "http" && mode !== "tls") return unsupported();
    params.push(`obfs=${mode}`);
    if (host !== null) params.push(`obfs-host=${escapePlugin(host)}`);
  } else {
    if (mode !== null && mode !== "websocket") return unsupported();
    params.push("mode=websocket");
    const path = take(options, "path");
    if (host !== null) params.push(`host=${escapePlugin(host)}`);
    if (path !== null) params.push(`path=${escapePlugin(path)}`);
    if (flag(take(options, "tls", false))) params.push("tls");
    const mux = take(options, "mux");
    if (mux !== null) params.push(`mux=${Number(flag(mux))}`);
  }
  requireConsumed(options);
  const value = params.join(";");
  return validShadowsocksPlugin(value) ? value : unsupported();
}

function shadowsocksLink(fields: Fields, authority: string, label: string): string {
  const method = text(take(fields, ["cipher", "method"]));
  if (!/^[A-Za-z0-9_-]+(?![\s\S])/u.test(method)) return unsupported();
  const rawPassword = take(fields, "password", method === "none" ? "" : null);
  const password = method === "none" && rawPassword === "" ? "" : text(rawPassword);
  const aead2022 = method.startsWith("2022-");
  if (aead2022 && !validShadowsocks2022Keys(method, password)) return unsupported();
  const userinfo = aead2022 ? `${quote(method)}:${quote(password)}`
    : base64(`${method}:${password}`).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
  const plugin = shadowsocksPlugin(fields);
  return `ss://${userinfo}@${authority}${plugin === null ? "" : `/${queryString({ plugin })}`}${label}`;
}

function vmessLink(fields: Fields, name: string, host: string, port: number, native: boolean): string {
  const cipher = text(take(fields, ["cipher", "security"], "auto"));
  const clientId = text(take(fields, "uuid"));
  const alterId = integer(take(fields, ["alterId", "alter_id"], 0), 0, 65535);
  const [network, transport] = transportQuery(fields, native);
  const tls = tlsQuery(fields);
  const security = tls.security;
  delete tls.security;
  if (security === "reality" || network === "http") return unsupported();
  if (tls.allowInsecure !== undefined) {
    delete tls.allowInsecure;
    tls.insecure = "1";
  }
  const payload: Query = {
    v: "2", ps: name, add: host, port: String(port), id: clientId, aid: String(alterId), scy: cipher, net: network,
    type: "none", host: transport.host ?? "", path: transport.serviceName ?? transport.path ?? "",
    tls: security === "tls" ? "tls" : "", ...tls,
  };
  // Keep v2rayN's legacy JSON envelope and the Python export's field order and spacing.
  const json = "{" + Object.entries(payload).map(([key, value]) => `${JSON.stringify(key)}: ${JSON.stringify(value)}`).join(", ") + "}";
  return "vmess://" + base64(json);
}

function simpleTlsQuery(fields: Fields, insecureKey: "insecure" | "allow_insecure", allowAlpn = false): Query {
  const query = tlsQuery(fields, true);
  if (query.security !== "tls") return unsupported();
  delete query.security;
  if (Object.keys(query).some((key) => key !== "sni" && key !== "allowInsecure" && (!allowAlpn || key !== "alpn"))) {
    return unsupported();
  }
  if (query.allowInsecure !== undefined) {
    delete query.allowInsecure;
    query[insecureKey] = "1";
  }
  return query;
}

function hysteria2Query(fields: Fields): Query {
  const query = simpleTlsQuery(fields, "insecure");
  let obfs = take(fields, "obfs");
  let password: unknown;
  if (isRecord(obfs)) {
    const options = fieldsOf(obfs);
    obfs = take(options, "type");
    password = take(options, "password");
    requireConsumed(options);
  } else {
    password = take(fields, "obfs-password");
  }
  if (obfs !== null) {
    if (obfs !== "salamander" && obfs !== "gecko") return unsupported();
    query.obfs = obfs;
    query["obfs-password"] = text(password);
  } else if (password !== null) {
    return unsupported();
  }
  const fingerprint = take(fields, "fingerprint");
  if (fingerprint !== null) {
    const pin = text(fingerprint).replaceAll(":", "");
    if (!/^[0-9a-fA-F]{64}(?![\s\S])/u.test(pin)) return unsupported();
    query.pinSHA256 = pin.toLowerCase();
  }
  return query;
}

function tuicQuery(fields: Fields): Query {
  const query = simpleTlsQuery(fields, "allow_insecure", true);
  const congestion = take(fields, ["congestion-controller", "congestion_control"]);
  if (congestion !== null) {
    if (congestion !== "cubic" && congestion !== "new_reno" && congestion !== "bbr") return unsupported();
    query.congestion_control = congestion;
  }
  const relay = take(fields, ["udp-relay-mode", "udp_relay_mode"]);
  if (relay !== null) {
    if (relay !== "native" && relay !== "quic") return unsupported();
    query.udp_relay_mode = relay;
  }
  return query;
}

function uuid(value: unknown): string {
  let id = text(value);
  if (id.startsWith("urn:uuid:")) id = id.slice(9);
  if (id.startsWith("{") && id.endsWith("}")) id = id.slice(1, -1);
  if (!/^(?:[0-9a-f]{32}|[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12})(?![\s\S])/iu.test(id)) return unsupported();
  const hex = id.replaceAll("-", "").toLowerCase();
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function authorityLink(fields: Fields, kind: string, authority: string, label: string, native: boolean): string {
  let auth: string;
  let query: Query;
  switch (kind) {
    case "vless":
    case "trojan": {
      auth = quote(text(take(fields, kind === "vless" ? "uuid" : "password")));
      const [network, transport] = transportQuery(fields, native);
      const tls = tlsQuery(fields, kind === "trojan");
      if (kind === "trojan" && (tls.security === "none" || network === "http")) return unsupported();
      query = { type: network, ...transport, ...tls };
      if (kind === "vless") {
        if (tls.allowInsecure !== undefined) return unsupported();
        query.encryption = text(take(fields, "encryption", "none"));
      }
      const flow = take(fields, "flow");
      if (flow !== null) query.flow = text(flow);
      break;
    }
    case "hysteria2": {
      const password = take(fields, "password");
      if (password === null) auth = "";
      else {
        const [user, secret] = splitOnce(text(password), ":");
        auth = quote(user) + (secret === undefined ? "" : `:${quote(secret)}`);
      }
      query = hysteria2Query(fields);
      break;
    }
    case "tuic":
      auth = `${uuid(take(fields, "uuid"))}:${quote(text(take(fields, "password")))}`;
      query = tuicQuery(fields);
      break;
    case "anytls":
      auth = quote(text(take(fields, "password")));
      query = simpleTlsQuery(fields, "insecure");
      break;
    default:
      return unsupported();
  }
  return `${kind}://${auth ? `${auth}@` : ""}${authority}${queryString(query)}${label}`;
}

export function serializeStructuredShare(node: Fields): string | null {
  try {
    const fields = fieldsOf(node);
    let kind = text(take(fields, "type")).toLowerCase();
    if (kind === "shadowsocks") kind = "ss";
    if (kind === "hy2") kind = "hysteria2";
    if (!["ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls"].includes(kind)) return null;

    const name = text(take(fields, ["name", "tag"], "node"));
    take(fields, ["share", "raw"]);
    // Clash's UDP flag is local forwarding. Native connection restrictions remain unsupported.
    flag(take(fields, "udp", false));
    const native = Object.hasOwn(fields, "server_port") && !Object.hasOwn(fields, "port");
    const [host, address] = serverAddress(take(fields, "server"));
    const defaultPort = kind === "hysteria2" || kind === "anytls" ? 443 : null;
    const port = integer(take(fields, ["port", "server_port"], defaultPort), 1, 65535);
    const authority = `${address}:${port}`;
    const label = `#${quote(name)}`;
    let link: string;
    if (kind === "ss") link = shadowsocksLink(fields, authority, label);
    else if (kind === "vmess") link = vmessLink(fields, name, host, port, native);
    else link = authorityLink(fields, kind, authority, label, native);
    requireConsumed(fields);
    return link;
  } catch (error) {
    if (error instanceof UnsupportedShareError || error instanceof URIError) return null;
    throw error;
  }
}

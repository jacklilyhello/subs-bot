import { fields, integer, isRecord, requireConsumed, server, take, unsupported, type Fields } from "./proxy-input.ts";

const AEAD = new Set(["aes-128-gcm", "chacha20-poly1305"]);
const SIMPLE_TLS = new Set(["enabled", "server_name", "insecure", "alpn", "disable_sni"]);
const ORIGIN_PATH = /^\/(?!\/)[A-Za-z0-9._~/-]*(?![\s\S])/u;
const AUTHORITY = /^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9_.-]+)(?::([0-9]{1,5}))?(?![\s\S])/u;

export function requireVmessH2Connection(tls: unknown, cipher: unknown, alterId: unknown): void {
  if (typeof cipher !== "string" || !AEAD.has(cipher) || (alterId !== undefined && alterId !== 0)
    || !isRecord(tls) || tls.enabled !== true || (tls.disable_sni !== undefined && tls.disable_sni !== false)
    || Object.keys(tls).some((key) => !SIMPLE_TLS.has(key))) unsupported();
  const { alpn, server_name: sni } = tls;
  const protocols = Array.isArray(alpn) ? alpn : alpn === undefined || alpn === "" ? [] : [alpn];
  if (protocols.length > 1 || (protocols.length === 1 && protocols[0] !== "h2")) unsupported();
  if (sni !== undefined && sni !== "" && server(sni) !== sni) unsupported();
}

function requireIdentityHttp(settings: Fields): void {
  const method = take(settings, "method");
  if (method !== undefined && method !== "" && method !== "PUT") unsupported();
  const headers = Object.entries(fields(take(settings, "headers")));
  if (headers.length !== 1 || headers[0][0].toLowerCase() !== "accept-encoding") unsupported();
  const value = headers[0][1];
  if (value !== "identity" && !(Array.isArray(value) && value.length === 1 && value[0] === "identity")) unsupported();
}

export function portableVmessH2Options(input: unknown, source: "clash" | "singbox"): Fields {
  const settings = fields(input);
  if (source === "singbox") requireIdentityHttp(settings);
  const host = take(settings, "host");
  const path = take(settings, "path");
  requireConsumed(settings);

  const options: Fields = {};
  if (host !== undefined) {
    const hosts = Array.isArray(host) ? host : [host];
    for (const value of hosts) {
      const match = typeof value === "string" && AUTHORITY.exec(value);
      if (!match) unsupported();
      server(match[1]);
      if (match[2] !== undefined) integer(match[2], 1, 65535);
    }
    if (hosts.length) options.host = hosts;
  }
  // Mihomo treats Path literally, while sing-box also interprets %-escapes.
  if (path !== undefined && path !== "") {
    if (typeof path !== "string" || !ORIGIN_PATH.test(path)) unsupported();
    options.path = path;
  }
  return options;
}

// Stored URI validation follows share_export.py. Return the exact input only
// when it can be forwarded, without rewriting the authority or display label.
const SCHEMES = new Set([
  "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2",
  "tuic", "snell", "wireguard", "anytls", "socks5", "socks5-tls",
]);
const AUTHORITY_SCHEMES = new Set(["vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks5"]);
const DEFAULT_PORT_SCHEMES = new Set(["hysteria2", "hy2", "anytls", "socks5"]);
const AUTH_REQUIRED = new Set(["vmess", "vless", "trojan", "tuic", "anytls"]);
const USERNAME_REQUIRED = new Set(["vmess", "vless", "tuic"]);
const SS_2022_KEY_BYTES = new Map([
  ["2022-blake3-aes-128-gcm", 16],
  ["2022-blake3-aes-256-gcm", 32],
  ["2022-blake3-chacha20-poly1305", 32],
  ["2022-blake3-chacha8-poly1305", 32],
]);
const INVALID_LINE_CHARACTER = /[\u0000-\u001f\u007f-\u009f\u2028\u2029\ud800-\udfff]/u;
const DOMAIN_LABEL = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?![\s\S])/u;
const utf8 = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true });
const percentUtf8 = new TextDecoder("utf-8", { ignoreBOM: true });

function splitOnce(value: string, separator: string): [string, string | undefined] {
  const index = value.indexOf(separator);
  return index === -1 ? [value, undefined] : [value.slice(0, index), value.slice(index + separator.length)];
}

function binaryBytes(value: string): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(value, (character) => character.charCodeAt(0));
}

function unquote(value: string): string {
  // Match urllib.parse.unquote, which keeps stray percent signs and replaces
  // invalid UTF-8 within an escaped run. Userinfo does not decode "+" as space.
  return value.replace(/(?:%[0-9a-f]{2})+/giu, (run) => {
    const bytes = new Uint8Array(run.length / 3);
    for (let index = 0; index < bytes.length; index++) {
      bytes[index] = Number.parseInt(run.slice(index * 3 + 1, index * 3 + 3), 16);
    }
    return percentUtf8.decode(bytes);
  });
}

function decodeBase64(value: string, requireStandardPadding = false): string | null {
  const match = /^([A-Za-z0-9+/_-]+)(=*)(?![\s\S])/u.exec(value);
  if (!match || (requireStandardPadding && /[-_]/u.test(match[1]))) return null;
  const [, encoded, explicitPadding] = match;
  const remainder = encoded.length % 4;
  const added = requireStandardPadding ? 0 : (4 - value.length % 4) % 4;
  // Python 3.11 accepts extra "=" only following an already complete quartet.
  if (remainder === 1 || (remainder !== 0 && explicitPadding.length + added !== 4 - remainder)) return null;
  return atob(encoded.replaceAll("-", "+").replaceAll("_", "/"));
}

function validIpv6(value: string): boolean {
  if (!value.includes(":") || /[^0-9a-f:.]/iu.test(value)) return false;
  try {
    return new URL("https://[" + value + "]/").hostname.startsWith("[");
  } catch {
    return false;
  }
}

function validServer(value: unknown): boolean {
  if (typeof value !== "string" || !value) return false;
  if (value.startsWith("[") && value.endsWith("]")) return validIpv6(value.slice(1, -1));
  if (value.includes(":")) return validIpv6(value);

  let domain = value;
  if (/[^\x00-\x7f]/u.test(value)) {
    // Use the platform IDNA conversion only after excluding URL delimiters.
    if (/[/\\?#@:%[\]\p{White_Space}]/u.test(value.normalize("NFKC"))) return false;
    domain = new URL("https://" + value + "/").hostname;
  }
  if (domain.endsWith(".")) domain = domain.slice(0, -1);
  return domain.length <= 253 && domain.split(".").every((label) => DOMAIN_LABEL.test(label));
}

function numberInRange(value: unknown, minimum: number, maximum: number): number | null {
  const number = typeof value === "string" && /^[0-9]{1,10}(?![\s\S])/u.test(value) ? Number(value) : value;
  return typeof number === "number" && Number.isSafeInteger(number) && number >= minimum && number <= maximum
    ? number : null;
}

function validEndpoint(endpoint: string, scheme: string): boolean {
  let ports: string | undefined;
  if (endpoint.startsWith("[")) {
    const match = /^\[([^\]]+)\](?::([^:]+))?(?![\s\S])/u.exec(endpoint);
    if (!match) return false;
    const [address, zone] = splitOnce(match[1], "%25");
    if (!validIpv6(address) || (zone !== undefined && !/^[A-Za-z0-9_.~-]+(?![\s\S])/u.test(zone))) return false;
    ports = match[2];
  } else {
    const match = /^([^:[\]]+)(?::([^:]+))?(?![\s\S])/u.exec(endpoint);
    if (!match || !validServer(match[1])) return false;
    ports = match[2];
  }
  if (ports === undefined) return DEFAULT_PORT_SCHEMES.has(scheme);
  if (scheme !== "hy2" && scheme !== "hysteria2") return numberInRange(ports, 1, 65535) !== null;
  return ports.split(",").every((span) => {
    const [start, end] = splitOnce(span, "-");
    const first = numberInRange(start, 1, 65535);
    return first !== null && (end === undefined || numberInRange(end, first, 65535) !== null);
  });
}

function authority(address: string): string {
  return address.split(/[/?#]/u, 1)[0];
}

function safeAuthority(value: string): boolean {
  const plain = value.replace(/[@:#?]/gu, "");
  return !/[/#?@:]/u.test(plain.normalize("NFKC")) && value.includes("[") === value.includes("]");
}

function validInlineEch(value: string): boolean {
  if (value.length > 87384) return false;
  const raw = decodeBase64(value);
  if (raw === null || raw.length < 6) return false;
  // Hysteria falls back to treating non-inline values as paths. Match only the
  // four canonical Base64 forms its inline decoder accepts.
  const standard = btoa(raw);
  const urlSafe = standard.replaceAll("+", "-").replaceAll("/", "_");
  if (![standard, standard.replace(/=+$/u, ""), urlSafe, urlSafe.replace(/=+$/u, "")].includes(value)) return false;
  const u16 = (offset: number) => raw.charCodeAt(offset) * 256 + raw.charCodeAt(offset + 1);
  if (u16(0) !== raw.length - 2) return false;
  let offset = 2;
  while (offset + 4 <= raw.length) offset += 4 + u16(offset + 2);
  return offset === raw.length;
}

function validHysteriaQuery(address: string): boolean {
  const [, query] = splitOnce(address, "?");
  if (!query) return true;
  let seenEch = false;
  // Limit all fields, including empty ones, as in Python parse_qs.
  const fields = query.split("&", 101);
  if (fields.length > 100) return false;
  for (const field of fields) {
    const [key, value = ""] = splitOnce(field.replaceAll("+", " "), "=");
    if (unquote(key) !== "ech") continue;
    if (seenEch || (value !== "" && !validInlineEch(unquote(value)))) return false;
    seenEch = true;
  }
  return true;
}

function validAuthorityShare(address: string, scheme: string): boolean {
  const netloc = authority(address);
  if (!safeAuthority(netloc)) return false;
  const at = netloc.lastIndexOf("@");
  if (at < 0 && AUTH_REQUIRED.has(scheme)) return false;
  if (at >= 0) {
    const userinfo = netloc.slice(0, at);
    if (!userinfo || userinfo.includes("@") || (USERNAME_REQUIRED.has(scheme) && userinfo.startsWith(":"))) return false;
  }
  return validEndpoint(netloc.slice(at + 1), scheme)
    && ((scheme !== "hy2" && scheme !== "hysteria2") || validHysteriaQuery(address));
}

function validShadowsocks(address: string): boolean {
  let [userinfo, endpoint] = splitOnce(address, "@");
  let method: string;
  let password: string | undefined;
  if (endpoint === undefined) {
    const decoded = decodeBase64(address);
    if (decoded === null) return false;
    const legacy = utf8.decode(binaryBytes(decoded));
    const at = legacy.lastIndexOf("@");
    if (at < 0) return false;
    userinfo = legacy.slice(0, at);
    endpoint = legacy.slice(at + 1);
    [method, password] = splitOnce(userinfo, ":");
  } else {
    [method, password] = splitOnce(userinfo, ":");
    if (password === undefined) {
      const decoded = decodeBase64(unquote(userinfo));
      if (decoded === null) return false;
      [method, password] = splitOnce(utf8.decode(binaryBytes(decoded)), ":");
    } else {
      method = unquote(method);
      password = unquote(password);
    }
  }
  const netloc = authority(endpoint);
  if (password === undefined || (!password && method !== "none") || !/^[A-Za-z0-9_-]+(?![\s\S])/u.test(method)
      || !safeAuthority(netloc) || !validEndpoint(netloc, "ss")) return false;
  const keyBytes = SS_2022_KEY_BYTES.get(method);
  return keyBytes === undefined || password.split(":").every((key) => decodeBase64(key, true)?.length === keyBytes);
}

function validJsonShape(source: string, numericPort: boolean): boolean {
  // JSON.parse merges JSON integers with floats. Preserve the Python
  // validator's rejection of decimal/exponential top-level port literals.
  let depth = 0;
  let previous = "";
  let checkValue = false;
  let integer = false;
  const tokens = /"(?:[^"\\]|\\[\s\S])*"|[{}\[\],:]|[^\s{}\[\],:"]+/gu;
  for (const [token] of source.matchAll(tokens)) {
    if (depth === 1 && checkValue && previous === ":") {
      integer = /^-?[0-9]+(?![\s\S])/u.test(token);
      checkValue = false;
    }
    if (numericPort && depth === 1 && (previous === "{" || previous === ",") && token.startsWith('"')) {
      checkValue = JSON.parse(token) === "port";
    }
    if ((token === "{" || token === "[") && ++depth > 256) return false;
    if (token === "}" || token === "]") depth--;
    previous = token;
  }
  return !numericPort || integer;
}

function vmessJsonText(raw: string): string {
  // Python json.loads(bytes) also accepts older UTF-16/32 JSON envelopes.
  const bytes = binaryBytes(raw);
  const [a, b, c, d] = bytes.subarray(0, 4);
  const bigBom = a === 0 && b === 0 && c === 254 && d === 255;
  const littleBom = a === 255 && b === 254 && c === 0 && d === 0;
  const big32 = a === 0 && b === 0;
  const little32 = a !== 0 && b === 0 && c === 0 && d === 0;
  if (big32 || little32 || littleBom) {
    const view = new DataView(bytes.buffer);
    let decoded = "";
    for (let offset = bigBom || littleBom ? 4 : 0; offset < bytes.length; offset += 4) {
      decoded += String.fromCodePoint(view.getUint32(offset, little32 || littleBom));
    }
    return decoded;
  }
  if ((a === 254 && b === 255) || a === 0) return new TextDecoder("utf-16be", { fatal: true }).decode(bytes);
  if ((a === 255 && b === 254) || b === 0) return new TextDecoder("utf-16le", { fatal: true }).decode(bytes);
  return utf8.decode(bytes).replace(/^\uFEFF/u, "");
}

function validVmessJson(address: string): boolean {
  const raw = decodeBase64(address);
  if (raw === null) return false;
  const text = vmessJsonText(raw);
  const data: unknown = JSON.parse(text);
  if (typeof data !== "object" || data === null || Array.isArray(data)) return false;
  const { add, id, port } = data as Record<string, unknown>;
  return validServer(add) && typeof id === "string" && id.length > 0 && numberInRange(port, 1, 65535) !== null
    && validJsonShape(text, typeof port === "number");
}

export function isValidStoredShare(value: unknown): value is string {
  if (typeof value !== "string" || INVALID_LINE_CHARACTER.test(value)) return false;
  const [schemeText, payload] = splitOnce(value, "://");
  const scheme = schemeText.toLowerCase();
  if (payload === undefined || !SCHEMES.has(scheme)) return false;
  const [address] = splitOnce(payload, "#");
  if (!address || /\p{White_Space}/u.test(address)) return false;

  try {
    if (scheme === "ss") return validShadowsocks(address);
    if (scheme === "vmess" && !address.includes("@")) return validVmessJson(address);
    if (scheme === "vmess" || AUTHORITY_SCHEMES.has(scheme)) return validAuthorityShare(address, scheme);
    // Legacy opaque schemes are only checked for the outer single-line format.
    return true;
  } catch {
    return false;
  }
}

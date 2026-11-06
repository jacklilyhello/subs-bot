"""Serialize nodes to client share links without dropping connection options."""
from __future__ import annotations

import base64
import ipaddress
import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlsplit
from uuid import UUID

from export_errors import ExportError


SHARE_SCHEMES = frozenset({
    "ss", "ssr", "vmess", "vless", "trojan", "hysteria", "hysteria2", "hy2",
    "tuic", "snell", "wireguard", "anytls", "socks5", "socks5-tls",
})
# SIP002 transports the method token without defining which ciphers a client supports.
_SS_METHOD = re.compile(r"[a-zA-Z0-9_-]+")
_SS_2022_KEY_BYTES = {
    "2022-blake3-aes-128-gcm": 16,
    "2022-blake3-aes-256-gcm": 32,
    "2022-blake3-chacha20-poly1305": 32,
    "2022-blake3-chacha8-poly1305": 32,
}
_AUTHORITY_SCHEMES = frozenset({"vless", "trojan", "hysteria", "hysteria2", "hy2", "tuic", "anytls", "socks5"})
_DEFAULT_PORT_SCHEMES = frozenset({"hysteria2", "hy2", "anytls", "socks5"})


def _take(options: dict[str, Any], *keys: str, default: Any = None) -> Any:
    values = [options.pop(key) for key in keys if key in options]
    values = [value for value in values if value is not None and value != ""]
    if not values:
        return default
    first = values[0]
    if any(type(value) is not type(first) or value != first for value in values[1:]):
        raise ExportError("Conflicting options cannot be represented in a share link.")
    return first


def _text(value: Any) -> str:
    if not isinstance(value, str) or not value:
        raise ExportError("A required share-link text field is missing or invalid.")
    return value


def _flag(value: Any) -> bool:
    if not isinstance(value, bool):
        raise ExportError("A share-link option requires a boolean value.")
    return value


def _number(value: Any, minimum: int, maximum: int) -> int:
    if isinstance(value, str) and re.fullmatch(r"[0-9]{1,10}", value):
        value = int(value)
    if type(value) is not int or not minimum <= value <= maximum:
        raise ExportError("A numeric share-link field is missing or out of range.")
    return value


def _mapping(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ExportError("A share-link option requires a mapping.")
    return dict(value)


def _require_consumed(options: dict[str, Any]) -> None:
    if options:
        raise ExportError("The node has options this share-link format cannot represent.")


def _server_address(value: Any) -> tuple[str, str]:
    host = _text(value)
    address = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    if "%" not in address:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            pass
        else:
            if ip.version == 6:
                return address, f"[{address}]"
            if address == host:
                return address, address
    domain = host.encode("idna").decode("ascii")
    labels = domain.removesuffix(".").split(".")
    if len(domain.removesuffix(".")) > 253 or not all(
        re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
        for label in labels
    ):
        raise ExportError("The node has an invalid server address for a share link.")
    return domain, domain


def _tls_query(fields: dict[str, Any], *, default_enabled: bool = False) -> dict[str, str]:
    tls = _take(fields, "tls", default=default_enabled)
    options = _mapping(tls) if isinstance(tls, dict) else {}
    enabled = _flag(_take(options, "enabled", default=False)) if isinstance(tls, dict) else _flag(tls)
    for key in ("sni", "servername", "skip-cert-verify", "alpn", "client-fingerprint", "reality-opts"):
        if key not in fields:
            continue
        if key in options and options[key] != fields[key]:
            raise ExportError("Conflicting TLS options cannot be represented in a share link.")
        options[key] = fields.pop(key)

    query = {"security": "tls" if enabled else "none"}
    sni = _take(options, "sni", "servername", "server_name")
    if sni is not None:
        query["sni"] = _text(sni)
    if _flag(_take(options, "skip-cert-verify", "insecure", default=False)):
        query["allowInsecure"] = "1"
    alpn = _take(options, "alpn", default=[])
    if isinstance(alpn, str):
        alpn = [alpn]
    if not isinstance(alpn, list) or any(not isinstance(value, str) or not value or "," in value for value in alpn):
        raise ExportError("The node has an invalid ALPN option for a share link.")
    if alpn:
        query["alpn"] = ",".join(alpn)

    fingerprint = _take(options, "client-fingerprint")
    utls = _mapping(_take(options, "utls", default={}))
    if _flag(_take(utls, "enabled", default=False)):
        if fingerprint is not None:
            raise ExportError("Conflicting TLS fingerprints cannot be represented in a share link.")
        fingerprint = _take(utls, "fingerprint", default="chrome")
    _require_consumed(utls)
    if fingerprint is not None:
        query["fp"] = _text(fingerprint)

    reality = _mapping(_take(options, "reality", "reality-opts", default={}))
    if _flag(_take(reality, "enabled", default=bool(reality))):
        query["security"] = "reality"
        query["pbk"] = _text(_take(reality, "public-key", "public_key"))
        short_id = _take(reality, "short-id", "short_id")
        if short_id is not None:
            query["sid"] = _text(short_id)
        spider = _take(reality, "spider-x", "spider_x")
        if spider is not None:
            query["spx"] = _text(spider)
        query.setdefault("fp", "chrome")
    _require_consumed(reality)
    _require_consumed(options)
    if not enabled and query != {"security": "none"}:
        raise ExportError("TLS options cannot be represented with TLS disabled.")
    return query


def _transport_query(fields: dict[str, Any], native: bool) -> tuple[str, dict[str, str]]:
    if native:
        transport = _mapping(_take(fields, "transport", default={}))
        kind = _take(transport, "type", default="tcp")
    else:
        kind = _take(fields, "network", default="tcp")
        kind = _text(kind)
        transport = _mapping(_take(fields, f"{kind}-opts", default={}))
    query: dict[str, str] = {}
    if kind in ("tcp", "raw"):
        kind = "tcp"
    elif kind in ("ws", "httpupgrade"):
        headers = _mapping(_take(transport, "headers", default={}))
        host = _take(transport, "host")
        for header, value in headers.items():
            if not isinstance(header, str) or header.casefold() != "host" or host is not None:
                raise ExportError("Custom transport headers cannot be represented in a share link.")
            host = value
        if isinstance(host, list) and len(host) == 1:
            host = host[0]
        if host is not None:
            query["host"] = _text(host)
        path = _take(transport, "path")
        early_data = _take(transport, "max-early-data", "max_early_data", default=0)
        early_data_header = _take(transport, "early-data-header-name", "early_data_header_name")
        if early_data or early_data_header:
            raise ExportError("WebSocket early data is not portable in this share-link format.")
        if path is not None:
            query["path"] = _text(path)
    elif kind == "grpc":
        service = _take(transport, "grpc-service-name", "service_name")
        if service is not None:
            query["serviceName"] = _text(service)
    elif kind in ("h2", "http"):
        kind = "http"
        host = _take(transport, "host")
        if isinstance(host, list):
            host = ",".join(_text(value) for value in host)
        if host:
            query["host"] = _text(host)
        path = _take(transport, "path")
        if path is not None:
            query["path"] = _text(path)
    else:
        raise ExportError("The node uses a transport without a supported share-link mapping.")
    _require_consumed(transport)
    return kind, query


def _escape_plugin(value: str) -> str:
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value):
        raise ExportError("A Shadowsocks plugin option contains invalid text.")
    return re.sub(r"[:;=\\]", lambda match: "\\" + match[0], value)


def validate_ss_plugin_options(plugin: str, options: str) -> None:
    """Validate the portable SIP003 client options shared by both exporters."""
    # Native clients interpret a subset of SIP003. Don't turn options for local
    # files, listeners or server mode into flags for a different client.
    if plugin not in ("obfs-local", "v2ray-plugin"):
        raise ExportError("The Shadowsocks plugin has no supported export mapping.")
    if not options:
        return
    parts = re.findall(r"(?:\\[:;=\\]|[^\\;])+", options)
    normalized = ";".join(parts)
    error = "The Shadowsocks plugin has options without a supported client share-link mapping."
    if not parts or options not in (normalized, normalized + ";") or any(
        ord(char) < 32 or 127 <= ord(char) <= 159 for char in options
    ):
        raise ExportError(error)
    allowed = {"obfs", "obfs-host"} if plugin == "obfs-local" else {"mode", "host", "path", "tls", "mux"}
    seen: set[str] = set()
    for part in parts:
        key, separator, value = part.partition("=")
        if key not in allowed or key in seen or (key != "tls" and (not separator or not value)):
            raise ExportError(error)
        seen.add(key)
        if key == "obfs" and value not in ("http", "tls"):
            raise ExportError(error)
        if key == "mode" and value != "websocket":
            raise ExportError(error)
        if key == "tls" and separator and value not in ("1", "true"):
            raise ExportError(error)
        if key == "mux":
            _number(value, 0, 65535)


def _ss_plugin(fields: dict[str, Any]) -> str | None:
    plugin = _take(fields, "plugin")
    if plugin is None:
        return None
    if plugin in ("obfs", "obfs-local"):
        plugin = "obfs-local"
    elif plugin != "v2ray-plugin":
        raise ExportError("The Shadowsocks plugin has no supported share-link mapping.")

    options = _take(fields, "plugin-opts", "plugin_opts", default={})
    if isinstance(options, str):
        validate_ss_plugin_options(plugin, options)
        return f"{plugin};{options}"
    options = _mapping(options)
    parameters = [plugin]
    mode = _take(options, "mode")
    host = _take(options, "host")
    if plugin == "obfs-local":
        if mode not in ("http", "tls"):
            raise ExportError("The Shadowsocks obfuscation mode has no supported share-link mapping.")
        parameters.append(f"obfs={mode}")
        if host is not None:
            parameters.append(f"obfs-host={_escape_plugin(_text(host))}")
    else:
        if mode is not None and mode != "websocket":
            raise ExportError("The Shadowsocks plugin mode has no supported share-link mapping.")
        parameters.append("mode=websocket")
        path = _take(options, "path")
        if host is not None:
            parameters.append(f"host={_escape_plugin(_text(host))}")
        if path is not None:
            parameters.append(f"path={_escape_plugin(_text(path))}")
        if _flag(_take(options, "tls", default=False)):
            parameters.append("tls")
        mux = _take(options, "mux")
        if mux is not None:
            parameters.append(f"mux={int(_flag(mux))}")
    _require_consumed(options)
    return ";".join(parameters)


def _ss_link(fields: dict[str, Any], authority: str, label: str) -> str:
    method = _text(_take(fields, "cipher", "method"))
    if not _SS_METHOD.fullmatch(method):
        raise ExportError("The Shadowsocks encryption method is invalid.")
    password = _take(fields, "password", default="" if method == "none" else None)
    if method != "none" or password != "":
        password = _text(password)
    if method.startswith("2022-"):
        if not _valid_ss_2022_keys(method, password):
            raise ExportError("The Shadowsocks 2022 pre-shared key encoding or length is invalid.")
        userinfo = f"{quote(method, safe='')}:{quote(password, safe='')}"
    else:
        userinfo = base64.urlsafe_b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
    plugin = _ss_plugin(fields)
    suffix = f"/?{urlencode({'plugin': plugin}, quote_via=quote)}" if plugin else ""
    return f"ss://{userinfo}@{authority}{suffix}{label}"


def _vmess_link(fields: dict[str, Any], name: str, host: str, port: int, native: bool) -> str:
    security = _text(_take(fields, "cipher", "security", default="auto"))
    client_id = _text(_take(fields, "uuid"))
    alter_id = _number(_take(fields, "alterId", "alter_id", default=0), 0, 65535)
    network, transport = _transport_query(fields, native)
    tls = _tls_query(fields)
    tls_mode = tls.pop("security")
    if tls_mode == "reality":
        raise ExportError("VMess with REALITY cannot be represented in this share-link format.")
    if network == "http":
        raise ExportError("VMess HTTP transport is not portable in this share-link format.")
    payload = {
        "v": "2", "ps": name, "add": host, "port": str(port), "id": client_id,
        "aid": str(alter_id), "scy": security, "net": network,
        "type": "none", "host": transport.get("host", ""),
        "path": transport.get("serviceName", transport.get("path", "")),
        "tls": "tls" if tls_mode == "tls" else "",
    }
    if "allowInsecure" in tls:
        tls["insecure"] = tls.pop("allowInsecure")
    payload.update(tls)
    return "vmess://" + base64.b64encode(json.dumps(payload, ensure_ascii=False).encode()).decode()


def _hysteria2_query(fields: dict[str, Any]) -> dict[str, str]:
    query = _tls_query(fields, default_enabled=True)
    if query.pop("security") != "tls" or query.keys() - {"sni", "allowInsecure"}:
        raise ExportError("The Hysteria 2 TLS options cannot be represented in a share link.")
    if "allowInsecure" in query:
        query["insecure"] = query.pop("allowInsecure")
    obfs = _take(fields, "obfs")
    if isinstance(obfs, dict):
        options = _mapping(obfs)
        obfs = _take(options, "type")
        password = _take(options, "password")
        _require_consumed(options)
    else:
        password = _take(fields, "obfs-password")
    if obfs is not None:
        if obfs not in ("salamander", "gecko"):
            raise ExportError("The Hysteria 2 obfuscation mode cannot be represented in a share link.")
        query.update({"obfs": obfs, "obfs-password": _text(password)})
    elif password is not None:
        raise ExportError("A Hysteria 2 obfuscation password requires an obfuscation mode.")
    pin = _take(fields, "fingerprint")
    if pin is not None:
        pin = _text(pin).replace(":", "")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", pin):
            raise ExportError("The Hysteria 2 certificate fingerprint is invalid.")
        query["pinSHA256"] = pin.lower()
    return query


def _tuic_query(fields: dict[str, Any]) -> dict[str, str]:
    query = _tls_query(fields, default_enabled=True)
    if query.pop("security") != "tls" or query.keys() - {"sni", "allowInsecure", "alpn"}:
        raise ExportError("The TUIC TLS options cannot be represented in a share link.")
    if "allowInsecure" in query:
        query["allow_insecure"] = query.pop("allowInsecure")
    congestion = _take(fields, "congestion-controller", "congestion_control")
    if congestion is not None:
        if congestion not in ("cubic", "new_reno", "bbr"):
            raise ExportError("The TUIC congestion control option is invalid.")
        query["congestion_control"] = congestion
    relay = _take(fields, "udp-relay-mode", "udp_relay_mode")
    if relay is not None:
        if relay not in ("native", "quic"):
            raise ExportError("The TUIC relay mode is invalid.")
        query["udp_relay_mode"] = relay
    return query


def _structured_share_link(node: dict[str, Any]) -> str:
    fields = dict(node)
    kind = _text(_take(fields, "type")).lower()
    kind = {"shadowsocks": "ss", "hy2": "hysteria2"}.get(kind, kind)
    if kind not in ("ss", "vmess", "vless", "trojan", "hysteria2", "tuic", "anytls"):
        raise ExportError("The node protocol has no supported share-link mapping.")

    name = _text(_take(fields, "name", "tag", default="node"))
    _take(fields, "share", "raw")
    # Clash's UDP flag controls local forwarding. Share links configure the
    # remote connection. Explicit native TCP/UDP restrictions are rejected.
    _flag(_take(fields, "udp", default=False))
    native = "server_port" in fields and "port" not in fields
    host, address = _server_address(_take(fields, "server"))
    default_port = 443 if kind in ("hysteria2", "anytls") else None
    port = _number(_take(fields, "port", "server_port", default=default_port), 1, 65535)
    authority = f"{address}:{port}"
    label = "#" + quote(name, safe="")

    if kind == "ss":
        link = _ss_link(fields, authority, label)
    elif kind == "vmess":
        link = _vmess_link(fields, name, host, port, native)
    else:
        if kind in ("vless", "trojan"):
            user_key = "uuid" if kind == "vless" else "password"
            auth = quote(_text(_take(fields, user_key)), safe="")
            network, transport = _transport_query(fields, native)
            tls = _tls_query(fields, default_enabled=kind == "trojan")
            if kind == "trojan" and (tls["security"] == "none" or network == "http"):
                raise ExportError("The Trojan security or transport mode is not portable in a share link.")
            query = {"type": network, **transport, **tls}
            if kind == "vless":
                if "allowInsecure" in tls:
                    raise ExportError("VLESS share links cannot preserve this TLS verification override.")
                query["encryption"] = _text(_take(fields, "encryption", default="none"))
            flow = _take(fields, "flow")
            if flow is not None:
                query["flow"] = _text(flow)
        elif kind == "hysteria2":
            password = _take(fields, "password")
            if password is None:
                auth = ""
            else:
                user, separator, secret = _text(password).partition(":")
                auth = quote(user, safe="") + separator + quote(secret, safe="")
            query = _hysteria2_query(fields)
        elif kind == "tuic":
            client_id = _text(_take(fields, "uuid"))
            try:
                client_id = str(UUID(client_id))
            except ValueError:
                raise ExportError("TUIC v5 share links require a valid UUID.") from None
            auth = f"{client_id}:{quote(_text(_take(fields, 'password')), safe='')}"
            query = _tuic_query(fields)
        else:
            auth = quote(_text(_take(fields, "password")), safe="")
            query = _tls_query(fields, default_enabled=True)
            if query.pop("security") != "tls" or query.keys() - {"sni", "allowInsecure"}:
                raise ExportError("The AnyTLS options cannot be represented in a share link.")
            if "allowInsecure" in query:
                query["insecure"] = query.pop("allowInsecure")
        userinfo = f"{auth}@" if auth else ""
        query_string = f"?{urlencode(query, quote_via=quote)}" if query else ""
        link = f"{kind}://{userinfo}{authority}{query_string}{label}"
    _require_consumed(fields)
    return link


def _decode_base64(value: str) -> bytes:
    return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)


def _valid_ss_2022_keys(method: str, password: str) -> bool:
    key_bytes = _SS_2022_KEY_BYTES.get(method)
    if key_bytes is None:
        return True
    try:
        return all(len(base64.b64decode(key, validate=True)) == key_bytes for key in password.split(":"))
    except ValueError:
        return False


def _endpoint_port(endpoint: str) -> str | None:
    pattern = r"\[([^\]]+)\](?::([^:]+))?" if endpoint.startswith("[") else r"([^:\[\]]+)(?::([^:]+))?"
    match = re.fullmatch(pattern, endpoint)
    if match is None:
        raise ExportError("The share link has an invalid server address.")
    host, ports = match.groups()
    if endpoint.startswith("["):
        address, has_zone, zone = host.partition("%25")
        if "%" in address or (has_zone and not re.fullmatch(r"[a-zA-Z0-9_.~-]+", zone)):
            raise ExportError("The share link has an invalid IPv6 address.")
        ipaddress.IPv6Address(address)
    else:
        _server_address(host)
    return ports


def hysteria2_port_fields(endpoint: str, legacy_ports: str | None = None) -> dict[str, int | str]:
    """Validate a Hysteria 2 endpoint and retain its complete port specification."""
    ports = _endpoint_port(endpoint)
    hopping = ports is not None and ("," in ports or "-" in ports)
    if not hopping:
        port = 443 if ports is None else _number(ports, 1, 65535)
        if legacy_ports is None:
            return {"port": port}
        ports = legacy_ports
    elif legacy_ports is not None:
        raise ExportError("The Hysteria 2 link contains conflicting port ranges.")

    for span in ports.split(","):
        start, has_end, end = span.partition("-")
        first = _number(start, 1, 65535)
        if has_end:
            _number(end, first, 65535)
    return {"ports": ports}


def hysteria2_inline_ech(value: str) -> str:
    """Normalize an inline ECHConfigList without permitting the client's file fallback."""
    error = "The Hysteria 2 ECH option must contain an inline ECHConfigList."
    if len(value) > 87384:
        raise ExportError(error)
    try:
        raw = _decode_base64(value)
    except ValueError:
        raise ExportError(error) from None
    standard = base64.b64encode(raw).decode("ascii")
    urlsafe = base64.urlsafe_b64encode(raw).decode("ascii")
    if value not in (standard, standard.rstrip("="), urlsafe, urlsafe.rstrip("=")):
        raise ExportError(error)
    if len(raw) < 6 or int.from_bytes(raw[:2], "big") != len(raw) - 2:
        raise ExportError(error)
    offset = 2
    while offset < len(raw):
        if offset + 4 > len(raw):
            raise ExportError(error)
        offset += 4 + int.from_bytes(raw[offset + 2:offset + 4], "big")
    if offset != len(raw):
        raise ExportError(error)
    return standard


def _valid_endpoint(endpoint: str, scheme: str) -> bool:
    if scheme in ("hysteria2", "hy2"):
        hysteria2_port_fields(endpoint)
        return True
    port = _endpoint_port(endpoint)
    if port is None:
        return scheme in _DEFAULT_PORT_SCHEMES
    _number(port, 1, 65535)
    return True


def _valid_authority_share(share: str, scheme: str) -> bool:
    parsed = urlsplit(share)
    userinfo, has_auth, endpoint = parsed.netloc.rpartition("@")
    if "@" in userinfo or (has_auth and not userinfo):
        return False
    if scheme in ("vmess", "vless", "trojan", "tuic", "anytls") and not has_auth:
        return False
    if scheme in ("vmess", "vless", "tuic") and not parsed.username:
        return False
    if scheme in ("hysteria2", "hy2"):
        ech = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=100).get("ech", [""])
        if len(ech) != 1:
            return False
        if ech[0]:
            hysteria2_inline_ech(ech[0])
    return _valid_endpoint(endpoint, scheme)


def _valid_ss_share(address: str) -> bool:
    userinfo, separator, endpoint = address.partition("@")
    if not separator:
        userinfo, separator, endpoint = _decode_base64(address).decode().rpartition("@")
        if not separator:
            return False
        method, separator, password = userinfo.partition(":")
    else:
        method, separator, password = userinfo.partition(":")
        if separator:
            method, password = unquote(method), unquote(password)
        else:
            method, separator, password = _decode_base64(unquote(userinfo)).decode().partition(":")
    parsed = urlsplit("//" + endpoint)
    return bool(
        separator and _SS_METHOD.fullmatch(method) and (password or method == "none")
        and _valid_ss_2022_keys(method, password) and _valid_endpoint(parsed.netloc, "ss")
    )


def _validate_stored_share(value: Any) -> str:
    share = _text(value)
    share.encode("utf-8")
    scheme, _, payload = share.partition("://")
    scheme = scheme.lower()
    address = payload.split("#", 1)[0]
    valid = (
        scheme in SHARE_SCHEMES and bool(address) and not any(char.isspace() for char in address)
        and share.splitlines() == [share] and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in share)
    )
    if valid:
        try:
            if scheme == "ss":
                valid = _valid_ss_share(address)
            elif scheme == "vmess":
                if "@" in address:
                    valid = _valid_authority_share(share, scheme)
                else:
                    data = json.loads(_decode_base64(address))
                    if not isinstance(data, dict):
                        valid = False
                    else:
                        _server_address(data.get("add"))
                        _text(data.get("id"))
                        _number(data.get("port"), 1, 65535)
            elif scheme in _AUTHORITY_SCHEMES:
                valid = _valid_authority_share(share, scheme)
        except (ValueError, RecursionError):
            valid = False
    if not valid:
        raise ExportError("The subscription contains an invalid stored share link.")
    return share


def to_share_links(nodes: list[dict[str, Any]]) -> list[str]:
    links = []
    for node in nodes:
        if not isinstance(node, dict):
            raise ExportError("The subscription contains an invalid node.")
        share = node.get("share")
        try:
            link = _structured_share_link(node) if share in (None, "") else _validate_stored_share(share)
        except UnicodeError:
            raise ExportError("The subscription contains invalid share-link text.") from None
        links.append(link)
    return links

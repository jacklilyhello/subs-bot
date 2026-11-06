"""Export Clash, share-link, and native outbound nodes to sing-box."""

from __future__ import annotations

import base64
import ipaddress
import json
import re
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit
from uuid import UUID

from export_errors import ExportError
from share_export import validate_ss_plugin_options


_ALIASES = {"ss": "shadowsocks", "hy2": "hysteria2", "socks5": "socks", "https": "http"}
_TRANSPORT_PROTOCOLS = {"vmess", "vless", "trojan"}
_TLS_REQUIRED = {"hysteria", "hysteria2", "tuic", "anytls"}
_TLS_DEFAULT = _TLS_REQUIRED | {"trojan"}
_NETWORK_PROTOCOLS = {"shadowsocks", "vmess", "vless", "trojan", "hysteria", "hysteria2", "tuic", "socks"}
_NATIVE_ONLY = {"ssh", "shadowtls", "snell", "naive"}
_SUPPORTED = _NETWORK_PROTOCOLS | _NATIVE_ONLY | {"anytls", "http"}
_DIAL_FIELDS = set((
    "server server_port bind_interface inet4_bind_address inet6_bind_address bind_address_no_port "
    "routing_mark reuse_addr connect_timeout tcp_fast_open tcp_multi_path disable_tcp_keep_alive "
    "tcp_keep_alive tcp_keep_alive_interval udp_fragment network_strategy network_type "
    "fallback_network_type fallback_delay domain_strategy"
).split())
_QUIC_FIELDS = set((
    "idle_timeout keep_alive_period stream_receive_window connection_receive_window "
    "max_concurrent_streams initial_packet_size disable_path_mtu_discovery"
).split())
_NATIVE_FIELDS = {
    "shadowsocks": "method password plugin plugin_opts udp_over_tcp multiplex",
    "vmess": "uuid security alter_id global_padding authenticated_length tls packet_encoding multiplex transport",
    "vless": "uuid flow tls multiplex transport packet_encoding",
    "trojan": "password tls multiplex transport",
    "hysteria": "server_ports hop_interval up down up_mbps down_mbps obfs auth auth_str tls recv_window_conn recv_window disable_mtu_discovery",
    "hysteria2": "server_ports hop_interval hop_interval_max up_mbps down_mbps obfs password tls bbr_profile brutal_debug disable_chrome_parrot",
    "tuic": "uuid password congestion_control udp_relay_mode udp_over_stream zero_rtt_handshake heartbeat tls",
    "anytls": "password tls idle_session_check_interval idle_session_timeout min_idle_session client_metadata",
    "socks": "version username password udp_over_tcp",
    "http": "username password tls path headers",
    "ssh": "user password private_key private_key_passphrase host_key host_key_algorithms client_version cipher mac kex_algorithm",
    "shadowtls": "version password tls",
    "snell": "version psk userkey reuse network obfs_mode obfs_host mode",
    "naive": "username password insecure_concurrency extra_headers stream_receive_window udp_over_tcp quic quic_congestion_control quic_session_receive_window tls",
}
_TLS_FIELDS = (
    "enabled engine disable_sni server_name insecure alpn min_version max_version cipher_suites curve_preferences "
    "certificate certificate_public_key_sha256 client_certificate client_key fragment fragment_fallback_delay "
    "record_fragment spoof spoof_method kernel_tx kernel_rx handshake_timeout ech utls reality"
)
_TRANSPORT_FIELDS = {
    "ws": "path headers max_early_data early_data_header_name",
    "grpc": "service_name idle_timeout ping_timeout permit_without_stream",
    "http": "host path method headers idle_timeout ping_timeout",
    "httpupgrade": "host path headers",
    "quic": "",
}
_SS_METHODS = {
    "none", "aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305", "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
    "aes-128-cfb", "aes-192-cfb", "aes-256-cfb", "rc4-md5", "chacha20-ietf", "xchacha20",
}
_VMESS_SECURITY = {"auto", "none", "zero", "aes-128-cfb", "aes-128-gcm", "chacha20-poly1305"}
_PORT_RANGE = re.compile(r"([0-9]{1,5})(?:[-:]([0-9]{1,5}))?\Z")
_DNS_LABEL = re.compile(r"[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\Z")


def _take(source: dict, *aliases: str, default: Any = None) -> Any:
    values = [source.pop(key) for key in aliases if key in source]
    if any(value != values[0] for value in values[1:]):
        raise ExportError("存在互相冲突的设置")
    return values[0] if values else default


def _remaining(source: dict) -> None:
    if any(value is not None and value != "" and value != {} and value != [] for value in source.values()):
        raise ExportError("存在无法保留的协议设置")


def _string(value: Any, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value.strip()):
        raise ExportError("缺少必要的连接或认证字段")
    return value


def _server(value: Any) -> str:
    host = _string(value)
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if ":" in host:
        if "%" in host:
            raise ExportError("服务器地址无效")
        ipaddress.IPv6Address(host)
        return host
    host = host.encode("idna").decode("ascii")
    if len(host) > 254 or not all(_DNS_LABEL.fullmatch(part) for part in host.removesuffix(".").split(".")):
        raise ExportError("服务器地址无效")
    return host


def _integer(value: Any, minimum: int, maximum: int) -> int:
    if type(value) is not int and not (isinstance(value, str) and re.fullmatch(r"[0-9]+", value)):
        raise ExportError("连接参数不是有效整数")
    number = int(value)
    if not minimum <= number <= maximum:
        raise ExportError("连接参数超出有效范围")
    return number


def _boolean(value: Any) -> bool:
    if type(value) is bool:
        return value
    if type(value) in (int, str):
        if str(value).lower() in {"true", "1"}:
            return True
        if str(value).lower() in {"false", "0"}:
            return False
    raise ExportError("连接参数不是有效布尔值")


def _object(value: Any) -> dict:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ExportError("连接参数不是有效对象")
    return dict(value)


def _only_fields(value: Any, fields: str) -> dict:
    settings = _object(value)
    if settings.keys() - set(fields.split()):
        raise ExportError("节点包含未知、外部依赖或不支持的设置")
    return settings


def _copy_options(source: dict, output: dict, mapping: dict[str, str]) -> None:
    for source_key, output_key in mapping.items():
        if source_key in source:
            output[output_key] = source.pop(source_key)


def _list(value: Any) -> list[str]:
    values = value.split(",") if isinstance(value, str) else value
    if not isinstance(values, list):
        raise ExportError("连接参数不是有效列表")
    return [_string(item).strip() for item in values]


def _tls(source: dict, protocol: str, *, default: bool = False) -> dict | None:
    enabled = _take(source, "tls", default=default or protocol in _TLS_DEFAULT)
    tls = _object(enabled) if isinstance(enabled, dict) else {"enabled": _boolean(enabled)}
    for keys, field in (
        (("sni", "servername"), "server_name"),
        (("skip-cert-verify",), "insecure"),
        (("disable-sni",), "disable_sni"),
        (("alpn",), "alpn"),
    ):
        value = _take(source, *keys)
        if value not in (None, "", []):
            if not tls.get("enabled"):
                if field in {"insecure", "disable_sni"} and not _boolean(value):
                    continue
                raise ExportError("TLS 已关闭但节点包含 TLS 设置")
            if field in {"insecure", "disable_sni"}:
                value = _boolean(value)
            if field == "alpn":
                value = _list(value)
            elif field == "server_name":
                value = _server(value)
            if field in tls and tls[field] != value:
                raise ExportError("存在互相冲突的 TLS 设置")
            tls[field] = value
    fingerprint = _take(source, "client-fingerprint")
    if fingerprint not in (None, "", "none"):
        tls["utls"] = {"enabled": True, "fingerprint": _string(fingerprint)}
    reality = _take(source, "reality-opts")
    if reality is not None:
        settings = _object(reality)
        tls["reality"] = {"enabled": True, "public_key": _string(settings.pop("public-key", None))}
        short_id = settings.pop("short-id", None)
        if short_id is not None:
            tls["reality"]["short_id"] = _string(short_id, allow_empty=True)
        _remaining(settings)
        if "utls" not in tls:
            raise ExportError("Reality 缺少 uTLS 指纹")
    if not tls.get("enabled"):
        if protocol in _TLS_REQUIRED or len(tls) > 1:
            raise ExportError("协议需要有效的 TLS 设置")
        return None
    return tls


def _transport(source: dict) -> dict | None:
    if "transport" in source:
        if source.get("network") not in (None, ""):
            raise ExportError("存在互相冲突的传输设置")
        return _object(source.pop("transport"))
    kind = _take(source, "network", default="tcp") or "tcp"
    if kind in ("tcp", "raw"):
        return None
    names = {"ws": "ws", "grpc": "grpc", "http": "http", "h2": "http", "httpupgrade": "httpupgrade", "quic": "quic"}
    if not isinstance(kind, str) or kind not in names:
        raise ExportError("传输方式无法转换为 sing-box")
    output: dict[str, Any] = {"type": names[kind]}
    settings = _object(source.pop(f"{kind}-opts", {}))
    if kind == "grpc":
        _copy_options(settings, output, {"grpc-service-name": "service_name"})
    elif kind != "quic":
        _copy_options(settings, output, {
            "path": "path", "headers": "headers", "host": "host", "method": "method",
            "max-early-data": "max_early_data", "early-data-header-name": "early_data_header_name",
        })
        if kind in {"http", "h2"} and isinstance(output.get("path"), list):
            if len(output["path"]) != 1:
                raise ExportError("sing-box 无法保留多个 HTTP 传输路径")
            output["path"] = output["path"][0]
        allowed = {"path", "headers"}
        allowed |= {"max_early_data", "early_data_header_name"} if kind == "ws" else {"host"}
        if kind in {"http", "h2"}:
            allowed.add("method")
        if output.keys() - allowed - {"type"}:
            raise ExportError("传输方式无法保留这些设置")
        if "path" in output:
            _string(output["path"], allow_empty=True)
        if "headers" in output:
            output["headers"] = _object(output["headers"])
        if "max_early_data" in output:
            output["max_early_data"] = _integer(output["max_early_data"], 0, 2**32 - 1)
    _remaining(settings)
    return output


def _plugin(source: dict, output: dict) -> None:
    plugin = source.pop("plugin", None)
    raw_settings = source.pop("plugin-opts", None)
    if not plugin:
        if raw_settings:
            raise ExportError("缺少 Shadowsocks 插件类型")
        return
    plugin = {"obfs": "obfs-local", "simple-obfs": "obfs-local"}.get(plugin, plugin)
    if plugin not in ("obfs-local", "v2ray-plugin"):
        raise ExportError("Shadowsocks 插件无法转换为 sing-box")
    output["plugin"] = plugin
    if isinstance(raw_settings, str):
        output["plugin_opts"] = raw_settings
    elif raw_settings is not None:
        settings = _object(raw_settings)
        names = {"mode": "obfs", "host": "obfs-host"} if plugin == "obfs-local" else {
            "mode": "mode", "host": "host", "path": "path", "tls": "tls", "mux": "mux",
        }
        options = []
        for key, option in names.items():
            if key not in settings:
                continue
            value = settings.pop(key)
            if key == "tls":
                if _boolean(value):
                    options.append("tls")
                continue
            if key == "mux":
                options.append(f"mux={int(_boolean(value))}")
                continue
            text = _string(value)
            if any(char in text for char in ";\\\r\n"):
                raise ExportError("Shadowsocks 插件设置无法安全转换")
            options.append(f"{option}={text}")
        _remaining(settings)
        if options:
            output["plugin_opts"] = ";".join(options)


def _ports(value: Any) -> list[str]:
    ports = []
    for item in _list(value):
        match = _PORT_RANGE.fullmatch(item)
        if not match:
            raise ExportError("端口范围无效")
        start = _integer(match[1], 1, 65535)
        end = _integer(match[2] or match[1], start, 65535)
        ports.append(f"{start}:{end}")
    if not ports:
        raise ExportError("端口范围无效")
    return ports


def _clash(source: dict, protocol: str) -> dict:
    output = {"type": protocol, "server": _server(source.pop("server", None))}
    port = source.pop("port", None)
    port_ranges = source.pop("ports", None) if protocol in {"hysteria", "hysteria2"} else None
    if port_ranges:
        output["server_ports"] = _ports(port_ranges)
    else:
        output["server_port"] = _integer(port, 1, 65535)

    if protocol in _TRANSPORT_PROTOCOLS:
        transport = _transport(source)
        if transport:
            output["transport"] = transport
    if protocol in _TLS_REQUIRED | _TRANSPORT_PROTOCOLS | {"http"}:
        tls = _tls(source, protocol, default=source.pop("_https", False))
        if tls:
            output["tls"] = tls

    udp = source.pop("udp", None) if protocol in _NETWORK_PROTOCOLS else None
    if udp is not None and not _boolean(udp):
        output["network"] = "tcp"
    for field, target in (("tfo", "tcp_fast_open"), ("mptcp", "tcp_multi_path")):
        if field in source:
            output[target] = _boolean(source.pop(field))

    if protocol in {"vmess", "vless", "tuic"}:
        output["uuid"] = _string(source.pop("uuid", None))
    if protocol == "shadowsocks":
        method = _string(_take(source, "cipher", "method"))
        output["method"] = method
        output["password"] = _string(source.pop("password", ""), allow_empty=method == "none")
        _plugin(source, output)
        _copy_options(source, output, {"udp-over-tcp": "udp_over_tcp"})
    elif protocol == "vmess":
        output["security"] = _take(source, "cipher", "security", default="auto")
        output["alter_id"] = _integer(_take(source, "alterId", "alter_id", default=0), 0, 65535)
        for field in ("global-padding", "authenticated-length"):
            if field in source:
                output[field.replace("-", "_")] = _boolean(source.pop(field))
    elif protocol in {"trojan", "anytls", "hysteria2", "tuic"}:
        password = source.pop("password", "" if protocol in {"hysteria2", "tuic"} else None)
        output["password"] = _string(password, allow_empty=protocol in {"hysteria2", "tuic"})
    if protocol == "vless":
        if source.pop("encryption", "none") not in ("", "none"):
            raise ExportError("VLESS 加密方式无法转换为 sing-box")
        flow = source.pop("flow", "")
        if flow:
            output["flow"] = flow
    if protocol in {"vmess", "vless"}:
        packet_encoding = _take(source, "packet-encoding", "packet_encoding")
        if packet_encoding is not None:
            output["packet_encoding"] = {"packet": "packetaddr", "none": ""}.get(packet_encoding, packet_encoding)
    if protocol in {"hysteria", "hysteria2"}:
        for key in ("up", "down"):
            value = source.pop(key, None)
            if value is not None:
                if isinstance(value, str):
                    value = re.sub(r"\s*Mbps\Z", "", value, flags=re.I)
                output[f"{key}_mbps"] = _integer(value, 0, 2**31 - 1)
        if "hop-interval" in source:
            output["hop_interval"] = f"{_integer(source.pop('hop-interval'), 1, 2**31 - 1)}s"
        obfs = source.pop("obfs", None)
        if protocol == "hysteria" and obfs:
            output["obfs"] = _string(obfs)
        elif obfs:
            settings = {"type": _string(obfs), "password": _string(source.pop("obfs-password", None))}
            if obfs == "gecko":
                for prefix in ("min", "max"):
                    key = f"{prefix}-packet-size"
                    if f"obfs-{key}" in source:
                        settings[key.replace("-", "_")] = _integer(source.pop(f"obfs-{key}"), 1, 2**31 - 1)
            output["obfs"] = settings
        if protocol == "hysteria":
            _copy_options(source, output, {"auth-str": "auth_str", "auth": "auth"})
    if protocol == "tuic":
        _copy_options(source, output, {
            "congestion-controller": "congestion_control", "udp-relay-mode": "udp_relay_mode",
        })
        if "reduce-rtt" in source:
            output["zero_rtt_handshake"] = _boolean(source.pop("reduce-rtt"))
        if "heartbeat-interval" in source:
            output["heartbeat"] = f"{_integer(source.pop('heartbeat-interval'), 1, 2**31 - 1)}ms"
    if protocol in {"socks", "http"}:
        _copy_options(source, output, {"username": "username", "password": "password"})
    _remaining(source)
    return output


def _query_options(url: str) -> dict[str, str]:
    options: dict[str, str] = {}
    for key, value in parse_qsl(url, keep_blank_values=True, max_num_fields=100):
        if key in options:
            raise ExportError("分享链接包含重复参数")
        options[key] = value
    return options


def _uri_transport(options: dict, source: dict, kind: str) -> None:
    source["network"] = kind
    if _take(options, "headerType", default="none") not in ("", "none"):
        raise ExportError("sing-box 无法保留分享链接的头部伪装")
    if kind == "grpc":
        if _take(options, "mode", default="gun") not in ("", "gun"):
            raise ExportError("sing-box 无法保留分享链接的 gRPC 模式")
        source["grpc-opts"] = {"grpc-service-name": options.pop("serviceName", "")}
    elif kind in {"ws", "http", "h2", "httpupgrade"}:
        settings: dict[str, Any] = {}
        host = options.pop("host", "")
        path = options.pop("path", "")
        if kind == "ws":
            if host:
                settings["headers"] = {"Host": host}
            # Xray encodes WebSocket early-data size as an ed query parameter in path.
            match = re.fullmatch(r"(.*)\?ed=([0-9]+)", path)
            if match:
                path = match[1]
                settings["max-early-data"] = match[2]
                settings["early-data-header-name"] = "Sec-WebSocket-Protocol"
        elif host:
            settings["host"] = _list(host) if kind in {"h2", "http"} else host
        if path:
            settings["path"] = path
        source[f"{kind}-opts"] = settings


def _uri_tls(options: dict, source: dict, protocol: str) -> None:
    security = options.pop("security", "tls" if protocol in _TLS_DEFAULT else "none")
    if security not in ("", "none", "tls", "reality"):
        raise ExportError("分享链接的安全模式无法转换为 sing-box")
    source["tls"] = security in ("tls", "reality")
    _copy_options(options, source, {"sni": "sni", "alpn": "alpn", "fp": "client-fingerprint", "disable_sni": "disable-sni"})
    insecure = _take(options, "allowInsecure", "allow_insecure", "insecure")
    if insecure not in (None, ""):
        source["skip-cert-verify"] = insecure
    if security == "reality":
        source["reality-opts"] = {"public-key": options.pop("pbk", None), "short-id": options.pop("sid", "")}
        source.setdefault("client-fingerprint", "chrome")


def _vmess_uri(share: str, parsed: dict) -> dict:
    payload = share.split("://", 1)[1].split("#", 1)[0]
    decoded = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
    data = _object(json.loads(decoded))
    for field in ("v", "ps", "add", "port", "id", "aid", "scy"):
        data.pop(field, None)
    source = {key: parsed[key] for key in ("server", "port", "uuid", "alterId", "cipher")}
    kind = data.pop("net", "tcp") or "tcp"
    options: dict[str, Any] = {}
    _copy_options(data, options, {
        "host": "host", "path": "path", "sni": "sni", "alpn": "alpn", "fp": "fp",
        "allowInsecure": "allowInsecure", "insecure": "insecure", "type": "headerType",
    })
    security = data.pop("tls", "")
    if security in ("tls", True, "1"):
        options["security"] = "tls"
    elif security not in ("", "none", False, "0", None):
        raise ExportError("分享链接的 VMess 安全模式无法转换")
    if kind == "grpc" and "path" in options:
        options["serviceName"] = options.pop("path")
    _uri_transport(options, source, kind)
    _uri_tls(options, source, "vmess")
    _remaining(options)
    _remaining(data)
    return source


def _uri(share: str, protocol: str, parse_share_link: Callable[[str], dict | None]) -> dict:
    url = urlsplit(share)
    if protocol in {"vmess", "shadowsocks"}:
        parsed = parse_share_link(share)
        if not parsed:
            raise ExportError("分享链接无法解析")
        if protocol == "vmess":
            return _vmess_uri(share, parsed)
        source = {key: parsed[key] for key in ("server", "port", "cipher", "password")}
        options = _query_options(url.query)
        plugin = options.pop("plugin", "")
        if plugin:
            source["plugin"], _, source["plugin-opts"] = plugin.partition(";")
        _remaining(options)
        return source

    if url.path not in ("", "/") or protocol not in (_TLS_DEFAULT | {"vless", "socks"}):
        raise ExportError("分享链接协议或路径无法转换为 sing-box")
    options = _query_options(url.query)
    source: dict[str, Any] = {"server": url.hostname}
    authority = url.netloc.rsplit("@", 1)[-1]
    port_field = authority.partition("]")[2] if authority.startswith("[") else authority.partition(":")[2]
    port_field = port_field.removeprefix(":")
    if protocol in {"hysteria", "hysteria2"} and ("," in port_field or "-" in port_field):
        if options.get("mport"):
            raise ExportError("分享链接包含互相冲突的端口范围")
        source["ports"] = port_field
    else:
        port = url.port
        source["port"] = 443 if port is None and protocol in _TLS_DEFAULT else port
    if protocol in _TRANSPORT_PROTOCOLS:
        _uri_transport(options, source, options.pop("type", "tcp"))
    if protocol in _TLS_REQUIRED | _TRANSPORT_PROTOCOLS:
        _uri_tls(options, source, protocol)
    user = unquote(url.username) if url.username is not None else ""
    password = unquote(url.password) if url.password is not None else ""
    if protocol == "vless":
        if password or options.pop("encryption", "none") not in ("", "none"):
            raise ExportError("VLESS 认证方式无法转换为 sing-box")
        source["uuid"] = user
        _copy_options(options, source, {"flow": "flow", "packetEncoding": "packet-encoding"})
    elif protocol == "tuic":
        source.update(uuid=user, password=password)
        _copy_options(options, source, {
            "congestion_control": "congestion-controller", "udp_relay_mode": "udp-relay-mode",
            "zero_rtt_handshake": "reduce-rtt",
        })
    elif protocol == "hysteria2":
        auth = user if url.password is None else f"{user}:{password}"
        if auth and options.get("auth") and auth != options["auth"]:
            raise ExportError("分享链接包含互相冲突的认证信息")
        source["password"] = auth or options.get("auth", "")
        options.pop("auth", None)
        _copy_options(options, source, {"obfs": "obfs", "obfs-password": "obfs-password", "mport": "ports"})
    elif protocol == "hysteria":
        if url.username is not None:
            raise ExportError("Hysteria 认证方式无法转换为 sing-box")
        _copy_options(options, source, {"auth": "auth-str", "upmbps": "up", "downmbps": "down", "obfsParam": "obfs"})
        if options.pop("protocol", "udp") != "udp" or options.pop("obfs", "xplus") not in ("", "xplus"):
            raise ExportError("Hysteria 传输方式无法转换为 sing-box")
    elif protocol == "socks":
        source.update(username=user, password=password)
    else:
        source["password"] = user if url.password is None else f"{user}:{password}"
    _remaining(options)
    return source


def _native(source: dict, protocol: str) -> dict:
    if "port" in source:
        raise ExportError("节点同时包含两种服务器端口格式")
    fields = _DIAL_FIELDS | set(_NATIVE_FIELDS[protocol].split())
    if protocol in _NETWORK_PROTOCOLS:
        fields.add("network")
    if protocol in {"hysteria", "hysteria2", "tuic"}:
        fields |= _QUIC_FIELDS
    if source.keys() - fields:
        raise ExportError("节点包含未知、外部依赖或不支持的设置")
    source["server"] = _server(source.get("server"))
    if not source.get("server_ports"):
        source["server_port"] = _integer(source.get("server_port"), 1, 65535)
    return {"type": protocol, **source}


def _validate(output: dict) -> None:
    protocol = output["type"]
    if protocol == "shadowsocks":
        method = _string(output.get("method"))
        if method not in _SS_METHODS:
            raise ExportError("Shadowsocks 加密方式无法转换为 sing-box")
        _string(output.get("password", ""), allow_empty=method == "none")
        plugin = output.get("plugin")
        raw_options = output.get("plugin_opts", "")
        options = _string("" if raw_options is None else raw_options, allow_empty=True)
        if plugin not in (None, ""):
            validate_ss_plugin_options(plugin, options)
        elif options:
            raise ExportError("缺少 Shadowsocks 插件类型")
    if protocol == "vmess":
        security = output.get("security", "")
        if not isinstance(security, str) or (security and security not in _VMESS_SECURITY):
            raise ExportError("VMess 加密方式无法转换为 sing-box")
    if protocol == "vless" and output.get("flow", "") not in ("", "xtls-rprx-vision"):
        raise ExportError("VLESS flow 无法转换为 sing-box")
    if protocol in {"vmess", "vless"}:
        _string(output.get("uuid"))
        if output.get("packet_encoding", "") not in ("", "packetaddr", "xudp"):
            raise ExportError("数据包编码无法转换为 sing-box")
    if protocol == "tuic":
        UUID(_string(output.get("uuid")))
    if protocol in {"trojan", "anytls"}:
        _string(output.get("password"))
    if protocol == "hysteria2" and output.get("obfs"):
        obfs = _only_fields(output["obfs"], "type password min_packet_size max_packet_size")
        if obfs.get("type") not in ("salamander", "gecko"):
            raise ExportError("Hysteria2 混淆方式无法转换为 sing-box")
        _string(obfs.get("password"))
    if protocol == "tuic":
        if output.get("congestion_control", "cubic") not in ("cubic", "new_reno", "bbr"):
            raise ExportError("TUIC 拥塞控制方式无法转换为 sing-box")
        if output.get("udp_relay_mode", "native") not in ("native", "quic"):
            raise ExportError("TUIC 中继方式无法转换为 sing-box")
        if output.get("udp_over_stream") and output.get("udp_relay_mode"):
            raise ExportError("TUIC 中继方式存在冲突")
    if "network" in output:
        network = output["network"]
        if any(value not in ("tcp", "udp") for value in (network if isinstance(network, list) else [network])):
            raise ExportError("代理网络设置无效")
    if "tls" in output:
        tls = _only_fields(output["tls"], _TLS_FIELDS)
        if "enabled" in tls and type(tls["enabled"]) is not bool:
            raise ExportError("TLS 设置无效")
        for key, fields in (
            ("ech", "enabled config query_server_name"),
            ("utls", "enabled fingerprint"),
            ("reality", "enabled public_key short_id"),
        ):
            if key in tls:
                _only_fields(tls[key], fields)
    else:
        tls = {}
    if protocol in _TLS_REQUIRED and tls.get("enabled") is not True:
        raise ExportError("协议需要有效的 TLS 设置")
    if "transport" in output:
        transport = _object(output["transport"])
        kind = transport.get("type")
        if not isinstance(kind, str) or kind not in _TRANSPORT_FIELDS:
            raise ExportError("传输方式无法转换为 sing-box")
        _only_fields(transport, f"type {_TRANSPORT_FIELDS[kind]}")
    if "multiplex" in output:
        multiplex = _only_fields(output["multiplex"], "enabled protocol max_connections min_streams max_streams padding brutal")
        if "brutal" in multiplex:
            _only_fields(multiplex["brutal"], "enabled up_mbps down_mbps")
    if "udp_over_tcp" in output and type(output["udp_over_tcp"]) is not bool:
        _only_fields(output["udp_over_tcp"], "enabled version")


def _outbound(node: dict, parse_share_link: Callable[[str], dict | None]) -> dict:
    source = {key: value for key, value in node.items() if key not in {"name", "tag", "type", "share", "raw"}}
    share = node.get("share") or node.get("raw")
    original_type = _string(node.get("type")).lower()
    if share:
        share = _string(share)
        scheme = share.split(":", 1)[0].lower()
        protocol = _ALIASES.get(scheme, scheme)
        if original_type != "temp" and _ALIASES.get(original_type, original_type) != protocol:
            raise ExportError("节点协议与分享链接不一致")
        source = _uri(share, protocol, parse_share_link)
    else:
        protocol = _ALIASES.get(original_type, original_type)
    if protocol not in _SUPPORTED:
        raise ExportError("节点协议无法转换为 sing-box")
    native = original_type == protocol and ("server_port" in source or "server_ports" in source)
    if native:
        output = _native(source, protocol)
    else:
        if protocol in _NATIVE_ONLY:
            raise ExportError("此协议需要原生 sing-box 出站配置")
        if original_type == "https":
            source["_https"] = True
        output = _clash(source, protocol)
    _validate(output)
    return output


def to_singbox(nodes: list[dict], *, parse_share_link: Callable[[str], dict | None]) -> str:
    outbounds = []
    tags = []
    used = {"proxy", "direct"}
    names = []
    for index, node in enumerate(nodes, 1):
        if not isinstance(node, dict) or not isinstance(node.get("name") or "node", str):
            raise ExportError(f"第 {index} 个节点：节点数据无效")
        names.append(node.get("name") or "node")
    originals = set(names)
    next_suffix: dict[str, int] = {}
    for index, (node, name) in enumerate(zip(nodes, names), 1):
        try:
            outbound = _outbound(node, parse_share_link)
            tag = name
            if tag in used:
                suffix = next_suffix.get(name, 2)
                while f"{name} ({suffix})" in used or f"{name} ({suffix})" in originals:
                    suffix += 1
                tag = f"{name} ({suffix})"
                next_suffix[name] = suffix + 1
            used.add(tag)
            tags.append(tag)
            outbounds.append({"tag": tag, **outbound})
        except ExportError as error:
            raise ExportError(f"第 {index} 个节点：{error}") from None
        except (ValueError, TypeError, KeyError, RecursionError):
            raise ExportError(f"第 {index} 个节点：节点数据无效") from None
    data = {
        "outbounds": [
            {"type": "selector", "tag": "proxy", "outbounds": tags or ["direct"]},
            {"type": "direct", "tag": "direct"},
            *outbounds,
        ]
    }
    try:
        payload = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)
        if re.search(r"[\ud800-\udfff]", payload):
            raise ExportError("节点配置包含无效的 Unicode 字符")
        return payload
    except ExportError:
        raise
    except (ValueError, TypeError, RecursionError):
        raise ExportError("节点配置无法编码为 JSON") from None

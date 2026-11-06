"""Regression fixtures for sing-box conversion and optional binary validation."""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from convert import parse_nodes_from_text, to_singbox  # noqa: E402
from export_errors import ExportError  # noqa: E402


UUID = "11111111-1111-4111-8111-111111111111"
SHADOWSOCKS = {
    "name": "HK", "type": "ss", "server": "ss.example", "port": 8388,
    "cipher": "aes-256-gcm", "password": "test-only:密码",
}


def protocol_matrix():
    vmess = base64.urlsafe_b64encode(json.dumps({
        "v": "2", "ps": "vmess", "add": "vm.example", "port": "443",
        "id": "named-vmess-user", "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": "front.example", "path": "/vmess?ed=1024", "tls": "tls",
        "sni": "tls.example", "alpn": "http/1.1", "insecure": "1",
    }).encode()).decode().rstrip("=")
    return [
        SHADOWSOCKS,
        {"name": "vmess", "type": "temp", "share": f"vmess://{vmess}"},
        {"name": "vless", "type": "vless", "share": (
            "vless://named-vless-user@vless.example:443"
            "?encryption=none&security=tls&sni=tls.example&type=grpc&serviceName=proxy%2Fv1"
        )},
        {"name": "trojan", "type": "trojan", "share": (
            "trojan://secret%3Avalue@tr.example:443?type=ws&host=front.example&path=%2Ftrojan"
        )},
        {"name": "hy2", "type": "temp", "share": (
            "hy2://user:pass@hy.example:443,5000-5002/"
            "?sni=tls.example&insecure=0&obfs=salamander&obfs-password=test%2Bsecret"
        )},
        {"name": "tuic", "type": "temp", "share": (
            f"tuic://{UUID}:test-password@tuic.example:443"
            "?congestion_control=bbr&udp_relay_mode=quic&alpn=h3&zero_rtt_handshake=0"
        )},
        {
            "name": "native-socks", "type": "socks", "server": "socks.example", "server_port": 1080,
            "version": "5", "username": "demo", "password": "test-password", "network": "tcp",
        },
    ]


class SingBoxExportTests(unittest.TestCase):
    def test_clash_yaml_shadowsocks_method(self):
        nodes = parse_nodes_from_text("""proxies:
          - name: 香港
            type: ss
            server: ss.example
            port: 8388
            cipher: aes-256-gcm
            password: test-password
            udp: false
        """)
        selector, direct, outbound = json.loads(to_singbox(nodes))["outbounds"]
        self.assertEqual(selector["outbounds"], ["香港"])
        self.assertEqual(direct, {"type": "direct", "tag": "direct"})
        self.assertEqual(outbound, {
            "type": "shadowsocks", "tag": "香港", "server": "ss.example", "server_port": 8388,
            "method": "aes-256-gcm", "password": "test-password", "network": "tcp",
        })

    def test_uri_and_native_matrix_preserve_protocol_fields(self):
        _, _, _, vmess, vless, trojan, hy2, tuic, socks = json.loads(to_singbox(protocol_matrix()))["outbounds"]
        self.assertEqual(vmess["uuid"], "named-vmess-user")
        self.assertEqual(vmess["alter_id"], 0)
        self.assertEqual(vmess["security"], "auto")
        self.assertEqual(vmess["tls"], {
            "enabled": True, "server_name": "tls.example", "insecure": True, "alpn": ["http/1.1"],
        })
        self.assertEqual(vmess["transport"], {
            "type": "ws", "path": "/vmess", "headers": {"Host": "front.example"},
            "max_early_data": 1024, "early_data_header_name": "Sec-WebSocket-Protocol",
        })
        self.assertEqual(vless["uuid"], "named-vless-user")
        self.assertEqual(vless["transport"], {"type": "grpc", "service_name": "proxy/v1"})
        self.assertEqual(trojan["password"], "secret:value")
        self.assertEqual(trojan["transport"], {"type": "ws", "path": "/trojan", "headers": {"Host": "front.example"}})
        self.assertEqual(hy2["password"], "user:pass")
        self.assertEqual(hy2["server_ports"], ["443:443", "5000:5002"])
        self.assertEqual(hy2["obfs"], {"type": "salamander", "password": "test+secret"})
        self.assertIs(hy2["tls"]["insecure"], False)
        self.assertEqual(tuic["congestion_control"], "bbr")
        self.assertEqual(tuic["udp_relay_mode"], "quic")
        self.assertIs(tuic["zero_rtt_handshake"], False)
        self.assertEqual(tuic["tls"]["alpn"], ["h3"])
        self.assertEqual(socks["version"], "5")
        self.assertEqual(socks["network"], "tcp")
        self.assertEqual(socks["username"], "demo")

    def test_reality_uses_tls_settings_and_rejects_cert_pin(self):
        key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        uri = f"vless://{UUID}@vless.example:443?security=reality&fp=chrome&sni=tls.example&pbk={key}&sid=0123"
        result = json.loads(to_singbox([{"name": "reality", "type": "temp", "share": uri}]))["outbounds"][2]
        self.assertEqual(result["tls"], {
            "enabled": True, "server_name": "tls.example",
            "utls": {"enabled": True, "fingerprint": "chrome"},
            "reality": {"enabled": True, "public_key": key, "short_id": "0123"},
        })
        with self.assertRaises(ExportError) as error:
            to_singbox([{"name": "secret-marker", "type": "temp", "share": (
                "hy2://secret-marker@hy.example:443?insecure=1&pinSHA256=secret-marker"
            )}])
        self.assertNotIn("secret-marker", str(error.exception))

    def test_unique_tags_do_not_rename_unrelated_names(self):
        names = ["proxy", "direct", "HK", "HK", "HK (2)", "HK"]
        outbounds = json.loads(to_singbox([dict(SHADOWSOCKS, name=name) for name in names]))["outbounds"]
        tags = [node["tag"] for node in outbounds[2:]]
        self.assertEqual(tags, ["proxy (2)", "direct (2)", "HK", "HK (3)", "HK (2)", "HK (4)"])
        self.assertEqual(outbounds[0]["outbounds"], tags)

    def test_rejects_lossy_or_invalid_input_without_echo(self):
        for invalid in (
            None,
            dict(SHADOWSOCKS, name="\ud800"),
            dict(SHADOWSOCKS, server="https://secret-marker.example"),
            dict(SHADOWSOCKS, port=0),
            dict(SHADOWSOCKS, tls=True, network="ws"),
            dict(SHADOWSOCKS, type="unsupported-secret-marker"),
            {"type": "socks", "server": "proxy.example", "server_port": 1080, "detour": "secret-marker"},
            {"type": "socks", "server": "proxy.example", "server_port": 1080, "port": 1081},
            {"type": "tor", "torrc": {"ClientTransportPlugin": "secret-marker"}},
            {
                "type": "vless", "server": "proxy.example", "server_port": 443, "uuid": UUID,
                "tls": {"enabled": True, "ech": {"enabled": True, "config_path": "/secret-marker"}},
            },
        ):
            with self.subTest(node_type=type(invalid).__name__), self.assertRaises(ExportError) as error:
                to_singbox([SHADOWSOCKS, invalid])
            self.assertNotIn("secret-marker", str(error.exception))


if __name__ == "__main__":
    if sys.argv[1:] == ["--emit-singbox"]:
        print(to_singbox(protocol_matrix()))
    else:
        unittest.main()

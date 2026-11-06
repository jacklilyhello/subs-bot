"""Regression checks for share-link serialization through the public converters."""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from convert import apply_path_maps, parse_nodes_from_text, to_base64_sub, to_share_links
from export_errors import ExportError


CLIENT_ID = "11111111-1111-1111-1111-111111111111"
TEST_PASSWORD = "fixture:p@ss/字#?"


def node(kind: str, **fields) -> dict:
    return {"name": "香港 节点", "type": kind, "server": "proxy.example.invalid", "port": 443, **fields}


class ShareExportTests(unittest.TestCase):
    def test_shadowsocks_sip002_escapes_ipv6_and_aead_2022_userinfo(self):
        ordinary = node("ss", server="2001:db8::5", cipher="aes-256-gcm", password=TEST_PASSWORD)
        native = {
            "name": "Native", "type": "shadowsocks", "server": "192.0.2.15", "server_port": 8388,
            "method": "2022-blake3-aes-128-gcm",
            "password": ":".join(base64.b64encode(bytes([value]) * 16).decode() for value in (251, 255)),
        }
        sip002, sip022 = to_share_links([ordinary, native])
        first = urlsplit(sip002)
        self.assertEqual(first.hostname, "2001:db8::5")
        self.assertEqual(first.port, 443)
        self.assertEqual(unquote(first.fragment), ordinary["name"])
        userinfo = first.username
        self.assertEqual(
            base64.urlsafe_b64decode(userinfo + "=" * (-len(userinfo) % 4)).decode(),
            f"{ordinary['cipher']}:{TEST_PASSWORD}",
        )
        self.assertNotIn("=", userinfo)
        second = urlsplit(sip022)
        self.assertEqual(second.username, native["method"])
        self.assertEqual(unquote(second.password), native["password"])
        self.assertIn("%2B", second.password)
        self.assertIn("%3A", second.password)

    def test_shadowsocks_plugin_keeps_sip003_mode_and_escaping(self):
        proxy = node("ss", cipher="aes-256-gcm", password=TEST_PASSWORD, plugin="v2ray-plugin")
        proxy["plugin-opts"] = {"mode": "websocket", "path": "/a;b=x", "tls": True, "host": "tls.example.invalid"}
        parsed = urlsplit(to_share_links([proxy])[0])
        self.assertEqual(parsed.path, "/")
        self.assertEqual(parse_qs(parsed.query), {
            "plugin": [r"v2ray-plugin;mode=websocket;host=tls.example.invalid;path=/a\;b\=x;tls"],
        })

    def test_native_shadowsocks_plugin_options_are_limited_to_client_settings(self):
        source = {
            "name": "Native plugin", "type": "shadowsocks", "server": "proxy.example.invalid", "server_port": 443,
            "method": "aes-256-gcm", "password": TEST_PASSWORD, "plugin": "v2ray-plugin",
        }
        allowed = r"mode=websocket;host=tls.example.invalid;tls;mux=1;path=/ws\;label\=node\;"
        parsed = urlsplit(to_share_links([{**source, "plugin_opts": allowed}])[0])
        self.assertEqual(parse_qs(parsed.query), {"plugin": [f"v2ray-plugin;{allowed}"]})
        for option in ("server", "cert=/fixture/cert.pem", "key=/fixture/key.pem", "localAddr=0.0.0.0"):
            with self.subTest(option=option.split("=", 1)[0]), self.assertRaises(ExportError):
                to_share_links([{**source, "plugin_opts": f"{allowed};{option}"}])
        with self.assertRaises(ExportError):
            to_share_links([{**source, "plugin_opts": "mode=websocket;tls=false"}])

    def test_vmess_native_ws_and_tls_export_to_v2rayn_json(self):
        source = {
            "outbounds": [{
                "tag": "日本 VMess", "type": "vmess", "server": "vm.example.invalid", "server_port": 443,
                "uuid": CLIENT_ID, "security": "aes-128-gcm", "alter_id": 2,
                "tls": {
                    "enabled": True, "server_name": "cert.example.invalid", "alpn": ["h2", "http/1.1"],
                    "insecure": True,
                },
                "transport": {"type": "ws", "path": "/ws?tag=字", "headers": {"Host": "ws.example.invalid"}},
            }],
        }
        link = to_share_links(parse_nodes_from_text(json.dumps(source)))[0]
        self.assertEqual(json.loads(base64.b64decode(link.removeprefix("vmess://"))), {
            "v": "2", "ps": "日本 VMess", "add": "vm.example.invalid", "port": "443", "id": CLIENT_ID,
            "aid": "2", "scy": "aes-128-gcm", "net": "ws", "type": "none", "host": "ws.example.invalid",
            "path": "/ws?tag=字", "tls": "tls", "sni": "cert.example.invalid", "alpn": "h2,http/1.1", "insecure": "1",
        })

    def test_vless_and_trojan_keep_reality_and_grpc_fields(self):
        vless = node("vless", uuid=CLIENT_ID, tls=True, flow="xtls-rprx-vision")
        vless.update({
            "servername": "reality.example.invalid", "client-fingerprint": "firefox",
            "reality-opts": {"public-key": "fixture-public-key", "short-id": "1234"},
        })
        trojan = node("trojan", password=TEST_PASSWORD, network="grpc", sni="tls.example.invalid")
        trojan["grpc-opts"] = {"grpc-service-name": "Example/Service"}
        vless_link, trojan_link = map(urlsplit, to_share_links([vless, trojan]))
        self.assertEqual(vless_link.username, CLIENT_ID)
        self.assertEqual(parse_qs(vless_link.query), {
            "type": ["tcp"], "security": ["reality"], "sni": ["reality.example.invalid"],
            "fp": ["firefox"], "pbk": ["fixture-public-key"], "sid": ["1234"],
            "encryption": ["none"], "flow": ["xtls-rprx-vision"],
        })
        self.assertEqual(unquote(trojan_link.username), TEST_PASSWORD)
        self.assertEqual(parse_qs(trojan_link.query), {
            "type": ["grpc"], "serviceName": ["Example/Service"], "security": ["tls"],
            "sni": ["tls.example.invalid"],
        })

    def test_hysteria2_tuic_and_anytls_keep_auth_and_protocol_options(self):
        hysteria = node("hysteria2", password=TEST_PASSWORD, obfs="salamander", sni="hy.example.invalid")
        hysteria.update({"obfs-password": "fixture obfs&key", "skip-cert-verify": True})
        tuic = {
            "name": "Native TUIC", "type": "tuic", "server": "tuic.example.invalid", "server_port": 443,
            "uuid": CLIENT_ID, "password": TEST_PASSWORD, "congestion_control": "cubic", "udp_relay_mode": "quic",
            "tls": {"enabled": True, "server_name": "tls.example.invalid", "alpn": ["h3"]},
        }
        anytls = node("anytls", password=TEST_PASSWORD, sni="anytls.example.invalid")
        links = to_share_links([hysteria, tuic, anytls])
        hy_link, tuic_link, anytls_link = map(urlsplit, links)
        self.assertEqual(unquote(hy_link.netloc.rsplit("@", 1)[0]), TEST_PASSWORD)
        self.assertEqual(parse_nodes_from_text(links[0])[0]["password"], TEST_PASSWORD)
        self.assertEqual(parse_qs(hy_link.query), {
            "sni": ["hy.example.invalid"], "insecure": ["1"],
            "obfs": ["salamander"], "obfs-password": ["fixture obfs&key"],
        })
        self.assertEqual(tuic_link.username, CLIENT_ID)
        self.assertEqual(unquote(tuic_link.password), TEST_PASSWORD)
        self.assertEqual(parse_qs(tuic_link.query), {
            "sni": ["tls.example.invalid"], "alpn": ["h3"],
            "congestion_control": ["cubic"], "udp_relay_mode": ["quic"],
        })
        self.assertEqual(unquote(anytls_link.username), TEST_PASSWORD)
        self.assertEqual(parse_qs(anytls_link.query), {"sni": ["anytls.example.invalid"]})

    def test_base64_preserves_order_original_shares_and_generated_names(self):
        old = f"vless://{CLIENT_ID}@192.0.2.20:443#Old label"
        temp = "socks5://192.0.2.30:1080#Temporary"
        structured = node("ss", cipher="aes-256-gcm", password=TEST_PASSWORD)
        nodes = apply_path_maps([node("vless", share=old), structured], {"香港": "Route A"})
        nodes.append({"name": "temp", "type": "temp", "share": temp})
        exported = base64.b64decode(to_base64_sub(nodes), validate=True).decode().splitlines()
        self.assertEqual(len(exported), 3)
        self.assertEqual(exported[0], old)
        self.assertEqual(unquote(urlsplit(exported[1]).fragment), "香港 节点 → Route A")
        self.assertEqual(exported[2], temp)

    def test_existing_sip002_and_legacy_ss_shares_are_unchanged(self):
        userinfo = base64.urlsafe_b64encode(f"aes-128-gcm:{TEST_PASSWORD}".encode()).decode().rstrip("=")
        legacy = base64.b64encode(b"aes-256-gcm:fixture:p@ss@192.0.2.40:443").decode()
        links = [
            f"ss://{userinfo}@[2001:db8::5]:443/?plugin=obfs-local%3Bobfs%3Dhttp#港 节点",
            f"ss://{legacy}#Legacy",
        ]
        self.assertEqual(to_share_links([node("ss", share=link) for link in links]), links)

        # A whole-blob password containing unescaped URI delimiters can be
        # interpreted as a different destination by a SIP002 client.
        ambiguous = base64.b64encode(f"aes-256-gcm:{TEST_PASSWORD}@192.0.2.40:443".encode()).decode()
        with self.assertRaises(ExportError):
            to_share_links([node("ss", share=f"ss://{ambiguous}#Ambiguous")])

    def test_raw_authority_accepts_protocol_defaults_and_hysteria2_port_hopping(self):
        links = [
            "hy2://proxy.example.invalid#Default port without auth",
            "hysteria2://user:pass@[2001:db8::5]:443,5000-6000/?sni=proxy.example.invalid#Port hopping",
            "anytls://test-password@proxy.example.invalid#Default port",
            "socks5://proxy.example.invalid#SOCKS without auth",
            "tuic://test-token@proxy.example.invalid:443#Legacy TUIC token",
            "ssr://opaque-legacy-share#Legacy opaque format",
        ]
        self.assertEqual(to_share_links([node("temp", share=link) for link in links]), links)

    def test_unsupported_fields_and_invalid_nodes_fail_the_whole_export_safely(self):
        good = node("ss", cipher="aes-256-gcm", password=TEST_PASSWORD)
        nested_vmess = base64.b64encode(b"[" * 2000 + b"]" * 2000).decode()
        invalid = [
            node("wireguard", password=TEST_PASSWORD),
            node("ss", cipher="aes-256-gcm", password=TEST_PASSWORD, tls=True, network="ws"),
            node("ss", cipher="aes-256-gcm", password=TEST_PASSWORD, **{"udp-over-tcp": True}),
            node("ss", cipher="2022-blake3-aes-256-gcm", password=base64.b64encode(b"x" * 16).decode()),
            node("vless", uuid=CLIENT_ID, server="good.invalid@unexpected.invalid"),
            node("vless", uuid=CLIENT_ID, port=True),
            node("vless", uuid=CLIENT_ID, tls={"enabled": False, "server_name": "name.invalid"}),
            node("vless", uuid=CLIENT_ID, tls=True, **{"skip-cert-verify": True}),
            node("trojan", password=TEST_PASSWORD, network="ws", **{"ws-opts": {"headers": {"X-Auth": TEST_PASSWORD}}}),
            node("trojan", password=TEST_PASSWORD, tls=False),
            node("tuic", token=TEST_PASSWORD),
            node("ss", share=f"ss://{TEST_PASSWORD}\nss://another.invalid"),
            node("ss", share="ss://nonsense"),
            node("vmess", share="vmess://nonsense"),
            node("vmess", share="vmess://user@"),
            node("vmess", share=f"vmess://{nested_vmess}"),
            node("vless", share="vless://nonsense"),
            node("vless", share=f"vless://{CLIENT_ID}@proxy.example.invalid"),
            node("trojan", share="trojan://nonsense"),
            node("trojan", share="trojan://test-password@proxy.example.invalid:0"),
            node("tuic", share="tuic://proxy.example.invalid:443"),
            node("hysteria2", share="hysteria2://proxy.example.invalid:6000-5000"),
            node("anytls", share="anytls://test-password@proxy.example.invalid:"),
            node("vless", share=f"vless://{CLIENT_ID}@192.0.2.20:443#Invalid\ud800"),
        ]
        for index, invalid_node in enumerate(invalid):
            with self.subTest(index=index):
                with self.assertRaises(ExportError) as error:
                    to_base64_sub([good, invalid_node])
                self.assertNotIn(TEST_PASSWORD, str(error.exception))
                self.assertNotIn("unexpected.invalid", str(error.exception))


if __name__ == "__main__":
    unittest.main()

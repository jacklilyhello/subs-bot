"""Hysteria 2 subscription import and export regression fixtures."""

from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from convert import parse_nodes_from_text, to_base64_sub, to_clash, to_singbox  # noqa: E402
from export_errors import ExportError  # noqa: E402


PORT_HOPPING = (
    "hysteria2://user%40fixture:p%3A%2B%2F%25%E7%A7%98@[2001:db8::5]:443,5000-5002/"
    "?sni=tls.example.invalid&insecure=1&obfs=salamander&obfs-password=fixture%2B%3B%25"
    "#%E9%A6%99%E6%B8%AF%20HY2"
)
DEFAULT_PORT = "hy2://default.example.invalid#Default"
LEGACY_AUTH = "hy2://legacy.example.invalid:8443?auth=old%2Bkey#Legacy"


def as_base64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


class Hysteria2ImportTests(unittest.TestCase):
    def test_port_hopping_survives_txt_and_base64_subscription_roundtrip(self):
        plain = "\n".join([PORT_HOPPING, DEFAULT_PORT, LEGACY_AUTH])
        for label, document in (("TXT", plain), ("Base64", as_base64(plain))):
            with self.subTest(label=label):
                nodes = parse_nodes_from_text(document)
                self.assertEqual([node["name"] for node in nodes], ["香港 HY2", "Default", "Legacy"])
                self.assertEqual([node["type"] for node in nodes], ["hysteria2"] * 3)
                self.assertEqual(nodes[0]["server"], "2001:db8::5")
                self.assertEqual(nodes[0]["ports"], "443,5000-5002")
                self.assertEqual(nodes[0]["password"], "user@fixture:p:+/%秘")
                self.assertEqual(nodes[0]["obfs"], "salamander")
                self.assertEqual(nodes[0]["obfs-password"], "fixture+;%")
                self.assertEqual(nodes[1]["port"], 443)
                self.assertEqual(nodes[1]["password"], "")
                self.assertEqual(nodes[2]["password"], "old+key")
                self.assertEqual(base64.b64decode(to_base64_sub(nodes), validate=True).decode(), plain)

    def test_clash_and_singbox_keep_ports_auth_and_connection_options(self):
        nodes = parse_nodes_from_text("\n".join([PORT_HOPPING, DEFAULT_PORT]))
        self.assertEqual(len(nodes), 2)
        hopping, default = yaml.safe_load(to_clash(nodes))["proxies"]
        self.assertEqual(hopping["server"], "2001:db8::5")
        self.assertEqual(hopping["ports"], "443,5000-5002")
        self.assertEqual(hopping["password"], "user@fixture:p:+/%秘")
        self.assertEqual(hopping["obfs"], "salamander")
        self.assertEqual(hopping["obfs-password"], "fixture+;%")
        self.assertEqual(hopping["sni"], "tls.example.invalid")
        self.assertIs(hopping["skip-cert-verify"], True)
        self.assertEqual(default["port"], 443)

        hopping, default = json.loads(to_singbox(nodes))["outbounds"][2:]
        self.assertEqual(hopping["server"], "2001:db8::5")
        self.assertEqual(hopping["server_ports"], ["443:443", "5000:5002"])
        self.assertNotIn("server_port", hopping)
        self.assertEqual(hopping["password"], "user@fixture:p:+/%秘")
        self.assertEqual(hopping["obfs"], {"type": "salamander", "password": "fixture+;%"})
        self.assertEqual(hopping["tls"], {"enabled": True, "server_name": "tls.example.invalid", "insecure": True})
        self.assertEqual(default["server_port"], 443)
        self.assertEqual(default["password"], "")

    def test_malformed_authorities_do_not_discard_neighboring_links(self):
        malformed = [
            "hy2://proxy.example.invalid:#Empty-port",
            "hy2://proxy.example.invalid:0#Zero-port",
            "hy2://proxy.example.invalid:443,,5000#Empty-list-entry",
            "hy2://proxy.example.invalid:443,5000-65536#Out-of-range",
            "hy2://[2001:db8::5]unexpected:443#Bracket-suffix",
            "hy2://user@#Missing-host",
        ]
        nodes = parse_nodes_from_text("\n".join([DEFAULT_PORT, *malformed, LEGACY_AUTH]))
        self.assertEqual([node["share"] for node in nodes], [DEFAULT_PORT, LEGACY_AUTH])

    def test_whole_certificate_pin_remains_in_base64_and_singbox_fails_explicitly(self):
        share = f"hy2://fixture-password@pin.example.invalid:443?pinSHA256={'ab' * 32}#Pinned"
        nodes = parse_nodes_from_text(share)
        self.assertEqual(base64.b64decode(to_base64_sub(nodes), validate=True).decode(), share)
        with self.assertRaises(ExportError) as error:
            to_singbox(nodes)
        self.assertNotIn("fixture-password", str(error.exception))


if __name__ == "__main__":
    unittest.main()

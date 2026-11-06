"""Structured Shadowsocks exports verified without using the production URI parser."""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path
from urllib.parse import unquote, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from convert import parse_nodes_from_text, to_base64_sub, to_singbox  # noqa: E402


SHADOWSOCKS_YAML = """
proxies:
  - name: "测试 节点#1"
    type: ss
    server: 203.0.113.10
    port: 8388
    cipher: aes-256-gcm
    password: "测试:pass@word?#"
"""


def singbox_fixture() -> str:
    return to_singbox(parse_nodes_from_text(SHADOWSOCKS_YAML))


class StructuredExportRegressions(unittest.TestCase):
    def test_shadowsocks_yaml_exports_one_sip002_link(self):
        nodes = parse_nodes_from_text(SHADOWSOCKS_YAML)
        self.assertEqual(len(nodes), 1)
        self.assertFalse(nodes[0].get("share"))

        subscription = to_base64_sub(nodes)
        links = base64.b64decode(subscription, validate=True).decode("utf-8").splitlines()
        self.assertEqual(len(links), 1, "structured Shadowsocks must produce one share URI")
        self.assertTrue(links[0].isascii())
        self.assertFalse(any(character.isspace() for character in links[0]))

        uri = urlsplit(links[0])
        self.assertEqual(uri.scheme, "ss")
        self.assertEqual(uri.hostname, "203.0.113.10")
        self.assertEqual(uri.port, 8388)
        self.assertEqual(unquote(uri.fragment), "测试 节点#1")
        self.assertFalse(uri.query)
        self.assertIsNotNone(uri.username)

        # SIP002 permits Base64URL userinfo or percent-encoded method and password for this cipher.
        if uri.password is None:
            encoded = unquote(uri.username)
            self.assertRegex(encoded, r"^[A-Za-z0-9_-]+={0,2}$")
            padded = encoded + "=" * (-len(encoded) % 4)
            credentials = base64.b64decode(padded, altchars=b"-_", validate=True).decode("utf-8")
            method, password = credentials.split(":", 1)
        else:
            method, password = unquote(uri.username), unquote(uri.password)
        self.assertEqual(method, "aes-256-gcm")
        self.assertEqual(password, "测试:pass@word?#")

    def test_shadowsocks_yaml_exports_singbox_fields_and_selector(self):
        outbounds = json.loads(singbox_fixture())["outbounds"]
        node_tag = "测试 节点#1"
        self.assertEqual(len(outbounds), 3)
        self.assertEqual({outbound["tag"] for outbound in outbounds}, {"proxy", "direct", node_tag})
        by_tag = {outbound["tag"]: outbound for outbound in outbounds}

        self.assertEqual(by_tag["proxy"]["type"], "selector")
        self.assertEqual(by_tag["proxy"]["outbounds"], [node_tag])
        self.assertEqual(by_tag["direct"]["type"], "direct")
        expected = {
            "type": "shadowsocks",
            "method": "aes-256-gcm",
            "password": "测试:pass@word?#",
            "server": "203.0.113.10",
            "server_port": 8388,
        }
        self.assertEqual({key: by_tag[node_tag].get(key) for key in expected}, expected)


if __name__ == "__main__":
    if sys.argv[1:] == ["--emit-singbox"]:
        print(singbox_fixture())
    else:
        unittest.main()

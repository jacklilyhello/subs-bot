"""Compare the Worker Clash compatibility cases with the legacy converter."""

import json
import sys
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from convert import to_clash  # noqa: E402


class WorkerClashOracleTests(unittest.TestCase):
    def test_shared_proxy_and_group_values_match_python(self):
        cases = json.loads((ROOT / "worker" / "test" / "clash-corpus.json").read_text(encoding="utf-8"))
        for case in cases:
            if not case.get("legacy"):
                continue
            with self.subTest(label=case["label"]):
                node = case["node"]
                payload = to_clash([node])
                self.assertNotRegex(payload, r"[\x85\u2028\u2029]")
                config = yaml.safe_load(payload)
                self.assertEqual(config["proxies"], [{"name": node["name"], **case["proxy"]}])
                self.assertEqual(config["proxy-groups"], [
                    {"name": "🚀 节点选择", "type": "select", "proxies": [node["name"]]},
                    {"name": "♻️ 自动选择", "type": "url-test", "proxies": [node["name"]],
                     "url": "http://www.gstatic.com/generate_204", "interval": 300},
                ])
                self.assertEqual(config["rules"], ["MATCH,🚀 节点选择"])


if __name__ == "__main__":
    unittest.main()

"""Compare the Worker Sing-box corpus with the legacy Python converter."""

import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from convert import to_singbox  # noqa: E402


class WorkerSingBoxOracleTests(unittest.TestCase):
    def test_shared_expected_outbounds_match_python(self):
        cases = json.loads((ROOT / "worker" / "test" / "singbox-corpus.json").read_text(encoding="utf-8"))
        for case in cases:
            if case.get("workerOnly"):
                continue
            with self.subTest(label=case["label"]):
                node = case["node"]
                if "vmess" in case:
                    payload = json.dumps(case["vmess"]).encode("utf-8")
                    node = dict(node, share="vmess://" + base64.b64encode(payload).decode("ascii"))
                config = json.loads(to_singbox([node]))
                outbound = config["outbounds"][2]
                del outbound["tag"]
                self.assertEqual(outbound, case["outbound"])


if __name__ == "__main__":
    unittest.main()

"""Check text export cases that were already lossless in the legacy service."""

import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from convert import to_qx, to_surge  # noqa: E402


class WorkerTextExportOracleTests(unittest.TestCase):
    def test_exact_legacy_profile_and_resource_bytes(self):
        cases = json.loads((ROOT / "worker" / "test" / "text-export-corpus.json").read_text(encoding="utf-8"))
        for case in cases:
            node = case["node"]
            for format in case.get("legacy", []):
                with self.subTest(label=case["label"], format=format):
                    if format == "surge":
                        expected = (f"[Proxy]\n{case[format]}\n\n[Proxy Group]\n"
                                    f"Proxy = select, {node['name']}\n\n[Rule]\nFINAL,Proxy\n")
                        self.assertEqual(to_surge([node]), expected)
                    else:
                        self.assertEqual(to_qx([node]), case[format] + "\n")


if __name__ == "__main__":
    unittest.main()

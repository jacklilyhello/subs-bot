"""Check the Worker's synthetic structured-share expectations with the legacy exporter."""

import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from export_errors import ExportError
from share_export import to_share_links


CORPUS = json.loads(Path(__file__).with_name("structured-share-corpus.json").read_text(encoding="utf-8"))


class StructuredShareOracleTests(unittest.TestCase):
    def test_worker_corpus_against_the_legacy_exporter(self):
        for case in CORPUS:
            with self.subTest(case=case["label"]):
                if "vmess" in case:
                    body = json.dumps(case["vmess"], ensure_ascii=False).encode("utf-8")
                    expected = "vmess://" + base64.b64encode(body).decode("ascii")
                else:
                    expected = case.get("pythonExpected", case["expected"])
                if expected is None:
                    with self.assertRaises(ExportError):
                        to_share_links([case["node"]])
                else:
                    self.assertEqual(to_share_links([case["node"]]), [expected])

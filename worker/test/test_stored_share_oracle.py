"""The TypeScript stored-share corpus also has to pass the legacy Python exporter."""

import base64
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from export_errors import ExportError
from share_export import to_share_links


CORPUS = json.loads(Path(__file__).with_name("stored-share-corpus.json").read_text(encoding="utf-8"))
ENCODINGS = {"utf16le": "utf-16-le", "utf32le": "utf-32-le"}


def corpus_share(row):
    if "base64Text" not in row:
        return row["share"]
    body = row["base64Text"].encode(ENCODINGS.get(row.get("encoding"), "utf-8"))
    return f"{row['scheme']}://{base64.b64encode(body).decode('ascii')}{row.get('fragment', '')}"


class StoredShareOracleTests(unittest.TestCase):
    def test_corpus_matches_legacy_exporter(self):
        for row in CORPUS:
            with self.subTest(case=row["label"]):
                share = corpus_share(row)
                if row["valid"]:
                    self.assertEqual(to_share_links([{"share": share}]), [share])
                else:
                    with self.assertRaises(ExportError):
                        to_share_links([{"share": share}])

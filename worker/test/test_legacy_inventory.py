"""Synthetic SQLite fixtures for the read-only legacy sizing tool."""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_inventory as tool


SHARE = "ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#fixture"


def compact(node):
    return json.dumps(node, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8") + b"\n"


def make_table(db, table="subscriptions", stored_count=True):
    node_count = ", node_count INTEGER" if stored_count else ""
    db.execute(f"""
        CREATE TABLE {table} (
            id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, nodes_json TEXT NOT NULL
            {node_count}, name TEXT DEFAULT 'fixture-private-name',
            url TEXT DEFAULT 'https://example.invalid/fixture-private-url',
            token TEXT DEFAULT 'fixture-private-token'
        )
    """)


class LegacyInventoryTests(unittest.TestCase):
    def setUp(self):
        root = TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.path = Path(root.name) / "fixture-private?#.sqlite"

    def test_one_closed_backup_reports_aggregate_metadata_without_writes_or_values(self):
        first = {"share": SHARE + "中文", "note": '{[}"\\\t', "nested": [{"a": 1, "b": False}]}
        second = {"type": "ss", "name": "second", "server": "203.0.113.10", "port": 8388,
                  "cipher": "aes-256-gcm", "password": "fixture-only"}
        raw = json.dumps([first, second], ensure_ascii=False, indent=2)
        trash_raw = json.dumps([{"share": SHARE}], ensure_ascii=True)
        with closing(sqlite3.connect(self.path)) as db, db:
            make_table(db)
            make_table(db, "deleted_subs", stored_count=False)
            db.execute("INSERT INTO subscriptions VALUES (1, 123, ?, 17, ?, ?, ?)",
                       (raw, "fixture-private-name", "https://example.invalid/fixture-private-url", "fixture-private-token"))
            db.execute("INSERT INTO subscriptions (id, user_id, nodes_json, node_count) VALUES (-2, 0, '[]', 0)")
            db.execute("INSERT INTO deleted_subs (id, user_id, nodes_json) VALUES (3, -100123, ?)", (trash_raw,))
        initial = self.path.read_bytes()
        original_files = {file.name for file in self.path.parent.iterdir()}

        out, errors = io.StringIO(), io.StringIO()
        # Every UTF-8 sequence, string escape and structural boundary is split.
        with patch.object(tool, "READ_BYTES", 1), redirect_stdout(out), redirect_stderr(errors):
            self.assertEqual(tool.main([str(self.path)]), 0)
        self.assertEqual(errors.getvalue(), "")
        report = json.loads(out.getvalue())
        self.assertEqual(report["version"], 1)
        active, trash = report["active"], report["trash"]
        self.assertEqual(active["rows"], 2)
        self.assertEqual(active["invalidOwnerRows"], 1)
        self.assertEqual(active["unsafeIdRows"], 1)
        self.assertEqual(active["negativeOwnerRows"], 0)
        self.assertEqual(active["rawBytes"], len(raw.encode("utf-8")) + 2)
        self.assertEqual(active["measuredRows"], 2)
        self.assertEqual(active["emptyRows"], 1)
        self.assertEqual(active["storedNodeCountMismatchRows"], 1)
        self.assertEqual(active["nodeCount"], 2)
        self.assertEqual(active["ndjsonBytes"], len(compact(first)) + len(compact(second)))
        self.assertEqual(active["chunkCount"], 1)
        self.assertEqual(active["storageFitRows"], 1)
        self.assertEqual(active["shareMeasuredRows"], 1)
        expected_shares = (SHARE + "中文", SHARE.removesuffix("fixture") + "second")
        self.assertEqual(active["shareBytes"], len("\n".join(expected_shares).encode("utf-8")))
        self.assertEqual(active["maxShareLineBytes"], max(len(line.encode("utf-8")) for line in expected_shares))
        self.assertEqual(trash["negativeOwnerRows"], 1)
        self.assertEqual(trash["invalidOwnerRows"], 1)
        self.assertFalse(trash["hasStoredNodeCount"])
        self.assertEqual(trash["nodeCount"], 1)
        for private in (str(self.path), "fixture-private", SHARE, "-100123", "中文"):
            self.assertNotIn(private, out.getvalue())
        self.assertEqual(self.path.read_bytes(), initial)
        self.assertEqual({file.name for file in self.path.parent.iterdir()}, original_files)

    def test_reports_invalid_arrays_and_limits_without_counting_partial_rows(self):
        invalid = [
            "{}",
            "[{},null]",
            "[{},]",
            "[{}]unexpected",
            '[{"x":NaN}]',
            '[{"x":1e9999}]',
            '[{"x":1,"x":2}]',
            '[{"x":[1}}]',
        ]
        invalid_text = [b'[{"x":"\xff"}]', b'[{"x":"\\ud800"}]']
        depth_limited = b'[{},{"x":' + b"[" * tool.MAX_DEPTH + b"0" + b"]" * tool.MAX_DEPTH + b"}]"
        record_limited = b'[{},{"x":"' + b"x" * tool.RAW_RECORD_BYTES + b'"}]'
        with closing(sqlite3.connect(self.path)) as db, db:
            make_table(db, stored_count=False)
            db.executemany("INSERT INTO subscriptions (user_id, nodes_json) VALUES (1, ?)",
                           ((value,) for value in invalid))
            db.executemany("INSERT INTO subscriptions (user_id, nodes_json) VALUES (1, CAST(? AS TEXT))",
                           ((value,) for value in (*invalid_text, depth_limited, record_limited)))
            db.execute("INSERT INTO subscriptions (user_id, nodes_json) VALUES (1, ?)", (b"[{}]",))
            db.execute("INSERT INTO subscriptions (user_id, nodes_json) VALUES (1, '[{}]')")
        report = tool.inventory(self.path)
        active = report["active"]
        self.assertEqual(active["invalidJsonRows"], len(invalid))
        self.assertEqual(active["invalidTextRows"], len(invalid_text))
        self.assertEqual(active["recordDepthLimitRows"], 1)
        self.assertEqual(active["recordReadLimitRows"], 1)
        self.assertEqual(active["nonTextRows"], 1)
        self.assertEqual(active["rows"], len(invalid) + len(invalid_text) + 4)
        self.assertEqual(active["measuredRows"], 1)
        self.assertEqual(active["nodeCount"], 1)
        self.assertEqual(active["ndjsonBytes"], len(b"{}\n"))
        self.assertEqual(active["shareUnsupportedRows"], 1)
        self.assertEqual(active["maxRawBytes"], len(record_limited))
        self.assertEqual(report["trash"], {"present": False})

    def test_large_text_cell_is_streamed_and_fits_the_exact_snapshot_limit(self):
        raw_bytes = 83_600_000
        chunks = tool.SNAPSHOT_BYTES // tool.CHUNK_BYTES
        compact_node = b'{"pad":"' + b"x" * (tool.CHUNK_BYTES - len(b'{"pad":""}\n')) + b'"}'
        padding, extra = divmod(raw_bytes - 2 - chunks * len(compact_node) - (chunks - 1), chunks)
        with closing(sqlite3.connect(self.path)) as db, db:
            make_table(db)
            rowid = db.execute("""
                INSERT INTO subscriptions (user_id, nodes_json, node_count)
                VALUES (1, CAST(zeroblob(?) AS TEXT), ?)
            """, (raw_bytes, chunks)).lastrowid
            with db.blobopen("subscriptions", "nodes_json", rowid) as blob:
                blob.write(b"[")
                for index in range(chunks):
                    if index:
                        blob.write(b",")
                    blob.write(b"{" + b" " * (padding + (index < extra)) + compact_node[1:])
                blob.write(b"]")
                self.assertEqual(blob.tell(), raw_bytes)

        active = tool.inventory(self.path)["active"]
        self.assertEqual(active["maxRawBytes"], raw_bytes)
        self.assertEqual(active["maxNdjsonBytes"], 64 * 1024 * 1024)
        self.assertEqual(active["maxNodeLineBytes"], 512 * 1024)
        self.assertEqual(active["maxChunkCount"], chunks)
        self.assertEqual(active["storageFitRows"], 1)
        self.assertEqual(active["snapshotBytesOverLimitRows"], 0)
        self.assertEqual(active["lineOverLimitRows"], 0)
        with patch.object(tool, "SNAPSHOT_BYTES", tool.SNAPSHOT_BYTES - 1):
            over = tool.inventory(self.path)["active"]
        self.assertEqual(over["storageFitRows"], 0)
        self.assertEqual(over["snapshotBytesOverLimitRows"], 1)

    def test_node_count_line_chunk_and_share_limits_are_independent(self):
        safe = json.dumps({"share": SHARE}, separators=(",", ":"))
        limit_line = '{"pad":"' + "a" * (tool.CHUNK_BYTES - len(b'{"pad":""}')) + '"}'
        with closing(sqlite3.connect(self.path)) as db, db:
            make_table(db)
            fixtures = [
                "[" + ",".join(["{}"] * tool.MAX_NODES) + "]",
                "[" + ",".join(["{}"] * (tool.MAX_NODES + 1)) + "]",
                f"[{limit_line}]",
                f"[{safe},{safe}]",
            ]
            db.executemany("INSERT INTO subscriptions (user_id, nodes_json) VALUES (1, ?)",
                           ((value,) for value in fixtures))
        joined_share_bytes = 2 * len(SHARE.encode("utf-8")) + 1
        with patch.object(tool, "SHARE_BYTES", joined_share_bytes), patch.object(tool, "MAX_CHUNKS", 1):
            active = tool.inventory(self.path)["active"]
        self.assertEqual(active["maxNodeCount"], 100_001)
        self.assertEqual(active["nodeCountOverLimitRows"], 1)
        self.assertEqual(active["maxNodeLineBytes"], 512 * 1024 + 1)
        self.assertEqual(active["lineOverLimitRows"], 1)
        self.assertEqual(active["chunkMeasurableRows"], 3)
        self.assertEqual(active["shareBytes"], joined_share_bytes)
        self.assertEqual(active["shareBytesOverLimitRows"], 0)
        self.assertEqual(active["storageFitRows"], 2)
        with patch.object(tool, "SHARE_BYTES", joined_share_bytes - 1), patch.object(tool, "MAX_CHUNKS", 0):
            over = tool.inventory(self.path)["active"]
        self.assertEqual(over["chunkCountOverLimitRows"], 3)
        self.assertEqual(over["shareBytesOverLimitRows"], 1)

    def test_rejects_bad_sources_without_creating_files_or_exposing_paths(self):
        out, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(errors):
            self.assertEqual(tool.main([str(self.path)]), 2)
        self.assertEqual(out.getvalue(), "")
        self.assertNotIn(str(self.path), errors.getvalue())
        self.assertFalse(self.path.exists())

        with closing(sqlite3.connect(self.path)) as db, db:
            make_table(db)
        sidecar = Path(str(self.path) + "-wal")
        sidecar.write_bytes(b"synthetic")
        with self.assertRaisesRegex(tool.InventoryError, "sidecar"):
            tool.inventory(self.path)
        self.assertEqual(sidecar.read_bytes(), b"synthetic")
        sidecar.unlink()

        alias = self.path.with_name("alias.sqlite")
        alias.symlink_to(self.path)
        with self.assertRaisesRegex(tool.InventoryError, "regular file"):
            tool.inventory(alias)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode = WAL").fetchone(), ("wal",))
        with self.assertRaisesRegex(tool.InventoryError, "DELETE journal mode"):
            tool.inventory(self.path)


if __name__ == "__main__":
    unittest.main()

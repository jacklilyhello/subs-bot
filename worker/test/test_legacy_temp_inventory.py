"""Hosted regression cases for sealed, dormant temporary-node inventories."""

from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import quote


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_temp_inventory as tool


BOT = "9000000000000101"
SHARE = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#Original%20URI%20label"
DDL = """CREATE TABLE IF NOT EXISTS temp_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
)"""


def json_bytes(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def digest(value):
    return sha256(value).hexdigest()


class LegacyTempInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "private source.sqlite"
        self.output = self.root / "inventory"

    def write_source(self, rows=(), *, ddl=DDL, sequence=None):
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute(ddl)
            if rows:
                db.executemany("INSERT INTO temp_nodes VALUES (?,?,?,?,?)", rows)
            if sequence is not None:
                db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='temp_nodes'", (sequence,))
        self.source.chmod(0o600)

    def seal(self, owners=None, **overrides):
        owners = owners if owners is not None else {}
        options = {"source_sha256": digest(self.source.read_bytes()), "owner_map": owners,
                   "owner_map_sha256": digest(json_bytes(dict(sorted(owners.items())))), "legacy_bot_id": BOT}
        return tool.seal_inventory(self.source, self.output, **(options | overrides))

    def rows(self):
        return [json.loads(line) for line in (self.output / tool.ROWS).read_bytes().splitlines()]

    def test_exact_seal_preserves_names_raw_duplicates_and_old_id_order(self):
        unicode_name = '  原始 "名称"\n\x01 👩\u200d💻  '
        encoded_share = SHARE.partition("#")[0] + "#" + quote(unicode_name, safe="")
        self.assertIn("%0A", encoded_share)
        self.write_source([(8, 123, encoded_share, unicode_name, 40), (3, 123, encoded_share, "", 41),
                           (4, 456, "future+opaque://raw#label", "third owner", 39)], sequence=12)
        before = self.source.read_bytes()
        result = self.seal()
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual(result["workerValidation"], "pending")
        self.assertIs(result["completeImportable"], False)
        raw = (self.output / tool.MANIFEST).read_bytes()
        manifest = json.loads(raw)
        self.assertEqual(manifest["sourceHighWater"], 12)
        self.assertEqual(manifest["sourceSha256"], digest(before))
        self.assertEqual(manifest["legacyBotId"], BOT)
        self.assertEqual(manifest["rowOrder"], "legacy-id-ascending")
        self.assertEqual((self.output / tool.SEAL).read_bytes(), digest(raw).encode("ascii") + b"\n")
        contents = (self.output / tool.ROWS).read_bytes()
        self.assertEqual(manifest["files"], [{"file": tool.ROWS, "bytes": len(contents), "sha256": digest(contents)}])
        rows = self.rows()
        self.assertEqual([(row["ordinal"], row["legacyId"], row["createdAt"]) for row in rows], [(1, 3, 41), (2, 4, 39), (3, 8, 40)])
        self.assertEqual([row["disposition"] for row in rows], ["pending-worker"] * 3)
        self.assertEqual(rows[0]["node"], {"name": "", "type": "temp", "share": encoded_share})
        self.assertEqual(rows[2]["node"], {"name": unicode_name, "type": "temp", "share": encoded_share})
        self.assertEqual(rows[1]["node"]["share"], "future+opaque://raw#label")
        self.assertEqual(rows[2]["uriSha256"], digest(encoded_share.encode("utf-8")))
        self.assertEqual(rows[2]["nameSha256"], digest(unicode_name.encode("utf-8")))
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(path.stat().st_mode & 0o777 == 0o600 for path in self.output.iterdir()))

    def test_bad_rows_are_accounted_for_without_copying_unsafe_raw_values(self):
        self.write_source([(1, 0, SHARE, "invalid owner", 1), (2, -77, SHARE, "unmapped", 1),
                           (3, -88, SHARE, "mapped", 1), (4, 88, SHARE, "coalesced", 1),
                           (5, 123, "https://example.invalid/sensitive", "web", 1),
                           (6, 123, SHARE + "\n\x01", "URI control", 1), (7, 123, SHARE, "clock", "bad date"),
                           (8, 123, "ss://#broken", "syntax", 1),
                           (9, 123, sqlite3.Binary(b"fake-raw"), "blob", 1),
                           (10, 123, "ss://" + "x" * tool.MAX_BATCH_BYTES, "overlong", 1),
                           (11, 123, SHARE, "invalid utf8", 1)])
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("UPDATE temp_nodes SET name=CAST(X'FF' AS TEXT) WHERE id=11")
        report = self.seal({"-88": "88"})
        counts = report["inventory"]
        self.assertEqual((counts["rows"], counts["blockedRows"], counts["pendingWorkerRows"]), (11, 11, 0))
        self.assertEqual(counts["rowReasons"], dict.fromkeys(("owner-identity", "owner-unmapped", "owner-remapped", "owner-coalesced",
            "unsupported-non-node-scheme", "uri-text", "created-at", "uri-shape", "uri-storage", "uri-limit", "name-encoding"), 1))
        rows = self.rows()
        self.assertTrue(all(row["disposition"] == "blocked" and row["node"] is None for row in rows))
        self.assertEqual((rows[2]["originalOwnerId"], rows[2]["ownerId"], rows[3]["ownerId"]), ("-88", "88", "88"))
        self.assertEqual((rows[9]["uriBytes"], rows[9]["uriSha256"]), (tool.MAX_BATCH_BYTES + 5, None))
        self.assertEqual(rows[10]["nameSha256"], digest(b"\xff"))
        sealed_rows = (self.output / tool.ROWS).read_text()
        self.assertNotIn("example.invalid", sealed_rows)
        self.assertNotIn("fake-raw", sealed_rows)

    def test_projects_exact_compact_batches_and_retains_rows_over_owner_quota(self):
        names = ("一", 'a"b', "a\\b")
        nodes = [{"name": name, "type": "temp", "share": SHARE} for name in names]
        expected_bytes = len(json_bytes(nodes[:2])) + len(json_bytes(nodes[2:]))
        self.write_source([(index, 123, SHARE, name, index) for index, name in enumerate(names, 1)])
        with (patch.object(tool, "MAX_BATCH_NODES", 2), patch.object(tool, "MAX_OWNER_NODES", 2),
              patch.object(tool, "MAX_OWNER_BYTES", expected_bytes - 1)):
            counts = self.seal()["inventory"]
        self.assertEqual((counts["pendingWorkerRows"], counts["blockedRows"], counts["blockedOwnerScopes"]), (3, 0, 1))
        self.assertEqual(counts["scopeReasons"], {"owner-byte-limit": 1, "owner-node-limit": 1})
        self.assertEqual(counts["projection"], {"status": "preflight-only", "owners": 1, "batches": 2,
            "payloadBytes": expected_bytes, "maxOwnerNodes": 3, "maxOwnerBytes": expected_bytes})
        self.assertEqual([row["node"] for row in self.rows()], nodes)

    def test_absent_table_is_distinct_from_present_empty(self):
        self.write_source(ddl="CREATE TABLE another_table (id INTEGER PRIMARY KEY)")
        self.assertEqual((self.seal()["inventory"]["present"], self.rows()), (False, []))
        self.source = self.root / "present.sqlite"
        self.output = self.root / "present"
        self.write_source()
        self.assertEqual((self.seal()["inventory"]["present"], self.rows()), (True, []))

    def test_pins_sidecars_and_noncanonical_schema_fail_without_output(self):
        self.write_source([(1, 123, SHARE, "sample", 1)])
        with self.assertRaises(tool.InventoryError):
            self.seal(source_sha256="0" * 64)
        self.assertFalse(self.output.exists())
        sidecar = Path(str(self.source) + "-wal")
        sidecar.touch(mode=0o600)
        with self.assertRaises(tool.InventoryError):
            self.seal()
        self.assertFalse(self.output.exists())
        sidecar.unlink()
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("CREATE INDEX temp_unexpected ON temp_nodes(name)")
        with self.assertRaisesRegex(tool.InventoryError, "table schema differs"):
            self.seal()
        self.assertFalse(self.output.exists())

    def test_cli_redacts_private_rows_and_returns_blocked_status(self):
        self.write_source([(1, 123, SHARE, "secret name", 1), (2, -77, SHARE, "blocked secret name", 1)])
        owners = self.root / "owners.json"
        owners.write_bytes(b"{}")
        owners.chmod(0o600)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = tool.main([str(self.source), str(self.output), digest(self.source.read_bytes()),
                                str(owners), digest(b"{}"), BOT])
        self.assertEqual(result, 2)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(json.loads(out.getvalue())["inventory"]["blockedRows"], 1)
        self.assertTrue((self.output / tool.SEAL).is_file())
        self.assertNotIn("secret", out.getvalue())
        self.assertNotIn(BOT, out.getvalue())
        self.assertNotIn(SHARE, out.getvalue())

    def test_cli_redacts_nonprivate_owner_map_parent_failure(self):
        self.write_source()
        public_parent = self.root / "readable private path"
        public_parent.mkdir()
        public_parent.chmod(0o755)
        owners = public_parent / "owners.json"
        owners.write_bytes(b"{}")
        owners.chmod(0o600)
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            result = tool.main([str(self.source), str(self.output), digest(self.source.read_bytes()),
                                str(owners), digest(b"{}"), BOT])
        self.assertEqual((result, out.getvalue(), err.getvalue()), (2, "", tool.ERROR + "\n"))
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

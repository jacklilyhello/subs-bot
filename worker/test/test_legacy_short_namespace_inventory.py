"""Hosted synthetic coverage for the mixed legacy short-link inventory."""

from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
from pathlib import Path
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_short_namespace_inventory as tool

ORIGIN = "https://old-bot.example.invalid"
ACTIVE = "synthetic-active-capability"
TRASH = "synthetic-deleted-capability"
EXTERNAL = "https://example.org/api/%2F?signature=synthetic-external-secret#keep"
OWNERS = {"-10010": "300", "-10020": "300", "123": "123"}
WHEN = 1700000000


def digest(value):
    return sha256(value.encode()).hexdigest()


def owner_pin(owners):
    return digest(json.dumps(owners, sort_keys=True, separators=(",", ":")))


class LegacyShortNamespaceInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.backup = self.root / "synthetic backup?#.sqlite"
        self.output = self.root / "namespace"
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.executescript("""
                CREATE TABLE subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    token TEXT NOT NULL UNIQUE, nodes_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE deleted_subs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token TEXT NOT NULL
                );
                CREATE TABLE short_links (
                    code TEXT PRIMARY KEY, user_id INTEGER NOT NULL, target_url TEXT NOT NULL, created_at INTEGER NOT NULL
                );
            """)
            db.execute("INSERT INTO subscriptions VALUES (2,123,?,CAST(X'ff' AS TEXT))", (ACTIVE,))
            db.executemany("INSERT INTO subscriptions(id,user_id,token) VALUES (?,?,?)", [
                (5, -10010, "synthetic-first-group-token"), (7, -10020, "synthetic-second-group-token"),
                (9, 123, "synthetic-prior-token"),
            ])
            db.execute("DELETE FROM subscriptions WHERE id=9")
            db.executemany("INSERT INTO deleted_subs VALUES (?,?,?)", [
                (3, 123, TRASH), (70, 123, "synthetic-high-trash-token"),
            ])
        self.backup.chmod(0o600)

    def execute(self, statement, values=()):
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.execute(statement, values)

    def add(self, target, *, code="Fixture_0001", owner=123, created=WHEN):
        self.execute("INSERT INTO short_links VALUES (?,?,?,?)", (code, owner, target, created))

    def arguments(self):
        return {"source_sha256": sha256(self.backup.read_bytes()).hexdigest(), "owner_map": OWNERS,
                "owner_map_sha256": owner_pin(OWNERS), "old_origin": ORIGIN, "legacy_bot_id": "9223372036854775807"}

    def seal(self, **options):
        tool.seal_inventory(self.backup, self.output, **(self.arguments() | options))
        manifest = (self.output / tool.MANIFEST).read_bytes()
        payload = (self.output / tool.ROWS).read_bytes()
        self.assertEqual((self.output / tool.SEAL).read_bytes(), sha256(manifest).hexdigest().encode() + b"\n")
        report = json.loads(manifest)
        self.assertEqual(report["files"], [{"file": tool.ROWS, "bytes": len(payload), "sha256": sha256(payload).hexdigest()}])
        rows = [json.loads(line) for line in payload.splitlines()]
        self.assertEqual(report["inventory"]["rows"], len(rows))
        self.assertEqual(report["inventory"]["rows"], sum(report["inventory"]["kinds"].values()))
        return report, rows, manifest + payload

    def reject(self, **options):
        with self.assertRaisesRegex(tool.InventoryError, r"^Legacy short namespace inventory could not be confirmed safely\.$"):
            self.seal(**options)
        self.assertFalse(self.output.exists())

    def test_closes_all_four_destination_types_without_capability_values(self):
        cases = [
            ("Fixture_0001", f"{ORIGIN}/sub/{ACTIVE}", "typed-subscription"),
            ("fixture_0001", f"{ORIGIN}/sub/{TRASH}/sing-box", "typed-subscription"),
            ("Fixture_0002", EXTERNAL, "external"),
            ("Fixture_0003", "aggregate://all", "aggregate-all"),
            ("Fixture_0004", "aggregate://ids/2,3,2,9", "aggregate-selected"),
        ]
        for index, (code, target, _) in enumerate(cases):
            self.add(target, code=code, created=WHEN + index)
        before = self.backup.read_bytes()
        report, rows, output = self.seal()
        self.assertEqual(self.backup.read_bytes(), before)
        self.assertEqual(report["scope"], "offline-dormant")
        self.assertEqual(report["externalRedirects"], "not-validated")
        self.assertEqual(report["inventory"]["activeHighWater"], 9)
        self.assertEqual(report["inventory"]["blocked"], 0)
        self.assertEqual([row["codeSha256"] for row in rows], [digest(code) for code, _, _ in cases])
        self.assertEqual([row["targetSha256"] for row in rows], [digest(target) for _, target, _ in cases])
        self.assertEqual([row["kind"] for row in rows], [kind for _, _, kind in cases])
        self.assertEqual([row["createdAt"] for row in rows], list(range(WHEN, WHEN + len(cases))))
        self.assertTrue(all(row["sourceIssuerId"] == row["ownerId"] == "123" for row in rows))
        self.assertEqual((rows[0]["legacyTable"], rows[0]["legacyId"], rows[0]["format"]), ("subscriptions", 2, ""))
        self.assertEqual((rows[1]["legacyTable"], rows[1]["legacyId"], rows[1]["format"]), ("deleted_subs", 3, "sing-box"))
        self.assertEqual(rows[1]["tokenSha256"], digest(TRASH))
        self.assertEqual(rows[4]["legacyIds"], [2, 3, 2, 9])
        self.assertEqual(rows[4]["activePositions"], [0, 2])
        for value in (ORIGIN, ACTIVE, TRASH, EXTERNAL, *(code for code, _, _ in cases)):
            self.assertNotIn(value.encode(), output)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in self.output.iterdir()))

    def test_coalesced_owner_and_active_only_id_rules_fail_closed(self):
        cases = [
            ("aggregate://all", -10010, "aggregate-all-owner-scope"),
            ("aggregate://all", 300, "aggregate-all-owner-scope"),
            ("aggregate://ids/5,7", -10010, "aggregate-selected-foreign-owner"),
            ("aggregate://ids/2,70", 123, "aggregate-selected-lineage"),
            ("aggregate://ids/2,,9", 123, "aggregate-selected-shape"),
            ("aggregate://ids/" + ",".join(["2"] * 129), 123, "aggregate-selected-limit"),
            (f"{ORIGIN}/sub/synthetic-second-group-token/clash", -10010, "typed-foreign-owner"),
        ]
        for index, (target, owner, _) in enumerate(cases, 1):
            self.add(target, code=f"Fixture_{index:04d}", owner=owner)
        self.add("aggregate://ids/9,5", code="Fixture_0008", owner=-10010)
        report, rows, _ = self.seal()
        self.assertEqual([row["reason"] for row in rows[:-1]], [reason for _, _, reason in cases])
        self.assertEqual(report["inventory"]["blocked"], len(cases))
        self.assertEqual(rows[-1]["sourceIssuerId"], "-10010")
        self.assertEqual(rows[-1]["ownerId"], "300")
        self.assertEqual(rows[-1]["legacyIds"], [9, 5])
        self.assertEqual(rows[-1]["activePositions"], [1])

    def test_unsafe_unknown_and_over_limit_rows_remain_accounted_for(self):
        cases = [
            (f"{ORIGIN}/s/Fixture_0001", "untyped-first-party-target"),
            (f"{ORIGIN}/agg/Fixture_0001/clash", "untyped-first-party-target"),
            (f"{ORIGIN}:443/sub/{ACTIVE}", "untyped-first-party-target"),
            (f"{ORIGIN}/sub/{ACTIVE}/Base64", "typed-target-shape"),
            ("https://fixture-user@example.org/a", "external-authority"),
            ("http://127.0.0.1/private", "external-authority"),
            ("https://example.org/a%0Ab", "external-url-shape"),
            ("https://0x7f.0.0.0x1/private", "external-authority"),
            ("https://example.org/" + "a" * 2048, "external-target-limit"),
            ("https://example.org/" + "a" * tool.MAX_TARGET_BYTES, "target-limit"),
            (sqlite3.Binary(b"not text"), "target-not-text"),
            ("aggregate://unknown", "unrecognized-target"),
        ]
        for index, (target, _) in enumerate(cases, 1):
            self.add(target, code=f"Fixture_{index:04d}")
        report, rows, output = self.seal()
        self.assertEqual([row["reason"] for row in rows], [reason for _, reason in cases])
        self.assertEqual(report["inventory"]["blocked"], len(cases))
        self.assertIsNone(rows[9]["targetSha256"])
        self.assertIsNone(rows[10]["targetSha256"])
        self.assertNotIn(b"fixture-user", output)

    def test_invalid_code_or_sequence_never_seals_partial_evidence(self):
        self.add(EXTERNAL)
        self.add(EXTERNAL, code="bad-code")
        self.reject()
        self.execute("DELETE FROM short_links WHERE code='bad-code'")
        self.execute("UPDATE sqlite_sequence SET seq=6 WHERE name='subscriptions'")
        self.reject()

    def test_wrong_pins_sidecar_and_output_cap_refuse_cleanly(self):
        self.add(EXTERNAL)
        self.reject(source_sha256="0" * 64)
        self.reject(owner_map_sha256="0" * 64)
        sidecar = self.backup.with_name(self.backup.name + "-wal")
        sidecar.touch(mode=0o600)
        self.reject()
        sidecar.unlink()
        with patch.object(tool, "MAX_METADATA_BYTES", 1):
            self.reject()

    def test_absent_short_table_and_empty_owner_map_cli(self):
        self.execute("DROP TABLE short_links")
        owner_map = self.root / "owners.json"
        owner_map.write_text("{}", encoding="ascii")
        owner_map.chmod(0o600)
        args = [str(self.backup), str(self.output), self.arguments()["source_sha256"], str(owner_map), owner_pin({}),
                ORIGIN, self.arguments()["legacy_bot_id"]]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(tool.main(args), 0)
        self.assertEqual(stdout.getvalue(), "Legacy short namespace inventory sealed.\n")
        self.assertEqual(stderr.getvalue(), "")
        report = json.loads((self.output / tool.MANIFEST).read_bytes())
        self.assertFalse(report["inventory"]["present"])
        self.assertEqual(report["inventory"]["activeHighWater"], 9)
        self.assertEqual((self.output / tool.ROWS).read_bytes(), b"")

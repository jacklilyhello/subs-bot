"""Hosted only. Compare legacy redirects and verify the sealed candidate replay."""

from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
from platform import python_version
from shutil import copytree
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from legacy_mixed_short_candidate import MixedShortInput
import legacy_restore_package as package
import legacy_short_namespace_inventory as mixed
import legacy_short_redirect_oracle as oracle
import legacy_snapshot_convert as converter
from test_legacy_snapshot_convert import insert, make_path_table

ORIGIN = "https://legacy-short.fixture.invalid"
TOKEN = "synthetic-redirect-fixture-token"
BOT_ID = "78901"
CREATED_AT = 1700000000
YARL = "1.20.0"
EXTERNAL = ("Oracle_00001", "https://example.org/route?value=synthetic-secret&mode=exact#keep", "equivalent")
DIFFERENT = ("Oracle_00002", "https://example.org", "location-differs")
TYPED = ("Oracle_00005", f"{ORIGIN}/sub/{TOKEN}", None)
AGGREGATE = ("Oracle_00006", "aggregate://all", None)


def digest(body):
    return sha256(body if isinstance(body, bytes) else body.encode()).hexdigest()


class LegacyShortRedirectOracleTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source.sqlite"
        self.inventory = self.root / "inventory"
        self.output = self.root / "oracle"
        self.config = self.root / "oracle.json"
        self.owner_map = self.root / "owners.json"
        self.owner_map.write_bytes(b"{}")
        self.owner_map.chmod(0o600)
        self.bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"]).resolve()
        self.revision = os.environ["WORKER_TEST_REVISION"]

    def prepare(self, cases=None, *, for_candidate=False):
        self.cases = cases if cases is not None else [
            EXTERNAL,
            DIFFERENT,
            ("Oracle_00003", "https://example.org/" + "é" * 500, "worker-refused"),
            ("Oracle_00004", "http://127.0.0.1/synthetic-local-destination", "inventory-blocked"),
            TYPED,
            AGGREGATE,
        ]
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("""CREATE TABLE subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT 'synthetic',url TEXT NOT NULL DEFAULT 'https://source.example.invalid/item',
                token TEXT NOT NULL UNIQUE,expire_at INTEGER,traffic_used REAL,traffic_total REAL,
                nodes_json TEXT NOT NULL DEFAULT '[]',node_count INTEGER NOT NULL DEFAULT 0,last_error TEXT,
                created_at INTEGER NOT NULL DEFAULT 1700000000,updated_at INTEGER NOT NULL DEFAULT 1700001000
            )""")
            insert(db, token=TOKEN)
            make_path_table(db)
            db.execute("INSERT INTO path_maps VALUES (3,123,' hk ',' 合成 ')")
            db.execute("""CREATE TABLE short_links (
                code TEXT PRIMARY KEY,user_id INTEGER NOT NULL,target_url TEXT NOT NULL,created_at INTEGER NOT NULL
            )""")
            db.executemany("INSERT INTO short_links VALUES (?,123,?,?)",
                           [(code, target, CREATED_AT) for code, target, _ in self.cases])
        self.source.chmod(0o600)
        self.source_sha = digest(self.source.read_bytes())
        mixed.seal_inventory(self.source, self.inventory, source_sha256=self.source_sha, owner_map={}, owner_map_sha256=digest(b"{}"),
                             old_origin=ORIGIN, legacy_bot_id=BOT_ID)
        if for_candidate:
            # Model main-only artifact provenance for this synthetic replay. The emitted Worker and migration bytes stay exact.
            self.bundle = copytree(self.bundle, self.root / "worker")
            manifest_path = self.bundle / "isolation.json"
            manifest = json.loads(manifest_path.read_bytes())
            manifest["ref"] = "refs/heads/main"
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        manifest = (self.bundle / "isolation.json").read_bytes()
        self.assertEqual(json.loads(manifest)["revision"], self.revision)
        self.settings = {"backup": str(self.source), "inventory": str(self.inventory), "output": str(self.output),
                         "sourceSha256": self.source_sha, "ownerMap": str(self.owner_map), "ownerMapSha256": digest(b"{}"),
                         "oldOrigin": ORIGIN, "legacyBotId": BOT_ID, "inventorySha256": digest((self.inventory / mixed.MANIFEST).read_bytes()),
                         "bundle": str(self.bundle), "workerManifestSha256": digest(manifest),
                         "revision": self.revision, "yarlVersion": YARL, "pythonVersion": python_version()}

    def run_cli(self, **overrides):
        self.config.write_text(json.dumps(self.settings | overrides), encoding="utf-8")
        self.config.chmod(0o600)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = oracle.main([str(self.config)])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_emitted_route_and_legacy_serialization_close_every_external_row(self):
        self.prepare()
        self.assertEqual(self.run_cli(), (0, "Legacy external redirect equivalence sealed.\n", ""))
        self.assertEqual(digest(self.source.read_bytes()), self.source_sha)
        manifest = (self.output / oracle.MANIFEST).read_bytes()
        rows = (self.output / oracle.ROWS).read_bytes()
        report = json.loads(manifest)
        self.assertEqual((self.output / oracle.SEAL).read_bytes(), digest(manifest).encode() + b"\n")
        self.assertEqual(report["files"], [{"file": oracle.ROWS, "bytes": len(rows), "sha256": digest(rows)}])
        self.assertEqual(report["sourceRows"], 6)
        self.assertEqual(report["externalRows"], 4)
        self.assertEqual(report["inventoryBlockedRows"], 1)
        self.assertEqual([json.loads(line) for line in rows.splitlines()], [
            {"codeSha256": digest(code), "state": state} for code, _, state in self.cases if state is not None
        ])
        self.assertEqual(report["legacySerializer"], {"python": python_version(), "aiohttp": oracle.AIOHTTP, "yarl": YARL})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in self.output.iterdir()))
        for value in (ORIGIN, TOKEN, *(code for code, _, _ in self.cases), *(target for _, target, _ in self.cases)):
            self.assertNotIn(value.encode(), manifest + rows)

    def test_wrong_pins_and_changed_inventory_never_publish_partial_evidence(self):
        self.prepare()
        failure = (2, "", oracle.FAILURE + "\n")
        self.assertEqual(self.run_cli(yarlVersion="0.0.0"), failure)
        self.assertEqual(self.run_cli(pythonVersion="0.0.0"), failure)
        self.assertEqual(self.run_cli(workerManifestSha256="0" * 64), failure)
        path = self.inventory / mixed.ROWS
        body = path.read_bytes()
        path.write_bytes(b"X" + body[1:])
        self.assertEqual(self.run_cli(), failure)
        self.assertFalse(self.output.exists())

    def prepare_candidate(self, cases):
        self.prepare(cases, for_candidate=True)
        self.conversion = self.root / "conversion"
        report = converter.convert_backup(self.source, self.conversion, owner_map={})
        self.assertEqual(report["blockers"], {"unhandled:short_links": len(cases)})
        self.assertEqual(self.run_cli(), (0, "Legacy external redirect equivalence sealed.\n", ""))
        self.candidate = self.root / "candidate"
        self.pins = MixedShortInput(
            source=self.source, owner_map=self.owner_map, old_origin=ORIGIN, legacy_bot_id=BOT_ID,
            namespace=self.inventory, namespace_sha256=self.settings["inventorySha256"],
            oracle=self.output, oracle_sha256=digest((self.output / oracle.MANIFEST).read_bytes()),
            legacy_python_version=python_version(), legacy_yarl_version=YARL,
        )

    def build_candidate(self):
        return package.build_candidate(
            self.conversion, self.bundle, self.candidate,
            converter_manifest_sha=digest((self.conversion / package.MANIFEST).read_bytes()),
            worker_manifest_sha=self.settings["workerManifestSha256"], revision=self.revision, applied_at=CREATED_AT,
            profile=package.MIXED_SHORT_PROFILE, source_sqlite_sha=self.source_sha, owner_map_sha=digest(b"{}"),
            mixed_short=self.pins,
        )

    def test_v5_replays_the_complete_typed_and_equivalent_external_namespace(self):
        self.prepare_candidate([EXTERNAL, TYPED])
        report = self.build_candidate()
        self.assertEqual(report["version"], 5)
        self.assertEqual(report["externalShortLinks"]["rows"], 1)
        self.assertEqual(report["typedShortLinks"]["rows"], 1)
        self.assertEqual(report["shortLinkCompatibility"], {"typed": "not-validated", "external": "offline-equivalent"})
        manifest_raw = (self.candidate / package.MANIFEST).read_bytes()
        manifest = json.loads(manifest_raw)
        self.assertEqual((self.candidate / package.MARKER).read_text(), digest(manifest_raw) + "\n")
        build = json.loads((self.bundle / "isolation.json").read_bytes())
        for field in ("revision", "bundleSha256", "compatibilityDate", "migrations"):
            self.assertEqual(manifest["workerArtifact"][field], build[field])
        self.assertEqual(manifest["workerArtifact"]["manifestSha256"], self.settings["workerManifestSha256"])
        self.assertEqual(manifest["source"]["sqliteSha256"], self.source_sha)
        self.assertEqual(manifest["source"]["ownerMapSha256"], digest(b"{}"))
        self.assertEqual(manifest["source"]["namespaceManifestSha256"], self.pins.namespace_sha256)
        self.assertEqual(manifest["source"]["oracleManifestSha256"], self.pins.oracle_sha256)
        self.assertEqual(manifest["source"]["legacySerializer"],
                         {"python": python_version(), "aiohttp": oracle.AIOHTTP, "yarl": YARL})
        sql = (self.candidate / package.SQL).read_text(encoding="utf-8")
        for code, target, _ in (EXTERNAL, TYPED):
            self.assertNotIn(code, sql)
            self.assertNotIn(code.encode(), manifest_raw)
            self.assertNotIn(target.encode(), manifest_raw)
        self.assertNotIn(TYPED[1], sql)
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(sql)
            self.assertEqual(db.execute("SELECT * FROM normal_short_links").fetchall(),
                             [(digest(EXTERNAL[0]), 12, BOT_ID, "123", None, None, None, EXTERNAL[1], CREATED_AT, None)])
            self.assertEqual(db.execute("SELECT * FROM legacy_subscription_short_links").fetchall(),
                             [(digest(TYPED[0]), BOT_ID, "123", 1, digest(TOKEN), "", CREATED_AT, None)])
            self.assertEqual(db.execute("SELECT id,owner_id,generation,node_count FROM subscriptions").fetchall(),
                             [(1, "123", 1, 1)])
            self.assertEqual(db.execute("SELECT id,owner_id,keyword,remark FROM path_rules").fetchall(),
                             [(3, "123", " hk ", " 合成 ")])
            self.assertEqual(db.execute("""SELECT position,name,sha256,mode,applied_at
                FROM subs_bot_schema_migrations ORDER BY position""").fetchall(),
                [(i, row["name"], row["sha256"], "applied", CREATED_AT) for i, row in enumerate(build["migrations"], 1)])
            for table in ("aggregate_links", "telegram_inbox", "telegram_short_link_actions"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(digest(self.source.read_bytes()), self.source_sha)

    def assert_candidate_refused(self):
        with self.assertRaises(package.PackageError) as raised:
            self.build_candidate()
        self.assertEqual(str(raised.exception), package.ERROR)
        self.assertFalse((self.candidate / package.MARKER).exists())
        self.assertEqual(digest(self.source.read_bytes()), self.source_sha)

    def test_v5_refuses_aggregate_even_when_external_redirect_is_equivalent(self):
        self.prepare_candidate([EXTERNAL, TYPED, AGGREGATE])
        self.assert_candidate_refused()

    def test_v5_refuses_a_verified_external_location_mismatch(self):
        self.prepare_candidate([DIFFERENT, TYPED])
        self.assertEqual([json.loads(line) for line in (self.output / oracle.ROWS).read_bytes().splitlines()],
                         [{"codeSha256": digest(DIFFERENT[0]), "state": "location-differs"}])
        self.assert_candidate_refused()


if __name__ == "__main__":
    unittest.main()

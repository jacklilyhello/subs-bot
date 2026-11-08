"""Hosted only. Compare the pinned legacy serializer with the emitted Workerd route."""

from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
from platform import python_version
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_short_namespace_inventory as mixed
import legacy_short_redirect_oracle as oracle

ORIGIN = "https://legacy-short.fixture.invalid"
TOKEN = "synthetic-redirect-fixture-token"
YARL = "1.20.0"


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
        self.cases = [
            ("Oracle_00001", "https://example.org/route?value=synthetic-secret&mode=exact#keep", "equivalent"),
            ("Oracle_00002", "https://example.org", "location-differs"),
            ("Oracle_00003", "https://example.org/" + "é" * 500, "worker-refused"),
            ("Oracle_00004", "http://127.0.0.1/synthetic-local-destination", "inventory-blocked"),
            ("Oracle_00005", f"{ORIGIN}/sub/{TOKEN}", None),
            ("Oracle_00006", "aggregate://all", None),
        ]
        with closing(sqlite3.connect(self.source)) as db, db:
            db.executescript("""
                CREATE TABLE subscriptions(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token TEXT NOT NULL UNIQUE);
                CREATE TABLE short_links(code TEXT PRIMARY KEY,user_id INTEGER NOT NULL,target_url TEXT NOT NULL,created_at INTEGER NOT NULL);
            """)
            db.execute("INSERT INTO subscriptions VALUES (1,123,?)", (TOKEN,))
            db.executemany("INSERT INTO short_links VALUES (?,123,?,1700000000)", [(code, target) for code, target, _ in self.cases])
        self.source.chmod(0o600)
        self.source_sha = digest(self.source.read_bytes())
        mixed.seal_inventory(self.source, self.inventory, source_sha256=self.source_sha, owner_map={}, owner_map_sha256=digest(b"{}"),
                             old_origin=ORIGIN, legacy_bot_id="78901")
        bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"]).resolve()
        manifest = (bundle / "isolation.json").read_bytes()
        revision = os.environ["WORKER_TEST_REVISION"]
        self.assertEqual(json.loads(manifest)["revision"], revision)
        self.settings = {"backup": str(self.source), "inventory": str(self.inventory), "output": str(self.output),
                         "sourceSha256": self.source_sha, "ownerMap": str(self.owner_map), "ownerMapSha256": digest(b"{}"),
                         "oldOrigin": ORIGIN, "legacyBotId": "78901", "inventorySha256": digest((self.inventory / mixed.MANIFEST).read_bytes()),
                         "bundle": str(bundle), "workerManifestSha256": digest(manifest),
                         "revision": revision, "yarlVersion": YARL, "pythonVersion": python_version()}

    def run_cli(self, **overrides):
        self.config.write_text(json.dumps(self.settings | overrides), encoding="utf-8")
        self.config.chmod(0o600)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            result = oracle.main([str(self.config)])
        return result, stdout.getvalue(), stderr.getvalue()

    def test_emitted_route_and_legacy_serialization_close_every_external_row(self):
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
        failure = (2, "", oracle.FAILURE + "\n")
        self.assertEqual(self.run_cli(yarlVersion="0.0.0"), failure)
        self.assertEqual(self.run_cli(pythonVersion="0.0.0"), failure)
        self.assertEqual(self.run_cli(workerManifestSha256="0" * 64), failure)
        path = self.inventory / mixed.ROWS
        body = path.read_bytes()
        path.write_bytes(b"X" + body[1:])
        self.assertEqual(self.run_cli(), failure)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

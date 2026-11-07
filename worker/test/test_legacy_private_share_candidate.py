"""Hosted-only synthetic coverage for the unbound legacy share candidate."""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import sqlite3
import stat
import sys
import unittest
from unittest.mock import patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import legacy_private_share_candidate as tool
import test_legacy_private_share_inventory as fixtures
import test_legacy_restore_package as package_fixtures


class LegacyPrivateShareCandidateTests(unittest.TestCase):
    def setUp(self):
        fixture = package_fixtures.LegacyRestorePackageTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.worker, self.worker_sha = fixture.root, fixture.worker, fixture.worker_sha
        self.inventory = self.root / "share-inventory"
        self.output = self.root / "share-candidate"

    def seal(self, shares=(), claims=(), *, inline=False, present=True):
        backup = self.root / "synthetic-shares.sqlite"
        with closing(sqlite3.connect(backup)) as db, db:
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            if present:
                db.execute(fixtures.SHARE_SCHEMA)
                db.execute(fixtures.CLAIM_SCHEMA)
                db.executemany("INSERT INTO shares VALUES (?,?,?,?,?,?,?,?,?)", shares)
                db.executemany("INSERT INTO share_claims VALUES (?,?,?,?)", claims)
                if inline:
                    db.execute("ALTER TABLE shares ADD COLUMN inline_message_id TEXT")
                    db.execute("UPDATE shares SET inline_message_id='fixture-inline-reference' WHERE code=?", (fixtures.code(1),))
        backup.chmod(0o600)
        self.source_sha = tool.native.digest(backup.read_bytes())
        tool.inventory.seal_inventory(backup, self.inventory, self.source_sha, fixtures.BOT_ID, fixtures.BOT_USERNAME)
        self.inventory_sha = tool.native.digest((self.inventory / tool.inventory.MANIFEST).read_bytes())
        return backup

    def build(self, output=None, **overrides):
        options = {"inventory_manifest_sha": self.inventory_sha, "worker_manifest_sha": self.worker_sha,
                   "source_sqlite_sha": self.source_sha, "legacy_bot_id": fixtures.BOT_ID, "legacy_bot_username": fixtures.BOT_USERNAME,
                   "revision": package_fixtures.REVISION, "applied_at": package_fixtures.APPLIED_AT, **overrides}
        return tool.build_candidate(self.inventory, self.worker, output or self.output, **options)

    def reseal(self, filename, body):
        (self.inventory / filename).write_bytes(body)
        manifest = self.inventory / tool.inventory.MANIFEST
        document = json.loads(manifest.read_bytes())
        for item in document["files"]:
            if item["file"] == filename:
                item.update(bytes=len(body), sha256=tool.native.digest(body))
        raw = tool.inventory._canonical_line(document)
        self.inventory_sha = tool.native.digest(raw)
        manifest.write_bytes(raw)
        (self.inventory / tool.inventory.SEAL).write_bytes(self.inventory_sha.encode("ascii") + b"\n")

    def test_exact_private_bytes_and_claim_history_are_replayed_without_other_domains(self):
        first, second = fixtures.code(1), fixtures.code(2)
        target = fixtures.MAX_ID - 1
        first_body = "\ufeff  合成私密正文\r\n\0  \n"
        second_body = "fixture-second-private\n"
        source = self.seal([
            fixtures.share(second, body=second_body, count=2),
            fixtures.share(first, target=target, body=first_body, count=1),
        ], [(13, second, 17, 20), (14, second, 22, 37), (fixtures.MAX_ID, first, target, 80)], inline=True)
        first_hash, second_hash = (tool.native.digest(value.encode("ascii")) for value in (first, second))
        report = self.build()
        self.assertEqual(report["profile"], "legacy-private-shares-v1")
        self.assertEqual(report["legacyDomains"], "private-shares-and-claims-only")
        self.assertEqual(report["shareCompatibility"], "not-validated")
        self.assertEqual(report["counts"], {"shares": 2, "claims": 3, "sourceInlineIdRows": 1})
        self.assertEqual((report["objectCount"], report["shareSequenceHighWater"]), (2, 2))
        sql = (self.output / tool.package.SQL).read_text(encoding="utf-8")
        raw_manifest = (self.output / tool.package.MANIFEST).read_bytes()
        manifest = json.loads(raw_manifest)
        self.assertEqual((self.output / tool.package.MARKER).read_bytes(), tool.native.digest(raw_manifest).encode("ascii") + b"\n")
        self.assertEqual(manifest["source"], {"sqliteSha256": self.source_sha, "inventoryManifestSha256": self.inventory_sha,
                                               "legacyBot": {"id": fixtures.BOT_ID, "username": fixtures.BOT_USERNAME}})
        self.assertEqual(tool.native.digest(source.read_bytes()), self.source_sha)
        for value in (first, second, "fixture-inline-reference", "合成私密正文", "fixture-second-private"):
            self.assertNotIn(value, sql)
            self.assertNotIn(value.encode("utf-8"), raw_manifest)
        actual_objects = {}
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone(), ("ok",))
            for table in ("subscriptions", "subscription_trash", "telegram_auth", "telegram_inbox", "telegram_outbox",
                          "telegram_private_share_creations", "legacy_empty_subscription_exports"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))
            ordered = db.execute("SELECT id,bot_id,code_sha256,sender_id,sender_name,payload_id,payload_bytes,max_claims,"
                                 "target_user_id,created_at,expire_at FROM private_shares ORDER BY id").fetchall()
            self.assertEqual([row[2] for row in ordered], sorted((first_hash, second_hash)))
            for share_id, bot, code, sender, name, payload_id, size, maximum, recipient, created, expiry in ordered:
                self.assertEqual((bot, sender, name, maximum, created, expiry),
                                 (fixtures.BOT_ID, str(fixtures.MAX_ID), "  合成发送者  ", 2, 20, 80))
                body, expected = (first_body, [(str(target), 80)]) if code == first_hash else (second_body, [("17", 20), ("22", 37)])
                self.assertEqual(recipient, str(target) if code == first_hash else None)
                self.assertEqual(db.execute("SELECT actor_id,claimed_at FROM private_share_claims WHERE share_id=? ORDER BY actor_id",
                                            (share_id,)).fetchall(), expected)
                key = f"private-shares/{payload_id}.txt"
                self.assertEqual((self.output / "objects" / key).read_bytes(), body.encode("utf-8"))
                self.assertEqual(size, len(body.encode("utf-8")))
                actual_objects[key] = tool.native.digest(body.encode("utf-8"))
            self.assertEqual(db.execute("SELECT name,seq FROM sqlite_sequence").fetchall(), [("private_shares", 2)])
        self.assertEqual({entry["key"]: entry["sha256"] for entry in manifest["objects"]}, actual_objects)
        self.assertTrue(all(entry["metadata"] == {"custom": {}, "http": {}} for entry in manifest["objects"]))
        self.assertEqual({path.relative_to(self.output).as_posix() for path in self.output.rglob("*") if path.is_file()},
                         {tool.package.MANIFEST, tool.package.MARKER, tool.package.SQL, *("objects/" + key for key in actual_objects)})
        second_output = self.root / "repeat-candidate"
        self.assertEqual(self.build(second_output), report)
        for path in [self.output, *self.output.rglob("*")]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
            if path.is_file():
                self.assertEqual(path.read_bytes(), (second_output / path.relative_to(self.output)).read_bytes())

    def test_rejects_wrong_independent_pins_and_altered_0005_without_output(self):
        self.seal([fixtures.share()])
        for overrides in ({"inventory_manifest_sha": "a" * 64}, {"source_sqlite_sha": "a" * 64},
                          {"legacy_bot_id": "46101"}, {"legacy_bot_username": "different_legacy_bot"},
                          {"worker_manifest_sha": "a" * 64}):
            with self.subTest(overrides=overrides), self.assertRaisesRegex(tool.CandidateError, "could not be built safely"):
                self.build(**overrides)
            self.assertFalse(self.output.exists())
        migration = self.worker / tool.MIGRATION
        changed = migration.read_bytes() + b"\n"
        migration.write_bytes(changed)
        artifact_manifest = self.worker / "isolation.json"
        worker_document = json.loads(artifact_manifest.read_bytes())
        worker_document["migrations"][4]["sha256"] = tool.native.digest(changed)
        raw = tool.native.canonical(worker_document)
        artifact_manifest.write_bytes(raw)
        with self.assertRaises(tool.CandidateError):
            self.build(worker_manifest_sha=tool.native.digest(raw))
        self.assertFalse(self.output.exists())

    def test_resealed_bad_offsets_and_claims_and_corrupt_payload_fail_closed(self):
        first = fixtures.code(1)
        self.seal([fixtures.share(target=17, count=1)], [(1, first, 17, 21)])
        packed = self.inventory / tool.inventory.PAYLOADS
        original = packed.read_bytes()
        packed.write_bytes(b"x" * len(original))
        with self.assertRaises(tool.CandidateError):
            self.build()
        packed.write_bytes(original)
        shares = (self.inventory / tool.inventory.SHARES).read_bytes()
        altered = json.loads(shares)
        altered["payload"]["offset"] = 1
        self.reseal(tool.inventory.SHARES, tool.inventory._canonical_line(altered))
        with self.assertRaises(tool.CandidateError):
            self.build()
        self.reseal(tool.inventory.SHARES, shares)
        claims = json.loads((self.inventory / tool.inventory.CLAIMS).read_bytes())
        self.reseal(tool.inventory.CLAIMS, tool.inventory._canonical_line({**claims, "userId": "18"}))
        with self.assertRaises(tool.CandidateError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_resealed_numeric_lookalikes_and_non_inventory_members_are_rejected(self):
        self.seal([fixtures.share()])
        shares = self.inventory / tool.inventory.SHARES
        original = json.loads(shares.read_bytes())
        for change in ({"senderId": fixtures.MAX_ID}, {"senderId": str(fixtures.MAX_ID + 1)}, {"maxViews": 2.0},
                       {"createdAt": True}, {"expireAt": tool.native.MAX_SAFE + 1},
                       {"payload": {**original["payload"], "offset": 0.0}}):
            with self.subTest(change=change):
                self.reseal(tool.inventory.SHARES, tool.inventory._canonical_line({**original, **change}))
                with self.assertRaises(tool.CandidateError):
                    self.build()
                self.assertFalse(self.output.exists())
        self.reseal(tool.inventory.SHARES, tool.inventory._canonical_line(original))
        (self.inventory / "foreign").mkdir(mode=0o700)
        with patch.object(tool.package, "worker_artifact") as worker, self.assertRaises(tool.CandidateError):
            self.build()
        worker.assert_not_called()

    def test_additive_index_cannot_execute_an_expression_on_imported_shares(self):
        self.seal([fixtures.share()])
        path = self.worker / "isolation.json"
        document = json.loads(path.read_bytes())
        name = f"{len(document['migrations']) + 1:04d}_synthetic_extra_index.sql"
        ddl = b"CREATE INDEX synthetic_extra_index ON private_shares (printf('%1000000000s',sender_name));\n"
        package_fixtures.put(self.worker / name, ddl)
        document["migrations"].append({"name": name, "sha256": tool.native.digest(ddl)})
        raw = tool.native.canonical(document)
        path.write_bytes(raw)
        with patch.object(tool, "load_shares") as load, self.assertRaises(tool.CandidateError):
            self.build(worker_manifest_sha=tool.native.digest(raw))
        load.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_interrupted_publish_releases_empty_destination_and_keeps_existing_output(self):
        self.seal([fixtures.share()])
        rename = Path.rename

        def interrupt(path, target):
            if target == self.output:
                self.assertTrue((path / tool.package.MARKER).is_file())
                self.assertEqual(list(self.output.iterdir()), [])
                raise KeyboardInterrupt
            return rename(path, target)

        with patch.object(Path, "rename", interrupt), self.assertRaises(KeyboardInterrupt):
            self.build()
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".share-candidate-*")), [])
        self.output.mkdir(mode=0o700)
        prior = self.output / "existing"
        prior.write_bytes(b"unchanged")
        with self.assertRaises(tool.CandidateError):
            self.build()
        self.assertEqual(prior.read_bytes(), b"unchanged")

    def test_empty_inventory_is_an_explicit_candidate_with_no_objects(self):
        self.seal(present=False)
        report = self.build()
        self.assertEqual(report["counts"], {"shares": 0, "claims": 0, "sourceInlineIdRows": 0})
        self.assertEqual({path.name for path in self.output.iterdir()}, {tool.package.MANIFEST, tool.package.MARKER, tool.package.SQL})
        self.assertEqual(report["shareSequenceHighWater"], 0)

    def test_sender_nul_is_unrepresentable_and_cli_error_is_redacted(self):
        source_row = list(fixtures.share())
        source_row[2] = "fixture-private-name\0"
        self.seal([source_row])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = tool.main([str(self.inventory), str(self.worker), str(self.output), self.inventory_sha,
                                self.worker_sha, package_fixtures.REVISION, str(package_fixtures.APPLIED_AT), self.source_sha,
                                fixtures.BOT_ID, fixtures.BOT_USERNAME])
        self.assertEqual((status, stdout.getvalue(), stderr.getvalue()), (2, "", tool.ERROR + "\n"))
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

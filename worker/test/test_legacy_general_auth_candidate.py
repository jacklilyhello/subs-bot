"""Hosted synthetic checks for the dormant general authorization package."""

from contextlib import closing, redirect_stderr, redirect_stdout
import io
import json
import sqlite3
import stat
import unittest

import test_legacy_authorization_reconcile as auth_fixtures
import test_legacy_restore_package as worker_fixtures
import legacy_general_auth_candidate as tool


class LegacyGeneralAuthorizationCandidateTests(unittest.TestCase):
    def setUp(self):
        self.legacy = auth_fixtures.LegacyAuthorizationReconcileTests()
        self.legacy.setUp()
        self.addCleanup(self.legacy.doCleanups)
        self.artifact = worker_fixtures.LegacyRestorePackageTests()
        self.artifact.setUp()
        self.addCleanup(self.artifact.doCleanups)
        self.output = self.legacy.root / "candidate"
        self.legacy.make_source(((101, 0, 10, 20), (102, 0, 12, 25), (103, 1, 15, 30)))

    def preview(self, *, allowlist=("102", "104"), target_bot="105", name="preview"):
        self.legacy.output = self.legacy.root / name
        self.legacy.write_config(list(allowlist), ["101", "106"])
        self.legacy.write_general_target(["-100200", "-100100"], botId=target_bot)
        self.assertEqual(self.legacy.run_cli(general=True), (0, auth_fixtures.tool.GENERAL_SUCCESS + "\n", ""))
        self.preview_sha = tool.native.digest((self.legacy.output / tool.inventory.MANIFEST).read_bytes())

    def arguments(self, output):
        return (self.legacy.backup, self.legacy.inventory, self.legacy.config, self.legacy.target, self.legacy.output,
                self.artifact.worker, output)

    def pins(self):
        return {"source_sha256": self.legacy.source_sha, "inventory_sha256": self.legacy.inventory_sha,
                "config_sha256": self.legacy.config_sha, "target_sha256": self.legacy.target_sha, "preview_sha256": self.preview_sha,
                "worker_manifest_sha256": self.artifact.worker_sha, "revision": worker_fixtures.REVISION,
                "applied_at": worker_fixtures.APPLIED_AT}

    def build(self, **overrides):
        return tool.build_candidate(*self.arguments(self.output), **(self.pins() | overrides))

    def assert_refused(self, **overrides):
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self.build(**overrides)
        self.assertFalse(self.output.exists())

    def test_sealed_closed_candidate_replays_original_overrides_and_no_runtime_state(self):
        self.preview()
        report = self.build()
        self.assertEqual((report["profile"], report["scope"], report["objectCount"]),
                         ("legacy-general-auth-v1", "fresh-unbound-d1", 0))
        self.assertIs(report["activationAllowed"], False)
        self.assertEqual(report["counts"], {"installations": 1, "principals": 5, "groups": 2, "overrides": 3})
        self.assertEqual(report["source"]["previewManifestSha256"], self.preview_sha)
        self.assertEqual(report["source"]["sourceSha256"], self.legacy.source_sha)
        self.assertEqual({entry.name for entry in self.output.iterdir()}, {"manifest.json", "manifest.sha256", "restore.sql"})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for entry in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)
        raw = (self.output / "manifest.json").read_bytes()
        manifest = json.loads(raw)
        self.assertEqual((self.output / "manifest.sha256").read_text(), tool.native.digest(raw) + "\n")
        self.assertEqual(manifest["summary"]["rowCount"], len(self.artifact.chain) + 8)
        sql = (self.output / "restore.sql").read_bytes()
        self.assertEqual((len(sql), tool.native.digest(sql)), (manifest["sql"]["bytes"], manifest["sql"]["sha256"]))
        self.assertEqual(manifest["candidateSchemaSha256"], tool.native._schema_digest(tool.SCHEMA))
        chain, _ = tool.package.worker_artifact(self.artifact.worker, worker_fixtures.REVISION, self.artifact.worker_sha)
        self.assertFalse(set(tool.COLUMNS) & {obj.name for obj in tool.migrations._objects(chain, len(chain), managed=True)})
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql.decode("utf-8"))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.execute(f"SELECT * FROM {tool.PRINCIPALS} ORDER BY user_id").fetchall(), [
                ("105", "101", 1, 0, 0, 10, 20),
                ("105", "102", 0, 1, 0, 12, 25),
                ("105", "103", 0, 0, 1, 15, 30),
                ("105", "104", 0, 1, None, None, None),
                ("105", "106", 1, 0, None, None, None),
            ])
            self.assertEqual(db.execute(f"SELECT * FROM {tool.GROUPS} ORDER BY chat_id DESC").fetchall(),
                             [("105", "-100100"), ("105", "-100200")])
            self.assertEqual(db.execute(f"SELECT admin_mode,unlisted_default FROM {tool.INSTALLATION}").fetchall(),
                             [("explicit", "denied")])
            for table in ("telegram_auth", "telegram_inbox", "telegram_outbox"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))
            self.assertEqual(db.execute(f"SELECT position,name,sha256 FROM {tool.migrations.LEDGER} ORDER BY position").fetchall(),
                             [(index, entry["name"], entry["sha256"]) for index, entry in enumerate(self.artifact.chain, 1)])
            self.assertEqual(tool.package.db_summary(db, manifest["layout"]), manifest["summary"])
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute(f"UPDATE {tool.INSTALLATION} SET unlisted_default='public'")

        second = self.legacy.root / "second-candidate"
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = tool.main([*map(str, self.arguments(second)), *map(str, self.pins().values())])
        self.assertEqual((status, stdout.getvalue(), stderr.getvalue()), (0, tool.SUCCESS + "\n", ""))
        for entry in self.output.iterdir():
            self.assertEqual(entry.read_bytes(), (second / entry.name).read_bytes())

    def test_rejects_public_default_different_bot_and_wrong_worker_pin(self):
        self.preview(allowlist=(), name="public")
        self.assert_refused()
        self.preview(target_bot="107", name="different-bot")
        self.assert_refused()
        self.preview(name="closed")
        self.assert_refused(worker_manifest_sha256="0" * 64)

    def test_rejects_resealed_override_substitution_and_extra_preview_file(self):
        self.preview()
        extra = self.legacy.output / "extra"
        extra.touch()
        self.assert_refused()
        extra.unlink()
        rows_path = self.legacy.output / tool.inventory.SIDECAR
        changed = rows_path.read_bytes().replace(b'"allowed":0', b'"allowed":1', 1)
        rows_path.write_bytes(changed)
        manifest = self.legacy.output / tool.inventory.MANIFEST
        report = json.loads(manifest.read_bytes())
        for item in report["files"]:
            if item["file"] == tool.inventory.SIDECAR:
                item.update(bytes=len(changed), sha256=tool.native.digest(changed))
        self.preview_sha = self.legacy.write_document(manifest, report)
        (self.legacy.output / tool.inventory.SEAL).write_text(self.preview_sha + "\n")
        self.assert_refused()

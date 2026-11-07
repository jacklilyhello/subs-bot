"""Hosted package tests for the fixed 0029 typed legacy short namespace."""

from contextlib import closing, redirect_stderr, redirect_stdout
from dataclasses import replace
import io
import json
import sqlite3
import unittest

import test_legacy_restore_package as existing
from test_legacy_snapshot_convert import make_path_table, make_table, insert


package = existing.package
inventory = package.typed_inventory
ORIGIN = "https://legacy-links.example.invalid"
BOT_ID = "9000000000000199"
LINKS = (
    ("TypedAct0001", 123, existing.TOKEN, "", 2),
    ("TypedEmp0002", 123, existing.EMPTY_TOKEN, "sing-box", 5),
    ("TypedRec0003", -100123, existing.TRASH_TOKEN, "v2ray", 71),
    ("TypedTmp0004", -100123, existing.EMPTY_TRASH_TOKEN, "qx", 72),
)


class LegacyTypedShortCandidateTests(unittest.TestCase):
    def setUp(self):
        self.fixture = existing.LegacyRestorePackageTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.sidecar = self.fixture.root / "typed-shorts"

    def capture(self, *, other_domain=False):
        source = self.fixture.legacy
        with closing(sqlite3.connect(source)) as db, db:
            # The old active token is implicitly UNIQUE, as required by inventory.
            db.execute("""CREATE TABLE subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,
                name TEXT NOT NULL DEFAULT 'synthetic',url TEXT NOT NULL DEFAULT 'https://source.example.invalid/item',
                token TEXT NOT NULL UNIQUE,expire_at INTEGER,traffic_used REAL,traffic_total REAL,
                nodes_json TEXT NOT NULL DEFAULT '[]',node_count INTEGER NOT NULL DEFAULT 0,last_error TEXT,
                created_at INTEGER NOT NULL DEFAULT 1700000000,updated_at INTEGER NOT NULL DEFAULT 1700001000)""")
            make_table(db, "deleted_subs")
            insert(db, row_id=2)
            insert(db, row_id=5, nodes=[], token=existing.EMPTY_TOKEN)
            insert(db, table="deleted_subs", row_id=2, owner=-100123, token=existing.TRASH_TOKEN)
            insert(db, table="deleted_subs", row_id=4, owner=-100123, nodes=[], token=existing.EMPTY_TRASH_TOKEN)
            db.execute("UPDATE sqlite_sequence SET seq=70 WHERE name='deleted_subs'")
            make_path_table(db)
            db.execute("INSERT INTO path_maps VALUES (5,-100123,' hk ',' 合成 ')")
            db.execute("UPDATE sqlite_sequence SET seq=80 WHERE name='path_maps'")
            db.execute("""CREATE TABLE short_links (
                code TEXT PRIMARY KEY,user_id INTEGER NOT NULL,target_url TEXT NOT NULL,created_at INTEGER NOT NULL)""")
            for code, owner, token, format_name, _ in LINKS:
                destination = f"{ORIGIN}/sub/{token}" + (f"/{format_name}" if format_name else "")
                db.execute("INSERT INTO short_links VALUES (?,?,?,?)", (code, owner, destination, existing.APPLIED_AT))
            if other_domain:
                db.execute("CREATE TABLE auth_overrides(user_id INTEGER PRIMARY KEY,allowed INTEGER,created_at INTEGER,updated_at INTEGER)")
                db.execute("INSERT INTO auth_overrides VALUES (123,1,1700000000,1700000000)")
        source.chmod(0o600)
        report = existing.convert.convert_backup(source, self.fixture.conversion, owner_map=existing.OWNER_MAP)
        self.fixture.convert_sha = existing.digest((self.fixture.conversion / "manifest.json").read_bytes())
        self.source_sha = existing.digest(source.read_bytes())
        self.owner_sha = existing.digest(existing.body(existing.OWNER_MAP))
        inventory.seal_inventory(source, self.sidecar, source_sha256=self.source_sha, owner_map=existing.OWNER_MAP,
                                 owner_map_sha256=self.owner_sha, old_origin=ORIGIN, legacy_bot_id=BOT_ID)
        self.pins = package.TypedShortInput(self.sidecar, existing.digest((self.sidecar / inventory.MANIFEST).read_bytes()),
                                           existing.digest(ORIGIN.encode("ascii")), BOT_ID)
        return report

    def build(self, **overrides):
        return self.fixture.build(**({"profile": package.TYPED_SHORT_PROFILE, "source_sqlite_sha": self.source_sha,
                                      "owner_map_sha": self.owner_sha, "typed_short": self.pins} | overrides))

    def reseal_short_row(self, **fields):
        rows = [json.loads(line) for line in (self.sidecar / inventory.ROWS).read_bytes().splitlines()]
        rows[0].update(fields)
        return self.reseal_short_rows(rows)

    def reseal_short_rows(self, rows):
        path = self.sidecar / inventory.ROWS
        raw = b"".join(existing.body(row) + b"\n" for row in rows)
        path.write_bytes(raw)
        manifest_path = self.sidecar / inventory.MANIFEST
        manifest = json.loads(manifest_path.read_bytes())
        manifest["inventory"]["rows"] = len(rows)
        manifest["files"][0].update(bytes=len(raw), sha256=existing.digest(raw))
        sealed = existing.body(manifest) + b"\n"
        manifest_path.write_bytes(sealed)
        manifest_sha = existing.digest(sealed)
        (self.sidecar / inventory.SEAL).write_bytes(manifest_sha.encode("ascii") + b"\n")
        return replace(self.pins, manifest_sha256=manifest_sha)

    def test_v4_replays_active_trash_aliases_and_v3_empty_exports_without_plaintext_short_links(self):
        self.assertEqual(self.capture()["blockers"], {"unhandled:short_links": 4})
        for pins in ({}, self.fixture.v3_pins()):
            with self.assertRaises(package.PackageError):
                self.fixture.build(**pins)
            self.assertFalse(self.fixture.output.exists())
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            rc = package.main([str(self.fixture.conversion), str(self.fixture.worker), str(self.fixture.output),
                               self.fixture.convert_sha, self.fixture.worker_sha, existing.REVISION, str(existing.APPLIED_AT),
                               package.TYPED_SHORT_PROFILE, self.source_sha, self.owner_sha, str(self.sidecar),
                               self.pins.manifest_sha256, self.pins.old_origin_sha256, BOT_ID])
        self.assertEqual((rc, errors.getvalue()), (0, ""))
        report = json.loads(output.getvalue())
        self.assertEqual(report["version"], 4)
        self.assertEqual({key: report["typedShortLinks"][key] for key in ("rows", "activeRows", "trashRows")},
                         {"rows": 4, "activeRows": 2, "trashRows": 2})
        self.assertEqual(report["typedShortLinks"]["migrationSha256"], package.TYPED_SHORT_MIGRATION_SHA256)
        self.assertEqual(report["shortLinkCompatibility"], "not-validated")
        manifest = json.loads((self.fixture.output / package.MANIFEST).read_bytes())
        self.assertEqual(manifest["source"]["typedShortInventoryManifestSha256"], self.pins.manifest_sha256)
        self.assertEqual(manifest["summary"]["tableSha256"][package.TYPED_SHORTS], report["typedShortLinks"]["tableSha256"])
        sql = (self.fixture.output / package.SQL).read_text(encoding="utf-8")
        self.assertNotIn(BOT_ID, output.getvalue())
        for code, _, _, _, _ in LINKS:
            self.assertNotIn(code, sql)
            self.assertNotIn(code, output.getvalue())
        self.assertNotIn(ORIGIN, sql)
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(sql)
            expected = sorted((existing.digest(code.encode("ascii")), BOT_ID, "123" if owner > 0 else "456", target,
                               existing.digest(token.encode("ascii")), format_name, existing.APPLIED_AT, None)
                              for code, owner, token, format_name, target in LINKS)
            self.assertEqual(db.execute(f"SELECT * FROM {package.TYPED_SHORTS} ORDER BY code_sha256").fetchall(), expected)
            self.assertEqual(db.execute(f"SELECT subscription_id FROM {package.EMPTY_EXPORTS} ORDER BY subscription_id").fetchall(),
                             [(5,), (72,)])
            self.assertEqual(db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name").fetchall(),
                             [("path_rules", 80), ("subscriptions", 72)])
            self.assertEqual(db.execute("SELECT owner_id,keyword,remark FROM path_rules").fetchall(), [("456", " hk ", " 合成 ")])
            for table in ("telegram_inbox", "telegram_outbox", "normal_short_links", "aggregate_links"):
                self.assertEqual(db.execute(f"SELECT count(*) FROM {table}").fetchone(), (0,))
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_v4_refuses_independently_resealed_wrong_owner_or_token_and_leaves_no_seal(self):
        self.capture()
        original = {name: (self.sidecar / name).read_bytes() for name in (inventory.MANIFEST, inventory.SEAL, inventory.ROWS)}
        for i, bad_row in enumerate(({"ownerId": "9009"}, {"tokenSha256": "0" * 64}, {"legacyId": 70})):
            with self.subTest(fields=bad_row):
                self.fixture.output = self.fixture.root / f"rejected-{i}"
                with self.assertRaises(package.PackageError):
                    self.build(typed_short=self.reseal_short_row(**bad_row))
                self.assertFalse((self.fixture.output / package.MARKER).exists())
                for name, data in original.items():
                    (self.sidecar / name).write_bytes(data)

    def test_v4_refuses_other_domains_and_wrong_independent_source_pins(self):
        self.assertEqual(self.capture(other_domain=True)["blockers"], {"unhandled:short_links": 4, "unhandled:auth_overrides": 1})
        for overrides in ({}, {"source_sqlite_sha": "1" * 64}, {"owner_map_sha": "2" * 64},
                          {"typed_short": replace(self.pins, old_origin_sha256="3" * 64)},
                          {"typed_short": replace(self.pins, legacy_bot_id="456")}):
            with self.assertRaises(package.PackageError):
                self.build(**overrides)
            self.assertFalse(self.fixture.output.exists())

    def test_v4_refuses_a_resealed_inventory_missing_a_source_row(self):
        self.capture()
        rows = [json.loads(line) for line in (self.sidecar / inventory.ROWS).read_bytes().splitlines()]
        with self.assertRaises(package.PackageError):
            self.build(typed_short=self.reseal_short_rows(rows[:-1]))
        self.assertFalse(self.fixture.output.exists())

    def test_v4_refuses_a_resealed_worker_manifest_with_altered_0029(self):
        self.capture()
        manifest_path = self.fixture.worker / "isolation.json"
        manifest = json.loads(manifest_path.read_bytes())
        migration_path = self.fixture.worker / package.TYPED_SHORT_MIGRATION
        changed = migration_path.read_bytes() + b"\n"
        migration_path.write_bytes(changed)
        manifest["migrations"][28]["sha256"] = existing.digest(changed)
        raw = existing.body(manifest)
        manifest_path.write_bytes(raw)
        self.fixture.worker_sha = existing.digest(raw)
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.fixture.output.exists())

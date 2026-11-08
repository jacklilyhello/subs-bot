"""Hosted fixtures for sealed typed legacy subscription short links."""

from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_typed_short_inventory as tool


ORIGIN = "https://old-bot.example.invalid"
ACTIVE = "synthetic-active-capability"
TRASH = "synthetic-deleted-capability"
BOT = "9223372036854775807"
OWNERS = {"-10020": "123", "-10010": "123"}
WHEN = 1700000000
SHORT = "Fixture_0001"


def owner_pin(owners):
    canonical = json.dumps(owners, sort_keys=True, separators=(",", ":")).encode("ascii")
    return sha256(canonical).hexdigest()


class TypedShortInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.backup = self.root / "synthetic backup?#.sqlite"
        self.output = self.root / "inventory"
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.executescript("""
                CREATE TABLE subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    token TEXT NOT NULL UNIQUE, nodes_json TEXT NOT NULL DEFAULT '[]'
                );
                CREATE TABLE deleted_subs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
                    token TEXT NOT NULL
                );
                CREATE TABLE short_links (
                    code TEXT PRIMARY KEY, user_id INTEGER NOT NULL,
                    target_url TEXT NOT NULL, created_at INTEGER NOT NULL
                );
            """)
            db.execute("INSERT INTO subscriptions (id,user_id,token,nodes_json) VALUES (2,123,?,CAST(X'ff' AS TEXT))", (ACTIVE,))
            db.execute("INSERT INTO deleted_subs VALUES (2,-10010,?)", (TRASH,))
        self.backup.chmod(0o600)

    def execute(self, statement, values=()):
        with closing(sqlite3.connect(self.backup)) as db, db:
            db.execute(statement, values)

    def add(self, target=None, *, code=SHORT, owner=123, created=WHEN):
        self.execute("INSERT INTO short_links VALUES (?,?,?,?)",
                     (code, owner, f"{ORIGIN}/sub/{ACTIVE}" if target is None else target, created))

    def arguments(self):
        return {"source_sha256": sha256(self.backup.read_bytes()).hexdigest(), "owner_map": OWNERS,
                "owner_map_sha256": owner_pin(OWNERS), "old_origin": ORIGIN, "legacy_bot_id": BOT}

    def seal(self, **options):
        tool.seal_inventory(self.backup, self.output, **(self.arguments() | options))

    def reject(self, **options):
        with self.assertRaisesRegex(tool.InventoryError, r"^Legacy typed short inventory could not be confirmed safely\.$"):
            self.seal(**options)
        self.assertFalse(self.output.exists())

    def test_exact_format_aliases_and_original_active_trash_lineage(self):
        formats = ("", "clash", "base64", "v2ray", "mixed", "singbox", "sing-box", "surge", "qx", "quantumult", "quantumultx")
        expected = {}
        for index, alias in enumerate(formats, 1):
            code = f"Fixture_{index:04d}"
            in_trash = index % 2 == 0
            token = TRASH if in_trash else ACTIVE
            self.add(f"{ORIGIN}/sub/{token}" + (f"/{alias}" if alias else ""),
                     code=code, owner=-10010 if in_trash else 123, created=WHEN + index)
            digest = sha256(code.encode()).hexdigest()
            expected[digest] = {"codeSha256": digest, "legacyTable": "deleted_subs" if in_trash else "subscriptions",
                                "legacyId": 2, "ownerId": "123", "tokenSha256": sha256(token.encode()).hexdigest(),
                                "format": alias, "createdAt": WHEN + index}
        before = self.backup.read_bytes()
        self.seal()
        self.assertEqual(self.backup.read_bytes(), before)
        self.assertEqual({path.name for path in self.output.iterdir()}, {tool.ROWS, tool.MANIFEST, tool.SEAL})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        manifest = (self.output / tool.MANIFEST).read_bytes()
        rows = (self.output / tool.ROWS).read_bytes()
        self.assertEqual([json.loads(line) for line in rows.splitlines()], [expected[key] for key in sorted(expected)])
        self.assertEqual(json.loads(manifest), {
            "version": 1, "kind": "legacy-typed-subscription-short-inventory",
            "sourceSha256": sha256(before).hexdigest(), "ownerMapSha256": owner_pin(OWNERS),
            "oldOriginSha256": sha256(ORIGIN.encode()).hexdigest(), "legacyBotId": BOT,
            "inventory": {"present": True, "rows": len(formats)},
            "files": [{"file": tool.ROWS, "bytes": len(rows), "sha256": sha256(rows).hexdigest()}],
        })
        self.assertEqual((self.output / tool.SEAL).read_bytes(), sha256(manifest).hexdigest().encode() + b"\n")
        for secret in (ORIGIN, ACTIVE, TRASH, SHORT):
            self.assertNotIn(secret.encode(), manifest + rows)

    def test_blocks_untyped_or_ambiguous_destinations(self):
        bad = (
            "aggregate://all", "aggregate://ids/2,4", "https://external.example.invalid/page",
            f"{ORIGIN}/s/{SHORT}", f"{ORIGIN}/agg/{SHORT}/clash", f"{ORIGIN}/sub/{ACTIVE}/unknown",
            f"{ORIGIN}/sub/{ACTIVE}/Base64", f"{ORIGIN}/sub/{ACTIVE}/", f"{ORIGIN}/sub/{ACTIVE}?x=1",
            f"{ORIGIN}/sub/{ACTIVE}#fragment", f"{ORIGIN}/sub/%73{ACTIVE[1:]}",
            f"{ORIGIN}/sub/{ACTIVE}/base64\n", f"{ORIGIN}/sub/{ACTIVE}\0", f"{ORIGIN}/sub/{ACTIVE.upper()}",
            f"{ORIGIN}.wrong/sub/{ACTIVE}", f"{ORIGIN}:443/sub/{ACTIVE}", f"{ORIGIN}/sub/synthetic-missing-capability",
            f"{ORIGIN}/sub\\{ACTIVE}", sqlite3.Binary(f"{ORIGIN}/sub/{ACTIVE}".encode()),
        )
        for target in bad:
            with self.subTest(target=target):
                self.execute("DELETE FROM short_links")
                self.add(target)
                self.reject()

    def test_owner_checks_precede_remapping_and_token_lookup_is_unique(self):
        self.add(f"{ORIGIN}/sub/{TRASH}/clash", owner=-10020)
        self.reject()
        self.execute("UPDATE short_links SET user_id=-10010")
        self.reject(owner_map={}, owner_map_sha256=owner_pin({}))
        self.execute("INSERT INTO subscriptions (id,user_id,token) VALUES (9,-10010,?)", (TRASH,))
        self.reject()

    def test_invalid_source_types_and_nonbinary_code_namespace(self):
        for code, created in ((sqlite3.Binary(SHORT.encode()), WHEN), (SHORT + "x", WHEN),
                              (SHORT, 0), (SHORT, 1.25), (SHORT, 2**53)):
            with self.subTest(code=code, created=created):
                self.execute("DELETE FROM short_links")
                self.add(code=code, created=created)
                self.reject()
        self.execute("DROP TABLE short_links")
        self.execute("""CREATE TABLE short_links (
            code TEXT PRIMARY KEY COLLATE NOCASE, user_id INTEGER NOT NULL,
            target_url TEXT NOT NULL, created_at INTEGER NOT NULL
        )""")
        self.add()
        self.reject()

    def test_nonbinary_token_namespace_cannot_shadow_a_deleted_subscription(self):
        self.execute("DROP TABLE subscriptions")
        self.execute("""CREATE TABLE subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
            token TEXT NOT NULL COLLATE NOCASE, UNIQUE(token COLLATE BINARY)
        )""")
        self.execute("INSERT INTO subscriptions VALUES (9,123,?)", (TRASH.upper(),))
        self.add(f"{ORIGIN}/sub/{TRASH}", owner=-10010)
        self.reject()

    def test_bounds_and_failure_after_creating_private_output(self):
        self.add()
        with patch.object(tool, "MAX_SHORTS", 0):
            self.reject()
        with patch.object(tool, "MAX_SUBSCRIPTIONS", 1):
            self.reject()
        with patch.object(tool, "MAX_SOURCE_BYTES", 20):
            self.reject()
        with patch.object(tool, "MAX_METADATA_BYTES", 1):
            self.reject()
        sync = os.fsync
        sync_count = 0

        def fail_final_sync(fd):
            nonlocal sync_count
            sync_count += 1
            if sync_count == 3:
                raise OSError("synthetic final seal failure")
            sync(fd)

        with patch.object(tool.os, "fsync", side_effect=fail_final_sync):
            self.reject()

    def test_independent_pins_canonical_origin_and_sealed_source(self):
        self.add()
        self.reject(source_sha256="1" * 64)
        self.reject(owner_map_sha256="2" * 64)
        self.reject(legacy_bot_id="092")
        for origin in (ORIGIN + "/", ORIGIN + ":443", ORIGIN.upper(), "https://127.0.0.1", "http://old.example.invalid",
                       "https://test@old.example.invalid", ORIGIN + "\t"):
            self.reject(old_origin=origin)
        sidecar = Path(str(self.backup) + "-wal")
        sidecar.touch()
        self.reject()
        sidecar.unlink()
        self.backup.chmod(0o644)
        self.reject()
        self.backup.chmod(0o600)
        (self.root / "another-name").hardlink_to(self.backup)
        self.reject()

    def test_changed_source_cannot_publish_captured_rows(self):
        self.add()
        capture = tool._capture

        def change_after_capture(*args):
            captured = capture(*args)
            self.execute("UPDATE short_links SET created_at=created_at+1")
            return captured

        with patch.object(tool, "_capture", side_effect=change_after_capture):
            self.reject()

    def test_empty_source_domain_and_no_overwrite(self):
        self.execute("DROP TABLE short_links")
        self.seal()
        self.assertEqual((self.output / tool.ROWS).read_bytes(), b"")
        self.assertEqual(json.loads((self.output / tool.MANIFEST).read_bytes())["inventory"], {"present": False, "rows": 0})
        before = (self.output / tool.SEAL).read_bytes()
        with self.assertRaises(tool.InventoryError):
            self.seal()
        self.assertEqual((self.output / tool.SEAL).read_bytes(), before)

    def test_cli_accepts_the_owner_map_file_without_printing_inputs(self):
        self.add()
        owner_map = self.root / "synthetic-map.json"
        owner_map.write_text(json.dumps(OWNERS, indent=2), encoding="utf-8")
        args = [str(self.backup), str(self.output), self.arguments()["source_sha256"], str(owner_map),
                owner_pin(OWNERS), ORIGIN, BOT]
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(tool.main(args), 0)
            self.assertEqual(tool.main(args), 2)
        self.assertEqual(stdout.getvalue(), "Legacy typed short inventory sealed.\n")
        self.assertEqual(stderr.getvalue(), tool.FAILURE + "\n")

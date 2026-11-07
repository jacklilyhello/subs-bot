"""Synthetic hosted coverage for sealed, unapplied legacy authorization evidence."""

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
import legacy_authorization_inventory as tool


SCHEMA = """CREATE TABLE auth_overrides (
    user_id INTEGER PRIMARY KEY, allowed INTEGER NOT NULL,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
)"""
FIXTURE_ID = 9_223_372_036_854_775_807


class LegacyAuthorizationInventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.backup = self.root / "synthetic-private?#.sqlite"
        self.output = self.root / "private-inventory"

    def make_backup(self, rows=(), schema=SCHEMA, filename=None, encoding="UTF-8"):
        path = self.backup if filename is None else self.root / filename
        with closing(sqlite3.connect(path)) as db, db:
            if encoding == "UTF-16le":
                db.execute("PRAGMA encoding = 'UTF-16le'")
            db.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO meta VALUES ('fixture', 'unrelated-private-sentinel')")
            if schema is not None:
                db.execute(schema)
                db.executemany("INSERT INTO auth_overrides VALUES (?, ?, ?, ?)", rows)
        path.chmod(0o600)
        return path, sha256(path.read_bytes()).hexdigest()

    def run_cli(self, backup, digest, output=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = tool.main([str(backup), str(output or self.output), digest])
        return status, stdout.getvalue(), stderr.getvalue()

    def assert_rejected(self, backup, digest):
        self.assertEqual(self.run_cli(backup, digest), (2, "", tool.FAILURE + "\n"))
        self.assertFalse(self.output.exists())

    def test_canonical_full_int64_rows_digest_and_private_permissions(self):
        backup, digest = self.make_backup(((FIXTURE_ID, 1, 100, tool.MAX_TIMESTAMP), (10, 0, 5, 5), (2, 1, 1, 3)))
        original = backup.read_bytes()
        with patch.object(tool, "_fingerprint", wraps=tool._fingerprint) as fingerprint:
            self.assertEqual(self.run_cli(backup, digest), (0, tool.SUCCESS + "\n", ""))
        self.assertEqual(fingerprint.call_count, 2)
        self.assertEqual(fingerprint.call_args_list[0], fingerprint.call_args_list[1])
        self.assertEqual(backup.read_bytes(), original)
        self.assertEqual({entry.name for entry in self.root.iterdir()}, {backup.name, self.output.name})
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual({entry.name for entry in self.output.iterdir()}, {tool.SIDECAR, tool.MANIFEST, tool.SEAL})
        for entry in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), 0o600)

        rows = (self.output / tool.SIDECAR).read_bytes()
        self.assertEqual(rows, (
            b'{"allowed":1,"createdAt":1,"updatedAt":3,"userId":"2"}\n'
            b'{"allowed":0,"createdAt":5,"updatedAt":5,"userId":"10"}\n'
            b'{"allowed":1,"createdAt":100,"updatedAt":9007199254740991,"userId":"9223372036854775807"}\n'
        ))
        manifest = (self.output / tool.MANIFEST).read_bytes()
        self.assertEqual(json.loads(manifest), {
            "version": 1, "kind": "legacy-authorization-inventory", "sourceSha256": digest,
            "authOverrides": {"present": True, "rows": 3, "allowedRows": 2, "deniedRows": 1,
                              "file": tool.SIDECAR, "bytes": len(rows), "sha256": sha256(rows).hexdigest()},
        })
        self.assertEqual((self.output / tool.SEAL).read_bytes(), sha256(manifest).hexdigest().encode("ascii") + b"\n")
        rerun = self.root / "another-private-inventory"
        self.assertEqual(self.run_cli(backup, digest, rerun), (0, tool.SUCCESS + "\n", ""))
        for entry in rerun.iterdir():
            self.assertEqual(entry.read_bytes(), (self.output / entry.name).read_bytes())

    def test_distinguishes_absent_and_empty_table(self):
        for present in (False, True):
            with self.subTest(present=present):
                backup, digest = self.make_backup(schema=SCHEMA if present else None, filename=f"empty-{present}.db")
                output = self.root / f"empty-{present}"
                self.assertEqual(self.run_cli(backup, digest, output), (0, tool.SUCCESS + "\n", ""))
                self.assertEqual((output / tool.SIDECAR).read_bytes(), b"")
                self.assertEqual(json.loads((output / tool.MANIFEST).read_bytes())["authOverrides"], {
                    "present": present, "rows": 0, "allowedRows": 0, "deniedRows": 0, "file": tool.SIDECAR,
                    "bytes": 0, "sha256": sha256(b"").hexdigest(),
                })

    def test_rejects_invalid_identity_flag_time_and_row_limit_without_seal(self):
        invalid = ((0, 1, 1, 1), (-1, 0, 1, 1), (1, 2, 1, 1), (1, -1, 1, 1), (1, 0.5, 1, 1),
                   (1, b"private-invalid-flag", 1, 1), (1, 1, 0, 1), (1, 1, 2, 1), (1, 1, 1, "private-time"),
                   (1, 1, 1, tool.MAX_TIMESTAMP + 1))
        for index, row in enumerate(invalid):
            with self.subTest(case=index):
                self.assert_rejected(*self.make_backup((row,), filename=f"invalid-{index}.db"))
        duplicate = SCHEMA.replace("INTEGER PRIMARY KEY", "INTEGER")
        self.assert_rejected(*self.make_backup(((7, 0, 1, 1), (7, 1, 2, 2)), schema=duplicate, filename="duplicate.db"))
        nullable = SCHEMA.replace("allowed INTEGER NOT NULL", "allowed INTEGER")
        self.assert_rejected(*self.make_backup(((7, None, 1, 1),), schema=nullable, filename="nullable.db"))
        with patch.object(tool, "MAX_ROWS", 2):
            rows = ((1, 0, 1, 1), (2, 1, 1, 1), (3, 1, 1, 1))
            self.assert_rejected(*self.make_backup(rows, filename="over-limit.db"))
            self.assertEqual(self.run_cli(*self.make_backup(rows[:2], filename="at-limit.db"))[0], 0)

    def test_rejects_unpinned_open_nonprivate_and_aliased_sources(self):
        backup, digest = self.make_backup()
        self.assert_rejected(backup, "0" * 64)
        self.assert_rejected(backup, "private-invalid-digest")
        for suffix in ("-wal", "-shm", "-journal"):
            with self.subTest(sidecar=suffix):
                sidecar = backup.with_name(backup.name + suffix)
                sidecar.write_bytes(b"synthetic")
                self.assert_rejected(backup, digest)
                self.assertEqual(sidecar.read_bytes(), b"synthetic")
                sidecar.unlink()
        alias = self.root / "source-alias.db"
        alias.symlink_to(backup)
        self.assert_rejected(alias, digest)
        alias.unlink()
        os.link(backup, alias)
        self.assert_rejected(backup, digest)
        alias.unlink()
        backup.chmod(0o640)
        self.assert_rejected(backup, digest)
        backup.chmod(0o600)
        self.root.chmod(0o750)
        self.assert_rejected(backup, digest)
        self.root.chmod(0o700)
        with closing(sqlite3.connect(backup)) as db:
            self.assertEqual(db.execute("PRAGMA journal_mode = WAL").fetchone(), ("wal",))
        self.assert_rejected(backup, sha256(backup.read_bytes()).hexdigest())
        self.assert_rejected(*self.make_backup(filename="not-utf8.db", encoding="UTF-16le"))

    def test_changed_source_and_incomplete_output_never_confirm_success(self):
        backup, digest = self.make_backup(((23, 0, 1, 2),))
        read_authorization = tool._read_authorization

        def change_after_read(source):
            result = read_authorization(source)
            with closing(sqlite3.connect(source)) as db, db:
                db.execute("UPDATE auth_overrides SET allowed = 1")
            return result

        with patch.object(tool, "_read_authorization", side_effect=change_after_read):
            self.assert_rejected(backup, digest)
        updated_digest = sha256(backup.read_bytes()).hexdigest()
        write_private = tool._write_private

        def interrupt_before_seal(path, body):
            if path.name == tool.SEAL:
                raise OSError("private-output-path-sentinel")
            return write_private(path, body)

        with patch.object(tool, "_write_private", side_effect=interrupt_before_seal):
            self.assert_rejected(backup, updated_digest)

        self.output.mkdir(mode=0o700)
        existing = self.output / tool.SIDECAR
        existing.write_bytes(b"preexisting")
        self.assertEqual(self.run_cli(backup, updated_digest), (2, "", tool.FAILURE + "\n"))
        self.assertEqual(existing.read_bytes(), b"preexisting")
        self.assertFalse((self.output / tool.SEAL).exists())


if __name__ == "__main__":
    unittest.main()

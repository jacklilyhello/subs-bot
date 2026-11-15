"""Synthetic live-WAL backup evidence; run only in the hosted validation suite."""
from contextlib import closing, redirect_stderr, redirect_stdout
from hashlib import sha256
import io
from itertools import chain, repeat
import json
import os
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_consistent_backup as tool


PRIVATE = "private-record-token-or-source-must-not-be-printed"


class ConsistentBackupTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory(prefix="consistent-backup-test-")
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "private?#-source.sqlite"
        self.output = self.root / "new-backup"
        self.writer = sqlite3.connect(self.source)
        self.addCleanup(self.writer.close)
        self.writer.execute("PRAGMA journal_mode=WAL")
        self.writer.execute("PRAGMA wal_autocheckpoint=0")
        self.writer.execute("CREATE TABLE records(id INTEGER PRIMARY KEY,value TEXT)")
        self.writer.commit()
        self.writer.execute("PRAGMA wal_checkpoint(TRUNCATE)")  # Fixture baseline only.
        self.writer.execute("INSERT INTO records VALUES(1,?)", (PRIVATE,))
        self.writer.commit()

    def target_rows(self):
        with closing(sqlite3.connect((self.output / tool.DATABASE).as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            return db.execute("SELECT * FROM records ORDER BY id").fetchall()

    def test_live_committed_wal_frames_are_included_without_source_checkpoint_or_reconfiguration(self):
        wal = Path(str(self.source) + "-wal")
        self.assertGreater(wal.stat().st_size, 0)
        # Demonstrate this fixture's committed row is absent from the main file.
        with closing(sqlite3.connect(self.source.as_uri() + "?mode=ro&immutable=1", uri=True)) as main_only:
            self.assertEqual(main_only.execute("SELECT count(*) FROM records").fetchone(), (0,))
        initial_wal = wal.read_bytes()
        initial_mode = self.source.stat().st_mode
        manifest = tool.backup(self.source, self.output)
        self.assertEqual(self.target_rows(), [(1, PRIVATE)])
        self.assertEqual(wal.read_bytes(), initial_wal)
        self.assertEqual(self.writer.execute("PRAGMA journal_mode").fetchone(), ("wal",))
        self.assertEqual(self.writer.execute("PRAGMA wal_autocheckpoint").fetchone(), (0,))
        self.assertEqual(self.source.stat().st_mode, initial_mode)
        self.assertTrue(manifest["sourceReadOnly"])
        self.assertFalse(manifest["sourceImmutable"])
        self.assertEqual(manifest["sourceJournalModeBefore"], "wal")
        self.assertEqual(manifest["sourceJournalModeAfter"], "wal")

    def test_uncommitted_source_changes_are_not_misrepresented_as_committed_backup_data(self):
        self.writer.execute("INSERT INTO records VALUES(2,'uncommitted')")
        tool.backup(self.source, self.output)
        self.assertEqual(self.target_rows(), [(1, PRIVATE)])
        self.writer.rollback()
        self.assertEqual(self.writer.execute("SELECT count(*) FROM records").fetchone(), (1,))

    def test_private_standalone_output_has_integrity_counts_and_final_digest_seal(self):
        manifest = tool.backup(self.source, self.output)
        database = self.output / tool.DATABASE
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        for name in (tool.DATABASE, tool.MANIFEST, tool.MARKER):
            self.assertEqual((self.output / name).stat().st_mode & 0o777, 0o600)
        self.assertFalse(any(Path(str(database) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")))
        self.assertEqual(sha256(database.read_bytes()).hexdigest(), manifest["sqliteSha256"])
        self.assertEqual(database.stat().st_size, manifest["sqliteBytes"])
        raw = (self.output / tool.MANIFEST).read_bytes()
        self.assertEqual((self.output / tool.MARKER).read_text(), sha256(raw).hexdigest() + "\n")
        self.assertEqual(json.loads(raw), manifest)
        self.assertEqual(manifest["tableCounts"], [{"nameSha256": sha256(b"records").hexdigest(), "rows": 1}])
        self.assertEqual(manifest["integrityCheck"], "ok")
        self.assertEqual(manifest["foreignKeyCheck"], "ok")
        self.assertFalse(manifest["finalCutoverSnapshot"])
        self.assertNotIn(PRIVATE, raw.decode())
        self.assertNotIn(str(self.source), raw.decode())

    def test_table_names_and_schema_are_hashed_not_exposed_in_manifest(self):
        name = 'private-table-"-credential'
        self.writer.execute("CREATE TABLE " + tool.quote_identifier(name) + "(value TEXT)")
        self.writer.commit()
        tool.backup(self.source, self.output)
        raw = (self.output / tool.MANIFEST).read_text()
        self.assertNotIn(name, raw)
        self.assertNotIn("CREATE TABLE", raw)
        self.assertNotIn(PRIVATE, raw)

    def test_existing_output_is_never_overwritten_or_unsealed(self):
        self.output.mkdir(mode=0o700)
        marker = self.output / tool.MARKER
        marker.write_text("retained-original")
        with self.assertRaises(tool.BackupError):
            tool.backup(self.source, self.output)
        self.assertEqual(marker.read_text(), "retained-original")
        self.assertEqual(list(self.output.iterdir()), [marker])

    def test_symlink_source_and_shared_output_parent_are_rejected(self):
        link = self.root / "linked.sqlite"
        link.symlink_to(self.source)
        with self.assertRaises(tool.BackupError):
            tool.backup(link, self.output)
        public_parent = self.root / "shared"
        public_parent.mkdir(mode=0o755)
        public_parent.chmod(0o755)
        with self.assertRaises(tool.BackupError):
            tool.backup(self.source, public_parent / "unsafe")
        self.assertFalse((public_parent / "unsafe").exists())

    def test_foreign_key_failure_preserves_partial_target_without_valid_seal(self):
        self.writer.executescript("CREATE TABLE parent(id INTEGER PRIMARY KEY); CREATE TABLE child(id INTEGER REFERENCES parent(id)); INSERT INTO child VALUES(999);")
        self.writer.commit()
        with self.assertRaises(tool.BackupError):
            tool.backup(self.source, self.output)
        self.assertTrue((self.output / tool.DATABASE).exists())
        self.assertFalse((self.output / tool.MARKER).exists())
        self.assertEqual(self.writer.execute("SELECT * FROM child").fetchall(), [(999,)])

    def test_backup_deadline_stops_without_seal_and_keeps_source_intact(self):
        with patch.object(tool.time, "monotonic", side_effect=chain([0], repeat(121))):
            with self.assertRaises(tool.BackupError):
                tool.backup(self.source, self.output)
        self.assertFalse((self.output / tool.MARKER).exists())
        self.assertEqual(self.writer.execute("SELECT * FROM records").fetchall(), [(1, PRIVATE)])

    def test_cli_projects_fixed_success_and_safe_failure_without_paths_or_private_values(self):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(tool.main([str(self.source), str(self.output)]), 0)
        self.assertEqual(out.getvalue(), tool.SUCCESS + "\n")
        self.assertEqual(err.getvalue(), "")
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(tool.main([str(self.root / PRIVATE), str(self.output)]), 1)
        self.assertEqual(out.getvalue(), "")
        self.assertEqual(err.getvalue(), tool.ERROR + "\n")


if __name__ == "__main__":
    unittest.main()

"""Synthetic hosted-only fixtures for unapplied legacy snapshot packages."""

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
import legacy_snapshot_convert as tool


TOKEN = "fixture-private-token-0001"
SHARE = "hy2://fixture-private-password@[2001:db8::1]:443,500-510/?sni=example.invalid#中文"
NODE = {"share": SHARE, "name": "fixture-private-name", "nested": {"x": [True, None, 1.5]}}


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def make_table(db, table, stored_count=True):
    final_time = "updated_at" if table == "subscriptions" else "deleted_at"
    counter = ", node_count INTEGER NOT NULL DEFAULT 0" if stored_count else ""
    db.execute(f"""CREATE TABLE {table} (
        id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        name TEXT NOT NULL DEFAULT 'fixture-private-name', url TEXT NOT NULL DEFAULT 'https://example.invalid/private',
        token TEXT NOT NULL, expire_at INTEGER, traffic_used REAL, traffic_total REAL,
        nodes_json TEXT NOT NULL DEFAULT '[]', last_error TEXT, created_at INTEGER NOT NULL DEFAULT 1700000000,
        {final_time} INTEGER NOT NULL DEFAULT 1700001000 {counter})""")


def make_path_table(db):
    db.execute("""CREATE TABLE path_maps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
        node_name TEXT NOT NULL, remark TEXT NOT NULL DEFAULT '', UNIQUE(user_id,node_name))""")


def insert(db, *, table="subscriptions", row_id=1, owner=123, nodes=None, token=TOKEN, stored_count=True):
    raw = json.dumps([NODE] if nodes is None else nodes, ensure_ascii=False, indent=2)
    columns = "id,user_id,token,nodes_json" + (",node_count" if stored_count else "")
    values = [row_id, owner, token, raw] + ([len([NODE] if nodes is None else nodes)] if stored_count else [])
    db.execute(f"INSERT INTO {table} ({columns}) VALUES ({','.join('?' for _ in values)})", values)


class LegacySnapshotConversionTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "fixture-private?#.sqlite"
        self.output = self.root / "package"

    def database(self, *, trash=True, stored_count=True, bookkeeping=True):
        db = sqlite3.connect(self.source)
        make_table(db, "subscriptions", stored_count=stored_count)
        if trash:
            make_table(db, "deleted_subs", stored_count=stored_count)
        if bookkeeping:
            db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
            db.execute("INSERT INTO meta VALUES ('node_count_backfilled_v1','1')")
        return db

    def rows(self, name):
        return [json.loads(line) for line in (self.output / name).read_bytes().splitlines()]

    def test_preserves_active_ids_tokens_node_order_and_uses_separate_stable_trash_mapping(self):
        with closing(self.database()) as db, db:
            insert(db, row_id=2, nodes=[NODE, {"name": "second", "opaque": "preserved"}])
            insert(db, row_id=5, nodes=[], token="fixture-private-empty-token")
            insert(db, table="deleted_subs", row_id=2, owner=-100123, token="fixture-private-trash-token")
            db.execute("UPDATE sqlite_sequence SET seq=100 WHERE name='subscriptions'")
            db.execute("UPDATE subscriptions SET expire_at=1700002000,traffic_used=1.25,traffic_total=10.5,last_error='old-safe-error' WHERE id=2")
        before = self.source.read_bytes()
        report = tool.convert_backup(self.source, self.output, owner_map={"-100123": "456"})
        self.assertTrue(report["completeImportable"])
        self.assertEqual(report["counts"]["convertedRows"], 3)
        self.assertEqual(report["counts"]["negativeOwnerRows"], 1)
        self.assertEqual(report["counts"]["nodeCount"], 3)
        manifest = tool.verify_bundle(self.output)
        self.assertEqual(manifest["sourceSha256"], sha256(before).hexdigest())
        self.assertEqual(manifest["trashIdMapping"], {"kind": "source-high-water-plus-ordinal", "sourceHighWater": 100,
                                                       "targetSequenceHighWater": 101})
        active = self.rows("active.ndjson")
        trash = self.rows("trash.ndjson")
        self.assertEqual([row["record"]["id"] for row in active], [2, 5])
        self.assertEqual(active[0]["record"]["token"], TOKEN)
        self.assertEqual(active[0]["record"]["owner_id"], "123")
        self.assertEqual(active[0]["record"]["traffic_used"], 1.25)
        self.assertEqual(active[0]["record"]["traffic_total"], 10.5)
        self.assertEqual(active[0]["record"]["expire_at"], 1700002000)
        self.assertEqual(active[0]["record"]["last_error"], "legacy-refresh-failed")
        self.assertEqual(report["counts"]["redactedErrorRows"], 1)
        self.assertEqual(report["counts"]["consumedBookkeepingRows"], 1)
        self.assertEqual(report["domains"]["meta"], {"present": True, "rows": 1, "consumedRows": 1, "unhandledRows": 0})
        self.assertEqual(active[1]["record"]["generation"], 0)
        self.assertIsNone(active[1]["record"]["snapshot_id"])
        self.assertEqual(trash[0]["legacyId"], 2)
        self.assertEqual(trash[0]["record"]["id"], 101)
        self.assertEqual(trash[0]["record"]["owner_id"], "456")
        self.assertEqual(trash[0]["record"]["updated_at"], trash[0]["record"]["deleted_at"])
        self.assertEqual(trash[0]["lifecycleRevision"], 1)
        pointer = active[0]["record"]
        prefix = self.output / "objects" / "subscriptions" / "2" / pointer["snapshot_id"]
        expected = compact(NODE) + b"\n" + compact({"name": "second", "opaque": "preserved"}) + b"\n"
        self.assertEqual((prefix / "0.ndjson").read_bytes(), expected)
        self.assertEqual(sha256((prefix / "manifest.json").read_bytes()).hexdigest(), pointer["manifest_sha256"])
        self.assertEqual(self.source.read_bytes(), before)
        self.assertEqual({item.name for item in self.root.iterdir()}, {self.source.name, self.output.name})
        for path in [self.output, *self.output.rglob("*")]:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o600)
        second = self.root / "second-package"
        tool.convert_backup(self.source, second, owner_map={"-100123": "456"})
        for path in self.output.rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (second / path.relative_to(self.output)).read_bytes())

        # The source-only metadata is accepted by the actual target migration chain.
        # No target apply or R2 endpoint is exercised here.
        with closing(sqlite3.connect(":memory:")) as target:
            target.execute("PRAGMA foreign_keys=ON")
            for migration in sorted((Path(__file__).resolve().parents[1] / "migrations").glob("*.sql")):
                target.executescript(migration.read_text())
            for table, rows in (("subscriptions", active), ("subscription_trash", trash)):
                for row in rows:
                    record = row["record"]
                    target.execute(f"INSERT INTO {table} ({','.join(record)}) VALUES ({','.join('?' for _ in record)})", tuple(record.values()))
                    if row["lifecycleRevision"]:
                        target.execute("INSERT INTO subscription_lifecycle VALUES (?,?)", (record["id"], row["lifecycleRevision"]))
            self.assertEqual(target.execute("PRAGMA quick_check").fetchone(), ("ok",))
            self.assertEqual(target.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_missing_signed_owner_mapping_blocks_all_handled_emission(self):
        with closing(self.database()) as db, db:
            insert(db)
            insert(db, table="deleted_subs", owner=-100123, token="fixture-private-other-token")
        report = tool.convert_backup(self.source, self.output)
        self.assertFalse(report["completeImportable"])
        self.assertEqual(report["blockers"], {"unmappedOwnerRows": 1})
        self.assertEqual(report["counts"]["convertedRows"], 0)
        self.assertFalse((self.output / "active.ndjson").exists())
        self.assertFalse((self.output / "objects").exists())
        with self.assertRaises(tool.ConversionError):
            tool.verify_bundle(self.output)
        self.assertFalse(tool.verify_bundle(self.output, require_complete=False)["completeImportable"])

    def test_all_other_domains_are_inventoried_and_nonempty_domains_block_completeness(self):
        with closing(self.database(trash=False, bookkeeping=False)) as db, db:
            insert(db)
            for name, columns in tool.DOMAINS.items():
                if name in (*tool.HANDLED, tool.PATH_DOMAIN):
                    continue
                db.execute(f"CREATE TABLE {name} ({','.join(column + ' TEXT' for column in columns)})")
                db.execute(f"INSERT INTO {name} VALUES ({','.join('?' for _ in columns)})", ["fixture-private-value"] * len(columns))
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(set(report["domains"]), set(tool.DOMAINS))
        self.assertEqual(report["blockers"], {f"unhandled:{name}": 1 for name in tool.DOMAINS if name not in (*tool.HANDLED, tool.PATH_DOMAIN)})
        self.assertEqual(report["counts"]["convertedRows"], 1)
        self.assertFalse(tool.verify_bundle(self.output, require_complete=False)["completeImportable"])

    def test_empty_path_table_keeps_existing_v1_shape(self):
        with closing(self.database(trash=False)) as db, db:
            make_path_table(db)
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["version"], 1)
        self.assertNotIn("pathIdMapping", tool.verify_bundle(self.output))
        self.assertFalse((self.output / tool.PATH_FILE).exists())

    def test_path_rules_keep_original_text_and_id_order_under_reviewed_owner_mapping(self):
        data = [(21, 456, " STRASSE ", "  exact\t remark → 尾  "), (4, -100123, "  香港\t ", "路径"),
                (20, 456, "Straße", "casefold first")]
        with closing(self.database(trash=False)) as db, db:
            make_path_table(db)
            db.executemany("INSERT INTO path_maps VALUES (?,?,?,?)", data)
            db.execute("UPDATE sqlite_sequence SET seq=70 WHERE name='path_maps'")
        report = tool.convert_backup(self.source, self.output, owner_map={"-100123": "456"})
        self.assertTrue(report["completeImportable"])
        self.assertEqual(report["version"], 2)
        mapping = {"kind": "identity", "rows": 3, "sourceHighWater": 70}
        self.assertEqual(report["pathIdMapping"], mapping)
        self.assertEqual(tool.verify_bundle(self.output)["pathIdMapping"], mapping)
        self.assertEqual(self.rows(tool.PATH_FILE), [{"id": row_id, "owner_id": "456", "keyword": keyword, "remark": remark}
            for row_id, _, keyword, remark in sorted(data)])

    def test_path_rules_block_ambiguous_cross_owner_overlap_even_with_different_raw_keys(self):
        with closing(self.database(trash=False)) as db, db:
            make_path_table(db)
            db.executemany("INSERT INTO path_maps VALUES (?,?,?,?)", [(1, 456, "Straße", "personal"), (2, -100123, " STRASSE ", "group")])
        report = tool.convert_backup(self.source, self.output, owner_map={"-100123": "456"})
        self.assertEqual(report["blockers"], {"ambiguousPathOwnerRows": 1})
        self.assertFalse((self.output / tool.PATH_FILE).exists())
        self.assertFalse(tool.verify_bundle(self.output, require_complete=False)["completeImportable"])

    def test_path_rules_block_unmapped_owners_and_invalid_text_without_partial_emission(self):
        with closing(self.database(trash=False)) as db, db:
            make_path_table(db)
            db.executemany("INSERT INTO path_maps VALUES (?,?,?,?)", [(1, -100123, "unmapped", "safe"),
                (2, 456, "empty", " \u3000 "), (3, 456, "nul\0", "safe"), (4, 456, "界" * 129, "safe")])
            db.execute("INSERT INTO path_maps VALUES (5,456,'malformed',CAST(X'FF' AS TEXT))")
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["blockers"], {"unmappedPathOwnerRows": 1, "invalidPathRuleRows": 4})
        self.assertFalse((self.output / "active.ndjson").exists())
        with self.assertRaises(tool.ConversionError):
            tool.verify_bundle(self.output)

    def test_path_rules_cap_applies_after_mapping_owners(self):
        with closing(self.database(trash=False)) as db, db:
            make_path_table(db)
            db.executemany("INSERT INTO path_maps VALUES (?,?,?,?)", [(i, 456 if i % 2 else -100123, f"unique-{i}", "ok")
                for i in range(1, 66)])
        report = tool.convert_backup(self.source, self.output, owner_map={"-100123": "456"})
        self.assertEqual(report["blockers"], {"pathRuleOwnerLimitRows": 1})
        self.assertFalse((self.output / tool.PATH_FILE).exists())

    def test_exhausted_path_allocator_reports_fixed_blocker(self):
        with closing(self.database(trash=False)) as db, db:
            make_path_table(db)
            db.execute("INSERT INTO path_maps VALUES (1,456,'safe','safe')")
            db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='path_maps'", (tool.MAX_SAFE_ID,))
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["blockers"], {"exhaustedPathAllocator": 1})
        self.assertFalse(tool.verify_bundle(self.output, require_complete=False)["completeImportable"])

    def test_token_collision_across_independent_source_tables_is_not_silently_rotated(self):
        with closing(self.database()) as db, db:
            insert(db)
            insert(db, table="deleted_subs")
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["blockers"], {"tokenCollisionRows": 1})
        self.assertEqual(report["counts"]["convertedRows"], 0)

    def test_raw_legacy_errors_remain_only_in_the_sealed_source(self):
        raw_error = "Provider failed https://user:legacy-secret-password@example.invalid/sub?token=legacy-secret-token response=" + "legacy-secret-response" * 500
        with closing(self.database(trash=False)) as db, db:
            insert(db)
            insert(db, row_id=2, token="fixture-private-token-0002")
            insert(db, row_id=3, token="fixture-private-token-0003")
            db.execute("UPDATE subscriptions SET last_error=? WHERE id=1", (raw_error,))
            db.execute("UPDATE subscriptions SET last_error='' WHERE id=2")
        report = tool.convert_backup(self.source, self.output)
        self.assertTrue(report["completeImportable"])
        self.assertEqual(report["counts"]["redactedErrorRows"], 1)
        self.assertEqual([row["record"]["last_error"] for row in self.rows("active.ndjson")],
                         ["legacy-refresh-failed", None, None])
        for path in self.output.rglob("*"):
            if path.is_file():
                for private in (b"legacy-secret-password", b"legacy-secret-token", b"legacy-secret-response"):
                    self.assertNotIn(private, path.read_bytes())
        with closing(sqlite3.connect(self.source)) as db:
            self.assertEqual(db.execute("SELECT last_error FROM subscriptions WHERE id=1").fetchone(), (raw_error,))
        tool.verify_bundle(self.output)

    def test_only_exact_normal_bookkeeping_is_consumed_and_unknown_meta_remains_blocked(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
            db.execute("INSERT INTO meta VALUES ('private-unknown-key','private-unknown-value')")
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["blockers"], {"unhandled:meta": 1})
        self.assertEqual(report["counts"]["consumedBookkeepingRows"], 1)
        self.assertEqual(report["domains"]["meta"]["rows"], 2)
        for index, value in enumerate(("0", "1\n", "true", sqlite3.Binary(b"1"))):
            with closing(sqlite3.connect(self.source)) as db, db:
                db.execute("DELETE FROM meta WHERE key='private-unknown-key'")
                db.execute("UPDATE meta SET value=? WHERE key='node_count_backfilled_v1'", (value,))
            blocked = tool.convert_backup(self.source, self.root / f"bad-marker-{index}")
            self.assertFalse(blocked["completeImportable"])
            self.assertEqual(blocked["blockers"], {"unhandled:meta": 1})
            self.assertEqual(blocked["counts"]["consumedBookkeepingRows"], 0)
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("DROP TABLE meta")
            db.execute("CREATE TABLE meta (key TEXT COLLATE NOCASE,value TEXT COLLATE RTRIM)")
            db.execute("INSERT INTO meta VALUES ('NODE_COUNT_BACKFILLED_V1','1')")
        blocked = tool.convert_backup(self.source, self.root / "nonbinary-meta")
        self.assertEqual(blocked["blockers"], {"unhandled:meta": 1})

    def test_missing_historical_node_count_is_supported_and_wrong_count_is_explicit(self):
        with closing(self.database(trash=False, stored_count=False)) as db, db:
            insert(db, stored_count=False)
        report = tool.convert_backup(self.source, self.output)
        self.assertTrue(report["completeImportable"])
        self.assertIsNone(self.rows("active.ndjson")[0]["storedNodeCount"])
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("ALTER TABLE subscriptions ADD COLUMN node_count INTEGER DEFAULT 77")
        other = self.root / "recomputed"
        report = tool.convert_backup(self.source, other)
        self.assertTrue(report["completeImportable"])
        self.assertEqual(report["counts"]["recomputedNodeCountRows"], 1)
        self.assertEqual(json.loads((other / "active.ndjson").read_text())["storedNodeCount"], 77)

    def test_snapshot_line_count_and_chunk_limits_block_without_truncating(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db, nodes=[{"pad": "a" * 40}] * 4)
        with patch.object(tool, "CHUNK_BYTES", 32), patch.object(tool, "SNAPSHOT_BYTES", 64), \
                patch.object(tool, "MAX_NODES", 3), patch.object(tool, "MAX_CHUNKS", 3):
            report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["counts"]["nodeCount"], 4)
        self.assertEqual(report["blockers"], {"lineOverLimitRows": 1, "snapshotOverLimitRows": 1,
                                                "nodeCountOverLimitRows": 1, "chunkCountOverLimitRows": 1})
        self.assertEqual(report["counts"]["convertedRows"], 0)
        self.assertFalse((self.output / "active.ndjson").exists())

    def test_large_original_text_cell_is_streamed_to_exact_sixty_four_mib_snapshot(self):
        raw_bytes = 83_600_000
        count = tool.SNAPSHOT_BYTES // tool.CHUNK_BYTES
        node = b'{"pad":"' + b"x" * (tool.CHUNK_BYTES - len(b'{"pad":""}\n')) + b'"}'
        spaces, extra = divmod(raw_bytes - 2 - count * len(node) - (count - 1), count)
        with closing(self.database(trash=False)) as db, db:
            rowid = db.execute("INSERT INTO subscriptions (user_id,token,nodes_json,node_count) VALUES (123,?,CAST(zeroblob(?) AS TEXT),?)",
                               (TOKEN, raw_bytes, count)).lastrowid
            with db.blobopen("subscriptions", "nodes_json", rowid) as blob:
                blob.write(b"[")
                for index in range(count):
                    if index:
                        blob.write(b",")
                    blob.write(b"{" + b" " * (spaces + (index < extra)) + node[1:])
                blob.write(b"]")
                self.assertEqual(blob.tell(), raw_bytes)
        report = tool.convert_backup(self.source, self.output)
        self.assertTrue(report["completeImportable"])
        self.assertEqual(report["counts"]["rawNodeBytes"], raw_bytes)
        self.assertEqual(report["counts"]["nodeBytes"], tool.SNAPSHOT_BYTES)
        manifest = tool.verify_bundle(self.output)
        self.assertEqual(manifest["files"]["count"], count + 3)

    def test_malformed_nodes_unsafe_numbers_and_invalid_utf8_never_emit_partial_rows(self):
        bad = [b'[{},null]', b'[{"x":1,"x":2}]', b'[{"x":NaN}]', b'[{"x":1e9999}]',
               b'[{"x":"\\ud800"}]', b'[{"x":"\xff"}]', b'[{"x":9007199254740992}]',
               b'[{}]extra', b'[{"x":' + b"[" * 5 + b"0" + b"]" * 5 + b"}]",
               b'[{"pad":"' + b"a" * 300 + b'"}]']
        with closing(self.database(trash=False)) as db, db:
            for index, raw in enumerate(bad, 1):
                db.execute("INSERT INTO subscriptions (id,user_id,token,nodes_json) VALUES (?,123,?,CAST(? AS TEXT))",
                           (index, f"fixture-private-token-{index}", raw))
        with patch.object(tool.inventory, "RAW_RECORD_BYTES", 256), patch.object(tool.inventory, "MAX_DEPTH", 4):
            report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["blockers"], {"invalidNodeRows": 8, "nodeReadLimitRows": 2})
        self.assertEqual(report["counts"]["convertedRows"], 0)

    def test_unbounded_or_invalid_metadata_cells_are_not_fetched_as_payload(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
            db.execute("UPDATE subscriptions SET url=CAST(zeroblob(2000000) AS TEXT),user_id=CAST(zeroblob(2000000) AS TEXT)")
        report = tool.convert_backup(self.source, self.output)
        self.assertEqual(report["blockers"], {"invalidMetadataRows": 1})

    def test_schema_and_sequence_anomalies_fail_closed_without_private_error_text(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
            db.execute("CREATE TABLE sqliteXunrecognized (private TEXT)")
        with self.assertRaisesRegex(tool.ConversionError, "^Legacy snapshot conversion could not be confirmed safely\\.$"):
            tool.convert_backup(self.source, self.output)
        self.assertFalse((self.output / "manifest.sha256").exists())
        with closing(sqlite3.connect(self.source)) as db, db:
            db.execute("DROP TABLE sqliteXunrecognized")
            db.execute("UPDATE sqlite_sequence SET seq=?", (tool.MAX_SAFE_ID + 1,))
        with self.assertRaises(tool.ConversionError):
            tool.convert_backup(self.source, self.root / "unsafe-sequence")

    def test_file_symlinks_parent_symlinks_sidecars_and_overwrite_are_rejected(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
        tool.convert_backup(self.source, self.output)
        marker = (self.output / "manifest.sha256").read_bytes()
        with self.assertRaises(tool.ConversionError):
            tool.convert_backup(self.source, self.output)
        self.assertEqual((self.output / "manifest.sha256").read_bytes(), marker)
        source_link = self.root / "source-link"
        source_link.symlink_to(self.source)
        parent_link = self.root / "parent-link"
        parent_link.symlink_to(self.root, target_is_directory=True)
        for source, output in ((source_link, self.root / "bad-one"), (self.source, parent_link / "bad-two")):
            with self.subTest(source=source.name):
                with self.assertRaises(tool.ConversionError):
                    tool.convert_backup(source, output)
        sidecar = Path(str(self.source) + "-wal")
        sidecar.write_bytes(b"synthetic")
        with self.assertRaises(tool.ConversionError):
            tool.convert_backup(self.source, self.root / "bad-sidecar")
        self.assertEqual((self.output / "manifest.sha256").read_bytes(), marker)

    def test_owner_policy_is_exact_and_cannot_reassign_positive_users(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
        for value in ({"-0100": "123"}, {"-100": "0"}, {"123": "456"}, {"-100": 123},
                      {"-100": str(2**63)}, {"-0": "123"}, {"-100\n": "123"}):
            with self.subTest(value=value):
                with self.assertRaises(tool.ConversionError):
                    tool.convert_backup(self.source, self.output, owner_map=value)
        self.assertFalse(self.output.exists())

    def test_private_bundle_closure_rejects_mutation_addition_and_symlink(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
        tool.convert_backup(self.source, self.output)
        original = (self.output / "active.ndjson").read_bytes()
        (self.output / "active.ndjson").write_bytes(original + b"\n")
        with self.assertRaises(tool.ConversionError):
            tool.verify_bundle(self.output)
        (self.output / "active.ndjson").write_bytes(original)
        extra = self.output / "extra-private-file"
        extra.write_bytes(b"synthetic")
        extra.chmod(0o600)
        with self.assertRaises(tool.ConversionError):
            tool.verify_bundle(self.output)
        extra.unlink()
        item = self.output / "active.ndjson"
        item.unlink()
        item.symlink_to(self.source)
        with self.assertRaises(tool.ConversionError):
            tool.verify_bundle(self.output)

    def test_source_drift_invalidates_marker_instead_of_certifying_package(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
        real_hash = tool._file_hash
        source_reads = 0

        def changed(path):
            nonlocal source_reads
            result = real_hash(path)
            if path == self.source:
                source_reads += 1
                if source_reads == 2:
                    return result[0], "0" * 64
            return result

        with patch.object(tool, "_file_hash", side_effect=changed):
            with self.assertRaises(tool.ConversionError):
                tool.convert_backup(self.source, self.output)
        self.assertFalse((self.output / "manifest.sha256").exists())

    def test_resigned_file_index_cannot_hide_broken_snapshot_reference_closure(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
        tool.convert_backup(self.source, self.output)
        index = self.rows("files.ndjson")
        chunk = next(item for item in index if item["path"].endswith("/0.ndjson"))
        path = self.output / chunk["path"]
        body = path.read_bytes().replace(b"fixture-private-name", b"fixture-private-test")
        path.write_bytes(body)
        chunk.update(bytes=len(body), sha256=sha256(body).hexdigest())
        index_body = b"".join(compact(item) + b"\n" for item in index)
        (self.output / "files.ndjson").write_bytes(index_body)
        manifest = json.loads((self.output / "manifest.json").read_bytes())
        manifest["files"].update(bytes=len(index_body), sha256=sha256(index_body).hexdigest())
        body = compact(manifest)
        (self.output / "manifest.json").write_bytes(body)
        (self.output / "manifest.sha256").write_bytes(sha256(body).hexdigest().encode("ascii") + b"\n")
        with self.assertRaises(tool.ConversionError):
            tool.verify_bundle(self.output)

    def test_second_pass_enforces_storage_bounds_independently(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db, nodes=[NODE, NODE])
        real_measure = tool._measure

        def misleading(*args):
            result = real_measure(*args)
            result["nodeCount"] = 1
            return result

        with patch.object(tool, "MAX_NODES", 1), patch.object(tool, "_measure", side_effect=misleading):
            with self.assertRaises(tool.ConversionError):
                tool.convert_backup(self.source, self.output)
        self.assertFalse((self.output / "manifest.sha256").exists())

    def test_cli_reports_only_counts_and_sanitized_fixed_failures(self):
        with closing(self.database(trash=False)) as db, db:
            insert(db)
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(tool.main([str(self.source), str(self.output)]), 0)
        self.assertEqual(stderr.getvalue(), "")
        for private in (str(self.source), str(self.output), TOKEN, SHARE, "fixture-private", "123"):
            self.assertNotIn(private, stdout.getvalue())
        report = json.loads(stdout.getvalue())
        self.assertTrue(report["completeImportable"])
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(tool.main([str(self.source), str(self.output)]), 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "Legacy snapshot conversion could not be confirmed safely.\n")


if __name__ == "__main__":
    unittest.main()

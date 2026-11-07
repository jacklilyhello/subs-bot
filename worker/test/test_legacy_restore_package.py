"""Hosted synthetic coverage for the private, unapplied legacy restore package."""

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

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import legacy_restore_package as package
import legacy_snapshot_convert as convert
from test_legacy_snapshot_convert import NODE, TOKEN, insert, make_path_table, make_table


REVISION = "a" * 40
APPLIED_AT = 1_800_000_000
TRASH_TOKEN = "fixture-private-trash-token"
EMPTY_TOKEN = "fixture-private-empty-token"
EMPTY_TRASH_TOKEN = "fixture-private-empty-trash-token"
OWNER_MAP = {"-100123": "456"}
QUOTE_NAME = "Synthetic '); DROP TABLE subscriptions; -- 名称"
UPLOAD_URL = "uploaded://fixture-only"


def digest(body):
    return sha256(body).hexdigest()


def body(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def put(path, raw):
    path.parent.mkdir(mode=0o700, exist_ok=True, parents=True)
    with package.native.private_file(path) as file:
        file.write(raw)


class LegacyRestorePackageTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.legacy = self.root / "source.sqlite"
        self.conversion = self.root / "conversion"
        self.output = self.root / "candidate"
        self.worker = self.root / "worker-artifact"
        self.worker.mkdir(mode=0o700)
        self.worker_sha, self.chain = self.make_worker_artifact()
        self.convert_sha = None

    def make_worker_artifact(self):
        module = b"export default {fetch(){return new Response('synthetic')}};\n"
        put(self.worker / "index.js", module)
        entries = []
        for path in sorted((WORKER / "migrations").glob("*.sql")):
            raw = path.read_bytes()
            put(self.worker / path.name, raw)
            entries.append({"name": path.name, "sha256": digest(raw)})
        snapshot_id = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        prefix = f"subscriptions/1/{snapshot_id}/"
        nodes = b'{"name":"synthetic"}\n'
        snapshot_manifest = body({"version": 1, "chunks": [{"bytes": len(nodes), "sha256": digest(nodes), "count": 1}]})
        objects = []
        for name, raw in (("0.ndjson", nodes), ("manifest.json", snapshot_manifest)):
            key = prefix + name
            put(self.worker / "r2" / key, raw)
            for directory in (self.worker / "r2", self.worker / "r2/subscriptions", self.worker / "r2/subscriptions/1"):
                directory.chmod(0o700)
            objects.append({"key": key, "file": f"r2/{key}", "bytes": len(raw), "sha256": digest(raw)})
        manifest = body({"version": 2, "ref": "refs/heads/main", "revision": REVISION, "runId": "1234", "runAttempt": "1",
            "bundleSha256": digest(module), "compatibilityDate": "2026-07-30", "migrations": entries,
            "snapshots": [{"id": 1, "snapshotId": snapshot_id, "token": "subsbot-synthetic-legacy-package",
                "manifestSha256": digest(snapshot_manifest), "nodeCount": 1, "nodeBytes": len(nodes),
                "bodyBytes": 1, "bodySha256": digest(b"x"), "objects": objects}]})
        put(self.worker / "isolation.json", manifest)
        return digest(manifest), entries

    def make_conversion(self, *, unsupported=False, trash_sequence=70, path_rows=(), path_sequence=None,
                        empty_trash=False, malformed_empty=False):
        with closing(sqlite3.connect(self.legacy)) as db, db:
            make_table(db, "subscriptions")
            make_table(db, "deleted_subs")
            insert(db, row_id=2, nodes=[NODE, NODE])
            insert(db, row_id=5, nodes=[], token=EMPTY_TOKEN)
            insert(db, table="deleted_subs", row_id=2, owner=-100123, token=TRASH_TOKEN)
            if empty_trash:
                insert(db, table="deleted_subs", row_id=4, owner=-100123, nodes=[], token=EMPTY_TRASH_TOKEN)
                db.execute("UPDATE deleted_subs SET nodes_json=?,node_count=99 WHERE id=4", (" [ \n ] ",))
                db.execute("UPDATE subscriptions SET node_count=17 WHERE id=5")
                db.execute("UPDATE subscriptions SET node_count=0 WHERE id=2")
            if malformed_empty:
                db.execute("UPDATE subscriptions SET nodes_json='[]extra' WHERE id=5")
            db.execute("UPDATE subscriptions SET name=?,url=?,expire_at=?,traffic_used=?,traffic_total=?,last_error=? WHERE id=2",
                       (QUOTE_NAME, UPLOAD_URL, 1_700_002_000, 1.25, 9.75, "fixture-private-provider-error"))
            db.execute("UPDATE sqlite_sequence SET seq=50 WHERE name='subscriptions'")
            db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='deleted_subs'", (trash_sequence,))
            if unsupported:
                db.execute("CREATE TABLE short_links(code TEXT PRIMARY KEY,user_id INTEGER,target_url TEXT,created_at INTEGER)")
                db.execute("INSERT INTO short_links VALUES ('synthetic001',123,'aggregate://all',1700000000)")
            if path_rows or path_sequence is not None:
                make_path_table(db)
                db.executemany("INSERT INTO path_maps VALUES (?,?,?,?)", path_rows)
                if not path_rows:
                    db.execute("INSERT INTO path_maps VALUES (?,456,'deleted','safe')", (path_sequence,))
                    db.execute("DELETE FROM path_maps")
                if path_sequence is not None:
                    db.execute("UPDATE sqlite_sequence SET seq=? WHERE name='path_maps'", (path_sequence,))
        self.legacy.chmod(0o600)
        report = convert.convert_backup(self.legacy, self.conversion, owner_map=OWNER_MAP)
        self.convert_sha = digest((self.conversion / "manifest.json").read_bytes())
        return report

    def build(self, **options):
        options = {"converter_manifest_sha": self.convert_sha, "worker_manifest_sha": self.worker_sha,
                   "revision": REVISION, "applied_at": APPLIED_AT, **options}
        return package.build_candidate(self.conversion, self.worker, self.output, **options)

    def v3_pins(self):
        return {"profile": "legacy-empty-v3", "source_sqlite_sha": digest(self.legacy.read_bytes()),
                "owner_map_sha": digest(body(OWNER_MAP))}

    def reseal_row(self, relative, mutate, *, valid=True):
        path = self.conversion / relative
        rows = [json.loads(line) for line in path.read_bytes().splitlines()]
        mutate(rows[0])
        raw = b"".join(body(row) + b"\n" for row in rows)
        path.write_bytes(raw)
        index_path = self.conversion / "files.ndjson"
        index = [json.loads(line) for line in index_path.read_bytes().splitlines()]
        for item in index:
            if item["path"] == relative:
                item.update(bytes=len(raw), sha256=digest(raw))
        index_raw = b"".join(body(item) + b"\n" for item in index)
        index_path.write_bytes(index_raw)
        manifest_path = self.conversion / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["files"].update(bytes=len(index_raw), sha256=digest(index_raw))
        raw = body(manifest)
        manifest_path.write_bytes(raw)
        self.convert_sha = digest(raw)
        (self.conversion / "manifest.sha256").write_text(self.convert_sha + "\n", encoding="ascii")
        if valid:
            self.assertTrue(convert.verify_bundle(self.conversion)["completeImportable"])

    def test_exact_fresh_candidate_preserves_tokens_objects_lineage_and_allocator(self):
        self.assertTrue(self.make_conversion()["completeImportable"])
        source_before = digest(self.legacy.read_bytes())
        result = self.build()
        self.assertEqual(result["version"], 1)
        self.assertNotIn("pathIdMapping", result)
        self.assertEqual(result["scope"], "fresh-unbound-d1-r2")
        self.assertEqual(result["legacyDomains"], "active-and-trash-only")
        self.assertEqual(result["counts"], {"activeRows": 2, "trashRows": 1, "generationZeroActiveRows": 1,
                                           "generationZeroTrashRows": 0, "nodeCount": 3, "redactedErrorRows": 1})
        self.assertEqual((result["sourceHighWater"], result["targetSequenceHighWater"]), (70, 71))
        self.assertEqual(result["generationZeroHttp"], "not-validated")
        self.assertEqual(result["formatCompatibility"], "not-validated")
        raw_manifest = (self.output / "manifest.json").read_bytes()
        manifest = json.loads(raw_manifest)
        self.assertEqual(result["manifestSha256"], digest(raw_manifest))
        self.assertEqual((self.output / "manifest.sha256").read_text(), digest(raw_manifest) + "\n")
        self.assertEqual(manifest["source"]["sqliteSha256"], source_before)
        self.assertEqual(manifest["workerArtifact"]["manifestSha256"], self.worker_sha)
        self.assertEqual(manifest["workerArtifact"]["migrations"], self.chain)
        self.assertEqual(digest(self.legacy.read_bytes()), source_before)
        self.assertEqual(set(self.output.iterdir()), {self.output / name for name in
                         ("manifest.json", "manifest.sha256", "restore.sql", "lineage.ndjson", "objects")})
        lineage = [json.loads(line) for line in (self.output / "lineage.ndjson").read_bytes().splitlines()]
        self.assertEqual([(row["legacyTable"], row["legacyId"], row["targetId"], row["lifecycleRevision"]) for row in lineage],
                         [("subscriptions", 2, 2, 0), ("subscriptions", 5, 5, 0), ("deleted_subs", 2, 71, 1)])
        for entry in manifest["objects"]:
            relative = Path("objects") / entry["key"]
            restored = (self.output / relative).read_bytes()
            self.assertEqual(restored, (self.conversion / relative).read_bytes())
            self.assertEqual((len(restored), digest(restored)), (entry["bytes"], entry["sha256"]))
            self.assertEqual(entry["metadata"], {"custom": {}, "http": {}})
        self.assertEqual(result["objectCount"], 4)
        sql = (self.output / "restore.sql").read_text(encoding="utf-8")
        self.assertNotIn("fixture-private-provider-error", sql)
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript(sql)
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.execute("PRAGMA quick_check").fetchall(), [("ok",)])
            self.assertEqual(db.execute("""SELECT id,owner_id,name,source_url,token,expire_at,traffic_used,traffic_total,last_error
                FROM subscriptions WHERE id=2""").fetchone(),
                (2, "123", QUOTE_NAME, UPLOAD_URL, TOKEN, 1_700_002_000, 1.25, 9.75, "legacy-refresh-failed"))
            self.assertEqual(db.execute("SELECT id,token,generation,node_count FROM subscriptions WHERE id=5").fetchone(),
                             (5, EMPTY_TOKEN, 0, 0))
            self.assertEqual(db.execute("SELECT id,owner_id,token,lifecycle_revision FROM subscription_trash").fetchall(),
                             [(71, "456", TRASH_TOKEN, 1)])
            self.assertEqual(db.execute("SELECT * FROM subscription_lifecycle").fetchall(), [(71, 1)])
            self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'").fetchone(), (71,))
            self.assertEqual(db.execute("SELECT * FROM path_rules").fetchall(), [])
            self.assertIsNone(db.execute("SELECT seq FROM sqlite_sequence WHERE name='path_rules'").fetchone())
            self.assertEqual(db.execute("SELECT position,name,sha256,mode,applied_at FROM subs_bot_schema_migrations ORDER BY position").fetchall(),
                [(i, item["name"], item["sha256"], "applied", APPLIED_AT) for i, item in enumerate(self.chain, 1)])
            self.assertIn("subscriptions_owner_id", {row[1] for row in db.execute("PRAGMA index_list('subscriptions')")})
            new = db.execute("""INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
                VALUES ('123','later','uploaded://later','fixture-later-token',1,1)""").lastrowid
            self.assertEqual(new, 72)
        for item in [self.output, *self.output.rglob("*")]:
            self.assertEqual(stat.S_IMODE(item.stat().st_mode), 0o700 if item.is_dir() else 0o600)

    def test_pinned_source_and_artifact_mutations_fail_before_candidate_creation(self):
        self.make_conversion()
        with self.assertRaisesRegex(package.PackageError, "could not be built"):
            self.build(converter_manifest_sha="f" * 64)
        self.assertFalse(self.output.exists())
        migration = self.worker / self.chain[-1]["name"]
        migration.write_bytes(migration.read_bytes() + b"\n")
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_corrupt_snapshot_fails_even_when_pinned_manifest_is_unchanged(self):
        self.make_conversion()
        path = next((self.conversion / "objects").rglob("0.ndjson"))
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_resealed_cross_table_token_collision_is_rejected_without_commit_marker(self):
        self.make_conversion()
        self.reseal_row("trash.ndjson", lambda item: item["record"].update(token=TOKEN))
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse((self.output / "manifest.sha256").exists())

    def test_resealed_invalid_metadata_is_rejected_without_printing_values(self):
        self.make_conversion()
        self.reseal_row("active.ndjson", lambda item: item["record"].update(last_error="credential-appears-only-in-input"))
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = package.main([str(self.conversion), str(self.worker), str(self.output),
                                   self.convert_sha, self.worker_sha, REVISION, str(APPLIED_AT)])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertEqual(errors.getvalue(), package.ERROR + "\n")
        self.assertFalse((self.output / "manifest.sha256").exists())

    def test_nonempty_unhandled_legacy_domain_never_seals(self):
        report = self.make_conversion(unsupported=True)
        self.assertEqual(report["blockers"], {"unhandled:short_links": 1})
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_exhausted_safe_id_allocator_does_not_create_candidate(self):
        self.assertTrue(self.make_conversion(trash_sequence=convert.MAX_SAFE_ID - 1)["completeImportable"])
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_v2_candidate_replays_exact_path_rows_and_independent_allocator(self):
        rule = "  路径\t '", '  remark " untouched \n  '
        self.make_conversion(path_rows=[(37, 456, " hk ", "second"), (5, -100123, *rule)], path_sequence=80)
        result = self.build()
        self.assertEqual(result["version"], 2)
        self.assertEqual(result["legacyDomains"], "active-trash-and-path-rules")
        self.assertEqual(result["pathIdMapping"], {"kind": "identity", "rows": 2, "sourceHighWater": 80, "targetSequenceHighWater": 80})
        self.assertEqual(result["objectCount"], 4)
        self.assertEqual(result["targetSequenceHighWater"], 71)
        manifest = json.loads((self.output / "manifest.json").read_bytes())
        self.assertEqual(manifest["summary"]["tableCounts"]["path_rules"], 2)
        self.assertEqual(manifest["pathIdMapping"], result["pathIdMapping"])
        self.assertFalse((self.output / convert.PATH_FILE).exists())
        with closing(sqlite3.connect(":memory:")) as db:
            db.execute("PRAGMA foreign_keys=ON")
            db.executescript((self.output / "restore.sql").read_text(encoding="utf-8"))
            self.assertEqual(db.execute("SELECT id,owner_id,keyword,remark FROM path_rules ORDER BY id").fetchall(),
                             [(5, "456", *rule), (37, "456", " hk ", "second")])
            self.assertEqual(db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name").fetchall(),
                             [("path_rules", 80), ("subscriptions", 71)])
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(db.execute("PRAGMA quick_check").fetchone(), ("ok",))
            self.assertIn("path_rules_owner_order", {row[1] for row in db.execute("PRAGMA index_list('path_rules')")})
            new = db.execute("INSERT INTO path_rules(owner_id,keyword,remark) VALUES ('456','new','new')").lastrowid
            self.assertEqual(new, 81)
            with self.assertRaises(sqlite3.IntegrityError):
                db.execute("INSERT INTO path_rules(owner_id,keyword,remark) VALUES ('456',' hk ','duplicate')")

    def test_v2_deleted_only_path_allocator_does_not_reuse_original_ids(self):
        report = self.make_conversion(path_sequence=100)
        self.assertEqual(report["pathIdMapping"], {"kind": "identity", "rows": 0, "sourceHighWater": 100})
        self.assertEqual((self.conversion / convert.PATH_FILE).read_bytes(), b"")
        self.assertEqual(self.build()["version"], 2)
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript((self.output / "restore.sql").read_text(encoding="utf-8"))
            self.assertEqual(db.execute("SELECT count(*) FROM path_rules").fetchone(), (0,))
            self.assertEqual(db.execute("INSERT INTO path_rules(owner_id,keyword,remark) VALUES ('456','new','new')").lastrowid, 101)

    def test_resealed_path_rows_with_invalid_target_text_fail(self):
        self.make_conversion(path_rows=[(5, -100123, "keyword", "remark")])
        self.reseal_row(convert.PATH_FILE, lambda item: item.update(keyword=" \u3000 "), valid=False)
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_path_support_does_not_admit_other_nonempty_legacy_domains(self):
        report = self.make_conversion(unsupported=True, path_rows=[(5, -100123, "keyword", "remark")])
        self.assertEqual(report["version"], 2)
        self.assertEqual(report["blockers"], {"unhandled:short_links": 1})
        with self.assertRaises(package.PackageError):
            self.build()
        self.assertFalse(self.output.exists())

    def test_v3_marks_exact_active_and_trash_empty_arrays_and_preserves_default(self):
        self.assertTrue(self.make_conversion(empty_trash=True)["completeImportable"])
        default = self.build()
        self.assertEqual(default["version"], 1)
        self.assertNotIn("emptyExportMarkers", default)
        original = self.output
        self.output = self.root / "explicit-v3"
        pins = self.v3_pins()
        result = self.build(**pins)
        self.assertEqual(result["version"], 3)
        self.assertEqual(result["legacyDomains"], "active-trash-and-empty-exports")
        self.assertEqual(result["counts"], {"activeRows": 2, "trashRows": 2, "generationZeroActiveRows": 1,
                                           "generationZeroTrashRows": 1, "nodeCount": 3, "redactedErrorRows": 1})
        self.assertEqual((result["targetSequenceHighWater"], result["objectCount"]), (72, 4))
        self.assertEqual(result["generationZeroHttp"], "not-validated")
        self.assertEqual(result["formatCompatibility"], "not-validated")
        raw = (self.output / "manifest.json").read_bytes()
        manifest = json.loads(raw)
        self.assertEqual((self.output / "manifest.sha256").read_bytes(), digest(raw).encode("ascii") + b"\n")
        self.assertEqual(manifest["source"]["sqliteSha256"], pins["source_sqlite_sha"])
        self.assertEqual(manifest["source"]["ownerMapSha256"], pins["owner_map_sha"])
        self.assertEqual(result["emptyExportMarkers"], {
            "activeRows": 1, "trashRows": 1, "migrationSha256": package.EMPTY_EXPORT_MIGRATION_SHA256,
            "tableSha256": manifest["summary"]["tableSha256"][package.EMPTY_EXPORTS],
        })
        self.assertEqual(manifest["summary"]["tableCounts"][package.EMPTY_EXPORTS], 2)
        self.assertEqual(manifest["objects"], json.loads((original / "manifest.json").read_bytes())["objects"])
        self.assertEqual((original / "lineage.ndjson").read_bytes(), (self.output / "lineage.ndjson").read_bytes())
        self.assertEqual(digest(self.legacy.read_bytes()), pins["source_sqlite_sha"])
        default_sql = (original / "restore.sql").read_text(encoding="utf-8")
        v3_sql = (self.output / "restore.sql").read_text(encoding="utf-8")
        self.assertEqual(default_sql, "".join(line for line in v3_sql.splitlines(keepends=True)
                                              if not line.startswith(f"INSERT INTO {package.EMPTY_EXPORTS} ")))
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(v3_sql)
            self.assertEqual(db.execute(f"SELECT * FROM {package.EMPTY_EXPORTS} ORDER BY subscription_id").fetchall(), [
                (5, "123", digest(EMPTY_TOKEN.encode("utf-8"))),
                (72, "456", digest(EMPTY_TRASH_TOKEN.encode("utf-8"))),
            ])
            self.assertEqual(db.execute("SELECT id,owner_id,token,generation,snapshot_id,manifest_sha256,node_count "
                                        "FROM subscription_trash WHERE id=72").fetchone(),
                             (72, "456", EMPTY_TRASH_TOKEN, 0, None, None, 0))
            self.assertEqual(db.execute("SELECT * FROM subscription_lifecycle ORDER BY subscription_id").fetchall(),
                             [(71, 1), (72, 1)])
            package.verify_empty_export_markers(db)
            for change, bindings in (
                (f"DELETE FROM {package.EMPTY_EXPORTS} WHERE subscription_id=72", ()),
                (f"UPDATE {package.EMPTY_EXPORTS} SET owner_id='789' WHERE subscription_id=72", ()),
                (f"UPDATE {package.EMPTY_EXPORTS} SET token_sha256=? WHERE subscription_id=72", ("b" * 64,)),
                (f"INSERT INTO {package.EMPTY_EXPORTS} VALUES (2,'123',?)", (digest(TOKEN.encode("utf-8")),)),
                ("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=26", ("b" * 64,)),
            ):
                with self.subTest(change=change):
                    db.execute("SAVEPOINT altered_candidate")
                    try:
                        db.execute(change, bindings)
                        with self.assertRaises(package.PackageError):
                            package.verify_empty_export_markers(db)
                    finally:
                        db.execute("ROLLBACK TO altered_candidate")
                        db.execute("RELEASE altered_candidate")

    def test_v3_cli_preserves_v2_path_rows_and_allocator(self):
        self.make_conversion(path_rows=[(5, -100123, "keyword", "remark")], path_sequence=100)
        default = self.build()
        self.assertEqual(default["version"], 2)
        self.assertNotIn("emptyExportMarkers", default)
        self.output = self.root / "explicit-v3-with-paths"
        pins = self.v3_pins()
        output, errors = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(errors):
            result = package.main([str(self.conversion), str(self.worker), str(self.output), self.convert_sha,
                                   self.worker_sha, REVISION, str(APPLIED_AT), pins["profile"],
                                   pins["source_sqlite_sha"], pins["owner_map_sha"]])
        self.assertEqual((result, errors.getvalue()), (0, ""))
        report = json.loads(output.getvalue())
        self.assertEqual(report["version"], 3)
        self.assertEqual(report["legacyDomains"], "active-trash-path-rules-and-empty-exports")
        self.assertEqual(report["pathIdMapping"], default["pathIdMapping"])
        self.assertEqual(report["emptyExportMarkers"]["activeRows"], 1)
        self.assertEqual(report["emptyExportMarkers"]["trashRows"], 0)
        for private_value in (EMPTY_TOKEN, "keyword", "remark"):
            self.assertNotIn(private_value, output.getvalue())
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript((self.output / "restore.sql").read_text(encoding="utf-8"))
            self.assertEqual(db.execute("SELECT * FROM path_rules").fetchall(), [(5, "456", "keyword", "remark")])
            self.assertEqual(db.execute("SELECT seq FROM sqlite_sequence WHERE name='path_rules'").fetchone(), (100,))

    def test_v3_requires_independent_source_pins_and_exact_migration(self):
        self.make_conversion()
        pins = self.v3_pins()
        for overrides in ({"source_sqlite_sha": None}, {"source_sqlite_sha": "b" * 64},
                          {"owner_map_sha": None}, {"owner_map_sha": "b" * 64}, {"profile": "unknown"}):
            with self.subTest(overrides=overrides):
                with self.assertRaises(package.PackageError):
                    self.build(**{**pins, **overrides})
                self.assertFalse(self.output.exists())

        manifest_path = self.worker / "isolation.json"
        manifest = json.loads(manifest_path.read_bytes())
        migration = self.worker / package.EMPTY_EXPORT_MIGRATION
        altered = migration.read_bytes() + b"\n"
        migration.write_bytes(altered)
        manifest["migrations"][25]["sha256"] = digest(altered)
        manifest_path.write_bytes(body(manifest))
        self.worker_sha = digest(body(manifest))
        with self.assertRaises(package.PackageError):
            self.build(**pins)
        self.assertFalse(self.output.exists())

    def test_v3_does_not_mark_malformed_legacy_nodes_as_empty(self):
        self.assertEqual(self.make_conversion(malformed_empty=True)["blockers"], {"invalidNodeRows": 1})
        with self.assertRaises(package.PackageError):
            self.build(**self.v3_pins())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()

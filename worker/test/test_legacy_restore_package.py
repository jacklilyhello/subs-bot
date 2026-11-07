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
from test_legacy_snapshot_convert import NODE, TOKEN, insert, make_table


REVISION = "a" * 40
APPLIED_AT = 1_800_000_000
TRASH_TOKEN = "fixture-private-trash-token"
EMPTY_TOKEN = "fixture-private-empty-token"
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

    def make_conversion(self, *, unsupported=False):
        with closing(sqlite3.connect(self.legacy)) as db, db:
            make_table(db, "subscriptions")
            make_table(db, "deleted_subs")
            insert(db, row_id=2, nodes=[NODE, NODE])
            insert(db, row_id=5, nodes=[], token=EMPTY_TOKEN)
            insert(db, table="deleted_subs", row_id=2, owner=-100123, token=TRASH_TOKEN)
            db.execute("UPDATE subscriptions SET name=?,url=?,expire_at=?,traffic_used=?,traffic_total=?,last_error=? WHERE id=2",
                       (QUOTE_NAME, UPLOAD_URL, 1_700_002_000, 1.25, 9.75, "fixture-private-provider-error"))
            db.execute("UPDATE sqlite_sequence SET seq=50 WHERE name='subscriptions'")
            db.execute("UPDATE sqlite_sequence SET seq=70 WHERE name='deleted_subs'")
            if unsupported:
                db.execute("CREATE TABLE short_links(code TEXT PRIMARY KEY,user_id INTEGER,target_url TEXT,created_at INTEGER)")
                db.execute("INSERT INTO short_links VALUES ('synthetic001',123,'aggregate://all',1700000000)")
        self.legacy.chmod(0o600)
        report = convert.convert_backup(self.legacy, self.conversion, owner_map={"-100123": "456"})
        self.convert_sha = digest((self.conversion / "manifest.json").read_bytes())
        return report

    def build(self, **options):
        options = {"converter_manifest_sha": self.convert_sha, "worker_manifest_sha": self.worker_sha,
                   "revision": REVISION, "applied_at": APPLIED_AT, **options}
        return package.build_candidate(self.conversion, self.worker, self.output, **options)

    def reseal_row(self, relative, mutate):
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
        self.assertTrue(convert.verify_bundle(self.conversion)["completeImportable"])

    def test_exact_fresh_candidate_preserves_tokens_objects_lineage_and_allocator(self):
        self.assertTrue(self.make_conversion()["completeImportable"])
        source_before = digest(self.legacy.read_bytes())
        result = self.build()
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


if __name__ == "__main__":
    unittest.main()

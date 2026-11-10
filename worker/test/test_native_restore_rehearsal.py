"""Hosted synthetic coverage; these tests do not contact Cloudflare."""

from copy import deepcopy
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import native_restore_rehearsal as native


ACCOUNT = "a" * 32
SOURCE_ID = "11111111-2222-3333-4444-555555555555"
RESTORE_ID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
SNAPSHOT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
PAYLOAD = "eeeeeeee-dddd-cccc-bbbb-aaaaaaaaaaaa"
COHORT = "0123456789abcdef0123456789abcdef"
REVISION = "b" * 40
PIN = {"revision": REVISION, "moduleSha256": "c" * 64}
STAMP = "2026-11-07T00:00:00.000Z"
TARGET = {"accountId": ACCOUNT, "d1Id": SOURCE_ID}
EMPTY_METADATA = {"custom": {}, "http": {}}


def envelope(value, **extra):
    return 200, {}, native.canonical({"success": True, "errors": [], "result": value, **extra})


class MemoryAPI:
    """Exact synthetic inventory and SQLite query reads; no conditional PUT."""

    def __init__(self):
        self.target = TARGET.copy()
        self.root = f"/accounts/{ACCOUNT}"
        self.source = self.root + f"/d1/database/{SOURCE_ID}"
        self.cohort = COHORT
        self.names = native.names(COHORT)
        self.journal_prefix = f"maintenance/native-restore/{COHORT}/journal/"
        self.archive_prefix = f"rehearsals/{COHORT}/"
        self.databases = {SOURCE_ID}
        self.restore_id = None
        self.restore_keys = set()
        self.restore_bucket = None
        self.objects = {}
        self.metadata = {}
        self.resource = {}
        self.calls = []
        self.response = None
        self.unknown_create = False
        self.fail_object = None
        self.fail_journal = None
        self.db = None

    def allow_restore(self, database_id=None, keys=None, object_bucket=None):
        if database_id is not None:
            self.restore_id = database_id
            self.databases.add(database_id)
        if keys is not None:
            self.restore_keys = set(keys)
        if object_bucket is not None:
            self.restore_bucket = object_bucket

    def object_or_none(self, bucket, key):
        value = self.objects.get((bucket, key))
        return (None, None) if value is None else (value, '"' + native.digest(value) + '"')

    def journal_entries(self, generation=None):
        prefix = self.journal_prefix + ("" if generation is None else f"{generation:06d}-")
        return [{"key": key} for bucket, key in self.objects if bucket == native.WORKER_NAME and key.startswith(prefix)]

    def list_objects(self, bucket, *, prefix="", maximum):
        return [{"key": key, "size": len(raw), "storage_class": "Standard", **self.metadata.get((name, key), {})}
                for (name, key), raw in self.objects.items() if name == bucket and key.startswith(prefix)][:maximum]

    def put_restored_object(self, key, body, metadata):
        self.calls.append(("S3 PUT", self.restore_bucket, key))
        location = (self.restore_bucket, key)
        if location in self.objects:
            raise native.RehearsalError(http_status=412)
        if self.fail_object == "uncommitted":
            raise native.RehearsalError(uncertain=True)
        self.objects[location] = body
        self.metadata[location] = {"custom_metadata": deepcopy(metadata["custom"]),
            "http_metadata": {field: metadata["http"][name] for field, name in native.HTTP_FIELDS.items() if name in metadata["http"]}}
        if self.fail_object == "committed":
            raise native.RehearsalError(uncertain=True)

    def r2(self, method, bucket, key, body=None):
        self.calls.append((method, bucket, key))
        if method == "GET":
            return self.object_or_none(bucket, key)
        assert method == "PUT"
        journal = key.startswith(self.journal_prefix)
        if self.fail_object == "uncommitted" and not journal or self.fail_journal == "uncommitted" and journal:
            raise native.RehearsalError(uncertain=True)
        self.objects[bucket, key] = body
        if self.fail_journal == "committed" and journal:
            self.fail_journal = None
            raise native.RehearsalError(uncertain=True)
        if self.fail_object == "committed" and not journal:
            raise native.RehearsalError(uncertain=True)

    def rows(self, database, sql, parameters=()):
        if self.db is not None:
            cursor = self.db.execute(sql, parameters)
            return [dict(zip([column[0] for column in cursor.description], row)) for row in cursor]
        if "sqlite_sequence" in sql:
            return []
        if "subs_bot_schema_migrations" in sql:
            return []
        if "watermark" in sql:
            return [{"watermark": 0}]
        return []

    def json(self, method, path, payload=None, *, envelope=False):
        self.calls.append((method, path, deepcopy(payload)))
        if method == "POST":
            if path.endswith("/import") or path.endswith("/export"):
                if callable(self.response):
                    return self.response(payload)
                if isinstance(self.response, Exception):
                    raise self.response
                return deepcopy(self.response)
            kind = "database" if path.endswith("/d1/database") else next(kind for kind in ("backup", "objects") if self.names.get(kind) == payload["name"])
            value = {"name": self.names[kind], "created_at" if kind == "database" else "creation_date": STAMP}
            if kind == "database":
                value["uuid"] = RESTORE_ID
            else:
                value["jurisdiction"] = "default"
            self.resource[kind] = value
            if self.unknown_create:
                raise native.RehearsalError(uncertain=True)
            return value
        url = urlsplit(path)
        if url.path.endswith("/objects"):
            name = url.path.rsplit("/", 2)[-2]
            query = parse_qs(url.query)
            result = self.list_objects(name, prefix=query.get("prefix", [""])[0], maximum=int(query.get("per_page", ["1000"])[0]))
            return {"result": result, "result_info": {}} if envelope else result
        raise AssertionError("Unexpected synthetic management read")


def fake_source():
    source = SimpleNamespace(scope_sha256="d" * 64, schema_sha256="e" * 64,
                             target=TARGET.copy(), before_write=Mock(), schema=Mock(), quiet=Mock(return_value=1_800_000_000))
    return source


class HarnessTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.api = MemoryAPI()
        self.source = fake_source()
        self.journal = native.Journal(self.api, "10/1")
        self.engine = native.Rehearsal(self.api, self.source, self.journal, Path(self.temporary.name))
        self.engine.observe = Mock(side_effect=lambda kind: None if kind not in self.api.resource else native.resource_identity(kind, self.api.resource[kind], self.api.names[kind]))
        self.engine.prepare(PIN)

    def pin_all(self):
        for kind in native.RESOURCES:
            self.engine.create(kind)
        self.engine.verify_resources(all_required=True)

    def test_default_verify_reads_existing_checkpoint_without_writes(self):
        self.pin_all()
        self.api.calls.clear()
        self.assertEqual(native.run_action("verify", self.engine, pin=PIN)["resourceCount"], 3)
        self.assertFalse(any(call[0] in {"POST", "PUT"} for call in self.api.calls))

    def test_private_journal_reconciles_lost_commit_and_rejects_advanced_predecessor(self):
        self.api.fail_journal = "committed"
        self.journal.update(phase="checked")
        self.assertEqual(self.journal.value["phase"], "checked")
        other = native.Journal(self.api, "11/1")
        other.load()
        with self.assertRaisesRegex(native.RehearsalError, "leased"):
            other.claim()
        other.value["lease"]["owner"] = None
        other.save(other.value)
        with self.assertRaisesRegex(native.RehearsalError, "advanced unexpectedly"):
            self.journal.update(phase="stale")

    def test_journal_unknown_write_fences_release_and_delayed_forks_are_refused(self):
        self.api.fail_journal = "uncommitted"
        with self.assertRaisesRegex(native.RehearsalError, "unconfirmed"):
            self.journal.update(phase="unknown")
        writes = len(self.api.calls)
        self.journal.release()
        self.assertEqual(len(self.api.calls), writes)
        fork = self.api.journal_prefix + f"000001-{'f' * 32}.json"
        self.api.objects[native.WORKER_NAME, fork] = b"contradictory checkpoint"
        with self.assertRaisesRegex(native.RehearsalError, "conflicting or missing"):
            native.Journal(self.api, "11/1").load()

    def test_each_create_once_then_read_only_replay_and_no_name_adoption(self):
        self.engine.create("database")
        self.engine.create("database")
        calls = [call for call in self.api.calls if call[0] == "POST"]
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][2], {"name": self.api.names["database"], "read_replication": {"mode": "disabled"}})
        self.assertEqual(self.journal.value["resources"]["database"]["pin"]["id"], RESTORE_ID)
        self.api.resource["backup"] = {"name": self.api.names["backup"], "creation_date": STAMP, "jurisdiction": "default"}
        with self.assertRaisesRegex(native.RehearsalError, "not adopted"):
            self.engine.create("backup")
        self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), 1)

    def test_unknown_create_never_retries_and_only_digest_pin_recovers(self):
        self.api.unknown_create = True
        with self.assertRaises(native.RehearsalError):
            self.engine.create("objects")
        with self.assertRaisesRegex(native.RehearsalError, "unpinned"):
            self.engine.create("objects")
        self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), 1)
        candidate = self.engine.observe("objects")
        with self.assertRaises(native.RehearsalError):
            self.engine.pin_resource("objects", "0" * 64)
        self.journal.value["resources"]["objects"]["intent"]["at"] = int(native.datetime.fromisoformat(STAMP).timestamp())
        self.engine.pin_resource("objects", native.digest(native.canonical(candidate)))
        self.assertEqual(self.journal.value["resources"]["objects"]["pin"], candidate)

    def test_stale_source_stops_create_after_durable_intent_before_post(self):
        self.source.before_write.side_effect = native.RehearsalError("stale source")
        with self.assertRaisesRegex(native.RehearsalError, "stale source"):
            self.engine.create("backup")
        self.assertEqual(self.journal.value["resources"]["backup"]["intent"]["state"], "started")
        self.assertFalse(any(call[0] == "POST" for call in self.api.calls))

    def test_busy_source_or_unknown_export_never_reinitiates(self):
        self.source.quiet.side_effect = native.RehearsalError("not quiet")
        with self.assertRaisesRegex(native.RehearsalError, "not quiet"):
            self.engine.begin_export()
        self.assertIsNone(self.journal.value["export"])
        self.source.quiet.side_effect = None
        self.api.response = native.RehearsalError(uncertain=True)
        with self.assertRaisesRegex(native.RehearsalError, "initiation is unknown"):
            self.engine.begin_export()
        with self.assertRaisesRegex(native.RehearsalError, "already recorded"):
            self.engine.begin_export()
        with self.assertRaisesRegex(native.RehearsalError, "confirmed"):
            self.engine.resume_export()
        self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), 1)

    def test_confirmed_export_poll_bookmark_recovers_without_new_initiation(self):
        self.journal.update(export={"state": "polling", "bookmark": "private-bookmark"})
        self.api.response = {"success": True, "status": "complete", "type": "export", "at_bookmark": "private-bookmark",
                             "result": {"signed_url": "https://d1.r2.cloudflarestorage.com/private?signature=secret"}}
        with patch.object(native.time, "sleep"):
            result = self.engine.resume_export()
        self.assertIn("signature=secret", result)
        writes = [call for call in self.api.calls if call[0] == "POST"]
        self.assertEqual(writes[0][2], {"output_format": "polling", "dump_options": {"compatibility": "d1"}, "current_bookmark": "private-bookmark"})
        self.assertEqual(self.journal.value["export"]["state"], "download-ready")

    def test_immutable_lost_commit_reconciles_and_uncommitted_never_certifies(self):
        key = self.api.archive_prefix + "blobs/" + "a" * 64
        self.api.fail_object = "committed"
        self.engine.immutable(self.api.names["backup"], key, b"private")
        self.engine.immutable(self.api.names["backup"], key, b"private")
        self.assertEqual(sum(call[:3] == ("PUT", self.api.names["backup"], key) for call in self.api.calls), 1)
        with self.assertRaisesRegex(native.RehearsalError, "different bytes"):
            self.engine.immutable(self.api.names["backup"], key, b"changed")
        self.api.fail_object = "uncommitted"
        with self.assertRaisesRegex(native.RehearsalError, "unconfirmed"):
            self.engine.immutable(self.api.names["backup"], self.api.archive_prefix + "blobs/" + "b" * 64, b"missing")

    def import_engine(self):
        self.pin_all()
        sql = Path(self.temporary.name) / "import.sql"
        sql.write_bytes(b"synthetic private SQL")
        document = {"sqlMd5": "a" * 32, "objects": []}
        self.engine.manifest = Mock(return_value=(document, sql))
        self.engine.verify_object_bytes = Mock()
        self.engine.verify_restore = Mock(return_value={"dataSha256": "f" * 64})
        return document

    def test_native_init_can_complete_immediately_and_is_not_followed_by_ingest(self):
        self.import_engine()
        self.api.response = {"success": True, "type": "import", "status": "complete", "result": {"final_bookmark": "private-final"}}
        with patch.object(native.migrations, "_matches_schema", return_value=True), patch.object(native, "signed_transfer") as transfer:
            self.engine.start_import()
        transfer.assert_not_called()
        actions = [call[2]["action"] for call in self.api.calls if call[0] == "POST" and call[1].endswith("/import")]
        self.assertEqual(actions, ["init"])
        self.assertEqual(self.journal.value["importState"]["state"], "complete")

    def test_upload_ingest_and_lost_ack_reconcile_without_second_post(self):
        self.import_engine()
        def response(payload):
            if payload["action"] == "init":
                return {"filename": "private.sql", "upload_url": "https://d1.r2.cloudflarestorage.com/private"}
            raise native.RehearsalError(uncertain=True)
        self.api.response = response
        with patch.object(native.migrations, "_matches_schema", return_value=True), patch.object(native, "signed_transfer") as transfer:
            with self.assertRaisesRegex(native.RehearsalError, "not acknowledged"):
                self.engine.start_import()
            self.assertEqual(self.journal.value["importState"]["state"], "ingest-started")
            self.engine.start_import()
        self.assertEqual(transfer.call_count, 1)
        actions = [call[2]["action"] for call in self.api.calls if call[0] == "POST" and call[1].endswith("/import")]
        self.assertEqual(actions, ["init", "ingest"])
        self.engine.verify_restore.assert_called_once()

    def test_import_poll_advances_only_to_validated_returned_bookmark(self):
        self.import_engine()
        self.journal.update(importState={"state": "polling", "bookmark": "bookmark-one"})

        def response(payload):
            self.assertEqual(payload["action"], "poll")
            bookmark = payload["current_bookmark"]
            self.assertEqual(bookmark, self.journal.value["importState"]["bookmark"])
            if bookmark == "bookmark-one":
                return {"success": True, "at_bookmark": "bookmark-two"}
            self.assertEqual(bookmark, "bookmark-two")
            return {"success": True, "status": "complete", "result": {"final_bookmark": "private-final"}}

        self.api.response = response
        with patch.object(native.time, "sleep"):
            self.engine.start_import()
        actions = [call[2] for call in self.api.calls if call[0] == "POST" and call[1].endswith("/import")]
        self.assertEqual(actions, [{"action": "poll", "current_bookmark": "bookmark-one"},
                                   {"action": "poll", "current_bookmark": "bookmark-two"}])
        self.engine.verify_restore.assert_called_once()

    def test_unknown_init_partial_target_is_retained_without_retry(self):
        self.import_engine()
        self.api.response = native.RehearsalError(uncertain=True)
        with patch.object(native.migrations, "_matches_schema", return_value=True):
            with self.assertRaises(native.RehearsalError):
                self.engine.start_import()
        self.engine.verify_restore.side_effect = native.RehearsalError()
        with self.assertRaisesRegex(native.RehearsalError, "never re-init"):
            self.engine.start_import()
        self.assertEqual(len([call for call in self.api.calls if call[0] == "POST" and call[1].endswith("/import")]), 1)

    def test_object_restore_resume_never_deletes_and_rejects_foreign_keys(self):
        self.pin_all()
        key = f"private-shares/{PAYLOAD}.txt"
        body = b"private synthetic payload"
        metadata = {"custom": {"purpose": native.PRIVATE_SHARE_PURPOSE, "receipt": "1"}, "http": {"content-type": "text/plain"}}
        entry = {"key": key, "bytes": len(body), "sha256": native.digest(body), "metadata": metadata}
        self.api.objects[self.api.names["backup"], self.api.archive_prefix + "blobs/" + entry["sha256"]] = body
        self.engine.manifest = Mock(return_value=({"objects": [entry]}, None))
        self.api.fail_object = "committed"
        self.engine.restore_objects()
        self.engine.restore_objects()
        self.assertEqual(self.api.object_or_none(self.api.names["objects"], key)[0], body)
        self.assertEqual(sum(call[:3] == ("S3 PUT", self.api.names["objects"], key) for call in self.api.calls), 1)
        self.api.metadata[self.api.names["objects"], key]["custom_metadata"]["receipt"] = "2"
        with self.assertRaisesRegex(native.RehearsalError, "conflicting size or metadata"):
            self.engine.restore_objects()
        self.assertEqual(sum(call[:3] == ("S3 PUT", self.api.names["objects"], key) for call in self.api.calls), 1)
        self.api.metadata[self.api.names["objects"], key]["custom_metadata"]["receipt"] = "1"
        self.api.objects[self.api.names["objects"], "foreign"] = b"do not delete"
        with self.assertRaises(native.RehearsalError):
            self.engine.restore_objects()
        self.assertEqual(self.api.objects[self.api.names["objects"], "foreign"], b"do not delete")

    def test_public_evidence_has_only_hashes_and_counts(self):
        self.journal.update(export={"url": "secret-url", "bookmark": "private-bookmark"},
                            private="private-content", backup={"manifestSha256": "a" * 64, "sqlSha256": "b" * 64,
                            "dataSha256": "c" * 64, "rowCount": 3, "objectCount": 2, "publishedShareMetadataCount": 1})
        report = native.report(self.journal, self.source)
        self.assertTrue(all(native.matches(native.DIGEST, value) or type(value) is int for value in report.values()))
        self.assertNotIn(b"secret-url", native.canonical(report))
        self.assertNotIn(b"private-content", native.canonical(report))


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        self.pin = patch.object(native, "ACCOUNT_SHA256", sha256(ACCOUNT.encode()).hexdigest())
        self.pin.start()
        self.addCleanup(self.pin.stop)
        self.api = native.RehearsalAPI(TARGET, "synthetic-data-token", COHORT)

    def test_write_allowlist_never_imports_source_or_changes_worker_or_deletes(self):
        bad = [("DELETE", self.api.source, None), ("POST", self.api.source + "/import", {"action": "init", "etag": "a" * 32}),
               ("POST", self.api.root + "/workers/scripts/anything", {}),
               ("POST", self.api.source + "/time_travel/restore", {}),
               ("POST", self.api.source + "/query", {"sql": "SELECT 1; DELETE FROM subscriptions"}),
               ("POST", self.api.root + "/d1/database", {"name": "other"})]
        with patch.object(native, "_response") as send:
            for method, path, payload in bad:
                with self.subTest(path=path), self.assertRaises(native.RehearsalError):
                    self.api.json(method, path, payload)
            send.assert_not_called()

    def test_read_queries_and_pinned_target_native_import_exact_wire(self):
        self.api.allow_restore(RESTORE_ID, [f"private-shares/{PAYLOAD}.txt"])
        self.api.allow_restore(RESTORE_ID)
        self.assertEqual(len(self.api.restore_keys), 1)
        with patch.object(native, "_response", return_value=envelope({"success": True})) as send:
            self.api.json("POST", self.api.root + f"/d1/database/{RESTORE_ID}/import", {"action": "init", "etag": "a" * 32})
        request = send.call_args.args[1]
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-data-token")
        self.assertEqual(json.loads(request.data), {"action": "init", "etag": "a" * 32})
        self.assertTrue(native.readonly_sql("SELECT ';--private' AS value"))
        self.assertTrue(native.readonly_sql("PRAGMA index_xinfo('subscriptions_owner_id')"))
        self.assertFalse(native.readonly_sql("PRAGMA foreign_keys=OFF"))
        self.assertFalse(native.readonly_sql("SELECT 1 /* mutation */"))

    def test_candidate_d1_schema_reads_use_the_single_statement_boundary(self):
        api = native.RehearsalAPI(self.api.target, "synthetic-data-token", COHORT, profile="synthetic-legacy-mixed-shorts")
        api.allow_restore(RESTORE_ID)
        path = api.root + f"/d1/database/{RESTORE_ID}"
        migrations = native.migrations
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        queries = []

        def response(_opener, request, _maximum):
            self.assertEqual(request.full_url, "https://api.cloudflare.com/client/v4" + path + "/query")
            sql = json.loads(request.data)["sql"]
            queries.append(sql)
            return envelope([{"success": True, "results": [{"matches": db.execute(sql).fetchone()[0]}]}])

        with patch.object(native, "_response", side_effect=response) as send:
            self.assertTrue(migrations._matches_schema(api, path, ()))
            definitions = {
                "subscriptions": "CREATE TABLE subscriptions (token TEXT UNIQUE)",
                "example": "CREATE TABLE example (text TEXT CHECK (text <> 'semicolon; -- literal'))",
            }
            for sql in definitions.values():
                db.execute(sql)
            objects = tuple(migrations.SchemaObject("table", name, name, sql) for name, sql in definitions.items())
            self.assertTrue(migrations._matches_schema(api, path, objects))
            self.assertIn("semicolon; -- literal", queries[1])
            self.assertTrue(all(sql.startswith("SELECT (") and sql.endswith(") AS matches") for sql in queries))
            for injected in ("DELETE FROM subscriptions;", "PRAGMA quick_check;", "-- hidden\nSELECT (1) AS matches;",
                             "SELECT (1) AS matches"):
                with self.subTest(injected=injected), self.assertRaises(native.RehearsalError):
                    api.json("POST", path + "/query", {"sql": "SELECT (1) AS matches;\n" + injected})
            self.assertEqual(send.call_count, 2)

    def test_candidate_d1_large_schema_reads_all_groups_in_one_request(self):
        api = native.RehearsalAPI(self.api.target, "synthetic-data-token", COHORT, profile=native.LEGACY_TEMP_CANDIDATE_PROFILE)
        api.databases.add(RESTORE_ID)
        api.allow_restore(RESTORE_ID)
        path = api.root + f"/d1/database/{RESTORE_ID}"
        migrations = native.migrations
        definitions = {"subscriptions": "CREATE TABLE subscriptions (token TEXT UNIQUE)"}
        for index in range(3):
            name = f"fixture_{index}"
            definitions[name] = f"CREATE TABLE {name} (text TEXT CHECK (text <> '{'a' * 35_000}; -- literal'))"
        objects = tuple(migrations.SchemaObject("table", name, name, sql) for name, sql in definitions.items())
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        for sql in definitions.values():
            db.execute(sql)

        def response(_opener, request, _maximum):
            self.assertEqual(request.full_url, "https://api.cloudflare.com/client/v4" + path + "/query")
            self.assertEqual(request.get_method(), "POST")
            payload = json.loads(request.data)
            self.assertEqual(set(payload), {"sql"})
            sql = payload["sql"]
            self.assertGreater(len(sql.encode("utf-8")), migrations.MAX_D1_STATEMENT_BYTES)
            statements = native.readonly_schema_batch(sql)
            self.assertIsNotNone(statements)
            self.assertEqual(len(statements), 2)
            self.assertTrue(all(len(statement.encode("utf-8")) < migrations.MAX_D1_STATEMENT_BYTES for statement in statements))
            self.assertIn("; -- literal", sql)
            return envelope([{"success": True, "results": [{"matches": db.execute(statement).fetchone()[0]}]}
                             for statement in statements])

        with patch.object(native, "_response", side_effect=response) as send:
            self.assertTrue(migrations._matches_schema(api, path, objects))
        send.assert_called_once()

    def test_candidate_d1_schema_batch_rejects_other_sql_parameters_and_limits(self):
        api = native.RehearsalAPI(self.api.target, "synthetic-data-token", COHORT, profile=native.LEGACY_CANDIDATE_PROFILE)
        api.allow_restore(RESTORE_ID)
        path = api.root + f"/d1/database/{RESTORE_ID}/query"
        check = "SELECT (1) AS matches"

        def batch(*statements):
            return ";\n".join(statements) + ";"

        valid = batch(check, check)
        too_wide = f"SELECT ('{'é' * 50_000}') AS matches"
        wide = f"SELECT ('{'x' * 75_000}') AS matches"
        cases = (
            {"sql": batch(check, "UPDATE subscriptions SET token='changed'")},
            {"sql": batch(check, "PRAGMA quick_check")},
            {"sql": batch(check, "SELECT 1")},
            {"sql": batch(check, "SELECT (1) UNION SELECT (1) AS matches")},
            {"sql": batch(check, "SELECT (1 /* comment */) AS matches")},
            {"sql": batch(check, "-- comment\n" + check)},
            {"sql": batch(check, "SELECT (:unbound) AS matches")},
            {"sql": valid, "params": []},
            {"sql": batch(check, "SELECT (?) AS matches"), "params": ["1"]},
            {"sql": batch(check, too_wide)},
            {"sql": batch(wide, wide, wide)},
            {"sql": batch(*([check] * (native.MAX_SCHEMA_READ_STATEMENTS + 1)))},
        )
        with patch.object(native, "_response") as send:
            for index, payload in enumerate(cases):
                with self.subTest(case=index), self.assertRaises(native.RehearsalError):
                    api.json("POST", path, payload)
            send.assert_not_called()

    def test_d1_rest_keyset_page_uses_strings_and_casts_only_integer_keys(self):
        self.api.allow_restore(RESTORE_ID)
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute("CREATE TABLE example(tenant TEXT, id INTEGER, PRIMARY KEY(tenant,id)) STRICT")
        db.executemany("INSERT INTO example VALUES (?,?)", [("001", index) for index in range(35)] + [("02", 0)])
        layout = native.table_layout(db, ["example"])
        expected = native.data_summary(layout, lambda _table, _definition: db.execute("SELECT tenant,id FROM example ORDER BY tenant,id"))

        def response(_opener, request, _maximum):
            self.assertEqual(request.full_url, "https://api.cloudflare.com/client/v4" + self.api.root + f"/d1/database/{RESTORE_ID}/query")
            query = json.loads(request.data)
            self.assertTrue(all(type(value) is str for value in query["params"]))
            cursor = db.execute(query["sql"], query["params"])
            return envelope([{"success": True, "results": [{"tenant": tenant, "id": identifier} for tenant, identifier in cursor]}])

        with patch.object(native, "_response", side_effect=response) as send:
            self.assertEqual(native.remote_summary(self.api, RESTORE_ID, layout), expected)
        self.assertEqual(send.call_count, 2)
        second = json.loads(send.call_args.args[1].data)
        self.assertEqual(second["params"], ["001", "31"])
        self.assertIn('("tenant","id") > (?, CAST(? AS INTEGER))', second["sql"])

    def test_legacy_temp_restore_readback_pages_one_payload_at_a_time(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        db.execute("CREATE TABLE legacy_temp_batches (bot TEXT, actor TEXT, id INTEGER, payload TEXT, PRIMARY KEY(bot,actor,id))")
        db.executemany("INSERT INTO legacy_temp_batches VALUES (?,?,?,?)",
                       [("123", "456", 1, "a" * 240_000), ("123", "456", 2, "b" * 240_000)])
        layout = native.table_layout(db, ["legacy_temp_batches"])
        expected = native.data_summary(layout, lambda _table, _definition: db.execute(
            "SELECT bot,actor,id,payload FROM legacy_temp_batches ORDER BY bot,actor,id"))

        def rows(database_id, sql, parameters):
            self.assertEqual(database_id, RESTORE_ID)
            self.assertTrue(sql.endswith("LIMIT 1"))
            return [dict(row) for row in db.execute(sql, parameters)]

        with patch.object(self.api, "rows", side_effect=rows) as read:
            self.assertEqual(native.remote_summary(self.api, RESTORE_ID, layout), expected)
        self.assertEqual(read.call_count, 3)

    def test_r2_inventory_cannot_treat_a_truncated_page_as_complete(self):
        first = {"key": "private-shares/first.txt"}
        second = {"key": "private-shares/second.txt"}
        bucket = self.api.names["objects"]
        with patch.object(self.api, "json", side_effect=[
            {"result": [first], "result_info": {"is_truncated": True, "cursor": "private-cursor"}},
            {"result": [second], "result_info": {"is_truncated": False}},
        ]) as call:
            self.assertEqual(self.api.list_objects(bucket, maximum=2), [first, second])
            self.assertIn("cursor=private-cursor", call.call_args.args[1])
        with patch.object(self.api, "json", return_value={"result": [first], "result_info": {"is_truncated": True}}):
            with self.assertRaisesRegex(native.RehearsalError, "truncated"):
                self.api.list_objects(bucket, maximum=2)
            engine = native.Rehearsal(self.api, None, None, None)
            with self.assertRaisesRegex(native.RehearsalError, "truncated"):
                engine.target_objects({first["key"]: {"bytes": 1, "metadata": EMPTY_METADATA}})

    def test_source_r2_only_reserved_write_once_journal_keys_are_writable(self):
        key = self.api.journal_prefix + f"000001-{'e' * 32}.json"
        with patch.object(native, "_response", return_value=envelope({})) as send:
            self.api.r2("PUT", native.WORKER_NAME, key, b"{}")
            request = send.call_args.args[1]
            self.assertEqual(request.get_header("If-none-match"), "*")
            with self.assertRaises(native.RehearsalError):
                self.api.r2("PUT", native.WORKER_NAME, f"private-shares/{PAYLOAD}.txt", b"private")
            with self.assertRaises(native.RehearsalError):
                self.api.r2("PUT", native.WORKER_NAME, self.api.journal_prefix + "journal.json", b"private")
        self.assertEqual(send.call_count, 1)

    def test_only_exact_http_404_is_absence_and_errors_are_redacted(self):
        request = native.Request("https://api.cloudflare.com/private", method="POST")
        opener = Mock()
        opener.open.side_effect = HTTPError(request.full_url, 500, "secret", {}, BytesIO(b"credential"))
        with self.assertRaises(native.RehearsalError) as caught:
            native._response(opener, request, 100)
        self.assertTrue(caught.exception.uncertain)
        self.assertNotIn("secret", str(caught.exception))
        key = self.api.journal_prefix + f"000001-{'e' * 32}.json"
        with patch.object(self.api, "r2", side_effect=native.RehearsalError(http_status=404)):
            self.assertEqual(self.api.object_or_none(native.WORKER_NAME, key), (None, None))
        with patch.object(self.api, "r2", side_effect=native.RehearsalError(http_status=403)):
            with self.assertRaises(native.RehearsalError):
                self.api.object_or_none(native.WORKER_NAME, key)

    def test_signed_transfers_reject_foreign_userinfo_and_port(self):
        for url in ("http://d1.r2.cloudflarestorage.com/file", "https://evil.example/file",
                    "https://d1.r2.cloudflarestorage.com.evil.example/file", "https://secret@d1.r2.cloudflarestorage.com/file",
                    "https://d1.r2.cloudflarestorage.com:444/file"):
            with self.subTest(url=url), patch.object(native, "build_opener") as build:
                with self.assertRaises(native.RehearsalError):
                    native.signed_transfer(url, download=Path("unused"))
                build.assert_not_called()

    def test_signed_download_never_adds_management_credentials(self):
        url = "https://d1.r2.cloudflarestorage.com/file?signature=synthetic"
        response = BytesIO(b"private synthetic dump")
        response.status, response.headers = 200, {}
        with tempfile.TemporaryDirectory() as directory, patch.object(native, "build_opener") as build:
            build.return_value.open.return_value = response
            path = Path(directory) / "dump.sql"
            native.signed_transfer(url, download=path)
            self.assertEqual(path.read_bytes(), b"private synthetic dump")
        request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, url)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertIsNone(request.get_header("Cookie"))

    def test_conditional_s3_put_uses_only_the_pinned_account_bucket_and_key(self):
        key = f"private-shares/{PAYLOAD}.txt"
        body = b"private synthetic share"
        metadata = {"custom": {"purpose": native.PRIVATE_SHARE_PURPOSE, "receipt": "123"},
                    "http": {"cache-control": "private, no-store", "content-type": "text/plain; charset=utf-8"}}
        token_id = "e" * 32
        self.api.allow_restore(keys=[key])
        with patch.object(native, "HTTPSConnection") as connect, patch.object(native, "_response", return_value=envelope({"id": token_id, "status": "active"})) as send:
            with self.assertRaises(native.RehearsalError):
                self.api.put_restored_object(key, body, metadata)
            self.api.allow_restore(object_bucket=self.api.names["objects"])
            for bad_key, bad_body, bad_metadata in ((key + "x", body, metadata), (key, b"x" * (native.OBJECT_BYTES + 1), metadata),
                                                     (key, body, {"custom": {}, "http": {"content-type": "x\r\nAuthorization: secret"}})):
                with self.assertRaises(native.RehearsalError):
                    self.api.put_restored_object(bad_key, bad_body, bad_metadata)
            send.assert_not_called()
            connect.assert_not_called()
            connection = connect.return_value
            connection.getresponse.return_value.status = 200
            connection.getresponse.return_value.read.return_value = b""
            self.api.put_restored_object(key, body, metadata)
        verify = send.call_args.args[1]
        self.assertEqual(verify.full_url, f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/tokens/verify")
        self.assertEqual(verify.get_header("Authorization"), "Bearer synthetic-data-token")
        connect.assert_called_once_with(f"{ACCOUNT}.r2.cloudflarestorage.com", timeout=30)
        args, kwargs = connection.request.call_args
        self.assertEqual(args, ("PUT", "/" + self.api.names["objects"] + "/" + key))
        self.assertEqual(kwargs["body"], body)
        headers = kwargs["headers"]
        self.assertEqual(headers["if-none-match"], "*")
        self.assertEqual(headers["content-length"], str(len(body)))
        self.assertEqual(headers["x-amz-content-sha256"], native.digest(body))
        self.assertEqual(headers["x-amz-storage-class"], "STANDARD")
        self.assertEqual(headers["x-amz-meta-purpose"], native.PRIVATE_SHARE_PURPOSE)
        self.assertEqual(headers["x-amz-meta-receipt"], "123")
        self.assertEqual(headers["content-type"], metadata["http"]["content-type"])
        self.assertRegex(headers["Authorization"], rf"^AWS4-HMAC-SHA256 Credential={token_id}/[0-9]{{8}}/auto/s3/aws4_request, SignedHeaders=[^,]+, Signature=[a-f0-9]{{64}}$")
        self.assertNotIn("synthetic-data-token", str(headers))
        self.assertNotIn(native.digest(b"synthetic-data-token"), str(headers))
        with patch.object(native, "HTTPSConnection", side_effect=OSError("synthetic-data-token")):
            with self.assertRaises(native.RehearsalError) as caught:
                self.api.put_restored_object(key, body, metadata)
        self.assertTrue(caught.exception.uncertain)
        self.assertNotIn("synthetic-data-token", str(caught.exception))

    def test_r2_metadata_rejects_unknown_custom_unknown_http_ssec_and_nonstandard_storage(self):
        for row in ({"custom_metadata": {"other": "private"}}, {"http_metadata": {"unknown": "private"}},
                    {"ssec": True}, {"http_metadata": {"cacheExpiry": "2026-11-07T00:00:00.123Z"}}):
            with self.subTest(row=row), self.assertRaises(native.RehearsalError):
                native.listed_metadata({"storage_class": "Standard", **row})
        for row in ({}, {"storage_class": "InfrequentAccess"}, {"storage_class": "unknown"}):
            with self.subTest(row=row), self.assertRaisesRegex(native.RehearsalError, "Standard R2"):
                native.listed_metadata(row)
        self.assertEqual(native.listed_metadata({"storage_class": "Standard",
                                                "http_metadata": {"cache_expiry": "2026-11-07T00:00:00Z"}}),
                         {"custom": {}, "http": {"expires": "Sat, 07 Nov 2026 00:00:00 GMT"}})


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        entries = []
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        for file in sorted((WORKER / "migrations").glob("*.sql")):
            body = file.read_bytes()
            (self.directory / file.name).write_bytes(body)
            entries.append({"name": file.name, "sha256": native.digest(body)})
            self.db.executescript(body.decode())
        loaded = native.migrations._load_migrations(self.directory, {"version": 2, "migrations": entries})
        self.db.execute(native.migrations.LEDGER_SQL)
        self.db.executemany("INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode,applied_at) VALUES (?,?,?,?,?)",
                            [(index, item.name, item.sha256, "adopted" if index == 1 else "applied", 1_800_000_000) for index, item in enumerate(loaded, 1)])
        objects = native.migrations._objects(loaded, len(loaded), managed=True)
        self.source = SimpleNamespace(objects=objects, tables=sorted(item.name for item in objects if item.type == "table"))
        self.bodies = {}

    def snapshot(self):
        raw = native.canonical({"share": "ss://synthetic@example.invalid:443#A\u2028B"}) + b"\n"
        plan = native.canonical({"version": 1, "chunks": [{"bytes": len(raw), "sha256": native.digest(raw), "count": 1}]})
        prefix = f"subscriptions/1/{SNAPSHOT}/"
        self.bodies[prefix + "0.ndjson"] = raw
        self.bodies[prefix + "manifest.json"] = plan
        self.db.execute("INSERT INTO subscriptions(id,owner_id,name,source_url,token,created_at,updated_at,generation,snapshot_id,manifest_sha256,node_count) VALUES (1,'881001','synthetic','https://example.invalid/source','abcdefghijklmnop',1,1,1,?,?,1)", (SNAPSHOT, native.digest(plan)))

    def published_share(self):
        self.assertIn("telegram_private_share_creations", self.source.tables)
        key = f"private-shares/{PAYLOAD}.txt"
        body = b"synthetic published private share"
        self.bodies[key] = body
        self.db.execute("INSERT INTO telegram_inbox(receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command) VALUES (1,'881000',1,'881001','881001','private',1,1,'list')")
        self.db.execute("""INSERT INTO private_shares(id,bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,
            payload_bytes,max_claims,target_user_id,expire_at,created_at)
            VALUES (1,'881000',?,'881001','synthetic',?,?,?,2,'881002',62,2)""", ("a" * 64, PAYLOAD, native.digest(body), len(body)))
        self.db.execute("""INSERT INTO telegram_private_share_creations(receipt_id,bot_id,actor_id,message_date,message_id,
            auth_message_date,auth_message_id,state,payload_id,payload_sha256,payload_bytes,sender_name,max_claims,target_user_id,
            duration_minutes,installation,key_version,reservation_expires_at,next_check_at,cleanup_after,share_id)
            VALUES (1,'881000','881001',1,1,0,0,'published',?,?,?,'synthetic',2,'881002',1,'isolation',1,5,5,6,1)""",
            (PAYLOAD, native.digest(body), len(body)))
        return key

    def dump(self, suffix="source"):
        path = self.directory / (suffix + ".sql")
        path.write_text("\n".join(self.db.iterdump()), "utf-8")
        return path

    def test_quiet_checks_only_unexpired_inline_work_on_the_new_schema(self):
        self.db.execute("""INSERT INTO telegram_inbox
            (receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (1,'881000',1,'881001','881001','private',1,1,'help','inline-consent:v1')""")
        self.db.execute("""INSERT INTO telegram_inline_search_consent
            (receipt_id,bot_id,actor_id,kind,message_date,update_id,expires_at,actor_role,auth_message_date,auth_message_id)
            VALUES (1,'881000','881001','on',1,1,100,'admin',0,0)""")
        self.db.execute("""INSERT INTO telegram_inline_search_receipts
            (bot_id,update_id,actor_id,query_id_sha256,consent_receipt_id,sort_mode,sort_update_id,received_at,lease_until,state)
            VALUES ('881000',2,'881001',?,1,'default',0,2,10,'preflight')""", ("a" * 64,))
        active = native.quiet_expression(self.source.tables, 9)
        expired = native.quiet_expression(self.source.tables, 10)
        older = native.quiet_expression(set(self.source.tables) - {"telegram_inline_search_receipts"}, 9)
        self.assertEqual(self.db.execute("SELECT " + active).fetchone(), (0,))
        self.db.execute("UPDATE telegram_inline_search_receipts SET state='sending'")
        self.assertEqual(self.db.execute("SELECT " + active).fetchone(), (0,))
        self.assertEqual(self.db.execute("SELECT " + expired).fetchone(), (1,))
        self.assertEqual(self.db.execute("SELECT " + older).fetchone(), (1,))

    def test_quiet_blocks_unsettled_telegram_provider_jobs_on_new_schema(self):
        self.db.execute("""INSERT INTO telegram_provider_jobs
            (owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,expected_lifecycle_revision,
             state,created_at,due_at,expires_at) VALUES ('881001',?,'refresh',1,?,0,0,'pending',1,1,10)""",
            ("a" * 64, "b" * 64))
        full = native.quiet_expression(self.source.tables, 2)
        older = native.quiet_expression(set(self.source.tables) - {"telegram_provider_jobs"}, 2)
        self.assertEqual(self.db.execute("SELECT " + full).fetchone(), (0,))
        self.assertEqual(self.db.execute("SELECT " + older).fetchone(), (1,))
        self.db.execute("UPDATE telegram_provider_jobs SET state='done',result_code='expired',finished_at=10")
        self.assertEqual(self.db.execute("SELECT " + full).fetchone(), (1,))

    def test_quiet_blocks_group_card_publication_and_unreconciled_edits(self):
        self.published_share()
        self.db.execute("INSERT INTO telegram_group_share_cards(receipt_id,group_id,state,due_at) VALUES (1,'-881003','pending',5)")

        def quiet(epoch, tables=self.source.tables):
            return self.db.execute("SELECT " + native.quiet_expression(tables, epoch)).fetchone()

        older = set(self.source.tables) - {"telegram_group_share_cards", "telegram_group_share_scopes"}
        self.assertEqual(quiet(10, older), (1,))
        self.assertEqual(quiet(10), (0,))
        self.db.execute("UPDATE telegram_group_share_cards SET state='sending',lease_id='synthetic',lease_until=10")
        self.assertEqual(quiet(10), (0,))
        self.db.execute("UPDATE telegram_group_share_cards SET state='uncertain'")
        self.assertEqual(quiet(9), (0,))
        self.assertEqual(quiet(10), (1,))
        self.db.execute("UPDATE telegram_group_share_cards SET state='sent',message_id=2")
        self.assertEqual(quiet(9), (0,))
        self.assertEqual(quiet(10), (0,))
        self.db.execute("UPDATE telegram_group_share_cards SET lease_id=NULL,lease_until=NULL")
        self.assertEqual(quiet(10), (1,))

    def test_quiet_blocks_batch_tickets_unsettled_children_and_late_replies(self):
        self.db.executescript("""INSERT INTO telegram_inbox
            (receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (1,'881000',1,'881001','881001','private',1,1,'help','provider-batch-preview:v1'),
                   (2,'881000',2,'881001','881001','private',2,2,'help','provider-batch-confirm:v1');
            INSERT INTO telegram_provider_batches
                (batch_id,preview_receipt_id,origin_attempt,bot_id,actor_id,actor_role,auth_message_date,auth_message_id,
                 admission_nonce,target_count,skipped_count,created_at,expires_at)
                VALUES (2,1,1,'881000','881001','admin',0,0,'synthetic',1,0,10,2710);
            INSERT INTO telegram_provider_batch_interactions
                (receipt_id,kind,actor_role,auth_message_date,auth_message_id,ready_at,targets,token_sha256,origin_attempt,expires_at)
                VALUES (1,'preview','admin',0,0,1,'[[1,0,0]]',printf('%064d',1),1,50);
            INSERT INTO telegram_provider_batch_jobs
                (batch_id,ordinal,owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,
                 expected_lifecycle_revision,state,created_at,due_at,expires_at)
                VALUES (2,1,'881001',printf('%064d',2),'refresh',1,printf('%064d',3),0,0,'waiting',10,10,2710);""")
        def quiet(epoch, tables=self.source.tables):
            return self.db.execute("SELECT " + native.quiet_expression(tables, epoch)).fetchone()

        older = set(self.source.tables) - {"telegram_provider_batches", "telegram_provider_batch_jobs",
                                         "telegram_provider_batch_interactions"}
        self.assertEqual(quiet(60, older), (1,))
        self.assertEqual(quiet(60), (0,))
        self.db.execute("""UPDATE telegram_provider_batches SET finished_at=20,saved_count=1,failed_count=0,
                        stale_count=0,expired_count=0""")
        self.assertEqual(quiet(1000), (0,))
        self.db.execute("UPDATE telegram_provider_batch_jobs SET state='done',result_code='saved',finished_at=20")
        self.assertEqual(quiet(60), (0,))
        self.db.execute("""INSERT INTO telegram_provider_batch_interactions
            (receipt_id,kind,batch_id,actor_role,auth_message_date,auth_message_id,ready_at) VALUES (2,'terminal',2,'admin',0,0,20)""")
        self.assertEqual(quiet(50), (0,))
        self.db.execute("INSERT INTO telegram_outbox (receipt_id,state,attempts,sent_message_id) VALUES (2,'sent',1,3)")
        self.assertEqual(quiet(49), (0,))
        self.assertEqual(quiet(50), (1,))

    def test_quiet_blocks_live_provider_snapshot_intents_and_preserves_expired_evidence(self):
        self.db.execute("""INSERT INTO provider_snapshot_attempts
            (snapshot_id,queue,job_id,job_attempt,subscription_id,owner_id,request_key,source_sha256,
             expected_generation,expected_lifecycle_revision,lease_until,bot_id,created_at,state)
            VALUES (?,'subscription_provider_jobs',1,1,1,'881001',?,?,0,0,10,'',1,'open')""",
            (SNAPSHOT, "a" * 64, "b" * 64))
        full = native.quiet_expression(self.source.tables, 9)
        expired = native.quiet_expression(self.source.tables, 10)
        older = native.quiet_expression(set(self.source.tables) - {"provider_snapshot_attempts"}, 9)
        self.assertEqual(self.db.execute("SELECT " + full).fetchone(), (0,))
        self.assertEqual(self.db.execute("SELECT " + expired).fetchone(), (1,))
        self.assertEqual(self.db.execute("SELECT " + older).fetchone(), (1,))
        self.assertEqual(self.db.execute("SELECT count(*) FROM provider_snapshot_attempts").fetchone(), (1,))

    def test_quiet_blocks_volatile_api_status_work_and_results_without_outbox(self):
        self.db.executescript("""INSERT INTO telegram_inbox
            (receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (1,'881000',1,'881001','881001','private',1,1,'help','api-status:v1'),
                   (2,'881000',2,'881001','881001','private',2,2,'help','api-status:v1');
            INSERT INTO telegram_api_status
                (receipt_id,prompt_receipt_id,actor_role,auth_message_date,auth_message_id,expires_at,ready_at,row_one,row_two)
                VALUES (1,NULL,'admin',0,0,60,1,NULL,NULL),(2,1,'admin',0,0,70,NULL,-2,-1);
            INSERT INTO telegram_outbox (receipt_id,state,attempts,sent_message_id) VALUES (1,'sent',1,3);""")

        def quiet(epoch, tables=self.source.tables):
            return self.db.execute("SELECT " + native.quiet_expression(tables, epoch)).fetchone()

        older = set(self.source.tables) - {"telegram_api_status"}
        self.assertEqual(quiet(60, older), (1,))
        self.assertEqual(quiet(60), (0,))
        self.assertEqual(quiet(1000), (0,))
        self.db.execute("UPDATE telegram_api_status SET row_one=-3,row_two=-3,ready_at=70 WHERE receipt_id=2")
        self.assertEqual(quiet(969), (0,))
        self.assertEqual(quiet(970), (1,))
        self.db.execute("INSERT INTO telegram_outbox (receipt_id) VALUES (2)")
        self.assertEqual(quiet(70), (0,))
        self.db.execute("UPDATE telegram_outbox SET state='sent',attempts=1,sent_message_id=4 WHERE receipt_id=2")
        self.assertEqual(quiet(70), (1,))

    def test_quiet_blocks_provider_document_work_until_summary_settles_or_expires(self):
        self.db.executescript("""INSERT INTO telegram_inbox
            (receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
            VALUES (1,'881000',1,'881001','881001','private',1,1,'help','document-job:v1'),
                   (2,'881000',2,'881001','881001','private',2,2,'help','provider-document:v1');
            INSERT INTO telegram_document_jobs
                (receipt_id,bot_id,actor_id,auth_message_date,auth_message_id,state,due_at,expires_at,file_id,name,suffix)
                VALUES (1,'881000','881001',0,0,'pending',1,60,'synthetic','fixture','txt');
            INSERT INTO telegram_provider_document_opt_in VALUES (1);""")

        def quiet(epoch, tables=self.source.tables):
            return self.db.execute("SELECT " + native.quiet_expression(tables, epoch)).fetchone()

        self.assertEqual(quiet(10), (0,))
        self.db.execute("""UPDATE telegram_document_jobs SET state='done',result_code='expired',finished_at=60,
                        file_id=NULL,name=NULL,suffix=NULL WHERE receipt_id=1""")
        self.assertEqual(quiet(60), (1,))
        self.db.execute("""INSERT INTO telegram_provider_documents
            (receipt_id,bot_id,actor_id,actor_role,auth_message_date,auth_message_id,expires_at,line_count)
            VALUES (2,'881000','881001','admin',0,0,70,1)""")
        older = set(self.source.tables) - {"telegram_provider_document_opt_in", "telegram_provider_documents",
                                         "telegram_provider_document_lines"}
        self.assertEqual(quiet(70, older), (1,))
        self.assertEqual(quiet(1000), (0,))
        self.db.execute("UPDATE telegram_provider_documents SET finished_at=70 WHERE receipt_id=2")
        self.assertEqual(quiet(969), (0,))
        self.assertEqual(quiet(970), (1,))
        self.db.execute("INSERT INTO telegram_outbox (receipt_id) VALUES (2)")
        self.assertEqual(quiet(970), (0,))
        self.db.execute("UPDATE telegram_outbox SET state='sent',attempts=1,sent_message_id=3 WHERE receipt_id=2")
        self.assertEqual(quiet(70), (1,))

    def test_full_schema_large_temp_text_and_r2_closure_roundtrip(self):
        self.snapshot()
        self.db.execute("INSERT INTO subscription_lifecycle VALUES (2,1)")
        self.db.execute("INSERT INTO subscription_trash(id,owner_id,name,source_url,token,created_at,updated_at,generation,node_count,deleted_at,lifecycle_revision) VALUES (2,'881001','synthetic trash','https://example.invalid/trash','ponmlkjihgfedcba',1,1,0,0,2,1)")
        self.db.execute("UPDATE sqlite_sequence SET seq=9 WHERE name='subscriptions'")
        self.db.execute("INSERT INTO telegram_inbox(receipt_id,bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce) VALUES (1,'881000',1,'881001','881001','private',1,1,'list','temp:v1')")
        node = {"share": "ss://synthetic@example.invalid:443", "padding": ""}
        node["padding"] = "x" * (262_144 - len(native.canonical([node])))
        payload = native.canonical([node]).decode()
        self.db.execute("INSERT INTO telegram_temp_batch VALUES (1,'881000','881001',1,1,?,1,?)", (payload, len(payload.encode())))
        private = "private synthetic message".encode()
        self.bodies[f"private-shares/{PAYLOAD}.txt"] = private
        self.db.execute("INSERT INTO private_shares(bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,payload_bytes,max_claims,target_user_id,expire_at,created_at) VALUES ('881000',?,'881001','synthetic',?,?,?,2,'881002',3,1)", ("a" * 64, PAYLOAD, native.digest(private), len(private)))
        self.db.execute("INSERT INTO private_share_claims VALUES (1,'881002',3)")
        path = self.dump()
        self.assertGreater(path.stat().st_size, 256 * 1024)
        with native.closing(native.open_export(path, self.source)[0]) as restored:
            refs = native.object_references(restored, lambda key: (self.bodies[key], EMPTY_METADATA))
            self.assertEqual({item["key"] for item in refs}, set(self.bodies))
            layout = native.table_layout(restored, self.source.tables)
            expected = native.data_summary(layout, lambda table, definition: restored.execute("SELECT " + ",".join(native._identifier(name) for name, _ in definition["columns"]) + " FROM " + native._identifier(table) + " ORDER BY " + ",".join(map(native._identifier, definition["primary"]))))
            api = MemoryAPI()
            api.db = restored
            self.assertEqual(native.remote_summary(api, RESTORE_ID, layout), expected)
            self.assertEqual(restored.execute("SELECT length(nodes_json) FROM telegram_temp_batch").fetchone()[0], len(payload))
            self.assertEqual(restored.execute("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'").fetchone(), (9,))
            self.assertEqual(restored.execute("SELECT id,lifecycle_revision FROM subscription_trash").fetchone(), (2, 1))

    def test_sealed_capture_objects_before_native_import_and_verify_digest(self):
        self.snapshot()
        share_key = self.published_share()
        sql = self.dump().read_bytes()
        api = MemoryAPI()
        api.db = self.db
        api.objects.update({(native.WORKER_NAME, key): body for key, body in self.bodies.items()})
        api.metadata[native.WORKER_NAME, share_key] = {
            "custom_metadata": {"purpose": native.PRIVATE_SHARE_PURPOSE, "receipt": "1"}}
        manifest_key = f"subscriptions/1/{SNAPSHOT}/manifest.json"
        api.metadata[native.WORKER_NAME, manifest_key] = {
            "http_metadata": {"contentType": "application/json", "cacheControl": "private, no-store"}}
        entries = {item["key"]: {"bytes": item["size"], "metadata": native.listed_metadata(item)}
                   for item in api.list_objects(native.WORKER_NAME, maximum=10)}
        source = fake_source()
        source.objects, source.tables = self.source.objects, self.source.tables
        journal = native.Journal(api, "10/1")
        engine = native.Rehearsal(api, source, journal, self.directory)
        engine.observe = Mock(side_effect=lambda kind: None if kind not in api.resource else native.resource_identity(kind, api.resource[kind], api.names[kind]))
        engine.prepare(PIN)
        for kind in native.RESOURCES:
            engine.create(kind)
        api.response = {"success": True, "type": "export", "status": "complete", "at_bookmark": "private-bookmark",
                        "result": {"signed_url": "https://d1.r2.cloudflarestorage.com/file?signature=private"}}
        capture, objects, target = [self.directory / part for part in ("capture", "objects", "target")]
        for directory in (capture, objects, target):
            directory.mkdir()

        def transfer(_url, *, download=None, upload=None, expected_md5=None):
            if download is not None:
                with native.private_file(download) as file:
                    file.write(sql)
            else:
                self.assertEqual(upload.read_bytes(), sql)
                self.assertEqual(native.file_hash(upload, "md5")[1], expected_md5)

        engine.directory = capture
        with patch.object(native, "signed_transfer", side_effect=transfer):
            engine.capture()
        self.assertEqual(journal.value["backup"]["objectCount"], 3)
        self.assertEqual(journal.value["backup"]["publishedShareMetadataCount"], 1)
        self.assertIsNone(journal.value["export"].get("url"))
        engine.directory = objects
        engine.restore_objects()
        self.assertEqual(engine.target_objects(entries), set(self.bodies))
        self.assertEqual(engine.object_metadata(api.names["objects"], share_key, len(self.bodies[share_key])), entries[share_key]["metadata"])
        self.assertEqual(engine.object_metadata(api.names["objects"], manifest_key, len(self.bodies[manifest_key])), entries[manifest_key]["metadata"])
        self.assertFalse(any(call[0] == "POST" and call[1].endswith("/import") for call in api.calls))
        engine.directory = target
        restored = sqlite3.connect(":memory:")
        self.addCleanup(restored.close)
        api.db = restored

        def respond(payload):
            if payload["action"] == "init":
                return {"filename": "private.sql", "upload_url": "https://d1.r2.cloudflarestorage.com/file"}
            self.assertEqual(payload["action"], "ingest")
            self.assertEqual(engine.target_objects(entries), set(self.bodies))
            restored.executescript(sql.decode())
            return {"success": True, "status": "complete", "result": {"final_bookmark": "private-final"}}

        api.response = respond
        with patch.object(native, "signed_transfer", side_effect=transfer), patch.object(native.migrations, "_matches_schema", return_value=True):
            engine.start_import()
        self.assertEqual(journal.value["phase"], "verified")
        self.assertEqual(journal.value["targetDataSha256"], journal.value["backup"]["dataSha256"])
        report = native.report(journal, source)
        self.assertEqual(report["publishedShareMetadataCount"], 1)
        self.assertEqual(report["targetPublishedShareMetadataCount"], 1)
        public = native.canonical(report)
        self.assertNotIn(b"private-bookmark", public)
        self.assertNotIn(b"abcdefghijklmnop", public)
        self.assertNotIn(native.PRIVATE_SHARE_PURPOSE.encode(), public)

    def test_published_share_rejects_absent_or_foreign_receipt_metadata(self):
        key = self.published_share()
        for custom in ({}, {"purpose": native.PRIVATE_SHARE_PURPOSE, "receipt": "2"}):
            with self.subTest(custom=custom), self.assertRaisesRegex(native.RehearsalError, "ownership metadata"):
                native.object_references(self.db, lambda name: (self.bodies[name], {"custom": custom, "http": {}}))
        custom = {"purpose": native.PRIVATE_SHARE_PURPOSE, "receipt": "1"}
        objects = native.object_references(self.db, lambda name: (self.bodies[name], {"custom": custom, "http": {}}))
        self.assertEqual(objects, [{"key": key, "bytes": len(self.bodies[key]), "sha256": native.digest(self.bodies[key]),
                                   "metadata": {"custom": custom, "http": {}}}])

    def test_corrupt_missing_snapshot_and_wrong_claim_target_fail_closed(self):
        self.snapshot()
        key = f"subscriptions/1/{SNAPSHOT}/0.ndjson"
        self.bodies[key] += b"tampered"
        with self.assertRaises(native.RehearsalError):
            native.object_references(self.db, lambda name: (self.bodies.get(name), EMPTY_METADATA))
        del self.bodies[key]
        with self.assertRaises(native.RehearsalError):
            native.object_references(self.db, lambda name: (self.bodies.get(name), EMPTY_METADATA))
        self.db.execute("INSERT INTO private_shares(bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,payload_bytes,max_claims,target_user_id,expire_at,created_at) VALUES ('881000',?,'881001','synthetic',?,?,1,1,'881002',3,1)", ("a" * 64, PAYLOAD, "b" * 64))
        self.db.execute("INSERT INTO private_share_claims VALUES (1,'881003',2)")
        with self.assertRaisesRegex(native.RehearsalError, "validation failed"):
            native.open_export(self.dump(), self.source)

    def test_unexpected_schema_and_attached_files_are_rejected_without_raw_errors(self):
        self.db.execute("CREATE TABLE unexpected (id INTEGER PRIMARY KEY)")
        with self.assertRaises(native.RehearsalError) as caught:
            native.open_export(self.dump(), self.source)
        self.assertNotIn("unexpected", str(caught.exception))
        malicious = self.directory / "malicious.sql"
        malicious.write_text("ATTACH DATABASE '/private/secret' AS other;", "utf-8")
        with self.assertRaisesRegex(native.RehearsalError, "validation failed"):
            native.open_export(malicious, self.source)


if __name__ == "__main__":
    unittest.main()

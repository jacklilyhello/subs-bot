"""Hosted synthetic tests for the protected Provider journal smoke."""

import sqlite3
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import provider_journal_smoke as smoke


COHORT = "ab" * 16
SNAPSHOT = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"


class Objects:
    def __init__(self):
        self.values = {}
        self.puts = []
        self.drop = False

    def request(self, method, key, body=None):
        if method == "PUT":
            self.puts.append(key)
            if self.drop != "before":
                if key in self.values:
                    raise AssertionError("Unexpected fixture overwrite")
                self.values[key] = body
            if self.drop:
                raise OSError("Synthetic lost management acknowledgement")
        elif method == "DELETE":
            self.values.pop(key, None)
        else:
            return self.values.get(key)


class Resources:
    database = "/owned/d1"
    bucket = "/owned/r2"

    def __init__(self, db):
        self.db, self.objects = db, Objects()

    def query(self, sql, params):
        return [dict(row) for row in self.db.execute(sql, tuple(map(str, params)))]

    def api(self, method, path, payload=None):
        if method == "GET":
            prefix, = parse_qs(urlsplit(path).query)["prefix"]
            return [{"key": key, "size": len(value)} for key, value in self.objects.values.items() if key.startswith(prefix)][:3]
        if (method, path) != ("POST", self.database + "/query"):
            raise AssertionError("Unexpected fixture management path")
        with self.db:
            return [{"success": True, "results": self.query(stmt["sql"], stmt["params"])} for stmt in payload["batch"]]


class ProviderJournalSmokeTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        migrations = Path(__file__).resolve().parents[1] / "migrations"
        for name in ("0001_subscriptions.sql", "0003_subscription_lifecycle.sql",
                     "0015_subscription_provider_jobs.sql", smoke.MIGRATION):
            self.db.executescript((migrations / name).read_text(encoding="utf-8"))
        for table in smoke.JOBS[1:]:
            self.db.execute(f"CREATE TABLE {table}(owner_id TEXT, subscription_id INTEGER, state TEXT)")
        self.resources = Resources(self.db)
        self.probes = []
        self.fixture = smoke.Fixture(self.resources, COHORT, lambda: None, lambda: None,
                                     lambda token, shares: self.probes.append((token, shares)))

    def simulate_completed_runtime(self):
        _, target = self.fixture.rows()
        digest = smoke.digest(self.fixture.expected["manifest.json"])
        with self.db:
            self.db.execute("""UPDATE subscriptions SET generation=1,snapshot_id=?,manifest_sha256=?,node_count=1
              WHERE id=?""", (SNAPSHOT, digest, target["id"]))
            self.db.execute(f"""UPDATE {smoke.TABLE} SET state='done',result_code='saved',attempts=1,finished_at=unixepoch()
              WHERE owner_id=? AND request_key=?""", (smoke.OWNER, self.fixture.requests[0]))
            self.db.execute(f"""INSERT INTO provider_snapshot_attempts ({smoke.ATTEMPT})
              SELECT ?,?,job_id,attempts,subscription_id,owner_id,request_key,source_sha256,expected_generation,
              expected_lifecycle_revision,expires_at,'',created_at,'published',?,1,2,unixepoch()
              FROM {smoke.TABLE} WHERE owner_id=? AND request_key=?""",
                            (SNAPSHOT, smoke.TABLE, digest, smoke.OWNER, self.fixture.requests[0]))
        for name, body in self.fixture.expected.items():
            self.resources.objects.values[f"subscriptions/{target['id']}/{SNAPSHOT}/{name}"] = body

    def test_scoped_lifecycle_reads_both_paths_and_retires_only_proven_objects(self):
        foreign_key = f"subscriptions/1000/{SNAPSHOT}/0.ndjson"
        self.resources.objects.values[foreign_key] = b"Unrelated synthetic object"
        self.assertEqual(self.fixture.prepare()["queuedLiveJobs"], 1)
        self.assertEqual(len(self.resources.objects.puts), 3)
        self.assertEqual(self.db.execute(f"SELECT state FROM {smoke.TABLE} ORDER BY state").fetchall()[0]["state"], "done")
        self.assertEqual(self.db.execute(f"SELECT count(*) FROM {smoke.TABLE} WHERE state='pending'").fetchone()[0], 1)
        with self.assertRaises(RuntimeError):
            self.fixture.capture()
        self.simulate_completed_runtime()
        self.assertEqual(self.fixture.capture()["verifiedObjects"], 5)
        self.assertEqual(len(self.probes), 3)
        self.assertEqual(self.fixture.retire(lambda *_: (404, "", b"")), {"retiredSubscriptions": 2})
        self.assertEqual(self.fixture.retire(lambda *_: (404, "", b"")), {"retiredSubscriptions": 0})
        self.assertEqual(self.resources.objects.values, {foreign_key: b"Unrelated synthetic object"})
        for table in ("subscriptions", smoke.TABLE, "provider_snapshot_attempts", "provider_snapshot_object_intents"):
            self.assertEqual(self.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_unrelated_active_work_refuses_admission(self):
        self.db.execute("INSERT INTO telegram_provider_jobs VALUES ('1',1,'leased')")
        with self.assertRaises(RuntimeError):
            self.fixture.prepare()
        self.assertEqual(self.resources.objects.puts, [])
        self.assertIsNone(self.fixture.rows())

    def test_lost_put_adopts_exact_present_bytes_and_never_retries_absence(self):
        self.resources.objects.drop = "after"
        self.assertEqual(self.fixture.put(100, SNAPSHOT, "0.ndjson", b"synthetic"), 1)
        self.resources.objects.drop = "before"
        with patch.object(smoke, "recheck_absent", return_value=None), self.assertRaises(RuntimeError):
            self.fixture.put(100, SNAPSHOT, "manifest.json", b"synthetic")
        self.assertEqual(len(self.resources.objects.puts), 2)
        self.assertEqual(len(self.resources.objects.values), 1)

    def test_capture_rejects_an_unexpected_interruption_manifest(self):
        self.fixture.prepare()
        self.simulate_completed_runtime()
        source, _ = self.fixture.rows()
        key = f"subscriptions/{source['id']}/{self.fixture.snapshots[1]}/manifest.json"
        self.resources.objects.values[key] = self.fixture.interrupted["manifest.json"]
        with self.assertRaises(RuntimeError):
            self.fixture.capture()
        with self.assertRaises(RuntimeError):
            self.fixture.retire(lambda *_: (404, "", b""))
        self.assertIn(key, self.resources.objects.values)
        self.assertEqual(self.fixture.rows()[0]["generation"], 1)

    def test_scope_confirmation_is_exact_and_capture_cannot_request_mutation(self):
        self.assertEqual(smoke.parse_inputs({"inputs": {"action": "capture", "cohort": COHORT}}), ("capture", COHORT))
        for action, confirm in (("prepare", ""), ("capture", "prepare synthetic provider journal " + COHORT),
                                ("retire", "retire synthetic provider journal " + "0" * 32)):
            with self.assertRaises(RuntimeError):
                smoke.parse_inputs({"inputs": {"action": action, "cohort": COHORT, "confirm": confirm}})

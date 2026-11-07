import base64
from contextlib import contextmanager
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))

import aggregate_smoke as aggregate
import capacity_fixtures as fixtures
import capacity_resources as capacity
from cloudflare_isolation import CloudflareError


REVISION = "1" * 40
RUN = "654321"
ATTEMPT = "1"
TARGET = {
    "accountId": "a" * 32, "workerId": "b" * 32, "workerCreatedOn": "2026-08-01T00:00:00Z",
    "d1Id": "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", "d1CreatedAt": "2026-08-01T00:00:00Z",
    "r2CreatedOn": "2026-08-01T00:00:00Z", "namespace": "lilyya",
}


class FakeD1:
    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for migration in sorted((WORKER / "migrations").glob("*.sql")):
            self.db.executescript(migration.read_text("utf-8"))
        self.failure = None
        self.pending = None
        self.reads_until_commit = 0

    def execute(self, statements):
        with self.db:
            return [{"success": True, "results": [dict(row) for row in self.db.execute(item["sql"], item["params"]).fetchall()]}
                    for item in statements]

    def __call__(self, method, path, payload):
        assert method == "POST" and path == f"/accounts/{TARGET['accountId']}/d1/database/{TARGET['d1Id']}/query"
        if "batch" not in payload:
            if self.pending is not None:
                self.reads_until_commit -= 1
                if self.reads_until_commit == 0:
                    self.execute(self.pending)
                    self.pending = None
            return self.execute([payload])
        failure, self.failure = self.failure, None
        if failure == "absent":
            raise CloudflareError("Synthetic insert result was lost.", uncertain=True)
        if failure == "late":
            self.pending, self.reads_until_commit = payload["batch"], 4
            raise CloudflareError("Synthetic insert result was delayed.", uncertain=True)
        if failure == "committed":
            self.execute(payload["batch"])
            raise CloudflareError("Synthetic committed result was lost.", uncertain=True)
        return self.execute(payload["batch"])


class AggregateSmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name) / "cohort"
        generated = fixtures.generate_capacity_fixtures(self.directory, REVISION, profile=fixtures.AGGREGATE_SMOKE)
        _, entries = capacity.read_fixtures(self.directory, REVISION, profile=fixtures.AGGREGATE_SMOKE)
        self.cloud = FakeD1()
        self.addCleanup(self.cloud.db.close)
        self.resources = capacity.Resources(TARGET, self.cloud, None)
        self.capacity = {"version": 1, "scopeSha256": self.resources.scope_hash, "revision": REVISION,
                         "runId": RUN, "phase": "seed", "fixtures": entries}
        for index, (fixture, entry) in enumerate(zip(generated["fixtures"], entries), start=1):
            entry["rowId"] = index
            name, source = capacity.marker(self.capacity, entry)
            self.cloud.db.execute("INSERT INTO subscriptions (id,owner_id,name,source_url,token,created_at,updated_at,"
                                  "generation,snapshot_id,manifest_sha256,node_count) VALUES (?,?,?,?,?,1,1,1,?,?,?)",
                                  (index, capacity.fixture_owner(entry), name, source, fixture["token"], entry["snapshotId"],
                                   entry["objects"][-1]["sha256"], entry["nodeCount"]))
        self.cloud.db.execute("INSERT INTO telegram_inbox (bot_id,update_id,actor_id,chat_id,chat_type,"
                              "message_id,message_date,command) VALUES ('5001',1,'5002','5002','private',1,1,'help')")
        self.cloud.db.execute("INSERT INTO telegram_outbox (receipt_id) SELECT receipt_id FROM telegram_inbox WHERE bot_id='5001'")
        self.cloud.db.commit()
        self.guard = lambda revision: self.assertEqual(revision, REVISION)

    def seed(self):
        aggregate.seed(self.directory, self.resources, self.capacity, REVISION, RUN, ATTEMPT, self.guard)
        return aggregate._load(self.directory, self.resources, self.capacity)

    def test_seed_reconciles_late_commit_and_retires_only_the_intended_temporary_cohort(self):
        self.cloud.failure = "late"
        with patch("capacity_resources.sleep", return_value=None):
            plan = self.seed()
        self.assertEqual(plan["phase"], "seeded")
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM aggregate_links").fetchone()[0], 4)
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM telegram_temp_batch").fetchone()[0], 3)
        selected = self.cloud.db.execute("SELECT selected_ids FROM aggregate_links WHERE code_sha256=?",
                                         (plan["digests"]["selected"],)).fetchone()[0]
        self.assertEqual(json.loads(selected), [2, 3, 1])
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM telegram_outbox").fetchone()[0], 1)
        for code in aggregate._request_codes(self.directory, REVISION).values():
            self.assertNotIn(code, (self.directory / aggregate.JOURNAL).read_text("ascii"))

        self.cloud.failure = "committed"
        aggregate.remove_temp(self.directory, self.resources, plan, REVISION, self.guard)
        self.assertEqual(plan["phase"], "temp-removed")
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM telegram_temp_batch").fetchone()[0], 2)
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM telegram_inbox").fetchone()[0], 4)
        self.cloud.failure = "committed"
        aggregate.cleanup(self.directory, self.resources, plan)
        aggregate.cleanup(self.directory, self.resources, plan)
        self.assertEqual(plan["phase"], "retired")
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM aggregate_links").fetchone()[0], 0)
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM telegram_temp_batch").fetchone()[0], 0)
        self.assertEqual(self.cloud.db.execute("SELECT bot_id FROM telegram_inbox").fetchone()[0], "5001")
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM telegram_outbox").fetchone()[0], 1)
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 3)

    def test_unknown_reservation_and_unexpected_reply_never_certify_cleanup(self):
        self.cloud.failure = "absent"
        with patch("capacity_resources.sleep", return_value=None):
            with self.assertRaisesRegex(capacity.CapacityError, "insertion remains unconfirmed"):
                self.seed()
            plan = aggregate._load(self.directory, self.resources, self.capacity)
            self.assertEqual(plan["phase"], "seeding")
            with self.assertRaisesRegex(capacity.CapacityError, "insertion remains unconfirmed"):
                aggregate.cleanup(self.directory, self.resources, plan)
        self.cloud.execute(aggregate._seed_statements(plan))
        self.cloud.db.execute("INSERT INTO telegram_outbox (receipt_id) SELECT min(receipt_id) FROM telegram_inbox WHERE bot_id=?",
                              (aggregate.BOTS[0],))
        self.cloud.db.commit()
        with self.assertRaisesRegex(capacity.CapacityError, "unexpected identity or reply"):
            aggregate.cleanup(self.directory, self.resources, plan)
        self.assertEqual(self.cloud.db.execute("SELECT count(*) FROM aggregate_links").fetchone()[0], 4)

    def test_probe_validates_exact_initial_and_changed_responses_without_disclosing_codes(self):
        self.seed()
        codes = aggregate._request_codes(self.directory, REVISION)
        base_headers = {"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer",
                        "X-Content-Type-Options": "nosniff", "CF-Cache-Status": "DYNAMIC"}
        requested = []
        incorrect_redirect = False
        after = False

        class Response(io.BytesIO):
            def __init__(self, status, body, headers):
                super().__init__(body)
                self.status, self.headers = status, headers

            def getheader(self, name, default=None):
                return self.headers.get(name, default)

        @contextmanager
        def request(method, path, _deadline, label):
            requested.append((method, path))
            headers = {**base_headers, "Content-Type": "text/plain; charset=utf-8"}
            if path == "/health":
                headers["Content-Type"] = "application/json"
                status, body = 200, json.dumps({"ok": True, "service": "subs-bot", "revision": REVISION}).encode()
            elif path == f"/s/{codes['all']}":
                status, body = 302, b""
                headers["Location"] = "https://example.invalid/unsafe" if incorrect_redirect else f"/agg/{codes['all']}/clash"
            elif label in ("all", "selected"):
                raw = {
                    "all": [*fixtures.aggregate_shares(fixtures.AGGREGATE_LABELS[0]),
                            *fixtures.aggregate_shares(fixtures.AGGREGATE_LABELS[1]),
                            *(() if after else fixtures.aggregate_shares("aggregate-temp"))],
                    "selected": [*fixtures.aggregate_shares(fixtures.AGGREGATE_LABELS[1]),
                                 *fixtures.aggregate_shares(fixtures.AGGREGATE_LABELS[0])],
                }
                status, body = 200, base64.b64encode("\n".join(raw[label]).encode("utf-8"))
                headers["Content-Length"] = str(len(body))
            else:
                status, body = 404, b"Not found."
            yield Response(status, b"" if method == "HEAD" else body, headers)

        with patch.object(aggregate, "_request", request):
            initial = aggregate.probe(self.directory, REVISION)
            after = True
            changed = aggregate.probe(self.directory, REVISION, after=True)
            incorrect_redirect = True
            after = False
            with self.assertRaisesRegex(capacity.CapacityError, "fixed local redirect"):
                aggregate.probe(self.directory, REVISION)
        self.assertEqual(initial["results"]["selected"], changed["results"]["selected"])
        self.assertNotEqual(initial["results"]["all"]["sha256"], changed["results"]["all"]["sha256"])
        self.assertIn(("GET", f"/agg/{codes['foreign-only']}/base64"), requested)
        self.assertIn(("HEAD", f"/agg/{codes['selected']}/mixed"), requested)
        for code in codes.values():
            self.assertNotIn(code, json.dumps(initial))


if __name__ == "__main__":
    unittest.main()

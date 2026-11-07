import json
from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import legacy_empty_export_smoke as smoke
from telegram_view_fixtures import FixtureError


class FixtureDatabase:
    scope_hash = "a" * 64
    database = "/fixture"

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        migrations = Path(__file__).resolve().parents[1] / "migrations"
        for path in sorted(migrations.glob("*.sql")):
            self.db.executescript(path.read_text())
        self.lose_response = False

    def query(self, sql, params=()):
        return [dict(row) for row in self.db.execute(sql, params)]

    def api(self, method, path, payload):
        assert (method, path) == ("POST", "/fixture/query")
        try:
            with self.db:
                result = [{"success": True, "results": self.query(row["sql"], row["params"])} for row in payload["batch"]]
        except sqlite3.Error:
            raise smoke.CloudflareError("Synthetic batch was rejected.") from None
        if self.lose_response:
            raise smoke.CloudflareError("Synthetic acknowledgement was lost.")
        return result


class EmptyExportSmokeTests(unittest.TestCase):
    def setUp(self):
        self.data = FixtureDatabase()
        self.addCleanup(self.data.db.close)
        self.fixtures = smoke.EmptyFixtures(self.data, {"adminId": "123", "memberId": "456"}, b"k" * 32, "a" * 16)
        self.guards = 0

    def guard(self):
        self.guards += 1

    def test_reconciles_lost_seed_and_retire_acknowledgements(self):
        self.data.lose_response = True
        self.fixtures.seed(self.guard)
        self.fixtures.seed(self.guard)
        self.assertEqual(len(self.fixtures.observe()), 2)
        self.assertEqual(self.guards, 1)
        self.assertEqual(self.data.query("SELECT count(*) AS n FROM legacy_empty_subscription_exports"), [{"n": 1}])
        self.assertEqual(self.fixtures.retire(self.guard), 2)
        self.assertEqual(self.fixtures.retire(self.guard), 0)
        self.assertEqual(self.guards, 2)

    def test_retirement_rejects_changed_identity_and_dangling_marker(self):
        self.fixtures.seed(self.guard)
        self.data.db.execute("UPDATE subscriptions SET name='foreign' WHERE owner_id='123'")
        with self.assertRaises(FixtureError):
            self.fixtures.retire(self.guard)
        self.assertEqual(len(self.data.query("SELECT id FROM subscriptions")), 2)
        self.data.db.execute("DELETE FROM subscriptions")
        with self.assertRaises(sqlite3.Error):
            self.fixtures.retire(self.guard)

    def test_checks_all_formats_and_unmarked_control(self):
        checks = []
        marked = self.fixtures.targets["marked"]["token"]

        def request(token, suffix, method):
            checks.append((token, suffix, method))
            if token != marked:
                return 404, "text/plain", b"Not found." if method == "GET" else b""
            if suffix in {"", "clash"}:
                media, body = "text/yaml", b"proxies: []\nproxy-groups:\nrules:\n"
            elif suffix in {"singbox", "sing-box"}:
                media, body = "application/json", json.dumps(smoke.EXPECTED_SINGBOX).encode()
            else:
                media, body = "text/plain", smoke.EXPECTED_SURGE if suffix == "surge" else b""
            return 200, media, body if method == "GET" else b""

        smoke.verify_formats(self.fixtures, request)
        self.assertEqual(len(checks), 24)

    def test_recovery_requires_explicit_exact_confirmation(self):
        cohort = "1" * 16
        self.assertEqual(smoke.parse_inputs({"inputs": {"action": "retire", "cohort": cohort, "confirm_retire": "retire " + cohort}}),
                         ("retire", cohort))
        with self.assertRaises(FixtureError):
            smoke.parse_inputs({"inputs": {"action": "retire", "cohort": cohort}})


if __name__ == "__main__":
    unittest.main()

"""Synthetic fixture staging and retirement against the reviewed SQLite schema."""

from pathlib import Path
import sqlite3
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from cloudflare_isolation import CloudflareError
from telegram_view_fixtures import FixtureError, manage, plan, read_cohort


POLICY = {"adminId": "1001", "memberId": "1002"}
COHORT = "fixturegroup0001"
OTHER = "fixturegroup0002"
PATH = "/accounts/synthetic/d1/database/synthetic"


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys = ON")
        for migration in sorted((Path(__file__).resolve().parents[1] / "migrations").glob("*.sql")):
            self.db.executescript(migration.read_text(encoding="utf-8"))
        self.lost_response = False
        self.write_calls = 0

    def api(self, method, path, payload):
        self.assertEqual((method, path), ("POST", PATH + "/query"))
        sql = payload["sql"]
        if not sql.startswith("SELECT CASE WHEN"):
            return [{"success": True, "results": [dict(row) for row in self.db.execute(sql)]}]
        self.write_calls += 1
        try:
            self.db.executescript("BEGIN;\n" + sql + "\nCOMMIT;")
        except sqlite3.DatabaseError:
            if self.db.in_transaction:
                self.db.rollback()
            raise CloudflareError("Synthetic transaction failed.") from None
        if self.lost_response:
            self.lost_response = False
            raise CloudflareError("Synthetic response lost after commit.", uncertain=True)
        return [{"success": True, "results": []}]

    def manage(self, action, cohort=COHORT):
        return manage(self.api, PATH, action, *plan(POLICY, cohort))

    def test_seed_and_retire_are_scoped_and_idempotent(self):
        prefix, expected = plan(POLICY, COHORT)
        self.assertEqual(self.manage("seed"), {"active": 12, "trashed": 10, "removed": 0})
        first = read_cohort(self.api, PATH, prefix, expected)
        self.assertEqual(self.manage("seed"), {"active": 12, "trashed": 10, "removed": 0})
        self.assertEqual(self.write_calls, 1)
        self.assertEqual(read_cohort(self.api, PATH, prefix, expected), first)
        self.manage("seed", OTHER)
        self.assertEqual(self.manage("retire"), {"active": 0, "trashed": 0, "removed": 22})
        self.assertEqual(self.manage("retire"), {"active": 0, "trashed": 0, "removed": 0})
        self.assertEqual(len(read_cohort(self.api, PATH, *plan(POLICY, OTHER))), 22)
        self.assertEqual(self.db.execute("SELECT count(*) FROM subscription_lifecycle").fetchone()[0], 10)

    def test_unexpected_trash_revision_prevents_any_retirement(self):
        self.manage("seed")
        self.db.execute("UPDATE subscription_trash SET lifecycle_revision = 2 WHERE id = (SELECT min(id) FROM subscription_trash)")
        with self.assertRaisesRegex(FixtureError, "ambiguous"):
            self.manage("retire")
        self.assertEqual(self.write_calls, 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM subscription_trash").fetchone()[0], 10)

    def test_readback_reconciles_a_lost_response_for_both_operations(self):
        self.lost_response = True
        self.assertEqual(self.manage("seed")["active"], 12)
        self.lost_response = True
        self.assertEqual(self.manage("retire")["removed"], 22)
        self.assertEqual(self.write_calls, 2)

    def test_trash_failure_rolls_back_the_entire_seed(self):
        self.db.executescript("""
            CREATE TRIGGER reject_fixture_trash BEFORE INSERT ON subscription_trash
            BEGIN SELECT RAISE(ABORT, 'Synthetic fixture failure'); END;
        """)
        with self.assertRaisesRegex(FixtureError, "could not be confirmed"):
            self.manage("seed")
        self.assertEqual(self.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 0)

    def test_unsafe_cohort_is_rejected_before_any_api_use(self):
        for cohort in ("short", "fixturegroup000%", "'fixturegroup001", "fixturegroup0001\n"):
            with self.assertRaisesRegex(FixtureError, "cohort key"):
                self.manage("seed", cohort)
        self.assertEqual(self.write_calls, 0)

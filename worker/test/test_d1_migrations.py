"""Hosted SQLite-backed tests for the isolation D1 migration protocol."""

from __future__ import annotations

import hashlib
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))

from d1_migrations import BASELINE_NAME, LEDGER, MigrationError, apply_migrations  # noqa: E402


TARGET = {
    "accountId": "a" * 32,
    "d1Id": "11111111-1111-4111-8111-111111111111",
    "d1CreatedAt": "2026-07-30T00:00:00.000Z",
}
BASELINE = (WORKER / "migrations" / BASELINE_NAME).read_bytes()
NEXT_NAME = "0002_messages.sql"
NEXT_SQL = b"""-- SQLite may find a semicolon in a literal.
CREATE TABLE test_messages (
    id INTEGER PRIMARY KEY,
    actor_id TEXT NOT NULL,
    marker TEXT NOT NULL DEFAULT 'first;second'
) STRICT;
CREATE INDEX test_messages_actor ON test_messages (actor_id, id);
"""


class FakeD1:
    def __init__(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID")
        self.metadata = {"uuid": TARGET["d1Id"], "name": "subs-bot-cf-dev-01", "created_at": TARGET["d1CreatedAt"]}
        self.path = f"/accounts/{TARGET['accountId']}/d1/database/{TARGET['d1Id']}"
        self.mutations = []
        self.executed = []
        self.db.set_trace_callback(self.executed.append)
        self.fail_before_ledger = False
        self.lose_success_response = False

    def __call__(self, method, path, payload=None):
        if method == "GET" and path == self.path:
            return self.metadata
        if method != "POST" or path != self.path + "/query" or set(payload) != {"sql"}:
            raise AssertionError("unexpected D1 request")
        sql = payload["sql"]
        if not sql.startswith("SELECT CASE WHEN"):
            return [{"success": True, "results": [dict(row) for row in self.db.execute(sql)]}]

        self.mutations.append(sql)
        if self.fail_before_ledger:
            sql = sql.replace(f"INSERT INTO {LEDGER} ", f"SELECT json_extract('deliberate failure', '$');\nINSERT INTO {LEDGER} ", 1)
        try:
            # The management API executes the submitted SQL as one transaction.
            self.db.executescript("BEGIN;\n" + sql + "\nCOMMIT;")
        except sqlite3.Error:
            self.db.rollback()
            raise
        if self.lose_success_response:
            self.lose_success_response = False
            raise OSError("synthetic lost response")
        return [{"success": True}]

    def seed_legacy(self):
        self.db.executescript(BASELINE.decode("utf-8"))

    def insert_subscription(self):
        self.db.execute("""INSERT INTO subscriptions
          (id, owner_id, name, source_url, token, created_at, updated_at)
          VALUES (2, '42', 'Synthetic', 'https://provider.example.invalid/list', 'synthetic-token-0001', 1, 1)""")

    def table_exists(self, name):
        return self.db.execute("SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


class MigrationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory(prefix="subs-d1-migrations-")
        self.addCleanup(directory.cleanup)
        self.bundle = Path(directory.name)
        self.api = FakeD1()
        self.addCleanup(self.api.db.close)
        self.guard_calls = 0
        self.manifest = {"version": 2, "migrations": []}
        self.add_file(BASELINE_NAME, BASELINE)

    def add_file(self, name, data):
        (self.bundle / name).write_bytes(data)
        self.manifest["migrations"].append({"name": name, "sha256": hashlib.sha256(data).hexdigest()})

    def guard(self):
        self.guard_calls += 1

    def apply(self, *, guard=None):
        return apply_migrations(self.api, TARGET, self.bundle, self.manifest, guard or self.guard)

    def test_fresh_applies_exact_chain_and_repeat_does_no_writes(self):
        self.add_file(NEXT_NAME, NEXT_SQL)
        expected = [{**item, "mode": "applied"} for item in self.manifest["migrations"]]
        self.assertEqual(self.apply(), expected)
        self.assertTrue(self.api.table_exists("subscriptions"))
        self.assertTrue(self.api.table_exists("test_messages"))
        self.api.db.execute("INSERT INTO test_messages (actor_id) VALUES ('42')")
        self.assertEqual(self.api.db.execute("SELECT marker FROM test_messages").fetchone()[0], "first;second")
        self.assertEqual(self.apply(), expected)
        self.assertEqual(len(self.api.mutations), 2)
        self.assertEqual(self.guard_calls, 2)

    def test_repository_migration_chain_applies_and_repeats_without_writes(self):
        # Match the production D1 limit, including autoindexes on long table names.
        self.api.db.setlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 50)
        for file in sorted((WORKER / "migrations").glob("*.sql")):
            if file.name != BASELINE_NAME:
                self.add_file(file.name, file.read_bytes())

        expected = [{**item, "mode": "applied"} for item in self.manifest["migrations"]]
        self.assertEqual(self.apply(), expected)
        self.assertEqual(self.apply(), expected)
        self.assertEqual(len(self.api.mutations), len(expected))
        self.assertEqual(self.guard_calls, len(expected))
        self.assertEqual(self.api.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_legacy_adopts_0001_without_replay_or_reset_and_applies_next(self):
        self.api.seed_legacy()
        self.api.insert_subscription()
        self.api.db.execute("DELETE FROM subscriptions WHERE id = 2")
        self.api.executed.clear()
        self.add_file(NEXT_NAME, NEXT_SQL)
        result = self.apply()
        self.assertEqual([item["mode"] for item in result], ["adopted", "applied"])
        self.assertFalse(any(sql.startswith("CREATE TABLE subscriptions") for sql in self.api.executed))
        self.assertEqual(self.api.db.execute("SELECT seq FROM sqlite_sequence WHERE name = 'subscriptions'").fetchone()[0], 2)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 0)
        self.assertEqual(self.guard_calls, 2)

    def test_missing_index_or_partial_state_is_never_repaired(self):
        self.api.seed_legacy()
        self.api.db.execute("DROP INDEX subscriptions_owner_id")
        with self.assertRaisesRegex(MigrationError, "original 0001 schema"):
            self.apply()
        self.assertFalse(self.api.table_exists(LEDGER))
        self.assertEqual(self.api.mutations, [])
        self.assertEqual(self.guard_calls, 0)

    def test_wrong_database_identity_fails_before_queries_or_writes(self):
        self.api.metadata["created_at"] = "2026-07-31T00:00:00.000Z"
        with self.assertRaisesRegex(MigrationError, "identity does not match"):
            self.apply()
        self.assertEqual(self.api.mutations, [])
        self.assertEqual(self.guard_calls, 0)

    def test_untracked_subscription_rows_prevent_adoption(self):
        self.api.seed_legacy()
        self.api.insert_subscription()
        with self.assertRaisesRegex(MigrationError, "contains subscription rows"):
            self.apply()
        self.assertEqual(self.api.mutations, [])
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 1)

    def test_transaction_rechecks_legacy_empty_state_after_operator_guard(self):
        self.api.seed_legacy()
        with self.assertRaisesRegex(MigrationError, "state could not be verified"):
            self.apply(guard=self.api.insert_subscription)
        self.assertFalse(self.api.table_exists(LEDGER))
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 1)

    def test_failure_after_pending_ddl_leaves_verified_prior_state_and_retries(self):
        applied = self.apply()
        self.add_file(NEXT_NAME, NEXT_SQL)
        self.api.fail_before_ledger = True
        with self.assertRaisesRegex(MigrationError, "prior state is safe to retry"):
            self.apply()
        self.assertFalse(self.api.table_exists("test_messages"))
        self.assertEqual(self.api.db.execute(f"SELECT count(*) FROM {LEDGER}").fetchone()[0], len(applied))
        self.api.fail_before_ledger = False
        self.assertEqual(len(self.apply()), 2)

    def test_lost_success_response_is_reconciled_from_exact_ledger_and_schema(self):
        self.api.lose_success_response = True
        self.assertEqual(self.apply()[0]["mode"], "applied")
        self.assertEqual(len(self.api.mutations), 1)
        self.assertEqual(self.apply()[0]["mode"], "applied")
        self.assertEqual(len(self.api.mutations), 1)

    def test_wrong_history_digest_and_untracked_schema_stop_before_more_writes(self):
        self.apply()
        self.add_file(NEXT_NAME, NEXT_SQL)
        self.api.db.execute(f"UPDATE {LEDGER} SET sha256 = ? WHERE position = 1", ("0" * 64,))
        with self.assertRaisesRegex(MigrationError, "history differs"):
            self.apply()
        self.api.db.execute(f"UPDATE {LEDGER} SET sha256 = ? WHERE position = 1", (self.manifest["migrations"][0]["sha256"],))
        self.api.db.execute("CREATE TABLE test_messages (id INTEGER PRIMARY KEY)")
        with self.assertRaisesRegex(MigrationError, "schema differs"):
            self.apply()
        self.assertEqual(len(self.api.mutations), 1)

    def test_artifact_changes_and_destructive_sql_are_rejected_before_any_writes(self):
        self.add_file(NEXT_NAME, b"CREATE TABLE test_messages (id INTEGER PRIMARY KEY);\nDROP TABLE subscriptions;\n")
        with self.assertRaisesRegex(MigrationError, "Only additive"):
            self.apply()
        (self.bundle / BASELINE_NAME).write_bytes(BASELINE + b"\n")
        with self.assertRaisesRegex(MigrationError, "artifact digest does not match"):
            self.apply()
        self.assertEqual(self.api.mutations, [])
        self.assertEqual(self.guard_calls, 0)


if __name__ == "__main__":
    unittest.main()

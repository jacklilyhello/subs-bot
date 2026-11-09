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

from d1_migrations import (  # noqa: E402
    BASELINE_NAME, LEDGER, MAX_D1_STATEMENT_BYTES, MAX_MIGRATION_BYTES, MigrationError, SchemaObject,
    _matches_schema, _statements, apply_migrations,
)


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


def sized_budget_ddl(size, padding):
    head = b"CREATE TABLE test_budget (id INTEGER PRIMARY KEY, marker TEXT NOT NULL DEFAULT '"
    tail = b"') STRICT;\n"
    repeats, leftover = divmod(size - len(head) - len(tail), len(padding))
    return head + padding * repeats + b"x" * leftover + tail


class FakeD1:
    def __init__(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("CREATE TABLE _cf_KV (key TEXT PRIMARY KEY, value BLOB) WITHOUT ROWID")
        self.metadata = {"uuid": TARGET["d1Id"], "name": "subs-bot-cf-dev-01", "created_at": TARGET["d1CreatedAt"]}
        self.path = f"/accounts/{TARGET['accountId']}/d1/database/{TARGET['d1Id']}"
        self.mutations = []
        self.reads = []
        self.executed = []
        self.db.set_trace_callback(self.executed.append)
        self.fail_before_ledger = False
        self.lose_success_response = False
        self.rewrite_batch = None

    def __call__(self, method, path, payload=None):
        if method == "GET" and path == self.path:
            return self.metadata
        if method != "POST" or path != self.path + "/query" or set(payload) != {"sql"}:
            raise AssertionError("unexpected D1 request")
        sql = payload["sql"]
        statements = list(_statements(sql if sql.endswith(";") else sql + ";"))
        if any(len(statement.encode("utf-8")) >= MAX_D1_STATEMENT_BYTES for statement in statements):
            raise AssertionError("oversized D1 statement")
        if not sql.startswith("SELECT CASE WHEN"):
            self.reads.append(statements)
            self.db.execute("BEGIN")
            try:
                return [{"success": True, "results": [dict(row) for row in self.db.execute(statement)]}
                        for statement in statements]
            finally:
                self.db.rollback()

        self.mutations.append(sql)
        if self.rewrite_batch:
            sql = self.rewrite_batch(sql)
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
        # Match D1 limits for the full schema and ledger guard and generated index names.
        self.api.db.setlimit(sqlite3.SQLITE_LIMIT_LIKE_PATTERN_LENGTH, 50)
        self.api.db.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 100)
        for file in sorted((WORKER / "migrations").glob("*.sql")):
            if file.name != BASELINE_NAME:
                self.add_file(file.name, file.read_bytes())

        expected = [{**item, "mode": "applied"} for item in self.manifest["migrations"]]
        self.assertEqual(self.apply(), expected)
        self.assertEqual(self.apply(), expected)
        self.assertEqual(len(self.api.mutations), len(expected))
        self.assertEqual(self.guard_calls, len(expected))
        batches = [list(_statements(sql)) for sql in self.api.mutations]
        guards = [sql for batch in batches for sql in batch if sql.startswith("SELECT CASE WHEN")]
        self.assertGreaterEqual(len(guards), 2 * len(expected))
        self.assertLess(max(len(sql.encode("utf-8")) for sql in guards), MAX_D1_STATEMENT_BYTES)
        read_migration = next(i for i, item in enumerate(expected) if item["name"] == "0018_telegram_subscription_reads.sql")
        batch = batches[read_migration]
        first_ddl = next(i for i, sql in enumerate(batch) if sql.startswith("CREATE TABLE"))
        self.assertNotIn("telegram_subscription_read_ticket", "\n".join(batch[:first_ddl]))
        self.assertTrue(any("telegram_subscription_read_ticket" in sql for sql in batch[first_ddl:]
                            if sql.startswith("SELECT CASE WHEN")))
        self.assertEqual(self.api.db.execute("PRAGMA foreign_key_check").fetchall(), [])

    def test_exact_cumulative_cap_above_64_kib_applies_and_reads_back(self):
        self.assertEqual(MAX_MIGRATION_BYTES, 72 * 1024)
        self.add_file("0002_budget.sql", sized_budget_ddl(MAX_MIGRATION_BYTES - len(BASELINE), "é".encode()))
        expected = [{**item, "mode": "applied"} for item in self.manifest["migrations"]]
        self.assertEqual(self.apply(), expected)
        self.assertEqual(self.apply(), expected)
        self.assertTrue(self.api.table_exists("test_budget"))
        self.assertEqual(len(self.api.mutations), 2)
        self.assertTrue(any(64 * 1024 < len(sql.encode("utf-8")) < MAX_D1_STATEMENT_BYTES
                            for sql in self.api.executed if sql.startswith("SELECT (")))

    def test_cumulative_cap_plus_one_fails_before_any_api_request(self):
        self.add_file("0002_budget.sql", sized_budget_ddl(MAX_MIGRATION_BYTES - len(BASELINE) + 1, b"x"))

        def unreachable(*_args):
            self.fail("Oversized artifact reached the D1 API.")

        with self.assertRaisesRegex(MigrationError, "Migration SQL exceeds the isolation tool's size limit"):
            apply_migrations(unreachable, TARGET, self.bundle, self.manifest, self.guard)
        self.assertEqual(self.guard_calls, 0)

    def test_late_guard_overflow_blocks_earlier_pending_transactions(self):
        self.add_file(NEXT_NAME, NEXT_SQL)
        # Quoting this valid DDL for the exact schema predicate doubles its apostrophes.
        self.add_file("0003_budget.sql", sized_budget_ddl(MAX_MIGRATION_BYTES - len(BASELINE) - len(NEXT_SQL), b"''"))
        with self.assertRaisesRegex(MigrationError, "D1 migration guard exceeds statement limits"):
            self.apply()
        self.assertEqual(self.api.mutations, [])
        self.assertEqual(self.guard_calls, 0)
        self.assertFalse(self.api.table_exists("subscriptions"))

    def test_oversized_schema_readback_stops_before_query(self):
        ddl = sized_budget_ddl(MAX_MIGRATION_BYTES, b"''").decode().rstrip(";\n")
        object_to_check = SchemaObject("table", "test_budget", "test_budget", ddl)
        with self.assertRaisesRegex(MigrationError, "D1 schema readback exceeds statement limits"):
            _matches_schema(self.api, self.api.path, (object_to_check,))
        self.assertEqual(self.api.executed, [])
        self.assertEqual(self.api.mutations, [])

    def test_split_post_guards_rollback_together_and_readback_checks_every_group(self):
        large_ddl = sized_budget_ddl(34 * 1024, b"''")
        self.add_file("0002_split.sql", large_ddl + large_ddl.replace(b"test_budget", b"test_budget_second", 1))
        # Keep the schema count and names exact while changing the later object's SQL.
        self.api.rewrite_batch = lambda sql: sql.replace(
            "CREATE TABLE test_budget_second (id INTEGER PRIMARY KEY, marker TEXT",
            "CREATE TABLE test_budget_second (id INTEGER PRIMARY KEY, altered TEXT", 1,
        )
        with self.assertRaisesRegex(MigrationError, "prior state is safe to retry"):
            self.apply()
        self.assertFalse(self.api.table_exists("test_budget"))
        self.assertFalse(self.api.table_exists("test_budget_second"))
        self.assertEqual(self.api.db.execute(f"SELECT count(*) FROM {LEDGER}").fetchone()[0], 1)
        failed_batch = list(_statements(self.api.mutations[-1]))
        after_ddl = next(i for i, sql in enumerate(failed_batch) if sql.startswith("CREATE TABLE test_budget_second")) + 1
        self.assertGreaterEqual(len(failed_batch[after_ddl:-1]), 2)
        self.assertTrue(all(sql.startswith("SELECT CASE WHEN") for sql in failed_batch[after_ddl:-1]))
        self.assertIn("test_budget_second", failed_batch[-2])

        self.api.rewrite_batch = None
        expected = [{**item, "mode": "applied"} for item in self.manifest["migrations"]]
        self.assertEqual(self.apply(), expected)
        self.assertEqual(self.apply(), expected)
        self.assertTrue(any(len(batch) > 1 for batch in self.api.reads))
        self.api.db.execute("ALTER TABLE test_budget_second RENAME COLUMN marker TO altered")
        with self.assertRaisesRegex(MigrationError, "schema differs"):
            self.apply()
        self.assertEqual(len(self.api.mutations), 3)

    def test_managed_transaction_rechecks_exact_ledger_after_operator_guard(self):
        self.apply()
        self.add_file(NEXT_NAME, NEXT_SQL)

        def change_history():
            self.api.db.execute(f"UPDATE {LEDGER} SET sha256 = ? WHERE position = 1", ("0" * 64,))

        with self.assertRaisesRegex(MigrationError, "state could not be verified"):
            self.apply(guard=change_history)
        self.assertFalse(self.api.table_exists("test_messages"))
        self.assertEqual(self.api.db.execute(f"SELECT count(*) FROM {LEDGER}").fetchone()[0], 1)

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

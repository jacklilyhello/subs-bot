"""Hosted regression for complete current-schema legacy oracle SQL admission."""

from pathlib import Path
from runpy import run_path
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ORACLE = run_path(str(Path(__file__).with_name("legacy-selected-short-oracle.integration.py")), run_name="oracle_sql_bounds")
PACKAGE = ORACLE["package"]


class OracleSqlBoundsTests(unittest.TestCase):
    def read_statements(self, sql):
        descriptor = {"path": PACKAGE.SQL, "bytes": len(sql), "sha256": PACKAGE.native.digest(sql)}
        manifest = PACKAGE.native.canonical({"sql": descriptor})
        candidate = SimpleNamespace(candidate=Path("/synthetic-private-candidate"), candidate_sha256=PACKAGE.native.digest(manifest))
        with patch.object(PACKAGE, "read_pinned", side_effect=[manifest, sql]):
            return ORACLE["sql_statements"](candidate)

    def test_current_v11_schema_above_256_statements_is_not_truncated(self):
        statements = [f"INSERT INTO synthetic_fixture VALUES ({index});\n" for index in range(259)]
        self.assertEqual(self.read_statements("".join(statements).encode()), statements)

    def test_emitted_worker_statement_bound_is_preserved(self):
        raw = b"INSERT INTO synthetic_fixture VALUES (1);\n"
        self.assertEqual(len(self.read_statements(raw * 512)), 512)
        with self.assertRaisesRegex(ORACLE["OracleError"], "^candidate-sql-statements$"):
            self.read_statements(raw * 513)

    def test_incomplete_final_statement_cannot_be_silently_discarded(self):
        with self.assertRaisesRegex(ORACLE["OracleError"], "^candidate-sql-statements$"):
            self.read_statements(b"INSERT INTO synthetic_fixture VALUES (1);\nINSERT INTO synthetic_fixture VALUES (")

    def test_literal_semicolon_does_not_split_one_statement(self):
        raw = b"INSERT INTO synthetic_fixture VALUES ('a;b');\n"
        self.assertEqual(self.read_statements(raw), [raw.decode()])


if __name__ == "__main__":
    unittest.main()

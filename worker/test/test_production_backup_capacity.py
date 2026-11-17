"""Synthetic read-only capacity checks; executed only by hosted CI."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_capacity as capacity


class Source:
    tables = list(capacity.PROJECTIONS) + ["telegram_inbox", "sqlite_sequence"]

    def schema(self):
        return []


class API:
    target = {"d1Id": "synthetic-database", "bucketName": "synthetic-bucket"}

    def __init__(self, counts=None):
        self.counts = counts or {}

    def rows(self, database, sql, parameters=()):
        assert database == self.target["d1Id"]
        if sql.startswith("SELECT count(*)"):
            table = sql.split('"')[1]
            return [{"n": self.counts.get(table, 0)}]
        assert sql.startswith("SELECT ")
        return []


class CapacityTests(unittest.TestCase):
    def test_thresholds_have_explicit_boundary_behavior(self):
        self.assertEqual(capacity.level(79, 100, 80), "normal")
        self.assertEqual(capacity.level(80, 100, 80), "warning")
        self.assertEqual(capacity.level(100, 100, 80), "warning")
        self.assertEqual(capacity.level(101, 100, 80), "over-limit")

    def test_empty_database_observation_includes_every_table(self):
        result = capacity.observe(API(), Source())
        self.assertEqual(result["tableCounts"], {table: 0 for table in Source.tables})
        self.assertEqual(result["objectCount"], 0)
        self.assertEqual(result["objectStatus"], "normal")
        self.assertFalse(result["snapshot"])
        self.assertFalse(result["backupVerified"])
        self.assertIsNone(result["sqlBytes"])

    def test_whole_database_limit_does_not_pretend_r2_was_checked(self):
        result = capacity.observe(API({"telegram_inbox": 20001}), Source())
        self.assertEqual(result["rowStatus"], "over-limit")
        self.assertEqual(result["objectStatus"], "not-checked")
        self.assertEqual(result["rows"], 20001)

    def test_513th_reference_reports_over_limit_without_partial_pass(self):
        def closure(_db, _read, *, observe_reference):
            observe_reference(513)
            raise AssertionError("the capacity guard should have stopped the scan")
        with patch.object(capacity.native, "object_references", side_effect=closure):
            result = capacity.observe(API(), Source())
        self.assertEqual(result["objectStatus"], "over-limit")
        self.assertEqual(result["objectCount"], 513)
        self.assertTrue(result["objectCountIsLowerBound"])
        self.assertFalse(result["backupVerified"])


if __name__ == "__main__":
    unittest.main()

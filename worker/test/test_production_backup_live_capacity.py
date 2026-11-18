"""Periodic capacity estimates remain read-only and fail closed on drift."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_live_capacity as live
from production_target import ContractError


class LiveCapacityTests(unittest.TestCase):
    def sample(self, changed=False):
        target = Mock(environment="rehearsal", digest="a" * 64, configuration_digest="b" * 64)
        target.data = {"d1Id": "db", "d1Name": "db-name", "d1CreatedAt": "created", "botId": "1",
                       "generation": 1, "bucketName": "nodes", "bucketCreatedAt": "bucket-date",
                       "backupBucketName": "backup", "backupBucketCreatedAt": "backup-date"}
        control = {"target_sha256": target.digest, "bot_id": "1", "release_revision": "c" * 40,
                   "generation": 1, "epoch": 1, "admission": "open", "workers": "run"}
        api = Mock(source="/accounts/a/d1/database/db")
        api.json.return_value = {"uuid": "db", "name": "db-name", "created_at": "created"}
        def read(_database, sql, *_args):
            if sql.startswith("SELECT target_sha256"):
                return [control]
            if sql.startswith('SELECT count(*)'):
                return [{"n": 2 if changed else 1}]
            raise AssertionError("unexpected read")
        api.rows.side_effect = read
        source = {"sourceTarget": Mock(configuration_digest=target.configuration_digest),
                  "manifest": {"revision": "c" * 40}, "bundle": Path("/synthetic")}
        schema = Mock(tables=["subscriptions"])
        observed = {"snapshot": False, "consistency": "unfrozen-observation", "rows": 1,
                    "tableCounts": {"subscriptions": 1}, "rowStatus": "normal", "objectStatus": "normal",
                    "objectBytesStatus": "normal", "backupVerified": False}
        with tempfile.TemporaryDirectory() as directory, patch.object(live, "load_release", return_value=source), \
             patch.object(live, "ReadOnlyRecoveryAPI", return_value=api), \
             patch.object(live.recovery, "RecoverySource", return_value=schema), \
             patch.object(live.capacity, "observe", return_value=observed):
            result = live.sample(target, "synthetic-read-token", "d" * 32, "e" * 64,
                                 warning_percent=80, root=directory, guard=lambda: None)
        return result, api

    def test_complete_observation_is_explicitly_not_a_snapshot(self):
        result, api = self.sample()
        self.assertIs(result["snapshot"], False)
        self.assertNotIn("tableCounts", result)
        self.assertEqual(live.alerts(result), [])
        self.assertEqual(api.json.call_args.args[0], "GET")

    def test_changed_row_count_is_unknown_not_success(self):
        result, _api = self.sample(changed=True)
        self.assertEqual(result["failureReason"], "source-changed-during-scan")
        self.assertIn("live-capacity-unknown", live.alerts(result))

    def test_limit_and_incomplete_object_scan_both_alert(self):
        self.assertEqual(live.alerts({"rowStatus": "warning", "objectStatus": "normal", "objectBytesStatus": "normal"}),
                         ["live-capacity-near-limit"])
        self.assertEqual(live.alerts({"rowStatus": "over-limit", "objectStatus": "not-checked", "objectBytesStatus": None}),
                         ["live-capacity-over-limit", "live-capacity-unknown"])

    def test_schedule_is_configurable_without_guessing_runner_time(self):
        self.assertTrue(live.due("workflow_dispatch", "", 60))
        self.assertTrue(live.due("schedule", "18 * * * *", 15))
        self.assertFalse(live.due("schedule", "18 * * * *", 30))
        self.assertTrue(live.due("schedule", "33 * * * *", 30))
        self.assertFalse(live.due("schedule", "33 * * * *", 60))
        with self.assertRaises(ContractError):
            live.due("schedule", "unexpected", 15)
        with self.assertRaises(ContractError):
            live.due("schedule", "3 * * * *", 20)


if __name__ == "__main__":
    unittest.main()

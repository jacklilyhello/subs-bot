"""Synthetic checks for production backup approval and window boundaries."""
from datetime import datetime, timezone
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_cli as backup
from production_target import ContractError


class ProductionBackupTests(unittest.TestCase):
    def setUp(self):
        self.policy = {"version": 1, "warningPercent": 80, "pauseLimitSeconds": 300,
                       "overdueHours": 48, "windowStartUtc": "23:30", "windowMinutes": 90, "frequencyHours": 24}

    def test_explicit_policy_and_cross_midnight_window(self):
        self.assertEqual(backup.settings(json.dumps(self.policy)), self.policy)
        self.assertTrue(backup.in_window(self.policy, datetime(2026, 1, 2, 0, 30, tzinfo=timezone.utc)))
        self.assertFalse(backup.in_window(self.policy, datetime(2026, 1, 2, 1, 0, tzinfo=timezone.utc)))
        for update in ({"warningPercent": 100}, {"pauseLimitSeconds": 0}, {"windowMinutes": 0}, {"frequencyHours": 0}):
            with self.subTest(update=update), self.assertRaises(ContractError):
                backup.settings(json.dumps({**self.policy, **update}))

    def test_unknown_predecessor_cannot_authorize_writes(self):
        with self.assertRaises(ContractError):
            backup.exact_predecessor({"BACKUP_STATE_SHA256": "a" * 64}, {"stateSha256": "b" * 64})

    def test_active_journal_required_and_bound_to_anchor(self):
        anchor = Mock()
        anchor.read.return_value = ({"state": "idle"}, b"", '"etag"')
        with self.assertRaises(ContractError):
            backup.active_transaction(anchor, Mock(), Mock())

    def test_invalid_or_unresolved_stage_cannot_progress(self):
        with self.assertRaises(ContractError):
            backup.last([{"stage": "capture-intent"}], "verified")

    def test_approval_is_passed_through_without_synthesis(self):
        target, envelope = Mock(), '{"explicit":"approval"}'
        with patch.object(backup, "approve") as approve:
            backup.authorized(target, {"SUBS_BOT_APPROVAL_JSON": envelope}, "pause", "a" * 40, "b" * 64, "c" * 40)
        approve.assert_called_once_with(target, envelope, "pause", "a" * 40, "b" * 64, control_revision="c" * 40)

    def test_latest_aborted_backup_alerts_even_if_not_overdue(self):
        anchor, store, target = Mock(), Mock(), Mock()
        target.digest = "a" * 64
        current = {"generation": 3, "state": "idle", "session": "1-1", "day": "2026/01/01",
                   "controlRevision": "b" * 40, "previousSha256": "c" * 64}
        previous = {"generation": 2, "state": "idle", "session": "2-1", "day": "2026/01/01",
                    "controlRevision": "b" * 40, "previousSha256": "d" * 64}
        anchor.read.return_value = (current, b"", "etag")
        anchor.history_digest_key.side_effect = lambda generation, pin: str(generation)
        store.get.side_effect = lambda key: backup.canonical(previous if key == "2" else {"generation": 1})
        normal = {"rowStatus": "normal", "objectStatus": "normal", "objectBytesStatus": "normal"}
        failed = [{"stage": "preflight", "timestamp": 1000, "details": {"capacity": normal}}, {"stage": "failed", "timestamp": 1000, "details": {}}]
        success = [{"stage": "verified", "timestamp": 999}, {"stage": "resumed", "timestamp": 999, "details": {}}]
        with patch.object(backup.maintenance, "Transaction") as transaction:
            transaction.side_effect = lambda _store, session, *_: Mock(load=Mock(return_value=failed if session == "1-1" else success))
            result = backup.monitor_anchor(anchor, store, target, self.policy, 1000)
        self.assertIn("backup-failed", result["alerts"])
        self.assertNotIn("backup-overdue", result["alerts"])

    def test_transition_reconciliation_requires_exact_successor_and_finished_run(self):
        previous = {"admission": "open", "workers": "run", "epoch": 8}
        details = {"control": previous, "runAttempt": "1", "runId": "123", "controlRevision": "a" * 40}
        events = [{"details": {"release": {"revision": "b"}, "configurationSha256": "c"}},
                  {"stage": "pause-intent", "details": details}]
        state = {"control": {**previous, "admission": "closed", "epoch": 9}, "release": {"revision": "b"},
                 "configurationSha256": "c", "stateSha256": "d" * 64}
        with patch.object(backup, "require_finished_intent") as finished:
            result = backup.transition_reconciliation({}, events, state, {"checkpointId": "e"})
            self.assertEqual(result["phase"], "pause-intent")
            finished.assert_called_once_with(details)
            with self.assertRaises(ContractError):
                backup.transition_reconciliation({}, events, {**state, "control": previous}, {"checkpointId": "e"})

    def test_monitor_rejects_future_journal_time(self):
        pin = {"generation": 2, "state": "active", "session": "1-1", "day": "2026/01/01",
               "controlRevision": "b" * 40, "previousSha256": "c" * 64}
        anchor, store, target = Mock(), Mock(), Mock(digest="a" * 64)
        anchor.read.return_value = (pin, b"", "etag")
        anchor.history_digest_key.return_value = "previous"
        store.get.return_value = backup.canonical({"generation": 1})
        with patch.object(backup.maintenance, "Transaction") as transaction:
            transaction.return_value.load.return_value = [{"stage": "started", "timestamp": 1001, "details": {}}]
            with self.assertRaises(ContractError):
                backup.monitor_anchor(anchor, store, target, self.policy, 1000)

    def test_failed_run_before_anchor_is_visible_even_with_recent_backup(self):
        revision, now = "a" * 40, 1800000000
        workflow = {"id": 123, "path": ".github/workflows/worker-production-backup.yml"}
        run = {"id": 456, "run_attempt": 1, "workflow_id": 123, "head_branch": "main", "head_sha": revision,
               "event": "workflow_dispatch", "repository": {"id": backup.artifact.REPOSITORY_ID},
               "head_repository": {"id": backup.artifact.REPOSITORY_ID},
               "display_title": "Production backup begin at " + revision,
               "updated_at": datetime.fromtimestamp(now - 1, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "status": "completed", "conclusion": "failure"}
        def github(path, _token):
            if "?" not in path:
                return workflow
            return {"total_count": 1, "workflow_runs": [run]}
        with patch.object(backup.artifact, "_github_token", return_value="synthetic"), \
             patch.object(backup.artifact, "_get_json", side_effect=github):
            result = backup.monitor_workflow_runs(json.dumps({"version": 1, "revisions": [revision]}), now, now - 100)
            self.assertTrue(result["failed"])
            self.assertFalse(result["unknown"])
            unknown = backup.monitor_workflow_runs(json.dumps({"version": 1, "revisions": ["b" * 40]}), now, now - 100)
            self.assertTrue(unknown["unknown"])
            missing = backup.monitor_workflow_runs(json.dumps({"version": 1, "revisions": [revision]}), now, now - 100, "999")
            self.assertTrue(missing["unknown"])

    def test_missing_or_incomplete_workflow_history_is_unknown(self):
        controllers = json.dumps({"version": 1, "revisions": ["a" * 40]})
        workflow = {"id": 123, "path": ".github/workflows/worker-production-backup.yml"}
        def empty(path, _token):
            return workflow if "?" not in path else {"total_count": 0, "workflow_runs": []}
        with patch.object(backup.artifact, "_github_token", return_value="synthetic"), \
             patch.object(backup.artifact, "_get_json", side_effect=empty):
            self.assertTrue(backup.monitor_workflow_runs(controllers, 1800000000, None)["unknown"])
        def incomplete(path, _token):
            return workflow if "?" not in path else {"total_count": 2, "workflow_runs": [{}]}
        with patch.object(backup.artifact, "_github_token", return_value="synthetic"), \
             patch.object(backup.artifact, "_get_json", side_effect=incomplete):
            with self.assertRaises(ContractError):
                backup.monitor_workflow_runs(controllers, 1800000000, None)

    def test_production_mutation_is_statically_disabled_before_any_setup(self):
        with patch.object(backup, "validate_target", return_value=Mock()), patch.object(backup, "check_context", return_value="a" * 40):
            with self.assertRaises(ContractError):
                backup.main({"BACKUP_ACTION": "resume-failed", "GITHUB_RUN_ATTEMPT": "1"})

    def test_failed_resume_does_not_record_intent_when_approval_rejected(self):
        ctl, record = Mock(), Mock()
        ctl.approval.side_effect = ContractError("invalid approval")
        plan = {"approvalAction": "maintenance-resume-drain:" + "a" * 64, "stateSha256": "b" * 64}
        with patch.object(backup.resume, "plan_aborted_drain", return_value=plan), \
             patch.object(backup.resume, "_commit") as commit:
            with self.assertRaises(ContractError):
                backup.resume.resume_aborted_drain(ctl, initial={}, paused={}, session="1-1",
                                                   approval_envelope="unapproved", record_intent=record)
        ctl.approval.assert_called_once_with("unapproved", plan["approvalAction"], plan["stateSha256"])
        record.assert_not_called()
        commit.assert_not_called()

    def test_failed_resume_never_writes_if_recheck_changes(self):
        ctl, record = Mock(), Mock()
        plan = {"approvalAction": "maintenance-resume-drain:" + "a" * 64, "stateSha256": "b" * 64}
        with patch.object(backup.resume, "plan_aborted_drain", side_effect=[plan, {**plan, "stateSha256": "c" * 64}]), \
             patch.object(backup.resume, "_commit") as commit:
            with self.assertRaises(ContractError):
                backup.resume.resume_aborted_drain(ctl, initial={}, paused={}, session="1-1",
                                                   approval_envelope="explicit", record_intent=record)
        record.assert_called_once_with(plan["stateSha256"], plan["approvalAction"])
        commit.assert_not_called()

    def test_public_result_does_not_disclose_controller_state(self):
        target = Mock(digest="a" * 64)
        with tempfile.TemporaryDirectory() as directory, patch.object(backup.artifact, "require_current_main"):
            result = backup.emit_result({"status": "observed", "action": "inspect", "state": {
                "stateSha256": "b" * 64, "control": {"bot_id": "sensitive"}}}, target, "c" * 40, Path(directory))
            saved = (Path(directory) / "production-backup-result.json").read_text()
        self.assertEqual(result["stateSha256"], "b" * 64)
        self.assertNotIn("sensitive", saved)
        self.assertNotIn("control", result)


if __name__ == "__main__":
    unittest.main()

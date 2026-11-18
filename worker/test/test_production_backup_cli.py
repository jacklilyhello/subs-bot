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
from test_production_backup_transaction import Store


class ProductionBackupTests(unittest.TestCase):
    def test_unstarted_abort_requires_exact_original_writer_and_unchanged_state(self):
        target = Mock(digest="a" * 64, configuration_digest="c" * 64)
        store = Store()
        initial = backup.maintenance.Anchor(store, target.digest, "0" * 64)
        genesis = backup.recovery.digest(initial.initial_material()[1])
        anchor = backup.maintenance.Anchor(store, target.digest, genesis)
        anchor.initialize()
        before_pin, before_raw, before_etag = anchor.read()
        policy = {"pauseLimitSeconds": 300}
        contract = {"checkpointId": "e" * 32}
        state = {"stateSha256": "d" * 64, "control": {"admission": "open", "workers": "run"},
                 "release": {"revision": "f" * 40}, "configurationSha256": target.configuration_digest, "terminal": {}}
        details = {"configurationSha256": target.configuration_digest, "control": state["control"], "release": state["release"],
                   "pauseLimitSeconds": 300, "checkpointId": contract["checkpointId"],
                   "contractSha256": backup.digest(contract), "policySha256": backup.digest(policy)}
        original = {"version": 1, "targetSha256": target.digest, "session": "123-1", "day": "2026/11/17",
            "controlRevision": "b" * 40, "dispatcherRevision": "b" * 40, "dispatcherWorkflow": "worker-production-backup.yml",
            "writerRunId": "456", "writerAttempt": "1", "anchorPredecessorSha256": backup.recovery.digest(before_raw),
            "stateSha256": state["stateSha256"], "sourceRevision": "f" * 40, "approvalSha256": "e" * 64,
            "timestamp": 100, "startedDetails": details}
        backup.maintenance.write_begin(store, original)
        ctl = Mock(revision="f" * 40, control_revision="b" * 40)
        ctl.inspect.return_value = state
        with patch.object(backup, "require_finished_intent") as finished:
            with patch.object(store, "compare_and_put", side_effect=ContractError("response unknown")):
                with self.assertRaises(ContractError):
                    anchor._advance(before_pin, before_raw, before_etag, state="active", session="123-1", day="2026/11/17", revision="b" * 40)
            future = [key for key in store.list_backup_anchor_history(target.digest) if "/000000000002-" in key]
            self.assertEqual(len(future), 1)
            candidate = future[0].rsplit("-", 1)[1][:-5]
            planned, _, _ = backup.unstarted_abort_plan(anchor, store, target, ctl, contract, policy, candidate_sha=candidate)
            self.assertEqual(planned["candidateSha256"], candidate)
            anchor.reconcile(candidate, planned["anchorPlanSha256"])
            plan, _, journal = backup.unstarted_abort_plan(anchor, store, target, ctl, contract, policy)
            self.assertTrue(plan["approvalAction"].startswith("backup-abort-unstarted:"))
            self.assertEqual(journal.load(), [])
            self.assertEqual(finished.call_count, 2)
            ctl.inspect.return_value = {**state, "stateSha256": "0" * 64}
            with self.assertRaises(ContractError):
                backup.unstarted_abort_plan(anchor, store, target, ctl, contract, policy)
            ctl.inspect.return_value = state
            backup.maintenance.claim_begin_reconciliation(store, target.digest, "123-1", {"writerRunId": "789"})
            with self.assertRaises(ContractError):
                backup.unstarted_abort_plan(anchor, store, target, ctl, contract, policy)
        with patch.object(backup, "require_finished_intent", side_effect=ContractError("writer still active")):
            with self.assertRaises(ContractError):
                backup.unstarted_abort_plan(anchor, store, target, ctl, contract, policy)
        self.assertEqual(anchor.read()[0]["state"], "active")

    def test_production_mutation_switch_defaults_off_and_rejects_reruns(self):
        for env in ({}, {"GITHUB_RUN_ATTEMPT": "1"},
                    {"GITHUB_RUN_ATTEMPT": "2", "SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED": "true"},
                    {"GITHUB_RUN_ATTEMPT": "1", "SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED": "True"}):
            with self.assertRaises(ContractError):
                backup.require_mutation_enabled(env)
        backup.require_mutation_enabled({"GITHUB_RUN_ATTEMPT": "1", "SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED": "true"})

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

    def test_pause_alarm_is_distinct_from_bounded_maximum(self):
        legacy = backup.settings(json.dumps(self.policy))
        self.assertEqual(legacy, self.policy)
        self.assertEqual(backup.maximum_pause(legacy), 1800)
        extended = backup.settings(json.dumps({**self.policy, "maximumPauseSeconds": 3600}))
        self.assertEqual(backup.maximum_pause(extended), 3600)
        for value in (True, 299, 21601):
            with self.subTest(value=value), self.assertRaises(ContractError):
                backup.settings(json.dumps({**self.policy, "maximumPauseSeconds": value}))
        events = [{"stage": "pause-intent", "timestamp": 1000}]
        with patch.object(backup.time, "time", return_value=1301):
            backup.require_pause_window(events, legacy)  # the 300s alert is not a hard stop
        with patch.object(backup.time, "time", return_value=2800), self.assertRaises(ContractError):
            backup.require_pause_window(events, legacy)

    def test_maximum_uses_the_journaled_session_value_with_legacy_default(self):
        event = {"stage": "started", "details": {"pauseLimitSeconds": 300, "maximumPauseSeconds": 3600}}
        self.assertEqual(backup.session_maximum([event]), 3600)
        del event["details"]["maximumPauseSeconds"]
        self.assertEqual(backup.session_maximum([event]), 1800)
        event["details"]["maximumPauseSeconds"] = True
        with self.assertRaises(ContractError):
            backup.session_maximum([event])

    def test_unknown_predecessor_cannot_authorize_writes(self):
        with self.assertRaises(ContractError):
            backup.exact_predecessor({"BACKUP_STATE_SHA256": "a" * 64}, {"stateSha256": "b" * 64})

    def test_active_journal_required_and_bound_to_anchor(self):
        anchor = Mock()
        anchor.read.return_value = ({"state": "idle"}, b"", '"etag"')
        with self.assertRaises(ContractError):
            backup.active_transaction(anchor, Mock(), Mock())

    def test_missing_started_remains_read_only_unknown(self):
        pin = {"state": "active", "session": "123-1", "day": "2026/11/17", "controlRevision": "a" * 40}
        anchor, store, target = Mock(), Mock(), Mock(digest="b" * 64)
        anchor.read.return_value = (pin, b"", '"etag"')
        with patch.object(backup.maintenance, "Transaction") as transaction:
            transaction.return_value.load.return_value = []
            result = backup.missing_started_observation(anchor, store, target)
            self.assertEqual(result["status"], "unknown")
            self.assertIs(result["mutationPermitted"], False)
            transaction.return_value.load.return_value = [{"stage": "started"}]
            with self.assertRaises(ContractError):
                backup.missing_started_observation(anchor, store, target)
        anchor.reconcile.assert_not_called()
        store.put.assert_not_called()

    def test_invalid_or_unresolved_stage_cannot_progress(self):
        with self.assertRaises(ContractError):
            backup.last([{"stage": "capture-intent"}], "verified")

    def test_ambiguous_edit_failure_blocks_frozen_maintenance(self):
        events = [{"stage": "started", "details": {"configurationSha256": "a", "release": {}}},
                  {"stage": "frozen", "details": {"control": {"epoch": 1}}}]
        state = {"control": {"epoch": 1}, "configurationSha256": "a", "release": {}, "work": {},
                 "terminal": {"terminalEditFailure": 1}}
        with self.assertRaises(ContractError):
            backup.frozen_matches(events, state)

    def test_uncaptured_predecessor_requires_finished_freeze_and_no_capture_intent(self):
        frozen = {"admission": "closed", "workers": "frozen", "epoch": 3}
        events = [{"stage": "freeze-intent", "details": {"runId": "123"}},
                  {"stage": "frozen", "details": {"control": frozen}}]
        with patch.object(backup, "require_finished_intent") as finished:
            self.assertEqual(backup.uncaptured_predecessor(events), (frozen, None))
            finished.assert_called_once_with(events[0]["details"], allowed_actions={"freeze"})
            self.assertEqual(backup.uncaptured_predecessor([*events, {"stage": "failed", "details": {"uncertain": False}}]), (frozen, None))
            fingerprint = {"dataSha256": "f" * 64}
            self.assertEqual(backup.uncaptured_predecessor([*events, {"stage": "frozen-data", "details": fingerprint},
                {"stage": "failed", "details": {"uncertain": False}}]), (frozen, fingerprint))
            for bad in (events + [{"stage": "capture-intent", "details": {}}],
                        [*events, {"stage": "failed", "details": {}}],
                        [*events, {"stage": "failed", "details": {"uncertain": True}}]):
                with self.assertRaises(ContractError):
                    backup.uncaptured_predecessor(bad)

    def test_uncaptured_resume_requires_empty_recovery_journal_and_exact_recheck(self):
        ctl, journal = Mock(), Mock(value=None)
        initial = {"control": {"admission": "open", "workers": "run"}}
        frozen = {"admission": "closed", "workers": "frozen", "epoch": 3}
        with patch.object(backup.resume, "_target"), patch.object(backup.resume, "_quiet_state", return_value={"stateSha256": "b" * 64}), \
             patch.object(backup.resume, "_dependencies"), patch.object(backup.resume, "_commit") as commit:
            plan = backup.resume.plan_uncaptured_backup(ctl, Mock(), Mock(), journal, initial=initial,
                                                        frozen=frozen, fingerprint=None, session="123-1")
            self.assertTrue(plan["approvalAction"].startswith("maintenance-resume-uncaptured:"))
            journal.value = {"export": {"state": "unknown"}}
            with self.assertRaises(ContractError):
                backup.resume.plan_uncaptured_backup(ctl, Mock(), Mock(), journal, initial=initial,
                                                    frozen=frozen, fingerprint=None, session="123-1")
            commit.assert_not_called()

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

    def test_monitor_uses_active_session_pause_limits_after_policy_changes(self):
        pin = {"generation": 2, "state": "active", "session": "1-1", "day": "2026/01/01",
               "controlRevision": "b" * 40, "previousSha256": "c" * 64}
        anchor, store, target = Mock(), Mock(), Mock(digest="a" * 64)
        anchor.read.return_value = (pin, b"", '"etag"')
        anchor.history_digest_key.return_value = "previous"
        store.get.return_value = backup.canonical({"generation": 1})
        events = [{"stage": "started", "timestamp": 1000,
                   "details": {"pauseLimitSeconds": 60, "maximumPauseSeconds": 300}},
                  {"stage": "pause-intent", "timestamp": 1000, "details": {}}]
        with patch.object(backup.maintenance, "Transaction") as transaction:
            transaction.return_value.load.return_value = events
            result = backup.monitor_anchor(anchor, store, target,
                                           {**self.policy, "maximumPauseSeconds": 3600}, 1301)
        self.assertIn("pause-limit-exceeded", result["alerts"])
        self.assertIn("pause-maximum-exceeded", result["alerts"])

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

    def test_anchor_reconciliation_rejects_unfinished_or_changed_successor(self):
        target, ctl, anchor, store = Mock(digest="a" * 64), Mock(), Mock(), Mock()
        contract, policy = {"checkpointId": "e" * 32}, self.policy
        candidate = {"state": "idle", "session": "123-1", "day": "2026/11/17", "controlRevision": "b" * 40}
        anchor.plan_reconciliation.return_value = ({"candidate": candidate}, b"old", '"etag"', b"new")
        state = {"control": {"admission": "open", "workers": "run", "epoch": 4}, "release": {"revision": "c"},
                 "configurationSha256": "d", "stateSha256": "e" * 64, "work": {}, "terminal": {}}
        ctl.inspect.return_value = state
        events = [{"stage": "started", "details": {"contractSha256": backup.digest(contract), "policySha256": backup.digest(policy),
                   "release": state["release"], "configurationSha256": "d"}},
                  {"stage": "resume-intent", "details": {"runId": "123"}},
                  {"stage": "resumed", "details": {"control": state["control"]}}]
        with patch.object(backup.maintenance, "Transaction") as transaction, patch.object(backup, "require_finished_intent") as finished:
            transaction.return_value.load.return_value = events
            result = backup.completed_anchor_reconciliation(anchor, store, target, ctl, "f" * 64, contract, policy)
            self.assertEqual(result["stateSha256"], state["stateSha256"])
            finished.assert_called_once_with(events[-2]["details"], allowed_actions={"activate", "resume-failed"})
            ctl.inspect.return_value = {**state, "control": {**state["control"], "epoch": 5}}
            with self.assertRaises(ContractError):
                backup.completed_anchor_reconciliation(anchor, store, target, ctl, "f" * 64, contract, policy)
            transaction.return_value.load.return_value = events[:-1]
            with self.assertRaises(ContractError):
                backup.completed_anchor_reconciliation(anchor, store, target, ctl, "f" * 64, contract, policy)
        anchor.reconcile.assert_not_called()

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

    def test_seven_days_of_monitor_runs_do_not_hide_a_failed_checkpoint(self):
        from urllib.parse import parse_qs, urlsplit
        revision, now = "a" * 40, 1800000000
        workflow = {"id": 123, "path": ".github/workflows/worker-production-backup.yml"}
        template = {"run_attempt": 1, "workflow_id": 123, "head_branch": "main", "head_sha": revision,
                    "event": "schedule", "repository": {"id": backup.artifact.REPOSITORY_ID},
                    "head_repository": {"id": backup.artifact.REPOSITORY_ID},
                    "display_title": "Production backup monitor at " + revision,
                    "updated_at": datetime.fromtimestamp(now - 1, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "status": "completed", "conclusion": "success"}
        rows = [{**template, "id": index + 1} for index in range(672)]
        rows.append({**template, "id": 673, "event": "workflow_dispatch",
                     "display_title": "Production backup begin at " + revision, "conclusion": "failure"})
        calls = []
        def github(path, _token):
            if "?" not in path:
                return workflow
            query = parse_qs(urlsplit(path).query)
            self.assertEqual(query["per_page"], ["50"])
            page = int(query["page"][0])
            calls.append(page)
            return {"total_count": len(rows), "workflow_runs": rows[(page - 1) * 50:page * 50]}
        controllers = json.dumps({"version": 1, "revisions": [revision]})
        with patch.object(backup.artifact, "_github_token", return_value="synthetic"), \
             patch.object(backup.artifact, "_get_json", side_effect=github):
            result = backup.monitor_workflow_runs(controllers, now, now - 100)
            self.assertEqual(result["runsObserved"], 673)
            self.assertTrue(result["failed"])
            self.assertFalse(result["unknown"])
            self.assertEqual(calls, list(range(1, 15)))
            rows[50] = {**rows[50], "id": rows[0]["id"]}
            with self.assertRaises(ContractError):
                backup.monitor_workflow_runs(controllers, now, now - 100)
            def at_bound(path, token):
                response = github(path, token)
                if "?" in path:
                    response["total_count"] = 1000
                return response
            with patch.object(backup.artifact, "_get_json", side_effect=at_bound), self.assertRaises(ContractError):
                backup.monitor_workflow_runs(controllers, now, now - 100)

    def test_production_mutation_is_disabled_by_default_before_any_setup(self):
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

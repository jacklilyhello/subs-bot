"""Hosted fault checks for production backup coordinator evidence."""
from pathlib import Path
from hashlib import sha256
from io import BytesIO
import sys
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_coordinator as coordinator
import production_backup_cli as cli
from production_target import ContractError, canonical


class CoordinatorTests(unittest.TestCase):
    def archive(self, result):
        raw = BytesIO()
        with ZipFile(raw, "w") as archive:
            archive.writestr("production-backup-result.json", canonical(result))
        return raw.getvalue()

    def intent(self):
        return coordinator.dispatch_intent(target="a" * 64, session="123", sequence=1,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")

    def test_single_use_intent_is_read_back_and_existing_intent_cannot_be_reissued(self):
        value = self.intent()
        store = Mock()
        store.get.side_effect = [(None, None), (canonical(value), '"etag"')]
        coordinator.write_dispatch_once(store, value)
        store.put_once.assert_called_once_with(coordinator.event_key("a" * 64, "123", 1), canonical(value))
        store.reset_mock()
        store.get.side_effect = None
        store.get.return_value = (canonical(value), '"etag"')
        with self.assertRaises(ContractError):
            coordinator.write_dispatch_once(store, value)
        store.put_once.assert_not_called()

    def test_uncertain_write_and_missing_receipt_never_allow_dispatch(self):
        value = self.intent()
        store = Mock()
        store.get.return_value = (None, None)
        store.put_once.side_effect = RuntimeError("unconfirmed")
        with self.assertRaises(RuntimeError):
            coordinator.write_dispatch_once(store, value)
        store.put_once.assert_called_once()
        store.get.side_effect = [(canonical(value), '"etag"'), (None, None), (None, None)]
        result = coordinator.inspect_stage(store, "a" * 64, "123", 1)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["dispatchPermitted"])

    def test_receipt_never_substitutes_for_gh_run_verification(self):
        value = self.intent()
        result_value = {"action": "plan-begin"}
        original = self.archive(result_value)
        done = coordinator.receipt(value, "456", result_value, "789", sha256(original).hexdigest())
        store = Mock()
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(done), '"etag"'), (original, '"etag"')]
        result = coordinator.inspect_stage(store, "a" * 64, "123", 1)
        self.assertEqual(result["status"], "receipt-needs-independent-run-verification")
        self.assertFalse(result["dispatchPermitted"])
        self.assertEqual(result["runId"], "456")

    def test_receipt_preserves_canonical_result_and_rejects_replacement(self):
        value = self.intent()
        result = {"action": "plan-begin", "stateSha256": "e" * 64}
        original = self.archive(result)
        saved = coordinator.receipt(value, "456", result, "789", sha256(original).hexdigest())
        self.assertEqual(saved["result"], result)
        changed = {**saved, "result": {"action": "plan-begin", "stateSha256": "f" * 64}}
        store = Mock()
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(changed), '"etag"'), (original, '"etag"')]
        with self.assertRaises(ContractError):
            coordinator.inspect_stage(store, "a" * 64, "123", 1)

    def test_pause_deadline_starts_before_dispatch_and_rejects_future_intent(self):
        value = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        self.assertEqual(coordinator.pause_deadline(value, 900, now=1005), 1900)
        with self.assertRaises(ContractError):
            coordinator.pause_deadline(value, 900, now=900)

    def test_stage_inputs_bind_prior_predecessor_and_source(self):
        from hashlib import sha256
        prior = [{"action": "plan-begin", "status": "plan-only", "session": "456-1",
                  "day": "2026/11/18", "stateSha256": "e" * 64}]
        intent = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=2,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        value, deadline = coordinator.stage_inputs(prior, "1" * 32, "2" * 64, "123", intent, 900, None)
        self.assertIsNone(deadline)
        self.assertEqual(value["state_sha256"], "e" * 64)
        changed, _ = coordinator.stage_inputs([{**prior[0], "stateSha256": "f" * 64}],
                                               "1" * 32, "2" * 64, "123", intent, 900, None)
        self.assertNotEqual(sha256(canonical(value)).hexdigest(), sha256(canonical(changed)).hexdigest())
        changed_source, _ = coordinator.stage_inputs(prior, "1" * 32, "3" * 64, "123", intent, 900, None)
        self.assertNotEqual(sha256(canonical(value)).hexdigest(), sha256(canonical(changed_source)).hexdigest())

    def test_resume_writer_claim_does_not_retry_an_existing_or_ambiguous_slot(self):
        history = {"writers": [], "lastSha256": "e" * 64}
        store = Mock()
        store.get.return_value = (b"existing", '"etag"')
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(store, "a" * 64, "123", "b" * 40, history, "456")
        store.put_once.assert_not_called()
        store.get.return_value = (None, None)
        store.put_once.side_effect = RuntimeError("unknown response")
        with self.assertRaises(RuntimeError):
            coordinator.claim_resume_writer(store, "a" * 64, "123", "b" * 40, history, "456")
        store.put_once.assert_called_once()
        store.put_once.reset_mock(side_effect=True)
        store.get.return_value = (b"competing writer", '"etag"')
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(store, "a" * 64, "123", "b" * 40, history, "457", action="reconcile")
        store.put_once.assert_not_called()

    def test_legacy_begin_intent_can_identify_nonce_named_writer(self):
        title = "Production backup begin at " + "b" * 40 + " #" + "c" * 64
        self.assertEqual(cli.run_action(title, "b" * 40), "begin")
        self.assertEqual(cli.run_action(title, "b" * 40, nonce="c" * 64), "begin")
        with self.assertRaises(ContractError):
            cli.run_action(title, "b" * 40, nonce="d" * 64)

    def test_finished_legacy_begin_keeps_full_run_identity_checks(self):
        revision, nonce = "b" * 40, "c" * 64
        workflow = {"id": 7, "path": ".github/workflows/worker-production-backup.yml"}
        run = {"id": 456, "run_attempt": 1, "workflow_id": 7, "event": "workflow_dispatch",
               "head_branch": "main", "head_sha": revision, "status": "completed",
               "display_title": "Production backup begin at " + revision + " #" + nonce,
               "repository": {"id": cli.artifact.REPOSITORY_ID}, "head_repository": {"id": cli.artifact.REPOSITORY_ID}}
        details = {"runId": "456", "runAttempt": "1", "controlRevision": revision}
        def checked(candidate, provided=details):
            with patch.object(cli.artifact, "_github_token", return_value="token"), \
                 patch.object(cli.artifact, "_get_json", side_effect=[candidate, workflow]):
                cli.require_finished_intent(provided, allowed_actions={"begin"})
        checked(run)
        for change in ({"id": 457}, {"run_attempt": 2}, {"head_sha": "d" * 40}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                checked({**run, **change})
        with self.assertRaises(ContractError):
            checked(run, {**details, "dispatchNonce": "d" * 64})

    def test_expired_dispatched_pause_is_rejected_but_activation_is_allowed(self):
        from hashlib import sha256
        target, store = Mock(digest="a" * 64), Mock()
        pause = coordinator.dispatch_intent(target=target.digest, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        env = {"GITHUB_SHA": "b" * 40, "BACKUP_ACTION": "pause", "BACKUP_DISPATCH_NONCE": "c" * 64,
               "BACKUP_COORDINATOR_SESSION": "123", "BACKUP_DISPATCH_DEADLINE": "1060",
               "BACKUP_SOURCE_CHECKPOINT_ID": "e" * 32, "BACKUP_SOURCE_MANIFEST_SHA256": "f" * 64,
               "BACKUP_SESSION": "456-1", "BACKUP_SESSION_DAY": "2026/11/18", "BACKUP_STATE_SHA256": "1" * 64}
        inputs = {"action": "pause", "source_checkpoint_id": "e" * 32, "source_manifest_sha256": "f" * 64,
                  "dispatch_nonce": "c" * 64, "coordinator_session": "123", "dispatch_deadline": "1060",
                  "session": "456-1", "session_day": "2026/11/18", "state_sha256": "1" * 64}
        pause["inputSha256"] = sha256(canonical(inputs)).hexdigest()
        store.objects.get.return_value = (canonical(pause), '"etag"')
        parent = {"id": 789, "run_attempt": 1, "path": ".github/workflows/worker-production-backup-coordinator.yml",
                  "head_sha": "b" * 40, "head_branch": "main", "event": "workflow_dispatch", "status": "in_progress",
                  "display_title": "Production backup coordinator run at " + "b" * 40,
                  "repository": {"id": cli.artifact.REPOSITORY_ID}, "head_repository": {"id": cli.artifact.REPOSITORY_ID}}
        jobs = {"total_count": 1, "jobs": [{"name": "coordinate", "run_id": 789, "run_attempt": 1,
                "head_sha": "b" * 40, "status": "in_progress", "conclusion": None,
                "steps": [{"name": "Coordinate one explicitly approved operation", "status": "in_progress", "conclusion": None}]}]}
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[parent, jobs, {**parent, "status": "completed"}]):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            with self.assertRaises(ContractError):
                guard()
        resumed = {**parent, "display_title": "Production backup coordinator resume at " + "b" * 40}
        with patch.object(cli.time, "time", return_value=1001) as clock, \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[resumed, jobs]):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            clock.return_value = 1061
            with self.assertRaises(ContractError):
                guard()
        ended = {"total_count": 1, "jobs": [{**jobs["jobs"][0],
                 "steps": [{"name": "Coordinate one explicitly approved operation", "status": "completed", "conclusion": "failure"}]}]}
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[parent, ended]), \
             self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        for change in ({"run_attempt": 2}, {"head_sha": "d" * 40}, {"repository": {"id": -1}}):
            with self.subTest(change=change), patch.object(cli.time, "time", return_value=1001), \
                 patch.object(cli.artifact, "_github_token", return_value="token"), \
                 patch.object(cli.artifact, "_get_json", return_value={**parent, **change}), \
                 self.assertRaises(ContractError):
                cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=OSError("unavailable")), \
             self.assertRaises(OSError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        with patch.object(cli.time, "time", return_value=1001), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", return_value={"id": 789, "status": "completed"}), \
             self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        with patch.object(cli.time, "time", return_value=1061), self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        env["BACKUP_ACTION"] = "activate"
        inputs["action"] = "activate"
        activate = coordinator.dispatch_intent(target=target.digest, session="123", sequence=11,
            revision="b" * 40, nonce="c" * 64, input_sha256=sha256(canonical(inputs)).hexdigest(), created_at=1050, writer_run_id="789")
        store.objects.get.side_effect = [(canonical(activate), '"etag"'), (canonical(pause), '"etag"')]
        with patch.object(cli.time, "time", return_value=1061):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            guard()

    def test_abort_rejects_a_child_that_has_not_finished(self):
        from hashlib import sha256
        target, objects, app_store = Mock(digest="a" * 64), Mock(), Mock()
        provisional = coordinator.dispatch_intent(target=target.digest, session="123", sequence=1,
            revision="b" * 40, nonce="c" * 64, input_sha256="0" * 64, created_at=1000, writer_run_id="789")
        inputs, _ = coordinator.stage_inputs([], "1" * 32, "2" * 64, "123", provisional, 900, None)
        intent = {**provisional, "inputSha256": sha256(canonical(inputs)).hexdigest()}
        objects.get.return_value = (canonical(intent), '"etag"')
        workflow = {"path": ".github/workflows/worker-production-backup.yml", "id": 7}
        with patch.object(coordinator.artifact, "_github_token", return_value="token"), \
             patch.object(coordinator.artifact, "_get_json", return_value=workflow), \
             patch.object(coordinator, "inspect_stage", return_value={"status": "unknown"}), \
             patch.object(coordinator, "discover_run", return_value={"id": 456, "status": "in_progress"}), \
             self.assertRaises(ContractError):
            coordinator.abort_observation(objects, app_store, target, "123", "b" * 40,
                                          "1" * 32, "2" * 64, 900, "3" * 64)
        app_store.get.assert_not_called()

    def test_run_discovery_queries_a_bounded_window_and_requires_complete_pages(self):
        from urllib.parse import parse_qs, urlsplit
        value = self.intent()
        row = {"created_at": "1970-01-01T00:16:40Z"}
        first = {"total_count": 101, "workflow_runs": [row] * 100}
        second = {"total_count": 101, "workflow_runs": [row]}
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, second]) as read, \
             patch.object(coordinator, "matching_run", return_value={"id": 456}) as match:
            self.assertEqual(coordinator.discover_run(value, 7, "token"), {"id": 456})
        query = parse_qs(urlsplit(read.call_args_list[0].args[0]).query)
        self.assertEqual(query["created"], ["1970-01-01T00:14:40Z..1970-01-02T00:16:40Z"])
        self.assertEqual(len(match.call_args.args[0]), 101)
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, {**second, "total_count": 102}]), \
             self.assertRaises(ContractError):
            coordinator.discover_run(value, 7, "token")


if __name__ == "__main__":
    unittest.main()

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
    def test_scheduled_monitor_checks_environment_before_read_credentials(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-production-backup-coordinator.yml").read_text()
        monitor = workflow.split("  monitor:\n", 1)[1]
        job_condition = monitor.split("    environment:", 1)[0]
        self.assertNotIn("vars.SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_MONITOR_ENABLED", job_condition)
        self.assertIn("MONITOR_ENABLED: ${{ vars.SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_MONITOR_ENABLED }}", monitor)
        self.assertIn("echo 'status=disabled'", monitor)
        self.assertEqual(monitor.count("if: steps.gate.outputs.enabled == 'true'"), 2)

    def test_backup_run_name_quotes_nonce_expression(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-production-backup.yml").read_text()
        run_name = next(line for line in workflow.splitlines() if line.startswith("run-name:"))
        self.assertTrue(run_name.startswith('run-name: "') and run_name.endswith('"'))
        self.assertIn("format(' #{0}', inputs.dispatch_nonce)", run_name)

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
        store.get.side_effect = [(canonical(value), '"etag"'), (None, None), (None, None), (None, None)]
        result = coordinator.inspect_stage(store, "a" * 64, "123", 1)
        self.assertEqual(result["status"], "unknown")
        self.assertFalse(result["dispatchPermitted"])

    def test_receipt_never_substitutes_for_gh_run_verification(self):
        value = self.intent()
        result_value = {"action": "plan-begin"}
        original = self.archive(result_value)
        done = coordinator.receipt(value, "456", result_value, "789", sha256(original).hexdigest())
        store = Mock()
        claim = canonical(coordinator.child_claim(value, "456", "1"))
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(done), '"etag"'), (original, '"etag"'), (claim, '"etag"')]
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
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(changed), '"etag"'), (original, '"etag"'), (None, None)]
        with self.assertRaises(ContractError):
            coordinator.inspect_stage(store, "a" * 64, "123", 1)

    def test_child_claim_is_single_use_and_bound_to_the_exact_run(self):
        value = self.intent()
        store = Mock()
        raw = canonical(coordinator.child_claim(value, "456", "1"))
        store.get.side_effect = [(None, None), (raw, '"etag"')]
        coordinator.claim_child_once(store, value, "456", "1")
        store.put_once.assert_called_once_with(coordinator.child_claim_key("a" * 64, "123", 1), raw)
        store.get.side_effect = None
        store.get.return_value = (raw, '"etag"')
        coordinator.verify_child_claim(store, value, "456")
        with self.assertRaises(ContractError):
            coordinator.verify_child_claim(store, value, "457")
        store.put_once.reset_mock()
        with self.assertRaises(ContractError):
            coordinator.claim_child_once(store, value, "457", "1")
        store.put_once.assert_not_called()

    def test_child_claim_unknown_write_never_retries_or_accepts_receipt(self):
        value = self.intent()
        store = Mock()
        store.get.return_value = (None, None)
        store.put_once.side_effect = RuntimeError("uncertain conditional write")
        with self.assertRaises(RuntimeError):
            coordinator.claim_child_once(store, value, "456", "1")
        store.put_once.assert_called_once()
        result = {"action": "plan-begin"}
        original = self.archive(result)
        done = coordinator.receipt(value, "456", result, "789", sha256(original).hexdigest())
        store.get.side_effect = [(canonical(value), '"etag"'), (canonical(done), '"etag"'), (original, '"etag"'), (None, None)]
        with self.assertRaises(ContractError):
            coordinator.inspect_stage(store, "a" * 64, "123", 1)

    def test_pause_deadline_starts_before_dispatch_and_rejects_future_intent(self):
        value = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        self.assertEqual(coordinator.pause_deadline(value, 900, now=1005), 1900)
        with self.assertRaises(ContractError):
            coordinator.pause_deadline(value, 900, now=900)

    def test_drain_cannot_hold_the_parent_past_pause_deadline(self):
        self.assertEqual(coordinator.checkpoint_wait_deadline("drain", 5000, 1100, now=1050, monotonic_now=2000), 2050)
        with self.assertRaises(ContractError):
            coordinator.checkpoint_wait_deadline("drain", 5000, 1100, now=1100, monotonic_now=2000)
        self.assertEqual(coordinator.checkpoint_wait_deadline("activate", 5000, 1100, now=1101, monotonic_now=2000), 5000)

    def test_alarm_threshold_does_not_become_the_maximum_pause(self):
        intent = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        maximum = coordinator.pause_deadline(intent, 1800, now=1301)
        self.assertEqual(maximum, 2800)
        self.assertEqual(coordinator.checkpoint_wait_deadline("drain", 5000, maximum, now=1301, monotonic_now=2000), 3499)

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

    def test_rehearsal_binds_real_dispatcher_and_separate_candidate(self):
        value = coordinator.dispatch_intent(target="a" * 64, session="123", sequence=1,
            revision="b" * 40, candidate_revision="c" * 40, profile="rehearsal", nonce="d" * 64,
            input_sha256="e" * 64, created_at=1000, writer_run_id="789")
        self.assertEqual(value["controllerRevision"], "b" * 40)
        self.assertEqual(value["candidateRevision"], "c" * 40)
        self.assertEqual(coordinator.child_title(value), "Rehearsal backup plan-begin at " + "b" * 40
                         + " candidate " + "c" * 40 + " #" + "d" * 64)
        inputs, _ = coordinator.stage_inputs([], "1" * 32, "2" * 64, "123", value, 900, None,
                                              validation_json='{"version":1}')
        self.assertEqual(inputs["validation_json"], '{"version":1}')
        with self.assertRaises(ContractError):
            coordinator.dispatch_intent(target="a" * 64, session="123", sequence=1, revision="b" * 40,
                candidate_revision="c" * 40, profile="production", nonce="d" * 64,
                input_sha256="e" * 64, created_at=1000, writer_run_id="789")

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

    def test_recovery_writer_uses_the_same_exclusive_slot_and_is_rehearsal_only(self):
        history = {"writers": [], "lastSha256": "c" * 64}
        store = Mock()
        objects = {}
        store.get.side_effect = lambda key, **_: (objects.get(key), '"etag"')
        store.put_once.side_effect = lambda key, body: objects.update({key: body})
        args = (store, "a" * 64, "123", "b" * 40, history, "456")
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(*args, action="recovery", recovery_action="resume-failed", recovery_plan_sha="d" * 64)
        coordinator.claim_resume_writer(*args, action="recovery", profile="rehearsal", candidate_revision="e" * 40,
                                        recovery_action="resume-failed", recovery_plan_sha="d" * 64)
        with self.assertRaises(ContractError):
            coordinator.claim_resume_writer(*args, action="resume", profile="rehearsal", candidate_revision="e" * 40)
        self.assertEqual(store.put_once.call_count, 1)

    def test_only_exact_in_progress_recovery_writer_can_extend_a_stopped_chain(self):
        target, revision, candidate, session = "a" * 64, "b" * 40, "c" * 40, "123"
        source, manifest, policy, validation, plan = "d" * 32, "e" * 64, "f" * 64, "1" * 64, "2" * 64
        start = {"version": 1, "action": "run", "targetSha256": target, "controlRevision": revision,
                 "session": session, "sourceCheckpointId": source, "sourceManifestSha256": manifest,
                 "anchorSha256": "3" * 64, "policySha256": policy, "writerRunId": "700", "writerAttempt": "1",
                 "profile": "rehearsal", "candidateRevision": candidate, "validationSha256": validation}
        writer = {"version": 1, "targetSha256": target, "session": session, "controlRevision": revision,
                  "position": 1, "previousSha256": sha256(canonical(start)).hexdigest(), "writerRunId": "701",
                  "writerAttempt": "1", "action": "recovery", "profile": "rehearsal", "candidateRevision": candidate,
                  "recoveryAction": "resume-failed", "recoveryPlanSha256": plan}
        base = coordinator.BASE + target + "/" + session + "/"
        objects = {base + "start-intent.json": canonical(start), base + "writers/0001.json": canonical(writer)}
        store = Mock()
        store.get.side_effect = lambda key, **_: (objects[key], '"etag"')
        store.list.return_value = [base + "writers/0001.json"]
        repo = {"id": coordinator.artifact.REPOSITORY_ID}
        original = {"id": 700, "head_sha": revision, "path": coordinator.PROFILES["rehearsal"]["parent"],
                    "display_title": coordinator.parent_title("rehearsal", "run", revision, candidate), "event": "workflow_dispatch",
                    "head_branch": "main", "status": "completed", "run_attempt": 1, "repository": repo, "head_repository": repo}
        current = {**original, "id": 701, "path": ".github/workflows/worker-backup-phase-recovery.yml", "status": "in_progress",
                   "display_title": "Rehearsal backup recovery resume-failed at " + revision + " candidate " + candidate + " session " + session}
        names = ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                 "Verify isolated recovery test Bot identity", "Plan or execute one reviewed recovery phase")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names[:-1]]
        steps.append({"name": names[-1], "status": "in_progress", "conclusion": None})
        job = {"name": "recovery", "run_id": 701, "run_attempt": 1, "head_sha": revision, "status": "in_progress", "steps": steps}
        job_list = [job]
        def api(path, _token):
            if path.endswith("/jobs?per_page=100"):
                return {"total_count": len(job_list), "jobs": job_list}
            return original if "/700" in path else current
        env = {"GITHUB_RUN_ID": "701", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": revision,
               "GITHUB_WORKFLOW_REF": coordinator.artifact.REPOSITORY + "/.github/workflows/worker-backup-phase-recovery.yml@" + coordinator.artifact.MAIN_REF,
               "BACKUP_ACTION": "resume-failed", "BACKUP_RECOVERY_PLAN_SHA256": plan, "BACKUP_GATE_ROLE": "recovery"}
        args = (store, target, session, revision, source, manifest, policy)
        kwargs = {"profile": "rehearsal", "candidate_revision": candidate, "validation_sha": validation}
        with patch.dict("os.environ", env, clear=True), patch.object(coordinator.artifact, "_github_token", return_value="synthetic"), \
             patch.object(coordinator.artifact, "_get_json", side_effect=api):
            result = coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            self.assertEqual(result["writers"], [writer])
            objects[base + "writers/0001.json"] = canonical({**writer, "version": True})
            with self.assertRaises(ContractError):
                coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            objects[base + "writers/0001.json"] = canonical(writer)
            with self.assertRaises(ContractError):
                coordinator.finished_controller(*args, **kwargs)
            with patch.dict("os.environ", {"BACKUP_RECOVERY_PLAN_SHA256": "9" * 64}):
                with self.assertRaises(ContractError):
                    coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            steps[-1] = {"name": names[-1], "status": "completed", "conclusion": "failure"}
            with self.assertRaises(ContractError):
                coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="execute")
            steps[-1]["conclusion"] = "success"
            job["status"] = "completed"
            job["conclusion"] = "success"
            read_names = ("Verify recovery readback identity before candidate checkout", "Verify exact reviewed recovery readback checkout",
                          "Verify recovery readback test Bot identity", "Independently read back the recovery evidence")
            read_steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in read_names[:-1]]
            read_steps.append({"name": read_names[-1], "status": "in_progress", "conclusion": None})
            job_list.append({"name": "readback", "run_id": 701, "run_attempt": 1, "head_sha": revision,
                             "status": "in_progress", "steps": read_steps})
            with patch.dict("os.environ", {"BACKUP_GATE_ROLE": "recovery-readback", "BACKUP_RECOVERY_MODE": "readback"}):
                coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="readback")
                read_steps[0]["conclusion"] = "failure"
                with self.assertRaises(ContractError):
                    coordinator.finished_controller(*args, **kwargs, current_writer=writer, current_mode="readback")

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

    @patch.object(coordinator, "stage_inputs")
    @patch.object(coordinator, "completed_results")
    @patch.object(coordinator, "verify_child_claim")
    @patch.object(coordinator, "claim_child_once")
    def test_expired_dispatched_pause_is_rejected_but_activation_is_allowed(self, _claim, _verify, completed, stage):
        from hashlib import sha256
        target, store = Mock(digest="a" * 64), Mock()
        pause = coordinator.dispatch_intent(target=target.digest, session="123", sequence=5,
            revision="b" * 40, nonce="c" * 64, input_sha256="d" * 64, created_at=1000, writer_run_id="789")
        env = {"GITHUB_SHA": "b" * 40, "GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "1", "BACKUP_ACTION": "pause", "BACKUP_DISPATCH_NONCE": "c" * 64,
               "BACKUP_COORDINATOR_SESSION": "123", "BACKUP_DISPATCH_DEADLINE": "1060",
               "BACKUP_SOURCE_CHECKPOINT_ID": "e" * 32, "BACKUP_SOURCE_MANIFEST_SHA256": "f" * 64,
               "BACKUP_SESSION": "456-1", "BACKUP_SESSION_DAY": "2026/11/18", "BACKUP_STATE_SHA256": "1" * 64}
        inputs = {"action": "pause", "source_checkpoint_id": "e" * 32, "source_manifest_sha256": "f" * 64,
                  "dispatch_nonce": "c" * 64, "coordinator_session": "123", "dispatch_deadline": "1060",
                  "session": "456-1", "session_day": "2026/11/18", "state_sha256": "1" * 64}
        completed.side_effect = lambda *_args, **kwargs: ([{}] * (kwargs["stop_before"] - 1), 1060)
        stage.side_effect = lambda *_args, **_kwargs: (dict(inputs), 1060)
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
             patch.object(cli.artifact, "_get_json", side_effect=[parent, jobs, parent, jobs, {**parent, "status": "completed"}]):
            guard = cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
            with self.assertRaises(ContractError):
                guard()
        resumed = {**parent, "display_title": "Production backup coordinator resume at " + "b" * 40}
        with patch.object(cli.time, "time", return_value=1001) as clock, \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[resumed, jobs, resumed, jobs]):
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
        with patch.object(cli.time, "time", return_value=1061), \
             patch.object(cli.artifact, "_github_token", return_value="token"), self.assertRaises(ContractError):
            cli.coordinator_guard(env, target, store, {"pauseLimitSeconds": 60}, lambda: None)
        env["BACKUP_ACTION"] = "activate"
        inputs["action"] = "activate"
        activate = coordinator.dispatch_intent(target=target.digest, session="123", sequence=11,
            revision="b" * 40, nonce="c" * 64, input_sha256=sha256(canonical(inputs)).hexdigest(), created_at=1050, writer_run_id="789")
        store.objects.get.side_effect = [(canonical(activate), '"etag"'), (canonical(pause), '"etag"')]
        with patch.object(cli.time, "time", return_value=1061), \
             patch.object(cli.artifact, "_github_token", return_value="token"), \
             patch.object(cli.artifact, "_get_json", side_effect=[parent, jobs, parent, jobs, parent, jobs]):
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
        rows = [{"id": index + 1, "created_at": "1970-01-01T00:16:40Z"} for index in range(51)]
        first = {"total_count": 51, "workflow_runs": rows[:50]}
        second = {"total_count": 51, "workflow_runs": rows[50:]}
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, second]) as read, \
             patch.object(coordinator, "matching_run", return_value={"id": 456}) as match:
            self.assertEqual(coordinator.discover_run(value, 7, "token"), {"id": 456})
        query = parse_qs(urlsplit(read.call_args_list[0].args[0]).query)
        self.assertEqual(query["created"], ["1970-01-01T00:14:40Z..1970-01-02T00:16:40Z"])
        self.assertEqual(query["per_page"], ["50"])
        self.assertEqual(len(match.call_args.args[0]), 51)
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, {**second, "total_count": 52}]), \
             self.assertRaises(ContractError):
            coordinator.discover_run(value, 7, "token")
        with patch.object(coordinator.artifact, "_get_json", side_effect=[first, {**second, "workflow_runs": [rows[0]]}]), \
             self.assertRaises(ContractError):
            coordinator.discover_run(value, 7, "token")


if __name__ == "__main__":
    unittest.main()

"""Hosted checks for fixed-source rehearsal recovery planning."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_rehearsal_recovery as recovery
from production_target import ContractError, canonical, digest


class RehearsalRecoveryTests(unittest.TestCase):
    def test_owned_writer_preserves_approved_complete_predecessor_chain(self):
        original = {"startSha256": "1" * 64, "lastSha256": "2" * 64, "writers": [{"prior": True}]}
        writer = {"previousSha256": original["lastSha256"], "writerRunId": "123"}
        current = {"startSha256": original["startSha256"], "lastSha256": "3" * 64,
                   "writers": [*original["writers"], writer]}
        spec = {"sourceCheckpointId": "4" * 32, "sourceManifestSha256": "5" * 64}
        plan = {"writerHistorySha256": digest(original)}
        with patch.object(recovery.core, "finished_controller", return_value=current):
            self.assertEqual(recovery.require_owned_writer(object(), "a" * 64, "456", "b" * 40, "c" * 40,
                spec, {"pauseLimitSeconds": 300}, "{}", writer, plan, mode="execute"), current)
            with self.assertRaises(ContractError):
                recovery.require_owned_writer(object(), "a" * 64, "456", "b" * 40, "c" * 40,
                    spec, {"pauseLimitSeconds": 300}, "{}", {**writer, "previousSha256": "9" * 64}, plan, mode="execute")

    def test_current_recovery_job_must_be_visible_before_any_claim(self):
        main, candidate, session = "a" * 40, "b" * 40, "123"
        env = {"GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "1", "BACKUP_ACTION": "resume-failed"}
        repo = {"id": recovery.github.REPOSITORY_ID}
        run = {"id": 456, "run_attempt": 1, "status": "in_progress", "head_sha": main,
               "head_branch": "main", "event": "workflow_dispatch", "path": recovery.RECOVERY_FILE,
               "display_title": "Rehearsal backup recovery resume-failed at " + main + " candidate " + candidate + " session " + session,
               "repository": repo, "head_repository": repo}
        names = ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                 "Verify isolated recovery test Bot identity")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        steps.append({"name": "Plan or execute one reviewed recovery phase", "status": "in_progress", "conclusion": None})
        jobs = {"total_count": 1, "jobs": [{"name": "recovery", "run_id": 456, "run_attempt": 1,
                "head_sha": main, "status": "in_progress", "steps": steps}]}
        with patch.object(recovery.github, "_get_json", side_effect=[run, run, jobs]):
            recovery.require_live_recovery_job(env, main, candidate, session, "dummy")
        with patch.object(recovery.github, "_get_json", side_effect=[run, {**run, "status": "completed"}]), self.assertRaises(ContractError):
            recovery.require_live_recovery_job(env, main, candidate, session, "dummy")

    def test_previous_recovery_intent_requires_exact_finished_writer_and_original_slot(self):
        from unittest.mock import Mock
        target = Mock(environment="rehearsal", data={"workerName": recovery.rehearsal.SERVICE}, digest="a" * 64)
        runtime = recovery.RecoveryRuntime(target, controller_revision="b" * 40, dispatcher_revision="c" * 40,
            source_revision="d" * 40, env={}, guard=lambda: None)
        plan = {"action": "resume-failed", "coordinatorSession": "123", "applicationSession": "456-1",
                "journalLength": 4, "targetSha256": target.digest,
                "dispatcherRevision": "c" * 40, "candidateRevision": "b" * 40}
        writer = {"action": "recovery", "writerRunId": "789", "writerAttempt": "1",
                  "recoveryAction": "resume-failed", "recoveryPlanSha256": digest(plan)}
        claim = {"writer": writer, "writerRunId": "789", "writerAttempt": "1", "plan": plan, "planSha256": digest(plan)}
        slot = recovery.core.BASE + target.digest + "/123/recovery/456-1-0004-intent.json"
        details = {"dispatcherWorkflow": recovery.RECOVERY_FILE.rsplit("/", 1)[1], "controlRevision": "b" * 40,
                   "dispatcherRevision": "c" * 40, "runId": "789", "runAttempt": "1",
                   "recoverySlot": slot, "recoveryClaimSha256": digest(claim)}
        runtime.store = Mock()
        runtime.store.objects.get.return_value = (canonical(claim), '"etag"')
        runtime.recovery_session = "123"
        runtime.recovery_history = {"writers": [writer]}
        self.assertTrue(runtime.require_finished(details, allowed_actions={"resume-failed"}))
        with self.assertRaises(ContractError):
            runtime.require_finished({**details, "recoverySlot": slot.replace("0004", "0005")})
        with self.assertRaises(ContractError):
            runtime.require_finished(details, allowed_actions={"activate"})
        runtime.recovery_history = {"writers": []}
        with self.assertRaises(ContractError):
            runtime.require_finished(details)

    def test_recovery_success_requires_actual_terminal_journal_and_open_state(self):
        pin = {"session": "123-1", "day": "2026/11/18", "state": "idle"}
        state = {"control": {"admission": "open", "workers": "run"}}
        events = [{"stage": "resumed", "details": {"control": state["control"], "backupVerified": False}}]
        recovery.require_recovery_result("resume-failed", "resumed-after-failure", pin, events, state, "123-1", "2026/11/18")
        for changed in ({**pin, "state": "active"}, {**pin, "session": "999-1"}):
            with self.assertRaises(ContractError):
                recovery.require_recovery_result("resume-failed", "resumed-after-failure", changed, events, state, "123-1", "2026/11/18")
        with self.assertRaises(ContractError):
            recovery.require_recovery_result("resume-failed", "resumed-after-failure", pin,
                [{"stage": "resume-intent", "details": {}}], state, "123-1", "2026/11/18")

    def test_child_inventory_rejects_inflight_or_unclaimed_phase(self):
        target, session, main, candidate = "a" * 64, "123", "b" * 40, "c" * 40
        inputs = {"dispatch_nonce": "d" * 64}
        intent = {"controllerRevision": main, "candidateRevision": candidate, "profile": "rehearsal",
                  "inputSha256": digest(inputs)}
        raw = canonical(intent)
        class Store:
            def get(self, _key, **_kwargs):
                return raw, '"etag"'
        spec = {"sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64, "validation_json": "{}"}
        run = {"id": 456, "status": "completed", "conclusion": "failure"}
        names = ("Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
                 "Verify isolated test Bot identity")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        steps.append({"name": "Execute one reviewed rehearsal phase", "status": "completed", "conclusion": "failure"})
        jobs = {"total_count": 1, "jobs": [{"name": "phase", "run_id": 456, "run_attempt": 1,
                "head_sha": main, "status": "completed", "steps": steps}]}
        def read(path, _token):
            if path.startswith("/actions/workflows/"):
                return {"path": recovery.core.PROFILES["rehearsal"]["child"], "id": 1}
            if path.endswith("/jobs?per_page=100"):
                return jobs
            return {"id": 456, "run_attempt": 1, "status": "completed"}
        def stage(_store, _target, _session, number):
            return {"status": "unknown" if number == 1 else "not-recorded"}
        with patch.object(recovery.github, "_get_json", side_effect=read), \
             patch.object(recovery.core, "inspect_stage", side_effect=stage), \
             patch.object(recovery.core, "completed_results", return_value=([], None)), \
             patch.object(recovery.core, "stage_inputs", return_value=(inputs, None)), \
             patch.object(recovery.core, "discover_run", return_value=run), \
             patch.object(recovery.core, "verify_child_claim", return_value="1" * 64):
            result = recovery.stopped_children(Store(), target, session, main, candidate, spec,
                                               {"pauseLimitSeconds": 300}, "dummy")
            self.assertEqual(result["children"][0]["conclusion"], "failure")
            run["status"] = "in_progress"
            with self.assertRaises(ContractError):
                recovery.stopped_children(Store(), target, session, main, candidate, spec,
                                          {"pauseLimitSeconds": 300}, "dummy")
            run["status"] = "completed"
            with patch.object(recovery.core, "verify_child_claim", side_effect=ContractError("unknown")), self.assertRaises(ContractError):
                recovery.stopped_children(Store(), target, session, main, candidate, spec,
                                          {"pauseLimitSeconds": 300}, "dummy")


if __name__ == "__main__":
    unittest.main()

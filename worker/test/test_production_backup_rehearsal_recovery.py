"""Hosted checks for fixed-source rehearsal recovery planning."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_rehearsal_recovery as recovery
from production_target import ContractError, canonical, digest


class RehearsalRecoveryTests(unittest.TestCase):
    def test_unknown_result_is_preserved_and_cannot_report_success(self):
        import tempfile
        from contextlib import redirect_stdout
        from io import StringIO
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary = root / "summary.txt"
            result = {"status": "unknown", "automaticReplay": False}
            output = StringIO()
            with redirect_stdout(output):
                success = recovery.publish_result(result, {"RUNNER_TEMP": directory, "GITHUB_STEP_SUMMARY": str(summary)})
            self.assertFalse(success)
            self.assertEqual((root / "rehearsal-backup-recovery-result.json").read_bytes(), canonical(result))
            self.assertIn("::warning::", output.getvalue())
            self.assertIn("remains unknown", summary.read_text())

    def test_recovery_api_budget_is_checked_before_any_claim(self):
        response = Mock()
        response.read.return_value = b'{"resources":{"core":{"remaining":1000,"reset":9999999999}}}'
        opener = Mock()
        opener.open.return_value.__enter__ = Mock(return_value=response)
        opener.open.return_value.__exit__ = Mock(return_value=False)
        with patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_OPENER", opener):
            recovery.require_recovery_budget(11, 0)
            with self.assertRaises(ContractError):
                recovery.require_recovery_budget(11, 20)
            with self.assertRaises(ContractError):
                recovery.require_recovery_budget(True, 0)

    def test_each_recovery_action_requires_approval_and_one_exclusive_stage_claim(self):
        from hashlib import sha256
        import production_recovery
        main, candidate, target_sha = "a" * 40, "b" * 40, "c" * 64
        spec = {"headSha": candidate, "sourceCheckpointId": "d" * 32,
                "sourceManifestSha256": "e" * 64, "genesisSha256": "f" * 64}
        original = canonical({"synthetic": True})
        history = {"startSha256": sha256(original).hexdigest(), "lastSha256": "1" * 64, "writers": []}
        state = {"stateSha256": "2" * 64, "targetSha256": target_sha, "configurationSha256": "3" * 64,
                 "control": {"admission": "open", "workers": "run"}, "release": {}, "terminal": {}}
        for planned, action, status in (("plan-resume-failed", "resume-failed", "resumed-after-failure"),
                ("plan-reconcile-transition", "reconcile-transition", "reconciled"),
                ("plan-abort-unstarted", "abort-unstarted", "aborted-before-pause")):
            with self.subTest(action=action):
                records, writes, phases = {}, [], []
                initial_events = [] if action == "abort-unstarted" else [{"stage": "paused", "details": {}}]
                final_events = ([{"stage": "started", "details": {"reconciledUnstarted": True}},
                                 {"stage": "failed", "details": {"uncertain": False}}] if action == "abort-unstarted" else
                                [{"stage": "paused", "details": {"reconciled": True, "control": state["control"]}}]
                                if action == "reconcile-transition" else
                                [{"stage": "resumed", "details": {"control": state["control"], "backupVerified": False}}])
                journal = Mock()
                journal.load.side_effect = lambda: final_events if phases else initial_events
                anchor = Mock()
                anchor.read.return_value = ({"session": "456-1", "day": "2026/11/18",
                    "state": "active" if action == "reconcile-transition" else "idle"}, b"final anchor", '"etag"')
                def get(key, **_kwargs):
                    if key.endswith("/start-intent.json"):
                        return original, '"etag"'
                    return records.get(key), '"etag"'
                def put(key, raw):
                    if key in records:
                        raise ContractError("claimed")
                    records[key] = raw
                    writes.append(key)
                objects = SimpleNamespace(get=get, put_once=put)
                store = SimpleNamespace(objects=objects, get_with_etag=lambda _key: (b"initial anchor", '"etag"'))
                target = SimpleNamespace(environment="rehearsal", digest=target_sha, configuration_digest="3" * 64,
                                         data={"workerName": recovery.rehearsal.SERVICE})
                ctl = Mock()
                ctl.inspect.return_value = state
                tool = Mock()
                tool.bind.return_value = ctl
                context = {"tool": tool, "target": target, "policy": {"pauseLimitSeconds": 300}, "contract": {},
                           "store": store, "bundle": object(), "manifest": {}, "archive": b"archive",
                           "proof": {"revision": "4" * 40}}
                writer = {"action": "recovery", "writerRunId": "789", "previousSha256": history["lastSha256"]}
                def phase(**kwargs):
                    if kwargs["action"] == planned:
                        return {"status": "plan-only", "stateSha256": state["stateSha256"]}
                    self.assertEqual(kwargs["action"], action)
                    kwargs["guard"]()
                    phases.append(action)
                    return {"status": status}
                env = {"GITHUB_SHA": main, "GITHUB_RUN_ID": "789", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": "/tmp",
                       "HEAD_VALIDATION_JSON": canonical(spec).decode(), "BACKUP_COORDINATOR_SESSION": "123",
                       "BACKUP_SESSION": "456-1", "BACKUP_SESSION_DAY": "2026/11/18", "BACKUP_ACTION": planned}
                with patch.object(recovery.rehearsal, "verify_trusted_gate"), \
                     patch.object(recovery.rehearsal, "prepare_coordinator_context", return_value=context), \
                     patch.object(recovery.rehearsal, "verify_owned_webhook_window", return_value={"window": "confirmed"}) as window, \
                     patch.object(recovery.core, "finished_controller", return_value=history), \
                     patch.object(recovery.core, "claim_resume_writer", return_value=writer), \
                     patch.object(recovery, "require_owned_writer", return_value=True), \
                     patch.object(recovery, "require_live_recovery_job"), \
                     patch.object(recovery, "require_recovery_budget"), \
                     patch.object(recovery, "stopped_children", return_value={"children": [], "verified": [{"session": "456-1", "day": "2026/11/18"}]}), \
                     patch.object(recovery.github, "_github_token", return_value="synthetic"), \
                     patch.object(recovery.backup.maintenance, "Anchor", return_value=anchor), \
                     patch.object(recovery.backup.maintenance, "Transaction", return_value=journal), \
                     patch.object(production_recovery, "RecoveryAPI", return_value=SimpleNamespace(verify_backup=Mock())), \
                     patch.object(production_recovery, "RecoverySource", return_value=SimpleNamespace()), \
                     patch.object(recovery.backup, "execute_phase", side_effect=phase):
                    result = recovery.main(env)
                    self.assertEqual(result["status"], "planned")
                    env.update(BACKUP_ACTION=action, SUBS_BOT_BACKUP_PHASE_RECOVERY_WRITES_ENABLED="true",
                               BACKUP_RECOVERY_PLAN_SHA256=result["planSha256"],
                               SUBS_BOT_BACKUP_PHASE_RECOVERY_APPROVAL_SHA256="0" * 64)
                    with self.assertRaises(ContractError):
                        recovery.main(env)
                    self.assertEqual(writes, [])
                    env["SUBS_BOT_BACKUP_PHASE_RECOVERY_APPROVAL_SHA256"] = result["planSha256"]
                    completed = recovery.main(env)
                    self.assertEqual(completed["status"], "completed-awaiting-independent-readback")
                    self.assertEqual(phases, [action])
                    self.assertEqual(len(writes), 2)  # stage claim and immutable completion
                    phases.clear()
                    with self.assertRaises(ContractError):
                        recovery.main(env)
                    self.assertEqual(phases, [])
                    records.clear()
                    writes.clear()
                    window.side_effect = [{"window": "confirmed"}, {"window": "confirmed"}, {"window": "changed"}]
                    with self.assertRaises(ContractError):
                        recovery.main(env)
                    self.assertEqual(len(writes), 1)  # an uncertain claimed stage is retained
                    self.assertEqual(phases, [])
                    window.side_effect = None
                    with self.assertRaises(ContractError):
                        recovery.main(env)
                    self.assertEqual(phases, [])  # never repeat a possibly issued action

    def test_later_readonly_verification_never_promotes_missing_or_unpinned_completion(self):
        main, candidate, target_sha = "a" * 40, "b" * 40, "c" * 64
        checkpoint, manifest = "d" * 32, "e" * 64
        spec = {"headSha": candidate, "sourceCheckpointId": checkpoint,
                "sourceManifestSha256": manifest, "genesisSha256": "f" * 64}
        prior = {"startSha256": "1" * 64, "lastSha256": "2" * 64, "writers": []}
        plan = {"action": "resume-failed", "targetSha256": target_sha, "dispatcherRevision": main,
                "candidateRevision": candidate, "coordinatorSession": "123", "applicationSession": "456-1",
                "day": "2026/11/18", "journalLength": 3, "sourceCheckpointId": checkpoint,
                "sourceManifestSha256": manifest, "writerHistorySha256": digest(prior)}
        writer = {"action": "recovery", "writerRunId": "789", "writerAttempt": "1",
                  "recoveryAction": "resume-failed", "recoveryPlanSha256": digest(plan),
                  "previousSha256": prior["lastSha256"]}
        history = {"startSha256": prior["startSha256"], "lastSha256": "3" * 64, "writers": [writer]}
        claim = {"plan": plan, "planSha256": digest(plan), "writer": writer,
                 "writerRunId": "789", "writerAttempt": "1"}
        control = {"admission": "open", "workers": "run"}
        state = {"targetSha256": target_sha, "configurationSha256": "4" * 64, "control": control,
                 "release": {"revision": "synthetic"}, "terminal": {}, "stateSha256": "5" * 64}
        events = [{"stage": "resumed", "details": {"control": control, "backupVerified": False}}]
        anchor_raw = b"synthetic anchor"
        from hashlib import sha256
        complete = {"claimSha256": digest(claim), "planSha256": digest(plan), "status": "resumed-after-failure",
                    "targetSha256": target_sha, "configurationSha256": state["configurationSha256"],
                    "control": control, "releaseSha256": digest(state["release"]), "anchorSha256": sha256(anchor_raw).hexdigest(),
                    "anchorState": "idle", "journalSha256": digest(events), "journalLength": len(events),
                    "stateSha256": state["stateSha256"]}
        records = {"claim": canonical(claim), "completion": None}
        def get(key, **_kwargs):
            if key.endswith("-intent.json"):
                return records["claim"], '"etag"'
            if key.endswith("-complete.json"):
                return records["completion"], '"etag"'
            return canonical({"synthetic": True}), '"etag"'
        objects = SimpleNamespace(write_credential=None, get=get)
        store = SimpleNamespace(objects=objects)
        target = SimpleNamespace(digest=target_sha, configuration_digest=state["configurationSha256"])
        ctl = Mock()
        ctl.inspect.return_value = state
        tool = Mock()
        tool.bind.return_value = ctl
        context = {"tool": tool, "target": target, "store": store, "policy": {"pauseLimitSeconds": 300},
                   "bundle": object(), "manifest": {}}
        env = {"BACKUP_RECOVERY_MODE": "verify", "GITHUB_SHA": main, "GITHUB_RUN_ID": "900",
               "BACKUP_RECOVERY_SOURCE_RUN_ID": "789", "HEAD_VALIDATION_JSON": canonical(spec).decode(),
               "BACKUP_COORDINATOR_SESSION": "123", "BACKUP_SESSION": "456-1", "BACKUP_SESSION_DAY": "2026/11/18",
               "BACKUP_RECOVERY_SLOT": "456-1-0003", "BACKUP_RECOVERY_CLAIM_SHA256": digest(claim),
               "BACKUP_RECOVERY_PLAN_SHA256": digest(plan), "BACKUP_ACTION": "resume-failed"}
        repo = {"id": recovery.github.REPOSITORY_ID}
        run = {"id": 789, "run_attempt": 1, "head_sha": main, "path": recovery.RECOVERY_FILE,
               "head_branch": "main", "event": "workflow_dispatch", "repository": repo, "head_repository": repo,
               "display_title": "Rehearsal backup recovery resume-failed at " + main + " candidate " + candidate + " session 123"}
        names = ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                 "Verify isolated recovery test Bot identity", "Plan or execute one reviewed recovery phase")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        steps[-1]["conclusion"] = "failure"
        jobs = {"total_count": 1, "jobs": [{"name": "recovery", "status": "completed", "conclusion": "failure",
                "run_id": 789, "run_attempt": 1, "head_sha": main, "steps": steps}]}
        anchor = Mock()
        anchor.read.return_value = ({"session": "456-1", "day": "2026/11/18", "state": "idle"}, anchor_raw, '"etag"')
        journal = Mock()
        journal.load.return_value = events
        with patch.object(recovery.rehearsal, "verify_trusted_gate"), \
             patch.object(recovery.rehearsal, "prepare_coordinator_context", return_value=context), \
             patch.object(recovery.rehearsal, "verify_owned_webhook_window"), \
             patch.object(recovery.core, "finished_controller", return_value=history), \
             patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", side_effect=lambda path, _token: jobs if path.endswith("/jobs?per_page=100") else run), \
             patch.object(recovery.backup.maintenance, "Anchor", return_value=anchor), \
             patch.object(recovery.backup.maintenance, "Transaction", return_value=journal):
            records["claim"] = None
            env["BACKUP_RECOVERY_CLAIM_SHA256"] = ""
            unknown = recovery.main(env)
            self.assertEqual((unknown["status"], unknown["claimStatus"]), ("unknown", "absent"))
            records["claim"] = canonical(claim)
            with self.assertRaises(ContractError):
                recovery.main(env)  # an occupied unpinned stage is not proof of absence
            env["BACKUP_RECOVERY_CLAIM_SHA256"] = digest(claim)
            unknown = recovery.main(env)
            self.assertEqual(unknown["status"], "unknown")
            self.assertEqual(unknown["observation"]["phase"], "resumed")
            self.assertEqual(unknown["observation"]["anchorState"], "idle")
            self.assertNotIn("control", unknown["observation"])
            records["completion"] = canonical(complete)
            self.assertEqual(recovery.main(env)["status"], "unknown")
            env["BACKUP_RECOVERY_COMPLETION_SHA256"] = digest(complete)
            self.assertEqual(recovery.main(env)["status"], "confirmed")
            steps[-1]["conclusion"] = "skipped"
            with self.assertRaises(ContractError):
                recovery.main(env)
            steps[-1]["conclusion"] = "failure"
            env["BACKUP_RECOVERY_COMPLETION_SHA256"] = "0" * 64
            with self.assertRaises(ContractError):
                recovery.main(env)

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

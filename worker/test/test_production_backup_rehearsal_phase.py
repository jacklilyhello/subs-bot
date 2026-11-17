"""Isolation approvals and dual-revision dispatcher guards use no real credentials."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_cli as backup
import production_backup_rehearsal_phase as phase
from production_target import ContractError, canonical, digest


class RehearsalPhaseTests(unittest.TestCase):
    def test_owned_webhook_window_requires_complete_one_shot_evidence_and_unchanged_lock(self):
        import production_lifecycle_drill as drill
        main, candidate, target_sha, config_sha = "a" * 40, "b" * 40, "c" * 64, "d" * 64
        target = SimpleNamespace(environment="rehearsal", digest=target_sha, configuration_digest=config_sha,
            data={"workerName": phase.SERVICE, "botId": "9293938370", "botUsername": "test_cfsubs_bot",
                  "webhook": {"maxConnections": 40, "allowedUpdates": ["message", "callback_query"]}})
        previous = {"botId": "9293938370", "webhookSecret": "synthetic-previous-secret"}
        snapshot = {"schemaVersion": 1, "runId": "456", "runAttempt": "1", "revision": candidate,
                    "draftSha256": "e" * 64, "botId": previous["botId"], "oldWebhookSecret": previous["webhookSecret"],
                    "webhookInfo": {"url": drill.ORIGINAL_ORIGIN + "/telegram/webhook", "has_custom_certificate": False,
                                    "max_connections": 40, "allowed_updates": ["message", "callback_query"]}}
        settings = {"url": drill.ORIGIN + "/telegram/webhook", "hasCustomCertificate": False,
                    "maxConnections": 40, "allowedUpdates": ["callback_query", "message"]}
        configured = {"targetSha256": target_sha, "configurationSha256": config_sha,
                      "webhookSha256": digest(settings), "dropPendingUpdates": False}
        intent = {"version": 1, "kind": "phase-webhook-setup-intent", "runId": "456", "runAttempt": "1",
                  "controllerRevision": candidate, "dispatcherRevision": main, "targetSha256": target_sha,
                  "configurationSha256": config_sha, "sourceCheckpointId": "f" * 32,
                  "sourceManifestSha256": "1" * 64, "snapshotSha256": digest(snapshot),
                  "predecessorSha256": "2" * 64, "webhookSettingsSha256": digest({
                      "url": drill.ORIGINAL_ORIGIN + "/telegram/webhook", "hasCustomCertificate": False,
                      "maxConnections": 40, "allowedUpdates": ["callback_query", "message"]}), "historySha256": "4" * 64}
        confirmed = {"version": 1, "kind": "phase-webhook-setup-confirmed", "intentSha256": digest(intent),
                     "snapshotSha256": digest(snapshot), "configuredSha256": digest(configured), "targetSha256": target_sha}
        prefix = "private/"
        objects = {prefix + "webhook-456-1.json": canonical(snapshot),
                   prefix + "456-1-webhook-configured.json": canonical(configured),
                   prefix + "phase-coordinator-webhook-setup-456-1-intent.json": canonical(intent),
                   prefix + "phase-coordinator-webhook-setup-456-1-confirmed.json": canonical(confirmed)}
        def get(key, *, absent=False):
            if absent:
                return objects.get(key)
            return objects[key]
        store = SimpleNamespace(get=get)
        tool = SimpleNamespace(store=store, prefix=prefix, draft=SimpleNamespace(digest="e" * 64),
                               previous=previous, secrets={"webhookSecret": "synthetic-active-secret"},
                               env={"SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256": "5" * 64}, guard=lambda: None)
        ctl = Mock()
        ctl.telegram.plan_webhook.return_value = {"settings": settings, "settingsSha256": digest(settings)}
        ctl.inspect.return_value = {"stateSha256": "6" * 64, "terminal": {}}
        context = {"tool": tool, "target": target, "controller": ctl,
                   "sourceCheckpointId": "f" * 32, "sourceManifestSha256": "1" * 64}
        start = {"version": 1, "action": "run", "profile": "rehearsal", "targetSha256": target_sha,
                 "controlRevision": main, "candidateRevision": candidate, "session": "123", "writerRunId": "456",
                 "writerAttempt": "1", "sourceCheckpointId": "f" * 32, "sourceManifestSha256": "1" * 64,
                 "anchorSha256": "7" * 64, "policySha256": "8" * 64, "validationSha256": "9" * 64}
        repo = {"id": phase.github.REPOSITORY_ID}
        run = {"id": 456, "run_attempt": 1, "path": phase.PARENT_FILE, "head_sha": main, "head_branch": "main",
               "event": "workflow_dispatch", "status": "completed", "display_title":
               "Rehearsal backup coordinator run at " + main + " candidate " + candidate,
               "repository": repo, "head_repository": repo}
        lock = Mock()
        lock.read.return_value = ({"state": "active", "session": "456-1", "controlRevision": candidate}, b"anchor", '"etag"')
        fake_module = SimpleNamespace(anchor=lambda *_: lock)
        with patch.dict(sys.modules, {"trusted_backup_webhook_anchor": fake_module}), \
             patch.object(phase.github, "_github_token", return_value="dummy"), \
             patch.object(phase.github, "_get_json", return_value=run), \
             patch.object(drill, "public_request", return_value=object()) as request, \
             patch.object(drill, "public_readback", return_value=(400, b"")):
            observed = phase.verify_owned_webhook_window(context, start, main, candidate)
            self.assertEqual(observed["sourceRunId"], "456")
            request.assert_called_once_with(drill.ORIGIN + "/telegram/webhook", method="POST", data=b"{}",
                                            secret="synthetic-active-secret")
            with self.assertRaises(ContractError):
                phase.verify_owned_webhook_window(context, {**start, "version": True}, main, candidate)
            objects[prefix + "webhook-recovery-456-1-intent.json"] = b"{}"
            with self.assertRaises(ContractError):
                phase.verify_owned_webhook_window(context, start, main, candidate)
            del objects[prefix + "webhook-recovery-456-1-intent.json"]
            objects[prefix + "phase-coordinator-webhook-setup-456-1-confirmed.json"] = canonical({**confirmed, "targetSha256": "0" * 64})
            with self.assertRaises(ContractError):
                phase.verify_owned_webhook_window(context, start, main, candidate)
            objects[prefix + "phase-coordinator-webhook-setup-456-1-confirmed.json"] = canonical(confirmed)
            ctl.inspect.return_value["terminal"]["terminalEditFailure"] = 1
            with self.assertRaises(ContractError):
                phase.verify_owned_webhook_window(context, start, main, candidate)
            ctl.inspect.return_value["terminal"].clear()
            lock.read.return_value = ({"state": "idle", "session": "456-1", "controlRevision": candidate}, b"anchor", '"etag"')
            with self.assertRaises(ContractError):
                phase.verify_owned_webhook_window(context, start, main, candidate)
            lock.read.return_value = ({"state": "active", "session": "456-1", "controlRevision": candidate}, b"anchor", '"etag"')
            with patch.object(drill, "public_readback", return_value=(503, b"")), self.assertRaises(ContractError):
                phase.verify_owned_webhook_window(context, start, main, candidate)

    def test_synthetic_approval_cannot_authorize_a_production_target(self):
        target = Mock(environment="production", data={"workerName": phase.SERVICE})
        with self.assertRaises(ContractError):
            phase.RehearsalPhaseRuntime(target, controller_revision="a" * 40,
                dispatcher_revision="b" * 40, source_revision="c" * 40, env={}, guard=lambda: None)

    def test_intent_requires_exact_profile_both_revisions_and_input_digest(self):
        inputs = {"dispatch_nonce": "e" * 64, "action": "pause", "validation_json": "{}"}
        intent = {"version": 1, "kind": "backup-dispatch-intent", "targetSha256": "a" * 64,
            "session": "123", "sequence": 5, "action": "pause", "controllerRevision": "b" * 40,
            "candidateRevision": "c" * 40, "profile": "rehearsal", "nonce": inputs["dispatch_nonce"],
            "inputSha256": digest(inputs), "createdAt": 1000, "writerRunId": "456", "writerAttempt": "1"}
        def read(value):
            return phase.validate_dispatch_intent(canonical(value), target_sha="a" * 64, session="123", action="pause",
                main_sha="b" * 40, candidate_sha="c" * 40, inputs=inputs)
        with patch.object(phase.time, "time", return_value=1001):
            self.assertEqual(read(intent), intent)
            for change in ({"profile": "production"}, {"candidateRevision": "d" * 40},
                           {"controllerRevision": "d" * 40}, {"inputSha256": "f" * 64}, {"writerAttempt": "2"}, {"sequence": True}):
                with self.subTest(change=change), self.assertRaises(ContractError):
                    read({**intent, **change})

    def test_parent_job_and_step_must_still_be_running(self):
        main, candidate = "a" * 40, "b" * 40
        repo = {"id": phase.github.REPOSITORY_ID}
        run = {"id": 456, "run_attempt": 1, "path": phase.PARENT_FILE, "head_sha": main,
               "head_branch": "main", "event": "workflow_dispatch", "status": "in_progress",
               "display_title": "Rehearsal backup coordinator run at " + main + " candidate " + candidate,
               "repository": repo, "head_repository": repo}
        jobs = {"total_count": 1, "jobs": [{"name": "coordinate", "run_id": 456, "run_attempt": 1,
                 "head_sha": main, "status": "in_progress", "conclusion": None,
                 "steps": [{"name": phase.PARENT_STEP, "status": "in_progress", "conclusion": None}]}]}
        with patch.object(phase.github, "_get_json", side_effect=[run, jobs]):
            phase.require_parent_running({"writerRunId": "456"}, main, candidate, "dummy")
        ended = {"total_count": 1, "jobs": [{**jobs["jobs"][0], "steps": [
            {"name": phase.PARENT_STEP, "status": "completed", "conclusion": "failure"}]}]}
        with patch.object(phase.github, "_get_json", side_effect=[run, ended]), self.assertRaises(ContractError):
            phase.require_parent_running({"writerRunId": "456"}, main, candidate, "dummy")
        with patch.object(phase.github, "_get_json", return_value={**run, "status": "completed"}), self.assertRaises(ContractError):
            phase.require_parent_running({"writerRunId": "456"}, main, candidate, "dummy")

    def test_rehearsal_run_never_authorizes_production_recovery(self):
        details = {"runId": "123", "runAttempt": "1", "controlRevision": "a" * 40,
                   "dispatcherRevision": "b" * 40, "dispatcherWorkflow": "worker-backup-phase-rehearsal.yml",
                   "dispatchNonce": "c" * 64}
        with self.assertRaises(ContractError):
            backup.require_finished_intent(details, allowed_actions={"pause"})

    def test_finished_rehearsal_origin_requires_exact_trusted_gate_steps(self):
        main, candidate, nonce = "a" * 40, "b" * 40, "c" * 64
        details = {"runId": "123", "runAttempt": "1", "controlRevision": candidate,
                   "dispatcherRevision": main, "dispatcherWorkflow": "worker-backup-phase-rehearsal.yml",
                   "dispatchNonce": nonce}
        repo = {"id": phase.github.REPOSITORY_ID}
        run = {"id": 123, "run_attempt": 1, "status": "completed", "workflow_id": 9,
               "head_branch": "main", "head_sha": main, "event": "workflow_dispatch",
               "display_title": "Rehearsal backup pause at " + main + " candidate " + candidate + " #" + nonce,
               "repository": repo, "head_repository": repo}
        names = ("Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
                 "Verify isolated test Bot identity", "Execute one reviewed rehearsal phase")
        steps = [{"name": name, "status": "completed", "conclusion": "success"} for name in names]
        jobs = {"total_count": 1, "jobs": [{"name": "phase", "run_id": 123, "run_attempt": 1,
                 "head_sha": main, "status": "completed", "steps": steps}]}
        workflow = {"id": 9, "path": phase.PHASE_FILE}
        def check(inv):
            with patch.object(backup.artifact, "_github_token", return_value="dummy"), \
                 patch.object(backup.artifact, "_get_json", side_effect=[run, run, workflow, inv]):
                backup.require_finished_intent(details, allowed_actions={"pause"}, rehearsal=True)
        check(jobs)
        changed = {"total_count": 1, "jobs": [{**jobs["jobs"][0], "steps": [
            {**item, "conclusion": "failure"} if item["name"] == names[1] else item for item in steps]}]}
        with self.assertRaises(ContractError):
            check(changed)


if __name__ == "__main__":
    unittest.main()

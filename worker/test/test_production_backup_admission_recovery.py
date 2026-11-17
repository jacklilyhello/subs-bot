"""Synthetic trusted admission cleanup and no-retry checks."""
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_admission_recovery as admission
from production_target import ContractError


class AdmissionTests(unittest.TestCase):
    def test_idle_session_journal_requires_complete_safe_terminal_chain(self):
        prefix = "maintenance/production-control/evidence/daily-backup/2026/11/17/123-1/"
        def fixture(stages):
            values, previous = {}, None
            for sequence, stage in enumerate(stages, 1):
                details = {"checkpointId": "d" * 32, "manifestSha256": "e" * 64} if stage == "verified" else {}
                raw = admission.canonical({"version": 1, "session": "123-1", "targetSha256": "a" * 64,
                    "controlRevision": "b" * 40, "sequence": sequence, "previousSha256": previous,
                    "timestamp": sequence, "stage": stage, "details": details})
                values[prefix + str(sequence).zfill(4) + ".json"] = raw
                previous = sha256(raw).hexdigest()
            return values
        safe = ["started", "preflight", "pause-intent", "paused", "freeze-intent", "frozen", "frozen-data",
                "capture-intent", "verified", "resume-intent", "resumed"]
        for stages, accepted in ((safe, True), (["started", "preflight", "failed"], True),
                                 (safe[:8] + ["failed"], False), (safe[:-1], False)):
            objects = fixture(stages)
            store = Mock()
            store.get.side_effect = objects.get
            with patch.object(admission, "list_history", return_value=sorted(objects)):
                if accepted:
                    self.assertRegex(admission.verified_journal(store, "a" * 64, "123-1", "b" * 40, "2026/11/17"), r"^[a-f0-9]{64}$")
                else:
                    with self.assertRaises(ContractError):
                        admission.verified_journal(store, "a" * 64, "123-1", "b" * 40, "2026/11/17")
        objects = fixture(safe)
        del objects[prefix + "0004.json"]
        store = Mock()
        store.get.side_effect = objects.get
        with patch.object(admission, "list_history", return_value=sorted(objects)), self.assertRaises(ContractError):
            admission.verified_journal(store, "a" * 64, "123-1", "b" * 40, "2026/11/17")

    def fixture(self, directory):
        candidate, main, digest = "a" * 40, "b" * 40, "c" * 64
        draft = Mock(digest="d" * 64, data={})
        target = Mock(environment="rehearsal", digest=digest, configuration_digest="e" * 64)
        target.data = {"workerName": admission.SERVICE, "backupBucketName": "private-backup",
                       "botId": admission.TEST_BOT_ID, "botUsername": "test_cfsubs_bot",
                       **{key: "pin" for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}}
        initial = {"targetSha256": digest, "configurationSha256": target.configuration_digest,
                   "release": {"revision": "f" * 40}, "control": {"admission": "open", "workers": "run", "epoch": 3},
                   "work": {"invocations": 0}, "terminal": {}, "stateSha256": "1" * 64}
        paused = {**initial, "control": {"admission": "closed", "workers": "run", "epoch": 4}, "stateSha256": "2" * 64}
        frozen = {**initial, "control": {"admission": "closed", "workers": "frozen", "epoch": 5}, "stateSha256": "3" * 64}
        prefix = "maintenance/production-control/evidence/lifecycle-" + draft.digest + "/"
        ready_raw = admission.canonical({"state": initial})
        registration = admission.canonical({"target": {}, "draftSha256": draft.digest, "targetSha256": digest,
                                            "configurationSha256": target.configuration_digest})
        receipt = admission.canonical({"version": 1, "status": "candidate-complete-before-trusted-cleanup",
            "runId": "123", "runAttempt": "1", "controllerRevision": candidate, "dispatcherRevision": main,
            "targetSha256": digest, "readySha256": sha256(ready_raw).hexdigest(), "admissionRestored": True,
            "authorizationUnchanged": True, "confirmedReceiptsNotRepeated": True})
        objects = {prefix + "registration.json": registration, prefix + "123-1-open-backup-ready-for-cleanup.json": ready_raw,
                   prefix + "123-1-backup-head-acceptance.json": receipt}
        store = Mock()
        store.get.side_effect = lambda key, **_: objects.get(key)
        store.put.side_effect = lambda key, raw: objects.update({key: raw})
        env = {"RUNNER_TEMP": directory, "GITHUB_SHA": main, "WEBHOOK_SOURCE_MAIN_SHA": main,
               "WEBHOOK_REGISTRATION_SHA256": sha256(registration).hexdigest(), "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic",
               "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-read", "BACKUP_SOURCE_CHECKPOINT_ID": "1" * 32,
               "BACKUP_SOURCE_MANIFEST_SHA256": "2" * 64, "BACKUP_GENESIS_SHA256": "3" * 64}
        ctl = Mock()
        ctl.inspect.side_effect = [initial, paused]
        ctl.plan_pause.return_value = initial
        ctl.transition.side_effect = [paused, frozen]
        ctl.revision = "f" * 40
        jobs = {"total_count": 1, "jobs": [{"steps": [{"name": "Run the reviewed candidate against only dedicated isolation",
                                                         "status": "completed", "conclusion": "success"}]}]}
        return candidate, draft, target, store, prefix, objects, env, ctl, jobs

    def execute(self, values, webhook=None):
        candidate, draft, target, store, prefix, _objects, env, ctl, jobs = values
        archive = {"sourceTarget": target, "bundle": Path("/synthetic"), "manifest": {}}
        with patch.object(admission, "context", return_value=True), \
             patch.object(admission, "source_run", return_value=("123", "1", candidate)), \
             patch.object(admission, "inspect_webhook", return_value=webhook or {"status": "observed", "intentPresent": False, "completionPresent": False}), \
             patch.object(admission, "open_store", return_value=(draft, {}, {"botId": admission.TEST_BOT_ID}, store, prefix)), \
             patch.object(admission, "validate_target", return_value=target), \
             patch.object(admission, "idle_anchor", return_value="4" * 64), \
             patch.object(admission.github, "_github_token", return_value="synthetic"), \
             patch.object(admission.github, "_get_json", return_value=jobs), \
             patch.object(admission.github, "require_current_main"), \
             patch.object(admission, "load_release", return_value=archive), \
             patch.object(admission, "API"), patch.object(admission, "PrivateStore"), \
             patch.object(admission, "Controller", return_value=ctl), patch.object(admission, "Telegram"), \
             patch.object(admission, "approval", return_value={"explicit": True}), \
             patch.object(admission, "claim_intent_once") as claim:
            result = admission.run(env)
        return result, claim

    def test_confirmed_candidate_closes_and_freezes_with_two_unique_intents(self):
        with tempfile.TemporaryDirectory() as directory:
            values = self.fixture(directory)
            result, claim = self.execute(values)
        self.assertEqual(result["status"], "closed-and-frozen")
        self.assertEqual(claim.call_count, 2)
        self.assertEqual([call.args[0] for call in values[7].transition.call_args_list], ["pause", "freeze"])

    def test_unconfirmed_candidate_never_starts_control_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            values = list(self.fixture(directory))
            values[8]["jobs"][0]["steps"][0]["conclusion"] = "failure"
            with self.assertRaises(ContractError):
                self.execute(values)
        values[7].transition.assert_not_called()

    def test_unknown_pause_response_never_attempts_freeze(self):
        with tempfile.TemporaryDirectory() as directory:
            values = self.fixture(directory)
            values[7].transition.side_effect = RuntimeError("synthetic unknown pause result")
            with self.assertRaises(RuntimeError):
                self.execute(values)
        values[7].transition.assert_called_once()
        self.assertEqual(values[7].transition.call_args.args[0], "pause")

    def test_prior_webhook_restore_blocks_admission_before_control_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            values = self.fixture(directory)
            with self.assertRaises(ContractError):
                self.execute(values, {"status": "observed", "intentPresent": True, "completionPresent": False})
        values[7].transition.assert_not_called()

    def test_aborted_plan_is_read_only_and_wrong_approval_never_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            values = self.fixture(directory)
            candidate, draft, target, store, prefix, _objects, env, ctl, _jobs = values
            env["WEBHOOK_SNAPSHOT_SHA256"] = "9" * 64
            archive = {"sourceTarget": target, "bundle": Path("/synthetic"), "manifest": {}}
            with patch.object(admission, "context", return_value=False), \
                 patch.object(admission, "source_run", return_value=("123", "1", candidate)), \
                 patch.object(admission, "inspect_webhook", return_value={"status": "observed", "intentPresent": False, "completionPresent": False}), \
                 patch.object(admission, "open_store", return_value=(draft, {}, {"botId": admission.TEST_BOT_ID}, store, prefix)), \
                 patch.object(admission, "validate_target", return_value=target), \
                 patch.object(admission, "idle_anchor", return_value="4" * 64), \
                 patch.object(admission, "load_release", return_value=archive), \
                 patch.object(admission, "API"), patch.object(admission, "PrivateStore"), \
                 patch.object(admission, "Controller", return_value=ctl), patch.object(admission, "Telegram"), \
                 patch.object(admission, "claim_intent_once") as claim:
                plan = admission.aborted_plan_or_execute(env, execute=False)
                self.assertEqual(plan["status"], "read-only-plan")
                env["BACKUP_APPROVED_PLAN_SHA256"] = "0" * 64
                with self.assertRaises(ContractError):
                    admission.aborted_plan_or_execute(env, execute=True)
                claim.assert_not_called()
                ctl.transition.assert_not_called()


if __name__ == "__main__":
    unittest.main()

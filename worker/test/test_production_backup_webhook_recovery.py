"""Hosted synthetic checks for one-shot test webhook restoration."""
from hashlib import sha256
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_webhook_recovery as recovery
from production_target import ContractError


class WebhookRecoveryTests(unittest.TestCase):
    def test_phase_source_is_bound_to_exact_dispatcher_title_and_candidate(self):
        main, candidate = "d" * 40, "c" * 40
        env = {"WEBHOOK_SOURCE_RUN_ID": "123", "WEBHOOK_SOURCE_ATTEMPT": "1", "GITHUB_RUN_ID": "123",
               "GITHUB_RUN_ATTEMPT": "1", "WEBHOOK_SOURCE_MAIN_SHA": main,
               "WEBHOOK_SOURCE_CANDIDATE_SHA": candidate, "WEBHOOK_REVIEWED_CANDIDATE_SHA": candidate,
               "WEBHOOK_SOURCE_KIND": "phase-coordinator", "GITHUB_WORKFLOW_REF": recovery.github.REPOSITORY + "/" +
               recovery.PHASE_DISPATCHER + "@" + recovery.github.MAIN_REF}
        run = {"id": 123, "run_attempt": 1, "path": recovery.PHASE_DISPATCHER, "head_sha": main,
               "head_branch": "main", "event": "workflow_dispatch", "status": "in_progress",
               "display_title": "Rehearsal backup coordinator run at " + main + " candidate " + candidate,
               "repository": {"id": recovery.github.REPOSITORY_ID}, "head_repository": {"id": recovery.github.REPOSITORY_ID}}
        with patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value=run):
            self.assertEqual(recovery.source_run(env, True), ("123", "1", candidate))
            for change in ({"WEBHOOK_SOURCE_KIND": "reviewed-head"}, {"WEBHOOK_REVIEWED_CANDIDATE_SHA": "e" * 40},
                           {"GITHUB_WORKFLOW_REF": env["GITHUB_WORKFLOW_REF"].replace("coordinator", "unrelated")}):
                with self.subTest(change=change), self.assertRaises(ContractError):
                    recovery.source_run({**env, **change}, True)
            with self.assertRaises(ContractError):
                recovery.source_run({**env, "WEBHOOK_SOURCE_RUN_ID": "124"}, True)

    def test_manual_history_accepts_other_source_at_old_main_but_rejects_prior_same_source(self):
        def row(run_id, title, head, attempt=1):
            return {"id": run_id, "display_title": title, "head_sha": head, "run_attempt": attempt,
                    "path": recovery.RECOVERY, "head_branch": "main", "event": "workflow_dispatch",
                    "repository": {"id": recovery.github.REPOSITORY_ID}, "head_repository": {"id": recovery.github.REPOSITORY_ID}}
        current = row(900, "Backup webhook restore 123-1", "a" * 40)
        previous = row(899, "Backup webhook restore 456-1", "b" * 40, attempt=2)
        env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "900"}
        with patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value={"total_count": 2, "workflow_runs": [current, previous]}):
            recovery.manual_no_prior_dispatch(env, "123")
        previous["display_title"] = "Backup webhook restore 123-1"
        with patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value={"total_count": 2, "workflow_runs": [current, previous]}), \
             self.assertRaises(ContractError):
            recovery.manual_no_prior_dispatch(env, "123")

    def test_manual_history_rejects_incomplete_inventory_and_unknown_title(self):
        current = {"id": 900, "display_title": "Backup webhook restore 123-1", "head_sha": "a" * 40,
                   "run_attempt": 1, "path": recovery.RECOVERY, "head_branch": "main", "event": "workflow_dispatch",
                   "repository": {"id": recovery.github.REPOSITORY_ID}, "head_repository": {"id": recovery.github.REPOSITORY_ID}}
        env = {"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "900"}
        with patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value={"total_count": 2, "workflow_runs": [current]}), \
             self.assertRaises(ContractError):
            recovery.manual_no_prior_dispatch(env, "123")
        unknown = {**current, "id": 901, "display_title": "unexpected"}
        with patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value={"total_count": 2, "workflow_runs": [current, unknown]}), \
             self.assertRaises(ContractError):
            recovery.manual_no_prior_dispatch(env, "123")

    def fixture(self):
        draft = Mock(digest="a" * 64, data={"workerName": "isolated"})
        pins = {key: "synthetic" for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}
        target = Mock(digest="b" * 64, configuration_digest="e" * 64, environment="rehearsal",
                      data={**pins, "workerName": "isolated", "botId": recovery.TEST_BOT_ID, "botUsername": "test_cfsubs_bot", "backupBucketName": "isolated",
                            "webhook": {"maxConnections": 1, "allowedUpdates": ["message"]}})
        previous = {"botId": recovery.TEST_BOT_ID, "webhookSecret": "synthetic"}
        before = {"url": recovery.ORIGINAL_ORIGIN + "/telegram/webhook", "has_custom_certificate": False,
                  "max_connections": 1, "allowed_updates": ["message"]}
        changed = {**before, "url": recovery.ORIGIN + "/telegram/webhook"}
        snapshot = {"schemaVersion": 1, "runId": "123", "runAttempt": "1", "revision": "c" * 40,
                    "draftSha256": draft.digest, "botId": recovery.TEST_BOT_ID, "oldWebhookSecret": "synthetic", "webhookInfo": before}
        registration = recovery.canonical({"target": {}, "draftSha256": draft.digest, "targetSha256": target.digest,
                                           "configurationSha256": target.configuration_digest})
        candidate = {"url": changed["url"], "hasCustomCertificate": False, "maxConnections": 1, "allowedUpdates": ["message"]}
        configured = recovery.canonical({"targetSha256": target.digest, "dropPendingUpdates": False,
                                         "webhookSha256": sha256(recovery.canonical(candidate)).hexdigest()})
        raw = recovery.canonical(snapshot)
        prefix = "maintenance/production-control/evidence/lifecycle-" + draft.digest + "/"
        data = {prefix + "registration.json": registration, prefix + "webhook-123-1.json": raw,
                prefix + "123-1-webhook-configured.json": configured}
        admission = prefix + "backup-admission-123-1-"
        pause_intent = recovery.canonical({"targetSha256": target.digest, "session": "123-1", "candidateRevision": "c" * 40})
        pause_confirmed = recovery.canonical({"intentSha256": sha256(pause_intent).hexdigest()})
        freeze_intent = recovery.canonical({"pauseConfirmationSha256": sha256(pause_confirmed).hexdigest(),
                                           "targetSha256": target.digest, "session": "123-1"})
        freeze = recovery.canonical({"version": 1, "intentSha256": sha256(freeze_intent).hexdigest(), "stateSha256": "f" * 64,
            "targetSha256": target.digest, "configurationSha256": target.configuration_digest, "control": {"epoch": 1},
            "release": {}, "candidateRevision": "c" * 40, "dispatcherRevision": "d" * 40})
        data.update({admission + "pause-intent.json": pause_intent, admission + "pause-confirmed.json": pause_confirmed,
                     admission + "freeze-intent.json": freeze_intent, admission + "freeze-confirmed.json": freeze})
        store = Mock()
        store.get.side_effect = lambda key, **_: data.get(key)
        store.put.side_effect = lambda key, value: data.update({key: value})
        env = {"GITHUB_SHA": "d" * 40, "WEBHOOK_SOURCE_MAIN_SHA": "d" * 40,
               "WEBHOOK_FREEZE_CONFIRMATION_SHA256": sha256(freeze).hexdigest(), "WEBHOOK_SNAPSHOT_SHA256": sha256(raw).hexdigest(),
               "WEBHOOK_REGISTRATION_SHA256": sha256(registration).hexdigest()}
        telegram = Mock()
        telegram.call.side_effect = lambda method, *_: {"getWebhookInfo": changed, "setWebhook": True}[method]
        return draft, target, previous, store, prefix, data, env, telegram, before, changed

    def test_unconfirmed_prior_switch_cannot_dispatch_restore(self):
        draft, target, previous, store, prefix, data, env, telegram, *_ = self.fixture()
        del data[prefix + "123-1-webhook-configured.json"]
        with patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", "c" * 40)), \
             patch.object(recovery, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "Telegram", return_value=telegram), \
             patch.object(recovery, "require_exact_freeze", return_value={"epoch": 1}):
            with self.assertRaises(ContractError):
                recovery.inspect(env, execute=True)
        store.put.assert_not_called()
        self.assertNotIn("setWebhook", [call.args[0] for call in telegram.call.call_args_list])

    def test_existing_intent_blocks_retry(self):
        draft, target, previous, store, prefix, data, env, telegram, *_ = self.fixture()
        data[prefix + "webhook-recovery-123-1-intent.json"] = b"unknown"
        with patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", "c" * 40)), \
             patch.object(recovery, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "Telegram", return_value=telegram):
            with self.assertRaises(ContractError):
                recovery.inspect(env, execute=True)
        store.put.assert_not_called()
        self.assertNotIn("setWebhook", [call.args[0] for call in telegram.call.call_args_list])

    def test_unverified_snapshot_is_rejected_before_telegram(self):
        draft, target, previous, store, prefix, _data, env, telegram, *_ = self.fixture()
        env["WEBHOOK_SNAPSHOT_SHA256"] = "0" * 64
        with patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", "c" * 40)), \
             patch.object(recovery, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "Telegram", return_value=telegram) as cls:
            with self.assertRaises(ContractError):
                recovery.inspect(env, execute=True)
        cls.assert_not_called()
        store.put.assert_not_called()

    def test_confirmed_change_restores_once_without_dropping_pending_updates(self):
        draft, target, previous, store, prefix, data, env, telegram, before, changed = self.fixture()
        telegram.call.side_effect = [changed, changed, True, before]
        jobs = {"total_count": 1, "jobs": [{"steps": [{"name": "Trusted restore original test webhook", "conclusion": "skipped"}]}]}
        with patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", "c" * 40)), \
             patch.object(recovery, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "Telegram", return_value=telegram), \
             patch.object(recovery, "require_exact_freeze", return_value={"epoch": 1}), \
             patch.object(recovery, "claim_intent_once", side_effect=lambda _store, key, raw: data.update({key: raw})), \
             patch.object(recovery, "manual_no_prior_dispatch"), patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value=jobs), patch.object(recovery.github, "require_current_main"), \
             patch.object(recovery, "probe_original_webhook", return_value=400):
            result = recovery.inspect(env, execute=True)
        writes = [call for call in telegram.call.call_args_list if call.args[0] == "setWebhook"]
        self.assertEqual(len(writes), 1)
        self.assertIs(writes[0].args[1]["drop_pending_updates"], False)
        self.assertEqual(result["status"], "settings-restored")
        self.assertIn(prefix + "webhook-recovery-123-1-intent.json", data)
        self.assertIn(prefix + "webhook-recovery-123-1-complete.json", data)

    def test_lost_restore_response_retains_intent_and_never_retries(self):
        draft, target, previous, store, prefix, data, env, telegram, _before, changed = self.fixture()
        telegram.call.side_effect = [changed, changed, RuntimeError("unknown")]
        jobs = {"total_count": 1, "jobs": [{"steps": [{"name": "Trusted restore original test webhook", "conclusion": "skipped"}]}]}
        with patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", "c" * 40)), \
             patch.object(recovery, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "Telegram", return_value=telegram), \
             patch.object(recovery, "require_exact_freeze", return_value={"epoch": 1}), \
             patch.object(recovery, "claim_intent_once", side_effect=lambda _store, key, raw: data.update({key: raw})), \
             patch.object(recovery, "manual_no_prior_dispatch"), patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "_get_json", return_value=jobs), patch.object(recovery.github, "require_current_main"):
            with self.assertRaises(RuntimeError):
                recovery.inspect(env, execute=True)
        self.assertIn(prefix + "webhook-recovery-123-1-intent.json", data)
        self.assertNotIn(prefix + "webhook-recovery-123-1-complete.json", data)
        self.assertEqual(sum(call.args[0] == "setWebhook" for call in telegram.call.call_args_list), 1)

    def test_conflicting_conditional_claim_never_authorizes_telegram(self):
        store = Mock()
        store.put_exclusive.side_effect = ContractError("conflict")
        with self.assertRaises(ContractError):
            recovery.claim_intent_once(store, "maintenance/production-control/evidence/example", b"intent")
        store.put_exclusive.assert_called_once()

    def test_scoped_conditional_claim_does_not_retry_unknown_result(self):
        store = Mock()
        store.put_exclusive.side_effect = ContractError("unknown")
        with self.assertRaises(ContractError):
            recovery.claim_intent_once(store, "maintenance/production-control/evidence/example", b"intent")
        store.put_exclusive.assert_called_once()
        store.api.assert_not_called()

    def test_open_target_is_never_a_valid_restore_predecessor(self):
        target = Mock(digest="b" * 64, configuration_digest="c" * 64)
        state = {"targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                 "stateSha256": "d" * 64, "control": {"admission": "open", "workers": "run"},
                 "release": {}, "work": {}, "terminal": {}}
        freeze = {"stateSha256": state["stateSha256"], "control": state["control"], "release": {}}
        source = {"sourceTarget": target, "bundle": "fixture", "manifest": {}}
        with tempfile.TemporaryDirectory() as directory, \
             patch("production_release_evidence.load_release", return_value=source), \
             patch.object(recovery, "API"), patch.object(recovery, "Controller") as controller:
            controller.return_value.inspect.return_value = state
            with self.assertRaises(ContractError):
                recovery.require_exact_freeze(target, {}, {"RUNNER_TEMP": directory, "GITHUB_SHA": "a" * 40,
                    "WEBHOOK_SOURCE_CHECKPOINT_ID": "e" * 32, "WEBHOOK_SOURCE_MANIFEST_SHA256": "f" * 64}, freeze)

    def test_diagnose_missing_snapshot_remains_unknown_without_writes(self):
        draft, target, previous, store, prefix, data, env, telegram, _before, _changed = self.fixture()
        del data[prefix + "webhook-123-1.json"]
        source = {"sourceTarget": target, "bundle": "fixture", "manifest": {}}
        state = {"stateSha256": "f" * 64, "control": {"admission": "open", "workers": "run"},
                 "work": {"accepted": 0}, "terminal": {}}
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", "c" * 40)), \
             patch.object(recovery, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "Telegram", return_value=telegram), \
             patch("production_release_evidence.load_release", return_value=source), patch.object(recovery, "API"), \
             patch.object(recovery, "PrivateStore", return_value=store), \
             patch.object(recovery, "Controller") as controller, patch.object(recovery.github, "require_current_main"):
            controller.return_value.inspect.return_value = state
            result = recovery.diagnose({**env, "RUNNER_TEMP": directory, "WEBHOOK_SOURCE_CHECKPOINT_ID": "a" * 32,
                                         "WEBHOOK_SOURCE_MANIFEST_SHA256": "b" * 64})
        self.assertIsNone(result["snapshotSha256"])
        self.assertEqual(result["missingEvidenceMeans"], "unknown")
        self.assertFalse(result["automaticRetryAuthorized"])
        store.put.assert_not_called()
        self.assertNotIn("setWebhook", [call.args[0] for call in telegram.call.call_args_list])


if __name__ == "__main__":
    unittest.main()

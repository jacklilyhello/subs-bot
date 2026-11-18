"""Unstarted lock recovery never retries or sends a webhook request."""
from hashlib import sha256
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_webhook_unstarted as recovery
from production_target import ContractError, canonical


class UnstartedReleaseTests(unittest.TestCase):
    def fixture(self):
        plan = {"version": 1, "sourceRunId": "123", "sourceAttempt": "1", "anchorSha256": "a" * 64}
        lock, store, body = Mock(), Mock(), {}
        lock.read.return_value = ({"state": "idle", "session": "123-1"}, b"pointer", '"etag"')
        store.put_exclusive.side_effect = lambda key, raw: body.update({key: raw})
        store.get.side_effect = lambda key: body[key]
        env = {"GITHUB_RUN_ID": "456", "GITHUB_RUN_ATTEMPT": "1", "WEBHOOK_RECOVERY_ACTION": "plan-phase-unstarted"}
        return plan, lock, store, env, body

    def test_plan_is_read_only_and_exact_approval_is_required(self):
        plan, lock, store, env, _body = self.fixture()
        with patch.object(recovery, "observe", return_value=(plan, lock, store, "private/")):
            result = recovery.run(env)
            self.assertEqual(result["status"], "planned")
            with self.assertRaises(ContractError):
                recovery.run({**env, "WEBHOOK_RECOVERY_ACTION": "release-phase-unstarted", "WEBHOOK_RECOVERY_APPROVAL_SHA256": result["planSha256"]})
        store.put_exclusive.assert_not_called()
        lock.release.assert_not_called()

    def test_exact_approval_releases_once_but_ambiguous_claim_never_does(self):
        plan, lock, store, env, body = self.fixture()
        pin = sha256(canonical(plan)).hexdigest()
        env.update(WEBHOOK_RECOVERY_ACTION="release-phase-unstarted", WEBHOOK_RECOVERY_APPROVAL_SHA256=pin,
                   SUBS_BOT_PHASE_WEBHOOK_UNSTARTED_APPROVAL_SHA256=pin)
        with patch.object(recovery, "observe", return_value=(plan, lock, store, "private/")):
            result = recovery.run(env)
        self.assertEqual(result["status"], "released-before-webhook-setup")
        lock.release.assert_called_once_with("123-1")
        plan, lock, store, env2, _body = self.fixture()
        env2.update(WEBHOOK_RECOVERY_ACTION="release-phase-unstarted", WEBHOOK_RECOVERY_APPROVAL_SHA256=pin,
                    SUBS_BOT_PHASE_WEBHOOK_UNSTARTED_APPROVAL_SHA256=pin)
        store.put_exclusive.side_effect = OSError("unknown response")
        with patch.object(recovery, "observe", return_value=(plan, lock, store, "private/")), self.assertRaises(OSError):
            recovery.run(env2)
        lock.release.assert_not_called()

    def test_existing_setup_intent_blocks_release_before_any_lock_write(self):
        main, candidate = "a" * 40, "b" * 40
        target = Mock(environment="rehearsal", digest="c" * 64, configuration_digest="d" * 64)
        target.data = {key: key for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}
        target.data.update(botId=recovery.TEST_BOT_ID, botUsername="test_cfsubs_bot")
        draft = Mock(digest="e" * 64, data={})
        registration = canonical({"target": {}, "draftSha256": draft.digest, "targetSha256": target.digest,
                                  "configurationSha256": target.configuration_digest})
        store = Mock()
        store.get.side_effect = lambda key, **_kw: registration if key.endswith("registration.json") else b"existing-intent"
        names = ("Verify trusted coordinator identity before candidate checkout", "Verify exact reviewed coordinator checkout",
                 "Verify isolated coordinator test Bot identity", "Coordinate reviewed isolated backup phases")
        job = {"name": "coordinate", "run_id": 123, "run_attempt": 1, "head_sha": main, "status": "completed",
               "steps": [{"name": name, "status": "completed", "conclusion": "success"} for name in names]}
        def api(path, _token):
            return {"total_count": 1, "jobs": [job]} if "jobs?" in path else {"id": 123, "run_attempt": 1, "status": "completed"}
        env = {"WEBHOOK_SOURCE_KIND": "phase-coordinator", "WEBHOOK_SOURCE_MAIN_SHA": main, "GITHUB_SHA": main,
               "WEBHOOK_REGISTRATION_SHA256": sha256(registration).hexdigest(),
               "SUBS_BOT_PHASE_WEBHOOK_UNSTARTED_REVIEW_JSON": canonical({"version": 1, "dispatcherRevision": main,
                   "candidateRevision": candidate, "setupOrdering": "exclusive-intent-before-setWebhook",
                   "backupOrdering": "callback-after-confirmed-webhook"}).decode()}
        diagnostic = {"status": "read-only-diagnosis", "admission": "closed", "workers": "frozen", "unsettledOrUnknown": False,
                      "webhookLocation": "original", "stateSha256": "f" * 64,
                      "privateRecordsPresent": {"webhookIntent": False, "webhookCompleted": False}}
        with patch.object(recovery, "context", return_value=False), patch.object(recovery, "source_run", return_value=("123", "1", candidate)), \
             patch.object(recovery.github, "_github_token", return_value="synthetic"), \
             patch.object(recovery.github, "compare_commits_metadata", create=True, return_value={"status": "identical", "behind_by": 0,
                          "base_commit": {"sha": main}, "merge_base_commit": {"sha": main}}), \
             patch.object(recovery.github, "_get_json", side_effect=api), patch.object(recovery, "diagnose", return_value=diagnostic), \
             patch.object(recovery, "open_store", return_value=(draft, {}, {"botId": recovery.TEST_BOT_ID}, store, "private/")), \
             patch.object(recovery, "validate_target", return_value=target), patch.object(recovery, "anchor") as lock, \
             self.assertRaises(ContractError):
            recovery.observe(env)
        lock.assert_not_called()

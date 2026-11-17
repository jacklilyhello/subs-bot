"""Synthetic failure-closed checks for the test webhook's history gate."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_webhook_history as history
from production_target import ContractError, canonical


class WebhookHistoryTests(unittest.TestCase):
    def test_split_inventory_rejects_disappearing_runs(self):
        calls = []
        def api(path, _token):
            if path == "":
                return {"created_at": "2026-01-01T00:00:00Z"}
            if path == "/actions/workflows/worker-backup-reviewed-head.yml":
                return {"id": 7, "path": history.HEAD}
            calls.append(path)
            return {"workflow_runs": [], "total_count": 900 if len(calls) == 1 else 0}
        with patch.object(history.github, "_get_json", side_effect=api), self.assertRaises(ContractError):
            history._runs(history.HEAD, "synthetic")
        self.assertEqual(len(calls), 3)

    def environment(self):
        return {"BACKUP_GATE_ROLE": "parent", "BACKUP_ACTION": "plan-webhook-history", "GITHUB_SHA": "a" * 40,
                "GITHUB_RUN_ID": "123", "BACKUP_PHASE_REGISTRATION_SHA256": "d" * 64,
                "SUBS_BOT_PHASE_WEBHOOK_CONTROLLERS_JSON": '["' + "a" * 40 + '"]',
                "SUBS_BOT_PHASE_WEBHOOK_CANDIDATES_JSON": "[]"}

    def inspect(self, env, *, keys=(), runs=()):
        target = Mock(environment="rehearsal", digest="b" * 64, configuration_digest="c" * 64)
        target.data = {key: key for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}
        draft = Mock(digest="e" * 64, data={})
        previous, store, prefix = {"botId": "synthetic", "webhookSecret": "synthetic"}, Mock(), "private/"
        store.objects = Mock()
        store.objects.list.return_value = [prefix + key for key in keys]
        registration = {"target": {}, "targetSha256": target.digest, "draftSha256": draft.digest,
                        "configurationSha256": target.configuration_digest}
        raw = canonical(registration)
        env = {**env, "BACKUP_PHASE_REGISTRATION_SHA256": history.sha256(raw).hexdigest()}
        store.get.return_value = raw
        with patch.object(history, "context", return_value=True), patch.object(history.github, "_github_token", return_value="synthetic"), \
             patch.object(history, "open_store", return_value=(draft, {}, previous, store, prefix)), \
             patch.object(history, "validate_target", return_value=target), \
             patch.object(history, "_runs", side_effect=lambda path, _token: (1, list(runs) if path == history.LIFECYCLE else [])):
            return history.inspect(env)

    def test_empty_history_requires_separately_pinned_digest_before_run(self):
        env = self.environment()
        plan = self.inspect(env)
        self.assertEqual(plan["status"], "resolved")
        with self.assertRaises(ContractError):
            self.inspect({**env, "BACKUP_ACTION": "run"})
        result = self.inspect({**env, "BACKUP_ACTION": "run", "SUBS_BOT_PHASE_WEBHOOK_HISTORY_SHA256": plan["historySha256"]})
        self.assertEqual(result["status"], "resolved")

    def test_unaccounted_snapshot_is_not_promoted_to_success(self):
        result = self.inspect(self.environment(), keys=["webhook-456-1.json"])
        self.assertEqual(result["status"], "needs-reconciliation")
        self.assertEqual(result["unknownRuns"][0]["reason"], "source-not-accounted")
        with self.assertRaises(ContractError):
            self.inspect({**self.environment(), "BACKUP_ACTION": "run", "SUBS_BOT_PHASE_WEBHOOK_HISTORY_SHA256": result["historySha256"]},
                         keys=["webhook-456-1.json"])

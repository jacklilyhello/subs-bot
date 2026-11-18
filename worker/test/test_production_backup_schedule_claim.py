"""Synthetic hosted checks for the disabled scheduled-claim boundary."""
from pathlib import Path
import sys
import unittest
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_schedule_claim as claim
from production_target import canonical
from test_production_backup_scope_bootstrap import BootstrapTarget


class Scoped:
    def __init__(self, target):
        self.bucket = target.data["backupBucketName"]
        self.host = target.account_id + ".r2.cloudflarestorage.com"


class Store:
    def __init__(self, objects):
        self.objects = objects


class Private:
    def __init__(self, target):
        self.bucket = target.data["backupBucketName"]
        self.api = SimpleNamespace(target=target.data)


class Scope:
    def __init__(self, target, objects, genesis):
        self.store = Store(objects)
        self.target_sha256 = claim.schedule.logical_scope(target)
        self.bucket_name = target.data["backupBucketName"]
        self.bucket_created_at = target.data["backupBucketCreatedAt"]
        self.genesis_sha256 = genesis


class TargetAnchor:
    def __init__(self, target, objects, genesis):
        self.store = Store(objects)
        self.target_sha256 = target.digest
        self.genesis_sha256 = genesis


class ScheduledClaimTests(unittest.TestCase):
    def test_source_original_rejects_wrong_revision_or_configuration(self):
        target = BootstrapTarget()
        authority = {"sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64, "sourceRevision": "d" * 40}
        saved = {"sourceTarget": target, "proof": {"revision": "d" * 40}, "manifest": {"revision": "d" * 40}}
        with TemporaryDirectory() as root, \
             patch("production_release_evidence.load_release", return_value=saved) as load:
            env = {"RUNNER_TEMP": root, "SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN": "synthetic-read"}
            observed = claim._source_original(env, target, authority)
            self.assertEqual(observed["sourceRevision"], authority["sourceRevision"])
            self.assertEqual(load.call_args.args[1:4], ("synthetic-read", "e" * 32, "f" * 64))
            saved["proof"]["revision"] = "c" * 40
            with self.assertRaises(ValueError):
                claim._source_original(env, target, authority)

    def test_not_due_does_not_read_or_write_remote_state(self):
        target, pin, genesis = BootstrapTarget(), "a" * 64, "b" * 64
        objects = Scoped(target)
        authority = {"ledgerGenesisSha256": genesis, "targetCoordinatorGenesisSha256": "c" * 64,
                     "sourceRevision": "d" * 40, "sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64}
        env = {"SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED": "true", "GITHUB_SHA": "1" * 40,
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON": canonical(authority).decode(),
               "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256": pin,
               "SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": genesis,
               "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": "c" * 64, "SUBS_BOT_BACKUP_GENESIS_SHA256": "2" * 64}
        with patch.object(claim, "validate_target", return_value=target), patch.object(claim.scoped_r2, "ScopedR2", Scoped), \
             patch.object(claim, "PrivateStore", Private), patch.object(claim.coordinator, "CoordinatorStore", Store), \
             patch.object(claim.coordinator, "ScheduleScopeAnchor", Scope), patch.object(claim.transaction, "Anchor", TargetAnchor), \
             patch.object(claim.schedule, "authority_document", return_value=authority), \
             patch.object(claim.schedule, "eligible_slot", return_value=None), \
             patch.object(claim.coordinator, "verify_context") as remote:
            result = claim.plan_start(env, target, objects, Private(target), Scope(target, objects, genesis),
                                      TargetAnchor(target, objects, "c" * 64), {}, authority, pin, "synthetic")
            self.assertEqual(result, {"version": 1, "status": "not-due", "mutationAuthorized": False})
            remote.assert_not_called()

    def test_claim_is_hard_disabled_before_any_access(self):
        objects = Mock()
        with self.assertRaises(ValueError):
            claim.claim_once({}, None, objects, None, None, None, None, None, None, None)
        objects.assert_not_called()

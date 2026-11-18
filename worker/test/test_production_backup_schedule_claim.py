"""Hosted fixtures for the guarded scheduled claim and its failure boundaries."""
from pathlib import Path
from hashlib import sha256, md5
import sys
import time
import unittest
from types import SimpleNamespace
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_schedule_claim as claim
from production_target import canonical
from test_production_backup_scope_bootstrap import BootstrapTarget
from test_production_backup_schedule_terminal import AppStore


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

    def _claim_fixture(self, *, fail_after=None, remaining=118):
        from contextlib import ExitStack
        from production_target import digest

        class MemoryScoped(Scoped):
            def __init__(self, target):
                super().__init__(target)
                self.write_credential, self.values, self.writes = object(), {}, []
                self.fail_after = None
            def get(self, key, *, absent=False, limit=16 * 1024 * 1024):
                raw = self.values.get(key)
                if raw is None:
                    if absent:
                        return None, None
                    raise ValueError("missing object")
                if len(raw) > limit:
                    raise ValueError("oversized")
                return raw, '"' + md5(raw).hexdigest() + '"'
            def list(self, prefix, *, maximum=10000):
                values = sorted(key for key in self.values if key.startswith(prefix))
                if len(values) > maximum:
                    raise ValueError("inventory bound")
                return values
            def put_once(self, key, raw):
                if key in self.values:
                    raise ValueError("exclusive conflict")
                self.values[key] = raw
                self.writes.append(key)
                if self.fail_after == len(self.writes):
                    raise ValueError("response unknown")
            def compare_and_put(self, key, expected, etag, raw):
                if self.get(key, absent=True) != (expected, etag):
                    raise ValueError("CAS conflict")
                self.values[key] = raw
                self.writes.append(key)
                if self.fail_after == len(self.writes):
                    raise ValueError("response unknown")
                return self.get(key)[1]

        class MemoryPrivate(AppStore):
            def __init__(self, target, objects):
                super().__init__()
                self.bucket, self.objects = target.data["backupBucketName"], objects
                self.api = SimpleNamespace(target=target.data)
            def verify(self):
                return {"private": True}

        class Fresh:
            def get(self, path, *, verify):
                job = {"id": 1234, "name": "coordinate", "run_id": 123, "run_attempt": 1,
                       "head_sha": "c" * 40, "status": "in_progress", "conclusion": None,
                       "steps": [{"name": name, "status": "in_progress" if index == 3 else "completed",
                                  "conclusion": None if index == 3 else "success"} for index, name in enumerate((
                           "Check scheduled authority switch", "Check out trusted current main",
                           "Verify scheduled dispatcher identity", "Coordinate one explicitly approved operation"))]}
                if verify(job) is not True:
                    raise ValueError("unconfirmed GH job")
                return job

        target = BootstrapTarget()
        objects = MemoryScoped(target)
        app_store = MemoryPrivate(target, objects)
        app_seed = claim.transaction.Anchor(app_store, target.digest, "0" * 64)
        app_sha = sha256(app_seed.initial_material()[1]).hexdigest()
        claim.transaction.Anchor(app_store, target.digest, app_sha).initialize()
        scope = claim.schedule.logical_scope(target)
        scope_store = claim.coordinator.CoordinatorStore(objects, scope)
        scope_seed = claim.coordinator.ScheduleScopeAnchor(scope_store, scope, "0" * 64,
            target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
        scope_sha = sha256(scope_seed.initial_material()[1]).hexdigest()
        scope_anchor = claim.coordinator.ScheduleScopeAnchor(scope_store, scope, scope_sha,
            target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
        scope_anchor.initialize()
        target_store = claim.coordinator.CoordinatorStore(objects, target.digest)
        target_seed = claim.transaction.Anchor(target_store, target.digest, "0" * 64)
        target_sha = sha256(target_seed.initial_material()[1]).hexdigest()
        target_anchor = claim.transaction.Anchor(target_store, target.digest, target_sha)
        target_anchor.initialize()
        objects.writes.clear()
        objects.fail_after = fail_after
        policy = {"frequencyHours": 24, "windowStartUtc": "01:00", "windowMinutes": 60,
                  "pauseLimitSeconds": 300, "maximumPauseSeconds": 1800}
        now = int(time.time())
        authority = {"version": 1, "kind": "production-backup-schedule", "environment": "production",
            "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
            "scopeSha256": scope, "resourcePins": claim.schedule.resource_pins(target), "controlRevision": "c" * 40,
            "sourceRevision": "d" * 40, "sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64,
            "policySha256": digest(policy), "validFrom": now - 10, "validUntil": now + 3600,
            "frequencyHours": 24, "maxExecutions": 7, "recoveryGraceSeconds": 3600,
            "ledgerGenesisSha256": scope_sha, "targetCoordinatorGenesisSha256": target_sha,
            "applicationGenesisSha256": app_sha, "readerLogRetentionDays": 90, "readerLogWarningDays": 7,
            "readerLogStopBeforeDays": 2, "actions": list(claim.schedule.ACTIONS),
            "authorization": "approved-recurring-backup-only"}
        pin, day = digest(authority), "2026-11-18"
        env = {"SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED": "true", "GITHUB_SHA": "c" * 40,
            "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON": canonical(authority).decode(),
            "SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256": pin,
            "SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": scope_sha,
            "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": target_sha, "SUBS_BOT_BACKUP_GENESIS_SHA256": app_sha,
            "SUBS_BOT_BACKUP_POLICY_JSON": canonical(policy).decode(), "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_SHA": "c" * 40, "GITHUB_REF": claim.github.MAIN_REF, "GITHUB_EVENT_NAME": "schedule",
            "GITHUB_REPOSITORY": claim.github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(claim.github.REPOSITORY_ID),
            "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_WORKFLOW_REF": claim.github.REPOSITORY +
                "/.github/workflows/worker-production-backup-coordinator.yml@" + claim.github.MAIN_REF}
        scope_value, scope_raw, _ = scope_anchor.read()
        target_value, target_raw, _ = target_anchor.read()
        _app, app_raw, _ = claim.transaction.Anchor(app_store, target.digest, app_sha).read()
        material = claim.coordinator.scheduled_start_material(target, policy, authority, pin, day, "123",
                                                               scope_value, scope_raw, target_value, target_raw)
        scope_keys = objects.list(claim.schedule.BASE + scope + "/")
        coordinator_keys = objects.list(claim.coordinator.BASE)
        plan = {"version": 1, "status": "observed", "day": day, "mutationAuthorized": False,
                "appAnchorSha256": sha256(app_raw).hexdigest(), "scopeAnchorSha256": sha256(scope_raw).hexdigest(),
                "targetAnchorSha256": sha256(target_raw).hexdigest(), "materialSha256": digest(material),
                "scopeKeysSha256": digest(scope_keys), "coordinatorKeysSha256": digest(coordinator_keys), "parentJobId": "1234"}
        source = {"targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                  "sourceCheckpointId": "e" * 32, "sourceManifestSha256": "f" * 64, "sourceRevision": "d" * 40}
        stack = ExitStack()
        for manager in (patch.object(claim, "plan_start", return_value=plan),
                        patch.object(claim, "validate_target", return_value=target),
                        patch.object(claim.scoped_r2, "ScopedR2", MemoryScoped),
                        patch.object(claim, "PrivateStore", MemoryPrivate),
                        patch.object(claim, "_source_original", return_value=source),
                        patch.object(claim.github, "_github_token", return_value="synthetic"),
                        patch.object(claim.schedule, "eligible_slot", return_value=day),
                        patch.object(claim.backup, "settings", return_value=policy),
                        patch.object(claim.backup, "scheduled_main_guard"),
                        patch.object(claim.coordinator, "scheduled_running_parent", return_value=1234),
                        patch.object(claim.coordinator, "bootstrap_rate_limit", return_value={"resources": {"core":
                            {"remaining": remaining, "reset": now + 3600}}}),
                        patch("production_backup_fresh_github.FreshConditionalJSON", Fresh)):
            stack.enter_context(manager)
        return stack, (env, target, objects, app_store, scope_anchor, target_anchor, policy, authority, pin, "synthetic")

    def test_complete_claim_has_seven_exact_mutations_and_no_replay(self):
        stack, args = self._claim_fixture()
        with stack:
            owner = claim.claim_once(*args)
            self.assertEqual(type(owner).__name__, "ScheduledScopeOwner")
            self.assertEqual(len(args[2].writes), 7)
            self.assertEqual(args[4].read()[0]["state"], "active")
            self.assertEqual(args[5].read()[0]["state"], "active")
            with self.assertRaises(ValueError):
                claim.claim_once(*args)
            self.assertEqual(len(args[2].writes), 7)

    def test_lost_response_at_each_mutation_never_replays(self):
        for index in range(1, 8):
            with self.subTest(write=index):
                stack, args = self._claim_fixture(fail_after=index)
                with stack:
                    with self.assertRaises(ValueError):
                        claim.claim_once(*args)
                    self.assertEqual(len(args[2].writes), index)
                    with self.assertRaises(ValueError):
                        claim.claim_once(*args)
                    self.assertEqual(len(args[2].writes), index)

    def test_insufficient_quota_stops_before_first_write(self):
        stack, args = self._claim_fixture(remaining=117)
        with stack, self.assertRaises(ValueError):
            claim.claim_once(*args)
        self.assertEqual(args[2].writes, [])

    def test_competing_orphan_stops_before_next_claim_write(self):
        stack, args = self._claim_fixture()
        objects, target = args[2], args[1]
        calls, original_list = [], objects.list
        prefix = claim.schedule.BASE + claim.schedule.logical_scope(target) + "/"
        def list_with_competitor(requested, *, maximum=10000):
            if requested == prefix:
                calls.append(1)
                if len(calls) == 3:
                    objects.values[prefix + "unexpected"] = b"unknown"
            return original_list(requested, maximum=maximum)
        with stack, patch.object(objects, "list", side_effect=list_with_competitor):
            with self.assertRaises(ValueError):
                claim.claim_once(*args)
            self.assertEqual(len(objects.writes), 1)

    def test_parent_job_stop_is_rejected_before_any_write(self):
        stack, args = self._claim_fixture()
        with stack, patch.object(claim.coordinator, "scheduled_running_job", return_value=False):
            with self.assertRaises(ValueError):
                claim.claim_once(*args)
        self.assertEqual(args[2].writes, [])

    def test_window_closing_during_guard_stops_before_first_write(self):
        stack, args = self._claim_fixture()
        with stack, patch.object(claim.schedule, "eligible_slot", side_effect=["2026-11-18", None]):
            with self.assertRaises(ValueError):
                claim.claim_once(*args)
        self.assertEqual(args[2].writes, [])

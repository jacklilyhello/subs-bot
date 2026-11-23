"""Synthetic hosted checks for first-launch scope evidence; no cloud access."""
from datetime import datetime, timezone
from pathlib import Path
import sys
import unittest
from hashlib import sha256
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_scope_bootstrap as bootstrap
from production_target import canonical, digest
from test_production_backup_schedule import Target


class BootstrapTarget(Target):
    @property
    def account_id(self):
        return self.data["accountId"]


class Objects:
    def __init__(self, account, bucket):
        self.host, self.bucket = account + ".r2.cloudflarestorage.com", bucket
        self.write_credential = None
        self.values = {}

    def list(self, prefix, *, maximum=10000):
        rows = sorted(key for key in self.values if key.startswith(prefix))
        if len(rows) > maximum:
            raise ValueError("inventory bound")
        return rows

    def get(self, key, *, limit=16 * 1024 * 1024):
        value = self.values[key]
        if len(value) > limit:
            raise ValueError("size bound")
        return value, '"' + "0" * 32 + '"'


class ReadAPI:
    def __init__(self, target, token):
        self.target, self.token, self.create = target.data, token, False
        self.root = "/accounts/" + target.account_id


class ReviewTime(datetime):
    @classmethod
    def now(cls, tz=None):
        return cls(2026, 1, 1, 3, tzinfo=timezone.utc).astimezone(tz)


def review_environment(action):
    return {"GITHUB_REPOSITORY": bootstrap.github.REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(bootstrap.github.REPOSITORY_ID), "GITHUB_REF": bootstrap.github.MAIN_REF,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_RUN_ID": "999", "GITHUB_SHA": "f" * 40, "BACKUP_COORDINATOR_ACTION": action,
            "GITHUB_WORKFLOW_REF": bootstrap.github.REPOSITORY
                + "/.github/workflows/worker-production-backup-coordinator.yml@" + bootstrap.github.MAIN_REF}


class BootstrapTests(unittest.TestCase):
    def test_bootstrap_gh_read_does_not_retry_or_expose_errors(self):
        for failure in (OSError("sensitive transport detail"),
                        HTTPError("https://example.invalid/private", 503, "sensitive detail", {}, None)):
            with self.subTest(failure=type(failure).__name__), \
                 patch.object(bootstrap.github._OPENER, "open", side_effect=failure) as opened:
                with self.assertRaises(ValueError) as caught:
                    bootstrap._get_json("/actions/runs", "synthetic")
                self.assertEqual(opened.call_count, 1)
                self.assertNotIn("sensitive", str(caught.exception))
                self.assertNotIn("example.invalid", str(caught.exception))

    def test_plan_then_each_guard_binds_approved_stage_and_rejects_drift(self):
        target = BootstrapTarget()
        objects = Objects(target.account_id, target.data["backupBucketName"])
        data_objects = Objects(target.account_id, target.data["bucketName"])
        anchor_objects = Objects(target.account_id, "provision-anchor")
        scope = bootstrap.schedule.logical_scope(target)
        store = bootstrap.coordinator.CoordinatorStore(objects, scope)
        anchor = bootstrap.coordinator.ScheduleScopeAnchor(store, scope, "0" * 64,
            target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
        initial, genesis = anchor.initial_material()
        anchor.genesis_sha256 = sha256(genesis).hexdigest()
        receipt = {"runId": "123", "revision": "b" * 40}
        original = {"receipt": receipt, "provisionJournalSha256": "c" * 64}
        reg = "d" * 64
        review = {"version": 1, "kind": "new-production-scope-bootstrap-review", "targetSha256": target.digest,
            "configurationSha256": target.configuration_digest, "scopeSha256": scope, "registrationSha256": reg,
            "windowStart": "2025-12-31T23:00:00Z", "windowEnd": "2026-01-01T01:00:00Z",
            "reviewedRuns": [{"runId": "123", "revision": "b" * 40,
                "path": ".github/workflows/worker-production-control.yml", "classification": "provision-only"}],
            "custody": bootstrap.CUSTODY, "noPriorInFlightWriter": True}
        raw = canonical(review).decode()
        review_pin = sha256(raw.encode()).hexdigest()
        env = {"GITHUB_REPOSITORY": bootstrap.github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(bootstrap.github.REPOSITORY_ID),
            "GITHUB_REF": bootstrap.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
            "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ID": "456", "GITHUB_SHA": "f" * 40,
            "GITHUB_WORKFLOW_REF": bootstrap.github.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + bootstrap.github.MAIN_REF,
            "BACKUP_COORDINATOR_ACTION": "plan-schedule-anchor", "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON": raw,
            "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256": review_pin,
            "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REGISTRATION_SHA256": reg,
            "SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN": "read-data", "SUBS_BOT_CF_WORKER_READ_TOKEN": "read-worker",
            "SUBS_BOT_CF_R2_METADATA_READ_TOKEN": "read-metadata",
            "SUBS_BOT_PROVISION_ANCHOR_JSON": canonical({"accountId": target.account_id,
                "bucketName": anchor_objects.bucket, "bucketCreatedAt": "2025-12-01T00:00:00Z"}).decode()}
        data_api, worker_api, meta_api = (ReadAPI(target, env[key]) for key in
            ("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN", "SUBS_BOT_CF_WORKER_READ_TOKEN", "SUBS_BOT_CF_R2_METADATA_READ_TOKEN"))
        observation = {"safe": True}
        writers = {"inventorySha256": digest(review["reviewedRuns"]), "reviewedRunCount": 1, "laterRunCount": 0}
        registration_key = "maintenance/production-control/registrations/" + target.digest + ".json"
        objects.values[registration_key] = b"fixture"
        args = (env, target, objects, data_objects, anchor_objects, data_api, worker_api, meta_api, anchor, raw, review_pin, reg, "gh-token")
        with patch.object(bootstrap, "validate_target", return_value=target), patch.object(bootstrap.scoped_r2, "ScopedR2", Objects), \
             patch.object(bootstrap.control, "API", ReadAPI), patch.object(bootstrap.control, "privacy", return_value={}), \
             patch.object(bootstrap, "provision_original", return_value=original), \
             patch.object(bootstrap, "new_resource_observation", return_value=observation), \
             patch.object(bootstrap, "_provision_job"), patch.object(bootstrap, "verify_first_launch_writers", return_value=writers) as guard_writers, \
             patch.object(bootstrap, "_require_current_main"), \
             patch.object(bootstrap, "_get_json", return_value={"created_at": "2025-12-31T23:30:00Z"}):
            plan = bootstrap.plan_first_launch(*args)
            env.update({"BACKUP_COORDINATOR_ACTION": "initialize-schedule-anchor",
                "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_PLAN_SHA256": digest(plan), "BACKUP_COORDINATOR_APPROVAL_SHA256": digest(plan),
                "SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256": plan["scopeGenesisSha256"],
                "SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256": plan["targetCoordinatorGenesisSha256"]})
            bootstrap.verify_first_launch_guard(*args, plan, stage=0)
            genesis_key = store._key(anchor.genesis_key)
            objects.values[genesis_key] = genesis
            bootstrap.verify_first_launch_guard(*args, plan, stage=1)
            history_key = store._key(anchor.history_key(1, initial))
            objects.values[history_key] = initial
            bootstrap.verify_first_launch_guard(*args, plan, stage=2)
            env["BACKUP_COORDINATOR_APPROVAL_SHA256"] = "e" * 64
            with self.assertRaises(ValueError):
                bootstrap.verify_first_launch_guard(*args, plan, stage=2)
            env["BACKUP_COORDINATOR_APPROVAL_SHA256"] = digest(plan)
            objects.values["unknown"] = b"x"
            with self.assertRaises(ValueError):
                bootstrap.verify_first_launch_guard(*args, plan, stage=2)
            del objects.values["unknown"]
            guard_writers.side_effect = ValueError("unknown writer")
            with self.assertRaises(ValueError):
                bootstrap.verify_first_launch_guard(*args, plan, stage=2)

    def test_source_bucket_must_be_the_registered_empty_bucket(self):
        target = BootstrapTarget()
        source = Objects(target.account_id, target.data["bucketName"])
        with patch.object(bootstrap.scoped_r2, "ScopedR2", Objects):
            bootstrap.empty_source_bucket(target, source)
            source.values["business/unknown"] = b""
            with self.assertRaises(ValueError):
                bootstrap.empty_source_bucket(target, source)
            with self.assertRaises(ValueError):
                bootstrap.empty_source_bucket(target, Objects(target.account_id, target.data["backupBucketName"]))

    def test_review_and_registration_are_independently_pinned(self):
        env = {"SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON": "{}",
               "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256": "a" * 64,
               "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REGISTRATION_SHA256": "b" * 64}
        bootstrap._protected_inputs(env, "{}", "a" * 64, "b" * 64)
        for review, pin, registration in (("{ }", "a" * 64, "b" * 64),
                                          ("{}", "c" * 64, "b" * 64),
                                          ("{}", "a" * 64, "c" * 64)):
            with self.assertRaises(ValueError):
                bootstrap._protected_inputs(env, review, pin, registration)

    def test_gh_pages_are_complete_and_reject_duplicate_or_count_drift(self):
        pages = [{"total_count": 51, "workflow_runs": [{"id": index} for index in range(1, 51)]},
                 {"total_count": 51, "workflow_runs": [{"id": 51}]}]
        with patch.object(bootstrap, "_get_json", side_effect=pages):
            self.assertEqual(len(bootstrap._pages("/actions/runs?created=x", "workflow_runs", "synthetic")), 51)
        duplicate = [pages[0], {"total_count": 51, "workflow_runs": [{"id": 1}]}]
        with patch.object(bootstrap, "_get_json", side_effect=duplicate), self.assertRaises(ValueError):
            bootstrap._pages("/actions/runs?created=x", "workflow_runs", "synthetic")
        changed = [pages[0], {"total_count": 52, "workflow_runs": [{"id": 51}, {"id": 52}]}]
        with patch.object(bootstrap, "_get_json", side_effect=changed), self.assertRaises(ValueError):
            bootstrap._pages("/actions/runs?created=x", "workflow_runs", "synthetic")

    def test_bootstrap_proposes_and_rechecks_every_reviewed_run_across_pages(self):
        target = BootstrapTarget()
        env = review_environment("plan-schedule-anchor")
        repo = {"id": bootstrap.github.REPOSITORY_ID}
        start = "2026-01-01T00:00:00Z"
        runs = [{"id": index, "created_at": start, "run_attempt": 1, "head_branch": "main", "head_sha": "e" * 40,
                 "event": "schedule", "path": ".github/workflows/worker-backup-monitor.yml",
                 "repository": repo, "head_repository": repo, "status": "completed", "conclusion": "success"}
                for index in range(1, 57)]
        runs[0].update({"path": ".github/workflows/worker-production-control.yml", "event": "workflow_dispatch"})
        pages = []

        def github_read(path, token):
            url = urlsplit(path)
            if url.path == "/actions/runs":
                page = int(parse_qs(url.query)["page"][0])
                self.assertEqual(parse_qs(url.query)["created"], [start + "..2026-01-01T03:00:00Z"])
                pages.append(page)
                current = {"id": 999, "created_at": "2026-01-01T02:00:00Z"}
                ordered = [current, *reversed(runs)]
                offset = (page - 1) * bootstrap.RUN_PAGE_SIZE
                return {"total_count": len(ordered), "workflow_runs": ordered[offset:offset + bootstrap.RUN_PAGE_SIZE]}
            if path == "/actions/runs/1/attempts/1":
                return runs[0]
            return runs[int(url.path.rsplit("/", 1)[-1]) - 1]

        def jobs(run_id, token):
            return [{"id": int(run_id) + 1000, "run_id": int(run_id), "run_attempt": 1, "head_sha": "e" * 40,
                     "status": "completed", "conclusion": "success"}]

        with patch.object(bootstrap, "datetime", ReviewTime), patch.object(bootstrap, "_get_json", side_effect=github_read), \
             patch.object(bootstrap, "_attempt_jobs", side_effect=jobs) as job_reads, \
             patch.object(bootstrap, "_workflow_identity", return_value=("c" * 64, "e" * 40)) as source_reads, \
             patch.object(bootstrap, "_provision_job"), patch.object(bootstrap, "_bootstrap_run"), \
             patch.object(bootstrap, "_require_current_main"), \
             patch.object(bootstrap, "provision_original", return_value={"receipt": {"runId": "1"}}):
            review = bootstrap.propose_writer_review(env, target, None, None, "a" * 64, "token")
            self.assertEqual([row["runId"] for row in review["reviewedRuns"]], [str(run["id"]) for run in runs])
            self.assertEqual(review["reviewedRuns"][0]["classification"], "provision-only")
            self.assertEqual(pages, [1, 2, 1, 2])
            self.assertEqual(job_reads.call_count, 56)
            self.assertEqual(source_reads.call_count, 2)
            raw = canonical(review).decode()
            pin = digest(review)
            env.update({"SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON": raw,
                        "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256": pin})
            observed = bootstrap.verify_first_launch_writers(env, raw, pin, "token")
            self.assertEqual(observed["reviewedRunCount"], 56)
            self.assertEqual(pages, [1, 2, 1, 2] * 2)
            self.assertEqual(job_reads.call_count, 112)

    def test_later_inventory_rechecks_more_than_five_and_stops_for_unknown_writer(self):
        env = review_environment("initialize-schedule-anchor")
        approved = {"runId": "1", "path": ".github/workflows/worker-production-control.yml",
                    "revision": "b" * 40, "classification": "provision-only"}
        review = {"version": 1, "kind": "new-production-scope-bootstrap-review", "custody": bootstrap.CUSTODY,
                  "noPriorInFlightWriter": True, "reviewedRuns": [approved],
                  "windowStart": "2026-01-01T00:00:00Z", "windowEnd": "2026-01-01T01:00:00Z"}
        raw, pin = canonical(review).decode(), digest(review)
        env.update({"SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON": raw,
                    "SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256": pin})
        path = ".github/workflows/worker-backup-monitor.yml"
        history = {"id": 1, "path": approved["path"], "head_sha": approved["revision"],
                   "created_at": review["windowStart"]}
        later = [{"id": index, "created_at": "2026-01-01T02:00:00Z", "event": "schedule", "path": path}
                 for index in range(2, 12)]
        evidence = {key: value for key, value in approved.items() if key != "classification"}
        with patch.object(bootstrap, "datetime", ReviewTime), \
             patch.object(bootstrap, "_writer_runs", return_value=[history, *later]) as inventory, \
             patch.object(bootstrap, "_run_evidence", return_value=evidence), patch.object(bootstrap, "_bootstrap_run"), \
             patch.object(bootstrap, "_require_current_main"), \
             patch.object(bootstrap, "_isolated_cron_inert", return_value=True) as inert:
            self.assertEqual(bootstrap.verify_first_launch_writers(env, raw, pin, "token")["laterRunCount"], 10)
            self.assertEqual(inert.call_count, 10)
            with self.assertRaisesRegex(ValueError, "reserved writer observation budget"):
                bootstrap.verify_first_launch_writers(env, raw, pin, "token", later_limit=8)
            changed = {**later[-1], "path": ".github/workflows/unknown.yml", "event": "workflow_dispatch"}
            inventory.return_value = [history, *later[:-1], changed]
            with self.assertRaisesRegex(ValueError, "unreviewed writer"):
                bootstrap.verify_first_launch_writers(env, raw, pin, "token")
            inventory.side_effect = [[history, *later], [history, *later, changed]]
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                bootstrap.verify_first_launch_writers(env, raw, pin, "token")

    def test_scheduled_isolation_requires_pinned_source_and_actual_skipped_steps(self):
        path = ".github/workflows/worker-production-lifecycle-rehearsal.yml"
        pin, titles, policy = bootstrap.ISOLATION_CRON[path]
        revision = "f" * 40
        repo = {"id": bootstrap.github.REPOSITORY_ID}
        run = {"id": 123, "display_title": titles[1] + " at " + revision, "event": "schedule", "run_attempt": 1,
               "status": "completed", "head_sha": revision, "head_branch": "main", "path": path,
               "repository": repo, "head_repository": repo}
        jobs = [{"name": name, "run_id": 123, "run_attempt": 1, "head_sha": revision, "status": "completed",
                 "conclusion": "success" if steps else "skipped",
                 "steps": [{"name": step, "status": "completed", "conclusion": "skipped"} for step in steps]}
                for name, steps in policy.items()]
        with patch.object(bootstrap, "_get_json", return_value=run), \
             patch.object(bootstrap, "_attempt_jobs", return_value=jobs), \
             patch.object(bootstrap, "_workflow_identity", return_value=(pin, "e" * 40)) as source:
            self.assertTrue(bootstrap._isolated_cron_inert(run, path, revision, "token", {}))
            jobs[1]["steps"][0]["conclusion"] = "success"
            with self.assertRaisesRegex(ValueError, "used credentials"):
                bootstrap._isolated_cron_inert(run, path, revision, "token", {})
            source.return_value = ("a" * 64, "e" * 40)
            with self.assertRaisesRegex(ValueError, "fresh source review"):
                bootstrap._isolated_cron_inert(run, path, revision, "token", {})

    def test_new_registration_is_bound_to_full_separate_journal(self):
        target = BootstrapTarget()
        source = Objects(target.account_id, target.data["backupBucketName"])
        anchor = Objects(target.account_id, "old-private-anchor")
        t = target.data
        resources = {"database": {"id": t["d1Id"], "name": t["d1Name"], "createdAt": t["d1CreatedAt"]},
                     "worker": {"id": t["workerId"], "name": t["workerName"], "createdOn": t["workerCreatedOn"]},
                     "bucketName": {"name": t["bucketName"], "createdAt": t["bucketCreatedAt"], "private": True},
                     "backupBucketName": {"name": t["backupBucketName"], "createdAt": t["backupBucketCreatedAt"], "private": True}}
        receipt = {"state": "created-no-module-no-consumer", "targetSha256": target.digest, "target": t,
                   "draftSha256": "a" * 64, "revision": "b" * 40, "runId": "123", "runAttempt": "1",
                   "resources": resources, "intents": {key: {"state": "confirmed"} for key in resources}}
        first = {"generation": 1, "previousSha256": None, "draftSha256": "a" * 64, "value": {"state": "intent"}}
        second = {"generation": 2, "previousSha256": sha256(canonical(first)).hexdigest(),
                  "draftSha256": "a" * 64, "value": receipt}
        prefix = "maintenance/production-control/registrations/provision-" + "a" * 64 + "/"
        anchor.values[prefix + "000001.json"] = canonical(first)
        anchor.values[prefix + "000002.json"] = canonical(second)
        key = "maintenance/production-control/registrations/" + target.digest + ".json"
        source.values[key] = canonical(receipt)
        pin = sha256(canonical(receipt)).hexdigest()
        with patch.object(bootstrap.scoped_r2, "ScopedR2", Objects):
            observed = bootstrap.provision_original(target, source, anchor, pin)
            self.assertEqual(observed["provisionJournalGenerations"], 2)
            anchor.values[prefix + "000002.json"] = canonical({**second, "previousSha256": "c" * 64})
            with self.assertRaises(ValueError):
                bootstrap.provision_original(target, source, anchor, pin)
            anchor.values[prefix + "000002.json"] = canonical(second)
            source.values["unclassified-object"] = b"unexpected"
            with self.assertRaises(ValueError):
                bootstrap.provision_original(target, source, anchor, pin)


if __name__ == "__main__":
    unittest.main()

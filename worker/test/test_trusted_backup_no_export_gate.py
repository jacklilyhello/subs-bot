"""Hosted fail-closed tests for the one fixed no-export evidence gate."""
from pathlib import Path
import base64
import json
from hashlib import sha256
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_no_export_gate as gate
from production_target import ContractError


class NoExportGateTests(unittest.TestCase):
    def test_single_metadata_read_never_retries_or_exposes_transport_details(self):
        secret = "synthetic-sensitive-transport-detail"
        with patch.object(gate.github._OPENER, "open", side_effect=OSError(secret)) as request, \
             self.assertRaises(ContractError) as error:
            gate.read_json("/git/ref/heads/main", "synthetic")
        self.assertEqual(request.call_count, 1)
        self.assertNotIn(secret, str(error.exception))

    def test_failure_phase_never_accepts_or_emits_arbitrary_input(self):
        gate.gate_stage("identity")
        secret = "synthetic-sensitive-input"
        with self.assertRaises(ContractError) as error:
            gate.gate_stage(secret)
        self.assertEqual(gate.GATE_STAGE, "identity")
        self.assertNotIn(secret, str(error.exception))

    def test_only_two_pinned_zero_job_pushes_are_classified(self):
        repo = {"id": gate.github.REPOSITORY_ID}
        for run_id, pin in gate.UNSTARTED_PUSHES.items():
            with self.subTest(run=run_id):
                item = {"id": int(run_id), "path": gate.UNSTARTED_WORKFLOW, "event": "push",
                        "head_sha": pin["head"], "run_attempt": 1}
                run = {**item, "head_branch": "codex/backup-coordinator", "created_at": pin["createdAt"],
                       "workflow_id": 421656360, "check_suite_id": int(pin["suite"]),
                       "status": "completed", "conclusion": "failure", "repository": repo, "head_repository": repo}
                suite = {"id": int(pin["suite"]), "head_branch": run["head_branch"], "head_sha": pin["head"],
                         "status": "completed", "conclusion": "failure", "latest_check_runs_count": 0,
                         "app": {"id": 15368, "slug": "github-actions"}, "repository": repo}
                empty_jobs, empty_checks = {"total_count": 0, "jobs": []}, {"total_count": 0, "check_runs": []}
                responses = [run, run, empty_jobs, suite, empty_checks]
                with tempfile.TemporaryDirectory() as directory, \
                     patch.object(gate, "read_json", side_effect=responses), patch.object(gate, "reviewed_source") as source:
                    gate.verify_fixed_unstarted_push(item, {"RUNNER_TEMP": directory}, "x")
                    self.assertEqual(source.call_args.args[:3], (pin["head"], gate.UNSTARTED_WORKFLOW, gate.UNSTARTED_WORKFLOW_SHA256))
                    with patch.object(gate, "read_json", return_value=run) as fresh:
                        gate.verify_fixed_unstarted_push(item, {"RUNNER_TEMP": directory}, "x")
                        self.assertEqual(fresh.call_count, 1)
                        self.assertEqual(fresh.call_args.args[0], "/actions/runs/" + run_id)
                    with patch.object(gate, "read_json", return_value={**run, "run_attempt": 2}) as fresh, self.assertRaises(ContractError):
                        gate.verify_fixed_unstarted_push(item, {"RUNNER_TEMP": directory}, "x")
                    self.assertEqual(fresh.call_count, 1)
                invalid = [
                    [run, {**run, "run_attempt": 2}],
                    [run, {**run, "head_sha": "f" * 40}],
                    [run, run, {"total_count": 1, "jobs": [{"id": 1}]}],
                    [run, run, {"total_count": False, "jobs": []}],
                    [run, run, empty_jobs, {**suite, "conclusion": "success"}],
                    [run, run, empty_jobs, suite, {"total_count": 1, "check_runs": [{"id": 1}]}],
                    [run, run, empty_jobs, suite, {"total_count": False, "check_runs": []}],
                ]
                for data in invalid:
                    with tempfile.TemporaryDirectory() as directory, patch.object(gate, "read_json", side_effect=data), \
                         patch.object(gate, "reviewed_source") as source, self.assertRaises(ContractError):
                        gate.verify_fixed_unstarted_push(item, {"RUNNER_TEMP": directory}, "x")
                    source.assert_not_called()
                for changed in ({**item, "id": 123}, {**item, "run_attempt": 2}, {**item, "head_sha": "e" * 40}):
                    with patch.object(gate, "read_json") as read, self.assertRaises(ContractError):
                        gate.verify_fixed_unstarted_push(changed, {"RUNNER_TEMP": "/synthetic"}, "x")
                    read.assert_not_called()

    def test_pinned_private_cache_rehashes_without_replacing_changed_evidence(self):
        body = b"synthetic private evidence"
        with tempfile.TemporaryDirectory() as directory:
            calls = []
            def fetch():
                calls.append(True)
                return body
            self.assertEqual(gate.cached_private_bytes(directory, "run-job", sha256(body).hexdigest(), 1024, fetch), body)
            self.assertEqual(gate.cached_private_bytes(directory, "run-job", sha256(body).hexdigest(), 1024, fetch), body)
            self.assertEqual(len(calls), 1)
            cached = next((Path(directory) / "no-export-reviewed-evidence-cache").iterdir())
            cached.write_bytes(b"changed")
            with self.assertRaises(ContractError):
                gate.cached_private_bytes(directory, "run-job", sha256(body).hexdigest(), 1024, fetch)
            self.assertEqual(len(calls), 1)
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "no-export-reviewed-evidence-cache").symlink_to(Path(directory))
            with self.assertRaises(ContractError):
                gate.cached_private_bytes(directory, "run-job", sha256(body).hexdigest(), 1024, lambda: body)

    def test_live_projection_preserves_fresh_status_without_changing_historic_shape(self):
        repo = {"id": gate.github.REPOSITORY_ID}
        row = {"id": 1, "path": "x", "event": "workflow_dispatch", "head_sha": "a" * 40,
               "created_at": "2026-01-01T00:00:00Z", "run_attempt": 1, "status": "completed", "conclusion": "success",
               "display_title": "safe", "workflow_id": 7, "head_branch": "main", "repository": repo, "head_repository": repo}
        with patch.object(gate, "read_json", return_value={"total_count": 1, "workflow_runs": [row]}):
            historic = gate.workflow_runs("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "x", maximum=150)
            live = gate.workflow_runs("2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "x", maximum=400, live_metadata=True)
        self.assertNotIn("status", historic[0])
        self.assertEqual((live[0]["status"], live[0]["conclusion"], live[0]["repository"]), ("completed", "success", repo))

    def test_pinned_legacy_archive_rejects_unreviewed_or_inflight_runs(self):
        repo = {"id": gate.github.REPOSITORY_ID}
        source = next(iter(gate.LEGACY_SOURCE_LOGS))
        record = {"action": "plan", "sourceRunId": source, "archiveJobId": "10", "readbackJobId": "",
                  "jobsSha256": "a" * 64, "archiveLogSha256": "b" * 64, "readbackLogSha256": "",
                  "sourceLogSha256": gate.LEGACY_SOURCE_LOGS[source], "planSha256": "c" * 64, "completionSha256": ""}
        row = {"id": 123, "path": gate.LEGACY_ARCHIVE_WORKFLOW, "event": "workflow_dispatch", "head_sha": gate.LATER_PROVIDER_MAIN,
               "run_attempt": 1, "head_branch": "main", "status": "completed", "conclusion": "success",
               "display_title": "Preserve isolated webhook evidence " + source, "repository": repo, "head_repository": repo}
        ledger, rows = {}, []
        for index, (source_id, source_sha) in enumerate(gate.LEGACY_SOURCE_LOGS.items()):
            for offset, action in enumerate(("plan", "seal")):
                run_id = str(1000 + 2 * index + offset)
                ledger[run_id] = {**record, "action": action, "sourceRunId": source_id, "sourceLogSha256": source_sha}
                rows.append({**row, "id": int(run_id), "display_title": "Preserve isolated webhook evidence " + source_id})
        env = {"GITHUB_RUN_ID": "99", "GITHUB_SHA": "a" * 40, "NO_EXPORT_LEGACY_ARCHIVES_JSON": json.dumps(ledger)}
        with patch.object(gate, "verify_legacy_archive") as checked:
            self.assertEqual(gate.live_writer_boundary(rows, env, "x", "b" * 40), 14)
            self.assertEqual(checked.call_count, 14)
        with self.assertRaises(ContractError):
            gate.live_writer_boundary([row], {**env, "NO_EXPORT_LEGACY_ARCHIVES_JSON": "{}"}, "x", "b" * 40)
        with self.assertRaises(ContractError):
            gate.verify_legacy_archive({**row, "status": "in_progress"}, record, env, "x")

    def test_sealed_legacy_archive_requires_matching_independent_reader(self):
        repo = {"id": gate.github.REPOSITORY_ID}
        source = next(iter(gate.LEGACY_SOURCE_LOGS))
        record = {"action": "seal", "sourceRunId": source, "archiveJobId": "10", "readbackJobId": "11",
                  "jobsSha256": "a" * 64, "archiveLogSha256": "b" * 64, "readbackLogSha256": "c" * 64,
                  "sourceLogSha256": gate.LEGACY_SOURCE_LOGS[source], "planSha256": "d" * 64, "completionSha256": "e" * 64}
        row = {"id": 123, "path": gate.LEGACY_ARCHIVE_WORKFLOW, "event": "workflow_dispatch", "head_sha": gate.LATER_PROVIDER_MAIN,
               "run_attempt": 1, "head_branch": "main", "status": "completed", "conclusion": "success",
               "display_title": "Preserve isolated webhook evidence " + source, "repository": repo, "head_repository": repo}
        jobs = [{"id": 10, "name": "archive", "run_id": 123, "run_attempt": 1, "head_sha": gate.LATER_PROVIDER_MAIN,
                 "status": "completed", "conclusion": "success", "steps": [
                     {"name": name, "status": "completed", "conclusion": "success"} for name in
                     ("Require the protected evidence archive switch", "Plan or conditionally seal the exact original job log")]},
                {"id": 11, "name": "readback", "run_id": 123, "run_attempt": 1, "head_sha": gate.LATER_PROVIDER_MAIN,
                 "status": "completed", "conclusion": "success", "steps": [
                     {"name": name, "status": "completed", "conclusion": "success"} for name in
                     ("Require the protected evidence archive switch", "Independently compare the retained original log")]}]
        sealed = {"status": "sealed-awaiting-independent-readback", "planSha256": record["planSha256"],
                  "logSha256": record["sourceLogSha256"], "completionSha256": record["completionSha256"]}
        readback = {**sealed, "status": "independently-read-back", "sourceRunId": source, "archiveRunId": "123",
                    "archiveJobId": "10", "readbackJobId": "11"}
        commit = gate.canonical({"sha": gate.LATER_PROVIDER_MAIN, "treeSha": gate.LEGACY_ARCHIVE_TREE})
        data = [commit, gate.canonical(jobs), gate.canonical(sealed), gate.canonical(readback)]
        with patch.object(gate, "reviewed_source"), patch.object(gate, "cached_private_bytes", side_effect=data):
            gate.verify_legacy_archive(row, record, {"RUNNER_TEMP": "/synthetic"}, "x")
        bad = {**readback, "completionSha256": "f" * 64}
        with patch.object(gate, "reviewed_source"), \
             patch.object(gate, "cached_private_bytes", side_effect=[commit, gate.canonical(jobs), gate.canonical(sealed), gate.canonical(bad)]), \
             self.assertRaises(ContractError):
            gate.verify_legacy_archive(row, record, {"RUNNER_TEMP": "/synthetic"}, "x")

    def test_later_provider_read_is_fixed_to_observed_jobs_and_candidate(self):
        repo = {"id": gate.github.REPOSITORY_ID}
        row = {"id": int(gate.LATER_PROVIDER_READ_RUN), "path": gate.PROVIDER_READ_WORKFLOW,
               "event": "workflow_dispatch", "head_sha": gate.LATER_PROVIDER_MAIN, "run_attempt": 1,
               "head_branch": "main", "status": "completed", "conclusion": "failure", "repository": repo,
               "head_repository": repo, "display_title": "Reviewed Provider source verification at " + gate.LATER_PROVIDER_MAIN}
        expected = {"Reviewed Provider source verification": "success", "Reviewed Provider simulated source fault": "success",
                    "Trusted Provider R2 attestation": "success", "Trusted Provider live attestation": "failure"}
        jobs = [{"id": index + 1, "name": name, "run_id": int(gate.LATER_PROVIDER_READ_RUN), "run_attempt": 1,
                 "head_sha": gate.LATER_PROVIDER_MAIN, "status": "completed", "conclusion": conclusion}
                for index, (name, conclusion) in enumerate(expected.items())]
        line = json.dumps({"status": "validated", "reviewedHeadSha": gate.LATER_PROVIDER_HEAD, "pr": "290"}).encode()
        raw = b"\n".join([line] * 3)
        with patch.object(gate, "reviewed_source"), patch.object(gate, "cached_private_bytes", side_effect=[gate.canonical(jobs), raw]):
            gate.verify_later_provider_read(row, {"RUNNER_TEMP": "/synthetic"}, "x")
        with self.assertRaises(ContractError):
            gate.verify_later_provider_read({**row, "run_attempt": 2}, {"RUNNER_TEMP": "/synthetic"}, "x")
    def test_pinned_source_cache_rehashes_and_never_overwrites(self):
        body = b"synthetic pinned source"
        source = {"path": "safe.py", "type": "file", "encoding": "base64",
                  "content": base64.b64encode(body).decode()}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate, "read_json", return_value=source) as get:
                gate.reviewed_source("a" * 40, "safe.py", sha256(body).hexdigest(), "synthetic", directory)
                gate.reviewed_source("a" * 40, "safe.py", sha256(body).hexdigest(), "synthetic", directory)
                self.assertEqual(get.call_count, 1)
                cached = next((Path(directory) / "no-export-reviewed-source-cache").iterdir())
                cached.write_bytes(b"corrupted")
                with self.assertRaises(ContractError):
                    gate.reviewed_source("a" * 40, "safe.py", sha256(body).hexdigest(), "synthetic", directory)
                self.assertEqual(get.call_count, 1)
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory) / "no-export-reviewed-source-cache"
            cache.symlink_to(Path(directory))
            with self.assertRaises(ContractError):
                gate.reviewed_source("a" * 40, "safe.py", sha256(body).hexdigest(), "synthetic", directory)

    def test_local_inventory_is_private_immutable_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "no-export-writer-inventory.json"
            gate.save_inventory(directory, b'[{"id":1}]')
            self.assertEqual(path.stat().st_mode & 0o077, 0)
            gate.save_inventory(directory, b'[{"id":1}]')
            with self.assertRaises(ContractError):
                gate.save_inventory(directory, b'[{"id":2}]')
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "no-export-writer-inventory.json"
            path.symlink_to(Path(directory) / "other")
            with self.assertRaises(OSError):
                gate.save_inventory(directory, b'[]')
        with tempfile.TemporaryDirectory() as directory:
            os.mkfifo(Path(directory) / "no-export-writer-inventory.json", 0o600)
            with self.assertRaises(ContractError):
                gate.save_inventory(directory, b'[]')

    def test_writer_inventory_rejects_incomplete_pages_and_duplicates(self):
        def row(number):
            return {"id": number, "path": ".github/workflows/python-ci.yml", "event": "pull_request",
                    "head_sha": "a" * 40, "created_at": "2026-11-17T20:00:00Z", "run_attempt": 1, "status": "completed"}
        env = ("2026-11-17T19:00:00Z", "2026-11-17T21:00:00Z", "synthetic")
        with patch.object(gate, "read_json", side_effect=[{"total_count": 51, "workflow_runs": [row(i) for i in range(1, 51)]},
                                                                  {"total_count": 51, "workflow_runs": [row(1)]}]):
            with self.assertRaises(ContractError):
                gate.workflow_runs(*env)

    def test_bounded_50_item_inventory_is_complete_and_rejects_overflow(self):
        def row(number):
            return {"id": number, "path": ".github/workflows/python-ci.yml", "event": "pull_request",
                    "head_sha": "a" * 40, "created_at": "2026-11-17T20:00:00Z", "run_attempt": 1, "status": "completed"}
        env = ("2026-11-17T19:00:00Z", "2026-11-17T21:00:00Z", "synthetic")
        responses = [{"total_count": 127, "workflow_runs": [row(i) for i in range(first, min(first + 50, 128))]}
                     for first in (1, 51, 101)]
        with patch.object(gate, "read_json", side_effect=responses) as get:
            self.assertEqual(len(gate.workflow_runs(*env, maximum=150)), 127)
            self.assertEqual(get.call_count, 3)
            self.assertTrue(all("per_page=50" in call.args[0] for call in get.call_args_list))
        full = [{"total_count": 400, "workflow_runs": [row(i) for i in range(first, first + 50)]}
                for first in range(1, 401, 50)]
        with patch.object(gate, "read_json", side_effect=full) as get:
            self.assertEqual(len(gate.workflow_runs(*env)), 400)
            self.assertEqual(get.call_count, 8)
        with patch.object(gate, "read_json", side_effect=full) as get:
            live = gate.workflow_runs(*env, maximum=400, live_metadata=True)
            self.assertEqual(len(live), 400)
            self.assertEqual(get.call_count, 8)
            self.assertTrue(all(row["status"] == "completed" for row in live))
        with patch.object(gate, "read_json", return_value={"total_count": 401, "workflow_runs": [row(1)]}):
            with self.assertRaises(ContractError):
                gate.workflow_runs(*env)
        with patch.object(gate, "read_json", return_value={"total_count": 2, "workflow_runs": [row(1)]}):
            with self.assertRaises(ContractError):
                gate.workflow_runs(*env)

    def test_live_window_rejects_unclassified_writers_and_unknown_release(self):
        env = {"GITHUB_RUN_ID": "99", "GITHUB_SHA": "a" * 40}
        gate.live_writer_boundary([{"id": 1, "path": ".github/workflows/python-ci.yml", "event": "pull_request", "head_sha": "b" * 40}], env, "synthetic", "b" * 40)
        with self.assertRaises(ContractError):
            gate.live_writer_boundary([{"id": 2, "path": ".github/workflows/worker-production-recovery.yml",
                                        "event": "workflow_dispatch", "head_sha": "a" * 40}], env, "synthetic", "b" * 40)
        prior = {"id": 3, "path": gate.WORKFLOW, "event": "workflow_dispatch", "head_sha": "a" * 40}
        run = {"id": 3, "run_attempt": 1, "status": "completed", "conclusion": "failure",
               "display_title": "No-export release at " + "a" * 40 + " candidate " + "b" * 40}
        with patch.object(gate, "read_json", return_value=run), self.assertRaises(ContractError):
            gate.live_writer_boundary([prior], env, "synthetic", "b" * 40)

    def test_only_exact_failed_precheckout_plan_is_classified_without_writes(self):
        item = {"id": int(gate.FAILED_PLAN_RUN), "path": gate.WORKFLOW, "event": "workflow_dispatch",
                "head_sha": gate.FAILED_PLAN_MAIN, "run_attempt": 1}
        repo = {"id": gate.github.REPOSITORY_ID}
        run = {**item, "head_branch": "main", "status": "completed", "conclusion": "failure",
               "display_title": "No-export plan at " + gate.FAILED_PLAN_MAIN + " candidate " + gate.FAILED_PLAN_HEAD,
               "repository": repo, "head_repository": repo}
        checkout = "Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        states = [(2, checkout, "success"), (3, "Verify no-export identity before candidate checkout", "failure"),
                  (4, checkout, "skipped"), (5, "Verify exact reviewed no-export checkout", "skipped"),
                  (6, "Verify no-export test Bot identity", "skipped"), (7, "Plan or apply the no-export resolution", "skipped")]
        steps = [{"number": n, "name": name, "status": "completed", "conclusion": result} for n, name, result in states]
        steps.append({"number": 1, "name": "Set up job", "status": "completed", "conclusion": "success"})
        base = {"run_id": int(gate.FAILED_PLAN_RUN), "run_attempt": 1, "head_sha": gate.FAILED_PLAN_MAIN, "status": "completed"}
        jobs = {"total_count": 2, "jobs": [{**base, "id": int(gate.FAILED_PLAN_JOB), "name": "resolution", "conclusion": "failure", "steps": steps},
                                           {**base, "name": "readback", "conclusion": "skipped", "steps": []}]}
        env = {"RUNNER_TEMP": "/synthetic"}
        with patch.object(gate, "read_json", side_effect=[run, run, jobs]), \
             patch.object(gate, "cached_private_bytes"), patch.object(gate, "reviewed_source") as sources:
            gate.verify_failed_initial_plan(item, env, "synthetic")
            self.assertEqual(sources.call_count, 2)
        steps[2]["conclusion"] = "success"
        with patch.object(gate, "read_json", side_effect=[run, run, jobs]), patch.object(gate, "reviewed_source"), self.assertRaises(ContractError):
            gate.verify_failed_initial_plan(item, env, "synthetic")
        steps[2]["conclusion"] = "skipped"
        with self.assertRaises(ContractError):
            gate.verify_failed_initial_plan({**item, "run_attempt": 2}, env, "synthetic")

    def test_fixed_later_audit_failure_preserves_original_attempt_log_and_sources(self):
        pin = gate.PRECHECKOUT_FAILURES[gate.FAILED_AUDIT_RUN]
        repo = {"id": gate.github.REPOSITORY_ID}
        item = {"id": int(gate.FAILED_AUDIT_RUN), "path": gate.WORKFLOW, "event": "workflow_dispatch",
                "head_sha": pin["main"], "run_attempt": 1}
        run = {**item, "head_branch": "main", "status": "completed", "conclusion": "failure",
               "display_title": "No-export audit-writers at " + pin["main"] + " candidate " + pin["head"],
               "repository": repo, "head_repository": repo}
        checkout = "Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
        states = [(1, "Set up job", "success"), (2, checkout, "success"),
                  (3, "Verify no-export identity before candidate checkout", "failure"), (4, checkout, "skipped"),
                  (5, "Verify exact reviewed no-export checkout", "skipped"),
                  (6, "Verify no-export test Bot identity", "skipped"), (7, "Plan or apply the no-export resolution", "skipped")]
        steps = [{"number": number, "name": name, "status": "completed", "conclusion": outcome} for number, name, outcome in states]
        base = {"run_id": item["id"], "run_attempt": 1, "head_sha": pin["main"], "status": "completed"}
        jobs = {"total_count": 2, "jobs": [{**base, "id": int(pin["job"]), "name": "resolution", "conclusion": "failure", "steps": steps},
                                           {**base, "name": "readback", "conclusion": "skipped", "steps": []}]}
        with patch.object(gate, "read_json", side_effect=[run, run, jobs]), \
             patch.object(gate, "reviewed_source") as source, patch.object(gate, "cached_private_bytes") as log:
            gate.verify_failed_initial_plan(item, {"RUNNER_TEMP": "/synthetic"}, "x")
            self.assertEqual(source.call_count, 2)
            self.assertEqual(log.call_args.args[2], pin["logSha256"])
        steps[-1]["conclusion"] = "success"
        with patch.object(gate, "read_json", side_effect=[run, run, jobs]), \
             patch.object(gate, "reviewed_source") as source, self.assertRaises(ContractError):
            gate.verify_failed_initial_plan(item, {"RUNNER_TEMP": "/synthetic"}, "x")
        source.assert_not_called()

    def test_only_pinned_finished_provider_read_is_allowed_from_previous_main(self):
        item = {"id": int(gate.PROVIDER_READ_RUN), "path": gate.PROVIDER_READ_WORKFLOW,
                "event": "workflow_dispatch", "head_sha": gate.FAILED_PLAN_MAIN, "run_attempt": 1}
        repo = {"id": gate.github.REPOSITORY_ID}
        run = {**item, "head_branch": "main", "status": "completed", "conclusion": "failure",
               "display_title": "Reviewed Provider source verification at " + gate.FAILED_PLAN_MAIN,
               "repository": repo, "head_repository": repo}
        expected = {"Reviewed Provider source verification": "success", "Trusted Provider R2 attestation": "success",
                    "Reviewed Provider simulated source fault": "skipped", "Trusted Provider live attestation": "failure"}
        jobs = [{"name": name, "run_id": int(gate.PROVIDER_READ_RUN), "run_attempt": 1,
                 "head_sha": gate.FAILED_PLAN_MAIN, "status": "completed", "conclusion": conclusion}
                for name, conclusion in expected.items()]
        result = {"total_count": 4, "jobs": jobs}
        with patch.object(gate, "read_json", side_effect=[run, result]), patch.object(gate, "reviewed_source") as source:
            gate.verify_fixed_provider_read(item, {"RUNNER_TEMP": "/synthetic"}, "synthetic")
            source.assert_called_once()
        jobs[0]["status"] = "in_progress"
        with patch.object(gate, "read_json", side_effect=[run, result]), patch.object(gate, "reviewed_source"), self.assertRaises(ContractError):
            gate.verify_fixed_provider_read(item, {"RUNNER_TEMP": "/synthetic"}, "synthetic")
        with self.assertRaises(ContractError):
            gate.verify_fixed_provider_read({**item, "run_attempt": 2}, {"RUNNER_TEMP": "/synthetic"}, "synthetic")

    def test_fresh_readback_never_receives_writer_credentials(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-backup-no-export-resolution.yml").read_text()
        readback = workflow.split("\n  readback:\n", 1)[1]
        self.assertIn("NO_EXPORT_ACTION:", readback)
        self.assertIn("SUBS_BOT_CF_REHEARSAL_DATA_READ_TOKEN", readback)
        self.assertNotIn("SUBS_BOT_CF_REHEARSAL_DATA_TOKEN", readback)
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", readback)

    def test_only_pinned_interrupted_runs_are_available_to_readers(self):
        env = {"GITHUB_RUN_ID": "99", "GITHUB_SHA": "a" * 40, "NO_EXPORT_ACTION": "verify-seal",
               "NO_EXPORT_SEAL_RUN_ID": "3", "SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID": "3"}
        prior = {"id": 3, "path": gate.WORKFLOW, "event": "workflow_dispatch", "head_sha": "a" * 40}
        run = {"id": 3, "run_attempt": 1, "status": "completed", "conclusion": "failure",
               "display_title": "No-export seal at " + "a" * 40 + " candidate " + "b" * 40}
        with patch.object(gate, "read_json", return_value=run):
            gate.live_writer_boundary([prior], env, "synthetic", "b" * 40)
            with self.assertRaises(ContractError):
                gate.live_writer_boundary([prior], {**env, "NO_EXPORT_SEAL_RUN_ID": "4"}, "synthetic", "b" * 40)
            with self.assertRaises(ContractError):
                gate.live_writer_boundary([prior], {**env, "NO_EXPORT_ACTION": "seal"}, "synthetic", "b" * 40)
        release = {**run, "display_title": "No-export release at " + "a" * 40 + " candidate " + "b" * 40}
        env.update({"NO_EXPORT_ACTION": "verify-release", "NO_EXPORT_RELEASE_RUN_ID": "3",
                    "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID": "3"})
        with patch.object(gate, "read_json", return_value=release):
            gate.live_writer_boundary([prior], env, "synthetic", "b" * 40)
            with self.assertRaises(ContractError):
                gate.live_writer_boundary([prior], {**env, "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID": "4"}, "synthetic", "b" * 40)

    def test_interrupted_run_needs_completed_gate_and_original_execution(self):
        main, candidate = "a" * 40, "b" * 40
        run = {"id": 3, "run_attempt": 1, "status": "completed", "conclusion": "failure", "path": gate.WORKFLOW,
               "head_sha": main, "head_branch": "main", "event": "workflow_dispatch",
               "display_title": "No-export seal at " + main + " candidate " + candidate,
               "repository": {"id": gate.github.REPOSITORY_ID}, "head_repository": {"id": gate.github.REPOSITORY_ID}}
        names = ("Verify no-export identity before candidate checkout", "Verify exact reviewed no-export checkout",
                 "Verify no-export test Bot identity", "Plan or apply the no-export resolution")
        steps = [{"name": name, "status": "completed", "conclusion": "failure" if name == names[-1] else "success"} for name in names]
        job = {"name": "resolution", "run_id": 3, "run_attempt": 1, "head_sha": main,
               "status": "completed", "conclusion": "failure", "steps": steps}
        required = [("resolution", names[-1], False)]
        with patch.object(gate, "read_json", side_effect=[run, run, {"total_count": 1, "jobs": [job]}]):
            gate.reviewed_run("3", "seal", main, candidate, "synthetic", successful=False, jobs_required=required)
        steps[1]["conclusion"] = "failure"
        with patch.object(gate, "read_json", side_effect=[run, run, {"total_count": 1, "jobs": [job]}]), self.assertRaises(ContractError):
            gate.reviewed_run("3", "seal", main, candidate, "synthetic", successful=False, jobs_required=required)

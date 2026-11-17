"""Hosted fail-closed tests for the one fixed no-export evidence gate."""
from pathlib import Path
import base64
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
    def test_pinned_source_cache_rehashes_and_never_overwrites(self):
        body = b"synthetic pinned source"
        source = {"path": "safe.py", "type": "file", "encoding": "base64",
                  "content": base64.b64encode(body).decode()}
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(gate.github, "_get_json", return_value=source) as get:
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
        with patch.object(gate.github, "_get_json", side_effect=[{"total_count": 51, "workflow_runs": [row(i) for i in range(1, 51)]},
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
        with patch.object(gate.github, "_get_json", side_effect=responses) as get:
            self.assertEqual(len(gate.workflow_runs(*env, maximum=150)), 127)
            self.assertEqual(get.call_count, 3)
            self.assertTrue(all("per_page=50" in call.args[0] for call in get.call_args_list))
        full = [{"total_count": 400, "workflow_runs": [row(i) for i in range(first, first + 50)]}
                for first in range(1, 401, 50)]
        with patch.object(gate.github, "_get_json", side_effect=full) as get:
            self.assertEqual(len(gate.workflow_runs(*env)), 400)
            self.assertEqual(get.call_count, 8)
        with patch.object(gate.github, "_get_json", return_value={"total_count": 401, "workflow_runs": [row(1)]}):
            with self.assertRaises(ContractError):
                gate.workflow_runs(*env)
        with patch.object(gate.github, "_get_json", return_value={"total_count": 2, "workflow_runs": [row(1)]}):
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
        with patch.object(gate.github, "_get_json", return_value=run), self.assertRaises(ContractError):
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
        with patch.object(gate.github, "_get_json", side_effect=[run, jobs]), patch.object(gate, "reviewed_source") as sources:
            gate.verify_failed_initial_plan(item, env, "synthetic")
            self.assertEqual(sources.call_count, 2)
        steps[2]["conclusion"] = "success"
        with patch.object(gate.github, "_get_json", side_effect=[run, jobs]), patch.object(gate, "reviewed_source"), self.assertRaises(ContractError):
            gate.verify_failed_initial_plan(item, env, "synthetic")
        steps[2]["conclusion"] = "skipped"
        with self.assertRaises(ContractError):
            gate.verify_failed_initial_plan({**item, "run_attempt": 2}, env, "synthetic")

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
        with patch.object(gate.github, "_get_json", return_value=run):
            gate.live_writer_boundary([prior], env, "synthetic", "b" * 40)
            with self.assertRaises(ContractError):
                gate.live_writer_boundary([prior], {**env, "NO_EXPORT_SEAL_RUN_ID": "4"}, "synthetic", "b" * 40)
            with self.assertRaises(ContractError):
                gate.live_writer_boundary([prior], {**env, "NO_EXPORT_ACTION": "seal"}, "synthetic", "b" * 40)
        release = {**run, "display_title": "No-export release at " + "a" * 40 + " candidate " + "b" * 40}
        env.update({"NO_EXPORT_ACTION": "verify-release", "NO_EXPORT_RELEASE_RUN_ID": "3",
                    "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID": "3"})
        with patch.object(gate.github, "_get_json", return_value=release):
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
        with patch.object(gate.github, "_get_json", side_effect=[run, run, {"total_count": 1, "jobs": [job]}]):
            gate.reviewed_run("3", "seal", main, candidate, "synthetic", successful=False, jobs_required=required)
        steps[1]["conclusion"] = "failure"
        with patch.object(gate.github, "_get_json", side_effect=[run, run, {"total_count": 1, "jobs": [job]}]), self.assertRaises(ContractError):
            gate.reviewed_run("3", "seal", main, candidate, "synthetic", successful=False, jobs_required=required)

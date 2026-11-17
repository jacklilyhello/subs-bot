"""Hosted-only checks for independent Provider source readback."""
from contextlib import redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_provider_head_attestation as attest
from test_production_provider import config
from test_trusted_provider_head_gate import spec


class AttestationTests(unittest.TestCase):
    def test_source_job_must_pass_trusted_gate_and_verification(self):
        rows = [{"name": name, "run_id": 101, "run_attempt": 1, "head_sha": "a" * 40,
                 "status": "completed", "conclusion": "success", "steps": [
                     {"name": "Verify reviewed Provider head using trusted main", "status": "completed", "conclusion": "success"},
                     {"name": final_step, "status": "completed", "conclusion": "success"}]}
                for name, final_step in attest.JOB_STEPS.items()]
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "a" * 40, "GH_TOKEN": "synthetic",
               "PROVIDER_HEAD_PHASE": "attest-r2", "PROVIDER_HEAD_VALIDATION_JSON": json.dumps(spec())}
        with patch.dict(os.environ, env, clear=True), patch.object(attest.gate, "validate", return_value={}), \
                patch.object(attest.provider.github, "_get_json", return_value={"total_count": len(rows), "jobs": rows}):
            attest.checks()
            rows[0]["steps"][0]["conclusion"] = "failure"
            with self.assertRaises(attest.provider.ProviderError):
                attest.checks()

    def test_r2_readback_refuses_changed_target_before_source_access(self):
        target = config(active=True)
        env = {"PROVIDER_HEAD_TARGET_SHA256": "0" * 64, "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(target)}
        with patch.dict(os.environ, env, clear=True), patch.object(attest, "checks", return_value=({}, spec())), \
                patch.object(attest, "source_ref") as source, self.assertRaises(attest.provider.ProviderError):
            attest.attest_r2()
        source.assert_not_called()

    def test_r2_readback_reverifies_all_originals(self):
        target = config(active=True)
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "output"
            output.write_text("")
            env = {"PROVIDER_HEAD_TARGET_SHA256": attest.provider.digest(target),
                   "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(target), "RUNNER_TEMP": temporary,
                   "GITHUB_OUTPUT": str(output)}
            with patch.dict(os.environ, env, clear=True), patch.object(attest, "checks", return_value=({}, spec())), \
                    patch.object(attest, "source_ref", return_value=target["build"]["archiveSha256"]) as source, \
                    redirect_stdout(StringIO()):
                attest.attest_r2()
            self.assertIn("target_sha256=", output.read_text())
        source.assert_called_once()

    def test_archive_attempt_must_match_recorded_controller_and_workflow(self):
        revision = "a" * 40
        ref = {"runId": "101", "runAttempt": "1", "kind": "complete"}
        run = {"id": 101, "run_attempt": 1, "path": attest.provider.REHEARSAL_WORKFLOW_PATH,
               "event": "workflow_dispatch", "head_branch": "main", "status": "completed", "conclusion": "success",
               "head_sha": revision, "repository": {"id": attest.provider.github.REPOSITORY_ID},
               "head_repository": {"id": attest.provider.github.REPOSITORY_ID}}
        with patch.dict(os.environ, {"GITHUB_SHA": revision, "GH_TOKEN": "synthetic"}, clear=True), \
                patch.object(attest.provider.github, "_get_json", return_value=run):
            attest.archive_run(ref, {"controllerRevision": revision})
            for change in ({"head_sha": "b" * 40}, {"conclusion": "failure"}, {"path": "other.yml"}):
                with patch.dict(run, change), self.assertRaises(attest.provider.ProviderError):
                    attest.archive_run(ref, {"controllerRevision": revision})
            with patch.dict(run, {"conclusion": "failure"}):
                attest.archive_run({**ref, "kind": "partial"}, {"controllerRevision": revision})

    def test_partial_checkpoint_must_bind_its_own_target_digest(self):
        target = config(active=True)
        mismatch = "0" * 64
        manifest = {"latestCheckpoint": {"record": "checkpoint", "targetSha256": mismatch}}
        checkpoint = {"version": 2, "target": target,
                      "journal": {"source": target["build"], "targetSha256": mismatch,
                                  "runId": "101", "runAttempt": "1"}}
        store = Mock(run_id="101", attempt="1")
        store.read.return_value = json.dumps(manifest).encode()
        ref = {"kind": "partial", "runId": "101", "runAttempt": "1", "manifestSha256": "1" * 64,
               "targetSha256": attest.provider.digest(target)}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {"SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": "{}"}, clear=True), \
                patch.object(attest.archive, "PrivateProofStore", return_value=store), \
                patch.object(attest.archive, "verify_partial"), \
                patch.object(attest.archive, "read_record", return_value=json.dumps(checkpoint).encode()), \
                patch.object(attest, "archive_run") as origin, self.assertRaises(attest.provider.ProviderError):
            attest.source_ref(ref, target, "synthetic", Path(temporary))
        origin.assert_not_called()


if __name__ == "__main__":
    unittest.main()

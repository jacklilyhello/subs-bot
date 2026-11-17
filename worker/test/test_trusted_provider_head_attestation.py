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
    def test_digest_witness_retrieves_and_verifies_complete_oci_closure(self):
        target = config(active=True)
        build = target["build"]
        registry = Mock(repository="fixture", mint=Mock(return_value="pull"))
        registry.manifest.return_value = build["ociManifestSha256"]
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"RUNNER_TEMP": temporary}, clear=True), \
                patch.object(attest.provider.publication, "_write_auth", return_value=Path(temporary) / "auth"), \
                patch.object(attest.provider.publication, "_skopeo_env", return_value={}), \
                patch.object(attest.subprocess, "run") as copy, \
                patch.object(attest.provider.provider, "verify_image", return_value=(build["ociManifestSha256"], build["ociConfigSha256"])) as verify:
            self.assertTrue(attest.verify_registry(target, registry, "digest-only"))
            self.assertEqual(registry.manifest.call_count, 1)
            self.assertIn("--retry-times=0", copy.call_args.args[0])
            verify.assert_called_once()
            verify.return_value = ("0" * 64, build["ociConfigSha256"])
            with self.assertRaises(attest.provider.ProviderError):
                attest.verify_registry(target, registry, "digest-only")
            with self.assertRaises(attest.provider.ProviderError):
                attest.verify_registry(target, registry, "unknown")

    def test_default_tag_witness_still_requires_exact_tag(self):
        target = config(active=True)
        registry = Mock(repository="fixture", mint=Mock(return_value="pull"))
        registry.manifest.return_value = target["build"]["ociManifestSha256"]
        with tempfile.TemporaryDirectory() as temporary, patch.dict(os.environ, {"RUNNER_TEMP": temporary}, clear=True), \
                patch.object(attest.provider.publication, "_write_auth", return_value=Path(temporary) / "auth"), \
                patch.object(attest.provider.publication, "_config", return_value=target["build"]["ociConfigSha256"]):
            self.assertFalse(attest.verify_registry(target, registry, "tag"))
            self.assertEqual(registry.manifest.call_count, 2)
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


    def test_isolated_source_independently_binds_seal_and_readback(self):
        from hashlib import sha256
        revision, target, operation = "b" * 40, config(active=True), "101"
        bucket = {"fixture": "registered-isolation-bucket"}
        plan = {"version": 1, "action": "seal-isolated-provider-source", "operationId": operation,
                "controllerRevision": revision, "targetSha256": attest.provider.digest(target), "build": target["build"],
                "bucketSha256": attest.provider.digest(bucket), "prefixState": "intent-and-manifest-absent",
                "inventorySha256": "1" * 64, "controllersSha256": "2" * 64}
        intent = {"version": 1, "plan": plan, "approvalSha256": attest.provider.digest(plan), "controllerRevision": revision,
                  "runId": "102", "runAttempt": "1", "status": "started-unknown"}
        manifest = {"version": 1, "kind": "subs-bot-isolated-provider-source", "runId": operation, "runAttempt": "1",
                    "controllerRevision": revision, "target": target, "files": {"provider-source-archive.zip": {
                        "bytes": 16, "sha256": target["build"]["archiveSha256"],
                        "chunks": [{"bytes": 16, "sha256": "3" * 64}]}}}
        raw_intent, raw_manifest = attest.provider.canonical(intent), attest.provider.canonical(manifest)
        source = {"intentSha256": sha256(raw_intent).hexdigest(), "manifestSha256": sha256(raw_manifest).hexdigest(),
                  "runId": "102", "controllerRevision": revision}
        report = {"version": 1, "kind": "isolated-provider-source-readback", "status": "source-original-verified",
                  "rehearsalCompletion": "not-evaluated", "operationId": operation, "manifestSha256": source["manifestSha256"],
                  "targetSha256": plan["targetSha256"], "seal": source, "readbackRunId": "103", "readbackRunAttempt": "1",
                  "readbackControllerRevision": revision}
        pin = {**source, "targetSha256": plan["targetSha256"], "readbackRunId": "103", "readbackRunAttempt": "1",
               "readbackControllerRevision": revision, "readbackSha256": attest.provider.digest(report)}
        ref = {"kind": "isolated-source", "runId": operation, "runAttempt": "1", "manifestSha256": pin["manifestSha256"],
               "targetSha256": pin["targetSha256"]}
        repo = {"id": attest.provider.github.REPOSITORY_ID}
        common = {"run_attempt": 1, "head_sha": revision, "head_branch": "main", "event": "workflow_dispatch",
                  "status": "completed", "conclusion": "success", "repository": repo, "head_repository": repo}
        seal = {**common, "id": 102, "path": ".github/workflows/worker-provider-isolated-source.yml",
                "display_title": "Isolated Provider source seal 101"}
        readback = {**common, "id": 103, "path": ".github/workflows/worker-provider-isolated-source-readback.yml",
                    "display_title": f"Read isolated source 101 1 {pin['manifestSha256']} {pin['targetSha256']}"}
        job = {"name": "readback", "run_id": 103, "run_attempt": 1, "head_sha": revision, "status": "completed",
               "conclusion": "success", "steps": [{"name": "Independently verify the pinned original from private R2",
                                                       "status": "completed", "conclusion": "success"}]}
        def get(path, _token):
            if path == "/actions/runs/102/attempts/1":
                return seal
            if path == "/actions/runs/103/attempts/1":
                return readback
            if path == "/actions/runs/103/attempts/1/jobs?per_page=100":
                return {"total_count": 1, "jobs": [job]}
            raise AssertionError("unexpected GitHub metadata")
        store = Mock()
        store.read.side_effect = lambda name: {"source-intent.json": raw_intent, "source-manifest.json": raw_manifest}[name]
        env = {"GITHUB_SHA": revision, "GH_TOKEN": "synthetic", "SUBS_BOT_PROVIDER_ISOLATED_SOURCE_LEDGER_JSON": json.dumps({operation: pin}),
               "SUBS_BOT_PROVIDER_ISOLATED_SOURCE_CONTROLLERS_JSON": json.dumps([revision])}
        with patch.dict(os.environ, env, clear=True), patch.object(attest, "IsolatedSourceStore", return_value=store), \
                patch.object(attest.provider.github, "_get_json", side_effect=get):
            self.assertEqual(attest.independent_isolated_source(ref, bucket, "synthetic")[2], target)
            with patch.dict(job, {"conclusion": "failure"}), self.assertRaises(attest.provider.ProviderError):
                attest.independent_isolated_source(ref, bucket, "synthetic")
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_ISOLATED_SOURCE_CONTROLLERS_JSON": json.dumps(["c" * 40])}), \
                    self.assertRaises(attest.provider.ProviderError):
                attest.independent_isolated_source(ref, bucket, "synthetic")
            identity = {"candidateRevision": "c" * 40, "reviewedPr": "290",
                        "workflowPath": ".github/workflows/worker-provider-reviewed-isolated-source.yml"}
            readback_path = ".github/workflows/worker-provider-reviewed-isolated-source-readback.yml"
            plan.update(identity)
            intent["approvalSha256"] = attest.provider.digest(plan)
            manifest.update(identity)
            raw_intent, raw_manifest = attest.provider.canonical(intent), attest.provider.canonical(manifest)
            source = {"intentSha256": sha256(raw_intent).hexdigest(), "manifestSha256": sha256(raw_manifest).hexdigest(),
                      "runId": "102", "controllerRevision": revision, **identity}
            report.update({"seal": source, "manifestSha256": source["manifestSha256"], "readbackWorkflowPath": readback_path})
            pin = {**source, "targetSha256": plan["targetSha256"], "readbackRunId": "103", "readbackRunAttempt": "1",
                   "readbackControllerRevision": revision, "readbackSha256": attest.provider.digest(report), "readbackWorkflowPath": readback_path}
            ref["manifestSha256"] = pin["manifestSha256"]
            seal["path"] = identity["workflowPath"]
            readback["path"] = readback_path
            readback["display_title"] = f"Read isolated source 101 1 {pin['manifestSha256']} {pin['targetSha256']}"
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_ISOLATED_SOURCE_LEDGER_JSON": json.dumps({operation: pin})}):
                self.assertEqual(attest.independent_isolated_source(ref, bucket, "synthetic")[2], target)
                bad = {**pin, "candidateRevision": "d" * 40}
                with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_ISOLATED_SOURCE_LEDGER_JSON": json.dumps({operation: bad})}), \
                        self.assertRaises(attest.provider.ProviderError):
                    attest.independent_isolated_source(ref, bucket, "synthetic")


if __name__ == "__main__":
    unittest.main()

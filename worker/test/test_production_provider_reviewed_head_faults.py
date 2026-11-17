"""Hosted checks for the isolated, read-only source-fault harness."""
from hashlib import sha256
from copy import deepcopy
import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import archive_production_provider as archive
import production_provider as control
import production_provider_reviewed_head_harness as harness
import provider_isolated_source as isolated
import reviewed_provider_candidate as candidate
from test_production_provider import config


class ReviewedSourceFaultTests(unittest.TestCase):
    def test_source_verified_operation_approvals_are_hashes_without_private_target(self):
        target = config(active=True)
        with tempfile.TemporaryDirectory() as root:
            output_path = Path(root) / "outputs"
            output_path.write_text("")
            capture = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": root, "GITHUB_OUTPUT": str(output_path)}, clear=True), \
                    patch.object(harness.publish, "config", return_value=target), patch.object(harness.durable, "restore"), \
                    patch.object(control, "guard_sources") as guard, patch.object(control, "prepare_durable"), \
                    patch.object(control, "verify_previous_archives"), redirect_stdout(capture):
                harness.verify_archived_chain()
            self.assertEqual(guard.call_count, 2)
            row = json.loads(capture.getvalue())
            self.assertEqual(row["targetSha256"], control.digest(target))
            self.assertEqual(row["approvals"], {operation: control.digest({"operation": operation, "target": target})
                                                for operation in ("prepare-image", "stage", "activate", "smoke")})
            self.assertFalse(row["authorizationGranted"])
            self.assertNotIn(target["service"], capture.getvalue())
            rejected = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": root, "GITHUB_OUTPUT": str(output_path)}, clear=True), \
                    patch.object(harness.publish, "config", return_value=target), patch.object(harness.durable, "restore"), \
                    patch.object(control, "guard_sources", side_effect=control.ProviderError("fixture rejection")), \
                    redirect_stdout(rejected), self.assertRaises(control.ProviderError):
                harness.verify_archived_chain()
            self.assertEqual(rejected.getvalue(), "")

    def test_previous_identity_fault_reaches_the_exact_source_guard(self):
        previous = config(active=True)
        build = deepcopy(previous["build"])
        build["revision"] = "7" * 40
        build["archiveSha256"] = "8" * 64
        target = candidate.candidate(previous, build)
        records = [{"build": row["build"], "target": row} for row in control.releases(target)]
        refs = [{"runId": "101", "runAttempt": "1", "kind": "isolated-source", "manifestSha256": "a" * 64},
                {"runId": "102", "runAttempt": "1", "kind": "complete", "manifestSha256": "b" * 64}]
        env = {"GITHUB_SHA": "9" * 40, "SUBS_BOT_PROVIDER_FAULT_SCENARIO": "identity-previous",
               "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps(refs)}
        def compare(revision, _head, _token):
            return {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                    "base_commit": {"sha": revision}, "merge_base_commit": {"sha": revision}}
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(harness.publish, "config", return_value=target), \
                patch.object(harness.durable, "restore"), patch.object(control, "durable_builds", return_value=records), \
                patch.object(control, "durable_archive"), patch.object(control.github, "require_current_main"), \
                patch.object(control.github, "_github_token", return_value="fixture"), \
                patch.object(control.github, "verify_main_run"), patch.object(control.github, "compare_commits_metadata", side_effect=compare), \
                redirect_stdout(output):
            harness.verify_source_fault()
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertTrue(any(row.get("phase") == "mutated-guard-rejected" and row.get("category") == "identity" for row in rows))
        self.assertEqual(rows[-1]["status"], "simulated-source-fault-rejected")

    def test_all_scenarios_use_fresh_scratch_and_restore_environment(self):
        seen = []
        with tempfile.TemporaryDirectory() as root:
            env = {"RUNNER_TEMP": root, "SUBS_BOT_PROVIDER_FAULT_SCENARIO": "all"}
            def observe():
                seen.append((os.environ["SUBS_BOT_PROVIDER_FAULT_SCENARIO"], os.environ["RUNNER_TEMP"]))
            with patch.dict(os.environ, env, clear=True), patch.object(harness, "verify_source_fault_case", side_effect=observe), \
                    patch.object(harness, "verify_archived_transport_fixture") as transport:
                harness.verify_source_fault()
                transport.assert_called_once()
                self.assertEqual(os.environ["RUNNER_TEMP"], root)
                self.assertEqual(os.environ["SUBS_BOT_PROVIDER_FAULT_SCENARIO"], "all")
            self.assertEqual(len(seen), 8)
            self.assertEqual(len({path for _, path in seen}), 8)

    def test_origin_fixture_uses_only_the_pinned_rehearsal_build_and_protected_source(self):
        target, bucket = config(active=True), {"fixture": "isolated-bucket"}
        ref = {"kind": "isolated-source", "runId": "101", "runAttempt": "1",
               "manifestSha256": "a" * 64, "targetSha256": "b" * 64}
        record = {"fixture": "protected-independent-readback"}
        with tempfile.TemporaryDirectory() as temp:
            env = {"RUNNER_TEMP": temp, "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([ref]),
                   "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": json.dumps(bucket)}
            output = io.StringIO()
            with patch.dict(os.environ, env, clear=True), patch.object(harness.publish, "config", return_value=target), \
                    patch.object(isolated, "ledger", return_value={"101": record}), \
                    patch.object(harness.durable, "prepare_archived_transport") as verify, redirect_stdout(output):
                harness.verify_archived_transport_fixture()
            passed_target, origin, root = verify.call_args.args
            self.assertEqual(passed_target, {"build": target["build"]})
            self.assertEqual(origin["bucketSha256"], control.digest(bucket))
            self.assertEqual(origin["ledgerRecordSha256"], control.digest(record))
            self.assertEqual(root, Path(temp))
            self.assertEqual(json.loads(output.getvalue())["productionTarget"], "not-evaluated")

    def test_real_read_bytes_are_faulted_and_rejected_by_chunk_validation(self):
        raw = b"actual-object-fixture"
        digest = sha256(raw).hexdigest()
        refs = [{"runId": "101", "runAttempt": "1", "kind": "isolated-source", "manifestSha256": "a" * 64},
                {"runId": "102", "runAttempt": "1", "kind": "complete", "manifestSha256": "b" * 64}]
        manifest = {"files": {"fixture": {"bytes": len(raw), "sha256": digest,
                                         "chunks": [{"bytes": len(raw), "sha256": digest}]}}}
        for fault in ("missing", "corrupt"):
            for index, where in enumerate(("current", "previous")):
                with self.subTest(fault=fault, where=where):
                    store = object.__new__(archive.PrivateProofStore)
                    store.run_id, store.attempt = refs[index]["runId"], "1"
                    def restore():
                        archive.read_record(store, manifest, "fixture")
                    env = {"SUBS_BOT_PROVIDER_FAULT_SCENARIO": fault + "-" + where,
                           "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps(refs)}
                    output = io.StringIO()
                    with patch.dict(os.environ, env, clear=True), patch.object(harness.publish, "config", return_value={}), \
                            patch.object(control, "releases", return_value=[{}, {}]), \
                            patch.object(archive.PrivateProofStore, "read", return_value=raw), \
                            patch.object(harness.durable, "restore", side_effect=restore), redirect_stdout(output):
                        harness.verify_source_fault()
                    self.assertEqual(json.loads(output.getvalue())["status"], "simulated-source-fault-rejected")

    def test_unrelated_failure_before_real_read_is_not_a_successful_fault_test(self):
        refs = [{"runId": "101", "runAttempt": "1", "kind": "isolated-source", "manifestSha256": "a" * 64}]
        env = {"SUBS_BOT_PROVIDER_FAULT_SCENARIO": "corrupt-current", "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps(refs)}
        with patch.dict(os.environ, env, clear=True), patch.object(harness.publish, "config", return_value={}), \
                patch.object(control, "releases", return_value=[{}]), \
                patch.object(harness.durable, "restore", side_effect=control.ProviderError("unrelated")), \
                self.assertRaises(control.ProviderError):
            harness.verify_source_fault()

    def test_wrong_previous_manifest_pin_is_checked_against_read_bytes(self):
        raw = b'{"fixture":"manifest"}'
        refs = [{"runId": "101", "runAttempt": "1", "kind": "isolated-source", "manifestSha256": "a" * 64},
                {"runId": "102", "runAttempt": "1", "kind": "complete", "manifestSha256": sha256(raw).hexdigest()}]
        store = object.__new__(archive.PrivateProofStore)
        store.run_id, store.attempt, store.verify = "102", "1", lambda: None
        def restore():
            mutated = json.loads(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"])
            archive.verify_archive(store, mutated[1]["manifestSha256"])
        env = {"SUBS_BOT_PROVIDER_FAULT_SCENARIO": "digest-previous", "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps(refs)}
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(harness.publish, "config", return_value={}), \
                patch.object(control, "releases", return_value=[{}, {}]), \
                patch.object(archive.PrivateProofStore, "read", return_value=raw), \
                patch.object(harness.durable, "restore", side_effect=restore), redirect_stdout(output):
            harness.verify_source_fault()
            self.assertEqual(json.loads(os.environ["SUBS_BOT_PROVIDER_ARCHIVE_REFS"]), refs)
        self.assertEqual(json.loads(output.getvalue())["status"], "simulated-source-fault-rejected")


if __name__ == "__main__":
    unittest.main()

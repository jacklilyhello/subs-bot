"""Hosted checks for the isolated, read-only source-fault harness."""
from hashlib import sha256
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


class ReviewedSourceFaultTests(unittest.TestCase):
    def test_all_scenarios_use_fresh_scratch_and_restore_environment(self):
        seen = []
        with tempfile.TemporaryDirectory() as root:
            env = {"RUNNER_TEMP": root, "SUBS_BOT_PROVIDER_FAULT_SCENARIO": "all"}
            def observe():
                seen.append((os.environ["SUBS_BOT_PROVIDER_FAULT_SCENARIO"], os.environ["RUNNER_TEMP"]))
            with patch.dict(os.environ, env, clear=True), patch.object(harness, "verify_source_fault_case", side_effect=observe):
                harness.verify_source_fault()
                self.assertEqual(os.environ["RUNNER_TEMP"], root)
                self.assertEqual(os.environ["SUBS_BOT_PROVIDER_FAULT_SCENARIO"], "all")
            self.assertEqual(len(seen), 8)
            self.assertEqual(len({path for _, path in seen}), 8)

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

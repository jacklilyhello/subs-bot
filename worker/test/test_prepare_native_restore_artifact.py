"""Hosted-only source provenance tests; no service or real credential is used."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_native_restore_artifact as selector
import prepare_isolation_artifact as artifact
import native_restore_rehearsal as native
import evidence_archive as evidence
from test_evidence_archive import LaterCandidateFixture, MemoryStore, manifest


CONTROL = "b" * 40


class NativeSourceTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="native-source-test-")
        self.addCleanup(self.directory.cleanup)
        self.env = {"GITHUB_WORKFLOW_REF": selector.WORKFLOW, "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_REF": artifact.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_REPOSITORY": artifact.REPOSITORY, "GITHUB_REPOSITORY_ID": str(artifact.REPOSITORY_ID),
            "GITHUB_SHA": CONTROL, "GH_TOKEN": "synthetic-read-token", "RUNNER_TEMP": self.directory.name,
            "SUBS_BOT_CI_RUN_ID": "1234", "SUBS_BOT_CI_RUN_ATTEMPT": "2"}

    def archive_fixture(self):
        fixture = LaterCandidateFixture()
        record = fixture.collect()
        value, blobs = manifest()
        value["additionalCandidates"] = [record]
        value["entries"].extend(fixture.entries)
        blobs.update(fixture.blobs)
        store = MemoryStore()
        store.objects = {"blobs/" + key: body for key, body in blobs.items()}
        raw = evidence.canonical(value)
        store.objects["manifest.json"] = raw
        self.env.update(NATIVE_SOURCE_ARCHIVE_RUN_ID="100", NATIVE_SOURCE_ARCHIVE_RUN_ATTEMPT="1",
            NATIVE_SOURCE_ARCHIVE_MANIFEST_SHA256=evidence.digest(raw),
            SUBS_BOT_CF_ISOLATION_TARGET_JSON=json.dumps({"synthetic": True}),
            SUBS_BOT_CF_BOOTSTRAP_TOKEN="synthetic-data-token")
        return fixture, store

    def assert_control_only(self, guard):
        self.assertGreaterEqual(guard.call_count, 2)
        self.assertTrue(all(call.args == (CONTROL,) for call in guard.call_args_list))

    def test_historical_main_ci_is_exact_while_control_stays_current_main(self):
        fixture = LaterCandidateFixture()
        with patch.dict(os.environ, self.env, clear=True), patch.object(selector, "checkout_revision", return_value=CONTROL), \
                patch.object(artifact, "require_current_main") as guard, \
                patch.object(artifact, "_get_json", side_effect=fixture.get_json), \
                patch.object(artifact, "_download", side_effect=fixture.download):
            result = selector.prepare()
        self.assertEqual(result["controlRevision"], CONTROL)
        self.assertEqual(result["sourceRevision"], fixture.revision)
        self.assertNotEqual(result["sourceRevision"], CONTROL)
        self.assertEqual(result["sourceCIProof"], fixture.proof)
        self.assertEqual(result["sourceBackend"], "github-actions")
        self.assertEqual(fixture.downloads, ["2345"])
        self.assertEqual((Path(self.directory.name) / artifact.VERIFIED_DIRECTORY / "index.js").is_file(), True)
        self.assert_control_only(guard)

    def test_private_archive_source_uses_no_source_github_or_write_request(self):
        fixture, store = self.archive_fixture()
        with patch.dict(os.environ, self.env, clear=True), patch.object(selector, "checkout_revision", return_value=CONTROL), \
                patch.object(artifact, "require_current_main") as guard, \
                patch.object(evidence, "PrivateStore", return_value=store), \
                patch.object(artifact, "_get_json", side_effect=AssertionError("No source GitHub read")), \
                patch.object(artifact, "_download", side_effect=AssertionError("No source GitHub artifact download")):
            result = selector.prepare()
        self.assertEqual(result["sourceCIProof"], fixture.proof)
        self.assertEqual(result["sourceRevision"], fixture.revision)
        self.assertEqual(result["sourceBackend"], "private-release-evidence")
        self.assertEqual(store.writes, [])
        self.assert_control_only(guard)

    def test_private_digest_source_attempt_and_blob_mismatch_fail_without_fallback(self):
        for case in ("digest", "attempt", "blob", "privacy"):
            fixture, store = self.archive_fixture()
            if case == "digest": self.env["NATIVE_SOURCE_ARCHIVE_MANIFEST_SHA256"] = "f" * 64
            if case == "attempt": self.env["SUBS_BOT_CI_RUN_ATTEMPT"] = "3"
            if case == "blob": store.objects["blobs/" + fixture.proof["archiveSha256"]] = b"corrupt"
            if case == "privacy": store.private = False
            with self.subTest(case=case), patch.dict(os.environ, self.env, clear=True), \
                    patch.object(selector, "checkout_revision", return_value=CONTROL), \
                    patch.object(artifact, "require_current_main"), patch.object(evidence, "PrivateStore", return_value=store), \
                    patch.object(artifact, "_get_json", side_effect=AssertionError("No source fallback")), \
                    patch.object(artifact, "_download", side_effect=AssertionError("No source fallback")), \
                    self.assertRaises((artifact.ArtifactError, evidence.ArchiveError)):
                selector.prepare()
            self.assertEqual(store.writes, [])

    def test_archive_inputs_must_be_complete_before_private_access(self):
        for changes in ({"NATIVE_SOURCE_ARCHIVE_RUN_ID": "100"},
                        {"NATIVE_SOURCE_ARCHIVE_MANIFEST_SHA256": "a" * 64},
                        {"NATIVE_SOURCE_ARCHIVE_RUN_ATTEMPT": "2"},
                        {"NATIVE_SOURCE_ARCHIVE_RUN_ID": "../100", "NATIVE_SOURCE_ARCHIVE_MANIFEST_SHA256": "a" * 64}):
            with self.subTest(changes=changes), patch.dict(os.environ, self.env | changes, clear=True), \
                    patch.object(selector, "checkout_revision", return_value=CONTROL), \
                    patch.object(artifact, "require_current_main"), patch.object(evidence, "PrivateStore") as store, \
                    patch.object(artifact, "_get_json", side_effect=AssertionError("No source request")), \
                    self.assertRaises(artifact.ArtifactError):
                selector.prepare()
            store.assert_not_called()

    def test_current_control_checkout_repository_workflow_and_runner_are_mandatory(self):
        for changes in ({"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_REF": "refs/heads/other"},
                        {"GITHUB_REPOSITORY_ID": "7"}, {"GITHUB_WORKFLOW_REF": selector.WORKFLOW.replace("main", "other")},
                        {"GITHUB_SHA": "not-a-revision"}):
            with self.subTest(changes=changes), patch.dict(os.environ, self.env | changes, clear=True), \
                    patch.object(selector, "checkout_revision", return_value=CONTROL), \
                    patch.object(artifact, "require_current_main") as guard, self.assertRaises(artifact.ArtifactError):
                selector.require_control_revision()
            guard.assert_not_called()
        with patch.dict(os.environ, self.env, clear=True), patch.object(selector, "checkout_revision", return_value="c" * 40), \
                self.assertRaises(artifact.ArtifactError):
            selector.require_control_revision()

    def test_fork_expired_or_wrong_source_attempt_cannot_enter_native_restore(self):
        for case in ("fork", "expired", "attempt"):
            fixture = LaterCandidateFixture()
            if case == "fork": fixture.runs["1234"]["head_repository"]["id"] = 7
            if case == "expired": fixture.ci_row["expired"] = True
            if case == "attempt": fixture.runs["1234"]["run_attempt"] = 3
            with self.subTest(case=case), patch.dict(os.environ, self.env, clear=True), \
                    patch.object(selector, "checkout_revision", return_value=CONTROL), \
                    patch.object(artifact, "require_current_main"), patch.object(artifact, "_get_json", side_effect=fixture.get_json), \
                    patch.object(artifact, "_download", side_effect=fixture.download), self.assertRaises(artifact.ArtifactError):
                selector.prepare()

    def test_native_import_and_global_deployment_selector_remain_separate(self):
        self.assertIs(native.native_artifact, selector)
        self.assertIsNot(artifact.prepare, selector.prepare)
        self.assertEqual(artifact.MAIN_REF, "refs/heads/main")

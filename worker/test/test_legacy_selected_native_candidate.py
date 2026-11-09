"""Hosted checks for the protected selected-only native restore verifier."""

from copy import deepcopy
import json
import os
from pathlib import Path
import runpy
import unittest
from unittest.mock import patch

import test_legacy_restore_package as existing
from cloudflare_isolation import LEGACY_SELECTED_HTTP_MARKER, LEGACY_SELECTED_RETIREMENT_MARKER
import legacy_selected_native_candidate as selected
from legacy_selected_oracle_fixture import build_selected_fixture


package = existing.package
native = selected.native


class SelectedNativeCandidateTests(unittest.TestCase):
    def setUp(self):
        base = existing.LegacyRestorePackageTests()
        base.setUp()
        self.addCleanup(base.doCleanups)
        self.root, self.worker = base.root, base.worker
        manifest_file = self.worker / "isolation.json"
        manifest = json.loads(manifest_file.read_bytes())
        module = self.worker / "index.js"
        module.write_bytes(b"/* " + LEGACY_SELECTED_HTTP_MARKER + b" " + LEGACY_SELECTED_RETIREMENT_MARKER + b" */\n"
                           + module.read_bytes())
        manifest["bundleSha256"] = native.file_hash(module)[1]
        manifest_file.write_bytes(existing.body(manifest))
        _, self.worker_pin = package.worker_artifact(self.worker, existing.REVISION, native.file_hash(manifest_file)[1])
        source_root = self.root / "fixture"
        source_root.mkdir(mode=0o700)
        self.fixture = build_selected_fixture(source_root, self.worker, existing.REVISION)
        self.outcomes = {**selected.HTTP_COUNTS, **selected.HTTP_RESULTS, "head-length-omitted": 17}
        self.report_sha = selected.seal_selected_http_report(self.fixture, self.worker_pin, self.outcomes)
        self.report_file = self.fixture.candidate / selected.SELECTED_HTTP_REPORT
        self.scratch = self.root / "protected"
        self.scratch.mkdir(mode=0o700)

    def verify(self):
        return selected.SelectedCandidate(self.fixture.candidate, self.worker, self.worker_pin, self.scratch)

    def test_fixed_candidate_binds_worker_report_and_native_table_readback(self):
        candidate = self.verify()
        pins = candidate.pin()
        self.assertEqual(pins["packageManifestSha256"], self.fixture.candidate_sha256)
        self.assertEqual(pins["workerManifestSha256"], self.worker_pin["manifestSha256"])
        self.assertEqual(pins["selectedHttpOracleSha256"], self.report_sha)
        self.assertEqual(pins["legacySelectedMigrationSha256"], package.LEGACY_SELECTED_MIGRATION_SHA256)
        self.assertEqual(len(candidate.entries), 12)
        readback = candidate.native_evidence(candidate.document["summary"])
        self.assertEqual((readback["verifiedSelectedAggregateCount"], readback["verifiedSelectedMarkerCount"],
                          readback["verifiedSelectedWatchCount"], readback["verifiedRetiredSelectedWatchCount"],
                          readback["verifiedSubscriptionSequenceHighWater"]), (3, 3, 4, 1, 72))
        for table, key in selected.TABLE_PINS.items():
            self.assertEqual(readback[key], candidate.document["summary"]["tableSha256"][table])
            tampered = deepcopy(candidate.document["summary"])
            tampered["tableSha256"][table] = "0" * 64
            with self.subTest(table=table), self.assertRaises(native.RehearsalError):
                candidate.native_evidence(tampered)

    def test_independently_resealed_wrong_sql_is_rejected(self):
        manifest_file = self.fixture.candidate / package.MANIFEST
        manifest = json.loads(manifest_file.read_bytes())
        sql = self.fixture.candidate / package.SQL
        sql.write_bytes(sql.read_bytes() + b"\n")
        size, sha = native.file_hash(sql)
        manifest["sql"].update(bytes=size, sha256=sha, md5=native.file_hash(sql, "md5")[1])
        raw = native.canonical(manifest)
        manifest_file.write_bytes(raw)
        changed_sha = native.digest(raw)
        (self.fixture.candidate / package.MARKER).write_bytes((changed_sha + "\n").encode("ascii"))
        proof = json.loads(self.report_file.read_bytes())
        proof["packageManifestSha256"] = changed_sha
        self.report_file.write_bytes(native.canonical(proof))
        with self.assertRaises(native.RehearsalError):
            self.verify()

    def test_oracle_report_cannot_be_substituted_across_builds(self):
        proof = json.loads(self.report_file.read_bytes())
        proof["worker"]["manifestSha256"] = "0" * 64
        self.report_file.write_bytes(native.canonical(proof))
        with self.assertRaises(native.RehearsalError):
            self.verify()

    def test_report_shape_requires_exact_typed_outcomes(self):
        self.report_file.unlink()
        with self.assertRaises(native.RehearsalError):
            selected.seal_selected_http_report(self.fixture, self.worker_pin, {**self.outcomes, "singbox-semantic": True})
        self.assertFalse(self.report_file.exists())

    def test_publication_requires_exact_main_attempt_and_preserves_existing_output(self):
        runner = runpy.run_path(str(Path(__file__).with_name("legacy-selected-short-oracle.integration.py")))
        bundle = self.root / "subs-bot-worker"
        self.worker.rename(bundle)
        destination = self.root / runner["PUBLISH_DIRECTORY"]
        arguments = ["--output", str(destination)]
        environment = {"RUNNER_TEMP": str(self.root), "GITHUB_REPOSITORY": selected.artifact.REPOSITORY,
                       "GITHUB_REF": selected.artifact.MAIN_REF, "GITHUB_SHA": existing.REVISION,
                       "GITHUB_EVENT_NAME": "push", "GITHUB_RUN_ID": self.worker_pin["runId"],
                       "GITHUB_RUN_ATTEMPT": self.worker_pin["runAttempt"]}
        with patch.dict(os.environ, environment, clear=True):
            self.assertEqual(runner["publication_target"](arguments, bundle, existing.REVISION),
                             (destination, self.worker_pin["manifestSha256"]))
            with patch.dict(os.environ, {"GITHUB_REF": "refs/pull/1/merge"}), self.assertRaises(runner["OracleError"]):
                runner["publication_target"](arguments, bundle, existing.REVISION)
            with patch.dict(os.environ, {"GITHUB_RUN_ATTEMPT": "9876"}), self.assertRaises(runner["OracleError"]):
                runner["publication_target"](arguments, bundle, existing.REVISION)
            self.report_file.unlink()
            runner["publish"](self.fixture, bundle, existing.REVISION, self.worker_pin["manifestSha256"],
                              self.outcomes, destination)
            self.assertEqual(native.file_hash(destination / selected.SELECTED_HTTP_REPORT)[1], self.report_sha)
            self.assertFalse(self.fixture.candidate.exists())
            with self.assertRaises(package.converter.ConversionError):
                runner["publication_target"](arguments, bundle, existing.REVISION)
            self.assertEqual(native.file_hash(destination / selected.SELECTED_HTTP_REPORT)[1], self.report_sha)


if __name__ == "__main__":
    unittest.main()

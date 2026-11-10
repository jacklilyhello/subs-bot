"""Hosted checks for the strictly V11 native candidate verifier."""

from copy import deepcopy
import json
import unittest
from unittest.mock import patch

import legacy_general_auth_native_candidate as standalone
import legacy_short_redirect_oracle as oracle
import legacy_unified_auth_native_candidate as tool
import legacy_unified_share_native_candidate as v10
import test_legacy_unified_share_native_candidate as support


class LegacyUnifiedAuthNativeCandidateTests(unittest.TestCase):
    def setUp(self):
        self.v10 = support.LegacyUnifiedShareNativeCandidateTests()
        self.v10.setUp()
        self.addCleanup(self.v10.doCleanups)
        self.worker = self.v10.worker
        self.worker_pin = self.v10.worker_pin
        source, self.scratch = (self.v10.root / name for name in ("v11-source", "verify-v11"))
        source.mkdir(mode=0o700)
        self.scratch.mkdir(mode=0o700)
        with patch.object(oracle, "seal_oracle", side_effect=self.v10._seal_synthetic_result):
            self.fixture = tool.fixture.build_unified_auth_fixture(source, self.worker, self.worker_pin["revision"], produce_oracle=True)
        self.root = self.fixture.candidate
        self.manifest = self.root / v10.package.MANIFEST
        self.document = json.loads(self.manifest.read_bytes())

    def verify(self, worker_pin=None):
        with patch.object(oracle, "seal_oracle", side_effect=AssertionError("Protected verification ran the HTTP oracle")):
            return tool.UnifiedAuthCandidate(self.root, self.worker, worker_pin or self.worker_pin, self.scratch)

    def reseal_manifest(self):
        raw = tool.native.canonical(self.document)
        self.manifest.write_bytes(raw)
        (self.root / v10.package.MARKER).write_bytes(tool.native.digest(raw).encode("ascii") + b"\n")

    def assert_refused(self, worker_pin=None):
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self.verify(worker_pin)

    def test_exact_source_rebuild_and_dormant_native_evidence(self):
        candidate = self.verify()
        self.assertEqual(candidate.profile, tool.UNIFIED_AUTH_PROFILE)
        paths = tool.unified_auth_candidate_files(self.document)
        self.assertEqual(len(paths), 17)
        self.assertEqual(paths, {path.relative_to(self.root).as_posix() for path in self.root.rglob("*") if path.is_file()})
        self.assertEqual(len(candidate.entries), 10)
        pin = candidate.pin()
        self.assertEqual(pin["packageManifestSha256"], self.fixture.candidate_sha256)
        self.assertEqual(pin["workerManifestSha256"], self.worker_pin["manifestSha256"])
        self.assertEqual(pin["unifiedAuthOracleManifestSha256"], self.document["source"]["oracleManifestSha256"])
        self.assertEqual(pin["generalAuthSourceSha256"], self.fixture.source_sha256)
        self.assertEqual(pin["previewManifestSha256"], self.document["source"]["generalAuthorization"]["previewManifestSha256"])
        summary = self.document["summary"]
        self.assertEqual(summary["rowCount"], len(self.worker_pin["migrations"]) + 38)
        evidence = candidate.native_evidence(summary)
        self.assertEqual((evidence["activationAllowed"], evidence["verifiedGeneralAuthInstallationCount"],
                          evidence["verifiedGeneralAuthPrincipalCount"], evidence["verifiedGeneralAuthGroupCount"],
                          evidence["verifiedGeneralAuthOverrideCount"]), (False, 1, 3, 2, 2))
        self.assertEqual((evidence["verifiedShortNamespaceCount"], evidence["verifiedPrivateShareCount"],
                          evidence["verifiedPrivateShareClaimCount"], evidence["verifiedTempCutover"]), (7, 2, 1, "dormant"))
        for table, key in tool.AUTH_TABLE_PINS.items():
            self.assertEqual(evidence[key], summary["tableSha256"][table])
        changed = deepcopy(summary)
        changed["tableSha256"][tool.auth.PRINCIPALS] = "0" * 64
        with self.assertRaises(tool.native.RehearsalError):
            candidate.native_evidence(changed)

    def test_version_and_attempt_boundaries(self):
        v10_document = json.loads(self.v10.manifest.read_bytes())
        self.assertEqual(len(v10.unified_share_candidate_files(v10_document)), 17)
        for parser, wrong in ((v10.unified_share_candidate_files, self.document), (standalone.candidate_files, self.document),
                              (tool.unified_auth_candidate_files, v10_document), (tool.unified_auth_candidate_files, {"version": 1})):
            with self.subTest(parser=parser.__name__, version=wrong["version"]), self.assertRaises(tool.native.RehearsalError):
                parser(wrong)
        self.assert_refused({**self.worker_pin, "runAttempt": "2"})

    def test_refuses_resealed_authorization_and_extra_archive_member(self):
        original = deepcopy(self.document)
        self.document["source"]["generalAuthorization"]["previewManifestSha256"] = "0" * 64
        self.reseal_manifest()
        self.assert_refused()

        self.document = deepcopy(original)
        self.document["generalAuthorization"]["activationAllowed"] = True
        self.reseal_manifest()
        self.assert_refused()

        self.document = original
        self.reseal_manifest()
        (self.root / "extra.json").write_bytes(b"{}")
        self.assert_refused()

    def test_refuses_resealed_wrong_external_proof(self):
        for name in v10.ORACLE_FILES:
            (self.root / name).write_bytes((self.v10.candidate / name).read_bytes())
        self.document["source"]["oracleManifestSha256"] = tool.native.digest((self.root / v10.ORACLE_MANIFEST).read_bytes())
        self.reseal_manifest()
        self.assert_refused()

    def test_refuses_resealed_changed_private_object(self):
        entry = next(item for item in self.document["objects"] if item["key"].startswith("private-shares/"))
        path = self.root / "objects" / entry["key"]
        replacement = b"x" + path.read_bytes()[1:]
        path.write_bytes(replacement)
        entry["sha256"] = tool.native.digest(replacement)
        self.reseal_manifest()
        self.assert_refused()


if __name__ == "__main__":
    unittest.main()

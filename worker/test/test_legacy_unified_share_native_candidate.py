"""Hosted checks for the V10 protected verifier's fixed synthetic archive."""

from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import test_legacy_unified_candidate as fixture_support
import legacy_short_redirect_oracle as oracle
import legacy_short_namespace_inventory as namespace
from legacy_mixed_short_candidate import MixedShortInput
import legacy_unified_share_native_candidate as tool


class LegacyUnifiedShareNativeCandidateTests(unittest.TestCase):
    def setUp(self):
        support = fixture_support.LegacyUnifiedCandidateTests()
        support.setUp()
        self.addCleanup(support.doCleanups)
        self.support = support
        self.root, self.worker = support.base.root, support.base.worker
        _, self.worker_pin = tool.package.worker_artifact(self.worker, fixture_support.fixtures.REVISION, support.base.worker_sha)
        source = self.root / "fixed-source"
        source.mkdir(mode=0o700)
        with patch.object(oracle, "seal_oracle", side_effect=self._seal_synthetic_result):
            self.fixture = tool.fixture.build_unified_share_fixture(source, self.worker, self.worker_pin["revision"], produce_oracle=True)
        self.candidate = self.fixture.candidate
        self.manifest = self.candidate / tool.package.MANIFEST
        self.scratch = self.root / "verify"
        self.scratch.mkdir(mode=0o700)

    def _seal_synthetic_result(self, config):
        """Stand in for the real HTTP oracle, which runs separately in hosted CI."""
        inventory = json.loads((Path(config["inventory"]) / namespace.MANIFEST).read_bytes())["inventory"]
        self.assertEqual((inventory["rows"], inventory["kinds"]["external"], inventory["blocked"]), (7, 1, 0))
        pins = MixedShortInput(Path(config["backup"]), Path(config["ownerMap"]), config["oldOrigin"], config["legacyBotId"],
                               Path(config["inventory"]), config["inventorySha256"], Path(config["output"]), "",
                               config["pythonVersion"], config["yarlVersion"])
        self.support.seal_external_oracle(pins, config["sourceSha256"], inventory)

    def verify(self, worker_pin=None):
        with patch.object(oracle, "seal_oracle", side_effect=AssertionError("Protected verification ran the HTTP oracle")):
            return tool.UnifiedShareCandidate(self.candidate, self.worker, worker_pin or self.worker_pin, self.scratch)

    def reseal_manifest(self, document):
        raw = tool.native.canonical(document)
        self.manifest.write_bytes(raw)
        (self.candidate / tool.package.MARKER).write_bytes(tool.native.digest(raw).encode("ascii") + b"\n")

    def test_exact_source_rebuild_and_native_evidence(self):
        candidate = self.verify()
        document = json.loads(self.manifest.read_bytes())
        paths = tool.unified_share_candidate_files(document)
        self.assertEqual(len(paths), 17)
        self.assertEqual(paths, {path.relative_to(self.candidate).as_posix() for path in self.candidate.rglob("*") if path.is_file()})
        self.assertEqual(len(candidate.entries), 10)
        self.assertEqual(candidate.pin()["packageManifestSha256"], self.fixture.candidate_sha256)
        self.assertEqual(candidate.pin()["unifiedShareOracleManifestSha256"], document["source"]["oracleManifestSha256"])
        self.assertEqual(candidate.pin()["workerManifestSha256"], self.worker_pin["manifestSha256"])
        summary = document["summary"]
        self.assertEqual(summary["rowCount"], len(self.worker_pin["migrations"]) + 32)
        evidence = candidate.native_evidence(summary)
        self.assertEqual((evidence["verifiedShortNamespaceCount"], evidence["verifiedPrivateShareCount"],
                          evidence["verifiedPrivateShareClaimCount"], evidence["sourceInlineMessageRows"],
                          evidence["verifiedTempCutover"]), (7, 2, 1, 1, "dormant"))
        for table, key in tool.TABLE_PINS.items():
            self.assertEqual(candidate.pin()[key], summary["tableSha256"][table])
            self.assertEqual(evidence[key], summary["tableSha256"][table])
        changed = deepcopy(summary)
        changed["tableSha256"][tool.shares.CLAIMS] = "0" * 64
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            candidate.native_evidence(changed)

    def test_v11_fixture_rebuilds_its_own_source_and_refuses_the_v10_oracle(self):
        source, rebuilt, wrong = (self.root / name for name in ("v11-source", "v11-rebuild", "v11-wrong"))
        for directory in (source, rebuilt, wrong):
            directory.mkdir(mode=0o700)
        revision = self.worker_pin["revision"]
        with patch.object(oracle, "seal_oracle", side_effect=self._seal_synthetic_result) as seal:
            v11 = tool.fixture.build_unified_auth_fixture(source, self.worker, revision, produce_oracle=True)
            seal.assert_called_once()
            self.assertEqual(seal.call_args.args[0]["sourceSha256"], v11.source_sha256)
        self.assertNotEqual(v11.source_sha256, self.fixture.source_sha256)
        document = json.loads((v11.candidate / tool.package.MANIFEST).read_bytes())
        v10 = json.loads(self.manifest.read_bytes())
        self.assertEqual((document["version"], document["scope"], document["objectCount"]), (11, "fresh-unbound-d1-r2", 10))
        self.assertEqual(document["summary"]["rowCount"], len(self.worker_pin["migrations"]) + 38)
        self.assertEqual(document["generalAuthorization"]["counts"], tool.fixture.AUTH_COUNTS)
        self.assertIs(document["generalAuthorization"]["activationAllowed"], False)
        self.assertFalse({item["key"] for item in document["objects"]} & {item["key"] for item in v10["objects"]})
        self.assertNotEqual(document["source"]["oracleManifestSha256"], v10["source"]["oracleManifestSha256"])
        proof_raw = (v11.candidate / tool.ORACLE_MANIFEST).read_bytes()
        proof = json.loads(proof_raw)
        self.assertEqual(document["source"]["oracleManifestSha256"], tool.native.digest(proof_raw))
        self.assertEqual((proof["sourceSha256"], proof["inventorySha256"], proof["worker"]["manifestSha256"], proof["outcomes"]["equivalent"]),
                         (v11.source_sha256, document["source"]["namespaceManifestSha256"], self.worker_pin["manifestSha256"], 1))
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            tool.unified_share_candidate_files(document)

        with patch.object(oracle, "seal_oracle", side_effect=AssertionError("Rebuilding started the HTTP oracle")):
            copy = tool.fixture.build_unified_auth_fixture(rebuilt, self.worker, revision, oracle=v11.candidate / tool.ORACLE_DIRECTORY)
            with self.assertRaisesRegex(tool.package.PackageError, tool.package.ERROR):
                tool.fixture.build_unified_auth_fixture(wrong, self.worker, revision,
                                                        oracle=self.fixture.candidate / tool.ORACLE_DIRECTORY)
        self.assertEqual((copy.source_sha256, copy.candidate_sha256), (v11.source_sha256, v11.candidate_sha256))
        names = {path.relative_to(v11.candidate).as_posix() for path in v11.candidate.rglob("*") if path.is_file()}
        self.assertEqual(len(names), 17)
        self.assertEqual({path.relative_to(copy.candidate).as_posix() for path in copy.candidate.rglob("*") if path.is_file()},
                         names - tool.ORACLE_FILES)
        for name in names - tool.ORACLE_FILES:
            self.assertEqual((v11.candidate / name).read_bytes(), (copy.candidate / name).read_bytes())

    def test_refuses_altered_share_body_even_with_resealed_descriptor(self):
        document = json.loads(self.manifest.read_bytes())
        entry = next(row for row in document["objects"] if row["key"].startswith("private-shares/"))
        path = self.candidate / "objects" / entry["key"]
        original = path.read_bytes()
        replacement = b"x" + original[1:]
        path.write_bytes(replacement)
        entry["sha256"] = tool.native.digest(replacement)
        self.reseal_manifest(document)
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self.verify()

    def test_refuses_resealed_oracle_with_changed_serializer_and_wrong_attempt(self):
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self.verify({**self.worker_pin, "runAttempt": "2"})
        document = json.loads(self.manifest.read_bytes())
        path = self.candidate / tool.ORACLE_MANIFEST
        external = json.loads(path.read_bytes())
        external["legacySerializer"]["yarl"] = "1.20.1"
        raw = tool.package.converter._json(external) + b"\n"
        changed = tool.native.digest(raw)
        path.write_bytes(raw)
        (self.candidate / tool.ORACLE_MARKER).write_bytes(changed.encode("ascii") + b"\n")
        document["source"]["oracleManifestSha256"] = changed
        self.reseal_manifest(document)
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self.verify()

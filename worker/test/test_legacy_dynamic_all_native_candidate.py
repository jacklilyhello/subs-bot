from copy import deepcopy
from hashlib import md5
import json
import unittest

import test_legacy_dynamic_all_candidate as builder_tests
import test_legacy_restore_package as fixtures
import legacy_dynamic_all_candidate as dynamic
import legacy_dynamic_all_native_candidate as tool


class LegacyDynamicAllNativeCandidateTests(unittest.TestCase):
    def setUp(self):
        fixture = builder_tests.LegacyDynamicAllCandidateTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.worker = fixture.root, fixture.worker
        _, self.worker_pin = tool.package.worker_artifact(self.worker, fixtures.REVISION, fixture.worker_sha)
        source = self.root / "fixed"
        source.mkdir(mode=0o700)
        self.fixture = dynamic.build_dynamic_all_fixture(source, self.worker, fixtures.REVISION)
        self.candidate = self.fixture.candidate
        self.manifest = self.candidate / tool.package.MANIFEST
        self.sidecar = self.candidate / tool.DYNAMIC_ALL_HTTP_REPORT
        self.scratch = 0

    def seal(self):
        return tool.seal_dynamic_all_http_report(self.fixture, self.worker_pin, dict(tool.HTTP_OUTCOMES))

    def verify(self):
        self.scratch += 1
        scratch = self.root / f"verify-{self.scratch}"
        scratch.mkdir(mode=0o700)
        return tool.DynamicAllCandidate(self.candidate, self.worker, self.worker_pin, scratch)

    def assert_refused(self):
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            self.verify()

    def test_exact_reconstruction_and_native_evidence(self):
        base = {path.relative_to(self.candidate).as_posix(): path.read_bytes()
                for path in self.candidate.rglob("*") if path.is_file()}
        self.assertEqual(len(base), 12)
        sidecar_sha = self.seal()
        document = json.loads(self.manifest.read_bytes())
        paths = tool.dynamic_all_candidate_files(document)
        self.assertEqual(paths, set(base) | {tool.DYNAMIC_ALL_HTTP_REPORT})
        self.assertTrue(all((self.candidate / path).read_bytes() == body for path, body in base.items()))
        self.assertEqual(self.sidecar.stat().st_mode & 0o777, 0o600)
        candidate = self.verify()
        pins = candidate.pin()
        self.assertEqual(len(candidate.entries), 8)
        self.assertEqual(pins["dynamicAllHttpOracleSha256"], sidecar_sha)
        self.assertEqual(pins["packageManifestSha256"], self.fixture.candidate_sha256)
        self.assertEqual(pins["activeLineageSha256"], document["source"]["activeLineageSha256"])
        for table, key in tool.TABLE_PINS.items():
            self.assertEqual(pins[key], document["summary"]["tableSha256"][table])
        evidence = candidate.native_evidence(document["summary"])
        self.assertEqual((evidence["verifiedDynamicAllCount"], evidence["verifiedDynamicAllMarkerCount"],
                          evidence["verifiedDynamicAllOrderCount"], evidence["verifiedTempNodeCount"],
                          evidence["verifiedTempCutover"], evidence["verifiedSubscriptionSequenceHighWater"]),
                         (3, 3, 0, 4, "dormant", 71))
        changed = deepcopy(document["summary"])
        changed["tableSha256"][dynamic.INSTALLATIONS] = "0" * 64
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            candidate.native_evidence(changed)

    def test_requires_canonical_current_oracle_and_known_outcomes(self):
        self.assert_refused()
        invalid = {**tool.HTTP_OUTCOMES, "historicalRestoreChecks": True}
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            tool.seal_dynamic_all_http_report(self.fixture, self.worker_pin, invalid)
        self.assertFalse(self.sidecar.exists())
        self.seal()
        pristine = self.sidecar.read_bytes()
        for field in ("sourceSha256", "packageManifestSha256", "worker"):
            with self.subTest(field=field):
                report = json.loads(pristine)
                if field == "worker":
                    report["worker"]["runAttempt"] = "2"
                else:
                    report[field] = "0" * 64
                self.sidecar.write_bytes(tool.native.canonical(report))
                self.assert_refused()
        self.sidecar.write_bytes(pristine + b"\n")
        self.assert_refused()

    def test_full_pinned_chain_may_extend_after_0040(self):
        path = self.worker / "isolation.json"
        manifest = json.loads(path.read_bytes())
        position = len(manifest["migrations"]) + 1
        migration = f"{position:04d}_future_v8_test.sql"
        ddl = b"CREATE TABLE future_v8_test (id INTEGER PRIMARY KEY) STRICT;\n"
        fixtures.put(self.worker / migration, ddl)
        manifest["migrations"].append({"name": migration, "sha256": tool.native.digest(ddl)})
        raw = tool.native.canonical(manifest)
        path.write_bytes(raw)
        _, worker_pin = tool.package.worker_artifact(self.worker, fixtures.REVISION, tool.native.digest(raw))
        source, scratch = self.root / "future", self.root / "verify-future"
        source.mkdir(mode=0o700)
        scratch.mkdir(mode=0o700)
        candidate = dynamic.build_dynamic_all_fixture(source, self.worker, fixtures.REVISION)
        tool.seal_dynamic_all_http_report(candidate, worker_pin, dict(tool.HTTP_OUTCOMES))
        verified = tool.DynamicAllCandidate(candidate.candidate, self.worker, worker_pin, scratch)
        summary = verified.document["summary"]
        self.assertEqual((summary["rowCount"], summary["tableCounts"][tool.migrations.LEDGER],
                          summary["tableCounts"]["future_v8_test"]), (position + 20, position, 0))
        self.assertEqual(verified.native_evidence(summary)["verifiedDynamicAllCount"], 3)

    def test_resealed_sql_cannot_activate_the_installation(self):
        self.seal()
        sql = self.candidate / tool.package.SQL
        lines = sql.read_text(encoding="utf-8").splitlines(keepends=True)
        index, = (index for index, line in enumerate(lines) if line.startswith("INSERT INTO legacy_temp_installations "))
        self.assertTrue(lines[index].endswith(",NULL);\n"))
        lines[index] = lines[index].removesuffix("NULL);\n") + "1700000000);\n"
        changed = "".join(lines).encode("utf-8")
        sql.write_bytes(changed)
        document = json.loads(self.manifest.read_bytes())
        document["sql"].update(bytes=len(changed), sha256=tool.native.digest(changed), md5=md5(changed, usedforsecurity=False).hexdigest())
        raw = tool.native.canonical(document)
        package_sha = tool.native.digest(raw)
        self.manifest.write_bytes(raw)
        (self.candidate / tool.package.MARKER).write_bytes((package_sha + "\n").encode("ascii"))
        report = json.loads(self.sidecar.read_bytes())
        report["packageManifestSha256"] = package_sha
        self.sidecar.write_bytes(tool.native.canonical(report))
        self.assert_refused()

    def test_rejects_extra_tree_entries_and_changed_objects(self):
        self.seal()
        extra = self.candidate / "objects" / "unlisted"
        extra.mkdir(mode=0o700)
        self.assert_refused()
        extra.rmdir()
        document = json.loads(self.manifest.read_bytes())
        entry = document["objects"][0]
        path = self.candidate / "objects" / entry["key"]
        original = path.read_bytes()
        path.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        self.assert_refused()
        entry["key"] = "subscriptions/100/" + entry["key"].split("/", 2)[-1]
        with self.assertRaisesRegex(tool.native.RehearsalError, tool.ERROR):
            tool.dynamic_all_candidate_files(document)

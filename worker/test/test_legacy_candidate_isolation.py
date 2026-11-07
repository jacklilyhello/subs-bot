"""Hosted synthetic tests for the protected candidate apply path."""

from io import BytesIO
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from zipfile import ZipFile

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import legacy_candidate_isolation as tool
import test_legacy_restore_package as package_tests
import test_native_restore_rehearsal as native_tests


class CandidateArtifactTests(unittest.TestCase):
    def setUp(self):
        fixture = package_tests.LegacyRestorePackageTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root, self.worker = fixture.root, fixture.worker
        self.output = self.root / "candidate-artifact"
        self.release = {"revision": package_tests.REVISION, "runId": "1234", "runAttempt": "1"}
        self.worker.rename(self.root / tool.artifact.VERIFIED_DIRECTORY)
        self.worker = self.root / tool.artifact.VERIFIED_DIRECTORY

    def build(self):
        return tool.build_synthetic_candidate(self.worker, self.output, self.release["revision"], "1234", "1")

    def archive(self, *, extra=False):
        file = BytesIO()
        with ZipFile(file, "w") as archive:
            for path in sorted(self.output.rglob("*")):
                if path.is_file():
                    archive.writestr(path.relative_to(self.output).as_posix(), path.read_bytes())
            if extra:
                archive.writestr("unreviewed-scratch.sqlite", b"unexpected")
        return file.getvalue()

    def verify(self, archive):
        tool.unpack_candidate(archive, tool.native.digest(archive), self.root / tool.CANDIDATE_DIRECTORY)
        with TemporaryDirectory(dir=self.root) as scratch:
            return tool.verified_candidate(self.root, {"worker": self.release}, Path(scratch))

    def test_sealed_synthetic_archive_and_exact_fixture_contents(self):
        report = self.build()
        candidate = self.verify(self.archive())
        self.assertEqual(candidate.pin()["packageManifestSha256"], report["manifestSha256"])
        self.assertEqual(candidate.document["counts"], tool.COUNTS)
        self.assertEqual(len(candidate.entries), 4)

    def test_correct_archive_digest_does_not_admit_extra_member(self):
        self.build()
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive(extra=True))
        self.assertFalse((self.root / tool.CANDIDATE_DIRECTORY).exists())

    def test_resealed_sql_with_extra_statement_is_rejected(self):
        self.build()
        sql = self.output / tool.package.SQL
        sql.write_bytes(sql.read_bytes() + b"SELECT 1;\n")
        manifest_path = self.output / tool.package.MANIFEST
        document = json.loads(manifest_path.read_bytes())
        document["sql"].update(bytes=sql.stat().st_size, sha256=tool.native.file_hash(sql)[1], md5=tool.native.file_hash(sql, "md5")[1])
        body = tool.native.canonical(document)
        manifest_path.write_bytes(body)
        (self.output / tool.package.MARKER).write_text(tool.native.digest(body) + "\n", encoding="ascii")
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive())


class CandidateBoundaryTests(unittest.TestCase):
    def test_only_candidate_names_use_the_full_cohort(self):
        native = tool.native
        cohort = native_tests.COHORT
        other = cohort[:16] + "e" * 16
        with patch.object(native, "ACCOUNT_SHA256", native.digest(native_tests.ACCOUNT.encode())):
            candidate = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort, profile=tool.PROFILE)
            second = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", other, profile=tool.PROFILE)
            existing = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort)
        self.assertEqual(candidate.names, {"database": f"subs-bot-cf-legacy-db-{cohort}",
                                           "objects": f"subs-bot-cf-legacy-r2-{cohort}"})
        self.assertTrue(set(candidate.names.values()).isdisjoint(second.names.values()))
        self.assertEqual(existing.names, {"backup": f"subs-bot-cf-backup-{cohort[:16]}",
                                          "database": f"subs-bot-cf-restore-{cohort[:16]}",
                                          "objects": f"subs-bot-cf-restore-{cohort[:16]}"})

    def test_d1_observation_requires_the_listed_uuid_in_its_detail(self):
        native = tool.native
        with patch.object(native, "ACCOUNT_SHA256", native.digest(native_tests.ACCOUNT.encode())):
            api = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", native_tests.COHORT, profile=tool.PROFILE)
        listed = {"uuid": native_tests.RESTORE_ID, "name": api.names["database"]}
        detail = {**listed, "created_at": native_tests.STAMP}
        inventory = native_tests.envelope([listed], result_info={"total_pages": 1})
        engine = tool.CandidateRehearsal(api, None, None, None)
        with patch.object(native, "_response", side_effect=[inventory, native_tests.envelope(detail)]) as response:
            self.assertEqual(engine.observe("database"), {"id": listed["uuid"], "name": listed["name"],
                                                          "createdAt": detail["created_at"]})
            self.assertEqual([call.args[1].get_method() for call in response.call_args_list], ["GET", "GET"])
            self.assertTrue(response.call_args.args[1].full_url.endswith("/d1/database/" + listed["uuid"]))
        foreign = {**detail, "uuid": native_tests.SOURCE_ID}
        with patch.object(native, "_response", side_effect=[inventory, native_tests.envelope(foreign)]) as response:
            with self.assertRaisesRegex(native.RehearsalError, "inventory and detail identities disagree"):
                engine.observe("database")
            self.assertEqual([call.args[1].get_method() for call in response.call_args_list], ["GET", "GET"])
        self.assertIsNone(api.restore_id)

    def test_candidate_management_profile_cannot_access_live_data_or_worker_writes(self):
        native = tool.native
        with patch.object(native, "ACCOUNT_SHA256", native.digest(native_tests.ACCOUNT.encode())), patch.object(native, "_response") as response:
            api = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", native_tests.COHORT, profile=tool.PROFILE)
            candidate_path = api.root + "/d1/database/" + native_tests.RESTORE_ID
            self.assertNotIn("backup", api.names)
            self.assertTrue(api.names["database"].startswith("subs-bot-cf-legacy-db-"))
            self.assertTrue(api.names["objects"].startswith("subs-bot-cf-legacy-r2-"))
            self.assertIn("/legacy-candidate/", api.journal_prefix)
            for mutation in (
                lambda: api.json("POST", api.source + "/query", {"sql": "SELECT id FROM subscriptions"}),
                lambda: api.json("POST", api.source + "/export", {"output_format": "polling", "dump_options": {"compatibility": "d1"}}),
                lambda: api.json("POST", candidate_path + "/import", {"action": "init", "etag": "a" * 32}),
                lambda: api.json("PUT", api.root + "/workers/scripts/" + native.WORKER_NAME),
                lambda: api.json("GET", api.root + f"/r2/buckets/{native.WORKER_NAME}/objects?prefix=subscriptions"),
                lambda: api.r2("GET", native.WORKER_NAME, f"subscriptions/1/{native_tests.SNAPSHOT}/0.ndjson"),
                lambda: api.r2("PUT", native.WORKER_NAME, "maintenance/native-restore/unrelated", b"synthetic"),
            ):
                with self.assertRaises(native.RehearsalError):
                    mutation()
            response.assert_not_called()
            api.allow_restore(native_tests.RESTORE_ID)
            response.return_value = native_tests.envelope({"status": "complete"})
            self.assertEqual(api.json("POST", candidate_path + "/import", {"action": "init", "etag": "a" * 32}), {"status": "complete"})

    def test_journal_guard_denial_happens_before_put(self):
        api = native_tests.MemoryAPI()
        guard = Mock(side_effect=tool.native.RehearsalError("fixed guard failure"))
        journal = tool.native.Journal(api, "1/1", guard=guard)
        with self.assertRaisesRegex(tool.native.RehearsalError, "fixed guard failure"):
            journal.save({"version": 1, "cohort": api.cohort})
        self.assertFalse(any(call[0] == "PUT" for call in api.calls))

    def test_different_runtime_pin_stops_before_claim(self):
        journal = Mock()
        journal.load.return_value = {"sourcePin": {"artifact": "unchanged", "live": "previous"}, "scopeSha256": "scope"}
        engine = SimpleNamespace(journal=journal, source=SimpleNamespace(scope_sha256="scope"), resource_kinds=("database", "objects"))
        with self.assertRaises(tool.native.RehearsalError):
            tool.run_action("start-import", engine, {"artifact": "unchanged", "live": "new"})
        journal.claim.assert_not_called()

    def test_object_resume_rejects_key_beyond_durable_intent(self):
        entries = [{"key": "fixture-0"}, {"key": "fixture-1"}]
        journal = Mock(value={"phase": "restoring-objects", "importState": None, "objectConfirmed": 0, "objectIntent": 0})
        api = Mock(root="/fixed", restore_id=native_tests.RESTORE_ID)
        candidate = SimpleNamespace(entries={entry["key"]: entry for entry in entries})
        engine = tool.CandidateRehearsal(api, Mock(), journal, candidate)
        engine.verify_resources = Mock()
        engine.manifest = Mock(return_value=({"objects": entries}, None))
        engine.target_objects = Mock(return_value={"fixture-1"})
        engine.restore_object = Mock()
        with patch.object(tool.migrations, "_matches_schema", return_value=True), self.assertRaises(tool.native.RehearsalError):
            engine.restore_objects()
        engine.restore_object.assert_not_called()
        journal.update.assert_not_called()

    def test_lost_import_init_reconciles_without_repeating_mutation(self):
        native = tool.native
        journal = Mock(value={"phase": "objects-restored", "importState": None})
        journal.update.side_effect = lambda **values: journal.value.update(values)
        api = Mock(root="/fixed", restore_id=native_tests.RESTORE_ID)
        api.json.side_effect = native.RehearsalError(uncertain=True)
        engine = tool.CandidateRehearsal(api, Mock(), journal, Mock())
        engine.verify_resources = Mock()
        engine.manifest = Mock(return_value=({"sqlMd5": "a" * 32}, None))
        engine.verify_object_bytes = Mock()
        engine.verify_restore = Mock(side_effect=native.RehearsalError())
        with patch.object(tool.migrations, "_matches_schema", return_value=True):
            with self.assertRaisesRegex(native.RehearsalError, "do not repeat init"):
                engine.start_import()
            self.assertEqual(journal.value["importState"], {"state": "unknown"})
            with self.assertRaisesRegex(native.RehearsalError, "never re-init"):
                engine.start_import()
        api.json.assert_called_once()
        self.assertEqual(api.json.call_args.args[2]["action"], "init")
        engine.verify_restore.assert_called_once()


if __name__ == "__main__":
    unittest.main()

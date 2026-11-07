"""Hosted synthetic tests for the protected candidate apply path."""

from contextlib import closing
from io import BytesIO
import json
from pathlib import Path
import sqlite3
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

    def build(self, profile=tool.PROFILE):
        return tool.build_synthetic_candidate(self.worker, self.output, self.release["revision"], "1234", "1", profile=profile)

    def test_share_build_keeps_private_files_under_hosted_runner_temp(self):
        runner = self.root / "runner-temp"
        runner.mkdir()
        runner.chmod(0o755)
        self.output = runner / tool.ARTIFACT_PREFIXES[tool.SHARE_PROFILE]

        report = self.build(tool.SHARE_PROFILE)

        self.assertEqual(report["objectCount"], 3)
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o700)
        self.assertEqual(set(runner.iterdir()), {self.output})
        manifest = self.output / tool.package.MANIFEST
        self.assertEqual(manifest.stat().st_mode & 0o777, 0o600)
        original = manifest.read_bytes()
        with self.assertRaises(FileExistsError):
            self.build(tool.SHARE_PROFILE)
        self.assertEqual(manifest.read_bytes(), original)

    def archive(self, *, extra=False):
        file = BytesIO()
        with ZipFile(file, "w") as archive:
            for path in sorted(self.output.rglob("*")):
                if path.is_file():
                    archive.writestr(path.relative_to(self.output).as_posix(), path.read_bytes())
            if extra:
                archive.writestr("unreviewed-scratch.sqlite", b"unexpected")
        return file.getvalue()

    def verify(self, archive, profile=tool.PROFILE):
        tool.unpack_candidate(archive, tool.native.digest(archive), self.root / tool.candidate_directory(profile), profile=profile)
        provenance = {"worker": self.release}
        if profile != tool.PROFILE:
            provenance["profile"] = profile
        with TemporaryDirectory(dir=self.root) as scratch:
            return tool.verified_candidate(self.root, provenance, Path(scratch), profile=profile)

    def reseal(self, document):
        body = tool.native.canonical(document)
        (self.output / tool.package.MANIFEST).write_bytes(body)
        (self.output / tool.package.MARKER).write_text(tool.native.digest(body) + "\n", encoding="ascii")

    def test_sealed_synthetic_archive_and_exact_fixture_contents(self):
        report = self.build()
        candidate = self.verify(self.archive())
        self.assertEqual(candidate.pin()["packageManifestSha256"], report["manifestSha256"])
        self.assertEqual(candidate.document["counts"], tool.COUNTS)
        self.assertEqual(len(candidate.entries), 4)
        self.assertEqual(report["version"], 1)
        self.assertNotIn("pathIdMapping", candidate.document)
        self.assertNotIn("pathRulesSha256", candidate.pin())

    def test_path_profile_replays_exact_v2_artifact_and_rejects_v1_cross_selection(self):
        report = self.build(tool.PATH_PROFILE)
        archive = self.archive()
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(archive)
        self.assertFalse((self.root / tool.CANDIDATE_DIRECTORY).exists())
        candidate = self.verify(archive, tool.PATH_PROFILE)
        self.assertEqual(candidate.document["version"], 2)
        self.assertEqual(candidate.document["pathIdMapping"], {"kind": "identity", "rows": 4, "sourceHighWater": 120,
                                                              "targetSequenceHighWater": 120})
        self.assertEqual(candidate.document["targetSequenceHighWater"], 71)
        self.assertEqual(candidate.document["summary"]["tableCounts"]["sqlite_sequence"], 2)
        self.assertEqual(candidate.pin()["packageManifestSha256"], report["manifestSha256"])
        self.assertEqual(candidate.pin()["pathRulesSha256"], candidate.document["summary"]["tableSha256"]["path_rules"])
        self.assertEqual(candidate.pin()["pathSequenceHighWater"], 120)

    def test_path_profile_rejects_a_valid_sealed_package_with_different_path_text(self):
        row = (*tool.PATH_FIXTURES[0][:3], "other synthetic remark")
        with patch.object(tool, "PATH_FIXTURES", (row, *tool.PATH_FIXTURES[1:])):
            self.build(tool.PATH_PROFILE)
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive(), tool.PATH_PROFILE)

    def test_path_profile_rejects_preflight_from_the_other_profile(self):
        with TemporaryDirectory(dir=self.root) as scratch:
            with self.assertRaises(tool.native.RehearsalError):
                tool.verified_candidate(self.root, {"worker": self.release}, Path(scratch), profile=tool.PATH_PROFILE)

    def test_empty_profile_replays_v3_and_reports_verified_markers(self):
        report = self.build(tool.EMPTY_PROFILE)
        archive = self.archive()
        for old_profile in (tool.PROFILE, tool.PATH_PROFILE):
            with self.subTest(profile=old_profile), self.assertRaises(tool.native.RehearsalError):
                self.verify(archive, old_profile)
        candidate = self.verify(archive, tool.EMPTY_PROFILE)
        self.assertEqual((report["version"], report["counts"], report["objectCount"]), (3, tool.EMPTY_COUNTS, 4))
        self.assertEqual(candidate.document["targetSequenceHighWater"], 72)
        self.assertEqual(candidate.document["pathIdMapping"], tool.path_mapping())
        self.assertEqual(candidate.document["summary"]["tableCounts"][tool.package.EMPTY_EXPORTS], 2)
        pin = candidate.pin()
        self.assertEqual(pin["packageManifestSha256"], report["manifestSha256"])
        self.assertEqual(pin["emptyExportMarkersSha256"], report["emptyExportMarkers"]["tableSha256"])
        self.assertEqual(pin["emptyExportMigrationSha256"], tool.package.EMPTY_EXPORT_MIGRATION_SHA256)
        self.assertEqual({key: pin[key] for key in candidate.document["source"]}, candidate.document["source"])
        self.assertTrue(all(key.startswith(("subscriptions/2/", "subscriptions/71/")) for key in candidate.entries))

        release_pin = {"profile": tool.EMPTY_PROFILE, "worker": self.release,
                       "candidate": {**pin, "artifactId": "123", "archiveSha256": tool.native.digest(archive)}}
        state = {"sourcePin": release_pin, "scopeSha256": "fixture-scope", "importState": {"state": "complete"},
                 "phase": "verified", "resources": {kind: {"pin": {"name": kind}} for kind in ("database", "objects")}}
        journal = Mock(value=state)
        journal.load.return_value = state
        source = Mock(scope_sha256="fixture-scope")
        engine = tool.CandidateRehearsal(Mock(), source, journal, candidate)
        engine.read_restored_summary = Mock(return_value=(candidate.document["summary"], candidate.document))
        result = tool.run_action("verify-restore", engine, release_pin)
        self.assertEqual(result["verifiedEmptyExportMarkerCount"], 2)
        self.assertEqual(result["emptyExportMarkersSha256"], pin["emptyExportMarkersSha256"])
        self.assertEqual(result["verifiedSubscriptionSequenceHighWater"], 72)
        self.assertEqual(result["verifiedPathSequenceHighWater"], 120)
        self.assertEqual(result["generationZeroHttp"], "not-validated")
        journal.claim.assert_not_called()

    def test_empty_profile_rejects_resealed_source_provenance(self):
        self.build(tool.EMPTY_PROFILE)
        document = json.loads((self.output / tool.package.MANIFEST).read_bytes())
        document["source"]["converterManifestSha256"] = "b" * 64
        self.reseal(document)
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive(), tool.EMPTY_PROFILE)

    def test_empty_profile_rejects_resealed_marker_for_other_owner(self):
        self.build(tool.EMPTY_PROFILE)
        sql = self.output / tool.package.SQL
        original = sql.read_text(encoding="utf-8")
        original_marker = next(line for line in original.splitlines()
                               if line.startswith(f"INSERT INTO {tool.package.EMPTY_EXPORTS} ") and "VALUES (72," in line)
        altered_marker = original_marker.replace("'456'", "'789'", 1)
        self.assertNotEqual(altered_marker, original_marker)
        changed = original.replace(original_marker, altered_marker, 1)
        sql.write_bytes(changed.encode("utf-8"))
        document = json.loads((self.output / tool.package.MANIFEST).read_bytes())
        document["sql"].update(bytes=sql.stat().st_size, sha256=tool.native.file_hash(sql)[1],
                               md5=tool.native.file_hash(sql, "md5")[1])
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(changed)
            document["summary"] = tool.package.db_summary(db, document["layout"])
        document["dataSha256"] = document["summary"]["dataSha256"]
        document["emptyExportMarkers"]["tableSha256"] = document["summary"]["tableSha256"][tool.package.EMPTY_EXPORTS]
        self.reseal(document)
        with self.assertRaises(tool.package.PackageError):
            self.verify(self.archive(), tool.EMPTY_PROFILE)

    def test_share_profile_restores_exact_claim_history_and_rechecks_private_metadata(self):
        fixture, native = tool.share_fixture, tool.native
        built = self.build(tool.SHARE_PROFILE)
        archive = self.archive()
        for other in (tool.PROFILE, tool.PATH_PROFILE, tool.EMPTY_PROFILE):
            with self.subTest(profile=other), self.assertRaises(native.RehearsalError):
                self.verify(archive, other)
        candidate = self.verify(archive, tool.SHARE_PROFILE)
        self.assertEqual(built["counts"], {"shares": 3, "claims": 3, "sourceInlineIdRows": 1})
        self.assertEqual(candidate.pin()["packageManifestSha256"], built["manifestSha256"])
        self.assertEqual(candidate.document["summary"]["rowCount"], len(candidate.document["workerArtifact"]["migrations"]) + 7)
        self.assertTrue(all(key.startswith("private-shares/") for key in candidate.entries))
        self.assertTrue(all(entry["metadata"] == fixture.EMPTY_METADATA for entry in candidate.entries.values()))
        self.assertNotIn(b"fixture-retired-inline", candidate.sql.read_bytes())
        self.assertTrue(all(fixture.code(index).encode("ascii") not in candidate.sql.read_bytes() for index in (1, 2, 3)))

        api = native_tests.MemoryAPI()
        api.names.update(database="synthetic-share-db", objects="synthetic-share-r2")
        api.journal_prefix = "maintenance/legacy-share-candidate/synthetic/journal/"
        source = native_tests.fake_source()
        journal = native.Journal(api, "1/1", guard=source.before_write)
        engine = tool.CandidateRehearsal(api, source, journal, candidate)

        def observe(kind):
            if kind not in api.resource:
                return None
            identity = native.resource_identity(kind, api.resource[kind], api.names[kind])
            return {**identity, "storageClass": "Standard"} if kind == "objects" else identity

        engine.observe = Mock(side_effect=observe)
        pin = {"profile": tool.SHARE_PROFILE, "worker": self.release,
               "candidate": {**candidate.pin(), "artifactId": "123", "archiveSha256": native.digest(archive)}}
        for action, resource_count in (("prepare", 0), ("create-restore-db", 1), ("create-restore-bucket", 2)):
            self.assertEqual(tool.run_action(action, engine, pin)["resourceCount"], resource_count)

        with closing(sqlite3.connect(":memory:")) as db:
            api.db = db

            def empty_target(_api, path, objects):
                self.assertEqual(path, api.root + "/d1/database/" + native_tests.RESTORE_ID)
                self.assertEqual(objects, ())
                return db.execute("SELECT count(*) FROM sqlite_schema").fetchone() == (0,)

            def import_result(payload):
                if payload["action"] == "init":
                    return {"filename": "fixture.sql", "upload_url": "https://fixture.invalid/upload"}
                self.assertEqual(payload["action"], "ingest")
                self.assertEqual({key for bucket, key in api.objects if bucket == api.names["objects"]}, set(candidate.entries))
                db.executescript(candidate.sql.read_text(encoding="utf-8"))
                return {"success": True, "status": "complete"}

            api.response = import_result
            with patch.object(tool.migrations, "_matches_schema", side_effect=empty_target), patch.object(native, "signed_transfer") as transfer:
                self.assertEqual(tool.run_action("restore-objects", engine, pin)["phase"], "objects-restored")
                self.assertEqual(tool.run_action("start-import", engine, pin)["phase"], "verified")
                transfer.assert_called_once_with("https://fixture.invalid/upload", upload=candidate.sql, expected_md5=candidate.document["sqlMd5"])
            exact_claims = [(1, None, 1, fixture.LATER_EXPIRY, fixture.OTHER, fixture.CREATED_AT + 15),
                            (2, fixture.TARGET, 2, fixture.LATER_EXPIRY, fixture.TARGET, fixture.CREATED_AT),
                            (3, fixture.TARGET, 1, fixture.EXPIRED_AT, fixture.TARGET, fixture.EXPIRED_AT)]
            for index, target, maximum, expiry, actor, claimed in exact_claims:
                result = db.execute("""SELECT bot_id, sender_id, target_user_id, max_claims, expire_at, actor_id, claimed_at
                    FROM private_shares JOIN private_share_claims ON private_shares.id = private_share_claims.share_id
                    WHERE code_sha256=?""", (native.digest(fixture.code(index).encode("ascii")),)).fetchone()
                self.assertEqual(result, (fixture.BOT_ID, str(fixture.SENDER), None if target is None else str(target),
                                          maximum, expiry, str(actor), claimed))
            self.assertEqual(db.execute("SELECT name,seq FROM sqlite_sequence").fetchall(), [("private_shares", 3)])

            api.calls.clear()
            verified = tool.run_action("verify-restore", engine, pin)
            self.assertEqual((verified["verifiedPrivateShareCount"], verified["verifiedPrivateShareClaimCount"],
                              verified["verifiedShareSequenceHighWater"], verified["r2Metadata"]), (3, 3, 3, "verified"))
            self.assertEqual(verified["shareCompatibility"], "not-validated")
            self.assertEqual(verified["privateSharesSha256"], candidate.pin()["privateSharesSha256"])
            self.assertNotIn(fixture.BOT_ID, json.dumps(verified))
            self.assertFalse(any(call[0] in {"POST", "PUT", "S3 PUT"} for call in api.calls))
            first = api.names["objects"], next(iter(candidate.entries))
            api.metadata[first]["http_metadata"] = {"contentType": "text/plain"}
            with self.assertRaisesRegex(native.RehearsalError, "size or metadata"):
                tool.run_action("verify-restore", engine, pin)

    def test_share_profile_rejects_a_valid_archive_from_altered_synthetic_source(self):
        with patch.object(tool.share_fixture, "SENDER", tool.share_fixture.SENDER + 10):
            self.build(tool.SHARE_PROFILE)
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive(), tool.SHARE_PROFILE)

    def test_typed_profile_rebuilds_the_fixed_source_and_verifies_exact_restore_evidence(self):
        report = self.build(tool.TYPED_PROFILE)
        archive = self.archive()
        for other in (tool.PROFILE, tool.PATH_PROFILE, tool.EMPTY_PROFILE, tool.SHARE_PROFILE):
            with self.subTest(profile=other), self.assertRaises(tool.native.RehearsalError):
                self.verify(archive, other)
        candidate = self.verify(archive, tool.TYPED_PROFILE)
        pin = candidate.pin()
        self.assertEqual(report["version"], 4)
        self.assertEqual(report["manifestSha256"], pin["packageManifestSha256"])
        self.assertEqual(len(candidate.entries), 4)
        self.assertEqual(candidate.document["targetSequenceHighWater"], 72)
        self.assertEqual(pin["pathSequenceHighWater"], 120)
        self.assertEqual(pin["typedShortMigrationSha256"], tool.package.TYPED_SHORT_MIGRATION_SHA256)
        self.assertNotIn("legacyBotId", pin)
        sql = candidate.sql.read_text(encoding="utf-8")
        self.assertNotIn(tool.TYPED_ORIGIN, sql)
        self.assertTrue(all(code not in sql for code, _, _ in tool.TYPED_LINK_FIXTURES))
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(sql)
            self.assertEqual(db.execute(f"SELECT subscription_id,owner_id,format FROM {tool.package.TYPED_SHORTS} "
                                        "ORDER BY subscription_id").fetchall(),
                             [(2, "123", ""), (5, "123", "sing-box"), (71, "456", "v2ray"), (72, "456", "qx")])
            self.assertEqual(db.execute("PRAGMA foreign_key_check").fetchall(), [])

        release = {"profile": tool.TYPED_PROFILE, "worker": self.release,
                   "candidate": {**pin, "artifactId": "123", "archiveSha256": tool.native.digest(archive)}}
        state = {"sourcePin": release, "scopeSha256": "fixture-scope", "importState": {"state": "complete"},
                 "phase": "verified", "resources": {kind: {"pin": {"name": kind}} for kind in ("database", "objects")}}
        journal = Mock(value=state)
        journal.load.return_value = state
        engine = tool.CandidateRehearsal(Mock(), Mock(scope_sha256="fixture-scope"), journal, candidate)
        engine.read_restored_summary = Mock(return_value=(candidate.document["summary"], candidate.document))
        result = tool.run_action("verify-restore", engine, release)
        self.assertEqual(result["verifiedTypedShortLinkCount"], 4)
        self.assertEqual(result["typedShortLinksSha256"], pin["typedShortLinksSha256"])
        self.assertEqual(result["typedShortInventoryManifestSha256"], pin["typedShortInventoryManifestSha256"])
        self.assertEqual(result["verifiedEmptyExportMarkerCount"], 2)
        self.assertEqual(result["verifiedPathRuleCount"], 4)
        self.assertEqual(result["shortLinkCompatibility"], "not-validated")
        self.assertNotIn(tool.TYPED_BOT, json.dumps(result))
        journal.claim.assert_not_called()

    def test_typed_profile_rejects_resealed_inventory_pin(self):
        self.build(tool.TYPED_PROFILE)
        document = json.loads((self.output / tool.package.MANIFEST).read_bytes())
        document["source"]["typedShortInventoryManifestSha256"] = "b" * 64
        self.reseal(document)
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive(), tool.TYPED_PROFILE)

    def test_typed_profile_rejects_resealed_sql_for_other_owner(self):
        self.build(tool.TYPED_PROFILE)
        sql = self.output / tool.package.SQL
        original = sql.read_text(encoding="utf-8")
        row = next(line for line in original.splitlines()
                   if line.startswith(f"INSERT INTO {tool.package.TYPED_SHORTS} ") and "'456'" in line)
        changed = original.replace(row, row.replace("'456'", "'789'", 1), 1)
        sql.write_bytes(changed.encode("utf-8"))
        document = json.loads((self.output / tool.package.MANIFEST).read_bytes())
        document["sql"].update(bytes=sql.stat().st_size, sha256=tool.native.file_hash(sql)[1],
                               md5=tool.native.file_hash(sql, "md5")[1])
        with closing(sqlite3.connect(":memory:")) as db:
            db.executescript(changed)
            document["summary"] = tool.package.db_summary(db, document["layout"])
        document["dataSha256"] = document["summary"]["dataSha256"]
        document["typedShortLinks"]["tableSha256"] = document["summary"]["tableSha256"][tool.package.TYPED_SHORTS]
        self.reseal(document)
        with self.assertRaises(tool.native.RehearsalError):
            self.verify(self.archive(), tool.TYPED_PROFILE)

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
        self.reseal(document)
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
            path = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort, profile=tool.PATH_PROFILE)
            empty = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort, profile=tool.EMPTY_PROFILE)
            share = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort, profile=tool.SHARE_PROFILE)
            typed = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort, profile=tool.TYPED_PROFILE)
            existing = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", cohort)
        self.assertEqual(candidate.names, {"database": f"subs-bot-cf-legacy-db-{cohort}",
                                           "objects": f"subs-bot-cf-legacy-r2-{cohort}"})
        self.assertTrue(set(candidate.names.values()).isdisjoint(second.names.values()))
        self.assertEqual(path.names, {"database": f"subs-bot-cf-legacy-path-db-{cohort}",
                                      "objects": f"subs-bot-cf-legacy-path-r2-{cohort}"})
        self.assertTrue(set(path.names.values()).isdisjoint(candidate.names.values()))
        self.assertNotEqual(path.journal_prefix, candidate.journal_prefix)
        self.assertEqual(empty.names, {"database": f"subs-bot-cf-legacy-empty-db-{cohort}",
                                       "objects": f"subs-bot-cf-legacy-empty-r2-{cohort}"})
        self.assertTrue(set(empty.names.values()).isdisjoint({*path.names.values(), *candidate.names.values()}))
        self.assertEqual(empty.journal_prefix, f"maintenance/legacy-empty-candidate/{cohort}/journal/")
        self.assertEqual(share.names, {"database": f"subs-bot-cf-legacy-share-db-{cohort}",
                                       "objects": f"subs-bot-cf-legacy-share-r2-{cohort}"})
        self.assertTrue(set(share.names.values()).isdisjoint({*empty.names.values(), *path.names.values(), *candidate.names.values()}))
        self.assertEqual(share.journal_prefix, f"maintenance/legacy-share-candidate/{cohort}/journal/")
        self.assertEqual(typed.names, {"database": f"subs-bot-cf-legacy-typed-db-{cohort}",
                                       "objects": f"subs-bot-cf-legacy-typed-r2-{cohort}"})
        self.assertTrue(set(typed.names.values()).isdisjoint(
            value for other_api in (candidate, second, path, empty, share) for value in other_api.names.values()))
        self.assertEqual(typed.journal_prefix, f"maintenance/legacy-typed-candidate/{cohort}/journal/")
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

    def test_path_profile_cannot_read_another_journal_or_list_live_objects(self):
        native = tool.native
        with patch.object(native, "ACCOUNT_SHA256", native.digest(native_tests.ACCOUNT.encode())), patch.object(native, "_response") as response:
            path = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", native_tests.COHORT, profile=tool.PATH_PROFILE)
            old = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", native_tests.COHORT, profile=tool.PROFILE)
            with self.assertRaises(native.RehearsalError):
                path.r2("GET", native.WORKER_NAME, old.journal_prefix + "000001-" + "a" * 32 + ".json")
            with self.assertRaises(native.RehearsalError):
                path.list_objects(native.WORKER_NAME, prefix="subscriptions/", maximum=1)
            response.assert_not_called()

    def test_empty_profile_cannot_write_another_profiles_resources_or_journal(self):
        native = tool.native
        with patch.object(native, "ACCOUNT_SHA256", native.digest(native_tests.ACCOUNT.encode())), patch.object(native, "_response") as response:
            empty = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", native_tests.COHORT, profile=tool.EMPTY_PROFILE)
            path = native.RehearsalAPI(native_tests.TARGET, "synthetic-token", native_tests.COHORT, profile=tool.PATH_PROFILE)
            for request in (
                lambda: empty.json("POST", empty.root + "/d1/database", {"name": path.names["database"],
                                                                         "read_replication": {"mode": "disabled"}}),
                lambda: empty.json("POST", empty.root + "/r2/buckets", {"name": path.names["objects"], "storageClass": "Standard"}),
                lambda: empty.r2("PUT", native.WORKER_NAME, path.journal_prefix + "000001-" + "a" * 32 + ".json", b"{}"),
            ):
                with self.assertRaises(native.RehearsalError):
                    request()
            response.assert_not_called()

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

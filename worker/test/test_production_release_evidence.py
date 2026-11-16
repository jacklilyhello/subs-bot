"""Hosted private-release loading and full frozen-baseline guard regressions."""

from copy import deepcopy
from hashlib import md5
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_release_evidence as evidence
import test_prepare_isolation_artifact as archive_fixture
import test_production_control as fixtures


CHECKPOINT = "a1" * 16
PAYLOAD = "dddddddd-1111-2222-3333-eeeeeeeeeeee"
OBJECT_KEY = "private-shares/" + PAYLOAD + ".txt"
OBJECT_BODY = b"synthetic private activation baseline\n"
EMPTY_METADATA = {"custom": {}, "http": {}}


class MemoryReader:
    """Private immutable byte store plus actual synthetic source SQL reads."""
    def __init__(self, target, source_db):
        self.target, self.db = target, source_db
        self.names = {"backup": target.data["backupBucketName"]}
        self.archive_prefix = "production/checkpoints/" + CHECKPOINT + "/"
        self.objects = {}
        self.metadata = {}
        self.calls = []
        self.private = True

    def verify_backup(self):
        self.calls.append(("verify-private", self.names["backup"]))
        evidence.require(self.private)

    def object_or_none(self, bucket, key):
        self.calls.append(("GET", bucket, key))
        return self.objects.get((bucket, key)), None

    def rows(self, database_id, sql, parameters=()):
        evidence.require(database_id == self.target.d1_id and evidence.native.readonly_sql(sql))
        self.calls.append(("SELECT", database_id))
        cursor = self.db.execute(sql, parameters)
        return [dict(zip([column[0] for column in cursor.description], row)) for row in cursor]

    def list_objects(self, bucket, *, prefix="", maximum):
        evidence.require(bucket == self.target.data["bucketName"])
        result = []
        for (name, key), body in self.objects.items():
            if name == bucket and key.startswith(prefix):
                metadata = self.metadata.get(key, EMPTY_METADATA)
                result.append({"key": key, "size": len(body), "storage_class": "Standard",
                               "custom_metadata": metadata["custom"], "http_metadata": metadata["http"]})
        evidence.require(len(result) <= maximum)
        return result


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        fixtures.ProductionControllerTests.setUp(self)
        self.controller.initialize()
        self.api.db.execute("""INSERT INTO private_shares
          (bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,payload_bytes,max_claims,expire_at,created_at)
          VALUES(?,?,?,?,?,?,?,1,2100000000,1)""", (self.target.data["botId"], "f" * 64,
            self.target.data["admins"][0], "Synthetic baseline sender", PAYLOAD,
            evidence.recovery.digest(OBJECT_BODY), len(OBJECT_BODY)))
        self.scratch = self.enterContext(TemporaryDirectory())
        self.env = self.enterContext(patch.dict(os.environ, {"RUNNER_ENVIRONMENT": "github-hosted", "RUNNER_TEMP": self.scratch}))
        self.reader = MemoryReader(self.target, self.api.db)
        self.before = self.controller.inspect()
        observed = evidence._observed(self.before)
        chain = evidence.migrations._load_migrations(self.bundle, self.manifest)
        objects = evidence.migrations._objects(chain, len(chain), managed=True)
        tables = sorted(obj.name for obj in objects if obj.type == "table")
        layout = evidence.native.table_layout(self.api.db, tables)
        summary = evidence.native.data_summary(layout, lambda table, definition: self.api.db.execute(
            "SELECT " + ",".join(evidence.native._identifier(name) for name, _kind in definition["columns"])
            + " FROM " + evidence.native._identifier(table) + " ORDER BY "
            + ",".join(map(evidence.native._identifier, definition["primary"]))))
        # The real Cloudflare export omits its private _cf_KV metadata table.
        # It has no business rows in this disposable source fixture.
        sql = ("\n".join(line for line in self.api.db.iterdump() if not line.startswith("CREATE TABLE _cf_KV")) + "\n").encode()
        ci_manifest, files = archive_fixture.synthetic_release()
        files = {name: value for name, value in files.items() if not name.endswith(".sql")}
        files["index.js"] = fixtures.MODULE
        for migration in self.manifest["migrations"]:
            files[migration["name"]] = (self.bundle / migration["name"]).read_bytes()
        ci_manifest.update(self.manifest)
        ci_manifest.update(ref=evidence.artifact.MAIN_REF, runId="1234", runAttempt="1")
        self.code = archive_fixture.zip_release(ci_manifest, files)
        proof = {"revision": fixtures.REVISION, "runId": "1234", "runAttempt": "1", "artifactId": "5678",
                 "archiveSha256": evidence.recovery.digest(self.code)}
        prefix = self.reader.archive_prefix
        self.document = {"version": 2,
            "sourcePin": {"version": 1, "scopeSha256": self.target.digest,
                "schemaSha256": evidence.native._schema_digest(objects), "revision": fixtures.REVISION,
                "moduleSha256": self.manifest["bundleSha256"], "compatibilityDate": self.manifest["compatibilityDate"],
                "observed": observed, "configurationSha256": self.target.configuration_digest,
                "configuration": deepcopy(self.target.data)},
            "schemaSha256": evidence.native._schema_digest(objects), "sourceBookmark": "synthetic-private-bookmark",
            "sqlBytes": len(sql), "sqlSha256": evidence.recovery.digest(sql), "sqlMd5": md5(sql, usedforsecurity=False).hexdigest(),
            "sqlParts": [{"key": prefix + "sql/0.sql", "bytes": len(sql), "sha256": evidence.recovery.digest(sql)}],
            "objects": [{"key": OBJECT_KEY, "bytes": len(OBJECT_BODY), "sha256": evidence.recovery.digest(OBJECT_BODY),
                         "metadata": deepcopy(EMPTY_METADATA)}],
            "layout": layout, "summary": summary,
            "codeArtifact": {"proof": proof, "bytes": len(self.code), "sha256": evidence.recovery.digest(self.code),
                "parts": [{"key": prefix + "code/0.zip", "bytes": len(self.code), "sha256": evidence.recovery.digest(self.code)}]}}
        self.reader.objects[(self.reader.names["backup"], prefix + "sql/0.sql")] = sql
        self.reader.objects[(self.reader.names["backup"], prefix + "code/0.zip")] = self.code
        self.reader.objects[(self.reader.names["backup"], prefix + "blobs/" + evidence.recovery.digest(OBJECT_BODY))] = OBJECT_BODY
        self.reader.objects[(self.target.data["bucketName"], OBJECT_KEY)] = OBJECT_BODY
        self.reseal()
        self.enterContext(patch.object(evidence, "_reader", return_value=self.reader))
        self.github = self.enterContext(patch.object(evidence.artifact, "_get_json", side_effect=AssertionError("Source Actions lookup is forbidden.")))

    def reseal(self):
        raw = evidence.native.canonical(self.document)
        self.manifest_sha = evidence.recovery.digest(raw)
        self.reader.objects[(self.reader.names["backup"], self.reader.archive_prefix + "manifest.json")] = raw

    def verify(self):
        return evidence.verify_activation_baseline(self.controller, "synthetic-data-token", CHECKPOINT, self.manifest_sha)

    def test_private_release_reconstructs_exact_original_code_and_configuration_without_actions(self):
        with TemporaryDirectory(dir=self.scratch) as directory:
            loaded = evidence.load_release(self.target, "synthetic-data-token", CHECKPOINT, self.manifest_sha, directory)
            self.assertEqual(loaded["body"], self.code)
            self.assertEqual(loaded["proof"]["revision"], fixtures.REVISION)
            self.assertEqual(loaded["sourceTarget"].data, self.target.data)
            self.assertEqual((loaded["bundle"] / "index.js").read_bytes(), fixtures.MODULE)
            self.assertEqual(loaded["manifest"]["migrations"], self.manifest["migrations"])
        self.github.assert_not_called()

    def test_full_activation_baseline_reads_sql_objects_and_current_data_without_mutation(self):
        before = list(self.api.db.iterdump())
        result = self.verify()
        self.assertTrue(result["baselineVerified"])
        self.assertFalse(result["mutationPerformed"])
        self.assertEqual(result["dataSha256"], self.document["summary"]["dataSha256"])
        self.assertEqual(result["objectCount"], 1)
        self.assertEqual(list(self.api.db.iterdump()), before)
        self.assertTrue(all(call[0] in {"GET", "SELECT", "verify-private"} for call in self.reader.calls))
        self.github.assert_not_called()

    def test_missing_or_wrong_checkpoint_pins_never_authorize_baseline(self):
        for checkpoint, sha in (("", self.manifest_sha), (CHECKPOINT, ""), (CHECKPOINT, "0" * 64)):
            with self.subTest(checkpoint=checkpoint, sha=sha), self.assertRaises(evidence.recovery.RecoveryError):
                evidence.verify_activation_baseline(self.controller, "synthetic-data-token", checkpoint, sha)

    def test_public_backup_wrong_scope_and_resealed_configuration_are_rejected(self):
        self.reader.private = False
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()
        self.reader.private = True
        self.document["sourcePin"]["scopeSha256"] = "0" * 64
        self.reseal()
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()
        self.document["sourcePin"]["scopeSha256"] = self.target.digest
        self.document["sourcePin"]["configuration"]["features"]["githubSearch"] = True
        self.reseal()
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()

    def test_corrupt_archive_sql_and_object_parts_are_not_partial_success(self):
        prefix, backup = self.reader.archive_prefix, self.reader.names["backup"]
        keys = [prefix + "code/0.zip", prefix + "sql/0.sql", prefix + "blobs/" + evidence.recovery.digest(OBJECT_BODY)]
        for key in keys:
            original = self.reader.objects[(backup, key)]
            self.reader.objects[(backup, key)] = b"corrupt"
            with self.subTest(key=key), self.assertRaises(evidence.recovery.RecoveryError):
                self.verify()
            self.reader.objects[(backup, key)] = original

    def test_resealed_schema_pin_must_still_match_the_original_archived_migrations(self):
        self.document["sourcePin"]["schemaSha256"] = "0" * 64
        self.document["schemaSha256"] = "0" * 64
        self.reseal()
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()

    def test_live_data_change_after_capture_requires_a_new_baseline(self):
        self.api.insert_business()
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()

    def test_live_object_or_ownership_metadata_change_blocks_activation(self):
        location = self.target.data["bucketName"], OBJECT_KEY
        self.reader.objects[location] = b"changed-current-object"
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()
        self.reader.objects[location] = OBJECT_BODY
        self.reader.metadata[OBJECT_KEY] = {"custom": {"purpose": evidence.native.PRIVATE_SHARE_PURPOSE, "receipt": "1"}, "http": {}}
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()

    def test_thaw_or_frozen_epoch_change_invalidates_the_captured_predecessor(self):
        self.api.db.execute("UPDATE subs_bot_production_control SET workers='run'")
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()
        self.api.db.execute("UPDATE subs_bot_production_control SET workers='frozen',epoch=epoch+1")
        with self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()

    def test_control_change_during_independent_readback_is_rejected(self):
        changed = deepcopy(self.before)
        changed["control"]["epoch"] += 1
        with patch.object(self.controller, "inspect", side_effect=[self.before, changed]), self.assertRaises(evidence.recovery.RecoveryError):
            self.verify()


class ReadOnlyTransportTests(unittest.TestCase):
    def test_reader_rejects_export_import_create_and_all_r2_writes_before_network(self):
        target, _secrets = fixtures.fixture()
        name = "subs-bot-cf-restore-evidence-" + CHECKPOINT[:16]
        api = evidence.ReadOnlyRecoveryAPI(target.data, "synthetic-data-token", Mock(),
            {"version": 1, "checkpointId": CHECKPOINT, "databaseName": name, "objectsName": name, "purpose": "baseline"})
        with patch.object(evidence.native, "_response") as network:
            for method, path, body in (("POST", api.source + "/export", {}),
                ("POST", api.source + "/import", {}), ("POST", api.root + "/d1/database", {}),
                ("POST", api.source + "/query", {"sql": "DELETE FROM subscriptions"})):
                with self.subTest(path=path), self.assertRaises(evidence.recovery.RecoveryError):
                    api.json(method, path, body)
            with self.assertRaises(evidence.recovery.RecoveryError):
                api.r2("PUT", api.names["backup"], api.archive_prefix + "manifest.json", b"changed")
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()

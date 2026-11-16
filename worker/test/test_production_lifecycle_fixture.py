"""Hosted tests for the bounded synthetic fixture publication protocol."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_lifecycle_fixture as fixture
import production_target as contract
import test_production_control as control_fixture


class FixtureWriter:
    objects = None
    writes = None

    def __init__(self, target, _token, _worker, _intent):
        self.target = target

    def object_or_none(self, bucket, key):
        if bucket != fixture.SERVICE:
            raise AssertionError("Synthetic fixture escaped its dedicated bucket.")
        return self.objects.get(key), None

    def _conditional_put(self, bucket, key, body, metadata):
        if bucket != fixture.SERVICE or key in self.objects:
            raise AssertionError("Synthetic fixture overwrote an object or selected a different bucket.")
        if metadata != {"custom": {}, "http": {}}:
            raise AssertionError("Unexpected synthetic fixture metadata.")
        self.objects[key] = body
        self.writes.append(key)

    def list_objects(self, bucket, *, prefix, maximum):
        return [{"key": key, "size": len(body), "storage_class": "Standard", "custom_metadata": {}, "http_metadata": {}}
                for key, body in self.objects.items() if key.startswith(prefix)]


class SyntheticFixtureTests(unittest.TestCase):
    def setUp(self):
        # Reuse the transactional SQLite target fixture without importing its
        # TestCase class into this module's unittest discovery namespace.
        self.context = control_fixture.ProductionControllerTests(methodName="test_fresh_initialization_is_schema_exact_whitelisted_frozen_and_repeatable")
        self.context.setUp()
        self.addCleanup(self.context.doCleanups)
        self.controller = self.context.controller
        self.controller.initialize()
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bundle = Path(self.directory.name)
        objects = []
        chunk = b'{"name":"Synthetic node"}\n' * 3
        manifest_body = contract.canonical({"version": 1, "chunks": [{"bytes": len(chunk), "sha256": sha256(chunk).hexdigest(), "count": 3}]})
        for suffix, body in (("0.ndjson", chunk), ("manifest.json", manifest_body)):
            key = "subscriptions/1/" + fixture.SNAPSHOT + "/" + suffix
            path = self.bundle / "r2" / key
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
            objects.append({"key": key, "file": "r2/" + key, "bytes": len(body), "sha256": sha256(body).hexdigest()})
        self.manifest = {"revision": self.controller.revision, "snapshots": [{"id": 1, "token": fixture.SMALL_TOKEN,
            "snapshotId": fixture.SNAPSHOT, "nodeCount": 3, "manifestSha256": objects[1]["sha256"], "objects": objects}]}
        FixtureWriter.objects, FixtureWriter.writes = {}, []
        self.writer = patch.object(fixture, "RecoveryAPI", FixtureWriter)
        self.writer.start()
        self.addCleanup(self.writer.stop)

    def seed(self):
        return fixture.seed_fixture(self.controller, self.bundle, self.manifest, "synthetic-data-token")

    def test_two_exact_objects_and_three_nodes_publish_once_with_a_revoked_token_fixture(self):
        first = self.seed()
        self.assertFalse(first["repeated"])
        self.assertEqual(first["referencedObjectCount"], 2)
        self.assertEqual(first["nodeCount"], 3)
        self.assertTrue(first["revokedTokenFixture"])
        self.assertEqual([tuple(row) for row in self.context.api.db.execute(
            "SELECT subscription_id,revision FROM subscription_lifecycle ORDER BY subscription_id")], [(1, 1), (fixture.REVOKED_ID, 1)])
        data = list(self.context.api.db.iterdump())
        self.assertTrue(self.seed()["repeated"])
        self.assertEqual(list(self.context.api.db.iterdump()), data)
        self.assertEqual(len(FixtureWriter.writes), 2)

    def test_occupied_business_id_stops_before_any_object_write(self):
        self.context.api.insert_business()
        data = list(self.context.api.db.iterdump())
        with self.assertRaises(contract.ContractError):
            self.seed()
        self.assertEqual(list(self.context.api.db.iterdump()), data)
        self.assertEqual(FixtureWriter.writes, [])

    def test_occupied_revoked_lifecycle_id_or_incomplete_repeat_is_not_overwritten(self):
        self.context.api.db.execute("INSERT INTO subscription_lifecycle VALUES(?,2)", (fixture.REVOKED_ID,))
        data = list(self.context.api.db.iterdump())
        with self.assertRaises(contract.ContractError):
            self.seed()
        self.assertEqual(list(self.context.api.db.iterdump()), data)
        self.assertEqual(FixtureWriter.writes, [])

    def test_corrupted_or_extra_ci_object_is_rejected_before_publication(self):
        path = self.bundle / self.manifest["snapshots"][0]["objects"][0]["file"]
        original = path.read_bytes()
        path.write_bytes(b"synthetic conflicting bytes")
        with self.assertRaises(contract.ContractError):
            self.seed()
        path.write_bytes(original)
        self.manifest["snapshots"][0]["objects"].append(deepcopy(self.manifest["snapshots"][0]["objects"][0]))
        with self.assertRaises(contract.ContractError):
            self.seed()
        self.assertEqual(FixtureWriter.writes, [])

    def test_existing_r2_conflict_or_open_admission_never_overwrites(self):
        entry = self.manifest["snapshots"][0]["objects"][0]
        FixtureWriter.objects[entry["key"]] = b"preserved conflicting bytes"
        with self.assertRaises(contract.ContractError):
            self.seed()
        self.assertEqual(FixtureWriter.objects[entry["key"]], b"preserved conflicting bytes")
        self.assertEqual(FixtureWriter.writes, [])
        self.context.api.db.execute("UPDATE subs_bot_production_control SET admission='open',workers='run'")
        with self.assertRaises(contract.ContractError):
            self.seed()
        self.assertEqual(FixtureWriter.writes, [])


if __name__ == "__main__":
    unittest.main()

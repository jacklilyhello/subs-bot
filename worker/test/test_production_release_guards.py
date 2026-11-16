"""Guard the last reversible checks before production resource/traffic mutations."""
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_control as control
import production_provision as provision
import production_target as contract
import test_production_control as fixtures

REVISION, VERSION = fixtures.REVISION, fixtures.VERSION
approval, fixture = fixtures.approval, fixtures.fixture

STAGED = "50000000-0000-4000-8000-000000000001"


class StagedReleaseTests(unittest.TestCase):
    setUp = fixtures.ProductionControllerTests.setUp
    def assert_staged_refused(self, *, wrong_module):
        self.controller.initialize()
        self.controller.telegram = Mock()
        original = self.api.__call__
        activations = []
        def api(method, path, payload=None, **kwargs):
            if method == "POST" and path == self.controller.worker_path + "/versions?deploy=false":
                return {"id": STAGED}
            if method == "GET" and path == self.controller.worker_path + "/versions/" + STAGED + "?include=modules":
                result = original("GET", self.controller.worker_path + "/versions/" + VERSION + "?include=modules")
                result["id"] = STAGED
                if wrong_module:
                    result["modules"][0]["content_base64"] = base64.b64encode(b"export default {};").decode()
                result["bindings"] = deepcopy(result["bindings"])
                for binding in result["bindings"]:
                    if not wrong_module and binding["name"] == "NODES":
                        binding["bucket_name"] = "another-project-bucket"
                return result
            if method == "POST" and path == self.controller.script + "/deployments":
                activations.append(payload)
                raise AssertionError("An unverified staged version received traffic.")
            return original(method, path, payload, **kwargs)
        self.controller.worker = api
        before = self.controller.inspect()
        with self.assertRaises(contract.ContractError):
            self.controller.deploy(approval(self.target, "deploy", before["stateSha256"]), before["stateSha256"])
        self.assertEqual(activations, [])
        self.assertEqual(self.controller._control()["workers"], "frozen")
        self.assertEqual(self.controller._control()["admission"], "closed")

    def test_bad_staged_module_is_rejected_before_any_traffic_mutation(self):
        self.assert_staged_refused(wrong_module=True)

    def test_bad_staged_binding_is_rejected_before_any_traffic_mutation(self):
        self.assert_staged_refused(wrong_module=False)

    def test_d1_readback_alias_must_match_and_foreign_r2_jurisdiction_is_rejected(self):
        self.controller.initialize()
        active = self.controller.active()
        db = active["bindings"]["DB"]
        db["id"] = db.pop("database_id")
        self.controller.verify_bindings(active)
        db["database_id"] = "60000000-0000-4000-8000-000000000001"
        with self.assertRaises(contract.ContractError):
            self.controller.verify_bindings(active)
        db.pop("database_id")
        active["bindings"]["NODES"]["jurisdiction"] = "eu"
        with self.assertRaises(contract.ContractError):
            self.controller.verify_bindings(active)


class ProvisionCredentialTests(unittest.TestCase):
    def test_explicit_production_subjects_are_never_inferred_from_test_defaults(self):
        rehearsal, _ = fixture()
        value = deepcopy(rehearsal.data)
        service, backup, hostname = contract.NAMES["production"]
        value.update(environment="production", workerName=service, d1Name=service, bucketName=service,
                     backupBucketName=backup, hostname=hostname, botUsername="ProductionFixtureBot")
        formal = contract.validate_target(value)
        self.assertEqual(formal.data["admins"], value["admins"])
        self.assertNotEqual(formal.digest, rehearsal.digest)
        missing = deepcopy(value)
        missing.pop("admins")
        with self.assertRaises(contract.ContractError):
            contract.validate_target(missing)
        with self.assertRaises(contract.ContractError):
            contract.approve(formal, approval(rehearsal, "initialize", "a"*64), "initialize", REVISION, "a"*64)

    def test_missing_bot_secret_stops_before_constructing_a_cloud_mutation_client(self):
        rehearsal, _ = fixture()
        value = deepcopy(rehearsal.data)
        service, backup, hostname = contract.NAMES["production"]
        value.update(environment="production", workerName=service, d1Name=service, bucketName=service,
                     backupBucketName=backup, hostname=hostname, botUsername="ProductionFixtureBot",
                     admins=["92002"], members=["92003"])
        for key in contract.PINS:
            value[key] = None
        contract.validate_target(value, draft=True)
        with patch.dict(os.environ, {"SUBS_BOT_TARGET_JSON": json.dumps(value), "SUBS_BOT_CONTROL_SECRETS": "", "GITHUB_SHA": REVISION}, clear=True), \
             patch.object(provision, "hosted_environment"), patch.object(provision.artifact, "require_current_main"), \
             patch.object(provision, "API") as client:
            with self.assertRaises(contract.ContractError):
                provision.main()
            client.assert_not_called()

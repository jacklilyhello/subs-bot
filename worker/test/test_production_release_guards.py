"""Guard the last reversible checks before production resource/traffic mutations."""
from copy import deepcopy
import base64
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_control as control
import production_provision as provision
import production_target as contract
import test_production_control as fixtures
import test_production_provider as provider_fixtures

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


class ActivationBaselineTests(unittest.TestCase):
    setUp = fixtures.ProductionControllerTests.setUp

    def prepare(self):
        self.controller.initialize()
        self.controller.telegram = Mock()
        self.controller.telegram.call.return_value = {"url": "https://" + self.target.data["hostname"] + "/telegram/webhook",
            "max_connections": self.target.data["webhook"]["maxConnections"],
            "allowed_updates": self.target.data["webhook"]["allowedUpdates"]}
        self.controller.verify_domain = Mock(return_value={"domainVerified": True})
        return {"baselineVerified": True, "checkpointId": "a" * 32, "manifestSha256": "b" * 64,
                "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
                "sourceRevision": REVISION, "moduleSha256": self.manifest["bundleSha256"], "versionId": VERSION}

    def test_missing_or_mismatched_baseline_never_opens_admission(self):
        proof = self.prepare()
        with self.assertRaises(contract.ContractError):
            self.controller.plan_activate()
        for key in ("targetSha256", "configurationSha256", "sourceRevision", "moduleSha256", "versionId", "manifestSha256", "checkpointId"):
            wrong = {**proof, key: "incorrect"}
            self.controller.activation_baseline_checker = lambda: wrong
            with self.assertRaises(contract.ContractError):
                self.controller.plan_activate()
        self.assertEqual(self.controller._control()["admission"], "closed")

    def test_baseline_pin_is_bound_to_the_exact_activation_approval(self):
        proof = self.prepare()
        self.controller.activation_baseline_checker = lambda: proof
        planned = self.controller.plan_activate()
        proof["manifestSha256"] = "c" * 64
        with self.assertRaises(contract.ContractError):
            self.controller.transition("activate", approval(self.target, "activate", planned["stateSha256"]), planned["stateSha256"])
        self.assertEqual(self.controller._control()["admission"], "closed")


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


class ActiveDependencyCliTests(unittest.TestCase):
    def exercise_provider_removal(self, *, private_source, provide_read_token=True):
        desired, secrets = fixture()
        current = deepcopy(desired.data)
        current["provider"] = provider_fixtures.config(active=True)
        current["provider"]["worker"]["workerId"] = "d" * 32
        current["provider"]["caller"] = {"id": desired.data["workerId"], "name": desired.data["workerName"]}
        current["features"]["providerUrlImport"] = True
        previous = contract.validate_target(current)
        self.assertIsNone(desired.data["provider"])
        self.assertEqual(previous.digest, desired.digest)
        token = "synthetic-dependency-read-token"
        dependency_api = Mock(name="previous-provider-read-client")
        constructors, prepared = [], []
        desired_proof = {"revision": REVISION, "runId": "11", "runAttempt": "1", "artifactId": "21", "archiveSha256": "e" * 64}
        active_proof = {**desired_proof, "revision": "a" * 40, "runId": "10", "artifactId": "20"}
        desired_manifest = {"version": 2, "revision": REVISION, "bundleSha256": "d" * 64}
        active_manifest = {**desired_manifest, "revision": active_proof["revision"]}

        def make_api(target, credential, **_kwargs):
            if credential == token:
                self.assertEqual(target.configuration_digest, previous.configuration_digest)
                return dependency_api
            return Mock(name="scoped-project-api")

        def make_controller(target, _data, _worker, _bundle, _manifest, **kwargs):
            instance = SimpleNamespace(target=target, dependency_api=kwargs.get("dependency_api"))
            constructors.append(instance)
            if target.configuration_digest == desired.configuration_digest:
                def plan(source_controller):
                    self.assertEqual(source_controller.target.configuration_digest, previous.configuration_digest)
                    self.assertIs(source_controller.dependency_api, dependency_api)
                    return {"stateSha256": "f" * 64, "targetSha256": target.digest}
                instance.plan_deploy = Mock(side_effect=plan)
            return instance

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            desired_bundle = root / control.artifact.VERIFIED_DIRECTORY
            desired_bundle.mkdir()
            (desired_bundle / "isolation.json").write_bytes(contract.canonical(desired_manifest))

            def prepare(action, *, run_id=None, directory=None):
                prepared.append((action, run_id))
                if directory is None:
                    return desired_proof
                bundle = Path(directory) / control.artifact.VERIFIED_DIRECTORY
                bundle.mkdir()
                (bundle / "isolation.json").write_bytes(contract.canonical(active_manifest))
                return active_proof

            env = {"CONTROL_ACTION": "plan-deploy", "SUBS_BOT_TARGET_JSON": json.dumps(desired.data),
                "SUBS_BOT_CONTROL_SECRETS": json.dumps(secrets), "SUBS_BOT_ACTIVE_TARGET_JSON": json.dumps(previous.data),
                "SUBS_BOT_ACTIVE_CONTROL_SECRETS": json.dumps(secrets), "GITHUB_SHA": REVISION,
                "RUNNER_TEMP": temporary, "SUBS_BOT_CF_DATA_TOKEN": "synthetic-data-token",
                "SUBS_BOT_CF_WORKER_TOKEN": "synthetic-worker-token"}
            if provide_read_token:
                env["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"] = token
            if private_source:
                env.update(CONTROL_ACTIVE_CHECKPOINT_ID="a" * 32, CONTROL_ACTIVE_MANIFEST_SHA256="b" * 64)
            else:
                env["CONTROL_ACTIVE_CI_RUN_ID"] = "10"
            archived = {"proof": active_proof, "bundle": desired_bundle, "manifest": active_manifest, "sourceTarget": previous}
            with patch.dict(os.environ, env, clear=True), patch.object(control, "hosted_environment"), \
                 patch.object(control.artifact, "require_current_main"), patch.object(control, "API", side_effect=make_api), \
                 patch.object(control, "Controller", side_effect=make_controller), \
                 patch.object(control.prepare_control_artifact, "prepare", side_effect=prepare), \
                 patch("production_release_evidence.load_release", return_value=archived) as load_private, \
                 patch("builtins.print"):
                if provide_read_token:
                    control.main()
                    self.assertEqual(len(constructors), 2)
                    self.assertIsNone(constructors[0].dependency_api)
                    self.assertIs(constructors[1].dependency_api, dependency_api)
                    constructors[0].plan_deploy.assert_called_once_with(constructors[1])
                else:
                    with self.assertRaisesRegex(contract.ContractError, "active ProviderFetch requires its own explicit read credential"):
                        control.main()
                    self.assertEqual(len(constructors), 1)
                    constructors[0].plan_deploy.assert_not_called()
                self.assertEqual(load_private.call_count, 1 if private_source else 0)
                self.assertEqual(prepared, [("plan-deploy", None)] if private_source else [("plan-deploy", None), ("inspect", "10")])

    def test_ci_active_source_keeps_dependency_reads_when_new_target_removes_provider(self):
        self.exercise_provider_removal(private_source=False)

    def test_private_active_source_keeps_dependency_reads_when_new_target_removes_provider(self):
        self.exercise_provider_removal(private_source=True)

    def test_missing_old_dependency_credential_refuses_both_source_backends(self):
        for private_source in (False, True):
            with self.subTest(private_source=private_source):
                self.exercise_provider_removal(private_source=private_source, provide_read_token=False)

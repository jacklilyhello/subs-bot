"""Hosted synthetic contracts for the protected private provider release."""

from base64 import b64encode
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import sys
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import activate_provider_isolation as activation


ACCOUNT = "a" * 32
NAMESPACE = "b" * 32
ACTOR = "c" * 64
REVISION = "d" * 40
ISOLATED = "e" * 40
VERSION = "11111111-2222-3333-4444-555555555555"
DEPLOYMENT = "22222222-3333-4444-5555-666666666666"
WORKFLOW = "33333333-4444-5555-6666-777777777777"
WORKFLOW_VERSION = "44444444-5555-6666-7777-888888888888"
FOREIGN = "99999999-8888-7777-6666-555555555555"
CREATED = "2026-11-07T00:00:00.123Z"
START = "2026-11-07T01:00:00Z"
STOP = "2026-11-07T01:00:05Z"
MODULE = b'export default {fetch(){return new Response(null,{status:404})}};\n'
EVIDENCE = {
    "revision": REVISION, "runId": "10", "runAttempt": "1", "artifactId": "20",
    "archiveSha256": "e" * 64, "compatibilityDate": activation.provider.COMPATIBILITY,
    "workerSha256": sha256(MODULE).hexdigest(), "ociArchiveSha256": "f" * 64,
    "ociManifestSha256": "1" * 64, "ociConfigSha256": "2" * 64,
}
RELEASE = {**EVIDENCE, "versionId": VERSION}
HISTORICAL = {**EVIDENCE, "revision": activation.HISTORICAL_PROVIDER_REVISION,
              "runId": activation.HISTORICAL_PROVIDER_CI_RUN}
IDENTITY = activation.bootstrap.Identity("3" * 32, CREATED)
ACTIVATION = {"deploymentId": DEPLOYMENT, "namespaceId": NAMESPACE}
CONTAINER = {"applicationId": NAMESPACE, "createdAt": CREATED}
WORKFLOW_PIN = {"workflowId": WORKFLOW, "createdOn": CREATED, "versionId": WORKFLOW_VERSION}
PINS = {"activation": ACTIVATION, "container": CONTAINER, "workflow": WORKFLOW_PIN}
NO_PINS = {"activation": None, "container": None, "workflow": None}
HEALTH = b'{"ok":true,"service":"subs-bot","revision":"' + ISOLATED.encode() + b'"}'
HEALTH_PROOF = {"status": 200, "bytes": len(HEALTH), "sha256": sha256(HEALTH).hexdigest()}
IMAGE = f"registry.cloudflare.com/{ACCOUNT}/{activation.provider.SERVICE}@sha256:{RELEASE['ociManifestSha256']}"


def envelope(result, **extra):
    return {"success": True, "errors": None, "result": result, **extra}


def response(result, **extra):
    return 200, {}, json.dumps(envelope(result, **extra)).encode()


def state(level=0, instance=None):
    return {"activation": ACTIVATION if level >= 1 else None, "container": CONTAINER if level >= 2 else None,
            "workflow": WORKFLOW_PIN if level >= 3 else None, "instance": instance}


def smoke():
    return {"status": "complete", "success": True, "error": None, "start": START, "end": STOP,
            "versionId": WORKFLOW_VERSION, "trigger": {"source": "api"},
            "params": {"providerRevision": REVISION, "isolatedRevision": ISOLATED},
            "output": json.dumps({"ok": True, "revision": REVISION, "isolatedRevision": ISOLATED,
                                  "imageSha256": RELEASE["ociManifestSha256"], "edgeStatus": 200,
                                  "approvedDnsFamilies": [4, 6], "bodyBytes": len(HEALTH),
                                  "bodySha256": HEALTH_PROOF["sha256"], "blockedPrivateTargets": 3, "stopped": True})}


def worker():
    value = deepcopy(activation.bootstrap.CREATE_SETTINGS)
    return {**value, "id": IDENTITY.worker_id, "created_on": CREATED, "updated_on": STOP,
            "deployed_on": None, "references": {key: [] for key in activation.bootstrap.REFERENCE_FIELDS}}


def version():
    metadata = deepcopy(activation.stage._metadata(RELEASE, IMAGE))
    del metadata["containers"]
    return {**metadata, "id": VERSION, "urls": [], "modules": [
        {"name": activation.provider.WORKER, "content_type": activation.stage.MODULE_TYPE,
         "content_base64": b64encode(MODULE).decode("ascii")},
    ]}


def legacy_version():
    metadata = activation.stage._metadata(RELEASE, IMAGE)
    return {"id": VERSION, "resources": {"bindings": metadata["bindings"],
            "script_runtime": {"containers": metadata["containers"],
                               "compatibility_date": metadata["compatibility_date"]}}}


class PinTests(unittest.TestCase):
    def test_release_requires_exact_artifact_fields_and_version_id(self):
        self.assertEqual(activation._release_pin(json.dumps(RELEASE), EVIDENCE), RELEASE)
        for changed in ({**RELEASE, "workerSha256": "0" * 64}, {**RELEASE, "runAttempt": "2"},
                        {**RELEASE, "versionId": "../secret"}, {**RELEASE, "extra": True}):
            with self.subTest(changed=changed), self.assertRaisesRegex(activation.ActivationError, "pin is invalid"):
                activation._release_pin(json.dumps(changed), EVIDENCE)

    def test_resource_pin_shape_ids_and_exact_timestamp(self):
        self.assertIsNone(activation._pin("", ACTIVATION))
        self.assertEqual(activation._pin(json.dumps(CONTAINER), CONTAINER), CONTAINER)
        for changed in ({**CONTAINER, "createdAt": "yesterday"}, {**CONTAINER, "applicationId": "a" * 31},
                        {**CONTAINER, "unexpected": "secret"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                activation._pin(json.dumps(changed), CONTAINER)
        with self.assertRaises(ValueError):
            activation._pin('{"namespaceId":"secret","namespaceId":"other"}', ACTIVATION)

    def test_cursor_or_excess_inventory_never_proves_absence(self):
        for info in ({"next_page_token": "more"}, {"cursor": "more"}, {"cursors": {"after": "more"}}):
            with self.subTest(info=info), self.assertRaises(activation.ActivationError):
                activation._page({"result_info": info}, [], 1, cursor=True)
        with self.assertRaises(activation.ActivationError):
            activation._page({}, [1, 2], 1, cursor=True)


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock(spec=activation.ProviderAPI)
        self.api.identity = IDENTITY
        self.api.actors.return_value = []
        self.api.instances.return_value = []
        self.guard = Mock()

    def run_operation(self, operation, states, pins=NO_PINS):
        with patch.object(activation, "_observe", side_effect=states), patch.object(
                activation, "_public", return_value=HEALTH_PROOF), patch.object(activation, "sleep"):
            return activation._run(self.api, operation, RELEASE, pins, ISOLATED, self.guard)

    def assert_writes(self, name=None):
        for method in ("deploy", "create_container", "create_workflow", "trigger"):
            self.assertEqual(getattr(self.api, method).call_count, int(method == name))

    def test_default_verify_is_read_only_and_reports_unpinned_partial_state(self):
        for level, expected in ((0, "staged"), (1, "active-awaiting-container"),
                                (2, "container-awaiting-workflow"), (3, "ready-to-smoke")):
            with self.subTest(level=level):
                result = self.run_operation("verify", [state(level), state(level)])
                self.assertEqual(result["status"], expected)
                self.assertEqual(result["activationIdentitySha256"], activation._fingerprint(state(level)["activation"]))
        self.assert_writes()

    def test_activate_only_deploys_and_returns_namespace_fingerprint(self):
        self.api.deploy.return_value = {"id": DEPLOYMENT}
        result = self.run_operation("activate", [state(), state(), state(1), state(1)])
        self.assertEqual(result["status"], "active-awaiting-container")
        self.api.deploy.assert_called_once_with(RELEASE)
        self.assert_writes("deploy")

    def test_each_provision_dispatch_writes_only_its_missing_resource(self):
        self.api.create_container.return_value = {"id": NAMESPACE, "created_at": CREATED}
        pins = {**NO_PINS, "activation": ACTIVATION}
        result = self.run_operation("provision-container", [state(1), state(1), state(2), state(2)], pins)
        self.assertEqual(result["status"], "container-awaiting-workflow")
        self.api.create_container.assert_called_once_with(NAMESPACE)
        self.assert_writes("create_container")
        self.api.reset_mock()
        self.api.create_workflow.return_value = {"id": WORKFLOW, "created_on": CREATED, "version_id": WORKFLOW_VERSION}
        pins = {**pins, "container": CONTAINER}
        result = self.run_operation("provision-workflow", [state(2), state(2), state(3), state(3)], pins)
        self.assertEqual(result["status"], "ready-to-smoke")
        self.assert_writes("create_workflow")

    def test_observed_unpinned_resource_is_not_automatically_adopted_for_next_write(self):
        for operation, level in (("provision-container", 1), ("provision-workflow", 2), ("smoke", 3)):
            with self.subTest(operation=operation), self.assertRaises(activation.ActivationError):
                self.run_operation(operation, [state(level), state(level)])
        self.assert_writes()

    def test_changed_state_or_stale_main_blocks_before_write(self):
        with self.assertRaisesRegex(activation.ActivationError, "changed"):
            self.run_operation("activate", [state(), state(1)])
        self.guard.side_effect = activation.github.ArtifactError("Current main changed.")
        with self.assertRaises(activation.github.ArtifactError):
            self.run_operation("activate", [state()])
        self.assert_writes()

    def test_foreign_or_incomplete_predecessor_pin_blocks_before_write(self):
        for pins in ({**NO_PINS, "activation": {**ACTIVATION, "deploymentId": FOREIGN}},
                     {**NO_PINS, "container": CONTAINER}):
            with self.subTest(pins=pins), self.assertRaises(activation.ActivationError):
                self.run_operation("provision-container", [state(1)], pins)
        self.assert_writes()

    def test_ambiguous_write_is_never_retried_or_followed_by_provisioning(self):
        self.api.deploy.side_effect = activation.ActivationError(activation.WRITE_ERROR)
        with self.assertRaisesRegex(activation.ActivationError, "not confirmed"):
            self.run_operation("activate", [state(), state()])
        self.assert_writes("deploy")

    def test_mutation_response_identity_must_match_independent_readback(self):
        self.api.deploy.return_value = {"id": FOREIGN}
        with self.assertRaisesRegex(activation.ActivationError, "not confirmed"):
            self.run_operation("activate", [state(), state(), state(1)])
        self.assert_writes("deploy")

    def test_failed_post_read_preserves_single_write_for_later_recovery(self):
        self.api.deploy.return_value = {"id": DEPLOYMENT}
        with self.assertRaises(activation.ActivationError):
            self.run_operation("activate", [state(), state(), activation.ActivationError(activation.ERROR)])
        self.assert_writes("deploy")

    def test_smoke_once_and_read_only_repeat_require_independent_shutdown(self):
        self.api.trigger.return_value = {"id": "provider-smoke-" + REVISION, "version_id": WORKFLOW_VERSION, "workflow_id": WORKFLOW}
        self.api.stopped.return_value = activation._hash(ACTOR)
        complete = state(3, smoke())
        result = self.run_operation("smoke", [state(3), state(3), complete, complete], PINS)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(set(result), activation.PROOF_FIELDS)
        self.api.trigger.assert_called_once_with(RELEASE, ISOLATED)
        self.api.stopped.assert_called_once_with(NAMESPACE, START, RELEASE["ociManifestSha256"])
        self.assert_writes("trigger")
        self.api.reset_mock()
        self.assertEqual(self.run_operation("verify", [complete, complete], PINS)["status"], "complete")
        self.assert_writes()

    def test_existing_smoke_or_actor_blocks_reexecution(self):
        with self.assertRaises(activation.ActivationError):
            self.run_operation("smoke", [state(3, smoke()), state(3, smoke())], PINS)
        self.api.actors.return_value = [{"id": ACTOR, "hasStoredData": True}]
        with self.assertRaises(activation.ActivationError):
            self.run_operation("smoke", [state(3), state(3)], PINS)
        self.assert_writes()

    def test_failed_or_running_one_shot_is_not_reported_complete(self):
        failed = {**smoke(), "status": "errored", "success": False, "error": {"message": "synthetic-secret"}}
        with self.assertRaises(activation.ActivationError) as error:
            self.run_operation("verify", [state(3, failed)], PINS)
        self.assertNotIn("synthetic-secret", str(error.exception))
        running = {**smoke(), "status": "running"}
        self.assertEqual(self.run_operation("verify", [state(3, running), state(3, running)], PINS)["status"], "smoke-running")
        self.assert_writes()


class APIContractTests(unittest.TestCase):
    def setUp(self):
        pin = patch.object(activation.bootstrap, "TARGET_ACCOUNT_SHA256", sha256(ACCOUNT.encode()).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        self.api = activation.ProviderAPI(ACCOUNT, "synthetic-worker", "synthetic-container", IDENTITY)

    def test_fixed_writes_use_separate_auth_and_never_a_second_write(self):
        cases = (
            ("deploy", (RELEASE,), "POST", self.api.worker_path + "/deployments", "synthetic-worker"),
            ("create_container", (NAMESPACE,), "POST", "/containers/applications", "synthetic-container"),
            ("create_workflow", (), "PUT", self.api.workflow_path, "synthetic-worker"),
            ("trigger", (RELEASE, ISOLATED), "POST", self.api.workflow_path + "/instances", "synthetic-worker"),
        )
        for method, args, verb, path, token in cases:
            with self.subTest(method=method), patch.object(activation.publication, "_response", return_value=response({})) as send:
                self.api._writes = 0
                getattr(self.api, method)(*args)
                request = send.call_args.args[0]
                self.assertEqual((request.method, request.full_url), (verb, self.api.base + path))
                self.assertEqual(request.get_header("Authorization"), "Bearer " + token)
                body = json.loads(request.data)
                if method == "deploy":
                    self.assertEqual(body["versions"], [{"version_id": VERSION, "percentage": 100}])
                    self.assertNotIn("force", body)
                elif method == "create_container":
                    self.assertEqual(body, {"name": activation.provider.SERVICE, "scheduling_policy": "durable_object",
                                           "durable_objects": {"namespace_id": NAMESPACE},
                                           "configuration": {"authorized_keys": [], "wrangler_ssh": {"enabled": False}},
                                           "observability": {"logs": {"enabled": False}}})
                elif method == "create_workflow":
                    self.assertEqual(body["schedules"], [])
                    self.assertEqual(body["concurrency"], {"limit": 1})
                else:
                    self.assertEqual(body["params"], {"providerRevision": REVISION, "isolatedRevision": ISOLATED})
                with self.assertRaisesRegex(activation.ActivationError, "not confirmed"):
                    self.api.deploy(RELEASE)
                send.assert_called_once()

    def test_unknown_error_envelopes_or_application_404_never_authorize_creation(self):
        for status, errors in ((403, [{"code": 10200}]), (404, [{"code": 10007}]),
                               (404, [{"code": True}]), (404, [{"code": 10200}, {"code": 10200}])):
            with self.subTest(status=status, errors=errors), patch.object(activation.publication, "_response", return_value=(
                    status, {}, json.dumps({"success": False, "errors": errors}).encode())):
                with self.assertRaises(activation.ActivationError):
                    self.api.workflow()
        missing = (404, {}, b'{"success":false,"errors":[{"code":10200}]}')
        with patch.object(activation.publication, "_response", return_value=missing):
            self.assertIsNone(self.api.workflow())

    def test_managed_container_sends_and_verifies_the_documented_disabled_ssh_object(self):
        expected = {"authorized_keys": [], "wrangler_ssh": {"enabled": False}}
        value = {"id": NAMESPACE, "account_id": ACCOUNT, "name": activation.provider.SERVICE,
                 "scheduling_policy": "durable_object", "durable_objects": {"namespace_id": NAMESPACE},
                 "created_at": CREATED, "configuration": expected, "observability": {"logs": {"enabled": False}}}
        with patch.object(activation.publication, "_response", return_value=response(value)) as send:
            self.api.create_container(NAMESPACE)
            self.assertEqual(json.loads(send.call_args.args[0].data)["configuration"], expected)
        with patch.object(self.api, "_request", side_effect=[envelope([value]), envelope(value)]):
            self.assertEqual(self.api.container(NAMESPACE), CONTAINER)

    def test_ambiguous_mutation_failure_consumes_write_allowance_and_redacts_body(self):
        failed = (503, {}, b'{"success":false,"errors":[{"code":4101,"message":"synthetic-secret"},'
                  b'{"code":true},{"code":"4102"},{"code":99999999}]}')
        with patch.object(activation.publication, "_response", return_value=failed) as send:
            with self.assertRaisesRegex(activation.ActivationError, r'"httpStatus":503,"cloudflareCodes":\[4101\]') as error:
                self.api.create_workflow()
            self.assertNotIn("synthetic-secret", str(error.exception))
            with self.assertRaisesRegex(activation.ActivationError, "not confirmed"):
                self.api.create_workflow()
            send.assert_called_once()

    def test_unparseable_mutation_reports_status_but_not_response(self):
        with patch.object(activation.publication, "_response", return_value=(422, {}, b"synthetic-secret")):
            with self.assertRaisesRegex(activation.ActivationError, '"phase":"response-json","httpStatus":422') as error:
                self.api.create_container(NAMESPACE)
        self.assertNotIn("synthetic-secret", str(error.exception))

    def test_container_requires_complete_inventory_exact_id_privacy_and_timestamp(self):
        value = {"id": NAMESPACE, "account_id": ACCOUNT, "name": activation.provider.SERVICE,
                 "scheduling_policy": "durable_object", "durable_objects": {"namespace_id": NAMESPACE},
                 "created_at": CREATED, "configuration": {"authorized_keys": [], "wrangler_ssh": {"enabled": False, "port": 22}},
                 "observability": {"logs": {"enabled": False}}}
        with patch.object(self.api, "_request", side_effect=[envelope([value]), envelope(value)]) as read:
            self.assertEqual(self.api.container(NAMESPACE), CONTAINER)
            self.assertEqual(read.call_args_list[0], call("/containers/applications?per_page=500", container=True))
        with patch.object(self.api, "_request", return_value=envelope([])) as read:
            self.assertIsNone(self.api.container(NAMESPACE))
            read.assert_called_once()
        for changed in ({"account_id": "f" * 32}, {"durable_objects": {"namespace_id": "f" * 32}},
                        {"scheduling_policy": "default"}, {"observability": {"logs": {"enabled": True}}},
                        {"configuration": {"authorized_keys": [{"public_key": "synthetic-key"}]}},
                        {"configuration": {}}, {"configuration": {"wrangler_ssh": False}},
                        {"configuration": {"wrangler_ssh": {"enabled": True}}},
                        {"configuration": {"wrangler_ssh": {"enabled": False, "port": True}}},
                        {"created_at": "unknown"}):
            with self.subTest(changed=changed), patch.object(self.api, "_request", side_effect=[envelope([value]), envelope({**value, **changed})]):
                with self.assertRaises(ValueError):
                    self.api.container(NAMESPACE)
        for inventory in ([value, value], [{**value, "name": "foreign"}], [value]):
            namespace = None if inventory == [value] else NAMESPACE
            with self.subTest(inventory=inventory), patch.object(self.api, "_request", return_value=envelope(inventory)):
                with self.assertRaises(activation.ActivationError):
                    self.api.container(namespace)

    def test_active_version_reuses_exact_bytes_and_requires_independent_sqlite_namespace(self):
        legacy = legacy_version()
        namespace = {"id": NAMESPACE, "script": activation.provider.SERVICE, "class": "ProviderContainer", "use_sqlite": True}
        replies = [envelope([{"id": VERSION}]), envelope(legacy), envelope([namespace]), envelope(version())]
        with patch.object(self.api, "_request", side_effect=replies):
            self.assertEqual(self.api.version(RELEASE, True), NAMESPACE)
        for changed in ({"use_sqlite": False}, {"script": "other"}, {"class": "Foreign"},
                        {"preview": {"id": "foreign"}}, {"dispatch_namespace": "foreign"}):
            with self.subTest(changed=changed), patch.object(self.api, "_request", side_effect=[
                    envelope([{"id": VERSION}]), envelope(legacy), envelope([{**namespace, **changed}])]):
                with self.assertRaises(activation.ActivationError):
                    self.api.version(RELEASE, True)
        bad = version()
        bad["modules"][0]["content_base64"] = b64encode(MODULE + b" ").decode()
        with patch.object(self.api, "_request", side_effect=[envelope([{"id": VERSION}]), envelope(legacy), envelope([namespace]), envelope(bad)]):
            with self.assertRaises(activation.stage.StageError):
                self.api.version(RELEASE, True)
        for bindings in (legacy["resources"]["bindings"], version()["bindings"]):
            bindings.append({"name": "PROVIDER_CONTAINER", "type": "durable_object_namespace",
                             "class_name": "ProviderContainer", "namespace_id": NAMESPACE})
            beta = {**version(), "bindings": bindings}
            with patch.object(self.api, "_request", side_effect=[
                    envelope([{"id": VERSION}]), envelope(legacy), envelope([namespace]), envelope(beta)]):
                with self.assertRaises(activation.stage.StageError):
                    self.api.version(RELEASE, True)
            bindings.pop()

    def test_full_default_verification_observes_real_module_and_separate_resource_versions(self):
        deployment = {"id": DEPLOYMENT, "strategy": "percentage", "created_on": START,
                      "versions": [{"version_id": VERSION, "percentage": 100}],
                      "annotations": {"workers/message": f"provider-activate/{REVISION}/{EVIDENCE['artifactId']}"}}
        container = {"id": NAMESPACE, "account_id": ACCOUNT, "name": activation.provider.SERVICE,
                     "scheduling_policy": "durable_object", "durable_objects": {"namespace_id": NAMESPACE},
                     "created_at": CREATED, "configuration": {"wrangler_ssh": {"enabled": False}},
                     "observability": {"logs": {"enabled": False}}}
        workflow = {"id": WORKFLOW, "created_on": CREATED, "name": activation.stage.WORKFLOW,
                    "class_name": "ProviderSmoke", "script_name": activation.provider.SERVICE}
        workflow_version = {"id": WORKFLOW_VERSION, "workflow_id": WORKFLOW, "class_name": "ProviderSmoke",
                            "language": "javascript", "concurrency": {"limit": 1}}
        for active in (False, True):
            profile = worker()
            profile["deployed_on"] = START if active else None
            replies = {
                self.api.worker_path + "/deployments?page=1&per_page=2": envelope({"deployments": [deployment] if active else []}),
                self.api.worker_path + "/deployments/" + DEPLOYMENT: envelope(deployment),
                self.api.beta_path + "?page=1&per_page=2": envelope([{"id": VERSION}]),
                self.api.beta_path + "/" + VERSION + "?include=modules": envelope(version()),
                self.api.worker_path + "/versions/" + VERSION: envelope(legacy_version()),
                "/workers/durable_objects/namespaces?page=1&per_page=1000": envelope([
                    {"id": NAMESPACE, "script": activation.provider.SERVICE, "class": "ProviderContainer", "use_sqlite": True}]),
                "/containers/applications?per_page=500": envelope([container] if active else []),
                "/containers/applications/" + NAMESPACE: envelope(container),
                self.api.workflow_path: envelope(workflow) if active else None,
                self.api.workflow_path + "/versions?page=1&per_page=2": envelope([workflow_version]),
                self.api.workflow_path + "/versions/" + WORKFLOW_VERSION: envelope(workflow_version),
                self.api.workflow_path + "/instances?page=1&per_page=2": envelope([]),
            }

            def read(path, **unused):
                return deepcopy(replies[path])

            with self.subTest(active=active), patch.object(self.api, "_request", side_effect=read) as requests, patch.object(
                    self.api.worker, "by_name", return_value=profile), patch.object(self.api.worker, "by_id", return_value=profile), patch.object(
                    activation, "_public", return_value={"status": 404}):
                result = activation._run(self.api, "verify", RELEASE, PINS if active else NO_PINS, ISOLATED, Mock())
                self.assertEqual(result["status"], "ready-to-smoke" if active else "staged")
                self.assertTrue(all(entry.kwargs.get("method", "GET") == "GET" for entry in requests.call_args_list))
                self.assertNotEqual(VERSION, WORKFLOW_VERSION)

    def test_workflow_version_or_instance_link_must_match_the_pinned_identity(self):
        value = {"id": WORKFLOW, "created_on": CREATED, "name": activation.stage.WORKFLOW,
                 "class_name": "ProviderSmoke", "script_name": activation.provider.SERVICE}
        version_row = {"id": WORKFLOW_VERSION, "workflow_id": WORKFLOW, "class_name": "ProviderSmoke",
                       "language": "javascript", "concurrency": {"limit": 1}}
        for changed in ({"workflow_id": FOREIGN}, {"class_name": "Other"}, {"concurrency": {"limit": 2}}):
            with self.subTest(changed=changed), patch.object(self.api, "_request", side_effect=[
                    envelope(value), envelope([version_row]), envelope({**version_row, **changed})]):
                with self.assertRaises(activation.ActivationError):
                    self.api.workflow()
        row = {"id": "provider-smoke-" + REVISION, "workflow_id": WORKFLOW, "version_id": WORKFLOW_VERSION, "trigger_source": "api"}
        for changed in ({"version_id": VERSION}, {"workflow_id": FOREIGN}, {"trigger_source": "binding"}):
            with self.subTest(changed=changed), patch.object(self.api, "_request", return_value=envelope([{**row, **changed}])):
                with self.assertRaises(activation.ActivationError):
                    self.api.smoke_instance(RELEASE, WORKFLOW_PIN)

    def test_exact_control_plane_stopped_instance_and_active_inventory(self):
        stopped = {"id": ACTOR, "application_id": NAMESPACE, "image": IMAGE, "status": {"state": "stopped", "updated_at": STOP}}
        with patch.object(self.api, "actors", return_value=[{"id": ACTOR, "hasStoredData": True}]), patch.object(
                self.api, "instances", side_effect=[[stopped], []]), patch.object(self.api, "_request", return_value=envelope(stopped)):
            self.assertEqual(self.api.stopped(NAMESPACE, START, RELEASE["ociManifestSha256"]), activation._hash(ACTOR))
        for changed in ({"status": {"state": "running", "updated_at": STOP}},
                        {"status": {"state": "stopped", "updated_at": CREATED}},
                        {"image": IMAGE.replace(RELEASE["ociManifestSha256"], "f" * 64)}, {"id": "f" * 64}):
            with self.subTest(changed=changed), patch.object(self.api, "actors", return_value=[{"id": ACTOR, "hasStoredData": True}]), patch.object(
                    self.api, "instances", side_effect=[[stopped], []]), patch.object(self.api, "_request", return_value=envelope({**stopped, **changed})):
                with self.assertRaises(activation.ActivationError):
                    self.api.stopped(NAMESPACE, START, RELEASE["ociManifestSha256"])


class ProofTests(unittest.TestCase):
    def test_smoke_output_rejects_wrong_revision_digest_auth_or_numeric_booleans(self):
        self.assertTrue(activation._smoke_result(smoke(), RELEASE, WORKFLOW_PIN, ISOLATED, HEALTH_PROOF)["ok"])
        for changed in ({"ok": 1}, {"stopped": 1}, {"revision": "f" * 40}, {"imageSha256": "f" * 64},
                        {"bodySha256": "f" * 64}, {"approvedDnsFamilies": []}, {"extra": "synthetic-secret"}):
            fixture = smoke()
            fixture["output"] = json.dumps({**json.loads(fixture["output"]), **changed})
            with self.subTest(changed=changed), self.assertRaises(activation.ActivationError) as error:
                activation._smoke_result(fixture, RELEASE, WORKFLOW_PIN, ISOLATED, HEALTH_PROOF)
            self.assertNotIn("synthetic-secret", str(error.exception))
        for changed in ({"versionId": FOREIGN}, {"trigger": {"source": "binding"}}, {"schedule": {"cron": "* * * * *"}},
                        {"output": {}}, {"output": '{"ok":true,"ok":true}'}, {"end": CREATED}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                activation._smoke_result({**smoke(), **changed}, RELEASE, WORKFLOW_PIN, ISOLATED, HEALTH_PROOF)

    def test_fixed_public_probe_has_no_authorization_and_refuses_redirect_or_live_handler(self):
        for status, headers, body, accepted in ((404, {}, b"Not found", True), (403, {}, b"Denied", True),
                                               (302, {"Location": "https://example.invalid"}, b"", False), (200, {}, b"ok", False)):
            with self.subTest(status=status), patch.object(activation.publication, "_response", return_value=(status, headers, body)) as send:
                if accepted:
                    activation._public(activation.PROVIDER_URL)
                else:
                    with self.assertRaises(activation.ActivationError):
                        activation._public(activation.PROVIDER_URL)
                request = send.call_args.args[0]
                self.assertIsNone(request.get_header("Authorization"))
                self.assertEqual(request.full_url, activation.PROVIDER_URL)

    def test_fixed_application_health_uses_the_isolation_release_user_agent(self):
        def edge(request, _opener, _error, **kwargs):
            self.assertEqual(request.full_url, activation.HEALTH_URL)
            self.assertIsNone(request.get_header("Authorization"))
            if request.get_header("User-agent") != "subs-bot-isolation-release/1.0":
                return 403, {}, b'{"error":"denied"}'
            return 200, {}, HEALTH

        with patch.object(activation.publication, "_response", side_effect=edge):
            self.assertEqual(activation._public(activation.HEALTH_URL, ISOLATED), HEALTH_PROOF)

    def test_fixed_application_health_redacts_rejected_bodies_and_checks_revision(self):
        with patch.object(activation.publication, "_response", return_value=(403, {}, b"synthetic-secret")):
            with self.assertRaisesRegex(activation.ActivationError, "HTTP 403") as error:
                activation._public(activation.HEALTH_URL, ISOLATED)
        self.assertNotIn("synthetic-secret", str(error.exception))
        with patch.object(activation.publication, "_response", return_value=(200, {}, HEALTH)):
            with self.assertRaisesRegex(activation.ActivationError, "exact app revision"):
                activation._public(activation.HEALTH_URL, REVISION)

    def test_private_worker_metadata_keeps_disabled_defaults_and_rejects_drift(self):
        value = worker()
        activation._private_profile(value, IDENTITY, False)
        value["deployed_on"] = START
        activation._private_profile(value, IDENTITY, True)
        for changed in ({"tags": ["foreign"]}, {"subdomain": {"enabled": True, "previews_enabled": False}},
                        {"references": {**value["references"], "workers": [{"worker_id": "foreign"}]}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                activation._private_profile({**value, **changed}, IDENTITY, True)

    def test_entrypoint_rejects_rerun_or_non_main_before_credential_or_network_use(self):
        env = {"GITHUB_REPOSITORY": activation.github.REPOSITORY, "GITHUB_REF": activation.github.MAIN_REF,
               "GITHUB_SHA": REVISION, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "2",
               "SUBS_BOT_PROVIDER_CI_RUN_ID": "10", "SUBS_BOT_PROVIDER_ACTIVATION_OPERATION": "activate", "RUNNER_TEMP": "/tmp"}
        with patch.dict(os.environ, env, clear=True), patch.object(activation.publication, "_verified_input") as artifact:
            with self.assertRaisesRegex(activation.ActivationError, "previous operation"):
                activation.activate()
            artifact.assert_not_called()
        env["GITHUB_RUN_ATTEMPT"] = "1"
        env["GITHUB_REF"] = "refs/pull/1/merge"
        with patch.dict(os.environ, env, clear=True), self.assertRaisesRegex(activation.ActivationError, "exact main"):
            activation.activate()

    def test_entrypoint_preserves_exact_provenance_and_separate_identity_pins(self):
        env = {"GITHUB_REPOSITORY": activation.github.REPOSITORY, "GITHUB_REF": activation.github.MAIN_REF,
               "GITHUB_SHA": REVISION, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
               "SUBS_BOT_PROVIDER_CI_RUN_ID": "10", "SUBS_BOT_PROVIDER_ACTIVATION_OPERATION": "verify", "RUNNER_TEMP": "/tmp",
               activation.bootstrap.IDENTITY_ENV: json.dumps({"workerId": IDENTITY.worker_id, "workerCreatedOn": CREATED}),
               activation.RELEASE_ENV: json.dumps(RELEASE), activation.ACTIVATION_ENV: json.dumps(ACTIVATION),
               activation.CONTAINER_ENV: json.dumps(CONTAINER), activation.WORKFLOW_ENV: json.dumps(WORKFLOW_PIN)}
        with patch.dict(os.environ, env, clear=True), patch.object(activation.publication, "_verified_input", return_value=(Path("unused"), EVIDENCE)), patch.object(
                activation.publication, "_guard_main") as guard, patch.object(activation, "ProviderAPI") as api, patch.object(
                activation, "_run", return_value={"status": "ready-to-smoke"}) as run:
            result = activation.activate()
            self.assertEqual(result, {**EVIDENCE, "status": "ready-to-smoke"})
            self.assertEqual(run.call_args.args[:5], (api.return_value, "verify", RELEASE, PINS, ""))
            guard.assert_called_once_with(EVIDENCE)


class BindingProofTests(unittest.TestCase):
    def setUp(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.proof_file = Path(directory.name) / activation.BINDING_PROOF_FILE
        self.output = Path(directory.name) / "github-output"
        self.output.write_text("previous=value\n", encoding="ascii")
        self.env = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": activation.github.REPOSITORY,
                    "GITHUB_REPOSITORY_ID": str(activation.github.REPOSITORY_ID), "GITHUB_REF": activation.github.MAIN_REF,
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": REVISION, "GITHUB_WORKFLOW_SHA": REVISION,
                    "GITHUB_WORKFLOW_REF": f"{activation.github.REPOSITORY}/{activation.WORKFLOW_PATH}@{activation.github.MAIN_REF}",
                    "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_OUTPUT": str(self.output),
                    "RUNNER_TEMP": directory.name, "RUNNER_ENVIRONMENT": "github-hosted",
                    "SUBS_BOT_PROVIDER_ACTIVATION_OPERATION": "verify", "SUBS_BOT_PROVIDER_ISOLATED_REVISION": ISOLATED}
        self.verification = {
            "status": "complete", "publicDenied": True, "stopped": True,
            "workerIdentitySha256": IDENTITY.fingerprint(), "versionSha256": activation._hash(VERSION),
            "activationIdentitySha256": activation._fingerprint(ACTIVATION),
            "containerIdentitySha256": activation._fingerprint(CONTAINER),
            "workflowIdentitySha256": activation._fingerprint(WORKFLOW_PIN), "actorSha256": activation._hash(ACTOR),
            "healthSha256": HEALTH_PROOF["sha256"], "healthBytes": len(HEALTH),
            "approvedDnsFamilies": [4, 6], "blockedPrivateTargets": 3,
        }
        self.manifest = {"version": 1, "accountSha256": activation.publication.TARGET_ACCOUNT_SHA256,
                         "providerBuild": EVIDENCE, "verification": self.verification,
                         "activation": {"runId": "100", "runAttempt": "2", "isolatedRevision": ISOLATED}}

    def verify(self, raw, **overrides):
        return activation.parse_binding_proof(raw, **{"revision": REVISION, "run_id": "100", "run_attempt": "2", **overrides})

    def test_completed_verification_writes_only_the_canonical_redacted_proof_and_signal(self):
        with patch.dict(os.environ, self.env, clear=True), patch.object(
                activation, "activate", return_value={**EVIDENCE, **self.verification}), patch("builtins.print"):
            activation.main()
            with self.assertRaises(FileExistsError):
                activation.main()
        raw = self.proof_file.read_bytes()
        self.assertEqual(self.verify(raw), self.manifest)
        self.assertEqual(raw, (json.dumps(self.manifest, separators=(",", ":"), sort_keys=True) + "\n").encode("ascii"))
        self.assertEqual(self.proof_file.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.output.read_bytes(), b"previous=value\nbinding_proof=true\n")
        for private_value in (ACCOUNT, IDENTITY.worker_id, VERSION, DEPLOYMENT, NAMESPACE, WORKFLOW, ACTOR, "https://"):
            self.assertNotIn(private_value.encode("ascii"), raw)

    def test_partial_results_never_write_a_proof_and_complete_requires_every_fact(self):
        with patch.dict(os.environ, self.env, clear=True):
            context = activation._binding_proof_context()
            for status in ("staged", "active-awaiting-container", "ready-to-smoke", "smoke-running"):
                activation._write_binding_proof({**EVIDENCE, "status": status}, *context)
            for change in ({"publicDenied": False}, {"stopped": 1}, {"actorSha256": None}, {"url": "synthetic-private"}):
                with self.subTest(change=change), self.assertRaises(activation.ActivationError) as error:
                    activation._write_binding_proof({**EVIDENCE, **self.verification, **change}, *context)
                self.assertNotIn("synthetic-private", str(error.exception))
        self.assertFalse(self.proof_file.exists())
        self.assertEqual(self.output.read_bytes(), b"previous=value\n")

    def test_invalid_hosted_workflow_provenance_rejects_before_activation(self):
        for change in ({"GITHUB_WORKFLOW_REF": "other"}, {"GITHUB_WORKFLOW_SHA": ISOLATED}, {"GITHUB_RUN_ID": "01"},
                       {"GITHUB_REPOSITORY_ID": "42"}, {"GITHUB_EVENT_NAME": "push"}, {"RUNNER_ENVIRONMENT": "self-hosted"}):
            with self.subTest(change=change), patch.dict(os.environ, {**self.env, **change}, clear=True), patch.object(activation, "activate") as activate:
                with self.assertRaises(activation.ActivationError):
                    activation.main()
                activate.assert_not_called()

    def test_parser_requires_exact_run_metadata_and_a_closed_bounded_schema(self):
        encode = activation._proof_bytes
        for override in ({"run_id": "101"}, {"run_attempt": "1"}, {"revision": ISOLATED}):
            with self.subTest(override=override), self.assertRaises(activation.ActivationError):
                self.verify(encode(self.manifest), **override)
        for change in ({"version": True}, {"accountSha256": "a" * 64}, {"versionId": VERSION},
                       {"providerBuild": {**EVIDENCE, "compatibilityDate": "2026-99-99"}},
                       {"providerBuild": {**EVIDENCE, "archiveSha256": "synthetic-private"}},
                       {"verification": {**self.verification, "healthBytes": True}},
                       {"verification": {**self.verification, "approvedDnsFamilies": [4.0, 6]}},
                       {"verification": {**self.verification, "approvedDnsFamilies": [6, 4]}}):
            with self.subTest(change=change), self.assertRaises(activation.ActivationError):
                self.verify(encode({**self.manifest, **change}))
        for malformed in (encode(self.manifest)[:-1], b'{"version":1,"version":1}', b" " * (activation.MAX_BINDING_PROOF + 1)):
            with self.assertRaises(ValueError):
                self.verify(malformed)

    def test_continuation_proof_authenticates_current_run_and_unchanged_historical_release(self):
        env = {**self.env, "SUBS_BOT_PROVIDER_ISOLATED_REVISION": HISTORICAL["revision"]}
        with patch.dict(os.environ, env, clear=True):
            activation._write_binding_proof({**HISTORICAL, **self.verification}, *activation._binding_proof_context())
        actual = self.verify(self.proof_file.read_bytes())
        self.assertEqual(actual, {**self.manifest, "version": 2, "providerBuild": HISTORICAL,
                                 "activation": {**self.manifest["activation"], "revision": REVISION,
                                                "isolatedRevision": HISTORICAL["revision"]}})
        for field, value in (("revision", ISOLATED), ("isolatedRevision", ISOLATED)):
            invalid = {**actual, "activation": {**actual["activation"], field: value}}
            with self.subTest(field=field), self.assertRaises(activation.ActivationError):
                self.verify(activation._proof_bytes(invalid))
        for field, value in (("revision", REVISION), ("runId", "13")):
            invalid = {**actual, "providerBuild": {**HISTORICAL, field: value}}
            with self.subTest(field=field), self.assertRaises(activation.ActivationError):
                self.verify(activation._proof_bytes(invalid))


class ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_REPOSITORY": activation.github.REPOSITORY, "GITHUB_REF": activation.github.MAIN_REF,
                    "GITHUB_SHA": REVISION, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
                    "SUBS_BOT_PROVIDER_CI_RUN_ID": HISTORICAL["runId"], "RUNNER_TEMP": "/tmp", "GH_TOKEN": "synthetic-token",
                    "SUBS_BOT_PROVIDER_RELEASE_SELECTION": activation.HISTORICAL_SELECTION,
                    "SUBS_BOT_PROVIDER_ACTIVATION_OPERATION": "provision-container",
                    activation.bootstrap.IDENTITY_ENV: json.dumps({"workerId": IDENTITY.worker_id, "workerCreatedOn": CREATED}),
                    activation.RELEASE_ENV: json.dumps({**HISTORICAL, "versionId": VERSION}),
                    activation.ACTIVATION_ENV: json.dumps(ACTIVATION)}
        self.compare = {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                        "base_commit": {"sha": HISTORICAL["revision"]}, "merge_base_commit": {"sha": HISTORICAL["revision"]}}

    def test_fixed_github_compare_requires_an_exact_ancestor(self):
        check = activation.require_historical_provider_ancestor
        with patch.object(activation.github, "_get_json", return_value=self.compare) as compare:
            check(HISTORICAL["revision"], REVISION, "synthetic-token")
            compare.assert_called_once_with(f"/compare/{HISTORICAL['revision']}...{REVISION}?per_page=1", "synthetic-token")
            for key, value in (("status", "diverged"), ("ahead_by", True), ("behind_by", False), ("behind_by", 1),
                               ("merge_base_commit", {"sha": ISOLATED}), ("base_commit", None)):
                compare.return_value = {**self.compare, key: value}
                with self.subTest(key=key, value=value), self.assertRaises(activation.ActivationError):
                    check(HISTORICAL["revision"], REVISION, "synthetic-token")

    def test_historical_selection_cannot_activate_or_select_another_build_or_smoke_target(self):
        for change in ({"SUBS_BOT_PROVIDER_ACTIVATION_OPERATION": "activate"}, {"SUBS_BOT_PROVIDER_CI_RUN_ID": "11"},
                       {"SUBS_BOT_PROVIDER_RELEASE_SELECTION": "foreign"}, {"GITHUB_SHA": HISTORICAL["revision"]},
                       {"SUBS_BOT_PROVIDER_ISOLATED_REVISION": ISOLATED}, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.subTest(change=change), patch.dict(os.environ, {**self.env, **change}, clear=True), patch.object(
                    activation.github, "_get_json") as request:
                with self.assertRaises(activation.ActivationError):
                    activation.prepare()
                with self.assertRaises(activation.ActivationError):
                    activation.activate()
                request.assert_not_called()

    def test_continuation_guard_uses_historical_artifact_and_current_main(self):
        provenance = activation.publication.provenance
        artifact = (HISTORICAL["runAttempt"], HISTORICAL["artifactId"], HISTORICAL["archiveSha256"])
        with patch.dict(os.environ, self.env, clear=True), patch.object(
                activation.github, "_get_json", return_value=self.compare), patch.object(
                activation.github, "require_current_main") as current, patch.object(
                provenance, "_select_artifact", return_value=artifact) as select, patch.object(
                provenance, "prepare", return_value=HISTORICAL) as prepare, patch.object(
                activation.publication, "_verified_input", return_value=(Path("unused"), HISTORICAL)) as read, patch.object(
                activation, "ProviderAPI") as api, patch.object(
                activation, "_run", return_value={"status": "container-awaiting-workflow"}) as run:
            self.assertEqual(activation.prepare(), HISTORICAL)
            prepare.assert_called_once_with(provider_revision=HISTORICAL["revision"])
            self.assertEqual(activation.activate()["revision"], HISTORICAL["revision"])
            read.assert_called_once_with(Path("/tmp"), HISTORICAL["revision"], HISTORICAL["runId"])
            select.assert_called_once_with(HISTORICAL["runId"], HISTORICAL["revision"], "synthetic-token")
            current.assert_called_once_with(REVISION)
            self.assertEqual(run.call_args.args[:5], (api.return_value, "provision-container",
                             {**HISTORICAL, "versionId": VERSION}, {**NO_PINS, "activation": ACTIVATION}, ""))
            api.reset_mock()
            with patch.dict(os.environ, {activation.ACTIVATION_ENV: ""}), self.assertRaises(activation.ActivationError):
                activation.activate()
            api.assert_not_called()
            select.return_value = ("2", *artifact[1:])
            with self.assertRaises(activation.ActivationError):
                activation.activate()
            api.assert_not_called()


if __name__ == "__main__":
    unittest.main()

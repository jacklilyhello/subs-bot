"""Hosted-only tests for the explicit ProviderFetch control path and refusal boundaries."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control

ACCOUNT = "9431815bdb8beb2272f6668e06b7d3be"
REVISION = "b" * 40
WORKER_ID = "c" * 32
VERSION = "11111111-2222-3333-4444-555555555555"
DEPLOYMENT = "22222222-3333-4444-5555-666666666666"
NS = "d" * 32
STAMP = "2026-11-16T00:00:00.123Z"
BUILD = {"revision": REVISION, "runId": "10", "runAttempt": "1", "artifactId": "20", "archiveSha256": "e" * 64,
         "compatibilityDate": control.provider.COMPATIBILITY, "workerSha256": "f" * 64,
         "ociArchiveSha256": "1" * 64, "ociManifestSha256": "2" * 64, "ociConfigSha256": "3" * 64}


def config(active=False):
    return {"version": 1, "environment": "rehearsal", "accountId": ACCOUNT,
            "service": "subs-bot-provider-fetch-control-drill-01",
            "workersDevOrigin": "https://subs-bot-provider-fetch-control-drill-01.fixture.workers.dev",
            "worker": {"workerId": WORKER_ID, "workerCreatedOn": STAMP}, "build": dict(BUILD), "versionId": VERSION,
            "activation": {"deploymentId": DEPLOYMENT, "namespaceId": NS} if active else None,
            "container": {"applicationId": NS, "createdAt": STAMP} if active else None,
            "workflow": {"workflowId": VERSION, "versionId": DEPLOYMENT, "createdOn": STAMP} if active else None,
            "smoke": {"healthUrl": "https://subs-bot-cf-control-drill-01.fixture.workers.dev/health", "healthRevision": REVISION,
                      "healthSha256": "4" * 64, "healthBytes": 87}, "caller": None}


def state():
    return {"activation": None, "container": None, "workflow": None, "instance": None}


def worker_profile(value):
    return {"id": value["worker"]["workerId"], "created_on": STAMP, "name": value["service"],
            "tags": [control.TAGS[value["environment"]]], "deployed_on": None,
            "subdomain": {"enabled": False, "previews_enabled": False}, "logpush": False,
            "tail_consumers": [],
            "observability": deepcopy(control.bootstrap.OBSERVABILITY_OFF),
            "references": {key: [] for key in control.bootstrap.REFERENCE_FIELDS}}


class TargetTests(unittest.TestCase):
    def test_read_endpoint_family_is_fixed_and_never_contains_resource_path(self):
        for path, container, expected in (("/workers/workers/private-id/versions?page=1", False, "worker-versions"),
                                           ("/workers/durable_objects/namespaces?page=1", False, "namespace-inventory"),
                                           ("/workflows/private-name", False, "workflow"),
                                           ("/containers/applications/private-id", True, "container-detail")):
            self.assertEqual(control.read_endpoint_family(path, container=container), expected)

    def test_production_and_rehearsal_are_separate(self):
        value = config()
        self.assertEqual(control.validate_config(value), value)
        value["environment"] = "production"
        with self.assertRaises(control.ProviderError):
            control.validate_config(value)
        value["service"] = control.SERVICES["production"]
        value["workersDevOrigin"] = "https://subs-bot-provider-fetch-prod-01.fixture.workers.dev"
        self.assertEqual(control.validate_config(value), value)

    def test_missing_unknown_and_legacy_dev_configuration_is_refused(self):
        for change in ({"service": "subs-bot-provider-fetch-dev-01"}, {"accountId": ""}, {"environment": "dev"},
                       {"version": True}, {"worker": {"workerId": WORKER_ID}}, {"unknown": True},
                       {"activation": {"deploymentId": DEPLOYMENT, "namespaceId": NS}, "versionId": None}):
            with self.subTest(change=change), self.assertRaises((control.ProviderError, control.bootstrap.BootstrapError)):
                control.validate_config({**config(), **change})
        value = config()
        del value["worker"]
        with self.assertRaises(control.ProviderError):
            control.validate_config(value)

    def test_binding_metadata_contains_explicit_account_and_service(self):
        value = config()
        metadata = control.metadata(value)
        pin = next(row for row in metadata["bindings"] if row["name"] == "PROVIDER_TARGET_JSON")
        self.assertEqual(json.loads(pin["text"]), {key: value[key] for key in ("environment", "accountId", "service")})
        self.assertEqual(metadata["containers"][0]["images"]["provider"], control.image_reference(value))
        self.assertNotIn("fetch-dev-01", json.dumps(metadata))

    def test_approval_digest_binds_each_configuration_field_and_operation(self):
        first = control.digest({"operation": "activate", "target": config()})
        changed = config()
        changed["accountId"] = "5" * 32
        self.assertNotEqual(first, control.digest({"operation": "activate", "target": changed}))
        self.assertNotEqual(first, control.digest({"operation": "stage", "target": config()}))

    def test_upgrade_has_explicit_source_chain_and_no_bound_caller(self):
        previous = config(active=True)
        current = config()
        current.update({"versionId": None, "container": previous["container"], "workflow": None, "previous": previous})
        current["build"]["revision"] = "7" * 40
        self.assertEqual(control.validate_config(current), current)
        self.assertEqual(len(control.releases(current)), 2)
        # Registering the first application caller after an unbound upgrade is
        # legitimate; the operation-time upgrade guard still rejects that caller.
        current["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        self.assertEqual(control.validate_config(current), current)
        for target in (current, previous):
            target["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        with self.assertRaises(control.ProviderError):
            control.validate_config(current)

    def test_profile_rejects_unknown_ownership_and_public_access(self):
        value = config()
        identity = control.bootstrap.Identity(WORKER_ID, STAMP)
        control.verify_profile(worker_profile(value), value, identity, False)
        for key, change in (("tags", ["other-project"]), ("id", "5" * 32),
                            ("subdomain", {"enabled": True, "previews_enabled": False})):
            observed = worker_profile(value)
            observed[key] = change
            with self.subTest(key=key), self.assertRaises(control.ProviderError):
                control.verify_profile(observed, value, identity, False)

    def test_duplicate_json_keys_refused(self):
        raw = json.dumps(config()).replace('"version": 1', '"version": 1, "version": 1')
        with self.assertRaises(control.github.ArtifactError):
            control.read_config(raw)


class OperationTests(unittest.TestCase):
    def setUp(self):
        self.api = Mock()
        self.api.config = config()
        self.api.actors.return_value = []
        self.api.instances.return_value = []
        self.image, self.guard = Mock(), Mock()

    def run_operation(self, operation):
        return control.run_operation(self.api, operation, b"fixture module", self.image, self.guard)

    def test_verify_has_no_mutation(self):
        with patch.object(control, "observe", return_value=state()):
            self.assertEqual(self.run_operation("verify"), state())
        self.api.deploy.assert_not_called()
        self.api.upload.assert_not_called()
        self.image.prepare.assert_not_called()

    def test_stage_uses_new_control_and_verifies_observed_candidate(self):
        self.api.config["versionId"] = None
        self.api.upload.return_value = VERSION
        with patch.object(control, "observe", return_value=state()) as observation:
            result = self.run_operation("stage")
        self.image.verify.assert_called_once()
        self.image.prepare.assert_called_once_with(self.guard)
        self.api.upload.assert_called_once_with(b"fixture module")
        self.assertEqual(result["versionId"], VERSION)
        self.assertGreaterEqual(observation.call_count, 4)

    def test_concurrent_target_change_stops_before_mutation(self):
        changed = {**state(), "activation": {"deploymentId": DEPLOYMENT, "namespaceId": NS}}
        with patch.object(control, "observe", side_effect=[state(), changed]), self.assertRaises(control.ProviderError):
            self.run_operation("activate")
        self.api.deploy.assert_not_called()

    def test_ambiguous_stage_is_never_retried_or_wrapped_as_success(self):
        self.api.config["versionId"] = None
        self.api.upload.side_effect = control.ProviderError(control.UNCERTAIN)
        with patch.object(control, "observe", return_value=state()), self.assertRaises(control.ProviderError):
            self.run_operation("stage")
        self.assertEqual(self.api.upload.call_count, 1)

    def test_activation_repeat_is_refused(self):
        active = {**state(), "activation": {"deploymentId": DEPLOYMENT, "namespaceId": NS}}
        with patch.object(control, "observe", return_value=active), self.assertRaises(control.ProviderError):
            self.run_operation("activate")
        self.api.deploy.assert_not_called()

    def test_empty_post_activation_does_not_report_success(self):
        with patch.object(control, "observe", return_value=state()), self.assertRaises(control.ProviderError):
            self.run_operation("activate")
        self.api.deploy.assert_called_once()

    def test_container_requires_pinned_activation_and_empty_actor_inventory(self):
        with patch.object(control, "observe", return_value=state()), self.assertRaises(control.ProviderError):
            self.run_operation("provision-container")
        self.api.create_container.assert_not_called()
        self.api.config["activation"] = {"deploymentId": DEPLOYMENT, "namespaceId": NS}
        self.api.actors.return_value = [{"id": "unknown-existing-object"}]
        with patch.object(control, "observe", return_value=state()), self.assertRaises(control.ProviderError):
            self.run_operation("provision-container")
        self.api.create_container.assert_not_called()

    def test_failed_smoke_is_never_accepted_as_proof(self):
        self.api.config = config(active=True)
        observed = {"instance": {"status": "complete", "success": False}}
        with self.assertRaises(control.ProviderError):
            control.verify_smoke(self.api, observed)
        self.api.stopped.assert_not_called()

    def test_staged_unbound_release_can_be_upgraded_without_deleting_old_version(self):
        previous = config()
        self.api.config = config()
        self.api.config.update({"versionId": None, "previous": previous})
        self.api.config["build"]["revision"] = "7" * 40
        self.api.by_name.return_value = {"references": {"workers": []}}
        self.api.worker.by_id.return_value = {"references": {"workers": []}}
        self.api.upload.return_value = DEPLOYMENT
        with patch.object(control, "observe", return_value=state()):
            result = self.run_operation("stage")
        self.assertEqual(result["versionId"], DEPLOYMENT)
        self.assertEqual(self.api.config["previous"], previous)
        self.api.upload.assert_called_once()

    def test_unbound_upgrade_refuses_an_actual_caller_even_if_contract_says_none(self):
        self.api.config = {**config(), "previous": config()}
        self.api.config["build"]["revision"] = "7" * 40
        self.api.config["versionId"] = None
        self.api.by_name.return_value = {"references": {"workers": [{"id": "5" * 32, "name": "unknown-caller"}]}}
        with patch.object(control, "observe", return_value=state()), self.assertRaises(control.ProviderError):
            self.run_operation("stage")
        self.api.upload.assert_not_called()

    def test_completed_smoke_requires_exact_output_and_stopped_container(self):
        value = config(active=True)
        self.api.config = value
        instance = {"status": "complete", "success": True, "versionId": value["workflow"]["versionId"],
                    "params": control.smoke_params(value), "trigger": {"source": "api"}, "schedule": None,
                    "start": STAMP, "end": STAMP, "error": None,
                    "output": {"ok": True, "stopped": True, "revision": REVISION, "imageSha256": BUILD["ociManifestSha256"],
                               **{key: value["smoke"][key] for key in ("healthRevision", "healthSha256", "healthBytes")}, "blockedPrivateTargets": 3, "rpcVerified": True}}
        self.api.stopped.return_value = "6" * 64
        self.assertEqual(control.verify_smoke(self.api, {"instance": instance}), "6" * 64)
        bad = deepcopy(instance)
        bad["output"]["healthSha256"] = "9" * 64
        with self.assertRaises(control.ProviderError):
            control.verify_smoke(self.api, {"instance": bad})


class ContextTests(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_SHA": REVISION, "GITHUB_REPOSITORY": control.github.REPOSITORY,
                    "GITHUB_REF": control.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_WORKFLOW_SHA": REVISION,
                    "GITHUB_WORKFLOW_REF": f"{control.github.REPOSITORY}/{control.WORKFLOW_PATH}@{control.github.MAIN_REF}",
                    "GITHUB_RUN_ATTEMPT": "1", "SUBS_BOT_PROVIDER_CONTROL_ENVIRONMENT": "rehearsal"}

    def test_only_hosted_exact_main_can_operate(self):
        with patch.dict(os.environ, self.env, clear=True):
            control.request_context("verify", config())
        for key, replacement in (("RUNNER_ENVIRONMENT", "self-hosted"), ("GITHUB_WORKFLOW_SHA", "9" * 40),
                                 ("SUBS_BOT_PROVIDER_CONTROL_ENVIRONMENT", "production")):
            with patch.dict(os.environ, {**self.env, key: replacement}, clear=True), self.assertRaises(control.ProviderError):
                control.request_context("verify", config())

    def test_mutation_requires_exact_approval_and_first_attempt(self):
        with patch.dict(os.environ, self.env, clear=True), self.assertRaises(control.ProviderError):
            control.request_context("create", config())
        env = {**self.env, "SUBS_BOT_PROVIDER_CONTROL_APPROVAL": control.digest({"operation": "create", "target": config()})}
        with patch.dict(os.environ, env, clear=True):
            control.request_context("create", config())
        with patch.dict(os.environ, {**env, "GITHUB_RUN_ATTEMPT": "2"}, clear=True), self.assertRaises(control.ProviderError):
            control.request_context("create", config())


class FrozenSourceTests(unittest.TestCase):
    def test_current_controller_verifies_frozen_main_ancestor_and_exact_archive(self):
        current = "9" * 40
        comparison = {"status": "ahead", "ahead_by": 3, "behind_by": 0,
                      "base_commit": {"sha": REVISION}, "merge_base_commit": {"sha": REVISION}}
        selection = (BUILD["runAttempt"], BUILD["artifactId"], BUILD["archiveSha256"])
        with patch.dict(os.environ, {"GITHUB_SHA": current}), patch.object(control.github, "require_current_main") as guard, \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=comparison), \
                patch.object(control.provenance, "_select_artifact", return_value=selection):
            control.guard_sources(config())
        self.assertEqual(guard.call_count, 2)

    def test_frozen_nonancestor_or_replaced_ci_attempt_is_refused(self):
        for comparison, selected in (({"status": "diverged"}, ("1", "20", BUILD["archiveSha256"])),
                                     ({"status": "ahead", "ahead_by": 1, "behind_by": 0,
                                       "base_commit": {"sha": REVISION}, "merge_base_commit": {"sha": REVISION}},
                                      ("2", "20", BUILD["archiveSha256"]))):
            with patch.dict(os.environ, {"GITHUB_SHA": "9" * 40}), patch.object(control.github, "require_current_main"), \
                    patch.object(control.github, "_github_token", return_value="synthetic"), \
                    patch.object(control.github, "_get_json", return_value=comparison), \
                    patch.object(control.provenance, "_select_artifact", return_value=selected), self.assertRaises(control.ProviderError):
                control.guard_sources(config())


class WriteScopeTests(unittest.TestCase):
    def test_wrong_worker_container_and_workflow_fail_before_transport(self):
        api = control.ProviderAPI(config(active=True), "synthetic-worker-token", "synthetic-container-token")
        cases = [("/workers/scripts/other-project/deployments", False, "POST", {"versions": []}),
                 ("/containers/applications", True, "POST", {"name": "other-project", "durable_objects": {"namespace_id": NS}}),
                 ("/workflows/other-project", False, "PUT", {"script_name": "other-project"}),
                 (api.workflow_path + "/instances", False, "POST", {"instance_id": "unknown", "params": {}})]
        for path, container, method, body in cases:
            with patch.object(control.legacy.ProviderAPI, "_request") as transport, self.assertRaises(control.ProviderError):
                api._request(path, container=container, method=method, body=body)
            transport.assert_not_called()


class DependencyCallerTests(unittest.TestCase):
    def verify(self, value, callers, **options):
        api = control.ProviderAPI(value, "synthetic-worker-token", "synthetic-container-token")
        observed = worker_profile(value)
        observed["deployed_on"] = STAMP
        observed["references"]["workers"] = callers
        with patch.object(control, "observe", return_value={"syntheticState": True}), \
                patch.object(api, "by_name", return_value=observed), patch.object(api.worker, "by_id", return_value=observed):
            return control.verify_provider_dependency(api, value, **options)

    def test_default_requires_explicit_exact_bound_caller(self):
        value = config(active=True)
        with self.assertRaises(control.ProviderError):
            self.verify(value, [])
        value["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        with self.assertRaises(control.ProviderError):
            self.verify(value, [])
        self.assertEqual(self.verify(value, [value["caller"]])["callerState"], "bound")

    def test_only_explicit_prebind_check_allows_empty_references(self):
        value = config(active=True)
        self.assertEqual(self.verify(value, [], allow_unbound_caller=True)["callerState"], "unbound")
        value["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        self.assertEqual(self.verify(value, [], allow_unbound_caller=True)["callerState"], "unbound")
        self.assertEqual(self.verify(value, [value["caller"]], allow_unbound_caller=True)["callerState"], "bound")

    def test_unknown_caller_is_refused_even_for_prebind(self):
        value = config(active=True)
        value["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        with self.assertRaises(control.ProviderError):
            self.verify(value, [{"id": "6" * 32, "name": "other-project"}], allow_unbound_caller=True)


class ReadDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.api = control.ProviderAPI(config(), "synthetic-worker-credential", "synthetic-container-credential")
        self.path = "/workers/workers/" + self.api.service
        self.private = "synthetic-private-response-content-never-log"

    def read(self, status, envelope, **options):
        with patch.object(control.publication, "_response", return_value=(status, {"Private-Header": self.private}, json.dumps(envelope).encode())):
            return self.api._request(self.path, **options)

    def test_success_and_exact_missing_name_semantics_are_preserved(self):
        envelope = {"success": True, "result": {"id": WORKER_ID}, "errors": []}
        self.assertEqual(self.read(200, envelope), envelope)
        missing = {"success": False, "result": None, "errors": [{"code": 10007, "message": self.private}]}
        self.assertIsNone(self.read(404, missing, absent=10007))
        with self.assertRaises(control.ProviderError):
            self.read(404, missing)
        self.assertEqual(self.api._writes, 0)

    def test_http_and_numeric_codes_are_visible_without_body_headers_or_credentials(self):
        for status, code in ((401, 10000), (403, 9109), (500, 10001)):
            envelope = {"success": False, "errors": [{"code": code, "message": self.private,
                         "source": {"pointer": self.private}}], "message": self.private, "result": {"credential": self.private}}
            with self.subTest(status=status), self.assertRaises(control.ProviderError) as raised:
                self.read(status, envelope, absent=10007)
            rendered = str(raised.exception)
            self.assertIn(f'"httpStatus":{status}', rendered)
            self.assertIn(f'"cloudflareCodes":[{code}]', rendered)
            for private in (self.private, "Private-Header", "synthetic-worker-credential", "synthetic-container-credential"):
                self.assertNotIn(private, rendered)

    def test_other_not_found_shapes_and_denials_never_become_absence(self):
        envelopes = [(404, {"success": False, "result": None, "errors": [{"code": 10000}]}),
                     (403, {"success": False, "result": None, "errors": [{"code": 10007}]}),
                     (404, {"success": True, "result": None, "errors": [{"code": 10007}]}),
                     (404, {"success": False, "result": {}, "errors": [{"code": 10007}]}),
                     (404, {"success": False, "result": None, "errors": [{"code": 10007}, {"code": 10007}]})]
        for status, envelope in envelopes:
            with self.subTest(status=status, envelope=envelope), self.assertRaises(control.ProviderError):
                self.read(status, envelope, absent=10007)

    def test_malformed_and_transport_errors_do_not_echo_private_data(self):
        with patch.object(control.publication, "_response", return_value=(403, {}, self.private.encode())), self.assertRaises(control.ProviderError) as raised:
            self.api._request(self.path)
        self.assertIn('"phase":"response-json"', str(raised.exception))
        self.assertIn('"httpStatus":403', str(raised.exception))
        self.assertNotIn(self.private, str(raised.exception))
        with patch.object(control.publication, "_response", side_effect=control.publication.PublicationError(self.private)), self.assertRaises(control.ProviderError) as raised:
            self.api._request(self.path)
        self.assertIn('"phase":"transport"', str(raised.exception))
        self.assertIn('"httpStatus":null', str(raised.exception))
        self.assertNotIn(self.private, str(raised.exception))

    def test_only_bounded_numeric_codes_are_reported(self):
        envelope = {"errors": [{"code": self.private}, {"code": True}, {"code": 999}, {"code": 1000000},
                               {"code": 10007}, {"code": 10007}, {"code": 9109}, {"code": 10000}, {"code": 99999}]}
        rendered = str(control.read_failure("response-envelope", 403, envelope))
        self.assertIn('"cloudflareCodes":[9109,10000,10007]', rendered)
        self.assertNotIn("99999", rendered)
        self.assertNotIn(self.private, rendered)


class UploadedVersionVisibilityTests(unittest.TestCase):
    def setUp(self):
        old = config()
        current = config()
        current["build"]["revision"] = "7" * 40
        current.update({"versionId": DEPLOYMENT, "previous": old})
        self.api = control.ProviderAPI(current, "synthetic-worker-token", "synthetic-container-token")

    def envelope(self, ids):
        return {"result": [{"id": value} for value in ids], "result_info": {"page": 1, "per_page": 10,
                "count": len(ids), "total_count": len(ids), "total_pages": 1}}

    def test_just_uploaded_candidate_can_settle_using_only_bounded_gets(self):
        with patch.object(self.api, "_request", side_effect=[self.envelope([VERSION]), self.envelope([DEPLOYMENT, VERSION])]) as read, \
                patch.object(control, "sleep") as wait, patch.object(self.api, "upload") as upload:
            self.api.wait_uploaded_version(DEPLOYMENT)
        self.assertEqual(read.call_count, 2)
        wait.assert_called_once_with(1)
        upload.assert_not_called()

    def test_generic_inventory_remains_strict_and_never_settles(self):
        with patch.object(self.api, "_request", return_value=self.envelope([VERSION])) as read, \
                patch.object(control, "sleep") as wait, self.assertRaises(control.ProviderError):
            self.api.versions()
        self.assertEqual(read.call_count, 1)
        wait.assert_not_called()

    def test_unknown_duplicate_missing_previous_or_incomplete_page_reject_immediately(self):
        for value in (self.envelope([DEPLOYMENT, VERSION, "33333333-4444-5555-6666-777777777777"]),
                      self.envelope([VERSION, VERSION]), self.envelope([DEPLOYMENT]),
                      {**self.envelope([VERSION]), "result_info": {"page": 1, "count": 1, "total_count": 2}}):
            with self.subTest(value=value), patch.object(self.api, "_request", return_value=value) as read, \
                    patch.object(control, "sleep") as wait, self.assertRaises(ValueError):
                self.api.wait_uploaded_version(DEPLOYMENT)
            self.assertEqual(read.call_count, 1)
            wait.assert_not_called()

    def test_unconfirmed_http_or_never_visible_candidate_cannot_repeat_upload(self):
        with patch.object(self.api, "_request", side_effect=control.ProviderError("read refused")) as read, \
                patch.object(control, "sleep") as wait, self.assertRaises(control.ProviderError):
            self.api.wait_uploaded_version(DEPLOYMENT)
        self.assertEqual(read.call_count, 1)
        wait.assert_not_called()
        with patch.object(self.api, "_request", return_value=self.envelope([VERSION])) as read, \
                patch.object(control, "sleep") as wait, patch.object(self.api, "upload") as upload, \
                self.assertRaises(control.ProviderError):
            self.api.wait_uploaded_version(DEPLOYMENT)
        self.assertEqual(read.call_count, 3)
        self.assertEqual(wait.call_count, 2)
        upload.assert_not_called()


if __name__ == "__main__":
    unittest.main()

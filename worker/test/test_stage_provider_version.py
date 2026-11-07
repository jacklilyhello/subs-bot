"""Synthetic tests for staging one private provider version without activation."""

from base64 import b64encode
from copy import deepcopy
from email import policy
from email.parser import BytesParser
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import stage_provider_version as stage


ACCOUNT = "a" * 32
REVISION = "b" * 40
MANIFEST = "c" * 64
CONFIG = "d" * 64
CANDIDATE = "11111111-2222-3333-4444-555555555555"
FOREIGN = "55555555-4444-3333-2222-111111111111"
IDENTITY = stage.bootstrap.Identity("f" * 32, "2026-11-07T00:00:00.123Z")
IMAGE = f"registry.cloudflare.com/{ACCOUNT}/{stage.provider.SERVICE}@sha256:{MANIFEST}"
MODULE = b'export default {fetch(){return new Response(null,{status:404})}};\n'
MODULE_SHA = sha256(MODULE).hexdigest()
EVIDENCE = {
    "revision": REVISION, "runId": "10", "runAttempt": "1", "artifactId": "20",
    "archiveSha256": "e" * 64, "compatibilityDate": stage.provider.COMPATIBILITY,
    "workerSha256": MODULE_SHA, "ociArchiveSha256": "9" * 64,
    "ociManifestSha256": MANIFEST, "ociConfigSha256": CONFIG,
}


def envelope(result, *, status=200, **extra):
    return status, {}, json.dumps({"success": True, "errors": None, "result": result, **extra}).encode()


def version():
    metadata = deepcopy(stage._metadata(EVIDENCE, IMAGE))
    del metadata["containers"]
    return {
        **metadata, "id": CANDIDATE, "urls": [], "modules": [
            {"name": stage.provider.WORKER, "content_type": stage.MODULE_TYPE,
             "content_base64": b64encode(MODULE).decode("ascii")},
        ],
    }


class StageTests(unittest.TestCase):
    def setUp(self):
        self.versions = Mock(spec=stage.WorkerVersions)
        self.versions.upload.return_value = CANDIDATE
        self.image = Mock(spec=stage.PublishedImage)
        self.image.reference = IMAGE
        self.guard = Mock()

    def run_stage(self, operation="stage"):
        return stage._stage(self.versions, self.image, operation, EVIDENCE, MODULE, self.guard)

    def test_default_preflight_does_no_prepare_or_upload(self):
        self.versions.baseline.return_value = None
        self.assertEqual(self.run_stage("verify"), ("preflight", None))
        self.image.verify.assert_called_once_with()
        self.image.prepare.assert_not_called()
        self.versions.upload.assert_not_called()
        self.versions.verify.assert_not_called()

    def test_stage_prepares_exact_image_and_uploads_once(self):
        self.versions.baseline.side_effect = [None, None, CANDIDATE]
        self.assertEqual(self.run_stage(), ("staged", CANDIDATE))
        self.image.verify.assert_called_once_with()
        self.image.prepare.assert_called_once_with(self.guard)
        metadata = stage._metadata(EVIDENCE, IMAGE)
        self.versions.upload.assert_called_once_with(metadata, MODULE)
        self.versions.verify.assert_called_once_with(CANDIDATE, metadata, MODULE_SHA)
        self.assertEqual(self.guard.call_count, 2)

    def test_existing_candidate_gets_readback_only(self):
        self.versions.baseline.return_value = CANDIDATE
        self.assertEqual(self.run_stage(), ("verified", CANDIDATE))
        self.image.prepare.assert_not_called()
        self.versions.upload.assert_not_called()
        self.versions.verify.assert_called_once_with(CANDIDATE, stage._metadata(EVIDENCE, IMAGE), MODULE_SHA)

    def test_candidate_appearing_after_preparation_is_never_overwritten(self):
        self.versions.baseline.side_effect = [None, CANDIDATE, CANDIDATE]
        self.assertEqual(self.run_stage(), ("verified", CANDIDATE))
        self.versions.upload.assert_not_called()

    def test_ambiguous_upload_checks_inventory_without_retrying(self):
        self.versions.upload.side_effect = stage.StageError(stage.UPLOAD_ERROR)
        self.versions.baseline.side_effect = [None, None, CANDIDATE, CANDIDATE]
        self.assertEqual(self.run_stage(), ("verified", CANDIDATE))
        self.versions.upload.assert_called_once()
        self.versions.verify.assert_called_once()

    def test_ambiguous_and_absent_candidate_fail_without_second_upload(self):
        self.versions.upload.side_effect = stage.StageError(stage.UPLOAD_ERROR)
        self.versions.baseline.return_value = None
        with self.assertRaisesRegex(stage.StageError, "upload was not confirmed"):
            self.run_stage()
        self.versions.upload.assert_called_once()
        self.versions.verify.assert_not_called()

    def test_stale_main_or_failed_image_never_uploads(self):
        self.versions.baseline.return_value = None
        self.guard.side_effect = stage.github.ArtifactError("stale main")
        with self.assertRaises(stage.github.ArtifactError):
            self.run_stage()
        self.versions.upload.assert_not_called()
        self.image.verify.side_effect = stage.StageError("image")
        with self.assertRaisesRegex(stage.StageError, "image"):
            self.run_stage()
        self.versions.upload.assert_not_called()

    def test_final_inventory_drift_refuses_success(self):
        self.versions.baseline.side_effect = [CANDIDATE, FOREIGN]
        with self.assertRaisesRegex(stage.StageError, "changed during verification"):
            self.run_stage()
        self.versions.upload.assert_not_called()

    def test_automatic_stage_rerun_is_refused_before_artifacts_or_network(self):
        env = {"GITHUB_REPOSITORY": stage.github.REPOSITORY, "GITHUB_REF": stage.github.MAIN_REF,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_SHA": REVISION, "GITHUB_RUN_ATTEMPT": "2",
               "SUBS_BOT_PROVIDER_CI_RUN_ID": "10", "RUNNER_TEMP": "/tmp/fake-runner",
               "SUBS_BOT_PROVIDER_STAGE_OPERATION": "stage"}
        with patch.dict(os.environ, env, clear=True), patch.object(stage.publication, "_verified_input") as verify:
            with self.assertRaisesRegex(stage.StageError, "previous staging attempt"):
                stage.stage()
            verify.assert_not_called()


class BoundaryTests(unittest.TestCase):
    def setUp(self):
        pin = patch.object(stage.bootstrap, "TARGET_ACCOUNT_SHA256", sha256(ACCOUNT.encode()).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        self.api = stage.WorkerVersions(ACCOUNT, "synthetic-worker-token", IDENTITY)
        self.metadata = stage._metadata(EVIDENCE, IMAGE)
        self.base = f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/workers"

    def test_upload_wire_is_exact_multipart_and_has_no_activation_request(self):
        with patch.object(stage.publication, "_response", return_value=envelope({"id": CANDIDATE})) as send:
            self.assertEqual(self.api.upload(self.metadata, MODULE), CANDIDATE)
        send.assert_called_once()
        request = send.call_args.args[0]
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.full_url,
                         f"{self.base}/scripts/{stage.provider.SERVICE}/versions?bindings_inherit=strict")
        header = f"Content-Type: {request.get_header('Content-type')}\r\n\r\n".encode()
        parts = list(BytesParser(policy=policy.default).parsebytes(header + request.data).iter_parts())
        self.assertEqual([part.get_param("name", header="content-disposition") for part in parts],
                         ["metadata", stage.provider.WORKER])
        self.assertEqual(json.loads(parts[0].get_payload(decode=True)), self.metadata)
        self.assertEqual(parts[1].get_content_type(), stage.MODULE_TYPE)
        self.assertEqual(parts[1].get_payload(decode=True), MODULE)
        self.assertEqual(self.metadata["containers"][0]["images"], {"provider": IMAGE})
        self.assertNotIn("migrations", self.metadata)
        self.assertNotIn("assets", self.metadata)

    def test_invalid_upload_id_or_api_failure_is_ambiguous_and_redacted(self):
        for reply in (envelope({"id": "wrong"}), (503, {}, b'{"success":false,"errors":[{"message":"secret"}]}')):
            with self.subTest(reply=reply), patch.object(stage.publication, "_response", return_value=reply) as send:
                with self.assertRaisesRegex(stage.StageError, "upload was not confirmed"):
                    self.api.upload(self.metadata, MODULE)
                send.assert_called_once()

    def test_upload_rejection_reports_only_bounded_status_codes_and_known_fields(self):
        secret = "synthetic-private-response"
        errors = [
            {"code": 10021, "message": secret, "documentation_url": f"https://example.invalid/{secret}",
             "source": {"pointer": "/metadata/exports/ProviderContainer/storage", "detail": secret}},
            {"code": 10026, "source": {"pointer": "/containers/0/images/provider"}},
            {"code": 10021, "source": {"pointer": f"/metadata/exports/ProviderContainer/{secret}"}},
            {"code": 87654, "source": {"pointer": f"/metadata/bindings/0/type\n{secret}"}},
            {"code": "10057", "source": {"pointer": "/migrations"}},
            {"code": True},
            {"code": 9999999},
            {"code": 10026},
            {"code": 10057, "source": {"pointer": "/migrations"}},
        ]
        response = json.dumps({"success": False, "errors": errors, "messages": [{"code": 10015, "message": secret}],
                               "result": {"id": secret}}).encode()
        with patch.object(stage.publication, "_response", return_value=(400, {"X-Synthetic": secret}, response)) as send:
            with self.assertRaises(stage.StageError) as failure:
                self.api.upload(self.metadata, MODULE)
        self.assertEqual(str(failure.exception), stage.UPLOAD_ERROR + ' Upload diagnostic '
                         '{"httpStatus":400,"cloudflareCodes":[10021,10026,87654],'
                         '"validationFields":["containers","exports"]}.')
        send.assert_called_once()

    def test_upload_reports_status_without_a_usable_json_body(self):
        with patch.object(stage.publication, "_response", return_value=(502, {}, b"synthetic-private-html")) as send:
            with self.assertRaises(stage.StageError) as failure:
                self.api.upload(self.metadata, MODULE)
        self.assertEqual(str(failure.exception), stage.UPLOAD_ERROR + ' Upload diagnostic {"httpStatus":502}.')
        send.assert_called_once()

    def test_upload_without_a_bounded_response_keeps_the_fixed_ambiguous_error(self):
        with patch.object(stage.publication, "_response",
                          side_effect=stage.publication.PublicationError("synthetic-private-transport")) as send:
            with self.assertRaises(stage.StageError) as failure:
                self.api.upload(self.metadata, MODULE)
        self.assertEqual(str(failure.exception), stage.UPLOAD_ERROR)
        send.assert_called_once()

    def test_beta_module_and_legacy_named_image_are_independent_and_exact(self):
        runtime = {"id": CANDIDATE, "resources": {"script_runtime": {"containers": self.metadata["containers"]}}}
        with patch.object(stage.publication, "_response", side_effect=[envelope(version()), envelope(runtime)]) as read:
            self.api.verify(CANDIDATE, self.metadata, MODULE_SHA)
        requests = [entry.args[0] for entry in read.call_args_list]
        self.assertEqual([request.full_url for request in requests], [
            f"{self.base}/workers/{IDENTITY.worker_id}/versions/{CANDIDATE}?include=modules",
            f"{self.base}/scripts/{stage.provider.SERVICE}/versions/{CANDIDATE}",
        ])
        for wrong in ({"id": CANDIDATE}, {"id": FOREIGN, **{"resources": runtime["resources"]}},
                      {"id": CANDIDATE, "resources": {"script_runtime": {"containers": [
                          {**self.metadata["containers"][0], "images": {"provider": IMAGE.replace(MANIFEST, CONFIG)}},
                      ]}}}):
            with self.subTest(wrong=wrong), patch.object(
                    stage.publication, "_response", side_effect=[envelope(version()), envelope(wrong)]):
                with self.assertRaisesRegex(stage.StageError, "did not match"):
                    self.api.verify(CANDIDATE, self.metadata, MODULE_SHA)

    def test_candidate_rejects_public_urls_changed_module_bindings_or_tag(self):
        changes = [
            {"urls": ["https://example.invalid/"]},
            {"modules": [{**version()["modules"][0], "content_base64": b64encode(MODULE + b" ").decode()}]},
            {"bindings": [*version()["bindings"], {"name": "EXTRA", "type": "secret_text"}]},
            {"annotations": {"workers/tag": "some-other-version"}},
            {"exports": {**version()["exports"], "Foreign": {"type": "worker"}}},
        ]
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaisesRegex(stage.StageError, "did not match"):
                stage._verify_version({**version(), **changed}, CANDIDATE, self.metadata, MODULE_SHA)

    def test_pinned_shell_inventory_refuses_deployment_second_version_or_pagination(self):
        with patch.object(stage.bootstrap, "_verify_profile") as privacy, patch.object(self.api, "_read") as read:
            deploys = {"result": {"deployments": []}, "result_info": {"page": 1, "count": 0, "total_count": 0}}
            read.side_effect = [deploys, {"result": [], "result_info": {"page": 1, "per_page": 2, "count": 0, "total_count": 0}}]
            self.api.worker = Mock()
            self.assertIsNone(self.api.baseline())
            self.assertEqual(privacy.call_count, 2)
            self.assertEqual(read.call_args_list, [
                call(f"/workers/scripts/{stage.provider.SERVICE}/deployments?page=1&per_page=1"),
                call(f"/workers/workers/{IDENTITY.worker_id}/versions?page=1&per_page=2", stage.MAX_VERSION_RESPONSE),
            ])
            for inventory in (
                    [{"result": {"deployments": [{"id": FOREIGN}]}}],
                    [deploys, {"result": [{"id": CANDIDATE}, {"id": FOREIGN}]}],
                    [deploys, {"result": [{"id": CANDIDATE}], "result_info": {"total_count": 2}}],
                    [deploys, {"result": [], "result_info": {"cursor": "has-more"}}],
            ):
                with self.subTest(inventory=inventory):
                    read.side_effect = inventory
                    with self.assertRaisesRegex(stage.StageError, "first-version state"):
                        self.api.baseline()


class ImageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        pin = patch.object(stage.publication, "TARGET_ACCOUNT_SHA256", sha256(ACCOUNT.encode()).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        self.image = stage.PublishedImage(ACCOUNT, "synthetic-container-token", EVIDENCE, Path(directory.name))

    def test_digest_only_registry_proof_mints_pull_only(self):
        credentials = ("synthetic-username", "a.b.c")
        registry = self.image._registry
        with patch.object(registry, "mint", return_value=credentials) as mint, patch.object(
                registry, "manifest", return_value=MANIFEST) as manifest, patch.object(
                stage.publication, "_config", return_value=CONFIG) as config:
            self.image.verify()
        mint.assert_called_once_with()
        manifest.assert_called_once_with("sha256:" + MANIFEST, credentials)
        self.assertEqual(config.call_args.args[1], IMAGE)

    def test_prepare_accepts_only_pending_then_ready_for_same_digest(self):
        guard = Mock()
        with patch.object(stage.publication, "_response", side_effect=[
            envelope({"image": IMAGE, "status": "pending"}, status=202),
            envelope({"image": IMAGE, "status": "ready", "artifact_digest": "sha256:" + "9" * 64}),
        ]) as send, patch.object(stage, "sleep") as wait:
            self.image.prepare(guard)
        guard.assert_called_once()
        wait.assert_called_once_with(4)
        for entry in send.call_args_list:
            request = entry.args[0]
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.full_url, f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/containers/image-preparations")
            self.assertEqual(json.loads(request.data), {"image": IMAGE})

    def test_prepare_rejects_wrong_image_and_terminal_status(self):
        for reply in (envelope({"image": IMAGE.replace(MANIFEST, CONFIG), "status": "ready"}),
                      envelope({"image": IMAGE, "status": "error", "reason": "synthetic provider detail"})):
            with self.subTest(reply=reply), patch.object(stage.publication, "_response", return_value=reply):
                with self.assertRaisesRegex(stage.StageError, "was not ready"):
                    self.image.prepare(Mock())


if __name__ == "__main__":
    unittest.main()

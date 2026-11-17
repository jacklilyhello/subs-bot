"""Hosted checks for isolated content-addressed Provider image publication."""

from hashlib import sha256
from email.message import Message
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_digest_publish as digest_publish
from test_production_provider import config
import test_prepare_provider_artifact as artifact_fixture


class DigestPublishTests(unittest.TestCase):
    def test_preflight_diagnostic_only_reports_bounded_numeric_read_details(self):
        output = io.StringIO()
        error = control.read_failure("response-envelope", 403, {"errors": [{"code": 9109, "message": "private-response"}]})
        def fail():
            raise error
        with redirect_stdout(output), self.assertRaises(control.ProviderError):
            digest_publish.observed_step("provider-state", fail)
        rows = [json.loads(line) for line in output.getvalue().splitlines()]
        self.assertEqual(rows[-1], {"phase": "provider-state", "status": "rejected", "readDiagnostic":
                                  {"phase": "response-envelope", "httpStatus": 403, "cloudflareCodes": [9109]}})
        self.assertNotIn("private-response", output.getvalue())

    def test_preflight_diagnostic_does_not_echo_untrusted_exception_details(self):
        output = io.StringIO()
        def fail():
            raise RuntimeError("private-token-and-path")
        with redirect_stdout(output), self.assertRaises(RuntimeError):
            digest_publish.observed_step("registry-auth", fail)
        self.assertNotIn("private-token-and-path", output.getvalue())
        self.assertEqual(json.loads(output.getvalue().splitlines()[-1]), {"phase": "registry-auth", "status": "rejected"})

    def test_tag_inventory_binds_every_tag_and_manifest_and_rejects_pagination(self):
        registry = Mock()
        registry.repository = "fixture/provider"
        registry._read_authorization = "fixture"
        headers = Message()
        headers["Content-Type"] = control.provider.OCI_MANIFEST
        listing = json.dumps({"name": registry.repository, "tags": ["old", "stable"]}).encode()
        with patch.object(control.publication, "_response", side_effect=[(200, headers, listing),
                (200, headers, b"old manifest"), (200, headers, b"stable manifest")]):
            first = digest_publish.tag_snapshot(registry, "fixture")
        with patch.object(control.publication, "_response", side_effect=[(200, headers, listing),
                (200, headers, b"old manifest"), (200, headers, b"changed manifest")]):
            second = digest_publish.tag_snapshot(registry, "fixture")
        self.assertNotEqual(first, second)
        headers["Link"] = '</v2/fixture/provider/tags/list?n=101&last=stable>; rel="next"'
        with patch.object(control.publication, "_response", return_value=(200, headers, listing)), \
                self.assertRaises(control.ProviderError):
            digest_publish.tag_snapshot(registry, "fixture")
        del headers["Link"]
        with patch.object(control.publication, "_response", return_value=(200, headers, b'{"name":"fixture/provider"}')), \
                self.assertRaises(control.ProviderError):
            digest_publish.tag_snapshot(registry, "fixture")
        headers["Docker-Content-Digest"] = "sha256:" + "0" * 64
        with patch.object(control.publication, "_response", side_effect=[(200, headers, listing), (200, headers, b"old manifest")]), \
                self.assertRaises(control.ProviderError):
            digest_publish.tag_snapshot(registry, "fixture")

    def test_changed_tags_stop_before_digest_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, image, state, refs, intent, env = self.fixture(temporary)
            changed = {**state, "tagsSha256": "5" * 64}
            with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources"), \
                    patch.object(digest_publish, "observe", return_value=changed), \
                    patch.object(control.publication, "_copy_image") as copy, self.assertRaises(control.ProviderError):
                digest_publish.publish_once(target, refs, image, intent, control.digest(intent), "worker", "read", "write")
            copy.assert_not_called()

    def test_independent_readback_verifies_full_oci_archive_and_never_pushes(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, _image, _state, _refs, _intent, env = self.fixture(temporary)
            registry = Mock()
            registry.repository = target["accountId"] + "/" + target["service"]
            registry.manifest.return_value = target["build"]["ociManifestSha256"]
            with patch.dict(os.environ, env, clear=True), patch.object(control, "Registry", return_value=registry), \
                    patch.object(control.publication, "_write_auth", return_value=Path(temporary) / "pull-auth"), \
                    patch.object(digest_publish.subprocess, "run") as copy, \
                    patch.object(control.provider, "verify_image", return_value=(target["build"]["ociManifestSha256"],
                                                                               target["build"]["ociConfigSha256"])) as verify:
                result = digest_publish.verify_remote_closure(target, "read-only")
            args = copy.call_args.args[0]
            self.assertIn("--retry-times=0", args)
            self.assertTrue(any(item.endswith("@sha256:" + target["build"]["ociManifestSha256"]) for item in args))
            self.assertTrue(any(item.startswith("oci-archive:") for item in args))
            self.assertTrue(result["allReferencedBlobsVerified"])
            verify.assert_called_once()

    def test_incomplete_or_changed_oci_closure_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, _image, _state, _refs, _intent, env = self.fixture(temporary)
            registry = Mock()
            registry.repository = target["accountId"] + "/" + target["service"]
            registry.manifest.return_value = target["build"]["ociManifestSha256"]
            with patch.dict(os.environ, env, clear=True), patch.object(control, "Registry", return_value=registry), \
                    patch.object(control.publication, "_write_auth", return_value=Path(temporary) / "pull-auth"), \
                    patch.object(digest_publish.subprocess, "run"), \
                    patch.object(control.provider, "verify_image", return_value=("0" * 64, target["build"]["ociConfigSha256"])), \
                    self.assertRaises(control.ProviderError):
                digest_publish.verify_remote_closure(target, "read-only")

    def test_corrupt_layer_in_downloaded_oci_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, _image, _state, _refs, _intent, env = self.fixture(temporary)
            registry = Mock()
            registry.repository = target["accountId"] + "/" + target["service"]
            registry.manifest.return_value = target["build"]["ociManifestSha256"]
            with patch.object(artifact_fixture, "REVISION", target["build"]["revision"]):
                corrupt = artifact_fixture.oci_fixture(wrong_diff_id=True)
            def download(args, **_kwargs):
                Path(next(value.removeprefix("oci-archive:") for value in args if value.startswith("oci-archive:"))).write_bytes(corrupt)
                return Mock(returncode=0)
            with patch.dict(os.environ, env, clear=True), patch.object(control, "Registry", return_value=registry), \
                    patch.object(control.publication, "_write_auth", return_value=Path(temporary) / "pull-auth"), \
                    patch.object(digest_publish.subprocess, "run", side_effect=download), self.assertRaises(control.ProviderError):
                digest_publish.verify_remote_closure(target, "read-only")

    def fixture(self, root):
        target = config(active=True)
        archive = Path(root) / "image.tar"
        archive.write_bytes(b"fixture-oci-original")
        target["build"]["ociArchiveSha256"] = sha256(archive.read_bytes()).hexdigest()
        state = {"dependencySha256": "1" * 64, "manifestSha256": None, "tagsSha256": "4" * 64}
        refs = [{"fixture": "original archive reference"}]
        with patch.dict(os.environ, {}, clear=True):
            expected = digest_publish.intent(target, refs, state, "101", "b" * 40)
        env = {"RUNNER_TEMP": root, "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40,
               "SUBS_BOT_PROVIDER_DIGEST_APPROVAL": expected["approvalSha256"]}
        return target, archive, state, refs, expected, env

    def test_unconfirmed_intent_stops_before_registry_or_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, image, state, refs, intent, env = self.fixture(temporary)
            with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources") as guard, \
                    patch.object(control, "Registry") as registry, patch.object(control.publication, "_copy_image") as copy, \
                    self.assertRaises(control.ProviderError):
                digest_publish.publish_once(target, refs, image, intent, "0" * 64, "read-worker", "read-registry", "write-registry")
            guard.assert_not_called()
            registry.assert_not_called()
            copy.assert_not_called()

    def test_copy_uses_exact_digest_and_never_a_mutable_tag(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, image, state, refs, intent, env = self.fixture(temporary)
            writer, reader = Mock(), Mock()
            writer.repository = target["accountId"] + "/" + target["service"]
            reader.manifest.side_effect = [None, target["build"]["ociManifestSha256"]]
            with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources"), \
                    patch.object(digest_publish, "observe", return_value=state), patch.object(control, "Registry", side_effect=[writer, reader]), \
                    patch.object(control.publication, "_write_auth", return_value=Path(temporary) / "auth"), \
                    patch.object(control.publication, "_config", return_value=target["build"]["ociConfigSha256"]), \
                    patch.object(control.publication, "_copy_image") as copy:
                result = digest_publish.publish_once(target, refs, image, intent, control.digest(intent), "worker", "read", "write")
            expected = "sha256:" + target["build"]["ociManifestSha256"]
            self.assertEqual(copy.call_count, 1)
            self.assertTrue(copy.call_args.args[2].endswith("@" + expected))
            self.assertEqual(copy.call_args.args[4], expected)
            self.assertEqual(result["status"], "published-digest")

    def test_unknown_copy_result_is_not_retried(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, image, state, refs, intent, env = self.fixture(temporary)
            writer, reader = Mock(), Mock()
            writer.repository = target["accountId"] + "/" + target["service"]
            reader.manifest.return_value = None
            with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources"), \
                    patch.object(digest_publish, "observe", return_value=state), patch.object(control, "Registry", side_effect=[writer, reader]), \
                    patch.object(control.publication, "_write_auth", return_value=Path(temporary) / "auth"), \
                    patch.object(control.publication, "_copy_image", side_effect=control.ProviderError("unknown")) as copy, \
                    self.assertRaises(control.ProviderError):
                digest_publish.publish_once(target, refs, image, intent, control.digest(intent), "worker", "read", "write")
            copy.assert_called_once()


if __name__ == "__main__":
    unittest.main()

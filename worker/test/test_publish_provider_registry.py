"""No-network tests for the protected provider registry publication."""

from email.message import Message
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import publish_provider_registry as publication


ACCOUNT = "a" * 32
REVISION = "b" * 40
MANIFEST = "c" * 64
CONFIG = "d" * 64
TAG = f"git-{REVISION}-{MANIFEST[:12]}"
DIGEST = "sha256:" + MANIFEST
REPOSITORY = f"{ACCOUNT}/{publication.provider.SERVICE}"
REPO = f"{publication.HOST}/{REPOSITORY}"
PULL = ("fixture-pull", "header.payload.signature")
PUSH = ("fixture-push", "header.payload.signature")
EVIDENCE = {
    "revision": REVISION, "runId": "10", "runAttempt": "2", "artifactId": "15", "archiveSha256": "e" * 64,
    "compatibilityDate": publication.provider.COMPATIBILITY, "workerSha256": "f" * 64,
    "ociArchiveSha256": "1" * 64, "ociManifestSha256": MANIFEST, "ociConfigSha256": CONFIG,
}


def headers(**values):
    result = Message()
    for name, value in values.items():
        result[name.replace("_", "-")] = value
    return result


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.registry = publication.Registry(ACCOUNT, "synthetic-token")

    def test_credential_endpoint_permissions_and_scope(self):
        result = {"success": True, "result": {"account_id": ACCOUNT, "registry_host": publication.HOST,
                                              "username": PULL[0], "password": PULL[1]}}
        with patch.object(publication, "_response", return_value=(200, headers(), json.dumps(result).encode())) as read:
            self.assertEqual(self.registry.mint(), PULL)
            self.assertEqual(self.registry.mint(push=True), PULL)
        for args, permissions in zip(read.call_args_list, (["pull"], ["pull", "push"]), strict=True):
            request = args.args[0]
            self.assertEqual(request.method, "POST")
            self.assertEqual(request.full_url,
                             f"https://api.cloudflare.com/client/v4/accounts/{ACCOUNT}/containers/registries/{publication.HOST}/credentials")
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")
            self.assertEqual(json.loads(request.data), {"expiration_minutes": 15, "permissions": permissions})

    def test_credentials_from_wrong_account_or_host_are_rejected(self):
        result = {"account_id": ACCOUNT, "registry_host": publication.HOST, "username": PULL[0], "password": PULL[1]}
        for key, value in (("account_id", "0" * 32), ("registry_host", "example.invalid"), ("username", "x:y"),
                           ("password", "non-jwt")):
            with self.subTest(key=key):
                payload = json.dumps({"success": True, "result": {**result, key: value}}).encode()
                with patch.object(publication, "_response", return_value=(200, headers(), payload)):
                    with self.assertRaisesRegex(publication.PublicationError, "expected short-lived"):
                        self.registry.mint()

    def test_created_registry_credentials_require_an_exact_account_and_host(self):
        result = {"account_id": ACCOUNT, "registry_host": publication.HOST, "username": PULL[0], "password": PULL[1]}
        valid = json.dumps({"success": True, "result": result}).encode()
        wrong_account = json.dumps({"success": True, "result": {**result, "account_id": "0" * 32}}).encode()
        with patch.object(publication, "_response", side_effect=[
            (201, headers(), valid),
            (201, headers(), wrong_account),
            (202, headers(), valid),
        ]):
            self.assertEqual(self.registry.mint(), PULL)
            with self.assertRaises(publication.PublicationError):
                self.registry.mint()
            with self.assertRaises(publication.PublicationError):
                self.registry.mint()

    def test_authentication_and_authorized_manifest_absence_then_exact_hash(self):
        www = (f'Bearer realm="https://{publication.HOST}/v2/token",service="{publication.HOST}",'
               f'scope="repository:{REPOSITORY}:pull"')
        raw = b'{"schemaVersion":2}'
        digest = sha256(raw).hexdigest()
        with patch.object(publication, "_response", side_effect=[
            (401, headers(WWW_Authenticate=www), b""),
            (200, headers(), b'{"token":"fixture-opaque-token"}'),
            (404, headers(), b'{"errors":[{"code":"MANIFEST_UNKNOWN"}]}'),
            (200, headers(Content_Type=publication.provider.OCI_MANIFEST, Docker_Content_Digest="sha256:" + digest), raw),
        ]) as read:
            self.assertIsNone(self.registry.manifest(TAG, PULL, allow_missing=True))
            self.assertEqual(self.registry.manifest(DIGEST, PULL), digest)
        first, token, missing, digest_read = [entry.args[0] for entry in read.call_args_list]
        self.assertIsNone(first.get_header("Authorization"))
        self.assertEqual(first.full_url, f"https://{publication.HOST}/v2/")
        self.assertEqual(missing.full_url, f"https://{publication.HOST}/v2/{REPOSITORY}/manifests/{TAG}")
        self.assertEqual(token.get_header("Authorization"), "Basic " + publication._basic(PULL))
        self.assertEqual(urlsplit(token.full_url).hostname, publication.HOST)
        self.assertEqual(parse_qs(urlsplit(token.full_url).query),
                         {"scope": [f"repository:{REPOSITORY}:pull"], "service": [publication.HOST]})
        self.assertEqual(missing.get_header("Authorization"), "Bearer fixture-opaque-token")
        self.assertEqual(digest_read.get_header("Authorization"), "Bearer fixture-opaque-token")

    def test_registry_can_offer_the_auth_challenge_on_the_manifest_endpoint(self):
        with patch.object(publication, "_response", side_effect=[
            (200, headers(), b"{}"),
            (401, headers(WWW_Authenticate='Basic realm="fixture realm"'), b""),
            (404, headers(), b'{"errors":[{"code":"NAME_UNKNOWN"}]}'),
        ]) as read:
            self.assertIsNone(self.registry.manifest(TAG, PULL, allow_missing=True))
        _, first, authenticated = [entry.args[0] for entry in read.call_args_list]
        self.assertEqual(first.full_url, authenticated.full_url)
        self.assertIsNone(first.get_header("Authorization"))
        self.assertEqual(authenticated.get_header("Authorization"), "Basic " + publication._basic(PULL))

    def test_challenge_cannot_send_credentials_to_another_origin_or_scope(self):
        invalid = [
            'Bearer realm="https://example.invalid/token"',
            f'Bearer realm="https://{publication.HOST}.example.invalid/token"',
            f'Bearer realm="http://{publication.HOST}/token"',
            f'Bearer realm="https://{publication.HOST}@example.invalid/token"',
            f'Bearer realm="https://{publication.HOST}/token",scope="repository:{REPOSITORY}:pull,push"',
            f'Bearer realm="https://{publication.HOST}/token",realm="https://{publication.HOST}/other"',
        ]
        for challenge in invalid:
            with self.subTest(challenge=challenge), patch.object(publication, "_response", return_value=(
                    401, headers(WWW_Authenticate=challenge), b"")) as read:
                with self.assertRaises(publication.PublicationError):
                    self.registry.manifest(TAG, PULL, allow_missing=True)
                self.assertEqual(read.call_count, 1)
                self.assertIsNone(read.call_args.args[0].get_header("Authorization"))

    def test_absence_requires_authentication_and_the_exact_registry_error(self):
        unknown = b'{"errors":[{"code":"NAME_UNKNOWN"}]}'
        with patch.object(publication, "_response", return_value=(404, headers(), unknown)):
            with self.assertRaises(publication.PublicationError):
                self.registry.manifest(TAG, PULL, allow_missing=True)

        for status, data in [(403, unknown), (503, unknown), (404, b"<html>missing</html>"),
                             (404, b'{"errors":[{"code":"UNAUTHORIZED"}]}'),
                             (404, b'{"errors":[{"code":"NAME_UNKNOWN"},{"code":"UNAUTHORIZED"}]}')]:
            with self.subTest(status=status, data=data), patch.object(publication, "_response", side_effect=[
                    (401, headers(WWW_Authenticate='Basic realm="fixture"'), b""), (status, headers(), data)]):
                self.registry._read_authorization = None
                with self.assertRaises((publication.PublicationError, publication.github.ArtifactError)):
                    self.registry.manifest(TAG, PULL, allow_missing=True)

    def test_success_requires_oci_media_type_and_consistent_digest_header(self):
        for result in (headers(Content_Type="application/json"),
                       headers(Content_Type=publication.provider.OCI_MANIFEST, Docker_Content_Digest=DIGEST)):
            with self.subTest(result=result), patch.object(publication, "_response", side_effect=[
                (401, headers(WWW_Authenticate='Basic realm="fixture"'), b""),
                (200, result, b"wrong bytes"),
            ]):
                self.registry._read_authorization = None
                with self.assertRaises(publication.PublicationError):
                    self.registry.manifest(DIGEST, PULL)


class PublicationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.scratch = Path(directory.name)
        self.archive = self.scratch / publication.provider.IMAGE
        self.registry = Mock(spec=publication.Registry)
        self.registry.repository = REPOSITORY
        self.registry.mint.side_effect = lambda *, push=False: PUSH if push else PULL
        for name in ("_guard_main", "_copy", "_config"):
            patcher = patch.object(publication, name)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        self._config.return_value = CONFIG

    def publish(self):
        return publication._publish(self.registry, self.scratch, self.archive, EVIDENCE)

    def test_publishes_only_after_second_absence_check_and_verifies_tag_and_digest(self):
        self.registry.manifest.side_effect = [None, None, MANIFEST, MANIFEST]
        result = self.publish()
        self.assertEqual(result, {**EVIDENCE, "tag": TAG, "status": "published"})
        self.assertEqual(self.registry.mint.call_args_list, [call(), call(push=True)])
        self.assertEqual(self.registry.manifest.call_args_list, [call(TAG, PULL, allow_missing=True)] * 2
                         + [call(DIGEST, PULL), call(TAG, PULL)])
        self._copy.assert_called_once_with(self.scratch, self.archive, f"{REPO}:{TAG}",
                                           self.scratch / "push-auth.json", DIGEST)
        self._config.assert_called_once_with(self.scratch, f"{REPO}@{DIGEST}", self.scratch / "pull-auth.json")
        self.assertEqual(self._guard_main.call_args_list, [call(EVIDENCE), call(EVIDENCE)])
        auth_path = self.scratch / "push-auth.json"
        self.assertEqual(auth_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(auth_path.read_bytes()), {"auths": {REPO: {"auth": publication._basic(PUSH)}}})
        self.assertNotIn(ACCOUNT, json.dumps(result))

    def test_existing_exact_image_is_adopted_using_pull_only(self):
        self.registry.manifest.return_value = MANIFEST
        self.assertEqual(self.publish()["status"], "adopted")
        self.registry.mint.assert_called_once_with()
        self._copy.assert_not_called()
        self._config.assert_called_once()
        self.assertFalse((self.scratch / "push-auth.json").exists())

    def test_tag_created_during_guard_is_checked_without_writing(self):
        self.registry.manifest.side_effect = [None, MANIFEST, MANIFEST, MANIFEST]
        self.assertEqual(self.publish()["status"], "adopted")
        self._copy.assert_not_called()

    def test_wrong_tag_or_ambiguous_lookup_never_copies(self):
        for lookup in (["0" * 64], [None, "0" * 64], [publication.PublicationError("ambiguous")]):
            with self.subTest(lookup=lookup):
                self.registry.manifest.side_effect = lookup
                with self.assertRaises(publication.PublicationError):
                    self.publish()
                self._copy.assert_not_called()
                (self.scratch / "push-auth.json").unlink(missing_ok=True)

    def test_stale_main_and_bad_config_never_emit_publication_result(self):
        self.registry.manifest.return_value = None
        self._guard_main.side_effect = publication.github.ArtifactError("main changed")
        with self.assertRaises(publication.github.ArtifactError):
            self.publish()
        self._copy.assert_not_called()

        self._guard_main.side_effect = None
        self.registry.manifest.return_value = MANIFEST
        self._config.return_value = "0" * 64
        with self.assertRaisesRegex(publication.PublicationError, "did not match"):
            self.publish()
        self._copy.assert_not_called()

    def test_uncertain_copy_never_retries_or_reports_success(self):
        self.registry.manifest.return_value = None
        self._copy.side_effect = publication.PublicationError("copy unconfirmed")
        with self.assertRaisesRegex(publication.PublicationError, "copy unconfirmed"):
            self.publish()
        self._copy.assert_called_once()
        self._config.assert_not_called()


class LocalBoundaryTests(unittest.TestCase):
    def test_evidence_is_bound_to_private_verified_files_and_trusted_run(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            evidence_file = root / publication.EVIDENCE_FILE
            evidence_file.write_text(json.dumps(EVIDENCE))
            evidence_file.chmod(0o600)
            verified = root / publication.provenance.VERIFIED_DIRECTORY
            verified.mkdir(mode=0o700)
            for name in publication.provenance.FILE_LIMITS:
                path = verified / name
                path.write_text("synthetic")
                path.chmod(0o600)
            with patch.object(publication.provider, "verify_release", return_value=EVIDENCE) as verify:
                self.assertEqual(publication._verified_input(root, REVISION, "10"),
                                 (verified / publication.provider.IMAGE, EVIDENCE))
                verify.assert_called_once_with(verified, REVISION, ref=publication.github.MAIN_REF,
                                               run_id="10", run_attempt="2")
                path = verified / publication.provider.IMAGE
                path.unlink()
                path.symlink_to(evidence_file)
                with self.assertRaises(publication.PublicationError):
                    publication._verified_input(root, REVISION, "10")
        with patch.object(publication.github, "require_current_main"), patch.object(
                publication.github, "_github_token", return_value="synthetic"), patch.object(
                publication.provenance, "_select_artifact", return_value=("3", "20", "0" * 64)):
            with self.assertRaisesRegex(publication.PublicationError, "attempt or artifact changed"):
                publication._guard_main(EVIDENCE)

    def test_skopeo_preserves_digest_without_exposing_credentials_or_subprocess_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            auth_path = scratch / "auth.json"

            def succeed(args, **options):
                self.assertIn("--preserve-digests", args)
                self.assertIn("--retry-times=0", args)
                self.assertIn("--dest-tls-verify=true", args)
                self.assertEqual(args[-1], f"docker://{REPO}:{TAG}")
                self.assertEqual(options["stderr"], subprocess.DEVNULL)
                self.assertNotIn("GH_TOKEN", options["env"])
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", options["env"])
                (scratch / "copied-digest").write_text(DIGEST)

            with patch.object(publication.subprocess, "run", side_effect=succeed):
                publication._copy(scratch, scratch / "image.tar", f"{REPO}:{TAG}", auth_path, DIGEST)
            with patch.object(publication.subprocess, "run", side_effect=subprocess.CalledProcessError(
                    1, ["skopeo"], stderr=b"synthetic-private-provider-error")):
                with self.assertRaisesRegex(publication.PublicationError, "^Skopeo did not confirm"):
                    publication._copy(scratch, scratch / "image.tar", f"{REPO}:{TAG}", auth_path, DIGEST)

    def test_config_digest_is_computed_from_raw_bytes_at_the_immutable_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            auth_path = scratch / "pull-auth.json"
            config = b'{"config": {}}\n'

            def raw_config(args, **options):
                self.assertIn("--raw", args)
                self.assertIn("--config", args)
                self.assertIn("--tls-verify=true", args)
                self.assertEqual(args[-1], f"docker://{REPO}@{DIGEST}")
                self.assertEqual(options["stderr"], subprocess.DEVNULL)
                options["stdout"].write(config)

            with patch.object(publication.subprocess, "run", side_effect=raw_config):
                self.assertEqual(publication._config(scratch, f"{REPO}@{DIGEST}", auth_path),
                                 sha256(config).hexdigest())

    def test_branch_guard_fails_before_credentials_or_artifacts_are_read(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": publication.github.REPOSITORY,
                                     "GITHUB_REF": "refs/heads/feature", "GITHUB_EVENT_NAME": "workflow_dispatch",
                                     "GITHUB_SHA": REVISION, "SUBS_BOT_PROVIDER_CI_RUN_ID": "10",
                                     "RUNNER_TEMP": "/tmp/synthetic-runner"}, clear=True), patch.object(
                publication, "_verified_input") as read:
            with self.assertRaisesRegex(publication.PublicationError, "protected dispatch"):
                publication.publish()
            read.assert_not_called()


    def test_foreign_account_fails_before_artifacts_or_credentials_are_used(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": publication.github.REPOSITORY,
                                     "GITHUB_REF": publication.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch",
                                     "GITHUB_SHA": REVISION, "SUBS_BOT_PROVIDER_CI_RUN_ID": "10",
                                     "RUNNER_TEMP": "/tmp/synthetic-runner",
                                     "SUBS_BOT_CF_PROVIDER_ACCOUNT_ID": ACCOUNT}, clear=True), patch.object(
                publication, "_verified_input") as read, patch.object(publication, "Registry") as registry:
            with self.assertRaisesRegex(publication.PublicationError, "does not match the isolation target"):
                publication.publish()
            read.assert_not_called()
            registry.assert_not_called()


if __name__ == "__main__":
    unittest.main()

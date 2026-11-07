"""Hosted tests for private Provider CI artifact verification without real credentials."""

import gzip
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_provider_artifact as release


github = release.github
provider = release.provider
REVISION = "a" * 40
RUN_ID = "101"
ATTEMPT = "2"
ARTIFACT_ID = "202"
TOKEN = "fixture-github-token"
SIGNED = "https://storage.example.invalid/artifact.zip?signature=fixture-signature"


def encoded(value):
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def descriptor(body, media_type, **options):
    return {"mediaType": media_type, "size": len(body), "digest": "sha256:" + sha256(body).hexdigest(), **options}


def tar_bytes(members):
    output = BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, data in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(data)
            archive.addfile(member, BytesIO(data))
    return output.getvalue()


def oci_fixture(*, wrong_diff_id=False, foreign_layer=False, wrong_platform=False, unreferenced=False,
                duplicate_metadata=False):
    plain = tar_bytes({"app/fixture.txt": b"isolated image fixture"})
    layer = gzip.compress(plain, mtime=0)
    config = encoded({
        "architecture": "amd64", "os": "linux",
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + ("0" * 64 if wrong_diff_id else sha256(plain).hexdigest())]},
        "config": {"User": "65532:65532", "Entrypoint": ["python", "-B", "-E", "-s", "/app/server.py"],
                   "WorkingDir": "/app", "Labels": {"org.opencontainers.image.revision": REVISION},
                   "ExposedPorts": {"8080/tcp": {}}, "Env": ["PATH=/usr/bin"]},
    })
    config_descriptor = descriptor(config, provider.OCI_CONFIG)
    layer_descriptor = descriptor(layer, provider.OCI_GZIP_LAYER)
    if foreign_layer:
        layer_descriptor["urls"] = ["https://fixture.example.invalid/layer"]
    manifest = encoded({"schemaVersion": 2, "mediaType": provider.OCI_MANIFEST,
                        "config": config_descriptor, "layers": [layer_descriptor]})
    manifest_descriptor = descriptor(manifest, provider.OCI_MANIFEST,
                                     platform={"architecture": "arm64" if wrong_platform else "amd64", "os": "linux"})
    index = encoded({"schemaVersion": 2, "mediaType": provider.OCI_INDEX, "manifests": [manifest_descriptor]})
    if duplicate_metadata:
        index = b'{"schemaVersion":1,' + index[1:]
    members = {"oci-layout": encoded({"imageLayoutVersion": "1.0.0"}), "index.json": index}
    for body, entry in ((layer, layer_descriptor), (config, config_descriptor), (manifest, manifest_descriptor)):
        members["blobs/sha256/" + entry["digest"].removeprefix("sha256:")] = body
    if unreferenced:
        members["blobs/sha256/" + "0" * 64] = b"unreferenced"
    return tar_bytes(members)


def zip_fixture(members):
    output = BytesIO()
    with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return output.getvalue()


class StorageResponse(BytesIO):
    status = 200

    def __init__(self, body):
        super().__init__(body)
        self.headers = {"Content-Length": str(len(body))}
        self.read_sizes = []

    def read1(self, size):
        if not 0 < size <= release.COPY_CHUNK:
            raise AssertionError("Artifact storage reads must be bounded.")
        self.read_sizes.append(size)
        return super().read1(size)


class PrepareProviderArtifactTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        source = self.root / "source"
        source.mkdir()
        (source / provider.IMAGE).write_bytes(oci_fixture())
        (source / provider.WORKER).write_bytes(b"export default {};\n")
        requirements = Path(provider.__file__).with_name("requirements.txt")
        self.manifest = provider.release_manifest(source, REVISION, requirements, ref=github.MAIN_REF,
                                                  run_id=RUN_ID, run_attempt=ATTEMPT)
        self.members = {name: (source / name).read_bytes() for name in (provider.IMAGE, provider.WORKER)}
        self.members[provider.MANIFEST] = encoded(self.manifest)
        self.archive = zip_fixture(self.members)
        self.run = {"id": int(RUN_ID), "workflow_id": release.WORKFLOW_ID, "path": release.WORKFLOW_PATH,
                    "event": "push", "status": "completed", "conclusion": "success", "head_branch": "main",
                    "head_sha": REVISION, "repository": {"id": github.REPOSITORY_ID},
                    "head_repository": {"id": github.REPOSITORY_ID}, "run_attempt": int(ATTEMPT)}
        self.artifact = {"id": int(ARTIFACT_ID), "name": f"subs-bot-provider-{REVISION}-{ATTEMPT}", "expired": False,
                         "workflow_run": {"id": int(RUN_ID), "head_branch": "main", "head_sha": REVISION,
                                          "repository_id": github.REPOSITORY_ID, "head_repository_id": github.REPOSITORY_ID}}
        self.main_revisions = [REVISION, REVISION]
        self.listed = 0
        self.second_digest = None
        self.enterContext(patch.object(github, "_get_json", side_effect=self.github_json))
        self.redirect = self.enterContext(patch.object(github._OPENER, "open", side_effect=self.github_redirect))
        self.storage = self.enterContext(patch.object(release.STORAGE_OPENER, "open", side_effect=self.storage_open))
        self.enterContext(patch.dict(os.environ, {"GITHUB_REPOSITORY": github.REPOSITORY, "GITHUB_REF": github.MAIN_REF,
                                                "GITHUB_SHA": REVISION, "SUBS_BOT_PROVIDER_CI_RUN_ID": RUN_ID,
                                                "GH_TOKEN": TOKEN, "RUNNER_TEMP": str(self.root)}, clear=True))

    def github_json(self, path, token):
        self.assertTrue(token == TOKEN)
        if path == "/git/ref/heads/main":
            return {"ref": github.MAIN_REF, "object": {"type": "commit", "sha": self.main_revisions.pop(0)}}
        if path == f"/actions/runs/{RUN_ID}":
            return self.run
        if path == f"/actions/runs/{RUN_ID}/artifacts?name={self.artifact['name']}&per_page=2":
            self.listed += 1
            digest = self.second_digest if self.listed == 2 and self.second_digest else sha256(self.archive).hexdigest()
            return {"total_count": 1, "artifacts": [{"digest": "sha256:" + digest, **self.artifact}]}
        self.fail("Unexpected GitHub API request.")

    def github_redirect(self, request, *, timeout):
        self.assertTrue(request.get_header("Authorization") == "Bearer " + TOKEN)
        self.assertTrue(request.full_url.endswith(f"/actions/artifacts/{ARTIFACT_ID}/zip"))
        raise HTTPError(request.full_url, 302, "redirect", {"Location": SIGNED}, BytesIO())

    def storage_open(self, request, *, timeout):
        self.assertTrue(request.full_url == SIGNED)
        self.assertEqual({name.lower() for name, _ in request.header_items()}, {"accept-encoding"})
        self.response = StorageResponse(self.archive)
        return self.response

    def assert_private_failure(self, expected):
        with self.assertRaises(github.ArtifactError) as error:
            release.prepare()
        self.assertTrue(expected in str(error.exception), "Verifier returned an unexpected failure.")
        self.assertTrue(TOKEN not in str(error.exception) and SIGNED not in str(error.exception), "Verifier leaked credentials.")
        self.assertFalse((self.root / release.VERIFIED_DIRECTORY).exists())
        self.assertFalse(list(self.root.glob(".subs-bot-provider-*")))

    def test_publishes_exact_files_only_after_rechecking_main_and_attempt(self):
        with patch.object(release, "COPY_CHUNK", 128):
            evidence = release.prepare()
        self.assertEqual(evidence, {"revision": REVISION, "runId": RUN_ID, "runAttempt": ATTEMPT, "artifactId": ARTIFACT_ID,
                                    "archiveSha256": sha256(self.archive).hexdigest(), "compatibilityDate": provider.COMPATIBILITY,
                                    "workerSha256": self.manifest["workerSha256"], "ociArchiveSha256": self.manifest["ociArchiveSha256"],
                                    "ociManifestSha256": self.manifest["ociManifestSha256"],
                                    "ociConfigSha256": self.manifest["ociConfigSha256"]})
        destination = self.root / release.VERIFIED_DIRECTORY
        self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o700)
        self.assertEqual({path.name for path in destination.iterdir()}, set(self.members))
        for name, data in self.members.items():
            self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o600)
            self.assertTrue((destination / name).read_bytes() == data, "A published member changed.")
        self.assertEqual(self.main_revisions, [])
        self.assertEqual(self.listed, 2)
        self.assertGreater(len(self.response.read_sizes), 2)

    def test_refuses_untrusted_run_before_downloading(self):
        for key, value in (("event", "pull_request"), ("conclusion", "failure"), ("workflow_id", 1),
                           ("path", ".github/workflows/untrusted.yml"), ("head_branch", "other"),
                           ("head_repository", {"id": 1})):
            with self.subTest(key=key):
                previous = self.run[key]
                self.run[key] = value
                self.main_revisions = [REVISION]
                self.assert_private_failure("not a successful Provider Fetch CI build")
                self.run[key] = previous
        self.redirect.assert_not_called()
        self.storage.assert_not_called()

    def test_refuses_wrong_artifact_ownership(self):
        self.artifact["workflow_run"]["head_repository_id"] = 1
        self.assert_private_failure("invalid provenance or digest")
        self.storage.assert_not_called()

    def test_refuses_stale_main_after_verifying_artifact(self):
        self.main_revisions[-1] = "b" * 40
        self.assert_private_failure("no longer current on main")

    def test_refuses_artifact_that_changes_before_publication(self):
        self.second_digest = "0" * 64
        self.assert_private_failure("changed during verification")

    def test_checks_download_digest_before_extracting(self):
        self.artifact["digest"] = "sha256:" + "0" * 64
        self.assert_private_failure("length or GitHub digest did not match")

    def test_enforces_download_bound_even_without_content_length(self):
        response = StorageResponse(self.archive)
        response.headers.clear()
        self.storage.side_effect = None
        self.storage.return_value = response
        with patch.object(release, "MAX_ZIP", len(self.archive) - 1):
            self.assert_private_failure("Could not download the verified provider archive")

    def test_does_not_replace_an_existing_destination(self):
        destination = self.root / release.VERIFIED_DIRECTORY
        destination.symlink_to(self.root / "missing")
        self.assert_private_failure("directory already exists")
        self.assertTrue(destination.is_symlink())
        self.storage.assert_not_called()

    def test_refuses_insecure_redirect_without_contacting_storage(self):
        for location in ("http://storage.example.invalid/file", "https://user@storage.example.invalid/file",
                         "https://storage.example.invalid:8080/file", "https://storage.example.invalid/\\file"):
            self.redirect.side_effect = HTTPError("https://api.github.com/fixture", 302, "redirect",
                                                  {"Location": location}, BytesIO())
            self.main_revisions = [REVISION]
            self.assert_private_failure("Could not download the selected GitHub artifact")
        self.storage.assert_not_called()

    def test_refuses_path_alias_symlink_and_wrong_file_size(self):
        link = ZipInfo(provider.WORKER)
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        others = {name: body for name, body in self.members.items() if name != provider.WORKER}
        for name, data in (("../" + provider.WORKER, b"unsafe"), (link, b"relative-path"),
                           (provider.WORKER, b"x" * (provider.MAX_WORKER + 1))):
            self.main_revisions = [REVISION]
            self.archive = zip_fixture({**others, name: data})
            self.assert_private_failure("ZIP has an unsafe")

    def test_refuses_v1_wrong_attempt_and_changed_worker(self):
        for patch_data in ({"version": 1}, {"runAttempt": "1"}, {"compatibilityDate": "2020-01-01"}):
            self.main_revisions = [REVISION]
            self.archive = zip_fixture({**self.members, provider.MANIFEST: encoded(self.manifest | patch_data)})
            self.assert_private_failure("manifest or its exact contents did not verify")
        self.main_revisions = [REVISION]
        self.archive = zip_fixture({**self.members, provider.WORKER: b"different Worker module"})
        self.assert_private_failure("manifest or its exact contents did not verify")

    def test_refuses_foreign_oci_descriptors_and_mismatched_rootfs(self):
        path = self.root / "image.tar"
        for option in ("wrong_diff_id", "foreign_layer", "wrong_platform", "unreferenced", "duplicate_metadata"):
            with self.subTest(option=option):
                path.write_bytes(oci_fixture(**{option: True}))
                with self.assertRaises(ValueError):
                    provider.verify_image(path, REVISION)

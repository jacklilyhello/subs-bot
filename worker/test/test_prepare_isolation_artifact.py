"""Hosted release-verification regressions using synthetic GitHub API responses."""

from copy import deepcopy
from email.message import Message
from hashlib import sha256
import io
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_isolation_artifact as release


REVISION = "a" * 40
RUN_ID = "1234"
RUN_ATTEMPT = "2"
ARTIFACT_ID = "2345"
FIXTURE_TOKEN = "fixture-gh-read"


def digest(body):
    return sha256(body).hexdigest()


def synthetic_release():
    snapshot_id = "11111111-1111-4111-8111-111111111111"
    prefix = f"subscriptions/1/{snapshot_id}/"
    bundle = b"export default {}"
    migration = b"CREATE TABLE subscriptions (id INTEGER);"
    chunk = b'{"name":"fixture"}\n'
    snapshot_manifest = b'{"version":1,"chunks":[]}'
    files = {
        "index.js": bundle,
        "0001_subscriptions.sql": migration,
        f"r2/{prefix}0.ndjson": chunk,
        f"r2/{prefix}manifest.json": snapshot_manifest,
    }
    manifest = {
        "version": 2,
        "ref": release.MAIN_REF,
        "runId": RUN_ID,
        "runAttempt": RUN_ATTEMPT,
        "revision": REVISION,
        "compatibilityDate": "2026-07-30",
        "bundleSha256": digest(bundle),
        "migrations": [{"name": "0001_subscriptions.sql", "sha256": digest(migration)}],
        "snapshots": [{
            "id": 1, "snapshotId": snapshot_id, "token": "subsbot-synthetic-test",
            "nodeCount": 1, "nodeBytes": len(chunk), "bodyBytes": 4, "bodySha256": digest(b"eA=="),
            "manifestSha256": digest(snapshot_manifest),
            "objects": [
                {"key": name.removeprefix("r2/"), "file": name, "bytes": len(body), "sha256": digest(body)}
                for name, body in files.items() if name.startswith("r2/")
            ],
        }],
    }
    return manifest, files


def zip_release(manifest, files, extra_entries=()):
    body = io.BytesIO()
    with ZipFile(body, "w") as archive:
        archive.writestr("isolation.json", json.dumps(manifest))
        for name, data in (*files.items(), *extra_entries):
            archive.writestr(name, data)
    return body.getvalue()


class PrepareIsolationArtifactTests(unittest.TestCase):
    def setUp(self):
        temp = self.enterContext(TemporaryDirectory())
        self.temp = Path(temp)
        self.destination = self.temp / release.VERIFIED_DIRECTORY
        self.env = self.enterContext(patch.dict(os.environ, {
            "GITHUB_REPOSITORY": release.REPOSITORY,
            "GITHUB_REF": release.MAIN_REF,
            "GITHUB_SHA": REVISION,
            "GH_TOKEN": FIXTURE_TOKEN,
            "SUBS_BOT_CI_RUN_ID": RUN_ID,
            "RUNNER_TEMP": temp,
        }))
        self.manifest, self.files = synthetic_release()
        self.archive = zip_release(self.manifest, self.files)
        self.main = {"ref": release.MAIN_REF, "object": {"type": "commit", "sha": REVISION}}
        self.run = {
            "id": int(RUN_ID), "workflow_id": release.WORKFLOW_ID, "path": release.WORKFLOW_PATH,
            "head_branch": "main", "head_sha": REVISION, "event": "push",
            "status": "completed", "conclusion": "success", "run_attempt": int(RUN_ATTEMPT),
            "repository": {"id": release.REPOSITORY_ID}, "head_repository": {"id": release.REPOSITORY_ID},
        }
        self.artifact = {
            "id": int(ARTIFACT_ID), "expired": False,
            "name": f"subs-bot-worker-{REVISION}-{RUN_ATTEMPT}", "digest": f"sha256:{digest(self.archive)}",
            "workflow_run": {
                "id": int(RUN_ID), "head_branch": "main", "head_sha": REVISION,
                "repository_id": release.REPOSITORY_ID, "head_repository_id": release.REPOSITORY_ID,
            },
        }
        self.total_count = 1
        self.github = self.enterContext(patch.object(release, "_get_json", side_effect=self.github_response))
        self.download = self.enterContext(patch.object(release, "_download", return_value=self.archive))

    def github_response(self, path, token):
        self.assertEqual(token, FIXTURE_TOKEN)
        parsed = urlsplit(path)
        if parsed.path == "/git/ref/heads/main":
            return self.main
        if parsed.path == f"/actions/runs/{RUN_ID}":
            return self.run
        if parsed.path == f"/actions/runs/{RUN_ID}/artifacts":
            self.assertEqual(parse_qs(parsed.query), {"name": [self.artifact["name"]], "per_page": ["2"]})
            return {"total_count": self.total_count, "artifacts": [self.artifact]}
        self.fail("Unexpected GitHub API request")

    def use_archive(self, manifest, files, extra_entries=()):
        self.archive = zip_release(manifest, files, extra_entries)
        self.artifact["digest"] = f"sha256:{digest(self.archive)}"
        self.download.return_value = self.archive

    def assert_rejected(self, message):
        with self.assertRaisesRegex(release.ArtifactError, message):
            release.prepare()
        self.assertFalse(self.destination.exists())
        self.assertEqual(list(self.temp.iterdir()), [])

    def test_verifies_extracts_only_known_files_and_returns_evidence(self):
        self.assertEqual(release.prepare(), {
            "revision": REVISION, "runId": RUN_ID, "runAttempt": RUN_ATTEMPT,
            "artifactId": ARTIFACT_ID, "archiveSha256": digest(self.archive),
        })
        self.download.assert_called_once_with(ARTIFACT_ID, FIXTURE_TOKEN)
        self.assertEqual(json.loads((self.destination / "isolation.json").read_bytes()), self.manifest)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        for name, expected in self.files.items():
            path = self.destination / name
            self.assertEqual(path.read_bytes(), expected)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)
        self.assertEqual(sorted(str(path.relative_to(self.destination)) for path in self.destination.rglob("*")
                                if path.is_file()), sorted(["isolation.json", *self.files]))

    def test_non_main_ref_and_stale_commit_are_refused_before_download(self):
        self.env["GITHUB_REF"] = "refs/tags/main"
        self.assert_rejected("requires main")
        self.github.assert_not_called()
        self.env["GITHUB_REF"] = release.MAIN_REF
        self.main["object"]["sha"] = "b" * 40
        self.assert_rejected("no longer current")
        self.download.assert_not_called()

    def test_rechecks_main_after_download(self):
        def advance_main(*_args):
            self.main["object"]["sha"] = "b" * 40
            return self.archive

        self.download.side_effect = advance_main
        self.assert_rejected("no longer current")

    def test_rechecks_artifact_selection_after_download(self):
        def change_digest(*_args):
            self.artifact["digest"] = f"sha256:{'c' * 64}"
            return self.archive

        self.download.side_effect = change_digest
        self.assert_rejected("artifact changed during verification")

    def test_rejects_mismatched_build_provenance_and_unsuccessful_runs(self):
        for key, value in (
            ("workflow_id", 1), ("path", ".github/workflows/other.yml"),
            ("event", "pull_request"), ("head_branch", "topic"), ("head_sha", "b" * 40),
            ("head_repository", {"id": 1}), ("repository", {"id": 1}),
            ("status", "in_progress"), ("conclusion", "failure"), ("run_attempt", 0),
        ):
            with self.subTest(key=key):
                with patch.dict(self.run, {key: value}):
                    self.assert_rejected("not a successful Worker CI build")
        self.download.assert_not_called()

    def test_rejects_ambiguous_expired_or_unbound_artifact(self):
        for count in (0, 2):
            with self.subTest(count=count):
                self.total_count = count
                self.assert_rejected("exactly one matching artifact")
        self.total_count = 1
        for key, value in (("expired", True), ("digest", ""), ("workflow_run", {"id": int(RUN_ID) + 1})):
            with self.subTest(key=key), patch.dict(self.artifact, {key: value}):
                self.assert_rejected("invalid provenance or digest")
        self.download.assert_not_called()

    def test_rejects_digest_or_manifest_mismatches(self):
        with patch.dict(self.artifact, {"digest": f"sha256:{'c' * 64}"}):
            self.assert_rejected("does not match the GitHub artifact digest")
        for key, value in (("runId", "9"), ("runAttempt", "1"), ("ref", "refs/tags/main"),
                           ("revision", "b" * 40), ("version", 1)):
            with self.subTest(key=key):
                self.use_archive({**self.manifest, key: value}, self.files)
                self.assert_rejected("invalid provenance or file metadata")

    def test_rejects_unexpected_missing_or_modified_entries(self):
        self.use_archive(self.manifest, {**self.files, "execute.py": b"fixture"})
        self.assert_rejected("missing or unexpected files")
        self.use_archive(self.manifest, {key: value for key, value in self.files.items() if key != "index.js"})
        self.assert_rejected("missing or unexpected files")
        for name in self.files:
            with self.subTest(name=name):
                self.use_archive(self.manifest, {**self.files, name: b"tampered fixture"})
                self.assert_rejected("does not match its manifest digest or length")
        manifest = deepcopy(self.manifest)
        manifest["migrations"].append({"name": "0003_skipped.sql", "sha256": digest(b"fixture")})
        self.use_archive(manifest, self.files)
        self.assert_rejected("invalid provenance or file metadata")

    def test_extracts_additional_ordered_migrations(self):
        manifest = deepcopy(self.manifest)
        name = "0002_release_marker.sql"
        sql = b"CREATE TABLE release_marker (id INTEGER);"
        manifest["migrations"].append({"name": name, "sha256": digest(sql)})
        self.use_archive(manifest, {**self.files, name: sql})
        release.prepare()
        self.assertEqual((self.destination / name).read_bytes(), sql)

    def test_bounds_expanded_archive(self):
        with patch.object(release, "_MAX_EXPANDED", 1):
            self.assert_rejected("unpacked release archive exceeds its size limit")

    def test_rejects_traversal_duplicate_and_symlink_entries(self):
        symlink = ZipInfo("untrusted-link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for name in ("../outside", "r2\\escape", "/absolute", symlink):
            with self.subTest(name=name):
                self.use_archive(self.manifest, self.files, [(name, b"fixture")])
                self.assert_rejected("unsafe or duplicate entry")
        with self.assertWarnsRegex(UserWarning, "Duplicate name"):
            self.use_archive(self.manifest, self.files, [("index.js", b"duplicate")])
        self.assert_rejected("unsafe or duplicate entry")

    def test_existing_destination_is_never_reused(self):
        self.destination.mkdir()
        sentinel = self.destination / "existing"
        sentinel.write_bytes(b"untouched")
        with self.assertRaisesRegex(release.ArtifactError, "already exists"):
            release.prepare()
        self.assertEqual(sentinel.read_bytes(), b"untouched")


class ArtifactDownloadTests(unittest.TestCase):
    def test_sends_authorization_only_to_github_api(self):
        location = "https://storage.example.invalid/archive.zip?signed=fixture"
        headers = Message()
        headers["Location"] = location
        api = f"{release.API_ROOT}/actions/artifacts/{ARTIFACT_ID}/zip"
        redirect = HTTPError(api, 302, "Found", headers, io.BytesIO())
        with patch.object(release._OPENER, "open", side_effect=[redirect, io.BytesIO(b"zip fixture")]) as opener:
            self.assertEqual(release._download(ARTIFACT_ID, FIXTURE_TOKEN), b"zip fixture")
        first, second = [call.args[0] for call in opener.call_args_list]
        self.assertEqual(first.full_url, api)
        self.assertEqual(first.get_header("Authorization"), f"Bearer {FIXTURE_TOKEN}")
        self.assertEqual(second.full_url, location)
        self.assertIsNone(second.get_header("Authorization"))

    def test_rejects_insecure_redirect_without_exposing_url(self):
        headers = Message()
        headers["Location"] = "http://storage.example.invalid/archive.zip?signed=fixture"
        redirect = HTTPError(release.API_ROOT, 302, "Found", headers, io.BytesIO())
        with patch.object(release._OPENER, "open", side_effect=redirect) as opener:
            with self.assertRaisesRegex(release.ArtifactError, "Could not download") as error:
                release._download(ARTIFACT_ID, FIXTURE_TOKEN)
        self.assertNotIn("signed", str(error.exception))
        opener.assert_called_once()

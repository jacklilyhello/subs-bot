"""Hosted tests for exact historical capacity checkpoint authentication."""

from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.parse import urlencode
from urllib.request import Request
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import capacity_recovery_artifact as recovery


RUN_ID, ATTEMPT, REVISION = "101", "2", "a" * 40
ARTIFACT_ID = "202"
TOKEN = "fixture-github-read-token"
LEDGER = recovery.capacity.LEDGER_FILE
RUN_PATH = f"/actions/runs/{RUN_ID}"
ATTEMPT_PATH = f"{RUN_PATH}/attempts/{ATTEMPT}"
ARTIFACT_NAME = f"isolation-capacity-recovery-{RUN_ID}-{ATTEMPT}"
ARTIFACT_PATH = f"{RUN_PATH}/artifacts?" + urlencode({"name": ARTIFACT_NAME, "per_page": 2})


def archive(members):
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as file:
        for name, body in members:
            file.writestr(name, body)
    return buffer.getvalue()


def step(name, number, conclusion="success"):
    return {"name": name, "number": number, "status": "completed", "conclusion": conclusion}


class RecoveryArtifactTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(TemporaryDirectory()))
        self.output = self.root / "verified"
        self.ledger = {"version": 1, "phase": "cleanup", "runId": RUN_ID, "revision": REVISION, "scopeSha256": "b" * 64,
                       "fixtures": [{
                           "label": label, "snapshotId": f"00000000-0000-4000-8000-{index:012d}", "nodeCount": 1,
                           "tokenSha256": str(index) * 64, "rowId": index,
                           "armed": [0], "reservePending": False, "putPending": [],
                           "objects": [{"bytes": 42, "sha256": "a" * 64}],
                       } for index, label in enumerate(("at-limits", "share-over", "snapshot-over"), 1)]}
        repo = {"id": recovery.github.REPOSITORY_ID, "full_name": recovery.github.REPOSITORY}
        self.run = {"id": int(RUN_ID), "workflow_id": recovery.WORKFLOW_ID, "path": recovery.WORKFLOW_PATH,
                    "event": "workflow_dispatch", "status": "completed", "conclusion": "failure", "head_branch": "main",
                    "head_sha": REVISION, "repository": dict(repo), "head_repository": dict(repo), "run_attempt": int(ATTEMPT)}
        self.steps = [step(name, number, conclusion) for (name, conclusion), number
                      in zip(recovery.REQUIRED_STEPS, (3, 4, 5, 8, 13, 15), strict=True)]
        self.steps.insert(3, step(recovery.RECOVERY_UPLOAD, 7))
        self.steps.append(step(recovery.RECOVERY_UPLOAD, 16))
        self.jobs = [{"name": "measure", "status": "completed", "conclusion": "failure", "run_id": int(RUN_ID),
                      "run_attempt": int(ATTEMPT), "head_sha": REVISION, "steps": self.steps}]
        self.artifacts = [{"id": int(ARTIFACT_ID), "name": ARTIFACT_NAME, "expired": False,
                           "workflow_run": {"id": int(RUN_ID), "repository_id": recovery.github.REPOSITORY_ID,
                                            "head_repository_id": recovery.github.REPOSITORY_ID, "head_branch": "main",
                                            "head_sha": REVISION}}]
        self.set_archive([(LEDGER, json.dumps(self.ledger))])
        self.metadata = self.enterContext(patch.object(recovery.github, "_get_json", side_effect=self.read_metadata))
        self.download = self.enterContext(patch.object(recovery, "_download", side_effect=lambda *_: self.body))
        self.enterContext(patch.dict(os.environ, {"GH_TOKEN": TOKEN, "GITHUB_REPOSITORY": recovery.github.REPOSITORY}, clear=True))

    def set_archive(self, members):
        self.body = archive(members)
        self.digest = sha256(self.body).hexdigest()
        self.artifacts[0]["digest"] = "sha256:" + self.digest

    def read_metadata(self, path, token):
        self.assertEqual(token, TOKEN)
        if path == ATTEMPT_PATH:
            return self.run
        if path == ATTEMPT_PATH + "/jobs?per_page=2":
            return {"total_count": len(self.jobs), "jobs": self.jobs}
        if path == ARTIFACT_PATH:
            return {"total_count": len(self.artifacts), "artifacts": self.artifacts}
        self.fail("Unexpected request for mutable or foreign GitHub metadata.")

    def prepare(self):
        recovery.prepare(self.output, RUN_ID, ATTEMPT, REVISION, self.digest)

    def assert_rejected(self):
        with self.assertRaises(recovery.github.ArtifactError) as error:
            self.prepare()
        self.assertEqual(str(error.exception), recovery.ERROR)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_authenticates_exact_historical_attempt_and_writes_one_private_ledger(self):
        self.prepare()
        self.assertEqual([call.args[0] for call in self.metadata.call_args_list],
                         [ATTEMPT_PATH, ATTEMPT_PATH + "/jobs?per_page=2", ARTIFACT_PATH] * 2)
        self.download.assert_called_once_with(ARTIFACT_ID, TOKEN)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((self.output / LEDGER).stat().st_mode), 0o600)
        self.assertEqual(list(self.output.iterdir()), [self.output / LEDGER])
        self.assertEqual(json.loads((self.output / LEDGER).read_bytes()), self.ledger)

    def test_rejects_mismatched_attempt_repository_event_and_job(self):
        for field, value in (("run_attempt", 3), ("conclusion", "success"), ("event", "push"), ("head_branch", "feature"),
                             ("head_repository", {"id": recovery.github.REPOSITORY_ID, "full_name": "foreign/repo"})):
            with self.subTest(field=field), patch.dict(self.run, {field: value}):
                self.assert_rejected()
        for field, value in (("run_attempt", 1), ("head_sha", "d" * 40), ("name", "foreign-job")):
            with self.subTest(field=field), patch.dict(self.jobs[0], {field: value}):
                self.assert_rejected()
        self.download.assert_not_called()

    def test_requires_the_post_cleanup_recovery_upload_and_exact_success_order(self):
        with patch.dict(self.steps[-1], {"conclusion": "failure"}):
            self.assert_rejected()
        with patch.dict(self.steps[4], {"number": 14}):
            self.assert_rejected()
        with patch.dict(self.steps[-2], {"conclusion": "success"}):
            self.assert_rejected()
        self.steps.pop()
        self.assert_rejected()
        self.download.assert_not_called()

    def test_rejects_wrong_artifact_digest_scope_and_substitution_after_download(self):
        for change in ({"digest": "sha256:" + "0" * 64}, {"expired": True}, {"name": ARTIFACT_NAME + "-other"},
                       {"workflow_run": self.artifacts[0]["workflow_run"] | {"head_repository_id": 1}}):
            with self.subTest(change=change), patch.dict(self.artifacts[0], change):
                self.assert_rejected()
        self.download.assert_not_called()
        self.body += b"foreign-bytes"
        self.assert_rejected()
        self.set_archive([(LEDGER, json.dumps(self.ledger))])

        def substituted(*_):
            self.artifacts[0]["id"] += 1
            return self.body

        self.download.side_effect = substituted
        self.assert_rejected()

    def test_rejects_unsafe_members_and_non_recovery_ledgers(self):
        ledger = json.dumps(self.ledger)
        link = ZipInfo(LEDGER)
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        for members in ([(f"../{LEDGER}", ledger)], [(link, ledger)], [(LEDGER, ledger), ("another.json", "{}")],
                        [(LEDGER, json.dumps(self.ledger | {"phase": "seed"}))],
                        [(LEDGER, json.dumps(self.ledger | {"runId": "999"}))],
                        [(LEDGER, json.dumps(self.ledger | {"revision": "d" * 40}))],
                        [(LEDGER, ledger.replace('"version": 1', '"version": 1, "version": 1'))],
                        [(LEDGER, json.dumps(self.ledger | {"foreign": "unexpected"}))]):
            with self.subTest(entries=len(members)):
                self.set_archive(members)
                self.assert_rejected()

    def test_never_overwrites_existing_destination(self):
        self.output.mkdir()
        with self.assertRaises(recovery.github.ArtifactError):
            self.prepare()
        self.assertEqual(list(self.output.iterdir()), [])
        self.metadata.assert_not_called()


class StorageRequestTests(unittest.TestCase):
    def test_storage_download_is_bounded_and_uses_the_header_free_signed_request(self):
        request = Request("https://storage.example.invalid/artifact.zip?signature=fixture", headers={"Accept-Encoding": "identity"})

        class Response(BytesIO):
            status = 200
            headers = {}

        response = Response(b"x" * (recovery.MAX_ARCHIVE_BYTES + 1))
        with (
            patch.object(recovery.github, "artifact_storage_request", return_value=request) as redirect,
            patch.object(recovery.github._OPENER, "open", return_value=response) as open_storage,
        ):
            with self.assertRaises(recovery.github.ArtifactError):
                recovery._download(ARTIFACT_ID, TOKEN)
        redirect.assert_called_once_with(ARTIFACT_ID, TOKEN)
        open_storage.assert_called_once_with(request, timeout=30)
        self.assertIsNone(request.get_header("Authorization"))

"""Hosted tests for encrypted Provider messages and exact GitHub origin pins."""

from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_private_handoff as handoff
from test_production_provider import config

REVISION = "b" * 40
RUN_ID = "101"


def environment():
    target = config(active=True)
    return {"GITHUB_REPOSITORY": control.github.REPOSITORY, "GITHUB_REF": control.github.MAIN_REF,
            "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_SHA": REVISION, "GITHUB_WORKFLOW_SHA": REVISION, "GITHUB_RUN_ID": RUN_ID,
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_WORKFLOW_REF": f"{control.github.REPOSITORY}/{handoff.WORKFLOW_PATH}@{control.github.MAIN_REF}",
            "SUBS_BOT_PROVIDER_CONTROL_OPERATION": "stage",
            "SUBS_BOT_PROVIDER_CONTROL_APPROVAL": control.digest({"operation": "stage", "target": target})}


def message():
    target = config(active=True)
    return {"version": 1, "kind": "private-provider-encrypted-handoff", "phase": "intent", "runId": RUN_ID,
            "runAttempt": "1", "controllerRevision": REVISION, "operation": "stage", "target": target,
            "targetSha256": control.digest(target), "approvalSha256": control.digest({"operation": "stage", "target": target}),
            "intentSha256": None, "state": {"private": "synthetic fixture"}}


class OriginTests(unittest.TestCase):
    def test_original_zip_hash_and_single_ciphertext_are_required(self):
        def bundle(extra=False):
            output = BytesIO()
            with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
                archive.writestr("payload.age", b"encrypted fixture")
                if extra:
                    archive.writestr("unapproved.txt", b"extra")
            return output.getvalue()
        class Response(BytesIO):
            status = 200
            headers = {}
            def read1(self, size):
                return self.read(size)
        with patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "artifact_storage_request", return_value=object()), \
                patch.object(control.provenance.STORAGE_OPENER, "open") as open_storage:
            good = bundle()
            open_storage.return_value = Response(good)
            self.assertEqual(handoff.download_cipher("42", sha256(good).hexdigest()), b"encrypted fixture")
            bad = bundle(extra=True)
            open_storage.return_value = Response(bad)
            with self.assertRaises(control.ProviderError):
                handoff.download_cipher("42", sha256(bad).hexdigest())
            open_storage.return_value = Response(good)
            with self.assertRaises(control.ProviderError):
                handoff.download_cipher("42", "0" * 64)

    def metadata(self):
        artifact = {"id": 42, "expired": False, "name": "provider-encrypted-intent-101-1", "digest": "sha256:" + "d" * 64,
                    "workflow_run": {"id": 101, "head_branch": "main", "head_sha": REVISION,
                                     "repository_id": control.github.REPOSITORY_ID, "head_repository_id": control.github.REPOSITORY_ID}}
        run = {"id": 101, "run_attempt": 1, "path": handoff.WORKFLOW_PATH, "head_sha": REVISION, "head_branch": "main",
               "event": "workflow_dispatch", "repository": {"id": control.github.REPOSITORY_ID},
               "head_repository": {"id": control.github.REPOSITORY_ID}}
        job = {"name": "Provider private preflight", "run_id": 101, "run_attempt": 1, "head_sha": REVISION,
               "status": "completed", "conclusion": "success",
               "steps": [{"name": "Upload encrypted intent", "status": "completed", "conclusion": "success"}]}
        return artifact, run, job

    def test_artifact_must_match_run_digest_and_successful_expected_job(self):
        artifact, run, job = self.metadata()
        cipher = b"synthetic encrypted bytes"
        env = {**environment(), "SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARTIFACT_ID": "42",
               "SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARCHIVE_SHA256": "d" * 64,
               "SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_CIPHER_SHA256": sha256(cipher).hexdigest()}
        def get(path, _token):
            if path == "/actions/artifacts/42":
                return artifact
            if path == "/actions/runs/101/attempts/1":
                return run
            if path == "/actions/runs/101/attempts/1/jobs?per_page=100":
                return {"total_count": 1, "jobs": [job]}
            raise AssertionError("unexpected metadata path")
        with patch.dict(os.environ, env, clear=True), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "require_current_main"), patch.object(control.github, "_get_json", side_effect=get):
            handoff.verify_artifact("intent", "42", "d" * 64, sha256(cipher).hexdigest(), cipher)
            for change in ({"name": "another job"}, {"conclusion": "failure"}, {"head_sha": "c" * 40}):
                with self.subTest(change=change), patch.dict(job, change), self.assertRaises(control.ProviderError):
                    handoff.verify_artifact("intent", "42", "d" * 64, sha256(cipher).hexdigest(), cipher)
            with self.assertRaises(control.ProviderError):
                handoff.verify_artifact("intent", "42", "d" * 64, "0" * 64, cipher)
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARTIFACT_ID": "43"}), \
                    self.assertRaises(control.ProviderError):
                handoff.verify_artifact("intent", "42", "d" * 64, sha256(cipher).hexdigest(), cipher)

    def test_target_or_attempt_change_is_refused(self):
        with patch.dict(os.environ, environment(), clear=True):
            value = message()
            self.assertEqual(handoff.envelope(value, "intent"), value)
            for change in ({"targetSha256": "0" * 64}, {"runAttempt": "2"}, {"phase": "response"}):
                with self.subTest(change=change), self.assertRaises(control.ProviderError):
                    handoff.envelope({**value, **change}, "intent")


class HostedAgeTests(unittest.TestCase):
    def test_pinned_age_roundtrip_never_places_plaintext_in_ciphertext(self):
        runner_temp = os.environ.get("RUNNER_TEMP", "")
        executable = Path(runner_temp) / "provider-age/usr/bin/age-keygen"
        if not runner_temp or not executable.is_file():
            self.skipTest("The pinned hosted age package is not installed for this test job.")
        generated = subprocess.run([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
        lines = generated.stdout.decode("ascii").splitlines()
        public = next(line.removeprefix("# public key: ") for line in lines if line.startswith("# public key: "))
        identity = next(line for line in lines if line.startswith("AGE-SECRET-KEY-1"))
        env = {**environment(), "RUNNER_TEMP": runner_temp, "SUBS_BOT_PROVIDER_REHEARSAL_RECIPIENT": public,
               "SUBS_BOT_PROVIDER_REHEARSAL_RECIPIENT_SHA256": sha256(public.encode("ascii")).hexdigest(),
               "SUBS_BOT_PROVIDER_REHEARSAL_AGE_IDENTITY": identity}
        with patch.dict(os.environ, env, clear=True), patch.object(handoff, "context"), patch.object(handoff, "verify_artifact"), \
                patch.object(handoff, "download_cipher") as download:
            original = message()
            cipher = handoff.encrypt(original, "intent")
            download.return_value = cipher
            self.assertNotIn(b"synthetic fixture", cipher)
            self.assertEqual(handoff.decrypt("intent", "42", "d" * 64, sha256(cipher).hexdigest()), original)
            other = subprocess.run([str(executable)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=True)
            other_identity = next(line for line in other.stdout.decode("ascii").splitlines() if line.startswith("AGE-SECRET-KEY-1"))
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_REHEARSAL_AGE_IDENTITY": other_identity}), \
                    self.assertRaises(control.ProviderError):
                handoff.decrypt("intent", "42", "d" * 64, sha256(cipher).hexdigest())


if __name__ == "__main__":
    unittest.main()

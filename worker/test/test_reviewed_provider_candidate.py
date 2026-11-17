"""Hosted tests for the sealed-only isolated Provider candidate target."""

import base64
import ctypes
import hmac
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import reviewed_provider_candidate as candidate
from test_production_provider import config
from test_isolation_sealed_transfer import keypair


class CandidateTargetTests(unittest.TestCase):
    def test_workflow_is_default_off_and_uploads_only_ciphertext(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-candidate-target.yml").read_text()
        self.assertIn("vars.SUBS_BOT_PROVIDER_CANDIDATE_TARGET_ENABLED == 'true'", workflow)
        self.assertIn("path: ${{ runner.temp }}/provider-candidate-target.json", workflow)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", workflow)
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", workflow)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", workflow)

    def test_upgrade_keeps_the_exact_previous_and_never_activates(self):
        previous = config(active=True)
        build = {**previous["build"], "revision": "7" * 40, "runId": "101"}
        value = candidate.candidate(previous, build)
        self.assertEqual(value["previous"], previous)
        self.assertEqual((value["worker"], value["container"], value["smoke"]),
                         (previous["worker"], previous["container"], previous["smoke"]))
        self.assertEqual((value["versionId"], value["activation"], value["workflow"], value["caller"]), (None, None, None, None))
        with self.assertRaises(control.ProviderError):
            candidate.candidate(previous, previous["build"])
        previous["caller"] = {"id": "e" * 32, "name": "subs-bot-cf-control-drill-01"}
        with self.assertRaises(control.ProviderError):
            candidate.candidate(previous, build)

    def test_only_ciphertext_and_hashes_leave_the_source_job(self):
        previous = config(active=True)
        build = {**previous["build"], "revision": "7" * 40, "runId": "101"}
        with tempfile.TemporaryDirectory() as temporary:
            env = {"RUNNER_TEMP": temporary, "GITHUB_SHA": "7" * 40, "SUBS_BOT_PROVIDER_CI_RUN_ID": "101",
                   "GITHUB_WORKFLOW_REF": candidate.transfer.CANDIDATE_WORKFLOW,
                   "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(previous)}
            approved = {"mapping": "provider-archive-target", "publicKey": b"k" * 32, "keyId": "123",
                        "runId": "102", "revision": "7" * 40, "keyPinSha256": "4" * 64}
            with patch.object(candidate.transfer, "gate", return_value=approved), \
                    patch.object(candidate.transfer, "attest_provider_source", return_value={"targetSha256": control.digest(previous)}), \
                    patch.object(candidate.provenance, "prepare", return_value=build) as prepare, \
                    patch.object(candidate.transfer, "seal", return_value=b"encrypted-fixture"), \
                    patch.object(control.github, "require_current_main"):
                result = candidate.create(env)
            prepare.assert_called_once_with(provider_revision="7" * 40)
            payload = (Path(temporary) / "provider-candidate-target.json").read_text()
            self.assertNotIn(previous["service"], payload)
            self.assertEqual(set(json.loads(payload)), {"encrypted_value", "key_id"})
            self.assertFalse(result["destinationWritten"])
            self.assertFalse(result["productionMutation"])
            self.assertEqual(result["candidateTargetSha256"], control.digest(candidate.candidate(previous, build)))
            value = candidate.candidate(previous, build)
            self.assertEqual(result["approvalSha256"], control.digest({"operation": "publish-digest", "target": value}))
            self.assertEqual(result["witnessApprovalSha256"], control.digest({"operation": "publish", "target": value}))

    def test_hosted_age_identity_is_sealed_and_only_recipient_is_reported(self):
        previous = config(active=True)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "provider-age/usr/bin/age-keygen"
            binary.parent.mkdir(parents=True)
            binary.write_text("synthetic")
            env = {"RUNNER_TEMP": temporary, "GITHUB_SHA": "7" * 40, "SUBS_BOT_PROVIDER_CI_RUN_ID": "101",
                   "GITHUB_WORKFLOW_REF": candidate.transfer.CANDIDATE_WORKFLOW,
                   "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(previous)}
            approved = {"mapping": "provider-live-age-identity", "publicKey": b"k" * 32, "keyId": "123",
                        "runId": "102", "revision": "7" * 40, "keyPinSha256": "4" * 64}
            private = b"AGE-SECRET-KEY-1" + b"Q" * 58
            recipient = b"age1" + b"q" * 58
            results = [SimpleNamespace(returncode=0, stdout=b"# generated fixture\n" + private + b"\n"),
                       SimpleNamespace(returncode=0, stdout=recipient + b"\n")]
            archive_approved = {**approved, "mapping": "provider-archive-age-identity", "publicKey": b"a" * 32, "keyId": "456"}
            with patch.object(candidate.transfer, "gate", side_effect=[approved, archive_approved]), \
                    patch.object(candidate.transfer, "attest_provider_source", return_value={"targetSha256": control.digest(previous)}), \
                    patch.object(candidate.subprocess, "run", side_effect=results), \
                    patch.object(candidate.transfer, "seal", return_value=b"encrypted-fixture") as seal, \
                    patch.object(control.github, "require_current_main"):
                result = candidate.create(env)
            self.assertEqual(seal.call_count, 2)
            seal.assert_any_call(private, approved["publicKey"])
            seal.assert_any_call(private, archive_approved["publicKey"])
            payload = (Path(temporary) / "provider-candidate-target.json").read_text()
            archive_payload = (Path(temporary) / "provider-candidate-age-archive.json").read_text()
            self.assertNotIn(private.decode().strip(), payload)
            self.assertNotIn(private.decode().strip(), archive_payload)
            self.assertNotIn(private.decode().strip(), json.dumps(result))
            self.assertEqual(result["recipient"], recipient.decode())
            self.assertFalse(result["destinationWritten"])

    def test_hosted_age_keygen_seal_and_recipient_roundtrip(self):
        installed = Path(os.environ.get("RUNNER_TEMP", "/nonexistent")) / "provider-age/usr/bin/age-keygen"
        if not installed.is_file():
            self.skipTest("The pinned hosted age client is unavailable.")
        sodium, public, private = keypair()
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "provider-age/usr/bin/age-keygen"
            binary.parent.mkdir(parents=True)
            shutil.copy2(installed, binary)
            approved = {"mapping": "provider-live-age-identity", "publicKey": public, "keyId": "123",
                        "runId": "102", "revision": "7" * 40, "keyPinSha256": "4" * 64}
            archive_approved = {**approved, "mapping": "provider-archive-age-identity"}
            with patch.object(control.github, "require_current_main"), patch.object(candidate.transfer, "gate", return_value=archive_approved):
                result = candidate.seal_age_identity({"RUNNER_TEMP": temporary, "GITHUB_SHA": "7" * 40}, approved,
                                                     {"targetSha256": "1" * 64})
            sealed = base64.b64decode(json.loads((Path(temporary) / "provider-candidate-target.json").read_text())["encrypted_value"])
            message = ctypes.create_string_buffer(len(sealed) - 48)
            sodium.crypto_box_seal_open.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p)
            sodium.crypto_box_seal_open.restype = ctypes.c_int
            self.assertEqual(sodium.crypto_box_seal_open(message, sealed, len(sealed), public, private), 0)
            derived = subprocess.run([str(binary), "-y"], input=message.raw + b"\n", stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     check=True, timeout=30)
            self.assertEqual(derived.stdout.decode().strip(), result["recipient"])
            other = base64.b64decode(json.loads((Path(temporary) / "provider-candidate-age-archive.json").read_text())["encrypted_value"])
            second = ctypes.create_string_buffer(len(other) - 48)
            self.assertEqual(sodium.crypto_box_seal_open(second, other, len(other), public, private), 0)
            self.assertTrue(hmac.compare_digest(second.raw, message.raw))


if __name__ == "__main__":
    unittest.main()

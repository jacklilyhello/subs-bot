"""Hosted tests for the sealed-only isolated Provider candidate target."""

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import reviewed_provider_candidate as candidate
from test_production_provider import config


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


if __name__ == "__main__":
    unittest.main()

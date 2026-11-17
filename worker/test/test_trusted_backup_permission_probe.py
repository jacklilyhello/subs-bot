"""Hosted checks for the single-use D1 read-permission probe intent."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from hashlib import sha256
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_permission_probe as probe
from production_target import ContractError, canonical


class PermissionProbeIntentTests(unittest.TestCase):
    def env(self, output):
        return {"BACKUP_CHECKOUT_PHASE": "fixture-credential-check", "CAPACITY_FIXTURE_MODE": "probe-read-token",
                "CAPACITY_FIXTURE_REGISTRATION_JSON": json.dumps({"bucketName": "subs-bot-cf-dev-01",
                    "bucketCreatedAt": "2026-11-18T00:00:00Z", "probeDatabaseId": "00000000-0000-4000-8000-000000000001"}),
                "CAPACITY_FIXTURE_REGISTRATION_SHA256": "a" * 64, "CAPACITY_FIXTURE_BINDING_WITNESS_SHA256": "b" * 64,
                "HEAD_VALIDATION_JSON": json.dumps({"checkpointId": "0" * 31 + "1", "headSha": "c" * 40, "approvalSha256": "d" * 64}),
                "SUBS_BOT_CF_R2_METADATA_READ_TOKEN": "synthetic", "GITHUB_RUN_ID": "123", "GITHUB_SHA": "e" * 40,
                "GITHUB_OUTPUT": output}

    def test_prior_probe_or_uncertain_write_never_grants_second_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.env(str(Path(directory) / "output"))
            objects = Mock(write_credential={"fixture": True})
            metadata = Mock(root="/accounts/synthetic")
            objects.get.return_value = (b"previous", '"etag"')
            with patch.object(probe.gate, "validate"), patch.object(probe, "API", return_value=metadata), \
                 patch.object(probe, "privacy"), patch.object(probe.scoped_r2, "from_environment", return_value=objects), \
                 self.assertRaises(ContractError):
                probe.main(env)
            objects.put_once.assert_not_called()
            objects.get.return_value = (None, None)
            objects.put_once.side_effect = RuntimeError("synthetic unknown")
            with patch.object(probe.gate, "validate"), patch.object(probe, "API", return_value=metadata), \
                 patch.object(probe, "privacy"), patch.object(probe.scoped_r2, "from_environment", return_value=objects), \
                 self.assertRaises(RuntimeError):
                probe.main(env)
            objects.put_once.assert_called_once()

    def test_fresh_readback_requires_successful_candidate_and_never_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.env(str(Path(directory) / "output"))
            env["CAPACITY_FIXTURE_D1_READ_TOKEN"] = "synthetic-read"
            registration = json.loads(env["CAPACITY_FIXTURE_REGISTRATION_JSON"])
            registration.update(probeDatabaseName="subs-bot-cf-backup-permission-20261118", probeCreatedAt="2026-11-18T00:00:00Z")
            env["CAPACITY_FIXTURE_REGISTRATION_JSON"] = json.dumps(registration)
            intent = {"version": 1, "kind": "d1-read-token-negative-probe", "targetSha256": "a" * 64,
                      "probeDatabaseId": registration["probeDatabaseId"], "runId": "123", "runAttempt": "1",
                      "dispatcherRevision": "e" * 40, "controllerRevision": "c" * 40,
                      "witnessSha256": "b" * 64, "approvalSha256": "d" * 64}
            raw = canonical(intent)
            env["CAPACITY_FIXTURE_PROBE_INTENT_SHA256"] = sha256(raw).hexdigest()
            objects = Mock(write_credential=None)
            objects.get.return_value = (raw, '"etag"')
            api = Mock(side_effect=[{"uuid": registration["probeDatabaseId"], "name": registration["probeDatabaseName"],
                                     "created_at": registration["probeCreatedAt"]}, [{"success": True, "results": []}]])
            job = {"name": "validate", "run_id": 123, "run_attempt": 1, "head_sha": "e" * 40,
                   "status": "completed", "conclusion": "success", "steps": [{"name": "Run the reviewed candidate against only dedicated isolation",
                   "status": "completed", "conclusion": "success"}]}
            with patch.object(probe.gate, "validate"), patch.object(probe, "API", return_value=Mock(root="/accounts/synthetic")), \
                 patch.object(probe, "privacy"), patch.object(probe.scoped_r2, "from_environment", return_value=objects), \
                 patch.object(probe.github, "_github_token", return_value="synthetic"), \
                 patch.object(probe.github, "_get_json", return_value={"jobs": [job], "total_count": 1}), \
                 patch.object(probe, "CloudflareClient", return_value=api):
                probe.readback(env)
            objects.put_once.assert_not_called()
            self.assertEqual(api.call_count, 2)
            self.assertTrue(api.call_args_list[1].args[2]["sql"].startswith("SELECT "))


if __name__ == "__main__":
    unittest.main()

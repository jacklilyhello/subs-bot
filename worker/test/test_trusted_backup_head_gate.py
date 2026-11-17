"""Synthetic trust-boundary checks for the main-only reviewed-head gate."""
from pathlib import Path
import json
from hashlib import sha256
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_head_gate as gate
from production_target import ACCOUNT, ContractError, canonical, digest


MAIN, HEAD = "a" * 40, "b" * 40


def spec():
    return {"version": 1, "pr": "291", "headSha": HEAD, "action": "inspect",
            "registrationSha256": "c" * 64, "sourceCheckpointId": "d" * 32,
            "sourceManifestSha256": "e" * 64, "genesisSha256": "", "approvalSha256": "",
            "fault": "none", "checkpointId": "", "manifestSha256": ""}


def github(path, _token):
    if path == "/git/ref/heads/main":
        return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}}
    if path == "/pulls/291":
        return {"number": 291, "state": "open", "head": {"sha": HEAD, "ref": "codex/backup-orchestration",
                "repo": {"id": gate.github.REPOSITORY_ID}}, "base": {"ref": "main",
                "repo": {"id": gate.github.REPOSITORY_ID}}}
    if path == "/compare/" + MAIN + "..." + HEAD:
        return {"status": "ahead", "base_commit": {"sha": MAIN}, "merge_base_commit": {"sha": MAIN}}
    raise AssertionError("unexpected API request")


class TrustedGateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        Path(self.directory.name, "trusted").mkdir()
        Path(self.directory.name, "candidate").mkdir()
        self.env = {"GITHUB_REPOSITORY": gate.github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(gate.github.REPOSITORY_ID),
                    "GITHUB_REF": gate.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW_REF": gate.WORKFLOW, "RUNNER_ENVIRONMENT": "github-hosted",
                    "BACKUP_HEAD_ENVIRONMENT": gate.ENVIRONMENT, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": MAIN,
                    "GH_TOKEN": "synthetic-read-token", "BACKUP_REVIEWED_HEAD_SHA": HEAD,
                    "HEAD_VALIDATION_JSON": json.dumps(spec()), "GITHUB_WORKSPACE": self.directory.name,
                    "BACKUP_CHECKOUT_PHASE": "ready"}

    def check(self, env):
        with patch.object(gate.github, "_get_json", side_effect=github), \
             patch.object(gate, "_sha", side_effect=lambda path: MAIN if path.name == "trusted" else HEAD):
            return gate.validate(env)

    def test_exact_reviewed_head_uses_trusted_and_candidate_checkouts(self):
        result = self.check(self.env)
        self.assertEqual(result["reviewedHeadSha"], HEAD)
        self.assertEqual(result["dispatcherMainSha"], MAIN)
        self.assertTrue(result["checkoutVerified"])

    def test_capacity_gate_requires_independent_fixture_and_fresh_binding_witness(self):
        fixture = {"version": 1, "accountId": ACCOUNT, "databaseId": "00000000-0000-4000-8000-000000000001",
                   "databaseName": "subs-bot-cf-backup-capacity-20261118", "createdAt": "2026-11-18T00:00:00Z",
                   "bucketName": "subs-bot-cf-dev-01", "bucketCreatedAt": "2026-11-17T00:00:00Z",
                   "probeDatabaseId": "00000000-0000-4000-8000-000000000004",
                   "probeDatabaseName": "subs-bot-cf-backup-permission-20261118", "probeCreatedAt": "2026-11-18T00:00:00Z"}
        witness = {"version": 1, "accountId": ACCOUNT, "databaseId": fixture["databaseId"],
                   "observedAt": 1000, "workerBindingCount": 0,
                   "probeDatabaseId": fixture["probeDatabaseId"], "probeWorkerBindingCount": 0}
        original = {"accountId": ACCOUNT, "d1Id": "00000000-0000-4000-8000-000000000002", "r2CreatedOn": fixture["bucketCreatedAt"]}
        fixture_pin, witness_pin = sha256(canonical(fixture)).hexdigest(), sha256(canonical(witness)).hexdigest()
        selection = {**spec(), "action": "capacity-fixture", "approvalSha256": digest({"registrationSha256": fixture_pin,
                     "witnessSha256": witness_pin, "mode": "verify-16000"})}
        env = {**self.env, "HEAD_VALIDATION_JSON": json.dumps(selection), "BACKUP_CAPACITY_ENABLED": "true",
               "BACKUP_CHECKOUT_PHASE": "fixture-credential-check", "CAPACITY_FIXTURE_MODE": "verify-16000",
               "CAPACITY_FIXTURE_REGISTRATION_JSON": json.dumps(fixture), "CAPACITY_FIXTURE_REGISTRATION_SHA256": fixture_pin,
               "CAPACITY_FIXTURE_BINDING_WITNESS_JSON": json.dumps(witness), "CAPACITY_FIXTURE_BINDING_WITNESS_SHA256": witness_pin,
               "CAPACITY_FIXTURE_REHEARSAL_D1_ID": "00000000-0000-4000-8000-000000000003",
               "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(original)}
        with patch.object(gate.time, "time", return_value=1100):
            self.assertTrue(self.check(env)["checkoutVerified"])
            for change in ({"BACKUP_CAPACITY_ENABLED": ""}, {"CAPACITY_FIXTURE_REHEARSAL_D1_ID": fixture["databaseId"]},
                           {"CAPACITY_FIXTURE_MODE": "20001"}, {"CAPACITY_FIXTURE_BINDING_WITNESS_SHA256": "0" * 64}):
                with self.subTest(change=change), self.assertRaises(ContractError):
                    self.check({**env, **change})
            probe_spec = {**selection, "checkpointId": "0" * 31 + "1",
                          "approvalSha256": digest({"registrationSha256": fixture_pin, "witnessSha256": witness_pin,
                                                    "mode": "probe-read-token"})}
            probe = {**env, "HEAD_VALIDATION_JSON": json.dumps(probe_spec), "CAPACITY_FIXTURE_MODE": "probe-read-token"}
            self.assertTrue(self.check(probe)["checkoutVerified"])
            with self.assertRaises(ContractError):
                self.check({**probe, "HEAD_VALIDATION_JSON": json.dumps({**probe_spec, "checkpointId": ""})})
        with patch.object(gate.time, "time", return_value=2000), self.assertRaises(ContractError):
            self.check(env)

    def test_capacity_credentials_are_conditionally_injected_after_trusted_gate(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-backup-reviewed-head.yml").read_text()
        self.assertLess(workflow.index("Confirm independently pinned capacity fixture identity"),
                        workflow.index("Run the reviewed candidate against only dedicated isolation"))
        self.assertIn("SUBS_BOT_BACKUP_CAPACITY_VALIDATION_ENABLED", workflow)
        self.assertIn("CAPACITY_FIXTURE_D1_READ_TOKEN", workflow)
        self.assertIn("CAPACITY_FIXTURE_D1_WRITE_TOKEN", workflow)
        self.assertIn("!startsWith(vars.SUBS_BOT_BACKUP_CAPACITY_MODE, 'verify-')", workflow)
        self.assertIn("SUBS_BOT_CF_REHEARSAL_DATA_READ_TOKEN", workflow)
        self.assertIn("needs: [probe_intent]", workflow)
        self.assertIn("CAPACITY_FIXTURE_PROBE_INTENT_SHA256: ${{ needs.probe_intent.outputs.intent_sha256 }}", workflow)

    def test_wrong_pin_environment_or_attempt_fails_before_checkout(self):
        for changed in ({"BACKUP_REVIEWED_HEAD_SHA": "f" * 40}, {"BACKUP_HEAD_ENVIRONMENT": "subs-bot-production"},
                        {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_REF": "refs/heads/codex/backup-orchestration"},
                        {"GITHUB_EVENT_NAME": "schedule"}):
            with self.subTest(changed=changed), self.assertRaises(ContractError):
                self.check({**self.env, **changed})

    def test_candidate_checkout_must_match_independent_pin(self):
        with patch.object(gate.github, "_get_json", side_effect=github), \
             patch.object(gate, "_sha", side_effect=lambda path: MAIN if path.name == "trusted" else "f" * 40), \
             self.assertRaises(ContractError):
            gate.validate(self.env)

    def test_non_backup_action_cannot_select_fault(self):
        bad = {**spec(), "fault": "process-kill"}
        with self.assertRaises(ContractError):
            self.check({**self.env, "HEAD_VALIDATION_JSON": json.dumps(bad)})

    def test_open_backup_requires_genesis_and_rejects_injected_faults(self):
        missing = {**spec(), "action": "open-backup"}
        with self.assertRaises(ContractError):
            self.check({**self.env, "HEAD_VALIDATION_JSON": json.dumps(missing)})
        valid = {**missing, "genesisSha256": "f" * 64}
        self.assertTrue(self.check({**self.env, "HEAD_VALIDATION_JSON": json.dumps(valid)})["checkoutVerified"])
        with self.assertRaises(ContractError):
            self.check({**self.env, "HEAD_VALIDATION_JSON": json.dumps({**valid, "fault": "process-kill"})})

    def test_forked_pr_is_rejected(self):
        def fork(path, token):
            value = github(path, token)
            if path == "/pulls/291":
                value["head"]["repo"]["id"] = 999
            return value
        with patch.object(gate.github, "_get_json", side_effect=fork), \
             patch.object(gate, "_sha", return_value=MAIN), self.assertRaises(ContractError):
            gate.validate(self.env)

    def test_credential_phase_accepts_only_authorized_test_identity(self):
        test = {"botId": "9293938370", "botUsername": "test_cfsubs_bot",
                "botToken": "9293938370:SYNTHETIC_TEST_TOKEN_ONLY_12345",
                "webhookSecret": "SYNTHETIC_WEBHOOK_SECRET_ONLY_1234567890",
                "adminId": "8813701954", "memberId": "8653767757", "groupId": "-5114255828"}
        env = {**self.env, "BACKUP_CHECKOUT_PHASE": "credential-check",
               "SUBS_BOT_TELEGRAM_TEST_CONFIG": json.dumps(test)}
        self.assertTrue(self.check(env)["checkoutVerified"])
        with self.assertRaises(ContractError):
            self.check({**env, "SUBS_BOT_TELEGRAM_TEST_CONFIG": json.dumps({**test, "botId": "1000000000"})})
        with self.assertRaises(ContractError):
            self.check({**env, "SUBS_BOT_TELEGRAM_TEST_CONFIG": json.dumps({**test, "botToken": "1000000000:OTHER_BOT_TOKEN_123456789"})})

    def test_cleanup_runs_in_a_distinct_trusted_job_after_candidate(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-backup-reviewed-head.yml").read_text()
        candidate, cleanup = workflow.split("\n  trusted_cleanup:\n", 1)
        self.assertIn("needs: [validate]", cleanup)
        self.assertIn("Check out trusted current main on a fresh runner", cleanup)
        self.assertNotIn("production_backup_admission_recovery.py", candidate)
        self.assertNotIn("production_backup_webhook_recovery.py", candidate)
        self.assertNotIn("working-directory: candidate", cleanup)
        self.assertLess(cleanup.index("Trusted inspect original webhook snapshot"), cleanup.index("Trusted close and freeze isolated admission"))
        self.assertLess(cleanup.index("Trusted close and freeze isolated admission"), cleanup.index("Trusted restore original test webhook"))
        self.assertIn("${{ needs.validate.outputs.snapshot_sha256 }}", cleanup)


if __name__ == "__main__":
    unittest.main()

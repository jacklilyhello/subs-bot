"""Synthetic trust-boundary checks for the main-only reviewed-head gate."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_head_gate as gate
from production_target import ContractError


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


if __name__ == "__main__":
    unittest.main()

"""Exact reviewed-head and dedicated environment guards; hosted CI only."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_head_harness as harness
from production_target import ContractError


HEAD, MAIN = "a" * 40, "b" * 40
BRANCH = "codex/backup-orchestration"


def environment(workspace):
    return {"GITHUB_REPOSITORY": harness.artifact.REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(harness.artifact.REPOSITORY_ID),
            "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
            "SUBS_BOT_CONTROL_ENVIRONMENT": "subs-bot-isolation", "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW_REF": harness.artifact.REPOSITORY + "/" + harness.FILE + "@refs/heads/main",
            "GITHUB_SHA": MAIN, "HEAD_TRUSTED_MAIN_SHA": MAIN, "HEAD_TRUSTED_REVIEWED_SHA": HEAD,
            "HEAD_VALIDATION_SHA": HEAD, "HEAD_VALIDATION_PR": "291", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKSPACE": workspace}


def github(path, _token):
    if path == "/pulls/291":
        return {"number": 291, "state": "open", "head": {"sha": HEAD, "ref": BRANCH,
                "repo": {"id": harness.artifact.REPOSITORY_ID}}, "base": {"ref": "main",
                "repo": {"id": harness.artifact.REPOSITORY_ID}}}
    if path == "/git/ref/heads/main":
        return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}}
    if path == "/compare/" + MAIN + "..." + HEAD:
        return {"status": "ahead", "base_commit": {"sha": MAIN}, "merge_base_commit": {"sha": MAIN}}
    raise AssertionError("unexpected request")


class HeadGuardTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        Path(self.directory.name, "trusted").mkdir()
        Path(self.directory.name, "candidate").mkdir()
        self.env = environment(self.directory.name)

    def test_exact_same_repository_pr_head_and_main_ancestor(self):
        with patch.object(harness.artifact, "_github_token", return_value="synthetic"), \
             patch.object(harness.artifact, "_get_json", side_effect=github), \
             patch.object(harness, "checkout_sha", side_effect=lambda path: MAIN if path.name == "trusted" else HEAD):
            self.assertEqual(harness.verified_head(self.env), (HEAD, BRANCH))

    def test_stale_head_wrong_environment_and_retries_are_rejected(self):
        for update in ({"HEAD_VALIDATION_SHA": "c" * 40}, {"SUBS_BOT_CONTROL_ENVIRONMENT": "subs-bot-production"},
                       {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_EVENT_NAME": "schedule"},
                       {"GITHUB_REF": "refs/heads/codex/backup-orchestration"},
                       {"HEAD_TRUSTED_MAIN_SHA": "c" * 40}, {"HEAD_TRUSTED_REVIEWED_SHA": "c" * 40}):
            with self.subTest(update=update), self.assertRaises(ContractError):
                harness.verified_head({**self.env, **update})

    def test_divergent_main_or_forked_head_is_rejected(self):
        def wrong(path, token):
            value = github(path, token)
            if path == "/pulls/291":
                value["head"]["repo"]["id"] = 123
            return value
        with patch.object(harness.artifact, "_github_token", return_value="synthetic"), \
             patch.object(harness.artifact, "_get_json", side_effect=wrong), self.assertRaises(ContractError):
            harness.verified_head(self.env)

    def test_changed_candidate_checkout_is_rejected(self):
        with patch.object(harness.artifact, "_github_token", return_value="synthetic"), \
             patch.object(harness.artifact, "_get_json", side_effect=github), \
             patch.object(harness, "checkout_sha", side_effect=lambda path: MAIN if path.name == "trusted" else "c" * 40), \
             self.assertRaises(ContractError):
            harness.verified_head(self.env)


if __name__ == "__main__":
    unittest.main()

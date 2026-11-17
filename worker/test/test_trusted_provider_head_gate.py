"""Hosted synthetic authorization checks for the trusted Provider head gate."""
from pathlib import Path
import json
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_provider_head_gate as gate
from production_target import ContractError
from test_production_provider import config

MAIN, HEAD = "a" * 40, "b" * 40


def spec():
    target = config(active=True)
    return {"version": 1, "pr": "290", "headSha": HEAD, "providerCiRunId": target["build"]["runId"],
            "approvalSha256": gate.provider.digest({"operation": "publish", "target": target}),
            "archiveRefs": [{"kind": "complete", "runId": "101", "runAttempt": "1",
                             "manifestSha256": "c" * 64, "targetSha256": "d" * 64}],
            "simulateActionsUnavailable": True}


def github(path, _token):
    if path == "/git/ref/heads/main":
        return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}}
    if path == "/pulls/290":
        return {"number": 290, "state": "open", "head": {"sha": HEAD, "ref": "codex/provider-durable-source",
                "repo": {"id": gate.github.REPOSITORY_ID}}, "base": {"ref": "main", "repo": {"id": gate.github.REPOSITORY_ID}}}
    if path == "/compare/" + MAIN + "..." + HEAD:
        return {"status": "ahead", "base_commit": {"sha": MAIN}, "merge_base_commit": {"sha": MAIN}}
    raise AssertionError("unexpected API request")


class TrustedProviderGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        Path(self.temporary.name, "trusted").mkdir()
        Path(self.temporary.name, "candidate").mkdir()
        self.env = {"GITHUB_REPOSITORY": gate.github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(gate.github.REPOSITORY_ID),
                    "GITHUB_REF": gate.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW_REF": gate.WORKFLOW, "GITHUB_WORKFLOW_SHA": MAIN, "RUNNER_ENVIRONMENT": "github-hosted",
                    "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": MAIN, "GH_TOKEN": "synthetic-token",
                    "PROVIDER_REVIEWED_HEAD_SHA": HEAD, "PROVIDER_HEAD_VALIDATION_JSON": json.dumps(spec()),
                    "GITHUB_WORKSPACE": self.temporary.name, "PROVIDER_HEAD_PHASE": "sources",
                    "PROVIDER_HEAD_ENVIRONMENT": "subs-bot-provider-archive-head-isolation", "PROVIDER_HEAD_CHECK": "ready"}

    def check(self, env):
        with patch.object(gate.github, "_get_json", side_effect=github), \
                patch.object(gate, "checkout_sha", side_effect=lambda path: MAIN if path.name == "trusted" else HEAD):
            return gate.validate(env)

    def test_exact_main_and_independently_reviewed_head(self):
        result = self.check(self.env)
        self.assertEqual((result["trustedMainSha"], result["reviewedHeadSha"]), (MAIN, HEAD))

    def test_workflow_keeps_private_keys_and_r2_writes_out_of_provider_jobs(self):
        text = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-reviewed-head.yml").read_text()
        self.assertIn("vars.SUBS_BOT_PROVIDER_HEAD_VALIDATION_ENABLED == 'true'", text)
        self.assertNotIn("uses: actions/upload-artifact@", text)
        jobs = ("verify_sources", "attest_r2", "attest_provider")
        for index, name in enumerate(jobs):
            section = text.split(f"\n  {name}:\n", 1)[1]
            if index + 1 < len(jobs):
                section = section.split(f"\n  {jobs[index + 1]}:\n", 1)[0]
            self.assertIn("uses: ./trusted/.github/actions/provider-reviewed-head-gate", section)
            self.assertNotIn("SUBS_BOT_PROVIDER_REHEARSAL_AGE_IDENTITY", section)
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", section)
            if name == "attest_provider":
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", section)
            else:
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", section)
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_READ_TOKEN", section)
            if name.startswith("attest_"):
                self.assertNotIn("python3 -B worker/tools/production_provider_reviewed_head_harness.py", section)
                self.assertIn("python3 -B trusted/worker/tools/trusted_provider_head_attestation.py", section)

    def test_wrong_head_environment_or_attempt_is_rejected(self):
        for change in ({"PROVIDER_REVIEWED_HEAD_SHA": "f" * 40}, {"PROVIDER_HEAD_ENVIRONMENT": "subs-bot-production"},
                       {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_WORKFLOW_SHA": HEAD}, {"GITHUB_EVENT_NAME": "pull_request"}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.check({**self.env, **change})

    def test_production_archive_and_non_simulated_input_are_rejected(self):
        for change in ({"simulateActionsUnavailable": False},
                       {"archiveRefs": [{**spec()["archiveRefs"][0], "kind": "production"}]}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.check({**self.env, "PROVIDER_HEAD_VALIDATION_JSON": json.dumps({**spec(), **change})})

    def test_exact_isolated_contract_and_approval_are_required_before_credentials(self):
        target = config(active=True)
        bucket = {"accountId": "9431815bdb8beb2272f6668e06b7d3be", "namespace": "lilyya",
                  "r2CreatedOn": "2026-11-16T00:00:00.123Z"}
        env = {**self.env, "PROVIDER_HEAD_CHECK": "credential", "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(target),
               "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": json.dumps(bucket),
               "SUBS_BOT_PROVIDER_REVIEWED_ARCHIVE_REFS_JSON": json.dumps(spec()["archiveRefs"])}
        self.assertTrue(self.check(env)["checkoutVerified"])
        with self.assertRaises(ContractError):
            self.check({**env, "SUBS_BOT_PROVIDER_REVIEWED_ARCHIVE_REFS_JSON": "[]"})
        target["caller"] = {"id": "e" * 32, "name": "subs-bot-cf-control-drill-01"}
        with self.assertRaises(ContractError):
            self.check({**env, "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(target)})


if __name__ == "__main__":
    unittest.main()

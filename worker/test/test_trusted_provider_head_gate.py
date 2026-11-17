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
                self.assertNotIn("SUBS_BOT_SCOPED_R2_READ_JSON", section)
            else:
                self.assertIn("SUBS_BOT_SCOPED_R2_READ_JSON", section)
                self.assertIn("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", section)
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

    def test_digest_dispatcher_requires_the_exact_isolated_phase_and_digest_approval(self):
        target = config(active=True)
        bucket = {"accountId": "9431815bdb8beb2272f6668e06b7d3be", "namespace": "lilyya",
                  "r2CreatedOn": "2026-11-16T00:00:00.123Z"}
        approved = {**spec(), "approvalSha256": gate.provider.digest({"operation": "publish-digest", "target": target})}
        env = {**self.env, "GITHUB_WORKFLOW_REF": gate.DIGEST_WORKFLOW,
               "PROVIDER_HEAD_PHASE": "digest-publish", "PROVIDER_HEAD_ENVIRONMENT": "subs-bot-provider-head-isolation",
               "PROVIDER_HEAD_CHECK": "credential", "PROVIDER_HEAD_VALIDATION_JSON": json.dumps(approved),
               "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(target),
               "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": json.dumps(bucket),
               "SUBS_BOT_PROVIDER_REVIEWED_ARCHIVE_REFS_JSON": json.dumps(approved["archiveRefs"])}
        self.assertTrue(self.check(env)["checkoutVerified"])
        for change in ({"PROVIDER_HEAD_PHASE": "attest-provider"},
                       {"PROVIDER_HEAD_ENVIRONMENT": "subs-bot-provider-archive-head-isolation"},
                       {"PROVIDER_HEAD_VALIDATION_JSON": json.dumps(spec())},
                       {"GITHUB_WORKFLOW_SHA": HEAD}, {"PROVIDER_REVIEWED_HEAD_SHA": MAIN}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.check({**env, **change})
        source = {**env, "GITHUB_WORKFLOW_REF": f"{gate.github.REPOSITORY}/{gate.SOURCE_WORKFLOW_PATH}@{gate.github.MAIN_REF}",
                  "PROVIDER_HEAD_PHASE": "isolated-source", "PROVIDER_HEAD_ENVIRONMENT": "subs-bot-provider-archive-head-isolation",
                  "PROVIDER_HEAD_VALIDATION_JSON": json.dumps({**approved, "simulateActionsUnavailable": False})}
        self.assertTrue(self.check(source)["checkoutVerified"])
        with self.assertRaises(ContractError):
            self.check({**source, "PROVIDER_HEAD_PHASE": "isolated-source-readback"})
        with self.assertRaises(ContractError):
            self.check({**source, "PROVIDER_HEAD_VALIDATION_JSON": json.dumps(approved)})
        operation = {**env, "GITHUB_WORKFLOW_REF": gate.OPERATION_WORKFLOW, "PROVIDER_HEAD_PHASE": "operation-dispatch"}
        self.assertTrue(self.check(operation)["checkoutVerified"])
        with self.assertRaises(ContractError):
            self.check({**operation, "PROVIDER_HEAD_PHASE": "digest-publish"})
        recovery = {**env, "GITHUB_WORKFLOW_REF": gate.RECOVERY_WORKFLOW, "PROVIDER_HEAD_PHASE": "recovery-inspect",
                    "PROVIDER_RECOVERY_POLICY_JSON": json.dumps({"version": 1, "enabled": True, "writeEnabled": False})}
        self.assertTrue(self.check(recovery)["checkoutVerified"])
        with self.assertRaises(ContractError):
            self.check({**recovery, "PROVIDER_HEAD_PHASE": "operation-dispatch"})
        with self.assertRaises(ContractError):
            self.check({**recovery, "PROVIDER_RECOVERY_POLICY_JSON": ""})
        with self.assertRaises(ContractError):
            self.check({**recovery, "PROVIDER_HEAD_PHASE": "recovery-archive",
                        "PROVIDER_HEAD_ENVIRONMENT": "subs-bot-provider-archive-head-isolation"})

    def test_digest_dispatcher_uses_fresh_gated_jobs_and_is_default_off(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-reviewed-digest.yml").read_text()
        self.assertIn("vars.SUBS_BOT_PROVIDER_REVIEWED_DIGEST_ENABLED == 'true'", workflow)
        self.assertIn("vars.SUBS_BOT_PROVIDER_DIGEST_WRITE_ENABLED == 'true'", workflow)
        jobs = ("source", "preflight", "intent_write", "intent_readback", "publish", "verify", "completion_write", "evidence_readback")
        self.assertEqual(workflow.count("uses: ./trusted/.github/actions/provider-reviewed-head-gate"), len(jobs))
        self.assertEqual(workflow.count("path: trusted"), len(jobs))
        self.assertEqual(workflow.count("reviewed_head_sha: ${{ vars.SUBS_BOT_PROVIDER_REVIEWED_HEAD_SHA }}"), len(jobs))
        for index, name in enumerate(jobs):
            section = workflow.split(f"\n  {name}:\n", 1)[1]
            if index + 1 < len(jobs):
                section = section.split(f"\n  {jobs[index + 1]}:\n", 1)[0]
            self.assertLess(section.index("uses: ./trusted/.github/actions/provider-reviewed-head-gate"), section.index("working-directory: candidate"))
            if name in ("preflight", "publish", "verify"):
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", section)
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", section)
                self.assertNotIn("SUBS_BOT_SCOPED_R2_READ_JSON", section)
                self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", section)
            else:
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", section)
                self.assertNotIn("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", section)
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", section)
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", section)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("path: ${{ runner.temp }}/provider-source-transfer.age", workflow)
        self.assertIn("needs: [source, preflight, intent_readback]", workflow)
        installer = Path(__file__).resolve().parents[1] / "tools/install_provider_age.sh"
        self.assertTrue(installer.is_file())
        self.assertIn("22ed034e16d8a7662d94dbb8d9f644f01284c6d87bc6b619903e38ba91125337", installer.read_text())

    def test_reviewed_source_seal_and_readback_are_default_off_and_scoped(self):
        root = Path(__file__).resolve().parents[2] / ".github/workflows"
        seal = (root / "worker-provider-reviewed-isolated-source.yml").read_text()
        readback = (root / "worker-provider-reviewed-isolated-source-readback.yml").read_text()
        for text in (seal, readback):
            self.assertIn("vars.SUBS_BOT_PROVIDER_REVIEWED_SOURCE_ENABLED == 'true'", text)
            self.assertIn("uses: ./trusted/.github/actions/provider-reviewed-head-gate", text)
            self.assertIn("SUBS_BOT_SCOPED_R2_READ_JSON", text)
            self.assertIn("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", text)
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", text)
            self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", text)
        self.assertIn("vars.SUBS_BOT_PROVIDER_REVIEWED_SOURCE_WRITE_ENABLED == 'true'", seal)
        self.assertIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", seal)
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", readback)

    def test_reviewed_operation_is_default_off_and_separates_write_domains(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-reviewed-operation.yml").read_text()
        self.assertIn("vars.SUBS_BOT_PROVIDER_REVIEWED_OPERATION_ENABLED == 'true'", workflow)
        self.assertIn("vars.SUBS_BOT_PROVIDER_OPERATION_WRITE_ENABLED == 'true'", workflow)
        self.assertEqual(workflow.count("uses: ./trusted/.github/actions/provider-reviewed-head-gate"), 10)
        section = workflow.split("\n  dispatch:\n", 1)[1].split("\n  verify:\n", 1)[0]
        self.assertIn("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", section)
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", section)
        self.assertIn("Preserve encrypted response-only observation", section)
        self.assertIn("if: always()", section)
        self.assertIn("needs.evidence_readback.result != 'success'", workflow)
        self.assertIn("SUBS_BOT_PROVIDER_MUTATION_ACTION: failure-readback", workflow)
        self.assertIn("SUBS_BOT_PROVIDER_MUTATION_RESOLUTIONS_JSON", workflow)
        prepare = section.split("- name: Prepare the exact image once", 1)[1].split("- name: Dispatch the exact approved Worker operation once", 1)[0]
        self.assertIn("secrets.SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", prepare)
        self.assertNotIn("secrets.SUBS_BOT_CF_PROVIDER_WORKER_WRITE_TOKEN", prepare)
        dispatch = section.split("- name: Dispatch the exact approved Worker operation once", 1)[1]
        self.assertNotIn("secrets.SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", dispatch)
        reconcile = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-reviewed-operation-reconcile.yml").read_text()
        self.assertIn("vars.SUBS_BOT_PROVIDER_REVIEWED_OPERATION_RECONCILE_ENABLED == 'true'", reconcile)
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", reconcile)

    def test_production_archive_and_non_simulated_input_are_rejected(self):
        for change in ({"simulateActionsUnavailable": False},
                       {"archiveRefs": [{**spec()["archiveRefs"][0], "kind": "production"}]}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.check({**self.env, "PROVIDER_HEAD_VALIDATION_JSON": json.dumps({**spec(), **change})})

    def test_recovery_is_default_off_and_contains_no_provider_write_credential(self):
        root = Path(__file__).resolve().parents[2] / ".github/workflows"
        workflow = (root / "worker-provider-reviewed-recovery.yml").read_text()
        self.assertIn("vars.SUBS_BOT_PROVIDER_RECOVERY_ENABLED == 'true'", workflow)
        self.assertIn("vars.SUBS_BOT_PROVIDER_RECOVERY_WRITE_ENABLED == 'true'", workflow)
        self.assertEqual(workflow.count("uses: ./trusted/.github/actions/provider-reviewed-head-gate"), 3)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_WORKER_WRITE_TOKEN", workflow)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", workflow)
        inspect = workflow.split("\n  inspect:\n", 1)[1].split("\n  archive:\n", 1)[0]
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", inspect)
        archive = workflow.split("\n  archive:\n", 1)[1].split("\n  readback:\n", 1)[0]
        self.assertIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", archive)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_WORKER_READ_TOKEN", archive)
        readback = workflow.split("\n  readback:\n", 1)[1]
        self.assertNotIn("SUBS_BOT_SCOPED_R2_WRITE_JSON", readback)

    def test_independently_registered_isolated_source_accepts_only_first_attempt(self):
        ref = {**spec()["archiveRefs"][0], "kind": "isolated-source", "runAttempt": "1"}
        self.assertEqual(self.check({**self.env, "PROVIDER_HEAD_VALIDATION_JSON": json.dumps({**spec(), "archiveRefs": [ref]})})["reviewedHeadSha"], HEAD)
        with self.assertRaises(ContractError):
            self.check({**self.env, "PROVIDER_HEAD_VALIDATION_JSON": json.dumps({**spec(), "archiveRefs": [{**ref, "runAttempt": "2"}]})})

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

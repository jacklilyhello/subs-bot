"""Synthetic checks for the default-disabled reviewed rehearsal phase gate."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_phase_gate as gate
from production_target import ContractError, canonical

MAIN, HEAD = "a" * 40, "b" * 40
SPEC = {"version": 1, "pr": "302", "headSha": HEAD, "registrationSha256": "c" * 64,
        "sourceCheckpointId": "d" * 32, "sourceManifestSha256": "e" * 64,
        "genesisSha256": "f" * 64, "checkpointId": "1" * 32}


def github(path, _token):
    if path == "/git/ref/heads/main":
        return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": MAIN}}
    if path == "/pulls/302":
        return {"number": 302, "state": "open", "head": {"sha": HEAD, "ref": "codex/backup-coordinator",
                "repo": {"id": gate.github.REPOSITORY_ID}}, "base": {"ref": "main", "repo": {"id": gate.github.REPOSITORY_ID}}}
    if path == "/compare/" + MAIN + "..." + HEAD:
        return {"status": "ahead", "base_commit": {"sha": MAIN}, "merge_base_commit": {"sha": MAIN}}
    raise AssertionError("unexpected API request")


class TrustedPhaseGateTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        Path(directory.name, "trusted").mkdir()
        Path(directory.name, "candidate").mkdir()
        self.env = {"GITHUB_REPOSITORY": gate.github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(gate.github.REPOSITORY_ID),
                    "GITHUB_REF": gate.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_WORKFLOW_REF": gate.github.REPOSITORY + "/" + gate.FILE + "@" + gate.github.MAIN_REF,
                    "GITHUB_WORKFLOW_SHA": MAIN, "GITHUB_SHA": MAIN, "RUNNER_ENVIRONMENT": "github-hosted",
                    "BACKUP_GATE_ROLE": "child", "BACKUP_HEAD_ENVIRONMENT": gate.ENVIRONMENT, "GITHUB_RUN_ATTEMPT": "1",
                    "SUBS_BOT_BACKUP_PHASE_REHEARSAL_ENABLED": "true", "SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED": "true",
                    "BACKUP_REVIEWED_HEAD_SHA": HEAD, "GH_TOKEN": "synthetic-token", "GITHUB_WORKSPACE": directory.name,
                    "HEAD_VALIDATION_JSON": canonical(SPEC).decode(), "BACKUP_CHECKOUT_PHASE": "ready",
                    "BACKUP_PHASE_REGISTRATION_SHA256": SPEC["registrationSha256"],
                    "BACKUP_PHASE_SOURCE_CHECKPOINT_ID": SPEC["sourceCheckpointId"],
                    "BACKUP_PHASE_SOURCE_MANIFEST_SHA256": SPEC["sourceManifestSha256"],
                    "BACKUP_PHASE_GENESIS_SHA256": SPEC["genesisSha256"], "BACKUP_PHASE_CHECKPOINT_ID": SPEC["checkpointId"],
                    "BACKUP_SOURCE_CHECKPOINT_ID": SPEC["sourceCheckpointId"], "BACKUP_SOURCE_MANIFEST_SHA256": SPEC["sourceManifestSha256"],
                    "BACKUP_ACTION": "plan-begin", "BACKUP_DISPATCH_NONCE": "2" * 64,
                    "BACKUP_COORDINATOR_SESSION": "123", "BACKUP_DISPATCH_DEADLINE": "0"}

    def check(self, env):
        with patch.object(gate.github, "_get_json", side_effect=github), \
             patch.object(gate, "checkout_sha", side_effect=lambda path: MAIN if path.name == "trusted" else HEAD):
            return gate.validate(env)

    def test_child_pins_and_default_off_claim_gate(self):
        self.assertEqual(self.check(self.env)["reviewedHeadSha"], HEAD)
        for change in ({"SUBS_BOT_BACKUP_PHASE_REHEARSAL_ENABLED": ""},
                       {"SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED": ""},
                       {"BACKUP_REVIEWED_HEAD_SHA": "0" * 40}, {"BACKUP_PHASE_GENESIS_SHA256": "0" * 64},
                       {"GITHUB_RUN_ATTEMPT": "2"}, {"BACKUP_HEAD_ENVIRONMENT": "subs-bot-production"}):
            with self.subTest(change=change), self.assertRaises(ContractError):
                self.check({**self.env, **change})

    def test_parent_has_fixed_workflow_and_separate_write_gate(self):
        parent = {**self.env, "BACKUP_GATE_ROLE": "parent", "BACKUP_ACTION": "plan-run",
                  "GITHUB_WORKFLOW_REF": gate.github.REPOSITORY + "/" + gate.PARENT_FILE + "@" + gate.github.MAIN_REF,
                  "SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED": ""}
        self.check(parent)
        with self.assertRaises(ContractError):
            self.check({**parent, "BACKUP_ACTION": "run"})
        with self.assertRaises(ContractError):
            self.check({**parent, "GITHUB_WORKFLOW_REF": self.env["GITHUB_WORKFLOW_REF"]})

    def test_same_source_and_destination_checkpoint_fails(self):
        spec = {**SPEC, "checkpointId": SPEC["sourceCheckpointId"]}
        with self.assertRaises(ContractError):
            self.check({**self.env, "HEAD_VALIDATION_JSON": canonical(spec).decode(),
                        "BACKUP_PHASE_CHECKPOINT_ID": spec["checkpointId"]})

    def test_rehearsal_workflows_gate_before_candidate_secrets(self):
        root = Path(__file__).resolve().parents[2] / ".github/workflows"
        for workflow in ("worker-backup-phase-rehearsal.yml", "worker-backup-reviewed-coordinator.yml"):
            text = (root / workflow).read_text()
            self.assertLess(text.index("BACKUP_CHECKOUT_PHASE: ready"), text.index("SUBS_BOT_CONTROL_DRILL_KEYS:"))
            self.assertIn("SUBS_BOT_BACKUP_PHASE_REHEARSAL_ENABLED: ${{ vars.SUBS_BOT_BACKUP_PHASE_REHEARSAL_ENABLED }}", text)
            self.assertNotIn("subs-bot-lifecycle-production", text)

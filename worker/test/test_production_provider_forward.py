"""Hosted-only checks of failed-terminal provenance and explicit forward approval."""

from copy import deepcopy
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import production_provider_forward as forward
from test_production_provider import config, REVISION


def recovery(previous):
    return {"version": 1, "sourceRunId": "100", "sourceRunAttempt": "1", "sourceManifestSha256": "1" * 64,
            "responseIdentitySha256": "2" * 64, "previousTargetSha256": control.digest(previous), "terminalSha256": "3" * 64}


class ForwardApprovalTests(unittest.TestCase):
    def test_forward_contract_pins_the_complete_distinct_previous_release(self):
        previous = config(active=True)
        current = config()
        current.update({"versionId": None, "container": previous["container"], "previous": previous,
                        "forwardRecovery": recovery(previous)})
        current["build"]["revision"] = "7" * 40
        self.assertEqual(control.validate_config(current), current)
        # A later application's precisely pinned caller is still supported;
        # live upgrade and terminal guards separately require no bound caller.
        current["caller"] = {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}
        self.assertEqual(control.validate_config(current), current)
        for changed in ({"previousTargetSha256": "8" * 64}, {"terminalSha256": ""}, {"version": True}, {"unknown": True}):
            invalid = deepcopy(current)
            invalid["forwardRecovery"].update(changed)
            with self.subTest(changed=changed), self.assertRaises(control.ProviderError):
                control.validate_config(invalid)
        current["previous"]["workflow"] = None
        current["forwardRecovery"]["previousTargetSha256"] = control.digest(current["previous"])
        with self.assertRaises(control.ProviderError):
            control.validate_config(current)

    def test_receipt_must_belong_to_this_exact_run_source_and_immutable_artifact(self):
        env = {"GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": REVISION}
        metadata = {"name": "subs-bot-provider-terminal-request-100-1", "expired": False, "digest": "sha256:" + "7" * 64,
                    "workflow_run": {"id": 100, "repository_id": control.github.REPOSITORY_ID,
                                     "head_branch": "main", "head_sha": REVISION}}
        with patch.dict(os.environ, env), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=metadata):
            forward.artifact_receipt("200", "7" * 64, "subs-bot-provider-terminal-request")
            for changed in ({"expired": True}, {"digest": "sha256:" + "8" * 64}, {"name": "foreign-artifact"},
                            {"workflow_run": {**metadata["workflow_run"], "head_sha": "9" * 40}}):
                original = deepcopy(metadata)
                metadata.update(changed)
                with self.subTest(changed=changed), self.assertRaises(control.ProviderError):
                    forward.artifact_receipt("200", "7" * 64, "subs-bot-provider-terminal-request")
                metadata.clear()
                metadata.update(original)

    def test_forward_live_terminal_cannot_be_changed_or_reused_for_the_same_source(self):
        previous = config(active=True)
        current = config()
        current.update({"versionId": None, "container": previous["container"], "previous": previous,
                        "forwardRecovery": recovery(previous)})
        current["build"]["revision"] = "7" * 40
        proof = {"status": "failed-terminal-preserved", "completion": "not-complete"}
        current["forwardRecovery"]["terminalSha256"] = control.digest(proof)
        api = Mock(config=current)
        with patch("production_provider_terminal.verify_forced_terminal", return_value=proof) as reader:
            self.assertEqual(control.verify_previous_terminal(api, previous, {}), proof)
            reader.assert_called_once_with(api, previous, current_config=current)
        with patch("production_provider_terminal.verify_forced_terminal", return_value={**proof, "changed": True}), \
                self.assertRaises(control.ProviderError):
            control.verify_previous_terminal(api, previous, {})
        current["build"]["revision"] = previous["build"]["revision"]
        with patch("production_provider_terminal.verify_forced_terminal") as reader, self.assertRaises(control.ProviderError):
            control.verify_previous_terminal(api, previous, {})
        reader.assert_not_called()


if __name__ == "__main__":
    unittest.main()

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


class ForwardStageReadbackTests(unittest.TestCase):
    def setUp(self):
        from test_production_provider import DEPLOYMENT
        previous = config(active=True)
        self.proof = {"status": "failed-terminal-preserved", "completion": "not-complete", "processSha256": "6" * 64}
        self.target = config()
        self.target.update({"versionId": DEPLOYMENT, "container": previous["container"], "previous": previous,
                            "forwardRecovery": {**recovery(previous), "terminalSha256": control.digest(self.proof)}})
        self.target["build"]["revision"] = "7" * 40
        self.api = Mock(config=self.target)
        self.api._request.return_value = {"result": [{"id": self.target["versionId"]}, {"id": previous["versionId"]}],
                                         "result_info": {"page": 1, "per_page": 10, "count": 2, "total_count": 2}}
        self.state = {key: previous[key] for key in ("activation", "container", "workflow")}
        self.state["instance"] = {"status": "complete"}

    def test_existing_stage_is_registered_only_after_live_state_and_old_terminal_checks(self):
        with patch.object(control, "observe", return_value=self.state) as observe, \
                patch.object(forward, "verify_forced_terminal", return_value=self.proof) as terminal:
            self.assertEqual(forward.confirmed_forward_stage(self.api, self.target), self.target)
        self.assertEqual(observe.call_count, 2)
        terminal.assert_called_once()
        self.api.upload.assert_not_called()
        self.api.trigger.assert_not_called()
        self.api.deploy.assert_not_called()

    def test_current_resource_drift_or_different_old_terminal_never_registers(self):
        for changed in ({**self.state, "activation": None}, {**self.state, "workflow": None},
                        {**self.state, "container": None}):
            with patch.object(control, "observe", return_value=changed), \
                    patch.object(forward, "verify_forced_terminal", return_value=self.proof), self.assertRaises(control.ProviderError):
                forward.confirmed_forward_stage(self.api, self.target)
        with patch.object(control, "observe", return_value=self.state), \
                patch.object(forward, "verify_forced_terminal", return_value={**self.proof, "changed": True}), \
                self.assertRaises(control.ProviderError):
            forward.confirmed_forward_stage(self.api, self.target)
        with patch.object(control, "observe", side_effect=[self.state, {**self.state, "instance": None}]), \
                patch.object(forward, "verify_forced_terminal", return_value=self.proof), self.assertRaises(control.ProviderError):
            forward.confirmed_forward_stage(self.api, self.target)

    def test_missing_new_pin_old_version_or_bound_caller_is_refused_before_read(self):
        for changed in ({"versionId": None}, {"versionId": self.target["previous"]["versionId"]},
                        {"caller": {"id": "5" * 32, "name": "subs-bot-cf-control-drill-01"}}):
            invalid = deepcopy(self.target)
            invalid.update(changed)
            with patch.object(control, "observe") as observe, self.subTest(changed=changed), self.assertRaises(ValueError):
                forward.confirmed_forward_stage(Mock(config=invalid), invalid)
            observe.assert_not_called()


if __name__ == "__main__":
    unittest.main()

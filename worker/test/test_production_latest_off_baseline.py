"""Hosted checks that the latest off candidate seals new writes independently."""
from copy import deepcopy
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_lifecycle_drill as drill
import production_recovery as recovery
import production_release_evidence as evidence
import production_target as contract
import test_production_control as control_fixtures
import test_production_lifecycle_drill as fixtures

ON, OFF, MANIFEST = "a" * 32, "b" * 32, "c" * 64


class LatestOffBaselineTests(unittest.TestCase):
    def tool(self):
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        tool = drill.Drill({**fixtures.environment(), "RUNNER_TEMP": directory.name})
        tool.store = fixtures.MemoryStore()
        target, _ = control_fixtures.fixture()
        controller = Mock(target=target, revision=control_fixtures.REVISION)
        controller.inspect.return_value = {"control": {"admission": "closed", "workers": "frozen"},
            "work": {"invocations": 0}, "terminal": {"unknownUpdates": 0}}
        tool.controller = controller
        tool.code_archive = Mock(return_value=({"revision": controller.revision}, b"synthetic reviewed complete ZIP"))
        tool.report.update(activationBaseline={"checkpointId": ON, "manifestSha256": "d" * 64,
            "verification": {"configurationSha256": "e" * 64}}, baselineReused=False)
        return tool

    def proof(self, tool):
        return {"baselineVerified": True, "checkpointId": OFF, "manifestSha256": MANIFEST,
            "targetSha256": tool.controller.target.digest, "configurationSha256": tool.controller.target.configuration_digest,
            "sourceRevision": tool.controller.revision, "mutationPerformed": False}

    def capture(self, tool, *, failure=None, changed_proof=None):
        order = []
        def action(name, _engine):
            order.append(name)
            if failure == name:
                raise recovery.RecoveryError("Synthetic backup interruption.")
            return {"backup": {"manifestSha256": MANIFEST}}
        def verify(*_args):
            order.append("independent-full-readback")
            if failure == "readback":
                raise recovery.RecoveryError("Synthetic sealed bytes mismatch.")
            return changed_proof or self.proof(tool)
        with patch.object(drill, "token_hex", return_value=OFF), patch.object(recovery, "RecoveryAPI") as api, \
                patch.object(recovery, "RecoverySource"), patch.object(recovery, "RecoveryJournal") as journal, \
                patch.object(recovery, "RecoveryEngine"), patch.object(recovery, "run_action", side_effect=action) as run, \
                patch.object(evidence, "verify_activation_baseline", side_effect=verify) as readback:
            try:
                tool.activation_baseline(stage_prefix="latest-off-baseline")
            finally:
                self.assertEqual([args.args[0] for args in run.call_args_list], order[:run.call_count])
                if run.called:
                    self.assertEqual(api.call_args.args[3]["checkpointId"], OFF)
                    self.assertEqual(api.call_args.args[3]["purpose"], "baseline")
                    journal.return_value.release.assert_called_once()
                tool.controller.telegram.call.assert_not_called()
        return order, readback

    def test_fresh_full_off_capture_preserves_on_and_uses_disjoint_immutable_stages(self):
        tool = self.tool()
        old = deepcopy(tool.report["activationBaseline"])
        order, readback = self.capture(tool)
        self.assertEqual(order, ["prepare", "capture", "verify-backup", "independent-full-readback"])
        readback.assert_called_once_with(tool.controller, tool.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], OFF, MANIFEST)
        self.assertEqual(tool.report["activationBaseline"], old)
        self.assertEqual(tool.report["onActivationBaseline"], old)
        self.assertIsNot(tool.report["onActivationBaseline"], tool.report["activationBaseline"])
        self.assertEqual(tool.report["latestOffBaseline"]["checkpointId"], OFF)
        self.assertEqual(tool.report["latestOffBaseline"]["verification"], self.proof(tool))
        stages = [stage["stage"] for stage in tool.report["stages"]]
        self.assertEqual(stages, ["latest-off-baseline-prepare", "latest-off-baseline-capture",
            "latest-off-baseline-verify-backup", "latest-off-baseline-verified"])
        self.assertEqual(len(tool.store.values), 4)

    def test_capture_interruption_or_independent_readback_failure_never_creates_latest_pass(self):
        for phase in ("prepare", "capture", "verify-backup", "readback"):
            tool = self.tool()
            old = deepcopy(tool.report["activationBaseline"])
            with self.subTest(phase=phase), self.assertRaises(recovery.RecoveryError):
                self.capture(tool, failure=phase)
            self.assertNotIn("latestOffBaseline", tool.report)
            self.assertEqual(tool.report["activationBaseline"], old)
            self.assertEqual(tool.report["onActivationBaseline"], old)
            self.assertNotEqual(tool.report.get("status"), "passed")

    def test_off_requires_exact_proof_source_configuration_and_no_mutation(self):
        for change in ({"baselineVerified": False}, {"checkpointId": ON}, {"configurationSha256": "e" * 64},
                       {"sourceRevision": "f" * 40}, {"targetSha256": "0" * 64}, {"mutationPerformed": True}):
            tool = self.tool()
            with self.subTest(change=change), self.assertRaises(contract.ContractError):
                self.capture(tool, changed_proof={**self.proof(tool), **change})
            self.assertNotIn("latestOffBaseline", tool.report)

    def test_old_pins_unknown_work_or_unfrozen_source_stop_before_export(self):
        for change in ({"control": {"admission": "open", "workers": "frozen"}},
                       {"control": {"admission": "closed", "workers": "run"}},
                       {"work": {"invocations": 1}}, {"terminal": {"unknownInvocations": 1}}):
            tool = self.tool()
            tool.controller.inspect.return_value.update(change)
            with self.subTest(change=change), patch.object(recovery, "RecoveryAPI") as api, self.assertRaises(contract.ContractError):
                tool.activation_baseline(stage_prefix="latest-off-baseline")
            tool.code_archive.assert_not_called()
            api.assert_not_called()
        tool = self.tool()
        tool.baseline_checkpoint, tool.baseline_manifest_sha = ON, "d" * 64
        with patch.object(recovery, "RecoveryAPI") as api, self.assertRaises(contract.ContractError):
            tool.activation_baseline(stage_prefix="latest-off-baseline")
        tool.controller.inspect.assert_not_called()
        api.assert_not_called()

    def test_stage_names_are_not_an_arbitrary_private_evidence_path(self):
        tool = self.tool()
        with patch.object(recovery, "RecoveryAPI") as api, self.assertRaises(contract.ContractError):
            tool.activation_baseline(stage_prefix="../activation-baseline")
        tool.controller.inspect.assert_not_called()
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()

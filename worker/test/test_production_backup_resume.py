"""Fail-closed resume checks for the isolated maintenance watchdog."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_lifecycle_drill as drill
from production_target import ContractError


def controller():
    target = Mock()
    target.environment = "rehearsal"
    target.data = {"workerName": drill.SERVICE}
    ctl = Mock()
    ctl.target = target
    return ctl


class ResumeTests(unittest.TestCase):
    def test_unknown_or_running_export_never_opens_or_records_resume_intent(self):
        for state in (None, "started", "unknown", "polling"):
            with self.subTest(state=state):
                ctl = controller()
                journal = Mock()
                journal.value = None if state is None else {"export": {"state": state}}
                record = Mock()
                with self.assertRaises(ContractError):
                    drill.resume_failed_backup(ctl, Mock(), Mock(), journal,
                        initial={"control": {"admission": "open", "workers": "run"}},
                        frozen={}, fingerprint={}, session="1-1", record_intent=record)
                record.assert_not_called()
                ctl.inspect.assert_not_called()

    def test_accepted_work_stays_running_during_aborted_drain(self):
        ctl = controller()
        paused = {"admission": "closed", "workers": "run"}
        ctl.inspect.return_value = {"control": paused, "release": {}, "configurationSha256": "x",
                                    "work": {"accepted": 1}, "terminal": {}}
        record = Mock()
        with self.assertRaises(ContractError):
            drill.resume_aborted_drain(ctl, initial={"control": {"admission": "open", "workers": "run"},
                "release": {}, "configurationSha256": "x"}, paused=paused, session="1-1", record_intent=record)
        record.assert_not_called()

    def test_production_target_cannot_use_automatic_rehearsal_resume(self):
        ctl = controller()
        ctl.target.environment = "production"
        record = Mock()
        with self.assertRaises(ContractError):
            drill.resume_aborted_drain(ctl, initial={}, paused={}, session="1-1", record_intent=record)
        record.assert_not_called()
        ctl.inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()

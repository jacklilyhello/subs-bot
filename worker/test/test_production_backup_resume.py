"""Fail-closed resume checks for the isolated maintenance watchdog."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_lifecycle_drill as drill
import production_backup_resume as resume
from production_target import ContractError


def controller():
    target = Mock()
    target.environment = "rehearsal"
    target.data = {"workerName": drill.SERVICE, "botId": "123"}
    target.digest = "a" * 64
    target.configuration_digest = "b" * 64
    ctl = Mock()
    ctl.target = target
    ctl.revision = "c" * 40
    return ctl


class ResumeTests(unittest.TestCase):
    def test_atomic_resume_rechecks_ambiguous_terminal_edit(self):
        ctl = controller()
        frozen = {"admission": "closed", "workers": "frozen", "epoch": 3}
        ctl.inspect.return_value = {"control": {"admission": "open", "workers": "run", "epoch": 4}}
        with patch.object(resume, "_mutate_sql") as mutate:
            resume._commit(ctl, frozen)
        sql = " ".join(mutate.call_args.args[2])
        self.assertIn("telegram_group_share_cards.shown<101", sql)
        self.assertIn("telegram_group_share_cards.attempts>=4", sql)

    def test_failed_backup_rechecks_full_data_after_intent_before_single_cas(self):
        ctl = controller()
        frozen = {"admission": "closed", "workers": "frozen", "epoch": 3}
        before = {"control": frozen, "release": {"revision": "c" * 40}, "configurationSha256": "b" * 64,
                  "work": {"invocations": 0}, "terminal": {}, "stateSha256": "d" * 64}
        after = {"control": {**frozen, "admission": "open", "workers": "run", "epoch": 4}}
        ctl.inspect.side_effect = [before, before, after]
        initial = {"control": {"admission": "open", "workers": "run"}, "release": before["release"],
                   "configurationSha256": before["configurationSha256"]}
        journal = Mock()
        journal.value = {"scopeSha256": "a" * 64, "export": {"state": "complete"}}
        trace = []
        record = Mock(side_effect=lambda *_args: trace.append("intent"))
        with patch.object(resume, "_dependencies"), \
             patch("production_backup_capacity.frozen_fingerprint", return_value={"dataSha256": "e" * 64}) as fingerprint, \
             patch.object(resume, "_mutate_sql", side_effect=lambda *_args: trace.append("cas")):
            resume.resume_failed_backup(ctl, Mock(), Mock(), journal, initial=initial, frozen=frozen,
                fingerprint={"dataSha256": "e" * 64}, session="1-1", approval_envelope={"explicit": True}, record_intent=record)
        self.assertEqual(trace, ["intent", "cas"])
        self.assertEqual(fingerprint.call_count, 2)

    def test_changed_frozen_data_after_intent_never_writes(self):
        ctl = controller()
        frozen = {"admission": "closed", "workers": "frozen", "epoch": 3}
        state = {"control": frozen, "release": {}, "configurationSha256": "b" * 64,
                 "work": {"invocations": 0}, "terminal": {}, "stateSha256": "d" * 64}
        ctl.inspect.return_value = state
        initial = {"control": {"admission": "open", "workers": "run"}, "release": {}, "configurationSha256": "b" * 64}
        journal = Mock()
        journal.value = {"scopeSha256": "a" * 64, "export": {"state": "complete"}}
        record = Mock()
        with patch.object(resume, "_dependencies"), \
             patch("production_backup_capacity.frozen_fingerprint", side_effect=[{"data": "same"}, {"data": "changed"}]), \
             patch.object(resume, "_mutate_sql") as mutate:
            with self.assertRaises(ContractError):
                resume.resume_failed_backup(ctl, Mock(), Mock(), journal, initial=initial, frozen=frozen,
                    fingerprint={"data": "same"}, session="1-1", approval_envelope={"explicit": True}, record_intent=record)
        record.assert_called_once()
        mutate.assert_not_called()

    def test_unknown_or_running_export_never_opens_or_records_resume_intent(self):
        for state in (None, "started", "unknown", "polling"):
            with self.subTest(state=state):
                ctl = controller()
                journal = Mock()
                journal.value = None if state is None else {"scopeSha256": "a" * 64, "export": {"state": state}}
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

    def test_unknown_terminal_edit_never_opens_admission(self):
        ctl = controller()
        paused = {"admission": "closed", "workers": "run"}
        ctl.inspect.return_value = {"control": paused, "release": {}, "configurationSha256": "x",
                                    "work": {"invocations": 0}, "terminal": {"terminalEditFailure": 1}}
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

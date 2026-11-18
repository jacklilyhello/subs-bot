"""The shared phase must retain production authorization and journal guards."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_cli as backup
from production_target import ContractError
from test_production_backup_transaction import Store


class SharedPhaseTests(unittest.TestCase):
    def test_failed_paused_backup_passes_exact_approval_to_resume(self):
        target = Mock(digest="a" * 64, configuration_digest="c" * 64, environment="production")
        policy = {"pauseLimitSeconds": 300}
        contract = {"checkpointId": "e" * 32}
        state = {"stateSha256": "d" * 64, "control": {"admission": "closed", "workers": "run"}}
        details = {"contractSha256": backup.digest(contract), "policySha256": backup.digest(policy),
                   "configurationSha256": target.configuration_digest}
        events = [{"stage": "started", "details": details},
                  {"stage": "pause-intent", "timestamp": 100, "details": {}},
                  {"stage": "paused", "details": {"control": state["control"]}}]
        anchor, journal = Mock(), Mock()
        anchor.initial_material.return_value = ({}, b"genesis")
        pin = {"session": "123-1"}
        plan = {"stateSha256": state["stateSha256"], "approvalAction": "maintenance-resume"}
        env = {"SUBS_BOT_BACKUP_GENESIS_SHA256": backup.recovery.digest(b"genesis"),
               "BACKUP_STATE_SHA256": state["stateSha256"], "SUBS_BOT_APPROVAL_JSON": "synthetic-approved-envelope"}
        with patch.object(backup.maintenance, "Anchor", return_value=anchor), \
             patch.object(backup, "active_transaction", return_value=(pin, journal, events)), \
             patch.object(backup, "require_finished_intent"), \
             patch.object(backup.resume, "plan_aborted_drain", return_value=plan), \
             patch.object(backup.resume, "resume_aborted_drain", return_value={"control": state["control"]}) as resume, \
             patch.object(backup.time, "time", return_value=200):
            result = backup.execute_phase(action="resume-failed", env=env, target=target, revision="b" * 40,
                policy=policy, contract=contract, proof={"revision": "f" * 40}, state=state, store=Mock(),
                guard=Mock(), bounded_guard=Mock(), ctl=Mock(), source=Mock(), api=Mock(), directory=Path("/tmp"))
        self.assertEqual(result["status"], "resumed-after-failure")
        self.assertEqual(resume.call_args.kwargs["approval_envelope"], "synthetic-approved-envelope")
        anchor.release.assert_called_once_with("123-1")

    def test_pause_alarm_and_maximum_have_distinct_compatible_limits(self):
        import json
        policy = {"version": 1, "warningPercent": 80, "pauseLimitSeconds": 300, "overdueHours": 48,
                  "windowStartUtc": "01:00", "windowMinutes": 60, "frequencyHours": 24}
        old = backup.settings(json.dumps(policy))
        self.assertEqual(old, policy)
        self.assertEqual(backup.maximum_pause(old), 1800)
        extended = backup.settings(json.dumps({**policy, "maximumPauseSeconds": 3600}))
        self.assertEqual(backup.maximum_pause(extended), 3600)
        for value in (True, 299, 21601):
            with self.subTest(value=value), self.assertRaises(ContractError):
                backup.settings(json.dumps({**policy, "maximumPauseSeconds": value}))
        with self.assertRaises(ContractError):
            backup.settings(json.dumps({**policy, "pauseLimitSeconds": 900, "maximumPauseSeconds": 600}))

    def test_preflight_rejects_unapproved_action_without_writing(self):
        target = Mock(digest="a" * 64, configuration_digest="c" * 64, environment="production")
        store = Store()
        seed = backup.maintenance.Anchor(store, target.digest, "0" * 64)
        genesis = backup.recovery.digest(seed.initial_material()[1])
        anchor = backup.maintenance.Anchor(store, target.digest, genesis)
        anchor.initialize()
        anchor.acquire("123-1", "2026/11/18", "b" * 40)
        policy = {"warningPercent": 80}
        contract = {"checkpointId": "e" * 32}
        journal = backup.maintenance.Transaction(store, "123-1", "2026/11/18", target.digest, "b" * 40)
        journal.append("started", {"contractSha256": backup.digest(contract), "policySha256": backup.digest(policy),
                                   "configurationSha256": target.configuration_digest}, 100)
        before = dict(store.objects)
        env = {"SUBS_BOT_BACKUP_GENESIS_SHA256": genesis, "BACKUP_STATE_SHA256": "d" * 64}
        with patch.object(backup, "authorized", side_effect=ContractError("approval rejected")), \
             patch.object(backup.capacity, "observe") as observe:
            with self.assertRaises(ContractError):
                backup.execute_phase(action="preflight", env=env, target=target, revision="b" * 40,
                    policy=policy, contract=contract, proof={"revision": "f" * 40},
                    state={"stateSha256": "d" * 64}, store=store, guard=Mock(), bounded_guard=Mock(),
                    ctl=Mock(), source=Mock(), api=Mock(), directory=Path("/tmp"))
        observe.assert_not_called()
        self.assertEqual(store.objects, before)


if __name__ == "__main__":
    unittest.main()

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
    def test_preflight_rejects_unapproved_action_without_writing(self):
        target = Mock(digest="a" * 64, configuration_digest="c" * 64)
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

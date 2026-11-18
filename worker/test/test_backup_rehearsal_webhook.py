"""The rehearsal adapter can never redirect the registered test Bot."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from backup_rehearsal_webhook import BackupRehearsalTelegram, DATABASE_ID, WORKER_ID
from production_control import Telegram
from production_lifecycle_drill import HOSTNAME, ORIGINAL_ORIGIN, SERVICE
from production_target import ACCOUNT, TEST_BOT_ID, ContractError


class RehearsalWebhookTests(unittest.TestCase):
    def setUp(self):
        self.target = SimpleNamespace(environment="rehearsal", data={
            "environment": "rehearsal", "accountId": ACCOUNT, "workerName": SERVICE, "workerId": WORKER_ID,
            "d1Id": DATABASE_ID, "hostname": HOSTNAME, "botId": TEST_BOT_ID, "botUsername": "test_cfsubs_bot",
            "webhook": {"allowedUpdates": ["message", "callback_query"], "maxConnections": 1},
        })
        self.original = {"url": ORIGINAL_ORIGIN + "/telegram/webhook", "pending_update_count": 17,
                         "has_custom_certificate": False, "max_connections": 2, "allowed_updates": ["message"]}

    def test_only_webhook_prerequisite_is_synthetic(self):
        adapter = BackupRehearsalTelegram(self.target, {})
        bot = {"id": int(TEST_BOT_ID), "username": "test_cfsubs_bot", "is_bot": True}
        with patch.object(Telegram, "call", side_effect=[self.original, self.original, bot]) as real:
            self.assertEqual(adapter.call("getWebhookInfo"), {
                "url": "https://" + HOSTNAME + "/telegram/webhook", "has_custom_certificate": False,
                "max_connections": 1, "allowed_updates": ["message", "callback_query"], "pending_update_count": 17,
            })
            self.assertEqual(adapter.observe_original()["observation"]["pendingUpdateCount"], 17)
            self.assertEqual(adapter.identity()["botId"], TEST_BOT_ID)
            self.assertEqual([item.args[0] for item in real.call_args_list], ["getWebhookInfo", "getWebhookInfo", "getMe"])

    def test_other_identity_and_real_mutation_are_blocked(self):
        for field, value in (("environment", "production"), ("workerId", "f" * 32), ("d1Id", "unknown"),
                             ("botId", "1"), ("hostname", "subs-bot.lilyya.top")):
            with self.subTest(field=field), self.assertRaises(ContractError):
                BackupRehearsalTelegram(SimpleNamespace(environment="rehearsal", data={**self.target.data, field: value}), {})
        adapter = BackupRehearsalTelegram(self.target, {})
        with patch.object(Telegram, "call") as real:
            with self.assertRaises(ContractError):
                adapter.call("setWebhook", {})
            with self.assertRaises(ContractError):
                adapter.configure("a" * 64)
            with self.assertRaises(ContractError):
                adapter.plan_webhook()
            real.assert_not_called()

    def test_original_webhook_must_be_outside_the_drill(self):
        adapter = BackupRehearsalTelegram(self.target, {})
        with patch.object(Telegram, "call", return_value={**self.original, "url": "https://" + HOSTNAME + "/telegram/webhook"}), \
             self.assertRaises(ContractError):
            adapter.call("getWebhookInfo")

    def test_reopened_probe_needs_exact_durable_disposition(self):
        from hashlib import sha256
        from unittest.mock import Mock
        from backup_rehearsal_webhook import receive_probe
        from production_target import canonical

        self.target.digest = "a" * 64
        secrets = {"webhookSecret": "synthetic-rehearsal-secret"}
        adapter = BackupRehearsalTelegram(self.target, secrets)
        state = {"control": {"admission": "open", "workers": "run", "epoch": 45}}
        controller = SimpleNamespace(telegram=adapter, target=self.target, secrets=secrets,
            data=object(), database="/accounts/" + ACCOUNT + "/d1/database/" + DATABASE_ID,
            inspect=Mock(return_value=state))
        update_id = 2**51 + 123
        expected = {"bot_id": TEST_BOT_ID, "target_sha256": self.target.digest, "state": "completed",
                    "http_status": 204, "payload_sha256": sha256(canonical({"update_id": update_id})).hexdigest()}
        guard = Mock()
        with patch("backup_rehearsal_webhook.rows", side_effect=[[], [expected]]) as read_rows, \
             patch("backup_rehearsal_webhook.public_readback", return_value=(204, b"")) as readback:
            self.assertTrue(receive_probe(controller, update_id, 204, guard=guard)["confirmedDisposition"])
            guard.assert_called_once_with()
            self.assertEqual(read_rows.call_count, 2)
            self.assertEqual(readback.call_args.args[0].data, canonical({"update_id": update_id}))

        guard.reset_mock()
        with patch("backup_rehearsal_webhook.rows", return_value=[expected]), \
             patch("backup_rehearsal_webhook.public_readback") as post, self.assertRaises(ContractError):
            receive_probe(controller, update_id, 204, guard=guard)
        guard.assert_not_called()
        post.assert_not_called()

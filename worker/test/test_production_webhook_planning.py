"""Hosted-only Webhook preflight, stable approval and uncertain-write guards."""

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_control as control
import production_target as contract
import test_production_control as fixtures

ORIGINAL = "https://subs-bot-cf-dev-01.lilyya.workers.dev/telegram/webhook"
PRIVATE = "synthetic-private-error https://private.invalid/path?token=synthetic-secret"


def empty_info():
    return {"url": "", "has_custom_certificate": False, "pending_update_count": 7}


def active_info(target):
    return {"url": "https://" + target.data["hostname"] + "/telegram/webhook", "has_custom_certificate": False,
        "pending_update_count": 7, "max_connections": target.data["webhook"]["maxConnections"],
        "allowed_updates": target.data["webhook"]["allowedUpdates"], "ip_address": "104.16.1.1"}


class WebhookSettingsTests(unittest.TestCase):
    def setUp(self):
        self.target, self.secrets = fixtures.fixture()
        self.telegram = control.Telegram(self.target, self.secrets)

    def test_pending_errors_and_reported_ip_rotation_are_observations_not_settings(self):
        before = active_info(self.target)
        after = {**before, "pending_update_count": 99, "last_error_date": 4, "last_error_message": PRIVATE,
                 "last_synchronization_error_date": 5, "ip_address": "104.16.2.2",
                 "allowed_updates": list(reversed(before["allowed_updates"]))}
        first, second = self.telegram.webhook_info(before), self.telegram.webhook_info(after)
        self.assertEqual(first["settingsSha256"], second["settingsSha256"])
        self.assertNotEqual(first["observation"]["infoSha256"], second["observation"]["infoSha256"])
        self.assertNotEqual(first["observation"]["reportedIpSha256"], second["observation"]["reportedIpSha256"])
        self.assertEqual(second["observation"]["pendingUpdateCount"], 99)
        self.assertNotIn(PRIVATE, json.dumps(second))
        self.assertNotIn("synthetic-secret", json.dumps(second))

    def test_formal_target_only_accepts_empty_or_its_exact_url(self):
        raw = deepcopy(self.target.data)
        service, backup, hostname = contract.NAMES["production"]
        raw.update(environment="production", workerName=service, d1Name=service, bucketName=service,
            backupBucketName=backup, hostname=hostname, botUsername="SyntheticFormalBot")
        target = contract.validate_target(raw)
        telegram = control.Telegram(target, self.secrets)
        self.assertEqual(telegram.webhook_info(empty_info())["settings"]["url"], "")
        self.assertEqual(telegram.webhook_info(active_info(target))["settings"]["url"], "https://" + hostname + "/telegram/webhook")
        for url in (ORIGINAL, active_info(self.target)["url"], "https://unknown.invalid/webhook",
                    "https://" + hostname + "/telegram/webhook?secret=unapproved"):
            with self.subTest(url=url), self.assertRaises(contract.ContractError):
                telegram.webhook_info({**active_info(target), "url": url})
        with self.assertRaises(contract.ContractError):
            control.Telegram(target, self.secrets, rehearsal_previous_url=ORIGINAL)

    def test_original_rehearsal_url_requires_explicit_registration_and_has_no_default(self):
        info = {**active_info(self.target), "url": ORIGINAL}
        with self.assertRaises(contract.ContractError):
            self.telegram.webhook_info(info)
        registered = control.Telegram(self.target, self.secrets, rehearsal_previous_url=ORIGINAL)
        self.assertEqual(registered.webhook_info(info)["settings"]["url"], ORIGINAL)
        with self.assertRaises(contract.ContractError):
            control.Telegram(self.target, self.secrets, rehearsal_previous_url="https://unknown.invalid/webhook")

    def test_unsupported_certificate_fields_ip_or_malformed_settings_are_rejected(self):
        cases = [{"has_custom_certificate": True}, {"has_custom_certificate": 0}, {"certificate": PRIVATE},
            {"ip_address_override": "104.16.1.1"}, {"ip_address": "127.0.0.1"}, {"ip_address": "not-an-IP"},
            {"ip_address": None}, {"ip_address": "224.0.0.1"},
            {"ip_address": "::ffff:127.0.0.1"}, {"max_connections": True}, {"allowed_updates": ["message", "message"]},
            {"allowed_updates": [{}]}, {"allowed_updates": ["edited_message"]}, {"pending_update_count": -1}]
        for changed in cases:
            with self.subTest(changed=changed), self.assertRaises(contract.ContractError):
                self.telegram.webhook_info({**active_info(self.target), **changed})
        with self.assertRaises(contract.ContractError):
            self.telegram.webhook_info({**empty_info(), "ip_address": "104.16.1.1"})


class WebhookControllerTests(unittest.TestCase):
    def setUp(self):
        fixtures.ProductionControllerTests.setUp(self)
        self.controller.initialize()
        self.info = empty_info()
        self.mutations = []
        self.after_write = None
        self.telegram = control.Telegram(self.target, self.secrets)
        def call(method, payload=None):
            if method == "getMe":
                return {"id": int(self.target.data["botId"]), "is_bot": True, "username": self.target.data["botUsername"]}
            if method == "getWebhookInfo":
                return deepcopy(self.info)
            self.assertEqual(method, "setWebhook")
            self.mutations.append(deepcopy(payload))
            self.info = active_info(self.target)
            if self.after_write is not None:
                return self.after_write()
            return True
        self.telegram.call = Mock(side_effect=call)
        self.controller.telegram = self.telegram
        self.controller.verify_domain = Mock(return_value={"domainVerified": True})

    def apply(self, plan):
        return self.controller.configure_webhook(fixtures.approval(self.target, "webhook", plan["stateSha256"]),
            plan["stateSha256"], plan["webhook"]["settingsSha256"])

    def test_read_only_plan_supplies_both_pins_and_live_delivery_changes_do_not_block_write(self):
        plan = self.controller.plan_webhook()
        self.assertEqual(self.mutations, [])
        self.assertEqual(plan["approvalState"]["planAction"], "webhook")
        self.assertEqual(plan["stateSha256"], contract.digest(plan["approvalState"]))
        self.assertEqual(plan["approvalState"]["webhookSettingsSha256"], plan["webhook"]["settingsSha256"])
        self.info.update(pending_update_count=99, last_error_message=PRIVATE, last_error_date=1)
        self.assertEqual(self.controller.plan_webhook()["stateSha256"], plan["stateSha256"])
        result = self.apply(plan)
        self.assertEqual(len(self.mutations), 1)
        desired = self.mutations[0]
        self.assertIs(desired["drop_pending_updates"], False)
        self.assertNotIn("certificate", desired)
        self.assertNotIn("ip_address", desired)
        self.assertEqual(desired["secret_token"], self.secrets["webhookSecret"])
        self.assertFalse(result["dropPendingUpdates"])
        self.assertNotIn(PRIVATE, json.dumps(result))
        self.assertNotIn(self.secrets["webhookSecret"], json.dumps(result))

    def test_unknown_url_wrong_bot_or_changed_settings_never_mutate(self):
        plan = self.controller.plan_webhook()
        for changed in ({"url": "https://unknown.invalid/webhook"},
                        {"url": active_info(self.target)["url"], "max_connections": 3, "allowed_updates": ["message"]}):
            self.info = {**empty_info(), **changed}
            with self.subTest(changed=changed), self.assertRaises(contract.ContractError):
                self.apply(plan)
        self.info = empty_info()
        self.telegram.identity = Mock(side_effect=contract.ContractError("Live Bot identity differs from the approved target."))
        with self.assertRaises(contract.ContractError):
            self.apply(plan)
        self.assertEqual(self.mutations, [])

    def test_ordinary_inspect_wrong_action_or_control_epoch_cannot_reuse_approval(self):
        observed = self.controller.inspect()
        plan = self.controller.plan_webhook()
        with self.assertRaises(contract.ContractError):
            self.apply({**plan, "stateSha256": observed["stateSha256"]})
        with self.assertRaises(contract.ContractError):
            self.controller.configure_webhook(fixtures.approval(self.target, "pause", plan["stateSha256"]),
                plan["stateSha256"], plan["webhook"]["settingsSha256"])
        self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch+1")
        with self.assertRaises(contract.ContractError):
            self.apply(plan)
        self.assertEqual(self.mutations, [])

    def test_open_admission_and_last_moment_control_change_stop_before_telegram_mutation(self):
        plan = self.controller.plan_webhook()
        self.api.db.execute("UPDATE subs_bot_production_control SET workers='run',admission='open'")
        with self.assertRaises(contract.ContractError):
            self.controller.plan_webhook()
        self.api.db.execute("UPDATE subs_bot_production_control SET workers='frozen',admission='closed'")
        self.controller.guard = lambda: self.api.db.execute("UPDATE subs_bot_production_control SET epoch=epoch+1")
        with self.assertRaises(contract.ContractError):
            self.apply(plan)
        self.assertEqual(self.mutations, [])

    def test_lost_response_or_bad_readback_is_uncertain_and_never_retried(self):
        for kind in ("transport", "false", "bad-readback"):
            self.info, self.mutations = empty_info(), []
            plan = self.controller.plan_webhook()
            def failure():
                if kind == "transport":
                    raise OSError(PRIVATE)
                if kind == "false":
                    return False
                self.info["has_custom_certificate"] = True
                return True
            self.after_write = failure
            with self.subTest(kind=kind), self.assertRaises(control.OperationError) as caught:
                self.apply(plan)
            self.assertTrue(caught.exception.uncertain)
            self.assertEqual(len(self.mutations), 1)
            self.assertNotIn(PRIVATE, str(caught.exception))
        self.after_write = None
        self.info = active_info(self.target)
        observation = self.controller.plan_webhook()
        self.assertEqual(len(self.mutations), 1, "read-only reconciliation never repeats setWebhook")
        self.assertEqual(observation["webhook"]["settings"]["url"], self.info["url"])


class WebhookCliTests(unittest.TestCase):
    def test_cli_routes_planning_and_writing_to_the_matching_controller_methods(self):
        target, secrets = fixtures.fixture()
        for action in ("plan-webhook", "webhook"):
            with self.subTest(action=action), TemporaryDirectory() as temporary:
                bundle = Path(temporary) / control.artifact.VERIFIED_DIRECTORY
                bundle.mkdir()
                (bundle / "isolation.json").write_bytes(contract.canonical({"revision": fixtures.REVISION}))
                ctl = Mock()
                ctl.plan_webhook.return_value = {"stateSha256": "a" * 64, "webhook": {"settingsSha256": "b" * 64}}
                ctl.configure_webhook.return_value = {"webhookSha256": "b" * 64, "dropPendingUpdates": False}
                env = {"CONTROL_ACTION": action, "SUBS_BOT_TARGET_JSON": json.dumps(target.data),
                    "SUBS_BOT_CONTROL_SECRETS": json.dumps(secrets), "GITHUB_SHA": fixtures.REVISION,
                    "RUNNER_TEMP": temporary, "SUBS_BOT_CF_DATA_TOKEN": "synthetic-data-token",
                    "SUBS_BOT_CF_WORKER_TOKEN": "synthetic-worker-token", "CONTROL_STATE_SHA256": "a" * 64,
                    "CONTROL_WEBHOOK_SHA256": "b" * 64, "SUBS_BOT_APPROVAL_JSON": "synthetic-approval"}
                with patch.dict(os.environ, env, clear=True), patch.object(control, "hosted_environment"), \
                     patch.object(control.artifact, "require_current_main"), patch.object(control, "API"), \
                     patch.object(control, "Controller", return_value=ctl), \
                     patch.object(control.prepare_control_artifact, "prepare", return_value={"revision": fixtures.REVISION}) as prepare, \
                     patch("builtins.print"):
                    control.main()
                prepare.assert_called_once_with(action)
                if action == "plan-webhook":
                    ctl.plan_webhook.assert_called_once_with()
                    ctl.configure_webhook.assert_not_called()
                else:
                    ctl.configure_webhook.assert_called_once_with("synthetic-approval", "a" * 64, "b" * 64)
                    ctl.plan_webhook.assert_not_called()
                result = json.loads((Path(temporary) / "production-control-result.json").read_bytes())
                self.assertEqual(result["controlRevision"], fixtures.REVISION)


if __name__ == "__main__":
    unittest.main()

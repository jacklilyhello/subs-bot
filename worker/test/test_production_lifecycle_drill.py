"""Hosted safety checks for the real rehearsal's configuration and webhook recovery."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_lifecycle_drill as drill
import production_target as contract
from test_production_control import REVISION, STAMP, fixture


def environment():
    target, secrets = fixture()
    previous = {"botId": target.data["botId"], "botUsername": "test_cfsubs_bot", "botToken": secrets["botToken"],
        "webhookSecret": "synthetic_original_hook_" + "x" * 32,
        "adminId": "8813701954", "memberId": "8653767757", "groupId": "-5114255828"}
    original = {"accountId": contract.ACCOUNT, "workerId": "c" * 32, "workerCreatedOn": STAMP,
        "d1Id": "30000000-0000-4000-8000-000000000001", "d1CreatedAt": STAMP, "r2CreatedOn": STAMP, "namespace": "lilyya"}
    return {"SUBS_BOT_TELEGRAM_TEST_CONFIG": json.dumps(previous),
        "SUBS_BOT_CONTROL_DRILL_KEYS": json.dumps({key: secrets[key] for key in ("aggregateKey", "privateShareKey", "webhookSecret")}),
        "SUBS_BOT_CF_ISOLATION_TARGET_JSON": json.dumps(original), "GITHUB_SHA": REVISION,
        "GITHUB_RUN_ID": "1001", "GITHUB_RUN_ATTEMPT": "1", "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic_data_token_" + "x" * 25,
        "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic_worker_token_" + "y" * 25}


class MemoryStore:
    def __init__(self):
        self.values = {}

    def put(self, key, body):
        if key in self.values and self.values[key] != body:
            raise contract.ContractError("Synthetic immutable checkpoint conflict.")
        self.values[key] = body

    def get(self, key, *, absent=False):
        if absent and key not in self.values:
            return None
        return self.values[key]


class LifecycleDrillTests(unittest.TestCase):
    def tool(self):
        value = drill.Drill(environment())
        value.store = MemoryStore()
        return value

    def snapshot(self, tool):
        info = {"url": drill.ORIGINAL_ORIGIN + "/telegram/webhook", "has_custom_certificate": False,
                "max_connections": 40, "allowed_updates": ["message", "callback_query", "inline_query"], "pending_update_count": 7}
        value = {"botId": tool.previous["botId"], "draftSha256": tool.draft.digest,
            "oldWebhookSecret": tool.previous["webhookSecret"], "webhookInfo": info}
        tool.store.put(tool.snapshot_key(), contract.canonical(value))
        return info

    def test_configuration_has_no_production_or_test_key_fallback(self):
        env = environment()
        target, secrets, previous, _ = drill.configuration(env)
        self.assertEqual(target.data["workerName"], drill.SERVICE)
        self.assertEqual(target.environment, "rehearsal")
        self.assertFalse(any(target.data["features"].values()))
        self.assertIsNone(target.data["provider"])
        self.assertNotEqual(secrets["webhookSecret"], previous["webhookSecret"])
        for key in ("SUBS_BOT_CONTROL_DRILL_KEYS", "SUBS_BOT_TELEGRAM_TEST_CONFIG", "SUBS_BOT_CF_ISOLATION_TARGET_JSON"):
            with self.assertRaises(contract.ContractError):
                drill.configuration({k: v for k, v in env.items() if k != key})
        changed = deepcopy(env)
        policy = json.loads(changed["SUBS_BOT_TELEGRAM_TEST_CONFIG"])
        policy["memberId"] = "999999"
        changed["SUBS_BOT_TELEGRAM_TEST_CONFIG"] = json.dumps(policy)
        with self.assertRaises(contract.ContractError):
            drill.configuration(changed)

    def test_automatic_approval_cannot_select_production(self):
        target, _, _, _ = drill.configuration(environment())
        with patch.dict(drill.os.environ, {"GITHUB_SHA": REVISION}):
            envelope = drill.approval(target, "deploy", REVISION, "f" * 64)
        self.assertTrue(contract.approve(target, envelope, "deploy", REVISION, "f" * 64))
        registered, _ = fixture()
        raw = deepcopy(registered.data)
        service, backup, hostname = contract.NAMES["production"]
        raw.update(environment="production", workerName=service, d1Name=service, bucketName=service,
            backupBucketName=backup, hostname=hostname, botUsername="SyntheticFormalBot", admins=["93002"], members=["93003"])
        formal = contract.validate_target(raw)
        with self.assertRaises(contract.ContractError):
            drill.approval(formal, "deploy", REVISION, "f" * 64)

    def test_restore_uses_private_snapshot_preserves_pending_and_is_idempotent(self):
        tool = self.tool()
        original = self.snapshot(tool)
        current = {**original, "url": drill.ORIGIN + "/telegram/webhook", "max_connections": 1,
            "allowed_updates": ["message", "callback_query"], "pending_update_count": 9}
        mutations = []
        telegram = Mock()
        def call(method, payload=None):
            nonlocal current
            if method == "getWebhookInfo":
                return deepcopy(current)
            self.assertEqual(method, "setWebhook")
            self.assertIs(payload["drop_pending_updates"], False)
            self.assertEqual(payload["secret_token"], tool.previous["webhookSecret"])
            self.assertEqual(payload["url"], original["url"])
            mutations.append(deepcopy(payload))
            current = {**original, "pending_update_count": 9}
            return True
        telegram.call.side_effect = call
        with patch.object(drill, "Telegram", return_value=telegram), patch.object(drill, "probe_original_webhook", return_value=400):
            self.assertTrue(tool.restore_webhook(automatic=True)["webhookRestored"])
            self.assertTrue(tool.restore_webhook(automatic=True)["webhookRestored"])
        self.assertEqual(len(mutations), 1)
        self.assertEqual(current["pending_update_count"], 9)

    def test_existing_registration_requires_its_independent_digest_even_for_bootstrap(self):
        tool = self.tool()
        target, _ = fixture()
        value = {"target": target.data, "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                 "draftSha256": tool.draft.digest}
        tool.store.put(tool.registration_key, contract.canonical(value))
        with self.assertRaises(contract.ContractError):
            tool.registration(required=False)
        tool.env["DRILL_REGISTRATION_SHA256"] = contract.digest(value)
        self.assertEqual(tool.registration(required=False).digest, target.digest)

    def test_same_original_url_with_wrong_secret_is_repaired_then_independently_probed(self):
        tool = self.tool()
        original = self.snapshot(tool)
        telegram = Mock()
        telegram.call.side_effect = lambda method, _payload=None: original if method == "getWebhookInfo" else True
        with patch.object(drill, "Telegram", return_value=telegram), patch.object(drill, "probe_original_webhook", side_effect=[401, 400]):
            result = tool.restore_webhook(automatic=True)
        self.assertEqual(result["originalWebhookAuthProbe"], {"status": 400, "businessAccepted": False})
        self.assertEqual([call.args[0] for call in telegram.call.call_args_list].count("setWebhook"), 1)
        telegram.reset_mock()
        with patch.object(drill, "Telegram", return_value=telegram), patch.object(drill, "probe_original_webhook", return_value=503):
            with self.assertRaises(contract.ContractError):
                tool.restore_webhook(automatic=True)
        self.assertNotIn("setWebhook", [call.args[0] for call in telegram.call.call_args_list])

    def test_other_current_webhook_or_wrong_snapshot_is_never_overwritten(self):
        tool = self.tool()
        original = self.snapshot(tool)
        telegram = Mock()
        telegram.call.return_value = {**original, "url": "https://different.fixture.invalid/webhook"}
        with patch.object(drill, "Telegram", return_value=telegram):
            with self.assertRaises(contract.ContractError):
                tool.restore_webhook(automatic=True)
        self.assertEqual([call.args[0] for call in telegram.call.call_args_list], ["getWebhookInfo"])
        tool.env["DRILL_WEBHOOK_CHECKPOINT"] = "1001/1"
        tool.env["DRILL_WEBHOOK_SNAPSHOT_SHA256"] = "0" * 64
        with patch.object(drill, "Telegram") as client:
            with self.assertRaises(contract.ContractError):
                tool.restore_webhook()
            client.assert_not_called()

    def test_failed_preflight_without_snapshot_does_not_touch_webhook(self):
        tool = self.tool()
        with patch.object(drill, "Telegram") as client:
            result = tool.restore_webhook(automatic=True)
            self.assertTrue(result["webhookWasNotChanged"])
            client.assert_not_called()
            tool.env["DRILL_WEBHOOK_CHECKPOINT"] = "1001/1"
            with self.assertRaises(contract.ContractError):
                tool.restore_webhook()
            client.assert_not_called()

    def test_recovery_finalization_requires_both_positive_and_revoked_results_and_retains_pending_evidence(self):
        tool = self.tool()
        target, _ = fixture()
        state = {"release": {"moduleSha256": "a" * 64, "revision": REVISION, "versionId": "synthetic-version"},
            "control": {"admission": "closed", "workers": "frozen", "epoch": 3},
            "work": {"invocations": 0, "processingUpdates": 0}, "migrationCount": 56}
        proof = {"revision": REVISION, "runId": "50", "runAttempt": "1", "artifactId": "60", "archiveSha256": "b" * 64}
        pending = {**tool.report, "status": "recovery-verified-http-pending", "ciProof": proof, "sourceState": state,
            "recovery": {"status": "recovery-verified-http-pending", "restoredDataSha256": "c" * 64},
            "stages": []}
        pending_key = tool.prefix + tool.run + "-" + tool.attempt + "-" + drill.REPORT
        pending_raw = contract.canonical(pending)
        tool.store.put(pending_key, pending_raw)
        controller = Mock()
        controller.target = target
        controller.inspect.return_value = state
        tool.proof = proof
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.bind = Mock(return_value=controller)
        tool.registration = Mock(return_value=target)
        replay = {"version": 1, "evidenceKind": "hosted-production-restored-data-http-replay", "revision": REVISION,
            "moduleSha256": "a" * 64, "targetSha256": target.digest, "restoredDataSha256": "c" * 64,
            "migrationCount": 56, "consumerBound": False, "realTelegramCredentialsSupplied": False,
            "syntheticProductionGateVerified": True, "outboundAttempts": 0,
            "counts": {"storedShareExports": 1, "trashDenials": 1}}
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            tool.env["RUNNER_TEMP"] = temporary
            (root / "production-recovery-drill-g0-http.json").write_bytes(contract.canonical(replay))
            with self.assertRaises(FileNotFoundError):
                tool.finalize_recovery()
            self.assertNotEqual(tool.report.get("status"), "passed")
            self.assertEqual(tool.store.get(pending_key), pending_raw)
            second = root / "production-recovery-drill-recovered-http.json"
            second.write_bytes(contract.canonical({**replay, "counts": {"storedShareExports": 0, "trashDenials": 1}}))
            with self.assertRaises(contract.ContractError):
                tool.finalize_recovery()
            self.assertEqual(tool.store.get(pending_key), pending_raw)
            second.write_bytes(contract.canonical(replay))
            tool.finalize_recovery()
            self.assertEqual(tool.report["status"], "passed")
            self.assertEqual(set(tool.report["httpReplays"]), {"g0", "recovered"})
            self.assertTrue(all(result["status"] == "passed" for result in tool.report["httpReplays"].values()))
            self.assertEqual(tool.store.get(pending_key), pending_raw)
            tool.finalize_recovery()
            self.assertEqual(tool.report["status"], "passed", "an exact repeated finalization remains independently verifiable")

    def test_http_result_rejects_changed_source_identity_egress_and_failed_status(self):
        source = {"revision": REVISION, "targetSha256": "a" * 64, "moduleSha256": "b" * 64,
            "dataSha256": "c" * 64, "migrationCount": 56}
        value = {"version": 1, "evidenceKind": "hosted-production-restored-data-http-replay", "revision": REVISION,
            "targetSha256": "a" * 64, "moduleSha256": "b" * 64, "restoredDataSha256": "c" * 64,
            "migrationCount": 56, "consumerBound": False, "realTelegramCredentialsSupplied": False,
            "syntheticProductionGateVerified": True, "outboundAttempts": 0,
            "counts": {"storedShareExports": 1, "trashDenials": 1}}
        for change in ({"targetSha256": "d" * 64}, {"moduleSha256": "d" * 64},
                {"restoredDataSha256": "d" * 64}, {"outboundAttempts": 1}, {"status": "stopped"},
                {"realTelegramCredentialsSupplied": True}, {"consumerBound": True}):
            with self.assertRaises(contract.ContractError):
                drill.checked_http_result({**value, **change}, source)


if __name__ == "__main__":
    unittest.main()

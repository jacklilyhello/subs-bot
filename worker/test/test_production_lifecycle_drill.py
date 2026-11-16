"""Hosted safety checks for the real rehearsal's configuration and webhook recovery."""
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, call, patch

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

    def test_activation_approval_uses_the_baseline_bound_plan(self):
        tool = self.tool()
        target, _ = fixture()
        controller = Mock()
        controller.target = target
        controller.revision = REVISION
        controller.plan_activate.return_value = {"stateSha256": "c" * 64,
            "activationBaseline": {"checkpointId": "d" * 32, "manifestSha256": "e" * 64}}
        controller.transition.return_value = {"stateSha256": "f" * 64}
        tool.controller = controller
        with patch.dict(drill.os.environ, {"GITHUB_SHA": REVISION}):
            tool.transition("activate")
        controller.plan_activate.assert_called_once_with()
        controller.inspect.assert_not_called()
        action, envelope, predecessor = controller.transition.call_args.args
        self.assertEqual(action, "activate")
        self.assertEqual(predecessor, "c" * 64)
        self.assertEqual(envelope["stateSha256"], predecessor)

    def planned_controller(self, tool):
        target, _ = fixture()
        controller = Mock(target=target, revision=REVISION)
        controller.plan_pause.return_value = {"stateSha256": "a" * 64, "control": {"admission": "open", "workers": "run"}}
        controller.transition.return_value = {"stateSha256": "b" * 64, "control": {"admission": "closed", "workers": "run"}}
        tool.controller = controller
        return controller

    def test_only_explicit_pre_sql_staleness_replans_with_unique_private_stages(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        confirmed = controller.transition.return_value
        controller.transition.side_effect = [drill.StalePredecessorError(), confirmed, confirmed]
        with patch.dict(drill.os.environ, {"GITHUB_SHA": REVISION}):
            tool.transition("pause")
            tool.transition("pause")
        self.assertEqual(controller.plan_pause.call_count, 3)
        self.assertEqual(controller.transition.call_count, 3)
        stages = [value["stage"] for value in tool.report["stages"]]
        self.assertEqual(stages, ["control-001-pause-intent", "control-001-pause-stale",
            "control-002-pause-intent", "control-002-pause-confirmed", "control-003-pause-intent", "control-003-pause-confirmed"])
        self.assertEqual(len(stages), len(set(stages)))
        self.assertEqual(tool.report["state"], confirmed)
        for attempted in controller.transition.call_args_list:
            action, envelope, predecessor = attempted.args
            self.assertEqual(action, "pause")
            self.assertEqual(envelope["stateSha256"], predecessor)
            self.assertEqual(envelope["environment"], "rehearsal")

    def test_stale_replanning_is_limited_to_three_and_unknown_results_never_retry(self):
        failures = [(drill.StalePredecessorError(), 3),
            (drill.OperationError("Synthetic unconfirmed SQL result.", uncertain=True), 1),
            (contract.ContractError("Predecessor state changed; no transition performed."), 1)]
        for failure, count in failures:
            tool = self.tool()
            controller = self.planned_controller(tool)
            controller.transition.side_effect = failure
            with self.subTest(kind=type(failure).__name__), patch.dict(drill.os.environ, {"GITHUB_SHA": REVISION}):
                with self.assertRaises(type(failure)):
                    tool.transition("pause")
            self.assertEqual(controller.transition.call_count, count)
            self.assertEqual(controller.plan_pause.call_count, count)
            self.assertFalse(any(stage["stage"].endswith("-confirmed") for stage in tool.report["stages"]))

    def test_private_confirmation_failure_cannot_repeat_an_executed_transition(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        tool.save = Mock(side_effect=[None, drill.OperationError("Synthetic private confirmation uncertainty.", uncertain=True)])
        with patch.dict(drill.os.environ, {"GITHUB_SHA": REVISION}):
            with self.assertRaises(drill.OperationError):
                tool.transition("pause")
        controller.transition.assert_called_once()
        controller.plan_pause.assert_called_once()

    def test_private_intent_must_be_durable_before_any_transition(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        tool.save = Mock(side_effect=drill.OperationError("Synthetic unconfirmed private intent.", uncertain=True))
        with self.assertRaises(drill.OperationError):
            tool.transition("pause")
        controller.transition.assert_not_called()

    def test_stabilize_preserves_unknowns_and_only_pauses_drains_and_freezes(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        initial = {"control": {"admission": "closed", "workers": "run"}, "work": {"invocations": 0},
            "terminal": {"unknownInvocations": 1}}
        frozen = {**initial, "control": {"admission": "closed", "workers": "frozen"}}
        controller.inspect.return_value = initial
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.registration = Mock(return_value=controller.target)
        tool.bind = Mock(return_value=controller)
        tool.transition = Mock(side_effect=[initial, frozen])
        tool.quiet = Mock(return_value=initial["work"])
        tool.stabilize()
        self.assertEqual(tool.transition.call_args_list, [call("pause"), call("freeze")])
        tool.prepare.assert_called_once_with(active=True)
        tool.registration.assert_called_once_with()
        tool.quiet.assert_called_once_with()
        self.assertEqual(tool.report["stabilization"]["preservedUnknown"]["unknownInvocations"], 1)
        self.assertIs(tool.report["stabilization"]["activationPermitted"], False)
        self.assertIs(tool.report["stabilization"]["webhookTouched"], False)
        controller.telegram.call.assert_not_called()
        controller.classify_interruption.assert_not_called()
        controller.data.assert_not_called()

    def test_stabilize_rejects_other_scope_before_transition_or_webhook(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        target = deepcopy(controller.target.data)
        service, backup, hostname = contract.NAMES["production"]
        target.update(environment="production", workerName=service, d1Name=service, bucketName=service,
            backupBucketName=backup, hostname=hostname, botUsername="SyntheticFormalBot")
        controller.target = contract.validate_target(target)
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.registration = Mock(return_value=controller.target)
        tool.bind = Mock(return_value=controller)
        with self.assertRaises(contract.ContractError):
            tool.stabilize()
        controller.inspect.assert_not_called()
        controller.transition.assert_not_called()
        controller.telegram.call.assert_not_called()

    def test_stabilize_never_classifies_or_freezes_work_that_has_not_drained(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        controller.inspect.return_value = {"control": {"admission": "closed", "workers": "run"},
            "work": {"invocations": 1}, "terminal": {"unknownInvocations": 1}}
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.registration = Mock(return_value=controller.target)
        tool.bind = Mock(return_value=controller)
        tool.transition = Mock(return_value=controller.inspect.return_value)
        tool.quiet = Mock(side_effect=contract.ContractError("Synthetic accepted work is not drained."))
        with self.assertRaises(contract.ContractError):
            tool.stabilize()
        self.assertEqual(tool.transition.call_args_list, [call("pause")])
        controller.classify_interruption.assert_not_called()
        controller.telegram.call.assert_not_called()
        self.assertNotEqual(tool.report.get("status"), "passed")

    def test_unfrozen_inspection_retains_actual_state_without_reporting_passed(self):
        tool = self.tool()
        controller = self.planned_controller(tool)
        state = {"control": {"admission": "closed", "workers": "run"}, "work": {"invocations": 1}}
        controller.inspect.return_value = state
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.registration = Mock(return_value=controller.target)
        tool.bind = Mock(return_value=controller)
        with self.assertRaises(contract.ContractError), patch.object(drill, "rows") as read:
            tool.inspect()
        self.assertEqual(tool.report["state"], state)
        self.assertIs(tool.report["independentReadback"], True)
        self.assertNotEqual(tool.report.get("status"), "passed")
        self.assertTrue(any(key.endswith("-independent-inspect.json") for key in tool.store.values))
        read.assert_not_called()

    def test_code_archive_rechecks_exact_attempt_and_rejects_changed_bytes(self):
        tool = self.tool()
        archive = b"synthetic trusted CI ZIP bytes"
        proof = {"revision": REVISION, "runId": "50", "runAttempt": "1", "artifactId": "60", "archiveSha256": sha256(archive).hexdigest()}
        tool.proof = proof
        selection = ("1", "60", proof["archiveSha256"])
        with patch.object(drill.artifact, "_github_token", return_value="synthetic-read-token"), \
                patch.object(drill.artifact, "_select_artifact", return_value=selection), \
                patch.object(drill.artifact, "_download", return_value=archive):
            actual_proof, actual = tool.code_archive()
        self.assertEqual(actual_proof, proof)
        self.assertEqual(actual, archive)
        with patch.object(drill.artifact, "_github_token", return_value="synthetic-read-token"), \
                patch.object(drill.artifact, "_select_artifact", return_value=selection), \
                patch.object(drill.artifact, "_download", return_value=b"changed bytes"):
            with self.assertRaises(contract.ContractError):
                tool.code_archive()

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

    def test_inspect_projects_bounded_human_receipts_without_claiming_human_acceptance(self):
        tool = self.tool()
        target, _ = fixture()
        controller = Mock()
        controller.target = target
        controller.inspect.return_value = {"control": {"admission": "closed", "workers": "frozen"}}
        tool.controller = controller
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.bind = Mock(return_value=controller)
        tool.registration = Mock(return_value=target)
        tool.proof = {"revision": REVISION}
        tool.display_timezone = Mock(return_value={"timezone": "UTC", "persisted": True})
        observed = [{"actor_id": "8813701954", "message_id": 123, "command": "help", "state": "sent", "attempts": 1},
            {"actor_id": "8653767757", "message_id": 456, "command": "list", "state": "sent", "attempts": 1}]
        with patch.object(drill, "rows", return_value=observed) as read:
            tool.inspect()
        self.assertEqual(tool.report["humanReceiptsObserved"], 2)
        self.assertEqual(tool.report["humanReceipts"], observed)
        self.assertIs(tool.report["humanAcceptance"], False)
        self.assertIs(tool.report["humanEvidenceRequiresIABCorrelation"], True)
        self.assertEqual(tool.report["displayTimezone"], {"timezone": "UTC", "persisted": True})
        sql = read.call_args.args[2]
        self.assertIn("inbox.update_id<7000000000000000", sql)
        self.assertIn("inbox.actor_id IN ('8813701954','8653767757')", sql)
        self.assertIn("inbox.chat_id=inbox.actor_id", sql)
        self.assertIn("LIMIT 201", sql)
        self.assertNotIn("payload", sql)
        self.assertNotIn("DELETE", sql)
        self.assertNotIn("UPDATE ", sql)

    def test_human_receipt_metadata_rejects_overflow_wrong_actors_and_unbounded_values(self):
        tool = self.tool()
        target, _ = fixture()
        tool.controller = Mock(target=target)
        receipt = {"actor_id": "8813701954", "message_id": 123, "command": "help", "state": "sent", "attempts": 1}
        for changed in ([receipt] * 201,
                [{**receipt, "actor_id": "999999"}], [{**receipt, "command": "https://fixture.invalid/private-link"}],
                [{**receipt, "message_id": True}], [{**receipt, "attempts": -1}],
                [{**receipt, "payload": "synthetic private data must not enter the projection"}]):
            with self.subTest(changed=changed[-1]), patch.object(drill, "rows", return_value=changed):
                with self.assertRaises(contract.ContractError):
                    tool.human_receipts()
        with patch.object(drill, "rows", return_value=[]):
            self.assertEqual(tool.human_receipts(), [])

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
            with self.assertRaises(drill.ProbeStatusError) as caught:
                tool.restore_webhook(automatic=True)
        self.assertEqual(caught.exception.http_status, 503)
        self.assertEqual(caught.exception.expected, (400, 401))
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
        replay = {"version": 1, "status": "passed", "evidenceKind": "hosted-production-restored-data-http-replay", "revision": REVISION,
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
        value = {"version": 1, "status": "passed", "evidenceKind": "hosted-production-restored-data-http-replay", "revision": REVISION,
            "targetSha256": "a" * 64, "moduleSha256": "b" * 64, "restoredDataSha256": "c" * 64,
            "migrationCount": 56, "consumerBound": False, "realTelegramCredentialsSupplied": False,
            "syntheticProductionGateVerified": True, "outboundAttempts": 0,
            "counts": {"storedShareExports": 1, "trashDenials": 1}}
        for change in ({"targetSha256": "d" * 64}, {"moduleSha256": "d" * 64},
                {"restoredDataSha256": "d" * 64}, {"outboundAttempts": 1}, {"status": "stopped"},
                {"realTelegramCredentialsSupplied": True}, {"consumerBound": True}):
            with self.assertRaises(contract.ContractError):
                drill.checked_http_result({**value, **change}, source)
        with self.assertRaises(contract.ContractError):
            drill.checked_http_result({key: item for key, item in value.items() if key != "status"}, source)


if __name__ == "__main__":
    unittest.main()

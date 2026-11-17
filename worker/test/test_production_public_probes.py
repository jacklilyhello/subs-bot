"""Hosted public-probe and interrupted-baseline recovery protocol checks."""
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, call, patch
from urllib.error import HTTPError

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_lifecycle_drill as drill
import production_lifecycle_fixture as fixture_tool
import production_release_evidence as release_evidence
import production_recovery as recovery
import production_target as contract
import test_production_lifecycle_drill as fixtures
import test_production_control as control_fixtures

SECRET = "synthetic-response-secret-must-never-be-reported"
CHECKPOINT, MANIFEST = "a" * 32, "b" * 64


class Response:
    def __init__(self, status, body=b""):
        self.status, self.stream = status, BytesIO(body)

    def read(self, size):
        return self.stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.stream.close()


class PublicProbeTests(unittest.TestCase):
    def tool(self, *, baseline=True):
        env = fixtures.environment()
        if baseline:
            env.update(DRILL_BASELINE_CHECKPOINT_ID=CHECKPOINT, DRILL_BASELINE_MANIFEST_SHA256=MANIFEST)
        tool = drill.Drill(env)
        tool.store = fixtures.MemoryStore()
        target, _ = control_fixtures.fixture()
        controller = Mock(target=target, revision=control_fixtures.REVISION, control_revision=control_fixtures.REVISION)
        controller.inspect.return_value = {"control": {"admission": "closed", "workers": "frozen"}, "work": {"invocations": 0}}
        controller.plan_webhook.return_value = {"stateSha256": "c" * 64, "webhook": {"settingsSha256": "d" * 64}}
        tool.controller = controller
        tool.prepare = Mock(return_value=(Path("/synthetic-unused-bundle"), {}))
        tool.registration = Mock(return_value=target)
        tool.bind = Mock(return_value=controller)
        tool.transition = Mock()
        tool.quiet = Mock()
        tool.code_archive = Mock(side_effect=AssertionError("Reused baseline must not capture again."))
        return tool, controller

    def proof(self, tool):
        return {"baselineVerified": True, "checkpointId": CHECKPOINT, "manifestSha256": MANIFEST,
            "targetSha256": tool.controller.target.digest, "configurationSha256": tool.controller.target.configuration_digest,
            "sourceRevision": tool.controller.revision, "mutationPerformed": False}

    def error_response(self, status, body=b""):
        return HTTPError("https://untrusted.invalid/" + SECRET, status, SECRET, {}, BytesIO(body))

    def test_post_probes_use_pinned_headers_and_original_probe_has_no_update_id(self):
        for original, status in ((False, 503), (True, 400)):
            opener = Mock()
            opener.open.side_effect = self.error_response(status, SECRET.encode())
            secret = "synthetic_webhook_secret_" + "x" * 32
            with self.subTest(original=original), patch.object(drill, "build_opener", return_value=opener) as build:
                result = drill.probe_original_webhook(secret) if original else drill.post_update({"update_id": 7000000000000001}, secret)
            self.assertEqual(result, status)
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "POST")
            self.assertEqual(request.get_header("User-agent"), drill.ISOLATION_RELEASE_USER_AGENT)
            self.assertEqual(request.get_header("Accept"), "application/json")
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(request.get_header("X-telegram-bot-api-secret-token"), secret)
            self.assertIsNone(request.get_header("Authorization"))
            self.assertEqual(request.full_url, (drill.ORIGINAL_ORIGIN if original else drill.ORIGIN) + "/telegram/webhook")
            if original:
                self.assertEqual(request.data, b"{}")
            self.assertEqual(build.call_args.args[0].proxies, {})
            self.assertIsInstance(build.call_args.args[1], drill.NoRedirect)
            self.assertEqual(len(build.call_args.args), 2)
            self.assertEqual(opener.open.call_count, 1)

    def test_wrong_origins_paths_or_business_updates_on_original_target_are_rejected(self):
        for url, options in (("https://wrong.invalid/telegram/webhook", {"method": "POST", "data": b"{}", "secret": "x" * 32}),
                (drill.ORIGINAL_ORIGIN + "/telegram/webhook", {"method": "POST", "data": b'{"update_id":1}', "secret": "x" * 32}),
                (drill.ORIGIN + "/sub/fixture/base64?redirect=secret", {}),
                (drill.ORIGINAL_ORIGIN + "/sub/fixture/base64", {})):
            with self.subTest(url=url), self.assertRaises(contract.ContractError):
                drill.public_request(url, **options)

    def test_status_diagnostics_are_numeric_secret_free_and_do_not_accept_denial(self):
        for expected, case in ((503, "closed-admission"), (401, "wrong-secret"), (400, "original-auth-after")):
            opener = Mock()
            opener.open.side_effect = self.error_response(403, SECRET.encode())
            with patch.object(drill, "build_opener", return_value=opener):
                status = drill.probe_original_webhook("x" * 32)
            with self.assertRaises(drill.ProbeStatusError) as caught:
                drill.expect_status(status, expected, case)
            diagnostic = drill.safe_failure(caught.exception, "closed-admission")
            self.assertEqual(diagnostic["httpStatus"], 403)
            self.assertEqual(diagnostic["expectedStatuses"], [expected])
            self.assertNotIn(SECRET, json.dumps(diagnostic) + str(caught.exception))
            self.assertNotIn("https://", json.dumps(diagnostic) + str(caught.exception))
            self.assertEqual(opener.open.call_count, 1)
        opener.open.side_effect = self.error_response(302)
        with patch.object(drill, "build_opener", return_value=opener):
            self.assertEqual(drill.probe_original_webhook("x" * 32), 302)

    def test_oversized_and_unconfirmed_post_responses_never_retry_or_pass(self):
        for failure in (self.error_response(400, b"x" * 4097), OSError(SECRET)):
            opener = Mock()
            opener.open.side_effect = failure
            with patch.object(drill, "build_opener", return_value=opener):
                with self.assertRaises(drill.OperationError) as caught:
                    drill.probe_original_webhook("x" * 32)
            self.assertTrue(caught.exception.uncertain)
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertEqual(opener.open.call_count, 1)

    def test_fixture_get_head_and_revocation_share_the_same_safe_request_contract(self):
        tool, controller = self.tool()
        body = b"synthetic exact three-node export"
        tool.prepare.return_value = (Path("/synthetic-unused-bundle"), {"snapshots": [{"token": fixture_tool.SMALL_TOKEN,
            "bodyBytes": len(body), "bodySha256": sha256(body).hexdigest()}]})
        opener = Mock()
        opener.open.side_effect = [Response(200, body), Response(200), self.error_response(404), self.error_response(404)]
        with patch.object(fixture_tool, "seed_fixture", return_value={"synthetic": True}), \
                patch.object(drill, "build_opener", return_value=opener):
            tool.seed_fixture()
        self.assertEqual(tool.report["fixture"]["publicPositiveExports"], 2)
        self.assertEqual(tool.report["fixture"]["publicRevokedDenials"], 2)
        self.assertEqual([item.args[0].get_method() for item in opener.open.call_args_list], ["GET", "HEAD", "GET", "HEAD"])
        for item in opener.open.call_args_list:
            request = item.args[0]
            self.assertEqual(request.get_header("User-agent"), drill.ISOLATION_RELEASE_USER_AGENT)
            self.assertEqual(request.get_header("Accept-encoding"), "identity")
            self.assertEqual(request.get_header("Accept"), "text/plain")
            self.assertIsNone(request.get_header("Authorization"))
            self.assertIsNone(request.get_header("X-telegram-bot-api-secret-token"))
            self.assertTrue(request.full_url.startswith(drill.ORIGIN + "/sub/"))
        controller.telegram.call.assert_not_called()

    def test_baseline_pins_must_be_paired_and_well_formed(self):
        for pins in ({"DRILL_BASELINE_CHECKPOINT_ID": CHECKPOINT}, {"DRILL_BASELINE_MANIFEST_SHA256": MANIFEST},
                {"DRILL_BASELINE_CHECKPOINT_ID": "wrong", "DRILL_BASELINE_MANIFEST_SHA256": MANIFEST}):
            with self.subTest(pins=pins), self.assertRaises(contract.ContractError):
                drill.Drill({**fixtures.environment(), **pins})

    def test_explicit_reuse_fully_verifies_before_webhook_and_does_not_thaw_or_capture(self):
        for valid in (False, True):
            tool, controller = self.tool()
            tool.anchors = Mock(side_effect=contract.ContractError("Synthetic stop before webhook."))
            proof = self.proof(tool)
            with self.subTest(valid=valid), patch.object(release_evidence, "verify_activation_baseline",
                    return_value=proof, side_effect=None if valid else contract.ContractError("Synthetic frozen state drift.")) as verify, \
                    patch.object(recovery, "RecoveryAPI") as capture:
                with self.assertRaises(contract.ContractError):
                    tool.exercise()
                verify.assert_called_once_with(controller, tool.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], CHECKPOINT, MANIFEST)
                if valid:
                    self.assertIs(tool.report["baselineReused"], True)
                    self.assertEqual(controller.activation_baseline_checker(), proof)
                    self.assertTrue(any(stage["stage"] == "activation-baseline-reused-verified" for stage in tool.report["stages"]))
                else:
                    tool.anchors.assert_not_called()
                    self.assertFalse(tool.report.get("baselineReused", False))
                capture.assert_not_called()
            tool.transition.assert_not_called()
            tool.code_archive.assert_not_called()
            controller.telegram.call.assert_not_called()
            controller.telegram.configure.assert_not_called()
            controller.configure_webhook.assert_not_called()

    def test_no_explicit_baseline_keeps_fresh_control_sequence(self):
        tool, controller = self.tool(baseline=False)
        tool.activation_baseline = Mock(side_effect=contract.ContractError("Synthetic capture boundary."))
        with self.assertRaises(contract.ContractError):
            tool.exercise()
        self.assertEqual(tool.transition.call_args_list, [call("thaw"), call("pause"), call("freeze")])
        controller.telegram.configure.assert_not_called()
        controller.configure_webhook.assert_not_called()

    def test_primary_probe_failure_survives_cleanup_failure_without_secret_leak(self):
        tool, controller = self.tool()
        tool.anchors = Mock(return_value={"admin": 1, "member": 2})
        controller.telegram.call.return_value = {"url": drill.ORIGINAL_ORIGIN + "/telegram/webhook", "has_custom_certificate": False,
            "max_connections": 40, "allowed_updates": ["message", "callback_query"]}
        controller.configure_webhook.return_value = {"configured": True}
        tool.restore_webhook = Mock(side_effect=drill.ProbeStatusError("original-auth-after", 403, (400,)))
        with patch.object(release_evidence, "verify_activation_baseline", return_value=self.proof(tool)), \
                patch.object(drill, "one", return_value={"n": 1000}), patch.object(drill, "post_update", return_value=403):
            with self.assertRaises(drill.ProbeStatusError) as caught:
                tool.exercise()
        self.assertEqual(caught.exception.case, "closed-admission")
        self.assertEqual(tool.report["primaryFailure"]["httpStatus"], 403)
        self.assertEqual(tool.report["primaryFailure"]["expectedStatuses"], [503])
        self.assertEqual(tool.report["cleanupFailures"][0]["expectedStatuses"], [400])
        self.assertEqual(tool.report["cleanupFailures"][0]["phase"], "cleanup-webhook")
        tool.restore_webhook.assert_called_once_with(automatic=True)
        controller.configure_webhook.assert_called_once()
        tool.quiet.assert_called_once_with()
        tool.transition.assert_not_called()
        report = json.dumps(tool.report)
        self.assertNotIn(tool.previous["webhookSecret"], report)
        self.assertNotIn(tool.secrets["webhookSecret"], report)
        self.assertNotIn("oldWebhookSecret", report)
        self.assertEqual(drill.safe_failure(drill.OperationError(SECRET, uncertain=True), "cleanup-pause"),
            {"phase": "cleanup-pause", "kind": "operation", "uncertain": True})

    def test_external_cleanup_requires_trusted_dispatcher(self):
        tool, controller = self.tool()
        with self.assertRaises(contract.ContractError):
            tool.exercise(external_webhook_cleanup=True)
        controller.telegram.call.assert_not_called()

    def test_open_window_refuses_existing_telegram_pending_updates_before_mutation(self):
        tool, controller = self.tool()
        tool.env["HEAD_TRUSTED_WEBHOOK_CLEANUP"] = "configured-v1"
        tool.backup_evidence_workflow = "worker-backup-reviewed-head.yml"
        tool.anchors = Mock(return_value={"admin": 1, "member": 2})
        controller.telegram.call.return_value = {"url": drill.ORIGINAL_ORIGIN + "/telegram/webhook",
            "has_custom_certificate": False, "max_connections": 40,
            "allowed_updates": ["message", "callback_query"], "pending_update_count": 1}
        with patch.object(release_evidence, "verify_activation_baseline", return_value=self.proof(tool)):
            with self.assertRaises(contract.ContractError):
                tool.exercise(external_webhook_cleanup=True)
        controller.configure_webhook.assert_not_called()

    def test_open_window_pins_snapshot_before_write_and_delegates_restore(self):
        tool, controller = self.tool()
        tool.env["HEAD_TRUSTED_WEBHOOK_CLEANUP"] = "configured-v1"
        tool.backup_evidence_workflow = "worker-backup-reviewed-head.yml"
        tool.anchors = Mock(return_value={"admin": 1, "member": 2})
        controller.telegram.call.return_value = {"url": drill.ORIGINAL_ORIGIN + "/telegram/webhook",
            "has_custom_certificate": False, "max_connections": 40,
            "allowed_updates": ["message", "callback_query"], "pending_update_count": 0}
        controller.configure_webhook.return_value = {"configured": True}
        tool.restore_webhook = Mock()
        with tempfile.TemporaryDirectory() as directory:
            tool.env["RUNNER_TEMP"] = directory
            with patch.object(release_evidence, "verify_activation_baseline", return_value=self.proof(tool)), \
                 patch.object(drill, "one", return_value={"n": 1000}), patch.object(drill, "post_update", return_value=403):
                with self.assertRaises(drill.ProbeStatusError):
                    tool.exercise(external_webhook_cleanup=True)
            pin = json.loads((Path(directory) / "backup-webhook-snapshot-pin.json").read_text())
        self.assertEqual(pin["snapshotSha256"], tool.report["webhookSnapshotSha256"])
        self.assertEqual(pin["controllerRevision"], tool.revision)
        self.assertEqual(pin["dispatcherRevision"], tool.env["GITHUB_SHA"])
        self.assertNotIn(tool.previous["webhookSecret"], json.dumps(pin))
        tool.restore_webhook.assert_not_called()
        self.assertEqual(tool.report["webhookRecovery"]["status"], "pending-trusted-dispatcher")

    def test_successful_open_window_leaves_confirmed_ready_state_to_trusted_cleanup(self):
        tool, controller = self.tool()
        tool.env["HEAD_TRUSTED_WEBHOOK_CLEANUP"] = "configured-v1"
        tool.backup_evidence_workflow = "worker-backup-reviewed-head.yml"
        tool.anchors = Mock(return_value={"admin": 1, "member": 2})
        controller.telegram.call.return_value = {"url": drill.ORIGINAL_ORIGIN + "/telegram/webhook",
            "has_custom_certificate": False, "max_connections": 40,
            "allowed_updates": ["message", "callback_query"], "pending_update_count": 0}
        controller.configure_webhook.return_value = {"configured": True}
        initial = {"control": {"admission": "closed", "workers": "frozen"}, "work": {"invocations": 0}}
        ready = {"control": {"admission": "open", "workers": "run"}, "work": {"invocations": 0},
                 "terminal": {}, "stateSha256": "a" * 64}
        controller.inspect.side_effect = [initial, ready]
        tool.restore_webhook = Mock()
        body = b"synthetic fixture payload"
        states = [{"update_id": 1, "state": "sent", "attempts": 1}, {"update_id": 2, "state": "sent", "attempts": 1}]
        def synthetic_rows(_api, _database, sql):
            if sql.startswith("SELECT * FROM telegram_general_actors"):
                return []
            if "SELECT creation.payload_id" in sql:
                return [{"payload_id": "11111111-1111-4111-8111-111111111111",
                         "payload_sha256": sha256(body).hexdigest(), "state": "published"}]
            if "SELECT inbox.update_id,outbox.state" in sql:
                return states
            raise AssertionError("unexpected synthetic query")
        with tempfile.TemporaryDirectory() as directory:
            tool.env["RUNNER_TEMP"] = directory
            with patch.object(release_evidence, "verify_activation_baseline", return_value=self.proof(tool)), \
                 patch.object(drill, "one", return_value={"n": 1000}), \
                 patch.object(drill, "rows", side_effect=synthetic_rows), \
                 patch.object(drill, "post_update", side_effect=[503, 401, 200, 200, 409, 204, 200]), \
                 patch.object(drill.native, "_response", return_value=(200, {}, body)):
                tool.exercise(verify_extra=lambda *_args: None, external_webhook_cleanup=True)
        self.assertEqual(tool.report["status"], "awaiting-trusted-cleanup")
        self.assertTrue(any(stage["stage"] == "open-backup-ready-for-cleanup" for stage in tool.report["stages"]))
        tool.restore_webhook.assert_not_called()
        self.assertEqual(tool.transition.call_args_list, [call("activate")])


if __name__ == "__main__":
    unittest.main()

"""Hosted app-binding controls, interruption boundaries and safe projections."""
import base64
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_application_provider_drill as app
import production_control as control
import production_lifecycle_drill as lifecycle
import production_provider as provider
import production_target as contract
import test_production_control as fixtures
import test_production_provider as provider_fixtures
import test_production_lifecycle_drill as drill_fixtures


def dependency():
    value = provider_fixtures.config(active=True)
    value["worker"]["workerId"] = "d" * 32
    return value


def frozen():
    return {"control": {"admission": "closed", "workers": "frozen"}, "work": {"invocations": 0},
        "terminal": {}, "stateSha256": "f" * 64}


class ProviderIncidentControlsTests(unittest.TestCase):
    def setUp(self):
        fixtures.ProductionControllerTests.setUp(self)
        self.controller.initialize()
        self.source = self.controller
        self.target = app.desired_target(self.target, dependency())
        self.controller = control.Controller(self.target, self.api, self.api, self.bundle, self.manifest,
            secrets=self.secrets, dependency_api=Mock(), telegram=Mock())
        self.api.controller = self.controller

    def test_busy_or_failed_dependency_does_not_prevent_inspect_or_pause_under_load(self):
        for identity, failure in (("a" * 32, provider.ProviderError("Synthetic active Container.")),
                                  ("b" * 32, provider.ProviderError("Synthetic unavailable upstream."))):
            self.api.db.execute("UPDATE subs_bot_production_control SET admission='open',workers='run'")
            with self.subTest(kind=str(failure)), patch.object(provider, "verify_provider_dependency", side_effect=failure) as strict:
                self.api.db.execute("""INSERT INTO subs_bot_production_invocations
                    VALUES(?,?,?,1,'scheduled',unixepoch(),unixepoch()+960,'running',NULL)""",
                    (identity, self.target.digest, self.target.data["botId"]))
                plan = self.controller.plan_pause()
                self.api.db.execute("UPDATE subs_bot_production_invocations SET state='finished',finished_at=unixepoch()")
                paused = self.controller.transition("pause", fixtures.approval(self.target, "pause", plan["stateSha256"]), plan["stateSha256"])
                self.assertEqual(paused["control"]["admission"], "closed")
                self.assertEqual(paused["control"]["workers"], "run")
                sealed = self.controller.transition("freeze", fixtures.approval(self.target, "freeze", paused["stateSha256"]), paused["stateSha256"])
                self.assertEqual(sealed["control"]["workers"], "frozen")
                strict.assert_not_called()
                # Activation still requires real live dependency health, before
                # it could evaluate a baseline or mutate the admission fence.
                self.controller.guard = Mock()
                with self.assertRaises(provider.ProviderError):
                    self.controller.plan_activate()
                self.controller.guard.assert_not_called()
                strict.assert_called_once_with(self.controller.dependency_api, self.target.data["provider"], allow_unbound_caller=False)

    def test_wrong_actual_service_binding_blocks_pause_before_control_mutation(self):
        original = self.controller.active
        def wrong(**options):
            value = original(**options)
            value["bindings"]["PROVIDER_FETCH"]["service"] = "foreign-project-worker"
            return value
        self.controller.active = wrong
        self.controller.guard = Mock()
        with self.assertRaises(contract.ContractError):
            self.controller.plan_pause()
        self.controller.guard.assert_not_called()
        self.assertEqual(self.api.db.execute("SELECT admission,epoch FROM subs_bot_production_control").fetchone()[:], ("closed", 1))

    def test_enabling_deployment_requires_strict_proof_before_any_version_upload(self):
        self.api.controller = self.source
        planned = self.controller.plan_deploy(self.source)
        with patch.object(provider, "verify_provider_dependency", side_effect=provider.ProviderError("Synthetic not stopped.")) as strict:
            with self.assertRaises(provider.ProviderError):
                self.controller.deploy(fixtures.approval(self.target, "deploy", planned["stateSha256"]),
                    planned["stateSha256"], source_controller=self.source)
        strict.assert_called_once_with(self.controller.dependency_api, self.target.data["provider"], allow_unbound_caller=True)
        self.assertFalse(any(method != "GET" and "/workers/" in path for method, path, _ in self.api.requests))


class ApplicationProviderProtocolTests(unittest.TestCase):
    def runner(self):
        target, secrets = fixtures.fixture()
        body = base64.b64encode(b"synthetic complete source")
        manifest = {"revision": fixtures.REVISION, "snapshots": [{"bodyBytes": len(body), "bodySha256": sha256(body).hexdigest()}]}
        source = Mock(target=target)
        source.inspect.return_value = frozen()
        on = Mock(target=app.desired_target(target, dependency()), revision=fixtures.REVISION)
        off = Mock(target=target, revision=fixtures.REVISION)
        for controller in (on, off):
            controller.plan_deploy.return_value = frozen()
            controller.deploy.return_value = frozen()
            controller.inspect.return_value = frozen()
        runner = SimpleNamespace(env={"DRILL_PROVIDER_READY_ACK": app.READY,
            "SUBS_BOT_CF_DEPENDENCY_READ_TOKEN": "synthetic-limited-reader", "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-data",
            "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-worker", "DRILL_PROVIDER_RUN_ID": "300", "DRILL_PROVIDER_RUN_ATTEMPT": "1",
            "DRILL_PROVIDER_MANIFEST_SHA256": "e" * 64}, human_window=300, attempt="1", run="1001", baseline_checkpoint="",
            revision=fixtures.REVISION, secrets=secrets, guard=Mock(), prefix="synthetic/private/", proof={"revision": fixtures.REVISION},
            report={}, prepare=Mock(return_value=(Path("/unused-synthetic-bundle"), manifest)), registration=Mock(return_value=target),
            bind=Mock(return_value=source), store=drill_fixtures.MemoryStore(), save=Mock(), controller=source)
        def exercise(**_kwargs):
            runner.report.update(webhookCheckpoint="1001/1", webhookRecovery={"webhookRestored": True,
                "originalWebhookAuthProbe": {"status": 400}}, applicationProviderCases={"realRefreshSaved": True})
        runner.exercise = Mock(side_effect=exercise)
        wire = {"origin": lifecycle.ORIGIN, "originalOrigin": lifecycle.ORIGINAL_ORIGIN, "approval": Mock(return_value={}),
            "public_readback": Mock(return_value=(200, body)), "public_request": Mock(), "expect_status": lifecycle.expect_status}
        loaded = {"config": dependency(), "evidence": {"manifestSha256": "e" * 64}}
        return runner, wire, loaded, source, on, off

    def execute(self, runner, wire, loaded, on, off):
        with patch.object(app, "seed_fixture", return_value={"synthetic": True}), patch.object(app, "load_provider", return_value=loaded), \
                patch.object(app, "DependencyReadOnly", return_value=Mock()), patch.object(app, "API"), patch.object(app, "Telegram"), \
                patch.object(app, "Controller", side_effect=[on, off]), \
                patch.object(provider, "verify_provider_dependency", side_effect=lambda *_args, **options:
                    {"callerState": "unbound" if options.get("allow_unbound_caller") else "bound"}):
            app.run(runner, wire)

    def test_complete_protocol_uses_real_controller_deploy_contract_on_and_off(self):
        runner, wire, loaded, source, on, off = self.runner()
        self.execute(runner, wire, loaded, on, off)
        self.assertEqual(runner.prepare.call_args_list, [call(active=True), call()])
        on.plan_deploy.assert_called_once_with(source)
        on.deploy.assert_called_once_with({}, "f" * 64, source_controller=source)
        off.plan_deploy.assert_called_once_with(on)
        off.deploy.assert_called_once_with({}, "f" * 64, source_controller=on)
        self.assertIs(runner.exercise.call_args.kwargs["provided_controller"], on)
        self.assertTrue(callable(runner.exercise.call_args.kwargs["verify_extra"]))
        self.assertEqual(runner.report["status"], "passed")
        self.assertTrue(runner.report["applicationProvider"]["configurationRestored"])
        self.assertIs(runner.controller, off)
        self.assertEqual(len(runner.store.values), 1)
        self.assertNotIn("registration.json", " ".join(runner.store.values))
        self.assertIs(on.target.data["features"]["providerRefresh"], True)
        self.assertIsNone(off.target.data["provider"])

    def test_unknown_enable_is_not_retried_or_hidden_by_cleanup(self):
        runner, wire, loaded, _source, on, off = self.runner()
        on.deploy.side_effect = control.OperationError("Synthetic unconfirmed deployment.", uncertain=True)
        with self.assertRaises(control.OperationError) as caught:
            self.execute(runner, wire, loaded, on, off)
        self.assertTrue(caught.exception.uncertain)
        on.deploy.assert_called_once()
        off.deploy.assert_not_called()
        runner.exercise.assert_not_called()
        self.assertEqual(len(runner.store.values), 1)
        self.assertNotEqual(runner.report.get("status"), "passed")

    def test_one_shot_intent_rejects_blind_repeated_deployment(self):
        runner, wire, loaded, _source, on, off = self.runner()
        admission = runner.prefix + "provider-binding/" + provider.digest(loaded["config"]) + "/" + runner.revision + "/admission.json"
        runner.store.put(admission, b"synthetic interrupted intent")
        with self.assertRaises(contract.ContractError):
            self.execute(runner, wire, loaded, on, off)
        on.deploy.assert_not_called()
        off.deploy.assert_not_called()

    def test_unconfirmed_original_auth_prevents_off_release_and_false_success(self):
        runner, wire, loaded, _source, on, off = self.runner()
        def failed(**_kwargs):
            runner.report.update(webhookCheckpoint="1001/1", webhookRecovery={"webhookRestored": True,
                "originalWebhookAuthProbe": {"status": 401}})
            raise control.OperationError("Synthetic authentication failure.")
        runner.exercise.side_effect = failed
        with self.assertRaises(control.OperationError):
            self.execute(runner, wire, loaded, on, off)
        off.deploy.assert_not_called()
        self.assertFalse(runner.report["applicationProvider"]["configurationRestored"])
        self.assertNotEqual(runner.report.get("status"), "passed")

    def test_unknown_disable_preserves_both_contracts_and_never_retries(self):
        runner, wire, loaded, _source, on, off = self.runner()
        off.deploy.side_effect = control.OperationError("Synthetic unconfirmed off release.", uncertain=True)
        with self.assertRaises(control.OperationError):
            self.execute(runner, wire, loaded, on, off)
        off.deploy.assert_called_once()
        self.assertFalse(runner.report["applicationProvider"]["configurationRestored"])
        self.assertNotEqual(runner.report.get("status"), "passed")
        self.assertIn("provider-binding-off-intent", [args.args[0] for args in runner.save.call_args_list])

    def test_unknown_terminal_preserves_safe_off_path_but_cannot_become_passed(self):
        runner, wire, loaded, _source, on, off = self.runner()
        on.inspect.return_value = {**frozen(), "terminal": {"unknownInvocations": 1}}
        with self.assertRaises(contract.ContractError):
            self.execute(runner, wire, loaded, on, off)
        off.deploy.assert_called_once()
        self.assertTrue(runner.report["applicationProvider"]["configurationRestored"])
        self.assertNotEqual(runner.report.get("status"), "passed")

    def test_missing_readiness_baseline_reuse_or_wrong_target_never_deploys(self):
        for change in ({"baseline_checkpoint": "a" * 32}, {"human_window": 0}, {"attempt": "2"}):
            runner, wire, loaded, _source, on, off = self.runner()
            for key, value in change.items():
                setattr(runner, key, value)
            with self.subTest(change=change), self.assertRaises(contract.ContractError):
                self.execute(runner, wire, loaded, on, off)
            on.deploy.assert_not_called()
            runner.prepare.assert_not_called()
        target, _ = fixtures.fixture()
        value = dependency()
        value["caller"] = {"id": target.data["workerId"], "name": target.data["workerName"]}
        with self.assertRaises(contract.ContractError):
            app.desired_target(target, value)

    def test_positive_export_requires_exact_uri_sequence_not_just_three_rows(self):
        target, _ = fixtures.fixture()
        ctl = Mock(target=target)
        expected = base64.b64encode(b"ss://synthetic-a\nss://synthetic-b\nss://synthetic-c")
        wire = {"origin": lifecycle.ORIGIN, "public_request": Mock(), "public_readback": Mock(return_value=(200, expected)),
            "expect_status": lifecycle.expect_status}
        with patch.object(app, "rows", return_value=[{"token": "synthetic-positive-token"}]):
            self.assertEqual(app.positive_export(None, ctl, 1, expected, wire)["nodeCount"], 3)
            wire["public_readback"].return_value = (200, base64.b64encode(b"ss://synthetic-c\nss://synthetic-b\nss://synthetic-a"))
            with self.assertRaises(contract.ContractError):
                app.positive_export(None, ctl, 1, expected, wire)


class DisplayAndWindowTests(unittest.TestCase):
    def tool(self):
        tool = lifecycle.Drill(drill_fixtures.environment())
        tool.controller = Mock(target=fixtures.fixture()[0])
        return tool

    def test_safe_timezone_default_and_exact_persisted_utc_projection(self):
        tool = self.tool()
        with patch.object(lifecycle, "rows", return_value=[]) as read:
            self.assertEqual(tool.display_timezone(), {"timezone": "UTC", "persisted": False,
                "updated_by": None, "update_id": None, "message_date": None})
        self.assertIn("WHERE bot_id='92001' LIMIT 2", read.call_args.args[2])
        row = {"timezone": "UTC", "updated_by": "8813701954", "update_id": 123, "message_date": 456}
        with patch.object(lifecycle, "rows", return_value=[row]):
            self.assertEqual(tool.display_timezone(), {**row, "persisted": True})
        for bad in ({**row, "timezone": "Not/A_Real_Zone"}, {**row, "updated_by": "8653767757"},
                    {**row, "update_id": True}, {**row, "unapprovedField": "payload"}):
            with self.subTest(row=bad), patch.object(lifecycle, "rows", return_value=[bad]), self.assertRaises(contract.ContractError):
                tool.display_timezone()
        with patch.object(lifecycle, "rows", return_value=[row, row]), self.assertRaises(contract.ContractError):
            tool.display_timezone()

    def test_extended_window_is_limited_to_provider_and_its_independent_cleanup(self):
        env = {**drill_fixtures.environment(), "DRILL_HUMAN_WINDOW_SECONDS": "300"}
        for action in ("provider-binding", "recover-webhook"):
            self.assertEqual(lifecycle.Drill({**env, "DRILL_ACTION": action}).human_window, 300)
        with self.assertRaises(contract.ContractError):
            lifecycle.Drill({**env, "DRILL_ACTION": "exercise"})
        with self.assertRaises(contract.ContractError):
            lifecycle.Drill({**env, "DRILL_ACTION": "provider-binding", "DRILL_HUMAN_WINDOW_SECONDS": "541"})

    def test_public_fixture_query_is_exact_and_never_an_arbitrary_forward_target(self):
        url = lifecycle.ORIGIN + "/sub/subsbot-synthetic-small-01/base64?provider_fixture=1001-1"
        self.assertEqual(lifecycle.public_request(url).full_url, url)
        for changed in (url + "&redirect=https://foreign.invalid", url.replace("1001-1", "001-1"),
                        url.replace("subsbot-synthetic-small-01", "foreign-token"), url.replace("provider_fixture", "target")):
            with self.subTest(url=changed), self.assertRaises(contract.ContractError):
                lifecycle.public_request(changed)


if __name__ == "__main__":
    unittest.main()

"""Hosted protocol tests for explicit owned deployment reconciliation."""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_application_provider_resume as resume
import production_target as contract
import test_production_application_provider_drill as app_fixtures
import test_production_control as fixtures

VERSION = "30000000-0000-4000-8000-000000000003"
DEPLOYMENT = "40000000-0000-4000-8000-000000000004"


def state_hash(value):
    value["stateSha256"] = contract.digest({key: item for key, item in value.items() if key != "stateSha256"})
    return value


class InterruptedBindingTests(unittest.TestCase):
    def setup_protocol(self):
        runner, wire, loaded, _source, on, off = app_fixtures.ApplicationProviderProtocolTests().runner()
        original = runner.registration.return_value
        runner.revision = "c" * 40
        bundle, manifest = runner.prepare.return_value
        manifest.update(migrations=[], bundleSha256="d" * 64)
        runner.proof = {"revision": fixtures.REVISION, "runId": "11", "runAttempt": "1",
            "artifactId": "21", "archiveSha256": "e" * 64}
        before = state_hash({"targetSha256": on.target.digest, "configurationSha256": on.target.configuration_digest,
            "control": {"singleton": 1, "target_sha256": on.target.digest, "bot_id": original.data["botId"],
                "generation": 1, "epoch": 18, "release_revision": "a" * 40, "admission": "closed", "workers": "frozen"},
            "release": {"versionId": fixtures.VERSION, "deploymentId": fixtures.DEPLOYMENT, "revision": "a" * 40,
                "moduleSha256": "a" * 64, "compatibilityDate": "2026-07-30"},
            "work": {"invocations": 0}, "terminal": {}, "migrationCount": 0})
        previous = {**before["release"], "bindings": {"BUILD_REVISION": {
            "type": "plain_text", "name": "BUILD_REVISION", "text": "a" * 40}}}
        active = {"versionId": VERSION, "deploymentId": DEPLOYMENT, "revision": fixtures.REVISION,
            "moduleSha256": "d" * 64, "compatibilityDate": "2026-07-30", "bindings": {"BUILD_REVISION": {
                "type": "plain_text", "name": "BUILD_REVISION", "text": fixtures.REVISION}}}
        current = state_hash({**deepcopy(before), "release": {key: item for key, item in active.items() if key != "bindings"},
            "reconcileCron": [{"cron": "* * * * *"}]})
        on.active.return_value = active
        on.verify_bindings.return_value = None
        on.plan_reconcile_deploy.return_value = current
        reconciled = state_hash({**deepcopy(current), "control": {**current["control"], "epoch": 19,
            "release_revision": fixtures.REVISION}})
        on.reconcile_deploy.return_value = reconciled
        intent = {"runId": "1000", "runAttempt": "1", "sourceTarget": original.data, "desiredTarget": on.target.data,
            "sourceProof": {**runner.proof, "revision": "a" * 40, "runId": "10", "artifactId": "20"},
            "desiredProof": deepcopy(runner.proof), "before": before, "providerEvidence": loaded["evidence"]}
        raw = contract.canonical(intent)
        params = {"runId": "1000", "runAttempt": "1", "intentSha256": sha256(raw).hexdigest(),
            "versionId": VERSION, "deploymentId": DEPLOYMENT}
        runner.env["DRILL_PROVIDER_BINDING_RESUME_JSON"] = contract.canonical(params).decode()
        runner.env["RUNNER_TEMP"] = "/unused-synthetic-runner"
        key = runner.prefix + "provider-binding/" + resume.app.provider.digest(loaded["config"]) + "/" + fixtures.REVISION + "/admission.json"
        local = runner.prefix + "1000-1-provider-binding-on-intent.json"
        runner.store.put(key, raw)
        runner.store.put(local, raw)
        return runner, wire, loaded, on, off, intent, previous, active, key, local

    def execute(self, value, *, reconcile_only=False):
        runner, wire, loaded, on, off, intent, previous, active, key, local = value
        with patch.object(resume.app, "load_provider", return_value=loaded), \
                patch.object(resume.app, "DependencyReadOnly", return_value=Mock()), \
                patch.object(resume.app, "controllers", return_value=(on, off)) as created, \
                patch.object(resume, "original_release", return_value=previous), \
                patch.object(resume.app, "complete_binding", return_value="continued") as completed:
            result = resume.run(runner, wire, reconcile_only=reconcile_only)
        return result, created, completed

    def test_resume_approves_real_reconcile_without_reupload_or_new_admission(self):
        value = self.setup_protocol()
        runner, wire, _loaded, on, off, intent, _previous, active, key, _local = value
        stored = deepcopy(runner.store.values)
        result, created, completed = self.execute(value)
        self.assertEqual(result, "continued")
        runner.prepare.assert_called_once_with(active=True)
        self.assertNotEqual(runner.revision, on.revision)
        on.reconcile_deploy.assert_called_once_with({}, on.plan_reconcile_deploy.return_value["stateSha256"],
            predecessor=intent["before"], expected_active=active)
        self.assertEqual(wire["approval"].call_args.args[1:3], ("reconcile-deploy", fixtures.REVISION))
        on.deploy.assert_not_called()
        off.deploy.assert_not_called()
        self.assertEqual(runner.store.values, stored)
        self.assertEqual(contract.digest(intent), runner.report["applicationProvider"]["oneShotIntentSha256"])
        self.assertIs(created.call_args.args[0], runner)
        completed.assert_called_once()

    def test_wrong_pins_proofs_or_full_contract_cannot_reconcile(self):
        for change in ("digest", "run-local", "runtime", "config", "control", "control-boolean", "unknown", "version"):
            value = self.setup_protocol()
            runner, _wire, _loaded, on, _off, intent, _previous, active, key, local = value
            if change == "digest":
                params = contract.parsed(runner.env["DRILL_PROVIDER_BINDING_RESUME_JSON"])
                params["intentSha256"] = "0" * 64
                runner.env["DRILL_PROVIDER_BINDING_RESUME_JSON"] = contract.canonical(params).decode()
            elif change == "run-local":
                runner.store.values[local] = b"different immutable record"
            elif change == "runtime":
                runner.proof["artifactId"] = "999"
            elif change == "config":
                changed = deepcopy(intent)
                changed["desiredTarget"]["features"]["inlineSearch"] = True
                raw = contract.canonical(changed)
                runner.store.values[key] = runner.store.values[local] = raw
                params = contract.parsed(runner.env["DRILL_PROVIDER_BINDING_RESUME_JSON"])
                params["intentSha256"] = sha256(raw).hexdigest()
                runner.env["DRILL_PROVIDER_BINDING_RESUME_JSON"] = contract.canonical(params).decode()
            elif change == "control":
                on.plan_reconcile_deploy.return_value["control"]["epoch"] = 20
            elif change == "control-boolean":
                on.plan_reconcile_deploy.return_value["control"]["generation"] = True
            elif change == "unknown":
                on.plan_reconcile_deploy.return_value["terminal"]["unknownUpdates"] = 1
            else:
                active["versionId"] = "50000000-0000-4000-8000-000000000005"
            with self.subTest(change=change), self.assertRaises((contract.ContractError, ValueError)):
                self.execute(value)
            on.reconcile_deploy.assert_not_called()
            on.deploy.assert_not_called()

    def test_only_exact_single_successor_can_continue_and_fixture_must_still_match(self):
        value = self.setup_protocol()
        runner, wire, _loaded, on, _off, _intent, _previous, _active, _key, _local = value
        on.plan_reconcile_deploy.return_value = deepcopy(on.reconcile_deploy.return_value)
        result, _created, completed = self.execute(value)
        self.assertEqual(result, "continued")
        completed.assert_called_once()
        value = self.setup_protocol()
        value[1]["public_readback"].return_value = (200, b"different complete fixture")
        with self.assertRaises(contract.ContractError):
            self.execute(value)
        value[3].reconcile_deploy.assert_called_once()
        self.assertNotEqual(value[0].report.get("status"), "passed")

    def test_missing_or_nonobject_explicit_resume_parameters_are_rejected(self):
        for raw in ("", "[]", "null", "{}", '{"runId":"1000"}'):
            with self.subTest(raw=raw), self.assertRaises(contract.ContractError):
                resume.parameters(raw)

    def test_reconcile_only_stops_closed_without_webhook_import_or_off_and_never_reports_passed(self):
        value = self.setup_protocol()
        runner, wire, _loaded, on, off, _intent, _previous, _active, _key, _local = value
        runner.human_window = 0
        runner.env.pop("DRILL_PROVIDER_READY_ACK")
        result, _created, completed = self.execute(value, reconcile_only=True)
        self.assertIsNone(result)
        self.assertEqual(runner.report["status"], "reconciled-closed-only")
        self.assertIs(runner.report["humanAcceptance"], False)
        self.assertEqual(runner.report["state"]["control"]["epoch"], 19)
        self.assertEqual(runner.report["configurationSha256"], on.target.configuration_digest)
        self.assertEqual(set(runner.report["providerBusinessAcceptance"].values()), {"not-run"})
        on.reconcile_deploy.assert_called_once()
        completed.assert_not_called()
        wire["public_readback"].assert_not_called()
        off.deploy.assert_not_called()

    def test_factory_keeps_frozen_runtime_and_current_control_approval_distinct(self):
        value = self.setup_protocol()
        runner, wire, _loaded, on, _off, _intent, _previous, _active, _key, _local = value
        original = runner.registration.return_value
        bundle, manifest = runner.prepare.return_value
        with patch.object(resume.app, "API", return_value=Mock()), patch.object(resume.app, "Telegram", return_value=Mock()):
            current, _off = resume.app.controllers(runner, wire, original, on.target, bundle, manifest, Mock())
        self.assertEqual(current.revision, fixtures.REVISION)
        self.assertEqual(current.control_revision, runner.revision)
        envelope = fixtures.approval(on.target, "reconcile-deploy", "f" * 64)
        with self.assertRaises(contract.ContractError):
            current.approval(envelope, "reconcile-deploy", "f" * 64)
        current.approval({**envelope, "controlRevision": runner.revision}, "reconcile-deploy", "f" * 64)

    def test_original_source_requires_the_full_ci_archive_proof_before_any_version_read(self):
        value = self.setup_protocol()
        runner, _wire, _loaded, _on, _off, intent, _previous, _active, _key, _local = value
        wrong = {**intent["sourceProof"], "archiveSha256": "0" * 64}
        with TemporaryDirectory() as directory, patch.object(resume.prepare_control_artifact, "prepare", return_value=wrong), \
                patch.object(resume, "Controller") as constructed:
            runner.env["RUNNER_TEMP"] = directory
            with self.assertRaises(contract.ContractError):
                resume.original_release(runner, runner.registration.return_value, intent, intent["before"])
        constructed.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Rehearsal orchestration boundaries, tested only on hosted CI."""

from copy import deepcopy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider_rehearsal as rehearsal
import production_provider as control
from test_production_provider import BUILD, REVISION, STAMP, WORKER_ID, config


class RehearsalTests(unittest.TestCase):
    def test_health_target_is_checked_before_network(self):
        for url in ("http://127.0.0.1/health", "file:///tmp/health", "https://another-project.example/health"):
            with patch.object(control.legacy, "_public") as read, self.assertRaises(control.ProviderError):
                rehearsal.initial_config(BUILD, url, REVISION)
            read.assert_not_called()

    def test_initial_identity_is_dedicated_and_never_production(self):
        with patch.object(control.legacy, "_public", return_value={"bytes": 87, "sha256": "4" * 64}):
            value = rehearsal.initial_config(BUILD, "https://subs-bot-cf-dev-01.lilyya.workers.dev/health", REVISION)
        self.assertEqual(value["environment"], "rehearsal")
        self.assertEqual(value["service"], "subs-bot-provider-fetch-control-drill-01")
        self.assertIsNone(value["worker"])
        self.assertIsNone(value["caller"])

    def test_shared_context_refuses_production_under_rehearsal_workflow(self):
        value = config()
        value["environment"], value["service"] = "production", control.SERVICES["production"]
        value["workersDevOrigin"] = "https://subs-bot-provider-fetch-prod-01.fixture.workers.dev"
        env = {"GITHUB_SHA": REVISION, "GITHUB_REPOSITORY": control.github.REPOSITORY, "GITHUB_REF": control.github.MAIN_REF,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_WORKFLOW_SHA": REVISION,
               "GITHUB_WORKFLOW_REF": f"{control.github.REPOSITORY}/{control.REHEARSAL_WORKFLOW_PATH}@{control.github.MAIN_REF}",
               "SUBS_BOT_PROVIDER_CONTROL_ENVIRONMENT": "production"}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(control.ProviderError):
            control.request_context("verify", value)


class DurableIntentTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.environment = patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "GITHUB_SHA": REVISION,
                                                  "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.context = patch.object(rehearsal, "context")
        self.context.start()
        self.addCleanup(self.context.stop)
        self.target = config()
        self.target.update({"worker": None, "versionId": None})
        journal = {"version": 2, "controllerRevision": REVISION, "runId": "100", "runAttempt": "1", "source": BUILD,
                   "events": [], "steps": [], "currentIntent": None, "completion": "not-complete"}
        rehearsal.checkpoint(self.target, journal)

    def prepare(self):
        reader = Mock()
        reader._request.return_value = None
        with patch.object(rehearsal, "approve"), patch.object(rehearsal, "api", return_value=reader):
            rehearsal.prepare_operation("create")

    def saved(self):
        return json.loads((self.root / rehearsal.CHECKPOINT).read_bytes())

    def test_intent_records_source_approval_and_preflight_without_dispatch(self):
        with patch.object(rehearsal, "execute") as mutation:
            self.prepare()
        mutation.assert_not_called()
        intent = self.saved()["journal"]["currentIntent"]
        self.assertEqual(intent["status"], "started-unknown")
        self.assertFalse(intent["executed"])
        self.assertTrue(intent["preflight"]["workerNameAbsent"])
        self.assertEqual(intent["source"], BUILD)
        self.assertEqual(intent["approvalSha256"], control.digest({"operation": "create", "target": self.target}))

    def test_missing_cloud_artifact_receipt_prevents_mutation(self):
        self.prepare()
        with patch.object(rehearsal, "execute") as mutation, self.assertRaises(control.ProviderError):
            rehearsal.execute_operation("create")
        mutation.assert_not_called()
        self.assertEqual(self.saved()["journal"]["currentIntent"]["status"], "failed-before-dispatch")

    def test_response_identity_survives_later_failure_and_cannot_be_replayed(self):
        self.prepare()

        def uncertain(_config, _operation, _module, _archive, *, sink):
            sink({"kind": "response-only", "identities": {"id": WORKER_ID, "created_on": STAMP}})
            raise control.ProviderError("synthetic-secret-not-recorded")

        with patch.object(rehearsal, "persisted_intent", return_value={"artifactId": "42", "archiveSha256": "7" * 64}), \
                patch.object(rehearsal, "approve"), patch.object(rehearsal, "verified_input", return_value=(self.root / "image", BUILD, b"module")), \
                patch.object(rehearsal, "execute", side_effect=uncertain) as mutation, self.assertRaises(control.ProviderError):
            rehearsal.execute_operation("create")
        self.assertEqual(mutation.call_count, 1)
        saved = self.saved()
        self.assertIsNone(saved["target"]["worker"])
        self.assertEqual(saved["journal"]["currentIntent"]["status"], "unconfirmed")
        observations = [event for event in saved["journal"]["events"] if event["phase"] == "observation"]
        self.assertEqual(observations[0]["identities"]["id"], WORKER_ID)
        self.assertNotIn("synthetic-secret-not-recorded", json.dumps(saved))
        with patch.object(rehearsal, "execute") as repeated, self.assertRaises(control.ProviderError):
            rehearsal.execute_operation("create")
        repeated.assert_not_called()
        with patch.object(rehearsal, "verified_input") as read, self.assertRaises(control.ProviderError):
            rehearsal.finalize()
        read.assert_not_called()
        self.assertFalse((self.root / "provider-rehearsal-proof.json").exists())

    def test_checkpoint_from_another_run_is_rejected(self):
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "200"}), self.assertRaises(control.ProviderError):
            rehearsal.load_checkpoint()

    def test_registered_source_resumes_frozen_revision_without_upgrading_partial_target(self):
        old = config()
        old["versionId"] = None
        with patch.dict(os.environ, {"GITHUB_SHA": "9" * 40, "SUBS_BOT_PROVIDER_REHEARSAL_TARGET_JSON": json.dumps(old),
                                     "SUBS_BOT_PROVIDER_REHEARSAL_SOURCE_MODE": "registered", "SUBS_BOT_PROVIDER_CI_RUN_ID": BUILD["runId"]}):
            _mode, target, revision = rehearsal.selection()
        self.assertEqual(revision, REVISION)
        self.assertIsNone(target["versionId"])

    def test_failed_job_never_packages_a_stale_proof_as_complete(self):
        (self.root / "provider-rehearsal-proof.json").write_bytes(b'{"status":"complete"}')
        with patch.dict(os.environ, {"PROVIDER_REHEARSAL_OUTCOME": "failure"}):
            rehearsal.assemble("final")
        attempt = json.loads((self.root / "provider-proof-output/provider-rehearsal-attempt.json").read_bytes())
        self.assertEqual(attempt["completion"], "not-complete")

    def test_artifact_receipt_is_bound_to_this_exact_main_run(self):
        artifact = {"name": "subs-bot-provider-attempt-intent-create-100-1", "expired": False, "digest": "sha256:" + "7" * 64,
                    "workflow_run": {"id": 100, "repository_id": control.github.REPOSITORY_ID, "head_branch": "main", "head_sha": REVISION}}
        env = {"SUBS_BOT_PROVIDER_INTENT_ARTIFACT_ID": "42", "SUBS_BOT_PROVIDER_INTENT_ARTIFACT_SHA256": "7" * 64}
        with patch.dict(os.environ, env), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=artifact):
            self.assertEqual(rehearsal.persisted_intent("create")["artifactId"], "42")
            artifact["workflow_run"]["head_sha"] = "9" * 40
            with self.assertRaises(control.ProviderError):
                rehearsal.persisted_intent("create")


if __name__ == "__main__":
    unittest.main()

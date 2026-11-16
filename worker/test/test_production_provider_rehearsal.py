"""Rehearsal orchestration boundaries, tested only on hosted CI."""

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider_rehearsal as rehearsal
import production_provider as control
from test_production_provider import BUILD, REVISION, config


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


if __name__ == "__main__":
    unittest.main()

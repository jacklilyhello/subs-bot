import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import backup_fixture_create as fixture
from production_target import ContractError


class FixtureCreateTests(unittest.TestCase):
    def setUp(self):
        self.name = "subs-bot-cf-backup-capacity-20261118"
        self.env = {"GITHUB_RUN_ID": "123", "GITHUB_SHA": "a" * 40,
                    "FIXTURE_D1_READ_TOKEN": "read", "FIXTURE_D1_WRITE_TOKEN": "write"}
        self.objects = Mock()
        self.objects.list.return_value = []
        self.objects.get.side_effect = lambda key: (self.objects.put_once.call_args.args[1], '"etag"')

    def test_unapproved_name_never_calls_api(self):
        env = {**self.env, "GITHUB_REPOSITORY": fixture.github.REPOSITORY,
               "GITHUB_REPOSITORY_ID": str(fixture.github.REPOSITORY_ID), "GITHUB_REF": fixture.github.MAIN_REF,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
               "RUNNER_ENVIRONMENT": "github-hosted", "FIXTURE_ENVIRONMENT": "subs-bot-backup-head-isolation",
               "GITHUB_WORKFLOW_REF": fixture.github.REPOSITORY + "/.github/workflows/worker-backup-fixture-create.yml@refs/heads/main",
               "GITHUB_WORKFLOW_SHA": "a" * 40, "FIXTURE_MAIN_SHA": "a" * 40,
               "FIXTURE_CREATE_ENABLED": "true", "GH_TOKEN": "synthetic", "FIXTURE_NAME": "another-project"}
        with patch.object(fixture.github, "_get_json") as api, self.assertRaises(ContractError):
            fixture.guard(env)
        api.assert_not_called()
        env["FIXTURE_NAME"] = self.name
        with patch.object(fixture.github, "_get_json", return_value={"ref": fixture.github.MAIN_REF,
             "object": {"sha": "a" * 40}}) as api:
            self.assertEqual(fixture.guard(env), self.name)
            self.assertEqual(api.call_count, 1)
        for key, value in (("FIXTURE_CREATE_ENABLED", "false"), ("FIXTURE_MAIN_SHA", "b" * 40)):
            with patch.object(fixture.github, "_get_json") as api, self.assertRaises(ContractError):
                fixture.guard({**env, key: value})
            api.assert_not_called()

    def test_existing_intent_or_name_stops_before_create(self):
        for has_intent in (True, False):
            with self.subTest(intent=has_intent), patch.object(fixture, "guard", return_value=self.name), \
                 patch.object(fixture, "store", return_value=self.objects), \
                 patch.object(fixture, "inventory", return_value=[] if has_intent else [{"name": self.name}]), \
                 patch.object(fixture, "CloudflareClient") as client:
                self.objects.list.return_value = ["occupied"] if has_intent else []
                with self.assertRaises(ContractError):
                    fixture.create(self.env)
                client.assert_not_called()
                self.objects.put_once.assert_not_called()

    def test_unknown_post_is_once_and_intent_is_preserved(self):
        with patch.object(fixture, "guard", return_value=self.name), \
             patch.object(fixture, "store", return_value=self.objects), \
             patch.object(fixture, "inventory", return_value=[]), \
             patch.object(fixture, "CloudflareClient") as client:
            client.return_value.side_effect = OSError("unconfirmed")
            with self.assertRaises(OSError):
                fixture.create(self.env)
            self.assertEqual(client.return_value.call_count, 1)
            self.assertEqual(client.return_value.call_args.args[0], "POST")
            self.assertEqual(self.objects.put_once.call_count, 1)
            self.assertTrue(self.objects.put_once.call_args.args[0].endswith("/intent.json"))

    def test_readback_requires_exact_receipt_and_independent_reader(self):
        resource = {"id": "11111111-1111-1111-1111-111111111111", "name": self.name,
                    "createdAt": "2026-11-18T00:00:00Z"}
        self.assertEqual(fixture.identity({"uuid": resource["id"], "name": self.name,
                                          "created_at": resource["createdAt"]}, self.name), resource)
        with self.assertRaises(ContractError):
            fixture.identity({"uuid": resource["id"], "name": "wrong", "created_at": resource["createdAt"]}, self.name)


if __name__ == "__main__":
    unittest.main()

"""Hosted-only source/controls lineage guards; no network or application execution."""

from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_recovery_cli as cli


SOURCE = "a" * 40
CONTROL = "b" * 40


class RecoverySourceLineageTests(unittest.TestCase):
    def test_unsupported_action_fails_before_private_configuration_reads(self):
        with patch.object(cli, "entry_configuration") as configure, self.assertRaises(cli.recovery.RecoveryError):
            cli.main({"GITHUB_WORKFLOW_REF": cli.WORKFLOW, "RECOVERY_ACTION": "unexpected"})
        configure.assert_not_called()

    def rehearsal_env(self):
        return {"RECOVERY_REHEARSAL_REGISTRATION_SHA256": "c" * 64, "SUBS_BOT_REHEARSAL_REGISTRATION_SHA256": "c" * 64,
                "SUBS_BOT_CONTROL_ENVIRONMENT": "subs-bot-isolation", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_REF": cli.artifact.MAIN_REF, "GITHUB_REPOSITORY": cli.artifact.REPOSITORY,
                "GITHUB_SHA": CONTROL, "SUBS_BOT_CF_DATA_TOKEN": "synthetic-data",
                "SUBS_BOT_CF_WORKER_TOKEN": "synthetic-reader"}

    def test_registered_rehearsal_reuses_exact_registration_and_private_configuration(self):
        resources = {key: "synthetic-only" for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}
        target = SimpleNamespace(environment="rehearsal", data={"workerName": "subs-bot-cf-control-drill-01", **resources},
                                 configuration_digest="d" * 64)
        with patch("production_lifecycle_drill.Drill") as drill, patch.object(cli, "general_config") as validate, \
                patch.object(cli, "validate_target", return_value=target) as target_config:
            drill.return_value.registration.return_value = target
            drill.return_value.draft.data = {"workerName": "subs-bot-cf-control-drill-01"}
            drill.return_value.secrets = {"fixture": "synthetic-only"}
            self.assertEqual(cli.entry_configuration(self.rehearsal_env()), (target, {"fixture": "synthetic-only"}, True))
            injected = drill.call_args.args[0]
            self.assertEqual(injected["DRILL_REGISTRATION_SHA256"], "c" * 64)
            self.assertEqual(injected["GITHUB_SHA"], CONTROL)
            self.assertEqual(injected["SUBS_BOT_CF_DEPLOY_TOKEN"], "synthetic-reader")
            drill.return_value.registration.assert_called_once_with()
            validate.assert_called_once_with(target, CONTROL, {"fixture": "synthetic-only"})
            target_config.assert_called_once_with(target.data)

    def test_changed_rehearsal_configuration_cannot_be_adopted_by_registration(self):
        resources = {key: "synthetic-only" for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}
        target = SimpleNamespace(environment="rehearsal", data={"workerName": "subs-bot-cf-control-drill-01", **resources},
                                 configuration_digest="d" * 64)
        with patch("production_lifecycle_drill.Drill") as drill, patch.object(cli, "general_config") as validate, \
                patch.object(cli, "validate_target", return_value=SimpleNamespace(configuration_digest="e" * 64)), \
                self.assertRaises(cli.recovery.RecoveryError):
            drill.return_value.registration.return_value = target
            drill.return_value.draft.data = {"workerName": "subs-bot-cf-control-drill-01"}
            cli.entry_configuration(self.rehearsal_env())
        validate.assert_not_called()

    def test_registered_rehearsal_rejects_production_ambiguity_and_unhosted_access_before_read(self):
        for change in ({"SUBS_BOT_CONTROL_ENVIRONMENT": "subs-bot-production"},
                       {"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_REF": "refs/heads/other"},
                       {"RECOVERY_REHEARSAL_REGISTRATION_SHA256": "invalid"},
                       {"SUBS_BOT_REHEARSAL_REGISTRATION_SHA256": "d" * 64},
                       {"SUBS_BOT_TARGET_JSON": "{}"}, {"SUBS_BOT_CONTROL_SECRETS": "{}"},
                       {"SUBS_BOT_APPROVAL_JSON": "{}"}):
            with self.subTest(change=change), patch("production_lifecycle_drill.Drill") as drill, self.assertRaises(cli.recovery.RecoveryError):
                cli.entry_configuration({**self.rehearsal_env(), **change})
            drill.assert_not_called()

    def test_registered_rehearsal_cannot_adopt_another_target(self):
        for target in (SimpleNamespace(environment="production", data={"workerName": "subs-bot-cf-prod-01"}),
                       SimpleNamespace(environment="rehearsal", data={"workerName": "another-worker"})):
            with self.subTest(target=target), patch("production_lifecycle_drill.Drill") as drill, self.assertRaises(cli.recovery.RecoveryError):
                drill.return_value.registration.return_value = target
                cli.entry_configuration(self.rehearsal_env())

    def test_same_exact_control_revision_needs_no_history_lookup(self):
        with patch.object(cli.artifact, "_get_json") as get:
            cli.require_reviewed_ancestor(SOURCE, SOURCE, "synthetic-read-token")
        get.assert_not_called()

    def test_older_source_requires_both_exact_base_and_merge_base(self):
        allowed = {"status": "ahead", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": SOURCE}}
        with patch.object(cli.artifact, "_get_json", return_value=allowed) as get:
            cli.require_reviewed_ancestor(SOURCE, CONTROL, "synthetic-read-token")
        get.assert_called_once_with("/compare/" + SOURCE + "..." + CONTROL + "?per_page=1&page=2", "synthetic-read-token")
        for wrong in ({**allowed, "status": "diverged"},
                      {**allowed, "base_commit": {"sha": CONTROL}},
                      {**allowed, "merge_base_commit": {"sha": CONTROL}}):
            with self.subTest(wrong=wrong), patch.object(cli.artifact, "_get_json", return_value=wrong), self.assertRaises(cli.recovery.RecoveryError):
                cli.require_reviewed_ancestor(SOURCE, CONTROL, "synthetic-read-token")

    def test_private_archive_never_consults_expired_actions_or_online_source_history(self):
        proof = {"revision": SOURCE}
        document = cli.recovery.canonical({"version": 2, "sourcePin": {"revision": SOURCE}})
        checkpoint = "c" * 32
        class PrivateAPI:
            names = {"backup": "subs-bot-private-checkpoint"}
            def object_or_none(self, bucket, key):
                self.location = bucket, key
                return document, None
        api = PrivateAPI()
        with patch.object(cli.artifact, "_get_json") as github, patch.object(cli.recovery, "load_code_archive", return_value=(b"original-ci-zip", proof)):
            self.assertEqual(cli.private_archive(api, checkpoint, cli.recovery.digest(document)), (b"original-ci-zip", proof))
        github.assert_not_called()
        self.assertEqual(api.location, (api.names["backup"], "production/checkpoints/" + checkpoint + "/manifest.json"))


if __name__ == "__main__":
    unittest.main()

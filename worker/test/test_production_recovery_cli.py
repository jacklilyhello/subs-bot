"""Hosted-only source/controls lineage guards; no network or application execution."""

from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_recovery_cli as cli


SOURCE = "a" * 40
CONTROL = "b" * 40


class RecoverySourceLineageTests(unittest.TestCase):
    def test_same_exact_control_revision_needs_no_history_lookup(self):
        with patch.object(cli.artifact, "_get_json") as get:
            cli.require_reviewed_ancestor(SOURCE, SOURCE, "synthetic-read-token")
        get.assert_not_called()

    def test_older_source_requires_both_exact_base_and_merge_base(self):
        allowed = {"status": "ahead", "base_commit": {"sha": SOURCE}, "merge_base_commit": {"sha": SOURCE}}
        with patch.object(cli.artifact, "_get_json", return_value=allowed):
            cli.require_reviewed_ancestor(SOURCE, CONTROL, "synthetic-read-token")
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

"""Hosted-only one-shot isolated digest journal refusal tests."""

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_digest_journal as journal
from test_production_provider import config


class DigestJournalTests(unittest.TestCase):
    def test_workflow_statically_disables_all_digest_and_journal_writes(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-digest-rehearsal.yml").read_text()
        intent = workflow.split("\n  intent_write:\n", 1)[1].split("\n  intent_readback:\n", 1)[0]
        self.assertIn("if: ${{ false }}", intent)
        self.assertIn("needs: [source, preflight, intent_readback]", workflow)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("path: ${{ runner.temp }}/provider-source-transfer.age", workflow)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", workflow.split("\n  publish:\n", 1)[0])
        publish = workflow.split("\n  publish:\n", 1)[1].split("\n  verify:\n", 1)[0]
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", publish)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", publish)

    def test_unknown_prior_intent_blocks_before_any_new_write(self):
        reader = Mock()
        with patch.object(journal.durable, "list_private_keys", return_value=[journal.BASE + "100/1/source-intent.json"]), \
                patch.object(journal, "ledger", return_value={}), patch.object(journal, "controllers", return_value=["b" * 40]), \
                self.assertRaises(control.ProviderError):
            journal.inventory(reader)
        reader.put.assert_not_called()

    def test_existing_digest_does_not_count_as_write_rehearsal(self):
        target = config(active=True)
        state = {"dependencySha256": "1" * 64, "manifestSha256": target["build"]["ociManifestSha256"]}
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40}, clear=True), \
                patch.object(journal.transfer, "context"), patch.object(journal.transfer, "target", return_value=target), \
                patch.object(journal.transfer, "refs", return_value=[{"fixture": "source"}]), patch.object(journal.transfer, "receive"), \
                patch.object(journal.digest, "observe", return_value=state), patch.object(journal, "output") as output, \
                self.assertRaises(control.ProviderError):
            journal.preflight()
        output.assert_not_called()

    def test_missing_independent_intent_readback_prevents_source_decode_and_copy(self):
        target = config(active=True)
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40}
        with patch.dict(os.environ, env, clear=True), patch.object(journal.transfer, "context"), \
                patch.object(journal, "parse_intent", return_value=(target, [{"fixture": "source"}], {})), \
                patch.object(journal, "workflow_job", side_effect=["1", control.ProviderError("missing readback")]), \
                patch.object(journal.transfer, "receive") as receive, patch.object(journal.digest, "publish_once") as publish, \
                self.assertRaises(control.ProviderError):
            journal.publish()
        receive.assert_not_called()
        publish.assert_not_called()

    def test_malformed_prestate_cannot_create_an_intent(self):
        target = config(active=True)
        import json
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40,
               "SUBS_BOT_PROVIDER_DIGEST_PRESTATE_JSON": json.dumps({"dependencySha256": "bad", "manifestSha256": None})}
        with patch.dict(os.environ, env, clear=True), patch.object(journal.transfer, "target", return_value=target), \
                patch.object(journal.transfer, "refs", return_value=[{"fixture": "source"}]), self.assertRaises(control.ProviderError):
            journal.parse_intent()


if __name__ == "__main__":
    unittest.main()

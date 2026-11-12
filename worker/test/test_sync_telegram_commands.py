import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from cloudflare_isolation import CloudflareError
from sync_telegram_commands import command_features, main


class TelegramCommandPreparationTests(unittest.TestCase):
    def test_rejects_untrusted_or_ambiguous_feature_flags(self):
        valid = dict(inlineSearch=True, providerUrlImport=False, providerBatch=False, apiStatus=True)
        for flags in (None, [], {**valid, "token": "synthetic"}, {**valid, "apiStatus": 1}, {"inlineSearch": True}):
            with self.assertRaises(CloudflareError):
                command_features([], flags)

    def test_paused_features_keep_only_implemented_management_status(self):
        names = ["0018_telegram_subscription_reads.sql", "0019_telegram_short_links.sql", "0020_telegram_inline_sort.sql",
                 "0024_telegram_bulk_trash.sql", "0027_telegram_github_search.sql", "0032_telegram_provider_batch_controls.sql"]
        flags = dict(inlineSearch=False, providerUrlImport=False, providerBatch=False, apiStatus=False)
        features = command_features([{"name": name} for name in names], flags)
        self.assertTrue(all(features[key] for key in ("subscriptionRead", "short", "inlineSort", "bulkTrash", "github", "batchStatus")))
        self.assertTrue(all(not features[key] for key in ("inline", "inlineTemp", "batchRefresh", "apiStatus", "providerImport", "displayTimezone")))
        self.assertEqual(features["authorizationScope"], "fixed")

    def test_never_runs_outside_exact_protected_hosted_workflow(self):
        for env in ({}, {"GITHUB_REPOSITORY": "other/repo"}, {"GITHUB_EVENT_NAME": "pull_request"}):
            with self.assertRaises(CloudflareError):
                main(env)


if __name__ == "__main__":
    unittest.main()

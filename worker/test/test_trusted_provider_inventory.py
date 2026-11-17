"""Hosted tests for the fixed, read-only Provider journal inventory."""
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_provider_inventory as inventory


class TrustedInventoryTests(unittest.TestCase):
    def env(self):
        github = inventory.provider.github
        return {"GITHUB_REPOSITORY": github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(github.REPOSITORY_ID),
                "GITHUB_REF": github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_WORKFLOW_REF": f"{github.REPOSITORY}/{inventory.WORKFLOW}@{github.MAIN_REF}",
                "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40, "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_RUN_ID": "101", "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": "{}"}

    def test_inventory_requires_all_three_complete_lists_and_no_write_credential(self):
        objects = Mock(write_credential=None)
        objects.list.side_effect = [[], ["fixture"], []]
        reader = Mock(objects=objects, base="/fixture")
        with patch.dict(os.environ, self.env(), clear=True), \
                patch.object(inventory.provider.github, "require_current_main"), \
                patch.object(inventory.archive, "PrivateProofStore", return_value=reader), \
                patch.object(inventory, "verify_lifecycle"):
            result = inventory.inspect()
            self.assertFalse(result["allEmpty"])
            self.assertEqual([result["prefixCounts"][name] for name in inventory.PREFIXES], [0, 1, 0])
            self.assertEqual(objects.list.call_count, 3)
            objects.write_credential = {"unexpected": True}
            with self.assertRaises(inventory.provider.ProviderError):
                inventory.inspect()


if __name__ == "__main__":
    unittest.main()

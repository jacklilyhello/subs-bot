"""Synthetic checks for the private target-scoped test webhook anchor."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_webhook_anchor as lock
from production_target import ContractError


class WebhookAnchorStoreTests(unittest.TestCase):
    def test_anchor_namespace_is_exact_and_escape_is_rejected(self):
        original = Mock()
        original.objects = Mock()
        original.objects.get.return_value = (b"private", '"synthetic"')
        store = lock.WebhookStore(original, "a" * 64)
        key = "maintenance/production-control/registrations/daily-backup-anchor-" + "a" * 64 + ".json"
        self.assertEqual(store.get(key), b"private")
        original.objects.get.assert_called_once_with(store.prefix + key, absent=False)
        with self.assertRaises(ContractError):
            store.get("maintenance/production-control/../../other-project")
        with self.assertRaises(ContractError):
            lock.WebhookStore(original, "invalid-target")

    def test_uncertain_conditional_anchor_write_does_not_retry(self):
        original = Mock()
        original.objects = Mock()
        original.objects.put_once.side_effect = OSError("lost response")
        store = lock.WebhookStore(original, "a" * 64)
        key = "maintenance/production-control/registrations/example.json"
        with self.assertRaises(OSError):
            store.put(key, b"private")
        original.objects.put_once.assert_called_once_with(store.prefix + key, b"private")

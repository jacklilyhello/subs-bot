"""Synthetic checks for the private target-scoped test webhook anchor."""
from pathlib import Path
from hashlib import sha256
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_webhook_anchor as lock
from production_target import ContractError, canonical


class MemoryObjects:
    def __init__(self):
        self.data = {}
        self.fail_cas = False

    def get(self, key, *, absent=False):
        raw = self.data.get(key)
        if raw is None and not absent:
            raise ContractError("missing")
        return raw, None if raw is None else '"' + sha256(raw).hexdigest()[:32] + '"'

    def list(self, prefix, *, maximum):
        keys = sorted(key for key in self.data if key.startswith(prefix))
        if len(keys) > maximum:
            raise ContractError("too many")
        return keys

    def put_once(self, key, body):
        if key in self.data:
            raise ContractError("occupied")
        self.data[key] = body

    def compare_and_put(self, key, expected_body, expected_etag, body):
        if self.get(key, absent=True) != (expected_body, expected_etag):
            raise ContractError("predecessor changed")
        if self.fail_cas:
            raise OSError("unknown result")
        self.data[key] = body


class WebhookAnchorStoreTests(unittest.TestCase):
    def test_wire_format_and_full_single_use_history(self):
        original = Mock()
        original.objects = MemoryObjects()
        target = "a" * 64
        adapter = lock.WebhookStore(original, target)
        expected_initial = canonical({"version": 1, "targetSha256": target, "generation": 1, "previousSha256": None,
            "state": "idle", "session": "1-1", "day": "1970/01/01", "controlRevision": "0" * 40})
        expected_genesis = canonical({"version": 1, "targetSha256": target,
                                     "initialAnchorSha256": sha256(expected_initial).hexdigest()})
        instance = lock.WebhookAnchor(adapter, target, sha256(expected_genesis).hexdigest())
        self.assertEqual(instance.initial_material(), (expected_initial, expected_genesis))
        instance.initialize()
        self.assertEqual(instance.acquire("123-1", "2026/11/17", "b" * 40)["state"], "active")
        with self.assertRaises(ContractError):
            instance.acquire("124-1", "2026/11/17", "b" * 40)
        self.assertEqual(instance.release("123-1")["state"], "idle")
        with self.assertRaises(ContractError):
            instance.acquire("123-1", "2026/11/17", "b" * 40)
        instance.acquire("124-1", "2026/11/17", "b" * 40)
        instance.release("124-1")
        with self.assertRaises(ContractError):
            instance.acquire("123-1", "2026/11/17", "b" * 40)

    def test_unknown_cas_and_fork_block_later_writes(self):
        original = Mock()
        original.objects = MemoryObjects()
        target = "a" * 64
        adapter = lock.WebhookStore(original, target)
        pin = lock.genesis_sha(original, target)
        instance = lock.WebhookAnchor(adapter, target, pin)
        instance.initialize()
        original.objects.fail_cas = True
        with self.assertRaises(OSError):
            instance.acquire("123-1", "2026/11/17", "b" * 40)
        original.objects.fail_cas = False
        with self.assertRaises(ContractError):
            instance.read()  # A future immutable generation must not be adopted.

    def test_fork_and_missing_history_are_rejected(self):
        original = Mock()
        original.objects = MemoryObjects()
        target = "a" * 64
        instance = lock.WebhookAnchor(lock.WebhookStore(original, target), target, lock.genesis_sha(original, target))
        instance.initialize()
        instance.acquire("123-1", "2026/11/17", "b" * 40)
        initial = instance.history_key(1, instance.initial_material()[0])
        mapped = instance.store._key(initial)
        saved = original.objects.data.pop(mapped)
        with self.assertRaises(ContractError):
            instance.read()
        original.objects.data[mapped] = saved
        fork = instance.store._key(instance.history_digest_key(1, "c" * 64))
        original.objects.data[fork] = b"fork"
        with self.assertRaises(ContractError):
            instance.read()

    def test_existing_nonadjacent_acquisition_replay_is_rejected(self):
        original = Mock()
        original.objects = MemoryObjects()
        target = "a" * 64
        instance = lock.WebhookAnchor(lock.WebhookStore(original, target), target, lock.genesis_sha(original, target))
        instance.initialize()
        for session in ("123-1", "124-1"):
            instance.acquire(session, "2026/11/17", "b" * 40)
            instance.release(session)
        prior, raw, _ = instance.read()
        replay = canonical({**prior, "generation": prior["generation"] + 1, "previousSha256": sha256(raw).hexdigest(),
                            "state": "active", "session": "123-1"})
        original.objects.data[instance.store._key(instance.history_key(prior["generation"] + 1, replay))] = replay
        original.objects.data[instance.store._key(instance.key)] = replay
        with self.assertRaises(ContractError):
            instance.read()

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

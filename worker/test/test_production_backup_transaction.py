"""Synthetic immutable journal and interrupted-write behavior."""
from pathlib import Path
from hashlib import sha256
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_transaction as transaction
from production_target import ContractError


class Store:
    def __init__(self):
        self.objects = {}

    def list(self, prefix, maximum):
        result = sorted(key for key in self.objects if key.startswith(prefix))
        if len(result) >= maximum:
            raise ContractError("overflow")
        return result

    def get(self, key, *, absent=False):
        if absent:
            return self.objects.get(key)
        return self.objects[key]

    def put(self, key, body):
        if key in self.objects and self.objects[key] != body:
            raise ContractError("conflict")
        self.objects[key] = body

    def get_with_etag(self, key):
        value = self.objects.get(key)
        return value, None if value is None else '"' + __import__("hashlib").md5(value).hexdigest() + '"'

    def compare_and_put(self, key, expected, etag, body):
        if self.get_with_etag(key) != (expected, etag):
            raise ContractError("stale")
        self.objects[key] = body

    def list_backup_anchor_history(self, target):
        prefix = "maintenance/production-control/evidence/daily-backup-anchor/" + target + "/"
        return sorted(key for key in self.objects if key.startswith(prefix))

    def list_backup_journals(self):
        return sorted(key for key in self.objects if key.startswith("maintenance/production-control/evidence/daily-backup/"))

    def list_backup_session(self, prefix):
        return sorted(key for key in self.objects if key.startswith(prefix))


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.store = Store()
        self.journal = transaction.Transaction(self.store, "123-1", "2026/11/17", "a" * 64, "b" * 40)

    def test_pending_write_is_not_treated_as_completed(self):
        self.journal.append("started", {}, 100)
        self.journal.append("preflight", {"capacity": {}}, 101)
        self.journal.append("pause-intent", {"stateSha256": "c" * 64}, 102)
        self.assertEqual(transaction.interruption(self.journal.load()), "reconciliation-required")
        with self.assertRaises(ContractError):
            self.journal.append("pause-intent", {}, 103)

    def test_missing_generation_and_altered_record_fail_closed(self):
        self.journal.append("started", {}, 100)
        self.journal.append("preflight", {"capacity": {}}, 101)
        first = self.journal.prefix + "0001.json"
        self.store.objects[first] = b'{}'
        with self.assertRaises(ContractError):
            self.journal.load()
        del self.store.objects[first]
        with self.assertRaises(ContractError):
            self.journal.load()

    def test_verified_event_requires_both_pins_and_in_order(self):
        self.journal.append("started", {}, 100)
        with self.assertRaises(ContractError):
            self.journal.append("verified", {"checkpointId": "a" * 32, "manifestSha256": "b" * 64}, 101)

    def test_poll_requires_a_recorded_intent_and_never_starts_a_second_capture(self):
        stages = [("started", {}), ("preflight", {"capacity": {}}), ("pause-intent", {}), ("paused", {}),
                  ("freeze-intent", {}), ("frozen", {}), ("frozen-data", {}), ("capture-intent", {})]
        for timestamp, (stage, details) in enumerate(stages, 100):
            self.journal.append(stage, details, timestamp)
        with self.assertRaises(ContractError):
            self.journal.append("capture-intent", {}, 110)
        self.journal.append("poll-intent", {}, 110)
        self.assertEqual(transaction.interruption(self.journal.load()), "reconciliation-required")
        self.journal.append("capture-intent", {}, 111)

    def test_failed_frozen_checkpoint_requires_confirmed_read_only_failure(self):
        for uncertain in (False, True):
            store = Store()
            journal = transaction.Transaction(store, "123-1", "2026/11/17", "a" * 64, "b" * 40)
            stages = [("started", {}), ("preflight", {"capacity": {}}), ("pause-intent", {}), ("paused", {}),
                      ("freeze-intent", {}), ("frozen", {}), ("failed", {"uncertain": uncertain})]
            for timestamp, (stage, details) in enumerate(stages, 100):
                journal.append(stage, details, timestamp)
            if uncertain:
                with self.assertRaises(ContractError):
                    journal.append("resume-intent", {}, 110)
            else:
                journal.append("resume-intent", {}, 110)
                self.assertEqual(journal.load()[-1]["stage"], "resume-intent")

    def test_anchor_blocks_new_sessions_until_exact_release(self):
        anchor = self.anchor()
        anchor.initialize()
        anchor.acquire("123-1", "2026/11/17", "b" * 40)
        with self.assertRaises(ContractError):
            anchor.acquire("124-1", "2026/11/17", "b" * 40)
        with self.assertRaises(ContractError):
            anchor.release("124-1")
        anchor.release("123-1")
        anchor.acquire("124-1", "2026/11/17", "b" * 40)
        self.assertEqual(anchor.read()[0]["session"], "124-1")

    def test_missing_pointer_or_broken_history_never_looks_like_genesis(self):
        anchor = self.anchor()
        anchor.initialize()
        anchor.acquire("123-1", "2026/11/17", "b" * 40)
        pointer = self.store.objects.pop(anchor.key)
        with self.assertRaises(ContractError):
            anchor.acquire("124-1", "2026/11/17", "b" * 40)
        self.store.objects[anchor.key] = pointer
        history = self.store.list_backup_anchor_history("a" * 64)
        self.store.objects[history[0]] = b'{}'
        with self.assertRaises(ContractError):
            anchor.read()

    def test_same_generation_fork_blocks_all_future_anchor_operations(self):
        anchor = self.anchor()
        anchor.initialize()
        anchor.acquire("123-1", "2026/11/17", "b" * 40)
        current, raw, _etag = anchor.read()
        competing = transaction.canonical({**current, "session": "124-1"})
        self.store.put(anchor.history_key(current["generation"], competing), competing)
        with self.assertRaises(ContractError):
            anchor.read()
        with self.assertRaises(ContractError):
            anchor.release("123-1")

    def test_approved_reconciliation_needs_terminal_journal_and_exact_plan(self):
        anchor = self.anchor()
        anchor.initialize()
        anchor.acquire("123-1", "2026/11/17", "b" * 40)
        prior, raw, _etag = anchor.read()
        candidate = {**prior, "generation": prior["generation"] + 1,
                     "previousSha256": sha256(raw).hexdigest(), "state": "idle"}
        body = transaction.canonical(candidate)
        candidate_sha = sha256(body).hexdigest()
        self.store.put(anchor.history_key(candidate["generation"], body), body)
        with self.assertRaises(ContractError):
            anchor.read()
        with self.assertRaises(ContractError):
            anchor.plan_reconciliation(candidate_sha)
        self.journal.append("started", {}, 100)
        self.journal.append("preflight", {"capacity": {}}, 101)
        self.journal.append("failed", {}, 102)
        plan, _raw, _etag, _body = anchor.plan_reconciliation(candidate_sha)
        with self.assertRaises(ContractError):
            anchor.reconcile(candidate_sha, "0" * 64)
        anchor.reconcile(candidate_sha, sha256(transaction.canonical(plan)).hexdigest())
        self.assertEqual(anchor.read()[0]["state"], "idle")

    def test_partial_genesis_requires_independently_approved_new_plan(self):
        anchor = self.anchor()
        _initial, genesis = anchor.initial_material()
        self.store.put(anchor.genesis_key, genesis)
        with self.assertRaises(ContractError):
            anchor.read()
        plan, _initial, _etag = anchor.plan_initialization_reconciliation()
        with self.assertRaises(ContractError):
            anchor.reconcile_initialization("0" * 64)
        anchor.reconcile_initialization(sha256(transaction.canonical(plan)).hexdigest())
        self.assertEqual(anchor.read()[0]["state"], "idle")

    def test_unknown_pointer_write_is_inspected_not_reissued(self):
        anchor = self.anchor()
        anchor.initialize()
        write = self.store.compare_and_put
        def committed_but_unacknowledged(*args):
            write(*args)
            raise RuntimeError("synthetic transport loss")
        with patch.object(self.store, "compare_and_put", side_effect=committed_but_unacknowledged):
            with self.assertRaises(RuntimeError):
                anchor.acquire("123-1", "2026/11/17", "b" * 40)
        self.assertEqual(anchor.read()[0]["session"], "123-1")
        with self.assertRaises(ContractError):
            anchor.acquire("123-1", "2026/11/17", "b" * 40)

    def test_unknown_uncommitted_pointer_write_blocks_new_claims(self):
        anchor = self.anchor()
        anchor.initialize()
        with patch.object(self.store, "compare_and_put", side_effect=RuntimeError("synthetic transport loss")):
            with self.assertRaises(RuntimeError):
                anchor.acquire("123-1", "2026/11/17", "b" * 40)
        with self.assertRaises(ContractError):
            anchor.acquire("124-1", "2026/11/17", "b" * 40)

    def anchor(self):
        target = "a" * 64
        seed = transaction.Anchor(self.store, target, "0" * 64)
        return transaction.Anchor(self.store, target, sha256(seed.initial_material()[1]).hexdigest())


if __name__ == "__main__":
    unittest.main()

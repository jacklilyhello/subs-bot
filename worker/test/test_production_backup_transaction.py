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

    def put_exclusive(self, key, body):
        if key in self.objects:
            raise ContractError("exclusive conflict")
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

    def test_begin_intent_is_unique_and_recovery_claim_cannot_be_replayed(self):
        original = {"version": 1, "targetSha256": "a" * 64, "session": "123-1", "day": "2026/11/17",
            "controlRevision": "b" * 40, "dispatcherRevision": "b" * 40, "dispatcherWorkflow": "worker-production-backup.yml",
            "writerRunId": "456", "writerAttempt": "1", "anchorPredecessorSha256": "c" * 64,
            "stateSha256": "d" * 64, "sourceRevision": "f" * 40, "approvalSha256": "e" * 64,
            "timestamp": 100, "startedDetails": {}}
        digest = transaction.write_begin(self.store, original)
        self.assertEqual(transaction.read_begin(self.store, "a" * 64, "123-1"), (original, digest))
        with self.assertRaises(ContractError):
            transaction.write_begin(self.store, original)
        transaction.claim_begin_reconciliation(self.store, "a" * 64, "123-1", {"writerRunId": "789"})
        with self.assertRaises(ContractError):
            transaction.claim_begin_reconciliation(self.store, "a" * 64, "123-1", {"writerRunId": "789"})
        with self.assertRaises(ContractError):
            transaction.read_begin(self.store, "a" * 64, "124-1")

    def test_invalid_begin_intent_does_not_become_recovery_evidence(self):
        key = transaction.begin_key("a" * 64, "123-1")
        self.store.objects[key] = b'{}'
        with self.assertRaises(ContractError):
            transaction.read_begin(self.store, "a" * 64, "123-1")

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

    def test_unconfirmed_capture_cannot_use_generic_terminal_append(self):
        for timestamp, (stage, details) in enumerate((("started", {}), ("preflight", {"capacity": {}}),
                ("frozen", {}), ("frozen-data", {}), ("capture-intent", {"checkpointId": "a" * 32})), 100):
            self.journal.append(stage, details, timestamp)
        with self.assertRaises(ContractError):
            self.journal.append("preserved-frozen", {"control": {}}, 110)
        self.journal.append("failed", {"uncertain": True}, 111)
        with self.assertRaises(ContractError):
            self.journal.append("preserved-frozen", {"control": {}}, 112)
        self.assertEqual(self.journal.load()[-1]["stage"], "failed")

    def test_stopped_export_requires_fresh_full_source_proof(self):
        import production_backup_capacity as capacity
        import production_control
        import production_recovery as recovery
        checkpoint = "a" * 32
        initial = {"checkpointId": checkpoint, "control": {"workers": "frozen"},
                   "release": {"revision": "b" * 40}, "configurationSha256": "c" * 64}
        fingerprint = {"dataSha256": "d" * 64, "rowCount": 1, "objectClosureSha256": "e" * 64}
        for timestamp, (stage, details) in enumerate((("started", initial), ("preflight", {"capacity": {}}),
                ("frozen", {}), ("frozen-data", fingerprint), ("capture-intent", {"checkpointId": checkpoint})), 100):
            self.journal.append(stage, details, timestamp)
        class FakeAPI:
            cohort = checkpoint
        class FakeSource:
            api, scope_sha256 = FakeAPI(), "a" * 64
        class FakeJournal:
            api, raw = FakeSource.api, b"journal"
            owner, guard = "123-1", None
            active = True
            def __init__(self, api=None, owner=None, guard=None):
                pass
            def load(self):
                return {"export": {"state": "complete"}} if self.active else None
        class FakeController:
            def inspect(self):
                return {"control": initial["control"], "release": initial["release"],
                        "configurationSha256": initial["configurationSha256"], "work": {"pending": 0}, "terminal": {}}
        details = {"control": initial["control"], "backupVerified": False, "confirmedByWatchdog": True}
        with patch.object(recovery, "RecoverySource", FakeSource), patch.object(recovery, "RecoveryJournal", FakeJournal), \
                patch.object(production_control, "Controller", FakeController), \
                patch.object(capacity, "frozen_fingerprint", return_value=fingerprint):
            FakeJournal.active = False
            with self.assertRaises(ContractError):
                self.journal.append_stopped_export(details, 109, source_journal=FakeJournal(),
                                                   source=FakeSource(), controller=FakeController())
            self.assertEqual(self.journal.load()[-1]["stage"], "capture-intent")
            FakeJournal.active = True
            self.journal.append_stopped_export(details, 110, source_journal=FakeJournal(),
                                               source=FakeSource(), controller=FakeController())
        self.assertEqual(self.journal.load()[-1]["stage"], "preserved-frozen")

    def test_no_export_requires_exact_private_release_intent_and_manifest(self):
        store = Store()
        journal = transaction.Transaction(store, "44164739374-1", "2026/11/17", "a" * 64,
                    "7aa685990859cffb30d47c5a6e593d969f1d0452")
        for timestamp, (stage, details) in enumerate((("started", {}), ("preflight", {"capacity": {}}),
                ("frozen", {}), ("frozen-data", {}),
                ("capture-intent", {"checkpointId": "1bbadaa9755d1733ddd80fe12192420a"})), 100):
            journal.append(stage, details, timestamp)
        prefix = "maintenance/production-control/evidence/no-export-resolution/" + "a" * 64 + "/44164739374-1/"
        manifest = {"kind": "no-export-original-evidence", "originalRunId": "44164739374", "originalAttempt": "1",
                    "planSha256": "b" * 64, "threatModel": "reviewed-writers-no-unapproved-deletion"}
        manifest_raw = transaction.canonical(manifest)
        evidence = sha256(manifest_raw).hexdigest()
        intent = {"kind": "no-export-release-intent", "targetSha256": "a" * 64, "originalRunId": "44164739374",
                  "originalAttempt": "1", "evidenceSha256": evidence, "planSha256": "b" * 64}
        intent_raw = transaction.canonical(intent)
        store.put(prefix + "evidence-manifest.json", manifest_raw)
        store.put(prefix + "evidence-intent.json", transaction.canonical({"version": 1, "kind": "no-export-evidence-intent",
                  "planSha256": "b" * 64, "manifestSha256": evidence}))
        store.put(prefix + "release-intent.json", intent_raw)
        details = {"control": {}, "backupVerified": False, "noExportEvidenceSha256": evidence,
                   "releaseIntentSha256": sha256(intent_raw).hexdigest(), "threatModel": manifest["threatModel"]}
        called = []
        journal.append_no_export(details, 110, guard=lambda: called.append(True))
        self.assertEqual(called, [True])
        self.assertEqual(journal.load()[-1]["stage"], "preserved-frozen")

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

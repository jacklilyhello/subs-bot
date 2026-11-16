"""Hosted checks for exact G0 journal resumption without recapture or creation."""

from copy import deepcopy
import json
from pathlib import Path
import sys
from unittest.mock import Mock
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_recovery as recovery
import production_recovery_drill as drill
import test_production_recovery as fixtures


class ResumeContractTests(unittest.TestCase):
    def test_explicit_paired_complete_pins_are_required(self):
        pins = {"version": 1, "checkpointId": fixtures.CHECKPOINT, "manifestSha256": "a" * 64, "journalSha256": "b" * 64}
        self.assertEqual(drill.resume_parameters(recovery.canonical(pins)), pins)
        self.assertIsNone(drill.resume_parameters(""))
        for changed in ({"version": True}, {"checkpointId": "../wrong"}, {"manifestSha256": ""},
                        {"journalSha256": ""}, {"extra": True}):
            with self.subTest(changed=changed), self.assertRaises(recovery.RecoveryError):
                drill.resume_parameters({**pins, **changed})

    def test_safe_failure_never_publishes_error_text_paths_or_other_projects(self):
        error = recovery.RecoveryError("synthetic-secret https://private.invalid/internal", uncertain=True, http_status=403)
        diagnostic = drill.safe_failure(error, "restore-objects", Mock(consumer_stage="service-environments"))
        self.assertEqual(diagnostic, {"action": "restore-objects", "uncertain": True, "httpStatus": 403,
                                      "consumerPhase": "service-environments"})
        self.assertNotIn("synthetic-secret", json.dumps(diagnostic))
        self.assertNotIn("https://", json.dumps(diagnostic))
        self.assertTrue(drill.safe_failure(OSError("private-detail"), "resume-g0", Mock(consumer_stage=None))["uncertain"])


class PreservedG0ResumeTests(unittest.TestCase):
    def setUp(self):
        fixtures.EngineTests.setUp(self)
        self.engine.create("database")
        self.engine.create("objects")
        self.journal.update(phase="captured", backup={"manifestSha256": "a" * 64}, importState=None)
        self.journal.release()
        self.journal = recovery.RecoveryJournal(self.api, "20/1")
        self.journal.load()
        self.engine = recovery.RecoveryEngine(self.api, self.source, self.journal, Path(self.temp.name))
        self.engine.observe = Mock(side_effect=lambda kind: recovery.native.resource_identity(kind, self.api.resources[kind], self.api.names[kind]))
        self.engine.verify_preservation = Mock()
        self.api.consumer_proof = Mock(return_value={"checked": 3, "consumers": 0, "inventorySha256": "c" * 64})
        self.pins = {"version": 1, "checkpointId": fixtures.CHECKPOINT,
            "manifestSha256": "a" * 64, "journalSha256": recovery.digest(self.journal.raw)}

    def test_exact_resumption_reads_ownership_and_preservation_then_claims_only_original_journal(self):
        generation = self.journal.generation
        before_creates = len([call for call in self.api.calls if call[0] == "POST"])
        report = drill.resume_baseline(self.engine, self.pins)
        self.assertEqual(report["previousJournalSha256"], self.pins["journalSha256"])
        self.assertFalse(report["captureRepeated"])
        self.assertFalse(report["resourcesCreated"])
        self.assertEqual(self.journal.generation, generation + 1)
        self.assertEqual(self.journal.value["lease"]["owner"], "20/1")
        self.assertEqual(self.journal.value["phase"], "captured")
        self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), before_creates)
        self.engine.verify_preservation.assert_called_once_with()
        self.api.consumer_proof.assert_called_once_with()
        self.source.verify.assert_called_with(capture=False)
        # The old latest pin cannot authorize a second claim after the chain advanced.
        with self.assertRaises(recovery.RecoveryError):
            drill.resume_baseline(self.engine, self.pins)
        self.assertEqual(self.journal.generation, generation + 1)

    def test_wrong_pins_unknown_resource_or_unsealed_state_never_claims_or_creates(self):
        original = deepcopy(self.journal.value)
        original_raw, generation = self.journal.raw, self.journal.generation
        cases = [({**self.pins, "journalSha256": "0" * 64}, None),
                 ({**self.pins, "manifestSha256": "0" * 64}, None),
                 (self.pins, {**original, "phase": "prepared"}),
                 (self.pins, {**original, "resources": {**original["resources"], "database": {"pin": None, "intent": None}}})]
        for pins, changed in cases:
            self.journal.value = deepcopy(changed or original)
            self.journal.raw = original_raw
            with self.subTest(changed=changed, pins=pins), self.assertRaises(recovery.RecoveryError):
                drill.resume_baseline(self.engine, pins)
            self.assertEqual(self.journal.generation, generation)
            self.api.consumer_proof.assert_not_called()

    def test_source_drift_target_replacement_or_consumer_blocks_before_claim(self):
        generation = self.journal.generation
        for failed in ("source", "resource", "consumer"):
            self.engine.verify_preservation = Mock()
            self.api.consumer_proof = Mock()
            self.engine.observe = Mock(side_effect=lambda kind: recovery.native.resource_identity(kind, self.api.resources[kind], self.api.names[kind]))
            self.journal.value["lease"] = {"owner": None, "until": 0}
            if failed == "source":
                self.engine.verify_preservation.side_effect = recovery.RecoveryError("Source differs from G0.")
            elif failed == "resource":
                self.engine.observe.return_value = None
                self.engine.observe.side_effect = None
            elif failed == "consumer":
                self.api.consumer_proof.side_effect = recovery.RecoveryError("Restore target has a consumer.")
            with self.subTest(failed=failed), self.assertRaises(recovery.RecoveryError):
                drill.resume_baseline(self.engine, self.pins)
            self.assertEqual(self.journal.generation, generation)

    def test_exact_latest_pin_does_not_take_over_another_runs_active_lease(self):
        occupied = deepcopy(self.journal.value)
        occupied["lease"] = {"owner": "other/1", "until": 9999999999}
        self.journal.save(occupied)
        pins = {**self.pins, "journalSha256": recovery.digest(self.journal.raw)}
        generation = self.journal.generation
        with self.assertRaisesRegex(recovery.RecoveryError, "leased by another run"):
            drill.resume_baseline(self.engine, pins)
        self.assertEqual(self.journal.generation, generation)
        self.assertEqual(self.journal.value["lease"], occupied["lease"])

    def test_resumption_preserves_unknown_import_and_never_restarts_init_or_ingest(self):
        self.engine.manifest = Mock(return_value=({"objects": []}, None))
        self.engine.verify_object_bytes = Mock()
        self.engine.verify_restore = Mock(side_effect=recovery.RecoveryError("Partial import still differs."))
        for state in ("init-started", "ingest-started", "unknown"):
            value = deepcopy(self.journal.value)
            value.update(phase="objects-restored", importState={"state": state})
            self.journal.save(value)
            pins = {**self.pins, "journalSha256": recovery.digest(self.journal.raw)}
            before = len([call for call in self.api.calls if call[0] == "POST"])
            drill.resume_baseline(self.engine, pins)
            self.assertEqual(self.journal.value["importState"], {"state": state})
            with self.subTest(state=state), self.assertRaisesRegex(recovery.RecoveryError, "never re-init"):
                self.engine.start_import()
            self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), before)

    def test_complete_or_verified_import_only_reverifies_data(self):
        self.engine.manifest = Mock(return_value=({"objects": []}, None))
        self.engine.verify_object_bytes = Mock()
        self.engine.verify_restore = Mock(return_value={"dataSha256": "d" * 64})
        for state in ("complete", "verified"):
            self.journal.claim()
            self.journal.update(importState={"state": state})
            before = len([call for call in self.api.calls if call[0] == "POST"])
            self.assertEqual(self.engine.start_import(), {"dataSha256": "d" * 64})
            self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), before)


if __name__ == "__main__":
    unittest.main()

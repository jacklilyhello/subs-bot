"""Synthetic tests for original webhook job evidence classification."""
from pathlib import Path
import sys
import unittest
from hashlib import sha256
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_webhook_log_archive as archive
from production_target import ContractError, canonical


class WebhookLogArchiveTests(unittest.TestCase):
    def log(self, *values):
        return b"\n".join(b"2026-11-18T00:00:00Z " + canonical(value) for value in values)

    def test_audit_pin_distinguishes_workflows_at_same_source_revision(self):
        revision = "a" * 40
        self.assertNotEqual(archive.audit_key(archive.HEAD, revision), archive.audit_key(archive.LIFECYCLE, revision))

    def test_inline_inspection_and_acknowledged_write_are_distinct(self):
        no_write = {"mode": "inspect", "writeAttempted": False, "writeAcknowledged": None}
        acknowledged = {"mode": "append", "writeAttempted": True, "writeAcknowledged": True, "inlineQuerySubscribed": True}
        self.assertEqual(archive.classify(self.log(no_write), archive.INLINE, "123"), "no-write-independently-confirmed")
        self.assertEqual(archive.classify(self.log(acknowledged), archive.INLINE, "123"), "response-independently-confirmed")
        with self.assertRaises(ContractError):
            archive.classify(self.log({**acknowledged, "writeAcknowledged": False}), archive.INLINE, "123")

    def test_legacy_failure_requires_configured_stage_and_exact_post_response_error(self):
        run_id = "43874513488"
        revision = "8e3af6d324661abf58c76437ef8f7a06c338ec67"
        report = {"runId": run_id, "stages": [{"stage": "webhook-configured"}]}
        error = {"status": "stopped", "uncertain": False,
                 "reason": "Original webhook secret was not independently confirmed; keep the private recovery snapshot."}
        self.assertEqual(archive.classify(self.log(report, error), archive.LIFECYCLE, run_id, main_sha=revision), "response-independently-confirmed")
        with self.assertRaises(ContractError):
            archive.classify(self.log({**report, "stages": []}, error), archive.LIFECYCLE, run_id, main_sha=revision)
        with self.assertRaises(ContractError):
            archive.classify(self.log(report, {**error, "uncertain": True}), archive.LIFECYCLE, run_id, main_sha=revision)
        with self.assertRaises(ContractError):
            archive.classify(self.log(report, error), archive.LIFECYCLE, run_id, main_sha="a" * 40)

    def test_legacy_missing_stage_and_cleanup_claim_do_not_prove_no_write(self):
        report = {"runId": "123", "stages": []}
        cleanup = {"runId": "123", "webhookRecovery": {"webhookWasNotChanged": True, "webhookRestored": True}}
        self.assertEqual(archive.classify(self.log(report, cleanup), archive.LIFECYCLE, "123"), "unresolved")

    def test_only_four_exact_reviewed_stopped_runs_have_pre_write_proof(self):
        for run_id, (revision, _action, stages, reason) in archive.REVIEWED_PRE_WEBHOOK.items():
            with self.subTest(run_id=run_id):
                report = {"runId": run_id, "status": "stopped", "stages": [{"stage": stage} for stage in stages]}
                error = {"status": "stopped", "reason": reason, "uncertain": False}
                cleanup = {"runId": run_id, "webhookRecovery": {"webhookWasNotChanged": True, "webhookRestored": True}}
                self.assertEqual(archive.classify(self.log(report, error, cleanup), archive.LIFECYCLE, run_id,
                                                  main_sha=revision), "no-write-independently-confirmed")
                self.assertEqual(archive.classify(self.log(report, {**error, "uncertain": True}, cleanup),
                                                  archive.LIFECYCLE, run_id, main_sha=revision), "unresolved")
                self.assertEqual(archive.classify(self.log({**report, "webhookRecovery": {}}, error, cleanup),
                                                  archive.LIFECYCLE, run_id, main_sha=revision), "unresolved")
                self.assertEqual(archive.classify(self.log(report, error, cleanup), archive.LIFECYCLE, run_id,
                                                  main_sha="a" * 40), "unresolved")

    def test_reviewed_head_requires_exact_candidate_and_explicit_no_webhook(self):
        result = {"runId": "123", "runAttempt": "1", "dispatcherMainRevision": "a" * 40,
                  "headRevision": "b" * 40, "environment": "rehearsal", "productionMutated": False, "webhookTouched": False}
        self.assertEqual(archive.classify(self.log(result), archive.HEAD, "123", main_sha="a" * 40,
                                         candidates=["b" * 40]), "no-write-independently-confirmed")
        with self.assertRaises(ContractError):
            archive.classify(self.log({**result, "webhookTouched": True}), archive.HEAD, "123", main_sha="a" * 40,
                             candidates=["b" * 40])

    def test_only_fixed_failed_backup_log_and_exact_validation_can_be_classified(self):
        run_id = "44164739374"
        fixed = archive.REVIEWED_FAILED_HEAD[run_id]
        spec = {"version": 1, "headSha": fixed["candidate"], "action": "backup", "fault": fixed["fault"]}
        raw = b"\n".join(b"HEAD_VALIDATION_JSON: " + canonical(spec) for _ in range(4))
        with patch.dict(archive.REVIEWED_FAILED_HEAD, {run_id: {**fixed, "logSha256": sha256(raw).hexdigest()}}):
            self.assertEqual(archive.classify(raw, archive.HEAD, run_id, main_sha=fixed["main"],
                                             candidates=[fixed["candidate"]]), "no-write-independently-confirmed")
            for altered, main, candidates in ((raw + b"x", fixed["main"], [fixed["candidate"]]),
                                               (raw, "a" * 40, [fixed["candidate"]]),
                                               (raw, fixed["main"], ["b" * 40])):
                with self.assertRaises(ContractError):
                    archive.classify(altered, archive.HEAD, run_id, main_sha=main, candidates=candidates)
        wrong = b"\n".join(b"HEAD_VALIDATION_JSON: " + canonical({**spec, "action": "open-backup"}) for _ in range(4))
        with patch.dict(archive.REVIEWED_FAILED_HEAD, {run_id: {**fixed, "logSha256": sha256(wrong).hexdigest()}}), \
                self.assertRaises(ContractError):
            archive.classify(wrong, archive.HEAD, run_id, main_sha=fixed["main"], candidates=[fixed["candidate"]])

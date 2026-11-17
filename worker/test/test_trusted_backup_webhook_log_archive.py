"""Synthetic tests for original webhook job evidence classification."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import trusted_backup_webhook_log_archive as archive
from production_target import ContractError, canonical


class WebhookLogArchiveTests(unittest.TestCase):
    def log(self, *values):
        return b"\n".join(b"2026-11-18T00:00:00Z " + canonical(value) for value in values)

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

    def test_reviewed_head_requires_exact_candidate_and_explicit_no_webhook(self):
        result = {"runId": "123", "runAttempt": "1", "dispatcherMainRevision": "a" * 40,
                  "headRevision": "b" * 40, "environment": "rehearsal", "productionMutated": False, "webhookTouched": False}
        self.assertEqual(archive.classify(self.log(result), archive.HEAD, "123", main_sha="a" * 40,
                                         candidates=["b" * 40]), "no-write-independently-confirmed")
        with self.assertRaises(ContractError):
            archive.classify(self.log({**result, "webhookTouched": True}), archive.HEAD, "123", main_sha="a" * 40,
                             candidates=["b" * 40])

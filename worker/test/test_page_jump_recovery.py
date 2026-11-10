"""Hosted source-proof and paused-gate regressions without live services."""

from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import cloudflare_isolation as cloudflare
import page_jump_recovery as recovery


STAGE = {
    "version": 1, "phase": "staged", "revision": "a" * 40, "bundleSha256": "b" * 64,
    "ciManifestSha256": "c" * 64, "ciRunId": "100", "ciRunAttempt": "1",
    "ciArtifactId": "200", "ciArchiveSha256": "d" * 64, "operationRunId": 300, "operationRunAttempt": 2,
    "checkpoint": {"activeSha256": "e" * 64, "gateSha256": "f" * 64, "priorEpoch": None},
    "epoch": 300, "reservedGateSha256": "1" * 64, "candidateSha256": "2" * 64,
}


def zip_document(value, name=recovery.EVIDENCE_NAME):
    target = BytesIO()
    with ZipFile(target, "w", ZIP_DEFLATED) as archive:
        archive.writestr(name, recovery._canonical(value))
    return target.getvalue()


class RecoveryProofTests(unittest.TestCase):
    def setUp(self):
        self.raw = zip_document(STAGE)
        self.source = {"runId": "300", "revision": STAGE["revision"], "runAttempt": "2",
                       "archiveSha256": sha256(self.raw).hexdigest()}

    def test_source_inputs_require_exact_phase_and_confirmation(self):
        pause = f"pause page jump for {cloudflare.WORKER_NAME}"
        self.assertEqual(recovery.recovery_inputs("pause", pause, json.dumps({"stage": self.source})), {"stage": self.source})
        for raw in ("{}", json.dumps({"stage": {**self.source, "runAttempt": 2}}),
                    json.dumps({"stage": self.source, "pause": self.source}),
                    '{"stage":{},"stage":' + json.dumps(self.source) + "}"):
            with self.subTest(raw=raw), self.assertRaisesRegex(cloudflare.CloudflareError, "recovery inputs"):
                recovery.recovery_inputs("pause", pause, raw)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "recovery inputs"):
            recovery.recovery_inputs("drain", pause, json.dumps({"stage": self.source}))

    def test_exact_successful_historical_attempt_is_reverified_after_download(self):
        chosen = ("2", "400", self.source["archiveSha256"])
        metadata = {"id": 19, "path": recovery.WORKFLOW, "state": "active"}
        with patch.object(recovery, "_github_token", return_value="synthetic-read-token"), patch.object(
                recovery, "_get_json", return_value=metadata), patch.object(
                recovery, "select_main_artifact", return_value=chosen) as select, patch.object(
                recovery, "_download", return_value=self.raw) as download:
            self.assertEqual(recovery.read_source(self.source, "stage"), STAGE)
            self.assertEqual(select.call_count, 2)
            self.assertEqual(select.call_args.args[:2], ("300", STAGE["revision"]))
            self.assertEqual(select.call_args.kwargs["run_attempt"], "2")
            self.assertEqual(select.call_args.kwargs["events"], ("workflow_dispatch",))
            self.assertEqual(select.call_args.kwargs["artifact_prefix"], "subs-bot-page-jump-stage-300")
            self.assertFalse(select.call_args.kwargs["revision_in_name"])
            download.assert_called_once_with("400", "synthetic-read-token")
            select.side_effect = [chosen, (chosen[0], "401", chosen[2])]
            with self.assertRaisesRegex(cloudflare.CloudflareError, "exact protected"):
                recovery.read_source(self.source, "stage")

    def test_closed_archive_and_phase_refuse_substitution(self):
        for raw in (zip_document(STAGE, "../" + recovery.EVIDENCE_NAME), b"broken archive"):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "exact protected"):
                recovery._unpack(raw)
        for change in ({"epoch": 301}, {"phase": "planned"}, {"operationRunAttempt": 1}, {"secret": "synthetic"}):
            with self.subTest(change=change), self.assertRaisesRegex(cloudflare.CloudflareError, "exact protected"):
                recovery._validate_source({**STAGE, **change}, self.source, "stage")

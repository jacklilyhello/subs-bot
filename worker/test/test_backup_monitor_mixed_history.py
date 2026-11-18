"""Synthetic GH pagination across multiple busy independent workflows."""
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_cli as backup
import production_backup_monitor as monitor


class MixedHistoryTests(unittest.TestCase):
    def test_more_than_1344_repository_runs_are_scoped_without_hiding_backup_failure(self):
        revision, now = "a" * 40, 1800000000
        stamp = datetime.fromtimestamp(now - 1, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        repository = {"id": backup.artifact.REPOSITORY_ID}
        base = {"run_attempt": 1, "head_branch": "main", "head_sha": revision, "event": "schedule",
                "repository": repository, "head_repository": repository, "updated_at": stamp, "created_at": stamp,
                "status": "completed", "conclusion": "success"}
        production = [{**base, "id": index + 1, "workflow_id": 123,
                       "display_title": "Production backup monitor at " + revision} for index in range(672)]
        production.append({**base, "id": 673, "workflow_id": 123, "event": "workflow_dispatch",
                           "display_title": "Production backup begin at " + revision, "conclusion": "failure"})
        lifecycle = [{**base, "id": 10000 + index, "workflow_id": 321, "path": monitor.WORKFLOW,
                      "display_title": "Production lifecycle rehearsal monitor at " + revision} for index in range(672)]
        lifecycle.append({**base, "id": 10673, "workflow_id": 321, "path": monitor.WORKFLOW,
                          "display_title": "Production lifecycle rehearsal daily-backup at " + revision})
        self.assertGreaterEqual(len(production) + len(lifecycle), 1344)
        observed = []

        def get(path, _token):
            observed.append(path)
            if path == "/actions/workflows/worker-production-backup.yml":
                return {"id": 123, "path": ".github/workflows/worker-production-backup.yml"}
            if path == "/actions/workflows/worker-production-lifecycle-rehearsal.yml":
                return {"id": 321, "path": monitor.WORKFLOW}
            parsed = urlsplit(path)
            self.assertNotEqual(parsed.path, "/actions/runs")
            if parsed.path == "/actions/workflows/worker-production-backup.yml/runs":
                rows = production
            elif parsed.path == "/actions/workflows/321/runs":
                rows = lifecycle
            else:
                self.fail("An unexpected workflow inventory was requested")
            query = parse_qs(parsed.query)
            self.assertEqual(query["per_page"], ["50"])
            page = int(query["page"][0])
            return {"total_count": len(rows), "workflow_runs": rows[(page - 1) * 50:page * 50]}

        with patch.object(backup.artifact, "_github_token", return_value="synthetic"), \
             patch.object(backup.artifact, "_get_json", side_effect=get):
            outcome = backup.monitor_workflow_runs(json.dumps({"version": 1, "revisions": [revision]}), now, now - 100)
            self.assertEqual(outcome["runsObserved"], 673)
            self.assertTrue(outcome["failed"])
            self.assertFalse(outcome["unknown"])
            lifecycle_outcome = monitor.read_runs(now, lookback_hours=168, token="synthetic")
            self.assertEqual([row["runId"] for row in lifecycle_outcome], ["10673"])
        self.assertEqual(sum("/runs?" in path for path in observed), 28)

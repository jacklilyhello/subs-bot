"""Monitor classification tests run on the hosted worker CI."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_monitor as monitor


def event(stage, details=None, timestamp=1000):
    return {"stage": stage, "details": details or {}, "timestamp": timestamp}


def run(status="completed", conclusion="success", created=900):
    return {"runId": "123", "runAttempt": "1", "revision": "a" * 40,
            "created": created, "status": status, "conclusion": conclusion}


def capacity(row="normal", objects="normal", size="normal"):
    return {"rowStatus": row, "objectStatus": objects, "objectBytesStatus": size}


def complete(row="normal"):
    return [event("started"), event("preflight", {"capacity": capacity(row)}),
            event("verified", {"checkpointId": "a" * 32, "manifestSha256": "b" * 64}),
            event("resumed")]


class MonitorTests(unittest.TestCase):
    def observe(self, runs, events, now=1100):
        return monitor.evaluate(runs, events, now, overdue_hours=1, timeout_minutes=2)

    def test_success_requires_verified_and_resumed(self):
        result = self.observe([run()], {"123-1": complete()})
        self.assertEqual(result["status"], "ok")
        self.assertFalse(result["archiveRereadByMonitor"])
        incomplete = self.observe([run()], {"123-1": complete()[:-1]})
        self.assertIn("evidence-incomplete", incomplete["alerts"])
        self.assertIn("backup-overdue", incomplete["alerts"])

    def test_failure_timeout_and_missing_backup_raise_alerts(self):
        self.assertIn("failed", self.observe([run(conclusion="failure")], {"123-1": []})["alerts"])
        self.assertIn("timed-out", self.observe([run(status="in_progress", conclusion=None)], {"123-1": []})["alerts"])
        self.assertIn("backup-overdue", self.observe([], {})["alerts"])
        self.assertIn("backup-overdue", self.observe([run()], {"123-1": complete()}, now=5000)["alerts"])

    def test_capacity_warnings_and_unknown_are_not_silent(self):
        self.assertIn("capacity-near-limit", self.observe([run()], {"123-1": complete("warning")})["alerts"])
        self.assertIn("capacity-over-limit", self.observe([run()], {"123-1": complete("over-limit")})["alerts"])
        self.assertIn("capacity-unknown", self.observe([run()], {"123-1": [event("preflight", {"capacity": capacity(objects="not-checked")})]})["alerts"])
        value = capacity(row="unknown", objects="unverified", size="unknown")
        value["failureReason"] = "object-too-large"
        observed = self.observe([run()], {"123-1": [event("preflight", {"capacity": value})]})
        self.assertIn("capacity-over-limit", observed["alerts"])
        self.assertIn("capacity-unknown", observed["alerts"])

    def test_extended_pause_is_visible_while_interrupted_or_after_resume(self):
        events = [event("started", {"pauseLimitSeconds": 60}), event("paused", timestamp=1000)]
        result = self.observe([run(status="in_progress", conclusion=None)], {"123-1": events})
        self.assertIn("pause-limit-exceeded", result["alerts"])
        events.append(event("resumed", {"pauseLimitExceeded": True}, timestamp=1090))
        result = self.observe([run()], {"123-1": events})
        self.assertIn("pause-limit-exceeded", result["alerts"])

    def test_maximum_pause_is_distinct_from_warning_and_legacy_receipts(self):
        events = [event("started", {"pauseLimitSeconds": 60, "maximumPauseSeconds": 300}),
                  event("pause-intent", timestamp=1000), event("paused", timestamp=1000)]
        active = self.observe([run(status="in_progress", conclusion=None)], {"123-1": events}, now=1301)
        self.assertIn("pause-limit-exceeded", active["alerts"])
        self.assertIn("pause-maximum-exceeded", active["alerts"])
        events.append(event("resumed", {"pauseLimitExceeded": True, "maximumPauseExceeded": True}, timestamp=1301))
        completed = self.observe([run()], {"123-1": events}, now=1301)
        self.assertIn("pause-maximum-exceeded", completed["alerts"])
        events[-1]["details"].pop("maximumPauseExceeded")
        self.assertIn("pause-maximum-exceeded", self.observe([run()], {"123-1": events}, now=1301)["alerts"])
        events[-1]["details"]["maximumPauseExceeded"] = "true"
        with self.assertRaises(Exception):
            self.observe([run()], {"123-1": events}, now=1301)

    def test_untrusted_or_future_success_cannot_clear_alerts(self):
        malformed = complete()
        malformed[2]["details"]["manifestSha256"] = "bad"
        with self.assertRaises(Exception):
            self.observe([run()], {"123-1": malformed})
        with self.assertRaises(Exception):
            self.observe([run()], {"123-1": [event("verified", timestamp=2000)]})

    def test_inventory_rejects_other_repository_and_accepts_scheduled_run(self):
        revision = "a" * 40
        record = {"id": 123, "run_attempt": 1, "head_sha": revision,
                  "display_title": "Production lifecycle rehearsal daily-backup at " + revision,
                  "workflow_id": 321, "path": monitor.WORKFLOW, "event": "schedule", "head_branch": "main",
                  "repository": {"id": monitor.github.REPOSITORY_ID}, "head_repository": {"id": monitor.github.REPOSITORY_ID},
                  "created_at": "1970-01-01T00:15:00Z", "status": "completed", "conclusion": "success"}

        def read(path, _token):
            if path.endswith("worker-production-lifecycle-rehearsal.yml"):
                return {"id": 321, "path": monitor.WORKFLOW}
            return {"total_count": 1, "workflow_runs": [record]}

        with patch.object(monitor.github, "_get_json", side_effect=read):
            self.assertEqual(monitor.read_runs(1100, lookback_hours=1, token="x")[0]["runId"], "123")
            record["head_repository"]["id"] = 999
            with self.assertRaises(Exception):
                monitor.read_runs(1100, lookback_hours=1, token="x")


if __name__ == "__main__":
    unittest.main()

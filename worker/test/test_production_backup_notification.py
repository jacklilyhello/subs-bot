"""Exercise bounded monitor routing; no external notification is sent."""
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_notification as notification


class NotificationTests(unittest.TestCase):
    def test_default_and_configured_filter_preserve_all_alerts(self):
        self.assertFalse(notification.prepare({"status": "ok", "alerts": []}, "*")["notificationRelevant"])
        report = {"status": "alert", "alerts": ["backup-overdue", "capacity-near-limit"]}
        notification.prepare(report, "*")
        self.assertTrue(report["notificationRelevant"])
        notification.prepare(report, "failed")
        self.assertFalse(report["notificationRelevant"])
        self.assertEqual(report["alerts"], ["backup-overdue", "capacity-near-limit"])
        self.assertEqual(report["status"], "alert")
        notification.prepare(report, "failed,capacity-near-limit")
        self.assertTrue(report["notificationRelevant"])

    def test_unknown_and_invalid_configuration_are_never_suppressed(self):
        report = {"status": "alert", "alerts": ["monitor-unknown"]}
        self.assertTrue(notification.prepare(report, "failed")["notificationRelevant"])
        invalid = notification.prepare({"status": "ok", "alerts": []}, "failed\nprivate-data")
        self.assertEqual(invalid["status"], "alert")
        self.assertIn("notification-config-invalid", invalid["alerts"])
        self.assertTrue(invalid["notificationRelevant"])
        self.assertNotIn("private-data", json.dumps(invalid))

    def test_outputs_are_bounded_and_digest_matches_private_report(self):
        with tempfile.TemporaryDirectory() as root:
            report = notification.prepare({"status": "alert", "alerts": ["backup-overdue"]}, "*")
            destination, output = Path(root) / "report.json", Path(root) / "outputs"
            output.touch()
            digest = notification.write(report, destination, output)
            self.assertEqual(digest, sha256(destination.read_bytes()).hexdigest())
            values = dict(line.split("=", 1) for line in output.read_text().splitlines())
            self.assertEqual(values, {"status": "alert", "alerts_json": '["backup-overdue"]',
                                      "report_sha256": digest, "notification_relevant": "true"})
            with self.assertRaises(FileExistsError):
                notification.write(report, destination, output)


if __name__ == "__main__":
    unittest.main()

"""Hosted checks for isolation lifecycle credential selection boundaries."""
from pathlib import Path
import json
import re
import unittest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_lifecycle_drill as drill
from production_target import ContractError


class LifecycleCredentialSelectionTests(unittest.TestCase):
    def test_pause_alarm_and_maximum_are_independently_configured(self):
        self.assertEqual(drill.backup_pause_limits({}), (300, 1800))
        self.assertEqual(drill.backup_pause_limits({"DRILL_BACKUP_PAUSE_LIMIT_SECONDS": "600",
                                                    "DRILL_BACKUP_MAX_PAUSE_SECONDS": "3600"}), (600, 3600))
        for env in ({"DRILL_BACKUP_MAX_PAUSE_SECONDS": "299"},
                    {"DRILL_BACKUP_MAX_PAUSE_SECONDS": "21601"},
                    {"DRILL_BACKUP_PAUSE_LIMIT_SECONDS": "900", "DRILL_BACKUP_MAX_PAUSE_SECONDS": "600"}):
            with self.subTest(env=env), self.assertRaises(ContractError):
                drill.backup_pause_limits(env)

    def test_read_and_write_actions_have_disjoint_exact_credentials(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-production-lifecycle-rehearsal.yml").read_text()
        section = workflow.split("- name: Execute the registered production lifecycle code path", 1)[1].split(
            "- name: Independently restore the original test webhook", 1)[0]
        lines = {name: next(line for line in section.splitlines() if name + ":" in line)
                 for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN")}
        def groups(line):
            return [set(json.loads(raw)) for raw in re.findall(r"fromJSON\('([^']+)'\)", line)]
        data_read, data_write = groups(lines["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
        worker_read, worker_write = groups(lines["SUBS_BOT_CF_DEPLOY_TOKEN"])
        self.assertFalse(data_read & data_write)
        self.assertFalse(worker_read & worker_write)
        self.assertTrue({"inspect", "backup-anchor-genesis-plan", "backup-anchor-reconcile-plan"} <= data_read)
        self.assertTrue({"daily-backup", "daily-backup-watchdog", "recovery"} <= data_write)
        self.assertTrue({"inspect", "daily-backup", "daily-backup-watchdog"} <= worker_read)
        self.assertTrue({"bootstrap", "provider-binding", "provider-binding-resume"} <= worker_write)
        self.assertIn("SUBS_BOT_CF_ISOLATION_DATA_READ_TOKEN", lines["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
        self.assertIn("SUBS_BOT_CF_ISOLATION_DATA_TOKEN", lines["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
        self.assertIn("SUBS_BOT_SEALED_WORKER_READ_TOKEN", lines["SUBS_BOT_CF_DEPLOY_TOKEN"])
        self.assertIn("SUBS_BOT_CF_ISOLATION_WORKER_TOKEN", lines["SUBS_BOT_CF_DEPLOY_TOKEN"])
        self.assertNotIn("secrets.SUBS_BOT_CF_BOOTSTRAP_TOKEN", lines["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
        self.assertNotIn("secrets.SUBS_BOT_CF_DEPLOY_TOKEN", lines["SUBS_BOT_CF_DEPLOY_TOKEN"])
        self.assertTrue(lines["SUBS_BOT_CF_BOOTSTRAP_TOKEN"].rstrip().endswith("|| '' }}"))
        self.assertTrue(lines["SUBS_BOT_CF_DEPLOY_TOKEN"].rstrip().endswith("|| '' }}"))
        for marker in ("- name: Independently restore the original test webhook after the exercise",
                       "- name: Finalize only both complete positive and revoked-link HTTP results"):
            segment = workflow.split(marker, 1)[1].split("        run:", 1)[0]
            self.assertIn("secrets.SUBS_BOT_CF_ISOLATION_DATA_READ_TOKEN", segment)
            self.assertIn("secrets.SUBS_BOT_SEALED_WORKER_READ_TOKEN", segment)
            self.assertNotIn("secrets.SUBS_BOT_CF_ISOLATION_DATA_TOKEN", segment)
            self.assertNotIn("secrets.SUBS_BOT_CF_ISOLATION_WORKER_TOKEN", segment)


if __name__ == "__main__":
    unittest.main()

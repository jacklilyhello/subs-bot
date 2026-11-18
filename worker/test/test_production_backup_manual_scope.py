"""Hosted checks for the independently approved manual scope boundary."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import prepare_isolation_artifact as artifact
import production_backup_manual_scope as manual
from production_target import ContractError


class ManualScopeTests(unittest.TestCase):
    def scope(self):
        scope = manual.ManualScope.__new__(manual.ManualScope)
        scope.start = {"action": "pause", "workflowRef": artifact.REPOSITORY +
                       "/.github/workflows/worker-production-backup.yml@" + artifact.MAIN_REF}
        scope.env = {"GITHUB_RUN_ID": "123"}
        scope.scope = "a" * 64
        scope.objects, scope.anchor, scope.guard = Mock(), Mock(), Mock()
        return scope

    def test_unconfirmed_result_cannot_release_scope_or_write_result(self):
        scope = self.scope()
        with self.assertRaises(ContractError):
            scope.finish({"action": "pause", "status": "unknown"})
        scope.objects.put_once.assert_not_called()
        scope.anchor.release.assert_not_called()

    def test_unknown_result_write_never_releases_or_reissues(self):
        scope = self.scope()
        scope.objects.get.return_value = (None, None)
        scope.objects.put_once.side_effect = RuntimeError("unconfirmed")
        with self.assertRaises(RuntimeError):
            scope.finish({"action": "pause", "status": "paused"})
        scope.objects.put_once.assert_called_once()
        scope.anchor.release.assert_not_called()


if __name__ == "__main__":
    unittest.main()

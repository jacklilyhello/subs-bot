"""Hosted checks for GET-only Provider response reconciliation."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_private_mutation_reconcile as reconcile
from test_production_provider import config


class ReconcileTests(unittest.TestCase):
    def fixture(self):
        previous = config(active=True)
        target = deepcopy(previous)
        target.update({"previous": previous, "versionId": None, "activation": None, "workflow": None})
        target["build"]["revision"] = "7" * 40
        intent = {"operation": "stage", "status": "started-unknown", "targetSha256": control.digest(target),
                  "runId": "101", "runAttempt": "1"}
        observation = {"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/versions",
                       "identities": {"versionId": "11111111-1111-1111-1111-111111111111"}}
        original = {"intentSha256": control.digest(intent), "targetSha256": control.digest(target), "operation": "stage",
                    "observation": observation}
        state = {"activation": previous["activation"], "container": previous["container"],
                 "workflow": previous["workflow"], "instance": {"status": "fixture"}}
        return target, intent, original, state

    def test_stage_uses_exact_response_identity_and_never_writes(self):
        target, intent, original, state = self.fixture()
        api = Mock()
        with patch.object(reconcile, "ReadOnlyAPI", return_value=api), patch.object(control, "observe", return_value=state), \
                patch.object(control, "unbound_upgrade") as previous, patch.object(control, "caller_state", return_value="unbound"):
            candidate, report = reconcile.confirmed_candidate(target, intent, original, "read-only", "read-only")
        self.assertEqual(candidate["versionId"], original["observation"]["identities"]["versionId"])
        self.assertEqual(report["originalRunId"], "101")
        self.assertFalse(report["originalRunSucceeded"])
        self.assertEqual(previous.call_count, 2)
        api.upload.assert_not_called()
        api.deploy.assert_not_called()
        api.trigger.assert_not_called()

    def test_wrong_response_or_changed_caller_remains_unknown(self):
        target, intent, original, state = self.fixture()
        with self.assertRaises(control.ProviderError):
            reconcile.confirmed_candidate(target, intent, {**original, "intentSha256": "0" * 64}, "r", "r")
        api = Mock()
        with patch.object(reconcile, "ReadOnlyAPI", return_value=api), patch.object(control, "observe", return_value=state), \
                patch.object(control, "unbound_upgrade"), patch.object(control, "caller_state", return_value="bound"), \
                self.assertRaises(control.ProviderError):
            reconcile.confirmed_candidate(target, intent, original, "r", "r")
        api.upload.assert_not_called()

    def test_reconciliation_reader_rejects_any_mutation(self):
        api = object.__new__(reconcile.ReadOnlyAPI)
        with self.assertRaises(control.ProviderError):
            api._request("/fixture", method="POST", body={})
        with self.assertRaises(control.ProviderError):
            api.upload(b"module")


if __name__ == "__main__":
    unittest.main()

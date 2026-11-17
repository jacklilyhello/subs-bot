"""Hosted-only one-shot isolated Provider mutation refusal tests."""

from hashlib import sha256
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_private_mutation as mutation
from test_production_provider import config


class ProviderPrivateMutationTests(unittest.TestCase):
    def fixture(self, root):
        target = config(active=True)
        image, module = Path(root) / "image.tar", b"fixture module"
        image.write_bytes(b"fixture image")
        target["build"]["ociArchiveSha256"] = sha256(image.read_bytes()).hexdigest()
        target["build"]["workerSha256"] = sha256(module).hexdigest()
        state = {"stateSha256": "1" * 64, "deploymentHistorySha256": "2" * 64, "callerState": "unbound"}
        refs = [{"fixture": "pinned source"}]
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_IMAGE_PREPARATION_SHA256": "3" * 64}, clear=True):
            original = mutation.intent(target, refs, "stage", state, "101", "b" * 40)
        env = {"RUNNER_TEMP": root, "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b" * 40,
               "SUBS_BOT_PROVIDER_IMAGE_PREPARATION_SHA256": "3" * 64,
               "SUBS_BOT_PROVIDER_MUTATION_APPROVAL": original["approvalSha256"],
               "SUBS_BOT_CF_PROVIDER_WORKER_TOKEN": "fixture-worker", "SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN": "fixture-container"}
        return target, image, module, state, refs, original, env

    def test_unconfirmed_intent_or_approval_stops_before_api(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, image, module, _state, refs, original, env = self.fixture(temporary)
            with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources") as guard, \
                    patch.object(mutation, "GuardedObservedAPI") as api, self.assertRaises(control.ProviderError):
                mutation.dispatch(target, refs, "stage", original, "0" * 64, image, module)
            guard.assert_not_called()
            api.assert_not_called()

    def test_response_only_observation_precedes_confirmation_and_failure_never_retries(self):
        with tempfile.TemporaryDirectory() as temporary:
            target, image, module, state, refs, original, env = self.fixture(temporary)
            api = Mock()
            calls = []
            def make_api(_target, sink, _operation, _guard):
                api.sink = sink
                return api
            def operate(client, _op, _module, _image, _guard):
                client.sink({"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/versions",
                             "identities": {"versionId": "11111111-1111-1111-1111-111111111111"}})
                calls.append("subsequent-read")
                raise control.ProviderError("unknown after response")
            def write(kind, _value):
                calls.append(kind)
                return "2" * 64
            with patch.dict(os.environ, env, clear=True), patch.object(control, "guard_sources"), \
                    patch.object(mutation, "observe", return_value=state), \
                    patch.object(mutation, "GuardedObservedAPI", side_effect=make_api), \
                    patch.object(control, "verify_previous_archives"), patch.object(control, "PublishedImage"), \
                    patch.object(control, "run_operation", side_effect=operate) as run, \
                    patch.object(mutation, "write_encrypted", side_effect=write), self.assertRaises(control.ProviderError):
                mutation.dispatch(target, refs, "stage", original, control.digest(original), image, module)
            self.assertEqual(calls, ["observation", "subsequent-read"])
            run.assert_called_once()

    def test_guard_rejection_occurs_before_worker_write(self):
        api = object.__new__(mutation.GuardedObservedAPI)
        api.write_guard = Mock(side_effect=control.ProviderError("caller changed"))
        with patch.object(mutation.rehearsal.ObservedAPI, "upload") as upload, self.assertRaises(control.ProviderError):
            api.upload(b"module")
        upload.assert_not_called()

    def test_response_observation_rejects_unexpected_secret_or_path(self):
        target = config(active=True)
        value = {"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/versions",
                 "identities": {"versionId": "11111111-1111-1111-1111-111111111111"}}
        self.assertEqual(mutation.checked_observation(target, "stage", value), value)
        for change in ({"token": "synthetic"}, {"path": "/other"}, {"identities": {"versionId": "not-a-uuid"}}):
            with self.subTest(change=change), self.assertRaises(control.ProviderError):
                mutation.checked_observation(target, "stage", {**value, **change})

    def test_deployment_inventory_rejects_duplicates_and_full_boundary(self):
        row = {"id": "11111111-1111-1111-1111-111111111111"}
        api = Mock(worker_path="/workers/scripts/fixture")
        api._request.return_value = {"result": {"deployments": [row, row]}, "result_info": {}}
        with self.assertRaises(control.ProviderError):
            mutation.deployment_history(api)
        rows = [{"id": f"00000000-0000-0000-0000-{i:012x}"} for i in range(100)]
        api._request.return_value = {"result": {"deployments": rows}, "result_info": {}}
        with self.assertRaises(control.ProviderError):
            mutation.deployment_history(api)

    def test_preparation_rechecks_before_each_confirmed_pending_followup(self):
        image = object.__new__(mutation.GuardedPreparation)
        image.reference = "fixture@sha256:" + "a" * 64
        image._url, image._opener, image._token = "https://fixture.invalid", Mock(), "fixture"
        pending = (202, {"result": {"image": image.reference, "status": "pending"}})
        ready = (200, {"result": {"image": image.reference, "status": "ready"}})
        guard = Mock()
        with patch.object(control.stage, "monotonic", side_effect=[0, 1, 2]), \
                patch.object(control.stage, "sleep"), patch.object(control.stage, "_json_request", side_effect=[pending, ready]) as request:
            image.prepare(guard)
        self.assertEqual(guard.call_count, 2)
        self.assertEqual(request.call_count, 2)


if __name__ == "__main__":
    unittest.main()

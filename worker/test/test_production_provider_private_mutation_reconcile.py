"""Hosted checks for GET-only Provider response reconciliation."""
from copy import deepcopy
from hashlib import sha256
import json
import io
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout

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
                  "runId": "101", "runAttempt": "1", "prestate": {"deploymentHistorySha256": control.digest([])}}
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
                patch.object(reconcile.mutation, "deployment_history", return_value=[]), \
                patch.object(control, "unbound_upgrade") as previous, patch.object(control, "caller_state", return_value="unbound"):
            candidate, report = reconcile.confirmed_candidate(target, intent, original, "read-only", "read-only")
        self.assertEqual(candidate["versionId"], original["observation"]["identities"]["versionId"])
        self.assertEqual(report["originalRunId"], "101")
        self.assertEqual(report["originalRunConclusion"], "not-success")
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
                patch.object(reconcile.mutation, "deployment_history", return_value=[]), \
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

    def test_activation_accepts_only_the_single_observed_new_deployment(self):
        target, intent, original, _state = self.fixture()
        target["versionId"] = "11111111-1111-1111-1111-111111111111"
        old = [{"id": target["previous"]["activation"]["deploymentId"]}]
        deployment_id = "22222222-2222-2222-2222-222222222222"
        intent.update(operation="activate", targetSha256=control.digest(target),
                      prestate={"deploymentHistorySha256": control.digest(old)})
        obs = {"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/deployments",
               "identities": {"id": deployment_id}, "responseSha256": "a" * 64}
        original.update(intentSha256=control.digest(intent), targetSha256=control.digest(target), operation="activate", observation=obs)
        state = {"activation": {"deploymentId": deployment_id, "namespaceId": target["previous"]["activation"]["namespaceId"]},
                 "container": target["previous"]["container"], "workflow": target["previous"]["workflow"], "instance": None}
        rows = [{"id": deployment_id}, *old]
        api = Mock()
        with patch.object(reconcile, "ReadOnlyAPI", return_value=api), patch.object(control, "observe", return_value=state), \
                patch.object(reconcile.mutation, "deployment_history", return_value=rows), \
                patch.object(control, "verify_previous_terminal"), patch.object(control, "caller_state", return_value="unbound"):
            candidate, _report = reconcile.confirmed_candidate(target, intent, original, "r", "r")
            self.assertEqual(candidate["activation"]["deploymentId"], deployment_id)
        with patch.object(reconcile, "ReadOnlyAPI", return_value=api), patch.object(control, "observe", return_value=state), \
                patch.object(reconcile.mutation, "deployment_history", return_value=[rows[0], {"id": "33333333-3333-3333-3333-333333333333"}, *old]), \
                self.assertRaises(control.ProviderError):
            reconcile.confirmed_candidate(target, intent, original, "r", "r")
        api.deploy.assert_not_called()

    def test_original_failed_run_and_response_are_pinned_before_observation(self):
        target, intent, original, _state = self.fixture()
        revision, candidate = "a" * 40, "b" * 40
        intent.update(controllerRevision=revision, candidateRevision=candidate, reviewedPr="290", workflowPath=reconcile.journal.WORKFLOW)
        original.update(intentSha256=control.digest(intent), observationCipherSha256=sha256(b"encrypted").hexdigest(),
                        controllerRevision=revision, candidateRevision=candidate, reviewedPr="290", runId="101", version=1,
                        kind="isolated-provider-response-only", confirmedCipherSha256=None, resultSha256=None)
        raw_intent, raw_original = control.canonical(intent), control.canonical(original)
        pin = {"version": 1, "originalRunId": "101", "intentSha256": sha256(raw_intent).hexdigest(),
               "observationSha256": sha256(b"encrypted").hexdigest(), "observationPlaintextSha256": sha256(raw_original).hexdigest(),
               "targetSha256": control.digest(target), "originalControllerRevision": revision, "originalCandidateRevision": candidate,
               "reviewedPr": "290", "operation": "stage", "readbackJobId": "201"}
        run = {"id": 101, "run_attempt": 1, "head_sha": revision, "path": reconcile.journal.WORKFLOW,
               "status": "completed", "conclusion": "failure"}
        job = {"id": 201, "steps": [{"name": "Independently read encrypted failure evidence", "status": "completed", "conclusion": "success"}]}
        def get(path, _token):
            return {"total_count": 1, "jobs": [job]} if path.endswith("/jobs?per_page=100") else run
        reader = Mock()
        reader.read.side_effect = lambda key: {"intent.json": raw_intent, "failure-observation.age": b"encrypted",
                                              "failure-observation.json": raw_original}[key]
        keys = {"intent.json", "failure-observation.age", "failure-observation.json"}
        with patch.dict(os.environ, {"PROVIDER_HEAD_REVIEWED_SHA": candidate}, clear=True), \
                patch.object(control.github, "_github_token", return_value="fixture"), patch.object(control.github, "_get_json", side_effect=get), \
                patch.object(reconcile.journal, "store", return_value=reader), patch.object(reconcile.journal, "inventory", return_value={"101": keys}), \
                patch.object(reconcile.journal, "ledger", return_value={}), patch.object(reconcile.journal, "controllers", return_value=[revision]), \
                patch.object(reconcile, "original_history"), patch.object(reconcile.digest_journal, "workflow_job"):
            self.assertEqual(reconcile.original_evidence(target, pin), (intent, original))
            with self.assertRaises(control.ProviderError):
                reconcile.original_evidence(target, {**pin, "observationSha256": "0" * 64})
        reader.put_once.assert_not_called()

    def test_resolution_receipt_never_claims_original_success_and_requires_both_payload_pins(self):
        plan = {"controllerRevision": "a" * 40, "candidateRevision": "b" * 40, "reviewedPr": "290"}
        pin = {"originalRunId": "101"}
        env = {"GITHUB_RUN_ID": "501", "SUBS_BOT_PROVIDER_RECONCILE_ARCHIVE_PAYLOAD_SHA256": "c" * 64,
               "SUBS_BOT_PROVIDER_RECONCILE_LIVE_PAYLOAD_SHA256": "d" * 64}
        with patch.dict(os.environ, env, clear=True):
            value = reconcile.receipt(plan, "e" * 64, pin)
            self.assertEqual(value["status"], "independent-observation-not-original-success")
            self.assertEqual(value["runId"], "501")
            self.assertEqual(value["pin"], pin)
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_RECONCILE_LIVE_PAYLOAD_SHA256": ""}):
                with self.assertRaises(control.ProviderError):
                    reconcile.receipt(plan, "e" * 64, pin)

    def test_resolution_requires_exact_plan_and_independent_approval(self):
        target = config(active=True)
        refs = [{"kind": "fixture"}]
        pin = {"version": 1, "originalRunId": "101", "intentSha256": "1" * 64, "observationSha256": "2" * 64,
               "observationPlaintextSha256": "3" * 64, "targetSha256": control.digest(target),
               "originalControllerRevision": "a" * 40, "originalCandidateRevision": "b" * 40,
               "reviewedPr": "290", "operation": "stage", "readbackJobId": "201"}
        observation = {"status": "observed-by-read-only-reconciliation", "operation": "stage", "originalRunId": "101",
                       "originalRunAttempt": "1", "intentSha256": pin["intentSha256"], "responseOriginalSha256": pin["observationPlaintextSha256"],
                       "targetSha256": pin["targetSha256"], "nextTargetSha256": "4" * 64, "stateSha256": "5" * 64,
                       "deploymentHistorySha256": "6" * 64, "callerState": "unbound", "originalRunConclusion": "not-success"}
        plan = {"version": 1, "kind": "isolated-provider-reconciliation-plan", "pinSha256": control.digest(pin),
                "controllerRevision": "a" * 40, "candidateRevision": "b" * 40, "reviewedPr": "290",
                "archiveRefsSha256": control.digest(refs), "observation": observation}
        approval = control.digest(plan)
        env = {"GITHUB_SHA": "a" * 40, "SUBS_BOT_PROVIDER_RECONCILE_PLAN_JSON": json.dumps(plan),
               "SUBS_BOT_PROVIDER_RECONCILE_APPROVAL": approval, "SUBS_BOT_PROVIDER_RECONCILE_TRUSTED_APPROVAL": approval}
        with patch.dict(os.environ, env, clear=True), patch.object(reconcile.transfer, "context"), \
                patch.object(reconcile.transfer, "workflow_path", return_value=reconcile.transfer.REVIEWED_RECOVERY_WORKFLOW_PATH), \
                patch.object(reconcile.transfer, "target", return_value=target), patch.object(reconcile.transfer, "refs", return_value=refs), \
                patch.object(reconcile, "protected_pin", return_value=pin), \
                patch.object(reconcile.transfer, "execution_identity", return_value={"candidateRevision": "b" * 40, "reviewedPr": "290"}):
            self.assertEqual(reconcile.approved_plan()[3], approval)
            with patch.object(reconcile, "protected_pin", return_value={**pin, "readbackJobId": "202"}), \
                    self.assertRaises(control.ProviderError):
                reconcile.approved_plan()

    def test_resolution_write_is_once_and_requires_original_evidence(self):
        target, pin, plan, approval = {}, {"originalRunId": "101"}, {}, "a" * 64
        reader = Mock()
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "501", "GITHUB_SHA": "b" * 40}, clear=True), \
                patch.object(reconcile, "approved_plan", return_value=(target, pin, plan, approval)), \
                patch.object(reconcile.digest_journal, "workflow_job"), patch.object(reconcile.digest_journal, "output"), \
                patch.object(reconcile, "original_evidence") as original, patch.object(reconcile.journal, "store", return_value=reader), \
                patch.object(reconcile, "receipt", return_value={"fixture": True}), patch.object(control.github, "require_current_main"):
            reconcile.write_resolution()
            reader.put_once.assert_called_once_with("resolution-501.json", control.canonical({"fixture": True}))
            reader.put_once.reset_mock()
            original.side_effect = control.ProviderError("missing original")
            with self.assertRaises(control.ProviderError):
                reconcile.write_resolution()
            reader.put_once.assert_not_called()

    def test_readback_seals_ledger_without_printing_protected_pin(self):
        pin = {"originalRunId": "101", "intentSha256": "9" * 64, "privateFixture": "do-not-print-this-pin"}
        plan = {"candidateRevision": "b" * 40, "reviewedPr": "290", "observation": {"nextTargetSha256": "c" * 64}}
        approval, raw = "d" * 64, control.canonical({"receipt": "fixture"})
        env = {"GITHUB_RUN_ID": "501", "GITHUB_SHA": "a" * 40,
               "SUBS_BOT_PROVIDER_RECONCILE_RESOLUTION_SHA256": sha256(raw).hexdigest()}
        reader = Mock()
        reader.read.return_value = raw
        sealed = {"archive": "e" * 64, "live": "f" * 64}
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), \
                patch.object(reconcile, "approved_plan", return_value=({}, pin, plan, approval)), \
                patch.object(reconcile.digest_journal, "workflow_job", return_value="201"), \
                patch.object(reconcile.digest_journal, "output") as emitted, patch.object(reconcile, "original_evidence"), \
                patch.object(reconcile.journal, "store", return_value=reader), patch.object(reconcile.journal, "reconciled", return_value={}), \
                patch.object(reconcile.journal, "seal_next_target", return_value=sealed) as seal, \
                patch.object(reconcile, "receipt", return_value={"receipt": "fixture"}), redirect_stdout(output):
            reconcile.readback_resolution()
        self.assertNotIn("do-not-print-this-pin", output.getvalue())
        self.assertNotIn("do-not-print-this-pin", repr(emitted.call_args_list))
        self.assertEqual(seal.call_args.args[0]["101"]["pin"], pin)
            with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_RECONCILE_TRUSTED_APPROVAL": "0" * 64}), \
                    self.assertRaises(control.ProviderError):
                reconcile.approved_plan()


if __name__ == "__main__":
    unittest.main()

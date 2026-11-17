"""Hosted checks for admission and immutable evidence of Provider mutations."""

import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_private_mutation_journal as journal
from test_production_provider import config


class ProviderMutationJournalTests(unittest.TestCase):
    def test_reconciled_ledger_must_be_explicit_and_key_match_original_run(self):
        with patch.dict(os.environ, {}, clear=True), self.assertRaises((ValueError, KeyError)):
            journal.reconciled()
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_MUTATION_RECONCILED_JSON": '{"101":{"pin":{"originalRunId":"102"}}}'}, clear=True), \
                self.assertRaises(control.ProviderError):
            journal.reconciled()
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_MUTATION_RECONCILED_JSON": '{}'}, clear=True):
            self.assertEqual(journal.reconciled(), {})

    def test_stage_requires_exact_independently_registered_image_preparation(self):
        value = {"targetSha256": "a" * 64, "imagePreparationSha256": "b" * 64}
        registered = {"100": {"operation": "prepare-image", "targetSha256": "a" * 64,
                              "completionSha256": "c" * 64}}
        writer = Mock()
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40}
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(None, None, "stage", value)), \
                patch.object(journal.digest_journal, "workflow_job"), patch.object(journal, "store", return_value=writer), \
                patch.object(journal, "inventory", return_value={"100": set()}), \
                patch.object(journal, "ledger", return_value=registered), \
                patch.object(journal, "history") as history, self.assertRaises(control.ProviderError):
            journal.write_intent()
        writer.put_once.assert_not_called()
        history.assert_not_called()

    def test_incomplete_verification_cannot_be_registered_as_completion(self):
        value = {"operation": "stage", "targetSha256": "a" * 64, "runId": "101"}
        verification = {"status": "independently-verified", "operation": "stage", "targetSha256": "a" * 64}
        env = {"SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON": json.dumps(verification),
               "SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256": "b" * 64}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(control.ProviderError):
            journal.completion_value(value, {})

    def test_completion_binds_safe_original_and_both_cipher_digests(self):
        value = {"operation": "stage", "targetSha256": "a" * 64, "runId": "101"}
        verified = {key: "1" * 64 for key in journal.VERIFICATION_HASH_FIELDS}
        verified.update({"status": "independently-verified", "operation": "stage", "targetSha256": "a" * 64})
        original = {"confirmedCipherSha256": "b" * 64, "observationCipherSha256": "c" * 64,
                    "resultSha256": verified["resultSha256"]}
        env = {"SUBS_BOT_PROVIDER_MUTATION_VERIFICATION_JSON": json.dumps(verified),
               "SUBS_BOT_PROVIDER_MUTATION_RESPONSE_SHA256": "b" * 64}
        with patch.dict(os.environ, env, clear=True):
            completed = journal.completion_value(value, original)
            self.assertEqual(completed["observationSha256"], "c" * 64)
            self.assertEqual(completed["observationPlaintextSha256"], control.digest(original))
            with self.assertRaises(control.ProviderError):
                journal.completion_value(value, {**original, "confirmedCipherSha256": "0" * 64})

    def test_unknown_inventory_blocks_next_mutation(self):
        reader = Mock()
        with patch.object(journal.durable, "list_private_keys", return_value=[
                journal.BASE + "100/1/intent.json"]), patch.object(journal, "ledger", return_value={}), \
                patch.object(journal, "reconciled", return_value={}), patch.object(journal, "controllers", return_value=["d" * 40]), \
                self.assertRaises(control.ProviderError):
            journal.inventory(reader)

    def test_failure_evidence_is_single_write_and_does_not_create_completion(self):
        from hashlib import sha256
        value = {"kind": "fixture-intent"}
        raw = control.canonical(value)
        reader = Mock()
        reader.run_id = "101"
        reader.read.return_value = raw
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "d" * 40,
               "SUBS_BOT_PROVIDER_MUTATION_INTENT_SHA256": sha256(raw).hexdigest()}
        original = {"confirmedCipherSha256": None}
        with patch.dict(os.environ, env, clear=True), patch.object(journal, "planned", return_value=(None, None, "stage", value)), \
                patch.object(journal, "store", return_value=reader), patch.object(journal, "inventory", return_value={"101": {"intent.json"}}), \
                patch.object(journal, "download_response", return_value=b"encrypted observation"), \
                patch.object(journal, "response_original", return_value=original), patch.object(journal.digest_journal, "output"):
            journal.failure_evidence()
        self.assertEqual([call.args[0] for call in reader.put_once.call_args_list], ["failure-observation.age", "failure-observation.json"])

    def test_readonly_resolution_requires_every_writing_job_skipped_and_empty_prefix(self):
        revision, run_id = "d" * 40, "101"
        run = {"id": 101, "run_attempt": 1, "head_sha": revision, "path": journal.WORKFLOW,
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "failure",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        jobs = [{"name": name, "id": 200 + index, "run_id": 101, "run_attempt": 1, "head_sha": revision,
                 "status": "completed", "conclusion": "skipped", "steps": []}
                for index, name in enumerate(journal.JOBS.values())]
        reader = Mock(target={"bucket": "fixture"})
        def get(path, _token):
            return {"jobs": jobs, "total_count": len(jobs)} if path.endswith("jobs?per_page=100") else run
        with patch.object(control.github, "_github_token", return_value="fixture"), patch.object(control.github, "_get_json", side_effect=get), \
                patch.object(journal.durable, "source_ancestor"), patch.object(journal.durable, "list_private_keys", return_value=[]) as listing:
            report = journal.inspect_readonly_run(reader, run_id, [revision])
            self.assertEqual(report["objectCount"], 0)
            job = next(row for row in jobs if row["name"] == journal.JOBS["failure-write"])
            job["conclusion"] = "failure"
            with self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            job["conclusion"] = "skipped"
            listing.return_value = [journal.BASE + run_id + "/1/intent.json"]
            with self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])

    def test_decrypted_response_original_is_strict_and_bound_to_both_ciphers(self):
        target = config(active=True)
        value = {"runId": "101", "operation": "stage", "controllerRevision": "a" * 40,
                 "candidateRevision": "b" * 40, "reviewedPr": "290", "targetSha256": control.digest(target)}
        obs = {"kind": "response-only", "method": "POST", "path": f"/workers/scripts/{target['service']}/versions",
               "identities": {"versionId": "11111111-1111-1111-1111-111111111111"}}
        first = {"intentSha256": control.digest(value), "observation": obs}
        confirmed = {"intentSha256": control.digest(value), "target": target, "operation": "stage", "observation": obs, "result": {}}
        with patch.object(journal, "decrypt_record", side_effect=[first, confirmed]):
            result = journal.response_original(target, value, b"observation", b"confirmed")
        self.assertEqual(result["observation"], obs)
        self.assertNotIn("target", result)
        first["observation"] = {**obs, "token": "synthetic"}
        with patch.object(journal, "decrypt_record", return_value=first), self.assertRaises(control.ProviderError):
            journal.response_original(target, value, b"observation")


if __name__ == "__main__":
    unittest.main()

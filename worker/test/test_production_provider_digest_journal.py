"""Hosted-only one-shot isolated digest journal refusal tests."""

import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_provider as control
import provider_digest_journal as journal
from test_production_provider import config


class DigestJournalTests(unittest.TestCase):
    def test_only_skipped_intent_and_empty_prefix_can_be_resolved_readonly(self):
        revision, run_id = "b" * 40, "101"
        run = {"id": 101, "run_attempt": 1, "path": journal.transfer.WORKFLOW_PATH, "head_sha": revision,
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        write_jobs = {journal.JOBS[k] for k in ("intent-write", "publish", "completion-write")}
        jobs = [{"id": 201 + index, "name": name, "run_id": 101, "run_attempt": 1, "head_sha": revision,
                 "status": "completed", "conclusion": "skipped" if name in write_jobs else "success", "steps": []}
                for index, name in enumerate(journal.JOBS.values())]
        publish_job = next(job for job in jobs if job["name"] == journal.JOBS["publish"])
        def get(path, _token):
            return {"total_count": len(jobs), "jobs": jobs} if path.endswith("/jobs?per_page=100") else run
        reader = Mock(target={"fixture": "registered isolated bucket"})
        with patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", side_effect=get), \
                patch.object(journal.durable, "source_ancestor") as ancestor, \
                patch.object(journal.durable, "list_private_keys", return_value=[]) as listing:
            report = journal.inspect_readonly_run(reader, run_id, [revision])
            self.assertEqual(report["classification"], "intent-job-skipped-empty-prefix")
            ancestor.assert_called_once_with({"revision": revision}, "synthetic")
            listing.assert_called_once_with(reader, journal.BASE + run_id + "/1/")
            with patch.dict(publish_job, {"conclusion": "success"}), self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            with patch.dict(publish_job, {"head_sha": "c" * 40}), self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            with patch.dict(publish_job, {"steps": [{"status": "completed", "conclusion": "failure"}]}), self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            with patch.dict(jobs[0], {"name": "unexpected extra job"}), self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
            with patch.object(journal.durable, "list_private_keys", return_value=[journal.BASE + run_id + "/1/source-intent.json"]), \
                    self.assertRaises(control.ProviderError):
                journal.inspect_readonly_run(reader, run_id, [revision])
        reader.put.assert_not_called()

    def test_readonly_resolution_requires_exact_successful_reconciliation(self):
        revision, run_id, reconcile_id = "b" * 40, "101", "103"
        report = {"version": 1, "kind": "isolated-provider-digest-readonly-resolution",
                  "classification": "intent-job-skipped-empty-prefix", "runId": run_id,
                  "controllerRevision": revision, "runConclusion": "success", "intentJobId": "202", "publishJobId": "203",
                  "completionJobId": "204",
                  "bucketSha256": "1" * 64, "objectCount": 0}
        pin = {"controllerRevision": revision, "intentJobId": "202", "publishJobId": "203", "completionJobId": "204",
               "readbackSha256": control.digest(report),
               "reconcileRunId": reconcile_id, "reconcileRunAttempt": "1", "reconcileRevision": revision}
        run = {"id": 103, "run_attempt": 1, "path": journal.RECONCILE_WORKFLOW, "display_title": "Inspect isolated digest 101",
               "head_sha": revision, "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        job = {"name": "Digest read-only reconciliation", "run_id": 103, "run_attempt": 1, "head_sha": revision,
               "status": "completed", "conclusion": "success", "steps": [
                   {"name": "Inspect skipped intent without writes", "status": "completed", "conclusion": "success"}]}
        def get(path, _token):
            return {"total_count": 1, "jobs": [job]} if path.endswith("/jobs?per_page=100") else run
        with patch.object(journal, "inspect_readonly_run", return_value=report), patch.object(journal.durable, "source_ancestor"), \
                patch.object(control.github, "_github_token", return_value="synthetic"), patch.object(control.github, "_get_json", side_effect=get):
            journal.verify_readonly_resolution(Mock(), run_id, pin, [revision])
            with patch.dict(run, {"display_title": "Inspect isolated digest 999"}), self.assertRaises(control.ProviderError):
                journal.verify_readonly_resolution(Mock(), run_id, pin, [revision])
            with patch.dict(job, {"conclusion": "failure"}), self.assertRaises(control.ProviderError):
                journal.verify_readonly_resolution(Mock(), run_id, pin, [revision])
            with self.assertRaises(control.ProviderError):
                journal.verify_readonly_resolution(Mock(), run_id, {**pin, "readbackSha256": "0" * 64}, [revision])

    def test_unregistered_readonly_run_blocks_until_explicit_resolution(self):
        revision = "b" * 40
        common = {"path": journal.transfer.WORKFLOW_PATH, "head_sha": revision, "head_branch": "main", "event": "workflow_dispatch",
                  "run_attempt": 1, "repository": {"id": control.github.REPOSITORY_ID},
                  "head_repository": {"id": control.github.REPOSITORY_ID}}
        rows = [{**common, "id": 101, "status": "completed", "conclusion": "success"},
                {**common, "id": 102, "status": "in_progress", "conclusion": None}]
        pin = {"controllerRevision": revision}
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "102", "GITHUB_SHA": revision}, clear=True), \
                patch.object(journal, "controllers", return_value=[revision]), \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value={"total_count": 2, "workflow_runs": rows}), \
                patch.object(journal, "verify_readonly_resolution") as verify:
            with patch.object(journal, "readonly_resolutions", return_value={}):
                with self.assertRaises(control.ProviderError):
                    journal.history({}, Mock())
            with patch.object(journal, "readonly_resolutions", return_value={"101": pin}):
                journal.history({}, Mock())
                verify.assert_called_once()

    def test_workflow_statically_disables_all_digest_and_journal_writes(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-provider-digest-rehearsal.yml").read_text()
        intent = workflow.split("\n  intent_write:\n", 1)[1].split("\n  intent_readback:\n", 1)[0]
        self.assertIn("if: ${{ vars.SUBS_BOT_PROVIDER_DIGEST_WRITE_ENABLED == 'true' }}", intent)
        self.assertIn("needs: [source, preflight, intent_readback]", workflow)
        self.assertEqual(workflow.count("uses: actions/upload-artifact@"), 1)
        self.assertIn("path: ${{ runner.temp }}/provider-source-transfer.age", workflow)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_CONTAINER_WRITE_TOKEN", workflow.split("\n  publish:\n", 1)[0])
        publish = workflow.split("\n  publish:\n", 1)[1].split("\n  verify:\n", 1)[0]
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN", publish)
        self.assertNotIn("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", publish)

    def test_unknown_prior_intent_blocks_before_any_new_write(self):
        reader = Mock()
        with patch.object(journal.durable, "list_private_keys", return_value=[journal.BASE + "100/1/source-intent.json"]), \
                patch.object(journal, "ledger", return_value={}), patch.object(journal, "controllers", return_value=["b" * 40]), \
                self.assertRaises(control.ProviderError):
            journal.inventory(reader)
        reader.put.assert_not_called()

    def test_intent_pins_readonly_resolution_ledger(self):
        target = config(active=True)
        state = {"dependencySha256": "1" * 64, "manifestSha256": None, "tagsSha256": "4" * 64}
        refs = [{"fixture": "source"}]
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_DIGEST_READONLY_RESOLUTIONS_JSON": "{}"}, clear=True):
            before = journal.digest.intent(target, refs, state, "101", "b" * 40)
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_DIGEST_READONLY_RESOLUTIONS_JSON": '{"99":{}}'}, clear=True):
            after = journal.digest.intent(target, refs, state, "101", "b" * 40)
        self.assertNotEqual(control.digest(before), control.digest(after))

    def test_existing_digest_does_not_count_as_write_rehearsal(self):
        target = config(active=True)
        state = {"dependencySha256": "1" * 64, "manifestSha256": target["build"]["ociManifestSha256"], "tagsSha256": "4" * 64}
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40}, clear=True), \
                patch.object(journal.transfer, "context"), patch.object(journal.transfer, "target", return_value=target), \
                patch.object(journal.transfer, "refs", return_value=[{"fixture": "source"}]), patch.object(journal.transfer, "receive"), \
                patch.object(journal.digest, "observe", return_value=state), patch.object(journal, "output") as output, \
                self.assertRaises(control.ProviderError):
            journal.preflight()
        output.assert_not_called()

    def test_missing_independent_intent_readback_prevents_source_decode_and_copy(self):
        target = config(active=True)
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40}
        with patch.dict(os.environ, env, clear=True), patch.object(journal.transfer, "context"), \
                patch.object(journal, "parse_intent", return_value=(target, [{"fixture": "source"}], {})), \
                patch.object(journal, "workflow_job", side_effect=["1", control.ProviderError("missing readback")]), \
                patch.object(journal.transfer, "receive") as receive, patch.object(journal.digest, "publish_once") as publish, \
                self.assertRaises(control.ProviderError):
            journal.publish()
        receive.assert_not_called()
        publish.assert_not_called()

    def test_malformed_prestate_cannot_create_an_intent(self):
        target = config(active=True)
        import json
        env = {"GITHUB_RUN_ID": "101", "GITHUB_SHA": "b" * 40,
               "SUBS_BOT_PROVIDER_DIGEST_PRESTATE_JSON": json.dumps({"dependencySha256": "bad", "manifestSha256": None})}
        with patch.dict(os.environ, env, clear=True), patch.object(journal.transfer, "target", return_value=target), \
                patch.object(journal.transfer, "refs", return_value=[{"fixture": "source"}]), self.assertRaises(control.ProviderError):
            journal.parse_intent()


if __name__ == "__main__":
    unittest.main()

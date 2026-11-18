"""Hosted-only isolation archive origin, interruption and refusal tests."""

from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import archive_production_provider as archive
import production_provider as control
import provider_durable_source as durable
import provider_isolated_source as isolated
import provider_digest_journal as digest_journal
from test_production_provider import config


class IsolatedSourceTests(unittest.TestCase):
    def target(self):
        target = config(active=True)
        target["build"]["archiveSha256"] = sha256(b"fixture-original").hexdigest()
        return target

    def manifest(self, target):
        return {"version": 1, "kind": "subs-bot-isolated-provider-source", "runId": "101", "runAttempt": "1",
                "controllerRevision": "b" * 40, "target": target,
                "files": {"provider-source-archive.zip": {"bytes": 16, "sha256": target["build"]["archiveSha256"],
                           "chunks": [{"bytes": 16, "sha256": target["build"]["archiveSha256"]}]}}}

    def test_manifest_pins_target_kind_and_exact_digest(self):
        target = self.target()
        value = self.manifest(target)
        raw = control.canonical(value)
        reader = Mock(run_id="101")
        reader.read.return_value = raw
        verified, observed = isolated.manifest(reader, sha256(raw).hexdigest())
        self.assertEqual((verified, observed), (value, target))
        with self.assertRaises(control.ProviderError):
            isolated.manifest(reader, "0" * 64)
        value["kind"] = "subs-bot-production-provider-source"
        raw = control.canonical(value)
        reader.read.return_value = raw
        with self.assertRaises(control.ProviderError):
            isolated.manifest(reader, sha256(raw).hexdigest())

    def test_reviewed_source_manifest_preserves_candidate_identity(self):
        target = self.target()
        value = {**self.manifest(target), "workflowPath": isolated.REVIEWED_SEAL_WORKFLOW,
                 "candidateRevision": "c" * 40, "reviewedPr": "290"}
        raw = control.canonical(value)
        reader = Mock(run_id="101")
        reader.read.return_value = raw
        verified, _ = isolated.manifest(reader, sha256(raw).hexdigest())
        self.assertEqual((verified["controllerRevision"], verified["candidateRevision"]), ("b" * 40, "c" * 40))
        for change in ({"workflowPath": isolated.SEAL_WORKFLOW}, {"candidateRevision": "bad"}, {"reviewedPr": ""}):
            with self.subTest(change=change):
                raw = control.canonical({**value, **change})
                reader.read.return_value = raw
                with self.assertRaises(control.ProviderError):
                    isolated.manifest(reader, sha256(raw).hexdigest())

    def test_incomplete_or_unknown_prior_intent_blocks_before_writes(self):
        reader = Mock()
        key = isolated.BASE + "100/1/source-intent.json"
        with patch.object(durable, "list_private_keys", return_value=[key]), self.assertRaises(control.ProviderError):
            isolated.inventory(reader)
        reader.put.assert_not_called()

    def test_unregistered_other_source_dispatch_blocks(self):
        revision = "b" * 40
        common = {"head_sha": revision, "head_branch": "main", "event": "workflow_dispatch", "run_attempt": 1,
                  "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        def get(path, _token):
            reviewed = isolated.REVIEWED_SEAL_WORKFLOW.rsplit("/", 1)[-1] in path
            row = {**common, "path": isolated.REVIEWED_SEAL_WORKFLOW if reviewed else isolated.SEAL_WORKFLOW,
                   "id": 101 if reviewed else 102, "display_title": "Isolated Provider source seal " + ("999" if reviewed else "100"),
                   "status": "completed" if reviewed else "in_progress", "conclusion": "failure" if reviewed else None}
            return {"total_count": 1, "workflow_runs": [row]}
        env = {"GITHUB_RUN_ID": "102", "GITHUB_SHA": revision}
        with patch.dict(os.environ, env, clear=True), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(digest_journal, "workflow_has_main_history", return_value=True), \
                patch.object(durable, "source_ancestor"), \
                patch.object(control.github, "_get_json", side_effect=get), self.assertRaises(control.ProviderError):
            isolated.history("100", {}, [revision])

    def test_duplicate_listing_is_not_treated_as_complete_inventory(self):
        reader = Mock()
        key = isolated.BASE + "100/1/source-intent.json"
        with patch.object(durable, "list_private_keys", return_value=[key, key]), self.assertRaises(control.ProviderError):
            isolated.inventory(reader)
        reader.put.assert_not_called()

    def test_origin_controller_must_be_independently_allowlisted(self):
        revision = "b" * 40
        record = {"runId": "102", "controllerRevision": revision}
        run = {"id": 102, "run_attempt": 1, "path": isolated.SEAL_WORKFLOW,
               "event": "workflow_dispatch", "display_title": "Isolated Provider source seal 101",
               "status": "completed", "conclusion": "success", "head_branch": "main", "head_sha": revision,
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        with patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=run), patch.object(durable, "source_ancestor"), \
                patch.object(isolated, "controllers", return_value=[revision]):
            isolated.verify_origin("101", record)
        with patch.object(isolated, "controllers", return_value=["c" * 40]), \
                patch.object(control.github, "_get_json") as get, self.assertRaises(control.ProviderError):
            isolated.verify_origin("101", record)
        get.assert_not_called()

    def test_registered_source_requires_exact_independent_successful_readback(self):
        revision, target = "b" * 40, self.target()
        source = {"intentSha256": "1" * 64, "manifestSha256": "2" * 64,
                  "runId": "102", "controllerRevision": revision}
        target_sha = control.digest(target)
        report = isolated.readback_projection("101", source, target_sha, "103", "1", revision)
        pin = {**source, "targetSha256": target_sha, "readbackRunId": "103", "readbackRunAttempt": "1",
               "readbackControllerRevision": revision, "readbackSha256": control.digest(report)}
        run = {"id": 103, "run_attempt": 1, "path": isolated.READBACK_WORKFLOW, "head_sha": revision,
               "display_title": f"Read isolated source 101 1 {source['manifestSha256']} {target_sha}",
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        job = {"name": "readback", "run_id": 103, "run_attempt": 1, "head_sha": revision,
               "status": "completed", "conclusion": "success", "steps": [{
                   "name": "Independently verify the pinned original from private R2", "status": "completed", "conclusion": "success"}]}
        def get(path, _token):
            return {"total_count": 1, "jobs": [job]} if path.endswith("/jobs?per_page=100") else run
        reader = Mock(target={}, token="synthetic")
        with patch.object(isolated, "controllers", return_value=[revision]), patch.object(isolated, "Store"), \
                patch.object(isolated, "manifest", return_value=({}, target)), patch.object(durable, "source_ancestor"), \
                patch.object(control.github, "_github_token", return_value="synthetic"), patch.object(control.github, "_get_json", side_effect=get):
            isolated.verify_registered(reader, {"101": source}, {"101": pin})
            for changed in ({"readbackSha256": "0" * 64}, {"targetSha256": "0" * 64}):
                with self.subTest(changed=changed), self.assertRaises(control.ProviderError):
                    isolated.verify_registered(reader, {"101": source}, {"101": {**pin, **changed}})
            with patch.dict(run, {"display_title": "Read isolated source 999 1 wrong wrong"}), self.assertRaises(control.ProviderError):
                isolated.verify_registered(reader, {"101": source}, {"101": pin})
            with patch.dict(job, {"conclusion": "failure"}), self.assertRaises(control.ProviderError):
                isolated.verify_registered(reader, {"101": source}, {"101": pin})
            with self.assertRaises(control.ProviderError):
                isolated.verify_registered(reader, {"101": source}, {})

    def test_target_cannot_be_production_or_have_caller(self):
        target = self.target()
        env = {"SUBS_BOT_PROVIDER_CI_RUN_ID": target["build"]["runId"]}
        with patch.dict(os.environ, env, clear=True), patch.object(control, "read_config", return_value=target):
            self.assertEqual(isolated.target_config(), target)
            for change in ({"environment": "production"}, {"caller": {"fixture": "bound"}}):
                with patch.dict(target, change), self.assertRaises(control.ProviderError):
                    isolated.target_config()

    def test_unknown_prior_inventory_stops_seal_before_intent(self):
        target = self.target()
        reader = Mock()
        env = {"SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": "{}", "SUBS_BOT_PROVIDER_ISOLATED_SOURCE_OPERATION_ID": "101"}
        with patch.dict(os.environ, env, clear=True), patch.object(isolated, "context"), \
                patch.object(isolated, "target_config", return_value=target), patch.object(isolated, "store", return_value=reader), \
                patch.object(isolated, "inventory", side_effect=control.ProviderError("unknown prior intent")), \
                self.assertRaises(control.ProviderError):
            isolated.seal(True)
        reader.put.assert_not_called()

    def test_isolation_store_and_original_chain_require_private_ledger(self):
        target = self.target()
        value = self.manifest(target)
        ref = {"kind": "isolated-source", "runId": "101", "runAttempt": "1", "manifestSha256": "a" * 64,
               "targetSha256": control.digest(target)}
        record = {"manifestSha256": ref["manifestSha256"]}
        def read_record(_store, _manifest, _name, output):
            output.write(b"fixture-original")
            return sha256(b"fixture-original").hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            env = {"RUNNER_TEMP": temporary, "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([ref]),
                   "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": "{}"}
            with patch.dict(os.environ, env, clear=True), patch.object(isolated, "Store"), \
                    patch.object(isolated, "inventory", return_value={"101": record}), \
                    patch.object(isolated, "ledger", return_value={"101": record}), \
                    patch.object(isolated, "verify_registered") as registered, \
                    patch.object(isolated, "verify_origin") as origin, patch.object(isolated, "manifest", return_value=(value, target)), \
                    patch.object(archive, "read_record", side_effect=read_record):
                durable.restore()
            origin.assert_called_once()
            registered.assert_called_once()
            index = json.loads((Path(temporary) / "provider-durable-sources/index.json").read_bytes())
            self.assertEqual(index, [{"build": target["build"], "target": target}])
        with tempfile.TemporaryDirectory() as temporary:
            env["RUNNER_TEMP"] = temporary
            with patch.dict(os.environ, env, clear=True), patch.object(isolated, "Store"), \
                    patch.object(isolated, "inventory", return_value={"101": record}), patch.object(isolated, "ledger", return_value={}), \
                    patch.object(isolated, "verify_registered", side_effect=control.ProviderError("missing independent readback")), \
                    patch.object(isolated, "verify_origin") as origin, self.assertRaises(control.ProviderError):
                durable.restore()
            origin.assert_not_called()

    def test_isolated_reference_is_never_accepted_as_production(self):
        ref = {"kind": "isolated-source", "runId": "101", "runAttempt": "1", "manifestSha256": "a" * 64,
               "targetSha256": "b" * 64}
        with tempfile.TemporaryDirectory() as temporary, \
                patch.dict(os.environ, {"RUNNER_TEMP": temporary, "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([ref]),
                                        "SUBS_BOT_PROVIDER_ARCHIVE_ENVIRONMENT": "production"}, clear=True), \
                self.assertRaises(control.ProviderError):
            durable.restore()


if __name__ == "__main__":
    unittest.main()

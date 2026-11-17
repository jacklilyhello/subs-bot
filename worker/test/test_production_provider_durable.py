"""Hosted checks for pinned Provider archive handoff and fail-closed source guards."""

from copy import deepcopy
from base64 import b64encode
from contextlib import nullcontext
from hashlib import sha1, sha256
from io import BytesIO
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
from test_archive_production_provider import MemoryStore, fixture
from test_production_provider import config
import test_prepare_provider_artifact as artifact_fixture


class DurableSourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        source = self.root / "source"
        source.mkdir()
        fixture(source)
        self.store = MemoryStore()
        self.result = archive.archive(self.store, source)
        self.proof = json.loads((source / "provider-rehearsal-proof.json").read_bytes())
        self.ref = {"runId": "100", "runAttempt": "1", "kind": "complete",
                    "manifestSha256": self.result["manifestSha256"],
                    "targetSha256": control.digest(self.proof["target"])}

    def restore(self, ref=None):
        env = {"RUNNER_TEMP": str(self.root), "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([ref or self.ref]),
               "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": "{}"}
        with patch.dict(os.environ, env, clear=True), patch.object(archive, "PrivateProofStore", return_value=self.store):
            durable.restore()

    def test_independent_manifest_target_and_original_are_bound(self):
        self.restore()
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root)}, clear=True):
            records = control.durable_builds()
            self.assertEqual(records[0]["target"], self.proof["target"])
            self.assertTrue(control.durable_archive(self.proof["target"]["build"]).is_file())
            path = control.durable_archive(self.proof["target"]["build"])
            path.write_bytes(b"corrupt")
            with self.assertRaises(control.ProviderError):
                control.durable_archive(self.proof["target"]["build"])

    def test_wrong_target_or_manifest_and_missing_blob_are_rejected(self):
        for field in ("targetSha256", "manifestSha256"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp:
                bad = {**self.ref, field: "0" * 64}
                env = {"RUNNER_TEMP": temp, "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([bad]),
                       "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": "{}"}
                with patch.dict(os.environ, env, clear=True), patch.object(archive, "PrivateProofStore", return_value=self.store):
                    with self.assertRaises(control.ProviderError):
                        durable.restore()
        self.store.objects.pop(next(key for key in self.store.objects if key.startswith("blobs/")))
        with self.assertRaises(control.ProviderError):
            self.restore()

    def test_missing_required_handoff_never_falls_back_to_ci(self):
        with patch.dict(os.environ, {"RUNNER_TEMP": str(self.root), "SUBS_BOT_PROVIDER_DURABLE_REQUIRED": "1"}, clear=True):
            with self.assertRaises(control.ProviderError):
                control.durable_builds()

    def test_production_cannot_use_isolation_archive(self):
        env = {"RUNNER_TEMP": str(self.root), "SUBS_BOT_PROVIDER_ARCHIVE_REFS": json.dumps([self.ref]),
               "SUBS_BOT_PROVIDER_ARCHIVE_ENVIRONMENT": "production"}
        with patch.dict(os.environ, env, clear=True), self.assertRaises(control.ProviderError):
            durable.restore()

    def test_target_identity_mismatch_rejected_before_provider_mutation(self):
        source = self.proof["target"]
        different = deepcopy(source)
        different["worker"]["workerId"] = "5" * 32
        row = {"build": source["build"], "target": different}
        env = {"GITHUB_SHA": source["build"]["revision"]}
        with patch.dict(os.environ, env, clear=True), patch.object(control.github, "require_current_main"), \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control, "durable_builds", return_value=[row]), \
                patch.object(control, "durable_archive") as read, self.assertRaises(control.ProviderError):
            control.guard_sources(source)
        read.assert_not_called()

    def test_archived_confirmed_identity_cannot_be_cleared(self):
        archived = config(active=True)
        requested = deepcopy(archived)
        requested.update({"versionId": None, "activation": None, "container": None, "workflow": None})
        row = {"build": archived["build"], "target": archived}
        with patch.dict(os.environ, {"GITHUB_SHA": archived["build"]["revision"]}, clear=True), \
                patch.object(control.github, "require_current_main"), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control, "durable_builds", return_value=[row]), patch.object(control, "durable_archive") as read, \
                self.assertRaises(control.ProviderError):
            control.guard_sources(requested)
        read.assert_not_called()

    def test_archived_previous_and_current_are_checked_without_actions_artifacts(self):
        previous = config(active=True)
        current = config()
        current["build"]["revision"] = "7" * 40
        current.update({"versionId": None, "container": previous["container"], "workflow": None, "previous": previous})
        records = [{"build": source["build"], "target": source} for source in (current, previous)]
        comparison = {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                      "base_commit": {"sha": previous["build"]["revision"]},
                      "merge_base_commit": {"sha": previous["build"]["revision"]}}
        with patch.dict(os.environ, {"GITHUB_SHA": current["build"]["revision"]}, clear=True), \
                patch.object(control.github, "require_current_main"), patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=comparison), \
                patch.object(control.github, "verify_main_run") as verify, patch.object(control, "durable_builds", return_value=records), \
                patch.object(control, "durable_archive") as read, patch.object(control.provenance, "_select_artifact") as actions:
            control.guard_sources(current)
        self.assertEqual(verify.call_count, 2)
        self.assertEqual(read.call_count, 2)
        actions.assert_not_called()

    def test_simulated_unavailable_actions_verifies_current_and_previous_oci(self):
        handoff = self.root / "provider-durable-sources"
        handoff.mkdir(mode=0o700)

        def release(revision, run_id, artifact_id, requirements=None):
            source = self.root / ("fixture-" + run_id)
            source.mkdir()
            with patch.object(artifact_fixture, "REVISION", revision):
                (source / control.provider.IMAGE).write_bytes(artifact_fixture.oci_fixture())
            (source / control.provider.WORKER).write_bytes(b"export default {};\n")
            manifest = control.provider.release_manifest(source, revision,
                requirements or Path(control.provider.__file__).with_name("requirements.txt"), ref=control.github.MAIN_REF,
                run_id=run_id, run_attempt="1")
            members = {name: (source / name).read_bytes() for name in (control.provider.IMAGE, control.provider.WORKER)}
            members[control.provider.MANIFEST] = artifact_fixture.encoded(manifest)
            original = artifact_fixture.zip_fixture(members)
            build = {"revision": revision, "runId": run_id, "runAttempt": "1", "artifactId": artifact_id,
                     "archiveSha256": sha256(original).hexdigest(),
                     **{key: manifest[key] for key in control.publication.MANIFEST_FIELDS}}
            (handoff / (build["archiveSha256"] + ".zip")).write_bytes(original)
            return build

        previous = config(active=True)
        old_requirements = self.root / "historical-requirements.txt"
        old_requirements.write_bytes(b"historical-package==1.2.3\n")
        previous["build"] = release("b" * 40, "101", "201", old_requirements)
        current = config()
        current["build"] = release("7" * 40, "102", "202")
        current.update({"versionId": None, "container": previous["container"], "workflow": None, "previous": previous})
        (handoff / "index.json").write_bytes(control.canonical([{"build": current["build"], "target": current},
                                                                 {"build": previous["build"], "target": previous}]))
        comparison = {"status": "ahead", "ahead_by": 1, "behind_by": 0,
                      "base_commit": {"sha": previous["build"]["revision"]},
                      "merge_base_commit": {"sha": previous["build"]["revision"]}}
        raw = old_requirements.read_bytes()
        blob = {"type": "file", "path": "worker/provider_fetch/requirements.txt", "encoding": "base64",
                "content": b64encode(raw).decode("ascii"), "size": len(raw),
                "sha": sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()}
        def metadata(path, _token):
            return blob if path.startswith("/contents/") else comparison
        env = {"RUNNER_TEMP": str(self.root), "GITHUB_SHA": current["build"]["revision"],
               "SUBS_BOT_PROVIDER_DURABLE_REQUIRED": "1", "SUBS_BOT_PROVIDER_CI_RUN_ID": "102"}
        with patch.dict(os.environ, env, clear=True), patch.object(control.github, "require_current_main"), \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", side_effect=metadata), \
                patch.object(control.github, "verify_main_run"), \
                patch.object(control.provenance, "_select_artifact", side_effect=AssertionError("simulated Actions unavailability")), \
                patch.object(control.provenance, "_download_zip", side_effect=AssertionError("simulated Actions unavailability")):
            control.guard_sources(current)
            self.assertEqual(control.prepare_durable(current["build"]), current["build"])
            scratch = self.root / "scratch"
            scratch.mkdir()
            control.verify_previous_archives(current, scratch)


class OriginalAttemptMetadataTests(unittest.TestCase):
    def test_historical_requirements_are_commit_pinned_and_blob_verified(self):
        revision = "b" * 40
        raw = b"historical-dependency==1.0\n"
        blob = {"type": "file", "path": "worker/provider_fetch/requirements.txt", "encoding": "base64",
                "content": b64encode(raw).decode("ascii"), "size": len(raw),
                "sha": sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()}
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"RUNNER_TEMP": temp, "GITHUB_SHA": "c" * 40}, clear=True), \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value=blob) as read:
            with control.provenance.source_requirements(revision) as requirements:
                self.assertEqual(requirements.read_bytes(), raw)
            read.assert_called_once_with(f"/contents/worker/provider_fetch/requirements.txt?ref={revision}", "synthetic")
            blob["sha"] = "0" * 40
            with self.assertRaises(control.github.ArtifactError):
                with control.provenance.source_requirements(revision):
                    pass

    def test_private_inventory_accepts_observed_paginated_and_null_terminal_envelopes(self):
        class Response(BytesIO):
            status = 200
            headers = {}
        store = Mock()
        store.target = {"accountId": "a" * 32}
        store.bucket = "fixture"
        store.token = "synthetic"
        store.api.return_value = {"status": "active", "id": "b" * 32}
        pages = [b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Prefix>maintenance/production-provider/</Prefix><IsTruncated>true</IsTruncated><NextContinuationToken>next-page</NextContinuationToken></ListBucketResult>',
                 b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Prefix>maintenance/production-provider/</Prefix><IsTruncated>false</IsTruncated></ListBucketResult>']
        store.opener.open.side_effect = [Response(page) for page in pages]
        self.assertEqual(durable.production_inventory(store, {}), {})
        self.assertEqual(store.opener.open.call_count, 2)

    def test_private_inventory_rejects_unknown_pagination_or_repeated_cursor(self):
        class Response(BytesIO):
            status = 200
            headers = {}
        no_state = b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Prefix>maintenance/production-provider/</Prefix></ListBucketResult>'
        repeated = b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Prefix>maintenance/production-provider/</Prefix><IsTruncated>true</IsTruncated><NextContinuationToken>same</NextContinuationToken></ListBucketResult>'
        for pages in ([no_state], [repeated, repeated]):
            store = Mock()
            store.target = {"accountId": "a" * 32}
            store.bucket = "fixture"
            store.token = "synthetic"
            store.api.return_value = {"status": "active", "id": "b" * 32}
            store.opener.open.side_effect = [Response(page) for page in pages]
            with self.subTest(pages=pages), self.assertRaises(control.ProviderError):
                durable.production_inventory(store, {})

    def test_simulated_actions_unavailability_disables_selection_and_download(self):
        with patch.dict(os.environ, {"SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE": "1"}, clear=True):
            with self.assertRaises(control.github.ArtifactError):
                control.provenance._select_artifact("1", "b" * 40, "synthetic")
            with self.assertRaises(control.github.ArtifactError):
                control.provenance._download_zip("2", "synthetic", "c" * 64, Path("unused"))

    def test_seal_approval_binds_exact_controller_commit(self):
        target = config(active=True)
        first = durable.source_plan(target, {"fixture": "bucket"}, "1001", {}, ["b" * 40, "c" * 40], "b" * 40)
        changed = durable.source_plan(target, {"fixture": "bucket"}, "1001", {}, ["b" * 40, "c" * 40], "c" * 40)
        self.assertNotEqual(control.digest(first), control.digest(changed))

    def test_seal_history_rejects_reuse_and_any_unresolved_prior_seal(self):
        revision = "b" * 40
        common = {"event": "workflow_dispatch", "run_attempt": 1, "head_sha": revision, "head_branch": "main",
                  "path": durable.SEAL_WORKFLOW, "repository": {"id": control.github.REPOSITORY_ID},
                  "head_repository": {"id": control.github.REPOSITORY_ID}}
        current = {**common, "id": 102, "display_title": "Provider source seal 1001"}
        prior = {**common, "id": 101, "display_title": "Provider source seal 1000", "status": "completed", "conclusion": "success"}
        env = {"GITHUB_RUN_ID": "102"}
        def check(rows):
            with patch.dict(os.environ, env, clear=True), patch.object(control.github, "_github_token", return_value="synthetic"), \
                    patch.object(control.github, "_get_json", return_value={"workflow_runs": rows, "total_count": len(rows)}):
                durable.seal_history("1001", {"1000": {"runId": "101", "controllerRevision": revision}}, [revision])
        check([current, prior])
        for changed in ({**prior, "conclusion": "failure"}, {**prior, "display_title": current["display_title"]}):
            with self.subTest(changed=changed), self.assertRaises(control.ProviderError):
                check([current, changed])

    def test_unknown_intent_write_never_attempts_source_chunks(self):
        target = config(active=True)
        target["environment"] = "production"
        target["service"] = control.SERVICES["production"]
        target["workersDevOrigin"] = "https://subs-bot-provider-fetch-prod-01.fixture.workers.dev"
        raw = b"fixture original archive"
        target["build"]["archiveSha256"] = sha256(raw).hexdigest()
        bucket = {"fixture": "independent target"}
        operation_id = "1001"
        revision = target["build"]["revision"]
        approval = control.digest(durable.source_plan(target, bucket, operation_id, {}, [revision], revision))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "provider-source-seal-input"
            root.mkdir()
            (root / "provider-source-archive.zip").write_bytes(raw)
            (root / "target.sha256").write_text(control.digest(target) + "\n")
            env = {"RUNNER_TEMP": temp, "GITHUB_SHA": target["build"]["revision"], "GITHUB_RUN_ID": "102",
                   "GITHUB_RUN_ATTEMPT": "1", "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON": json.dumps(target),
                   "SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON": json.dumps(bucket), "SUBS_BOT_PROVIDER_SOURCE_OPERATION_ID": operation_id,
                   "SUBS_BOT_PROVIDER_SOURCE_APPROVAL": approval}
            store = Mock()
            store.read.return_value = None
            store.put.side_effect = control.ProviderError("unknown write")
            with patch.dict(os.environ, env, clear=True), patch.object(durable, "seal_context"), \
                    patch.object(durable, "seal_history"), patch.object(durable, "production_inventory", return_value={}), \
                    patch.object(durable, "source_ledger", return_value={}), \
                    patch.object(durable, "trusted_controllers", return_value=[target["build"]["revision"]]), \
                    patch.object(durable, "ProductionStore", return_value=store), \
                    patch.object(control.github, "require_current_main"), patch.object(control.provenance, "_unpack"), \
                    patch.object(control.provenance, "source_requirements", return_value=nullcontext(Path("requirements"))), \
                    patch.object(control.provider, "verify_release", return_value=target["build"]):
                with self.assertRaises(control.ProviderError):
                    durable.production_seal_action(True)
            self.assertEqual(store.put.call_count, 1)
            self.assertEqual(store.put.call_args.args[0], "source-intent.json")

    def run_metadata(self, attempt):
        return {"id": 101, "run_attempt": attempt, "workflow_id": control.provenance.WORKFLOW_ID,
                "path": control.provenance.WORKFLOW_PATH, "event": "push", "status": "completed", "conclusion": "success",
                "head_branch": "main", "head_sha": "b" * 40,
                "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}

    def verify(self, attempt=None):
        return control.github.verify_main_run("101", "b" * 40, "synthetic", workflow_id=control.provenance.WORKFLOW_ID,
            workflow_path=control.provenance.WORKFLOW_PATH, workflow_label="Provider Fetch CI", run_attempt=attempt)

    def test_pinned_attempt_uses_historical_endpoint_even_after_rerun(self):
        with patch.object(control.github, "_get_json", return_value=self.run_metadata(1)) as get:
            self.assertEqual(self.verify("1"), "1")
        get.assert_called_once_with("/actions/runs/101/attempts/1", "synthetic")
        with patch.object(control.github, "_get_json", return_value=self.run_metadata(2)) as get:
            self.assertEqual(self.verify(), "2")
        get.assert_called_once_with("/actions/runs/101", "synthetic")

    def test_wrong_original_run_or_attempt_is_rejected(self):
        for value in ({**self.run_metadata(1), "id": 102}, self.run_metadata(2),
                      {**self.run_metadata(1), "conclusion": "failure"}):
            with self.subTest(value=value), patch.object(control.github, "_get_json", return_value=value):
                with self.assertRaises(control.github.ArtifactError):
                    self.verify("1")


if __name__ == "__main__":
    unittest.main()

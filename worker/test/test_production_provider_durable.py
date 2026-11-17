"""Hosted checks for pinned Provider archive handoff and fail-closed source guards."""

from copy import deepcopy
from base64 import b64encode
from contextlib import nullcontext, redirect_stdout
from hashlib import sha1, sha256
from io import BytesIO, StringIO
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
from test_archive_production_provider import MemoryStore, fixture
from test_production_provider import config
import test_prepare_provider_artifact as artifact_fixture


class DurableSourceTests(unittest.TestCase):
    def test_workflow_history_pages_are_bounded_stable_complete_and_unique(self):
        path = durable.SEAL_WORKFLOW
        first = [{"id": index} for index in range(1, 51)]
        with patch.object(control.github, "_get_json", side_effect=[
                {"total_count": 51, "workflow_runs": first}, {"total_count": 51, "workflow_runs": [{"id": 51}]}]) as get:
            self.assertEqual(len(durable.workflow_runs(path, "fixture")), 51)
            self.assertIn("per_page=50&page=1", get.call_args_list[0].args[0])
            self.assertIn("per_page=50&page=2", get.call_args_list[1].args[0])
        for second in ({"total_count": 52, "workflow_runs": [{"id": 51}]},
                       {"total_count": 51, "workflow_runs": [{"id": 50}]},
                       {"total_count": 51, "workflow_runs": []}):
            with self.subTest(second=second), patch.object(control.github, "_get_json", side_effect=[
                    {"total_count": 51, "workflow_runs": first}, second]), self.assertRaises(control.ProviderError):
                durable.workflow_runs(path, "fixture")
        pages = [{"total_count": 999, "workflow_runs": [{"id": index} for index in range(start, min(start + 50, 1000))]}
                 for start in range(1, 1000, 50)]
        with patch.object(control.github, "_get_json", side_effect=pages) as get:
            self.assertEqual(len(durable.workflow_runs(path, "fixture")), 999)
            self.assertEqual(get.call_count, 20)
        with patch.object(control.github, "_get_json", return_value={"total_count": 1000, "workflow_runs": first}), \
                self.assertRaises(control.ProviderError):
            durable.workflow_runs(path, "fixture")
        with self.assertRaises(control.ProviderError):
            durable.workflow_runs(".github/workflows/../../other.yml", "fixture")

    def test_production_store_allows_only_source_records_and_digest_blobs(self):
        store = durable.ProductionStore.__new__(durable.ProductionStore)
        store.prefix = "maintenance/production-provider/101/1/"
        for name in ("source-intent.json", "source-manifest.json", "blobs/" + "a" * 64):
            self.assertEqual(store.key(name), store.prefix + name)
        for name in ("../source-intent.json", "manifest.json", "blobs/../source-intent.json", "blobs/" + "g" * 64, None):
            with self.subTest(name=name), self.assertRaises(control.ProviderError):
                store.key(name)

    def test_production_intent_and_manifest_collisions_are_unknown_not_success(self):
        for name in ("source-intent.json", "source-manifest.json"):
            store = durable.ProductionStore.__new__(durable.ProductionStore)
            store.prefix, store.bucket = "maintenance/production-provider/101/1/", "test-bucket"
            store.target, store.token, store.access_key = {"accountId": "a" * 32}, "synthetic", "b" * 32
            store.read = Mock(return_value=None)
            connection, response = Mock(), Mock(status=412)
            response.read.return_value = b""
            connection.getresponse.return_value = response
            with self.subTest(name=name), patch.object(archive, "HTTPSConnection", return_value=connection), \
                    patch.object(archive, "signed_put_headers", return_value={}), self.assertRaises(control.ProviderError):
                store.put(name, b"fixture")
            connection.request.assert_called_once()
            store.read.assert_called_once_with(name)

    def test_scoped_intent_is_single_conditional_write_and_rejects_unknown(self):
        store = Mock()
        store.key.return_value = "maintenance/production-provider/101/1/source-intent.json"
        store.read.side_effect = [None, b"fixture"]
        durable.ProductionStore.put(store, "source-intent.json", b"fixture")
        store.objects.put_once.assert_called_once_with(store.key.return_value, b"fixture",
            metadata={"cache-control": "no-store, private", "content-type": "application/octet-stream"})
        self.assertEqual(store.read.call_count, 2)
        store.reset_mock()
        store.read.side_effect = [None]
        store.objects.put_once.side_effect = ValueError("unknown or conflict")
        with self.assertRaises(ValueError):
            durable.ProductionStore.put(store, "source-intent.json", b"fixture")
        store.objects.put_once.assert_called_once()
        store.read.assert_called_once_with("source-intent.json")

    def test_scoped_inventory_uses_bounded_complete_listing_without_token_identity(self):
        store = Mock()
        store.objects.list.return_value = ["maintenance/production-provider/101/1/source-intent.json"]
        with patch.object(archive, "verified_token_identity") as identity:
            keys = durable.list_private_keys(store, "maintenance/production-provider/")
        self.assertEqual(keys, store.objects.list.return_value)
        store.objects.list.assert_called_once_with("maintenance/production-provider/", maximum=10000)
        identity.assert_not_called()

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
    def test_failed_seal_readback_never_writes_and_never_authorizes_retry(self):
        origin = {"runId": "102", "controllerRevision": "b" * 40, "runConclusion": "failure",
                  "sealStepConclusion": "skipped"}
        env = {"SUBS_BOT_PROVIDER_SOURCE_OPERATION_ID": "1001", "SUBS_BOT_PROVIDER_SOURCE_FAILED_RUN_ID": "102",
               "SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON": "{}", "GITHUB_SHA": "c" * 40}
        store = Mock()
        output = StringIO()
        with patch.dict(os.environ, env, clear=True), patch.object(durable, "seal_context"), \
                patch.object(durable, "ProductionStore", return_value=store), \
                patch.object(durable, "production_inventory", return_value=({}, set())), \
                patch.object(durable, "source_ledger", return_value={}), patch.object(durable, "trusted_controllers", return_value=[]), \
                patch.object(durable, "failed_seal_origin", return_value=origin), \
                patch.object(control.github, "require_current_main"), redirect_stdout(output):
            durable.inspect_production_failure()
        result = json.loads(output.getvalue())
        self.assertEqual(result["classification"], "seal-step-not-dispatched")
        self.assertFalse(result["retryAuthorized"])
        store.put.assert_not_called()

    def test_missing_intent_after_executed_seal_never_proves_no_dispatch(self):
        origin = {"runId": "102", "controllerRevision": "b" * 40, "runConclusion": "failure",
                  "sealStepConclusion": "failure"}
        env = {"SUBS_BOT_PROVIDER_SOURCE_OPERATION_ID": "1001", "SUBS_BOT_PROVIDER_SOURCE_FAILED_RUN_ID": "102",
               "SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON": "{}", "GITHUB_SHA": "c" * 40}
        store = Mock()
        with patch.dict(os.environ, env, clear=True), patch.object(durable, "seal_context"), \
                patch.object(durable, "ProductionStore", return_value=store), \
                patch.object(durable, "production_inventory", return_value=({}, set())), \
                patch.object(durable, "source_ledger", return_value={}), patch.object(durable, "trusted_controllers", return_value=[]), \
                patch.object(durable, "failed_seal_origin", return_value=origin), self.assertRaises(control.ProviderError):
            durable.inspect_production_failure()
        store.put.assert_not_called()

    def test_skipped_seal_never_claims_preexisting_complete_objects(self):
        origin = {"runId": "102", "controllerRevision": "b" * 40, "runConclusion": "failure",
                  "sealStepConclusion": "skipped"}
        env = {"SUBS_BOT_PROVIDER_SOURCE_OPERATION_ID": "1001", "SUBS_BOT_PROVIDER_SOURCE_FAILED_RUN_ID": "102",
               "SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON": "{}", "GITHUB_SHA": "c" * 40}
        store = Mock()
        with patch.dict(os.environ, env, clear=True), patch.object(durable, "seal_context"), \
                patch.object(durable, "ProductionStore", return_value=store), \
                patch.object(durable, "production_inventory", return_value=({}, {"source-intent.json", "source-manifest.json"})), \
                patch.object(durable, "source_ledger", return_value={}), patch.object(durable, "trusted_controllers", return_value=[]), \
                patch.object(durable, "failed_seal_origin", return_value=origin), \
                patch.object(durable, "production_manifest") as manifest, self.assertRaises(control.ProviderError):
            durable.inspect_production_failure()
        manifest.assert_not_called()
        store.put.assert_not_called()

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
        store.objects = None
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
            store.objects = None
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

    def test_seal_approval_changes_when_failure_resolution_changes(self):
        target = config(active=True)
        before = durable.source_plan(target, {}, "1001", {}, ["b" * 40], "b" * 40, {})
        after = durable.source_plan(target, {}, "1001", {}, ["b" * 40], "b" * 40, {"1000": {"fixture": "resolution"}})
        self.assertNotEqual(control.digest(before), control.digest(after))

    def test_production_seal_origin_is_independently_pinned_to_approval(self):
        target = config(active=True)
        origin = {"version": 1, "kind": "isolated-source", "runId": "101", "runAttempt": "1",
                  **{key: "a" * 64 for key in ("manifestSha256", "targetSha256", "bucketSha256", "ledgerRecordSha256")}}
        plain = durable.source_plan(target, {}, "1001", {}, ["b" * 40], "b" * 40)
        archived = durable.source_plan(target, {}, "1001", {}, ["b" * 40], "b" * 40, origin=origin)
        self.assertNotEqual(control.digest(plain), control.digest(archived))
        self.assertNotEqual(control.digest(archived), control.digest(durable.source_plan(
            target, {}, "1001", {}, ["b" * 40], "b" * 40, origin={**origin, "manifestSha256": "b" * 64})))
        for bad in ({**origin, "kind": "partial"}, {**origin, "runAttempt": "2"}, {**origin, "targetSha256": "bad"},
                    {**origin, "extra": True}):
            with self.subTest(bad=bad), self.assertRaises(control.ProviderError):
                durable.source_plan(target, {}, "1001", {}, ["b" * 40], "b" * 40, origin=bad)

    def test_archived_transport_requires_original_identity_and_never_selects_actions_artifact(self):
        target, bucket, store = config(active=True), {"fixture": "isolated-bucket"}, Mock()
        raw = b"fixture original ZIP"
        target["build"]["archiveSha256"] = sha256(raw).hexdigest()
        source_target = deepcopy(target)
        source_target["environment"] = "rehearsal"
        record = {"manifestSha256": "a" * 64, "targetSha256": control.digest(source_target)}
        origin = {"version": 1, "kind": "isolated-source", "runId": "101", "runAttempt": "1",
                  "manifestSha256": record["manifestSha256"], "targetSha256": record["targetSha256"],
                  "bucketSha256": control.digest(bucket), "ledgerRecordSha256": control.digest(record)}
        def read_record(_store, _manifest, _name, output):
            output.write(raw)
            return sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as temp, patch.dict(os.environ, {"RUNNER_TEMP": temp,
                "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": json.dumps(bucket),
                "SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE": "1"}, clear=True), \
                patch.object(isolated, "Store", return_value=store), patch.object(isolated, "inventory", return_value={"101": record}), \
                patch.object(isolated, "ledger", return_value={"101": record}), patch.object(isolated, "verify_registered") as registered, \
                patch.object(isolated, "verify_origin") as source_run, patch.object(isolated, "manifest", return_value=({}, source_target)), \
                patch.object(isolated, "verify_original") as original, patch.object(archive, "read_record", side_effect=read_record), \
                patch.object(control.provenance, "_select_artifact") as select, patch.object(control.provenance, "_download_zip") as download:
            durable.prepare_archived_transport(target, origin, Path(temp))
            self.assertEqual((Path(temp) / "provider-source-archive.zip").read_bytes(), raw)
            registered.assert_called_once()
            source_run.assert_called_once()
            original.assert_called_once()
            select.assert_not_called()
            download.assert_not_called()
            store.put.assert_not_called()
            with tempfile.TemporaryDirectory() as other, patch.object(isolated, "manifest", return_value=({}, {**source_target, "build": {**source_target["build"], "artifactId": "999"}})), \
                    self.assertRaises(control.ProviderError):
                durable.prepare_archived_transport(target, origin, Path(other))
            for failure in ("missing", "corrupt"):
                with self.subTest(failure=failure), tempfile.TemporaryDirectory() as other, \
                        patch.object(isolated, "verify_original", side_effect=control.ProviderError(failure)), \
                        self.assertRaises(control.ProviderError):
                    durable.prepare_archived_transport(target, origin, Path(other))
                store.put.assert_not_called()
            with tempfile.TemporaryDirectory() as other, \
                    patch.object(isolated, "ledger", return_value={"101": {**record, "manifestSha256": "b" * 64}}), \
                    self.assertRaises(control.ProviderError):
                durable.prepare_archived_transport(target, origin, Path(other))
            store.put.assert_not_called()

    def test_transport_marker_cannot_silently_lose_the_archived_origin(self):
        origin = {"version": 1, "kind": "isolated-source", "runId": "101", "runAttempt": "1",
                  **{key: "a" * 64 for key in ("manifestSha256", "targetSha256", "bucketSha256", "ledgerRecordSha256")}}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source-transport.json"
            with self.assertRaises((OSError, control.ProviderError)):
                durable.read_transport_marker(path)
            for marker in ({"version": 1, "mode": "isolated-source", "origin": None},
                           {"version": 1, "mode": "actions", "origin": origin},
                           {"version": 1, "mode": "other", "origin": None}):
                path.write_bytes(control.canonical(marker))
                with self.subTest(marker=marker), self.assertRaises(control.ProviderError):
                    durable.read_transport_marker(path)
            path.write_bytes(control.canonical({"version": 1, "mode": "isolated-source", "origin": origin}))
            self.assertEqual(durable.read_transport_marker(path), origin)
            path.write_bytes(control.canonical({"version": 1, "mode": "actions", "origin": None}))
            self.assertIsNone(durable.read_transport_marker(path))

    def test_origin_verifies_real_fixture_zip_and_complete_oci_without_actions(self):
        revision, run_id, attempt = artifact_fixture.REVISION, artifact_fixture.RUN_ID, artifact_fixture.ATTEMPT
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "release"
            source.mkdir()
            (source / control.provider.IMAGE).write_bytes(artifact_fixture.oci_fixture())
            (source / control.provider.WORKER).write_bytes(b"export default {};\n")
            requirements = Path(control.provider.__file__).with_name("requirements.txt")
            manifest = control.provider.release_manifest(source, revision, requirements, ref=control.github.MAIN_REF,
                                                         run_id=run_id, run_attempt=attempt)
            members = {name: (source / name).read_bytes() for name in (control.provider.IMAGE, control.provider.WORKER)}
            members[control.provider.MANIFEST] = artifact_fixture.encoded(manifest)
            original = artifact_fixture.zip_fixture(members)
            target, bucket, store = config(active=True), {"fixture": "origin-bucket"}, Mock()
            target["build"].update(revision=revision, runId=run_id, runAttempt=attempt, artifactId=artifact_fixture.ARTIFACT_ID,
                                   archiveSha256=sha256(original).hexdigest(),
                                   **{key: manifest[key] for key in control.publication.MANIFEST_FIELDS})
            source_target = deepcopy(target)
            target["environment"] = "production"
            target["service"] = control.SERVICES["production"]
            record = {"manifestSha256": "a" * 64, "targetSha256": control.digest(source_target)}
            origin = {"version": 1, "kind": "isolated-source", "runId": "101", "runAttempt": "1",
                      "manifestSha256": record["manifestSha256"], "targetSha256": record["targetSha256"],
                      "bucketSha256": control.digest(bucket), "ledgerRecordSha256": control.digest(record)}
            def read_record(_store, _manifest, _name, output):
                output.write(original)
                return sha256(original).hexdigest()
            env = {"RUNNER_TEMP": temp, "GITHUB_SHA": revision, "GH_TOKEN": "fixture-token",
                   "SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON": json.dumps(bucket), "SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE": "1"}
            destination = root / "output"
            destination.mkdir()
            with patch.dict(os.environ, env, clear=True), patch.object(isolated, "Store", return_value=store), \
                    patch.object(isolated, "inventory", return_value={"101": record}), patch.object(isolated, "ledger", return_value={"101": record}), \
                    patch.object(isolated, "verify_registered"), patch.object(isolated, "verify_origin"), \
                    patch.object(isolated, "manifest", return_value=({}, source_target)), patch.object(archive, "read_record", side_effect=read_record), \
                    patch.object(control.github, "verify_main_run"), patch.object(control.github, "_github_token", return_value="fixture-token"), \
                    patch.object(control.provenance, "_select_artifact", side_effect=AssertionError("unexpected artifact selection")), \
                    patch.object(control.provenance, "_download_zip", side_effect=AssertionError("unexpected artifact download")):
                durable.prepare_archived_transport(target, origin, destination)
            self.assertEqual((destination / "provider-source-archive.zip").read_bytes(), original)
            store.put.assert_not_called()

    def test_skipped_resolution_requires_original_and_independent_readback(self):
        revision, operation_id, seal_run, reconcile_run = "b" * 40, "1000", "101", "102"
        origin = {"runId": seal_run, "controllerRevision": revision, "runConclusion": "failure", "sealStepConclusion": "skipped"}
        bucket = {"fixture": "bucket"}
        projection = {"version": 1, "kind": "provider-source-failure-readback", "operationId": operation_id,
                      "bucketSha256": control.digest(bucket), "origin": origin, "objectCount": 0,
                      "classification": "seal-step-not-dispatched"}
        record = {"classification": "seal-step-not-dispatched", "sealRunId": seal_run, "controllerRevision": revision,
                  "readbackSha256": control.digest(projection), "reconcileRunId": reconcile_run, "reconcileRevision": revision,
                  "manifestSha256": None, "targetSha256": None}
        run = {"id": 102, "run_attempt": 1, "path": durable.RECONCILE_WORKFLOW, "head_sha": revision,
               "display_title": f"Inspect Provider source {operation_id} {seal_run} none none",
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        job = {"name": "inspect", "run_id": 102, "run_attempt": 1, "head_sha": revision,
               "status": "completed", "conclusion": "success", "steps": [{
                   "name": "Independently inspect the failed run and private archive without writing",
                   "status": "completed", "conclusion": "success"}]}
        def get(path, _token):
            return {"total_count": 1, "jobs": [job]} if path.endswith("/jobs?per_page=100") else run
        with patch.object(durable, "failed_seal_origin", return_value=origin), patch.object(durable, "list_private_keys", return_value=[]), \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", side_effect=get):
            durable.verify_source_resolution(operation_id, record, bucket, [revision], {}, Mock())
            for bad in ({**record, "readbackSha256": "0" * 64}, {**record, "reconcileRevision": "c" * 40}):
                with self.assertRaises(control.ProviderError):
                    durable.verify_source_resolution(operation_id, bad, bucket, [revision], {}, Mock())
            with patch.dict(origin, {"sealStepConclusion": "failure"}), self.assertRaises(control.ProviderError):
                durable.verify_source_resolution(operation_id, record, bucket, [revision], {}, Mock())
            with patch.object(durable, "list_private_keys", return_value=[archive.BASE + operation_id + "/1/source-intent.json"]), \
                    self.assertRaises(control.ProviderError):
                durable.verify_source_resolution(operation_id, record, bucket, [revision], {}, Mock())

    def test_complete_failed_seal_keeps_failure_and_requires_exact_original_and_readback(self):
        revision, operation_id, seal_run, reconcile_run = "b" * 40, "1000", "101", "102"
        origin = {"runId": seal_run, "controllerRevision": revision, "runConclusion": "failure", "sealStepConclusion": "failure"}
        bucket, target = {"fixture": "bucket"}, config(active=True)
        manifest_sha, target_sha, blob = "1" * 64, control.digest(target), "2" * 64
        original = {"intentSha256": "3" * 64, "manifestSha256": manifest_sha, "runId": seal_run, "controllerRevision": revision}
        projection = {"version": 1, "kind": "provider-source-failure-readback", "operationId": operation_id,
                      "bucketSha256": control.digest(bucket), "origin": origin, "objectCount": 3,
                      "classification": "complete-original-observed-failed-run", "ledgerRecord": original, "targetSha256": target_sha}
        record = {"classification": "complete-original-observed-failed-run", "sealRunId": seal_run, "controllerRevision": revision,
                  "readbackSha256": control.digest(projection), "reconcileRunId": reconcile_run, "reconcileRevision": revision,
                  "manifestSha256": manifest_sha, "targetSha256": target_sha}
        manifest = {"files": {"provider-source-archive.zip": {"chunks": [{"sha256": blob}]}}}
        prefix = archive.BASE + operation_id + "/1/"
        keys = [prefix + name for name in ("source-intent.json", "source-manifest.json", "blobs/" + blob)]
        run = {"id": 102, "run_attempt": 1, "path": durable.RECONCILE_WORKFLOW, "head_sha": revision,
               "display_title": f"Inspect Provider source {operation_id} {seal_run} {manifest_sha} {target_sha}",
               "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
               "repository": {"id": control.github.REPOSITORY_ID}, "head_repository": {"id": control.github.REPOSITORY_ID}}
        job = {"name": "inspect", "run_id": 102, "run_attempt": 1, "head_sha": revision, "status": "completed",
               "conclusion": "success", "steps": [{"name": "Independently inspect the failed run and private archive without writing",
                                                     "status": "completed", "conclusion": "success"}]}
        def get(path, _token):
            return {"total_count": 1, "jobs": [job]} if path.endswith("/jobs?per_page=100") else run
        with patch.object(durable, "failed_seal_origin", return_value=origin), patch.object(durable, "list_private_keys", return_value=keys), \
                patch.object(durable, "ProductionStore"), patch.object(durable, "production_manifest", return_value=(manifest, target)), \
                patch.object(control.github, "_github_token", return_value="synthetic"), patch.object(control.github, "_get_json", side_effect=get):
            durable.verify_source_resolution(operation_id, record, bucket, [revision], {operation_id: original}, Mock(token="synthetic"))
            with self.assertRaises(control.ProviderError):
                durable.verify_source_resolution(operation_id, {**record, "targetSha256": "0" * 64}, bucket,
                                                 [revision], {operation_id: original}, Mock(token="synthetic"))
            with patch.dict(run, {"conclusion": "failure"}), self.assertRaises(control.ProviderError):
                durable.verify_source_resolution(operation_id, record, bucket, [revision], {operation_id: original}, Mock(token="synthetic"))
            with patch.dict(run, {"display_title": "Inspect Provider source 999 101 none none"}), self.assertRaises(control.ProviderError):
                durable.verify_source_resolution(operation_id, record, bucket, [revision], {operation_id: original}, Mock(token="synthetic"))
            with patch.dict(origin, {"sealStepConclusion": "skipped"}), self.assertRaises(control.ProviderError):
                durable.verify_source_resolution(operation_id, record, bucket, [revision], {operation_id: original}, Mock(token="synthetic"))

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

    def test_skipped_resolution_cannot_reuse_operation_or_hide_existing_objects(self):
        revision = "b" * 40
        common = {"event": "workflow_dispatch", "run_attempt": 1, "head_sha": revision, "head_branch": "main",
                  "path": durable.SEAL_WORKFLOW, "repository": {"id": control.github.REPOSITORY_ID},
                  "head_repository": {"id": control.github.REPOSITORY_ID}}
        rows = [{**common, "id": 102, "display_title": "Provider source seal 1001"},
                {**common, "id": 101, "display_title": "Provider source seal 1000", "status": "completed", "conclusion": "failure"}]
        record = {"sealRunId": "101", "controllerRevision": revision}
        with patch.dict(os.environ, {"GITHUB_RUN_ID": "102"}, clear=True), \
                patch.object(control.github, "_github_token", return_value="synthetic"), \
                patch.object(control.github, "_get_json", return_value={"workflow_runs": rows, "total_count": 2}), \
                patch.object(durable, "verify_source_resolution") as verify:
            durable.seal_history("1001", {}, [revision], resolutions={"1000": record}, bucket={}, store=Mock())
            verify.assert_called_once()
            with self.assertRaises(control.ProviderError):
                durable.seal_history("1001", {"1000": {"runId": "101", "controllerRevision": revision}},
                                     [revision], resolutions={}, bucket={}, store=Mock())
            with self.assertRaises(control.ProviderError):
                durable.seal_history("1001", {"1000": {}}, [revision], resolutions={}, bucket={}, store=Mock())
            with self.assertRaises(control.ProviderError):
                durable.seal_history("1000", {}, [revision], resolutions={"1000": record}, bucket={}, store=Mock())

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
            (root / "source-transport.json").write_bytes(control.canonical({"version": 1, "mode": "actions", "origin": None}))
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
                (root / "source-transport.json").unlink()
                with self.assertRaises((OSError, control.ProviderError)):
                    durable.production_seal_action(True)
                store.put.assert_not_called()
                (root / "source-transport.json").write_bytes(control.canonical({"version": 1, "mode": "actions", "origin": None}))
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

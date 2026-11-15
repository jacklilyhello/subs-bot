"""Hosted-only synthetic archive tests. No external service or credential is used."""

from pathlib import Path
import sys
from unittest import TestCase
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import evidence_archive as archive
import prepare_isolation_artifact as artifact


class MemoryStore:
    prefix = archive.BASE + "100/1/"

    def __init__(self):
        self.objects, self.writes, self.events = {}, [], []
        self.fail, self.commit_then_fail, self.corrupt, self.private = False, False, False, True

    def verify(self):
        self.events.append("verify")
        archive.require(self.private)

    def read(self, key):
        self.events.append("read:" + key)
        return self.objects.get(key)

    def put(self, key, raw):
        self.events.append("put:" + key)
        self.writes.append(key)
        if self.fail:
            raise archive.ArchiveError(archive.ERROR)
        archive.require(key not in self.objects)
        self.objects[key] = b"conflicting bytes" if self.corrupt else raw
        if self.commit_then_fail:
            raise archive.ArchiveError(archive.ERROR)


def manifest(body=b"synthetic historical bytes"):
    key = archive.digest(body)
    return {"version": 1, "kind": "private-historical-release-evidence", "revision": archive.REVISION,
        "candidateJsonSha256": archive.CANDIDATE_JSON, "historicalStatusesUnchanged": True,
        "productionMutationPerformed": False, "rawLogsArchived": False,
        "entries": [{"label": "synthetic.zip", "sha256": key, "bytes": len(body)}]}, {key: body}


class EvidenceArchiveTests(TestCase):
    def test_collection_preserves_verified_deployment_job_identity(self):
        spec = archive.SOURCES[0]
        raw = b"synthetic original archive bytes"
        proof = {"revision": archive.REVISION}
        deployment = {"ciProof": proof, "migrationCount": 54, "jobLogSha256": "b" * 64}
        original = {"source": {"ciProof": proof}, "historicalIsolationDeployment": {**deployment, "jobId": "42"}}
        run = {"id": int(spec[0]), "run_attempt": 1, "path": spec[1], "head_sha": spec[2],
            "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "success",
            "workflow_id": 777, "repository": {"id": artifact.REPOSITORY_ID},
            "head_repository": {"id": artifact.REPOSITORY_ID}}
        projected = {"artifactId": archive.CANDIDATE_ID, "sha256": archive.digest(raw), "bytes": len(raw)}
        def read(path, _token):
            if path.endswith("/attempts/1"): return run
            if "/artifacts?" in path: return {"total_count": 1, "artifacts": [{}]}
            if "/jobs?" in path: return {"jobs": []}
            if path == "/issues/comments/6825266606":
                return {"id": 6825266606, "user": {"login": "jacklilyhello"},
                    "issue_url": artifact.API_ROOT + "/issues/253", "body": "Synthetic acceptance"}
            self.fail("Unexpected evidence source")
        with patch.object(archive, "SOURCES", (spec,)), patch.object(archive, "artifact_projection", return_value=projected), \
                patch.object(archive, "verified_candidate", return_value=original), \
                patch.object(archive.candidate, "deploy_job", return_value="42"), \
                patch.object(archive.candidate, "deployment_proofs", return_value=dict(deployment)):
            manifest_value, blobs = archive.collect("synthetic", read, lambda *_: raw, lambda *_: b"synthetic log")
        entry = next(item for item in manifest_value["entries"] if item["label"] == "deployment-proofs.json")
        self.assertEqual(archive.parse(blobs[entry["sha256"]]), original["historicalIsolationDeployment"])

    def test_failure_projection_never_exposes_error_bodies_paths_or_untrusted_statuses(self):
        archive.stage("artifact-download")
        error = archive.ArchiveError("synthetic Bearer secret and /private/sensitive/path", http_status=403)
        archive.stage("readback")
        self.assertEqual(archive.failure_projection(error),
            {"status": "Failed", "stage": "artifact-download", "httpStatus": 403})
        error.stage = "synthetic secret path"
        for status in (True, "403 synthetic secret", -1, 999, None):
            error.http_status = status
            self.assertEqual(archive.failure_projection(error), {"status": "Failed", "stage": "startup"})
        self.assertEqual(archive.failure_projection(RuntimeError("synthetic raw API body")),
            {"status": "Failed", "stage": "readback"})

    def test_preserves_failed_historical_status_and_rejects_changed_provenance(self):
        spec = archive.SOURCES[3]
        run = {"id": int(spec[0]), "run_attempt": 1, "path": spec[1], "head_sha": spec[2],
            "head_branch": "main", "event": "workflow_dispatch", "status": "completed", "conclusion": "failure",
            "workflow_id": 777, "repository": {"id": artifact.REPOSITORY_ID},
            "head_repository": {"id": artifact.REPOSITORY_ID}, "untrusted_extra": "never archive raw metadata"}
        result = archive.run_projection(run, spec)
        self.assertEqual(result["conclusion"], "failure")
        self.assertNotIn("untrusted_extra", result)
        for key, value in (("head_sha", archive.REVISION), ("run_attempt", 2), ("head_branch", "other"),
                           ("conclusion", "success"), ("path", ".github/workflows/other.yml"), ("status", "in_progress")):
            with self.subTest(key=key), self.assertRaises(archive.ArchiveError):
                archive.run_projection({**run, key: value}, spec)
        with self.assertRaises(archive.ArchiveError):
            archive.run_projection({**run, "head_repository": {"id": 7}}, spec)

    def test_candidate_original_artifact_and_digest_are_pinned(self):
        spec = archive.SOURCES[0]
        row = {"id": int(archive.CANDIDATE_ID), "expired": False, "size_in_bytes": 6508,
            "name": f"subs-bot-production-candidate-{archive.REVISION}-{spec[0]}-1",
            "digest": "sha256:" + archive.CANDIDATE_ZIP, "expires_at": "2026-11-19T13:35:36Z",
            "workflow_run": {"id": int(spec[0]), "repository_id": artifact.REPOSITORY_ID,
                "head_repository_id": artifact.REPOSITORY_ID, "head_branch": "main", "head_sha": archive.REVISION}}
        self.assertEqual(archive.artifact_projection(row, spec)["sha256"], archive.CANDIDATE_ZIP)
        for key, value in (("id", 1), ("digest", "sha256:" + "a" * 64), ("expired", True),
                           ("size_in_bytes", archive.MAX_BLOB + 1), ("name", "other")):
            with self.subTest(key=key), self.assertRaises(archive.ArchiveError):
                archive.artifact_projection({**row, key: value}, spec)
        with self.assertRaises(archive.ArchiveError):
            archive.verified_candidate(b"synthetic substitute is not the immutable candidate")

    def test_lifecycle_cannot_expire_any_overlapping_archive_objects(self):
        rule = {"id": "fixture", "enabled": True, "conditions": {"prefix": "maintenance/"},
            "deleteObjectsTransition": {"condition": {"type": "Age", "maxAge": 604800}}}
        for prefix in ("", "maintenance/", archive.BASE, archive.BASE + "100/1/blobs/a"):
            with self.subTest(prefix=prefix), self.assertRaises(archive.ArchiveError):
                archive.verify_lifecycle({"rules": [{**rule, "conditions": {"prefix": prefix}}]}, archive.BASE + "100/1/")
        archive.verify_lifecycle({"rules": [{**rule, "conditions": {"prefix": "temporary/"}}]}, archive.BASE)
        archive.verify_lifecycle({"rules": [{**rule, "enabled": False}]}, archive.BASE)
        archive.verify_lifecycle({"rules": [{"id": "abort", "enabled": True, "conditions": {"prefix": ""},
            "abortMultipartUploadsTransition": {"condition": {"type": "Age", "maxAge": 86400}}}]}, archive.BASE)
        for value in ({"rules": None}, {"rules": [{"enabled": True}]}, {"unknown": []}):
            with self.assertRaises(archive.ArchiveError):
                archive.verify_lifecycle(value, archive.BASE)

    def test_manifest_is_last_and_fresh_verification_reads_all_original_bytes(self):
        store = MemoryStore()
        value, blobs = manifest()
        checks = []
        result = archive.archive(store, value, blobs, lambda: checks.append("guard"))
        self.assertEqual(store.writes[-1], "manifest.json")
        self.assertEqual(result["status"], "Passed")
        self.assertEqual(result["blobCount"], 1)
        self.assertEqual(len(checks), 2)
        readback = archive.verify_archive(store, archive.digest(archive.canonical(value)))
        self.assertEqual(readback, result)
        count = len(store.writes)
        with self.assertRaises(archive.ArchiveError):
            archive.archive(store, value, blobs)
        self.assertEqual(len(store.writes), count, "existing manifests must not be replaced")
        key = next(iter(blobs))
        store.objects["blobs/" + key] = b"damaged"
        with self.assertRaises(archive.ArchiveError):
            archive.verify_archive(store, result["manifestSha256"])

    def test_conflicting_existing_blob_never_overwrites_or_commits_manifest(self):
        store = MemoryStore()
        value, blobs = manifest()
        key = "blobs/" + next(iter(blobs))
        store.objects[key] = b"prior conflicting bytes"
        with self.assertRaises(archive.ArchiveError):
            archive.archive(store, value, blobs)
        self.assertEqual(store.objects[key], b"prior conflicting bytes")
        self.assertEqual(store.writes, [])
        self.assertNotIn("manifest.json", store.objects)

    def test_unacknowledged_committed_put_reads_back_without_repeating_mutation(self):
        store = MemoryStore()
        store.commit_then_fail = True
        value, blobs = manifest()
        archive.archive(store, value, blobs)
        self.assertEqual(len(store.writes), 2)
        self.assertEqual(len(set(store.writes)), 2)

    def test_unconfirmed_or_corrupt_write_never_commits_manifest(self):
        for mode in ("fail", "corrupt"):
            store = MemoryStore()
            setattr(store, mode, True)
            value, blobs = manifest()
            with self.subTest(mode=mode), self.assertRaises(archive.ArchiveError):
                archive.archive(store, value, blobs)
            self.assertEqual(len(store.writes), 1)
            self.assertNotIn("manifest.json", store.objects)

    def test_privacy_and_current_main_guards_stop_before_writes(self):
        store = MemoryStore()
        value, blobs = manifest()
        store.private = False
        with self.assertRaises(archive.ArchiveError):
            archive.archive(store, value, blobs)
        self.assertEqual(store.writes, [])
        store.private = True
        def changed_main():
            raise artifact.ArtifactError("Current main changed")
        with self.assertRaises(artifact.ArtifactError):
            archive.archive(store, value, blobs, changed_main)
        self.assertEqual(store.writes, [])

    def test_store_rejects_foreign_account_and_path_injection_before_any_request(self):
        for target, prefix in (({"accountId": "a" * 32, "r2CreatedOn": "fixture", "namespace": "lilyya"}, archive.BASE + "1/1/"),
            ({"accountId": "a" * 32, "r2CreatedOn": "fixture", "namespace": "lilyya"}, archive.BASE + "../")):
            with self.assertRaises(archive.ArchiveError):
                archive.PrivateStore(target, "synthetic-token", prefix)
        store = object.__new__(archive.PrivateStore)
        store.prefix = archive.BASE + "1/1/"
        for path in ("../manifest.json", "blobs/" + "A" * 64, "other/data", "manifest.json?x=1", ""):
            with self.assertRaises(archive.ArchiveError):
                store.key(path)

    def test_independent_manifest_digest_is_required(self):
        store = MemoryStore()
        value, blobs = manifest()
        archive.archive(store, value, blobs)
        for expected in ("", "a" * 64, "A" * 64):
            with self.assertRaises(archive.ArchiveError):
                archive.verify_archive(store, expected)

"""Hosted-only synthetic archive tests. No external service or credential is used."""

from copy import deepcopy
import io
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit
from unittest import TestCase
from unittest.mock import patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import evidence_archive as archive
import prepare_isolation_artifact as artifact
from test_prepare_isolation_artifact import synthetic_release, zip_release


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


class LaterCandidateFixture:
    """Real bounded ZIPs and the same safe proof format as the hosted packager."""
    def __init__(self):
        self.revision = "a" * 40
        self.isolation, files = synthetic_release()
        self.ci_zip = zip_release(self.isolation, files)
        self.proof = {"revision": self.revision, "runId": "1234", "runAttempt": "2", "artifactId": "2345",
            "archiveSha256": archive.digest(self.ci_zip)}
        result = {"revision": self.revision, "deploymentId": "00000000-0000-4000-8000-000000000001",
            "versionId": "00000000-0000-4000-8000-000000000002", "previousVersionId": "00000000-0000-4000-8000-000000000003",
            "changed": True, "inlineSearchEnabled": False}
        self.raw_log = (b"2026-11-15T00:00:00Z ::add-mask::synthetic-private-log-sentinel\n"
            + b"2026-11-15T00:00:01Z " + archive.canonical(self.proof)
            + b"2026-11-15T00:00:02Z Verified 1 isolated D1 migration records.\n"
            + b"2026-11-15T00:00:03Z " + archive.canonical(result))
        self.deployment = archive.candidate.deployment_proofs(self.raw_log, self.proof) | {"jobId": "42"}
        paths = {"500": (archive.SOURCES[0][1], 600, "2", "workflow_dispatch"),
            "1234": (artifact.WORKFLOW_PATH, artifact.WORKFLOW_ID, "2", "push"),
            "300": (archive.candidate.DEPLOY_WORKFLOW, 400, "3", "workflow_dispatch")}
        self.runs, self.workflows = {}, {}
        for run, (path, workflow, attempt, event) in paths.items():
            self.runs[run] = {"id": int(run), "run_attempt": int(attempt), "workflow_id": workflow, "path": path,
                "head_branch": "main", "head_sha": self.revision, "event": event, "status": "completed", "conclusion": "success",
                "repository": {"id": artifact.REPOSITORY_ID}, "head_repository": {"id": artifact.REPOSITORY_ID}}
            self.workflows[path.rsplit("/", 1)[-1]] = {"id": workflow, "path": path}
        deploy_run = archive.candidate.run_metadata(self.runs["300"], "300", "3", self.revision, 400, archive.candidate.DEPLOY_WORKFLOW)
        self.value = archive.candidate.make_manifest(self.proof, self.isolation, self.deployment, deploy_run, {},
            source_kind="not-supplied", source_sha="")
        self.rows = {}
        self.ci_row = self.artifact_row("2345", "1234", "2", f"subs-bot-worker-{self.revision}-2", self.ci_zip)
        self.rows[self.ci_row["name"]] = self.ci_row
        self.refresh_package()
        self.requests, self.downloads = [], []

    def artifact_row(self, identity, run, attempt, name, raw):
        return {"id": int(identity), "name": name, "expired": False, "size_in_bytes": len(raw),
            "digest": "sha256:" + archive.digest(raw), "expires_at": "2026-11-22T00:00:00Z",
            "workflow_run": {"id": int(run), "repository_id": artifact.REPOSITORY_ID,
                "head_repository_id": artifact.REPOSITORY_ID, "head_branch": "main", "head_sha": self.revision}}

    def refresh_package(self):
        raw = archive.canonical(self.value)
        self.json_sha = archive.digest(raw)
        buffer = io.BytesIO()
        with ZipFile(buffer, "w") as file:
            file.writestr("candidate.json", raw)
            file.writestr("candidate.sha256", self.json_sha + "  candidate.json\n")
            file.writestr("review.md", "Synthetic later review package; readiness remains false.")
        self.package_zip = buffer.getvalue()
        self.package_row = self.artifact_row("501", "500", "2", f"subs-bot-production-candidate-{self.revision}-500-2", self.package_zip)
        self.rows[self.package_row["name"]] = self.package_row

    def get_json(self, path, _token):
        self.requests.append(path)
        url = urlsplit(path)
        if url.path.startswith("/actions/workflows/"):
            return self.workflows[url.path.rsplit("/", 1)[-1]]
        if url.path.endswith("/artifacts"):
            name, = parse_qs(url.query)["name"]
            return {"total_count": 1, "artifacts": [self.rows[name]]}
        if url.path.endswith("/jobs"):
            return {"total_count": 1, "jobs": [{"id": 42, "name": "deploy", "status": "completed", "conclusion": "success",
                "run_id": 300, "run_attempt": 3, "head_sha": self.revision, "steps": [
                    {"name": name, "status": "completed", "conclusion": "success"} for name in
                    ("Verify merged artifact provenance and digests", "Release the verified Worker or stage page jump closed")]}]}
        parts = url.path.split("/")
        if len(parts) == 6 and parts[1:3] == ["actions", "runs"] and parts[4] == "attempts":
            return self.runs[parts[3]]
        raise AssertionError("Unexpected request; historical evidence must not require current main")

    def download(self, identity, _token):
        self.downloads.append(identity)
        return {"501": self.package_zip, "2345": self.ci_zip}[identity]

    def collect(self):
        self.entries, self.blobs = [], {}
        def add(label, raw, **metadata):
            key = archive.digest(raw)
            self.blobs[key] = raw
            self.entries.append({"label": label, "sha256": key, "bytes": len(raw), **metadata})
        return archive.collect_additional("synthetic", "500", "2", self.json_sha, add, self.blobs,
            self.get_json, self.download, lambda *_: self.raw_log)


class EvidenceArchiveTests(TestCase):
    def test_later_candidate_preserves_exact_attempts_closed_provenance_and_no_raw_log(self):
        fixture = LaterCandidateFixture()
        record = fixture.collect()
        self.assertEqual(record["candidateRun"]["runAttempt"], "2")
        self.assertEqual(record["ciRun"]["runAttempt"], "2")
        self.assertEqual(record["deployRun"]["runAttempt"], "3")
        self.assertEqual(len(fixture.entries), 3)
        self.assertEqual(fixture.downloads, ["501", "2345"], "metadata recheck must not download unchanged archives again")
        self.assertNotIn("synthetic-private-log-sentinel", archive.canonical(record).decode())
        self.assertTrue(all(b"synthetic-private-log-sentinel" not in raw for raw in fixture.blobs.values()))
        summary = archive.verify_additional(record, fixture.blobs)
        self.assertEqual(summary["revision"], fixture.revision)
        self.assertEqual(summary["candidateJsonSha256"], fixture.json_sha)
        self.assertFalse(any("/git/ref/" in path for path in fixture.requests))

    def test_independent_later_candidate_readback_needs_only_durable_blobs(self):
        fixture = LaterCandidateFixture()
        record = fixture.collect()
        value, blobs = manifest()
        value["additionalCandidates"] = [record]
        value["entries"].extend(fixture.entries)
        blobs.update(fixture.blobs)
        store = MemoryStore()
        with patch.object(artifact, "_get_json", side_effect=AssertionError("No GitHub read during independent private verification")):
            result = archive.archive(store, value, blobs)
            self.assertEqual(archive.verify_archive(store, result["manifestSha256"]), result)
        self.assertEqual(result["historicalRevision"], archive.REVISION)
        self.assertEqual(result["additionalCandidates"][0]["revision"], fixture.revision)
        self.assertEqual(store.writes[-1], "manifest.json")

    def test_later_candidate_cannot_promote_readiness_or_substitute_migrations(self):
        for field, value in (("productionReady", True), ("productionMutationPerformed", True),
                             ("productionAuthorization", "granted"), ("migrations", [{"name": "0001_subscriptions.sql", "sha256": "f" * 64}])):
            fixture = LaterCandidateFixture()
            if field == "migrations":
                fixture.value["artifact"][field] = value
            else:
                fixture.value[field] = value
            fixture.refresh_package()
            with self.subTest(field=field), self.assertRaises((archive.ArchiveError, artifact.ArtifactError)):
                fixture.collect()

    def test_later_candidate_rejects_wrong_attempt_fork_expiry_or_artifact_digest(self):
        for case in ("attempt", "fork", "expired", "digest"):
            fixture = LaterCandidateFixture()
            if case == "attempt": fixture.runs["500"]["run_attempt"] = 1
            if case == "fork": fixture.runs["1234"]["head_repository"]["id"] = 7
            if case == "expired": fixture.package_row["expired"] = True
            if case == "digest": fixture.ci_row["digest"] = "sha256:" + "f" * 64
            with self.subTest(case=case), self.assertRaises((archive.ArchiveError, artifact.ArtifactError)):
                fixture.collect()

    def test_later_candidate_must_match_fresh_deployment_proof(self):
        fixture = LaterCandidateFixture()
        fixture.raw_log = fixture.raw_log.replace(b'"changed":true', b'"changed":false')
        with self.assertRaises((archive.ArchiveError, artifact.ArtifactError)):
            fixture.collect()

    def test_later_candidate_offline_verification_rejects_broken_linkage_and_blobs(self):
        fixture = LaterCandidateFixture()
        record = fixture.collect()
        for case in ("ci-id", "deployment-blob", "revision", "candidate-json-sha"):
            changed, blobs = deepcopy(record), dict(fixture.blobs)
            if case == "ci-id": changed["ciArtifact"]["artifactId"] = "999"
            if case == "deployment-blob": blobs.pop(changed["deploymentProofSha256"])
            if case == "revision": changed["deployRun"]["revision"] = "f" * 40
            if case == "candidate-json-sha": changed["candidateJsonSha256"] = "f" * 64
            with self.subTest(case=case), self.assertRaises((archive.ArchiveError, artifact.ArtifactError)):
                archive.verify_additional(changed, blobs)

    def test_invalid_later_candidate_is_rejected_before_any_archive_write(self):
        fixture = LaterCandidateFixture()
        record = fixture.collect()
        record["candidateJsonSha256"] = "f" * 64
        value, blobs = manifest()
        value["additionalCandidates"] = [record]
        value["entries"].extend(fixture.entries)
        blobs.update(fixture.blobs)
        store = MemoryStore()
        with self.assertRaises(archive.ArchiveError):
            archive.archive(store, value, blobs)
        self.assertEqual(store.writes, [])

    def test_optional_candidate_run_and_digest_must_be_supplied_together_before_reads(self):
        for values in ({"current_candidate_run_id": "500"}, {"candidate_json_sha256": "a" * 64},
                       {"current_candidate_run_id": "../500", "candidate_json_sha256": "a" * 64}):
            with self.subTest(values=values), self.assertRaises(archive.ArchiveError):
                archive.collect("synthetic", lambda *_: self.fail("Invalid inputs must stop before reads"), **values)

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

    def test_observed_prefixless_abort_rule_is_safe_but_prefixless_object_expiry_blocks(self):
        observed = {"id": "default-abort", "enabled": True, "conditions": {},
            "abortMultipartUploadsTransition": {"condition": {"type": "Age", "maxAge": 604800}}}
        archive.verify_lifecycle({"rules": [observed]}, archive.BASE)
        for conditions in ({}, {"prefix": ""}):
            with self.subTest(conditions=conditions), self.assertRaises(archive.ArchiveError):
                archive.verify_lifecycle({"rules": [{**observed, "conditions": conditions,
                    "deleteObjectsTransition": {"condition": {"type": "Age", "maxAge": 604800}}}]}, archive.BASE)
        with self.assertRaises(archive.ArchiveError):
            archive.verify_lifecycle({"rules": [{**observed, "conditions": {"prefix": None}}]}, archive.BASE)

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

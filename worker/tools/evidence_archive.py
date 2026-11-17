"""Preserve the reviewed 5752 handoff and an optional later candidate in private R2.

Only the protected hosted workflow may write. Historical conclusions and ZIP
bytes remain unchanged. Raw job logs and signed download URLs are never stored.
"""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPSConnection, HTTPException
import io
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import ZipFile

import prepare_isolation_artifact as artifact
import production_candidate as candidate
from cloudflare_isolation import API_ORIGIN, CloudflareClient, CloudflareError, WORKER_NAME, _NoRedirect
from native_restore_rehearsal import ACCOUNT_SHA256, signed_put_headers
import scoped_r2

ERROR = "Private release evidence could not be verified; preserve existing objects and investigate."
WORKFLOW = artifact.REPOSITORY + "/.github/workflows/worker-evidence-archive.yml@refs/heads/main"
REVISION = "5752d09d9d205fe9ebcae2eea0b1f4f700d9701e"
BASE = "maintenance/release-evidence/" + REVISION + "/"
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
DIGEST = re.compile(r"[0-9a-f]{64}")
MAX_BLOB = 16 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
SOURCES = (
    ("43228751749", ".github/workflows/worker-production-candidate.yml", REVISION, "success", 1),
    ("43226934772", ".github/workflows/worker-ci.yml", REVISION, "success", 14),
    ("43228139603", ".github/workflows/worker-isolation-deploy.yml", REVISION, "success", 0),
    ("43215885724", ".github/workflows/worker-isolation-shortlink-fault-drill.yml", "d0988ce0a2942a5737c57a50c7f04850e9d69b85", "failure", 2),
    ("43219276895", ".github/workflows/worker-isolation-shortlink-fault-drill.yml", "2d52d15cb05fa5c63cb290b7e36cf29bf12ff95a", "success", 1),
)
CANDIDATE_ID = "13947584493"
CANDIDATE_ZIP = "871212c9a3d20db402dc64269fc26ea03c732cf1712c1319b9fc2682d7e5c23f"
CANDIDATE_JSON = "07d8bc9109f49ac0baa1bebc1d54c2b2ae6773f8d0d0bc8ef4ee443daef5ddd6"
RECOVERY_PINS = {
    "13943986513": "1237dce961bfc9751432f3b05311af3b751ceae4affdec8dd7b9b5a5e7f2053a",
    "13943856356": "f6cded37441a5ef984a1e46d509ef3aa779108f009061f2bc69135c55f79905e",
    "13945960103": "567ac686abe8be1740886711c28b9d839539ec1238835438ceab3d4f3af66f45",
}
STAGES = frozenset({"startup", "runtime-guard", "collect-run", "artifact-list", "artifact-download", "candidate-verify",
    "additional-candidate", "ci-proof",
    "deployment-proof", "public-comment", "store-private", "lifecycle", "put", "readback", "manifest", "complete"})
_STAGE = "startup"


class ArchiveError(ValueError):
    def __init__(self, message=ERROR, *, http_status=None):
        super().__init__(message)
        self.stage = _STAGE
        self.http_status = http_status


def stage(value):
    global _STAGE
    if value not in STAGES:
        raise ArchiveError()
    _STAGE = value


def failure_projection(error):
    """Only an enumerated boundary and a validated numeric status may escape."""
    value = getattr(error, "stage", _STAGE)
    result = {"status": "Failed", "stage": value if isinstance(value, str) and value in STAGES else "startup"}
    status = getattr(error, "http_status", None)
    if status is None and isinstance(error, HTTPError):
        status = error.code
    if type(status) is int and 100 <= status <= 599:
        result["httpStatus"] = status
    return result


def require(value):
    if not value:
        raise ArchiveError(ERROR)


def digest(raw):
    return sha256(raw).hexdigest()


def canonical(value):
    return candidate.canonical(value)


def parse(raw):
    require(isinstance(raw, bytes) and len(raw) <= MAX_BLOB)
    return json.loads(raw, object_pairs_hook=artifact._unique_json_object,
                      parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))


def run_projection(raw, spec, attempt="1"):
    run, path, revision, conclusion, _ = spec
    require(isinstance(attempt, str) and DECIMAL.fullmatch(attempt)
        and isinstance(raw, dict) and str(raw.get("id")) == run and type(raw.get("run_attempt")) is int
        and str(raw["run_attempt"]) == attempt
        and raw.get("path") in (path, path + "@main", path + "@refs/heads/main")
        and raw.get("head_branch") == "main" and raw.get("head_sha") == revision
        and raw.get("status") == "completed" and raw.get("conclusion") == conclusion
        and raw.get("event") in ("push", "workflow_dispatch")
        and type(raw.get("workflow_id")) is int
        and all(isinstance(raw.get(key), dict) and raw[key].get("id") == artifact.REPOSITORY_ID
                for key in ("repository", "head_repository")))
    return {"runId": run, "runAttempt": attempt, "revision": revision, "workflow": path,
            "workflowId": raw["workflow_id"], "event": raw["event"], "status": "completed", "conclusion": conclusion}


def artifact_projection(raw, spec):
    run, _, revision, _, _ = spec
    require(isinstance(raw, dict) and raw.get("expired") is False
        and type(raw.get("id")) is int and DECIMAL.fullmatch(str(raw["id"]))
        and type(raw.get("size_in_bytes")) is int and 0 < raw["size_in_bytes"] <= MAX_BLOB
        and isinstance(raw.get("digest"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", raw["digest"]))
    source = raw.get("workflow_run")
    require(isinstance(source, dict) and str(source.get("id")) == run
        and source.get("repository_id") == source.get("head_repository_id") == artifact.REPOSITORY_ID
        and source.get("head_branch") == "main" and source.get("head_sha") == revision)
    name = raw.get("name")
    require(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_-]{1,200}", name))
    if run == SOURCES[0][0]:
        require(str(raw["id"]) == CANDIDATE_ID and raw["digest"] == "sha256:" + CANDIDATE_ZIP
            and name == f"subs-bot-production-candidate-{REVISION}-{run}-1")
    elif run == SOURCES[1][0]:
        require(name.startswith("subs-bot-") and (name.endswith("-" + REVISION + "-1")
                or name == "subs-bot-unicode14-lower-" + REVISION))
    else:
        require(str(raw["id"]) in RECOVERY_PINS and raw["digest"] == "sha256:" + RECOVERY_PINS[str(raw["id"])]
            and name in (f"subs-bot-shortlink-fault-result-{run}-1", f"subs-bot-shortlink-fault-recovery-{run}-1"))
    return {"artifactId": str(raw["id"]), "name": name, "sha256": raw["digest"][7:], "bytes": raw["size_in_bytes"],
            "sourceRunId": run, "sourceRunAttempt": "1", "sourceRevision": revision,
            "sourceExpiresAt": raw.get("expires_at")}


def verified_candidate(raw):
    require(digest(raw) == CANDIDATE_ZIP)
    with ZipFile(io.BytesIO(raw)) as archive:
        members = artifact._zip_members(archive)
        require(set(members) == {"candidate.json", "candidate.sha256", "review.md"})
        body = archive.read(members["candidate.json"])
        require(digest(body) == CANDIDATE_JSON
            and archive.read(members["candidate.sha256"]) == (CANDIDATE_JSON + "  candidate.json\n").encode("ascii"))
    value = parse(body)
    require(value.get("productionReady") is False and value.get("productionMutationPerformed") is False
        and value.get("source", {}).get("revision") == REVISION
        and value.get("dataSource", {}).get("kind") == "not-supplied")
    return value


def additional_candidate(raw, expected):
    """Verify a bounded later candidate without promoting its immutable Not run fields."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BLOB
        and isinstance(expected, str) and DIGEST.fullmatch(expected))
    marker = (expected + "  candidate.json\n").encode("ascii")
    with ZipFile(io.BytesIO(raw)) as archive:
        members = artifact._zip_members(archive)
        require(set(members) == {"candidate.json", "candidate.sha256", "review.md"}
            and members["candidate.json"].file_size <= 65536 and members["review.md"].file_size <= 65536
            and members["candidate.sha256"].file_size == len(marker))
        body = archive.read(members["candidate.json"])
        require(digest(body) == expected
            and archive.read(members["candidate.sha256"]) == marker)
    value = parse(body)
    require(isinstance(value, dict) and value.get("version") == 1
        and value.get("kind") == "production-candidate-review-only"
        and value.get("productionReady") is False and value.get("productionMutationPerformed") is False
        and value.get("productionAuthorization") == "not-granted")
    data = value.get("dataSource")
    require(isinstance(data, dict) and data.get("kind") in ("not-supplied", "synthetic-fixture")
        and data.get("realDataImportAuthorized") is False and data.get("emptyDatabaseApproved") is False
        and data.get("discardLegacyLinksApproved") is False)
    return value


def ci_archive(raw, proof):
    """Recheck every bounded original CI member in memory; never execute or extract it."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BLOB and digest(raw) == proof["archiveSha256"])
    with ZipFile(io.BytesIO(raw)) as archive:
        members = artifact._zip_members(archive)
        require("isolation.json" in members and members["isolation.json"].file_size <= artifact._MAX_JSON)
        isolation = parse(archive.read(members["isolation.json"]))
        require(isinstance(isolation, dict))
        hashes, sizes = artifact._expected_hashes(isolation, proof["revision"], proof["runId"], proof["runAttempt"])
        require(set(members) == set(hashes) | {"isolation.json"}
            and 0 < members["index.js"].file_size <= artifact.MAX_MODULE_BYTES)
        for name, expected in hashes.items():
            body = archive.read(members[name])
            require(digest(body) == expected and (name not in sizes or len(body) == sizes[name]))
    return isolation


def additional_artifact(raw, run, attempt, revision, name):
    require(isinstance(raw, dict) and raw.get("name") == name and raw.get("expired") is False
        and type(raw.get("id")) is int and DECIMAL.fullmatch(str(raw["id"]))
        and type(raw.get("size_in_bytes")) is int and 0 < raw["size_in_bytes"] <= MAX_BLOB
        and isinstance(raw.get("digest"), str) and re.fullmatch(r"sha256:[0-9a-f]{64}", raw["digest"])
        and isinstance(raw.get("expires_at"), str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z", raw["expires_at"]))
    source = raw.get("workflow_run")
    require(isinstance(source, dict) and str(source.get("id")) == run
        and source.get("repository_id") == source.get("head_repository_id") == artifact.REPOSITORY_ID
        and source.get("head_branch") == "main" and source.get("head_sha") == revision)
    return {"artifactId": str(raw["id"]), "name": name, "sha256": raw["digest"][7:], "bytes": raw["size_in_bytes"],
        "sourceRunId": run, "sourceRunAttempt": attempt, "sourceRevision": revision, "sourceExpiresAt": raw["expires_at"]}


def _record_run(value, workflow):
    require(isinstance(value, dict) and set(value) == {"runId", "runAttempt", "revision", "workflow", "workflowId", "event", "status", "conclusion"}
        and all(isinstance(value.get(key), str) and DECIMAL.fullmatch(value[key]) for key in ("runId", "runAttempt"))
        and isinstance(value.get("revision"), str) and artifact._REVISION.fullmatch(value["revision"])
        and value["workflow"] == workflow and type(value["workflowId"]) is int and value["workflowId"] > 0
        and value["status"] == "completed" and value["conclusion"] == "success"
        and value["event"] in (("push", "workflow_dispatch") if workflow == artifact.WORKFLOW_PATH else ("workflow_dispatch",)))
    if workflow == artifact.WORKFLOW_PATH:
        require(value["workflowId"] == artifact.WORKFLOW_ID)


def _record_artifact(value, run, expected_name, blobs):
    require(isinstance(value, dict) and set(value) == {"artifactId", "name", "sha256", "bytes", "sourceRunId", "sourceRunAttempt", "sourceRevision", "sourceExpiresAt"}
        and isinstance(value["artifactId"], str) and DECIMAL.fullmatch(value["artifactId"])
        and value["name"] == expected_name and isinstance(value["sha256"], str) and DIGEST.fullmatch(value["sha256"])
        and type(value["bytes"]) is int and 0 < value["bytes"] <= MAX_BLOB
        and isinstance(value["sourceExpiresAt"], str)
        and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z", value["sourceExpiresAt"])
        and (value["sourceRunId"], value["sourceRunAttempt"], value["sourceRevision"])
            == (run["runId"], run["runAttempt"], run["revision"]))
    raw = blobs.get(value["sha256"])
    require(raw is not None and len(raw) == value["bytes"] and digest(raw) == value["sha256"])
    return raw


def verify_additional(record, blobs):
    """Rebuild the closed candidate/CI/deployment linkage from durable archive bytes."""
    require(isinstance(record, dict) and set(record) == {"candidateRun", "candidateArtifact", "candidateJsonSha256",
        "ciRun", "ciArtifact", "deployRun", "deploymentProofSha256"})
    package_run, ci_run, deploy_run = (record[key] for key in ("candidateRun", "ciRun", "deployRun"))
    _record_run(package_run, SOURCES[0][1])
    _record_run(ci_run, artifact.WORKFLOW_PATH)
    _record_run(deploy_run, candidate.DEPLOY_WORKFLOW)
    revision = package_run["revision"]
    require(ci_run["revision"] == deploy_run["revision"] == revision)
    package = _record_artifact(record["candidateArtifact"], package_run,
        f"subs-bot-production-candidate-{revision}-{package_run['runId']}-{package_run['runAttempt']}", blobs)
    value = additional_candidate(package, record["candidateJsonSha256"])
    raw_ci = _record_artifact(record["ciArtifact"], ci_run,
        f"subs-bot-worker-{revision}-{ci_run['runAttempt']}", blobs)
    expected_proof = {"revision": revision, "runId": ci_run["runId"], "runAttempt": ci_run["runAttempt"],
        "artifactId": record["ciArtifact"]["artifactId"], "archiveSha256": record["ciArtifact"]["sha256"]}
    source = value.get("source")
    require(isinstance(source, dict) and source.get("revision") == revision and source.get("ciProof") == expected_proof)
    expected_deploy = {key: deploy_run[key] for key in ("runId", "runAttempt", "revision", "workflow", "conclusion")}
    expected_deploy["url"] = f"https://github.com/{artifact.REPOSITORY}/actions/runs/{deploy_run['runId']}/attempts/{deploy_run['runAttempt']}"
    require(source.get("deployRun") == expected_deploy)
    isolation = ci_archive(raw_ci, expected_proof)
    require(isinstance(value.get("artifact"), dict) and type(value["artifact"].get("migrationCount")) is int
        and value["artifact"] == {"moduleSha256": isolation["bundleSha256"], "compatibilityDate": isolation["compatibilityDate"],
        "migrations": [{key: item[key] for key in ("name", "sha256")} for item in isolation["migrations"]],
        "migrationCount": len(isolation["migrations"])})
    proof_sha = record["deploymentProofSha256"]
    require(isinstance(proof_sha, str) and DIGEST.fullmatch(proof_sha) and proof_sha in blobs)
    deployment = parse(blobs[proof_sha])
    require(isinstance(deployment, dict) and deployment == value.get("historicalIsolationDeployment")
        and set(deployment) == {"ciProof", "release", "migrationCount", "jobLogSha256", "basis", "liveReadback", "jobId"}
        and deployment["ciProof"] == expected_proof and type(deployment["migrationCount"]) is int
        and deployment["migrationCount"] == len(isolation["migrations"])
        and deployment["basis"] == "historical-protected-workflow-log" and deployment["liveReadback"] is False
        and isinstance(deployment["jobLogSha256"], str) and DIGEST.fullmatch(deployment["jobLogSha256"])
        and isinstance(deployment["jobId"], str) and DECIMAL.fullmatch(deployment["jobId"]))
    release = deployment["release"]
    require(isinstance(release, dict) and candidate.RESULT_KEYS | {"flags"} <= set(release)
        and set(release) <= candidate.RESULT_KEYS | {"flags", "serviceMetadata"}
        and release["revision"] == revision and type(release["changed"]) is bool
        and all(isinstance(release.get(key), str) and candidate.UUID.fullmatch(release[key])
                for key in ("deploymentId", "versionId", "previousVersionId"))
        and isinstance(release["flags"], dict) and release["flags"]
        and all(candidate.FLAG.fullmatch(key) and type(value) is bool for key, value in release["flags"].items())
        and ("serviceMetadata" not in release or release["serviceMetadata"] == candidate.SERVICE_METADATA))
    return {"revision": revision, "candidateRunId": package_run["runId"], "candidateRunAttempt": package_run["runAttempt"],
        "candidateJsonSha256": record["candidateJsonSha256"], "sourceCiRunId": ci_run["runId"],
        "sourceCiRunAttempt": ci_run["runAttempt"], "deployRunId": deploy_run["runId"], "deployRunAttempt": deploy_run["runAttempt"]}


def collect_additional(token, run, attempt, expected_json, add, blobs, get_json, download, log):
    stage("additional-candidate")
    require(all(isinstance(value, str) and DECIMAL.fullmatch(value) for value in (run, attempt))
        and isinstance(expected_json, str) and DIGEST.fullmatch(expected_json))

    def read_run(run_id, run_attempt, path, revision=None):
        workflow = get_json("/actions/workflows/" + path.rsplit("/", 1)[-1], token)
        require(isinstance(workflow, dict) and type(workflow.get("id")) is int and workflow.get("path") == path)
        raw = get_json(f"/actions/runs/{run_id}/attempts/{run_attempt}", token)
        sha = raw.get("head_sha") if isinstance(raw, dict) else None
        require(isinstance(sha, str) and artifact._REVISION.fullmatch(sha) and (revision is None or sha == revision))
        projected = run_projection(raw, (run_id, path, sha, "success", 0), run_attempt)
        require(projected["workflowId"] == workflow["id"])
        _record_run(projected, path)
        return projected

    def read_artifact(source_run, name, *, metadata_only=False):
        listing = get_json(f"/actions/runs/{source_run['runId']}/artifacts?name={quote(name, safe='')}&per_page=2", token)
        require(isinstance(listing, dict) and listing.get("total_count") == 1
            and isinstance(listing.get("artifacts"), list) and len(listing["artifacts"]) == 1)
        projected = additional_artifact(listing["artifacts"][0], source_run["runId"], source_run["runAttempt"], source_run["revision"], name)
        if metadata_only:
            return projected
        raw = download(projected["artifactId"], token)
        require(len(raw) == projected["bytes"] and digest(raw) == projected["sha256"])
        return projected, raw

    package_run = read_run(run, attempt, SOURCES[0][1])
    revision = package_run["revision"]
    package_artifact, package_zip = read_artifact(package_run, f"subs-bot-production-candidate-{revision}-{run}-{attempt}")
    value = additional_candidate(package_zip, expected_json)
    source = value.get("source")
    require(isinstance(source, dict) and source.get("revision") == revision
        and isinstance(source.get("ciProof"), dict) and set(source["ciProof"]) == candidate.PROOF_KEYS
        and isinstance(source.get("deployRun"), dict))
    proof = source["ciProof"]
    require(proof.get("revision") == revision and all(isinstance(proof.get(key), str) and DECIMAL.fullmatch(proof[key])
        for key in ("runId", "runAttempt", "artifactId")) and isinstance(proof.get("archiveSha256"), str)
        and DIGEST.fullmatch(proof["archiveSha256"]))
    stage("ci-proof")
    ci_run = read_run(proof["runId"], proof["runAttempt"], artifact.WORKFLOW_PATH, revision)
    ci_artifact, ci_zip = read_artifact(ci_run, f"subs-bot-worker-{revision}-{ci_run['runAttempt']}")
    require(ci_artifact["artifactId"] == proof["artifactId"] and ci_artifact["sha256"] == proof["archiveSha256"])
    deploy = source["deployRun"]
    require(all(isinstance(deploy.get(key), str) and DECIMAL.fullmatch(deploy[key]) for key in ("runId", "runAttempt")))
    deploy_run = read_run(deploy["runId"], deploy["runAttempt"], candidate.DEPLOY_WORKFLOW, revision)
    stage("deployment-proof")
    job = candidate.deploy_job(get_json(f"/actions/runs/{deploy['runId']}/attempts/{deploy['runAttempt']}/jobs?per_page=100", token),
        deploy["runId"], deploy["runAttempt"], revision)
    projected = candidate.deployment_proofs(log(job, token), proof)
    projected["jobId"] = job
    require(projected == value.get("historicalIsolationDeployment"))
    add(f"candidate-{run}-{attempt}.zip", package_zip, artifact=package_artifact)
    add(f"candidate-{run}-{attempt}-worker-ci.zip", ci_zip, artifact=ci_artifact)
    raw_proof = canonical(projected)
    add(f"candidate-{run}-{attempt}-deployment-proof.json", raw_proof)
    record = {"candidateRun": package_run, "candidateArtifact": package_artifact, "candidateJsonSha256": expected_json,
        "ciRun": ci_run, "ciArtifact": ci_artifact, "deployRun": deploy_run, "deploymentProofSha256": digest(raw_proof)}
    verify_additional(record, blobs)
    # Re-read exact historical attempts/artifacts after collection. They need not
    # still be main; only this archive writer is guarded against current main.
    for observed in (package_run, ci_run, deploy_run):
        require(read_run(observed["runId"], observed["runAttempt"], observed["workflow"], revision) == observed)
    require(read_artifact(package_run, package_artifact["name"], metadata_only=True) == package_artifact
        and read_artifact(ci_run, ci_artifact["name"], metadata_only=True) == ci_artifact)
    return record


def collect(token, get_json=artifact._get_json, download=artifact._download, log=candidate.download_job_log,
            *, current_candidate_run_id="", current_candidate_run_attempt="1", candidate_json_sha256=""):
    """Download exact historical originals; only safe projections of API metadata/logs survive."""
    require(bool(current_candidate_run_id) == bool(candidate_json_sha256))
    if current_candidate_run_id:
        require(all(isinstance(value, str) and DECIMAL.fullmatch(value)
            for value in (current_candidate_run_id, current_candidate_run_attempt))
            and isinstance(candidate_json_sha256, str) and DIGEST.fullmatch(candidate_json_sha256))
    blobs, entries, runs, original = {}, [], [], None

    def add(label, raw, **metadata):
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BLOB)
        key = digest(raw)
        blobs[key] = raw
        require(sum(map(len, blobs.values())) <= MAX_TOTAL)
        entries.append({"label": label, "sha256": key, "bytes": len(raw), **metadata})

    for spec in SOURCES:
        run = spec[0]
        stage("collect-run")
        metadata = run_projection(get_json(f"/actions/runs/{run}/attempts/1", token), spec)
        runs.append(metadata)
        add(f"run-{run}-1.json", canonical(metadata))
        if spec[4] == 0:
            continue
        stage("artifact-list")
        listing = get_json(f"/actions/runs/{run}/artifacts?per_page=100", token)
        require(isinstance(listing, dict) and listing.get("total_count") == spec[4]
            and isinstance(listing.get("artifacts"), list) and len(listing["artifacts"]) == spec[4])
        ids = set()
        for item in listing["artifacts"]:
            stage("artifact-list")
            projected = artifact_projection(item, spec)
            require(projected["artifactId"] not in ids)
            ids.add(projected["artifactId"])
            stage("artifact-download")
            raw = download(projected["artifactId"], token)
            require(len(raw) == projected["bytes"] and digest(raw) == projected["sha256"])
            if run == SOURCES[0][0]:
                stage("candidate-verify")
                original = verified_candidate(raw)
            add("github-artifact-" + projected["artifactId"] + ".zip", raw, artifact=projected)
    require(original is not None)
    stage("deployment-proof")
    proof = original["source"]["ciProof"]
    jobs = get_json("/actions/runs/43228139603/attempts/1/jobs?per_page=100", token)
    job = candidate.deploy_job(jobs, "43228139603", "1", REVISION)
    projected = candidate.deployment_proofs(log(job, token), proof)
    projected["jobId"] = job
    require(projected == original["historicalIsolationDeployment"])
    add("deployment-proofs.json", canonical(projected))
    stage("public-comment")
    comment = get_json("/issues/comments/6825266606", token)
    require(comment.get("id") == 6825266606 and comment.get("user", {}).get("login") == "jacklilyhello"
        and comment.get("issue_url") == artifact.API_ROOT + "/issues/253"
        and isinstance(comment.get("body"), str) and len(comment["body"].encode("utf-8")) <= 65536)
    add("pr253-acceptance-comment.json", canonical({key: comment.get(key) for key in
        ("id", "html_url", "created_at", "updated_at", "body")}))
    additional = []
    if current_candidate_run_id:
        additional.append(collect_additional(token, current_candidate_run_id, current_candidate_run_attempt,
            candidate_json_sha256, add, blobs, get_json, download, log))
    return {"version": 1, "kind": "private-historical-release-evidence", "revision": REVISION,
        "candidateJsonSha256": CANDIDATE_JSON, "historicalStatusesUnchanged": True,
        "productionMutationPerformed": False, "rawLogsArchived": False, "runs": runs, "entries": entries,
        **({"additionalCandidates": additional} if additional else {})}, blobs


def verify_lifecycle(value, prefix):
    require(isinstance(value, dict) and set(value) <= {"rules"} and isinstance(value.get("rules", []), list))
    for rule in value.get("rules", []):
        require(isinstance(rule, dict) and type(rule.get("enabled")) is bool
            and isinstance(rule.get("conditions"), dict) and isinstance(rule["conditions"].get("prefix", ""), str))
        # The observed default multipart-abort rule omits prefix entirely.
        # Treat omission conservatively as global scope: any object deletion
        # transition still overlaps and blocks archival; abort-only is safe.
        other = rule["conditions"].get("prefix", "")
        overlap = prefix.startswith(other) or other.startswith(prefix)
        require(not (rule["enabled"] and overlap and rule.get("deleteObjectsTransition") is not None))


class PrivateStore:
    """Only fixed project bucket reads and create-only S3 PUTs inside one archive prefix."""

    def __init__(self, target, token, prefix):
        require(isinstance(target, dict) and target.get("namespace") == "lilyya"
            and isinstance(target.get("accountId"), str) and re.fullmatch(r"[0-9a-f]{32}", target["accountId"])
            and digest(target["accountId"].encode("ascii")) == ACCOUNT_SHA256
            and isinstance(target.get("r2CreatedOn"), str)
            and re.fullmatch(re.escape(BASE) + r"[1-9][0-9]{0,19}/[1-9][0-9]{0,19}/", prefix))
        self.target, self.token, self.prefix = target, token, prefix
        self.root = "/accounts/" + target["accountId"]
        self.bucket = self.root + "/r2/buckets/" + WORKER_NAME
        metadata_token = os.environ.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", "")
        self.api = CloudflareClient(token or metadata_token)
        self.metadata_api = CloudflareClient(metadata_token) if metadata_token else self.api
        self.objects = scoped_r2.from_environment(target["accountId"], WORKER_NAME)
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())
        self.access_key = None

    def verify(self):
        stage("store-private")
        bucket = self.metadata_api("GET", self.bucket)
        require(isinstance(bucket, dict) and bucket.get("name") == WORKER_NAME
            and bucket.get("creation_date") == self.target["r2CreatedOn"] and bucket.get("jurisdiction") == "default")
        require(self.metadata_api("GET", self.bucket + "/domains/managed").get("enabled") is False
            and self.metadata_api("GET", self.bucket + "/domains/custom") in ([], {"domains": []}))
        stage("lifecycle")
        verify_lifecycle(self.metadata_api("GET", self.bucket + "/lifecycle"), self.prefix)

    def key(self, relative):
        require(relative == "manifest.json" or re.fullmatch(r"blobs/[0-9a-f]{64}", relative))
        return self.prefix + relative

    def read(self, relative):
        key = self.key(relative)
        if self.objects is not None:
            raw, _etag = self.objects.get(key, absent=True, limit=MAX_BLOB)
            return raw
        request = Request(API_ORIGIN + self.bucket + "/objects/" + quote(key, safe="/"), headers={
            "Authorization": "Bearer " + self.token, "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"})
        try:
            with self.opener.open(request, timeout=30) as response:
                return artifact._bounded_read(response, MAX_BLOB)
        except HTTPError as error:
            status = error.code
            error.close()
            if status == 404:
                return None
            raise ArchiveError(ERROR, http_status=status) from None
        except (OSError, HTTPException):
            raise ArchiveError(ERROR) from None

    def put(self, relative, raw):
        key = self.key(relative)
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BLOB)
        if self.objects is not None:
            self.objects.put_once(key, raw,
                metadata={"cache-control": "no-store, private", "content-type": "application/octet-stream"})
            return
        if self.access_key is None:
            # The protected environment uses a scoped user API token. This
            # read-only endpoint provides its R2 S3 access-key identity.
            result = self.api("GET", "/user/tokens/verify")
            require(isinstance(result, dict) and result.get("status") == "active"
                and isinstance(result.get("id"), str) and re.fullmatch(r"[0-9a-f]{32}", result["id"]))
            self.access_key = result["id"]
        host = self.target["accountId"] + ".r2.cloudflarestorage.com"
        path = "/" + WORKER_NAME + "/" + quote(key, safe="/-_.~")
        headers = signed_put_headers(host, path, self.access_key, self.token, raw,
            {"custom": {}, "http": {"cache-control": "no-store, private", "content-type": "application/octet-stream"}}, datetime.now(timezone.utc))
        try:
            with closing(HTTPSConnection(host, timeout=45)) as connection:
                connection.request("PUT", path, body=raw, headers=headers)
                with closing(connection.getresponse()) as response:
                    if response.status not in (200, 412):
                        raise ArchiveError(ERROR, http_status=response.status)
                    require(len(response.read(4097)) <= 4096)
        except (OSError, HTTPException):
            raise ArchiveError(ERROR) from None


def immutable_put(store, key, raw):
    phase = "manifest" if key == "manifest.json" else None
    stage(phase or "readback")
    current = store.read(key)
    if current is not None:
        require(current == raw)
        return
    try:
        stage(phase or "put")
        store.put(key, raw)
    except (ArchiveError, CloudflareError) as error:
        # Never repeat a mutation after an uncertain response; independent read is authoritative.
        stage(phase or "readback")
        if store.read(key) != raw:
            stage(phase or "put")
            raise ArchiveError(http_status=getattr(error, "http_status", None)) from None
        return
    stage(phase or "readback")
    require(store.read(key) == raw)


def archive(store, manifest, blobs, guard=lambda: None):
    store.verify()
    raw = canonical(manifest)
    stage("manifest")
    require(store.read("manifest.json") is None)
    require({entry["sha256"] for entry in manifest["entries"]} == set(blobs))
    additional = manifest.get("additionalCandidates", [])
    require(isinstance(additional, list) and len(additional) <= 1)
    for record in additional:
        verify_additional(record, blobs)
    for key, body in sorted(blobs.items()):
        require(DIGEST.fullmatch(key) and digest(body) == key)
        guard()
        immutable_put(store, "blobs/" + key, body)
    store.verify()
    stage("manifest")
    guard()
    immutable_put(store, "manifest.json", raw)
    return verify_archive(store, digest(raw))


def verify_archive(store, expected):
    store.verify()
    stage("manifest")
    require(isinstance(expected, str) and DIGEST.fullmatch(expected))
    raw = store.read("manifest.json")
    require(raw is not None and digest(raw) == expected)
    value = parse(raw)
    require(value.get("version") == 1 and value.get("kind") == "private-historical-release-evidence"
        and value.get("revision") == REVISION and value.get("productionMutationPerformed") is False
        and value.get("historicalStatusesUnchanged") is True and value.get("rawLogsArchived") is False
        and value.get("candidateJsonSha256") == CANDIDATE_JSON
        and isinstance(value.get("entries"), list) and 1 <= len(value["entries"]) <= 100)
    total, seen, blobs = 0, set(), {}
    for entry in value["entries"]:
        stage("readback")
        require(isinstance(entry, dict) and isinstance(entry.get("sha256"), str) and DIGEST.fullmatch(entry["sha256"])
            and type(entry.get("bytes")) is int and 0 < entry["bytes"] <= MAX_BLOB)
        body = store.read("blobs/" + entry["sha256"])
        require(body is not None and len(body) == entry["bytes"] and digest(body) == entry["sha256"])
        if entry["sha256"] not in seen:
            total += len(body)
            seen.add(entry["sha256"])
        require(total <= MAX_TOTAL)
        blobs[entry["sha256"]] = body
    additional = value.get("additionalCandidates", [])
    require(isinstance(additional, list) and len(additional) <= 1)
    summaries = [verify_additional(record, blobs) for record in additional]
    stage("complete")
    return {"status": "Passed", "archivePrefix": store.prefix, "manifestSha256": expected,
        "blobCount": len(seen), "bytes": total, "historicalRevision": REVISION,
        "productionMutationPerformed": False, "historicalStatusesUnchanged": True, "rawLogsArchived": False,
        **({"additionalCandidates": summaries} if summaries else {})}


def main():
    env = os.environ
    stage("runtime-guard")
    require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY)
    action = env.get("EVIDENCE_ACTION")
    require(action in ("archive", "verify"))
    run = env.get("GITHUB_RUN_ID", "") if action == "archive" else env.get("EVIDENCE_ARCHIVE_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT", "") if action == "archive" else env.get("EVIDENCE_ARCHIVE_RUN_ATTEMPT", "")
    require(DECIMAL.fullmatch(run) and DECIMAL.fullmatch(attempt))
    store = PrivateStore(json.loads(env["SUBS_BOT_CF_ISOLATION_TARGET_JSON"]), env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], BASE + run + "/" + attempt + "/")
    if action == "archive":
        require(env.get("EVIDENCE_CONFIRMATION") == "preserve original subs-bot 5752 release evidence")
        guard = lambda: artifact.require_current_main(env["GITHUB_SHA"])
        guard()
        manifest, blobs = collect(artifact._github_token(),
            current_candidate_run_id=env.get("EVIDENCE_CURRENT_CANDIDATE_RUN_ID", ""),
            current_candidate_run_attempt=env.get("EVIDENCE_CURRENT_CANDIDATE_RUN_ATTEMPT", "1"),
            candidate_json_sha256=env.get("EVIDENCE_CANDIDATE_JSON_SHA256", ""))
        manifest["archiveWriter"] = {"revision": env["GITHUB_SHA"], "runId": run, "runAttempt": attempt}
        result = archive(store, manifest, blobs, guard)
    else:
        result = verify_archive(store, env.get("EVIDENCE_MANIFEST_SHA256", ""))
    print(canonical(result).decode("ascii"))
    summary = env.get("GITHUB_STEP_SUMMARY")
    if summary:
        with Path(summary).open("a", encoding="utf-8") as file:
            file.write("Private release evidence verified. No original statuses changed; no production operation.\n\n```json\n"
                + json.dumps(result, indent=2) + "\n```\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        sys.exit(ERROR + " " + json.dumps(failure_projection(error), sort_keys=True, separators=(",", ":")))

"""Preserve the reviewed 5752 handoff in private, immutable R2 objects.

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


def run_projection(raw, spec):
    run, path, revision, conclusion, _ = spec
    require(isinstance(raw, dict) and str(raw.get("id")) == run and raw.get("run_attempt") == 1
        and raw.get("path") in (path, path + "@main", path + "@refs/heads/main")
        and raw.get("head_branch") == "main" and raw.get("head_sha") == revision
        and raw.get("status") == "completed" and raw.get("conclusion") == conclusion
        and raw.get("event") in ("push", "workflow_dispatch")
        and type(raw.get("workflow_id")) is int
        and all(isinstance(raw.get(key), dict) and raw[key].get("id") == artifact.REPOSITORY_ID
                for key in ("repository", "head_repository")))
    return {"runId": run, "runAttempt": "1", "revision": revision, "workflow": path,
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


def collect(token, get_json=artifact._get_json, download=artifact._download, log=candidate.download_job_log):
    """Download exact historical originals; only safe projections of API metadata/logs survive."""
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
    require(projected == original["historicalIsolationDeployment"])
    add("deployment-proofs.json", canonical(projected))
    stage("public-comment")
    comment = get_json("/issues/comments/6825266606", token)
    require(comment.get("id") == 6825266606 and comment.get("user", {}).get("login") == "jacklilyhello"
        and comment.get("issue_url") == artifact.API_ROOT + "/issues/253"
        and isinstance(comment.get("body"), str) and len(comment["body"].encode("utf-8")) <= 65536)
    add("pr253-acceptance-comment.json", canonical({key: comment.get(key) for key in
        ("id", "html_url", "created_at", "updated_at", "body")}))
    return {"version": 1, "kind": "private-historical-release-evidence", "revision": REVISION,
        "candidateJsonSha256": CANDIDATE_JSON, "historicalStatusesUnchanged": True,
        "productionMutationPerformed": False, "rawLogsArchived": False, "runs": runs, "entries": entries}, blobs


def verify_lifecycle(value, prefix):
    require(isinstance(value, dict) and set(value) <= {"rules"} and isinstance(value.get("rules", []), list))
    for rule in value.get("rules", []):
        require(isinstance(rule, dict) and type(rule.get("enabled")) is bool
            and isinstance(rule.get("conditions"), dict) and isinstance(rule["conditions"].get("prefix"), str))
        other = rule["conditions"]["prefix"]
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
        self.api = CloudflareClient(token)
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())
        self.access_key = None

    def verify(self):
        stage("store-private")
        bucket = self.api("GET", self.bucket)
        require(isinstance(bucket, dict) and bucket.get("name") == WORKER_NAME
            and bucket.get("creation_date") == self.target["r2CreatedOn"] and bucket.get("jurisdiction") == "default")
        require(self.api("GET", self.bucket + "/domains/managed").get("enabled") is False
            and self.api("GET", self.bucket + "/domains/custom") in ([], {"domains": []}))
        stage("lifecycle")
        verify_lifecycle(self.api("GET", self.bucket + "/lifecycle"), self.prefix)

    def key(self, relative):
        require(relative == "manifest.json" or re.fullmatch(r"blobs/[0-9a-f]{64}", relative))
        return self.prefix + relative

    def read(self, relative):
        key = self.key(relative)
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
    total, seen = 0, set()
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
    stage("complete")
    return {"status": "Passed", "archivePrefix": store.prefix, "manifestSha256": expected,
        "blobCount": len(seen), "bytes": total, "historicalRevision": REVISION,
        "productionMutationPerformed": False, "historicalStatusesUnchanged": True, "rawLogsArchived": False}


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
        manifest, blobs = collect(artifact._github_token())
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

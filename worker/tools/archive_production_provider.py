"""Seal provider source/proof bytes in project-private R2 and independently read them back."""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPSConnection, HTTPException
import json
import os
from pathlib import Path
import re
import shutil
import tempfile
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

from cloudflare_isolation import CloudflareClient, API_ORIGIN, _NoRedirect
from evidence_archive import verify_lifecycle
from native_restore_rehearsal import signed_put_headers
import production_provider as provider
import production_provider_rehearsal as rehearsal

CHUNK_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 600 * 1024 * 1024
MAX_CHUNKS = 128
BASE = "maintenance/production-provider/"
FILE_LIMITS = {"provider-rehearsal-proof.json": 65536, "provider-rehearsal-target.json": 65536,
               "provider-rehearsal-journal.json": 65536, "provider-source-archive.zip": provider.provenance.MAX_ZIP,
               "source/provider-worker.js": provider.provider.MAX_WORKER,
               "source/provider-release.json": provider.provider.MAX_METADATA,
               "source/provider-image.tar": provider.provider.MAX_IMAGE}
ERROR = "The private provider source/proof archive could not be verified safely."
PARTIAL_LIMITS = {**FILE_LIMITS, "provider-rehearsal-journal.json": rehearsal.MAX_CHECKPOINT,
                  rehearsal.CHECKPOINT: rehearsal.MAX_CHECKPOINT, "provider-rehearsal-attempt.json": rehearsal.MAX_CHECKPOINT}
MAX_PARTIAL_FILES = 128
MAX_PARTIAL_LOGICAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_PARTIAL_MANIFEST = 256 * 1024


def require(value):
    provider.require(value, ERROR)


class PrivateProofStore:
    """Exact existing project bucket and append-only prefix, never production bucket fallback."""

    def __init__(self, target, token, run_id, attempt):
        require(isinstance(target, dict) and target.get("accountId") == "9431815bdb8beb2272f6668e06b7d3be"
                and target.get("namespace") == "lilyya" and isinstance(target.get("r2CreatedOn"), str)
                and provider.match(provider.provider.DECIMAL, run_id) and provider.match(provider.provider.DECIMAL, attempt))
        self.target, self.token = target, token
        self.bucket = "subs-bot-cf-dev-01"
        self.run_id, self.attempt = run_id, attempt
        self.prefix = f"{BASE}{run_id}/{attempt}/"
        self.base = f"/accounts/{target['accountId']}/r2/buckets/{self.bucket}"
        self.api = CloudflareClient(token)
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())
        self.access_key = None

    def verify(self):
        bucket = self.api("GET", self.base)
        require(isinstance(bucket, dict) and bucket.get("name") == self.bucket
                and bucket.get("creation_date") == self.target["r2CreatedOn"] and bucket.get("jurisdiction") == "default")
        require(self.api("GET", self.base + "/domains/managed").get("enabled") is False
                and self.api("GET", self.base + "/domains/custom") in ([], {"domains": []}))
        verify_lifecycle(self.api("GET", self.base + "/lifecycle"), self.prefix)

    def key(self, relative):
        require(relative in {"manifest.json", "partial-manifest.json"} or re.fullmatch(r"blobs/[0-9a-f]{64}", relative))
        return self.prefix + relative

    def read(self, relative):
        request = Request(API_ORIGIN + self.base + "/objects/" + quote(self.key(relative), safe="/"), headers={
            "Authorization": "Bearer " + self.token, "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"})
        try:
            with self.opener.open(request, timeout=30) as response:
                require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
                raw = response.read(CHUNK_BYTES + 1)
                require(0 < len(raw) <= CHUNK_BYTES)
                return raw
        except HTTPError as error:
            code = error.code
            error.close()
            if code == 404:
                return None
            raise provider.ProviderError(ERROR) from None
        except (OSError, HTTPException):
            raise provider.ProviderError(ERROR) from None

    def put(self, relative, raw):
        require(isinstance(raw, bytes) and 0 < len(raw) <= CHUNK_BYTES)
        observed = self.read(relative)
        if observed is not None:
            require(observed == raw)
            return
        if self.access_key is None:
            identity = self.api("GET", "/user/tokens/verify")
            require(isinstance(identity, dict) and identity.get("status") == "active" and provider.match(provider.publication.ACCOUNT, identity.get("id")))
            self.access_key = identity["id"]
        host = self.target["accountId"] + ".r2.cloudflarestorage.com"
        path = "/" + self.bucket + "/" + quote(self.key(relative), safe="/-_.~")
        headers = signed_put_headers(host, path, self.access_key, self.token, raw,
                                    {"custom": {}, "http": {"cache-control": "no-store, private", "content-type": "application/octet-stream"}},
                                    datetime.now(timezone.utc))
        try:
            with closing(HTTPSConnection(host, timeout=45)) as connection:
                connection.request("PUT", path, body=raw, headers=headers)
                with closing(connection.getresponse()) as response:
                    require(response.status in (200, 412) and len(response.read(4097)) <= 4096)
        except (OSError, HTTPException):
            raise provider.ProviderError(ERROR) from None
        # A failed readback remains failure; the write is never attempted a second time.
        require(self.read(relative) == raw)


def verify_archive(store, expected_manifest):
    store.verify()
    raw = store.read("manifest.json")
    require(isinstance(raw, bytes) and sha256(raw).hexdigest() == expected_manifest and len(raw) <= 65536)
    manifest = provider.github._parse_object(raw, ERROR)
    require(set(manifest) == {"version", "kind", "controllerRevision", "runId", "runAttempt", "proofSha256", "files", "totalBytes"}
            and manifest["version"] == 1 and manifest["kind"] == "subs-bot-provider-source-proof"
            and provider.match(provider.provider.REVISION, manifest["controllerRevision"])
            and provider.match(provider.provider.HEX, manifest["proofSha256"])
            and manifest["runId"] == store.run_id and manifest["runAttempt"] == store.attempt
            and isinstance(manifest["files"], dict) and set(manifest["files"]) == set(FILE_LIMITS))
    require(manifest["files"]["provider-rehearsal-proof.json"].get("sha256") == manifest["proofSha256"])
    total, chunks = 0, 0
    for name, entry in manifest["files"].items():
        require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256", "chunks"}
                and type(entry["bytes"]) is int and 0 < entry["bytes"] <= FILE_LIMITS[name]
                and provider.match(provider.provider.HEX, entry["sha256"]) and isinstance(entry["chunks"], list))
        file_hash, size = sha256(), 0
        for chunk in entry["chunks"]:
            chunks += 1
            require(chunks <= MAX_CHUNKS and isinstance(chunk, dict) and set(chunk) == {"bytes", "sha256"}
                    and type(chunk["bytes"]) is int and 0 < chunk["bytes"] <= CHUNK_BYTES
                    and provider.match(provider.provider.HEX, chunk["sha256"]))
            require(size + chunk["bytes"] <= entry["bytes"])
            body = store.read("blobs/" + chunk["sha256"])
            require(isinstance(body, bytes) and len(body) == chunk["bytes"] and sha256(body).hexdigest() == chunk["sha256"])
            file_hash.update(body)
            size += len(body)
        require(size == entry["bytes"] and file_hash.hexdigest() == entry["sha256"])
        total += size
        require(total <= MAX_TOTAL_BYTES)
    require(total == manifest["totalBytes"])
    store.verify()
    return {"manifestSha256": expected_manifest, "prefix": store.prefix, "files": len(manifest["files"]),
            "chunks": chunks, "bytes": total, "proofSha256": manifest["proofSha256"], "readback": "R2-only-complete"}


def archive(store, directory):
    store.verify()
    require({str(path.relative_to(directory)) for path in directory.rglob("*") if path.is_file()} == set(FILE_LIMITS))
    for name, limit in FILE_LIMITS.items():
        provider.provider.checked_file(directory / name, limit)
    require(sum((directory / name).stat().st_size for name in FILE_LIMITS) <= MAX_TOTAL_BYTES)
    proof = provider.github._parse_object((directory / "provider-rehearsal-proof.json").read_bytes(), ERROR)
    require(proof.get("status") == "complete" and proof.get("productionMutation") is False)
    require(proof.get("runId") == store.run_id and proof.get("runAttempt") == store.attempt
            and provider.match(provider.provider.REVISION, proof.get("controllerRevision")))
    target = provider.validate_config(proof["target"])
    require(target["environment"] == "rehearsal" and target["caller"] is None)
    require(provider.github._parse_object((directory / "provider-rehearsal-target.json").read_bytes(), ERROR) == target)
    build = target["build"]
    expected = {"provider-source-archive.zip": build["archiveSha256"], "source/provider-worker.js": build["workerSha256"],
                "source/provider-image.tar": build["ociArchiveSha256"]}
    manifest = {"version": 1, "kind": "subs-bot-provider-source-proof", "controllerRevision": proof["controllerRevision"],
                "runId": proof["runId"], "runAttempt": proof["runAttempt"], "proofSha256": provider.digest(proof), "files": {}, "totalBytes": 0}
    count = 0
    for name, limit in FILE_LIMITS.items():
        path = provider.provider.checked_file(directory / name, limit)
        entries, hashed, size = [], sha256(), 0
        with path.open("rb") as source:
            while raw := source.read(CHUNK_BYTES):
                count += 1
                require(count <= MAX_CHUNKS)
                size += len(raw)
                hashed.update(raw)
                chunk_sha = sha256(raw).hexdigest()
                store.put("blobs/" + chunk_sha, raw)
                entries.append({"sha256": chunk_sha, "bytes": len(raw)})
        file_sha = hashed.hexdigest()
        require(name not in expected or file_sha == expected[name])
        manifest["files"][name] = {"bytes": size, "sha256": file_sha, "chunks": entries}
        manifest["totalBytes"] += size
        require(manifest["totalBytes"] <= MAX_TOTAL_BYTES)
    encoded = provider.canonical(manifest)
    require(len(encoded) <= 65536)
    store.put("manifest.json", encoded)
    return verify_archive(store, sha256(encoded).hexdigest())


def attempt_name(name, run_id, attempt):
    operations = "(?:create|publish|stage|activate|provision-container|provision-workflow|smoke)"
    return re.fullmatch(r"subs-bot-provider-attempt-(?:source|final|(?:intent|result)-" + operations + r")-"
                        + re.escape(run_id) + "-" + re.escape(attempt), name) is not None


def original_run(run_id, attempt):
    require(provider.match(provider.provider.DECIMAL, run_id) and provider.match(provider.provider.DECIMAL, attempt))
    token = provider.github._github_token()
    run = provider.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}", token)
    require(str(run.get("id")) == run_id and str(run.get("run_attempt")) == attempt
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and run.get("path") in {provider.REHEARSAL_WORKFLOW_PATH, provider.REHEARSAL_WORKFLOW_PATH + "@main",
                                    provider.REHEARSAL_WORKFLOW_PATH + "@refs/heads/main"}
            and all(isinstance(run.get(key), dict) and run[key].get("id") == provider.github.REPOSITORY_ID
                    for key in ("repository", "head_repository"))
            and provider.match(provider.provider.REVISION, run.get("head_sha")))
    current = os.environ["GITHUB_SHA"]
    if run["head_sha"] != current:
        comparison = provider.github._get_json(f"/compare/{run['head_sha']}...{current}?per_page=1", token)
        require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                and all(isinstance(comparison.get(key), dict) and comparison[key].get("sha") == run["head_sha"]
                        for key in ("base_commit", "merge_base_commit")))
    listing = provider.github._get_json(f"/actions/runs/{run_id}/artifacts?per_page=100", token)
    rows = listing.get("artifacts")
    require(isinstance(rows, list) and type(listing.get("total_count")) is int
            and listing["total_count"] == len(rows) and len(rows) <= 100)
    selected = {}
    for row in rows:
        name = row.get("name") if isinstance(row, dict) else None
        if isinstance(name, str) and attempt_name(name, run_id, attempt):
            require(name not in selected and row.get("expired") is False and type(row.get("id")) is int
                    and row["id"] > 0 and isinstance(row.get("digest"), str)
                    and re.fullmatch(r"sha256:[0-9a-f]{64}", row["digest"]))
            selected[name] = {"artifactId": str(row["id"]), "archiveSha256": row["digest"][7:]}
    require(selected)
    return {"revision": run["head_sha"], "runId": run_id, "runAttempt": attempt,
            "workflowPath": provider.REHEARSAL_WORKFLOW_PATH, "artifacts": selected}


def partial_record(name, run_id, attempt):
    parts = name.split("/", 1)
    require(len(parts) == 2 and attempt_name(parts[0], run_id, attempt) and parts[1] in PARTIAL_LIMITS)
    return PARTIAL_LIMITS[parts[1]]


def response_identity(envelope):
    journal = envelope.get("journal")
    intent = journal.get("currentIntent") if isinstance(journal, dict) else None
    if not isinstance(intent, dict):
        return None
    observations = [event.get("identities") for event in journal.get("events", []) if isinstance(event, dict)
                    and event.get("phase") == "observation" and event.get("kind") == "response-only"
                    and event.get("operation") == intent.get("operation") and event.get("intentSha256") == intent.get("intentSha256")]
    if not observations:
        return None
    require(all(isinstance(value, dict) and value == observations[0] for value in observations))
    value = {"operation": intent["operation"], "intentSha256": intent["intentSha256"], "identities": observations[0]}
    return {**value, "sha256": provider.digest(value)}


def archive_partial(store, directory, provenance):
    """Preserve every downloaded source/intent/result original, never promote it to acceptance."""
    store.verify()
    require({path.name for path in directory.iterdir()} == set(provenance["artifacts"]))
    files = []
    for artifact in sorted(directory.iterdir()):
        require(artifact.is_dir() and not artifact.is_symlink())
        for path in sorted(artifact.rglob("*")):
            require(not path.is_symlink())
            if path.is_file():
                name = str(path.relative_to(directory))
                provider.provider.checked_file(path, partial_record(name, store.run_id, store.attempt))
                files.append((name, path))
    require(0 < len(files) <= MAX_PARTIAL_FILES
            and sum(path.stat().st_size for _name, path in files) <= MAX_PARTIAL_LOGICAL_BYTES)
    manifest = {"version": 1, "kind": "subs-bot-provider-partial-checkpoints", "completion": "not-complete",
                "controllerRevision": provenance["revision"], "runId": store.run_id, "runAttempt": store.attempt,
                "source": provenance, "files": {}, "logicalBytes": 0, "uniqueBytes": 0, "latestCheckpoint": None}
    unique, latest_events = {}, -1
    for name, path in files:
        entries, hashed, size = [], sha256(), 0
        with path.open("rb") as source:
            while body := source.read(CHUNK_BYTES):
                size += len(body)
                hashed.update(body)
                chunk_sha = sha256(body).hexdigest()
                if chunk_sha not in unique:
                    unique[chunk_sha] = len(body)
                    manifest["uniqueBytes"] += len(body)
                    require(len(unique) <= MAX_CHUNKS and manifest["uniqueBytes"] <= MAX_TOTAL_BYTES)
                    store.put("blobs/" + chunk_sha, body)
                entries.append({"sha256": chunk_sha, "bytes": len(body)})
        manifest["files"][name] = {"bytes": size, "sha256": hashed.hexdigest(), "chunks": entries}
        manifest["logicalBytes"] += size
        if path.name == rehearsal.CHECKPOINT:
            envelope = provider.github._parse_object(path.read_bytes(), ERROR)
            journal, target = envelope.get("journal"), envelope.get("target")
            require(envelope.get("version") == 2 and isinstance(journal, dict) and isinstance(target, dict)
                    and journal.get("controllerRevision") == provenance["revision"]
                    and journal.get("runId") == store.run_id and journal.get("runAttempt") == store.attempt
                    and journal.get("targetSha256") == provider.digest(target) and isinstance(journal.get("events"), list))
            target = provider.validate_config(target)
            require(target["environment"] == "rehearsal" and target["caller"] is None)
            if len(journal["events"]) > latest_events:
                latest_events = len(journal["events"])
                intent = journal.get("currentIntent")
                manifest["latestCheckpoint"] = {"record": name, "targetSha256": provider.digest(target),
                    "events": latest_events, "intent": {key: intent[key] for key in ("operation", "status", "intentSha256")}
                    if isinstance(intent, dict) else None, "responseIdentity": response_identity(envelope)}
    raw = provider.canonical(manifest)
    require(len(raw) <= MAX_PARTIAL_MANIFEST)
    store.put("partial-manifest.json", raw)
    return verify_partial(store, sha256(raw).hexdigest())


def verify_partial(store, expected_manifest):
    store.verify()
    raw = store.read("partial-manifest.json")
    require(isinstance(raw, bytes) and len(raw) <= MAX_PARTIAL_MANIFEST and sha256(raw).hexdigest() == expected_manifest)
    manifest = provider.github._parse_object(raw, ERROR)
    require(set(manifest) == {"version", "kind", "completion", "controllerRevision", "runId", "runAttempt", "source", "files",
                              "logicalBytes", "uniqueBytes", "latestCheckpoint"}
            and manifest["version"] == 1 and manifest["kind"] == "subs-bot-provider-partial-checkpoints"
            and manifest["completion"] == "not-complete" and manifest["runId"] == store.run_id and manifest["runAttempt"] == store.attempt
            and isinstance(manifest["files"], dict) and 0 < len(manifest["files"]) <= MAX_PARTIAL_FILES)
    source = manifest["source"]
    require(isinstance(source, dict) and source.get("revision") == manifest["controllerRevision"]
            and source.get("runId") == store.run_id and source.get("runAttempt") == store.attempt
            and source.get("workflowPath") == provider.REHEARSAL_WORKFLOW_PATH and isinstance(source.get("artifacts"), dict)
            and set(source["artifacts"]) == {name.split("/", 1)[0] for name in manifest["files"]})
    logical, unique = 0, {}
    for name, entry in manifest["files"].items():
        limit = partial_record(name, store.run_id, store.attempt)
        require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256", "chunks"}
                and type(entry["bytes"]) is int and 0 < entry["bytes"] <= limit
                and provider.match(provider.provider.HEX, entry["sha256"]) and isinstance(entry["chunks"], list)
                and 0 < len(entry["chunks"]) <= 64)
        size, hashed = 0, sha256()
        for chunk in entry["chunks"]:
            require(isinstance(chunk, dict) and set(chunk) == {"bytes", "sha256"}
                    and type(chunk["bytes"]) is int and 0 < chunk["bytes"] <= CHUNK_BYTES
                    and provider.match(provider.provider.HEX, chunk["sha256"]))
            require(size + chunk["bytes"] <= entry["bytes"])
            body = store.read("blobs/" + chunk["sha256"])
            require(isinstance(body, bytes) and len(body) == chunk["bytes"] and sha256(body).hexdigest() == chunk["sha256"])
            require(chunk["sha256"] not in unique or unique[chunk["sha256"]] == len(body))
            unique[chunk["sha256"]] = len(body)
            require(len(unique) <= MAX_CHUNKS and sum(unique.values()) <= MAX_TOTAL_BYTES)
            size += len(body)
            hashed.update(body)
        require(size == entry["bytes"] and hashed.hexdigest() == entry["sha256"])
        logical += size
        require(logical <= MAX_PARTIAL_LOGICAL_BYTES)
    require(logical == manifest["logicalBytes"] and sum(unique.values()) == manifest["uniqueBytes"])
    store.verify()
    return {"status": "partial-preserved", "completion": "not-complete", "readback": "R2-only-partial",
            "manifestSha256": expected_manifest, "prefix": store.prefix, "records": len(manifest["files"]),
            "logicalBytes": logical, "uniqueBytes": sum(unique.values()), "latestCheckpoint": manifest["latestCheckpoint"]}


def read_record(store, manifest, name, output=None):
    entry = manifest["files"].get(name)
    require(isinstance(entry, dict))
    digest, count, collected = sha256(), 0, bytearray()
    for chunk in entry["chunks"]:
        body = store.read("blobs/" + chunk["sha256"])
        require(isinstance(body, bytes) and len(body) == chunk["bytes"] and sha256(body).hexdigest() == chunk["sha256"])
        count += len(body)
        require(count <= entry["bytes"])
        digest.update(body)
        if output is not None:
            output.write(body)
        else:
            require(count <= rehearsal.MAX_CHECKPOINT)
            collected.extend(body)
    require(count == entry["bytes"] and digest.hexdigest() == entry["sha256"])
    return bytes(collected) if output is None else digest.hexdigest()


class ReconciliationReader(provider.ProviderAPI):
    def _request(self, path, *, container=False, method="GET", body=None, absent=None, limit=provider.publication.HTTP_LIMIT):
        require(method == "GET" and not container and body is None and path.startswith("/workers/"))
        return super()._request(path, method="GET", absent=absent, limit=limit)

    def _write(self, *_args, **_kwargs):
        raise provider.ProviderError("Provider reconciliation is read-only.")

    def upload(self, *_args, **_kwargs):
        raise provider.ProviderError("Provider reconciliation is read-only.")


def reconcile_identity(config, identity):
    candidate = json.loads(provider.canonical(config))
    require(candidate["environment"] == "rehearsal" and candidate["caller"] is None and candidate.get("previous") is None
            and candidate["activation"] is None and candidate["container"] is None and candidate["workflow"] is None)
    operation, observed = identity["operation"], identity["identities"]
    if operation == "create":
        require(candidate["worker"] is None and candidate["versionId"] is None)
        pin = provider.bootstrap.Identity(observed.get("id"), observed.get("created_on"))
        candidate["worker"] = {"workerId": pin.worker_id, "workerCreatedOn": pin.created_on}
    elif operation == "stage":
        require(candidate["worker"] is not None and candidate["versionId"] is None
                and provider.match(provider.stage.VERSION_ID, observed.get("versionId")))
        candidate["versionId"] = observed["versionId"]
    else:
        raise provider.ProviderError("Only the declared pre-consumer create/stage responses can be reconciled by this tool.")
    candidate = provider.validate_config(candidate)
    client = ReconciliationReader(candidate, os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN", ""))
    for _pass in range(2):
        for worker in (client.by_name(), client.worker.by_id(client.identity)):
            provider.verify_profile(worker, candidate, client.identity, False)
            provider.legacy._references(worker, client.identity, None, service=candidate["service"])
        client.versions()
        require(client.deployment() is None)
        if candidate["versionId"] is not None:
            version = candidate["versionId"]
            metadata = provider.metadata(candidate)
            beta = client._request(client.beta_path + "/" + version + "?include=modules", limit=provider.stage.MAX_VERSION_RESPONSE)["result"]
            legacy = client._request(client.worker_path + "/versions/" + version)["result"]
            provider.stage._verify_version(beta, version, metadata, candidate["build"]["workerSha256"], service=candidate["service"])
            provider.stage._verify_legacy_version(legacy, version, metadata, service=candidate["service"])
    provider.public_denied(candidate)
    return candidate


def reconcile_partial(store, manifest_sha256, response_sha256):
    require(provider.match(provider.provider.HEX, response_sha256))
    verify_partial(store, manifest_sha256)
    manifest = provider.github._parse_object(store.read("partial-manifest.json"), ERROR)
    latest = manifest["latestCheckpoint"]
    require(isinstance(latest, dict) and isinstance(latest.get("responseIdentity"), dict)
            and latest["responseIdentity"].get("sha256") == response_sha256)
    envelope = provider.github._parse_object(read_record(store, manifest, latest["record"]), ERROR)
    target, journal = provider.validate_config(envelope["target"]), envelope["journal"]
    identity = response_identity(envelope)
    require(identity is not None and identity == latest["responseIdentity"] and identity["sha256"] == response_sha256)
    intent = journal["currentIntent"]
    require(intent["status"] in {"started-unknown", "unconfirmed"} and intent["targetSha256"] == provider.digest(target)
            and intent["source"] == target["build"] and journal["source"] == target["build"]
            and intent["approvalSha256"] == provider.digest({"operation": intent["operation"], "target": target}))
    name = f"subs-bot-provider-attempt-intent-{intent['operation']}-{store.run_id}-{store.attempt}"
    recorded = manifest["source"]["artifacts"].get(name)
    require(isinstance(recorded, dict) and any(event.get("phase") == "intent-persisted"
            and event.get("intentSha256") == intent["intentSha256"] and event.get("artifactId") == recorded["artifactId"]
            and event.get("archiveSha256") == recorded["archiveSha256"] for event in journal["events"]))
    source_name = f"subs-bot-provider-attempt-source-{store.run_id}-{store.attempt}/provider-source-archive.zip"
    with tempfile.TemporaryDirectory(prefix=".provider-partial-source-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        directory = Path(temporary)
        archive = directory / "source.zip"
        with provider.provenance._write_private(archive) as output:
            archive_sha = read_record(store, manifest, source_name, output)
        require(archive_sha == target["build"]["archiveSha256"])
        verified = directory / "verified"
        verified.mkdir(mode=0o700)
        provider.provenance._unpack(archive, verified)
        release = provider.provider.verify_release(verified, target["build"]["revision"], ref=provider.github.MAIN_REF,
                                                   run_id=target["build"]["runId"], run_attempt=target["build"]["runAttempt"])
        require(all(release[key] == target["build"][key] for key in provider.publication.MANIFEST_FIELDS))
        confirmed = reconcile_identity(target, identity)
    result = {"status": "confirmed-identity-only", "completion": "not-complete", "operation": identity["operation"],
              "sourceManifestSha256": manifest_sha256, "responseIdentitySha256": response_sha256,
              "targetSha256": provider.digest(confirmed), "sourceRevision": confirmed["build"]["revision"]}
    for name, value in (("provider-reconciled-target.json", confirmed), ("provider-reconciliation.json", result)):
        with provider.provenance._write_private(Path(os.environ["RUNNER_TEMP"]) / name) as output:
            output.write(provider.canonical(value))
    return result


def main():
    require(os.environ.get("GITHUB_REPOSITORY") == provider.github.REPOSITORY
            and os.environ.get("GITHUB_REF") == provider.github.MAIN_REF and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_WORKFLOW_REF") == f"{provider.github.REPOSITORY}/{provider.REHEARSAL_WORKFLOW_PATH}@{provider.github.MAIN_REF}")
    action = os.environ.get("PROVIDER_ARCHIVE_ACTION", "")
    require(action in {"archive", "verify", "rehearse", "preserve-partial", "verify-archive", "verify-partial", "reconcile-partial"})
    run_id = os.environ["GITHUB_RUN_ID"] if action in {"archive", "rehearse"} else os.environ.get("PROVIDER_ARCHIVE_RUN_ID", "")
    attempt = os.environ["GITHUB_RUN_ATTEMPT"] if action in {"archive", "rehearse"} else os.environ.get("PROVIDER_ARCHIVE_RUN_ATTEMPT", "")
    target = provider.github._parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), ERROR)
    store = PrivateProofStore(target, os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), run_id, attempt)
    if action in {"rehearse", "preserve-partial"}:
        provenance = original_run(run_id, attempt)
        inputs = Path(os.environ["RUNNER_TEMP"]) / "provider-attempt-input"
        if action == "rehearse" and os.environ.get("PROVIDER_REHEARSAL_JOB_RESULT") == "success":
            final = inputs / f"subs-bot-provider-attempt-final-{run_id}-{attempt}"
            raw_proof = provider.provider.checked_file(final / "provider-rehearsal-proof.json", 65536).read_bytes()
            proof = provider.github._parse_object(raw_proof, ERROR)
            require(proof.get("controllerRevision") == provenance["revision"])
            require(proof.get("journalSha256") == sha256((final / "provider-rehearsal-journal.json").read_bytes()).hexdigest())
            with tempfile.TemporaryDirectory(prefix=".provider-complete-proof-", dir=os.environ["RUNNER_TEMP"]) as temporary:
                complete = Path(temporary)
                for name, limit in FILE_LIMITS.items():
                    source = provider.provider.checked_file(final / name, limit)
                    (complete / name).parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    shutil.copyfile(source, complete / name)
                result = {"status": "complete", "completion": "complete", **archive(store, complete)}
        else:
            result = archive_partial(store, inputs, provenance)
    elif action == "archive":
        require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
        result = {"status": "complete", **archive(store, Path(os.environ["RUNNER_TEMP"]) / "provider-proof-input")}
    else:
        expected = os.environ.get("PROVIDER_ARCHIVE_MANIFEST_SHA256", "")
        require(provider.match(provider.provider.HEX, expected))
        if action == "reconcile-partial":
            result = reconcile_partial(store, expected, os.environ.get("PROVIDER_RESPONSE_IDENTITY_SHA256", ""))
        else:
            result = verify_partial(store, expected) if action == "verify-partial" else {"status": "complete", **verify_archive(store, expected)}
    print(json.dumps({"action": action, **result}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(ERROR) from None

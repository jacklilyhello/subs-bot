"""Seal provider source/proof bytes in project-private R2 and independently read them back."""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPSConnection, HTTPException
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import ProxyHandler, Request, build_opener

from cloudflare_isolation import CloudflareClient, API_ORIGIN, _NoRedirect
from evidence_archive import verify_lifecycle
from native_restore_rehearsal import signed_put_headers
import production_provider as provider

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
        require(relative == "manifest.json" or re.fullmatch(r"blobs/[0-9a-f]{64}", relative))
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


def main():
    require(os.environ.get("GITHUB_REPOSITORY") == provider.github.REPOSITORY
            and os.environ.get("GITHUB_REF") == provider.github.MAIN_REF and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("GITHUB_WORKFLOW_REF") == f"{provider.github.REPOSITORY}/{provider.REHEARSAL_WORKFLOW_PATH}@{provider.github.MAIN_REF}")
    action = os.environ.get("PROVIDER_ARCHIVE_ACTION", "")
    require(action in {"archive", "verify"})
    run_id = os.environ["GITHUB_RUN_ID"] if action == "archive" else os.environ.get("PROVIDER_ARCHIVE_RUN_ID", "")
    attempt = os.environ["GITHUB_RUN_ATTEMPT"] if action == "archive" else os.environ.get("PROVIDER_ARCHIVE_RUN_ATTEMPT", "")
    target = provider.github._parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), ERROR)
    store = PrivateProofStore(target, os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), run_id, attempt)
    if action == "archive":
        require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
        result = archive(store, Path(os.environ["RUNNER_TEMP"]) / "provider-proof-input")
    else:
        expected = os.environ.get("PROVIDER_ARCHIVE_MANIFEST_SHA256", "")
        require(provider.match(provider.provider.HEX, expected))
        result = verify_archive(store, expected)
    print(json.dumps({"status": "complete", "action": action, **result}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit(ERROR) from None

"""Verify or stage the first private Provider Fetch Worker version by digest."""

from base64 import b64decode
from binascii import Error as Base64Error
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from secrets import token_hex
import tempfile
from time import monotonic, sleep
from urllib.request import ProxyHandler, Request, build_opener

import bootstrap_provider_worker as bootstrap
import prepare_isolation_artifact as github
import publish_provider_registry as publication


provider = publication.provider
VERSION_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
WORKFLOW = provider.SERVICE + "-smoke"
MODULE_TYPE = "application/javascript+module"
MAX_VERSION_RESPONSE = 2 * provider.MAX_WORKER
PREPARE_SECONDS = 15 * 60
VERSION_ERROR = "The staged provider Worker version did not match the exact private release."
UPLOAD_ERROR = "The provider version upload was not confirmed. Use verification to reconcile the exact candidate before another stage."
PREPARE_ERROR = "The pinned provider image was not ready for Cloudflare Workers."


class StageError(ValueError):
    """Failure with a fixed message suitable for public Actions logs."""


def _require(condition, message):
    if not condition:
        raise StageError(message)


def _metadata(evidence, image):
    return {
        "main_module": provider.WORKER,
        "compatibility_date": evidence["compatibilityDate"],
        "bindings": [
            {"name": "BUILD_REVISION", "type": "plain_text", "text": evidence["revision"]},
            {"name": "PROVIDER_CONTAINER", "type": "durable_object_namespace", "class_name": "ProviderContainer"},
            {"name": "PROVIDER_SMOKE", "type": "workflow", "workflow_name": WORKFLOW, "class_name": "ProviderSmoke"},
        ],
        "exports": {
            "ProviderContainer": {"type": "durable-object", "storage": "sqlite", "container": provider.SERVICE},
            "ProviderFetch": {"type": "worker"},
        },
        "containers": [{"name": provider.SERVICE, "class_name": "ProviderContainer", "images": {"provider": image}}],
        "annotations": {
            "workers/tag": f"provider-{evidence['revision']}-{evidence['artifactId']}",
            "workers/message": f"provider-ci/{evidence['runId']}/{evidence['runAttempt']}/{evidence['artifactId']}",
        },
    }


def _multipart(metadata, module):
    boundary = "subs-bot-" + token_hex(24)
    prefix = f"--{boundary}\r\n".encode("ascii")
    metadata_bytes = json.dumps(metadata, separators=(",", ":")).encode("ascii")
    marker = f"--{boundary}".encode("ascii")
    _require(marker not in module and marker not in metadata_bytes, "The provider version upload could not be framed.")
    body = b"".join((
        prefix, b'Content-Disposition: form-data; name="metadata"\r\n\r\n', metadata_bytes, b"\r\n",
        prefix, (f'Content-Disposition: form-data; name="{provider.WORKER}"; filename="{provider.WORKER}"\r\n'
                 f"Content-Type: {MODULE_TYPE}\r\n\r\n").encode("ascii"),
        module, f"\r\n--{boundary}--\r\n".encode("ascii"),
    ))
    return f"multipart/form-data; boundary={boundary}", body


def _json_request(url, opener, token, error, *, content_type=None, body=None,
                  statuses=(200,), limit=publication.HTTP_LIMIT):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json", "Cache-Control": "no-cache"}
    if body is not None:
        headers["Content-Type"] = content_type
    request = Request(url, data=body, headers=headers, method="GET" if body is None else "POST")
    status, _, raw = publication._response(request, opener, error, limit=limit)
    envelope = github._parse_object(raw, error)
    _require(status in statuses and envelope.get("success") is True and envelope.get("errors") in (None, [])
             and "result" in envelope, error)
    return status, envelope


def _version_id(value):
    _require(isinstance(value, str) and VERSION_ID.fullmatch(value), VERSION_ERROR)
    return value


def _one_page(envelope, rows, maximum, *, per_page=None):
    pagination = envelope.get("result_info", {})
    _require(isinstance(rows, list) and len(rows) <= maximum and isinstance(pagination, dict)
             and all(type(pagination.get(key, expected if per_page is None else None)) is int
                     and pagination.get(key, expected) == expected
                     for key, expected in (("count", len(rows)), ("total_count", len(rows)), ("page", 1)))
             and (per_page is None or (type(pagination.get("per_page")) is int and pagination["per_page"] == per_page))
             and type(pagination.get("total_pages", 1)) is int
             and pagination.get("total_pages", 1) in ((1,) if rows else (0, 1))
             and pagination.get("cursor") in (None, ""),
             "The provider Worker is not in the supported first-version state.")


class WorkerVersions:
    def __init__(self, account, token, identity):
        self.worker = bootstrap.WorkerAPI(account, token)
        self.identity = identity
        self._base = f"{publication.API_ORIGIN}/accounts/{account}"
        self._legacy = f"/workers/scripts/{provider.SERVICE}"
        self._beta = f"/workers/workers/{identity.worker_id}/versions"
        self._token = token
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())

    def _read(self, path, limit=publication.HTTP_LIMIT):
        return _json_request(self._base + path, self._opener, self._token, VERSION_ERROR, limit=limit)[1]

    def baseline(self):
        bootstrap._verify_profile(self.worker.by_name(), self.identity)
        bootstrap._verify_profile(self.worker.by_id(self.identity), self.identity)
        deployments = self._read(f"{self._legacy}/deployments?page=1&per_page=1")
        result = deployments["result"]
        _require(isinstance(result, dict), VERSION_ERROR)
        _one_page(deployments, result.get("deployments"), 0)
        versions = self._read(f"{self._beta}?page=1&per_page=2", MAX_VERSION_RESPONSE)
        rows = versions["result"]
        _one_page(versions, rows, 1, per_page=2)
        if not rows:
            return None
        _require(isinstance(rows[0], dict), VERSION_ERROR)
        return _version_id(rows[0].get("id"))

    def upload(self, metadata, module):
        content_type, body = _multipart(metadata, module)
        try:
            _, envelope = _json_request(f"{self._base}{self._legacy}/versions?bindings_inherit=strict",
                                        self._opener, self._token, UPLOAD_ERROR, content_type=content_type,
                                        body=body, statuses=(200, 201))
            result = envelope["result"]
            _require(isinstance(result, dict), UPLOAD_ERROR)
            return _version_id(result.get("id"))
        except (StageError, publication.PublicationError, github.ArtifactError):
            raise StageError(UPLOAD_ERROR) from None

    def verify(self, candidate, metadata, module_sha256):
        candidate = _version_id(candidate)
        beta = self._read(f"{self._beta}/{candidate}?include=modules", MAX_VERSION_RESPONSE)["result"]
        _verify_version(beta, candidate, metadata, module_sha256)
        legacy = self._read(f"{self._legacy}/versions/{candidate}")["result"]
        _require(isinstance(legacy, dict) and legacy.get("id") == candidate, VERSION_ERROR)
        resources = legacy.get("resources")
        runtime = resources.get("script_runtime") if isinstance(resources, dict) else None
        _require(isinstance(runtime, dict) and runtime.get("containers") == metadata["containers"], VERSION_ERROR)


def _verify_version(version, candidate, metadata, module_sha256):
    _require(isinstance(version, dict) and version.get("id") == candidate
             and version.get("main_module") == provider.WORKER and version.get("urls") == []
             and version.get("compatibility_date") in (metadata["compatibility_date"], metadata["compatibility_date"] + "T00:00:00Z")
             and version.get("usage_model") in (None, "standard")
             and not any(version.get(key) for key in ("assets", "compatibility_flags", "limits", "migrations", "placement"))
             and version.get("cache_options") in (None, {}, {"enabled": False},
                                                 {"enabled": False, "cross_version_cache": False}), VERSION_ERROR)
    annotations = version.get("annotations")
    _require(isinstance(annotations, dict)
             and all(annotations.get(key) == expected for key, expected in metadata["annotations"].items()), VERSION_ERROR)
    bindings = version.get("bindings")
    _require(isinstance(bindings, list) and len(bindings) == len(metadata["bindings"])
             and all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in bindings), VERSION_ERROR)
    by_name = {row["name"]: row for row in bindings}
    for binding in metadata["bindings"]:
        row = by_name.get(binding["name"])
        _require(isinstance(row, dict) and all(row.get(key) == value for key, value in binding.items())
                 and row.get("script_name") in (None, provider.SERVICE) and row.get("environment") in (None, "production")
                 and row.get("namespace_id") is None, VERSION_ERROR)
    exports = version.get("exports")
    _require(isinstance(exports, dict) and set(exports) - set(metadata["exports"]) <= {"default"}, VERSION_ERROR)
    for name, expected in metadata["exports"].items():
        row = exports.get(name)
        _require(isinstance(row, dict) and all(row.get(key) == value for key, value in expected.items())
                 and row.get("state", "created") == "created"
                 and row.get("cache") in (None, {"enabled": False}), VERSION_ERROR)
    if "default" in exports:
        default = exports["default"]
        _require(isinstance(default, dict) and default.get("type") == "worker"
                 and default.get("state", "created") == "created"
                 and default.get("cache") in (None, {"enabled": False}), VERSION_ERROR)
    modules = version.get("modules")
    _require(isinstance(modules, list) and len(modules) == 1 and isinstance(modules[0], dict), VERSION_ERROR)
    module = modules[0]
    encoded = module.get("content_base64")
    _require(module.get("name") == provider.WORKER and module.get("content_type") == MODULE_TYPE
             and isinstance(encoded, str) and 0 < len(encoded) <= 4 * ((provider.MAX_WORKER + 2) // 3), VERSION_ERROR)
    try:
        raw = b64decode(encoded, validate=True)
    except (Base64Error, ValueError):
        raise StageError(VERSION_ERROR) from None
    _require(0 < len(raw) <= provider.MAX_WORKER and sha256(raw).hexdigest() == module_sha256, VERSION_ERROR)


class PublishedImage:
    def __init__(self, account, token, evidence, scratch):
        _require(publication.ACCOUNT.fullmatch(account)
                 and sha256(account.encode("ascii")).hexdigest() == publication.TARGET_ACCOUNT_SHA256,
                 "The protected Cloudflare account does not match the provider target.")
        self._registry = publication.Registry(account, token)
        self._token = token
        self._url = f"{publication.API_ORIGIN}/accounts/{account}/containers/image-preparations"
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())
        self._scratch = scratch
        self._manifest = evidence["ociManifestSha256"]
        self._config = evidence["ociConfigSha256"]
        self.reference = f"{publication.HOST}/{self._registry.repository}@sha256:{self._manifest}"

    def verify(self):
        pull = self._registry.mint()
        auth = publication._write_auth(self._scratch / "pull-auth.json", pull, self._registry.repository)
        _require(self._registry.manifest("sha256:" + self._manifest, pull) == self._manifest
                 and publication._config(self._scratch, self.reference, auth) == self._config,
                 "The published provider OCI manifest or config digest did not match.")

    def prepare(self, guard):
        body = json.dumps({"image": self.reference}, separators=(",", ":")).encode("ascii")
        deadline = monotonic() + PREPARE_SECONDS
        guard()
        while monotonic() < deadline:
            status, envelope = _json_request(self._url, self._opener, self._token, PREPARE_ERROR,
                                             content_type="application/json", body=body, statuses=(200, 202))
            result = envelope["result"]
            _require(isinstance(result, dict) and result.get("image") == self.reference, PREPARE_ERROR)
            if status == 200 and result.get("status") == "ready":
                digest = result.get("artifact_digest")
                _require(digest is None or (isinstance(digest, str) and publication.MANIFEST_DIGEST.fullmatch(digest)),
                         PREPARE_ERROR)
                return
            _require(status == 202 and result.get("status") == "pending", PREPARE_ERROR)
            sleep(4)
        raise StageError(PREPARE_ERROR)


def _stage(versions, image, operation, evidence, module, guard):
    metadata = _metadata(evidence, image.reference)
    candidate = versions.baseline()
    image.verify()
    status = "preflight"
    if candidate is None and operation == "stage":
        image.prepare(guard)
        candidate = versions.baseline()
        if candidate is None:
            guard()
            try:
                candidate = versions.upload(metadata, module)
                status = "staged"
            except StageError:
                candidate = versions.baseline()
                if candidate is None:
                    raise
    if candidate is not None:
        versions.verify(candidate, metadata, evidence["workerSha256"])
        if status != "staged":
            status = "verified"
    _require(versions.baseline() == candidate, "The provider version or deployment changed during verification.")
    guard()
    return status, candidate


def stage():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    operation = os.environ.get("SUBS_BOT_PROVIDER_STAGE_OPERATION", "")
    _require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
             and os.environ.get("GITHUB_REF") == github.MAIN_REF
             and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and provider.REVISION.fullmatch(revision) and provider.DECIMAL.fullmatch(run_id)
             and runner_temp.is_absolute() and operation in {"stage", "verify"},
             "Provider version staging requires a protected dispatch from the exact main revision.")
    _require(operation == "verify" or os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
             "Reconcile a previous staging attempt with a new verification dispatch.")
    identity = bootstrap._pin(os.environ.get(bootstrap.IDENTITY_ENV, ""))
    _require(identity is not None, "Provider version staging requires the protected Worker identity pin.")
    archive, evidence = publication._verified_input(runner_temp, revision, run_id)
    with provider.checked_file(archive.with_name(provider.WORKER), provider.MAX_WORKER).open("rb") as source:
        module = source.read(provider.MAX_WORKER + 1)
    _require(0 < len(module) <= provider.MAX_WORKER and sha256(module).hexdigest() == evidence["workerSha256"],
             "The compiled provider module changed after artifact verification.")

    def guard():
        publication._guard_main(evidence)

    guard()
    account = os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", "")
    versions = WorkerVersions(account, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""), identity)
    with tempfile.TemporaryDirectory(prefix=".subs-bot-provider-version-", dir=runner_temp) as scratch:
        image = PublishedImage(account, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""), evidence, Path(scratch))
        status, candidate = _stage(versions, image, operation, evidence, module, guard)
    return {**evidence, "status": status, "workerIdentitySha256": identity.fingerprint(),
            "versionSha256": sha256(candidate.encode("ascii")).hexdigest() if candidate else None,
            "activeDeployments": 0}


if __name__ == "__main__":
    try:
        print(json.dumps(stage(), sort_keys=True))
    except (StageError, bootstrap.BootstrapError, publication.PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The private provider version could not be staged safely.") from None

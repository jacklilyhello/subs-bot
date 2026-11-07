"""Activate and verify the pinned private provider, one explicit write per dispatch."""

from copy import deepcopy
from datetime import date
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
from time import monotonic, sleep
from urllib.request import ProxyHandler, Request, build_opener

import stage_provider_version as stage


bootstrap = stage.bootstrap
publication = stage.publication
github = stage.github
provider = stage.provider
RELEASE_ENV = "SUBS_BOT_CF_PROVIDER_RELEASE_JSON"
ACTIVATION_ENV = "SUBS_BOT_CF_PROVIDER_ACTIVATION_JSON"
CONTAINER_ENV = "SUBS_BOT_CF_PROVIDER_CONTAINER_IDENTITY_JSON"
WORKFLOW_ENV = "SUBS_BOT_CF_PROVIDER_WORKFLOW_IDENTITY_JSON"
PROVIDER_URL = "https://subs-bot-provider-fetch-dev-01.lilyya.workers.dev/health"
HEALTH_URL = "https://subs-bot-cf-dev-01.lilyya.workers.dev/health"
ACTOR = re.compile(r"[0-9a-f]{64}")
ERROR = "The private provider state did not match the pinned release and resource identities."
WRITE_ERROR = "The provider operation was not confirmed. Use read-only verification and independently pin its observed state before continuing."
PIN_ERROR = "The protected provider release or resource identity pin is invalid."
OPERATIONS = {"verify", "activate", "provision-container", "provision-workflow", "smoke"}
WORKFLOW_PATH = ".github/workflows/worker-provider-isolation-activate.yml"
BINDING_PROOF_FILE = "provider-binding-proof.json"
MAX_BINDING_PROOF = 4096
BINDING_PROOF_ERROR = "The private provider binding proof does not match the verified run and release."
BUILD_FIELDS = {"revision", "runId", "runAttempt", "artifactId", "archiveSha256", *publication.MANIFEST_FIELDS}
PROOF_DIGESTS = {"workerIdentitySha256", "versionSha256", "activationIdentitySha256",
                 "containerIdentitySha256", "workflowIdentitySha256", "actorSha256", "healthSha256"}
PROOF_FIELDS = {"status", "publicDenied", "stopped", "healthBytes", "approvedDnsFamilies",
                "blockedPrivateTargets", *PROOF_DIGESTS}


class ActivationError(ValueError):
    """Fixed, redacted failure suitable for public Actions logs."""


def _require(condition, message=ERROR):
    if not condition:
        raise ActivationError(message)


def _uuid(value):
    _require(isinstance(value, str) and stage.VERSION_ID.fullmatch(value), PIN_ERROR)
    return value


def _id(value):
    _require(isinstance(value, str) and publication.ACCOUNT.fullmatch(value), PIN_ERROR)
    return value


def _hash(value):
    return sha256(value.encode("ascii")).hexdigest()


def _fingerprint(value):
    return _hash(json.dumps(value, sort_keys=True, separators=(",", ":"))) if value else None


def _match(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _proof_bytes(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def parse_binding_proof(raw, *, revision, run_id, run_attempt):
    """Verify canonical proof bytes against separately authenticated GitHub run metadata."""
    _require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_BINDING_PROOF, BINDING_PROOF_ERROR)
    proof = github._parse_object(raw, BINDING_PROOF_ERROR)
    _require(set(proof) == {"version", "accountSha256", "providerBuild", "activation", "verification"}
             and type(proof["version"]) is int and proof["version"] == 1
             and proof["accountSha256"] == publication.TARGET_ACCOUNT_SHA256, BINDING_PROOF_ERROR)
    build, activation, verification = proof["providerBuild"], proof["activation"], proof["verification"]
    _require(isinstance(build, dict) and set(build) == BUILD_FIELDS
             and _match(provider.REVISION, revision) and build["revision"] == revision
             and all(_match(provider.DECIMAL, build[key]) for key in ("runId", "runAttempt", "artifactId"))
             and all(_match(provider.HEX, build[key]) for key in BUILD_FIELDS if key.endswith("Sha256")), BINDING_PROOF_ERROR)
    try:
        compatibility = date.fromisoformat(build["compatibilityDate"]).isoformat()
    except (ValueError, TypeError):
        raise ActivationError(BINDING_PROOF_ERROR) from None
    _require(build["compatibilityDate"] == compatibility and isinstance(activation, dict)
             and set(activation) == {"runId", "runAttempt", "isolatedRevision"}
             and _match(provider.DECIMAL, run_id) and activation["runId"] == run_id
             and _match(provider.DECIMAL, run_attempt) and activation["runAttempt"] == run_attempt
             and _match(provider.REVISION, activation["isolatedRevision"]), BINDING_PROOF_ERROR)
    _require(isinstance(verification, dict) and set(verification) == PROOF_FIELDS
             and verification["status"] == "complete" and verification["publicDenied"] is True
             and verification["stopped"] is True and all(_match(provider.HEX, verification[key]) for key in PROOF_DIGESTS)
             and type(verification["healthBytes"]) is int and 0 < verification["healthBytes"] <= 4096
             and type(verification["blockedPrivateTargets"]) is int and verification["blockedPrivateTargets"] == 3,
             BINDING_PROOF_ERROR)
    families = verification["approvedDnsFamilies"]
    _require(isinstance(families, list) and families in ([4], [6], [4, 6])
             and all(type(family) is int for family in families) and raw == _proof_bytes(proof), BINDING_PROOF_ERROR)
    return proof


def _binding_proof_context():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "")
    _require(os.environ.get("GITHUB_SERVER_URL") == "https://github.com"
             and os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
             and os.environ.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
             and os.environ.get("GITHUB_REF") == github.MAIN_REF
             and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
             and os.environ.get("GITHUB_WORKFLOW_REF") == f"{github.REPOSITORY}/{WORKFLOW_PATH}@{github.MAIN_REF}"
             and os.environ.get("GITHUB_WORKFLOW_SHA") == revision and _match(provider.REVISION, revision)
             and _match(provider.DECIMAL, run_id) and _match(provider.DECIMAL, run_attempt), BINDING_PROOF_ERROR)
    return revision, run_id, run_attempt


def _write_binding_proof(result, revision, run_id, run_attempt):
    if result["status"] != "complete":
        return
    _require(os.environ.get("SUBS_BOT_PROVIDER_ACTIVATION_OPERATION") in {"smoke", "verify"}
             and set(result) == BUILD_FIELDS | PROOF_FIELDS, BINDING_PROOF_ERROR)
    raw = _proof_bytes({
        "version": 1,
        "accountSha256": publication.TARGET_ACCOUNT_SHA256,
        "providerBuild": {key: result[key] for key in BUILD_FIELDS},
        "activation": {"runId": run_id, "runAttempt": run_attempt,
                       "isolatedRevision": os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_REVISION", "")},
        "verification": {key: result[key] for key in PROOF_FIELDS},
    })
    parse_binding_proof(raw, revision=revision, run_id=run_id, run_attempt=run_attempt)
    directory = Path(os.environ.get("RUNNER_TEMP", ""))
    output = Path(os.environ.get("GITHUB_OUTPUT", ""))
    _require(directory.is_absolute() and output.is_absolute() and output.name != BINDING_PROOF_FILE
             and output.parent.resolve().is_relative_to(directory.resolve()), BINDING_PROOF_ERROR)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(directory / BINDING_PROOF_FILE, flags, 0o600), "wb") as file:
        file.write(raw)
    flags = os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(output, flags), "ab") as file:
        info = os.fstat(file.fileno())
        _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid(), BINDING_PROOF_ERROR)
        file.write(b"binding_proof=true\n")


def _pin(value, fields):
    if not value:
        return None
    _require(isinstance(value, str) and len(value) <= 4096, PIN_ERROR)
    pin = github._parse_object(value, PIN_ERROR)
    _require(set(pin) == set(fields), PIN_ERROR)
    for key in fields:
        if key in {"namespaceId", "applicationId"}:
            _id(pin[key])
        elif key in {"deploymentId", "workflowId", "versionId"}:
            _uuid(pin[key])
        else:
            bootstrap._timestamp(pin[key])
    return pin


def _release_pin(value, evidence):
    _require(isinstance(value, str) and 0 < len(value) <= 4096, PIN_ERROR)
    pin = github._parse_object(value, PIN_ERROR)
    _require(set(pin) == set(evidence) | {"versionId"}
             and all(pin[key] == expected for key, expected in evidence.items()), PIN_ERROR)
    _uuid(pin["versionId"])
    return pin


def _page(envelope, rows, maximum, *, cursor=False):
    _require(isinstance(rows, list) and len(rows) <= maximum)
    info = envelope.get("result_info", {})
    _require(isinstance(info, dict))
    if cursor:
        _require(info.get("next_page_token") in (None, "") and info.get("cursor") in (None, "")
                 and info.get("cursors") in (None, {}, {"after": None}))
    else:
        stage._one_page(envelope, rows, maximum)
    return rows


def _private_profile(worker, identity, active):
    _require(bootstrap._identity(worker) == identity)
    subdomain = worker.get("subdomain")
    _require(worker.get("tags") == [bootstrap.OWNERSHIP_TAG] and isinstance(subdomain, dict)
             and subdomain.get("enabled") is False and subdomain.get("previews_enabled") is False)
    if active:
        bootstrap._timestamp(worker.get("deployed_on"))
    else:
        _require(worker.get("deployed_on") is None)
    references = worker.get("references")
    _require(isinstance(references, dict)
             and all(references.get(key) == [] for key in bootstrap.REFERENCE_FIELDS if key != "durable_objects")
             and all(key in bootstrap.REFERENCE_FIELDS or not value for key, value in references.items()))
    bootstrap._logging_off(worker)
    preview = worker.get("previews_base_config")
    if preview is not None:
        _require(isinstance(preview, dict) and preview.get("env", {}) == {})
        bootstrap._logging_off(preview, preview=True)


def _references(worker, identity, namespace):
    rows = worker["references"].get("durable_objects")
    _require(rows == [] or (namespace is not None and isinstance(rows, list) and len(rows) == 1
             and isinstance(rows[0], dict) and rows[0].get("namespace_id") == namespace
             and rows[0].get("worker_id") == identity.worker_id
             and rows[0].get("worker_name") == provider.SERVICE))


class ProviderAPI:
    """Fixed project operations with at most one attempted mutation per process."""

    def __init__(self, account, worker_token, container_token, identity):
        self.worker = bootstrap.WorkerAPI(account, worker_token)
        _require(publication.API_TOKEN.fullmatch(container_token),
                 "The dedicated Containers credential is required for the provider resource inventory.")
        self.account = account
        self.identity = identity
        self.base = f"{publication.API_ORIGIN}/accounts/{account}"
        self.worker_path = f"/workers/scripts/{provider.SERVICE}"
        self.beta_path = f"/workers/workers/{identity.worker_id}/versions"
        self.workflow_path = f"/workflows/{stage.WORKFLOW}"
        self._worker_token = worker_token
        self._container_token = container_token
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())
        self._writes = 0

    def _request(self, path, *, container=False, method="GET", body=None, absent=None, limit=publication.HTTP_LIMIT):
        token = self._container_token if container else self._worker_token
        _require(publication.API_TOKEN.fullmatch(token), "The dedicated provider credential required for this phase is missing.")
        _require(path.startswith("/containers/" if container else ("/workers/", "/workflows/")))
        error = ERROR if method == "GET" else WRITE_ERROR
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json", "Cache-Control": "no-cache"}
        data = None
        if method != "GET":
            _require(self._writes == 0, WRITE_ERROR)
            self._writes += 1
            data = json.dumps(body, separators=(",", ":")).encode("ascii")
            headers["Content-Type"] = "application/json"
        request = Request(self.base + path, data=data, headers=headers, method=method)
        status, _, raw = publication._response(request, self._opener, error, limit=limit)
        envelope = github._parse_object(raw, error)
        if method == "GET" and absent is not None and status == 404:
            errors = envelope.get("errors")
            _require(envelope.get("success") is False and envelope.get("result") is None
                     and isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
                     and type(errors[0].get("code")) is int and errors[0]["code"] == absent)
            return None
        _require(status in ((200,) if method == "GET" else (200, 201))
                 and envelope.get("success") is True and envelope.get("errors") in (None, [])
                 and "result" in envelope, error)
        return envelope

    def _write(self, path, body, *, container=False, method="POST"):
        try:
            return self._request(path, container=container, method=method, body=body)["result"]
        except (ActivationError, bootstrap.BootstrapError, publication.PublicationError, github.ArtifactError):
            raise ActivationError(WRITE_ERROR) from None

    def deploy(self, release):
        return self._write(self.worker_path + "/deployments", {
            "strategy": "percentage", "versions": [{"version_id": release["versionId"], "percentage": 100}],
            "annotations": {"workers/message": f"provider-activate/{release['revision']}/{release['artifactId']}"},
        })

    def create_container(self, namespace):
        return self._write("/containers/applications", {
            "name": provider.SERVICE, "scheduling_policy": "durable_object",
            "durable_objects": {"namespace_id": _id(namespace)},
            "configuration": {"authorized_keys": [], "wrangler_ssh": False},
            "observability": {"logs": {"enabled": False}},
        }, container=True)

    def create_workflow(self):
        return self._write(self.workflow_path, {"script_name": provider.SERVICE, "class_name": "ProviderSmoke",
                           "schedules": [], "concurrency": {"limit": 1}}, method="PUT")

    def trigger(self, release, isolated_revision):
        return self._write(self.workflow_path + "/instances", {
            "instance_id": "provider-smoke-" + release["revision"],
            "params": {"providerRevision": release["revision"], "isolatedRevision": isolated_revision},
        })

    def deployment(self, release):
        envelope = self._request(self.worker_path + "/deployments?page=1&per_page=2")
        result = envelope["result"]
        _require(isinstance(result, dict))
        rows = _page(envelope, result.get("deployments"), 1)
        if not rows:
            return None
        deployment = rows[0]
        _require(isinstance(deployment, dict))
        deployment_id = _uuid(deployment.get("id"))
        detail = self._request(self.worker_path + "/deployments/" + deployment_id)["result"]
        for value in (deployment, detail):
            _require(isinstance(value, dict) and value.get("id") == deployment_id
                     and value.get("strategy") == "percentage"
                     and value.get("versions") == [{"version_id": release["versionId"], "percentage": 100}]
                     and value.get("annotations", {}).get("workers/message")
                     == f"provider-activate/{release['revision']}/{release['artifactId']}")
            bootstrap._timestamp(value.get("created_on"))
        return detail

    def version(self, release, active):
        envelope = self._request(self.beta_path + "?page=1&per_page=2", limit=stage.MAX_VERSION_RESPONSE)
        rows = _page(envelope, envelope["result"], 1)
        _require(len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get("id") == release["versionId"])
        legacy = self._request(self.worker_path + "/versions/" + release["versionId"])["result"]
        resources = legacy.get("resources") if isinstance(legacy, dict) else None
        _require(isinstance(resources, dict) and legacy.get("id") == release["versionId"])
        image = f"{publication.HOST}/{self.account}/{provider.SERVICE}@sha256:{release['ociManifestSha256']}"
        metadata = stage._metadata(release, image)
        _require(resources.get("script_runtime", {}).get("containers") == metadata["containers"])
        namespace = None
        if active:
            bindings = resources.get("bindings")
            _require(isinstance(bindings, list))
            found = [row for row in bindings if isinstance(row, dict) and row.get("type") == "durable_object_namespace"]
            _require(len(found) == 1 and found[0].get("name") == "PROVIDER_CONTAINER"
                     and found[0].get("class_name") == "ProviderContainer"
                     and found[0].get("script_name") in (None, provider.SERVICE)
                     and found[0].get("dispatch_namespace") is None)
            binding = found[0]
            envelope = self._request("/workers/durable_objects/namespaces?page=1&per_page=1000")
            namespaces = _page(envelope, envelope["result"], 1000)
            found = [row for row in namespaces if isinstance(row, dict) and row.get("script") == provider.SERVICE]
            _require(len(found) == 1 and found[0].get("class") == "ProviderContainer" and found[0].get("use_sqlite") is True
                     and found[0].get("preview") is None and found[0].get("dispatch_namespace") is None)
            namespace = _id(found[0].get("id"))
            _require(binding.get("namespace_id") in (None, namespace))
        beta = self._request(self.beta_path + "/" + release["versionId"] + "?include=modules",
                             limit=stage.MAX_VERSION_RESPONSE)["result"]
        # Reuse static byte/metadata checks without weakening staging's undeployed verifier.
        normalized = deepcopy(beta)
        if active:
            _require(isinstance(normalized, dict) and isinstance(normalized.get("bindings"), list))
            for binding in normalized["bindings"]:
                _require(isinstance(binding, dict))
                if binding.get("type") == "durable_object_namespace":
                    _require(binding.get("namespace_id") in (None, namespace)
                             and binding.get("dispatch_namespace") is None)
                    binding.pop("namespace_id", None)
        stage._verify_version(normalized, release["versionId"], metadata, release["workerSha256"])
        return namespace

    def container(self, namespace):
        # A complete bounded inventory proves both name and namespace absence. The public
        # API does not document a specific application-not-found error code for a safe retry.
        envelope = self._request("/containers/applications?per_page=500", container=True)
        inventory = _page(envelope, envelope["result"], 500, cursor=True)
        _require(all(isinstance(row, dict) for row in inventory))
        rows = [row for row in inventory if row.get("name") == provider.SERVICE
                or (namespace is not None and row.get("id") == namespace)]
        if not rows:
            return None
        _require(namespace is not None and len(rows) == 1 and rows[0].get("id") == namespace)
        detail = self._request("/containers/applications/" + namespace, container=True)
        value = detail["result"]
        _require(isinstance(value, dict) and value.get("id") == namespace and value.get("account_id") == self.account
                 and value.get("name") == provider.SERVICE and value.get("scheduling_policy") == "durable_object"
                 and value.get("durable_objects") == {"namespace_id": namespace}
                 and value.get("observability") == {"logs": {"enabled": False}}
                 and value["observability"]["logs"]["enabled"] is False)
        configuration = value.get("configuration")
        _require(isinstance(configuration, dict) and set(configuration) <= {"authorized_keys", "wrangler_ssh"}
                 and configuration.get("authorized_keys", []) == [] and configuration.get("wrangler_ssh", False) is False)
        bootstrap._timestamp(value.get("created_at"))
        return {"applicationId": namespace, "createdAt": value["created_at"]}

    def workflow(self):
        envelope = self._request(self.workflow_path, absent=10200)
        if envelope is None:
            return None
        value = envelope["result"]
        _require(isinstance(value, dict) and value.get("name") == stage.WORKFLOW
                 and value.get("script_name") == provider.SERVICE and value.get("class_name") == "ProviderSmoke"
                 and (value.get("script_deleted") is None or value.get("script_deleted") is False)
                 and value.get("schedules", []) == [])
        pin = {"workflowId": _uuid(value.get("id")), "createdOn": value.get("created_on")}
        bootstrap._timestamp(pin["createdOn"])
        envelope = self._request(self.workflow_path + "/versions?page=1&per_page=2")
        rows = _page(envelope, envelope["result"], 1)
        _require(len(rows) == 1 and isinstance(rows[0], dict))
        pin["versionId"] = _uuid(rows[0].get("id"))
        version = self._request(self.workflow_path + "/versions/" + pin["versionId"])["result"]
        _require(isinstance(version, dict) and version.get("id") == pin["versionId"]
                 and version.get("workflow_id") == pin["workflowId"] and version.get("class_name") == "ProviderSmoke"
                 and version.get("language") == "javascript" and version.get("concurrency") == {"limit": 1})
        return pin

    def smoke_instance(self, release, workflow):
        envelope = self._request(self.workflow_path + "/instances?page=1&per_page=2")
        rows = _page(envelope, envelope["result"], 1)
        if not rows:
            return None
        instance_id = "provider-smoke-" + release["revision"]
        _require(isinstance(rows[0], dict) and rows[0].get("id") == instance_id
                 and rows[0].get("workflow_id") == workflow["workflowId"]
                 and rows[0].get("version_id") == workflow["versionId"] and rows[0].get("trigger_source") == "api")
        value = self._request(self.workflow_path + "/instances/" + instance_id + "?simple=true")["result"]
        _require(isinstance(value, dict) and value.get("versionId") == workflow["versionId"])
        return value

    def actors(self, namespace):
        envelope = self._request(f"/workers/durable_objects/namespaces/{namespace}/objects?limit=10")
        return _page(envelope, envelope["result"], 1, cursor=True)

    def instances(self, namespace, *, active=False):
        path = f"/containers/applications/{namespace}/instances-v2?per_page=2"
        if active:
            path += "&state=active"
        envelope = self._request(path, container=True)
        return _page(envelope, envelope["result"], 1, cursor=True)

    def stopped(self, namespace, start, manifest):
        actors = self.actors(namespace)
        _require(len(actors) == 1 and isinstance(actors[0], dict) and actors[0].get("hasStoredData") is True
                 and isinstance(actors[0].get("id"), str) and ACTOR.fullmatch(actors[0]["id"]))
        actor = actors[0]["id"]
        rows = self.instances(namespace)
        _require(len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get("id") == actor
                 and rows[0].get("application_id") == namespace)
        instance = self._request(f"/containers/applications/{namespace}/instances/{actor}", container=True)["result"]
        _require(isinstance(instance, dict) and instance.get("id") == actor and instance.get("application_id") == namespace)
        _require(instance.get("image") in (None, "", f"{publication.HOST}/{self.account}/{provider.SERVICE}@sha256:{manifest}"))
        status = instance.get("status")
        _require(isinstance(status, dict) and status.get("state") == "stopped"
                 and bootstrap._timestamp(status.get("updated_at")) >= bootstrap._timestamp(start)
                 and self.instances(namespace, active=True) == [])
        return _hash(actor)


def _public(url, expected_revision=None):
    request = Request(url, headers={"Accept": "application/json", "Accept-Encoding": "identity",
                                   "Cache-Control": "no-cache"}, method="GET")
    status, headers, raw = publication._response(request, build_opener(ProxyHandler({}), github._NoRedirect()), ERROR, limit=4096)
    _require(not headers.get("Location"))
    if expected_revision is None:
        _require(status in (403, 404), "The fixed provider public endpoint did not deny access.")
    else:
        _require(status == 200 and github._parse_object(raw, ERROR)
                 == {"ok": True, "service": "subs-bot", "revision": expected_revision})
    return {"status": status, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _observe(api, release):
    deployment = api.deployment(release)
    active = deployment is not None
    by_name, by_id = api.worker.by_name(), api.worker.by_id(api.identity)
    for worker in (by_name, by_id):
        _private_profile(worker, api.identity, active)
    namespace = api.version(release, active)
    for worker in (by_name, by_id):
        _references(worker, api.identity, namespace)
    state = {"activation": None, "container": api.container(namespace), "workflow": api.workflow(), "instance": None}
    if active:
        state["activation"] = {"deploymentId": deployment["id"], "namespaceId": namespace}
        if state["workflow"] is not None:
            _require(state["container"] is not None)
            state["instance"] = api.smoke_instance(release, state["workflow"])
    else:
        _require(state["container"] is None and state["workflow"] is None)
    _public(PROVIDER_URL)
    return state


def _match_pins(state, pins):
    for key in ("activation", "container", "workflow"):
        if pins[key] is not None:
            _require(pins[key] == state[key])
    _require(pins["container"] is None or pins["activation"] is not None, PIN_ERROR)
    _require(pins["workflow"] is None or pins["container"] is not None, PIN_ERROR)


def _smoke_result(instance, release, workflow, isolated_revision, health):
    _require(isinstance(instance, dict) and instance.get("status") == "complete" and instance.get("success") is True
             and instance.get("versionId") == workflow["versionId"]
             and instance.get("params") == {"providerRevision": release["revision"], "isolatedRevision": isolated_revision}
             and instance.get("error") in (None, {}) and instance.get("trigger") == {"source": "api"}
             and instance.get("schedule") is None)
    bootstrap._timestamp(instance.get("start"))
    _require(bootstrap._timestamp(instance.get("end")) >= bootstrap._timestamp(instance["start"]))
    raw = instance.get("output")
    _require(isinstance(raw, str) and len(raw) <= 2048)
    output = github._parse_object(raw, ERROR)
    _require(output.get("ok") is True and output.get("stopped") is True
             and all(type(output.get(key)) is int for key in ("edgeStatus", "bodyBytes", "blockedPrivateTargets"))
             and output == {"ok": True, "revision": release["revision"], "isolatedRevision": isolated_revision,
                       "imageSha256": release["ociManifestSha256"], "edgeStatus": 200,
                       "approvedDnsFamilies": output.get("approvedDnsFamilies"), "bodyBytes": health["bytes"],
                       "bodySha256": health["sha256"], "blockedPrivateTargets": 3, "stopped": True}
             and output["approvedDnsFamilies"] in ([4], [6], [4, 6]))
    return output


def _run(api, operation, release, pins, isolated_revision, guard):
    state = _observe(api, release)
    _match_pins(state, pins)
    if operation != "verify":
        guard()
        fresh = _observe(api, release)
        _match_pins(fresh, pins)
        _require(fresh == state, "The provider state changed before its explicit operation.")
        guard()
        if operation == "activate":
            _require(all(value is None for value in pins.values()) and state["activation"] is None)
            response = api.deploy(release)
            _require(isinstance(response, dict), WRITE_ERROR)
            created = {"deploymentId": _uuid(response.get("id"))}
        elif operation == "provision-container":
            _require(pins["activation"] is not None and pins["container"] is None
                     and pins["workflow"] is None and state["container"] is None and state["workflow"] is None)
            _require(api.actors(pins["activation"]["namespaceId"]) == [])
            guard()
            response = api.create_container(pins["activation"]["namespaceId"])
            _require(isinstance(response, dict), WRITE_ERROR)
            created = {"applicationId": _id(response.get("id")), "createdAt": response.get("created_at")}
            bootstrap._timestamp(created["createdAt"])
        elif operation == "provision-workflow":
            _require(pins["activation"] is not None and pins["container"] is not None
                     and pins["workflow"] is None and state["workflow"] is None)
            namespace = pins["activation"]["namespaceId"]
            _require(api.actors(namespace) == [] and api.instances(namespace) == [])
            guard()
            response = api.create_workflow()
            _require(isinstance(response, dict), WRITE_ERROR)
            created = {"workflowId": _uuid(response.get("id")), "createdOn": response.get("created_on"),
                       "versionId": _uuid(response.get("version_id"))}
            bootstrap._timestamp(created["createdOn"])
        else:
            _require(all(value is not None for value in pins.values()) and state["instance"] is None)
            namespace = pins["activation"]["namespaceId"]
            _require(api.actors(namespace) == [] and api.instances(namespace) == [])
            _public(HEALTH_URL, isolated_revision)
            guard()
            response = api.trigger(release, isolated_revision)
            _require(isinstance(response, dict) and response.get("id") == "provider-smoke-" + release["revision"]
                     and response.get("version_id") == pins["workflow"]["versionId"]
                     and response.get("workflow_id") == pins["workflow"]["workflowId"], WRITE_ERROR)
            created = None
        # Read retries never repeat a mutation. A partial state remains private for operator recovery.
        deadline = monotonic() + 150
        while True:
            state = _observe(api, release)
            _match_pins(state, pins)
            if operation != "smoke" or (state["instance"] is not None
                                        and state["instance"].get("status") not in {"queued", "running", "waiting"}):
                break
            _require(monotonic() < deadline, WRITE_ERROR)
            sleep(4)
        expected = {"activate": "activation", "provision-container": "container", "provision-workflow": "workflow", "smoke": "instance"}
        _require(state[expected[operation]] is not None, WRITE_ERROR)
        if created is not None:
            _require(all(state[expected[operation]].get(key) == value for key, value in created.items()), WRITE_ERROR)
    guard()
    result = {"status": "staged", "workerIdentitySha256": api.identity.fingerprint(),
              "versionSha256": _hash(release["versionId"]), "publicDenied": True}
    for key in ("activation", "container", "workflow"):
        result[key + "IdentitySha256"] = _fingerprint(state[key])
        if state[key] is not None:
            result["status"] = {"activation": "active-awaiting-container", "container": "container-awaiting-workflow",
                                "workflow": "ready-to-smoke"}[key]
    instance = state["instance"]
    if instance is not None:
        _require(all(pins[key] is not None for key in pins), "Pin the recovered resources before verifying the one-shot smoke.")
        _require(provider.REVISION.fullmatch(isolated_revision),
                 "The exact isolated Worker revision is required to verify the admitted provider smoke.")
        if instance.get("status") in {"queued", "running", "waiting"}:
            result["status"] = "smoke-running"
        else:
            health = _public(HEALTH_URL, isolated_revision)
            proof = _smoke_result(instance, release, state["workflow"], isolated_revision, health)
            result["actorSha256"] = api.stopped(state["activation"]["namespaceId"], instance["start"], release["ociManifestSha256"])
            result["status"] = "complete"
            result["stopped"] = True
            result["healthSha256"] = health["sha256"]
            result["healthBytes"] = health["bytes"]
            result["approvedDnsFamilies"] = proof["approvedDnsFamilies"]
            result["blockedPrivateTargets"] = 3
    # Detect a replacement after any long smoke poll or independent shutdown readback.
    _require(_observe(api, release) == state, "The provider state changed during verification.")
    guard()
    return result


def activate():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    operation = os.environ.get("SUBS_BOT_PROVIDER_ACTIVATION_OPERATION", "")
    isolated_revision = os.environ.get("SUBS_BOT_PROVIDER_ISOLATED_REVISION", "")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    _require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
             and os.environ.get("GITHUB_REF") == github.MAIN_REF
             and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and provider.REVISION.fullmatch(revision) and provider.DECIMAL.fullmatch(run_id)
             and runner_temp.is_absolute() and operation in OPERATIONS,
             "Provider activation requires a protected dispatch for exact main.")
    _require(operation == "verify" or os.environ.get("GITHUB_RUN_ATTEMPT") == "1",
             "Use a new read-only verification dispatch to reconcile a previous operation.")
    _require(isolated_revision == "" or provider.REVISION.fullmatch(isolated_revision), PIN_ERROR)
    _require(operation != "smoke" or provider.REVISION.fullmatch(isolated_revision), PIN_ERROR)
    identity = bootstrap._pin(os.environ.get(bootstrap.IDENTITY_ENV, ""))
    _require(identity is not None, PIN_ERROR)
    _, evidence = publication._verified_input(runner_temp, revision, run_id)
    release = _release_pin(os.environ.get(RELEASE_ENV, ""), evidence)
    pins = {
        "activation": _pin(os.environ.get(ACTIVATION_ENV, ""), ("deploymentId", "namespaceId")),
        "container": _pin(os.environ.get(CONTAINER_ENV, ""), ("applicationId", "createdAt")),
        "workflow": _pin(os.environ.get(WORKFLOW_ENV, ""), ("workflowId", "createdOn", "versionId")),
    }
    api = ProviderAPI(os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", ""),
                      os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                      os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""), identity)
    guard = lambda: publication._guard_main(evidence)
    guard()
    return {**evidence, **_run(api, operation, release, pins, isolated_revision, guard)}


def main():
    context = _binding_proof_context()
    result = activate()
    _write_binding_proof(result, *context)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ActivationError, stage.StageError, bootstrap.BootstrapError, publication.PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The private provider activation could not be verified safely.") from None

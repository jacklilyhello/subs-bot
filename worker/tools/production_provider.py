"""Explicit first-release ProviderFetch controls; no production resource is inferred from dev.

The fetch-v1 CI archive is target-neutral code and OCI bytes. Its historical service
label is verified as part of that archive, then a separately approved runtime identity
is bound to the emitted code. Existing isolation tools and pins are never rewritten.
"""

from copy import deepcopy
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys
import tempfile
from time import monotonic, sleep
from urllib.request import ProxyHandler, Request, build_opener

import activate_provider_isolation as legacy
import bootstrap_provider_worker as bootstrap
import prepare_isolation_artifact as github
import prepare_provider_artifact as provenance
import publish_provider_registry as publication
import stage_provider_version as stage

provider = publication.provider
ERROR = "The explicit ProviderFetch target, release or private state did not verify."
UNCERTAIN = "Provider mutation was not confirmed. Keep the target private and use a new verify dispatch; do not retry the mutation."
WORKFLOW_PATH = ".github/workflows/worker-production-provider.yml"
REHEARSAL_WORKFLOW_PATH = ".github/workflows/worker-production-provider-rehearsal.yml"
OPERATIONS = {"verify", "create", "publish", "stage", "activate", "provision-container", "provision-workflow", "smoke"}
SERVICES = {"production": "subs-bot-provider-fetch-prod-01", "rehearsal": "subs-bot-provider-fetch-control-drill-01"}
TAGS = {"production": "subs-bot-production-provider", "rehearsal": "subs-bot-provider-control-rehearsal"}
BUILD_FIELDS = {"revision", "runId", "runAttempt", "artifactId", "archiveSha256", "compatibilityDate", "workerSha256",
                "ociArchiveSha256", "ociManifestSha256", "ociConfigSha256"}


class ProviderError(ValueError):
    """Fixed messages only; upstream bodies and credentials stay private."""


def require(condition, message=ERROR):
    if not condition:
        raise ProviderError(message)


def read_failure(phase, status=None, envelope=None):
    """Only bounded numeric diagnostics cross the private HTTP boundary."""
    require(phase in {"transport", "response-json", "response-envelope", "absence"})
    diagnostic = {"phase": phase, "httpStatus": status if type(status) is int and 100 <= status <= 599 else None,
                  "cloudflareCodes": []}
    errors = envelope.get("errors") if isinstance(envelope, dict) else None
    if isinstance(errors, list):
        diagnostic["cloudflareCodes"] = sorted({row["code"] for row in errors[:8] if isinstance(row, dict)
            and type(row.get("code")) is int and 1000 <= row["code"] <= 999999})
    error = ProviderError("The explicit ProviderFetch GET was not confirmed. Read diagnostic "
                          + json.dumps(diagnostic, separators=(",", ":")) + ".")
    error.read_diagnostic = diagnostic
    return error


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value):
    return sha256(canonical(value)).hexdigest()


def match(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def fields(value, names):
    require(isinstance(value, dict) and set(value) == set(names))
    return value


def pin(value, names, patterns=()):
    if value is None:
        return None
    fields(value, names)
    for key, pattern in patterns:
        require(match(pattern, value[key]))
    return value


def validate_config(value, *, depth=0):
    """Pure strict contract, also used by the application's dependency preflight."""
    required = {"version", "environment", "accountId", "service", "workersDevOrigin", "worker", "build", "versionId",
                "activation", "container", "workflow", "smoke", "caller"}
    require(isinstance(value, dict) and required <= set(value) <= required | {"previous", "forwardRecovery"} and depth <= 8)
    require(type(value["version"]) is int and value["version"] == 1 and isinstance(value["environment"], str)
            and value["environment"] in SERVICES
            and value["service"] == SERVICES[value["environment"]]
            and match(publication.ACCOUNT, value["accountId"])
            and sha256(value["accountId"].encode("ascii")).hexdigest() == publication.TARGET_ACCOUNT_SHA256)
    require(isinstance(value["workersDevOrigin"], str)
            and re.fullmatch(r"https://" + re.escape(value["service"]) + r"\.[a-z0-9-]{1,63}\.workers\.dev", value["workersDevOrigin"]))
    worker = pin(value["worker"], {"workerId", "workerCreatedOn"}, (("workerId", publication.ACCOUNT),))
    if worker:
        bootstrap.Identity(worker["workerId"], worker["workerCreatedOn"])
    build = fields(value["build"], BUILD_FIELDS)
    require(match(provider.REVISION, build["revision"]) and build["compatibilityDate"] == provider.COMPATIBILITY)
    require(all(match(provider.DECIMAL, build[key]) for key in ("runId", "runAttempt", "artifactId")))
    require(all(match(provider.HEX, build[key]) for key in BUILD_FIELDS - {"revision", "runId", "runAttempt", "artifactId", "compatibilityDate"}))
    require(value["versionId"] is None or match(stage.VERSION_ID, value["versionId"]))
    active = pin(value["activation"], {"deploymentId", "namespaceId"},
                 (("deploymentId", stage.VERSION_ID), ("namespaceId", publication.ACCOUNT)))
    container = pin(value["container"], {"applicationId", "createdAt"}, (("applicationId", publication.ACCOUNT),))
    workflow = pin(value["workflow"], {"workflowId", "createdOn", "versionId"},
                   (("workflowId", stage.VERSION_ID), ("versionId", stage.VERSION_ID)))
    previous = value.get("previous")
    if previous is not None:
        previous = validate_config(previous, depth=depth + 1)
        require(all(previous[key] == value[key] for key in ("environment", "accountId", "service", "worker", "workersDevOrigin"))
                and previous["versionId"] is not None and previous["build"]["revision"] != value["build"]["revision"]
                and previous["caller"] is None,
                "Provider upgrades require an explicitly pinned previous release with no application caller.")
    effective_active = active or (previous["activation"] if previous else None)
    if container:
        bootstrap._timestamp(container["createdAt"])
        require(effective_active is not None and container["applicationId"] == effective_active["namespaceId"])
    if workflow:
        bootstrap._timestamp(workflow["createdOn"])
        require(container is not None)
    require(active is None or (worker is not None and value["versionId"] is not None))
    require(value["versionId"] is None or worker is not None)
    smoke = fields(value["smoke"], {"healthUrl", "healthRevision", "healthSha256", "healthBytes"})
    require(isinstance(smoke["healthUrl"], str) and re.fullmatch(r"https://[a-z0-9.-]+/health", smoke["healthUrl"])
            and match(provider.REVISION, smoke["healthRevision"]) and match(provider.HEX, smoke["healthSha256"])
            and type(smoke["healthBytes"]) is int and 0 < smoke["healthBytes"] <= 512)
    caller = pin(value["caller"], {"id", "name"}, (("id", publication.ACCOUNT),))
    if caller:
        require(caller["name"] == ("subs-bot-cf-prod-01" if value["environment"] == "production" else "subs-bot-cf-control-drill-01")
                and (worker is None or caller["id"] != worker["workerId"]))
    if "forwardRecovery" in value:
        recovery = validate_forward_recovery(value["forwardRecovery"])
        require(previous is not None and recovery["previousTargetSha256"] == digest(previous)
                and all(previous[key] is not None for key in ("worker", "versionId", "activation", "container", "workflow")),
                "A failed-terminal forward approval must pin the complete previous unbound target.")
    return deepcopy(value)


def validate_forward_recovery(value):
    fields(value, {"version", "sourceRunId", "sourceRunAttempt", "sourceManifestSha256", "responseIdentitySha256",
                   "previousTargetSha256", "terminalSha256"})
    require(type(value["version"]) is int and value["version"] == 1
            and all(match(provider.DECIMAL, value[key]) for key in ("sourceRunId", "sourceRunAttempt"))
            and all(match(provider.HEX, value[key]) for key in ("sourceManifestSha256", "responseIdentitySha256",
                                                               "previousTargetSha256", "terminalSha256")))
    return deepcopy(value)


def read_config(raw):
    require(isinstance(raw, str) and raw.isascii() and 0 < len(raw) <= 64 * 1024)
    return validate_config(github._parse_object(raw, ERROR))


def runtime_target(config):
    return {key: config[key] for key in ("environment", "accountId", "service")}


def image_reference(config):
    return f"{publication.HOST}/{config['accountId']}/{config['service']}@sha256:{config['build']['ociManifestSha256']}"


def metadata(config):
    build = config["build"]
    service = config["service"]
    return {"main_module": provider.WORKER, "compatibility_date": build["compatibilityDate"],
            "bindings": [{"name": "BUILD_REVISION", "type": "plain_text", "text": build["revision"]},
                         {"name": "PROVIDER_TARGET_JSON", "type": "plain_text", "text": canonical(runtime_target(config)).decode("ascii")},
                         {"name": "PROVIDER_SMOKE", "type": "workflow", "workflow_name": service + "-smoke", "class_name": "ProviderReleaseSmoke"}],
            "exports": {"ProviderContainer": {"type": "durable-object", "storage": "sqlite", "container": service},
                        "ProviderFetch": {"type": "worker"}},
            "containers": [{"name": service, "class_name": "ProviderContainer", "images": {"provider": image_reference(config)}}],
            "annotations": {"workers/tag": f"provider-{build['revision']}-{build['artifactId']}",
                            "workers/message": f"provider-ci/{build['runId']}/{build['runAttempt']}/{build['artifactId']}"}}


def releases(config):
    chain = []
    while config is not None:
        require(len(chain) <= 8)
        chain.append(config)
        config = config.get("previous")
    ids = [row["versionId"] for row in chain if row["versionId"] is not None]
    require(len(ids) == len(set(ids)), "Pinned provider release versions are not unique.")
    return chain


def verify_profile(worker, config, identity, active):
    require(isinstance(worker, dict) and worker.get("id") == identity.worker_id
            and worker.get("created_on") == identity.created_on and worker.get("name") == config["service"]
            and worker.get("tags") == [TAGS[config["environment"]]])
    require(isinstance(worker.get("subdomain"), dict) and worker["subdomain"].get("enabled") is False
            and worker["subdomain"].get("previews_enabled") is False)
    if active:
        bootstrap._timestamp(worker.get("deployed_on"))
    else:
        require(worker.get("deployed_on") is None)
    bootstrap._logging_off(worker)
    preview = worker.get("previews_base_config")
    if preview is not None:
        require(isinstance(preview, dict) and preview.get("env", {}) == {})
        bootstrap._logging_off(preview, preview=True)
    refs = worker.get("references")
    require(isinstance(refs, dict) and all(refs.get(key) == [] for key in set(bootstrap.REFERENCE_FIELDS) - {"durable_objects", "workers"})
            and all(key in bootstrap.REFERENCE_FIELDS or not item for key, item in refs.items()))
    require(refs.get("workers") == [] or (config["caller"] is not None and refs.get("workers") == [config["caller"]]))


class Shell:
    def __init__(self, api):
        self.api = api

    def by_name(self):
        return self.api._request("/workers/workers/" + self.api.service)["result"]

    def by_id(self, identity):
        return self.api._request("/workers/workers/" + identity.worker_id)["result"]


class ProviderAPI(legacy.ProviderAPI):
    """Inherit bounded inventories and single-mutation transport, with explicit identity.

    Target construction is independent of the historical isolation constructor. No
    module globals or source pins are replaced, and every inherited path uses the
    already validated account/service/immutable identity supplied here.
    """

    def __init__(self, config, worker_token, container_token=""):
        self.config = validate_config(config)
        require(match(publication.API_TOKEN, worker_token))
        require(container_token == "" or match(publication.API_TOKEN, container_token))
        self.profile = provider.FETCH_PROFILE
        self.service = config["service"]
        self.workflow_name = self.service + "-smoke"
        self.account = config["accountId"]
        self.identity = bootstrap.Identity(**{"worker_id": config["worker"]["workerId"], "created_on": config["worker"]["workerCreatedOn"]}) if config["worker"] else None
        self.base = f"{publication.API_ORIGIN}/accounts/{self.account}"
        self.worker_path = "/workers/scripts/" + self.service
        self.beta_path = "/workers/workers/" + (self.identity.worker_id if self.identity else self.service) + "/versions"
        self.workflow_path = "/workflows/" + self.workflow_name
        self._worker_token, self._container_token = worker_token, container_token
        self._worker_reads_only = False
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())
        self._writes = 0
        self.worker = Shell(self)

    def _request(self, path, *, container=False, method="GET", body=None, absent=None, limit=publication.HTTP_LIMIT):
        if method == "GET":
            return self._read(path, container=container, body=body, absent=absent, limit=limit)
        if method != "GET":
            require(isinstance(body, dict), "Provider writes require an explicit exact-target payload.")
            if method == "POST" and path == "/workers/workers":
                require(not container and self.identity is None and body.get("name") == self.service
                        and body.get("tags") == [TAGS[self.config["environment"]]])
            elif method == "POST" and path == self.worker_path + "/deployments":
                require(not container and self.config["versionId"] is not None
                        and body.get("versions") == [{"version_id": self.config["versionId"], "percentage": 100}])
            elif method == "POST" and path == "/containers/applications":
                require(container and self.config["activation"] is not None and body.get("name") == self.service
                        and body.get("durable_objects") == {"namespace_id": self.config["activation"]["namespaceId"]})
            elif method == "PUT" and path == self.workflow_path:
                require(not container and body.get("script_name") == self.service and body.get("class_name") == "ProviderReleaseSmoke")
            elif method == "POST" and path == self.workflow_path + "/instances":
                require(not container and body == {"instance_id": "provider-release-" + self.config["build"]["revision"],
                                                   "params": smoke_params(self.config)})
            else:
                raise ProviderError("Provider writes outside the exact registered target are forbidden.")
        return super()._request(path, container=container, method=method, body=body, absent=absent, limit=limit)

    def _read(self, path, *, container=False, body=None, absent=None, limit=publication.HTTP_LIMIT):
        # Keep the legacy transport's token/path and strict absence/envelope rules.
        require(body is None and (not self._worker_reads_only or not container and path.startswith("/workers/")))
        token = self._container_token if container else self._worker_token
        require(match(publication.API_TOKEN, token), "The dedicated provider read credential is missing or malformed.")
        require(path.startswith("/containers/" if container else ("/workers/", "/workflows/")))
        request = Request(self.base + path, headers={"Authorization": "Bearer " + token, "Accept": "application/json",
                                                    "Cache-Control": "no-cache"}, method="GET")
        try:
            status, _headers, raw = publication._response(request, self._opener, ERROR, limit=limit)
        except publication.PublicationError:
            raise read_failure("transport") from None
        try:
            envelope = github._parse_object(raw, ERROR)
        except github.ArtifactError:
            raise read_failure("response-json", status) from None
        if absent is not None and status == 404:
            errors = envelope.get("errors")
            valid = (envelope.get("success") is False and envelope.get("result") is None
                     and isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
                     and type(errors[0].get("code")) is int and errors[0]["code"] == absent)
            if not valid:
                raise read_failure("absence", status, envelope) from None
            return None
        if not (status == 200 and envelope.get("success") is True and envelope.get("errors") in (None, []) and "result" in envelope):
            raise read_failure("response-envelope", status, envelope) from None
        return envelope

    def by_name(self):
        return self.worker.by_name()

    def create(self):
        require(self.identity is None)
        require(self._request("/workers/workers/" + self.service, absent=10007) is None,
                "The explicit provider name is occupied; unknown resources cannot be adopted.")
        settings = {**bootstrap.CREATE_SETTINGS, "name": self.service, "tags": [TAGS[self.config["environment"]]]}
        result = self._write("/workers/workers", settings)
        require(isinstance(result, dict), UNCERTAIN)
        identity = bootstrap.Identity(result.get("id"), result.get("created_on"))
        verify_profile(self.worker.by_id(identity), self.config, identity, False)
        verify_profile(self.worker.by_name(), self.config, identity, False)
        rows = self._request(f"/workers/workers/{identity.worker_id}/versions?page=1&per_page=2")["result"]
        require(rows == [], UNCERTAIN)
        return {"workerId": identity.worker_id, "workerCreatedOn": identity.created_on}

    def versions(self):
        require(self.identity is not None)
        envelope = self._request(self.beta_path + "?page=1&per_page=10", limit=stage.MAX_VERSION_RESPONSE)
        rows = legacy._page(envelope, envelope["result"], 9)
        expected = {row["versionId"] for row in releases(self.config) if row["versionId"] is not None}
        require(all(isinstance(row, dict) for row in rows) and {row.get("id") for row in rows} == expected
                and len(rows) == len(expected), "Unknown provider versions require independent reconciliation.")
        return rows

    def wait_uploaded_version(self, candidate):
        """Only settle a just-returned candidate; ordinary inventory stays strict."""
        require(match(stage.VERSION_ID, candidate) and self.config["versionId"] == candidate)
        expected = {row["versionId"] for row in releases(self.config) if row["versionId"] is not None}
        for delay in (0, 1, 3):
            if delay:
                sleep(delay)
            envelope = self._request(self.beta_path + "?page=1&per_page=10", limit=stage.MAX_VERSION_RESPONSE)
            rows = legacy._page(envelope, envelope["result"], 9)
            require(all(isinstance(row, dict) for row in rows))
            observed = {row.get("id") for row in rows}
            require(len(observed) == len(rows), "Duplicate provider versions require independent reconciliation.")
            if observed == expected:
                return
            require(observed == expected - {candidate},
                    "Unexpected provider versions require independent reconciliation; no upload was repeated.")
        raise ProviderError("The exact uploaded provider candidate is not visible; independently reconcile without repeating upload.")

    def deployment(self, release=None):
        envelope = self._request(self.worker_path + "/deployments?page=1&per_page=100")
        require(isinstance(envelope["result"], dict))
        rows = legacy._page(envelope, envelope["result"].get("deployments"), 100)
        if not rows:
            return None
        current = rows[0]
        require(isinstance(current, dict) and match(stage.VERSION_ID, current.get("id")))
        detail = self._request(self.worker_path + "/deployments/" + current["id"])["result"]
        selected = [item for item in releases(self.config) if item["versionId"] is not None
                    and current.get("versions") == [{"version_id": item["versionId"], "percentage": 100}]]
        require(len(selected) == 1)
        build = selected[0]["build"]
        for observed in (current, detail):
            require(isinstance(observed, dict) and observed.get("id") == current["id"]
                    and observed.get("strategy") == "percentage" and observed.get("versions") == current["versions"]
                    and observed.get("annotations", {}).get("workers/message") == f"provider-activate/{build['revision']}/{build['artifactId']}")
            bootstrap._timestamp(observed.get("created_on"))
        if release is not None:
            require(release["versionId"] == selected[0]["versionId"])
        return detail

    def version(self, release, active):
        rows = self.versions()
        require(any(row.get("id") == release["versionId"] for row in rows))
        selected = [row for row in releases(self.config) if row["versionId"] == release["versionId"]]
        require(len(selected) == 1)
        desired = metadata(selected[0])
        legacy_version = self._request(self.worker_path + "/versions/" + release["versionId"])["result"]
        stage._verify_legacy_version(legacy_version, release["versionId"], desired, service=self.service)
        version = self._request(self.beta_path + "/" + release["versionId"] + "?include=modules", limit=stage.MAX_VERSION_RESPONSE)["result"]
        stage._verify_version(version, release["versionId"], desired, release["workerSha256"], service=self.service)
        envelope = self._request("/workers/durable_objects/namespaces?page=1&per_page=1000")
        namespaces = legacy._page(envelope, envelope["result"], 1000)
        found = [row for row in namespaces if isinstance(row, dict) and row.get("script") == self.service]
        if not active and not any(row["activation"] is not None for row in releases(self.config)):
            require(found == [])
            return None
        require(len(found) == 1 and found[0].get("class") == "ProviderContainer" and found[0].get("use_sqlite") is True
                and found[0].get("preview") is None and found[0].get("dispatch_namespace") is None
                and match(publication.ACCOUNT, found[0].get("id")))
        return found[0]["id"]

    def upload(self, module):
        require(self.config["versionId"] is None)
        self.versions()
        content_type, body = stage._multipart(metadata(self.config), module)
        require(self._writes == 0, UNCERTAIN)
        self._writes += 1
        _, envelope = stage._json_request(self.base + self.worker_path + "/versions?bindings_inherit=strict", self._opener,
                                         self._worker_token, UNCERTAIN, content_type=content_type, body=body, statuses=(200, 201))
        candidate = envelope["result"].get("id")
        require(match(stage.VERSION_ID, candidate), UNCERTAIN)
        return candidate

    def create_workflow(self):
        return self._write(self.workflow_path, {"script_name": self.service, "class_name": "ProviderReleaseSmoke",
                           "schedules": [], "concurrency": {"limit": 1}}, method="PUT")

    def workflow(self):
        envelope = self._request(self.workflow_path, absent=10200)
        if envelope is None:
            return None
        value = envelope["result"]
        require(isinstance(value, dict) and value.get("name") == self.workflow_name
                and value.get("script_name") == self.service and value.get("class_name") == "ProviderReleaseSmoke"
                and value.get("script_deleted") in (None, False) and value.get("schedules", []) == [])
        identity = {"workflowId": legacy._uuid(value.get("id")), "createdOn": value.get("created_on")}
        bootstrap._timestamp(identity["createdOn"])
        envelope = self._request(self.workflow_path + "/versions?page=1&per_page=10")
        rows = legacy._page(envelope, envelope["result"], 9)
        require(rows and all(isinstance(row, dict) for row in rows))
        identity["versionId"] = legacy._uuid(rows[0].get("id"))
        version = self._request(self.workflow_path + "/versions/" + identity["versionId"])["result"]
        require(isinstance(version, dict) and version.get("id") == identity["versionId"]
                and version.get("workflow_id") == identity["workflowId"] and version.get("class_name") == "ProviderReleaseSmoke"
                and version.get("language") == "javascript" and version.get("concurrency") == {"limit": 1})
        return identity

    def smoke_instance(self, release, workflow):
        envelope = self._request(self.workflow_path + "/instances?page=1&per_page=10")
        rows = legacy._page(envelope, envelope["result"], 9)
        if not rows:
            return None
        instance_id = "provider-release-" + release["revision"]
        allowed = {"provider-release-" + row["build"]["revision"] for row in releases(self.config)}
        require(all(isinstance(row, dict) and row.get("id") in allowed for row in rows))
        found = [row for row in rows if row.get("id") == instance_id]
        if not found:
            return None
        require(len(found) == 1 and found[0].get("workflow_id") == workflow["workflowId"]
                and found[0].get("version_id") == workflow["versionId"] and found[0].get("trigger_source") == "api")
        result = self._request(self.workflow_path + "/instances/" + instance_id + "?simple=true")["result"]
        require(isinstance(result, dict) and result.get("versionId") == workflow["versionId"])
        return result

    def trigger(self, release, ignored=None):
        return self._write(self.workflow_path + "/instances", {"instance_id": "provider-release-" + release["revision"],
                           "params": smoke_params(self.config)})


class Registry(publication.Registry):
    def __init__(self, config, token):
        # Reuse the bounded OCI auth/digest implementation, with a validated exact repository.
        require(match(publication.API_TOKEN, token))
        self._account, self._api_token = config["accountId"], token
        self.repository = config["accountId"] + "/" + config["service"]
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())
        self._read_authorization = None


class PublishedImage(stage.PublishedImage):
    def __init__(self, config, token, scratch):
        self._registry = Registry(config, token)
        self._token = token
        self._url = f"{publication.API_ORIGIN}/accounts/{config['accountId']}/containers/image-preparations"
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())
        self._scratch = scratch
        self._manifest, self._config = config["build"]["ociManifestSha256"], config["build"]["ociConfigSha256"]
        self.reference = image_reference(config)


def smoke_params(config):
    return {"providerRevision": config["build"]["revision"], "imageSha256": config["build"]["ociManifestSha256"],
            **{key: config["smoke"][key] for key in ("healthUrl", "healthRevision", "healthSha256")}}


def public_denied(config):
    legacy._public(config["workersDevOrigin"] + "/health")


def observe(api, *, need_smoke=False):
    config = api.config
    require(api.identity is not None)
    api.versions()
    deployment = api.deployment()
    active_config, namespace = None, None
    if deployment is not None:
        active_id = deployment["versions"][0]["version_id"]
        active_config = next((row for row in releases(config) if row["versionId"] == active_id), None)
        require(active_config is not None)
    for source in releases(config):
        if source["versionId"] is not None:
            found = api.version({**source["build"], "versionId": source["versionId"]}, source is active_config)
            if source is active_config:
                namespace = found
    for worker in (api.by_name(), api.worker.by_id(api.identity)):
        verify_profile(worker, config, api.identity, deployment is not None)
        legacy._references(worker, api.identity, namespace, service=config["service"])
    state = {"activation": {"deploymentId": deployment["id"], "namespaceId": namespace} if deployment else None,
             "container": api.container(namespace), "workflow": api.workflow(), "instance": None}
    if state["workflow"]:
        require(state["container"] is not None)
        require(active_config is not None)
        state["instance"] = api.smoke_instance({**active_config["build"], "versionId": active_config["versionId"]}, state["workflow"])
    require(deployment is not None or all(value is None for value in state.values()))
    public_denied(config)
    for key in ("activation", "container", "workflow"):
        # A non-null pin is mandatory before the next dependent operation. An unpinned
        # newly-created resource is shown by verify for independent reconciliation only.
        if config[key] is not None:
            require(state[key] == config[key])
    if need_smoke:
        require(all(config[key] is not None for key in ("activation", "container", "workflow")))
        require(active_config is config, "The staged ProviderFetch release has not been activated.")
        verify_smoke(api, state)
    return state


def verify_smoke(api, state, *, config=None):
    instance = state["instance"]
    config = api.config if config is None else config
    require(isinstance(instance, dict) and instance.get("status") == "complete" and instance.get("success") is True
            and instance.get("versionId") == config["workflow"]["versionId"] and instance.get("params") == smoke_params(config)
            and instance.get("error") in (None, {}) and instance.get("trigger") == {"source": "api"} and instance.get("schedule") is None)
    start, end = bootstrap._timestamp(instance.get("start")), bootstrap._timestamp(instance.get("end"))
    require(end >= start)
    output = instance.get("output")
    if isinstance(output, str):
        require(len(output) <= 2048)
        output = github._parse_object(output, ERROR)
    require(output == {"ok": True, "stopped": True, "revision": config["build"]["revision"],
                       "imageSha256": config["build"]["ociManifestSha256"], "healthRevision": config["smoke"]["healthRevision"],
                       "healthSha256": config["smoke"]["healthSha256"], "healthBytes": config["smoke"]["healthBytes"], "blockedPrivateTargets": 3,
                       "rpcVerified": True})
    return api.stopped(config["activation"]["namespaceId"], instance["start"], config["build"]["ociManifestSha256"])


def config_source_for_state(config, state):
    instance = state.get("instance")
    require(isinstance(instance, dict))
    selected = [source for source in releases(config) if instance.get("params") == smoke_params(source)]
    require(len(selected) == 1)
    return selected[0]


def unbound_upgrade(api, state):
    """A first dependency may be repaired before it has any application caller.

    An already-bound consumer requires a separate application freeze/release plan;
    this tool never guesses that the caller is paused from an empty HTTP sample.
    """
    config = api.config
    previous = config.get("previous")
    require(previous is not None and config["caller"] is None and previous["caller"] is None)
    for worker in (api.by_name(), api.worker.by_id(api.identity)):
        require(worker.get("references", {}).get("workers") == [], "Bound ProviderFetch cannot be upgraded without a separately reviewed frozen-caller plan.")
    require(state["activation"] == previous["activation"])
    require(state["container"] == previous["container"] and state["workflow"] == previous["workflow"],
            "The unbound provider resource identities changed before upgrade.")
    if previous["activation"] is not None:
        require(previous["container"] is not None and previous["workflow"] is not None)
        old_instance = api.smoke_instance({**previous["build"], "versionId": previous["versionId"]}, previous["workflow"])
        verify_previous_terminal(api, previous, old_instance)
    else:
        require(state["container"] is None and state["workflow"] is None)


def verify_previous_terminal(api, previous, old_instance):
    recovery = api.config.get("forwardRecovery")
    if recovery is None:
        return verify_smoke(api, {"instance": old_instance}, config=previous)
    from production_provider_terminal import verify_forced_terminal
    require(recovery["previousTargetSha256"] == digest(previous) and api.config["caller"] is None
            and previous["caller"] is None and api.config["build"]["revision"] != previous["build"]["revision"])
    # This proof is solely an upgrade precondition. The ordinary stopped/smoke
    # verifier remains strict, and the previous failed release is never passed.
    result = verify_forced_terminal(api, previous, current_config=api.config)
    require(digest(result) == recovery["terminalSha256"], "The preserved failed terminal changed before forward recovery.")
    return result


def run_operation(api, operation, module, image, guard):
    require(operation in OPERATIONS - {"publish", "create"})
    state = observe(api)
    if operation == "verify":
        if state["instance"] is not None and state["instance"].get("status") not in {"queued", "running", "waiting"}:
            source = config_source_for_state(api.config, state)
            verify_smoke(api, state, config=source)
        guard()
        require(observe(api) == state, "The explicit provider state changed during independent verification.")
        return state
    guard()
    require(observe(api) == state, "The explicit provider state changed before mutation.")
    config = api.config
    if operation == "stage":
        require(config["versionId"] is None)
        if config.get("previous") is None:
            require(all(item is None for item in state.values()))
        else:
            unbound_upgrade(api, state)
        image.verify()
        image.prepare(guard)
        require(observe(api) == state)
        guard()
        candidate = api.upload(module)
        # Do not silently create the identity pin; report it for independent readback.
        api.config = {**config, "versionId": candidate}
        api.wait_uploaded_version(candidate)
        result = observe(api)
        require(result == state, UNCERTAIN)
        return {**result, "versionId": candidate}
    require(config["versionId"] is not None)
    if operation == "activate":
        if config.get("previous") is None:
            require(all(config[key] is None and state[key] is None for key in ("activation", "container", "workflow")))
        else:
            require(config["activation"] is None)
            unbound_upgrade(api, state)
        api.deploy({**config["build"], "versionId": config["versionId"]})
    elif operation == "provision-container":
        require(config["activation"] is not None and config["container"] is None and state["container"] is None
                and state["workflow"] is None and config["workflow"] is None)
        require(api.actors(config["activation"]["namespaceId"]) == [])
        api.create_container(config["activation"]["namespaceId"])
    elif operation == "provision-workflow":
        require(config["container"] is not None and config["workflow"] is None and state["workflow"] is None)
        require(api.actors(config["activation"]["namespaceId"]) == [] and api.instances(config["activation"]["namespaceId"]) == [])
        api.create_workflow()
    else:
        require(operation == "smoke" and all(config[key] is not None for key in ("activation", "container", "workflow"))
                and state["instance"] is None)
        if config.get("previous") and config["previous"]["activation"] is not None:
            require(config["caller"] is None)
            previous = config["previous"]
            old_instance = api.smoke_instance({**previous["build"], "versionId": previous["versionId"]}, previous["workflow"])
            verify_previous_terminal(api, previous, old_instance)
        else:
            require(api.actors(config["activation"]["namespaceId"]) == [] and api.instances(config["activation"]["namespaceId"]) == [])
        api.trigger({**config["build"], "versionId": config["versionId"]})
    deadline = monotonic() + 600
    while True:
        result = observe(api)
        if operation != "smoke" or (result["instance"] is not None and result["instance"].get("status") not in {"queued", "running", "waiting"}):
            break
        require(monotonic() < deadline, UNCERTAIN)
        sleep(4)
    expected = {"activate": "activation", "provision-container": "container", "provision-workflow": "workflow", "smoke": "instance"}
    require(result[expected[operation]] is not None, UNCERTAIN)
    if operation == "smoke":
        verify_smoke(api, result)
    guard()
    require(observe(api) == result, UNCERTAIN)
    return result


def caller_state(api, config, allow_unbound):
    require(type(allow_unbound) is bool)
    caller = config["caller"]
    require(caller is not None or allow_unbound, "A bound ProviderFetch dependency requires the exact application caller pin.")
    inventories = []
    for worker in (api.by_name(), api.worker.by_id(api.identity)):
        verify_profile(worker, config, api.identity, True)
        workers = worker["references"]["workers"]
        require((caller is not None and workers == [caller]) or (allow_unbound and workers == []),
                "The ProviderFetch caller is not bound to the exact approved application identity.")
        inventories.append(workers)
    require(inventories[0] == inventories[1], "ProviderFetch caller references changed during readback.")
    return "unbound" if inventories[0] == [] else "bound"


def verify_provider_dependency(api, target_provider, *, allow_unbound_caller=False):
    """Read a fully pinned dependency. No registry/Container write credential is needed.

    ``api`` may be an existing ProviderAPI or an object with request(method,path,payload,envelope=True).
    The caller's Cloudflare reader must cover Workers, Workflows and Containers reads.
    This function never binds the caller or changes provider state.
    """
    config = validate_config(target_provider)
    require(config["worker"] is not None and config["versionId"] is not None)
    require(type(allow_unbound_caller) is bool and (config["caller"] is not None or allow_unbound_caller),
            "A bound ProviderFetch dependency requires the exact application caller pin.")
    if not isinstance(api, ProviderAPI):
        api = DependencyReader(config, api)
    require(api.config == config)
    first = observe(api, need_smoke=True)
    caller = caller_state(api, config, allow_unbound_caller)
    require(observe(api, need_smoke=True) == first)
    require(caller_state(api, config, allow_unbound_caller) == caller)
    return {"service": config["service"], "entrypoint": "ProviderFetch", "revision": config["build"]["revision"],
            "imageSha256": config["build"]["ociManifestSha256"], "callerState": caller,
            "proofSha256": digest({"target": config, "state": first, "callerState": caller})}


class DependencyReader(ProviderAPI):
    def __init__(self, config, reader):
        # No token is retained in this adapter. All access stays inside the caller's client.
        self.config, self.reader = validate_config(config), reader
        self.service, self.account = config["service"], config["accountId"]
        self.identity = bootstrap.Identity(config["worker"]["workerId"], config["worker"]["workerCreatedOn"])
        self.worker_path = "/workers/scripts/" + self.service
        self.beta_path = "/workers/workers/" + self.identity.worker_id + "/versions"
        self.workflow_name = self.service + "-smoke"
        self.workflow_path = "/workflows/" + self.workflow_name
        self.worker = Shell(self)

    def _request(self, path, *, container=False, method="GET", body=None, absent=None, limit=publication.HTTP_LIMIT):
        require(method == "GET" and body is None)
        envelope = self.reader.request("GET", "/accounts/" + self.account + path, envelope=True)
        require(isinstance(envelope, dict) and envelope.get("success") is True and "result" in envelope)
        require(len(canonical(envelope)) <= limit)
        return envelope


def request_context(operation, config):
    revision = os.environ.get("GITHUB_SHA", "")
    allowed_workflows = {f"{github.REPOSITORY}/{WORKFLOW_PATH}@{github.MAIN_REF}"}
    if config["environment"] == "rehearsal":
        allowed_workflows.add(f"{github.REPOSITORY}/{REHEARSAL_WORKFLOW_PATH}@{github.MAIN_REF}")
    require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY and os.environ.get("GITHUB_REF") == github.MAIN_REF
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("GITHUB_WORKFLOW_SHA") == revision and match(provider.REVISION, revision)
            and os.environ.get("GITHUB_WORKFLOW_REF") in allowed_workflows)
    require(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_ENVIRONMENT") == config["environment"])
    require(match(provider.REVISION, config["build"]["revision"]))
    if operation != "verify":
        require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "A mutation cannot be retried; dispatch verify to reconcile.")
        require(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_APPROVAL") == digest({"operation": operation, "target": config}),
                "The exact ProviderFetch operation and full target configuration were not approved.")


def guard_sources(config):
    """Separate the current reviewed controller from each frozen main-ancestor source."""
    current = os.environ.get("GITHUB_SHA", "")
    require(match(provider.REVISION, current))
    github.require_current_main(current)
    token = github._github_token()
    for source in releases(config):
        build = source["build"]
        revision = build["revision"]
        if revision != current:
            comparison = github.compare_commits_metadata(revision, current, token)
            require(comparison.get("status") == "ahead" and type(comparison.get("ahead_by")) is int
                    and comparison["ahead_by"] > 0 and type(comparison.get("behind_by")) is int and comparison["behind_by"] == 0
                    and all(isinstance(comparison.get(key), dict) and comparison[key].get("sha") == revision
                            for key in ("base_commit", "merge_base_commit")),
                    "The frozen provider source is not an exact reviewed main ancestor.")
        require(provenance._select_artifact(build["runId"], revision, token)
                == (build["runAttempt"], build["artifactId"], build["archiveSha256"]),
                "The frozen source CI attempt or archive digest changed.")
    github.require_current_main(current)


def prepare_input():
    config = read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    operation = os.environ.get("SUBS_BOT_PROVIDER_CONTROL_OPERATION", "")
    require(operation in OPERATIONS)
    request_context(operation, config)
    guard_sources(config)
    evidence = provenance.prepare(provider_revision=config["build"]["revision"])
    require(evidence == config["build"])
    print(json.dumps(evidence, sort_keys=True))


def verify_previous_archives(config, scratch):
    token = github._github_token()
    for index, source in enumerate(releases(config)[1:], start=1):
        build = source["build"]
        directory = scratch / f"source-{index}"
        directory.mkdir(mode=0o700)
        archive = directory / "artifact.zip"
        provenance._download_zip(build["artifactId"], token, build["archiveSha256"], archive)
        extracted = directory / "verified"
        extracted.mkdir(mode=0o700)
        provenance._unpack(archive, extracted)
        manifest = provider.verify_release(extracted, build["revision"], ref=github.MAIN_REF,
                                           run_id=build["runId"], run_attempt=build["runAttempt"])
        require(all(manifest[key] == build[key] for key in publication.MANIFEST_FIELDS),
                "A frozen previous release differs from its verified source archive.")


def publish_image(config, scratch, archive, guard):
    registry = Registry(config, os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))
    build = config["build"]
    manifest, image_config = build["ociManifestSha256"], build["ociConfigSha256"]
    tag = f"git-{build['revision']}-{manifest[:12]}"
    repository = f"{publication.HOST}/{registry.repository}"
    pull = registry.mint()
    observed = registry.manifest(tag, pull, allow_missing=True)
    status = "verified-existing"
    if observed is None:
        push_auth = publication._write_auth(scratch / "push-auth.json", registry.mint(push=True), registry.repository)
        require(registry.manifest(tag, pull, allow_missing=True) is None, "The exact provider revision tag changed before publication.")
        guard()
        publication._copy(scratch, archive, repository + ":" + tag, push_auth, "sha256:" + manifest)
        status = "published"
    else:
        require(observed == manifest, "The exact provider revision tag contains different bytes.")
    pull_auth = publication._write_auth(scratch / "pull-auth.json", pull, registry.repository)
    require(registry.manifest("sha256:" + manifest, pull) == manifest
            and publication._config(scratch, repository + "@sha256:" + manifest, pull_auth) == image_config
            and registry.manifest(tag, pull) == manifest)
    guard()
    return {"status": status, "repositorySha256": sha256(repository.encode("ascii")).hexdigest(),
            "imageReferenceSha256": sha256(image_reference(config).encode("ascii")).hexdigest()}


def main():
    operation = os.environ.get("SUBS_BOT_PROVIDER_CONTROL_OPERATION", "")
    require(operation in OPERATIONS)
    config = read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    request_context(operation, config)
    revision = config["build"]["revision"]
    archive, evidence = publication._verified_input(Path(os.environ.get("RUNNER_TEMP", "")), revision, config["build"]["runId"])
    require(evidence == config["build"])
    guard = lambda: guard_sources(config)
    guard()
    module = provider.checked_file(archive.with_name(provider.WORKER), provider.MAX_WORKER).read_bytes()
    require(sha256(module).hexdigest() == config["build"]["workerSha256"])
    api = ProviderAPI(config, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                      os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))
    with tempfile.TemporaryDirectory(prefix=".subs-bot-explicit-provider-", dir=os.environ["RUNNER_TEMP"]) as directory:
        scratch = Path(directory)
        verify_previous_archives(config, scratch)
        if operation == "publish":
            result = publish_image(config, scratch, archive, guard)
        elif operation == "create":
            guard()
            result = {"worker": api.create()}
            guard()
        else:
            result = run_operation(api, operation, module, PublishedImage(config, api._container_token, scratch), guard)
    result = {"operation": operation, "environment": config["environment"], "service": config["service"],
              "targetSha256": digest(config), "build": evidence, "observed": result}
    path = Path(os.environ["RUNNER_TEMP"]) / "production-provider-evidence.json"
    with provenance._write_private(path) as output:
        output.write(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        if sys.argv[1:] == ["prepare"]:
            prepare_input()
        else:
            require(not sys.argv[1:])
            main()
    except (ProviderError, legacy.ActivationError, bootstrap.BootstrapError, stage.StageError,
            publication.PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit(ERROR) from None

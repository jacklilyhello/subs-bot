"""Create or verify the one empty, private Worker reserved for Provider Fetch."""

from dataclasses import dataclass
from datetime import datetime
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from urllib.request import ProxyHandler, Request, build_opener

import prepare_isolation_artifact as github
from publish_provider_registry import (
    ACCOUNT,
    API_ORIGIN,
    API_TOKEN,
    TARGET_ACCOUNT_SHA256,
    PublicationError,
    _guard_main,
    _response,
    _verified_input,
    provider,
)


OWNERSHIP_TAG = "subs-bot-provider-isolation"
API_STATUS_OWNERSHIP_TAG = "subs-bot-provider-api-status-isolation"
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z")
IDENTITY_ENV = "SUBS_BOT_CF_PROVIDER_WORKER_IDENTITY_JSON"
REFERENCE_FIELDS = ("dispatch_namespace_outbounds", "domains", "durable_objects", "queues", "workers")
READ_ERROR = "The private provider Worker could not be read conclusively."
CREATE_ERROR = "Private provider Worker creation was not confirmed. Inspect the exact target before another attempt."
PROFILE_ERROR = "The provider Worker does not have the expected private, empty settings."
OBSERVABILITY_OFF = {
    "enabled": False,
    "issues": {"enabled": False},
    "logs": {"enabled": False, "invocation_logs": False, "persist": False, "destinations": []},
    "traces": {"enabled": False, "persist": False, "destinations": []},
}
CREATE_SETTINGS = {
    "name": provider.SERVICE,
    "subdomain": {"enabled": False, "previews_enabled": False},
    "logpush": False,
    "observability": OBSERVABILITY_OFF,
    "tail_consumers": [],
    "tags": [OWNERSHIP_TAG],
    "previews_base_config": {"logpush": False, "observability": OBSERVABILITY_OFF, "tail_consumers": []},
}


class BootstrapError(ValueError):
    """Failure with a fixed message suitable for public Actions logs."""


def _require(condition, message):
    if not condition:
        raise BootstrapError(message)


def _settings(profile):
    if profile == provider.FETCH_PROFILE:
        return CREATE_SETTINGS
    _require(profile == provider.API_STATUS_PROFILE, "Unknown provider Worker profile.")
    return {**CREATE_SETTINGS, "name": provider.API_STATUS_SERVICE, "tags": [API_STATUS_OWNERSHIP_TAG]}


def _timestamp(value):
    if isinstance(value, str) and TIMESTAMP.fullmatch(value):
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
    raise BootstrapError("The provider Worker identity has an invalid timestamp.")


@dataclass(frozen=True)
class Identity:
    worker_id: str
    created_on: str

    def __post_init__(self):
        _require(isinstance(self.worker_id, str) and ACCOUNT.fullmatch(self.worker_id),
                 "The provider Worker identity has an invalid immutable ID.")
        _timestamp(self.created_on)

    def fingerprint(self):
        return sha256(f"{self.worker_id}\n{self.created_on}".encode("ascii")).hexdigest()


def _pin(value):
    if not value:
        return None
    error = "The protected provider Worker identity pin is invalid."
    _require(len(value) <= 512, error)
    obj = github._parse_object(value, error)
    _require(set(obj) == {"workerId", "workerCreatedOn"}, error)
    return Identity(obj["workerId"], obj["workerCreatedOn"])


def _identity(worker, *, profile=provider.FETCH_PROFILE):
    _require(isinstance(worker, dict) and worker.get("name") == _settings(profile)["name"],
             "The provider Worker name did not match the fixed target.")
    identity = Identity(worker.get("id"), worker.get("created_on"))
    _require(_timestamp(worker.get("updated_on")) >= _timestamp(identity.created_on),
             "The provider Worker update timestamp precedes its creation.")
    return identity


def _logging_off(settings, *, preview=False):
    observability = settings.get("observability")
    tail_consumers = settings.get("tail_consumers", [] if preview else None)
    _require(settings.get("logpush") is False and tail_consumers == []
             and isinstance(observability, dict) and observability.get("enabled") is False, PROFILE_ERROR)
    issues = observability.get("issues")
    _require(issues is None or (isinstance(issues, dict) and issues.get("enabled") is False), PROFILE_ERROR)
    for field in ("logs", "traces"):
        stream = observability.get(field)
        _require(isinstance(stream, dict) and stream.get("enabled") is False
                 and stream.get("destinations", []) == [], PROFILE_ERROR)
    latent_flags = (observability["logs"].get("invocation_logs", False), observability["logs"].get("persist", False),
                    observability["traces"].get("persist", False))
    explicitly_disabled = all(flag is False for flag in latent_flags)
    # Cloudflare returns these dormant defaults on the main Worker even when both streams are disabled.
    inactive_main_defaults = not preview and all(flag is True for flag in latent_flags)
    _require(explicitly_disabled or inactive_main_defaults, PROFILE_ERROR)


def _verify_profile(worker, expected, *, profile=provider.FETCH_PROFILE):
    _require(_identity(worker, profile=profile) == expected, "The private provider Worker did not match its pinned identity.")
    subdomain = worker.get("subdomain")
    references = worker.get("references")
    _require(isinstance(subdomain, dict) and subdomain.get("enabled") is False
             and subdomain.get("previews_enabled") is False and worker.get("tags") == _settings(profile)["tags"]
             and worker.get("deployed_on") is None and isinstance(references, dict)
             and all(references.get(key) == [] for key in REFERENCE_FIELDS), PROFILE_ERROR)
    _logging_off(worker)
    preview = worker.get("previews_base_config")
    if preview is not None:
        _require(isinstance(preview, dict) and preview.get("env", {}) == {}, PROFILE_ERROR)
        _logging_off(preview, preview=True)


class WorkerAPI:
    """Only the fixed Worker shell may be created. Other operations are exact reads."""

    def __init__(self, account, token, *, profile=provider.FETCH_PROFILE):
        _require(ACCOUNT.fullmatch(account) and sha256(account.encode("ascii")).hexdigest() == TARGET_ACCOUNT_SHA256,
                 "The protected Cloudflare account does not match the provider target.")
        _require(API_TOKEN.fullmatch(token), "The dedicated Cloudflare Workers credential is missing or malformed.")
        self._settings = _settings(profile)
        self.profile = profile
        self._workers = f"{API_ORIGIN}/accounts/{account}/workers/workers"
        self._token = token
        self._opener = build_opener(ProxyHandler({}), github._NoRedirect())

    def _request(self, url, *, create=False, absent=False):
        error = CREATE_ERROR if create else READ_ERROR
        headers = {"Authorization": f"Bearer {self._token}", "Accept": "application/json",
                   "Cache-Control": "no-cache"}
        data = None
        if create:
            headers["Content-Type"] = "application/json"
            data = json.dumps(self._settings, separators=(",", ":")).encode("ascii")
        request = Request(url, data=data, headers=headers, method="POST" if create else "GET")
        status, _, raw = _response(request, self._opener, error)
        envelope = github._parse_object(raw, error)
        if absent and status == 404:
            errors = envelope.get("errors")
            _require(envelope.get("success") is False and envelope.get("result") is None
                     and isinstance(errors, list) and len(errors) == 1 and isinstance(errors[0], dict)
                     and type(errors[0].get("code")) is int and errors[0]["code"] == 10007, error)
            return None
        _require(status in ({200, 201} if create else {200}) and envelope.get("success") is True
                 and envelope.get("errors") in (None, []) and "result" in envelope, error)
        return envelope

    def by_name(self, *, absent=False):
        result = self._request(f"{self._workers}/{self._settings['name']}", absent=absent)
        if result is None:
            return None
        _require(isinstance(result["result"], dict), READ_ERROR)
        return result["result"]

    def by_id(self, identity):
        return self._request(f"{self._workers}/{identity.worker_id}")["result"]

    def create(self):
        return self._request(self._workers, create=True)["result"]

    def require_no_versions(self, identity):
        result = self._request(f"{self._workers}/{identity.worker_id}/versions?page=1&per_page=1")
        pagination = result.get("result_info", {})
        _require(result["result"] == [] and isinstance(pagination, dict)
                 and all(type(pagination.get(key)) is int and pagination[key] == expected
                         for key, expected in (("count", 0), ("total_count", 0), ("page", 1), ("per_page", 1))), PROFILE_ERROR)


def _bootstrap(api, action, pin, guard, *, profile=provider.FETCH_PROFILE):
    _require(api.profile == profile, "The provider Worker client profile does not match the requested shell.")
    if action == "create":
        _require(pin is None, "The protected provider Worker is already pinned. Use verification.")
        _require(api.by_name(absent=True) is None, "The exact provider Worker name is occupied. Creation refused.")
        guard()
        _require(api.by_name(absent=True) is None, "The exact provider Worker name became occupied. Creation refused.")
        try:
            expected = _identity(api.create(), profile=profile)
        except (BootstrapError, PublicationError, github.ArtifactError):
            raise BootstrapError(CREATE_ERROR) from None
        status = "created"
    else:
        _require(action == "verify" and pin is not None, "Verification requires the protected provider Worker identity pin.")
        expected = pin
        _verify_profile(api.by_name(), expected, profile=profile)
        status = "verified"
    _verify_profile(api.by_id(expected), expected, profile=profile)
    api.require_no_versions(expected)
    _verify_profile(api.by_name(), expected, profile=profile)
    guard()
    return status, expected


def bootstrap():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    action = os.environ.get("SUBS_BOT_PROVIDER_WORKER_ACTION", "")
    _require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
             and os.environ.get("GITHUB_REF") == github.MAIN_REF
             and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
             and provider.REVISION.fullmatch(revision) and provider.DECIMAL.fullmatch(run_id)
             and runner_temp.is_absolute() and action in {"create", "verify"},
             "Provider Worker bootstrap requires a protected dispatch from the exact main revision.")
    pin = _pin(os.environ.get(IDENTITY_ENV, ""))
    _require((action == "create") == (pin is None),
             "Provider Worker creation requires no pin. Verification requires an existing pin.")
    api = WorkerAPI(os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", ""),
                    os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""))
    _, evidence = _verified_input(runner_temp, revision, run_id)
    _guard_main(evidence)
    status, identity = _bootstrap(api, action, pin, lambda: _guard_main(evidence))
    return {"status": status, "service": provider.SERVICE, "ownershipTag": OWNERSHIP_TAG,
            "workerIdentitySha256": identity.fingerprint(), "revision": revision, "artifactId": evidence["artifactId"],
            "workersDev": False, "previews": False, "logging": False, "versions": 0}


if __name__ == "__main__":
    try:
        print(json.dumps(bootstrap(), sort_keys=True))
    except (BootstrapError, PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The private provider Worker bootstrap could not be completed safely.") from None

"""Release an already verified bundle to the one project-owned isolated Worker."""

from __future__ import annotations

import base64
from dataclasses import dataclass, replace
from hashlib import sha256
from http.client import HTTPException
import json
from pathlib import Path
import re
from time import sleep
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from uuid import uuid4


WORKER_NAME = "subs-bot-cf-dev-01"
NAMESPACE = "lilyya"
TELEGRAM_CONFIG_BINDING = "TELEGRAM_ISOLATION_CONFIG"
TELEGRAM_DIGEST_BINDING = "TELEGRAM_CONFIG_SHA256"
INLINE_SEARCH_BINDING = "TELEGRAM_INLINE_SEARCH"
INLINE_SEARCH_MIGRATION = "0025_telegram_personal_inline.sql"
INLINE_SEARCH_MIGRATION_SHA256 = "2c504b14ca94597925b1703d2f50d211d29addaff8f139b5411be5fd2306b122"
AGGREGATE_KEY_BINDING = "TELEGRAM_AGGREGATE_KEY"
AGGREGATE_DIGEST_BINDING = "TELEGRAM_AGGREGATE_KEY_SHA256"
PRIVATE_SHARE_KEY_BINDING = "TELEGRAM_PRIVATE_SHARE_CREATION_KEY"
PRIVATE_SHARE_DIGEST_BINDING = "TELEGRAM_PRIVATE_SHARE_CREATION_KEY_SHA256"
TELEGRAM_CRON = "* * * * *"
TELEGRAM_BINDINGS = {TELEGRAM_CONFIG_BINDING, TELEGRAM_DIGEST_BINDING}
AGGREGATE_BINDINGS = {AGGREGATE_KEY_BINDING, AGGREGATE_DIGEST_BINDING}
PRIVATE_SHARE_BINDINGS = {PRIVATE_SHARE_KEY_BINDING, PRIVATE_SHARE_DIGEST_BINDING}
PROVIDER_SERVICE = "subs-bot-provider-fetch-dev-01"
PROVIDER_ENTRYPOINT = "ProviderFetch"
PROVIDER_BINDINGS = {"PROVIDER_FETCH", "PROVIDER_REVISION", "PROVIDER_IMAGE_SHA256"}
PROVIDER_MESSAGE = "Reviewed isolated Worker release provider "
_UNSPECIFIED_TELEGRAM_CONFIG = object()
_UNSPECIFIED_AGGREGATE_KEY = object()
_UNSPECIFIED_PRIVATE_SHARE_KEY = object()
_UNSPECIFIED_PROVIDER_BINDING = object()
ORIGIN = f"https://{WORKER_NAME}.{NAMESPACE}.workers.dev"
HEALTH_URL = ORIGIN + "/health"
API_ORIGIN = "https://api.cloudflare.com/client/v4"
HEX_ID = re.compile(r"[0-9a-f]{32}")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
REVISION = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
TIMESTAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z")
SAFE_PATH = re.compile(r"/[A-Za-z0-9/_.%?=&,~-]+")
SCHEDULE_PATH = re.compile(rf"/accounts/{HEX_ID.pattern}/workers/scripts/{WORKER_NAME}/schedules")
MAX_MODULE_BYTES = 1024 * 1024
MAX_API_BYTES = 8 * 1024 * 1024
MAX_TELEGRAM_CONFIG_BYTES = 5000
READBACK_DELAYS = (0, 1, 2, 4)


class CloudflareError(RuntimeError):
    def __init__(self, message, *, uncertain=False, http_status=None):
        super().__init__(message)
        self.uncertain = uncertain
        self.http_status = http_status


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _require(condition, message):
    if not condition:
        raise CloudflareError(message)


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _object(value, label):
    _require(isinstance(value, dict), f"Invalid Cloudflare {label} response.")
    return value


class CloudflareClient:
    """Authenticated fixed-origin API requests, without credential-bearing redirects."""

    def __init__(self, token):
        _require(_matches(re.compile(r"[A-Za-z0-9_.-]+"), token), "Cloudflare API credential unavailable or malformed.")
        self._token = token
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, method, path, payload=None):
        _require(method in {"GET", "POST", "PUT"} and _matches(SAFE_PATH, path) and not path.startswith("//"),
                 "Invalid Cloudflare API request.")
        route = path.partition("?")[0]
        _require("%" not in route and not any(part in {".", ".."} for part in route.split("/")),
                 "Invalid Cloudflare API request.")
        if method == "PUT":
            _require(_matches(SCHEDULE_PATH, path) and payload == [{"cron": TELEGRAM_CRON}],
                     "Invalid isolated Cloudflare schedule update.")
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json"}
        data = None
        if payload is not None:
            _require(method != "GET", "Cloudflare GET cannot carry a payload.")
            try:
                data = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode()
            except (TypeError, ValueError):
                raise CloudflareError("Invalid Cloudflare API payload.") from None
            headers["Content-Type"] = "application/json"
        request = Request(API_ORIGIN + path, headers=headers, data=data, method=method)
        try:
            with self._opener.open(request, timeout=30) as response:
                raw = response.read(MAX_API_BYTES + 1)
        except HTTPError as error:
            error.close()
            uncertain = method != "GET" and (error.code == 408 or error.code >= 500)
            raise CloudflareError(f"Cloudflare API rejected the request (HTTP {error.code}).",
                                  uncertain=uncertain, http_status=error.code) from None
        except (OSError, ValueError, HTTPException):
            raise CloudflareError("Cloudflare API connection failed.", uncertain=method != "GET") from None
        try:
            if len(raw) > MAX_API_BYTES:
                raise ValueError()
            envelope = json.loads(raw)
            if not isinstance(envelope, dict) or not isinstance(envelope.get("success"), bool):
                raise ValueError()
        except (ValueError, RecursionError):
            raise CloudflareError("Cloudflare API returned an invalid response.",
                                  uncertain=method != "GET") from None
        _require(envelope["success"], "Cloudflare API rejected the request.")
        if "result" not in envelope:
            raise CloudflareError("Cloudflare API response is missing its result.", uncertain=method != "GET")
        return envelope["result"]


@dataclass(frozen=True)
class _Deployment:
    id: str
    version: str
    message: str | None


@dataclass(frozen=True)
class ProviderBinding:
    revision: str
    image_sha256: str
    identity_sha256: str

    def __post_init__(self):
        _require(_matches(REVISION, self.revision) and _matches(DIGEST, self.image_sha256)
                 and _matches(DIGEST, self.identity_sha256), "Invalid isolated provider binding identity.")


@dataclass(frozen=True)
class _Version:
    revision: str
    digest: str
    compatibility: str
    tag: str | None
    telegram_config_sha256: str | None = None
    telegram_aggregate_key_sha256: str | None = None
    telegram_private_share_key_sha256: str | None = None
    provider_binding: ProviderBinding | None = None
    telegram_inline_search: bool = False


def _release_tag(revision, telegram_digest, aggregate_digest, private_share_digest, provider_binding):
    tag = revision
    if telegram_digest is not None:
        parts = [revision, telegram_digest]
        if aggregate_digest is not None or private_share_digest is not None:
            parts.append(str(aggregate_digest))
        if private_share_digest is not None:
            parts.append(private_share_digest)
        tag = "telegram-" + sha256(":".join(parts).encode("ascii")).hexdigest()
    if provider_binding is not None:
        tag = "provider-" + sha256(f"{tag}:{provider_binding.identity_sha256}".encode("ascii")).hexdigest()
    return tag


def _inline_search_tag(tag):
    return "inline-" + sha256(f"{tag}:inline-search:1".encode("ascii")).hexdigest()


class _Isolation:
    def __init__(self, worker_api, data_api, target):
        _require(isinstance(target, dict) and target.get("namespace") == NAMESPACE
                 and _matches(HEX_ID, target.get("accountId"))
                 and _matches(HEX_ID, target.get("workerId"))
                 and _matches(UUID, target.get("d1Id"))
                 and all(_matches(TIMESTAMP, target.get(key))
                         for key in ("workerCreatedOn", "d1CreatedAt", "r2CreatedOn")),
                 "Invalid isolated Cloudflare ownership configuration.")
        self.worker_api = worker_api
        self.data_api = data_api
        self.target = target
        self.account = f"/accounts/{target['accountId']}"
        self.worker = f"{self.account}/workers/workers/{target['workerId']}"
        self.script = f"{self.account}/workers/scripts/{WORKER_NAME}"
        self.deployments = self.script + "/deployments"
        self.versions = self.worker + "/versions"
        self.schedules = self.script + "/schedules"

    def worker_config(self):
        worker = _object(self.worker_api("GET", self.worker), "Worker")
        _require(worker.get("id") == self.target["workerId"] and worker.get("name") == WORKER_NAME
                 and worker.get("created_on") == self.target["workerCreatedOn"],
                 "Isolated Worker ownership could not be verified.")
        subdomain = _object(worker.get("subdomain"), "Worker subdomain")
        _require(subdomain.get("url") == ORIGIN and subdomain.get("enabled") is True
                 and subdomain.get("previews_enabled") is False,
                 "Isolated Worker URL or preview settings differ from the expected configuration.")
        observability = _object(worker.get("observability"), "Worker observability")
        _require(observability.get("enabled") is False and worker.get("logpush") is False
                 and worker.get("tail_consumers") == [], "Isolated Worker logging or tail is enabled.")
        for name in ("logs", "traces"):
            settings = _object(observability.get(name), "Worker observability")
            _require(settings.get("enabled") is False and not settings.get("destinations"),
                     "Isolated Worker logging or tracing is enabled.")
        # Legacy settings can describe the staged version, so only read the script tags here.
        settings = _object(self.worker_api("GET", self.script + "/settings"), "script settings")
        tags = settings.get("tags")
        _require(isinstance(tags, list) and len(tags) == 2 and "subs-bot" in tags and "isolation-01" in tags,
                 "Isolated Worker ownership tags do not match.")
        _require(self.worker_api("GET", f"{self.account}/workers/domains?service={WORKER_NAME}") == [],
                 "Isolated Worker custom domains are present or could not be verified.")
        return subdomain, observability

    def cron_enabled(self):
        result = _object(self.worker_api("GET", self.schedules), "Worker schedules")
        schedules = result.get("schedules")
        if schedules == []:
            return False
        _require(isinstance(schedules, list) and len(schedules) == 1 and isinstance(schedules[0], dict)
                 and schedules[0].get("cron") == TELEGRAM_CRON,
                 "Isolated Worker has an unexpected schedule or its schedules could not be verified.")
        return True

    def ensure_cron(self, deployment, config, guard):
        _require(self.worker_config() == config, "Isolated Worker configuration changed before Cron setup.")
        enabled = self.cron_enabled()
        _require(self.active() == deployment, "Active isolated Worker deployment changed before Cron setup.")
        _guard_current(guard)
        if enabled:
            return False
        try:
            self.worker_api("PUT", self.schedules, [{"cron": TELEGRAM_CRON}])
        except CloudflareError as error:
            if not error.uncertain:
                raise CloudflareError("The isolated Worker is active. Cloudflare rejected the Cron setup.") from None
        for delay in READBACK_DELAYS:
            if delay:
                sleep(delay)
            try:
                enabled = self.cron_enabled()
            except CloudflareError:
                continue
            if enabled:
                _require(self.active() == deployment, "Active isolated Worker deployment changed during Cron setup.")
                return True
        raise CloudflareError("The isolated Worker is active. Cron setup could not be confirmed.", uncertain=True)

    def verify_resources(self):
        namespace = _object(self.worker_api("GET", self.account + "/workers/subdomain"), "account namespace")
        _require(namespace.get("subdomain") == NAMESPACE, "Isolated Workers namespace mismatch.")
        database = _object(self.data_api("GET", f"{self.account}/d1/database/{self.target['d1Id']}"), "D1 database")
        _require(database.get("uuid") == self.target["d1Id"] and database.get("name") == WORKER_NAME
                 and database.get("created_at") == self.target["d1CreatedAt"],
                 "Isolated D1 ownership could not be verified.")
        path = f"{self.account}/r2/buckets/{WORKER_NAME}"
        bucket = _object(self.data_api("GET", path), "R2 bucket")
        _require(bucket.get("name") == WORKER_NAME and bucket.get("creation_date") == self.target["r2CreatedOn"]
                 and bucket.get("jurisdiction") == "default", "Isolated R2 ownership could not be verified.")
        managed = _object(self.data_api("GET", path + "/domains/managed"), "R2 managed domain")
        _require(managed.get("enabled") is False and self.data_api("GET", path + "/domains/custom")
                 in ([], {"domains": []}), "Isolated R2 bucket is public or its privacy could not be verified.")

    def verify_inline_search(self, bot_id, *, require_fresh=False):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated inline search migration could not be verified."
        try:
            result = self.data_api("POST", path, {"sql": """
                SELECT name, sha256, mode, CASE WHEN ? = '1' THEN EXISTS (
                  SELECT 1 FROM telegram_inline_search_consent AS consent
                  WHERE consent.bot_id = ? AND consent.kind = 'on' AND consent.expires_at > unixepoch()
                    AND consent.receipt_id = (SELECT latest.receipt_id FROM telegram_inline_search_consent AS latest
                      WHERE latest.bot_id = consent.bot_id AND latest.actor_id = consent.actor_id AND latest.kind IN ('on', 'off')
                      ORDER BY latest.message_date DESC, latest.update_id DESC LIMIT 1)
                ) ELSE 0 END AS activeConsent
                FROM subs_bot_schema_migrations WHERE position = 25
            """, "params": ["1" if require_fresh else "0", bot_id]})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0].get("results")
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), error)
            row = rows[0]
            _require(set(row) == {"name", "sha256", "mode", "activeConsent"} and row["name"] == INLINE_SEARCH_MIGRATION
                     and row["sha256"] == INLINE_SEARCH_MIGRATION_SHA256 and row["mode"] == "applied"
                     and type(row["activeConsent"]) is int and row["activeConsent"] in (0, 1), error)
        except (CloudflareError, AttributeError, TypeError, ValueError, KeyError):
            raise CloudflareError(error) from None
        _require(row["activeConsent"] == 0, "Existing isolated inline search consent must end before enabling.")

    def active(self):
        result = _object(self.worker_api("GET", self.deployments), "deployments").get("deployments")
        _require(isinstance(result, list) and result, "Isolated Worker has no verified active deployment.")
        active = _object(result[0], "active deployment")
        allocations = active.get("versions")
        _require(_matches(UUID, active.get("id")) and active.get("strategy") == "percentage"
                 and isinstance(allocations, list) and len(allocations) == 1,
                 "Isolated Worker does not have a single active version.")
        allocation = _object(allocations[0], "deployment allocation")
        _require(allocation.get("percentage") == 100 and _matches(UUID, allocation.get("version_id")),
                 "Isolated Worker active allocation is not 100%.")
        annotations = _object(active.get("annotations") or {}, "deployment annotations")
        return _Deployment(active["id"], allocation["version_id"], annotations.get("workers/message"))

    def version(self, version_id):
        _require(_matches(UUID, version_id), "Invalid isolated Worker version ID.")
        version = _object(self.worker_api("GET", f"{self.versions}/{version_id}?include=modules"), "Worker version")
        _require(version.get("id") == version_id and version.get("main_module") == "index.js"
                 and _matches(DATE, version.get("compatibility_date"))
                 and version.get("usage_model") in (None, "standard")
                 and not any(version.get(key) for key in ("compatibility_flags", "limits", "placement",
                                                          "assets", "containers", "migrations"))
                 and version.get("cache_options") in (None, {}, {"enabled": False},
                                                     {"enabled": False, "cross_version_cache": False}),
                 "Isolated Worker version runtime settings differ from the supported configuration.")
        rows = version.get("bindings")
        _require(isinstance(rows, list) and 3 <= len(rows) <= 13
                 and all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in rows),
                 "Unexpected isolated Worker binding inventory.")
        bindings = {row["name"]: row for row in rows}
        base_bindings = {"DB", "NODES", "BUILD_REVISION"}
        telegram_bindings = base_bindings | TELEGRAM_BINDINGS
        has_provider = bool(PROVIDER_BINDINGS & bindings.keys())
        inline = bindings.get(INLINE_SEARCH_BINDING)
        binding_names = set(bindings) - PROVIDER_BINDINGS - {INLINE_SEARCH_BINDING}
        _require(len(bindings) == len(rows) and binding_names in (base_bindings, telegram_bindings,
            telegram_bindings | AGGREGATE_BINDINGS, telegram_bindings | PRIVATE_SHARE_BINDINGS,
            telegram_bindings | AGGREGATE_BINDINGS | PRIVATE_SHARE_BINDINGS)
            and (not has_provider or PROVIDER_BINDINGS <= bindings.keys()),
                 "Unexpected isolated Worker binding names.")
        _require(inline is None or (TELEGRAM_BINDINGS <= binding_names and inline == {
            "name": INLINE_SEARCH_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker inline search binding.")
        db, r2, rev = (bindings[name] for name in ("DB", "NODES", "BUILD_REVISION"))
        database_ids = [db[key] for key in ("database_id", "id") if db.get(key) is not None]
        _require(db.get("type") == "d1" and database_ids
                 and all(database_id == self.target["d1Id"] for database_id in database_ids)
                 and r2.get("type") == "r2_bucket" and r2.get("bucket_name") == WORKER_NAME
                 and r2.get("jurisdiction") in (None, "default")
                 and rev.get("type") == "plain_text" and _matches(REVISION, rev.get("text")),
                 "Isolated Worker data or revision binding mismatch.")
        telegram_digest = None
        if TELEGRAM_CONFIG_BINDING in bindings:
            secret, digest = (bindings[name] for name in (TELEGRAM_CONFIG_BINDING, TELEGRAM_DIGEST_BINDING))
            _require(secret.get("type") == "secret_text" and digest.get("type") == "plain_text"
                     and _matches(DIGEST, digest.get("text")), "Isolated Worker Telegram binding mismatch.")
            telegram_digest = digest["text"]
        aggregate_digest = None
        if AGGREGATE_KEY_BINDING in bindings:
            secret, digest = (bindings[name] for name in (AGGREGATE_KEY_BINDING, AGGREGATE_DIGEST_BINDING))
            _require(secret.get("type") == "secret_text" and digest.get("type") == "plain_text"
                     and _matches(DIGEST, digest.get("text")), "Isolated Worker aggregate binding mismatch.")
            aggregate_digest = digest["text"]
        private_share_digest = None
        if PRIVATE_SHARE_KEY_BINDING in bindings:
            secret, digest = (bindings[name] for name in (PRIVATE_SHARE_KEY_BINDING, PRIVATE_SHARE_DIGEST_BINDING))
            _require(secret.get("type") == "secret_text" and digest.get("type") == "plain_text"
                     and _matches(DIGEST, digest.get("text")), "Isolated Worker private share binding mismatch.")
            private_share_digest = digest["text"]
        modules = version.get("modules")
        _require(isinstance(modules, list) and len(modules) == 1, "Unexpected isolated Worker module inventory.")
        module = _object(modules[0], "Worker module")
        content = module.get("content_base64")
        _require(module.get("name") == "index.js" and module.get("content_type") == "application/javascript+module"
                 and isinstance(content, str) and 0 < len(content) <= 4 * ((MAX_MODULE_BYTES + 2) // 3),
                 "Unexpected isolated Worker module.")
        try:
            body = base64.b64decode(content, validate=True)
        except (TypeError, ValueError):
            raise CloudflareError("Cloudflare Worker module encoding is invalid.") from None
        _require(0 < len(body) <= MAX_MODULE_BYTES, "Cloudflare Worker module size is invalid.")
        annotations = _object(version.get("annotations") or {}, "version annotations")
        provider_binding = None
        message = annotations.get("workers/message")
        tagged_provider = isinstance(message, str) and message.startswith(PROVIDER_MESSAGE)
        _require(has_provider == tagged_provider, "Isolated provider binding identity is incomplete.")
        if has_provider:
            service = bindings["PROVIDER_FETCH"]
            revision_pin, image_pin = (bindings[name] for name in ("PROVIDER_REVISION", "PROVIDER_IMAGE_SHA256"))
            _require(set(service) <= {"name", "type", "service", "entrypoint", "environment"}
                     and service.get("type") == "service" and service.get("service") == PROVIDER_SERVICE
                     and service.get("entrypoint") == PROVIDER_ENTRYPOINT and service.get("environment") in (None, "production")
                     and all(set(pin) == {"name", "type", "text"} and pin["type"] == "plain_text"
                             for pin in (revision_pin, image_pin)),
                     "Isolated provider binding target differs from the reviewed service.")
            provider_binding = ProviderBinding(revision_pin.get("text"), image_pin.get("text"), message[len(PROVIDER_MESSAGE):])
        tag = annotations.get("workers/tag")
        if inline is not None:
            _require(tag == _inline_search_tag(_release_tag(rev["text"], telegram_digest, aggregate_digest,
                                                             private_share_digest, provider_binding)),
                     "Isolated Worker inline search release tag differs.")
        return _Version(rev["text"], sha256(body).hexdigest(), version["compatibility_date"],
                        tag, telegram_digest, aggregate_digest, private_share_digest, provider_binding, inline is not None)

    def verify_candidate(self, candidate, desired):
        # A version can be visible in its creation response or listing before its module is readable.
        for delay in READBACK_DELAYS:
            if delay:
                sleep(delay)
            try:
                actual = self.version(candidate)
            except CloudflareError as error:
                if error.http_status != 404:
                    raise
                continue
            _require(actual == desired, "Isolated candidate Worker version differs from the verified artifact.")
            return candidate
        raise CloudflareError("Isolated candidate Worker version readback could not be confirmed (HTTP 404).",
                              uncertain=True, http_status=404)

    def staged(self, desired):
        rows = self.worker_api("GET", self.versions + "?page=1&per_page=100")
        _require(isinstance(rows, list), "Invalid Cloudflare Worker version list.")
        candidates = []
        for row in rows:
            item = _object(row, "listed Worker version")
            annotations = _object(item.get("annotations") or {}, "version annotations")
            if annotations.get("workers/tag") == desired.tag:
                candidates.append(item.get("id"))
        _require(len(candidates) <= 1, "More than one isolated Worker version claims the target revision.")
        if not candidates:
            return None
        return self.verify_candidate(candidates[0], desired)

    def upload(self, module, desired, telegram_config, aggregate_key, private_share_key):
        bindings = [
            {"type": "d1", "name": "DB", "database_id": self.target["d1Id"]},
            {"type": "r2_bucket", "name": "NODES", "bucket_name": WORKER_NAME},
            {"type": "plain_text", "name": "BUILD_REVISION", "text": desired.revision},
        ]
        if telegram_config is not None:
            bindings.extend([
                {"type": "secret_text", "name": TELEGRAM_CONFIG_BINDING, "text": telegram_config},
                {"type": "plain_text", "name": TELEGRAM_DIGEST_BINDING, "text": desired.telegram_config_sha256},
            ])
        if aggregate_key is not None:
            bindings.extend([
                {"type": "secret_text", "name": AGGREGATE_KEY_BINDING, "text": aggregate_key},
                {"type": "plain_text", "name": AGGREGATE_DIGEST_BINDING, "text": desired.telegram_aggregate_key_sha256},
            ])
        if private_share_key is not None:
            bindings.extend([
                {"type": "secret_text", "name": PRIVATE_SHARE_KEY_BINDING, "text": private_share_key},
                {"type": "plain_text", "name": PRIVATE_SHARE_DIGEST_BINDING, "text": desired.telegram_private_share_key_sha256},
            ])
        if desired.telegram_inline_search:
            bindings.append({"type": "plain_text", "name": INLINE_SEARCH_BINDING, "text": "1"})
        message = "Reviewed isolated Worker release"
        if desired.provider_binding is not None:
            binding = desired.provider_binding
            bindings.extend([
                {"type": "service", "name": "PROVIDER_FETCH", "service": PROVIDER_SERVICE, "entrypoint": PROVIDER_ENTRYPOINT},
                {"type": "plain_text", "name": "PROVIDER_REVISION", "text": binding.revision},
                {"type": "plain_text", "name": "PROVIDER_IMAGE_SHA256", "text": binding.image_sha256},
            ])
            message = PROVIDER_MESSAGE + binding.identity_sha256
        try:
            result = self.worker_api("POST", self.versions + "?deploy=false", {
                "main_module": "index.js",
                "compatibility_date": desired.compatibility,
                "usage_model": "standard",
                "modules": [{
                    "name": "index.js",
                    "content_type": "application/javascript+module",
                    "content_base64": base64.b64encode(module).decode("ascii"),
                }],
                "bindings": bindings,
                "annotations": {"workers/tag": desired.tag, "workers/message": message},
            })
        except CloudflareError as error:
            if not error.uncertain:
                if error.http_status is not None:
                    raise CloudflareError(f"Isolated Worker version upload was rejected (HTTP {error.http_status}).",
                                          http_status=error.http_status) from None
                raise
            result = None
        if isinstance(result, dict) and _matches(UUID, result.get("id")):
            return self.verify_candidate(result["id"], desired)
        for delay in READBACK_DELAYS:
            if delay:
                sleep(delay)
            candidate = self.staged(desired)
            if candidate is not None:
                return candidate
        raise CloudflareError("Isolated Worker upload could not be confirmed.", uncertain=True)

    def activate(self, previous, version_id, message):
        try:
            result = self.worker_api("POST", self.deployments, {
                "strategy": "percentage",
                "versions": [{"version_id": version_id, "percentage": 100}],
                "annotations": {"workers/message": message},
            })
        except CloudflareError as error:
            if not error.uncertain:
                if error.http_status is not None:
                    raise CloudflareError(f"Isolated Worker activation was rejected (HTTP {error.http_status}).",
                                          http_status=error.http_status) from None
                raise
            result = None
        ack = result.get("id") if isinstance(result, dict) else None
        ack = ack if _matches(UUID, ack) else None
        for delay in READBACK_DELAYS:
            if delay:
                sleep(delay)
            try:
                active = self.active()
            except CloudflareError:
                continue
            if active == previous:
                continue
            if active.version == version_id and (active.id == ack or active.message == message):
                _require(ack is None or active.id == ack, "Isolated activation response conflicts with active deployment.")
                return active
            break
        raise CloudflareError("Isolated activation could not be confirmed from deployment history.", uncertain=True)


def _guard_current(guard):
    try:
        fresh = guard()
    except Exception:
        raise CloudflareError("The reviewed GitHub main revision could not be verified.") from None
    _require(fresh is not False, "The reviewed GitHub main revision changed.")


def validate_aggregate_key(raw):
    _require(isinstance(raw, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", raw),
             "The isolated aggregate key must be a canonical Base64URL encoding of 32 bytes.")
    decoded = base64.urlsafe_b64decode(raw + "=")
    _require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == raw,
             "The isolated aggregate key must be a canonical Base64URL encoding of 32 bytes.")


def validate_private_share_key(raw):
    _require(isinstance(raw, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", raw),
             "The isolated private share key must be a canonical Base64URL encoding of 32 bytes.")
    decoded = base64.urlsafe_b64decode(raw + "=")
    _require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode("ascii").rstrip("=") == raw,
             "The isolated private share key must be a canonical Base64URL encoding of 32 bytes.")


def _artifact(bundle_dir, manifest, telegram_config, aggregate_key=None, private_share_key=None, provider_binding=None):
    _require(isinstance(manifest, dict) and manifest.get("version") == 2
             and _matches(REVISION, manifest.get("revision")) and _matches(DIGEST, manifest.get("bundleSha256"))
             and _matches(DATE, manifest.get("compatibilityDate")) and isinstance(manifest.get("migrations"), list),
             "Invalid verified Worker release manifest.")
    try:
        path = Path(bundle_dir) / "index.js"
        _require(path.is_file() and not path.is_symlink(), "Verified Worker module is not a regular file.")
        with path.open("rb") as source:
            module = source.read(MAX_MODULE_BYTES + 1)
    except (OSError, ValueError, TypeError):
        raise CloudflareError("Verified Worker module is unavailable.") from None
    _require(0 < len(module) <= MAX_MODULE_BYTES and sha256(module).hexdigest() == manifest["bundleSha256"],
             "Verified Worker module digest mismatch.")
    revision = manifest["revision"]
    telegram_digest = None
    aggregate_digest = None
    private_share_digest = None
    if telegram_config is not None:
        _require(isinstance(telegram_config, str), "Invalid isolated Telegram configuration.")
        try:
            config_bytes = telegram_config.encode("utf-8")
        except UnicodeError:
            raise CloudflareError("Invalid isolated Telegram configuration.") from None
        _require(0 < len(config_bytes) <= MAX_TELEGRAM_CONFIG_BYTES,
                 "Isolated Telegram configuration size is invalid.")
        telegram_digest = sha256(config_bytes).hexdigest()
    if aggregate_key is not None:
        _require(telegram_digest is not None, "An isolated aggregate key requires the approved Telegram configuration.")
        validate_aggregate_key(aggregate_key)
        aggregate_digest = sha256(aggregate_key.encode("ascii")).hexdigest()
    if private_share_key is not None:
        _require(telegram_digest is not None, "An isolated private share key requires the approved Telegram configuration.")
        validate_private_share_key(private_share_key)
        _require(private_share_key != aggregate_key, "The isolated private share key must be distinct from the aggregate key.")
        private_share_digest = sha256(private_share_key.encode("ascii")).hexdigest()
    if provider_binding is not None:
        _require(isinstance(provider_binding, ProviderBinding), "Invalid isolated provider binding identity.")
    # Distinct configuration releases can share a Git revision.
    tag = _release_tag(revision, telegram_digest, aggregate_digest, private_share_digest, provider_binding)
    return module, _Version(revision, manifest["bundleSha256"], manifest["compatibilityDate"],
                            tag, telegram_digest, aggregate_digest, private_share_digest, provider_binding)


def _read_health():
    request = Request(HEALTH_URL, headers={"Accept": "application/json",
                                         "User-Agent": "subs-bot-isolation-release/1.0"})
    try:
        with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=10) as response:
            raw = response.read(1025)
            cache = {value.strip().lower() for value in response.headers.get("Cache-Control", "").split(",")}
            _require(response.status == 200 and response.headers.get_content_type() == "application/json"
                     and {"private", "no-store"} <= cache and len(raw) <= 1024
                     and response.headers.get("Referrer-Policy") == "no-referrer"
                     and response.headers.get("X-Content-Type-Options") == "nosniff",
                     "Isolated Worker health response is invalid.")
            return json.loads(raw)
    except (OSError, ValueError, HTTPException, RecursionError):
        raise CloudflareError("Isolated Worker health request failed.") from None


def _verify_health(revision):
    for delay in READBACK_DELAYS:
        if delay:
            sleep(delay)
        try:
            if _read_health() == {"ok": True, "service": "subs-bot", "revision": revision}:
                return
        except CloudflareError:
            pass
    raise CloudflareError("Isolated Worker health could not verify the expected revision.")


def _require_provider_continuity(active, desired):
    _require(active is None or active == desired,
             "Changing or dropping the isolated provider binding requires a separate rotation release.")


def _verify_first_provider_binding(active, desired, revision, proof_guard):
    _require(active is not None or desired is None or desired.revision == revision,
             "First provider binding requires proof of the same main revision as the application release.")
    if active is None and desired is not None:
        _require(callable(proof_guard), "First provider binding requires the verified GitHub activation artifact.")
        proof_guard()


def _inline_search_target(active, requested, manifest, telegram_config):
    _require(requested is None or type(requested) is bool, "Invalid isolated inline search release mode.")
    enabled = active.telegram_inline_search if requested is None else requested
    if not (active.telegram_inline_search or enabled):
        return enabled, None

    migrations = manifest.get("migrations") if isinstance(manifest, dict) else None
    _require(isinstance(migrations, list) and len(migrations) >= 25 and migrations[24] == {
        "name": INLINE_SEARCH_MIGRATION, "sha256": INLINE_SEARCH_MIGRATION_SHA256,
    }, "Isolated inline search requires the exact 0025 migration artifact.")
    try:
        bot_id = json.loads(telegram_config)["botId"]
        digest = sha256(telegram_config.encode("utf-8")).hexdigest()
    except (KeyError, TypeError, ValueError, AttributeError, RecursionError):
        raise CloudflareError("Isolated inline search requires the verified Telegram configuration.") from None
    _require(_matches(re.compile(r"[1-9][0-9]{0,15}"), bot_id) and digest == active.telegram_config_sha256,
             "Isolated inline search requires the same verified Telegram configuration.")
    if enabled and not active.telegram_inline_search:
        _require(active.revision == manifest.get("revision") and active.digest == manifest.get("bundleSha256"),
                 "Enable inline search only after verifying the same Worker artifact with inline search disabled.")
    return enabled, bot_id


def _require_telegram_config_continuity(active, desired_digest):
    _require(active.telegram_config_sha256 is None or active.telegram_config_sha256 == desired_digest,
             "Changing or dropping the isolated Telegram configuration requires a separate scoped release.")


def verify_worker_target(worker_api, data_api, target, *, aggregate_key=_UNSPECIFIED_AGGREGATE_KEY,
                         private_share_key=_UNSPECIFIED_PRIVATE_SHARE_KEY, provider_binding=_UNSPECIFIED_PROVIDER_BINDING,
                         release_revision=None, provider_first_binding_guard=None, release_manifest=None,
                         telegram_config=_UNSPECIFIED_TELEGRAM_CONFIG, inline_search=None):
    """Read ownership, privacy and active binding facts before any release writes."""
    scope = _Isolation(worker_api, data_api, target)
    scope.worker_config()
    had_cron = scope.cron_enabled()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    # Read-only fixtures can inspect the live binding without the secret.
    if telegram_config is not _UNSPECIFIED_TELEGRAM_CONFIG:
        _require(telegram_config is None or isinstance(telegram_config, str), "The isolated Telegram configuration is invalid.")
        desired_digest = sha256(telegram_config.encode("utf-8")).hexdigest() if telegram_config is not None else None
        _require_telegram_config_continuity(version, desired_digest)
    # Releases explicitly pass their expected keys.
    if aggregate_key is not _UNSPECIFIED_AGGREGATE_KEY and version.telegram_aggregate_key_sha256 is not None:
        validate_aggregate_key(aggregate_key)
        _require(version.telegram_aggregate_key_sha256 == sha256(aggregate_key.encode("ascii")).hexdigest(),
                 "Changing the isolated aggregate key requires a separate rotation release.")
    if private_share_key is not _UNSPECIFIED_PRIVATE_SHARE_KEY and version.telegram_private_share_key_sha256 is not None:
        validate_private_share_key(private_share_key)
        _require(version.telegram_private_share_key_sha256 == sha256(private_share_key.encode("ascii")).hexdigest(),
                 "Changing the isolated private share key requires a separate rotation release.")
    if release_manifest is not None or inline_search is not None:
        enabled, bot_id = _inline_search_target(version, inline_search, release_manifest, telegram_config)
        if enabled != version.telegram_inline_search:
            _require(had_cron and (aggregate_key is _UNSPECIFIED_AGGREGATE_KEY
                      or (aggregate_key is not None) == (version.telegram_aggregate_key_sha256 is not None))
                     and (private_share_key is _UNSPECIFIED_PRIVATE_SHARE_KEY
                          or (private_share_key is not None) == (version.telegram_private_share_key_sha256 is not None))
                     and (provider_binding is _UNSPECIFIED_PROVIDER_BINDING or provider_binding == version.provider_binding),
                     "Change the isolated inline search flag with the existing Cron, same keys and provider binding.")
        if bot_id is not None:
            scope.verify_inline_search(bot_id, require_fresh=enabled and not version.telegram_inline_search)
    if provider_binding is not _UNSPECIFIED_PROVIDER_BINDING:
        _require_provider_continuity(version.provider_binding, provider_binding)
        _verify_first_provider_binding(version.provider_binding, provider_binding, release_revision, provider_first_binding_guard)
    return {"deploymentId": active.id, "versionId": active.version, "revision": version.revision}


def release_worker(worker_api, data_api, target, bundle_dir, manifest, guard, *, expected_active=None,
                   telegram_config: str | None = None, aggregate_key: str | None = None, private_share_key: str | None = None,
                   provider_binding: ProviderBinding | None = None, provider_guard=None, provider_first_binding_guard=None,
                   inline_search: bool | None = None):
    """Release the verified Worker and optionally configure its isolated Telegram schedule."""
    _require((provider_binding is None and provider_guard is None) or (provider_binding is not None and callable(provider_guard)),
             "An isolated provider release requires a verified dependency guard.")
    module, desired = _artifact(bundle_dir, manifest, telegram_config, aggregate_key, private_share_key, provider_binding)
    scope = _Isolation(worker_api, data_api, target)
    config = scope.worker_config()
    had_cron = scope.cron_enabled()
    scope.verify_resources()
    previous = scope.active()
    old_version = scope.version(previous.version)
    _require(expected_active is None or expected_active == {
        "deploymentId": previous.id, "versionId": previous.version, "revision": old_version.revision,
    }, "Isolated Worker deployment changed while verifying D1.")
    _require(old_version.compatibility == desired.compatibility, "Worker compatibility date change requires separate approval.")
    _require_telegram_config_continuity(old_version, desired.telegram_config_sha256)
    _require(telegram_config is not None or (not had_cron and old_version.telegram_config_sha256 is None),
             "Isolated Telegram configuration is required to preserve the active configuration.")
    _require(old_version.telegram_aggregate_key_sha256 is None
             or old_version.telegram_aggregate_key_sha256 == desired.telegram_aggregate_key_sha256,
             "Changing or dropping the isolated aggregate key requires a separate rotation release.")
    _require(old_version.telegram_private_share_key_sha256 is None
             or old_version.telegram_private_share_key_sha256 == desired.telegram_private_share_key_sha256,
             "Changing or dropping the isolated private share key requires a separate rotation release.")
    _require_provider_continuity(old_version.provider_binding, desired.provider_binding)
    enabled, inline_bot = _inline_search_target(old_version, inline_search, manifest, telegram_config)
    first_enable = enabled and not old_version.telegram_inline_search
    if enabled != old_version.telegram_inline_search:
        _require(had_cron and (old_version.telegram_aggregate_key_sha256, old_version.telegram_private_share_key_sha256,
                  old_version.provider_binding) == (desired.telegram_aggregate_key_sha256,
                  desired.telegram_private_share_key_sha256, desired.provider_binding),
                 "Change the isolated inline search flag with the existing Cron, same keys and provider binding.")
    if enabled:
        desired = replace(desired, telegram_inline_search=True, tag=_inline_search_tag(desired.tag))
    if inline_bot is not None:
        scope.verify_inline_search(inline_bot, require_fresh=first_enable)
    _verify_first_provider_binding(old_version.provider_binding, desired.provider_binding, desired.revision, provider_first_binding_guard)
    _verify_health(old_version.revision)
    if provider_guard is not None:
        provider_guard()
    if old_version.revision == desired.revision:
        _require(old_version.digest == desired.digest, "Active revision differs from the verified module digest.")
        if (old_version.telegram_config_sha256, old_version.telegram_aggregate_key_sha256,
                old_version.telegram_private_share_key_sha256, old_version.provider_binding, old_version.telegram_inline_search) == (
                desired.telegram_config_sha256, desired.telegram_aggregate_key_sha256,
                desired.telegram_private_share_key_sha256, desired.provider_binding, desired.telegram_inline_search):
            if telegram_config is None:
                _require(scope.active() == previous, "Active isolated Worker deployment changed during verification.")
                _guard_current(guard)
                changed = False
            else:
                changed = scope.ensure_cron(previous, config, guard)
            return {"revision": desired.revision, "deploymentId": previous.id, "versionId": previous.version,
                    "previousVersionId": previous.version, "changed": changed, "inlineSearchEnabled": enabled}

    candidate = scope.staged(desired)
    if candidate is None:
        _require(scope.active() == previous, "Active isolated Worker deployment changed before upload.")
        _guard_current(guard)
        candidate = scope.upload(module, desired, telegram_config, aggregate_key, private_share_key)

    _require(scope.worker_config() == config, "Isolated Worker configuration changed before activation.")
    _require(scope.cron_enabled() == had_cron, "Isolated Worker schedule changed before activation.")
    scope.verify_resources()
    if provider_guard is not None:
        provider_guard()
    if inline_bot is not None:
        scope.verify_inline_search(inline_bot, require_fresh=first_enable)
    _require(scope.active() == previous, "Active isolated Worker deployment changed before activation.")
    _guard_current(guard)
    activated = scope.activate(previous, candidate, f"Isolated Worker release {desired.revision} {uuid4()}")
    try:
        _require(scope.worker_config() == config, "Isolated Worker configuration changed after activation.")
        _require(scope.cron_enabled() == had_cron, "Isolated Worker schedule changed during activation.")
        scope.verify_resources()
        _require(scope.version(activated.version) == desired, "Active Worker version differs from the verified artifact.")
        _verify_health(desired.revision)
        if inline_bot is not None:
            scope.verify_inline_search(inline_bot)
        if provider_guard is not None:
            provider_guard()
        _require(scope.active() == activated, "Active isolated Worker deployment changed during verification.")
    except CloudflareError:
        try:
            _require(scope.worker_config() == config, "Isolated Worker configuration changed before rollback.")
            _require(scope.cron_enabled() == had_cron, "Isolated Worker schedule changed before rollback.")
            scope.verify_resources()
            _require(scope.version(previous.version) == old_version, "Prior Worker version changed before rollback.")
            _require(scope.active() == activated, "Active isolated Worker deployment changed before rollback.")
            _guard_current(guard)
            restored = scope.activate(activated, previous.version, f"Isolated Worker rollback {uuid4()}")
            _verify_health(old_version.revision)
            if inline_bot is not None:
                _require(scope.version(restored.version) == old_version, "Isolated Worker inline search rollback state differs.")
            _require(scope.active() == restored, "Isolated Worker rollback activation changed.")
        except CloudflareError:
            raise CloudflareError("Isolated Worker verification failed and a safe rollback could not be confirmed.") from None
        raise CloudflareError("Isolated Worker verification failed. The prior version was restored.") from None

    # Cron is script-level. A failed update must not restore code that cannot handle a possibly installed trigger.
    if telegram_config is not None:
        scope.ensure_cron(activated, config, guard)
    return {"revision": desired.revision, "deploymentId": activated.id, "versionId": activated.version,
            "previousVersionId": previous.version, "changed": True, "inlineSearchEnabled": enabled}

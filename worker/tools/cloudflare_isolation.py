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
PAGE_JUMP_BINDING = "TELEGRAM_PAGE_JUMP"
PAGE_JUMP_MARKER = b"subs-bot:telegram-page-jump:v1"
PAGE_JUMP_MIGRATION = "0042_telegram_page_jumps.sql"
PAGE_JUMP_MIGRATION_SHA256 = "195fdd3611d9f380e86d9b30983fff306d4218c2ae7899d7dcf49fa275f9c288"
PAGE_JUMP_CONTROL_MARKER = b"subs-bot:telegram-page-jump-epoch:v1"
PAGE_JUMP_CONTROL_MIGRATION = "0043_telegram_page_jump_controls.sql"
PAGE_JUMP_CONTROL_MIGRATION_SHA256 = "cad46bc0c6b296de85e8c77ce2cb71e8aef156b5e03e04628e0c1ee060649571"
INLINE_SEARCH_BINDING = "TELEGRAM_INLINE_SEARCH"
INLINE_SEARCH_MIGRATION = "0025_telegram_personal_inline.sql"
INLINE_SEARCH_MIGRATION_SHA256 = "2c504b14ca94597925b1703d2f50d211d29addaff8f139b5411be5fd2306b122"
PROVIDER_URL_IMPORT_BINDING = "TELEGRAM_PROVIDER_URL_IMPORT"
PROVIDER_URL_IMPORT_TAG_PREFIX = "provider-url-"
PROVIDER_URL_IMPORT_MIGRATIONS = (
    (21, "0021_telegram_provider_admission.sql", "c0557767395697de2d9c3073b4493759104f0eabd399b7391ba9204b7e6527bc"),
    (23, "0023_telegram_provider_replies.sql", "67b4f625259bdef325fc70ef1042a1b33aa73d8396261ba79c85763c2e1c7c14"),
)
PROVIDER_URL_DOCUMENTS_BINDING = "TELEGRAM_PROVIDER_URL_DOCUMENTS"
PROVIDER_URL_DOCUMENTS_MIGRATIONS = (
    *PROVIDER_URL_IMPORT_MIGRATIONS,
    (33, "0033_provider_snapshot_journal.sql", "35873c62fd9482bc446fb2c80a675ddc22cf70d3f97d7632877b2ce28cbb3f7f"),
    (35, "0035_telegram_provider_documents.sql", "9a3fc29e9ea19abac2874a11a0152497eee63a54ecb401168c153fb838f92505"),
)
PROVIDER_URL_DOCUMENTS_SCHEMA_SHA256 = "1c10a1883dec04447fd4bf2c687a029da2d6723768ea43490cfc998b15054e37"
MIXED_DOCUMENTS_BINDING = "TELEGRAM_MIXED_DOCUMENTS"
MIXED_DOCUMENTS_MIGRATION = "0036_telegram_mixed_document_opt_in.sql"
MIXED_DOCUMENTS_MIGRATION_SHA256 = "05b67a3a3ddfb49b6f801b87dafae240f7328711e9e6c598b8b67e8738a892f8"
MIXED_DOCUMENTS_TABLE_SHA256 = "0277bcc1e391b3c06c1db96babf44ba7ac54fe27d52fa3478c2079f2fe41212e"
GROUP_SHARE_CARDS_BINDING = "TELEGRAM_GROUP_SHARE_CARDS"
GROUP_SHARE_CARDS_MARKER = b"subs-bot:telegram-group-share-cards:v1"
GROUP_SHARE_CARDS_MIGRATION = "0037_telegram_group_share_cards.sql"
GROUP_SHARE_CARDS_MIGRATION_SHA256 = "064f461428f244f780e5655528fb0dc7e35676d1f805145ffff722b50780c748"
GROUP_SHARE_CARDS_SCHEMA_SHA256 = "66ea7065ed9ce609e30c330e0214c296afac91c7648d2cae71f1907eb82f34c7"
PROVIDER_REFRESH_BINDING = "TELEGRAM_PROVIDER_REFRESH"
PROVIDER_REFRESH_TAG_PREFIX = "provider-rf-"
PROVIDER_REFRESH_MIGRATIONS = (
    (18, "0018_telegram_subscription_reads.sql", "382e9e5e7a850e4f38aece8c2a9f0e98fd890203edf7aa83c37212f5ab038e62"),
    *PROVIDER_URL_IMPORT_MIGRATIONS,
    (28, "0028_telegram_provider_refresh_tickets.sql", "ccbfe6d71864608b9a6d680d955c11af083aa34280b55845edef1296d87dab2e"),
)
PROVIDER_BATCH_BINDING = "TELEGRAM_PROVIDER_BATCH_REFRESH"
PROVIDER_BATCH_TAG_PREFIX = "provider-batch-"
PROVIDER_BATCH_READY_TAG_PREFIX = "batch-ready-"
PROVIDER_BATCH_MIGRATIONS = (
    *PROVIDER_URL_IMPORT_MIGRATIONS,
    (31, "0031_telegram_provider_batch_queue.sql", "82a3f86930692de873ae30354608b49d8671ff9562bbd15d5893110fa9992e63"),
    (32, "0032_telegram_provider_batch_controls.sql", "9b4318878f29b531010ff7fb0d77d1e0b802add09607829ce8aac886a2b6f666"),
)
PROVIDER_BATCH_SCHEMA_SHA256 = "b64dc593d40fa6184ad737a67f0e3c789b9caa1752ebe65d8205a8341bf2fff3"
LEGACY_SUBSCRIPTION_SHORT_BINDING = "LEGACY_SUBSCRIPTION_SHORTS"
LEGACY_SUBSCRIPTION_SHORT_TAG_PREFIX = "legacy-sl-"
LEGACY_SUBSCRIPTION_SHORT_MIGRATION = "0029_legacy_subscription_short_links.sql"
LEGACY_SUBSCRIPTION_SHORT_SHA256 = "1a0da8aa8aedde095b3e1a4bc71b5e03376587882288c4e276c9a1f9afa1297d"
# SQLite records the exact CREATE statement without the trailing semicolon.
LEGACY_SUBSCRIPTION_SHORT_TABLE_SHA256 = "7c490869f45c42234b6c01083975a8cb06bfa5fe8d104a89ab69f24d156fc8e2"
LEGACY_SELECTED_MIGRATION = "0038_legacy_selected_aggregates.sql"
LEGACY_SELECTED_MIGRATION_SHA256 = "29ddd93dc46120614c4837268ac2c0a0c5b4c48af9d7e4fe4de1e5e24451b74f"
LEGACY_SELECTED_HTTP_MARKER = b"subs-bot:legacy-selected-http:v1"
LEGACY_SELECTED_RETIREMENT_MARKER = b"subs-bot:legacy-selected-retirement:v1"
LEGACY_SELECTED_MARKER_TABLE_SHA256 = "6122d2db8608de2a1a548e4e210751cc4797ad4dd7de5be04f22a5de2973358c"
LEGACY_SELECTED_MEMBER_TABLE_SHA256 = "7fd16b93997c1646e6160cec599a282564dc9ac3b0ab06a9a7166eacd95ab3f3"
LEGACY_TEMP_MIGRATION = "0039_legacy_temp_baseline.sql"
LEGACY_TEMP_MIGRATION_SHA256 = "4a5253618caf42baf997301d4e27c1d11f15166dadf48740d1c7d60da3af82d6"
LEGACY_TEMP_READ_MARKER = b"subs-bot:legacy-temp-read:v1"
LEGACY_TEMP_MUTATE_MARKER = b"subs-bot:legacy-temp-mutate:v1"
LEGACY_TEMP_INSTALL_TABLE_SHA256 = "8cf3847e5df08a64261e82fbb972d9cde57be94143b35ca1de7c0f8dbbf0856f"
LEGACY_TEMP_BATCH_TABLE_SHA256 = "2cc851299d68628cb46fe2d927adf027b551d010ac17e1bd42f8746273e59eca"
LEGACY_DYNAMIC_ALL_MIGRATION = "0040_legacy_all_aggregates.sql"
LEGACY_DYNAMIC_ALL_MIGRATION_SHA256 = "55a3de863e8b05eff6a25c52f5fe1b2e8be8f246f6b2e23348b6ef2a4456e3ed"
LEGACY_DYNAMIC_ALL_READ_MARKER = b"subs-bot:legacy-dynamic-all-read:v1"
LEGACY_DYNAMIC_ALL_ORDER_MARKER = b"subs-bot:legacy-dynamic-all-order:v1"
LEGACY_DYNAMIC_ALL_TABLE_SHA256 = "283a9dca5ffe1b9e68a12aa3038fd7cd52c39d06a050aff5b2b8be6b085105ff"
LEGACY_DYNAMIC_ALL_INDEX_SHA256 = "3660ac17b67cb885524869ae0b7a2b7fcd9c678b370b334fbaea29ba9acc43ce"
LEGACY_DYNAMIC_ALL_ORDER_TABLE_SHA256 = "6198ba160f56bd64c98b962b7f972b43d4dcdd60df2193f5796da79e4a230087"
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
API_STATUS_BINDING = "TELEGRAM_API_STATUS"
PROVIDER_API_STATUS_SERVICE = "subs-bot-provider-api-status-dev-01"
PROVIDER_API_STATUS_ENTRYPOINT = "ProviderApiStatus"
PROVIDER_API_STATUS_BINDINGS = {"PROVIDER_API_STATUS", "PROVIDER_API_STATUS_REVISION",
                                "PROVIDER_API_STATUS_IMAGE_SHA256", "PROVIDER_API_STATUS_IDENTITY_SHA256"}
API_STATUS_MIGRATION = "0034_telegram_api_status.sql"
API_STATUS_MIGRATION_SHA256 = "39f9f1473740ddbff2ff6d218f91f6a5ef050c6b2221e5b915dd7d91a5618664"
API_STATUS_SCHEMA_SHA256 = "21e64519fa87d4d1435b53888936cfc830d297684842e565b38d3770f145ca65"
_UNSPECIFIED_TELEGRAM_CONFIG = object()
_UNSPECIFIED_AGGREGATE_KEY = object()
_UNSPECIFIED_PRIVATE_SHARE_KEY = object()
_UNSPECIFIED_PROVIDER_BINDING = object()
_UNSPECIFIED_API_STATUS_GATE = object()
ORIGIN = f"https://{WORKER_NAME}.{NAMESPACE}.workers.dev"
HEALTH_URL = ORIGIN + "/health"
ISOLATION_RELEASE_USER_AGENT = "subs-bot-isolation-release/1.0"
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
class ProviderApiStatusBinding(ProviderBinding):
    """Immutable identity of the independently verified V2 named service."""


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
    telegram_provider_url_import: bool = False
    telegram_provider_refresh: bool = False
    legacy_subscription_shorts: bool = False
    telegram_provider_batch: bool = False
    telegram_provider_batch_capable: bool = False
    api_status_binding: ProviderApiStatusBinding | None = None
    telegram_api_status: bool = False
    telegram_provider_url_documents: bool = False
    telegram_provider_url_documents_capable: bool = False
    telegram_mixed_documents: bool = False
    telegram_mixed_documents_capable: bool = False
    telegram_group_share_cards: bool = False
    telegram_group_share_cards_capable: bool = False
    telegram_page_jump_capable: bool = False
    telegram_page_jump_control_capable: bool = False
    telegram_page_jump_epoch: int | None = None


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


def _api_status_tag(tag, binding, enabled):
    if binding is None:
        return tag
    value = f"{tag}:api-status-v2:{binding.revision}:{binding.image_sha256}:{binding.identity_sha256}:{int(enabled)}"
    return "api-status-" + sha256(value.encode("ascii")).hexdigest()


def _telegram_feature_tag(tag, inline_search, provider_url_import, provider_refresh=False, legacy_subscription_shorts=False,
                          provider_batch=False, batch_module_sha256=None, *, url_documents=False, url_documents_module_sha256=None,
                          mixed_documents=None, group_share_cards=None):
    if inline_search:
        tag = _inline_search_tag(tag)
    if provider_url_import:
        tag = PROVIDER_URL_IMPORT_TAG_PREFIX + sha256(f"{tag}:provider-url-import:1".encode("ascii")).hexdigest()
    if provider_refresh:
        tag = PROVIDER_REFRESH_TAG_PREFIX + sha256(f"{tag}:provider-refresh:1".encode("ascii")).hexdigest()
    if legacy_subscription_shorts:
        tag = LEGACY_SUBSCRIPTION_SHORT_TAG_PREFIX + sha256(f"{tag}:legacy-subscription-shorts:1".encode("ascii")).hexdigest()
    if url_documents_module_sha256 is not None:
        pin = f"{tag}:provider-url-documents:{int(url_documents)}:{url_documents_module_sha256}:{PROVIDER_URL_DOCUMENTS_SCHEMA_SHA256}"
        tag = sha256(pin.encode("ascii")).hexdigest()
    if mixed_documents is not None:
        pin = f"{tag}:mixed-documents:{int(mixed_documents)}:{MIXED_DOCUMENTS_TABLE_SHA256}"
        tag = sha256(pin.encode("ascii")).hexdigest()
    if group_share_cards is not None:
        pin = f"{tag}:group-share-cards:{int(group_share_cards)}:{GROUP_SHARE_CARDS_MIGRATION_SHA256}"
        tag = sha256(pin.encode("ascii")).hexdigest()
    if batch_module_sha256 is not None:
        prefix = PROVIDER_BATCH_TAG_PREFIX if provider_batch else PROVIDER_BATCH_READY_TAG_PREFIX
        batch_pin = f"{tag}:provider-batch:{int(provider_batch)}:{batch_module_sha256}:{PROVIDER_BATCH_SCHEMA_SHA256}"
        tag = prefix + sha256(batch_pin.encode("ascii")).hexdigest()
    return tag


def _page_jump_binding(epoch):
    _require(type(epoch) is int and 1 <= epoch <= 2**53 - 1, "Invalid isolated page-jump epoch.")
    return {"name": PAGE_JUMP_BINDING, "type": "plain_text", "text": f"v2:{epoch}"}


def _page_jump_tag(tag, epoch, module_sha):
    if epoch is None:
        return tag
    # Batch readback identifies its independently reviewed capability by prefix.
    prefix = next((value for value in (PROVIDER_BATCH_TAG_PREFIX, PROVIDER_BATCH_READY_TAG_PREFIX)
                   if tag.startswith(value)), "page-jump-")
    pin = f"{tag}:page-jump-v2:{epoch}:{module_sha}:{PAGE_JUMP_CONTROL_MIGRATION_SHA256}"
    return prefix + sha256(pin.encode("ascii")).hexdigest()


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

    def verify_provider_url_import(self):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated provider URL migrations could not be verified."
        try:
            result = self.data_api("POST", path, {"sql": """
                SELECT position, name, sha256, mode,
                  (SELECT count(*) FROM sqlite_schema WHERE type='table'
                    AND name IN ('telegram_provider_jobs','telegram_provider_requests','telegram_provider_replies')) AS queueTables
                FROM subs_bot_schema_migrations WHERE position IN (21, 23) ORDER BY position
            """})
            expected = [{"position": position, "name": name, "sha256": digest, "mode": "applied", "queueTables": 3}
                        for position, name, digest in PROVIDER_URL_IMPORT_MIGRATIONS]
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                     and result[0].get("results") == expected, error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None

    def verify_provider_url_documents(self, *, drained=False):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated provider URL document schema or ledger could not be verified."

        def read(sql):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                     and isinstance(result[0].get("results"), list), error)
            return result[0]["results"]

        try:
            ledger = read("SELECT position,name,sha256,mode FROM subs_bot_schema_migrations "
                          "WHERE position IN (21,23,33,35) ORDER BY position")
            expected = [{"position": position, "name": name, "sha256": digest, "mode": "applied"}
                        for position, name, digest in PROVIDER_URL_DOCUMENTS_MIGRATIONS]
            schema = read("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL AND tbl_name IN ("
                          "'provider_snapshot_attempts','provider_snapshot_object_intents',"
                          "'telegram_provider_document_opt_in','telegram_provider_documents',"
                          "'telegram_provider_document_lines') ORDER BY name")
            fingerprint = sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
            _require(ledger == expected and fingerprint == PROVIDER_URL_DOCUMENTS_SCHEMA_SHA256, error)
            active = read("""SELECT EXISTS(SELECT 1 FROM telegram_provider_documents AS document
                LEFT JOIN telegram_outbox AS reply USING(receipt_id)
                WHERE document.finished_at IS NULL OR reply.state IN ('pending','leased','sending')
                  OR (document.finished_at>unixepoch()-900 AND reply.receipt_id IS NULL)) OR EXISTS (
                SELECT 1 FROM telegram_provider_document_opt_in AS opted
                JOIN telegram_document_jobs AS job USING(receipt_id) WHERE job.state IN ('pending','leased'))
                AS providerDocumentsActive""") if drained else None
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(not drained or (active == [{"providerDocumentsActive": 0}] and type(active[0]["providerDocumentsActive"]) is int),
                 "Drain isolated provider URL documents before switching to a Worker artifact without verified recovery.")

    def verify_mixed_documents(self):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated mixed document schema or ledger could not be verified."
        try:
            result = self.data_api("POST", path, {"sql": """
                SELECT name,sha256,mode,
                  (SELECT sql FROM sqlite_schema WHERE type='table' AND name='telegram_mixed_document_opt_in') AS tableSql,
                  (SELECT count(*) FROM sqlite_schema WHERE sql IS NOT NULL
                    AND tbl_name='telegram_mixed_document_opt_in') AS schemaCount
                FROM subs_bot_schema_migrations WHERE position=36
            """})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0].get("results")
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), error)
            row = rows[0]
            _require(set(row) == {"name", "sha256", "mode", "tableSql", "schemaCount"}
                     and (row["name"], row["sha256"], row["mode"]) == (MIXED_DOCUMENTS_MIGRATION, MIXED_DOCUMENTS_MIGRATION_SHA256, "applied")
                     and type(row["schemaCount"]) is int and row["schemaCount"] == 1
                     and isinstance(row["tableSql"], str)
                     and sha256(row["tableSql"].encode("ascii")).hexdigest() == MIXED_DOCUMENTS_TABLE_SHA256, error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None

    def verify_group_share_cards(self, *, drained=False):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated group share card schema or ledger could not be verified."

        def read(sql):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                     and isinstance(result[0].get("results"), list), error)
            return result[0]["results"]

        try:
            ledger = read("SELECT position,name,sha256,mode FROM subs_bot_schema_migrations WHERE position=37")
            schema = read("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL "
                          "AND tbl_name IN ('telegram_group_share_cards','telegram_group_share_scopes') ORDER BY name")
            fingerprint = sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
            _require(ledger == [{"position": 37, "name": GROUP_SHARE_CARDS_MIGRATION,
                                 "sha256": GROUP_SHARE_CARDS_MIGRATION_SHA256, "mode": "applied"}]
                     and fingerprint == GROUP_SHARE_CARDS_SCHEMA_SHA256, error)
            active = read("""SELECT EXISTS(
                SELECT 1 FROM telegram_group_share_cards
                WHERE state IN ('pending','sending') OR lease_until>unixepoch()
            ) OR EXISTS (
                SELECT 1 FROM telegram_group_share_scopes AS scope
                JOIN telegram_inbox AS inbox USING(receipt_id)
                JOIN telegram_outbox AS reply USING(receipt_id)
                WHERE inbox.receipt_nonce='group-claim:v1' AND reply.state IN ('pending','leased','sending')
            ) AS groupShareCardsActive""") if drained else None
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(not drained or (active == [{"groupShareCardsActive": 0}] and type(active[0]["groupShareCardsActive"]) is int),
                 "Drain isolated group share card work before switching to a Worker artifact without verified recovery.")

    def verify_provider_refresh(self):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated provider refresh migrations could not be verified."
        try:
            result = self.data_api("POST", path, {"sql": """
                SELECT position, name, sha256, mode,
                  (SELECT count(*) FROM sqlite_schema WHERE type='table' AND name IN (
                    'telegram_subscription_read','telegram_provider_jobs','telegram_provider_requests',
                    'telegram_provider_replies','telegram_provider_refresh_tickets')) AS refreshTables,
                  (SELECT count(*) FROM sqlite_schema WHERE type='index'
                    AND name='telegram_provider_refresh_ticket_expiry'
                    AND tbl_name='telegram_provider_refresh_tickets') AS refreshIndex
                FROM subs_bot_schema_migrations WHERE position IN (18, 21, 23, 28) ORDER BY position
            """})
            expected = [{"position": position, "name": name, "sha256": digest, "mode": "applied",
                         "refreshTables": 5, "refreshIndex": 1} for position, name, digest in PROVIDER_REFRESH_MIGRATIONS]
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                     and result[0].get("results") == expected, error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None

    def verify_provider_batch(self, *, drained=False):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated provider batch schema or ledger could not be verified."

        def read(sql):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                     and isinstance(result[0].get("results"), list), error)
            return result[0]["results"]

        try:
            ledger = read("SELECT position,name,sha256,mode FROM subs_bot_schema_migrations "
                          "WHERE position IN (21,23,31,32) ORDER BY position")
            expected = [{"position": position, "name": name, "sha256": digest, "mode": "applied"}
                        for position, name, digest in PROVIDER_BATCH_MIGRATIONS]
            schema = read("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE "
                          "name GLOB 'telegram_provider_batch*' AND sql IS NOT NULL ORDER BY name")
            fingerprint = sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
            _require(ledger == expected and fingerprint == PROVIDER_BATCH_SCHEMA_SHA256, error)
            active = read("""SELECT CASE WHEN EXISTS(
                SELECT 1 FROM telegram_provider_batches WHERE finished_at IS NULL
              ) OR EXISTS(
                SELECT 1 FROM telegram_provider_batch_jobs WHERE state IN ('waiting','pending','leased')
              ) THEN 1 ELSE 0 END AS batchActive""") if drained else None
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(not drained or (active == [{"batchActive": 0}] and type(active[0]["batchActive"]) is int),
                 "Drain isolated provider batches before switching to a different Worker artifact.")

    def verify_api_status(self, *, drained=False):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated API status schema or ledger could not be verified."

        def read(sql):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                     and isinstance(result[0].get("results"), list), error)
            return result[0]["results"]

        try:
            ledger = read("SELECT position,name,sha256,mode FROM subs_bot_schema_migrations WHERE position=34")
            schema = read("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE "
                          "tbl_name='telegram_api_status' AND sql IS NOT NULL ORDER BY name")
            fingerprint = sha256(json.dumps(schema, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()
            _require(ledger == [{"position": 34, "name": API_STATUS_MIGRATION, "sha256": API_STATUS_MIGRATION_SHA256,
                                 "mode": "applied"}] and fingerprint == API_STATUS_SCHEMA_SHA256, error)
            active = read("""SELECT EXISTS(SELECT 1 FROM telegram_api_status AS action
                LEFT JOIN telegram_outbox AS reply USING(receipt_id)
                WHERE action.ready_at IS NULL OR reply.state IN ('pending','leased','sending')
                  OR (action.prompt_receipt_id IS NOT NULL AND action.ready_at>unixepoch()-900
                      AND reply.receipt_id IS NULL)) AS apiStatusActive""") if drained else None
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(not drained or (active == [{"apiStatusActive": 0}] and type(active[0]["apiStatusActive"]) is int),
                 "Drain isolated API status work before switching to a Worker artifact without verified recovery.")

    def verify_legacy_subscription_shorts(self):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated legacy subscription short-link schema could not be verified."
        try:
            result = self.data_api("POST", path, {"sql": """
                SELECT name, sha256, mode,
                  (SELECT sql FROM sqlite_schema WHERE type='table'
                    AND name='legacy_subscription_short_links' AND tbl_name='legacy_subscription_short_links') AS tableSql,
                  (SELECT count(*) FROM sqlite_schema WHERE type='index'
                    AND tbl_name='legacy_subscription_short_links') AS indexCount,
                  (SELECT count(*) FROM sqlite_schema WHERE type='index' AND tbl_name='legacy_subscription_short_links'
                    AND name='sqlite_autoindex_legacy_subscription_short_links_1' AND sql IS NULL) AS primaryIndex
                FROM subs_bot_schema_migrations WHERE position=29
            """})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0].get("results")
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), error)
            row = rows[0]
            _require(set(row) == {"name", "sha256", "mode", "tableSql", "indexCount", "primaryIndex"}
                     and row["name"] == LEGACY_SUBSCRIPTION_SHORT_MIGRATION and row["sha256"] == LEGACY_SUBSCRIPTION_SHORT_SHA256
                     and row["mode"] == "applied" and type(row["indexCount"]) is int and row["indexCount"] == 1
                     and type(row["primaryIndex"]) is int and row["primaryIndex"] == 1
                     and isinstance(row["tableSql"], str)
                     and sha256(row["tableSql"].encode("utf-8")).hexdigest() == LEGACY_SUBSCRIPTION_SHORT_TABLE_SHA256, error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None

    def verify_legacy_selected_floor(self, *, allow_rows, require_schema):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated legacy selected aggregate schema or ledger could not be verified."

        def read(sql, names):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0].get("results")
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
                     and set(rows[0]) == set(names), error)
            return rows[0]

        try:
            schema = read("""SELECT
                count(CASE WHEN name IN ('legacy_selected_aggregates','legacy_selected_members') THEN 1 END) AS sidecars,
                count(CASE WHEN name='subs_bot_schema_migrations' AND type='table' THEN 1 END) AS ledger
                FROM sqlite_schema""", ("sidecars", "ledger"))
            _require(type(schema["sidecars"]) is int and type(schema["ledger"]) is int and schema["ledger"] in (0, 1), error)
            if schema["sidecars"] == 0:
                _require(not require_schema, error)
                if schema["ledger"]:
                    pin = read(f"""SELECT EXISTS (SELECT 1 FROM subs_bot_schema_migrations
                        WHERE position=38 OR name='{LEGACY_SELECTED_MIGRATION}') AS selectedRegistered""", ("selectedRegistered",))
                    _require(type(pin["selectedRegistered"]) is int and pin["selectedRegistered"] == 0, error)
                return
            _require(schema["sidecars"] == 2 and schema["ledger"] == 1, error)
            # Both table definitions, the exact pin and occupancy share one D1 read.
            state = read(f"""SELECT
                (SELECT sql FROM sqlite_schema WHERE type='table' AND name='legacy_selected_aggregates'
                    AND tbl_name='legacy_selected_aggregates') AS markerSql,
                (SELECT sql FROM sqlite_schema WHERE type='table' AND name='legacy_selected_members'
                    AND tbl_name='legacy_selected_members') AS membersSql,
                (SELECT count(*) FROM sqlite_schema WHERE tbl_name IN ('legacy_selected_aggregates','legacy_selected_members')) AS objects,
                (SELECT count(*) FROM sqlite_schema WHERE type='index' AND tbl_name='legacy_selected_aggregates'
                    AND name='sqlite_autoindex_legacy_selected_aggregates_1' AND sql IS NULL) AS markerIndex,
                (SELECT count(*) FROM subs_bot_schema_migrations WHERE position=38 OR name='{LEGACY_SELECTED_MIGRATION}') AS pins,
                EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=38 AND name='{LEGACY_SELECTED_MIGRATION}'
                    AND sha256='{LEGACY_SELECTED_MIGRATION_SHA256}' AND mode='applied') AS pinned,
                EXISTS (SELECT 1 FROM legacy_selected_aggregates) AS markers,
                EXISTS (SELECT 1 FROM legacy_selected_members) AS members""",
                ("markerSql", "membersSql", "objects", "markerIndex", "pins", "pinned", "markers", "members"))
            _require(all(type(state[key]) is int and state[key] == expected for key, expected in
                         (("objects", 3), ("markerIndex", 1), ("pins", 1), ("pinned", 1)))
                     and all(type(state[key]) is int and state[key] in (0, 1) for key in ("markers", "members"))
                     and isinstance(state["markerSql"], str) and isinstance(state["membersSql"], str)
                     and sha256(state["markerSql"].encode("ascii")).hexdigest() == LEGACY_SELECTED_MARKER_TABLE_SHA256
                     and sha256(state["membersSql"].encode("ascii")).hexdigest() == LEGACY_SELECTED_MEMBER_TABLE_SHA256, error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(allow_rows or (state["markers"], state["members"]) == (0, 0),
                 "Keep a Worker with verified legacy selected export and retirement while isolated legacy selected rows exist.")

    def verify_legacy_temp_floor(self, *, allow_rows, require_schema):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated legacy temporary-node schema or ledger could not be verified."

        def read(sql, names):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0].get("results")
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
                     and set(rows[0]) == set(names), error)
            return rows[0]

        try:
            schema = read("""SELECT
                count(CASE WHEN name IN ('legacy_temp_installations','legacy_temp_batches') THEN 1 END) AS tempTables,
                count(CASE WHEN name='subs_bot_schema_migrations' AND type='table' THEN 1 END) AS tempLedger
                FROM sqlite_schema""", ("tempTables", "tempLedger"))
            _require(type(schema["tempTables"]) is int and type(schema["tempLedger"]) is int and schema["tempLedger"] in (0, 1), error)
            if schema["tempTables"] == 0:
                _require(not require_schema, error)
                if schema["tempLedger"]:
                    pin = read(f"""SELECT EXISTS (SELECT 1 FROM subs_bot_schema_migrations
                        WHERE position=39 OR name='{LEGACY_TEMP_MIGRATION}') AS tempRegistered""", ("tempRegistered",))
                    _require(type(pin["tempRegistered"]) is int and pin["tempRegistered"] == 0, error)
                return
            _require(schema["tempTables"] == 2 and schema["tempLedger"] == 1, error)
            state = read(f"""SELECT
                (SELECT sql FROM sqlite_schema WHERE type='table' AND name='legacy_temp_installations'
                    AND tbl_name='legacy_temp_installations') AS tempInstallSql,
                (SELECT sql FROM sqlite_schema WHERE type='table' AND name='legacy_temp_batches'
                    AND tbl_name='legacy_temp_batches') AS tempBatchSql,
                (SELECT count(*) FROM sqlite_schema WHERE tbl_name IN ('legacy_temp_installations','legacy_temp_batches')) AS objects,
                (SELECT count(*) FROM sqlite_schema WHERE type='index' AND sql IS NULL AND (
                    (tbl_name='legacy_temp_installations' AND name='sqlite_autoindex_legacy_temp_installations_1') OR
                    (tbl_name='legacy_temp_batches' AND name='sqlite_autoindex_legacy_temp_batches_1'))) AS primaryIndexes,
                (SELECT count(*) FROM subs_bot_schema_migrations WHERE position=39 OR name='{LEGACY_TEMP_MIGRATION}') AS pins,
                EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=39 AND name='{LEGACY_TEMP_MIGRATION}'
                    AND sha256='{LEGACY_TEMP_MIGRATION_SHA256}' AND mode='applied') AS pinned,
                EXISTS (SELECT 1 FROM legacy_temp_installations) AS installations,
                EXISTS (SELECT 1 FROM legacy_temp_batches) AS batches""",
                ("tempInstallSql", "tempBatchSql", "objects", "primaryIndexes", "pins", "pinned", "installations", "batches"))
            _require(all(type(state[key]) is int and state[key] == expected for key, expected in
                         (("objects", 4), ("primaryIndexes", 2), ("pins", 1), ("pinned", 1)))
                     and all(type(state[key]) is int and state[key] in (0, 1) for key in ("installations", "batches"))
                     and isinstance(state["tempInstallSql"], str) and isinstance(state["tempBatchSql"], str)
                     and sha256(state["tempInstallSql"].encode("ascii")).hexdigest() == LEGACY_TEMP_INSTALL_TABLE_SHA256
                     and sha256(state["tempBatchSql"].encode("ascii")).hexdigest() == LEGACY_TEMP_BATCH_TABLE_SHA256, error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(allow_rows or (state["installations"], state["batches"]) == (0, 0),
                 "Keep a Worker with verified legacy temporary-node reads and mutations while isolated baseline rows exist.")

    def verify_legacy_dynamic_all_floor(self, *, allow_rows, require_schema):
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated legacy dynamic aggregate schema or ledger could not be verified."

        def read(sql, names):
            result = self.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0].get("results")
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
                     and set(rows[0]) == set(names), error)
            return rows[0]

        try:
            schema = read("""SELECT
                count(CASE WHEN name IN ('legacy_all_aggregates','legacy_all_subscription_order') THEN 1 END) AS dynamicAllTables,
                count(CASE WHEN name='legacy_all_aggregates_owner' THEN 1 END) AS ownerIndexObjects,
                count(CASE WHEN name='subs_bot_schema_migrations' THEN 1 END) AS ledgerObjects,
                count(CASE WHEN name='subs_bot_schema_migrations' AND type='table' THEN 1 END) AS ledger
                FROM sqlite_schema""", ("dynamicAllTables", "ownerIndexObjects", "ledgerObjects", "ledger"))
            _require(all(type(schema[key]) is int for key in schema) and schema["ledger"] in (0, 1)
                     and schema["ledgerObjects"] == schema["ledger"], error)
            if schema["dynamicAllTables"] == 0:
                _require(not require_schema and schema["ownerIndexObjects"] == 0, error)
                if schema["ledger"]:
                    pin = read(f"""SELECT EXISTS (SELECT 1 FROM subs_bot_schema_migrations
                        WHERE position=40 OR name='{LEGACY_DYNAMIC_ALL_MIGRATION}') AS dynamicAllRegistered""", ("dynamicAllRegistered",))
                    _require(type(pin["dynamicAllRegistered"]) is int and pin["dynamicAllRegistered"] == 0, error)
                return
            _require(schema["dynamicAllTables"] == 2 and schema["ownerIndexObjects"] == 1 and schema["ledger"] == 1, error)
            state = read(f"""SELECT
                (SELECT sql FROM sqlite_schema WHERE type='table' AND name='legacy_all_aggregates'
                    AND tbl_name='legacy_all_aggregates') AS dynamicAllMarkerSql,
                (SELECT sql FROM sqlite_schema WHERE type='table' AND name='legacy_all_subscription_order'
                    AND tbl_name='legacy_all_subscription_order') AS orderSql,
                (SELECT sql FROM sqlite_schema WHERE type='index' AND name='legacy_all_aggregates_owner'
                    AND tbl_name='legacy_all_aggregates') AS ownerIndexSql,
                (SELECT count(*) FROM sqlite_schema WHERE tbl_name IN ('legacy_all_aggregates','legacy_all_subscription_order')) AS objects,
                (SELECT count(*) FROM sqlite_schema WHERE type='index' AND sql IS NULL AND (
                    (tbl_name='legacy_all_aggregates' AND name='sqlite_autoindex_legacy_all_aggregates_1') OR
                    (tbl_name='legacy_all_subscription_order' AND name='sqlite_autoindex_legacy_all_subscription_order_1'))) AS autoIndexes,
                (SELECT count(*) FROM subs_bot_schema_migrations WHERE position=40 OR name='{LEGACY_DYNAMIC_ALL_MIGRATION}') AS pins,
                EXISTS (SELECT 1 FROM subs_bot_schema_migrations WHERE position=40 AND name='{LEGACY_DYNAMIC_ALL_MIGRATION}'
                    AND sha256='{LEGACY_DYNAMIC_ALL_MIGRATION_SHA256}' AND mode='applied') AS pinned,
                EXISTS (SELECT 1 FROM legacy_all_aggregates) AS markers,
                EXISTS (SELECT 1 FROM legacy_all_subscription_order) AS orderRows""",
                ("dynamicAllMarkerSql", "orderSql", "ownerIndexSql", "objects", "autoIndexes", "pins", "pinned", "markers", "orderRows"))
            _require(all(type(state[key]) is int and state[key] == expected for key, expected in
                         (("objects", 5), ("autoIndexes", 2), ("pins", 1), ("pinned", 1)))
                     and all(type(state[key]) is int and state[key] in (0, 1) for key in ("markers", "orderRows"))
                     and all(isinstance(state[key], str) and sha256(state[key].encode("utf-8")).hexdigest() == expected
                             for key, expected in (("dynamicAllMarkerSql", LEGACY_DYNAMIC_ALL_TABLE_SHA256),
                                                   ("orderSql", LEGACY_DYNAMIC_ALL_ORDER_TABLE_SHA256),
                                                   ("ownerIndexSql", LEGACY_DYNAMIC_ALL_INDEX_SHA256))), error)
        except (CloudflareError, AttributeError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(allow_rows or (state["markers"], state["orderRows"]) == (0, 0),
                 "Keep a Worker with verified legacy dynamic aggregate reads and ordering while isolated dynamic aggregate rows exist.")

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

    def version(self, version_id, *, with_legacy_selected=False, with_legacy_temp=False, with_legacy_dynamic_all=False,
                page_jump_epoch=None):
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
        _require(isinstance(rows, list) and 3 <= len(rows) <= 25 + int(page_jump_epoch is not None)
                 and all(isinstance(row, dict) and isinstance(row.get("name"), str) for row in rows),
                 "Unexpected isolated Worker binding inventory.")
        bindings = {row["name"]: row for row in rows}
        if page_jump_epoch is None:
            _require(PAGE_JUMP_BINDING not in bindings,
                     "An admission-enabled page-jump release requires a separately reviewed pause and drain.")
        else:
            _require(bindings.pop(PAGE_JUMP_BINDING, None) == _page_jump_binding(page_jump_epoch),
                     "The isolated staged page-jump epoch differs.")
        base_bindings = {"DB", "NODES", "BUILD_REVISION"}
        telegram_bindings = base_bindings | TELEGRAM_BINDINGS
        has_provider = bool(PROVIDER_BINDINGS & bindings.keys())
        has_api_status = bool(PROVIDER_API_STATUS_BINDINGS & bindings.keys())
        inline = bindings.get(INLINE_SEARCH_BINDING)
        provider_url = bindings.get(PROVIDER_URL_IMPORT_BINDING)
        provider_documents = bindings.get(PROVIDER_URL_DOCUMENTS_BINDING)
        mixed_documents = bindings.get(MIXED_DOCUMENTS_BINDING)
        group_share_cards = bindings.get(GROUP_SHARE_CARDS_BINDING)
        refresh = bindings.get(PROVIDER_REFRESH_BINDING)
        legacy_shorts = bindings.get(LEGACY_SUBSCRIPTION_SHORT_BINDING)
        provider_batch = bindings.get(PROVIDER_BATCH_BINDING)
        api_status = bindings.get(API_STATUS_BINDING)
        binding_names = set(bindings) - PROVIDER_BINDINGS - PROVIDER_API_STATUS_BINDINGS - {
            INLINE_SEARCH_BINDING, PROVIDER_URL_IMPORT_BINDING, PROVIDER_REFRESH_BINDING, LEGACY_SUBSCRIPTION_SHORT_BINDING,
            PROVIDER_BATCH_BINDING, API_STATUS_BINDING, PROVIDER_URL_DOCUMENTS_BINDING, MIXED_DOCUMENTS_BINDING,
            GROUP_SHARE_CARDS_BINDING,
        }
        _require(len(bindings) + int(page_jump_epoch is not None) == len(rows) and binding_names in (base_bindings, telegram_bindings,
            telegram_bindings | AGGREGATE_BINDINGS, telegram_bindings | PRIVATE_SHARE_BINDINGS,
            telegram_bindings | AGGREGATE_BINDINGS | PRIVATE_SHARE_BINDINGS)
            and (not has_provider or PROVIDER_BINDINGS <= bindings.keys())
            and (not has_api_status or (PROVIDER_API_STATUS_BINDINGS <= bindings.keys() and TELEGRAM_BINDINGS <= binding_names)),
                 "Unexpected isolated Worker binding names.")
        _require(inline is None or (TELEGRAM_BINDINGS <= binding_names and inline == {
            "name": INLINE_SEARCH_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker inline search binding.")
        _require(provider_url is None or (has_provider and TELEGRAM_BINDINGS <= binding_names and provider_url == {
            "name": PROVIDER_URL_IMPORT_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker provider URL import binding.")
        _require(provider_documents is None or (has_provider and TELEGRAM_BINDINGS <= binding_names and provider_documents == {
            "name": PROVIDER_URL_DOCUMENTS_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker provider URL document binding.")
        _require(mixed_documents is None or (provider_documents is not None and mixed_documents == {
            "name": MIXED_DOCUMENTS_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker mixed document binding.")
        _require(group_share_cards is None or (TELEGRAM_BINDINGS | PRIVATE_SHARE_BINDINGS <= binding_names
                 and group_share_cards == {"name": GROUP_SHARE_CARDS_BINDING, "type": "plain_text", "text": "1"}),
                 "Unexpected isolated Worker group share card binding.")
        _require(refresh is None or (has_provider and TELEGRAM_BINDINGS <= binding_names and refresh == {
            "name": PROVIDER_REFRESH_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker provider refresh binding.")
        _require(legacy_shorts is None or legacy_shorts == {
            "name": LEGACY_SUBSCRIPTION_SHORT_BINDING, "type": "plain_text", "text": "1",
        }, "Unexpected isolated Worker legacy subscription short-link binding.")
        _require(provider_batch is None or (has_provider and TELEGRAM_BINDINGS <= binding_names and provider_batch == {
            "name": PROVIDER_BATCH_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker provider batch binding.")
        _require(api_status is None or (has_api_status and api_status == {
            "name": API_STATUS_BINDING, "type": "plain_text", "text": "1",
        }), "Unexpected isolated Worker API status admission binding.")
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
        api_status_binding = None
        if has_api_status:
            service = bindings["PROVIDER_API_STATUS"]
            names = ("PROVIDER_API_STATUS_REVISION", "PROVIDER_API_STATUS_IMAGE_SHA256", "PROVIDER_API_STATUS_IDENTITY_SHA256")
            pins = [bindings[name] for name in names]
            _require(set(service) <= {"name", "type", "service", "entrypoint", "environment"}
                     and service.get("type") == "service" and service.get("service") == PROVIDER_API_STATUS_SERVICE
                     and service.get("entrypoint") == PROVIDER_API_STATUS_ENTRYPOINT
                     and service.get("environment") in (None, "production")
                     and all(set(pin) == {"name", "type", "text"} and pin["type"] == "plain_text" for pin in pins),
                     "Isolated API status V2 binding differs from the reviewed service.")
            api_status_binding = ProviderApiStatusBinding(*(pin["text"] for pin in pins))
        tag = annotations.get("workers/tag")
        module_sha256 = sha256(body).hexdigest()
        _require(page_jump_epoch is None or (telegram_digest is not None and PAGE_JUMP_MARKER in body
                 and PAGE_JUMP_CONTROL_MARKER in body), "The isolated Worker lacks staged page-jump capability.")

        def tag_matches(expected):
            return tag == _page_jump_tag(expected, page_jump_epoch, module_sha256)

        batch_capable = isinstance(tag, str) and tag.startswith((PROVIDER_BATCH_TAG_PREFIX, PROVIDER_BATCH_READY_TAG_PREFIX))
        _require(provider_url is not None or not (isinstance(tag, str) and tag.startswith(PROVIDER_URL_IMPORT_TAG_PREFIX)),
                 "Isolated Worker provider URL import release tag differs.")
        _require(refresh is not None or not (isinstance(tag, str) and tag.startswith(PROVIDER_REFRESH_TAG_PREFIX)),
                 "Isolated Worker provider refresh release tag differs.")
        _require(legacy_shorts is not None or not (isinstance(tag, str) and tag.startswith(LEGACY_SUBSCRIPTION_SHORT_TAG_PREFIX)),
                 "Isolated Worker legacy subscription short-link release tag differs.")
        _require((provider_batch is not None) == (batch_capable and tag.startswith(PROVIDER_BATCH_TAG_PREFIX)),
                 "Isolated Worker provider batch release tag differs.")
        _require(has_api_status or not (isinstance(tag, str) and tag.startswith("api-status-")),
                 "Isolated Worker API status release tag differs.")
        documents_capable = False
        mixed_documents_capable = False
        group_share_cards_capable = False
        has_group_share_cards_marker = GROUP_SHARE_CARDS_MARKER in body
        if (batch_capable or has_api_status or page_jump_epoch is not None
                or any(binding is not None for binding in (inline, provider_url, refresh, legacy_shorts))):
            release_tag = _release_tag(rev["text"], telegram_digest, aggregate_digest, private_share_digest, provider_binding)
            tag_inputs = (_api_status_tag(release_tag, api_status_binding, api_status is not None),
                          inline is not None, provider_url is not None, refresh is not None, legacy_shorts is not None,
                          provider_batch is not None, module_sha256 if batch_capable else None)
            expected = _telegram_feature_tag(*tag_inputs)
            document_tag_inputs = {"url_documents": provider_documents is not None, "url_documents_module_sha256": module_sha256}
            mixed_tag_inputs = {**document_tag_inputs, "mixed_documents": mixed_documents is not None}
            group_share_cards_capable = batch_capable and has_group_share_cards_marker and tag_matches(_telegram_feature_tag(
                *tag_inputs, **mixed_tag_inputs, group_share_cards=group_share_cards is not None))
            mixed_documents_capable = group_share_cards_capable or (batch_capable and tag_matches(_telegram_feature_tag(
                *tag_inputs, **mixed_tag_inputs)))
            documents_capable = mixed_documents_capable or (batch_capable and tag_matches(_telegram_feature_tag(
                *tag_inputs, **document_tag_inputs)))
            feature = "API status" if has_api_status else "inline search"
            if batch_capable:
                feature = "provider batch"
            elif legacy_shorts is not None:
                feature = "legacy subscription short-link"
            elif refresh is not None:
                feature = "provider refresh"
            elif provider_url is not None:
                feature = "provider URL import"
            elif page_jump_epoch is not None:
                feature = "page-jump"
            _require(tag_matches(expected) or documents_capable, f"Isolated Worker {feature} release tag differs.")
        _require(provider_documents is None or documents_capable, "Isolated Worker provider URL document release tag differs.")
        _require(mixed_documents is None or mixed_documents_capable, "Isolated Worker mixed document release tag differs.")
        _require(group_share_cards_capable == has_group_share_cards_marker
                 and (group_share_cards is None or group_share_cards_capable),
                 "Isolated Worker group share card release tag differs.")
        value = _Version(rev["text"], module_sha256, version["compatibility_date"],
                        tag, telegram_digest, aggregate_digest, private_share_digest, provider_binding, inline is not None,
                        provider_url is not None, refresh is not None, legacy_shorts is not None,
                        provider_batch is not None, batch_capable, api_status_binding, api_status is not None,
                        provider_documents is not None, documents_capable, mixed_documents is not None, mixed_documents_capable,
                        group_share_cards is not None, group_share_cards_capable,
                        telegram_page_jump_capable=PAGE_JUMP_MARKER in body,
                        telegram_page_jump_control_capable=PAGE_JUMP_CONTROL_MARKER in body,
                        telegram_page_jump_epoch=page_jump_epoch)
        capabilities = tuple(check(body) for requested, check in (
            (with_legacy_selected, _legacy_selected_module_capable),
            (with_legacy_temp, _legacy_temp_module_capable),
            (with_legacy_dynamic_all, _legacy_dynamic_all_module_capable),
        ) if requested)
        return (value, *capabilities) if capabilities else value

    def verify_candidate(self, candidate, desired):
        # A version can be visible in its creation response or listing before its module is readable.
        for delay in READBACK_DELAYS:
            if delay:
                sleep(delay)
            try:
                actual = self.version(candidate, page_jump_epoch=desired.telegram_page_jump_epoch)
            except CloudflareError as error:
                if error.http_status != 404:
                    raise
                continue
            _require(actual == desired, "Isolated candidate Worker version differs from the verified artifact.")
            return candidate
        raise CloudflareError("Isolated candidate Worker version readback could not be confirmed (HTTP 404).",
                              uncertain=True, http_status=404)

    def staged(self, desired):
        candidates = []
        seen = set()
        epoch_bound = desired.telegram_page_jump_epoch is not None
        for page in range(1, 11 if epoch_bound else 2):
            rows = self.worker_api("GET", f"{self.versions}?page={page}&per_page=100")
            _require(isinstance(rows, list) and (not epoch_bound or len(rows) <= 100), "Invalid Cloudflare Worker version list.")
            for row in rows:
                item = _object(row, "listed Worker version")
                version_id = item.get("id")
                if epoch_bound:
                    _require(_matches(UUID, version_id) and version_id not in seen, "Ambiguous isolated page-jump version listing.")
                    seen.add(version_id)
                annotations = _object(item.get("annotations") or {}, "version annotations")
                if annotations.get("workers/tag") == desired.tag:
                    candidates.append(version_id)
            if not epoch_bound or not rows:
                break
        else:
            raise CloudflareError("The isolated page-jump version listing exceeded its verified bound.")
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
        if desired.telegram_provider_url_import:
            bindings.append({"type": "plain_text", "name": PROVIDER_URL_IMPORT_BINDING, "text": "1"})
        if desired.telegram_provider_url_documents:
            bindings.append({"type": "plain_text", "name": PROVIDER_URL_DOCUMENTS_BINDING, "text": "1"})
        if desired.telegram_mixed_documents:
            bindings.append({"type": "plain_text", "name": MIXED_DOCUMENTS_BINDING, "text": "1"})
        if desired.telegram_group_share_cards:
            bindings.append({"type": "plain_text", "name": GROUP_SHARE_CARDS_BINDING, "text": "1"})
        if desired.telegram_provider_refresh:
            bindings.append({"type": "plain_text", "name": PROVIDER_REFRESH_BINDING, "text": "1"})
        if desired.legacy_subscription_shorts:
            bindings.append({"type": "plain_text", "name": LEGACY_SUBSCRIPTION_SHORT_BINDING, "text": "1"})
        if desired.telegram_provider_batch:
            bindings.append({"type": "plain_text", "name": PROVIDER_BATCH_BINDING, "text": "1"})
        if desired.api_status_binding is not None:
            binding = desired.api_status_binding
            bindings.extend([
                {"type": "service", "name": "PROVIDER_API_STATUS", "service": PROVIDER_API_STATUS_SERVICE,
                 "entrypoint": PROVIDER_API_STATUS_ENTRYPOINT},
                {"type": "plain_text", "name": "PROVIDER_API_STATUS_REVISION", "text": binding.revision},
                {"type": "plain_text", "name": "PROVIDER_API_STATUS_IMAGE_SHA256", "text": binding.image_sha256},
                {"type": "plain_text", "name": "PROVIDER_API_STATUS_IDENTITY_SHA256", "text": binding.identity_sha256},
            ])
        if desired.telegram_api_status:
            bindings.append({"type": "plain_text", "name": API_STATUS_BINDING, "text": "1"})
        if desired.telegram_page_jump_epoch is not None:
            bindings.append(_page_jump_binding(desired.telegram_page_jump_epoch))
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

    def verify_page_jump_drain(self, current, target):
        downgrade = (current.telegram_page_jump_capable and not target.telegram_page_jump_capable
                     or current.telegram_page_jump_control_capable and not target.telegram_page_jump_control_capable)
        if not downgrade:
            return
        markers = "'view-jump:v2'" if target.telegram_page_jump_capable else "'view-jump:v1','view-jump:v2'"
        control_open = ("EXISTS (SELECT 1 FROM telegram_page_jump_controls WHERE enabled=1)"
                        if current.telegram_page_jump_control_capable else "0")
        path = f"{self.account}/d1/database/{self.target['d1Id']}/query"
        error = "The isolated page-jump drain could not be verified."
        try:
            # Admission is off in every version accepted by version(). Concurrent
            # settlements may finish these receipts. They cannot create new ones.
            result = self.data_api("POST", path, {"sql": f"""
                SELECT EXISTS (SELECT 1 FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id)
                    WHERE inbox.receipt_nonce IN ({markers})
                      AND reply.state IN ('pending','leased','sending')) AS pageJumpUnsettled, {control_open} AS pageJumpOpen
            """})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, error)
            rows = result[0]["results"]
            _require(isinstance(rows, list) and len(rows) == 1
                     and all(type(rows[0][field]) is int and rows[0][field] in (0, 1)
                             for field in ("pageJumpUnsettled", "pageJumpOpen")), error)
        except (CloudflareError, AttributeError, KeyError, TypeError, ValueError):
            raise CloudflareError(error) from None
        _require(rows[0]["pageJumpOpen"] == 0, "Close isolated page-jump admission before downgrading.")
        _require(rows[0]["pageJumpUnsettled"] == 0,
                 "Keep a Worker with verified page-jump delivery until isolated page-jump replies have drained.")

    def activate(self, previous, version_id, message, *, current_version, target_version, current_capable, target_capable, guard,
                 current_temp_capable=False, target_temp_capable=False,
                 current_dynamic_all_capable=False, target_dynamic_all_capable=False):
        from page_jump_activation import require_clear_for_release

        # All tracked application deployment writes use this boundary, including rollback.
        _require(current_version.telegram_page_jump_epoch is None and target_version.telegram_page_jump_epoch is None,
                 "An epoch-bound isolated page-jump version may only be staged.")
        self.verify_legacy_selected_floor(allow_rows=current_capable and target_capable,
                                          require_schema=current_capable or target_capable)
        self.verify_legacy_temp_floor(allow_rows=current_temp_capable and target_temp_capable,
                                      require_schema=current_temp_capable or target_temp_capable)
        self.verify_legacy_dynamic_all_floor(allow_rows=current_dynamic_all_capable and target_dynamic_all_capable,
                                             require_schema=current_dynamic_all_capable or target_dynamic_all_capable)
        self.verify_page_jump_drain(current_version, target_version)
        require_clear_for_release(self)
        _require(self.active() == previous, "Active isolated Worker deployment changed before activation.")
        _guard_current(guard)
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


def _verified_module(bundle_dir, expected_digest):
    try:
        path = Path(bundle_dir) / "index.js"
        _require(path.is_file() and not path.is_symlink(), "Verified Worker module is not a regular file.")
        with path.open("rb") as source:
            module = source.read(MAX_MODULE_BYTES + 1)
    except (OSError, ValueError, TypeError):
        raise CloudflareError("Verified Worker module is unavailable.") from None
    _require(0 < len(module) <= MAX_MODULE_BYTES, "The verified Worker module is empty or exceeds the isolation size limit.")
    _require(sha256(module).hexdigest() == expected_digest, "Verified Worker module digest mismatch.")
    return module


def group_share_cards_artifact(bundle_dir, manifest):
    # Earlier artifact manifests cannot advertise the group-card schema.
    return len(manifest["migrations"]) >= 37 and GROUP_SHARE_CARDS_MARKER in _verified_module(
        bundle_dir, manifest.get("bundleSha256"))


def _legacy_selected_module_capable(module):
    return LEGACY_SELECTED_HTTP_MARKER in module and LEGACY_SELECTED_RETIREMENT_MARKER in module


def _legacy_selected_artifact_capable(module, manifest):
    migrations = manifest.get("migrations")
    capable = _legacy_selected_module_capable(module)
    _require(isinstance(migrations, list) and (LEGACY_SELECTED_HTTP_MARKER not in module or capable),
             "The verified Worker lacks complete legacy selected aggregate capability.")
    if len(migrations) >= 38 or LEGACY_SELECTED_RETIREMENT_MARKER in module:
        _require(len(migrations) >= 38 and migrations[37] == {
            "name": LEGACY_SELECTED_MIGRATION, "sha256": LEGACY_SELECTED_MIGRATION_SHA256,
        }, "The verified Worker artifact does not pin the exact legacy selected aggregate migration.")
    return capable


def legacy_selected_artifact(bundle_dir, manifest):
    return _legacy_selected_artifact_capable(_verified_module(bundle_dir, manifest.get("bundleSha256")), manifest)


def _legacy_temp_module_capable(module):
    return LEGACY_TEMP_READ_MARKER in module and LEGACY_TEMP_MUTATE_MARKER in module


def _legacy_temp_artifact_capable(module, manifest):
    migrations = manifest.get("migrations")
    has_marker = LEGACY_TEMP_READ_MARKER in module or LEGACY_TEMP_MUTATE_MARKER in module
    capable = _legacy_temp_module_capable(module)
    _require(isinstance(migrations, list) and (not has_marker or capable),
             "The verified Worker lacks complete legacy temporary-node capability.")
    if len(migrations) >= 39 or has_marker:
        _require(len(migrations) >= 39 and migrations[38] == {
            "name": LEGACY_TEMP_MIGRATION, "sha256": LEGACY_TEMP_MIGRATION_SHA256,
        }, "The verified Worker artifact does not pin the exact legacy temporary-node migration.")
    return capable


def legacy_temp_artifact(bundle_dir, manifest):
    return _legacy_temp_artifact_capable(_verified_module(bundle_dir, manifest.get("bundleSha256")), manifest)


def _legacy_dynamic_all_module_capable(module):
    return LEGACY_DYNAMIC_ALL_READ_MARKER in module and LEGACY_DYNAMIC_ALL_ORDER_MARKER in module


def _legacy_dynamic_all_artifact_capable(module, manifest):
    migrations = manifest.get("migrations")
    has_marker = LEGACY_DYNAMIC_ALL_READ_MARKER in module or LEGACY_DYNAMIC_ALL_ORDER_MARKER in module
    capable = _legacy_dynamic_all_module_capable(module)
    _require(isinstance(migrations, list) and (not has_marker or capable),
             "The verified Worker lacks complete legacy dynamic aggregate capability.")
    if len(migrations) >= 40 or has_marker:
        _require(len(migrations) >= 40 and migrations[39] == {
            "name": LEGACY_DYNAMIC_ALL_MIGRATION, "sha256": LEGACY_DYNAMIC_ALL_MIGRATION_SHA256,
        }, "The verified Worker artifact does not pin the exact legacy dynamic aggregate migration.")
    return capable


def legacy_dynamic_all_artifact(bundle_dir, manifest):
    return _legacy_dynamic_all_artifact_capable(_verified_module(bundle_dir, manifest.get("bundleSha256")), manifest)


def _page_jump_artifact_capabilities(module, manifest):
    migrations = manifest.get("migrations")
    capable = PAGE_JUMP_MARKER in module
    control_capable = PAGE_JUMP_CONTROL_MARKER in module
    _require(isinstance(migrations, list), "The verified Worker artifact lacks a migration chain.")
    if capable or len(migrations) >= 42:
        _require(capable and len(migrations) >= 42 and migrations[41] == {
            "name": PAGE_JUMP_MIGRATION, "sha256": PAGE_JUMP_MIGRATION_SHA256,
        }, "The verified Worker artifact does not pin the exact 0042 page-jump migration and runtime.")
    if control_capable or len(migrations) >= 43:
        _require(capable and control_capable and len(migrations) >= 43 and migrations[42] == {
            "name": PAGE_JUMP_CONTROL_MIGRATION, "sha256": PAGE_JUMP_CONTROL_MIGRATION_SHA256,
        }, "The verified Worker artifact does not pin the exact 0043 page-jump control migration and runtime.")
    return capable, control_capable


def verify_page_jump_artifact(bundle_dir, manifest):
    _page_jump_artifact_capabilities(_verified_module(bundle_dir, manifest.get("bundleSha256")), manifest)


def _artifact(bundle_dir, manifest, telegram_config, aggregate_key=None, private_share_key=None, provider_binding=None):
    _require(isinstance(manifest, dict) and manifest.get("version") == 2
             and _matches(REVISION, manifest.get("revision")) and _matches(DIGEST, manifest.get("bundleSha256"))
             and _matches(DATE, manifest.get("compatibilityDate")) and isinstance(manifest.get("migrations"), list),
             "Invalid verified Worker release manifest.")
    module = _verified_module(bundle_dir, manifest["bundleSha256"])
    page_jump_capable, page_jump_control_capable = _page_jump_artifact_capabilities(module, manifest)
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
                            tag, telegram_digest, aggregate_digest, private_share_digest, provider_binding,
                            telegram_page_jump_capable=page_jump_capable,
                            telegram_page_jump_control_capable=page_jump_control_capable)


def _read_health():
    request = Request(HEALTH_URL, headers={"Accept": "application/json",
                                         "User-Agent": ISOLATION_RELEASE_USER_AGENT})
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


def _verify_first_provider_binding(active, desired, revision, proof_guard, historical_application_revision):
    if active.provider_binding is not None or desired is None:
        return
    expected_revision = desired.revision
    if historical_application_revision is not None:
        _require(_matches(REVISION, historical_application_revision) and historical_application_revision != desired.revision
                 and active.revision == desired.revision,
                 "First historical provider binding requires the exact active isolated health baseline.")
        expected_revision = historical_application_revision
    _require(expected_revision == revision,
             "First provider binding requires proof of the same main revision as the application release.")
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


def _provider_url_import_target(active, requested, manifest, telegram_digest, provider_binding, had_cron):
    _require(requested is None or type(requested) is bool, "Invalid isolated provider URL import release mode.")
    enabled = active.telegram_provider_url_import if requested is None else requested
    if not (active.telegram_provider_url_import or enabled):
        return enabled
    _require(had_cron and active.provider_binding is not None and provider_binding == active.provider_binding
             and telegram_digest is not None and telegram_digest == active.telegram_config_sha256,
             "Isolated provider URL import requires the same active provider, Telegram policy and Cron.")
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    _require(isinstance(entries, list) and all(len(entries) >= position and entries[position - 1] == {"name": name, "sha256": digest}
             for position, name, digest in PROVIDER_URL_IMPORT_MIGRATIONS),
             "Isolated provider URL import requires the exact 0021 and 0023 migration artifacts.")
    if enabled and not active.telegram_provider_url_import:
        # A rollback of the first enable must still drain already-admitted jobs.
        _require(active.revision == manifest.get("revision") and active.digest == manifest.get("bundleSha256")
                 and active.compatibility == manifest.get("compatibilityDate"),
                 "Enable provider URL import only after verifying the same Worker artifact with admission disabled.")
    return enabled


def _provider_url_documents_target(active, requested, manifest, telegram_digest, provider_binding, had_cron):
    _require(requested is None or type(requested) is bool, "Invalid isolated provider URL document release mode.")
    enabled = active.telegram_provider_url_documents if requested is None else requested
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    includes_schema = isinstance(entries, list) and len(entries) >= 35
    capable = includes_schema and all(entries[position - 1] == {"name": name, "sha256": digest}
                                     for position, name, digest in PROVIDER_URL_DOCUMENTS_MIGRATIONS)
    _require(not (includes_schema or active.telegram_provider_url_documents_capable or enabled) or capable,
             "Isolated provider URL documents require the exact 0021, 0023, 0033 and 0035 migration artifacts.")
    if active.telegram_provider_url_documents or enabled:
        _require(had_cron and active.provider_binding is not None and provider_binding == active.provider_binding
                 and telegram_digest is not None and telegram_digest == active.telegram_config_sha256,
                 "Isolated provider URL documents require the same active V1 Provider, Telegram policy and Cron.")
    if enabled and not active.telegram_provider_url_documents:
        _require(active.telegram_provider_url_documents_capable and active.revision == manifest.get("revision")
                 and active.digest == manifest.get("bundleSha256") and active.compatibility == manifest.get("compatibilityDate"),
                 "Enable provider URL documents only after verifying the same Worker artifact with admission disabled.")
    return enabled, capable


def _mixed_documents_target(active, requested, manifest, documents_enabled, documents_capable):
    _require(requested is None or type(requested) is bool, "Invalid isolated mixed document release mode.")
    enabled = active.telegram_mixed_documents if requested is None else requested
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    includes_schema = isinstance(entries, list) and len(entries) >= 36
    capable = documents_capable and includes_schema and entries[35] == {
        "name": MIXED_DOCUMENTS_MIGRATION, "sha256": MIXED_DOCUMENTS_MIGRATION_SHA256,
    }
    _require(not (includes_schema or active.telegram_mixed_documents_capable or enabled) or capable,
             "Isolated mixed documents require the exact 0036 migration artifact and provider URL document schema.")
    if enabled:
        # The existing URL-document release gate verifies the pinned V1 Provider, Telegram policy and Cron.
        _require(active.telegram_provider_url_documents and documents_enabled,
                 "Isolated mixed documents require active and preserved provider URL document admission.")
        if not active.telegram_mixed_documents:
            _require(active.telegram_mixed_documents_capable and active.revision == manifest.get("revision")
                     and active.digest == manifest.get("bundleSha256") and active.compatibility == manifest.get("compatibilityDate"),
                     "Enable mixed documents only after verifying the same Worker artifact with admission disabled.")
    return enabled, capable


def _group_share_cards_target(active, requested, manifest, capable, telegram_digest, private_share_digest, had_cron):
    _require(requested is None or type(requested) is bool, "Invalid isolated group share card release mode.")
    enabled = active.telegram_group_share_cards if requested is None else requested
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    includes_schema = isinstance(entries, list) and len(entries) >= 37
    if includes_schema or capable:
        _require(includes_schema and entries[36] == {
            "name": GROUP_SHARE_CARDS_MIGRATION, "sha256": GROUP_SHARE_CARDS_MIGRATION_SHA256,
        }, "Isolated group share cards require the exact 0037 migration artifact.")
    _require(not (active.telegram_group_share_cards or enabled) or capable,
             "Keep a verified group share card artifact active when changing or preserving admission.")
    if active.telegram_group_share_cards or enabled:
        _require(had_cron and telegram_digest is not None and telegram_digest == active.telegram_config_sha256
                 and private_share_digest is not None and private_share_digest == active.telegram_private_share_key_sha256,
                 "Group share cards require the existing isolated Telegram policy, Cron and private share key.")
    if enabled and not active.telegram_group_share_cards:
        _require(active.telegram_group_share_cards_capable and active.revision == manifest.get("revision")
                 and active.digest == manifest.get("bundleSha256") and active.compatibility == manifest.get("compatibilityDate"),
                 "Enable group share cards only after verifying the same Worker artifact with admission disabled.")
    return enabled


def _provider_refresh_target(active, requested, manifest, telegram_digest, provider_binding, had_cron):
    _require(requested is None or type(requested) is bool, "Invalid isolated provider refresh release mode.")
    enabled = active.telegram_provider_refresh if requested is None else requested
    if not (active.telegram_provider_refresh or enabled):
        return enabled
    _require(had_cron and active.provider_binding is not None and provider_binding == active.provider_binding
             and telegram_digest is not None and telegram_digest == active.telegram_config_sha256,
             "Isolated provider refresh requires the same active provider, Telegram policy and Cron.")
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    _require(isinstance(entries, list) and all(len(entries) >= position and entries[position - 1] == {"name": name, "sha256": digest}
             for position, name, digest in PROVIDER_REFRESH_MIGRATIONS),
             "Isolated provider refresh requires the exact 0018, 0021, 0023 and 0028 migration artifacts.")
    if enabled and not active.telegram_provider_refresh:
        # The disabled artifact must still drain refresh jobs and reap tickets after a rollback.
        _require(active.revision == manifest.get("revision") and active.digest == manifest.get("bundleSha256")
                 and active.compatibility == manifest.get("compatibilityDate"),
                 "Enable provider refresh only after verifying the same Worker artifact with admission disabled.")
    return enabled


def _legacy_subscription_shorts_target(active, requested, manifest):
    _require(requested is None or type(requested) is bool, "Invalid isolated legacy subscription short-link release mode.")
    enabled = active.legacy_subscription_shorts if requested is None else requested
    if not (active.legacy_subscription_shorts or enabled):
        return enabled
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    _require(isinstance(entries, list) and len(entries) >= 29 and entries[28] == {
        "name": LEGACY_SUBSCRIPTION_SHORT_MIGRATION, "sha256": LEGACY_SUBSCRIPTION_SHORT_SHA256,
    }, "Isolated legacy subscription short links require the exact 0029 migration artifact.")
    if enabled and not active.legacy_subscription_shorts:
        _require(active.revision == manifest.get("revision") and active.digest == manifest.get("bundleSha256")
                 and active.compatibility == manifest.get("compatibilityDate"),
                 "Enable legacy subscription short links only after verifying the same Worker artifact with compatibility disabled.")
    return enabled


def _provider_batch_target(active, requested, manifest, telegram_digest, provider_binding, had_cron):
    _require(requested is None or type(requested) is bool, "Invalid isolated provider batch release mode.")
    enabled = active.telegram_provider_batch if requested is None else requested
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    capable = isinstance(entries, list) and all(len(entries) >= position and
        entries[position - 1] == {"name": name, "sha256": digest}
        for position, name, digest in PROVIDER_BATCH_MIGRATIONS)
    # A manifest that purports to include the controls must match both exact migration digests.
    includes_controls = isinstance(entries, list) and len(entries) >= 32
    _require(not (includes_controls or active.telegram_provider_batch_capable or enabled) or capable,
             "Isolated provider batch requires the exact 0021, 0023, 0031 and 0032 migration artifacts.")
    if active.telegram_provider_batch or enabled:
        _require(had_cron and active.provider_binding is not None and provider_binding == active.provider_binding
                 and telegram_digest is not None and telegram_digest == active.telegram_config_sha256,
                 "Isolated provider batch requires the same active provider, Telegram policy and Cron.")
    if enabled and not active.telegram_provider_batch:
        _require(active.telegram_provider_batch_capable and active.revision == manifest.get("revision")
                 and active.digest == manifest.get("bundleSha256") and active.compatibility == manifest.get("compatibilityDate"),
                 "Enable provider batch only after verifying the same Worker artifact with admission disabled.")
    return enabled, capable


def _api_status_target(active, requested, manifest, telegram_digest, had_cron, load_gate):
    _require(requested is None or type(requested) is bool, "Invalid isolated API status release mode.")
    enabled = active.telegram_api_status if requested is None else requested
    entries = manifest.get("migrations") if isinstance(manifest, dict) else None
    includes_schema = isinstance(entries, list) and len(entries) >= 34
    capable = includes_schema and entries[33] == {"name": API_STATUS_MIGRATION, "sha256": API_STATUS_MIGRATION_SHA256}
    existing = active.api_status_binding
    _require(not (includes_schema or existing is not None or enabled) or capable,
             "Isolated API status requires the exact 0034 migration artifact.")
    if existing is not None or enabled:
        _require(had_cron and telegram_digest is not None and telegram_digest == active.telegram_config_sha256,
                 "Isolated API status requires the same active Telegram policy and Cron.")
    same_artifact = (isinstance(manifest, dict) and active.revision == manifest.get("revision")
                     and active.digest == manifest.get("bundleSha256")
                     and active.compatibility == manifest.get("compatibilityDate"))
    if enabled and not active.telegram_api_status:
        _require(same_artifact, "Enable API status only after verifying the same Worker artifact with admission disabled.")
    gate = None
    binding = existing
    if enabled:
        gate = load_gate() if callable(load_gate) else None
        binding = getattr(gate, "binding", None)
        _require(isinstance(binding, ProviderApiStatusBinding), "Enable API status with a verified private V2 activation proof.")
        _require(existing is None or existing == binding, "Changing the isolated API status V2 pin requires a separate release.")
    # Turning admission off retains the immutable binding and never needs the dependency to be healthy.
    return enabled, binding, gate, capable, capable and existing is None and not same_artifact


def _verify_api_status_dependency(active, gate, revision):
    if gate is not None:
        if active.api_status_binding is None:
            gate.verify_first_binding(revision)
        gate.verify()


def _require_telegram_config_continuity(active, desired_digest):
    _require(active.telegram_config_sha256 is None or active.telegram_config_sha256 == desired_digest,
             "Changing or dropping the isolated Telegram configuration requires a separate scoped release.")


def verify_worker_target(worker_api, data_api, target, *, aggregate_key=_UNSPECIFIED_AGGREGATE_KEY,
                         private_share_key=_UNSPECIFIED_PRIVATE_SHARE_KEY, provider_binding=_UNSPECIFIED_PROVIDER_BINDING,
                         release_revision=None, provider_first_binding_guard=None, historical_application_revision=None,
                         release_manifest=None,
                         telegram_config=_UNSPECIFIED_TELEGRAM_CONFIG, inline_search=None, provider_url_import=None,
                         provider_refresh=None, legacy_subscription_shorts=None, provider_batch=None,
                         api_status=None, api_status_gate=_UNSPECIFIED_API_STATUS_GATE, provider_url_documents=None,
                         mixed_documents=None, group_share_cards=None, group_share_cards_capable=None,
                         legacy_selected_capable=None, legacy_temp_capable=None, legacy_dynamic_all_capable=None):
    """Read ownership, privacy and active binding facts before any release writes."""
    from page_jump_activation import require_clear_for_release

    scope = _Isolation(worker_api, data_api, target)
    scope.worker_config()
    had_cron = scope.cron_enabled()
    scope.verify_resources()
    require_clear_for_release(scope)
    active = scope.active()
    version, active_selected_capable, active_temp_capable, active_dynamic_all_capable = scope.version(
        active.version, with_legacy_selected=True, with_legacy_temp=True, with_legacy_dynamic_all=True)
    if legacy_selected_capable is not None:
        _require(type(legacy_selected_capable) is bool, "The verified legacy selected release capability is invalid.")
        # A first capable release may still be about to apply 0038.
        scope.verify_legacy_selected_floor(allow_rows=active_selected_capable and legacy_selected_capable,
                                          require_schema=active_selected_capable)
    if legacy_temp_capable is not None:
        _require(type(legacy_temp_capable) is bool, "The verified legacy temporary-node release capability is invalid.")
        scope.verify_legacy_temp_floor(allow_rows=active_temp_capable and legacy_temp_capable,
                                       require_schema=active_temp_capable)
    if legacy_dynamic_all_capable is not None:
        _require(type(legacy_dynamic_all_capable) is bool, "The verified legacy dynamic aggregate release capability is invalid.")
        scope.verify_legacy_dynamic_all_floor(allow_rows=active_dynamic_all_capable and legacy_dynamic_all_capable,
                                             require_schema=active_dynamic_all_capable)
    # Read-only fixtures can inspect the live binding without the secret.
    desired_digest = None
    if telegram_config is not _UNSPECIFIED_TELEGRAM_CONFIG:
        _require(telegram_config is None or isinstance(telegram_config, str), "The isolated Telegram configuration is invalid.")
        desired_digest = sha256(telegram_config.encode("utf-8")).hexdigest() if telegram_config is not None else None
        _require_telegram_config_continuity(version, desired_digest)
    # Releases explicitly pass their expected keys.
    if aggregate_key is not _UNSPECIFIED_AGGREGATE_KEY and version.telegram_aggregate_key_sha256 is not None:
        validate_aggregate_key(aggregate_key)
        _require(version.telegram_aggregate_key_sha256 == sha256(aggregate_key.encode("ascii")).hexdigest(),
                 "Changing the isolated aggregate key requires a separate rotation release.")
    private_share_digest = None
    if private_share_key is not _UNSPECIFIED_PRIVATE_SHARE_KEY and version.telegram_private_share_key_sha256 is not None:
        validate_private_share_key(private_share_key)
        private_share_digest = sha256(private_share_key.encode("ascii")).hexdigest()
        _require(version.telegram_private_share_key_sha256 == private_share_digest,
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
    verify_provider_url = False
    if release_manifest is not None or provider_url_import is not None:
        enabled = _provider_url_import_target(version, provider_url_import, release_manifest, desired_digest, provider_binding, had_cron)
        verify_provider_url = version.telegram_provider_url_import or enabled
    verify_provider_refresh = False
    if release_manifest is not None or provider_refresh is not None:
        enabled = _provider_refresh_target(version, provider_refresh, release_manifest, desired_digest, provider_binding, had_cron)
        verify_provider_refresh = version.telegram_provider_refresh or enabled
    if verify_provider_refresh:
        scope.verify_provider_refresh()
    elif verify_provider_url:
        scope.verify_provider_url_import()
    if release_manifest is not None or legacy_subscription_shorts is not None:
        enabled = _legacy_subscription_shorts_target(version, legacy_subscription_shorts, release_manifest)
        if version.legacy_subscription_shorts or enabled:
            scope.verify_legacy_subscription_shorts()
    if release_manifest is not None or provider_batch is not None:
        enabled, _ = _provider_batch_target(version, provider_batch, release_manifest, desired_digest, provider_binding, had_cron)
        if version.telegram_provider_batch_capable or enabled:
            scope.verify_provider_batch()
    if release_manifest is not None or provider_url_documents is not None or mixed_documents is not None:
        documents_enabled, documents_capable = _provider_url_documents_target(version, provider_url_documents,
            release_manifest, desired_digest, provider_binding, had_cron)
        mixed_enabled, _ = _mixed_documents_target(version, mixed_documents, release_manifest, documents_enabled, documents_capable)
        if version.telegram_provider_url_documents_capable or documents_enabled:
            scope.verify_provider_url_documents()
        if version.telegram_mixed_documents_capable or mixed_enabled:
            scope.verify_mixed_documents()
        if ((documents_enabled and not version.telegram_provider_url_documents)
                or (mixed_enabled and not version.telegram_mixed_documents)):
            _verify_health(version.revision)
            _require(scope.active() == active, "Active isolated Worker deployment changed during URL document verification.")
    if api_status_gate is not _UNSPECIFIED_API_STATUS_GATE or api_status is not None:
        enabled, binding, gate, _, _ = _api_status_target(version, api_status, release_manifest, desired_digest,
                                                        had_cron, api_status_gate)
        if binding is not None:
            scope.verify_api_status()
        if enabled:
            if not version.telegram_api_status:
                _verify_health(version.revision)
            _verify_api_status_dependency(version, gate, release_revision)
            _require(scope.active() == active, "Active isolated Worker deployment changed during API status proof verification.")
    if group_share_cards_capable is not None or group_share_cards is not None:
        enabled = _group_share_cards_target(version, group_share_cards, release_manifest, group_share_cards_capable,
                                            desired_digest, private_share_digest, had_cron)
        if version.telegram_group_share_cards_capable or enabled:
            scope.verify_group_share_cards(drained=not group_share_cards_capable)
        if enabled and not version.telegram_group_share_cards:
            _verify_health(version.revision)
            _require(scope.active() == active, "Active isolated Worker deployment changed during group share card verification.")
    if provider_binding is not _UNSPECIFIED_PROVIDER_BINDING:
        _verify_first_provider_binding(version, provider_binding, release_revision, provider_first_binding_guard,
                                       historical_application_revision)
        if historical_application_revision is not None and version.provider_binding is None and provider_binding is not None:
            _verify_health(version.revision)
            _require(scope.active() == active, "Active isolated Worker deployment changed during historical proof verification.")
    return {"deploymentId": active.id, "versionId": active.version, "revision": version.revision}


def release_worker(worker_api, data_api, target, bundle_dir, manifest, guard, *, expected_active=None,
                   telegram_config: str | None = None, aggregate_key: str | None = None, private_share_key: str | None = None,
                   provider_binding: ProviderBinding | None = None, provider_guard=None, provider_first_binding_guard=None,
                   historical_application_revision: str | None = None,
                   inline_search: bool | None = None, provider_url_import: bool | None = None,
                   provider_refresh: bool | None = None, legacy_subscription_shorts: bool | None = None,
                   provider_batch: bool | None = None, api_status: bool | None = None, api_status_gate=None,
                   provider_url_documents: bool | None = None, mixed_documents: bool | None = None,
                   group_share_cards: bool | None = None):
    """Release the verified Worker and optionally configure its isolated Telegram schedule."""
    from page_jump_activation import MIGRATION, require_clear_for_release

    _require((provider_binding is None and provider_guard is None) or (provider_binding is not None and callable(provider_guard)),
             "An isolated provider release requires a verified dependency guard.")
    module, desired = _artifact(bundle_dir, manifest, telegram_config, aggregate_key, private_share_key, provider_binding)
    desired_selected_capable = _legacy_selected_artifact_capable(module, manifest)
    desired_temp_capable = _legacy_temp_artifact_capable(module, manifest)
    desired_dynamic_all_capable = _legacy_dynamic_all_artifact_capable(module, manifest)
    scope = _Isolation(worker_api, data_api, target)
    config = scope.worker_config()
    had_cron = scope.cron_enabled()
    scope.verify_resources()
    require_clear_for_release(scope, required=any(entry["name"] == MIGRATION for entry in manifest["migrations"]))
    previous = scope.active()
    old_version, old_selected_capable, old_temp_capable, old_dynamic_all_capable = scope.version(
        previous.version, with_legacy_selected=True, with_legacy_temp=True, with_legacy_dynamic_all=True)
    _require(expected_active is None or expected_active == {
        "deploymentId": previous.id, "versionId": previous.version, "revision": old_version.revision,
    }, "Isolated Worker deployment changed while verifying D1.")
    scope.verify_legacy_selected_floor(allow_rows=old_selected_capable and desired_selected_capable,
                                      require_schema=old_selected_capable or desired_selected_capable)
    scope.verify_legacy_temp_floor(allow_rows=old_temp_capable and desired_temp_capable,
                                   require_schema=old_temp_capable or desired_temp_capable)
    scope.verify_legacy_dynamic_all_floor(allow_rows=old_dynamic_all_capable and desired_dynamic_all_capable,
                                         require_schema=old_dynamic_all_capable or desired_dynamic_all_capable)
    scope.verify_page_jump_drain(old_version, desired)
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
    provider_url_enabled = _provider_url_import_target(old_version, provider_url_import, manifest,
        desired.telegram_config_sha256, desired.provider_binding, had_cron)
    documents_enabled, documents_capable = _provider_url_documents_target(old_version, provider_url_documents, manifest,
        desired.telegram_config_sha256, desired.provider_binding, had_cron)
    mixed_enabled, mixed_capable = _mixed_documents_target(old_version, mixed_documents, manifest, documents_enabled, documents_capable)
    group_capable = GROUP_SHARE_CARDS_MARKER in module
    group_enabled = _group_share_cards_target(old_version, group_share_cards, manifest, group_capable,
                                             desired.telegram_config_sha256, desired.telegram_private_share_key_sha256, had_cron)
    verify_group_schema = group_capable or old_version.telegram_group_share_cards_capable
    # Mixed opt-ins are children of provider opt-ins and all committed plans use the existing document ledger.
    documents_must_be_drained = ((documents_capable and not old_version.telegram_provider_url_documents_capable)
                                 or (mixed_capable and not old_version.telegram_mixed_documents_capable))
    refresh_enabled = _provider_refresh_target(old_version, provider_refresh, manifest,
        desired.telegram_config_sha256, desired.provider_binding, had_cron)
    legacy_shorts_enabled = _legacy_subscription_shorts_target(old_version, legacy_subscription_shorts, manifest)
    batch_enabled, batch_capable = _provider_batch_target(old_version, provider_batch, manifest,
        desired.telegram_config_sha256, desired.provider_binding, had_cron)
    api_status_enabled, api_status_binding, api_gate, api_status_capable, api_status_must_be_drained = _api_status_target(
        old_version, api_status, manifest, desired.telegram_config_sha256, had_cron, api_status_gate)
    # An unproven previous module can never be the rollback target of an admission-enabled release.
    batch_must_be_drained = batch_capable and not old_version.telegram_provider_batch_capable
    verify_legacy_shorts = old_version.legacy_subscription_shorts or legacy_shorts_enabled
    verify_provider_schema = None
    if old_version.telegram_provider_refresh or refresh_enabled:
        verify_provider_schema = scope.verify_provider_refresh
    elif old_version.telegram_provider_url_import or provider_url_enabled:
        verify_provider_schema = scope.verify_provider_url_import
    first_enable = enabled and not old_version.telegram_inline_search
    if enabled != old_version.telegram_inline_search:
        _require(had_cron and (old_version.telegram_aggregate_key_sha256, old_version.telegram_private_share_key_sha256,
                  old_version.provider_binding) == (desired.telegram_aggregate_key_sha256,
                  desired.telegram_private_share_key_sha256, desired.provider_binding),
                 "Change the isolated inline search flag with the existing Cron, same keys and provider binding.")
    desired = replace(desired, telegram_inline_search=enabled, telegram_provider_url_import=provider_url_enabled,
                      telegram_provider_refresh=refresh_enabled, legacy_subscription_shorts=legacy_shorts_enabled,
                      telegram_provider_batch=batch_enabled, telegram_provider_batch_capable=batch_capable,
                      telegram_api_status=api_status_enabled, api_status_binding=api_status_binding,
                      telegram_provider_url_documents=documents_enabled, telegram_provider_url_documents_capable=documents_capable,
                      telegram_mixed_documents=mixed_enabled, telegram_mixed_documents_capable=mixed_capable,
                      telegram_group_share_cards=group_enabled, telegram_group_share_cards_capable=group_capable,
                      tag=_telegram_feature_tag(_api_status_tag(desired.tag, api_status_binding, api_status_enabled),
                                                enabled, provider_url_enabled, refresh_enabled, legacy_shorts_enabled,
                                                batch_enabled, desired.digest if batch_capable else None,
                                                url_documents=documents_enabled,
                                                url_documents_module_sha256=desired.digest if documents_capable else None,
                                                mixed_documents=mixed_enabled if mixed_capable else None,
                                                group_share_cards=group_enabled if group_capable else None))
    if inline_bot is not None:
        scope.verify_inline_search(inline_bot, require_fresh=first_enable)
    if verify_provider_schema is not None:
        verify_provider_schema()
    if verify_legacy_shorts:
        scope.verify_legacy_subscription_shorts()
    if batch_capable:
        scope.verify_provider_batch(drained=batch_must_be_drained)
    if api_status_capable:
        scope.verify_api_status(drained=api_status_must_be_drained)
    if documents_capable:
        scope.verify_provider_url_documents(drained=documents_must_be_drained)
    if mixed_capable:
        scope.verify_mixed_documents()
    if verify_group_schema:
        scope.verify_group_share_cards(drained=not group_capable)
    _verify_first_provider_binding(old_version, desired.provider_binding, desired.revision, provider_first_binding_guard,
                                   historical_application_revision)
    _verify_health(old_version.revision)
    if provider_guard is not None:
        provider_guard()
    _verify_api_status_dependency(old_version, api_gate, desired.revision)
    if old_version.revision == desired.revision:
        _require(old_version.digest == desired.digest, "Active revision differs from the verified module digest.")
        if (old_version.telegram_config_sha256, old_version.telegram_aggregate_key_sha256,
                old_version.telegram_private_share_key_sha256, old_version.provider_binding,
                old_version.telegram_inline_search, old_version.telegram_provider_url_import,
                old_version.telegram_provider_refresh, old_version.legacy_subscription_shorts,
                old_version.telegram_provider_batch, old_version.telegram_provider_batch_capable,
                old_version.api_status_binding, old_version.telegram_api_status,
                old_version.telegram_provider_url_documents, old_version.telegram_provider_url_documents_capable,
                old_version.telegram_mixed_documents, old_version.telegram_mixed_documents_capable,
                old_version.telegram_group_share_cards, old_version.telegram_group_share_cards_capable) == (
                desired.telegram_config_sha256, desired.telegram_aggregate_key_sha256,
                desired.telegram_private_share_key_sha256, desired.provider_binding,
                desired.telegram_inline_search, desired.telegram_provider_url_import, desired.telegram_provider_refresh,
                desired.legacy_subscription_shorts, desired.telegram_provider_batch, desired.telegram_provider_batch_capable,
                desired.api_status_binding, desired.telegram_api_status,
                desired.telegram_provider_url_documents, desired.telegram_provider_url_documents_capable,
                desired.telegram_mixed_documents, desired.telegram_mixed_documents_capable,
                desired.telegram_group_share_cards, desired.telegram_group_share_cards_capable):
            scope.verify_legacy_selected_floor(allow_rows=old_selected_capable, require_schema=old_selected_capable)
            scope.verify_legacy_temp_floor(allow_rows=old_temp_capable, require_schema=old_temp_capable)
            scope.verify_legacy_dynamic_all_floor(allow_rows=old_dynamic_all_capable, require_schema=old_dynamic_all_capable)
            if telegram_config is None:
                _require(scope.active() == previous, "Active isolated Worker deployment changed during verification.")
                _guard_current(guard)
                changed = False
            else:
                changed = scope.ensure_cron(previous, config, guard)
            return {"revision": desired.revision, "deploymentId": previous.id, "versionId": previous.version,
                    "previousVersionId": previous.version, "changed": changed, "inlineSearchEnabled": enabled,
                    "providerUrlImportEnabled": provider_url_enabled, "providerRefreshEnabled": refresh_enabled,
                    "legacySubscriptionShortsEnabled": legacy_shorts_enabled, "providerBatchEnabled": batch_enabled,
                    "apiStatusEnabled": api_status_enabled, "providerUrlDocumentsEnabled": documents_enabled,
                    "mixedDocumentsEnabled": mixed_enabled, "groupShareCardsEnabled": group_enabled}

    candidate = scope.staged(desired)
    if candidate is None:
        _require(scope.active() == previous, "Active isolated Worker deployment changed before upload.")
        scope.verify_legacy_temp_floor(allow_rows=old_temp_capable and desired_temp_capable,
                                       require_schema=old_temp_capable or desired_temp_capable)
        scope.verify_legacy_dynamic_all_floor(allow_rows=old_dynamic_all_capable and desired_dynamic_all_capable,
                                             require_schema=old_dynamic_all_capable or desired_dynamic_all_capable)
        _guard_current(guard)
        candidate = scope.upload(module, desired, telegram_config, aggregate_key, private_share_key)

    _require(scope.worker_config() == config, "Isolated Worker configuration changed before activation.")
    _require(scope.cron_enabled() == had_cron, "Isolated Worker schedule changed before activation.")
    scope.verify_resources()
    if provider_guard is not None:
        provider_guard()
    if api_gate is not None:
        api_gate.verify()
    if inline_bot is not None:
        scope.verify_inline_search(inline_bot, require_fresh=first_enable)
    if verify_provider_schema is not None:
        verify_provider_schema()
    if verify_legacy_shorts:
        scope.verify_legacy_subscription_shorts()
    if batch_capable:
        scope.verify_provider_batch(drained=batch_must_be_drained)
    if api_status_capable:
        scope.verify_api_status(drained=api_status_must_be_drained)
    if documents_capable:
        scope.verify_provider_url_documents(drained=documents_must_be_drained)
    if mixed_capable:
        scope.verify_mixed_documents()
    if verify_group_schema:
        scope.verify_group_share_cards(drained=not group_capable)
    activated = scope.activate(previous, candidate, f"Isolated Worker release {desired.revision} {uuid4()}",
                               current_version=old_version, target_version=desired,
                               current_capable=old_selected_capable, target_capable=desired_selected_capable, guard=guard,
                               current_temp_capable=old_temp_capable, target_temp_capable=desired_temp_capable,
                               current_dynamic_all_capable=old_dynamic_all_capable, target_dynamic_all_capable=desired_dynamic_all_capable)
    try:
        _require(scope.worker_config() == config, "Isolated Worker configuration changed after activation.")
        _require(scope.cron_enabled() == had_cron, "Isolated Worker schedule changed during activation.")
        scope.verify_resources()
        _require(scope.version(activated.version) == desired, "Active Worker version differs from the verified artifact.")
        scope.verify_legacy_selected_floor(allow_rows=desired_selected_capable, require_schema=desired_selected_capable)
        scope.verify_legacy_temp_floor(allow_rows=desired_temp_capable, require_schema=desired_temp_capable)
        scope.verify_legacy_dynamic_all_floor(allow_rows=desired_dynamic_all_capable, require_schema=desired_dynamic_all_capable)
        _verify_health(desired.revision)
        if inline_bot is not None:
            scope.verify_inline_search(inline_bot)
        if verify_provider_schema is not None:
            verify_provider_schema()
        if verify_legacy_shorts:
            scope.verify_legacy_subscription_shorts()
        if batch_capable:
            scope.verify_provider_batch(drained=batch_must_be_drained)
        if api_status_capable:
            scope.verify_api_status(drained=api_status_must_be_drained)
        if documents_capable:
            scope.verify_provider_url_documents(drained=documents_must_be_drained)
        if mixed_capable:
            scope.verify_mixed_documents()
        if verify_group_schema:
            scope.verify_group_share_cards(drained=not group_capable)
        if provider_guard is not None:
            provider_guard()
        if api_gate is not None:
            api_gate.verify()
        _require(scope.active() == activated, "Active isolated Worker deployment changed during verification.")
    except CloudflareError:
        try:
            _require(scope.worker_config() == config, "Isolated Worker configuration changed before rollback.")
            _require(scope.cron_enabled() == had_cron, "Isolated Worker schedule changed before rollback.")
            scope.verify_resources()
            _require(scope.version(previous.version) == old_version, "Prior Worker version changed before rollback.")
            _require(scope.active() == activated, "Active isolated Worker deployment changed before rollback.")
            if batch_capable:
                scope.verify_provider_batch(drained=batch_must_be_drained)
            if api_status_capable:
                scope.verify_api_status(drained=api_status_must_be_drained)
            if documents_capable:
                scope.verify_provider_url_documents(drained=documents_must_be_drained)
            if mixed_capable:
                scope.verify_mixed_documents()
            if verify_group_schema:
                scope.verify_group_share_cards(drained=not old_version.telegram_group_share_cards_capable)
            restored = scope.activate(activated, previous.version, f"Isolated Worker rollback {uuid4()}",
                                      current_version=desired, target_version=old_version,
                                      current_capable=desired_selected_capable, target_capable=old_selected_capable, guard=guard,
                                      current_temp_capable=desired_temp_capable, target_temp_capable=old_temp_capable,
                                      current_dynamic_all_capable=desired_dynamic_all_capable, target_dynamic_all_capable=old_dynamic_all_capable)
            _verify_health(old_version.revision)
            scope.verify_legacy_selected_floor(allow_rows=old_selected_capable, require_schema=old_selected_capable)
            scope.verify_legacy_temp_floor(allow_rows=old_temp_capable, require_schema=old_temp_capable)
            scope.verify_legacy_dynamic_all_floor(allow_rows=old_dynamic_all_capable, require_schema=old_dynamic_all_capable)
            if (inline_bot is not None or verify_provider_schema is not None or verify_legacy_shorts or batch_capable
                    or api_status_capable or documents_capable or verify_group_schema):
                _require(scope.version(restored.version) == old_version, "Isolated Worker Telegram rollback state differs.")
            if old_version.legacy_subscription_shorts:
                scope.verify_legacy_subscription_shorts()
            _require(scope.active() == restored, "Isolated Worker rollback activation changed.")
        except CloudflareError:
            raise CloudflareError("Isolated Worker verification failed and a safe rollback could not be confirmed.") from None
        raise CloudflareError("Isolated Worker verification failed. The prior version was restored.") from None

    # Cron is script-level. A failed update must not restore code that cannot handle a possibly installed trigger.
    if telegram_config is not None:
        scope.ensure_cron(activated, config, guard)
    return {"revision": desired.revision, "deploymentId": activated.id, "versionId": activated.version,
            "previousVersionId": previous.version, "changed": True, "inlineSearchEnabled": enabled,
            "providerUrlImportEnabled": provider_url_enabled, "providerRefreshEnabled": refresh_enabled,
            "legacySubscriptionShortsEnabled": legacy_shorts_enabled, "providerBatchEnabled": batch_enabled,
            "apiStatusEnabled": api_status_enabled, "providerUrlDocumentsEnabled": documents_enabled,
            "mixedDocumentsEnabled": mixed_enabled, "groupShareCardsEnabled": group_enabled}

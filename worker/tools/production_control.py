"""Protected first-release lifecycle; production and registered rehearsal use the same code.

No token, SQL export, Bot credential, capability URL or user list is printed.
Mutations never retry transport failures. Inspect/reconcile the independent state first.
"""
from __future__ import annotations

import base64
import errno
from hashlib import sha256
from http.client import HTTPException
from ipaddress import ip_address
import json
import os
from pathlib import Path
import re
import socket
import ssl
import tempfile
from time import sleep
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import d1_migrations as migrations
import prepare_isolation_artifact as artifact
import prepare_control_artifact
from cloudflare_isolation import ISOLATION_RELEASE_USER_AGENT
from general_isolation_window import work_sql, terminal_card_sql
from production_target import Target, ContractError, approve, canonical, digest, matches, parsed, require, validate_target, SHA, REV, UUID
import scoped_r2

API_ROOT = "https://api.cloudflare.com/client/v4"
MAX_API = 8 * 1024 * 1024
CONTROL = "subs_bot_production_control"
INVOCATIONS = "subs_bot_production_invocations"
FEATURE_BINDINGS = {
    "inlineSearch": "TELEGRAM_INLINE_SEARCH", "providerUrlImport": "TELEGRAM_PROVIDER_URL_IMPORT",
    "providerUrlDocuments": "TELEGRAM_PROVIDER_URL_DOCUMENTS", "mixedDocuments": "TELEGRAM_MIXED_DOCUMENTS",
    "providerRefresh": "TELEGRAM_PROVIDER_REFRESH", "providerBatch": "TELEGRAM_PROVIDER_BATCH_REFRESH",
    "subscriptionShorts": "TELEGRAM_SUBSCRIPTION_SHORTS", "externalShortlinks": "TELEGRAM_EXTERNAL_SHORTLINKS",
    "groupShareCards": "TELEGRAM_GROUP_SHARE_CARDS", "apiStatus": "TELEGRAM_API_STATUS",
}


class OperationError(RuntimeError):
    def __init__(self, message, *, uncertain=False, status=None):
        super().__init__(message)
        self.uncertain, self.http_status = uncertain, status


class DeploymentReconciliationRequired(OperationError):
    """A deployment mutation was attempted; no write is safe to retry blindly."""
    def __init__(self, phase, version_id=None, deployment_id=None):
        require(phase in {"upload", "staged-readback", "traffic", "active-readback", "reconcile"})
        self.phase = phase
        self.version_sha256 = sha256(version_id.encode()).hexdigest() if matches(UUID, version_id) else None
        self.deployment_sha256 = sha256(deployment_id.encode()).hexdigest() if matches(UUID, deployment_id) else None
        super().__init__("Deployment requires independent reconciliation (phase=" + phase + ").", uncertain=True)

    def safe_details(self):
        return {"kind": "deployment-reconciliation-required", "phase": self.phase, "uncertain": True,
            "mutationAttempted": True, "versionSha256": self.version_sha256,
            "deploymentSha256": self.deployment_sha256}


class StalePredecessorError(ContractError):
    """A transition's read-only predecessor comparison failed before any SQL began."""
    def __init__(self):
        super().__init__("Predecessor state changed; no transition performed.")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _HealthReadbackError(OperationError):
    def __init__(self, category, *, status=None, codes=(), retryable=False, attempts=1):
        self.category, self.codes, self.retryable = category, codes, retryable
        super().__init__("HTTPS domain health was not confirmed (category=%s; HTTP=%s; Cloudflare=%s; attempts=%d); admission remains closed."
            % (category, status if status is not None else "none", ",".join(map(str, codes)) or "none", attempts), status=status)


def _health_http_error(status, raw, attempt):
    # Numeric edge codes are useful diagnostics; response text and URLs are never
    # exposed. A response containing credentials must not become an error message.
    codes = tuple(sorted({int(code) for code in re.findall(
        rb'(?:\berror\s+code\s*:\s*|"code"\s*:\s*)(1[0-9]{3})\b', raw[:4096], re.IGNORECASE)}))[:4]
    return _HealthReadbackError("http", status=status, codes=codes, attempts=attempt,
        retryable=status in {408, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524})


def _health_transport_error(error, attempt):
    reason = error.reason if isinstance(error, URLError) else error
    if isinstance(reason, (ssl.SSLError, ssl.CertificateError)):
        category, retryable = "tls", False
    elif isinstance(reason, socket.gaierror):
        category, retryable = "dns", reason.errno == socket.EAI_AGAIN
    elif isinstance(reason, TimeoutError):
        category, retryable = "timeout", True
    elif isinstance(reason, OSError) and reason.errno in {
            errno.ECONNRESET, errno.ECONNABORTED, errno.ECONNREFUSED, errno.ETIMEDOUT, errno.ENETUNREACH, errno.EHOSTUNREACH}:
        category, retryable = "connection", True
    else:
        category, retryable = ("protocol" if isinstance(reason, HTTPException) else "transport"), False
    return _HealthReadbackError(category, retryable=retryable, attempts=attempt)


def _read_domain_health(url, revision, attempt):
    request = Request(url, headers={"Accept": "application/json", "User-Agent": ISOLATION_RELEASE_USER_AGENT,
        "Cache-Control": "no-cache", "Accept-Encoding": "identity"})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=10) as response:
            status = response.status
            if type(status) is not int or not 100 <= status <= 599:
                raise _HealthReadbackError("protocol", attempts=attempt)
            if status != 200:
                raise _health_http_error(status, response.read(4097), attempt)
            raw = response.read(1025)
            cache = {value.strip().lower() for value in response.headers.get("Cache-Control", "").split(",")}
            if len(raw) > 1024 or response.headers.get_content_type() != "application/json" \
                    or not {"private", "no-store"} <= cache or response.headers.get("Referrer-Policy") != "no-referrer" \
                    or response.headers.get("X-Content-Type-Options") != "nosniff":
                raise _HealthReadbackError("response", status=200, attempts=attempt)
    except HTTPError as error:
        try:
            failure = _health_http_error(error.code, error.read(4097), attempt)
        except (OSError, HTTPException):
            failure = _health_http_error(error.code, b"", attempt)
        finally:
            error.close()
        raise failure from None
    except (OSError, HTTPException) as error:
        raise _health_transport_error(error, attempt) from None
    try:
        health = parsed(raw)
    except ContractError:
        raise _HealthReadbackError("body", status=200, attempts=attempt) from None
    if health.get("ok") is not True or health != {"ok": True, "service": "subs-bot", "revision": revision}:
        raise _HealthReadbackError("body", status=200, attempts=attempt)


class API:
    """Fixed origin, bounded responses and per-project write routes.

    Credentials still need platform-side least privilege; path checks are a second
    boundary, not a substitute for scoped Cloudflare tokens.
    """
    def __init__(self, target, token, *, create=False):
        self.target = target.data if isinstance(target, Target) else target
        require(matches(r"[A-Za-z0-9_.-]{20,4096}", token), "The scoped Cloudflare credential is unavailable.")
        self.token, self.create = token, create
        self.root = "/accounts/" + self.target["accountId"]
        self.script = self.root + "/workers/scripts/" + self.target["workerName"]
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def __call__(self, method, path, payload=None, *, envelope=False, absent=False):
        require(isinstance(path, str) and len(path) <= 16384 and matches(r"/[A-Za-z0-9/_.%?=&,~-]+", path)
                and "%" not in path.partition("?")[0]
                and not any(p in (".", "..") for p in path.partition("?")[0].split("/")))
        require(path.startswith(self.root + "/") or (method == "GET" and path == "/user/tokens/verify") or path in (self.root, "/zones/" + self.target["zoneId"])
                or path.startswith("/zones/" + self.target["zoneId"] + "/"), "API request is outside the approved account or zone.")
        if method != "GET":
            t = self.target
            query = self.root + "/d1/database/" + str(t["d1Id"]) + "/query"
            versions = self.root + "/workers/workers/" + str(t["workerId"]) + "/versions"
            writes = {( "POST", query), ("POST", versions + "?deploy=false"),
                ("POST", self.script + "/deployments"), ("PUT", self.script + "/schedules"),
                ("PUT", self.root + "/workers/domains")}
            if self.create:
                writes |= {("POST", self.root + "/d1/database"), ("POST", self.root + "/r2/buckets"),
                    ("POST", self.root + "/workers/workers")}
            require((method, path) in writes, "Mutation route is outside this target's lifecycle contract.")
            if path == self.root + "/d1/database":
                require(payload == {"name": t["d1Name"], "read_replication": {"mode": "disabled"}})
            if path == self.root + "/r2/buckets":
                require(payload in [{"name": t[k], "storageClass": "Standard"} for k in ("bucketName", "backupBucketName")])
            if path == self.root + "/workers/workers":
                require(isinstance(payload, dict) and payload.get("name") == t["workerName"])
            if method == "PUT" and path.endswith("/domains"):
                require(payload == {"hostname": t["hostname"], "service": t["workerName"],
                    "environment": "production", "zone_id": t["zoneId"]})
            if method == "PUT" and path.endswith("/schedules"):
                require(payload in ([], [{"cron": "* * * * *"}]))
        else:
            require(payload is None)
        data = None if payload is None else canonical(payload)
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json", "Cache-Control": "no-cache"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        request = Request(API_ROOT + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=45) as response:
                raw = response.read(MAX_API + 1)
        except HTTPError as error:
            status = error.code
            error.close()
            if absent and status == 404 and method == "GET":
                return None
            raise OperationError("Cloudflare rejected the protected request (HTTP %d)." % status,
                uncertain=method != "GET" and (status == 408 or status >= 500), status=status) from None
        except (OSError, ValueError, HTTPException):
            raise OperationError("Cloudflare response is unavailable; reconcile before another mutation.", uncertain=method != "GET") from None
        try:
            require(len(raw) <= MAX_API, "Cloudflare response exceeded the supported capacity.")
            value = parsed(raw) if len(raw) <= 65536 else json.loads(raw)
            require(isinstance(value, dict) and value.get("success") is True and "result" in value,
                    "Cloudflare did not confirm the protected operation.")
        except (ValueError, RecursionError):
            raise OperationError("Cloudflare response could not be verified.", uncertain=method != "GET") from None
        return value if envelope else value["result"]

    request = __call__
    json = __call__


def rows(api, path, sql):
    result = api("POST", path + "/query", {"sql": sql})
    require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
            and isinstance(result[0].get("results"), list), "D1 query was not fully confirmed.")
    return result[0]["results"]


def one(api, path, sql):
    result = rows(api, path, sql)
    require(len(result) == 1, "A single complete D1 state was required.")
    return result[0]


def _mutate_sql(api, path, statements):
    # Cloudflare executes a D1 SQL batch transactionally. Assertions are part of
    # that same batch; no check-then-write gap inside the database.
    result = api("POST", path + "/query", {"sql": ";\n".join(statements) + ";"})
    require(isinstance(result, list) and len(result) == len(statements)
            and all(r.get("success") is True for r in result), "D1 mutation was not fully confirmed.")


def privacy(api, root, name, created):
    metadata_token = scoped_r2.metadata_token()
    if metadata_token:
        metadata_api = API(api.target, metadata_token)
        require(metadata_api.root == root, "The bucket metadata account differs from the approved target.")
        api = metadata_api
    path = root + "/r2/buckets/" + name
    identity = api("GET", path)
    require(isinstance(identity, dict) and identity.get("name") == name
            and identity.get("creation_date") == created and identity.get("jurisdiction") == "default",
            "R2 immutable resource registration differs.")
    managed = api("GET", path + "/domains/managed")
    custom = api("GET", path + "/domains/custom")
    rules = api("GET", path + "/lifecycle")
    domains = custom.get("domains") if isinstance(custom, dict) else custom
    require(isinstance(managed, dict) and managed.get("enabled") is False and domains == [], "R2 target must be private without custom domains.")
    require(isinstance(rules, dict) and isinstance(rules.get("rules"), list)
            and all(not rule.get("enabled") or not rule.get("deleteObjectsTransition") for rule in rules["rules"]),
            "An enabled R2 object deletion rule conflicts with preservation.")
    return {"name": name, "createdAt": created, "private": True, "deletionRules": 0}


def general_config(target, revision, secrets):
    t, flags = target.data, target.data["features"]
    require(set(secrets) == {"botToken", "webhookSecret", "aggregateKey", "privateShareKey", "shortlinkToken"})
    require(matches(r"[1-9][0-9]{0,15}:[A-Za-z0-9_-]{20,128}", secrets["botToken"])
            and secrets["botToken"].split(":")[0] == t["botId"], "Bot credential prefix differs from the approved Bot identity.")
    for source, key in (("webhookSecret", "webhook"), ("aggregateKey", "aggregate"), ("privateShareKey", "privateShare"), ("shortlinkToken", "shortlink")):
        value = secrets[source]
        if key == "shortlink" and not flags["externalShortlinks"]:
            require(value is None)
            continue
        pattern = {"webhook": r"[A-Za-z0-9_-]{32,256}", "aggregate": r"[A-Za-z0-9_-]{43}",
                   "privateShare": r"[A-Za-z0-9_-]{43}", "shortlink": r"sl_[A-Za-z0-9_-]{32,128}"}[key]
        require(matches(pattern, value)
                and sha256(value.encode()).hexdigest() == t["keyDigests"][key], "A secret is missing or differs from its approved digest.")
        if key in ("aggregate", "privateShare"):
            decoded = base64.urlsafe_b64decode(value + "=")
            require(len(decoded) == 32 and base64.urlsafe_b64encode(decoded).decode().rstrip("=") == value)
    result = {"botId": t["botId"], "botUsername": t["botUsername"], "botToken": secrets["botToken"],
        "webhookSecret": secrets["webhookSecret"], "generation": t["generation"], "cutoverAt": 1,
        "activationSha256": target.digest,
        "outbox": "shared-private-management-formats-temp-node-document-provider-claims-share-aggregate-selected-short",
        "authManagement": True, "subscriptionBrowsing": True, "pageJump": True,
        "subscriptionShorts": "issue" if flags["subscriptionShorts"] else "drain"}
    for enabled, key in ((flags["inlineSearch"], "inlineSearch"), (flags["githubSearch"], "githubSearch"),
                         (flags["providerBatch"], "providerBatch")):
        if enabled:
            result[key] = True
    if flags["groupShareCards"]:
        result["groupShare"] = t["groups"][0]
    encoded = canonical(result).decode()
    require(len(encoded) <= 4096, "General Bot configuration exceeds the runtime contract capacity.")
    return encoded


class Telegram:
    """No redirects; token-bearing URL never leaves this bounded client."""
    def __init__(self, target, secrets, *, rehearsal_previous_url=None):
        self.target, self.secrets = target, secrets
        require(rehearsal_previous_url is None or (target.environment == "rehearsal"
                and rehearsal_previous_url == "https://subs-bot-cf-dev-01.lilyya.workers.dev/telegram/webhook"),
                "Only an explicitly registered original rehearsal webhook may be selected.")
        self.rehearsal_previous_url = rehearsal_previous_url
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, method, payload=None):
        require(method in ("getMe", "getWebhookInfo", "setWebhook", "getChat", "getChatMember"))
        if method in ("getChat", "getChatMember"):
            require(isinstance(payload, dict) and str(payload.get("chat_id")) in {g["chatId"] for g in self.target.data["groups"]})
            if method == "getChatMember":
                require(str(payload.get("user_id")) == self.target.data["botId"])
        request = Request("https://api.telegram.org/bot" + self.secrets["botToken"] + "/" + method,
            data=canonical(payload or {}), headers={"Content-Type": "application/json"}, method="POST")
        try:
            with self.opener.open(request, timeout=30) as response:
                raw = response.read(65537)
            value = parsed(raw)
            require(value.get("ok") is True and "result" in value)
            return value["result"]
        except (OSError, HTTPException, ValueError):
            raise OperationError("Telegram operation is unconfirmed; perform identity and webhook readback before retry.",
                                 uncertain=method == "setWebhook") from None

    def identity(self):
        me = self.call("getMe")
        require(isinstance(me, dict) and me.get("is_bot") is True and str(me.get("id")) == self.target.data["botId"]
                and me.get("username") == self.target.data["botUsername"], "Live Bot identity differs from the approved target.")
        return {"botId": str(me["id"]), "botUsername": me["username"]}

    def group_permissions(self):
        self.identity()
        for group in self.target.data["groups"]:
            chat = self.call("getChat", {"chat_id": group["chatId"]})
            member = self.call("getChatMember", {"chat_id": group["chatId"], "user_id": self.target.data["botId"]})
            require(str(chat.get("id")) == group["chatId"] and chat.get("type") == group["chatType"]
                    and member.get("user", {}).get("is_bot") is True and str(member["user"].get("id")) == self.target.data["botId"]
                    and (member.get("status") in ("creator", "administrator") or (member.get("status") == "member"
                        and chat.get("permissions", {}).get("can_send_messages") is True)),
                    "The exact configured group or Bot send permission was not confirmed.")
        return {"verifiedGroups": len(self.target.data["groups"])}

    def webhook_info(self, info):
        """Separate stable settings from delivery observations; never expose error text."""
        fields = {"url", "has_custom_certificate", "pending_update_count", "ip_address", "last_error_date",
                  "last_error_message", "last_synchronization_error_date", "max_connections", "allowed_updates"}
        require(isinstance(info, dict) and set(info) <= fields and isinstance(info.get("url"), str)
                and info.get("has_custom_certificate") is False, "Webhook settings contain an unsupported certificate or field.")
        desired_url = "https://" + self.target.data["hostname"] + "/telegram/webhook"
        allowed = {"", desired_url}
        if self.rehearsal_previous_url is not None:
            allowed.add(self.rehearsal_previous_url)
        require(info["url"] in allowed, "Webhook URL is outside the explicitly approved predecessor scope; no mutation performed.")
        connections, updates = info.get("max_connections"), info.get("allowed_updates", [])
        require((connections is None and info["url"] == "") or type(connections) is int and 1 <= connections <= 100)
        require(isinstance(updates, list) and all(isinstance(value, str) for value in updates)
                and len(updates) == len(set(updates))
                and set(updates) <= {"message", "callback_query", "inline_query"}, "Webhook update categories are unsupported.")
        count = info.get("pending_update_count")
        require(type(count) is int and 0 <= count <= 9007199254740991, "Webhook pending-update observation is malformed.")
        for field in ("last_error_date", "last_synchronization_error_date"):
            require(field not in info or type(info[field]) is int and 0 <= info[field] <= 9007199254740991)
        require("last_error_message" not in info or isinstance(info["last_error_message"], str)
                and len(info["last_error_message"].encode("utf-8")) <= 4096)
        reported_ip = info.get("ip_address")
        ip_proof = None
        if "ip_address" in info:
            require(info["url"] != "" and isinstance(reported_ip, str), "An empty webhook cannot carry an IP override.")
            try:
                address = ip_address(reported_ip)
                require(address.is_global and not address.is_multicast and not address.is_reserved,
                        "Webhook IP is outside the public target scope.")
            except ValueError:
                raise ContractError("Webhook reported IP is malformed or outside the public target scope.") from None
            # Telegram exposes the currently used address, not whether a fixed
            # override was configured. Observe it without inventing that proof
            # or making DNS rotation invalidate a stable settings approval.
            ip_proof = digest(str(address))
        settings = {"url": info["url"], "hasCustomCertificate": False,
                    "maxConnections": connections, "allowedUpdates": sorted(updates)}
        return {"settings": settings, "settingsSha256": digest(settings), "observation": {
            "infoSha256": digest(info), "pendingUpdateCount": count,
            "lastErrorDate": info.get("last_error_date"), "hasLastError": "last_error_message" in info,
            "lastSynchronizationErrorDate": info.get("last_synchronization_error_date"), "reportedIpSha256": ip_proof}}

    def plan_webhook(self):
        identity = self.identity()
        return {"botIdentity": identity, **self.webhook_info(self.call("getWebhookInfo"))}

    def configure(self, expected_before, *, before_write=lambda: None):
        before = self.plan_webhook()
        require(matches(SHA, expected_before) and before["settingsSha256"] == expected_before,
                "Webhook settings predecessor changed; no mutation performed.")
        t = self.target.data
        desired = {"url": "https://" + t["hostname"] + "/telegram/webhook", "secret_token": self.secrets["webhookSecret"],
            "drop_pending_updates": False, "allowed_updates": t["webhook"]["allowedUpdates"],
            "max_connections": t["webhook"]["maxConnections"]}
        before_write()
        try:
            require(self.call("setWebhook", desired) is True)
            after = self.plan_webhook()
            require(after["settings"] == {"url": desired["url"], "hasCustomCertificate": False,
                "maxConnections": desired["max_connections"], "allowedUpdates": sorted(desired["allowed_updates"])})
        except Exception:
            raise OperationError("Webhook mutation is unconfirmed; keep admission closed and use read-only planning before any new approval.",
                                 uncertain=True) from None
        return {"webhookSha256": after["settingsSha256"], "pendingUpdateCount": after["observation"]["pendingUpdateCount"],
                "webhookObservation": after["observation"], "dropPendingUpdates": False}


class Controller:
    def __init__(self, target, data_api, worker_api, bundle, manifest, *, guard=lambda: None, telegram=None, secrets=None, dependency_api=None, control_revision=None, activation_baseline_checker=None, deployment_checkpoint=None):
        self.target, self.data, self.worker = target, data_api, worker_api
        self.bundle, self.manifest, self.guard = Path(bundle), manifest, guard
        self.telegram, self.secrets = telegram, secrets
        self.dependency_api = dependency_api
        self.activation_baseline_checker = activation_baseline_checker
        self.deployment_checkpoint = deployment_checkpoint
        self.root = "/accounts/" + target.data["accountId"]
        self.database = self.root + "/d1/database/" + target.data["d1Id"]
        self.script = self.root + "/workers/scripts/" + target.data["workerName"]
        self.worker_path = self.root + "/workers/workers/" + target.data["workerId"]
        self.revision = manifest["revision"]
        self.control_revision = self.revision if control_revision is None else control_revision
        require(matches(REV, self.revision) and matches(SHA, manifest.get("bundleSha256")))

    def approval(self, envelope, action, state_sha):
        return approve(self.target, envelope, action, self.revision, state_sha, control_revision=self.control_revision)

    def resources(self):
        t = self.target.data
        if self.target.environment == "production":
            account = self.data("GET", self.root)
            zone = self.worker("GET", "/zones/" + t["zoneId"])
            require(account.get("id") == t["accountId"] and zone.get("id") == t["zoneId"]
                    and zone.get("account", {}).get("id") == t["accountId"] and zone.get("name") == "lilyya.top")
        db = self.data("GET", self.database)
        require((db.get("uuid"), db.get("name"), db.get("created_at")) == (t["d1Id"], t["d1Name"], t["d1CreatedAt"]),
                "D1 immutable identity differs; no mutation is allowed.")
        buckets = [privacy(self.data, self.root, t[name], t[created]) for name, created in
            (("bucketName", "bucketCreatedAt"), ("backupBucketName", "backupBucketCreatedAt"))]
        live = self.worker("GET", self.worker_path)
        require((live.get("id"), live.get("name"), live.get("created_on")) ==
                (t["workerId"], t["workerName"], t["workerCreatedOn"]), "Worker immutable identity differs.")
        require(set(live.get("tags", [])) == {"subs-bot", "lifecycle-" + t["environment"]}, "Worker ownership tags differ.")
        require(live.get("logpush") is False and live.get("tail_consumers") == []
                and live.get("observability", {}).get("enabled") is False, "Unexpected logging or consumers are present.")
        references = live.get("references")
        require(isinstance(references, dict) and all(references.get(k) == [] for k in
                ("queues", "durable_objects", "dispatch_namespace_outbounds", "workers")),
                "Unexpected queue, durable object or Worker consumers are present.")
        if self.target.environment == "production":
            require(live.get("subdomain", {}).get("enabled") is False and live.get("subdomain", {}).get("previews_enabled") is False,
                    "Production workers.dev and preview access must be disabled.")
        return {"targetSha256": self.target.digest, "buckets": buckets}

    def migration_state(self):
        chain = migrations._load_migrations(self.bundle, self.manifest)
        kind, history = migrations._read_state(self.data, self.database, chain)
        return chain, kind, history

    def _control(self):
        result = rows(self.data, self.database, "SELECT * FROM " + CONTROL)
        require(len(result) == 1, "Production control is not initialized.")
        row = result[0]
        t = self.target.data
        require(row["singleton"] == 1 and row["target_sha256"] == self.target.digest and row["bot_id"] == t["botId"]
                and row["generation"] == t["generation"] and matches(REV, row["release_revision"])
                and type(row["epoch"]) is int and row["epoch"] > 0, "Durable control identity differs.")
        return row

    def work(self):
        sql, fields = work_sql(self.target.data["botId"])
        work = one(self.data, self.database, sql)
        require(set(work) == set(fields) and all(type(v) is int and v >= 0 for v in work.values()))
        calls = one(self.data, self.database, "SELECT count(*) AS invocations FROM " + INVOCATIONS + " WHERE state='running'")
        work.update(calls)
        work.update(one(self.data, self.database, "SELECT count(*) AS processingUpdates FROM subs_bot_production_updates WHERE state='processing'"))
        return work

    def terminal(self):
        bot = migrations._literal(self.target.data["botId"])
        cards, _ = terminal_card_sql(self.target.data["botId"])
        card = one(self.data, self.database, cards)
        terminal = one(self.data, self.database, f"""SELECT
          (SELECT count(*) FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND state='sent') AS sent,
          (SELECT count(*) FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND state='failed') AS failed,
          (SELECT count(*) FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND state='uncertain') AS uncertain,
          (SELECT count(*) FROM {INVOCATIONS} WHERE state='uncertain' OR (state='running' AND lease_until<=unixepoch())) AS unknownInvocations,
          (SELECT count(*) FROM subs_bot_production_updates WHERE state='uncertain') AS unknownUpdates,
          (SELECT count(*) FROM subs_bot_production_updates WHERE state='retryable') AS heldUpdates""")
        return {**card, **terminal}

    def active(self, *, allow_empty=False):
        result = self.worker("GET", self.script + "/deployments", absent=allow_empty)
        deployments = result.get("deployments") if isinstance(result, dict) else None
        if allow_empty and (result is None or deployments == []):
            return {"revision": None, "moduleSha256": None, "versionId": None, "deploymentId": None, "bindings": {}, "compatibilityDate": None}
        require(isinstance(deployments, list) and deployments, "No active deployment was confirmed.")
        current = deployments[0]
        require(isinstance(current, dict), "Active deployment metadata is not an exact object.")
        versions = current.get("versions")
        require(matches(UUID, current.get("id")) and current.get("strategy") == "percentage" and isinstance(versions, list) and len(versions) == 1
                and isinstance(versions[0], dict) and versions[0].get("percentage") == 100 and matches(UUID, versions[0].get("version_id")))
        return self.version(versions[0]["version_id"], deployment_id=current["id"])

    def version(self, version_id, *, deployment_id=None):
        require(matches(UUID, version_id))
        version = self.worker("GET", self.worker_path + "/versions/" + version_id + "?include=modules")
        modules = version.get("modules")
        require(version.get("id") == version_id and version.get("main_module") == "index.js"
                and not any(version.get(k) for k in ("compatibility_flags", "limits", "placement", "assets", "containers", "migrations"))
                and version.get("usage_model") in (None, "standard")
                and isinstance(modules, list) and len(modules) == 1 and modules[0].get("name") == "index.js"
                and modules[0].get("content_type") == "application/javascript+module")
        try:
            body = base64.b64decode(modules[0]["content_base64"], validate=True)
        except (ValueError, KeyError, TypeError):
            raise ContractError("Active module bytes could not be verified.") from None
        require(0 < len(body) <= 1152 * 1024)
        binding_rows = version.get("bindings")
        require(isinstance(binding_rows, list) and len(binding_rows) <= 50)
        bindings = {r["name"]: r for r in binding_rows}
        require(len(bindings) == len(binding_rows))
        revision = bindings.get("BUILD_REVISION", {}).get("text")
        require(matches(REV, revision))
        return {"revision": revision, "moduleSha256": sha256(body).hexdigest(), "versionId": version["id"],
                "deploymentId": deployment_id, "bindings": bindings, "compatibilityDate": version["compatibility_date"]}

    def verify_dependency(self, *, allow_unbound=False):
        config = self.target.data["provider"]
        if config is None:
            return None
        from production_provider import verify_provider_dependency
        require(self.dependency_api is not None, "An explicit read-only ProviderFetch inspection credential is required.")
        return verify_provider_dependency(self.dependency_api, config, allow_unbound_caller=allow_unbound)

    def expected_bindings(self, *, include_secrets=False, allow_unbound_provider=False, verify_dependency=False):
        t, flags = self.target.data, self.target.data["features"]
        result = [{"type": "d1", "name": "DB", "database_id": t["d1Id"]},
            {"type": "r2_bucket", "name": "NODES", "bucket_name": t["bucketName"]}]
        text = {"BUILD_REVISION": self.revision, "PUBLIC_ORIGIN": "https://" + t["hostname"],
            "TELEGRAM_PRODUCTION_CONTROL_SHA256": self.target.digest,
            "SUBS_BOT_CONFIGURATION_SHA256": self.target.configuration_digest,
            "TELEGRAM_AGGREGATE_KEY_SHA256": t["keyDigests"]["aggregate"],
            "TELEGRAM_PRIVATE_SHARE_CREATION_KEY_SHA256": t["keyDigests"]["privateShare"]}
        require(self.secrets is not None, "Safe secret injection is required for binding verification.")
        general = general_config(self.target, self.revision, self.secrets)
        text["TELEGRAM_CONFIG_SHA256"] = sha256(general.encode()).hexdigest()
        for feature, binding in FEATURE_BINDINGS.items():
            text[binding] = "1" if flags[feature] else "0"
        secrets = {"TELEGRAM_GENERAL_CONFIG": general, "TELEGRAM_AGGREGATE_KEY": self.secrets["aggregateKey"],
                   "TELEGRAM_PRIVATE_SHARE_CREATION_KEY": self.secrets["privateShareKey"]}
        if flags["externalShortlinks"]:
            result.append({"type": "service", "name": "SHORTLINK", "service": "shortlink-new", "entrypoint": "ShortlinkService"})
            secrets["SHORTLINK_BUSINESS_TOKEN"] = self.secrets["shortlinkToken"]
        if t["provider"] is not None:
            # Incident inspection/pause validates the application's exact approved
            # binding even while its dependency is busy or unavailable. Enabling
            # deployment and final activation separately require live full proof.
            config = t["provider"]
            dependency = self.verify_dependency(allow_unbound=allow_unbound_provider) if verify_dependency else {
                "service": config["service"], "revision": config["build"]["revision"],
                "imageSha256": config["build"]["ociManifestSha256"]}
            result.append({"type": "service", "name": "PROVIDER_FETCH", "service": dependency["service"], "entrypoint": "ProviderFetch"})
            text.update({"PROVIDER_REVISION": dependency["revision"], "PROVIDER_IMAGE_SHA256": dependency["imageSha256"]})
        result.extend({"type": "plain_text", "name": key, "text": value} for key, value in text.items())
        result.extend({"type": "secret_text", "name": key, **({"text": value} if include_secrets else {})} for key, value in secrets.items())
        return result

    def verify_bindings(self, active, *, allow_unbound_provider=False, verify_dependency=False):
        expected = {r["name"]: r for r in self.expected_bindings(allow_unbound_provider=allow_unbound_provider,
            verify_dependency=verify_dependency)}
        actual = active["bindings"]
        require(set(expected) == set(actual), "Active binding inventory differs from the exact configuration.")
        for name, wanted in expected.items():
            observed = actual[name]
            if wanted["type"] == "secret_text":
                require(observed.get("type") == "secret_text" and "text" not in observed)
            elif wanted["type"] == "d1":
                identities = [observed[k] for k in ("database_id", "id") if observed.get(k) is not None]
                require(observed.get("name") == wanted["name"] and observed.get("type") == "d1"
                        and identities and all(identity == wanted["database_id"] for identity in identities), "D1 binding identity differs.")
            else:
                require(all(observed.get(k) == v for k, v in wanted.items()), "Active binding differs from the approved configuration.")
                if wanted["type"] == "service":
                    require(observed.get("environment") in (None, "production"), "Service binding points to an unexpected environment.")
                if wanted["type"] == "r2_bucket":
                    require(observed.get("jurisdiction") in (None, "default"), "R2 binding points to an unexpected jurisdiction.")
        require(active["revision"] == self.revision and active["moduleSha256"] == self.manifest["bundleSha256"]
                and active["compatibilityDate"] == self.manifest["compatibilityDate"], "Active artifact differs from the verified CI artifact.")

    def inspect(self, *, verify_release=True):
        self.resources()
        chain, kind, history = self.migration_state()
        require(kind == "managed" and len(history) == len(chain), "Exact migration chain is not fully applied.")
        control = self._control()
        active = self.active(allow_empty=not verify_release)
        if verify_release:
            self.verify_bindings(active)
            require(control["release_revision"] == active["revision"])
            schedules = self.worker("GET", self.script + "/schedules")
            require(isinstance(schedules, dict) and isinstance(schedules.get("schedules"), list)
                    and len(schedules["schedules"]) == 1 and schedules["schedules"][0].get("cron") == "* * * * *",
                    "The recovery Cron configuration differs from the reviewed release.")
        state = {"targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest, "release": {k: v for k, v in active.items() if k != "bindings"},
            "control": control, "work": self.work(), "terminal": self.terminal(), "migrationCount": len(history)}
        state["stateSha256"] = digest(state)
        return state

    def initialize(self):
        self.resources()
        if self.telegram is not None:
            self.telegram.identity()
            self.telegram.group_permissions()
        chain, kind, history = self.migration_state()
        # Empty or partially applied *schema only* can resume. Every business table
        # must remain empty before the one atomic whitelist initialization.
        tables = rows(self.data, self.database, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'_cf_KV' ORDER BY name")
        initialized = any(r["name"] == CONTROL for r in tables) and rows(self.data, self.database, "SELECT 1 FROM " + CONTROL)
        if initialized:
            self.verify_initial_whitelist()
            return {"initialized": True, "repeated": True, "targetSha256": self.target.digest}
        for row in tables:
            name = row["name"]
            require(matches(r"[a-z][a-z0-9_]*", name))
            if name not in (migrations.LEDGER, "d1_migrations"):
                require(one(self.data, self.database, 'SELECT count(*) AS n FROM "' + name + '"')["n"] == 0,
                        "New production initialization found non-whitelisted data.")
        require(kind in ("fresh", "managed"), "Unknown or adopted schema cannot be initialized.")
        while len(history) < len(chain):
            self.resources()
            self.guard()
            history = migrations._apply_one(self.data, self.database, chain, kind, history, self.guard)
            kind = "managed"
        t, literal = self.target.data, migrations._literal
        bot, rev, pin = literal(t["botId"]), literal(self.revision), literal(self.target.digest)
        empty_guards = []
        for migration in chain:
            for obj in migration.objects:
                if obj.type == "table":
                    empty_guards.append('NOT EXISTS(SELECT 1 FROM "' + obj.name + '")')
        empty_guards.extend(migrations._schema_conditions(migrations._objects(chain, len(chain), managed=True)))
        empty_guards.extend(migrations._history_conditions(history))
        statements = migrations._bounded_statements(empty_guards, migrations._assert_sql, "Initialization guards exceed the D1 statement capacity.")
        statements.append(f"INSERT INTO telegram_general_policy VALUES({bot},{t['generation']},{rev},{pin},1,1)")
        for role, key in (("admin", "admins"), ("member", "members")):
            statements += [f"INSERT INTO telegram_general_actors VALUES({bot},{t['generation']},{literal(i)},1,1,'{role}')" for i in t[key]]
        for group in t["groups"]:
            statements.append(f"INSERT INTO telegram_general_groups VALUES({bot},{t['generation']},{literal(group['chatId'])},{literal(group['chatType'])})")
        statements.append(f"INSERT INTO {CONTROL} VALUES(1,{pin},{bot},{rev},{t['generation']},1,'closed','frozen')")
        self.guard()
        _mutate_sql(self.data, self.database, statements)
        self.verify_initial_whitelist()
        return {"initialized": True, "repeated": False, "targetSha256": self.target.digest, "migrationCount": len(history)}

    def verify_initial_whitelist(self):
        t = self.target.data
        control = self._control()
        require(control["admission"] == "closed" and control["workers"] == "frozen" and control["release_revision"] == self.revision)
        policy = rows(self.data, self.database, "SELECT * FROM telegram_general_policy")
        require(policy == [{"bot_id": t["botId"], "generation": t["generation"], "release_revision": self.revision,
            "activation_sha256": self.target.digest, "cutover_at": 1, "active": 1}])
        actors = rows(self.data, self.database, "SELECT actor_id,role,revision,effective_at,bot_id,generation FROM telegram_general_actors ORDER BY actor_id")
        expected = sorted([{"actor_id": i, "role": role, "revision": 1, "effective_at": 1, "bot_id": t["botId"], "generation": t["generation"]}
            for role, key in (("admin", "admins"), ("member", "members")) for i in t[key]], key=lambda r: r["actor_id"])
        require(actors == expected)
        groups = rows(self.data, self.database, "SELECT * FROM telegram_general_groups ORDER BY chat_id")
        require(groups == [{"bot_id": t["botId"], "generation": t["generation"], "chat_id": g["chatId"], "chat_type": g["chatType"]} for g in t["groups"]])
        for row in rows(self.data, self.database, "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'_cf_KV'"):
            name = row["name"]
            if name not in {CONTROL, "telegram_general_policy", "telegram_general_actors", "telegram_general_groups", migrations.LEDGER, "d1_migrations"}:
                require(matches(r"[a-z][a-z0-9_]*", name) and one(self.data, self.database, 'SELECT count(*) AS n FROM "' + name + '"')["n"] == 0,
                        "Initialization contains data outside the approved whitelist.")
        # No timezone row means UTC, avoiding a synthetic Telegram receipt.
        return True

    def plan_pause(self):
        before = self.inspect()
        # Accepted work may finish, fail or become uncertain while a pause is
        # approved. The complete observation remains visible; approval binds the
        # immutable target/configuration/release and the entire control CAS row.
        before["approvalState"] = {"planAction": "pause", **{key: before[key] for key in
            ("targetSha256", "configurationSha256", "release", "control", "migrationCount")}}
        before["stateSha256"] = digest(before["approvalState"])
        return before

    def plan_webhook(self):
        before = self.inspect()
        require(before["control"]["admission"] == "closed", "Webhook planning requires closed admission.")
        require(self.telegram is not None)
        webhook = self.telegram.plan_webhook()
        before["webhook"] = webhook
        before["approvalState"] = {"planAction": "webhook", **{key: before[key] for key in
            ("targetSha256", "configurationSha256", "release", "control", "migrationCount")},
            "webhookSettingsSha256": webhook["settingsSha256"]}
        before["stateSha256"] = digest(before["approvalState"])
        return before

    def configure_webhook(self, envelope, predecessor, webhook_sha256):
        before = self.plan_webhook()
        require(before["stateSha256"] == predecessor, "Webhook plan changed; no mutation performed.")
        self.approval(envelope, "webhook", predecessor)
        require(matches(SHA, webhook_sha256) and before["webhook"]["settingsSha256"] == webhook_sha256,
                "The exact planned webhook settings digest is required.")
        self.verify_domain()
        def before_write():
            self.guard()
            require(self._control() == before["control"], "Durable control changed before webhook configuration.")
        result = self.telegram.configure(webhook_sha256, before_write=before_write)
        try:
            after = self.inspect()
            require(after["control"] == before["control"])
        except Exception:
            raise OperationError("Webhook configuration requires independent control readback; keep admission closed and do not retry blindly.",
                                 uncertain=True) from None
        return {**result, "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
                "stateSha256": after["stateSha256"]}

    def plan_activate(self):
        before = self.inspect()
        require(before["control"]["admission"] == "closed" and before["control"]["workers"] == "frozen"
                and not any(before["work"].values()), "Final activation requires a drained, frozen source.")
        require(not any(before["terminal"].get(key, 0) for key in ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates")),
                "Unresolved external effects or interrupted updates require an explicit decision before activation.")
        dependency = self.verify_dependency()
        require(callable(self.activation_baseline_checker), "A pinned independently verified current baseline is required before activation.")
        proof = self.activation_baseline_checker()
        require(isinstance(proof, dict) and proof.get("baselineVerified") is True
                and proof.get("targetSha256") == self.target.digest
                and proof.get("configurationSha256") == self.target.configuration_digest
                and proof.get("sourceRevision") == self.revision
                and proof.get("moduleSha256") == before["release"]["moduleSha256"]
                and proof.get("versionId") == before["release"]["versionId"]
                and matches(SHA, proof.get("manifestSha256")) and matches(r"[0-9a-f]{32}", proof.get("checkpointId")),
                "Activation baseline proof does not match this exact frozen release and configuration.")
        require(self.telegram is not None)
        self.telegram.identity()
        self.telegram.group_permissions()
        info = self.telegram.call("getWebhookInfo")
        self.telegram.webhook_info(info)
        require(info.get("url") == "https://" + self.target.data["hostname"] + "/telegram/webhook"
                and info.get("max_connections") == self.target.data["webhook"]["maxConnections"]
                and set(info.get("allowed_updates", [])) == set(self.target.data["webhook"]["allowedUpdates"])
                and info.get("has_custom_certificate") is False,
                "An exact read-back webhook is required before activation.")
        self.verify_domain()
        before["activationBaseline"] = proof
        if dependency is not None:
            before["dependencyProof"] = dependency
        before["stateSha256"] = digest({k: v for k, v in before.items() if k != "stateSha256"})
        return before

    def transition(self, action, approval, state_sha):
        before = self.plan_activate() if action == "activate" else self.plan_pause() if action == "pause" else self.inspect()
        if before["stateSha256"] != state_sha:
            raise StalePredecessorError()
        self.approval(approval, action, state_sha)
        control = before["control"]
        desired = {"pause": ("closed", "run"), "freeze": ("closed", "frozen"),
                   "thaw": ("closed", "run"), "activate": ("open", "run")}
        require(action in desired)
        admission, workers = desired[action]
        if action == "pause":
            workers = control["workers"]
        if action == "freeze":
            require(control["admission"] == "closed", "Close admission and drain before freezing workers.")
        if action in ("freeze", "activate", "thaw"):
            require(not any(before["work"].values()), "Active, future or uncertain invocation work prevents this transition.")
        predicate = " AND ".join(f"{key} IS {migrations._literal(value) if isinstance(value,str) else value}" for key, value in control.items())
        quiet, fields = work_sql(self.target.data["botId"])
        conditions = [f"EXISTS(SELECT 1 FROM {CONTROL} WHERE {predicate})"]
        if action in ("freeze", "activate", "thaw"):
            conditions += ["EXISTS(SELECT 1 FROM (" + quiet + ") WHERE " + " AND ".join(f"{f}=0" for f in fields) + ")",
                f"NOT EXISTS(SELECT 1 FROM {INVOCATIONS} WHERE state='running')",
                "NOT EXISTS(SELECT 1 FROM subs_bot_production_updates WHERE state='processing')"]
        if action == "activate":
            bot = migrations._literal(self.target.data["botId"])
            conditions += [f"NOT EXISTS(SELECT 1 FROM {INVOCATIONS} WHERE state='uncertain' OR (state='running' AND lease_until<=unixepoch()))",
                "NOT EXISTS(SELECT 1 FROM subs_bot_production_updates WHERE state='uncertain')",
                f"NOT EXISTS(SELECT 1 FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND state='uncertain')",
                f"NOT EXISTS(SELECT 1 FROM telegram_group_share_cards JOIN telegram_private_share_creations USING(receipt_id) WHERE bot_id={bot} AND telegram_group_share_cards.state='uncertain')"]
        self.guard()
        _mutate_sql(self.data, self.database, [migrations._assert_sql(" AND ".join(conditions)),
            f"UPDATE {CONTROL} SET admission='{admission}',workers='{workers}',epoch=epoch+1 WHERE singleton=1"])
        after = self.inspect()
        require(after["control"]["epoch"] == control["epoch"] + 1 and after["control"]["admission"] == admission
                and after["control"]["workers"] == workers, "Transition outcome is not confirmed; inspect before proceeding.")
        if action == "activate":
            after["activationBaseline"] = before["activationBaseline"]
            if "dependencyProof" in before:
                after["dependencyProof"] = before["dependencyProof"]
        return after

    def classify_interruption(self, approval, state_sha):
        before = self.inspect()
        require(before["stateSha256"] == state_sha and before["control"]["admission"] == "closed")
        self.approval(approval, "classify-interruption", state_sha)
        # 960s lease + 60s quarantine exceeds the platform's 900s scheduled
        # execution ceiling. This classifies execution as ended, not its external
        # effect as successful. Nothing is deleted or automatically re-executed.
        epoch = before["control"]["epoch"]
        identity = "target_sha256=" + migrations._literal(self.target.digest) + " AND bot_id=" + migrations._literal(self.target.data["botId"])
        self.guard()
        _mutate_sql(self.data, self.database, [
            migrations._assert_sql(f"EXISTS(SELECT 1 FROM {CONTROL} WHERE epoch={epoch} AND admission='closed' AND {identity})"),
            f"UPDATE {INVOCATIONS} SET state='uncertain',finished_at=unixepoch() WHERE state='running' AND lease_until<=unixepoch()-60 AND {identity}",
            f"UPDATE subs_bot_production_updates SET state='uncertain' WHERE state='processing' AND {identity} AND EXISTS(SELECT 1 FROM {INVOCATIONS} AS invocation WHERE invocation.invocation_id=subs_bot_production_updates.invocation_id AND invocation.state='uncertain' AND invocation.finished_at IS NOT NULL)"])
        return self.inspect()

    def plan_deploy(self, source_controller=None):
        before = self.inspect(verify_release=False)
        require(before["control"]["admission"] == "closed"
                and before["control"]["workers"] == "frozen" and not any(before["work"].values()), "Freeze and reconcile the exact source before deployment.")
        if before["release"]["versionId"] is not None:
            if source_controller is None:
                self.verify_bindings(self.active())
            else:
                require(source_controller.target.digest == self.target.digest, "The approved source belongs to a different target.")
                prior = source_controller.inspect()
                require(prior["release"] == before["release"] and prior["control"] == before["control"]
                        and not any(prior["work"].values()), "Current release does not match the independent reviewed source artifact.")
        return before

    def deploy(self, approval, state_sha, source_controller=None):
        before = self.plan_deploy(source_controller)
        require(before["stateSha256"] == state_sha, "The planned deployment predecessor changed.")
        self.approval(approval, "deploy", state_sha)
        module = (self.bundle / "index.js").read_bytes()
        require(sha256(module).hexdigest() == self.manifest["bundleSha256"] and 0 < len(module) <= 1152*1024)
        bindings = self.expected_bindings(include_secrets=True, allow_unbound_provider=True, verify_dependency=True)
        previous_active = self.active(allow_empty=True)
        require(canonical({key: value for key, value in previous_active.items() if key != "bindings"}) == canonical(before["release"]),
                "The approved active predecessor changed before upload.")
        if previous_active["versionId"] is not None:
            (self if source_controller is None else source_controller).verify_bindings(previous_active)
            for binding, key in (("TELEGRAM_AGGREGATE_KEY_SHA256", "aggregate"), ("TELEGRAM_PRIVATE_SHARE_CREATION_KEY_SHA256", "privateShare")):
                require(previous_active["bindings"].get(binding, {}).get("text") == self.target.data["keyDigests"][key],
                        "Ordinary deployment cannot replace published-link signing keys.")
        require(self.telegram is not None)
        self.telegram.identity()
        self.guard()
        version_id, deployment_id, phase = None, None, "upload"
        def checkpoint(name):
            if self.deployment_checkpoint is not None:
                self.deployment_checkpoint({"phase": name, "versionId": version_id, "deploymentId": deployment_id,
                    "targetSha256": self.target.digest, "configurationSha256": self.target.configuration_digest,
                    "sourceRevision": self.revision, "moduleSha256": self.manifest["bundleSha256"],
                    "predecessorStateSha256": before["stateSha256"], "previousVersionId": before["release"]["versionId"],
                    "previousDeploymentId": before["release"]["deploymentId"]})
        try:
            checkpoint("upload-intent")
        except Exception:
            raise ContractError("The deployment intent evidence was not confirmed; no upload was attempted.") from None
        try:
            uploaded = self.worker("POST", self.worker_path + "/versions?deploy=false", {
                "main_module": "index.js", "compatibility_date": self.manifest["compatibilityDate"], "usage_model": "standard",
                "modules": [{"name": "index.js", "content_type": "application/javascript+module", "content_base64": base64.b64encode(module).decode()}],
                "bindings": bindings, "annotations": {"workers/tag": "lifecycle-" + self.revision[:12], "workers/message": self.target.digest}})
            require(isinstance(uploaded, dict) and matches(UUID, uploaded.get("id")))
            version_id, phase = uploaded["id"], "staged-readback"
            checkpoint("upload-confirmed")
            self.verify_bindings(self.version(version_id), allow_unbound_provider=True, verify_dependency=True)
            self.resources()
            prior = self.active(allow_empty=True)
            require(canonical(prior) == canonical(previous_active), "Active deployment changed during staging.")
            self.guard()
            phase = "traffic"
            checkpoint("traffic-intent")
            deployed = self.worker("POST", self.script + "/deployments", {"strategy": "percentage",
                "versions": [{"version_id": version_id, "percentage": 100}],
                "annotations": {"workers/message": "Reviewed lifecycle release " + self.target.digest}})
            require(isinstance(deployed, dict) and matches(UUID, deployed.get("id")))
            deployment_id, phase = deployed["id"], "active-readback"
            checkpoint("traffic-confirmed")
            from production_deploy_readback import wait_for_deployment
            def read():
                self.resources()
                return self.active(allow_empty=True)
            active = wait_for_deployment(read, previous=previous_active, desired_version=version_id,
                desired_deployment=deployment_id, verify_desired=lambda active: self.verify_bindings(active, verify_dependency=True))
            checkpoint("active-confirmed")
            phase = "reconcile"
            return self.reconcile_deployment(before, expected_active=active)
        except Exception:
            raise DeploymentReconciliationRequired(phase, version_id, deployment_id) from None

    def _reconcile_cron(self):
        value = self.worker("GET", self.script + "/schedules")
        require(isinstance(value, dict) and isinstance(value.get("schedules"), list), "Cron reconciliation readback is unknown.")
        cron = value["schedules"]
        require(cron == [] or len(cron) == 1 and isinstance(cron[0], dict) and cron[0].get("cron") == "* * * * *"
            and set(cron[0]) <= {"cron", "created_on", "modified_on"}
            and all(isinstance(item, str) for item in cron[0].values()), "Unknown Cron configuration cannot be replaced.")
        return cron

    def plan_reconcile_deploy(self):
        before = self.inspect(verify_release=False)
        require(before["control"]["admission"] == "closed" and before["control"]["workers"] == "frozen"
            and not any(before["work"].values()), "Only a drained frozen release may plan reconciliation.")
        active = self.active()
        self.verify_bindings(active, verify_dependency=True)
        require(canonical({key: value for key, value in active.items() if key != "bindings"}) == canonical(before["release"]))
        before["reconcileCron"] = self._reconcile_cron()
        policy = one(self.data, self.database, "SELECT release_revision FROM telegram_general_policy WHERE bot_id="
            + migrations._literal(self.target.data["botId"]))["release_revision"]
        require(policy == before["control"]["release_revision"], "The current control and policy revisions differ.")
        before["reconcilePolicyRevision"] = policy
        before["reconcileMode"] = "already-coherent" if policy == self.revision else "revision-reconcile"
        before["stateSha256"] = digest({key: value for key, value in before.items() if key != "stateSha256"})
        return before

    def reconcile_deploy(self, approval, state_sha, *, predecessor=None, expected_active=None):
        before = self.plan_reconcile_deploy()
        require(before["stateSha256"] == state_sha, "The reconciliation predecessor changed before any SQL.")
        self.approval(approval, "reconcile-deploy", state_sha)
        active = self.active()
        self.verify_bindings(active, verify_dependency=True)
        require(canonical({key: value for key, value in active.items() if key != "bindings"}) == canonical(before["release"]),
                "The approved reconciliation release changed before mutation.")
        if expected_active is not None:
            require(canonical(active) == canonical(expected_active), "The independently pinned reconciliation release differs.")
        return self.reconcile_deployment(before if predecessor is None else predecessor, expected_active=active,
            approved_cron=before["reconcileCron"], current_coherent=predecessor is None and before["reconcileMode"] == "already-coherent")

    def reconcile_deployment(self, before, *, expected_active=None, approved_cron=None, current_coherent=False):
        old = before["control"]["release_revision"]
        active = self.active()
        self.verify_bindings(active, verify_dependency=True)
        if expected_active is not None:
            require(canonical(active) == canonical(expected_active), "The complete reconciliation release changed before SQL.")
        else:
            expected_active = active
        require(before["control"]["admission"] == "closed" and before["control"]["workers"] == "frozen"
                and not any(self.work().values()), "Only a fully frozen deployment can reconcile its revision.")
        observed = self._control()
        cron = self._reconcile_cron()
        if approved_cron is not None:
            require(canonical(cron) == canonical(approved_cron), "The approved Cron predecessor changed before mutation.")
        successor = {**before["control"], "epoch": before["control"]["epoch"] + 1, "release_revision": self.revision}
        expected_control = before["control"] if current_coherent else successor
        def confirmed():
            result = self.inspect()
            require(canonical(result["release"]) == canonical({key: value for key, value in expected_active.items() if key != "bindings"})
                and canonical(result["control"]) == canonical(expected_control), "The exact reconciled control state changed.")
            require(one(self.data, self.database, "SELECT release_revision FROM telegram_general_policy WHERE bot_id="
                + migrations._literal(self.target.data["botId"]))["release_revision"] == self.revision,
                "The exact reconciled policy successor changed.")
            return result
        if current_coherent or canonical(observed) == canonical(successor):
            require(type(current_coherent) is bool and canonical(observed) == canonical(expected_control)
                and observed["release_revision"] == self.revision, "The exact coherent control state changed.")
            policy = one(self.data, self.database, "SELECT release_revision FROM telegram_general_policy WHERE bot_id=" + migrations._literal(self.target.data["botId"]))
            require(policy["release_revision"] == self.revision, "The reconciliation successor policy differs.")
            if not cron:
                require(approved_cron == [], "Empty successor Cron needs a new explicit reconciliation approval.")
                self.guard()
                try:
                    self.worker("PUT", self.script + "/schedules", [{"cron": "* * * * *"}])
                    return confirmed()
                except Exception:
                    raise DeploymentReconciliationRequired("reconcile", active["versionId"], active["deploymentId"]) from None
            else:
                return confirmed()
        require(canonical(observed) == canonical(before["control"]), "The original reconciliation control predecessor changed.")
        policy_guard = "EXISTS(SELECT 1 FROM telegram_general_policy WHERE bot_id=" + migrations._literal(self.target.data["botId"]) \
            + " AND release_revision=" + migrations._literal(old) + ")"
        require(one(self.data, self.database, "SELECT release_revision FROM telegram_general_policy WHERE bot_id="
            + migrations._literal(self.target.data["botId"]))["release_revision"] == old,
            "The original reconciliation policy predecessor changed; no mutation was attempted.")
        self.guard()
        try:
            _mutate_sql(self.data, self.database, [migrations._assert_sql(f"EXISTS(SELECT 1 FROM {CONTROL} WHERE admission='closed' AND workers='frozen' AND epoch={before['control']['epoch']} AND target_sha256={migrations._literal(self.target.digest)} AND bot_id={migrations._literal(self.target.data['botId'])} AND generation={self.target.data['generation']} AND release_revision={migrations._literal(old)}) AND {policy_guard}"),
                f"UPDATE {CONTROL} SET release_revision={migrations._literal(self.revision)},epoch=epoch+1 WHERE singleton=1",
                f"UPDATE telegram_general_policy SET release_revision={migrations._literal(self.revision)} WHERE bot_id={migrations._literal(self.target.data['botId'])} AND release_revision={migrations._literal(old)}"])
            self.worker("PUT", self.script + "/schedules", [{"cron": "* * * * *"}])
            return confirmed()
        except Exception:
            raise DeploymentReconciliationRequired("reconcile", active["versionId"], active["deploymentId"]) from None

    def verify_domain(self):
        t = self.target.data
        if self.target.environment == "rehearsal":
            worker = self.worker("GET", self.worker_path)
            require(worker.get("subdomain", {}).get("enabled") is True and worker["subdomain"].get("url") == "https://" + t["hostname"])
        else:
            rows_ = self.worker("GET", self.root + "/workers/domains?" + urlencode({"hostname": t["hostname"]}))
            require(isinstance(rows_, list) and len(rows_) == 1 and all(rows_[0].get(k) == v for k, v in
                {"hostname": t["hostname"], "service": t["workerName"], "zone_id": t["zoneId"], "environment": "production"}.items()),
                "Custom domain is not attached to the exact approved target.")
        url = "https://" + t["hostname"] + "/health"
        for attempt, delay in enumerate((0, 1, 3), 1):
            if delay:
                sleep(delay)
            try:
                _read_domain_health(url, self.revision, attempt)
                return {"domainVerified": True, "healthReadbackAttempts": attempt}
            except _HealthReadbackError as error:
                if not error.retryable or attempt == 3:
                    raise

    def attach_domain(self, approval, state_sha):
        before = self.inspect()
        require(before["stateSha256"] == state_sha and before["control"]["admission"] == "closed")
        self.approval(approval, "domain", state_sha)
        require(self.telegram is not None)
        self.telegram.identity()
        require(self.target.environment == "production", "Rehearsal uses its registered workers.dev identity.")
        t = self.target.data
        current = self.worker("GET", self.root + "/workers/domains?" + urlencode({"hostname": t["hostname"]}))
        dns = self.worker("GET", "/zones/" + t["zoneId"] + "/dns_records?" + urlencode({"name": t["hostname"], "per_page": 100}), envelope=True)
        require(current == [] and dns.get("result") == [] and dns.get("result_info", {}).get("total_count", 0) == 0,
                "An existing domain or DNS record cannot be adopted or overwritten.")
        self.guard()
        self.worker("PUT", self.root + "/workers/domains", {"hostname": t["hostname"], "service": t["workerName"],
            "environment": "production", "zone_id": t["zoneId"]})
        return self.verify_domain()


def hosted_environment(environment):
    expected = "subs-bot-production" if environment == "production" else "subs-bot-isolation"
    require(os.environ.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and os.environ.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and os.environ.get("GITHUB_REF") == artifact.MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted" and os.environ.get("SUBS_BOT_CONTROL_ENVIRONMENT") == expected,
            "Lifecycle actions require the project's protected main workflow on a GitHub-hosted runner.")


def main():
    action = os.environ.get("CONTROL_ACTION", "inspect")
    target = validate_target(os.environ.get("SUBS_BOT_TARGET_JSON", ""))
    hosted_environment(target.environment)
    revision = os.environ.get("GITHUB_SHA", "")
    artifact.require_current_main(revision)
    secrets = parsed(os.environ.get("SUBS_BOT_CONTROL_SECRETS", ""))
    general_config(target, revision, secrets)
    data = API(target, os.environ.get("SUBS_BOT_CF_DATA_TOKEN", ""))
    worker = API(target, os.environ.get("SUBS_BOT_CF_WORKER_TOKEN", ""))
    source_checkpoint = os.environ.get("CONTROL_SOURCE_CHECKPOINT_ID", "")
    source_manifest_sha = os.environ.get("CONTROL_SOURCE_MANIFEST_SHA256", "")
    require(bool(source_checkpoint) == bool(source_manifest_sha), "Both pinned private source fields are required.")
    if source_checkpoint:
        from production_release_evidence import load_release
        archived = load_release(target, os.environ["SUBS_BOT_CF_DATA_TOKEN"], source_checkpoint, source_manifest_sha, Path(os.environ["RUNNER_TEMP"]))
        proof, bundle, manifest = archived["proof"], archived["bundle"], archived["manifest"]
        if action in ("plan-deploy", "deploy", "initialize", "preflight"):
            require(proof["revision"] == revision, "New deployment requires the exact current main, including an archived source.")
        else:
            require(archived["sourceTarget"].configuration_digest == target.configuration_digest,
                    "Archived source configuration differs from the explicitly selected target.")
    else:
        proof = prepare_control_artifact.prepare(action)
        bundle = Path(os.environ["RUNNER_TEMP"]) / artifact.VERIFIED_DIRECTORY
        manifest = parsed((bundle / "isolation.json").read_bytes())
    controller = Controller(target, data, worker, bundle, manifest, guard=lambda: artifact.require_current_main(revision),
                            telegram=Telegram(target, secrets), secrets=secrets, control_revision=revision,
                            dependency_api=API(target, os.environ["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"]) if target.data["provider"] is not None and os.environ.get("SUBS_BOT_CF_DEPENDENCY_READ_TOKEN") else None)
    def deployment_checkpoint(event):
        path = Path(os.environ["RUNNER_TEMP"]) / "production-control-deployment-events.ndjson"
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW
        with os.fdopen(os.open(path, flags, 0o600), "ab") as stream:
            stream.write(canonical(event) + b"\n")
    controller.deployment_checkpoint = deployment_checkpoint
    source_controller = None
    source_directory = None
    baseline_checkpoint = os.environ.get("CONTROL_BASELINE_CHECKPOINT_ID", "")
    baseline_manifest_sha = os.environ.get("CONTROL_BASELINE_MANIFEST_SHA256", "")
    require(bool(baseline_checkpoint) == bool(baseline_manifest_sha), "Both exact activation baseline fields are required.")
    if baseline_checkpoint:
        from production_release_evidence import verify_activation_baseline
        controller.activation_baseline_checker = lambda: verify_activation_baseline(controller, os.environ["SUBS_BOT_CF_DATA_TOKEN"], baseline_checkpoint, baseline_manifest_sha)
    active_checkpoint = os.environ.get("CONTROL_ACTIVE_CHECKPOINT_ID", "")
    active_manifest_sha = os.environ.get("CONTROL_ACTIVE_MANIFEST_SHA256", "")
    require(bool(active_checkpoint) == bool(active_manifest_sha), "Both archived active-source fields are required.")
    if action in ("plan-deploy", "deploy") and (os.environ.get("CONTROL_ACTIVE_CI_RUN_ID") or active_checkpoint):
        source_directory = tempfile.TemporaryDirectory(prefix="subs-bot-reviewed-active-", dir=os.environ["RUNNER_TEMP"])
        if active_checkpoint:
            from production_release_evidence import load_release
            previous_release = load_release(target, os.environ["SUBS_BOT_CF_DATA_TOKEN"], active_checkpoint, active_manifest_sha, source_directory.name)
            source_proof, source_bundle, source_manifest = previous_release["proof"], previous_release["bundle"], previous_release["manifest"]
            previous_target = previous_release["sourceTarget"]
            if os.environ.get("SUBS_BOT_ACTIVE_TARGET_JSON"):
                require(validate_target(os.environ["SUBS_BOT_ACTIVE_TARGET_JSON"]).configuration_digest == previous_target.configuration_digest)
        else:
            source_proof = prepare_control_artifact.prepare("inspect", run_id=os.environ["CONTROL_ACTIVE_CI_RUN_ID"], directory=source_directory.name)
            source_bundle = Path(source_directory.name) / artifact.VERIFIED_DIRECTORY
            source_manifest = parsed((source_bundle / "isolation.json").read_bytes())
            previous_target = validate_target(os.environ.get("SUBS_BOT_ACTIVE_TARGET_JSON") or canonical(target.data))
        previous_secrets = parsed(os.environ.get("SUBS_BOT_ACTIVE_CONTROL_SECRETS") or canonical(secrets))
        previous_dependency_api = None
        if previous_target.data["provider"] is not None:
            require(os.environ.get("SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"),
                    "The reviewed active ProviderFetch requires its own explicit read credential before unbinding.")
            previous_dependency_api = API(previous_target, os.environ["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"])
        source_controller = Controller(previous_target, data, worker, source_bundle, source_manifest,
            guard=lambda: artifact.require_current_main(revision), secrets=previous_secrets, control_revision=revision,
            dependency_api=previous_dependency_api)
    envelope = os.environ.get("SUBS_BOT_APPROVAL_JSON", "")
    predecessor = os.environ.get("CONTROL_STATE_SHA256", "")
    if action == "preflight":
        result = {"resources": controller.resources(), "bot": controller.telegram.identity(), "groups": controller.telegram.group_permissions()}
        result["stateSha256"] = digest(result["resources"])
    elif action == "inspect":
        result = controller.inspect()
    elif action == "initialize":
        require(matches(SHA, predecessor))
        controller.approval(envelope, action, predecessor)
        # The predecessor for initialization is the exact resource registration.
        require(digest(controller.resources()) == predecessor)
        result = controller.initialize()
    elif action == "plan-deploy":
        result = controller.plan_deploy(source_controller)
    elif action == "plan-reconcile-deploy":
        result = controller.plan_reconcile_deploy()
    elif action == "plan-pause":
        result = controller.plan_pause()
    elif action == "plan-webhook":
        result = controller.plan_webhook()
    elif action == "plan-activate":
        result = controller.plan_activate()
    elif action == "deploy":
        result = controller.deploy(envelope, predecessor, source_controller)
    elif action == "reconcile-deploy":
        result = controller.reconcile_deploy(envelope, predecessor)
    elif action in ("pause", "freeze", "thaw", "activate"):
        result = controller.transition(action, envelope, predecessor)
    elif action == "classify-interruption":
        result = controller.classify_interruption(envelope, predecessor)
    elif action == "drain":
        result = controller.inspect()
        require(result["control"]["admission"] == "closed" and not any(result["work"].values()),
                "Drain is incomplete; preserve all records and wait for accepted work or classify uncertainty.")
        result["drained"] = True
    elif action == "domain":
        result = controller.attach_domain(envelope, predecessor)
    elif action == "webhook":
        result = controller.configure_webhook(envelope, predecessor, os.environ.get("CONTROL_WEBHOOK_SHA256", ""))
    else:
        raise ContractError("Unsupported lifecycle action.")
    # Public evidence never contains actor lists, bindings with Secrets or SQL.
    result["ciProof"] = proof
    result["controlRevision"] = revision
    result["releaseSourceBackend"] = "private-r2" if source_checkpoint else "github-actions"
    if source_controller is not None:
        result["activeCIProof"] = source_proof
    path = Path(os.environ["RUNNER_TEMP"]) / "production-control-result.json"
    path.write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    from production_recovery import RecoveryError
    try:
        main()
    except (ContractError, OperationError, migrations.MigrationError, artifact.ArtifactError, RecoveryError) as error:
        print(json.dumps({"status": "stopped", "reason": str(error), "uncertain": bool(getattr(error, "uncertain", False)),
            **(error.safe_details() if isinstance(error, DeploymentReconciliationRequired) else {})}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "An unexpected lifecycle failure occurred. Inspect the target state before retrying.", "uncertain": True}))
        raise SystemExit(1) from None

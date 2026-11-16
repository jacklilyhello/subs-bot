"""Protected first-release lifecycle; production and registered rehearsal use the same code.

No token, SQL export, Bot credential, capability URL or user list is printed.
Mutations never retry transport failures. Inspect/reconcile the independent state first.
"""
from __future__ import annotations

import base64
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

import d1_migrations as migrations
import prepare_isolation_artifact as artifact
from general_isolation_window import work_sql, terminal_card_sql
from production_target import Target, ContractError, approve, canonical, digest, matches, parsed, require, validate_target, SHA, REV, UUID

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


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


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
        require(isinstance(path, str) and matches(r"/[A-Za-z0-9/_.?=&,~-]+", path)
                and not any(p in (".", "..") for p in path.partition("?")[0].split("/")))
        require(path.startswith(self.root + "/") or path in (self.root, "/zones/" + self.target["zoneId"])
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
    def __init__(self, target, secrets):
        self.target, self.secrets = target, secrets
        self.opener = build_opener(ProxyHandler({}), NoRedirect())

    def call(self, method, payload=None):
        require(method in ("getMe", "getWebhookInfo", "setWebhook"))
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

    def configure(self, expected_before):
        self.identity()
        before = self.call("getWebhookInfo")
        require(digest(before) == expected_before, "Webhook predecessor changed; no mutation performed.")
        t = self.target.data
        desired = {"url": "https://" + t["hostname"] + "/telegram/webhook", "secret_token": self.secrets["webhookSecret"],
            "drop_pending_updates": False, "allowed_updates": t["webhook"]["allowedUpdates"],
            "max_connections": t["webhook"]["maxConnections"]}
        self.call("setWebhook", desired)
        after = self.call("getWebhookInfo")
        require(after.get("url") == desired["url"] and after.get("max_connections") == desired["max_connections"]
                and set(after.get("allowed_updates", [])) == set(desired["allowed_updates"])
                and after.get("has_custom_certificate") is False, "Webhook mutation did not read back exactly; keep admission closed.")
        return {"webhookSha256": digest(after), "pendingUpdateCount": after.get("pending_update_count"), "dropPendingUpdates": False}


class Controller:
    def __init__(self, target, data_api, worker_api, bundle, manifest, *, guard=lambda: None, telegram=None, secrets=None):
        self.target, self.data, self.worker = target, data_api, worker_api
        self.bundle, self.manifest, self.guard = Path(bundle), manifest, guard
        self.telegram, self.secrets = telegram, secrets
        self.root = "/accounts/" + target.data["accountId"]
        self.database = self.root + "/d1/database/" + target.data["d1Id"]
        self.script = self.root + "/workers/scripts/" + target.data["workerName"]
        self.worker_path = self.root + "/workers/workers/" + target.data["workerId"]
        self.revision = manifest["revision"]
        require(matches(REV, self.revision) and matches(SHA, manifest.get("bundleSha256")))

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
        versions = current.get("versions")
        require(current.get("strategy") == "percentage" and isinstance(versions, list) and len(versions) == 1
                and versions[0].get("percentage") == 100 and matches(UUID, versions[0].get("version_id")))
        version = self.worker("GET", self.worker_path + "/versions/" + versions[0]["version_id"] + "?include=modules")
        modules = version.get("modules")
        require(version.get("id") == versions[0]["version_id"] and version.get("main_module") == "index.js"
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
                "deploymentId": current["id"], "bindings": bindings, "compatibilityDate": version["compatibility_date"]}

    def expected_bindings(self, *, include_secrets=False):
        t, flags = self.target.data, self.target.data["features"]
        result = [{"type": "d1", "name": "DB", "database_id": t["d1Id"]},
            {"type": "r2_bucket", "name": "NODES", "bucket_name": t["bucketName"]}]
        text = {"BUILD_REVISION": self.revision, "PUBLIC_ORIGIN": "https://" + t["hostname"],
            "TELEGRAM_PRODUCTION_CONTROL_SHA256": self.target.digest,
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
            from production_provider import verify_provider_dependency
            dependency = verify_provider_dependency(self.worker, t["provider"])
            result.append({"type": "service", "name": "PROVIDER_FETCH", "service": dependency["service"], "entrypoint": "ProviderFetch"})
            text.update({"PROVIDER_REVISION": dependency["revision"], "PROVIDER_IMAGE_SHA256": dependency["imageSha256"]})
        result.extend({"type": "plain_text", "name": key, "text": value} for key, value in text.items())
        result.extend({"type": "secret_text", "name": key, **({"text": value} if include_secrets else {})} for key, value in secrets.items())
        return result

    def verify_bindings(self, active):
        expected = {r["name"]: r for r in self.expected_bindings()}
        actual = active["bindings"]
        require(set(expected) == set(actual), "Active binding inventory differs from the exact configuration.")
        for name, wanted in expected.items():
            observed = actual[name]
            if wanted["type"] == "secret_text":
                require(observed.get("type") == "secret_text" and "text" not in observed)
            else:
                require(all(observed.get(k) == v for k, v in wanted.items()), "Active binding differs from the approved configuration.")
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
        state = {"targetSha256": self.target.digest, "release": {k: v for k, v in active.items() if k != "bindings"},
            "control": control, "work": self.work(), "terminal": self.terminal(), "migrationCount": len(history)}
        state["stateSha256"] = digest(state)
        return state

    def initialize(self):
        self.resources()
        if self.telegram is not None:
            self.telegram.identity()
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

    def transition(self, action, approval, state_sha):
        before = self.inspect()
        require(before["stateSha256"] == state_sha, "Predecessor state changed; no transition performed.")
        approve(self.target, approval, action, self.revision, state_sha)
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
        if action == "activate":
            require(not any(before["terminal"].get(key, 0) for key in ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates")),
                    "Unresolved external effects or interrupted updates require an explicit decision before activation.")
            require(self.telegram is not None)
            self.telegram.identity()
            info = self.telegram.call("getWebhookInfo")
            require(info.get("url") == "https://" + self.target.data["hostname"] + "/telegram/webhook"
                    and info.get("max_connections") == self.target.data["webhook"]["maxConnections"]
                    and set(info.get("allowed_updates", [])) == set(self.target.data["webhook"]["allowedUpdates"]),
                    "An exact read-back webhook is required before activation.")
            self.verify_domain()
        predicate = " AND ".join(f"{key} IS {migrations._literal(value) if isinstance(value,str) else value}" for key, value in control.items())
        quiet, fields = work_sql(self.target.data["botId"])
        conditions = [f"EXISTS(SELECT 1 FROM {CONTROL} WHERE {predicate})"]
        if action in ("freeze", "activate", "thaw"):
            conditions += ["EXISTS(SELECT 1 FROM (" + quiet + ") WHERE " + " AND ".join(f"{f}=0" for f in fields) + ")",
                f"NOT EXISTS(SELECT 1 FROM {INVOCATIONS} WHERE state='running')",
                "NOT EXISTS(SELECT 1 FROM subs_bot_production_updates WHERE state='processing')"]
        self.guard()
        _mutate_sql(self.data, self.database, [migrations._assert_sql(" AND ".join(conditions)),
            f"UPDATE {CONTROL} SET admission='{admission}',workers='{workers}',epoch=epoch+1 WHERE singleton=1"])
        after = self.inspect()
        require(after["control"]["epoch"] == control["epoch"] + 1 and after["control"]["admission"] == admission
                and after["control"]["workers"] == workers, "Transition outcome is not confirmed; inspect before proceeding.")
        return after

    def classify_interruption(self, approval, state_sha):
        before = self.inspect()
        require(before["stateSha256"] == state_sha and before["control"]["admission"] == "closed")
        approve(self.target, approval, "classify-interruption", self.revision, state_sha)
        # 960s lease + 60s quarantine exceeds the platform's 900s scheduled
        # execution ceiling. This classifies execution as ended, not its external
        # effect as successful. Nothing is deleted or automatically re-executed.
        epoch = before["control"]["epoch"]
        self.guard()
        _mutate_sql(self.data, self.database, [
            migrations._assert_sql(f"EXISTS(SELECT 1 FROM {CONTROL} WHERE epoch={epoch} AND admission='closed')"),
            f"UPDATE {INVOCATIONS} SET state='uncertain',finished_at=unixepoch() WHERE state='running' AND lease_until<=unixepoch()-60",
            f"UPDATE subs_bot_production_updates SET state='uncertain' WHERE state='processing' AND EXISTS(SELECT 1 FROM {INVOCATIONS} AS invocation WHERE invocation.invocation_id=subs_bot_production_updates.invocation_id AND invocation.state='uncertain' AND invocation.finished_at IS NOT NULL)"])
        return self.inspect()

    def deploy(self, approval, state_sha):
        before = self.inspect(verify_release=False)
        require(before["stateSha256"] == state_sha and before["control"]["admission"] == "closed"
                and before["control"]["workers"] == "frozen" and not any(before["work"].values()), "Freeze and reconcile the exact source before deployment.")
        approve(self.target, approval, "deploy", self.revision, state_sha)
        module = (self.bundle / "index.js").read_bytes()
        require(sha256(module).hexdigest() == self.manifest["bundleSha256"] and 0 < len(module) <= 1152*1024)
        bindings = self.expected_bindings(include_secrets=True)
        require(self.telegram is not None)
        self.telegram.identity()
        self.guard()
        uploaded = self.worker("POST", self.worker_path + "/versions?deploy=false", {
            "main_module": "index.js", "compatibility_date": self.manifest["compatibilityDate"], "usage_model": "standard",
            "modules": [{"name": "index.js", "content_type": "application/javascript+module", "content_base64": base64.b64encode(module).decode()}],
            "bindings": bindings, "annotations": {"workers/tag": "lifecycle-" + self.revision[:12], "workers/message": self.target.digest}})
        require(isinstance(uploaded, dict) and matches(UUID, uploaded.get("id")), "Uploaded version is unconfirmed; do not retry blindly.")
        self.resources()
        require(self.active(allow_empty=True)["deploymentId"] == before["release"]["deploymentId"], "Active deployment changed during staging.")
        self.guard()
        self.worker("POST", self.script + "/deployments", {"strategy": "percentage", "versions": [{"version_id": uploaded["id"], "percentage": 100}],
            "annotations": {"workers/message": "Reviewed lifecycle release " + self.target.digest}})
        active = self.active()
        self.verify_bindings(active)
        require(active["versionId"] == uploaded["id"])
        # At this point a failure stays safely frozen. Revision updates are one
        # transaction, and never reset actor permissions, receipts or business data.
        return self.reconcile_deployment(before)

    def reconcile_deployment(self, before):
        old = before["control"]["release_revision"]
        self.verify_bindings(self.active())
        require(before["control"]["admission"] == "closed" and before["control"]["workers"] == "frozen"
                and not any(self.work().values()), "Only a fully frozen deployment can reconcile its revision.")
        self.guard()
        _mutate_sql(self.data, self.database, [migrations._assert_sql(f"EXISTS(SELECT 1 FROM {CONTROL} WHERE admission='closed' AND workers='frozen' AND epoch={before['control']['epoch']})"),
            f"UPDATE {CONTROL} SET release_revision={migrations._literal(self.revision)},epoch=epoch+1 WHERE singleton=1",
            f"UPDATE telegram_general_policy SET release_revision={migrations._literal(self.revision)} WHERE bot_id={migrations._literal(self.target.data['botId'])} AND release_revision={migrations._literal(old)}"])
        self.worker("PUT", self.script + "/schedules", [{"cron": "* * * * *"}])
        return self.inspect()

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
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(Request(url, headers={"Cache-Control": "no-cache"}), timeout=20) as response:
                health = parsed(response.read(4097))
            require(health == {"ok": True, "service": "subs-bot", "revision": self.revision})
        except (OSError, HTTPException):
            raise OperationError("HTTPS domain health did not confirm the exact revision; admission remains closed.") from None
        return {"domainVerified": True}

    def attach_domain(self, approval, state_sha):
        before = self.inspect()
        require(before["stateSha256"] == state_sha and before["control"]["admission"] == "closed")
        approve(self.target, approval, "domain", self.revision, state_sha)
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
    proof = artifact.prepare()
    bundle = Path(os.environ["RUNNER_TEMP"]) / artifact.VERIFIED_DIRECTORY
    manifest = parsed((bundle / "isolation.json").read_bytes())
    secrets = parsed(os.environ.get("SUBS_BOT_CONTROL_SECRETS", ""))
    general_config(target, revision, secrets)
    data = API(target, os.environ.get("SUBS_BOT_CF_DATA_TOKEN", ""))
    worker = API(target, os.environ.get("SUBS_BOT_CF_WORKER_TOKEN", ""))
    controller = Controller(target, data, worker, bundle, manifest, guard=lambda: artifact.require_current_main(revision),
                            telegram=Telegram(target, secrets), secrets=secrets)
    envelope = os.environ.get("SUBS_BOT_APPROVAL_JSON", "")
    predecessor = os.environ.get("CONTROL_STATE_SHA256", "")
    if action == "preflight":
        result = {"resources": controller.resources(), "bot": controller.telegram.identity()}
        result["stateSha256"] = digest(result["resources"])
    elif action == "inspect":
        result = controller.inspect()
    elif action == "initialize":
        require(matches(SHA, predecessor))
        approve(target, envelope, action, revision, predecessor)
        # The predecessor for initialization is the exact resource registration.
        require(digest(controller.resources()) == predecessor)
        result = controller.initialize()
    elif action == "deploy":
        result = controller.deploy(envelope, predecessor)
    elif action == "reconcile-deploy":
        before = controller.inspect(verify_release=False)
        require(before["stateSha256"] == predecessor)
        approve(target, envelope, action, revision, predecessor)
        result = controller.reconcile_deployment(before)
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
        state = controller.inspect()
        require(state["stateSha256"] == predecessor and state["control"]["admission"] == "closed")
        approve(target, envelope, action, revision, predecessor)
        controller.verify_domain()
        result = controller.telegram.configure(os.environ.get("CONTROL_WEBHOOK_SHA256", ""))
    else:
        raise ContractError("Unsupported lifecycle action.")
    # Public evidence never contains actor lists, bindings with Secrets or SQL.
    result["ciProof"] = proof
    path = Path(os.environ["RUNNER_TEMP"]) / "production-control-result.json"
    path.write_bytes(canonical(result))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ContractError, OperationError, migrations.MigrationError, artifact.ArtifactError) as error:
        print(json.dumps({"status": "stopped", "reason": str(error), "uncertain": bool(getattr(error, "uncertain", False))}))
        raise SystemExit(1) from None

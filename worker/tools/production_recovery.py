"""Production D1/R2 checkpoint and independent-target recovery controls.

This module intentionally does not use or alter the rehearsal API's fixed
account/resource allowlist.  Only bounded SQL/schema/data encoders and the
native import state machine are shared.  Production identity, admission,
consumer discovery, resource ownership and the journal are separate contracts.

All entry points run on the hosted control runner.  Private SQL, bookmarks,
capabilities and manifests stay in runner scratch or the target's private
backup bucket.  The public result contains hashes/counts only.  This tool never
switches consumers or writes business data to the source.
"""

from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPSConnection, HTTPException
import os
import re
from secrets import token_hex
import time
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

import d1_migrations as migrations
import native_restore_rehearsal as native
from cloudflare_isolation import API_ORIGIN, DIGEST, HEX_ID, REVISION, UUID, _NoRedirect
from production_target import Target


ERROR = "The production recovery checkpoint could not be verified safely."
NAME = re.compile(r"subs-bot-(?:cf-)?restore-[a-z0-9][a-z0-9-]{0,34}")
SCRIPT = re.compile(r"[a-zA-Z0-9_][a-zA-Z0-9_-]{0,62}")
CHECKPOINT = re.compile(r"[a-f0-9]{32}")
MAX_CONSUMERS = 1000
MAX_ENVIRONMENTS = 32
LIMITS = {"sqlBytes": native.SQL_BYTES, "rows": native.MAX_ROWS,
          "referencedObjects": native.MAX_OBJECTS, "objectBytes": native.OBJECT_BYTES,
          "totalObjectBytes": native.TOTAL_OBJECT_BYTES, "manifestBytes": native.MANIFEST_BYTES,
          "workerServices": MAX_CONSUMERS, "environmentsPerService": MAX_ENVIRONMENTS}

require = native.require
canonical = native.canonical
digest = native.digest
matches = native.matches
integer = native.integer
RecoveryError = native.RehearsalError


def recovery_contract(raw, target):
    """Names are intentions; unknown existing resources can never become pins."""
    value = native.parsed(raw.encode() if isinstance(raw, str) else raw, 8192)
    require(set(value) <= {"version", "checkpointId", "databaseName", "objectsName", "purpose", "preservedG1", "sessionId", "sourceManifestSha256"}
            and {"version", "checkpointId", "databaseName", "objectsName", "purpose"} <= set(value))
    require(type(value["version"]) is int and value["version"] == 1
            and matches(CHECKPOINT, value["checkpointId"])
            and all(matches(NAME, value[key]) for key in ("databaseName", "objectsName"))
            and value["purpose"] in {"baseline", "incident", "recovery"})
    source_names = {target["d1Name"], target["bucketName"], target["backupBucketName"], target["workerName"]}
    require(not {value["databaseName"], value["objectsName"]} & source_names,
            "Recovery targets must be independent of every source resource.")
    g1 = value.get("preservedG1")
    if g1 is not None:
        require(isinstance(g1, dict) and set(g1) == {"checkpointId", "manifestSha256"}
                and matches(CHECKPOINT, g1["checkpointId"]) and g1["checkpointId"] != value["checkpointId"]
                and matches(DIGEST, g1["manifestSha256"]))
    require(value["purpose"] != "recovery" or g1 is not None,
            "Recovery requires a separately sealed current-state G1 checkpoint.")
    if "sessionId" in value or "sourceManifestSha256" in value:
        require(matches(CHECKPOINT, value.get("sessionId")) and value["sessionId"] != value["checkpointId"]
                and matches(DIGEST, value.get("sourceManifestSha256")) and value["purpose"] == "recovery",
                "An independent recovery session requires an explicit source manifest and preserved G1.")
    return value


def contract_identity(contract):
    """Source/destination ownership is immutable; later recovery approval adds G1.

    The complete contract (including purpose and preservedG1) is separately
    hashed into the action-specific approval. A baseline may therefore be
    recovered after a later incident without rewriting its historical journal.
    """
    return digest(canonical({key: contract[key] for key in ("version", "checkpointId", "databaseName", "objectsName", "sessionId", "sourceManifestSha256") if key in contract}))


class RecoveryAPI:
    """Explicit per-target allowlist. No DELETE, reset, source write or Worker mutation."""

    def __init__(self, target, token, worker_api, contract):
        require(isinstance(target, dict) and matches(HEX_ID, target.get("accountId"))
                and matches(UUID, target.get("d1Id"))
                and re.fullmatch(r"[A-Za-z0-9_.-]{1,4096}", token or ""))
        self.target, self.token, self.worker_api = target, token, worker_api
        self.contract = recovery_contract(canonical(contract), target)
        self.cohort = self.contract["checkpointId"]
        self.account_id = target["accountId"]
        self.root = "/accounts/" + self.account_id
        self.source = self.root + "/d1/database/" + target["d1Id"]
        self.names = {"backup": target["backupBucketName"], "database": self.contract["databaseName"],
                      "objects": self.contract["objectsName"]}
        self.archive_prefix = f"production/checkpoints/{self.cohort}/"
        self.journal_prefix = f"production/recovery/{self.contract.get('sessionId', self.cohort)}/journal/"
        self.databases = {target["d1Id"]}
        self.buckets = {target["bucketName"], target["backupBucketName"], self.names["objects"]}
        require(len(self.buckets) == 3)
        self.restore_id = self.restore_bucket = self.s3_access_key = None
        self.restore_keys = set()
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, method, path, payload=None):
        return self.json(method, path, payload)

    def allow_restore(self, database_id=None, keys=None, object_bucket=None):
        if database_id is not None:
            require(matches(UUID, database_id) and database_id != self.target["d1Id"]
                    and database_id in self.databases)
            self.restore_id = database_id
        if keys is not None:
            require(isinstance(keys, list) and len(keys) <= native.MAX_OBJECTS
                    and len(set(keys)) == len(keys) and all(matches(native.KEY, key) for key in keys))
            self.restore_keys = set(keys)
        if object_bucket is not None:
            require(object_bucket == self.names["objects"])
            self.restore_bucket = object_bucket

    def json(self, method, path, payload=None, *, envelope=False):
        require(method in {"GET", "POST"} and isinstance(path, str)
                and not any(char in path for char in "#\\\n\r") and not path.startswith("//"))
        route = path.partition("?")[0]
        require("%" not in route and all(part not in {".", ".."} for part in route.split("/")))
        allowed = False
        if method == "GET" and payload is None:
            allowed = path in {"/user/tokens/verify", self.root + "/tokens/verify"}
            allowed |= path == self.root + "/d1/database?" + urlencode({"name": self.names["database"], "per_page": 100})
            allowed |= path == self.root + "/r2/buckets?" + urlencode({"name_contains": self.names["objects"], "per_page": 100})
            allowed |= any(path == self.root + "/d1/database/" + database for database in self.databases)
            for bucket in self.buckets:
                base = self.root + "/r2/buckets/" + bucket
                allowed |= path in {base, base + "/domains/managed", base + "/domains/custom", base + "/lifecycle"}
                if route == base + "/objects":
                    from urllib.parse import parse_qs
                    query = parse_qs(path.partition("?")[2], keep_blank_values=True, max_num_fields=3)
                    allowed |= (set(query) <= {"prefix", "per_page", "cursor"}
                                and {"prefix", "per_page"} <= set(query)
                                and all(len(values) == 1 for values in query.values())
                                and query["per_page"][0].isdigit() and 1 <= int(query["per_page"][0]) <= 1000
                                and len(query.get("cursor", [""])[0]) <= 4096
                                and (bucket != self.names["backup"] or query["prefix"][0].startswith(self.journal_prefix)))
        elif method == "POST" and path == route and isinstance(payload, dict):
            if route == self.root + "/d1/database":
                allowed = payload == {"name": self.names["database"], "read_replication": {"mode": "disabled"}}
            elif route == self.root + "/r2/buckets":
                allowed = payload == {"name": self.names["objects"], "storageClass": "Standard"}
            elif route.endswith("/query") and route in {
                self.root + "/d1/database/" + database + "/query" for database in self.databases
            }:
                sql = payload.get("sql")
                allowed = (set(payload) <= {"sql", "params"} and isinstance(sql, str)
                           and isinstance(payload.get("params", []), list)
                           and all(isinstance(value, str) for value in payload.get("params", []))
                           and ((len(sql.encode()) <= migrations.MAX_D1_STATEMENT_BYTES and native.readonly_sql(sql.strip()))
                                or ("params" not in payload and native.readonly_schema_batch(sql) is not None)))
            elif route == self.source + "/export":
                allowed = (set(payload) <= {"output_format", "dump_options", "current_bookmark"}
                           and payload.get("output_format") == "polling"
                           and payload.get("dump_options") == {"compatibility": "d1"}
                           and ("current_bookmark" not in payload or matches(native.BOOKMARK, payload["current_bookmark"])))
            elif self.restore_id is not None and route == self.root + "/d1/database/" + self.restore_id + "/import":
                fields = {"init": {"action", "etag"}, "ingest": {"action", "etag", "filename"},
                          "poll": {"action", "current_bookmark"}}
                allowed = (payload.get("action") in fields and set(payload) == fields[payload["action"]]
                           and ("etag" not in payload or re.fullmatch(r"[a-f0-9]{32}", payload["etag"] or "") is not None)
                           and all(matches(native.BOOKMARK, payload[key]) for key in ("filename", "current_bookmark") if key in payload))
        require(allowed, "The recovery API rejected an out-of-scope operation.")
        token = self.token
        if method == "GET" and route.startswith(self.root + "/r2/buckets") and not route.endswith("/objects"):
            token = native.scoped_r2.metadata_token() or token
        elif method == "POST" and route == self.root + "/r2/buckets":
            token = native.scoped_r2.creation_token(token)
        headers = {"Authorization": "Bearer " + token, "Accept": "application/json",
                   "Cache-Control": "no-cache", "cf-r2-jurisdiction": "default"}
        body = None if payload is None else canonical(payload)
        if body is not None:
            headers["Content-Type"] = "application/json"
        _, _, raw = native._response(self.opener, Request(API_ORIGIN + path, data=body, headers=headers, method=method), 8 * 1024 * 1024)
        result = native.parsed(raw, 8 * 1024 * 1024)
        require(result.get("success") is True and result.get("errors") in (None, []) and "result" in result)
        return result if envelope else result["result"]

    def list_objects(self, bucket, *, prefix="", maximum):
        return native.RehearsalAPI.list_objects(self, bucket, prefix=prefix, maximum=maximum)

    def journal_entries(self, generation=None):
        prefix = self.journal_prefix + ("" if generation is None else f"{generation:06d}-")
        return self.list_objects(self.names["backup"], prefix=prefix,
                                 maximum=native.MAX_CHECKPOINTS if generation is None else 2)

    def _key_allowed(self, method, bucket, key):
        if bucket == self.target["bucketName"]:
            return method == "GET" and matches(native.KEY, key)
        if bucket == self.names["objects"]:
            return method == "GET" and key in self.restore_keys
        if bucket != self.names["backup"]:
            return False
        prefixes = [self.archive_prefix]
        if self.contract.get("preservedG1"):
            prefixes.append("production/checkpoints/" + self.contract["preservedG1"]["checkpointId"] + "/")
        return (native.journal_key(self.journal_prefix, key) is not None
                or any(re.fullmatch(re.escape(prefix) + r"(?:manifest\.json|sql/[0-9]{1,3}\.sql|code/[0-9]{1,3}\.zip|blobs/[a-f0-9]{64})", key)
                       and (method == "GET" or prefix == self.archive_prefix) for prefix in prefixes))

    def r2(self, method, bucket, key, body=None):
        require(method in {"GET", "PUT"} and self._key_allowed(method, bucket, key))
        if method == "PUT":
            require(isinstance(body, bytes) and 0 < len(body) <= native.OBJECT_BYTES)
            self._conditional_put(bucket, key, body, {"custom": {}, "http": {}})
            return None
        require(body is None)
        objects = native.scoped_object_store(self, bucket)
        if objects is not None:
            value = objects.get(key, absent=True, limit=native.OBJECT_BYTES)
            if value == (None, None):
                raise RecoveryError("The scoped R2 object is absent.", http_status=404)
            return value
        request = Request(API_ORIGIN + self.root + "/r2/buckets/" + bucket + "/objects/" + quote(key, safe="/"),
                          headers={"Authorization": "Bearer " + self.token, "Accept": "application/octet-stream",
                                   "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"})
        _, headers, raw = native._response(self.opener, request, native.OBJECT_BYTES)
        return raw, headers.get("ETag") or headers.get("Etag")

    def object_or_none(self, bucket, key):
        try:
            return self.r2("GET", bucket, key)
        except RecoveryError as error:
            if error.http_status == 404:
                return None, None
            raise

    def _conditional_put(self, bucket, key, body, metadata):
        native.validate_metadata(metadata)
        require(isinstance(body, bytes) and 0 < len(body) <= native.OBJECT_BYTES)
        objects = native.scoped_object_store(self, bucket)
        if objects is not None:
            objects.put_once(key, body, metadata=native.scoped_metadata_headers(metadata))
            return
        if self.s3_access_key is None:
            try:
                result = self.json("GET", self.root + "/tokens/verify")
            except RecoveryError as error:
                require(error.http_status in {400, 401, 403, 404})
                result = self.json("GET", "/user/tokens/verify")
            require(isinstance(result, dict) and result.get("status") == "active" and matches(HEX_ID, result.get("id")))
            self.s3_access_key = result["id"]
        host = self.account_id + ".r2.cloudflarestorage.com"
        path = "/" + bucket + "/" + quote(key, safe="/-_.~")
        headers = native.signed_put_headers(host, path, self.s3_access_key, self.token, body, metadata, datetime.now(timezone.utc))
        try:
            with closing(HTTPSConnection(host, timeout=30)) as connection:
                connection.request("PUT", path, body=body, headers=headers)
                with closing(connection.getresponse()) as response:
                    if response.status != 200 or len(response.read(4097)) > 4096:
                        raise RecoveryError("A conditional recovery write was not confirmed.",
                                            uncertain=response.status in {200, 408} or response.status >= 500,
                                            http_status=response.status)
        except (OSError, ValueError, HTTPException):
            raise RecoveryError("A conditional recovery write was not confirmed.", uncertain=True) from None

    def put_restored_object(self, key, body, metadata):
        require(self.restore_bucket == self.names["objects"] and key in self.restore_keys and matches(native.KEY, key))
        self._conditional_put(self.restore_bucket, key, body, metadata)

    def rows(self, database_id, sql, parameters=()):
        return native.RehearsalAPI.rows(self, database_id, sql, parameters)

    def verify_backup(self):
        self.verify_bucket(self.target["backupBucketName"], self.target["backupBucketCreatedAt"])

    def verify_bucket(self, name, created_at):
        path = self.root + "/r2/buckets/" + name
        value = self.json("GET", path)
        identity = native.resource_identity("objects", value, name)
        require(identity == {"name": name, "createdAt": created_at, "jurisdiction": "default"})
        require(self.json("GET", path + "/domains/managed").get("enabled") is False
                and self.json("GET", path + "/domains/custom") in ([], {"domains": []}), "A recovery bucket is public.")
        rules = self.json("GET", path + "/lifecycle")
        require(isinstance(rules, dict) and isinstance(rules.get("rules"), list))
        require(all(isinstance(rule, dict) and (rule.get("enabled") is False or not any(
            field in rule for field in ("deleteObjectsTransition", "storageClassTransitions"))) for rule in rules["rules"]),
                "Recovery requires a bucket without enabled object deletion or storage-class transitions.")
        return identity

    def consumer_proof(self):
        """Read every Workers script/service environment; unknown or bounded inventory stops."""
        def get(path):
            method = getattr(self.worker_api, "json", None)
            if method is None:
                method = self.worker_api
            envelope = method("GET", path, envelope=True)
            require(isinstance(envelope, dict) and envelope.get("success") is True
                    and envelope.get("errors") in (None, []) and "result" in envelope)
            info = envelope.get("result_info", {})
            require(isinstance(info, dict) and set(info) <= {"page", "per_page", "count", "total_count", "total_pages",
                    "cursor", "next_page_token", "is_truncated"}
                    and info.get("cursor") in (None, "") and info.get("next_page_token") in (None, "")
                    and (info.get("is_truncated") is None or info.get("is_truncated") is False)
                    and all(type(info[key]) is int and info[key] >= 0
                            for key in ("page", "per_page", "count", "total_count", "total_pages") if key in info)
                    and info.get("page", 1) == 1 and info.get("total_pages", 1) <= 1
                    and ("per_page" not in info or info["per_page"] > 0),
                    "Consumer discovery was truncated; no recovery mutation is permitted.")
            result = envelope["result"]
            inventory = result if isinstance(result, list) else result.get("environments") if isinstance(result, dict) else None
            if isinstance(inventory, list):
                require(all(info[key] == len(inventory) for key in ("count", "total_count") if key in info)
                        and ("per_page" not in info or len(inventory) <= info["per_page"])
                        and (not inventory or info.get("total_pages", 1) == 1),
                        "Consumer inventory count differs; no recovery mutation is permitted.")
            return envelope["result"]

        self.consumer_stage = "services-list"
        services = get(self.root + "/workers/services")
        self.consumer_stage = "scripts-list"
        scripts = get(self.root + "/workers/scripts")
        require(isinstance(services, list) and isinstance(scripts, list)
                and len(services) < MAX_CONSUMERS and len(scripts) < MAX_CONSUMERS,
                "Consumer inventory exceeded its complete-scan bound.")
        checked = []

        def check(label, settings):
            require(isinstance(settings, dict) and isinstance(settings.get("bindings"), list))
            for binding in settings["bindings"]:
                require(isinstance(binding, dict) and isinstance(binding.get("type"), str))
                if binding["type"] == "d1":
                    database_ids = [binding[key] for key in ("id", "database_id") if binding.get(key) is not None]
                    require(database_ids and all(matches(UUID, value) for value in database_ids),
                            "A Worker D1 binding has an unrecognized identity.")
                    require(self.restore_id is None or self.restore_id not in database_ids,
                            "The independent restore D1 is bound to a Worker consumer.")
                if binding["type"] == "r2_bucket":
                    require(isinstance(binding.get("bucket_name"), str)
                            and re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", binding["bucket_name"]),
                            "A Worker R2 binding has an unrecognized identity.")
                    require(binding.get("bucket_name") != self.names["objects"],
                            "The independent restore R2 is bound to a Worker consumer.")
            checked.append([label, digest(canonical(settings["bindings"]))])

        script_ids = []
        for script in scripts:
            self.consumer_stage = "script-settings"
            require(isinstance(script, dict) and matches(SCRIPT, script.get("id")))
            name = script["id"]
            require(name not in script_ids)
            script_ids.append(name)
            check("script/" + name, get(self.root + "/workers/scripts/" + name + "/settings"))
        seen = set()
        for service in services:
            self.consumer_stage = "service-environments"
            require(isinstance(service, dict) and matches(SCRIPT, service.get("id")) and service["id"] not in seen)
            name = service["id"]
            seen.add(name)
            wrapper = get(self.root + "/workers/services/" + name + "/environments")
            require(isinstance(wrapper, dict) and {"id", "environments", "default_environment"} <= set(wrapper)
                    and set(wrapper) <= {"id", "environments", "default_environment", "created_on", "modified_on", "usage_model"}
                    and wrapper["id"] == name and isinstance(wrapper["environments"], list)
                    and 0 < len(wrapper["environments"]) < MAX_ENVIRONMENTS
                    and isinstance(wrapper["default_environment"], dict)
                    and matches(SCRIPT, wrapper["default_environment"].get("environment")),
                    "Consumer discovery requires the exact complete service-environments wrapper.")
            environments = wrapper["environments"]
            envs = set()
            for environment in environments:
                require(isinstance(environment, dict) and matches(SCRIPT, environment.get("environment"))
                        and environment["environment"] not in envs)
                env_name = environment["environment"]
                envs.add(env_name)
                self.consumer_stage = "service-settings"
                check("service/" + name + "/" + env_name, get(self.root + "/workers/services/" + name
                    + "/environments/" + env_name + "/settings"))
                self.consumer_stage = "service-environments"
            require(wrapper["default_environment"]["environment"] in envs,
                    "The default service environment is missing from the complete inventory.")
        self.consumer_stage = "complete"
        return {"checked": len(checked), "inventorySha256": digest(canonical(sorted(checked))), "consumers": 0}


class RecoveryJournal(native.Journal):
    """Append-only hash chain in the fixed private backup bucket, never source R2."""

    def load(self):
        keys = self.keys()
        require([native.journal_key(self.api.journal_prefix, key) for key in keys] == list(range(1, len(keys) + 1)),
                "The recovery journal has missing or conflicting checkpoints.")
        previous = None
        for generation, key in enumerate(keys, 1):
            raw, _ = self.api.object_or_none(self.api.names["backup"], key)
            checkpoint = native.parsed(raw, native.JOURNAL_BYTES)
            require(set(checkpoint) == {"generation", "previous", "value"} and canonical(checkpoint) == raw
                    and type(checkpoint["generation"]) is int and checkpoint["generation"] == generation
                    and checkpoint["previous"] == previous)
            value = checkpoint["value"]
            require(isinstance(value, dict) and value.get("version") == 1 and value.get("cohort") == self.api.cohort
                    and value.get("contractSha256") == contract_identity(self.api.contract))
            self.generation, self.key, self.raw, self.value = generation, key, raw, value
            previous = {"key": key, "sha256": digest(raw)}
        return self.value

    def save(self, value):
        require(not self.poisoned and self.generation < native.MAX_CHECKPOINTS)
        bucket, previous = self.api.names["backup"], None
        if self.key is not None:
            actual, _ = self.api.object_or_none(bucket, self.key)
            require(actual == self.raw and self.keys(self.generation) == [self.key])
            previous = {"key": self.key, "sha256": digest(self.raw)}
        generation = self.generation + 1
        require(self.keys(generation) == [])
        key = f"{self.api.journal_prefix}{generation:06d}-{token_hex(16)}.json"
        raw = canonical({"generation": generation, "previous": previous, "value": value})
        require(len(raw) <= native.JOURNAL_BYTES)
        if self.guard:
            self.guard()
        self.poisoned = True
        try:
            self.api.r2("PUT", bucket, key, raw)
        except RecoveryError:
            pass
        actual, _ = self.api.object_or_none(bucket, key)
        if actual != raw or self.keys(generation) != [key]:
            raise RecoveryError("A recovery journal write remains unconfirmed.", uncertain=True)
        self.poisoned = False
        self.generation, self.key, self.raw, self.value = generation, key, raw, deepcopy(value)


class RecoverySource:
    """Production source proof supplied by the same target-aware control tool."""

    def __init__(self, api, target, bundle_dir, manifest, verify_source, before_write):
        self.api, self.target, self.manifest, self.bundle_dir = api, target, manifest, bundle_dir
        self.verify_source, self.guard = verify_source, before_write
        self.migrations = migrations._load_migrations(bundle_dir, manifest)
        self.objects = migrations._objects(self.migrations, len(self.migrations), managed=True)
        self.tables = sorted(obj.name for obj in self.objects if obj.type == "table")
        self.schema_sha256 = native._schema_digest(self.objects)
        self.scope_sha256 = Target(target).digest
        self.current = None

    def observe(self):
        result = self.verify_source()
        require(isinstance(result, dict) and isinstance(result.get("release"), dict)
                and result.get("targetSha256") == self.scope_sha256
                and isinstance(result.get("control"), dict) and isinstance(result.get("work"), dict))
        control = result["control"]
        require(control.get("admission") == "closed" and control.get("workers") == "frozen"
                and integer(control.get("epoch"), 1)
                and "invocations" in result["work"] and all(type(count) is int and count == 0 for count in result["work"].values()),
                "Capture/recovery requires closed admission, frozen workers and zero unsettled work.")
        release = result["release"]
        require(matches(REVISION, release.get("revision")) and matches(DIGEST, release.get("moduleSha256"))
                and matches(UUID, release.get("versionId")))
        return {"release": release, "targetSha256": result["targetSha256"], "control": control,
                "work": result["work"], "terminal": result.get("terminal", {})}

    def verify(self, expected=None, *, capture=True):
        self.guard()
        self.current = self.observe()
        if capture:
            require(self.current["release"]["revision"] == self.manifest["revision"]
                    and self.current["release"]["moduleSha256"] == self.manifest["bundleSha256"],
                    "Capture artifact does not match the exact active source release.")
        pin = {"version": 1, "scopeSha256": self.scope_sha256, "schemaSha256": self.schema_sha256,
               "revision": self.manifest["revision"], "moduleSha256": self.manifest["bundleSha256"],
               "compatibilityDate": self.manifest["compatibilityDate"], "observed": self.current,
               "configurationSha256": Target(self.target).configuration_digest,
               "configuration": deepcopy(self.target)}
        require(expected is None or pin == expected, "The capture source changed after its checkpoint was prepared.")
        return pin

    def before_write(self):
        self.guard()
        require(self.current is not None and self.observe() == self.current,
                "The frozen source control, release or target changed before a recovery operation.")

    def quiet(self):
        self.before_write()
        return int(time.time())

    def schema(self, database_id=None):
        state, history = migrations._read_state(self.api, self.api.root + "/d1/database/" + (database_id or self.target["d1Id"]), self.migrations)
        require(state == "managed" and len(history) == len(self.migrations), "Recovery schema differs from the pinned artifact.")
        return history


class RecoveryEngine(native.Rehearsal):
    """Separate identity/control layer around bounded native restore mechanics."""

    resource_kinds = ("database", "objects")
    creation_window_seconds = 300

    def manifest(self):
        # A single action uses one immutable, fully checked manifest. The next
        # workflow invocation independently reads all private bytes again.
        if not hasattr(self, "_checked_manifest"):
            checked = super().manifest()
            document, _ = checked
            body, proof = load_code_archive(self.api, document, self.api.archive_prefix)
            require(proof["revision"] == self.source.manifest["revision"]
                    and body == self.source.archive_body, "Sealed recovery code differs from the independently verified source artifact.")
            self._checked_manifest = checked
        return self._checked_manifest

    def prepare(self, pin):
        require(self.journal.value is None)
        require("sessionId" not in self.api.contract, "A separate recovery session must use prepare-restore.")
        self.api.verify_backup()
        require(all(self.observe(kind) is None for kind in self.resource_kinds),
                "An independent recovery resource name is occupied; it cannot be adopted.")
        self.source.before_write()
        self.journal.save({"version": 1, "cohort": self.api.cohort,
            "contractSha256": contract_identity(self.api.contract), "scopeSha256": self.source.scope_sha256,
            "sourcePin": pin, "resources": {kind: {"pin": None, "intent": None} for kind in self.resource_kinds},
            "phase": "prepared", "export": None, "backup": None, "importState": None,
            "lease": {"owner": self.journal.owner, "until": int(time.time()) + native.LEASE_SECONDS}})

    def prepare_restore(self):
        contract = self.api.contract
        require(self.journal.value is None and contract["purpose"] == "recovery" and "sessionId" in contract)
        self.api.verify_backup()
        require(all(self.observe(kind) is None for kind in self.resource_kinds),
                "A new recovery-session target name is already occupied.")
        raw, _ = self.api.object_or_none(self.api.names["backup"], self.api.archive_prefix + "manifest.json")
        require(raw is not None and digest(raw) == contract["sourceManifestSha256"])
        document = native.parsed(raw, native.MANIFEST_BYTES)
        require(document.get("version") == 2 and document.get("schemaSha256") == self.source.schema_sha256
                and document.get("sourcePin", {}).get("scopeSha256") == self.source.scope_sha256
                and document["sourcePin"].get("revision") == self.source.manifest["revision"]
                and isinstance(document.get("summary"), dict) and isinstance(document.get("objects"), list))
        self.preserve_g1()
        self.source.before_write()
        self.journal.save({"version": 1, "cohort": self.api.cohort, "contractSha256": contract_identity(contract),
            "scopeSha256": self.source.scope_sha256, "sourcePin": document["sourcePin"],
            "resources": {kind: {"pin": None, "intent": None} for kind in self.resource_kinds},
            "phase": "captured", "export": {"state": "complete", "bookmark": document.get("sourceBookmark")},
            "backup": {"manifestSha256": digest(raw), "sqlSha256": document["sqlSha256"],
                "dataSha256": document["summary"]["dataSha256"], "rowCount": document["summary"]["rowCount"],
                "objectCount": len(document["objects"]), "publishedShareMetadataCount": native.published_share_metadata_count(document["objects"])},
            "importState": None, "lease": {"owner": self.journal.owner, "until": int(time.time()) + native.LEASE_SECONDS}})
        self.manifest()

    def verify_resources(self, *, all_required=False):
        self.api.verify_backup()
        super().verify_resources(all_required=all_required)
        if self.api.restore_bucket:
            pin = self.journal.value["resources"]["objects"]["pin"]
            self.api.verify_bucket(pin["name"], pin["createdAt"])

    def begin_export(self):
        require(self.journal.value["export"] is None,
                "An export initiation exists; it cannot be blindly repeated.")
        self.source.schema()
        observed = self.source.quiet()
        self.journal.update(export={"state": "started", "observedAt": observed})
        self.source.before_write()
        try:
            result = self.api.json("POST", self.api.source + "/export",
                                   {"output_format": "polling", "dump_options": {"compatibility": "d1"}})
        except RecoveryError:
            self.journal.update(export={"state": "unknown", "observedAt": observed})
            raise RecoveryError("Source export initiation is unknown; preserve the journal and do not initiate again.", uncertain=True) from None
        require(isinstance(result, dict))
        return self._poll_export(result)

    def capture(self):
        # Capture needs only the existing backup bucket; creating a recovery
        # destination is deliberately unnecessary for routine production backup.
        self.api.verify_backup()
        require(self.journal.value["backup"] is None, "This backup is already sealed; verify it instead.")
        require(self.source.verify(self.journal.value["sourcePin"]) == self.journal.value["sourcePin"])
        sql = self.directory / "source.sql"
        saved = self.journal.value["export"]
        if isinstance(saved, dict) and saved.get("state") == "sql-archived":
            self.load_sql(saved, sql)
        else:
            url = self.begin_export() if saved is None else self.resume_export()
            native.signed_transfer(url, download=sql)
        db, layout, summary = native.open_export(sql, self.source)
        try:
            self.source.before_write()
            require(native.remote_summary(self.api, self.api.target["d1Id"], layout) == summary,
                    "The source changed during export; this checkpoint was not sealed.")
            prefix, bucket = self.api.archive_prefix, self.api.names["backup"]
            parts = []
            with sql.open("rb") as stream:
                while block := stream.read(native.OBJECT_BYTES):
                    key = prefix + f"sql/{len(parts)}.sql"
                    self.immutable(bucket, key, block)
                    parts.append({"key": key, "bytes": len(block), "sha256": digest(block)})
            saved = {**self.journal.value["export"], "state": "sql-archived", "sqlParts": parts,
                     "sqlSha256": native.file_hash(sql)[1], "sqlMd5": native.file_hash(sql, "md5")[1],
                     "sqlBytes": sql.stat().st_size}
            saved.pop("url", None)
            self.journal.update(export=saved)

            def read_source(key):
                body, _ = self.api.object_or_none(self.api.target["bucketName"], key)
                require(body is not None)
                return body, self.object_metadata(self.api.target["bucketName"], key, len(body))

            entries = native.object_references(db, read_source,
                lambda _key, sha, body: self.immutable(bucket, prefix + "blobs/" + sha, body))
            code = self.source.archive_body
            code_proof = self.source.code_proof
            require(isinstance(code, bytes) and 0 < len(code) <= 16 * 1024 * 1024
                    and digest(code) == code_proof.get("archiveSha256"))
            code_parts = []
            for offset in range(0, len(code), native.OBJECT_BYTES):
                part = code[offset:offset + native.OBJECT_BYTES]
                key = prefix + f"code/{len(code_parts)}.zip"
                self.immutable(bucket, key, part)
                code_parts.append({"key": key, "bytes": len(part), "sha256": digest(part)})
            document = {"version": 2, "sourcePin": self.journal.value["sourcePin"],
                "schemaSha256": self.source.schema_sha256, "sourceBookmark": saved.get("bookmark"),
                "sqlSha256": saved["sqlSha256"], "sqlMd5": saved["sqlMd5"], "sqlBytes": saved["sqlBytes"],
                "sqlParts": parts, "objects": entries, "layout": layout, "summary": summary,
                "codeArtifact": {"proof": code_proof, "bytes": len(code), "sha256": digest(code), "parts": code_parts}}
            raw = canonical(document)
            require(len(raw) <= native.MANIFEST_BYTES)
            self.source.before_write()
            require(native.remote_summary(self.api, self.api.target["d1Id"], layout) == summary,
                    "The source changed during R2 capture; no complete checkpoint was published.")
            # All objects are fetched again: same closure, bytes and ownership metadata.
            require(native.object_references(db, read_source) == entries)
            self.source.before_write()
            self.immutable(bucket, prefix + "manifest.json", raw)
            self.journal.update(phase="captured", export={"state": "complete", "bookmark": saved.get("bookmark")},
                backup={"manifestSha256": digest(raw), "sqlSha256": document["sqlSha256"],
                        "dataSha256": summary["dataSha256"], "rowCount": summary["rowCount"],
                        "objectCount": len(entries), "publishedShareMetadataCount": native.published_share_metadata_count(entries)})
        finally:
            db.close()

    def preserve_g1(self):
        """Preserve current writes; never imply automatic incremental replay or switching."""
        pin = self.api.contract.get("preservedG1")
        require(pin is not None, "A recovery action requires a separate sealed current-state G1 checkpoint.")
        prefix = "production/checkpoints/" + pin["checkpointId"] + "/"
        raw, _ = self.api.object_or_none(self.api.names["backup"], prefix + "manifest.json")
        require(raw is not None and digest(raw) == pin["manifestSha256"])
        document = native.parsed(raw, native.MANIFEST_BYTES)
        require(document.get("version") == 2 and document.get("sourcePin", {}).get("scopeSha256") == self.source.scope_sha256
                and isinstance(document.get("layout"), dict) and isinstance(document.get("summary"), dict))
        load_code_archive(self.api, document, prefix)
        # Full SQL and every referenced object are verified even though only
        # current remote summaries decide whether the G1 is still current.
        require(integer(document.get("sqlBytes"), 1, native.SQL_BYTES)
                and isinstance(document.get("sqlParts"), list)
                and 1 <= len(document["sqlParts"]) <= native.SQL_BYTES // native.OBJECT_BYTES)
        total = 0
        h = sha256()
        for index, part in enumerate(document["sqlParts"]):
            require(isinstance(part, dict) and part.get("key") == prefix + f"sql/{index}.sql"
                    and integer(part.get("bytes"), 1, native.OBJECT_BYTES) and matches(DIGEST, part.get("sha256")))
            body, _ = self.api.object_or_none(self.api.names["backup"], part["key"])
            require(body is not None and len(body) == part["bytes"] and digest(body) == part["sha256"])
            total += len(body)
            require(total <= native.SQL_BYTES)
            h.update(body)
        require(total == document["sqlBytes"] and h.hexdigest() == document.get("sqlSha256"))
        require(isinstance(document.get("objects"), list) and len(document["objects"]) <= native.MAX_OBJECTS)
        keys, total = set(), 0
        for entry in document["objects"]:
            require(isinstance(entry, dict) and matches(native.KEY, entry.get("key")) and entry["key"] not in keys
                    and matches(DIGEST, entry.get("sha256")) and integer(entry.get("bytes"), 1, native.OBJECT_BYTES))
            native.validate_metadata(entry.get("metadata"))
            body, _ = self.api.object_or_none(self.api.names["backup"], prefix + "blobs/" + entry["sha256"])
            require(body is not None and len(body) == entry["bytes"] and digest(body) == entry["sha256"])
            source_body, _ = self.api.object_or_none(self.api.target["bucketName"], entry["key"])
            require(source_body == body and self.object_metadata(self.api.target["bucketName"], entry["key"], len(body)) == entry["metadata"],
                    "The current source object differs from preserved G1.")
            total += len(body)
            require(total <= native.TOTAL_OBJECT_BYTES)
            keys.add(entry["key"])
        self.source.before_write()
        require(native.remote_summary(self.api, self.api.target["d1Id"], document["layout"]) == document["summary"],
                "New writes are not preserved by G1; stop recovery and seal a fresh incident checkpoint.")
        # The configuration and exact observed frozen epoch are part of G1.
        require(document["sourcePin"].get("observed") == self.source.current,
                "The current source differs from preserved G1; no switch is permitted.")
        return {"manifestSha256": pin["manifestSha256"], "dataSha256": document["summary"].get("dataSha256"),
                "automaticReplay": False, "switchAuthorized": False}

    def before_target_write(self):
        self.source.before_write()
        if not getattr(self, "_source_data_checked", False):
            self.verify_preservation()
            self._source_data_checked = True
        if not getattr(self, "_consumer_checked", False):
            self.api.consumer_proof()
            self._consumer_checked = True

    def verify_preservation(self):
        self.source.before_write()
        if self.api.contract["purpose"] == "recovery":
            self.preserve_g1()
        else:
            require(self.source.current == self.journal.value["sourcePin"].get("observed"),
                    "The source advanced after this baseline; seal G1 and use an explicit recovery contract.")
            document, _ = self.manifest()
            require(native.remote_summary(self.api, self.api.target["d1Id"], document["layout"]) == document["summary"],
                    "The current source differs from this baseline; seal G1 before recovery.")

    def restore_objects(self):
        self.verify_resources(all_required=True)
        document, _ = self.manifest()
        self.before_target_write()
        entries = {entry["key"]: entry for entry in document["objects"]}
        actual = self.target_objects(entries)
        confirmed = self.journal.value.get("objectConfirmed", 0)
        require(integer(confirmed, 0, len(document["objects"])))
        # Resume confirmed ordinals without adding two more journal generations
        # per object. Their actual bytes/metadata are still independently read.
        for entry in document["objects"][:confirmed]:
            require(entry["key"] in actual)
            body, _ = self.api.object_or_none(self.api.names["objects"], entry["key"])
            require(body is not None and len(body) == entry["bytes"] and digest(body) == entry["sha256"])
        self.journal.update(phase="restoring-objects")
        for index in range(confirmed, len(document["objects"])):
            entry = document["objects"][index]
            self.journal.update(objectIntent=index)
            body, _ = self.api.object_or_none(self.api.names["backup"], self.api.archive_prefix + "blobs/" + entry["sha256"])
            require(body is not None and len(body) == entry["bytes"] and digest(body) == entry["sha256"])
            self.restore_object(entry, body)
            self.journal.update(objectIntent=None, objectConfirmed=index + 1)
        self.verify_object_bytes(document)
        self.verify_preservation()
        self.api.consumer_proof()
        self.journal.update(phase="objects-restored")

    def start_import(self):
        self.before_target_write()
        value = super().start_import()
        self.verify_preservation()
        self.api.consumer_proof()
        return value

    def read_restored_summary(self, document=None):
        self.api.consumer_proof()
        return super().read_restored_summary(document)

    def prepare_link_validation(self, document):
        # Native replay input generation is reusable, but production HMAC and
        # aggregate origins must never use the old fixed-isolation probes.
        super().prepare_link_validation(document)
        path = self.validation_directory / "input.json"
        payload = native.parsed(path.read_bytes(), 6 * native.SQL_BYTES + 1024 * 1024)
        t = self.source.target
        payload.update(version=3, origin="https://" + t["hostname"], targetSha256=self.source.scope_sha256,
            runtimeConfig=canonical({"botId": t["botId"], "botUsername": t["botUsername"],
                "botToken": t["botId"] + ":synthetic-recovery-never-network-0000000000",
                "webhookSecret": "synthetic-recovery-never-network-0000000000", "generation": t["generation"],
                "cutoverAt": 1, "activationSha256": self.source.scope_sha256}).decode())
        path.write_bytes(canonical(payload))

    def aggregate_link_probes(self, db, document):
        # All row ownership/authorization/revocation and hash capabilities are
        # included in complete data equality. Stored-share replay requires no
        # signing key. Live aggregate link probes are a separately explicit
        # target-aware validation action, never borrowed from isolated origin.
        return []


def run_action(action, engine, *, resource=None, identity_sha256=None):
    """Called by the protected production control workflow after its target gate."""
    require(action in {"inspect", "prepare", "prepare-restore", "create-database", "create-objects", "pin-resource", "capture",
                       "poll-export", "restore-objects", "start-import", "verify-backup", "verify-restore"})
    source, api, journal = engine.source, engine.api, engine.journal
    capture = action in {"prepare", "capture", "poll-export"}
    pin = source.verify(capture=capture)
    if action == "prepare":
        engine.prepare(pin)
    elif action == "prepare-restore":
        engine.prepare_restore()
    elif action == "inspect" and journal.value is None:
        return {"version": 1, "action": "inspect", "checkpointId": api.cohort, "phase": "not-prepared",
                "targetSha256": source.scope_sha256, "limits": LIMITS, "sourceRevision": pin["revision"],
                "resourceNamesAvailable": all(engine.observe(kind) is None for kind in engine.resource_kinds),
                "automaticReplay": False, "consumerSwitch": "not-authorized"}
    else:
        require(journal.value is not None and journal.value["scopeSha256"] == source.scope_sha256)
        require(journal.value["contractSha256"] == contract_identity(api.contract))
        engine.verify_resources()
        if capture:
            source.verify(journal.value["sourcePin"])
        if action == "create-database":
            engine.create("database")
        elif action == "create-objects":
            engine.create("objects")
        elif action == "pin-resource":
            engine.pin_resource(resource, identity_sha256)
        elif action in {"capture", "poll-export"}:
            engine.capture()
        elif action == "restore-objects":
            engine.restore_objects()
        elif action == "start-import":
            engine.start_import()
        elif action == "verify-backup":
            engine.manifest()
        elif action == "verify-restore":
            engine.verify_restore()
    backup = journal.value.get("backup") or {}
    result = {"version": 1, "action": action, "checkpointId": api.cohort, "phase": journal.value["phase"],
              "sessionId": api.contract.get("sessionId", api.cohort),
              "targetSha256": source.scope_sha256, "sourceRevision": journal.value["sourcePin"]["revision"],
              "backup": backup, "limits": LIMITS, "dataCoverage": "complete-d1-and-referenced-r2-closure",
              "automaticReplay": False, "consumerSwitch": "requires-separate-data-decision-and-approval"}
    if action == "verify-restore":
        result["consumers"] = api.consumer_proof()
        result["restoredDataSha256"] = journal.value.get("targetDataSha256")
    return result


def load_code_archive(api, document, prefix):
    """Read original CI ZIP bytes from the sealed private checkpoint, without Actions."""
    code = document.get("codeArtifact")
    require(isinstance(code, dict) and set(code) == {"proof", "bytes", "sha256", "parts"}
            and integer(code["bytes"], 1, 16 * 1024 * 1024) and matches(DIGEST, code["sha256"])
            and isinstance(code["parts"], list) and 1 <= len(code["parts"]) <= 32)
    proof = code["proof"]
    require(isinstance(proof, dict) and set(proof) == {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}
            and matches(REVISION, proof["revision"]) and matches(DIGEST, proof["archiveSha256"])
            and code["sha256"] == proof["archiveSha256"]
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", proof[key] or "") for key in ("runId", "runAttempt", "artifactId")))
    parts, size = [], 0
    for index, part in enumerate(code["parts"]):
        require(isinstance(part, dict) and set(part) == {"key", "bytes", "sha256"}
                and part["key"] == prefix + f"code/{index}.zip"
                and integer(part["bytes"], 1, native.OBJECT_BYTES) and matches(DIGEST, part["sha256"]))
        body, _ = api.object_or_none(api.names["backup"], part["key"])
        require(body is not None and len(body) == part["bytes"] and digest(body) == part["sha256"])
        size += len(body)
        require(size <= 16 * 1024 * 1024)
        parts.append(body)
    body = b"".join(parts)
    require(size == code["bytes"] and digest(body) == code["sha256"])
    return body, proof

"""Protected native D1/R2 rehearsal. Never restores, resets or deletes the source.

SQL, bookmarks, signed URLs and ownership pins stay in private R2 or runner temp.
Only hashes/counts leave this tool. Export temporarily blocks source D1 queries;
capture is for an already quiet, project-owned isolation environment only.
"""

from __future__ import annotations

from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
from email.utils import format_datetime, parsedate_to_datetime
from hashlib import md5, sha256
import hmac
from http.client import HTTPSConnection, HTTPException
import json
import math
import os
from pathlib import Path
import re
from secrets import token_hex
import sqlite3
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlencode, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

import d1_migrations as migrations
import prepare_isolation_artifact as artifact
from cloudflare_isolation import (
    API_ORIGIN, CloudflareClient, CloudflareError, DIGEST, HEX_ID, REVISION, TIMESTAMP, UUID,
    WORKER_NAME, _Isolation, _NoRedirect, _verify_health,
)


COHORT = re.compile(r"[a-f0-9]{32}")
KEY = re.compile(r"(?:subscriptions/[1-9][0-9]{0,15}/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}/(?:[0-9]{1,3}\.ndjson|manifest\.json)|private-shares/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\.txt)")
BOOKMARK = re.compile(r"[!-~]{1,512}")
PRIVATE_SHARE_PURPOSE = "telegram-private-share-creation-v1"
HTTP_FIELDS = {
    "cacheControl": "cache-control", "cacheExpiry": "expires", "contentDisposition": "content-disposition",
    "contentEncoding": "content-encoding", "contentLanguage": "content-language", "contentType": "content-type",
}
HTTP_FIELD_ALIASES = {re.sub(r"[A-Z]", lambda match: "_" + match[0].lower(), name): header
                      for name, header in HTTP_FIELDS.items()}
SQL_BYTES = 32 * 1024 * 1024
OBJECT_BYTES = 512 * 1024
MANIFEST_BYTES = 256 * 1024
JOURNAL_BYTES = 32 * 1024
MAX_OBJECTS = 512
MAX_CHECKPOINTS = 4096
TOTAL_OBJECT_BYTES = 256 * 1024 * 1024
MAX_ROWS = 20_000
MAX_CELL_BYTES = 2_000_000
MAX_SCHEMA_READ_BYTES = 200_000
MAX_SCHEMA_READ_STATEMENTS = 4
MAX_SAFE = 2**53 - 1
LEASE_SECONDS = 120
POLL_SECONDS = 120
READ_ERROR = "Native restore rehearsal could not be verified safely."
ACTIONS = {"verify", "prepare", "create-backup-bucket", "create-restore-db", "create-restore-bucket",
           "pin-resource", "capture", "poll-export", "restore-objects", "start-import", "verify-restore"}
RESOURCES = ("backup", "database", "objects")
LEGACY_CANDIDATE_PROFILE = "synthetic-legacy"
LEGACY_PATH_CANDIDATE_PROFILE = "synthetic-legacy-path"
LEGACY_EMPTY_CANDIDATE_PROFILE = "synthetic-legacy-empty"
LEGACY_PRIVATE_SHARE_CANDIDATE_PROFILE = "synthetic-legacy-private-shares"
LEGACY_TYPED_SHORT_CANDIDATE_PROFILE = "synthetic-legacy-typed-shorts"
LEGACY_MIXED_SHORT_CANDIDATE_PROFILE = "synthetic-legacy-mixed-shorts"
LEGACY_SELECTED_AGGREGATE_CANDIDATE_PROFILE = "synthetic-legacy-selected-aggregates"
LEGACY_TEMP_CANDIDATE_PROFILE = "synthetic-legacy-temp-nodes"
LEGACY_DYNAMIC_ALL_CANDIDATE_PROFILE = "synthetic-legacy-dynamic-all"
LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE = "synthetic-legacy-unified-shares"
LEGACY_GENERAL_AUTH_CANDIDATE_PROFILE = "synthetic-legacy-general-auth"
D1_ONLY_CANDIDATE_PROFILES = frozenset({LEGACY_TEMP_CANDIDATE_PROFILE, LEGACY_GENERAL_AUTH_CANDIDATE_PROFILE})
PINNED_TARGET_CANDIDATE_PROFILES = D1_ONLY_CANDIDATE_PROFILES | {
    LEGACY_DYNAMIC_ALL_CANDIDATE_PROFILE, LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE,
}
LEGACY_CANDIDATE_NAMES = {LEGACY_CANDIDATE_PROFILE: "legacy", LEGACY_PATH_CANDIDATE_PROFILE: "legacy-path",
                          LEGACY_EMPTY_CANDIDATE_PROFILE: "legacy-empty", LEGACY_PRIVATE_SHARE_CANDIDATE_PROFILE: "legacy-share",
                          LEGACY_TYPED_SHORT_CANDIDATE_PROFILE: "legacy-typed", LEGACY_MIXED_SHORT_CANDIDATE_PROFILE: "legacy-mixed",
                          LEGACY_SELECTED_AGGREGATE_CANDIDATE_PROFILE: "legacy-select",
                          LEGACY_TEMP_CANDIDATE_PROFILE: "legacy-temp",
                          LEGACY_DYNAMIC_ALL_CANDIDATE_PROFILE: "legacy-all",
                          LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE: "legacy-unified",
                          LEGACY_GENERAL_AUTH_CANDIDATE_PROFILE: "legacy-auth"}
ACCOUNT_SHA256 = "ffdbf3dd5d042c6edb68d7f628998a69a22320b0199775bfda9f97593136e508"


class RehearsalError(RuntimeError):
    def __init__(self, message=READ_ERROR, *, uncertain=False, http_status=None):
        super().__init__(message)
        self.uncertain = uncertain
        self.http_status = http_status


def require(value, message=READ_ERROR):
    if not value:
        raise RehearsalError(message)


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def integer(value, minimum=0, maximum=MAX_SAFE):
    return type(value) is int and minimum <= value <= maximum


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return sha256(value).hexdigest()


def parsed(raw, maximum):
    require(isinstance(raw, bytes) and len(raw) <= maximum)
    try:
        result = json.loads(raw.decode("utf-8"), object_pairs_hook=artifact._unique_json_object,
                            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
        require(isinstance(result, dict))
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise RehearsalError() from None


def names(cohort):
    require(matches(COHORT, cohort))
    return {"backup": "subs-bot-cf-backup-" + cohort[:16], "database": "subs-bot-cf-restore-" + cohort[:16],
            "objects": "subs-bot-cf-restore-" + cohort[:16]}


def expires_header(value):
    require(isinstance(value, str) and len(value) <= 64)
    try:
        try:
            date = datetime.fromisoformat(value)
        except ValueError:
            date = parsedate_to_datetime(value)
        require(date.tzinfo is not None and date.microsecond == 0)
        return format_datetime(date.astimezone(timezone.utc), usegmt=True)
    except (TypeError, ValueError, OverflowError):
        raise RehearsalError("An R2 expiry value cannot be restored exactly.") from None


def validate_metadata(metadata):
    require(isinstance(metadata, dict) and set(metadata) == {"custom", "http"})
    custom, http = metadata["custom"], metadata["http"]
    require(isinstance(custom, dict) and isinstance(http, dict))
    if custom:
        require(set(custom) == {"purpose", "receipt"} and custom["purpose"] == PRIVATE_SHARE_PURPOSE
                and matches(re.compile(r"[1-9][0-9]{0,15}"), custom["receipt"]) and int(custom["receipt"]) <= MAX_SAFE,
                "An R2 object has unsupported custom metadata.")
    require(set(http) <= set(HTTP_FIELDS.values()))
    for name, value in http.items():
        require(matches(re.compile(r"[ -~]{1,512}"), value) and value == value.strip(),
                "An R2 HTTP metadata value cannot be restored exactly.")
        if name == "expires":
            require(expires_header(value) == value)
    require(len(canonical(metadata)) <= 2048, "An R2 object's metadata exceeds the rehearsal bound.")
    return metadata


def listed_metadata(row):
    require(row.get("storage_class") == "Standard", "The rehearsal requires explicitly verified Standard R2 storage.")
    require(row.get("ssec") is None or row.get("ssec") is False, "The rehearsal cannot restore SSE-C objects.")
    require("customMetadata" not in row and "httpMetadata" not in row)
    custom, raw_http = row.get("custom_metadata"), row.get("http_metadata")
    require(raw_http is None or isinstance(raw_http, dict))
    http = {}
    seen = set()
    for name, value in (raw_http or {}).items():
        header = HTTP_FIELDS.get(name) or HTTP_FIELD_ALIASES.get(name)
        require(header is not None and header not in seen, "An R2 object has unknown or duplicate HTTP metadata.")
        seen.add(header)
        if value is not None:
            http[header] = expires_header(value) if header == "expires" else value
    return validate_metadata({"custom": {} if custom is None else custom, "http": http})


def signed_put_headers(host, path, token_id, token, raw, metadata, now):
    """One S3 SigV4 PUT using the verified account token's derived key."""
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    day = timestamp[:8]
    payload_sha = digest(raw)
    headers = {"host": host, "content-length": str(len(raw)), "if-none-match": "*",
               "x-amz-date": timestamp, "x-amz-content-sha256": payload_sha, "x-amz-storage-class": "STANDARD", **metadata["http"],
               **{f"x-amz-meta-{name}": value for name, value in metadata["custom"].items()}}
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{' '.join(headers[name].split())}\n" for name in sorted(headers))
    canonical_request = "\n".join(("PUT", path, "", canonical_headers, signed_headers, payload_sha))
    scope = f"{day}/auto/s3/aws4_request"
    string_to_sign = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, digest(canonical_request.encode("ascii"))))
    key = ("AWS4" + digest(token.encode("ascii"))).encode("ascii")
    for part in (day, "auto", "s3", "aws4_request"):
        key = hmac.digest(key, part.encode("ascii"), "sha256")
    signature = hmac.digest(key, string_to_sign.encode("ascii"), "sha256").hex()
    headers["Authorization"] = (f"AWS4-HMAC-SHA256 Credential={token_id}/{scope}, "
                                f"SignedHeaders={signed_headers}, Signature={signature}")
    return headers


def _response(opener, request, maximum):
    try:
        with opener.open(request, timeout=30) as response:
            body = response.read(maximum + 1)
            require(len(body) <= maximum)
            return response.status, dict(response.headers.items()), body
    except HTTPError as error:
        status = error.code
        error.close()
        raise RehearsalError("Native rehearsal API request was not confirmed.", uncertain=request.method != "GET" and
                             (status == 408 or status >= 500), http_status=status) from None
    except (OSError, ValueError, HTTPException):
        raise RehearsalError("Native rehearsal API request was not confirmed.", uncertain=request.method != "GET") from None


class RehearsalAPI:
    """Fixed account/resource allowlist; no DELETE, reset, Worker write or Time Travel restore."""

    def __init__(self, target, token, cohort, *, profile="native"):
        require(isinstance(target, dict) and matches(HEX_ID, target.get("accountId")) and matches(UUID, target.get("d1Id")))
        require(digest(target["accountId"].encode("ascii")) == ACCOUNT_SHA256)
        require(matches(re.compile(r"[A-Za-z0-9_.-]{1,4096}"), token))
        require((profile == "native" or profile in LEGACY_CANDIDATE_NAMES) and matches(COHORT, cohort))
        self.target, self.token, self.cohort = target, token, cohort
        self.profile = profile
        self.account_id = target["accountId"]
        self.names = names(cohort)
        self.root = "/accounts/" + target["accountId"]
        self.source = self.root + "/d1/database/" + target["d1Id"]
        self.journal_prefix = f"maintenance/native-restore/{cohort}/journal/"
        self.archive_prefix = f"rehearsals/{cohort}/"
        if profile in LEGACY_CANDIDATE_NAMES:
            label = LEGACY_CANDIDATE_NAMES[profile]
            self.names = {"database": f"subs-bot-cf-{label}-db-{cohort}"}
            if profile not in D1_ONLY_CANDIDATE_PROFILES:
                self.names["objects"] = f"subs-bot-cf-{label}-r2-{cohort}"
            self.journal_prefix = f"maintenance/{label}-candidate/{cohort}/journal/"
        self.buckets = {WORKER_NAME, *(self.names[kind] for kind in self.names if kind != "database")}
        self.databases = {target["d1Id"]}
        self.restore_id = None
        self.restore_keys = set()
        self.restore_bucket = None
        self.s3_access_key = None
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, method, path, payload=None):
        return self.json(method, path, payload)

    def allow_restore(self, database_id=None, keys=None, object_bucket=None):
        if self.profile in D1_ONLY_CANDIDATE_PROFILES:
            require(object_bucket is None and (keys is None or not keys))
        if database_id is not None:
            require(matches(UUID, database_id) and database_id != self.target["d1Id"]
                    and (self.profile not in PINNED_TARGET_CANDIDATE_PROFILES
                         or database_id in self.databases))
            self.databases.add(database_id)
            self.restore_id = database_id
        if keys is not None:
            require(len(keys) <= MAX_OBJECTS and all(matches(KEY, key) for key in keys))
            if self.profile == LEGACY_DYNAMIC_ALL_CANDIDATE_PROFILE:
                require(all(key.startswith("subscriptions/") for key in keys))
            if self.profile == LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE:
                require(len(set(keys)) == len(keys) == 10
                        and sum(key.startswith("subscriptions/") for key in keys) == 8
                        and sum(key.startswith("private-shares/") for key in keys) == 2)
            self.restore_keys = set(keys)
        if object_bucket is not None:
            require(object_bucket == self.names["objects"])
            self.restore_bucket = object_bucket

    def json(self, method, path, payload=None, *, envelope=False):
        require(method in {"GET", "POST"} and path.startswith(self.root + "/") and not any(c in path for c in ("#", "\\", "\n", "\r")))
        route = path.partition("?")[0]
        if self.profile in D1_ONLY_CANDIDATE_PROFILES:
            if method == "GET" and route == self.root + "/d1/database":
                require(path == route + "?" + urlencode({"name": self.names["database"], "per_page": 100}))
            elif method == "GET":
                require(route not in {self.root + "/r2/buckets", self.root + "/tokens/verify"})
            else:
                require(path == route)
        if self.profile in (LEGACY_DYNAMIC_ALL_CANDIDATE_PROFILE, LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE):
            if method == "GET" and route == self.root + "/d1/database":
                require(path == route + "?" + urlencode({"name": self.names["database"], "per_page": 100}))
            elif method == "GET" and route == self.root + "/r2/buckets":
                require(path == route + "?" + urlencode({"name_contains": self.names["objects"], "per_page": 100}))
            elif method == "POST" or route == self.root + "/tokens/verify":
                require(path == route)
        if method == "POST":
            if route == self.root + "/d1/database":
                require(payload == {"name": self.names["database"], "read_replication": {"mode": "disabled"}})
            elif route == self.root + "/r2/buckets":
                require(any(payload == {"name": self.names[kind], "storageClass": "Standard"}
                            for kind in self.names if kind != "database"))
            elif route.endswith("/query"):
                databases = self.databases if self.profile == "native" else {self.restore_id}
                require(route in {self.root + f"/d1/database/{value}/query" for value in databases if value is not None})
                require(isinstance(payload, dict) and set(payload) <= {"sql", "params"} and isinstance(payload.get("sql"), str))
                params = payload.get("params", [])
                require(isinstance(params, list) and all(isinstance(value, str) for value in params))
                sql = payload["sql"].strip()
                require((len(sql.encode()) <= migrations.MAX_D1_STATEMENT_BYTES and readonly_sql(sql))
                        or ("params" not in payload and readonly_schema_batch(payload["sql"]) is not None))
            elif route == self.source + "/export" and self.profile == "native":
                require(isinstance(payload, dict) and set(payload) <= {"output_format", "dump_options", "current_bookmark"}
                        and payload.get("output_format") == "polling" and payload.get("dump_options") == {"compatibility": "d1"})
                require("current_bookmark" not in payload or matches(BOOKMARK, payload["current_bookmark"]))
            else:
                require(self.restore_id is not None and route == self.root + f"/d1/database/{self.restore_id}/import")
                require(isinstance(payload, dict) and payload.get("action") in {"init", "ingest", "poll"})
                allowed = {"init": {"action", "etag"}, "ingest": {"action", "etag", "filename"}, "poll": {"action", "current_bookmark"}}
                require(set(payload) == allowed[payload["action"]])
                if "etag" in payload:
                    require(matches(re.compile(r"[a-f0-9]{32}"), payload["etag"]))
                if "current_bookmark" in payload:
                    require(matches(BOOKMARK, payload["current_bookmark"]))
                if "filename" in payload:
                    require(matches(BOOKMARK, payload["filename"]))
        else:
            allowed = route in {self.root + "/d1/database", self.root + "/r2/buckets", self.root + "/tokens/verify"}
            allowed = allowed or any(route == self.root + f"/d1/database/{value}" for value in self.databases)
            allowed = allowed or any(route in {self.root + f"/r2/buckets/{bucket}" + suffix for suffix in
                ("", "/domains/managed", "/domains/custom", "/objects")} for bucket in self.buckets)
            require(allowed and payload is None)
            if self.profile in LEGACY_CANDIDATE_NAMES and route == self.root + f"/r2/buckets/{WORKER_NAME}/objects":
                query = parse_qs(urlsplit(path).query, max_num_fields=3)
                prefix = query.get("prefix", [])
                require(len(prefix) == 1 and re.fullmatch(re.escape(self.journal_prefix) + r"(?:[0-9]{6}-)?", prefix[0]))
                if self.profile in PINNED_TARGET_CANDIDATE_PROFILES:
                    require(set(query) <= {"prefix", "per_page", "cursor"}
                            and all(len(values) == 1 for values in query.values()))
            elif self.profile == LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE:
                if route == self.root + f"/r2/buckets/{self.names['objects']}/objects":
                    query = parse_qs(urlsplit(path).query, keep_blank_values=True, max_num_fields=3)
                    prefix = query.get("prefix", [])
                    require(self.restore_bucket == self.names["objects"] and self.restore_keys
                            and len(prefix) == 1 and (prefix[0] == "" or prefix[0] in self.restore_keys)
                            and set(query) <= {"prefix", "per_page", "cursor"}
                            and all(len(values) == 1 for values in query.values()))
                elif route not in {self.root + "/d1/database", self.root + "/r2/buckets"}:
                    require(path == route)
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json", "Cache-Control": "no-cache",
                   "cf-r2-jurisdiction": "default"}
        body = None if payload is None else canonical(payload)
        if body is not None:
            headers["Content-Type"] = "application/json"
        _, _, raw = _response(self.opener, Request(API_ORIGIN + path, data=body, headers=headers, method=method), 8 * 1024 * 1024)
        value = parsed(raw, 8 * 1024 * 1024)
        require(value.get("success") is True and value.get("errors") in (None, []) and "result" in value)
        return value if envelope else value["result"]

    def journal_entries(self, generation=None):
        return self.list_objects(WORKER_NAME, prefix=self.journal_prefix + ("" if generation is None else f"{generation:06d}-"),
                                 maximum=MAX_CHECKPOINTS if generation is None else 2)

    def list_objects(self, bucket, *, prefix="", maximum):
        require(bucket in self.buckets)
        base = self.root + f"/r2/buckets/{bucket}/objects?"
        rows, cursors, cursor = [], set(), None
        while True:
            query = {"prefix": prefix, "per_page": min(maximum, 1000)}
            if cursor is not None:
                query["cursor"] = cursor
            page = self.json("GET", base + urlencode(query), envelope=True)
            result, info = page.get("result"), page.get("result_info", {})
            require(isinstance(result, list) and isinstance(info, dict) and all(
                isinstance(row, dict) and isinstance(row.get("key"), str) and row["key"].startswith(prefix) for row in result))
            rows.extend(result)
            require(len(rows) <= maximum)
            cursor = info.get("cursor")
            truncated = info.get("is_truncated")
            require((truncated is None or type(truncated) is bool)
                    and (cursor is None or isinstance(cursor, str)) and not info.get("next_page_token"))
            if not cursor:
                require(truncated is not True, "R2 object listing was truncated without a continuation cursor.")
                return rows
            require(isinstance(cursor, str) and len(cursor) <= 4096 and result and cursor not in cursors and len(cursors) < 32)
            cursors.add(cursor)

    def r2(self, method, bucket, key, body=None):
        require(method in {"GET", "PUT"} and bucket in self.buckets)
        if bucket == WORKER_NAME:
            require(journal_key(self.journal_prefix, key) is not None
                    or self.profile == "native" and method == "GET" and matches(KEY, key))
        elif bucket == self.names.get("backup"):
            require(key == self.archive_prefix + "manifest.json" or re.fullmatch(re.escape(self.archive_prefix) + r"(?:sql/[0-9]{1,3}\.sql|blobs/[a-f0-9]{64})", key))
        else:
            require(method == "GET" and key in self.restore_keys)
            if self.profile == LEGACY_UNIFIED_SHARE_CANDIDATE_PROFILE:
                require(self.restore_bucket == bucket)
        require(method != "GET" or body is None)
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/octet-stream",
                   "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"}
        if method == "PUT":
            require(isinstance(body, bytes) and len(body) <= max(OBJECT_BYTES, MANIFEST_BYTES))
            # Advisory defense only: the management endpoint does not document
            # conditional PUT. All writes use protected concurrency and readback.
            headers.update({"Content-Type": "application/octet-stream", "If-None-Match": "*"})
        request = Request(API_ORIGIN + self.root + f"/r2/buckets/{bucket}/objects/" + quote(key, safe="/"),
                          data=body, headers=headers, method=method)
        _, returned, raw = _response(self.opener, request, OBJECT_BYTES)
        if method == "GET":
            return raw, returned.get("ETag") or returned.get("Etag")
        if raw:
            require(parsed(raw, OBJECT_BYTES).get("success") is True)
        return None

    def object_or_none(self, bucket, key):
        try:
            return self.r2("GET", bucket, key)
        except RehearsalError as error:
            if getattr(error, "http_status", None) == 404:
                return None, None
            raise

    def put_restored_object(self, key, body, metadata):
        require("objects" in self.names and self.restore_bucket == self.names["objects"]
                and key in self.restore_keys and matches(KEY, key))
        require(isinstance(body, bytes) and 0 < len(body) <= OBJECT_BYTES)
        validate_metadata(metadata)
        if self.s3_access_key is None:
            result = self.json("GET", self.root + "/tokens/verify")
            require(isinstance(result, dict) and result.get("status") == "active" and matches(HEX_ID, result.get("id")),
                    "The existing isolation data token could not be verified for R2 signing.")
            self.s3_access_key = result["id"]
        host = f"{self.account_id}.r2.cloudflarestorage.com"
        path = "/" + self.restore_bucket + "/" + quote(key, safe="/-_.~")
        headers = signed_put_headers(host, path, self.s3_access_key, self.token, body, metadata, datetime.now(timezone.utc))
        try:
            # A single TLS request to the pinned account. No proxy, redirects or retry.
            with closing(HTTPSConnection(host, timeout=30)) as connection:
                connection.request("PUT", path, body=body, headers=headers)
                with closing(connection.getresponse()) as response:
                    if response.status != 200 or len(response.read(4097)) > 4096:
                        raise RehearsalError("The conditional R2 restore write was not confirmed.",
                            uncertain=response.status in (200, 408) or response.status >= 500, http_status=response.status)
        except (OSError, ValueError, HTTPException):
            raise RehearsalError("The conditional R2 restore write was not confirmed.", uncertain=True) from None

    def rows(self, database_id, sql, parameters=()):
        require(database_id in self.databases)
        require(all(isinstance(value, str) or integer(value, -MAX_SAFE) for value in parameters))
        result = self.json("POST", self.root + f"/d1/database/{database_id}/query",
                           {"sql": sql, "params": [str(value) for value in parameters]})
        require(isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict)
                and result[0].get("success") is True and isinstance(result[0].get("results"), list))
        return result[0]["results"]


def signed_transfer(url, *, download=None, upload=None, expected_md5=None):
    """Presigned R2 transfers never receive Cloudflare or GitHub credentials."""
    require(isinstance(url, str) and len(url) <= 16384 and re.search(r"[\x00-\x20\x7f\\]", url) is None)
    try:
        parsed_url = urlsplit(url)
        require(parsed_url.scheme == "https" and parsed_url.hostname is not None
                and parsed_url.hostname.endswith(".r2.cloudflarestorage.com") and parsed_url.port in (None, 443)
                and parsed_url.username is None and parsed_url.password is None and not parsed_url.fragment)
    except ValueError:
        raise RehearsalError() from None
    require((download is None) != (upload is None))
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        if download is not None:
            request = Request(url, headers={"Accept-Encoding": "identity"})
            deadline = time.monotonic() + POLL_SECONDS
            with opener.open(request, timeout=30) as response, private_file(download) as output:
                require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
                total = 0
                while block := response.read(64 * 1024):
                    total += len(block)
                    require(total <= SQL_BYTES and time.monotonic() < deadline)
                    output.write(block)
            require(total > 0)
            return
        require(upload.is_file() and not upload.is_symlink() and 0 < upload.stat().st_size <= SQL_BYTES)
        with upload.open("rb") as body:
            request = Request(url, data=body, method="PUT", headers={"Content-Length": str(upload.stat().st_size),
                "Content-Type": "application/octet-stream", "Accept-Encoding": "identity"})
            with opener.open(request, timeout=30) as response:
                require(response.status == 200 and response.headers.get("ETag", "").strip('"') == expected_md5)
    except (OSError, ValueError, HTTPException, HTTPError):
        raise RehearsalError("Private D1 signed transfer was not confirmed.", uncertain=upload is not None) from None


def private_file(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")


def file_hash(path, algorithm="sha256"):
    require(path.is_file() and not path.is_symlink())
    value = sha256() if algorithm == "sha256" else md5(usedforsecurity=False)
    size = 0
    with path.open("rb") as file:
        while block := file.read(64 * 1024):
            value.update(block)
            size += len(block)
            require(size <= SQL_BYTES)
    return size, value.hexdigest()


def journal_key(prefix, key):
    if not isinstance(key, str) or not key.startswith(prefix):
        return None
    match = re.fullmatch(r"([0-9]{6})-[a-f0-9]{32}\.json", key[len(prefix):])
    return int(match[1]) if match and integer(int(match[1]), 1, MAX_CHECKPOINTS) else None


class Journal:
    """Append-only intent log, serialized by the protected workflow concurrency group."""

    def __init__(self, api, owner, *, guard=None):
        self.api, self.owner = api, owner
        self.guard = guard
        self.value = None
        self.generation = 0
        self.key = self.raw = None
        self.poisoned = False

    def keys(self, generation=None):
        keys = [entry["key"] for entry in self.api.journal_entries(generation)]
        require(all(journal_key(self.api.journal_prefix, key) is not None for key in keys))
        return sorted(keys)

    def load(self):
        keys = self.keys()
        require([journal_key(self.api.journal_prefix, key) for key in keys] == list(range(1, len(keys) + 1)),
                "Private rehearsal journal contains conflicting or missing checkpoints.")
        if not keys:
            return None
        self.generation, self.key = len(keys), keys[-1]
        self.raw, _ = self.api.object_or_none(WORKER_NAME, self.key)
        checkpoint = parsed(self.raw, JOURNAL_BYTES)
        require(set(checkpoint) == {"generation", "previous", "value"} and canonical(checkpoint) == self.raw
                and type(checkpoint["generation"]) is int and checkpoint["generation"] == self.generation)
        if self.generation == 1:
            require(checkpoint["previous"] is None)
        else:
            predecessor, _ = self.api.object_or_none(WORKER_NAME, keys[-2])
            require(predecessor is not None and checkpoint["previous"] == {"key": keys[-2], "sha256": digest(predecessor)})
        self.value = checkpoint["value"]
        require(isinstance(self.value, dict) and self.value.get("version") == 1 and self.value.get("cohort") == self.api.cohort)
        return self.value

    def save(self, value):
        require(not self.poisoned and self.generation < MAX_CHECKPOINTS)
        previous = None
        if self.key is not None:
            actual, _ = self.api.object_or_none(WORKER_NAME, self.key)
            require(actual == self.raw and self.keys(self.generation) == [self.key],
                    "Private rehearsal journal predecessor changed.")
            previous = {"key": self.key, "sha256": digest(self.raw)}
        generation = self.generation + 1
        require(self.keys(generation) == [], "Private rehearsal journal advanced unexpectedly.")
        key = f"{self.api.journal_prefix}{generation:06d}-{token_hex(16)}.json"
        expected = canonical({"generation": generation, "previous": previous, "value": value})
        require(len(expected) <= JOURNAL_BYTES and self.api.object_or_none(WORKER_NAME, key)[0] is None)
        if self.guard is not None:
            self.guard()
        # From this point no subsequent checkpoint is allowed until exact
        # readback. Losing the runner cannot authorize the operation it fenced.
        self.poisoned = True
        try:
            self.api.r2("PUT", WORKER_NAME, key, expected)
        except RehearsalError:
            pass
        actual, _ = self.api.object_or_none(WORKER_NAME, key)
        if actual != expected or self.keys(generation) != [key]:
            raise RehearsalError("Private rehearsal journal write remains unconfirmed.", uncertain=True)
        self.poisoned = False
        self.generation, self.key, self.raw, self.value = generation, key, expected, deepcopy(value)

    def claim(self):
        require(self.value is not None)
        lease = self.value.get("lease") or {}
        require(lease.get("owner") in (None, self.owner) or lease.get("until", 0) <= int(time.time()),
                "Private rehearsal journal is leased by another run.")
        value = deepcopy(self.value)
        value["lease"] = {"owner": self.owner, "until": int(time.time()) + LEASE_SECONDS}
        self.save(value)

    def update(self, **values):
        require(self.value is not None and self.value.get("lease", {}).get("owner") == self.owner)
        value = deepcopy(self.value)
        value.update(values)
        value["lease"] = {"owner": self.owner, "until": int(time.time()) + LEASE_SECONDS}
        self.save(value)

    def release(self):
        if not self.poisoned and self.value is not None and self.value.get("lease", {}).get("owner") == self.owner:
            value = deepcopy(self.value)
            value["lease"] = {"owner": None, "until": 0}
            self.save(value)


def readonly_sql(sql, *, schema_check=False):
    if not isinstance(sql, str):
        return False
    sql = sql.strip()
    if schema_check:
        prefix, suffix = "SELECT (", ") AS matches"
        if not sql.startswith(prefix) or not sql.endswith(suffix):
            return False
        sql = sql[len(prefix):-len(suffix)]
        if not sql.strip():
            return False
    elif not (sql.startswith("SELECT ") or re.fullmatch(r"PRAGMA (?:table_list|table_info|table_xinfo|index_list|index_xinfo|foreign_key_check|quick_check)(?:\([^;\r\n]*\))?", sql)):
        return False
    quote_char = None
    offset = depth = 0
    while offset < len(sql):
        char = sql[offset]
        if quote_char:
            if char == quote_char:
                if offset + 1 < len(sql) and sql[offset + 1] == quote_char:
                    offset += 1
                else:
                    quote_char = None
        elif char in ("'", '"'):
            quote_char = char
        elif char == ";" or sql[offset:offset + 2] in ("--", "/*"):
            return False
        elif schema_check and char in "?@:$`[]":
            return False
        elif schema_check and char == "(":
            depth += 1
        elif schema_check and char == ")":
            if depth == 0:
                return False
            depth -= 1
        offset += 1
    return quote_char is None and depth == 0


def readonly_schema_batch(sql: str) -> tuple[str, ...] | None:
    """Accept only the canonical multi-SELECT produced by the exact schema check."""
    # Bound repeated SQLite tokenization even when semicolons occur inside literals.
    if len(sql.encode("utf-8")) > MAX_SCHEMA_READ_BYTES or sql.count(";") > 64 or "\0" in sql or "\r" in sql:
        return None
    try:
        statements = tuple(migrations._statements(sql))
    except migrations.MigrationError:
        return None
    if (not 2 <= len(statements) <= MAX_SCHEMA_READ_STATEMENTS or ";\n".join(statements) + ";" != sql
            or any(len(statement.encode("utf-8")) >= migrations.MAX_D1_STATEMENT_BYTES
                   or not readonly_sql(statement, schema_check=True) for statement in statements)):
        return None
    return statements


def _identifier(value):
    require(isinstance(value, str) and re.fullmatch(r"[a-z][a-z0-9_]*", value))
    return '"' + value + '"'


def _schema_digest(objects):
    return digest(canonical([[obj.type, obj.name, obj.table, obj.sql] for obj in objects]))


class Source:
    def __init__(self, api, worker_api, target, bundle_dir, manifest, guard):
        self.api, self.target, self.manifest, self.guard_main = api, target, manifest, guard
        self.bundle_dir = bundle_dir
        self.scope = _Isolation(worker_api, api, target)
        self.migrations = migrations._load_migrations(bundle_dir, manifest)
        self.objects = migrations._objects(self.migrations, len(self.migrations), managed=True)
        self.tables = sorted(obj.name for obj in self.objects if obj.type == "table")
        self.schema_sha256 = _schema_digest(self.objects)
        self.scope_sha256 = digest(canonical(target))
        self.config = self.active = self.version = None

    def verify(self, expected=None):
        self.guard_main()
        config = self.scope.worker_config()
        self.scope.verify_resources()
        active = self.scope.active()
        version = self.scope.version(active.version)
        require(version.revision == self.manifest["revision"] and version.digest == self.manifest["bundleSha256"]
                and version.compatibility == self.manifest["compatibilityDate"] and self.scope.cron_enabled())
        pin = {"revision": version.revision, "versionId": active.version, "moduleSha256": version.digest,
               "compatibilityDate": version.compatibility, "scopeSha256": self.scope_sha256,
               "schemaSha256": self.schema_sha256, "telegramConfigSha256": version.telegram_config_sha256,
               "aggregateKeySha256": version.telegram_aggregate_key_sha256}
        require(expected is None or pin == expected, "The source release or ownership changed after rehearsal preparation.")
        self.config, self.active, self.version = config, active, version
        _verify_health(version.revision)
        return pin

    def before_write(self):
        require(self.scope.active() == self.active and self.scope.worker_config() == self.config
                and self.scope.version(self.active.version) == self.version and self.scope.cron_enabled(),
                "The source release changed before a rehearsal write.")
        self.guard_main()

    def schema(self, database_id=None):
        path = self.api.root + "/d1/database/" + (database_id or self.target["d1Id"])
        state, history = migrations._read_state(self.api, path, self.migrations)
        require(state == "managed" and len(history) == len(self.migrations))
        return history

    def quiet(self):
        rows = self.api.rows(self.target["d1Id"], "SELECT " + quiet_expression(self.tables) + " AS quiet, unixepoch() AS observed_at")
        require(len(rows) == 1 and rows[0].get("quiet") == 1 and integer(rows[0].get("observed_at"), 1),
                "The isolated source is not quiet; finish interactions and durable work before export.")
        return rows[0]["observed_at"]


def quiet_expression(tables, observed_at=None):
    require(observed_at is None or integer(observed_at, 1))
    epoch = "unixepoch()" if observed_at is None else str(observed_at)
    conditions = [
        "NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE state IN ('pending','leased','sending'))",
        "NOT EXISTS(SELECT 1 FROM telegram_document_jobs WHERE state IN ('pending','leased'))",
        "NOT EXISTS(SELECT 1 FROM telegram_document_stages)",
        "NOT EXISTS(SELECT 1 FROM telegram_aggregate_slots WHERE code_sha256 IS NOT NULL)",
    ]
    waits = ["telegram_rename_wait", "telegram_view_ticket", "telegram_lifecycle_ticket"]
    for table in ("subscription_provider_jobs", "telegram_provider_jobs"):
        if table in tables:
            conditions.append(f"NOT EXISTS(SELECT 1 FROM {table} WHERE state IN ('pending','leased'))")
    if "telegram_inline_search_receipts" in tables:
        conditions.append(f"NOT EXISTS(SELECT 1 FROM telegram_inline_search_receipts WHERE state IN ('preflight','sending') AND lease_until > {epoch})")
    if "telegram_provider_batches" in tables:
        conditions.append("NOT EXISTS(SELECT 1 FROM telegram_provider_batches WHERE finished_at IS NULL)")
    if "telegram_provider_batch_jobs" in tables:
        conditions.append("NOT EXISTS(SELECT 1 FROM telegram_provider_batch_jobs WHERE state IN ('waiting','pending','leased'))")
    if "telegram_provider_batch_interactions" in tables:
        waits.append("telegram_provider_batch_interactions")
        if "telegram_provider_batches" in tables:
            conditions.append(f"""NOT EXISTS(SELECT 1 FROM telegram_provider_batches AS batch
                WHERE batch.finished_at>{epoch}-900 AND NOT EXISTS(
                    SELECT 1 FROM telegram_provider_batch_interactions JOIN telegram_outbox USING(receipt_id)
                    WHERE receipt_id=batch.batch_id))""")
    if "telegram_provider_document_opt_in" in tables:
        conditions.append("""NOT EXISTS(SELECT 1 FROM telegram_provider_document_opt_in AS opted
            JOIN telegram_document_jobs AS job USING(receipt_id) WHERE job.state IN ('pending','leased'))""")
    if "telegram_provider_documents" in tables:
        conditions.append(f"""NOT EXISTS(SELECT 1 FROM telegram_provider_documents AS document
            LEFT JOIN telegram_outbox AS reply USING(receipt_id)
            WHERE document.finished_at IS NULL OR reply.state IN ('pending','leased','sending')
              OR (document.finished_at>{epoch}-900 AND reply.receipt_id IS NULL))""")
    if "telegram_api_status" in tables:
        conditions.append(f"""NOT EXISTS(SELECT 1 FROM telegram_api_status AS action
            LEFT JOIN telegram_outbox AS reply USING(receipt_id)
            WHERE action.ready_at IS NULL OR (action.prompt_receipt_id IS NOT NULL
              AND action.ready_at>{epoch}-900 AND reply.receipt_id IS NULL))""")
    if "telegram_private_share_creations" in tables:
        conditions.append("NOT EXISTS(SELECT 1 FROM telegram_private_share_creations WHERE state='reserved' OR (state='abandoned' AND cleaned_at IS NULL))")
    if "telegram_group_share_cards" in tables:
        # A sent card still carrying an edit lease is unresolved until the consumer clears it.
        conditions.append(f"""NOT EXISTS(SELECT 1 FROM telegram_group_share_cards
            WHERE state IN ('pending','sending') OR lease_until>{epoch}
              OR (state='sent' AND lease_until IS NOT NULL))""")
    if "provider_snapshot_attempts" in tables:
        conditions.append(f"NOT EXISTS(SELECT 1 FROM provider_snapshot_attempts WHERE state IN ('open','sealed') AND lease_until > {epoch})")
    if "telegram_selected_links" in tables:
        waits.append("telegram_selected_revoke_ticket")
        conditions.append("NOT EXISTS(SELECT 1 FROM telegram_selected_links AS selected JOIN aggregate_links AS link ON link.code_sha256=selected.code_sha256 WHERE link.revoked_at IS NULL)")
    if "telegram_subscription_read_ticket" in tables:
        waits.append("telegram_subscription_read_ticket")
    conditions.extend(f"NOT EXISTS(SELECT 1 FROM {table} WHERE expires_at > {epoch} AND used_by_receipt_id IS NULL)" for table in waits)
    return "(" + " AND ".join(conditions) + ")"


def table_layout(db, tables):
    result = {}
    for table in tables:
        columns = list(db.execute(f"PRAGMA table_info({_identifier(table)})"))
        require(columns and len(columns) <= 100)
        names_and_types = [(row[1], row[2].upper() or ("TEXT" if row[1] == "name" else "INTEGER")) for row in columns]
        require(all(kind in {"TEXT", "INTEGER", "REAL"} for _, kind in names_and_types))
        primary = [row[1] for row in sorted(columns, key=lambda row: row[5]) if row[5]]
        if table == "sqlite_sequence":
            primary = ["name"]
        require(primary)
        result[table] = {"columns": names_and_types, "primary": primary}
    return result


def _cell(value, kind):
    if value is None:
        return ["null"]
    if kind == "TEXT":
        require(isinstance(value, str) and len(value.encode("utf-8")) <= MAX_CELL_BYTES)
        return ["text", value]
    if kind == "INTEGER":
        require(type(value) is int and -MAX_SAFE <= value <= MAX_SAFE)
        return ["integer", str(value)]
    require(type(value) in (float, int) and math.isfinite(value))
    return ["real", float(value).hex()]


def data_summary(layout, read_rows):
    hashes = {}
    counts = {}
    total = 0
    for table, definition in sorted(layout.items()):
        value = sha256(canonical(definition) + b"\n")
        count = 0
        for row in read_rows(table, definition):
            require(len(row) == len(definition["columns"]))
            cells = [_cell(cell, kind) for cell, (_, kind) in zip(row, definition["columns"])]
            encoded = canonical(cells)
            require(len(encoded) <= 4 * MAX_CELL_BYTES)
            value.update(encoded + b"\n")
            count += 1
            total += 1
            require(total <= MAX_ROWS)
        hashes[table], counts[table] = value.hexdigest(), count
    return {"dataSha256": digest(canonical(hashes)), "tableSha256": hashes, "tableCounts": counts, "rowCount": total}


def remote_summary(api, database_id, layout):
    def rows(table, definition):
        columns = [name for name, _ in definition["columns"]]
        primary = definition["primary"]
        kinds = dict(definition["columns"])
        require(all(kinds[name] in {"INTEGER", "TEXT"} for name in primary))
        key_bindings = ", ".join("CAST(? AS INTEGER)" if kinds[name] == "INTEGER" else "?" for name in primary)
        last = None
        while True:
            predicate = "" if last is None else " WHERE (" + ",".join(map(_identifier, primary)) + ") > (" + key_bindings + ")"
            limit = 1 if table in {"telegram_temp_batch", "legacy_temp_batches"} else 32
            sql = "SELECT " + ",".join(map(_identifier, columns)) + " FROM " + _identifier(table) + predicate
            sql += " ORDER BY " + ",".join(map(_identifier, primary)) + f" LIMIT {limit}"
            page = api.rows(database_id, sql, last or ())
            require(len(page) <= limit)
            for row in page:
                require(set(row) == set(columns))
                yield [row[name] for name in columns]
            if len(page) < limit:
                break
            next_key = [page[-1][name] for name in primary]
            require(last is None or next_key != last)
            last = next_key
    return data_summary(layout, rows)


def open_export(path, source):
    """Hosted scratch validation. Nothing is evaluated on the local control computer."""
    size, _ = file_hash(path)
    require(0 < size <= SQL_BYTES)
    scratch = path.with_name("scratch-" + path.name + ".sqlite")
    with private_file(scratch):
        pass
    db = sqlite3.connect(scratch)
    try:
        db.execute("PRAGMA trusted_schema=OFF")
        # A dump can list a child before its parent; check the entire graph
        # after the scratch replay. The remote import receives unmodified SQL.
        db.execute("PRAGMA foreign_keys=OFF")
        db.execute("PRAGMA cache_size=-2048")
        db.execute("PRAGMA temp_store=FILE")
        page_size = db.execute("PRAGMA page_size").fetchone()[0]
        db.execute(f"PRAGMA max_page_count={128 * 1024 * 1024 // page_size}")
        deadline = time.monotonic() + 45
        db.set_progress_handler(lambda: int(time.monotonic() >= deadline), 10_000)
        approved = set(source.tables)
        forbidden = {sqlite3.SQLITE_ATTACH, sqlite3.SQLITE_DETACH, sqlite3.SQLITE_CREATE_VTABLE,
                     sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_ALTER_TABLE,
                     sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_VIEW,
                     sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_TEMP_INDEX,
                     sqlite3.SQLITE_CREATE_TEMP_TRIGGER, sqlite3.SQLITE_CREATE_TEMP_VIEW}

        def authorizer(action, first, second, _database, _trigger):
            if action in forbidden:
                return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_PRAGMA and first not in {"defer_foreign_keys", "foreign_keys"}:
                return sqlite3.SQLITE_DENY
            if action in {sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE}:
                if first not in approved | {"sqlite_master", "sqlite_sequence"}:
                    return sqlite3.SQLITE_DENY
                if action in {sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE} and first not in {"sqlite_master", "sqlite_sequence"}:
                    return sqlite3.SQLITE_DENY
            if action == sqlite3.SQLITE_FUNCTION and second in {"load_extension", "readfile", "writefile"}:
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorizer)
        # Native imports do not use the query endpoint. Do not apply its 100KB
        # statement limit to normal 256KiB temp TEXT; validate the whole bounded dump.
        db.executescript(path.read_bytes().decode("utf-8"))
        db.set_authorizer(None)
        require(not db.in_transaction)
        db.execute("PRAGMA foreign_keys=ON")
        require(db.execute("PRAGMA quick_check").fetchall() == [("ok",)] and db.execute("PRAGMA foreign_key_check").fetchall() == [])
        actual = sorted(db.execute("SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE sql IS NOT NULL"))
        expected = sorted(tuple(obj) for obj in source.objects)
        require(actual == expected, "Native export schema does not match the pinned source artifact.")
        for sql in (
            "SELECT 1 FROM sqlite_sequence GROUP BY name HAVING count(*)<>1 LIMIT 1",
            "SELECT 1 FROM subscriptions AS active JOIN subscription_trash AS trash ON active.id=trash.id OR active.token=trash.token LIMIT 1",
            "SELECT 1 FROM subscription_trash AS trash LEFT JOIN subscription_lifecycle AS life ON life.subscription_id=trash.id WHERE trash.lifecycle_revision IS NOT life.revision LIMIT 1",
            "SELECT 1 FROM private_shares AS share WHERE share.max_claims < (SELECT count(*) FROM private_share_claims WHERE share_id=share.id) LIMIT 1",
            "SELECT 1 FROM private_share_claims AS claim JOIN private_shares AS share ON share.id=claim.share_id WHERE claim.claimed_at NOT BETWEEN share.created_at AND share.expire_at OR (share.target_user_id IS NOT NULL AND claim.actor_id<>share.target_user_id) LIMIT 1",
        ):
            require(db.execute(sql).fetchone() is None)
        layout = table_layout(db, source.tables)
        summary = data_summary(layout, lambda table, definition: db.execute("SELECT " + ",".join(_identifier(name) for name, _ in definition["columns"])
            + " FROM " + _identifier(table) + " ORDER BY " + ",".join(map(_identifier, definition["primary"]))))
        return db, layout, summary
    except Exception:
        db.close()
        raise RehearsalError("Private native export validation failed.") from None


def object_references(db, read_object, save_object=lambda _key, _hash, _raw: None):
    result = []
    seen = set()
    total = 0

    def add(key, expected_hash, expected_size=None, maximum=OBJECT_BYTES, custom=None):
        nonlocal total
        require(matches(KEY, key) and matches(DIGEST, expected_hash) and key not in seen and len(result) < MAX_OBJECTS)
        raw, metadata = read_object(key)
        require(isinstance(raw, bytes) and 0 < len(raw) <= maximum and digest(raw) == expected_hash
                and (expected_size is None or len(raw) == expected_size))
        require(validate_metadata(metadata)["custom"] == (custom or {}),
                "An R2 object's ownership metadata does not match its database reference.")
        total += len(raw)
        require(total <= TOTAL_OBJECT_BYTES)
        result.append({"key": key, "bytes": len(raw), "sha256": expected_hash, "metadata": metadata})
        seen.add(key)
        save_object(key, expected_hash, raw)
        return raw

    for table in ("subscriptions", "subscription_trash"):
        for sub_id, generation, snapshot, manifest_hash, node_count in db.execute(
            f"SELECT id,generation,snapshot_id,manifest_sha256,node_count FROM {table} ORDER BY id"
        ):
            if generation == 0:
                require(snapshot is None and manifest_hash is None and node_count == 0)
                continue
            require(integer(sub_id, 1) and matches(UUID, snapshot) and integer(node_count, 1, 100_000))
            prefix = f"subscriptions/{sub_id}/{snapshot}/"
            plan = parsed(add(prefix + "manifest.json", manifest_hash, maximum=65536), 65536)
            require(set(plan) == {"version", "chunks"} and type(plan["version"]) is int and plan["version"] == 1
                    and isinstance(plan["chunks"], list) and 1 <= len(plan["chunks"]) <= 256)
            count = 0
            snapshot_bytes = 0
            for index, chunk in enumerate(plan["chunks"]):
                require(isinstance(chunk, dict) and set(chunk) == {"bytes", "sha256", "count"}
                        and integer(chunk["bytes"], 1, OBJECT_BYTES) and integer(chunk["count"], 1, 100_000))
                raw = add(prefix + f"{index}.ndjson", chunk["sha256"], chunk["bytes"])
                snapshot_bytes += len(raw)
                require(snapshot_bytes <= 64 * 1024 * 1024)
                lines = raw.split(b"\n")
                require(lines.pop() == b"" and len(lines) == chunk["count"])
                for line in lines:
                    parsed(line, OBJECT_BYTES)
                count += len(lines)
            require(count == node_count)
    has_creation = db.execute("SELECT 1 FROM sqlite_schema WHERE type='table' AND name='telegram_private_share_creations'").fetchone() is not None
    share_fields = "share.payload_id,share.payload_sha256,share.payload_bytes"
    if has_creation:
        require(db.execute("""SELECT 1 FROM telegram_private_share_creations AS creation
            LEFT JOIN private_shares AS share ON share.id=creation.share_id
            WHERE creation.state='published' AND (share.id IS NULL OR creation.payload_id<>share.payload_id
              OR creation.payload_sha256<>share.payload_sha256 OR creation.payload_bytes<>share.payload_bytes
              OR creation.bot_id<>share.bot_id OR creation.actor_id<>share.sender_id) LIMIT 1""").fetchone() is None,
            "A published share does not match its creation record.")
        shares = db.execute(f"SELECT {share_fields},creation.receipt_id FROM private_shares AS share "
            "LEFT JOIN telegram_private_share_creations AS creation ON creation.share_id=share.id ORDER BY share.id")
    else:
        shares = db.execute(f"SELECT {share_fields},NULL FROM private_shares AS share ORDER BY share.id")
    for payload, expected_hash, size, receipt in shares:
        custom = None if receipt is None else {"purpose": PRIVATE_SHARE_PURPOSE, "receipt": str(receipt)}
        add(f"private-shares/{payload}.txt", expected_hash, size, 65536, custom).decode("utf-8")
    return sorted(result, key=lambda item: item["key"])


def published_share_metadata_count(entries):
    return sum(entry["metadata"]["custom"].get("purpose") == PRIVATE_SHARE_PURPOSE for entry in entries)


def resource_identity(kind, value, expected_name):
    require(isinstance(value, dict) and value.get("name") == expected_name)
    if kind == "database":
        require(matches(UUID, value.get("uuid")) and matches(TIMESTAMP, value.get("created_at")))
        return {"id": value["uuid"], "name": expected_name, "createdAt": value["created_at"]}
    require(matches(TIMESTAMP, value.get("creation_date")) and value.get("jurisdiction") == "default")
    return {"name": expected_name, "createdAt": value["creation_date"], "jurisdiction": "default"}


class Rehearsal:
    resource_kinds = RESOURCES
    creation_window_seconds = None

    def __init__(self, api, source, journal, directory):
        self.api, self.source, self.journal, self.directory = api, source, journal, directory

    def observe(self, kind):
        name = self.api.names[kind]
        if kind == "database":
            path = self.api.root + "/d1/database?" + urlencode({"name": name, "per_page": 100})
            envelope = self.api.json("GET", path, envelope=True)
            rows = envelope["result"]
            info = envelope.get("result_info", {})
            require(isinstance(rows, list) and len(rows) < 100 and isinstance(info, dict)
                    and info.get("total_pages", 1) in (0, 1))
            exact = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
            require(len(exact) <= 1)
            if not exact:
                return None
            candidate = exact[0].get("uuid")
            require(matches(UUID, candidate) and candidate != self.api.target["d1Id"])
            self.api.databases.add(candidate)
            identity = resource_identity(kind, self.api.json("GET", self.api.root + "/d1/database/" + candidate), name)
            require(identity["id"] == candidate, "D1 inventory and detail identities disagree.")
            return identity
        path = self.api.root + "/r2/buckets?" + urlencode({"name_contains": name, "per_page": 100})
        envelope = self.api.json("GET", path, envelope=True)
        result = envelope["result"]
        info = envelope.get("result_info", {})
        rows = result.get("buckets") if isinstance(result, dict) else None
        require(isinstance(rows, list) and len(rows) < 100 and isinstance(info, dict)
                and not info.get("cursor") and not info.get("next_page_token")
                and (info.get("is_truncated") is None or info["is_truncated"] is False))
        exact = [row for row in rows if isinstance(row, dict) and row.get("name") == name]
        require(len(exact) <= 1)
        if not exact:
            return None
        path = self.api.root + "/r2/buckets/" + name
        identity = resource_identity(kind, self.api.json("GET", path), name)
        require(self.api.json("GET", path + "/domains/managed").get("enabled") is False
                and self.api.json("GET", path + "/domains/custom") in ([], {"domains": []}),
                "A rehearsal bucket is not private.")
        return identity

    def verify_resources(self, *, all_required=False):
        require(self.journal.value is not None)
        resources = self.journal.value["resources"]
        require(set(resources) == set(self.resource_kinds))
        for kind, record in resources.items():
            require(isinstance(record, dict) and set(record) == {"pin", "intent"})
            if record["pin"] is not None:
                require(self.observe(kind) == record["pin"], "Pinned native restore resource ownership changed.")
                if kind == "database":
                    self.api.allow_restore(record["pin"]["id"])
                if kind == "objects":
                    self.api.allow_restore(object_bucket=record["pin"]["name"])
            else:
                require(not all_required, "Create and pin all three dedicated rehearsal resources first.")

    def prepare(self, pin):
        require(self.journal.value is None, "This rehearsal already has a private journal.")
        require(all(self.observe(kind) is None for kind in self.resource_kinds), "A proposed rehearsal resource name is occupied.")
        self.source.before_write()
        self.journal.save({"version": 1, "cohort": self.api.cohort, "scopeSha256": self.source.scope_sha256,
            "sourcePin": pin, "resources": {kind: {"pin": None, "intent": None} for kind in self.resource_kinds},
            "phase": "prepared", "export": None, "backup": None, "importState": None,
            "lease": {"owner": self.journal.owner, "until": int(time.time()) + LEASE_SECONDS}})

    def create(self, kind):
        require(kind in self.resource_kinds)
        record = self.journal.value["resources"][kind]
        if record["pin"] is not None:
            require(self.observe(kind) == record["pin"])
            return
        require(record["intent"] is None or record["intent"].get("state") == "rejected",
                "A resource create remains unpinned; inspect its private intent before another mutation.")
        require(self.observe(kind) is None, "The proposed rehearsal resource already exists; it was not adopted.")
        resources = deepcopy(self.journal.value["resources"])
        resources[kind]["intent"] = {"state": "started", "at": int(time.time()), "owner": self.journal.owner}
        self.journal.update(resources=resources)
        self.source.before_write()
        try:
            if kind == "database":
                value = self.api.json("POST", self.api.root + "/d1/database", {
                    "name": self.api.names[kind], "read_replication": {"mode": "disabled"}})
            else:
                value = self.api.json("POST", self.api.root + "/r2/buckets", {"name": self.api.names[kind], "storageClass": "Standard"})
            require(isinstance(value, dict) and value.get("name") == self.api.names[kind])
            candidate = self.observe(kind)
            require(candidate is not None)
            if kind == "database":
                require(value.get("uuid") == candidate["id"])
            timestamp = value.get("created_at" if kind == "database" else "creation_date")
            require(timestamp is None or timestamp == candidate["createdAt"])
        except RehearsalError as error:
            resources[kind]["intent"]["state"] = "rejected" if error.http_status is not None and 400 <= error.http_status < 500 and error.http_status != 408 else "unknown"
            self.journal.update(resources=resources)
            raise RehearsalError("Rehearsal resource creation was not pinned. Do not repeat an unknown create.", uncertain=True) from None
        resources[kind]["pin"] = candidate
        resources[kind]["intent"]["state"] = "confirmed"
        self.journal.update(resources=resources)

    def pin_resource(self, kind, expected_sha256):
        require(kind in self.resource_kinds and matches(DIGEST, expected_sha256))
        resources = deepcopy(self.journal.value["resources"])
        record = resources[kind]
        require(record["pin"] is None and isinstance(record["intent"], dict)
                and record["intent"].get("state") in {"started", "unknown"})
        candidate = self.observe(kind)
        require(candidate is not None and digest(canonical(candidate)) == expected_sha256)
        created = datetime.fromisoformat(candidate["createdAt"]).timestamp()
        require(created >= record["intent"]["at"] - 5,
                "The observed resource predates the recorded project creation attempt.")
        if self.creation_window_seconds is not None:
            require(created <= record["intent"]["at"] + self.creation_window_seconds,
                    "The observed resource falls outside the recorded project creation window.")
        self.source.before_write()
        record["pin"] = candidate
        record["intent"]["state"] = "confirmed"
        self.journal.update(resources=resources)

    def immutable(self, bucket, key, body):
        require(0 < len(body) <= OBJECT_BYTES)
        current, _ = self.api.object_or_none(bucket, key)
        if current is not None:
            require(current == body, "An immutable rehearsal object is occupied by different bytes.")
            return
        # Manifest/phase intent already owns the complete deterministic key set.
        self.journal.update()
        self.source.before_write()
        try:
            self.api.r2("PUT", bucket, key, body)
        except RehearsalError:
            pass
        current, _ = self.api.object_or_none(bucket, key)
        require(current == body, "A private rehearsal object write remains unconfirmed.")

    def _poll_export(self, result):
        deadline = time.monotonic() + POLL_SECONDS
        while result.get("status") not in {"complete", "error"}:
            bookmark = result.get("at_bookmark")
            saved = dict(self.journal.value["export"])
            require(matches(BOOKMARK, bookmark) and saved.get("bookmark", bookmark) == bookmark)
            if saved.get("state") != "polling":
                saved.update(state="polling", bookmark=bookmark)
                self.journal.update(export=saved)
            require(time.monotonic() < deadline, "Native source export polling reached its bounded window; preserve the private bookmark.")
            time.sleep(1)
            # Known-bookmark status polls must finish even when main advances.
            result = self.api.json("POST", self.api.source + "/export", {
                "output_format": "polling", "dump_options": {"compatibility": "d1"}, "current_bookmark": bookmark})
            require(isinstance(result, dict) and result.get("success") is True)
        require(result.get("status") == "complete" and result.get("success") is True and result.get("type", "export") == "export")
        output = result.get("result")
        require(isinstance(output, dict) and isinstance(output.get("signed_url"), str))
        saved = dict(self.journal.value["export"])
        bookmark = result.get("at_bookmark") or saved.get("bookmark")
        require(matches(BOOKMARK, bookmark) and saved.get("bookmark", bookmark) == bookmark)
        saved.update(state="download-ready", bookmark=bookmark, url=output["signed_url"])
        self.journal.update(export=saved)
        return output["signed_url"]

    def begin_export(self):
        require(self.journal.value["export"] is None, "An export initiation is already recorded; never blindly initiate it twice.")
        self.source.schema()
        observed_at = self.source.quiet()
        sequence = self.api.rows(self.api.target["d1Id"], "SELECT name,seq FROM sqlite_sequence ORDER BY name")
        ledger = self.api.rows(self.api.target["d1Id"], "SELECT position,name,sha256,mode,applied_at FROM subs_bot_schema_migrations ORDER BY position")
        watermark = self.api.rows(self.api.target["d1Id"], "SELECT COALESCE(max(receipt_id),0) AS watermark FROM telegram_inbox")
        self.journal.update(export={"state": "started", "sequence": sequence, "ledger": ledger, "watermark": watermark,
                                    "observedAt": observed_at})
        self.source.before_write()
        # Initiating export can lock source queries. Losing its first bookmark is
        # not permission to retry initiation; auto-cancellation must release it.
        try:
            result = self.api.json("POST", self.api.source + "/export", {"output_format": "polling", "dump_options": {"compatibility": "d1"}})
        except RehearsalError:
            saved = dict(self.journal.value["export"])
            saved["state"] = "unknown"
            self.journal.update(export=saved)
            raise RehearsalError("Source export initiation is unknown. Preserve the journal and verify normal queries recover; do not re-initiate.", uncertain=True) from None
        require(isinstance(result, dict))
        return self._poll_export(result)

    def resume_export(self):
        saved = self.journal.value["export"]
        require(isinstance(saved, dict))
        if saved.get("state") == "download-ready":
            return saved["url"]
        require(saved.get("state") == "polling" and isinstance(saved.get("bookmark"), str),
                "There is no confirmed source export bookmark to poll.")
        return self._poll_export({"at_bookmark": saved["bookmark"]})

    def capture(self):
        self.verify_resources(all_required=True)
        require(self.journal.value["backup"] is None, "This capture is already sealed; verify it instead of exporting again.")
        sql = self.directory / "source.sql"
        saved = self.journal.value["export"]
        if isinstance(saved, dict) and saved.get("state") == "sql-archived":
            self.load_sql(saved, sql)
        else:
            url = self.begin_export() if saved is None else self.resume_export()
            signed_transfer(url, download=sql)
        db, layout, summary = open_export(sql, self.source)
        try:
            saved = self.journal.value["export"]
            require(db.execute("SELECT " + quiet_expression(self.source.tables, saved["observedAt"])).fetchone() == (1,),
                    "The captured database contains active interactions or durable work.")
            require([dict(zip(("name", "seq"), row)) for row in db.execute("SELECT name,seq FROM sqlite_sequence ORDER BY name")] == saved["sequence"])
            require([dict(zip(("position", "name", "sha256", "mode", "applied_at"), row)) for row in db.execute(
                "SELECT position,name,sha256,mode,applied_at FROM subs_bot_schema_migrations ORDER BY position")] == saved["ledger"])
            require([{"watermark": db.execute("SELECT COALESCE(max(receipt_id),0) FROM telegram_inbox").fetchone()[0]}] == saved["watermark"])
            self.source.before_write()
            self.source.quiet()
            require(self.api.rows(self.api.target["d1Id"], "SELECT COALESCE(max(receipt_id),0) AS watermark FROM telegram_inbox") == saved["watermark"],
                    "Human activity arrived during source capture; this rehearsal was not sealed.")
            backup = self.api.names["backup"]
            prefix = self.api.archive_prefix
            sql_parts = []
            with sql.open("rb") as file:
                while part := file.read(OBJECT_BYTES):
                    key = prefix + f"sql/{len(sql_parts)}.sql"
                    self.immutable(backup, key, part)
                    sql_parts.append({"key": key, "bytes": len(part), "sha256": digest(part)})
            saved = {**saved, "state": "sql-archived", "sqlParts": sql_parts, "sqlSha256": file_hash(sql)[1],
                     "sqlMd5": file_hash(sql, "md5")[1], "sqlBytes": sql.stat().st_size}
            saved.pop("url", None)
            self.journal.update(export=saved)

            def read_source(key):
                raw, _ = self.api.object_or_none(WORKER_NAME, key)
                require(raw is not None)
                return raw, self.object_metadata(WORKER_NAME, key, len(raw))

            refs = object_references(db, read_source,
                lambda _key, expected_hash, raw: self.immutable(backup, prefix + "blobs/" + expected_hash, raw))
            document = {"version": 2, "sourcePin": self.journal.value["sourcePin"], "schemaSha256": self.source.schema_sha256,
                "sourceBookmark": saved.get("bookmark"), "sqlSha256": file_hash(sql)[1], "sqlMd5": file_hash(sql, "md5")[1],
                "sqlBytes": sql.stat().st_size, "sqlParts": sql_parts, "objects": refs, "layout": layout, "summary": summary}
            raw = canonical(document)
            require(len(raw) <= MANIFEST_BYTES)
            self.source.quiet()
            require(self.api.rows(self.api.target["d1Id"], "SELECT COALESCE(max(receipt_id),0) AS watermark FROM telegram_inbox") == saved["watermark"])
            # Seal last: partial content-addressed uploads never advertise completeness.
            self.immutable(backup, prefix + "manifest.json", raw)
            self.journal.update(phase="captured", export={"state": "complete", "bookmark": saved.get("bookmark")},
                backup={"manifestSha256": digest(raw), "sqlSha256": document["sqlSha256"],
                        "dataSha256": summary["dataSha256"], "rowCount": summary["rowCount"], "objectCount": len(refs),
                        "publishedShareMetadataCount": published_share_metadata_count(refs)})
        finally:
            db.close()

    def load_sql(self, document, path):
        require(integer(document.get("sqlBytes"), 1, SQL_BYTES) and matches(DIGEST, document.get("sqlSha256"))
                and isinstance(document.get("sqlParts"), list) and 1 <= len(document["sqlParts"]) <= SQL_BYTES // OBJECT_BYTES)
        total = 0
        with private_file(path) as file:
            for index, part in enumerate(document["sqlParts"]):
                require(isinstance(part, dict) and set(part) == {"key", "bytes", "sha256"}
                        and part["key"] == self.api.archive_prefix + f"sql/{index}.sql"
                        and integer(part["bytes"], 1, OBJECT_BYTES) and matches(DIGEST, part["sha256"]))
                raw, _ = self.api.object_or_none(self.api.names["backup"], part["key"])
                require(raw is not None and len(raw) == part["bytes"] and digest(raw) == part["sha256"])
                total += len(raw)
                require(total <= SQL_BYTES)
                file.write(raw)
        require(total == document["sqlBytes"] and file_hash(path)[1] == document["sqlSha256"]
                and file_hash(path, "md5")[1] == document["sqlMd5"])

    def manifest(self):
        backup = self.journal.value["backup"]
        require(isinstance(backup, dict) and matches(DIGEST, backup.get("manifestSha256")))
        raw, _ = self.api.object_or_none(self.api.names["backup"], self.api.archive_prefix + "manifest.json")
        require(raw is not None and digest(raw) == backup["manifestSha256"])
        document = parsed(raw, MANIFEST_BYTES)
        require(canonical(document) == raw and document.get("version") == 2 and type(document["version"]) is int
                and document.get("sourcePin") == self.journal.value["sourcePin"]
                and document.get("schemaSha256") == self.source.schema_sha256)
        sql = self.directory / "restore.sql"
        self.load_sql(document, sql)
        db, layout, summary = open_export(sql, self.source)
        try:
            require(canonical(layout) == canonical(document.get("layout")) and summary == document.get("summary")
                    and summary["dataSha256"] == backup["dataSha256"])

            require(isinstance(document.get("objects"), list) and len(document["objects"]) <= MAX_OBJECTS)
            entries = {}
            for entry in document["objects"]:
                require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"}
                        and matches(KEY, entry["key"]) and matches(DIGEST, entry["sha256"])
                        and integer(entry["bytes"], 1, OBJECT_BYTES) and entry["key"] not in entries)
                entries[entry["key"]] = entry

            def read_blob(key):
                entry = entries.get(key)
                require(entry is not None)
                body, _ = self.api.object_or_none(self.api.names["backup"], self.api.archive_prefix + "blobs/" + entry["sha256"])
                return body, entry["metadata"]

            references = object_references(db, read_blob)
            require(references == document["objects"]
                    and published_share_metadata_count(references) == backup["publishedShareMetadataCount"])
        finally:
            db.close()
        self.api.allow_restore(keys=[item["key"] for item in document["objects"]])
        return document, sql

    def object_metadata(self, bucket, key, size):
        exact = [row for row in self.api.list_objects(bucket, prefix=key, maximum=2) if row["key"] == key]
        require(len(exact) == 1 and integer(exact[0].get("size"), 1, OBJECT_BYTES) and exact[0]["size"] == size)
        return listed_metadata(exact[0])

    def target_objects(self, entries):
        rows = self.api.list_objects(self.api.names["objects"], maximum=MAX_OBJECTS)
        actual = []
        for row in rows:
            require(isinstance(row, dict) and isinstance(row.get("key"), str) and row["key"] in entries)
            key = row["key"]
            require(integer(row.get("size"), 1, OBJECT_BYTES) and row["size"] == entries[key]["bytes"]
                    and listed_metadata(row) == entries[key]["metadata"], "A restore object has conflicting size or metadata.")
            actual.append(key)
        require(len(actual) == len(set(actual)))
        return set(actual)

    def before_target_write(self):
        self.source.before_write()

    def restore_objects(self):
        self.verify_resources(all_required=True)
        document, _ = self.manifest()
        entries = {item["key"]: item for item in document["objects"]}
        self.target_objects(entries)
        self.journal.update(phase="restoring-objects")
        for index, entry in enumerate(document["objects"]):
            # Durable ordinal intent survives an unknown write and runner loss.
            self.journal.update(objectIntent=index)
            body, _ = self.api.object_or_none(self.api.names["backup"], self.api.archive_prefix + "blobs/" + entry["sha256"])
            require(body is not None and len(body) == entry["bytes"] and digest(body) == entry["sha256"])
            self.restore_object(entry, body)
            self.journal.update(objectIntent=None, objectConfirmed=index + 1)
        require(self.target_objects(entries) == set(entries))
        self.journal.update(phase="objects-restored")

    def restore_object(self, entry, body):
        bucket, key = self.api.names["objects"], entry["key"]
        current, _ = self.api.object_or_none(bucket, key)
        if current is None:
            self.before_target_write()
            try:
                self.api.put_restored_object(key, body, entry["metadata"])
            except RehearsalError as error:
                if not error.uncertain and error.http_status not in (409, 412):
                    raise
            current, _ = self.api.object_or_none(bucket, key)
        require(current == body, "A restore object has conflicting bytes or remains unconfirmed.")
        require(self.object_metadata(bucket, key, len(body)) == entry["metadata"], "A restore object has conflicting metadata.")

    def verify_object_bytes(self, document):
        entries = {item["key"]: item for item in document["objects"]}
        require(self.target_objects(entries) == set(entries))
        for entry in document["objects"]:
            body, _ = self.api.object_or_none(self.api.names["objects"], entry["key"])
            require(body is not None and len(body) == entry["bytes"] and digest(body) == entry["sha256"])

    def _poll_import(self, result):
        deadline = time.monotonic() + POLL_SECONDS
        while result.get("status") not in {"complete", "error"}:
            bookmark = result.get("at_bookmark")
            require(result.get("success") is True and matches(BOOKMARK, bookmark))
            previous = self.journal.value.get("importState") or {}
            if previous.get("state") != "polling" or previous.get("bookmark") != bookmark:
                self.journal.update(importState={"state": "polling", "bookmark": bookmark})
            require(time.monotonic() < deadline, "Target import polling reached its bounded window; preserve the private bookmark.")
            time.sleep(1)
            result = self.api.json("POST", self.api.root + f"/d1/database/{self.api.restore_id}/import",
                                   {"action": "poll", "current_bookmark": bookmark})
            require(isinstance(result, dict))
        require(result.get("success") is True and result.get("status") == "complete")
        self.journal.update(importState={"state": "complete", "finalBookmark": result.get("result", {}).get("final_bookmark")}, phase="imported")

    def start_import(self):
        self.verify_resources(all_required=True)
        document, sql = self.manifest()
        self.verify_object_bytes(document)
        state = self.journal.value.get("importState")
        if state is not None and state.get("state") in {"complete", "verified"}:
            return self.verify_restore(document)
        if state is not None and state.get("state") == "polling":
            self._poll_import({"success": True, "at_bookmark": state["bookmark"]})
            return self.verify_restore(document)
        if state is not None and state.get("state") in {"init-started", "ingest-started", "unknown"}:
            # Query availability and exact full-state equality can confirm an
            # acknowledged-lost commit. Never repeat init/ingest on a partial DB.
            try:
                return self.verify_restore(document)
            except (RehearsalError, migrations.MigrationError):
                raise RehearsalError("Target import remains unconfirmed. Preserve the target; never re-init, re-ingest or reset it.", uncertain=True) from None
        path = self.api.root + f"/d1/database/{self.api.restore_id}"
        require(migrations._matches_schema(self.api, path, ()), "Native import requires the new, still empty restore D1.")
        if state is None:
            self.journal.update(importState={"state": "init-started", "etag": document["sqlMd5"]})
            self.before_target_write()
            try:
                result = self.api.json("POST", path + "/import", {"action": "init", "etag": document["sqlMd5"]})
            except RehearsalError:
                self.journal.update(importState={"state": "unknown"})
                raise RehearsalError("Target init may already have started importing. Reconcile it; do not repeat init.", uncertain=True) from None
            require(isinstance(result, dict))
            if "upload_url" not in result:
                self._poll_import(result)
                return self.verify_restore(document)
            # Wrangler's upload-ready inner result is only filename + URL.
            # The outer management envelope was already checked by json().
            require(result.get("success", True) is True)
            require(matches(BOOKMARK, result.get("filename")))
            state = {"state": "upload-ready", "filename": result["filename"], "url": result["upload_url"], "etag": document["sqlMd5"]}
            self.journal.update(importState=state)
        require(state.get("state") in {"upload-ready", "upload-unknown"} and state.get("etag") == document["sqlMd5"])
        self.before_target_write()
        try:
            signed_transfer(state["url"], upload=sql, expected_md5=document["sqlMd5"])
        except RehearsalError:
            self.journal.update(importState={**state, "state": "upload-unknown"})
            raise
        require(migrations._matches_schema(self.api, path, ()))
        self.journal.update(importState={"state": "ingest-started", "filename": state["filename"], "etag": state["etag"]})
        self.before_target_write()
        try:
            result = self.api.json("POST", path + "/import", {"action": "ingest", "filename": state["filename"], "etag": state["etag"]})
        except RehearsalError:
            # Keep the durable ingest intent for exact read-only reconciliation.
            raise RehearsalError("Target ingestion was not acknowledged. Reconcile it; do not repeat ingestion.", uncertain=True) from None
        require(isinstance(result, dict))
        self._poll_import(result)
        return self.verify_restore(document)

    def verify_restore(self, document=None):
        summary, document = self.read_restored_summary(document)
        self.journal.update(phase="verified", importState={"state": "verified"}, targetDataSha256=summary["dataSha256"],
                            targetPublishedShareMetadataCount=published_share_metadata_count(document["objects"]))
        return summary

    def read_restored_summary(self, document=None):
        self.verify_resources(all_required=True)
        if document is None:
            document, _ = self.manifest()
        self.source.schema(self.api.restore_id)
        require(self.api.rows(self.api.restore_id, "PRAGMA foreign_key_check") == [])
        check = self.api.rows(self.api.restore_id, "PRAGMA quick_check")
        require(check == [{"quick_check": "ok"}])
        summary = remote_summary(self.api, self.api.restore_id, document["layout"])
        require(summary == document["summary"], "The native restored target does not match the captured full data digest.")
        self.verify_object_bytes(document)
        return summary, document


def report(journal, source):
    value = journal.value
    result = {"sourceReleaseSha256": digest(canonical(value["sourcePin"])), "sourceScopeSha256": source.scope_sha256,
              "schemaSha256": source.schema_sha256, "resourceCount": sum(item["pin"] is not None for item in value["resources"].values()),
              "resourcePinsSha256": digest(canonical({kind: item["pin"] for kind, item in value["resources"].items()})),
              "phaseSha256": digest(value["phase"].encode("ascii"))}
    if value.get("backup") is not None:
        result.update({key: value["backup"][key] for key in
                       ("manifestSha256", "sqlSha256", "dataSha256", "rowCount", "objectCount", "publishedShareMetadataCount")})
    if value.get("targetDataSha256") is not None:
        result["targetDataSha256"] = value["targetDataSha256"]
        result["targetPublishedShareMetadataCount"] = value["targetPublishedShareMetadataCount"]
    return result


def run_action(action, engine, *, pin=None, resource=None, identity_sha256=None):
    require(action in ACTIONS)
    journal = engine.journal
    current = journal.load()
    if action == "verify" and current is None:
        candidates = {kind: candidate for kind in RESOURCES if (candidate := engine.observe(kind)) is not None}
        engine.source.before_write()
        return {"sourceReleaseSha256": digest(canonical(pin)), "sourceScopeSha256": engine.source.scope_sha256,
                "schemaSha256": engine.source.schema_sha256, "resourceCount": 0,
                "unconfirmedResourceCount": len(candidates),
                "candidateIdentitySha256": {kind: digest(canonical(candidate)) for kind, candidate in candidates.items()}}
    if action == "prepare":
        engine.prepare(pin)
    else:
        require(current is not None and current.get("scopeSha256") == engine.source.scope_sha256)
        require(action == "poll-export" or current.get("sourcePin") == pin,
                "This rehearsal was prepared for a different immutable source release.")
        if action == "verify":
            engine.verify_resources()
            result = report(journal, engine.source)
            candidates = {kind: candidate for kind in RESOURCES if current["resources"][kind]["pin"] is None
                          and (candidate := engine.observe(kind)) is not None}
            result.update(unconfirmedResourceCount=len(candidates),
                          candidateIdentitySha256={kind: digest(canonical(candidate)) for kind, candidate in candidates.items()})
            engine.source.before_write()
            return result
        journal.claim()
    try:
        engine.verify_resources(all_required=action in {"capture", "poll-export", "restore-objects", "start-import", "verify-restore"})
        if action.startswith("create-"):
            engine.create({"create-backup-bucket": "backup", "create-restore-db": "database", "create-restore-bucket": "objects"}[action])
        elif action == "pin-resource":
            engine.pin_resource(resource, identity_sha256)
        elif action == "capture":
            engine.capture()
        elif action == "poll-export":
            engine.resume_export()
        elif action == "restore-objects":
            engine.restore_objects()
        elif action == "start-import":
            engine.start_import()
        elif action == "verify-restore":
            engine.verify_restore()
        engine.source.before_write()
        return report(journal, engine.source)
    finally:
        journal.release()


def main():
    require(os.environ.get("GITHUB_REPOSITORY") == artifact.REPOSITORY and os.environ.get("GITHUB_REF") == artifact.MAIN_REF
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch")
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision))
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event_file:
        event = parsed(event_file.read(65537), 65536)
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"action", "cohort", "source_run_id", "resource", "identity_sha256"})
    action, cohort = inputs.get("action"), inputs.get("cohort")
    require(action in ACTIONS and matches(COHORT, cohort))
    target = parsed(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "").encode(), 4096)
    token, deploy = os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN", "")
    require(token and deploy and token != deploy)
    bundle = Path(os.environ["RUNNER_TEMP"]) / artifact.VERIFIED_DIRECTORY
    manifest = parsed((bundle / "isolation.json").read_bytes(), 65536)
    require(manifest.get("revision") == revision and manifest.get("version") == 2
            and file_hash(bundle / "index.js")[1] == manifest.get("bundleSha256"))
    api = RehearsalAPI(target, token, cohort)
    worker_client = CloudflareClient(deploy)

    def read_worker(method, path, payload=None):
        require(method == "GET" and payload is None)
        return worker_client(method, path)

    source = Source(api, read_worker, target, bundle, manifest, lambda: artifact.require_current_main(revision))
    if action == "poll-export":
        # A source export may still be locking D1 and its original main may have
        # advanced. This branch can only poll the privately recorded bookmark.
        source.guard_main()
        source.config = source.scope.worker_config()
        source.scope.verify_resources()
        source.active = source.scope.active()
        source.version = source.scope.version(source.active.version)
        pin = None
    else:
        pin = source.verify()
        source.schema()
    owner = os.environ.get("GITHUB_RUN_ID", "") + "/" + os.environ.get("GITHUB_RUN_ATTEMPT", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}/[1-9][0-9]{0,9}", owner))
    journal = Journal(api, owner)
    with tempfile.TemporaryDirectory(prefix="native-restore-private-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        result = run_action(action, Rehearsal(api, source, journal, Path(temporary)), pin=pin,
                            resource=inputs.get("resource"), identity_sha256=inputs.get("identity_sha256"))
    path = Path(os.environ["RUNNER_TEMP"]) / "native-restore-evidence.json"
    with private_file(path) as file:
        file.write(canonical(result))
    print(canonical(result).decode("ascii"))


if __name__ == "__main__":
    try:
        main()
    except (RehearsalError, CloudflareError, migrations.MigrationError, artifact.ArtifactError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit(READ_ERROR)

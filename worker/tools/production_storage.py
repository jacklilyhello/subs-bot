"""Private, immutable lifecycle registration storage (separate from data backups)."""
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPSConnection, HTTPException
import os
from urllib.parse import quote, urlencode
from urllib.request import Request

import native_restore_rehearsal as native
from production_control import API, API_ROOT, OperationError, NoRedirect, privacy
from production_target import canonical, matches, require, parsed
import scoped_r2


class PrivateStore:
    def __init__(self, api, bucket):
        require(bucket == api.target["backupBucketName"])
        self.api, self.bucket = api, bucket
        self.objects = scoped_r2.from_environment(api.target["accountId"], bucket)
        metadata_token = os.environ.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", "")
        self.metadata_api = API(api.target, metadata_token) if metadata_token else api

    def verify(self):
        return privacy(self.metadata_api, self.metadata_api.root, self.bucket, self.api.target["backupBucketCreatedAt"])

    def list(self, prefix, maximum=128):
        self.verify()
        require(matches(r"maintenance/production-control/(?:registrations|evidence)/[a-zA-Z0-9/_.-]{1,200}", prefix))
        require(not any(p in (".", "..") for p in prefix.split("/")))
        if self.objects is not None:
            keys = self.objects.list(prefix, maximum=maximum)
            require(len(keys) < maximum, "Lifecycle registration listing exceeds capacity.")
            return keys
        result = self.api("GET", self.api.root + "/r2/buckets/" + self.bucket + "/objects?" + urlencode({"prefix": prefix, "per_page": maximum}), envelope=True)
        rows, info = result.get("result"), result.get("result_info", {})
        require(isinstance(rows, list) and len(rows) < maximum and not info.get("cursor")
                and not info.get("next_page_token") and info.get("is_truncated") is not True,
                "Lifecycle registration listing exceeds capacity or is truncated.")
        require(all(isinstance(r, dict) and isinstance(r.get("key"), str) and r["key"].startswith(prefix) for r in rows))
        return sorted(r["key"] for r in rows)

    def get(self, key, *, absent=False):
        require(matches(r"maintenance/production-control/(?:registrations|evidence)/[a-zA-Z0-9/_.-]{1,240}", key))
        require(not any(p in (".", "..") for p in key.split("/")))
        self.verify()
        if self.objects is not None:
            raw, _etag = self.objects.get(key, absent=absent, limit=512 * 1024)
            return raw
        request = Request(API_ROOT + self.api.root + "/r2/buckets/" + self.bucket + "/objects/" + quote(key, safe="/"),
            headers={"Authorization": "Bearer " + self.api.token, "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"})
        try:
            _, _, raw = native._response(self.api.opener, request, 512 * 1024)
            return raw
        except native.RehearsalError as error:
            if absent and error.http_status == 404:
                return None
            raise

    def put_exclusive(self, key, body):
        """Claim a unique intent once; 412 or unknown results never authorize writes."""
        require(isinstance(body, bytes) and 0 < len(body) <= 512 * 1024)
        require(self.get(key, absent=True) is None, "The private intent is already occupied.")
        if self.objects is not None:
            self.objects.put_once(key, body)
            return
        try:
            token = self.api("GET", self.api.root + "/tokens/verify")
        except OperationError as error:
            require(error.http_status in (400, 401, 403, 404))
            token = self.api("GET", "/user/tokens/verify")
        require(isinstance(token, dict) and token.get("status") == "active" and matches(r"[a-f0-9]{32}", token.get("id")))
        host = self.api.target["accountId"] + ".r2.cloudflarestorage.com"
        path = "/" + self.bucket + "/" + quote(key, safe="/-_.~")
        headers = native.signed_put_headers(host, path, token["id"], self.api.token, body,
                                            {"custom": {}, "http": {}}, datetime.now(timezone.utc))
        try:
            with closing(HTTPSConnection(host, timeout=30)) as connection:
                connection.request("PUT", path, body=body, headers=headers)
                with closing(connection.getresponse()) as response:
                    require(response.status == 200 and len(response.read(4097)) <= 4096,
                            "The private intent was not uniquely claimed; do not retry.")
        except (OSError, HTTPException, ValueError):
            raise OperationError("The private intent result is unknown; do not retry.", uncertain=True) from None
        require(self.get(key) == body, "The private intent was not independently confirmed.")

    def put(self, key, body):
        require(isinstance(body, bytes) and 0 < len(body) <= 512*1024)
        existing = self.get(key, absent=True)
        if existing is not None:
            require(existing == body, "Immutable lifecycle registration is occupied by different bytes.")
            return sha256(body).hexdigest()
        if self.objects is not None:
            self.objects.put_once(key, body)
            return sha256(body).hexdigest()
        try:
            token = self.api("GET", self.api.root + "/tokens/verify")
        except OperationError as error:
            require(error.http_status in (400, 401, 403, 404))
            token = self.api("GET", "/user/tokens/verify")
        require(isinstance(token, dict) and token.get("status") == "active" and matches(r"[a-f0-9]{32}", token.get("id")))
        host = self.api.target["accountId"] + ".r2.cloudflarestorage.com"
        path = "/" + self.bucket + "/" + quote(key, safe="/-_.~")
        headers = native.signed_put_headers(host, path, token["id"], self.api.token, body, {"custom": {}, "http": {}}, datetime.now(timezone.utc))
        try:
            with closing(HTTPSConnection(host, timeout=30)) as connection:
                connection.request("PUT", path, body=body, headers=headers)
                with closing(connection.getresponse()) as response:
                    require(response.status in (200, 412) and len(response.read(4097)) <= 4096, "Private lifecycle write is unconfirmed.")
        except (OSError, HTTPException, ValueError):
            raise OperationError("Private lifecycle write is unconfirmed; independently read back before retry.", uncertain=True) from None
        require(self.get(key) == body, "Private lifecycle storage readback differs.")
        return sha256(body).hexdigest()

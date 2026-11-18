"""Private, immutable lifecycle registration storage (separate from data backups)."""
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from http.client import HTTPSConnection, HTTPException
import os
from urllib.parse import quote, urlencode
from urllib.request import Request
import xml.etree.ElementTree as ET

import native_restore_rehearsal as native
from production_control import API, API_ROOT, OperationError, NoRedirect, privacy
from production_target import canonical, matches, require, parsed
import scoped_r2


class PrivateStore:
    def __init__(self, api, bucket):
        require(bucket == api.target["backupBucketName"])
        self.api, self.bucket = api, bucket
        self.objects = scoped_r2.from_environment(api.target["accountId"], bucket)
        metadata_token = scoped_r2.metadata_token()
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

    def list_backup_anchor_history(self, target_sha256):
        """Enumerate private R2 through S3's explicit IsTruncated contract."""
        require(matches(r"[a-f0-9]{64}", target_sha256))
        prefix = "maintenance/production-control/evidence/daily-backup-anchor/" + target_sha256 + "/"
        return self._list_backup_prefix(prefix)

    def list_backup_journals(self):
        return self._list_backup_prefix("maintenance/production-control/evidence/daily-backup/")

    def list_backup_session(self, prefix):
        require(matches(r"maintenance/production-control/evidence/daily-backup/[0-9]{4}/[0-9]{2}/[0-9]{2}/[1-9][0-9]{0,19}-[1-9][0-9]{0,9}/", prefix))
        return self._list_backup_prefix(prefix)

    def _list_backup_prefix(self, prefix):
        require(prefix == "maintenance/production-control/evidence/daily-backup/" or
                matches(r"maintenance/production-control/evidence/daily-backup-anchor/[a-f0-9]{64}/", prefix) or
                matches(r"maintenance/production-control/evidence/daily-backup/[0-9]{4}/[0-9]{2}/[0-9]{2}/[1-9][0-9]{0,19}-[1-9][0-9]{0,9}/", prefix))
        self.verify()
        if self.objects is not None:
            return self.objects.list(prefix, maximum=10000)
        try:
            token = self.api("GET", self.api.root + "/tokens/verify")
        except OperationError as error:
            require(error.http_status in (400, 401, 403, 404))
            token = self.api("GET", "/user/tokens/verify")
        require(isinstance(token, dict) and token.get("status") == "active" and matches(r"[a-f0-9]{32}", token.get("id")))
        host = self.api.target["accountId"] + ".r2.cloudflarestorage.com"
        path = "/" + quote(self.bucket, safe="-_.~")
        keys, cursors, cursor = [], set(), None
        while True:
            query = {"list-type": "2", "max-keys": "1000", "prefix": prefix}
            if cursor is not None:
                query["continuation-token"] = cursor
            encoded = urlencode(sorted(query.items()), quote_via=quote, safe="-_.~")
            now = datetime.now(timezone.utc)
            timestamp, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
            payload_sha = sha256(b"").hexdigest()
            signed_headers = "host;x-amz-content-sha256;x-amz-date"
            canonical_headers = "host:" + host + "\nx-amz-content-sha256:" + payload_sha + "\nx-amz-date:" + timestamp + "\n"
            request = "\n".join(("GET", path, encoded, canonical_headers, signed_headers, payload_sha))
            scope = day + "/auto/s3/aws4_request"
            string_to_sign = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, sha256(request.encode("ascii")).hexdigest()))
            signing_key = ("AWS4" + sha256(self.api.token.encode("ascii")).hexdigest()).encode("ascii")
            for part in (day, "auto", "s3", "aws4_request"):
                signing_key = hmac.digest(signing_key, part.encode("ascii"), "sha256")
            signature = hmac.digest(signing_key, string_to_sign.encode("ascii"), "sha256").hex()
            headers = {"Host": host, "x-amz-date": timestamp, "x-amz-content-sha256": payload_sha,
                       "Authorization": "AWS4-HMAC-SHA256 Credential=" + token["id"] + "/" + scope
                           + ", SignedHeaders=" + signed_headers + ", Signature=" + signature}
            try:
                with closing(HTTPSConnection(host, timeout=30)) as connection:
                    connection.request("GET", path + "?" + encoded, headers=headers)
                    with closing(connection.getresponse()) as response:
                        require(response.status == 200, "Private anchor S3 listing failed.")
                        body = response.read(2 * 1024 * 1024 + 1)
            except (OSError, HTTPException, ValueError):
                raise OperationError("Private anchor S3 listing was not confirmed.") from None
            require(len(body) <= 2 * 1024 * 1024 and b"<!DOCTYPE" not in body.upper())
            try:
                root = ET.fromstring(body)
            except ET.ParseError:
                require(False, "Private anchor S3 listing was malformed.")
            ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
            require(root.tag == ns + "ListBucketResult" and all(len(root.findall(ns + field)) == 1
                    for field in ("Name", "Prefix", "IsTruncated"))
                    and len(root.findall(ns + "NextContinuationToken")) <= 1
                    and root.findtext(ns + "Name") == self.bucket
                    and root.findtext(ns + "Prefix") == prefix)
            truncated = root.findtext(ns + "IsTruncated")
            require(truncated in {"true", "false"})
            contents = root.findall(ns + "Contents")
            require(all(len(item.findall(ns + "Key")) == 1 for item in contents))
            rows = [item.findtext(ns + "Key") for item in contents]
            require(len(rows) <= 1000 and all(isinstance(key, str) and key.startswith(prefix) for key in rows))
            keys.extend(rows)
            require(len(keys) <= 10000 and len(keys) == len(set(keys)),
                    "The complete backup anchor inventory exceeded its supported boundary.")
            next_cursor = root.findtext(ns + "NextContinuationToken")
            if truncated == "false":
                require(next_cursor is None, "Unexpected continuation on a completed S3 listing.")
                return sorted(keys)
            require(isinstance(next_cursor, str) and 0 < len(next_cursor) <= 4096 and next_cursor not in cursors and rows)
            cursors.add(next_cursor)
            cursor = next_cursor

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

    def get_with_etag(self, key):
        """Read a single private mutable coordination pointer and its ETag."""
        require(matches(r"maintenance/production-control/registrations/daily-backup-anchor-[a-f0-9]{64}\.json", key))
        self.verify()
        if self.objects is not None:
            raw, etag = self.objects.get(key, absent=True, limit=32768)
            require(raw is None or matches(r'"[a-f0-9]{32}"', etag))
            return raw, etag
        request = Request(API_ROOT + self.api.root + "/r2/buckets/" + self.bucket + "/objects/" + quote(key, safe="/"),
            headers={"Authorization": "Bearer " + self.api.token, "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"})
        try:
            _, headers, raw = native._response(self.api.opener, request, 32768)
        except native.RehearsalError as error:
            if error.http_status == 404:
                return None, None
            raise
        etag = headers.get("ETag") or headers.get("Etag")
        require(matches(r'"[a-f0-9]{32}"', etag), "The private coordination pointer has no exact ETag.")
        return raw, etag

    def compare_and_put(self, key, expected_body, expected_etag, body):
        """Conditionally advance a single pointer; unknown results are never retried."""
        require(matches(r"maintenance/production-control/registrations/daily-backup-anchor-[a-f0-9]{64}\.json", key)
                and isinstance(body, bytes) and 0 < len(body) <= 32768)
        if self.objects is not None:
            self.verify()
            return self.objects.compare_and_put(key, expected_body, expected_etag, body)
        actual, etag = self.get_with_etag(key)
        require(actual == expected_body and etag == expected_etag, "The backup coordination predecessor changed.")
        try:
            token = self.api("GET", self.api.root + "/tokens/verify")
        except OperationError as error:
            require(error.http_status in (400, 401, 403, 404))
            token = self.api("GET", "/user/tokens/verify")
        require(isinstance(token, dict) and token.get("status") == "active" and matches(r"[a-f0-9]{32}", token.get("id")))
        host = self.api.target["accountId"] + ".r2.cloudflarestorage.com"
        path = "/" + self.bucket + "/" + quote(key, safe="/-_.~")
        headers = native.signed_put_headers(host, path, token["id"], self.api.token, body,
                                            {"custom": {}, "http": {}}, datetime.now(timezone.utc), if_match=etag)
        try:
            with closing(HTTPSConnection(host, timeout=30)) as connection:
                connection.request("PUT", path, body=body, headers=headers)
                with closing(connection.getresponse()) as response:
                    require(response.status == 200 and len(response.read(4097)) <= 4096,
                            "The backup coordination write was not confirmed.")
        except (OSError, HTTPException, ValueError):
            raise OperationError("The backup coordination write is unknown; independently inspect before proceeding.", uncertain=True) from None
        observed, observed_etag = self.get_with_etag(key)
        require(observed == body and observed_etag is not None, "The backup coordination readback differs.")
        return observed_etag

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

"""Explicit bucket-scoped S3 object transport; metadata uses a separate API token.

Credentials are optional and scoped per exact bucket by the platform. No method
retries an unconfirmed write; callers independently verify durable state.
"""
from contextlib import closing
from datetime import datetime, timezone
from hashlib import sha256
import hmac
from http.client import HTTPSConnection, HTTPException
import os
import re
from urllib.parse import quote
from xml.etree import ElementTree

from production_target import parsed, require

MAX_OBJECT = 16 * 1024 * 1024
MAX_LIST = 2 * 1024 * 1024


class ScopedR2Error(ValueError):
    """An operation was not confirmed; never infer a failed write was absent."""


def sign(method, host, path, query, headers, payload_sha, access, secret, now):
    return _sign(method, host, path, query, headers, payload_sha, access, secret, now, "auto")


def _sign(method, host, path, query, headers, payload_sha, access, secret, now, region):
    timestamp = now.strftime("%Y%m%dT%H%M%SZ")
    day = timestamp[:8]
    values = {k.lower(): str(v) for k, v in headers.items()}
    values.update({"host": host, "x-amz-date": timestamp, "x-amz-content-sha256": payload_sha})
    names = ";".join(sorted(values))
    canonical_headers = "".join(f"{key}:{' '.join(values[key].split())}\n" for key in sorted(values))
    request = "\n".join((method, path, query, canonical_headers, names, payload_sha))
    scope = f"{day}/{region}/s3/aws4_request"
    message = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, sha256(request.encode("ascii")).hexdigest()))
    key = ("AWS4" + secret).encode("ascii")
    for part in (day, region, "s3", "aws4_request"):
        key = hmac.digest(key, part.encode("ascii"), "sha256")
    signature = hmac.digest(key, message.encode("ascii"), "sha256").hex()
    values["authorization"] = f"AWS4-HMAC-SHA256 Credential={access}/{scope}, SignedHeaders={names}, Signature={signature}"
    return values


def _credential(raw, bucket, *, required):
    if not raw:
        require(not required, "The exact bucket-scoped object credential is required.")
        return None
    value = parsed(raw)
    credential = value.get(bucket)
    require(isinstance(credential, dict) and set(credential) == {"accessKeyId", "secretAccessKey"}
            and re.fullmatch(r"[a-f0-9]{32}", credential.get("accessKeyId", "") or "")
            and re.fullmatch(r"[a-f0-9]{64}", credential.get("secretAccessKey", "") or ""),
            "The exact bucket-scoped object credential is missing or malformed.")
    return credential


def from_environment(account, bucket, env=None):
    env = os.environ if env is None else env
    read = env.get("SUBS_BOT_SCOPED_R2_READ_JSON", "")
    write = env.get("SUBS_BOT_SCOPED_R2_WRITE_JSON", "")
    if not read and not write:
        return None
    return ScopedR2(account, bucket, _credential(read, bucket, required=True), _credential(write, bucket, required=False))


class ScopedR2:
    def __init__(self, account, bucket, read, write=None):
        require(re.fullmatch(r"[a-f0-9]{32}", account or "")
                and re.fullmatch(r"[a-z0-9][a-z0-9-]{1,61}[a-z0-9]", bucket or ""))
        self.host, self.bucket, self.read_credential, self.write_credential = account + ".r2.cloudflarestorage.com", bucket, read, write

    def _request(self, method, key, *, query=None, raw=b"", headers=None, limit=MAX_OBJECT):
        require(method in {"GET", "PUT"} and isinstance(key, str) and len(key) <= 1024
                and not any(part in {".", ".."} for part in key.split("/")))
        credential = self.read_credential if method == "GET" else self.write_credential
        require(isinstance(credential, dict), "The bucket-scoped write credential is unavailable.")
        path = "/" + self.bucket + ("/" + quote(key, safe="/-_.~") if key else "")
        encoded = "&".join(quote(str(k), safe="-_.~") + "=" + quote(str(v), safe="-_.~")
                           for k, v in sorted((query or {}).items()))
        headers = sign(method, self.host, path, encoded, headers or {}, sha256(raw).hexdigest(),
                       credential["accessKeyId"], credential["secretAccessKey"], datetime.now(timezone.utc))
        try:
            with closing(HTTPSConnection(self.host, timeout=45)) as connection:
                connection.request(method, path + ("?" + encoded if encoded else ""), body=raw if method == "PUT" else None, headers=headers)
                with closing(connection.getresponse()) as response:
                    status, etag = response.status, response.getheader("ETag")
                    require(response.getheader("Content-Encoding", "identity") == "identity")
                    body = response.read(limit + 1)
                    require(len(body) <= limit)
                    return status, etag, body
        except (OSError, HTTPException, ValueError):
            raise ScopedR2Error("The scoped R2 request is unconfirmed; do not retry a write.") from None

    def get(self, key, *, absent=False, limit=MAX_OBJECT):
        status, etag, raw = self._request("GET", key, limit=limit)
        if status == 404 and absent:
            return None, None
        require(status == 200 and etag and not any(c in etag for c in "\r\n"))
        return raw, etag

    def put_once(self, key, raw, *, etag=None, metadata=None):
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_OBJECT)
        require(etag is None or re.fullmatch(r'"[a-f0-9]{32}"', etag) is not None)
        metadata = {} if metadata is None else metadata
        require(isinstance(metadata, dict) and set(metadata) <= {"cache-control", "content-type"}
                and all(isinstance(value, str) and not any(c in value for c in "\r\n") for value in metadata.values()))
        condition = {"if-none-match": "*"} if etag is None else {"if-match": etag}
        status, _etag, _body = self._request("PUT", key, raw=raw,
            headers={**condition, "content-length": str(len(raw)), **metadata}, limit=4096)
        require(status == 200, "The conditional R2 write is unknown or conflicted; do not retry.")
        observed, _ = self.get(key)
        require(observed == raw, "The conditional R2 write was not independently confirmed.")

    def compare_and_put(self, key, expected_body, expected_etag, body):
        observed, etag = self.get(key, absent=True)
        require(observed == expected_body and etag == expected_etag,
                "The exact bucket coordination predecessor changed.")
        self.put_once(key, body, etag=etag)
        confirmed, confirmed_etag = self.get(key)
        require(confirmed == body and re.fullmatch(r'"[a-f0-9]{32}"', confirmed_etag or "") is not None)
        return confirmed_etag

    def list(self, prefix, *, maximum=10000):
        require(isinstance(prefix, str) and prefix and type(maximum) is int and 0 < maximum <= 10000)
        cursor, cursors, keys = None, set(), []
        for _ in range(16):
            query = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
            if cursor is not None:
                query["continuation-token"] = cursor
            status, _etag, raw = self._request("GET", "", query=query, limit=MAX_LIST)
            require(status == 200 and b"<!" not in raw)
            try:
                root = ElementTree.fromstring(raw)
            except ElementTree.ParseError:
                raise ScopedR2Error("The bucket listing could not be verified.") from None
            ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
            require(root.tag == ns + "ListBucketResult" and all(len(root.findall(ns + name)) == 1
                    for name in ("Name", "Prefix", "IsTruncated")) and len(root.findall(ns + "NextContinuationToken")) <= 1
                    and root.findtext(ns + "Name") == self.bucket and root.findtext(ns + "Prefix") == prefix)
            truncated = root.findtext(ns + "IsTruncated")
            require(truncated in {"true", "false"})
            contents = root.findall(ns + "Contents")
            require(len(contents) <= 1000 and all(len(node.findall(ns + "Key")) == 1 for node in contents))
            batch = [node.findtext(ns + "Key") for node in contents]
            require(all(isinstance(k, str) and k.startswith(prefix) for k in batch)
                    and len(set(batch)) == len(batch) and not set(batch).intersection(keys))
            keys.extend(batch)
            require(len(keys) <= maximum)
            next_cursor = root.findtext(ns + "NextContinuationToken")
            if truncated == "false":
                require(next_cursor is None)
                return sorted(keys)
            require(isinstance(next_cursor, str) and 0 < len(next_cursor) <= 4096 and next_cursor not in cursors and batch)
            cursors.add(next_cursor)
            cursor = next_cursor
        raise ScopedR2Error("The complete bucket listing exceeds its verified bound.")

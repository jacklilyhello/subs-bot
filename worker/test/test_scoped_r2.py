"""Hosted synthetic checks for explicit bucket-scoped object operations."""
import json
import os
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import scoped_r2
import production_storage
import archive_production_provider
import native_restore_rehearsal
from production_target import ContractError


ACCOUNT = "a" * 32
BUCKET = "subs-bot-cf-dev-01"
KEY = "maintenance/production-control/evidence/example.json"
CREDENTIAL = {"accessKeyId": "b" * 32, "secretAccessKey": "c" * 64}


def page(keys, *, truncated="false", cursor=None, prefix="test/"):
    values = "".join("<Contents><Key>" + key + "</Key></Contents>" for key in keys)
    next_value = "" if cursor is None else "<NextContinuationToken>" + cursor + "</NextContinuationToken>"
    return (f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{BUCKET}</Name>'
            f'<Prefix>{prefix}</Prefix><IsTruncated>{truncated}</IsTruncated>{values}{next_value}</ListBucketResult>').encode()


class ScopedR2Tests(unittest.TestCase):
    def test_signature_matches_the_published_aws_s3_vector(self):
        # Public example from AWS's SigV4 S3 header-authentication reference.
        headers = scoped_r2._sign("GET", "examplebucket.s3.amazonaws.com", "/test.txt", "", {"range": "bytes=0-9"},
            sha256(b"").hexdigest(), "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            datetime(2013, 5, 24, tzinfo=timezone.utc), "us-east-1")
        self.assertTrue(headers["authorization"].endswith(
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

    def test_legacy_put_still_derives_secret_and_preserves_cas_headers(self):
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        token, body, etag = "fixture-token", b"fixture", '"' + "d" * 32 + '"'
        metadata = {"custom": {}, "http": {"content-type": "application/octet-stream"}}
        headers = native_restore_rehearsal.signed_put_headers("example.invalid", "/bucket/item", "b" * 32,
                                                             token, body, metadata, now, if_match=etag)
        expected = scoped_r2.sign("PUT", "example.invalid", "/bucket/item", "",
            {"content-length": str(len(body)), "if-match": etag, "x-amz-storage-class": "STANDARD",
             "content-type": "application/octet-stream"}, sha256(body).hexdigest(), "b" * 32,
            sha256(token.encode()).hexdigest(), now)
        expected["Authorization"] = expected.pop("authorization")
        self.assertEqual(headers, expected)
        self.assertNotIn("if-none-match", headers)

    def test_explicit_per_bucket_credentials_and_no_fallback(self):
        self.assertIsNone(scoped_r2.from_environment(ACCOUNT, BUCKET, {}))
        env = {"SUBS_BOT_SCOPED_R2_READ_JSON": json.dumps({BUCKET: CREDENTIAL})}
        store = scoped_r2.from_environment(ACCOUNT, BUCKET, env)
        self.assertEqual(store.bucket, BUCKET)
        self.assertIsNone(store.write_credential)
        with self.assertRaises(ContractError):
            scoped_r2.from_environment(ACCOUNT, "another-bucket", env)
        with self.assertRaises(ContractError):
            store.put_once(KEY, b"test")

    def test_conditional_write_rejects_conflict_and_never_retries(self):
        store = scoped_r2.ScopedR2(ACCOUNT, BUCKET, CREDENTIAL, CREDENTIAL)
        with patch.object(store, "_request", return_value=(412, None, b"")) as request, \
             patch.object(store, "get") as readback, self.assertRaises(ContractError):
            store.put_once(KEY, b"candidate")
        request.assert_called_once()
        self.assertEqual(request.call_args.kwargs["headers"]["if-none-match"], "*")
        readback.assert_not_called()
        with patch.object(store, "_request", side_effect=scoped_r2.ScopedR2Error("unknown")) as request, \
             patch.object(store, "get") as readback, self.assertRaises(scoped_r2.ScopedR2Error):
            store.put_once(KEY, b"candidate")
        request.assert_called_once()
        readback.assert_not_called()

    def test_transport_does_not_drop_empty_objects(self):
        store = scoped_r2.ScopedR2(ACCOUNT, BUCKET, CREDENTIAL, CREDENTIAL)
        with patch.object(store, "_request", return_value=(200, None, b"")) as request, \
             patch.object(store, "get", return_value=(b"", '"' + 'd' * 32 + '"')):
            store.put_once(KEY, b"")
        self.assertEqual(request.call_args.kwargs["raw"], b"")
        self.assertEqual(request.call_args.kwargs["headers"]["content-length"], "0")

    def test_cas_checks_predecessor_and_exact_etag_before_one_write(self):
        store = scoped_r2.ScopedR2(ACCOUNT, BUCKET, CREDENTIAL, CREDENTIAL)
        etag = '"' + 'd' * 32 + '"'
        with patch.object(store, "get", side_effect=[(b"prior", etag), (b"next", etag), (b"next", etag)]), \
             patch.object(store, "_request", return_value=(200, etag, b"")) as request:
            self.assertEqual(store.compare_and_put(KEY, b"prior", etag, b"next"), etag)
            self.assertEqual(request.call_args.kwargs["headers"]["if-match"], etag)
            self.assertNotIn("if-none-match", request.call_args.kwargs["headers"])
            request.assert_called_once()
        with patch.object(store, "get", return_value=(b"changed", etag)), \
             patch.object(store, "_request") as request, self.assertRaises(ContractError):
            store.compare_and_put(KEY, b"prior", etag, b"next")
        request.assert_not_called()

    def test_full_s3_pagination_and_duplicate_refusal(self):
        store = scoped_r2.ScopedR2(ACCOUNT, BUCKET, CREDENTIAL)
        with patch.object(store, "_request", side_effect=[(200, None, page(["test/a"], truncated="true", cursor="next")),
                                                          (200, None, page(["test/b"]))]) as request:
            self.assertEqual(store.list("test/"), ["test/a", "test/b"])
            self.assertEqual(request.call_args.kwargs["query"]["continuation-token"], "next")
        with patch.object(store, "_request", side_effect=[(200, None, page(["test/a"], truncated="true", cursor="next")),
                                                          (200, None, page(["test/a"]))]), self.assertRaises(ContractError):
            store.list("test/")
        with patch.object(store, "_request", return_value=(200, None, page(["test/a"], truncated="unknown"))), \
             self.assertRaises(ContractError):
            store.list("test/")

    def test_lifecycle_store_uses_separate_metadata_and_scoped_objects(self):
        from unittest.mock import Mock
        source = Mock(target={"accountId": ACCOUNT, "backupBucketName": BUCKET, "backupBucketCreatedAt": "created"}, root="/source")
        metadata = Mock(root="/metadata")
        objects = Mock()
        objects.get.return_value = (b"registered", '"' + 'd' * 32 + '"')
        with patch.dict(os.environ, {"SUBS_BOT_CF_R2_METADATA_READ_TOKEN": "metadata-only"}, clear=True), \
             patch.object(production_storage, "API", return_value=metadata), \
             patch.object(production_storage.scoped_r2, "from_environment", return_value=objects), \
             patch.object(production_storage, "privacy") as privacy:
            store = production_storage.PrivateStore(source, BUCKET)
            self.assertEqual(store.get(KEY), b"registered")
        privacy.assert_called_once_with(metadata, "/metadata", BUCKET, "created")
        objects.get.assert_called_once_with(KEY, absent=False, limit=512 * 1024)
        source.assert_not_called()

    def test_legacy_exclusive_intent_rejects_412_without_readback_or_retry(self):
        from unittest.mock import Mock
        store = object.__new__(production_storage.PrivateStore)
        store.api = Mock(root="/accounts/" + ACCOUNT, target={"accountId": ACCOUNT}, token="synthetic")
        store.api.return_value = {"status": "active", "id": "b" * 32}
        store.bucket, store.objects = BUCKET, None
        with patch.object(store, "get", return_value=None) as read, \
             patch.object(production_storage.native, "signed_put_headers", return_value={}), \
             patch.object(production_storage, "HTTPSConnection") as connection, \
             self.assertRaises(production_storage.OperationError):
            connection.return_value.getresponse.return_value.status = 412
            store.put_exclusive(KEY, b"intent")
        connection.return_value.request.assert_called_once()
        read.assert_called_once_with(KEY, absent=True)

    def test_referenced_object_metadata_requires_matching_etag_and_size(self):
        from unittest.mock import Mock
        key = "private-shares/00000000-0000-0000-0000-000000000000.txt"
        etag = '"' + 'd' * 32 + '"'
        listing = {"key": key, "size": 7, "etag": etag, "storage_class": "Standard"}
        observed = {**listing, "ssec": False, "custom_metadata": {"purpose": native_restore_rehearsal.PRIVATE_SHARE_PURPOSE,
                    "receipt": "123"}, "http_metadata": {"contentType": "text/plain"}}
        store = Mock()
        store.list_entries.return_value = [listing]
        store.head.return_value = observed
        result = native_restore_rehearsal.scoped_object_rows(store, key, 2)
        self.assertEqual(native_restore_rehearsal.listed_metadata(result[0]),
                         {"custom": observed["custom_metadata"], "http": {"content-type": "text/plain"}})
        store.head.return_value = {**observed, "etag": '"' + 'e' * 32 + '"'}
        with self.assertRaises(native_restore_rehearsal.RehearsalError):
            native_restore_rehearsal.scoped_object_rows(store, key, 2)

    def test_head_preserves_supported_http_and_custom_metadata(self):
        store = scoped_r2.ScopedR2(ACCOUNT, BUCKET, CREDENTIAL)
        etag = '"' + 'd' * 32 + '"'
        headers = [("Content-Length", "7"), ("Content-Type", "text/plain"),
                   ("x-amz-meta-purpose", native_restore_rehearsal.PRIVATE_SHARE_PURPOSE), ("x-amz-meta-receipt", "123")]
        with patch.object(store, "_request", return_value=(200, etag, b"", headers)):
            result = store.head("private-shares/fixture.txt")
        self.assertEqual(result["http_metadata"], {"contentType": "text/plain"})
        self.assertEqual(result["custom_metadata"], {"purpose": native_restore_rehearsal.PRIVATE_SHARE_PURPOSE, "receipt": "123"})

    def test_detailed_listing_refuses_unknown_or_nonstandard_storage(self):
        store = scoped_r2.ScopedR2(ACCOUNT, BUCKET, CREDENTIAL)
        etag = '"' + 'd' * 32 + '"'
        raw = (f'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>{BUCKET}</Name>'
               f'<Prefix>test/</Prefix><IsTruncated>false</IsTruncated><Contents><Key>test/a</Key>'
               f'<Size>7</Size><ETag>{etag}</ETag><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>').encode()
        with patch.object(store, "_request", return_value=(200, None, raw)):
            self.assertEqual(store.list_entries("test/"), [{"key": "test/a", "size": 7, "etag": etag, "storage_class": "Standard"}])
        with patch.object(store, "_request", return_value=(200, None, raw.replace(b"STANDARD", b"UNKNOWN"))), \
             self.assertRaises(ContractError):
            store.list_entries("test/")

    def test_provider_store_keeps_metadata_api_separate_from_object_keys(self):
        from unittest.mock import Mock
        target = {"accountId": "9431815bdb8beb2272f6668e06b7d3be", "namespace": "lilyya", "r2CreatedOn": "created"}
        objects = Mock()
        objects.get.return_value = (b"original", '"' + 'd' * 32 + '"')
        metadata = Mock()
        with patch.dict(os.environ, {"SUBS_BOT_CF_R2_METADATA_READ_TOKEN": "metadata-only"}, clear=True), \
             patch.object(archive_production_provider, "CloudflareClient", side_effect=[Mock(), metadata]), \
             patch.object(archive_production_provider.scoped_r2, "from_environment", return_value=objects):
            store = archive_production_provider.PrivateProofStore(target, "legacy", "123", "1")
            self.assertIs(store.metadata_api, metadata)
            self.assertEqual(store.read("manifest.json"), b"original")
        objects.get.assert_called_once_with(store.prefix + "manifest.json", absent=True, limit=archive_production_provider.CHUNK_BYTES)


if __name__ == "__main__":
    unittest.main()

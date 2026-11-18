"""Synthetic S3 pagination proofs; no Cloudflare calls in ordinary CI."""
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_storage as storage
from production_target import ContractError


TARGET = "a" * 64
PREFIX = "maintenance/production-control/evidence/daily-backup-anchor/" + TARGET + "/"


class API:
    target = {"backupBucketName": "private-test-bucket", "accountId": "b" * 32}
    token = "synthetic-test-token"
    root = "/accounts/" + "b" * 32
    def __call__(self, _method, _path):
        return {"id": "c" * 32, "status": "active"}


class Response:
    status = 200
    def __init__(self, body):
        self.body = body
    def read(self, _limit):
        return self.body
    def close(self):
        pass


class Connection:
    pages = []
    def __init__(self, _host, timeout):
        assert timeout == 30
    def request(self, method, path, headers):
        assert method == "GET" and "list-type=2" in path and "Authorization" in headers
    def getresponse(self):
        return Response(self.pages.pop(0))
    def close(self):
        pass


def page(truncated, key=None, cursor=None):
    contents = "" if key is None else "<Contents><Key>" + PREFIX + key + "</Key></Contents>"
    continuation = "" if cursor is None else "<NextContinuationToken>" + cursor + "</NextContinuationToken>"
    flag = "" if truncated is None else "<IsTruncated>" + truncated + "</IsTruncated>"
    return ('<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            '<Name>private-test-bucket</Name><Prefix>' + PREFIX + '</Prefix>' + flag + contents
            + continuation + '</ListBucketResult>').encode()


class S3ListingTests(unittest.TestCase):
    def test_scoped_anchor_list_get_and_cas_do_not_use_rest_object_token(self):
        private = storage.PrivateStore(API(), "private-test-bucket")
        objects = Mock()
        etag = '"' + 'd' * 32 + '"'
        objects.list.return_value = [PREFIX + "000000000001-" + "e" * 64 + ".json"]
        objects.get.return_value = (b"old", etag)
        objects.compare_and_put.return_value = etag
        private.objects = objects
        key = "maintenance/production-control/registrations/daily-backup-anchor-" + TARGET + ".json"
        with patch.object(private, "verify"), patch.object(storage, "HTTPSConnection") as rest:
            self.assertEqual(private.list_backup_anchor_history(TARGET), objects.list.return_value)
            self.assertEqual(private.get_with_etag(key), (b"old", etag))
            self.assertEqual(private.compare_and_put(key, b"old", etag, b"new"), etag)
        objects.compare_and_put.assert_called_once_with(key, b"old", etag, b"new")
        rest.assert_not_called()
        with self.assertRaises(ContractError):
            private.compare_and_put("maintenance/production-control/registrations/unrelated.json", b"old", etag, b"new")
        objects.compare_and_put.assert_called_once()

    def test_exclusive_intent_conflict_or_lost_response_never_confirms_or_retries(self):
        private = storage.PrivateStore(API(), "private-test-bucket")
        for failure in (False, True):
            connection, response = Mock(), Mock(status=412)
            connection.getresponse.return_value = response
            if failure:
                connection.request.side_effect = OSError("synthetic lost response")
            with patch.object(private, "get", return_value=None) as read, \
                 patch.object(storage, "HTTPSConnection", return_value=connection), \
                 self.assertRaises(storage.OperationError):
                private.put_exclusive("maintenance/production-control/evidence/example.json", b"intent")
            connection.request.assert_called_once()
            self.assertEqual(connection.request.call_args.kwargs["headers"]["if-none-match"], "*")
            read.assert_called_once()

    def run_pages(self, pages):
        Connection.pages = list(pages)
        private = storage.PrivateStore(API(), "private-test-bucket")
        with patch.object(private, "verify"), patch.object(storage, "HTTPSConnection", Connection):
            return private.list_backup_anchor_history(TARGET)

    def test_all_pages_require_explicit_false(self):
        self.assertEqual(self.run_pages([page("true", "one", "next"), page("false", "two")]),
                         [PREFIX + "one", PREFIX + "two"])
        with self.assertRaises(ContractError):
            self.run_pages([page(None)])

    def test_repeated_cursor_never_truncates_to_a_pass(self):
        with self.assertRaises(ContractError):
            self.run_pages([page("true", "one", "next"), page("true", "two", "next")])


if __name__ == "__main__":
    unittest.main()

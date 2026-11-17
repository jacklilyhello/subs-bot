"""Synthetic S3 pagination proofs; no Cloudflare calls in ordinary CI."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

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

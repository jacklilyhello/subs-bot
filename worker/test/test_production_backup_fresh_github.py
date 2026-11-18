"""Hosted checks for fresh, conditional scheduled-backup liveness reads."""
from io import BytesIO
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_backup_fresh_github as fresh
from production_target import ContractError


class Response(BytesIO):
    def __init__(self, body, etag):
        super().__init__(body)
        self.status = 200
        self.headers = {"ETag": etag}


def not_modified(tag):
    return HTTPError("https://api.github.com/ignored", 304, "not modified", {"ETag": tag}, BytesIO())


class FreshGitHubTests(unittest.TestCase):
    def test_child_run_recheck_detects_a_new_attempt(self):
        client = fresh.FreshConditionalJSON()
        def verified(value):
            return value.get("id") == 123 and value.get("run_attempt") == 1 and value.get("status") == "completed"
        responses = [Response(b'{"id":123,"run_attempt":1,"status":"completed"}', '"old"'),
                     not_modified('"old"'),
                     Response(b'{"id":123,"run_attempt":2,"status":"completed"}', '"new"')]
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", side_effect=responses) as opened:
            self.assertTrue(verified(client.get("/actions/runs/123", verify=verified)))
            self.assertTrue(verified(client.get("/actions/runs/123", verify=verified)))
            with self.assertRaises(ContractError):
                client.get("/actions/runs/123", verify=verified)
            self.assertEqual(opened.call_count, 3)
        with self.assertRaises(ContractError):
            client.get("/actions/runs/123/attempts/2", verify=verified)

    def test_each_read_is_network_revalidated_and_changed_body_replaces_cache(self):
        client = fresh.FreshConditionalJSON()
        responses = [Response(b'{"status":"in_progress"}', 'W/"old"'), not_modified('"old"'),
                     Response(b'{"status":"completed"}', '"new"')]
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", side_effect=responses) as opened:
            self.assertEqual(client.get("/actions/jobs/123", verify=lambda _value: True)["status"], "in_progress")
            self.assertEqual(client.get("/actions/jobs/123", verify=lambda _value: True)["status"], "in_progress")
            self.assertEqual(client.get("/actions/jobs/123", verify=lambda _value: True)["status"], "completed")
            self.assertEqual(opened.call_count, 3)
            self.assertEqual(opened.call_args_list[1].args[0].get_header("If-none-match"), 'W/"old"')

    def test_unknown_304_changed_cached_bytes_and_other_paths_fail_closed(self):
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", side_effect=not_modified('"x"')):
            with self.assertRaises(ContractError):
                fresh.FreshConditionalJSON().get("/git/ref/heads/main", verify=lambda _value: True)
        client = fresh.FreshConditionalJSON()
        client._cached["/git/ref/heads/main"] = ('W/"x"', b'{"changed":true}', "0" * 64)
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", side_effect=not_modified('"x"')):
            with self.assertRaises(ContractError):
                client.get("/git/ref/heads/main", verify=lambda _value: True)
        with self.assertRaises(ContractError):
            client.get("/actions/jobs/../secrets", verify=lambda _value: True)
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", return_value=Response(b'{}', '"bad"quote"')):
            with self.assertRaises(ContractError):
                fresh.FreshConditionalJSON().get("/actions/jobs/123", verify=lambda _value: True)
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", side_effect=OSError("unavailable")):
            with self.assertRaises(ContractError):
                fresh.FreshConditionalJSON().get("/actions/jobs/123", verify=lambda _value: True)

    def test_unverified_200_is_never_cached_for_a_later_304(self):
        client = fresh.FreshConditionalJSON()
        with patch.object(fresh.github, "_github_token", return_value="synthetic"), \
             patch.object(fresh.github._OPENER, "open", side_effect=[Response(b'{"status":"completed"}', '"x"'),
                                                                     not_modified('"x"')]) as opened:
            with self.assertRaises(ContractError):
                client.get("/actions/jobs/123", verify=lambda _value: False)
            with self.assertRaises(ContractError):
                client.get("/actions/jobs/123", verify=lambda _value: True)
            self.assertEqual(opened.call_count, 1)

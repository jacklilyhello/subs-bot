"""Synthetic checks for the hosted public capability probe."""

from io import BytesIO
import json
from pathlib import Path
import sys
from time import monotonic
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import github_search_capability as probe


URL = "https://github.com/jquery/jquery/blob/main/src/attributes/classes.js"
TEXT = f"Repository: {probe.REPO}\nPath: {probe.PATH}\nURL: {URL}\nLicense: MIT\n\nSnippets:\nsynthetic excerpt"
EMPTY = {"items": [], "incomplete_results": False, "total_count": 0}


def rpc(request_id, result, **kwargs):
    return probe.Reply(200, "json", {"jsonrpc": "2.0", "id": request_id, "result": result}, **kwargs)


class GitHubSearchCapabilityTests(unittest.TestCase):
    def test_github_distinguishes_authentication_from_complete_empty(self):
        transport = Mock(return_value=probe.Reply(401))
        report = probe.probe_github(transport)
        self.assertEqual((report["positive"]["outcome"], report["negative"]), ("auth-required", None))
        transport.assert_called_once()
        self.assertNotIn("Authorization", transport.call_args.args[3])
        hit = {"repository": {"full_name": probe.REPO, "private": False}, "path": probe.PATH, "html_url": URL}
        positive = {**EMPTY, "items": [hit], "total_count": 1}
        for response, expected in ((probe.Reply(200, "json", EMPTY), "empty"),
                                   (probe.Reply(200, "json", {**EMPTY, "incomplete_results": True}), "incomplete"),
                                   (probe.Reply(429), "rate-limited")):
            report = probe.probe_github(Mock(side_effect=[probe.Reply(200, "json", positive), response]))
            self.assertEqual((report["positive"]["verifiedMatches"], report["negative"]["outcome"]), (1, expected))
        self.assertFalse(probe._fixture_link(URL.replace("github.com/", "github.com@evil.invalid/")))

    def test_grep_distinguishes_absence_empty_shape_and_opaque_no_result_text(self):
        initial = rpc(1, {"protocolVersion": probe.MCP_VERSION}, session="synthetic-session")
        for tools, content, expected in (([], None, "tool-absent"),
                                         ([{"name": "searchGitHub", "inputSchema": {}}], [], "empty-content"),
                                         ([{"name": "searchGitHub", "inputSchema": {}}],
                                          [{"type": "text", "text": "No matches: synthetic upstream prose"}], "opaque-text")):
            transport = Mock(side_effect=[initial, probe.Reply(202), rpc(2, {"tools": tools}),
                                          rpc(3, {"content": [{"type": "text", "text": TEXT}]}),
                                          rpc(4, {"content": content})])
            report = probe.probe_grep(transport)
            self.assertEqual(report["negative"]["outcome"] if tools else report["outcome"], expected)
            self.assertEqual(transport.call_count, 5 if tools else 3)
            self.assertNotIn("synthetic", json.dumps(report))
            for index, call in enumerate(transport.call_args_list):
                host, path, method, headers, _ = call.args
                self.assertEqual((host, path, method), (probe.GREP, "/", "POST"))
                self.assertNotIn("Authorization", headers)
                self.assertEqual(headers.get("Mcp-Session-Id"), "synthetic-session" if index else None)
        self.assertFalse(probe._grep_hit("Snippets:\n" + TEXT))

    def test_sse_framing_and_cap(self):
        response = BytesIO(b': priming\r\ndata: \r\n\r\nevent: message\ndata: {"id":1}\n\ndata: later\n')
        self.assertEqual(probe._sse(response), {"id": 1})
        self.assertEqual(response.read(), b"data: later\n")
        for payload, label in ((b"data: " + b"x" * probe.MAX_BODY, "body-limit"),
                               (b'data: {"id":1,"id":2}\n\n', "malformed"),
                               (b"event: other\ndata: {}\n\n", "unsupported-sse-event")):
            with self.assertRaisesRegex(probe.ProbeError, label):
                probe._sse(BytesIO(payload))

    def test_redirect_never_reads_a_body_or_opens_another_connection(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 302
        with patch.object(probe, "HTTPSConnection", return_value=connection) as connect:
            reply = probe._exchange(probe.GITHUB, "/search/code", "GET", {}, None, deadline=monotonic() + 5)
        self.assertEqual(probe._failure(reply), "redirect")
        connect.assert_called_once()
        response.read.assert_not_called()

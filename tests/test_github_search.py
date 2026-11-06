"""Verify /g request credentials and fallback behavior without network access."""
from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix="subs-github-search-") as data_dir:
    with patch.dict(os.environ, {"BOT_TOKEN": "0:TEST", "DATA_DIR": data_dir}):
        import bot


PLACEHOLDER_TOKEN = "placeholder-for-header-test"
REPOSITORIES = "https://api.github.com/search/repositories"
CODE = "https://api.github.com/search/code"
FALLBACK = "https://grep.app/api/search"


class Response:
    def __init__(self, status, payload):
        self.status = status
        self.payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def json(self, **_kwargs):
        return self.payload


class GitHubSearchTests(unittest.IsolatedAsyncioTestCase):
    async def search(self, responses, token=PLACEHOLDER_TOKEN):
        requests = []
        reply_html = AsyncMock()
        update = SimpleNamespace(effective_message=SimpleNamespace(reply_html=reply_html))

        async def intercept(session, method, url, *, headers=None, allow_redirects=True, **_kwargs):
            parsed = urlsplit(str(url))
            endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            effective_headers = session._prepare_headers(headers)
            requests.append((method, endpoint, effective_headers.get("Authorization"), allow_redirects))
            response = responses[endpoint]
            if isinstance(response, Exception):
                raise response
            return response

        # Keep aiohttp's default/per-request header merging while replacing the network request.
        with (
            patch.object(bot, "GITHUB_TOKEN", token),
            patch.object(bot, "deny", AsyncMock(return_value=False)),
            patch.object(bot.aiohttp.ClientSession, "_request", intercept),
        ):
            await bot.cmd_github_search(update, SimpleNamespace(args=["sample"]))

        reply_html.assert_awaited_once()
        return requests, reply_html.await_args.args[0]

    async def test_fallback_request_never_receives_github_authorization(self):
        requests, reply = await self.search({
            REPOSITORIES: Response(200, {"items": []}),
            CODE: Response(403, {}),
            FALLBACK: Response(200, {"hits": {"hits": [{"repo": {"raw": "owner/repo"}, "path": "config.yaml"}]}}),
        })

        self.assertEqual([request[1] for request in requests], [REPOSITORIES, CODE, FALLBACK])
        self.assertEqual(requests[0][2], f"Bearer {PLACEHOLDER_TOKEN}")
        self.assertEqual(requests[1][2], f"Bearer {PLACEHOLDER_TOKEN}")
        self.assertIsNone(requests[2][2], "grep.app must not receive GitHub Authorization")
        self.assertIn("grep.app", reply)
        self.assertIn("owner/repo/config.yaml", reply)

    async def test_authenticated_requests_cannot_follow_redirects(self):
        requests, _ = await self.search({
            REPOSITORIES: Response(302, None),
            CODE: Response(307, None),
            FALLBACK: Response(200, {}),
        })

        self.assertEqual([request[1] for request in requests], [REPOSITORIES, CODE, FALLBACK])
        self.assertEqual(requests[0], ("GET", REPOSITORIES, f"Bearer {PLACEHOLDER_TOKEN}", False))
        self.assertEqual(requests[1], ("GET", CODE, f"Bearer {PLACEHOLDER_TOKEN}", False))

    async def test_request_errors_keep_credentials_out_of_logs_and_reply(self):
        with self.assertLogs(bot.log, level="WARNING") as logged:
            _, reply = await self.search({
                REPOSITORIES: ValueError(f"request detail contained {PLACEHOLDER_TOKEN}"),
                CODE: ValueError(f"request detail contained {PLACEHOLDER_TOKEN}"),
                FALLBACK: Response(503, {}),
            })

        self.assertNotIn(PLACEHOLDER_TOKEN, "\n".join(logged.output))
        self.assertNotIn(PLACEHOLDER_TOKEN, reply)

    async def test_without_token_search_still_uses_unauthenticated_fallback(self):
        requests, reply = await self.search({
            REPOSITORIES: Response(200, {"items": [{"full_name": "owner/repo"}]}),
            CODE: Response(401, {}),
            FALLBACK: Response(200, {"hits": {"hits": [{"repo": {"raw": "owner/match"}, "path": "data.txt"}]}}),
        }, token="")

        self.assertEqual([request[1] for request in requests], [REPOSITORIES, CODE, FALLBACK])
        self.assertTrue(all(request[2] is None for request in requests))
        self.assertIn("owner/repo", reply)
        self.assertIn("owner/match/data.txt", reply)


if __name__ == "__main__":
    unittest.main()

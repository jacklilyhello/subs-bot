"""Exercise private ingress and edge restrictions with a hosted in-process server."""

import asyncio
from base64 import urlsafe_b64decode
from hashlib import sha256
import ipaddress
import json
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer

import server
from transport import ApiProbeSuccess, FetchFailure, FetchSuccess


REVISION = "a" * 40
HOST = {"Host": "container"}


class ServerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.client = TestClient(TestServer(server.application(REVISION)))
        await self.client.start_server()
        self.addAsyncCleanup(self.client.close)

    async def test_ingress_rejects_other_hosts_routes_and_credential_fields(self):
        with patch.object(server, "fetch_provider", new_callable=AsyncMock) as fetch:
            for path, headers, payload, status in (
                ("/v1/fetch", {}, b'{"url":"https://provider.example/"}', 404),
                ("/v1/fetch?fixture=secret", HOST, b'{}', 404),
                ("/v1/edge-proof", HOST, b'{"url":"https://provider.example/"}', 400),
                ("/v1/fetch", HOST, b'{"url":"fixture","password":"secret"}', 400),
                ("/v1/fetch", HOST, b'{"url":"fixture","url":"duplicate"}', 400),
                ("/v1/fetch", HOST, b'x' * (server.MAX_REQUEST + 1), 413),
                ("/v1/fetch", HOST | {"Content-Encoding": "gzip"}, b'not-a-gzip', 400),
            ):
                async with self.client.post(path, headers=headers | {"Content-Type": "application/json"}, data=payload) as reply:
                    self.assertEqual(reply.status, status)
                    self.assertNotIn("secret", await reply.text())
            fetch.assert_not_called()

    async def test_api_probe_ingress_uses_exact_fields_and_returns_only_status_and_latency(self):
        with patch.object(server, "probe_api_status", new_callable=AsyncMock,
                          return_value=ApiProbeSuccess(401, 62)) as probe:
            for path, headers, raw, status in (
                ("/v1/api-status", {}, b'{}', 404),
                ("/v1/api-status?test=1", HOST, b'{}', 404),
                ("/v1/api-status", HOST, b'{"url":"fixture","key":3}', 400),
                ("/v1/api-status", HOST, b'{"url":"fixture","key":"x","key":"y"}', 400),
                ("/v1/api-status", HOST, b'{"url":"fixture","key":"x","extra":true}', 400),
            ):
                async with self.client.post(path, headers=headers | {"Content-Type": "application/json"}, data=raw) as response:
                    self.assertEqual(response.status, status)
            probe.assert_not_called()
            url = "https://provider.example/v1/models"
            async with self.client.post("/v1/api-status", headers=HOST, json={"url": url, "key": "synthetic-key"}) as response:
                self.assertEqual(response.status, 200)
                self.assertEqual(response.headers["Cache-Control"], "private, no-store")
                self.assertEqual(await response.json(), {"status": 401, "elapsedMs": 62})
            probe.assert_awaited_once_with(url, "synthetic-key")

    async def test_fixed_edge_probe_narrows_addresses_and_refuses_redirects(self):
        async def synthetic(url, **policy):
            self.assertEqual(url, server.ORIGIN)
            self.assertFalse(policy["follow_redirects"])
            self.assertEqual(policy["user_agent"], "subs-bot-isolation-release/1.0")
            self.assertFalse(policy["address_policy"]((ipaddress.ip_address("8.8.8.8"),)))
            self.assertTrue(policy["address_policy"]((ipaddress.ip_address("104.16.0.1"), ipaddress.ip_address("2606:4700::1"))))
            return FetchSuccess(b"synthetic response", {"profile-title": "synthetic metadata"})

        with patch.object(server, "fetch_provider", side_effect=synthetic):
            async with self.client.post("/v1/edge-proof", headers=HOST, json={}) as reply:
                self.assertEqual(reply.status, 200)
                self.assertEqual(reply.headers["Cache-Control"], "private, no-store")
                self.assertEqual(reply.headers["X-Provider-Approved-Families"], "4,6")
                self.assertEqual(reply.headers["Content-Type"], "application/octet-stream")
                body = await reply.read()
                self.assertEqual(body, b"synthetic response")
                self.assertEqual(reply.headers["X-Provider-Body-Sha256"], sha256(body).hexdigest())
                self.assertEqual(json.loads(urlsafe_b64decode(reply.headers["X-Provider-Metadata"])),
                                 {"profile-title": "synthetic metadata"})

    async def test_second_request_is_rejected_while_first_is_in_progress(self):
        entered, finish = asyncio.Event(), asyncio.Event()

        async def synthetic(_):
            entered.set()
            await finish.wait()
            return FetchSuccess(b"fixture", {})

        with patch.object(server, "fetch_provider", side_effect=synthetic):
            first = asyncio.create_task(self.client.post("/v1/fetch", headers=HOST, json={"url": "https://fixture.example/"}))
            try:
                await asyncio.wait_for(entered.wait(), timeout=2)
                async with self.client.post("/v1/fetch", headers=HOST, json={"url": "https://fixture.example/"}) as reply:
                    self.assertEqual(reply.status, 429)
                    self.assertEqual(await reply.json(), {"error": "busy"})
            finally:
                finish.set()
                async with await first as reply:
                    self.assertEqual(reply.status, 200)

    async def test_reports_only_a_valid_numeric_upstream_status_for_http_failures(self):
        for upstream, expected in (
            (429, {"error": "http-status", "upstreamStatus": 429}),
            (503, {"error": "http-status", "upstreamStatus": 503}),
            (None, {"error": "unavailable"}), (200, {"error": "unavailable"}), (600, {"error": "unavailable"}),
        ):
            with patch.object(server, "fetch_provider", new_callable=AsyncMock, return_value=FetchFailure("http-status", upstream)):
                async with self.client.post("/v1/fetch", headers=HOST, json={"url": "https://fixture.example/"}) as reply:
                    self.assertEqual(reply.status, 502)
                    self.assertEqual(await reply.json(), expected)

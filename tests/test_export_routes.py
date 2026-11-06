"""Exercise the HTTP and Telegram export entry points with synthetic SQLite data."""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
from urllib.parse import unquote, urlsplit

from aiohttp import ClientSession, ClientTimeout

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
with tempfile.TemporaryDirectory(prefix="subs-export-config-") as config_dir:
    with patch.dict(os.environ, {
        "BOT_TOKEN": "0:TEST",
        "DATA_DIR": config_dir,
        "DB_PATH": str(Path(config_dir) / "test.db"),
    }):
        import bot
        from db import Store


OWNER = 42
PUBLIC_URL = "https://bot.example"
PASSWORD = "test-only:ss-password"
SUPPORTED = {
    "type": "ss", "name": "Example node", "server": "203.0.113.15", "port": 8388,
    "cipher": "aes-256-gcm", "password": PASSWORD,
}
UNSUPPORTED = {
    "type": "example-unsupported", "name": "private-example-node", "server": "198.51.100.10",
    "port": 443, "password": "test-only:unsupported-password",
}
HTTP_ERROR = "Some nodes or connection settings are unsupported by this export format."
BASE64_KINDS = ("base64", "v2ray", "mixed")
SINGBOX_KINDS = ("singbox", "sing-box")


def telegram_update(data=None):
    message = SimpleNamespace(reply_text=AsyncMock(), reply_html=AsyncMock(), reply_document=AsyncMock())
    query = SimpleNamespace(data=data, answer=AsyncMock(), message=message) if data else None
    return SimpleNamespace(
        effective_user=SimpleNamespace(id=OWNER),
        effective_chat=SimpleNamespace(id=OWNER, type="private"),
        effective_message=message,
        callback_query=query,
    )


class ExportRouteTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        temp = tempfile.TemporaryDirectory(prefix="subs-export-routes-")
        self.addCleanup(temp.cleanup)
        self.store = Store(str(Path(temp.name) / "test.db"))
        patches = patch.multiple(bot, store=self.store, PUBLIC_BASE_URL=PUBLIC_URL, deny=AsyncMock(return_value=False))
        patches.start()
        self.addCleanup(patches.stop)
        self.addAsyncCleanup(self.store.close)

    @asynccontextmanager
    async def http_session(self):
        # Test the registered routes over loopback, with no external network or live tokens.
        with patch.multiple(bot, HTTP_HOST="127.0.0.1", HTTP_PORT=0):
            runner = await bot.start_http(None)
        try:
            host, port = runner.addresses[0]
            async with ClientSession(timeout=ClientTimeout(total=5)) as session:
                yield session, f"http://{host}:{port}"
        finally:
            await runner.cleanup()

    async def paths(self, sub):
        all_code = await self.store.create_short(OWNER, "aggregate://all")
        selected_code = await self.store.create_short(OWNER, f"aggregate://ids/{sub['id']}")
        return (f"/sub/{sub['token']}", f"/agg/{all_code}", f"/agg/{selected_code}")

    def assert_private(self, response):
        directives = {directive.strip() for directive in response.headers.get("Cache-Control", "").split(",")}
        self.assertTrue({"no-store", "private"} <= directives)

    def assert_no_unsupported_data(self, message):
        for field in ("name", "server", "password", "type"):
            self.assertNotIn(UNSUPPORTED[field], message)

    def assert_shadowsocks_link(self, link):
        uri = urlsplit(link)
        self.assertEqual(uri.scheme, "ss")
        self.assertEqual(uri.hostname, SUPPORTED["server"])
        self.assertEqual(uri.port, SUPPORTED["port"])
        self.assertEqual(unquote(uri.fragment), SUPPORTED["name"])

    async def test_unsupported_http_exports_return_a_safe_uncacheable_error(self):
        sub = await self.store.add_imported_sub(OWNER, "mixed", [SUPPORTED, UNSUPPORTED])
        async with self.http_session() as (session, origin):
            for path in await self.paths(sub):
                for kind in (*BASE64_KINDS, *SINGBOX_KINDS):
                    with self.subTest(route=path.split("/")[1], kind=kind):
                        async with session.get(f"{origin}{path}/{kind}", allow_redirects=False) as response:
                            self.assertEqual(response.status, 422)
                            self.assertEqual(response.content_type, "text/plain")
                            self.assert_private(response)
                            self.assertEqual(await response.text(), HTTP_ERROR)

    async def test_supported_http_exports_return_normalized_private_content(self):
        sub = await self.store.add_imported_sub(OWNER, "supported", [SUPPORTED])
        await self.store.add_imported_sub(OWNER + 1, "other owner", [UNSUPPORTED])
        async with self.http_session() as (session, origin):
            for path in await self.paths(sub):
                for kind in (*BASE64_KINDS, *SINGBOX_KINDS):
                    with self.subTest(route=path.split("/")[1], kind=kind):
                        async with session.get(f"{origin}{path}/{kind}", allow_redirects=False) as response:
                            self.assertEqual(response.status, 200)
                            self.assert_private(response)
                            body = await response.text()
                            if kind in BASE64_KINDS:
                                self.assertEqual(response.content_type, "text/plain")
                                links = base64.b64decode(body, validate=True).decode("utf-8").splitlines()
                                self.assertEqual(len(links), 1)
                                self.assert_shadowsocks_link(links[0])
                            else:
                                self.assertEqual(response.content_type, "application/json")
                                outbounds = json.loads(body)["outbounds"]
                                self.assertEqual(outbounds[0]["outbounds"], [SUPPORTED["name"]])
                                node = next(ob for ob in outbounds if ob["tag"] == SUPPORTED["name"])
                                self.assertEqual(node["type"], "shadowsocks")
                                self.assertEqual(node["method"], SUPPORTED["cipher"])
                                self.assertEqual(node["server"], SUPPORTED["server"])
                                self.assertEqual(node["server_port"], SUPPORTED["port"])
                                self.assertEqual(node["password"], PASSWORD)

    async def test_access_logs_keep_status_without_capability_urls(self):
        sub = await self.store.add_imported_sub(OWNER, "supported", [SUPPORTED])
        await self.store.add_imported_sub(OWNER, "unsupported", [UNSUPPORTED])
        code = await self.store.create_short(OWNER, "aggregate://all")
        query_marker = "synthetic-query-secret"
        referer_marker = "synthetic-referer-secret"
        requests = ((f"/sub/{sub['token']}/base64", 200), (f"/agg/{code}/singbox", 422))
        with self.assertLogs("aiohttp.access", level="INFO") as logs:
            async with self.http_session() as (session, origin):
                for path, status in requests:
                    async with session.get(
                        f"{origin}{path}",
                        params={"marker": query_marker},
                        headers={"Referer": f"https://referer.example/{referer_marker}"},
                    ) as response:
                        self.assertEqual(response.status, status)
                        await response.read()

        self.assertEqual(len(logs.output), 2)
        for log_entry, (_, status) in zip(logs.output, requests):
            self.assertIn(f"status={status}", log_entry)
            self.assertIn("time=", log_entry)
        logged = "\n".join(logs.output)
        for value in (sub["token"], code, query_marker, referer_marker):
            self.assertNotIn(value, logged)

    async def test_telegram_node_download_rejects_mixed_unconvertible_nodes(self):
        sub = await self.store.add_imported_sub(OWNER, "mixed", [SUPPORTED, UNSUPPORTED])
        update = telegram_update(f"sub:nodes:{sub['id']}")
        await bot.on_callback(update, SimpleNamespace())
        message = update.effective_message
        message.reply_document.assert_not_awaited()
        message.reply_text.assert_awaited_once()
        reply = message.reply_text.await_args.args[0]
        self.assertIn("无法转换", reply)
        self.assert_no_unsupported_data(reply)

    async def test_telegram_node_download_retains_plain_newline_separated_attachment(self):
        userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:test-only:legacy-password").decode("ascii").rstrip("=")
        legacy_link = f"ss://{userinfo}@203.0.113.16:8389#Legacy"
        sub = await self.store.add_imported_sub(OWNER, "supported", [SUPPORTED, *bot.parse_nodes_from_text(legacy_link)])
        update = telegram_update(f"sub:nodes:{sub['id']}")
        await bot.on_callback(update, SimpleNamespace())
        message = update.effective_message
        message.reply_text.assert_not_awaited()
        message.reply_document.assert_awaited_once()
        document = message.reply_document.await_args.kwargs["document"]
        self.assertEqual(document.filename, "Base64.txt")
        links = document.input_file_content.decode("utf-8").splitlines()
        self.assertEqual(len(links), 2)
        self.assert_shadowsocks_link(links[0])
        self.assertEqual(links[1], legacy_link)

    async def test_telegram_format_buttons_reject_unsupported_without_minting_a_short_url(self):
        sub = await self.store.add_imported_sub(OWNER, "mixed", [SUPPORTED, UNSUPPORTED])
        with patch.object(bot, "make_short_url", AsyncMock()) as make_short_url:
            for kind in ("base64", "singbox"):
                with self.subTest(kind=kind):
                    update = telegram_update(f"sub:fmt:{sub['id']}:{kind}")
                    await bot.on_callback(update, SimpleNamespace())
                    message = update.effective_message
                    message.reply_html.assert_not_awaited()
                    message.reply_text.assert_awaited_once()
                    reply = message.reply_text.await_args.args[0]
                    self.assertIn("无法转换", reply)
                    self.assert_no_unsupported_data(reply)
            make_short_url.assert_not_awaited()

    async def test_telegram_base64_button_keeps_supported_subscription_short_link(self):
        sub = await self.store.add_imported_sub(OWNER, "supported", [SUPPORTED])
        short_url = f"{PUBLIC_URL}/s/synthetic-code"
        update = telegram_update(f"sub:fmt:{sub['id']}:base64")
        with patch.object(bot, "make_short_url", AsyncMock(return_value=short_url)) as make_short_url:
            await bot.on_callback(update, SimpleNamespace())
        make_short_url.assert_awaited_once_with(OWNER, f"{PUBLIC_URL}/sub/{sub['token']}/base64")
        message = update.effective_message
        message.reply_text.assert_not_awaited()
        message.reply_html.assert_awaited_once()
        self.assertIn(short_url, message.reply_html.await_args.args[0])

    async def test_telegram_aggregate_export_keeps_clash_and_explains_unavailable_base64(self):
        await self.store.add_imported_sub(OWNER, "mixed", [SUPPORTED, UNSUPPORTED])
        update = telegram_update()
        await bot.cmd_export(update, SimpleNamespace())
        message = update.effective_message
        message.reply_html.assert_awaited_once()
        reply = message.reply_html.await_args.args[0]
        self.assertRegex(reply, r"https://bot\.example/agg/[\w-]+/clash")
        self.assertNotIn("/base64", reply)
        self.assertIn("Base64", reply)
        self.assertRegex(reply, r"无法|不可|不支持")
        self.assert_no_unsupported_data(reply)


if __name__ == "__main__":
    unittest.main()

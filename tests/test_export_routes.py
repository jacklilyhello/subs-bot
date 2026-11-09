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

    async def test_imported_native_singbox_http_transport_guards_raw_request_fields(self):
        node = {
            "type": "vmess", "server": "203.0.113.41", "server_port": 443, "alter_id": 0,
            "uuid": "12345678-1234-4234-8234-123456789012", "security": "aes-128-gcm",
        }
        http1 = {**node, "tag": "Synthetic HTTP1", "transport": {
            "type": "http", "method": "PUT", "path": "/escaped%2Fpath",
            "host": ["front.example.invalid:8443", "[2001:db8::41]:8443"], "headers": {"X-Fixture": ["one", "two"]},
        }}
        http2 = {**node, "tag": "Synthetic HTTP2", "tls": {"enabled": True, "server_name": "tls.example.invalid"},
                 "transport": {"type": "http", "method": "", "path": "", "headers": {"Accept-Encoding": "identity"}}}

        async def upload(name, outbounds):
            raw = json.dumps({"outbounds": outbounds}).encode("utf-8")
            update = telegram_update()
            message = update.effective_message
            message.document = SimpleNamespace(file_name=f"{name}.json", file_size=len(raw), file_id="fixture")
            message.reply_text.return_value = SimpleNamespace(edit_text=AsyncMock())
            file = SimpleNamespace(download_as_bytearray=AsyncMock(return_value=bytearray(raw)))
            context = SimpleNamespace(bot=SimpleNamespace(get_file=AsyncMock(return_value=file)))
            with patch.object(bot, "fetch_subscription", AsyncMock()) as fetch:
                await bot.handle_document(update, context)
                fetch.assert_not_awaited()
            sub = next(sub for sub in await self.store.list_subs(OWNER) if sub["name"] == name)
            self.assertEqual(sub["node_count"], len(outbounds))
            return sub

        bad_fields = {
            "method": {"method": "GET\r\nX-Fixture: marker"},
            "method-space": {"method": "GET /"},
            "host": {"host": ["front.example.invalid", "front.example.invalid\r\nX-Fixture: marker"]},
            "path": {"path": "/fixture\r\nX-Fixture: marker"},
            "header-name": {"headers": {"X-Fixture\r\nX-Extra": "marker"}},
            "header-value": {"headers": {"X-Fixture": "one\r\nX-Extra: marker"}},
            "duplicate-host": {"headers": {"Host": "front.example.invalid", "host": "other.example.invalid"}},
            "multi-value-host": {"headers": {"Host": ["front.example.invalid", "other.example.invalid"]}},
            "content-length": {"headers": {"Content-Length": "0"}},
            "transfer-encoding": {"headers": {"Transfer-Encoding": "chunked"}},
        }
        valid = await upload("safe-http", [http1, http2])
        invalid = {}
        for label, fields in bad_fields.items():
            unsafe = {**node, "tag": "Synthetic refused", "transport": {"type": "http", **fields}}
            invalid[label] = await upload(f"unsafe-http-{label}", [http1, unsafe])

        async with self.http_session() as (session, origin):
            async with session.get(f"{origin}/sub/{valid['token']}/singbox") as response:
                self.assertEqual(response.status, 200)
                self.assertEqual((await response.json())["outbounds"][2:], [http1, http2])
            for label, sub in invalid.items():
                for method in ("GET", "HEAD"):
                    with self.subTest(field=label, method=method):
                        async with session.request(method, f"{origin}/sub/{sub['token']}/sing-box") as response:
                            self.assertEqual(response.status, 422)
                            self.assert_private(response)
                            self.assertEqual(await response.text(), HTTP_ERROR if method == "GET" else "")
            for path in (await self.paths(invalid["method"]))[1:]:
                with self.subTest(route=path.split("/")[1]):
                    async with session.get(f"{origin}{path}/singbox") as response:
                        self.assertEqual(response.status, 422)
                        self.assertEqual(await response.text(), HTTP_ERROR)

        update = telegram_update(f"sub:fmt:{invalid['method']['id']}:singbox")
        with patch.object(bot, "make_short_url", AsyncMock(return_value="https://example.invalid/s/synthetic")) as make_short_url:
            await bot.on_callback(update, SimpleNamespace())
        make_short_url.assert_not_awaited()
        update.effective_message.reply_html.assert_not_awaited()
        update.effective_message.reply_text.assert_awaited_once_with(bot._EXPORT_UNSUPPORTED)

    async def test_selected_aggregate_keeps_order_and_does_not_follow_a_restored_id(self):
        first_node = {**SUPPORTED, "name": "First fixture", "server": "203.0.113.11"}
        stale_node = {**SUPPORTED, "name": "Restored fixture", "server": "203.0.113.12"}
        second_node = {**SUPPORTED, "name": "Second fixture", "server": "203.0.113.13"}
        foreign_node = {**SUPPORTED, "name": "Foreign fixture", "server": "203.0.113.14"}
        first = await self.store.add_imported_sub(OWNER, "first", [first_node])
        stale = await self.store.add_imported_sub(OWNER, "stale", [stale_node])
        second = await self.store.add_imported_sub(OWNER, "second", [second_node])
        foreign = await self.store.add_imported_sub(OWNER + 1, "foreign", [foreign_node])
        userinfo = base64.urlsafe_b64encode(f"aes-256-gcm:{PASSWORD}".encode("ascii")).decode("ascii").rstrip("=")
        await self.store.add_temp(OWNER, f"ss://{userinfo}@203.0.113.16:8388#Temporary", "Temporary")

        async def selected(*rows):
            ids = ",".join(str(row["id"]) for row in rows)
            return await self.store.create_short(OWNER, f"aggregate://ids/{ids}")

        ordered_code = await selected(second, stale, first, second)
        empty_code = await selected(stale, foreign)
        async with self.http_session() as (session, origin):
            async def assert_export(code, *nodes):
                url = f"{origin}/agg/{code}/base64"
                async with session.get(url, allow_redirects=False) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.content_type, "text/plain")
                    self.assert_private(response)
                    encoded = await response.read()
                    links = base64.b64decode(encoded, validate=True).decode("utf-8").splitlines()
                    actual = [(unquote(uri.fragment), uri.hostname, uri.port) for uri in map(urlsplit, links)]
                    self.assertEqual(actual, [(node["name"], node["server"], node["port"]) for node in nodes])
                async with session.head(url, allow_redirects=False) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.content_type, "text/plain")
                    self.assert_private(response)
                    self.assertEqual(response.content_length, len(encoded))
                    self.assertEqual(await response.read(), b"")

            await assert_export(ordered_code, second_node, stale_node, first_node, second_node)
            self.assertTrue(await self.store.delete_sub(OWNER, stale["id"]))
            await assert_export(ordered_code, second_node, first_node, second_node)

            deleted, = await self.store.list_deleted(OWNER)
            restored = await self.store.restore_deleted(OWNER, deleted["id"])
            self.assertIsNotNone(restored)
            self.assertGreater(restored["id"], foreign["id"])
            self.assertEqual(restored["token"], stale["token"])
            # The legacy selection stores IDs. The restore preserves the token and allocates a new ID.
            await assert_export(ordered_code, second_node, first_node, second_node)
            await assert_export(empty_code)
            await assert_export(await selected(restored), stale_node)

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

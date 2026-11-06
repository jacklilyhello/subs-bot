"""Subscription fetch safety regressions. No network."""
from __future__ import annotations

import asyncio
import socket
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aiohttp import InvalidURL, StreamReader

from convert import MAX_SUBSCRIPTION_BYTES, fetch_subscription  # noqa: E402


class FakeContent:
    def __init__(self, body: bytes):
        self.body = body
        self.offset = 0

    async def read(self, limit: int) -> bytes:
        chunk = self.body[self.offset:self.offset + limit]
        self.offset += len(chunk)
        return chunk


class FakeResponse:
    def __init__(self, status: int, *, headers=None, body: bytes = b""):
        self.status = status
        self.headers = headers or {}
        self.charset = "utf-8"
        self.content = FakeContent(body)

    async def __aenter__(self):
        return self

    async def __aexit__(self, _type, _value, _tb):
        return False


class FakeSession:
    def __init__(self, responses):
        self.responses = list(responses)
        self.urls: list[str] = []

    def get(self, url: str, **_kwargs):
        self.urls.append(url)
        return self.responses.pop(0)


async def test_redirect_target_is_revalidated():
    session = FakeSession([
        FakeResponse(302, headers={"Location": "http://127.0.0.1/internal"}),
    ])
    def resolve(host, _port):
        address = "127.0.0.1" if host == "127.0.0.1" else "8.8.8.8"
        return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (address, 0))]

    with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
        "convert.socket.getaddrinfo", side_effect=resolve
    ) as dns:
        nodes, _meta, error = await fetch_subscription("https://public.example/sub")
    assert nodes == []
    assert error == "URL 指向内网/保留地址"
    assert [call.args for call in dns.call_args_list] == [("public.example", None), ("127.0.0.1", None)]
    assert session.urls == ["https://public.example/sub"]


async def test_response_size_is_capped():
    session = FakeSession([
        FakeResponse(200, body=b"x" * (MAX_SUBSCRIPTION_BYTES + 1)),
    ])
    with patch("convert.get_session", new=AsyncMock(return_value=session)):
        with patch("convert._check_public_url", new=AsyncMock()):
            nodes, _meta, error = await fetch_subscription("https://public.example/sub")
    assert nodes == []
    assert error == "订阅响应过大"


async def test_fetch_error_does_not_include_the_provider_url():
    url = "https://public.example/sub?access=synthetic-provider-marker"
    session = FakeSession([])
    session.get = Mock(side_effect=InvalidURL(url))
    with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
        "convert._check_public_url", new=AsyncMock()
    ):
        nodes, _meta, error = await fetch_subscription(url)
    assert nodes == []
    assert error == "订阅请求失败"


async def test_fetch_error_does_not_include_dns_or_parser_data():
    url = "https://public.example/sub"
    session = FakeSession([FakeResponse(200, body=b"synthetic-response-marker")])
    with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
        "convert.socket.getaddrinfo", side_effect=socket.gaierror("synthetic-dns-marker")
    ):
        assert (await fetch_subscription(url))[2] == "主机名解析失败"
    with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
        "convert._check_public_url", new=AsyncMock()
    ), patch("convert.parse_nodes_from_text_with_report", side_effect=ValueError("synthetic-response-marker")):
        assert (await fetch_subscription(url))[2] == "订阅处理失败"


async def test_fetch_error_preserves_timeout_category():
    session = FakeSession([])
    session.get = Mock(side_effect=TimeoutError("synthetic-timeout-marker"))
    with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
        "convert._check_public_url", new=AsyncMock()
    ):
        assert (await fetch_subscription("https://public.example/sub"))[2] == "订阅请求超时"


async def test_fragmented_response_is_read_to_eof():
    body = (
        b'proxies:\n  - name: streamed\n    type: ss\n'
        b'    server: example.com\n    port: 443\n'
        b'    cipher: aes-256-gcm\n    password: secret\n'
    )
    protocol = Mock(_reading_paused=False)
    reader = StreamReader(protocol, limit=2**16)
    reader.feed_data(body[:18])
    response = FakeResponse(200)
    response.content = reader
    session = FakeSession([response])

    async def finish_body():
        await asyncio.sleep(0)
        reader.feed_data(body[18:])
        reader.feed_eof()

    producer = asyncio.create_task(finish_body())
    try:
        with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
            "convert._check_public_url", new=AsyncMock()
        ):
            nodes, _meta, error = await fetch_subscription("https://public.example/sub")
    finally:
        await producer
    assert error is None
    assert nodes == [{
        "name": "streamed", "type": "ss", "server": "example.com",
        "port": 443, "cipher": "aes-256-gcm", "password": "secret", "share": "",
    }]


async def test_response_exactly_at_limit_is_accepted():
    body = b"#" + b" " * (MAX_SUBSCRIPTION_BYTES - 1)
    session = FakeSession([FakeResponse(200, body=body)])
    with patch("convert.get_session", new=AsyncMock(return_value=session)), patch(
        "convert._check_public_url", new=AsyncMock()
    ):
        nodes, _meta, error = await fetch_subscription("https://public.example/sub")
    assert error is None
    assert nodes == []


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            asyncio.run(fn())
            print("ok", name)
    print("all passed")

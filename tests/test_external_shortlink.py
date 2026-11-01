"""External short-link integration: success wraps the local code, every failure falls back. No network."""
from __future__ import annotations

import asyncio
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

_tmp = tempfile.mkdtemp(prefix="subs-shortlink-")
os.environ["BOT_TOKEN"] = "0:TEST"
os.environ["DATA_DIR"] = _tmp
os.environ["DB_PATH"] = str(Path(_tmp) / "shortlink.db")
os.environ["PUBLIC_BASE_URL"] = "https://bot.example"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import bot  # noqa: E402

TARGET = "https://bot.example/sub/secret-token/clash"
LOCAL_PREFIX = "https://bot.example/s/"
SHORTENER = {
    "SHORTLINK_API_URL": "https://shortener.example/api/shorten",
    "SHORTLINK_TOKEN": "test-token",
    "SHORTLINK_DOMAIN": "s.example",
}


class FakeResponse:
    def __init__(self, status: int, payload):
        self.status = status
        self._payload = payload

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_exc):
        return False

    async def json(self, content_type=None):
        if isinstance(self._payload, Exception):
            raise self._payload
        return self._payload


class FakeSession:
    def __init__(self, outcome):
        self.outcome = outcome
        self.requests: list[dict] = []

    def post(self, url, **kwargs):
        self.requests.append({"url": url, **kwargs})
        if isinstance(self.outcome, Exception):
            raise self.outcome
        return self.outcome


async def shorten_with(outcome, **config) -> tuple[str, FakeSession]:
    session = FakeSession(outcome)
    with patch.multiple(bot, **{**SHORTENER, **config}, get_session=AsyncMock(return_value=session)):
        short = await bot.make_short_url(1, TARGET)
    return short, session


async def resolves_to_target(url: str) -> bool:
    if not url.startswith(LOCAL_PREFIX):
        return False
    row = await bot.store.get_short(url.removeprefix(LOCAL_PREFIX))
    return row is not None and row["target_url"] == TARGET


async def test_external_link_only_sees_local_code():
    ok = {"ok": True, "data": {"slug": "Ab9xQ2mR", "short_url": "https://s.example/Ab9xQ2mR"}}
    short, session = await shorten_with(FakeResponse(201, ok))
    assert short == "https://s.example/Ab9xQ2mR"
    sent = session.requests[0]["json"]
    assert sent["domain"] == "s.example"
    # The third party receives the revocable local link, never the subscription token URL.
    assert await resolves_to_target(sent["url"])


async def test_failures_fall_back_to_working_local_link():
    outcomes = {
        "network error": OSError("unreachable"),
        "waf block": FakeResponse(403, None),
        "api error": FakeResponse(401, {"ok": False, "error": {"code": "TOKEN_INVALID"}}),
        "malformed json": FakeResponse(201, ValueError("not json")),
        "foreign host": FakeResponse(201, {"ok": True, "data": {"short_url": "https://evil.example/x"}}),
        "plain http": FakeResponse(201, {"ok": True, "data": {"short_url": "http://s.example/x"}}),
    }
    for label, outcome in outcomes.items():
        short, _ = await shorten_with(outcome)
        assert await resolves_to_target(short), label


async def test_unconfigured_or_plaintext_api_never_calls_out():
    configs = {
        "unconfigured": {"SHORTLINK_API_URL": "", "SHORTLINK_TOKEN": "", "SHORTLINK_DOMAIN": ""},
        "plaintext api": {"SHORTLINK_API_URL": "http://shortener.example/api/shorten"},
    }
    for label, config in configs.items():
        short, session = await shorten_with(FakeResponse(201, {}), **config)
        assert session.requests == [], label
        assert await resolves_to_target(short), label


async def main() -> None:
    await bot.store.init()
    try:
        for name, fn in list(globals().items()):
            if name.startswith("test_"):
                await fn()
                print("ok", name)
    finally:
        await bot.store.close()
    print("all passed")


if __name__ == "__main__":
    asyncio.run(main())

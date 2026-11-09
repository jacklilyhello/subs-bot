"""Fixed legacy dynamic aggregate lifecycle over the actual Python HTTP routes."""

import asyncio
from base64 import b64encode
from contextlib import asynccontextmanager
from hashlib import sha256
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
from platform import python_version
import resource
import socket
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
OWNER = 74102
OTHER = 74103
EMPTY_KINDS = ("base64", "v2ray", "mixed", "clash", "unknown-format", "singbox", "sing-box",
               "surge", "qx", "quantumult", "quantumultx")
HEADER_NAMES = {
    "contentType": "Content-Type", "cacheControl": "Cache-Control",
    "contentLength": "Content-Length", "location": "Location",
}


def require(condition):
    if not condition:
        raise RuntimeError("Legacy dynamic aggregate observation differed.")


def verify_sandbox():
    require(sys.platform == "linux" and os.geteuid() != 0 and [name for _, name in socket.if_nameindex()] == ["lo"]
            and resource.getrlimit(resource.RLIMIT_CORE)[0] == 0 and not os.path.lexists(ROOT / ".env")
            and python_version() == "3.11.18" and version("aiohttp") == "3.11.18" and version("yarl") == "1.20.0")


def share(name):
    return f"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#{name}"


@asynccontextmanager
async def legacy_http(root):
    verify_sandbox()
    os.environ.update(BOT_TOKEN="0:TEST", DATA_DIR=str(root), DB_PATH=str(root / "legacy.sqlite"),
                      HTTP_HOST="127.0.0.1")
    logging.disable(logging.CRITICAL)
    sys.path.insert(0, str(ROOT))
    import bot
    from aiohttp import ClientSession, ClientTimeout

    store = bot.store
    bot.HTTP_PORT = 0
    await store.init()
    runner = None
    try:
        runner = await bot.start_http(None)
        (host, port), = runner.addresses
        require(host == "127.0.0.1")
        async with ClientSession(timeout=ClientTimeout(total=5), trust_env=False, auto_decompress=False,
                                 headers={"Accept-Encoding": "identity"}) as session:
            yield store, session, f"http://{host}:{port}"
    finally:
        if runner is not None:
            await runner.cleanup()
        await store.close()


async def capture(session, origin, case):
    code, kind = case["code"], case["format"]
    path = f"/s/{code}" if case["route"] == "short" else f"/agg/{code}" + (f"/{kind}" if kind else "")
    async with session.request(case["method"], origin + path, allow_redirects=False) as response:
        body = bytearray()
        async for block in response.content.iter_chunked(1024):
            body.extend(block)
            require(len(body) <= 4096)
        return {"status": response.status, "body": bytes(body),
                **{field: response.headers.get(name) for field, name in HEADER_NAMES.items()}}


async def observe(root):
    async with legacy_http(root) as (store, session, origin):
        code = await store.create_short(OWNER, "aggregate://all")
        require(len(code) == 12)
        active = {}
        tokens = {}

        async def add(name, owner=OWNER):
            row = await store.add_imported_sub(owner, name, [{"name": name, "type": "ss",
                "server": "203.0.113.10", "port": 8388, "cipher": "aes-256-gcm", "password": "fixture", "share": share(name)}])
            if owner == OWNER:
                active[name], tokens[name] = row["id"], row["token"]

        async def remove(name):
            require(await store.delete_sub(OWNER, active[name]))

        async def restore(name):
            matches = [row for row in await store.list_deleted(OWNER) if row["name"] == name]
            require(len(matches) == 1)
            row = await store.restore_deleted(OWNER, matches[0]["id"])
            require(row and row["id"] > active[name] and row["token"] == tokens[name])
            active[name] = row["id"]

        observations = []

        async def wire(kind):
            case = {"route": "aggregate", "code": code, "format": kind}
            get, head = [await capture(session, origin, {**case, "method": method}) for method in ("GET", "HEAD")]
            body, media = get["body"], get["contentType"]
            require(get["status"] == head["status"] == 200 and get["cacheControl"] == "no-store, private"
                    and head["contentType"] == media and head["contentLength"] in (None, str(len(body))) and head["body"] == b"")
            return body, {"media": media, "bytes": len(body), "sha256": sha256(body).hexdigest()}

        async def phase(*names):
            body, record = await wire("base64")
            require(body == b64encode("\n".join(map(share, names)).encode()))
            observations.append(record)

        for name in ("alpha", "beta", "gamma"):
            await add(name)
        await add("foreign-sub", OTHER)
        await store.add_temp(OWNER, share("temporary"), "legacy temporary")
        await store.add_temp(OTHER, share("foreign-temp"), "foreign temporary")
        await phase("alpha", "beta", "gamma", "temporary")
        await remove("alpha")
        await remove("beta")
        await phase("gamma", "temporary")
        await restore("beta")
        await phase("gamma", "beta", "temporary")
        await restore("alpha")
        await phase("gamma", "beta", "alpha", "temporary")
        await add("delta")
        await phase("gamma", "beta", "alpha", "delta", "temporary")
        await remove("gamma")
        await restore("gamma")
        await phase("beta", "alpha", "delta", "gamma", "temporary")
        for name in active:
            await remove(name)
        require(await store.clear_temp(OWNER) == 1)
        empty = {kind: (await wire(kind))[1] for kind in EMPTY_KINDS}
        for method in ("GET", "HEAD"):
            short = await capture(session, origin, {"route": "short", "method": method, "code": code, "format": None})
            require(short["status"] == 302 and short["location"] == f"/agg/{code}/clash")
            omitted = await capture(session, origin, {"route": "aggregate", "method": method, "code": code, "format": None})
            require(omitted["status"] == 404)
    return {"phases": observations, "empty": empty}


async def observe_candidate(root, cases, fixture):
    """Observe only the fixed V8 synthetic source copied into this scratch directory."""
    owner, foreign = int(fixture.OWNER), int(fixture.FOREIGN_OWNER)
    async with legacy_http(root) as (store, session, origin):
        old = [await capture(session, origin, case) for case in cases["active"]]
        trash = await store.list_deleted(owner)
        require(len(trash) == 1 and trash[0]["id"] == fixture.LEGACY_TRASH_ID
                and trash[0]["token"] == fixture.fixture_token("trash"))
        async with store.connection() as db:
            async with db.execute("SELECT seq FROM sqlite_sequence WHERE name='subscriptions'") as cursor:
                high = await cursor.fetchone()
        require(high is not None and type(high[0]) is int and high[0] >= fixture.FOREIGN_ID)
        require(await store.restore_deleted(foreign, fixture.LEGACY_TRASH_ID) is None)
        restored = await store.restore_deleted(owner, fixture.LEGACY_TRASH_ID)
        require(restored and restored["id"] > high[0] and restored["token"] == trash[0]["token"])
        return {"active": old, "restored": [await capture(session, origin, case) for case in cases["restored"]]}


if __name__ == "__main__":
    try:
        with TemporaryDirectory(prefix="legacy-dynamic-all-") as directory:
            print(json.dumps(asyncio.run(observe(Path(directory))), sort_keys=True))
    except Exception:
        raise SystemExit("The offline Python dynamic aggregate observation could not be confirmed.") from None

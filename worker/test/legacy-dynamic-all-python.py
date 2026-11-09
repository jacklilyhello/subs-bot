"""Fixed legacy dynamic aggregate lifecycle over the actual Python HTTP routes."""

import asyncio
from base64 import b64encode
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


def require(condition):
    if not condition:
        raise RuntimeError("Legacy dynamic aggregate observation differed.")


def share(name):
    return f"ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#{name}"


async def observe(root):
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
        origin = f"http://{host}:{port}"
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

        async with ClientSession(timeout=ClientTimeout(total=5), trust_env=False, auto_decompress=False,
                                 headers={"Accept-Encoding": "identity"}) as session:
            observations = []

            async def wire(kind):
                url = f"{origin}/agg/{code}/{kind}"
                async with session.get(url, allow_redirects=False) as response:
                    body = bytearray()
                    async for block in response.content.iter_chunked(1024):
                        body.extend(block)
                        require(len(body) <= 4096)
                    require(response.status == 200 and response.headers.get("Cache-Control") == "no-store, private")
                    media = response.headers.get("Content-Type")
                async with session.head(url, allow_redirects=False) as response:
                    require(response.status == 200 and response.headers.get("Content-Type") == media
                            and response.headers.get("Content-Length") in (None, str(len(body)))
                            and await response.read() == b"")
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
                async with session.request(method, f"{origin}/s/{code}", allow_redirects=False) as response:
                    require(response.status == 302 and response.headers.get("Location") == f"/agg/{code}/clash")
                async with session.request(method, f"{origin}/agg/{code}", allow_redirects=False) as response:
                    require(response.status == 404)
        return {"phases": observations, "empty": empty}
    finally:
        if runner is not None:
            await runner.cleanup()
        await store.close()


if __name__ == "__main__":
    try:
        require(sys.platform == "linux" and os.geteuid() != 0 and [name for _, name in socket.if_nameindex()] == ["lo"]
                and resource.getrlimit(resource.RLIMIT_CORE)[0] == 0 and not os.path.lexists(ROOT / ".env")
                and python_version() == "3.11.18" and version("aiohttp") == "3.11.18" and version("yarl") == "1.20.0")
        with TemporaryDirectory(prefix="legacy-dynamic-all-") as directory:
            print(json.dumps(asyncio.run(observe(Path(directory))), sort_keys=True))
    except Exception:
        raise SystemExit("The offline Python dynamic aggregate observation could not be confirmed.") from None

"""Private Container HTTP protocol reached by the project-owned Durable Object."""

import asyncio
from base64 import urlsafe_b64encode
from hashlib import sha256
from ipaddress import ip_network
import json
import logging
from pathlib import Path
import re

from aiohttp import web

from transport import FetchFailure, fetch_provider, probe_api_status


PORT = 8080
MAX_REQUEST = 12 * 1024
ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev/health"
HEADERS = {"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff"}
# Cloudflare's published IPv4 and IPv6 proxy ranges. This gate only narrows the smoke target.
CF_EDGE = tuple(map(ip_network, (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)))


def problem(code, status):
    return web.json_response({"error": code}, status=status, headers=HEADERS)


def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError()
    return result


def reply(result, families=()):
    if isinstance(result, FetchFailure):
        if result.code == "http-status":
            upstream = result.upstream_status
            if type(upstream) is int and 100 <= upstream <= 599 and upstream != 200:
                return web.json_response({"error": "http-status", "upstreamStatus": upstream}, status=502, headers=HEADERS)
            return problem("unavailable", 502)
        status = 504 if result.code == "timeout" else 422 if result.code in {"invalid-url", "blocked-address"} else 502
        return problem(result.code, status)
    headers = {**HEADERS, "X-Provider-Body-Sha256": sha256(result.body).hexdigest()}
    if families:
        headers["X-Provider-Approved-Families"] = ",".join(map(str, sorted(families)))
    metadata = json.dumps(result.headers, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    if len(metadata) <= 3072:
        headers["X-Provider-Metadata"] = urlsafe_b64encode(metadata).decode("ascii")
    return web.Response(body=result.body, content_type="application/octet-stream", headers=headers)


def application(revision):
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Provider build revision is invalid.")
    busy = False

    async def handle(request):
        nonlocal busy
        if request.host != "container":
            return problem("not-found", 404)
        if (request.method, request.raw_path) == ("GET", "/ready"):
            return web.json_response({"ok": True, "revision": revision}, headers=HEADERS)
        if request.method != "POST" or request.raw_path not in {"/v1/fetch", "/v1/edge-proof", "/v1/api-status"}:
            return problem("not-found", 404)
        if (request.headers.getall("Content-Type", []) != ["application/json"]
                or request.headers.getall("Content-Encoding", [])):
            return problem("invalid-request", 400)
        if request.content_length is not None and request.content_length > MAX_REQUEST:
            return problem("invalid-request", 413)
        if busy:
            return problem("busy", 429)
        busy = True
        try:
            async with asyncio.timeout(3):
                raw = await request.read()
            if len(raw) > MAX_REQUEST:
                return problem("invalid-request", 413)
            body = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
            if request.raw_path == "/v1/fetch" and isinstance(body, dict) and set(body) == {"url"} and isinstance(body["url"], str):
                return reply(await fetch_provider(body["url"]))
            if request.raw_path == "/v1/api-status" and isinstance(body, dict) and set(body) == {"url", "key"}:
                if not isinstance(body["url"], str) or not isinstance(body["key"], str):
                    return problem("invalid-request", 400)
                status = await probe_api_status(body["url"], body["key"])
                if isinstance(status, FetchFailure):
                    return reply(status)
                return web.json_response({"status": status.status, "elapsedMs": status.elapsed_ms}, headers=HEADERS)
            if request.raw_path == "/v1/edge-proof" and body == {}:
                families = set()

                def edge_only(addresses):
                    if not addresses or not all(any(address in network for network in CF_EDGE) for address in addresses):
                        return False
                    families.update(address.version for address in addresses)
                    return True

                result = await fetch_provider(ORIGIN, address_policy=edge_only, follow_redirects=False,
                                              user_agent="subs-bot-isolation-release/1.0")
                return reply(result, families)
            return problem("invalid-request", 400)
        except web.HTTPRequestEntityTooLarge:
            return problem("invalid-request", 413)
        except (ValueError, RecursionError, TimeoutError):
            return problem("invalid-request", 400)
        except Exception:
            return problem("unavailable", 503)
        finally:
            busy = False

    quiet = logging.Logger("provider-private")
    quiet.addHandler(logging.NullHandler())
    app = web.Application(logger=quiet, client_max_size=MAX_REQUEST + 1, handler_args={
        "auto_decompress": False, "max_headers": 32, "max_line_size": 4096, "max_field_size": 4096,
    })
    app.router.add_route("*", "/{path:.*}", handle)
    return app


if __name__ == "__main__":
    revision = Path(__file__).with_name("revision").read_text(encoding="ascii").strip()
    web.run_app(application(revision), host="0.0.0.0", port=PORT, access_log=None, print=None, handler_cancellation=True)

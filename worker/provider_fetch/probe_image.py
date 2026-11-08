"""Probe the actual hosted OCI runtime over loopback with networking disabled."""

from http.client import HTTPConnection
import json
import os
import sys
from time import monotonic, sleep, time_ns


def require(value):
    if not value:
        raise RuntimeError("Hosted provider image check differed from its expected result.")


def request(method, path, payload=None, host="container"):
    connection = HTTPConnection("127.0.0.1", 8080, timeout=2)
    try:
        headers = {"Host": host}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        connection.request(method, path, None if payload is None else json.dumps(payload), headers)
        with connection.getresponse() as response:
            require(response.getheader("Cache-Control") == "private, no-store")
            return response.status, json.loads(response.read(1025))
    finally:
        connection.close()


def main(revision):
    require(os.getuid() == os.getgid() == 65532 and os.access("/etc/ssl/certs/ca-certificates.crt", os.R_OK))
    require(not any(name.startswith(("CLOUDFLARE_", "SUBS_BOT_", "GH_", "TELEGRAM_")) for name in os.environ))
    deadline = monotonic() + 8
    while True:
        try:
            status, body = request("GET", "/ready")
            break
        except OSError:
            require(monotonic() < deadline)
            sleep(0.1)
    require((status, body) == (200, {"ok": True, "revision": revision}))
    require(request("GET", "/ready", host="foreign.example") == (404, {"error": "not-found"}))
    for url in ("http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/"):
        require(request("POST", "/v1/fetch", {"url": url}) == (422, {"error": "blocked-address"}))
    require(request("POST", "/v1/edge-proof", {"url": "https://fixture.example/"}) == (400, {"error": "invalid-request"}))
    for url in ("https://127.0.0.1/v1/models", "https://[::1]/v1/models", "https://169.254.169.254/v1/models"):
        require(request("POST", "/v1/api-status", {"url": url, "key": "synthetic-probe-key"}) ==
                (422, {"error": "blocked-address"}))
    v2 = {"url": "https://127.0.0.1/v1/models", "key": "synthetic-probe-key"}
    require(request("POST", "/v2/api-status", {**v2, "dispatchBeforeMs": 1}) == (504, {"error": "timeout"}))
    require(request("POST", "/v2/api-status", {**v2, "dispatchBeforeMs": time_ns() // 1_000_000 + 25_000}) ==
            (422, {"error": "blocked-address"}))
    print("Hosted nonroot provider image and private port policy verified.")


if __name__ == "__main__":
    main(sys.argv[1])

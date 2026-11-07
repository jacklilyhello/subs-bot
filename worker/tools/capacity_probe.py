"""Measure fixed synthetic fixtures through the dedicated Worker over HTTPS."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException, HTTPSConnection
import json
import os
from pathlib import Path
import re
from socket import SHUT_RDWR
from statistics import median
import sys
from threading import Barrier, BrokenBarrierError, Lock, Timer
from time import monotonic, sleep

from capacity_fixtures import CLASH_SMOKE, SINGBOX_SMOKE, SMOKE_OBJECT_LIMIT, SMOKE_PROFILES, STRUCTURED_SMOKE, canonical_config


HOST = "subs-bot-cf-dev-01.lilyya.workers.dev"
MAX_REQUESTS = 18
RUN_SECONDS = 420
REQUEST_SECONDS = 90
SOCKET_SECONDS = 30
READ_BYTES = 128 * 1024
CANCEL_BYTES = 64 * 1024
SLOW_INTERVAL_BYTES = 1024 * 1024
SLOW_PAUSE_SECONDS = 0.25
MAX_CHUNK_BYTES = 512 * 1024
MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024
MAX_SHARE_BYTES = 16 * 1024 * 1024
MAX_NODES = 100_000
MAX_CAPACITY_JSON_BYTES = 64 * 1024
MAX_SMALL_BODY_BYTES = 1024
SHA1 = re.compile(r"[0-9a-f]{40}")
SHA256 = re.compile(r"[0-9a-f]{64}")
UUID4 = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
TOKEN = re.compile(r"subsbot-synthetic-capacity-[A-Za-z0-9_-]{1,102}")
FIXTURE_STATUS = {"at-limits": 200, "share-over": 422, "snapshot-over": 503}
ERROR_BODY = {
    422: b"Subscription content cannot be exported.",
    503: b"Subscription temporarily unavailable.",
}


class ProbeError(RuntimeError):
    """A static, safe-to-report failure without a request target or body."""


@dataclass(frozen=True)
class Fixture:
    label: str
    token: str
    status: int
    export_bytes: int
    export_sha256: str | None


@dataclass(frozen=True)
class Sample:
    status: int
    elapsed_ms: int
    body_bytes: int
    first_body_byte_ms: int | None = None
    body_bytes_per_second: int | None = None


def _matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _load_fixtures(directory, revision):
    if not _matches(SHA1, revision):
        raise ProbeError("An exact GITHUB_SHA is required.")
    try:
        with (Path(directory) / "capacity.json").open("rb") as file:
            raw = file.read(MAX_CAPACITY_JSON_BYTES + 1)
        if len(raw) > MAX_CAPACITY_JSON_BYTES:
            raise ProbeError("The capacity manifest exceeds its size limit.")
        data = json.loads(raw)
    except (OSError, ValueError, RecursionError):
        raise ProbeError("The capacity manifest could not be read.") from None
    if (not isinstance(data, dict) or not _integer(data.get("version"), 1, 1)
            or data.get("revision") != revision or not isinstance(data.get("fixtures"), list)
            or len(data["fixtures"]) != len(FIXTURE_STATUS)):
        raise ProbeError("The capacity manifest version, revision, or fixture count differs.")

    fixtures = {}
    tokens = set()
    snapshot_ids = set()
    for row in data["fixtures"]:
        if not isinstance(row, dict) or not isinstance(row.get("label"), str):
            raise ProbeError("The capacity fixture descriptor is invalid.")
        label = row["label"]
        token = row.get("token")
        snapshot_id = row.get("snapshotId")
        status = FIXTURE_STATUS.get(label)
        if (status is None or label in fixtures or not _integer(row.get("status"), status, status)
                or not _matches(TOKEN, token) or token in tokens
                or not _matches(UUID4, snapshot_id) or snapshot_id in snapshot_ids
                or row.get("manifestFile") != f"{label}/manifest.json" or not _matches(SHA256, row.get("manifestSha256"))):
            raise ProbeError("The capacity fixture identity is invalid.")

        node_count, node_bytes = row.get("nodeCount"), row.get("nodeBytes")
        share_bytes, export_bytes = row.get("shareBytes"), row.get("exportBytes")
        digest, chunks = row.get("exportSha256"), row.get("chunks")
        if (not _integer(node_count, 1, MAX_NODES) or not _integer(node_bytes, 1, MAX_SNAPSHOT_BYTES + 1)
                or not _integer(share_bytes, 0, MAX_SHARE_BYTES + 1)
                or not _integer(export_bytes, 0, 4 * ((MAX_SHARE_BYTES + 2) // 3))
                or not isinstance(chunks, list) or len(chunks) > 256):
            raise ProbeError("The capacity fixture dimensions are invalid.")
        if status == 200:
            if ((node_count, node_bytes, share_bytes) != (MAX_NODES, MAX_SNAPSHOT_BYTES, MAX_SHARE_BYTES)
                    or export_bytes != 4 * ((share_bytes + 2) // 3) or not _matches(SHA256, digest)):
                raise ProbeError("The successful fixture does not match the exact size limits.")
        elif export_bytes != 0 or digest is not None:
            raise ProbeError("A rejected fixture cannot declare an export body.")
        if status == 422 and (share_bytes != MAX_SHARE_BYTES + 1 or node_bytes > MAX_SNAPSHOT_BYTES):
            raise ProbeError("The share-limit rejection fixture has the wrong size.")
        if status == 503 and (node_bytes != MAX_SNAPSHOT_BYTES + 1 or share_bytes != 0 or chunks):
            raise ProbeError("The snapshot-limit rejection fixture has the wrong size.")

        if status != 503:
            total_bytes = total_count = 0
            for index, chunk in enumerate(chunks):
                if (not isinstance(chunk, dict) or chunk.get("file") != f"{label}/{index}.ndjson"
                        or not _integer(chunk.get("bytes"), 1, MAX_CHUNK_BYTES)
                        or not _integer(chunk.get("count"), 1, MAX_NODES) or not _matches(SHA256, chunk.get("sha256"))):
                    raise ProbeError("A capacity fixture chunk descriptor is invalid.")
                total_bytes += chunk["bytes"]
                total_count += chunk["count"]
            if (total_bytes, total_count) != (node_bytes, node_count):
                raise ProbeError("The capacity fixture chunk totals differ.")
        fixtures[label] = Fixture(label, token, status, export_bytes, digest)
        tokens.add(token)
        snapshot_ids.add(snapshot_id)
    return fixtures


def _remaining(deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise ProbeError("The capacity probe reached its deadline.")
    return remaining


def _abort_socket(sock):
    try:
        sock.shutdown(SHUT_RDWR)
    except OSError:
        pass


@contextmanager
def _request(method, path, deadline, label="probe"):
    # Direct HTTPS verifies the fixed hostname. No proxy, auth, cookies, or redirect handler.
    connection = HTTPSConnection(HOST, timeout=min(SOCKET_SECONDS, _remaining(deadline)))
    timer = None
    stage = "connection"
    try:
        connection.connect()
        # A peer making steady partial progress still cannot hold an open request past its deadline.
        timer = Timer(_remaining(deadline), _abort_socket, (connection.sock,))
        timer.daemon = True
        timer.start()
        stage = "response headers"
        connection.request(method, path, headers={
            "Accept-Encoding": "identity", "Connection": "close", "User-Agent": "subs-bot-isolation-release/1.0",
        })
        with connection.getresponse() as response:
            stage = "response body"
            yield response
    except (HTTPException, OSError):
        raise ProbeError(f"HTTPS request failed or timed out during {stage} for {method} {label}.") from None
    finally:
        if timer is not None:
            timer.cancel()
        connection.close()


def _check_headers(response, expected_status, label, media_type):
    if response.status != expected_status:
        raise ProbeError(f"Unexpected HTTP status {response.status} for {label}.")
    cache = {value.strip().lower() for value in response.getheader("Cache-Control", "").split(",")}
    if (cache != {"private", "no-store"} or response.getheader("Referrer-Policy") != "no-referrer"
            or response.getheader("X-Content-Type-Options") != "nosniff"
            or response.getheader("Age") is not None
            or response.getheader("CF-Cache-Status", "").upper() not in {"", "DYNAMIC", "BYPASS"}
            or response.getheader("Set-Cookie") is not None or response.getheader("Location") is not None):
        raise ProbeError(f"Response privacy headers differ for {label}.")
    if (response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != media_type
            or response.getheader("Content-Encoding", "identity").lower() != "identity"):
        raise ProbeError(f"Response media type or encoding differs for {label}.")


def _small_body(response):
    data = response.read(MAX_SMALL_BODY_BYTES + 1)
    if len(data) > MAX_SMALL_BODY_BYTES:
        raise ProbeError("A health or rejected response exceeds its size limit.")
    return data


def _verify_health(response, revision):
    body = _small_body(response)
    try:
        data = json.loads(body)
    except (ValueError, RecursionError):
        raise ProbeError("The Worker health response is malformed.") from None
    if (not isinstance(data, dict) or data.get("ok") is not True
            or data != {"ok": True, "service": "subs-bot", "revision": revision}):
        raise ProbeError("The Worker health response differs from the exact expected revision.")
    return len(body)


def _verify_export(response, fixture, mode, deadline):
    if (response.getheader("Content-Length") != str(fixture.export_bytes)
            or response.getheader("Transfer-Encoding") is not None):
        raise ProbeError("The successful export did not declare its exact length.")
    first_byte = response.read(1)
    first_byte_at = monotonic()
    if mode == "cancel":
        if not first_byte or len(response.read(CANCEL_BYTES - 1)) != CANCEL_BYTES - 1:
            raise ProbeError("The cancelled export ended before the controlled prefix was read.")
        # Closing this response and its dedicated socket intentionally abandons the body.
        return CANCEL_BYTES, first_byte_at, None
    if not first_byte:
        raise ProbeError("The successful export length or digest differs.")

    digest = sha256(first_byte)
    total = len(first_byte)
    last_byte_at = first_byte_at
    next_pause = SLOW_INTERVAL_BYTES
    while total < fixture.export_bytes:
        _remaining(deadline)
        data = response.read(min(READ_BYTES, fixture.export_bytes - total))
        if not data:
            break
        total += len(data)
        if total == fixture.export_bytes:
            last_byte_at = monotonic()
        digest.update(data)
        if mode == "slow" and next_pause <= total < fixture.export_bytes:
            if _remaining(deadline) <= SLOW_PAUSE_SECONDS:
                raise ProbeError("The slow export reached its deadline.")
            sleep(SLOW_PAUSE_SECONDS)
            next_pause += SLOW_INTERVAL_BYTES
    if total != fixture.export_bytes or response.read(1) or digest.hexdigest() != fixture.export_sha256:
        raise ProbeError("The successful export length or digest differs.")
    return total, first_byte_at, last_byte_at


def _stats(values):
    return {"min": min(values), "median": round(median(values)), "max": max(values)}


def _summary(samples):
    result = {
        "status": samples[0].status,
        "samples": len(samples),
        "bodyBytes": samples[0].body_bytes,
        "elapsedMs": _stats([sample.elapsed_ms for sample in samples]),
    }
    first_byte = [sample.first_body_byte_ms for sample in samples if sample.first_body_byte_ms is not None]
    throughput = [sample.body_bytes_per_second for sample in samples if sample.body_bytes_per_second is not None]
    if first_byte:
        result["firstBodyByteMs"] = _stats(first_byte)
    if throughput:
        result["bodyBytesPerSecond"] = _stats(throughput)
    return result


def run_probe(directory, revision):
    fixtures = _load_fixtures(directory, revision)
    run_deadline = monotonic() + RUN_SECONDS
    requests = 0
    request_lock = Lock()

    def sample(fixture=None, method="GET", mode="full"):
        nonlocal requests
        start = monotonic()
        first_body_byte_ms = body_bytes_per_second = None
        deadline = min(start + REQUEST_SECONDS, run_deadline)
        _remaining(deadline)
        with request_lock:
            if requests >= MAX_REQUESTS:
                raise ProbeError("The capacity probe reached its request limit.")
            requests += 1
        if fixture is None:
            path, status, label, media_type = "/health", 200, "health", "application/json"
        else:
            path = f"/sub/{fixture.token}/base64"
            status, label, media_type = fixture.status, fixture.label, "text/plain"

        with _request(method, path, deadline, f"{label} ({mode})") as response:
            _check_headers(response, status, label, media_type)
            if fixture is None:
                body_bytes = _verify_health(response, revision)
            elif method == "HEAD":
                if response.read(1):
                    raise ProbeError(f"HEAD returned a body for {label}.")
                body_bytes = 0
            elif status != 200:
                body = _small_body(response)
                if body != ERROR_BODY[status]:
                    raise ProbeError(f"The fixed error response differs for {label}.")
                body_bytes = len(body)
            else:
                body_bytes, first_byte_at, last_byte_at = _verify_export(response, fixture, mode, deadline)
                first_body_byte_ms = round((first_byte_at - start) * 1000)
                if last_byte_at is not None:
                    # Measure the body phase alone, including the reader's deliberate slow-mode pauses.
                    transfer_seconds = last_byte_at - first_byte_at
                    if transfer_seconds <= 0:
                        raise ProbeError("The export body transfer timing could not be measured.")
                    body_bytes_per_second = round(body_bytes / transfer_seconds)
        _remaining(deadline)
        return Sample(status, round((monotonic() - start) * 1000), body_bytes,
                      first_body_byte_ms, body_bytes_per_second)

    positive = fixtures["at-limits"]

    def wave(count):
        ready = Barrier(count, timeout=min(10, _remaining(run_deadline)))

        def request():
            try:
                ready.wait()
            except BrokenBarrierError:
                raise ProbeError("The capacity request wave could not start.") from None
            return sample(positive)

        with ThreadPoolExecutor(max_workers=count) as executor:
            pending = [executor.submit(request) for _ in range(count)]
            return [result.result() for result in pending]

    first_health = sample()
    heads = {label: _summary([sample(fixtures[label], "HEAD")]) for label in FIXTURE_STATUS}
    rejected = {label: _summary([sample(fixtures[label])]) for label in ("share-over", "snapshot-over")}
    serial = [sample(positive) for _ in range(3)]
    parallel_two = wave(2)
    slow = sample(positive, mode="slow")
    cancel = sample(positive, mode="cancel")
    parallel_four = wave(4)
    last_health = sample()
    return {
        "requests": requests,
        "health": _summary([first_health, last_health]),
        "head": heads,
        "rejectedGet": rejected,
        "export": {
            "serial": _summary(serial),
            "parallel2": _summary(parallel_two),
            "parallel4": _summary(parallel_four),
            "slow": _summary([slow]),
            "cancel": _summary([cancel]),
        },
    }


def _unique_json(text):
    def unique_object(pairs):
        value = dict(pairs)
        if len(value) != len(pairs):
            raise ValueError()
        return value
    return json.loads(text, object_pairs_hook=unique_object)


def _clash_flow_document(text):
    # The Worker emits three block sequences, each containing JSON flow values.
    # Parse only that bounded wire format. The hosted Mihomo test covers YAML compatibility.
    if not text.endswith("\n") or re.search(r"[\x85\u2028\u2029]", text):
        raise ValueError()
    expected = ["proxies", "proxy-groups", "rules"]
    document = {}
    current = None
    for line in text[:-1].split("\n"):
        if line.startswith("  - ") and current is not None:
            document[current].append(_unique_json(line[4:]))
        else:
            if not expected or line != expected[0] + ":":
                raise ValueError()
            current = expected.pop(0)
            document[current] = []
    if expected:
        raise ValueError()
    return document


def _verify_native_config(response, fixture, *, clash):
    length = response.getheader("Content-Length", "")
    if (not re.fullmatch(r"[1-9][0-9]{0,3}", length) or int(length) > SMOKE_OBJECT_LIMIT
            or (not clash and int(length) != fixture.export_bytes)
            or response.getheader("Transfer-Encoding") is not None):
        raise ProbeError("The native export smoke response length is invalid.")
    body = response.read(int(length) + 1)
    try:
        text = body.decode("utf-8")
        normalized = canonical_config(_clash_flow_document(text) if clash else _unique_json(text))
    except (ValueError, RecursionError):
        raise ProbeError("The native export smoke response has invalid YAML flow entries or invalid JSON.") from None
    if (len(body) != int(length) or len(normalized) != fixture.export_bytes
            or sha256(normalized).hexdigest() != fixture.export_sha256):
        raise ProbeError("The native export smoke response differs from the Python oracle or fixed fixture.")
    return len(body), sha256(body).hexdigest()


def run_structured_smoke(directory, revision, *, profile=STRUCTURED_SMOKE):
    from capacity_resources import read_fixtures

    if not _matches(SHA1, revision) or profile not in SMOKE_PROFILES:
        raise ProbeError("An exact hosted revision and export smoke profile are required.")
    fixtures, _ = read_fixtures(Path(directory), revision, profile=profile)
    run_deadline = monotonic() + 60
    singbox = profile == SINGBOX_SMOKE
    clash = profile == CLASH_SMOKE
    routes = ("", "/clash") if clash else (("/sing-box",) if singbox else ("/base64",))

    def health():
        deadline = min(monotonic() + 15, run_deadline)
        with _request("GET", "/health", deadline, "export smoke health") as response:
            _check_headers(response, 200, "export smoke health", "application/json")
            _verify_health(response, revision)
        _remaining(deadline)

    health()
    results = {}
    for row in fixtures:
        fixture = Fixture(row["label"], row["token"], row["status"], row["exportBytes"], row["exportSha256"])
        wire_digests = set()
        for route in routes:
            path = f"/sub/{fixture.token}{route}"
            label = fixture.label + ((":" + (route[1:] or "default")) if clash else "")
            result = {}
            for method in ("GET", "HEAD"):
                deadline = min(monotonic() + 15, run_deadline)
                with _request(method, path, deadline, label) as response:
                    media = ("text/yaml" if clash else "application/json" if singbox else "text/plain")
                    _check_headers(response, fixture.status, label, media if fixture.status == 200 else "text/plain")
                    if method == "HEAD":
                        if response.read(1):
                            raise ProbeError(f"HEAD returned a body for {label}.")
                        body_bytes = 0
                    elif fixture.status == 200 and (singbox or clash):
                        body_bytes, wire_digest = _verify_native_config(response, fixture, clash=clash)
                        wire_digests.add(wire_digest)
                    elif fixture.status == 200:
                        body_bytes, _, _ = _verify_export(response, fixture, "full", deadline)
                    else:
                        body = _small_body(response)
                        if body != ERROR_BODY[422]:
                            raise ProbeError(f"The fixed error response differs for {label}.")
                        body_bytes = len(body)
                    result[method] = {"status": fixture.status, "bodyBytes": body_bytes}
                _remaining(deadline)
            results[label] = result
        if len(wire_digests) > 1:
            raise ProbeError("The Clash aliases returned different bytes.")
    health()
    verified = "fixedClashFixtureDigestMatched" if clash else "pythonOracleDigestMatched"
    return {"requests": 2 + 2 * len(fixtures) * len(routes), "exactHealth": 2, verified: True, "exports": results}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        if len(args) == 3 and args[1] == "--profile" and args[2] in SMOKE_PROFILES:
            report = run_structured_smoke(args[0], os.environ.get("GITHUB_SHA"), profile=args[2])
        elif len(args) == 1:
            report = run_probe(args[0], os.environ.get("GITHUB_SHA"))
        else:
            raise ProbeError("One capacity artifact directory is required.")
        print(json.dumps(report, sort_keys=True))
        return 0
    except ProbeError as error:
        print(str(error), file=sys.stderr)
    except Exception:
        # Keep even unexpected transport or input exceptions out of hosted logs.
        print("The capacity probe could not finish.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

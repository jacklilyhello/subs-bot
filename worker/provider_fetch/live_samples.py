"""Run a bounded private source sample with the pinned transport on GitHub."""

from __future__ import annotations

import asyncio
from asyncio import sleep
from hashlib import sha256
import json
import logging
import os
from pathlib import Path
import re
import stat
import sys
from typing import get_args
from urllib.parse import urlsplit

from transport import FailureCode, FetchFailure, FetchSuccess, MAX_DECODED_BODY, METADATA_HEADERS, _parse_target, fetch_provider


SECRET = "SUBS_BOT_PROVIDER_LIVE_SAMPLE_JSON"
DIGEST = "SUBS_BOT_PROVIDER_LIVE_SAMPLE_SHA256"
MAX_SAMPLES = 12
MAX_MANIFEST_BYTES = 48 * 1024
MAX_TOTAL_SECONDS = 330
SAMPLE_INTERVAL_SECONDS = 1
MAX_RPC_METADATA_BYTES = 3072
MAX_CONTENT_TYPE_BYTES = 8192
FAILURE = "Hosted provider sampling could not be confirmed safely."
_FAILURES = frozenset(get_args(FailureCode))


class SampleError(ValueError):
    """A failure that exposes no source material."""


def _require(condition: object) -> None:
    if not condition:
        raise SampleError(FAILURE)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = dict(pairs)
    _require(len(result) == len(pairs))
    return result


def _json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def read_manifest(secret: str, expected_sha256: str) -> tuple[str, ...]:
    """Validate the entire batch before making any provider request."""
    try:
        _require(re.fullmatch(r"[a-f0-9]{64}", expected_sha256) and len(secret) <= MAX_MANIFEST_BYTES)
        raw = secret.encode("utf-8")
        _require(0 < len(raw) <= MAX_MANIFEST_BYTES and sha256(raw).hexdigest() == expected_sha256)
        value = json.loads(raw, object_pairs_hook=_unique_object)
        _require(type(value) is dict and set(value) == {"version", "origin", "path", "urls"}
                 and type(value["version"]) is int and value["version"] == 1)
        origin, path, urls = value["origin"], value["path"], value["urls"]
        _require(isinstance(origin, str) and isinstance(path, str) and path.startswith("/")
                 and not path.startswith("//") and "?" not in path and "#" not in path
                 and isinstance(urls, list) and 1 <= len(urls) <= MAX_SAMPLES)
        approved = urlsplit(origin)
        _require(approved.scheme == "https" and approved.netloc and not approved.path and not approved.query and not approved.fragment
                 and approved.username is None and approved.password is None and approved.port in (None, 443)
                 and str(_parse_target(origin + "/").url) == origin + "/")
        _require(str(_parse_target(origin + path).url) == origin + path)
        seen = set()
        for url in urls:
            _require(isinstance(url, str) and url not in seen)
            parts = urlsplit(url)
            _require(parts.scheme == approved.scheme and parts.netloc == approved.netloc and parts.path == path
                     and parts.query and not parts.fragment and str(_parse_target(url).url) == url)
            seen.add(url)
        return tuple(urls)
    except (ValueError, TypeError, RecursionError):
        raise SampleError(FAILURE) from None


def _private_output(path: Path, runner_temp: Path) -> Path:
    info = path.lstat()
    _require(path.is_absolute() and path.parent == runner_temp.resolve(strict=True) and path == path.resolve(strict=True)
             and stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o700
             and not any(path.iterdir()))
    return path


def _write_private(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags, 0o600), "wb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def _record_success(case: int, result: FetchSuccess, output: Path) -> tuple[dict, dict]:
    _require(type(result.body) is bytes and len(result.body) <= MAX_DECODED_BODY and type(result.headers) is dict
             and all(key in METADATA_HEADERS and isinstance(value, str) for key, value in result.headers.items()))
    name = f"sample-{case:02d}.body"
    public = {"case": case, "outcome": "ok", "decodedBytes": len(result.body)}
    private = {**public, "file": name, "bodySha256": sha256(result.body).hexdigest()}
    # Match server.py's private protocol metadata envelope for later replay.
    if len(_json(result.headers)) <= MAX_RPC_METADATA_BYTES:
        private["rpcMetadata"] = result.headers
    content_type = result.headers.get("content-type")
    if content_type is not None and len(content_type.encode("utf-8")) <= MAX_CONTENT_TYPE_BYTES:
        private["legacyContentType"] = content_type
    _write_private(output / name, result.body)
    return public, private


def _record_failure(case: int, result: FetchFailure) -> dict:
    _require(result.code in _FAILURES)
    row = {"case": case, "outcome": result.code}
    if result.code == "http-status":
        status = result.upstream_status
        _require(type(status) is int and 100 <= status <= 599 and status != 200)
        row["httpStatus"] = status
    else:
        _require(result.upstream_status is None)
    return row


async def sample_sources(urls: tuple[str, ...], output: Path) -> list[dict]:
    public_rows = []
    private_rows = []
    limited = False
    async with asyncio.timeout(MAX_TOTAL_SECONDS):
        for case, url in enumerate(urls, 1):
            if limited:
                public = private = {"case": case, "outcome": "skipped-rate-limit"}
            else:
                if case > 1:
                    await sleep(SAMPLE_INTERVAL_SECONDS)
                result = await fetch_provider(url, follow_redirects=False)
                if isinstance(result, FetchSuccess):
                    public, private = _record_success(case, result, output)
                else:
                    _require(isinstance(result, FetchFailure))
                    public = private = _record_failure(case, result)
                    limited = public.get("httpStatus") == 429
            public_rows.append(public)
            private_rows.append(private)
    _write_private(output / "index.json", _json({"version": 1, "samples": private_rows}) + b"\n")
    return public_rows


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    logging.disable(logging.CRITICAL)
    try:
        _require(len(args) == 1 and os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                 and os.environ.get("GITHUB_REPOSITORY") == "jacklilyhello/subs-bot"
                 and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_REF") == "refs/heads/main"
                 and os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
        urls = read_manifest(os.environ.pop(SECRET, ""), os.environ.get(DIGEST, ""))
        output = _private_output(Path(args[0]), Path(os.environ["RUNNER_TEMP"]))
        rows = asyncio.run(sample_sources(urls, output))
    except KeyboardInterrupt:
        print("Hosted provider sampling was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2
    print(_json({"version": 1, "runtime": "github-hosted", "samples": rows}).decode("ascii"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

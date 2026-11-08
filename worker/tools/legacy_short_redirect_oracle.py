"""Seal an offline, byte-exact legacy external redirect comparison."""

from __future__ import annotations

from base64 import b64encode
from collections import Counter
from contextlib import closing, contextmanager, suppress
from hashlib import sha256
from importlib.metadata import version
import json
import os
from pathlib import Path
from platform import python_version
import re
import resource
from select import select
from shutil import which
import signal
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic

import legacy_short_namespace_inventory as mixed
import legacy_typed_short_inventory as typed
import prepare_isolation_artifact as artifact
from legacy_restore_package import private_path, read_pinned, read_private
from legacy_snapshot_convert import _bounded_json, _json, _safe_path

ROWS = "external.ndjson"
MANIFEST = "manifest.json"
SEAL = "manifest.sha256"
AIOHTTP = "3.11.18"
OUTCOMES = ("equivalent", "inventory-blocked", "legacy-rejected", "worker-refused", "location-differs", "worker-unconfirmed")
WORKER_OUTCOMES = frozenset(OUTCOMES) - {"inventory-blocked", "legacy-rejected"}
MAX_CASE_SECONDS = 15
MAX_SECONDS = 240
MAX_INPUT_LINE = 4096
FAILURE = "Legacy external redirect equivalence could not be confirmed safely."


class OracleError(RuntimeError):
    """A fixed redacted oracle failure."""


def require(condition: object) -> None:
    if not condition:
        raise OracleError(FAILURE)


def source_check(path: Path, digest: str, state: tuple[int, ...]) -> None:
    require(not any(os.path.lexists(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")))
    typed._verify_source(path, digest, state)


def bundle_pin(root: Path, manifest_sha: str, revision: str) -> tuple[Path, dict]:
    manifest = artifact._parse_object(read_pinned(root / "isolation.json", artifact._MAX_JSON, manifest_sha), FAILURE)
    require(type(manifest.get("version")) is int and manifest["version"] == 2
            and re.fullmatch(r"[0-9a-f]{40}", revision) and manifest.get("revision") == revision
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", manifest["compatibilityDate"]))
    file = private_path(root / "index.js")
    read_pinned(file, 4 * 1024 * 1024, manifest["bundleSha256"])
    return file, {key: manifest[key] for key in ("revision", "compatibilityDate", "bundleSha256")}


@contextmanager
def worker_process(bundle: Path, build: dict, scratch: Path):
    node = which("node")
    require(node is not None)
    command = [node, str(Path(__file__).with_name("legacy-short-redirect-worker.ts")), str(bundle),
               build["bundleSha256"], build["compatibilityDate"]]
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             cwd=scratch, bufsize=0, start_new_session=True,
                             env={"HOME": str(scratch), "TMPDIR": str(scratch), "PATH": os.defpath})
    deadline = monotonic() + MAX_SECONDS
    try:
        send, receive = child.stdin.fileno(), child.stdout.fileno()
        pipe_buf = os.fpathconf(send, "PC_PIPE_BUF")
        os.set_blocking(send, False)
        os.set_blocking(receive, False)

        def check(raw: bytes, legacy_sha: str) -> str:
            line = _json({"raw": b64encode(raw).decode("ascii"), "legacySha": legacy_sha}) + b"\n"
            require(len(line) <= min(pipe_buf, MAX_INPUT_LINE))
            require(select([], [send], [], max(0, min(MAX_CASE_SECONDS, deadline - monotonic())))[1])
            require(os.write(send, line) == len(line))
            require(select([receive], [], [], max(0, min(MAX_CASE_SECONDS, deadline - monotonic())))[0])
            reply = os.read(receive, 128)
            require(reply.endswith(b"\n") and reply.count(b"\n") == 1)
            outcome = reply[:-1].decode("ascii")
            require(outcome in WORKER_OUTCOMES)
            return outcome

        yield check
        child.stdin.close()
        require(child.wait(timeout=MAX_CASE_SECONDS) == 0 and os.read(receive, 1) == b"")
    finally:
        if child.returncode != 0:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        child.stdin.close()
        child.stdout.close()


def legacy_location(raw: bytes, found) -> str | None:
    try:
        response = found(raw.decode("utf-8", "strict"))
        location = response.headers.get("Location")
        if response.status != 302 or not isinstance(location, str) or not location.isascii():
            return None
        return sha256(location.encode("ascii")).hexdigest()
    except (UnicodeError, ValueError):
        return None


def compare_rows(source: Path, inventory: Path, destination: Path, manifest: dict, found, check) -> tuple[dict, dict]:
    expected = manifest["inventory"]
    counts = Counter(dict.fromkeys(OUTCOMES, 0))
    seen = 0
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema=OFF")
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        rows = db.execute("SELECT rowid,typeof(code),typeof(target_url) FROM main.short_links ORDER BY rowid") if expected["present"] else ()

        def lines():
            nonlocal seen
            with (inventory / mixed.ROWS).open("rb") as metadata:
                for row, raw in zip(rows, metadata, strict=True):
                    rowid, code_type, target_type = row
                    item = json.loads(raw)
                    digest = sha256(typed._text_bytes(db, "short_links", "code", rowid, code_type, 12)).hexdigest()
                    require(item["codeSha256"] == digest)
                    seen += 1
                    if item["kind"] != "external":
                        continue
                    if item["state"] == "blocked":
                        outcome = "inventory-blocked"
                    else:
                        require(item["state"] == "classified")
                        target, issue = mixed.read_target(db, rowid, target_type)
                        require(issue is None and target and len(target) <= mixed.MAX_EXTERNAL_BYTES
                                and target.startswith((b"http://", b"https://")) and sha256(target).hexdigest() == item["targetSha256"])
                        location = legacy_location(target, found)
                        outcome = "legacy-rejected" if location is None else check(target, location)
                    counts[outcome] += 1
                    yield _json({"codeSha256": digest, "state": outcome}) + b"\n"

        descriptor = typed._write_file(destination / ROWS, lines(), 4 * 1024**2)
        db.execute("ROLLBACK")
    require(seen == expected["rows"] and sum(counts.values()) == expected["kinds"]["external"])
    return dict(counts), descriptor


def seal_oracle(config: dict) -> None:
    destination = None
    sealed = False
    try:
        require(set(config) == {"backup", "inventory", "bundle", "output", "sourceSha256", "ownerMap", "ownerMapSha256",
                                "oldOrigin", "legacyBotId", "inventorySha256", "workerManifestSha256", "revision", "yarlVersion",
                                "pythonVersion"})
        require(all(isinstance(value, str) for value in config.values()))
        require(python_version() == config["pythonVersion"] and version("aiohttp") == AIOHTTP
                and version("yarl") == config["yarlVersion"] and resource.getrlimit(resource.RLIMIT_CORE)[0] == 0)
        from aiohttp.web import HTTPFound

        source = private_path(config["backup"])
        sealed_inventory = private_path(config["inventory"], directory=True)
        bundle = private_path(config["bundle"], directory=True)
        output = _safe_path(Path(config["output"]), existing=False)
        typed._private_parent(output)
        owner_map = _bounded_json(private_path(config["ownerMap"]), typed.MAX_METADATA_BYTES)
        require(set(os.listdir(sealed_inventory)) == {mixed.ROWS, mixed.MANIFEST, mixed.SEAL})
        manifest_raw = read_pinned(sealed_inventory / mixed.MANIFEST, 64 * 1024, config["inventorySha256"])
        require(read_private(sealed_inventory / mixed.SEAL, 65) == config["inventorySha256"].encode("ascii") + b"\n")
        script, build = bundle_pin(bundle, config["workerManifestSha256"], config["revision"])
        state = typed._source_state(source)
        source_check(source, config["sourceSha256"], state)
        with TemporaryDirectory(prefix=".redirect-oracle-", dir=output.parent) as path:
            scratch = Path(path)
            reconstructed = scratch / "inventory"
            mixed.seal_inventory(source, reconstructed, source_sha256=config["sourceSha256"], owner_map=owner_map,
                                 owner_map_sha256=config["ownerMapSha256"], old_origin=config["oldOrigin"],
                                 legacy_bot_id=config["legacyBotId"])
            require(read_private(reconstructed / mixed.MANIFEST, 64 * 1024) == manifest_raw)
            manifest = json.loads(manifest_raw)
            descriptor, = manifest["files"]
            original_rows = private_path(sealed_inventory / mixed.ROWS)
            require(descriptor["file"] == mixed.ROWS and original_rows.stat().st_size == descriptor["bytes"]
                    and typed._file_hash(original_rows) == (descriptor["bytes"], descriptor["sha256"]))
            output.mkdir(mode=0o700)
            destination = output
            with worker_process(script, build, scratch) as check:
                counts, result = compare_rows(source, reconstructed, output, manifest, HTTPFound, check)
        source_check(source, config["sourceSha256"], state)
        report = _json({"version": 1, "kind": "legacy-external-redirect-oracle", "scope": "offline-dormant",
                        "sourceSha256": config["sourceSha256"], "inventorySha256": config["inventorySha256"],
                        "worker": {**build, "manifestSha256": config["workerManifestSha256"]},
                        "legacySerializer": {"python": config["pythonVersion"], "aiohttp": AIOHTTP, "yarl": config["yarlVersion"]},
                        "sourceRows": manifest["inventory"]["rows"], "externalRows": sum(counts.values()),
                        "inventoryBlockedRows": manifest["inventory"]["blocked"], "outcomes": counts, "files": [result]}) + b"\n"
        seal = typed._write_file(output / MANIFEST, (report,), 64 * 1024)
        typed._write_file(output / SEAL, (seal["sha256"].encode("ascii") + b"\n",), 65)
        sealed = True
    except Exception:
        raise OracleError(FAILURE) from None
    finally:
        if destination is not None and not sealed:
            for name in (SEAL, MANIFEST, ROWS):
                with suppress(OSError):
                    (destination / name).unlink()
            with suppress(OSError):
                destination.rmdir()


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    if len(args) != 1:
        print("Usage: legacy_short_redirect_oracle.py PRIVATE_CONFIG_JSON", file=sys.stderr)
        return 2
    try:
        seal_oracle(_bounded_json(private_path(args[0]), 16 * 1024))
    except (Exception, KeyboardInterrupt):
        print(FAILURE, file=sys.stderr)
        return 2
    print("Legacy external redirect equivalence sealed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

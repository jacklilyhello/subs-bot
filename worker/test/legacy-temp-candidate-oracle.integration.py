"""Hosted comparison of a sealed dormant temp candidate and the real legacy HTTP route."""

import asyncio
from base64 import b64encode
from contextlib import suppress
from hashlib import sha256
from importlib.metadata import version
import json
import logging
import os
from pathlib import Path
from platform import python_version
import re
import resource
from shutil import which
import signal
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "worker/tools"
sys.path[:0] = [str(TOOLS), str(ROOT)]

import legacy_candidate_isolation as candidate_io
import legacy_restore_package as package
import legacy_temp_native_candidate as fixture
import prepare_isolation_artifact as artifact


OUTPUT_NAME = "subs-bot-legacy-temp-node-candidate"
MAX_SQL = 256 * 1024
MAX_BODY = 512 * 1024
CHILD_STAGE = re.compile(rb"The dormant temp Worker oracle could not be confirmed \("
                         rb"(sandbox|input|artifact|replay|dormant|cutoff|private|aggregate|clear|dispose)\)\.\n")
OWNERS = (fixture.FIRST_OWNER, fixture.SECOND_OWNER)


class OracleError(RuntimeError):
    """Fixed checkpoints only, so exceptions never print fixture contents."""


def require(condition, checkpoint):
    if not condition:
        raise OracleError(checkpoint)


def digest(raw):
    return sha256(raw).hexdigest()


def verify_worker(bundle, revision, root, output):
    raw = package.read_private(bundle / "isolation.json", artifact._MAX_JSON)
    manifest = artifact._parse_object(raw, "Unexpected Worker manifest.")
    ref = manifest.get("ref")
    run, attempt = manifest.get("runId"), manifest.get("runAttempt")
    require(package.native.matches(artifact._REVISION, revision)
            and package.native.matches(artifact._DECIMAL, run)
            and package.native.matches(artifact._DECIMAL, attempt)
            and manifest.get("revision") == revision and isinstance(ref, str)
            and re.fullmatch(r"refs/(?:heads/[^\s]+|pull/[1-9][0-9]*/merge)", ref), "build-provenance")
    normalized = {**manifest, "ref": artifact.MAIN_REF}
    hashes, sizes = artifact._expected_hashes(normalized, revision, run, attempt)
    require(output is None or (ref, run, attempt) == (
        artifact.MAIN_REF, os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT")), "publish-worker-pin")

    # The builder requires main artifact shape. Only a disposable PR copy may
    # change ref. The emitted probe always opens the original, exact artifact.
    package_worker = bundle if ref == artifact.MAIN_REF else root / "worker"
    if package_worker != bundle:
        package_worker.mkdir(mode=0o700)
    total = 0
    for name, expected in hashes.items():
        body = package.read_pinned(bundle / name, sizes.get(name, artifact._MAX_EXPANDED), expected)
        total += len(body)
        require(body and total <= artifact._MAX_EXPANDED and (name not in sizes or len(body) == sizes[name]),
                "build-file-bounds")
        if package_worker != bundle:
            target = package_worker / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            candidate_io.put(target, body)
    if package_worker != bundle:
        candidate_io.put(package_worker / "isolation.json", package.native.canonical(normalized))
    return package_worker, digest(raw)


def publication_target(arguments, bundle, revision):
    if not arguments:
        return None
    require(len(arguments) == 2 and arguments[0] == "--output", "arguments")
    runner, output = Path(os.environ.get("RUNNER_TEMP", "")), Path(arguments[1])
    require(runner.is_absolute() and output == runner / OUTPUT_NAME and bundle == runner / "subs-bot-worker"
            and os.environ.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and os.environ.get("GITHUB_REF") == artifact.MAIN_REF and os.environ.get("GITHUB_SHA") == revision
            and os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"}, "publish-provenance")
    output = package.converter._safe_path(output, existing=False)
    state = runner.stat()
    require(state.st_uid == os.geteuid() and not state.st_mode & 0o022, "publish-directory")
    return output


def candidate_sql(candidate):
    directory = candidate.candidate
    require({entry.name for entry in directory.iterdir()} == {"manifest.json", "manifest.sha256", "restore.sql"},
            "candidate-closure")
    require(package.read_private(directory / "manifest.sha256", 65) == (candidate.candidate_sha256 + "\n").encode(),
            "candidate-seal")
    raw = package.read_pinned(directory / "manifest.json", package.native.MANIFEST_BYTES, candidate.candidate_sha256)
    descriptor = package.native.parsed(raw, package.native.MANIFEST_BYTES)["sql"]
    require(set(descriptor) == {"path", "bytes", "sha256", "md5"} and descriptor["path"] == "restore.sql",
            "candidate-sql-descriptor")
    sql = package.read_pinned(directory / "restore.sql", MAX_SQL, descriptor["sha256"])
    require(len(sql) == descriptor["bytes"], "candidate-sql-size")
    statements, pending = [], ""
    for line in sql.decode("utf-8", "strict").splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statements.append(pending)
            pending = ""
    require(not pending and 0 < len(statements) <= 512 and "".join(statements).encode() == sql, "candidate-sql-statements")
    return descriptor["sha256"], statements


async def legacy_http(root, candidate, rows):
    require(not os.path.lexists(ROOT / ".env"), "legacy-dotenv-absent")
    replay = root / "legacy-replay.sqlite"
    source = package.read_pinned(candidate.source, 1024 * 1024, candidate.source_sha256)
    candidate_io.put(replay, source)
    os.environ.update(BOT_TOKEN="0:TEST", DATA_DIR=str(root), DB_PATH=str(replay), HTTP_HOST="127.0.0.1")
    logging.disable(logging.CRITICAL)
    import bot
    from aiohttp import ClientSession, ClientTimeout

    store = bot.store
    bot.HTTP_PORT = 0
    await store.init()
    runner = None
    output = []
    try:
        runner = await bot.start_http(None)
        (host, port), = runner.addresses
        require(host == "127.0.0.1", "legacy-loopback-bind")
        origin = f"http://{host}:{port}"
        async with ClientSession(timeout=ClientTimeout(total=5), trust_env=False, auto_decompress=False,
                                 headers={"Accept-Encoding": "identity"}) as session:
            for owner in OWNERS:
                expected = [(identity, uri, name, created) for identity, issuer, uri, name, created in rows
                            if str(issuer) == owner]
                stored = await store.list_temp(int(owner))
                require([(row["id"], row["url"], row["name"], row["created_at"]) for row in stored] == expected,
                        "legacy-store-readback")
                body = b64encode("\n".join(row[1] for row in expected).encode("utf-8"))
                code = await store.create_short(int(owner), "aggregate://all")
                aggregate = f"/agg/{code}/base64"
                for method in ("GET", "HEAD"):
                    async with session.request(method, origin + aggregate, allow_redirects=False) as response:
                        actual = bytearray()
                        async for block in response.content.iter_chunked(4096):
                            actual.extend(block)
                            require(len(actual) <= MAX_BODY, "legacy-http-body-bound")
                        require(response.status == 200 and response.headers.get("Content-Type") == "text/plain; charset=utf-8"
                                and response.headers.get("Cache-Control") == "no-store, private"
                                and response.headers.get("Content-Length") == str(len(body))
                                and actual == (body if method == "GET" else b""), "legacy-aggregate-wire")
                    async with session.request(method, origin + f"/s/{code}", allow_redirects=False) as response:
                        require(response.status == 302 and response.headers.get("Location") == f"/agg/{code}/clash",
                                "legacy-relative-short")
                output.append({"bytes": len(body), "sha256": digest(body)})
    finally:
        if runner is not None:
            await runner.cleanup()
        await store.close()
    return output


def worker_probe(root, bundle, worker_sha, revision, candidate, sql_sha, statements, legacy):
    node = which("node")
    require(node is not None, "node-present")
    batches = []
    for batch in candidate.projection.batches:
        names = [node["name"] for node in json.loads(batch.payload_json)]
        batches.append({"ownerId": batch.owner_id, "firstId": batch.first_legacy_id, "lastId": batch.last_legacy_id,
                        "nodeCount": batch.node_count, "payloadBytes": batch.payload_bytes,
                        "payloadSha256": digest(batch.payload_json.encode()), "namesSha256": digest(candidate_io.compact(names))})
    require([batch["nodeCount"] for batch in batches] == [500, 1, 2], "projected-batch-closure")
    payload = package.native.canonical({
        "workerDir": str(bundle), "workerManifestSha256": worker_sha, "revision": revision,
        "candidateDir": str(candidate.candidate), "candidateManifestSha256": candidate.candidate_sha256,
        "sqlSha256": sql_sha, "sqlStatements": statements,
        "inventorySha256": candidate.projection.inventory_manifest_sha256,
        "batches": batches, "legacyBase64": legacy,
    })
    require(len(payload) <= 1024 * 1024, "worker-input-bound")
    with subprocess.Popen([node, str(TOOLS / "legacy-temp-candidate-oracle-worker.ts")], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, start_new_session=True,
                          env={"HOME": str(root), "TMPDIR": str(root), "PATH": os.defpath}) as child:
        try:
            raw, diagnostic = child.communicate(payload, timeout=75)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise OracleError("worker-probe-deadline") from None
    if child.returncode:
        stage = CHILD_STAGE.fullmatch(diagnostic)
        raise OracleError("worker-" + (stage[1].decode("ascii") if stage else "unconfirmed"))
    expected = {"sourceRows": 503, "batchRows": 3, "dormantOwnerChecks": 2, "rawOwnerChecks": 2,
                "aggregateWireChecks": 4, "relativeRedirectChecks": 4, "cutoffChecks": 2,
                "clearOwnerChecks": 2, "noR2": True}
    require(0 < len(raw) <= 2048 and json.loads(raw) == expected, "worker-report")
    return expected


def publish(candidate, destination):
    destination.mkdir(mode=0o700)
    reservation = destination.lstat()
    try:
        candidate.candidate.rename(destination)
    except OSError:
        with suppress(OSError):
            if os.path.samestat(reservation, destination.lstat()):
                destination.rmdir()
        raise


def main(arguments):
    require(sys.platform == "linux" and os.geteuid() != 0 and [name for _, name in socket.if_nameindex()] == ["lo"]
            and resource.getrlimit(resource.RLIMIT_CORE)[0] == 0, "loopback-only-namespace")
    require(python_version() == "3.11.18" and version("aiohttp") == "3.11.18" and version("yarl") == "1.20.0",
            "legacy-runtime-version")
    bundle, revision = Path(os.environ["WORKER_TEST_BUNDLE_DIR"]), os.environ["WORKER_TEST_REVISION"]
    destination = publication_target(arguments, bundle, revision)
    with TemporaryDirectory(prefix="legacy-temp-candidate-oracle-", dir=destination.parent if destination else None) as name:
        scratch = Path(name)
        root = scratch / "fixture"
        root.mkdir(mode=0o700)
        package_worker, worker_sha = verify_worker(bundle, revision, scratch, destination)
        candidate = fixture.build_temp_fixture(root, package_worker, revision)
        sql_sha, statements = candidate_sql(candidate)
        legacy = asyncio.run(legacy_http(root, candidate, fixture.fixture_rows()))
        report = worker_probe(root, bundle, worker_sha, revision, candidate, sql_sha, statements, legacy)
        require(package.native.file_hash(candidate.source)[1] == candidate.source_sha256
                and candidate_sql(candidate)[0] == sql_sha, "source-and-candidate-unchanged")
        if destination is not None:
            publish(candidate, destination)
        print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        main(sys.argv[1:])
    except OracleError as error:
        print(f"Legacy temp candidate oracle failed at {error}.", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print("Legacy temp candidate oracle could not be confirmed safely.", file=sys.stderr)
        raise SystemExit(2) from None

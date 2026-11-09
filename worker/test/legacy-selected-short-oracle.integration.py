"""Compare the registered legacy routes and the exact emitted Worker over a V6 fixture."""

from base64 import b64decode, b64encode
from contextlib import closing, suppress
from importlib.metadata import version
from pathlib import Path
from platform import python_version
from shutil import which
import asyncio
import json
import logging
import os
import re
import resource
import signal
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "worker/tools"
sys.path[:0] = [str(TOOLS), str(ROOT)]
import legacy_candidate_isolation as protected
import legacy_selected_oracle_fixture as fixture
import legacy_short_namespace_inventory as namespace
import legacy_restore_package as package
import prepare_isolation_artifact as artifact


TEXT = "text/plain; charset=utf-8"
YAML = "text/yaml; charset=utf-8"
JSON = "application/json; charset=utf-8"
BASE64 = ("base64", "v2ray", "mixed")
QX = ("qx", "quantumult", "quantumultx")
SINGBOX = ("singbox", "sing-box")
FORMATS = (*BASE64, *QX, *SINGBOX, "clash", "surge", "unknown-format")
MAX_BODY = 64 * 1024
HEADER_FIELDS = {
    "contentType": "Content-Type", "cacheControl": "Cache-Control", "referrerPolicy": "Referrer-Policy",
    "noSniff": "X-Content-Type-Options", "contentLength": "Content-Length", "location": "Location",
}
WORKER_FAILURE = re.compile(rb"The isolated V6 Worker oracle could not be confirmed \("
                            rb"(sandbox|input|request-shape|artifact|sql-replay|d1-readback|r2-replay|health|dispose|"
                            rb"request(?:, case (?:[1-9]|[1-5][0-9]|6[0-4]))?)\)\.\n")


class OracleError(RuntimeError):
    """Only fixed, fixture-independent diagnostic names are raised."""


def require(condition, check):
    if not condition:
        raise OracleError(check)


def prepare_worker(source: Path, destination: Path, revision: str) -> str:
    raw = package.read_private(source / "isolation.json", artifact._MAX_JSON)
    manifest = package.native.parsed(raw, artifact._MAX_JSON)
    require(manifest["revision"] == revision and manifest["ref"].startswith("refs/"), "build-provenance")
    # Package tooling consumes the main archive shape. For PR CI normalize
    # only the ref in this private synthetic copy, never in the emitted artifact.
    if manifest["ref"] != artifact.MAIN_REF:
        manifest["ref"] = artifact.MAIN_REF
        raw = package.native.canonical(manifest)
    hashes, sizes = artifact._expected_hashes(manifest, revision, manifest["runId"], manifest["runAttempt"])
    destination.mkdir(mode=0o700)
    total = 0
    for name, digest in hashes.items():
        body = package.read_pinned(source / name, sizes.get(name, artifact._MAX_EXPANDED), digest)
        total += len(body)
        require(total <= artifact._MAX_EXPANDED and len(body) == sizes.get(name, len(body)), "build-file-bounds")
        target = destination / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        protected.put(target, body)
    protected.put(destination / "isolation.json", raw)
    return package.native.digest(raw)


def sql_statements(candidate: fixture.SelectedFixture) -> list[str]:
    manifest = package.native.parsed(package.read_pinned(candidate.candidate / package.MANIFEST,
        package.native.MANIFEST_BYTES, candidate.candidate_sha256), package.native.MANIFEST_BYTES)
    descriptor = manifest["sql"]
    require(descriptor["path"] == package.SQL, "candidate-sql-path")
    raw = package.read_pinned(candidate.candidate / package.SQL, 256 * 1024, descriptor["sha256"])
    require(len(raw) == descriptor["bytes"], "candidate-sql-size")
    statements, pending = [], ""
    for line in raw.decode("utf-8", "strict").splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statements.append(pending)
            pending = ""
    require(not pending and 0 < len(statements) <= 256, "candidate-sql-statements")
    return statements


def probe_cases() -> list[dict]:
    targets = [
        *(("aggregate", fixture.ORDERED_CODE, kind) for kind in (*BASE64, "clash", "unknown-format", "singbox")),
        *(("aggregate", fixture.EMPTY_CODE, kind) for kind in FORMATS),
        *(("aggregate", fixture.HOLE_CODE, kind) for kind in ("base64", "clash")),
        *(("short", code, None) for code in (*fixture.ACTIVE_CODES, fixture.UNKNOWN_CODE)),
        ("aggregate", fixture.UNKNOWN_CODE, "base64"),
        ("aggregate", fixture.ORDERED_CODE, None),
    ]
    return [{"method": method, "route": route, "code": code, "format": kind}
            for route, code, kind in targets for method in ("GET", "HEAD")]


def worker_responses(root: Path, worker: Path, worker_sha: str, revision: str, candidate: fixture.SelectedFixture, cases: list[dict]):
    node = which("node")
    require(node is not None, "node-present")
    payload = package.native.canonical({
        "workerDir": str(worker), "workerManifestSha256": worker_sha, "revision": revision,
        "candidateDir": str(candidate.candidate), "candidateManifestSha256": candidate.candidate_sha256,
        "sqlStatements": sql_statements(candidate), "requests": cases,
    })
    require(len(payload) <= 1024 * 1024 and len(cases) <= 64, "worker-input-bounds")
    with subprocess.Popen(
        [node, str(TOOLS / "legacy-selected-oracle-worker.ts")], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, start_new_session=True,
        env={"HOME": str(root), "TMPDIR": str(root), "PATH": os.defpath},
    ) as child:
        try:
            raw, diagnostic = child.communicate(payload, timeout=60)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise OracleError("worker-probe-deadline") from None
    if child.returncode:
        match = WORKER_FAILURE.fullmatch(diagnostic)
        stage = match[1].decode("ascii") if match else "unconfirmed"
        raise OracleError("worker-" + stage)
    require(0 < len(raw) <= 2 * 1024 * 1024, "worker-probe")
    report = json.loads(raw)
    require(type(report) is dict and set(report) == {"responses"} and type(report["responses"]) is list
            and len(report["responses"]) == len(cases), "worker-report-shape")
    for response in report["responses"]:
        require(type(response) is dict and set(response) == {"status", "bodyBase64", *HEADER_FIELDS}
                and type(response["status"]) is int and type(response["bodyBase64"]) is str
                and all(value is None or type(value) is str for value in (response[field] for field in HEADER_FIELDS)),
                "worker-response-shape")
    return report["responses"]


def request_path(case: dict) -> str:
    code, kind = case["code"], case["format"]
    if case["route"] == "short":
        return f"/s/{code}"
    return f"/agg/{code}" + (f"/{kind}" if kind else "")


async def capture(session, origin, case):
    async with session.request(case["method"], origin + request_path(case), allow_redirects=False) as response:
        body = bytearray()
        async for block in response.content.iter_chunked(4096):
            body.extend(block)
            require(len(body) <= MAX_BODY, "legacy-body-bound")
        return {"status": response.status, "bodyBase64": b64encode(body).decode("ascii"),
                **{field: response.headers.get(name) for field, name in HEADER_FIELDS.items()}}


def expected_base64(*labels):
    return b64encode("\n".join(fixture.fixture_node(label)["share"] for label in labels).encode("ascii"))


def add_foreign_selection(db):
    return db.execute("INSERT INTO short_links VALUES (?,?,?,?)", (
        fixture.FOREIGN_CODE, fixture.OWNER, fixture.selector(fixture.BETA, fixture.FOREIGN, fixture.ALPHA),
        protected.FIXTURE_CREATED,
    ))


def check_foreign_inventory(source_bytes, root):
    negative = root / "negative.sqlite"
    protected.put(negative, source_bytes)
    with closing(sqlite3.connect(negative)) as db, db:
        db.execute("DELETE FROM short_links")
        add_foreign_selection(db)
    directory = root / "negative-namespace"
    coalesced = fixture.OWNER_MAP | {str(fixture.FOREIGN_OWNER): str(fixture.OWNER)}
    fixture.seal_selected_inventory(negative, directory, package.native.file_hash(negative)[1], coalesced)
    report = json.loads((directory / namespace.MANIFEST).read_bytes())["inventory"]
    require(report["rows"] == 1 and report["blockedReasons"] == {"aggregate-selected-foreign-owner": 1},
            "foreign-owner-inventory-block")


async def legacy_responses(root, candidate, cases):
    require(not os.path.lexists(ROOT / ".env"), "legacy-dotenv-absent")
    db_path = root / "legacy-replay.sqlite"
    source_bytes = package.read_pinned(candidate.source, 256 * 1024, candidate.source_sha256)
    protected.put(db_path, source_bytes)
    check_foreign_inventory(source_bytes, root)
    os.environ.update(BOT_TOKEN="0:TEST", DATA_DIR=str(root), DB_PATH=str(db_path), HTTP_HOST="127.0.0.1")
    logging.disable(logging.CRITICAL)
    import bot
    from aiohttp import ClientSession, ClientTimeout

    store = bot.store
    bot.HTTP_PORT = 0
    await store.init()
    runner = None
    try:
        async with store.connection() as db:
            async with db.execute("SELECT id,node_count FROM deleted_subs WHERE id=?", (fixture.HOLE,)) as cursor:
                row = await cursor.fetchone()
                require(row is not None and tuple(row) == (fixture.HOLE, 1), "legacy-same-id-trash-present")
        temp = fixture.fixture_node("temp")
        await store.add_temp(fixture.OWNER, temp["share"], temp["name"])
        runner = await bot.start_http(None)
        (host, port), = runner.addresses
        require(host == "127.0.0.1", "legacy-loopback-bind")
        origin = f"http://{host}:{port}"
        async with ClientSession(timeout=ClientTimeout(total=5), trust_env=False, auto_decompress=False,
                                 headers={"Accept-Encoding": "identity"}) as session:
            replies = [await capture(session, origin, case) for case in cases]
            async with store.connection() as db:
                cursor = await add_foreign_selection(db)
                await cursor.close()
                await db.commit()
            case = {"method": "GET", "route": "aggregate", "code": fixture.FOREIGN_CODE, "format": "base64"}
            foreign = await capture(session, origin, case)
            require(foreign["status"] == 200 and response_body(foreign) == expected_base64("beta", "alpha"),
                    "legacy-foreign-excluded")
            require(await store.delete_sub(fixture.OWNER, fixture.BETA), "legacy-delete")
            case["code"] = fixture.ORDERED_CODE
            deleted = await capture(session, origin, case)
            require(deleted["status"] == 200 and response_body(deleted) == expected_base64("alpha"), "legacy-after-delete")
            trash = await store.list_deleted(fixture.OWNER)
            deleted_id, = [row["id"] for row in trash if row["token"] == fixture.BETA_TOKEN]
            restored = await store.restore_deleted(fixture.OWNER, deleted_id)
            require(restored is not None and restored["id"] > fixture.ACTIVE_HIGH_WATER
                    and restored["token"] == fixture.BETA_TOKEN, "legacy-new-restored-id")
            replay = await capture(session, origin, case)
            require(replay["status"] == 200 and response_body(replay) == expected_base64("alpha"), "legacy-after-restore")
            code = await store.create_short(fixture.OWNER, fixture.selector(restored["id"]))
            case["code"] = code
            current = await capture(session, origin, case)
            require(current["status"] == 200 and response_body(current) == expected_base64("beta"), "legacy-restored-row-readable")
            return replies
    finally:
        if runner is not None:
            await runner.cleanup()
        await store.close()


def response_body(response):
    encoded = response["bodyBase64"]
    require(len(encoded) <= ((MAX_BODY + 2) // 3) * 4, "response-body-bound")
    decoded = b64decode(encoded, validate=True)
    require(len(decoded) <= MAX_BODY, "response-body-bound")
    return decoded


def media(kind):
    if kind in SINGBOX:
        return JSON
    if kind in {"clash", "unknown-format"}:
        return YAML
    return TEXT


def check_clash(body, labels, names):
    import yaml
    config = yaml.safe_load(body)
    expected = []
    for label, name in zip(labels, names, strict=True):
        node = fixture.fixture_node(label)
        expected.append({**{key: node[key] for key in ("type", "server", "port", "cipher", "password")}, "name": name})
    group_names = names or ["DIRECT"]
    expected_groups = [
        {"name": "🚀 节点选择", "type": "select", "proxies": group_names},
        {"name": "♻️ 自动选择", "type": "url-test", "proxies": group_names,
         "url": "http://www.gstatic.com/generate_204", "interval": 300},
    ]
    require(config == {"proxies": expected, "proxy-groups": expected_groups, "rules": ["MATCH,🚀 节点选择"]},
            "clash-proxies-and-groups")


def check_singbox(old, new, labels):
    names = ["selected-beta", "selected-alpha", "selected-beta (2)"] if labels else ["direct"]
    expected = [{"type": "selector", "tag": "proxy", "outbounds": names}, {"type": "direct", "tag": "direct"}]
    for label, name in zip(labels, names):
        node = fixture.fixture_node(label)
        expected.append({"type": "shadowsocks", "tag": name, "server": node["server"], "server_port": node["port"],
                         "method": node["cipher"], "password": node["password"]})
    require(json.loads(old) == json.loads(new) == {"outbounds": expected}, "singbox-ordered-outbounds")


def compare(cases, legacy, worker):
    counts = dict.fromkeys(("export-exact", "clash-semantic", "singbox-semantic", "redirect-framing-differs",
                            "not-found", "head-length-omitted"), 0)
    for index in range(0, len(cases), 2):
        case = cases[index]
        kind, code = case["format"], case["code"]
        old_get, old_head = legacy[index:index + 2]
        new_get, new_head = worker[index:index + 2]
        old, new = response_body(old_get), response_body(new_get)
        missing = code == fixture.UNKNOWN_CODE or (case["route"] == "aggregate" and kind is None)
        status = 404 if missing else 302 if case["route"] == "short" else 200
        for response in (old_get, old_head, new_get, new_head):
            require(response["status"] == status, "paired-route-status")
        for response in (new_get, new_head):
            require((response["cacheControl"], response["referrerPolicy"], response["noSniff"])
                    == ("private, no-store", "no-referrer", "nosniff"), "worker-privacy-headers")
        for head, body in ((old_head, old), (new_head, new)):
            require(response_body(head) == b"", "head-body")
            length = head["contentLength"]
            if length is None:
                counts["head-length-omitted"] += 1
            else:
                require(length == str(len(body)), "head-length-truth")
        if status == 404:
            require(all(response["location"] is None for response in (old_get, old_head, new_get, new_head))
                    and new == b"Not found." and old in (b"not found", b"404: Not Found"), "not-found-framing")
            counts["not-found"] += 1
            continue
        if status == 302:
            require(all(response["location"] == f"/agg/{code}/clash"
                        for response in (old_get, old_head, new_get, new_head))
                    and old == b"302: Found" and new == b"", "relative-redirect-framing")
            counts["redirect-framing-differs"] += 1
            continue

        for get, head, body in ((old_get, old_head, old), (new_get, new_head, new)):
            require(get["contentType"] == head["contentType"] == media(kind), "export-media-type")
            length = get["contentLength"]
            require(length == str(len(body)) if body else length in (None, "0"), "get-length-truth")
        for response in (old_get, old_head):
            require(set((response["cacheControl"] or "").replace(" ", "").split(",")) == {"private", "no-store"},
                    "legacy-cache-privacy")
        labels = ("beta", "alpha", "beta") if code == fixture.ORDERED_CODE else ()
        if kind in BASE64:
            require(old == new == expected_base64(*labels), "ordered-base64-bytes")
        elif kind in {"clash", "unknown-format"}:
            old_names = [f"selected-{label}" for label in labels]
            new_names = [*old_names[:2], "selected-beta (2)"] if labels else []
            check_clash(old, labels, old_names)
            check_clash(new, labels, new_names)
            if labels:
                counts["clash-semantic"] += 1
                continue
            require(old == new, "empty-clash-bytes")
        elif kind in SINGBOX:
            check_singbox(old, new, labels)
            if labels:
                counts["singbox-semantic"] += 1
                continue
            require(old == new, "empty-singbox-bytes")
        elif kind == "surge":
            require(old == new == b"[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n", "empty-surge-bytes")
        else:
            require(kind in QX and old == new == b"", "empty-qx-bytes")
        counts["export-exact"] += 1
    return counts


def main():
    require(sys.platform == "linux" and os.geteuid() != 0
            and [name for _, name in socket.if_nameindex()] == ["lo"]
            and resource.getrlimit(resource.RLIMIT_CORE)[0] == 0, "loopback-only-namespace")
    require(python_version() == "3.11.18" and version("aiohttp") == fixture.AIOHTTP
            and version("yarl") == fixture.YARL, "legacy-runtime-version")
    bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"])
    revision = os.environ["WORKER_TEST_REVISION"]
    with TemporaryDirectory(prefix="legacy-selected-oracle-") as name:
        root = Path(name)
        worker = root / "worker"
        try:
            worker_sha = prepare_worker(bundle, worker, revision)
            candidate = fixture.build_selected_fixture(root, worker, revision)
        except (package.PackageError, package.native.RehearsalError, artifact.ArtifactError):
            raise OracleError("v6-fixture-build") from None
        cases = probe_cases()
        replies = worker_responses(root, worker, worker_sha, revision, candidate, cases)
        legacy = asyncio.run(legacy_responses(root, candidate, cases))
        require(package.native.file_hash(candidate.source)[1] == candidate.source_sha256, "legacy-source-unchanged")
        counts = compare(cases, legacy, replies)
        print(json.dumps({"requestCountPerRuntime": len(cases), **counts, "legacy-lifecycle": "confirmed",
                          "foreign-source-policy": "blocked"}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except OracleError as error:
        print(f"Legacy selected HTTP oracle failed at {error}.", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print("Legacy selected HTTP oracle could not be confirmed safely.", file=sys.stderr)
        raise SystemExit(2) from None

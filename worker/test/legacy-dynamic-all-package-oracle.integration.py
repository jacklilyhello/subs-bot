"""Compare the V8 sealed synthetic restore with the actual old and emitted Worker HTTP routes."""

import asyncio
from base64 import b64encode
from contextlib import suppress
import json
import os
from pathlib import Path
import re
from runpy import run_path
from shutil import which
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory

TEST = Path(__file__).resolve().parent
TOOLS = TEST.parent / "tools"
sys.path.insert(0, str(TOOLS))

import legacy_candidate_isolation as candidate_io
import legacy_dynamic_all_candidate as fixture
import legacy_restore_package as package


BASE64 = ("base64", "v2ray", "mixed")
CLASH = ("clash", "unknown-format")
SINGBOX = ("singbox", "sing-box")
QX = ("qx", "quantumult", "quantumultx")
EMPTY_FORMATS = (*BASE64, *CLASH, *SINGBOX, "surge", *QX)
MISSING = "DynAllX00004"
CODES = (fixture.OWNER_CODE, fixture.TEMP_ONLY_CODE, fixture.EMPTY_CODE)
CHILD_STAGE = re.compile(rb"The isolated V8 Worker oracle could not be confirmed \("
                         rb"(sandbox|input|request-shape|artifact|sql-replay|d1-readback|r2-replay|health|cutoff|restore|dispose|"
                         rb"request, case (?:[1-9]|[1-5][0-9]|6[0-4]))\)\.\n")


class OracleError(RuntimeError):
    """Only fixed stage and case classes may appear in diagnostics."""


def require(condition, checkpoint):
    if not condition:
        raise OracleError(checkpoint)


def cases():
    def pair(targets):
        return [{"method": method, "route": route, "code": code, "format": kind}
                for route, code, kind in targets for method in ("GET", "HEAD")]

    return {
        "dormant": pair((route, code, "base64" if route == "aggregate" else None)
                         for code in CODES for route in ("aggregate", "short")),
        "active": pair([
            *(("aggregate", fixture.OWNER_CODE, kind) for kind in (*BASE64, *CLASH)),
            ("aggregate", fixture.TEMP_ONLY_CODE, "base64"),
            *(("aggregate", fixture.EMPTY_CODE, kind) for kind in EMPTY_FORMATS),
            *(("short", code, None) for code in (*CODES, MISSING)),
            ("aggregate", MISSING, "base64"),
            ("aggregate", fixture.OWNER_CODE, None),
        ]),
        "restored": pair([("aggregate", code, "base64") for code in CODES[:2]]),
    }


def worker_responses(root, worker, worker_sha, revision, candidate, requests, selected_oracle):
    node = which("node")
    require(node is not None, "node-present")
    raw = package.native.canonical({
        "profile": "dynamic-all-v8", "workerDir": str(worker), "workerManifestSha256": worker_sha,
        "candidateDir": str(candidate.candidate), "candidateManifestSha256": candidate.candidate_sha256,
        "revision": revision, "sqlStatements": selected_oracle["sql_statements"](candidate), "requests": requests,
    })
    require(len(raw) <= 1024 * 1024 and sum(map(len, requests.values())) <= 64, "worker-input-bounds")
    with subprocess.Popen([node, str(TOOLS / "legacy-selected-oracle-worker.ts")], stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, start_new_session=True,
                          env={"HOME": str(root), "TMPDIR": str(root), "PATH": os.defpath}) as child:
        try:
            output, diagnostic = child.communicate(raw, timeout=60)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise OracleError("worker-deadline") from None
    if child.returncode:
        stage = CHILD_STAGE.fullmatch(diagnostic)
        raise OracleError("worker-" + (stage[1].decode("ascii") if stage else "unconfirmed"))
    require(0 < len(output) <= 2 * 1024 * 1024, "worker-report-bound")
    report = json.loads(output)
    require(type(report) is dict and set(report) == {"responses"} and type(report["responses"]) is dict
            and report["responses"].keys() == requests.keys(), "worker-report")
    responses = report["responses"]
    headers = selected_oracle["HEADER_FIELDS"]
    for phase, group in responses.items():
        require(type(group) is list and len(group) == len(requests[phase]), "worker-response-count")
        for response in group:
            require(type(response) is dict and set(response) == {"status", "bodyBase64", *headers}
                    and type(response["status"]) is int and type(response["bodyBase64"]) is str
                    and all(response[name] is None or type(response[name]) is str for name in headers), "worker-response")
            response["body"] = selected_oracle["response_body"](response)
    return responses


def check_head(get, head):
    require(head["body"] == b"" and head["contentLength"] in (None, str(len(get["body"])))
            and (get["status"] != 200 or head["contentType"] == get["contentType"])
            and head["location"] == get["location"], "head-framing")


def check_nonempty_clash(old, new):
    import yaml

    original_names = ["alpha → mapped", "beta", "alpha", "alpha"]
    current_names = ["alpha → mapped", "beta", "alpha", "alpha (2)"]
    credentials = {"type": "ss", "server": "203.0.113.10", "port": 8388, "cipher": "aes-256-gcm", "password": "fixture"}
    for raw, names, legacy in ((old, original_names, True), (new, current_names, False)):
        expected = [{"name": name, **({"type": "temp"} if legacy and index >= 2 else credentials)}
                    for index, name in enumerate(names)]
        document = yaml.safe_load(raw)
        require(document["proxies"] == expected and len(document["proxy-groups"]) == 2
                and all(group["proxies"] == names for group in document["proxy-groups"]), "clash-path-and-temp-shape")


def compare(requests, old, worker, selected_oracle):
    counts = {"dormantChecks": 0, "exportBytePairs": 0, "clashShapePairs": 0, "relativeShortPairs": 0, "missingPairs": 0}
    for phase, group in requests.items():
        for index in range(0, len(group), 2):
            request = group[index]
            code, kind = request["code"], request["format"]
            new_get, new_head = worker[phase][index:index + 2]
            for response in (new_get, new_head):
                require((response["cacheControl"], response["referrerPolicy"], response["noSniff"])
                        == ("private, no-store", "no-referrer", "nosniff"), "worker-privacy")
            check_head(new_get, new_head)
            missing = phase == "dormant" or code == MISSING or (request["route"] == "aggregate" and kind is None)
            status = 404 if missing else 302 if request["route"] == "short" else 200
            require(new_get["status"] == new_head["status"] == status, "worker-paired-status")
            if phase == "dormant":
                require(new_get["body"] == b"Not found." and new_get["location"] is None, "dormant-refusal")
                counts["dormantChecks"] += 2
                continue
            old_get, old_head = old[phase][index:index + 2]
            check_head(old_get, old_head)
            require(old_get["status"] == old_head["status"] == status, "python-paired-status")
            old_body, new_body = old_get["body"], new_get["body"]
            if missing:
                require(new_body == b"Not found." and old_body in (b"not found", b"404: Not Found")
                        and old_get["location"] is None and new_get["location"] is None, "missing-framing")
                counts["missingPairs"] += 1
            elif status == 302:
                require(old_get["location"] == new_get["location"] == f"/agg/{code}/clash"
                        and old_body == b"302: Found" and new_body == b"", "relative-short-framing")
                counts["relativeShortPairs"] += 1
            else:
                for response, body in ((old_get, old_body), (new_get, new_body)):
                    require(response["contentType"] == selected_oracle["media"](kind) and response["location"] is None
                            and response["contentLength"] in ((str(len(body)),) if body else (None, "0")), "export-wire")
                require(old_get["cacheControl"] == old_head["cacheControl"] == "no-store, private", "python-privacy")
                if code == fixture.OWNER_CODE and kind in CLASH:
                    # Legacy emits two incomplete type=temp rows. The Worker resolves
                    # their raw SS links while keeping the names distinct for Mihomo.
                    check_nonempty_clash(old_body, new_body)
                    counts["clashShapePairs"] += 1
                    continue
                require(old_body == new_body, "export-bytes")
                if kind in BASE64:
                    labels = () if code == fixture.EMPTY_CODE else ("temporary-only",)
                    if code == fixture.OWNER_CODE:
                        owned = ("alpha", "beta", "trash") if phase == "restored" else ("alpha", "beta")
                        labels = (*owned, "temporary", "temporary")
                    expected = b64encode("\n".join(map(fixture.fixture_share, labels)).encode("ascii"))
                    require(new_body == expected, "ordered-scope-bytes")
                else:
                    require(code == fixture.EMPTY_CODE, "empty-case")
                    if kind in CLASH:
                        selected_oracle["check_clash"](new_body, (), [])
                    elif kind in SINGBOX:
                        selected_oracle["check_singbox"](old_body, new_body, ())
                    elif kind == "surge":
                        require(new_body == b"[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n", "empty-surge")
                    else:
                        require(kind in QX and new_body == b"", "empty-quantumult")
                counts["exportBytePairs"] += 1
    return counts


def main():
    require(len(sys.argv) == 1, "arguments")
    # Reuse the existing fixed scripts without changing either command contract.
    selected_oracle = run_path(str(TEST / "legacy-selected-short-oracle.integration.py"))
    dynamic_oracle = run_path(str(TEST / "legacy-dynamic-all-python.py"))
    dynamic_oracle["verify_sandbox"]()
    bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"])
    revision = os.environ["WORKER_TEST_REVISION"]
    with TemporaryDirectory(prefix="legacy-dynamic-all-package-oracle-") as directory:
        root = Path(directory)
        worker, fixtures, legacy_copy = root / "worker", root / "fixture", root / "legacy"
        fixtures.mkdir(mode=0o700)
        legacy_copy.mkdir(mode=0o700)
        worker_sha = selected_oracle["prepare_worker"](bundle, worker, revision)
        candidate = fixture.build_dynamic_all_fixture(fixtures, worker, revision)
        source = package.read_pinned(candidate.source, 1024 * 1024, candidate.source_sha256)
        candidate_io.put(legacy_copy / "legacy.sqlite", source)
        requests = cases()
        old = asyncio.run(dynamic_oracle["observe_candidate"](legacy_copy, requests, fixture))
        new = worker_responses(root, worker, worker_sha, revision, candidate, requests, selected_oracle)
        counts = compare(requests, old, new, selected_oracle)
        require(package.native.file_hash(candidate.source)[1] == candidate.source_sha256, "source-unchanged")
        selected_oracle["sql_statements"](candidate)
        print(json.dumps({"candidateVersion": 8, "historicalRestoreChecks": 1,
                          "legacyIncompleteClashTempRows": 2, **counts}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except OracleError as error:
        print(f"Legacy dynamic all package oracle failed at {error}.", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print("Legacy dynamic all package oracle could not be confirmed safely.", file=sys.stderr)
        raise SystemExit(2) from None

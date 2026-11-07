"""Compare one protected provider capture in legacy Python and emitted Workerd."""

from __future__ import annotations

from hashlib import sha256
import json
import logging
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory

from legacy_restore_package import private_path, read_pinned, read_private
import prepare_isolation_artifact as artifact


MAX_BODY = 10 * 1024**2
MAX_CONFIG = 16 * 1024**2
MAX_EXPORT = 4 * ((MAX_CONFIG + 2) // 3)
MAX_SAMPLES = 12
FORMATS = ("base64", "clash", "singbox", "surge", "qx")
FETCH_FAILURES = frozenset((
    "invalid-url", "invalid-auth", "blocked-address", "dns-failed", "tls-failed", "unavailable", "timeout",
    "invalid-redirect", "redirect-limit", "http-status", "body-too-large", "invalid-body", "skipped-rate-limit",
))
METADATA = frozenset(("content-type", "content-disposition", "profile-title", "subscription-userinfo"))
WORKER_JOBS = frozenset(("saved", "invalid-document", "source-rejected", "fetch-rejected"))
PARSER_KINDS = frozenset(("parsed", "no-nodes", "invalid-encoding", "malformed", "unsupported", "limit"))
PARSER_LIMITS = frozenset(("input-bytes", "depth", "complexity", "nodes", "node-bytes", "snapshot-bytes"))
FAILURE = "Hosted provider comparison could not be confirmed safely."
ROOT = Path(__file__).resolve().parents[2]


class ComparisonError(ValueError):
    """A fixed error for invalid private inputs or incomplete replay."""


def require(condition):
    if not condition:
        raise ComparisonError(FAILURE)


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def parse_json(body):
    return artifact._parse_object(body, FAILURE)


def compact(document):
    return json.dumps(document, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


def sample_urls(secret, expected):
    body = secret.encode("utf-8")
    require(0 < len(body) <= 48 * 1024 and sha256(body).hexdigest() == expected)
    document = parse_json(body)
    require(set(document) == {"version", "origin", "path", "urls"} and integer(document["version"], 1, 1))
    urls = document["urls"]
    require(isinstance(urls, list) and 1 <= len(urls) <= MAX_SAMPLES
            and all(isinstance(url, str) and 1 <= len(url.encode("utf-8")) <= 8192 for url in urls)
            and len(set(urls)) == len(urls))
    # The producer's independently pinned manifest already constrains the live
    # origin and path. Replay selects an exact URL by case without making requests.
    return urls


def read_samples(directory, count):
    document = parse_json(read_private(directory / "index.json", 256 * 1024))
    require(set(document) == {"version", "samples"} and integer(document["version"], 1, 1))
    rows = document["samples"]
    require(isinstance(rows, list) and len(rows) == count)
    expected_files = {"index.json"}
    for case, row in enumerate(rows, 1):
        require(isinstance(row, dict) and integer(row.get("case"), case, case))
        outcome = row.get("outcome")
        if outcome == "ok":
            name = f"sample-{case:02d}.body"
            require(set(row) - {"rpcMetadata", "legacyContentType"} == {"case", "outcome", "file", "decodedBytes", "bodySha256"}
                    and row["file"] == name and integer(row["decodedBytes"], 0, MAX_BODY))
            metadata = row.get("rpcMetadata", {})
            require(isinstance(metadata, dict) and set(metadata) <= METADATA
                    and all(isinstance(value, str) for value in metadata.values()) and len(compact(metadata)) <= 3072)
            media = row.get("legacyContentType", "")
            require(isinstance(media, str) and len(media.encode("utf-8")) <= 8192)
            expected_files.add(name)
        elif outcome == "http-status":
            require(set(row) == {"case", "outcome", "httpStatus"} and integer(row["httpStatus"], 100, 599)
                    and row["httpStatus"] != 200)
        else:
            require(outcome in FETCH_FAILURES and set(row) == {"case", "outcome"})
    require({entry.name for entry in directory.iterdir()} == expected_files)
    return rows


def verify_bundle(bundle, revision, run_id):
    require(re.fullmatch(r"[a-f0-9]{40}", revision) and re.fullmatch(r"[1-9][0-9]{0,19}", run_id))
    manifest = parse_json(read_private(bundle / "isolation.json", artifact._MAX_JSON))
    attempt = manifest.get("runAttempt")
    require(isinstance(attempt, str) and artifact._DECIMAL.fullmatch(attempt))
    hashes, _ = artifact._expected_hashes(manifest, revision, run_id, attempt)
    for name in ("index.js", *(migration["name"] for migration in manifest["migrations"])):
        read_pinned(bundle / name, artifact._MAX_EXPANDED, hashes[name])
    return attempt


def write_private(path, content):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as file:
        file.write(content)


def quiet(command, scratch, timeout, *, cwd=None):
    environment = {"PATH": os.defpath, "HOME": str(scratch), "TMPDIR": str(scratch), "LANG": "C.UTF-8"}
    return subprocess.run(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, timeout=timeout, check=False).returncode


def native_check(format_name, scratch):
    setting = {"clash": "MIHOMO_TEST_BINARY", "singbox": "SINGBOX_TEST_BINARY"}.get(format_name)
    binary = os.environ.get(setting, "") if setting else ""
    if not binary:
        return "not-applicable" if format_name == "base64" else "unavailable"
    path = Path(binary)
    require(path.is_absolute() and path.is_file())
    # The caller obtains the checksum-pinned binaries before secrets are exposed.
    # The same network-namespace mechanism is used by Provider Fetch CI.
    isolate = ("sudo", "-n", "unshare", "--net", f"--setgid={os.getegid()}", f"--setuid={os.geteuid()}", "--")
    fresh = ("/usr/bin/env", "-i", f"HOME={scratch}", f"TMPDIR={scratch}", f"PATH={os.defpath}", "LANG=C.UTF-8")
    options = ("-t", "-d", str(scratch), "-f") if format_name == "clash" else ("check", "-c")
    try:
        if quiet((*isolate, "/usr/bin/true"), scratch, 3) != 0:
            return "unavailable"
        command = (*isolate, *fresh, binary, *options, str(scratch / (format_name + ".body")))
        return "accepted" if quiet(command, scratch, 15) == 0 else "rejected"
    except (OSError, subprocess.TimeoutExpired):
        return "unavailable"


def worker_replay(bundle, sample_file, row, source, scratch):
    controls = scratch / "request.json"
    write_private(controls, compact({"source": source, "decodedBytes": row["decodedBytes"],
                                     "bodySha256": row["bodySha256"], "rpcMetadata": row.get("rpcMetadata")}))
    node = shutil.which("node")
    require(node)
    try:
        result = quiet((node, str(Path(__file__).with_name("provider-live-worker.ts")),
                        str(bundle), str(sample_file), str(scratch), str(controls)), scratch, 90, cwd=ROOT / "worker")
    finally:
        controls.unlink()
    require(result == 0)
    replay = parse_json(read_private(scratch / "worker.json", 16 * 1024))
    document = replay["document"]
    require(isinstance(document, dict)
            and set(document) - {"limit"} == {"kind", "format", "envelope", "nodes", "malformed", "unsupported", "ignored"}
            and document["kind"] in PARSER_KINDS and document["format"] in (None, "text", "clash", "singbox")
            and document["envelope"] in ("plain", "base64")
            and all(integer(document[key], 0, MAX_BODY) for key in ("nodes", "malformed", "unsupported", "ignored"))
            and (document.get("limit") in PARSER_LIMITS if document["kind"] == "limit" else "limit" not in document)
            and replay["job"] in WORKER_JOBS)
    return replay


def compare_exports(convert, nodes, worker, scratch):
    import yaml

    exports = (convert.to_base64_sub, convert.to_clash, convert.to_singbox, convert.to_surge, convert.to_qx)
    results = {}
    for format_name, export in zip(FORMATS, exports, strict=True):
        expected = None
        legacy = "not-tested"
        if nodes:
            try:
                expected = export(nodes).encode("utf-8")
                legacy = "available" if len(expected) <= MAX_EXPORT else "limit"
            except convert.ExportError:
                legacy = "rejected"
            except Exception:
                legacy = "error"
        result = {"legacy": legacy, "workerStatus": None, "bytes": None, "comparison": "not-comparable", "client": "not-tested"}
        if worker["job"] == "saved":
            response = worker["formats"][format_name]
            status, size = response["status"], response["bytes"]
            limit = MAX_EXPORT if format_name == "base64" else MAX_CONFIG
            require(status in (200, 422) and integer(size, 0, limit))
            result.update(workerStatus=status, bytes=size)
            if status == 200:
                actual = read_private(scratch / (format_name + ".body"), limit)
                require(len(actual) == size)
                if legacy == "available":
                    comparison = "exact" if actual == expected else "different"
                    if comparison == "different" and format_name in ("clash", "singbox"):
                        parse = yaml.safe_load if format_name == "clash" else json.loads
                        try:
                            left = json.dumps(parse(actual), sort_keys=True, allow_nan=False)
                            right = json.dumps(parse(expected), sort_keys=True, allow_nan=False)
                            if left == right:
                                comparison = "equal-document"
                        except Exception:
                            pass
                    result["comparison"] = comparison
                result["client"] = native_check(format_name, scratch)
        results[format_name] = result
    return results


def compare_sample(directory, bundle, row, source):
    # Load the legacy parser in its own pinned environment, separate from transport.
    sys.path.insert(0, str(ROOT))
    import aiohttp.helpers
    import convert

    sample_file = directory / row["file"]
    body = read_pinned(sample_file, MAX_BODY, row["bodySha256"])
    require(len(body) == row["decodedBytes"])
    headers = row.get("rpcMetadata", {})
    legacy_headers = {**headers}
    if "legacyContentType" in row:
        legacy_headers["content-type"] = row["legacyContentType"]
    try:
        charset = aiohttp.helpers.parse_mimetype(legacy_headers.get("content-type", "")).parameters.get("charset")
        nodes, hysteria_rejected = convert.parse_nodes_from_text_with_report(convert.decode_subscription_bytes(body, charset))
        legacy = "limit" if len(nodes) > 5000 else "parsed" if nodes else "no-nodes"
        metadata = convert.parse_subscription_headers(legacy_headers)
    except Exception:
        nodes, hysteria_rejected, legacy, metadata = [], 0, "error", {}
    with TemporaryDirectory(prefix=".provider-compare-", dir=directory) as temp:
        scratch = Path(temp)
        worker = worker_replay(bundle, sample_file, row, source, scratch)
        result = {"case": row["case"], "outcome": "ok", "decodedBytes": len(body),
                  "legacy": {"kind": legacy, "nodes": len(nodes), "rejectedHysteria2": hysteria_rejected},
                  "worker": {"job": worker["job"], "document": worker["document"]}}
        if worker["job"] == "saved":
            require(integer(worker.get("chunks"), 1, 256) and integer(worker.get("ndjsonBytes"), 1, 64 * 1024**2)
                    and set(worker["formats"]) == set(FORMATS))
            match = {}
            for name, old_name in (("trafficUsed", "traffic_used"), ("trafficTotal", "traffic_total"), ("expireAt", "expire_at")):
                old, new = metadata.get(old_name), worker["metadata"][name]
                if new is not None:
                    require(type(new) in (int, float) and math.isfinite(new))
                match[name] = "not-compared" if "subscription-userinfo" not in headers or legacy == "error" else (
                    "both-missing" if old is None and new is None else "equal" if old == new else "different")
            result["worker"].update(chunks=worker["chunks"], ndjsonBytes=worker["ndjsonBytes"], metadata=match)
        result["formats"] = compare_exports(convert, nodes if legacy == "parsed" else [], worker, scratch)
        return result


def main(args=None):
    args = sys.argv[1:] if args is None else args
    logging.disable(logging.CRITICAL)
    try:
        require(len(args) == 1 and os.environ.get("GITHUB_ACTIONS") == "true"
                and os.environ.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
                and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and os.environ.get("GITHUB_REF") == artifact.MAIN_REF and os.environ.get("GITHUB_RUN_ATTEMPT") == "1")
        runner = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
        directory = private_path(Path(args[0]), directory=True)
        require(directory.parent == runner)
        bundle = private_path(runner / artifact.VERIFIED_DIRECTORY, directory=True)
        revision, run_id = os.environ["GITHUB_SHA"], os.environ["SUBS_BOT_CI_RUN_ID"]
        build_attempt = verify_bundle(bundle, revision, run_id)
        urls = sample_urls(os.environ.pop("SUBS_BOT_PROVIDER_LIVE_SAMPLE_JSON", ""), os.environ["SUBS_BOT_PROVIDER_LIVE_SAMPLE_SHA256"])
        rows = read_samples(directory, len(urls))
        result = [compare_sample(directory, bundle, row, url) if row["outcome"] == "ok" else row
                  for row, url in zip(rows, urls, strict=True)]
        print(compact({"version": 1, "runtime": "github-hosted-workerd-replay", "revision": revision,
                       "workerCiRunId": run_id, "workerBuildAttempt": build_attempt, "samples": result}).decode("ascii"))
        return 0 if any(row.get("worker", {}).get("job") == "saved" for row in result) else 1
    except KeyboardInterrupt:
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""Hosted exact emitted-Worker check of a sealed synthetic legacy temp inventory."""

from base64 import b64encode
from contextlib import closing, suppress
from hashlib import sha256
from pathlib import Path
from shutil import which
import json
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

import legacy_restore_package as package
import legacy_temp_inventory as inventory
import legacy_temp_worker_projection as projection
import prepare_isolation_artifact as artifact
from export_errors import ExportError
from share_export import to_share_links


BOT_ID = "73101"
OWNERS = {"supported": "73102", "malformed": "73103", "realm": "73104"}
CHILD_FAILURE = re.compile(rb"The isolated temp Worker oracle could not be confirmed \("
                           rb"(sandbox|input|artifact|migrations|d1-seed|d1-readback|http|r2-empty|dispose)\)\.\n")
MAX_INPUT = 1024 * 1024
MAX_REPORT = 16 * 1024
DDL = """CREATE TABLE IF NOT EXISTS temp_nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    url TEXT NOT NULL,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL
)"""


class OracleError(RuntimeError):
    """A failure carrying only a fixed fixture checkpoint."""


def require(condition, checkpoint):
    if not condition:
        raise OracleError(checkpoint)


def compact(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value):
    return sha256(value).hexdigest()


def fixture_groups():
    ss = "SS://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388"
    vmess = "vmess://" + b64encode(compact({
        "ps": "VMess payload label", "add": "vm.fixture.invalid", "port": 443, "id": "synthetic-client", "net": "tcp",
    })).decode("ascii") + "#VMess%20fragment%20label"
    repeated = ("same node across the batch seam", ss + "#Repeated")
    supported = [
        ('  旧名称 "引号"\n\x01👩\u200d💻  ', ss + "#%E5%8E%9F%E5%A7%8B%0A%26尾 "),
        ("独立保存的 VMess 名称", vmess),
        ("", "ssr://opaque-legacy-share#Original"),
        ("Legacy Snell", "snell://opaque-legacy-share#Original"),
        ("Legacy WireGuard", "wireguard://opaque-legacy-share#Original"),
        ("Legacy SOCKS TLS", "socks5-tls://opaque-legacy-share#Original"),
        ("Legacy Hysteria 2", "hy2://auth-fixture@[2001:db8::42]:443,5000-5001#Hop%20ports"),
    ]
    supported.extend([("stable filler", ss + "#Filler")] * 492)
    supported.extend([repeated, repeated])
    return {
        "supported": supported,
        "malformed": [("valid prefix must not escape", ss + "#ValidPrefix"), ("malformed known scheme", "ss://nonsense")],
        "realm": [("unsupported Realm", "hysteria2+realm://token-fixture@realm.example.invalid/name")],
    }


def make_source(path, groups):
    # Interleave distinct owners so only the old ID order determines each
    # owner's batches. Legacy dates deliberately do not sort the rows.
    sequence = [
        ("supported", groups["supported"][0]),
        ("malformed", groups["malformed"][0]),
        ("realm", groups["realm"][0]),
        ("malformed", groups["malformed"][1]),
        *(("supported", node) for node in groups["supported"][1:]),
    ]
    rows = {key: [] for key in groups}
    with closing(sqlite3.connect(path)) as db, db:
        db.execute(DDL)
        for index, (label, (name, share)) in enumerate(sequence, 1):
            identity = index * 2
            db.execute("INSERT INTO temp_nodes VALUES (?,?,?,?,?)",
                       (identity, int(OWNERS[label]), share, name, 1_700_000_000 - index))
            rows[label].append((identity, {"name": name, "type": "temp", "share": share}))
    path.chmod(0o600)
    return rows


def verified_fixture(root):
    source, sealed = root / "source.sqlite", root / "inventory"
    rows = make_source(source, fixture_groups())
    source_sha = package.native.file_hash(source)[1]
    owner_map_sha = digest(b"{}")
    pins = {"source_sha256": source_sha, "owner_map": {}, "owner_map_sha256": owner_map_sha, "legacy_bot_id": BOT_ID}
    try:
        result = inventory.seal_inventory(source, sealed, **pins)
    except inventory.InventoryError:
        raise OracleError("inventory-seal") from None
    require(result["inventory"]["rows"] == result["inventory"]["pendingWorkerRows"] == 504
            and result["inventory"]["blockedRows"] == 0 and result["inventory"]["blockedOwnerScopes"] == 0,
            "inventory-closure")
    try:
        verified = projection.verify_projection(source, sealed, root, inventory_manifest_sha256=result["manifestSha256"], **pins)
    except projection.ProjectionError:
        raise OracleError("inventory-projection") from None
    require(verified.source_sha256 == source_sha and verified.inventory_manifest_sha256 == result["manifestSha256"]
            and verified.node_count == 504 and len(verified.batches) == 4, "projection-closure")
    return source, rows, verified


def fixture_expectations(rows, verified):
    expected = {
        "supported": [rows["supported"][:500], rows["supported"][500:]],
        "malformed": [rows["malformed"]],
        "realm": [rows["realm"]],
    }
    node_batches = iter(verified.batches)
    owners, readback = [], {}
    for label, expected_batches in expected.items():
        batches = []
        readback[label] = []
        for rows_in_batch in expected_batches:
            batch = next(node_batches)
            nodes = [node for _, node in rows_in_batch]
            raw = compact(nodes)
            require(batch.owner_id == OWNERS[label] and batch.node_count == len(nodes)
                    and batch.first_legacy_id == rows_in_batch[0][0] and batch.last_legacy_id == rows_in_batch[-1][0]
                    and batch.payload_bytes == len(raw) and batch.payload_json.encode("utf-8") == raw,
                    "projection-name-uri-order")
            batches.append({"nodesJson": batch.payload_json, "nodeCount": batch.node_count, "payloadBytes": batch.payload_bytes})
            readback[label].append({"nodeCount": len(nodes), "payloadBytes": len(raw), "payloadSha256": digest(raw),
                                    "namesSha256": digest(compact([node["name"] for node in nodes]))})
        owners.append({"label": label, "ownerId": OWNERS[label], "batches": batches})
    require(verified.payload_bytes == sum(batch["payloadBytes"] for batches in readback.values() for batch in batches),
            "projection-payload-bytes")
    supported = [node for _, node in rows["supported"]]
    shares = [node["share"] for node in supported]
    require(len(shares) == 501 and shares[499] == shares[500] and to_share_links(supported) == shares, "legacy-raw-compatibility")
    for label in ("malformed", "realm"):
        try:
            to_share_links([node for _, node in rows[label]])
        except ExportError:
            continue
        raise OracleError("legacy-rejected-group")
    return owners, readback, b64encode("\n".join(shares).encode("utf-8"))


def worker_probe(root, bundle, revision, owners):
    node = which("node")
    require(node is not None, "node-present")
    raw = package.read_private(bundle / "isolation.json", artifact._MAX_JSON)
    manifest = package.native.parsed(raw, artifact._MAX_JSON)
    require(manifest.get("revision") == revision and artifact._REVISION.fullmatch(revision), "build-revision")
    payload = compact({"workerDir": str(bundle), "workerManifestSha256": digest(raw), "revision": revision,
                       "botId": BOT_ID, "owners": owners})
    require(len(payload) <= MAX_INPUT, "probe-input-bound")
    with subprocess.Popen(
        [node, str(TOOLS / "legacy-temp-oracle-worker.ts")], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=root, start_new_session=True,
        env={"HOME": str(root), "TMPDIR": str(root), "PATH": os.defpath},
    ) as child:
        try:
            report, diagnostic = child.communicate(payload, timeout=60)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise OracleError("probe-deadline") from None
    if child.returncode:
        match = CHILD_FAILURE.fullmatch(diagnostic)
        raise OracleError("worker-" + (match[1].decode("ascii") if match else "unconfirmed"))
    require(0 < len(report) <= MAX_REPORT, "probe-output-bound")
    return json.loads(report)


def check_worker(report, revision, readback, expected_base64):
    require(type(report) is dict and set(report) == {"revision", "batches", "http", "r2ObjectCount"}
            and report["revision"] == revision and report["batches"] == readback
            and type(report["r2ObjectCount"]) is int and report["r2ObjectCount"] == 0, "worker-name-and-payload-readback")
    rejected = b"Subscription content cannot be exported."
    missing = b"Not found."
    expected = {
        "supported": (200, expected_base64), "malformed": (422, rejected), "realm": (422, rejected),
        "wrongBot": (404, missing), "wrongOwner": (404, missing), "selected": (404, missing), "short": (302, b""),
    }
    require(type(report["http"]) is dict and set(report["http"]) == set(expected), "worker-http-closure")
    for label, (status, body) in expected.items():
        row = report["http"][label]
        require(type(row) is dict and set(row) == {"getStatus", "headStatus", "bodyBytes", "bodySha256", "headContentLength"}
                and row["getStatus"] == row["headStatus"] == status and type(row["bodyBytes"]) is int and row["bodyBytes"] == len(body)
                and row["bodySha256"] == digest(body), "worker-http-" + label)
        length = row["headContentLength"]
        require(length is None or (type(length) is int and length == len(body)), "worker-head-length")


def main():
    require(sys.platform == "linux" and os.geteuid() != 0 and [name for _, name in socket.if_nameindex()] == ["lo"]
            and resource.getrlimit(resource.RLIMIT_CORE)[0] == 0, "loopback-only-namespace")
    bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"])
    revision = os.environ["WORKER_TEST_REVISION"]
    with TemporaryDirectory(prefix="legacy-temp-worker-oracle-") as name:
        root = Path(name)
        source, rows, verified = verified_fixture(root)
        owners, readback, expected_base64 = fixture_expectations(rows, verified)
        check_worker(worker_probe(root, bundle, revision, owners), revision, readback, expected_base64)
        require(package.native.file_hash(source)[1] == verified.source_sha256, "source-remains-unchanged")
        print(json.dumps({"sourceRows": verified.node_count, "verifiedBatches": len(verified.batches), "rawCompatibleRows": 501,
                          "malformedAggregateScopes": 1, "unsupportedRealmScopes": 1, "isolationChecks": 3,
                          "relativeRedirectChecks": 1}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except OracleError as error:
        print(f"Legacy temp Worker oracle failed at {error}.", file=sys.stderr)
        raise SystemExit(2) from None
    except Exception:
        print("Legacy temp Worker oracle could not be confirmed safely.", file=sys.stderr)
        raise SystemExit(2) from None

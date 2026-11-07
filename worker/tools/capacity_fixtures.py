"""Create private, synthetic fixtures for the isolated Worker's export boundaries."""

import argparse
import base64
from collections.abc import Iterator
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sys
import uuid


CHUNK_BYTES = 512 * 1024
SNAPSHOT_BYTES = 64 * 1024 * 1024
SHARE_BYTES = 16 * 1024 * 1024
NODE_COUNT = 100_000
LINE_OVERHEAD = len(b'{"share":"","pad":""}\n')
SHARE_PREFIX = b"ss://YWVzLTI1Ni1nY206Zml4dHVyZS1vbmx5@203.0.113.10:8388#"
CAPACITY_STATUS = {"at-limits": 200, "share-over": 422, "snapshot-over": 503}
STRUCTURED_SMOKE = "structured-smoke"
SINGBOX_SMOKE = "singbox-smoke"
SMOKE_PROFILES = {
    STRUCTURED_SMOKE: {"structured-mixed": 200, "structured-unsupported": 422},
    SINGBOX_SMOKE: {"singbox-mixed": 200, "singbox-unsupported": 422},
}
FIXTURE_PROFILES = {"capacity": CAPACITY_STATUS, **SMOKE_PROFILES}
SMOKE_CHUNK_COUNT = 2
SMOKE_OBJECT_LIMIT = 4096


def _write_private(path: Path, body: bytes | bytearray) -> str:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(body)
    return hashlib.sha256(body).hexdigest()


def _json_bytes(value: dict) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _at_limits_layout() -> Iterator[list[tuple[int, int]]]:
    chunk_count = SNAPSHOT_BYTES // CHUNK_BYTES
    nodes_per_chunk, larger_chunks = divmod(NODE_COUNT, chunk_count)
    share_length, longer_shares = divmod(SHARE_BYTES - (NODE_COUNT - 1), NODE_COUNT)
    first_node = 0
    for index in range(chunk_count):
        count = nodes_per_chunk + (index < larger_chunks)
        line_length, longer_lines = divmod(CHUNK_BYTES, count)
        yield [
            (line_length + (offset < longer_lines), share_length + (first_node + offset < longer_shares))
            for offset in range(count)
        ]
        first_node += count


def _share_over_layout() -> Iterator[list[tuple[int, int]]]:
    full_share = CHUNK_BYTES - LINE_OVERHEAD
    full_chunks, final_share = divmod(SHARE_BYTES + 1, full_share + 1)
    for _ in range(full_chunks):
        yield [(CHUNK_BYTES, full_share)]
    yield [(final_share + LINE_OVERHEAD, final_share)]


def _fixture_metadata(
    root: Path, label: str, status: int, chunks: list[dict], descriptors: list[dict],
    share_bytes: int, export_sha256: str | None,
) -> dict:
    manifest_file = f"{label}/manifest.json"
    manifest_sha256 = _write_private(
        root / manifest_file, _json_bytes({"version": 1, "chunks": descriptors}),
    )
    return {
        "label": label,
        "token": "subsbot-synthetic-capacity-" + secrets.token_urlsafe(24),
        "snapshotId": str(uuid.uuid4()),
        "nodeCount": sum(entry["count"] for entry in descriptors),
        "nodeBytes": sum(entry["bytes"] for entry in descriptors),
        "shareBytes": share_bytes,
        "exportBytes": 4 * ((share_bytes + 2) // 3) if export_sha256 is not None else 0,
        "exportSha256": export_sha256,
        "manifestFile": manifest_file,
        "manifestSha256": manifest_sha256,
        "status": status,
        "chunks": chunks,
    }


def _write_data_fixture(
    root: Path, label: str, status: int, layout: Iterator[list[tuple[int, int]]],
) -> dict:
    (root / label).mkdir(mode=0o700)
    chunks = []
    node_index = 0
    share_bytes = 0
    export_hash = hashlib.sha256()
    carry = b""
    for index, records in enumerate(layout):
        chunk = bytearray()
        for line_length, share_length in records:
            prefix = SHARE_PREFIX + f"capacity-{node_index:06d}-".encode("ascii")
            share = prefix + b"x" * (share_length - len(prefix))
            pad_length = line_length - len(share) - LINE_OVERHEAD
            if len(share) != share_length or pad_length < 0:
                raise ValueError("Capacity fixture layout does not fit its synthetic records.")
            chunk.extend(b'{"share":"' + share + b'","pad":"' + b"p" * pad_length + b'"}\n')

            # The Worker joins share lines with LF and never appends a final LF.
            raw = (b"\n" + share) if node_index else share
            share_bytes += len(raw)
            if status == 200:
                part = carry + raw
                end = len(part) - len(part) % 3
                export_hash.update(base64.b64encode(part[:end]))
                carry = part[end:]
            node_index += 1

        if not 0 < len(chunk) <= CHUNK_BYTES:
            raise ValueError("Capacity fixture chunk exceeds its size limit.")
        file = f"{label}/{index}.ndjson"
        chunks.append({
            "file": file, "bytes": len(chunk), "sha256": _write_private(root / file, chunk), "count": len(records),
        })
    export_hash.update(base64.b64encode(carry))
    descriptors = [{key: entry[key] for key in ("bytes", "sha256", "count")} for entry in chunks]
    return _fixture_metadata(
        root, label, status, chunks, descriptors, share_bytes, export_hash.hexdigest() if status == 200 else None,
    )


def _write_over_snapshot(root: Path) -> dict:
    label = "snapshot-over"
    (root / label).mkdir(mode=0o700)
    # The sizes, counts and hashes are individually well formed. Their sum is
    # over the limit, so the Worker must reject the manifest before reading a chunk.
    sizes = [CHUNK_BYTES] * (SNAPSHOT_BYTES // CHUNK_BYTES - 1) + [CHUNK_BYTES - 2, 3]
    descriptors = [
        {"bytes": size, "sha256": hashlib.sha256(f"absent synthetic chunk {index}".encode("ascii")).hexdigest(), "count": 1}
        for index, size in enumerate(sizes)
    ]
    return _fixture_metadata(root, label, 503, [], descriptors, 0, None)


def structured_smoke_fixture(label: str) -> tuple[list[bytes], int, bytes]:
    # The Python serializer is independent of the deployed Worker's implementation.
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)
    from export_errors import ExportError
    from share_export import to_share_links

    structured = {
        "type": "ss", "server": "203.0.113.10", "port": 8388,
        "name": "港 + 字", "cipher": "aes-256-gcm", "password": "fixture-only",
    }
    stored = {"share": "vless://synthetic-client@bücher.example:443#原始标签 😀"}
    if label == "structured-mixed":
        nodes = [structured, stored]
        raw = "\n".join(to_share_links(nodes)).encode("utf-8")
    elif label == "structured-unsupported":
        # Put a valid stored share first to check rejection before a partial response.
        nodes = [stored, {**structured, "plugin": "v2ray-plugin", "plugin_opts": "tls;cert=/path/to/synthetic-fixture"}]
        try:
            to_share_links(nodes)
        except ExportError:
            raw = b""
        else:
            raise ValueError("The Python oracle accepted the unsupported synthetic fixture.")
    else:
        raise ValueError("Unknown structured smoke fixture.")
    return [_json_bytes(node) + b"\n" for node in nodes], len(raw), base64.b64encode(raw)


def canonical_singbox(value) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def singbox_smoke_fixture(label: str) -> tuple[list[bytes], int, bytes]:
    root = str(Path(__file__).resolve().parents[2])
    if root not in sys.path:
        sys.path.insert(0, root)
    from export_errors import ExportError
    from singbox_export import to_singbox

    structured = {
        "type": "ss", "server": "203.0.113.10", "port": 8388,
        "name": "proxy", "cipher": "aes-256-gcm", "password": "fixture-only",
    }
    stored = {
        "type": "temp", "name": "港 字",
        "share": "vless://11111111-1111-4111-8111-111111111111@proxy.example.invalid:443?security=tls&type=grpc&serviceName=fixture",
    }
    if label == "singbox-mixed":
        nodes = [structured, stored]
    elif label == "singbox-unsupported":
        nodes = [stored, {**structured, "dialer-proxy": "unavailable-dependency"}]
    else:
        raise ValueError("Unknown Sing-box smoke fixture.")

    try:
        # These fixed raw families are fully parsed by singbox_export itself.
        config = to_singbox(nodes, parse_share_link=lambda _: None)
    except ExportError:
        if label != "singbox-unsupported":
            raise ValueError("The Python oracle rejected the accepted synthetic Sing-box fixture.") from None
        expected = b""
    else:
        if label != "singbox-mixed":
            raise ValueError("The Python oracle accepted the unsupported synthetic Sing-box fixture.")
        expected = canonical_singbox(json.loads(config))
    return [_json_bytes(node) + b"\n" for node in nodes], 0, expected


def smoke_fixture(profile: str, label: str) -> tuple[list[bytes], int, bytes]:
    return singbox_smoke_fixture(label) if profile == SINGBOX_SMOKE else structured_smoke_fixture(label)


def _write_smoke_fixture(root: Path, profile: str, label: str, status: int) -> dict:
    (root / label).mkdir(mode=0o700)
    bodies, share_bytes, export = smoke_fixture(profile, label)
    descriptors, chunks = [], []
    for index, body in enumerate(bodies):
        file = f"{label}/{index}.ndjson"
        descriptor = {"bytes": len(body), "sha256": _write_private(root / file, body), "count": 1}
        descriptors.append(descriptor)
        chunks.append({"file": file, **descriptor})
    metadata = _fixture_metadata(
        root, label, status, chunks, descriptors, share_bytes, hashlib.sha256(export).hexdigest() if export else None,
    )
    metadata["exportBytes"] = len(export)
    return metadata


def generate_capacity_fixtures(directory: Path, revision: str, *, profile: str = "capacity") -> dict:
    """Create a new fixture directory and write its metadata last."""
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("A full lowercase Git revision is required.")
    if profile not in FIXTURE_PROFILES:
        raise ValueError("Unknown synthetic fixture profile.")
    directory.mkdir(mode=0o700)
    if profile in SMOKE_PROFILES:
        fixtures = [_write_smoke_fixture(directory, profile, label, status) for label, status in SMOKE_PROFILES[profile].items()]
    else:
        fixtures = [
            _write_data_fixture(directory, "at-limits", 200, _at_limits_layout()),
            _write_data_fixture(directory, "share-over", 422, _share_over_layout()),
            _write_over_snapshot(directory),
        ]
    metadata = {"version": 1, "revision": revision, "fixtures": fixtures}
    _write_private(directory / "capacity.json", _json_bytes(metadata) + b"\n")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("revision")
    parser.add_argument("--profile", choices=FIXTURE_PROFILES, default="capacity")
    args = parser.parse_args()
    try:
        generate_capacity_fixtures(args.output_dir, args.revision, profile=args.profile)
    except ValueError as exc:
        parser.exit(1, f"{exc}\n")
    except OSError:
        parser.exit(1, "Could not create the private capacity fixture directory or files.\n")


if __name__ == "__main__":
    main()

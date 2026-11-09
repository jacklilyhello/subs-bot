"""Rebuild a sealed private temporary-node inventory before Worker validation."""

from contextlib import contextmanager
from dataclasses import dataclass, field
from hashlib import sha256
from itertools import islice
import json
import os
from pathlib import Path
import stat
from tempfile import TemporaryDirectory

import legacy_snapshot_convert as converter
import legacy_temp_inventory as inventory


ERROR = "The legacy temporary node projection could not be verified safely."
FILES = {inventory.MANIFEST: 64 * 1024, inventory.SEAL: 65, inventory.ROWS: inventory.MAX_ROWS_BYTES}
ROW_FIELDS = {"ordinal", "legacyId", "originalOwnerId", "ownerId", "createdAt", "uriBytes", "uriSha256",
              "nameBytes", "nameSha256", "disposition", "reasons", "node"}


class ProjectionError(RuntimeError):
    """A projection failure with a fixed, non-sensitive message."""


@dataclass(frozen=True)
class TempBatch:
    owner_id: str = field(repr=False)
    first_legacy_id: int
    last_legacy_id: int
    node_count: int
    payload_bytes: int
    payload_json: str = field(repr=False)


@dataclass(frozen=True)
class TempProjection:
    source_sha256: str
    inventory_manifest_sha256: str
    node_count: int
    payload_bytes: int
    batches: tuple[TempBatch, ...] = field(repr=False)


def require(condition):
    if not condition:
        raise ProjectionError(ERROR)


def _directory(value):
    directory = converter._safe_path(Path(value), existing=True, directory=True)
    info = directory.lstat()
    require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0)
    return directory


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_mode, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


@contextmanager
def _open_private(path, maximum):
    expected = path.lstat()
    require(stat.S_ISREG(expected.st_mode) and expected.st_uid == os.geteuid() and expected.st_mode & 0o077 == 0
            and expected.st_nlink == 1 and expected.st_size <= maximum)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as stream:
        require(_identity(os.fstat(stream.fileno())) == _identity(expected))
        yield stream
        require(_identity(os.fstat(stream.fileno())) == _identity(path.lstat()) == _identity(expected))


def _require_file_set(root):
    with os.scandir(root) as entries:
        require({entry.name for entry in islice(entries, len(FILES) + 1)} == set(FILES))


def _compare_files(original, rebuilt):
    _require_file_set(original)
    _require_file_set(rebuilt)
    for name, maximum in FILES.items():
        with _open_private(original / name, maximum) as supplied, _open_private(rebuilt / name, maximum) as expected:
            remaining = maximum
            while block := expected.read(64 * 1024):
                remaining -= len(block)
                require(remaining >= 0 and supplied.read(len(block)) == block)
            require(not supplied.read(1))
    _require_file_set(original)


@dataclass
class _OwnerBatches:
    owner_id: str
    nodes: int = 0
    payload_bytes: int = 0
    first_id: int = 0
    last_id: int = 0
    current_bytes: int = 0
    current: list[bytes] = field(default_factory=list)
    batches: list[TempBatch] = field(default_factory=list)

    def flush(self):
        if not self.current:
            return
        payload = b"[" + b",".join(self.current) + b"]"
        require(len(payload) == self.current_bytes)
        self.batches.append(TempBatch(self.owner_id, self.first_id, self.last_id, len(self.current), len(payload),
                                      payload.decode("utf-8")))
        self.current.clear()
        self.current_bytes = 0

    def add(self, identity, node):
        require(len(node) + 2 <= inventory.MAX_BATCH_BYTES and self.last_id < identity)
        if self.current and (len(self.current) >= inventory.MAX_BATCH_NODES
                             or self.current_bytes + len(node) + 1 > inventory.MAX_BATCH_BYTES):
            self.flush()
        additional = len(node) + (1 if self.current else 2)
        require(self.nodes < inventory.MAX_OWNER_NODES and self.payload_bytes + additional <= inventory.MAX_OWNER_BYTES)
        if not self.current:
            self.first_id = identity
        self.last_id = identity
        self.nodes += 1
        self.payload_bytes += additional
        self.current_bytes += additional
        self.current.append(node)


def _read_row(raw, ordinal, previous):
    row = json.loads(raw.decode("utf-8"))
    require(isinstance(row, dict) and set(row) == ROW_FIELDS and converter._json(row) + b"\n" == raw
            and inventory._integer(row["ordinal"], ordinal, ordinal)
            and inventory._integer(row["legacyId"], previous + 1) and inventory._integer(row["createdAt"])
            and isinstance(row["ownerId"], str) and converter.OWNER.fullmatch(row["ownerId"])
            and int(row["ownerId"]) <= converter.MAX_OWNER and row["originalOwnerId"] == row["ownerId"]
            and row["disposition"] == "pending-worker" and row["reasons"] == [])
    node = row["node"]
    require(isinstance(node, dict) and set(node) == {"name", "type", "share"} and node["type"] == "temp"
            and isinstance(node["name"], str) and isinstance(node["share"], str))
    for field_name, evidence in (("name", "name"), ("share", "uri")):
        value = node[field_name].encode("utf-8")
        require(inventory._integer(row[evidence + "Bytes"], len(value), len(value))
                and row[evidence + "Sha256"] == sha256(value).hexdigest())
    return row["ownerId"], row["legacyId"], converter._json({"name": node["name"], "type": "temp", "share": node["share"]})


def _project(root, report, source_sha, manifest_sha):
    counts = report["inventory"]
    require(report["workerValidation"] == "pending" and report["completeImportable"] is False
            and counts["blockedRows"] == counts["blockedOwnerScopes"] == 0
            and counts["rowReasons"] == counts["scopeReasons"] == {}
            and counts["pendingWorkerRows"] == counts["rows"] and inventory._integer(counts["rows"], 0, inventory.MAX_ROWS))
    owners = {}
    maximum = inventory.MAX_BATCH_BYTES + 4096
    previous = ordinal = 0
    with _open_private(root / inventory.ROWS, inventory.MAX_ROWS_BYTES) as rows:
        while raw := rows.readline(maximum + 1):
            ordinal += 1
            require(ordinal <= counts["rows"] and len(raw) <= maximum and raw.endswith(b"\n"))
            owner, previous, node = _read_row(raw, ordinal, previous)
            if owner not in owners:
                owners[owner] = _OwnerBatches(owner)
            owners[owner].add(previous, node)
    require(ordinal == counts["rows"])
    batches = []
    for owner in sorted(owners, key=int):
        state = owners[owner]
        state.flush()
        batches.extend(state.batches)
    payload_bytes = sum(batch.payload_bytes for batch in batches)
    require(counts["projection"] == {"status": "preflight-only", "owners": len(owners), "batches": len(batches),
            "payloadBytes": payload_bytes, "maxOwnerNodes": max((state.nodes for state in owners.values()), default=0),
            "maxOwnerBytes": max((state.payload_bytes for state in owners.values()), default=0)})
    return TempProjection(source_sha, manifest_sha, ordinal, payload_bytes, tuple(batches))


def verify_projection(backup_path, inventory_dir, working_parent, *, source_sha256, owner_map, owner_map_sha256,
                      legacy_bot_id, inventory_manifest_sha256):
    """Return every admitted structural candidate, without performing Worker validation."""
    try:
        require(isinstance(inventory_manifest_sha256, str) and converter.HASH.fullmatch(inventory_manifest_sha256))
        original, parent = _directory(inventory_dir), _directory(working_parent)
        require(not parent.is_relative_to(original))
        _require_file_set(original)
        with TemporaryDirectory(prefix="legacy-temp-projection-", dir=parent) as temporary:
            rebuilt = Path(temporary) / "inventory"
            report = inventory.seal_inventory(backup_path, rebuilt, source_sha256=source_sha256, owner_map=owner_map,
                                              owner_map_sha256=owner_map_sha256, legacy_bot_id=legacy_bot_id)
            require(report["manifestSha256"] == inventory_manifest_sha256)
            _compare_files(original, rebuilt)
            return _project(rebuilt, report, source_sha256, inventory_manifest_sha256)
    except (ProjectionError, inventory.InventoryError, converter.ConversionError, OSError, ValueError, TypeError,
            KeyError, RecursionError, OverflowError):
        raise ProjectionError(ERROR) from None

"""Seal an offline ordinary-access reconciliation from a verified legacy backup.

CONFIG and TARGET are private canonical ASCII JSON lines with version 1.
CONFIG carries source botId, revision, deploymentSha256 and sqliteSha256,
plus numerically sorted allowedUserIds and adminUserIds lists of decimal IDs.
A null adminUserIds means the legacy setting was omitted. An empty list means
it was explicitly empty. TARGET carries botId, adminId and memberId only.
The independent pins identify reviewed inputs. The backup alone cannot prove
which Bot or effective startup configuration used it.
"""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from itertools import islice
import json
import os
from pathlib import Path
import re
import stat
import sys

import legacy_authorization_inventory as inventory


PRINCIPALS = "principals.ndjson"
MAX_CONFIG_IDS = 20_000
MAX_CONFIG_BYTES = 1024 * 1024
MAX_OVERRIDE_BYTES = inventory.MAX_ROWS * 128
MAX_TARGET_ID = 2**53 - 1
REVISION = re.compile(r"[0-9a-f]{40}", re.ASCII)
USER_ID = re.compile(r"[1-9][0-9]{0,18}", re.ASCII)
BLOCKERS = (
    "different-bot", "public-default", "outside-target", "reserved-identity",
    "id-out-of-range", "target-admin-mismatch", "target-member-admin", "member-denial-needs-baseline",
)
USAGE = ("Usage: legacy_authorization_reconcile.py BACKUP INVENTORY CONFIG TARGET OUTPUT "
         "SOURCE_SHA256 INVENTORY_SHA256 CONFIG_SHA256 TARGET_SHA256")
SUCCESS = "Legacy authorization reconciliation sealed."
FAILURE = "Legacy authorization reconciliation could not be confirmed safely."


def _require(condition: bool) -> None:
    if not condition:
        raise inventory.InventoryError(FAILURE)


def _file_state(info: os.stat_result, maximum: int) -> tuple:
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1
             and not info.st_mode & 0o077 and 0 <= info.st_size <= maximum)
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns, info.st_mode


def _private_bytes(path: Path, maximum: int) -> bytes:
    path, parents = inventory._private_parent(path)
    state = _file_state(path.lstat(), maximum)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    with os.fdopen(os.open(path, flags), "rb") as file:
        _require(_file_state(os.fstat(file.fileno()), maximum) == state)
        raw = file.read(maximum + 1)
        _require(len(raw) == state[2] and _file_state(os.fstat(file.fileno()), maximum) == state)
    _require(_file_state(path.lstat(), maximum) == state and inventory._private_parent(path)[1] == parents)
    return raw


def _pinned_document(path: Path, expected_sha256: str, maximum: int, fields: set[str]) -> dict:
    raw = _private_bytes(path, maximum)
    _require(sha256(raw).hexdigest() == expected_sha256)
    document = json.loads(raw)
    _require(type(document) is dict and set(document) == fields and inventory._canonical_line(document) == raw)
    return document


def _id(value: object, maximum: int = inventory.MAX_USER_ID) -> int:
    _require(type(value) is str and USER_ID.fullmatch(value) is not None)
    number = int(value)
    _require(number <= maximum)
    return number


def _ids(value: object) -> set[int]:
    _require(type(value) is list and len(value) <= MAX_CONFIG_IDS)
    found = [_id(item) for item in value]
    _require(all(previous < current for previous, current in zip(found, found[1:])))
    return set(found)


def _inventory_is_closed(path: Path) -> bool:
    expected = {inventory.MANIFEST, inventory.SEAL, inventory.SIDECAR}
    with os.scandir(path) as entries:
        return {entry.name for entry in islice(entries, len(expected) + 1)} == expected


def _verify_inventory(path: Path, expected_sha256: str, manifest: bytes, overrides: bytearray) -> None:
    path, parents = inventory._private_parent(path)
    state = inventory._directory_identity(path)
    _require(state[2] == os.geteuid() and not state[3] & 0o077 and _inventory_is_closed(path))
    _require(sha256(manifest).hexdigest() == expected_sha256
             and _private_bytes(path / inventory.MANIFEST, 4096) == manifest
             and _private_bytes(path / inventory.SEAL, 65) == (expected_sha256 + "\n").encode("ascii")
             and _private_bytes(path / inventory.SIDECAR, MAX_OVERRIDE_BYTES) == overrides)
    _require(inventory._private_parent(path)[1] == parents and inventory._directory_identity(path) == state
             and _inventory_is_closed(path))


def _principal_plan(
    source_bot: int, allowlist: set[int], administrators: set[int], overrides: bytearray, target: dict,
) -> tuple[bytearray, dict[str, int], int]:
    override_roles = {}
    for raw in overrides.splitlines():
        row = json.loads(raw)
        override_roles[int(row["userId"])] = row["allowed"] == 1
    target_bot, target_admin, target_member = (_id(target[field], MAX_TARGET_ID)
                                              for field in ("botId", "adminId", "memberId"))
    _require(len({target_bot, target_admin, target_member}) == 3)
    target_roles = {target_admin: "admin", target_member: "member"}
    reserved = {source_bot, target_bot}
    principals = sorted(allowlist.union(administrators, override_roles, target_roles))
    blockers = Counter(dict.fromkeys(BLOCKERS, 0))
    blockers["different-bot"] = int(source_bot != target_bot)
    blockers["public-default"] = int(not allowlist)
    output = bytearray()
    for user in principals:
        if user in administrators:
            role, basis = "admin", "administrator"
        elif user in override_roles:
            role, basis = ("member", "override-allow") if override_roles[user] else ("denied", "override-deny")
        elif user in allowlist:
            role, basis = "member", "allowlist"
        elif not allowlist:
            role, basis = "member", "public"
        else:
            role, basis = "denied", "default-deny"

        target_role = "reserved" if user in reserved else target_roles.get(user, "outside-target")
        reasons = []
        if target_role == "reserved":
            reasons.append("reserved-identity")
        elif target_role == "outside-target":
            reasons.append("outside-target")
        elif target_role == "admin" and role != "admin":
            reasons.append("target-admin-mismatch")
        elif target_role == "member" and role == "admin":
            reasons.append("target-member-admin")
        elif target_role == "member" and role == "denied":
            reasons.append("member-denial-needs-baseline")
        if user > MAX_TARGET_ID:
            reasons.append("id-out-of-range")
        blockers.update(reasons)
        output.extend(inventory._canonical_line({
            "userId": str(user), "legacyRole": role, "basis": basis, "allowlisted": user in allowlist,
            "targetRole": target_role, "blockers": reasons,
        }))
    return output, dict(blockers), len(principals)


def seal_reconciliation(
    backup: Path, inventory_dir: Path, config_path: Path, target_path: Path, output: Path,
    *, source_sha256: str, inventory_sha256: str, config_sha256: str, target_sha256: str,
) -> None:
    """Recompute the old inventory and classify principals without applying the result."""
    _require(all(inventory._SHA256.fullmatch(digest) is not None
                 for digest in (source_sha256, inventory_sha256, config_sha256, target_sha256)))
    destination, parents = inventory._private_parent(output)
    _require(not destination.is_relative_to(inventory_dir.absolute()))
    config = _pinned_document(config_path, config_sha256, MAX_CONFIG_BYTES,
                              {"version", "source", "allowedUserIds", "adminUserIds"})
    target = _pinned_document(target_path, target_sha256, 4096, {"version", "botId", "adminId", "memberId"})
    _require(type(config["version"]) is int and config["version"] == 1
             and type(target["version"]) is int and target["version"] == 1)
    source = config["source"]
    _require(type(source) is dict and set(source) == {"botId", "revision", "deploymentSha256", "sqliteSha256"}
             and type(source["revision"]) is str and REVISION.fullmatch(source["revision"]) is not None
             and type(source["deploymentSha256"]) is str and inventory._SHA256.fullmatch(source["deploymentSha256"]) is not None
             and source["sqliteSha256"] == source_sha256)
    source_bot = _id(source["botId"])
    allowlist = _ids(config["allowedUserIds"])
    inherits_administrators = config["adminUserIds"] is None
    administrators = allowlist if inherits_administrators else _ids(config["adminUserIds"])

    present, overrides, count, allowed = inventory._verified_source_rows(backup, source_sha256)
    manifest = inventory._inventory_manifest(source_sha256, present, overrides, count, allowed)
    _verify_inventory(inventory_dir, inventory_sha256, manifest, overrides)
    plan, blockers, principal_count = _principal_plan(source_bot, allowlist, administrators, overrides, target)
    sidecars = {inventory.SIDECAR: overrides, PRINCIPALS: plan}
    report = inventory._canonical_line({
        "version": 1, "kind": "legacy-authorization-reconciliation", "scope": "offline-dormant",
        "sourceSha256": source_sha256, "sourceRevision": source["revision"], "sourceDeploymentSha256": source["deploymentSha256"],
        "inventoryManifestSha256": inventory_sha256, "configSha256": config_sha256, "targetSha256": target_sha256,
        "adminMode": "inherited" if inherits_administrators else "explicit",
        "unlistedDefault": "public" if not allowlist else "denied",
        "overrideTablePresent": present, "overrideRows": count, "principalRows": principal_count,
        "blockers": blockers,
        "files": [{"file": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest()} for name, raw in sidecars.items()],
    })
    inventory._seal_package(destination, parents, report, sidecars)


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    if args in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if len(args) != 9:
        print(USAGE, file=sys.stderr)
        return 2
    backup, inventory_dir, config, target, output = map(Path, args[:5])
    source_sha256, inventory_sha256, config_sha256, target_sha256 = args[5:]
    try:
        seal_reconciliation(backup, inventory_dir, config, target, output, source_sha256=source_sha256,
                            inventory_sha256=inventory_sha256, config_sha256=config_sha256, target_sha256=target_sha256)
    except KeyboardInterrupt:
        print("Legacy authorization reconciliation was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

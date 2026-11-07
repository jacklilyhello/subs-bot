"""Seal unapplied private share evidence from a closed, pinned legacy backup."""

from __future__ import annotations

from contextlib import closing, suppress
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from typing import BinaryIO

from legacy_inventory import _file_state
from legacy_snapshot_convert import _file_hash, _new_file, _safe_path


MAX_SHARES = 20_000
MAX_CLAIMS = 20_000
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_TOTAL_PAYLOAD_BYTES = 64 * 1024 * 1024
MAX_SHARE_METADATA_BYTES = 32 * 1024 * 1024
MAX_SENDER_BYTES = 256
MAX_INLINE_ID_BYTES = 1024
MAX_ID = 2**63 - 1
MAX_TIMESTAMP = 2**53 - 1
SHARES = "shares.ndjson"
CLAIMS = "claims.ndjson"
PAYLOADS = "payloads.bin"
MANIFEST = "manifest.json"
SEAL = "manifest.sha256"
USAGE = "Usage: legacy_private_share_inventory.py BACKUP OUTPUT EXPECTED_SOURCE_SHA256 LEGACY_BOT_ID LEGACY_BOT_USERNAME"
SUCCESS = "Legacy private share inventory sealed."
FAILURE = "Legacy private share inventory could not be confirmed safely."
_SHA256 = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_ID = re.compile(r"[1-9][0-9]{0,18}\Z", re.ASCII)
_BOT_USERNAME = re.compile(r"[a-z][a-z0-9_]{1,28}bot\Z", re.ASCII)
_CODE = re.compile(rb"[A-Za-z0-9_-]{10}[AEIMQUYcgkosw048]\Z")
_SHARE_COLUMNS = {
    "code": ("TEXT", 0, None, 1, 0),
    "sender_id": ("INTEGER", 1, None, 0, 0),
    "sender_name": ("TEXT", 1, None, 0, 0),
    "content": ("TEXT", 1, None, 0, 0),
    "max_views": ("INTEGER", 1, "1", 0, 0),
    "claimed_count": ("INTEGER", 1, "0", 0, 0),
    "target_user_id": ("INTEGER", 0, None, 0, 0),
    "expire_at": ("INTEGER", 1, None, 0, 0),
    "created_at": ("INTEGER", 1, None, 0, 0),
}
_CLAIM_COLUMNS = {
    "id": ("INTEGER", 0, None, 1, 0),
    "share_code": ("TEXT", 1, None, 0, 0),
    "user_id": ("INTEGER", 1, None, 0, 0),
    "claimed_at": ("INTEGER", 1, None, 0, 0),
}


class InventoryError(RuntimeError):
    """The backup or inventory package could not be verified."""


@dataclass
class _Share:
    rowid: int
    code_sha256: str
    sender_id: int
    sender_name: str
    target_id: int | None
    inline_id: str | None
    max_views: int
    claimed_count: int
    created_at: int
    expire_at: int
    claims: int = 0


def _require(condition: bool) -> None:
    if not condition:
        raise InventoryError(FAILURE)


def _canonical_line(record: dict) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8") + b"\n"


def _private_parent(path: Path) -> None:
    info = path.parent.lstat()
    _require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077)


def _source_state(path: Path) -> tuple[int, ...]:
    _private_parent(path)
    info = path.lstat()
    _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077 and info.st_nlink == 1)
    state = _file_state(path)
    _require(state == (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
    return (*state, info.st_mode)


def _verify_source(path: Path, state: tuple[int, ...], expected_sha256: str) -> None:
    _require(_source_state(path) == state)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        _require((info.st_dev, info.st_ino) == state[:2])
        header = source.read(20)
        _require(header.startswith(b"SQLite format 3\0") and header[18:20] == b"\x01\x01")
    _require(_file_hash(path) == (state[2], expected_sha256) and _source_state(path) == state)


def _schema(db: sqlite3.Connection) -> tuple[bool, bool]:
    definitions = db.execute("""
        SELECT name, type, wr, strict FROM pragma_table_list
        WHERE schema = 'main' AND lower(name) IN ('shares', 'share_claims')
    """)
    tables = {name: (kind, without_rowid, strict) for name, kind, without_rowid, strict in definitions}
    if not tables:
        return False, False
    _require(tables == {"shares": ("table", 0, 0), "share_claims": ("table", 0, 0)})
    shares = {row[1]: row[2:] for row in db.execute("PRAGMA main.table_xinfo(shares)")}
    claims = {row[1]: row[2:] for row in db.execute("PRAGMA main.table_xinfo(share_claims)")}
    inline = "inline_message_id" in shares
    expected = {**_SHARE_COLUMNS, "inline_message_id": ("TEXT", 0, None, 0, 0)} if inline else _SHARE_COLUMNS
    _require(shares == expected and claims == _CLAIM_COLUMNS)
    # The claim ID is also the rowid used to read claim-code bytes. An actual
    # INTEGER PRIMARY KEY alias has no separate primary-key index.
    _require(all(index[3] != "pk" for index in db.execute("PRAGMA main.index_list(share_claims)")))
    return True, inline


def _integer_columns(names: tuple[str, ...]) -> str:
    # Every caller passes fixed schema column names.
    return ", ".join(f"CASE WHEN typeof({name}) = 'integer' THEN {name} END" for name in names)


def _text_bytes(db: sqlite3.Connection, table: str, column: str, rowid: int, storage_type: str, limit: int) -> bytes:
    _require(storage_type == "text")
    with db.blobopen(table, column, rowid, readonly=True) as blob:
        _require(1 <= len(blob) <= limit)
        return blob.read()


def _id(value: object) -> bool:
    return type(value) is int and 1 <= value <= MAX_ID


def _read_shares(db: sqlite3.Connection, inline: bool) -> dict[bytes, _Share]:
    inline_type_sql = "typeof(inline_message_id)" if inline else "'null'"
    numbers = _integer_columns(("sender_id", "max_views", "claimed_count", "created_at", "expire_at"))
    rows = db.execute(f"""
        SELECT rowid, typeof(code), typeof(sender_name), {inline_type_sql}, {numbers},
            CASE WHEN target_user_id IS NULL OR typeof(target_user_id) = 'integer' THEN target_user_id ELSE 0 END
        FROM main.shares ORDER BY rowid LIMIT ?
    """, (MAX_SHARES + 1,))
    shares = {}
    hashes = set()
    for rowid, code_type, name_type, inline_type, sender, maximum, claimed, created, expiry, target in rows:
        _require(len(shares) < MAX_SHARES and _id(sender) and (target is None or _id(target))
                 and type(maximum) is int and 1 <= maximum <= 100
                 and type(claimed) is int and 0 <= claimed <= maximum
                 and type(created) is int and type(expiry) is int and 1 <= created < expiry <= MAX_TIMESTAMP)
        code = _text_bytes(db, "shares", "code", rowid, code_type, 11)
        _require(_CODE.fullmatch(code) is not None and code not in shares)
        code_sha256 = sha256(code).hexdigest()
        _require(code_sha256 not in hashes)
        hashes.add(code_sha256)
        sender_name = _text_bytes(db, "shares", "sender_name", rowid, name_type, MAX_SENDER_BYTES).decode("utf-8")
        inline_id = None if inline_type == "null" else _text_bytes(
            db, "shares", "inline_message_id", rowid, inline_type, MAX_INLINE_ID_BYTES,
        ).decode("utf-8")
        shares[code] = _Share(rowid, code_sha256, sender, sender_name, target, inline_id, maximum, claimed, created, expiry)
    return shares


def _write_claims(db: sqlite3.Connection, shares: dict[bytes, _Share], file: BinaryIO) -> int:
    numbers = _integer_columns(("user_id", "claimed_at"))
    rows = db.execute(f"""
        SELECT id, typeof(share_code), {numbers} FROM main.share_claims ORDER BY id LIMIT ?
    """, (MAX_CLAIMS + 1,))
    previous_id = 0
    seen = set()
    for claim_id, code_type, user, claimed_at in rows:
        _require(len(seen) < MAX_CLAIMS and _id(claim_id) and claim_id > previous_id and _id(user) and type(claimed_at) is int)
        code = _text_bytes(db, "share_claims", "share_code", claim_id, code_type, 11)
        share = shares.get(code)
        _require(share is not None and (share.target_id is None or share.target_id == user)
                 and share.created_at <= claimed_at <= share.expire_at and share.claims < share.claimed_count
                 and (code, user) not in seen)
        seen.add((code, user))
        previous_id = claim_id
        share.claims += 1
        file.write(_canonical_line({
            "legacyClaimId": str(claim_id), "codeSha256": share.code_sha256, "userId": str(user), "claimedAt": claimed_at,
        }))
    _require(all(share.claims == share.claimed_count for share in shares.values()))
    return len(seen)


def _write_shares(db: sqlite3.Connection, shares: dict[bytes, _Share], file: BinaryIO, payloads: BinaryIO) -> None:
    offset = 0
    for share in sorted(shares.values(), key=lambda item: item.code_sha256):
        storage_type = db.execute("SELECT typeof(content) FROM main.shares WHERE rowid=?", (share.rowid,)).fetchone()[0]
        available = min(MAX_PAYLOAD_BYTES, MAX_TOTAL_PAYLOAD_BYTES - offset)
        payload = _text_bytes(db, "shares", "content", share.rowid, storage_type, available)
        payload.decode("utf-8")  # Validate text while retaining the original bytes.
        record = _canonical_line({
            "codeSha256": share.code_sha256, "senderId": str(share.sender_id), "senderName": share.sender_name,
            "targetUserId": str(share.target_id) if share.target_id is not None else None, "inlineMessageId": share.inline_id,
            "maxViews": share.max_views, "claimedCount": share.claimed_count, "createdAt": share.created_at, "expireAt": share.expire_at,
            "payload": {"offset": offset, "bytes": len(payload), "sha256": sha256(payload).hexdigest()},
        })
        _require(file.tell() + len(record) <= MAX_SHARE_METADATA_BYTES)
        payloads.write(payload)
        file.write(record)
        offset += len(payload)


def _sync(file: BinaryIO) -> None:
    file.flush()
    os.fsync(file.fileno())


def _capture(source: Path, output: Path) -> dict:
    # immutable is valid only for a completed backup with no concurrent writer.
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True, isolation_level=None)) as db:
        db.execute("PRAGMA trusted_schema = OFF")
        db.execute("PRAGMA query_only = ON")
        db.execute("PRAGMA temp_store = MEMORY")
        db.execute("PRAGMA cache_size = -2048")
        _require(db.execute("PRAGMA trusted_schema").fetchone() == (0,) and db.execute("PRAGMA query_only").fetchone() == (1,))
        db.execute("BEGIN")
        _require(db.execute("PRAGMA encoding").fetchone() == ("UTF-8",))
        present, inline = _schema(db)
        shares = _read_shares(db, inline) if present else {}
        with _new_file(output / SHARES) as share_file, _new_file(output / CLAIMS) as claim_file, _new_file(output / PAYLOADS) as payloads:
            claim_count = _write_claims(db, shares, claim_file) if present else 0
            _write_shares(db, shares, share_file, payloads)
            for file in (share_file, claim_file, payloads):
                _sync(file)
        db.execute("ROLLBACK")
    return {"present": present, "inlineMessageIdColumn": inline, "shares": len(shares), "claims": claim_count}


def seal_inventory(backup: Path, output: Path, expected_sha256: str, bot_id: str, bot_username: str) -> None:
    """Write private sidecars bound to a separately approved source and old Bot."""
    _require(_SHA256.fullmatch(expected_sha256) is not None and _ID.fullmatch(bot_id) is not None and int(bot_id) <= MAX_ID
             and _BOT_USERNAME.fullmatch(bot_username) is not None)
    source = _safe_path(backup, existing=True)
    destination = _safe_path(output, existing=False)
    _private_parent(destination)
    state = _source_state(source)
    _verify_source(source, state, expected_sha256)

    destination.mkdir(mode=0o700)
    try:
        counts = _capture(source, destination)
        _verify_source(source, state, expected_sha256)
        files = []
        for name in (SHARES, CLAIMS, PAYLOADS):
            size, digest = _file_hash(destination / name)
            files.append({"file": name, "bytes": size, "sha256": digest})
        manifest = _canonical_line({
            "version": 1, "kind": "legacy-private-share-inventory", "sourceSha256": expected_sha256,
            "legacyBot": {"id": bot_id, "username": bot_username}, "inventory": counts, "files": files,
        })
        with _new_file(destination / MANIFEST) as file:
            file.write(manifest)
            _sync(file)
        with _new_file(destination / SEAL) as file:
            file.write(sha256(manifest).hexdigest().encode("ascii") + b"\n")
            _sync(file)
    except BaseException:
        # Only fixed filenames in the newly created private directory are ours.
        for name in (SEAL, MANIFEST, PAYLOADS, CLAIMS, SHARES):
            with suppress(OSError):
                (destination / name).unlink()
        with suppress(OSError):
            destination.rmdir()
        raise


def main(args: list[str] | None = None) -> int:
    args = sys.argv[1:] if args is None else args
    if args in (["-h"], ["--help"]):
        print(USAGE)
        return 0
    if len(args) != 5:
        print(USAGE, file=sys.stderr)
        return 2
    try:
        seal_inventory(Path(args[0]), Path(args[1]), args[2], args[3], args[4])
    except KeyboardInterrupt:
        print("Legacy private share inventory was interrupted.", file=sys.stderr)
        return 130
    except Exception:
        print(FAILURE, file=sys.stderr)
        return 2
    print(SUCCESS)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Build a private, unapplied candidate for the legacy share domain only."""

from collections import Counter
from contextlib import closing, contextmanager, suppress
from hashlib import sha256
import os
from pathlib import Path
import re
import sqlite3
import stat
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from uuid import NAMESPACE_URL, uuid5

import d1_migrations as migrations
import legacy_private_share_inventory as inventory
import legacy_restore_package as package
import legacy_snapshot_convert as converter
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact


PROFILE = "legacy-private-shares-v1"
MIGRATION = "0005_private_shares.sql"
MIGRATION_SHA256 = "d7edd0fcd6d2e5223c95940c965ef1eb37d07c8399df111e7f48a719addcfc7f"
SHARES = "private_shares"
CLAIMS = "private_share_claims"
COLUMNS = {SHARES: ("id", "bot_id", "code_sha256", "sender_id", "sender_name", "payload_id", "payload_sha256",
                   "payload_bytes", "max_claims", "target_user_id", "expire_at", "created_at"),
           CLAIMS: ("share_id", "actor_id", "claimed_at")}
MAX_SHARE_LINE = 16 * 1024
MAX_CLAIM_LINE = 512
MANIFEST_LIMIT = 4096
SQL_REPLAY_LIMIT = 4 * 1024 * 1024
ERROR = "Private legacy share candidate could not be built safely."
USAGE = ("Usage: legacy_private_share_candidate.py INVENTORY_DIR WORKER_ARTIFACT_DIR OUTPUT_DIR "
         "INVENTORY_MANIFEST_SHA WORKER_MANIFEST_SHA REVISION APPLIED_AT SOURCE_SQLITE_SHA LEGACY_BOT_ID LEGACY_BOT_USERNAME")


class CandidateError(RuntimeError):
    """Only fixed errors may leave the candidate builder."""


def require(condition):
    if not condition:
        raise CandidateError(ERROR)


def valid_id(value):
    return native.matches(inventory._ID, value) and int(value) <= inventory.MAX_ID


def valid_text(value, maximum):
    return isinstance(value, str) and 0 < len(value.encode("utf-8")) <= maximum


def read_inventory(root, manifest_sha, source_sha, bot):
    require(native.matches(native.DIGEST, source_sha) and valid_id(bot["id"])
            and native.matches(inventory._BOT_USERNAME, bot["username"]))
    names = (inventory.SHARES, inventory.CLAIMS, inventory.PAYLOADS)
    expected = {*names, inventory.MANIFEST, inventory.SEAL}
    with os.scandir(root) as members:
        for member in members:
            require(member.name in expected)
            expected.remove(member.name)
            path = package.private_path(root / member.name)
            require(path.lstat().st_nlink == 1)
    require(not expected)
    raw = package.read_pinned(root / inventory.MANIFEST, MANIFEST_LIMIT, manifest_sha)
    require(package.read_private(root / inventory.SEAL, 65) == manifest_sha.encode("ascii") + b"\n")
    document = native.parsed(raw, MANIFEST_LIMIT)
    require(inventory._canonical_line(document) == raw and set(document) == {"version", "kind", "sourceSha256",
            "legacyBot", "inventory", "files"} and native.integer(document["version"], 1, 1)
            and document["kind"] == "legacy-private-share-inventory" and document["sourceSha256"] == source_sha
            and document["legacyBot"] == bot)
    counts, entries = document["inventory"], document["files"]
    require(isinstance(counts, dict) and set(counts) == {"present", "inlineMessageIdColumn", "shares", "claims"}
            and type(counts["present"]) is bool and type(counts["inlineMessageIdColumn"]) is bool
            and native.integer(counts["shares"], 0, native.MAX_OBJECTS)
            and native.integer(counts["claims"], 0, min(inventory.MAX_CLAIMS, counts["shares"] * 100))
            and (counts["present"] or (not counts["shares"] and not counts["inlineMessageIdColumn"])))
    maximums = (counts["shares"] * MAX_SHARE_LINE, counts["claims"] * MAX_CLAIM_LINE,
                counts["shares"] * inventory.MAX_PAYLOAD_BYTES)
    require(isinstance(entries, list) and len(entries) == len(names))
    for entry, name, maximum in zip(entries, names, maximums):
        require(isinstance(entry, dict) and set(entry) == {"file", "bytes", "sha256"} and entry["file"] == name
                and native.integer(entry["bytes"], 0, maximum) and native.matches(native.DIGEST, entry["sha256"]))
    return counts, {entry["file"]: entry for entry in entries}


@contextmanager
def open_inventory_file(root, entry):
    path = root / entry["file"]
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        before = os.fstat(file.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_uid == os.getuid() and not before.st_mode & 0o077
                and before.st_nlink == 1 and before.st_size == entry["bytes"])
        yield file
        after = os.fstat(file.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) == (after.st_size, after.st_mtime_ns, after.st_ctime_ns))


def read_rows(root, entry, max_line):
    size, digest = 0, sha256()
    with open_inventory_file(root, entry) as file:
        while line := file.readline(max_line + 1):
            size += len(line)
            require(size <= entry["bytes"])
            digest.update(line)
            row = native.parsed(line, max_line)
            require(inventory._canonical_line(row) == line)
            yield row
    require(size == entry["bytes"] and digest.hexdigest() == entry["sha256"])


def validate_share(row, prior, offset, allow_inline):
    require(set(row) == {"codeSha256", "senderId", "senderName", "targetUserId", "inlineMessageId", "maxViews",
            "claimedCount", "createdAt", "expireAt", "payload"})
    digest, name, target, inline = (row[key] for key in ("codeSha256", "senderName", "targetUserId", "inlineMessageId"))
    require(native.matches(native.DIGEST, digest) and digest > prior and valid_id(row["senderId"])
            and valid_text(name, inventory.MAX_SENDER_BYTES) and "\0" not in name
            and (target is None or valid_id(target))
            and (inline is None or allow_inline and valid_text(inline, inventory.MAX_INLINE_ID_BYTES))
            and native.integer(row["maxViews"], 1, 100) and native.integer(row["claimedCount"], 0, row["maxViews"])
            and native.integer(row["createdAt"], 1) and native.integer(row["expireAt"], row["createdAt"] + 1))
    pointer = row["payload"]
    require(isinstance(pointer, dict) and set(pointer) == {"offset", "bytes", "sha256"}
            and native.integer(pointer["offset"], offset, offset)
            and native.integer(pointer["bytes"], 1, inventory.MAX_PAYLOAD_BYTES)
            and native.matches(native.DIGEST, pointer["sha256"]))


def load_shares(db, root, counts, files, staged, source_sha, bot_id):
    shares, keys = {}, set()
    objects = staged / "objects" / "private-shares"
    if counts["shares"]:
        objects.parent.mkdir(mode=0o700)
        objects.mkdir(mode=0o700)
    packed = files[inventory.PAYLOADS]
    offset, prior, inline_count = 0, "", 0
    full_digest = sha256()
    with open_inventory_file(root, packed) as payloads:
        for share_id, row in enumerate(read_rows(root, files[inventory.SHARES], MAX_SHARE_LINE), 1):
            require(share_id <= counts["shares"])
            validate_share(row, prior, offset, counts["inlineMessageIdColumn"])
            code, pointer = row["codeSha256"], row["payload"]
            require(offset + pointer["bytes"] <= packed["bytes"])
            body = payloads.read(pointer["bytes"])
            require(len(body) == pointer["bytes"] and native.digest(body) == pointer["sha256"])
            body.decode("utf-8")
            full_digest.update(body)
            offset += len(body)
            prior = code
            inline_count += row["inlineMessageId"] is not None
            payload_id = str(uuid5(NAMESPACE_URL, f"subs-bot-legacy-private-share-v1:{source_sha}:{bot_id}:{code}"))
            key = f"private-shares/{payload_id}.txt"
            require(key not in keys)
            keys.add(key)
            with native.private_file(staged / "objects" / key) as target:
                target.write(body)
            db.execute(f"INSERT INTO {SHARES} VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", (
                share_id, bot_id, code, row["senderId"], row["senderName"], payload_id, pointer["sha256"], len(body),
                row["maxViews"], row["targetUserId"], row["expireAt"], row["createdAt"],
            ))
            shares[code] = (share_id, row["targetUserId"], row["createdAt"], row["expireAt"], row["claimedCount"])
        require(not payloads.read(1) and offset == packed["bytes"] and full_digest.hexdigest() == packed["sha256"])
    require(len(shares) == counts["shares"])
    return shares, keys, inline_count


def load_claims(db, root, counts, files, shares):
    claims = Counter()
    prior = count = 0
    for count, row in enumerate(read_rows(root, files[inventory.CLAIMS], MAX_CLAIM_LINE), 1):
        require(count <= counts["claims"] and set(row) == {"legacyClaimId", "codeSha256", "userId", "claimedAt"}
                and valid_id(row["legacyClaimId"]) and int(row["legacyClaimId"]) > prior and valid_id(row["userId"])
                and native.matches(native.DIGEST, row["codeSha256"]) and row["codeSha256"] in shares)
        code = row["codeSha256"]
        share_id, target, created, expiry, claimed_count = shares[code]
        require((target is None or row["userId"] == target) and native.integer(row["claimedAt"], created, expiry)
                and claims[code] < claimed_count)
        db.execute(f"INSERT INTO {CLAIMS} VALUES (?,?,?)", (share_id, row["userId"], row["claimedAt"]))
        claims[code] += 1
        prior = int(row["legacyClaimId"])
    require(count == counts["claims"] and all(claims[code] == share[4] for code, share in shares.items()))


def build_candidate(inventory_dir, worker, output, *, inventory_manifest_sha, worker_manifest_sha, revision, applied_at,
                    source_sqlite_sha, legacy_bot_id, legacy_bot_username):
    try:
        root = package.private_path(inventory_dir, directory=True)
        worker = package.private_path(worker, directory=True)
        output = converter._safe_path(Path(output), existing=False)
        package.private_path(output.parent, directory=True)
        require(not output.is_relative_to(root) and not output.is_relative_to(worker) and native.integer(applied_at, 1))
        bot = {"id": legacy_bot_id, "username": legacy_bot_username}
        counts, files = read_inventory(root, inventory_manifest_sha, source_sqlite_sha, bot)
        chain, worker_pin = package.worker_artifact(worker, revision, worker_manifest_sha)
        require(chain[4].name == MIGRATION and chain[4].sha256 == MIGRATION_SHA256
                and counts["shares"] + counts["claims"] + len(chain) + bool(counts["shares"]) <= native.MAX_ROWS)
        # The share-only profile is scoped to the exact two populated 0005 tables.
        require(all(obj.table not in COLUMNS for item in chain[5:] for obj in item.objects))
        schema = migrations._objects(chain, len(chain), managed=True)
        source = SimpleNamespace(objects=schema, tables=sorted(obj.name for obj in schema if obj.type == "table"))
        ledger = [(position, item.name, item.sha256, "applied", applied_at) for position, item in enumerate(chain, 1)]

        with TemporaryDirectory(prefix=".share-candidate-", dir=output.parent) as temporary:
            scratch = Path(temporary)
            staged = scratch / "sealed"
            staged.mkdir(mode=0o700)
            database, sql = scratch / "candidate.sqlite", scratch / package.SQL
            with native.private_file(database):
                pass
            with closing(sqlite3.connect(database)) as db, db:
                db.execute("PRAGMA foreign_keys=ON")
                db.execute("PRAGMA trusted_schema=OFF")
                db.execute("PRAGMA cache_size=-2048")
                db.execute("PRAGMA temp_store=FILE")
                page_size = db.execute("PRAGMA page_size").fetchone()[0]
                db.execute(f"PRAGMA max_page_count={128 * 1024 * 1024 // page_size}")
                for obj in schema:
                    if obj.name != "sqlite_sequence":
                        db.execute(obj.sql)
                db.executemany(f"INSERT INTO {migrations.LEDGER} VALUES (?,?,?,?,?)", ledger)
                shares, keys, inline_count = load_shares(db, root, counts, files, staged, source_sqlite_sha, legacy_bot_id)
                load_claims(db, root, counts, files, shares)
                layout = native.table_layout(db, source.tables)
                summary = package.db_summary(db, layout)
                package.write_sql(db, schema, 0, sql, extra_tables=COLUMNS)
            require(sql.stat().st_size <= SQL_REPLAY_LIMIT)

            def read_object(key):
                require(key in keys)
                return package.read_private(staged / "objects" / key, inventory.MAX_PAYLOAD_BYTES), {"custom": {}, "http": {}}

            replayed, replay_layout, replay_summary = native.open_export(sql, source)
            with closing(replayed):
                require(replay_layout == layout and replay_summary == summary)
                expected = {table: 0 for table in layout}
                expected.update({SHARES: counts["shares"], CLAIMS: counts["claims"], migrations.LEDGER: len(ledger),
                                 "sqlite_sequence": int(bool(counts["shares"]))})
                require(summary["tableCounts"] == expected)
                sequence = [(SHARES, counts["shares"])] if counts["shares"] else []
                require(replayed.execute("SELECT name,seq FROM sqlite_sequence").fetchall() == sequence)
                objects = native.object_references(replayed, read_object)
                require({entry["key"] for entry in objects} == keys)
            sql = sql.rename(staged / package.SQL)

            report = {"version": 1, "profile": PROFILE, "scope": "fresh-unbound-d1-r2", "shareCompatibility": "not-validated",
                      "legacyDomains": "private-shares-and-claims-only",
                      "counts": {"shares": counts["shares"], "claims": counts["claims"], "sourceInlineIdRows": inline_count},
                      "schemaSha256": native._schema_digest(schema), "dataSha256": summary["dataSha256"],
                      "objectCount": len(objects), "objectBytes": sum(item["bytes"] for item in objects),
                      "shareSequenceHighWater": counts["shares"]}
            manifest = {**report, "source": {"sqliteSha256": source_sqlite_sha, "inventoryManifestSha256": inventory_manifest_sha,
                        "legacyBot": bot}, "workerArtifact": worker_pin, "layout": layout, "summary": summary, "objects": objects,
                        "sql": {**package.describe(sql), "md5": native.file_hash(sql, "md5")[1]}}
            body = native.canonical(manifest)
            require(len(body) <= native.MANIFEST_BYTES)
            manifest_sha = native.digest(body)
            with native.private_file(staged / package.MANIFEST) as file:
                file.write(body)
            with native.private_file(staged / package.MARKER) as file:
                file.write(manifest_sha.encode("ascii") + b"\n")
            output.mkdir(mode=0o700)  # Reserve an absent path before moving the sealed directory.
            try:
                staged.rename(output)
            except BaseException:
                with suppress(OSError):
                    output.rmdir()
                raise
        return {**report, "manifestSha256": manifest_sha}
    except (CandidateError, package.PackageError, converter.ConversionError, native.RehearsalError, migrations.MigrationError,
            artifact.ArtifactError, OSError, sqlite3.Error, ValueError, TypeError, KeyError, RecursionError, OverflowError):
        raise CandidateError(ERROR) from None


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if len(args) != 10 or not re.fullmatch(r"[1-9][0-9]{0,15}", args[6]):
        print(USAGE, file=sys.stderr)
        return 2
    try:
        result = build_candidate(*map(Path, args[:3]), inventory_manifest_sha=args[3], worker_manifest_sha=args[4],
                                 revision=args[5], applied_at=int(args[6]), source_sqlite_sha=args[7],
                                 legacy_bot_id=args[8], legacy_bot_username=args[9])
        print(native.canonical(result).decode("utf-8"))
        return 0
    except CandidateError:
        print(ERROR, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

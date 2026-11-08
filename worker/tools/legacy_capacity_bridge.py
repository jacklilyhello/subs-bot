"""Build a synthetic legacy-to-live fixture using the existing capacity contract."""

import argparse
from contextlib import closing
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory

from capacity_fixtures import CAPACITY_STATUS, _write_private, generate_capacity_fixtures
from capacity_resources import OWNER, read_private
import legacy_snapshot_convert as converter


LEGACY_BYTES = 83_600_000
ERROR = "The synthetic legacy capacity conversion could not be verified."


def require(value):
    if not value:
        raise ValueError(ERROR)


def write_legacy_fixture(path, directory, fixture):
    """Write one SQLite TEXT cell without assembling the full JSON in memory."""
    padding = LEGACY_BYTES - fixture["nodeBytes"] - 1
    count = fixture["nodeCount"]
    require(padding >= 0 and count > 0)
    spaces, extra = divmod(padding, count)
    _write_private(path, b"")
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("PRAGMA cache_size=-2048")
        db.execute("""CREATE TABLE subscriptions (
          id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,name TEXT NOT NULL,url TEXT NOT NULL,
          token TEXT NOT NULL,expire_at INTEGER,traffic_used REAL,traffic_total REAL,nodes_json TEXT NOT NULL,
          node_count INTEGER NOT NULL,last_error TEXT,created_at INTEGER NOT NULL,updated_at INTEGER NOT NULL)""")
        row_id = db.execute("""INSERT INTO subscriptions(user_id,name,url,token,nodes_json,node_count,created_at,updated_at)
          VALUES(?,'synthetic legacy capacity','https://capacity.example.invalid/',?,CAST(zeroblob(?) AS TEXT),?,1700000000,1700000001)""",
                            (int(OWNER), fixture["token"], LEGACY_BYTES, count)).lastrowid
        index = 0
        with db.blobopen("subscriptions", "nodes_json", row_id) as blob:
            blob.write(b"[")
            for chunk in fixture["chunks"]:
                body = read_private(directory / chunk["file"], converter.CHUNK_BYTES)
                require(len(body) == chunk["bytes"] and sha256(body).hexdigest() == chunk["sha256"])
                for line in BytesIO(body):
                    require(index < count and line.endswith(b"\n") and line.startswith(b"{"))
                    if index:
                        blob.write(b",")
                    blob.write(b" " * (spaces + (index < extra)) + line[:-1])
                    index += 1
            blob.write(b"]")
            require(index == count and blob.tell() == LEGACY_BYTES)


def adopt_converted_fixture(directory, fixture, package):
    report = converter.verify_bundle(package)
    counts = report["counts"]
    require(report["completeImportable"] and not report["blockers"]
            and (counts["activeRows"], counts["trashRows"], counts["convertedRows"], counts["rawNodeBytes"],
                 counts["nodeCount"], counts["nodeBytes"]) == (1, 0, 1, LEGACY_BYTES, fixture["nodeCount"], fixture["nodeBytes"]))
    require(report["files"]["count"] == len(fixture["chunks"]) + 3)
    metadata = json.loads(read_private(package / "active.ndjson", converter.MAX_METADATA_BYTES))
    record = metadata["record"]
    require((record["id"], record["owner_id"], record["token"], record["generation"], record["node_count"], record["manifest_sha256"])
            == (1, OWNER, fixture["token"], 1, fixture["nodeCount"], fixture["manifestSha256"]))
    converted = package / "objects" / "subscriptions" / "1" / record["snapshot_id"]
    files = [(entry["file"], converter.CHUNK_BYTES) for entry in fixture["chunks"]]
    files.append((fixture["manifestFile"], 64 * 1024))
    for relative, maximum in files:
        expected = directory / relative
        actual = converted / expected.name
        require(read_private(expected, maximum) == read_private(actual, maximum))
        # Stage the converter's files themselves through the existing scoped fixture publisher.
        os.replace(actual, expected)
    return {"syntheticLegacyCellBytes": LEGACY_BYTES, "convertedNdjsonBytes": counts["nodeBytes"],
            "nodes": counts["nodeCount"], "chunks": len(fixture["chunks"]),
            "sourceSqliteSha256": report["sourceSha256"], "snapshotManifestSha256": fixture["manifestSha256"],
            "expectedBase64Sha256": fixture["exportSha256"]}


def generate_legacy_capacity(directory, revision):
    # All source and intermediate data remain in runner-private temporary storage.
    with TemporaryDirectory(prefix=".subs-bot-legacy-capacity-", dir=directory.parent) as temporary:
        root = Path(temporary)
        staging, source, package = root / "fixtures", root / "synthetic.sqlite", root / "converted"
        metadata = generate_capacity_fixtures(staging, revision)
        positive = metadata["fixtures"][0]
        require(positive["label"] == "at-limits")
        write_legacy_fixture(source, staging, positive)
        converter.convert_backup(source, package)
        proof = adopt_converted_fixture(staging, positive, package)
        directory.mkdir(mode=0o700)
        for label in CAPACITY_STATUS:
            (staging / label).rename(directory / label)
        (staging / "capacity.json").rename(directory / "capacity.json")
    return {"revision": revision, **proof}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("revision")
    args = parser.parse_args()
    try:
        print(json.dumps(generate_legacy_capacity(args.directory, args.revision), sort_keys=True))
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, sqlite3.Error):
        parser.exit(1, ERROR + "\n")


if __name__ == "__main__":
    main()

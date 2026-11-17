"""Read-only capacity observations for a pinned production recovery source.

This is deliberately not a backup or an authorization to pause. The active
database can change between queries; capture repeats all checks when frozen.
"""

from contextlib import closing
import re
import sqlite3

import native_restore_rehearsal as native


PROJECTIONS = {
    "subscriptions": ("id", "generation", "snapshot_id", "manifest_sha256", "node_count"),
    "subscription_trash": ("id", "generation", "snapshot_id", "manifest_sha256", "node_count"),
    "private_shares": ("id", "payload_id", "payload_sha256", "payload_bytes", "bot_id", "sender_id"),
    "telegram_private_share_creations": ("receipt_id", "state", "share_id", "payload_id", "payload_sha256", "payload_bytes", "bot_id", "actor_id"),
}


class ObjectLimitExceeded(Exception):
    pass


class ObservationError(Exception):
    def __init__(self, reason):
        self.reason = reason


def level(value, maximum, warning_percent):
    native.require(type(value) is int and value >= 0 and type(maximum) is int and maximum > 0)
    native.require(type(warning_percent) is int and 1 <= warning_percent <= 99)
    return "over-limit" if value > maximum else "warning" if value * 100 >= maximum * warning_percent else "normal"


def observe(api, source, *, warning_percent=80):
    try:
        return _observe(api, source, warning_percent=warning_percent)
    except ObservationError as error:
        return {"version": 1, "consistency": "unfrozen-observation", "snapshot": False,
                "rowStatus": "unknown", "objectStatus": "unverified", "objectBytesStatus": "unknown",
                "sqlBytesStatus": "unknown-until-native-export", "failureReason": error.reason,
                "warningPercent": warning_percent, "backupVerified": False}
    except (native.RehearsalError, UnicodeError, sqlite3.Error):
        return {"version": 1, "consistency": "unfrozen-observation", "snapshot": False,
                "rowStatus": "unknown", "objectStatus": "unverified", "objectBytesStatus": "unknown",
                "sqlBytesStatus": "unknown-until-native-export", "failureReason": "read-or-validation-failed",
                "warningPercent": warning_percent, "backupVerified": False}


def _observe(api, source, *, warning_percent=80):
    """Check all schema tables and the same object closure as recovery capture.

    Results are not a consistent snapshot and never replace capture validation.
    Large/invalid sources stop rather than truncate and report a false pass.
    """
    native.require(type(warning_percent) is int and 1 <= warning_percent <= 99)
    source.schema()
    database = api.target["d1Id"]
    tables = source.tables
    native.require(len(tables) == len(set(tables)) and all(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]*", name) for name in tables))
    counts = {}
    for table in tables:
        rows = api.rows(database, 'SELECT count(*) AS n FROM "' + table + '"')
        native.require(len(rows) == 1 and set(rows[0]) == {"n"} and type(rows[0]["n"]) is int and rows[0]["n"] >= 0)
        counts[table] = rows[0]["n"]
    total_rows = sum(counts.values())
    report = {"version": 1, "consistency": "unfrozen-observation", "snapshot": False,
              "rows": total_rows, "rowLimit": native.MAX_ROWS, "rowStatus": level(total_rows, native.MAX_ROWS, warning_percent),
              "tableCounts": counts, "warningPercent": warning_percent,
              "objectStatus": "not-checked", "sqlBytes": None,
              "sqlBytesStatus": "unknown-until-native-export", "backupVerified": False}
    # The same upper bound controls the materialized reference input. Do not
    # claim that R2 was checked if the source has already exceeded it.
    if total_rows > native.MAX_ROWS:
        return report
    native.require(set(PROJECTIONS) <= set(tables), "The reference schema is incomplete.")
    with closing(sqlite3.connect(":memory:")) as db:
        for table, columns in PROJECTIONS.items():
            definitions = ",".join('"' + name + '"' for name in columns)
            db.execute('CREATE TABLE "' + table + '" (' + definitions + ')')
            last = None
            observed = 0
            while True:
                key = columns[0]
                query = 'SELECT ' + definitions + ' FROM "' + table + '"'
                params = ()
                if last is not None:
                    query += ' WHERE "' + key + '" > CAST(? AS INTEGER)'
                    params = (str(last),)
                query += ' ORDER BY "' + key + '" LIMIT 32'
                page = api.rows(database, query, params)
                native.require(len(page) <= 32)
                for row in page:
                    native.require(set(row) == set(columns) and type(row[key]) is int
                                   and row[key] > (last if last is not None else 0))
                    last = row[key]
                    db.execute('INSERT INTO "' + table + '" VALUES (' + ','.join('?' for _ in columns) + ')',
                               tuple(row[column] for column in columns))
                    observed += 1
                    native.require(observed <= native.MAX_ROWS)
                if len(page) < 32:
                    break
            if observed != counts[table]:
                raise ObservationError("source-changed-during-scan")

        def read_object(key):
            try:
                exact = [row for row in api.list_objects(api.target["bucketName"], prefix=key, maximum=2) if row["key"] == key]
            except native.RehearsalError:
                raise ObservationError("object-inventory-failed") from None
            if not exact:
                raise ObservationError("object-missing")
            if len(exact) != 1 or type(exact[0].get("size")) is not int or exact[0]["size"] < 1:
                raise ObservationError("object-inventory-invalid")
            if exact[0]["size"] > native.OBJECT_BYTES:
                raise ObservationError("object-too-large")
            try:
                metadata = native.listed_metadata(exact[0])
            except native.RehearsalError:
                raise ObservationError("object-metadata-invalid") from None
            try:
                body, _ = api.object_or_none(api.target["bucketName"], key)
            except native.RehearsalError:
                raise ObservationError("object-read-failed") from None
            if body is None or len(body) != exact[0]["size"]:
                raise ObservationError("object-changed-during-scan")
            return body, metadata

        def observe_reference(count):
            if count > native.MAX_OBJECTS:
                raise ObjectLimitExceeded()

        try:
            refs = native.object_references(db, read_object, observe_reference=observe_reference)
        except ObjectLimitExceeded:
            report.update(objectCount=native.MAX_OBJECTS + 1, objectCountIsLowerBound=True,
                          objectLimit=native.MAX_OBJECTS, objectStatus="over-limit",
                          objectBytesStatus="not-checked")
            return report
        except native.RehearsalError:
            raise ObservationError("reference-or-digest-invalid") from None
    size = sum(entry["bytes"] for entry in refs)
    object_status = level(len(refs), native.MAX_OBJECTS, warning_percent)
    size_status = level(size, native.TOTAL_OBJECT_BYTES, warning_percent)
    report.update(objectCount=len(refs), objectLimit=native.MAX_OBJECTS, objectBytes=size,
                  objectBytesLimit=native.TOTAL_OBJECT_BYTES, objectStatus=object_status,
                  objectBytesStatus=size_status, objectClosureSha256=native.digest(native.canonical(refs)))
    return report


def frozen_fingerprint(api, source):
    """Read complete typed data and referenced objects while control is frozen."""
    source.verify()
    source.schema()
    database = api.target["d1Id"]
    layout = {}
    for table in source.tables:
        columns = api.rows(database, 'PRAGMA table_info("' + table + '")')
        native.require(columns and len(columns) <= 100)
        types = [(row["name"], row["type"].upper() or ("TEXT" if row["name"] == "name" else "INTEGER")) for row in columns]
        native.require(all(kind in {"TEXT", "INTEGER", "REAL"} for _, kind in types))
        primary = [row["name"] for row in sorted(columns, key=lambda row: row["pk"]) if row["pk"]]
        if table == "sqlite_sequence":
            primary = ["name"]
        native.require(primary)
        layout[table] = {"columns": types, "primary": primary}
    summary = native.remote_summary(api, database, layout)
    observation = observe(api, source)
    native.require(observation.get("rowStatus") in {"normal", "warning"}
                   and observation.get("objectStatus") in {"normal", "warning"}
                   and observation.get("objectBytesStatus") in {"normal", "warning"}
                   and observation.get("rows") == summary["rowCount"]
                   and native.matches(native.DIGEST, observation.get("objectClosureSha256")))
    source.verify()
    return {"dataSha256": summary["dataSha256"], "rowCount": summary["rowCount"],
            "objectClosureSha256": observation["objectClosureSha256"]}

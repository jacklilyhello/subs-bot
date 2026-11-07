"""Apply reviewed additive migrations to the one dedicated isolation database."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import NamedTuple


DATABASE_NAME = "subs-bot-cf-dev-01"
BASELINE_NAME = "0001_subscriptions.sql"
BASELINE_SHA256 = "596041248d9b3e6addfd3c297526105a4a7aefdf6ea1774373d2169eaccba76e"
LEDGER = "subs_bot_schema_migrations"
LEDGER_SQL = f"""CREATE TABLE {LEDGER} (
    position INTEGER PRIMARY KEY CHECK (position >= 1),
    name TEXT NOT NULL UNIQUE,
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    mode TEXT NOT NULL CHECK (mode = 'applied' OR (position = 1 AND mode = 'adopted')),
    applied_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK (applied_at > 0)
) STRICT"""

FILE_NAME = re.compile(r"([0-9]{4})_[a-z][a-z0-9_]*\.sql")
SHA256 = re.compile(r"[a-f0-9]{64}")
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
TABLE = re.compile(r"CREATE TABLE ([a-z][a-z0-9_]*) \(")
INDEX = re.compile(r"CREATE (?:UNIQUE )?INDEX ([a-z][a-z0-9_]*) ON ([a-z][a-z0-9_]*)[ \t\n]+\(")
MAX_MIGRATION_BYTES = 32 * 1024
MAX_D1_STATEMENT_BYTES = 100_000


class MigrationError(RuntimeError):
    """A migration could not be safely applied or confirmed."""


class SchemaObject(NamedTuple):
    type: str
    name: str
    table: str
    sql: str


class Migration(NamedTuple):
    name: str
    sha256: str
    objects: tuple[SchemaObject, ...]


LEDGER_OBJECT = SchemaObject("table", LEDGER, LEDGER, LEDGER_SQL)
SEQUENCE_OBJECT = SchemaObject("table", "sqlite_sequence", "sqlite_sequence", "CREATE TABLE sqlite_sequence(name,seq)")


def _require(condition, message: str) -> None:
    if not condition:
        raise MigrationError(message)


def _literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _statements(sql: str):
    # SQLite tokenization only. No migration SQL is executed on the deployment host.
    start = 0
    for end, character in enumerate(sql, start=1):
        if character == ";" and sqlite3.complete_statement(sql[start:end]):
            statement = re.sub(r"\A(?:\s|--[^\n]*\n|/\*[\s\S]*?\*/)*", "", sql[start:end - 1]).rstrip()
            yield statement
            start = end
    _require(not sql[start:].strip(), "Migration must end with complete SQL statements.")


def _load_migrations(bundle_dir: Path, manifest: dict) -> list[Migration]:
    entries = manifest.get("migrations")
    _require(manifest.get("version") == 2 and isinstance(entries, list) and entries,
             "Migration manifest is missing or unsupported.")
    directory = Path(bundle_dir).resolve(strict=True)
    names = {LEDGER, "d1_migrations"}
    tables = set()
    migrations = []
    total_bytes = 0
    for position, entry in enumerate(entries, 1):
        _require(isinstance(entry, dict) and isinstance(entry.get("name"), str) and isinstance(entry.get("sha256"), str),
                 "Malformed migration manifest entry.")
        name, digest = entry["name"], entry["sha256"]
        match = FILE_NAME.fullmatch(name)
        _require(match and int(match[1]) == position and SHA256.fullmatch(digest),
                 "Migration files must have unique contiguous positions and valid digests.")
        if position == 1:
            _require((name, digest) == (BASELINE_NAME, BASELINE_SHA256), "Original migration 0001 changed.")
        file = directory / name
        _require(not file.is_symlink() and file.is_file(), "Migration file is missing or is not a regular artifact file.")
        total_bytes += file.stat().st_size
        _require(total_bytes <= MAX_MIGRATION_BYTES, "Migration SQL exceeds the isolation tool's size limit.")
        data = file.read_bytes()
        _require(hashlib.sha256(data).hexdigest() == digest, "Migration artifact digest does not match.")
        try:
            sql = data.decode("utf-8")
        except UnicodeDecodeError:
            raise MigrationError("Migration SQL must use UTF-8.") from None
        _require("\0" not in sql and "\r" not in sql, "Migration SQL contains unsupported characters or line endings.")
        objects = []
        for statement in _statements(sql):
            if table := TABLE.match(statement):
                object_name = table[1]
                objects.append(SchemaObject("table", object_name, object_name, statement))
                tables.add(object_name)
            elif index := INDEX.match(statement):
                object_name, table_name = index.groups()
                _require(table_name in tables, "Index references a table outside the approved migration chain.")
                objects.append(SchemaObject("index", object_name, table_name, statement))
            else:
                raise MigrationError("Only additive CREATE TABLE and CREATE INDEX migrations are supported.")
            _require(object_name not in names and not object_name.startswith("sqlite_"),
                     "Migration repeats or uses a reserved schema name.")
            names.add(object_name)
        _require(objects, "Empty migration file.")
        migrations.append(Migration(name, digest, tuple(objects)))
    _require({path.name for path in directory.glob("*.sql")} == {migration.name for migration in migrations},
             "Migration manifest does not match the artifact SQL files.")
    return migrations


def _results(api, path: str, sql: str) -> list[dict]:
    result = api("POST", path + "/query", {"sql": sql})
    _require(isinstance(result, list) and result and all(isinstance(row, dict) and row.get("success") is True for row in result),
             "D1 did not confirm the query.")
    return result


def _rows(api, path: str, sql: str) -> list[dict]:
    result = _results(api, path, sql)
    _require(len(result) == 1 and isinstance(result[0].get("results"), list), "Unexpected D1 read response.")
    return result[0]["results"]


def _objects(migrations: list[Migration], position: int, *, managed: bool) -> tuple[SchemaObject, ...]:
    if position == 0:
        return ()
    objects = tuple(obj for migration in migrations[:position] for obj in migration.objects) + (SEQUENCE_OBJECT,)
    return objects + (LEDGER_OBJECT,) if managed else objects


def _schema_condition(objects: tuple[SchemaObject, ...]) -> str:
    # Ignore only D1's reserved storage table and SQLite's generated indexes.
    # The full CREATE TABLE SQL pins inline UNIQUE/PK/CHECK constraints.
    explicit = "sqlite_schema WHERE tbl_name <> '_cf_KV' AND sql IS NOT NULL"
    parts = [f"(SELECT count(*) FROM {explicit}) = {len(objects)}"]
    parts.extend(
        f"EXISTS (SELECT 1 FROM sqlite_schema WHERE type = {_literal(obj.type)}"
        f" AND name = {_literal(obj.name)} AND tbl_name = {_literal(obj.table)} AND sql = {_literal(obj.sql)})"
        for obj in objects
    )
    parts.append("""NOT EXISTS (SELECT 1 FROM sqlite_schema AS i
        WHERE i.tbl_name <> '_cf_KV' AND i.sql IS NULL
        AND NOT (i.type = 'index' AND i.name GLOB ('sqlite_autoindex_' || i.tbl_name || '_[0-9]*')
          AND EXISTS (SELECT 1 FROM sqlite_schema AS t WHERE t.type = 'table' AND t.name = i.tbl_name AND t.sql IS NOT NULL)))""")
    if objects:
        parts.append("""EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'subscriptions'
            AND name = 'sqlite_autoindex_subscriptions_1' AND sql IS NULL)""")
    return "\nAND ".join(parts)


def _validate_indexes(api, path: str, objects: tuple[SchemaObject, ...]) -> None:
    tables = _rows(api, path, "PRAGMA table_list")
    subscription = [row for row in tables if row.get("name") == "subscriptions"]
    _require(len(subscription) == 1 and subscription[0].get("strict") == 1 and subscription[0].get("wr") == 0,
             "The subscriptions table layout is unexpected.")
    rows = _rows(api, path, "PRAGMA index_list('subscriptions')")
    actual = {(row.get("name"), row.get("unique"), row.get("origin"), row.get("partial")) for row in rows}
    expected = {
        ("sqlite_autoindex_subscriptions_1", 1, "u", 0),
        ("subscriptions_owner_id", 0, "c", 0),
    }
    reviewed_indexes = {obj.name for obj in objects if obj.type == "index" and obj.table == "subscriptions"}
    _require(expected <= actual and {row[0] for row in actual} == reviewed_indexes | {"sqlite_autoindex_subscriptions_1"},
             "The subscription indexes or token uniqueness differ from the reviewed migrations.")
    for name, columns in (("sqlite_autoindex_subscriptions_1", ["token"]), ("subscriptions_owner_id", ["owner_id", "id"])):
        rows = _rows(api, path, f"PRAGMA index_xinfo({_literal(name)})")
        keys = sorted((row["seqno"], row["name"], row["desc"], row["coll"]) for row in rows if row["key"] == 1)
        _require(keys == [(index, column, 0, "BINARY") for index, column in enumerate(columns)],
                 "Subscription index keys or collation differ from the original migration.")


def _matches_schema(api, path: str, objects: tuple[SchemaObject, ...]) -> bool:
    return _rows(api, path, f"SELECT ({_schema_condition(objects)}) AS matches") == [{"matches": 1}]


def _read_state(api, path: str, migrations: list[Migration]) -> tuple[str, list[dict]]:
    ledger_schema = _rows(api, path, f"SELECT type, tbl_name, sql FROM sqlite_schema WHERE name = '{LEDGER}'")
    if not ledger_schema:
        if _matches_schema(api, path, ()):
            return "fresh", []
        objects = _objects(migrations, 1, managed=False)
        _require(_matches_schema(api, path, objects),
                 "D1 does not match the original 0001 schema or a fresh database.")
        _validate_indexes(api, path, objects)
        _require(_rows(api, path, "SELECT EXISTS (SELECT 1 FROM subscriptions) AS present") == [{"present": 0}],
                 "The untracked original database contains subscription rows; adoption stopped.")
        return "legacy", []

    _require(ledger_schema == [{"type": "table", "tbl_name": LEDGER, "sql": LEDGER_SQL}],
             "D1 migration ledger has an unexpected schema.")
    history = _rows(api, path, f"SELECT position, name, sha256, mode FROM {LEDGER} ORDER BY position")
    _require(0 < len(history) <= len(migrations), "D1 migration history is empty or ahead of the artifact.")
    for position, (row, migration) in enumerate(zip(history, migrations), 1):
        _require((row.get("position"), row.get("name"), row.get("sha256")) == (position, migration.name, migration.sha256)
                 and (row.get("mode") == "applied" or (position == 1 and row.get("mode") == "adopted")),
                 "D1 migration history differs from the reviewed artifact.")
    objects = _objects(migrations, len(history), managed=True)
    _require(_matches_schema(api, path, objects),
             "D1 schema differs from its recorded migration history.")
    _validate_indexes(api, path, objects)
    return "managed", history


def _history_condition(history: list[dict]) -> str:
    parts = [f"(SELECT count(*) FROM {LEDGER}) = {len(history)}"]
    parts.extend(
        f"EXISTS (SELECT 1 FROM {LEDGER} WHERE position = {row['position']}"
        f" AND name = {_literal(row['name'])} AND sha256 = {_literal(row['sha256'])} AND mode = {_literal(row['mode'])})"
        for row in history
    )
    return "\nAND ".join(parts)


def _assert_sql(condition: str) -> str:
    # SQLite CASE short-circuits. Invalid JSON on a false guard aborts the D1 batch.
    return f"SELECT CASE WHEN {condition} THEN 1 ELSE json_extract('migration guard failed', '$') END AS guard"


def _apply_one(api, path, migrations, kind, history, guard):
    position = len(history) + 1
    migration = migrations[position - 1]
    mode = "adopted" if kind == "legacy" else "applied"
    expected_before = _objects(migrations, 1 if kind == "legacy" else position - 1, managed=kind == "managed")
    before = _schema_condition(expected_before)
    if kind == "legacy":
        before += "\nAND NOT EXISTS (SELECT 1 FROM subscriptions)"
    elif kind == "managed":
        before += "\nAND " + _history_condition(history)

    after = _schema_condition(_objects(migrations, position, managed=True))
    statements = [_assert_sql(before)]
    if kind != "managed":
        statements.append(LEDGER_SQL)
    if mode == "applied":
        statements.extend(obj.sql for obj in migration.objects)
    statements.extend((_assert_sql(after),
        f"INSERT INTO {LEDGER} (position, name, sha256, mode) VALUES"
        f" ({position}, {_literal(migration.name)}, {_literal(migration.sha256)}, {_literal(mode)})"))
    _require(all(len(sql.encode("utf-8")) < MAX_D1_STATEMENT_BYTES for sql in statements), "D1 migration guard exceeds statement limits.")
    expected = [*history, {"position": position, "name": migration.name, "sha256": migration.sha256, "mode": mode}]
    guard()
    failed = False
    try:
        # Wrangler uses the same REST form for one transactional migration + ledger insert.
        _results(api, path, ";\n".join(statements) + ";")
    except Exception:
        failed = True
    try:
        observed_kind, observed = _read_state(api, path, migrations)
    except Exception:
        raise MigrationError("D1 migration state could not be verified; further changes stopped.") from None
    if observed_kind == "managed" and observed == expected:
        return observed
    if failed and observed_kind == kind and observed == history:
        raise MigrationError("D1 migration was not applied; the verified prior state is safe to retry.")
    raise MigrationError("D1 migration outcome differs from the expected state; further changes stopped.")


def apply_migrations(api, target: dict, bundle_dir: Path, manifest: dict, guard) -> list[dict]:
    """Verify/adopt 0001 and apply pending additive migrations to the pinned D1.

    Destructive and data migrations require a separate reviewed tool and plan.
    Ambiguous API results are reconciled by reading schema and history before any retry.
    """
    account_id, database_id, created = (target.get(key) for key in ("accountId", "d1Id", "d1CreatedAt"))
    _require(isinstance(account_id, str) and re.fullmatch(r"[a-f0-9]{32}", account_id)
             and isinstance(database_id, str) and UUID.fullmatch(database_id)
             and isinstance(created, str) and created, "D1 ownership record is incomplete.")
    migrations = _load_migrations(bundle_dir, manifest)
    path = f"/accounts/{account_id}/d1/database/{database_id}"
    database = api("GET", path)
    _require(isinstance(database, dict) and (database.get("uuid"), database.get("name"), database.get("created_at"))
             == (database_id, DATABASE_NAME, created), "D1 identity does not match the pinned isolation database.")
    kind, history = _read_state(api, path, migrations)
    while len(history) < len(migrations):
        history = _apply_one(api, path, migrations, kind, history, guard)
        kind = "managed"
    return [{key: row[key] for key in ("name", "sha256", "mode")} for row in history]

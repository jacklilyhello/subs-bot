"""Hosted-only SQLite prepare check for the synthetic emitted reply claim."""

from contextlib import closing
import json
import sqlite3
import sys


MAX_INPUT_BYTES = 1024 * 1024
D1_EXPRESSION_DEPTH = 100


def check() -> str:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return "invalid-fixture"
    fixture = json.loads(raw)
    migrations = fixture["migrations"]
    sql, bindings = fixture["claim"]["sql"], fixture["claim"]["bindings"]
    if (not isinstance(migrations, list) or not migrations or not all(isinstance(item, str) for item in migrations)
            or not isinstance(sql, str) or not sql.lstrip().startswith("UPDATE telegram_outbox")
            or not isinstance(bindings, list) or len(bindings) > 100):
        return "invalid-fixture"
    with closing(sqlite3.connect(":memory:")) as db:
        for migration in migrations:
            db.executescript(migration)
        db.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, D1_EXPRESSION_DEPTH)
        if db.getlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH) != D1_EXPRESSION_DEPTH:
            return "invalid-fixture"
        try:
            # Prepare the unchanged UPDATE against the artifact's actual tables.
            # EXPLAIN compiles the full expression but does not run the update.
            db.execute("EXPLAIN " + sql, bindings).fetchone()
        except sqlite3.Error as error:
            return "expression-depth" if "expression tree is too large" in str(error).lower() else "sqlite-error"
    return "ok"


if __name__ == "__main__":
    try:
        outcome = check()
    except sqlite3.Error:
        outcome = "sqlite-error"
    except Exception:
        outcome = "invalid-fixture"
    print(outcome)
    raise SystemExit(0 if outcome == "ok" else 1)

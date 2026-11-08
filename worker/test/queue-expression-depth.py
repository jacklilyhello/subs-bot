"""Prepare the hosted emitted reply queries against the artifact schema."""

from contextlib import closing
import json
import sqlite3
import sys


MAX_INPUT_BYTES = 1024 * 1024
D1_EXPRESSION_DEPTH = 100
STAGES = {
    "base-claim": ("UPDATE", "telegram_outbox"),
    "base-reap": ("UPDATE", "telegram_outbox"),
    "provider-claim": ("UPDATE", "telegram_outbox"),
    "provider-reap": ("UPDATE", "telegram_outbox"),
    "provider-work-claim-batch": ("UPDATE", "telegram_provider_batch_jobs"),
    "provider-work-claim-single": ("UPDATE", "telegram_provider_jobs"),
    "provider-work-reap-batch": ("WITH", "terminal", "AS", "MATERIALIZED", "("),
}


def check() -> str:
    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        return "invalid-fixture"
    fixture = json.loads(raw)
    migrations, queries = fixture["migrations"], fixture["queries"]
    if (not isinstance(migrations, list) or not migrations or not all(isinstance(item, str) for item in migrations)
            or not isinstance(queries, list) or [query["stage"] for query in queries] != list(STAGES)):
        return "invalid-fixture"
    with closing(sqlite3.connect(":memory:")) as db:
        for migration in migrations:
            db.executescript(migration)
        db.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, D1_EXPRESSION_DEPTH)
        if db.getlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH) != D1_EXPRESSION_DEPTH:
            return "invalid-fixture"
        for query in queries:
            sql, bindings = query["sql"], query["bindings"]
            stage = query["stage"]
            prefix = STAGES[stage]
            if not isinstance(sql, str) or tuple(sql.split(maxsplit=len(prefix))[:len(prefix)]) != prefix:
                return f"{stage} invalid-statement"
            if not isinstance(bindings, list) or len(bindings) > 100:
                return f"{stage} invalid-bindings"
            try:
                # Compile each unchanged statement with its actual synthetic bind values.
                db.execute("EXPLAIN " + sql, bindings).fetchone()
            except sqlite3.Error as error:
                message = str(error).lower()
                category = ("expression-depth" if "expression tree is too large" in message
                            or "parser stack overflow" in message else "sqlite-error")
                return f"{stage} {category}"
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

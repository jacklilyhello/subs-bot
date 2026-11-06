"""Stage or retire only synthetic rows for the isolated two-account Telegram acceptance."""

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import secrets
import sys

from cloudflare_isolation import CloudflareClient, CloudflareError, REVISION, _Isolation, _verify_health
from d1_migrations import MigrationError, _assert_sql, _literal, _results, _rows
from prepare_isolation_artifact import ArtifactError, require_current_main
from release_isolation import telegram_release_config


MIGRATION = "0004_telegram_views.sql"
ORIGIN = "https://subs-bot-view-fixtures.invalid/"
FIELDS = "id, owner_id, name, source_url, token, expire_at, created_at, updated_at, generation, node_count"


class FixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Fixture:
    owner: str
    name: str
    source: str
    trashed: bool
    expire_offset: int


def plan(policy, cohort):
    if not isinstance(cohort, str) or re.fullmatch(r"[a-z0-9]{16}", cohort) is None:
        raise FixtureError("A 16-character lowercase synthetic cohort key is required.")
    prefix = f"{ORIGIN}{cohort}/"
    entries = [
        Fixture(policy[owner], f"CFV-{cohort[-6:]}-{role}{kind}{index:02}",
                f"{prefix}{role}{kind}{index:02}", kind == "T", -3600 if index == 1 else 86400)
        for owner, role, kind, count in (
            ("adminId", "A", "L", 10), ("adminId", "A", "T", 9),
            ("memberId", "B", "L", 2), ("memberId", "B", "T", 1),
        )
        for index in range(1, count + 1)
    ]
    return prefix, {entry.source: entry for entry in entries}


def read_cohort(api, path, prefix, expected):
    match = f"source_url GLOB {_literal(prefix + '*')}"
    rows = _rows(api, path, f"""
        SELECT id, owner_id, name, source_url, generation, node_count, snapshot_id, manifest_sha256, created_at, expire_at,
          (SELECT revision FROM subscription_lifecycle WHERE subscription_id = subscriptions.id) AS revision,
          NULL AS trash_revision, 0 AS trashed
        FROM subscriptions WHERE {match}
        UNION ALL
        SELECT id, owner_id, name, source_url, generation, node_count, snapshot_id, manifest_sha256, created_at, expire_at,
          (SELECT revision FROM subscription_lifecycle WHERE subscription_id = subscription_trash.id), lifecycle_revision, 1
        FROM subscription_trash WHERE {match}
        LIMIT {len(expected) + 1}
    """)
    by_source = {}
    for row in rows:
        source = row.get("source_url")
        fixture = expected.get(source)
        if (not fixture or source in by_source or type(row.get("id")) is not int
                or not 0 < row["id"] < 2**53
                or (row.get("owner_id"), row.get("name"), row.get("trashed"))
                != (fixture.owner, fixture.name, int(fixture.trashed))
                or (row.get("revision"), row.get("trash_revision")) != ((1, 1) if fixture.trashed else (None, None))
                or type(row.get("created_at")) is not int or row.get("expire_at") != row["created_at"] + fixture.expire_offset
                or (row.get("generation"), row.get("node_count"), row.get("snapshot_id"), row.get("manifest_sha256"))
                != (0, 0, None, None)):
            raise FixtureError("Synthetic fixture ownership or state is ambiguous.")
        by_source[source] = row
    return by_source


def cohort_count(prefix, count):
    where = f"source_url GLOB {_literal(prefix + '*')}"
    return f"((SELECT count(*) FROM subscriptions WHERE {where}) + (SELECT count(*) FROM subscription_trash WHERE {where})) = {count}"


def seed_statements(prefix, expected):
    values = ",\n".join(
        f"({_literal(entry.owner)}, {_literal(entry.name)}, {_literal(entry.source)}, "
        f"{_literal(secrets.token_urlsafe(24))}, unixepoch() + ({entry.expire_offset}), unixepoch(), unixepoch())"
        for entry in expected.values()
    )
    trash = "source_url IN (" + ",".join(_literal(entry.source) for entry in expected.values() if entry.trashed) + ")"
    return [
        _assert_sql(cohort_count(prefix, 0)),
        "INSERT INTO subscriptions (owner_id,name,source_url,token,expire_at,created_at,updated_at) VALUES\n" + values,
        f"INSERT INTO subscription_trash ({FIELDS}, deleted_at, lifecycle_revision) "
        f"SELECT {FIELDS}, unixepoch() - 3600, 1 FROM subscriptions WHERE {trash}",
        f"INSERT INTO subscription_lifecycle (subscription_id,revision) SELECT id,1 FROM subscription_trash WHERE {trash}",
        f"DELETE FROM subscriptions WHERE {trash}",
        _assert_sql(cohort_count(prefix, len(expected))),
    ]


def retire_statements(prefix, rows):
    statements = [_assert_sql(cohort_count(prefix, len(rows)))]
    for row in rows.values():
        table = "subscription_trash" if row["trashed"] else "subscriptions"
        conditions = (f"id = {row['id']} AND source_url = {_literal(row['source_url'])} "
                      f"AND owner_id = {_literal(row['owner_id'])} AND name = {_literal(row['name'])} "
                      "AND generation = 0 AND node_count = 0 AND snapshot_id IS NULL AND manifest_sha256 IS NULL")
        if row["trashed"]:
            conditions += " AND lifecycle_revision = 1"
            statements.append("DELETE FROM subscription_lifecycle WHERE revision = 1 "
                              f"AND subscription_id IN (SELECT id FROM {table} WHERE {conditions})")
        conditions += f" AND NOT EXISTS (SELECT 1 FROM subscription_lifecycle WHERE subscription_id = {table}.id)"
        statements.append(f"DELETE FROM {table} WHERE {conditions}")
    statements.append(_assert_sql(cohort_count(prefix, 0)))
    return statements


def manage(api, path, action, prefix, expected):
    before = read_cohort(api, path, prefix, expected)
    if action == "seed" and before and set(before) != set(expected):
        raise FixtureError("A partial synthetic cohort must be retired before another seed attempt.")
    statements = (seed_statements(prefix, expected) if action == "seed" and not before else
                  retire_statements(prefix, before) if action == "retire" and before else [])
    if statements:
        try:
            _results(api, path, ";\n".join(statements) + ";")
        except (CloudflareError, MigrationError):
            pass  # Reconcile an ambiguous API result by verifying the exact cohort.
    after = read_cohort(api, path, prefix, expected)
    if set(after) != (set(expected) if action == "seed" else set()):
        raise FixtureError("The synthetic fixture operation could not be confirmed.")
    return {"active": sum(not row["trashed"] for row in after.values()),
            "trashed": sum(row["trashed"] for row in after.values()), "removed": len(before) if action == "retire" else 0}


def run():
    action = os.environ.get("SUBS_BOT_TELEGRAM_FIXTURE_ACTION")
    revision = os.environ.get("GITHUB_SHA", "")
    if (action not in {"seed", "retire"} or REVISION.fullmatch(revision) is None
            or os.environ.get("GITHUB_REPOSITORY") != "jacklilyhello/subs-bot"
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch" or os.environ.get("GITHUB_REF") != "refs/heads/main"):
        raise FixtureError("Telegram fixtures require the project's manually dispatched main workflow.")
    raw = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    prefix, expected = plan(json.loads(raw), os.environ.get("SUBS_BOT_TELEGRAM_FIXTURE_COHORT"))
    target = json.loads(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "null"))
    data = os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN")
    deploy = os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN")
    if not data or not deploy or data == deploy:
        raise FixtureError("Separate scoped Cloudflare credentials are required.")
    data_api = CloudflareClient(data)
    scope = _Isolation(CloudflareClient(deploy), data_api, target)
    require_current_main(revision)
    scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    if not scope.cron_enabled() or version.revision != revision or version.telegram_config_sha256 != sha256(raw.encode()).hexdigest():
        raise FixtureError("The active Worker and Telegram configuration must match the reviewed isolation release.")
    _verify_health(revision)
    path = f"{scope.account}/d1/database/{target['d1Id']}"
    digest = sha256((Path(__file__).resolve().parents[1] / "migrations" / MIGRATION).read_bytes()).hexdigest()
    if _rows(data_api, path, f"SELECT sha256, mode FROM subs_bot_schema_migrations WHERE name = {_literal(MIGRATION)}") != [
        {"sha256": digest, "mode": "applied"},
    ]:
        raise FixtureError("The isolated Telegram view migration does not match the checked-out revision.")
    require_current_main(revision)
    if scope.active() != active:
        raise FixtureError("The isolation deployment changed before the fixture operation.")
    print(json.dumps(manage(data_api, path, action, prefix, expected), sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CloudflareError, FixtureError, MigrationError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram fixture operation could not be verified.")

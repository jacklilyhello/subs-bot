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
from d1_migrations import _assert_sql
from prepare_isolation_artifact import ArtifactError, require_current_main
from release_isolation import telegram_release_config


MIGRATION = "0004_telegram_views.sql"
LIFECYCLE_MIGRATION = "0006_telegram_lifecycle.sql"
ORIGIN = "https://subs-bot-view-fixtures.invalid/"
LIFECYCLE_ORIGIN = "https://subs-bot-action-fixtures.invalid/"
FIELDS = "id, owner_id, name, source_url, token, expire_at, created_at, updated_at, generation, node_count"
PREFIX_MATCH = "substr(source_url, 1, length(?)) = ?"


class FixtureError(RuntimeError):
    pass


@dataclass(frozen=True)
class Fixture:
    owner: str
    name: str
    source: str
    trashed: bool
    expire_offset: int


def statement(sql, *parameters):
    return {"sql": sql, "params": [str(value) for value in parameters]}


def query(api, path, payload, result_count):
    results = api("POST", path + "/query", payload)
    if (not isinstance(results, list) or len(results) != result_count
            or not all(isinstance(result, dict) and result.get("success") is True
                       and isinstance(result.get("results"), list) for result in results)):
        raise FixtureError("D1 fixture query results could not be verified.")
    return results


def rows(api, path, sql, *parameters):
    return query(api, path, statement(sql, *parameters), 1)[0]["results"]


def plan(policy, cohort, purpose="views"):
    if not isinstance(cohort, str) or re.fullmatch(r"[a-z0-9]{16}", cohort) is None:
        raise FixtureError("A 16-character lowercase synthetic cohort key is required.")
    if purpose == "views":
        prefix = f"{ORIGIN}{cohort}/"
        name_prefix = "CFV"
        counts = (10, 9, 2, 1)
    elif purpose == "lifecycle":
        prefix = f"{LIFECYCLE_ORIGIN}{cohort}/"
        name_prefix = "CFA"
        counts = (1, 1, 1, 1)
    else:
        raise FixtureError("Unknown Telegram acceptance purpose.")
    entries = [
        Fixture(policy[owner], f"{name_prefix}-{cohort[-6:]}-{role}{kind}{index:02}",
                f"{prefix}{role}{kind}{index:02}", kind == "T", -3600 if index == 1 else 86400)
        for (owner, role, kind), count in zip(
            (("adminId", "A", "L"), ("adminId", "A", "T"), ("memberId", "B", "L"), ("memberId", "B", "T")),
            counts, strict=True)
        for index in range(1, count + 1)
    ]
    return prefix, {entry.source: entry for entry in entries}


def lifecycle_state_matches(row, fixture, allow_lifecycle):
    revision, trash_revision = row.get("revision"), row.get("trash_revision")
    name, trashed = row.get("name"), row.get("trashed")
    if (name, trashed, revision, trash_revision) == (
            fixture.name, int(fixture.trashed), 1 if fixture.trashed else None, 1 if fixture.trashed else None):
        return True
    if not allow_lifecycle or type(revision) is not int or not 1 <= revision <= 8:
        return False
    if type(trashed) is not int or trashed not in (0, 1) or trash_revision != (revision if trashed else None):
        return False
    if revision < int(fixture.trashed) + int(trashed != int(fixture.trashed)) + int(name != fixture.name):
        return False
    return name in (fixture.name, fixture.name + "-renamed")


def read_cohort(api, path, prefix, expected, allow_lifecycle=False):
    observed = rows(api, path, f"""
        SELECT id, owner_id, name, source_url, generation, node_count, snapshot_id, manifest_sha256, created_at, expire_at,
          (SELECT revision FROM subscription_lifecycle WHERE subscription_id = subscriptions.id) AS revision,
          NULL AS trash_revision, 0 AS trashed
        FROM subscriptions WHERE {PREFIX_MATCH}
        UNION ALL
        SELECT id, owner_id, name, source_url, generation, node_count, snapshot_id, manifest_sha256, created_at, expire_at,
          (SELECT revision FROM subscription_lifecycle WHERE subscription_id = subscription_trash.id), lifecycle_revision, 1
        FROM subscription_trash WHERE {PREFIX_MATCH}
        LIMIT {len(expected) + 1}
    """, prefix, prefix, prefix, prefix)
    by_source = {}
    for row in observed:
        source = row.get("source_url")
        fixture = expected.get(source)
        if (not fixture or source in by_source or type(row.get("id")) is not int
                or not 0 < row["id"] < 2**53
                or row.get("owner_id") != fixture.owner or not lifecycle_state_matches(row, fixture, allow_lifecycle)
                or type(row.get("created_at")) is not int or row.get("expire_at") != row["created_at"] + fixture.expire_offset
                or (row.get("generation"), row.get("node_count"), row.get("snapshot_id"), row.get("manifest_sha256"))
                != (0, 0, None, None)):
            raise FixtureError("Synthetic fixture ownership or state is ambiguous.")
        by_source[source] = row
    return by_source


def cohort_count(prefix, count):
    # A fixture prefix can exceed D1's LIKE/GLOB pattern limit.
    return statement(_assert_sql(
        f"((SELECT count(*) FROM subscriptions WHERE {PREFIX_MATCH}) + "
        f"(SELECT count(*) FROM subscription_trash WHERE {PREFIX_MATCH})) = CAST(? AS INTEGER)"
    ), prefix, prefix, prefix, prefix, count)


def seed_statements(prefix, expected):
    values = ",\n".join(
        f"(?, ?, ?, ?, unixepoch() + ({entry.expire_offset}), unixepoch(), unixepoch())"
        for entry in expected.values()
    )
    values_parameters = [value for entry in expected.values()
                         for value in (entry.owner, entry.name, entry.source, secrets.token_urlsafe(24))]
    trash_parameters = [entry.source for entry in expected.values() if entry.trashed]
    trash = "source_url IN (" + ",".join("?" for _ in trash_parameters) + ")"
    return [
        cohort_count(prefix, 0),
        statement("INSERT INTO subscriptions (owner_id,name,source_url,token,expire_at,created_at,updated_at) VALUES\n" + values,
                  *values_parameters),
        statement(f"INSERT INTO subscription_trash ({FIELDS}, deleted_at, lifecycle_revision) "
                  f"SELECT {FIELDS}, unixepoch() - 3600, 1 FROM subscriptions WHERE {trash}", *trash_parameters),
        statement(f"INSERT INTO subscription_lifecycle (subscription_id,revision) "
                  f"SELECT id,1 FROM subscription_trash WHERE {trash}", *trash_parameters),
        statement(f"DELETE FROM subscriptions WHERE {trash}", *trash_parameters),
        cohort_count(prefix, len(expected)),
    ]


def retire_statements(prefix, rows):
    statements = [cohort_count(prefix, len(rows))]
    for row in rows.values():
        table = "subscription_trash" if row["trashed"] else "subscriptions"
        parameters = (row["id"], row["source_url"], row["owner_id"], row["name"], row["created_at"], row["expire_at"])
        conditions = ("id = CAST(? AS INTEGER) AND source_url = ? AND owner_id = ? AND name = ? "
                      "AND created_at = CAST(? AS INTEGER) AND expire_at = CAST(? AS INTEGER) "
                      "AND generation = 0 AND node_count = 0 AND snapshot_id IS NULL AND manifest_sha256 IS NULL")
        if row["trashed"]:
            conditions += " AND lifecycle_revision = CAST(? AS INTEGER)"
            parameters += (row["trash_revision"],)
        if row["revision"] is not None:
            statements.append(statement("DELETE FROM subscription_lifecycle WHERE revision = CAST(? AS INTEGER) "
                                        f"AND subscription_id IN (SELECT id FROM {table} WHERE {conditions})",
                                        row["revision"], *parameters))
        conditions += f" AND NOT EXISTS (SELECT 1 FROM subscription_lifecycle WHERE subscription_id = {table}.id)"
        statements.append(statement(f"DELETE FROM {table} WHERE {conditions}", *parameters))
    statements.append(cohort_count(prefix, 0))
    return statements


def manage(api, path, action, prefix, expected, purpose="views"):
    allow_lifecycle = action == "retire" and purpose == "lifecycle" and prefix.startswith(LIFECYCLE_ORIGIN)
    before = read_cohort(api, path, prefix, expected, allow_lifecycle)
    if action == "seed" and before and set(before) != set(expected):
        raise FixtureError("A partial synthetic cohort must be retired before another seed attempt.")
    statements = (seed_statements(prefix, expected) if action == "seed" and not before else
                  retire_statements(prefix, before) if action == "retire" and before else [])
    failure = None
    if statements:
        try:
            query(api, path, {"batch": statements}, len(statements))
        except (CloudflareError, FixtureError) as error:
            failure = error  # Reconcile an ambiguous API result by verifying the exact cohort.
    after = read_cohort(api, path, prefix, expected, allow_lifecycle)
    if set(after) != (set(expected) if action == "seed" else set()):
        reason = str(failure) if failure else "D1 cohort readback differed."
        raise FixtureError(f"The synthetic fixture operation could not be confirmed. {reason}")
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
    purpose = os.environ.get("SUBS_BOT_TELEGRAM_FIXTURE_PURPOSE", "views")
    prefix, expected = plan(json.loads(raw), os.environ.get("SUBS_BOT_TELEGRAM_FIXTURE_COHORT"), purpose)
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
    migrations = (MIGRATION, LIFECYCLE_MIGRATION) if purpose == "lifecycle" else (MIGRATION,)
    for migration in migrations:
        digest = sha256((Path(__file__).resolve().parents[1] / "migrations" / migration).read_bytes()).hexdigest()
        if rows(data_api, path, "SELECT sha256, mode FROM subs_bot_schema_migrations WHERE name = ?", migration) != [
            {"sha256": digest, "mode": "applied"},
        ]:
            raise FixtureError("The isolated Telegram migration does not match the checked-out revision.")
    require_current_main(revision)
    if scope.active() != active:
        raise FixtureError("The isolation deployment changed before the fixture operation.")
    print(json.dumps(manage(data_api, path, action, prefix, expected, purpose), sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CloudflareError, FixtureError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram fixture operation could not be verified.")

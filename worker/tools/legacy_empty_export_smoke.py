"""Check exact synthetic legacy empty exports on the live isolation Worker."""

from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from capacity_resources import Resources, integer
from cloudflare_isolation import CloudflareClient, CloudflareError, REVISION, _Isolation, _NoRedirect, _verify_health
from d1_migrations import _assert_sql
from prepare_isolation_artifact import MAIN_REF, REPOSITORY, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import MAX_ID, ORIGIN, SUBSCRIPTION_FIELDS, canonical, digest, key_bytes, require
from telegram_bulk_trash_smoke import snapshot_assert
from telegram_view_fixtures import FixtureError, query, statement


MIGRATION = "0026_legacy_empty_subscription_exports.sql"
MIGRATION_SHA256 = "124eb153b8f8d1fc01165d2ba0db1adee8948cd6bffe8a8ad2465afa62da3976"
COHORT = re.compile(r"[a-f0-9]{16}\Z")
SUFFIXES = ("", "clash", "base64", "v2ray", "mixed", "singbox", "sing-box", "surge", "qx", "quantumult", "quantumultx")
ROW_FIELDS = (*SUBSCRIPTION_FIELDS.split(","), "trashed", "revision", "marker_owner", "marker_digest")
EXPECTED_SINGBOX = {"outbounds": [{"type": "selector", "tag": "proxy", "outbounds": ["direct"]},
                                  {"type": "direct", "tag": "direct"}]}
EXPECTED_SURGE = b"[Proxy]\n\n[Proxy Group]\nProxy = select, DIRECT\n\n[Rule]\nFINAL,Proxy\n"
ERROR = "The isolated legacy empty export smoke could not be verified."


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"action", "cohort", "confirm_retire"}, ERROR)
    action, cohort, confirm = (inputs.get(key, "") for key in ("action", "cohort", "confirm_retire"))
    require(action in {"verify", "retire"} and isinstance(cohort, str) and COHORT.fullmatch(cohort)
            and confirm == (f"retire {cohort}" if action == "retire" else ""), ERROR)
    return action, cohort


class EmptyFixtures:
    def __init__(self, resources, policy, key, cohort):
        self.resources = resources
        self.prefix = f"https://subs-bot-empty-export-fixtures.invalid/{cohort}/"
        scope_key = hmac.digest(key, b"subs-bot/legacy-empty-export-fixture/v1", "sha256")
        self.targets = {
            kind: {"source_url": self.prefix + kind, "owner_id": policy[actor], "name": f"empty-fixture-{cohort}-{kind}",
                   "token": hmac.digest(scope_key, canonical([resources.scope_hash, cohort, kind]).encode("ascii"), "sha256").hex()}
            for kind, actor in (("marked", "adminId"), ("unmarked", "memberId"))
        }

    def inventory(self):
        token_list = canonical([row["token"] for row in self.targets.values()])
        name_list = canonical([row["name"] for row in self.targets.values()])
        where = """substr(source_url,1,length(?))=? OR token IN (SELECT value FROM json_each(?))
            OR name IN (SELECT value FROM json_each(?))"""
        params = (self.prefix, self.prefix, token_list, name_list)
        sql = f"""SELECT inventory.*, lifecycle.revision, marker.owner_id AS marker_owner, marker.token_sha256 AS marker_digest
          FROM (SELECT {SUBSCRIPTION_FIELDS},0 AS trashed FROM subscriptions WHERE {where}
                UNION ALL SELECT {SUBSCRIPTION_FIELDS},1 AS trashed FROM subscription_trash WHERE {where}) AS inventory
          LEFT JOIN subscription_lifecycle AS lifecycle ON lifecycle.subscription_id=inventory.id
          LEFT JOIN legacy_empty_subscription_exports AS marker ON marker.subscription_id=inventory.id
          ORDER BY inventory.id,inventory.trashed LIMIT 3"""
        return sql, (*params, *params)

    def observe(self):
        sql, params = self.inventory()
        rows = self.resources.query(sql, params)
        by_source = {row["source_url"]: row for row in rows}
        require(not rows or len(rows) == len(by_source) == len(self.targets), ERROR)
        for kind, fixture in self.targets.items():
            if not rows:
                break
            row = by_source.get(fixture["source_url"])
            marker = (fixture["owner_id"], digest(fixture["token"].encode("ascii"))) if kind == "marked" else (None, None)
            require(row and all(row[field] == value for field, value in fixture.items())
                    and integer(row["id"], 1, MAX_ID) and integer(row["created_at"], 1, MAX_ID)
                    and row["created_at"] == row["updated_at"] and (row["generation"], row["node_count"], row["trashed"]) == (0, 0, 0)
                    and all(row[field] is None for field in ("snapshot_id", "manifest_sha256", "expire_at", "traffic_used",
                                                            "traffic_total", "last_error", "revision"))
                    and (row["marker_owner"], row["marker_digest"]) == marker, ERROR)
        return rows

    def no_markers(self):
        return statement(_assert_sql("""NOT EXISTS (SELECT 1 FROM legacy_empty_subscription_exports
            WHERE token_sha256 IN (?,?))"""), *(digest(row["token"].encode("ascii")) for row in self.targets.values()))

    def seed(self, guard):
        if self.observe():
            return
        sql, params = self.inventory()
        steps = [snapshot_assert(sql, params, ROW_FIELDS, []), self.no_markers()]
        for fixture in self.targets.values():
            steps.append(statement("""INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at)
                VALUES (?,?,?,?,unixepoch(),unixepoch())""", *(fixture[field] for field in ("owner_id", "name", "source_url", "token"))))
        marked = self.targets["marked"]
        steps += [statement("""INSERT INTO legacy_empty_subscription_exports (subscription_id,owner_id,token_sha256)
            SELECT id,owner_id,? FROM subscriptions WHERE source_url=? AND owner_id=? AND token=?""",
            digest(marked["token"].encode("ascii")), marked["source_url"], marked["owner_id"], marked["token"]),
            statement(_assert_sql(f"(SELECT count(*) FROM ({sql}) WHERE marker_owner=owner_id AND marker_digest=?)=1"),
                      *params, digest(marked["token"].encode("ascii"))),
            statement(_assert_sql(f"(SELECT count(*) FROM ({sql}))=2"), *params)]
        self.apply(steps, guard)
        require(len(self.observe()) == 2, ERROR)

    def retire(self, guard):
        rows = self.observe()
        if not rows:
            statement_pin = self.no_markers()
            self.resources.query(statement_pin["sql"], statement_pin["params"])
            return 0
        sql, params = self.inventory()
        marked = next(row for row in rows if row["marker_digest"] is not None)
        steps = [snapshot_assert(sql, params, ROW_FIELDS, rows),
                 statement("DELETE FROM legacy_empty_subscription_exports WHERE subscription_id=CAST(? AS INTEGER) AND owner_id=? AND token_sha256=?",
                           marked["id"], marked["owner_id"], marked["marker_digest"])]
        steps.extend(statement("DELETE FROM subscriptions WHERE id=CAST(? AS INTEGER) AND owner_id=? AND token=?",
                               row["id"], row["owner_id"], row["token"]) for row in rows)
        steps += [snapshot_assert(sql, params, ROW_FIELDS, []), self.no_markers()]
        self.apply(steps, guard)
        require(not self.observe(), ERROR)
        return len(rows)

    def apply(self, steps, guard):
        guard()
        try:
            query(self.resources.api, self.resources.database, {"batch": steps}, len(steps))
        except (CloudflareError, FixtureError):
            # Read back the exact proposed state to reconcile an ambiguous result.
            pass


def request_export(opener, token, suffix, method):
    path = f"{ORIGIN}/sub/{token}" + (f"/{suffix}" if suffix else "")
    request = Request(path, method=method, headers={"Cache-Control": "no-cache"})
    try:
        response = opener.open(request, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        headers = response.headers
        body = response.read(4097)
        require(len(body) <= 4096 and headers.get("Cache-Control") == "private, no-store"
                and headers.get("Referrer-Policy") == "no-referrer" and headers.get("X-Content-Type-Options") == "nosniff"
                and headers.get("Location") is None and (method != "HEAD" or not body), ERROR)
        return response.status, headers.get_content_type(), body


def verify_formats(fixtures, request):
    token = fixtures.targets["marked"]["token"]
    default_clash = None
    for suffix in SUFFIXES:
        status, media, body = request(token, suffix, "GET")
        expected_media = {"": "text/yaml", "clash": "text/yaml",
                          "singbox": "application/json", "sing-box": "application/json"}.get(suffix, "text/plain")
        require(status == 200 and media == expected_media and request(token, suffix, "HEAD") == (200, media, b""), ERROR)
        if expected_media == "text/yaml":
            require(body.startswith(b"proxies: []\n") and b"proxy-groups:\n" in body and b"rules:\n" in body, ERROR)
            if suffix:
                require(body == default_clash, ERROR)
            else:
                default_clash = body
        elif expected_media == "application/json":
            require(json.loads(body) == EXPECTED_SINGBOX, ERROR)
        else:
            require(body == (EXPECTED_SURGE if suffix == "surge" else b""), ERROR)
    verify_unavailable(fixtures.targets["unmarked"]["token"], request)


def verify_unavailable(token, request):
    for method in ("GET", "HEAD"):
        require(request(token, "", method) == (404, "text/plain", b"Not found." if method == "GET" else b""), ERROR)


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(REVISION.fullmatch(revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", ERROR)
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        payload = event.read(65537)
    require(len(payload) <= 65536, ERROR)
    action, cohort = parse_inputs(_parse_object(payload, ERROR))
    require_current_main(revision)
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    encoded = os.environ["SUBS_BOT_TELEGRAM_AGGREGATE_KEY"]
    target = _parse_object(os.environ["SUBS_BOT_CF_ISOLATION_TARGET_JSON"], ERROR)
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, ERROR)
    data = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), data, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    require(version.revision == revision and version.telegram_config_sha256 == digest(raw_policy.encode("utf-8"))
            and version.telegram_aggregate_key_sha256 == digest(encoded.encode("ascii")), ERROR)
    _verify_health(revision)
    resources = Resources(target, data, None)
    require(resources.query("SELECT name,sha256,mode FROM subs_bot_schema_migrations WHERE position=26")
            == [{"name": MIGRATION, "sha256": MIGRATION_SHA256, "mode": "applied"}], ERROR)

    def guard():
        require_current_main(revision)
        require(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version, ERROR)

    fixtures = EmptyFixtures(resources, json.loads(raw_policy), key_bytes(encoded), cohort)
    opener = build_opener(ProxyHandler({}), _NoRedirect())

    def request(token, suffix, method):
        return request_export(opener, token, suffix, method)

    if action == "verify":
        fixtures.seed(guard)
        try:
            verify_formats(fixtures, request)
        finally:
            removed = fixtures.retire(guard)
        require(removed == 2, ERROR)
    else:
        removed = fixtures.retire(guard)
    for fixture in fixtures.targets.values():
        verify_unavailable(fixture["token"], request)
    guard()
    _verify_health(revision)
    print(json.dumps({"action": action, "verifiedFormats": len(SUFFIXES) if action == "verify" else 0,
                      "syntheticRowsRemoved": removed, "privateNoStore": True, "activeVersion": active.version}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except Exception:
        # HTTP and database errors may include synthetic capability values.
        sys.exit(ERROR)

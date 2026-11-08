"""Verify an isolated Provider publication and a separately staged interruption."""

from base64 import b64encode
from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import secrets
import sys
from urllib.parse import urlencode
from urllib.request import ProxyHandler, build_opener
from uuid import UUID

from aggregate_smoke import _batch, _statement
from capacity_resources import Resources, R2Objects, digest, integer, recheck_absent, require
from cloudflare_isolation import CloudflareClient, ORIGIN, REVISION, _Isolation, _NoRedirect, _verify_health
from d1_migrations import _assert_sql
from legacy_empty_export_smoke import request_export
from prepare_isolation_artifact import MAIN_REF, REPOSITORY, _parse_object, require_current_main
from provider_binding_gate import CONFIG_ENV, load_provider_gate
from telegram_document_smoke import probe_export


OWNER = "9223372036854775789"
MIGRATION = "0033_provider_snapshot_journal.sql"
ERROR = "Isolated Provider journal verification failed."
COHORT = re.compile(r"[a-f0-9]{32}\Z")
TOKEN = re.compile(r"[A-Za-z0-9_-]{32}\Z")
SNAPSHOT = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\Z")
MAX_ID = 9007199254740991
OBJECT_NAMES = ("0.ndjson", "manifest.json")
PARKED = "synthetic-provider-journal-retired"
TABLE = "subscription_provider_jobs"
JOBS = (TABLE, "telegram_provider_jobs", "telegram_provider_batch_jobs")
ROW = """id,owner_id,name,source_url,token,generation,snapshot_id,manifest_sha256,node_count,last_error,
  EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id=id) AS lifecycle"""
JOB = """job_id,owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,
  expected_lifecycle_revision,state,result_code,attempts,lease_id,lease_until,expires_at"""
ATTEMPT = """snapshot_id,queue,job_id,job_attempt,subscription_id,owner_id,request_key,source_sha256,
  expected_generation,expected_lifecycle_revision,lease_until,bot_id,created_at,state,manifest_sha256,node_count,
  object_count,published_at"""


def check(value):
    require(value, ERROR)


def parse_inputs(event):
    values = event.get("inputs")
    check(isinstance(values, dict) and set(values) <= {"action", "cohort", "confirm"})
    action, cohort, confirm = (values.get(name, "") for name in ("action", "cohort", "confirm"))
    check(action in ("prepare", "capture", "retire") and isinstance(cohort, str) and COHORT.fullmatch(cohort))
    check(confirm == (f"{action} synthetic provider journal {cohort}" if action != "capture" else ""))
    return action, cohort


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def content(cohort, label):
    name = f"journal-{label}-{cohort}"
    share = f"ss://YWVzLTEyOC1nY206Zml4dHVyZQ@203.0.113.19:443#{name}"
    chunk = encoded({"name": name, "type": "ss", "share": share}) + b"\n"
    manifest = encoded({"version": 1, "chunks": [{"bytes": len(chunk), "sha256": digest(chunk), "count": 1}]})
    return share, {OBJECT_NAMES[0]: chunk, OBJECT_NAMES[1]: manifest}


def assert_statement(sql, *params):
    return _statement(_assert_sql(sql), *params)


class Fixture:
    def __init__(self, resources, cohort, guard, provider_guard, probe=probe_export):
        self.resources, self.guard, self.probe = resources, guard, probe
        self.provider_guard = provider_guard
        self.marker = f"synthetic:provider-journal:{cohort}"
        self.names = (self.marker + ":source", self.marker + ":target")
        self.requests = tuple(digest(f"{self.marker}/{label}".encode("ascii")) for label in ("live", "interrupted"))
        self.snapshots = tuple(str(UUID(digest(f"{self.marker}/{label}".encode("ascii"))[:32], version=4))
                               for label in ("source", "interrupted"))
        self.share, self.expected = content(cohort, "source")
        _, self.interrupted = content(cohort, "interrupted")

    def read(self, sql, *params):
        return self.resources.query(sql, params)

    def transact(self, *statements):
        self.guard()
        return _batch(self.resources, statements)

    def rows(self):
        where = "owner_id=? OR name IN (?,?)"
        rows = self.read(f"SELECT {ROW},0 AS trashed FROM subscriptions WHERE {where} "
                         f"UNION ALL SELECT {ROW},1 AS trashed FROM subscription_trash WHERE {where} LIMIT 3",
                         OWNER, *self.names, OWNER, *self.names)
        if not rows:
            return None
        by_name = {row.get("name"): row for row in rows}
        check(len(rows) == 2 and set(by_name) == set(self.names))
        source, target = (by_name[name] for name in self.names)
        for row in (source, target):
            check(row.get("owner_id") == OWNER and row.get("trashed") == row.get("lifecycle") == 0
                  and integer(row.get("id"), 1, MAX_ID) and isinstance(row.get("token"), str)
                  and TOKEN.fullmatch(row["token"]))
        check(source["id"] != target["id"] and source["token"] != target["token"]
              and source["source_url"] == target["source_url"] == f"{ORIGIN}/sub/{source['token']}/base64")
        return source, target

    def quiet(self):
        for table in JOBS:
            check(self.read(f"SELECT NOT EXISTS(SELECT 1 FROM {table} WHERE state IN ('waiting','pending','leased')) AS quiet")
                  == [{"quiet": 1}])

    def keys(self, subscription, snapshot, expected, *, allow_missing=False):
        check(integer(subscription, 1, MAX_ID) and isinstance(snapshot, str) and SNAPSHOT.fullmatch(snapshot))
        prefix = f"subscriptions/{subscription}/{snapshot}/"
        listed = self.resources.api("GET", self.resources.bucket + "/objects?" + urlencode({"prefix": prefix, "per_page": 3}))
        check(isinstance(listed, list) and len(listed) <= len(expected))
        found = set()
        for obj in listed:
            key = obj.get("key")
            check(isinstance(key, str) and key.startswith(prefix) and key not in found)
            body = expected.get(key[len(prefix):])
            check(body is not None and obj.get("size") == len(body) and self.resources.objects.request("GET", key) == body)
            found.add(key)
        for name, body in expected.items():
            key = prefix + name
            check(self.resources.objects.request("GET", key) == (body if key in found else None))
        for name in set(OBJECT_NAMES) - set(expected):
            check(self.resources.objects.request("GET", prefix + name) is None)
        check(allow_missing or len(found) == len(expected))
        return found

    def put(self, subscription, snapshot, name, body):
        key = f"subscriptions/{subscription}/{snapshot}/{name}"
        self.guard()
        check(self.resources.objects.request("GET", key) is None)
        # An unknown PUT never authorizes a second PUT. Exact readback can adopt it.
        unacknowledged = False
        try:
            self.resources.objects.request("PUT", key, body)
        except Exception:
            unacknowledged = True
        check(recheck_absent(self.resources.objects.request("GET", key),
                             lambda: self.resources.objects.request("GET", key)) == body)
        return int(unacknowledged)

    def prepare(self):
        check(self.rows() is None)
        self.quiet()
        token, target_token = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        url = f"{ORIGIN}/sub/{token}/base64"
        self.transact(
            assert_statement("NOT EXISTS(SELECT 1 FROM subscriptions WHERE owner_id=? OR name IN (?,?) OR token IN (?,?)) "
                             "AND NOT EXISTS(SELECT 1 FROM subscription_trash WHERE owner_id=? OR name IN (?,?) OR token IN (?,?)) "
                             "AND NOT EXISTS(SELECT 1 FROM subscription_provider_jobs WHERE owner_id=? OR request_key IN (?,?)) "
                             "AND NOT EXISTS(SELECT 1 FROM provider_snapshot_attempts WHERE owner_id=? OR snapshot_id IN (?,?))",
                             OWNER, *self.names, token, target_token, OWNER, *self.names, token, target_token,
                             OWNER, *self.requests, OWNER, *self.snapshots),
            _statement("""INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
              VALUES(?,?,?,?,unixepoch(),unixepoch()),(?,?,?,?,unixepoch(),unixepoch())""",
                       OWNER, self.names[0], url, token, OWNER, self.names[1], url, target_token),
        )
        source, target = self.rows()
        check((source["token"], target["token"]) == (token, target_token))
        source_id, interruption = self.snapshots
        self.keys(source["id"], source_id, {}, allow_missing=True)
        self.keys(source["id"], interruption, {}, allow_missing=True)
        unacknowledged = sum(self.put(source["id"], source_id, name, body) for name, body in self.expected.items())
        self.keys(source["id"], source_id, self.expected)
        self.transact(
            assert_statement("EXISTS(SELECT 1 FROM subscriptions WHERE id=? AND owner_id=? AND token=? AND generation=0)",
                             source["id"], OWNER, token),
            _statement("""UPDATE subscriptions SET generation=1,snapshot_id=?,manifest_sha256=?,node_count=1
              WHERE id=? AND owner_id=? AND token=? AND generation=0""",
                       source_id, digest(self.expected["manifest.json"]), source["id"], OWNER, token),
            assert_statement("changes()=1"),
            # Historical synthetic terminal job. It never holds or claims a real queue lease.
            _statement(f"""INSERT INTO {TABLE}(owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,
              expected_lifecycle_revision,state,created_at,due_at,expires_at,attempts,result_code,finished_at)
              VALUES(?,?,'refresh',?,?,1,0,'done',unixepoch()-121,unixepoch()-121,unixepoch()-1,1,'expired',unixepoch()-1)""",
                       OWNER, self.requests[1], source["id"], digest(url.encode("ascii"))),
            _statement(f"""INSERT INTO provider_snapshot_attempts ({ATTEMPT})
              SELECT ?,?,job_id,attempts,subscription_id,owner_id,request_key,source_sha256,expected_generation,
              expected_lifecycle_revision,expires_at,'',created_at,'open',NULL,NULL,NULL,NULL
              FROM {TABLE} WHERE owner_id=? AND request_key=? AND changes()=1""", interruption, TABLE, OWNER, self.requests[1]),
            assert_statement("changes()=1"),
            _statement("""INSERT INTO provider_snapshot_object_intents(snapshot_id,ordinal,byte_count,sha256)
              VALUES(?,0,?,?),(?,256,?,?)""", interruption, len(self.interrupted["0.ndjson"]), digest(self.interrupted["0.ndjson"]),
                       interruption, len(self.interrupted["manifest.json"]), digest(self.interrupted["manifest.json"])),
        )
        unacknowledged += self.put(source["id"], interruption, "0.ndjson", self.interrupted["0.ndjson"])
        self.keys(source["id"], interruption, {"0.ndjson": self.interrupted["0.ndjson"]})
        self.probe(token, [self.share])
        self.quiet()
        self.provider_guard()
        self.transact(
            assert_statement(" AND ".join(
                f"NOT EXISTS(SELECT 1 FROM {table} WHERE state IN ('waiting','pending','leased'))" for table in JOBS) + " AND "
                             "EXISTS(SELECT 1 FROM subscriptions WHERE id=? AND owner_id=? AND token=? AND generation=0)",
                             target["id"], OWNER, target_token),
            _statement(f"""INSERT INTO {TABLE}(owner_id,request_key,kind,subscription_id,source_sha256,expected_generation,
              expected_lifecycle_revision,state,created_at,due_at,expires_at)
              VALUES(?,?,'url-import',?,?,0,0,'pending',unixepoch(),unixepoch(),unixepoch()+600)""",
                       OWNER, self.requests[0], target["id"], digest(target["source_url"].encode("ascii"))),
        )
        return {"queuedLiveJobs": 1, "stagedExpiredAttempts": 1, "operatorPutAcknowledgementsLostAndVerified": unacknowledged}

    def graph(self, source, target):
        jobs = self.read(f"""SELECT {JOB} FROM {TABLE} WHERE owner_id=? OR request_key IN (?,?)
          OR subscription_id IN (?,?) LIMIT 3""", OWNER, *self.requests, source["id"], target["id"])
        by_request = {row.get("request_key"): row for row in jobs}
        check(len(jobs) == 2 and set(by_request) == set(self.requests))
        live, interrupted = (by_request[key] for key in self.requests)
        for job, row, kind, generation, result in ((live, target, "url-import", 0, "saved"),
                                                    (interrupted, source, "refresh", 1, "expired")):
            check(integer(job.get("job_id"), 1, MAX_ID) and
                  tuple(job[key] for key in ("owner_id", "kind", "subscription_id", "source_sha256", "expected_generation",
                                            "expected_lifecycle_revision", "state", "result_code", "attempts", "lease_id", "lease_until"))
                  == (OWNER, kind, row["id"], digest(row["source_url"].encode("ascii")), generation, 0, "done", result, 1, None, None))
        attempts = self.read(f"""SELECT {ATTEMPT} FROM provider_snapshot_attempts WHERE owner_id=?
          OR snapshot_id IN (?,?) OR subscription_id IN (?,?) OR (queue=? AND job_id IN (?,?)) LIMIT 3""",
                             OWNER, *self.snapshots, source["id"], target["id"], TABLE, live["job_id"], interrupted["job_id"])
        by_request = {row.get("request_key"): row for row in attempts}
        check(len(attempts) == 2 and set(by_request) == set(self.requests))
        published, opened = (by_request[key] for key in self.requests)
        for attempt, job in ((published, live), (opened, interrupted)):
            check(tuple(attempt[key] for key in ("queue", "job_attempt", "bot_id")) == (TABLE, 1, "")
                  and all(attempt[key] == job[key] for key in ("job_id", "subscription_id", "owner_id", "request_key",
                            "source_sha256", "expected_generation", "expected_lifecycle_revision")))
        check(isinstance(published.get("snapshot_id"), str) and SNAPSHOT.fullmatch(published["snapshot_id"])
              and published["snapshot_id"] not in self.snapshots
              and (published["state"], published["manifest_sha256"], published["node_count"], published["object_count"])
              == ("published", digest(self.expected["manifest.json"]), 1, 2)
              and integer(published["published_at"], published["created_at"], published["lease_until"]))
        check((opened["snapshot_id"], opened["state"], opened["manifest_sha256"], opened["node_count"],
               opened["object_count"], opened["published_at"], opened["lease_until"])
              == (self.snapshots[1], "open", None, None, None, None, interrupted["expires_at"])
              and self.read("SELECT CAST(? AS INTEGER) < unixepoch() AS expired", opened["lease_until"]) == [{"expired": 1}])
        intents = self.read("""SELECT snapshot_id,ordinal,byte_count,sha256 FROM provider_snapshot_object_intents
          WHERE snapshot_id IN (?,?) ORDER BY ordinal LIMIT 3""", published["snapshot_id"], opened["snapshot_id"])
        check(intents == [{"snapshot_id": opened["snapshot_id"], "ordinal": ordinal,
                           "byte_count": len(body), "sha256": digest(body)}
                          for ordinal, body in zip((0, 256), self.interrupted.values(), strict=True)])
        return live, interrupted, published, opened

    def closure(self, rows, published, *, parked=False):
        source, target = rows
        specs = ((source, self.snapshots[0], self.expected), (target, published["snapshot_id"], self.expected),
                 (source, self.snapshots[1], {"0.ndjson": self.interrupted["0.ndjson"]}))
        for row, snapshot, bodies in specs[:2]:
            expected = (0, None, None, 0, PARKED) if parked else (1, snapshot, digest(bodies["manifest.json"]), 1, None)
            check(tuple(row[key] for key in ("generation", "snapshot_id", "manifest_sha256", "node_count", "last_error")) == expected)
        return set().union(*(self.keys(row["id"], snapshot, bodies, allow_missing=parked) for row, snapshot, bodies in specs))

    def capture(self):
        rows = self.rows()
        check(rows is not None)
        _, _, published, _ = self.graph(*rows)
        keys = self.closure(rows, published)
        for row in rows:
            self.probe(row["token"], [self.share])
        check(self.rows() == rows)
        return {"liveSaved": 1, "publishedMarkers": 1, "publishedIntents": 0, "publishedObjects": 2,
                "stagedInterruption": 1, "stagedIntents": 2, "stagedObjects": 1,
                "untouchedSourceGeneration": 1, "verifiedObjects": len(keys),
                "base64Sha256": digest(b64encode(self.share.encode("ascii"))),
                "runtimeUnknownResponse": "not-observed"}

    def retirement_guard(self, rows, jobs, published, opened):
        row_clause = """EXISTS(SELECT 1 FROM subscriptions WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=?
            AND generation=? AND COALESCE(snapshot_id,'')=? AND COALESCE(manifest_sha256,'')=? AND node_count=?
            AND COALESCE(last_error,'')=? AND NOT EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id=id))"""
        row_values = [row[key] if row[key] is not None else "" for row in rows
                      for key in ("id", "owner_id", "name", "source_url", "token", "generation",
                                  "snapshot_id", "manifest_sha256", "node_count", "last_error")]
        return assert_statement(f"{row_clause} AND {row_clause} "
            "AND (SELECT count(*) FROM subscriptions WHERE owner_id=?)=2 "
            "AND NOT EXISTS(SELECT 1 FROM subscription_trash WHERE owner_id=? OR id IN (?,?) OR token IN (?,?)) "
            f"AND (SELECT count(*) FROM {TABLE} WHERE owner_id=? AND state='done' AND job_id IN (?,?))=2 "
            f"AND NOT EXISTS(SELECT 1 FROM {TABLE} WHERE (owner_id=? OR subscription_id IN (?,?)) AND job_id NOT IN (?,?)) "
            "AND NOT EXISTS(SELECT 1 FROM telegram_provider_jobs WHERE owner_id=? OR subscription_id IN (?,?)) "
            "AND NOT EXISTS(SELECT 1 FROM telegram_provider_batch_jobs WHERE owner_id=? OR subscription_id IN (?,?)) "
            "AND (SELECT count(*) FROM provider_snapshot_attempts WHERE owner_id=? AND queue=? AND snapshot_id IN (?,?))=2 "
            "AND NOT EXISTS(SELECT 1 FROM provider_snapshot_attempts WHERE (owner_id=? OR subscription_id IN (?,?)) "
            "AND snapshot_id NOT IN (?,?))",
            *row_values, OWNER, OWNER, *(row["id"] for row in rows), *(row["token"] for row in rows),
            OWNER, *(job["job_id"] for job in jobs), OWNER, *(row["id"] for row in rows), *(job["job_id"] for job in jobs),
            OWNER, *(row["id"] for row in rows), OWNER, *(row["id"] for row in rows),
            OWNER, TABLE, published["snapshot_id"], opened["snapshot_id"],
            OWNER, *(row["id"] for row in rows), published["snapshot_id"], opened["snapshot_id"])

    def retire(self, request):
        rows = self.rows()
        if rows is None:
            check(self.read(f"""SELECT NOT EXISTS(SELECT 1 FROM {TABLE} WHERE owner_id=? OR request_key IN (?,?))
                AND NOT EXISTS(SELECT 1 FROM provider_snapshot_attempts WHERE owner_id=? OR snapshot_id IN (?,?)) AS empty""",
                OWNER, *self.requests, OWNER, *self.snapshots) == [{"empty": 1}])
            return {"retiredSubscriptions": 0}
        live, interrupted, published, opened = self.graph(*rows)
        jobs = (live, interrupted)
        parked = all(row["last_error"] == PARKED for row in rows)
        self.closure(rows, published, parked=parked)
        if not parked:
            self.transact(self.retirement_guard(rows, jobs, published, opened),
                _statement("""UPDATE subscriptions SET generation=0,snapshot_id=NULL,manifest_sha256=NULL,node_count=0,last_error=?
                  WHERE owner_id=? AND id IN (?,?)""", PARKED, OWNER, *(row["id"] for row in rows)),
                assert_statement("changes()=2"))
            rows = self.rows()
            check(rows is not None and all(row["last_error"] == PARKED for row in rows))
        keys = self.closure(rows, published, parked=True)
        for row in rows:
            for method in ("GET", "HEAD"):
                check(request(row["token"], method)[0] == 404)
        for key in sorted(keys):
            self.guard()
            try:
                self.resources.objects.request("DELETE", key)
            except Exception:
                pass
            check(self.resources.objects.request("GET", key) is None)
        check(not self.closure(rows, published, parked=True))
        self.transact(self.retirement_guard(rows, jobs, published, opened),
            _statement("DELETE FROM provider_snapshot_object_intents WHERE snapshot_id=?", opened["snapshot_id"]),
            assert_statement("changes()=2"),
            _statement("DELETE FROM provider_snapshot_attempts WHERE owner_id=? AND queue=? AND snapshot_id IN (?,?)",
                       OWNER, TABLE, published["snapshot_id"], opened["snapshot_id"]),
            assert_statement("changes()=2"),
            _statement(f"DELETE FROM {TABLE} WHERE owner_id=? AND state='done' AND job_id IN (?,?)",
                       OWNER, live["job_id"], interrupted["job_id"]),
            assert_statement("changes()=2"),
            _statement("DELETE FROM subscriptions WHERE owner_id=? AND id IN (?,?) AND last_error=?",
                       OWNER, *(row["id"] for row in rows), PARKED),
            assert_statement("changes()=2"))
        check(self.rows() is None)
        for row in rows:
            for method in ("GET", "HEAD"):
                check(request(row["token"], method)[0] == 404)
        return {"retiredSubscriptions": 2}


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    check(REVISION.fullmatch(revision) and (os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_REF"),
          os.environ.get("GITHUB_EVENT_NAME"), os.environ.get("GITHUB_RUN_ATTEMPT"))
          == (REPOSITORY, MAIN_REF, "workflow_dispatch", "1"))
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as stream:
        event = stream.read(65537)
    check(len(event) <= 65536)
    action, cohort = parse_inputs(_parse_object(event, ERROR))
    require_current_main(revision)
    target = _parse_object(os.environ["SUBS_BOT_CF_ISOLATION_TARGET_JSON"], ERROR)
    data_token, deploy_token = (os.environ.get(key, "") for key in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    check(data_token and deploy_token and data_token != deploy_token)
    data = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), data, target)
    scope.verify_resources()
    active, config = scope.active(), scope.worker_config()
    version = scope.version(active.version)
    provider = load_provider_gate(os.environ[CONFIG_ENV], target, deploy_token)
    check(version.revision == revision and provider is not None and version.provider_binding == provider.binding and scope.cron_enabled())
    provider.verify()
    _verify_health(revision)
    resources = Resources(target, data, R2Objects(target["accountId"], data_token))
    migration = Path(__file__).resolve().parents[1] / "migrations" / MIGRATION
    check(resources.query("SELECT name,sha256,mode FROM subs_bot_schema_migrations WHERE position=33", ())
          == [{"name": MIGRATION, "sha256": digest(migration.read_bytes()), "mode": "applied"}])

    def guard():
        require_current_main(revision)
        check(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version)

    fixture = Fixture(resources, cohort, guard, provider_guard=provider.verify)
    try:
        if action == "prepare":
            result = fixture.prepare()
        elif action == "capture":
            result = fixture.capture()
        else:
            opener = build_opener(ProxyHandler({}), _NoRedirect())
            result = fixture.retire(lambda token, method: request_export(opener, token, "base64", method))
    except Exception:
        raise RuntimeError(f"{ERROR} Phase {action}. Preserve unconfirmed fixture evidence.") from None
    provider.verify()
    scope.verify_resources()
    guard()
    _verify_health(revision)
    identity = digest(encoded([resources.scope_hash, active.id, asdict(provider.binding)]))
    print(json.dumps({"action": action, "revision": revision, "moduleSha256": version.digest,
                      "identitySha256": identity, **result}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except Exception as error:
        if type(error) is RuntimeError and str(error) in {
            f"{ERROR} Phase {action}. Preserve unconfirmed fixture evidence." for action in ("prepare", "capture", "retire")
        }:
            sys.exit(str(error))
        sys.exit(f"{ERROR} Verify the protected release and resource pins before retrying.")

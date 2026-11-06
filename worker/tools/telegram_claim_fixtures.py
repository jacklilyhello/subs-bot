"""Stage four fixed private claims for the isolated Telegram acceptance.

Only SHA-256 digests are accepted. The same cohort and map can reconcile an
interrupted seed or retirement without access to the original claim codes.
"""

from dataclasses import dataclass
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import UUID

from capacity_resources import recheck_absent
from cloudflare_isolation import (
    API_ORIGIN, DIGEST, REVISION, WORKER_NAME, CloudflareClient, CloudflareError, _Isolation, _NoRedirect, _verify_health,
)
from d1_migrations import _assert_sql
from prepare_isolation_artifact import ArtifactError, require_current_main
from release_isolation import telegram_release_config
from telegram_view_fixtures import FixtureError, query, rows, statement


CASES = ("targeted", "race", "expired", "document")
MIGRATIONS = ("0005_private_shares.sql", "0007_telegram_private_claims.sql")
MAX_DOCUMENT = 65_536
LIVE_SECONDS = 3600
MAX_ID = 9_007_199_254_740_991
SHARE_FIELDS = ("id", "bot_id", "code_sha256", "sender_id", "sender_name", "payload_id", "payload_sha256",
                "payload_bytes", "max_claims", "target_user_id", "expire_at", "created_at")
COHORT_MATCH = "(payload_id IN (?, ?, ?, ?) OR (bot_id = ? AND (code_sha256 IN (?, ?, ?, ?) OR substr(sender_name, 1, length(?)) = ?)))"
PRIOR_RECEIPT = ("SELECT 1 FROM telegram_private_claim AS claim JOIN telegram_inbox AS inbox USING (receipt_id) "
                 "WHERE inbox.bot_id = ? AND claim.code_sha256 IN (?, ?, ?, ?)")


def require(condition, message):
    if not condition:
        raise FixtureError(message)


@dataclass(frozen=True)
class Fixture:
    case: str
    digest: str
    payload_id: str
    name: str
    body: bytes
    body_digest: str
    target: str | None
    created_offset: int
    expire_offset: int

    @property
    def key(self):
        return f"private-shares/{self.payload_id}.txt"


def unique_json(pairs):
    values = dict(pairs)
    require(len(values) == len(pairs), "Duplicate fields in private claim fixture inputs.")
    return values


def plan(policy, cohort, digests):
    require(isinstance(cohort, str) and re.fullmatch(r"[a-z0-9]{16}", cohort),
            "A 16-character lowercase synthetic cohort key is required.")
    require(isinstance(digests, dict) and set(digests) == set(CASES)
            and all(isinstance(value, str) and DIGEST.fullmatch(value) for value in digests.values())
            and len(set(digests.values())) == len(CASES), "Four distinct SHA-256 fixture digests are required.")
    fixtures = {}
    for case in CASES:
        digest = digests[case]
        identity = bytearray(sha256(f"subs-bot-isolation-claim-v1/{cohort}/{case}/{digest}".encode("ascii")).digest()[:16])
        # The normal application writes random UUIDv4 keys. Reserve UUIDv8 for these fixtures.
        identity[6] = (identity[6] & 0x0f) | 0x80
        identity[8] = (identity[8] & 0x3f) | 0x80
        payload_id = str(UUID(bytes=bytes(identity)))
        body = f"Synthetic private claim fixture · {case}\n".encode("utf-8")
        if case == "document":
            body += b"x" * (MAX_DOCUMENT - len(body) - 1) + b"\n"
        target = {"targeted": policy["memberId"], "document": policy["adminId"]}.get(case)
        created, expiry = (-120, -60) if case == "expired" else (0, LIVE_SECONDS)
        fixtures[payload_id] = Fixture(case, digest, payload_id, f"CFC-{cohort}-{case}", body,
                                       sha256(body).hexdigest(), target, created, expiry)
    return fixtures


class ClaimObjects:
    def __init__(self, account, token, fixtures):
        self.prefix = f"{API_ORIGIN}/accounts/{account}/r2/buckets/{WORKER_NAME}/objects/"
        self.token = token
        self.expected = {fixture.key: fixture.body for fixture in fixtures.values()}
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def request(self, method, key, body=None):
        require(key in self.expected and ((method in {"GET", "DELETE"} and body is None)
                                          or (method == "PUT" and body == self.expected[key])),
                "Invalid scoped private claim object request.")
        headers = {"Authorization": "Bearer " + self.token, "cf-r2-jurisdiction": "default", "Accept-Encoding": "identity"}
        if method == "PUT":
            headers.update({"Content-Type": "application/octet-stream", "If-None-Match": "*"})
        request = Request(self.prefix + key, headers=headers, data=body, method=method)
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(MAX_DOCUMENT + 1)
        except HTTPError as error:
            error.close()
            if error.code == 404 and method in {"GET", "DELETE"}:
                return None
            raise CloudflareError(f"Private claim R2 {method} failed (HTTP {error.code}).") from None
        except (OSError, ValueError, HTTPException):
            raise CloudflareError(f"Private claim R2 {method} could not be confirmed.") from None
        require(len(raw) <= MAX_DOCUMENT, "Private claim R2 response exceeds its size limit.")
        if method == "GET":
            return raw
        if raw:
            try:
                result = json.loads(raw)
                require(isinstance(result, dict) and result.get("success") is True,
                        "Private claim R2 write could not be verified.")
            except (ValueError, RecursionError):
                raise FixtureError("Private claim R2 write could not be verified.") from None
        return None


def cohort_parameters(policy, cohort, fixtures):
    prefix = f"CFC-{cohort}-"
    return (*fixtures, policy["botId"], *(fixture.digest for fixture in fixtures.values()), prefix, prefix)


def share_identity(policy, fixture):
    return (policy["botId"], fixture.digest, policy["adminId"], fixture.name, fixture.payload_id,
            fixture.body_digest, len(fixture.body), 1, fixture.target)


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def read_cohort(api, path, policy, cohort, fixtures, *, seeding=False):
    result = rows(api, path, f"SELECT {', '.join(SHARE_FIELDS)}, unixepoch() AS now FROM private_shares "
                  f"WHERE {COHORT_MATCH} LIMIT 5", *cohort_parameters(policy, cohort, fixtures))
    require(len(result) <= len(fixtures), "Unexpected private claim fixture rows.")
    records = {}
    for row in result:
        fixture = fixtures.get(row.get("payload_id"))
        require(fixture is not None and fixture.payload_id not in records
                and tuple(row.get(field) for field in SHARE_FIELDS[1:-2]) == share_identity(policy, fixture)
                and integer(row.get("id"), 1, MAX_ID)
                and integer(row.get("now"), 1, MAX_ID)
                and integer(row.get("created_at"), 1, row["now"])
                and integer(row.get("expire_at"), row["created_at"], MAX_ID)
                and (fixture.case != "expired" or row["expire_at"] < row["now"])
                and row["expire_at"] - row["created_at"] == fixture.expire_offset - fixture.created_offset,
                "Private claim fixture ownership or row state differs.")
        if seeding and fixture.case != "expired":
            require(row["expire_at"] > row["now"], "The existing private claim cohort expired. Retire it before using a new cohort.")
        claims = rows(api, path, "SELECT actor_id, claimed_at FROM private_share_claims "
                      "WHERE share_id = CAST(? AS INTEGER) LIMIT 2", row["id"])
        require(len(claims) <= (0 if fixture.case == "expired" else 1)
                and all(claim.get("actor_id") in {policy["adminId"], policy["memberId"]}
                        and (fixture.target is None or claim["actor_id"] == fixture.target)
                        and integer(claim.get("claimed_at"), row["created_at"], min(row["expire_at"], row["now"]))
                        for claim in claims),
                "Private claim fixture contains an unexpected claim.")
        records[fixture.payload_id] = (row, claims)
    return records


def cohort_count(parameters, expected):
    return statement(_assert_sql(f"(SELECT count(*) FROM private_shares WHERE {COHORT_MATCH}) = CAST(? AS INTEGER)"),
                     *parameters, expected)


def seed_batch(policy, fixtures, parameters):
    records = []
    bindings = []
    for fixture in fixtures.values():
        records.append("(?, ?, ?, ?, ?, ?, CAST(? AS INTEGER), CAST(? AS INTEGER), NULLIF(?, ''), "
                       "unixepoch() + CAST(? AS INTEGER), unixepoch() + CAST(? AS INTEGER))")
        identity = share_identity(policy, fixture)
        bindings.extend((*identity[:-1], identity[-1] or "", fixture.expire_offset, fixture.created_offset))
    return [cohort_count(parameters, 0),
            statement(_assert_sql(f"NOT EXISTS ({PRIOR_RECEIPT})"), policy["botId"],
                      *(fixture.digest for fixture in fixtures.values())),
            statement(f"INSERT INTO private_shares ({', '.join(SHARE_FIELDS[1:])}) VALUES " + ", ".join(records), *bindings),
            cohort_count(parameters, len(fixtures))]


def retire_batch(parameters, records):
    batch = [cohort_count(parameters, len(records))]
    fields = ("id = CAST(? AS INTEGER) AND bot_id = ? AND code_sha256 = ? AND sender_id = ? AND sender_name = ? "
              "AND payload_id = ? AND payload_sha256 = ? AND payload_bytes = CAST(? AS INTEGER) "
              "AND max_claims = CAST(? AS INTEGER) AND target_user_id IS NULLIF(?, '') "
              "AND expire_at = CAST(? AS INTEGER) AND created_at = CAST(? AS INTEGER)")
    for row, claims in records.values():
        identity = tuple(row[field] if field != "target_user_id" else row[field] or "" for field in SHARE_FIELDS)
        batch.append(statement(_assert_sql(f"EXISTS (SELECT 1 FROM private_shares WHERE {fields})"), *identity))
        batch.append(statement(_assert_sql("(SELECT count(*) FROM private_share_claims "
                                          "WHERE share_id = CAST(? AS INTEGER)) = CAST(? AS INTEGER)"),
                               row["id"], len(claims)))
        for claim in claims:
            batch.append(statement("DELETE FROM private_share_claims WHERE share_id = CAST(? AS INTEGER) "
                                   "AND actor_id = ? AND claimed_at = CAST(? AS INTEGER)",
                                   row["id"], claim["actor_id"], claim["claimed_at"]))
        batch.append(statement(f"DELETE FROM private_shares WHERE {fields} "
                               "AND NOT EXISTS (SELECT 1 FROM private_share_claims WHERE share_id = private_shares.id)", *identity))
    batch.append(cohort_count(parameters, 0))
    return batch


def manage(api, path, objects, action, policy, cohort, fixtures, guard):
    require(action in {"seed", "retire"}, "Unknown private claim fixture action.")
    seeding = action == "seed"
    read = lambda: read_cohort(api, path, policy, cohort, fixtures, seeding=seeding)
    before = read()
    require(not seeding or not before or set(before) == set(fixtures),
            "Retire the partial private claim cohort before a new seed.")
    if seeding and not before:
        require(not rows(api, path, PRIOR_RECEIPT + " LIMIT 1", policy["botId"],
                         *(fixture.digest for fixture in fixtures.values())),
                "A private claim digest has a prior receipt. Use fresh synthetic codes for a new seed.")
    existing = {fixture.key: objects.request("GET", fixture.key) for fixture in fixtures.values()}
    require(all(existing[fixture.key] in {None, fixture.body} for fixture in fixtures.values()),
            "A private claim fixture object contains different bytes. No writes were made.")
    if seeding:
        require(not before or all(body is not None for body in existing.values()),
                "A published private claim fixture payload is missing. Retire the cohort.")
        for fixture in fixtures.values():
            if existing[fixture.key] is not None:
                continue
            guard()
            try:
                objects.request("PUT", fixture.key, fixture.body)
            except (CloudflareError, FixtureError):
                pass  # An interrupted upload may have committed the exact fixture.
            found = recheck_absent(objects.request("GET", fixture.key), lambda: objects.request("GET", fixture.key))
            require(found == fixture.body, "Private claim R2 upload could not be verified. Reconcile this cohort before reuse.")
    parameters = cohort_parameters(policy, cohort, fixtures)
    batch = (seed_batch(policy, fixtures, parameters) if seeding and not before else
             retire_batch(parameters, before) if not seeding and before else [])
    if batch:
        guard()
        try:
            query(api, path, {"batch": batch}, len(batch))
        except (CloudflareError, FixtureError):
            pass  # Reconcile against the exact D1 cohort after any ambiguous response.
    after = read()
    require(set(after) == (set(fixtures) if seeding else set()), "Private claim D1 cohort operation could not be verified.")
    if not seeding:
        for fixture in fixtures.values():
            found = objects.request("GET", fixture.key)
            if found is None:
                continue
            require(found == fixture.body, "A private claim payload changed and was preserved.")
            guard()
            try:
                objects.request("DELETE", fixture.key)
            except (CloudflareError, FixtureError):
                pass
    require(all(objects.request("GET", fixture.key) == (fixture.body if seeding else None) for fixture in fixtures.values()),
            "Private claim R2 final readback could not be verified.")
    guard()
    return {"activeShares": len(after), "retiredShares": len(before) if not seeding else 0,
            "retiredClaims": sum(len(claims) for _, claims in before.values()) if not seeding else 0,
            "verifiedObjectsPresent": len(fixtures) if seeding else 0,
            "verifiedObjectsAbsent": 0 if seeding else len(fixtures)}


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(REVISION.fullmatch(revision) and os.environ.get("GITHUB_REPOSITORY") == "jacklilyhello/subs-bot"
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_REF") == "refs/heads/main",
            "Private claim fixtures require the project's manually dispatched main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        raw_event = event.read(65_537)
    require(len(raw_event) <= 65_536, "Private claim fixture inputs exceed the allowed size.")
    inputs = json.loads(raw_event, object_pairs_hook=unique_json)["inputs"]
    require(isinstance(inputs, dict) and set(inputs) == {"action", "cohort", "digests"}
            and inputs["action"] in {"seed", "retire"} and isinstance(inputs["digests"], str)
            and len(inputs["digests"]) <= 1024, "Invalid private claim fixture inputs.")
    raw = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy = json.loads(raw)
    cohort = inputs["cohort"]
    fixtures = plan(policy, cohort, json.loads(inputs["digests"], object_pairs_hook=unique_json))
    target = json.loads(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "null"))
    require(isinstance(target, dict) and set(target) == {"accountId", "workerId", "workerCreatedOn", "d1Id",
                                                        "d1CreatedAt", "r2CreatedOn", "namespace"},
            "The reviewed isolation resource identities are required.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped Cloudflare credentials are required.")
    api = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), api, target)
    print("Verifying the isolated Worker, bindings and private resource ownership.", flush=True)
    require_current_main(revision)
    scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    require(scope.cron_enabled() and version.revision == revision and version.telegram_config_sha256 == sha256(raw.encode()).hexdigest(),
            "The active Worker and Telegram policy differ from the checked-out isolation release.")
    _verify_health(revision)
    path = f"{scope.account}/d1/database/{target['d1Id']}"
    print("Verifying the two private claim migration records.", flush=True)
    for name in MIGRATIONS:
        digest = sha256((Path(__file__).resolve().parents[1] / "migrations" / name).read_bytes()).hexdigest()
        require(rows(api, path, "SELECT position, sha256, mode FROM subs_bot_schema_migrations WHERE name = ?", name)
                == [{"position": int(name[:4]), "sha256": digest, "mode": "applied"}],
                "A private claim migration differs from the checked-out revision.")

    def guard():
        require_current_main(revision)
        require(scope.active() == active, "The isolation deployment changed during the private claim fixture operation.")

    print("Managing the exact synthetic D1 and private R2 cohort.", flush=True)
    objects = ClaimObjects(target["accountId"], data_token, fixtures)
    print(json.dumps(manage(api, path, objects, inputs["action"], policy, cohort, fixtures, guard), sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CloudflareError, FixtureError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated private claim fixture operation could not be verified.")

"""Read-only evidence for two real IAB normal short links in the owned isolation."""

from base64 import urlsafe_b64encode
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import sys
from time import monotonic

from capacity_probe import ProbeError, _check_headers, _request, _small_body
from capacity_resources import CapacityError, TARGET_KEYS, integer, matches, read_private, save_private_json
from cloudflare_isolation import CloudflareClient, CloudflareError, DIGEST, REVISION, WORKER_NAME, _Isolation, _verify_health
from native_restore_rehearsal import readonly_sql
from prepare_isolation_artifact import ArtifactError, MAIN_REF, REPOSITORY, VERIFIED_DIRECTORY, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import (
    COHORT, DECIMAL, MAX_ID, ORIGIN, ROLES, canonical, canonical_nonce, digest, key_bytes, read_checkpoint, require, validate_release_pin,
)
from telegram_view_fixtures import FixtureError, rows


WORKFLOW = "worker-isolation-telegram-short-links-smoke.yml"
ARTIFACT_PREFIX = "subs-bot-telegram-normal-short"
CHECKPOINT = "telegram-normal-short-checkpoint.json"
WORKER_PROVENANCE = "telegram-short-worker-artifact.json"
MIGRATION = "0019_telegram_short_links.sql"
CODE = re.compile(r"[A-Za-z0-9_-]{21}s")
MARKER = "short:v1"
HOSTS = {"admin": "example.com", "member": "example.org"}
PREVIOUS = {"issued": "prepare", "retired": "issued"}


def targets(cohort):
    require(matches(COHORT, cohort), "Normal short link challenge differs.")
    return {role: f"https://{host}/subs-bot-normal-short/{cohort}/{role}" for role, host in HOSTS.items()}


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"action", "cohort", "worker_ci_run_id", "source_run_id", "browser_hashes"},
            "Normal short link workflow inputs differ.")
    action, cohort, run = (inputs.get(field) for field in ("action", "cohort", "worker_ci_run_id"))
    source, raw = inputs.get("source_run_id", ""), inputs.get("browser_hashes", "")
    require(action in {"prepare", *PREVIOUS} and matches(COHORT, cohort) and matches(DECIMAL, run)
            and (source == "" if action == "prepare" else matches(DECIMAL, source))
            and (isinstance(raw, str) and 0 < len(raw) <= 256 if action == "retired" else raw == ""),
            "Normal short link action, challenge or previous run differs.")
    hashes = _parse_object(raw, "Normal short link browser evidence differs.") if raw else {}
    if action == "retired":
        require(set(hashes) == {"admin", "member", "foreignTarget"} and all(matches(DIGEST, value) for value in hashes.values()),
                "Normal short link browser evidence requires only the three exact digests.")
    return action, cohort, run, source, hashes


def proof(key, label, value):
    material = json.dumps(["subs-bot/normal-short-smoke/v1", label, value], ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, material.encode("ascii"), sha256).hexdigest()


def seal(key, checkpoint):
    return {**checkpoint, "proofSha256": proof(key, "checkpoint", checkpoint)}


def open_checkpoint(key, document, action, identity):
    require(isinstance(document, dict) and matches(DIGEST, document.get("proofSha256")), "Normal short link checkpoint differs.")
    body = {field: value for field, value in document.items() if field != "proofSha256"}
    require(hmac.compare_digest(document["proofSha256"], proof(key, "checkpoint", body))
            and type(body.get("version")) is int and body["version"] == 1 and body.get("phase") == PREVIOUS[action]
            and body.get("identity") == identity and integer(body.get("afterReceiptId"), 0, MAX_ID)
            and matches(DIGEST, body.get("authEpochSha256")), "Normal short link checkpoint scope, release or signature differs.")
    fields = {"version", "phase", "identity", "afterReceiptId", "authEpochSha256"}
    if action == "retired":
        for field in ("codeSha256", "issuedReceiptSha256", "linkIdentitySha256"):
            values = body.get(field)
            require(isinstance(values, dict) and set(values) == set(ROLES) and all(matches(DIGEST, value) for value in values.values()),
                    "Normal short link issued checkpoint evidence differs.")
            fields.add(field)
    require(set(body) == fields, "Normal short link checkpoint inventory differs.")
    return body


def derive_code(key, bot, actor, nonce):
    require(canonical_nonce(nonce), "Normal short link derivation nonce differs.")
    message = canonical(["subs-bot/telegram-short/external", 1, ORIGIN, bot, actor, nonce])
    raw = hmac.new(key, message.encode("utf-8"), sha256).digest()[:16]
    return urlsafe_b64encode(raw).decode("ascii")[:21] + "s"


def probe_code(code, destination, *, active):
    require(matches(CODE, code), "Normal short link code shape differs.")
    deadline = monotonic() + 40
    status = 302 if active else 404
    for method in ("GET", "HEAD"):
        # This shared transport opens one direct TLS request and has no redirect handling.
        with _request(method, f"/s/{code}", deadline, "normal short link") as response:
            if active:
                cache = {item.strip().lower() for item in response.getheader("Cache-Control", "").split(",")}
                require(response.status == status and response.getheader("Location") == destination
                        and cache == {"private", "no-store"} and response.getheader("Referrer-Policy") == "no-referrer"
                        and response.getheader("X-Content-Type-Options") == "nosniff" and response.getheader("Set-Cookie") is None
                        and response.getheader("Age") is None and response.getheader("CF-Cache-Status", "").upper() in {"", "DYNAMIC", "BYPASS"}
                        and response.getheader("Content-Encoding", "identity").lower() == "identity" and _small_body(response) == b"",
                        "Normal short link redirect, body or privacy headers differ.")
            else:
                _check_headers(response, status, "retired normal short link", "text/plain")
                require(_small_body(response) == (b"Not found." if method == "GET" else b""), "Normal short link denial body differs.")
    return {"GET": status, "HEAD": status}


class Cohort:
    def __init__(self, read, policy, cohort, key):
        self.read, self.bot, self.key = read, policy["botId"], key
        self.actors = {role: policy[field] for role, field in ROLES.items()}
        self.targets = targets(cohort)

    def auth(self):
        result = self.read("SELECT allowed,message_date,message_id FROM telegram_auth WHERE bot_id=? AND user_id=?",
                           self.bot, self.actors["member"])
        require(len(result) <= 1 and (not result or result[0]["allowed"] == 1 and all(
            integer(result[0][key], 1, MAX_ID) for key in ("message_date", "message_id"))), "Normal short link member grant differs.")
        return (result[0]["message_date"], result[0]["message_id"]) if result else (0, 0)

    def active(self):
        return self.read("SELECT code_sha256,owner_id,target_url FROM normal_short_links WHERE bot_id=? AND revoked_at IS NULL "
                         "AND owner_id IN (?,?) AND target_url IN (?,?) ORDER BY code_sha256 LIMIT 3",
                         self.bot, *self.actors.values(), *self.targets.values())

    def history(self, after):
        return self.read("""SELECT i.receipt_id,i.actor_id,i.chat_id,i.chat_type,i.thread_id,i.message_id,i.message_date,
          i.command,i.receipt_nonce,o.state,o.attempts,o.sent_message_id,a.result,a.code_sha256,a.auth_message_date,a.auth_message_id
          FROM telegram_inbox AS i LEFT JOIN telegram_short_link_actions AS a USING(receipt_id)
          LEFT JOIN telegram_outbox AS o USING(receipt_id)
          WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER)
            AND (i.receipt_nonce=? OR a.receipt_id IS NOT NULL)
          ORDER BY i.receipt_id LIMIT 6""", self.bot, *self.actors.values(), after, MARKER)

    def links(self, hashes, *, retired):
        target = "l.target_url IS NULL AND l.revoked_at IS NOT NULL" if retired else "l.target_url=? AND l.revoked_at IS NULL"
        where = f"(l.code_sha256=? AND l.owner_id=? AND {target})"
        parameters = []
        for role in ROLES:
            parameters.extend((hashes[role], self.actors[role]))
            if not retired:
                parameters.append(self.targets[role])
        return self.read(f"""SELECT l.code_sha256,l.code_length,l.owner_id,l.origin_receipt_id,l.nonce,l.key_version,
          l.target_url,l.created_at,l.revoked_at,EXISTS(SELECT 1 FROM aggregate_links AS a WHERE a.code_sha256=l.code_sha256) AS collision
          FROM normal_short_links AS l WHERE l.bot_id=? AND ({where} OR {where}) ORDER BY l.code_sha256 LIMIT 3""",
          self.bot, *parameters)

    def prepare(self, identity):
        require(not self.active(), "An active normal short link already uses an exact challenge target.")
        high = self.read("SELECT coalesce(max(receipt_id),0) AS highWater FROM telegram_inbox WHERE bot_id=?", self.bot)
        require(len(high) == 1 and integer(high[0].get("highWater"), 0, MAX_ID), "Normal short link receipt baseline differs.")
        return {"version": 1, "phase": "prepare", "identity": identity, "afterReceiptId": high[0]["highWater"],
                "authEpochSha256": proof(self.key, "auth", self.auth())}

    def inspect(self, checkpoint, *, retired):
        epoch = self.auth()
        require(proof(self.key, "auth", epoch) == checkpoint["authEpochSha256"], "Normal short link authorization epoch changed.")
        history = self.history(checkpoint["afterReceiptId"])
        require(len(history) == (5 if retired else 2), "Normal short link needs exactly two issues and, at retirement, three revocation actions.")
        by_actor = {actor: role for role, actor in self.actors.items()}
        grouped = {role: [] for role in ROLES}
        for row in history:
            role = by_actor.get(row.get("actor_id"))
            require(role is not None and row["chat_type"] == "private" and row["chat_id"] == row["actor_id"]
                    and row["thread_id"] is None and row["command"] == "help" and row["receipt_nonce"] == MARKER and row["state"] == "sent"
                    and integer(row["receipt_id"], checkpoint["afterReceiptId"] + 1, MAX_ID)
                    and integer(row["message_id"], 1, MAX_ID) and integer(row["sent_message_id"], 1, MAX_ID)
                    and integer(row["message_date"], 1, MAX_ID) and integer(row["attempts"], 1, 4),
                    "Normal short link receipt scope or delivery differs.")
            expected_epoch = (0, 0) if role == "admin" else epoch
            require((row["auth_message_date"], row["auth_message_id"]) == expected_epoch and row["message_date"] > expected_epoch[0],
                    "Normal short link receipt authorization differs.")
            grouped[role].append(row)
        expected = {"admin": ["issued", "missing", "revoked"], "member": ["issued", "revoked"]} if retired else {
            "admin": ["issued"], "member": ["issued"]}
        require(all([row["result"] for row in grouped[role]] == expected[role] for role in ROLES), "Normal short link action sequence differs.")
        issued = {role: grouped[role][0] for role in ROLES}
        hashes = {role: row["code_sha256"] for role, row in issued.items()}
        require(all(matches(DIGEST, value) for value in hashes.values()) and len(set(hashes.values())) == 2, "Normal short link code digests differ.")
        if retired:
            foreign = grouped["admin"][1]
            require(max(row["receipt_id"] for row in issued.values()) < foreign["receipt_id"]
                    < min(grouped[role][-1]["receipt_id"] for role in ROLES) and foreign["code_sha256"] is None
                    and all(grouped[role][-1]["code_sha256"] == hashes[role] for role in ROLES),
                    "Normal short link foreign attempt or owner revocations differ.")
        if retired:
            require(hashes == checkpoint["codeSha256"], "Normal short link issued digests changed before tombstone lookup.")
        candidates = self.active()
        expected_active = [{"code_sha256": hashes[role], "owner_id": self.actors[role], "target_url": self.targets[role]} for role in ROLES]
        require(candidates == ([] if retired else sorted(expected_active, key=lambda row: row["code_sha256"])), "Normal short link exact active target inventory differs.")
        # Read derivation metadata only after matching the synthetic targets or the signed issuance checkpoint.
        links = self.links(hashes, retired=retired)
        require(len(links) == 2 and {row["code_sha256"] for row in links} == set(hashes.values()), "Normal short link inventory differs.")
        by_hash = {row["code_sha256"]: row for row in links}
        identities, codes = {}, {}
        for role in ROLES:
            row = by_hash[hashes[role]]
            require((row["owner_id"], row["origin_receipt_id"], row["code_length"], row["key_version"], row["collision"])
                    == (self.actors[role], issued[role]["receipt_id"], 22, 1, 0)
                    and integer(row["created_at"], 1, MAX_ID), "Normal short link row identity differs.")
            require((row["target_url"] is None and integer(row["revoked_at"], row["created_at"], MAX_ID)) if retired else
                    (row["target_url"] == self.targets[role] and row["revoked_at"] is None), "Normal short link target or tombstone differs.")
            codes[role] = derive_code(self.key, self.bot, self.actors[role], row["nonce"])
            require(digest(codes[role].encode("ascii")) == hashes[role], "Normal short link derivation does not match D1.")
            identities[role] = proof(self.key, "link", {field: value for field, value in row.items() if field not in {"revoked_at", "target_url"}})
        evidence = {"codeSha256": hashes, "issuedReceiptSha256": {role: proof(self.key, "receipt", row) for role, row in issued.items()},
                    "linkIdentitySha256": identities}
        return evidence, codes, proof(self.key, "readback", [history, links, candidates, epoch])


def run_checkpoint(cohort, action, identity, prior, browser_hashes, probe=probe_code):
    if action == "prepare":
        checkpoint = cohort.prepare(identity)
        require(cohort.prepare(identity) == checkpoint, "Normal short link baseline changed during preparation.")
        return checkpoint, {"phase": action, "activeChallengeCount": 0}
    retired = action == "retired"
    evidence, codes, fingerprint = cohort.inspect(prior, retired=retired)
    hashes = evidence["codeSha256"]
    if retired:
        require(all(prior[field] == value for field, value in evidence.items()) and browser_hashes == {**hashes, "foreignTarget": hashes["member"]},
                "Normal short link issued or browser evidence differs.")
    http = {role: probe(codes[role], cohort.targets[role], active=not retired) for role in ROLES}
    require(cohort.inspect(prior, retired=retired)[2] == fingerprint, "Normal short link readback changed during HTTP verification.")
    checkpoint = {**prior, **evidence, "phase": action}
    report = {"phase": action, "codeSha256": hashes, "http": http, "sentIssueCount": 2, "activeChallengeCount": 0 if retired else 2}
    if retired:
        checkpoint["retirementReadbackSha256"] = fingerprint
        report.update(sentOwnRevokeCount=2, sentForeignMissingCount=1, retainedTombstoneCount=2)
    return checkpoint, report


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "Normal short link acceptance requires a trusted manual main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as file:
        raw = file.read(65537)
    require(len(raw) <= 65536, "Normal short link workflow event is oversized.")
    action, cohort_id, ci_run, source_run, hashes = parse_inputs(_parse_object(raw, "Normal short link workflow event differs."))
    require_current_main(revision)
    runner = Path(os.environ["RUNNER_TEMP"])
    provenance = _parse_object(read_private(runner / WORKER_PROVENANCE, 4096), "Normal short link Worker artifact provenance differs.")
    require(set(provenance) == {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}
            and (provenance["revision"], provenance["runId"]) == (revision, ci_run)
            and all(matches(DECIMAL, provenance[name]) for name in ("runId", "runAttempt", "artifactId"))
            and matches(DIGEST, provenance["archiveSha256"]), "Normal short link Worker artifact identity differs.")
    manifest = _parse_object(read_private(runner / VERIFIED_DIRECTORY / "isolation.json", 1_048_576), "Normal short link Worker manifest differs.")
    expected_migration = digest((Path(__file__).resolve().parents[1] / "migrations" / MIGRATION).read_bytes())
    require(manifest.get("version") == 2 and (manifest.get("revision"), manifest.get("runId"), manifest.get("runAttempt"))
            == (revision, ci_run, provenance["runAttempt"])
            and {"name": MIGRATION, "sha256": expected_migration} in manifest["migrations"], "Normal short link Worker artifact migration differs.")
    raw_policy = telegram_release_config(manifest)
    policy = json.loads(raw_policy)
    encoded = os.environ.get("SUBS_BOT_TELEGRAM_AGGREGATE_KEY", "")
    key = key_bytes(encoded)
    target = _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), "Normal short link ownership differs.")
    require(set(target) == TARGET_KEYS, "Normal short link ownership fields differ.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped readback credentials are required.")
    data, worker = CloudflareClient(data_token), CloudflareClient(deploy_token)
    root = f"/accounts/{target['accountId']}"
    db_path = root + f"/d1/database/{target['d1Id']}"
    bucket = root + f"/r2/buckets/{WORKER_NAME}"

    def read_data(method, path, payload=None):
        allowed = method == "GET" and path in {db_path, bucket, bucket + "/domains/managed", bucket + "/domains/custom"} and payload is None
        allowed = allowed or (method == "POST" and path == db_path + "/query" and isinstance(payload, dict)
            and set(payload) == {"sql", "params"} and readonly_sql(payload["sql"]) and payload["sql"].startswith("SELECT "))
        require(allowed, "Normal short link evidence only permits scoped resource reads.")
        return data(method, path, payload)

    def read_worker(method, path, payload=None):
        require(method == "GET" and payload is None, "Normal short link evidence only permits Worker reads.")
        return worker(method, path)

    scope = _Isolation(read_worker, read_data, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    release = {"revision": version.revision, "versionId": active.version, "moduleSha256": version.digest, "compatibilityDate": version.compatibility}
    validate_release_pin(release)
    policy_sha, key_sha = digest(raw_policy.encode("utf-8")), digest(encoded.encode("ascii"))
    require(scope.cron_enabled() and (version.revision, version.digest, version.compatibility) == (revision, manifest["bundleSha256"], manifest["compatibilityDate"])
            and version.telegram_config_sha256 == policy_sha and version.telegram_aggregate_key_sha256 == key_sha,
            "Normal short link active artifact, Telegram policy or key differs.")
    _verify_health(revision)
    read = lambda sql, *params: rows(read_data, db_path, sql, *params)
    require(read("SELECT position,sha256,mode FROM subs_bot_schema_migrations WHERE name=?", MIGRATION)
            == [{"position": 19, "sha256": expected_migration, "mode": "applied"}], "Normal short link migration proof differs.")
    identity = proof(key, "scope", [cohort_id, target, policy_sha, key_sha, release, active.id, provenance])
    prior = None
    if source_run:
        previous = read_checkpoint(source_run, revision, os.environ["GH_TOKEN"], workflow_file=WORKFLOW,
                                   artifact_prefix=ARTIFACT_PREFIX, checkpoint_file=CHECKPOINT)
        prior = open_checkpoint(key, previous, action, identity)
    checkpoint, report = run_checkpoint(Cohort(read, policy, cohort_id, key), action, identity, prior, hashes)
    require(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version
            and scope.cron_enabled(), "Normal short link release changed during verification.")
    scope.verify_resources()
    _verify_health(revision)
    require_current_main(revision)
    save_private_json(runner / CHECKPOINT, seal(key, checkpoint))
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CapacityError, CloudflareError, FixtureError, ProbeError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The normal short link checkpoint could not be verified safely.")

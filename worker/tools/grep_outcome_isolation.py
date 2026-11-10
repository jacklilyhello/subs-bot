"""Arm, inspect and redact one exact isolated Telegram Grep diagnostic cohort."""

from contextlib import closing
from datetime import datetime, timezone
from hashlib import md5, sha256
from http.client import HTTPSConnection, HTTPException
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from cloudflare_isolation import API_ORIGIN, DATE, DIGEST, HEX_ID, REVISION, UUID, WORKER_NAME, CloudflareClient, _Isolation, _verify_health
from native_restore_rehearsal import ACCOUNT_SHA256, signed_put_headers
from prepare_isolation_artifact import MAIN_REF, REPOSITORY, VERIFIED_DIRECTORY, _NoRedirect, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_view_fixtures import rows


PREFIX = "diagnostics/telegram-github-search/v1"
ARM = f"{PREFIX}/arm.json"
ROLES = ("admin", "member")
COHORT = re.compile(r"[0-9a-f]{32}")
ETAG = re.compile(r'"[0-9a-f]{32}"')
WEAK_ETAG = re.compile(r'W/"([0-9a-f]{32})"')
MAX_BYTES = 1024
MAX_LIST_BYTES = 8192
MAX_ID = 9007199254740991
WINDOW = 600
MIGRATION = "0027_telegram_github_search.sql"
OUTCOMES = ("found", "empty", "unavailable")
GREP_PHASES = ("not-started", "initialize", "initialize-response", "initialized", "initialized-response",
               "authorization", "authorization-denied", "tool", "tool-response", "tool-shape", "complete")
CLOCK = "SELECT unixepoch() AS now, COALESCE(MAX(receipt_id),0) AS highWater FROM telegram_inbox WHERE bot_id=? AND actor_id IN (?,?)"
LEDGER = "SELECT position,sha256,mode FROM subs_bot_schema_migrations WHERE name=?"
RECEIPT = """SELECT search.state AS settled, reply.state AS delivery
  FROM telegram_inbox AS inbox
  JOIN telegram_github_search AS search USING (receipt_id)
  JOIN telegram_outbox AS reply USING (receipt_id)
  WHERE inbox.receipt_id=? AND inbox.receipt_id>? AND inbox.bot_id=? AND inbox.actor_id=?
    AND inbox.chat_id=inbox.actor_id AND inbox.chat_type='private' AND inbox.thread_id IS NULL
    AND inbox.receipt_nonce='github-search:v1' AND inbox.command='help'
    AND search.bot_id=inbox.bot_id AND search.actor_id=inbox.actor_id
    AND inbox.received_at>=? AND inbox.received_at<? AND inbox.message_date>=? AND inbox.message_date<?"""


class ProofError(ValueError):
    pass


def require(condition, message="The scoped Grep diagnostic could not be verified."):
    if not condition:
        raise ProofError(message)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(raw):
    return sha256(raw).hexdigest()


def integer(value, low, high=MAX_ID):
    return type(value) is int and low <= value <= high


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def control_key(cohort):
    return f"{PREFIX}/{cohort}/control.json"


def result_key(cohort, role):
    return f"{PREFIX}/{cohort}/{role}.json"


def parsed(raw):
    return _parse_object(raw, "The scoped Grep record is invalid.")


class Objects:
    def __init__(self, target, token, token_id, cohort):
        require(matches(HEX_ID, target["accountId"]) and digest(target["accountId"].encode("ascii")) == ACCOUNT_SHA256
                and matches(HEX_ID, token_id) and matches(COHORT, cohort))
        self.base = f"{API_ORIGIN}/accounts/{target['accountId']}/r2/buckets/{WORKER_NAME}/objects/"
        self.host = f"{target['accountId']}.r2.cloudflarestorage.com"
        self.token, self.token_id, self.cohort = token, token_id, cohort
        self.keys = {ARM, control_key(cohort), *(result_key(cohort, role) for role in ROLES)}
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())
        self.headers = {"Authorization": f"Bearer {token}", "cf-r2-jurisdiction": "default",
                        "Accept-Encoding": "identity", "Cache-Control": "no-cache"}

    def get(self, key, *, prior_control=False):
        old = re.fullmatch(re.escape(PREFIX) + r"/[0-9a-f]{32}/control\.json", key)
        require(key in self.keys or prior_control and old is not None)
        try:
            with self.opener.open(Request(self.base + key, headers=self.headers), timeout=20) as response:
                raw = response.read(MAX_BYTES + 1)
                validators = response.headers.get_all("ETag", [])
                require(response.status == 200 and 0 < len(raw) <= MAX_BYTES and len(validators) == 1,
                        "The scoped Grep R2 download is missing exact content or its validator.")
        except HTTPError as error:
            error.close()
            if error.code == 404:
                return None
            raise ProofError("The scoped Grep R2 read was refused.") from None
        etag = validators[0]
        if matches(ETAG, etag):
            return raw, etag
        weak = WEAK_ETAG.fullmatch(etag)
        require(weak is not None, "The scoped Grep R2 validator is unsupported.")
        return raw, self.confirm_weak_validator(key, raw, weak[1])

    def confirm_weak_validator(self, key, raw, validator):
        # The REST gateway can wrap the stored tag as a weak HTTP validator. Use
        # only the exact stored ETag from object metadata for a conditional PUT.
        error = "The scoped Grep R2 stored ETag could not be confirmed."
        query = urlencode({"prefix": key, "per_page": 2})
        request = Request(self.base.removesuffix("/") + "?" + query, headers=self.headers)
        try:
            with self.opener.open(request, timeout=20) as response:
                body = response.read(MAX_LIST_BYTES + 1)
                require(response.status == 200 and 0 < len(body) <= MAX_LIST_BYTES, error)
        except HTTPError as refusal:
            refusal.close()
            raise ProofError(error) from None
        result = parsed(body)
        rows, info = result.get("result"), result.get("result_info", {})
        require(result.get("success") is True and result.get("errors") in (None, [])
                and isinstance(info, dict) and all(info.get(field) in (None, "") for field in ("cursor", "next_page_token"))
                and (info.get("is_truncated") is None or info["is_truncated"] is False)
                and isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), error)
        row = rows[0]
        require(row.get("key") == key and type(row.get("size")) is int and row["size"] == len(raw)
                and row.get("etag") == validator == md5(raw, usedforsecurity=False).hexdigest(), error)
        return f'"{validator}"'

    def write(self, key, body, previous):
        require(key in self.keys and isinstance(body, bytes) and 0 < len(body) <= MAX_BYTES
                and (previous is None or matches(ETAG, previous[1])))
        if key == control_key(self.cohort):
            require(previous is None, "The Grep reservation is immutable.")
        elif key != ARM:
            value = parsed(body)
            require(value.get("state") == "retired" and value.get("cohort") == self.cohort
                    and key == result_key(self.cohort, value.get("kind")))
        path = f"/{WORKER_NAME}/{key}"
        headers = signed_put_headers(self.host, path, self.token_id, self.token, body,
                                    {"custom": {}, "http": {"content-type": "application/json", "cache-control": "private, no-store"}},
                                    datetime.now(timezone.utc), if_match=None if previous is None else previous[1])
        try:
            with closing(HTTPSConnection(self.host, timeout=20)) as connection:
                connection.request("PUT", path, body=body, headers=headers)
                with closing(connection.getresponse()) as response:
                    response.read(4097)
        except (OSError, ValueError, HTTPException):
            # A timeout may follow a committed PUT. Only read back this exact key.
            pass
        actual = self.get(key)
        require(actual is not None and actual[0] == body,
                "The conditional Grep R2 write was not confirmed. Preserve the cohort and verify before resuming.")


def validate_arm(value, cohort, pin):
    require(set(value) == {"version", "revision", "policySha256", "cohort", "opensAt", "expiresAt"}
            and type(value["version"]) is int and value["version"] == 1
            and (value["cohort"], value["revision"], value["policySha256"]) == (cohort, pin["revision"], pin["policySha256"])
            and integer(value["opensAt"], 1, MAX_ID - WINDOW) and value["expiresAt"] == value["opensAt"] + WINDOW
            and integer(value["expiresAt"], 1))
    return value


def check_control(value, cohort, pin):
    fields = {"revision": REVISION, "versionId": UUID, "deploymentId": UUID, "moduleSha256": DIGEST,
              "compatibilityDate": DATE, "policySha256": DIGEST, "scopeSha256": DIGEST}
    require(set(pin) == set(fields) and all(matches(pattern, pin[key]) for key, pattern in fields.items()))
    require(set(value) == {"version", "arm", "release", "highWater"} and type(value["version"]) is int and value["version"] == 1
            and value["release"] == pin and integer(value["highWater"], 0) and isinstance(value["arm"], dict))
    validate_arm(value["arm"], cohort, pin)
    return value


def tombstone(cohort, kind, control, previous):
    return {"version": 1, "state": "retired", "cohort": cohort, "kind": kind, "controlSha256": digest(control),
            "previousSha256": digest(previous) if previous is not None else None}


def check_tombstone(value, cohort, kind, control):
    require(set(value) == {"version", "state", "cohort", "kind", "controlSha256", "previousSha256"}
            and type(value["version"]) is int and value["version"] == 1 and value["state"] == "retired"
            and (value["cohort"], value["kind"], value["controlSha256"]) == (cohort, kind, digest(control))
            and (value["previousSha256"] is None or matches(DIGEST, value["previousSha256"])))


def validate_report(raw, role, control):
    report = parsed(raw)
    fields = {"version", "cohort", "revision", "role", "receiptId", "remainingMs", "repositoryStatus", "repositoryState",
              "grep", "candidates", "codeTimedOut", "verifiedFiles", "visibility", "settled"}
    require(set(report) == fields and type(report["version"]) is int and report["version"] == 1
            and (report["cohort"], report["revision"], report["role"]) ==
                (control["arm"]["cohort"], control["arm"]["revision"], role)
            and integer(report["receiptId"], control["highWater"] + 1) and integer(report["remainingMs"], 1, 8000)
            and report["settled"] in OUTCOMES and report["repositoryState"] in OUTCOMES
            and type(report["codeTimedOut"]) is bool and integer(report["candidates"], 0, 2)
            and integer(report["verifiedFiles"], 0, report["candidates"]))

    def status(value):
        return value is None or integer(value, 100, 599)

    grep = report["grep"]
    visibility = report["visibility"]
    require(status(report["repositoryStatus"]) and isinstance(grep, dict)
            and set(grep) == {"phase", "initializeStatus", "initializedStatus", "toolStatus", "timedOut", "contentBlocks"}
            and grep["phase"] in GREP_PHASES and type(grep["timedOut"]) is bool and integer(grep["contentBlocks"], 0, 20)
            and all(status(grep[field]) for field in ("initializeStatus", "initializedStatus", "toolStatus"))
            and isinstance(visibility, list) and len(visibility) <= report["candidates"]
            and all(isinstance(check, dict) and set(check) == {"status", "outcome"} and status(check["status"])
                    and check["outcome"] in ("public", "unconfirmed", "deadline", "transport-or-body") for check in visibility))
    return report


def operate(objects, action, cohort, pin, now, high_water, receipt, guard):
    key = control_key(cohort)
    reservation, active = objects.get(key), objects.get(ARM)
    if action == "arm" and reservation is None:
        if active is not None:
            old = parsed(active[0])
            old_cohort = old.get("cohort")
            require(old.get("state") == "retired" and old.get("kind") == "arm"
                    and matches(COHORT, old_cohort) and old_cohort != cohort, "The diagnostic arm key is already occupied.")
            prior = objects.get(control_key(old_cohort), prior_control=True)
            require(prior is not None)
            old_control = parsed(prior[0])
            old_pin = old_control.get("release")
            require(isinstance(old_pin, dict) and old_pin.get("scopeSha256") == pin["scopeSha256"])
            check_control(old_control, old_cohort, old_pin)
            check_tombstone(old, old_cohort, "arm", prior[0])
            require(old["previousSha256"] == digest(canonical(old_control["arm"])), "The earlier arm retirement differs.")
        require(all(objects.get(result_key(cohort, role)) is None for role in ROLES), "The diagnostic cohort is already occupied.")
        arm = {"version": 1, "revision": pin["revision"], "policySha256": pin["policySha256"], "cohort": cohort,
               "opensAt": now, "expiresAt": now + WINDOW}
        reservation_body = canonical({"version": 1, "arm": arm, "release": pin, "highWater": high_water})
        guard()
        objects.write(key, reservation_body, None)
        guard()
        objects.write(ARM, canonical(arm), active)
        return {"phase": "armed", "cohort": cohort, "opensAt": now, "expiresAt": now + WINDOW}

    require(reservation is not None, "No verified Grep cohort reservation exists.")
    control = check_control(parsed(reservation[0]), cohort, pin)
    arm = control["arm"]
    arm_body = canonical(arm)
    require(active is not None, "The arm is unconfirmed. Do not repeat the write.")
    if action != "retire":
        require(active[0] == arm_body, "The exact live Grep arm differs.")
    if action == "arm":
        require(now < arm["expiresAt"], "The original arm has expired. Retire it before a fresh cohort.")
        return {"phase": "armed", "cohort": cohort, "opensAt": arm["opensAt"], "expiresAt": arm["expiresAt"]}

    if action == "inspect":
        reports = []
        for role in ROLES:
            result = objects.get(result_key(cohort, role))
            require(result is not None, "The two scoped Grep outcomes are not ready.")
            report = validate_report(result[0], role, control)
            require(receipt(report, control) == "sent", "The exact scoped Grep reply is not confirmed sent.")
            reports.append({key: value for key, value in report.items() if key != "receiptId"} | {"delivery": "sent"})
        return {"phase": "inspected", "cohort": cohort, "outcomes": reports}

    require(now >= arm["expiresAt"], "Wait for the scoped Grep arm to expire before retirement.")
    arm_retired = active[0] != arm_body
    if arm_retired:
        retired = parsed(active[0])
        check_tombstone(retired, cohort, "arm", reservation[0])
        require(retired["previousSha256"] == digest(arm_body))
    updates = []
    for role in ROLES:
        result = objects.get(result_key(cohort, role))
        if result is not None and parsed(result[0]).get("state") == "retired":
            check_tombstone(parsed(result[0]), cohort, role, reservation[0])
            continue
        require(not arm_retired, "A retired arm has an incomplete outcome retirement.")
        if result is not None:
            report = validate_report(result[0], role, control)
            require(receipt(report, control) in ("sent", "failed", "uncertain"), "Wait for the scoped Grep reply to settle.")
        updates.append((result_key(cohort, role), canonical(tombstone(cohort, role, reservation[0],
                                                                   result[0] if result else None)), result))
    if not arm_retired:
        updates.append((ARM, canonical(tombstone(cohort, "arm", reservation[0], arm_body)), active))
    for target, body, previous in updates:
        guard()
        objects.write(target, body, previous)
    return {"phase": "retired", "cohort": cohort, "retiredRoles": 2, "armRetired": True}


def run():
    revision, action = os.environ.get("GITHUB_SHA", ""), os.environ.get("SUBS_BOT_GREP_ACTION", "")
    cohort, confirm = os.environ.get("SUBS_BOT_GREP_COHORT", ""), os.environ.get("SUBS_BOT_GREP_CONFIRM", "")
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY and os.environ.get("GITHUB_REF") == MAIN_REF
            and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and matches(REVISION, revision) and matches(COHORT, cohort) and action in ("arm", "inspect", "retire")
            and confirm == ("" if action == "inspect" else f"{action} Grep diagnostic {cohort}"))
    directory = Path(os.environ["RUNNER_TEMP"]) / VERIFIED_DIRECTORY
    manifest = parsed((directory / "isolation.json").read_bytes())
    module = (directory / "index.js").read_bytes()
    require(manifest.get("revision") == revision and manifest.get("bundleSha256") == digest(module)
            and PREFIX.encode("ascii") in module)
    entries = [entry for entry in manifest["migrations"] if entry.get("name") == MIGRATION]
    require(len(entries) == 1 and matches(DIGEST, entries[0].get("sha256")))
    policy_raw = telegram_release_config(manifest)
    require(isinstance(policy_raw, str))
    policy = json.loads(policy_raw)
    policy_sha = digest(policy_raw.encode())
    target = parsed(os.environ["SUBS_BOT_CF_ISOLATION_TARGET_JSON"].encode())
    data_token, deploy_token = (os.environ[key] for key in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token != deploy_token and matches(HEX_ID, target.get("accountId"))
            and digest(target["accountId"].encode("ascii")) == ACCOUNT_SHA256)
    data, deploy = CloudflareClient(data_token), CloudflareClient(deploy_token)
    root = f"/accounts/{target['accountId']}"
    worker = f"{root}/workers/workers/{target['workerId']}"
    script = f"{root}/workers/scripts/{WORKER_NAME}"
    database, bucket = f"{root}/d1/database/{target['d1Id']}", f"{root}/r2/buckets/{WORKER_NAME}"
    worker_reads = {worker, script + "/settings", script + "/schedules", script + "/deployments", root + "/workers/subdomain",
                    f"{root}/workers/domains?service={WORKER_NAME}"}
    data_reads = {database, bucket, bucket + "/domains/managed", bucket + "/domains/custom", root + "/tokens/verify"}

    def read_worker(method, path, payload=None):
        version_path = re.fullmatch(re.escape(worker + "/versions/") + UUID.pattern + r"\?include=modules", path)
        require(method == "GET" and payload is None and (path in worker_reads or version_path))
        return deploy(method, path)

    def read_data(method, path, payload=None):
        read = method == "GET" and path in data_reads and payload is None
        select = (method == "POST" and path == database + "/query" and isinstance(payload, dict)
                  and set(payload) == {"sql", "params"} and payload["sql"] in (CLOCK, LEDGER, RECEIPT)
                  and isinstance(payload["params"], list)
                  and len(payload["params"]) == {CLOCK: 3, LEDGER: 1, RECEIPT: 8}[payload["sql"]]
                  and all(isinstance(value, str) and 0 < len(value) <= 64 for value in payload["params"]))
        require(read or select)
        return data(method, path, payload)

    scope = _Isolation(read_worker, read_data, target)

    def live_pin():
        require_current_main(revision)
        scope.worker_config()
        scope.verify_resources()
        active = scope.active()
        version = scope.version(active.version)
        require((version.revision, version.digest, version.compatibility, version.telegram_config_sha256) ==
                (revision, manifest["bundleSha256"], manifest["compatibilityDate"], policy_sha) and scope.cron_enabled(),
                "The exact isolated Grep deployment differs.")
        return {"revision": revision, "versionId": active.version, "deploymentId": active.id, "moduleSha256": version.digest,
                "compatibilityDate": version.compatibility, "policySha256": policy_sha, "scopeSha256": digest(canonical(target))}

    pin = live_pin()
    _verify_health(revision)
    require(rows(read_data, database, LEDGER, MIGRATION) == [{"position": 27, "sha256": entries[0]["sha256"], "mode": "applied"}])
    clock = rows(read_data, database, CLOCK, policy["botId"], policy["adminId"], policy["memberId"])
    require(len(clock) == 1 and integer(clock[0].get("now"), 1, MAX_ID - WINDOW) and integer(clock[0].get("highWater"), 0))
    token_id = read_data("GET", root + "/tokens/verify")
    require(isinstance(token_id, dict) and token_id.get("status") == "active" and matches(HEX_ID, token_id.get("id")))

    def receipt(report, control):
        arm = control["arm"]
        actor = policy[report["role"] + "Id"]
        result = rows(read_data, database, RECEIPT, report["receiptId"], control["highWater"], policy["botId"], actor,
                      arm["opensAt"], arm["expiresAt"], arm["opensAt"], arm["expiresAt"])
        require(len(result) == 1 and result[0].get("settled") == report["settled"], "The exact scoped Grep receipt differs.")
        return result[0].get("delivery")

    def guard():
        require(live_pin() == pin, "The active isolated Worker changed.")

    objects = Objects(target, data_token, token_id["id"], cohort)
    output = operate(objects, action, cohort, pin, clock[0]["now"], clock[0]["highWater"], receipt, guard)
    _verify_health(revision)
    guard()
    print(json.dumps({"revision": revision, **output}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except ProofError as error:
        raise SystemExit(str(error)) from None
    except Exception:
        raise SystemExit("The scoped Grep diagnostic could not be completed safely.") from None

"""Exercise the production lifecycle implementation on one registered rehearsal target.

Original isolation D1 is read only. Registration, intents, webhook recovery
snapshots and evidence are append-only in the existing project's private R2.
This script cannot select production and never prints credentials or payloads.
"""
from copy import deepcopy
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
from secrets import token_hex
import tempfile
from time import monotonic, sleep, time
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from cloudflare_isolation import ISOLATION_RELEASE_USER_AGENT
import d1_migrations as migrations
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact
import prepare_control_artifact
from production_control import API, Controller, NoRedirect, OperationError, StalePredecessorError, Telegram, general_config, hosted_environment, one, rows
from production_provision import Provisioner, ProvisionJournal
from production_storage import PrivateStore
from production_target import ACCOUNT, ZONE, FEATURES, NAMES, HEX, UUID, STAMP, ContractError, canonical, digest, matches, parsed, require, validate_target

WORKFLOW = "jacklilyhello/subs-bot/.github/workflows/worker-production-lifecycle-rehearsal.yml@refs/heads/main"
ORIGINAL_SERVICE = "subs-bot-cf-dev-01"
ORIGINAL_ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev"
SERVICE, BACKUP, HOSTNAME = NAMES["rehearsal"]
ORIGIN = "https://" + HOSTNAME
REPORT = "production-lifecycle-drill-result.json"
FINAL_REPORT = "production-lifecycle-drill-final.json"


def checked_http_result(value, source):
    require(isinstance(value, dict) and value.get("version") == 1
            and value.get("status") == "passed"
            and value.get("evidenceKind") == "hosted-production-restored-data-http-replay"
            and value.get("revision") == source["revision"] and value.get("moduleSha256") == source["moduleSha256"]
            and value.get("targetSha256") == source["targetSha256"] and value.get("restoredDataSha256") == source["dataSha256"]
            and value.get("migrationCount") == source["migrationCount"]
            and value.get("consumerBound") is False and value.get("realTelegramCredentialsSupplied") is False
            and value.get("syntheticProductionGateVerified") is True and value.get("outboundAttempts") == 0,
            "The restored HTTP replay does not match the exact sealed source and private target identity.")
    counts = value.get("counts")
    require(isinstance(counts, dict) and all(type(counts.get(key)) is int and counts[key] >= 1
            for key in ("storedShareExports", "trashDenials")),
            "Both restored HTTP runs require a positive stored-share export and a revoked-token denial.")
    return {**value, "status": "passed"}


def configuration(env):
    previous = parsed(env.get("SUBS_BOT_TELEGRAM_TEST_CONFIG", ""))
    require(set(previous) == {"botId", "botUsername", "botToken", "webhookSecret", "adminId", "memberId", "groupId"})
    require(previous["botUsername"] == "test_cfsubs_bot" and previous["adminId"] == "8813701954"
            and previous["memberId"] == "8653767757" and previous["groupId"] == "-5114255828",
            "Only the authorized two-account test Bot can enter this rehearsal.")
    require(matches(r"[A-Za-z0-9_-]{32,256}", previous["webhookSecret"]), "The original test webhook secret is invalid.")
    keys = parsed(env.get("SUBS_BOT_CONTROL_DRILL_KEYS", ""))
    require(set(keys) == {"aggregateKey", "privateShareKey", "webhookSecret"}
            and all(isinstance(value, str) for value in keys.values())
            and keys["webhookSecret"] != previous["webhookSecret"], "Independent rehearsal signing keys are required.")
    original = parsed(env.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""))
    require(set(original) == {"accountId", "workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "r2CreatedOn", "namespace"}
            and original["accountId"] == ACCOUNT and original["namespace"] == "lilyya"
            and matches(HEX, original["workerId"]) and matches(UUID, original["d1Id"])
            and all(matches(STAMP, original[key]) for key in ("workerCreatedOn", "d1CreatedAt", "r2CreatedOn")))
    value = {"schemaVersion": 1, "environment": "rehearsal", "accountId": ACCOUNT, "zoneId": ZONE,
        "namespace": "lilyya", "workerName": SERVICE, "workerId": None, "workerCreatedOn": None,
        "d1Name": SERVICE, "d1Id": None, "d1CreatedAt": None, "bucketName": SERVICE, "bucketCreatedAt": None,
        "backupBucketName": BACKUP, "backupBucketCreatedAt": None, "hostname": HOSTNAME,
        "botId": previous["botId"], "botUsername": previous["botUsername"], "generation": 1,
        "admins": [previous["adminId"]], "members": [previous["memberId"]], "groups": [],
        "defaultAccess": "deny", "features": {key: False for key in FEATURES}, "provider": None,
        "webhook": {"allowedUpdates": ["message", "callback_query"], "maxConnections": 1},
        "keyDigests": {"aggregate": sha256(keys["aggregateKey"].encode()).hexdigest(),
            "privateShare": sha256(keys["privateShareKey"].encode()).hexdigest(),
            "webhook": sha256(keys["webhookSecret"].encode()).hexdigest(), "shortlink": None}}
    draft = validate_target(value, draft=True)
    secrets = {**keys, "botToken": previous["botToken"], "shortlinkToken": None}
    general_config(draft, "a" * 40, secrets)
    return draft, secrets, previous, original


def approval(target, action, revision, predecessor):
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE,
            "Automatic approvals are restricted to the dedicated rehearsal target.")
    return {"schemaVersion": 1, "environment": "rehearsal", "targetSha256": target.digest,
        "configurationSha256": target.configuration_digest, "controlRevision": os.environ.get("GITHUB_SHA", revision),
        "revision": revision, "action": action, "stateSha256": predecessor,
        "authorization": "approve " + action + " for " + SERVICE}


def webhook_settings(info):
    require(isinstance(info, dict) and isinstance(info.get("url"), str)
            and info.get("has_custom_certificate") is False
            and type(info.get("max_connections")) is int and 1 <= info["max_connections"] <= 100
            and isinstance(info.get("allowed_updates", []), list))
    updates = info.get("allowed_updates", [])
    require(all(isinstance(value, str) for value in updates) and len(updates) == len(set(updates)))
    return {"url": info["url"], "has_custom_certificate": False,
            "max_connections": info["max_connections"], "allowed_updates": sorted(updates)}


PROBE_CASES = {"closed-admission", "wrong-secret", "durable-help", "duplicate-update", "payload-conflict",
    "member-admin-denial", "private-share", "paused-admission", "original-auth-before", "original-auth-after",
    "fixture-get", "fixture-head", "revoked-get", "revoked-head"}


class ProbeStatusError(OperationError):
    def __init__(self, case, status, expected):
        require(case in PROBE_CASES and type(status) is int and 100 <= status <= 599
                and expected and all(type(value) is int and 100 <= value <= 599 for value in expected))
        self.case, self.expected = case, tuple(expected)
        super().__init__("Public probe did not match (case=%s; HTTP=%d; expected=%s); no retry performed."
            % (case, status, ",".join(map(str, expected))), status=status)


def expect_status(status, expected, case):
    expected = (expected,) if type(expected) is int else tuple(expected)
    if type(status) is not int or not 100 <= status <= 599:
        raise OperationError("Public probe returned no valid numeric HTTP status; no retry performed.")
    if status not in expected:
        raise ProbeStatusError(case, status, expected)


def public_request(url, *, method="GET", data=None, secret=None):
    parts = urlsplit(url)
    origin = parts.scheme + "://" + parts.netloc
    require(origin in (ORIGIN, ORIGINAL_ORIGIN) and not parts.query and not parts.fragment)
    headers = {"User-Agent": ISOLATION_RELEASE_USER_AGENT, "Accept-Encoding": "identity", "Cache-Control": "no-cache"}
    if method == "POST":
        require(parts.path == "/telegram/webhook" and isinstance(data, bytes)
                and matches(r"[A-Za-z0-9_-]{1,256}", secret) and (origin != ORIGINAL_ORIGIN or data == b"{}"))
        headers.update({"Accept": "application/json", "Content-Type": "application/json",
            "X-Telegram-Bot-Api-Secret-Token": secret})
    else:
        require(method in ("GET", "HEAD") and origin == ORIGIN and data is None and secret is None
                and matches(r"/sub/[A-Za-z0-9_-]{1,128}/base64", parts.path))
        headers["Accept"] = "text/plain"
    return Request(url, data=data, method=method, headers=headers)


def public_readback(request, maximum, *, timeout=20):
    require(type(maximum) is int and 0 < maximum <= 64 * 1024)
    try:
        try:
            response = build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=timeout)
        except HTTPError as error:
            response = error
        with response:
            status = response.status
            require(type(status) is int and 100 <= status <= 599, "Public probe returned no valid numeric HTTP status.")
            body = response.read(maximum + 1)
            if len(body) > maximum:
                raise OperationError("Public probe exceeded its explicit capacity; no partial response is accepted.",
                    uncertain=request.get_method() == "POST", status=status)
            return status, body
    except (OSError, HTTPException):
        raise OperationError("Public probe response is unconfirmed; no retry performed.", uncertain=request.get_method() == "POST") from None


def safe_failure(error, phase):
    require(phase in ("configure-webhook", "closed-admission", "activation", "synthetic-verification", "human-window",
        "pause-and-freeze", "cleanup-pause", "cleanup-webhook", "cleanup-freeze"))
    kind = "http-status" if isinstance(error, ProbeStatusError) else "stale-predecessor" if isinstance(error, StalePredecessorError) \
        else "operation" if isinstance(error, OperationError) else "contract" if isinstance(error, ContractError) else "unexpected"
    result = {"phase": phase, "kind": kind, "uncertain": bool(getattr(error, "uncertain", kind == "unexpected"))}
    status = getattr(error, "http_status", None)
    if type(status) is int and 100 <= status <= 599:
        result["httpStatus"] = status
    if isinstance(error, ProbeStatusError):
        result.update(probe=error.case, expectedStatuses=list(error.expected))
    return result


def post_update(update, secret):
    request = public_request(ORIGIN + "/telegram/webhook", data=canonical(update), method="POST", secret=secret)
    return public_readback(request, 4096, timeout=45)[0]


def probe_original_webhook(secret):
    """An empty object has no update_id and cannot become a business receipt.
    The original handler authenticates first: 400 proves the secret, 401 rejects
    it. No genuine Telegram update or original-database write is submitted.
    """
    request = public_request(ORIGINAL_ORIGIN + "/telegram/webhook", data=b"{}", method="POST", secret=secret)
    return public_readback(request, 4096)[0]


def update_payload(update_id, actor, message_id, text, date):
    require(actor in ("8813701954", "8653767757") and type(message_id) is int and 0 < message_id < 2**31)
    require(type(update_id) is int and 7_000_000_000_000_000 <= update_id < 8_000_000_000_000_000)
    return {"update_id": update_id, "message": {"message_id": message_id, "date": date,
        "text": text, "from": {"id": int(actor), "is_bot": False, "first_name": "Lifecycle rehearsal fixture"},
        "chat": {"id": int(actor), "type": "private"},
        "entities": [{"type": "bot_command", "offset": 0, "length": len(text.split(None, 1)[0])}]}}


class Drill:
    def __init__(self, env):
        self.env = env
        self.draft, self.secrets, self.previous, self.original = configuration(env)
        data_token, worker_token = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), env.get("SUBS_BOT_CF_DEPLOY_TOKEN", "")
        require(data_token != worker_token, "Separate existing data and deployment credentials are required.")
        anchor_target = {**self.draft.data, "d1Id": self.original["d1Id"], "d1Name": ORIGINAL_SERVICE,
            "backupBucketName": ORIGINAL_SERVICE, "backupBucketCreatedAt": self.original["r2CreatedOn"]}
        self.anchor_api = API(anchor_target, data_token)
        self.store = PrivateStore(self.anchor_api, ORIGINAL_SERVICE)
        self.prefix = "maintenance/production-control/evidence/lifecycle-" + self.draft.digest + "/"
        self.registration_key = self.prefix + "registration.json"
        self.run = env.get("GITHUB_RUN_ID", "")
        self.attempt = env.get("GITHUB_RUN_ATTEMPT", "")
        require(matches(r"[1-9][0-9]{0,19}", self.run) and matches(r"[1-9][0-9]{0,5}", self.attempt))
        self.revision = env.get("GITHUB_SHA", "")
        window = env.get("DRILL_HUMAN_WINDOW_SECONDS") or "0"
        require(matches(r"0|[1-9][0-9]{0,2}", window) and int(window) <= 180,
                "The explicit human observation window must be between zero and 180 seconds.")
        self.human_window = int(window)
        self.baseline_checkpoint = env.get("DRILL_BASELINE_CHECKPOINT_ID", "")
        self.baseline_manifest_sha = env.get("DRILL_BASELINE_MANIFEST_SHA256", "")
        require(bool(self.baseline_checkpoint) == bool(self.baseline_manifest_sha)
                and (not self.baseline_checkpoint or (matches(r"[0-9a-f]{32}", self.baseline_checkpoint)
                    and matches(r"[0-9a-f]{64}", self.baseline_manifest_sha))),
                "Explicit reused baseline pins must be paired and well formed.")
        self.guard = lambda: artifact.require_current_main(self.revision)
        self.controller = None
        self.transition_sequence = 0
        self.proof = None
        self.report = {"schemaVersion": 1, "environment": "rehearsal", "productionMutated": False,
            "controlRevision": self.revision, "runId": self.run, "runAttempt": self.attempt,
            "humanAcceptance": False, "originalBusinessMutationRequests": 0, "stages": []}

    def save(self, stage, value):
        require(matches(r"[a-z][a-z0-9-]{0,50}", stage))
        key = self.prefix + self.run + "-" + self.attempt + "-" + stage + ".json"
        body = canonical(value)
        self.store.put(key, body)
        self.report["stages"].append({"stage": stage, "sha256": sha256(body).hexdigest()})
        return key

    def prepare(self, *, active=False):
        active_run = (self.env.get("DRILL_ACTIVE_CI_RUN_ID") or self.env.get("SUBS_BOT_CI_RUN_ID", "")) if active else ""
        if active_run:
            self.active_directory = tempfile.TemporaryDirectory(prefix="lifecycle-reviewed-active-", dir=self.env["RUNNER_TEMP"])
            self.proof = prepare_control_artifact.prepare("inspect", run_id=active_run, directory=self.active_directory.name)
            bundle = Path(self.active_directory.name) / artifact.VERIFIED_DIRECTORY
        else:
            self.proof = artifact.prepare()
            bundle = Path(self.env["RUNNER_TEMP"]) / artifact.VERIFIED_DIRECTORY
        self.proof = {key: str(self.proof[key]) for key in ("revision", "runId", "runAttempt", "artifactId", "archiveSha256")}
        manifest = parsed((bundle / "isolation.json").read_bytes())
        require(active_run or manifest["revision"] == self.revision, "Deployment must use this exact main CI artifact.")
        self.report["releaseRevision"] = manifest["revision"]
        return bundle, manifest

    def registration(self, *, required=True):
        expected = self.env.get("DRILL_REGISTRATION_SHA256", "")
        raw = self.store.get(self.registration_key, absent=True)
        if raw is None:
            require(not required and expected == "", "No matching durable rehearsal registration exists; inspect before continuing.")
            return None
        value = parsed(raw)
        target = validate_target(value.get("target"))
        require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE
                and value.get("draftSha256") == self.draft.digest and value.get("targetSha256") == target.digest
                and value.get("configurationSha256") == target.configuration_digest)
        require(matches(r"[0-9a-f]{64}", expected) and expected == sha256(raw).hexdigest(),
                "The independent rehearsal registration digest is required and must match exactly.")
        self.report.update(registrationSha256=sha256(raw).hexdigest(), targetSha256=target.digest,
                           configurationSha256=target.configuration_digest)
        return target

    def bind(self, target, bundle, manifest):
        desired = deepcopy(self.draft.data)
        for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
            desired[key] = target.data[key]
        require(validate_target(desired).configuration_digest == target.configuration_digest,
                "Registered rehearsal secrets or configuration changed; use an explicit reviewed configuration release.")
        data = API(target, self.env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""))
        worker = API(target, self.env.get("SUBS_BOT_CF_DEPLOY_TOKEN", ""))
        self.controller = Controller(target, data, worker, bundle, manifest, guard=self.guard,
            telegram=Telegram(target, self.secrets, rehearsal_previous_url=ORIGINAL_ORIGIN + "/telegram/webhook"),
            secrets=self.secrets, control_revision=self.revision)
        return self.controller

    def source_controller(self, target):
        active_run = self.env.get("DRILL_ACTIVE_CI_RUN_ID", "")
        if not active_run:
            return None
        self.source_directory = tempfile.TemporaryDirectory(prefix="lifecycle-reviewed-source-", dir=self.env["RUNNER_TEMP"])
        proof = prepare_control_artifact.prepare("inspect", run_id=active_run, directory=self.source_directory.name)
        bundle = Path(self.source_directory.name) / artifact.VERIFIED_DIRECTORY
        manifest = parsed((bundle / "isolation.json").read_bytes())
        self.report["activeSourceProof"] = proof
        return Controller(target, self.controller.data, self.controller.worker, bundle, manifest,
            guard=self.guard, secrets=self.secrets, control_revision=self.revision)

    def transition(self, action):
        ctl = self.controller
        require(ctl is not None and ctl.target.environment == "rehearsal"
                and ctl.target.data["workerName"] == SERVICE and action in ("pause", "freeze", "thaw", "activate"))
        for attempt in range(1, 4):
            self.transition_sequence += 1
            stage = "control-" + str(self.transition_sequence).zfill(3) + "-" + action
            before = ctl.plan_activate() if action == "activate" else ctl.plan_pause() if action == "pause" else ctl.inspect()
            self.report.update(state=before, ciProof=self.proof)
            self.save(stage + "-intent", {"action": action, "attempt": attempt, "observed": before})
            try:
                after = ctl.transition(action, approval(ctl.target, action, ctl.revision, before["stateSha256"]), before["stateSha256"])
            except StalePredecessorError:
                self.save(stage + "-stale", {"action": action, "attempt": attempt, "transitionPerformed": False})
                if attempt == 3:
                    raise
                continue
            # A SQL/transport/unknown result or failed confirmation never reaches
            # the retry branch, including a failure of this private evidence write.
            self.report["state"] = after
            self.save(stage + "-confirmed", after)
            return after

    def negative_preflight(self, target, bundle, manifest):
        observed = {"reads": 0, "mutationAttempts": 0}
        def readonly(api):
            def call(method, path, payload=None, **options):
                if method != "GET":
                    observed["mutationAttempts"] += 1
                    raise ContractError("Negative identity preflight attempted a mutation.")
                observed["reads"] += 1
                return api(method, path, payload, **options)
            return call
        data = API(target, self.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
        worker = API(target, self.env["SUBS_BOT_CF_DEPLOY_TOKEN"])
        wrong = deepcopy(target.data)
        wrong["d1CreatedAt"] = "2000-01-01T00:00:00.000Z"
        wrong_controller = Controller(validate_target(wrong), readonly(data), readonly(worker), bundle, manifest, secrets=self.secrets)
        refused = False
        try:
            wrong_controller.initialize()
        except ContractError:
            refused = True
        require(refused and observed["reads"] > 0 and observed["mutationAttempts"] == 0,
                "Wrong immutable resource registration was not rejected before mutation.")
        missing = deepcopy(target.data)
        missing["botId"] = None
        refused = False
        try:
            validate_target(missing)
        except ContractError:
            refused = True
        require(refused, "Missing Bot identity was not rejected.")
        return {"wrongImmutableTargetRejected": True, "missingIdentityRejected": True, "mutationAttempts": 0}

    def bootstrap(self):
        bundle, manifest = self.prepare()
        target = self.registration(required=False)
        if target is None:
            journal = ProvisionJournal(self.store, self.draft, self.guard)
            tool = Provisioner(self.draft, API(self.draft, self.env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), create=True),
                API(self.draft, self.env.get("SUBS_BOT_CF_DEPLOY_TOKEN", ""), create=True), self.guard, journal=journal)
            previous = journal.value if journal.value is not None else tool.available()
            predecessor = digest(previous)
            target, receipt = tool.create(approval(self.draft, "provision", self.revision, predecessor), self.revision, predecessor)
            value = {"schemaVersion": 1, "draftSha256": self.draft.digest, "target": target.data,
                "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                "provisionJournalSha256": journal.previous, "registrationState": receipt["state"]}
            self.store.put(self.registration_key, canonical(value))
            self.report.update(registrationSha256=digest(value), targetSha256=target.digest,
                               configurationSha256=target.configuration_digest)
        ctl = self.bind(target, bundle, manifest)
        ctl.resources()
        self.save("negative-preflight", self.negative_preflight(target, bundle, manifest))
        control_exists = one(ctl.data, ctl.database,
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='subs_bot_production_control') AS present")["present"]
        initialized_control = control_exists and one(ctl.data, ctl.database, "SELECT count(*) AS n FROM subs_bot_production_control")["n"]
        source = self.source_controller(target)
        if not initialized_control:
            initialized = ctl.initialize()
            repeated = ctl.initialize()
            require(initialized["initialized"] is True and repeated.get("repeated") is True)
            self.save("initialization", {"first": initialized, "repeat": repeated, "ciProof": self.proof})
            self.report["initializedTwice"] = True
        else:
            existing = (source or ctl).inspect()
            require(existing["control"]["admission"] == "closed" and existing["control"]["workers"] == "frozen"
                    and not any(existing["work"].values()), "Preserve and close the reviewed active source before redeployment.")
            self.save("existing-state-preserved", existing)
            self.report["existingBusinessDataPreserved"] = True
        before = ctl.plan_deploy(source)
        release = ctl.deploy(approval(target, "deploy", ctl.revision, before["stateSha256"]), before["stateSha256"], source_controller=source)
        require(release["control"]["admission"] == "closed" and release["control"]["workers"] == "frozen")
        ctl.verify_domain()
        self.save("deployed-closed", release)
        self.report.update(status="passed", deployedClosed=True, state=release, ciProof=self.proof)

    def original_read(self, sql):
        # This client is pinned to the original D1. The only exposed operation is
        # a fixed SELECT, so the drill cannot modify original business records.
        require(isinstance(sql, str) and sql.lstrip().startswith("SELECT ") and ";" not in sql)
        database = "/accounts/" + ACCOUNT + "/d1/database/" + self.original["d1Id"]
        identity = self.anchor_api("GET", database)
        require((identity.get("uuid"), identity.get("name"), identity.get("created_at")) ==
                (self.original["d1Id"], ORIGINAL_SERVICE, self.original["d1CreatedAt"]))
        return rows(self.anchor_api, database, sql)

    def anchors(self):
        result = {}
        bot = migrations._literal(self.previous["botId"])
        for role, key in (("admin", "adminId"), ("member", "memberId")):
            actor = migrations._literal(self.previous[key])
            explicit = self.env.get("DRILL_" + role.upper() + "_MESSAGE_ID", "")
            if explicit:
                require(matches(r"[1-9][0-9]{0,9}", explicit) and int(explicit) < 2**31)
                message = int(explicit)
            else:
                selected = self.original_read(f"SELECT message_id FROM telegram_inbox WHERE bot_id={bot} AND actor_id={actor} "
                    f"AND chat_id={actor} AND chat_type='private' AND message_id BETWEEN 1 AND 2147483647 "
                    "ORDER BY received_at DESC,receipt_id DESC LIMIT 1")
                require(len(selected) == 1 and type(selected[0].get("message_id")) is int,
                        "A real private-message reply anchor is required for each authorized test actor.")
                message = selected[0]["message_id"]
            result[role] = message
        return result

    def snapshot_key(self, checkpoint=None):
        checkpoint = checkpoint or self.run + "/" + self.attempt
        require(matches(r"[1-9][0-9]{0,19}/[1-9][0-9]{0,5}", checkpoint))
        return self.prefix + "webhook-" + checkpoint.replace("/", "-") + ".json"

    def restore_webhook(self, *, automatic=False):
        checkpoint = self.env.get("DRILL_WEBHOOK_CHECKPOINT", "")
        if automatic:
            checkpoint = self.run + "/" + self.attempt
        else:
            require(checkpoint, "The exact interrupted webhook checkpoint is required.")
        raw = self.store.get(self.snapshot_key(checkpoint), absent=True)
        if raw is None:
            require(automatic, "The private webhook recovery snapshot is missing.")
            return {"webhookWasNotChanged": True, "webhookRestored": True}
        snapshot = parsed(raw)
        expected = self.env.get("DRILL_WEBHOOK_SNAPSHOT_SHA256", "")
        require(automatic or (matches(r"[0-9a-f]{64}", expected) and expected == sha256(raw).hexdigest()),
                "The independent webhook snapshot digest is required.")
        require(snapshot.get("botId") == self.previous["botId"] and snapshot.get("oldWebhookSecret") == self.previous["webhookSecret"]
                and snapshot.get("draftSha256") == self.draft.digest)
        before = webhook_settings(snapshot["webhookInfo"])
        require(before["url"] == ORIGINAL_ORIGIN + "/telegram/webhook")
        telegram = Telegram(self.draft, {**self.secrets, "webhookSecret": self.previous["webhookSecret"]})
        telegram.identity()
        current = webhook_settings(telegram.call("getWebhookInfo"))
        require(current["url"] in (before["url"], ORIGIN + "/telegram/webhook"),
                "Webhook ownership changed unexpectedly; no restore mutation was attempted.")
        probe = None
        rewrite = current != before
        if not rewrite:
            probe = probe_original_webhook(self.previous["webhookSecret"])
            expect_status(probe, (400, 401), "original-auth-before")
            rewrite = probe == 401
        if rewrite:
            telegram.call("setWebhook", {"url": before["url"], "secret_token": self.previous["webhookSecret"],
                "drop_pending_updates": False, "allowed_updates": before["allowed_updates"],
                "max_connections": before["max_connections"]})
        after = webhook_settings(telegram.call("getWebhookInfo"))
        require(after == before, "Original test webhook restoration was not confirmed; keep all recovery evidence.")
        if rewrite:
            probe = probe_original_webhook(self.previous["webhookSecret"])
        expect_status(probe, 400, "original-auth-after")
        return {"webhookRestored": True, "restoredSettingsSha256": digest(after), "dropPendingUpdates": False,
                "originalWebhookAuthProbe": {"status": 400, "businessAccepted": False}}

    def quiet(self, seconds=180):
        deadline = monotonic() + seconds
        while True:
            work = self.controller.work()
            if not any(work.values()):
                return work
            require(monotonic() < deadline, "Rehearsal work has not drained; preserve categorized work and do not clear records.")
            sleep(2)

    def code_archive(self):
        proof = {key: str(self.proof[key]) for key in ("revision", "runId", "runAttempt", "artifactId", "archiveSha256")}
        token = artifact._github_token()
        expected = (proof["runAttempt"], proof["artifactId"], proof["archiveSha256"])
        require(tuple(map(str, artifact._select_artifact(proof["runId"], proof["revision"], token))) == expected)
        archive = artifact._download(proof["artifactId"], token)
        require(sha256(archive).hexdigest() == proof["archiveSha256"]
                and tuple(map(str, artifact._select_artifact(proof["runId"], proof["revision"], token))) == expected,
                "The frozen source CI ZIP changed or its digest did not verify.")
        return proof, archive

    def activation_baseline(self):
        import production_recovery as recovery
        from production_release_evidence import verify_activation_baseline
        ctl = self.controller
        data_token = self.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"]
        if self.baseline_checkpoint:
            checkpoint, manifest_sha = self.baseline_checkpoint, self.baseline_manifest_sha
        else:
            proof, archive = self.code_archive()
            checkpoint = token_hex(16)
            name = "subs-bot-cf-restore-control-" + checkpoint[:16]
            contract = {"version": 1, "checkpointId": checkpoint, "databaseName": name, "objectsName": name, "purpose": "baseline"}
            api = recovery.RecoveryAPI(ctl.target.data, data_token, ctl.worker, contract)
            source = recovery.RecoverySource(api, ctl.target.data, ctl.bundle, ctl.manifest, ctl.inspect, ctl.guard)
            source.archive_body, source.code_proof = archive, proof
            journal = recovery.RecoveryJournal(api, self.run + "/" + self.attempt, guard=ctl.guard)
            journal.load()
            try:
                with tempfile.TemporaryDirectory(prefix="lifecycle-activation-baseline-", dir=self.env["RUNNER_TEMP"]) as directory:
                    engine = recovery.RecoveryEngine(api, source, journal, Path(directory))
                    for action in ("prepare", "capture", "verify-backup"):
                        result = recovery.run_action(action, engine)
                        self.save("activation-baseline-" + action, result)
                manifest_sha = result["backup"]["manifestSha256"]
            finally:
                journal.release()
        ctl.activation_baseline_checker = lambda: verify_activation_baseline(ctl, data_token, checkpoint, manifest_sha)
        verified = ctl.activation_baseline_checker()
        require(isinstance(verified, dict) and verified.get("baselineVerified") is True
                and verified.get("checkpointId") == checkpoint and verified.get("manifestSha256") == manifest_sha
                and verified.get("targetSha256") == ctl.target.digest
                and verified.get("configurationSha256") == ctl.target.configuration_digest
                and verified.get("sourceRevision") == ctl.revision and verified.get("mutationPerformed") is False,
                "The independent activation baseline proof did not verify exactly.")
        self.report["activationBaseline"] = {"checkpointId": checkpoint, "manifestSha256": manifest_sha,
            "targetSha256": ctl.target.digest, "verification": verified}
        self.report["baselineReused"] = bool(self.baseline_checkpoint)
        self.save("activation-baseline-reused-verified" if self.baseline_checkpoint else "activation-baseline-verified",
            self.report["activationBaseline"])

    def exercise(self):
        bundle, manifest = self.prepare(active=True)
        ctl = self.bind(self.registration(), bundle, manifest)
        baseline = ctl.inspect()
        self.report.update(state=baseline, ciProof=self.proof)
        require(baseline["control"]["admission"] == "closed" and baseline["control"]["workers"] == "frozen"
                and not any(baseline["work"].values()))
        ctl.verify_domain()
        if not self.baseline_checkpoint:
            self.transition("thaw")
            self.transition("pause")
            self.quiet()
            self.transition("freeze")
        self.activation_baseline()
        reply_anchors = self.anchors()
        before_hook = ctl.telegram.call("getWebhookInfo")
        old_settings = webhook_settings(before_hook)
        require(old_settings["url"] == ORIGINAL_ORIGIN + "/telegram/webhook",
                "Recover the previous test webhook before opening another rehearsal window.")
        webhook_plan = ctl.plan_webhook()
        snapshot = {"schemaVersion": 1, "draftSha256": self.draft.digest, "botId": self.previous["botId"],
            "oldWebhookSecret": self.previous["webhookSecret"], "webhookInfo": before_hook,
            "revision": self.revision, "runId": self.run, "runAttempt": self.attempt}
        self.store.put(self.snapshot_key(), canonical(snapshot))
        self.report.update(webhookCheckpoint=self.run + "/" + self.attempt, webhookSnapshotSha256=digest(snapshot))
        changed = False
        primary_error = None
        phase = "configure-webhook"
        try:
            configured = ctl.configure_webhook(approval(ctl.target, "webhook", ctl.revision, webhook_plan["stateSha256"]),
                webhook_plan["stateSha256"], webhook_plan["webhook"]["settingsSha256"])
            changed = True
            self.save("webhook-configured", configured)
            # The new production code path is present but still denies new work.
            now = one(ctl.data, ctl.database, "SELECT unixepoch() AS n")["n"]
            base = 7_000_000_000_000_000 + (int(self.run) % 1_000_000_000) * 1000 + int(self.attempt) * 100
            admin, member = self.previous["adminId"], self.previous["memberId"]
            help_update = update_payload(base + 1, admin, reply_anchors["admin"], "/help", now - 5)
            phase = "closed-admission"
            expect_status(post_update(help_update, self.secrets["webhookSecret"]), 503, "closed-admission")
            phase = "activation"
            active = self.transition("activate")
            self.save("activated", active)
            phase = "synthetic-verification"
            expect_status(post_update(help_update, "incorrect-lifecycle-fixture-secret"), 401, "wrong-secret")
            expect_status(post_update(help_update, self.secrets["webhookSecret"]), 200, "durable-help")
            self.quiet()
            before_duplicate = one(ctl.data, ctl.database, "SELECT count(*) AS n FROM telegram_inbox")["n"]
            expect_status(post_update(help_update, self.secrets["webhookSecret"]), 200, "duplicate-update")
            require(one(ctl.data, ctl.database, "SELECT count(*) AS n FROM telegram_inbox")["n"] == before_duplicate,
                    "A repeated update created another business receipt.")
            conflict = deepcopy(help_update)
            conflict["message"]["text"] = "/list"
            conflict["message"]["entities"][0]["length"] = 5
            expect_status(post_update(conflict, self.secrets["webhookSecret"]), 409, "payload-conflict")
            denied = update_payload(base + 2, member, reply_anchors["member"], "/auth remove " + admin, now - 5)
            actor_before = rows(ctl.data, ctl.database, "SELECT * FROM telegram_general_actors ORDER BY actor_id,revision")
            expect_status(post_update(denied, self.secrets["webhookSecret"]), 204, "member-admin-denial")
            require(rows(ctl.data, ctl.database, "SELECT * FROM telegram_general_actors ORDER BY actor_id,revision") == actor_before,
                    "A denied operation changed authorization records.")
            share_text = "/share s1440 x1 id" + member + " -- Lifecycle control fixture " + self.run + "-" + self.attempt
            shared = update_payload(base + 3, admin, reply_anchors["admin"], share_text, now - 5)
            expect_status(post_update(shared, self.secrets["webhookSecret"]), 200, "private-share")
            self.quiet()
            private = rows(ctl.data, ctl.database, f"SELECT creation.payload_id,creation.payload_sha256,creation.state FROM telegram_private_share_creations AS creation "
                f"JOIN telegram_inbox USING(receipt_id) WHERE telegram_inbox.update_id={base + 3}")
            require(len(private) == 1 and private[0]["state"] == "published", "The fixture object was not published.")
            key = "private-shares/" + private[0]["payload_id"] + ".txt"
            request = Request("https://api.cloudflare.com/client/v4/accounts/" + ACCOUNT + "/r2/buckets/" + SERVICE + "/objects/" + key,
                headers={"Authorization": "Bearer " + self.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], "Accept-Encoding": "identity", "cf-r2-jurisdiction": "default"})
            _, _, body = native._response(ctl.data.opener, request, 64 * 1024)
            require(sha256(body).hexdigest() == private[0]["payload_sha256"], "Independent R2 bytes do not match the durable fixture digest.")
            states = rows(ctl.data, ctl.database, f"SELECT inbox.update_id,outbox.state,outbox.attempts FROM telegram_inbox AS inbox "
                f"JOIN telegram_outbox AS outbox USING(receipt_id) WHERE inbox.update_id IN ({base + 1},{base + 3}) ORDER BY inbox.update_id")
            require(len(states) == 2 and all(r["state"] == "sent" for r in states),
                    "Synthetic replies did not both reach a confirmed sent terminal state.")
            if self.human_window:
                phase = "human-window"
                window = {"stage": "human-window-open", "targetSha256": ctl.target.digest,
                    "deadlineEpoch": int(time()) + self.human_window, "seconds": self.human_window,
                    "humanPassed": "not-evaluated-by-runner"}
                self.save("human-window-open", window)
                self.report.update(humanWindowOpened=True, humanAcceptance="requires-independent-IAB-evidence")
                print(json.dumps(window, sort_keys=True), flush=True)
                sleep(self.human_window)
            phase = "pause-and-freeze"
            self.transition("pause")
            paused = update_payload(base + 4, member, reply_anchors["member"], "/help", now - 5)
            expect_status(post_update(paused, self.secrets["webhookSecret"]), 503, "paused-admission")
            self.quiet()
            frozen = self.transition("freeze")
            final_states = rows(ctl.data, ctl.database, f"SELECT inbox.update_id,outbox.state,outbox.attempts FROM telegram_inbox AS inbox "
                f"JOIN telegram_outbox AS outbox USING(receipt_id) WHERE inbox.update_id IN ({base + 1},{base + 3}) ORDER BY inbox.update_id")
            require(final_states == states, "A completed synthetic reply was executed again during the observation window.")
            require(one(ctl.data, ctl.database, f"SELECT count(*) AS n FROM telegram_inbox WHERE update_id={base + 4}")["n"] == 0)
            require(one(ctl.data, ctl.database, f"SELECT count(*) AS n FROM subs_bot_production_updates WHERE update_id={base + 2} AND state='completed' AND http_status=204")["n"] == 1)
            self.save("paused-drained-frozen", frozen)
            self.report.update(status="passed", syntheticCases={"syntheticOnly": True, "positiveSent": len(states)}, positiveSent=len(states), duplicateBusinessReceipts=0,
                wrongSecretRejected=True, conflictingPayloadRejected=True, memberAdminDenied=True,
                closedAdmissionRejected=True, pausedAdmissionRejected=True, referencedObjectCount=1,
                referencedObjectSha256=sha256(body).hexdigest(), state=frozen, ciProof=self.proof)
        except Exception as error:
            primary_error = error
            self.report["primaryFailure"] = safe_failure(error, phase)
            raise
        finally:
            try:
                self.cleanup_exercise(changed)
            except Exception:
                if primary_error is not None:
                    raise primary_error from None
                raise

    def cleanup_exercise(self, changed):
        # Always attempt restoration, including a lost setWebhook response or a
        # pause failure. A cleanup failure must not hide the primary probe result.
        ctl, errors = self.controller, []
        def attempt(phase, action):
            try:
                action()
            except Exception as error:
                self.report.setdefault("cleanupFailures", []).append(safe_failure(error, phase))
                errors.append(error)
        def pause():
            current = ctl.inspect()
            if current["control"]["admission"] != "closed":
                self.transition("pause")
        def restore():
            self.report["webhookRecovery"] = self.restore_webhook(automatic=True)
            if "originalWebhookAuthProbe" in self.report["webhookRecovery"]:
                self.report["originalWebhookAuthProbe"] = self.report["webhookRecovery"]["originalWebhookAuthProbe"]
        def freeze():
            self.quiet()
            current = ctl.inspect()
            if current["control"]["workers"] != "frozen":
                self.transition("freeze")
        if changed:
            attempt("cleanup-pause", pause)
        attempt("cleanup-webhook", restore)
        if changed:
            attempt("cleanup-freeze", freeze)
        if errors:
            raise errors[0] from None

    def inspect(self):
        bundle, manifest = self.prepare(active=True)
        ctl = self.bind(self.registration(), bundle, manifest)
        state = ctl.inspect()
        self.report.update(state=state, ciProof=self.proof, independentReadback=True)
        self.save("independent-inspect", state)
        require(state["control"]["admission"] == "closed" and state["control"]["workers"] == "frozen",
                "The observed rehearsal target is not closed and frozen; its actual state was retained.")
        human = self.human_receipts()
        self.report.update(status="passed",
            humanReceiptsObserved=len(human), humanReceipts=human, humanEvidenceRequiresIABCorrelation=True)

    def stabilize(self):
        bundle, manifest = self.prepare(active=True)
        ctl = self.bind(self.registration(), bundle, manifest)
        require(ctl.target.environment == "rehearsal" and ctl.target.data["workerName"] == SERVICE)
        before = ctl.inspect()
        self.report.update(state=before, ciProof=self.proof)
        self.save("stabilization-observed", before)
        self.transition("pause")
        self.quiet()
        frozen = self.transition("freeze")
        require(frozen["control"]["admission"] == "closed" and frozen["control"]["workers"] == "frozen"
                and not any(frozen["work"].values()))
        unknown = {key: frozen["terminal"].get(key, 0) for key in
            ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates")}
        self.report.update(status="passed", state=frozen,
            stabilization={"admissionClosed": True, "workersFrozen": True, "preservedUnknown": unknown,
                "activationPermitted": False, "webhookTouched": False})
        self.save("stabilization-confirmed", self.report["stabilization"])

    def human_receipts(self):
        """Project bounded receipt metadata; a person must still correlate the IAB messages."""
        ctl = self.controller
        require(ctl is not None and ctl.target.environment == "rehearsal"
                and ctl.target.data["workerName"] == SERVICE
                and ctl.target.data["admins"] == ["8813701954"] and ctl.target.data["members"] == ["8653767757"])
        observed = rows(ctl.data, ctl.database,
            "SELECT inbox.actor_id,inbox.message_id,inbox.command,outbox.state,outbox.attempts "
            "FROM telegram_inbox AS inbox JOIN telegram_outbox AS outbox USING(receipt_id) "
            f"WHERE inbox.bot_id={migrations._literal(ctl.target.data['botId'])} "
            "AND inbox.actor_id IN ('8813701954','8653767757') AND inbox.chat_type='private' "
            "AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL "
            "AND inbox.update_id>0 AND inbox.update_id<7000000000000000 ORDER BY inbox.receipt_id LIMIT 201")
        require(len(observed) <= 200, "Human receipt metadata exceeds the explicit inspection limit; no truncated result is accepted.")
        for receipt in observed:
            require(set(receipt) == {"actor_id", "message_id", "command", "state", "attempts"}
                    and receipt["actor_id"] in ("8813701954", "8653767757")
                    and type(receipt["message_id"]) is int and 0 < receipt["message_id"] < 2**31
                    and receipt["command"] in ("start", "help", "list", "auth-list", "auth-add", "auth-remove", "auth-usage")
                    and receipt["state"] in ("pending", "leased", "sending", "sent", "failed", "uncertain")
                    and type(receipt["attempts"]) is int and 0 <= receipt["attempts"] < 2**31,
                    "Human receipt metadata is outside the explicit authorized projection.")
        return observed

    def seed_fixture(self):
        from production_lifecycle_fixture import REVOKED_TOKEN, seed_fixture
        bundle, manifest = self.prepare(active=True)
        ctl = self.bind(self.registration(), bundle, manifest)
        result = seed_fixture(ctl, bundle, manifest, self.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
        snapshot = manifest["snapshots"][0]
        url = ORIGIN + "/sub/" + snapshot["token"] + "/base64"
        status, body = public_readback(public_request(url), 64 * 1024)
        expect_status(status, 200, "fixture-get")
        require(len(body) == snapshot["bodyBytes"] and sha256(body).hexdigest() == snapshot["bodySha256"],
                "The actual deployed synthetic three-node export differs from its verified CI bytes.")
        status, body = public_readback(public_request(url, method="HEAD"), 1024)
        expect_status(status, 200, "fixture-head")
        require(body == b"", "The actual deployed fixture HEAD readback failed.")
        denied = 0
        for method in ("GET", "HEAD"):
            status, _ = public_readback(public_request(ORIGIN + "/sub/" + REVOKED_TOKEN + "/base64", method=method), 4096)
            expect_status(status, 404, "revoked-" + method.lower())
            denied += 1
        require(denied == 2, "A synthetic revoked-token request unexpectedly succeeded.")
        result.update(publicPositiveExports=2, publicRevokedDenials=denied)
        self.save("synthetic-export-fixture", result)
        self.report.update(status="passed", fixture=result, state=ctl.inspect(), ciProof=self.proof)

    def recovery(self):
        from production_recovery_drill import run_recovery_drill
        bundle, manifest = self.prepare(active=True)
        ctl = self.bind(self.registration(), bundle, manifest)
        source = ctl.inspect()
        require(source["control"]["admission"] == "closed" and source["control"]["workers"] == "frozen"
                and not any(source["work"].values()))
        proof, archive = self.code_archive()
        generation = 0
        def evidence(value):
            nonlocal generation
            generation += 1
            self.save("recovery-stage-" + str(generation).zfill(3), value)
        recovered = run_recovery_drill(ctl, archive, proof, self.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], evidence=evidence)
        require(recovered.get("status") == "recovery-verified-http-pending"
                and recovered.get("newWritesPreservedInG1") is True,
                "Recovery cannot finish before the independent no-egress HTTP stages.")
        self.report.update(status="recovery-verified-http-pending", recovery=recovered, sourceState=source,
            ciProof=proof, httpReplay="pending-hosted-no-egress-step", state=ctl.inspect())

    def finalize_recovery(self):
        # Load the first terminal report from private R2, retaining it unchanged.
        pending_raw = self.store.get(self.prefix + self.run + "-" + self.attempt + "-" + REPORT)
        pending = parsed(pending_raw)
        require(pending.get("status") == "recovery-verified-http-pending"
                and pending.get("controlRevision") == self.revision and pending.get("runId") == self.run
                and pending.get("runAttempt") == self.attempt and isinstance(pending.get("recovery"), dict)
                and pending["recovery"].get("status") == "recovery-verified-http-pending",
                "Only the exact independently read pending recovery checkpoint can be finalized.")
        bundle, manifest = self.prepare(active=True)
        ctl = self.bind(self.registration(), bundle, manifest)
        current = ctl.inspect()
        require(current["control"]["admission"] == "closed" and current["control"]["workers"] == "frozen"
                and not any(current["work"].values()) and pending["ciProof"] == self.proof
                and current["release"] == pending["sourceState"]["release"]
                and current["control"] == pending["sourceState"]["control"],
                "The reviewed source or onsite frozen state changed before final verification.")
        source = {"revision": pending["ciProof"]["revision"], "targetSha256": ctl.target.digest,
            "moduleSha256": pending["sourceState"]["release"]["moduleSha256"],
            "dataSha256": pending["recovery"]["restoredDataSha256"], "migrationCount": pending["sourceState"]["migrationCount"]}
        results = {}
        root = Path(self.env["RUNNER_TEMP"])
        for kind in ("g0", "recovered"):
            raw = (root / ("production-recovery-drill-" + kind + "-http.json")).read_bytes()
            result = checked_http_result(parsed(raw), source)
            result["sourceReportSha256"] = sha256(raw).hexdigest()
            result["baselineOrRecovery"] = kind
            results[kind] = result
        for kind, result in results.items():
            output = root / ("production-lifecycle-recovery-" + kind + "-http-result.json")
            body = canonical(result)
            if output.exists():
                require(not output.is_symlink() and output.is_file() and output.read_bytes() == body,
                        "An existing HTTP result conflicts with the verified replay.")
            else:
                with output.open("xb") as stream:
                    output.chmod(0o600)
                    stream.write(body)
        self.report = {**pending, "status": "passed", "pendingReportSha256": sha256(pending_raw).hexdigest(),
            "httpReplay": "passed-hosted-no-egress", "httpReplays": results, "independentFinalState": current,
            "recovery": {**pending["recovery"], "status": "passed", "httpReplay": "passed-hosted-no-egress"}}
        self.save("recovery-finalized", {"targetSha256": ctl.target.digest, "pendingReportSha256": sha256(pending_raw).hexdigest(),
            "httpResultSha256": {key: digest(value) for key, value in results.items()}, "status": "passed"})

    def publish(self):
        name = self.env.get("DRILL_REPORT_NAME", REPORT)
        require(name in (REPORT, FINAL_REPORT, "production-lifecycle-drill-cleanup.json"))
        body = canonical(self.report)
        self.store.put(self.prefix + self.run + "-" + self.attempt + "-" + name, body)
        path = Path(self.env["RUNNER_TEMP"]) / name
        path.write_bytes(body)
        path.chmod(0o600)
        print(json.dumps(self.report, sort_keys=True))


def main():
    env = os.environ
    hosted_environment("rehearsal")
    require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW, "Only the protected dedicated hosted rehearsal workflow may run this drill.")
    action = env.get("DRILL_ACTION", "inspect")
    require(action in ("bootstrap", "exercise", "inspect", "stabilize", "recover-webhook", "seed-fixture", "recovery", "finalize-recovery"))
    tool = Drill(env)
    try:
        if action == "recover-webhook":
            automatic = env.get("DRILL_AUTOMATIC_CLEANUP") == "1"
            recovered = tool.restore_webhook(automatic=automatic)
            tool.report.update(status="passed", webhookRecovery=recovered)
            if "originalWebhookAuthProbe" in recovered:
                tool.report["originalWebhookAuthProbe"] = recovered["originalWebhookAuthProbe"]
        else:
            artifact.require_current_main(tool.revision)
            getattr(tool, action.replace("-", "_"))()
    except Exception:
        tool.report["status"] = "stopped"
        tool.publish()
        raise
    tool.publish()


if __name__ == "__main__":
    try:
        main()
    except (ContractError, OperationError, artifact.ArtifactError, migrations.MigrationError, native.RehearsalError) as error:
        print(json.dumps({"status": "stopped", "reason": str(error), "uncertain": bool(getattr(error, "uncertain", False))}))
        raise SystemExit(1) from None
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "The rehearsal encountered an unconfirmed result; retain the private checkpoints and inspect independently."}))
        raise SystemExit(1) from None

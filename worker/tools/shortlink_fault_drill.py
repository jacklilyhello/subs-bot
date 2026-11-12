"""Bounded caller-only RPC failure drill, with a prepublished signed recovery pin.

Only the existing isolation Worker versions/deployments may change. The dependency,
Telegram configuration, resource bindings, feature flags and business data do not.
No request URL, capability, credential or untrusted API error is printed.
"""

from dataclasses import asdict, fields, replace
from hashlib import sha256
from io import BytesIO
import base64
import hmac
import json
import os
from pathlib import Path
import re
import signal
import sys
from time import monotonic, sleep, time
from urllib.parse import urlencode
from zipfile import ZipFile

import external_shortlink_release as external
import prepare_isolation_artifact as artifact
import production_candidate as candidate
from capacity_resources import CapacityError, integer, read_private, save_private_json
from cloudflare_isolation import (CloudflareClient, CloudflareError, MAX_MODULE_BYTES, ProviderApiStatusBinding, ProviderBinding,
    UUID, _Isolation, _Version, _artifact, _matches, _require, _verify_health)
from d1_migrations import MigrationError, _load_migrations, _read_state
from general_read_rehearsal import require_general_read_lane_clear
from native_restore_rehearsal import readonly_schema_batch, readonly_sql
from release_isolation import isolation_credentials, isolated_telegram_config
from stage_page_jump_isolation import _ordinary_tag
from telegram_aggregate_smoke import key_bytes
from telegram_short_links_smoke import Cohort, ORIGIN, probe_code
from telegram_view_fixtures import FixtureError, rows

ERROR = "The isolated shortlink fault drill could not be confirmed safely."
WORKFLOW_FILE = "worker-isolation-shortlink-fault-drill.yml"
WORKFLOW_PATH = ".github/workflows/" + WORKFLOW_FILE
WORKFLOW = artifact.REPOSITORY + "/" + WORKFLOW_PATH + "@refs/heads/main"
PREFIX = "subs-bot-shortlink-fault-recovery"
CHECKPOINT = "shortlink-fault-checkpoint.json"
RESULT = "shortlink-fault-result.json"
RESTORE_RESULT = "shortlink-fault-restore.json"
COHORT = re.compile(r"[0-9a-f]{16}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
MAX_CHECKPOINT = 65536
POLL_SECONDS = 300
# A deliberately invalid, non-secret fixture. Its valid syntax reaches the real RPC.
INVALID_TOKEN = "sl_" + "0" * 64
INVALID_DIGEST = sha256(INVALID_TOKEN.encode("ascii")).hexdigest()
POLICY_IDS = {"botId": "9293938370", "adminId": "8813701954", "memberId": "8653767757", "groupId": "-5114255828"}
DATABASE_ID = "c690f7f1-de21-48dc-a6e0-539416fb2e08"
FAILURE_PHASES = frozenset({"entry", "context-hosted-identity", "context-resources", "context-policy", "context-keys",
    "prepare-inputs", "artifact", "artifact-manifest", "resources", "config", "active", "version", "artifact-identity",
    "ordinary-tag", "cron", "shortlink-identity", "ordinary-proof", "schema", "idle", "health", "cohort",
    "preupload-recheck", "upload-R", "upload-C", "cohort-recheck", "checkpoint", "run-preflight", "run-activation",
    "run-acceptance", "restore-preflight", "restore-version", "restore-module", "restore-upload", "restore-activation",
    "restore-readback", "unexpected"})
API_BOUNDARIES = frozenset({"data-read-gate", "d1-resource", "d1-read-query", "r2-bucket", "r2-managed-domain",
    "r2-custom-domains", "worker-resource", "worker-config", "worker-active", "worker-version", "worker-namespace",
    "worker-domains", "worker-schedules", "worker-upload", "worker-activation", "other"})
FAILURE_CATEGORIES = frozenset({"cloudflare", "artifact", "migration", "fixture", "private-file", "io", "validation", "unexpected"})
_failure_phase = "entry"
_api_boundary = None


def failure_phase(value):
    """Retain only a fixed stage label; successful calls produce no diagnostic noise."""
    global _failure_phase, _api_boundary
    _failure_phase = value if isinstance(value, str) and value in FAILURE_PHASES else "unexpected"
    _api_boundary = None


def observed_api(boundary, operation):
    global _api_boundary
    _api_boundary = boundary if isinstance(boundary, str) and boundary in API_BOUNDARIES else "other"
    result = operation()
    _api_boundary = None
    return result


def failure_projection(error):
    saved = getattr(error, "_shortlink_fault_projection", None)
    if (isinstance(saved, dict) and set(saved) <= {"currentPhaseOnFailure", "category", "apiBoundary", "httpStatus", "uncertain"}
            and isinstance(saved.get("currentPhaseOnFailure"), str) and saved["currentPhaseOnFailure"] in FAILURE_PHASES
            and isinstance(saved.get("category"), str) and saved["category"] in FAILURE_CATEGORIES
            and ("apiBoundary" not in saved or isinstance(saved["apiBoundary"], str) and saved["apiBoundary"] in API_BOUNDARIES)
            and ("httpStatus" not in saved or type(saved["httpStatus"]) is int and 100 <= saved["httpStatus"] <= 599)
            and ("uncertain" not in saved or type(saved["uncertain"]) is bool)):
        return dict(saved)
    category = next((name for cls, name in ((CloudflareError, "cloudflare"), (artifact.ArtifactError, "artifact"),
        (MigrationError, "migration"), (FixtureError, "fixture"), (CapacityError, "private-file"),
        (OSError, "io"), ((ValueError, TypeError, KeyError, AttributeError), "validation")) if isinstance(error, cls)), "unexpected")
    result = {"currentPhaseOnFailure": _failure_phase, "category": category}
    if _api_boundary in API_BOUNDARIES:
        result["apiBoundary"] = _api_boundary
    if isinstance(error, CloudflareError):
        if type(error.http_status) is int and 100 <= error.http_status <= 599:
            result["httpStatus"] = error.http_status
        if type(error.uncertain) is bool:
            result["uncertain"] = error.uncertain
    return result


def remember_failure(error):
    # Keep the acceptance failure's safe phase even when finally performs recovery.
    error._shortlink_fault_projection = failure_projection(error)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def digest(value):
    return sha256(canonical(value)).hexdigest()


def sign(key, value):
    return hmac.new(key, b"subs-bot/shortlink-fault-drill/v1\0" + canonical(value), sha256).hexdigest()


def seal(key, value):
    return {**value, "proofSha256": sign(key, value)}


def canary_version(original):
    _require(original.telegram_external_shortlinks and original.external_shortlink_capable
        and original.external_shortlink_token_sha256 != INVALID_DIGEST and original.external_shortlink_base_tag is not None
        and original.telegram_page_jump_epoch is None, ERROR)
    return replace(original, external_shortlink_token_sha256=INVALID_DIGEST,
        tag=external.release_tag(original.external_shortlink_base_tag, INVALID_DIGEST, True))


def version_document(value):
    _require(isinstance(value, dict) and set(value) == {item.name for item in fields(_Version)}, ERROR)
    data = dict(value)
    for name, cls in (("provider_binding", ProviderBinding), ("api_status_binding", ProviderApiStatusBinding)):
        if data[name] is not None:
            _require(isinstance(data[name], dict) and set(data[name]) == {"revision", "image_sha256", "identity_sha256"}, ERROR)
            data[name] = cls(**data[name])
    return _Version(**data)


def open_checkpoint(key, value, scope_sha, *, run_id=None, attempt=None):
    _require(isinstance(value, dict) and len(canonical(value)) <= MAX_CHECKPOINT, ERROR)
    proof = value.get("proofSha256")
    body = {name: item for name, item in value.items() if name != "proofSha256"}
    _require(isinstance(proof, str) and artifact._SHA256.fullmatch(proof)
        and hmac.compare_digest(proof, sign(key, body)), ERROR)
    _require(set(body) == {"version", "revision", "operationRunId", "operationRunAttempt", "cohort", "scopeSha256",
        "createdAt", "originalVersionId", "recoveryVersionId", "canaryVersionId", "originalVersion", "canaryVersion",
        "workerConfigSha256", "ciProof", "receiptBaseline"} and type(body["version"]) is int and body["version"] == 1
        and body["scopeSha256"] == scope_sha and _matches(artifact._REVISION, body["revision"])
        and _matches(COHORT, body["cohort"]) and integer(body["createdAt"], 1, 2**53 - 1)
        and all(_matches(DECIMAL, body[name]) for name in ("operationRunId", "operationRunAttempt"))
        and all(_matches(UUID, body[name]) for name in ("originalVersionId", "recoveryVersionId", "canaryVersionId"))
        and len({body[name] for name in ("originalVersionId", "recoveryVersionId", "canaryVersionId")}) == 3
        and _matches(artifact._SHA256, body["workerConfigSha256"]), ERROR)
    if run_id is not None:
        _require((body["operationRunId"], body["operationRunAttempt"]) == (run_id, attempt), ERROR)
    original, canary = version_document(body["originalVersion"]), version_document(body["canaryVersion"])
    _require(original.revision == body["revision"] and canary == canary_version(original), ERROR)
    ci = body["ciProof"]
    _require(isinstance(ci, dict) and set(ci) == candidate.PROOF_KEYS and ci["revision"] == body["revision"]
        and all(_matches(DECIMAL, ci[name]) for name in ("runId", "runAttempt", "artifactId"))
        and _matches(artifact._SHA256, ci["archiveSha256"]), ERROR)
    baseline = body["receiptBaseline"]
    _require(isinstance(baseline, dict) and set(baseline) == {"version", "phase", "identity", "afterReceiptId", "authEpochSha256"}
        and type(baseline["version"]) is int and baseline["version"] == 1 and baseline["phase"] == "prepare"
        and _matches(artifact._SHA256, baseline["identity"]) and _matches(artifact._SHA256, baseline["authEpochSha256"])
        and integer(baseline["afterReceiptId"], 0, 2**53 - 1), ERROR)
    return body, original, canary


def recovery_run_metadata(value, run_id, attempt, workflow_id):
    """Preparation artifacts remain recoverable after failure/cancellation or main advancing."""
    _require(isinstance(value, dict) and str(value.get("id")) == run_id and str(value.get("run_attempt")) == attempt
        and value.get("workflow_id") == workflow_id and value.get("path") in (WORKFLOW_PATH, WORKFLOW_PATH + "@main", WORKFLOW_PATH + "@refs/heads/main")
        and (value.get("event"), value.get("head_branch")) == ("workflow_dispatch", "main")
        and _matches(artifact._REVISION, value.get("head_sha"))
        and value.get("status") in {"queued", "in_progress", "completed", "waiting", "pending", "requested"}
        and all(isinstance(value.get(name), dict) and value[name].get("id") == artifact.REPOSITORY_ID
                for name in ("repository", "head_repository")), ERROR)
    return value["head_sha"]


def read_recovery_artifact(run_id, attempt, token):
    _require(_matches(DECIMAL, run_id) and _matches(DECIMAL, attempt), ERROR)
    workflow = artifact._get_json("/actions/workflows/" + WORKFLOW_FILE, token)
    _require(type(workflow.get("id")) is int and workflow.get("path") == WORKFLOW_PATH, ERROR)
    read_run = lambda: artifact._get_json(f"/actions/runs/{run_id}/attempts/{attempt}", token)
    revision = recovery_run_metadata(read_run(), run_id, attempt, workflow["id"])
    name = f"{PREFIX}-{run_id}-{attempt}"
    listing = artifact._get_json(f"/actions/runs/{run_id}/artifacts?" + urlencode({"name": name, "per_page": 2}), token)
    entries = listing.get("artifacts")
    _require(listing.get("total_count") == 1 and isinstance(entries, list) and len(entries) == 1, ERROR)
    entry = entries[0]
    _require(isinstance(entry, dict) and entry.get("name") == name and entry.get("expired") is False
        and type(entry.get("id")) is int and _matches(DECIMAL, str(entry["id"]))
        and isinstance(entry.get("digest"), str) and entry["digest"].startswith("sha256:")
        and _matches(artifact._SHA256, entry["digest"][7:]), ERROR)
    raw = artifact._download(str(entry["id"]), token)
    _require(len(raw) <= MAX_CHECKPOINT * 2 and sha256(raw).hexdigest() == entry["digest"][7:], ERROR)
    with ZipFile(BytesIO(raw)) as archive:
        members = artifact._zip_members(archive)
        _require(set(members) == {CHECKPOINT} and members[CHECKPOINT].file_size <= MAX_CHECKPOINT, ERROR)
        value = artifact._parse_object(archive.read(members[CHECKPOINT]), ERROR)
    _require(value.get("revision") == revision
        and recovery_run_metadata(read_run(), run_id, attempt, workflow["id"]) == revision, ERROR)
    return value


def readonly_data_request(method, path, payload, db_path, bucket_path):
    if method == "GET" and payload is None:
        return path in {db_path, bucket_path, bucket_path + "/domains/managed", bucket_path + "/domains/custom"}
    if not (method == "POST" and path == db_path + "/query" and isinstance(payload, dict)
            and "sql" in payload and set(payload) <= {"sql", "params"} and isinstance(payload["sql"], str)):
        return False
    return readonly_sql(payload["sql"]) or (set(payload) == {"sql"} and readonly_schema_batch(payload["sql"]) is not None)


class Context:
    def __init__(self, env):
        self.env = env
        failure_phase("context-hosted-identity")
        _require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and all(_matches(DECIMAL, env.get(name)) for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")), ERROR)
        self.directory = Path(env["RUNNER_TEMP"])
        failure_phase("context-resources")
        self.target, data_token, deploy_token = isolation_credentials()
        _require(self.target["d1Id"] == DATABASE_ID, ERROR)
        failure_phase("context-policy")
        self.raw_policy = isolated_telegram_config()
        self.policy = json.loads(self.raw_policy)
        _require(all(self.policy[name] == value for name, value in POLICY_IDS.items()), ERROR)
        failure_phase("context-keys")
        self.aggregate = env.get("SUBS_BOT_TELEGRAM_AGGREGATE_KEY", "")
        self.private = env.get("SUBS_BOT_TELEGRAM_PRIVATE_SHARE_CREATION_KEY", "")
        self.key = key_bytes(self.aggregate)
        self.business = env.get("SUBS_BOT_SHORTLINK_BUSINESS_TOKEN", "")
        _require(_matches(external.TOKEN, self.business) and self.business != INVALID_TOKEN, ERROR)
        data, worker = CloudflareClient(data_token), CloudflareClient(deploy_token)
        self.db_path = f"/accounts/{self.target['accountId']}/d1/database/{DATABASE_ID}"
        bucket_path = f"/accounts/{self.target['accountId']}/r2/buckets/subs-bot-cf-dev-01"

        def read_data(method, path, payload=None):
            global _api_boundary
            _api_boundary = "data-read-gate"
            _require(readonly_data_request(method, path, payload, self.db_path, bucket_path), ERROR)
            boundary = {self.db_path: "d1-resource", self.db_path + "/query": "d1-read-query", bucket_path: "r2-bucket",
                bucket_path + "/domains/managed": "r2-managed-domain", bucket_path + "/domains/custom": "r2-custom-domains"}[path]
            return observed_api(boundary, lambda: data(method, path, payload))

        def observed_worker(method, path, payload=None):
            scope = self.scope
            boundary = {scope.worker: "worker-resource", scope.script + "/settings": "worker-config",
                scope.deployments: "worker-active" if method == "GET" else "worker-activation",
                scope.account + "/workers/subdomain": "worker-namespace", scope.schedules: "worker-schedules",
                scope.account + "/workers/domains?service=subs-bot-cf-dev-01": "worker-domains",
                scope.versions + "?deploy=false": "worker-upload"}.get(path, "worker-version" if path.startswith(scope.versions + "/") else "other")
            return observed_api(boundary, lambda: worker(method, path, payload))

        self.scope = _Isolation(observed_worker, read_data, self.target)
        self.read = lambda sql, *params: rows(read_data, self.db_path, sql, *params)
        self.scope_sha = sign(self.key, [self.target, digest(self.raw_policy), digest(self.aggregate), digest(self.private)])

    def cohort(self, name):
        return Cohort(self.read, self.policy, name, self.key)

    def idle(self):
        require_general_read_lane_clear(self.scope, required=True)
        value = self.read("SELECT count(*) AS n FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) "
            "WHERE bot_id=? AND state IN ('pending','leased','sending')", self.policy["botId"])
        _require(value == [{"n": 0}], ERROR)

    def verify(self, checkpoint, *, current=False, healthy=True):
        self.scope.verify_resources()
        _require(digest(self.scope.worker_config()) == checkpoint["workerConfigSha256"] and self.scope.cron_enabled(), ERROR)
        if current:
            require_general_read_lane_clear(self.scope, required=True)
        if healthy:
            _verify_health(checkpoint["revision"])

    def activate(self, previous, target_id, current, target, message, guard):
        for version_id, expected in ((previous.version, current), (target_id, target)):
            inspected = self.scope.version(version_id, with_legacy_selected=True, with_legacy_temp=True, with_legacy_dynamic_all=True)
            _require(inspected == (expected, True, True, True), ERROR)
        return self.scope.activate(previous, target_id, message, current_version=current, target_version=target,
            current_capable=True, target_capable=True, current_temp_capable=True, target_temp_capable=True,
            current_dynamic_all_capable=True, target_dynamic_all_capable=True, guard=guard)


def ordinary_deployment(env, proof, active):
    run, attempt = env.get("SHORTLINK_FAULT_DEPLOY_RUN_ID", ""), env.get("SHORTLINK_FAULT_DEPLOY_RUN_ATTEMPT", "")
    _require(_matches(DECIMAL, run) and _matches(DECIMAL, attempt), ERROR)
    token = artifact._github_token()
    workflow = artifact._get_json("/actions/workflows/worker-isolation-deploy.yml", token)
    _require(type(workflow.get("id")) is int and workflow.get("path") == candidate.DEPLOY_WORKFLOW, ERROR)
    read_run = lambda: artifact._get_json(f"/actions/runs/{run}/attempts/{attempt}", token)
    metadata = candidate.run_metadata(read_run(), run, attempt, proof["revision"], workflow["id"], candidate.DEPLOY_WORKFLOW)
    job = candidate.deploy_job(artifact._get_json(f"/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100", token),
        run, attempt, proof["revision"])
    evidence = candidate.deployment_proofs(candidate.download_job_log(job, token), proof)
    _require((evidence["release"]["deploymentId"], evidence["release"]["versionId"]) == (active.id, active.version)
        and evidence["release"]["flags"].get("externalShortlinksEnabled") is True
        and candidate.run_metadata(read_run(), run, attempt, proof["revision"], workflow["id"], candidate.DEPLOY_WORKFLOW) == metadata, ERROR)


def prepare(ctx):
    env, scope = ctx.env, ctx.scope
    failure_phase("prepare-inputs")
    _require(env.get("SHORTLINK_FAULT_CONFIRMATION") == "drill shortlink fallback for subs-bot-cf-dev-01"
        and _matches(COHORT, env.get("SHORTLINK_FAULT_COHORT")), ERROR)
    failure_phase("artifact")
    proof = artifact.prepare()
    failure_phase("artifact-manifest")
    bundle = ctx.directory / artifact.VERIFIED_DIRECTORY
    manifest = artifact._parse_object(read_private(bundle / "isolation.json", 1_048_576), ERROR)
    failure_phase("resources")
    scope.verify_resources()
    failure_phase("config")
    config = scope.worker_config()
    failure_phase("active")
    original_active = scope.active()
    failure_phase("version")
    original = scope.version(original_active.version)
    failure_phase("artifact-identity")
    module, base = _artifact(bundle, manifest, ctx.raw_policy, ctx.aggregate, ctx.private, original.provider_binding)
    _require((original.revision, original.digest, original.compatibility, original.telegram_config_sha256,
        original.telegram_aggregate_key_sha256, original.telegram_private_share_key_sha256)
        == (base.revision, base.digest, base.compatibility, base.telegram_config_sha256,
            base.telegram_aggregate_key_sha256, base.telegram_private_share_key_sha256), ERROR)
    failure_phase("ordinary-tag")
    _require(original.tag == _ordinary_tag(base, original), ERROR)
    failure_phase("cron")
    _require(scope.cron_enabled(), ERROR)
    failure_phase("shortlink-identity")
    external.target(original, None, ctx.business, capable=base.external_shortlink_capable,
        telegram_digest=base.telegram_config_sha256, aggregate_digest=base.telegram_aggregate_key_sha256)
    canary = canary_version(original)
    failure_phase("ordinary-proof")
    ordinary_deployment(env, proof, original_active)
    failure_phase("schema")
    migrations = _load_migrations(bundle, manifest)
    state, history = _read_state(scope.data_api, ctx.db_path, migrations)
    _require(state == "managed" and len(history) == len(migrations), ERROR)
    failure_phase("idle")
    ctx.idle()
    failure_phase("health")
    _verify_health(original.revision)
    failure_phase("cohort")
    cohort = ctx.cohort(env["SHORTLINK_FAULT_COHORT"])
    baseline = cohort.prepare(sign(ctx.key, [proof, env["SHORTLINK_FAULT_COHORT"]]))

    def unchanged():
        failure_phase("preupload-recheck")
        artifact.require_current_main(original.revision)
        _require(scope.active() == original_active and scope.version(original_active.version) == original
            and scope.worker_config() == config and scope.cron_enabled(), ERROR)
        ctx.idle()

    unchanged()
    failure_phase("upload-R")
    recovery_id = scope.upload(module, original, ctx.raw_policy, ctx.aggregate, ctx.private, ctx.business)
    unchanged()
    failure_phase("upload-C")
    canary_id = scope.upload(module, canary, ctx.raw_policy, ctx.aggregate, ctx.private, INVALID_TOKEN)
    unchanged()
    failure_phase("cohort-recheck")
    _require(cohort.prepare(baseline["identity"]) == baseline, ERROR)
    failure_phase("checkpoint")
    checkpoint = {"version": 1, "revision": original.revision, "operationRunId": env["GITHUB_RUN_ID"],
        "operationRunAttempt": env["GITHUB_RUN_ATTEMPT"], "cohort": env["SHORTLINK_FAULT_COHORT"],
        "scopeSha256": ctx.scope_sha, "createdAt": int(time()), "originalVersionId": original_active.version,
        "recoveryVersionId": recovery_id, "canaryVersionId": canary_id, "originalVersion": asdict(original),
        "canaryVersion": asdict(canary), "workerConfigSha256": digest(config), "ciProof": proof, "receiptBaseline": baseline}
    sealed = seal(ctx.key, checkpoint)
    open_checkpoint(ctx.key, sealed, ctx.scope_sha, run_id=env["GITHUB_RUN_ID"], attempt=env["GITHUB_RUN_ATTEMPT"])
    save_private_json(ctx.directory / CHECKPOINT, sealed)
    return {"phase": "prepared", "revision": original.revision, "recoveryVersionId": recovery_id,
        "canaryVersionId": canary_id, "checkpointSha256": digest(sealed), "activeChanged": False}


def recovery_module(scope, version_id, original):
    """Read the signed normal version's sole module, independently of old CI retention."""
    _require(scope.version(version_id) == original, ERROR)
    version = scope.worker_api("GET", f"{scope.versions}/{version_id}?include=modules")
    _require(isinstance(version, dict) and version.get("id") == version_id and version.get("main_module") == "index.js", ERROR)
    modules = version.get("modules")
    _require(isinstance(modules, list) and len(modules) == 1 and isinstance(modules[0], dict), ERROR)
    module = modules[0]
    content = module.get("content_base64")
    _require(module.get("name") == "index.js" and module.get("content_type") == "application/javascript+module"
        and isinstance(content, str) and 0 < len(content) <= 4 * ((MAX_MODULE_BYTES + 2) // 3), ERROR)
    try:
        body = base64.b64decode(content, validate=True)
    except (ValueError, TypeError):
        raise CloudflareError(ERROR) from None
    _require(0 < len(body) <= MAX_MODULE_BYTES and sha256(body).hexdigest() == original.digest, ERROR)
    return body


def restore(ctx, checkpoint, original, canary):
    """Never overwrite a foreign deployment; recovery does not depend on old CI retention or main tip."""
    failure_phase("restore-preflight")
    ctx.verify(checkpoint, current=True, healthy=False)
    failure_phase("restore-version")
    active = ctx.scope.active()
    if active.version == checkpoint["canaryVersionId"]:
        _require(ctx.scope.version(active.version) == canary, ERROR)
        def guard():
            _require(ctx.scope.active() == active and ctx.scope.version(active.version) == canary, ERROR)
            ctx.verify(checkpoint, current=True, healthy=False)
        failure_phase("restore-module")
        module = recovery_module(ctx.scope, checkpoint["recoveryVersionId"], original)
        guard()
        # Secret changes can prohibit deploying an older version. Upload the exact
        # normal bundle and protected original secrets forward; never force rollback.
        failure_phase("restore-upload")
        forward_id = ctx.scope.upload(module, original, ctx.raw_policy, ctx.aggregate, ctx.private, ctx.business)
        _require(forward_id not in {checkpoint["originalVersionId"], checkpoint["recoveryVersionId"], checkpoint["canaryVersionId"]}
            and ctx.scope.version(forward_id) == original, ERROR)
        guard()
        failure_phase("restore-activation")
        active = ctx.activate(active, forward_id, canary, original,
            f"Restore isolated shortlink fault drill {checkpoint['operationRunId']}/{checkpoint['operationRunAttempt']}", guard)
    else:
        # An interrupted activation may have succeeded before its receipt was saved.
        # An unknown ID is accepted only as an exact, already-normal readback; no write.
        _require(ctx.scope.version(active.version) == original, ERROR)
    failure_phase("restore-readback")
    _require(ctx.scope.active() == active and ctx.scope.version(active.version) == original, ERROR)
    ctx.verify(checkpoint, current=True)
    _require(ctx.scope.active() == active and ctx.scope.version(active.version) == original, ERROR)
    return {"phase": "restored", "revision": original.revision, "versionId": active.version,
        "deploymentId": active.id, "configurationReadback": "Passed", "postRestoreBusinessRPC": "Not run"}


def failure_evidence(ctx, checkpoint, activated_at):
    cohort = ctx.cohort(checkpoint["cohort"])
    history = cohort.history(checkpoint["receiptBaseline"]["afterReceiptId"])
    _require(len(history) <= 2, ERROR)
    _require(not any(row.get("state") in {"failed", "uncertain"} for row in history), ERROR)
    if len(history) < 2 or any(row.get("state") in {"pending", "leased", "sending"} for row in history):
        return None
    _require(all(row.get("state") == "sent" and type(row.get("message_date")) is int
        and row["message_date"] > activated_at for row in history), ERROR)
    evidence, codes, fingerprint = cohort.inspect(checkpoint["receiptBaseline"], retired=False)
    http, external_rows = {}, []
    for role, code in codes.items():
        local_hash = sha256((ORIGIN + "/s/" + code).encode("ascii")).hexdigest()
        found = ctx.read("SELECT operation_id,domain,attempts,terminal,short_url,lease_id,lease_until "
            "FROM telegram_external_shortlinks WHERE bot_id=? AND local_sha256=?", ctx.policy["botId"], local_hash)
        _require(len(found) == 1 and set(found[0]) == {"operation_id", "domain", "attempts", "terminal", "short_url", "lease_id", "lease_until"}, ERROR)
        row = found[0]
        _require(_matches(UUID, row["operation_id"]) and (row["domain"], row["attempts"], row["terminal"],
            row["short_url"], row["lease_id"], row["lease_until"]) == ("gfw.mom", 1, 1, None, None, None), ERROR)
        external_rows.append(row)
        http[role] = probe_code(code, cohort.targets[role], active=True)
    _require(len({row["operation_id"] for row in external_rows}) == 2
        and cohort.inspect(checkpoint["receiptBaseline"], retired=False)[2] == fingerprint, ERROR)
    return {"phase": "fallback-verified", "rpcFailureFallbackEvidence": "Passed", "sentIssueCount": 2,
        "codeSha256": evidence["codeSha256"], "http": http, "externalAttemptsPerLink": 1,
        "externalRowsSha256": sign(ctx.key, external_rows), "httpResponseStatusObserved": "Not run",
        "humanFallbackText": "Not run"}


def run_drill(ctx, checkpoint, original, canary, *, wait=sleep, clock=monotonic, poll_seconds=POLL_SECONDS):
    failure_phase("run-preflight")
    _require(0 < poll_seconds <= POLL_SECONDS and int(time()) - checkpoint["createdAt"] in range(601)
        and (checkpoint["operationRunId"], checkpoint["operationRunAttempt"])
            == (ctx.env["GITHUB_RUN_ID"], ctx.env["GITHUB_RUN_ATTEMPT"]), ERROR)
    ctx.verify(checkpoint, current=True)
    ctx.idle()
    active = ctx.scope.active()
    _require(active.version == checkpoint["originalVersionId"] and ctx.scope.version(active.version) == original
        and ctx.scope.version(checkpoint["canaryVersionId"]) == canary, ERROR)
    artifact.require_current_main(checkpoint["revision"])
    result = None
    try:
        failure_phase("run-activation")
        active = ctx.activate(active, checkpoint["canaryVersionId"], original, canary,
            f"Isolated shortlink fault drill {checkpoint['operationRunId']}/{checkpoint['operationRunAttempt']}",
            lambda: artifact.require_current_main(checkpoint["revision"]))
        ctx.verify(checkpoint, current=True)
        _require(ctx.scope.version(active.version) == canary, ERROR)
        activated_at, deadline = int(time()), clock() + poll_seconds
        failure_phase("run-acceptance")
        print(json.dumps({"phase": "canary-active", "canaryVersionId": active.version,
            "waitSecondsMaximum": poll_seconds, "cohort": checkpoint["cohort"]}), flush=True)
        while clock() < deadline:
            _require(ctx.scope.active() == active and ctx.scope.version(active.version) == canary, ERROR)
            result = failure_evidence(ctx, checkpoint, activated_at)
            if result is not None:
                break
            wait(min(3, max(0, deadline - clock())))
        _require(result is not None, "The bounded shortlink fallback acceptance timed out; recovery is required and retained.")
        save_private_json(ctx.directory / RESULT, result)
        return result
    except Exception as error:
        remember_failure(error)
        raise
    finally:
        restored = restore(ctx, checkpoint, original, canary)
        save_private_json(ctx.directory / RESTORE_RESULT, restored)
        print(json.dumps(restored, sort_keys=True), flush=True)


def main(env):
    failure_phase("entry")
    ctx = Context(env)
    phase, action = env.get("SHORTLINK_FAULT_PHASE"), env.get("SHORTLINK_FAULT_ACTION")
    _require((action == "drill" and phase in {"prepare", "run", "restore"}) or (action == "restore" and phase == "restore"), ERROR)
    if phase == "prepare":
        return prepare(ctx)
    if action == "restore":
        _require(env.get("SHORTLINK_FAULT_CONFIRMATION") == "restore shortlink fallback for subs-bot-cf-dev-01", ERROR)
        run, attempt = env.get("SHORTLINK_FAULT_CHECKPOINT_RUN_ID", ""), env.get("SHORTLINK_FAULT_CHECKPOINT_RUN_ATTEMPT", "")
        value = read_recovery_artifact(run, attempt, artifact._github_token())
    else:
        run, attempt = env["GITHUB_RUN_ID"], env["GITHUB_RUN_ATTEMPT"]
        value = artifact._parse_object(read_private(ctx.directory / CHECKPOINT, MAX_CHECKPOINT), ERROR)
    checkpoint, original, canary = open_checkpoint(ctx.key, value, ctx.scope_sha, run_id=run, attempt=attempt)
    _require(original.external_shortlink_token_sha256 == sha256(ctx.business.encode("ascii")).hexdigest(), ERROR)
    if phase == "run":
        return run_drill(ctx, checkpoint, original, canary)
    result = restore(ctx, checkpoint, original, canary)
    save_private_json(ctx.directory / RESTORE_RESULT, result)
    return result


if __name__ == "__main__":
    def interrupted(_number, _frame):
        raise CloudflareError("The shortlink fault drill was interrupted; its signed recovery checkpoint is retained.")
    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        print(json.dumps(main(os.environ), sort_keys=True), flush=True)
    except Exception as error:
        print(json.dumps(failure_projection(error), sort_keys=True), flush=True)
        sys.exit(ERROR + " Use the protected restore action if restoration was not independently confirmed.")

"""Build a review-only package from immutable GitHub evidence. No Cloudflare client is used.

Raw deployment logs and signed download URLs stay in memory. Only allowlisted
proofs, booleans, counts and digests can enter the generated package.
"""

from datetime import datetime, timezone
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

import prepare_isolation_artifact as artifact

ERROR = "The production candidate review package could not be verified."
WORKFLOW = "jacklilyhello/subs-bot/.github/workflows/worker-production-candidate.yml@refs/heads/main"
DEPLOY_WORKFLOW = ".github/workflows/worker-isolation-deploy.yml"
MAX_LOG_BYTES = 16 * 1024 * 1024
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
DIGEST = re.compile(r"[0-9a-f]{64}")
UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
FLAG = re.compile(r"[a-z][A-Za-z0-9]{0,63}(?:Enabled|Capable)")
NAME = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
TIMESTAMP = re.compile(r"^20[0-9]{2}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z (.*)$")
PROOF_KEYS = {"revision", "runId", "runAttempt", "artifactId", "archiveSha256"}
RESULT_KEYS = {"revision", "deploymentId", "versionId", "previousVersionId", "changed"}
SERVICE_METADATA = {"externalShortlinkService": "shortlink-new", "externalShortlinkEntrypoint": "ShortlinkService"}
SHORTLINK_BINDINGS = {"SHORTLINK", "SHORTLINK_BUSINESS_TOKEN", "SHORTLINK_BUSINESS_TOKEN_SHA256", "SHORTLINK_RELEASE_BASE_TAG"}
METADATA_BINDINGS = {"SHORTLINK_BUSINESS_TOKEN_SHA256", "SHORTLINK_RELEASE_BASE_TAG"}
BASE_BINDINGS = {"DB", "NODES", "BUILD_REVISION", "TELEGRAM_ISOLATION_CONFIG", "TELEGRAM_CONFIG_SHA256"}
FLAG_BINDINGS = {
    "inlineSearchEnabled": {"TELEGRAM_INLINE_SEARCH"},
    "providerUrlImportEnabled": {"TELEGRAM_PROVIDER_URL_IMPORT", "PROVIDER_FETCH", "PROVIDER_REVISION", "PROVIDER_IMAGE_SHA256"},
    "providerRefreshEnabled": {"TELEGRAM_PROVIDER_REFRESH", "PROVIDER_FETCH"},
    "providerUrlDocumentsEnabled": {"TELEGRAM_PROVIDER_URL_DOCUMENTS", "PROVIDER_FETCH"},
    "mixedDocumentsEnabled": {"TELEGRAM_MIXED_DOCUMENTS"},
    "providerBatchEnabled": {"TELEGRAM_PROVIDER_BATCH_REFRESH", "PROVIDER_FETCH"},
    "apiStatusEnabled": {"TELEGRAM_API_STATUS", "PROVIDER_API_STATUS", "PROVIDER_API_STATUS_REVISION", "PROVIDER_API_STATUS_IMAGE_SHA256"},
    "groupShareCardsEnabled": {"TELEGRAM_GROUP_SHARE_CARDS", "TELEGRAM_PRIVATE_SHARE_CREATION_KEY"},
    "legacySubscriptionShortsEnabled": {"LEGACY_SUBSCRIPTION_SHORTS"},
    "subscriptionShortsEnabled": {"TELEGRAM_SUBSCRIPTION_SHORTS", "TELEGRAM_AGGREGATE_KEY"},
    "externalShortlinksEnabled": SHORTLINK_BINDINGS | {"TELEGRAM_EXTERNAL_SHORTLINKS"},
}


def require(value):
    if not value:
        raise artifact.ArtifactError(ERROR)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii") + b"\n"


def parsed(raw):
    require(isinstance(raw, (str, bytes)) and len(raw) <= 65536)
    return json.loads(raw, object_pairs_hook=artifact._unique_json_object,
                     parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))


def run_metadata(value, run_id, attempt, revision, workflow_id, workflow_path):
    require(isinstance(value, dict) and str(value.get("id")) == run_id and str(value.get("run_attempt")) == attempt
        and value.get("workflow_id") == workflow_id and value.get("path") in (workflow_path, workflow_path + "@main", workflow_path + "@refs/heads/main")
        and (value.get("event"), value.get("head_branch"), value.get("head_sha"), value.get("status"), value.get("conclusion"))
            == ("workflow_dispatch", "main", revision, "completed", "success")
        and all(isinstance(value.get(key), dict) and value[key].get("id") == artifact.REPOSITORY_ID
                for key in ("repository", "head_repository")))
    return {"runId": run_id, "runAttempt": attempt, "revision": revision, "workflow": workflow_path,
            "url": f"https://github.com/{artifact.REPOSITORY}/actions/runs/{run_id}/attempts/{attempt}", "conclusion": "success"}


def deploy_job(value, run_id=None, attempt=None, revision=None):
    require(isinstance(value, dict) and value.get("total_count", 101) <= 100 and isinstance(value.get("jobs"), list))
    jobs = [job for job in value["jobs"] if isinstance(job, dict) and job.get("name") == "deploy"]
    require(len(jobs) == 1)
    job = jobs[0]
    require(type(job.get("id")) is int and DECIMAL.fullmatch(str(job["id"]))
        and (job.get("status"), job.get("conclusion")) == ("completed", "success") and isinstance(job.get("steps"), list))
    if run_id is not None:
        require(str(job.get("run_id")) == run_id and str(job.get("run_attempt")) == attempt and job.get("head_sha") == revision)
    for name in ("Verify merged artifact provenance and digests", "Release the verified Worker or stage page jump closed"):
        steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    return str(job["id"])


def download_job_log(job_id, token):
    """Follow only the authenticated GitHub API's temporary HTTPS log redirect, without forwarding credentials."""
    try:
        with artifact._OPENER.open(artifact._api_request(f"/actions/jobs/{job_id}/logs", token), timeout=20) as response:
            return artifact._bounded_read(response, MAX_LOG_BYTES)
    except HTTPError as exc:
        with exc:
            location = exc.headers.get("Location", "") if exc.code == 302 else ""
    except (OSError, URLError, HTTPException):
        raise artifact.ArtifactError(ERROR) from None
    require(isinstance(location, str) and re.fullmatch(r"[!-~]{1,8192}", location) and "\\" not in location)
    url = urlsplit(location)
    require(url.scheme == "https" and url.hostname and url.username is None and url.password is None
        and url.port in (None, 443) and not url.fragment
        and (url.hostname.endswith(".blob.core.windows.net") or url.hostname.endswith(".githubusercontent.com")))
    try:
        with artifact._OPENER.open(Request(location, headers={"Accept-Encoding": "identity"}), timeout=60) as response:
            return artifact._bounded_read(response, MAX_LOG_BYTES)
    except (OSError, URLError, HTTPException):
        raise artifact.ArtifactError(ERROR) from None


def deployment_proofs(raw, ci_proof):
    require(isinstance(raw, bytes) and len(raw) <= MAX_LOG_BYTES)
    text = raw.decode("utf-8", errors="strict")
    proofs, results, migration_counts = [], [], []
    for line in text.splitlines():
        match = TIMESTAMP.fullmatch(line)
        if not match:
            continue
        payload = match[1]
        count = re.fullmatch(r"Verified ([1-9][0-9]{0,2}) isolated D1 migration records\.", payload)
        if count:
            migration_counts.append(int(count[1]))
        if not payload.startswith("{"):
            continue
        try:
            value = parsed(payload)
        except (ValueError, TypeError):
            continue
        if not isinstance(value, dict):
            continue
        if set(value) == PROOF_KEYS:
            require(value == ci_proof)
            proofs.append(value)
        if RESULT_KEYS <= value.keys():
            require(value["revision"] == ci_proof["revision"] and type(value["changed"]) is bool
                and all(isinstance(value[key], str) and UUID.fullmatch(value[key])
                        for key in ("deploymentId", "versionId", "previousVersionId")))
            metadata = {key: item for key, item in value.items() if key in SERVICE_METADATA}
            require(not metadata or metadata == SERVICE_METADATA)
            flags = {key: item for key, item in value.items() if key not in RESULT_KEYS | SERVICE_METADATA.keys()}
            require(flags and all(FLAG.fullmatch(key) and type(item) is bool for key, item in flags.items()))
            require(("externalShortlinksEnabled" in flags) == bool(metadata))
            results.append({**{key: value[key] for key in RESULT_KEYS}, "flags": dict(sorted(flags.items())),
                            **({"serviceMetadata": metadata} if metadata else {})})
    require(len(proofs) == len(results) == len(migration_counts) == 1)
    return {"ciProof": proofs[0], "release": results[0], "migrationCount": migration_counts[0],
            "jobLogSha256": sha256(raw).hexdigest(), "basis": "historical-protected-workflow-log", "liveReadback": False}


def expectations(flags_raw, bindings_raw, deployment, module):
    flags, requested = parsed(flags_raw), parsed(bindings_raw)
    require(isinstance(flags, dict) and len(flags) <= 32 and all(FLAG.fullmatch(key) and type(value) is bool for key, value in flags.items()))
    historical = deployment["release"]["flags"]
    require(all(key in historical and historical[key] == value for key, value in flags.items()))
    require(isinstance(requested, list) and len(requested) <= 48
        and all(isinstance(name, str) and NAME.fullmatch(name) for name in requested) and len(set(requested)) == len(requested))
    names = set(BASE_BINDINGS) | set(requested)
    for flag, bindings in FLAG_BINDINGS.items():
        if historical.get(flag):
            names.update(bindings)
    if deployment["release"].get("serviceMetadata") == SERVICE_METADATA:
        names.update(SHORTLINK_BINDINGS)
    require(all(name.encode("ascii") in module for name in names - METADATA_BINDINGS))
    services = []
    for binding, service, entrypoint in (("PROVIDER_FETCH", "subs-bot-provider-fetch-dev-01", "ProviderFetch"),
            ("PROVIDER_API_STATUS", "subs-bot-provider-api-status-dev-01", "ProviderApiStatus"),
            ("SHORTLINK", "shortlink-new", "ShortlinkService")):
        if binding in names:
            services.append({"binding": binding, "service": service, "entrypoint": entrypoint, "status": "Not run"})
    return {"scope": "isolated-candidate; production resource bindings require a separate approved plan", "serviceExpectations": services,
        "flags": historical, "requestedFlagExpectations": flags, "bindingNames": sorted(names),
        "bindingInventoryStatus": "Not run", "bindingValuesStatus": "Not run",
        "basis": "review-expectations-from-verified-source-and-historical-flags", "liveVerified": False,
        "displayTimezone": {"default": "UTC", "persistedSelectionStatus": "Not run"}}


def make_manifest(ci_proof, isolation, deployment, deploy_run, configuration, *, source_kind, source_sha):
    require(source_kind in ("not-supplied", "synthetic-fixture") and (source_sha == "" or DIGEST.fullmatch(source_sha))
        and (source_kind != "not-supplied" or source_sha == ""))
    migrations = [{"name": entry["name"], "sha256": entry["sha256"]} for entry in isolation["migrations"]]
    require(deployment["migrationCount"] == len(migrations))
    not_run = lambda reason: {"status": "Not run", "reason": reason}
    return {
        "version": 1, "kind": "production-candidate-review-only", "productionReady": False,
        "productionMutationPerformed": False, "productionAuthorization": "not-granted", "reservedProductionHostname": "subs-bot.lilyya.top",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "source": {"revision": ci_proof["revision"], "ciProof": ci_proof, "deployRun": deploy_run},
        "artifact": {"moduleSha256": isolation["bundleSha256"], "compatibilityDate": isolation["compatibilityDate"],
            "migrations": migrations, "migrationCount": len(migrations)},
        "historicalIsolationDeployment": deployment, "configurationExpectations": configuration,
        "validation": {
            "hostedWorkerCI": {"status": "Passed", "scope": "exact verified main CI artifact; synthetic coverage only"},
            "historicalIsolationDeployment": {"status": "Passed", "scope": "same CI proof and successful protected workflow attempt"},
            "liveVersionBindingsMigrations": not_run("This package performs no live Cloudflare request; independently read back before approval."),
            "realSQLiteRehearsal": not_run("A real source backup, WAL consistency and ownership reconciliation were not evaluated."),
            "humanTelegramAcceptance": not_run("Two-account and approved-group evidence must be reviewed separately; CI is not human acceptance."),
            "syntheticIsolationAcceptance": not_run("A successful deployment does not establish the individual live acceptance cases."),
        },
        "dataSource": {"kind": source_kind, "sha256": source_sha or None, "realDataImportAuthorized": False,
            "finalConsistentBackup": "Not run", "ownershipAndCountsReconciled": "Not run",
            "emptyDatabaseApproved": False, "discardLegacyLinksApproved": False},
        "recovery": {"strategy": "retain-current-cloudflare-data-and-use-a-compatible-worker-version",
            "sqliteFallbackAllowed": False, "cloudflareNewWritesMustBePreserved": True,
            "consistentD1AndR2RecoveryRehearsal": "Not run", "restoreIntoUnboundTargetsFirst": True},
        "requiredBeforeProduction": [
            "Independent live readback of exact version, bindings, flags, migration ledger, Cron and timezone",
            "Complete synthetic and two-account full general-path acceptance, including shortlink RPC and revocation",
            "Authorized final SQLite backup including WAL; ownership/count/object/link reconciliation in an isolated target",
            "Close new admission; preserve Cron and dependencies; verify classified drain and uncertain-delivery handling",
            "Approve a production window and exact resource/domain/webhook operations with a compatible rollback target",
            "Stop and drain the old consumer only in the approved window; fix final data and Telegram update watermarks",
            "Preserve pending Telegram updates; never enable two consumers against divergent databases",
            "Seal Cloudflare new writes before any data recovery; never resume stale SQLite as a lossless rollback",
        ],
    }


def write_package(directory, manifest):
    directory.mkdir(mode=0o700)
    raw = canonical(manifest)
    digest = sha256(raw).hexdigest()
    files = {"candidate.json": raw, "candidate.sha256": (digest + "  candidate.json\n").encode("ascii"),
        "review.md": ("# Production candidate review package\n\n"
            "Review only. `productionReady` is **false**. No production operation was performed.\n\n"
            f"Revision: `{manifest['source']['revision']}`\n\n"
            "Passed: exact main Worker CI artifact and matching historical isolation workflow evidence.\n\n"
            "Not run: live Cloudflare readback, real SQLite rehearsal, live synthetic acceptance and human Telegram acceptance.\n\n"
            "Binding names and flags are review expectations, not a current live inventory.\n\n"
            "Before production:\n\n" + "".join(f"- {item}\n" for item in manifest["requiredBeforeProduction"])).encode("utf-8")}
    for name, body in files.items():
        with (directory / name).open("xb") as stream:
            stream.write(body)
        (directory / name).chmod(0o600)
    return digest


def main(env):
    require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID))
    revision = env.get("GITHUB_SHA", "")
    token = artifact._github_token()
    artifact.require_current_main(revision)
    ci_run, ci_attempt, deploy_run, deploy_attempt = [env.get(key, "") for key in (
        "CANDIDATE_CI_RUN_ID", "CANDIDATE_CI_RUN_ATTEMPT", "CANDIDATE_DEPLOY_RUN_ID", "CANDIDATE_DEPLOY_RUN_ATTEMPT")]
    require(all(DECIMAL.fullmatch(value) for value in (ci_run, ci_attempt, deploy_run, deploy_attempt)))
    selection = lambda: artifact.select_main_artifact(ci_run, revision, token, workflow_id=artifact.WORKFLOW_ID,
        workflow_path=artifact.WORKFLOW_PATH, artifact_prefix="subs-bot-worker", workflow_label="Worker CI", run_attempt=ci_attempt)
    attempt, artifact_id, archive_sha = selection()
    ci_proof = {"revision": revision, "runId": ci_run, "runAttempt": attempt, "artifactId": artifact_id, "archiveSha256": archive_sha}
    temp = Path(env["RUNNER_TEMP"])
    artifact._unpack(artifact._download(artifact_id, token), archive_sha, revision, ci_run, attempt, temp)
    require(selection() == (attempt, artifact_id, archive_sha))
    bundle = temp / artifact.VERIFIED_DIRECTORY
    isolation = artifact._parse_object((bundle / "isolation.json").read_bytes(), ERROR)
    workflow = artifact._get_json("/actions/workflows/worker-isolation-deploy.yml", token)
    require(isinstance(workflow, dict) and type(workflow.get("id")) is int and workflow.get("path") == DEPLOY_WORKFLOW)
    read_run = lambda: artifact._get_json(f"/actions/runs/{deploy_run}/attempts/{deploy_attempt}", token)
    metadata = run_metadata(read_run(), deploy_run, deploy_attempt, revision, workflow["id"], DEPLOY_WORKFLOW)
    job_id = deploy_job(artifact._get_json(f"/actions/runs/{deploy_run}/attempts/{deploy_attempt}/jobs?per_page=100", token),
        deploy_run, deploy_attempt, revision)
    deployment = deployment_proofs(download_job_log(job_id, token), ci_proof)
    deployment["jobId"] = job_id
    configuration = expectations(env.get("CANDIDATE_EXPECTED_FLAGS", "{}"), env.get("CANDIDATE_EXPECTED_BINDINGS", "[]"),
        deployment, (bundle / "index.js").read_bytes())
    manifest = make_manifest(ci_proof, isolation, deployment, metadata, configuration,
        source_kind=env.get("CANDIDATE_DATA_SOURCE_KIND", "not-supplied"), source_sha=env.get("CANDIDATE_DATA_SOURCE_SHA256", ""))
    require(run_metadata(read_run(), deploy_run, deploy_attempt, revision, workflow["id"], DEPLOY_WORKFLOW) == metadata)
    artifact.require_current_main(revision)
    digest = write_package(temp / "subs-bot-production-candidate", manifest)
    print(json.dumps({"candidateSha256": digest, "revision": revision, "productionReady": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main(os.environ)
    except (artifact.ArtifactError, OSError, ValueError, TypeError, KeyError, RecursionError):
        raise SystemExit(ERROR) from None

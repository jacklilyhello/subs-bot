"""Read-only first-launch evidence for initializing the project backup scope.

This is deliberately limited to newly provisioned, undeployed resources. It
never creates a pin or writes to D1, R2, Workers, GitHub or Telegram. Operator
review of the exact bounded writer inventory and custody assumptions is required.
"""
import base64
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.client import HTTPException
import re
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode

import prepare_isolation_artifact as github
import production_backup_coordinator as coordinator
import production_backup_schedule as schedule
import production_control as control
import scoped_r2
from production_target import canonical, digest, parsed, require, validate_target

HEX = re.compile(r"[a-f0-9]{64}")
REV = re.compile(r"[a-f0-9]{40}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
WORKFLOW = re.compile(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml")
CUSTODY = "new-project-reviewed-writers-no-unapproved-deletion"


def _stamp(raw):
    require(isinstance(raw, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", raw))
    try:
        return datetime.fromisoformat(raw[:-1] + "+00:00").astimezone(timezone.utc)
    except ValueError:
        require(False, "A new-resource creation time is invalid.")


def _sha(raw):
    return sha256(raw).hexdigest()


def _get_json(path, token):
    """One bounded GH read; no hidden retries after a mutation has begun."""
    require(isinstance(path, str) and path.startswith("/") and not path.startswith("//"))
    try:
        with github._OPENER.open(github._api_request(path, token), timeout=20) as response:
            require(getattr(response, "status", None) == 200)
            return github._parse_object(github._bounded_read(response, 1024 * 1024),
                                        "The bootstrap GitHub read is unavailable.")
    except (HTTPError, URLError, OSError, HTTPException):
        raise ValueError("The bootstrap GitHub read is unavailable.") from None


def _require_current_main(revision, token):
    require(REV.fullmatch(revision or ""))
    ref = _get_json("/git/ref/heads/main", token)
    obj = ref.get("object")
    require(ref.get("ref") == github.MAIN_REF and isinstance(obj, dict)
            and (obj.get("type"), obj.get("sha")) == ("commit", revision), "The bootstrap main revision changed.")


def _protected_inputs(env, review_raw, review_pin, registration_sha256=None):
    require(isinstance(review_raw, str)
            and env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON") == review_raw
            and env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256") == review_pin)
    if registration_sha256 is not None:
        require(env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REGISTRATION_SHA256") == registration_sha256)


def empty_source_bucket(target, data_objects):
    require(type(data_objects) is scoped_r2.ScopedR2 and data_objects.write_credential is None
            and data_objects.bucket == target.data["bucketName"]
            and data_objects.host == target.account_id + ".r2.cloudflarestorage.com"
            and data_objects.bucket != target.data["backupBucketName"])
    require(data_objects.list("", maximum=10000) == [] and data_objects.list("", maximum=10000) == [],
            "A first-launch source bucket must be empty.")


def provision_original(target, objects, anchor_objects, registration_sha256, *, expected_new_bucket_keys=None):
    """Read the registration and its complete separately stored provision chain."""
    require(target.environment == "production" and type(objects) is scoped_r2.ScopedR2
            and type(anchor_objects) is scoped_r2.ScopedR2 and objects.write_credential is None
            and anchor_objects.write_credential is None and objects.bucket == target.data["backupBucketName"]
            and objects.host == target.account_id + ".r2.cloudflarestorage.com"
            and anchor_objects.host == objects.host and HEX.fullmatch(registration_sha256 or ""))
    registration_key = "maintenance/production-control/registrations/" + target.digest + ".json"
    keys = objects.list("", maximum=10000)
    expected = [registration_key] if expected_new_bucket_keys is None else sorted(expected_new_bucket_keys)
    require(keys == expected and registration_key in expected, "The new backup bucket has missing or unexpected objects.")
    raw, _ = objects.get(registration_key, limit=65536)
    receipt = parsed(raw)
    require(canonical(receipt) == raw and _sha(raw) == registration_sha256
            and receipt.get("state") == "created-no-module-no-consumer"
            and receipt.get("targetSha256") == target.digest and receipt.get("target") == target.data
            and HEX.fullmatch(receipt.get("draftSha256", "")) and REV.fullmatch(receipt.get("revision", ""))
            and DECIMAL.fullmatch(receipt.get("runId", "")) and receipt.get("runAttempt") == "1"
            and isinstance(receipt.get("resources"), dict) and isinstance(receipt.get("intents"), dict))
    resources, intents, t = receipt["resources"], receipt["intents"], target.data
    require(set(resources) == {"database", "bucketName", "backupBucketName", "worker"}
            and set(intents) == set(resources) and all(isinstance(intents[k], dict)
                and intents[k].get("state") in {"confirmed", "independently-confirmed"} for k in resources))
    require(resources["database"] == {"id": t["d1Id"], "name": t["d1Name"], "createdAt": t["d1CreatedAt"]}
            and resources["worker"] == {"id": t["workerId"], "name": t["workerName"], "createdOn": t["workerCreatedOn"]}
            and all(isinstance(resources[k], dict) and resources[k].get("name") == t[k]
                    and resources[k].get("createdAt") == t["bucketCreatedAt" if k == "bucketName" else "backupBucketCreatedAt"]
                    for k in ("bucketName", "backupBucketName")))
    prefix = "maintenance/production-control/registrations/provision-" + receipt["draftSha256"] + "/"
    history = anchor_objects.list(prefix, maximum=128)
    require(0 < len(history) < 128 and len(history) == len(set(history)))
    previous = None
    for index, key in enumerate(history, 1):
        require(key == prefix + str(index).zfill(6) + ".json")
        body, _ = anchor_objects.get(key, limit=65536)
        envelope = parsed(body)
        require(canonical(envelope) == body and set(envelope) == {"generation", "previousSha256", "draftSha256", "value"}
                and type(envelope["generation"]) is int and envelope["generation"] == index
                and envelope["previousSha256"] == previous and envelope["draftSha256"] == receipt["draftSha256"]
                and isinstance(envelope["value"], dict))
        previous = _sha(body)
    require(envelope["value"] == receipt, "The retained provisioning chain does not match its registration.")
    # A second complete list catches changed page contents during observation.
    require(anchor_objects.list(prefix, maximum=128) == history and objects.list("", maximum=10000) == keys)
    return {"receipt": receipt, "registrationKey": registration_key, "registrationSha256": _sha(raw),
            "provisionJournalSha256": previous, "provisionJournalGenerations": len(history)}


def new_resource_observation(target, data_api, worker_api, metadata_api):
    """Recheck immutable identities and a pristine, undeployed source."""
    require(type(data_api) is control.API and type(worker_api) is control.API and type(metadata_api) is control.API
            and data_api.target == target.data and worker_api.target == target.data and metadata_api.target == target.data
            and data_api.create is False and worker_api.create is False and metadata_api.create is False)
    t, root = target.data, data_api.root
    db = data_api("GET", root + "/d1/database/" + t["d1Id"])
    require(isinstance(db, dict) and (db.get("uuid"), db.get("name"), db.get("created_at")) ==
            (t["d1Id"], t["d1Name"], t["d1CreatedAt"]))
    worker = worker_api("GET", root + "/workers/workers/" + t["workerId"])
    require(isinstance(worker, dict) and (worker.get("id"), worker.get("name"), worker.get("created_on")) ==
            (t["workerId"], t["workerName"], t["workerCreatedOn"])
            and set(worker.get("tags", [])) == {"subs-bot", "lifecycle-production"}
            and worker.get("logpush") is False and worker.get("tail_consumers") == []
            and worker.get("observability", {}).get("enabled") is False
            and isinstance(worker.get("references"), dict)
            and all(worker["references"].get(k) == [] for k in ("queues", "durable_objects", "dispatch_namespace_outbounds", "workers"))
            and worker.get("subdomain", {}).get("enabled") is False
            and worker.get("subdomain", {}).get("previews_enabled") is False)
    script = root + "/workers/scripts/" + t["workerName"]
    deployments = worker_api("GET", script + "/deployments", absent=True)
    require(deployments is None or isinstance(deployments, dict) and deployments.get("deployments") == [],
            "A previously deployed Worker is not a new first-launch source.")
    schedules = worker_api("GET", script + "/schedules", absent=True)
    require(schedules is None or isinstance(schedules, dict) and schedules.get("schedules") == [])
    tables = control.rows(data_api, root + "/d1/database/" + t["d1Id"],
        "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name<>'_cf_KV' ORDER BY name")
    require(tables == [], "A first-launch D1 database must be pristine before schema initialization.")
    buckets = [control.privacy(metadata_api, root, t[name], t[created]) for name, created in
               (("bucketName", "bucketCreatedAt"), ("backupBucketName", "backupBucketCreatedAt"))]
    return {"targetSha256": target.digest, "configurationSha256": target.configuration_digest,
            "resourcePinsSha256": digest(schedule.resource_pins(target)), "tables": 0,
            "activeDeployments": 0, "schedules": 0, "bucketsSha256": digest(buckets)}


def _pages(path, key, token, *, maximum=500):
    rows, seen, total = [], set(), None
    for page in range(1, 12):
        separator = "&" if "?" in path else "?"
        response = _get_json(path + separator + urlencode({"per_page": 50, "page": page}), token)
        batch, count = response.get(key), response.get("total_count")
        require(type(count) is int and 0 <= count <= maximum and isinstance(batch, list)
                and len(batch) == min(50, max(0, count - len(rows))))
        require(total is None or total == count, "The GH inventory changed between pages.")
        total = count
        for item in batch:
            require(isinstance(item, dict) and type(item.get("id")) is int and item["id"] > 0 and item["id"] not in seen)
            seen.add(item["id"])
            rows.append(item)
        if len(rows) == total:
            return rows
    require(False, "The GH inventory exceeds its verified bound.")


def _workflow_identity(path, revision, token):
    require(WORKFLOW.fullmatch(path or "") and REV.fullmatch(revision or ""))
    encoded = _get_json("/contents/" + quote(path, safe="/-_.") + "?" + urlencode({"ref": revision}), token)
    require(encoded.get("encoding") == "base64" and isinstance(encoded.get("content"), str))
    try:
        raw = base64.b64decode(encoded["content"].replace("\n", ""), validate=True)
    except (ValueError, TypeError):
        require(False, "The reviewed workflow original is unavailable.")
    require(0 < len(raw) <= 1024 * 1024)
    commit = _get_json("/git/commits/" + revision, token)
    require(commit.get("sha") == revision and isinstance(commit.get("tree"), dict)
            and REV.fullmatch(commit["tree"].get("sha", "")))
    return _sha(raw), commit["tree"]["sha"]


def _run_evidence(run, token):
    require(isinstance(run, dict) and type(run.get("id")) is int and run["id"] > 0
            and type(run.get("run_attempt")) is int and run["run_attempt"] == 1
            and run.get("status") == "completed" and isinstance(run.get("conclusion"), str)
            and isinstance(run.get("head_branch"), str) and 0 < len(run["head_branch"]) <= 255
            and isinstance(run.get("event"), str) and re.fullmatch(r"[a-z_]{1,64}", run["event"])
            and REV.fullmatch(run.get("head_sha", ""))
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    path = run.get("path", "").split("@", 1)[0]
    require(WORKFLOW.fullmatch(path or ""))
    _stamp(run.get("created_at"))
    run_id = str(run["id"])
    latest = _get_json("/actions/runs/" + run_id, token)
    require(str(latest.get("id")) == run_id and latest.get("run_attempt") == 1
            and latest.get("status") == "completed" and latest.get("head_sha") == run["head_sha"])
    jobs = _pages("/actions/runs/" + run_id + "/attempts/1/jobs", "jobs", token, maximum=100)
    require(jobs and all(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1
            and job.get("head_sha") == run["head_sha"] and job.get("status") == "completed"
            and isinstance(job.get("conclusion"), str) for job in jobs))
    workflow_sha, tree = _workflow_identity(path, run["head_sha"], token)
    return {"runId": run_id, "revision": run["head_sha"], "headBranch": run["head_branch"], "path": path, "event": run.get("event"),
            "createdAt": run.get("created_at"), "conclusion": run["conclusion"], "jobsSha256": digest(jobs),
            "workflowSha256": workflow_sha, "treeSha": tree}


def _bootstrap_run(run_id, revision, action, token, *, running):
    """Verify a fixed trusted bootstrap job; no workflow inputs are inferred."""
    require(DECIMAL.fullmatch(run_id or "") and REV.fullmatch(revision or "")
            and action in {"plan-schedule-anchor", "initialize-schedule-anchor"})
    run = _get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = _get_json("/actions/runs/" + run_id, token)
    path = ".github/workflows/worker-production-backup-coordinator.yml"
    for item in (run, latest):
        require(str(item.get("id")) == run_id and item.get("run_attempt") == 1 and item.get("head_sha") == revision
                and item.get("head_branch") == "main" and item.get("event") == "workflow_dispatch"
                and item.get("path") in {path, path + "@main", path + "@refs/heads/main"}
                and item.get("display_title") == "Production backup coordinator " + action + " at " + revision
                and item.get("status") == ("in_progress" if running else "completed")
                and (running or item.get("conclusion") == "success")
                and all(isinstance(item.get(k), dict) and item[k].get("id") == github.REPOSITORY_ID
                        for k in ("repository", "head_repository")))
    jobs = _pages("/actions/runs/" + run_id + "/attempts/1/jobs", "jobs", token, maximum=100)
    matched = [job for job in jobs if job.get("name") == "inspect_or_reconcile"]
    require(len(matched) == 1)
    job = matched[0]
    require(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == revision
            and job.get("status") == ("in_progress" if running else "completed")
            and job.get("conclusion") == (None if running else "success") and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == "Inspect or reconcile without workflow dispatch"]
    require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) ==
            (("in_progress", None) if running else ("completed", "success")))
    return True


def _provision_job(receipt, token):
    run_id, revision = receipt["runId"], receipt["revision"]
    run = _get_json("/actions/runs/" + run_id + "/attempts/1", token)
    require(str(run.get("id")) == run_id and run.get("run_attempt") == 1 and run.get("head_sha") == revision
            and run.get("display_title") == "Lifecycle production provision at " + revision
            and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "success")
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    jobs = _pages("/actions/runs/" + run_id + "/attempts/1/jobs", "jobs", token, maximum=100)
    matching = [job for job in jobs if job.get("name") == "control"]
    require(len(matching) == 1 and isinstance(matching[0].get("steps"), list)
            and str(matching[0].get("run_id")) == run_id and matching[0].get("run_attempt") == 1
            and matching[0].get("head_sha") == revision and matching[0].get("status") == "completed")
    for name in ("Execute an exact target lifecycle step", "Preserve new private registration"):
        steps = [step for step in matching[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))


def verify_first_launch_writers(env, review_raw, review_pin, token):
    """Freshly recheck the reviewed window and all runs after it, without writes."""
    _protected_inputs(env, review_raw, review_pin)
    raw = review_raw.encode("utf-8") if isinstance(review_raw, str) else review_raw
    review = parsed(raw)
    require(isinstance(raw, bytes) and canonical(review) == raw and HEX.fullmatch(review_pin or "") and _sha(raw) == review_pin
            and review.get("version") == 1 and type(review.get("version")) is int
            and review.get("kind") == "new-production-scope-bootstrap-review" and review.get("custody") == CUSTODY
            and review.get("noPriorInFlightWriter") is True and isinstance(review.get("reviewedRuns"), list)
            and len(review["reviewedRuns"]) <= 25 and DECIMAL.fullmatch(env.get("GITHUB_RUN_ID", ""))
            and REV.fullmatch(env.get("GITHUB_SHA", ""))
            and env.get("GITHUB_REPOSITORY") == github.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_RUN_ATTEMPT") == "1" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + github.MAIN_REF
            and env.get("BACKUP_COORDINATOR_ACTION") in {"plan-schedule-anchor", "initialize-schedule-anchor"})
    start, end = _stamp(review.get("windowStart")), _stamp(review.get("windowEnd"))
    now = datetime.now(timezone.utc)
    require(start <= end <= now and end - start <= timedelta(days=31))
    time_range = review["windowStart"] + ".." + review["windowEnd"]
    runs = _pages("/actions/runs?" + urlencode({"created": time_range}), "workflow_runs", token, maximum=26)
    reviewed = {entry.get("runId"): entry for entry in review["reviewedRuns"] if isinstance(entry, dict)}
    require(len(reviewed) == len(review["reviewedRuns"]) and all(DECIMAL.fullmatch(key or "") for key in reviewed))
    current_id = env["GITHUB_RUN_ID"]
    actual = [run for run in runs if str(run.get("id")) != current_id]
    require({str(run.get("id")) for run in actual} == set(reviewed), "The reviewed run inventory differs.")
    for run in actual:
        item = _run_evidence(run, token)
        approved = reviewed[item["runId"]]
        require(isinstance(approved, dict) and set(approved) == set(item) | {"classification"}
                and {k: approved[k] for k in item} == item
                and approved["classification"] in {"reviewed-no-target-mutation", "provision-only"})
    _bootstrap_run(current_id, env["GITHUB_SHA"], env["BACKUP_COORDINATOR_ACTION"], token, running=True)
    after = _pages("/actions/runs?" + urlencode({"created": review["windowEnd"] + ".." + now.strftime("%Y-%m-%dT%H:%M:%SZ")}),
                   "workflow_runs", token, maximum=31)
    require(len(after) <= 31, "The bounded first-launch live writer inventory is too large.")
    safe_plans = 0
    for run in after:
        run_id = str(run.get("id"))
        if run_id == current_id or run_id in reviewed:
            continue
        require(run.get("display_title") == "Production backup coordinator plan-schedule-anchor at " + env["GITHUB_SHA"]
                and run.get("head_sha") == env["GITHUB_SHA"]
                and _bootstrap_run(run_id, env["GITHUB_SHA"], "plan-schedule-anchor", token, running=False),
                "A new unreviewed writer appeared after the approved inventory.")
        safe_plans += 1
    require(safe_plans <= 5, "Too many prior bootstrap plans require a new reviewed inventory.")
    again = _pages("/actions/runs?" + urlencode({"created": time_range}), "workflow_runs", token, maximum=26)
    require([run for run in again if str(run.get("id")) != current_id] == actual,
            "The independently reviewed run inventory changed during observation.")
    after_again = _pages("/actions/runs?" + urlencode({"created": review["windowEnd"] + ".." + now.strftime("%Y-%m-%dT%H:%M:%SZ")}),
                         "workflow_runs", token, maximum=31)
    require([run for run in after_again if str(run.get("id")) != current_id] ==
            [run for run in after if str(run.get("id")) != current_id],
            "The live writer inventory changed during observation.")
    _require_current_main(env["GITHUB_SHA"], token)
    return {"reviewSha256": review_pin, "inventorySha256": digest(review["reviewedRuns"]),
            "reviewedRunCount": len(reviewed), "safePlanRunCount": safe_plans,
            "guardGithubUpperBound": 13 + 5 * len(reviewed) + 4 * 5}


def plan_first_launch(env, target, objects, data_objects, anchor_objects, data_api, worker_api, metadata_api, scope_anchor,
                      review_raw, review_pin, registration_sha256, token):
    """Produce a bounded, independently reviewable plan. No mutation is performed."""
    _protected_inputs(env, review_raw, review_pin, registration_sha256)
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_RUN_ATTEMPT") == "1" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + github.MAIN_REF
            and env.get("BACKUP_COORDINATOR_ACTION") in {"plan-schedule-anchor", "initialize-schedule-anchor"}
            and DECIMAL.fullmatch(env.get("GITHUB_RUN_ID", "")) and REV.fullmatch(env.get("GITHUB_SHA", "")))
    require(validate_target(target.data) == target and target.environment == "production")
    _require_current_main(env["GITHUB_SHA"], token)
    require(type(scope_anchor) is coordinator.ScheduleScopeAnchor and scope_anchor.target_sha256 == schedule.logical_scope(target)
            and type(scope_anchor.store) is coordinator.CoordinatorStore and scope_anchor.store.objects is objects
            and scope_anchor.bucket_name == target.data["backupBucketName"]
            and scope_anchor.bucket_created_at == target.data["backupBucketCreatedAt"])
    anchor_registration = parsed(env.get("SUBS_BOT_PROVISION_ANCHOR_JSON", ""))
    require(set(anchor_registration) == {"accountId", "bucketName", "bucketCreatedAt"}
            and anchor_registration["accountId"] == target.account_id
            and anchor_registration["bucketName"] == anchor_objects.bucket
            and anchor_objects.bucket != objects.bucket)
    require(type(data_api) is control.API and type(worker_api) is control.API and type(metadata_api) is control.API
            and data_api.token == env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN")
            and worker_api.token == env.get("SUBS_BOT_CF_WORKER_READ_TOKEN")
            and metadata_api.token == env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN"),
            "The three independent bootstrap read credentials are required.")
    control.privacy(metadata_api, metadata_api.root, anchor_objects.bucket, anchor_registration["bucketCreatedAt"])
    initial, genesis = scope_anchor.initial_material()
    configured_genesis = env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256", "")
    require(_sha(genesis) == scope_anchor.genesis_sha256
            and (configured_genesis == _sha(genesis)
                 or env["BACKUP_COORDINATOR_ACTION"] == "plan-schedule-anchor" and configured_genesis == ""))
    import production_backup_transaction as maintenance
    target_seed = maintenance.Anchor(coordinator.CoordinatorStore(objects, target.digest), target.digest, "0" * 64)
    target_genesis = _sha(target_seed.initial_material()[1])
    configured_target_genesis = env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", "")
    require(configured_target_genesis == target_genesis
            or env["BACKUP_COORDINATOR_ACTION"] == "plan-schedule-anchor" and configured_target_genesis == "")
    original = provision_original(target, objects, anchor_objects, registration_sha256)
    empty_source_bucket(target, data_objects)
    observation = new_resource_observation(target, data_api, worker_api, metadata_api)
    raw = review_raw.encode("utf-8") if isinstance(review_raw, str) else review_raw
    review = parsed(raw)
    require(isinstance(raw, bytes) and canonical(review) == raw and HEX.fullmatch(review_pin or "") and _sha(raw) == review_pin
            and set(review) == {"version", "kind", "targetSha256", "configurationSha256", "scopeSha256",
                "registrationSha256", "windowStart", "windowEnd", "reviewedRuns", "custody", "noPriorInFlightWriter"}
            and type(review["version"]) is int and review["version"] == 1
            and review["kind"] == "new-production-scope-bootstrap-review" and review["targetSha256"] == target.digest
            and review["configurationSha256"] == target.configuration_digest and review["scopeSha256"] == schedule.logical_scope(target)
            and review["registrationSha256"] == registration_sha256 and review["custody"] == CUSTODY
            and review["noPriorInFlightWriter"] is True and isinstance(review["reviewedRuns"], list)
            and len(review["reviewedRuns"]) <= 25)
    earliest = min(_stamp(target.data[key]) for key in ("d1CreatedAt", "workerCreatedOn", "bucketCreatedAt", "backupBucketCreatedAt"))
    start, end = _stamp(review["windowStart"]), _stamp(review["windowEnd"])
    now = datetime.now(timezone.utc)
    provision_run = _get_json("/actions/runs/" + original["receipt"]["runId"] + "/attempts/1", token)
    require(start <= _stamp(provision_run.get("created_at")) <= earliest and earliest <= end <= now
            and end - start <= timedelta(days=31), "The reviewed first-launch inventory window is incomplete.")
    reviewed = {entry.get("runId"): entry for entry in review["reviewedRuns"] if isinstance(entry, dict)}
    provision_id = original["receipt"]["runId"]
    require(provision_id in reviewed and reviewed[provision_id]["classification"] == "provision-only"
            and [entry.get("runId") for entry in review["reviewedRuns"] if entry.get("classification") == "provision-only"] == [provision_id]
            and reviewed[provision_id]["revision"] == original["receipt"]["revision"]
            and reviewed[provision_id]["path"] == ".github/workflows/worker-production-control.yml")
    _provision_job(original["receipt"], token)
    verify_first_launch_writers(env, review_raw, review_pin, token)
    # Repeat the independently bounded source observations before any caller can write.
    require(provision_original(target, objects, anchor_objects, registration_sha256) == original
            and new_resource_observation(target, data_api, worker_api, metadata_api) == observation)
    empty_source_bucket(target, data_objects)
    _require_current_main(env["GITHUB_SHA"], token)
    return {"version": 1, "kind": "new-production-scope-bootstrap-plan", "targetSha256": target.digest,
            "configurationSha256": target.configuration_digest, "scopeSha256": schedule.logical_scope(target),
            "controlRevision": env["GITHUB_SHA"], "targetCoordinatorGenesisSha256": target_genesis,
            "scopeGenesisSha256": _sha(genesis), "initialAnchorSha256": _sha(initial),
            "registrationSha256": registration_sha256, "provisionJournalSha256": original["provisionJournalSha256"],
            "resourceObservationSha256": digest(observation), "reviewSha256": review_pin,
            "inventorySha256": digest(review["reviewedRuns"]), "windowStart": review["windowStart"],
            "windowEnd": review["windowEnd"], "custody": CUSTODY}


def verify_first_launch_guard(env, target, objects, data_objects, anchor_objects, data_api, worker_api, metadata_api, scope_anchor,
                              review_raw, review_pin, registration_sha256, token, plan, *, stage):
    """Recheck the fixed pristine/partial genesis state before one bounded write.

    stage 0 precedes genesis, 1 precedes the immutable initial history, and 2
    precedes the pointer CAS. The caller performs the one write and readback.
    """
    _protected_inputs(env, review_raw, review_pin, registration_sha256)
    require(type(stage) is int and stage in {0, 1, 2} and isinstance(plan, dict)
            and env.get("BACKUP_COORDINATOR_ACTION") == "initialize-schedule-anchor"
            and env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_PLAN_SHA256")
            and env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_PLAN_SHA256") == digest(plan),
            "The independently approved first-launch plan is required.")
    require(type(scope_anchor) is coordinator.ScheduleScopeAnchor and type(scope_anchor.store) is coordinator.CoordinatorStore
            and scope_anchor.store.objects is objects and scope_anchor.target_sha256 == schedule.logical_scope(target)
            and scope_anchor.bucket_name == target.data["backupBucketName"]
            and scope_anchor.bucket_created_at == target.data["backupBucketCreatedAt"]
            and type(data_api) is control.API and type(worker_api) is control.API and type(metadata_api) is control.API
            and data_api.token == env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN")
            and worker_api.token == env.get("SUBS_BOT_CF_WORKER_READ_TOKEN")
            and metadata_api.token == env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN"))
    initial, genesis = scope_anchor.initial_material()
    import production_backup_transaction as maintenance
    target_seed = maintenance.Anchor(coordinator.CoordinatorStore(objects, target.digest), target.digest, "0" * 64)
    target_genesis = _sha(target_seed.initial_material()[1])
    require(plan.get("kind") == "new-production-scope-bootstrap-plan" and plan.get("targetSha256") == target.digest
            and plan.get("configurationSha256") == target.configuration_digest
            and plan.get("controlRevision") == env.get("GITHUB_SHA")
            and plan.get("targetCoordinatorGenesisSha256") == target_genesis == env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256")
            and plan.get("scopeSha256") == schedule.logical_scope(target) and plan.get("reviewSha256") == review_pin
            and plan.get("registrationSha256") == registration_sha256 and plan.get("custody") == CUSTODY
            and plan.get("initialAnchorSha256") == _sha(initial) and plan.get("scopeGenesisSha256") == _sha(genesis)
            and scope_anchor.genesis_sha256 == _sha(genesis) == env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256"))
    scope_store = scope_anchor.store
    registration = "maintenance/production-control/registrations/" + target.digest + ".json"
    genesis_key = scope_store._key(scope_anchor.genesis_key)
    history_key = scope_store._key(scope_anchor.history_key(1, initial))
    expected = [registration]
    if stage >= 1:
        expected.append(genesis_key)
        actual, _etag = objects.get(genesis_key, limit=65536)
        require(actual == genesis, "The exact initial scope genesis is not confirmed.")
    if stage >= 2:
        expected.append(history_key)
        actual, _etag = objects.get(history_key, limit=65536)
        require(actual == initial, "The exact initial scope history is not confirmed.")
    expected.sort()
    require(objects.list("", maximum=10000) == expected, "The exact bootstrap stage changed or contains unknown objects.")
    anchor_registration = parsed(env.get("SUBS_BOT_PROVISION_ANCHOR_JSON", ""))
    require(set(anchor_registration) == {"accountId", "bucketName", "bucketCreatedAt"}
            and anchor_registration["accountId"] == target.account_id and anchor_registration["bucketName"] == anchor_objects.bucket
            and anchor_objects.bucket != objects.bucket)
    control.privacy(metadata_api, metadata_api.root, anchor_objects.bucket, anchor_registration["bucketCreatedAt"])
    original = provision_original(target, objects, anchor_objects, registration_sha256, expected_new_bucket_keys=expected)
    empty_source_bucket(target, data_objects)
    require(original["provisionJournalSha256"] == plan.get("provisionJournalSha256")
            and digest(new_resource_observation(target, data_api, worker_api, metadata_api)) == plan.get("resourceObservationSha256"))
    _provision_job(original["receipt"], token)
    writers = verify_first_launch_writers(env, review_raw, review_pin, token)
    require(writers["inventorySha256"] == plan.get("inventorySha256"))
    return {**writers, "guardGithubUpperBound": writers["guardGithubUpperBound"] + 4}

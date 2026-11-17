"""Trusted-main single-use intent for the isolated D1 read-token probe."""
from hashlib import sha256
import json
import os

import scoped_r2
import trusted_backup_head_gate as gate
import prepare_isolation_artifact as github
from cloudflare_isolation import CloudflareClient
from production_control import API, privacy
from production_target import ACCOUNT, canonical, parsed, require


def main(env):
    require(env.get("BACKUP_CHECKOUT_PHASE") == "fixture-credential-check"
            and env.get("CAPACITY_FIXTURE_MODE") == "probe-read-token")
    gate.validate(env)
    registration = parsed(env["CAPACITY_FIXTURE_REGISTRATION_JSON"])
    target_sha = env["CAPACITY_FIXTURE_REGISTRATION_SHA256"]
    spec = parsed(env["HEAD_VALIDATION_JSON"])
    require(spec["checkpointId"] == "0" * 31 + "1")
    metadata = API({"accountId": ACCOUNT, "workerName": "subs-bot-cf-dev-01"},
                   env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
    privacy(metadata, metadata.root, registration["bucketName"], registration["bucketCreatedAt"])
    objects = scoped_r2.from_environment(ACCOUNT, registration["bucketName"], env)
    require(objects is not None and objects.write_credential is not None)
    key = "maintenance/production-control/evidence/capacity-fixture/read-token-probe/" + registration["probeDatabaseId"] + "/intent.json"
    prior, _ = objects.get(key, absent=True)
    require(prior is None, "A prior capability probe intent exists; do not repeat it.")
    intent = {"version": 1, "kind": "d1-read-token-negative-probe", "targetSha256": target_sha,
              "probeDatabaseId": registration["probeDatabaseId"], "runId": env["GITHUB_RUN_ID"], "runAttempt": "1",
              "dispatcherRevision": env["GITHUB_SHA"], "controllerRevision": spec["headSha"],
              "witnessSha256": env["CAPACITY_FIXTURE_BINDING_WITNESS_SHA256"], "approvalSha256": spec["approvalSha256"]}
    raw = canonical(intent)
    objects.put_once(key, raw)
    observed, _ = objects.get(key)
    require(observed == raw)
    result = sha256(raw).hexdigest()
    with open(env["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write("intent_sha256=" + result + "\n")
    print(json.dumps({"status": "intent-recorded", "intentSha256": result, "fixtureOnly": True}))


def readback(env):
    """Fresh trusted runner confirms the candidate's denied probe left no table."""
    require(env.get("BACKUP_CHECKOUT_PHASE") == "fixture-credential-check"
            and env.get("CAPACITY_FIXTURE_MODE") == "probe-read-token"
            and not env.get("CAPACITY_FIXTURE_D1_WRITE_TOKEN") and not env.get("SUBS_BOT_SCOPED_R2_WRITE_JSON"))
    gate.validate(env)
    registration = parsed(env["CAPACITY_FIXTURE_REGISTRATION_JSON"])
    target_sha = env["CAPACITY_FIXTURE_REGISTRATION_SHA256"]
    metadata = API({"accountId": ACCOUNT, "workerName": "subs-bot-cf-dev-01"},
                   env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
    privacy(metadata, metadata.root, registration["bucketName"], registration["bucketCreatedAt"])
    objects = scoped_r2.from_environment(ACCOUNT, registration["bucketName"], env)
    require(objects is not None and objects.write_credential is None)
    key = "maintenance/production-control/evidence/capacity-fixture/read-token-probe/" + registration["probeDatabaseId"] + "/intent.json"
    raw, _ = objects.get(key)
    require(sha256(raw).hexdigest() == env.get("CAPACITY_FIXTURE_PROBE_INTENT_SHA256"))
    intent, spec = parsed(raw), parsed(env["HEAD_VALIDATION_JSON"])
    require(canonical(intent) == raw and intent.get("kind") == "d1-read-token-negative-probe"
            and intent.get("targetSha256") == target_sha and intent.get("probeDatabaseId") == registration["probeDatabaseId"]
            and intent.get("runId") == env["GITHUB_RUN_ID"] and intent.get("runAttempt") == "1"
            and intent.get("dispatcherRevision") == env["GITHUB_SHA"] and intent.get("controllerRevision") == spec["headSha"]
            and intent.get("witnessSha256") == env["CAPACITY_FIXTURE_BINDING_WITNESS_SHA256"]
            and intent.get("approvalSha256") == spec["approvalSha256"])
    token = github._github_token()
    response = github._get_json("/actions/runs/" + env["GITHUB_RUN_ID"] + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int and response["total_count"] == len(jobs) < 100)
    candidates = [job for job in jobs if isinstance(job, dict) and job.get("name") == "validate"]
    require(len(candidates) == 1)
    job = candidates[0]
    require(str(job.get("run_id")) == env["GITHUB_RUN_ID"] and job.get("run_attempt") == 1
            and job.get("head_sha") == env["GITHUB_SHA"] and (job.get("status"), job.get("conclusion")) == ("completed", "success")
            and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == "Run the reviewed candidate against only dedicated isolation"]
    require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    api = CloudflareClient(env.get("CAPACITY_FIXTURE_D1_READ_TOKEN", ""))
    path = "/accounts/" + ACCOUNT + "/d1/database/" + registration["probeDatabaseId"]
    identity = api("GET", path)
    require(isinstance(identity, dict) and (identity.get("uuid"), identity.get("name"), identity.get("created_at")) ==
            (registration["probeDatabaseId"], registration["probeDatabaseName"], registration["probeCreatedAt"]))
    result = api("POST", path + "/query", {"sql": "SELECT name FROM sqlite_schema WHERE type='table' AND name='subs_bot_d1_read_permission_probe'"})
    require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True and result[0].get("results") == [])
    print(json.dumps({"status": "independently-confirmed", "intentSha256": sha256(raw).hexdigest(),
                      "fixtureOnly": True, "probeTableAbsent": True, "readbackMutation": False}))


if __name__ == "__main__":
    try:
        action = os.environ.get("CAPACITY_FIXTURE_PROBE_ACTION", "intent")
        require(action in {"intent", "readback"})
        (main if action == "intent" else readback)(os.environ)
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "The single-use probe intent was not confirmed; do not retry."}))
        raise SystemExit(1) from None

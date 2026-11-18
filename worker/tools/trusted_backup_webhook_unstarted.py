"""Explicitly release a phase webhook lock when setup never began.

This path never calls setWebhook or modifies application control state. An
unknown conditional lock or an existing setup intent must be reconciled by a
separate, stronger forward plan, not retried here.
"""
from hashlib import sha256
import json
import os
import re

import prepare_isolation_artifact as github
from production_backup_webhook_recovery import (context, source_run, open_store, diagnose, Telegram,
    ORIGINAL_ORIGIN, probe_original_webhook, webhook_settings)
from production_target import TEST_BOT_ID, canonical, parsed, require, validate_target
from trusted_backup_webhook_anchor import anchor


def observe(env):
    require(context(env) is False and env.get("WEBHOOK_SOURCE_KIND") == "phase-coordinator")
    run_id, attempt, candidate = source_run(env, False)
    reviewed = parsed(env.get("SUBS_BOT_PHASE_WEBHOOK_UNSTARTED_REVIEW_JSON", ""))
    require(reviewed == {"version": 1, "dispatcherRevision": env.get("WEBHOOK_SOURCE_MAIN_SHA"),
                         "candidateRevision": candidate, "setupOrdering": "exclusive-intent-before-setWebhook",
                         "backupOrdering": "callback-after-confirmed-webhook"},
            "The exact original dispatcher and candidate ordering must be independently reviewed.")
    comparison = github.compare_commits_metadata(env["WEBHOOK_SOURCE_MAIN_SHA"], env["GITHUB_SHA"], github._github_token())
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == env["WEBHOOK_SOURCE_MAIN_SHA"]
            and comparison.get("merge_base_commit", {}).get("sha") == env["WEBHOOK_SOURCE_MAIN_SHA"])
    current = github._get_json("/actions/runs/" + run_id, github._github_token())
    require(str(current.get("id")) == run_id and current.get("run_attempt") == 1 and current.get("status") == "completed")
    jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", github._github_token())
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    selected = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "coordinate"]
    require(len(selected) == 1 and str(selected[0].get("run_id")) == run_id and selected[0].get("run_attempt") == 1
            and selected[0].get("head_sha") == env["WEBHOOK_SOURCE_MAIN_SHA"]
            and selected[0].get("status") == "completed" and isinstance(selected[0].get("steps"), list))
    for name in ("Verify trusted coordinator identity before candidate checkout", "Verify exact reviewed coordinator checkout",
                 "Verify isolated coordinator test Bot identity"):
        steps = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    execution = [step for step in selected[0]["steps"] if isinstance(step, dict)
                 and step.get("name") == "Coordinate reviewed isolated backup phases"]
    require(len(execution) == 1 and execution[0].get("status") == "completed")
    result = diagnose(env)
    require(result.get("status") == "read-only-diagnosis" and result.get("admission") == "closed"
            and result.get("workers") == "frozen" and result.get("unsettledOrUnknown") is False
            and re.fullmatch(r"[a-f0-9]{64}", result.get("stateSha256", ""))
            and result.get("webhookLocation") == "original"
            and result.get("privateRecordsPresent", {}).get("webhookIntent") is False
            and result["privateRecordsPresent"].get("webhookCompleted") is False)
    draft, secrets, previous, store, prefix = open_store(env)
    registration_raw = store.get(prefix + "registration.json")
    require(sha256(registration_raw).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    registration = parsed(registration_raw)
    target = validate_target(registration.get("target"))
    desired = dict(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["botId"] == previous["botId"] == TEST_BOT_ID
            and target.data["botUsername"] == "test_cfsubs_bot" and registration.get("draftSha256") == draft.digest
            and registration.get("targetSha256") == target.digest and registration.get("configurationSha256") == target.configuration_digest
            and validate_target(desired).configuration_digest == target.configuration_digest)
    suffix = run_id + "-" + attempt
    for key in ("phase-coordinator-webhook-setup-" + suffix + "-intent.json",
                "phase-coordinator-webhook-setup-" + suffix + "-confirmed.json", suffix + "-webhook-configured.json"):
        require(store.get(prefix + key, absent=True) is None,
                "Webhook setup may have started; the unstarted release cannot be used.")
    telegram = Telegram(draft, {**secrets, "webhookSecret": previous["webhookSecret"]})
    telegram.identity()
    info = telegram.call("getWebhookInfo")
    settings = webhook_settings(info)
    require(settings["url"] == ORIGINAL_ORIGIN + "/telegram/webhook" and type(info.get("pending_update_count")) is int
            and info["pending_update_count"] >= 0 and probe_original_webhook(previous["webhookSecret"]) == 400)
    lock = anchor(store, target.digest, env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256", ""))
    value, raw, _ = lock.read()
    require(value["state"] == "active" and value["session"] == suffix and value["controlRevision"] == candidate)
    plan = {"version": 1, "kind": "phase-webhook-unstarted-release", "sourceRunId": run_id, "sourceAttempt": attempt,
            "sourceMainRevision": env["WEBHOOK_SOURCE_MAIN_SHA"], "sourceCandidateRevision": candidate,
            "reviewSha256": sha256(canonical(reviewed)).hexdigest(),
            "targetSha256": target.digest, "registrationSha256": sha256(registration_raw).hexdigest(),
            "anchorSha256": sha256(raw).hexdigest(), "stateSha256": result["stateSha256"],
            "snapshotSha256": result.get("snapshotSha256"), "settingsSha256": sha256(canonical(settings)).hexdigest(),
            "pendingUpdateCount": info["pending_update_count"]}
    return plan, lock, store, prefix


def run(env):
    action = env.get("WEBHOOK_RECOVERY_ACTION", "")
    require(action in {"plan-phase-unstarted", "release-phase-unstarted"})
    plan, lock, store, prefix = observe(env)
    plan_sha = sha256(canonical(plan)).hexdigest()
    if action == "plan-phase-unstarted":
        return {"status": "planned", "planSha256": plan_sha, "mutationPerformed": False, "oldOutcome": "not-promoted"}
    require(env.get("WEBHOOK_RECOVERY_APPROVAL_SHA256") == plan_sha
            and env.get("SUBS_BOT_PHASE_WEBHOOK_UNSTARTED_APPROVAL_SHA256") == plan_sha,
            "The exact independently reviewed unstarted release plan is required.")
    claim_key = prefix + "phase-webhook-unstarted-" + plan["sourceRunId"] + "-1-intent.json"
    claim = {"version": 1, "planSha256": plan_sha, "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": env["GITHUB_RUN_ATTEMPT"]}
    require(re.fullmatch(r"[1-9][0-9]{0,19}", claim["writerRunId"]) and claim["writerAttempt"] == "1")
    store.put_exclusive(claim_key, canonical(claim))
    require(store.get(claim_key) == canonical(claim))
    again, _, _, _ = observe(env)
    require(again == plan, "The unstarted release predecessor changed after its exclusive intent.")
    lock.release(plan["sourceRunId"] + "-1")
    released, _, _ = lock.read()
    require(released["state"] == "idle" and released["session"] == plan["sourceRunId"] + "-1")
    done = {"version": 1, "intentSha256": sha256(canonical(claim)).hexdigest(), "planSha256": plan_sha,
            "status": "released-before-webhook-setup", "oldOutcome": "not-promoted"}
    done_key = prefix + "phase-webhook-unstarted-" + plan["sourceRunId"] + "-1-complete.json"
    store.put_exclusive(done_key, canonical(done))
    require(store.get(done_key) == canonical(done))
    return {"status": "released-before-webhook-setup", "planSha256": plan_sha, "webhookMutation": False}


if __name__ == "__main__":
    try:
        print(json.dumps(run(os.environ), sort_keys=True))
    except Exception:
        print("::error::The webhook lock remains active or its result is unknown; retain the evidence and do not retry.")
        raise SystemExit(1) from None

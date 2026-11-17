"""Explicit isolated cleanup when the reviewed parent stopped before backup dispatch.

No application state is changed until a protected plan is independently approved.
Unknown parent, child, lock, webhook or private evidence remains blocked.
"""
from copy import deepcopy
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile
from time import monotonic, sleep
import time
from urllib.parse import urlencode
from urllib.request import Request

import prepare_isolation_artifact as github
from production_backup_webhook_recovery import context, source_run, open_store, inspect as inspect_webhook
from production_control import API, Controller, Telegram
from production_lifecycle_drill import SERVICE, ORIGINAL_ORIGIN, approval
from production_release_evidence import load_release
from production_storage import PrivateStore
from production_target import TEST_BOT_ID, canonical, parsed, require, validate_target
from trusted_backup_no_export_terminal import verify as verify_old_terminal
from trusted_backup_webhook_anchor import anchor as webhook_anchor

SHA = re.compile(r"[a-f0-9]{64}")
REV = re.compile(r"[a-f0-9]{40}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
PARENT = ".github/workflows/worker-backup-reviewed-coordinator.yml"
CHILD = ".github/workflows/worker-backup-phase-rehearsal.yml"
BASE = "maintenance/production-control/evidence/backup-coordinator/"
GATES = ("Verify trusted coordinator identity before candidate checkout", "Verify exact reviewed coordinator checkout",
         "Verify isolated coordinator test Bot identity")


def require_read_budget(extra=0):
    """Reserve bounded fresh GH checks before the first pause intent."""
    request = Request("https://api.github.com/rate_limit", headers={"Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + github._github_token(), "Cache-Control": "no-cache",
        "X-GitHub-Api-Version": "2022-11-28"})
    with github._OPENER.open(request, timeout=20) as response:
        raw = response.read(65537)
    require(isinstance(raw, bytes) and len(raw) <= 65536)
    value = json.loads(raw).get("resources", {}).get("core", {})
    require(type(extra) is int and 0 <= extra <= 960)
    require(type(value.get("remaining")) is int and value["remaining"] >= 300 + extra
            and type(value.get("reset")) is int and value["reset"] > int(time.time()),
            "Insufficient GitHub quota for guarded cleanup; no pause intent was written.")


def initial_coordinator_evidence(store, target, keys, env):
    """Accept only the pinned fresh coordinator genesis and no other object."""
    root = BASE + target.digest + "/coordination/maintenance/production-control/"
    initial = canonical({"version": 1, "targetSha256": target.digest, "generation": 1, "previousSha256": None,
                         "state": "idle", "session": "1-1", "day": "1970/01/01", "controlRevision": "0" * 40})
    genesis = canonical({"version": 1, "targetSha256": target.digest, "initialAnchorSha256": sha256(initial).hexdigest()})
    genesis_key = root + "registrations/daily-backup-genesis-" + target.digest + ".json"
    anchor_key = root + "registrations/daily-backup-anchor-" + target.digest + ".json"
    history_key = root + "evidence/daily-backup-anchor/" + target.digest + "/000000000001-" + sha256(initial).hexdigest() + ".json"
    require(sha256(genesis).hexdigest() == env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256")
            and sorted(keys) == sorted([genesis_key, anchor_key, history_key])
            and store.get(genesis_key) == genesis and store.get(anchor_key) == initial and store.get(history_key) == initial,
            "Any prior coordinator session or orphan requires separate complete terminal proofs.")
    return sha256(canonical(sorted(keys))).hexdigest()


def _runs(path, start, end, token):
    rows, total = [], None
    for page in range(1, 6):
        query = urlencode({"created": start + ".." + end, "per_page": 50, "page": page})
        response = github._get_json("/actions/workflows/" + path.rsplit("/", 1)[1] + "/runs?" + query, token)
        batch, count = response.get("workflow_runs"), response.get("total_count")
        require(isinstance(batch, list) and len(batch) <= 50 and type(count) is int and 0 <= count <= 250
                and (total is None or total == count))
        total = count
        for row in batch:
            require(isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                    and row.get("path") in {path, path + "@main", path + "@refs/heads/main"}
                    and row.get("event") == "workflow_dispatch" and row.get("head_branch") == "main"
                    and REV.fullmatch(row.get("head_sha", "")) and isinstance(row.get("created_at"), str)
                    and start <= row["created_at"] <= end and type(row.get("run_attempt")) is int
                    and row["run_attempt"] >= 1 and isinstance(row.get("status"), str))
            rows.append({key: row.get(key) for key in ("id", "head_sha", "created_at", "run_attempt", "status")})
        require(len(rows) <= count)
        if len(rows) == count:
            require(len({row["id"] for row in rows}) == len(rows))
            return sorted(rows, key=lambda row: row["id"])
        require(len(batch) == 50)
    require(False, "The bounded phase-run inventory was not complete.")


def no_child_started(env, store, target, source_id, candidate):
    """Use reviewed ordering, complete private intents and GH history, not missing output alone."""
    review = parsed(env.get("SUBS_BOT_PHASE_EARLY_REVIEW_JSON", ""))
    require(review == {"version": 1, "targetSha256": target.digest,
            "dispatcherRevision": env.get("WEBHOOK_SOURCE_MAIN_SHA"), "candidateRevision": candidate,
            "ordering": "durable-start-before-child-dispatch", "custody": "no-unapproved-private-evidence-deletion"}
            and type(review.get("version")) is int)
    token = github._github_token()
    main = env["WEBHOOK_SOURCE_MAIN_SHA"]
    comparison = github.compare_commits_metadata(main, env["GITHUB_SHA"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == main and comparison.get("merge_base_commit", {}).get("sha") == main)
    original = github._get_json("/actions/runs/" + source_id, token)
    require(str(original.get("id")) == source_id and original.get("run_attempt") == 1
            and original.get("head_sha") == main and original.get("head_branch") == "main"
            and original.get("path") in {PARENT, PARENT + "@main", PARENT + "@refs/heads/main"}
            and original.get("event") == "workflow_dispatch" and original.get("status") == "completed"
            and original.get("display_title") == "Rehearsal backup coordinator run at " + main + " candidate " + candidate
            and all(isinstance(original.get(key), dict) and original[key].get("id") == github.REPOSITORY_ID
                    for key in ("repository", "head_repository"))
            and isinstance(original.get("created_at"), str))
    response = github._get_json("/actions/runs/" + source_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100)
    selected = [job for job in jobs if isinstance(job, dict) and job.get("name") == "coordinate"]
    require(len(selected) == 1 and str(selected[0].get("run_id")) == source_id and selected[0].get("run_attempt") == 1
            and selected[0].get("head_sha") == main and selected[0].get("status") == "completed"
            and isinstance(selected[0].get("steps"), list))
    for name in GATES:
        matches = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
        require(len(matches) == 1 and (matches[0].get("status"), matches[0].get("conclusion")) == ("completed", "success"))
    executing = [step for step in selected[0]["steps"] if isinstance(step, dict)
                 and step.get("name") == "Coordinate reviewed isolated backup phases"]
    require(len(executing) == 1 and executing[0].get("status") == "completed"
            and executing[0].get("conclusion") in {"success", "failure", "cancelled", "timed_out"})
    require(store.objects is not None)
    prefix = BASE + target.digest + "/"
    keys = store.objects.list(prefix, maximum=10000)
    inventory_sha = initial_coordinator_evidence(store, target, keys, env)
    start = original["created_at"]
    end = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    require(start <= end)
    children = _runs(CHILD, start, end, token)
    parents = _runs(PARENT, start, end, token)
    require(not children and len(parents) == 1 and str(parents[0]["id"]) == source_id
            and parents[0]["status"] == "completed",
            "A child or another live coordinator requires independent reconciliation.")
    return {"reviewSha256": sha256(canonical(review)).hexdigest(),
            "startInventorySha256": inventory_sha,
            "sourceRunId": source_id, "sourceAttempt": "1", "children": 0}


def finished_pause_writer(env, intent, source_id, *, pin_key="SUBS_BOT_PHASE_EARLY_WRITER_SHA"):
    """Only a completed exact trusted admission writer can be continued."""
    writer = intent.get("writerRunId", "")
    revision = intent.get("dispatcherRevision", "")
    require(DECIMAL.fullmatch(writer or "") and intent.get("writerAttempt") == "1"
            and REV.fullmatch(revision or "") and revision == env.get(pin_key) == env.get("GITHUB_SHA"),
            "A writer from a different main requires independent source-closure reconciliation.")
    token = github._github_token()
    run = github._get_json("/actions/runs/" + writer, token)
    path = ".github/workflows/worker-backup-admission-recovery.yml"
    require(str(run.get("id")) == writer and run.get("run_attempt") == 1 and run.get("status") == "completed"
            and run.get("head_sha") == revision and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("path") in {path, path + "@main", path + "@refs/heads/main"}
            and run.get("display_title") == "Backup admission recovery " + source_id + "-1"
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository")))
    comparison = github.compare_commits_metadata(revision, env["GITHUB_SHA"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == revision and comparison.get("merge_base_commit", {}).get("sha") == revision)
    response = github._get_json("/actions/runs/" + writer + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100)
    selected = [job for job in jobs if isinstance(job, dict) and job.get("name") == "recover"]
    require(len(selected) == 1 and str(selected[0].get("run_id")) == writer and selected[0].get("run_attempt") == 1
            and selected[0].get("head_sha") == revision and selected[0].get("status") == "completed")
    for name in ("Require protected admission recovery switch", "Close, drain and freeze once using trusted main"):
        steps = [step for step in selected[0].get("steps", []) if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and steps[0].get("status") == "completed"
                and steps[0].get("conclusion") in ({"success"} if name == "Require protected admission recovery switch"
                                                   else {"success", "failure", "cancelled", "timed_out"}))


def continuation_history(env, store, keys, target, source_id, pause_sha, *, current=None):
    """Classify every previous continuation without replaying its intent."""
    require(store.objects is not None)
    store.verify()
    prefix = keys + "continuation-"
    found = store.objects.list(prefix, maximum=9)
    if current is not None:
        current_key, current_raw = current
        require(found and found[-1] == current_key and store.get(current_key) == current_raw,
                "The current continuation claim changed.")
        found = found[:-1]
    require(len(found) <= 8 and found == [prefix + str(n).zfill(4) + "-intent.json" for n in range(1, len(found) + 1)])
    pins = parsed(env.get("SUBS_BOT_PHASE_EARLY_CONTINUATION_WRITERS_JSON", "") or "{}")
    require(isinstance(pins, dict) and len(pins) == len(found))
    values, previous, writers = [], None, set()
    for number, key in enumerate(found, 1):
        raw = store.get(key)
        value = parsed(raw)
        require(canonical(value) == raw and set(value) == {"version", "kind", "targetSha256", "sourceRunId",
                "pauseConfirmationSha256", "planSha256", "writerRunId", "writerAttempt", "dispatcherRevision",
                "sequence", "previousSha256"} and type(value["version"]) is int and value["version"] == 1
                and value["kind"] == "phase-early-continuation" and value["targetSha256"] == target.digest
                and value["sourceRunId"] == source_id and value["pauseConfirmationSha256"] == pause_sha
                and SHA.fullmatch(value["planSha256"] or "") and type(value["sequence"]) is int and value["sequence"] == number
                and value["previousSha256"] == previous and DECIMAL.fullmatch(value["writerRunId"] or "")
                and value["writerRunId"] not in writers and value["writerAttempt"] == "1"
                and REV.fullmatch(value["dispatcherRevision"] or "")
                and pins.get(value["writerRunId"]) == value["dispatcherRevision"])
        finished_pause_writer({**env, "SUBS_BOT_PHASE_EARLY_CONTINUATION_PIN": value["dispatcherRevision"]},
                              value, source_id, pin_key="SUBS_BOT_PHASE_EARLY_CONTINUATION_PIN")
        writers.add(value["writerRunId"])
        previous = sha256(raw).hexdigest()
        values.append({"key": key, "sha256": previous})
    require(set(pins) == writers)
    return values


def run(env, *, execute, resume=False, inspect_frozen=False):
    require(context(env) is False and env.get("WEBHOOK_SOURCE_KIND") == "phase-coordinator")
    source_id, attempt, candidate = source_run(env, False)
    require(attempt == "1" and SHA.fullmatch(env.get("WEBHOOK_SNAPSHOT_SHA256", "")))
    webhook = inspect_webhook(env)
    require(webhook.get("status") == "observed" and webhook.get("intentPresent") is False
            and webhook.get("completionPresent") is False)
    draft, secrets, previous, store, prefix = open_store(env)
    registration_raw = store.get(prefix + "registration.json")
    require(sha256(registration_raw).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    registered = parsed(registration_raw)
    target = validate_target(registered.get("target"))
    desired = deepcopy(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE
            and target.data["botId"] == previous["botId"] == TEST_BOT_ID and target.data["botUsername"] == "test_cfsubs_bot"
            and registered.get("draftSha256") == draft.digest and registered.get("targetSha256") == target.digest
            and registered.get("configurationSha256") == target.configuration_digest
            and validate_target(desired).configuration_digest == target.configuration_digest)
    lock = webhook_anchor(store, target.digest, env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256", ""))
    lock_value, lock_raw, _ = lock.read()
    require(lock_value["state"] == "active" and lock_value["session"] == source_id + "-1"
            and lock_value["controlRevision"] == candidate)
    backup_store = PrivateStore(API(target, env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")), target.data["backupBucketName"])
    backup_store.verify()
    require(backup_store.objects is not None)
    def evidence():
        current_webhook = inspect_webhook(env)
        require(current_webhook == webhook and current_webhook.get("intentPresent") is False
                and current_webhook.get("completionPresent") is False)
        old = verify_old_terminal(backup_store, target, env.get("BACKUP_GENESIS_SHA256", ""), env)
        children = no_child_started(env, backup_store, target, source_id, candidate)
        observed, raw, _ = lock.read()
        require(observed == lock_value and raw == lock_raw)
        return {"oldTerminal": old, "noChild": children, "webhookLockSha256": sha256(raw).hexdigest()}
    proof = evidence()
    suffix = source_id + "-1"
    keys = prefix + "backup-admission-" + suffix + "-"
    stages = {stage: store.get(keys + stage + ".json", absent=True)
              for stage in ("pause-intent", "pause-confirmed", "freeze-intent", "freeze-confirmed")}
    if inspect_frozen:
        require(not execute and isinstance(stages["freeze-intent"], bytes) and isinstance(stages["freeze-confirmed"], bytes),
                "The original freeze is not independently confirmed.")
    else:
        require(stages["freeze-intent"] is None and stages["freeze-confirmed"] is None,
                "A freeze may have started; inspect its outcome without repeating it.")
    prior_intent = prior_confirmation = None
    if resume or inspect_frozen:
        require(isinstance(stages["pause-intent"], bytes) and isinstance(stages["pause-confirmed"], bytes),
                "The original pause is not independently confirmed.")
        prior_intent, prior_confirmation = parsed(stages["pause-intent"]), parsed(stages["pause-confirmed"])
        require(canonical(prior_intent) == stages["pause-intent"] and canonical(prior_confirmation) == stages["pause-confirmed"]
                and set(prior_intent) == {"version", "kind", "planSha256", "targetSha256", "sourceRunId", "session",
                    "candidateRevision", "predecessorSha256", "predecessorControl", "release", "configurationSha256",
                    "writerRunId", "writerAttempt", "dispatcherRevision"}
                and type(prior_intent["version"]) is int and prior_intent["version"] == 1
                and all(SHA.fullmatch(prior_intent.get(key, "")) for key in ("planSha256", "predecessorSha256"))
                and set(prior_confirmation) == {"version", "intentSha256", "stateSha256", "targetSha256", "control", "release", "configurationSha256"}
                and type(prior_confirmation["version"]) is int and prior_confirmation["version"] == 1
                and SHA.fullmatch(prior_confirmation.get("stateSha256", ""))
                and prior_intent.get("kind") == "phase-early-pause" and prior_intent.get("targetSha256") == target.digest
                and prior_intent.get("sourceRunId") == source_id and prior_intent.get("session") == suffix
                and prior_intent.get("candidateRevision") == candidate
                and prior_confirmation.get("intentSha256") == sha256(stages["pause-intent"]).hexdigest()
                and prior_confirmation.get("targetSha256") == target.digest
                and isinstance(prior_intent.get("predecessorControl"), dict)
                and type(prior_intent["predecessorControl"].get("epoch")) is int
                and prior_confirmation.get("control") == {**prior_intent["predecessorControl"], "admission": "closed",
                    "epoch": prior_intent["predecessorControl"]["epoch"] + 1}
                and prior_confirmation.get("release") == prior_intent.get("release")
                and prior_intent.get("configurationSha256") == target.configuration_digest
                and prior_confirmation.get("configurationSha256") == target.configuration_digest)
        finished_pause_writer(env, prior_intent, source_id)
    else:
        require(stages["pause-intent"] is None and stages["pause-confirmed"] is None,
                "An earlier pause may have started; inspect its outcome without repeating it.")
    with tempfile.TemporaryDirectory(prefix="trusted-early-admission-", dir=env["RUNNER_TEMP"]) as directory:
        archived = load_release(target, env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""),
                                env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""), Path(directory))
        require(archived["sourceTarget"].configuration_digest == target.configuration_digest)
        guard = lambda: github.require_current_main(env["GITHUB_SHA"])
        ctl = Controller(target, API(target, env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"]),
            API(target, env.get("SUBS_BOT_CF_DEPLOY_TOKEN", "")), archived["bundle"], archived["manifest"], guard=guard,
            telegram=Telegram(target, secrets, rehearsal_previous_url=ORIGINAL_ORIGIN + "/telegram/webhook"),
            secrets=secrets, control_revision=env["GITHUB_SHA"])
        if inspect_frozen:
            freeze_intent, frozen_record = parsed(stages["freeze-intent"]), parsed(stages["freeze-confirmed"])
            require(canonical(freeze_intent) == stages["freeze-intent"] and canonical(frozen_record) == stages["freeze-confirmed"]
                    and set(freeze_intent) == {"version", "targetSha256", "session", "pauseConfirmationSha256", "predecessorSha256",
                        "writerRunId", "writerAttempt", "dispatcherRevision"}
                    and type(freeze_intent["version"]) is int and freeze_intent["version"] == 1
                    and SHA.fullmatch(freeze_intent.get("predecessorSha256", ""))
                    and set(frozen_record) == {"version", "intentSha256", "stateSha256", "targetSha256", "configurationSha256",
                        "control", "release", "candidateRevision", "dispatcherRevision"}
                    and type(frozen_record["version"]) is int and frozen_record["version"] == 1
                    and freeze_intent.get("targetSha256") == target.digest and freeze_intent.get("session") == suffix
                    and freeze_intent.get("pauseConfirmationSha256") == sha256(stages["pause-confirmed"]).hexdigest()
                    and frozen_record.get("intentSha256") == sha256(stages["freeze-intent"]).hexdigest()
                    and frozen_record.get("targetSha256") == target.digest and frozen_record.get("candidateRevision") == candidate
                    and frozen_record.get("dispatcherRevision") == env["WEBHOOK_SOURCE_MAIN_SHA"]
                    and frozen_record.get("configurationSha256") == target.configuration_digest)
            finished_pause_writer(env, freeze_intent, source_id, pin_key="SUBS_BOT_PHASE_EARLY_FREEZE_WRITER_SHA")
            current = ctl.inspect()
            require(current["stateSha256"] == frozen_record.get("stateSha256")
                    and current["control"] == frozen_record.get("control") and current["release"] == frozen_record.get("release")
                    and current["control"]["admission"] == "closed" and current["control"]["workers"] == "frozen"
                    and not any(current["work"].values()) and not any(current["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
            return {"status": "freeze-confirmed", "freezeConfirmationSha256": sha256(stages["freeze-confirmed"]).hexdigest(),
                    "targetSha256": target.digest, "mutationPerformed": False}
        state = ctl.inspect() if resume else ctl.plan_pause()
        require(not any(state["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
        if resume:
            require(state["control"] == prior_confirmation["control"] and state["release"] == prior_confirmation["release"]
                    and state["configurationSha256"] == prior_confirmation["configurationSha256"]
                    and state["control"]["admission"] == "closed" and state["control"]["workers"] == "run")
            predecessor = sha256(canonical({key: state[key] for key in ("control", "release", "configurationSha256")})).hexdigest()
        else:
            require(state["control"]["admission"] == "open" and state["control"]["workers"] == "run")
            predecessor = state["stateSha256"]
        plan = {"version": 1, "kind": "phase-early-resume-cleanup" if resume else "phase-early-admission-cleanup", "sourceRunId": source_id,
                "sourceAttempt": attempt, "dispatcherRevision": env["WEBHOOK_SOURCE_MAIN_SHA"],
                "candidateRevision": candidate, "targetSha256": target.digest, "snapshotSha256": webhook["snapshotSha256"],
                "predecessorSha256": predecessor, "evidenceSha256": sha256(canonical(proof)).hexdigest()}
        history = []
        if resume:
            plan["pauseConfirmationSha256"] = sha256(stages["pause-confirmed"]).hexdigest()
            history = continuation_history(env, store, keys, target, source_id, plan["pauseConfirmationSha256"])
            require(len(history) < 8, "The bounded continuation history requires independent reconciliation.")
            plan["continuationHistorySha256"] = sha256(canonical(history)).hexdigest()
            plan["continuationSequence"] = len(history) + 1
        plan_sha = sha256(canonical(plan)).hexdigest()
        if not execute:
            return {"status": "read-only-plan", "planSha256": plan_sha, "mutationPerformed": False}
        require(env.get("BACKUP_APPROVED_PLAN_SHA256") == plan_sha
                and env.get("SUBS_BOT_PHASE_EARLY_CLEANUP_APPROVAL_SHA256") == plan_sha)
        # The pause writer and every completed continuation are checked again at
        # each write guard, not just when the plan was produced.
        require_read_budget(120 * (len(history) + 1) if resume else 0)
        guard()
        from production_backup_webhook_recovery import claim_intent_once
        current_claim = None
        def write_guard():
            guard()
            require(evidence() == proof, "The reviewed webhook window or old terminal proof changed.")
            if resume:
                require(current_claim is not None
                        and store.get(keys + "pause-intent.json") == stages["pause-intent"]
                        and store.get(keys + "pause-confirmed.json") == stages["pause-confirmed"])
                finished_pause_writer(env, prior_intent, source_id)
                require(continuation_history(env, store, keys, target, source_id,
                        plan["pauseConfirmationSha256"], current=current_claim) == history,
                        "A previous continuation or its writer changed.")
        ctl.guard = write_guard
        if resume:
            require(evidence() == proof and store.get(keys + "pause-confirmed.json") == stages["pause-confirmed"])
            require(continuation_history(env, store, keys, target, source_id, plan["pauseConfirmationSha256"]) == history)
            continuation = {"version": 1, "kind": "phase-early-continuation", "targetSha256": target.digest,
                "sourceRunId": source_id, "pauseConfirmationSha256": plan["pauseConfirmationSha256"],
                "planSha256": plan_sha, "writerRunId": env.get("GITHUB_RUN_ID", ""), "writerAttempt": env.get("GITHUB_RUN_ATTEMPT", ""),
                "dispatcherRevision": env["GITHUB_SHA"], "sequence": plan["continuationSequence"],
                "previousSha256": history[-1]["sha256"] if history else None}
            require(DECIMAL.fullmatch(continuation["writerRunId"] or "") and continuation["writerAttempt"] == "1")
            continuation_key = keys + "continuation-" + str(plan["continuationSequence"]).zfill(4) + "-intent.json"
            claim_intent_once(store, continuation_key, canonical(continuation))
            current_claim = (continuation_key, canonical(continuation))
            require(evidence() == proof and store.get(keys + "pause-confirmed.json") == stages["pause-confirmed"]
                    and store.get(continuation_key) == canonical(continuation)
                    and store.objects.list(keys + "continuation-", maximum=9) == [item["key"] for item in history] + [continuation_key])
            paused, confirmed = state, prior_confirmation
        else:
            require(evidence() == proof and ctl.plan_pause()["stateSha256"] == state["stateSha256"])
            intent = {"version": 1, "kind": "phase-early-pause", "planSha256": plan_sha,
                      "targetSha256": target.digest, "sourceRunId": source_id, "session": suffix,
                      "candidateRevision": candidate, "predecessorSha256": state["stateSha256"],
                      "predecessorControl": state["control"], "release": state["release"],
                      "configurationSha256": target.configuration_digest,
                      "writerRunId": env.get("GITHUB_RUN_ID", ""), "writerAttempt": env.get("GITHUB_RUN_ATTEMPT", ""),
                      "dispatcherRevision": env["GITHUB_SHA"]}
            require(DECIMAL.fullmatch(intent["writerRunId"] or "") and intent["writerAttempt"] == "1")
            claim_intent_once(store, keys + "pause-intent.json", canonical(intent))
            require(evidence() == proof and ctl.plan_pause()["stateSha256"] == state["stateSha256"])
            paused = ctl.transition("pause", approval(target, "pause", ctl.revision, state["stateSha256"]), state["stateSha256"])
            confirmed = {"version": 1, "intentSha256": sha256(canonical(intent)).hexdigest(), "stateSha256": paused["stateSha256"],
                         "targetSha256": target.digest, "control": paused["control"], "release": paused["release"],
                         "configurationSha256": paused["configurationSha256"]}
            store.put_exclusive(keys + "pause-confirmed.json", canonical(confirmed))
        deadline = monotonic() + 180
        while True:
            drained = ctl.inspect()
            require(drained["control"] == paused["control"] and drained["release"] == state["release"]
                    and drained["configurationSha256"] == target.configuration_digest
                    and not any(drained["terminal"].get(key, 0) for key in
                                ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
            if not any(drained["work"].values()):
                break
            require(monotonic() < deadline, "Accepted work remains in progress; keep the target closed and alert.")
            sleep(2)
        require(evidence() == proof)
        freeze_intent = {"version": 1, "targetSha256": target.digest, "session": suffix,
                         "pauseConfirmationSha256": sha256(canonical(confirmed)).hexdigest(),
                         "predecessorSha256": drained["stateSha256"], "writerRunId": env.get("GITHUB_RUN_ID", ""),
                         "writerAttempt": env.get("GITHUB_RUN_ATTEMPT", ""), "dispatcherRevision": env["GITHUB_SHA"]}
        require(DECIMAL.fullmatch(freeze_intent["writerRunId"] or "") and freeze_intent["writerAttempt"] == "1")
        write_guard()
        claim_intent_once(store, keys + "freeze-intent.json", canonical(freeze_intent))
        require(evidence() == proof)
        frozen = ctl.transition("freeze", approval(target, "freeze", ctl.revision, drained["stateSha256"]), drained["stateSha256"])
        require(frozen["control"]["admission"] == "closed" and frozen["control"]["workers"] == "frozen"
                and not any(frozen["work"].values()) and not any(frozen["terminal"].get(key, 0) for key in
                    ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
        completion = {"version": 1, "intentSha256": sha256(canonical(freeze_intent)).hexdigest(),
                      "stateSha256": frozen["stateSha256"], "targetSha256": target.digest,
                      "configurationSha256": target.configuration_digest, "control": frozen["control"],
                      "release": frozen["release"], "candidateRevision": candidate,
                      "dispatcherRevision": env["WEBHOOK_SOURCE_MAIN_SHA"]}
        store.put_exclusive(keys + "freeze-confirmed.json", canonical(completion))
        return {"status": "closed-and-frozen", "freezeConfirmationSha256": sha256(canonical(completion)).hexdigest(),
                "targetSha256": target.digest}

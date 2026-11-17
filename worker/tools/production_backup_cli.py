"""Explicit production backup checkpoints; no automatic production approval.

Every mutating checkpoint requires the protected action-specific envelope and
the exact observed predecessor. This entry point does not schedule itself, touch
the webhook, switch a consumer, remove data or retry an uncertain write.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import tempfile
import time
from urllib.parse import urlencode

import prepare_isolation_artifact as artifact
import production_backup_capacity as capacity
import production_backup_transaction as maintenance
import production_backup_resume as resume
import production_recovery as recovery
import production_recovery_cli as recovery_cli
from production_control import API, Controller, Telegram, general_config, hosted_environment
from production_storage import PrivateStore
from production_target import approve, canonical, digest, parsed, require, validate_target

WORKFLOW = artifact.REPOSITORY + "/.github/workflows/worker-production-backup.yml@" + artifact.MAIN_REF
READ_ONLY = {"inspect", "monitor", "plan-initialize-anchor", "inspect-anchor-initialization", "inspect-anchor-unknown", "plan-abort-unstarted", "plan-begin", "plan-pause", "drain", "plan-activate", "plan-reconcile-transition", "plan-resume-failed", "plan-anchor-reconcile"}
ACTIONS = READ_ONLY | {"initialize-anchor", "begin", "abort-unstarted", "preflight", "abort-preflight", "pause", "freeze", "fingerprint", "capture", "poll-export", "verify", "activate", "reconcile-transition", "resume-failed", "anchor-reconcile"}

def require_mutation_enabled(env):
    """A protected enable switch never replaces an action-specific approval."""
    require(env.get("GITHUB_RUN_ATTEMPT") == "1", "Mutating maintenance runs cannot be re-run.")
    require(env.get("SUBS_BOT_PRODUCTION_BACKUP_WRITES_ENABLED") == "true",
            "Production backup mutations are disabled until explicitly enabled.")


def settings(raw):
    value = parsed(raw)
    required = {"version", "warningPercent", "pauseLimitSeconds", "overdueHours", "windowStartUtc", "windowMinutes", "frequencyHours"}
    require(required <= set(value) <= required | {"maximumPauseSeconds"})
    require(type(value["version"]) is int and value["version"] == 1
            and type(value["warningPercent"]) is int and 1 <= value["warningPercent"] <= 99
            and type(value["pauseLimitSeconds"]) is int and 60 <= value["pauseLimitSeconds"] <= 900
            and type(value["overdueHours"]) is int and 1 <= value["overdueHours"] <= 168
            and type(value["frequencyHours"]) is int and 1 <= value["frequencyHours"] <= 168
            and type(value["windowMinutes"]) is int and 1 <= value["windowMinutes"] <= 720
            and isinstance(value["windowStartUtc"], str)
            and re.fullmatch(r"(?:[01][0-9]|2[0-3]):[0-5][0-9]", value["windowStartUtc"]))
    maximum_pause(value)
    return value


def maximum_pause(policy):
    """The alert threshold and the maximum permitted pause are distinct."""
    maximum = policy.get("maximumPauseSeconds", 1800)
    require(type(maximum) is int and 300 <= maximum <= 21600
            and type(policy.get("pauseLimitSeconds")) is int and maximum >= policy["pauseLimitSeconds"])
    return maximum


def session_maximum(events):
    require(events and events[0]["stage"] == "started")
    details = events[0]["details"]
    warning = details.get("pauseLimitSeconds")
    maximum = details.get("maximumPauseSeconds", 1800)
    require(type(warning) is int and 60 <= warning <= 900 and type(maximum) is int
            and 300 <= maximum <= 21600 and maximum >= warning)
    return maximum


def require_pause_window(events, policy):
    pauses = [event for event in events if event.get("stage") == "pause-intent"]
    now = int(time.time())
    require(len(pauses) == 1 and type(pauses[0].get("timestamp")) is int
            and 0 < pauses[0]["timestamp"] <= now
            and now - pauses[0]["timestamp"] < maximum_pause(policy),
            "The maximum pause elapsed; use the explicitly approved recovery path.")


def session_input(env):
    session, day = env.get("BACKUP_SESSION", ""), env.get("BACKUP_SESSION_DAY", "")
    require(maintenance.SESSION.fullmatch(session or "") is not None and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", day or ""))
    try:
        datetime.strptime(day, "%Y/%m/%d")
    except ValueError:
        require(False, "The requested maintenance session date is invalid.")
    return session, day


def in_window(policy, now):
    start_hour, start_minute = map(int, policy["windowStartUtc"].split(":"))
    minute = now.hour * 60 + now.minute
    return (minute - (start_hour * 60 + start_minute)) % 1440 < policy["windowMinutes"]


def check_context(env, target):
    require(target.environment == "production" and env.get("GITHUB_WORKFLOW_REF") == WORKFLOW)
    if env.get("GITHUB_EVENT_NAME") == "schedule":
        require(env.get("BACKUP_ACTION") == "monitor" and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
                and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
                and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
                and env.get("SUBS_BOT_CONTROL_ENVIRONMENT") == "subs-bot-production")
    else:
        hosted_environment("production")
    revision = env.get("GITHUB_SHA", "")
    artifact.require_current_main(revision)
    return revision


def active_transaction(anchor, store, target):
    pin, _raw, _etag = anchor.read()
    require(pin["state"] == "active", "An exact active maintenance transaction is required.")
    journal = maintenance.Transaction(store, pin["session"], pin["day"], target.digest, pin["controlRevision"])
    events = journal.load()
    require(events and events[0]["stage"] == "started", "The active transaction journal is missing.")
    return pin, journal, events


def missing_started_observation(anchor, store, target):
    pin, _raw, _etag = anchor.read()
    require(pin["state"] == "active")
    journal = maintenance.Transaction(store, pin["session"], pin["day"], target.digest, pin["controlRevision"])
    require(not journal.load(), "A transaction journal exists; inspect its exact stage instead.")
    return {"status": "unknown", "phase": "started-journal-missing", "session": pin["session"],
            "day": pin["day"], "mutationPermitted": False}


def unstarted_abort_plan(anchor, store, target, ctl, contract, policy, *, candidate_sha=None, reconciliation_raw=None):
    """Prove the actual begin writer ended before recovering an empty journal."""
    pin, raw, _etag = anchor.read(allow_future=True)
    pending_anchor_plan = None
    if pin["state"] == "idle":
        require(isinstance(candidate_sha, str) and re.fullmatch(r"[a-f0-9]{64}", candidate_sha),
                "The exact unconfirmed anchor acquisition candidate is required.")
        pending_anchor_plan, _prior, _etag, candidate_raw = anchor.plan_reconciliation(candidate_sha)
        pin, raw = pending_anchor_plan["candidate"], candidate_raw
        require(pin["state"] == "active")
    else:
        require(not candidate_sha)
        anchor.read()  # A competing future generation must not be ignored.
    txn = maintenance.Transaction(store, pin["session"], pin["day"], target.digest, pin["controlRevision"])
    require(not txn.load(), "A transaction exists; use its normal recovery path.")
    original, intent_sha = maintenance.read_begin(store, target.digest, pin["session"])
    details = original["startedDetails"]
    require(original["day"] == pin["day"] and original["controlRevision"] == pin["controlRevision"]
            and original["controlRevision"] == ctl.control_revision
            and original["dispatcherRevision"] == pin["controlRevision"]
            and original["dispatcherWorkflow"] == "worker-production-backup.yml"
            and original["sourceRevision"] == ctl.revision
            and original["anchorPredecessorSha256"] == pin["previousSha256"]
            and details.get("configurationSha256") == target.configuration_digest
            and details.get("contractSha256") == digest(contract) and details.get("policySha256") == digest(policy)
            and details.get("checkpointId") == contract["checkpointId"]
            and details.get("pauseLimitSeconds") == policy["pauseLimitSeconds"])
    require_finished_intent({"runId": original["writerRunId"], "runAttempt": original["writerAttempt"],
                             "controlRevision": original["dispatcherRevision"]}, allowed_actions={"begin"})
    current = ctl.inspect()
    require(current["stateSha256"] == original["stateSha256"] and current["control"] == details.get("control")
            and current["release"] == details.get("release") and current["configurationSha256"] == details["configurationSha256"]
            and not any(current["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
    previous_reconcile = store.get(maintenance.begin_key(target.digest, pin["session"], reconciliation=True), absent=True)
    require(previous_reconcile == reconciliation_raw, "A prior begin recovery is unresolved; do not replay it.")
    scope = digest({"beginIntentSha256": intent_sha, "anchorSha256": recovery.digest(raw),
                    "stateSha256": current["stateSha256"], "contractSha256": digest(contract), "policySha256": digest(policy)})
    return {"approvalAction": "backup-abort-unstarted:" + scope, "stateSha256": current["stateSha256"],
            "beginIntentSha256": intent_sha, "session": pin["session"], "day": pin["day"],
            "candidateSha256": candidate_sha or None,
            "anchorPlanSha256": digest(pending_anchor_plan) if pending_anchor_plan is not None else None}, original, txn


def exact_predecessor(env, state):
    supplied = env.get("BACKUP_STATE_SHA256", "")
    require(re.fullmatch(r"[0-9a-f]{64}", supplied or "") and state.get("stateSha256") == supplied,
            "The exact observed predecessor is required.")
    return supplied


def authorized(target, env, action, source_revision, predecessor, control_revision, *, key="SUBS_BOT_APPROVAL_JSON"):
    return approve(target, env.get(key, ""), action, source_revision, predecessor, control_revision=control_revision)


def last(events, expected):
    require(events[-1]["stage"] == expected, "The maintenance checkpoint or a prior result is unresolved.")


def frozen_matches(events, state):
    frozen = next((event for event in events if event["stage"] == "frozen"), None)
    require(frozen is not None and state.get("control") == frozen["details"].get("control")
            and state.get("configurationSha256") == events[0]["details"].get("configurationSha256")
            and state.get("release") == events[0]["details"].get("release")
            and not any(state.get("work", {}).values())
            and not any(state.get("terminal", {}).get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))


def uncaptured_predecessor(events):
    require(events and (events[-1]["stage"] in {"frozen", "frozen-data"}
            or (len(events) >= 2 and events[-1]["stage"] == "failed"
                and events[-1]["details"].get("uncertain") is False
                and events[-2]["stage"] in {"frozen", "frozen-data"}))
            and not any(event["stage"] in {"capture-intent", "poll-intent"} for event in events),
            "Capture may have started; do not infer an empty export.")
    freeze_intents = [event for event in events if event["stage"] == "freeze-intent"]
    frozen = [event for event in events if event["stage"] == "frozen"]
    fingerprints = [event for event in events if event["stage"] == "frozen-data"]
    require(len(freeze_intents) == len(frozen) == 1 and len(fingerprints) <= 1)
    require_finished_intent(freeze_intents[0]["details"], allowed_actions={"freeze"})
    return frozen[0]["details"]["control"], fingerprints[0]["details"] if fingerprints else None


def confirm_plan_run(session, day, revision):
    run_id, attempt = session.split("-")
    require(attempt == "1")
    token = artifact._github_token()
    run = artifact._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
    require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow.get("id") and workflow.get("path") == ".github/workflows/worker-production-backup.yml"
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and run.get("head_sha") == revision and run.get("display_title") == "Production backup plan-begin at " + revision
            and (run.get("status"), run.get("conclusion")) == ("completed", "success")
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")))
    try:
        created = datetime.strptime(run["created_at"], "%Y-%m-%dT%H:%M:%SZ").strftime("%Y/%m/%d")
    except (KeyError, TypeError, ValueError):
        require(False, "The original plan run date is unavailable.")
    require(created == day)


def intent_metadata(env, state):
    require(env.get("GITHUB_RUN_ATTEMPT") == "1" and re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", "")))
    return {"stateSha256": state["stateSha256"], "control": state["control"],
            "runId": env["GITHUB_RUN_ID"], "runAttempt": "1", "controlRevision": env["GITHUB_SHA"]}


def require_finished_intent(details, *, allowed_actions=None):
    require(isinstance(details, dict) and details.get("runAttempt") == "1"
            and re.fullmatch(r"[1-9][0-9]{0,19}", details.get("runId", ""))
            and re.fullmatch(r"[0-9a-f]{40}", details.get("controlRevision", "")))
    token = artifact._github_token()
    run = artifact._get_json("/actions/runs/" + details["runId"] + "/attempts/1", token)
    workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
    require(str(run.get("id")) == details["runId"] and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow.get("id") and workflow.get("path") == ".github/workflows/worker-production-backup.yml"
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main"
            and run.get("head_sha") == details["controlRevision"] and run.get("status") == "completed"
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")), "The original operation has not independently finished.")
    if allowed_actions is not None:
        require(isinstance(allowed_actions, set) and bool(allowed_actions)
                and run.get("display_title") in {"Production backup " + action + " at " + details["controlRevision"]
                                                for action in allowed_actions},
                "The finished run is not the exact intended backup action.")


def monitor_anchor(anchor, store, target, policy, now):
    """Read committed anchor history; missing or malformed evidence fails closed."""
    pin, _raw, _etag = anchor.read()
    history, current, seen, latest_capacity, latest_completed_failed, latest_pause_exceeded, latest_maximum_exceeded = [], pin, set(), None, None, False, False
    while current["generation"] > 1:
        if current["state"] == "idle":
            session = current["session"]
            require(session not in seen)
            seen.add(session)
            txn = maintenance.Transaction(store, session, current["day"], target.digest, current["controlRevision"])
            events = txn.load()
            require(events and (events[-1]["stage"] in {"resumed", "preserved-frozen"}
                    or events[-1]["stage"] == "failed"))
            require(all(event["timestamp"] <= now for event in events), "A maintenance journal has a future timestamp.")
            verified = [event for event in events if event["stage"] == "verified"]
            if latest_completed_failed is None:
                latest_completed_failed = not (verified and events[-1]["stage"] in {"resumed", "preserved-frozen"})
                latest_pause_exceeded = events[-1]["details"].get("pauseLimitExceeded") is True
                maximum_exceeded = events[-1]["details"].get("maximumPauseExceeded")
                require(maximum_exceeded is None or type(maximum_exceeded) is bool)
                pauses = [event for event in events if event["stage"] == "pause-intent"]
                latest_maximum_exceeded = maximum_exceeded is True or (maximum_exceeded is None
                    and events[-1]["stage"] == "resumed" and pauses
                    and events[-1]["timestamp"] - pauses[0]["timestamp"] > session_maximum(events))
            preflight = [event for event in events if event["stage"] == "preflight"]
            if latest_capacity is None and preflight:
                latest_capacity = preflight[0]["details"].get("capacity")
            require(len(verified) <= 1)
            if verified and events[-1]["stage"] in {"resumed", "preserved-frozen"}:
                history.append((verified[0]["timestamp"], session.split("-")[0]))
        previous = anchor.history_digest_key(current["generation"] - 1, current["previousSha256"])
        current = parsed(store.get(previous))
    latest, latest_plan_run = max(history) if history else (None, None)
    alerts = []
    if type(getattr(anchor, "last_history_count", None)) is int and anchor.last_history_count >= 8000:
        alerts.append("anchor-history-near-limit")
    if latest_completed_failed:
        alerts.append("backup-failed")
    if latest_pause_exceeded:
        alerts.append("pause-limit-exceeded")
    if latest_maximum_exceeded:
        alerts.append("pause-maximum-exceeded")
    if latest is None or now - latest > policy["overdueHours"] * 3600:
        alerts.append("backup-overdue")
    elif now - latest > policy["frequencyHours"] * 3600:
        alerts.append("backup-frequency-exceeded")
    phase = None
    if pin["state"] == "active":
        txn = maintenance.Transaction(store, pin["session"], pin["day"], target.digest, pin["controlRevision"])
        events = txn.load()
        require(events)
        require(all(event["timestamp"] <= now for event in events), "A maintenance journal has a future timestamp.")
        phase = events[-1]["stage"]
        preflight = [event for event in events if event["stage"] == "preflight"]
        if preflight:
            latest_capacity = preflight[0]["details"].get("capacity")
        if phase in {"pause-intent", "freeze-intent", "capture-intent", "poll-intent", "resume-intent"}:
            alerts.append("operation-reconciliation-required")
        if phase == "failed":
            alerts.append("backup-failed")
        pauses = [event for event in events if event["stage"] == "pause-intent"]
        maximum = session_maximum(events) if pauses else None
        if pauses and phase not in {"resumed", "preserved-frozen"} and now - pauses[0]["timestamp"] > events[0]["details"]["pauseLimitSeconds"]:
            if "pause-limit-exceeded" not in alerts:
                alerts.append("pause-limit-exceeded")
        if pauses and phase not in {"resumed", "preserved-frozen"} and now - pauses[0]["timestamp"] > maximum:
            if "pause-maximum-exceeded" not in alerts:
                alerts.append("pause-maximum-exceeded")
    if isinstance(latest_capacity, dict):
        levels = [latest_capacity.get(key) for key in ("rowStatus", "objectStatus", "objectBytesStatus")]
        if "over-limit" in levels or latest_capacity.get("failureReason") == "object-too-large":
            alerts.append("capacity-over-limit")
        elif "warning" in levels:
            alerts.append("capacity-near-limit")
        if any(value not in {"normal", "warning", "over-limit"} for value in levels):
            alerts.append("capacity-unknown")
    else:
        alerts.append("capacity-unknown")
    return {"status": "alert" if alerts else "ok", "action": "monitor", "alerts": alerts,
            "latestVerifiedAt": latest, "latestPlanRunId": latest_plan_run, "phase": phase, "notification": "github-check-only"}


def monitor_workflow_runs(raw_controllers, now, latest_verified, expected_plan_run=None):
    """Bounded GitHub history supplements, but never replaces, private journals."""
    configured = parsed(raw_controllers)
    require(set(configured) == {"version", "revisions"} and type(configured["version"]) is int
            and configured["version"] == 1 and isinstance(configured["revisions"], list)
            and 0 < len(configured["revisions"]) <= 32
            and len(set(configured["revisions"])) == len(configured["revisions"])
            and all(isinstance(item, str) and re.fullmatch(r"[a-f0-9]{40}", item) for item in configured["revisions"]))
    token = artifact._github_token()
    workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
    require(workflow.get("path") == ".github/workflows/worker-production-backup.yml" and type(workflow.get("id")) is int)
    since = datetime.fromtimestamp(max(0, now - 7 * 86400), timezone.utc).strftime("%Y-%m-%d")
    rows, total = [], None
    for page in range(1, 7):
        query = urlencode({"branch": "main", "created": ">=" + since, "per_page": 100, "page": page})
        response = artifact._get_json("/actions/workflows/worker-production-backup.yml/runs?" + query, token)
        batch = response.get("workflow_runs")
        count = response.get("total_count")
        require(type(count) is int and 0 <= count <= 500 and isinstance(batch, list) and len(batch) <= 100)
        require(total is None or total == count, "The workflow history changed during observation.")
        total = count
        rows.extend(batch)
        require(len(rows) <= total)
        if len(rows) == total:
            break
        require(len(batch) == 100, "The workflow history is incomplete.")
    require(total is not None and len(rows) == total)
    observed, failed, unknown, relevant, expected_seen = set(), False, False, 0, False
    for run in rows:
        require(isinstance(run, dict) and type(run.get("id")) is int and run["id"] not in observed
                and run.get("run_attempt") == 1
                and run.get("workflow_id") == workflow["id"] and run.get("head_branch") == "main"
                and run.get("event") in {"workflow_dispatch", "schedule"}
                and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
        observed.add(run["id"])
        revision = run.get("head_sha", "")
        require(isinstance(revision, str) and re.fullmatch(r"[a-f0-9]{40}", revision))
        title = run.get("display_title", "")
        prefix, suffix = "Production backup ", " at " + revision
        require(isinstance(title, str) and title.startswith(prefix) and title.endswith(suffix))
        action = title[len(prefix):-len(suffix)]
        require(action in ACTIONS)
        if str(run["id"]) == expected_plan_run:
            require(action == "plan-begin" and run.get("status") == "completed" and run.get("conclusion") == "success")
            expected_seen = True
        if action == "monitor":
            continue
        relevant += 1
        if revision not in configured["revisions"]:
            unknown = True
            continue
        try:
            updated = int(datetime.strptime(run["updated_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
        except (KeyError, TypeError, ValueError):
            require(False, "The workflow update time is unavailable.")
        require(updated <= now and run.get("status") in {"queued", "in_progress", "completed", "waiting", "pending", "requested"})
        if latest_verified is not None and updated < latest_verified:
            continue
        if run["status"] == "completed":
            require(run.get("conclusion") in {"success", "failure", "cancelled", "timed_out", "action_required", "startup_failure", "stale", "skipped", "neutral"})
            if run["conclusion"] != "success":
                failed = True
        elif now - updated > 1800:
            unknown = True
    return {"failed": failed, "unknown": unknown or relevant == 0 or (expected_plan_run is not None and not expected_seen),
            "runsObserved": len(observed)}


def transition_reconciliation(env, events, state, contract):
    event = events[-1]
    phase = event["stage"]
    require(phase in {"pause-intent", "freeze-intent", "resume-intent"})
    details = event["details"]
    require(isinstance(details, dict) and isinstance(details.get("control"), dict)
            and details.get("runAttempt") == "1" and re.fullmatch(r"[1-9][0-9]{0,19}", details.get("runId", ""))
            and re.fullmatch(r"[0-9a-f]{40}", details.get("controlRevision", "")))
    require_finished_intent(details)
    before = details["control"]
    require(type(before.get("epoch")) is int)
    desired = {"pause-intent": ("closed", before.get("workers")), "freeze-intent": ("closed", "frozen"),
               "resume-intent": ("open", "run")}[phase]
    expected = {**before, "admission": desired[0], "workers": desired[1], "epoch": before["epoch"] + 1}
    require(state.get("control") == expected and state.get("release") == events[0]["details"].get("release")
            and state.get("configurationSha256") == events[0]["details"].get("configurationSha256")
            and not any(state.get("terminal", {}).get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")),
            "The exact successor is not confirmed; do not replay the original write.")
    scope = digest({"contract": contract, "intent": details, "successor": expected})
    return {"phase": phase, "approvalAction": "backup-reconcile-transition:" + scope, "stateSha256": state["stateSha256"]}


def completed_anchor_reconciliation(anchor, store, target, ctl, candidate_sha, contract, policy):
    """Only reconcile a confirmed release after a finished resume operation."""
    plan, _raw, _etag, _candidate_raw = anchor.plan_reconciliation(candidate_sha)
    candidate = plan["candidate"]
    require(candidate["state"] == "idle", "An unconfirmed anchor acquisition requires manual investigation.")
    events = maintenance.Transaction(store, candidate["session"], candidate["day"], target.digest,
                                     candidate["controlRevision"]).load()
    require(len(events) >= 2 and events[-1]["stage"] == "resumed" and events[-2]["stage"] == "resume-intent"
            and events[0]["details"].get("contractSha256") == digest(contract)
            and events[0]["details"].get("policySha256") == digest(policy),
            "Only a fully recorded resume can reconcile an anchor release.")
    require_finished_intent(events[-2]["details"], allowed_actions={"activate", "resume-failed"})
    state = ctl.inspect()
    require(state["control"] == events[-1]["details"].get("control")
            and state["release"] == events[0]["details"].get("release")
            and state["configurationSha256"] == events[0]["details"].get("configurationSha256")
            and not any(state["work"].values())
            and not any(state["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")),
            "The completed transaction or current predecessor is not independently confirmed.")
    anchor_plan_sha = digest(plan)
    scope = digest({"anchorPlanSha256": anchor_plan_sha, "contractSha256": digest(contract),
                    "stateSha256": state["stateSha256"]})
    return {"approvalAction": "backup-anchor-reconcile:" + scope, "stateSha256": state["stateSha256"],
            "anchorPlanSha256": anchor_plan_sha, "candidateSha256": candidate_sha}


def emit_result(result, target, revision, root, *, source_revision=None):
    # Controller observations contain the real Bot identifier and release details.
    # GitHub logs and artifacts are visible to repository readers, so expose only
    # the exact predecessor digest and non-identifying operational aggregates.
    safe_keys = {"status", "action", "alerts", "latestVerifiedAt", "phase", "notification", "approvalAction",
                 "stateSha256", "session", "day", "pauseSeconds", "pauseLimitExceeded", "maximumPauseExceeded", "capacity", "liveCapacity", "checkpointId", "manifestSha256",
                 "anchorPlanSha256", "candidateSha256", "genesisSha256", "historyPresent", "pointerPresent", "mutationPermitted"}
    observed = result.get("state")
    result = {key: value for key, value in result.items() if key in safe_keys}
    if isinstance(observed, dict) and "stateSha256" in observed:
        result["stateSha256"] = observed["stateSha256"]
    result.update(targetSha256=target.digest, controlRevision=revision,
                  scheduleEnabled=False, automaticReplay=False, consumerSwitch="not-authorized")
    if source_revision is not None:
        result["sourceRevision"] = source_revision
    artifact.require_current_main(revision)
    with recovery.native.private_file(root / "production-backup-result.json") as output:
        output.write(canonical(result))
    print(json.dumps(result, sort_keys=True))
    if result.get("action") == "monitor" and result["status"] == "alert":
        print("::warning::Production backup monitoring requires attention.")
        raise SystemExit(1)
    return result


def main(env=None):
    env = os.environ if env is None else env
    action = env.get("BACKUP_ACTION", "")
    require(action in ACTIONS)
    target = validate_target(env.get("SUBS_BOT_TARGET_JSON", ""))
    revision = check_context(env, target)
    if action not in READ_ONLY:
        require_mutation_enabled(env)
    policy = settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", ""))
    root = Path(env["RUNNER_TEMP"])
    require(root.is_absolute() and root.is_dir())
    if action == "monitor":
        # The monitor has its own read-only token and does not load Bot keys,
        # Worker credentials, recovery contracts, CI archives or approvals.
        data = API(target, env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN", ""))
        store = PrivateStore(data, target.data["backupBucketName"])
        anchor = maintenance.Anchor(store, target.digest, env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
        now = int(time.time())
        result = monitor_anchor(anchor, store, target, policy, now)
        try:
            scan = monitor_workflow_runs(env.get("SUBS_BOT_BACKUP_MONITOR_CONTROLLERS_JSON", ""), now,
                                         result["latestVerifiedAt"], result["latestPlanRunId"])
            if scan["failed"]:
                result["alerts"].append("backup-workflow-failed")
            if scan["unknown"]:
                result["alerts"].append("workflow-history-unknown")
        except Exception:
            result["alerts"].append("workflow-history-unknown")
        try:
            import production_backup_live_capacity as live_capacity
            interval = int(env.get("MONITOR_CAPACITY_INTERVAL_MINUTES") or "15")
            if live_capacity.due(env.get("GITHUB_EVENT_NAME", ""), env.get("MONITOR_SCHEDULE", ""), interval):
                observed = live_capacity.sample(target, env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN", ""),
                    env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""), env.get("BACKUP_SOURCE_MANIFEST_SHA256", ""),
                    warning_percent=policy["warningPercent"], root=root, guard=lambda: artifact.require_current_main(revision))
                result["liveCapacity"] = observed
                result["alerts"] = sorted(set(result["alerts"]) | set(live_capacity.alerts(observed)))
            else:
                result["liveCapacity"] = {"status": "not-due", "intervalMinutes": interval}
        except Exception:
            result["liveCapacity"] = {"status": "unknown", "snapshot": False}
            result["alerts"] = sorted(set(result["alerts"]) | {"live-capacity-unknown"})
        result["status"] = "alert" if result["alerts"] else "ok"
        return emit_result(result, target, revision, root)
    contract = recovery.recovery_contract(env.get("SUBS_BOT_RECOVERY_JSON", ""), target.data)
    require(contract.get("purpose") == "baseline" and "sessionId" not in contract,
            "Routine backup requires a fresh baseline checkpoint and no restore session.")
    secrets = parsed(env.get("SUBS_BOT_CONTROL_SECRETS", ""))
    general_config(target, revision, secrets)
    data = API(target, env.get("SUBS_BOT_CF_DATA_TOKEN", ""))
    worker = API(target, env.get("SUBS_BOT_CF_WORKER_TOKEN", ""))
    api = recovery.RecoveryAPI(target.data, env.get("SUBS_BOT_CF_DATA_TOKEN", ""), worker, contract)
    api.verify_backup()
    source_checkpoint = env.get("BACKUP_SOURCE_CHECKPOINT_ID", "")
    source_sha = env.get("BACKUP_SOURCE_MANIFEST_SHA256", "")
    require(bool(source_checkpoint) == bool(source_sha))
    with tempfile.TemporaryDirectory(prefix="production-daily-source-", dir=root) as directory:
        directory = Path(directory)
        if source_checkpoint:
            from production_release_evidence import load_release
            archived = load_release(target, env["SUBS_BOT_CF_DATA_TOKEN"], source_checkpoint, source_sha, directory)
            require(archived["sourceTarget"].configuration_digest == target.configuration_digest)
            bundle, manifest, proof, body = archived["bundle"], archived["manifest"], archived["proof"], archived["body"]
        else:
            body, proof = recovery_cli.ci_archive(env.get("SUBS_BOT_CI_RUN_ID", ""), env.get("SUBS_BOT_CI_RUN_ATTEMPT", "1"), control_revision=revision)
            bundle, manifest = recovery_cli.unpack(body, proof, directory)
        guard = lambda: artifact.require_current_main(revision)
        dependency = API(target, env["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"]) if target.data["provider"] is not None and env.get("SUBS_BOT_CF_DEPENDENCY_READ_TOKEN") else None
        ctl = Controller(target, data, worker, bundle, manifest, guard=guard,
                         telegram=Telegram(target, secrets), secrets=secrets, control_revision=revision, dependency_api=dependency)
        source = recovery.RecoverySource(api, target.data, bundle, manifest, ctl.inspect, guard)
        source.archive_body, source.code_proof = body, proof
        state = ctl.inspect()
        require(state["release"]["revision"] == proof["revision"] and state["release"]["moduleSha256"] == manifest["bundleSha256"],
                "The archived source is not the active release.")
        store = PrivateStore(data, target.data["backupBucketName"])
        seed = maintenance.Anchor(store, target.digest, "0" * 64)
        genesis_sha = recovery.digest(seed.initial_material()[1])
        supplied_genesis = env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", "")
        require(supplied_genesis == genesis_sha or action == "plan-initialize-anchor" and not supplied_genesis,
                "The independently pinned maintenance genesis differs.")
        anchor = maintenance.Anchor(store, target.digest, genesis_sha)
        if action == "inspect-anchor-initialization":
            plan, _initial, _etag = anchor.plan_initialization_reconciliation()
            result = {"status": "unknown", "action": action, "anchorPlanSha256": digest(plan),
                      "historyPresent": plan["historyPresent"], "pointerPresent": plan["pointerPresent"],
                      "genesisSha256": genesis_sha, "stateSha256": state["stateSha256"], "mutationPermitted": False}
        elif action == "inspect-anchor-unknown":
            result = {**missing_started_observation(anchor, store, target), "action": action,
                      "stateSha256": state["stateSha256"]}
        elif action in {"plan-initialize-anchor", "initialize-anchor"}:
            require(store.get(anchor.genesis_key, absent=True) is None and store.get_with_etag(anchor.key) == (None, None)
                    and not store.list_backup_anchor_history(target.digest) and not store.list_backup_journals(),
                    "An existing or partial maintenance anchor requires independent reconciliation.")
            scope = digest({"policy": policy, "genesisSha256": genesis_sha, "contract": contract})
            approval_action = "backup-initialize-anchor:" + scope
            if action == "plan-initialize-anchor":
                result = {"status": "plan-only", "action": action, "approvalAction": approval_action,
                          "stateSha256": state["stateSha256"], "genesisSha256": genesis_sha}
            else:
                predecessor = exact_predecessor(env, state)
                authorized(target, env, approval_action, proof["revision"], predecessor, revision)
                guard()
                anchor.initialize()
                result = {"status": "initialized", "action": action}
        elif action in {"plan-begin", "begin"}:
            require(state["control"]["admission"] == "open" and state["control"]["workers"] == "run"
                    and not any(state["terminal"].get(key, 0) for key in ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
            now = datetime.now(timezone.utc)
            if action == "plan-begin":
                require(env.get("GITHUB_RUN_ATTEMPT") == "1" and re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", "")))
                session, day = env["GITHUB_RUN_ID"] + "-1", now.strftime("%Y/%m/%d")
            else:
                session, day = session_input(env)
                confirm_plan_run(session, day, revision)
            require(day == now.strftime("%Y/%m/%d") and in_window(policy, now), "The selected maintenance window is not open.")
            pin, anchor_raw, anchor_etag = anchor.read()
            require(pin["state"] == "idle" and pin["session"] != session)
            scope = digest({"policy": policy, "contract": contract, "session": session, "day": day,
                            "anchorSha256": recovery.digest(anchor_raw)})
            approval_action = "backup-begin:" + scope
            if action == "plan-begin":
                result = {"status": "plan-only", "action": action, "approvalAction": approval_action,
                          "stateSha256": state["stateSha256"], "session": session, "day": day}
            else:
                predecessor = exact_predecessor(env, state)
                authorized(target, env, approval_action, proof["revision"], predecessor, revision)
                journal = maintenance.Transaction(store, session, day, target.digest, revision)
                require(not journal.load())
                guard()
                started = {"configurationSha256": target.configuration_digest, "control": state["control"],
                    "release": state["release"], "pauseLimitSeconds": policy["pauseLimitSeconds"],
                    "maximumPauseSeconds": maximum_pause(policy),
                    "checkpointId": contract["checkpointId"], "contractSha256": digest(contract), "policySha256": digest(policy)}
                original = {"version": 1, "targetSha256": target.digest, "session": session, "day": day,
                    "controlRevision": revision, "dispatcherRevision": revision, "dispatcherWorkflow": "worker-production-backup.yml",
                    "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": env["GITHUB_RUN_ATTEMPT"],
                    "anchorPredecessorSha256": recovery.digest(anchor_raw), "stateSha256": state["stateSha256"],
                    "sourceRevision": proof["revision"], "approvalSha256": recovery.digest(env["SUBS_BOT_APPROVAL_JSON"].encode("utf-8")),
                    "timestamp": int(time.time()), "startedDetails": started}
                intent_sha = maintenance.write_begin(store, original)
                guard()
                require(ctl.inspect()["stateSha256"] == predecessor, "The approved begin predecessor changed.")
                anchor._advance(pin, anchor_raw, anchor_etag, state="active", session=session, day=day, revision=revision)
                journal.append("started", {**started, "beginIntentSha256": intent_sha}, int(time.time()))
                result = {"status": "started", "action": action, "session": session, "day": day}
        elif action in {"plan-abort-unstarted", "abort-unstarted"}:
            candidate = env.get("BACKUP_ANCHOR_CANDIDATE_SHA256", "") or None
            plan, original, journal = unstarted_abort_plan(anchor, store, target, ctl, contract, policy, candidate_sha=candidate)
            if action == "plan-abort-unstarted":
                result = {"status": "plan-only", "action": action, **plan}
            else:
                predecessor = exact_predecessor(env, plan)
                authorized(target, env, plan["approvalAction"], proof["revision"], predecessor, revision)
                claim = {"version": 1, "targetSha256": target.digest, "session": plan["session"],
                         "beginIntentSha256": plan["beginIntentSha256"], "stateSha256": predecessor,
                         "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": env["GITHUB_RUN_ATTEMPT"],
                         "controlRevision": revision}
                maintenance.claim_begin_reconciliation(store, target.digest, plan["session"], claim)
                guard()
                again, _original, _journal = unstarted_abort_plan(anchor, store, target, ctl, contract, policy,
                    candidate_sha=candidate, reconciliation_raw=canonical(claim))
                require(again == plan, "The approved begin recovery predecessor changed.")
                if candidate:
                    anchor.reconcile(candidate, plan["anchorPlanSha256"])
                journal.append("started", {**original["startedDetails"], "beginIntentSha256": plan["beginIntentSha256"],
                                           "reconciledUnstarted": True}, int(time.time()))
                journal.append("failed", {"reason": "aborted-before-start-confirmation", "uncertain": False}, int(time.time()))
                anchor.release(plan["session"])
                result = {"status": "aborted-before-pause", "action": action, "session": plan["session"]}
        elif action in {"plan-anchor-reconcile", "anchor-reconcile"}:
            candidate = env.get("BACKUP_ANCHOR_CANDIDATE_SHA256", "")
            plan = completed_anchor_reconciliation(anchor, store, target, ctl, candidate, contract, policy)
            if action == "plan-anchor-reconcile":
                result = {"status": "plan-only", "action": action, **plan}
            else:
                predecessor = exact_predecessor(env, plan)
                authorized(target, env, plan["approvalAction"], proof["revision"], predecessor, revision)
                guard()
                require(completed_anchor_reconciliation(anchor, store, target, ctl, candidate, contract, policy) == plan,
                        "The exact approved anchor reconciliation changed.")
                anchor.reconcile(candidate, plan["anchorPlanSha256"])
                result = {"status": "anchor-release-reconciled", "action": action,
                          "candidateSha256": candidate, "anchorPlanSha256": plan["anchorPlanSha256"]}
        else:
            pin, journal, events = active_transaction(anchor, store, target)
            require(events[0]["details"].get("contractSha256") == digest(contract)
                    and events[0]["details"].get("policySha256") == digest(policy)
                    and events[0]["details"].get("configurationSha256") == target.configuration_digest)
            if action == "inspect":
                result = {"status": "observed", "action": action, "phase": events[-1]["stage"], "state": state}
            elif action == "preflight":
                last(events, "started")
                predecessor = exact_predecessor(env, state)
                authorized(target, env, "backup-preflight:" + digest(contract), proof["revision"], predecessor, revision)
                observed = capacity.observe(api, source, warning_percent=policy["warningPercent"])
                guard()
                journal.append("preflight", {"capacity": observed}, int(time.time()))
                result = {"status": "observed", "action": action, "capacity": {key: value for key, value in observed.items() if key != "tableCounts"}}
            elif action == "abort-preflight":
                require(events[-1]["stage"] in {"started", "preflight"},
                        "Only an operation confirmed not to have started pausing can be aborted.")
                predecessor = exact_predecessor(env, state)
                require(state["control"] == events[0]["details"]["control"] and state["release"] == events[0]["details"]["release"])
                authorized(target, env, "backup-abort-preflight:" + digest(contract), proof["revision"], predecessor, revision)
                journal.append("failed", {"reason": "operator-aborted-before-pause", "uncertain": False}, int(time.time()))
                anchor.release(pin["session"])
                result = {"status": "aborted-before-pause", "action": action}
            elif action == "plan-pause":
                last(events, "preflight")
                result = ctl.plan_pause()
            elif action == "pause":
                last(events, "preflight")
                require(in_window(policy, datetime.now(timezone.utc)), "A new pause cannot start outside its approved UTC window.")
                observed = events[-1]["details"]["capacity"]
                capacity.require_within_limits(observed)
                plan = ctl.plan_pause()
                require(plan["control"] == events[0]["details"]["control"] and plan["release"] == events[0]["details"]["release"]
                        and plan["configurationSha256"] == events[0]["details"]["configurationSha256"])
                predecessor = exact_predecessor(env, plan)
                ctl.approval(env.get("SUBS_BOT_APPROVAL_JSON", ""), "pause", predecessor)
                journal.append("pause-intent", intent_metadata(env, plan), int(time.time()))
                after = ctl.transition("pause", env.get("SUBS_BOT_APPROVAL_JSON", ""), predecessor)
                journal.append("paused", {"control": after["control"]}, int(time.time()))
                result = {"status": "paused", "action": action, "state": after}
            elif action == "drain":
                last(events, "paused")
                require(state["control"]["admission"] == "closed" and not any(state["work"].values()))
                result = {"status": "drained", "action": action, "state": state}
            elif action == "freeze":
                last(events, "paused")
                require_pause_window(events, policy)
                def freeze_guard():
                    guard()
                    require_pause_window(events, policy)
                ctl.guard = freeze_guard
                require(state["control"] == events[-1]["details"]["control"]
                        and state["release"] == events[0]["details"]["release"]
                        and state["configurationSha256"] == events[0]["details"]["configurationSha256"])
                predecessor = exact_predecessor(env, state)
                ctl.approval(env.get("SUBS_BOT_APPROVAL_JSON", ""), "freeze", predecessor)
                freeze_guard()
                journal.append("freeze-intent", intent_metadata(env, state), int(time.time()))
                after = ctl.transition("freeze", env.get("SUBS_BOT_APPROVAL_JSON", ""), predecessor)
                journal.append("frozen", {"control": after["control"]}, int(time.time()))
                journal.append("frozen-data", capacity.frozen_fingerprint(api, source), int(time.time()))
                result = {"status": "frozen", "action": action, "state": after}
            elif action == "fingerprint":
                last(events, "frozen")
                frozen_matches(events, state)
                predecessor = exact_predecessor(env, state)
                authorized(target, env, "backup-fingerprint:" + digest(contract), proof["revision"], predecessor, revision)
                journal.append("frozen-data", capacity.frozen_fingerprint(api, source), int(time.time()))
                result = {"status": "frozen-data-confirmed", "action": action}
            elif action in {"plan-reconcile-transition", "reconcile-transition"}:
                plan = transition_reconciliation(env, events, state, contract)
                if action == "plan-reconcile-transition":
                    result = {"status": "plan-only", "action": action, **plan}
                else:
                    predecessor = exact_predecessor(env, state)
                    authorized(target, env, plan["approvalAction"], proof["revision"], predecessor, revision)
                    guard()
                    require(transition_reconciliation(env, events, ctl.inspect(), contract) == plan,
                            "The approved reconciliation observation changed.")
                    next_stage = {"pause-intent": "paused", "freeze-intent": "frozen", "resume-intent": "resumed"}[plan["phase"]]
                    details = {"control": state["control"], "reconciled": True}
                    if next_stage == "resumed":
                        pause = next(event for event in events if event["stage"] == "pause-intent")
                        elapsed = max(0, int(time.time()) - pause["timestamp"])
                        details.update(pauseSeconds=elapsed, pauseLimitExceeded=elapsed > policy["pauseLimitSeconds"],
                                       maximumPauseExceeded=elapsed > maximum_pause(policy))
                    journal.append(next_stage, details, int(time.time()))
                    if next_stage == "resumed":
                        anchor.release(pin["session"])
                    result = {"status": "reconciled", "action": action, "phase": next_stage}
            elif action in {"plan-resume-failed", "resume-failed"}:
                # No export may be inferred stopped from missing evidence. Before
                # capture, require the complete journal and an absent recovery journal.
                prior = events[-2] if events[-1]["stage"] == "failed" and len(events) > 1 else events[-1]
                require(prior["stage"] in {"paused", "frozen", "frozen-data", "capture-intent"})
                initial = events[0]["details"]
                pause = next(item for item in events if item["stage"] == "pause-intent")
                require_finished_intent(pause["details"])
                common = {"initial": initial, "session": pin["session"]}
                if prior["stage"] == "paused":
                    kwargs = {**common, "paused": prior["details"]["control"]}
                    plan = resume.plan_aborted_drain(ctl, **kwargs)
                elif prior["stage"] in {"frozen", "frozen-data"}:
                    frozen_control, fingerprint = uncaptured_predecessor(events)
                    rj = recovery.RecoveryJournal(api, env["GITHUB_RUN_ID"] + "/" + env["GITHUB_RUN_ATTEMPT"], guard=guard)
                    kwargs = {**common, "frozen": frozen_control, "fingerprint": fingerprint}
                    plan = resume.plan_uncaptured_backup(ctl, api, source, rj, **kwargs)
                else:
                    require_finished_intent(prior["details"])
                    frozen = next(item for item in events if item["stage"] == "frozen")
                    fingerprint = next(item for item in events if item["stage"] == "frozen-data")
                    rj = recovery.RecoveryJournal(api, env["GITHUB_RUN_ID"] + "/" + env["GITHUB_RUN_ATTEMPT"], guard=guard)
                    kwargs = {**common, "frozen": frozen["details"]["control"], "fingerprint": fingerprint["details"]}
                    plan = resume.plan_failed_backup(ctl, api, source, rj, **kwargs)
                if action == "plan-resume-failed":
                    result = {"status": "plan-only", "action": action, **plan}
                else:
                    require(exact_predecessor(env, state) == plan["stateSha256"])
                    def record_intent(state_sha, approval_action):
                        require(state_sha == state["stateSha256"] and approval_action == plan["approvalAction"])
                        journal.append("resume-intent", {**intent_metadata(env, state), "approvalAction": approval_action}, int(time.time()))
                    if prior["stage"] == "paused":
                        after = resume.resume_aborted_drain(ctl, **kwargs, approval_envelope=env.get("SUBS_BOT_APPROVAL_JSON", ""), record_intent=record_intent)
                    elif prior["stage"] in {"frozen", "frozen-data"}:
                        after = resume.resume_uncaptured_backup(ctl, api, source, rj, **kwargs, approval_envelope=env.get("SUBS_BOT_APPROVAL_JSON", ""), record_intent=record_intent)
                    else:
                        after = resume.resume_failed_backup(ctl, api, source, rj, **kwargs, approval_envelope=env.get("SUBS_BOT_APPROVAL_JSON", ""), record_intent=record_intent)
                    elapsed = max(0, int(time.time()) - pause["timestamp"])
                    journal.append("resumed", {"control": after["control"], "pauseSeconds": elapsed,
                                   "pauseLimitExceeded": elapsed > policy["pauseLimitSeconds"],
                                   "maximumPauseExceeded": elapsed > maximum_pause(policy), "backupVerified": False}, int(time.time()))
                    anchor.release(pin["session"])
                    result = {"status": "resumed-after-failure", "action": action, "pauseSeconds": elapsed,
                              "pauseLimitExceeded": elapsed > policy["pauseLimitSeconds"], "maximumPauseExceeded": elapsed > maximum_pause(policy)}
            elif action == "capture":
                last(events, "frozen-data")
                require_pause_window(events, policy)
                def capture_guard():
                    guard()
                    require_pause_window(events, policy)
                source.guard = capture_guard
                frozen_matches(events, state)
                predecessor = exact_predecessor(env, state)
                for name, key in (("prepare", "SUBS_BOT_BACKUP_PREPARE_APPROVAL_JSON"), ("capture", "SUBS_BOT_BACKUP_CAPTURE_APPROVAL_JSON")):
                    authorized(target, env, "recovery-" + name + ":" + digest(contract), proof["revision"], predecessor, revision, key=key)
                owner = env["GITHUB_RUN_ID"] + "/" + env["GITHUB_RUN_ATTEMPT"]
                recovery_journal = recovery.RecoveryJournal(api, owner, guard=guard)
                recovery_journal.load()
                require(recovery_journal.value is None, "The capture checkpoint already exists; reconcile instead of restarting.")
                capture_guard()
                journal.append("capture-intent", {**intent_metadata(env, state), "checkpointId": contract["checkpointId"]}, int(time.time()))
                try:
                    engine = recovery.RecoveryEngine(api, source, recovery_journal, directory)
                    recovery.run_action("prepare", engine)
                    result = recovery.run_action("capture", engine)
                finally:
                    recovery_journal.release()
                result = {"status": "captured-unverified", "action": action, "backup": result["backup"]}
            elif action == "poll-export":
                last(events, "capture-intent")
                frozen_matches(events, state)
                require_finished_intent(events[-1]["details"])
                predecessor = exact_predecessor(env, state)
                owner = env["GITHUB_RUN_ID"] + "/" + env["GITHUB_RUN_ATTEMPT"]
                rj = recovery.RecoveryJournal(api, owner, guard=guard)
                rj.load()
                saved = rj.value.get("export") if isinstance(rj.value, dict) else None
                require(isinstance(saved, dict) and saved.get("state") == "polling"
                        and recovery.matches(recovery.native.BOOKMARK, saved.get("bookmark")),
                        "Only the original confirmed export bookmark may be polled.")
                bookmark_sha = recovery.digest(saved["bookmark"].encode("utf-8"))
                scope = "recovery-poll-export:" + digest(contract)
                authorized(target, env, scope, proof["revision"], predecessor, revision)
                guard()
                rj.claim()
                try:
                    saved = rj.value.get("export")
                    require(isinstance(saved, dict) and saved.get("state") == "polling"
                            and recovery.digest(saved.get("bookmark", "").encode("utf-8")) == bookmark_sha)
                    journal.append("poll-intent", {**intent_metadata(env, state), "bookmarkSha256": bookmark_sha,
                                   "checkpointId": contract["checkpointId"]}, int(time.time()))
                    engine = recovery.RecoveryEngine(api, source, rj, directory)
                    outcome = recovery.run_action("poll-export", engine)
                    journal.append("capture-intent", {**intent_metadata(env, state), "checkpointId": contract["checkpointId"],
                                   "pollConfirmed": True}, int(time.time()))
                finally:
                    rj.release()
                result = {"status": "captured-unverified", "action": action, "backup": outcome["backup"]}
            elif action == "verify":
                last(events, "capture-intent")
                frozen_matches(events, state)
                predecessor = exact_predecessor(env, state)
                authorized(target, env, "backup-verify:" + digest(contract), proof["revision"], predecessor, revision)
                rj = recovery.RecoveryJournal(api, env["GITHUB_RUN_ID"] + "/" + env["GITHUB_RUN_ATTEMPT"], guard=guard)
                rj.load()
                engine = recovery.RecoveryEngine(api, source, rj, directory)
                verified = recovery.run_action("verify-backup", engine)
                manifest_sha = verified["backup"].get("manifestSha256")
                from production_release_evidence import verify_activation_baseline
                proof_result = verify_activation_baseline(ctl, env["SUBS_BOT_CF_DATA_TOKEN"], contract["checkpointId"], manifest_sha)
                require(proof_result.get("baselineVerified") is True and proof_result.get("manifestSha256") == manifest_sha)
                journal.append("verified", {"checkpointId": contract["checkpointId"], "manifestSha256": manifest_sha}, int(time.time()))
                result = {"status": "verified", "action": action, "checkpointId": contract["checkpointId"], "manifestSha256": manifest_sha}
            elif action in {"plan-activate", "activate"}:
                last(events, "verified")
                frozen_matches(events, state)
                from production_release_evidence import verify_activation_baseline
                checkpoint = events[-1]["details"]["checkpointId"]
                manifest_sha = events[-1]["details"]["manifestSha256"]
                ctl.activation_baseline_checker = lambda: verify_activation_baseline(ctl, env["SUBS_BOT_CF_DATA_TOKEN"], checkpoint, manifest_sha)
                plan = ctl.plan_activate()
                if action == "plan-activate":
                    result = plan
                else:
                    predecessor = exact_predecessor(env, plan)
                    ctl.approval(env.get("SUBS_BOT_APPROVAL_JSON", ""), "activate", predecessor)
                    journal.append("resume-intent", intent_metadata(env, plan), int(time.time()))
                    after = ctl.transition("activate", env.get("SUBS_BOT_APPROVAL_JSON", ""), predecessor)
                    started = next(event for event in events if event["stage"] == "pause-intent")
                    elapsed = max(0, int(time.time()) - started["timestamp"])
                    journal.append("resumed", {"control": after["control"], "pauseSeconds": elapsed,
                        "pauseLimitExceeded": elapsed > policy["pauseLimitSeconds"], "maximumPauseExceeded": elapsed > maximum_pause(policy)}, int(time.time()))
                    anchor.release(pin["session"])
                    result = {"status": "resumed", "action": action, "pauseSeconds": elapsed,
                              "pauseLimitExceeded": elapsed > policy["pauseLimitSeconds"], "maximumPauseExceeded": elapsed > maximum_pause(policy)}
            else:
                raise ValueError("Unsupported backup action.")
        return emit_result(result, target, revision, root, source_revision=proof["revision"])


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "The backup checkpoint was not confirmed; retain its private intent and inspect before continuing."}))
        raise SystemExit(1) from None

"""Observe dedicated rehearsal backup runs and their immutable private journals.

No application operation is performed and no external notification is sent.
The verified event records a completed independent readback at backup time; this
observer does not claim to re-read the backup contents itself.
"""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from urllib.parse import urlencode

import prepare_isolation_artifact as github
from production_control import API
from production_lifecycle_drill import configuration, ORIGINAL_SERVICE, SERVICE
from production_storage import PrivateStore
from production_target import require, parsed, validate_target
from production_backup_transaction import Anchor, Transaction, interruption
import production_backup_live_capacity as live_capacity
import production_backup_notification as notification

WORKFLOW = ".github/workflows/worker-production-lifecycle-rehearsal.yml"
MONITOR_WORKFLOW = "jacklilyhello/subs-bot/.github/workflows/worker-backup-monitor.yml@refs/heads/main"
HEX = re.compile(r"[0-9a-f]{64}")
CHECKPOINT = re.compile(r"[0-9a-f]{32}")


def _timestamp(value):
    require(isinstance(value, str) and value.endswith("Z"))
    try:
        result = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        require(False, "Invalid hosted run timestamp.")
    return int(result.timestamp())


def read_runs(now, *, lookback_hours, token):
    """Read a complete bounded GitHub workflow inventory, rejecting truncation."""
    since = (datetime.fromtimestamp(now, timezone.utc) - timedelta(hours=lookback_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    workflow = github._get_json("/actions/workflows/worker-production-lifecycle-rehearsal.yml", token)
    require(type(workflow.get("id")) is int and workflow.get("path") == WORKFLOW)
    selected, total, count = [], None, 0
    for page in range(1, 11):
        query = urlencode({"per_page": 100, "page": page, "branch": "main", "created": ">=" + since})
        result = github._get_json("/actions/workflows/" + str(workflow["id"]) + "/runs?" + query, token)
        rows = result.get("workflow_runs")
        require(isinstance(rows, list) and len(rows) <= 100 and type(result.get("total_count")) is int)
        if total is None:
            total = result["total_count"]
            require(total <= 1000, "Backup run inventory exceeds the monitoring bound.")
        require(result["total_count"] == total, "Backup run inventory changed during pagination.")
        count += len(rows)
        for run in rows:
            require(isinstance(run, dict))
            sha = run.get("head_sha")
            if run.get("display_title") != "Production lifecycle rehearsal daily-backup at " + str(sha):
                continue
            require(run.get("workflow_id") == workflow["id"] and run.get("path") in (WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main")
                    and run.get("event") in {"workflow_dispatch", "schedule"} and run.get("head_branch") == "main"
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository"))
                    and isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha)
                    and type(run.get("id")) is int and run["id"] > 0 and type(run.get("run_attempt")) is int and run["run_attempt"] > 0)
            created = _timestamp(run.get("created_at"))
            require(created <= now + 60)
            selected.append({"runId": str(run["id"]), "runAttempt": str(run["run_attempt"]),
                             "revision": sha, "created": created, "status": run.get("status"), "conclusion": run.get("conclusion")})
        if count == total:
            break
        require(len(rows) == 100 and count < total)
    require(count == total, "Backup run inventory was truncated.")
    return sorted(selected, key=lambda item: (item["created"], int(item["runId"])), reverse=True)


def evaluate(runs, journals, now, *, overdue_hours=48, timeout_minutes=30):
    """Evaluate already identity-checked runs and hash-chain-checked journals."""
    require(type(now) is int and type(overdue_hours) is int and 1 <= overdue_hours <= 168
            and type(timeout_minutes) is int and 1 <= timeout_minutes <= 180)
    alerts, latest_verified, capacity = set(), None, None
    for run in runs:
        session = run["runId"] + "-" + run["runAttempt"]
        events = journals.get(session, [])
        require(all(event["timestamp"] <= now + 60 and event["timestamp"] >= run["created"] - 60 for event in events))
        verified = [event for event in events if event["stage"] == "verified"]
        preflight = [event for event in events if event["stage"] == "preflight"]
        require(len(verified) <= 1 and len(preflight) <= 1)
        if verified:
            details = verified[0]["details"]
            require(CHECKPOINT.fullmatch(details.get("checkpointId", "")) and HEX.fullmatch(details.get("manifestSha256", "")),
                    "Backup success lacks a complete checkpoint and manifest pin.")
            if run["status"] == "completed" and run["conclusion"] == "success" and events[-1]["stage"] in {"resumed", "preserved-frozen"}:
                latest_verified = max(latest_verified or 0, verified[0]["timestamp"])
        if capacity is None and preflight:
            capacity = preflight[0]["details"].get("capacity")
            require(isinstance(capacity, dict))
            states = [capacity.get("rowStatus"), capacity.get("objectStatus"), capacity.get("objectBytesStatus")]
            require(all(value in {"normal", "warning", "over-limit", "not-checked", "unknown", "unverified", None} for value in states))
            if "over-limit" in states:
                alerts.add("capacity-over-limit")
            elif "warning" in states:
                alerts.add("capacity-near-limit")
            if any(value in {"not-checked", "unknown", "unverified", None} for value in states):
                alerts.add("capacity-unknown")
            reason = capacity.get("failureReason")
            require(reason is None or reason in {"source-changed-during-scan", "object-inventory-failed", "object-missing",
                    "object-inventory-invalid", "object-too-large", "object-metadata-invalid", "object-read-failed",
                    "object-changed-during-scan", "reference-or-digest-invalid", "read-or-validation-failed"})
            if reason:
                alerts.add("capacity-" + reason)
                if reason == "object-too-large":
                    alerts.add("capacity-over-limit")
        if run is runs[0]:
            paused = [event for event in events if event["stage"] == "paused"]
            intents = [event for event in events if event["stage"] == "pause-intent"]
            resumed = [event for event in events if event["stage"] == "resumed"]
            if paused:
                require(events[0]["stage"] == "started")
                warning = events[0]["details"].get("pauseLimitSeconds")
                maximum = events[0]["details"].get("maximumPauseSeconds", 1800)
                require(type(warning) is int and 60 <= warning <= 900 and type(maximum) is int
                        and 300 <= maximum <= 21600 and maximum >= warning and len(paused) == 1 and len(resumed) <= 1)
                started = intents[0]["timestamp"] if intents else paused[0]["timestamp"]
                if resumed:
                    require(type(resumed[0]["details"].get("pauseLimitExceeded")) is bool)
                    if resumed[0]["details"]["pauseLimitExceeded"]:
                        alerts.add("pause-limit-exceeded")
                    maximum_exceeded = resumed[0]["details"].get("maximumPauseExceeded")
                    require(maximum_exceeded is None or type(maximum_exceeded) is bool)
                    if maximum_exceeded is True or (maximum_exceeded is None and resumed[0]["timestamp"] - started > maximum):
                        alerts.add("pause-maximum-exceeded")
                else:
                    if now - started > warning:
                        alerts.add("pause-limit-exceeded")
                    if now - started > maximum:
                        alerts.add("pause-maximum-exceeded")
            elif intents:
                alerts.add("pause-state-unconfirmed")
            if run["status"] == "completed":
                if run["conclusion"] == "timed_out":
                    alerts.add("timed-out")
                elif run["conclusion"] != "success":
                    alerts.add("failed")
                elif not verified or not events or events[-1]["stage"] not in {"resumed", "preserved-frozen"}:
                    alerts.add("evidence-incomplete")
            elif run["status"] in {"queued", "in_progress", "waiting", "requested", "pending"}:
                if now - run["created"] > timeout_minutes * 60:
                    alerts.add("timed-out")
            else:
                alerts.add("run-state-unknown")
    if latest_verified is None or now - latest_verified > overdue_hours * 3600:
        alerts.add("backup-overdue")
    if capacity is None:
        alerts.add("capacity-unknown")
    return {"version": 1, "scope": "registered-rehearsal-only", "observedAt": now,
            "latestVerifiedAt": latest_verified, "latestRun": runs[0] if runs else None,
            "alerts": sorted(alerts), "status": "alert" if alerts else "ok",
            "capacity": capacity, "notification": "github-check-only", "archiveRereadByMonitor": False}


def main():
    require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY
            and os.environ.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and os.environ.get("GITHUB_REF") == github.MAIN_REF
            and os.environ.get("GITHUB_EVENT_NAME") in {"workflow_dispatch", "schedule"}
            and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and os.environ.get("SUBS_BOT_CONTROL_ENVIRONMENT") == "subs-bot-isolation"
            and os.environ.get("GITHUB_WORKFLOW_REF") == MONITOR_WORKFLOW)
    revision = os.environ.get("GITHUB_SHA", "")
    github.require_current_main(revision)
    overdue = int(os.environ.get("MONITOR_OVERDUE_HOURS") or "48")
    timeout = int(os.environ.get("MONITOR_TIMEOUT_MINUTES") or "30")
    require(1 <= overdue <= 168 and 1 <= timeout <= 180)
    now = int(datetime.now(timezone.utc).timestamp())
    draft, _secrets, _previous, original = configuration(os.environ)
    anchor = {**draft.data, "d1Id": original["d1Id"], "d1Name": ORIGINAL_SERVICE,
              "backupBucketName": ORIGINAL_SERVICE, "backupBucketCreatedAt": original["r2CreatedOn"]}
    anchor_store = PrivateStore(API(anchor, os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")), ORIGINAL_SERVICE)
    registration_key = "maintenance/production-control/evidence/lifecycle-" + draft.digest + "/registration.json"
    raw = anchor_store.get(registration_key)
    require(HEX.fullmatch(os.environ.get("DRILL_REGISTRATION_SHA256", ""))
            and sha256(raw).hexdigest() == os.environ["DRILL_REGISTRATION_SHA256"])
    registration = parsed(raw)
    target = validate_target(registration.get("target"))
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE
            and registration.get("draftSha256") == draft.digest and registration.get("targetSha256") == target.digest
            and registration.get("configurationSha256") == target.configuration_digest)
    store = PrivateStore(API(target, os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")), target.data["backupBucketName"])
    runs = read_runs(now, lookback_hours=max(168, overdue + 24), token=github._github_token())
    journals = {}
    for run in runs:
        session = run["runId"] + "-" + run["runAttempt"]
        day = datetime.fromtimestamp(run["created"], timezone.utc).strftime("%Y/%m/%d")
        journals[session] = Transaction(store, session, day, target.digest, run["revision"]).load()
    result = evaluate(runs, journals, now, overdue_hours=overdue, timeout_minutes=timeout)
    anchor = Anchor(store, target.digest, os.environ.get("DRILL_BACKUP_GENESIS_SHA256", ""))
    active, _raw, _etag = anchor.read()
    result["anchorHistoryObjects"] = anchor.last_history_count
    if anchor.last_history_count >= 8000:
        result["alerts"] = sorted(set(result["alerts"]) | {"anchor-history-near-limit"})
        result["status"] = "alert"
    if active is not None and active["state"] == "active":
        session = active["session"]
        events = Transaction(store, session, active["day"], target.digest, active["controlRevision"]).load()
        result["activeTransaction"] = {"session": session, "state": interruption(events),
                                       "stage": events[-1]["stage"] if events else "missing"}
        matching = [run for run in runs if run["runId"] + "-" + run["runAttempt"] == session]
        normally_running = (len(matching) == 1 and matching[0]["status"] in
                            {"queued", "in_progress", "waiting", "requested", "pending"}
                            and now - matching[0]["created"] <= timeout * 60)
        if not normally_running:
            result["alerts"] = sorted(set(result["alerts"]) | {"maintenance-transaction-unresolved"})
            result["status"] = "alert"
    try:
        interval = int(os.environ.get("MONITOR_CAPACITY_INTERVAL_MINUTES") or "15")
        if live_capacity.due(os.environ.get("GITHUB_EVENT_NAME", ""), os.environ.get("MONITOR_SCHEDULE", ""), interval):
            warning = int(os.environ.get("MONITOR_WARNING_PERCENT") or "80")
            observed = live_capacity.sample(target, os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""),
                os.environ.get("DRILL_BACKUP_SOURCE_CHECKPOINT_ID", ""),
                os.environ.get("DRILL_BACKUP_SOURCE_MANIFEST_SHA256", ""), warning_percent=warning,
                root=os.environ.get("RUNNER_TEMP", ""), guard=lambda: github.require_current_main(revision))
            result["liveCapacity"] = observed
            result["alerts"] = sorted(set(result["alerts"]) | set(live_capacity.alerts(observed)))
        else:
            result["liveCapacity"] = {"status": "not-due", "intervalMinutes": interval}
    except Exception:
        result["liveCapacity"] = {"status": "unknown", "snapshot": False}
        result["alerts"] = sorted(set(result["alerts"]) | {"live-capacity-unknown"})
    result["status"] = "alert" if result["alerts"] else "ok"
    github.require_current_main(revision)
    return result


if __name__ == "__main__":
    try:
        report = main()
    except Exception:
        report = {"version": 1, "scope": "registered-rehearsal-only", "status": "alert",
                  "alerts": ["monitor-unknown"], "notification": "github-check-only", "archiveRereadByMonitor": False}
    report = notification.prepare(report, os.environ.get("MONITOR_NOTIFICATION_FILTER", "*"))
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":"))
    output = Path(os.environ["RUNNER_TEMP"]) / "production-backup-monitor.json"
    notification.write(report, output, os.environ.get("GITHUB_OUTPUT"))
    print(encoded)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as stream:
            stream.write("## Rehearsal backup monitor\n\nStatus: " + report["status"] + "\n\nAlerts: "
                         + (", ".join(report["alerts"]) or "none") + "\n")
    if report["status"] != "ok":
        print("::warning::Backup monitoring requires attention; see the bounded report.")
        raise SystemExit(1)

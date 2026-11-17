"""Read-only inventory of prior test webhook operations before a new window.

Unknown, missing or incomplete historical evidence blocks a write. A digest is
returned for an independently pinned protected configuration; it is not an
assertion that an unresolved operation succeeded.
"""
from hashlib import sha256
from io import BytesIO
from datetime import datetime, timezone
import json
import os
import re
from urllib.parse import quote
from zipfile import BadZipFile, ZipFile

import prepare_isolation_artifact as github
from production_backup_webhook_recovery import (open_store, context, ORIGINAL_ORIGIN, webhook_settings,
                                                 probe_original_webhook, Telegram)
from production_target import canonical, parsed, require, validate_target

LIFECYCLE = ".github/workflows/worker-production-lifecycle-rehearsal.yml"
HEAD = ".github/workflows/worker-backup-reviewed-head.yml"
PHASE = ".github/workflows/worker-backup-reviewed-coordinator.yml"
RECOVERY = ".github/workflows/worker-backup-webhook-recovery.yml"
CONTROL = ".github/workflows/worker-production-control.yml"
INLINE = ".github/workflows/worker-isolation-telegram-inline-webhook.yml"
REV = re.compile(r"[a-f0-9]{40}")
SHA = re.compile(r"[a-f0-9]{64}")


def _runs(path, token):
    workflow = github._get_json("/actions/workflows/" + path.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == path and type(workflow.get("id")) is int)
    repository = github._get_json("", token)
    created = repository.get("created_at", "")
    require(isinstance(created, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created))
    start = int(datetime.strptime(created, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    end = int(datetime.now(timezone.utc).timestamp()) + 120
    require(0 < start <= end)
    all_rows = {}
    def read_window(lower, upper, depth=0):
        first = datetime.fromtimestamp(lower, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        last = datetime.fromtimestamp(upper, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        interval = quote(first + ".." + last, safe="")
        path_prefix = "/actions/workflows/" + path.rsplit("/", 1)[-1] + "/runs?per_page=100&created=" + interval + "&page="
        reply = github._get_json(path_prefix + "1", token)
        batch, total = reply.get("workflow_runs"), reply.get("total_count")
        require(isinstance(batch, list) and len(batch) <= 100 and type(total) is int and total >= 0)
        if total >= 900:
            require(lower < upper and depth < 48, "Historical workflow time window is too dense to enumerate.")
            middle = (lower + upper) // 2
            left = read_window(lower, middle, depth + 1)
            right = read_window(middle + 1, upper, depth + 1)
            require(left + right == total, "Historical workflow counts changed across time windows.")
            return total
        rows = list(batch)
        for page in range(2, (total + 99) // 100 + 1):
            reply = github._get_json(path_prefix + str(page), token)
            batch = reply.get("workflow_runs")
            require(reply.get("total_count") == total and isinstance(batch, list) and len(batch) <= 100)
            rows.extend(batch)
        require(len(rows) == total and len({row.get("id") for row in rows if isinstance(row, dict)}) == len(rows))
        for row in rows:
            timestamp = row.get("created_at", "") if isinstance(row, dict) else ""
            require(isinstance(timestamp, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", timestamp))
            observed = int(datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
            require(lower <= observed <= upper and row.get("id") not in all_rows)
            all_rows[row["id"]] = row
        return total
    read_window(start, end)
    rows = list(all_rows.values())
    for row in rows:
        require(isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                and row.get("workflow_id") == workflow["id"] and row.get("path") in (path, path + "@main", path + "@refs/heads/main")
                and row.get("head_branch") == "main" and row.get("event") in {"workflow_dispatch", "schedule"}
                and type(row.get("run_attempt")) is int and row["run_attempt"] == 1 and REV.fullmatch(row.get("head_sha", ""))
                and all(isinstance(row.get(key), dict) and row[key].get("id") == github.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
    return workflow["id"], rows


def _no_webhook_artifact(run, workflow_id, token, candidates):
    run_id, revision = str(run["id"]), run["head_sha"]
    selected = github.select_main_artifact(run_id, revision, token, workflow_id=workflow_id, workflow_path=HEAD,
        artifact_prefix="subs-bot-reviewed-backup-head-" + run_id, workflow_label="reviewed isolated backup",
        events=("workflow_dispatch",), revision_in_name=False, run_attempt="1")
    body = github._download(selected[1], token)
    require(len(body) <= 2 * 1024 * 1024 and sha256(body).hexdigest() == selected[2]
            and github.select_main_artifact(run_id, revision, token, workflow_id=workflow_id, workflow_path=HEAD,
                artifact_prefix="subs-bot-reviewed-backup-head-" + run_id, workflow_label="reviewed isolated backup",
                events=("workflow_dispatch",), revision_in_name=False, run_attempt="1") == selected)
    try:
        with ZipFile(BytesIO(body)) as archive:
            members = archive.infolist()
            require(len(members) == 1 and members[0].filename == "production-backup-head-result.json"
                    and members[0].filename == members[0].orig_filename and not members[0].is_dir()
                    and not members[0].flag_bits & (1 | 64) and members[0].file_size <= 65536)
            result = parsed(archive.read(members[0]))
    except (BadZipFile, OSError, RuntimeError, ValueError):
        require(False, "The historical result artifact is invalid.")
    require(isinstance(result, dict) and result.get("runId") == run_id and result.get("runAttempt") == "1"
            and result.get("dispatcherMainRevision") == revision and result.get("headRevision") in candidates
            and result.get("environment") == "rehearsal" and result.get("productionMutated") is False
            and result.get("webhookTouched") is False)
    return selected[2]


def _restoration_boundary(env, store, prefix, draft, secrets, previous, token, controllers):
    """Verify a later known restoration without changing older run conclusions."""
    supplied = env.get("SUBS_BOT_PHASE_WEBHOOK_BOUNDARY_JSON", "")
    if not supplied:
        return None
    pin = parsed(supplied)
    require(set(pin) == {"version", "runId", "controllerRevision", "reportName", "reportSha256"}
            and type(pin["version"]) is int and pin["version"] == 1
            and re.fullmatch(r"[1-9][0-9]{0,19}", pin.get("runId", ""))
            and pin.get("controllerRevision") in controllers and SHA.fullmatch(pin.get("reportSha256", ""))
            and pin.get("reportName") in {"production-lifecycle-drill-cleanup.json", "production-lifecycle-drill-result.json"})
    run_id, revision = pin["runId"], pin["controllerRevision"]
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(str(run.get("id")) == str(latest.get("id")) == run_id and run.get("run_attempt") == latest.get("run_attempt") == 1
            and run.get("path") in (LIFECYCLE, LIFECYCLE + "@main", LIFECYCLE + "@refs/heads/main")
            and run.get("head_sha") == revision and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("status") == latest.get("status") == "completed"
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    title = run.get("display_title", "")
    require(isinstance(title, str) and re.fullmatch(
        r"Production lifecycle rehearsal (?:exercise|provider-binding|provider-binding-resume|recover-webhook) at " + revision, title))
    comparison = github.compare_commits_metadata(revision, env["GITHUB_SHA"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == revision
            and comparison.get("merge_base_commit", {}).get("sha") == revision)
    jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    step_name = ("Independently restore the original test webhook after the exercise"
                 if pin["reportName"].endswith("cleanup.json") else "Execute the registered production lifecycle code path")
    steps = [step for job in jobs["jobs"] if isinstance(job, dict) for step in job.get("steps", [])
             if isinstance(step, dict) and step.get("name") == step_name]
    require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    created = run.get("created_at", "")
    require(isinstance(created, str) and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", created))
    raw = store.get(prefix + run_id + "-1-" + pin["reportName"])
    report = parsed(raw)
    recovery = report.get("webhookRecovery")
    require(canonical(report) == raw and sha256(raw).hexdigest() == pin["reportSha256"]
            and report.get("runId") == run_id and report.get("runAttempt") == "1"
            and report.get("controlRevision") == revision and isinstance(recovery, dict)
            and recovery.get("webhookRestored") is True and recovery.get("dropPendingUpdates") is False
            and recovery.get("originalWebhookAuthProbe", {}).get("status") == 400)
    telegram = Telegram(draft, {**secrets, "webhookSecret": previous["webhookSecret"]})
    telegram.identity()
    current = webhook_settings(telegram.call("getWebhookInfo"))
    require(current["url"] == ORIGINAL_ORIGIN + "/telegram/webhook"
            and sha256(canonical(current)).hexdigest() == recovery.get("restoredSettingsSha256")
            and probe_original_webhook(previous["webhookSecret"]) == 400)
    return {"runId": run_id, "controllerRevision": revision, "startedAt": created,
            "reportSha256": pin["reportSha256"], "settingsSha256": recovery["restoredSettingsSha256"]}


def inspect(env):
    require(context(env) is True and env.get("BACKUP_GATE_ROLE") == "parent")
    token = github._github_token()
    controllers = json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CONTROLLERS_JSON", ""))
    candidates = json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CANDIDATES_JSON", ""))
    require(isinstance(controllers, list) and 0 < len(controllers) <= 128 and len(set(controllers)) == len(controllers)
            and all(isinstance(item, str) and REV.fullmatch(item) for item in controllers)
            and isinstance(candidates, list) and len(candidates) <= 128 and len(set(candidates)) == len(candidates)
            and all(isinstance(item, str) and REV.fullmatch(item) for item in candidates))
    draft, secrets, previous, store, prefix = open_store(env)
    registration_raw = store.get(prefix + "registration.json")
    require(sha256(registration_raw).hexdigest() == env.get("BACKUP_PHASE_REGISTRATION_SHA256"))
    registration = parsed(registration_raw)
    target = validate_target(registration.get("target"))
    desired = dict(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and registration.get("targetSha256") == target.digest
            and registration.get("draftSha256") == draft.digest and registration.get("configurationSha256") == target.configuration_digest
            and validate_target(desired).configuration_digest == target.configuration_digest and store.objects is not None)
    # Restrict the bounded inventory to webhook evidence rather than allowing
    # unrelated daily backup stages to exhaust this query's capacity.
    keys = store.objects.list(prefix + "webhook-", maximum=10000)
    snapshots = {key[len(prefix):] for key in keys if re.fullmatch(r"webhook-[1-9][0-9]{0,19}-1\.json", key[len(prefix):])}
    boundary = _restoration_boundary(env, store, prefix, draft, secrets, previous, token, controllers)
    observed_snapshots, evidence, unknown, finished = set(), [], [], {}
    for workflow in (LIFECYCLE, HEAD, PHASE, RECOVERY, CONTROL, INLINE):
        workflow_id, runs = _runs(workflow, token)
        for run in runs:
            run_id, head, title = str(run["id"]), run["head_sha"], run.get("display_title", "")
            updated = run.get("updated_at", "")
            if run.get("status") == "completed" and isinstance(updated, str) and re.fullmatch(
                    r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", updated):
                finished[run_id] = updated
            if workflow == PHASE and run_id == env.get("GITHUB_RUN_ID"):
                continue
            if workflow == LIFECYCLE and boundary is not None and run_id == boundary["runId"]:
                continue
            if workflow == INLINE:
                require(title == "Inspect or append isolated Telegram inline webhook")
                require(run.get("status") == "completed")
                # Inputs are not present in the runs API and the legacy workflow
                # did not retain a private original. Explicit forward evidence
                # is required rather than guessing inspect versus append.
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "inline-request-needs-forward-resolution"})
                continue
            if workflow == CONTROL:
                match = re.fullmatch(r"Lifecycle (rehearsal|production) ([a-z-]+) at ([a-f0-9]{40})", title or "")
                require(match is not None and match[3] == head)
                if match[1] != "rehearsal" or match[2] != "webhook":
                    continue
                require(run.get("status") == "completed")
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "control-request-needs-forward-resolution"})
                continue
            if workflow == LIFECYCLE:
                match = re.fullmatch(r"Production lifecycle rehearsal ([a-z-]+) at ([a-f0-9]{40})", title or "")
                require(match is not None and match[2] == head)
                action = match[1]
                if action not in {"exercise", "provider-binding", "provider-binding-resume", "recover-webhook"}:
                    continue
            elif workflow == RECOVERY:
                match = re.fullmatch(r"Backup webhook (diagnose|inspect|restore) ([1-9][0-9]{0,19})-1", title or "")
                require(match is not None)
                if match[1] != "restore":
                    continue
                action = "restore"
            elif workflow == PHASE:
                match = re.fullmatch(r"Rehearsal backup coordinator ([a-z-]+) at ([a-f0-9]{40}) candidate ([a-f0-9]{40})", title or "")
                require(match is not None and match[2] == head)
                if match[1] != "run":
                    continue
                action = "phase-run"
            else:
                require(title == "Reviewed backup head validation at " + head)
                action = "reviewed-head"
            require(run.get("status") == "completed")
            if head not in controllers:
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "controller-not-reviewed"})
                continue
            comparison = github.compare_commits_metadata(head, env["GITHUB_SHA"], token)
            require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
                    and comparison.get("base_commit", {}).get("sha") == head
                    and comparison.get("merge_base_commit", {}).get("sha") == head)
            if workflow == HEAD:
                try:
                    proof = _no_webhook_artifact(run, workflow_id, token, candidates)
                    evidence.append({"workflow": workflow, "runId": run_id, "headSha": head, "kind": "no-webhook", "proofSha256": proof})
                    continue
                except Exception:
                    # A failed or expired artifact is unknown unless private
                    # restoration evidence can independently resolve the run.
                    pass
            suffix = run_id + "-1"
            if workflow == RECOVERY:
                suffix = match[2] + "-1"
            snapshot_name = "webhook-" + suffix + ".json"
            snapshot_raw = store.get(prefix + snapshot_name, absent=True)
            if snapshot_raw is None:
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "snapshot-or-resolution-missing"})
                continue
            observed_snapshots.add(snapshot_name)
            snapshot = parsed(snapshot_raw)
            require(canonical(snapshot) == snapshot_raw and snapshot.get("runId") == suffix.split("-", 1)[0]
                    and snapshot.get("runAttempt") == "1" and snapshot.get("draftSha256") == draft.digest
                    and snapshot.get("botId") == previous["botId"] and snapshot.get("oldWebhookSecret") == previous["webhookSecret"]
                    and (snapshot.get("revision") == head if workflow == LIFECYCLE and action != "recover-webhook"
                         else snapshot.get("revision") in candidates)
                    and webhook_settings(snapshot.get("webhookInfo"))["url"] == ORIGINAL_ORIGIN + "/telegram/webhook")
            completion_raw = store.get(prefix + "webhook-recovery-" + suffix + "-complete.json", absent=True)
            if completion_raw is not None:
                completion = parsed(completion_raw)
                intent_raw = store.get(prefix + "webhook-recovery-" + suffix + "-intent.json")
                intent = parsed(intent_raw)
                require(canonical(intent) == intent_raw and canonical(completion) == completion_raw
                        and intent.get("sourceRunId") == suffix.split("-", 1)[0] and intent.get("sourceAttempt") == "1"
                        and intent.get("candidateRevision") == snapshot.get("revision")
                        and intent.get("snapshotSha256") == sha256(snapshot_raw).hexdigest()
                        and intent.get("beforeSha256") == sha256(canonical(webhook_settings(snapshot["webhookInfo"]))).hexdigest()
                        and completion.get("intentSha256") == sha256(intent_raw).hexdigest()
                        and completion.get("snapshotSha256") == sha256(snapshot_raw).hexdigest()
                        and completion.get("settingsSha256") == sha256(canonical(webhook_settings(snapshot["webhookInfo"]))).hexdigest()
                        and completion.get("dropPendingUpdates") is False)
                proof = sha256(completion_raw).hexdigest()
            elif workflow == LIFECYCLE:
                reports = [store.get(prefix + suffix + "-" + name, absent=True) for name in
                           ("production-lifecycle-drill-cleanup.json", "production-lifecycle-drill-result.json")]
                usable = []
                for raw in reports:
                    if raw is None:
                        continue
                    report = parsed(raw)
                    recovery = report.get("webhookRecovery") if isinstance(report, dict) else None
                    if (canonical(report) == raw and report.get("runId") == run_id and report.get("runAttempt") == "1"
                            and report.get("controlRevision") == head and isinstance(recovery, dict)
                            and recovery.get("webhookRestored") is True and recovery.get("dropPendingUpdates") is False
                            and recovery.get("originalWebhookAuthProbe", {}).get("status") == 400):
                        usable.append(sha256(raw).hexdigest())
                if not usable:
                    unknown.append({"workflow": workflow, "runId": run_id, "reason": "restoration-unconfirmed"})
                    continue
                proof = usable[0]
            else:
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "restoration-unconfirmed"})
                continue
            evidence.append({"workflow": workflow, "runId": run_id, "headSha": head, "kind": "restored",
                             "snapshotSha256": sha256(snapshot_raw).hexdigest(), "proofSha256": proof})
    for missing in sorted(snapshots - observed_snapshots):
        unknown.append({"workflow": "private-snapshot", "runId": missing, "reason": "source-not-accounted"})
    superseded = []
    if boundary is not None:
        for item in unknown[:]:
            source = item["runId"]
            if item["workflow"] == "private-snapshot":
                match = re.fullmatch(r"webhook-([1-9][0-9]{0,19})-1\.json", source)
                source = match[1] if match else ""
            if source in finished and finished[source] < boundary["startedAt"]:
                superseded.append(item)
                unknown.remove(item)
    inventory = {"version": 1, "targetSha256": target.digest, "boundary": boundary,
                 "evidence": sorted(evidence, key=lambda x: (x["workflow"], x["runId"])),
                 "priorUnknownBeforeBoundary": sorted(superseded, key=lambda x: (x["workflow"], x["runId"])),
                 "unknown": sorted(unknown, key=lambda x: (x["workflow"], x["runId"]))}
    pin = sha256(canonical(inventory)).hexdigest()
    if env.get("BACKUP_ACTION") == "plan-webhook-history":
        return {"status": "resolved" if not unknown else "needs-reconciliation", "historySha256": pin,
                "unknownRuns": unknown, "priorUnknownBeforeBoundary": superseded,
                "boundary": boundary, "evidenceCount": len(evidence)}
    require(not unknown and SHA.fullmatch(env.get("SUBS_BOT_PHASE_WEBHOOK_HISTORY_SHA256", ""))
            and env["SUBS_BOT_PHASE_WEBHOOK_HISTORY_SHA256"] == pin,
            "Historical webhook operations are unknown or the independently pinned inventory changed.")
    return {"status": "resolved", "historySha256": pin}


if __name__ == "__main__":
    try:
        print(json.dumps(inspect(os.environ), sort_keys=True))
    except Exception:
        print(json.dumps({"status": "unknown", "reason": "The complete webhook history could not be independently verified."}))
        raise SystemExit(1) from None

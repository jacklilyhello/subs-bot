"""Read-only inventory of prior test webhook operations before a new window.

Unknown, missing or incomplete historical evidence blocks a write. A digest is
returned for an independently pinned protected configuration; it is not an
assertion that an unresolved operation succeeded.
"""
from hashlib import sha256
from io import BytesIO
from datetime import datetime, timezone
import base64
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
ARCHIVE = ".github/workflows/worker-backup-webhook-history-archive.yml"
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


def _archived_log(run, workflow, record, store, prefix, token, controllers, env):
    """Recheck original bytes plus the exact fresh readback run and jobs."""
    from trusted_backup_webhook_log_archive import REVIEWED_PRE_WEBHOOK, audit_key, audited_paths, classify
    require(isinstance(record, dict) and set(record) == {"status", "sourceRunId", "sourceJobId", "sourceHeadSha",
            "sourceWorkflow", "classification", "logSha256", "planSha256", "completionSha256", "archiveRunId",
            "archiveControllerRevision", "archiveJobId", "readbackJobId"}
            and record.get("status") == "independently-read-back" and record.get("sourceRunId") == str(run["id"])
            and record.get("sourceHeadSha") == run["head_sha"] and record.get("sourceWorkflow") == workflow
            and record.get("classification") in {"no-write-independently-confirmed", "response-independently-confirmed", "unresolved"}
            and all(SHA.fullmatch(record.get(k, "")) for k in ("logSha256", "planSha256", "completionSha256"))
            and all(re.fullmatch(r"[1-9][0-9]{0,19}", record.get(k, "")) for k in ("sourceJobId", "archiveRunId", "archiveJobId", "readbackJobId"))
            and record.get("archiveControllerRevision") in controllers)
    key = prefix + "history-log-" + record["sourceRunId"] + "-"
    intent_raw, done_raw = store.get(key + "intent.json"), store.get(key + "complete.json")
    raw, _ = store.objects.get(key + "original.log")
    intent, done = parsed(intent_raw), parsed(done_raw)
    require(canonical(intent) == intent_raw and canonical(done) == done_raw and isinstance(raw, bytes)
            and sha256(raw).hexdigest() == record["logSha256"] and sha256(done_raw).hexdigest() == record["completionSha256"]
            and done == {"version": 1, "intentSha256": sha256(intent_raw).hexdigest(), "logSha256": record["logSha256"]}
            and intent.get("archiveRunId") == record["archiveRunId"] and intent.get("archiveAttempt") == "1"
            and intent.get("planSha256") == record["planSha256"] == sha256(canonical(intent.get("plan"))).hexdigest())
    plan = intent["plan"]
    item = plan.get("record", {})
    require(plan.get("kind") == "test-webhook-history-log-archive"
            and plan.get("registrationSha256") == env.get("BACKUP_PHASE_REGISTRATION_SHA256")
            and item.get("sourceRunId") == record["sourceRunId"]
            and item.get("sourceJobId") == record["sourceJobId"] and item.get("sourceControllerRevision") == record["sourceHeadSha"]
            and item.get("sourceWorkflow") == workflow and item.get("sourceAttempt") == "1"
            and item.get("logSha256") == record["logSha256"] and item.get("logBytes") == len(raw)
            and item.get("classification") == record["classification"] == classify(raw, workflow, record["sourceRunId"],
                main_sha=record["sourceHeadSha"], candidates=json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CANDIDATES_JSON", "[]"))))
    audit = parsed(env.get("SUBS_BOT_PHASE_WEBHOOK_LOG_AUDIT_JSON", "")).get(audit_key(workflow, record["sourceHeadSha"]))
    paths = audited_paths(workflow, record["sourceHeadSha"])
    reviewed = REVIEWED_PRE_WEBHOOK.get(record["sourceRunId"])
    if workflow == LIFECYCLE and reviewed:
        require(record["sourceHeadSha"] == reviewed[0] and run.get("display_title") ==
                "Production lifecycle rehearsal " + reviewed[1] + " at " + reviewed[0])
    require(isinstance(audit, dict) and set(audit) == paths
            and sha256(canonical(audit)).hexdigest() == item.get("auditedSourceSha256"))
    for path in sorted(paths):
        source = github._get_json("/contents/" + path + "?ref=" + record["sourceHeadSha"], token)
        require(source.get("path") == path and source.get("type") == "file" and source.get("encoding") == "base64"
                and isinstance(source.get("content"), str) and SHA.fullmatch(audit.get(path, "")))
        body = base64.b64decode(source["content"].replace("\n", ""), validate=True)
        require(len(body) <= 512 * 1024 and sha256(body).hexdigest() == audit[path])
    original_jobs = github._get_json("/actions/runs/" + record["sourceRunId"] + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(original_jobs.get("jobs"), list) and type(original_jobs.get("total_count")) is int
            and original_jobs["total_count"] == len(original_jobs["jobs"]) < 100)
    source_job = [job for job in original_jobs["jobs"] if isinstance(job, dict) and str(job.get("id")) == record["sourceJobId"]]
    require(len(source_job) == 1 and source_job[0].get("name") == ("webhook" if workflow == INLINE else "validate" if workflow == HEAD else "rehearse")
            and str(source_job[0].get("run_id")) == record["sourceRunId"] and source_job[0].get("run_attempt") == 1
            and source_job[0].get("head_sha") == record["sourceHeadSha"] and source_job[0].get("status") == "completed")
    archive_run = github._get_json("/actions/runs/" + record["archiveRunId"] + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + record["archiveRunId"], token)
    require(str(archive_run.get("id")) == str(latest.get("id")) == record["archiveRunId"]
            and archive_run.get("run_attempt") == latest.get("run_attempt") == 1
            and archive_run.get("path") in (ARCHIVE, ARCHIVE + "@main", ARCHIVE + "@refs/heads/main")
            and archive_run.get("head_sha") == record["archiveControllerRevision"] and archive_run.get("head_branch") == "main"
            and archive_run.get("event") == "workflow_dispatch" and (archive_run.get("status"), archive_run.get("conclusion")) == ("completed", "success")
            and all(isinstance(archive_run.get(k), dict) and archive_run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    comparison = github.compare_commits_metadata(record["archiveControllerRevision"], env["GITHUB_SHA"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == record["archiveControllerRevision"]
            and comparison.get("merge_base_commit", {}).get("sha") == record["archiveControllerRevision"])
    jobs = github._get_json("/actions/runs/" + record["archiveRunId"] + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    for name, identifier, step_name in (("archive", record["archiveJobId"], "Plan or conditionally seal the exact original job log"),
                                         ("readback", record["readbackJobId"], "Independently compare the retained original log")):
        selected = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == name and str(job.get("id")) == identifier]
        require(len(selected) == 1 and str(selected[0].get("run_id")) == record["archiveRunId"]
                and selected[0].get("run_attempt") == 1 and selected[0].get("head_sha") == record["archiveControllerRevision"]
                and (selected[0].get("status"), selected[0].get("conclusion")) == ("completed", "success"))
        steps = [step for step in selected[0].get("steps", []) if isinstance(step, dict) and step.get("name") == step_name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    return record["classification"]


def inspect(env):
    require(context(env) is True and env.get("BACKUP_GATE_ROLE") == "parent")
    token = github._github_token()
    controllers = json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CONTROLLERS_JSON", ""))
    candidates = json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CANDIDATES_JSON", ""))
    require(isinstance(controllers, list) and 0 < len(controllers) <= 128 and len(set(controllers)) == len(controllers)
            and all(isinstance(item, str) and REV.fullmatch(item) for item in controllers)
            and isinstance(candidates, list) and len(candidates) <= 128 and len(set(candidates)) == len(candidates)
            and all(isinstance(item, str) and REV.fullmatch(item) for item in candidates))
    archives = parsed(env.get("SUBS_BOT_PHASE_WEBHOOK_HISTORY_ARCHIVES_JSON", "{}"))
    require(len(archives) <= 128 and all(re.fullmatch(r"[1-9][0-9]{0,19}", key) and isinstance(value, dict)
                                        for key, value in archives.items()))
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
    observed_snapshots, evidence, unknown, finished, ancestor_cache, used_archives = set(), [], [], {}, set(), set()
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
            if run.get("status") != "completed":
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "workflow-still-active"})
                continue
            if head not in controllers:
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "controller-not-reviewed"})
                continue
            if head not in ancestor_cache:
                comparison = github.compare_commits_metadata(head, env["GITHUB_SHA"], token)
                require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
                        and comparison.get("base_commit", {}).get("sha") == head
                        and comparison.get("merge_base_commit", {}).get("sha") == head)
                ancestor_cache.add(head)
            if workflow == INLINE:
                require(title == "Inspect or append isolated Telegram inline webhook")
                require(run.get("status") == "completed")
                # Inputs are not present in the runs API and the legacy workflow
                # did not retain a private original. Explicit forward evidence
                # is required rather than guessing inspect versus append.
                reason = "inline-request-needs-forward-resolution"
                if run_id in archives:
                    reason = _archived_log(run, workflow, archives[run_id], store, prefix, token, controllers, env)
                    used_archives.add(run_id)
                unknown.append({"workflow": workflow, "runId": run_id, "reason": reason})
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
                match = re.fullmatch(r"Backup webhook (diagnose|inspect|restore|plan-phase-unstarted|release-phase-unstarted) ([1-9][0-9]{0,19})-1", title or "")
                require(match is not None)
                if match[1] == "release-phase-unstarted":
                    base = prefix + "phase-webhook-unstarted-" + match[2] + "-1-"
                    claim_raw = store.get(base + "intent.json", absent=True)
                    done_raw = store.get(base + "complete.json", absent=True)
                    if claim_raw is None or done_raw is None:
                        unknown.append({"workflow": workflow, "runId": run_id, "reason": "lock-release-outcome-unconfirmed"})
                        continue
                    claim, done = parsed(claim_raw), parsed(done_raw)
                    require(canonical(claim) == claim_raw and canonical(done) == done_raw
                            and claim.get("writerRunId") == run_id and claim.get("writerAttempt") == "1"
                            and done.get("intentSha256") == sha256(claim_raw).hexdigest()
                            and done.get("planSha256") == claim.get("planSha256")
                            and done.get("status") == "released-before-webhook-setup" and done.get("oldOutcome") == "not-promoted")
                    evidence.append({"workflow": workflow, "runId": run_id, "headSha": head,
                                     "kind": "lock-released-without-webhook", "proofSha256": sha256(done_raw).hexdigest()})
                    continue
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
            if workflow == HEAD:
                if run_id in archives:
                    reason = _archived_log(run, workflow, archives[run_id], store, prefix, token, controllers, env)
                    require(reason == "no-write-independently-confirmed")
                    used_archives.add(run_id)
                    evidence.append({"workflow": workflow, "runId": run_id, "headSha": head,
                                     "kind": "no-webhook-archived", "proofSha256": archives[run_id]["completionSha256"]})
                    continue
                try:
                    proof = _no_webhook_artifact(run, workflow_id, token, candidates)
                    evidence.append({"workflow": workflow, "runId": run_id, "headSha": head, "kind": "no-webhook", "proofSha256": proof})
                    continue
                except Exception:
                    # A failed or expired artifact is unknown unless private
                    # restoration evidence can independently resolve the run.
                    pass
            if workflow == LIFECYCLE and action == "recover-webhook":
                recovered_raw = store.get(prefix + run_id + "-1-production-lifecycle-drill-result.json", absent=True)
                if recovered_raw is not None:
                    recovered = parsed(recovered_raw)
                    proof = recovered.get("webhookRecovery")
                    if (canonical(recovered) == recovered_raw and recovered.get("runId") == run_id
                            and recovered.get("runAttempt") == "1" and recovered.get("controlRevision") == head
                            and recovered.get("status") == "passed" and isinstance(proof, dict)
                            and proof.get("webhookRestored") is True and proof.get("dropPendingUpdates") is False
                            and proof.get("originalWebhookAuthProbe", {}).get("status") == 400
                            and (boundary is None or proof.get("restoredSettingsSha256") == boundary["settingsSha256"])):
                        evidence.append({"workflow": workflow, "runId": run_id, "headSha": head,
                                         "kind": "confirmed-original-restoration", "proofSha256": sha256(recovered_raw).hexdigest()})
                        continue
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "recovery-source-not-confirmed"})
                continue
            suffix = run_id + "-1"
            if workflow == RECOVERY:
                suffix = match[2] + "-1"
            snapshot_name = "webhook-" + suffix + ".json"
            snapshot_raw = store.get(prefix + snapshot_name, absent=True)
            if snapshot_raw is None:
                reason = "snapshot-or-resolution-missing"
                if workflow == LIFECYCLE and run_id in archives:
                    reason = _archived_log(run, workflow, archives[run_id], store, prefix, token, controllers, env)
                    require(reason in {"no-write-independently-confirmed", "unresolved"})
                    used_archives.add(run_id)
                unknown.append({"workflow": workflow, "runId": run_id, "reason": reason})
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
                    reason = "restoration-unconfirmed"
                    if run_id in archives:
                        reason = _archived_log(run, workflow, archives[run_id], store, prefix, token, controllers, env)
                        used_archives.add(run_id)
                    unknown.append({"workflow": workflow, "runId": run_id, "reason": reason})
                    continue
                proof = usable[0]
            else:
                unknown.append({"workflow": workflow, "runId": run_id, "reason": "restoration-unconfirmed"})
                continue
            evidence.append({"workflow": workflow, "runId": run_id, "headSha": head, "kind": "restored",
                             "snapshotSha256": sha256(snapshot_raw).hexdigest(), "proofSha256": proof})
    for missing in sorted(snapshots - observed_snapshots):
        unknown.append({"workflow": "private-snapshot", "runId": missing, "reason": "source-not-accounted"})
    require(used_archives == set(archives), "A protected history archive does not correspond to a classified source run.")
    superseded = []
    if boundary is not None:
        for item in unknown[:]:
            source = item["runId"]
            if item["workflow"] == "private-snapshot":
                match = re.fullmatch(r"webhook-([1-9][0-9]{0,19})-1\.json", source)
                source = match[1] if match else ""
            if (item.get("reason") in {"no-write-independently-confirmed", "response-independently-confirmed"}
                    and source in finished and finished[source] < boundary["startedAt"]):
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

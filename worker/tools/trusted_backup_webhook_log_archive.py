"""Archive original historical test-webhook job logs to private R2 once.

Only fixed lifecycle/inline job names and independently pinned source runs are
accepted. Raw logs are never printed. A fresh readback is required before a
history record can be used.
"""
from hashlib import sha256
import base64
from http.client import HTTPException
import json
import os
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request

import prepare_isolation_artifact as github
from production_backup_webhook_recovery import open_store
from production_target import canonical, parsed, require

WORKFLOW = ".github/workflows/worker-backup-webhook-history-archive.yml"
INLINE = ".github/workflows/worker-isolation-telegram-inline-webhook.yml"
LIFECYCLE = ".github/workflows/worker-production-lifecycle-rehearsal.yml"
HEAD = ".github/workflows/worker-backup-reviewed-head.yml"
REV = re.compile(r"[a-f0-9]{40}")
SHA = re.compile(r"[a-f0-9]{64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
MAX_LOG = 4 * 1024 * 1024
# Each entry is tied to a separately reviewed historical source and its exact
# published stopped report. These are observations, not general retry rules.
REVIEWED_PRE_WEBHOOK = {
    "43945207035": ("cc9d3a9425bcf0858ffbe63ce3e5283748bd0e9b", "provider-binding", ["provider-binding-on-intent"],
                    "Active binding inventory differs from the exact configuration."),
    "43939288298": ("cc9d3a9425bcf0858ffbe63ce3e5283748bd0e9b", "provider-binding", [],
                    "Active binding inventory differs from the exact configuration."),
    "43868642682": ("e0a9c9398f1ea84835a5d9b32dc8e3d890972651", "exercise", [],
                    "Predecessor state changed; no transition performed."),
    "43865731376": ("7d068deae67fbf4183698434001cbb1e5f5d06a6", "exercise", [],
                    "HTTPS domain health did not confirm the exact revision; admission remains closed."),
}
# Only these two failed, frozen-backup runs have separately reviewed source
# closure and immutable original logs. Their classification concerns webhook
# writes alone; it says nothing about backup or export success.
REVIEWED_FAILED_HEAD = {
    "44164739374": {"main": "43ec8cc22c3f51eedde5569e8025e26f3244091a", "candidate": "7aa685990859cffb30d47c5a6e593d969f1d0452",
                     "job": "134327660057", "fault": "readback-failure", "logSha256": "6bc155ec5a2dac24b96a036bb0b884fe98ecb07ff82092f3992ca8d6983c194a"},
    "44160464601": {"main": "d6dfeef9c4e16b032c5529d1c3844e11c91e46dd", "candidate": "d6462891bddc9877f99bd9a2a11dfe96f075e958",
                     "job": "134312572827", "fault": "capacity-over", "logSha256": "819dd9c78f6ff682f97a30a71e002c500b2c858f18dcb6fbe33b0e0c7b151547"},
}
FAILED_HEAD_PATHS = {"worker/tools/production_backup_head_harness.py", "worker/tools/production_lifecycle_drill.py",
                     "worker/tools/production_recovery.py", "worker/tools/native_restore_rehearsal.py",
                     "worker/tools/production_storage.py", "worker/tools/scoped_r2.py", "worker/tools/production_backup_transaction.py",
                     "worker/tools/production_backup_capacity.py", "worker/tools/production_control.py",
                     "worker/tools/production_target.py", "worker/tools/production_release_evidence.py"}
FAILED_HEAD_CLOSURE_SHA256 = "91b651f56cb22508251849a025ec316b8a29683175255289a9706b7c88453470"
FAILED_HEAD_DISPATCHER = {".github/workflows/worker-backup-reviewed-head.yml": "850d735d15e7177664e831c289a35044eabab553ef86c452fef62a02091945b5",
                          "worker/tools/trusted_backup_head_gate.py": "84aee74ddb0f2404811f5b8609ac24886f3da5c30cefb78f0b36cd8798eb0e5d"}


def verify_failed_head_source(run_id, token):
    """Independently re-read the exact audited main and candidate source closure."""
    fixed = REVIEWED_FAILED_HEAD[run_id]
    def source_hash(revision, path):
        entry = github._get_json("/contents/" + path + "?ref=" + revision, token)
        require(entry.get("type") == "file" and entry.get("path") == path and entry.get("encoding") == "base64"
                and isinstance(entry.get("content"), str))
        body = base64.b64decode(entry["content"].replace("\n", ""), validate=True)
        require(len(body) <= 512 * 1024)
        return sha256(body).hexdigest()
    require(all(source_hash(fixed["main"], path) == expected for path, expected in FAILED_HEAD_DISPATCHER.items()))
    closure = {path: source_hash(fixed["candidate"], path) for path in sorted(FAILED_HEAD_PATHS)}
    require(sha256(canonical(closure)).hexdigest() == FAILED_HEAD_CLOSURE_SHA256,
            "The reviewed frozen-backup source closure changed.")


def audited_paths(workflow, revision):
    if workflow == INLINE:
        return {"worker/tools/telegram_inline_webhook.py"}
    if workflow == HEAD:
        return {"worker/tools/trusted_backup_head_gate.py"}
    paths = {"worker/tools/production_lifecycle_drill.py", "worker/tools/production_control.py"}
    if revision == REVIEWED_PRE_WEBHOOK["43945207035"][0]:
        paths.add("worker/tools/production_application_provider_drill.py")
    return paths


def audit_key(workflow, revision):
    require(workflow in {INLINE, LIFECYCLE, HEAD} and REV.fullmatch(revision or ""))
    return revision + ":" + workflow


def context(env):
    main = env.get("GITHUB_SHA", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/" + WORKFLOW + "@" + github.MAIN_REF
            and env.get("GITHUB_WORKFLOW_SHA") == main and REV.fullmatch(main or "")
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("SUBS_BOT_PHASE_WEBHOOK_HISTORY_ARCHIVE_ENABLED") == "true")
    github.require_current_main(main)


def download_log(job_id, token):
    require(DECIMAL.fullmatch(job_id or ""))
    try:
        with github._OPENER.open(github._api_request("/actions/jobs/" + job_id + "/logs", token), timeout=30):
            require(False, "The historical job log did not provide the expected storage redirect.")
    except HTTPError as error:
        with error:
            location = error.headers.get("Location", "") if error.code == 302 else ""
    except (URLError, OSError, HTTPException):
        require(False, "The historical job log is unavailable.")
    try:
        url = urlsplit(location)
        require(isinstance(location, str) and re.fullmatch(r"[!-~]{1,8192}", location)
                and "\\" not in location and url.scheme == "https" and url.hostname
                and url.username is None and url.password is None and url.fragment == "" and url.port in (None, 443))
        # A fresh request deliberately has no GitHub authorization header.
        request = Request(location, headers={"Accept-Encoding": "identity"})
        with github._OPENER.open(request, timeout=60) as response:
            raw = response.read(MAX_LOG + 1)
        require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LOG)
        return raw
    except (URLError, OSError, HTTPException, ValueError):
        require(False, "The historical job log could not be privately read.")


def classify(raw, workflow, run_id, *, main_sha="", candidates=()):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LOG)
    text = raw.decode("utf-8-sig")
    documents = []
    for line in text.splitlines():
        position = line.find("{")
        if position < 0:
            continue
        try:
            value = json.loads(line[position:])
        except (ValueError, TypeError):
            continue
        if isinstance(value, dict):
            documents.append(value)
    if workflow == INLINE:
        result = [value for value in documents if value.get("mode") in {"inspect", "append"}
                  and type(value.get("writeAttempted")) is bool and "writeAcknowledged" in value]
        require(len(result) == 1)
        value = result[0]
        if value["mode"] == "inspect":
            require(value["writeAttempted"] is False and value["writeAcknowledged"] is None)
            return "no-write-independently-confirmed"
        require(value["mode"] == "append" and value["writeAttempted"] is True and value["writeAcknowledged"] is True
                and value.get("inlineQuerySubscribed") is True)
        return "response-independently-confirmed"
    if workflow == HEAD:
        fixed = REVIEWED_FAILED_HEAD.get(run_id)
        if fixed is not None:
            require(main_sha == fixed["main"] and fixed["candidate"] in candidates
                    and sha256(raw).hexdigest() == fixed["logSha256"])
            specifications = []
            for line in text.splitlines():
                if "HEAD_VALIDATION_JSON" not in line or "{" not in line:
                    continue
                try:
                    value = json.loads(line[line.index("{"):])
                except (TypeError, ValueError):
                    require(False, "The reviewed frozen-backup validation is malformed.")
                require(isinstance(value, dict))
                specifications.append(value)
            require(len(specifications) == 4 and all(value == specifications[0] for value in specifications)
                    and type(specifications[0].get("version")) is int and specifications[0]["version"] == 1
                    and specifications[0].get("headSha") == fixed["candidate"]
                    and specifications[0].get("action") == "backup" and specifications[0].get("fault") == fixed["fault"])
            return "no-write-independently-confirmed"
        result = [value for value in documents if value.get("runId") == run_id and value.get("runAttempt") == "1"
                  and value.get("dispatcherMainRevision") == main_sha and value.get("headRevision") in candidates
                  and value.get("environment") == "rehearsal" and value.get("productionMutated") is False
                  and value.get("webhookTouched") is False]
        require(len(result) == 1)
        return "no-write-independently-confirmed"
    require(workflow == LIFECYCLE)
    reports = [value for value in documents if value.get("runId") == run_id and isinstance(value.get("stages"), list)]
    # A missing snapshot or configured stage does not prove that an earlier
    # request was never sent. Preserve the original log while keeping such a
    # run unresolved; only a determinate result can clear the history gate.
    no_change = [value for value in documents if isinstance(value.get("webhookRecovery"), dict)
                 and value.get("runId") == run_id
                 and value["webhookRecovery"].get("webhookWasNotChanged") is True
                 and value["webhookRecovery"].get("webhookRestored") is True]
    reviewed = REVIEWED_PRE_WEBHOOK.get(run_id)
    stopped = [value for value in reports if value.get("status") == "stopped"]
    errors = [value for value in documents if value.get("status") == "stopped" and "reason" in value]
    if reviewed and reviewed[0] == main_sha and len(stopped) == len(errors) == len(no_change) == 1:
        stages = [stage.get("stage") for stage in stopped[0]["stages"] if isinstance(stage, dict)]
        if (len(stages) == len(stopped[0]["stages"]) and stages == reviewed[2]
                and "webhookRecovery" not in stopped[0] and errors[0].get("reason") == reviewed[3]
                and errors[0].get("uncertain") is False):
            return "no-write-independently-confirmed"
    if len(no_change) == 1 and not any(any(stage.get("stage") == "webhook-configured" for stage in value["stages"] if isinstance(stage, dict))
                                       for value in reports):
        return "unresolved"
    # The exact reviewed legacy implementation raises this message only after
    # setWebhook returned and the original settings were read back; it does not
    # claim that the old authentication probe succeeded.
    require(run_id == "43874513488" and main_sha == "8e3af6d324661abf58c76437ef8f7a06c338ec67",
            "The legacy response proof applies only to the independently reviewed historical run.")
    errors = [value for value in documents if value.get("status") == "stopped" and value.get("uncertain") is False
              and value.get("reason") == "Original webhook secret was not independently confirmed; keep the private recovery snapshot."]
    configured = any(any(stage.get("stage") == "webhook-configured" for stage in value["stages"] if isinstance(stage, dict))
                     for value in reports)
    require(len(errors) == 1 and configured)
    return "response-independently-confirmed"


def source(env):
    context(env)
    token = github._github_token()
    run_id, job_id, revision, workflow = (env.get(key, "") for key in
        ("HISTORY_SOURCE_RUN_ID", "HISTORY_SOURCE_JOB_ID", "HISTORY_SOURCE_HEAD_SHA", "HISTORY_SOURCE_WORKFLOW"))
    require(DECIMAL.fullmatch(run_id or "") and DECIMAL.fullmatch(job_id or "") and REV.fullmatch(revision or "")
            and workflow in {INLINE, LIFECYCLE, HEAD})
    approved = json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CONTROLLERS_JSON", ""))
    require(isinstance(approved, list) and revision in approved and all(isinstance(item, str) and REV.fullmatch(item) for item in approved))
    audits = parsed(env.get("SUBS_BOT_PHASE_WEBHOOK_LOG_AUDIT_JSON", ""))
    audited_files = audits.get(audit_key(workflow, revision))
    expected_paths = audited_paths(workflow, revision)
    require(isinstance(audited_files, dict) and set(audited_files) == expected_paths
            and all(isinstance(value, str) and SHA.fullmatch(value) for value in audited_files.values()),
            "The exact historical request code must be independently reviewed and pinned.")
    for path in sorted(expected_paths):
        entry = github._get_json("/contents/" + path + "?ref=" + revision, token)
        require(entry.get("type") == "file" and entry.get("path") == path and entry.get("encoding") == "base64"
                and isinstance(entry.get("content"), str))
        body = base64.b64decode(entry["content"].replace("\n", ""), validate=True)
        require(len(body) <= 512 * 1024 and sha256(body).hexdigest() == audited_files[path],
                "The historical request source differs from the independent audit pin.")
    comparison = github.compare_commits_metadata(revision, env["GITHUB_SHA"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == revision and comparison.get("merge_base_commit", {}).get("sha") == revision)
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(str(run.get("id")) == str(latest.get("id")) == run_id and run.get("run_attempt") == latest.get("run_attempt") == 1
            and run.get("path") in (workflow, workflow + "@main", workflow + "@refs/heads/main")
            and run.get("head_sha") == revision and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("status") == latest.get("status") == "completed"
            and all(isinstance(run.get(key), dict) and run[key].get("id") == github.REPOSITORY_ID
                    for key in ("repository", "head_repository")))
    reviewed = REVIEWED_PRE_WEBHOOK.get(run_id)
    if workflow == LIFECYCLE and reviewed:
        require(revision == reviewed[0] and run.get("display_title") ==
                "Production lifecycle rehearsal " + reviewed[1] + " at " + revision)
    jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    selected = [job for job in jobs["jobs"] if isinstance(job, dict) and str(job.get("id")) == job_id]
    name = "webhook" if workflow == INLINE else "validate" if workflow == HEAD else "rehearse"
    require(len(selected) == 1 and selected[0].get("name") == name and str(selected[0].get("run_id")) == run_id
            and selected[0].get("run_attempt") == 1
            and selected[0].get("head_sha") == revision and selected[0].get("status") == "completed")
    if workflow == HEAD:
        fixed = REVIEWED_FAILED_HEAD.get(run_id)
        require(isinstance(selected[0].get("steps"), list)
                and ((fixed is None and (run.get("status"), run.get("conclusion")) == ("completed", "success"))
                     or (fixed is not None and revision == fixed["main"] and job_id == fixed["job"]
                         and (run.get("status"), run.get("conclusion")) == ("completed", "failure")
                         and run.get("display_title") == "Reviewed backup head validation at " + revision)))
        for step_name in ("Verify the exact independently reviewed head before checkout",
                          "Independently recheck trusted main and candidate checkout",
                          "Confirm only the authorized isolated test identity",
                          "Run the reviewed candidate against only dedicated isolation"):
            steps = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == step_name]
            conclusion = "failure" if fixed is not None and step_name == "Run the reviewed candidate against only dedicated isolation" else "success"
            require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", conclusion))
        if fixed is not None:
            verify_failed_head_source(run_id, token)
    raw = download_log(job_id, token)
    candidates = json.loads(env.get("SUBS_BOT_PHASE_WEBHOOK_CANDIDATES_JSON", "[]"))
    require(isinstance(candidates, list) and all(isinstance(value, str) and REV.fullmatch(value) for value in candidates))
    classification = classify(raw, workflow, run_id, main_sha=revision, candidates=candidates)
    return {"version": 1, "sourceRunId": run_id, "sourceAttempt": "1", "sourceJobId": job_id,
            "sourceWorkflow": workflow, "sourceControllerRevision": revision, "logSha256": sha256(raw).hexdigest(),
            "logBytes": len(raw), "classification": classification,
            "auditedSourceSha256": sha256(canonical(audited_files)).hexdigest()}, raw


def collect(env):
    action = env.get("HISTORY_ARCHIVE_ACTION", "")
    require(action in {"plan", "seal"})
    record, raw = source(env)
    _, _, _, store, prefix = open_store(env)
    registration = store.get(prefix + "registration.json")
    require(sha256(registration).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    plan = {"version": 1, "kind": "test-webhook-history-log-archive", "record": record,
            "registrationSha256": sha256(registration).hexdigest()}
    plan_sha = sha256(canonical(plan)).hexdigest()
    if action == "plan":
        return {"status": "planned", "planSha256": plan_sha, "classification": record["classification"], "mutationPerformed": False}
    require(env.get("HISTORY_SOURCE_LOG_SHA256") == record["logSha256"] and env.get("HISTORY_ARCHIVE_APPROVAL_SHA256") == plan_sha
            and env.get("SUBS_BOT_PHASE_WEBHOOK_HISTORY_ARCHIVE_APPROVAL_SHA256") == plan_sha)
    key = prefix + "history-log-" + record["sourceRunId"] + "-"
    intent = {"version": 1, "plan": plan, "planSha256": plan_sha, "archiveRunId": env["GITHUB_RUN_ID"], "archiveAttempt": "1"}
    store.put_exclusive(key + "intent.json", canonical(intent))
    require(store.get(key + "intent.json") == canonical(intent) and store.objects is not None)
    # Raw logs may exceed the smaller registration-object limit; scoped S3
    # still enforces its hard limit and one conditional creation.
    store.objects.put_once(key + "original.log", raw)
    observed, _ = store.objects.get(key + "original.log")
    require(observed == raw)
    done = {"version": 1, "intentSha256": sha256(canonical(intent)).hexdigest(), "logSha256": record["logSha256"]}
    store.put_exclusive(key + "complete.json", canonical(done))
    require(store.get(key + "complete.json") == canonical(done))
    return {"status": "sealed-awaiting-independent-readback", "planSha256": plan_sha,
            "logSha256": record["logSha256"], "completionSha256": sha256(canonical(done)).hexdigest()}


def readback(env):
    record, original = source(env)
    _, _, _, store, prefix = open_store(env)
    registration = store.get(prefix + "registration.json")
    require(sha256(registration).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    plan = {"version": 1, "kind": "test-webhook-history-log-archive", "record": record,
            "registrationSha256": sha256(registration).hexdigest()}
    plan_sha = sha256(canonical(plan)).hexdigest()
    require(env.get("HISTORY_ARCHIVE_APPROVAL_SHA256") == env.get("SUBS_BOT_PHASE_WEBHOOK_HISTORY_ARCHIVE_APPROVAL_SHA256") == plan_sha)
    key = prefix + "history-log-" + record["sourceRunId"] + "-"
    intent_raw, done_raw = store.get(key + "intent.json"), store.get(key + "complete.json")
    intent, done = parsed(intent_raw), parsed(done_raw)
    require(canonical(intent) == intent_raw and canonical(done) == done_raw
            and intent.get("plan") == plan and intent.get("planSha256") == plan_sha
            and intent.get("archiveRunId") == env.get("GITHUB_RUN_ID") and intent.get("archiveAttempt") == "1"
            and done == {"version": 1, "intentSha256": sha256(intent_raw).hexdigest(), "logSha256": record["logSha256"]})
    private, _ = store.objects.get(key + "original.log")
    require(private == original and sha256(private).hexdigest() == env.get("HISTORY_SOURCE_LOG_SHA256"))
    jobs = github._get_json("/actions/runs/" + env["GITHUB_RUN_ID"] + "/attempts/1/jobs?per_page=100", github._github_token())
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    archive_jobs = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "archive"]
    readers = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "readback"]
    require(len(archive_jobs) == len(readers) == 1 and archive_jobs[0].get("status") == "completed"
            and archive_jobs[0].get("conclusion") == "success" and readers[0].get("status") == "in_progress"
            and all(str(job.get("run_id")) == env["GITHUB_RUN_ID"] and job.get("run_attempt") == 1
                    and job.get("head_sha") == env["GITHUB_SHA"] and type(job.get("id")) is int for job in (archive_jobs[0], readers[0])))
    return {"status": "independently-read-back", "sourceRunId": record["sourceRunId"], "sourceJobId": record["sourceJobId"],
            "sourceHeadSha": record["sourceControllerRevision"], "sourceWorkflow": record["sourceWorkflow"],
            "classification": record["classification"], "logSha256": record["logSha256"],
            "planSha256": plan_sha, "completionSha256": sha256(done_raw).hexdigest(), "archiveRunId": env["GITHUB_RUN_ID"],
            "archiveControllerRevision": env["GITHUB_SHA"], "archiveJobId": str(archive_jobs[0]["id"]),
            "readbackJobId": str(readers[0]["id"])}


if __name__ == "__main__":
    try:
        os.umask(0o077)
        result = readback(os.environ) if os.environ.get("HISTORY_ARCHIVE_ACTION") == "readback" else collect(os.environ)
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("::error::Historical webhook log evidence is incomplete or unknown; do not infer that the old write succeeded.")
        raise SystemExit(1) from None

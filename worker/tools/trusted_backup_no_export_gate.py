"""Trusted fixed-target gate for the one interrupted isolated backup.

The custody statement is an explicitly reviewed trust assumption, not a
Cloudflare retention guarantee. This gate does not mutate Cloudflare.
"""
from datetime import datetime, timezone
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from urllib.parse import urlencode

import prepare_isolation_artifact as github
from production_target import canonical, parsed, require

WORKFLOW = ".github/workflows/worker-backup-no-export-resolution.yml"
OLD_WORKFLOW = ".github/workflows/worker-backup-reviewed-head.yml"
OLD_MAIN = "43ec8cc22c3f51eedde5569e8025e26f3244091a"
OLD_CANDIDATE = "7aa685990859cffb30d47c5a6e593d969f1d0452"
OLD_RUN, OLD_JOB, CHECKPOINT = "44164739374", "134327660057", "1bbadaa9755d1733ddd80fe12192420a"
OLD_LOG = "6bc155ec5a2dac24b96a036bb0b884fe98ecb07ff82092f3992ca8d6983c194a"
FAILED_PLAN_RUN = "44180277055"
FAILED_PLAN_JOB = "134382463410"
FAILED_PLAN_MAIN = "777bf60f8881755802a957777f55b7e3e9ff273a"
FAILED_PLAN_HEAD = "98562f7cbef35a6847db1bd342abf689b31eacc0"
FAILED_PLAN_SOURCES = {
    ".github/workflows/worker-backup-no-export-resolution.yml": "8b46e11408866e5369013d2715b2339df9d37794753b6b61cdc067dade523355",
    "worker/tools/trusted_backup_no_export_gate.py": "dec99713970c4259161ed038b1e02fa96e620bfa1d739a794cdfd162d937ba3f",
}
ENVIRONMENT = "subs-bot-backup-head-isolation"
HEX32, HEX40, HEX64 = (re.compile(r"[a-f0-9]{32}"), re.compile(r"[a-f0-9]{40}"), re.compile(r"[a-f0-9]{64}"))
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
SPEC_KEYS = {"version", "pr", "headSha", "registrationSha256", "sourceCheckpointId", "sourceManifestSha256", "genesisSha256"}
REVIEW_KEYS = {"version", "targetSha256", "registrationSha256", "sourceCheckpointId", "sourceManifestSha256",
               "oldRunId", "oldAttempt", "oldDispatcherSha", "oldCandidateSha", "checkpointId", "sourceJobId",
               "sourceLogSha256", "oldTransactionSha256", "oldAnchorSha256", "writerInventorySha256", "custodySha256",
               "auditWindowStart", "auditWindowEnd", "threatModel", "candidateCodeSha256", "dispatcherCodeSha256"}
CANDIDATE_PATHS = {"worker/tools/production_backup_head_harness.py", "worker/tools/production_lifecycle_drill.py",
                   "worker/tools/production_recovery.py", "worker/tools/native_restore_rehearsal.py",
                   "worker/tools/production_storage.py", "worker/tools/scoped_r2.py", "worker/tools/production_backup_transaction.py",
                   "worker/tools/production_backup_capacity.py", "worker/tools/production_control.py",
                   "worker/tools/production_target.py", "worker/tools/production_release_evidence.py"}
DISPATCHER_PATHS = {".github/workflows/worker-backup-reviewed-head.yml", "worker/tools/trusted_backup_head_gate.py",
                    ".github/workflows/worker-provider-reviewed-head.yml"}


def checkout_sha(path):
    require(path.is_dir() and not path.is_symlink())
    value = subprocess.run(["git", "-C", str(path), "rev-parse", "--verify", "HEAD"],
                           capture_output=True, check=True, text=True, timeout=15).stdout.strip()
    require(HEX40.fullmatch(value or ""))
    return value


def workflow_runs(start, end, token, *, maximum=400):
    """Complete bounded run inventory; zero omitted pages or duplicate runs."""
    require(type(maximum) is int and 1 <= maximum <= 400)
    rows, total = [], None
    for page in range(1, (maximum + 49) // 50 + 1):
        query = urlencode({"created": start + ".." + end, "per_page": 50, "page": page})
        result = github._get_json("/actions/runs?" + query, token)
        batch, count = result.get("workflow_runs"), result.get("total_count")
        require(isinstance(batch, list) and len(batch) <= 50 and type(count) is int and 0 <= count <= maximum
                and (total is None or total == count))
        total = count
        for run in batch:
            require(isinstance(run, dict) and type(run.get("id")) is int and run["id"] > 0
                    and isinstance(run.get("path"), str) and isinstance(run.get("event"), str)
                    and HEX40.fullmatch(run.get("head_sha", "")) and isinstance(run.get("created_at"), str)
                    and start <= run["created_at"] <= end and isinstance(run.get("status"), str)
                    and type(run.get("run_attempt")) is int and run["run_attempt"] >= 1)
            rows.append({key: run.get(key) for key in ("id", "path", "event", "head_sha", "created_at", "run_attempt")})
        require(len(rows) <= count)
        if len(rows) == count:
            require(len({row["id"] for row in rows}) == len(rows))
            return sorted(rows, key=lambda row: row["id"])
        require(len(batch) == 50)
    require(False, "The complete writer-window inventory exceeded its bound.")


def reviewed_source(revision, path, expected, token, directory):
    """Fetch a pinned immutable source once per runner; always rehash on use."""
    root = Path(directory)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink())
    cache = root / "no-export-reviewed-source-cache"
    try:
        cache.mkdir(mode=0o700)
    except FileExistsError:
        pass
    require(cache.is_dir() and not cache.is_symlink() and cache.stat().st_mode & 0o077 == 0)
    key = sha256((revision + "\n" + path).encode("utf-8")).hexdigest()
    name = cache / key
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        item = github._get_json("/contents/" + path + "?ref=" + revision, token)
        require(item.get("path") == path and item.get("type") == "file" and item.get("encoding") == "base64"
                and isinstance(item.get("content"), str))
        body = base64.b64decode(item["content"].replace("\n", ""), validate=True)
        require(0 < len(body) <= 1024 * 1024 and sha256(body).hexdigest() == expected,
                "An independently reviewed source differs.")
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as saved:
            saved.write(body)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as cached:
        metadata = os.fstat(cached.fileno())
        require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= 1024 * 1024
                and metadata.st_mode & 0o077 == 0)
        body = cached.read(1024 * 1024 + 1)
    require(len(body) == metadata.st_size and sha256(body).hexdigest() == expected,
            "A cached reviewed source differs.")


def original_source(review, token, main, directory):
    source = github._get_json("/actions/runs/" + OLD_RUN + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + OLD_RUN, token)
    require(str(source.get("id")) == str(latest.get("id")) == OLD_RUN and source.get("run_attempt") == latest.get("run_attempt") == 1
            and source.get("path") in {OLD_WORKFLOW, OLD_WORKFLOW + "@main", OLD_WORKFLOW + "@refs/heads/main"}
            and source.get("head_sha") == OLD_MAIN and source.get("head_branch") == "main"
            and source.get("event") == "workflow_dispatch" and (source.get("status"), source.get("conclusion")) == ("completed", "failure")
            and latest.get("status") == "completed"
            and all(isinstance(source.get(key), dict) and source[key].get("id") == github.REPOSITORY_ID for key in ("repository", "head_repository")))
    jobs = github._get_json("/actions/runs/" + OLD_RUN + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int and jobs["total_count"] == len(jobs["jobs"]) < 100)
    selected = [job for job in jobs["jobs"] if isinstance(job, dict) and str(job.get("id")) == OLD_JOB and job.get("name") == "validate"]
    require(len(selected) == 1 and str(selected[0].get("run_id")) == OLD_RUN and selected[0].get("run_attempt") == 1
            and selected[0].get("head_sha") == OLD_MAIN and (selected[0].get("status"), selected[0].get("conclusion")) == ("completed", "failure"))
    for name in ("Verify the exact independently reviewed head before checkout", "Independently recheck trusted main and candidate checkout",
                 "Confirm only the authorized isolated test identity", "Run the reviewed candidate against only dedicated isolation"):
        steps = [step for step in selected[0].get("steps", []) if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) ==
                (("completed", "failure") if name == "Run the reviewed candidate against only dedicated isolation" else ("completed", "success")))
    if OLD_MAIN != main:
        comparison = github.compare_commits_metadata(OLD_MAIN, main, token)
        require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                and comparison.get("base_commit", {}).get("sha") == OLD_MAIN and comparison.get("merge_base_commit", {}).get("sha") == OLD_MAIN)
    for revision, entries in ((OLD_CANDIDATE, review["candidateCodeSha256"]), (OLD_MAIN, review["dispatcherCodeSha256"])):
        for path, expected in sorted(entries.items()):
            reviewed_source(revision, path, expected, token, directory)
    provider_path = ".github/workflows/worker-provider-reviewed-head.yml"
    reviewed_source(main, provider_path, review["dispatcherCodeSha256"][provider_path], token, directory)


def verify_failed_initial_plan(item, env, token):
    """The one proven failed pre-candidate plan never received cloud credentials."""
    require(str(item["id"]) == FAILED_PLAN_RUN and item["path"] == WORKFLOW
            and item["event"] == "workflow_dispatch" and item["head_sha"] == FAILED_PLAN_MAIN
            and item["run_attempt"] == 1)
    run = github._get_json("/actions/runs/" + FAILED_PLAN_RUN, token)
    require(str(run.get("id")) == FAILED_PLAN_RUN and run.get("run_attempt") == 1
            and run.get("path") in {WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main"}
            and run.get("head_sha") == FAILED_PLAN_MAIN and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "failure")
            and run.get("display_title") == "No-export plan at " + FAILED_PLAN_MAIN + " candidate " + FAILED_PLAN_HEAD
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + FAILED_PLAN_RUN + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == 2
            and {job.get("name") for job in jobs} == {"resolution", "readback"})
    resolution = next(job for job in jobs if job.get("name") == "resolution")
    reader = next(job for job in jobs if job.get("name") == "readback")
    require(str(resolution.get("id")) == FAILED_PLAN_JOB and str(resolution.get("run_id")) == FAILED_PLAN_RUN and resolution.get("run_attempt") == 1
            and resolution.get("head_sha") == FAILED_PLAN_MAIN
            and (resolution.get("status"), resolution.get("conclusion")) == ("completed", "failure")
            and str(reader.get("run_id")) == FAILED_PLAN_RUN and reader.get("run_attempt") == 1
            and reader.get("head_sha") == FAILED_PLAN_MAIN
            and (reader.get("status"), reader.get("conclusion")) == ("completed", "skipped"))
    steps = resolution.get("steps")
    require(isinstance(steps, list) and len(steps) >= 7)
    expected = ((2, "Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "success"),
                (3, "Verify no-export identity before candidate checkout", "failure"),
                (4, "Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "skipped"),
                (5, "Verify exact reviewed no-export checkout", "skipped"),
                (6, "Verify no-export test Bot identity", "skipped"),
                (7, "Plan or apply the no-export resolution", "skipped"))
    for number, name, conclusion in expected:
        matches = [step for step in steps if isinstance(step, dict) and step.get("number") == number]
        require(len(matches) == 1 and matches[0].get("name") == name
                and (matches[0].get("status"), matches[0].get("conclusion")) == ("completed", conclusion))
    for path, expected_sha in FAILED_PLAN_SOURCES.items():
        reviewed_source(FAILED_PLAN_MAIN, path, expected_sha, token, env.get("RUNNER_TEMP", ""))


def live_writer_boundary(rows, env, token, candidate):
    """Reject non-reviewed writers after the fixed historical audit cutoff."""
    safe_ci = {".github/workflows/python-ci.yml", ".github/workflows/worker-ci.yml", ".github/workflows/worker-provider-fetch-ci.yml"}
    provider_read = ".github/workflows/worker-provider-reviewed-head.yml"
    current_run = env.get("GITHUB_RUN_ID", "")
    require(DECIMAL.fullmatch(current_run or ""))
    for item in rows:
        path, event, run_id = item["path"], item["event"], str(item["id"])
        if event in {"pull_request", "push"} and path in safe_ci:
            continue
        if event == "workflow_dispatch" and path == provider_read and item["head_sha"] in {OLD_MAIN, env["GITHUB_SHA"]}:
            continue
        if run_id == FAILED_PLAN_RUN:
            verify_failed_initial_plan(item, env, token)
            continue
        require(event == "workflow_dispatch" and path == WORKFLOW and item["head_sha"] == env["GITHUB_SHA"],
                "An unreviewed run may have held a target-bucket writer.")
        if run_id == current_run:
            continue
        run = github._get_json("/actions/runs/" + run_id, token)
        title = run.get("display_title", "")
        actions = ("audit-writers", "plan", "seal", "verify-seal", "release", "verify-release")
        require(str(run.get("id")) == run_id and run.get("run_attempt") == 1 and run.get("status") == "completed"
                and title in {"No-export " + action + " at " + env["GITHUB_SHA"] + " candidate " + candidate
                              for action in actions},
                "A prior resolution writer is unresolved or could have released the anchor.")
        if title.startswith("No-export release "):
            require(env.get("NO_EXPORT_ACTION") == "verify-release" and run_id == env.get("NO_EXPORT_RELEASE_RUN_ID")
                    and run_id == env.get("SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID"),
                    "Only the exact protected release can be inspected without writing.")
        if title.startswith("No-export seal "):
            if run.get("conclusion") != "success":
                require(env.get("NO_EXPORT_ACTION") in {"verify-seal", "release", "release-readback", "verify-release"}
                        and run_id == env.get("NO_EXPORT_SEAL_RUN_ID")
                        and run_id == env.get("SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID"),
                        "Only the exact protected interrupted seal can be independently inspected.")
                continue
            jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
            require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
                    and jobs["total_count"] == len(jobs["jobs"]) < 100)
            readers = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "readback"]
            require(len(readers) == 1 and str(readers[0].get("run_id")) == run_id and readers[0].get("run_attempt") == 1
                    and (readers[0].get("status"), readers[0].get("conclusion")) == ("completed", "success"))
            steps = [step for step in readers[0].get("steps", []) if isinstance(step, dict)
                     and step.get("name") == "Independently verify no-export evidence"]
            require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))


def reviewed_run(run_id, action, main, candidate, token, *, successful, jobs_required):
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(str(run.get("id")) == str(latest.get("id")) == run_id and run.get("run_attempt") == latest.get("run_attempt") == 1
            and run.get("path") in {WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main"}
            and run.get("head_sha") == main and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("display_title") == "No-export " + action + " at " + main + " candidate " + candidate
            and run.get("status") == latest.get("status") == "completed"
            and run.get("conclusion") in {"success", "failure", "cancelled", "timed_out"}
            and (not successful or run.get("conclusion") == "success")
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(response.get("jobs"), list) and type(response.get("total_count")) is int
            and response["total_count"] == len(response["jobs"]) < 100)
    for name, final, final_success in jobs_required:
        selected = [job for job in response["jobs"] if isinstance(job, dict) and job.get("name") == name]
        require(len(selected) == 1 and str(selected[0].get("run_id")) == run_id and selected[0].get("run_attempt") == 1
                and selected[0].get("head_sha") == main and selected[0].get("status") == "completed"
                and (not final_success or selected[0].get("conclusion") == "success"))
        for wanted in ("Verify no-export identity before candidate checkout", "Verify exact reviewed no-export checkout",
                       "Verify no-export test Bot identity", final):
            steps = [step for step in selected[0].get("steps", []) if isinstance(step, dict) and step.get("name") == wanted]
            require(len(steps) == 1 and steps[0].get("status") == "completed"
                    and (steps[0].get("conclusion") == "success" if wanted != final or final_success
                         else steps[0].get("conclusion") in {"success", "failure", "cancelled", "timed_out"}))


def save_inventory(directory, inventory):
    temporary = Path(directory)
    require(temporary.is_absolute() and temporary.is_dir() and not temporary.is_symlink())
    path = temporary / "no-export-writer-inventory.json"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as existing:
            metadata = os.fstat(existing.fileno())
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_size == len(inventory)
                    and metadata.st_mode & 0o077 == 0 and existing.read(len(inventory) + 1) == inventory,
                    "The local writer inventory changed.")
    else:
        with os.fdopen(descriptor, "wb") as saved:
            saved.write(inventory)


def validate(env):
    main, token, action = env.get("GITHUB_SHA", ""), env.get("GH_TOKEN", ""), env.get("NO_EXPORT_ACTION", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/" + WORKFLOW + "@" + github.MAIN_REF
            and env.get("GITHUB_WORKFLOW_SHA") == main and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_RUN_ATTEMPT") == "1" and HEX40.fullmatch(main or "")
            and re.fullmatch(r"[!-~]{1,4096}", token or "") and env.get("NO_EXPORT_ENVIRONMENT") == ENVIRONMENT
            and env.get("SUBS_BOT_BACKUP_NO_EXPORT_ENABLED") == "true"
            and action in {"audit-writers", "plan", "seal", "verify-seal", "release", "verify-release", "evidence-readback", "release-readback"})
    spec = parsed(env.get("NO_EXPORT_VALIDATION_JSON", ""))
    require(set(spec) == SPEC_KEYS and type(spec["version"]) is int and spec["version"] == 1 and spec["pr"] == "291"
            and HEX40.fullmatch(spec.get("headSha", "")) and spec["headSha"] == env.get("BACKUP_REVIEWED_HEAD_SHA")
            and HEX32.fullmatch(spec.get("sourceCheckpointId", ""))
            and all(HEX64.fullmatch(spec.get(key, "")) for key in ("registrationSha256", "sourceManifestSha256", "genesisSha256"))
            and canonical(spec).decode() == env["NO_EXPORT_VALIDATION_JSON"])
    review_raw = env.get("NO_EXPORT_REVIEW_JSON", "")
    review = parsed(review_raw)
    require(set(review) == REVIEW_KEYS and type(review["version"]) is int and review["version"] == 1
            and review["oldRunId"] == OLD_RUN and review["oldAttempt"] == "1" and review["oldDispatcherSha"] == OLD_MAIN
            and review["oldCandidateSha"] == OLD_CANDIDATE and review["checkpointId"] == CHECKPOINT
            and review["sourceJobId"] == OLD_JOB and review["sourceLogSha256"] == OLD_LOG
            and review["threatModel"] == "reviewed-writers-no-unapproved-deletion"
            and all(HEX64.fullmatch(review.get(k, "")) for k in ("targetSha256", "registrationSha256", "sourceManifestSha256",
                "oldTransactionSha256", "oldAnchorSha256", "writerInventorySha256", "custodySha256"))
            and review["registrationSha256"] == spec["registrationSha256"]
            and review["sourceCheckpointId"] == spec["sourceCheckpointId"]
            and review["sourceManifestSha256"] == spec["sourceManifestSha256"]
            and review["auditWindowStart"] == "2026-11-17T17:53:00Z" and review["auditWindowEnd"] == "2026-11-17T20:26:27Z"
            and sha256(canonical(review)).hexdigest() == env.get("NO_EXPORT_REVIEW_SHA256"))
    custody = parsed(env.get("NO_EXPORT_CUSTODY_JSON", ""))
    require(custody == {"version": 1, "targetSha256": review["targetSha256"],
            "writerInventorySha256": review["writerInventorySha256"], "auditWindowStart": review["auditWindowStart"],
            "auditWindowEnd": review["auditWindowEnd"], "threatModel": review["threatModel"],
            "assertions": ["protected-environments-main-only", "reviewed-project-writers-only",
                           "no-unapproved-object-writes-or-deletions", "no-concurrent-target-bucket-writers-during-resolution"]}
            and type(custody.get("version")) is int and sha256(canonical(custody)).hexdigest() == review["custodySha256"])
    for key, paths in (("candidateCodeSha256", CANDIDATE_PATHS), ("dispatcherCodeSha256", DISPATCHER_PATHS)):
        require(isinstance(review[key], dict) and set(review[key]) == paths
                and all(HEX64.fullmatch(value or "") for value in review[key].values()))
    if action in {"seal", "verify-seal", "release", "verify-release", "evidence-readback", "release-readback"}:
        require(HEX64.fullmatch(env.get("NO_EXPORT_PLAN_SHA256", ""))
                and env.get("NO_EXPORT_PROTECTED_PLAN_SHA256") == env["NO_EXPORT_PLAN_SHA256"])
    if action in {"seal", "release"}:
        require(env.get("SUBS_BOT_BACKUP_NO_EXPORT_WRITES_ENABLED") == "true")
    if action in {"verify-seal", "release", "verify-release", "release-readback"}:
        require(HEX64.fullmatch(env.get("NO_EXPORT_EVIDENCE_SHA256", ""))
                and env.get("NO_EXPORT_PROTECTED_EVIDENCE_SHA256") == env["NO_EXPORT_EVIDENCE_SHA256"]
                and DECIMAL.fullmatch(env.get("NO_EXPORT_SEAL_RUN_ID", ""))
                and env.get("SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID") == env["NO_EXPORT_SEAL_RUN_ID"])
    if action in {"release", "release-readback", "verify-release"}:
        reader = env.get("NO_EXPORT_SEAL_READER_RUN_ID", "")
        require(reader == env.get("SUBS_BOT_BACKUP_NO_EXPORT_SEAL_READER_RUN_ID", "")
                and (not reader or DECIMAL.fullmatch(reader)))
    if action == "verify-release":
        require(DECIMAL.fullmatch(env.get("NO_EXPORT_RELEASE_RUN_ID", ""))
                and env.get("SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID") == env["NO_EXPORT_RELEASE_RUN_ID"])
    ref = github._get_json("/git/ref/heads/main", token)
    require(ref.get("ref") == github.MAIN_REF and ref.get("object", {}).get("sha") == main)
    pull = github._get_json("/pulls/291", token)
    require(pull.get("number") == 291 and pull.get("state") == "open" and pull.get("base", {}).get("ref") == "main"
            and pull.get("head", {}).get("sha") == spec["headSha"] and pull["head"].get("ref") == "codex/backup-orchestration"
            and all(isinstance(pull.get(key, {}).get("repo"), dict) and pull[key]["repo"].get("id") == github.REPOSITORY_ID for key in ("head", "base")))
    comparison = github.compare_commits_metadata(main, spec["headSha"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == main and comparison.get("merge_base_commit", {}).get("sha") == main)
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink()
            and checkout_sha(workspace / "trusted") == main)
    check = env.get("NO_EXPORT_GATE_CHECK", "")
    require(check in {"before", "ready", "credential"})
    if check != "before":
        require(checkout_sha(workspace / "candidate") == spec["headSha"])
    if check == "credential":
        test = parsed(env.get("SUBS_BOT_TELEGRAM_TEST_CONFIG", ""))
        require(set(test) == {"botId", "botUsername", "botToken", "webhookSecret", "adminId", "memberId", "groupId"}
                and test["botId"] == "9293938370" and test["botUsername"] == "test_cfsubs_bot"
                and test["adminId"] == "8813701954" and test["memberId"] == "8653767757" and test["groupId"] == "-5114255828"
                and re.fullmatch(r"9293938370:[A-Za-z0-9_-]{20,128}", test["botToken"] or "")
                and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", test["webhookSecret"] or ""))
    original_source(review, token, main, env.get("RUNNER_TEMP", ""))
    if action in {"verify-seal", "release", "release-readback", "verify-release"}:
        reader = env.get("NO_EXPORT_SEAL_READER_RUN_ID", "") if action != "verify-seal" else ""
        independent = action == "verify-seal" or bool(reader)
        jobs_required = [("resolution", "Plan or apply the no-export resolution", not independent)]
        if not independent:
            jobs_required.append(("readback", "Independently verify no-export evidence", True))
        reviewed_run(env["NO_EXPORT_SEAL_RUN_ID"], "seal", main, spec["headSha"], token,
                     successful=not independent, jobs_required=jobs_required)
        if reader:
            reviewed_run(reader, "verify-seal", main, spec["headSha"], token, successful=True,
                         jobs_required=[("resolution", "Plan or apply the no-export resolution", True)])
    if action == "verify-release":
        reviewed_run(env["NO_EXPORT_RELEASE_RUN_ID"], "release", main, spec["headSha"], token, successful=False,
                     jobs_required=[("resolution", "Plan or apply the no-export resolution", False)])
    historic = workflow_runs(review["auditWindowStart"], review["auditWindowEnd"], token, maximum=150)
    inventory = canonical(historic)
    inventory_sha = sha256(inventory).hexdigest()
    require(action == "audit-writers" or inventory_sha == review["writerInventorySha256"], "The reviewed writer inventory changed.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    require(now >= review["auditWindowEnd"])
    live = workflow_runs(review["auditWindowEnd"], now, token)
    writers = sum(row["path"] == WORKFLOW and str(row["id"]) != env.get("GITHUB_RUN_ID") for row in live)
    require(writers <= 40, "The no-export history exceeds this one-time resolution's bounded audit.")
    live_writer_boundary(live, env, token, spec["headSha"])
    if check == "credential":
        save_inventory(env.get("RUNNER_TEMP", ""), inventory)
    return {"status": "validated", "writerInventorySha256": inventory_sha, "oldRunId": OLD_RUN,
            "liveRunCount": len(live), "writerRunCount": writers,
            "reviewSha256": sha256(canonical(review)).hexdigest()}


if __name__ == "__main__":
    try:
        result = validate(os.environ)
        output = os.environ.get("GITHUB_OUTPUT", "")
        if output:
            with open(output, "a", encoding="ascii") as stream:
                stream.write("writer_inventory_sha256=" + result["writerInventorySha256"] + "\n")
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("::error::The fixed isolated no-export identity or complete audit inventory did not verify.")
        raise SystemExit(1) from None

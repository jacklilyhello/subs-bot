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
FAILED_AUDIT_RUN = "44211462453"
PRECHECKOUT_FAILURES = {
    FAILED_PLAN_RUN: {"main": FAILED_PLAN_MAIN, "head": FAILED_PLAN_HEAD, "job": FAILED_PLAN_JOB,
                      "action": "plan", "logSha256": "06b7dc59ad424d1862233aca9290914bb1c67863569f5ef6908b2f99b3068852",
                      "sources": FAILED_PLAN_SOURCES},
    FAILED_AUDIT_RUN: {"main": "2cf63df6b024f356ce20e7540e18e0fe551efa00",
                       "head": "4dd43d8ffe5b232f8ec49e1bd68542a66e2167c0", "job": "134490616925",
                       "action": "audit-writers", "logSha256": "0b36071ed1c0f9c3153e14ee6cb068ca00a510ee8f118ed5787697ec9d3b0031",
                       "sources": {".github/workflows/worker-backup-no-export-resolution.yml":
                                   "fd9bc30a9339ac23ea9e354494fb0b0baef946cbc9c6f8458aeae41d2af0fc94",
                                   "worker/tools/trusted_backup_no_export_gate.py":
                                   "6ac708aaf01e2bb7f880264b2e859a93292c59bd6d118efd6ffb83514e4d22c5"}},
}
UNSTARTED_PUSHES = {
    "44184558493": {"head": "065c3365de786127dc5c547474961a88b77d0f0e", "suite": "119612100985",
                     "createdAt": "2026-11-17T21:53:52Z"},
    "44184809455": {"head": "7d8c324fd68fefdd2356c5d573a22d8f681859ba", "suite": "119612767443",
                     "createdAt": "2026-11-17T21:55:20Z"},
}
UNSTARTED_WORKFLOW = ".github/workflows/worker-production-backup.yml"
UNSTARTED_WORKFLOW_SHA256 = "39ae8c13690402336f3c54055be8c088949799fd602615446ba5407854c58b73"
PROVIDER_READ_RUN = "44179992037"
PROVIDER_READ_WORKFLOW = ".github/workflows/worker-provider-reviewed-head.yml"
PROVIDER_READ_SOURCE_SHA256 = "4d46897f48702019d0f376a33f744998d1a0a5ea852058642f0034e50e4f1dbf"
LATER_PROVIDER_READ_RUN = "44192480776"
LATER_PROVIDER_MAIN = "e9a7b892780aa6020f0725b76c57162dba908458"
LATER_PROVIDER_HEAD = "45e069320c08022907b609900475228732e9cd5d"
LATER_PROVIDER_SOURCE_JOB = "134425218323"
LATER_PROVIDER_LOG_SHA256 = "3b1b18d4ec9481c7aa07d726d179ae4a6c2763185552cd34fd3c1da4a6935ae2"
LATER_PROVIDER_JOBS_SHA256 = "52b052970085dd7568a1f58897ae8c9aa58171c138b5559b95c9ccb0248efc83"
LEGACY_ARCHIVE_WORKFLOW = ".github/workflows/worker-backup-webhook-history-archive.yml"
LEGACY_ARCHIVE_TREE = "efe71e36bc6f62643c3d5c7c6d3bc2b6019e3d46"
LEGACY_SOURCE_LOGS = {
    "43945207035": "4ce541b5b14079876e4d6f48857936c8ab7756a57a7109a716fa1ecbebfff066",
    "43939288298": "27fad88301a26adb1ce260b6c09d144de3788c3cf5872f1feb0f76877c75f471",
    "43868642682": "bf1dccf3051c046d79a00c33026408bd8b5c9b1c4e1637e8b1522ce6b2457603",
    "43865731376": "99c9592f73cb60fd72c76fe2a96091428178c73ac2eb8688731ccbebc0a61ed5",
    "43874513488": "ec4801b9322afec168c698a3a521c4aedeac2282c5d36eb92b3d7f639310b3f1",
    "42363001024": "7e966885f6b2b111502770fc06f897417e4e2525cfd08836a62055d23e079f3b",
    "42362915072": "b6c6d2f7f441230599a1ce25d1eabe582732fdfce5fd64088b124e24abd0378c",
}
LEGACY_ARCHIVE_SOURCE = {
    ".github/workflows/worker-backup-webhook-history-archive.yml": "e5740bda069e4092b0d845591d3efd1dbd8b94e3ec854df4d2717ed3c8d50b39",
    "worker/tools/trusted_backup_webhook_log_archive.py": "02b6501993099464986e9fde59a561554a4ab59bbe0853110f2c5337d5181270",
    "worker/tools/production_backup_webhook_recovery.py": "208d62569d33e3a62adba23702f122f316d15efb8642e2119a503ef1721d18f3",
    "worker/tools/production_lifecycle_drill.py": "70cb89a28a21658c2f6876b5417c7faf1647d00e161fb1ddcd71328eabe38a70",
    "worker/tools/production_storage.py": "efcedd04416c016fdb046b28c79b837d114fe89ddc43d802d869c15eccadd2b0",
    "worker/tools/scoped_r2.py": "ccb8b20ea19b6b38f2f079cc60cfbe1419c052d11615d186f0df0d9609fd5b9f",
    "worker/tools/production_target.py": "6a21bfcf541b9612fd479fb83f4f12aaf44239f423f5bf8b549c16cf7d54f1f3",
    "worker/tools/production_control.py": "79755dd7ca803dbefe69d0c2f33d47e9057907f94c3f2ae3ceac158a2ca96021",
    "worker/tools/prepare_isolation_artifact.py": "e356152118b6f7f073c2c93fb5731fa5201de6824891679216dc4e76319cd616",
}
ENVIRONMENT = "subs-bot-backup-head-isolation"
HEX32, HEX40, HEX64 = (re.compile(r"[a-f0-9]{32}"), re.compile(r"[a-f0-9]{40}"), re.compile(r"[a-f0-9]{64}"))
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
GATE_STAGES = {"identity", "review-contract", "current-main-and-head", "checkout", "original-run",
               "original-steps", "original-parentage", "original-source", "prior-resolution", "historic-inventory",
               "live-inventory", "writer-boundary", "legacy-identity", "legacy-source", "legacy-jobs",
               "legacy-logs", "provider-identity", "provider-jobs", "provider-log", "unstarted-push", "inventory-output"}
GATE_STAGE = "identity"
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


def gate_stage(value):
    """Expose only a fixed public phase, never an exception or input value."""
    global GATE_STAGE
    require(value in GATE_STAGES)
    GATE_STAGE = value


def checkout_sha(path):
    require(path.is_dir() and not path.is_symlink())
    value = subprocess.run(["git", "-C", str(path), "rev-parse", "--verify", "HEAD"],
                           capture_output=True, check=True, text=True, timeout=15).stdout.strip()
    require(HEX40.fullmatch(value or ""))
    return value


def workflow_runs(start, end, token, *, maximum=400, live_metadata=False):
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
            keys = ("id", "path", "event", "head_sha", "created_at", "run_attempt")
            if live_metadata:
                keys += ("status", "conclusion", "display_title", "workflow_id", "head_branch", "repository", "head_repository")
            rows.append({key: run.get(key) for key in keys})
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


def cached_private_bytes(directory, key, expected, maximum, fetch):
    """Cache only independently SHA-pinned immutable bytes on this fresh runner."""
    root = Path(directory)
    require(root.is_absolute() and root.is_dir() and not root.is_symlink() and HEX64.fullmatch(expected or ""))
    cache = root / "no-export-reviewed-evidence-cache"
    try:
        cache.mkdir(mode=0o700)
    except FileExistsError:
        pass
    require(cache.is_dir() and not cache.is_symlink() and cache.stat().st_mode & 0o077 == 0)
    name = cache / sha256(key.encode("utf-8")).hexdigest()
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        body = fetch()
        require(isinstance(body, bytes) and 0 < len(body) <= maximum and sha256(body).hexdigest() == expected)
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "wb") as saved:
            saved.write(body)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as saved:
        metadata = os.fstat(saved.fileno())
        require(stat.S_ISREG(metadata.st_mode) and 0 < metadata.st_size <= maximum and metadata.st_mode & 0o077 == 0)
        body = saved.read(maximum + 1)
    require(len(body) == metadata.st_size and sha256(body).hexdigest() == expected)
    return body


def original_source(review, token, main, directory):
    gate_stage("original-run")
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
    gate_stage("original-steps")
    for name in ("Verify the exact independently reviewed head before checkout", "Independently recheck trusted main and candidate checkout",
                 "Confirm only the authorized isolated test identity", "Run the reviewed candidate against only dedicated isolation"):
        steps = [step for step in selected[0].get("steps", []) if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) ==
                (("completed", "failure") if name == "Run the reviewed candidate against only dedicated isolation" else ("completed", "success")))
    if OLD_MAIN != main:
        gate_stage("original-parentage")
        comparison = github.compare_commits_metadata(OLD_MAIN, main, token)
        require(comparison.get("status") == "ahead" and comparison.get("behind_by") == 0
                and comparison.get("base_commit", {}).get("sha") == OLD_MAIN and comparison.get("merge_base_commit", {}).get("sha") == OLD_MAIN)
    gate_stage("original-source")
    for revision, entries in ((OLD_CANDIDATE, review["candidateCodeSha256"]), (OLD_MAIN, review["dispatcherCodeSha256"])):
        for path, expected in sorted(entries.items()):
            reviewed_source(revision, path, expected, token, directory)
    provider_path = ".github/workflows/worker-provider-reviewed-head.yml"
    reviewed_source(main, provider_path, review["dispatcherCodeSha256"][provider_path], token, directory)


def verify_failed_initial_plan(item, env, token):
    """Only two pinned first-gate failures, never an arbitrary failed writer."""
    gate_stage("prior-resolution")
    run_id = str(item["id"])
    require(run_id in PRECHECKOUT_FAILURES)
    pin = PRECHECKOUT_FAILURES[run_id]
    require(item["path"] == WORKFLOW
            and item["event"] == "workflow_dispatch" and item["head_sha"] == pin["main"]
            and item["run_attempt"] == 1)
    original = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    for run in (original, latest):
        require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
                and run.get("path") in {WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main"}
                and run.get("head_sha") == pin["main"] and run.get("head_branch") == "main"
                and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "failure")
                and run.get("display_title") == "No-export " + pin["action"] + " at " + pin["main"] + " candidate " + pin["head"]
                and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == 2
            and {job.get("name") for job in jobs} == {"resolution", "readback"})
    resolution = next(job for job in jobs if job.get("name") == "resolution")
    reader = next(job for job in jobs if job.get("name") == "readback")
    require(str(resolution.get("id")) == pin["job"] and str(resolution.get("run_id")) == run_id and resolution.get("run_attempt") == 1
            and resolution.get("head_sha") == pin["main"]
            and (resolution.get("status"), resolution.get("conclusion")) == ("completed", "failure")
            and str(reader.get("run_id")) == run_id and reader.get("run_attempt") == 1
            and reader.get("head_sha") == pin["main"]
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
    for path, expected_sha in pin["sources"].items():
        reviewed_source(pin["main"], path, expected_sha, token, env.get("RUNNER_TEMP", ""))
    from trusted_backup_webhook_log_archive import download_log
    cached_private_bytes(env.get("RUNNER_TEMP", ""), "precheckout-log-" + pin["job"], pin["logSha256"],
                         4 * 1024 * 1024, lambda: download_log(pin["job"], token))


def verify_fixed_unstarted_push(item, env, token):
    """Two exact completed failures with no jobs; no failure cause is inferred."""
    gate_stage("unstarted-push")
    run_id = str(item["id"])
    require(run_id in UNSTARTED_PUSHES)
    pin = UNSTARTED_PUSHES[run_id]
    require(item["path"] == UNSTARTED_WORKFLOW and item["event"] == "push"
            and item["head_sha"] == pin["head"] and item["run_attempt"] == 1)
    original = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    for run in (original, latest):
        require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
                and run.get("path") == UNSTARTED_WORKFLOW and run.get("event") == "push"
                and run.get("head_sha") == pin["head"] and run.get("head_branch") == "codex/backup-coordinator"
                and run.get("created_at") == pin["createdAt"] and run.get("workflow_id") == 421656360
                and str(run.get("check_suite_id")) == pin["suite"]
                and (run.get("status"), run.get("conclusion")) == ("completed", "failure")
                and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                        for k in ("repository", "head_repository")))
    jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs, dict) and set(jobs) == {"total_count", "jobs"}
            and type(jobs["total_count"]) is int and jobs["total_count"] == 0 and jobs["jobs"] == [],
            "A fixed unstarted push now has jobs or incomplete metadata.")
    suite = github._get_json("/check-suites/" + pin["suite"], token)
    require(str(suite.get("id")) == pin["suite"] and suite.get("head_sha") == pin["head"]
            and suite.get("head_branch") == "codex/backup-coordinator"
            and (suite.get("status"), suite.get("conclusion")) == ("completed", "failure")
            and type(suite.get("latest_check_runs_count")) is int and suite["latest_check_runs_count"] == 0
            and suite.get("app", {}).get("id") == 15368 and suite.get("app", {}).get("slug") == "github-actions"
            and suite.get("repository", {}).get("id") == github.REPOSITORY_ID)
    checks = github._get_json("/check-suites/" + pin["suite"] + "/check-runs?per_page=100", token)
    require(isinstance(checks, dict) and set(checks) == {"total_count", "check_runs"}
            and type(checks["total_count"]) is int and checks["total_count"] == 0 and checks["check_runs"] == [],
            "A fixed unstarted push now has check runs.")
    reviewed_source(pin["head"], UNSTARTED_WORKFLOW, UNSTARTED_WORKFLOW_SHA256, token, env.get("RUNNER_TEMP", ""))


def verify_fixed_provider_read(item, env, token):
    """Recognize only the completed, reviewed read-only Provider run at old main."""
    gate_stage("provider-identity")
    require(str(item["id"]) == PROVIDER_READ_RUN and item["path"] == PROVIDER_READ_WORKFLOW
            and item["event"] == "workflow_dispatch" and item["head_sha"] == FAILED_PLAN_MAIN
            and item["run_attempt"] == 1)
    run = github._get_json("/actions/runs/" + PROVIDER_READ_RUN, token)
    require(str(run.get("id")) == PROVIDER_READ_RUN and run.get("run_attempt") == 1
            and run.get("head_sha") == FAILED_PLAN_MAIN and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "failure")
            and run.get("path") in {PROVIDER_READ_WORKFLOW, PROVIDER_READ_WORKFLOW + "@main", PROVIDER_READ_WORKFLOW + "@refs/heads/main"}
            and run.get("display_title") == "Reviewed Provider source verification at " + FAILED_PLAN_MAIN
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + PROVIDER_READ_RUN + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    expected = {"Reviewed Provider source verification": "success", "Trusted Provider R2 attestation": "success",
                "Reviewed Provider simulated source fault": "skipped", "Trusted Provider live attestation": "failure"}
    require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == len(expected)
            and {job.get("name") for job in jobs} == set(expected))
    for job in jobs:
        require(str(job.get("run_id")) == PROVIDER_READ_RUN and job.get("run_attempt") == 1
                and job.get("head_sha") == FAILED_PLAN_MAIN and job.get("status") == "completed"
                and job.get("conclusion") == expected[job["name"]])
    reviewed_source(FAILED_PLAN_MAIN, PROVIDER_READ_WORKFLOW, PROVIDER_READ_SOURCE_SHA256, token, env.get("RUNNER_TEMP", ""))


def verify_later_provider_read(item, env, token):
    """Recognize only the fixed later read-only run, not its failed live result."""
    gate_stage("provider-identity")
    require(str(item["id"]) == LATER_PROVIDER_READ_RUN and item["path"] == PROVIDER_READ_WORKFLOW
            and item["event"] == "workflow_dispatch" and item["head_sha"] == LATER_PROVIDER_MAIN
            and item["run_attempt"] == 1 and item.get("head_branch") == "main"
            and (item.get("status"), item.get("conclusion")) == ("completed", "failure")
            and item.get("display_title") == "Reviewed Provider source verification at " + LATER_PROVIDER_MAIN
            and all(isinstance(item.get(k), dict) and item[k].get("id") == github.REPOSITORY_ID for k in ("repository", "head_repository")))
    reviewed_source(LATER_PROVIDER_MAIN, PROVIDER_READ_WORKFLOW, PROVIDER_READ_SOURCE_SHA256, token, env.get("RUNNER_TEMP", ""))
    fields = ("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion")
    def fetch_jobs():
        response = github._get_json("/actions/runs/" + LATER_PROVIDER_READ_RUN + "/attempts/1/jobs?per_page=100", token)
        jobs = response.get("jobs")
        require(isinstance(jobs, list) and type(response.get("total_count")) is int and response["total_count"] == len(jobs) == 4)
        return canonical([{key: job.get(key) for key in fields} for job in jobs])
    gate_stage("provider-jobs")
    raw = cached_private_bytes(env.get("RUNNER_TEMP", ""), "provider-jobs-" + LATER_PROVIDER_READ_RUN,
                               LATER_PROVIDER_JOBS_SHA256, 65536, fetch_jobs)
    jobs = json.loads(raw)
    expected = {"Reviewed Provider source verification": "success", "Reviewed Provider simulated source fault": "success",
                "Trusted Provider R2 attestation": "success", "Trusted Provider live attestation": "failure"}
    require(isinstance(jobs, list) and len(jobs) == 4 and {job.get("name") for job in jobs} == set(expected))
    for job in jobs:
        require(str(job.get("run_id")) == LATER_PROVIDER_READ_RUN and job.get("run_attempt") == 1
                and job.get("head_sha") == LATER_PROVIDER_MAIN and job.get("status") == "completed"
                and job.get("conclusion") == expected[job["name"]])
    gate_stage("provider-log")
    from trusted_backup_webhook_log_archive import download_log
    raw_log = cached_private_bytes(env.get("RUNNER_TEMP", ""), "provider-log-" + LATER_PROVIDER_SOURCE_JOB,
                                   LATER_PROVIDER_LOG_SHA256, 4 * 1024 * 1024,
                                   lambda: download_log(LATER_PROVIDER_SOURCE_JOB, token))
    values = []
    for line in raw_log.decode("utf-8-sig").splitlines():
        if "reviewedHeadSha" not in line or "{" not in line:
            continue
        try:
            value = json.loads(line[line.index("{"):])
        except (TypeError, ValueError):
            continue
        if isinstance(value, dict) and value.get("status") == "validated":
            values.append(value)
    require(len(values) == 3 and all(value.get("reviewedHeadSha") == LATER_PROVIDER_HEAD and value.get("pr") == "290" for value in values))


def verify_legacy_archive(item, record, env, token):
    """Check only an independently pinned completed archive run on reviewed main."""
    gate_stage("legacy-identity")
    run_id = str(item["id"])
    fields = {"action", "sourceRunId", "archiveJobId", "readbackJobId", "jobsSha256", "archiveLogSha256",
              "readbackLogSha256", "sourceLogSha256", "planSha256", "completionSha256"}
    require(isinstance(record, dict) and set(record) == fields and record["action"] in {"plan", "seal"}
            and record["sourceRunId"] in LEGACY_SOURCE_LOGS
            and record["sourceLogSha256"] == LEGACY_SOURCE_LOGS[record["sourceRunId"]]
            and DECIMAL.fullmatch(record["archiveJobId"] or "")
            and all(HEX64.fullmatch(record[key] or "") for key in ("jobsSha256", "archiveLogSha256", "planSha256"))
            and ((record["action"] == "plan" and record["readbackJobId"] == record["readbackLogSha256"] == record["completionSha256"] == "")
                 or (record["action"] == "seal" and DECIMAL.fullmatch(record["readbackJobId"] or "")
                     and HEX64.fullmatch(record["readbackLogSha256"] or "") and HEX64.fullmatch(record["completionSha256"] or ""))))
    require(item["path"] == LEGACY_ARCHIVE_WORKFLOW and item["head_sha"] == LATER_PROVIDER_MAIN
            and item["event"] == "workflow_dispatch" and item["run_attempt"] == 1
            and item.get("head_branch") == "main" and (item.get("status"), item.get("conclusion")) == ("completed", "success")
            and item.get("display_title") == "Preserve isolated webhook evidence " + record["sourceRunId"]
            and all(isinstance(item.get(key), dict) and item[key].get("id") == github.REPOSITORY_ID
                    for key in ("repository", "head_repository")))
    gate_stage("legacy-source")
    commit_pin = {"sha": LATER_PROVIDER_MAIN, "treeSha": LEGACY_ARCHIVE_TREE}
    def fetch_commit():
        commit = github._get_json("/git/commits/" + LATER_PROVIDER_MAIN, token)
        require(commit.get("sha") == LATER_PROVIDER_MAIN and isinstance(commit.get("tree"), dict)
                and commit["tree"].get("sha") == LEGACY_ARCHIVE_TREE)
        return canonical(commit_pin)
    require(cached_private_bytes(env.get("RUNNER_TEMP", ""), "legacy-commit-" + LATER_PROVIDER_MAIN,
                                 sha256(canonical(commit_pin)).hexdigest(), 1024, fetch_commit) == canonical(commit_pin))
    for path, expected in LEGACY_ARCHIVE_SOURCE.items():
        reviewed_source(LATER_PROVIDER_MAIN, path, expected, token, env.get("RUNNER_TEMP", ""))
    def fetch_jobs():
        response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
        jobs = response.get("jobs")
        require(isinstance(jobs, list) and type(response.get("total_count")) is int and response["total_count"] == len(jobs) == 2)
        return canonical(jobs)
    gate_stage("legacy-jobs")
    jobs = json.loads(cached_private_bytes(env.get("RUNNER_TEMP", ""), "legacy-jobs-" + run_id,
                                           record["jobsSha256"], 1024 * 1024, fetch_jobs))
    require(isinstance(jobs, list) and len(jobs) == 2 and {job.get("name") for job in jobs} == {"archive", "readback"})
    writer = next(job for job in jobs if job.get("name") == "archive")
    reader = next(job for job in jobs if job.get("name") == "readback")
    for job in jobs:
        require(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == LATER_PROVIDER_MAIN
                and job.get("status") == "completed")
    require(str(writer.get("id")) == record["archiveJobId"] and writer.get("conclusion") == "success"
            and reader.get("conclusion") == ("success" if record["action"] == "seal" else "skipped")
            and (record["action"] != "seal" or str(reader.get("id")) == record["readbackJobId"]))
    required_jobs = [(writer, ("Require the protected evidence archive switch", "Plan or conditionally seal the exact original job log"))]
    if record["action"] == "seal":
        required_jobs.append((reader, ("Require the protected evidence archive switch", "Independently compare the retained original log")))
    for job, names in required_jobs:
        require(isinstance(job.get("steps"), list))
        for name in names:
            steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == name]
            require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    gate_stage("legacy-logs")
    from trusted_backup_webhook_log_archive import download_log
    def report(job, expected, kind):
        raw = cached_private_bytes(env.get("RUNNER_TEMP", ""), "legacy-log-" + job, expected, 4 * 1024 * 1024,
                                   lambda: download_log(job, token))
        found = []
        for line in raw.decode("utf-8-sig").splitlines():
            if "{" not in line:
                continue
            try:
                value = json.loads(line[line.index("{"):])
            except (TypeError, ValueError):
                continue
            if isinstance(value, dict) and value.get("status") == kind:
                found.append(value)
        require(len(found) == 1 and found[0].get("planSha256") == record["planSha256"])
        return found[0]
    if record["action"] == "plan":
        require(report(record["archiveJobId"], record["archiveLogSha256"], "planned").get("mutationPerformed") is False)
    else:
        saved = report(record["archiveJobId"], record["archiveLogSha256"], "sealed-awaiting-independent-readback")
        readback = report(record["readbackJobId"], record["readbackLogSha256"], "independently-read-back")
        require(saved.get("logSha256") == readback.get("logSha256") == record["sourceLogSha256"]
                and saved.get("completionSha256") == readback.get("completionSha256") == record["completionSha256"]
                and readback.get("sourceRunId") == record["sourceRunId"] and readback.get("archiveRunId") == run_id
                and readback.get("archiveJobId") == record["archiveJobId"] and readback.get("readbackJobId") == record["readbackJobId"])


def live_writer_boundary(rows, env, token, candidate):
    """Reject non-reviewed writers after the fixed historical audit cutoff."""
    safe_ci = {".github/workflows/python-ci.yml", ".github/workflows/worker-ci.yml", ".github/workflows/worker-provider-fetch-ci.yml"}
    provider_read = PROVIDER_READ_WORKFLOW
    current_run = env.get("GITHUB_RUN_ID", "")
    require(DECIMAL.fullmatch(current_run or ""))
    legacy = parsed(env.get("NO_EXPORT_LEGACY_ARCHIVES_JSON", "") or "{}")
    require(isinstance(legacy, dict) and len(legacy) <= 14 and all(DECIMAL.fullmatch(key or "") for key in legacy))
    if legacy:
        pairs = [(entry.get("sourceRunId"), entry.get("action")) for entry in legacy.values() if isinstance(entry, dict)]
        require(len(pairs) == len(legacy) == 14 and set(pairs) ==
                {(source, action) for source in LEGACY_SOURCE_LOGS for action in ("plan", "seal")},
                "The complete seven-source archive ledger is required.")
    observed_legacy = set()
    for item in rows:
        gate_stage("writer-boundary")
        path, event, run_id = item["path"], item["event"], str(item["id"])
        if path == LEGACY_ARCHIVE_WORKFLOW:
            require(run_id in legacy, "An unreviewed history archive run was observed.")
            verify_legacy_archive(item, legacy[run_id], env, token)
            observed_legacy.add(run_id)
            continue
        if event in {"pull_request", "push"} and path in safe_ci:
            continue
        if event == "workflow_dispatch" and path == provider_read and item["head_sha"] in {OLD_MAIN, env["GITHUB_SHA"]}:
            continue
        if run_id == PROVIDER_READ_RUN:
            verify_fixed_provider_read(item, env, token)
            continue
        if run_id == LATER_PROVIDER_READ_RUN:
            verify_later_provider_read(item, env, token)
            continue
        if run_id in UNSTARTED_PUSHES:
            verify_fixed_unstarted_push(item, env, token)
            continue
        if run_id in PRECHECKOUT_FAILURES:
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
    require(observed_legacy == set(legacy), "A protected history archive is missing from the complete live inventory.")
    return len(observed_legacy)


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
    gate_stage("identity")
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
    gate_stage("review-contract")
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
    gate_stage("current-main-and-head")
    ref = github._get_json("/git/ref/heads/main", token)
    require(ref.get("ref") == github.MAIN_REF and ref.get("object", {}).get("sha") == main)
    pull = github._get_json("/pulls/291", token)
    require(pull.get("number") == 291 and pull.get("state") == "open" and pull.get("base", {}).get("ref") == "main"
            and pull.get("head", {}).get("sha") == spec["headSha"] and pull["head"].get("ref") == "codex/backup-orchestration"
            and all(isinstance(pull.get(key, {}).get("repo"), dict) and pull[key]["repo"].get("id") == github.REPOSITORY_ID for key in ("head", "base")))
    comparison = github.compare_commits_metadata(main, spec["headSha"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == main and comparison.get("merge_base_commit", {}).get("sha") == main)
    gate_stage("checkout")
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
    gate_stage("prior-resolution")
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
    gate_stage("historic-inventory")
    historic = workflow_runs(review["auditWindowStart"], review["auditWindowEnd"], token, maximum=150)
    inventory = canonical(historic)
    inventory_sha = sha256(inventory).hexdigest()
    require(action == "audit-writers" or inventory_sha == review["writerInventorySha256"], "The reviewed writer inventory changed.")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    require(now >= review["auditWindowEnd"])
    # This is one bounded incident-resolution window, not a production
    # monitoring retention limit. A full or larger inventory remains unknown.
    gate_stage("live-inventory")
    live = workflow_runs(review["auditWindowEnd"], now, token, maximum=400, live_metadata=True)
    writers = sum(row["path"] == WORKFLOW and str(row["id"]) != env.get("GITHUB_RUN_ID") for row in live)
    require(writers <= 40, "The no-export history exceeds this one-time resolution's bounded audit.")
    legacy_count = live_writer_boundary(live, env, token, spec["headSha"])
    gate_stage("inventory-output")
    if check == "credential":
        save_inventory(env.get("RUNNER_TEMP", ""), inventory)
    legacy = parsed(env.get("NO_EXPORT_LEGACY_ARCHIVES_JSON", "") or "{}")
    return {"status": "validated", "writerInventorySha256": inventory_sha, "oldRunId": OLD_RUN,
            "liveRunCount": len(live), "writerRunCount": writers, "legacyArchiveRunCount": legacy_count,
            "legacyArchiveSha256": sha256(canonical(legacy)).hexdigest(),
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
        print("::error::The fixed isolated no-export identity or complete audit inventory did not verify. Phase: " + GATE_STAGE)
        raise SystemExit(1) from None

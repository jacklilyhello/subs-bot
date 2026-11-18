"""Single-use dispatch journal for approved production backup checkpoints.

This module never fabricates a production approval. Its caller must validate the
protected main workflow, pinned configuration and every checkpoint result. An
unconfirmed dispatch is intentionally not retried.
"""
from hashlib import sha256
import os
import re

import prepare_isolation_artifact as artifact
import production_backup_transaction as maintenance
from production_target import canonical, parsed, require

HEX = re.compile(r"[a-f0-9]{64}")
REVISION = re.compile(r"[a-f0-9]{40}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
STEPS = ("plan-begin", "begin", "preflight", "plan-pause", "pause", "drain", "freeze", "capture", "verify", "plan-activate", "activate")
BASE = "maintenance/production-control/evidence/backup-coordinator/"
PROFILES = {"production": {"child": ".github/workflows/worker-production-backup.yml",
                            "parent": ".github/workflows/worker-production-backup-coordinator.yml",
                            "artifact": "subs-bot-production-backup-"},
            "rehearsal": {"child": ".github/workflows/worker-backup-phase-rehearsal.yml",
                          "parent": ".github/workflows/worker-backup-reviewed-coordinator.yml",
                          "artifact": "subs-bot-rehearsal-backup-"}}


def profile_config(profile):
    require(profile in PROFILES)
    return PROFILES[profile]


def child_title(intent):
    if intent["profile"] == "production":
        return "Production backup " + intent["action"] + " at " + intent["controllerRevision"] + " #" + intent["nonce"]
    return ("Rehearsal backup " + intent["action"] + " at " + intent["controllerRevision"]
            + " candidate " + intent["candidateRevision"] + " #" + intent["nonce"])


def parent_title(profile, action, revision, candidate_revision):
    profile_config(profile)
    require(action in {"run", "resume", "abort", "reconcile"} and REVISION.fullmatch(revision or "")
            and REVISION.fullmatch(candidate_revision or ""))
    if profile == "production":
        require(candidate_revision == revision)
        return "Production backup coordinator " + action + " at " + revision
    return "Rehearsal backup coordinator " + action + " at " + revision + " candidate " + candidate_revision


def valid_target(target):
    require(isinstance(target, str) and HEX.fullmatch(target) is not None)
    return target


def event_key(target, session, sequence):
    valid_target(target)
    require(DECIMAL.fullmatch(session or "") and type(sequence) is int and 1 <= sequence <= len(STEPS))
    return f"{BASE}{target}/{session}/{sequence:02d}-intent.json"


def receipt_key(target, session, sequence):
    return event_key(target, session, sequence).replace("-intent.json", "-receipt.json")


def result_archive_key(target, session, sequence):
    return event_key(target, session, sequence).replace("-intent.json", "-result.zip")


def child_claim_key(target, session, sequence):
    return event_key(target, session, sequence).replace("-intent.json", "-child-claim.json")


def child_claim(intent, child_run_id, child_attempt):
    require(isinstance(intent, dict) and DECIMAL.fullmatch(child_run_id or "") and child_attempt == "1")
    require(intent == dispatch_intent(target=intent.get("targetSha256"), session=intent.get("session"),
        sequence=intent.get("sequence"), revision=intent.get("controllerRevision"), nonce=intent.get("nonce"),
        input_sha256=intent.get("inputSha256"), created_at=intent.get("createdAt"), writer_run_id=intent.get("writerRunId"),
        profile=intent.get("profile"), candidate_revision=intent.get("candidateRevision")))
    return {"version": 1, "kind": "backup-dispatch-child-claim", "intentSha256": sha256(canonical(intent)).hexdigest(),
            "targetSha256": intent["targetSha256"], "session": intent["session"], "sequence": intent["sequence"],
            "nonce": intent["nonce"], "profile": intent["profile"], "controllerRevision": intent["controllerRevision"],
            "candidateRevision": intent["candidateRevision"], "childRunId": child_run_id, "childAttempt": child_attempt}


def claim_child_once(store, intent, child_run_id, child_attempt):
    """A coordinator-dispatched child acquires exactly one immutable slot."""
    value = child_claim(intent, child_run_id, child_attempt)
    key = child_claim_key(intent["targetSha256"], intent["session"], intent["sequence"])
    existing, _ = store.get(key, absent=True)
    require(existing is None, "A child already claimed this dispatch; do not retry.")
    raw = canonical(value)
    store.put_once(key, raw)
    observed, _ = store.get(key)
    require(observed == raw, "The exclusive child claim was not independently confirmed.")
    return value


def verify_child_claim(store, intent, child_run_id, child_attempt="1"):
    raw, _ = store.get(child_claim_key(intent["targetSha256"], intent["session"], intent["sequence"]))
    require(isinstance(raw, bytes) and raw == canonical(child_claim(intent, child_run_id, child_attempt)),
            "The exact exclusive child claim is missing or differs.")
    return sha256(raw).hexdigest()


def dispatch_intent(*, target, session, sequence, revision, nonce, input_sha256, created_at, writer_run_id,
                    profile="production", candidate_revision=None):
    valid_target(target)
    profile_config(profile)
    candidate_revision = revision if candidate_revision is None and profile == "production" else candidate_revision
    require(DECIMAL.fullmatch(session or "") and type(sequence) is int and 1 <= sequence <= len(STEPS)
            and REVISION.fullmatch(revision or "") and HEX.fullmatch(nonce or "") and HEX.fullmatch(input_sha256 or "")
            and REVISION.fullmatch(candidate_revision or "") and (profile != "production" or candidate_revision == revision)
            and type(created_at) is int and created_at > 0 and DECIMAL.fullmatch(writer_run_id or ""))
    return {"version": 1, "kind": "backup-dispatch-intent", "targetSha256": target,
            "session": session, "sequence": sequence, "action": STEPS[sequence - 1],
            "controllerRevision": revision, "candidateRevision": candidate_revision, "profile": profile,
            "nonce": nonce, "inputSha256": input_sha256, "createdAt": created_at,
            "writerRunId": writer_run_id, "writerAttempt": "1"}


def write_dispatch_once(store, intent):
    """Claim a single stage; callers must not dispatch unless readback succeeds."""
    require(isinstance(intent, dict) and intent == dispatch_intent(target=intent.get("targetSha256"),
        session=intent.get("session"), sequence=intent.get("sequence"), revision=intent.get("controllerRevision"),
        nonce=intent.get("nonce"), input_sha256=intent.get("inputSha256"), created_at=intent.get("createdAt"),
        writer_run_id=intent.get("writerRunId"), profile=intent.get("profile"), candidate_revision=intent.get("candidateRevision")))
    key = event_key(intent["targetSha256"], intent["session"], intent["sequence"])
    existing, _ = store.get(key, absent=True)
    require(existing is None, "A dispatch intent already exists; inspect it rather than reissue it.")
    raw = canonical(intent)
    store.put_once(key, raw)
    observed, _ = store.get(key)
    require(observed == raw, "The exact dispatch intent was not independently confirmed.")
    return sha256(raw).hexdigest()


def receipt(intent, run_id, result, artifact_id, archive_sha256):
    require(DECIMAL.fullmatch(run_id or "") and DECIMAL.fullmatch(artifact_id or "")
            and HEX.fullmatch(archive_sha256 or "") and isinstance(result, dict))
    raw = canonical(result)
    require(0 < len(raw) <= 65536)
    return {"version": 1, "kind": "backup-dispatch-receipt", "intentSha256": sha256(canonical(intent)).hexdigest(),
            "runId": run_id, "runAttempt": "1", "resultSha256": sha256(raw).hexdigest(), "result": result,
            "artifactId": artifact_id, "artifactSha256": archive_sha256}


def inspect_stage(store, target, session, sequence):
    """Only classify evidence; neither an absent receipt nor a 404 authorizes replay."""
    raw, _ = store.get(event_key(target, session, sequence), absent=True)
    result, _ = store.get(receipt_key(target, session, sequence), absent=True)
    original, _ = store.get(result_archive_key(target, session, sequence), absent=True)
    claim, _ = store.get(child_claim_key(target, session, sequence), absent=True)
    if raw is None:
        require(result is None and original is None and claim is None, "A result or claim without its dispatch intent is invalid.")
        return {"status": "not-recorded", "dispatchPermitted": False}
    intent = parsed(raw)
    require(canonical(intent) == raw and intent == dispatch_intent(target=target, session=session, sequence=sequence,
        revision=intent.get("controllerRevision"), nonce=intent.get("nonce"), input_sha256=intent.get("inputSha256"),
        created_at=intent.get("createdAt"), writer_run_id=intent.get("writerRunId"),
        profile=intent.get("profile"), candidate_revision=intent.get("candidateRevision")))
    if result is None:
        return {"status": "unknown", "intentSha256": sha256(raw).hexdigest(), "dispatchPermitted": False}
    value = parsed(result)
    require(canonical(value) == result and value == receipt(intent, value.get("runId"), value.get("result"),
                                                             value.get("artifactId"), value.get("artifactSha256"))
            and isinstance(original, bytes) and sha256(original).hexdigest() == value["artifactSha256"]
            and archive_result(original) == value["result"] and isinstance(claim, bytes)
            and claim == canonical(child_claim(intent, value["runId"], "1")))
    return {"status": "receipt-needs-independent-run-verification", "intentSha256": sha256(raw).hexdigest(),
            "runId": value["runId"], "dispatchPermitted": False}


class CoordinatorStore:
    """Give the coordinator an independent namespace in the fixed private bucket."""
    def __init__(self, objects, target):
        self.objects = objects
        self.prefix = BASE + valid_target(target) + "/coordination/"

    def _key(self, key):
        require(isinstance(key, str) and key.startswith("maintenance/production-control/")
                and not any(part in {".", ".."} for part in key.split("/")))
        return self.prefix + key

    def get(self, key, *, absent=False):
        raw, _ = self.objects.get(self._key(key), absent=absent)
        return raw

    def get_with_etag(self, key):
        return self.objects.get(self._key(key), absent=True)

    def put(self, key, body):
        self.objects.put_once(self._key(key), body)
        return sha256(body).hexdigest()

    def compare_and_put(self, key, expected_body, expected_etag, body):
        return self.objects.compare_and_put(self._key(key), expected_body, expected_etag, body)

    def _list(self, prefix):
        mapped = self._key(prefix)
        keys = self.objects.list(mapped)
        require(all(key.startswith(self.prefix) for key in keys))
        return [key[len(self.prefix):] for key in keys]

    def list_backup_anchor_history(self, target_sha256):
        require(HEX.fullmatch(target_sha256 or ""))
        return self._list("maintenance/production-control/evidence/daily-backup-anchor/" + target_sha256 + "/")

    def list_backup_journals(self):
        # Initialization cannot mistake old stage intents for a fresh ledger.
        root = BASE + self.prefix[len(BASE):].split("/", 1)[0] + "/"
        keys = self.objects.list(root)
        return [key for key in keys if "/coordination/" not in key]

    def list_backup_session(self, prefix):
        return self._list(prefix)


class ScheduleScopeAnchor(maintenance.Anchor):
    """Project-wide schedule lock, pinned to its original private ledger bucket."""

    def __init__(self, store, scope, genesis, bucket_name, bucket_created_at):
        super().__init__(store, scope, genesis)
        require(isinstance(bucket_name, str) and 1 <= len(bucket_name) <= 63
                and isinstance(bucket_created_at, str) and 1 <= len(bucket_created_at) <= 128)
        self.bucket_name, self.bucket_created_at = bucket_name, bucket_created_at

    def initial_material(self):
        initial, _unused = super().initial_material()
        genesis = canonical({"version": 1, "kind": "scheduled-backup-scope-genesis",
            "targetSha256": self.target_sha256, "initialAnchorSha256": sha256(initial).hexdigest(),
            "backupBucketName": self.bucket_name, "backupBucketCreatedAt": self.bucket_created_at})
        return initial, genesis


def coordinator_anchor_history(anchor):
    """Return every verified acquisition, without treating absence as a terminal."""
    pinned, raw, _etag = anchor.read()
    require(type(pinned.get("generation")) is int and pinned["generation"] <= 4096,
            "Coordinator history exceeds the independently verified bound.")
    current, current_raw = pinned, raw
    active, seen = [], set()
    while current["generation"] > 1:
        if current["state"] == "active":
            session = current["session"]
            require(session not in seen, "A coordinator session appears more than once in anchor history.")
            seen.add(session)
            active.append({"session": session, "day": current["day"], "controlRevision": current["controlRevision"],
                           "anchorSha256": sha256(current_raw).hexdigest(), "previousSha256": current["previousSha256"]})
        previous_sha = current["previousSha256"]
        current_raw = anchor.store.get(anchor.history_digest_key(current["generation"] - 1, previous_sha))
        require(isinstance(current_raw, bytes) and sha256(current_raw).hexdigest() == previous_sha)
        previous = parsed(current_raw)
        require(canonical(previous) == current_raw and type(previous.get("generation")) is int
                and previous["generation"] == current["generation"] - 1)
        current = previous
    final, final_raw, _etag = anchor.read()
    require(final == pinned and final_raw == raw, "The coordinator anchor changed during history inventory.")
    return list(reversed(active))


SCHEDULE_REVIEW_WORKFLOWS = (
    ".github/workflows/worker-production-backup-coordinator.yml", ".github/workflows/worker-production-backup.yml",
)


def scheduled_review_document(env):
    """Load only an independently pinned, bounded operator-reviewed list."""
    raw = env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_JSON", "")
    pin = env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_REVIEW_SHA256", "")
    review = parsed(raw)
    require(isinstance(raw, str) and canonical(review).decode() == raw
            and HEX.fullmatch(pin or "") and sha256(raw.encode()).hexdigest() == pin
            and isinstance(review, dict) and set(review) == {"version", "controllers"}
            and type(review["version"]) is int and review["version"] == 1
            and isinstance(review["controllers"], dict) and 1 <= len(review["controllers"]) <= 128)
    for key, row in review["controllers"].items():
        require(REVISION.fullmatch(key or "") and isinstance(row, dict)
                and set(row) == {"treeSha", "workflowSha256", "childWorkflowSha256", "sourceClosureSha256"}
                and REVISION.fullmatch(row.get("treeSha", ""))
                and all(HEX.fullmatch(row.get(name, "")) for name in
                        ("workflowSha256", "childWorkflowSha256", "sourceClosureSha256")))
    return review, pin


def historical_schedule_source_review(env, revision, recorded_review, source):
    """Revalidate a prior fresh reader's immutable source proof against current pins."""
    review, _pin = scheduled_review_document(env)
    require(REVISION.fullmatch(revision or "") and revision in review["controllers"]
            and isinstance(recorded_review, dict) and set(recorded_review) == {"version", "controllers"}
            and type(recorded_review.get("version")) is int and recorded_review["version"] == 1
            and isinstance(recorded_review.get("controllers"), dict)
            and recorded_review["controllers"].get(revision) == review["controllers"][revision]
            and isinstance(source, dict) and set(source) == {"revision", "treeSha", "sources", "reviewSha256"}
            and source["revision"] == revision and source["treeSha"] == review["controllers"][revision]["treeSha"]
            and source["reviewSha256"] == sha256(canonical(recorded_review)).hexdigest())
    sources = source["sources"]
    require(isinstance(sources, dict) and 2 < len(sources) <= 514
            and all(isinstance(path, str) and (path in SCHEDULE_REVIEW_WORKFLOWS
                    or re.fullmatch(r"worker/tools/[A-Za-z0-9_/-]+\.py", path)) and HEX.fullmatch(value or "")
                    for path, value in sources.items())
            and all(path in sources for path in (*SCHEDULE_REVIEW_WORKFLOWS,
                    "worker/tools/production_backup_coordinator.py", "worker/tools/production_backup_schedule.py"))
            and sha256(canonical(sources)).hexdigest() == review["controllers"][revision]["sourceClosureSha256"]
            and sources[SCHEDULE_REVIEW_WORKFLOWS[0]] == review["controllers"][revision]["workflowSha256"]
            and sources[SCHEDULE_REVIEW_WORKFLOWS[1]] == review["controllers"][revision]["childWorkflowSha256"])
    return True


def scheduled_source_review(env, revision, *, historical=False):
    """Verify the protected exact commit, full tree and reviewed source set."""
    import subprocess
    from pathlib import Path

    review, pin = scheduled_review_document(env)
    require(REVISION.fullmatch(revision or "") and revision in review["controllers"])
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink())
    def git(*arguments):
        return subprocess.run(["git", "-C", str(workspace), *arguments], check=True,
                              capture_output=True, timeout=20).stdout
    head = git("rev-parse", "--verify", "HEAD").strip().decode("ascii")
    require(head == env.get("GITHUB_SHA") and REVISION.fullmatch(head or ""))
    if historical:
        git("merge-base", "--is-ancestor", revision, head)
    else:
        require(head == revision)
    tree = git("rev-parse", "--verify", revision + "^{tree}").strip().decode("ascii")
    expected = review["controllers"][revision]
    require(tree == expected["treeSha"])
    listing = git("ls-tree", "-r", "--name-only", revision, "--", "worker/tools")
    require(len(listing) <= 1024 * 1024)
    paths = [path for path in listing.decode("utf-8").splitlines() if path.endswith(".py")]
    require(1 <= len(paths) <= 512 and len(paths) == len(set(paths))
            and all(re.fullmatch(r"worker/tools/[A-Za-z0-9_/-]+\.py", path) for path in paths)
            and "worker/tools/production_backup_schedule.py" in paths
            and "worker/tools/production_backup_coordinator.py" in paths)
    sources = {}
    for path in [*SCHEDULE_REVIEW_WORKFLOWS, *sorted(paths)]:
        size = git("cat-file", "-s", revision + ":" + path).strip()
        require(size.isdigit() and 0 < int(size) <= 1024 * 1024)
        content = git("show", revision + ":" + path)
        require(len(content) == int(size))
        sources[path] = sha256(content).hexdigest()
    require(sha256(canonical(sources)).hexdigest() == expected["sourceClosureSha256"]
            and sources[SCHEDULE_REVIEW_WORKFLOWS[0]] == expected["workflowSha256"]
            and sources[SCHEDULE_REVIEW_WORKFLOWS[1]] == expected["childWorkflowSha256"])
    return {"revision": revision, "treeSha": tree, "sources": sources, "reviewSha256": pin}


def historical_manual_source_review(env, revision):
    """Re-read an approved prior commit without importing or executing it."""
    return scheduled_source_review(env, revision, historical=True)


def scheduled_continuation(objects, slot):
    """Read the only supported continuation of an original scheduled writer."""
    target, session = valid_target(slot["targetSha256"]), slot["session"]
    require(DECIMAL.fullmatch(session or ""))
    prefix = BASE + target + "/" + session + "/writers/"
    key = prefix + "0001.json"
    keys = objects.list(prefix, maximum=2)
    require(keys in ([], [key]), "A scheduled continuation has unexpected writer evidence.")
    if not keys:
        return None
    raw, _ = objects.get(key)
    value = parsed(raw)
    require(isinstance(value, dict) and canonical(value) == raw and value == {
        "version": 1, "kind": "scheduled-backup-continuation", "slotSha256": sha256(canonical(slot)).hexdigest(),
        "writerRunId": value.get("writerRunId"), "writerAttempt": "1", "firstSequence": value.get("firstSequence"),
        "planSha256": value.get("planSha256")}
        and type(value["version"]) is int and DECIMAL.fullmatch(value["writerRunId"] or "")
        and value["writerRunId"] != slot["writerRunId"] and HEX.fullmatch(value["planSha256"] or "")
        and type(value["firstSequence"]) is int and 1 <= value["firstSequence"] <= len(STEPS) + 1)
    return value


def scheduled_writer_id(slot, continuation, sequence):
    require(type(sequence) is int and 1 <= sequence <= len(STEPS))
    if continuation is not None and sequence >= continuation["firstSequence"]:
        return continuation["writerRunId"]
    return slot["writerRunId"]


def scheduled_run_identity(run, run_id, revision, *, continuation=False):
    path = PROFILES["production"]["parent"]
    action = "resume-scheduled" if continuation else "scheduled-run"
    require(isinstance(run, dict) and str(run.get("id")) == run_id and run.get("run_attempt") == 1
            and run.get("head_sha") == revision and run.get("head_branch") == "main"
            and run.get("event") == ("workflow_dispatch" if continuation else "schedule")
            and run.get("path") in {path, path + "@main", path + "@refs/heads/main"}
            and run.get("display_title") == "Production backup coordinator " + action + " at " + revision
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")), "The scheduled writer identity differs.")


def stopped_scheduled_writer(slot, token):
    revision, run_id = slot["authority"]["controlRevision"], slot["writerRunId"]
    original = artifact._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = artifact._get_json("/actions/runs/" + run_id, token)
    for run in (original, latest):
        scheduled_run_identity(run, run_id, revision)
        require(run.get("status") == "completed" and run.get("conclusion") in
                {"success", "failure", "cancelled", "timed_out"}, "The original scheduled writer is not confirmed stopped.")
    require(original["conclusion"] == latest["conclusion"])
    return original


def verify_scheduled_parent(env, slot, mode="finished", *, continuation=None):
    """Read the exact scheduled coordinator and independent reader job from GitHub."""
    require(mode in {"fresh-reader", "finished"} and isinstance(slot, dict)
            and DECIMAL.fullmatch(slot.get("writerRunId", "")) and slot.get("writerAttempt") == "1"
            and slot.get("session") == slot["writerRunId"] and isinstance(slot.get("authority"), dict))
    revision = slot["authority"].get("controlRevision", "")
    require(REVISION.fullmatch(revision or "") and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("RUNNER_ENVIRONMENT") == "github-hosted")
    event = "schedule" if continuation is None else "workflow_dispatch"
    token = artifact._github_token()
    run_id = slot["writerRunId"] if continuation is None else continuation["writerRunId"]
    if mode == "fresh-reader":
        require(env.get("GITHUB_SHA") == revision and env.get("GITHUB_RUN_ID") == run_id
                and env.get("GITHUB_RUN_ATTEMPT") == "1" and env.get("GITHUB_EVENT_NAME") == event
                and env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/" + PROFILES["production"]["parent"] + "@" + artifact.MAIN_REF)
    prior = None if continuation is None else stopped_scheduled_writer(slot, token)
    original = artifact._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = artifact._get_json("/actions/runs/" + run_id, token)
    for run in (original, latest):
        scheduled_run_identity(run, run_id, revision, continuation=continuation is not None)
        require(run.get("status") == ("in_progress" if mode == "fresh-reader" else "completed"))
        if mode == "finished":
            require(run.get("conclusion") == "success")
    response = artifact._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100
            and len({job.get("id") for job in jobs if isinstance(job, dict)}) == len(jobs))
    def exact_job(name, *, running, steps):
        found = [job for job in jobs if isinstance(job, dict) and job.get("name") == name]
        require(len(found) == 1)
        job = found[0]
        require(type(job.get("id")) is int and job["id"] > 0 and str(job.get("run_id")) == run_id
                and job.get("run_attempt") == 1 and job.get("head_sha") == revision
                and job.get("status") == ("in_progress" if running else "completed")
                and job.get("conclusion") == (None if running else "success")
                and isinstance(job.get("steps"), list))
        for name, in_progress in steps:
            matching = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == name]
            require(len(matching) == 1 and (matching[0].get("status"), matching[0].get("conclusion")) ==
                    (("in_progress", None) if in_progress else ("completed", "success")))
        return job
    coordinate = exact_job("coordinate", running=False, steps=[
        ("Check scheduled authority switch", False), ("Check out trusted current main", False),
        ("Verify scheduled dispatcher identity", False), ("Coordinate one explicitly approved operation", False)])
    reader = exact_job("schedule_readback", running=mode == "fresh-reader", steps=[
        ("Check out trusted current main", False),
        ("Independently verify completed scheduled backup", mode == "fresh-reader")])
    result = {"originalRun": original, "latestRun": latest, "jobs": response,
              "coordinateJobId": coordinate["id"], "readerJobId": reader["id"]}
    if continuation is not None:
        result.update(continuation=continuation, stoppedOriginalRun=prior)
    return result


def require_completed_receipt(intent, value, run, workflow_id, result):
    """Authenticate an exact dispatch before any later checkpoint can run."""
    require(isinstance(intent, dict) and isinstance(value, dict) and isinstance(run, dict) and isinstance(result, dict))
    require(value == receipt(intent, str(run.get("id")), result, value.get("artifactId"), value.get("artifactSha256")))
    expected = child_title(intent)
    require(run.get("display_title") == expected and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow_id and run.get("head_branch") == "main"
            and run.get("head_sha") == intent["controllerRevision"] and run.get("event") == "workflow_dispatch"
            and (run.get("status"), run.get("conclusion")) == ("completed", "success")
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")),
            "The unique original checkpoint run did not finish successfully.")
    require(result.get("action") == intent["action"] and result.get("targetSha256") == intent["targetSha256"]
            and result.get("controlRevision") == intent["candidateRevision"]
            and (intent["profile"] == "production" or result.get("dispatcherRevision") == intent["controllerRevision"])
            and result.get("consumerSwitch") == "not-authorized" and result.get("automaticReplay") is False)
    return True


def matching_run(rows, intent, workflow_id):
    """Find only the unique nonce-bound run; absence or ambiguity is not success."""
    require(isinstance(rows, list) and type(workflow_id) is int)
    title = child_title(intent)
    matches = [row for row in rows if isinstance(row, dict) and row.get("display_title") == title]
    require(len(matches) == 1, "The unique dispatched run is unavailable or ambiguous.")
    run = matches[0]
    require(type(run.get("id")) is int and run["id"] > 0 and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow_id and run.get("head_sha") == intent["controllerRevision"]
            and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and all(isinstance(run.get(k), dict) and run[k].get("id") == artifact.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    return run


def dispatch_once(token, intent, inputs, store):
    """Persist an exclusive intent then make exactly one workflow-dispatch POST."""
    import json
    from urllib.request import Request
    require(isinstance(inputs, dict) and inputs.get("action") == intent["action"]
            and inputs.get("dispatch_nonce") == intent["nonce"]
            and sha256(canonical(inputs)).hexdigest() == intent["inputSha256"])
    write_dispatch_once(store, intent)
    artifact.require_current_main(intent["controllerRevision"])
    body = json.dumps({"ref": "main", "inputs": inputs}, separators=(",", ":")).encode("utf-8")
    request = Request(artifact.API_ROOT + "/actions/workflows/" + profile_config(intent["profile"])["child"].rsplit("/", 1)[-1] + "/dispatches", data=body,
                      headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                               "Content-Type": "application/json", "X-GitHub-Api-Version": "2022-11-28"}, method="POST")
    # No retries: an exception or non-204 response is an unknown dispatch and
    # leaves the immutable intent as the reconciliation barrier.
    with artifact._OPENER.open(request, timeout=30) as response:
        require(response.status == 204 and not response.read(1), "The dispatch outcome is not confirmed.")


def selected_result(run_id, revision, action, token, *, profile="production"):
    """Read one bounded GitHub artifact tied to the successful original run."""
    require(DECIMAL.fullmatch(run_id or "") and REVISION.fullmatch(revision or "") and action in STEPS)
    listing = artifact._get_json("/actions/runs/" + run_id + "/artifacts?per_page=100", token)
    entries = listing.get("artifacts")
    require(isinstance(entries, list) and type(listing.get("total_count")) is int
            and listing["total_count"] == len(entries) < 100)
    name = profile_config(profile)["artifact"] + action + "-" + run_id + "-1"
    selected = [item for item in entries if isinstance(item, dict) and item.get("name") == name]
    require(len(selected) == 1)
    item = selected[0]
    source = item.get("workflow_run")
    sha = item.get("digest", "")
    require(type(item.get("id")) is int and item["id"] > 0 and item.get("expired") is False
            and type(item.get("size_in_bytes")) is int and 0 < item["size_in_bytes"] <= 2 * 1024 * 1024
            and isinstance(sha, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", sha)
            and isinstance(source, dict) and str(source.get("id")) == run_id and source.get("head_sha") == revision
            and source.get("head_branch") == "main" and source.get("repository_id") == artifact.REPOSITORY_ID
            and source.get("head_repository_id") == artifact.REPOSITORY_ID)
    raw = artifact._download(str(item["id"]), token)
    require(sha256(raw).hexdigest() == sha[7:])
    return archive_result(raw), {"artifactId": str(item["id"]), "artifactSha256": sha[7:]}, raw


def archive_result(raw):
    """Validate a retained original result archive without GitHub artifact access."""
    from io import BytesIO
    from zipfile import ZipFile
    require(isinstance(raw, bytes) and 0 < len(raw) <= 2 * 1024 * 1024)
    with ZipFile(BytesIO(raw)) as archive:
        members = archive.infolist()
        require(len(members) == 1 and members[0].filename == "production-backup-result.json"
                and members[0].filename == members[0].orig_filename and members[0].file_size <= 65536
                and not members[0].is_dir() and not members[0].flag_bits & (1 | 64))
        body = archive.read(members[0])
    value = parsed(body)
    require(canonical(value) == body and isinstance(value, dict))
    return value


def next_inputs(results, *, source_checkpoint_id, source_manifest_sha256):
    """Derive only the next fixed checkpoint from verified preceding results."""
    require(isinstance(results, list) and len(results) < len(STEPS)
            and all(isinstance(value, dict) and value.get("action") == STEPS[i] for i, value in enumerate(results))
            and re.fullmatch(r"[a-f0-9]{32}", source_checkpoint_id or "")
            and HEX.fullmatch(source_manifest_sha256 or ""))
    expected = {"plan-begin": "plan-only", "begin": "started", "preflight": "observed", "pause": "paused",
                "drain": "drained", "freeze": "frozen", "capture": "captured-unverified", "verify": "verified",
                "activate": "resumed"}
    require(all(value.get("status") == expected[value["action"]] for value in results if value["action"] in expected),
            "A prior checkpoint did not reach its expected terminal result.")
    action = STEPS[len(results)]
    inputs = {"action": action, "source_checkpoint_id": source_checkpoint_id, "source_manifest_sha256": source_manifest_sha256}
    if results:
        first = results[0]
        require(first.get("status") == "plan-only" and re.fullmatch(r"[1-9][0-9]{0,19}-1", first.get("session", ""))
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", first.get("day", "")))
        inputs.update(session=first["session"], session_day=first["day"])
    predecessor_index = {"begin": 0, "preflight": 0, "pause": 3, "freeze": 5,
                         "capture": 6, "verify": 6, "activate": 9}.get(action)
    if predecessor_index is not None:
        predecessor = results[predecessor_index].get("stateSha256", "")
        require(HEX.fullmatch(predecessor or ""), "The exact predecessor was not returned by its plan.")
        inputs["state_sha256"] = predecessor
    return inputs


def stage_inputs(results, source_checkpoint_id, source_manifest_sha256, session, intent, pause_limit, pause_until, *, validation_json=None):
    """Reconstruct the exact input digest from verified predecessors."""
    require(intent["sequence"] == len(results) + 1 and intent["action"] == STEPS[len(results)])
    if intent["action"] == "pause":
        pause_until = pause_deadline(intent, pause_limit, now=int(__import__("time").time()))
    inputs = next_inputs(results, source_checkpoint_id=source_checkpoint_id, source_manifest_sha256=source_manifest_sha256)
    inputs.update(dispatch_nonce=intent["nonce"], coordinator_session=session,
                  dispatch_deadline=str(pause_until or 0))
    if intent["profile"] == "rehearsal":
        require(isinstance(validation_json, str) and 0 < len(validation_json) <= 16384)
        inputs["validation_json"] = validation_json
    else:
        require(validation_json is None)
    return inputs, pause_until


def completed_results(store, target, session, revision, token, source_checkpoint_id, source_manifest_sha256, pause_limit, *,
                      stop_before=None, profile="production", candidate_revision=None, validation_json=None, fresh_client=None):
    """Revalidate the complete ordered receipt chain against GitHub and original artifacts."""
    child = profile_config(profile)["child"]
    candidate_revision = revision if candidate_revision is None and profile == "production" else candidate_revision
    require(REVISION.fullmatch(candidate_revision or ""))
    if fresh_client is not None:
        from production_backup_fresh_github import FreshConditionalJSON
        require(type(fresh_client) is FreshConditionalJSON and profile == "production")
    workflow = artifact._get_json("/actions/workflows/" + child.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == child and type(workflow.get("id")) is int)
    values, pause_until = [], None
    for sequence in range(1, len(STEPS) + 1):
        if stop_before is not None and sequence == stop_before:
            break
        status = inspect_stage(store, target, session, sequence)
        if status["status"] == "not-recorded":
            # No later stage can be silently skipped or adopted.
            require(all(inspect_stage(store, target, session, later)["status"] == "not-recorded"
                        for later in range(sequence + 1, len(STEPS) + 1)))
            break
        require(status["status"] == "receipt-needs-independent-run-verification",
                "An earlier dispatch is unknown; inspect and explicitly reconcile it without reissuing.")
        raw, _ = store.get(event_key(target, session, sequence))
        raw_receipt, _ = store.get(receipt_key(target, session, sequence))
        intent, proof = parsed(raw), parsed(raw_receipt)
        require(intent["controllerRevision"] == revision and intent["candidateRevision"] == candidate_revision and intent["profile"] == profile)
        inputs, pause_until = stage_inputs(values, source_checkpoint_id, source_manifest_sha256, session, intent, pause_limit,
                                           pause_until, validation_json=validation_json)
        require(sha256(canonical(inputs)).hexdigest() == intent["inputSha256"],
                "The dispatched inputs do not match verified predecessor results.")
        original_path = "/actions/runs/" + status["runId"] + "/attempts/1"
        latest_path = "/actions/runs/" + status["runId"]
        if fresh_client is None:
            run = artifact._get_json(original_path, token)
            latest = artifact._get_json(latest_path, token)
            require(str(latest.get("id")) == status["runId"] and latest.get("run_attempt") == 1
                    and latest.get("status") == "completed", "A later checkpoint attempt requires reconciliation.")
        result = proof.get("result")
        original, _ = store.get(result_archive_key(target, session, sequence))
        require(isinstance(original, bytes) and sha256(original).hexdigest() == proof.get("artifactSha256")
                and archive_result(original) == result, "The privately retained original checkpoint result differs.")
        def verify_original(value):
            require_completed_receipt(intent, proof, value, workflow["id"], result)
            return True
        def verify_latest(value):
            require(str(value.get("id")) == status["runId"] and value.get("run_attempt") == 1
                    and value.get("status") == "completed" and value.get("conclusion") == "success"
                    and value.get("head_sha") == revision,
                    "A later or changed checkpoint attempt requires reconciliation.")
            return True
        if fresh_client is not None:
            run = fresh_client.get(original_path, verify=verify_original)
            fresh_client.get(latest_path, verify=verify_latest)
        require_completed_receipt(intent, proof, run, workflow["id"], result)
        values.append(result)
    return values, pause_until


def verified_plan_begin(store, target, session, revision, token, source_checkpoint_id, source_manifest_sha256,
                        pause_limit, *, profile, candidate_revision, validation_json):
    """Recheck the original plan receipt and GitHub run before a child begin."""
    values, _ = completed_results(store, target, session, revision, token, source_checkpoint_id,
                                  source_manifest_sha256, pause_limit, stop_before=2, profile=profile,
                                  candidate_revision=candidate_revision, validation_json=validation_json)
    require(len(values) == 1 and values[0].get("action") == "plan-begin" and values[0].get("status") == "plan-only")
    raw, _ = store.get(receipt_key(target, session, 1))
    proof = parsed(raw)
    require(canonical(proof) == raw and values[0].get("session") == proof["runId"] + "-1")
    return {"result": values[0], "runId": proof["runId"]}


def confirm_stage(store, intent, run, workflow_id, result, source, original):
    """Record a verified completion exactly once; a prior receipt is never replaced."""
    key = receipt_key(intent["targetSha256"], intent["session"], intent["sequence"])
    existing, _ = store.get(key, absent=True)
    require(existing is None, "An existing receipt requires independent inspection.")
    require(isinstance(source, dict) and set(source) == {"artifactId", "artifactSha256"}
            and isinstance(original, bytes) and sha256(original).hexdigest() == source["artifactSha256"]
            and archive_result(original) == result)
    proof = receipt(intent, str(run.get("id")), result, source["artifactId"], source["artifactSha256"])
    require_completed_receipt(intent, proof, run, workflow_id, result)
    verify_child_claim(store, intent, str(run.get("id")))
    original_key = result_archive_key(intent["targetSha256"], intent["session"], intent["sequence"])
    saved, _ = store.get(original_key, absent=True)
    if saved is None:
        store.put_once(original_key, original)
        saved, _ = store.get(original_key)
    require(saved == original, "The original checkpoint result was not independently retained.")
    raw = canonical(proof)
    store.put_once(key, raw)
    observed, _ = store.get(key)
    require(observed == raw)
    return proof


def verify_context(env):
    """Only a separately protected main dispatcher can use the coordinator."""
    workflow = artifact.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF
    revision = env.get("GITHUB_SHA", "")
    require(env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_WORKFLOW_REF") == workflow
            and env.get("GITHUB_EVENT_NAME") in {"workflow_dispatch", "schedule"}
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("SUBS_BOT_CONTROL_ENVIRONMENT") == "subs-bot-production-backup-coordinator"
            and REVISION.fullmatch(revision or "") and DECIMAL.fullmatch(env.get("GITHUB_RUN_ID", "")))
    artifact.require_current_main(revision)
    return revision


def finished_controller(objects, target, session, revision, source_checkpoint, source_sha, policy_sha, *,
                        profile="production", candidate_revision=None, validation_sha=None, current_writer=None, current_mode=None,
                        scheduled_authority=None, scheduled_authority_sha256=None):
    parent_path = profile_config(profile)["parent"]
    candidate_revision = revision if candidate_revision is None and profile == "production" else candidate_revision
    require(REVISION.fullmatch(candidate_revision or "") and (profile != "production" or candidate_revision == revision)
            and (validation_sha is None if profile == "production" else HEX.fullmatch(validation_sha or ""))
            and ((current_writer is None and current_mode is None) or
                 (profile == "rehearsal" and isinstance(current_writer, dict) and current_mode in {"execute", "readback"})))
    raw, _ = objects.get(BASE + target + "/" + session + "/start-intent.json")
    start = parsed(raw)
    start_fields = {"version", "action", "targetSha256", "controlRevision", "session",
            "sourceCheckpointId", "sourceManifestSha256", "anchorSha256", "policySha256", "writerRunId", "writerAttempt",
            "profile", "candidateRevision", "validationSha256"}
    scheduled_fields = {"authoritySha256", "slotDay", "slotSha256", "scopePredecessorSha256"}
    is_scheduled = isinstance(start, dict) and set(start) == start_fields | scheduled_fields
    require(canonical(start) == raw and set(start) == (start_fields | scheduled_fields if is_scheduled else start_fields)
            and type(start.get("version")) is int and start.get("version") == 1 and start.get("action") == "run"
            and HEX.fullmatch(start.get("anchorSha256", "")) and start.get("targetSha256") == target and start.get("session") == session
            and start.get("sourceCheckpointId") == source_checkpoint and start.get("sourceManifestSha256") == source_sha
            and start.get("controlRevision") == revision and start.get("policySha256") == policy_sha
            and start.get("profile") == profile and start.get("candidateRevision") == candidate_revision
            and start.get("validationSha256") == validation_sha
            and DECIMAL.fullmatch(start.get("writerRunId", ""))
            and start.get("writerAttempt") == "1")
    if is_scheduled:
        import production_backup_schedule as scheduled
        require(profile == "production" and isinstance(scheduled_authority, dict)
                and HEX.fullmatch(scheduled_authority_sha256 or "")
                and start["authoritySha256"] == scheduled_authority_sha256
                and start["writerRunId"] == session
                and scheduled_authority.get("targetSha256") == target
                and scheduled_authority.get("controlRevision") == revision
                and scheduled_authority.get("sourceCheckpointId") == source_checkpoint
                and scheduled_authority.get("sourceManifestSha256") == source_sha
                and scheduled_authority.get("policySha256") == policy_sha)
        slot_raw, _ = objects.get(scheduled.slot_key(scheduled_authority["scopeSha256"], start["slotDay"]))
        slot = parsed(slot_raw)
        require(canonical(slot) == slot_raw and start["slotSha256"] == sha256(slot_raw).hexdigest()
                and scheduled.read_slot(objects, scheduled_authority, scheduled_authority_sha256,
                                        start["slotDay"], slot) == start["slotSha256"]
                and slot["session"] == session and slot["writerRunId"] == start["writerRunId"])
    else:
        require(scheduled_authority is None and scheduled_authority_sha256 is None,
                "A manual coordinator cannot use scheduled authority.")
    run = artifact._get_json("/actions/runs/" + start["writerRunId"] + "/attempts/1", artifact._github_token())
    path = parent_path
    require(str(run.get("id")) == start["writerRunId"] and run.get("head_sha") == revision
            and run.get("path") in {path, path + "@main", path + "@refs/heads/main"}
            and run.get("display_title") == ("Production backup coordinator scheduled-run at " + revision
                if is_scheduled else parent_title(profile, "run", revision, candidate_revision))
            and run.get("event") == ("schedule" if is_scheduled else "workflow_dispatch") and run.get("head_branch") == "main"
            and run.get("status") == "completed" and run.get("run_attempt") == 1
            and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                    for key in ("repository", "head_repository")), "The original coordinator run is not confirmed stopped.")
    latest = artifact._get_json("/actions/runs/" + start["writerRunId"], artifact._github_token())
    require(str(latest.get("id")) == start["writerRunId"] and latest.get("run_attempt") == 1
            and latest.get("status") == "completed", "A later coordinator run attempt requires independent reconciliation.")
    prefix = BASE + target + "/" + session + "/writers/"
    keys = objects.list(prefix, maximum=128)
    require(len(keys) < 128)
    previous, writers, current_seen = sha256(raw).hexdigest(), [], False
    for position, key in enumerate(keys, 1):
        require(key == prefix + str(position).zfill(4) + ".json")
        body, _ = objects.get(key)
        value = parsed(body)
        fields = {"version", "targetSha256", "session", "controlRevision", "position", "previousSha256",
                  "writerRunId", "writerAttempt", "action", "profile", "candidateRevision"}
        if value.get("action") == "recovery":
            fields |= {"recoveryAction", "recoveryPlanSha256"}
        require(canonical(value) == body and set(value) == fields
                and type(value["version"]) is int and value["version"] == 1 and value["targetSha256"] == target and value["session"] == session
                and value["controlRevision"] == revision and value["position"] == position
                and value["profile"] == profile and value["candidateRevision"] == candidate_revision
                and value["action"] in {"resume", "abort", "reconcile", "recovery"}
                and (value["action"] != "recovery" or profile == "rehearsal"
                     and value.get("recoveryAction") in {"resume-failed", "reconcile-transition", "abort-unstarted"}
                     and HEX.fullmatch(value.get("recoveryPlanSha256", "")))
                and value["previousSha256"] == previous and DECIMAL.fullmatch(value["writerRunId"] or "")
                and value["writerAttempt"] == "1")
        is_current = current_writer is not None and value == current_writer
        if is_current:
            require(not current_seen and position == len(keys) and value["action"] == "recovery"
                    and value["writerRunId"] == os.environ.get("GITHUB_RUN_ID") and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                    and os.environ.get("GITHUB_SHA") == revision and os.environ.get("BACKUP_ACTION") == value["recoveryAction"]
                    and os.environ.get("BACKUP_RECOVERY_PLAN_SHA256") == value["recoveryPlanSha256"]
                    and os.environ.get("BACKUP_GATE_ROLE") == ("recovery" if current_mode == "execute" else "recovery-readback")
                    and (current_mode == "execute" or os.environ.get("BACKUP_RECOVERY_MODE") == "readback")
                    and os.environ.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/.github/workflows/worker-backup-phase-recovery.yml@" + artifact.MAIN_REF)
            current_seen = True
        observed = artifact._get_json("/actions/runs/" + value["writerRunId"] + "/attempts/1", artifact._github_token())
        recovery_path = ".github/workflows/worker-backup-phase-recovery.yml"
        writer_path = recovery_path if value["action"] == "recovery" else path
        title = ("Rehearsal backup recovery " + value["recoveryAction"] + " at " + revision + " candidate " + candidate_revision
                 + " session " + session) if value["action"] == "recovery" else parent_title(profile, value["action"], revision, candidate_revision)
        require(str(observed.get("id")) == value["writerRunId"] and observed.get("head_sha") == revision
                and observed.get("path") in {writer_path, writer_path + "@main", writer_path + "@refs/heads/main"}
                and observed.get("display_title") == title
                and observed.get("event") == "workflow_dispatch" and observed.get("head_branch") == "main"
                and observed.get("status") == ("in_progress" if is_current else "completed") and observed.get("run_attempt") == 1
                and all(isinstance(observed.get(k), dict) and observed[k].get("id") == artifact.REPOSITORY_ID
                        for k in ("repository", "head_repository")), "A prior coordinator writer has not finished.")
        if value["action"] == "recovery":
            jobs = artifact._get_json("/actions/runs/" + value["writerRunId"] + "/attempts/1/jobs?per_page=100", artifact._github_token())
            require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
                    and jobs["total_count"] == len(jobs["jobs"]) < 100)
            matching = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "recovery"]
            require(len(matching) == 1 and str(matching[0].get("run_id")) == value["writerRunId"]
                    and matching[0].get("run_attempt") == 1 and matching[0].get("head_sha") == revision
                    and matching[0].get("status") == ("in_progress" if is_current and current_mode == "execute" else "completed")
                    and (not is_current or current_mode != "readback" or matching[0].get("conclusion") == "success")
                    and isinstance(matching[0].get("steps"), list))
            for name in ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                         "Verify isolated recovery test Bot identity", "Plan or execute one reviewed recovery phase"):
                steps = [step for step in matching[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
                executing = is_current and current_mode == "execute" and name == "Plan or execute one reviewed recovery phase"
                require(len(steps) == 1)
                if is_current:
                    require((steps[0].get("status"), steps[0].get("conclusion")) ==
                            (("in_progress", None) if executing else ("completed", "success")))
                else:
                    require(steps[0].get("status") == "completed" and
                            (steps[0].get("conclusion") in {"success", "failure", "cancelled", "timed_out"}
                             if name == "Plan or execute one reviewed recovery phase" else steps[0].get("conclusion") == "success"))
            if is_current and current_mode == "readback":
                readers = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "readback"]
                require(len(readers) == 1 and str(readers[0].get("run_id")) == value["writerRunId"]
                        and readers[0].get("run_attempt") == 1 and readers[0].get("head_sha") == revision
                        and readers[0].get("status") == "in_progress" and isinstance(readers[0].get("steps"), list))
                for name in ("Verify recovery readback identity before candidate checkout", "Verify exact reviewed recovery readback checkout",
                             "Verify recovery readback test Bot identity", "Independently read back the recovery evidence"):
                    steps = [step for step in readers[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
                    require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) ==
                            (("in_progress", None) if name == "Independently read back the recovery evidence" else ("completed", "success")))
        latest = artifact._get_json("/actions/runs/" + value["writerRunId"], artifact._github_token())
        require(str(latest.get("id")) == value["writerRunId"] and latest.get("run_attempt") == 1
                and latest.get("status") == ("in_progress" if is_current else "completed"), "A later coordinator run attempt requires independent reconciliation.")
        previous = sha256(body).hexdigest()
        writers.append(value)
    require(current_writer is None or current_seen, "The exact current recovery writer is missing from the complete chain.")
    return {"startSha256": sha256(raw).hexdigest(), "lastSha256": previous, "writers": writers}


def claim_resume_writer(objects, target, session, revision, history, run_id, *, action="resume",
                        profile="production", candidate_revision=None, recovery_action=None, recovery_plan_sha=None):
    """A single immutable slot serializes concurrent continuation attempts."""
    profile_config(profile)
    candidate_revision = revision if candidate_revision is None and profile == "production" else candidate_revision
    require(REVISION.fullmatch(candidate_revision or "") and (profile != "production" or candidate_revision == revision)
            and action in {"resume", "abort", "reconcile", "recovery"} and DECIMAL.fullmatch(run_id or "") and isinstance(history, dict) and isinstance(history.get("writers"), list)
            and (action == "recovery" and profile == "rehearsal" and recovery_action in {"resume-failed", "reconcile-transition", "abort-unstarted"}
                 and HEX.fullmatch(recovery_plan_sha or "") or action != "recovery" and recovery_action is None and recovery_plan_sha is None)
            and len(history["writers"]) < 127 and HEX.fullmatch(history.get("lastSha256", "")))
    position = len(history["writers"]) + 1
    value = {"version": 1, "targetSha256": target, "session": session, "controlRevision": revision,
             "position": position, "previousSha256": history["lastSha256"], "writerRunId": run_id, "writerAttempt": "1",
             "action": action, "profile": profile, "candidateRevision": candidate_revision}
    if action == "recovery":
        value.update(recoveryAction=recovery_action, recoveryPlanSha256=recovery_plan_sha)
    key = BASE + target + "/" + session + "/writers/" + str(position).zfill(4) + ".json"
    existing, _ = objects.get(key, absent=True)
    require(existing is None, "A continuation writer already owns this slot.")
    raw = canonical(value)
    objects.put_once(key, raw)
    observed, _ = objects.get(key)
    require(observed == raw, "The continuation claim was not independently confirmed.")
    return value


def abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha, pause_limit, genesis, *,
                      profile="production", candidate_revision=None, validation_json=None):
    """Only abandon coordination after all child runs and application state are known."""
    import production_backup_transaction as maintenance
    child = profile_config(profile)["child"]
    candidate_revision = revision if candidate_revision is None and profile == "production" else candidate_revision
    require(REVISION.fullmatch(candidate_revision or "") and (profile != "production" or candidate_revision == revision))
    token = artifact._github_token()
    workflow = artifact._get_json("/actions/workflows/" + child.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == child and type(workflow.get("id")) is int)
    verified, children, pause_until, stopped = [], [], None, False
    for sequence in range(1, len(STEPS) + 1):
        status = inspect_stage(objects, target.digest, session, sequence)
        if status["status"] == "not-recorded":
            require(all(inspect_stage(objects, target.digest, session, later)["status"] == "not-recorded"
                        for later in range(sequence + 1, len(STEPS) + 1)))
            break
        require(not stopped, "A later child exists after an unresolved result.")
        raw, _ = objects.get(event_key(target.digest, session, sequence))
        intent = parsed(raw)
        require(intent["controllerRevision"] == revision and intent["candidateRevision"] == candidate_revision and intent["profile"] == profile)
        inputs, pause_until = stage_inputs(verified, source_checkpoint, source_sha, session, intent, pause_limit,
                                           pause_until, validation_json=validation_json)
        require(sha256(canonical(inputs)).hexdigest() == intent["inputSha256"])
        run = discover_run(intent, workflow["id"], token)
        require(run.get("status") == "completed" and isinstance(run.get("conclusion"), str),
                "A dispatched child is not independently confirmed stopped.")
        children.append({"sequence": sequence, "runId": str(run["id"]), "conclusion": run["conclusion"],
                         "intentSha256": sha256(raw).hexdigest()})
        if status["status"] == "unknown":
            stopped = True
        else:
            body, _ = objects.get(receipt_key(target.digest, session, sequence))
            proof = parsed(body)
            result = proof.get("result")
            original, _ = objects.get(result_archive_key(target.digest, session, sequence))
            require(isinstance(original, bytes) and sha256(original).hexdigest() == proof.get("artifactSha256")
                    and archive_result(original) == result)
            require_completed_receipt(intent, proof, run, workflow["id"], result)
            verified.append(result)
    pin, raw_pin, _ = maintenance.Anchor(app_store, target.digest, genesis).read()
    require(pin["state"] == "idle", "The application backup anchor must first reach a confirmed safe terminal state.")
    terminal = "no-mutating-child"
    if len(children) > 1:
        require(verified and verified[0].get("action") == "plan-begin")
        first = verified[0]
        require(pin["session"] == first["session"] and pin["day"] == first["day"]
                and pin["controlRevision"] == candidate_revision)
        events = maintenance.Transaction(app_store, pin["session"], pin["day"], target.digest, candidate_revision).load()
        require(events and (events[-1]["stage"] in {"resumed", "preserved-frozen"}
                or (events[-1]["stage"] == "failed" and len(events) >= 2
                    and events[-2]["stage"] in {"started", "preflight"}
                    and events[-1]["details"].get("uncertain") is False)),
                "The application transaction lacks a confirmed safe terminal state.")
        terminal = events[-1]["stage"]
    return {"children": children, "applicationAnchorSha256": sha256(raw_pin).hexdigest(), "terminal": terminal}


def discover_run(intent, workflow_id, token):
    from urllib.parse import urlencode
    from datetime import datetime, timedelta, timezone
    # A child can only belong to this one-shot dispatch if its creation falls
    # near the immutable intent. The bounded 24-hour window avoids making an
    # hourly monitor's entire lifetime history a prerequisite. Anything outside
    # it remains unknown and cannot be re-dispatched automatically.
    created = datetime.fromtimestamp(intent["createdAt"], tz=timezone.utc)
    start = (created - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    end = (created + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    rows, total, seen = [], None, set()
    for page in range(1, 12):
        query = urlencode({"branch": "main", "created": start + ".." + end, "per_page": 50, "page": page})
        child = profile_config(intent["profile"])["child"].rsplit("/", 1)[-1]
        response = artifact._get_json("/actions/workflows/" + child + "/runs?" + query, token)
        batch, count = response.get("workflow_runs"), response.get("total_count")
        require(isinstance(batch, list) and len(batch) <= 50 and type(count) is int and 0 <= count <= 500
                and (total is None or total == count))
        for row in batch:
            require(isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                    and row["id"] not in seen and isinstance(row.get("created_at"), str))
            seen.add(row["id"])
            try:
                timestamp = datetime.strptime(row["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            except ValueError:
                require(False, "A checkpoint run has an invalid creation timestamp.")
            require(created - timedelta(minutes=2) <= timestamp <= created + timedelta(hours=24),
                    "The checkpoint run inventory did not honor its bounded creation window.")
        total = count
        rows.extend(batch)
        require(len(rows) <= total)
        if len(rows) == total:
            return matching_run(rows, intent, workflow_id)
        require(len(batch) == 50)
    require(False, "The complete checkpoint workflow history could not be enumerated.")


def wait_for_run(intent, token, *, deadline, pause_alarm_at=None):
    import time
    child = profile_config(intent["profile"])["child"]
    workflow = artifact._get_json("/actions/workflows/" + child.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == child and type(workflow.get("id")) is int)
    pause_reported = False
    run_id = None
    while time.monotonic() < deadline:
        if pause_alarm_at is not None and not pause_reported and int(time.time()) >= pause_alarm_at:
            print("::warning::The configured alert interval elapsed since pause dispatch; independently observe actual admission and continue only verified recovery steps.", flush=True)
            pause_reported = True
        try:
            if run_id is None:
                run = discover_run(intent, workflow["id"], token)
                run_id = run["id"]
            else:
                live = artifact._get_json("/actions/runs/" + str(run_id), token)
                run = matching_run([live], intent, workflow["id"])
                require(run["id"] == run_id)
        except Exception:
            # An unavailable or ambiguous run never authorizes a second POST.
            time.sleep(15)
            continue
        if run.get("status") == "completed":
            require(run.get("conclusion") == "success", "The dispatched checkpoint did not complete successfully.")
            original = discover_run(intent, workflow["id"], token)
            require(original["id"] == run_id and (original.get("status"), original.get("conclusion")) == ("completed", "success"))
            return original, workflow["id"]
        require(run.get("status") in {"queued", "in_progress", "waiting", "pending", "requested"})
        time.sleep(15)
    print("::error::A backup checkpoint did not complete within its allowed window; inspect its private intent before any recovery.", flush=True)
    require(False, "The checkpoint did not complete within the coordinator window; inspect its immutable intent.")


def pause_deadline(intent, pause_limit, *, now):
    """Use the pre-dispatch intent time, a conservative bound before pause starts."""
    require(isinstance(intent, dict) and intent.get("action") == "pause" and type(intent.get("createdAt")) is int
            and type(pause_limit) is int and 60 <= pause_limit <= 21600 and type(now) is int
            and 0 < intent["createdAt"] <= now + 60)
    return intent["createdAt"] + pause_limit


def checkpoint_wait_deadline(action, deadline, pause_until, *, now, monotonic_now):
    """Stop waiting for drain as well as pause-side mutations at the limit."""
    if pause_until is not None and action in {"pause", "drain", "freeze", "capture"}:
        remaining = pause_until - now
        if remaining <= 0:
            print("::error::The approved pause limit elapsed; inspect the private journal and use the explicitly approved recovery plan.", flush=True)
            require(False, "The pause deadline elapsed; do not dispatch another checkpoint.")
        return min(deadline, monotonic_now + remaining)
    return deadline


def run_sequence(store, anchor, target, session, revision, source_checkpoint_id, source_manifest_sha256, token, *,
                 deadline, pause_limit, writer_run_id, pause_alarm_seconds=300, profile="production", candidate_revision=None, validation_json=None,
                 scope_owner=None, rehearsal_complete=None):
    """Drive the fixed checkpoint sequence; unknown external writes are never replayed."""
    from secrets import token_hex
    import time
    profile_config(profile)
    require(rehearsal_complete is None or profile == "rehearsal" and callable(rehearsal_complete))
    candidate_revision = revision if candidate_revision is None and profile == "production" else candidate_revision
    require(REVISION.fullmatch(candidate_revision or "") and (profile != "production" or candidate_revision == revision)
            and type(pause_alarm_seconds) is int and 1 <= pause_alarm_seconds <= pause_limit)
    pinned, _raw, _etag = anchor.read()
    require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == candidate_revision)
    results, pause_until = completed_results(store, target, session, revision, token, source_checkpoint_id,
                                             source_manifest_sha256, pause_limit, profile=profile,
                                             candidate_revision=candidate_revision, validation_json=validation_json)
    pause_alarm_at = None
    if len(results) >= STEPS.index("pause") + 1:
        raw_pause, _ = store.get(event_key(target, session, STEPS.index("pause") + 1))
        pause_alarm_at = parsed(raw_pause)["createdAt"] + pause_alarm_seconds
    while len(results) < len(STEPS):
        artifact.require_current_main(revision)
        if scope_owner is not None:
            from production_backup_manual_scope import ManualScope
            require(type(scope_owner) in {ManualScope, ScheduledScopeOwner} and profile == "production")
            scope_owner.guard()
        nonce = token_hex(32)
        now = int(time.time())
        provisional = dispatch_intent(target=target, session=session, sequence=len(results) + 1, revision=revision,
                                      nonce=nonce, input_sha256="0" * 64, created_at=now, writer_run_id=writer_run_id,
                                      profile=profile, candidate_revision=candidate_revision)
        inputs, pause_until = stage_inputs(results, source_checkpoint_id, source_manifest_sha256, session,
                                           provisional, pause_limit, pause_until, validation_json=validation_json)
        intent = {**provisional, "inputSha256": sha256(canonical(inputs)).hexdigest()}
        if intent["action"] == "pause":
            pause_alarm_at = intent["createdAt"] + pause_alarm_seconds
        stage_deadline = checkpoint_wait_deadline(intent["action"], deadline, pause_until, now=now, monotonic_now=time.monotonic())
        dispatch_once(token, intent, inputs, store)
        print("::notice::A protected backup checkpoint was dispatched; exact action approval remains required.", flush=True)
        run, workflow_id = wait_for_run(intent, token, deadline=stage_deadline, pause_alarm_at=pause_alarm_at)
        result, source, original = selected_result(str(run["id"]), revision, intent["action"], token, profile=profile)
        if scope_owner is not None:
            scope_owner.guard()
        confirm_stage(store, intent, run, workflow_id, result, source, original)
        results.append(result)
    require(results[-1].get("status") == "resumed" and results[-1].get("action") == "activate")
    if scope_owner is not None:
        scope_owner.guard()
    if rehearsal_complete is not None:
        rehearsal_complete(results)
    anchor.release(session + "-1")
    return {"status": "completed", "verifiedCheckpoints": len(results), "productionApprovalSynthesized": False}


def initialize_anchor_once(anchor, guard):
    """Write only a wholly absent genesis, with the caller's guard before each write."""
    initial, genesis = anchor.initial_material()
    require(sha256(genesis).hexdigest() == anchor.genesis_sha256
            and anchor.store.get(anchor.genesis_key, absent=True) is None
            and anchor.store.get_with_etag(anchor.key) == (None, None)
            and not anchor.store.list_backup_anchor_history(anchor.target_sha256)
            and not anchor.store.list_backup_journals(),
            "A partial anchor initialization requires independent reconciliation.")
    guard()
    anchor.store.put(anchor.genesis_key, genesis)
    guard()
    anchor.store.put(anchor.history_key(1, initial), initial)
    guard()
    anchor.store.compare_and_put(anchor.key, None, None, initial)
    anchor.read()


def bootstrap_rate_limit(token):
    """Read GitHub's global quota endpoint once, without exposing response details."""
    from urllib.request import Request
    from urllib.error import HTTPError, URLError
    from http.client import HTTPException
    require(isinstance(token, str) and bool(token))
    request = Request("https://api.github.com/rate_limit", headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer " + token,
        "Cache-Control": "no-cache", "X-GitHub-Api-Version": "2022-11-28"})
    try:
        with artifact._OPENER.open(request, timeout=20) as response:
            require(getattr(response, "status", None) == 200)
            return artifact._parse_object(artifact._bounded_read(response, 65536),
                                          "The GitHub quota response is invalid.")
    except (HTTPError, URLError, OSError, HTTPException):
        require(False, "The GitHub quota is unavailable; no scope object was written.")


def require_bootstrap_budget(observation, token):
    """Reserve primary GH quota before any first-launch scope object is written."""
    require(isinstance(observation, dict) and type(observation.get("reviewedRunCount")) is int
            and 0 <= observation["reviewedRunCount"] <= 25
            and type(observation.get("safePlanRunCount")) is int and 0 <= observation["safePlanRunCount"] <= 5
            and observation.get("guardGithubUpperBound") == 37 + 5 * observation["reviewedRunCount"],
            "The bounded bootstrap writer inventory is required before a write.")
    import time
    rate = bootstrap_rate_limit(token)
    core = rate.get("resources", {}).get("core", {})
    require(type(core.get("remaining")) is int and type(core.get("reset")) is int
            and core["reset"] > int(time.time())
            and core["remaining"] >= 3 * observation["guardGithubUpperBound"] + 100,
            "GitHub read quota is insufficient for the three guarded bootstrap writes.")


def scheduled_start_material(target, policy, authority, authority_sha256, day, session,
                             scope_prior, scope_raw, target_prior, target_raw):
    """Derive the one scheduled slot and both anchor claims without writing."""
    import production_backup_schedule as scheduled
    from production_target import digest
    require(target.environment == "production" and isinstance(policy, dict) and isinstance(authority, dict)
            and HEX.fullmatch(authority_sha256 or "") and digest(authority) == authority_sha256
            and authority.get("targetSha256") == target.digest
            and authority.get("configurationSha256") == target.configuration_digest
            and authority.get("policySha256") == digest(policy) and authority.get("environment") == "production"
            and authority.get("scopeSha256") == scheduled.logical_scope(target)
            and REVISION.fullmatch(authority.get("controlRevision", "")) and DECIMAL.fullmatch(session or ""))
    scheduled._day(day)
    scope = authority["scopeSha256"]
    require(scope != target.digest)
    def advance(prior, raw, identity):
        require(isinstance(prior, dict) and isinstance(raw, bytes) and canonical(prior) == raw
                and set(prior) == {"version", "targetSha256", "generation", "previousSha256", "state", "session", "day", "controlRevision"}
                and type(prior.get("version")) is int and prior["version"] == 1
                and prior.get("targetSha256") == identity and type(prior.get("generation")) is int
                and 1 <= prior["generation"] < 4096 and prior.get("state") == "idle"
                and ((prior["generation"] == 1 and prior["previousSha256"] is None)
                     or (prior["generation"] > 1 and HEX.fullmatch(prior.get("previousSha256", "") or "")))
                and re.fullmatch(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,9}", prior.get("session", ""))
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", prior.get("day", ""))
                and REVISION.fullmatch(prior.get("controlRevision", ""))
                and prior.get("session") != session + "-1")
        return {"version": 1, "targetSha256": identity, "generation": prior["generation"] + 1,
                "previousSha256": sha256(raw).hexdigest(), "state": "active", "session": session + "-1",
                "day": day.replace("-", "/"), "controlRevision": authority["controlRevision"]}
    scope_active = advance(scope_prior, scope_raw, scope)
    target_active = advance(target_prior, target_raw, target.digest)
    scope_sha, target_sha = digest(scope_active), digest(target_active)
    slot = scheduled.slot_intent(authority, authority_sha256, day, target=target, policy=policy,
        session=session, scope_anchor_sha256=scope_sha, anchor_sha256=target_sha,
        writer_run_id=session, writer_attempt="1")
    target_start = {"version": 1, "action": "run", "targetSha256": target.digest,
        "controlRevision": authority["controlRevision"], "session": session,
        "sourceCheckpointId": authority["sourceCheckpointId"], "sourceManifestSha256": authority["sourceManifestSha256"],
        "anchorSha256": sha256(target_raw).hexdigest(), "policySha256": digest(policy),
        "profile": "production", "candidateRevision": authority["controlRevision"], "validationSha256": None,
        "writerRunId": session, "writerAttempt": "1", "authoritySha256": authority_sha256,
        "slotDay": day, "slotSha256": digest(slot), "scopePredecessorSha256": sha256(scope_raw).hexdigest()}
    scope_start = scheduled.scope_start(authority, day, session=session,
        scope_predecessor_sha256=sha256(scope_raw).hexdigest(), target_predecessor_sha256=sha256(target_raw).hexdigest(),
        scope_anchor_sha256=scope_sha, coordinator_anchor_sha256=target_sha, slot_sha256=digest(slot),
        target_start_sha256=digest(target_start), writer_run_id=session, writer_attempt="1")
    return {"slot": slot, "targetStart": target_start, "scopeStart": scope_start,
            "scopeActive": scope_active, "targetActive": target_active}


def scheduled_running_parent(env, slot, token, *, continuation=None):
    """Identify the live fixed coordinator job before any scheduled claim."""
    require(isinstance(slot, dict) and isinstance(slot.get("authority"), dict)
            and slot.get("writerRunId") == slot.get("session") and slot.get("writerAttempt") == "1"
            and env.get("GITHUB_RUN_ATTEMPT") == "1" and env.get("GITHUB_REF") == artifact.MAIN_REF
            and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/" + PROFILES["production"]["parent"] + "@" + artifact.MAIN_REF
            and env.get("GITHUB_WORKFLOW_SHA") == env.get("GITHUB_SHA") == slot["authority"].get("controlRevision"))
    run_id, revision = env["GITHUB_RUN_ID"], env["GITHUB_SHA"]
    require(DECIMAL.fullmatch(run_id or "") and REVISION.fullmatch(revision or ""))
    if continuation is None:
        require(env.get("GITHUB_EVENT_NAME") == "schedule" and run_id == slot["writerRunId"])
    else:
        require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and env.get("BACKUP_COORDINATOR_ACTION") == "resume-scheduled"
                and continuation["writerRunId"] == run_id
                and continuation["planSha256"] == env.get("BACKUP_COORDINATOR_APPROVAL_SHA256"))
    run = artifact._get_json("/actions/runs/" + run_id, token)
    scheduled_run_identity(run, run_id, revision, continuation=continuation is not None)
    require(run.get("status") == "in_progress" and run.get("conclusion") is None)
    response = artifact._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100
            and len({job.get("id") for job in jobs if isinstance(job, dict)}) == len(jobs))
    matched = [job for job in jobs if isinstance(job, dict) and job.get("name") == "coordinate"]
    require(len(matched) == 1 and type(matched[0].get("id")) is int and matched[0]["id"] > 0)
    scheduled_running_job(matched[0], run_id, revision, matched[0]["id"])
    return matched[0]["id"]


def scheduled_running_job(job, run_id, revision, job_id):
    require(isinstance(job, dict) and job.get("id") == job_id and job.get("name") == "coordinate"
            and str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == revision
            and job.get("status") == "in_progress" and job.get("conclusion") is None and isinstance(job.get("steps"), list))
    names = ("Check scheduled authority switch", "Check out trusted current main", "Verify scheduled dispatcher identity",
             "Coordinate one explicitly approved operation")
    indexes = []
    for index, name in enumerate(names):
        matching = [(i, step) for i, step in enumerate(job["steps"]) if isinstance(step, dict) and step.get("name") == name]
        require(len(matching) == 1 and (matching[0][1].get("status"), matching[0][1].get("conclusion")) ==
                (("in_progress", None) if index == len(names) - 1 else ("completed", "success")))
        indexes.append(matching[0][0])
    require(indexes == sorted(set(indexes)))
    return True


class ScheduledScopeOwner:
    """Recheck a claimed scheduled owner before a parent dispatch or finalization."""
    def __init__(self, env, target, objects, scope_anchor, target_anchor, material, scope_keys, job_id, *, continuation=None):
        from production_backup_fresh_github import FreshConditionalJSON
        import production_backup_schedule as scheduled
        require(isinstance(material, dict) and set(material) == {"slot", "scopeStart", "targetStart", "scopeActive", "targetActive"}
                and isinstance(scope_keys, list) and len(scope_keys) == len(set(scope_keys))
                and type(scope_anchor) is ScheduleScopeAnchor and scope_anchor.store.objects is objects
                and type(target_anchor) is maintenance.Anchor and target_anchor.store.objects is objects
                and scope_anchor.target_sha256 == scheduled.logical_scope(target) and target_anchor.target_sha256 == target.digest
                and type(job_id) is int and job_id > 0
                and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
                and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
                and env.get("GITHUB_REF") == artifact.MAIN_REF
                and env.get("GITHUB_EVENT_NAME") == ("schedule" if continuation is None else "workflow_dispatch")
                and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
                and env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF
                and env.get("GITHUB_WORKFLOW_SHA") == env.get("GITHUB_SHA"))
        self.env, self.target, self.objects = env, target, objects
        self.continuation = continuation
        self.scope_anchor, self.target_anchor, self.material = scope_anchor, target_anchor, material
        self.scope_keys, self.job_id, self.client = set(scope_keys), job_id, FreshConditionalJSON()

    def guard(self, *, target_released=False, scope_released=False):
        import production_backup_cli as backup
        import production_backup_schedule as scheduled
        slot, start, scope_start = self.material["slot"], self.material["targetStart"], self.material["scopeStart"]
        authority, pin = slot["authority"], slot["authoritySha256"]
        require(backup.settings(self.env.get("SUBS_BOT_BACKUP_POLICY_JSON", "")) == slot["policy"],
                "The protected scheduled backup policy changed.")
        fresh = scheduled.authority_document(self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_JSON", ""),
            self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256", ""), target=self.target,
            control_revision=self.env["GITHUB_SHA"], source_revision=authority["sourceRevision"],
            source_checkpoint_id=authority["sourceCheckpointId"], source_manifest_sha256=authority["sourceManifestSha256"],
            policy=slot["policy"], target_genesis_sha256=self.env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", ""),
            application_genesis_sha256=self.env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
        import time
        require(fresh == authority and pin == self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_AUTHORITY_SHA256")
                and self.env.get("SUBS_BOT_PRODUCTION_BACKUP_SCHEDULE_ENABLED") == "true"
                and authority["ledgerGenesisSha256"] == self.scope_anchor.genesis_sha256
                    == self.env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256")
                and authority["targetCoordinatorGenesisSha256"] == self.target_anchor.genesis_sha256
                    == self.env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256")
                and self.scope_anchor.bucket_name == self.target.data["backupBucketName"]
                and self.scope_anchor.bucket_created_at == self.target.data["backupBucketCreatedAt"]
                and authority["validFrom"] <= int(time.time()) < authority["validUntil"])
        backup.scheduled_main_guard(self.env["GITHUB_SHA"], self.client)
        run_id = self.env["GITHUB_RUN_ID"]
        self.client.get("/actions/jobs/" + str(self.job_id),
            verify=lambda value: scheduled_running_job(value, run_id, self.env["GITHUB_SHA"], self.job_id))
        require(scheduled_continuation(self.objects, slot) == self.continuation)
        if self.continuation is None:
            require(run_id == slot["writerRunId"])
        else:
            require(self.continuation["writerRunId"] == run_id
                    and self.continuation["planSha256"] == self.env.get("BACKUP_COORDINATOR_APPROVAL_SHA256"))
        scope_value, scope_raw, _etag = self.scope_anchor.read()
        target_value, target_raw, _etag = self.target_anchor.read()
        require(type(target_released) is bool and type(scope_released) is bool
                and scope_value.get("session") == target_value.get("session") == slot["session"] + "-1"
                and scope_value.get("controlRevision") == target_value.get("controlRevision") == self.env["GITHUB_SHA"]
                and scope_value.get("day") == target_value.get("day") == slot["slotDay"].replace("-", "/"))
        if scope_released:
            require(target_released and self.continuation is not None and scope_value["state"] == "idle"
                    and scope_value["generation"] == self.material["scopeActive"]["generation"] + 1
                    and scope_value["previousSha256"] == slot["scopeAnchorSha256"])
        else:
            require(scope_value == self.material["scopeActive"] and scope_value["state"] == "active"
                    and sha256(scope_raw).hexdigest() == slot["scopeAnchorSha256"]
                    and scope_value["previousSha256"] == start["scopePredecessorSha256"])
        if target_released:
            require(target_value.get("state") == "idle"
                    and target_value.get("generation") == self.material["targetActive"]["generation"] + 1
                    and target_value.get("previousSha256") == slot["coordinatorAnchorSha256"],
                    "The scheduled target release is not the exact confirmed successor.")
        else:
            require(target_value == self.material["targetActive"] and target_value.get("state") == "active"
                    and sha256(target_raw).hexdigest() == slot["coordinatorAnchorSha256"]
                    and target_value.get("previousSha256") == start.get("anchorSha256"))
        scope_key = scheduled.scope_start_key(slot["scopeSha256"], slot["session"])
        target_key = BASE + self.target.digest + "/" + slot["session"] + "/start-intent.json"
        slot_key = scheduled.slot_key(slot["scopeSha256"], slot["slotDay"])
        expected_start = {"version": 1, "action": "run", "targetSha256": self.target.digest,
            "controlRevision": self.env["GITHUB_SHA"], "session": slot["session"],
            "sourceCheckpointId": authority["sourceCheckpointId"], "sourceManifestSha256": authority["sourceManifestSha256"],
            "anchorSha256": self.material["targetActive"]["previousSha256"], "policySha256": sha256(canonical(slot["policy"])).hexdigest(),
            "profile": "production", "candidateRevision": self.env["GITHUB_SHA"], "validationSha256": None,
            "writerRunId": slot["session"], "writerAttempt": "1", "authoritySha256": pin,
            "slotDay": slot["slotDay"], "slotSha256": sha256(canonical(slot)).hexdigest(),
            "scopePredecessorSha256": self.material["scopeActive"]["previousSha256"]}
        require(scope_key in self.scope_keys and slot_key in self.scope_keys
                and slot["writerRunId"] == slot["session"]
                and slot["writerAttempt"] == "1" and start == expected_start
                and scope_start == scheduled.scope_start(authority, slot["slotDay"], session=slot["session"],
                    scope_predecessor_sha256=start.get("scopePredecessorSha256"),
                    target_predecessor_sha256=start.get("anchorSha256"),
                    scope_anchor_sha256=slot["scopeAnchorSha256"], coordinator_anchor_sha256=slot["coordinatorAnchorSha256"],
                    slot_sha256=start["slotSha256"], target_start_sha256=sha256(canonical(start)).hexdigest(),
                    writer_run_id=slot["writerRunId"], writer_attempt=slot["writerAttempt"]))
        scope_raw, _ = self.objects.get(scope_key)
        target_raw, _ = self.objects.get(target_key)
        require(scope_raw == canonical(scope_start) and target_raw == canonical(start)
                and scheduled.read_slot(self.objects, authority, pin, slot["slotDay"], slot) == start["slotSha256"])
        keys = self.objects.list(scheduled.BASE + slot["scopeSha256"] + "/", maximum=10000)
        require(len(keys) < 10000 and len(keys) == len(set(keys)) and set(keys) == self.scope_keys,
                "The scheduled scope inventory changed; do not dispatch another phase.")


def finish_scheduled_sequence(owner, app_store, token, *, scope_released=False):
    """Publish only a completely verified scheduled terminal, without retrying writes."""
    import time
    import production_backup_cli as backup
    import production_backup_schedule as scheduled
    import production_backup_schedule_terminal as terminal
    require(type(owner) is ScheduledScopeOwner)
    env, target, objects = owner.env, owner.target, owner.objects
    slot, authority = owner.material["slot"], owner.material["slot"]["authority"]
    owner.guard(target_released=True, scope_released=scope_released)
    key = scheduled.terminal_key(slot["scopeSha256"], slot["slotDay"])
    witness_key = terminal.witness_key(slot["scopeSha256"], slot["slotDay"])
    existing, _ = objects.get(key, absent=True)
    require((existing is None or scope_released) and objects.get(witness_key, absent=True)[0] is None,
            "An existing scheduled witness requires inspection, not a repeated write.")
    phase = terminal.collect_phase_evidence(objects, target, slot, token)
    chain_sha = terminal.verify_phase_evidence(objects, target, slot, phase)
    app = terminal.collect_app_terminal(objects, app_store, target, slot, phase, authority["applicationGenesisSha256"])
    rate = bootstrap_rate_limit(token)
    core = rate.get("resources", {}).get("core", {})
    # Two parent guards and a final main/job recheck use at most six primary
    # reads on 200 responses; leave a further 100 for concurrent use.
    require(type(core.get("remaining")) is int and core["remaining"] >= 106
            and type(core.get("reset")) is int and core["reset"] > int(time.time()),
            "Insufficient GitHub read quota for scheduled terminal publication.")
    owner.guard(target_released=True, scope_released=scope_released)
    require(terminal.collect_app_terminal(objects, app_store, target, slot, phase, authority["applicationGenesisSha256"]) == app
            and terminal.verify_phase_evidence(objects, target, slot, phase) == chain_sha)
    owner.guard(target_released=True, scope_released=scope_released)
    target_value, target_raw, _etag = owner.target_anchor.read()
    target_idle_sha = sha256(target_raw).hexdigest()
    require(target_value.get("state") == "idle" and target_value.get("previousSha256") == slot["coordinatorAnchorSha256"])
    if not scope_released:
        owner.scope_anchor.release(slot["session"] + "-1")
    idle, idle_raw, _etag = owner.scope_anchor.read()
    require(idle.get("state") == "idle" and idle.get("session") == slot["session"] + "-1"
            and idle.get("previousSha256") == slot["scopeAnchorSha256"])
    done = scheduled.terminal_record(slot, chain_sha256=chain_sha,
        scope_idle_anchor_sha256=sha256(idle_raw).hexdigest(), coordinator_idle_anchor_sha256=target_idle_sha,
        result="success")
    backup.scheduled_main_guard(env["GITHUB_SHA"], owner.client)
    owner.client.get("/actions/jobs/" + str(owner.job_id),
        verify=lambda value: scheduled_running_job(value, env["GITHUB_RUN_ID"], env["GITHUB_SHA"], owner.job_id))
    again_scope, again_scope_raw, _etag = owner.scope_anchor.read()
    again_target, again_target_raw, _etag = owner.target_anchor.read()
    require(again_scope == idle and again_scope_raw == idle_raw and again_target == target_value and again_target_raw == target_raw
            and objects.get(key, absent=True)[0] == existing and objects.get(witness_key, absent=True)[0] is None)
    body = canonical(done)
    if existing is None:
        objects.put_once(key, body)
    else:
        require(existing == body, "The retained terminal does not match the independently verified completion.")
    confirmed, _etag = objects.get(key)
    require(confirmed == body, "The scheduled terminal was not independently confirmed.")
    return {"status": "completed", "slotDay": slot["slotDay"], "verifiedCheckpoints": len(STEPS),
            "terminalSha256": sha256(body).hexdigest(), "productionApprovalSynthesized": False}


def scope_initialization(env, action, target, objects, revision, target_anchor, target_genesis):
    """Plan or initialize only a new, explicitly approved project scope."""
    import production_backup_schedule as scheduled
    import production_backup_scope_bootstrap as bootstrap
    import scoped_r2
    from production_control import API
    from production_target import digest

    require(action in {"plan-schedule-anchor", "initialize-schedule-anchor"}
            and target_anchor.target_sha256 == target.digest and target_anchor.genesis_sha256 == target_genesis)
    # Both source readers are built without any writer map, even when this job
    # separately holds the single-bucket scope writer for the approved CAS.
    read_env = dict(env)
    read_env.pop("SUBS_BOT_SCOPED_R2_WRITE_JSON", None)
    read_env.pop("SUBS_BOT_SCOPED_R2_EXTRA_WRITE_JSON", None)
    registration = parsed(env.get("SUBS_BOT_PROVISION_ANCHOR_JSON", ""))
    require(isinstance(registration, dict) and set(registration) == {"accountId", "bucketName", "bucketCreatedAt"}
            and registration["accountId"] == target.account_id)
    target_reader = scoped_r2.from_environment(target.account_id, target.data["backupBucketName"], read_env)
    data_reader = scoped_r2.from_environment(target.account_id, target.data["bucketName"], read_env)
    provision_reader = scoped_r2.from_environment(target.account_id, registration["bucketName"], read_env)
    require(target_reader is not None and data_reader is not None and provision_reader is not None
            and target_reader.write_credential is None and data_reader.write_credential is None
            and provision_reader.write_credential is None)
    scope = scheduled.logical_scope(target)
    require(scope != target.digest)
    read_store = CoordinatorStore(target_reader, scope)
    seed = ScheduleScopeAnchor(read_store, scope, "0" * 64, target.data["backupBucketName"],
                               target.data["backupBucketCreatedAt"])
    _initial, genesis_raw = seed.initial_material()
    scope_genesis = sha256(genesis_raw).hexdigest()
    read_anchor = ScheduleScopeAnchor(read_store, scope, scope_genesis, target.data["backupBucketName"],
                                      target.data["backupBucketCreatedAt"])
    data_api = API(target, env.get("SUBS_BOT_CF_BACKUP_MONITOR_READ_TOKEN", ""))
    worker_api = API(target, env.get("SUBS_BOT_CF_WORKER_READ_TOKEN", ""))
    metadata_api = API(target, env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
    review_raw = env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_JSON", "")
    review_pin = env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REVIEW_SHA256", "")
    registration_sha = env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_REGISTRATION_SHA256", "")
    token = artifact._github_token()
    args = (env, target, target_reader, data_reader, provision_reader, data_api, worker_api, metadata_api, read_anchor,
            review_raw, review_pin, registration_sha, token)
    plan = bootstrap.plan_first_launch(*args)
    require(plan.get("targetCoordinatorGenesisSha256") == target_genesis
            and plan.get("controlRevision") == revision)
    plan_sha = digest(plan)
    if action == "plan-schedule-anchor":
        return {"status": "planned", "planSha256": plan_sha, "scopeGenesisSha256": scope_genesis,
                "scopeSha256": scope, "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                "targetCoordinatorGenesisSha256": target_genesis,
                "applicationGenesisSha256": sha256(maintenance.Anchor(None, target.digest, "0" * 64).initial_material()[1]).hexdigest(),
                "controlRevision": revision, "mutationPerformed": False}
    require(env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256") == target_genesis
            and env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256") == scope_genesis
            and env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == plan_sha
            and env.get("SUBS_BOT_BACKUP_SCOPE_BOOTSTRAP_PLAN_SHA256") == plan_sha,
            "The exact independently pinned first-launch plan and both genesis pins are required.")
    first = bootstrap.verify_first_launch_guard(*args, plan, stage=0)
    require_bootstrap_budget(first, token)
    stage = 0
    def guarded_write():
        nonlocal stage
        require(stage in {0, 1, 2})
        current = bootstrap.verify_first_launch_guard(*args, plan, stage=stage)
        require(current.get("reviewedRunCount") == first["reviewedRunCount"]
                and current.get("guardGithubUpperBound") == first["guardGithubUpperBound"])
        stage += 1
    writer_anchor = ScheduleScopeAnchor(CoordinatorStore(objects, scope), scope, scope_genesis,
                                        target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    initialize_anchor_once(writer_anchor, guarded_write)
    require(stage == 3)
    return {"status": "schedule-anchor-initialized", "scopeGenesisSha256": scope_genesis, "mutationPerformed": True}


def main(env=None):
    import os
    import time
    from datetime import datetime, timezone
    import scoped_r2
    import production_backup_transaction as maintenance
    import production_backup_cli as backup_cli
    from production_control import API, privacy
    from production_storage import PrivateStore
    from production_target import validate_target, digest

    env = os.environ if env is None else env
    revision = verify_context(env)
    action = env.get("BACKUP_COORDINATOR_ACTION", "inspect")
    require(action in {"inspect", "plan-initialize", "initialize", "plan-schedule-anchor", "initialize-schedule-anchor",
                       "scheduled-run", "plan-resume-scheduled", "resume-scheduled", "plan-run", "run",
                       "plan-resume", "resume", "plan-reconcile", "reconcile", "plan-abort", "abort"})
    if env.get("GITHUB_EVENT_NAME") == "schedule":
        require(action in {"inspect", "scheduled-run"}, "The cron event cannot select a manual action.")
    else:
        require(action != "scheduled-run", "A scheduled start requires the fixed cron event.")
    target = validate_target(env.get("SUBS_BOT_TARGET_JSON", ""))
    require(target.environment == "production")
    policy = backup_cli.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", ""))
    metadata = API(target, env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
    privacy(metadata, metadata.root, target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    objects = scoped_r2.from_environment(target.data["accountId"], target.data["backupBucketName"], env)
    require(objects is not None, "A separately scoped private backup bucket reader is required.")
    genesis = env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", "")
    seed = maintenance.Anchor(CoordinatorStore(objects, target.digest), target.digest, "0" * 64)
    expected = sha256(seed.initial_material()[1]).hexdigest()
    require(genesis == expected or action in {"plan-initialize", "plan-schedule-anchor"} and not genesis)
    anchor = maintenance.Anchor(CoordinatorStore(objects, target.digest), target.digest, expected)
    if action == "plan-initialize":
        return {"status": "planned", "genesisSha256": expected, "mutationPerformed": False}
    if action in {"initialize", "initialize-schedule-anchor", "scheduled-run", "resume-scheduled", "run", "resume", "reconcile", "abort"}:
        require(env.get("SUBS_BOT_PRODUCTION_BACKUP_COORDINATOR_ENABLED") == "true"
                and objects.write_credential is not None, "The production coordinator is disabled.")
    if action in {"plan-schedule-anchor", "initialize-schedule-anchor"}:
        return scope_initialization(env, action, target, objects, revision, anchor, expected)
    if action in {"scheduled-run", "plan-resume-scheduled", "resume-scheduled"}:
        from production_backup_schedule_claim import run_scheduled
        from production_backup_schedule_resume import resume_scheduled

        app_store = PrivateStore(metadata, target.data["backupBucketName"])
        app_store.objects = objects
        runner = run_scheduled if action == "scheduled-run" else resume_scheduled
        return runner(env, target, objects, app_store, anchor, policy, artifact._github_token())
    if action == "initialize":
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == expected)
        from production_backup_manual_scope import ManualScope
        app_store = PrivateStore(metadata, target.data["backupBucketName"])
        manual_scope = ManualScope(env, target, objects, revision, policy=policy, app_store=app_store)
        manual_scope.acquire_coordinator_initialization(expected)
        initialize_anchor_once(anchor, manual_scope.guard)
        result = {"status": "initialized", "mutationPerformed": True}
        manual_scope.finish(result)
        return result
    pinned, raw, _etag = anchor.read()
    if action == "inspect":
        return {"status": "attention" if pinned["state"] == "active" else "observed",
                "phase": pinned["state"], "mutationPerformed": False,
                "notification": "github-check-only", "automaticReplay": False}
    source_checkpoint, source_sha = env.get("BACKUP_SOURCE_CHECKPOINT_ID", ""), env.get("BACKUP_SOURCE_MANIFEST_SHA256", "")
    require(re.fullmatch(r"[a-f0-9]{32}", source_checkpoint or "") and HEX.fullmatch(source_sha or ""))
    session = env["GITHUB_RUN_ID"] if action == "plan-run" else env.get("BACKUP_COORDINATOR_SESSION", "")
    require(DECIMAL.fullmatch(session or ""))
    normalized = {"plan-run": "run", "plan-resume": "resume", "plan-reconcile": "reconcile", "plan-abort": "abort"}.get(action, action)
    plan = {"version": 1, "action": normalized, "targetSha256": target.digest, "controlRevision": revision,
            "session": session, "sourceCheckpointId": source_checkpoint, "sourceManifestSha256": source_sha,
            "anchorSha256": sha256(raw).hexdigest(), "policySha256": digest(policy),
            "profile": "production", "candidateRevision": revision, "validationSha256": None}
    if action == "plan-run":
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1")
        return {"status": "planned", "planSha256": digest(plan), "session": session, "mutationPerformed": False}
    if action in {"plan-resume", "resume", "plan-reconcile", "reconcile", "plan-abort", "abort"}:
        import production_backup_schedule as scheduled
        scope = scheduled.logical_scope(target)
        scope_anchor = ScheduleScopeAnchor(CoordinatorStore(objects, scope), scope,
            env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256", ""), target.data["backupBucketName"],
            target.data["backupBucketCreatedAt"])
        scope_state, scope_raw, _ = scope_anchor.read()
        require(scope_state["state"] == "active" and scope_state["controlRevision"] == revision,
                "The original manual coordinator must still own the project scope.")
        plan["scopePointerSha256"] = sha256(scope_raw).hexdigest()
    if action == "plan-resume":
        require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        plan["writerHistorySha256"] = digest(history)
        verified, _ = completed_results(objects, target.digest, session, revision, artifact._github_token(),
                                        source_checkpoint, source_sha, backup_cli.maximum_pause(policy))
        plan.update(completedResultsSha256=digest(verified), nextAction=STEPS[len(verified)] if len(verified) < len(STEPS) else "complete")
        return {"status": "planned", "planSha256": digest(plan), "session": session,
                "verifiedCheckpoints": len(verified), "mutationPerformed": False}
    if action in {"plan-abort", "abort"}:
        require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        app_store = PrivateStore(metadata, target.data["backupBucketName"])
        app_genesis = env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", "")
        observed = abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha,
                                     backup_cli.maximum_pause(policy), app_genesis)
        plan.update(writerHistorySha256=digest(history), abortObservationSha256=digest(observed))
        if action == "plan-abort":
            return {"status": "planned", "planSha256": digest(plan), "terminal": observed["terminal"], "mutationPerformed": False}
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        from production_backup_manual_scope import ManualScope
        manual_scope = ManualScope(env, target, objects, revision, policy=policy, app_store=app_store)
        artifact.require_current_main(revision)
        require(finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy)) == history
                and abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha,
                                      backup_cli.maximum_pause(policy), app_genesis) == observed)
        manual_scope.continue_coordinator("abort", plan, history)
        require(abort_observation(objects, app_store, target, session, revision, source_checkpoint, source_sha,
                                  backup_cli.maximum_pause(policy), app_genesis) == observed)
        manual_scope.guard()
        anchor.release(session + "-1")
        result = {"status": "abandoned-after-confirmed-terminal", "terminal": observed["terminal"],
                "abortObservationSha256": digest(observed), "applicationAnchorSha256": observed["applicationAnchorSha256"],
                "productionMutation": False, "dispatchRetried": False}
        manual_scope.finish(result)
        return result
    if action in {"plan-reconcile", "reconcile"}:
        require(pinned["state"] == "active" and pinned["session"] == session + "-1" and pinned["controlRevision"] == revision)
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        sequence = int(env.get("BACKUP_COORDINATOR_SEQUENCE", "0"))
        stage = inspect_stage(objects, target.digest, session, sequence)
        require(stage["status"] == "unknown", "Only an unresolved original dispatch can be reconciled.")
        prior, prior_pause = completed_results(objects, target.digest, session, revision, artifact._github_token(),
                                              source_checkpoint, source_sha, backup_cli.maximum_pause(policy), stop_before=sequence)
        require(len(prior) == sequence - 1, "An earlier coordinator stage has not been independently verified.")
        intent_raw, _ = objects.get(event_key(target.digest, session, sequence))
        intent = parsed(intent_raw)
        expected_inputs, _ = stage_inputs(prior, source_checkpoint, source_sha, session, intent,
                                          backup_cli.maximum_pause(policy), prior_pause)
        require(sha256(canonical(expected_inputs)).hexdigest() == intent["inputSha256"])
        token = artifact._github_token()
        workflow = artifact._get_json("/actions/workflows/worker-production-backup.yml", token)
        require(workflow.get("path") == ".github/workflows/worker-production-backup.yml" and type(workflow.get("id")) is int)
        run = discover_run(intent, workflow["id"], token)
        require((run.get("status"), run.get("conclusion")) == ("completed", "success"))
        result, source, original = selected_result(str(run["id"]), revision, intent["action"], token)
        proof = receipt(intent, str(run["id"]), result, source["artifactId"], source["artifactSha256"])
        require_completed_receipt(intent, proof, run, workflow["id"], result)
        plan.update(sequence=sequence, intentSha256=sha256(intent_raw).hexdigest(),
                    runId=str(run["id"]), resultSha256=proof["resultSha256"], artifactId=source["artifactId"],
                    artifactSha256=source["artifactSha256"], writerHistorySha256=digest(history))
        if action == "plan-reconcile":
            return {"status": "planned", "planSha256": digest(plan), "mutationPerformed": False}
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        from production_backup_manual_scope import ManualScope
        app_store = PrivateStore(metadata, target.data["backupBucketName"])
        manual_scope = ManualScope(env, target, objects, revision, policy=policy, app_store=app_store)
        artifact.require_current_main(revision)
        require(finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy)) == history)
        manual_scope.continue_coordinator("reconcile", plan, history)
        again = discover_run(intent, workflow["id"], token)
        again_result, again_source, again_original = selected_result(str(again["id"]), revision, intent["action"], token)
        require(again == run and again_result == result and again_source == source and again_original == original,
                "The approved reconciliation evidence changed.")
        manual_scope.guard()
        confirm_stage(objects, intent, run, workflow["id"], result, source, original)
        return {"status": "reconciled", "mutationPerformed": True, "dispatchRetried": False,
                "scopeRetainedForContinuation": True}
    if action == "resume":
        history = finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy))
        plan["writerHistorySha256"] = digest(history)
        verified, _ = completed_results(objects, target.digest, session, revision, artifact._github_token(),
                                        source_checkpoint, source_sha, backup_cli.maximum_pause(policy))
        plan.update(completedResultsSha256=digest(verified), nextAction=STEPS[len(verified)] if len(verified) < len(STEPS) else "complete")
    require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan),
            "The exact independently approved coordinator plan is required.")
    from production_backup_manual_scope import ManualScope
    app_store = PrivateStore(metadata, target.data["backupBucketName"])
    manual_scope = ManualScope(env, target, objects, revision, policy=policy, app_store=app_store)
    if action == "run":
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1")
        require(backup_cli.in_window(policy, datetime.now(timezone.utc)), "A new backup cannot start outside its approved UTC window.")
        original_plan = artifact._get_json("/actions/runs/" + session + "/attempts/1", artifact._github_token())
        require(str(original_plan.get("id")) == session and original_plan.get("head_sha") == revision
                and original_plan.get("display_title") == "Production backup coordinator plan-run at " + revision
                and original_plan.get("event") == "workflow_dispatch" and original_plan.get("head_branch") == "main"
                and original_plan.get("run_attempt") == 1 and (original_plan.get("status"), original_plan.get("conclusion")) == ("completed", "success")
                and all(isinstance(original_plan.get(key), dict) and original_plan[key].get("id") == artifact.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
        app_anchor = maintenance.Anchor(app_store, target.digest, env.get("SUBS_BOT_BACKUP_GENESIS_SHA256", ""))
        app_pin, _app_raw, _etag = app_anchor.read()
        require(app_pin["state"] == "idle", "An existing application maintenance transaction requires reconciliation.")
        manual_scope.acquire_coordinator("run", plan)
        require(app_anchor.read()[0] == app_pin, "The application maintenance anchor changed before coordinator start.")
        start = {**plan, "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": "1"}
        key = BASE + target.digest + "/" + session + "/start-intent.json"
        existing, _ = objects.get(key, absent=True)
        require(existing is None, "A coordinator start intent already exists.")
        manual_scope.guard()
        objects.put_once(key, canonical(start))
        artifact.require_current_main(revision)
        manual_scope.guard()
        anchor.acquire(session + "-1", datetime.now(timezone.utc).strftime("%Y/%m/%d"), revision)
    else:
        require(action == "resume" and pinned["state"] == "active" and pinned["session"] == session + "-1"
                and pinned["controlRevision"] == revision)
        require(finished_controller(objects, target.digest, session, revision, source_checkpoint, source_sha, digest(policy)) == history)
        manual_scope.continue_coordinator("resume", plan, history)
        again, _ = completed_results(objects, target.digest, session, revision, artifact._github_token(),
                                     source_checkpoint, source_sha, backup_cli.maximum_pause(policy))
        require(again == verified, "The approved continuation results changed.")
    result = run_sequence(objects, anchor, target.digest, session, revision, source_checkpoint, source_sha,
                          artifact._github_token(), deadline=time.monotonic() + 5 * 3600,
                          pause_limit=backup_cli.maximum_pause(policy), pause_alarm_seconds=policy["pauseLimitSeconds"],
                          writer_run_id=env["GITHUB_RUN_ID"], scope_owner=manual_scope)
    manual_scope.finish(result)
    return result


if __name__ == "__main__":
    import json
    import os
    from pathlib import Path
    try:
        os.umask(0o077)
        # Use the normal module identity also used by the claim and scope verifiers.
        from production_backup_coordinator import main as run
        result = run()
        root = Path(os.environ["RUNNER_TEMP"])
        require(root.is_absolute() and root.is_dir() and not root.is_symlink())
        path = root / "production-backup-coordinator-result.json"
        with path.open("xb") as output:
            os.chmod(path, 0o600)
            output.write(canonical(result))
        print(json.dumps(result, sort_keys=True))
        if result.get("status") == "attention":
            print("::error::A coordinator session remains active; inspect its private journal and current backup state.")
            raise SystemExit(1)
    except Exception:
        print("::error::Backup coordination stopped; inspect the private intent and current state before continuing.")
        raise SystemExit(1) from None

"""Private evidence for one interrupted rehearsal backup; no export is retried.

The custody assertion is an explicitly reviewed assumption, not an R2
immutability guarantee. A trusted main gate and separate protected switches
are required for every read and write.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
from hashlib import sha256
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import time
from urllib.request import Request

import prepare_isolation_artifact as github
from production_target import canonical, parsed, require

OLD_RUN = "44164739374"
OLD_JOB = "134327660057"
OLD_MAIN = "43ec8cc22c3f51eedde5569e8025e26f3244091a"
OLD_HEAD = "7aa685990859cffb30d47c5a6e593d969f1d0452"
OLD_CHECKPOINT = "1bbadaa9755d1733ddd80fe12192420a"
OLD_LOG_SHA = "6bc155ec5a2dac24b96a036bb0b884fe98ecb07ff82092f3992ca8d6983c194a"
FAILED_PLAN_RUN = "44180277055"
FAILED_PLAN_JOB = "134382463410"
FAILED_PLAN_MAIN = "777bf60f8881755802a957777f55b7e3e9ff273a"
FAILED_PLAN_HEAD = "98562f7cbef35a6847db1bd342abf689b31eacc0"
FAILED_PLAN_LOG_SHA = "06b7dc59ad424d1862233aca9290914bb1c67863569f5ef6908b2f99b3068852"
FAILED_PLAN_WORKFLOW_SHA = "8b46e11408866e5369013d2715b2339df9d37794753b6b61cdc067dade523355"
FAILED_PLAN_GATE_SHA = "dec99713970c4259161ed038b1e02fa96e620bfa1d739a794cdfd162d937ba3f"
CHUNK = 512 * 1024
MAX_SOURCE = 1024 * 1024
MAX_LOG = 4 * 1024 * 1024
SHA = re.compile(r"[a-f0-9]{64}")
WORKFLOW = ".github/workflows/worker-backup-no-export-resolution.yml"
GATES = ("Verify no-export identity before candidate checkout", "Verify exact reviewed no-export checkout",
         "Verify no-export test Bot identity")
STAGES = {"setup", "gate", "originals", "observe", "budget", "seal-intent", "seal-chunks", "seal-manifest",
          "claim", "append", "anchor-cas", "receipt", "readback"}
CURRENT_STAGE = "setup"


def stage(value):
    """A progress marker is not evidence that a write completed."""
    global CURRENT_STAGE
    require(value in STAGES)
    CURRENT_STAGE = value
    print(json.dumps({"noExportStage": value}, sort_keys=True), flush=True)


def checked_gate(env, *, with_stats=False):
    """Invoke the separately checked-out, current-main gate, never candidate code."""
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    gate = workspace / "trusted/worker/tools/trusted_backup_no_export_gate.py"
    require(workspace.is_absolute() and gate.is_file() and not gate.is_symlink())
    gate_env = {**env, "NO_EXPORT_GATE_CHECK": "credential"}
    gate_env.pop("GITHUB_OUTPUT", None)
    process = subprocess.run(["python3", "-B", str(gate)], env=gate_env,
                             capture_output=True, check=True, timeout=300)
    lines = process.stdout.decode("utf-8").splitlines()
    require(len(lines) == 1)
    result = json.loads(lines[0])
    review = parsed(env.get("NO_EXPORT_REVIEW_JSON", ""))
    require(result.get("status") == "validated" and result.get("oldRunId") == OLD_RUN
            and result.get("reviewSha256") == sha256(canonical(review)).hexdigest()
            and result.get("writerInventorySha256") == review.get("writerInventorySha256")
            and result.get("writerInventorySha256") == env.get("NO_EXPORT_WRITER_INVENTORY_SHA256"))
    if with_stats:
        writers = result.get("writerRunCount")
        require(type(writers) is int and 0 <= writers <= 40)
        return review, writers
    return review


def require_request_budget(env, review, remaining_guards):
    """Fail before an intent if the remaining hosted core quota is insufficient."""
    checked, writers = checked_gate(env, with_stats=True)
    require(checked == review and type(remaining_guards) is int and 1 <= remaining_guards <= 100)
    # Gate's bounded fixed work is at most 21 GETs, including the exact old
    # Provider read; allow two per known or two extra same-workflow runs, six
    # for release's seal provenance, and 100 spare. Concurrent rate use or
    # secondary limits remain unknown.
    require(env.get("NO_EXPORT_ACTION") in {"seal", "release"})
    per_guard = 21 + 2 * (writers + 2) + (6 if env["NO_EXPORT_ACTION"] == "release" else 0)
    required = per_guard * remaining_guards + 100
    request = Request("https://api.github.com/rate_limit", headers={
        "Accept": "application/vnd.github+json", "Authorization": "Bearer " + github._github_token(),
        "Cache-Control": "no-cache", "X-GitHub-Api-Version": "2022-11-28"})
    with github._OPENER.open(request, timeout=20) as response:
        raw = response.read(65537)
    require(isinstance(raw, bytes) and len(raw) <= 65536)
    data = json.loads(raw)
    core = data.get("resources", {}).get("core", {})
    require(type(core.get("remaining")) is int and type(core.get("reset")) is int
            and core["reset"] > int(time.time()) and core["remaining"] >= required,
            "Insufficient GitHub read quota for the bounded guarded operation; no intent was written.")
    return {"required": required, "remaining": core["remaining"]}


def log_reader(env):
    """Load only the reviewed trusted-main reader from the checked checkout."""
    path = Path(env["GITHUB_WORKSPACE"]) / "trusted/worker/tools/trusted_backup_webhook_log_archive.py"
    require(path.is_file() and not path.is_symlink())
    spec = importlib.util.spec_from_file_location("trusted_original_log_reader", path)
    require(spec is not None and spec.loader is not None)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.download_log


def observe(env, review, guard, *, finished=False, evidence_sha=None, release_intent_sha=None):
    """Independently read the pinned frozen source and complete old evidence."""
    import production_backup_capacity as capacity
    import production_backup_head_harness as harness
    import production_backup_transaction as maintenance
    import production_lifecycle_drill as lifecycle
    import production_recovery as recovery
    from production_storage import PrivateStore

    spec = parsed(env["NO_EXPORT_VALIDATION_JSON"])
    local = dict(env)
    local.update(DRILL_REGISTRATION_SHA256=spec["registrationSha256"],
                 DRILL_BACKUP_SOURCE_CHECKPOINT_ID=spec["sourceCheckpointId"],
                 DRILL_BACKUP_SOURCE_MANIFEST_SHA256=spec["sourceManifestSha256"],
                 DRILL_BACKUP_GENESIS_SHA256=spec["genesisSha256"], DRILL_ACTION="daily-backup")
    tool = lifecycle.Drill(local, control_revision=spec["headSha"])
    tool.guard = guard
    guard()
    target, bundle, manifest = tool.prepare_maintenance()
    ctl = tool.bind(target, bundle, manifest)
    require(target.environment == "rehearsal" and target.data["workerName"] == lifecycle.SERVICE
            and target.digest == review["targetSha256"])
    state = ctl.inspect()
    harness.allowed_initial_state("backup", state)
    require(state["release"]["revision"] == manifest["revision"]
            and state["release"]["moduleSha256"] == manifest["bundleSha256"])
    old_run = github._get_json("/actions/runs/" + OLD_RUN + "/attempts/1", github._github_token())
    created = datetime.strptime(old_run["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    require(old_run.get("id") == int(OLD_RUN) and old_run.get("run_attempt") == 1
            and old_run.get("head_sha") == OLD_MAIN and old_run.get("status") == "completed")
    day = created.strftime("%Y/%m/%d")
    store = PrivateStore(ctl.data, target.data["backupBucketName"])
    store.verify()
    require(store.objects is not None, "A complete S3 inventory is required.")
    journal = maintenance.Transaction(store, OLD_RUN + "-1", day, target.digest, OLD_HEAD)
    events = journal.load()
    original = events[:5]
    require([item["stage"] for item in original] == ["started", "preflight", "frozen", "frozen-data", "capture-intent"]
            and len(events) == (6 if finished else 5)
            and sha256(canonical(original)).hexdigest() == review["oldTransactionSha256"]
            and events[0]["details"].get("checkpointId") == OLD_CHECKPOINT
            and events[4]["details"] == {"checkpointId": OLD_CHECKPOINT}
            and events[0]["details"].get("control") == state["control"]
            and events[0]["details"].get("release") == state["release"]
            and events[0]["details"].get("configurationSha256") == target.configuration_digest)
    anchor = maintenance.Anchor(store, target.digest, spec["genesisSha256"])
    pointer, raw, _etag = anchor.read()
    require(pointer["session"] == OLD_RUN + "-1" and pointer["day"] == day and pointer["controlRevision"] == OLD_HEAD)
    if finished:
        if release_intent_sha is None:
            release_key = ("maintenance/production-control/evidence/no-export-resolution/" + target.digest
                           + "/" + OLD_RUN + "-1/release-intent.json")
            release_intent_sha = sha256(store.get(release_key)).hexdigest()
        require(pointer["state"] == "idle" and pointer["generation"] == 7
                and pointer["previousSha256"] == review["oldAnchorSha256"]
                and events[5]["stage"] == "preserved-frozen"
                and events[5]["details"] == {"control": state["control"], "backupVerified": False,
                    "noExportEvidenceSha256": evidence_sha, "releaseIntentSha256": release_intent_sha,
                    "threatModel": review["threatModel"]})
    else:
        require(pointer["state"] == "active" and pointer["generation"] == 6
                and sha256(raw).hexdigest() == review["oldAnchorSha256"])
    contract = {"version": 1, "checkpointId": OLD_CHECKPOINT,
                "databaseName": "subs-bot-cf-restore-control-" + OLD_CHECKPOINT[:16],
                "objectsName": "subs-bot-cf-restore-control-" + OLD_CHECKPOINT[:16], "purpose": "baseline"}
    api = recovery.RecoveryAPI(target.data, env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], ctl.worker, contract)
    api.verify_backup()
    source = recovery.RecoverySource(api, target.data, bundle, manifest, ctl.inspect, guard)
    fingerprint = capacity.frozen_fingerprint(api, source)
    require(fingerprint == events[3]["details"])
    require(not store.objects.list(api.journal_prefix, maximum=10000)
            and not store.objects.list(api.archive_prefix, maximum=10000))
    tool.store.verify()
    require(tool.store.objects is not None
            and not tool.store.objects.list(tool.prefix + OLD_RUN + "-1-activation-baseline-", maximum=10000))
    after = ctl.inspect()
    harness.allowed_initial_state("backup", after)
    require(after["stateSha256"] == state["stateSha256"])
    plan = {"version": 1, "kind": "isolated-no-export-plan", "reviewSha256": sha256(canonical(review)).hexdigest(),
            "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
            "sourceCheckpointId": spec["sourceCheckpointId"], "sourceManifestSha256": spec["sourceManifestSha256"],
            "genesisSha256": spec["genesisSha256"], "originalRunId": OLD_RUN, "originalAttempt": "1",
            "oldTransactionSha256": review["oldTransactionSha256"], "oldAnchorSha256": review["oldAnchorSha256"],
            "frozenDataSha256": sha256(canonical(fingerprint)).hexdigest(), "stateSha256": state["stateSha256"],
            "writerInventorySha256": review["writerInventorySha256"], "custodySha256": review["custodySha256"],
            "threatModel": review["threatModel"], "exportDispatchedUnderCustodyAssumption": False}
    return tool, ctl, store, journal, anchor, state, plan


def historical_originals(review, spec, token, download_log):
    """Re-fetch every independently pinned source byte, never output its content."""
    result = {}
    for name, revision, field in (("candidate", OLD_HEAD, "candidateCodeSha256"),
                                  ("dispatcher", OLD_MAIN, "dispatcherCodeSha256")):
        files = review[field]
        require(isinstance(files, dict) and files)
        for path in sorted(files):
            entry = github._get_json("/contents/" + path + "?ref=" + revision, token)
            require(entry.get("path") == path and entry.get("type") == "file"
                    and entry.get("encoding") == "base64" and isinstance(entry.get("content"), str))
            raw = base64.b64decode(entry["content"].replace("\n", ""), validate=True)
            require(0 < len(raw) <= MAX_SOURCE and type(entry.get("size")) is int and entry["size"] == len(raw)
                    and sha256(raw).hexdigest() == files[path])
            result[name + "/" + path] = raw
    raw = download_log(OLD_JOB, token)
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_LOG
            and sha256(raw).hexdigest() == review["sourceLogSha256"] == OLD_LOG_SHA)
    found = []
    for line in raw.decode("utf-8-sig").splitlines():
        marker = "HEAD_VALIDATION_JSON: "
        if marker in line:
            found.append(json.loads(line.split(marker, 1)[1].strip()))
    require(len(found) == 4 and all(item == found[0] for item in found))
    original_spec = found[0]
    require(isinstance(original_spec, dict) and set(original_spec) == {"action", "approvalSha256", "checkpointId", "fault",
            "genesisSha256", "headSha", "manifestSha256", "pr", "registrationSha256", "sourceCheckpointId",
            "sourceManifestSha256", "version"} and type(original_spec.get("version")) is int
            and original_spec["version"] == 1 and original_spec["pr"] == "291"
            and original_spec["headSha"] == OLD_HEAD and original_spec["action"] == "backup"
            and original_spec["fault"] == "readback-failure"
            and all(original_spec[key] == spec[key] for key in
                    ("registrationSha256", "sourceCheckpointId", "sourceManifestSha256", "genesisSha256")))
    result["original-job-log"] = raw
    return result


def failed_plan_originals(token, download_log):
    """Preserve the separate, proven pre-candidate 100-item pagination failure."""
    run = github._get_json("/actions/runs/" + FAILED_PLAN_RUN + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + FAILED_PLAN_RUN, token)
    require(run.get("id") == latest.get("id") == int(FAILED_PLAN_RUN)
            and run.get("run_attempt") == latest.get("run_attempt") == 1
            and run.get("head_sha") == FAILED_PLAN_MAIN and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "failure")
            and latest.get("status") == "completed"
            and run.get("path") in {WORKFLOW, WORKFLOW + "@main", WORKFLOW + "@refs/heads/main"}
            and run.get("display_title") == "No-export plan at " + FAILED_PLAN_MAIN + " candidate " + FAILED_PLAN_HEAD
            and all(isinstance(run.get(key), dict) and run[key].get("id") == github.REPOSITORY_ID
                    for key in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + FAILED_PLAN_RUN + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and response.get("total_count") == len(jobs) == 2
            and {job.get("name") for job in jobs} == {"resolution", "readback"})
    selected = next(job for job in jobs if job.get("name") == "resolution")
    reader = next(job for job in jobs if job.get("name") == "readback")
    require(selected.get("id") == int(FAILED_PLAN_JOB) and selected.get("run_id") == int(FAILED_PLAN_RUN)
            and selected.get("run_attempt") == 1 and selected.get("head_sha") == FAILED_PLAN_MAIN
            and (selected.get("status"), selected.get("conclusion")) == ("completed", "failure")
            and reader.get("run_id") == int(FAILED_PLAN_RUN) and reader.get("run_attempt") == 1
            and reader.get("head_sha") == FAILED_PLAN_MAIN
            and (reader.get("status"), reader.get("conclusion")) == ("completed", "skipped"))
    expected = {2: ("Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "success"),
                3: (GATES[0], "failure"),
                4: ("Run actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", "skipped"),
                5: (GATES[1], "skipped"), 6: (GATES[2], "skipped"),
                7: ("Plan or apply the no-export resolution", "skipped")}
    steps = selected.get("steps")
    require(isinstance(steps, list))
    for number, (name, conclusion) in expected.items():
        matched = [step for step in steps if step.get("number") == number]
        require(len(matched) == 1 and matched[0].get("name") == name
                and (matched[0].get("status"), matched[0].get("conclusion")) == ("completed", conclusion))
    originals = {}
    for path, name, expected_sha in ((WORKFLOW, "known-preflight-failure-workflow.yml", FAILED_PLAN_WORKFLOW_SHA),
            ("worker/tools/trusted_backup_no_export_gate.py", "known-preflight-failure-gate.py", FAILED_PLAN_GATE_SHA)):
        entry = github._get_json("/contents/" + path + "?ref=" + FAILED_PLAN_MAIN, token)
        require(entry.get("path") == path and entry.get("type") == "file" and entry.get("encoding") == "base64")
        raw = base64.b64decode(entry.get("content", "").replace("\n", ""), validate=True)
        require(0 < len(raw) <= MAX_SOURCE and entry.get("size") == len(raw) and sha256(raw).hexdigest() == expected_sha)
        originals[name] = raw
    log_raw = download_log(FAILED_PLAN_JOB, token)
    require(isinstance(log_raw, bytes) and 0 < len(log_raw) <= MAX_LOG
            and sha256(log_raw).hexdigest() == FAILED_PLAN_LOG_SHA)
    marker = b"GitHub metadata read diagnostic "
    matches = [json.loads(line.split(marker, 1)[1]) for line in log_raw.splitlines() if marker in line]
    require(len(matches) == 1 and matches[0].get("family") == "other" and matches[0].get("phase") == "response"
            and matches[0].get("httpStatus") == 200)
    evidence = {"version": 1, "kind": "failed-plan-before-candidate", "runId": FAILED_PLAN_RUN,
                "attempt": "1", "jobId": FAILED_PLAN_JOB, "dispatcherRevision": FAILED_PLAN_MAIN,
                "controlRevision": FAILED_PLAN_HEAD, "workflowSha256": FAILED_PLAN_WORKFLOW_SHA,
                "gateSha256": FAILED_PLAN_GATE_SHA, "logSha256": FAILED_PLAN_LOG_SHA,
                "failure": "github-metadata-response-unconfirmed", "httpStatus": 200,
                "candidateCheckout": "skipped", "candidateExecution": "skipped"}
    originals.update({"known-preflight-failure-job-log": log_raw,
                      "known-preflight-failure-evidence.json": canonical(evidence)})
    return originals


def custody_original(env, review):
    raw = env.get("NO_EXPORT_CUSTODY_JSON", "")
    value = parsed(raw)
    require(isinstance(value, dict) and set(value) == {"version", "targetSha256", "writerInventorySha256",
            "auditWindowStart", "auditWindowEnd", "threatModel", "assertions"}
            and type(value["version"]) is int and value["version"] == 1
            and all(value[key] == review[key] for key in
                    ("targetSha256", "writerInventorySha256", "auditWindowStart", "auditWindowEnd", "threatModel"))
            and value["assertions"] == ["protected-environments-main-only", "reviewed-project-writers-only",
                "no-unapproved-object-writes-or-deletions", "no-concurrent-target-bucket-writers-during-resolution"]
            and canonical(value).decode() == raw and sha256(canonical(value)).hexdigest() == review["custodySha256"])
    return canonical(value)


def inventory_original(env, review):
    inventory = Path(env["RUNNER_TEMP"]) / "no-export-writer-inventory.json"
    require(inventory.is_file() and not inventory.is_symlink() and inventory.stat().st_size <= 1024 * 1024)
    raw = inventory.read_bytes()
    value = json.loads(raw)
    require(isinstance(value, list) and len(value) <= 500 and sha256(raw).hexdigest() == review["writerInventorySha256"]
            and canonical(value) == raw)
    return raw


def evidence_layout(plan_sha, originals, seal):
    """Canonical, bounded object names independent of untrusted paths."""
    require(SHA.fullmatch(plan_sha or "") and isinstance(originals, dict) and originals
            and isinstance(seal, dict) and set(seal) == {"runId", "runAttempt", "dispatcherRevision", "controlRevision"}
            and re.fullmatch(r"[1-9][0-9]{0,19}", seal["runId"] or "") and seal["runAttempt"] == "1"
            and all(re.fullmatch(r"[a-f0-9]{40}", seal[key] or "") for key in ("dispatcherRevision", "controlRevision")))
    records, pieces = [], {}
    for index, name in enumerate(sorted(originals), 1):
        raw = originals[name]
        require(isinstance(name, str) and isinstance(raw, bytes) and 0 < len(raw) <= MAX_LOG)
        chunks = []
        for pos in range(0, len(raw), CHUNK):
            part = raw[pos:pos + CHUNK]
            key = "objects/" + str(index).zfill(3) + "/" + str(pos // CHUNK + 1).zfill(3)
            chunks.append({"key": key, "bytes": len(part), "sha256": sha256(part).hexdigest()})
            pieces[key] = part
        records.append({"name": name, "bytes": len(raw), "sha256": sha256(raw).hexdigest(), "chunks": chunks})
    manifest = {"version": 1, "kind": "no-export-original-evidence", "planSha256": plan_sha,
                "originalRunId": OLD_RUN, "originalAttempt": "1", "originalJobId": OLD_JOB,
                "threatModel": "reviewed-writers-no-unapproved-deletion", "seal": seal, "originals": records}
    return manifest, pieces


def seal_originals(store, prefix, plan_sha, originals, seal, guard, stage_callback=None):
    """A single guarded claim, exact original chunks, and a final receipt."""
    manifest, pieces = evidence_layout(plan_sha, originals, seal)
    body = canonical(manifest)
    intent = canonical({"version": 1, "kind": "no-export-evidence-intent", "planSha256": plan_sha,
                        "manifestSha256": sha256(body).hexdigest()})
    if stage_callback:
        stage_callback("seal-intent")
    guard()
    store.put_exclusive(prefix + "evidence-intent.json", intent)
    if stage_callback:
        stage_callback("seal-chunks")
    for key, raw in pieces.items():
        guard()
        store.put_exclusive(prefix + key, raw)
    if stage_callback:
        stage_callback("seal-manifest")
    guard()
    store.put_exclusive(prefix + "evidence-manifest.json", body)
    return sha256(body).hexdigest()


def read_originals(store, prefix, plan_sha, originals, seal, evidence_sha):
    """Fresh runner compares every private byte to a fresh GH source download."""
    manifest, pieces = evidence_layout(plan_sha, originals, seal)
    body = canonical(manifest)
    require(SHA.fullmatch(evidence_sha or "") and sha256(body).hexdigest() == evidence_sha)
    expected_intent = canonical({"version": 1, "kind": "no-export-evidence-intent", "planSha256": plan_sha,
                                 "manifestSha256": evidence_sha})
    require(store.get(prefix + "evidence-intent.json") == expected_intent
            and store.get(prefix + "evidence-manifest.json") == body)
    for key, raw in pieces.items():
        require(store.get(prefix + key) == raw)
    return evidence_sha


def verify_jobs(run_id, main, candidate, action, *, in_readback=False):
    """Confirm the original jobs and gates, not just an artifact or SHA."""
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id or "") and action in {"seal", "release"})
    token = github._github_token()
    workflow = github._get_json("/actions/workflows/" + WORKFLOW.rsplit("/", 1)[1], token)
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(type(workflow.get("id")) is int and run.get("id") == int(run_id) and run.get("run_attempt") == 1
            and latest.get("id") == int(run_id) and latest.get("run_attempt") == 1
            and run.get("workflow_id") == workflow["id"] and run.get("event") == "workflow_dispatch"
            and run.get("head_branch") == "main" and run.get("head_sha") == main
            and run.get("display_title") == "No-export " + action + " at " + main + " candidate " + candidate
            and isinstance(run.get("repository"), dict) and run["repository"].get("id") == github.REPOSITORY_ID)
    if in_readback:
        require(run.get("status") == "in_progress")
    else:
        require(run.get("status") == "completed" and run.get("conclusion") == "success")
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(response.get("total_count") == 2 and isinstance(jobs, list) and len(jobs) == 2
            and {job.get("name") for job in jobs} == {"resolution", "readback"})
    for job in jobs:
        require(job.get("run_id") == int(run_id) and job.get("run_attempt") == 1 and job.get("head_sha") == main
                and isinstance(job.get("steps"), list))
        names = [step.get("name") for step in job["steps"]]
        expected = (*GATES, "Plan or apply the no-export resolution" if job["name"] == "resolution"
                    else "Independently verify no-export evidence")
        require(all(names.count(name) == 1 for name in expected))
        for name in expected:
            step = job["steps"][names.index(name)]
            if in_readback and job["name"] == "readback" and name == expected[-1]:
                require(job.get("status") == "in_progress" and step.get("status") == "in_progress")
            else:
                require(step.get("status") == "completed" and step.get("conclusion") == "success")
        if not (in_readback and job["name"] == "readback"):
            require(job.get("status") == "completed" and job.get("conclusion") == "success")


def verify_interrupted_writer(run_id, main, candidate, action):
    """Only a finished original writer with all trusted preflight gates is inspectable."""
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id or "") and action in {"seal", "release"})
    token = github._github_token()
    workflow = github._get_json("/actions/workflows/" + WORKFLOW.rsplit("/", 1)[1], token)
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(type(workflow.get("id")) is int and run.get("id") == latest.get("id") == int(run_id)
            and run.get("run_attempt") == latest.get("run_attempt") == 1 and run.get("workflow_id") == workflow["id"]
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main" and run.get("head_sha") == main
            and run.get("status") == latest.get("status") == "completed"
            and run.get("display_title") == "No-export " + action + " at " + main + " candidate " + candidate
            and isinstance(run.get("repository"), dict) and run["repository"].get("id") == github.REPOSITORY_ID)
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100)
    matches = [job for job in jobs if job.get("name") == "resolution"]
    require(len(matches) == 1)
    job = matches[0]
    require(job.get("run_id") == int(run_id) and job.get("run_attempt") == 1 and job.get("head_sha") == main
            and job.get("status") == "completed" and isinstance(job.get("steps"), list))
    steps = job["steps"]
    for name in (*GATES, "Plan or apply the no-export resolution"):
        found = [item for item in steps if item.get("name") == name]
        require(len(found) == 1 and found[0].get("status") == "completed")
        if name in GATES:
            require(found[0].get("conclusion") == "success")


def verify_seal_reader(run_id, seal_run, main, candidate, plan_sha, evidence_sha, download_log):
    """An independent successful verify-seal run must report these exact pins."""
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id or ""))
    token = github._github_token()
    workflow = github._get_json("/actions/workflows/" + WORKFLOW.rsplit("/", 1)[1], token)
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(type(workflow.get("id")) is int and run.get("id") == latest.get("id") == int(run_id)
            and run.get("run_attempt") == latest.get("run_attempt") == 1 and run.get("workflow_id") == workflow["id"]
            and run.get("event") == "workflow_dispatch" and run.get("head_branch") == "main" and run.get("head_sha") == main
            and (run.get("status"), run.get("conclusion")) == ("completed", "success")
            and latest.get("status") == "completed"
            and run.get("display_title") == "No-export verify-seal at " + main + " candidate " + candidate
            and isinstance(run.get("repository"), dict) and run["repository"].get("id") == github.REPOSITORY_ID)
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100)
    selected = [job for job in jobs if job.get("name") == "resolution"]
    require(len(selected) == 1)
    job = selected[0]
    require(type(job.get("id")) is int and job.get("run_id") == int(run_id) and job.get("run_attempt") == 1
            and job.get("head_sha") == main and (job.get("status"), job.get("conclusion")) == ("completed", "success"))
    for name in (*GATES, "Plan or apply the no-export resolution"):
        found = [item for item in job.get("steps", []) if item.get("name") == name]
        require(len(found) == 1 and (found[0].get("status"), found[0].get("conclusion")) == ("completed", "success"))
    raw = download_log(str(job["id"]), token)
    results = []
    for line in raw.decode("utf-8-sig").splitlines():
        pos = line.find("{")
        if pos >= 0:
            try:
                value = json.loads(line[pos:])
            except ValueError:
                continue
            if isinstance(value, dict) and value.get("status") == "seal-readback-confirmed":
                results.append(value)
    require(results == [{"status": "seal-readback-confirmed", "planSha256": plan_sha,
                         "evidenceSha256": evidence_sha, "sealRunId": seal_run}])


def output(name, value):
    require(name in {"plan_sha256", "evidence_sha256", "release_sha256"} and SHA.fullmatch(value or ""))
    filename = os.environ.get("GITHUB_OUTPUT", "")
    require(filename and Path(filename).is_file())
    with open(filename, "a", encoding="ascii") as stream:
        stream.write(name + "=" + value + "\n")


def run(env):
    """Run one fixed action; all original evidence and the source are re-read."""
    action = env.get("NO_EXPORT_ACTION", "")
    require(action in {"plan", "seal", "evidence-readback", "verify-seal", "release", "release-readback", "verify-release"})
    stage("gate")
    review = checked_gate(env)
    spec = parsed(env["NO_EXPORT_VALIDATION_JSON"])
    def guard():
        require(checked_gate(env) == review)
    seal_run = env.get("GITHUB_RUN_ID", "") if action in {"seal", "evidence-readback"} else env.get("NO_EXPORT_SEAL_RUN_ID", "")
    require(re.fullmatch(r"[1-9][0-9]{0,19}", seal_run or "") is not None or action == "plan")
    if action in {"verify-seal", "release", "release-readback", "verify-release"}:
        require(seal_run == env.get("SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID"))
        if action == "verify-seal":
            verify_interrupted_writer(seal_run, env["GITHUB_SHA"], spec["headSha"], "seal")
        else:
            reader_run = env.get("NO_EXPORT_SEAL_READER_RUN_ID", "")
            require(reader_run == env.get("SUBS_BOT_BACKUP_NO_EXPORT_SEAL_READER_RUN_ID", ""))
            if reader_run:
                verify_interrupted_writer(seal_run, env["GITHUB_SHA"], spec["headSha"], "seal")
                verify_seal_reader(reader_run, seal_run, env["GITHUB_SHA"], spec["headSha"],
                    env["NO_EXPORT_PLAN_SHA256"], env["NO_EXPORT_EVIDENCE_SHA256"], log_reader(env))
            else:
                verify_jobs(seal_run, env["GITHUB_SHA"], spec["headSha"], "seal")
    if action in {"verify-release"}:
        release_run = env.get("NO_EXPORT_RELEASE_RUN_ID", "")
        require(release_run == env.get("SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID"))
        verify_interrupted_writer(release_run, env["GITHUB_SHA"], spec["headSha"], "release")
    if action in {"evidence-readback", "release-readback", "verify-seal", "verify-release"}:
        require(not env.get("SUBS_BOT_SCOPED_R2_WRITE_JSON") and not env.get("SUBS_BOT_SCOPED_R2_EXTRA_WRITE_JSON"),
                "Independent readback must not receive private object write credentials.")
        if action in {"evidence-readback", "release-readback"}:
            verify_jobs(env["GITHUB_RUN_ID"], env["GITHUB_SHA"], spec["headSha"],
                        "seal" if action == "evidence-readback" else "release", in_readback=True)
    stage("originals")
    token = github._github_token()
    originals = historical_originals(review, spec, token, log_reader(env))
    originals.update(failed_plan_originals(token, log_reader(env)))
    originals["protected-custody.json"] = custody_original(env, review)
    originals["writer-inventory.json"] = inventory_original(env, review)
    seal = {"runId": seal_run, "runAttempt": "1", "dispatcherRevision": env["GITHUB_SHA"],
            "controlRevision": spec["headSha"]}
    prefix = "maintenance/production-control/evidence/no-export-resolution/" + review["targetSha256"] + "/" + OLD_RUN + "-1/"
    finished = action in {"release-readback", "verify-release"}
    evidence = (env.get("NO_EXPORT_SEAL_EVIDENCE_SHA256", "") if action == "evidence-readback"
                else env.get("NO_EXPORT_EVIDENCE_SHA256", ""))
    stage("observe")
    tool, ctl, store, journal, anchor, state, plan = observe(env, review, guard, finished=finished,
        evidence_sha=evidence)
    plan_sha = sha256(canonical(plan)).hexdigest()
    originals["resolution-plan.json"] = canonical(plan)
    originals["protected-review.json"] = canonical(review)
    if action == "plan":
        output("plan_sha256", plan_sha)
        return {"status": "planned", "planSha256": plan_sha, "mutationPerformed": False}
    require(plan_sha == env.get("NO_EXPORT_PLAN_SHA256") == env.get("NO_EXPORT_PROTECTED_PLAN_SHA256"))
    if action == "seal":
        _manifest, pieces = evidence_layout(plan_sha, originals, seal)
        stage("budget")
        require_request_budget(env, review, len(pieces) + 4)
        evidence = seal_originals(store, prefix, plan_sha, originals, seal, guard, stage_callback=stage)
        output("evidence_sha256", evidence)
        return {"status": "sealed", "planSha256": plan_sha, "evidenceSha256": evidence}
    stage("readback")
    read_originals(store, prefix, plan_sha, originals, seal, evidence)
    if action == "evidence-readback":
        return {"status": "evidence-readback-confirmed", "planSha256": plan_sha, "evidenceSha256": evidence}
    require(evidence == env.get("NO_EXPORT_PROTECTED_EVIDENCE_SHA256"))
    if action == "verify-seal":
        return {"status": "seal-readback-confirmed", "planSha256": plan_sha, "evidenceSha256": evidence,
                "sealRunId": seal_run}
    if action == "release":
        stage("budget")
        require_request_budget(env, review, 15)
        # Guard against ambiguous retries with a fixed per-original-session slot.
        intent = {"version": 1, "kind": "no-export-release-intent", "planSha256": plan_sha,
                  "evidenceSha256": evidence, "sealRunId": seal_run, "releaseRunId": env["GITHUB_RUN_ID"],
                  "releaseAttempt": "1", "dispatcherRevision": env["GITHUB_SHA"], "controlRevision": spec["headSha"],
                  "targetSha256": review["targetSha256"], "originalRunId": OLD_RUN, "originalAttempt": "1"}
        intent_raw = canonical(intent)
        intent_sha = sha256(intent_raw).hexdigest()
        stage("claim")
        guard()
        store.put_exclusive(prefix + "release-intent.json", intent_raw)
        tool, ctl, store, journal, anchor, state, next_plan = observe(env, review, guard)
        require(canonical(next_plan) == canonical(plan) and store.get(prefix + "release-intent.json") == intent_raw)
        def resolution_guard():
            guard()
            _tool, _ctl, checked_store, _journal, _anchor, _state, checked_plan = observe(env, review, guard)
            require(canonical(checked_plan) == canonical(plan)
                    and checked_store.get(prefix + "release-intent.json") == intent_raw)
            read_originals(checked_store, prefix, plan_sha, originals, seal, evidence)
        stage("append")
        journal.append_no_export({"control": state["control"], "backupVerified": False,
            "noExportEvidenceSha256": evidence, "releaseIntentSha256": intent_sha,
            "threatModel": review["threatModel"]}, int(time.time()), guard=resolution_guard)
        stage("anchor-cas")
        guard()
        pointer, raw, _etag = anchor.read()
        require(pointer["state"] == "active" and pointer["session"] == OLD_RUN + "-1"
                and sha256(raw).hexdigest() == review["oldAnchorSha256"]
                and ctl.inspect()["stateSha256"] == state["stateSha256"])
        anchor.release(OLD_RUN + "-1")
        _tool, _ctl, store, journal, anchor, _state, final_plan = observe(env, review, guard, finished=True,
            evidence_sha=evidence, release_intent_sha=intent_sha)
        require(canonical(final_plan) == canonical(plan))
        final_anchor, final_raw, _etag = anchor.read()
        receipt = {"version": 1, "kind": "no-export-release-complete", "intentSha256": intent_sha,
                   "planSha256": plan_sha, "evidenceSha256": evidence, "originalRunId": OLD_RUN,
                   "releaseRunId": env["GITHUB_RUN_ID"], "terminalJournalSha256": sha256(canonical(journal.load())).hexdigest(),
                   "anchorSha256": sha256(final_raw).hexdigest(), "backupVerified": False}
        require(final_anchor["state"] == "idle")
        stage("receipt")
        guard()
        receipt_raw = canonical(receipt)
        store.put_exclusive(prefix + "release-complete.json", receipt_raw)
        release_sha = sha256(receipt_raw).hexdigest()
        output("release_sha256", release_sha)
        return {"status": "released-awaiting-independent-readback", "releaseSha256": release_sha,
                "backupVerified": False}
    require(action in {"release-readback", "verify-release"})
    intent_raw = store.get(prefix + "release-intent.json")
    intent = parsed(intent_raw)
    require(canonical(intent) == intent_raw and intent == {"version": 1, "kind": "no-export-release-intent",
            "planSha256": plan_sha, "evidenceSha256": evidence, "sealRunId": seal_run,
            "releaseRunId": release_run if action == "verify-release" else env["GITHUB_RUN_ID"],
            "releaseAttempt": "1", "dispatcherRevision": env["GITHUB_SHA"],
            "controlRevision": spec["headSha"], "targetSha256": review["targetSha256"],
            "originalRunId": OLD_RUN, "originalAttempt": "1"})
    receipt_raw = store.get(prefix + "release-complete.json", absent=action == "verify-release")
    if receipt_raw is None:
        return {"status": "release-confirmed", "receiptPresent": False, "backupVerified": False}
    receipt = parsed(receipt_raw)
    _anchor, anchor_raw, _etag = anchor.read()
    require((action == "verify-release" or sha256(receipt_raw).hexdigest() == env.get("NO_EXPORT_RELEASE_SHA256"))
            and receipt == {"version": 1, "kind": "no-export-release-complete", "intentSha256": sha256(intent_raw).hexdigest(),
                "planSha256": plan_sha, "evidenceSha256": evidence, "originalRunId": OLD_RUN,
                "releaseRunId": release_run if action == "verify-release" else env["GITHUB_RUN_ID"],
                "terminalJournalSha256": sha256(canonical(journal.load())).hexdigest(),
                "anchorSha256": sha256(anchor_raw).hexdigest(), "backupVerified": False})
    return {"status": "release-confirmed" if action == "verify-release" else "release-readback-confirmed",
            "releaseSha256": sha256(receipt_raw).hexdigest(),
            "backupVerified": False}


def main():
    result = run(dict(os.environ))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        from production_lifecycle_drill import backup_error_kind
        print(json.dumps({"status": "stopped", "stage": CURRENT_STAGE,
                          "error": backup_error_kind(error)}, sort_keys=True))
        if os.environ.get("NO_EXPORT_ACTION") in {"verify-seal", "verify-release"}:
            print(json.dumps({"status": "unknown", "action": os.environ["NO_EXPORT_ACTION"],
                              "mutationPerformed": False}, sort_keys=True))
        print("::error::The isolated no-export resolution is not confirmed; preserve the original transaction.")
        raise SystemExit(1) from None

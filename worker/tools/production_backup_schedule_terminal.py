"""Bounded private evidence for one completed scheduled backup.

These routines do not authorize a write or certify a reader. The caller must
independently verify the fixed trusted fresh-reader job and its reviewed source
before accepting the returned evidence as a terminal witness.
"""
from hashlib import sha256
from datetime import datetime, timezone
import time
from collections.abc import Mapping

import prepare_isolation_artifact as artifact
import production_backup_cli as backup
import production_backup_coordinator as coordinator
import production_backup_schedule as schedule
from production_target import canonical, parsed, require

MAX_WITNESS = 8 * 1024 * 1024
MAX_RECORD = 65536
MAX_ARCHIVE = 2 * 1024 * 1024
MANUAL_START_FIELDS = {"version", "kind", "scopeSha256", "targetSha256", "configurationSha256", "targetDocument",
    "policy", "policySha256", "readerLogPolicy", "readerLogPolicySha256", "priorScopeKeysSha256", "targetCoordinatorGenesisSha256",
    "applicationGenesisSha256", "action", "approvalActionSha256", "approvalSha256", "predecessorSha256",
    "scopePredecessorSha256", "scopeAnchorSha256", "writerRunId", "writerAttempt", "day", "workflowRef",
    "controlRevision", "sourceRevision", "coordinatorSession"}


def witness_key(scope_sha256, day, *, profile="production"):
    return schedule.slot_key(scope_sha256, day, profile=profile).replace("-intent.json", "-witness.json")


def _sha(raw):
    return sha256(raw).hexdigest()


def _verify_job_marker(job_id, token, expected_sha256, marker):
    """Bind a fixed job's single public digest marker to private bytes."""
    import re
    from trusted_backup_webhook_log_archive import download_log

    require(isinstance(job_id, str) and coordinator.DECIMAL.fullmatch(job_id)
            and schedule.HEX.fullmatch(expected_sha256 or ""))
    raw = download_log(job_id, token)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError:
        require(False, "The original scheduled reader log is invalid.")
    require(marker in {"SCHEDULE_WITNESS_SHA256", "SCHEDULE_MANUAL_COMPLETE_SHA256"})
    pattern = re.compile(r"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z +)?" + marker + r"=([a-f0-9]{64})")
    candidates = [line for line in lines if marker + "=" in line]
    match = pattern.fullmatch(candidates[0]) if len(candidates) == 1 else None
    require(match is not None and match.group(1) == expected_sha256,
            "The original reader did not uniquely confirm this witness.")
    return True


def verify_reader_log(job_id, token, expected_sha256):
    return _verify_job_marker(job_id, token, expected_sha256, "SCHEDULE_WITNESS_SHA256")


def completion_writer(start, done):
    """A coordinator may close the original scope from its claimed continuation."""
    if "completionWriterRunId" not in done:
        require("completionAction" not in done)
        return start["writerRunId"], start["action"]
    run_id, action = done["completionWriterRunId"], done.get("completionAction")
    require(schedule.SESSION.fullmatch(run_id or "") and run_id != start["writerRunId"])
    if start["workflowRef"].endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF):
        require(start["action"] == "run" and action in {"resume", "abort"})
    else:
        require(start["workflowRef"].endswith("/worker-production-recovery.yml@" + artifact.MAIN_REF)
                and ((action == "poll-export" and start["action"] in {"capture", "poll-export"})
                     or (action == "start-import" and start["action"] == "start-import")))
    return run_id, action


def verify_manual_job(record, token, env, now, *, allow_expiring=False):
    """Independently verify one immutable manual scope result and its GH writer."""
    import production_backup_manual_scope as manual_scope

    start, done, result = record["start"], record["complete"], record["result"]
    run_id, action = completion_writer(start, done)
    revision, path = start["controlRevision"], start["workflowRef"]
    allowed = {artifact.REPOSITORY + "/" + value + "@" + artifact.MAIN_REF: value for value in manual_scope.WORKFLOWS}
    require(path in allowed)
    source_review = coordinator.historical_manual_source_review(env, revision)
    require(isinstance(source_review, dict) and source_review.get("revision") == revision)
    expected_path = allowed[path]
    original = artifact._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = artifact._get_json("/actions/runs/" + run_id, token)
    for run in (original, latest):
        require(str(run.get("id")) == run_id and run.get("run_attempt") == 1 and run.get("head_sha") == revision
                and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                and run.get("path") in {expected_path, expected_path + "@main", expected_path + "@refs/heads/main"}
                and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                and all(isinstance(run.get(key), dict) and run[key].get("id") == artifact.REPOSITORY_ID
                        for key in ("repository", "head_repository")),
                "The manual completion writer is not independently confirmed successful.")
        if run_id != start["writerRunId"] and expected_path == coordinator.PROFILES["production"]["parent"]:
            require(run.get("display_title") == coordinator.parent_title("production", action, revision, revision))
    response = artifact._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100
            and len({job.get("id") for job in jobs if isinstance(job, dict)}) == len(jobs))
    names = {".github/workflows/worker-production-backup.yml": ("checkpoint", "Run one explicitly selected production checkpoint"),
             ".github/workflows/worker-production-backup-coordinator.yml": ("coordinate", "Coordinate one explicitly approved operation"),
             ".github/workflows/worker-production-recovery.yml": ("recovery", "Verify identities and execute one production-aware checkpoint")}
    job_name, step_name = names[expected_path]
    if expected_path == ".github/workflows/worker-production-backup-coordinator.yml" and action not in {"run", "resume"}:
        job_name, step_name = "inspect_or_reconcile", "Inspect or reconcile without workflow dispatch"
    matching = [job for job in jobs if isinstance(job, dict) and job.get("name") == job_name]
    require(len(matching) == 1)
    job = matching[0]
    require(type(job.get("id")) is int and job["id"] > 0 and str(job.get("run_id")) == run_id
            and job.get("run_attempt") == 1 and job.get("head_sha") == revision
            and (job.get("status"), job.get("conclusion")) == ("completed", "success")
            and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == step_name]
    require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    retention = start["readerLogPolicy"]
    deadline = reader_log_deadlines(original.get("created_at"),
        {"readerLogRetentionDays": retention.get("retentionDays"), "readerLogWarningDays": retention.get("warningDays"),
         "readerLogStopBeforeDays": retention.get("stopBeforeDays")}, now)
    require(type(allow_expiring) is bool and (allow_expiring or not deadline["stop"]),
            "A required manual log is near its configured retention limit; stop new scheduled backups.")
    require(_verify_job_marker(str(job["id"]), token, record["completeSha256"], "SCHEDULE_MANUAL_COMPLETE_SHA256"))
    require(isinstance(done, dict) and isinstance(result, dict))
    if run_id != start["writerRunId"] and expected_path.endswith("/worker-production-recovery.yml"):
        require(result.get("action") == action and result.get("runId") == run_id and result.get("runAttempt") == "1"
                and result.get("controlRevision") == revision
                and result.get("phase") == ("captured" if action == "poll-export" else "verified"))
    return deadline


def reader_log_deadlines(created_at, authority, now):
    """Compute conservative operator-configured boundaries, not platform guarantees."""
    require(isinstance(created_at, str) and type(now) is int and now > 0)
    try:
        created = int(datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())
    except (ValueError, OverflowError, OSError):
        require(False, "The original reader retention start is unknown.")
    retention, warning, stop = (authority.get("readerLogRetentionDays"), authority.get("readerLogWarningDays"),
                                authority.get("readerLogStopBeforeDays"))
    require(0 < created <= now + 60 and type(retention) is int and 14 <= retention <= 400
            and type(stop) is int and 1 <= stop <= 30 and type(warning) is int
            and stop < warning < retention)
    expiry = created + retention * 86400
    return {"warning": now >= expiry - warning * 86400, "stop": now >= expiry - stop * 86400,
            "stopAt": expiry - stop * 86400}


def _read(objects, key, limit):
    raw, _ = objects.get(key, limit=limit)
    require(isinstance(raw, bytes) and 0 < len(raw) <= limit, "A scheduled witness original is missing or too large.")
    return raw


def _stage_originals(objects, target, session, sequence):
    return {
        "intent": _read(objects, coordinator.event_key(target, session, sequence), MAX_RECORD),
        "claim": _read(objects, coordinator.child_claim_key(target, session, sequence), MAX_RECORD),
        "receipt": _read(objects, coordinator.receipt_key(target, session, sequence), MAX_RECORD),
        "archive": _read(objects, coordinator.result_archive_key(target, session, sequence), MAX_ARCHIVE),
    }


def _hashes(originals):
    return {key: {"sha256": _sha(raw), "bytes": len(raw)} for key, raw in originals.items()}


def _phase_identity(objects, target, slot):
    require(isinstance(slot, dict) and isinstance(slot.get("authority"), dict)
            and target.environment in {"production", "rehearsal"} and target.digest == slot.get("targetSha256"))
    authority = slot["authority"]
    profile = target.environment
    require(authority.get("environment") == profile)
    schedule.read_slot(objects, authority, slot["authoritySha256"], slot["slotDay"], slot)
    candidate = authority["controlRevision"]
    dispatcher = candidate if profile == "production" else authority.get("dispatcherRevision")
    validation = slot.get("validationJson") if profile == "rehearsal" else None
    require(schedule.REV.fullmatch(candidate or "") and schedule.REV.fullmatch(dispatcher or "")
            and (profile == "rehearsal" or "validationJson" not in slot))
    checked = schedule.authority_document(canonical(authority), slot["authoritySha256"], target=target,
        control_revision=candidate, source_revision=authority.get("sourceRevision"),
        source_checkpoint_id=authority.get("sourceCheckpointId"), source_manifest_sha256=authority.get("sourceManifestSha256"),
        policy=slot["policy"], profile=profile,
        dispatcher_revision=dispatcher if profile == "rehearsal" else None,
        registration_sha256=authority.get("registrationSha256") if profile == "rehearsal" else None,
        validation_json=validation, target_genesis_sha256=authority.get("targetCoordinatorGenesisSha256"),
        application_genesis_sha256=authority.get("applicationGenesisSha256"))
    require(checked == authority)
    return profile, dispatcher, candidate, validation


def _phase_job_evidence(jobs, run_id, revision, profile):
    require(isinstance(jobs, dict) and isinstance(jobs.get("jobs"), list)
            and type(jobs.get("total_count")) is int and jobs["total_count"] == len(jobs["jobs"]) == 1)
    job = jobs["jobs"][0]
    name = "checkpoint" if profile == "production" else "phase"
    names = (["Run one explicitly selected production checkpoint"] if profile == "production" else
             ["Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
              "Verify isolated test Bot identity", "Execute one reviewed rehearsal phase"])
    require(isinstance(job, dict) and job.get("name") == name and type(job.get("id")) is int and job["id"] > 0
            and str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == revision
            and job.get("status") == "completed" and job.get("conclusion") == "success"
            and isinstance(job.get("steps"), list))
    indexes = []
    for name in names:
        matches = [(index, step) for index, step in enumerate(job["steps"])
                   if isinstance(step, dict) and step.get("name") == name]
        require(len(matches) == 1 and matches[0][1].get("status") == "completed"
                and matches[0][1].get("conclusion") == "success")
        indexes.append(matches[0][0])
    require(indexes == sorted(set(indexes)))


def collect_phase_evidence(objects, target, slot, token):
    """Fetch full live GH run originals after independently verifying all 11 phases."""
    profile, dispatcher, candidate, validation = _phase_identity(objects, target, slot)
    authority, policy = slot["authority"], slot["policy"]
    session = slot["session"]
    results, _ = coordinator.completed_results(objects, target.digest, session, dispatcher, token,
        authority["sourceCheckpointId"], authority["sourceManifestSha256"], backup.maximum_pause(policy),
        profile=profile, candidate_revision=candidate, validation_json=validation)
    require(len(results) == len(coordinator.STEPS) and results[-1].get("status") == "resumed"
            and results[-1].get("action") == "activate", "The complete backup phase chain is not successful.")
    expected_checkpoint = schedule.checkpoint_contract(authority, target, slot["slotDay"])["checkpointId"]
    verified = results[coordinator.STEPS.index("verify")]
    require(verified.get("checkpointId") == expected_checkpoint
            and schedule.HEX.fullmatch(verified.get("manifestSha256", "")),
            "The verified checkpoint differs from the scheduled slot.")
    child = coordinator.PROFILES[profile]["child"]
    workflow = artifact._get_json("/actions/workflows/" + child.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == child and type(workflow.get("id")) is int)
    stages = []
    for sequence, result in enumerate(results, 1):
        originals = _stage_originals(objects, target.digest, session, sequence)
        intent, receipt = parsed(originals["intent"]), parsed(originals["receipt"])
        require(canonical(intent) == originals["intent"] and canonical(receipt) == originals["receipt"]
                and result.get("sourceRevision") == authority["sourceRevision"]
                and receipt.get("result") == result and coordinator.archive_result(originals["archive"]) == result
                and originals["claim"] == canonical(coordinator.child_claim(intent, receipt.get("runId"), "1")))
        if sequence == 1:
            require(result.get("session") == receipt.get("runId", "") + "-1",
                    "The planned maintenance session does not belong to its exact child run.")
        run_id = receipt["runId"]
        run = artifact._get_json("/actions/runs/" + run_id + "/attempts/1", token)
        latest = artifact._get_json("/actions/runs/" + run_id, token)
        jobs = artifact._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
        require(str(latest.get("id")) == run_id and latest.get("run_attempt") == 1
                and latest.get("status") == "completed" and latest.get("conclusion") == "success"
                and all(latest.get(key) == run.get(key) for key in
                    ("head_sha", "head_branch", "event", "workflow_id"))
                and all(isinstance(latest.get(key), dict) and latest[key].get("id") == artifact.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
        coordinator.require_completed_receipt(intent, receipt, run, workflow["id"], result)
        _phase_job_evidence(jobs, run_id, dispatcher, profile)
        stages.append({"sequence": sequence, "originals": _hashes(originals), "run": run, "latest": latest, "jobs": jobs})
    value = {"version": 1, "kind": "scheduled-backup-phase-originals", "targetSha256": target.digest,
             "session": session, "slotDay": slot["slotDay"], "authoritySha256": slot["authoritySha256"],
             "workflow": workflow, "stages": stages}
    require(len(canonical(value)) <= MAX_WITNESS, "The bounded witness cannot preserve the complete originals.")
    return value


def verify_phase_evidence(objects, target, slot, value):
    """Re-read all retained private originals against an independently attested witness.

    This does not establish the provenance of the witness itself. A trusted
    fresh-reader job and its immutable code must be separately authenticated.
    """
    require(isinstance(value, dict) and set(value) == {"version", "kind", "targetSha256", "session", "slotDay",
            "authoritySha256", "workflow", "stages"} and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "scheduled-backup-phase-originals" and value["targetSha256"] == target.digest
            and value["session"] == slot["session"] and value["slotDay"] == slot["slotDay"]
            and value["authoritySha256"] == slot["authoritySha256"] and len(canonical(value)) <= MAX_WITNESS)
    profile, dispatcher, candidate, validation = _phase_identity(objects, target, slot)
    authority, policy = slot["authority"], slot["policy"]
    workflow, stages = value["workflow"], value["stages"]
    require(isinstance(workflow, dict) and workflow.get("path") == coordinator.PROFILES[profile]["child"]
            and type(workflow.get("id")) is int and isinstance(stages, list) and len(stages) == len(coordinator.STEPS))
    continuation = coordinator.scheduled_continuation(objects, slot) if profile == "production" else None
    results, pause_until = [], None
    for sequence, entry in enumerate(stages, 1):
        require(isinstance(entry, dict) and set(entry) == {"sequence", "originals", "run", "latest", "jobs"}
                and type(entry["sequence"]) is int and entry["sequence"] == sequence)
        originals = _stage_originals(objects, target.digest, slot["session"], sequence)
        require(_hashes(originals) == entry["originals"], "A retained scheduled phase original changed.")
        intent, receipt = parsed(originals["intent"]), parsed(originals["receipt"])
        result = receipt.get("result")
        require(canonical(intent) == originals["intent"] and canonical(receipt) == originals["receipt"]
                and isinstance(result, dict) and result.get("sourceRevision") == authority["sourceRevision"]
                and intent == coordinator.dispatch_intent(target=target.digest, session=slot["session"], sequence=sequence,
                    revision=dispatcher, nonce=intent.get("nonce"), input_sha256=intent.get("inputSha256"),
                    created_at=intent.get("createdAt"), writer_run_id=coordinator.scheduled_writer_id(slot, continuation, sequence),
                    profile=profile, candidate_revision=candidate)
                and originals["claim"] == canonical(coordinator.child_claim(intent, receipt.get("runId"), "1"))
                and receipt == coordinator.receipt(intent, receipt.get("runId"), result, receipt.get("artifactId"),
                                                   _sha(originals["archive"]))
                and coordinator.archive_result(originals["archive"]) == result)
        if sequence == 1:
            require(result.get("session") == receipt.get("runId", "") + "-1",
                    "The retained plan session does not belong to its exact child run.")
        inputs, pause_until = coordinator.stage_inputs(results, authority["sourceCheckpointId"], authority["sourceManifestSha256"],
            slot["session"], intent, backup.maximum_pause(policy), pause_until, validation_json=validation)
        require(schedule.digest(inputs) == intent["inputSha256"])
        latest = entry["latest"]
        require(isinstance(latest, dict) and str(latest.get("id")) == receipt.get("runId")
                and latest.get("run_attempt") == 1 and latest.get("status") == "completed"
                and latest.get("conclusion") == "success"
                and all(latest.get(key) == entry["run"].get(key) for key in
                    ("head_sha", "head_branch", "event", "workflow_id"))
                and all(isinstance(latest.get(key), dict) and latest[key].get("id") == artifact.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
        coordinator.require_completed_receipt(intent, receipt, entry["run"], workflow["id"], result)
        _phase_job_evidence(entry["jobs"], receipt["runId"], dispatcher, profile)
        results.append(result)
    expected = schedule.checkpoint_contract(authority, target, slot["slotDay"])["checkpointId"]
    verified = results[coordinator.STEPS.index("verify")]
    require(results[-1].get("status") == "resumed" and results[-1].get("action") == "activate"
            and verified.get("checkpointId") == expected and schedule.HEX.fullmatch(verified.get("manifestSha256", "")))
    return schedule.digest(value)


def read_witness_structure(objects, target, slot):
    """Read canonical originals; this alone does not authenticate the reader job."""
    profile = target.environment
    require(profile in {"production", "rehearsal"})
    raw_slot, _ = objects.get(schedule.slot_key(slot["scopeSha256"], slot["slotDay"], profile=profile), limit=MAX_RECORD)
    require(raw_slot == canonical(slot))
    terminal_raw = _read(objects, schedule.terminal_key(slot["scopeSha256"], slot["slotDay"], profile=profile), MAX_RECORD)
    value = parsed(terminal_raw)
    require(canonical(value) == terminal_raw and value == schedule.terminal_record(slot,
            chain_sha256=value.get("chainSha256"), scope_idle_anchor_sha256=value.get("scopeIdleAnchorSha256"),
            coordinator_idle_anchor_sha256=value.get("coordinatorIdleAnchorSha256"),
            result=value.get("result")))
    raw = _read(objects, witness_key(slot["scopeSha256"], slot["slotDay"], profile=profile), MAX_WITNESS)
    witness = backup.recovery.native.parsed(raw, MAX_WITNESS)
    require(canonical(witness) == raw and set(witness) == {"version", "kind", "scopeSha256", "targetSha256", "slotDay", "session",
            "slotSha256", "terminalSha256", "reviewSha256", "review", "parent", "phaseEvidence", "appTerminal"}
            and type(witness.get("version")) is int and witness["version"] == 1
            and witness["kind"] == "scheduled-backup-independent-witness"
            and witness["scopeSha256"] == slot["scopeSha256"]
            and witness["targetSha256"] == target.digest and witness["slotDay"] == slot["slotDay"]
            and witness["session"] == slot["session"] and witness["slotSha256"] == _sha(raw_slot)
            and witness["terminalSha256"] == _sha(terminal_raw) and isinstance(witness["review"], dict)
            and witness["reviewSha256"] == schedule.digest(witness["review"])
            and isinstance(witness["parent"], dict) and isinstance(witness["appTerminal"], dict)
            and value["chainSha256"] == verify_phase_evidence(objects, target, slot, witness["phaseEvidence"]),
            "The retained scheduled witness is missing, incomplete or inconsistent.")
    return {"witness": witness, "witnessSha256": _sha(raw), "terminal": value}


def collect_app_terminal(objects, app_store, target, slot, phase_evidence, app_genesis_sha256):
    """Read the exact verified/resumed app journal and its historical idle anchor."""
    require(app_genesis_sha256 == slot["authority"].get("applicationGenesisSha256"))
    verify_phase_evidence(objects, target, slot, phase_evidence)
    first = parsed(_read(objects, coordinator.receipt_key(target.digest, slot["session"], 1), MAX_RECORD))["result"]
    verification = parsed(_read(objects, coordinator.receipt_key(target.digest, slot["session"],
                          coordinator.STEPS.index("verify") + 1), MAX_RECORD))["result"]
    value = _app_terminal(app_store, target, first, verification, slot["authority"]["controlRevision"],
                          slot["authority"]["policySha256"], slot["authority"]["configurationSha256"], app_genesis_sha256)
    require(value["events"][0]["details"].get("release", {}).get("revision") == slot["authority"]["sourceRevision"])
    return value


def _app_terminal(app_store, target, first, verification, revision, policy_sha256, configuration_sha256, app_genesis_sha256):
    import production_backup_transaction as maintenance

    require(schedule.HEX.fullmatch(app_genesis_sha256 or ""))
    session, day = first["session"], first["day"]
    transaction = maintenance.Transaction(app_store, session, day, target.digest, revision)
    events = transaction.load()
    require(len(events) >= 3 and [event["stage"] for event in events[-3:]] == ["verified", "resume-intent", "resumed"]
            and events[0]["stage"] == "started"
            and events[0]["details"].get("checkpointId") == verification.get("checkpointId")
            and events[0]["details"].get("policySha256") == policy_sha256
            and events[0]["details"].get("configurationSha256") == configuration_sha256
            and events[0]["details"].get("control", {}).get("admission") == "open"
            and events[0]["details"].get("control", {}).get("workers") == "run"
            and events[-3]["details"].get("checkpointId") == verification.get("checkpointId")
            and events[-3]["details"].get("manifestSha256") == verification.get("manifestSha256")
            and (events[-1]["details"].get("backupVerified") is None
                 or events[-1]["details"].get("backupVerified") is True)
            and events[-1]["details"].get("control", {}).get("admission") == "open"
            and events[-1]["details"].get("control", {}).get("workers") == "run",
            "The exact verified backup was not independently confirmed resumed.")
    anchor = maintenance.Anchor(app_store, target.digest, app_genesis_sha256)
    pointer, raw, _etag = anchor.read()
    current, current_raw, releases = pointer, raw, []
    require(current["generation"] <= 10000)
    while current["generation"] > 1:
        if current["state"] == "idle" and current["session"] == session:
            require(current["day"] == day and current["controlRevision"] == revision)
            releases.append({"record": current, "sha256": _sha(current_raw)})
        prior = app_store.get(anchor.history_digest_key(current["generation"] - 1, current["previousSha256"]))
        require(isinstance(prior, bytes) and _sha(prior) == current["previousSha256"])
        current = parsed(prior)
        require(canonical(current) == prior)
        current_raw = prior
    require(len(releases) == 1, "The app maintenance release is missing or ambiguous.")
    final_pointer, final_raw, _etag = anchor.read()
    require(final_pointer == pointer and final_raw == raw and transaction.load() == events,
            "The app transaction changed during independent readback.")
    return {"version": 1, "session": session, "day": day, "appGenesisSha256": app_genesis_sha256,
            "events": events, "release": releases[0]}


def _coordinator_release(anchor, session, day, revision, active_sha256):
    pointer, raw, _etag = anchor.read()
    node, body, releases = pointer, raw, []
    while node["generation"] > 1:
        if node["state"] == "idle" and node["session"] == session + "-1":
            require(node["day"] == day and node["controlRevision"] == revision
                    and node["previousSha256"] == active_sha256)
            releases.append(_sha(body))
        body = anchor.store.get(anchor.history_digest_key(node["generation"] - 1, node["previousSha256"]))
        require(isinstance(body, bytes) and _sha(body) == node["previousSha256"])
        node = parsed(body)
        require(canonical(node) == body)
    require(len(releases) == 1, "The exact coordinator terminal anchor is unknown.")
    pointer_again, raw_again, _etag = anchor.read()
    require(pointer_again == pointer and raw_again == raw)
    return releases[0]


def verify_prior_history(objects, app_store, target, scope_anchor, token, env, authority_sha256,
                         app_genesis_sha256, target_genesis_sha256, policy):
    """Accept history only after fixed provenance, journal and anchor verification.

    Manual scope history is currently classified unknown. No result here
    authorizes a mutation by itself.
    """
    require((authority_sha256 is None or schedule.HEX.fullmatch(authority_sha256 or ""))
            and schedule.HEX.fullmatch(app_genesis_sha256 or ""))
    require(scope_anchor.genesis_sha256 == env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256")
            and target_genesis_sha256 == env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256")
            and app_genesis_sha256 == env.get("SUBS_BOT_BACKUP_GENESIS_SHA256"),
            "The independent scope, coordinator and application genesis pins are required.")
    coordinator.scheduled_review_document(env)  # Re-read the protected review and independent pin.
    inventory = scope_inventory(objects, target, scope_anchor, target_genesis_sha256, env=env)
    complete, log_warning, log_stop, log_stop_at = 0, False, False, None
    for record in inventory["records"]:
        if record["kind"] == "manual-needs-verification":
            manual = record["start"]
            require(not (manual["workflowRef"].endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF)
                         and manual["action"] in {"abort", "reconcile"}),
                    "A manual coordinator reconciliation needs its independent terminal proof.")
            deadline = verify_manual_job(record, token, env, int(time.time()), allow_expiring=authority_sha256 is None)
            log_warning = log_warning or deadline["warning"]
            log_stop = log_stop or deadline["stop"]
            log_stop_at = deadline["stopAt"] if log_stop_at is None else min(log_stop_at, deadline["stopAt"])
            require(_coordinator_release(scope_anchor, manual["writerRunId"], manual["day"], manual["controlRevision"],
                                         manual["scopeAnchorSha256"]) == record["complete"]["idleAnchorSha256"])
            if manual["workflowRef"].endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF) \
                    and manual["action"] in {"run", "resume"}:
                session = manual.get("coordinatorSession")
                require(schedule.SESSION.fullmatch(session or ""))
                old_target = record["target"]
                raw = _read(objects, coordinator.BASE + old_target.digest + "/" + session + "/start-intent.json", MAX_RECORD)
                start = parsed(raw)
                require(canonical(start) == raw and start.get("policySha256") == manual["policySha256"]
                        and start.get("controlRevision") == manual["controlRevision"])
                history = coordinator.finished_controller(objects, old_target.digest, session, manual["controlRevision"],
                    start["sourceCheckpointId"], start["sourceManifestSha256"], manual["policySha256"])
                end_run, end_action = completion_writer(manual, record["complete"])
                if end_run != manual["writerRunId"]:
                    require(history["writers"] and history["writers"][-1]["writerRunId"] == end_run
                            and history["writers"][-1]["action"] == end_action)
                if end_action == "abort":
                    result = record["result"]
                    require(result.get("status") == "abandoned-after-confirmed-terminal" and result.get("dispatchRetried") is False
                            and result.get("productionMutation") is False
                            and result.get("terminal") in {"no-mutating-child", "resumed", "preserved-frozen", "failed"}
                            and all(schedule.HEX.fullmatch(result.get(k, "")) for k in
                                    ("abortObservationSha256", "applicationAnchorSha256")))
                else:
                    results, _ = coordinator.completed_results(objects, old_target.digest, session, manual["controlRevision"], token,
                        start["sourceCheckpointId"], start["sourceManifestSha256"], backup.maximum_pause(manual["policy"]))
                    require(len(results) == len(coordinator.STEPS) and results[-1].get("status") == "resumed"
                            and results[-1].get("action") == "activate")
                    receipt = parsed(_read(objects, coordinator.receipt_key(old_target.digest, session, 1), MAX_RECORD))
                    source_revision = results[0].get("sourceRevision")
                    require(results[0].get("session") == receipt.get("runId", "") + "-1"
                            and schedule.REV.fullmatch(source_revision or "")
                            and all(result.get("sourceRevision") == source_revision for result in results))
                    app = _app_terminal(app_store, old_target, results[0], results[coordinator.STEPS.index("verify")],
                                        manual["controlRevision"], manual["policySha256"], manual["configurationSha256"],
                                        manual["applicationGenesisSha256"])
                    require(app["events"][0]["details"].get("release", {}).get("revision") == source_revision)
                target_items = coordinator.coordinator_anchor_history(record["targetAnchor"])
                matches = [item for item in target_items if item["session"] == session + "-1"]
                require(len(matches) == 1)
                _coordinator_release(record["targetAnchor"], session, matches[0]["day"], manual["controlRevision"],
                                     matches[0]["anchorSha256"])
            continue
        require(record["kind"] == "scheduled-needs-verification")
        slot = record["slot"]
        old_target = record["target"]
        stored = read_witness_structure(objects, old_target, slot)
        witness, terminal = stored["witness"], stored["terminal"]
        parent = witness["parent"]
        continuation = coordinator.scheduled_continuation(objects, slot)
        fields = {"originalRun", "latestRun", "jobs", "coordinateJobId", "readerJobId", "sourceReview"}
        if continuation is not None:
            fields |= {"continuation", "stoppedOriginalRun"}
        require(set(parent) == fields and isinstance(parent["originalRun"], dict)
                and isinstance(parent["latestRun"], dict) and isinstance(parent["jobs"], dict))
        revision = slot["authority"]["controlRevision"]
        require(coordinator.historical_schedule_source_review(env, revision, witness["review"], parent["sourceReview"]) is True)
        if continuation is None:
            observed = coordinator.verify_scheduled_parent(env, slot, mode="finished")
            writer_id = slot["writerRunId"]
        else:
            observed = coordinator.verify_scheduled_parent(env, slot, mode="finished", continuation=continuation)
            require(parent["continuation"] == observed["continuation"] == continuation
                    and parent["stoppedOriginalRun"] == observed["stoppedOriginalRun"])
            writer_id = continuation["writerRunId"]
        retention = reader_log_deadlines(observed["originalRun"].get("created_at"), slot["authority"], int(time.time()))
        require(authority_sha256 is None or not retention["stop"],
                "A required reader log is near its configured retention limit; stop new scheduled backups.")
        log_warning = log_warning or retention["warning"]
        log_stop = log_stop or retention["stop"]
        log_stop_at = retention["stopAt"] if log_stop_at is None else min(log_stop_at, retention["stopAt"])
        require(observed["coordinateJobId"] == parent["coordinateJobId"]
                and observed["readerJobId"] == parent["readerJobId"]
                and str(parent["originalRun"].get("id")) == writer_id
                and str(parent["latestRun"].get("id")) == writer_id
                and parent["originalRun"].get("head_sha") == revision
                and parent["latestRun"].get("head_sha") == revision
                and parent["originalRun"].get("run_attempt") == parent["latestRun"].get("run_attempt") == 1,
                "The saved reader evidence is not bound to the exact finished parent.")
        require(verify_reader_log(str(observed["readerJobId"]), token, stored["witnessSha256"]) is True)
        app = collect_app_terminal(objects, app_store, old_target, slot, witness["phaseEvidence"],
                                   slot["authority"]["applicationGenesisSha256"])
        require(app == witness["appTerminal"], "The independently verified app terminal changed.")
        require(_coordinator_release(record["targetAnchor"], slot["session"], slot["slotDay"].replace("-", "/"), revision,
                                     slot["coordinatorAnchorSha256"]) == terminal["coordinatorIdleAnchorSha256"])
        require(_coordinator_release(scope_anchor, slot["session"], slot["slotDay"].replace("-", "/"), revision,
                                     slot["scopeAnchorSha256"]) == terminal["scopeIdleAnchorSha256"])
        if slot["authoritySha256"] == authority_sha256:
            complete += 1
    return {"historyCount": inventory["historyCount"], "authorityExecutions": complete,
            "rotationWarning": inventory["rotationWarning"], "readerLogExpiryWarning": log_warning,
            "readerLogStopRequired": log_stop,
            "readerLogStopAt": log_stop_at, "scopeKeysSha256": inventory["scopeKeysSha256"],
            "coordinatorKeysSha256": inventory["coordinatorKeysSha256"],
            "scopeKeys": inventory["scopeKeys"], "coordinatorKeys": inventory["coordinatorKeys"]}


def scope_inventory(objects, target, scope_anchor, target_genesis_sha256, *, env=None):
    """Inventory all scheduled scope starts, including previous target configurations.

    Returned records require independent terminal and source verification.
    Unknown/manual scope-start formats deliberately block admission.
    """
    import re
    import production_backup_transaction as maintenance
    from production_target import validate_target

    scope = schedule.logical_scope(target)
    require(target.environment == "production" and type(scope_anchor) is coordinator.ScheduleScopeAnchor
            and scope_anchor.target_sha256 == scope
            and scope_anchor.bucket_name == target.data["backupBucketName"]
            and scope_anchor.bucket_created_at == target.data["backupBucketCreatedAt"]
            and schedule.HEX.fullmatch(target_genesis_sha256 or ""))
    pointer, pointer_raw, _etag = scope_anchor.read()
    require(pointer["state"] == "idle", "An active scope must be independently reconciled.")
    history = coordinator.coordinator_anchor_history(scope_anchor)
    require(len(history) <= 200, "The reviewed schedule scope history limit was reached.")
    history_by_session = {}
    for item in history:
        match = re.fullmatch(r"([1-9][0-9]{0,19})-1", item.get("session", ""))
        require(match is not None and match.group(1) not in history_by_session)
        history_by_session[match.group(1)] = item
    prefix = schedule.BASE + scope + "/"
    keys = objects.list(prefix, maximum=10000)
    require(isinstance(keys, list) and len(keys) < 10000 and len(set(keys)) == len(keys))
    starts, manual_files, slot_names = {}, {}, set()
    for key in keys:
        require(isinstance(key, str) and key.startswith(prefix))
        suffix = key[len(prefix):]
        match = re.fullmatch(r"sessions/([1-9][0-9]{0,19})-start\.json", suffix)
        if match:
            require(match.group(1) not in starts)
            starts[match.group(1)] = key
            continue
        match = re.fullmatch(r"manual/([1-9][0-9]{0,19})-(start|result|complete)\.json", suffix)
        if match:
            manual_files.setdefault(match.group(1), {})[match.group(2)] = key
            continue
        match = re.fullmatch(r"slots/([0-9]{4}-[0-9]{2}-[0-9]{2})-(intent|terminal|witness)\.json", suffix)
        require(match is not None, "An unclassified scope object requires inspection.")
        schedule._day(match.group(1))
        slot_names.add((match.group(1), match.group(2)))
    require(not set(starts) & set(manual_files)
            and set(starts) | set(manual_files) == set(history_by_session)
            and all(set(files) == {"start", "result", "complete"} for files in manual_files.values()),
            "A scope start, terminal or its anchor is missing or unconfirmed.")
    current_target_store = coordinator.CoordinatorStore(objects, target.digest)
    current_target_anchor = maintenance.Anchor(current_target_store, target.digest, target_genesis_sha256)
    target_genesis = current_target_store.get(current_target_anchor.genesis_key, absent=True)
    uninitialized = target_genesis is None
    if uninitialized:
        expected_genesis = current_target_anchor.initial_material()[1]
        require(isinstance(env, Mapping) and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
                and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
                and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and env.get("GITHUB_RUN_ATTEMPT") == "1" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
                and env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/.github/workflows/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF
                and env.get("BACKUP_COORDINATOR_ACTION") == "initialize"
                and env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256") == target_genesis_sha256
                and _sha(expected_genesis) == target_genesis_sha256 and not history and not starts and not manual_files
                and current_target_store.get_with_etag(current_target_anchor.key) == (None, None)
                and not current_target_store.list_backup_anchor_history(target.digest)
                and not current_target_store.list_backup_journals(),
                "An uninitialized target anchor needs the exact approved initialization path.")
        target_history = []
    else:
        current_target_pin, _raw, _etag = current_target_anchor.read()
        require(current_target_pin["state"] == "idle", "The current target coordinator remains active.")
        target_history = coordinator.coordinator_anchor_history(current_target_anchor)
    records, expected_days = [], set()
    target_histories = {target.digest: (target, current_target_anchor, target_history)}
    for session, files in sorted(manual_files.items()):
        raw_start = _read(objects, files["start"], MAX_RECORD)
        manual = parsed(raw_start)
        require(canonical(manual) == raw_start and set(manual) == MANUAL_START_FIELDS and type(manual["version"]) is int
                and manual["version"] == 1 and manual["kind"] == "manual-backup-scope-start"
                and manual["scopeSha256"] == scope and manual["writerRunId"] == session and manual["writerAttempt"] == "1"
                and isinstance(manual["policy"], dict) and schedule.digest(manual["policy"]) == manual["policySha256"]
                and isinstance(manual["readerLogPolicy"], dict)
                and set(manual["readerLogPolicy"]) == {"version", "retentionDays", "warningDays", "stopBeforeDays"}
                and type(manual["readerLogPolicy"].get("version")) is int and manual["readerLogPolicy"]["version"] == 1
                and schedule.digest(manual["readerLogPolicy"]) == manual["readerLogPolicySha256"]
                and all(schedule.HEX.fullmatch(manual.get(name, "")) for name in
                        ("approvalActionSha256", "approvalSha256", "predecessorSha256", "scopePredecessorSha256",
                         "scopeAnchorSha256", "priorScopeKeysSha256", "targetCoordinatorGenesisSha256", "applicationGenesisSha256"))
                and schedule.REV.fullmatch(manual["controlRevision"])
                and (manual["sourceRevision"] is None or schedule.REV.fullmatch(manual["sourceRevision"])))
        old_target = validate_target(manual["targetDocument"])
        is_coordinator = manual["workflowRef"].endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF)
        if is_coordinator and manual["action"] in {"run", "resume", "abort", "reconcile"}:
            require(schedule.SESSION.fullmatch(manual.get("coordinatorSession") or "")
                    and manual["sourceRevision"] is None)
        else:
            require(manual.get("coordinatorSession") is None and schedule.REV.fullmatch(manual["sourceRevision"] or ""))
        require(old_target.environment == "production" and schedule.logical_scope(old_target) == scope
                and old_target.digest == manual["targetSha256"] and old_target.configuration_digest == manual["configurationSha256"]
                and old_target.data["backupBucketName"] == target.data["backupBucketName"]
                and old_target.data["backupBucketCreatedAt"] == target.data["backupBucketCreatedAt"])
        hist = history_by_session[session]
        require(hist["anchorSha256"] == manual["scopeAnchorSha256"] and hist["previousSha256"] == manual["scopePredecessorSha256"]
                and hist["day"] == manual["day"] and hist["controlRevision"] == manual["controlRevision"])
        raw_result = _read(objects, files["result"], 256 * 1024)
        result = backup.recovery.native.parsed(raw_result, 256 * 1024)
        raw_done = _read(objects, files["complete"], MAX_RECORD)
        done = parsed(raw_done)
        require(isinstance(done, dict))
        end_run, end_action = completion_writer(manual, done)
        expected_done = {"version": 1, "kind": "manual-backup-scope-complete", "scopeSha256": scope,
                         "startSha256": _sha(raw_start), "idleAnchorSha256": done.get("idleAnchorSha256"),
                         "resultSha256": _sha(raw_result), "writerRunId": session, "writerAttempt": "1"}
        if end_run != session:
            expected_done.update(completionWriterRunId=end_run, completionAction=end_action)
            if end_action in {"poll-export", "start-import"}:
                from production_backup_manual_scope import recovery_writers_prefix
                prefix = recovery_writers_prefix(scope, session)
                continuations = objects.list(prefix, maximum=16)
                require(0 < len(continuations) < 16 and continuations ==
                        [prefix + str(n).zfill(4) + ".json" for n in range(1, len(continuations) + 1)])
                previous = _sha(raw_start)
                for key in continuations:
                    raw_writer = _read(objects, key, MAX_RECORD)
                    writer = parsed(raw_writer)
                    require(canonical(writer) == raw_writer and writer.get("kind") == "recovery-scope-continuation"
                            and writer.get("previousSha256") == previous and writer.get("action") == end_action
                            and schedule.SESSION.fullmatch(writer.get("writerRunId", ""))
                            and all(schedule.HEX.fullmatch(writer.get(name, "")) for name in ("contractSha256", "journalSha256")))
                    previous = _sha(raw_writer)
                require(writer["writerRunId"] == end_run)
        require(canonical(result) == raw_result and canonical(done) == raw_done and done == expected_done
                and schedule.HEX.fullmatch(done.get("idleAnchorSha256", "")))
        if old_target.digest not in target_histories:
            old_store = coordinator.CoordinatorStore(objects, old_target.digest)
            old_anchor = maintenance.Anchor(old_store, old_target.digest, manual["targetCoordinatorGenesisSha256"])
            current, _body, _etag = old_anchor.read()
            require(current["state"] == "idle", "A historical target coordinator remains active.")
            target_histories[old_target.digest] = (old_target, old_anchor, coordinator.coordinator_anchor_history(old_anchor))
        else:
            require(target_histories[old_target.digest][1].genesis_sha256 == manual["targetCoordinatorGenesisSha256"])
        records.append({"kind": "manual-needs-verification", "start": manual, "result": result, "complete": done,
                        "completeSha256": _sha(raw_done), "target": old_target,
                        "targetAnchor": target_histories[old_target.digest][1]})
    for session, key in sorted(starts.items()):
        start_raw = _read(objects, key, MAX_RECORD)
        start = parsed(start_raw)
        require(canonical(start) == start_raw and start.get("kind") == "scheduled-backup-scope-start"
                and start.get("profile") == "production" and start.get("scopeSha256") == scope
                and start.get("session") == session and start.get("writerRunId") == session)
        day = start.get("day")
        require(day not in expected_days, "A scheduled date has multiple scope claims.")
        expected_days.add(day)
        raw_slot = _read(objects, schedule.slot_key(scope, day), MAX_RECORD)
        slot = parsed(raw_slot)
        require(canonical(slot) == raw_slot and isinstance(slot.get("targetDocument"), dict))
        old_target = validate_target(slot["targetDocument"])
        require(old_target.environment == "production" and schedule.logical_scope(old_target) == scope
                and old_target.digest == slot.get("targetSha256") == start.get("targetSha256")
                and old_target.data["backupBucketName"] == target.data["backupBucketName"]
                and old_target.data["backupBucketCreatedAt"] == target.data["backupBucketCreatedAt"]
                and slot["authority"].get("ledgerGenesisSha256") == scope_anchor.genesis_sha256)
        slot_sha = schedule.read_slot(objects, slot["authority"], slot["authoritySha256"], day, slot)
        scope_item = history_by_session[session]
        require(slot_sha == _sha(raw_slot) and slot_sha == start.get("slotSha256")
                and slot["scopeAnchorSha256"] == scope_item["anchorSha256"] == start.get("scopeAnchorSha256")
                and scope_item["previousSha256"] == start.get("scopePredecessorSha256")
                and scope_item["day"] == day.replace("-", "/") and scope_item["controlRevision"] == start.get("controlRevision"))
        old_sha = old_target.digest
        if old_sha not in target_histories:
            old_store = coordinator.CoordinatorStore(objects, old_sha)
            old_anchor = maintenance.Anchor(old_store, old_sha, slot["authority"]["targetCoordinatorGenesisSha256"])
            current, _body, _etag = old_anchor.read()
            require(current["state"] == "idle", "A historical target coordinator remains active.")
            target_histories[old_sha] = (old_target, old_anchor, coordinator.coordinator_anchor_history(old_anchor))
        _target, target_anchor, target_history = target_histories[old_sha]
        require(target_anchor.genesis_sha256 == slot["authority"]["targetCoordinatorGenesisSha256"])
        matches = [item for item in target_history if item["session"] == session + "-1"]
        require(len(matches) == 1 and matches[0]["anchorSha256"] == slot["coordinatorAnchorSha256"]
                and matches[0]["anchorSha256"] == start.get("coordinatorAnchorSha256")
                and matches[0]["previousSha256"] == start.get("targetPredecessorSha256"))
        target_start_raw = _read(objects, coordinator.BASE + old_sha + "/" + session + "/start-intent.json", MAX_RECORD)
        require(_sha(target_start_raw) == start.get("targetStartSha256"))
        target_start = parsed(target_start_raw)
        target_fields = {"version", "action", "targetSha256", "controlRevision", "session", "sourceCheckpointId",
                         "sourceManifestSha256", "anchorSha256", "policySha256", "writerRunId", "writerAttempt",
                         "profile", "candidateRevision", "validationSha256", "authoritySha256", "slotDay", "slotSha256",
                         "scopePredecessorSha256"}
        require(canonical(target_start) == target_start_raw and set(target_start) == target_fields
                and type(target_start.get("version")) is int and target_start["version"] == 1
                and target_start.get("action") == "run" and target_start.get("profile") == "production"
                and target_start.get("validationSha256") is None and target_start.get("writerRunId") == session
                and target_start.get("writerAttempt") == "1" and target_start.get("slotDay") == day
                and target_start.get("controlRevision") == target_start.get("candidateRevision") == start.get("controlRevision")
                and target_start.get("sourceCheckpointId") == slot["authority"].get("sourceCheckpointId")
                and target_start.get("sourceManifestSha256") == slot["authority"].get("sourceManifestSha256")
                and target_start.get("policySha256") == slot["authority"].get("policySha256")
                and target_start.get("scopePredecessorSha256") == start.get("scopePredecessorSha256")
                and target_start.get("session") == session
                and target_start.get("targetSha256") == old_sha and target_start.get("slotSha256") == slot_sha
                and target_start.get("authoritySha256") == slot["authoritySha256"]
                and target_start.get("anchorSha256") == start["targetPredecessorSha256"])
        require(start == schedule.scope_start(slot["authority"], day, session=session,
            scope_predecessor_sha256=start.get("scopePredecessorSha256"),
            target_predecessor_sha256=start.get("targetPredecessorSha256"),
            scope_anchor_sha256=start.get("scopeAnchorSha256"), coordinator_anchor_sha256=start.get("coordinatorAnchorSha256"),
            slot_sha256=slot_sha, target_start_sha256=_sha(target_start_raw), writer_run_id=start.get("writerRunId"),
            writer_attempt=start.get("writerAttempt")))
        records.append({"kind": "scheduled-needs-verification", "slot": slot, "start": target_start,
                        "scopeStart": start, "scopeAnchor": scope_anchor, "targetAnchor": target_anchor,
                        "target": old_target})
    require({day for day, kind in slot_names if kind == "intent"} == expected_days
            and all(day in expected_days for day, _kind in slot_names), "An orphan schedule slot requires inspection.")
    records_by_session = {(record["slot"]["session"] if record["kind"] == "scheduled-needs-verification"
                           else record["start"]["writerRunId"]): record for record in records}
    require(len(records_by_session) == len(records))
    preceding_keys = []
    for item in history:
        session = item["session"][:-2]
        record = records_by_session[session]
        if record["kind"] == "manual-needs-verification":
            require(record["start"]["priorScopeKeysSha256"] == schedule.digest(sorted(preceding_keys)),
                    "The historical manual scope inventory differs from its original proof.")
            preceding_keys.extend(manual_files[session].values())
        else:
            day = record["slot"]["slotDay"]
            preceding_keys.append(starts[session])
            preceding_keys.extend(key for key in (schedule.slot_key(scope, day), schedule.terminal_key(scope, day),
                                                   witness_key(scope, day)) if key in keys)
    require(set(preceding_keys) == set(keys), "A scope evidence object is not bound to its ordered history.")
    all_coordinator_keys = objects.list(coordinator.BASE, maximum=10000)
    require(isinstance(all_coordinator_keys, list) and len(all_coordinator_keys) < 10000
            and len(set(all_coordinator_keys)) == len(all_coordinator_keys))
    for key in all_coordinator_keys:
        require(isinstance(key, str) and key.startswith(coordinator.BASE))
        match = re.match(r"([a-f0-9]{64})/", key[len(coordinator.BASE):])
        require(match is not None and match.group(1) in set(target_histories) | {scope},
                "An unclassified historical coordinator target requires inspection.")
        if match.group(1) == scope:
            allowed = {scope_anchor.store._key(scope_anchor.key), scope_anchor.store._key(scope_anchor.genesis_key)}
            history_root = scope_anchor.store._key("maintenance/production-control/evidence/daily-backup-anchor/" + scope + "/")
            require(key in allowed or re.fullmatch(re.escape(history_root) + r"[0-9]{12}-[a-f0-9]{64}\.json", key),
                    "An unclassified scope coordinator object requires inspection.")
    # Other target-anchor sessions require a separately authenticated manual history path.
    for _old_sha, (_old_target, _old_anchor, old_history) in target_histories.items():
        known = {record["slot"]["session"] + "-1" for record in records
                 if record["kind"] == "scheduled-needs-verification" and record["target"].digest == _old_sha}
        known.update(record["start"]["coordinatorSession"] + "-1" for record in records
                     if record["kind"] == "manual-needs-verification" and record["target"].digest == _old_sha
                     and record["start"]["action"] in {"run", "resume"}
                     and isinstance(record["start"].get("coordinatorSession"), str)
                     and schedule.SESSION.fullmatch(record["start"]["coordinatorSession"]))
        require(all(item["session"] in known for item in old_history),
                "A legacy manual coordinator session requires its separate verified proof.")
        target_root = coordinator.BASE + _old_sha + "/"
        target_keys = objects.list(target_root, maximum=10000)
        require(isinstance(target_keys, list) and len(target_keys) < 10000 and len(set(target_keys)) == len(target_keys))
        found_starts = set()
        for key in target_keys:
            require(isinstance(key, str) and key.startswith(target_root))
            suffix = key[len(target_root):]
            if suffix.startswith("coordination/"):
                allowed = {_old_anchor.store._key(_old_anchor.key), _old_anchor.store._key(_old_anchor.genesis_key)}
                history_root = _old_anchor.store._key("maintenance/production-control/evidence/daily-backup-anchor/" + _old_sha + "/")
                require(key in allowed or re.fullmatch(re.escape(history_root) + r"[0-9]{12}-[a-f0-9]{64}\.json", key))
                continue
            match = re.fullmatch(r"([1-9][0-9]{0,19})/(.+)", suffix)
            require(match is not None and match.group(1) + "-1" in known,
                    "An orphan target coordinator object requires inspection.")
            if match.group(2) == "start-intent.json":
                found_starts.add(match.group(1) + "-1")
            else:
                require(re.fullmatch(r"(?:0[1-9]|1[01])-(?:intent\.json|receipt\.json|child-claim\.json|result\.zip)|writers/[0-9]{4}\.json", match.group(2)))
        require(found_starts == known, "A target coordinator start is missing.")
    final_history = coordinator.coordinator_anchor_history(scope_anchor)
    final, final_raw, _etag = scope_anchor.read()
    require(final_history == history and final == pointer and final_raw == pointer_raw,
            "The scope history changed during inventory.")
    return {"records": records, "historyCount": len(history), "rotationWarning": len(history) >= 160,
            "scopeKeysSha256": schedule.digest(sorted(keys)),
            "coordinatorKeysSha256": schedule.digest(sorted(all_coordinator_keys)),
            "scopeKeys": sorted(keys), "coordinatorKeys": sorted(all_coordinator_keys)}


def _observe_manual_pending_inventory(objects, scope_anchor, start, run_id, *, complete_exists):
    """List the entire scope around one retained result without authorizing release."""
    import re
    import production_backup_manual_scope as manual_scope

    scope = start["scopeSha256"]
    prefix = schedule.BASE + scope + "/"
    keys = objects.list(prefix, maximum=10000)
    require(isinstance(keys, list) and keys == sorted(set(keys)) and len(keys) < 10000)
    own = {manual_scope.start_key(scope, run_id), manual_scope.result_key(scope, run_id)}
    if complete_exists:
        own.add(manual_scope.complete_key(scope, run_id))
    require(own <= set(keys) and schedule.digest([key for key in keys if key not in own]) == start["priorScopeKeysSha256"],
            "The original manual scope inventory is missing or changed.")
    starts, manuals, slots = set(), {}, {}
    for key in keys:
        require(key.startswith(prefix))
        suffix = key[len(prefix):]
        match = re.fullmatch(r"sessions/([1-9][0-9]{0,19})-start\.json", suffix)
        if match:
            require(match.group(1) not in starts)
            starts.add(match.group(1))
            continue
        match = re.fullmatch(r"manual/([1-9][0-9]{0,19})-(start|result|complete)\.json", suffix)
        if match:
            manuals.setdefault(match.group(1), set()).add(match.group(2))
            continue
        match = re.fullmatch(r"slots/([0-9]{4}-[0-9]{2}-[0-9]{2})-(intent|terminal|witness)\.json", suffix)
        require(match is not None, "An unclassified scope object requires inspection.")
        schedule._day(match.group(1))
        slots.setdefault(match.group(1), set()).add(match.group(2))
    expected_own = {"start", "result", "complete"} if complete_exists else {"start", "result"}
    require(manuals.get(run_id) == expected_own and all(
        fields == {"start", "result", "complete"} for session, fields in manuals.items() if session != run_id)
        and all(fields == {"intent", "terminal", "witness"} for fields in slots.values()))
    history = coordinator.coordinator_anchor_history(scope_anchor)
    history_sessions = [item["session"][:-2] for item in history if item.get("session", "").endswith("-1")]
    require(len(history) <= 200 and len(history_sessions) == len(history) == len(set(history_sessions))
            and set(history_sessions) == starts | set(manuals),
            "The complete scope inventory and immutable anchor history differ.")
    own_history = [item for item in history if item["session"] == run_id + "-1"]
    require(len(own_history) == 1 and own_history[0]["anchorSha256"] == start["scopeAnchorSha256"]
            and own_history[0]["previousSha256"] == start["scopePredecessorSha256"])
    require(objects.list(prefix, maximum=10000) == keys
            and coordinator.coordinator_anchor_history(scope_anchor) == history,
            "The scope inventory changed during independent observation.")
    return {"scopeKeysSha256": schedule.digest(keys), "historyCount": len(history),
            "requiresHistoricalTerminalVerification": True}


def plan_manual_result_reconciliation(objects, target, scope_anchor, token, env, run_id, *, _inspect_complete=False):
    """Observe one ended manual writer with a retained result; never authorize a write.

    The caller must additionally prove the complete scope inventory and exact
    application/target state under an independently approved reconciliation.
    """
    import re
    import production_backup_manual_scope as manual_scope

    scope = schedule.logical_scope(target)
    require(target.environment == "production" and type(scope_anchor) is coordinator.ScheduleScopeAnchor
            and scope_anchor.target_sha256 == scope and scope_anchor.genesis_sha256 == env.get("SUBS_BOT_BACKUP_SCHEDULE_SCOPE_GENESIS_SHA256")
            and scope_anchor.bucket_name == target.data["backupBucketName"]
            and scope_anchor.bucket_created_at == target.data["backupBucketCreatedAt"]
            and schedule.SESSION.fullmatch(run_id or ""))
    start_raw = _read(objects, manual_scope.start_key(scope, run_id), MAX_RECORD)
    start = parsed(start_raw)
    require(canonical(start) == start_raw and set(start) == MANUAL_START_FIELDS
            and type(start.get("version")) is int and start["version"] == 1
            and start.get("kind") == "manual-backup-scope-start"
            and start.get("scopeSha256") == scope and start.get("targetSha256") == target.digest
            and start.get("configurationSha256") == target.configuration_digest and start.get("targetDocument") == target.data
            and start.get("writerRunId") == run_id and start.get("writerAttempt") == "1"
            and isinstance(start.get("policy"), dict) and schedule.digest(start["policy"]) == start.get("policySha256")
            and isinstance(start.get("readerLogPolicy"), dict)
            and schedule.digest(start["readerLogPolicy"]) == start.get("readerLogPolicySha256")
            and all(schedule.HEX.fullmatch(start.get(key, "")) for key in
                    ("approvalActionSha256", "approvalSha256", "predecessorSha256", "priorScopeKeysSha256",
                     "applicationGenesisSha256", "targetCoordinatorGenesisSha256"))
            and schedule.REV.fullmatch(start.get("controlRevision", ""))
            and schedule.HEX.fullmatch(start.get("scopeAnchorSha256", ""))
            and schedule.HEX.fullmatch(start.get("scopePredecessorSha256", "")))
    result_raw = _read(objects, manual_scope.result_key(scope, run_id), 256 * 1024)
    result = backup.recovery.native.parsed(result_raw, 256 * 1024)
    require(canonical(result) == result_raw)
    complete, _etag = objects.get(manual_scope.complete_key(scope, run_id), absent=True)
    if _inspect_complete:
        require(isinstance(complete, bytes), "The original manual completion is absent.")
        done = parsed(complete)
        require(canonical(done) == complete and done == {"version": 1, "kind": "manual-backup-scope-complete",
                "scopeSha256": scope, "startSha256": _sha(start_raw), "idleAnchorSha256": done.get("idleAnchorSha256"),
                "resultSha256": _sha(result_raw), "writerRunId": run_id, "writerAttempt": "1"}
                and schedule.HEX.fullmatch(done.get("idleAnchorSha256", "")))
    else:
        require(complete is None, "A manual completion already exists; inspect it without replay.")
    # Recovery/G1 needs its own independently re-read journal and is not inferred
    # stopped merely from an unconfirmed result object.
    workflow = start.get("workflowRef", "")
    require(workflow.endswith("/worker-production-backup.yml@" + artifact.MAIN_REF)
            or workflow.endswith("/worker-production-backup-coordinator.yml@" + artifact.MAIN_REF),
            "This manual result needs a separate recovery-journal reconciliation.")
    if workflow.endswith("/worker-production-backup.yml@" + artifact.MAIN_REF):
        expected = {"initialize-anchor": "initialized", "begin": "started", "abort-unstarted": "aborted-before-pause",
                    "preflight": "observed", "abort-preflight": "aborted-before-pause", "pause": "paused",
                    "freeze": "frozen", "fingerprint": "frozen-data-confirmed", "capture": "captured-unverified",
                    "poll-export": "captured-unverified", "verify": "verified", "activate": "resumed",
                    "reconcile-transition": "reconciled", "resume-failed": "resumed-after-failure",
                    "anchor-reconcile": "anchor-release-reconciled"}
        require(start["action"] in expected and result.get("action") == start["action"]
                and result.get("status") == expected[start["action"]])
    else:
        require((start["action"] == "initialize" and result.get("status") == "initialized"
                 and result.get("mutationPerformed") is True)
                or (start["action"] in {"run", "resume"} and result.get("status") == "completed"
                    and result.get("verifiedCheckpoints") == len(coordinator.STEPS))
                or (start["action"] == "abort" and result.get("status") == "abandoned-after-confirmed-terminal")
                or (start["action"] == "reconcile" and result.get("status") == "reconciled"))
    revision = start["controlRevision"]
    source = coordinator.historical_manual_source_review(env, revision)
    require(isinstance(source, dict) and source.get("revision") == revision)
    original = artifact._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = artifact._get_json("/actions/runs/" + run_id, token)
    path = workflow[len(artifact.REPOSITORY) + 1:].removesuffix("@" + artifact.MAIN_REF)
    require(path in manual_scope.WORKFLOWS)
    for run in (original, latest):
        require(str(run.get("id")) == run_id and run.get("run_attempt") == 1 and run.get("head_sha") == revision
                and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                and run.get("path") in {path, path + "@main", path + "@refs/heads/main"}
                and run.get("status") == "completed" and run.get("conclusion") in {"success", "failure", "cancelled", "timed_out"}
                and all(isinstance(run.get(k), dict) and run[k].get("id") == artifact.REPOSITORY_ID
                        for k in ("repository", "head_repository")))
    jobs = artifact._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    if path.endswith("worker-production-backup.yml"):
        name, step_name = "checkpoint", "Run one explicitly selected production checkpoint"
    elif start.get("action") in {"run", "resume"}:
        name, step_name = "coordinate", "Coordinate one explicitly approved operation"
    else:
        name, step_name = "inspect_or_reconcile", "Inspect or reconcile without workflow dispatch"
    matching = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == name]
    require(len(matching) == 1)
    job = matching[0]
    require(type(job.get("id")) is int and job["id"] > 0 and str(job.get("run_id")) == run_id
            and job.get("run_attempt") == 1 and job.get("head_sha") == revision and job.get("status") == "completed"
            and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == step_name]
    require(len(steps) == 1 and steps[0].get("status") == "completed"
            and steps[0].get("conclusion") in {"success", "failure", "cancelled", "timed_out"})
    pointer, pointer_raw, _etag = scope_anchor.read()
    require(pointer.get("session") == run_id + "-1" and pointer.get("controlRevision") == revision
            and pointer.get("day") == start.get("day")
            and ((pointer.get("state") == "active" and _sha(pointer_raw) == start["scopeAnchorSha256"])
                 or (pointer.get("state") == "idle" and pointer.get("previousSha256") == start["scopeAnchorSha256"])),
            "The original scope write is not independently confirmed.")
    if pointer["state"] == "active":
        active = pointer
    else:
        active_raw = scope_anchor.store.get(scope_anchor.history_digest_key(pointer["generation"] - 1, start["scopeAnchorSha256"]))
        require(isinstance(active_raw, bytes) and _sha(active_raw) == start["scopeAnchorSha256"])
        active = parsed(active_raw)
        require(canonical(active) == active_raw)
    require(active.get("state") == "active" and active.get("session") == run_id + "-1"
            and active.get("day") == start.get("day") and active.get("controlRevision") == revision
            and active.get("previousSha256") == start["scopePredecessorSha256"],
            "The exact manual scope predecessor differs.")
    second, second_raw, _etag = scope_anchor.read()
    require(second == pointer and second_raw == pointer_raw)
    inventory = _observe_manual_pending_inventory(objects, scope_anchor, start, run_id, complete_exists=_inspect_complete)
    if _inspect_complete:
        require(pointer["state"] == "idle" and _sha(pointer_raw) == done["idleAnchorSha256"]
                and _verify_job_marker(str(job["id"]), token, _sha(complete), "SCHEDULE_MANUAL_COMPLETE_SHA256"),
                "The original completed scope evidence is not independently confirmed.")
    result = {"version": 1, "kind": "manual-completion-readback" if _inspect_complete else "manual-result-reconciliation-plan", "scopeSha256": scope,
            "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
            "runId": run_id, "runAttempt": "1", "jobId": str(job["id"]), "controlRevision": revision,
            "action": start["action"], "startSha256": _sha(start_raw), "resultSha256": _sha(result_raw),
            "scopeState": pointer["state"], "scopePointerSha256": _sha(pointer_raw),
            "scopeAnchorSha256": start["scopeAnchorSha256"], "scopeInventory": inventory,
            "requiresFullScopeInventory": True,
            "trustModel": "reviewed-writers-no-unapproved-deletion"}
    if _inspect_complete:
        result["completeSha256"] = _sha(complete)
    return result


def inspect_manual_completion(objects, target, scope_anchor, token, env, run_id):
    """Re-read an existing completion without creating or retrying any write."""
    return plan_manual_result_reconciliation(objects, target, scope_anchor, token, env, run_id, _inspect_complete=True)


def verify_manual_prior_history(objects, app_store, target, scope_anchor, token, env, run_id,
                                app_genesis_sha256, target_genesis_sha256, policy):
    """Revalidate prior terminals from a fixed, authenticated pre-claim view.

    This read-only view excludes only the exact current manual objects and its
    verified anchor generations. It does not authorize a release or mutation.
    """
    import production_backup_manual_scope as manual_scope

    scope = schedule.logical_scope(target)
    complete, _ = objects.get(manual_scope.complete_key(scope, run_id), absent=True)
    observed = plan_manual_result_reconciliation(objects, target, scope_anchor, token, env, run_id,
                                                   _inspect_complete=complete is not None)
    start_raw = _read(objects, manual_scope.start_key(scope, run_id), MAX_RECORD)
    start = parsed(start_raw)
    require(canonical(start) == start_raw and _sha(start_raw) == observed["startSha256"])
    pointer, pointer_raw, _etag = scope_anchor.read()
    require(_sha(pointer_raw) == observed["scopePointerSha256"])
    hidden = {manual_scope.start_key(scope, run_id), manual_scope.result_key(scope, run_id)}
    if complete is not None:
        hidden.add(manual_scope.complete_key(scope, run_id))
    if pointer["state"] == "active":
        active, active_raw = pointer, pointer_raw
    else:
        require(pointer["state"] == "idle" and pointer["previousSha256"] == start["scopeAnchorSha256"])
        active_raw = scope_anchor.store.get(scope_anchor.history_digest_key(pointer["generation"] - 1,
                                                                              start["scopeAnchorSha256"]))
        active = parsed(active_raw)
        require(canonical(active) == active_raw and _sha(active_raw) == start["scopeAnchorSha256"])
        hidden.add(scope_anchor.store._key(scope_anchor.history_key(pointer["generation"], pointer_raw)))
    require(active["state"] == "active" and active["session"] == run_id + "-1"
            and active["previousSha256"] == start["scopePredecessorSha256"] and active["generation"] > 1)
    hidden.add(scope_anchor.store._key(scope_anchor.history_key(active["generation"], active_raw)))
    previous_raw = scope_anchor.store.get(scope_anchor.history_digest_key(active["generation"] - 1,
                                                                           start["scopePredecessorSha256"]))
    previous = parsed(previous_raw)
    require(canonical(previous) == previous_raw and _sha(previous_raw) == start["scopePredecessorSha256"]
            and previous.get("state") == "idle" and previous.get("generation") == active["generation"] - 1)
    pointer_key = scope_anchor.store._key(scope_anchor.key)

    class PriorReadView:
        def get(self, key, *, absent=False, limit=16 * 1024 * 1024):
            if key == pointer_key:
                require(len(previous_raw) <= limit)
                return previous_raw, '"historical-read-only"'
            require(key not in hidden, "A current manual object is unavailable in the prior read-only view.")
            return objects.get(key, absent=absent, limit=limit)

        def list(self, prefix, *, maximum=10000):
            rows = objects.list(prefix, maximum=maximum)
            return [key for key in rows if key not in hidden]

    view = PriorReadView()
    old_anchor = coordinator.ScheduleScopeAnchor(coordinator.CoordinatorStore(view, scope), scope,
        scope_anchor.genesis_sha256, scope_anchor.bucket_name, scope_anchor.bucket_created_at)
    history = verify_prior_history(view, app_store, target, old_anchor, token, env, None,
                                   app_genesis_sha256, target_genesis_sha256, policy)
    require(history["scopeKeysSha256"] == start["priorScopeKeysSha256"])
    latest = plan_manual_result_reconciliation(objects, target, scope_anchor, token, env, run_id,
                                                 _inspect_complete=complete is not None)
    require(latest == observed, "The manual scope changed during historical verification.")
    return {"version": 1, "kind": "manual-prior-history-observation", "scopeSha256": scope,
            "runId": run_id, "startSha256": observed["startSha256"], "scopePointerSha256": observed["scopePointerSha256"],
            "priorScopeKeysSha256": history["scopeKeysSha256"], "historyCount": history["historyCount"],
            "historicalVerificationComplete": True, "mutationAuthorized": False}

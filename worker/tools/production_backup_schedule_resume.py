"""Explicit continuation from the original scheduled slot and child results."""
from hashlib import sha256
import time

import prepare_isolation_artifact as github
import production_backup_cli as backup
import production_backup_coordinator as coordinator
import production_backup_schedule as schedule
import production_backup_schedule_claim as claim
import production_backup_schedule_terminal as terminal
import production_backup_transaction as transaction
from production_target import canonical, digest, parsed, require


def _completed_parts(objects, target, slot, token):
    """Read the contiguous completed prefix and, at most, its one pending receipt."""
    authority, session = slot["authority"], slot["session"]
    revision, source = authority["controlRevision"], authority["sourceCheckpointId"]
    source_sha = authority["sourceManifestSha256"]
    limit = backup.maximum_pause(slot["policy"])
    statuses = [coordinator.inspect_stage(objects, target.digest, session, n)
                for n in range(1, len(coordinator.STEPS) + 1)]
    completed_count = 0
    for status in statuses:
        if status["status"] != "receipt-needs-independent-run-verification":
            break
        completed_count += 1
    completed, pause_until = coordinator.completed_results(objects, target.digest, session, revision, token,
        source, source_sha, limit, stop_before=completed_count + 1)
    require(len(completed) == completed_count)
    for n in range(1, completed_count + 1):
        intent, _ = objects.get(coordinator.event_key(target.digest, session, n))
        require(parsed(intent)["writerRunId"] == slot["writerRunId"],
                "A previous scheduled continuation requires independent reconciliation.")
    if completed_count == len(statuses):
        return completed, None, pause_until
    suffix = statuses[completed_count:]
    require(all(status["status"] == "not-recorded" for status in suffix[1:]),
            "There is evidence after the first unresolved checkpoint.")
    if suffix[0]["status"] == "not-recorded":
        return completed, None, pause_until
    require(suffix[0]["status"] == "unknown")
    raw, _ = objects.get(coordinator.event_key(target.digest, session, completed_count + 1))
    intent = parsed(raw)
    inputs, pause_until = coordinator.stage_inputs(completed, source, source_sha, session, intent, limit, pause_until)
    require(canonical(intent) == raw and intent["writerRunId"] == slot["writerRunId"]
            and intent["controllerRevision"] == intent["candidateRevision"] == revision and intent["profile"] == "production"
            and digest(inputs) == intent["inputSha256"])
    path = coordinator.PROFILES["production"]["child"]
    workflow = github._get_json("/actions/workflows/" + path.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == path and type(workflow.get("id")) is int)
    run = coordinator.discover_run(intent, workflow["id"], token)
    require((run.get("status"), run.get("conclusion")) == ("completed", "success"),
            "The pending child lacks a confirmed successful original; preserve the scope and do not re-dispatch.")
    result, proof, archive = coordinator.selected_result(str(run["id"]), revision, intent["action"], token)
    receipt = coordinator.receipt(intent, str(run["id"]), result, proof["artifactId"], proof["artifactSha256"])
    coordinator.require_completed_receipt(intent, receipt, run, workflow["id"], result)
    coordinator.verify_child_claim(objects, intent, str(run["id"]))
    require(result.get("sourceRevision") == authority["sourceRevision"])
    return completed + [result], (intent, run, workflow["id"], result, proof, archive), pause_until


def _active_predecessor(anchor, slot, sha, *, allow_released=False):
    node, raw, _ = anchor.read()
    released = node["state"] == "idle"
    if released:
        require(allow_released and node["previousSha256"] == sha and node["generation"] > 1)
        saved = anchor.store.get(anchor.history_digest_key(node["generation"] - 1, sha))
    else:
        saved = raw
    active = parsed(saved)
    require(canonical(active) == saved and sha256(saved).hexdigest() == sha
            and active["state"] == "active" and active["session"] == node["session"] == slot["session"] + "-1"
            and active["day"] == node["day"] == slot["slotDay"].replace("-", "/")
            and active["controlRevision"] == node["controlRevision"] == slot["authority"]["controlRevision"],
            "The exact original scheduled scope no longer owns this target.")
    return active, digest(node), released


def observe(env, target, objects, app_store, target_anchor, policy, token):
    authority, pin = claim.protected_authority(env, target, policy)
    require(authority["validFrom"] <= int(time.time()) < authority["validUntil"],
            "The original schedule authority has expired; preserve the incident for independent reconciliation.")
    scope, session = authority["scopeSha256"], env.get("BACKUP_COORDINATOR_SESSION", "")
    require(coordinator.DECIMAL.fullmatch(session or ""))
    scope_anchor = coordinator.ScheduleScopeAnchor(coordinator.CoordinatorStore(objects, scope), scope,
        authority["ledgerGenesisSha256"], target.data["backupBucketName"], target.data["backupBucketCreatedAt"])
    key = coordinator.BASE + target.digest + "/" + session + "/start-intent.json"
    raw_start, _ = objects.get(key)
    start = parsed(raw_start)
    require(canonical(start) == raw_start and start.get("session") == start.get("writerRunId") == session
            and start.get("authoritySha256") == pin)
    raw_slot, _ = objects.get(schedule.slot_key(scope, start["slotDay"]))
    slot = parsed(raw_slot)
    require(canonical(slot) == raw_slot and schedule.read_slot(objects, authority, pin, start["slotDay"], slot) == start["slotSha256"]
            and slot["session"] == session and slot["targetSha256"] == target.digest)
    require(coordinator.scheduled_continuation(objects, slot) is None,
            "A continuation already has a durable claim; no automatic replay is permitted.")
    scope_active, scope_sha, scope_idle = _active_predecessor(scope_anchor, slot, slot["scopeAnchorSha256"], allow_released=True)
    target_active, target_sha, target_idle = _active_predecessor(target_anchor, slot, slot["coordinatorAnchorSha256"],
                                                                 allow_released=True)
    scope_start_sha = backup.verify_schedule_scope_start(objects, target, start, raw_start, slot)
    scope_start, _ = objects.get(schedule.scope_start_key(scope, session))
    require(sha256(scope_start).hexdigest() == scope_start_sha)
    original = coordinator.stopped_scheduled_writer(slot, token)
    completed, pending, pause_until = _completed_parts(objects, target, slot, token)
    phase_count = len(completed)
    require(not scope_idle or target_idle)
    if target_idle:
        require(phase_count == len(coordinator.STEPS) and pending is None)
    if phase_count == len(coordinator.STEPS):
        require(completed[-1]["status"] == "resumed")
    else:
        next_step = coordinator.next_inputs(completed, source_checkpoint_id=authority["sourceCheckpointId"],
                                            source_manifest_sha256=authority["sourceManifestSha256"])["action"]
        now = int(time.time())
        if phase_count <= coordinator.STEPS.index("pause"):
            require(schedule.eligible_slot(authority, policy, now) == slot["slotDay"],
                    "A new pause cannot start outside the original approved slot.")
        if next_step in {"freeze", "capture"}:
            require(pause_until and now < pause_until, "The pause deadline passed; preserve the confirmed state for explicit recovery.")
    app_store.verify()
    app_anchor = transaction.Anchor(app_store, target.digest, authority["applicationGenesisSha256"])
    app, app_raw, _ = app_anchor.read()
    if phase_count < 2:
        require(app["state"] == "idle")
    else:
        first = completed[0]
        require(app["session"] == first["session"] and app["day"] == first["day"]
                and app["controlRevision"] == authority["controlRevision"]
                and app["state"] == ("idle" if phase_count == len(coordinator.STEPS) else "active"))
        events = transaction.Transaction(app_store, app["session"], app["day"], target.digest, app["controlRevision"]).load()
        expected = ("started", "preflight", "preflight", "paused", "paused", "frozen-data",
                    "capture-intent", "verified", "verified", "resumed")
        require(events and events[-1]["stage"] == expected[phase_count - 2],
                "The durable application checkpoint differs from the confirmed child results.")
    scope_keys = objects.list(schedule.BASE + scope + "/", maximum=10000)
    require(len(scope_keys) < 10000 and len(set(scope_keys)) == len(scope_keys)
            and schedule.slot_key(scope, slot["slotDay"]) in scope_keys
            and schedule.scope_start_key(scope, session) in scope_keys
            and (scope_idle or schedule.terminal_key(scope, slot["slotDay"]) not in scope_keys)
            and terminal.witness_key(scope, slot["slotDay"]) not in scope_keys)
    plan = {"version": 1, "kind": "scheduled-backup-resume-plan", "targetSha256": target.digest,
            "configurationSha256": target.configuration_digest, "session": session,
            "slotSha256": digest(slot), "controlRevision": env["GITHUB_SHA"],
            "scopePointerSha256": scope_sha, "targetPointerSha256": target_sha,
            "appPointerSha256": sha256(app_raw).hexdigest(), "scopeKeysSha256": digest(sorted(scope_keys)),
            "stoppedWriterConclusion": original["conclusion"], "phaseResultsSha256": digest(completed),
            "phaseCount": phase_count, "targetReleased": target_idle, "scopeReleased": scope_idle,
            "pendingIntentSha256": digest(pending[0]) if pending else None,
            "pendingArtifactSha256": pending[4]["artifactSha256"] if pending else None}
    material = {"slot": slot, "scopeStart": parsed(scope_start), "targetStart": start,
                "scopeActive": scope_active, "targetActive": target_active}
    return plan, scope_anchor, material, scope_keys, pending


def resume_scheduled(env, target, objects, app_store, target_anchor, policy, token):
    action = env.get("BACKUP_COORDINATOR_ACTION", "")
    require(env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and action in {"plan-resume-scheduled", "resume-scheduled"})
    args = (env, target, objects, app_store, target_anchor, policy, token)
    plan, scope_anchor, material, keys, pending = observe(*args)
    plan_sha = digest(plan)
    if action == "plan-resume-scheduled":
        return {"status": "planned", "planSha256": plan_sha, "verifiedCheckpoints": plan["phaseCount"],
                "mutationPerformed": False}
    require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == plan_sha and objects.write_credential is not None,
            "Independent approval of the exact scheduled continuation is required.")
    slot = material["slot"]
    record = {"version": 1, "kind": "scheduled-backup-continuation", "slotSha256": digest(slot),
              "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": "1", "firstSequence": plan["phaseCount"] + 1,
              "planSha256": plan_sha}
    require(observe(*args)[0] == plan, "The approved continuation observation changed.")
    job = coordinator.scheduled_running_parent(env, slot, token, continuation=record)
    github.require_current_main(env["GITHUB_SHA"])
    key = coordinator.BASE + target.digest + "/" + plan["session"] + "/writers/0001.json"
    objects.put_once(key, canonical(record))
    require(coordinator.scheduled_continuation(objects, slot) == record)
    owner = coordinator.ScheduledScopeOwner(env, target, objects, scope_anchor, target_anchor, material, keys, job,
                                            continuation=record)
    owner.guard(target_released=plan["targetReleased"], scope_released=plan["scopeReleased"])
    if pending is not None:
        intent, run, workflow_id, result, proof, archive = pending
        again = coordinator.discover_run(intent, workflow_id, token)
        repeated = coordinator.selected_result(str(again["id"]), env["GITHUB_SHA"], intent["action"], token)
        require(again == run and repeated == (result, proof, archive))
        owner.guard()
        coordinator.confirm_stage(objects, intent, run, workflow_id, result, proof, archive)
    if plan["targetReleased"]:
        return coordinator.finish_scheduled_sequence(owner, app_store, token, scope_released=plan["scopeReleased"])
    return claim.run_owned_schedule(owner, app_store, token)

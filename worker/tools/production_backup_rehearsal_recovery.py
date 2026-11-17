"""Read-only planning and one-shot recovery for a registered rehearsal phase.

This entry runs only under the reviewed trusted-main dispatcher. It never
redelivers an uncertain request and cannot synthesize production approval.
"""
from hashlib import sha256
import os
from pathlib import Path
import re

import prepare_isolation_artifact as github
import production_backup_cli as backup
import production_backup_coordinator as core
import production_backup_rehearsal_phase as rehearsal
from production_target import canonical, digest, parsed, require

RECOVERY_FILE = ".github/workflows/worker-backup-phase-recovery.yml"
PAIRS = {"plan-resume-failed": "resume-failed", "plan-reconcile-transition": "reconcile-transition",
         "plan-abort-unstarted": "abort-unstarted"}


def require_recovery_result(action, status, pinned, events, state, app_session, day):
    require(isinstance(pinned, dict) and pinned.get("session") == app_session and pinned.get("day") == day
            and isinstance(events, list) and events and isinstance(state.get("control"), dict))
    last = events[-1]
    if action == "resume-failed":
        require(status == "resumed-after-failure" and pinned.get("state") == "idle" and last.get("stage") == "resumed"
                and last["details"].get("backupVerified") is False
                and last["details"].get("control") == state["control"]
                and state["control"].get("admission") == "open" and state["control"].get("workers") == "run")
    elif action == "abort-unstarted":
        require(status == "aborted-before-pause" and pinned.get("state") == "idle" and len(events) == 2
                and events[0].get("stage") == "started" and events[0]["details"].get("reconciledUnstarted") is True
                and last.get("stage") == "failed" and last["details"].get("uncertain") is False)
    else:
        require(action == "reconcile-transition" and status == "reconciled"
                and last.get("stage") in {"paused", "frozen", "resumed"}
                and last["details"].get("reconciled") is True and last["details"].get("control") == state["control"]
                and pinned.get("state") == ("idle" if last["stage"] == "resumed" else "active"))


def require_owned_writer(objects, target, session, main, candidate, spec, policy, raw_spec, writer, plan, *, mode):
    history = core.finished_controller(objects, target, session, main, spec["sourceCheckpointId"],
        spec["sourceManifestSha256"], digest(policy), profile="rehearsal", candidate_revision=candidate,
        validation_sha=sha256(raw_spec.encode()).hexdigest(), current_writer=writer, current_mode=mode)
    require(history["writers"] and history["writers"][-1] == writer)
    previous = {"startSha256": history["startSha256"], "lastSha256": writer["previousSha256"],
                "writers": history["writers"][:-1]}
    require(digest(previous) == plan["writerHistorySha256"], "The prior coordinator writer chain changed.")
    return history


def require_live_recovery_job(env, main, candidate, session, token):
    """Fail before claiming a slot if the current hosted job is not observable."""
    run_id = env.get("GITHUB_RUN_ID", "")
    require(rehearsal.DECIMAL.fullmatch(run_id or "") and env.get("GITHUB_RUN_ATTEMPT") == "1")
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    latest = github._get_json("/actions/runs/" + run_id, token)
    require(str(run.get("id")) == str(latest.get("id")) == run_id and run.get("run_attempt") == latest.get("run_attempt") == 1
            and run.get("status") == latest.get("status") == "in_progress" and run.get("head_sha") == main
            and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("path") in {RECOVERY_FILE, RECOVERY_FILE + "@main", RECOVERY_FILE + "@refs/heads/main"}
            and run.get("display_title") == "Rehearsal backup recovery " + env["BACKUP_ACTION"] + " at " + main
                + " candidate " + candidate + " session " + session
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(response.get("jobs"), list) and type(response.get("total_count")) is int
            and response["total_count"] == len(response["jobs"]) < 100)
    jobs = [job for job in response["jobs"] if isinstance(job, dict) and job.get("name") == "recovery"]
    require(len(jobs) == 1 and str(jobs[0].get("run_id")) == run_id and jobs[0].get("run_attempt") == 1
            and jobs[0].get("head_sha") == main and jobs[0].get("status") == "in_progress")
    for name in ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                 "Verify isolated recovery test Bot identity", "Plan or execute one reviewed recovery phase"):
        steps = [step for step in jobs[0].get("steps", []) if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) ==
                (("in_progress", None) if name == "Plan or execute one reviewed recovery phase" else ("completed", "success")))


def stopped_children(objects, target, session, main, candidate, spec, policy, token):
    """Inventory every dispatched child; missing or in-flight evidence is unknown."""
    path = core.PROFILES["rehearsal"]["child"]
    workflow = github._get_json("/actions/workflows/" + path.rsplit("/", 1)[-1], token)
    require(workflow.get("path") == path and type(workflow.get("id")) is int)
    verified, seen, stopped = [], [], False
    for sequence in range(1, len(core.STEPS) + 1):
        status = core.inspect_stage(objects, target, session, sequence)
        if status["status"] == "not-recorded":
            require(all(core.inspect_stage(objects, target, session, later)["status"] == "not-recorded"
                        for later in range(sequence + 1, len(core.STEPS) + 1)))
            break
        require(not stopped, "A later phase exists after an unconfirmed child.")
        raw, _ = objects.get(core.event_key(target, session, sequence))
        intent = parsed(raw)
        require(canonical(intent) == raw and intent.get("controllerRevision") == main
                and intent.get("candidateRevision") == candidate and intent.get("profile") == "rehearsal")
        prior, pause_until = core.completed_results(objects, target, session, main, token,
            spec["sourceCheckpointId"], spec["sourceManifestSha256"], backup.maximum_pause(policy),
            stop_before=sequence, profile="rehearsal", candidate_revision=candidate,
            validation_json=spec["validation_json"])
        require(prior == verified and len(prior) == sequence - 1)
        expected, _ = core.stage_inputs(prior, spec["sourceCheckpointId"], spec["sourceManifestSha256"],
            session, intent, backup.maximum_pause(policy), pause_until, validation_json=spec["validation_json"])
        require(digest(expected) == intent["inputSha256"], "A dispatched child's predecessor inputs differ.")
        run = core.discover_run(intent, workflow["id"], token)
        run_id = str(run["id"])
        latest = github._get_json("/actions/runs/" + run_id, token)
        require(run.get("status") == latest.get("status") == "completed" and latest.get("run_attempt") == 1
                and str(latest.get("id")) == run_id and isinstance(run.get("conclusion"), str),
                "A dispatched child or later attempt has not independently stopped.")
        claim_sha = core.verify_child_claim(objects, intent, run_id, "1")
        jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
        require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
                and jobs["total_count"] == len(jobs["jobs"]) < 100)
        selected = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "phase"]
        require(len(selected) == 1 and str(selected[0].get("run_id")) == run_id
                and selected[0].get("run_attempt") == 1 and selected[0].get("head_sha") == main
                and selected[0].get("status") == "completed" and isinstance(selected[0].get("steps"), list))
        for name in ("Verify trusted phase identity before candidate checkout", "Verify exact reviewed phase checkout",
                     "Verify isolated test Bot identity"):
            steps = [step for step in selected[0]["steps"] if isinstance(step, dict) and step.get("name") == name]
            require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
        execution = [step for step in selected[0]["steps"] if isinstance(step, dict)
                     and step.get("name") == "Execute one reviewed rehearsal phase"]
        require(len(execution) == 1 and execution[0].get("status") == "completed")
        if status["status"] == "unknown":
            stopped = True
        else:
            verified, _ = core.completed_results(objects, target, session, main, token,
                spec["sourceCheckpointId"], spec["sourceManifestSha256"], backup.maximum_pause(policy),
                stop_before=sequence + 1, profile="rehearsal", candidate_revision=candidate,
                validation_json=spec["validation_json"])
            require(len(verified) == sequence)
        seen.append({"sequence": sequence, "runId": run_id, "conclusion": run["conclusion"],
                     "intentSha256": sha256(raw).hexdigest(), "claimSha256": claim_sha})
    return {"children": seen, "verified": verified}


class RecoveryRuntime(rehearsal.RehearsalPhaseRuntime):
    """Use explicit rehearsal approval without impersonating an old child."""
    def intent_metadata(self, state):
        require(isinstance(getattr(self, "recovery_claim", None), dict)
                and isinstance(getattr(self, "recovery_slot", None), str))
        return {"stateSha256": state["stateSha256"], "control": state["control"],
                "runId": self.env["GITHUB_RUN_ID"], "runAttempt": "1", "controlRevision": self.controller_revision,
                "dispatcherRevision": self.dispatcher_revision, "dispatcherWorkflow": RECOVERY_FILE.rsplit("/", 1)[1],
                "recoverySlot": self.recovery_slot, "recoveryClaimSha256": digest(self.recovery_claim)}

    def require_finished(self, details, *, allowed_actions=None):
        if details.get("dispatcherWorkflow") != RECOVERY_FILE.rsplit("/", 1)[1]:
            return super().require_finished(details, allowed_actions=allowed_actions)
        require(isinstance(getattr(self, "recovery_history", None), dict) and self.store.objects is not None
                and details.get("controlRevision") == self.controller_revision
                and details.get("dispatcherRevision") == self.dispatcher_revision
                and details.get("runAttempt") == "1" and rehearsal.DECIMAL.fullmatch(details.get("runId", ""))
                and rehearsal.HEX64.fullmatch(details.get("recoveryClaimSha256", "")))
        history = self.recovery_history
        writers = [item for item in history["writers"] if item.get("action") == "recovery"
                   and item.get("writerRunId") == details["runId"] and item.get("writerAttempt") == "1"]
        require(len(writers) == 1 and writers[0].get("recoveryAction") == "resume-failed"
                and (allowed_actions is None or "resume-failed" in allowed_actions))
        slot = details.get("recoverySlot", "")
        expected_prefix = core.BASE + self.target.digest + "/" + self.recovery_session + "/recovery/"
        require(isinstance(slot, str) and slot.startswith(expected_prefix)
                and re.fullmatch(r"[1-9][0-9]{0,19}-1-[0-9]{4}-intent\.json", slot[len(expected_prefix):]))
        raw, _ = self.store.objects.get(slot)
        claim = parsed(raw)
        require(canonical(claim) == raw and sha256(raw).hexdigest() == details["recoveryClaimSha256"]
                and claim.get("writer") == writers[0] and claim.get("writerRunId") == details["runId"]
                and claim.get("writerAttempt") == "1" and claim.get("planSha256") == digest(claim.get("plan"))
                and claim["planSha256"] == writers[0].get("recoveryPlanSha256")
                and claim["plan"].get("action") == writers[0].get("recoveryAction")
                and claim["plan"].get("coordinatorSession") == self.recovery_session
                and claim["plan"].get("targetSha256") == self.target.digest
                and claim["plan"].get("dispatcherRevision") == self.dispatcher_revision
                and claim["plan"].get("candidateRevision") == self.controller_revision
                and type(claim["plan"].get("journalLength")) is int
                and slot[len(expected_prefix):] == claim["plan"].get("applicationSession", "") + "-"
                    + str(claim["plan"]["journalLength"]).zfill(4) + "-intent.json")
        return True


def main(env=None):
    import production_recovery as recovery
    from production_storage import PrivateStore

    env = dict(os.environ if env is None else env)
    if env.get("BACKUP_RECOVERY_MODE") == "readback":
        return readback(env)
    require(env.get("BACKUP_RECOVERY_MODE", "execute") == "execute")
    action = env.get("BACKUP_ACTION", "")
    inverse = {value: key for key, value in PAIRS.items()}
    require(action in PAIRS or action in inverse)
    gate_env = {**env, "BACKUP_GATE_ROLE": "recovery", "BACKUP_CHECKOUT_PHASE": "ready"}
    def guard():
        rehearsal.verify_trusted_gate(gate_env)
    guard()
    raw_spec = env.get("HEAD_VALIDATION_JSON", "")
    spec = parsed(raw_spec)
    require(canonical(spec).decode("utf-8") == raw_spec)
    main_sha, candidate = env["GITHUB_SHA"], spec["headSha"]
    context = rehearsal.prepare_coordinator_context(env, spec, guard=guard)
    tool, target, policy, contract = context["tool"], context["target"], context["policy"], context["contract"]
    store, objects = context["store"], context["store"].objects
    session = env.get("BACKUP_COORDINATOR_SESSION", "")
    app_session, day = env.get("BACKUP_SESSION", ""), env.get("BACKUP_SESSION_DAY", "")
    require(rehearsal.DECIMAL.fullmatch(session or "") and backup.maintenance.SESSION.fullmatch(app_session or "")
            and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", day or ""))
    token = github._github_token()
    options = {"profile": "rehearsal", "candidate_revision": candidate,
               "validation_sha": sha256(raw_spec.encode()).hexdigest()}
    history = core.finished_controller(objects, target.digest, session, main_sha, spec["sourceCheckpointId"],
                                        spec["sourceManifestSha256"], digest(policy), **options)
    original_raw, _ = objects.get(core.BASE + target.digest + "/" + session + "/start-intent.json")
    require(sha256(original_raw).hexdigest() == history["startSha256"])
    start = parsed(original_raw)
    inventory_spec = {**spec, "validation_json": raw_spec}
    children = stopped_children(objects, target.digest, session, main_sha, candidate, inventory_spec, policy, token)
    require(children["verified"] and children["verified"][0].get("session") == app_session
            and children["verified"][0].get("day") == day,
            "The application session is not the exact verified original plan.")
    ctl = tool.bind(target, context["bundle"], context["manifest"])
    context["controller"] = ctl
    window = rehearsal.verify_owned_webhook_window(context, start, main_sha, candidate)
    state = ctl.inspect()
    api = recovery.RecoveryAPI(target.data, env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), ctl.worker, contract)
    api.verify_backup()
    source = recovery.RecoverySource(api, target.data, context["bundle"], context["manifest"], ctl.inspect, guard)
    source.archive_body, source.code_proof = context["archive"], context["proof"]
    local = dict(env)
    local["SUBS_BOT_BACKUP_GENESIS_SHA256"] = spec["genesisSha256"]
    local["SUBS_BOT_CF_DATA_TOKEN"] = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    runtime = RecoveryRuntime(target, controller_revision=candidate, dispatcher_revision=main_sha,
                              source_revision=context["proof"]["revision"], env=local, guard=guard)
    runtime.store, runtime.recovery_history, runtime.recovery_session = store, history, session
    planned_action = action if action in PAIRS else inverse[action]
    plan_result = backup.execute_phase(action=planned_action, env=local, target=target, revision=candidate,
        policy=policy, contract=contract, proof=context["proof"], state=state, store=store,
        guard=guard, bounded_guard=guard, ctl=ctl, source=source, api=api,
        directory=Path(env["RUNNER_TEMP"]), runtime=runtime)
    require(plan_result.get("status") == "plan-only" and rehearsal.HEX64.fullmatch(plan_result.get("stateSha256", "")))
    anchor = backup.maintenance.Anchor(store, target.digest, spec["genesisSha256"])
    anchor_raw, _etag = store.get_with_etag(anchor.key)
    require(isinstance(anchor_raw, bytes))
    txn = backup.maintenance.Transaction(store, app_session, day, target.digest, candidate)
    events = txn.load()
    plan = {"version": 1, "action": PAIRS[planned_action], "targetSha256": target.digest,
            "dispatcherRevision": main_sha, "candidateRevision": candidate, "coordinatorSession": session,
            "applicationSession": app_session, "day": day, "sourceCheckpointId": spec["sourceCheckpointId"],
            "sourceManifestSha256": spec["sourceManifestSha256"], "policySha256": digest(policy),
            "contractSha256": digest(contract), "writerHistorySha256": digest(history), "childrenSha256": digest(children),
            "webhookWindowSha256": digest(window), "anchorSha256": sha256(anchor_raw).hexdigest(),
            "journalSha256": digest(events), "journalLength": len(events), "phasePlan": plan_result}
    plan_sha = digest(plan)
    if action in PAIRS:
        return {"status": "planned", "action": action, "planSha256": plan_sha,
                "stateSha256": plan_result["stateSha256"], "mutationPerformed": False}
    require(env.get("SUBS_BOT_BACKUP_PHASE_RECOVERY_WRITES_ENABLED") == "true"
            and env.get("BACKUP_RECOVERY_PLAN_SHA256") == plan_sha
            and env.get("SUBS_BOT_BACKUP_PHASE_RECOVERY_APPROVAL_SHA256") == plan_sha
            and env.get("GITHUB_RUN_ATTEMPT") == "1")
    # Until the separate readback and recovery-origin reconciliation are fully
    # linked, no automatic recovery mutation may be issued.
    require(False, "Recovery execution is disabled pending the independent readback path.")

    # Both the global writer generation and the original application stage
    # are claimed once. The slot deliberately does not contain the plan SHA:
    # a changed plan cannot authorize repeating an unknown external operation.
    require(main({**env, "BACKUP_ACTION": planned_action})["planSha256"] == plan_sha)
    require_live_recovery_job(env, main_sha, candidate, session, token)
    writer = core.claim_resume_writer(objects, target.digest, session, main_sha, history, env["GITHUB_RUN_ID"],
        action="recovery", profile="rehearsal", candidate_revision=candidate,
        recovery_action=action, recovery_plan_sha=plan_sha)
    require_owned_writer(objects, target.digest, session, main_sha, candidate, spec, policy, raw_spec, writer, plan, mode="execute")
    require(len(events) < 10000)
    slot = app_session + "-" + str(len(events)).zfill(4)
    slot_key = core.BASE + target.digest + "/" + session + "/recovery/" + slot + "-intent.json"
    claim = {"version": 1, "plan": plan, "planSha256": plan_sha, "writer": writer,
             "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": "1"}
    objects.put_once(slot_key, canonical(claim))
    observed, _ = objects.get(slot_key)
    require(observed == canonical(claim), "The one-shot recovery claim was not confirmed.")
    require(rehearsal.verify_owned_webhook_window(context, start, main_sha, candidate) == window
            and ctl.inspect()["stateSha256"] == plan_result["stateSha256"] and txn.load() == events
            and store.get_with_etag(anchor.key)[0] == anchor_raw
            and stopped_children(objects, target.digest, session, main_sha, candidate, inventory_spec, policy, token) == children
            and require_owned_writer(objects, target.digest, session, main_sha, candidate, spec, policy, raw_spec,
                                     writer, plan, mode="execute"),
            "The exact approved recovery predecessor changed after its claim.")
    runtime.recovery_claim, runtime.recovery_slot = claim, slot_key
    local["BACKUP_STATE_SHA256"] = plan_result["stateSha256"]
    def mutation_guard():
        guard()
        current, _ = objects.get(slot_key)
        require(current == canonical(claim), "The recovery claim changed.")
        require_owned_writer(objects, target.digest, session, main_sha, candidate, spec, policy, raw_spec,
                             writer, plan, mode="execute")
        rehearsal.verify_owned_webhook_window(context, start, main_sha, candidate)
    ctl.guard, source.guard, runtime.guard = mutation_guard, mutation_guard, mutation_guard
    result = backup.execute_phase(action=action, env=local, target=target, revision=candidate,
        policy=policy, contract=contract, proof=context["proof"], state=state, store=store,
        guard=mutation_guard, bounded_guard=mutation_guard, ctl=ctl, source=source, api=api,
        directory=Path(env["RUNNER_TEMP"]), runtime=runtime)
    guard()
    after = ctl.inspect()
    final_anchor, final_raw, _ = anchor.read()
    final_events = txn.load()
    require_recovery_result(action, result.get("status"), final_anchor, final_events, after, app_session, day)
    completion = {"version": 1, "claimSha256": sha256(canonical(claim)).hexdigest(), "planSha256": plan_sha,
                  "status": result.get("status"), "stateSha256": after["stateSha256"],
                  "targetSha256": after["targetSha256"], "configurationSha256": after["configurationSha256"],
                  "control": after["control"], "releaseSha256": digest(after["release"]),
                  "anchorSha256": sha256(final_raw).hexdigest(), "anchorState": final_anchor["state"],
                  "journalSha256": digest(final_events), "journalLength": len(final_events)}
    complete_key = slot_key.removesuffix("-intent.json") + "-complete.json"
    objects.put_once(complete_key, canonical(completion))
    saved, _ = objects.get(complete_key)
    require(saved == canonical(completion), "The recovery result is unconfirmed.")
    return {"status": "completed-awaiting-independent-readback", "action": action, "planSha256": plan_sha,
            "slot": slot, "claimSha256": completion["claimSha256"],
            "completionSha256": sha256(saved).hexdigest(), "automaticReplay": False}


def readback(env):
    """Independently read private originals and the completed recovery job."""
    gate_env = {**env, "BACKUP_GATE_ROLE": "recovery-readback", "BACKUP_CHECKOUT_PHASE": "ready"}
    def guard():
        rehearsal.verify_trusted_gate(gate_env)
    guard()
    raw_spec = env.get("HEAD_VALIDATION_JSON", "")
    spec = parsed(raw_spec)
    require(canonical(spec).decode("utf-8") == raw_spec)
    main_sha, candidate = env["GITHUB_SHA"], spec["headSha"]
    context = rehearsal.prepare_coordinator_context(env, spec, guard=guard)
    tool, target, store = context["tool"], context["target"], context["store"]
    objects, session = store.objects, env.get("BACKUP_COORDINATOR_SESSION", "")
    require(objects is not None and objects.write_credential is None
            and not env.get("SUBS_BOT_SCOPED_R2_WRITE_JSON")
            and not env.get("SUBS_BOT_SCOPED_R2_EXTRA_WRITE_JSON")
            and env.get("BACKUP_RECOVERY_SOURCE_RUN_ID") == env.get("GITHUB_RUN_ID"),
            "Independent readback requires the original run and read-only object credentials.")
    app_session, day, slot = env.get("BACKUP_SESSION", ""), env.get("BACKUP_SESSION_DAY", ""), env.get("BACKUP_RECOVERY_SLOT", "")
    require(rehearsal.DECIMAL.fullmatch(session or "") and backup.maintenance.SESSION.fullmatch(app_session or "")
            and re.fullmatch(re.escape(app_session) + r"-[0-9]{4}", slot or "")
            and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", day or "")
            and rehearsal.HEX64.fullmatch(env.get("BACKUP_RECOVERY_CLAIM_SHA256", ""))
            and rehearsal.HEX64.fullmatch(env.get("BACKUP_RECOVERY_COMPLETION_SHA256", "")))
    prefix = core.BASE + target.digest + "/" + session + "/recovery/" + slot
    claim_raw, _ = objects.get(prefix + "-intent.json")
    complete_raw, _ = objects.get(prefix + "-complete.json")
    claim, complete = parsed(claim_raw), parsed(complete_raw)
    require(canonical(claim) == claim_raw and canonical(complete) == complete_raw
            and sha256(claim_raw).hexdigest() == env["BACKUP_RECOVERY_CLAIM_SHA256"]
            and sha256(complete_raw).hexdigest() == env["BACKUP_RECOVERY_COMPLETION_SHA256"]
            and claim.get("writerRunId") == env.get("GITHUB_RUN_ID") and claim.get("writerAttempt") == "1"
            and claim.get("planSha256") == digest(claim.get("plan")) == env.get("BACKUP_RECOVERY_PLAN_SHA256")
            and complete.get("claimSha256") == sha256(claim_raw).hexdigest()
            and complete.get("planSha256") == claim["planSha256"])
    plan = claim["plan"]
    require(plan.get("action") == env.get("BACKUP_ACTION") and plan.get("targetSha256") == target.digest
            and plan.get("dispatcherRevision") == main_sha and plan.get("candidateRevision") == candidate
            and plan.get("coordinatorSession") == session and plan.get("applicationSession") == app_session
            and plan.get("day") == day and slot == app_session + "-" + str(plan.get("journalLength")).zfill(4)
            and plan.get("sourceCheckpointId") == spec["sourceCheckpointId"]
            and plan.get("sourceManifestSha256") == spec["sourceManifestSha256"])
    require_owned_writer(objects, target.digest, session, main_sha, candidate, spec, context["policy"], raw_spec,
                         claim["writer"], plan, mode="readback")
    token = github._github_token()
    run_id = env["GITHUB_RUN_ID"]
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", token)
    require(str(run.get("id")) == run_id and run.get("run_attempt") == 1 and run.get("head_sha") == main_sha
            and run.get("path") in {RECOVERY_FILE, RECOVERY_FILE + "@main", RECOVERY_FILE + "@refs/heads/main"}
            and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
            and run.get("display_title") == "Rehearsal backup recovery " + env["BACKUP_ACTION"] + " at " + main_sha
                + " candidate " + candidate + " session " + session
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")))
    jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    require(isinstance(jobs.get("jobs"), list) and type(jobs.get("total_count")) is int
            and jobs["total_count"] == len(jobs["jobs"]) < 100)
    writer = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "recovery"]
    reader = [job for job in jobs["jobs"] if isinstance(job, dict) and job.get("name") == "readback"]
    require(len(writer) == len(reader) == 1 and (writer[0].get("status"), writer[0].get("conclusion")) == ("completed", "success")
            and reader[0].get("status") == "in_progress"
            and all(str(job.get("run_id")) == run_id and job.get("run_attempt") == 1 and job.get("head_sha") == main_sha
                    for job in (writer[0], reader[0])))
    for name in ("Verify recovery identity before candidate checkout", "Verify exact reviewed recovery checkout",
                 "Verify isolated recovery test Bot identity", "Plan or execute one reviewed recovery phase"):
        steps = [step for step in writer[0].get("steps", []) if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    ctl = tool.bind(target, context["bundle"], context["manifest"])
    state = ctl.inspect()
    anchor = backup.maintenance.Anchor(store, target.digest, spec["genesisSha256"])
    pinned, raw, _ = anchor.read()
    events = backup.maintenance.Transaction(store, app_session, day, target.digest, candidate).load()
    require(state.get("targetSha256") == complete.get("targetSha256") == target.digest
            and state.get("configurationSha256") == complete.get("configurationSha256") == target.configuration_digest
            and state.get("control") == complete.get("control") and digest(state.get("release")) == complete.get("releaseSha256")
            and not any(state["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates"))
            and sha256(raw).hexdigest() == complete.get("anchorSha256")
            and pinned["state"] == complete.get("anchorState") and digest(events) == complete.get("journalSha256")
            and len(events) == complete.get("journalLength"), "The recovery result changed before independent readback.")
    require_recovery_result(env["BACKUP_ACTION"], complete.get("status"), pinned, events, state, app_session, day)
    original, _ = objects.get(core.BASE + target.digest + "/" + session + "/start-intent.json")
    rehearsal.verify_owned_webhook_window({**context, "controller": ctl}, parsed(original), main_sha, candidate)
    guard()
    return {"status": "independently-read-back", "action": env["BACKUP_ACTION"], "planSha256": claim["planSha256"],
            "slot": slot, "claimSha256": sha256(claim_raw).hexdigest(),
            "completionSha256": sha256(complete_raw).hexdigest(),
            "workObservationChanged": state["stateSha256"] != complete.get("stateSha256"), "automaticReplay": False}


if __name__ == "__main__":
    import json
    try:
        os.umask(0o077)
        result = main()
        root = Path(os.environ["RUNNER_TEMP"])
        require(root.is_absolute() and root.is_dir() and not root.is_symlink())
        with (root / "rehearsal-backup-recovery-result.json").open("xb") as output:
            output.write(canonical(result))
        if result.get("status") == "completed-awaiting-independent-readback":
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write("recovery_slot=" + result["slot"] + "\nrecovery_claim_sha256=" + result["claimSha256"]
                             + "\nrecovery_completion_sha256=" + result["completionSha256"] + "\n")
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("::error::The isolated recovery is not confirmed; preserve its evidence and do not retry.")
        raise SystemExit(1) from None

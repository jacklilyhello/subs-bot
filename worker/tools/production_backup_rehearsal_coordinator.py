"""Fixed reviewed-head rehearsal wrapper for the shared backup coordinator.

The trusted main workflow gates the candidate before providing credentials.
No production target or approval is accepted by this wrapper.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import prepare_isolation_artifact as github
from backup_rehearsal_webhook import MODE
from production_backup_rehearsal_window import run_with_simulated_webhook
import production_backup_cli as backup
import production_backup_coordinator as core
import production_backup_rehearsal_phase as rehearsal
import production_backup_transaction as maintenance
from production_target import canonical, digest, parsed, require


def main(env=None):
    env = dict(os.environ if env is None else env)
    gate_env = {**env, "BACKUP_GATE_ROLE": "parent", "BACKUP_CHECKOUT_PHASE": "ready"}
    trusted_gate = Path(env.get("GITHUB_WORKSPACE", "")) / "trusted/worker/tools/trusted_backup_phase_gate.py"
    require(trusted_gate.is_absolute() and trusted_gate.is_file() and not trusted_gate.is_symlink())
    def guard():
        subprocess.run([sys.executable, "-B", str(trusted_gate)], env=gate_env,
                       capture_output=True, check=True, timeout=60)
    guard()
    raw_spec = env.get("HEAD_VALIDATION_JSON", "")
    spec = parsed(raw_spec)
    require(canonical(spec).decode("utf-8") == raw_spec)
    main_sha, candidate = env["GITHUB_SHA"], spec["headSha"]
    action = env.get("BACKUP_ACTION", "")
    actions = {"inspect", "plan-initialize", "initialize", "plan-webhook-history", "plan-webhook-anchor", "initialize-webhook-anchor", "plan-run", "run", "plan-resume", "resume",
               "plan-reconcile", "reconcile", "plan-abort", "abort"}
    require(action in actions and env.get("GITHUB_RUN_ATTEMPT") == "1")
    context = rehearsal.prepare_coordinator_context(env, spec, guard=guard)
    target, policy, app_store = context["target"], context["policy"], context["store"]
    require(target.environment == "rehearsal" and app_store.objects is not None)
    objects = app_store.objects
    if action == "plan-webhook-history":
        history_checker = Path(env["GITHUB_WORKSPACE"]) / "trusted/worker/tools/trusted_backup_webhook_history.py"
        require(history_checker.is_file() and not history_checker.is_symlink())
        observed = subprocess.run([sys.executable, "-B", str(history_checker)], env=gate_env,
                                  capture_output=True, check=True, timeout=180)
        result = parsed(observed.stdout)
        require(isinstance(result, dict) and result.get("status") in {"resolved", "needs-reconciliation"})
        return result
    if action in {"plan-webhook-anchor", "initialize-webhook-anchor"}:
        from trusted_backup_webhook_anchor import anchor as webhook_anchor, genesis_sha
        tool = context["tool"]
        expected = genesis_sha(tool.store, target.digest)
        configured = env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256", "")
        require(configured == expected or action == "plan-webhook-anchor" and not configured)
        if action == "plan-webhook-anchor":
            return {"status": "planned", "genesisSha256": expected, "mutationPerformed": False}
        require(env.get("SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED") == "true"
                and env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == expected)
        guard()
        webhook_anchor(tool.store, target.digest, expected).initialize()
        return {"status": "initialized", "genesisSha256": expected, "mutationPerformed": True}
    seed = maintenance.Anchor(core.CoordinatorStore(objects, target.digest), target.digest, "0" * 64)
    expected_genesis = sha256(seed.initial_material()[1]).hexdigest()
    configured = env.get("SUBS_BOT_BACKUP_COORDINATOR_GENESIS_SHA256", "")
    require(configured == expected_genesis or action == "plan-initialize" and not configured)
    anchor = maintenance.Anchor(core.CoordinatorStore(objects, target.digest), target.digest, expected_genesis)
    if action == "plan-initialize":
        return {"status": "planned", "genesisSha256": expected_genesis, "mutationPerformed": False}
    if action in {"initialize", "run", "resume", "reconcile", "abort"}:
        require(env.get("SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED") == "true" and objects.write_credential is not None)
    if action == "initialize":
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == expected_genesis)
        guard()
        anchor.initialize()
        return {"status": "initialized", "mutationPerformed": True}
    pinned, raw_anchor, _ = anchor.read()
    if action == "inspect":
        return {"status": "attention" if pinned["state"] == "active" else "observed", "phase": pinned["state"],
                "mutationPerformed": False, "automaticReplay": False}
    checkpoint, manifest = spec["sourceCheckpointId"], spec["sourceManifestSha256"]
    validation_sha = sha256(raw_spec.encode("utf-8")).hexdigest()
    session = env["GITHUB_RUN_ID"] if action == "plan-run" else env.get("BACKUP_COORDINATOR_SESSION", "")
    require(core.DECIMAL.fullmatch(session or ""))
    normalized = {"plan-run": "run", "plan-resume": "resume", "plan-reconcile": "reconcile", "plan-abort": "abort"}.get(action, action)
    plan = {"version": 1, "action": normalized, "targetSha256": target.digest, "controlRevision": main_sha,
            "candidateRevision": candidate, "profile": "rehearsal", "validationSha256": validation_sha,
            "session": session, "sourceCheckpointId": checkpoint, "sourceManifestSha256": manifest,
            "anchorSha256": sha256(raw_anchor).hexdigest(), "policySha256": digest(policy)}
    options = {"profile": "rehearsal", "candidate_revision": candidate, "validation_json": raw_spec}
    history_options = {"profile": "rehearsal", "candidate_revision": candidate, "validation_sha": validation_sha}
    token = github._github_token()
    if action in {"plan-run", "run"}:
        require(env.get("HEAD_TRUSTED_WEBHOOK_PRECONDITION") == MODE
                and not env.get("HEAD_TRUSTED_WEBHOOK_CLEANUP"),
                "This rehearsal requires the trusted simulation of the webhook precondition.")
        plan_sha = digest({"plan": plan, "webhookPrecondition": MODE})
    if action == "plan-run":
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1")
        return {"status": "planned", "planSha256": plan_sha, "session": session, "mutationPerformed": False,
                "webhookPreconditionSimulated": True}
    if action in {"plan-resume", "resume", "plan-reconcile", "reconcile", "plan-abort", "abort"}:
        require(pinned["state"] == "active" and pinned["session"] == session + "-1"
                and pinned["controlRevision"] == candidate)
        history = core.finished_controller(objects, target.digest, session, main_sha, checkpoint, manifest,
                                           digest(policy), **history_options)
    if action in {"plan-resume", "resume"}:
        verified, _ = core.completed_results(objects, target.digest, session, main_sha, token, checkpoint, manifest,
                                              backup.maximum_pause(policy), **options)
        original_start_raw, _ = objects.get(core.BASE + target.digest + "/" + session + "/start-intent.json")
        require(sha256(original_start_raw).hexdigest() == history["startSha256"])
        original_start = parsed(original_start_raw)
        webhook_observation = rehearsal.verify_owned_webhook_window(context, original_start, main_sha, candidate)
        plan.update(writerHistorySha256=digest(history), completedResultsSha256=digest(verified),
                    webhookObservationSha256=digest(webhook_observation),
                    nextAction=core.STEPS[len(verified)] if len(verified) < len(core.STEPS) else "complete")
        if action == "plan-resume":
            return {"status": "planned", "planSha256": digest(plan), "verifiedCheckpoints": len(verified), "mutationPerformed": False}
    if action in {"plan-reconcile", "reconcile"}:
        sequence = int(env.get("BACKUP_COORDINATOR_SEQUENCE", "0"))
        stage = core.inspect_stage(objects, target.digest, session, sequence)
        require(stage["status"] == "unknown")
        prior, pause = core.completed_results(objects, target.digest, session, main_sha, token, checkpoint, manifest,
                                             backup.maximum_pause(policy), stop_before=sequence, **options)
        require(len(prior) == sequence - 1)
        raw, _ = objects.get(core.event_key(target.digest, session, sequence))
        intent = parsed(raw)
        expected, _ = core.stage_inputs(prior, checkpoint, manifest, session, intent, backup.maximum_pause(policy), pause,
                                         validation_json=raw_spec)
        require(sha256(canonical(expected)).hexdigest() == intent["inputSha256"])
        path = core.PROFILES["rehearsal"]["child"]
        workflow = github._get_json("/actions/workflows/" + path.rsplit("/", 1)[-1], token)
        require(workflow.get("path") == path and type(workflow.get("id")) is int)
        run = core.discover_run(intent, workflow["id"], token)
        require((run.get("status"), run.get("conclusion")) == ("completed", "success"))
        result, source, original = core.selected_result(str(run["id"]), main_sha, intent["action"], token, profile="rehearsal")
        receipt = core.receipt(intent, str(run["id"]), result, source["artifactId"], source["artifactSha256"])
        core.require_completed_receipt(intent, receipt, run, workflow["id"], result)
        plan.update(sequence=sequence, intentSha256=sha256(raw).hexdigest(), runId=str(run["id"]),
                    resultSha256=receipt["resultSha256"], artifactId=source["artifactId"], artifactSha256=source["artifactSha256"],
                    writerHistorySha256=digest(history))
        if action == "plan-reconcile":
            return {"status": "planned", "planSha256": digest(plan), "mutationPerformed": False}
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        guard()
        require(core.finished_controller(objects, target.digest, session, main_sha, checkpoint, manifest, digest(policy), **history_options) == history)
        core.claim_resume_writer(objects, target.digest, session, main_sha, history, env["GITHUB_RUN_ID"], action="reconcile",
                                 profile="rehearsal", candidate_revision=candidate)
        again = core.discover_run(intent, workflow["id"], token)
        new_result, new_source, new_original = core.selected_result(str(again["id"]), main_sha, intent["action"], token, profile="rehearsal")
        require(again == run and new_result == result and new_source == source and new_original == original)
        core.confirm_stage(objects, intent, run, workflow["id"], result, source, original)
        return {"status": "reconciled", "mutationPerformed": True, "dispatchRetried": False}
    if action in {"plan-abort", "abort"}:
        observed = core.abort_observation(objects, app_store, target, session, main_sha, checkpoint, manifest,
                                          backup.maximum_pause(policy), spec["genesisSha256"], **options)
        plan.update(writerHistorySha256=digest(history), abortObservationSha256=digest(observed))
        if action == "plan-abort":
            return {"status": "planned", "planSha256": digest(plan), "terminal": observed["terminal"], "mutationPerformed": False}
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        guard()
        require(core.finished_controller(objects, target.digest, session, main_sha, checkpoint, manifest, digest(policy), **history_options) == history
                and core.abort_observation(objects, app_store, target, session, main_sha, checkpoint, manifest,
                                           backup.maximum_pause(policy), spec["genesisSha256"], **options) == observed)
        core.claim_resume_writer(objects, target.digest, session, main_sha, history, env["GITHUB_RUN_ID"], action="abort",
                                 profile="rehearsal", candidate_revision=candidate)
        require(core.abort_observation(objects, app_store, target, session, main_sha, checkpoint, manifest,
                                       backup.maximum_pause(policy), spec["genesisSha256"], **options) == observed)
        anchor.release(session + "-1")
        return {"status": "abandoned-after-confirmed-terminal", "terminal": observed["terminal"], "dispatchRetried": False}
    if action == "run":
        require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == plan_sha)
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1"
                and backup.in_window(policy, datetime.now(timezone.utc)))
        original = github._get_json("/actions/runs/" + session + "/attempts/1", token)
        path = core.PROFILES["rehearsal"]["parent"]
        title = "Rehearsal backup coordinator plan-run at " + main_sha + " candidate " + candidate
        require(str(original.get("id")) == session and original.get("head_sha") == main_sha
                and original.get("path") in (path, path + "@main", path + "@refs/heads/main")
                and original.get("display_title") == title and original.get("event") == "workflow_dispatch"
                and original.get("head_branch") == "main" and original.get("run_attempt") == 1
                and (original.get("status"), original.get("conclusion")) == ("completed", "success")
                and all(isinstance(original.get(k), dict) and original[k].get("id") == github.REPOSITORY_ID
                        for k in ("repository", "head_repository")))
        return run_with_simulated_webhook(context, anchor, app_store, plan, env, guard, token, options)
    else:
        require(action == "resume" and env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
        guard()
        require(core.finished_controller(objects, target.digest, session, main_sha, checkpoint, manifest, digest(policy), **history_options) == history)
        require(rehearsal.verify_owned_webhook_window(context, original_start, main_sha, candidate) == webhook_observation)
        core.claim_resume_writer(objects, target.digest, session, main_sha, history, env["GITHUB_RUN_ID"],
                                 profile="rehearsal", candidate_revision=candidate)
        require(rehearsal.verify_owned_webhook_window(context, original_start, main_sha, candidate) == webhook_observation)
        again, _ = core.completed_results(objects, target.digest, session, main_sha, token, checkpoint, manifest,
                                          backup.maximum_pause(policy), **options)
        require(again == verified)
    return core.run_sequence(objects, anchor, target.digest, session, main_sha, checkpoint, manifest, token,
                             deadline=time.monotonic() + 5 * 3600, pause_limit=backup.maximum_pause(policy),
                             pause_alarm_seconds=policy["pauseLimitSeconds"],
                             writer_run_id=env["GITHUB_RUN_ID"], **options)


if __name__ == "__main__":
    try:
        os.umask(0o077)
        result = main()
        root = Path(os.environ["RUNNER_TEMP"])
        require(root.is_absolute() and root.is_dir() and not root.is_symlink())
        with (root / "rehearsal-backup-coordinator-result.json").open("xb") as output:
            output.write(canonical(result))
        print(json.dumps(result, sort_keys=True))
        if result.get("status") == "attention":
            raise SystemExit(1)
    except Exception:
        print("::error::The isolated coordinator stopped; preserve and inspect its private intent before continuing.")
        raise SystemExit(1) from None

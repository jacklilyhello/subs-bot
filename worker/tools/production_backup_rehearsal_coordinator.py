"""Fixed reviewed-head rehearsal wrapper for the shared backup coordinator.

The trusted main workflow gates the candidate before providing credentials.
No production target or approval is accepted by this wrapper.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import prepare_isolation_artifact as github
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
    if action == "plan-run":
        require(pinned["state"] == "idle" and pinned["session"] != session + "-1")
        return {"status": "planned", "planSha256": digest(plan), "session": session, "mutationPerformed": False}
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
    require(env.get("BACKUP_COORDINATOR_APPROVAL_SHA256") == digest(plan))
    if action == "run":
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
        require(env.get("HEAD_TRUSTED_WEBHOOK_CLEANUP") == "configured-v1")
        tool = context["tool"]
        from trusted_backup_webhook_anchor import anchor as webhook_anchor, genesis_sha
        expected_webhook_genesis = genesis_sha(tool.store, target.digest)
        require(env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256") == expected_webhook_genesis)
        webhook_lock = webhook_anchor(tool.store, target.digest, expected_webhook_genesis)
        prior_webhook, _, _ = webhook_lock.read()
        require(prior_webhook["state"] == "idle" and prior_webhook["session"] != tool.run + "-1")
        tool.backup_evidence_workflow = "worker-backup-reviewed-coordinator.yml"
        tool.baseline_checkpoint, tool.baseline_manifest_sha = checkpoint, manifest
        ctl = tool.bind(target, context["bundle"], context["manifest"])
        from production_lifecycle_drill import rows
        def authorization_state(controller):
            return {"policy": rows(controller.data, controller.database, "SELECT * FROM telegram_general_policy ORDER BY bot_id"),
                    "actors": rows(controller.data, controller.database, "SELECT * FROM telegram_general_actors ORDER BY actor_id"),
                    "groups": rows(controller.data, controller.database, "SELECT * FROM telegram_general_groups ORDER BY chat_id")}
        def run_backup(controller, _anchors, _base):
            before_auth = authorization_state(controller)
            start = {**plan, "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": "1"}
            key = core.BASE + target.digest + "/" + session + "/start-intent.json"
            existing, _ = objects.get(key, absent=True)
            require(existing is None)
            objects.put_once(key, canonical(start))
            guard()
            anchor.acquire(session + "-1", datetime.now(timezone.utc).strftime("%Y/%m/%d"), candidate)
            completed = core.run_sequence(objects, anchor, target.digest, session, main_sha, checkpoint, manifest, token,
                deadline=time.monotonic() + 5 * 3600, pause_limit=backup.maximum_pause(policy),
                pause_alarm_seconds=policy["pauseLimitSeconds"], writer_run_id=env["GITHUB_RUN_ID"], **options)
            values, _ = core.completed_results(objects, target.digest, session, main_sha, token, checkpoint, manifest,
                                                backup.maximum_pause(policy), **options)
            after = controller.inspect()
            require(completed.get("status") == "completed" and len(values) == len(core.STEPS)
                    and values[-1].get("status") == "resumed" and after["control"]["admission"] == "open"
                    and after["control"]["workers"] == "run" and authorization_state(controller) == before_auth
                    and not any(after["terminal"].get(k, 0) for k in
                                ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
            tool.report["dailyBackupAcceptance"] = {"baseline": {"checkpointId": values[8]["checkpointId"],
                "manifestSha256": values[8]["manifestSha256"]}, "planBeginSession": values[0]["session"],
                "planBeginDay": values[0]["day"], "pauseSeconds": values[-1]["pauseSeconds"],
                "pauseLimitExceeded": values[-1]["pauseLimitExceeded"], "admissionRestored": True, "authorizationUnchanged": True}
        # The trusted-main history checker and the one-shot setup callbacks are
        # deliberately required before exercise can change the test webhook.
        history_checker = Path(env["GITHUB_WORKSPACE"]) / "trusted/worker/tools/trusted_backup_webhook_history.py"
        require(history_checker.is_file() and not history_checker.is_symlink(), "The trusted webhook history gate is unavailable.")
        history_output = subprocess.run([sys.executable, "-B", str(history_checker)], env=gate_env,
                                       capture_output=True, check=True, timeout=180)
        history = parsed(history_output.stdout)
        require(isinstance(history, dict) and history.get("status") == "resolved" and re.fullmatch(r"[a-f0-9]{64}", history.get("historySha256", "")))
        guard()
        webhook_lock.acquire(tool.run + "-1", datetime.now(timezone.utc).strftime("%Y/%m/%d"), candidate)
        history_again = subprocess.run([sys.executable, "-B", str(history_checker)], env=gate_env,
                                       capture_output=True, check=True, timeout=180)
        require(parsed(history_again.stdout) == history, "The observed webhook history changed after acquiring the lock.")
        setup_key = tool.prefix + "phase-coordinator-webhook-setup-" + tool.run + "-" + tool.attempt + "-intent.json"
        confirmed_key = tool.prefix + "phase-coordinator-webhook-setup-" + tool.run + "-" + tool.attempt + "-confirmed.json"
        setup_intent = {}
        def webhook_setup(controller, webhook_plan, snapshot_sha):
            require(not setup_intent and re.fullmatch(r"[a-f0-9]{64}", snapshot_sha or ""))
            lock, _, _ = webhook_lock.read()
            require(lock["state"] == "active" and lock["session"] == tool.run + "-1"
                    and lock["controlRevision"] == candidate)
            value = {"version": 1, "kind": "phase-webhook-setup-intent", "runId": tool.run, "runAttempt": tool.attempt,
                "controllerRevision": candidate, "dispatcherRevision": main_sha, "targetSha256": target.digest,
                "configurationSha256": target.configuration_digest, "sourceCheckpointId": checkpoint,
                "sourceManifestSha256": manifest, "snapshotSha256": snapshot_sha,
                "predecessorSha256": webhook_plan["stateSha256"],
                "webhookSettingsSha256": webhook_plan["webhook"]["settingsSha256"], "historySha256": history["historySha256"]}
            guard()
            tool.store.put_exclusive(setup_key, canonical(value))
            require(tool.store.get(setup_key) == canonical(value))
            fresh = controller.plan_webhook()
            require(fresh["stateSha256"] == value["predecessorSha256"]
                    and fresh["webhook"]["settingsSha256"] == value["webhookSettingsSha256"])
            setup_intent.update(value)
        def webhook_confirm(_controller, configured, snapshot_sha):
            require(setup_intent and setup_intent["snapshotSha256"] == snapshot_sha)
            value = {"version": 1, "kind": "phase-webhook-setup-confirmed", "intentSha256": digest(setup_intent),
                     "snapshotSha256": snapshot_sha, "configuredSha256": digest(configured), "targetSha256": target.digest}
            tool.store.put_exclusive(confirmed_key, canonical(value))
            require(tool.store.get(confirmed_key) == canonical(value))
        tool.exercise(provided_controller=ctl, verify_extra=run_backup, external_webhook_cleanup=True,
                      external_webhook_setup=webhook_setup, external_webhook_confirm=webhook_confirm)
        ready = [item for item in tool.report["stages"] if item.get("stage") == "open-backup-ready-for-cleanup"]
        accepted = tool.report["dailyBackupAcceptance"]
        require(len(ready) == 1 and accepted["admissionRestored"] is True and accepted["authorizationUnchanged"] is True)
        receipt = {"version": 1, "status": "candidate-complete-before-trusted-cleanup", "runId": tool.run,
            "runAttempt": tool.attempt, "controllerRevision": candidate, "dispatcherRevision": main_sha,
            "targetSha256": target.digest, "readySha256": ready[0]["sha256"],
            "snapshotSha256": tool.report["webhookSnapshotSha256"], "checkpointId": accepted["baseline"]["checkpointId"],
            "manifestSha256": accepted["baseline"]["manifestSha256"], "pauseSeconds": accepted["pauseSeconds"],
            "pauseLimitExceeded": accepted["pauseLimitExceeded"], "admissionRestored": True, "authorizationUnchanged": True,
            "confirmedReceiptsNotRepeated": True, "coordinatorSession": session, "planBeginSession": accepted["planBeginSession"],
            "planBeginDay": accepted["planBeginDay"], "sourceCheckpointId": checkpoint, "sourceManifestSha256": manifest}
        receipt_key = tool.prefix + tool.run + "-" + tool.attempt + "-backup-head-acceptance.json"
        tool.store.put_exclusive(receipt_key, canonical(receipt))
        require(tool.store.get(receipt_key) == canonical(receipt))
        return {"status": "awaiting-trusted-cleanup", "pauseSeconds": accepted["pauseSeconds"],
                "pauseLimitExceeded": accepted["pauseLimitExceeded"], "consumerSwitch": "not-authorized"}
    else:
        require(action == "resume")
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

"""Run a registered backup rehearsal with Telegram's original consumer in place."""
from datetime import datetime, timezone
from hashlib import sha256
import time

from backup_rehearsal_webhook import BackupRehearsalTelegram, MODE, receive_probe
import production_backup_cli as backup
import production_backup_coordinator as core
import production_backup_transaction as maintenance
from production_lifecycle_drill import rows
from production_target import canonical, digest, require


def run_with_simulated_webhook(context, anchor, app_store, plan, env, guard, token, options):
    tool, target, policy = context["tool"], context["target"], context["policy"]
    session, main_sha, candidate = plan["session"], plan["controlRevision"], plan["candidateRevision"]
    checkpoint, manifest = plan["sourceCheckpointId"], plan["sourceManifestSha256"]
    app_anchor = maintenance.Anchor(app_store, target.digest, context["genesisSha256"])
    before_app, app_raw, _ = app_anchor.read()
    require(before_app["state"] == "idle", "Resolve the existing backup before opening the drill.")
    ctl = tool.bind(target, context["bundle"], context["manifest"])
    ctl.telegram = BackupRehearsalTelegram(target, tool.secrets)
    original_webhook = ctl.telegram.observe_original()["settingsSha256"]
    current = ctl.inspect()

    def quiet_terminal(state):
        require(not any(state["work"].values()) and not any(state["terminal"].get(k, 0) for k in
                    ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))

    def authorization_sha():
        return digest({"policy": rows(ctl.data, ctl.database, "SELECT * FROM telegram_general_policy ORDER BY bot_id"),
                       "actors": rows(ctl.data, ctl.database, "SELECT * FROM telegram_general_actors ORDER BY actor_id"),
                       "groups": rows(ctl.data, ctl.database, "SELECT * FROM telegram_general_groups ORDER BY chat_id")})

    def record(key, value):
        guard()
        raw = canonical(value)
        tool.store.put_exclusive(key, raw)
        require(tool.store.get(key) == raw, "The isolated evidence write needs independent confirmation.")

    quiet_terminal(current)
    require(current["control"]["admission"] == "closed" and current["control"]["workers"] == "frozen")
    original_auth = authorization_sha()
    start = {**plan, "writerRunId": env["GITHUB_RUN_ID"], "writerAttempt": "1"}
    start_key = core.BASE + target.digest + "/" + session + "/start-intent.json"
    window = tool.prefix + "backup-simulated-open-" + start["writerRunId"] + "-1"
    reserve = {"version": 1, "mode": MODE, "startSha256": digest(start), "targetSha256": target.digest,
               "configurationSha256": target.configuration_digest, "originalWebhookSettingsSha256": original_webhook}
    require(app_store.objects is not None)
    guard()
    app_store.objects.put_once(start_key, canonical(start))
    require(app_store.objects.get(start_key)[0] == canonical(start))
    guard()
    anchor.acquire(session + "-1", datetime.now(timezone.utc).strftime("%Y/%m/%d"), candidate)
    record(window + "-intent.json", {**reserve, "stateSha256": current["stateSha256"],
           "appAnchorSha256": sha256(app_raw).hexdigest(), "authorizationSha256": original_auth})

    probe_base = 2**51 + int(start["writerRunId"]) * 4
    require(probe_base < 2**52)

    def probe(label, expected_status, *, denied_proof=None):
        intent = {**reserve, "probe": label, "updateId": probe_base, "expectedStatus": expected_status}
        if denied_proof is not None:
            require(denied_proof.get("status") == 503 and denied_proof.get("confirmedDisposition") is False
                    and tool.store.get(window + "-closed-verified.json") == canonical(denied_proof))
            intent["deniedProofSha256"] = digest(denied_proof)
        record(window + "-" + label + "-intent.json", intent)
        observed = receive_probe(ctl, probe_base, expected_status, guard=guard)
        receipt = {"intentSha256": digest(intent), **observed}
        record(window + "-" + label + "-verified.json", receipt)
        return receipt

    before = probe("closed", 503)
    tool.baseline_checkpoint, tool.baseline_manifest_sha = checkpoint, manifest
    tool.activation_baseline()
    # The regular controller fences the D1 transition. Any unconfirmed
    # write leaves the original intent for a separate reconciliation.
    require(app_anchor.read()[1] == app_raw and ctl.inspect() == current)
    opened = tool.transition("activate")
    require(opened["control"]["admission"] == "open" and opened["control"]["workers"] == "run"
            and opened["control"]["epoch"] == current["control"]["epoch"] + 1)
    record(window + "-verified.json", {**reserve, "openedEpoch": opened["control"]["epoch"]})

    limit = backup.maximum_pause(policy)
    accepted = {}

    def finish_window(completed):
        values, _ = core.completed_results(app_store.objects, target.digest, session, main_sha, token, checkpoint, manifest,
                                          limit, **options)
        after = ctl.inspect()
        quiet_terminal(after)
        require(values == completed and len(values) == len(core.STEPS)
                and all(value.get("webhookPreconditionSimulated") is True for value in values)
                and values[-1].get("status") == "resumed" and after["control"]["admission"] == "open"
                and after["control"]["workers"] == "run" and authorization_sha() == original_auth)
        reopened = probe("reopened", 204, denied_proof=before)
        journal = maintenance.Transaction(app_store, values[0]["session"], values[0]["day"], target.digest, candidate)
        stages = journal.load()
        times = {event["stage"]: event["timestamp"] for event in stages}
        required = {"paused", "frozen", "capture-intent", "verified", "resumed"}
        require(required <= times.keys() and stages[-1]["stage"] == "resumed" and app_anchor.read()[0]["state"] == "idle")
        record(window + "-close-intent.json", {**reserve, "stateSha256": ctl.inspect()["stateSha256"],
               "journalSha256": digest(stages)})
        # Reset only from the proven successful state. An exception never triggers
        # automatic close, thaw, or reopen of an unresolved state.
        closed = tool.transition("pause")
        tool.quiet()
        final = tool.transition("freeze")
        quiet_terminal(final)
        require(closed["control"]["admission"] == "closed" and final["control"]["admission"] == "closed"
                and final["control"]["workers"] == "frozen" and authorization_sha() == original_auth
                and ctl.telegram.observe_original()["settingsSha256"] == original_webhook)
        result = {"version": 1, "status": "completed", "admissionRestored": True, "isolationResetFrozen": True,
                  "webhookPreconditionSimulated": True, "authorizationUnchanged": True, "consumerSwitchPerformed": False,
                  "closedProbeStatus": before["status"], "restoredProbeStatus": reopened["status"],
                  "pauseSeconds": values[-1]["pauseSeconds"], "pauseLimitExceeded": values[-1]["pauseLimitExceeded"],
                  "drainAndFreezeSeconds": times["frozen"] - times["paused"],
                  "captureAndReadbackSeconds": times["verified"] - times["capture-intent"],
                  "recoveryToOpenSeconds": times["resumed"] - times["verified"],
                  "checkpointId": values[8]["checkpointId"], "manifestSha256": values[8]["manifestSha256"]}
        record(window + "-completed.json", {**result, "startSha256": digest(start), "journalSha256": digest(stages),
               "finalStateSha256": final["stateSha256"], "targetSha256": target.digest})
        accepted.update(result)

    completed = core.run_sequence(app_store.objects, anchor, target.digest, session, main_sha, checkpoint, manifest, token,
        deadline=time.monotonic() + 5 * 3600, pause_limit=limit,
        pause_alarm_seconds=policy["pauseLimitSeconds"], writer_run_id=start["writerRunId"],
        rehearsal_complete=finish_window, **options)
    require(completed.get("status") == "completed" and accepted.get("status") == "completed")
    return accepted

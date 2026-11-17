"""Trusted-main, single-use recovery of the authorized test Bot webhook.

An absent or uncertain intent never authorizes a retry. This entry point does
not alter application admission or consume Telegram updates.
"""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import tempfile

import prepare_isolation_artifact as github
from production_control import API, Controller, Telegram
from production_lifecycle_drill import (configuration, ORIGINAL_ORIGIN, ORIGINAL_SERVICE, ORIGIN,
                                        probe_original_webhook, webhook_settings)
from production_storage import PrivateStore
from production_target import TEST_BOT_ID, canonical, parsed, require, validate_target

DISPATCHER = ".github/workflows/worker-backup-reviewed-head.yml"
PHASE_DISPATCHER = ".github/workflows/worker-backup-reviewed-coordinator.yml"
RECOVERY = ".github/workflows/worker-backup-webhook-recovery.yml"
ADMISSION_RECOVERY = ".github/workflows/worker-backup-admission-recovery.yml"
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
SHA = re.compile(r"[a-f0-9]{64}")
REV = re.compile(r"[a-f0-9]{40}")


def context(env):
    revision = env.get("GITHUB_SHA", "")
    ref = env.get("GITHUB_WORKFLOW_REF", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_WORKFLOW_SHA") == revision
            and REV.fullmatch(revision or "") and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and ref in {github.REPOSITORY + "/" + path + "@" + github.MAIN_REF for path in (DISPATCHER, PHASE_DISPATCHER, RECOVERY, ADMISSION_RECOVERY)})
    github.require_current_main(revision)
    return any(ref.endswith(path + "@" + github.MAIN_REF) for path in (DISPATCHER, PHASE_DISPATCHER))


def source_run(env, automatic):
    run_id, attempt = env.get("WEBHOOK_SOURCE_RUN_ID", ""), env.get("WEBHOOK_SOURCE_ATTEMPT", "")
    require(DECIMAL.fullmatch(run_id or "") and attempt == "1")
    require(not automatic or (run_id == env.get("GITHUB_RUN_ID") and attempt == env.get("GITHUB_RUN_ATTEMPT")))
    expected_main = env.get("WEBHOOK_SOURCE_MAIN_SHA", "")
    expected_head = env.get("WEBHOOK_SOURCE_CANDIDATE_SHA", "")
    require(REV.fullmatch(expected_main or "") and REV.fullmatch(expected_head or "")
            and expected_head == env.get("WEBHOOK_REVIEWED_CANDIDATE_SHA"),
            "The source candidate differs from the independent protected pin.")
    source_kind = env.get("WEBHOOK_SOURCE_KIND", "reviewed-head")
    require(source_kind in {"reviewed-head", "phase-coordinator"})
    workflow = PHASE_DISPATCHER if source_kind == "phase-coordinator" else DISPATCHER
    if automatic:
        require(env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/" + workflow + "@" + github.MAIN_REF)
    run = github._get_json("/actions/runs/" + run_id + "/attempts/1", github._github_token())
    require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
            and run.get("path") in (workflow, workflow + "@main", workflow + "@refs/heads/main")
            and run.get("head_sha") == expected_main and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch"
            and (source_kind != "phase-coordinator" or run.get("display_title") ==
                 "Rehearsal backup coordinator run at " + expected_main + " candidate " + expected_head)
            and all(isinstance(run.get(key), dict) and run[key].get("id") == github.REPOSITORY_ID
                    for key in ("repository", "head_repository"))
            and (automatic or run.get("status") == "completed"))
    return run_id, attempt, expected_head


def manual_no_prior_dispatch(env, run_id):
    """Reject any prior manual write attempt, including one with a lost response."""
    token = github._github_token()
    rows, count = [], None
    for page in range(1, 11):
        response = github._get_json("/actions/workflows/worker-backup-webhook-recovery.yml/runs?per_page=100&page=" + str(page), token)
        batch, total = response.get("workflow_runs"), response.get("total_count")
        require(isinstance(batch, list) and len(batch) <= 100 and type(total) is int and 0 <= total < 1000)
        require(count is None or count == total, "Recovery workflow history changed during inspection.")
        count = total
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        require(False, "The recovery workflow history exceeds its safe bound.")
    require(len(rows) == total and len({row.get("id") for row in rows if isinstance(row, dict)}) == len(rows))
    title = "Backup webhook restore " + run_id + "-1"
    current_seen = False
    for row in rows:
        require(isinstance(row, dict) and type(row.get("id")) is int and row["id"] > 0
                and row.get("path") in (RECOVERY, RECOVERY + "@main", RECOVERY + "@refs/heads/main")
                and row.get("head_branch") == "main" and row.get("event") == "workflow_dispatch"
                and REV.fullmatch(row.get("head_sha", "") or "")
                and type(row.get("run_attempt")) is int and 1 <= row["run_attempt"] <= 100
                and all(isinstance(row.get(key), dict) and row[key].get("id") == github.REPOSITORY_ID
                        for key in ("repository", "head_repository")))
        if str(row.get("id")) == env.get("GITHUB_RUN_ID"):
            require(row.get("display_title") == title and row.get("head_sha") == env.get("GITHUB_SHA")
                    and row.get("run_attempt") == 1 and not current_seen)
            current_seen = True
        elif row.get("display_title") == title:
            require(False, "A prior manual restore may have been dispatched; reconcile without replay.")
        else:
            require(re.fullmatch(r"Backup webhook (?:diagnose|inspect|restore|plan-phase-unstarted|release-phase-unstarted) [1-9][0-9]{0,19}-1", row.get("display_title", "")))
    require(current_seen, "The current recovery run is not visible in complete history.")


def open_store(env):
    draft, secrets, previous, original = configuration(env)
    anchor = {**draft.data, "d1Id": original["d1Id"], "d1Name": ORIGINAL_SERVICE,
              "backupBucketName": ORIGINAL_SERVICE, "backupBucketCreatedAt": original["r2CreatedOn"]}
    store = PrivateStore(API(anchor, env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")), ORIGINAL_SERVICE)
    prefix = "maintenance/production-control/evidence/lifecycle-" + draft.digest + "/"
    return draft, secrets, previous, store, prefix


def claim_intent_once(store, key, raw):
    """A 412 or transport failure never grants authority to call Telegram."""
    store.put_exclusive(key, raw)


def require_exact_freeze(target, secrets, env, freeze):
    """Reverify the complete pinned release and Controller binding before a write."""
    from production_release_evidence import load_release
    checkpoint = env.get("WEBHOOK_SOURCE_CHECKPOINT_ID", "")
    manifest = env.get("WEBHOOK_SOURCE_MANIFEST_SHA256", "")
    require(re.fullmatch(r"[a-f0-9]{32}", checkpoint or "") and SHA.fullmatch(manifest or ""))
    root = Path(env.get("RUNNER_TEMP", ""))
    require(root.is_absolute() and root.is_dir() and not root.is_symlink())
    token = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    with tempfile.TemporaryDirectory(prefix="webhook-recovery-source-", dir=root) as directory:
        source = load_release(target, token, checkpoint, manifest, Path(directory))
        require(source["sourceTarget"].configuration_digest == target.configuration_digest)
        guard = lambda: github.require_current_main(env["GITHUB_SHA"])
        ctl = Controller(target, API(target, token), API(target, env.get("SUBS_BOT_CF_REHEARSAL_WORKER_READ_TOKEN", "")),
                         source["bundle"], source["manifest"], guard=guard, secrets=secrets,
                         control_revision=env["GITHUB_SHA"])
        state = ctl.inspect()
        require(state["stateSha256"] == freeze["stateSha256"] and state["targetSha256"] == target.digest
                and state["configurationSha256"] == target.configuration_digest
                and state["control"] == freeze["control"] and state["release"] == freeze["release"]
                and state["control"]["admission"] == "closed" and state["control"]["workers"] == "frozen"
                and not any(state["work"].values()) and not any(state["terminal"].get(key, 0) for key in
                    ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")),
                "The complete registered target, release, bindings or frozen state changed.")
        guard()
        return state["control"]


def diagnose(env):
    """Read-only stage inventory; no missing record is interpreted as failure."""
    automatic = context(env)
    run_id, attempt, candidate = source_run(env, automatic)
    draft, secrets, previous, store, prefix = open_store(env)
    raw = store.get(prefix + "registration.json")
    require(SHA.fullmatch(env.get("WEBHOOK_REGISTRATION_SHA256", "") or "")
            and sha256(raw).hexdigest() == env["WEBHOOK_REGISTRATION_SHA256"])
    registration = parsed(raw)
    target = validate_target(registration.get("target"))
    desired = dict(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["botId"] == previous["botId"] == TEST_BOT_ID
            and target.data["botUsername"] == "test_cfsubs_bot" and registration.get("draftSha256") == draft.digest
            and registration.get("targetSha256") == target.digest
            and registration.get("configurationSha256") == target.configuration_digest
            and validate_target(desired).configuration_digest == target.configuration_digest)
    suffix = run_id + "-" + attempt
    keys = {"snapshot": prefix + "webhook-" + suffix + ".json", "configured": prefix + suffix + "-webhook-configured.json",
            "ready": prefix + suffix + "-open-backup-ready-for-cleanup.json",
            "acceptance": prefix + suffix + "-backup-head-acceptance.json",
            "pauseIntent": prefix + "backup-admission-" + suffix + "-pause-intent.json",
            "pauseConfirmed": prefix + "backup-admission-" + suffix + "-pause-confirmed.json",
            "freezeIntent": prefix + "backup-admission-" + suffix + "-freeze-intent.json",
            "freezeConfirmed": prefix + "backup-admission-" + suffix + "-freeze-confirmed.json",
            "webhookIntent": prefix + "webhook-recovery-" + suffix + "-intent.json",
            "webhookCompleted": prefix + "webhook-recovery-" + suffix + "-complete.json"}
    records = {name: store.get(key, absent=True) for name, key in keys.items()}
    snapshot_sha = None
    if records["snapshot"] is not None:
        snapshot = parsed(records["snapshot"])
        require(snapshot.get("schemaVersion") == 1 and snapshot.get("runId") == run_id and snapshot.get("runAttempt") == attempt
                and snapshot.get("revision") == candidate and snapshot.get("draftSha256") == draft.digest
                and snapshot.get("botId") == previous["botId"] and snapshot.get("oldWebhookSecret") == previous["webhookSecret"]
                and webhook_settings(snapshot["webhookInfo"])["url"] == ORIGINAL_ORIGIN + "/telegram/webhook")
        snapshot_sha = sha256(records["snapshot"]).hexdigest()
    from production_release_evidence import load_release
    checkpoint, manifest = env.get("WEBHOOK_SOURCE_CHECKPOINT_ID", ""), env.get("WEBHOOK_SOURCE_MANIFEST_SHA256", "")
    require(re.fullmatch(r"[a-f0-9]{32}", checkpoint or "") and SHA.fullmatch(manifest or ""))
    temp = Path(env.get("RUNNER_TEMP", ""))
    require(temp.is_absolute() and temp.is_dir() and not temp.is_symlink())
    token = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    with tempfile.TemporaryDirectory(prefix="webhook-diagnose-source-", dir=temp) as directory:
        source = load_release(target, token, checkpoint, manifest, Path(directory))
        require(source["sourceTarget"].configuration_digest == target.configuration_digest)
        guard = lambda: github.require_current_main(env["GITHUB_SHA"])
        ctl = Controller(target, API(target, token), API(target, env.get("SUBS_BOT_CF_REHEARSAL_WORKER_READ_TOKEN", "")),
                         source["bundle"], source["manifest"], guard=guard, secrets=secrets, control_revision=env["GITHUB_SHA"])
        state = ctl.inspect()
        guard()
    telegram = Telegram(draft, {**secrets, "webhookSecret": previous["webhookSecret"]})
    telegram.identity()
    webhook = webhook_settings(telegram.call("getWebhookInfo"))
    require(webhook["url"] in {ORIGINAL_ORIGIN + "/telegram/webhook", ORIGIN + "/telegram/webhook"})
    backup_store = PrivateStore(API(target, token), target.data["backupBucketName"])
    anchor_raw = backup_store.get("maintenance/production-control/registrations/daily-backup-anchor-" + target.digest + ".json", absent=True)
    anchor = parsed(anchor_raw) if anchor_raw is not None else None
    if anchor is not None:
        require(anchor.get("targetSha256") == target.digest and anchor.get("state") in {"idle", "active"})
    flags = {name: body is not None for name, body in records.items()}
    uncertain = bool(any(state["work"].values()) or any(state["terminal"].get(key, 0) for key in
                      ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
    return {"status": "read-only-diagnosis", "snapshotSha256": snapshot_sha, "privateRecordsPresent": flags,
            "admission": state["control"]["admission"], "workers": state["control"]["workers"],
            "stateSha256": state["stateSha256"], "unsettledOrUnknown": uncertain,
            "anchorObservedState": anchor["state"] if anchor else "missing",
            "anchorObservation": "unverified-read-only-not-authority",
            "webhookLocation": "original" if webhook["url"] == ORIGINAL_ORIGIN + "/telegram/webhook" else "rehearsal",
            "telegramSecretReadback": "not-available", "missingEvidenceMeans": "unknown",
            "automaticRetryAuthorized": False}


def inspect(env, *, execute=False):
    automatic = context(env)
    run_id, attempt, candidate = source_run(env, automatic)
    draft, secrets, previous, store, prefix = open_store(env)
    registration = store.get(prefix + "registration.json")
    registration_pin = env.get("WEBHOOK_REGISTRATION_SHA256", "")
    require(SHA.fullmatch(registration_pin or "") and sha256(registration).hexdigest() == registration_pin)
    registered = parsed(registration)
    target = validate_target(registered.get("target"))
    require(target.environment == "rehearsal" and target.data["workerName"] == draft.data["workerName"]
            and target.data["botId"] == previous["botId"] == TEST_BOT_ID
            and target.data["botUsername"] == "test_cfsubs_bot" and registered.get("draftSha256") == draft.digest
            and registered.get("targetSha256") == target.digest
            and registered.get("configurationSha256") == target.configuration_digest)
    desired = dict(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(validate_target(desired).configuration_digest == target.configuration_digest,
            "The approved registered rehearsal configuration changed.")
    suffix = run_id + "-" + attempt
    snapshot_key = prefix + "webhook-" + suffix + ".json"
    intent_key = prefix + "webhook-recovery-" + suffix + "-intent.json"
    completion_key = prefix + "webhook-recovery-" + suffix + "-complete.json"
    raw = store.get(snapshot_key, absent=True)
    require(isinstance(raw, bytes), "The original webhook snapshot is missing; state remains unknown.")
    pin = sha256(raw).hexdigest()
    supplied = env.get("WEBHOOK_SNAPSHOT_SHA256", "")
    if automatic or execute or supplied:
        require(SHA.fullmatch(supplied or "") and supplied == pin, "The exact independently observed snapshot is required.")
    snapshot = parsed(raw)
    require(snapshot.get("schemaVersion") == 1 and snapshot.get("runId") == run_id and snapshot.get("runAttempt") == attempt
            and snapshot.get("revision") == candidate and snapshot.get("draftSha256") == draft.digest
            and snapshot.get("botId") == previous["botId"] and snapshot.get("oldWebhookSecret") == previous["webhookSecret"])
    before = webhook_settings(snapshot["webhookInfo"])
    require(before["url"] == ORIGINAL_ORIGIN + "/telegram/webhook")
    telegram = Telegram(draft, {**secrets, "webhookSecret": previous["webhookSecret"]})
    telegram.identity()
    current = webhook_settings(telegram.call("getWebhookInfo"))
    require(current["url"] in {before["url"], ORIGIN + "/telegram/webhook"})
    intent = store.get(intent_key, absent=True)
    completion = store.get(completion_key, absent=True)
    # This is also a preflight before admission is closed. Snapshot alone does
    # not establish that the preceding webhook change actually completed.
    configured_raw = store.get(prefix + suffix + "-webhook-configured.json", absent=True)
    require(isinstance(configured_raw, bytes) and current["url"] == ORIGIN + "/telegram/webhook",
            "The preceding webhook change is not confirmed; keep its outcome unknown.")
    configured = parsed(configured_raw)
    candidate_settings = {"url": ORIGIN + "/telegram/webhook", "hasCustomCertificate": False,
                          "maxConnections": target.data["webhook"]["maxConnections"],
                          "allowedUpdates": sorted(target.data["webhook"]["allowedUpdates"])}
    require(configured.get("targetSha256") == target.digest and configured.get("dropPendingUpdates") is False
            and configured.get("webhookSha256") == sha256(canonical(candidate_settings)).hexdigest()
            and current == {"url": candidate_settings["url"], "has_custom_certificate": False,
                            "max_connections": candidate_settings["maxConnections"],
                            "allowed_updates": candidate_settings["allowedUpdates"]},
            "The preceding webhook confirmation is malformed.")
    if env.get("WEBHOOK_SOURCE_KIND") == "phase-coordinator":
        setup_prefix = prefix + "phase-coordinator-webhook-setup-" + suffix + "-"
        setup_raw = store.get(setup_prefix + "intent.json")
        setup_done_raw = store.get(setup_prefix + "confirmed.json")
        setup, setup_done = parsed(setup_raw), parsed(setup_done_raw)
        require(canonical(setup) == setup_raw and canonical(setup_done) == setup_done_raw
                and set(setup) == {"version", "kind", "runId", "runAttempt", "controllerRevision", "dispatcherRevision",
                    "targetSha256", "configurationSha256", "sourceCheckpointId", "sourceManifestSha256", "snapshotSha256",
                    "predecessorSha256", "webhookSettingsSha256", "historySha256"}
                and type(setup["version"]) is int and setup["version"] == 1 and setup["kind"] == "phase-webhook-setup-intent"
                and setup["runId"] == run_id and setup["runAttempt"] == attempt and setup["controllerRevision"] == candidate
                and setup["dispatcherRevision"] == env["WEBHOOK_SOURCE_MAIN_SHA"] and setup["targetSha256"] == target.digest
                and setup["configurationSha256"] == target.configuration_digest and setup["snapshotSha256"] == pin
                and all(SHA.fullmatch(setup.get(k, "")) for k in ("sourceManifestSha256", "predecessorSha256", "webhookSettingsSha256", "historySha256"))
                and re.fullmatch(r"[a-f0-9]{32}", setup.get("sourceCheckpointId", ""))
                and setup["webhookSettingsSha256"] == sha256(canonical({"url": before["url"],
                    "hasCustomCertificate": before["has_custom_certificate"], "maxConnections": before["max_connections"],
                    "allowedUpdates": before["allowed_updates"]})).hexdigest()
                and type(setup_done.get("version")) is int and setup_done == {"version": 1, "kind": "phase-webhook-setup-confirmed",
                    "intentSha256": sha256(setup_raw).hexdigest(), "snapshotSha256": pin,
                    "configuredSha256": sha256(configured_raw).hexdigest(), "targetSha256": target.digest},
                "The one-shot webhook setup intent and confirmation are not independently verified.")
    if not execute:
        if automatic:
            require(intent is None and completion is None,
                    "A prior webhook restore may have started; do not close admission or repeat it.")
        return {"status": "observed", "snapshotSha256": pin, "intentPresent": intent is not None,
                "completionPresent": completion is not None, "settingsMatchOriginal": current == before,
                "telegramSecretReadback": "not-available", "restoreAuthorized": False}
    require(intent is None and completion is None, "An earlier restore is present or uncertain; do not retry.")
    # A separate legacy recovery must never cross an unresolved phase window.
    # A phase cleanup may restore only its own active lock; an old source may
    # restore only after the complete shared lock history proves idle.
    from trusted_backup_webhook_anchor import anchor as webhook_anchor
    lock_pin = env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256", "")
    require(SHA.fullmatch(lock_pin or ""), "The protected shared webhook lock is not configured.")
    lock = webhook_anchor(store, target.digest, lock_pin)
    lock_before, _, _ = lock.read()
    if env.get("WEBHOOK_SOURCE_KIND") == "phase-coordinator":
        require(lock_before["state"] == "active" and lock_before["session"] == suffix
                and lock_before["controlRevision"] == candidate)
    else:
        require(lock_before["state"] == "idle", "An unresolved webhook window blocks legacy restoration.")
    freeze_sha = env.get("WEBHOOK_FREEZE_CONFIRMATION_SHA256", "")
    require(SHA.fullmatch(freeze_sha or ""))
    freeze_raw = store.get(prefix + "backup-admission-" + suffix + "-freeze-confirmed.json")
    require(sha256(freeze_raw).hexdigest() == freeze_sha)
    freeze = parsed(freeze_raw)
    require(canonical(freeze) == freeze_raw and set(freeze) == {"version", "intentSha256", "stateSha256", "targetSha256",
            "configurationSha256", "control", "release", "candidateRevision", "dispatcherRevision"}
            and freeze["version"] == 1 and SHA.fullmatch(freeze["intentSha256"] or "")
            and SHA.fullmatch(freeze["stateSha256"] or "") and freeze["targetSha256"] == target.digest
            and freeze["configurationSha256"] == target.configuration_digest
            and freeze["candidateRevision"] == candidate and freeze["dispatcherRevision"] == env["WEBHOOK_SOURCE_MAIN_SHA"])
    frozen = require_exact_freeze(target, secrets, env, freeze)
    admission = prefix + "backup-admission-" + suffix + "-"
    freeze_intent_raw = store.get(admission + "freeze-intent.json")
    pause_confirmation_raw = store.get(admission + "pause-confirmed.json")
    pause_intent_raw = store.get(admission + "pause-intent.json")
    freeze_intent, pause_confirmation, pause_intent = map(parsed, (freeze_intent_raw, pause_confirmation_raw, pause_intent_raw))
    require(all(canonical(value) == raw for value, raw in ((freeze_intent, freeze_intent_raw),
                (pause_confirmation, pause_confirmation_raw), (pause_intent, pause_intent_raw)))
            and freeze["intentSha256"] == sha256(freeze_intent_raw).hexdigest()
            and freeze_intent.get("pauseConfirmationSha256") == sha256(pause_confirmation_raw).hexdigest()
            and freeze_intent.get("targetSha256") == target.digest and freeze_intent.get("session") == suffix
            and pause_confirmation.get("intentSha256") == sha256(pause_intent_raw).hexdigest()
            and pause_intent.get("targetSha256") == target.digest and pause_intent.get("session") == suffix
            and pause_intent.get("candidateRevision") == candidate)
    if not automatic:
        manual_no_prior_dispatch(env, run_id)
        jobs = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", github._github_token())
        require(type(jobs.get("total_count")) is int and isinstance(jobs.get("jobs"), list)
                and jobs["total_count"] == len(jobs["jobs"]) < 100)
        steps = [step for job in jobs["jobs"] for step in job.get("steps", [])
                 if step.get("name") == "Trusted restore original test webhook"]
        require(len(steps) == 1 and steps[0].get("conclusion") == "skipped",
                "The original cleanup may have run; do not repeat an unknown write.")
    phase_source = env.get("WEBHOOK_SOURCE_KIND") == "phase-coordinator"
    if not phase_source:
        from datetime import datetime, timezone
        owner = env.get("GITHUB_RUN_ID", "") + "-" + env.get("GITHUB_RUN_ATTEMPT", "")
        require(re.fullmatch(r"[1-9][0-9]{0,19}-1", owner or "") and REV.fullmatch(env.get("GITHUB_SHA", "")))
        lock.acquire(owner, datetime.now(timezone.utc).strftime("%Y/%m/%d"), env["GITHUB_SHA"])
        lock_before, _, _ = lock.read()
        require(lock_before["state"] == "active" and lock_before["session"] == owner
                and lock_before["controlRevision"] == env["GITHUB_SHA"])
        require(require_exact_freeze(target, secrets, env, freeze) == frozen
                and webhook_settings(telegram.call("getWebhookInfo")) == current)
    planned = {"version": 1, "sourceRunId": run_id, "sourceAttempt": attempt, "candidateRevision": candidate,
               "snapshotSha256": pin, "beforeSha256": sha256(canonical(before)).hexdigest(),
               "predecessorSha256": sha256(canonical(current)).hexdigest()}
    github.require_current_main(env["GITHUB_SHA"])
    claim_intent_once(store, intent_key, canonical(planned))
    lock_after, _, _ = lock.read()
    require(lock_after == lock_before, "The shared webhook lock changed after the restore intent.")
    require(require_exact_freeze(target, secrets, env, freeze) == frozen,
            "The complete isolated predecessor changed after its restore intent.")
    require(webhook_settings(telegram.call("getWebhookInfo")) == current, "Webhook predecessor changed after intent.")
    acknowledged = telegram.call("setWebhook", {"url": before["url"], "secret_token": previous["webhookSecret"],
        "drop_pending_updates": False, "allowed_updates": before["allowed_updates"], "max_connections": before["max_connections"]})
    require(acknowledged is True and webhook_settings(telegram.call("getWebhookInfo")) == before
            and probe_original_webhook(previous["webhookSecret"]) == 400,
            "Webhook restoration was not independently confirmed; do not retry.")
    done = {"version": 1, "intentSha256": sha256(canonical(planned)).hexdigest(), "snapshotSha256": pin,
            "settingsSha256": sha256(canonical(before)).hexdigest(), "dropPendingUpdates": False,
            "telegramSecretReadback": "not-available"}
    store.put(completion_key, canonical(done))
    require(store.get(completion_key) == canonical(done))
    if not phase_source:
        require(require_exact_freeze(target, secrets, env, freeze) == frozen
                and webhook_settings(telegram.call("getWebhookInfo")) == before
                and probe_original_webhook(previous["webhookSecret"]) == 400)
        lock.release(owner)
        released, _, _ = lock.read()
        require(released["state"] == "idle" and released["session"] == owner)
    return {"status": "settings-restored", "snapshotSha256": pin, "completionSha256": sha256(canonical(done)).hexdigest(),
            "dropPendingUpdates": False, "telegramSecretReadback": "not-available"}


if __name__ == "__main__":
    try:
        action = os.environ.get("WEBHOOK_RECOVERY_ACTION", "")
        require(action in {"inspect", "diagnose", "restore"})
        result = diagnose(os.environ) if action == "diagnose" else inspect(os.environ, execute=action == "restore")
        print(json.dumps(result, sort_keys=True))
        if action == "diagnose" and (result["unsettledOrUnknown"] or result["admission"] != "closed"
                                      or result["workers"] != "frozen" or result["snapshotSha256"] is None
                                      or result["anchorObservedState"] != "idle"
                                      or result["webhookLocation"] != "original"
                                      or result["privateRecordsPresent"]["webhookIntent"]
                                      and not result["privateRecordsPresent"]["webhookCompleted"]):
            print("::warning::The isolated backup or webhook requires independent reconciliation.")
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
                if result["snapshotSha256"] is not None:
                    output.write("snapshot_sha256=" + result["snapshotSha256"] + "\n")
    except Exception:
        print(json.dumps({"status": "unknown", "reason": "Webhook state or restoration is not confirmed; do not retry an unknown write."}))
        raise SystemExit(1) from None

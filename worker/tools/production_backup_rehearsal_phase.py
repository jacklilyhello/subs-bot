"""Rehearsal-only adapters for the shared backup phase dispatcher.

The trusted main workflow must validate and pin the candidate before giving it
isolated credentials. No caller may change the real GitHub execution context.
"""
from datetime import datetime, timezone
import json
import re
import time

import prepare_isolation_artifact as github
from production_lifecycle_drill import SERVICE, approval
from production_target import approve, canonical, digest, parsed, require

PHASE_FILE = ".github/workflows/worker-backup-phase-rehearsal.yml"
PARENT_FILE = ".github/workflows/worker-backup-reviewed-coordinator.yml"
PARENT_STEP = "Coordinate reviewed isolated backup phases"
HEX40 = re.compile(r"[a-f0-9]{40}")
HEX64 = re.compile(r"[a-f0-9]{64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
STEPS = ("plan-begin", "begin", "preflight", "plan-pause", "pause", "drain", "freeze", "capture", "verify", "plan-activate", "activate")
BASE = "maintenance/production-control/evidence/backup-coordinator/"


def public_phase_result(result, target, candidate_revision, dispatcher_revision, verified_proof):
    """Project only safe fields and the previously verified source identity."""
    require(isinstance(result, dict) and target.environment == "rehearsal"
            and HEX64.fullmatch(target.digest or "") and HEX40.fullmatch(candidate_revision or "")
            and HEX40.fullmatch(dispatcher_revision or "") and isinstance(verified_proof, dict)
            and HEX40.fullmatch(verified_proof.get("revision", "")))
    safe_keys = {"status", "action", "stateSha256", "session", "day", "pauseSeconds", "pauseLimitExceeded",
                 "capacity", "checkpointId", "manifestSha256", "approvalAction"}
    observed = result.get("state")
    public = {key: value for key, value in result.items() if key in safe_keys}
    if isinstance(observed, dict) and "stateSha256" in observed:
        public["stateSha256"] = observed["stateSha256"]
    public.update(targetSha256=target.digest, controlRevision=candidate_revision, dispatcherRevision=dispatcher_revision,
                  sourceRevision=verified_proof["revision"], scheduleEnabled=False, automaticReplay=False,
                  consumerSwitch="not-authorized")
    return public


def intent_key(target_sha, session, sequence):
    require(HEX64.fullmatch(target_sha or "") and DECIMAL.fullmatch(session or "")
            and type(sequence) is int and 1 <= sequence <= len(STEPS))
    return f"{BASE}{target_sha}/{session}/{sequence:02d}-intent.json"


def validate_dispatch_intent(raw, *, target_sha, session, action, main_sha, candidate_sha, inputs):
    value = parsed(raw)
    require(isinstance(value, dict) and canonical(value) == raw
            and set(value) == {"version", "kind", "targetSha256", "session", "sequence", "action",
                "controllerRevision", "candidateRevision", "profile", "nonce", "inputSha256",
                "createdAt", "writerRunId", "writerAttempt"}
            and type(value["version"]) is int and value["version"] == 1
            and value["kind"] == "backup-dispatch-intent" and value["profile"] == "rehearsal"
            and value["targetSha256"] == target_sha and value["session"] == session
            and value["action"] == action and action in STEPS and type(value["sequence"]) is int
            and value["sequence"] == STEPS.index(action) + 1
            and value["controllerRevision"] == main_sha and value["candidateRevision"] == candidate_sha
            and HEX40.fullmatch(main_sha or "") and HEX40.fullmatch(candidate_sha or "")
            and HEX64.fullmatch(value["nonce"] or "") and value["nonce"] == inputs.get("dispatch_nonce")
            and value["inputSha256"] == digest(inputs) and type(value["createdAt"]) is int
            and 0 < value["createdAt"] <= int(time.time()) + 60
            and DECIMAL.fullmatch(value["writerRunId"] or "") and value["writerAttempt"] == "1")
    return value


def require_parent_running(intent, main_sha, candidate_sha, token):
    run_id = intent["writerRunId"]
    run = github._get_json("/actions/runs/" + run_id, token)
    expected = {"Rehearsal backup coordinator " + action + " at " + main_sha + " candidate " + candidate_sha
                for action in ("run", "resume")}
    require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
            and run.get("path") in {PARENT_FILE, PARENT_FILE + "@main", PARENT_FILE + "@refs/heads/main"}
            and run.get("head_sha") == main_sha and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch" and run.get("status") == "in_progress"
            and run.get("display_title") in expected
            and all(isinstance(run.get(k), dict) and run[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")), "The exact rehearsal coordinator is not running.")
    response = github._get_json("/actions/runs/" + run_id + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100)
    matched = [job for job in jobs if isinstance(job, dict) and job.get("name") == "coordinate"]
    require(len(matched) == 1 and str(matched[0].get("run_id")) == run_id and matched[0].get("run_attempt") == 1
            and matched[0].get("head_sha") == main_sha and matched[0].get("status") == "in_progress"
            and matched[0].get("conclusion") is None and isinstance(matched[0].get("steps"), list))
    steps = [step for step in matched[0]["steps"] if isinstance(step, dict) and step.get("name") == PARENT_STEP]
    require(len(steps) == 1 and steps[0].get("status") == "in_progress" and steps[0].get("conclusion") is None,
            "The exact rehearsal coordinator step is not running.")


class RehearsalPhaseRuntime:
    """Only a fixed, verified rehearsal target may synthesize rehearsal approvals."""
    def __init__(self, target, *, controller_revision, dispatcher_revision, source_revision, env, guard):
        require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE
                and HEX40.fullmatch(controller_revision or "") and HEX40.fullmatch(dispatcher_revision or "")
                and HEX40.fullmatch(source_revision or "") and callable(guard))
        self.target, self.controller_revision, self.dispatcher_revision = target, controller_revision, dispatcher_revision
        self.dispatcher_workflow, self.source_revision, self.env, self.guard = PHASE_FILE.rsplit("/", 1)[1], source_revision, env, guard

    def envelope(self, action, predecessor, key="SUBS_BOT_APPROVAL_JSON"):
        self.guard()
        return canonical(approval(self.target, action, self.source_revision, predecessor,
                                  control_revision=self.controller_revision)).decode("utf-8")

    def authorized(self, target, env, action, source_revision, predecessor, control_revision, *, key="SUBS_BOT_APPROVAL_JSON"):
        require(target is self.target and env is self.env and source_revision == self.source_revision
                and control_revision == self.controller_revision)
        return approve(target, self.envelope(action, predecessor, key), action, source_revision, predecessor,
                       control_revision=control_revision)

    def intent_metadata(self, state):
        env = self.env
        require(env.get("GITHUB_RUN_ATTEMPT") == "1" and DECIMAL.fullmatch(env.get("GITHUB_RUN_ID", "")))
        result = {"stateSha256": state["stateSha256"], "control": state["control"],
                  "runId": env["GITHUB_RUN_ID"], "runAttempt": "1", "controlRevision": self.controller_revision,
                  "dispatcherRevision": self.dispatcher_revision, "dispatcherWorkflow": self.dispatcher_workflow}
        nonce = env.get("BACKUP_DISPATCH_NONCE", "")
        require(HEX64.fullmatch(nonce or ""))
        require(isinstance(getattr(self, "intent", None), dict) and getattr(self, "store", None) is not None)
        import production_backup_coordinator as coordinator
        claim_sha = coordinator.verify_child_claim(self.store.objects, self.intent, env["GITHUB_RUN_ID"], "1")
        result.update(dispatchNonce=nonce, coordinatorSession=self.intent["session"],
                      dispatchSequence=self.intent["sequence"], dispatchIntentSha256=digest(self.intent),
                      childClaimSha256=claim_sha)
        return result

    def begin_evidence(self):
        require(isinstance(getattr(self, "intent", None), dict) and self.intent["action"] == "begin")
        state = {"stateSha256": "0" * 64, "control": {}}
        details = self.intent_metadata(state)
        return {key: details[key] for key in ("coordinatorSession", "dispatchSequence", "dispatchIntentSha256",
                                               "childClaimSha256", "dispatchNonce")}

    def require_finished(self, details, *, allowed_actions=None):
        import production_backup_cli as backup
        import production_backup_coordinator as coordinator
        require(isinstance(details, dict) and DECIMAL.fullmatch(details.get("coordinatorSession", ""))
                and type(details.get("dispatchSequence")) is int and 1 <= details["dispatchSequence"] <= len(STEPS)
                and HEX64.fullmatch(details.get("dispatchIntentSha256", ""))
                and HEX64.fullmatch(details.get("childClaimSha256", "")))
        raw, _ = self.store.objects.get(intent_key(self.target.digest, details["coordinatorSession"], details["dispatchSequence"]))
        prior = parsed(raw)
        require(isinstance(prior, dict) and canonical(prior) == raw and digest(prior) == details["dispatchIntentSha256"]
                and prior.get("profile") == "rehearsal" and prior.get("targetSha256") == self.target.digest
                and prior.get("session") == details["coordinatorSession"] and prior.get("sequence") == details["dispatchSequence"]
                and prior.get("controllerRevision") == details.get("dispatcherRevision")
                and prior.get("candidateRevision") == self.controller_revision
                and prior.get("nonce") == details.get("dispatchNonce"))
        claim_sha = coordinator.verify_child_claim(self.store.objects, prior, details.get("runId", ""), details.get("runAttempt", ""))
        require(claim_sha == details["childClaimSha256"], "The original child claim differs.")
        return backup.require_finished_intent(details, allowed_actions=allowed_actions, rehearsal=True)

    def confirm_plan_run(self, session, day, revision):
        # A trustworthy plan requires its private intent and verified original
        # result, not just a matching run title. The caller must provide an
        # independently verified plan callback before a begin is permitted.
        require(revision == self.controller_revision and callable(getattr(self, "verified_plan", None)),
                "The isolated plan origin has not been independently verified.")
        return self.verified_plan(session, day, revision)


def verify_trusted_gate(env):
    """Run the fixed main checkout's gate, never the candidate module of the same name."""
    import subprocess
    import sys
    from pathlib import Path
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    trusted = workspace / "trusted" / "worker" / "tools" / "trusted_backup_phase_gate.py"
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink()
            and trusted.is_file() and not trusted.is_symlink())
    result = subprocess.run([sys.executable, "-B", str(trusted)], env=env, capture_output=True,
                            check=True, timeout=90)
    require(len(result.stdout) <= 4096 and len(result.stderr) <= 4096)
    report = parsed(result.stdout)
    require(report == {"status": "validated", "dispatcherMainSha": env.get("GITHUB_SHA"),
                       "reviewedHeadSha": env.get("BACKUP_REVIEWED_HEAD_SHA")})
    return report


def prepare_coordinator_context(env, validation, *, guard):
    """Load only the registered isolation target and its pinned private source.

    The trusted caller validates its own main/candidate workflow identity; the
    callback rechecks that identity before and after each source observation.
    The returned Drill retains its temporary source directory until the caller
    finishes. No target is accepted from the caller as an authoritative pin.
    """
    import production_backup_cli as backup
    import production_recovery as recovery
    from production_lifecycle_drill import Drill
    from production_storage import PrivateStore

    require(isinstance(validation, dict) and callable(guard)
            and set(validation) == {"version", "pr", "headSha", "registrationSha256", "sourceCheckpointId",
                                    "sourceManifestSha256", "genesisSha256", "checkpointId"}
            and validation.get("version") == 1 and HEX40.fullmatch(validation.get("headSha", ""))
            and HEX64.fullmatch(validation.get("registrationSha256", ""))
            and HEX64.fullmatch(validation.get("sourceManifestSha256", ""))
            and HEX64.fullmatch(validation.get("genesisSha256", ""))
            and re.fullmatch(r"[a-f0-9]{32}", validation.get("sourceCheckpointId", ""))
            and re.fullmatch(r"[a-f0-9]{32}", validation.get("checkpointId", ""))
            and validation["checkpointId"] != validation["sourceCheckpointId"])
    guard()
    local = dict(env)
    local["DRILL_REGISTRATION_SHA256"] = validation["registrationSha256"]
    local["DRILL_BACKUP_SOURCE_CHECKPOINT_ID"] = validation["sourceCheckpointId"]
    local["DRILL_BACKUP_SOURCE_MANIFEST_SHA256"] = validation["sourceManifestSha256"]
    tool = Drill(local, control_revision=validation["headSha"])
    tool.guard = guard
    target, bundle, manifest = tool.prepare_maintenance()
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE)
    proof, archive = tool.code_archive()
    policy = backup.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", ""))
    name = "subs-bot-cf-restore-control-" + validation["checkpointId"][:16]
    contract = recovery.recovery_contract(canonical({"version": 1, "checkpointId": validation["checkpointId"],
        "databaseName": name, "objectsName": name, "purpose": "baseline"}), target.data)
    api = recovery.RecoveryAPI(target.data, env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", ""), None, contract)
    api.verify_backup()
    from production_control import API
    store = PrivateStore(API(target, env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")), target.data["backupBucketName"])
    require(store.objects is not None, "The isolated coordinator requires a scoped private store.")
    guard()
    return {"tool": tool, "target": target, "bundle": bundle, "manifest": manifest, "proof": proof,
            "archive": archive, "policy": policy, "contract": contract, "store": store,
            "sourceCheckpointId": validation["sourceCheckpointId"],
            "sourceManifestSha256": validation["sourceManifestSha256"], "genesisSha256": validation["genesisSha256"]}


def verify_owned_webhook_window(context, start, main_sha, candidate_sha):
    """Re-read the original isolated webhook window before continuing phases.

    The Bot API cannot reveal its stored secret. A confirmed one-shot setup,
    unchanged private lock, absence of cleanup intents and an authenticated
    no-update probe are all required; none authorizes another setWebhook.
    """
    from hashlib import sha256
    from production_lifecycle_drill import ORIGIN, ORIGINAL_ORIGIN, public_readback, public_request, webhook_settings
    from production_target import TEST_BOT_ID
    from trusted_backup_webhook_anchor import anchor as webhook_anchor

    tool, target = context["tool"], context["target"]
    require(isinstance(start, dict) and set(start) == {"version", "action", "targetSha256", "controlRevision", "session",
            "sourceCheckpointId", "sourceManifestSha256", "anchorSha256", "policySha256", "writerRunId", "writerAttempt",
            "profile", "candidateRevision", "validationSha256"} and type(start.get("version")) is int
            and target.environment == "rehearsal"
            and target.data["workerName"] == SERVICE and target.data["botId"] == TEST_BOT_ID
            and target.data["botUsername"] == "test_cfsubs_bot" and start.get("version") == 1
            and start.get("action") == "run" and start.get("profile") == "rehearsal"
            and start.get("targetSha256") == target.digest and start.get("controlRevision") == main_sha
            and start.get("candidateRevision") == candidate_sha and HEX40.fullmatch(main_sha or "")
            and HEX40.fullmatch(candidate_sha or "") and DECIMAL.fullmatch(start.get("session", ""))
            and all(HEX64.fullmatch(start.get(key, "")) for key in ("anchorSha256", "policySha256", "validationSha256"))
            and DECIMAL.fullmatch(start.get("writerRunId", "")) and start.get("writerAttempt") == "1"
            and start.get("sourceCheckpointId") == context["sourceCheckpointId"]
            and start.get("sourceManifestSha256") == context["sourceManifestSha256"])
    run_id = start["writerRunId"]
    source = github._get_json("/actions/runs/" + run_id + "/attempts/1", github._github_token())
    latest = github._get_json("/actions/runs/" + run_id, github._github_token())
    require(str(source.get("id")) == str(latest.get("id")) == run_id
            and source.get("run_attempt") == latest.get("run_attempt") == 1
            and source.get("path") in {PARENT_FILE, PARENT_FILE + "@main", PARENT_FILE + "@refs/heads/main"}
            and source.get("head_sha") == main_sha and source.get("head_branch") == "main"
            and source.get("event") == "workflow_dispatch" and source.get("status") in {"in_progress", "completed"}
            and source.get("display_title") == "Rehearsal backup coordinator run at " + main_sha + " candidate " + candidate_sha
            and all(isinstance(source.get(k), dict) and source[k].get("id") == github.REPOSITORY_ID
                    for k in ("repository", "head_repository")), "The original webhook window run is unconfirmed.")
    suffix = run_id + "-1"
    store, prefix = tool.store, tool.prefix
    lock = webhook_anchor(store, target.digest, tool.env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256", ""))
    pinned, raw_anchor, _ = lock.read()
    require(pinned["state"] == "active" and pinned["session"] == suffix
            and pinned["controlRevision"] == candidate_sha, "The original webhook window no longer owns its lock.")
    for name in ("webhook-recovery-" + suffix + "-intent.json", "webhook-recovery-" + suffix + "-complete.json",
                 "backup-admission-" + suffix + "-pause-intent.json", "backup-admission-" + suffix + "-pause-confirmed.json",
                 "backup-admission-" + suffix + "-freeze-intent.json", "backup-admission-" + suffix + "-freeze-confirmed.json",
                 "phase-webhook-unstarted-" + suffix + "-intent.json", "phase-webhook-unstarted-" + suffix + "-complete.json"):
        require(store.get(prefix + name, absent=True) is None,
                "A cleanup or release intent exists; stop and reconcile it independently.")
    names = {"snapshot": "webhook-" + suffix + ".json", "configured": suffix + "-webhook-configured.json",
             "intent": "phase-coordinator-webhook-setup-" + suffix + "-intent.json",
             "confirmed": "phase-coordinator-webhook-setup-" + suffix + "-confirmed.json"}
    bodies = {key: store.get(prefix + name) for key, name in names.items()}
    values = {key: parsed(raw) for key, raw in bodies.items()}
    require(all(canonical(values[key]) == bodies[key] for key in values))
    snapshot, configured, intent, confirmed = (values[key] for key in ("snapshot", "configured", "intent", "confirmed"))
    snapshot_sha, intent_sha = sha256(bodies["snapshot"]).hexdigest(), sha256(bodies["intent"]).hexdigest()
    original = webhook_settings(snapshot.get("webhookInfo"))
    original_settings = {"url": original["url"], "hasCustomCertificate": False,
                         "maxConnections": original["max_connections"], "allowedUpdates": original["allowed_updates"]}
    require(set(snapshot) == {"schemaVersion", "draftSha256", "botId", "oldWebhookSecret", "webhookInfo", "revision", "runId", "runAttempt"}
            and type(snapshot.get("schemaVersion")) is int and snapshot.get("schemaVersion") == 1
            and snapshot.get("runId") == run_id and snapshot.get("runAttempt") == "1"
            and snapshot.get("revision") == candidate_sha and snapshot.get("draftSha256") == tool.draft.digest
            and snapshot.get("botId") == tool.previous["botId"] == TEST_BOT_ID
            and snapshot.get("oldWebhookSecret") == tool.previous["webhookSecret"]
            and original["url"] == ORIGINAL_ORIGIN + "/telegram/webhook")
    require(set(intent) == {"version", "kind", "runId", "runAttempt", "controllerRevision", "dispatcherRevision",
            "targetSha256", "configurationSha256", "sourceCheckpointId", "sourceManifestSha256", "snapshotSha256",
            "predecessorSha256", "webhookSettingsSha256", "historySha256"}
            and type(intent.get("version")) is int and intent.get("version") == 1 and intent.get("kind") == "phase-webhook-setup-intent"
            and intent.get("runId") == run_id and intent.get("runAttempt") == "1"
            and intent.get("controllerRevision") == candidate_sha and intent.get("dispatcherRevision") == main_sha
            and intent.get("targetSha256") == target.digest and intent.get("configurationSha256") == target.configuration_digest
            and intent.get("sourceCheckpointId") == context["sourceCheckpointId"]
            and intent.get("sourceManifestSha256") == context["sourceManifestSha256"]
            and intent.get("snapshotSha256") == snapshot_sha
            and intent.get("webhookSettingsSha256") == digest(original_settings)
            and all(HEX64.fullmatch(intent.get(key, "")) for key in ("predecessorSha256", "webhookSettingsSha256", "historySha256")))
    require(type(confirmed.get("version")) is int and confirmed == {"version": 1, "kind": "phase-webhook-setup-confirmed", "intentSha256": intent_sha,
            "snapshotSha256": snapshot_sha, "configuredSha256": sha256(bodies["configured"]).hexdigest(),
            "targetSha256": target.digest} and configured.get("targetSha256") == target.digest
            and configured.get("configurationSha256") == target.configuration_digest
            and configured.get("dropPendingUpdates") is False)
    ctl = context.get("controller") or tool.bind(target, context["bundle"], context["manifest"])
    context["controller"] = ctl
    current = ctl.telegram.plan_webhook()
    expected = {"url": ORIGIN + "/telegram/webhook", "hasCustomCertificate": False,
                "maxConnections": target.data["webhook"]["maxConnections"],
                "allowedUpdates": sorted(target.data["webhook"]["allowedUpdates"])}
    require(current.get("settings") == expected and configured.get("webhookSha256") == current.get("settingsSha256"))
    status = public_readback(public_request(ORIGIN + "/telegram/webhook", method="POST", data=b"{}",
                              secret=tool.secrets["webhookSecret"]), 4096, timeout=45)[0]
    require(status == 400, "The isolated webhook authentication could not be independently confirmed.")
    state = ctl.inspect()
    require(not any(state["terminal"].get(key, 0) for key in
                    ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")))
    tool.guard()
    again, raw_again, _ = lock.read()
    require(again == pinned and raw_again == raw_anchor, "The webhook window changed during observation.")
    return {"targetSha256": target.digest, "configurationSha256": target.configuration_digest,
            "sourceRunId": run_id, "anchorSha256": sha256(raw_anchor).hexdigest(), "snapshotSha256": snapshot_sha,
            "setupIntentSha256": intent_sha, "setupConfirmedSha256": sha256(bodies["confirmed"]).hexdigest(),
            "settingsSha256": current["settingsSha256"], "stateSha256": state["stateSha256"]}


def run(env):
    """Execute one pinned rehearsal phase after the trusted gate has run."""
    import os
    from pathlib import Path
    import production_backup_cli as backup
    import production_backup_coordinator as coordinator
    import production_recovery as recovery
    from production_lifecycle_drill import Drill
    from production_target import canonical

    # This is a second check inside the already-reviewed candidate. The trusted
    # main job must have performed its own gate before injecting any credentials.
    gate_env = dict(env)
    gate_env["BACKUP_CHECKOUT_PHASE"] = "ready"
    verify_trusted_gate(gate_env)
    spec = parsed(env["HEAD_VALIDATION_JSON"])
    require(spec["checkpointId"] != spec["sourceCheckpointId"], "A new backup requires a distinct checkpoint.")
    main_sha, candidate_sha = env["GITHUB_SHA"], spec["headSha"]
    require(env.get("HEAD_TRUSTED_MAIN_SHA") == main_sha and env.get("HEAD_TRUSTED_REVIEWED_SHA") == candidate_sha
            and env.get("SUBS_BOT_CONTROL_ENVIRONMENT") == "subs-bot-isolation")
    local = dict(env)
    local["DRILL_REGISTRATION_SHA256"] = spec["registrationSha256"]
    local["DRILL_BACKUP_SOURCE_CHECKPOINT_ID"] = spec["sourceCheckpointId"]
    local["DRILL_BACKUP_SOURCE_MANIFEST_SHA256"] = spec["sourceManifestSha256"]
    local["SUBS_BOT_BACKUP_GENESIS_SHA256"] = spec["genesisSha256"]
    local["SUBS_BOT_CF_DATA_TOKEN"] = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    local["BACKUP_SOURCE_CHECKPOINT_ID"] = spec["sourceCheckpointId"]
    local["BACKUP_SOURCE_MANIFEST_SHA256"] = spec["sourceManifestSha256"]
    tool = Drill(local, control_revision=candidate_sha)
    def identity_guard():
        verify_trusted_gate(gate_env)
    tool.guard = identity_guard
    target, bundle, manifest = tool.prepare_maintenance()
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE)
    ctl = tool.bind(target, bundle, manifest)
    before = ctl.inspect()
    require(before["release"]["revision"] == manifest["revision"]
            and before["release"]["moduleSha256"] == manifest["bundleSha256"])
    proof, archive = tool.code_archive()
    policy = backup.settings(env.get("SUBS_BOT_BACKUP_POLICY_JSON", ""))
    name = "subs-bot-cf-restore-control-" + spec["checkpointId"][:16]
    contract = recovery.recovery_contract(canonical({"version": 1, "checkpointId": spec["checkpointId"],
        "databaseName": name, "objectsName": name, "purpose": "baseline"}), target.data)
    api = recovery.RecoveryAPI(target.data, local["SUBS_BOT_CF_DATA_TOKEN"], ctl.worker, contract)
    api.verify_backup()
    source = recovery.RecoverySource(api, target.data, bundle, manifest, ctl.inspect, identity_guard)
    source.archive_body, source.code_proof = archive, proof
    from production_storage import PrivateStore
    store = PrivateStore(ctl.data, target.data["backupBucketName"])
    require(store.objects is not None, "The isolated phase requires the independently scoped private store.")
    action = env.get("BACKUP_ACTION", "")
    session = env.get("BACKUP_COORDINATOR_SESSION", "")
    inputs = {"validation_json": env["HEAD_VALIDATION_JSON"], "action": action,
              "source_checkpoint_id": spec["sourceCheckpointId"], "source_manifest_sha256": spec["sourceManifestSha256"],
              "dispatch_nonce": env.get("BACKUP_DISPATCH_NONCE", ""), "coordinator_session": session,
              "dispatch_deadline": env.get("BACKUP_DISPATCH_DEADLINE", "")}
    if env.get("BACKUP_SESSION"):
        inputs.update(session=env["BACKUP_SESSION"], session_day=env.get("BACKUP_SESSION_DAY", ""))
    if env.get("BACKUP_STATE_SHA256"):
        inputs["state_sha256"] = env["BACKUP_STATE_SHA256"]
    require(action in STEPS)
    raw, _ = store.objects.get(intent_key(target.digest, session, STEPS.index(action) + 1))
    intent = validate_dispatch_intent(raw, target_sha=target.digest, session=session, action=action,
                                      main_sha=main_sha, candidate_sha=candidate_sha, inputs=inputs)
    sequence = STEPS.index(action) + 1
    prior, pause_until = coordinator.completed_results(store.objects, target.digest, session, main_sha,
        github._github_token(), spec["sourceCheckpointId"], spec["sourceManifestSha256"], backup.maximum_pause(policy),
        stop_before=sequence, profile="rehearsal", candidate_revision=candidate_sha,
        validation_json=env["HEAD_VALIDATION_JSON"])
    require(len(prior) == sequence - 1, "A prior phase has not been independently verified.")
    expected, pause_until = coordinator.stage_inputs(prior, spec["sourceCheckpointId"], spec["sourceManifestSha256"],
        session, intent, backup.maximum_pause(policy), pause_until, validation_json=env["HEAD_VALIDATION_JSON"])
    require(expected == inputs and intent["inputSha256"] == digest(expected),
            "The phase inputs differ from the complete verified predecessor chain.")
    raw_deadline = env.get("BACKUP_DISPATCH_DEADLINE", "")
    require(re.fullmatch(r"0|[1-9][0-9]{0,19}", raw_deadline))
    deadline = int(raw_deadline)
    require(deadline == (pause_until or 0), "The exact predecessor pause deadline differs.")
    start_key = BASE + target.digest + "/" + session + "/start-intent.json"
    start_raw, _ = store.objects.get(start_key)
    start = parsed(start_raw)
    require(canonical(start) == start_raw and start.get("session") == session)
    window_context = {"tool": tool, "target": target, "bundle": bundle, "manifest": manifest, "controller": ctl,
                      "sourceCheckpointId": spec["sourceCheckpointId"],
                      "sourceManifestSha256": spec["sourceManifestSha256"]}
    def parent_guard():
        identity_guard()
        if action in {"pause", "freeze", "capture"}:
            require(deadline > int(time.time()), "The isolated pause deadline has elapsed.")
        require_parent_running(intent, main_sha, candidate_sha, github._github_token())
        current_start, _ = store.objects.get(start_key)
        require(current_start == start_raw, "The original coordinator start intent changed.")
        verify_owned_webhook_window(window_context, start, main_sha, candidate_sha)
        require_parent_running(intent, main_sha, candidate_sha, github._github_token())
        if action in {"pause", "freeze", "capture"}:
            require(deadline > int(time.time()), "The isolated pause deadline elapsed before the write.")
    parent_guard()
    coordinator.claim_child_once(store.objects, intent, env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""))
    def bounded_guard():
        parent_guard()
        coordinator.verify_child_claim(store.objects, intent, env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""))
    bounded_guard()
    ctl.guard = bounded_guard
    source.guard = bounded_guard
    runtime = RehearsalPhaseRuntime(target, controller_revision=candidate_sha, dispatcher_revision=main_sha,
                                    source_revision=proof["revision"], env=local, guard=identity_guard)
    def verified_plan(session_id, day, revision):
        evidence = coordinator.verified_plan_begin(store.objects, target.digest, session, main_sha, github._github_token(),
            spec["sourceCheckpointId"], spec["sourceManifestSha256"], backup.maximum_pause(policy), profile="rehearsal",
            candidate_revision=candidate_sha, validation_json=env["HEAD_VALIDATION_JSON"])
        require(revision == candidate_sha and evidence["result"].get("session") == session_id
                and evidence["result"].get("day") == day)
        return True
    runtime.verified_plan = verified_plan
    runtime.store, runtime.intent = store, intent
    result = backup.execute_phase(action=action, env=local, target=target, revision=candidate_sha, policy=policy,
        contract=contract, proof=proof, state=before, store=store, guard=bounded_guard, bounded_guard=bounded_guard,
        ctl=ctl, source=source, api=api, directory=Path(env["RUNNER_TEMP"]), runtime=runtime)
    # This is the same public projection as production, without invoking its
    # production-only current-main check with the candidate SHA.
    public = public_phase_result(result, target, candidate_sha, main_sha, proof)
    identity_guard()
    path = Path(env["RUNNER_TEMP"]) / "production-backup-result.json"
    with recovery.native.private_file(path) as output:
        output.write(canonical(public))
    print(json.dumps(public, sort_keys=True))
    return public


if __name__ == "__main__":
    import os
    try:
        os.umask(0o077)
        run(os.environ)
    except Exception:
        print("::error::The isolated backup phase stopped; preserve and inspect the private intent before continuing.")
        raise SystemExit(1) from None

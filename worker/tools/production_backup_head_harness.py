"""Exact-PR-head, dedicated-rehearsal-only backup verification harness.

The production main-only lifecycle and recovery entry points are unchanged.
This harness refuses an open source and never configures a Telegram webhook.
"""
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import subprocess

import prepare_isolation_artifact as artifact
import production_backup_transaction as maintenance
from production_lifecycle_drill import Drill, SERVICE
from production_control import API, privacy, rows
from production_release_evidence import verify_activation_baseline
from production_storage import PrivateStore
from production_target import canonical, digest, parsed, require


FILE = ".github/workflows/worker-backup-reviewed-head.yml"


def public_result(result):
    """Project only bounded evidence; full control and test identities stay private."""
    value = {}
    for key in ("headRevision", "dispatcherMainRevision"):
        if isinstance(result.get(key), str) and re.fullmatch(r"[a-f0-9]{40}", result[key]):
            value[key] = result[key]
    for key in ("targetSha256", "stateSha256", "genesisSha256", "manifestSha256"):
        if isinstance(result.get(key), str) and re.fullmatch(r"[a-f0-9]{64}", result[key]):
            value[key] = result[key]
    if result.get("status") in {"observed", "planned", "initialized", "passed", "warning",
                                "awaiting-trusted-webhook-restoration"}:
        value["status"] = result["status"]
    for key in ("mutationPerformed", "productionMutated", "webhookTouched", "baselineVerified"):
        if type(result.get(key)) is bool:
            value[key] = result[key]
    if result.get("environment") == "rehearsal":
        value["environment"] = "rehearsal"
    for key in ("runId", "runAttempt"):
        if isinstance(result.get(key), str) and re.fullmatch(r"[1-9][0-9]{0,19}", result[key]):
            value[key] = result[key]
    stages = result.get("stages")
    if isinstance(stages, list):
        value["stages"] = [{"stage": stage["stage"], "sha256": stage["sha256"]} for stage in stages
            if isinstance(stage, dict) and isinstance(stage.get("stage"), str)
            and re.fullmatch(r"[a-z0-9-]{1,80}", stage["stage"])
            and isinstance(stage.get("sha256"), str) and re.fullmatch(r"[a-f0-9]{64}", stage["sha256"])]
    maintenance = result.get("dailyBackupAcceptance", result.get("backupMaintenance"))
    if isinstance(maintenance, dict):
        summary = {}
        for key in ("pauseSeconds", "pauseLimitSeconds"):
            if type(maintenance.get(key)) in (int, float) and 0 <= maintenance[key] <= 86400:
                summary[key] = maintenance[key]
        for key in ("pauseLimitExceeded", "admissionRestored", "authorizationUnchanged", "initiallyFrozen"):
            if type(maintenance.get(key)) is bool:
                summary[key] = maintenance[key]
        baseline = maintenance.get("baseline")
        if isinstance(baseline, dict):
            for key, pattern in (("checkpointId", r"[a-f0-9]{32}"), ("manifestSha256", r"[a-f0-9]{64}")):
                if isinstance(baseline.get(key), str) and re.fullmatch(pattern, baseline[key]):
                    summary[key] = baseline[key]
        capacity = maintenance.get("capacity")
        if isinstance(capacity, dict):
            for key in ("rows", "rowLimit", "objectCount", "objectLimit", "objectBytes", "objectBytesLimit"):
                if type(capacity.get(key)) is int and 0 <= capacity[key] <= 1 << 50:
                    summary[key] = capacity[key]
            for key in ("rowStatus", "objectStatus", "objectBytesStatus"):
                if capacity.get(key) in {"normal", "warning", "over-limit", "unknown", "not-checked", "unverified"}:
                    summary[key] = capacity[key]
        value["backupSummary"] = summary
    boundary = result.get("capacityFixture")
    if isinstance(boundary, dict):
        value["capacityFixture"] = {key: boundary[key] for key in
            ("fixtureSha256", "schemaVerified", "migrationCount", "rows", "rowStatus", "objectStatus", "prePauseRejected", "fixtureOnly", "pausePerformed", "intentSha256", "receiptSha256", "independentReadback")
            if key in boundary and (type(boundary[key]) in (int, bool) or isinstance(boundary[key], str))}
    return value


def checkout_sha(directory):
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "--verify", "HEAD"],
                            check=True, capture_output=True, text=True, timeout=15)
    require(re.fullmatch(r"[a-f0-9]{40}", result.stdout.strip()) is not None)
    return result.stdout.strip()


def verified_head(env):
    main = env.get("GITHUB_SHA", "")
    head = env.get("HEAD_VALIDATION_SHA", "")
    number = env.get("HEAD_VALIDATION_PR", "")
    require(env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID)
            and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("SUBS_BOT_CONTROL_ENVIRONMENT") == "subs-bot-isolation"
            and env.get("GITHUB_REF") == artifact.MAIN_REF
            and env.get("GITHUB_WORKFLOW_REF") == artifact.REPOSITORY + "/" + FILE + "@" + artifact.MAIN_REF
            and re.fullmatch(r"[1-9][0-9]{0,8}", number or "") is not None
            and re.fullmatch(r"[a-f0-9]{40}", main or "") is not None
            and re.fullmatch(r"[a-f0-9]{40}", head or "") is not None
            and env.get("HEAD_TRUSTED_MAIN_SHA") == main and env.get("HEAD_TRUSTED_REVIEWED_SHA") == head
            and env.get("GITHUB_RUN_ATTEMPT") == "1",
            "The exact trusted-main and reviewed-head dispatcher identity is required.")
    token = artifact._github_token()
    pull = artifact._get_json("/pulls/" + number, token)
    require(pull.get("state") == "open" and pull.get("number") == int(number)
            and isinstance(pull.get("head"), dict) and isinstance(pull.get("base"), dict)
            and pull["head"].get("sha") == head
            and re.fullmatch(r"codex/[a-z0-9._/-]{1,120}", pull["head"].get("ref", "")) is not None
            and pull["base"].get("ref") == "main"
            and all(isinstance(pull[key].get("repo"), dict)
                    and pull[key]["repo"].get("id") == artifact.REPOSITORY_ID for key in ("head", "base")),
            "The selected PR no longer points to the exact reviewed repository and head.")
    ref = artifact._get_json("/git/ref/heads/main", token)
    current = ref.get("object", {})
    require(ref.get("ref") == artifact.MAIN_REF and current.get("type") == "commit"
            and current.get("sha") == main)
    comparison = artifact._get_json("/compare/" + current["sha"] + "..." + head, token)
    require(comparison.get("status") in {"ahead", "identical"}
            and comparison.get("base_commit", {}).get("sha") == current["sha"]
            and comparison.get("merge_base_commit", {}).get("sha") == current["sha"],
            "The reviewed head is no longer based on current main.")
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink())
    trusted, candidate = workspace / "trusted", workspace / "candidate"
    require(trusted.is_dir() and candidate.is_dir() and not trusted.is_symlink() and not candidate.is_symlink()
            and checkout_sha(trusted) == main and checkout_sha(candidate) == head,
            "The trusted dispatcher or candidate checkout differs from its independent pin.")
    return head, pull["head"]["ref"]


def allowed_initial_state(action, current):
    control = current["control"]
    if action == "watchdog":
        require((control["admission"], control["workers"]) in {("open", "run"), ("closed", "run"), ("closed", "frozen")},
                "The maintenance watchdog cannot inspect an unsupported control state.")
    else:
        require(control["admission"] == "closed" and control["workers"] == "frozen"
                and not any(current["work"].values()),
                "The head harness requires the independently verified closed and frozen rehearsal.")
    require(not any(current["terminal"].get(key, 0) for key in
                    ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")),
            "Unconfirmed external results prevent this maintenance operation.")


def setup(env):
    head, branch = verified_head(env)
    require(re.fullmatch(r"[0-9a-f]{32}", env.get("DRILL_BACKUP_SOURCE_CHECKPOINT_ID", ""))
            and re.fullmatch(r"[0-9a-f]{64}", env.get("DRILL_BACKUP_SOURCE_MANIFEST_SHA256", "")),
            "The registered rehearsal's exact private active-source checkpoint is required.")
    tool = Drill(env, control_revision=head)
    tool.guard = lambda: verified_head(env)
    tool.backup_evidence_workflow = "worker-backup-reviewed-head.yml"
    tool.backup_evidence_branch = "main"
    tool.backup_dispatcher_revision = env["GITHUB_SHA"]
    target, bundle, manifest = tool.prepare_maintenance()
    ctl = tool.bind(target, bundle, manifest)
    require(target.environment == "rehearsal" and target.data["workerName"] == SERVICE)
    current = ctl.inspect()
    allowed_initial_state(env.get("HEAD_VALIDATION_ACTION", ""), current)
    require(current["release"]["revision"] == manifest["revision"]
            and current["release"]["moduleSha256"] == manifest["bundleSha256"])
    return tool, ctl, current


def main(env=None):
    env = dict(os.environ if env is None else env)
    spec = parsed(env.get("HEAD_VALIDATION_JSON", ""))
    require(set(spec) == {"version", "pr", "headSha", "action", "registrationSha256", "sourceCheckpointId",
                          "sourceManifestSha256", "genesisSha256", "approvalSha256", "fault", "checkpointId", "manifestSha256"}
            and type(spec["version"]) is int and spec["version"] == 1
            and all(isinstance(spec[key], str) for key in spec if key != "version"))
    env.update(HEAD_VALIDATION_PR=spec["pr"], HEAD_VALIDATION_SHA=spec["headSha"], HEAD_VALIDATION_ACTION=spec["action"],
               DRILL_REGISTRATION_SHA256=spec["registrationSha256"],
               DRILL_BACKUP_SOURCE_CHECKPOINT_ID=spec["sourceCheckpointId"],
               DRILL_BACKUP_SOURCE_MANIFEST_SHA256=spec["sourceManifestSha256"],
               DRILL_BACKUP_GENESIS_SHA256=spec["genesisSha256"], HEAD_VALIDATION_APPROVAL_SHA256=spec["approvalSha256"],
               DRILL_BACKUP_FAULT=spec["fault"], HEAD_VALIDATION_CHECKPOINT_ID=spec["checkpointId"],
               HEAD_VALIDATION_MANIFEST_SHA256=spec["manifestSha256"],
               DRILL_ACTION="daily-backup-watchdog" if spec["action"] == "watchdog" else "daily-backup")
    action = env.get("HEAD_VALIDATION_ACTION", "")
    require(action in {"inspect", "genesis-plan", "genesis-initialize", "backup", "open-backup", "watchdog", "verify", "capacity-fixture"})
    tool, ctl, state = setup(env)
    store = PrivateStore(ctl.data, ctl.target.data["backupBucketName"])
    if action in {"genesis-plan", "genesis-initialize"}:
        seed = maintenance.Anchor(store, ctl.target.digest, "0" * 64)
        _initial, raw = seed.initial_material()
        pin = sha256(raw).hexdigest()
        result = {"status": "planned", "genesisSha256": pin, "mutationPerformed": False}
        if action == "genesis-initialize":
            require(env.get("DRILL_BACKUP_GENESIS_SHA256") == pin and env.get("HEAD_VALIDATION_APPROVAL_SHA256") == pin,
                    "The exact independently reviewed genesis pin is required.")
            tool.guard()
            require(ctl.inspect()["stateSha256"] == state["stateSha256"])
            maintenance.Anchor(store, ctl.target.digest, pin).initialize()
            result.update(status="initialized", mutationPerformed=True)
    elif action == "inspect":
        result = {"status": "observed", "stateSha256": state["stateSha256"], "mutationPerformed": False}
    elif action == "capacity-fixture":
        # This branch is unreachable through trusted main until its dedicated,
        # default-disabled fixture gate is separately reviewed and installed.
        import time
        import scoped_r2
        import production_backup_capacity_fixture as fixture
        registration = parsed(env.get("CAPACITY_FIXTURE_REGISTRATION_JSON", ""))
        witness = parsed(env.get("CAPACITY_FIXTURE_BINDING_WITNESS_JSON", ""))
        registration_sha = env.get("CAPACITY_FIXTURE_REGISTRATION_SHA256", "")
        witness_sha = env.get("CAPACITY_FIXTURE_BINDING_WITNESS_SHA256", "")
        mode = env.get("CAPACITY_FIXTURE_MODE", "")
        require(mode in {"initialize", "16000", "20000", "20001", "verify-16000", "verify-20000", "verify-20001"} and spec["fault"] == "none"
                and spec["approvalSha256"] == digest({"registrationSha256": registration_sha,
                    "witnessSha256": witness_sha, "mode": mode}), "The exact isolated fixture plan was not approved.")
        def fixture_guard():
            tool.guard()
            fixture.validate_registration(registration, registration_sha, witness, witness_sha, now=int(time.time()),
                                          excluded_database_ids=[ctl.target.data["d1Id"], tool.original["d1Id"]])
            require(registration["bucketCreatedAt"] == tool.original["r2CreatedOn"],
                    "The fixture evidence bucket differs from the registered private project bucket.")
        fixture_guard()
        metadata_api = API(ctl.target, env.get("SUBS_BOT_CF_R2_METADATA_READ_TOKEN", ""))
        privacy(metadata_api, metadata_api.root, registration["bucketName"], registration["bucketCreatedAt"])
        objects = scoped_r2.from_environment(registration["accountId"], registration["bucketName"], env)
        readonly = mode.startswith("verify-")
        require(objects is not None and (readonly or objects.write_credential is not None)
                and (not readonly or objects.write_credential is None and not env.get("CAPACITY_FIXTURE_D1_WRITE_TOKEN")),
                "Independent fixture readback must not receive a write credential.")
        class FixtureStore:
            def get(self, key, *, absent=False):
                return objects.get(key, absent=absent)[0]
            def put_once(self, key, raw):
                return objects.put_once(key, raw)
        api = fixture.FixtureAPI(registration, env.get("CAPACITY_FIXTURE_D1_READ_TOKEN" if readonly else "CAPACITY_FIXTURE_D1_WRITE_TOKEN", ""))
        api.verify_identity()
        source = fixture.FixtureSource(api, ctl.bundle, ctl.manifest)
        if mode == "initialize":
            boundary = fixture.initialize_schema_once(api, FixtureStore(), source, target_sha256=registration_sha,
                                                      run_id=tool.run, guard=fixture_guard)
        elif mode.startswith("verify-"):
            boundary = fixture.verify_seed(api, FixtureStore(), source, target_sha256=registration_sha,
                desired=int(mode.removeprefix("verify-")), controller_revision=tool.revision,
                dispatcher_revision=env["GITHUB_SHA"], guard=fixture_guard)
        else:
            boundary = fixture.seed_once(api, FixtureStore(), source, target_sha256=registration_sha,
                database_id=registration["databaseId"], desired=int(mode), now=int(time.time()), run_id=tool.run, guard=fixture_guard,
                controller_revision=tool.revision, dispatcher_revision=env["GITHUB_SHA"])
        result = {"status": "passed", "capacityFixture": {**boundary, "fixtureSha256": registration_sha},
                  "mutationPerformed": not mode.startswith("verify-")}
    elif action == "verify":
        checkpoint = env.get("HEAD_VALIDATION_CHECKPOINT_ID", "")
        manifest_sha = env.get("HEAD_VALIDATION_MANIFEST_SHA256", "")
        require(re.fullmatch(r"[0-9a-f]{32}", checkpoint or "")
                and re.fullmatch(r"[0-9a-f]{64}", manifest_sha or ""))
        result = verify_activation_baseline(ctl, env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"], checkpoint, manifest_sha)
        require(result.get("baselineVerified") is True and result.get("manifestSha256") == manifest_sha)
    elif action == "open-backup":
        require(env.get("HEAD_TRUSTED_WEBHOOK_CLEANUP") == "configured-v1" and spec["fault"] == "none",
                "Open rehearsal requires the trusted dispatcher cleanup and no injected fault.")
        # Reuse the explicitly pinned current frozen checkpoint for the initial
        # activation check. This avoids even temporary control mutations before
        # the independently recoverable webhook snapshot is written.
        tool.baseline_checkpoint = spec["sourceCheckpointId"]
        tool.baseline_manifest_sha = spec["sourceManifestSha256"]
        def authorization_state(controller):
            return {"policy": rows(controller.data, controller.database, "SELECT * FROM telegram_general_policy ORDER BY bot_id"),
                    "actors": rows(controller.data, controller.database, "SELECT * FROM telegram_general_actors ORDER BY actor_id"),
                    "groups": rows(controller.data, controller.database, "SELECT * FROM telegram_general_groups ORDER BY chat_id")}
        def run_backup(controller, _reply_anchors, _fixture_base):
            before_auth = authorization_state(controller)
            initial_checkpoint, initial_manifest = tool.baseline_checkpoint, tool.baseline_manifest_sha
            tool.baseline_checkpoint, tool.baseline_manifest_sha = "", ""
            try:
                tool.daily_backup()
            finally:
                tool.baseline_checkpoint, tool.baseline_manifest_sha = initial_checkpoint, initial_manifest
            after = tool.controller.inspect()
            require(after["control"]["admission"] == "open" and after["control"]["workers"] == "run"
                    and not any(after["terminal"].get(key, 0) for key in
                                ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates"))
                    and authorization_state(tool.controller) == before_auth,
                    "The backup did not restore admission or preserve the exact authorization state.")
            observed = tool.report.get("backupMaintenance")
            require(isinstance(observed, dict) and isinstance(observed.get("baseline"), dict)
                    and observed.get("pauseSeconds", 0) > 0)
            tool.report["dailyBackupAcceptance"] = {"baseline": observed["baseline"],
                "pauseSeconds": observed["pauseSeconds"], "pauseLimitExceeded": observed["pauseLimitExceeded"],
                "admissionRestored": True, "authorizationUnchanged": True}
            tool.report["openWindowStartingBaseline"] = {"checkpointId": initial_checkpoint, "manifestSha256": initial_manifest}
        tool.exercise(provided_controller=ctl, verify_extra=run_backup, external_webhook_cleanup=True)
        result = tool.report
        result["status"] = "awaiting-trusted-webhook-restoration"
    else:
        # Each invocation re-resolves PR head and active source. The same
        # implementation and private transaction engine are used by rehearsal.
        if action == "backup":
            tool.daily_backup()
        else:
            tool.daily_backup_watchdog()
        result = tool.report
    tool.guard()
    result.update(headRevision=env["HEAD_VALIDATION_SHA"], dispatcherMainRevision=env["GITHUB_SHA"], targetSha256=ctl.target.digest,
                  environment="rehearsal", productionMutated=False, webhookTouched=action == "open-backup",
                  runId=env["GITHUB_RUN_ID"], runAttempt=env["GITHUB_RUN_ATTEMPT"])
    if action == "open-backup":
        ready = [item for item in tool.report["stages"] if item.get("stage") == "open-backup-ready-for-cleanup"]
        accepted = tool.report["dailyBackupAcceptance"]
        require(len(ready) == 1 and accepted["admissionRestored"] is True and accepted["authorizationUnchanged"] is True)
        receipt = {"version": 1, "status": "candidate-complete-before-trusted-cleanup", "runId": tool.run,
                   "runAttempt": tool.attempt, "controllerRevision": tool.revision,
                   "dispatcherRevision": env["GITHUB_SHA"], "targetSha256": ctl.target.digest,
                   "readySha256": ready[0]["sha256"], "snapshotSha256": tool.report["webhookSnapshotSha256"],
                   "checkpointId": accepted["baseline"]["checkpointId"],
                   "manifestSha256": accepted["baseline"]["manifestSha256"],
                   "pauseSeconds": accepted["pauseSeconds"], "pauseLimitExceeded": accepted["pauseLimitExceeded"],
                   "admissionRestored": True, "authorizationUnchanged": True, "confirmedReceiptsNotRepeated": True}
        key = tool.prefix + tool.run + "-" + tool.attempt + "-backup-head-acceptance.json"
        body = canonical(receipt)
        tool.store.put(key, body)
        require(tool.store.get(key) == body, "The private head acceptance evidence was not read back.")
    result = public_result(result)
    output = Path(env["RUNNER_TEMP"]) / "production-backup-head-result.json"
    with output.open("xb") as stream:
        stream.write(canonical(result))
    output.chmod(0o600)
    print(json.dumps(result, sort_keys=True))
    return result


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main()
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "Head validation was not confirmed; preserve its private intent and inspect before retry."}))
        raise SystemExit(1) from None

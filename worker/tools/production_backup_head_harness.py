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
from production_control import rows
from production_release_evidence import verify_activation_baseline
from production_storage import PrivateStore
from production_target import canonical, parsed, require


FILE = ".github/workflows/worker-backup-reviewed-head.yml"


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
    require(current["control"]["admission"] == "closed" and current["control"]["workers"] == "frozen"
            and not any(current["work"].values())
            and not any(current["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates")),
            "The head harness only operates on the independently verified closed and frozen rehearsal.")
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
    require(action in {"inspect", "genesis-plan", "genesis-initialize", "backup", "open-backup", "watchdog", "verify"})
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
                                ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates"))
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

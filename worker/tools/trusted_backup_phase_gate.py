"""Trusted-main gate for a reviewed, fixed-target rehearsal backup phase.

This gate is run from the trusted main checkout before candidate credentials
are made available. It never accepts a production environment or target.
"""
from pathlib import Path
import re
import subprocess

import prepare_isolation_artifact as github
from production_target import parsed, require

FILE = ".github/workflows/worker-backup-phase-rehearsal.yml"
PARENT_FILE = ".github/workflows/worker-backup-reviewed-coordinator.yml"
RECOVERY_FILE = ".github/workflows/worker-backup-phase-recovery.yml"
ENVIRONMENT = "subs-bot-backup-head-isolation"
HEX32 = re.compile(r"[a-f0-9]{32}")
HEX40 = re.compile(r"[a-f0-9]{40}")
HEX64 = re.compile(r"[a-f0-9]{64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
STEPS = ("plan-begin", "begin", "preflight", "plan-pause", "pause", "drain", "freeze", "capture", "verify", "plan-activate", "activate")
RECOVERY_ACTIONS = {"plan-resume-failed", "resume-failed", "plan-reconcile-transition", "reconcile-transition",
                    "plan-abort-unstarted", "abort-unstarted"}
KEYS = {"version", "pr", "headSha", "registrationSha256", "sourceCheckpointId", "sourceManifestSha256", "genesisSha256", "checkpointId"}


def checkout_sha(directory):
    require(directory.is_dir() and not directory.is_symlink())
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "--verify", "HEAD"],
                            capture_output=True, check=True, text=True, timeout=15)
    require(HEX40.fullmatch(result.stdout.strip()) is not None)
    return result.stdout.strip()


def validate(env):
    main = env.get("GITHUB_SHA", "")
    role = env.get("BACKUP_GATE_ROLE", "")
    require(role in {"child", "parent", "recovery", "recovery-readback"})
    workflow = {"child": FILE, "parent": PARENT_FILE, "recovery": RECOVERY_FILE, "recovery-readback": RECOVERY_FILE}[role]
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/" + workflow + "@" + github.MAIN_REF
            and env.get("GITHUB_WORKFLOW_SHA") == main
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("BACKUP_HEAD_ENVIRONMENT") == ENVIRONMENT and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("SUBS_BOT_BACKUP_PHASE_REHEARSAL_ENABLED") == "true"
            and HEX40.fullmatch(main or ""), "The trusted rehearsal phase gate is disabled or its identity differs.")
    raw = env.get("HEAD_VALIDATION_JSON", "")
    spec = parsed(raw)
    require(isinstance(spec, dict) and set(spec) == KEYS and type(spec["version"]) is int and spec["version"] == 1
            and spec.get("pr") == "302" and HEX40.fullmatch(spec.get("headSha", ""))
            and env.get("BACKUP_REVIEWED_HEAD_SHA") == spec["headSha"]
            and all(HEX64.fullmatch(spec.get(k, "")) for k in ("registrationSha256", "sourceManifestSha256", "genesisSha256"))
            and all(HEX32.fullmatch(spec.get(k, "")) for k in ("sourceCheckpointId", "checkpointId"))
            and spec["checkpointId"] != spec["sourceCheckpointId"]
            and all(spec[k] == env.get(name) for k, name in (
                ("registrationSha256", "BACKUP_PHASE_REGISTRATION_SHA256"),
                ("sourceCheckpointId", "BACKUP_PHASE_SOURCE_CHECKPOINT_ID"),
                ("sourceManifestSha256", "BACKUP_PHASE_SOURCE_MANIFEST_SHA256"),
                ("genesisSha256", "BACKUP_PHASE_GENESIS_SHA256"),
                ("checkpointId", "BACKUP_PHASE_CHECKPOINT_ID")))
            and env.get("BACKUP_SOURCE_CHECKPOINT_ID") == spec["sourceCheckpointId"]
            and env.get("BACKUP_SOURCE_MANIFEST_SHA256") == spec["sourceManifestSha256"]
            and env.get("BACKUP_ACTION") in (STEPS if role == "child" else RECOVERY_ACTIONS if role in {"recovery", "recovery-readback"} else {"inspect", "plan-initialize", "initialize", "plan-webhook-history", "plan-webhook-anchor", "initialize-webhook-anchor", "plan-run", "run", "plan-resume", "resume", "plan-reconcile", "reconcile", "plan-abort", "abort"}))
    if role == "child":
        require(HEX64.fullmatch(env.get("BACKUP_DISPATCH_NONCE", "")))
        require(DECIMAL.fullmatch(env.get("BACKUP_COORDINATOR_SESSION", ""))
                and re.fullmatch(r"0|[1-9][0-9]{0,19}", env.get("BACKUP_DISPATCH_DEADLINE", "")))
        # Even a read-only phase must create its exclusive private child claim.
        require(env.get("SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED") == "true",
                "Isolated phase claims and writes are disabled.")
    elif role in {"recovery", "recovery-readback"}:
        require(env.get("SUBS_BOT_BACKUP_PHASE_RECOVERY_ENABLED") == "true"
                and DECIMAL.fullmatch(env.get("BACKUP_COORDINATOR_SESSION", ""))
                and re.fullmatch(r"[1-9][0-9]{0,19}-1", env.get("BACKUP_SESSION", ""))
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", env.get("BACKUP_SESSION_DAY", ""))
                and (not env.get("BACKUP_ANCHOR_CANDIDATE_SHA256") or
                     env["BACKUP_ACTION"] in {"plan-abort-unstarted", "abort-unstarted"}
                     and HEX64.fullmatch(env["BACKUP_ANCHOR_CANDIDATE_SHA256"])))
        if not env["BACKUP_ACTION"].startswith("plan-"):
            require((role == "recovery-readback" or env.get("SUBS_BOT_BACKUP_PHASE_RECOVERY_WRITES_ENABLED") == "true")
                    and HEX64.fullmatch(env.get("BACKUP_RECOVERY_PLAN_SHA256", ""))
                    and env.get("SUBS_BOT_BACKUP_PHASE_RECOVERY_APPROVAL_SHA256") == env["BACKUP_RECOVERY_PLAN_SHA256"],
                    "The exact independently approved isolated recovery plan is required.")
        if role == "recovery-readback":
            require(not env["BACKUP_ACTION"].startswith("plan-") and env.get("BACKUP_RECOVERY_MODE") == "readback"
                    and DECIMAL.fullmatch(env.get("GITHUB_RUN_ID", ""))
                    and env.get("BACKUP_RECOVERY_SOURCE_RUN_ID") == env["GITHUB_RUN_ID"]
                    and re.fullmatch(r"[1-9][0-9]{0,19}-1-[0-9]{4}", env.get("BACKUP_RECOVERY_SLOT", ""))
                    and env["BACKUP_RECOVERY_SLOT"].startswith(env["BACKUP_SESSION"] + "-")
                    and all(HEX64.fullmatch(env.get(key, "")) for key in
                            ("BACKUP_RECOVERY_CLAIM_SHA256", "BACKUP_RECOVERY_COMPLETION_SHA256")))
    elif env.get("BACKUP_ACTION") in {"initialize", "initialize-webhook-anchor", "run", "resume", "reconcile", "abort"}:
        require(env.get("SUBS_BOT_BACKUP_PHASE_REHEARSAL_WRITES_ENABLED") == "true",
                "Isolated coordinator writes are disabled.")
    from production_target import canonical
    require(canonical(spec).decode("utf-8") == raw, "The phase validation document must be canonical.")
    token = env.get("GH_TOKEN", "")
    require(re.fullmatch(r"[!-~]{1,4096}", token or ""))
    ref = github._get_json("/git/ref/heads/main", token)
    require(ref.get("ref") == github.MAIN_REF and ref.get("object", {}).get("type") == "commit"
            and ref["object"].get("sha") == main)
    pull = github._get_json("/pulls/" + spec["pr"], token)
    require(pull.get("number") == int(spec["pr"]) and pull.get("state") == "open"
            and isinstance(pull.get("head"), dict) and isinstance(pull.get("base"), dict)
            and pull["head"].get("sha") == spec["headSha"] and pull["base"].get("ref") == "main"
            and pull["head"].get("ref") == "codex/backup-coordinator"
            and all(isinstance(pull[k].get("repo"), dict) and pull[k]["repo"].get("id") == github.REPOSITORY_ID
                    for k in ("head", "base")))
    comparison = github.compare_commits_metadata(main, spec["headSha"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == main
            and comparison.get("merge_base_commit", {}).get("sha") == main)
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink())
    require(checkout_sha(workspace / "trusted") == main)
    phase = env.get("BACKUP_CHECKOUT_PHASE", "")
    require(phase in {"before", "ready", "credential-check"})
    if phase != "before":
        require(checkout_sha(workspace / "candidate") == spec["headSha"])
    if phase == "credential-check":
        test = parsed(env.get("SUBS_BOT_TELEGRAM_TEST_CONFIG", ""))
        require(set(test) == {"botId", "botUsername", "botToken", "webhookSecret", "adminId", "memberId", "groupId"}
                and test["botId"] == "9293938370" and test["botUsername"] == "test_cfsubs_bot"
                and test["adminId"] == "8813701954" and test["memberId"] == "8653767757" and test["groupId"] == "-5114255828"
                and re.fullmatch(r"9293938370:[A-Za-z0-9_-]{20,128}", test["botToken"] or "")
                and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", test["webhookSecret"] or ""))
    return {"status": "validated", "dispatcherMainSha": main, "reviewedHeadSha": spec["headSha"]}


if __name__ == "__main__":
    import json
    import os
    try:
        print(json.dumps(validate(os.environ), sort_keys=True))
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "The trusted rehearsal phase identity or source pins were not confirmed."}))
        raise SystemExit(1) from None

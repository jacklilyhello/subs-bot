"""Trusted-main gate for a reviewed, dedicated-isolation backup head run.

The final check validates the explicitly authorized test Bot identity without
printing its credential. The gate never reads Cloudflare credentials.
"""
from pathlib import Path
from hashlib import sha256
import json
import os
import re
import subprocess
import time

import prepare_isolation_artifact as github
from production_target import ACCOUNT, canonical, digest, parsed, require


WORKFLOW = github.REPOSITORY + "/.github/workflows/worker-backup-reviewed-head.yml@" + github.MAIN_REF
ENVIRONMENT = "subs-bot-backup-head-isolation"
HEX32 = re.compile(r"[0-9a-f]{32}")
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
KEYS = {"version", "pr", "headSha", "action", "registrationSha256", "sourceCheckpointId",
        "sourceManifestSha256", "genesisSha256", "approvalSha256", "fault", "checkpointId", "manifestSha256"}


def _sha(directory):
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "--verify", "HEAD"],
                            check=True, capture_output=True, text=True, timeout=15)
    require(HEX40.fullmatch(result.stdout.strip()) is not None)
    return result.stdout.strip()


def validate(env):
    main = env.get("GITHUB_SHA", "")
    token = env.get("GH_TOKEN", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("BACKUP_HEAD_ENVIRONMENT") == ENVIRONMENT and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and HEX40.fullmatch(main or "") is not None and re.fullmatch(r"[!-~]{1,4096}", token or "") is not None,
            "The trusted main dispatcher identity is invalid.")
    spec = parsed(env.get("HEAD_VALIDATION_JSON", ""))
    require(set(spec) == KEYS and type(spec["version"]) is int and spec["version"] == 1
            and all(isinstance(spec[key], str) for key in KEYS - {"version"}))
    require(re.fullmatch(r"[1-9][0-9]{0,8}", spec["pr"]) is not None
            and HEX40.fullmatch(spec["headSha"]) is not None
            and env.get("BACKUP_REVIEWED_HEAD_SHA") == spec["headSha"]
            and spec["action"] in {"inspect", "genesis-plan", "genesis-initialize", "backup", "watchdog", "verify", "open-backup", "capacity-fixture"}
            and HEX64.fullmatch(spec["registrationSha256"]) is not None
            and HEX32.fullmatch(spec["sourceCheckpointId"]) is not None
            and HEX64.fullmatch(spec["sourceManifestSha256"]) is not None
            and all(not spec[key] or HEX64.fullmatch(spec[key]) for key in ("genesisSha256", "approvalSha256", "manifestSha256"))
            and (not spec["checkpointId"] or HEX32.fullmatch(spec["checkpointId"]))
            and spec["fault"] in {"none", "capacity-near", "capacity-over", "readback-failure", "process-kill"}
            and (spec["action"] == "backup" or spec["fault"] == "none"),
            "The reviewed head, exact source pins or bounded action is invalid.")
    if spec["action"] in {"genesis-initialize", "backup", "watchdog", "open-backup"}:
        require(HEX64.fullmatch(spec["genesisSha256"]) is not None)
    if spec["action"] == "genesis-initialize":
        require(spec["approvalSha256"] == spec["genesisSha256"])
    if spec["action"] == "verify":
        require(HEX32.fullmatch(spec["checkpointId"]) is not None and HEX64.fullmatch(spec["manifestSha256"]) is not None)
    if spec["action"] == "capacity-fixture":
        require(env.get("BACKUP_CAPACITY_ENABLED") == "true" and HEX64.fullmatch(spec["approvalSha256"] or ""),
                "The dedicated capacity gate is disabled or lacks its exact plan pin.")
    ref = github._get_json("/git/ref/heads/main", token)
    require(ref.get("ref") == github.MAIN_REF and ref.get("object", {}).get("type") == "commit"
            and ref["object"].get("sha") == main, "The trusted dispatcher is no longer current main.")
    pull = github._get_json("/pulls/" + spec["pr"], token)
    require(pull.get("number") == int(spec["pr"]) and pull.get("state") == "open"
            and isinstance(pull.get("head"), dict) and isinstance(pull.get("base"), dict)
            and pull["head"].get("sha") == spec["headSha"]
            and re.fullmatch(r"codex/[a-z0-9._/-]{1,120}", pull["head"].get("ref", "")) is not None
            and pull["base"].get("ref") == "main"
            and all(isinstance(pull[key].get("repo"), dict)
                    and pull[key]["repo"].get("id") == github.REPOSITORY_ID for key in ("head", "base")),
            "The pull request no longer identifies the reviewed same-repository head.")
    comparison = github._get_json("/compare/" + main + "..." + spec["headSha"], token)
    require(comparison.get("status") in {"ahead", "identical"}
            and comparison.get("base_commit", {}).get("sha") == main
            and comparison.get("merge_base_commit", {}).get("sha") == main,
            "The reviewed head is no longer based on the exact current main.")
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink())
    trusted, candidate = workspace / "trusted", workspace / "candidate"
    require(trusted.is_dir() and not trusted.is_symlink() and _sha(trusted) == main,
            "The trusted gate checkout differs from current main.")
    phase = env.get("BACKUP_CHECKOUT_PHASE", "")
    require(phase in {"before", "ready", "credential-check", "fixture-credential-check"})
    if phase in {"ready", "credential-check", "fixture-credential-check"}:
        require(candidate.is_dir() and not candidate.is_symlink() and _sha(candidate) == spec["headSha"],
                "The candidate checkout differs from the exact independently reviewed head.")
    if phase == "credential-check":
        test = parsed(env.get("SUBS_BOT_TELEGRAM_TEST_CONFIG", ""))
        require(set(test) == {"botId", "botUsername", "botToken", "webhookSecret", "adminId", "memberId", "groupId"}
                and test["botId"] == "9293938370" and test["botUsername"] == "test_cfsubs_bot"
                and test["adminId"] == "8813701954" and test["memberId"] == "8653767757" and test["groupId"] == "-5114255828"
                and re.fullmatch(r"9293938370:[A-Za-z0-9_-]{20,128}", test["botToken"]) is not None
                and re.fullmatch(r"[A-Za-z0-9_-]{32,256}", test["webhookSecret"]) is not None,
                "The isolated Telegram configuration does not match the authorized test identity.")
    if phase == "fixture-credential-check":
        require(spec["action"] == "capacity-fixture")
        fixture = parsed(env.get("CAPACITY_FIXTURE_REGISTRATION_JSON", ""))
        witness = parsed(env.get("CAPACITY_FIXTURE_BINDING_WITNESS_JSON", ""))
        original = parsed(env.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""))
        fixture_sha = env.get("CAPACITY_FIXTURE_REGISTRATION_SHA256", "")
        witness_sha = env.get("CAPACITY_FIXTURE_BINDING_WITNESS_SHA256", "")
        mode = env.get("CAPACITY_FIXTURE_MODE", "")
        database = fixture.get("databaseId", "")
        excluded = env.get("CAPACITY_FIXTURE_REHEARSAL_D1_ID", "")
        uuid = r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}"
        require(set(fixture) == {"version", "accountId", "databaseId", "databaseName", "createdAt", "bucketName", "bucketCreatedAt"}
                and type(fixture["version"]) is int and fixture["version"] == 1 and fixture["accountId"] == ACCOUNT
                and fixture["databaseName"] == "subs-bot-cf-backup-capacity-20261118" and fixture["bucketName"] == "subs-bot-cf-dev-01"
                and re.fullmatch(uuid, database) and re.fullmatch(uuid, excluded)
                and isinstance(original, dict) and original.get("accountId") == ACCOUNT
                and re.fullmatch(uuid, original.get("d1Id", "")) and database not in {excluded, original["d1Id"]}
                and fixture["bucketCreatedAt"] == original.get("r2CreatedOn")
                and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", fixture["createdAt"] or "")
                and HEX64.fullmatch(fixture_sha or "") and sha256(canonical(fixture)).hexdigest() == fixture_sha)
        require(set(witness) == {"version", "accountId", "databaseId", "observedAt", "workerBindingCount"}
                and type(witness["version"]) is int and witness["version"] == 1 and witness["accountId"] == ACCOUNT
                and witness["databaseId"] == database and type(witness["observedAt"]) is int
                and 0 <= int(time.time()) - witness["observedAt"] <= 900
                and type(witness["workerBindingCount"]) is int and witness["workerBindingCount"] == 0
                and HEX64.fullmatch(witness_sha or "") and sha256(canonical(witness)).hexdigest() == witness_sha
                and mode in {"initialize", "16000", "20000", "20001", "verify-16000", "verify-20000", "verify-20001"}
                and spec["approvalSha256"] == digest({"registrationSha256": fixture_sha, "witnessSha256": witness_sha, "mode": mode}),
                "The independently pinned fixture, no-binding witness or exact mode differs.")
    return {"status": "validated", "environment": ENVIRONMENT, "dispatcherMainSha": main,
            "reviewedHeadSha": spec["headSha"], "pr": spec["pr"], "checkoutVerified": phase != "before"}


if __name__ == "__main__":
    try:
        print(json.dumps(validate(os.environ), sort_keys=True))
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "Trusted head identity or source pins were not confirmed."}))
        raise SystemExit(1) from None

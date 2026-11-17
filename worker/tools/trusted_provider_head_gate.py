"""Trusted-main authorization gate for a reviewed isolated Provider head.

The gate never runs candidate code or contacts Cloudflare. Each job must run it
from the trusted checkout before and after candidate execution, with credentials
injected only after the ready check. No production identity is accepted.
"""

import json
import os
from pathlib import Path
import re
import subprocess

import prepare_isolation_artifact as github
import production_provider as provider
from production_target import parsed, require

WORKFLOW_PATH = ".github/workflows/worker-provider-reviewed-head.yml"
WORKFLOW = f"{github.REPOSITORY}/{WORKFLOW_PATH}@{github.MAIN_REF}"
ENVIRONMENTS = {"subs-bot-provider-head-isolation", "subs-bot-provider-archive-head-isolation"}
HEX40 = re.compile(r"[0-9a-f]{40}")
HEX64 = re.compile(r"[0-9a-f]{64}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
FIELDS = {"version", "pr", "headSha", "providerCiRunId", "approvalSha256", "archiveRefs", "simulateActionsUnavailable"}
PHASES = {"sources", "attest-r2", "attest-provider"}
PROVIDER_PHASES = {"attest-provider"}


def checkout_sha(directory):
    result = subprocess.run(["git", "-C", str(directory), "rev-parse", "--verify", "HEAD"],
                            check=True, capture_output=True, text=True, timeout=15)
    value = result.stdout.strip()
    require(HEX40.fullmatch(value) is not None)
    return value


def validate(env):
    main, token = env.get("GITHUB_SHA", ""), env.get("GH_TOKEN", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("GITHUB_WORKFLOW_SHA") == main
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and HEX40.fullmatch(main or "") is not None and re.fullmatch(r"[!-~]{1,4096}", token or "") is not None)
    spec = parsed(env.get("PROVIDER_HEAD_VALIDATION_JSON", ""))
    require(set(spec) == FIELDS and type(spec["version"]) is int and spec["version"] == 1
            and isinstance(spec["pr"], str) and re.fullmatch(r"[1-9][0-9]{0,8}", spec["pr"]) is not None
            and isinstance(spec["headSha"], str) and HEX40.fullmatch(spec["headSha"]) is not None
            and env.get("PROVIDER_REVIEWED_HEAD_SHA") == spec["headSha"]
            and isinstance(spec["providerCiRunId"], str) and DECIMAL.fullmatch(spec["providerCiRunId"]) is not None
            and isinstance(spec["approvalSha256"], str) and HEX64.fullmatch(spec["approvalSha256"]) is not None
            and spec["simulateActionsUnavailable"] is True and isinstance(spec["archiveRefs"], list)
            and 0 < len(spec["archiveRefs"]) <= 9)
    for ref in spec["archiveRefs"]:
        require(isinstance(ref, dict) and set(ref) == {"kind", "runId", "runAttempt", "manifestSha256", "targetSha256"}
                and ref["kind"] in {"complete", "partial", "isolated-source"}
                and all(isinstance(ref[key], str) and DECIMAL.fullmatch(ref[key]) is not None for key in ("runId", "runAttempt"))
                and all(isinstance(ref[key], str) and HEX64.fullmatch(ref[key]) is not None for key in ("manifestSha256", "targetSha256"))
                and (ref["kind"] != "isolated-source" or ref["runAttempt"] == "1"))
    phase, environment = env.get("PROVIDER_HEAD_PHASE", ""), env.get("PROVIDER_HEAD_ENVIRONMENT", "")
    require(phase in PHASES and environment in ENVIRONMENTS
            and environment == ("subs-bot-provider-head-isolation" if phase in PROVIDER_PHASES else "subs-bot-provider-archive-head-isolation"))
    ref = github._get_json("/git/ref/heads/main", token)
    require(ref.get("ref") == github.MAIN_REF and ref.get("object", {}).get("type") == "commit" and ref["object"].get("sha") == main)
    pull = github._get_json("/pulls/" + spec["pr"], token)
    require(pull.get("number") == int(spec["pr"]) and pull.get("state") == "open"
            and isinstance(pull.get("head"), dict) and isinstance(pull.get("base"), dict)
            and pull["head"].get("sha") == spec["headSha"]
            and re.fullmatch(r"codex/[a-z0-9._/-]{1,120}", pull["head"].get("ref", "")) is not None
            and pull["base"].get("ref") == "main"
            and all(isinstance(pull[key].get("repo"), dict) and pull[key]["repo"].get("id") == github.REPOSITORY_ID
                    for key in ("head", "base")))
    comparison = github._get_json("/compare/" + main + "..." + spec["headSha"], token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("base_commit", {}).get("sha") == main
            and comparison.get("merge_base_commit", {}).get("sha") == main)
    workspace = Path(env.get("GITHUB_WORKSPACE", ""))
    require(workspace.is_absolute() and workspace.is_dir() and not workspace.is_symlink())
    trusted, candidate = workspace / "trusted", workspace / "candidate"
    require(trusted.is_dir() and not trusted.is_symlink() and checkout_sha(trusted) == main)
    check = env.get("PROVIDER_HEAD_CHECK", "")
    require(check in {"before", "ready", "credential", "after"})
    if check != "before":
        require(candidate.is_dir() and not candidate.is_symlink() and checkout_sha(candidate) == spec["headSha"])
    if check == "credential":
        # These are resource contracts, not credentials. The gate intentionally
        # never receives or prints any Cloudflare or age secret.
        target = provider.read_config(env.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
        pinned_refs = json.loads(env.get("SUBS_BOT_PROVIDER_REVIEWED_ARCHIVE_REFS_JSON", ""),
                                 object_pairs_hook=github._unique_json_object)
        require(pinned_refs == spec["archiveRefs"])
        require(target["environment"] == "rehearsal" and target["caller"] is None
                and target["service"] == "subs-bot-provider-fetch-control-drill-01"
                and target["build"]["runId"] == spec["providerCiRunId"]
                and spec["approvalSha256"] == provider.digest({"operation": "publish", "target": target}))
        bucket = parsed(env.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""))
        require(bucket.get("accountId") == "9431815bdb8beb2272f6668e06b7d3be" and bucket.get("namespace") == "lilyya"
                and isinstance(bucket.get("r2CreatedOn"), str)
                and provider.match(provider.bootstrap.TIMESTAMP, bucket["r2CreatedOn"]))
    return {"status": "validated", "phase": phase, "environment": environment, "trustedMainSha": main,
            "reviewedHeadSha": spec["headSha"], "pr": spec["pr"], "checkoutVerified": check != "before"}


if __name__ == "__main__":
    try:
        print(json.dumps(validate(os.environ), sort_keys=True))
    except Exception:
        print(json.dumps({"status": "stopped", "reason": "Trusted Provider head, environment or source pins were not confirmed."}))
        raise SystemExit(1) from None

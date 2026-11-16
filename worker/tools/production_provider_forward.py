"""Read-only failed-terminal reconciliation on the provider credential environment."""

import json
import os
from pathlib import Path

import production_provider as control
from production_provider_terminal import verify_forced_terminal


def artifact_receipt(artifact_id, archive_sha256, prefix):
    control.require(control.match(control.provider.DECIMAL, artifact_id)
                    and control.match(control.provider.HEX, archive_sha256)
                    and prefix in {"subs-bot-provider-terminal-request", "subs-bot-provider-forward-terminal"})
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, control.github._github_token())
    run = artifact.get("workflow_run")
    control.require(artifact.get("name") == prefix + "-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
                    and artifact.get("expired") is False and artifact.get("digest") == "sha256:" + archive_sha256
                    and isinstance(run, dict) and str(run.get("id")) == os.environ["GITHUB_RUN_ID"]
                    and run.get("repository_id") == control.github.REPOSITORY_ID
                    and run.get("head_branch") == "main" and run.get("head_sha") == os.environ["GITHUB_SHA"],
                    "The failed-terminal evidence artifact is not from this exact protected run.")


def main():
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == os.environ.get("GITHUB_SHA")
                    and os.environ.get("GITHUB_WORKFLOW_REF")
                    == f"{control.github.REPOSITORY}/{control.REHEARSAL_WORKFLOW_PATH}@{control.github.MAIN_REF}")
    artifact_receipt(os.environ.get("PROVIDER_TERMINAL_ARTIFACT_ID", ""),
                     os.environ.get("PROVIDER_TERMINAL_ARTIFACT_SHA256", ""), "subs-bot-provider-terminal-request")
    root = Path(os.environ["RUNNER_TEMP"])
    directory = root / "provider-terminal-request-input"
    target = control.read_config(control.provider.checked_file(directory / "provider-reconciled-target.json", 65536).read_text("ascii"))
    request = control.github._parse_object(control.provider.checked_file(directory / "provider-terminal-request.json", 4096).read_bytes(), control.ERROR)
    control.fields(request, {"version", "controllerRevision", "runId", "runAttempt", "sourceRunId", "sourceRunAttempt",
                             "sourceManifestSha256", "responseIdentitySha256", "previousTargetSha256"})
    control.require(request["version"] == 1 and request["controllerRevision"] == os.environ["GITHUB_SHA"]
                    and request["runId"] == os.environ["GITHUB_RUN_ID"] and request["runAttempt"] == os.environ["GITHUB_RUN_ATTEMPT"]
                    and request["previousTargetSha256"] == control.digest(target) and target["environment"] == "rehearsal"
                    and target["caller"] is None)
    recovery = {key: request[key] for key in ("version", "sourceRunId", "sourceRunAttempt", "sourceManifestSha256",
                                             "responseIdentitySha256", "previousTargetSha256")}
    control.validate_forward_recovery({**recovery, "terminalSha256": "0" * 64})
    control.guard_sources(target)
    api = control.ProviderAPI(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                              os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))
    observations = []
    terminal = verify_forced_terminal(api, target, evidence_sink=observations.append)
    control.require(len(observations) == 1)
    control.guard_sources(target)
    recovery["terminalSha256"] = control.digest(terminal)
    recovery = control.validate_forward_recovery(recovery)
    output = root / "provider-forward-terminal-output"
    output.mkdir(mode=0o700)
    for name, value in (("provider-reconciled-target.json", target), ("provider-forward-terminal.json", recovery),
                        ("provider-failed-terminal-state.json", terminal),
                        ("provider-failed-terminal-readback.json", observations[0])):
        with control.provenance._write_private(output / name) as destination:
            destination.write(control.canonical(value))
    print(json.dumps({"status": "failed-terminal-preserved", "completion": "not-complete", "targetSha256": control.digest(target),
                      "recoverySha256": control.digest(recovery), "terminalSha256": recovery["terminalSha256"]}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("The failed provider terminal could not be independently confirmed; no mutation was performed.") from None

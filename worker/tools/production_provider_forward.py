"""Read-only failed-terminal reconciliation on the provider credential environment."""

import json
import os
from pathlib import Path

import production_provider as control
from production_provider_terminal import GETOnlyProviderAPI, verify_forced_terminal

PHASES = {"context", "artifact", "source", "candidate_inventory", "candidate_resources", "old_resource_pins",
          "terminal_before", "terminal_digest", "terminal_after", "snapshot_unchanged", "output"}
READS = {"none", "versions", "candidate_module", "previous_module", "old_active", "namespace", "worker_identity",
         "container_profile", "container_instance", "workflow_metadata", "workflow_instance", "other"}
CONTEXT = {"phase": "context", "lastRead": "none"}


def phase(value):
    control.require(value in PHASES)
    CONTEXT["phase"] = value


class DiagnosticReader(GETOnlyProviderAPI):
    def _request(self, path, **kwargs):
        if "/deployments" in path:
            label = "old_active"
        elif path.startswith("/workers/durable_objects/"):
            label = "namespace"
        elif "/versions/" in path and path.startswith("/workers/"):
            label = "candidate_module" if self.config["versionId"] in path else "previous_module"
        elif path.startswith("/workers/") and "/versions?" in path:
            label = "versions"
        elif path.startswith("/workers/"):
            label = "worker_identity"
        elif path.startswith("/containers/"):
            label = "container_instance" if "/instances" in path else "container_profile"
        elif path.startswith("/workflows/"):
            label = "workflow_instance" if "/instances" in path else "workflow_metadata"
        else:
            label = "other"
        CONTEXT["lastRead"] = label
        return super()._request(path, **kwargs)


def safe_diagnostic(error):
    classes = ((control.ProviderError, "provider_guard"), (control.stage.StageError, "version_guard"),
               (control.legacy.ActivationError, "resource_guard"), (control.github.ArtifactError, "source_guard"),
               (AttributeError, "attribute_error"), (KeyError, "field_error"), (TypeError, "type_error"), (ValueError, "format_guard"))
    kind = next((label for expected, label in classes if isinstance(error, expected)), "unexpected")
    result = {"phase": CONTEXT["phase"] if CONTEXT.get("phase") in PHASES else "context",
              "lastRead": CONTEXT["lastRead"] if CONTEXT.get("lastRead") in READS else "none", "reason": kind}
    diagnostic = getattr(error, "read_diagnostic", None) if isinstance(error, control.ProviderError) else None
    if isinstance(diagnostic, dict):
        status, codes = diagnostic.get("httpStatus"), diagnostic.get("cloudflareCodes")
        result["httpStatus"] = status if type(status) is int and 100 <= status <= 599 else None
        result["cloudflareCodes"] = sorted({value for value in codes[:8] if type(value) is int and 1000 <= value <= 999999}) \
            if isinstance(codes, list) else []
    return result


def artifact_receipt(artifact_id, archive_sha256, prefix):
    control.require(control.match(control.provider.DECIMAL, artifact_id)
                    and control.match(control.provider.HEX, archive_sha256)
                    and prefix in {"subs-bot-provider-terminal-request", "subs-bot-provider-forward-terminal", "subs-bot-provider-forward-stage"})
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, control.github._github_token())
    run = artifact.get("workflow_run")
    control.require(artifact.get("name") == prefix + "-" + os.environ["GITHUB_RUN_ID"] + "-" + os.environ["GITHUB_RUN_ATTEMPT"]
                    and artifact.get("expired") is False and artifact.get("digest") == "sha256:" + archive_sha256
                    and isinstance(run, dict) and str(run.get("id")) == os.environ["GITHUB_RUN_ID"]
                    and run.get("repository_id") == control.github.REPOSITORY_ID
                    and run.get("head_branch") == "main" and run.get("head_sha") == os.environ["GITHUB_SHA"],
                    "The failed-terminal evidence artifact is not from this exact protected run.")


def confirmed_forward_stage(api, target):
    target = control.validate_config(target)
    previous = target.get("previous")
    control.require(previous is not None and target.get("forwardRecovery") is not None and target["caller"] is None
                    and previous["caller"] is None and target["versionId"] is not None
                    and target["versionId"] != previous["versionId"]
                    and target["activation"] is None and target["workflow"] is None and target["container"] == previous["container"])
    reader = GETOnlyProviderAPI(api, target)
    phase("candidate_inventory")
    reader.wait_uploaded_version(target["versionId"])
    phase("candidate_resources")
    state = control.observe(reader)
    phase("old_resource_pins")
    control.require(all(state[key] == previous[key] for key in ("activation", "container", "workflow")))
    phase("terminal_before")
    terminal = verify_forced_terminal(reader, previous, current_config=target)
    phase("terminal_digest")
    control.require(control.digest(terminal) == target["forwardRecovery"]["terminalSha256"])
    phase("terminal_after")
    control.require(control.canonical(control.observe(reader)) == control.canonical(state),
                    "The forward staged state changed during read-only reconciliation.")
    return target


def main():
    CONTEXT.update({"phase": "context", "lastRead": "none"})
    phase("context")
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == os.environ.get("GITHUB_SHA")
                    and os.environ.get("GITHUB_WORKFLOW_REF")
                    == f"{control.github.REPOSITORY}/{control.REHEARSAL_WORKFLOW_PATH}@{control.github.MAIN_REF}")
    phase("artifact")
    phase("artifact")
    artifact_receipt(os.environ.get("PROVIDER_TERMINAL_ARTIFACT_ID", ""),
                     os.environ.get("PROVIDER_TERMINAL_ARTIFACT_SHA256", ""), "subs-bot-provider-terminal-request")
    root = Path(os.environ["RUNNER_TEMP"])
    directory = root / "provider-terminal-request-input"
    target = control.read_config(control.provider.checked_file(directory / "provider-reconciled-target.json", 65536).read_text("ascii"))
    request = control.github._parse_object(control.provider.checked_file(directory / "provider-terminal-request.json", 4096).read_bytes(), control.ERROR)
    control.fields(request, {"version", "controllerRevision", "runId", "runAttempt", "sourceRunId", "sourceRunAttempt",
                             "sourceManifestSha256", "responseIdentitySha256", "previousTargetSha256", "kind", "sourceTargetSha256"})
    control.require(request["version"] == 1 and request["controllerRevision"] == os.environ["GITHUB_SHA"]
                    and request["runId"] == os.environ["GITHUB_RUN_ID"] and request["runAttempt"] == os.environ["GITHUB_RUN_ATTEMPT"]
                    and request["previousTargetSha256"] == control.digest(target) and target["environment"] == "rehearsal"
                    and target["caller"] is None)
    control.require(request["kind"] in {"terminal", "forward-stage"})
    recovery = {key: request[key] for key in ("version", "sourceRunId", "sourceRunAttempt", "sourceManifestSha256",
                                             "responseIdentitySha256", "previousTargetSha256")}
    control.validate_forward_recovery({**recovery, "terminalSha256": "0" * 64})
    phase("source")
    phase("source")
    control.guard_sources(target)
    api = control.ProviderAPI(target, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                              os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))
    api = DiagnosticReader(api, target)
    if request["kind"] == "forward-stage":
        control.require(request["sourceTargetSha256"] == control.digest({**target, "versionId": None}))
        confirmed = confirmed_forward_stage(api, target)
        control.guard_sources(confirmed)
        result = {"version": 1, "status": "confirmed-identity-only", "completion": "not-complete", "operation": "forward-stage",
                  "readOnly": True, "controllerRevision": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
                  "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "targetSha256": control.digest(confirmed),
                  "sourceRevision": confirmed["build"]["revision"],
                  **{key: request[key] for key in ("sourceRunId", "sourceRunAttempt", "sourceManifestSha256", "responseIdentitySha256", "sourceTargetSha256")}}
        phase("output")
        output = root / "provider-forward-stage-output"
        output.mkdir(mode=0o700)
        for name, value in (("provider-reconciled-target.json", confirmed), ("provider-reconciliation.json", result)):
            with control.provenance._write_private(output / name) as destination:
                destination.write(control.canonical(value))
        print(json.dumps(result, sort_keys=True))
        return
    control.require(request["sourceTargetSha256"] == control.digest(target))
    observations = []
    phase("terminal_before")
    terminal = verify_forced_terminal(api, target, evidence_sink=observations.append)
    control.require(len(observations) == 1)
    control.guard_sources(target)
    recovery["terminalSha256"] = control.digest(terminal)
    recovery = control.validate_forward_recovery(recovery)
    phase("output")
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
    except Exception as error:
        print("Provider readback diagnostic " + json.dumps(safe_diagnostic(error), sort_keys=True))
        raise SystemExit("The failed provider terminal could not be independently confirmed; no mutation was performed.") from None

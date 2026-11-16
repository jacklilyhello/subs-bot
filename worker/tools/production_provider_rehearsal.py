"""Durable intent/execute protocol for the dedicated production-provider rehearsal.

The workflow uploads an immutable intent artifact before invoking execute. A new
run may use independently registered pins, but can never replay an old run's
started/unknown intent. All resource operations use production_provider itself.
"""

from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

import production_provider as control

CONFIRMATION = "rehearse production ProviderFetch controls for subs-bot-provider-fetch-control-drill-01"
CHECKPOINT = "provider-rehearsal-checkpoint.json"
OPERATIONS = ("create", "publish", "stage", "activate", "provision-container", "provision-workflow", "smoke")
FAULTS = {"none", "after-create-response", "after-stage-response"}
MAX_CHECKPOINT = 256 * 1024
MAX_EVENTS = 80
SAFE_FILES = {"provider-rehearsal-proof.json": 65536, "provider-rehearsal-target.json": 65536,
              "provider-rehearsal-journal.json": MAX_CHECKPOINT, CHECKPOINT: MAX_CHECKPOINT,
              "provider-source-archive.zip": control.provenance.MAX_ZIP}


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def context():
    control.require(os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_CONFIRMATION") == CONFIRMATION,
                    "The dedicated rehearsal resource creation was not explicitly selected.")
    control.require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "Do not retry an interrupted rehearsal; reconcile its saved pins first.")
    control.require(os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_FAULT", "none") in FAULTS)
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == os.environ.get("GITHUB_SHA")
                    and os.environ.get("GITHUB_WORKFLOW_REF")
                    == f"{control.github.REPOSITORY}/{control.REHEARSAL_WORKFLOW_PATH}@{control.github.MAIN_REF}")


def atomic(path, value):
    raw = control.canonical(value)
    control.require(len(raw) <= MAX_CHECKPOINT, "Provider checkpoint capacity exceeded; stop without truncation.")
    temporary = path.with_suffix(".new")
    with control.provenance._write_private(temporary) as output:
        output.write(raw)
    temporary.replace(path)


def checkpoint(config, journal):
    root = Path(os.environ["RUNNER_TEMP"])
    journal["targetSha256"] = control.digest(config)
    # The combined envelope is authoritative if interruption leaves a derived file stale.
    atomic(root / CHECKPOINT, {"version": 2, "target": config, "journal": journal})
    atomic(root / "provider-rehearsal-target.json", config)
    atomic(root / "provider-rehearsal-journal.json", journal)


def load_checkpoint():
    context()
    root = Path(os.environ["RUNNER_TEMP"])
    raw = control.provider.checked_file(root / CHECKPOINT, MAX_CHECKPOINT).read_bytes()
    envelope = control.github._parse_object(raw, control.ERROR)
    control.require(set(envelope) == {"version", "target", "journal"} and envelope["version"] == 2)
    config = control.validate_config(envelope["target"])
    journal = envelope["journal"]
    control.require(isinstance(journal, dict) and journal.get("version") == 2
                    and journal.get("controllerRevision") == os.environ["GITHUB_SHA"]
                    and journal.get("runId") == os.environ["GITHUB_RUN_ID"]
                    and journal.get("runAttempt") == os.environ["GITHUB_RUN_ATTEMPT"]
                    and journal.get("targetSha256") == control.digest(config)
                    and isinstance(journal.get("events"), list) and len(journal["events"]) <= MAX_EVENTS
                    and isinstance(journal.get("steps"), list)
                    and config["environment"] == "rehearsal" and config["caller"] is None,
                    "A checkpoint from another run or an unconfirmed identity cannot be replayed.")
    return config, journal


def append(config, journal, phase, **fields):
    control.require(len(journal["events"]) < MAX_EVENTS, "Provider checkpoint event capacity exceeded.")
    journal["events"].append({"sequence": len(journal["events"]) + 1, "at": now(), "phase": phase, **fields})
    checkpoint(config, journal)


def approve(config, operation):
    os.environ["SUBS_BOT_PROVIDER_CONTROL_ENVIRONMENT"] = "rehearsal"
    os.environ["SUBS_BOT_PROVIDER_CONTROL_APPROVAL"] = control.digest({"operation": operation, "target": config})
    control.request_context(operation, config)
    control.guard_sources(config)


def api(config):
    return control.ProviderAPI(config, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                               os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))


class ObservedAPI(control.ProviderAPI):
    """Save response-only identities before any later readback can fail.

    These are observations, never automatically promoted to confirmed target pins.
    Neither response bodies nor exception text are saved.
    """

    def __init__(self, config, sink, operation):
        super().__init__(config, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                         os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))
        self.sink = sink
        self.operation = operation

    def observed(self, value):
        self.sink(value)
        fault = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_FAULT", "none")
        control.require(fault in FAULTS and self.config["environment"] == "rehearsal")
        if (fault == "after-create-response" and self.operation == "create") or (fault == "after-stage-response" and self.operation == "stage"):
            raise control.ProviderError("The explicit rehearsal interruption preserved a response-only identity; independently reconcile before continuing.")

    def _write(self, path, body, *, container=False, method="POST"):
        result = super()._write(path, body, container=container, method=method)
        safe = {}
        if isinstance(result, dict):
            for field in ("id", "version_id", "workflow_id", "account_id"):
                value = result.get(field)
                if control.match(control.publication.ACCOUNT, value) or control.match(control.stage.VERSION_ID, value):
                    safe[field] = value
                elif field == "id" and value == "provider-release-" + self.config["build"]["revision"]:
                    safe[field] = value
            for field in ("created_on", "created_at"):
                value = result.get(field)
                if control.match(control.bootstrap.TIMESTAMP, value):
                    safe[field] = value
        self.observed({"kind": "response-only", "method": method, "path": path,
                   "identities": safe, "responseSha256": control.digest(result)})
        return result

    def upload(self, module):
        candidate = super().upload(module)
        self.observed({"kind": "response-only", "method": "POST", "path": self.worker_path + "/versions",
                   "identities": {"versionId": candidate}})
        return candidate


def execute(config, operation, module, archive, *, sink=lambda _value: None):
    with tempfile.TemporaryDirectory(prefix=".provider-control-step-", dir=os.environ["RUNNER_TEMP"]) as directory:
        scratch = Path(directory)
        client = ObservedAPI(config, sink, operation)
        guard = lambda: control.guard_sources(config)
        if operation == "create":
            return {"worker": client.create()}
        if operation == "publish":
            return control.publish_image(config, scratch, archive, guard)
        return control.run_operation(client, operation, module, control.PublishedImage(config, client._container_token, scratch), guard)


def initial_config(build, health_url, health_revision):
    control.require(health_url in {"https://subs-bot-cf-dev-01.lilyya.workers.dev/health",
                                   "https://subs-bot-cf-control-drill-01.lilyya.workers.dev/health"}
                    and control.match(control.provider.REVISION, health_revision),
                    "The rehearsal health fixture is outside the approved project identities.")
    health = control.legacy._public(health_url, health_revision)
    value = {"version": 1, "environment": "rehearsal", "accountId": "9431815bdb8beb2272f6668e06b7d3be",
             "service": control.SERVICES["rehearsal"], "workersDevOrigin": "https://subs-bot-provider-fetch-control-drill-01.lilyya.workers.dev",
             "worker": None, "build": build, "versionId": None, "activation": None, "container": None,
             "workflow": None, "smoke": {"healthUrl": health_url, "healthRevision": health_revision,
                                           "healthSha256": health["sha256"], "healthBytes": health["bytes"]},
             "caller": None, "previous": None}
    return control.validate_config(value)


def selection():
    mode = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_SOURCE_MODE", "registered")
    control.require(mode in {"registered", "current"})
    raw = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_TARGET_JSON", "")
    old = control.read_config(raw) if raw else None
    control.require(old is None or old["environment"] == "rehearsal" and old["caller"] is None)
    revision = old["build"]["revision"] if old is not None and mode == "registered" else os.environ["GITHUB_SHA"]
    if old is not None and mode == "registered":
        control.require(os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID") == old["build"]["runId"],
                        "Registered continuation requires the exact frozen source CI run.")
    return mode, old, revision


def prepare_source():
    context()
    _mode, old, revision = selection()
    if old is not None:
        approve(old, "verify")
    evidence = control.provenance.prepare(provider_revision=revision)
    root = Path(os.environ["RUNNER_TEMP"])
    control.provenance._download_zip(evidence["artifactId"], control.github._github_token(), evidence["archiveSha256"],
                                     root / "provider-source-archive.zip")
    print(json.dumps(evidence, sort_keys=True))


def verified_input(config=None):
    root = Path(os.environ["RUNNER_TEMP"])
    with (root / control.publication.EVIDENCE_FILE).open("rb") as source:
        build = control.provider.json_object(source)
    archive, evidence = control.publication._verified_input(root, build["revision"], build["runId"])
    control.require(config is None or config["build"] == evidence)
    module = control.provider.checked_file(archive.with_name(control.provider.WORKER), control.provider.MAX_WORKER).read_bytes()
    control.require(control.sha256(module).hexdigest() == evidence["workerSha256"])
    return archive, evidence, module


def initialize():
    context()
    mode, old, _revision = selection()
    _archive, evidence, _module = verified_input()
    if old is not None and old["build"] == evidence:
        config = old
    else:
        config = initial_config(evidence, os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_HEALTH_URL", ""),
                                os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_HEALTH_REVISION", ""))
        if old is not None:
            control.require(mode == "current")
            approve(old, "verify")
            control.verify_provider_dependency(api(old), old, allow_unbound_caller=True)
            config.update({"worker": old["worker"], "container": old["container"], "workflow": None, "previous": old})
            config = control.validate_config(config)
    fault = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_FAULT", "none")
    if fault != "none":
        control.require(config.get("previous") is None and config["activation"] is None,
                        "A deterministic interruption is limited to the first private release before consumers.")
        control.require((fault == "after-create-response" and config["worker"] is None)
                        or (fault == "after-stage-response" and config["versionId"] is None),
                        "The selected deterministic interruption operation has already completed.")
    journal = {"version": 2, "controllerRevision": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
               "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "sourceMode": mode, "source": evidence,
               "faultMode": fault,
               "events": [], "steps": [], "currentIntent": None, "completion": "not-complete"}
    checkpoint(config, journal)
    with tempfile.TemporaryDirectory(prefix=".provider-source-closure-", dir=os.environ["RUNNER_TEMP"]) as directory:
        control.verify_previous_archives(config, Path(directory))
    append(config, journal, "initialized", status="registered", targetSha256=control.digest(config))


def needed(config, operation):
    control.require(operation in OPERATIONS)
    field = {"create": "worker", "stage": "versionId", "activate": "activation",
             "provision-container": "container", "provision-workflow": "workflow"}.get(operation)
    if field:
        return config[field] is None
    if operation == "smoke":
        observed = control.observe(api(config))
        if observed["instance"] is not None:
            control.verify_smoke(api(config), observed)
            return False
    return True


def prepare_operation(operation):
    config, journal = load_checkpoint()
    previous = journal["currentIntent"]
    control.require(previous is None or previous["status"] in {"confirmed", "skipped"},
                    "An unconfirmed intent requires independent reconciliation, never automatic replay.")
    approve(config, operation)
    is_needed = needed(config, operation)
    if is_needed and operation == "create":
        preflight = {"workerNameAbsent": api(config)._request("/workers/workers/" + config["service"], absent=10007) is None}
        control.require(preflight["workerNameAbsent"], "An occupied unregistered provider name cannot be adopted.")
    elif is_needed and operation != "publish":
        preflight = {"stateSha256": control.digest(control.observe(api(config)))}
    else:
        preflight = {"mutationNeeded": is_needed}
    intent = {"operation": operation, "runId": os.environ["GITHUB_RUN_ID"], "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"],
              "controllerRevision": os.environ["GITHUB_SHA"], "source": config["build"], "targetSha256": control.digest(config),
              "approvalSha256": control.digest({"operation": operation, "target": config}), "preflight": preflight,
              "faultMode": os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_FAULT", "none"),
              "status": "started-unknown" if is_needed else "skipped", "executed": False}
    intent["intentSha256"] = control.digest(intent)
    journal["currentIntent"] = intent
    append(config, journal, "intent", **deepcopy(intent))


def confirmed_target(config, operation, result):
    value = deepcopy(config)
    if operation == "create":
        value["worker"] = result["worker"]
    elif operation == "stage":
        value["versionId"] = result["versionId"]
    elif operation == "activate":
        value["activation"] = result["activation"]
        if result["workflow"] is not None:
            previous = value.get("previous")
            control.require(previous is not None and result["workflow"]["workflowId"] == previous["workflow"]["workflowId"]
                            and result["workflow"]["createdOn"] == previous["workflow"]["createdOn"])
            value["workflow"] = result["workflow"]
    elif operation == "provision-container":
        value["container"] = result["container"]
    elif operation == "provision-workflow":
        value["workflow"] = result["workflow"]
    return control.validate_config(value)


def persisted_intent(operation):
    artifact_id = os.environ.get("SUBS_BOT_PROVIDER_INTENT_ARTIFACT_ID", "")
    digest = os.environ.get("SUBS_BOT_PROVIDER_INTENT_ARTIFACT_SHA256", "")
    control.require(control.match(control.provider.DECIMAL, artifact_id) and control.match(control.provider.HEX, digest),
                    "A cloud-persisted intent artifact is required before a provider mutation.")
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, control.github._github_token())
    run = artifact.get("workflow_run")
    control.require(artifact.get("name") == f"subs-bot-provider-attempt-intent-{operation}-{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}"
                    and artifact.get("expired") is False and artifact.get("digest") == "sha256:" + digest
                    and isinstance(run, dict) and str(run.get("id")) == os.environ["GITHUB_RUN_ID"]
                    and run.get("repository_id") == control.github.REPOSITORY_ID
                    and run.get("head_branch") == "main" and run.get("head_sha") == os.environ["GITHUB_SHA"],
                    "The provider intent artifact does not match this exact protected workflow run.")
    return {"artifactId": artifact_id, "archiveSha256": digest}


def execute_operation(operation):
    config, journal = load_checkpoint()
    intent = journal["currentIntent"]
    control.require(isinstance(intent, dict) and intent.get("operation") == operation
                    and intent.get("targetSha256") == control.digest(config) and intent.get("executed") is False
                    and intent.get("status") in {"started-unknown", "skipped"}, "An old or already executed provider intent cannot be replayed.")
    control.require(intent.get("intentSha256") == control.digest({key: value for key, value in intent.items() if key != "intentSha256"})
                    and intent.get("source") == config["build"]
                    and intent.get("faultMode") == os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_FAULT", "none")
                    and intent.get("approvalSha256") == control.digest({"operation": operation, "target": config}),
                    "The operation intent, source, target and approval digest differ.")
    if intent["status"] == "skipped":
        return
    try:
        receipt = persisted_intent(operation)
        append(config, journal, "intent-persisted", operation=operation, intentSha256=intent["intentSha256"], **receipt)
        approve(config, operation)
        archive, _evidence, module = verified_input(config)
    except Exception:
        intent["status"] = "failed-before-dispatch"
        append(config, journal, "result", operation=operation, status="failed-before-dispatch", intentSha256=intent["intentSha256"])
        raise
    intent["executed"] = True
    append(config, journal, "dispatch", operation=operation, status="started-unknown", intentSha256=intent["intentSha256"])

    def observe_response(value):
        append(config, journal, "observation", operation=operation, intentSha256=intent["intentSha256"], **value)

    try:
        result = execute(config, operation, module, archive, sink=observe_response)
        updated = confirmed_target(config, operation, result)
    except Exception:
        intent["status"] = "unconfirmed"
        append(config, journal, "result", operation=operation, status="unconfirmed", intentSha256=intent["intentSha256"])
        raise
    intent["status"] = "confirmed"
    receipt = {"operation": operation, "status": "confirmed", "intentSha256": intent["intentSha256"],
               "stateSha256": control.digest(result), "targetSha256": control.digest(updated)}
    journal["steps"].append(receipt)
    append(updated, journal, "result", **receipt)


def finalize():
    config, journal = load_checkpoint()
    control.require(journal["currentIntent"] is None or journal["currentIntent"]["status"] in {"confirmed", "skipped"})
    approve(config, "verify")
    archive, _evidence, module = verified_input(config)
    execute(config, "verify", module, archive)
    binding = control.verify_provider_dependency(api(config), config, allow_unbound_caller=True)
    journal["completion"] = "complete"
    append(config, journal, "final-readback", status="confirmed", bindingSha256=control.digest(binding))
    proof = {"version": 1, "controllerRevision": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
             "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "status": "complete", "target": config,
             "binding": binding, "steps": journal["steps"], "journalSha256": control.digest(journal), "productionMutation": False}
    atomic(Path(os.environ["RUNNER_TEMP"]) / "provider-rehearsal-proof.json", proof)
    print(json.dumps({"status": "complete", "targetSha256": control.digest(config), "proofSha256": control.digest(proof),
                      "sourceRevision": config["build"]["revision"], "productionMutation": False}, sort_keys=True))


def assemble(phase):
    # No credentials are accepted by this packaging path. Preserve only fixed safe outputs.
    control.require(phase in {"source", "final"})
    root = Path(os.environ["RUNNER_TEMP"])
    output = root / ("provider-control-source-output" if phase == "source" else "provider-proof-output")
    output.mkdir(mode=0o700, exist_ok=True)
    complete = phase == "final" and os.environ.get("PROVIDER_REHEARSAL_OUTCOME") == "success" and (root / "provider-rehearsal-proof.json").is_file()
    attempt = {"version": 1, "controllerRevision": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
               "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "phase": phase,
               "completion": "complete" if complete else "not-complete", "productionMutation": False,
               "jobOutcome": os.environ.get("PROVIDER_REHEARSAL_OUTCOME", "in-progress"), "missingFiles": []}
    atomic(output / "provider-rehearsal-attempt.json", attempt)
    for name, limit in SAFE_FILES.items():
        source = root / name
        if source.is_file():
            control.provider.checked_file(source, limit)
            shutil.copyfile(source, output / name)
        else:
            attempt["missingFiles"].append(name)
    verified = root / control.provenance.VERIFIED_DIRECTORY
    for name, limit in control.provenance.FILE_LIMITS.items():
        source = verified / name
        if source.is_file():
            control.provider.checked_file(source, limit)
            (output / "source").mkdir(mode=0o700, exist_ok=True)
            shutil.copyfile(source, output / "source" / name)
        else:
            attempt["missingFiles"].append("source/" + name)
    atomic(output / "provider-rehearsal-attempt.json", attempt)


def main():
    args = sys.argv[1:]
    control.require(args and args[0] in {"prepare-source", "initialize", "prepare-operation", "execute-operation", "finalize", "assemble"})
    command = args[0]
    if command in {"prepare-operation", "execute-operation", "assemble"}:
        control.require(len(args) == 2)
        {"prepare-operation": prepare_operation, "execute-operation": execute_operation, "assemble": assemble}[command](args[1])
    else:
        control.require(len(args) == 1)
        {"prepare-source": prepare_source, "initialize": initialize, "finalize": finalize}[command]()


if __name__ == "__main__":
    try:
        main()
    except (control.ProviderError, control.legacy.ActivationError, control.bootstrap.BootstrapError, control.stage.StageError,
            control.publication.PublicationError, control.github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except control.provider.VERIFICATION_ERRORS:
        raise SystemExit(control.ERROR) from None

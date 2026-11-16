"""Run the actual production ProviderFetch controls on the one registered rehearsal identity."""

from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile

import production_provider as control

CONFIRMATION = "rehearse production ProviderFetch controls for subs-bot-provider-fetch-control-drill-01"


def checkpoint(config, steps):
    root = Path(os.environ["RUNNER_TEMP"])
    for name, value in (("provider-rehearsal-target.json", config),
                        ("provider-rehearsal-journal.json", {"version": 1, "controllerRevision": os.environ["GITHUB_SHA"],
                           "targetSha256": control.digest(config), "steps": steps})):
        path = root / name
        temporary = path.with_suffix(".new")
        with control.provenance._write_private(temporary) as output:
            output.write(control.canonical(value))
        temporary.replace(path)


def approve(config, operation):
    os.environ["SUBS_BOT_PROVIDER_CONTROL_ENVIRONMENT"] = "rehearsal"
    os.environ["SUBS_BOT_PROVIDER_CONTROL_APPROVAL"] = control.digest({"operation": operation, "target": config})
    control.request_context(operation, config)
    control.guard_sources(config)


def api(config):
    return control.ProviderAPI(config, os.environ.get("SUBS_BOT_CF_PROVIDER_WORKER_TOKEN", ""),
                               os.environ.get("SUBS_BOT_CF_PROVIDER_CONTAINER_TOKEN", ""))


def execute(config, operation, module, archive):
    approve(config, operation)
    with tempfile.TemporaryDirectory(prefix=".provider-control-step-", dir=os.environ["RUNNER_TEMP"]) as directory:
        scratch = Path(directory)
        client = api(config)
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


def main():
    control.require(os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_CONFIRMATION") == CONFIRMATION,
                    "The dedicated rehearsal resource creation was not explicitly selected.")
    control.require(os.environ.get("GITHUB_RUN_ATTEMPT") == "1", "Do not retry an interrupted rehearsal; reconcile its saved pins first.")
    root = Path(os.environ["RUNNER_TEMP"])
    revision, run_id = os.environ["GITHUB_SHA"], os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    archive, evidence = control.publication._verified_input(root, revision, run_id)
    module = control.provider.checked_file(archive.with_name(control.provider.WORKER), control.provider.MAX_WORKER).read_bytes()
    control.require(control.sha256(module).hexdigest() == evidence["workerSha256"])
    health_url = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_HEALTH_URL", "")
    health_revision = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_HEALTH_REVISION", "")
    config = initial_config(evidence, health_url, health_revision)
    existing = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_TARGET_JSON", "")
    if existing:
        old = control.read_config(existing)
        control.require(old["environment"] == "rehearsal" and old["caller"] is None)
        if old["build"] == evidence:
            config = old
        else:
            approve(old, "verify")
            control.verify_provider_dependency(api(old), old, allow_unbound_caller=True)
            config.update({"worker": old["worker"], "container": old["container"], "workflow": None, "previous": old})
            config = control.validate_config(config)
    with tempfile.TemporaryDirectory(prefix=".provider-source-closure-", dir=root) as directory:
        control.verify_previous_archives(config, Path(directory))
    steps = []
    checkpoint(config, steps)
    if config["worker"] is None:
        result = execute(config, "create", module, archive)
        config["worker"] = result["worker"]
        steps.append({"operation": "create", "stateSha256": control.digest(result)})
        checkpoint(config, steps)
    result = execute(config, "publish", module, archive)
    steps.append({"operation": "publish", "stateSha256": control.digest(result)})
    checkpoint(config, steps)
    if config["versionId"] is None:
        result = execute(config, "stage", module, archive)
        config["versionId"] = result["versionId"]
        steps.append({"operation": "stage", "stateSha256": control.digest(result)})
        checkpoint(config, steps)
    if config["activation"] is None:
        result = execute(config, "activate", module, archive)
        config["activation"] = result["activation"]
        if result["workflow"] is not None:
            previous = config.get("previous")
            control.require(previous is not None and result["workflow"]["workflowId"] == previous["workflow"]["workflowId"]
                            and result["workflow"]["createdOn"] == previous["workflow"]["createdOn"])
            config["workflow"] = result["workflow"]
        steps.append({"operation": "activate", "stateSha256": control.digest(result)})
        checkpoint(config, steps)
    if config["container"] is None:
        result = execute(config, "provision-container", module, archive)
        config["container"] = result["container"]
        steps.append({"operation": "provision-container", "stateSha256": control.digest(result)})
        checkpoint(config, steps)
    if config["workflow"] is None:
        result = execute(config, "provision-workflow", module, archive)
        config["workflow"] = result["workflow"]
        steps.append({"operation": "provision-workflow", "stateSha256": control.digest(result)})
        checkpoint(config, steps)
    observed = control.observe(api(config))
    if observed["instance"] is None:
        result = execute(config, "smoke", module, archive)
        steps.append({"operation": "smoke", "stateSha256": control.digest(result)})
        checkpoint(config, steps)
    execute(config, "verify", module, archive)
    binding = control.verify_provider_dependency(api(config), config, allow_unbound_caller=True)
    proof = {"version": 1, "controllerRevision": revision, "runId": os.environ["GITHUB_RUN_ID"],
             "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "status": "complete", "target": config,
             "binding": binding, "steps": steps, "productionMutation": False}
    with control.provenance._write_private(root / "provider-rehearsal-proof.json") as output:
        output.write(control.canonical(proof))
    control.provenance._download_zip(evidence["artifactId"], control.github._github_token(), evidence["archiveSha256"],
                                     root / "provider-source-archive.zip")
    print(json.dumps({"status": "complete", "controllerRevision": revision, "sourceRevision": evidence["revision"],
                      "targetSha256": control.digest(config), "proofSha256": control.digest(proof), "steps": steps,
                      "productionMutation": False}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (control.ProviderError, control.legacy.ActivationError, control.bootstrap.BootstrapError, control.stage.StageError,
            control.publication.PublicationError, control.github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except control.provider.VERIFICATION_ERRORS:
        raise SystemExit(control.ERROR) from None

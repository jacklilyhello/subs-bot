"""Activate or verify the separate, pinned private API status V2 service."""

import json
import os
from pathlib import Path

import activate_provider_isolation as activation
import stage_provider_api_status_version as version


provider = activation.provider
bootstrap = activation.bootstrap
publication = activation.publication
github = activation.github
WORKFLOW = ".github/workflows/worker-provider-api-status-isolation-activate.yml"
PROOF_FILE = "provider-api-status-v2-binding-proof.json"
PREFIX = "SUBS_BOT_CF_PROVIDER_API_STATUS_"
CONTAINER_TOKEN_ENV = PREFIX + "CONTAINER_TOKEN"
OPERATION_ENV = "SUBS_BOT_PROVIDER_API_STATUS_ACTIVATION_OPERATION"
CONFIRMATION_ENV = "SUBS_BOT_PROVIDER_API_STATUS_ACTIVATION_CONFIRMATION"
ISOLATED_REVISION_ENV = "SUBS_BOT_PROVIDER_API_STATUS_ISOLATED_REVISION"


def activate(revision, attempt):
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    operation = os.environ.get(OPERATION_ENV, "")
    confirmation = os.environ.get(CONFIRMATION_ENV, "")
    isolated_revision = os.environ.get(ISOLATED_REVISION_ENV, "")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    activation._require(provider.DECIMAL.fullmatch(run_id) and runner_temp.is_absolute()
                        and operation in activation.OPERATIONS
                        and ((operation == "verify" and confirmation == "") or
                             (operation != "verify" and attempt == "1" and confirmation == f"{operation} {provider.API_STATUS_SERVICE}")),
                        "Use verification or an explicitly confirmed first-attempt API status operation.")
    activation._require((not isolated_revision and operation != "smoke") or provider.REVISION.fullmatch(isolated_revision), activation.PIN_ERROR)
    identity = bootstrap._pin(os.environ.get(version.IDENTITY_ENV, ""))
    activation._require(identity is not None, activation.PIN_ERROR)
    account = os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", "")
    worker_token = os.environ.get(version.WORKER_TOKEN_ENV, "")
    container_token = os.environ.get(CONTAINER_TOKEN_ENV, "")
    activation._require(worker_token != container_token and all(publication.API_TOKEN.fullmatch(token) for token in (worker_token, container_token)),
                        "Separate dedicated API status Worker and activation Container credentials are required.")
    profile = provider.API_STATUS_PROFILE
    _, evidence = publication._verified_input(runner_temp, revision, run_id, profile=profile, account=account)
    release = activation._release_pin(os.environ.get(PREFIX + "RELEASE_JSON", ""), evidence)
    pins = {
        "activation": activation._pin(os.environ.get(PREFIX + "ACTIVATION_JSON", ""), ("deploymentId", "namespaceId")),
        "container": activation._pin(os.environ.get(PREFIX + "CONTAINER_IDENTITY_JSON", ""), ("applicationId", "createdAt")),
        "workflow": activation._pin(os.environ.get(PREFIX + "WORKFLOW_IDENTITY_JSON", ""), ("workflowId", "createdOn", "versionId")),
    }

    def guard():
        publication._guard_main(evidence)

    guard()
    api = activation.ProviderAPI(account, worker_token, container_token, identity, profile=profile)
    return {**evidence, **activation._run(api, operation, release, pins, isolated_revision, guard)}


def write_proof(result, revision, run_id, attempt):
    if result["status"] != "complete":
        return
    build_fields = activation.API_STATUS_BUILD_FIELDS
    proof_fields = activation.PROOF_FIELDS | {"apiStatus"}
    activation._require(set(result) == build_fields | proof_fields, activation.BINDING_PROOF_ERROR)
    raw = activation._proof_bytes({
        "version": 3,
        "accountSha256": publication.TARGET_ACCOUNT_SHA256,
        "providerBuild": {key: result[key] for key in build_fields},
        "activation": {"runId": run_id, "runAttempt": attempt, "isolatedRevision": os.environ.get(ISOLATED_REVISION_ENV, "")},
        "verification": {key: result[key] for key in proof_fields},
    })
    activation.parse_binding_proof(raw, revision=revision, run_id=run_id, run_attempt=attempt, profile=provider.API_STATUS_PROFILE)
    activation._write_proof_artifact(raw, PROOF_FILE)


def main():
    revision, run_id, attempt = activation._binding_proof_context(workflow_path=WORKFLOW)
    result = activate(revision, attempt)
    write_proof(result, revision, run_id, attempt)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (activation.ActivationError, activation.stage.StageError, bootstrap.BootstrapError,
            publication.PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The private API status activation could not be verified safely.") from None

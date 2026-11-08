"""Verify or stage the exact current private API status V2 Worker version."""

from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

import stage_provider_version as version

publication = version.publication
provider = publication.provider
github = publication.github
WORKFLOW = ".github/workflows/worker-provider-api-status-version-stage.yml"
WORKER_TOKEN_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_WORKER_TOKEN"
IDENTITY_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_WORKER_IDENTITY_JSON"
IMAGE_TOKEN_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_CONTAINER_TOKEN"
CONFIRM_STAGE = "stage subs-bot-provider-api-status-dev-01"


def stage():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    runner_temp = Path(os.environ.get("RUNNER_TEMP", ""))
    operation = os.environ.get("SUBS_BOT_PROVIDER_API_STATUS_STAGE_OPERATION", "")
    confirmation = os.environ.get("SUBS_BOT_PROVIDER_API_STATUS_STAGE_CONFIRMATION", "")
    version._require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY and os.environ.get("GITHUB_REF") == github.MAIN_REF
                     and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and provider.REVISION.fullmatch(revision)
                     and os.environ.get("GITHUB_WORKFLOW_REF") == f"{github.REPOSITORY}/{WORKFLOW}@{github.MAIN_REF}"
                     and os.environ.get("GITHUB_WORKFLOW_SHA") == revision and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                     and provider.DECIMAL.fullmatch(run_id) and runner_temp.is_absolute(),
                     "API status version staging requires its exact protected GitHub-hosted main workflow.")
    version._require((operation == "verify" and confirmation == "") or
                     (operation == "stage" and confirmation == CONFIRM_STAGE and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"),
                     "Use verification or an explicitly confirmed first-attempt API status version stage.")
    identity = version.bootstrap._pin(os.environ.get(IDENTITY_ENV, ""))
    version._require(identity is not None, "API status version staging requires the independently pinned Worker identity.")
    account = os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", "")
    worker_token = os.environ.get(WORKER_TOKEN_ENV, "")
    image_token = os.environ.get(IMAGE_TOKEN_ENV, "")
    version._require(worker_token != image_token and all(publication.API_TOKEN.fullmatch(token) for token in (worker_token, image_token)),
                     "Separate dedicated API status Worker and image preparation credentials are required.")
    profile = provider.API_STATUS_PROFILE
    archive, evidence = publication._verified_input(runner_temp, revision, run_id, profile=profile, account=account)
    with provider.checked_file(archive.with_name(provider.WORKER), provider.MAX_WORKER).open("rb") as source:
        module = source.read(provider.MAX_WORKER + 1)
    version._require(0 < len(module) <= provider.MAX_WORKER and sha256(module).hexdigest() == evidence["workerSha256"],
                     "The compiled API status module changed after artifact verification.")

    def guard():
        publication._guard_main(evidence)

    guard()
    versions = version.WorkerVersions(account, worker_token, identity, profile=profile)
    with tempfile.TemporaryDirectory(prefix=".subs-bot-api-status-version-", dir=runner_temp) as scratch:
        image = version.PublishedImage(account, image_token, evidence, Path(scratch))
        status, candidate = version._stage(versions, image, operation, evidence, module, guard)
    return {**evidence, "status": status, "workerIdentitySha256": identity.fingerprint(),
            "versionSha256": sha256(candidate.encode("ascii")).hexdigest() if candidate else None, "activeDeployments": 0}


if __name__ == "__main__":
    try:
        print(json.dumps(stage(), sort_keys=True))
    except (version.StageError, version.bootstrap.BootstrapError, publication.PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The private API status version could not be staged safely.") from None

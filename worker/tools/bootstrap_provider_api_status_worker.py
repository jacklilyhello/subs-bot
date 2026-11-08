"""Create or verify the fixed empty private API status V2 Worker shell."""

import json
import os

import bootstrap_provider_worker as shell
import prepare_provider_api_status_artifact as artifact
import prepare_provider_artifact as provenance

provider = provenance.provider
github = provenance.github
WORKFLOW = ".github/workflows/worker-provider-api-status-bootstrap.yml"
TOKEN_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_WORKER_TOKEN"
IDENTITY_ENV = "SUBS_BOT_CF_PROVIDER_API_STATUS_WORKER_IDENTITY_JSON"
CONFIRM_CREATE = "create subs-bot-provider-api-status-dev-01"


def bootstrap():
    revision = os.environ.get("GITHUB_SHA", "")
    action = os.environ.get("SUBS_BOT_PROVIDER_API_STATUS_BOOTSTRAP_OPERATION", "")
    confirmation = os.environ.get("SUBS_BOT_PROVIDER_API_STATUS_BOOTSTRAP_CONFIRMATION", "")
    shell._require(os.environ.get("GITHUB_REPOSITORY") == github.REPOSITORY and os.environ.get("GITHUB_REF") == github.MAIN_REF
                   and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and provider.REVISION.fullmatch(revision)
                   and os.environ.get("GITHUB_WORKFLOW_REF") == f"{github.REPOSITORY}/{WORKFLOW}@{github.MAIN_REF}"
                   and os.environ.get("GITHUB_WORKFLOW_SHA") == revision and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
                   "API status Worker bootstrap requires its exact protected GitHub-hosted main workflow.")
    pin = shell._pin(os.environ.get(IDENTITY_ENV, ""))
    shell._require((action == "verify" and pin is not None and confirmation == "")
                   or (action == "create" and pin is None and confirmation == CONFIRM_CREATE
                       and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"),
                   "Use a pinned verification or an explicitly confirmed first-attempt API status Worker creation.")
    worker_token = os.environ.get(TOKEN_ENV, "")
    shell._require(shell.API_TOKEN.fullmatch(worker_token), "The dedicated API status Worker credential is missing or malformed.")
    evidence = artifact.prepare()
    profile = provider.API_STATUS_PROFILE
    shell._require((evidence.get("revision"), evidence.get("profile"), evidence.get("service"), evidence.get("rpcEntrypoint"))
                   == (revision, profile, provider.API_STATUS_SERVICE, provider.API_STATUS_ENTRYPOINT),
                   "The exact API status artifact did not match the Worker profile.")

    def guard():
        actual = provenance._select_artifact(evidence["runId"], revision, github._github_token(), profile=profile)
        shell._require(actual == (evidence["runAttempt"], evidence["artifactId"], evidence["archiveSha256"]),
                       "The trusted API status build attempt or artifact changed.")
        github.require_current_main(revision)

    guard()
    api = shell.WorkerAPI(os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", ""), worker_token, profile=profile)
    status, identity = shell._bootstrap(api, action, pin, guard, profile=profile)
    return {"status": status, "profile": profile, "service": provider.API_STATUS_SERVICE,
            "ownershipTag": shell.API_STATUS_OWNERSHIP_TAG, "workerIdentitySha256": identity.fingerprint(),
            "revision": revision, "artifactId": evidence["artifactId"], "workersDev": False,
            "previews": False, "logging": False, "versions": 0}


if __name__ == "__main__":
    try:
        print(json.dumps(bootstrap(), sort_keys=True))
    except (shell.BootstrapError, shell.PublicationError, github.ArtifactError) as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The private API status Worker bootstrap could not be completed safely.") from None

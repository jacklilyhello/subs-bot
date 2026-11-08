"""Verify the API status V2 build and exact private OCI destination without publishing."""

from hashlib import sha256
import json
import os
from pathlib import Path

import prepare_isolation_artifact as github
import prepare_provider_artifact as provenance
from publish_provider_registry import ACCOUNT, TARGET_ACCOUNT_SHA256, api_status_registry_pin

provider = provenance.provider


def prepare():
    if (os.environ.get("GITHUB_REPOSITORY") != github.REPOSITORY
            or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"):
        raise github.ArtifactError("API status artifact verification requires a protected main dispatch.")
    account = os.environ.get("SUBS_BOT_CF_PROVIDER_ACCOUNT_ID", "")
    if not ACCOUNT.fullmatch(account) or sha256(account.encode("ascii")).hexdigest() != TARGET_ACCOUNT_SHA256:
        raise github.ArtifactError("The API status OCI destination does not match the isolated account.")
    profile = provider.API_STATUS_PROFILE
    evidence = provenance.prepare(profile=profile)
    directory = Path(os.environ["RUNNER_TEMP"]) / provenance.API_STATUS_VERIFIED_DIRECTORY
    with provider.checked_file(directory / provider.MANIFEST, provider.MAX_METADATA).open("rb") as source:
        manifest = provider.json_object(source)
    fields = ("profile", "service", "rpcEntrypoint", "ociManifestSha256", "ociConfigSha256", "workerSha256")
    provider.require(all(manifest[field] == evidence[field] for field in fields))
    _, image, pin = api_status_registry_pin(account, evidence["ociManifestSha256"])
    config = provider.config_for(directory, manifest, account, profile=profile)
    provider.require(config["name"] == provider.API_STATUS_SERVICE and len(config["containers"]) == 1
                     and config["containers"][0]["images"] == {"provider": {"image": image}})
    github.require_current_main(evidence["revision"])
    return {**evidence, **pin}


if __name__ == "__main__":
    try:
        print(json.dumps(prepare(), sort_keys=True))
    except github.ArtifactError as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("API status artifact verification could not be completed safely.") from None

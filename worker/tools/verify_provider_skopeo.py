"""Exercise the publication CLI on the exact Provider Fetch CI archive offline."""

import argparse
from pathlib import Path
import tempfile

from publish_provider_registry import PublicationError, _copy_image, _inspect_digest, provider


def verify(directory, runner_temp):
    with provider.checked_file(directory / provider.MANIFEST, provider.MAX_METADATA).open("rb") as source:
        manifest = provider.json_object(source)
    archive = provider.checked_file(directory / provider.IMAGE, provider.MAX_IMAGE)
    provider.require(provider.checksum(archive) == manifest["ociArchiveSha256"])
    manifest_sha = manifest["ociManifestSha256"]
    config_sha = manifest["ociConfigSha256"]
    provider.require(provider.HEX.fullmatch(manifest_sha) and provider.HEX.fullmatch(config_sha))
    with tempfile.TemporaryDirectory(prefix="subs-bot-skopeo-", dir=runner_temp) as scratch_name:
        scratch = Path(scratch_name)
        auth = scratch / "auth.json"
        auth.write_text('{"auths":{}}', encoding="ascii")
        destination = f"oci:{scratch / 'layout'}:verified"
        _copy_image(scratch, archive, destination, auth, "sha256:" + manifest_sha)
        if _inspect_digest(scratch, destination, auth) != manifest_sha:
            raise PublicationError("Skopeo raw manifest digest differs from the built OCI manifest.")
        if _inspect_digest(scratch, destination, auth, config=True) != config_sha:
            raise PublicationError("Skopeo raw config digest differs from the built OCI config.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("runner_temp", type=Path)
    args = parser.parse_args()
    try:
        verify(args.artifact, args.runner_temp)
    except PublicationError as error:
        raise SystemExit(str(error)) from None
    except provider.VERIFICATION_ERRORS:
        raise SystemExit("The built OCI archive or release manifest could not be verified.") from None
    print("Pinned Skopeo preserved the built OCI manifest and config digests offline.")

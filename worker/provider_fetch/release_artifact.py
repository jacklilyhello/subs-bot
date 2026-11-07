"""Verify the exact OCI and Worker bytes and render a private deployment config."""

import argparse
from hashlib import file_digest, sha256
import json
from pathlib import Path
import re
import stat
import tarfile


SERVICE = "subs-bot-provider-fetch-dev-01"
COMPATIBILITY = "2026-11-06"
MANIFEST = "provider-release.json"
IMAGE = "provider-image.tar"
WORKER = "provider-worker.js"
HEX = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
BASE_ENV = {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"}
MAX_IMAGE = 256 * 1024 * 1024
MAX_WORKER = 1024 * 1024
MAX_METADATA = 64 * 1024


def require(condition):
    if not condition:
        raise ValueError("The provider artifact or its configuration differs from the expected format.")


def checked_file(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit)
    return path


def checksum(path):
    with path.open("rb") as file:
        return file_digest(file, "sha256").hexdigest()


def verify_image(path, revision):
    with tarfile.open(checked_file(path, MAX_IMAGE), mode="r:") as archive:
        members = {}
        for index, member in enumerate(archive):
            require(index < 34)
            name = member.name.removeprefix("./")
            if member.isdir() and name in {"", ".", "blobs", "blobs/sha256"}:
                continue
            require(len(members) < 30 and name not in members and member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    and 0 < member.size <= MAX_IMAGE
                    and (name in {"oci-layout", "index.json"} or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)))
            members[name] = member

        def metadata(name):
            member = members[name]
            require(0 < member.size <= MAX_METADATA)
            with archive.extractfile(member) as file:
                value = json.load(file)
            require(isinstance(value, dict))
            return value

        referenced = {"oci-layout", "index.json"}

        def blob(descriptor):
            algorithm, _, digest = descriptor["digest"].partition(":")
            require(algorithm == "sha256" and HEX.fullmatch(digest))
            name = "blobs/sha256/" + digest
            member = members[name]
            require(type(descriptor["size"]) is int and descriptor["size"] == member.size and member.size > 0)
            with archive.extractfile(member) as file:
                actual = file_digest(file, "sha256").hexdigest()
            require(digest == actual)
            referenced.add(name)
            return name, digest

        require(metadata("oci-layout") == {"imageLayoutVersion": "1.0.0"})
        index = metadata("index.json")
        manifests = index["manifests"]
        require(index["schemaVersion"] == 2 and len(manifests) == 1 and manifests[0]["mediaType"] == OCI_MANIFEST)
        manifest_name, manifest_digest = blob(manifests[0])
        manifest = metadata(manifest_name)
        require(manifest["schemaVersion"] == 2 and 0 < len(manifest["layers"]) <= 20)
        config_name, config_digest = blob(manifest["config"])
        config = metadata(config_name)
        for layer in manifest["layers"]:
            blob(layer)
        require(set(members) == referenced and config["architecture"] == "amd64" and config["os"] == "linux")
        runtime = config["config"]
        require(runtime["User"] == "65532:65532" and runtime["Entrypoint"] == ["python", "-B", "-E", "-s", "/app/server.py"]
                and runtime["WorkingDir"] == "/app" and runtime["Labels"]["org.opencontainers.image.revision"] == revision
                and set(runtime["ExposedPorts"]) == {"8080/tcp"} and not runtime.get("Volumes")
                and all(item.partition("=")[0] in BASE_ENV for item in runtime["Env"]))
    return manifest_digest, config_digest


def release_manifest(directory, revision, requirements):
    require(isinstance(revision, str) and REVISION.fullmatch(revision))
    image = directory / IMAGE
    manifest_digest, config_digest = verify_image(image, revision)
    return {"version": 1, "service": SERVICE, "revision": revision, "compatibilityDate": COMPATIBILITY,
            "ociArchiveSha256": checksum(image), "ociManifestSha256": manifest_digest, "ociConfigSha256": config_digest,
            "workerSha256": checksum(checked_file(directory / WORKER, MAX_WORKER)),
            "requirementsSha256": sha256(checked_file(requirements, MAX_METADATA).read_bytes()).hexdigest()}


def config_for(directory, manifest, account):
    require(isinstance(account, str) and re.fullmatch(r"[0-9a-f]{32}", account))
    digest = manifest["ociManifestSha256"]
    require(HEX.fullmatch(digest) and manifest["service"] == SERVICE and REVISION.fullmatch(manifest["revision"]))
    return {
        "name": SERVICE, "account_id": account, "main": str((directory / WORKER).resolve()), "no_bundle": True,
        "compatibility_date": COMPATIBILITY, "workers_dev": False, "preview_urls": False, "logpush": False,
        "observability": {"enabled": False, "logs": {"enabled": False, "invocation_logs": False}, "traces": {"enabled": False}},
        "vars": {"BUILD_REVISION": manifest["revision"]},
        "durable_objects": {"bindings": [{"name": "PROVIDER_CONTAINER", "class_name": "ProviderContainer"}]},
        "exports": {"ProviderContainer": {"type": "durable-object", "storage": "sqlite"}},
        "containers": [{"class_name": "ProviderContainer", "scheduling_policy": "durable_object",
                        "images": {"provider": {"image": f"registry.cloudflare.com/{account}/{SERVICE}@sha256:{digest}"}},
                        "observability": {"logs": {"enabled": False}}}],
        "workflows": [{"name": SERVICE + "-smoke", "binding": "PROVIDER_SMOKE", "class_name": "ProviderSmoke"}],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("pack", "config"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("revision")
    parser.add_argument("--account-id")
    args = parser.parse_args()
    try:
        requirements = Path(__file__).with_name("requirements.txt")
        manifest = release_manifest(args.directory, args.revision, requirements)
        if args.action == "pack":
            require(args.account_id is None)
            with (args.directory / MANIFEST).open("x", encoding="ascii") as file:
                json.dump(manifest, file, sort_keys=True)
        else:
            recorded = json.loads(checked_file(args.directory / MANIFEST, MAX_METADATA).read_bytes())
            require(recorded == manifest)
            print(json.dumps(config_for(args.directory, manifest, args.account_id), indent=2))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, tarfile.TarError):
        parser.exit(1, "The exact provider release artifact or private configuration could not be verified.\n")


if __name__ == "__main__":
    main()

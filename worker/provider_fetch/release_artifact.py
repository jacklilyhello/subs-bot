"""Verify the exact OCI and Worker bytes and render a private deployment config."""

import argparse
import gzip
from hashlib import file_digest, sha256
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import zlib


SERVICE = "subs-bot-provider-fetch-dev-01"
COMPATIBILITY = "2026-11-06"
LOOPBACK_FLAG = "enable_ctx_exports"
MANIFEST = "provider-release.json"
IMAGE = "provider-image.tar"
WORKER = "provider-worker.js"
HEX = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
GIT_REF = re.compile(r"refs/(?:heads/[^\x00-\x20\x7f]{1,200}|pull/[1-9][0-9]{0,19}/merge)")
OCI_INDEX = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
OCI_CONFIG = "application/vnd.oci.image.config.v1+json"
OCI_LAYER = "application/vnd.oci.image.layer.v1.tar"
OCI_GZIP_LAYER = OCI_LAYER + "+gzip"
BASE_ENV = {"PATH", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"}
MAX_IMAGE = 256 * 1024 * 1024
MAX_WORKER = 1024 * 1024
MAX_METADATA = 64 * 1024
MAX_LAYER_EXPANSION = 1024 * 1024 * 1024
READ_BYTES = 1024 * 1024
VERIFICATION_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError, tarfile.TarError,
                       EOFError, zlib.error)


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


def json_object(file):
    def unique(pairs):
        value = dict(pairs)
        require(len(value) == len(pairs))
        return value

    def invalid_constant(_):
        raise ValueError("Invalid JSON constant.")

    data = file.read(MAX_METADATA + 1)
    require(0 < len(data) <= MAX_METADATA)
    value = json.loads(data.decode("utf-8"), object_pairs_hook=unique, parse_constant=invalid_constant)
    require(isinstance(value, dict))
    return value


def layer_diff_id(archive, member, media_type, budget):
    with archive.extractfile(member) as raw:
        stream = gzip.GzipFile(fileobj=raw) if media_type == OCI_GZIP_LAYER else raw
        with stream:
            digest = sha256()
            size = 0
            while chunk := stream.read(min(READ_BYTES, budget + 1 - size)):
                size += len(chunk)
                require(size <= budget)
                digest.update(chunk)
    require(size > 0)
    return "sha256:" + digest.hexdigest(), size


def verify_image(path, revision):
    with tarfile.open(checked_file(path, MAX_IMAGE), mode="r:") as archive:
        members = {}
        seen = set()
        for index, member in enumerate(archive):
            require(index < 34)
            name = member.name.removeprefix("./")
            require(name not in seen)
            seen.add(name)
            if member.isdir() and name in {"", ".", "blobs", "blobs/sha256"}:
                require(member.size == 0)
                continue
            require(len(members) < 30 and member.type in {tarfile.REGTYPE, tarfile.AREGTYPE} and not member.issparse()
                    and 0 < member.size <= MAX_IMAGE
                    and (name in {"oci-layout", "index.json"} or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)))
            members[name] = member

        def metadata(name):
            member = members[name]
            require(0 < member.size <= MAX_METADATA)
            with archive.extractfile(member) as file:
                return json_object(file)

        referenced = {"oci-layout", "index.json"}

        def blob(descriptor, media_types, *, allow_platform=False):
            allowed = {"mediaType", "digest", "size", "annotations"}
            if allow_platform:
                allowed.add("platform")
            require(isinstance(descriptor, dict) and set(descriptor) <= allowed
                    and descriptor.get("mediaType") in media_types)
            annotations = descriptor.get("annotations", {})
            require(isinstance(annotations, dict) and all(isinstance(value, str) for value in annotations.values()))
            if "platform" in descriptor:
                require(descriptor["platform"] == {"architecture": "amd64", "os": "linux"})
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
        require(set(index) <= {"schemaVersion", "mediaType", "manifests", "annotations"}
                and index["schemaVersion"] == 2 and index.get("mediaType", OCI_INDEX) == OCI_INDEX
                and isinstance(manifests, list) and len(manifests) == 1)
        manifest_name, manifest_digest = blob(manifests[0], {OCI_MANIFEST}, allow_platform=True)
        manifest = metadata(manifest_name)
        layers = manifest["layers"]
        require(set(manifest) <= {"schemaVersion", "mediaType", "config", "layers", "annotations"}
                and manifest["schemaVersion"] == 2 and manifest.get("mediaType", OCI_MANIFEST) == OCI_MANIFEST
                and isinstance(layers, list) and 0 < len(layers) <= 20)
        config_name, config_digest = blob(manifest["config"], {OCI_CONFIG})
        config = metadata(config_name)
        rootfs = config["rootfs"]
        diff_ids = rootfs["diff_ids"]
        require(rootfs["type"] == "layers" and isinstance(diff_ids, list) and len(diff_ids) == len(layers))
        expanded = 0
        for layer, expected in zip(layers, diff_ids, strict=True):
            layer_name, _ = blob(layer, {OCI_LAYER, OCI_GZIP_LAYER})
            actual, size = layer_diff_id(archive, members[layer_name], layer["mediaType"], MAX_LAYER_EXPANSION - expanded)
            require(actual == expected)
            expanded += size
        require(set(members) == referenced and config["architecture"] == "amd64" and config["os"] == "linux")
        runtime = config["config"]
        env = runtime["Env"]
        require(runtime["User"] == "65532:65532" and runtime["Entrypoint"] == ["python", "-B", "-E", "-s", "/app/server.py"]
                and runtime["WorkingDir"] == "/app" and runtime["Labels"]["org.opencontainers.image.revision"] == revision
                and runtime["ExposedPorts"] == {"8080/tcp": {}} and not runtime.get("Volumes")
                and isinstance(env, list) and len(env) <= len(BASE_ENV)
                and all(isinstance(item, str) and "=" in item and item.partition("=")[0] in BASE_ENV for item in env)
                and len({item.partition("=")[0] for item in env}) == len(env))
    return manifest_digest, config_digest


def release_manifest(directory, revision, requirements, *, ref, run_id, run_attempt):
    require(isinstance(revision, str) and REVISION.fullmatch(revision))
    require(isinstance(ref, str) and GIT_REF.fullmatch(ref) and isinstance(run_id, str) and DECIMAL.fullmatch(run_id)
            and isinstance(run_attempt, str) and DECIMAL.fullmatch(run_attempt))
    image = directory / IMAGE
    manifest_digest, config_digest = verify_image(image, revision)
    return {"version": 2, "service": SERVICE, "ref": ref, "runId": run_id, "runAttempt": run_attempt,
            "revision": revision, "compatibilityDate": COMPATIBILITY,
            "ociArchiveSha256": checksum(image), "ociManifestSha256": manifest_digest, "ociConfigSha256": config_digest,
            "workerSha256": checksum(checked_file(directory / WORKER, MAX_WORKER)),
            "requirementsSha256": sha256(checked_file(requirements, MAX_METADATA).read_bytes()).hexdigest()}


def verify_release(directory, revision, *, ref, run_id, run_attempt):
    requirements = Path(__file__).with_name("requirements.txt")
    with checked_file(directory / MANIFEST, MAX_METADATA).open("rb") as file:
        recorded = json_object(file)
    require(type(recorded.get("version")) is int and recorded["version"] == 2
            and (recorded.get("ref"), recorded.get("runId"), recorded.get("runAttempt"), recorded.get("revision"))
            == (ref, run_id, run_attempt, revision))
    manifest = release_manifest(directory, revision, requirements, ref=ref, run_id=run_id, run_attempt=run_attempt)
    require(recorded == manifest)
    return manifest


def config_for(directory, manifest, account):
    require(isinstance(account, str) and re.fullmatch(r"[0-9a-f]{32}", account))
    digest = manifest["ociManifestSha256"]
    require(HEX.fullmatch(digest) and manifest["service"] == SERVICE and REVISION.fullmatch(manifest["revision"]))
    return {
        "name": SERVICE, "account_id": account, "main": str((directory / WORKER).resolve()), "no_bundle": True,
        "compatibility_date": COMPATIBILITY, "compatibility_flags": [LOOPBACK_FLAG],
        "workers_dev": False, "preview_urls": False, "logpush": False,
        "observability": {"enabled": False, "logs": {"enabled": False, "invocation_logs": False}, "traces": {"enabled": False}},
        "vars": {"BUILD_REVISION": manifest["revision"]},
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
    parser.add_argument("--ref", default=os.environ.get("GITHUB_REF"))
    parser.add_argument("--run-id", default=os.environ.get("GITHUB_RUN_ID"))
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT"))
    args = parser.parse_args()
    try:
        provenance = {"ref": args.ref, "run_id": args.run_id, "run_attempt": args.run_attempt}
        if args.action == "pack":
            require(args.account_id is None)
            requirements = Path(__file__).with_name("requirements.txt")
            manifest = release_manifest(args.directory, args.revision, requirements, **provenance)
            fd = os.open(args.directory / MANIFEST, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as file:
                json.dump(manifest, file, sort_keys=True)
        else:
            manifest = verify_release(args.directory, args.revision, **provenance)
            print(json.dumps(config_for(args.directory, manifest, args.account_id), indent=2))
    except VERIFICATION_ERRORS:
        parser.exit(1, "The exact provider release artifact or private configuration could not be verified.\n")


if __name__ == "__main__":
    main()

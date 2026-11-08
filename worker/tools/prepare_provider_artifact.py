"""Verify the exact main-branch Provider Fetch CI artifact without deploying it."""

import hashlib
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
from time import monotonic
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
import zlib

import prepare_isolation_artifact as github

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "provider_fetch"))
import release_artifact as provider


WORKFLOW_ID = 409913800
WORKFLOW_PATH = ".github/workflows/worker-provider-fetch-ci.yml"
VERIFIED_DIRECTORY = "subs-bot-provider-verified"
API_STATUS_VERIFIED_DIRECTORY = "subs-bot-provider-api-status-v2-verified"
FILE_LIMITS = {provider.MANIFEST: provider.MAX_METADATA, provider.WORKER: provider.MAX_WORKER,
               provider.IMAGE: provider.MAX_IMAGE}
MAX_ZIP = sum(FILE_LIMITS.values()) + 1024 * 1024
MAX_ZIP_DIRECTORY = 16 * 1024
ZIP_END = struct.Struct("<4s4H2IH")
COPY_CHUNK = 1024 * 1024
STORAGE_TIMEOUT_SECONDS = 120
STORAGE_OPENER = build_opener(ProxyHandler({}), github._NoRedirect())


def _select_artifact(run_id, revision, token, *, profile=provider.FETCH_PROFILE):
    if profile == provider.FETCH_PROFILE:
        prefix, label = "subs-bot-provider", "Provider Fetch CI"
    elif profile == provider.API_STATUS_PROFILE:
        prefix, label = "subs-bot-provider-api-status-v2", "Provider API Status CI"
    else:
        raise github.ArtifactError("Unknown provider release profile.")
    return github.select_main_artifact(run_id, revision, token, workflow_id=WORKFLOW_ID, workflow_path=WORKFLOW_PATH,
                                       artifact_prefix=prefix, workflow_label=label)


def _write_private(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def _download_zip(artifact_id, token, expected_digest, path):
    error = "Could not download the verified provider archive."
    try:
        request = github.artifact_storage_request(artifact_id, token)
        deadline = monotonic() + STORAGE_TIMEOUT_SECONDS
        with STORAGE_OPENER.open(request, timeout=15) as response, _write_private(path) as output:
            length = response.headers.get("Content-Length")
            if (response.status != 200 or response.headers.get("Content-Encoding", "identity").lower() != "identity"
                    or (length is not None and (not re.fullmatch(r"[1-9][0-9]{0,9}", length) or int(length) > MAX_ZIP))):
                raise github.ArtifactError(error)
            digest = hashlib.sha256()
            total = 0
            while monotonic() < deadline:
                chunk = response.read1(min(COPY_CHUNK, MAX_ZIP + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ZIP:
                    raise github.ArtifactError(error)
                digest.update(chunk)
                output.write(chunk)
            if (monotonic() >= deadline or total == 0 or (length is not None and total != int(length))
                    or digest.hexdigest() != expected_digest):
                raise github.ArtifactError("The provider archive length or GitHub digest did not match.")
    except (OSError, URLError, HTTPException):
        raise github.ArtifactError(error) from None


def _check_central_directory(path):
    # The pinned GitHub uploader emits a single-disk ZIP with no comment. Check
    # its small directory before ZipFile allocates memory for member metadata.
    with path.open("rb") as file:
        end_offset = file.seek(-ZIP_END.size, os.SEEK_END)
        signature, disk, start_disk, disk_count, count, size, offset, comment = ZIP_END.unpack(file.read(ZIP_END.size))
    if (signature != b"PK\x05\x06" or disk or start_disk or comment or disk_count != len(FILE_LIMITS)
            or count != len(FILE_LIMITS) or not 0 < size <= MAX_ZIP_DIRECTORY or offset + size != end_offset):
        raise github.ArtifactError("The provider ZIP directory differs from the fixed artifact layout.")


def _unpack(path, staged):
    error = "The provider ZIP has an unsafe, missing, oversized, or unexpected member."
    try:
        _check_central_directory(path)
        with ZipFile(path) as archive:
            members = archive.infolist()
            if len(members) != len(FILE_LIMITS) or {entry.filename for entry in members} != set(FILE_LIMITS):
                raise github.ArtifactError(error)
            for entry in members:
                if (entry.orig_filename != entry.filename or entry.flag_bits & (1 | 64)
                        or entry.compress_type not in (ZIP_STORED, ZIP_DEFLATED)
                        or stat.S_IFMT(entry.external_attr >> 16) not in (0, stat.S_IFREG)
                        or not 0 < entry.file_size <= FILE_LIMITS[entry.filename]):
                    raise github.ArtifactError(error)
                with archive.open(entry) as source, _write_private(staged / entry.filename) as output:
                    total = 0
                    while chunk := source.read(COPY_CHUNK):
                        total += len(chunk)
                        if total > entry.file_size:
                            raise github.ArtifactError(error)
                        output.write(chunk)
                    if total != entry.file_size:
                        raise github.ArtifactError(error)
    except (BadZipFile, OSError, RuntimeError, NotImplementedError, struct.error, zlib.error):
        raise github.ArtifactError(error) from None


def prepare(*, provider_revision=None, profile=provider.FETCH_PROFILE):
    main_revision = os.environ.get("GITHUB_SHA", "")
    revision = provider_revision if provider_revision is not None else main_revision
    run_id = os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID", "")
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    if (os.environ.get("GITHUB_REF") != github.MAIN_REF or not provider.DECIMAL.fullmatch(run_id)
            or not Path(runner_temp).is_absolute()):
        raise github.ArtifactError("Provider artifact verification requires main, a CI run ID and runner temporary storage.")
    if profile == provider.API_STATUS_PROFILE:
        if revision != main_revision:
            raise github.ArtifactError("API status artifact verification requires the exact current main revision.")
        directory_name = API_STATUS_VERIFIED_DIRECTORY
    elif profile == provider.FETCH_PROFILE:
        directory_name = VERIFIED_DIRECTORY
    else:
        raise github.ArtifactError("Unknown provider release profile.")
    token = github._github_token()
    github.require_current_main(main_revision)
    attempt, artifact_id, digest = _select_artifact(run_id, revision, token, profile=profile)
    destination = Path(runner_temp) / directory_name
    if os.path.lexists(destination):
        raise github.ArtifactError("The verified provider artifact directory already exists.")
    with tempfile.TemporaryDirectory(prefix=".subs-bot-provider-", dir=runner_temp) as directory:
        scratch = Path(directory)
        archive = scratch / "download.zip"
        staged = scratch / "verified"
        staged.mkdir(mode=0o700)
        _download_zip(artifact_id, token, digest, archive)
        _unpack(archive, staged)
        try:
            manifest = provider.verify_release(staged, revision, ref=github.MAIN_REF, run_id=run_id, run_attempt=attempt,
                                               profile=profile)
        except provider.VERIFICATION_ERRORS:
            raise github.ArtifactError("The provider release manifest or its exact contents did not verify.") from None
        if _select_artifact(run_id, revision, token, profile=profile) != (attempt, artifact_id, digest):
            raise github.ArtifactError("The trusted provider build artifact changed during verification.")
        github.require_current_main(main_revision)
        if os.path.lexists(destination):
            raise github.ArtifactError("The verified provider artifact directory already exists.")
        staged.rename(destination)
    evidence = {"revision": revision, "runId": run_id, "runAttempt": attempt, "artifactId": artifact_id,
                "archiveSha256": digest, "compatibilityDate": manifest["compatibilityDate"],
                "workerSha256": manifest["workerSha256"], "ociArchiveSha256": manifest["ociArchiveSha256"],
                "ociManifestSha256": manifest["ociManifestSha256"], "ociConfigSha256": manifest["ociConfigSha256"]}
    if profile == provider.API_STATUS_PROFILE:
        evidence.update({key: manifest[key] for key in ("profile", "service", "rpcEntrypoint")})
    return evidence


if __name__ == "__main__":
    try:
        print(json.dumps(prepare()))
    except github.ArtifactError as exc:
        raise SystemExit(str(exc)) from None
    except (OSError, ValueError):
        raise SystemExit("Provider artifact verification could not be completed safely.") from None

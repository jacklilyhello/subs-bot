"""Authenticate one failed hosted capacity run and its private recovery ledger."""

import argparse
from hashlib import sha256
from io import BytesIO
from http.client import HTTPException
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.error import URLError
from urllib.parse import urlencode
from zipfile import BadZipFile, ZipFile
import zlib

import capacity_resources as capacity
import prepare_isolation_artifact as github


WORKFLOW_ID = 409801587
WORKFLOW_PATH = ".github/workflows/worker-isolation-capacity.yml"
RECOVERY_UPLOAD = "Run actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
REQUIRED_STEPS = (
    ("Generate the bounded synthetic capacity fixtures", "success"),
    ("Verify the active isolation Worker before staging", "success"),
    ("Seed only the recorded isolated D1 and private R2", "success"),
    ("Check live boundaries, digest and bounded concurrency", "success"),
    ("Verify the active isolation Worker after probing", "success"),
    ("Retire the recorded synthetic capabilities and objects", "failure"),
)
MAX_ARCHIVE_BYTES = 128 * 1024
ERROR = "The historical capacity recovery checkpoint could not be authenticated."


def require(condition):
    if not condition:
        raise github.ArtifactError(ERROR)


def _decimal(value):
    return type(value) is int and github._DECIMAL.fullmatch(str(value)) is not None


def _trusted_repository(repo):
    return isinstance(repo, dict) and (repo.get("id"), repo.get("full_name")) == (github.REPOSITORY_ID, github.REPOSITORY)


def _verify_attempt(run_path, run_id, attempt, revision, token):
    run = github._get_json(run_path, token)
    require(_decimal(run.get("id")) and str(run["id"]) == run_id and run.get("workflow_id") == WORKFLOW_ID
            and run.get("path") in (WORKFLOW_PATH, f"{WORKFLOW_PATH}@main", f"{WORKFLOW_PATH}@{github.MAIN_REF}")
            and (run.get("event"), run.get("status"), run.get("conclusion")) == ("workflow_dispatch", "completed", "failure")
            and (run.get("head_branch"), run.get("head_sha")) == ("main", revision)
            and _decimal(run.get("run_attempt")) and str(run["run_attempt"]) == attempt
            and _trusted_repository(run.get("repository")) and _trusted_repository(run.get("head_repository")))
    listing = github._get_json(run_path + "/jobs?per_page=2", token)
    jobs = listing.get("jobs")
    require(listing.get("total_count") == 1 and isinstance(jobs, list) and len(jobs) == 1)
    job = jobs[0]
    require(isinstance(job, dict) and (job.get("name"), job.get("status"), job.get("conclusion"))
            == ("measure", "completed", "failure")
            and _decimal(job.get("run_id")) and str(job["run_id"]) == run_id
            and _decimal(job.get("run_attempt")) and str(job["run_attempt"]) == attempt
            and job.get("head_sha") == revision)
    steps = job.get("steps")
    require(isinstance(steps, list) and 7 <= len(steps) <= 64
            and all(isinstance(step, dict) and _decimal(step.get("number")) for step in steps))
    require(len({step["number"] for step in steps}) == len(steps))
    previous = 0
    for name, conclusion in REQUIRED_STEPS:
        matching = [step for step in steps if step.get("name") == name]
        require(len(matching) == 1)
        step = matching[0]
        require(step["number"] > previous and (step.get("status"), step.get("conclusion")) == ("completed", conclusion))
        previous = step["number"]
    # The earlier checkpoint uses the same action. Only the upload after failed cleanup is recovery evidence.
    recovery = [step for step in steps if step.get("name") == RECOVERY_UPLOAD and step["number"] > previous]
    require(len(recovery) == 1 and (recovery[0].get("status"), recovery[0].get("conclusion")) == ("completed", "success"))


def _select(run_id, attempt, revision, archive_sha, token):
    run_path = f"/actions/runs/{run_id}"
    _verify_attempt(f"{run_path}/attempts/{attempt}", run_id, attempt, revision, token)
    name = f"isolation-capacity-recovery-{run_id}-{attempt}"
    query = urlencode({"name": name, "per_page": 2})
    listing = github._get_json(f"{run_path}/artifacts?{query}", token)
    artifacts = listing.get("artifacts")
    require(listing.get("total_count") == 1 and isinstance(artifacts, list) and len(artifacts) == 1)
    artifact = artifacts[0]
    require(isinstance(artifact, dict) and artifact.get("name") == name and artifact.get("expired") is False
            and _decimal(artifact.get("id")) and artifact.get("digest") == "sha256:" + archive_sha)
    origin = artifact.get("workflow_run")
    require(isinstance(origin, dict) and _decimal(origin.get("id")) and str(origin["id"]) == run_id
            and (origin.get("repository_id"), origin.get("head_repository_id"), origin.get("head_branch"), origin.get("head_sha"))
            == (github.REPOSITORY_ID, github.REPOSITORY_ID, "main", revision))
    return str(artifact["id"])


def _download(artifact_id, token):
    request = github.artifact_storage_request(artifact_id, token)
    with github._OPENER.open(request, timeout=30) as response:
        require(response.status == 200 and response.headers.get("Content-Encoding", "identity").lower() == "identity")
        return github._bounded_read(response, MAX_ARCHIVE_BYTES)


def _ledger_body(archive, archive_sha, revision, run_id):
    require(0 < len(archive) <= MAX_ARCHIVE_BYTES and sha256(archive).hexdigest() == archive_sha)
    with ZipFile(BytesIO(archive)) as zipped:
        members = github._zip_members(zipped)
        require(len(zipped.infolist()) == 1 and set(members) == {capacity.LEDGER_FILE})
        member = members[capacity.LEDGER_FILE]
        require(0 < member.file_size <= capacity.MAX_JSON and not member.flag_bits & 64)
        with zipped.open(member) as stream:
            body = github._bounded_read(stream, capacity.MAX_JSON)
        require(len(body) == member.file_size)
    ledger = github._parse_object(body, ERROR)
    require(type(ledger.get("version")) is int and ledger["version"] == 1
            and (ledger.get("revision"), ledger.get("runId"), ledger.get("phase")) == (revision, run_id, "cleanup")
            and capacity.matches(capacity.DIGEST, ledger.get("scopeSha256")))
    return body, ledger


def prepare(directory, run_id, attempt, revision, archive_sha):
    """Authenticate before making a new owner-only output directory."""
    try:
        require(github._DECIMAL.fullmatch(run_id) and github._DECIMAL.fullmatch(attempt)
                and github._REVISION.fullmatch(revision) and github._SHA256.fullmatch(archive_sha)
                and not os.path.lexists(directory))
        token = github._github_token()
        artifact_id = _select(run_id, attempt, revision, archive_sha, token)
        body, ledger = _ledger_body(_download(artifact_id, token), archive_sha, revision, run_id)
        require(_select(run_id, attempt, revision, archive_sha, token) == artifact_id)
        with TemporaryDirectory(prefix=".capacity-recovery-", dir=directory.parent) as temporary:
            private = Path(temporary)
            staged = private / capacity.LEDGER_FILE
            fd = os.open(staged, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as file:
                file.write(body)
            require(capacity.load_ledger(private, ledger["scopeSha256"]) == ledger)
            directory.mkdir(mode=0o700)
            try:
                staged.rename(directory / capacity.LEDGER_FILE)
            except OSError:
                directory.rmdir()
                raise
    except (ValueError, OSError, HTTPException, URLError, RuntimeError, BadZipFile, TypeError, KeyError, AttributeError,
            NotImplementedError, EOFError, zlib.error):
        raise github.ArtifactError(ERROR) from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("source_run_id")
    parser.add_argument("source_attempt")
    parser.add_argument("source_revision")
    parser.add_argument("source_archive_sha256")
    args = parser.parse_args()
    try:
        prepare(args.output_dir, args.source_run_id, args.source_attempt, args.source_revision, args.source_archive_sha256)
    except github.ArtifactError as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()

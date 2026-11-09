"""Verify and unpack the exact main-branch Worker CI artifact for isolation deployment."""

import hashlib
from http.client import HTTPException
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile
import zlib

from cloudflare_isolation import MAX_MODULE_BYTES


REPOSITORY = "jacklilyhello/subs-bot"
REPOSITORY_ID = 1441743951
WORKFLOW_ID = 409652814
WORKFLOW_PATH = ".github/workflows/worker-ci.yml"
MAIN_REF = "refs/heads/main"
API_ROOT = f"https://api.github.com/repos/{REPOSITORY}"
VERIFIED_DIRECTORY = "subs-bot-verified"

_REVISION = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")
_DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
_MIGRATION = re.compile(r"[0-9]{4}_[a-z][a-z0-9_]*\.sql")
_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_TOKEN = re.compile(r"subsbot-synthetic-[a-z0-9-]{1,100}")
_MAX_JSON = 1024 * 1024
_MAX_ZIP = 16 * 1024 * 1024
_MAX_EXPANDED = 64 * 1024 * 1024
_MAX_ENTRIES = 1024


class ArtifactError(ValueError):
    """A release input failed verification. Messages must omit untrusted values."""


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = build_opener(_NoRedirect())


def _github_token():
    token = os.environ.get("GH_TOKEN", "")
    if os.environ.get("GITHUB_REPOSITORY") != REPOSITORY or not re.fullmatch(r"[!-~]{1,4096}", token):
        raise ArtifactError("The trusted repository and a GitHub read token are required.")
    return token


def _api_request(path, token):
    return Request(API_ROOT + path, headers={
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "Cache-Control": "no-cache",
        "X-GitHub-Api-Version": "2022-11-28",
    })


def _bounded_read(response, limit):
    body = response.read(limit + 1)
    if len(body) > limit:
        raise ArtifactError("A release response exceeded its size limit.")
    return body


def _unique_json_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("Duplicate JSON keys")
    return result


def _parse_object(body, error):
    try:
        value = json.loads(body, object_pairs_hook=_unique_json_object)
    except (ValueError, RecursionError):
        raise ArtifactError(error) from None
    if not isinstance(value, dict):
        raise ArtifactError(error)
    return value


def _get_json(path, token):
    error = "Could not read trusted GitHub release metadata."
    try:
        with _OPENER.open(_api_request(path, token), timeout=20) as response:
            return _parse_object(_bounded_read(response, _MAX_JSON), error)
    except (URLError, OSError, HTTPException):
        raise ArtifactError(error) from None


def require_current_main(revision: str) -> None:
    """Raise ArtifactError unless the exact revision is the current GitHub main tip."""
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise ArtifactError("A full Git revision is required.")
    ref = _get_json("/git/ref/heads/main", _github_token())
    commit = ref.get("object")
    if ref.get("ref") != MAIN_REF or not isinstance(commit, dict) or (
        commit.get("type"), commit.get("sha")
    ) != ("commit", revision):
        raise ArtifactError("The requested revision is no longer current on main.")


def select_main_artifact(run_id, revision, token, *, workflow_id, workflow_path, artifact_prefix, workflow_label,
                         events=("push", "workflow_dispatch")):
    run = _get_json(f"/actions/runs/{run_id}", token)
    repositories = (run.get("repository"), run.get("head_repository"))
    attempt = run.get("run_attempt")
    if (
        str(run.get("id")) != run_id
        or run.get("workflow_id") != workflow_id
        or run.get("path") not in (workflow_path, f"{workflow_path}@main", f"{workflow_path}@{MAIN_REF}")
        or run.get("event") not in events
        or (run.get("status"), run.get("conclusion")) != ("completed", "success")
        or (run.get("head_branch"), run.get("head_sha")) != ("main", revision)
        or any(not isinstance(repo, dict) or repo.get("id") != REPOSITORY_ID for repo in repositories)
        or type(attempt) is not int or not _DECIMAL.fullmatch(str(attempt))
    ):
        raise ArtifactError(f"The selected run is not a successful {workflow_label} build of current main.")
    name = f"{artifact_prefix}-{revision}-{attempt}"
    query = urlencode({"name": name, "per_page": 2})
    listing = _get_json(f"/actions/runs/{run_id}/artifacts?{query}", token)
    artifacts = listing.get("artifacts")
    if listing.get("total_count") != 1 or not isinstance(artifacts, list) or len(artifacts) != 1:
        raise ArtifactError("The selected build must have exactly one matching artifact.")
    artifact = artifacts[0]
    if not isinstance(artifact, dict):
        raise ArtifactError("The selected artifact has invalid provenance or digest.")
    artifact_id = artifact.get("id")
    digest = artifact.get("digest")
    source = artifact.get("workflow_run")
    if (
        artifact.get("name") != name or artifact.get("expired") is not False
        or type(artifact_id) is not int or not _DECIMAL.fullmatch(str(artifact_id))
        or not isinstance(digest, str) or not digest.startswith("sha256:") or not _SHA256.fullmatch(digest[7:])
        or not isinstance(source, dict) or str(source.get("id")) != run_id
        or (source.get("repository_id"), source.get("head_repository_id")) != (REPOSITORY_ID, REPOSITORY_ID)
        or (source.get("head_branch"), source.get("head_sha")) != ("main", revision)
    ):
        raise ArtifactError("The selected artifact has invalid provenance or digest.")
    return str(attempt), str(artifact_id), digest[7:]


def _select_artifact(run_id, revision, token):
    return select_main_artifact(run_id, revision, token, workflow_id=WORKFLOW_ID, workflow_path=WORKFLOW_PATH,
                                artifact_prefix="subs-bot-worker", workflow_label="Worker CI")


def artifact_storage_request(artifact_id, token):
    error = "Could not download the selected GitHub artifact."
    try:
        with _OPENER.open(_api_request(f"/actions/artifacts/{artifact_id}/zip", token), timeout=20):
            raise ArtifactError(error)
    except HTTPError as exc:
        with exc:
            location = exc.headers.get("Location", "") if exc.code == 302 else ""
    except (URLError, OSError, HTTPException):
        raise ArtifactError(error) from None
    try:
        if not re.fullmatch(r"[!-~]{1,8192}", location) or "\\" in location:
            raise ArtifactError(error)
        url = urlsplit(location)
        if (url.scheme != "https" or not url.hostname or url.username is not None
                or url.password is not None or url.fragment or url.port not in (None, 443)):
            raise ArtifactError(error)
        # Construct a fresh request with no GitHub headers. Signed storage URLs must stay private.
        return Request(location, headers={"Accept-Encoding": "identity"})
    except ValueError:
        raise ArtifactError(error) from None


def _download(artifact_id, token):
    try:
        with _OPENER.open(artifact_storage_request(artifact_id, token), timeout=60) as response:
            return _bounded_read(response, _MAX_ZIP)
    except (URLError, OSError, HTTPException):
        raise ArtifactError("Could not download the selected GitHub artifact.") from None


def _sha256(body):
    return hashlib.sha256(body).hexdigest()


def _zip_members(archive):
    members = {}
    directories = set()
    expanded = 0
    entries = archive.infolist()
    if len(entries) > _MAX_ENTRIES:
        raise ArtifactError("The release archive has too many entries.")
    for entry in entries:
        name = entry.filename
        directory = entry.is_dir()
        path = name.removesuffix("/")
        mode = stat.S_IFMT(entry.external_attr >> 16)
        if (
            name != entry.orig_filename or "\\" in path
            or any(part in ("", ".", "..") for part in path.split("/"))
            or path in members or path in directories
            or entry.flag_bits & 1 or entry.compress_type not in (ZIP_STORED, ZIP_DEFLATED)
            or (directory and (mode not in (0, stat.S_IFDIR) or entry.file_size != 0))
            or (not directory and mode not in (0, stat.S_IFREG))
        ):
            raise ArtifactError("The release archive has an unsafe or duplicate entry.")
        if directory:
            directories.add(path)
            continue
        expanded += entry.file_size
        if expanded > _MAX_EXPANDED:
            raise ArtifactError("The unpacked release archive exceeds its size limit.")
        members[path] = entry
    allowed_directories = {
        str(parent) for name in members for parent in Path(name).parents if parent != Path(".")
    }
    if directories - allowed_directories or set(members) & allowed_directories:
        raise ArtifactError("The release archive has unexpected directories.")
    return members


def _expected_hashes(manifest, revision, run_id, attempt):
    error = "The release manifest has invalid provenance or file metadata."
    if (
        type(manifest.get("version")) is not int or manifest["version"] != 2 or manifest.get("ref") != MAIN_REF
        or (manifest.get("revision"), manifest.get("runId"), manifest.get("runAttempt")) != (revision, run_id, attempt)
        or not isinstance(manifest.get("compatibilityDate"), str)
        or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", manifest["compatibilityDate"])
    ):
        raise ArtifactError(error)
    hashes = {}

    def register(name, digest):
        if name in hashes or not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ArtifactError(error)
        hashes[name] = digest

    register("index.js", manifest.get("bundleSha256"))
    migrations = manifest.get("migrations")
    if not isinstance(migrations, list) or not migrations or len(migrations) > 100:
        raise ArtifactError(error)
    for ordinal, migration in enumerate(migrations, 1):
        name = migration.get("name") if isinstance(migration, dict) else None
        if (
            not isinstance(name, str) or not _MIGRATION.fullmatch(name) or int(name[:4]) != ordinal
            or (ordinal == 1 and name != "0001_subscriptions.sql")
        ):
            raise ArtifactError(error)
        register(name, migration.get("sha256"))

    snapshots = manifest.get("snapshots")
    if not isinstance(snapshots, list) or not snapshots:
        raise ArtifactError(error)
    sizes = {}
    for snapshot in snapshots:
        if not isinstance(snapshot, dict):
            raise ArtifactError(error)
        snapshot_id, token, numeric_id = snapshot.get("snapshotId"), snapshot.get("token"), snapshot.get("id")
        if (
            type(numeric_id) is not int or not 1 <= numeric_id <= 9007199254740991
            or not isinstance(snapshot_id, str) or not _UUID.fullmatch(snapshot_id)
            or not isinstance(token, str) or not _TOKEN.fullmatch(token)
            or not isinstance(snapshot.get("bodySha256"), str) or not _SHA256.fullmatch(snapshot["bodySha256"])
            or any(type(snapshot.get(key)) is not int or snapshot[key] <= 0
                   for key in ("nodeCount", "nodeBytes", "bodyBytes"))
        ):
            raise ArtifactError(error)
        prefix = f"subscriptions/{numeric_id}/{snapshot_id}/"
        objects = snapshot.get("objects")
        if not isinstance(objects, list) or not 2 <= len(objects) <= 257:
            raise ArtifactError(error)
        chunk_bytes = 0
        for index, entry in enumerate(objects):
            is_manifest = index == len(objects) - 1
            key = prefix + ("manifest.json" if is_manifest else f"{index}.ndjson")
            name = f"r2/{key}"
            limit = 64 * 1024 if is_manifest else 512 * 1024
            if (
                not isinstance(entry, dict) or (entry.get("key"), entry.get("file")) != (key, name)
                or type(entry.get("bytes")) is not int or not 1 <= entry["bytes"] <= limit
                or (is_manifest and entry.get("sha256") != snapshot.get("manifestSha256"))
            ):
                raise ArtifactError(error)
            register(name, entry.get("sha256"))
            sizes[name] = entry["bytes"]
            if not is_manifest:
                chunk_bytes += entry["bytes"]
        if chunk_bytes != snapshot["nodeBytes"]:
            raise ArtifactError(error)
    return hashes, sizes


def _unpack(archive_body, digest, revision, run_id, attempt, runner_temp):
    if _sha256(archive_body) != digest:
        raise ArtifactError("The downloaded archive does not match the GitHub artifact digest.")
    destination = runner_temp / VERIFIED_DIRECTORY
    if os.path.lexists(destination):
        raise ArtifactError("The verified artifact directory already exists.")
    staged = Path(tempfile.mkdtemp(prefix=".subs-bot-verify-", dir=runner_temp))
    try:
        with ZipFile(io.BytesIO(archive_body)) as archive:
            members = _zip_members(archive)
            manifest_member = members.get("isolation.json")
            if manifest_member is None or manifest_member.file_size > _MAX_JSON:
                raise ArtifactError("The archive is missing a bounded release manifest.")
            manifest_body = archive.read(manifest_member)
            manifest = _parse_object(manifest_body, "The release manifest is not valid JSON.")
            hashes, sizes = _expected_hashes(manifest, revision, run_id, attempt)
            if set(members) != set(hashes) | {"isolation.json"}:
                raise ArtifactError("The release archive contains missing or unexpected files.")
            if not 0 < members["index.js"].file_size <= MAX_MODULE_BYTES:
                raise ArtifactError("The verified Worker module is empty or exceeds the isolation size limit.")
            for name, member in members.items():
                body = manifest_body if name == "isolation.json" else archive.read(member)
                if (name in hashes and _sha256(body) != hashes[name]) or (name in sizes and len(body) != sizes[name]):
                    raise ArtifactError("A release file does not match its manifest digest or length.")
                relative = Path(name)
                for parent in reversed(relative.parents):
                    (staged / parent).mkdir(mode=0o700, exist_ok=True)
                target = staged / relative
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "wb") as output:
                    output.write(body)
        staged.rename(destination)
    except (BadZipFile, OSError, RuntimeError, NotImplementedError, zlib.error):
        raise ArtifactError("The verified archive could not be extracted safely.") from None
    finally:
        if staged.exists():
            shutil.rmtree(staged)


def prepare():
    revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_CI_RUN_ID", "")
    runner_temp = os.environ.get("RUNNER_TEMP", "")
    if os.environ.get("GITHUB_REF") != MAIN_REF or not _DECIMAL.fullmatch(run_id) or not runner_temp:
        raise ArtifactError("Deployment preparation requires main, a build run ID and runner temporary storage.")
    token = _github_token()
    require_current_main(revision)
    attempt, artifact_id, digest = _select_artifact(run_id, revision, token)
    archive_body = _download(artifact_id, token)
    if _select_artifact(run_id, revision, token) != (attempt, artifact_id, digest):
        raise ArtifactError("The trusted build artifact changed during verification.")
    require_current_main(revision)
    _unpack(archive_body, digest, revision, run_id, attempt, Path(runner_temp))
    return {
        "revision": revision,
        "runId": run_id,
        "runAttempt": attempt,
        "artifactId": artifact_id,
        "archiveSha256": digest,
    }


if __name__ == "__main__":
    try:
        print(json.dumps(prepare()))
    except ArtifactError as exc:
        raise SystemExit(str(exc)) from None
    except (OSError, ValueError):
        raise SystemExit("Artifact verification could not be completed safely.") from None

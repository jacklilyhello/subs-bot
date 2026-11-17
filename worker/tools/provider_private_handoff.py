"""Authenticated workflow provenance around age-encrypted private Provider messages.

Age provides recipient confidentiality; it does not authenticate a sender. GitHub's
immutable artifact identity and the exact protected upstream job provide provenance.
No Provider mutation is dispatched by this module.
"""

from hashlib import sha256
from http.client import HTTPException
from io import BytesIO
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from time import monotonic
import zlib
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

import production_provider as control

WORKFLOW_PATH = ".github/workflows/worker-production-provider-encrypted-rehearsal.yml"
MAX_PLAINTEXT = 256 * 1024
MAX_CIPHERTEXT = MAX_PLAINTEXT + 32 * 1024
MAX_ARTIFACT_ZIP = MAX_CIPHERTEXT + 1024 * 1024
PHASES = {"intent": ("Provider private preflight", "Upload encrypted intent"),
          "response": ("Provider private dispatch", "Upload encrypted response"),
          "completion": ("Provider private verify", "Upload encrypted completion")}


def context():
    revision = os.environ.get("GITHUB_SHA", "")
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == revision
                    and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                    and os.environ.get("GITHUB_WORKFLOW_REF") == f"{control.github.REPOSITORY}/{WORKFLOW_PATH}@{control.github.MAIN_REF}"
                    and control.match(control.provider.REVISION, revision)
                    and control.match(control.provider.DECIMAL, os.environ.get("GITHUB_RUN_ID", "")))
    control.github.require_current_main(revision)


def age_binary(name):
    control.require(name in {"age", "age-keygen"})
    root = Path(os.environ.get("RUNNER_TEMP", ""))
    control.require(root.is_absolute())
    executable = root / "provider-age" / "usr" / "bin" / name
    control.provider.checked_file(executable, 32 * 1024 * 1024)
    control.require(os.access(executable, os.X_OK))
    return executable


def recipient():
    value = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_RECIPIENT", "")
    expected = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_RECIPIENT_SHA256", "")
    control.require(re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", value) is not None
                    and control.match(control.provider.HEX, expected)
                    and sha256(value.encode("ascii")).hexdigest() == expected)
    return value


def envelope(value, phase):
    control.require(phase in PHASES and isinstance(value, dict)
                    and set(value) == {"version", "kind", "phase", "runId", "runAttempt", "controllerRevision",
                                       "operation", "target", "targetSha256", "approvalSha256", "intentSha256", "state"}
                    and type(value["version"]) is int and value["version"] == 1
                    and value["kind"] == "private-provider-encrypted-handoff" and value["phase"] == phase
                    and value["runId"] == os.environ.get("GITHUB_RUN_ID") and value["runAttempt"] == "1"
                    and value["controllerRevision"] == os.environ.get("GITHUB_SHA")
                    and value["operation"] in control.OPERATIONS - {"verify"}
                    and value["operation"] == os.environ.get("SUBS_BOT_PROVIDER_CONTROL_OPERATION")
                    and isinstance(value["state"], dict))
    target = control.validate_config(value["target"])
    control.require(target["environment"] == "rehearsal" and target["caller"] is None
                    and value["targetSha256"] == control.digest(target)
                    and value["approvalSha256"] == control.digest({"operation": value["operation"], "target": target})
                    and value["approvalSha256"] == os.environ.get("SUBS_BOT_PROVIDER_CONTROL_APPROVAL")
                    and (value["intentSha256"] is None if phase == "intent" else control.match(control.provider.HEX, value["intentSha256"])))
    control.require(len(control.canonical(value)) <= MAX_PLAINTEXT)
    return value


def encrypt(value, phase):
    context()
    raw = control.canonical(envelope(value, phase))
    result = subprocess.run([str(age_binary("age")), "--encrypt", "--recipient", recipient()], input=raw,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    control.require(result.returncode == 0 and 0 < len(result.stdout) <= MAX_CIPHERTEXT,
                    "Private Provider message encryption failed.")
    return result.stdout


def verify_artifact(phase, artifact_id, archive_sha, cipher_sha, cipher):
    """Check trusted DAG outputs, artifact metadata and bytes before decryption.

    A calling workflow MUST map these three variables directly from the named
    upstream job's `needs` outputs. User inputs or another job are not authority.
    """
    context()
    control.require(phase in PHASES and control.match(control.provider.DECIMAL, artifact_id)
                    and control.match(control.provider.HEX, archive_sha) and control.match(control.provider.HEX, cipher_sha)
                    and isinstance(cipher, bytes) and 0 < len(cipher) <= MAX_CIPHERTEXT and sha256(cipher).hexdigest() == cipher_sha
                    and os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARTIFACT_ID") == artifact_id
                    and os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_ARCHIVE_SHA256") == archive_sha
                    and os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_UPSTREAM_CIPHER_SHA256") == cipher_sha,
                    "Encrypted Provider handoff differs from the trusted upstream job outputs.")
    run_id, attempt, revision = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"], os.environ["GITHUB_SHA"]
    token = control.github._github_token()
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, token)
    origin = artifact.get("workflow_run")
    control.require(str(artifact.get("id")) == artifact_id and artifact.get("expired") is False
                    and artifact.get("name") == f"provider-encrypted-{phase}-{run_id}-{attempt}"
                    and artifact.get("digest") == "sha256:" + archive_sha and isinstance(origin, dict)
                    and str(origin.get("id")) == run_id and origin.get("head_branch") == "main"
                    and origin.get("head_sha") == revision
                    and origin.get("repository_id") == origin.get("head_repository_id") == control.github.REPOSITORY_ID)
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}", token)
    control.require(str(run.get("id")) == run_id and str(run.get("run_attempt")) == attempt
                    and run.get("path") in (WORKFLOW_PATH, WORKFLOW_PATH + "@main", WORKFLOW_PATH + "@refs/heads/main")
                    and run.get("head_sha") == revision and run.get("head_branch") == "main"
                    and run.get("event") == "workflow_dispatch"
                    and all(isinstance(run.get(key), dict) and run[key].get("id") == control.github.REPOSITORY_ID
                            for key in ("repository", "head_repository")))
    response = control.github._get_json(f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100", token)
    rows = response.get("jobs")
    control.require(isinstance(rows, list) and type(response.get("total_count")) is int
                    and response["total_count"] == len(rows) < 100)
    job_name, step_name = PHASES[phase]
    jobs = [row for row in rows if isinstance(row, dict) and row.get("name") == job_name]
    control.require(len(jobs) == 1 and str(jobs[0].get("run_id")) == run_id
                    and str(jobs[0].get("run_attempt")) == attempt and jobs[0].get("head_sha") == revision
                    and (jobs[0].get("status"), jobs[0].get("conclusion")) == ("completed", "success")
                    and isinstance(jobs[0].get("steps"), list))
    steps = [step for step in jobs[0]["steps"] if isinstance(step, dict) and step.get("name") == step_name]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    control.github.require_current_main(revision)


def download_cipher(artifact_id, archive_sha):
    """Read and hash the original immutable Actions ZIP, never trust an extracted file."""
    control.require(control.match(control.provider.DECIMAL, artifact_id) and control.match(control.provider.HEX, archive_sha))
    request = control.github.artifact_storage_request(artifact_id, control.github._github_token())
    deadline = monotonic() + 120
    raw, hashed = bytearray(), sha256()
    try:
        with control.provenance.STORAGE_OPENER.open(request, timeout=15) as response:
            control.require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
            while monotonic() < deadline:
                chunk = response.read1(min(65536, MAX_ARTIFACT_ZIP + 1 - len(raw)))
                if not chunk:
                    break
                raw.extend(chunk)
                control.require(len(raw) <= MAX_ARTIFACT_ZIP)
                hashed.update(chunk)
        control.require(monotonic() < deadline and raw and hashed.hexdigest() == archive_sha)
        control.require(len(raw) >= control.provenance.ZIP_END.size)
        end = len(raw) - control.provenance.ZIP_END.size
        signature, disk, start_disk, disk_count, count, size, offset, comment = control.provenance.ZIP_END.unpack(raw[end:])
        control.require(signature == b"PK\x05\x06" and disk == start_disk == comment == 0
                        and disk_count == count == 1 and 0 < size <= control.provenance.MAX_ZIP_DIRECTORY and offset + size == end)
        with ZipFile(BytesIO(raw)) as archive:
            members = archive.infolist()
            control.require(len(members) == 1 and members[0].filename == members[0].orig_filename == "payload.age"
                            and members[0].flag_bits & (1 | 64) == 0
                            and members[0].compress_type in (ZIP_STORED, ZIP_DEFLATED)
                            and stat.S_IFMT(members[0].external_attr >> 16) in (0, stat.S_IFREG)
                            and 0 < members[0].file_size <= MAX_CIPHERTEXT)
            cipher = archive.read(members[0])
            control.require(len(cipher) == members[0].file_size)
            return cipher
    except (OSError, HTTPException, BadZipFile, RuntimeError, ValueError, zlib.error):
        raise control.ProviderError("The exact encrypted Provider artifact could not be read safely.") from None


def run_with_identity(identity, arguments, *, data=None):
    control.require(isinstance(identity, str) and identity.isascii() and 0 < len(identity) <= 1024
                    and identity.startswith("AGE-SECRET-KEY-1") and "\n" not in identity and "\r" not in identity)
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (identity + "\n").encode("ascii"))
        os.close(write_fd)
        write_fd = -1
        command = [str(age_binary(arguments[0])), *[item.replace("{identity}", f"/dev/fd/{read_fd}") for item in arguments[1:]]]
        result = subprocess.run(command, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False, pass_fds=(read_fd,),
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)
    return result


def decrypt(phase, artifact_id, archive_sha, cipher_sha):
    cipher = download_cipher(artifact_id, archive_sha)
    verify_artifact(phase, artifact_id, archive_sha, cipher_sha, cipher)
    identity = os.environ.get("SUBS_BOT_PROVIDER_REHEARSAL_AGE_IDENTITY", "")
    public = run_with_identity(identity, ["age-keygen", "-y", "{identity}"])
    control.require(public.returncode == 0 and public.stdout == (recipient() + "\n").encode("ascii"),
                    "The private Provider handoff identity differs from the pinned recipient.")
    result = run_with_identity(identity, ["age", "--decrypt", "--identity", "{identity}"], data=cipher)
    control.require(result.returncode == 0 and 0 < len(result.stdout) <= MAX_PLAINTEXT,
                    "The authenticated private Provider message could not be decrypted.")
    return envelope(control.github._parse_object(result.stdout, "The private Provider message is invalid."), phase)

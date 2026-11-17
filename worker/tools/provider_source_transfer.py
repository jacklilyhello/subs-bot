"""Encrypted, bounded source-chain handoff between fresh isolated CI jobs.

The producing job may hold private R2 read credentials; the receiving job must
not. The workflow must map all upstream pins directly from the producer's needs
outputs and protect the recipient and identity in their respective environments.
"""

from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
from time import monotonic
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile

import production_provider as control
import production_provider_encrypted_publish as existing
import provider_durable_source as durable
import provider_private_handoff as handoff

WORKFLOW_PATH = ".github/workflows/worker-provider-digest-rehearsal.yml"
REVIEWED_WORKFLOW_PATH = ".github/workflows/worker-provider-reviewed-digest.yml"
REVIEWED_OPERATION_WORKFLOW_PATH = ".github/workflows/worker-provider-reviewed-operation.yml"
REVIEWED_RECOVERY_WORKFLOW_PATH = ".github/workflows/worker-provider-reviewed-recovery.yml"
REVIEWED_SOURCE_WORKFLOW_PATH = ".github/workflows/worker-provider-reviewed-isolated-source.yml"
REVIEWED_SOURCE_READBACK_WORKFLOW_PATH = ".github/workflows/worker-provider-reviewed-isolated-source-readback.yml"
MAX_BUNDLE = 2 * 1024 * 1024 * 1024
MAX_INDEX = 512 * 1024
DISK_MARGIN = 512 * 1024 * 1024


def require_disk(root, required):
    control.require(root.is_absolute() and root.is_dir() and type(required) is int and required > 0
                    and shutil.disk_usage(root).free >= required,
                    "Insufficient isolated runner scratch space for the complete private source transfer.")


def workflow_path():
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    matches = [path for path in (WORKFLOW_PATH, REVIEWED_WORKFLOW_PATH, REVIEWED_OPERATION_WORKFLOW_PATH, REVIEWED_RECOVERY_WORKFLOW_PATH,
                                 REVIEWED_SOURCE_WORKFLOW_PATH, REVIEWED_SOURCE_READBACK_WORKFLOW_PATH)
               if ref == f"{control.github.REPOSITORY}/{path}@{control.github.MAIN_REF}"]
    control.require(len(matches) == 1)
    return matches[0]


def execution_identity(revision):
    """Distinguish the actual main dispatcher from the reviewed PR code."""
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    if not ref or ref == f"{control.github.REPOSITORY}/{WORKFLOW_PATH}@{control.github.MAIN_REF}":
        return {"workflowPath": WORKFLOW_PATH, "candidateRevision": revision, "reviewedPr": None}
    path = workflow_path()
    control.require(path in {REVIEWED_WORKFLOW_PATH, REVIEWED_OPERATION_WORKFLOW_PATH, REVIEWED_RECOVERY_WORKFLOW_PATH,
                             REVIEWED_SOURCE_WORKFLOW_PATH, REVIEWED_SOURCE_READBACK_WORKFLOW_PATH})
    simulation = path in {REVIEWED_WORKFLOW_PATH, REVIEWED_OPERATION_WORKFLOW_PATH, REVIEWED_RECOVERY_WORKFLOW_PATH}
    spec = control.github._parse_object(os.environ.get("PROVIDER_HEAD_VALIDATION_JSON", ""), control.ERROR)
    head = os.environ.get("PROVIDER_HEAD_REVIEWED_SHA", "")
    control.require(set(spec) == {"version", "pr", "headSha", "providerCiRunId", "approvalSha256", "archiveRefs", "simulateActionsUnavailable"}
                    and type(spec["version"]) is int and spec["version"] == 1
                    and control.match(control.provider.DECIMAL, spec["pr"])
                    and control.match(control.provider.REVISION, head) and spec["headSha"] == head
                    and os.environ.get("PROVIDER_HEAD_TRUSTED_MAIN_SHA") == revision
                    and spec["providerCiRunId"] == os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID")
                    and spec["approvalSha256"] == os.environ.get("SUBS_BOT_PROVIDER_DIGEST_APPROVAL")
                    and spec["archiveRefs"] == refs() and spec["simulateActionsUnavailable"] is simulation
                    and os.environ.get("SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE") == ("1" if simulation else "0"))
    return {"workflowPath": path, "candidateRevision": head, "reviewedPr": spec["pr"]}


def context():
    revision = os.environ.get("GITHUB_SHA", "")
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == revision
                    and workflow_path() in {WORKFLOW_PATH, REVIEWED_WORKFLOW_PATH, REVIEWED_OPERATION_WORKFLOW_PATH, REVIEWED_RECOVERY_WORKFLOW_PATH}
                    and os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
                    and control.match(control.provider.REVISION, revision)
                    and control.match(control.provider.DECIMAL, os.environ.get("GITHUB_RUN_ID", "")))
    control.github.require_current_main(revision)


def target():
    value = control.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(value["environment"] == "rehearsal" and value["caller"] is None
                    and os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID") == value["build"]["runId"]
                    and os.environ.get("SUBS_BOT_PROVIDER_DURABLE_REQUIRED") == "1"
                    and os.environ.get("SUBS_BOT_PROVIDER_DIGEST_APPROVAL") == control.digest({"operation": "publish-digest", "target": value}))
    return value


def refs():
    value = json.loads(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_REFS", ""), object_pairs_hook=control.github._unique_json_object)
    trusted = json.loads(os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_ARCHIVE_REFS_JSON", ""),
                         object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(value, list) and 0 < len(value) <= 9 and value == trusted)
    return value


def recipient():
    value = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_RECIPIENT", "")
    expected = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_RECIPIENT_SHA256", "")
    control.require(re.fullmatch(r"age1[023456789acdefghjklmnpqrstuvwxyz]{58}", value) is not None
                    and control.match(control.provider.HEX, expected) and sha256(value.encode("ascii")).hexdigest() == expected)
    return value


def metadata(value):
    simulation = os.environ.get("SUBS_BOT_PROVIDER_SIMULATE_ARTIFACT_UNAVAILABLE", "0")
    control.require(simulation in {"0", "1"})
    return {"version": 1, "kind": "isolated-provider-source-transfer", "runId": os.environ["GITHUB_RUN_ID"],
            "runAttempt": "1", "controllerRevision": os.environ["GITHUB_SHA"], "targetSha256": control.digest(value),
            "archiveRefsSha256": control.digest(refs()), "simulatedActionsUnavailable": simulation == "1",
            **execution_identity(os.environ["GITHUB_SHA"])}


def file_sha(path, limit):
    control.provider.checked_file(path, limit)
    digest, size = sha256(), 0
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            size += len(chunk)
            control.require(size <= limit)
            digest.update(chunk)
    return digest.hexdigest()


def strict_zip_end(path, max_entries):
    size = path.stat().st_size
    control.require(size >= control.provenance.ZIP_END.size)
    with path.open("rb") as source:
        source.seek(-control.provenance.ZIP_END.size, os.SEEK_END)
        end = size - control.provenance.ZIP_END.size
        signature, disk, start_disk, disk_count, count, length, offset, comment = control.provenance.ZIP_END.unpack(source.read())
    control.require(signature == b"PK\x05\x06" and disk == start_disk == comment == 0
                    and disk_count == count and 0 < count <= max_entries
                    and 0 < length <= control.provenance.MAX_ZIP_DIRECTORY and offset + length == end)


def age_identity(arguments, source, destination):
    identity = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_AGE_IDENTITY", "")
    control.require(isinstance(identity, str) and identity.isascii() and 0 < len(identity) <= 1024
                    and identity.startswith("AGE-SECRET-KEY-1") and "\n" not in identity and "\r" not in identity)
    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (identity + "\n").encode("ascii"))
        os.close(write_fd)
        write_fd = -1
        command = [str(handoff.age_binary(arguments[0])), *[item.replace("{identity}", f"/dev/fd/{read_fd}") for item in arguments[1:]]]
        with source.open("rb") if source is not None else open(os.devnull, "rb") as input_file, \
                control.provenance._write_private(destination) as output_file:
            result = subprocess.run(command, stdin=input_file, stdout=output_file, stderr=subprocess.PIPE,
                                    timeout=900, check=False, pass_fds=(read_fd,),
                                    env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
        control.require(result.returncode == 0 and destination.stat().st_size > 0)
    finally:
        os.close(read_fd)
        if write_fd != -1:
            os.close(write_fd)


def produce():
    context()
    value = target()
    root = Path(os.environ["RUNNER_TEMP"])
    # Originals plus one expanded verification scratch tree must fit before R2 reads.
    require_disk(root, MAX_BUNDLE + 2 * control.provider.MAX_IMAGE + DISK_MARGIN)
    durable.restore()
    existing.verify_sources(value)
    source = root / "provider-durable-sources"
    rows = control.durable_builds()
    control.require(isinstance(rows, list) and 0 < len(rows) <= 9)
    index = control.provider.checked_file(source / "index.json", MAX_INDEX).read_bytes()
    meta = control.canonical(metadata(value))
    bundle = root / "provider-source-transfer.zip"
    originals = []
    total = len(index) + len(meta)
    for row in rows:
        build = row["build"]
        original = control.durable_archive(build)
        total += original.stat().st_size
        control.require(total <= MAX_BUNDLE and file_sha(original, control.provenance.MAX_ZIP) == build["archiveSha256"])
        originals.append((original, build["archiveSha256"] + ".zip"))
    # Source originals already exist; allow for stored ZIP, age ciphertext and
    # another complete verification scratch tree before opening either output.
    require_disk(root, 2 * total + 2 * control.provider.MAX_IMAGE + DISK_MARGIN)
    with control.provenance._write_private(bundle) as bundle_file, ZipFile(bundle_file, "w", compression=ZIP_STORED, allowZip64=False) as out:
        out.writestr("transfer.json", meta)
        out.writestr("index.json", index)
        for original, name in originals:
            out.write(original, name)
    control.require(bundle.stat().st_size <= MAX_BUNDLE)
    cipher = root / "provider-source-transfer.age"
    with bundle.open("rb") as input_file, control.provenance._write_private(cipher) as output_file:
        result = subprocess.run([str(handoff.age_binary("age")), "--encrypt", "--recipient", recipient()],
                                stdin=input_file, stdout=output_file, stderr=subprocess.PIPE, timeout=900, check=False,
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    control.require(result.returncode == 0 and 0 < cipher.stat().st_size <= MAX_BUNDLE + 1024 * 1024)
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="ascii") as output:
        output.write("cipher_sha256=" + file_sha(cipher, MAX_BUNDLE + 1024 * 1024) + "\n")


def download_cipher():
    artifact_id = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ARTIFACT_ID", "")
    archive_sha = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ARTIFACT_SHA256", "")
    cipher_sha = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_CIPHER_SHA256", "")
    control.require(control.match(control.provider.DECIMAL, artifact_id)
                    and all(control.match(control.provider.HEX, value) for value in (archive_sha, cipher_sha))
                    and os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_SOURCE_ARTIFACT_ID") == artifact_id
                    and os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_SOURCE_ARTIFACT_SHA256") == archive_sha
                    and os.environ.get("SUBS_BOT_PROVIDER_TRUSTED_SOURCE_CIPHER_SHA256") == cipher_sha)
    run_id, revision, token = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_SHA"], control.github._github_token()
    artifact = control.github._get_json("/actions/artifacts/" + artifact_id, token)
    origin = artifact.get("workflow_run")
    control.require(str(artifact.get("id")) == artifact_id and artifact.get("expired") is False
                    and artifact.get("name") == f"provider-encrypted-source-{run_id}-1"
                    and artifact.get("digest") == "sha256:" + archive_sha and isinstance(origin, dict)
                    and str(origin.get("id")) == run_id and origin.get("head_branch") == "main"
                    and origin.get("head_sha") == revision
                    and origin.get("repository_id") == origin.get("head_repository_id") == control.github.REPOSITORY_ID)
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    path = workflow_path()
    control.require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
                    and run.get("path") in (path, path + "@main", path + "@refs/heads/main")
                    and run.get("head_sha") == revision and run.get("head_branch") == "main" and run.get("event") == "workflow_dispatch"
                    and all(isinstance(run.get(k), dict) and run[k].get("id") == control.github.REPOSITORY_ID
                            for k in ("repository", "head_repository")))
    listing = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = listing.get("jobs")
    control.require(isinstance(jobs, list) and type(listing.get("total_count")) is int and listing["total_count"] == len(jobs) < 100)
    matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == "Provider private source transfer"]
    control.require(len(matches) == 1 and str(matches[0].get("run_id")) == run_id and matches[0].get("run_attempt") == 1
                    and matches[0].get("head_sha") == revision and (matches[0].get("status"), matches[0].get("conclusion")) == ("completed", "success")
                    and isinstance(matches[0].get("steps"), list))
    steps = [step for step in matches[0]["steps"] if isinstance(step, dict) and step.get("name") == "Upload encrypted source bundle"]
    control.require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    path = Path(os.environ["RUNNER_TEMP"]) / "provider-source-artifact.zip"
    limit = MAX_BUNDLE + 3 * 1024 * 1024
    require_disk(path.parent, limit + DISK_MARGIN)
    deadline, size, digest = monotonic() + 900, 0, sha256()
    request = control.github.artifact_storage_request(artifact_id, token)
    try:
        with control.provenance.STORAGE_OPENER.open(request, timeout=30) as response, control.provenance._write_private(path) as output:
            control.require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
            while monotonic() < deadline:
                chunk = response.read1(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                control.require(size <= limit)
                digest.update(chunk)
                output.write(chunk)
        control.require(monotonic() < deadline and size > 0 and digest.hexdigest() == archive_sha)
        strict_zip_end(path, 1)
        with ZipFile(path) as archive:
            members = archive.infolist()
            control.require(len(members) == 1 and members[0].filename == members[0].orig_filename == "provider-source-transfer.age"
                            and members[0].flag_bits & (1 | 64) == 0 and members[0].compress_type in (ZIP_STORED, ZIP_DEFLATED)
                            and stat.S_IFMT(members[0].external_attr >> 16) in (0, stat.S_IFREG)
                            and 0 < members[0].file_size <= MAX_BUNDLE + 1024 * 1024)
            # The outer ZIP now occupies disk; use the declared ciphertext size
            # rather than assuming incompressible data when reserving space.
            require_disk(path.parent, 3 * members[0].file_size + 2 * control.provider.MAX_IMAGE + DISK_MARGIN)
            cipher = Path(os.environ["RUNNER_TEMP"]) / "provider-source-transfer.age"
            with archive.open(members[0]) as source, control.provenance._write_private(cipher) as output:
                while chunk := source.read(1024 * 1024):
                    output.write(chunk)
            control.require(cipher.stat().st_size == members[0].file_size and file_sha(cipher, MAX_BUNDLE + 1024 * 1024) == cipher_sha)
    except (OSError, HTTPException, BadZipFile, RuntimeError, ValueError):
        raise control.ProviderError("The exact encrypted Provider source artifact could not be read safely.") from None
    control.github.require_current_main(revision)
    return cipher


def receive():
    context()
    value = target()
    root = Path(os.environ["RUNNER_TEMP"])
    cipher = download_cipher()
    public = root / "provider-source-recipient.txt"
    age_identity(["age-keygen", "-y", "{identity}"], None, public)
    control.require(public.read_bytes() == (recipient() + "\n").encode("ascii"))
    bundle = root / "provider-source-transfer.zip"
    age_identity(["age", "--decrypt", "--identity", "{identity}"], cipher, bundle)
    control.require(0 < bundle.stat().st_size <= MAX_BUNDLE)
    strict_zip_end(bundle, 11)
    source_root = root / "provider-durable-sources"
    source_root.mkdir(mode=0o700)
    try:
        with ZipFile(bundle) as archive:
            entries = archive.infolist()
            control.require(2 < len(entries) <= 11 and len({item.filename for item in entries}) == len(entries)
                            and all(item.filename == item.orig_filename and item.flag_bits & (1 | 64) == 0
                                    and item.compress_type == ZIP_STORED and stat.S_IFMT(item.external_attr >> 16) in (0, stat.S_IFREG)
                                    for item in entries))
            by_name = {item.filename: item for item in entries}
            control.require("transfer.json" in by_name and "index.json" in by_name
                            and 0 < by_name["transfer.json"].file_size <= MAX_INDEX
                            and 0 < by_name["index.json"].file_size <= MAX_INDEX)
            recorded = control.github._parse_object(archive.read(by_name["transfer.json"]), control.ERROR)
            control.require(recorded == metadata(value))
            index_raw = archive.read(by_name["index.json"])
            rows = json.loads(index_raw, object_pairs_hook=control.github._unique_json_object)
            control.require(isinstance(rows, list) and 0 < len(rows) <= 9
                            and all(isinstance(row, dict) and isinstance(row.get("build"), dict)
                                    and control.match(control.provider.HEX, row["build"].get("archiveSha256")) for row in rows))
            names = [row["build"]["archiveSha256"] + ".zip" for row in rows]
            control.require(len(set(names)) == len(names) and set(by_name) == {"transfer.json", "index.json", *names}
                            and sum(item.file_size for item in entries) <= MAX_BUNDLE)
            with control.provenance._write_private(source_root / "index.json") as output:
                output.write(index_raw)
            for name in names:
                item = by_name[name]
                control.require(0 < item.file_size <= control.provenance.MAX_ZIP)
                destination = source_root / name
                with archive.open(item) as source, control.provenance._write_private(destination) as output:
                    while chunk := source.read(1024 * 1024):
                        output.write(chunk)
                control.require(destination.stat().st_size == item.file_size and file_sha(destination, control.provenance.MAX_ZIP) == name[:-4])
    except (OSError, BadZipFile, RuntimeError, ValueError):
        raise control.ProviderError("The encrypted Provider source bundle failed its exact source checks.") from None
    existing.verify_sources(value)


if __name__ == "__main__":
    try:
        {"produce": produce, "receive": receive}[os.environ.get("SUBS_BOT_PROVIDER_SOURCE_TRANSFER_ACTION", "")]()
    except Exception:
        raise SystemExit("Private Provider source transfer stopped; do not retry an unknown write.") from None

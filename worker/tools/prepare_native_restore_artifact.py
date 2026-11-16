"""Verify an immutable native-restore source using the current main control tool.

This selector is exclusive to native restore. It grants no Worker deployment or
rollback operation. Source.verify must still match the actual Worker and the
private checkpoint before a rehearsal mutation; ordinary deployment selectors
continue to require a source artifact of the current main commit.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

import prepare_isolation_artifact as artifact


ERROR = "The native restore source artifact and current control tool could not be verified."
WORKFLOW = artifact.REPOSITORY + "/.github/workflows/worker-isolation-native-restore.yml@" + artifact.MAIN_REF


def require(value):
    if not value:
        raise artifact.ArtifactError(ERROR)


def checkout_revision():
    try:
        result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[2],
            check=True, capture_output=True, text=True, encoding="ascii", timeout=10)
        return result.stdout.strip()
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise artifact.ArtifactError(ERROR) from None


def require_control_revision():
    env = os.environ
    require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_REF") == artifact.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
        and env.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
        and env.get("GITHUB_REPOSITORY_ID") == str(artifact.REPOSITORY_ID))
    control = env.get("GITHUB_SHA", "")
    require(isinstance(control, str) and artifact._REVISION.fullmatch(control) and checkout_revision() == control)
    artifact.require_current_main(control)
    return control


def private_source(env, run, attempt):
    # evidence_archive reuses native restore's signing constants. Load it only
    # after this module/native restore have finished their definitions.
    import evidence_archive as evidence

    archive_run, archive_attempt, expected = (env.get(key, "") for key in (
        "NATIVE_SOURCE_ARCHIVE_RUN_ID", "NATIVE_SOURCE_ARCHIVE_RUN_ATTEMPT", "NATIVE_SOURCE_ARCHIVE_MANIFEST_SHA256"))
    require(all(isinstance(value, str) and artifact._DECIMAL.fullmatch(value) for value in (archive_run, archive_attempt))
        and isinstance(expected, str) and artifact._SHA256.fullmatch(expected))
    config = env.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "").encode("utf-8")
    require(len(config) <= 4096)
    target = evidence.parse(config)
    token = env.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "")
    require(isinstance(token, str) and 0 < len(token) <= 4096)
    store = evidence.PrivateStore(target, token, evidence.BASE + archive_run + "/" + archive_attempt + "/")
    # verify_archive validates the fixed private bucket identity/lifecycle and
    # every immutable blob, including the candidate/CI/deployment closure.
    # This code path deliberately never calls put/archive or any source GitHub API.
    evidence.verify_archive(store, expected)
    raw_manifest = store.read("manifest.json")
    require(isinstance(raw_manifest, bytes) and evidence.digest(raw_manifest) == expected)
    archived = evidence.parse(raw_manifest)
    records = [record for record in archived.get("additionalCandidates", [])
        if record["ciRun"]["runId"] == run and record["ciRun"]["runAttempt"] == attempt]
    require(len(records) == 1)
    record = records[0]
    pinned = record["ciArtifact"]
    raw = store.read("blobs/" + pinned["sha256"])
    proof = {"revision": record["ciRun"]["revision"], "runId": run, "runAttempt": attempt,
        "artifactId": pinned["artifactId"], "archiveSha256": pinned["sha256"]}
    require(isinstance(raw, bytes) and len(raw) == pinned["bytes"])
    evidence.ci_archive(raw, proof)
    return raw, proof, {"sourceBackend": "private-release-evidence", "sourceArchive": {
        "runId": archive_run, "runAttempt": archive_attempt, "manifestSha256": expected,
        "candidateJsonSha256": record["candidateJsonSha256"]}}


def prepare():
    env = os.environ
    control = require_control_revision()
    run, attempt = env.get("SUBS_BOT_CI_RUN_ID", ""), env.get("SUBS_BOT_CI_RUN_ATTEMPT", "1")
    require(all(isinstance(value, str) and artifact._DECIMAL.fullmatch(value) for value in (run, attempt)))
    runner_temp = Path(env.get("RUNNER_TEMP", ""))
    require(runner_temp.is_absolute() and runner_temp.is_dir())
    archive_inputs = [env.get(key, "") for key in (
        "NATIVE_SOURCE_ARCHIVE_RUN_ID", "NATIVE_SOURCE_ARCHIVE_RUN_ATTEMPT", "NATIVE_SOURCE_ARCHIVE_MANIFEST_SHA256")]
    # The workflow defaults archive attempt to 1; run/digest still must be paired.
    private = bool(archive_inputs[0]) or bool(archive_inputs[2])
    if private:
        raw, proof, backend = private_source(env, run, attempt)
        source = proof["revision"]
    else:
        require(not archive_inputs[0] and not archive_inputs[2] and archive_inputs[1] in ("", "1"))
        token = artifact._github_token()
        metadata = artifact._get_json(f"/actions/runs/{run}/attempts/{attempt}", token)
        source = metadata.get("head_sha") if isinstance(metadata, dict) else None
        require(isinstance(source, str) and artifact._REVISION.fullmatch(source))
        select = lambda: artifact.select_main_artifact(run, source, token, workflow_id=artifact.WORKFLOW_ID,
            workflow_path=artifact.WORKFLOW_PATH, artifact_prefix="subs-bot-worker", workflow_label="Worker CI", run_attempt=attempt)
        selected_attempt, identity, digest = select()
        raw = artifact._download(identity, token)
        require(select() == (selected_attempt, identity, digest))
        proof = {"revision": source, "runId": run, "runAttempt": selected_attempt, "artifactId": identity, "archiveSha256": digest}
        backend = {"sourceBackend": "github-actions"}
    require(require_control_revision() == control)
    artifact._unpack(raw, proof["archiveSha256"], source, run, proof["runAttempt"], runner_temp)
    require(require_control_revision() == control)
    return {"controlRevision": control, "sourceRevision": source, "sourceCIProof": proof, **backend}


if __name__ == "__main__":
    try:
        print(json.dumps(prepare(), sort_keys=True))
    except Exception:
        sys.exit(ERROR)

"""Hosted entry point for the production-aware recovery engine.

The same workflow and code support the registered rehearsal target. No target,
credential, source artifact, approval or recovery identity falls back to dev.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import tempfile

import d1_migrations
import prepare_isolation_artifact as artifact
from production_control import API, Controller, OperationError, Telegram, general_config, hosted_environment
from production_target import ContractError, approve, canonical as target_canonical, parsed, validate_target
import production_recovery as recovery


WORKFLOW = artifact.REPOSITORY + "/.github/workflows/worker-production-recovery.yml@" + artifact.MAIN_REF
READ_ONLY = {"inspect", "verify-backup"}


def require_reviewed_ancestor(revision, control_revision, token):
    recovery.require(recovery.matches(artifact._REVISION, revision)
                     and recovery.matches(artifact._REVISION, control_revision))
    if revision != control_revision:
        # GitHub emits changed-file patches only on page one. Ancestry fields
        # remain available on page two, including when its commit list is empty.
        comparison = artifact.compare_commits_metadata(revision, control_revision, token)
        recovery.require(isinstance(comparison, dict) and comparison.get("status") in {"ahead", "identical"}
                         and comparison.get("base_commit", {}).get("sha") == revision
                         and comparison.get("merge_base_commit", {}).get("sha") == revision,
                         "The selected Actions source is not an exact reviewed main ancestor.")


def ci_archive(run, attempt, *, control_revision=None):
    recovery.require(all(isinstance(value, str) and re.fullmatch(r"[1-9][0-9]{0,19}", value) for value in (run, attempt)))
    token = artifact._github_token()
    metadata = artifact._get_json(f"/actions/runs/{run}/attempts/{attempt}", token)
    revision = metadata.get("head_sha")
    recovery.require(recovery.matches(artifact._REVISION, revision))
    require_reviewed_ancestor(revision, control_revision or os.environ.get("GITHUB_SHA", ""), token)
    select = lambda: artifact.select_main_artifact(run, revision, token, workflow_id=artifact.WORKFLOW_ID,
        workflow_path=artifact.WORKFLOW_PATH, artifact_prefix="subs-bot-worker", workflow_label="Worker CI", run_attempt=attempt)
    selected, identity, sha = select()
    body = artifact._download(identity, token)
    recovery.require(select() == (selected, identity, sha) and recovery.digest(body) == sha)
    return body, {"revision": revision, "runId": run, "runAttempt": selected, "artifactId": identity, "archiveSha256": sha}


def private_archive(api, checkpoint_id, expected_sha256):
    recovery.require(recovery.matches(recovery.CHECKPOINT, checkpoint_id)
                     and recovery.matches(recovery.DIGEST, expected_sha256))
    prefix = "production/checkpoints/" + checkpoint_id + "/"
    raw, _ = api.object_or_none(api.names["backup"], prefix + "manifest.json")
    recovery.require(raw is not None and recovery.digest(raw) == expected_sha256)
    document = recovery.native.parsed(raw, recovery.native.MANIFEST_BYTES)
    recovery.require(document.get("version") == 2 and isinstance(document.get("sourcePin"), dict))
    body, proof = recovery.load_code_archive(api, document, prefix)
    recovery.require(proof["revision"] == document["sourcePin"].get("revision"))
    return body, proof


def unpack(body, proof, directory):
    artifact._unpack(body, proof["archiveSha256"], proof["revision"], proof["runId"], proof["runAttempt"], directory)
    bundle = directory / artifact.VERIFIED_DIRECTORY
    manifest = json.loads((bundle / "isolation.json").read_bytes())
    return bundle, manifest


def main(env=None):
    env = os.environ if env is None else env
    recovery.require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW)
    target = validate_target(env.get("SUBS_BOT_TARGET_JSON", ""))
    hosted_environment(target.environment)
    control_revision = env.get("GITHUB_SHA", "")
    guard = lambda: artifact.require_current_main(control_revision)
    guard()
    action = env.get("RECOVERY_ACTION", "inspect")
    contract = recovery.recovery_contract(env.get("SUBS_BOT_RECOVERY_JSON", ""), target.data)
    secrets = parsed(env.get("SUBS_BOT_CONTROL_SECRETS", ""))
    # Validate safe injection before creating any cloud-backed journal intent.
    general_config(target, control_revision, secrets)
    worker = API(target, env.get("SUBS_BOT_CF_WORKER_TOKEN", ""))
    data = API(target, env.get("SUBS_BOT_CF_DATA_TOKEN", ""))
    api = recovery.RecoveryAPI(target.data, env.get("SUBS_BOT_CF_DATA_TOKEN", ""), worker, contract)
    api.verify_backup()
    source_manifest = contract.get("sourceManifestSha256") or env.get("RECOVERY_SOURCE_MANIFEST_SHA256")
    if source_manifest:
        body, proof = private_archive(api, contract["checkpointId"], source_manifest)
    else:
        body, proof = ci_archive(env.get("SUBS_BOT_CI_RUN_ID", ""), env.get("SUBS_BOT_CI_RUN_ATTEMPT", "1"), control_revision=control_revision)
    current_run = env.get("RECOVERY_CURRENT_CI_RUN_ID", "")
    if current_run:
        current_body, current_proof = ci_archive(current_run, env.get("RECOVERY_CURRENT_CI_RUN_ATTEMPT", "1"), control_revision=control_revision)
    elif contract.get("preservedG1"):
        g1 = contract["preservedG1"]
        current_body, current_proof = private_archive(api, g1["checkpointId"], g1["manifestSha256"])
    else:
        current_body, current_proof = body, proof
    root = Path(env["RUNNER_TEMP"])
    recovery.require(root.is_absolute() and root.is_dir())
    # TemporaryDirectory is hosted-only; never expose this directory as an artifact.
    with tempfile.TemporaryDirectory(prefix="subs-bot-production-recovery-", dir=root) as temporary:
        directory = Path(temporary)
        source_dir, current_dir = directory / "source", directory / "current"
        source_dir.mkdir(mode=0o700)
        current_dir.mkdir(mode=0o700)
        bundle, manifest = unpack(body, proof, source_dir)
        current_bundle, current_manifest = unpack(current_body, current_proof, current_dir)
        controller = Controller(target, data, worker, current_bundle, current_manifest, guard=guard,
                                telegram=Telegram(target, secrets), secrets=secrets, control_revision=control_revision,
                                dependency_api=API(target, env["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"])
                                if target.data["provider"] is not None and env.get("SUBS_BOT_CF_DEPENDENCY_READ_TOKEN") else None)
        before = controller.inspect()
        if action not in READ_ONLY:
            recovery.require(before["stateSha256"] == env.get("RECOVERY_STATE_SHA256"),
                             "The current source predecessor differs; no mutation is authorized.")
            approved_action = "recovery-" + action + ":" + recovery.digest(recovery.canonical(contract))
            approve(target, env.get("SUBS_BOT_APPROVAL_JSON", ""), approved_action, proof["revision"], before["stateSha256"],
                    control_revision=control_revision)
        source = recovery.RecoverySource(api, target.data, bundle, manifest, controller.inspect, guard)
        source.archive_body, source.code_proof = body, proof
        owner = env.get("GITHUB_RUN_ID", "") + "/" + env.get("GITHUB_RUN_ATTEMPT", "")
        recovery.require(re.fullmatch(r"[1-9][0-9]{0,19}/[1-9][0-9]{0,9}", owner))
        journal = recovery.RecoveryJournal(api, owner, guard=guard)
        journal.load()
        if action not in READ_ONLY and journal.value is not None:
            journal.claim()
        try:
            validation = root / "production-restored-links" if action == "verify-restore" else None
            engine = recovery.RecoveryEngine(api, source, journal, directory, validation_directory=validation)
            result = recovery.run_action(action, engine, resource=env.get("RECOVERY_RESOURCE", ""),
                                         identity_sha256=env.get("RECOVERY_IDENTITY_SHA256", ""))
            if validation is not None:
                module = root / "production-restored-module"
                module.mkdir(mode=0o700)
                with recovery.native.private_file(module / "index.js") as output:
                    output.write((bundle / "index.js").read_bytes())
        finally:
            # Unknown journal state cannot be released or followed by a mutation.
            if action not in READ_ONLY:
                journal.release()
        result.update(sourceStateSha256=controller.inspect()["stateSha256"],
                      controlRevision=control_revision, sourceCIProof=proof, currentCIProof=current_proof,
                      environment=target.environment, runId=env["GITHUB_RUN_ID"], runAttempt=env["GITHUB_RUN_ATTEMPT"])
        output = root / "production-recovery-result.json"
        with recovery.native.private_file(output) as stream:
            stream.write(target_canonical(result))
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main()
    except (recovery.RecoveryError, ContractError, OperationError, d1_migrations.MigrationError,
            artifact.ArtifactError, OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        # Untrusted transport/data exception strings may contain private values.
        print(json.dumps({"status": "stopped", "reason": "Recovery was not verified; preserve the private checkpoint and inspect before retry.",
                          "uncertain": bool(getattr(error, "uncertain", False))}))
        raise SystemExit(1) from None

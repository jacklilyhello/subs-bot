"""Verify current control code separately from an explicitly selected main release.

Ordinary deployment/initialization requires current main. Readback, pause, drain
and recovery may inspect an older reviewed main artifact without rebuilding it.
"""
import os
from pathlib import Path
import re

import prepare_isolation_artifact as source


def prepare(action, *, run_id=None, directory=None):
    control_revision = os.environ.get("GITHUB_SHA", "")
    run_id = os.environ.get("SUBS_BOT_CI_RUN_ID", "") if run_id is None else run_id
    if not re.fullmatch(r"[1-9][0-9]{0,19}", run_id) or os.environ.get("GITHUB_REF") != source.MAIN_REF:
        raise source.ArtifactError("An explicit reviewed main CI run is required.")
    source.require_current_main(control_revision)
    token = source._github_token()
    run = source._get_json("/actions/runs/" + run_id, token)
    revision = run.get("head_sha")
    if not isinstance(revision, str) or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise source.ArtifactError("The selected release revision is invalid.")
    if action in {"plan-deploy", "deploy", "initialize", "preflight"} and revision != control_revision:
        raise source.ArtifactError("New deployment and initialization require the exact current main artifact.")
    if revision != control_revision:
        comparison = source._get_json("/compare/" + revision + "..." + control_revision, token)
        if (comparison.get("status") not in ("ahead", "identical")
                or comparison.get("base_commit", {}).get("sha") != revision
                or comparison.get("merge_base_commit", {}).get("sha") != revision):
            raise source.ArtifactError("The selected release is not a reviewed ancestor of current main.")
    select = lambda: source._select_artifact(run_id, revision, token)
    attempt, identity, archive_sha = select()
    raw = source._download(identity, token)
    if select() != (attempt, identity, archive_sha):
        raise source.ArtifactError("The selected release artifact changed during verification.")
    destination = Path(os.environ["RUNNER_TEMP"]) if directory is None else Path(directory)
    source._unpack(raw, archive_sha, revision, run_id, attempt, destination)
    source.require_current_main(control_revision)
    return {"revision": revision, "runId": run_id, "runAttempt": attempt, "artifactId": identity, "archiveSha256": archive_sha}

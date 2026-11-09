"""Build the synthetic V10 candidate using an actual offline redirect comparison."""

from contextlib import suppress
import json
import os
from pathlib import Path
from runpy import run_path
import sys
from tempfile import TemporaryDirectory


TEST = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST.parent / "tools"))

import legacy_restore_package as package
import legacy_unified_share_native_fixture as fixture
import prepare_isolation_artifact as artifact


PUBLISH_DIRECTORY = "subs-bot-legacy-unified-share-candidate"


def publication_target(arguments, bundle, revision):
    if not arguments:
        return None, None
    fixture.require(len(arguments) == 2 and arguments[0] == "--output")
    runner = Path(os.environ.get("RUNNER_TEMP", ""))
    output = Path(arguments[1])
    run, attempt = (os.environ.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    fixture.require(runner.is_absolute() and output == runner / PUBLISH_DIRECTORY and bundle == runner / "subs-bot-worker"
                    and os.environ.get("GITHUB_REPOSITORY") == artifact.REPOSITORY
                    and os.environ.get("GITHUB_REF") == artifact.MAIN_REF and os.environ.get("GITHUB_SHA") == revision
                    and os.environ.get("GITHUB_EVENT_NAME") in {"push", "workflow_dispatch"}
                    and artifact._REVISION.fullmatch(revision) and artifact._DECIMAL.fullmatch(run)
                    and artifact._DECIMAL.fullmatch(attempt))
    output = package.converter._safe_path(output, existing=False)
    state = runner.stat()
    fixture.require(state.st_uid == os.geteuid() and not state.st_mode & 0o022)
    raw = package.read_private(bundle / "isolation.json", artifact._MAX_JSON)
    manifest = package.native.parsed(raw, artifact._MAX_JSON)
    fixture.require((manifest.get("ref"), manifest.get("revision"), manifest.get("runId"), manifest.get("runAttempt"))
                    == (artifact.MAIN_REF, revision, run, attempt))
    return output, package.native.digest(raw)


def publish(candidate, destination):
    # Reserve the fixed, unused name before moving the already verified package.
    destination.mkdir(mode=0o700)
    reservation = destination.lstat()
    try:
        candidate.candidate.rename(destination)
    except OSError:
        with suppress(OSError):
            if os.path.samestat(reservation, destination.lstat()):
                destination.rmdir()
        raise


def main(arguments):
    stage = "sandbox"
    try:
        run_path(str(TEST / "legacy-dynamic-all-python.py"))["verify_sandbox"]()
        stage = "provenance"
        bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"])
        revision = os.environ["WORKER_TEST_REVISION"]
        destination, original_sha = publication_target(arguments, bundle, revision)
        prepare_worker = run_path(str(TEST / "legacy-selected-short-oracle.integration.py"))["prepare_worker"]
        with TemporaryDirectory(prefix="legacy-unified-share-oracle-", dir=destination.parent if destination else None) as temporary:
            root = Path(temporary)
            worker, source_root = root / "worker", root / "fixture"
            source_root.mkdir(mode=0o700)
            stage = "worker"
            worker_sha = prepare_worker(bundle, worker, revision)
            fixture.require(original_sha is None or worker_sha == original_sha)
            stage = "candidate"
            candidate = fixture.build_unified_share_fixture(source_root, worker, revision, produce_oracle=True)
            if destination is not None:
                stage = "publication"
                publish(candidate, destination)
        print(json.dumps({"candidateVersion": 10, "equivalentExternalRows": 1, "privateShares": 2, "claimRows": 1,
                          "objects": 10}, sort_keys=True))
        return 0
    except Exception:
        print(f"Synthetic unified share candidate could not be confirmed ({stage}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

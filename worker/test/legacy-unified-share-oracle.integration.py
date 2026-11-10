"""Build the exact synthetic unified candidates and run their hosted loopback proofs."""

from contextlib import suppress
import json
import os
from pathlib import Path
import re
from runpy import run_path
from shutil import which
import signal
import subprocess
import sys
from tempfile import TemporaryDirectory


TEST = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST.parent / "tools"))

import legacy_restore_package as package
import legacy_unified_share_native_fixture as fixture
import prepare_isolation_artifact as artifact


PUBLISH_DIRECTORY = "subs-bot-legacy-unified-share-candidate"
ROUTE_PAIRS = 24
HISTORICAL_CLAIM_REPLIES = 3
AUTH_ACTIVATION = {"admittedActors": 2, "confirmedReplies": 3, "discardedReplies": 2, "uncertainReplies": 1}
WORKER_FAILURE = re.compile(rb"The isolated V(?:10|11) Worker oracle could not be confirmed \("
                            rb"(sandbox|input|request-shape|artifact|sql-replay|d1-readback|r2-replay|health|cutoff|restore|historical-claim|general-auth|dispose|"
                            rb"request, case (?:[1-9]|[1-3][0-9]|4[0-8]))\)\.\n")


class RouteContinuityError(RuntimeError):
    """Only a fixed Worker stage or bounded case number may leave the probe."""


def worker_continuity(root, worker, worker_sha, revision, candidate, sql_statements, *, v11=False):
    node = which("node")
    fixture.require(node is not None)
    raw = package.native.canonical({
        "profile": "unified-auth-v11" if v11 else "unified-shares-v10",
        "workerDir": str(worker), "workerManifestSha256": worker_sha,
        "candidateDir": str(candidate.candidate), "candidateManifestSha256": candidate.candidate_sha256,
        "revision": revision, "sqlStatements": sql_statements(candidate),
    })
    fixture.require(len(raw) <= 1024 * 1024)
    with subprocess.Popen([node, str(TEST.parent / "tools/legacy-selected-oracle-worker.ts")],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          cwd=root, start_new_session=True,
                          env={"HOME": str(root), "TMPDIR": str(root), "PATH": os.defpath}) as child:
        try:
            output, diagnostic = child.communicate(raw, timeout=60)
        except subprocess.TimeoutExpired:
            with suppress(ProcessLookupError):
                os.killpg(child.pid, signal.SIGKILL)
            child.communicate()
            raise RouteContinuityError("route-replay-deadline") from None
    if child.returncode:
        detail = WORKER_FAILURE.fullmatch(diagnostic)
        raise RouteContinuityError("route-replay, " + (detail[1].decode("ascii") if detail else "unconfirmed"))
    report = package.native.parsed(output, 256 if v11 else 128)
    if v11:
        fixture.require(set(report) == {"activation"} and type(report["activation"]) is dict
                        and set(report["activation"]) == set(AUTH_ACTIVATION)
                        and all(package.native.integer(report["activation"][name], count, count)
                                for name, count in AUTH_ACTIVATION.items()))
        return report["activation"]
    fixture.require(set(report) == {"continuity"} and type(report["continuity"]) is dict
                    and set(report["continuity"]) == {"routePairs", "historicalClaimReplies"}
                    and package.native.integer(report["continuity"]["routePairs"], ROUTE_PAIRS, ROUTE_PAIRS)
                    and package.native.integer(report["continuity"]["historicalClaimReplies"],
                                               HISTORICAL_CLAIM_REPLIES, HISTORICAL_CLAIM_REPLIES))
    return report["continuity"]


def publication_target(arguments, bundle, revision, *, v11=False):
    if not arguments:
        return None, None
    fixture.require(len(arguments) == 2 and arguments[0] == "--output")
    runner = Path(os.environ.get("RUNNER_TEMP", ""))
    output = Path(arguments[1])
    run, attempt = (os.environ.get(name, "") for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"))
    directory = fixture.AUTH_ARTIFACT_PREFIX if v11 else PUBLISH_DIRECTORY
    fixture.require(runner.is_absolute() and output == runner / directory and bundle == runner / "subs-bot-worker"
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
    v11 = arguments[:1] == ["--v11"]
    if v11:
        arguments = arguments[1:]
    stage = "sandbox"
    try:
        run_path(str(TEST / "legacy-dynamic-all-python.py"))["verify_sandbox"]()
        stage = "provenance"
        bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"])
        revision = os.environ["WORKER_TEST_REVISION"]
        destination, original_sha = publication_target(arguments, bundle, revision, v11=v11)
        selected_oracle = run_path(str(TEST / "legacy-selected-short-oracle.integration.py"))
        with TemporaryDirectory(prefix="legacy-unified-share-oracle-", dir=destination.parent if destination else None) as temporary:
            root = Path(temporary)
            worker, source_root = root / "worker", root / "fixture"
            source_root.mkdir(mode=0o700)
            stage = "worker"
            worker_sha = selected_oracle["prepare_worker"](bundle, worker, revision)
            fixture.require(original_sha is None or worker_sha == original_sha)
            stage = "candidate"
            if v11:
                candidate = fixture.build_unified_auth_fixture(source_root, worker, revision, produce_oracle=True)
                stage = "general-auth"
                activation = worker_continuity(root, worker, worker_sha, revision, candidate,
                                               selected_oracle["sql_statements"], v11=True)
                outcomes = {"candidateVersion": 11, "equivalentExternalRows": 1, "privateShares": 2, "claimRows": 1, "objects": 10,
                            "generalAuthorization": {"activationAllowed": False, "counts": fixture.AUTH_COUNTS},
                            "hostedSyntheticActivation": activation}
            else:
                candidate = fixture.build_unified_share_fixture(source_root, worker, revision, produce_oracle=True)
                stage = "route-replay"
                continuity = worker_continuity(root, worker, worker_sha, revision, candidate, selected_oracle["sql_statements"])
                outcomes = {"candidateVersion": 10, "equivalentExternalRows": 1, "workerRoutePairs": continuity["routePairs"],
                            "historicalClaimReplies": continuity["historicalClaimReplies"], "privateShares": 2, "claimRows": 1, "objects": 10}
            package.read_pinned(candidate.candidate / package.MANIFEST, package.native.MANIFEST_BYTES, candidate.candidate_sha256)
            if destination is not None:
                stage = "publication"
                publish(candidate, destination)
        print(json.dumps(outcomes, sort_keys=True))
        return 0
    except RouteContinuityError as error:
        label = "authorization" if v11 else "share"
        print(f"Synthetic unified {label} candidate could not be confirmed ({error}).", file=sys.stderr)
        return 2
    except Exception:
        label = "authorization" if v11 else "share"
        print(f"Synthetic unified {label} candidate could not be confirmed ({stage}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

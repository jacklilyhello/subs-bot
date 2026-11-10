"""Rebuild and verify the exact fixed dormant candidate for hosted replay only."""

import os
from pathlib import Path
from runpy import run_path
from tempfile import TemporaryDirectory
import sys
from types import SimpleNamespace


TEST = Path(__file__).resolve().parent
sys.path.insert(0, str(TEST.parent / "tools"))

import legacy_general_auth_native_candidate as general
import legacy_restore_package as package


def main():
    stage = "sandbox"
    try:
        run_path(str(TEST / "legacy-dynamic-all-python.py"))["verify_sandbox"]()
        stage = "artifact"
        shared = run_path(str(TEST / "legacy-selected-short-oracle.integration.py"))
        revision = os.environ["WORKER_TEST_REVISION"]
        bundle = Path(os.environ["WORKER_TEST_BUNDLE_DIR"])
        with TemporaryDirectory(prefix="general-auth-replay-") as temporary:
            root = Path(temporary)
            worker = root / "worker"
            worker_sha = shared["prepare_worker"](bundle, worker, revision)
            _, worker_pin = package.worker_artifact(worker, revision, worker_sha)
            stage = "candidate"
            candidate = root / "candidate"
            general.build_fixture(worker, candidate, worker_pin)
            verified = general.GeneralAuthCandidate(candidate, worker, worker_pin, root)
            statements = shared["sql_statements"](SimpleNamespace(candidate=candidate, candidate_sha256=verified.manifest_sha))
            source = verified.document["source"]
            report = {
                "botId": general.BOT, "sourceSha256": source["sourceSha256"], "targetSha256": source["targetSha256"],
                "previewSha256": source["previewManifestSha256"], "workerManifestSha256": worker_sha,
                "candidateManifestSha256": verified.manifest_sha, "releaseRevision": revision,
                "bundleSha256": worker_pin["bundleSha256"], "compatibilityDate": worker_pin["compatibilityDate"],
                "statements": statements,
            }
            sys.stdout.buffer.write(package.native.canonical(report))
        return 0
    except Exception:
        print(f"Synthetic general authorization fixture could not be confirmed ({stage}).", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

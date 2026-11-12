"""Hosted synthetic tests for a GitHub-only review package; no Cloudflare access."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
import json
import stat
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from urllib.error import HTTPError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_candidate as candidate
import prepare_isolation_artifact as artifact

REVISION = "a" * 40
PROOF = {"revision": REVISION, "runId": "100", "runAttempt": "2", "artifactId": "200", "archiveSha256": "b" * 64}
RESULT = {"revision": REVISION, "deploymentId": "00000000-0000-4000-8000-000000000001",
    "versionId": "00000000-0000-4000-8000-000000000002", "previousVersionId": "00000000-0000-4000-8000-000000000003",
    "changed": True, "inlineSearchEnabled": True, "apiStatusEnabled": False}
RUN = {"id": 300, "run_attempt": 1, "workflow_id": 400, "path": candidate.DEPLOY_WORKFLOW,
    "event": "workflow_dispatch", "head_branch": "main", "head_sha": REVISION, "status": "completed", "conclusion": "success",
    "repository": {"id": artifact.REPOSITORY_ID}, "head_repository": {"id": artifact.REPOSITORY_ID}}
ISOLATION = {"bundleSha256": "d" * 64, "compatibilityDate": "2026-07-30",
    "migrations": [{"name": "0001_subscriptions.sql", "sha256": "e" * 64}]}


def log(proof=PROOF, result=RESULT):
    return ("2026-11-12T00:00:00.0000000Z ::add-mask::synthetic-private-log-only-value\n"
        + "2026-11-12T00:00:01.0000000Z " + json.dumps(proof) + "\n"
        + "2026-11-12T00:00:02.0000000Z Verified 1 isolated D1 migration records.\n"
        + "2026-11-12T00:00:03.0000000Z " + json.dumps(result) + "\n").encode()


class ProductionCandidateTests(TestCase):
    def evidence(self):
        return candidate.deployment_proofs(log(), PROOF)

    def configuration(self):
        return candidate.expectations('{"inlineSearchEnabled":true}', '["SHORTLINK"]', self.evidence(),
            " ".join(candidate.BASE_BINDINGS | {"TELEGRAM_INLINE_SEARCH", "SHORTLINK"}).encode())

    def test_only_exact_successful_main_deployment_attempt_is_accepted(self):
        pin = candidate.run_metadata(RUN, "300", "1", REVISION, 400, candidate.DEPLOY_WORKFLOW)
        self.assertEqual(pin["revision"], REVISION)
        for key, value in (("head_sha", "c" * 40), ("event", "pull_request"), ("conclusion", "failure"),
                           ("run_attempt", 2), ("workflow_id", 401), ("head_branch", "other")):
            with self.subTest(key=key), self.assertRaises(artifact.ArtifactError):
                candidate.run_metadata({**RUN, key: value}, "300", "1", REVISION, 400, candidate.DEPLOY_WORKFLOW)
        foreign = deepcopy(RUN)
        foreign["head_repository"]["id"] = 7
        with self.assertRaises(artifact.ArtifactError):
            candidate.run_metadata(foreign, "300", "1", REVISION, 400, candidate.DEPLOY_WORKFLOW)

    def test_job_requires_the_successful_provenance_and_ordinary_release_steps(self):
        job = {"id": 500, "name": "deploy", "status": "completed", "conclusion": "success", "steps": [
            {"name": name, "status": "completed", "conclusion": "success"} for name in
            ("Verify merged artifact provenance and digests", "Release the verified Worker or stage page jump closed")]}
        self.assertEqual(candidate.deploy_job({"total_count": 1, "jobs": [job]}), "500")
        bad = deepcopy(job)
        bad["steps"][1]["conclusion"] = "skipped"
        for jobs in ([bad], [job, job], []):
            with self.assertRaises(artifact.ArtifactError):
                candidate.deploy_job({"total_count": len(jobs), "jobs": jobs})

    def test_log_projection_omits_raw_logs_and_rejects_wrong_duplicate_or_untyped_proofs(self):
        projected = self.evidence()
        self.assertEqual(projected["jobLogSha256"], sha256(log()).hexdigest())
        self.assertNotIn("synthetic-private-log-only-value", json.dumps(projected))
        self.assertFalse(projected["liveReadback"])
        for raw in (log({**PROOF, "archiveSha256": "f" * 64}), log() + log(),
                    log(result={**RESULT, "apiStatusEnabled": "false"}),
                    log(result={**RESULT, "secret": "synthetic-private-value"}),
                    log().replace(b"Verified 1 isolated", b"Verified 2 isolated") + b"2026-11-12T00:00:04Z Verified 1 isolated D1 migration records.\n"):
            with self.assertRaises(artifact.ArtifactError):
                candidate.deployment_proofs(raw, PROOF)

    def test_expectations_are_names_and_booleans_without_claiming_live_binding_inventory(self):
        config = self.configuration()
        self.assertIn("SHORTLINK", config["bindingNames"])
        self.assertEqual(config["bindingInventoryStatus"], "Not run")
        self.assertFalse(config["liveVerified"])
        for flags, names, module in (("{\"apiStatusEnabled\":true}", "[]", b""),
                ("{\"productionReady\":true}", "[]", b""), ("{}", '["https://private.invalid"]', b""),
                ("{}", '["SHORTLINK","SHORTLINK"]', b""), ("{}", "[]", b"missing bindings")):
            with self.assertRaises(artifact.ArtifactError):
                candidate.expectations(flags, names, self.evidence(), module)

    def test_package_cannot_promote_ci_or_historical_deployment_to_production_readiness(self):
        run = candidate.run_metadata(RUN, "300", "1", REVISION, 400, candidate.DEPLOY_WORKFLOW)
        manifest = candidate.make_manifest(PROOF, ISOLATION, self.evidence(), run, self.configuration(),
            source_kind="not-supplied", source_sha="")
        self.assertFalse(manifest["productionReady"])
        self.assertFalse(manifest["productionMutationPerformed"])
        for key in ("liveVersionBindingsMigrations", "realSQLiteRehearsal", "humanTelegramAcceptance", "syntheticIsolationAcceptance"):
            self.assertEqual(manifest["validation"][key]["status"], "Not run")
        self.assertFalse(manifest["recovery"]["sqliteFallbackAllowed"])
        with TemporaryDirectory() as temp:
            output = Path(temp) / "candidate"
            digest = candidate.write_package(output, manifest)
            self.assertEqual(sha256((output / "candidate.json").read_bytes()).hexdigest(), digest)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "candidate.json").stat().st_mode), 0o600)
            self.assertEqual({file.name for file in output.iterdir()}, {"candidate.json", "candidate.sha256", "review.md"})
            self.assertNotIn("synthetic-private-log-only-value", (output / "candidate.json").read_text())
            with self.assertRaises(FileExistsError):
                candidate.write_package(output, manifest)
        with self.assertRaises(artifact.ArtifactError):
            candidate.make_manifest(PROOF, {**ISOLATION, "migrations": []}, self.evidence(), run, self.configuration(), source_kind="not-supplied", source_sha="")
        with self.assertRaises(artifact.ArtifactError):
            candidate.make_manifest(PROOF, ISOLATION, self.evidence(), run, self.configuration(), source_kind="real-sqlite", source_sha="f" * 64)

    def test_shortlink_metadata_is_exact_and_disabled_configuration_retains_binding_expectations(self):
        for enabled in (False, True):
            result = {**RESULT, **candidate.SERVICE_METADATA, "externalShortlinksEnabled": enabled}
            evidence = candidate.deployment_proofs(log(result=result), PROOF)
            runtime_names = candidate.BASE_BINDINGS | {"TELEGRAM_INLINE_SEARCH", "SHORTLINK", "SHORTLINK_BUSINESS_TOKEN"}
            if enabled:
                runtime_names.add("TELEGRAM_EXTERNAL_SHORTLINKS")
            configuration = candidate.expectations("{}", "[]", evidence, " ".join(runtime_names).encode())
            self.assertTrue(candidate.SHORTLINK_BINDINGS <= set(configuration["bindingNames"]))
            self.assertIn({"binding": "SHORTLINK", "service": "shortlink-new", "entrypoint": "ShortlinkService", "status": "Not run"}, configuration["serviceExpectations"])
        for result in ({**RESULT, "externalShortlinksEnabled": True},
                       {**RESULT, **candidate.SERVICE_METADATA},
                       {**RESULT, **candidate.SERVICE_METADATA, "externalShortlinkService": "other", "externalShortlinksEnabled": True},
                       {**RESULT, "externalShortlinkService": "shortlink-new", "externalShortlinksEnabled": True}):
            with self.assertRaises(artifact.ArtifactError):
                candidate.deployment_proofs(log(result=result), PROOF)

    def test_manifest_migrations_project_only_the_verified_name_and_digest(self):
        isolation = deepcopy(ISOLATION)
        isolation["migrations"][0]["unexpectedPrivateValue"] = "synthetic-must-never-enter-package"
        run = candidate.run_metadata(RUN, "300", "1", REVISION, 400, candidate.DEPLOY_WORKFLOW)
        manifest = candidate.make_manifest(PROOF, isolation, self.evidence(), run, self.configuration(),
            source_kind="not-supplied", source_sha="")
        self.assertEqual(manifest["artifact"]["migrations"], ISOLATION["migrations"])
        self.assertNotIn("synthetic-must-never-enter-package", json.dumps(manifest))

    def test_download_redirect_never_forwards_github_authorization_to_storage(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *_args): return False
            def read(self, _limit): return b"synthetic job log"
        calls = []
        def open_request(request, **_kwargs):
            calls.append(request)
            if len(calls) == 1:
                self.assertTrue(request.full_url.startswith(artifact.API_ROOT + "/actions/jobs/500/logs"))
                self.assertIsNotNone(request.get_header("Authorization"))
                raise HTTPError(request.full_url, 302, "redirect", {"Location": "https://fixture.blob.core.windows.net/private?sig=synthetic"}, None)
            self.assertIsNone(request.get_header("Authorization"))
            return Response()
        with patch.object(artifact._OPENER, "open", side_effect=open_request):
            self.assertEqual(candidate.download_job_log("500", "synthetic-gh-read-token"), b"synthetic job log")
        for location in ("http://fixture.blob.core.windows.net/private", "https://api.cloudflare.com/private", "https://user:password@fixture.blob.core.windows.net/private"):
            with patch.object(artifact._OPENER, "open", side_effect=HTTPError("https://api.github.com", 302, "redirect", {"Location": location}, None)):
                with self.assertRaises(artifact.ArtifactError):
                    candidate.download_job_log("500", "synthetic-gh-read-token")

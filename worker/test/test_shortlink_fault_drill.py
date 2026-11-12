"""Hosted synthetic coverage for canary containment and independent restoration."""

from copy import deepcopy
from dataclasses import asdict, replace
from io import BytesIO
from pathlib import Path
import json
import sqlite3
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase
from unittest.mock import patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import shortlink_fault_drill as drill
import d1_migrations as migrations
from cloudflare_isolation import CloudflareError, _Deployment, _Version

KEY = bytes(range(32))
REVISION = "a" * 40
IDS = {name: f"00000000-0000-4000-8000-{number:012d}" for number, name in enumerate(("original", "recovery", "canary", "foreign"), 1)}
BASE_TAG = "batch-ready-" + "b" * 64
REAL_DIGEST = "c" * 64
NORMAL = _Version(REVISION, "d" * 64, "2026-07-30", drill.external.release_tag(BASE_TAG, REAL_DIGEST, True),
    telegram_config_sha256="e" * 64, telegram_aggregate_key_sha256="f" * 64,
    external_shortlink_capable=True, external_shortlink_token_sha256=REAL_DIGEST,
    external_shortlink_base_tag=BASE_TAG, telegram_external_shortlinks=True)


def checkpoint():
    return {"version": 1, "revision": REVISION, "operationRunId": "100", "operationRunAttempt": "2",
        "cohort": "0123456789abcdef", "scopeSha256": "1" * 64, "createdAt": 500,
        **{name + "VersionId": IDS[name] for name in ("original", "recovery", "canary")},
        "originalVersion": asdict(NORMAL), "canaryVersion": asdict(drill.canary_version(NORMAL)),
        "workerConfigSha256": "2" * 64,
        "ciProof": {"revision": REVISION, "runId": "50", "runAttempt": "1", "artifactId": "60", "archiveSha256": "3" * 64},
        "receiptBaseline": {"version": 1, "phase": "prepare", "identity": "4" * 64,
            "afterReceiptId": 10, "authEpochSha256": "5" * 64}}


class Scope:
    def __init__(self, current="canary"):
        self.current = _Deployment("00000000-0000-4000-8000-000000000010", IDS[current], None)
        self.versions = {IDS["original"]: NORMAL, IDS["recovery"]: NORMAL, IDS["canary"]: drill.canary_version(NORMAL), IDS["foreign"]: NORMAL}

    def active(self):
        return self.current

    def version(self, version_id):
        return self.versions[version_id]


class Context:
    def __init__(self, directory, current="canary"):
        self.scope = Scope(current)
        self.directory = Path(directory)
        self.env = {"GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "2"}
        self.config_valid = True
        self.activations = []
        self.fail_activation = False
        self.health_available = True
        self.health_checks = []

    def verify(self, _checkpoint, *, current=False, healthy=True):
        drill._require(self.config_valid and current, drill.ERROR)
        if healthy:
            self.health_checks.append(self.scope.active().version)
            drill._require(self.health_available, drill.ERROR)

    def idle(self):
        return None

    def activate(self, previous, target_id, current, target, message, guard):
        guard()
        if self.scope.active() != previous:
            raise CloudflareError("Synthetic deployment drift")
        self.activations.append(target_id)
        self.scope.current = _Deployment("00000000-0000-4000-8000-000000000011", target_id, message)
        if target_id == IDS["recovery"]:
            self.health_available = True
        if self.fail_activation:
            self.fail_activation = False
            raise CloudflareError("Synthetic uncertain activation", uncertain=True)
        return self.scope.current


class CheckpointTests(TestCase):
    def test_actual_migration_readback_crosses_only_readonly_schema_and_pragma_gate(self):
        directory = Path(__file__).resolve().parents[1] / "migrations"
        entries = [{"name": path.name, "sha256": drill.sha256(path.read_bytes()).hexdigest()}
            for path in sorted(directory.glob("*.sql"))]
        chain = migrations._load_migrations(directory, {"version": 2, "migrations": entries})
        self.assertGreaterEqual(len(chain), 54)
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.row_factory = sqlite3.Row
        for entry in entries:
            db.executescript((directory / entry["name"]).read_text())
        db.execute(migrations.LEDGER_SQL)
        db.executemany("INSERT INTO subs_bot_schema_migrations(position,name,sha256,mode) VALUES(?,?,?,'applied')",
            [(position, entry["name"], entry["sha256"]) for position, entry in enumerate(entries, 1)])
        db_path, bucket = "/accounts/synthetic/d1/database/synthetic", "/accounts/synthetic/r2/buckets/synthetic"
        seen = []
        def api(method, path, payload):
            self.assertTrue(drill.readonly_data_request(method, path, payload, db_path, bucket))
            sql = payload["sql"]
            statements = tuple(migrations._statements(sql if sql.endswith(";") else sql + ";"))
            seen.append(statements)
            return [{"success": True, "results": [dict(row) for row in db.execute(statement)]} for statement in statements]
        with patch.object(migrations, "MAX_D1_STATEMENT_BYTES", 70_000):
            state, history = migrations._read_state(api, db_path, chain)
        self.assertEqual((state, len(history)), ("managed", len(chain)))
        self.assertTrue(any(len(batch) > 1 for batch in seen))
        self.assertTrue(any(statement.startswith("PRAGMA ") for batch in seen for statement in batch))
        for sql in ("UPDATE subscriptions SET name='synthetic'", "SELECT 1;DELETE FROM subscriptions;", "PRAGMA journal_mode(WAL)"):
            self.assertFalse(drill.readonly_data_request("POST", db_path + "/query", {"sql": sql}, db_path, bucket))
        self.assertFalse(drill.readonly_data_request("POST", db_path + "-other/query", {"sql": "SELECT 1"}, db_path, bucket))
        self.assertFalse(drill.readonly_data_request("GET", bucket + "/objects/private", None, db_path, bucket))

    def test_canary_only_changes_business_digest_and_derived_tag(self):
        canary = drill.canary_version(NORMAL)
        changed = {key for key, value in asdict(NORMAL).items() if asdict(canary)[key] != value}
        self.assertEqual(changed, {"tag", "external_shortlink_token_sha256"})
        self.assertRegex(drill.INVALID_TOKEN, drill.external.TOKEN)
        self.assertEqual(canary.external_shortlink_token_sha256, drill.INVALID_DIGEST)
        with self.assertRaisesRegex(CloudflareError, "separate reviewed operation"):
            drill.external.target(canary, None, "sl_" + "z" * 64, capable=True,
                telegram_digest=NORMAL.telegram_config_sha256, aggregate_digest=NORMAL.telegram_aggregate_key_sha256)
        for invalid in (replace(NORMAL, telegram_external_shortlinks=False), replace(NORMAL, telegram_page_jump_epoch=2)):
            with self.assertRaises(CloudflareError):
                drill.canary_version(invalid)

    def test_checkpoint_hmac_scope_attempt_and_difference_whitelist(self):
        body = checkpoint()
        sealed = drill.seal(KEY, body)
        self.assertEqual(drill.open_checkpoint(KEY, sealed, body["scopeSha256"], run_id="100", attempt="2")[0], body)
        for changed in ({**sealed, "cohort": "f" * 16}, {**sealed, "recoveryVersionId": IDS["foreign"]}):
            with self.assertRaises(CloudflareError):
                drill.open_checkpoint(KEY, changed, body["scopeSha256"])
        for scope, attempt in (("6" * 64, "2"), (body["scopeSha256"], "1")):
            with self.assertRaises(CloudflareError):
                drill.open_checkpoint(KEY, sealed, scope, run_id="100", attempt=attempt)
        for name, value in (("telegram_inline_search", True), ("digest", "7" * 64), ("external_shortlink_base_tag", "other")):
            changed = deepcopy(body)
            changed["canaryVersion"][name] = value
            with self.assertRaises(CloudflareError):
                drill.open_checkpoint(KEY, drill.seal(KEY, changed), body["scopeSha256"])
        leaked = json.dumps(sealed)
        self.assertNotIn(drill.INVALID_TOKEN, leaked)
        self.assertNotIn("/s/", leaked)
        self.assertNotIn("https://", leaked)

    def test_recovery_metadata_accepts_failure_and_cancellation_but_not_foreign_provenance(self):
        base = {"id": 100, "run_attempt": 2, "workflow_id": 300, "path": drill.WORKFLOW_PATH,
            "event": "workflow_dispatch", "head_branch": "main", "head_sha": REVISION,
            "status": "completed", "conclusion": "failure", "repository": {"id": drill.artifact.REPOSITORY_ID},
            "head_repository": {"id": drill.artifact.REPOSITORY_ID}}
        for status, conclusion in (("completed", "failure"), ("completed", "cancelled"), ("in_progress", None)):
            self.assertEqual(drill.recovery_run_metadata({**base, "status": status, "conclusion": conclusion}, "100", "2", 300), REVISION)
        for field, value in (("run_attempt", 1), ("workflow_id", 301), ("path", ".github/workflows/other.yml"),
                ("event", "pull_request"), ("head_branch", "feature"), ("head_repository", {"id": 7})):
            with self.subTest(field=field), self.assertRaises(CloudflareError):
                drill.recovery_run_metadata({**base, field: value}, "100", "2", 300)

    def test_recovery_archive_requires_exact_attempt_digest_and_single_projected_file(self):
        value = drill.seal(KEY, checkpoint())
        data = BytesIO()
        with ZipFile(data, "w") as archive:
            archive.writestr(drill.CHECKPOINT, json.dumps(value))
        raw = data.getvalue()
        run = {"id": 100, "run_attempt": 2, "workflow_id": 300, "path": drill.WORKFLOW_PATH,
            "event": "workflow_dispatch", "head_branch": "main", "head_sha": REVISION, "status": "completed",
            "repository": {"id": drill.artifact.REPOSITORY_ID}, "head_repository": {"id": drill.artifact.REPOSITORY_ID}}
        entry = {"name": f"{drill.PREFIX}-100-2", "expired": False, "id": 400, "digest": "sha256:" + drill.sha256(raw).hexdigest()}
        def get(path, _token):
            if path.startswith("/actions/workflows/"):
                return {"id": 300, "path": drill.WORKFLOW_PATH}
            if "/artifacts?" in path:
                return {"total_count": 1, "artifacts": [entry]}
            return run
        with patch.object(drill.artifact, "_get_json", get), patch.object(drill.artifact, "_download", return_value=raw):
            self.assertEqual(drill.read_recovery_artifact("100", "2", "synthetic"), value)
            entry["digest"] = "sha256:" + "0" * 64
            with self.assertRaises(CloudflareError):
                drill.read_recovery_artifact("100", "2", "synthetic")


class RestorationTests(TestCase):
    def test_unhealthy_canary_does_not_prevent_verified_recovery_activation(self):
        with TemporaryDirectory() as directory:
            ctx = Context(directory)
            ctx.health_available = False
            drill.restore(ctx, checkpoint(), NORMAL, drill.canary_version(NORMAL))
            self.assertEqual(ctx.activations, [IDS["recovery"]])
            self.assertEqual(ctx.health_checks, [IDS["recovery"]])

    def test_restore_only_known_verified_versions_and_is_idempotent(self):
        with TemporaryDirectory() as directory:
            ctx = Context(directory)
            with patch.object(drill.artifact, "require_current_main", side_effect=AssertionError("Recovery must survive main advancing")):
                result = drill.restore(ctx, checkpoint(), NORMAL, drill.canary_version(NORMAL))
                self.assertEqual(result["phase"], "restored")
                self.assertEqual(ctx.activations, [IDS["recovery"]])
                drill.restore(ctx, checkpoint(), NORMAL, drill.canary_version(NORMAL))
                self.assertEqual(ctx.activations, [IDS["recovery"]])
            for current in ("foreign", "original"):
                other = Context(directory, current)
                if current == "foreign":
                    with self.assertRaises(CloudflareError):
                        drill.restore(other, checkpoint(), NORMAL, drill.canary_version(NORMAL))
                else:
                    drill.restore(other, checkpoint(), NORMAL, drill.canary_version(NORMAL))
                self.assertEqual(other.activations, [])

    def test_config_or_module_drift_never_gets_overwritten(self):
        with TemporaryDirectory() as directory:
            for field in ("config", "module"):
                ctx = Context(directory)
                if field == "config":
                    ctx.config_valid = False
                else:
                    ctx.scope.versions[IDS["canary"]] = replace(drill.canary_version(NORMAL), digest="0" * 64)
                with self.assertRaises(CloudflareError):
                    drill.restore(ctx, checkpoint(), NORMAL, drill.canary_version(NORMAL))
                self.assertEqual(ctx.activations, [])

    def test_timeout_poll_error_and_uncertain_activation_all_restore_normal(self):
        with TemporaryDirectory() as directory:
            for scenario in ("timeout", "poll-error", "uncertain-activation", "success"):
                ctx = Context(directory, "original")
                ctx.fail_activation = scenario == "uncertain-activation"
                counter = [0]
                def clock():
                    counter[0] += 1
                    return counter[0]
                kwargs = {"side_effect": CloudflareError("Synthetic poll error")} if scenario == "poll-error" else {
                    "return_value": {"phase": "fallback-verified"} if scenario == "success" else None}
                with patch.object(drill, "time", return_value=501), patch.object(drill.artifact, "require_current_main"), \
                        patch.object(drill, "failure_evidence", **kwargs):
                    if scenario == "success":
                        self.assertEqual(drill.run_drill(ctx, checkpoint(), NORMAL, drill.canary_version(NORMAL),
                            wait=lambda _seconds: None, clock=clock, poll_seconds=3)["phase"], "fallback-verified")
                    else:
                        with self.assertRaises(CloudflareError):
                            drill.run_drill(ctx, checkpoint(), NORMAL, drill.canary_version(NORMAL),
                                wait=lambda _seconds: None, clock=clock, poll_seconds=3)
                self.assertEqual(ctx.scope.active().version, IDS["recovery"], scenario)
                self.assertEqual(ctx.activations[-1], IDS["recovery"])


class FailureEvidenceTests(TestCase):
    def test_only_sent_cohort_links_with_one_terminal_external_attempt_are_evidence(self):
        codes = {"admin": "A" * 21 + "s", "member": "B" * 21 + "s"}
        history = [{"state": "sent", "message_date": 502}, {"state": "sent", "message_date": 503}]
        class Cohort:
            targets = {"admin": "https://example.com/synthetic", "member": "https://example.org/synthetic"}
            def history(self, _after):
                return deepcopy(history)
            def inspect(self, _prior, *, retired):
                return {"codeSha256": {role: drill.sha256(code.encode()).hexdigest() for role, code in codes.items()}}, codes, "stable"
        class EvidenceContext:
            key = KEY
            policy = {"botId": drill.POLICY_IDS["botId"]}
            current = {"operation_id": IDS["original"], "domain": "gfw.mom", "attempts": 1, "terminal": 1,
                "short_url": None, "lease_id": None, "lease_until": None}
            def cohort(self, _name):
                return Cohort()
            def read(self, _sql, bot, local_hash):
                row = dict(self.current)
                if local_hash == drill.sha256((drill.ORIGIN + "/s/" + codes["member"]).encode()).hexdigest():
                    row["operation_id"] = IDS["recovery"]
                return [row]
        ctx = EvidenceContext()
        with patch.object(drill, "probe_code", return_value={"GET": 302, "HEAD": 302}):
            result = drill.failure_evidence(ctx, checkpoint(), 501)
            self.assertEqual(result["rpcFailureFallbackEvidence"], "Passed")
            self.assertEqual(result["httpResponseStatusObserved"], "Not run")
            self.assertNotIn(codes["admin"], json.dumps(result))
            self.assertNotIn("https://", json.dumps(result))
            for name, value in (("attempts", 2), ("terminal", 0), ("short_url", "https://gfw.mom/synthetic"),
                    ("lease_id", IDS["foreign"]), ("domain", "other.example")):
                original = ctx.current[name]
                ctx.current[name] = value
                with self.subTest(name=name), self.assertRaises(CloudflareError):
                    drill.failure_evidence(ctx, checkpoint(), 501)
                ctx.current[name] = original
            history[0]["state"] = "failed"
            with self.assertRaises(CloudflareError):
                drill.failure_evidence(ctx, checkpoint(), 501)
            history[0]["state"] = "pending"
            self.assertIsNone(drill.failure_evidence(ctx, checkpoint(), 501))

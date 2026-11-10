"""Hosted SQLite and Worker API fault tests for one-shot page-jump activation."""

from dataclasses import asdict, replace
from hashlib import sha256
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from test_page_jump_control import BOT, TARGET, WORKER, MemoryD1, current

import cloudflare_isolation as cloudflare
import page_jump_activation as activation
import page_jump_open as opening
import page_jump_recovery as recovery
import page_jump_rollback as rollback
from page_jump_control import PageJumpControl, PageJumpGate
from stage_page_jump_isolation import _digest


PREDECESSOR = "00000000-0000-4000-8000-000000000010"
PRIOR_VERSION = "00000000-0000-4000-8000-000000000020"
CANDIDATE = "00000000-0000-4000-8000-000000000030"
DEPLOYMENT = "00000000-0000-4000-8000-000000000040"
RESTORED = "00000000-0000-4000-8000-000000000050"
CONFIG = '{"botId":"' + BOT + '"}'
SOURCE = {"archiveSha256": "f" * 64}
STAGE_RUN = 101
ACTIVATE_RUN = 105
PAUSE_RUN = 110
ROLLBACK_RUN = 112
OPEN_RUN = 116
VERIFY_STAGE_BUILD = activation._verify_stage_build


class Scope(cloudflare._Isolation):
    def __init__(self, db):
        super().__init__(self.call, db, TARGET)
        self.previous = cloudflare._Deployment(PREDECESSOR, PRIOR_VERSION, "synthetic predecessor")
        self.live = self.previous
        self.prior = cloudflare._Version("a" * 40, "b" * 64, "2026-07-30", "synthetic",
                                         telegram_config_sha256=sha256(CONFIG.encode()).hexdigest(),
                                         telegram_page_jump_control_capable=True)
        self.desired = replace(self.prior, tag=cloudflare._page_jump_tag(self.prior.tag, STAGE_RUN, self.prior.digest),
                               telegram_page_jump_epoch=STAGE_RUN)
        self.posts = []
        self.on_post = None

    def verify_resources(self):
        pass

    def worker_config(self):
        return ("synthetic",)

    def cron_enabled(self):
        return True

    def active(self):
        return self.live

    def version(self, version_id, *, page_jump_epoch=None):
        if version_id == PRIOR_VERSION and page_jump_epoch is None:
            return self.prior
        if version_id == CANDIDATE and page_jump_epoch == STAGE_RUN:
            return self.desired
        raise AssertionError("Unexpected version read.")

    def staged(self, desired):
        return CANDIDATE if self.desired == desired else None

    def call(self, method, path, data):
        if method != "POST" or path != self.deployments or data["strategy"] != "percentage":
            raise AssertionError("Unexpected Worker request.")
        expected = CANDIDATE if not self.posts else PRIOR_VERSION
        if data["versions"] != [{"version_id": expected, "percentage": 100}]:
            raise AssertionError("Unexpected version allocation.")
        self.posts.append(data)
        if self.on_post:
            return self.on_post()
        self.apply_post()
        return {"id": self.live.id}

    def apply_post(self):
        last = self.posts[-1]
        target = last["versions"][0]["version_id"]
        self.live = cloudflare._Deployment(DEPLOYMENT if target == CANDIDATE else RESTORED, target,
                                           last["annotations"]["workers/message"])


class PageJumpActivationTests(TestCase):
    def setUp(self):
        self.db = MemoryD1()
        self.addCleanup(self.db.db.close)
        migration = (WORKER / "migrations" / activation.MIGRATION).read_bytes()
        self.assertEqual(sha256(migration).hexdigest(), activation.MIGRATION_SHA256)
        self.db.db.executescript(migration.decode("utf-8"))
        with self.db.db:
            self.db.db.execute("INSERT INTO subs_bot_schema_migrations VALUES (45,?,?,'applied')",
                               (activation.MIGRATION, activation.MIGRATION_SHA256))
        self.scope = Scope(self.db)
        self.control = PageJumpControl(self.scope, BOT)
        self.journal = activation.PageJumpActivationJournal(self.control)
        self.reserved = self.control.reserve(None, STAGE_RUN, current)
        self.stage = {
            "epoch": STAGE_RUN,
            "revision": self.scope.prior.revision,
            "bundleSha256": self.scope.prior.digest,
            "checkpoint": {"activeSha256": _digest({"scope": TARGET, "deployment": asdict(self.scope.previous),
                                                    "version": cloudflare.version_evidence(self.scope.prior)})},
            "reservedGateSha256": _digest(asdict(self.reserved)),
            "candidateSha256": _digest({"versionId": CANDIDATE, "version": cloudflare.version_evidence(self.scope.desired)}),
        }
        reader = patch.object(activation, "read_source", return_value=self.stage)
        self.read_source = reader.start()
        self.addCleanup(reader.stop)
        delays = patch.object(activation, "READBACK_DELAYS", (0,))
        delays.start()
        self.addCleanup(delays.stop)
        for check in ("_verify_stage_build", "_verify_health"):
            checker = patch.object(activation, check)
            checker.start()
            self.addCleanup(checker.stop)

    def activate(self, *, source=SOURCE, run_id=ACTIVATE_RUN):
        return activation.activate_once(self.scope, source, CONFIG, current, run_id=run_id,
                                        revision=self.stage["revision"], bundle=WORKER)

    def reconcile(self):
        return activation.reconcile_activation(
            self.scope, CONFIG, current, epoch=STAGE_RUN, stage_sha256=SOURCE["archiveSha256"])

    def test_confirmed_closed_activation_and_same_stage_rerun_do_not_repeat(self):
        record = self.activate()
        self.read_source.assert_called_once_with(SOURCE, "stage")
        self.assertEqual(record.deployment_id, DEPLOYMENT)
        self.assertEqual(self.scope.live.message, record.intent.message)
        self.assertEqual(self.control.observe().gate, self.reserved)
        self.assertEqual(self.journal.read(STAGE_RUN), record)
        self.journal.require_clear()
        self.assertEqual(self.activate(run_id=106), record)
        self.read_source.reset_mock()
        self.assertEqual(self.reconcile(), record)
        self.read_source.assert_not_called()
        self.assertEqual(len(self.scope.posts), 1)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "closed page-jump stage changed"):
            self.activate(source={"archiveSha256": "e" * 64})

    def test_lost_d1_claim_ack_does_not_authorize_cloud_post(self):
        self.db.fault = "lost"
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent") as failure:
            self.activate()
        self.assertTrue(failure.exception.uncertain)
        self.assertIsNone(self.journal.read(STAGE_RUN).deployment_id)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "remains unresolved"):
            self.journal.require_clear()
        for action in (self.activate, self.reconcile):
            with self.subTest(action=action.__name__), self.assertRaisesRegex(cloudflare.CloudflareError,
                                                                            "Reconcile the existing intent"):
                action()
        self.assertEqual(self.scope.posts, [])

    def test_cloud_ack_and_d1_confirmation_ack_can_both_be_lost(self):
        def lost_cloud_ack():
            self.scope.apply_post()
            self.db.fault = "lost"
            raise cloudflare.CloudflareError("synthetic lost activation acknowledgement", uncertain=True)

        self.scope.on_post = lost_cloud_ack
        result = self.activate()
        self.assertEqual(result.deployment_id, DEPLOYMENT)
        self.assertEqual(self.reconcile(), result)
        self.assertEqual(len(self.scope.posts), 1)

    def test_lost_release_guard_after_claim_leaves_only_reconciliation(self):
        calls = iter((None, False))
        with self.assertRaisesRegex(cloudflare.CloudflareError, "main revision changed"):
            activation.activate_once(self.scope, SOURCE, CONFIG, lambda: next(calls), run_id=ACTIVATE_RUN,
                                     revision=self.stage["revision"], bundle=WORKER)
        self.assertIsNone(self.journal.read(STAGE_RUN).deployment_id)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
            self.activate()
        self.assertEqual(self.scope.posts, [])

    def test_workflow_activation_rejects_other_main_and_requires_stage_artifact_check_before_post(self):
        with patch.object(activation, "_verify_stage_build", side_effect=cloudflare.CloudflareError("Synthetic artifact mismatch.")) as verify:
            with self.assertRaisesRegex(cloudflare.CloudflareError, "closed page-jump stage changed"):
                activation.activate_once(self.scope, SOURCE, CONFIG, current, run_id=ACTIVATE_RUN,
                                         revision="0" * 40, bundle=WORKER)
            verify.assert_not_called()
            with self.assertRaisesRegex(cloudflare.CloudflareError, "Synthetic artifact mismatch"):
                activation.activate_once(self.scope, SOURCE, CONFIG, current, run_id=ACTIVATE_RUN,
                                         revision=self.stage["revision"], bundle=WORKER)
            verify.assert_called_once_with(self.scope, WORKER, self.stage)
        self.assertIsNone(self.journal.read(STAGE_RUN))
        self.assertEqual(self.scope.posts, [])

    def test_original_stage_proof_pins_exact_ci_archive_and_complete_d1_history(self):
        with TemporaryDirectory() as directory:
            bundle = Path(directory) / "subs-bot-verified"
            bundle.mkdir()
            manifest = {"revision": self.stage["revision"], "bundleSha256": self.stage["bundleSha256"],
                        "runId": "51", "runAttempt": "3"}
            raw = json.dumps(manifest).encode("ascii")
            (bundle / "isolation.json").write_bytes(raw)
            proof = {"revision": manifest["revision"], "runId": "51", "runAttempt": "3",
                     "artifactId": "73", "archiveSha256": "e" * 64}
            proof_path = bundle.parent / "subs-bot-isolation-artifact-proof.json"
            proof_path.write_text(json.dumps(proof), encoding="ascii")
            proof_path.chmod(0o600)
            stage = {**self.stage, "ciManifestSha256": sha256(raw).hexdigest(), "ciRunId": "51", "ciRunAttempt": "3",
                     "ciArtifactId": "73", "ciArchiveSha256": "e" * 64}
            migrations = [object()] * 44 + [SimpleNamespace(name=activation.MIGRATION, sha256=activation.MIGRATION_SHA256)]
            with patch.object(activation, "_load_migrations", return_value=migrations) as load, patch.object(
                    activation, "_read_state", return_value=("managed", migrations[:-1])) as state:
                with self.assertRaisesRegex(cloudflare.CloudflareError, "closed page-jump stage changed"):
                    VERIFY_STAGE_BUILD(self.scope, bundle, {**stage, "ciRunAttempt": "2"})
                load.assert_not_called()
                with self.assertRaisesRegex(cloudflare.CloudflareError, "closed page-jump stage changed"):
                    VERIFY_STAGE_BUILD(self.scope, bundle, stage)
                state.return_value = ("managed", migrations)
                VERIFY_STAGE_BUILD(self.scope, bundle, stage)

    def test_reconcile_workflow_uses_exact_durable_stage_pin(self):
        record = self.activate()
        confirm = f"reconcile page jump for {cloudflare.WORKER_NAME}"
        selected = {"epoch": STAGE_RUN, "stageSha256": SOURCE["archiveSha256"]}
        self.assertEqual(activation.activation_inputs("reconcile", confirm, json.dumps(selected)), selected)
        for raw in ('{"epoch":true,"stageSha256":"' + "f" * 64 + '"}', json.dumps({**selected, "stageSha256": "invalid"})):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "activation inputs"):
                activation.activation_inputs("reconcile", confirm, raw)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "closed page-jump stage changed"):
            activation.reconcile_activation(self.scope, CONFIG, current, epoch=STAGE_RUN, stage_sha256="e" * 64)
        self.assertEqual(activation.reconcile_activation(
            self.scope, CONFIG, current, epoch=STAGE_RUN, stage_sha256=SOURCE["archiveSha256"]), record)
        self.assertEqual(len(self.scope.posts), 1)

    def test_unknown_commit_blocks_other_bot_and_reconciles_after_pause(self):
        def delayed_commit():
            raise cloudflare.CloudflareError("synthetic delayed activation", uncertain=True)

        self.scope.on_post = delayed_commit
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
            self.activate()
        pending = self.journal.read(STAGE_RUN)
        other = PageJumpControl(self.scope, "456")
        other_gate = other.reserve(None, 109, current)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "remains unresolved"):
            activation.PageJumpActivationJournal(other).claim(replace(pending.intent, epoch=109, intent_run_id=110), other_gate)
        paused = self.control.pause(self.reserved, 111, current)
        self.assertEqual(paused, PageJumpGate(111, False, 0))
        self.scope.apply_post()
        self.assertEqual(self.reconcile().deployment_id, DEPLOYMENT)
        self.assertEqual(self.control.observe().gate, paused)
        self.assertEqual(len(self.scope.posts), 1)

    def test_other_candidate_message_and_version_digest_cannot_confirm(self):
        def wrong_message():
            self.scope.apply_post()
            self.scope.live = replace(self.scope.live, message="another synthetic operation")
            return {"id": DEPLOYMENT}

        self.scope.on_post = wrong_message
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
            self.activate()
        self.scope.apply_post()
        original = self.scope.desired
        self.scope.desired = replace(original, digest="c" * 64)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
            self.reconcile()
        self.assertIsNone(self.journal.read(STAGE_RUN).deployment_id)
        self.scope.desired = original
        self.assertEqual(self.reconcile().deployment_id, DEPLOYMENT)
        self.assertEqual(len(self.scope.posts), 1)

    def test_atomic_claim_checks_closed_gate_and_exact_migration_pin(self):
        self.db.before_write = lambda: self.control.pause(self.reserved, 111, current)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
            self.activate()
        self.assertIsNone(self.journal.read(STAGE_RUN))
        with self.db.db:
            self.db.db.execute("UPDATE subs_bot_schema_migrations SET sha256=? WHERE position=45", ("0" * 64,))
        with self.assertRaisesRegex(cloudflare.CloudflareError, "journal could not be verified"):
            self.journal.require_clear()
        self.assertEqual(self.scope.posts, [])

    def pause(self):
        return rollback.pause_durable(self.scope, CONFIG, current, epoch=STAGE_RUN, stage_sha256=SOURCE["archiveSha256"],
                                      revision=self.stage["revision"], run_id=PAUSE_RUN, attempt=1)

    def restore(self, proof):
        source = {"runId": str(PAUSE_RUN), "runAttempt": "1", "revision": self.stage["revision"], "archiveSha256": "c" * 64}
        with patch.object(rollback, "read_source", side_effect=lambda pin, kind: recovery._validate_source(proof, pin, kind)):
            return rollback.rollback_once(self.scope, source, CONFIG, current, run_id=ROLLBACK_RUN)

    def test_durable_pause_and_exact_predecessor_rollback_require_real_drain(self):
        self.activate()
        with patch.object(activation, "_verify_health", side_effect=AssertionError("Unhealthy recovery must still work.")):
            proof = self.pause()
            self.assertEqual(self.pause(), proof)
            receipt = self.db.receipt(state="pending")
            with self.assertRaisesRegex(cloudflare.CloudflareError, "replies have not drained"):
                self.restore(proof)
            self.assertEqual(len(self.scope.posts), 1)
            with self.db.db:
                self.db.db.execute("UPDATE telegram_outbox SET state='failed' WHERE receipt_id=?", (receipt,))
            for changed, error in (({"operationRunAttempt": 2}, "source artifact"),
                                   ({"pausedGateSha256": "0" * 64}, "recovery checkpoint"),
                                   ({"activeSha256": "0" * 64}, "recovery checkpoint")):
                with self.subTest(changed=changed), self.assertRaisesRegex(cloudflare.CloudflareError, error):
                    self.restore({**proof, **changed})
            self.assertEqual(len(self.scope.posts), 1)
            record = self.restore(proof)
        self.assertEqual(record.intent.restores_epoch, STAGE_RUN)
        self.assertEqual(record.deployment_id, RESTORED)
        self.assertEqual(self.scope.live.version, PRIOR_VERSION)
        self.assertEqual(self.control.observe().gate, PageJumpGate(PAUSE_RUN, False, 0))
        self.assertEqual(self.restore(proof), record)
        self.journal.require_clear()
        self.assertEqual(len(self.scope.posts), 2)

    def test_ambiguous_rollback_never_posts_twice_and_reconciles_without_pause_archive(self):
        self.activate()
        proof = self.pause()

        def delayed_commit():
            raise cloudflare.CloudflareError("Synthetic delayed rollback.", uncertain=True)

        self.scope.on_post = delayed_commit
        for _ in range(2):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
                self.restore(proof)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "remains unresolved"):
            self.journal.require_clear()
        self.assertEqual(len(self.scope.posts), 2)
        self.scope.apply_post()
        with patch.object(rollback, "read_source", side_effect=AssertionError("Pause evidence expired.")):
            result = activation.reconcile_activation(self.scope, CONFIG, current, epoch=PAUSE_RUN,
                                                     stage_sha256=SOURCE["archiveSha256"])
        self.assertEqual(result.deployment_id, RESTORED)
        self.assertEqual(len(self.scope.posts), 2)

    def test_durable_pause_can_fence_still_unresolved_activation_on_predecessor(self):
        self.db.fault = "lost"
        with self.assertRaisesRegex(cloudflare.CloudflareError, "Reconcile the existing intent"):
            self.activate()
        proof = self.pause()
        self.assertEqual(proof["epoch"], PAUSE_RUN)
        self.assertEqual(self.scope.live.version, PRIOR_VERSION)
        with self.assertRaisesRegex(cloudflare.CloudflareError, "recovery checkpoint"):
            self.restore(proof)
        self.assertEqual(self.scope.posts, [])

    def open(self, revision=None):
        return opening.open_admission(self.scope, CONFIG, current, epoch=STAGE_RUN, stage_sha256=SOURCE["archiveSha256"],
                                      revision=revision or self.stage["revision"], run_id=OPEN_RUN, attempt=1)

    def test_open_confirms_bound_activation_and_pins_inbox_watermark_once(self):
        with patch.object(opening, "_verify_health") as health:
            with self.assertRaisesRegex(cloudflare.CloudflareError, "recovery checkpoint"):
                self.open()
            health.assert_not_called()
            self.activate()
            with self.assertRaisesRegex(cloudflare.CloudflareError, "open checkpoint"):
                self.open(revision="0" * 40)
            self.db.receipt()
            last = self.db.receipt()
            with self.db.db:
                self.db.db.execute("DELETE FROM telegram_inbox WHERE receipt_id=?", (last,))
            self.db.fault = "lost"
            proof = self.open()
            self.assertEqual(self.control.observe().gate, PageJumpGate(STAGE_RUN, True, last))
            self.db.receipt(state="pending")
            self.assertEqual(self.open(), proof)
            self.assertEqual(self.control.observe().gate, PageJumpGate(STAGE_RUN, True, last))
        self.assertEqual(len(self.scope.posts), 1)

    def test_open_does_not_win_racing_pause_or_require_health_for_pause(self):
        self.activate()
        with patch.object(opening, "_verify_health", side_effect=cloudflare.CloudflareError("Synthetic unhealthy release.")):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "unhealthy"):
                self.open()
        self.assertEqual(self.control.observe().gate, self.reserved)
        self.db.before_write = self.pause
        with patch.object(opening, "_verify_health"):
            with self.assertRaisesRegex(cloudflare.CloudflareError, "transition could not be confirmed"):
                self.open()
            with self.assertRaisesRegex(cloudflare.CloudflareError, "open checkpoint"):
                self.open()
        self.assertEqual(self.control.observe().gate, PageJumpGate(PAUSE_RUN, False, 0))

    def test_open_transaction_rechecks_confirmed_journal_before_writing_gate(self):
        self.activate()

        def lose_journal_confirmation():
            with self.db.db:
                self.db.db.execute(f"UPDATE {activation.JOURNAL} SET deployment_id=NULL WHERE epoch=?", (STAGE_RUN,))

        self.db.before_write = lose_journal_confirmation
        with patch.object(opening, "_verify_health"), self.assertRaisesRegex(cloudflare.CloudflareError,
                                                                           "transition could not be confirmed"):
            self.open()
        self.assertEqual(self.control.observe().gate, self.reserved)

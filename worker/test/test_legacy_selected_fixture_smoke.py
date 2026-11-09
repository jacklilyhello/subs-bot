from base64 import urlsafe_b64encode
import json
import os
from pathlib import Path
import sqlite3
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from test_legacy_empty_export_smoke import FixtureDatabase
import legacy_selected_fixture_smoke as smoke


COHORT = "a" * 32
REVISION = "b" * 40
PIN = {"revision": REVISION, "versionId": "11111111-2222-4333-8444-555555555555",
       "moduleSha256": "c" * 64, "compatibilityDate": "2026-11-06"}


class Objects:
    def __init__(self):
        self.rows = {"unrelated/object": b"foreign data"}
        self.writes = []
        self.lose_response = False

    def list_objects(self, bucket, *, prefix, maximum):
        assert bucket == smoke.WORKER_NAME and maximum == 2
        return [{"key": key, "size": len(body)} for key, body in self.rows.items() if key.startswith(prefix)]

    def request(self, method, key, body=None):
        if method == "GET":
            return self.rows.get(key)
        self.writes.append((method, key))
        if method == "PUT":
            assert key not in self.rows
            self.rows[key] = body
        else:
            assert method == "DELETE"
            self.rows.pop(key, None)
        if self.lose_response:
            raise smoke.CapacityError("Synthetic acknowledgement lost.")


class LegacySelectedFixtureTests(unittest.TestCase):
    def setUp(self):
        self.data = FixtureDatabase()
        self.addCleanup(self.data.db.close)
        self.data.db.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 100)
        self.data.db.execute("PRAGMA foreign_keys=ON")
        self.data.db.execute("""INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
            VALUES ('123','other','uploaded://other','synthetic-existing-token',1,1)""")
        self.data.db.commit()
        high_water, stamp = smoke.allocator(self.data)
        self.checkpoint = {"version": 1, "phase": "prepared", "cohort": COHORT, "revision": REVISION,
                           "identity": "d" * 64, "releasePin": PIN, "highWater": high_water,
                           "createdAt": stamp, "reserveUntil": stamp + 1800}
        self.objects = Objects()
        self.data.objects = self.objects
        self.fixtures = smoke.Cohort(self.data, self.objects, self.checkpoint, b"k" * 32)
        self.guard = Mock()

    def test_exact_reconciliation_and_recovery_from_original_prepared_ids(self):
        self.data.lose_response = self.objects.lose_response = True
        self.assertEqual(self.fixtures.observe(), ("absent", smoke.CLEAN_INTENTS))
        self.fixtures.reserve(self.guard)
        self.fixtures.reserve(self.guard)
        self.assertEqual(self.fixtures.observe(), ("reserved", smoke.CLEAN_INTENTS))
        self.assertFalse(self.objects.writes)
        with patch.object(smoke, "verify_legacy_selected_http", return_value={}) as http:
            self.fixtures.verify(self.guard)
            self.assertEqual(self.fixtures.observe(), ("member-retired", smoke.CLEAN_INTENTS))
            self.assertEqual(len(self.objects.writes), 4)
            recovered = smoke.Cohort(self.data, self.objects, self.checkpoint, b"k" * 32)
            self.assertEqual(recovered.ids, self.fixtures.ids)
            recovered.retire(self.guard)
            recovered.retire(self.guard)
            self.assertEqual([call.args[1] for call in http.call_args_list],
                             ["published", "member-retired", "cohort-retired", "cohort-retired"])
        self.assertEqual([method for method, _ in self.objects.writes], ["PUT"] * 4 + ["DELETE"] * 4)
        self.assertEqual(self.objects.rows, {"unrelated/object": b"foreign data"})
        self.assertEqual(self.data.query("SELECT id,name FROM subscriptions", ()), [{"id": 1, "name": "other"}])
        self.assertEqual(smoke.allocator(self.data)[0], max(self.fixtures.ids.values()))
        with self.assertRaises(smoke.FixtureError):
            self.fixtures.reserve(self.guard)

    def test_partial_prepare_retires_only_owned_objects(self):
        self.fixtures.reserve(self.guard)
        _, _, bodies = self.fixtures.objects["alpha"]
        key, body = next(iter(bodies.items()))
        self.objects.rows[key] = b"unexpected private bytes"
        with (patch.object(smoke, "verify_legacy_selected_http") as http,
              self.assertRaises(smoke.FixtureError)):
            self.fixtures.retire(self.guard)
        http.assert_not_called()
        self.assertEqual(self.fixtures.observe(), ("reserved", smoke.CLEAN_INTENTS))
        self.assertFalse(self.objects.writes)
        del self.objects.rows[key]
        self.fixtures.advance_intent(smoke.CLEAN_INTENTS, "alpha", 0, "-", "a", self.guard)
        self.objects.rows[key] = body
        with patch.object(smoke, "verify_legacy_selected_http", return_value={}):
            self.fixtures.retire(self.guard)
        self.assertEqual(self.objects.writes, [("DELETE", key)])
        self.assertEqual(self.fixtures.observe(), ("absent", smoke.CLEAN_INTENTS))

    def test_armed_absent_put_survives_retry_and_blocks_retirement(self):
        self.fixtures.reserve(self.guard)
        put_attempts = []
        request = self.objects.request

        def uncertain_put(method, key, body=None):
            if method == "PUT":
                self.assertEqual(self.fixtures.observe(), ("reserved", ("a-", "--")))
                put_attempts.append((key, body))
                raise smoke.CapacityError("Synthetic transport lost before visible publication.")
            return request(method, key, body)

        with (patch.object(self.objects, "request", side_effect=uncertain_put), patch.object(smoke, "sleep"),
              patch.object(smoke, "verify_legacy_selected_http", return_value={}) as http):
            with self.assertRaises(smoke.FixtureError):
                self.fixtures.verify(self.guard)
            recovered = smoke.Cohort(self.data, self.objects, self.checkpoint, b"k" * 32)
            with self.assertRaises(smoke.UnconfirmedPut):
                recovered.verify(self.guard)
            with self.assertRaises(smoke.UnconfirmedPut):
                recovered.retire(self.guard)
            self.assertEqual(recovered.observe(), ("reserved", ("a-", "--")))
            self.assertEqual(len(put_attempts), 1)
            self.assertFalse(self.objects.writes)
            http.assert_not_called()

            key, body = put_attempts[0]
            self.objects.rows[key] = body
            recovered.retire(self.guard)
        self.assertEqual(self.objects.writes, [("DELETE", key)])
        self.assertEqual(recovered.observe(), ("absent", smoke.CLEAN_INTENTS))

    def test_readonly_prepare_can_expire_but_cannot_replay_after_allocator_change(self):
        with self.assertRaises(smoke.FixtureError):
            self.fixtures.retire(self.guard)
        with patch.object(smoke, "allocator", return_value=(self.checkpoint["highWater"], self.checkpoint["reserveUntil"] + 1)):
            with self.assertRaises(smoke.FixtureError):
                self.fixtures.reserve(self.guard)
            with patch.object(smoke, "verify_legacy_selected_http", return_value={}):
                self.fixtures.retire(self.guard)
        self.assertFalse(self.objects.writes)
        self.assertEqual(self.fixtures.observe(), ("absent", smoke.CLEAN_INTENTS))

    def test_workflow_uses_native_listing_cohort_shape(self):
        self.assertEqual(smoke.inputs({"inputs": {"action": "prepare", "cohort": COHORT}}), ("prepare", COHORT, ""))
        with self.assertRaises(smoke.FixtureError):
            smoke.inputs({"inputs": {"action": "prepare", "cohort": COHORT[:16]}})

    def test_retirement_rejects_allocator_regression_even_after_expiry(self):
        with (patch.object(smoke, "allocator", return_value=(self.checkpoint["highWater"] - 1,
                                                              self.checkpoint["reserveUntil"] + 1)),
              patch.object(smoke, "verify_legacy_selected_http") as http,
              self.assertRaises(smoke.FixtureError)):
            self.fixtures.retire(self.guard)
        http.assert_not_called()
        self.guard.assert_not_called()
        self.assertFalse(self.objects.writes)

    def test_checkpoint_rejects_drift_except_scoped_cleanup(self):
        changed = PIN | {"moduleSha256": "e" * 64}
        for action, pin, identity in (("reserve", changed, self.checkpoint["identity"]), ("retire", PIN, "f" * 64),
                                      ("verify", PIN, self.checkpoint["identity"])):
            with self.assertRaises(smoke.FixtureError):
                smoke.validate_checkpoint(self.checkpoint, action, COHORT, REVISION, identity, pin)
        smoke.validate_checkpoint(self.checkpoint, "retire", COHORT, REVISION, self.checkpoint["identity"], changed)

    def test_missing_live_floor_stops_before_any_fixture_access(self):
        key = urlsafe_b64encode(b"k" * 32).decode("ascii").rstrip("=")
        policy = json.dumps({"botId": "7", "adminId": "8", "memberId": "9"})
        scope = Mock()
        scope.version.return_value = (SimpleNamespace(revision=REVISION, telegram_config_sha256=smoke.digest(policy.encode()),
                                                      telegram_aggregate_key_sha256=smoke.digest(key.encode())), True)
        scope.verify_legacy_selected_floor.side_effect = smoke.CloudflareError("synthetic floor missing")
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event.json"
            path.write_text(json.dumps({"inputs": {"action": "prepare", "cohort": COHORT}}))
            env = {"GITHUB_REPOSITORY": smoke.REPOSITORY, "GITHUB_REF": smoke.MAIN_REF, "GITHUB_SHA": REVISION,
                   "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_EVENT_PATH": str(path), "GH_TOKEN": "synthetic",
                   "SUBS_BOT_CF_ISOLATION_TARGET_JSON": "{}", "SUBS_BOT_CF_BOOTSTRAP_TOKEN": "synthetic-data",
                   "SUBS_BOT_CF_DEPLOY_TOKEN": "synthetic-deploy", "SUBS_BOT_TELEGRAM_AGGREGATE_KEY": key}
            with (patch.dict(os.environ, env, clear=True), patch.object(smoke, "require_current_main"),
                  patch.object(smoke, "telegram_release_config", return_value=policy), patch.object(smoke, "CloudflareClient"),
                  patch.object(smoke, "_Isolation", return_value=scope), patch.object(smoke, "Cohort") as fixture):
                with self.assertRaisesRegex(smoke.FixtureError, "Failed phase exact isolated release and rollback floor"):
                    smoke.run()
        scope.verify_legacy_selected_floor.assert_called_once_with(allow_rows=True, require_schema=True)
        fixture.assert_not_called()

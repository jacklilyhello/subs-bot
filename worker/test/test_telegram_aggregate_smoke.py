"""Hosted-only SQLite/network doubles; these do not represent real Telegram actions."""

from base64 import urlsafe_b64encode
from contextlib import contextmanager
from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import sqlite3
import sys
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from zipfile import ZipFile

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))

import telegram_aggregate_smoke as smoke
from capacity_resources import CapacityError
from cloudflare_isolation import CloudflareError
from telegram_view_fixtures import FixtureError


COHORT, REVISION, IDENTITY = "0123456789abcdef", "a" * 40, "b" * 64
RELEASE_PIN = {"revision": REVISION, "versionId": "00000000-0000-4000-8000-000000000001",
               "moduleSha256": "c" * 64, "compatibilityDate": "2026-07-30"}
KEY = urlsafe_b64encode(b"\x17" * 32).decode().rstrip("=")
POLICY = {"botId": "881001", "memberId": "881002", "adminId": "881003"}
STAMP = 1_800_000_000


class FakeResources:
    database = "/test/db"
    bucket = "/test/bucket"

    def __init__(self):
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        for migration in sorted((WORKER / "migrations").glob("*.sql")):
            self.db.executescript(migration.read_text("utf-8"))
        self.objects = self
        self.data, self.deleted, self.puts = {}, [], []
        self.failure, self.fail_put, self.fail_delete = None, None, None

    def query(self, sql, params):
        return [dict(row) for row in self.db.execute(sql, params).fetchall()]

    def api(self, method, path, payload=None):
        if method == "GET":
            parsed = urlsplit(path)
            assert parsed.path == self.bucket + "/objects"
            prefix, = parse_qs(parsed.query)["prefix"]
            limit, = parse_qs(parsed.query)["per_page"]
            return [{"key": key, "size": len(body)} for key, body in sorted(self.data.items())
                    if key.startswith(prefix)][:int(limit)]
        assert method == "POST" and path == self.database + "/query"
        failure, self.failure = self.failure, None
        if failure == "uncommitted":
            raise CloudflareError("Synthetic D1 response lost.", uncertain=True)
        try:
            with self.db:
                results = [{"success": True, "results": self.query(item["sql"], item["params"])} for item in payload["batch"]]
        except sqlite3.Error:
            raise CloudflareError("Synthetic D1 transaction rejected.") from None
        if failure == "committed":
            raise CloudflareError("Synthetic committed D1 response lost.", uncertain=True)
        return results

    def request(self, method, key, body=None):
        if method == "GET":
            return self.data.get(key)
        if method == "PUT":
            if self.fail_put == len(self.puts):
                raise CapacityError("Synthetic PUT interrupted.")
            if key in self.data:
                raise CapacityError("Synthetic conditional write refused overwrite.")
            self.data[key] = body
            self.puts.append(key)
            return None
        assert method == "DELETE"
        if self.fail_delete == len(self.deleted):
            raise CapacityError("Synthetic DELETE interrupted.")
        self.deleted.append(key)
        self.data.pop(key, None)


class AggregateAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeResources()
        self.addCleanup(self.cloud.db.close)
        self.cohort = smoke.Cohort(self.cloud, POLICY, COHORT, KEY, IDENTITY)
        self.sequence = 0
        self.probed = []
        self.checkpoint = smoke.prepare(self.cohort, REVISION, lambda: None, RELEASE_PIN)

    def probe(self, cohort, role, recovery, *, active):
        code = smoke.derive_code(KEY, POLICY, role, recovery["nonce"])
        self.assertEqual(smoke.digest(code.encode()), recovery["sha256"])
        self.probed.append((role, recovery["sha256"], active))
        return {"status": 200 if active else 404}

    def receipt(self, role, result):
        """Only the synthetic D1 double fabricates normalized receipts."""
        self.sequence += 1
        actor = self.cohort.actors[role]
        slot = self.cloud.db.execute("SELECT * FROM telegram_aggregate_slots WHERE bot_id=? AND actor_id=?",
                                     (POLICY["botId"], actor)).fetchone()
        revision = slot["revision"] if slot else 0
        nonce, code_hash = (slot["nonce"], slot["code_sha256"]) if slot else (None, None)
        if result == "issued":
            revision += 1
            nonce = urlsafe_b64encode(bytes([self.sequence]) * 16).decode().rstrip("=")
            code_hash = smoke.digest(smoke.derive_code(KEY, POLICY, role, nonce).encode())
            self.cloud.db.execute("INSERT INTO aggregate_links(code_sha256,owner_id,kind,bot_id) VALUES (?,?,'all',?)",
                                  (code_hash, actor, POLICY["botId"]))
        elif result == "revoked":
            revision += 1
            self.cloud.db.execute("UPDATE aggregate_links SET revoked_at=max(created_at,unixepoch()) WHERE code_sha256=?", (code_hash,))
        receipt, = self.cloud.db.execute("""INSERT INTO telegram_inbox
          (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce)
          VALUES (?,?,?,?,'private',?,?,'help',?) RETURNING receipt_id""",
          (POLICY["botId"], self.sequence, actor, actor, self.sequence, STAMP + self.sequence, smoke.MARKER)).fetchone()
        self.cloud.db.execute("""INSERT INTO telegram_aggregate_actions
          (receipt_id,result,revision,code_sha256,auth_message_date,auth_message_id) VALUES (?,?,?,?,0,0)""",
          (receipt, result, revision, code_hash))
        self.cloud.db.execute("INSERT INTO telegram_outbox(receipt_id,state,sent_message_id) VALUES (?,'sent',?)",
                              (receipt, self.sequence + 100))
        self.cloud.db.execute("""INSERT INTO telegram_aggregate_slots
          (bot_id,actor_id,revision,code_sha256,nonce,key_version,message_date,message_id) VALUES (?,?,?,?,?,?,?,?)
          ON CONFLICT(bot_id,actor_id) DO UPDATE SET revision=excluded.revision,code_sha256=excluded.code_sha256,
            nonce=excluded.nonce,key_version=excluded.key_version,message_date=excluded.message_date,message_id=excluded.message_id""",
          (POLICY["botId"], actor, revision, None if result == "revoked" else code_hash,
           None if result == "revoked" else nonce, None if result == "revoked" else 1, STAMP + self.sequence, self.sequence))
        self.cloud.db.commit()

    def capture(self, action):
        smoke.validate_checkpoint(self.checkpoint, action, COHORT, REVISION, IDENTITY, RELEASE_PIN)
        self.checkpoint, _ = smoke.capture(self.cohort, self.checkpoint, action, self.probe, release_pin=RELEASE_PIN)
        return self.checkpoint

    def initial(self):
        for role in smoke.ROLES:
            self.receipt(role, "issued")
            self.receipt(role, "ready")
        return self.capture("capture-initial")

    def rotated(self):
        self.initial()
        self.receipt("member", "revoked")
        self.capture("verify-member-revoked")
        self.receipt("member", "issued")
        return self.capture("verify-rotated")

    def revoked(self):
        self.rotated()
        for role in smoke.ROLES:
            self.receipt(role, "revoked")

    def test_real_acceptance_checkpoints_capture_stability_revocation_rotation_and_separate_owners(self):
        checkpoint = self.rotated()
        old, new = (checkpoint["capabilities"][key]["sha256"] for key in ("member-initial", "member-rotated"))
        self.assertNotEqual(old, new)
        self.assertIn(("member", old, False), self.probed)
        self.assertIn(("member", new, True), self.probed)
        self.assertNotEqual(smoke.expected_exports(self.cohort, "admin"), smoke.expected_exports(self.cohort, "member"))
        raw = json.dumps(checkpoint)
        for secret in (*(json.dumps(value) for value in POLICY.values()), KEY, "ss://", "fixture-admin", "fixture-member"):
            self.assertNotIn(secret, raw)
        for role in smoke.ROLES:
            token, _ = self.cohort.seed_identity(role)
            self.assertNotIn(token, raw)
        # Nonsecret nonce recovery metadata is deliberate; the protected key is still required.
        self.assertIn('"nonce"', raw)
        self.assertNotIn(smoke.derive_code(KEY, POLICY, "member", checkpoint["capabilities"]["member-rotated"]["nonce"]), raw)

    def test_prepare_reconciles_lost_d1_response_and_partial_conditional_uploads(self):
        self.cloud = FakeResources()
        self.addCleanup(self.cloud.db.close)
        self.cohort = smoke.Cohort(self.cloud, POLICY, COHORT, KEY, IDENTITY)
        self.cloud.failure, self.cloud.fail_put = "committed", 1
        with self.assertRaisesRegex(FixtureError, "R2 upload"):
            smoke.prepare(self.cohort, REVISION, lambda: None, RELEASE_PIN)
        self.assertEqual(len(self.cloud.puts), 1)
        self.assertEqual(len(self.cohort.subscriptions()), 2)
        self.cloud.fail_put = None
        checkpoint = smoke.prepare(self.cohort, REVISION, lambda: None, RELEASE_PIN)
        self.assertEqual(len(self.cloud.puts), 4)
        self.assertEqual(smoke.prepare(self.cohort, REVISION, lambda: None, RELEASE_PIN), checkpoint)
        self.assertEqual(len(self.cloud.puts), 4)

    def test_unknown_object_or_same_basename_is_not_adopted(self):
        pointer = self.checkpoint["snapshots"]["admin"]
        prefix, _ = self.cohort.list_objects(pointer)
        self.cloud.data[prefix + "unrelated"] = b"untouched"
        with self.assertRaisesRegex(FixtureError, "inventory|unknown"):
            smoke.prepare(self.cohort, REVISION, lambda: None, RELEASE_PIN)
        self.assertEqual(len(self.cloud.puts), 4)
        self.cloud.data.pop(prefix + "unrelated")
        self.cloud.db.execute("""INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
          VALUES ('999',?,'https://example.invalid/','unrelated-fixture-token',1,1)""", (self.cohort.name,))
        self.cloud.db.commit()
        with self.assertRaisesRegex(FixtureError, "identity|pointer"):
            smoke.prepare(self.cohort, REVISION, lambda: None, RELEASE_PIN)
        self.assertEqual(self.cloud.deleted, [])

    def test_retirement_requires_both_real_revocations_and_preserves_tombstones(self):
        self.rotated()
        with self.assertRaisesRegex(FixtureError, "command count"):
            smoke.retire(self.cohort, self.checkpoint, lambda: None, self.probe, release_pin=RELEASE_PIN)
        self.assertEqual(len(self.cohort.subscriptions()), 2)
        for role in smoke.ROLES:
            self.receipt(role, "revoked")
        self.cloud.failure = "committed"
        self.cloud.fail_delete = 1
        with self.assertRaisesRegex(CapacityError, "DELETE"):
            smoke.retire(self.cohort, self.checkpoint, lambda: None, self.probe, release_pin=RELEASE_PIN)
        self.assertEqual(self.cohort.subscriptions(), {})
        self.cloud.fail_delete = None
        retired, _ = smoke.retire(self.cohort, self.checkpoint, lambda: None, self.probe, release_pin=RELEASE_PIN)
        self.assertEqual(retired["phase"], "retired")
        self.assertEqual(self.cloud.data, {})
        self.assertEqual(len(set(self.cloud.deleted)), 4)
        for table, count in (("telegram_inbox", 8), ("telegram_outbox", 8), ("telegram_aggregate_actions", 8),
                             ("telegram_aggregate_slots", 2), ("aggregate_links", 3)):
            self.assertEqual(self.cloud.db.execute(f"SELECT count(*) FROM {table}").fetchone()[0], count)

    def test_changed_authorization_pointer_or_nonce_fails_closed(self):
        checkpoint = self.initial()
        changed = deepcopy(checkpoint)
        changed["capabilities"]["member-initial"]["nonce"] = "A" * 21 + "B"
        with self.assertRaisesRegex(FixtureError, "recovery"):
            smoke.validate_checkpoint(changed, "verify-member-revoked", COHORT, REVISION, IDENTITY, RELEASE_PIN)
        self.cloud.db.execute("INSERT INTO telegram_auth VALUES (?,?,1,1,1)", (POLICY["botId"], POLICY["memberId"]))
        self.cloud.db.commit()
        self.receipt("member", "revoked")
        with self.assertRaisesRegex(FixtureError, "epoch"):
            self.capture("verify-member-revoked")
        self.assertEqual(len(self.cloud.data), 4)

    def test_checkpoint_rejects_replaced_active_version_or_module_at_the_same_revision(self):
        # BUILD_REVISION alone cannot prove that later captures use the same immutable module.
        changed_pins = [
            {**RELEASE_PIN, "versionId": "00000000-0000-4000-8000-000000000002"},
            {**RELEASE_PIN, "moduleSha256": "d" * 64},
            {**RELEASE_PIN, "compatibilityDate": "2026-08-01"},
        ]
        smoke.validate_checkpoint(self.checkpoint, "capture-initial", COHORT, REVISION, IDENTITY, RELEASE_PIN)
        for changed in changed_pins:
            with self.subTest(field=next(name for name in changed if changed[name] != RELEASE_PIN[name])):
                self.assertEqual(changed["revision"], REVISION)
                with self.assertRaisesRegex(FixtureError, "active release changed"):
                    smoke.validate_checkpoint(self.checkpoint, "capture-initial", COHORT, REVISION, IDENTITY, changed)
                with self.assertRaisesRegex(FixtureError, "active release changed"):
                    smoke.capture(self.cohort, self.checkpoint, "capture-initial", self.probe, release_pin=changed)
        self.assertEqual(self.probed, [])
        self.assertEqual(len(self.cloud.data), 4)
        self.assertEqual(self.cloud.deleted, [])
        self.assertEqual(self.checkpoint["releasePin"], RELEASE_PIN)

    def test_retire_on_a_later_release_preserves_original_seed_identity_and_acceptance_pin(self):
        self.revoked()
        original = deepcopy(self.checkpoint)
        identities = {role: self.cohort.seed_identity(role) for role in smoke.ROLES}
        cleanup_pin = {"revision": "e" * 40, "versionId": "00000000-0000-4000-8000-000000000002",
                       "moduleSha256": "d" * 64, "compatibilityDate": "2026-08-01"}
        smoke.validate_checkpoint(self.checkpoint, "retire", COHORT, REVISION, IDENTITY, cleanup_pin)
        retired, _ = smoke.retire(self.cohort, self.checkpoint, lambda: None, self.probe, release_pin=cleanup_pin)
        self.assertEqual(self.checkpoint, original)
        self.assertEqual(retired["identity"], IDENTITY)
        self.assertEqual(retired["revision"], REVISION)
        self.assertEqual(retired["releasePin"], RELEASE_PIN)
        self.assertEqual(retired["retiredAtReleasePin"], cleanup_pin)
        self.assertEqual({role: self.cohort.seed_identity(role) for role in smoke.ROLES}, identities)
        self.assertEqual(self.cohort.subscriptions(), {})
        self.assertEqual(self.cloud.data, {})
        self.assertEqual(len(set(self.cloud.deleted)), 4)

    def test_literal_confirmation_and_checkpoint_provenance_are_required(self):
        event = {"inputs": {"action": "retire", "cohort": COHORT, "source_run_id": "123", "confirm_retire": f"retire {COHORT}"}}
        self.assertEqual(smoke.parse_inputs(event), ("retire", COHORT, "123"))
        event["inputs"]["confirm_retire"] = "yes"
        with self.assertRaises(FixtureError):
            smoke.parse_inputs(event)
        raw = BytesIO()
        with ZipFile(raw, "w") as archive:
            archive.writestr(smoke.CHECKPOINT, json.dumps(self.checkpoint))
        with patch.object(smoke, "_get_json", return_value={"id": 42, "path": f".github/workflows/{smoke.WORKFLOW}"}), \
             patch.object(smoke, "select_main_artifact", return_value=("1", "2", smoke.digest(raw.getvalue()))) as select, \
             patch.object(smoke, "_download", return_value=raw.getvalue()) as download:
            self.assertEqual(smoke.read_checkpoint("123", REVISION, "synthetic"), self.checkpoint)
            self.assertEqual(select.call_args.kwargs["workflow_id"], 42)
            download.return_value += b"unexpected"
            with self.assertRaisesRegex(FixtureError, "archive"):
                smoke.read_checkpoint("123", REVISION, "synthetic")

    def test_exact_http_bytes_private_redirect_head_and_owner_separation(self):
        checkpoint = self.initial()
        recovery = checkpoint["capabilities"]["admin-initial"]
        code = smoke.derive_code(KEY, POLICY, "admin", recovery["nonce"])
        seen = []
        corrupt = False

        class Response:
            def __init__(self, status, body, media="text/plain", location=None):
                self.status, self.body = status, BytesIO(body)
                self.headers = {"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer",
                    "X-Content-Type-Options": "nosniff", "Content-Type": media, "Content-Length": str(len(body))}
                if location:
                    self.headers["Location"] = location

            def getheader(self, name, default=None):
                return self.headers.get(name, default)

            def read(self, length):
                return self.body.read(length)

        @contextmanager
        def request(method, path, deadline, label):
            nonlocal corrupt
            seen.append((method, path))
            if path == f"/s/{code}":
                yield Response(302, b"", location=f"/agg/{code}/clash")
            else:
                format_name = path.rsplit("/", 1)[1]
                self.assertEqual(path, f"/agg/{code}/{format_name}")
                role = "member" if corrupt else "admin"
                body = smoke.expected_exports(self.cohort, role)[format_name]
                yield Response(200, b"" if method == "HEAD" else body,
                               "text/yaml" if format_name == "clash" else "text/plain")

        with patch.object(smoke, "_request", request):
            result = smoke.probe_capability(self.cohort, "admin", recovery, active=True)
            self.assertEqual(len(seen), 6)
            self.assertEqual(result["base64"]["status"], 200)
            self.assertNotIn(code, json.dumps(result))
            self.assertEqual(smoke.expected_exports(self.cohort, "admin")["base64"],
                             smoke.b64encode(self.cohort.node("admin")["share"].encode()))
            corrupt = True
            with self.assertRaisesRegex(FixtureError, "bytes or length"):
                smoke.probe_capability(self.cohort, "admin", recovery, active=True)

        @contextmanager
        def denied(method, path, deadline, label):
            yield Response(404, b"" if method == "HEAD" else b"Not found.")

        with patch.object(smoke, "_request", denied):
            result = smoke.probe_capability(self.cohort, "admin", recovery, active=False)
            self.assertTrue(all(row["status"] == 404 for row in result.values()))

    def test_snapshot_put_is_conditional_and_never_prints_request_details(self):
        objects = smoke.SnapshotObjects("a" * 32, "synthetic-token")
        pointer = self.checkpoint["snapshots"]["admin"]
        key = f"subscriptions/{pointer['id']}/{pointer['snapshotId']}/0.ndjson"
        body = self.cohort.bodies("admin")["0.ndjson"]
        with patch.object(objects.opener, "open", side_effect=HTTPError("https://fixture.invalid/", 412, "occupied", {}, BytesIO())) as opened:
            with self.assertRaisesRegex(CapacityError, "conditional R2 PUT") as raised:
                objects.request("PUT", key, body)
            request = opened.call_args.args[0]
            self.assertEqual(request.get_header("If-none-match"), "*")
            self.assertNotIn(key, str(raised.exception))
            self.assertNotIn("synthetic-token", str(raised.exception))

    def test_wrong_recovery_key_fails_before_any_public_request(self):
        checkpoint = self.initial()
        self.cohort.encoded = urlsafe_b64encode(b"\x18" * 32).decode().rstrip("=")
        with patch.object(smoke, "_request") as request:
            with self.assertRaisesRegex(FixtureError, "recovery digest"):
                smoke.probe_capability(self.cohort, "admin", checkpoint["capabilities"]["admin-initial"], active=True)
            request.assert_not_called()


if __name__ == "__main__":
    unittest.main()

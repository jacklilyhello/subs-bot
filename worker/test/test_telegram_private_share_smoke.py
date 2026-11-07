"""Exercise the acceptance evidence and cleanup with disposable SQLite and R2 doubles."""

from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import telegram_private_share_smoke as smoke


COHORT = "01ef23456789abcd"
POLICY = {"botId": "9100", "adminId": "9101", "memberId": "9102", "groupId": "-1009103"}
IDENTITY = "b" * 64
PATH = "/accounts/synthetic/d1/database/synthetic"
PIN = {"revision": "a" * 40, "deploymentId": str(UUID(int=1)), "versionId": str(UUID(int=2)),
       "moduleSha256": "c" * 64, "compatibilityDate": "2026-07-30"}
LATER = {**PIN, "revision": "d" * 40, "deploymentId": str(UUID(int=3))}
CODES = {name: sha256(name.encode()).hexdigest() for name in smoke.CASES}
OBSERVED = {"codeHashes": CODES, "raceWinner": "admin", "groupShareMessageId": 800, "groupControlMessageId": 801}


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.initial = self.now
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.addCleanup(self.db.close)
        self.db.row_factory = sqlite3.Row
        self.db.create_function("unixepoch", 0, lambda: self.now, deterministic=True)
        self.db.execute("PRAGMA foreign_keys = ON")
        for path in sorted((Path(__file__).resolve().parents[1] / "migrations").glob("*.sql")):
            self.db.executescript(path.read_text(encoding="utf-8"))
        self.db.execute("INSERT INTO telegram_auth VALUES (?,?,1,?,7)", (POLICY["botId"], POLICY["memberId"], self.now - 100))
        self.other_payload = str(UUID(int=900))
        self.other_share = self.share("other", "admin", None, self.other_payload, b"not a fixture", self.now - 100, 1)
        self.db.execute("INSERT INTO private_share_claims VALUES (?,?,?)", (self.other_share, POLICY["adminId"], self.now - 80))
        self.objects = {self.other_payload: (0, b"not a fixture")}
        self.d1_writes = 0
        self.deleted = []
        self.before_batch = None
        self.lose_batch = False
        self.lose_delete = False
        self.guard = Mock()
        self.cohort = smoke.Cohort(self.api, PATH, self, POLICY, COHORT)
        self.prepared = self.cohort.prepare(IDENTITY, PIN)
        self.next_update = 0
        self.case_ids = {}

    def api(self, method, path, payload):
        self.assertEqual((method, path), ("POST", PATH + "/query"))

        def execute(item):
            self.assertLessEqual(len(item["params"]), 100)
            self.assertNotIn(COHORT, item["sql"])
            return {"success": True, "results": [dict(row) for row in self.db.execute(item["sql"], item["params"])]}

        if "batch" not in payload:
            return [execute(payload)]
        self.d1_writes += 1
        if self.before_batch:
            self.before_batch()
        try:
            self.db.execute("BEGIN")
            result = [execute(item) for item in payload["batch"]]
            self.db.commit()
        except sqlite3.DatabaseError:
            self.db.rollback()
            raise smoke.CloudflareError("Synthetic D1 batch rolled back.") from None
        if self.lose_batch:
            self.lose_batch = False
            raise smoke.CloudflareError("Synthetic D1 acknowledgement lost.", uncertain=True)
        return result

    def check(self, payload_id, receipt_id, expected, *, missing=False):
        self.assertNotEqual(payload_id, self.other_payload)
        current = self.objects.get(payload_id)
        if current is None and missing:
            return False
        if current != (receipt_id, expected):
            raise smoke.FixtureError("Synthetic object does not match.")
        return True

    def request(self, method, payload_id):
        self.assertEqual(method, "DELETE")
        self.assertIsNone(self.db.execute("SELECT 1 FROM private_shares WHERE payload_id=?", (payload_id,)).fetchone())
        self.assertIsNone(self.db.execute("SELECT 1 FROM telegram_private_share_creations WHERE payload_id=?", (payload_id,)).fetchone())
        self.assertNotEqual(payload_id, self.other_payload)
        self.deleted.append(payload_id)
        del self.objects[payload_id]
        if self.lose_delete:
            self.lose_delete = False
            raise smoke.CloudflareError("Synthetic R2 acknowledgement lost.", uncertain=True)

    def share(self, name, creator, target, payload, body, created, duration):
        return self.db.execute("""INSERT INTO private_shares (bot_id,code_sha256,sender_id,sender_name,payload_id,payload_sha256,
            payload_bytes,max_claims,target_user_id,expire_at,created_at) VALUES (?,?,?,?,?,?,?,1,?,?,?)""",
            (POLICY["botId"], CODES.get(name, "f" * 64), POLICY[smoke.ROLES[creator]], "Synthetic creator", payload,
             sha256(body).hexdigest(), len(body), POLICY[smoke.ROLES[target]] if target else None, created + 60 * duration, created)).lastrowid

    def receipt(self, role, marker, when, *, group_message=None, group_type="supergroup"):
        self.next_update += 1
        actor = POLICY[smoke.ROLES[role]]
        message = self.next_update if group_message is None else group_message
        chat = actor if group_message is None else POLICY["groupId"]
        scope = "private" if group_message is None else group_type
        receipt_id = self.db.execute("""INSERT INTO telegram_inbox (bot_id,update_id,actor_id,chat_id,chat_type,message_id,
            message_date,command,received_at,receipt_nonce) VALUES (?,?,?,?,?,?,?,'help',?,?)""",
            (POLICY["botId"], self.next_update, actor, chat, scope, message, when, when, marker)).lastrowid
        self.db.execute("INSERT INTO telegram_outbox (receipt_id,state,attempts,sent_message_id) VALUES (?,'sent',1,?)",
                        (receipt_id, 1000 + message))
        return receipt_id, message

    def create(self, name, when):
        creator, target, duration = smoke.CASES[name]
        receipt, message = self.receipt(creator, smoke.CREATE_MARKER, when)
        payload = str(UUID(int=receipt + 20, version=4))
        body = smoke.body_for(COHORT, name)
        share = self.share(name, creator, target, payload, body, when, duration)
        target_id = POLICY[smoke.ROLES[target]] if target else None
        epoch = (self.initial - 100, 7) if creator == "member" else (0, 0)
        self.db.execute("""INSERT INTO telegram_private_share_creations VALUES
            (?,?,?,?,?,?,?,'published',?,?,?,'Synthetic creator',1,?,?,'subs-bot-cf-dev-01',1,?,?,?,NULL,?)""",
            (receipt, POLICY["botId"], POLICY[smoke.ROLES[creator]], when, message, *epoch, payload,
             sha256(body).hexdigest(), len(body), target_id, duration, when + 600, when, when + 1800, share))
        self.objects[payload] = (receipt, body)
        self.case_ids[name] = (receipt, share, payload)

    def claim(self, case, role, when, *, won=False):
        receipt, _ = self.receipt(role, smoke.CLAIM_MARKER, when)
        self.db.execute("INSERT INTO telegram_private_claim VALUES (?,?)", (receipt, CODES[case]))
        if won:
            self.db.execute("INSERT INTO private_share_claims VALUES (?,?,?)",
                            (self.case_ids[case][1], POLICY[smoke.ROLES[role]], when))
        return receipt

    def complete(self, *, group_type="supergroup", group_message=OBSERVED["groupControlMessageId"]):
        self.create("expired", self.initial + 1)
        self.create("targeted", self.initial + 4)
        self.claim("targeted", "admin", self.initial + 6)
        self.claim("targeted", "member", self.initial + 9, won=True)
        self.claim("targeted", "member", self.initial + 13)
        self.create("race", self.initial + 21)
        self.claim("race", "member", self.initial + 24)
        self.claim("race", "admin", self.initial + 25, won=True)
        self.expired_receipt = self.claim("expired", "member", self.initial + 63)
        self.receipt("admin", None, self.initial + 66, group_message=group_message, group_type=group_type)
        self.now = self.initial + 67

    def verify(self, observed=OBSERVED):
        smoke.validate_checkpoint(self.prepared, "verify", COHORT, PIN["revision"], IDENTITY, PIN)
        return self.cohort.verify(self.prepared, observed, PIN)

    def test_iab_evidence_binds_body_scope_and_natural_expiry(self):
        self.complete()
        verified = self.verify()
        self.assertEqual(verified["phase"], "verified")
        self.assertEqual({name: item["claimCount"] for name, item in verified["cases"].items()},
                         {"targeted": 1, "race": 1, "expired": 0})
        artifact = json.dumps(verified)
        self.assertNotIn(json.dumps(POLICY["adminId"]), artifact)
        self.assertNotIn("Second line.", artifact)
        self.assertNotIn("Synthetic creator", artifact)
        self.assertEqual(self.d1_writes, 0)
        self.assertEqual(self.deleted, [])
        with self.assertRaisesRegex(smoke.FixtureError, "winner differs"):
            self.verify({**OBSERVED, "raceWinner": "member"})
        self.db.execute("UPDATE telegram_inbox SET message_date=? WHERE receipt_id=?", (self.initial + 61, self.expired_receipt))
        with self.assertRaisesRegex(smoke.FixtureError, "naturally"):
            self.verify()
        self.db.execute("UPDATE telegram_inbox SET message_date=? WHERE receipt_id=?", (self.initial + 63, self.expired_receipt))
        self.receipt("admin", None, self.initial + 65, group_message=OBSERVED["groupShareMessageId"])
        with self.assertRaisesRegex(smoke.FixtureError, "group receipt"):
            self.verify()

    def test_basic_group_keeps_actor_local_ids_and_rejects_any_extra_receipt(self):
        self.receipt("admin", None, self.initial - 1, group_message=3, group_type="group")
        self.prepared = self.cohort.prepare(IDENTITY, PIN)
        self.complete(group_type="group", group_message=4)
        verified = self.verify()
        proof = verified["groupProof"]
        self.assertEqual((proof["chatType"], proof["shareMessageId"], proof["controlMessageId"]),
                         ("group", OBSERVED["groupShareMessageId"], OBSERVED["groupControlMessageId"]))
        self.assertTrue(smoke.matches(smoke.DIGEST, proof["controlReceiptSha256"]))
        self.receipt("member", None, self.initial + 67, group_message=5, group_type="group")
        with self.assertRaisesRegex(smoke.FixtureError, "additional receipts"):
            self.verify()

    def test_supergroup_still_requires_the_exact_shared_control_id(self):
        self.complete(group_message=4)
        with self.assertRaisesRegex(smoke.FixtureError, "group control reply"):
            self.verify()

    def test_retirement_waits_reconciles_lost_writes_and_preserves_genuine_history(self):
        self.complete()
        verified = self.verify()
        with self.assertRaisesRegex(smoke.FixtureError, "cleanup grace"):
            self.cohort.retire(verified, self.guard, PIN)
        self.assertEqual((self.d1_writes, self.deleted), (0, []))
        self.now = self.initial + 1900
        history = [self.db.execute(f"SELECT * FROM {table} ORDER BY receipt_id").fetchall()
                   for table in ("telegram_inbox", "telegram_outbox", "telegram_private_claim")]
        self.lose_batch = self.lose_delete = True
        smoke.validate_checkpoint(verified, "retire", COHORT, PIN["revision"], IDENTITY, LATER, allow_drift=True)
        retired = self.cohort.retire(verified, self.guard, LATER)
        self.assertEqual((retired["phase"], retired["releasePin"], retired["retiredAtReleasePin"]), ("retired", PIN, LATER))
        self.assertEqual(self.d1_writes, 1)
        self.assertEqual(set(self.deleted), {item["payloadId"] for item in verified["cases"].values()})
        self.assertEqual(list(self.objects), [self.other_payload])
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_shares").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_share_claims").fetchone()[0], 1)
        self.assertEqual(self.db.execute("SELECT count(*) FROM telegram_private_share_creations").fetchone()[0], 0)
        self.assertEqual(self.db.execute("PRAGMA foreign_key_check").fetchall(), [])
        self.assertEqual(history, [self.db.execute(f"SELECT * FROM {table} ORDER BY receipt_id").fetchall()
                                   for table in ("telegram_inbox", "telegram_outbox", "telegram_private_claim")])
        self.assertEqual(self.cohort.retire(verified, self.guard, LATER), retired)
        self.assertEqual((self.d1_writes, len(self.deleted)), (1, 3))

    def test_transaction_race_aborts_all_cleanup_before_r2_deletion(self):
        self.complete()
        verified = self.verify()
        self.now = self.initial + 1900
        self.before_batch = lambda: self.db.execute("UPDATE private_share_claims SET claimed_at=claimed_at+1 WHERE share_id=?",
                                                   (self.case_ids["race"][1],))
        with self.assertRaisesRegex(smoke.FixtureError, "D1 retirement could not be confirmed"):
            self.cohort.retire(verified, self.guard, PIN)
        self.assertEqual(self.deleted, [])
        self.assertEqual(self.db.execute("SELECT count(*) FROM telegram_private_share_creations").fetchone()[0], 3)
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_shares").fetchone()[0], 4)
        self.assertEqual(self.db.execute("SELECT count(*) FROM private_share_claims").fetchone()[0], 3)

    def test_verification_rejects_same_revision_replacement_and_retire_requires_scope_identity(self):
        for field, replacement in (("deploymentId", str(UUID(int=7))), ("versionId", str(UUID(int=8))), ("moduleSha256", "e" * 64)):
            with self.subTest(field=field), self.assertRaisesRegex(smoke.FixtureError, "active release changed"):
                smoke.validate_checkpoint(self.prepared, "verify", COHORT, PIN["revision"], IDENTITY, {**PIN, field: replacement})
        self.complete()
        verified = self.verify()
        with self.assertRaisesRegex(smoke.FixtureError, "active release changed"):
            smoke.validate_checkpoint(verified, "retire", COHORT, PIN["revision"], IDENTITY, LATER)
        with self.assertRaisesRegex(smoke.FixtureError, "scope"):
            smoke.validate_checkpoint(verified, "retire", COHORT, PIN["revision"], "0" * 64, LATER, allow_drift=True)

    def test_equivalent_verification_keeps_both_release_pins_for_retirement(self):
        with self.assertRaisesRegex(smoke.FixtureError, "active release changed"):
            smoke.validate_checkpoint(self.prepared, "verify", COHORT, PIN["revision"], IDENTITY, LATER)
        for change in ({"moduleSha256": "e" * 64}, {"compatibilityDate": "2026-08-01"}, {"revision": PIN["revision"]}):
            with self.subTest(change=change), self.assertRaisesRegex(smoke.FixtureError, "active release changed"):
                smoke.validate_checkpoint(self.prepared, "verify", COHORT, PIN["revision"], IDENTITY, {**LATER, **change}, allow_equivalent=True)
        smoke.validate_checkpoint(self.prepared, "verify", COHORT, PIN["revision"], IDENTITY, LATER, allow_equivalent=True)
        self.complete(group_type="group", group_message=4)
        verified = self.cohort.verify(self.prepared, OBSERVED, LATER)
        self.assertEqual((verified["releasePin"], verified["verifiedAtReleasePin"]), (PIN, LATER))
        smoke.validate_checkpoint(verified, "retire", COHORT, LATER["revision"], IDENTITY, LATER)
        with self.assertRaisesRegex(smoke.FixtureError, "pin differs"):
            smoke.validate_checkpoint(verified, "retire", COHORT, PIN["revision"], IDENTITY, LATER)

    def test_equivalent_verification_proves_ancestry_and_historic_version_bindings(self):
        with patch.object(smoke, "_get_json", return_value={"status": "ahead", "merge_base_commit": {"sha": PIN["revision"]}}) as compare:
            smoke.require_successor(PIN["revision"], LATER["revision"], "synthetic")
            compare.assert_called_once_with(f"/compare/{PIN['revision']}...{LATER['revision']}", "synthetic")
        with patch.object(smoke, "_get_json", return_value={"status": "diverged", "merge_base_commit": {"sha": PIN["revision"]}}):
            with self.assertRaisesRegex(smoke.FixtureError, "not a successor"):
                smoke.require_successor(PIN["revision"], LATER["revision"], "synthetic")
        bindings = {"telegram_config_sha256": "1" * 64, "telegram_private_share_key_sha256": "2" * 64,
                    "telegram_aggregate_key_sha256": "3" * 64}
        old = SimpleNamespace(revision=PIN["revision"], digest=PIN["moduleSha256"], compatibility=PIN["compatibilityDate"], **bindings)
        active = SimpleNamespace(**bindings)
        scope = SimpleNamespace(version=Mock(return_value=old))
        smoke.verify_historic_release(scope, PIN, active)
        scope.version.assert_called_once_with(PIN["versionId"])
        active.telegram_private_share_key_sha256 = "4" * 64
        with self.assertRaisesRegex(smoke.FixtureError, "historical"):
            smoke.verify_historic_release(scope, PIN, active)

    def test_only_hash_observations_and_exact_retirement_confirmation_are_accepted(self):
        event = {"inputs": {"action": "verify", "cohort": COHORT, "source_run_id": "123", "observations": json.dumps(OBSERVED)}}
        self.assertEqual(smoke.parse_inputs(event), ("verify", COHORT, "123", OBSERVED, False))
        event["inputs"]["confirm_verify"] = f"verify {COHORT} on equivalent release"
        self.assertEqual(smoke.parse_inputs(event), ("verify", COHORT, "123", OBSERVED, True))
        event["inputs"]["confirm_verify"] = "verify wrong cohort on equivalent release"
        with self.assertRaisesRegex(smoke.FixtureError, "confirmation"):
            smoke.parse_inputs(event)
        del event["inputs"]["confirm_verify"]
        changed = deepcopy(OBSERVED)
        changed["codeHashes"]["race"] = "a" * 22
        event["inputs"]["observations"] = json.dumps(changed)
        with self.assertRaisesRegex(smoke.FixtureError, "invalid"):
            smoke.parse_inputs(event)
        event["inputs"] = {"action": "retire", "cohort": COHORT, "source_run_id": "123"}
        with self.assertRaisesRegex(smoke.FixtureError, "confirmation"):
            smoke.parse_inputs(event)
        event["inputs"]["confirm_retire"] = f"retire {COHORT} on current release"
        self.assertEqual(smoke.parse_inputs(event), ("retire", COHORT, "123", None, True))

    def test_r2_bytes_and_exact_runtime_metadata_are_both_required(self):
        payload = str(UUID(int=4, version=4))
        body = smoke.body_for(COHORT, "race")
        key = smoke.Objects.key(payload)
        listed = {"key": key, "size": len(body), "custom_metadata": {"purpose": smoke.PURPOSE, "receipt": "12"}}
        api = Mock(return_value=[listed])
        objects = smoke.Objects(api, "/accounts/synthetic", "synthetic-token")
        with patch.object(objects, "request", return_value=body):
            self.assertTrue(objects.check(payload, 12, body))
            self.assertTrue(api.call_args.args[1].endswith(f"prefix=private-shares%2F{payload}.txt&per_page=2"))
            listed["custom_metadata"]["receipt"] = "13"
            with self.assertRaisesRegex(smoke.FixtureError, "ownership"):
                objects.check(payload, 12, body)


if __name__ == "__main__":
    unittest.main()

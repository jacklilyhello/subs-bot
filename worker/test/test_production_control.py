"""Hosted-only lifecycle protocol tests with transactional SQLite and explicit identities."""
import base64
from copy import deepcopy
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import d1_migrations as migrations
import production_control as control
import production_target as contract

REVISION = "b" * 40
STAMP = "2026-11-16T00:00:00.000Z"
VERSION = "10000000-0000-4000-8000-000000000001"
DEPLOYMENT = "20000000-0000-4000-8000-000000000001"
MODULE = b"export default {fetch(){return new Response(null)}};"


def fixture():
    key = lambda value: base64.urlsafe_b64encode(bytes([value]) * 32).decode().rstrip("=")
    secrets = {"botToken": "92001:synthetic_token_" + "x" * 25, "webhookSecret": "synthetic_webhook_" + "x" * 32,
               "aggregateKey": key(1), "privateShareKey": key(2), "shortlinkToken": None}
    target = {"schemaVersion": 1, "environment": "rehearsal", "accountId": contract.ACCOUNT,
        "zoneId": contract.ZONE, "namespace": "lilyya", "workerName": contract.NAMES["rehearsal"][0],
        "workerId": "c" * 32, "workerCreatedOn": STAMP, "d1Id": "30000000-0000-4000-8000-000000000001",
        "d1Name": contract.NAMES["rehearsal"][0], "d1CreatedAt": STAMP,
        "bucketName": contract.NAMES["rehearsal"][0], "bucketCreatedAt": STAMP,
        "backupBucketName": contract.NAMES["rehearsal"][1], "backupBucketCreatedAt": STAMP,
        "hostname": contract.NAMES["rehearsal"][2], "botId": "92001", "botUsername": "test_cfsubs_bot",
        "generation": 1, "admins": ["8813701954"], "members": ["8653767757"], "groups": [],
        "defaultAccess": "deny", "features": {name: False for name in contract.FEATURES}, "provider": None,
        "webhook": {"allowedUpdates": ["message", "callback_query"], "maxConnections": 2},
        "keyDigests": {"aggregate": sha256(secrets["aggregateKey"].encode()).hexdigest(),
            "privateShare": sha256(secrets["privateShareKey"].encode()).hexdigest(),
            "webhook": sha256(secrets["webhookSecret"].encode()).hexdigest(), "shortlink": None}}
    return contract.validate_target(target), secrets


def approval(target, action, state):
    return {"schemaVersion": 1, "environment": target.environment, "targetSha256": target.digest,
        "revision": REVISION, "action": action, "stateSha256": state,
        "authorization": "approve " + action + " for " + target.data["workerName"]}


class StatefulAPI:
    def __init__(self, target):
        self.target = target
        self.t = target.data
        self.root = "/accounts/" + self.t["accountId"]
        self.database = self.root + "/d1/database/" + self.t["d1Id"]
        self.script = self.root + "/workers/scripts/" + self.t["workerName"]
        self.worker_path = self.root + "/workers/workers/" + self.t["workerId"]
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.execute("CREATE TABLE _cf_KV(key TEXT PRIMARY KEY,value BLOB) WITHOUT ROWID")
        self.controller = None
        self.requests = []
        self.inject_initialization_row = False
        self.lose_initialization_response = False
        self.initialization_mutations = 0

    def insert_business(self):
        self.db.execute("""INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
            VALUES('8653767757','Synthetic preserved row','https://fixture.invalid/source','synthetic-token-001',1,1)""")

    def query(self, sql):
        statements = list(migrations._statements(sql if sql.endswith(";") else sql + ";"))
        if any(len(statement.encode()) >= migrations.MAX_D1_STATEMENT_BYTES for statement in statements):
            raise AssertionError("Synthetic D1 received an oversized SQL statement.")
        initialize = "INSERT INTO telegram_general_policy VALUES" in sql
        if initialize:
            self.initialization_mutations += 1
            if self.inject_initialization_row:
                self.inject_initialization_row = False
                self.insert_business()
        results = []
        try:
            self.db.execute("BEGIN")
            for statement in statements:
                cursor = self.db.execute(statement)
                rows = [dict(row) for row in cursor] if cursor.description else []
                results.append({"success": True, "results": rows})
            self.db.execute("COMMIT")
        except sqlite3.Error:
            self.db.rollback()
            raise control.OperationError("Synthetic D1 transaction rejected.") from None
        if initialize and self.lose_initialization_response:
            self.lose_initialization_response = False
            raise control.OperationError("Synthetic lost mutation response.", uncertain=True)
        return results

    def __call__(self, method, path, payload=None, **kwargs):
        self.requests.append((method, path, deepcopy(payload)))
        t = self.t
        if method == "POST" and path == self.database + "/query":
            return self.query(payload["sql"])
        if method != "GET":
            raise AssertionError("Unexpected mutation outside the SQLite fixture.")
        if path == self.root:
            return {"id": t["accountId"]}
        if path == "/zones/" + t["zoneId"]:
            return {"id": t["zoneId"], "name": "lilyya.top", "account": {"id": t["accountId"]}}
        if path == self.database:
            return {"uuid": t["d1Id"], "name": t["d1Name"], "created_at": t["d1CreatedAt"]}
        for name_key, created_key in (("bucketName", "bucketCreatedAt"), ("backupBucketName", "backupBucketCreatedAt")):
            bucket = self.root + "/r2/buckets/" + t[name_key]
            if path == bucket:
                return {"name": t[name_key], "creation_date": t[created_key], "jurisdiction": "default"}
            if path == bucket + "/domains/managed":
                return {"enabled": False}
            if path == bucket + "/domains/custom":
                return {"domains": []}
            if path == bucket + "/lifecycle":
                return {"rules": []}
        if path == self.worker_path:
            return {"id": t["workerId"], "name": t["workerName"], "created_on": t["workerCreatedOn"],
                "tags": ["subs-bot", "lifecycle-rehearsal"], "logpush": False, "tail_consumers": [],
                "observability": {"enabled": False}, "subdomain": {"enabled": True, "url": "https://" + t["hostname"]}}
        if path == self.script + "/schedules":
            return {"schedules": [{"cron": "* * * * *"}]}
        if path == self.script + "/deployments":
            return {"deployments": [{"id": DEPLOYMENT, "strategy": "percentage",
                "versions": [{"version_id": VERSION, "percentage": 100}]}]}
        if path == self.worker_path + "/versions/" + VERSION + "?include=modules":
            return {"id": VERSION, "main_module": "index.js", "compatibility_date": "2026-07-30", "usage_model": "standard",
                "modules": [{"name": "index.js", "content_type": "application/javascript+module",
                    "content_base64": base64.b64encode(MODULE).decode()}], "bindings": self.controller.expected_bindings()}
        raise AssertionError("Unexpected read in explicit target fixture: " + path)


class ProductionControllerTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.bundle = Path(self.directory.name)
        self.manifest = {"version": 2, "revision": REVISION, "compatibilityDate": "2026-07-30",
                         "bundleSha256": sha256(MODULE).hexdigest(), "migrations": []}
        (self.bundle / "index.js").write_bytes(MODULE)
        for path in sorted((WORKER / "migrations").glob("*.sql")):
            raw = path.read_bytes()
            (self.bundle / path.name).write_bytes(raw)
            self.manifest["migrations"].append({"name": path.name, "sha256": sha256(raw).hexdigest()})
        self.target, self.secrets = fixture()
        self.api = StatefulAPI(self.target)
        self.addCleanup(self.api.db.close)
        self.controller = control.Controller(self.target, self.api, self.api, self.bundle, self.manifest, secrets=self.secrets)
        self.api.controller = self.controller

    def test_fresh_initialization_is_schema_exact_whitelisted_frozen_and_repeatable(self):
        result = self.controller.initialize()
        self.assertTrue(result["initialized"])
        self.assertFalse(result["repeated"])
        self.assertTrue(self.controller.verify_initial_whitelist())
        self.assertEqual(self.api.db.execute("SELECT admission,workers FROM subs_bot_production_control").fetchone()[:], ("closed", "frozen"))
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 0)
        self.assertEqual(self.api.db.execute("SELECT DISTINCT effective_at FROM telegram_general_actors").fetchall()[0][0], 1)
        before = list(self.api.db.iterdump())
        self.assertTrue(self.controller.initialize()["repeated"])
        self.assertEqual(list(self.api.db.iterdump()), before)

    def test_unknown_schema_is_not_adopted_or_changed(self):
        self.api.db.execute("CREATE TABLE unexpected_project_data(value TEXT)")
        self.api.db.execute("INSERT INTO unexpected_project_data VALUES('preserved')")
        before = list(self.api.db.iterdump())
        with self.assertRaises((contract.ContractError, migrations.MigrationError)):
            self.controller.initialize()
        self.assertEqual(list(self.api.db.iterdump()), before)
        self.assertEqual(self.api.initialization_mutations, 0)

    def test_data_injected_after_preflight_blocks_atomic_permission_initialization(self):
        self.api.inject_initialization_row = True
        with self.assertRaises((contract.ContractError, control.OperationError)):
            self.controller.initialize()
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subscriptions").fetchone()[0], 1)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM telegram_general_policy").fetchone()[0], 0)
        self.assertEqual(self.api.db.execute("SELECT count(*) FROM subs_bot_production_control").fetchone()[0], 0)

    def test_unknown_initialization_result_is_not_retried_and_can_be_read_back(self):
        self.api.lose_initialization_response = True
        with self.assertRaises(control.OperationError) as caught:
            self.controller.initialize()
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual(self.api.initialization_mutations, 1)
        self.assertTrue(self.controller.verify_initial_whitelist())
        self.assertTrue(self.controller.initialize()["repeated"])
        self.assertEqual(self.api.initialization_mutations, 1)

    def test_pause_does_not_thaw_a_frozen_target(self):
        self.controller.initialize()
        before = self.controller.inspect()
        result = self.controller.transition("pause", approval(self.target, "pause", before["stateSha256"]), before["stateSha256"])
        self.assertEqual(result["control"]["workers"], "frozen")
        self.assertEqual(result["control"]["admission"], "closed")

    def test_pending_and_unknown_invocations_block_freeze_without_deleting_them(self):
        self.controller.initialize()
        self.api.db.execute("UPDATE subs_bot_production_control SET workers='run'")
        for index, state in enumerate(("running", "uncertain"), 1):
            with self.subTest(state=state):
                invocation = format(index, "032x")
                finished = None if state == "running" else 10
                self.api.db.execute("""INSERT INTO subs_bot_production_invocations
                    VALUES(?,?,?,1,'scheduled',1,9999999999,?,?)""", (invocation, self.target.digest, self.target.data["botId"], state, finished))
                before = self.controller.inspect()
                with self.assertRaises(contract.ContractError):
                    self.controller.transition("freeze", approval(self.target, "freeze", before["stateSha256"]), before["stateSha256"])
                self.assertEqual(self.api.db.execute("SELECT workers FROM subs_bot_production_control").fetchone()[0], "run")
                self.assertEqual(self.api.db.execute("SELECT state FROM subs_bot_production_invocations WHERE invocation_id=?", (invocation,)).fetchone()[0], state)

    def test_pending_durable_business_reply_prevents_freeze_and_activation(self):
        self.controller.initialize()
        self.api.db.execute("UPDATE subs_bot_production_control SET workers='run'")
        bot, member = self.target.data["botId"], self.target.data["members"][0]
        self.api.db.execute("""INSERT INTO telegram_inbox
            (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command)
            VALUES(?,1,?,?,'private',1,unixepoch(),'help')""", (bot, member, member))
        receipt = self.api.db.execute("SELECT receipt_id FROM telegram_inbox").fetchone()[0]
        self.api.db.execute("INSERT INTO telegram_outbox(receipt_id) VALUES(?)", (receipt,))
        for action in ("freeze", "activate"):
            before = self.controller.inspect()
            self.assertEqual(before["work"]["outbox"], 1)
            with self.assertRaises(contract.ContractError):
                self.controller.transition(action, approval(self.target, action, before["stateSha256"]), before["stateSha256"])
        self.assertEqual(self.api.db.execute("SELECT state FROM telegram_outbox").fetchone()[0], "pending")
        self.assertEqual(self.api.db.execute("SELECT workers FROM subs_bot_production_control").fetchone()[0], "run")

    def test_missing_or_wrong_identity_and_approval_never_mutate(self):
        for key, value in (("d1Id", None), ("workerId", "d" * 32), ("botId", "8813701954")):
            changed = deepcopy(self.target.data)
            changed[key] = value
            if key == "workerId":
                changed_target = contract.validate_target(changed)
                wrong = control.Controller(changed_target, self.api, self.api, self.bundle, self.manifest, secrets=self.secrets)
                with self.assertRaises((contract.ContractError, AssertionError)):
                    wrong.initialize()
            else:
                with self.assertRaises(contract.ContractError):
                    contract.validate_target(changed)
        self.assertEqual(self.api.initialization_mutations, 0)
        self.controller.initialize()
        before = self.controller.inspect()
        for key in ("targetSha256", "revision", "action", "stateSha256", "authorization"):
            envelope = approval(self.target, "thaw", before["stateSha256"])
            envelope[key] = "incorrect"
            with self.assertRaises(contract.ContractError):
                self.controller.transition("thaw", envelope, before["stateSha256"])
        self.assertEqual(self.controller.inspect()["stateSha256"], before["stateSha256"])


class ConfigurationAndTransportTests(unittest.TestCase):
    def test_config_rejects_keys_that_runtime_cannot_decode(self):
        target, secrets = fixture()
        self.assertEqual(json.loads(control.general_config(target, REVISION, secrets))["cutoverAt"], 1)
        for key, value in (("aggregateKey", "x" * 32), ("privateShareKey", "x" * 43),
                ("webhookSecret", "x" * 257), ("webhookSecret", "x" * 32 + ":invalid")):
            with self.subTest(key=key, size=len(value)):
                changed_secrets = {**secrets, key: value}
                raw = deepcopy(target.data)
                name = {"aggregateKey": "aggregate", "privateShareKey": "privateShare", "webhookSecret": "webhook"}[key]
                raw["keyDigests"][name] = sha256(value.encode()).hexdigest()
                with self.assertRaises((contract.ContractError, control.OperationError)):
                    control.general_config(contract.validate_target(raw), REVISION, changed_secrets)
        with self.assertRaises(contract.ContractError):
            control.general_config(target, REVISION, {key: value for key, value in secrets.items() if key != "botToken"})

    def test_mutation_transport_uncertainty_is_reported_without_retry(self):
        target, _ = fixture()
        api = control.API(target, "synthetic_scoped_token_" + "x" * 20)
        api.opener.open = Mock(side_effect=OSError("synthetic network loss"))
        path = "/accounts/" + target.account_id + "/d1/database/" + target.d1_id + "/query"
        with self.assertRaises(control.OperationError) as caught:
            api("POST", path, {"sql": "SELECT 1"})
        self.assertTrue(caught.exception.uncertain)
        self.assertEqual(api.opener.open.call_count, 1)
        for method, suffix in (("DELETE", path), ("PUT", "/accounts/" + target.account_id + "/workers/scripts/unrelated/schedules")):
            with self.assertRaises(contract.ContractError):
                api(method, suffix, {})
        self.assertEqual(api.opener.open.call_count, 1)

    def test_webhook_preserves_pending_updates_and_wrong_bot_cannot_be_modified(self):
        target, secrets = fixture()
        telegram = control.Telegram(target, secrets)
        before = {"url": "", "pending_update_count": 7}
        after = {"url": "https://" + target.data["hostname"] + "/telegram/webhook",
            "pending_update_count": 7, "max_connections": 2, "allowed_updates": ["message", "callback_query"],
            "has_custom_certificate": False}
        calls = []
        def call(method, payload=None):
            calls.append((method, payload))
            if method == "getMe":
                return {"id": int(target.data["botId"]), "username": target.data["botUsername"], "is_bot": True}
            if method == "getWebhookInfo":
                return before if len([m for m, _ in calls if m == "getWebhookInfo"]) == 1 else after
            return True
        telegram.call = call
        result = telegram.configure(contract.digest(before))
        self.assertFalse(result["dropPendingUpdates"])
        sent = [body for method, body in calls if method == "setWebhook"]
        self.assertEqual(len(sent), 1)
        self.assertIs(sent[0]["drop_pending_updates"], False)
        self.assertEqual(result["pendingUpdateCount"], 7)
        telegram.call = Mock(return_value={"id": 999, "username": "wrong_bot", "is_bot": True})
        with self.assertRaises(contract.ContractError):
            telegram.configure(contract.digest(before))
        self.assertEqual([call.args[0] for call in telegram.call.call_args_list], ["getMe"])


if __name__ == "__main__":
    unittest.main()

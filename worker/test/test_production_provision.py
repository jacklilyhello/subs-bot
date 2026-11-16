"""Provisioning protocol tests; all resource identities and credentials are synthetic."""
from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

WORKER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WORKER / "tools"))
import production_control as control
import production_provision as provision
import production_target as contract
from test_production_control import REVISION, STAMP, approval, fixture

EPOCH = int(datetime.fromisoformat(STAMP).timestamp())
DATABASE = "40000000-0000-4000-8000-000000000001"
WORKER_ID = "d" * 32


def draft_fixture():
    registered, _ = fixture()
    raw = deepcopy(registered.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        raw[key] = None
    return contract.validate_target(raw, draft=True)


class MemoryPrivateStore:
    def __init__(self):
        self.objects = {}

    def list(self, prefix):
        return sorted(key for key in self.objects if key.startswith(prefix))

    def get(self, key):
        return self.objects[key]

    def put(self, key, body):
        if key in self.objects and self.objects[key] != body:
            raise contract.ContractError("Synthetic immutable journal conflict.")
        self.objects[key] = body
        return contract.digest(json.loads(body))

    def latest(self):
        return json.loads(self.objects[sorted(self.objects)[-1]])["value"] if self.objects else None


class ProvisionAPI:
    def __init__(self, draft, store):
        self.t, self.store = draft.data, store
        self.root = "/accounts/" + self.t["accountId"]
        self.databases, self.buckets, self.worker = {}, {}, None
        self.posts = []
        self.lost_response = None
        self.before_post = None

    def __call__(self, method, path, payload=None, **kwargs):
        if method == "POST":
            if path == self.root + "/d1/database":
                kind = "database"
            elif path == self.root + "/r2/buckets":
                kind = "bucketName" if payload["name"] == self.t["bucketName"] else "backupBucketName"
            elif path == self.root + "/workers/workers":
                kind = "worker"
            else:
                raise AssertionError("Unexpected provision mutation.")
            latest = self.store.latest()
            if not latest or latest["intents"].get(kind, {}).get("state") != "started" or kind in latest["resources"]:
                raise AssertionError("Resource creation preceded its durable private intent.")
            if self.before_post:
                self.before_post(kind)
            self.posts.append((kind, deepcopy(payload), len(self.store.objects)))
            if kind == "database":
                if self.databases:
                    raise AssertionError("The database was created twice.")
                result = {"uuid": DATABASE, "name": self.t["d1Name"], "created_at": STAMP}
                self.databases[DATABASE] = result
            elif kind == "worker":
                if self.worker:
                    raise AssertionError("The worker was created twice.")
                result = {"id": WORKER_ID, "name": self.t["workerName"], "created_on": STAMP,
                    "tags": ["subs-bot", "lifecycle-" + self.t["environment"]]}
                self.worker = result
            else:
                if payload["name"] in self.buckets:
                    raise AssertionError("The bucket was created twice.")
                result = {"name": payload["name"], "creation_date": STAMP, "jurisdiction": "default"}
                self.buckets[result["name"]] = result
            if self.lost_response == kind:
                self.lost_response = None
                raise control.OperationError("Synthetic accepted creation with lost response.", uncertain=True)
            return deepcopy(result)
        if method != "GET":
            raise AssertionError("Provisioning attempted an unsupported method.")
        if path == self.root:
            return {"id": self.t["accountId"]}
        if path == "/zones/" + self.t["zoneId"]:
            return {"id": self.t["zoneId"], "account": {"id": self.t["accountId"]}}
        worker_path = self.root + "/workers/workers/"
        if path.startswith(worker_path):
            if self.worker and path.removeprefix(worker_path) in (self.worker["id"], self.worker["name"]):
                return deepcopy(self.worker)
            if kwargs.get("absent"):
                return None
            raise control.OperationError("Synthetic worker absent.", status=404)
        if path.startswith(self.root + "/d1/database?"):
            return {"result": deepcopy(list(self.databases.values())), "result_info": {"total_pages": 1}}
        if path.startswith(self.root + "/d1/database/"):
            identity = path.removeprefix(self.root + "/d1/database/")
            if identity not in self.databases:
                raise control.OperationError("Synthetic database absent.", status=404)
            return deepcopy(self.databases[identity])
        if path.startswith(self.root + "/r2/buckets?"):
            return {"result": {"buckets": deepcopy(list(self.buckets.values()))}, "result_info": {}}
        for name, bucket in self.buckets.items():
            base = self.root + "/r2/buckets/" + name
            if path == base:
                return deepcopy(bucket)
            if path == base + "/domains/managed":
                return {"enabled": False}
            if path == base + "/domains/custom":
                return {"domains": []}
            if path == base + "/lifecycle":
                return {"rules": []}
        raise AssertionError("Unexpected resource read in provision fixture.")


class ProvisionProtocolTests(unittest.TestCase):
    def setUp(self):
        self.draft = draft_fixture()
        self.store = MemoryPrivateStore()
        self.api = ProvisionAPI(self.draft, self.store)
        self.journal = provision.ProvisionJournal(self.store, self.draft)
        self.tool = provision.Provisioner(self.draft, self.api, self.api, journal=self.journal)
        self.clock = patch.object(provision.time, "time", return_value=EPOCH)
        self.clock.start()
        self.addCleanup(self.clock.stop)

    def create(self, tool=None):
        tool = tool or self.tool
        state = contract.digest(tool.journal.value if tool.journal.value is not None else tool.available())
        return tool.create(approval(self.draft, "provision", state), REVISION, state)

    def restart(self):
        journal = provision.ProvisionJournal(self.store, self.draft)
        return provision.Provisioner(self.draft, self.api, self.api, journal=journal)

    def test_unknown_same_name_worker_database_and_bucket_are_never_adopted(self):
        for kind in ("worker", "database", "bucket"):
            with self.subTest(kind=kind):
                api = ProvisionAPI(self.draft, self.store)
                if kind == "worker":
                    api.worker = {"id": "a" * 32, "name": self.draft.data["workerName"], "created_on": STAMP, "tags": []}
                elif kind == "database":
                    api.databases[DATABASE] = {"uuid": DATABASE, "name": self.draft.data["d1Name"], "created_at": STAMP}
                else:
                    name = self.draft.data["bucketName"]
                    api.buckets[name] = {"name": name, "creation_date": STAMP, "jurisdiction": "default"}
                tool = provision.Provisioner(self.draft, api, api, journal=self.journal)
                with self.assertRaises(contract.ContractError):
                    tool.available()
                self.assertEqual(api.posts, [])
                self.assertEqual(self.store.objects, {})

    def test_each_create_has_a_durable_intent_and_final_registration_survives_a_new_runner(self):
        final, receipt = self.create()
        self.assertEqual([kind for kind, _, _ in self.api.posts], ["database", "bucketName", "backupBucketName", "worker"])
        self.assertTrue(all(count > 0 for _, _, count in self.api.posts))
        self.assertEqual(receipt["state"], "created-no-module-no-consumer")
        self.assertEqual(final.data["d1Id"], DATABASE)
        self.assertEqual(final.data["workerId"], WORKER_ID)
        for kind in ("database", "bucketName", "backupBucketName", "worker"):
            self.assertIn(kind, receipt["resources"])
        restored = self.restart()
        self.assertEqual(restored.journal.value, receipt)
        self.assertGreater(restored.journal.generation, 4)
        again, _ = self.create(restored)
        self.assertEqual(again.digest, final.digest)
        self.assertEqual(len(self.api.posts), 4, "repeating confirmed creation reads pins rather than creating resources again")

    def test_lost_response_retains_intent_and_a_new_runner_refuses_blind_retry(self):
        self.api.lost_response = "database"
        with self.assertRaises(control.OperationError) as caught:
            self.create()
        self.assertTrue(caught.exception.uncertain)
        latest = self.store.latest()
        self.assertEqual(latest["intents"]["database"]["state"], "started")
        self.assertNotIn("database", latest["resources"])
        restored = self.restart()
        self.assertEqual(restored.journal.value, latest)
        with self.assertRaises(contract.ContractError):
            self.create(restored)
        self.assertEqual(len(self.api.posts), 1)
        self.assertEqual(len(self.api.databases), 1)

    def test_only_the_independently_approved_pin_within_intent_window_can_resume(self):
        self.api.lost_response = "database"
        with self.assertRaises(control.OperationError):
            self.create()
        restored = self.restart()
        predecessor = contract.digest(restored.journal.value)
        before = deepcopy(self.store.objects)
        wrong = "0" * 64
        action = "provision-reconcile:database:" + wrong
        with self.assertRaises(contract.ContractError):
            restored.reconcile("database", wrong, approval(self.draft, action, predecessor), REVISION, predecessor)
        self.assertEqual(self.store.objects, before)
        self.api.databases[DATABASE]["created_at"] = datetime.fromtimestamp(EPOCH - 3600, timezone.utc).isoformat().replace("+00:00", "Z")
        old = contract.digest(restored.observe_candidate("database"))
        with self.assertRaises(contract.ContractError):
            restored.reconcile("database", old, approval(self.draft, "provision-reconcile:database:" + old, predecessor), REVISION, predecessor)
        self.assertEqual(self.store.objects, before)
        self.api.databases[DATABASE]["created_at"] = STAMP
        identity = contract.digest(restored.observe_candidate("database"))
        result = restored.reconcile("database", identity,
            approval(self.draft, "provision-reconcile:database:" + identity, predecessor), REVISION, predecessor)
        self.assertTrue(result["reconciled"])
        self.assertEqual(self.store.latest()["intents"]["database"]["state"], "independently-confirmed")
        final, _ = self.create(self.restart())
        self.assertEqual(final.data["d1Id"], DATABASE)
        self.assertEqual([kind for kind, _, _ in self.api.posts].count("database"), 1)
        self.assertEqual(len(self.api.posts), 4)

    def test_confirmed_partial_resume_does_not_create_the_database_again(self):
        guards = 0
        def interrupt():
            nonlocal guards
            guards += 1
            if guards == 2:
                raise control.OperationError("Synthetic interruption between confirmed resources.")
        self.tool.guard = interrupt
        with self.assertRaises(control.OperationError):
            self.create()
        self.assertEqual([kind for kind, _, _ in self.api.posts], ["database"])
        self.assertIn("database", self.store.latest()["resources"])
        self.assertNotIn("bucketName", self.store.latest()["intents"])
        final, _ = self.create(self.restart())
        self.assertEqual(final.data["d1Id"], DATABASE)
        self.assertEqual(len(self.api.posts), 4)
        self.assertEqual([kind for kind, _, _ in self.api.posts].count("database"), 1)

    def test_missing_anchor_stops_before_any_creation_or_journal_write(self):
        tool = provision.Provisioner(self.draft, self.api, self.api)
        state = contract.digest(tool.available())
        with self.assertRaises(contract.ContractError):
            tool.create(approval(self.draft, "provision", state), REVISION, state)
        self.assertEqual(self.api.posts, [])
        self.assertEqual(self.store.objects, {})

    def test_journal_gap_or_rewritten_hash_link_cannot_be_used_for_resume(self):
        self.journal.save({"state": "synthetic-first"})
        self.journal.save({"state": "synthetic-second"})
        second = sorted(self.store.objects)[1]
        envelope = json.loads(self.store.objects[second])
        envelope["previousSha256"] = "0" * 64
        self.store.objects[second] = contract.canonical(envelope)
        with self.assertRaises(contract.ContractError):
            self.restart()
        self.assertEqual(self.api.posts, [])


if __name__ == "__main__":
    unittest.main()

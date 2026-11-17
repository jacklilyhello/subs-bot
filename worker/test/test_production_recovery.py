"""Hosted-only synthetic production recovery failure and identity coverage."""

from copy import deepcopy
from io import BytesIO
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import production_recovery as recovery
import production_control as control


ACCOUNT = "a" * 32
SOURCE = "11111111-2222-3333-4444-555555555555"
DESTINATION = "66666666-7777-8888-9999-aaaaaaaaaaaa"
STAMP = "2026-11-16T00:00:00.000Z"
CHECKPOINT = "1234567890abcdef1234567890abcdef"
TARGET = {"accountId": ACCOUNT, "d1Id": SOURCE, "d1Name": "subs-bot-cf-control-drill",
          "workerName": "subs-bot-control-drill", "bucketName": "subs-bot-control-drill",
          "bucketCreatedAt": STAMP, "backupBucketName": "subs-bot-control-drill-backup", "backupBucketCreatedAt": STAMP}
CONTRACT = {"version": 1, "checkpointId": CHECKPOINT, "databaseName": "subs-bot-restore-db-drill",
            "objectsName": "subs-bot-restore-r2-drill", "purpose": "baseline"}
PIN = {"revision": "b" * 40, "scopeSha256": recovery.digest(recovery.canonical(TARGET))}


def inventory_reader(read):
    """Callable-only adapter: recovery must explicitly request the envelope."""
    def request(method, path, payload=None, *, envelope=False):
        assert method == "GET" and payload is None and envelope is True
        return {"success": True, "result": read(method, path)}
    return request


class ContractTests(unittest.TestCase):
    def test_explicit_independent_target_and_missing_g1(self):
        self.assertEqual(recovery.recovery_contract(recovery.canonical(CONTRACT), TARGET), CONTRACT)
        for change in ({"checkpointId": "../wrong"}, {"purpose": "recovery"},
                       {"objectsName": TARGET["bucketName"]}, {"databaseName": TARGET["d1Name"]},
                       {"unknown": True}, {"version": True}):
            with self.subTest(change=change), self.assertRaises(recovery.RecoveryError):
                recovery.recovery_contract(recovery.canonical({**CONTRACT, **change}), TARGET)

    def test_recovery_requires_distinct_explicit_g1_pin(self):
        pin = {"checkpointId": "f" * 32, "manifestSha256": "e" * 64}
        value = {**CONTRACT, "purpose": "recovery", "preservedG1": pin}
        self.assertEqual(recovery.recovery_contract(recovery.canonical(value), TARGET), value)
        for bad in ({**pin, "checkpointId": CHECKPOINT}, {**pin, "manifestSha256": ""}, {**pin, "extra": 1}):
            with self.subTest(pin=bad), self.assertRaises(recovery.RecoveryError):
                recovery.recovery_contract(recovery.canonical({**value, "preservedG1": bad}), TARGET)

    def test_recovery_adds_g1_without_rewriting_historical_ownership(self):
        changed = {**CONTRACT, "purpose": "recovery",
                   "preservedG1": {"checkpointId": "f" * 32, "manifestSha256": "e" * 64}}
        self.assertEqual(recovery.contract_identity(CONTRACT), recovery.contract_identity(changed))
        self.assertNotEqual(recovery.digest(recovery.canonical(CONTRACT)), recovery.digest(recovery.canonical(changed)))
        changed["objectsName"] = "subs-bot-restore-another"
        self.assertNotEqual(recovery.contract_identity(CONTRACT), recovery.contract_identity(changed))

    def test_independent_session_requires_source_manifest_and_new_session(self):
        value = {**CONTRACT, "purpose": "recovery", "sessionId": "d" * 32, "sourceManifestSha256": "b" * 64,
                 "preservedG1": {"checkpointId": "f" * 32, "manifestSha256": "e" * 64}}
        self.assertEqual(recovery.recovery_contract(recovery.canonical(value), TARGET), value)
        for bad in ({**value, "sessionId": CHECKPOINT}, {key: v for key, v in value.items() if key != "sourceManifestSha256"}):
            with self.assertRaises(recovery.RecoveryError):
                recovery.recovery_contract(recovery.canonical(bad), TARGET)


class APITests(unittest.TestCase):
    def setUp(self):
        self.worker = Mock(return_value=[])
        self.api = recovery.RecoveryAPI(TARGET, "synthetic-token", self.worker, CONTRACT)

    def test_wrong_target_and_business_mutations_never_reach_network(self):
        bad = [("POST", self.api.source + "/query", {"sql": "DELETE FROM telegram_inbox"}),
               ("POST", self.api.source + "/query", {"sql": "INSERT INTO subscriptions VALUES(1)"}),
               ("POST", self.api.source + "/import", {"action": "init", "etag": "b" * 32}),
               ("POST", self.api.root + "/d1/database/" + DESTINATION + "/query", {"sql": "SELECT 1"}),
               ("GET", "/accounts/" + "f" * 32 + "/d1/database/" + SOURCE, None),
               ("POST", self.api.root + "/r2/buckets", {"name": TARGET["bucketName"], "storageClass": "Standard"}),
               ("DELETE", self.api.source, None)]
        with patch.object(recovery.native, "_response") as response:
            for method, path, body in bad:
                with self.subTest(path=path), self.assertRaises(recovery.RecoveryError):
                    self.api.json(method, path, body)
            response.assert_not_called()

    def test_source_r2_is_readonly_and_other_checkpoint_writes_are_rejected(self):
        key = "private-shares/eeeeeeee-dddd-cccc-bbbb-aaaaaaaaaaaa.txt"
        with patch.object(self.api, "_conditional_put") as put:
            with self.assertRaises(recovery.RecoveryError):
                self.api.r2("PUT", TARGET["bucketName"], key, b"x")
            with self.assertRaises(recovery.RecoveryError):
                self.api.r2("PUT", self.api.names["backup"], "production/checkpoints/" + "f" * 32 + "/manifest.json", b"x")
            put.assert_not_called()

    def test_foreign_or_unregistered_restore_id_is_rejected(self):
        with self.assertRaises(recovery.RecoveryError):
            self.api.allow_restore(SOURCE)
        with self.assertRaises(recovery.RecoveryError):
            self.api.allow_restore(DESTINATION)
        self.api.databases.add(DESTINATION)
        self.api.allow_restore(DESTINATION)
        self.assertEqual(self.api.restore_id, DESTINATION)

    def test_all_worker_binding_identity_aliases_are_checked(self):
        self.api.databases.add(DESTINATION)
        self.api.allow_restore(DESTINATION)
        for key in ("id", "database_id"):
            def worker(_method, path):
                if path.endswith("/workers/services"):
                    return []
                if path.endswith("/workers/scripts"):
                    return [{"id": "consumer"}]
                return {"bindings": [{"type": "d1", key: DESTINATION}]}
            self.api.worker_api = inventory_reader(worker)
            with self.subTest(alias=key), self.assertRaises(recovery.RecoveryError):
                self.api.consumer_proof()

    def test_service_environment_binding_blocks_recovery(self):
        def worker(_method, path):
            if path.endswith("/workers/services"):
                return [{"id": "consumer"}]
            if path.endswith("/workers/scripts"):
                return []
            if path.endswith("/environments"):
                return {"id": "consumer", "default_environment": {"environment": "staging"},
                        "environments": [{"environment": "staging"}]}
            return {"bindings": [{"type": "r2_bucket", "bucket_name": self.api.names["objects"]}]}
        self.api.worker_api = inventory_reader(worker)
        with self.assertRaises(recovery.RecoveryError):
            self.api.consumer_proof()

    def test_real_service_wrapper_scans_every_environment_including_the_default(self):
        reads = []
        def worker(_method, path):
            reads.append(path)
            if path.endswith("/workers/services"):
                return [{"id": "consumer"}]
            if path.endswith("/workers/scripts"):
                return []
            if path.endswith("/environments"):
                return {"id": "consumer", "created_on": STAMP, "modified_on": STAMP, "usage_model": "standard",
                        "default_environment": {"environment": "production", "script": {"id": "consumer"}},
                        "environments": [{"environment": "production"}, {"environment": "staging"}]}
            return {"bindings": []}
        self.api.worker_api = inventory_reader(worker)
        result = self.api.consumer_proof()
        self.assertEqual(result["checked"], 2)
        self.assertEqual(result["consumers"], 0)
        self.assertTrue(any(path.endswith("/environments/production/settings") for path in reads))
        self.assertTrue(any(path.endswith("/environments/staging/settings") for path in reads))
        self.assertEqual(set(result), {"checked", "inventorySha256", "consumers"})

    def test_incomplete_wrong_identity_or_unknown_environment_wrappers_are_rejected(self):
        valid = {"id": "consumer", "default_environment": {"environment": "production"},
                 "environments": [{"environment": "production"}]}
        cases = [[], {**valid, "id": "foreign"}, {**valid, "environments": []},
            {**valid, "environments": [{"environment": "staging"}]},
            {**valid, "environments": valid["environments"] * 2},
            {**valid, "default_environment": None}, {**valid, "cursor": "unread-page"},
            {**valid, "environments": [{"environment": "production"}] * recovery.MAX_ENVIRONMENTS}]
        for wrapper in cases:
            def worker(_method, path):
                if path.endswith("/workers/services"):
                    return [{"id": "consumer"}]
                if path.endswith("/workers/scripts"):
                    return []
                if path.endswith("/environments"):
                    return deepcopy(wrapper)
                return {"bindings": []}
            self.api.worker_api = inventory_reader(worker)
            with self.subTest(wrapper=wrapper), self.assertRaises(recovery.RecoveryError):
                self.api.consumer_proof()
            self.assertEqual(self.api.consumer_stage, "service-environments")

    def test_bounded_consumer_inventory_fails_instead_of_truncating(self):
        self.api.worker_api = inventory_reader(lambda _method, _path: [{"id": "worker"}] * recovery.MAX_CONSUMERS)
        with self.assertRaises(recovery.RecoveryError):
            self.api.consumer_proof()

    def test_pagination_metadata_cannot_be_ignored(self):
        self.api.worker_api = SimpleNamespace(json=Mock(return_value={"success": True, "result": [],
            "result_info": {"total_pages": 2}}))
        with self.assertRaises(recovery.RecoveryError):
            self.api.consumer_proof()


class ConsumerTransportTests(unittest.TestCase):
    """Use the real control API parser/transport, including callable-only support."""

    def api(self, metadata=None, *, callable_only=False, stopped_at="services"):
        requests = []
        worker = control.API(TARGET, "synthetic-scoped-worker-read-token")
        def transport(request, *, timeout):
            self.assertEqual(request.method, "GET")
            self.assertIsNone(request.data)
            self.assertEqual(timeout, 45)
            requests.append(request)
            route = request.full_url.split("/accounts/" + ACCOUNT, 1)[1]
            if route.endswith("/workers/services"):
                result = [{"id": "consumer"}]
                info = metadata if stopped_at == "services" else None
            elif route.endswith("/workers/scripts"):
                result, info = [], metadata if stopped_at == "scripts" else None
            elif route.endswith("/environments"):
                result = {"id": "consumer", "default_environment": {"environment": "production"},
                          "environments": [{"environment": "production"}]}
                info = metadata if stopped_at == "environments" else None
            else:
                self.assertTrue(route.endswith("/environments/production/settings"))
                result, info = {"bindings": []}, None
            body = {"success": True, "result": result, **({"result_info": info} if info is not None else {})}
            return BytesIO(recovery.canonical(body))
        worker.opener.open = Mock(side_effect=transport)
        reader = (lambda *args, **kwargs: worker(*args, **kwargs)) if callable_only else worker
        return recovery.RecoveryAPI(TARGET, "synthetic-token", reader, CONTRACT), requests, worker

    def test_real_controller_api_and_callable_only_adapter_read_complete_envelopes(self):
        for callable_only in (False, True):
            api, requests, _worker = self.api({"page": 1, "per_page": 1000, "count": 1, "total_count": 1, "total_pages": 1},
                                               callable_only=callable_only)
            with self.subTest(callable_only=callable_only):
                self.assertEqual(api.consumer_proof()["checked"], 1)
                self.assertEqual(len(requests), 4)
                self.assertTrue(all(request.method == "GET" for request in requests))

    def test_paginated_truncated_or_inconsistent_real_envelopes_stop_before_resource_writes(self):
        metadata = [{"total_pages": 2}, {"total_count": 2}, {"count": 0}, {"page": 2}, {"cursor": "next"},
            {"next_page_token": "next"}, {"is_truncated": True}, {"is_truncated": 0}, {"has_more": True},
            {"total_count": True}, {"total_pages": "1"}, {"per_page": 0}, {"total_pages": 0}]
        for callable_only in (False, True):
            for info in metadata:
                api, requests, _worker = self.api(info, callable_only=callable_only)
                engine = object.__new__(recovery.RecoveryEngine)
                engine.api, engine.source, engine.journal = api, Mock(), Mock()
                engine.verify_resources = Mock()
                engine.verify_preservation = Mock()
                engine.manifest = Mock(return_value=({"objects": []}, None))
                engine.target_objects, engine.restore_object = Mock(), Mock()
                with self.subTest(callable_only=callable_only, info=info), self.assertRaises(recovery.RecoveryError):
                    engine.restore_objects()
                engine.journal.update.assert_not_called()
                engine.target_objects.assert_not_called()
                engine.restore_object.assert_not_called()
                self.assertEqual(len(requests), 1)
                self.assertTrue(all(request.method == "GET" for request in requests))

    def test_pagination_is_checked_at_scripts_and_service_environments_too(self):
        for stopped_at in ("scripts", "environments"):
            api, requests, _worker = self.api({"total_pages": 2}, callable_only=True, stopped_at=stopped_at)
            with self.subTest(stopped_at=stopped_at), self.assertRaises(recovery.RecoveryError):
                api.consumer_proof()
            self.assertEqual(len(requests), 2 if stopped_at == "scripts" else 3)
            self.assertTrue(all(request.method == "GET" for request in requests))

    def test_bare_list_fallback_is_never_accepted_as_a_complete_inventory(self):
        # A callable which ignores the requested envelope cannot prove its list
        # is complete, even if no consumer happens to appear in that list.
        reader = Mock(side_effect=lambda *_args, **_kwargs: [])
        del reader.json
        api = recovery.RecoveryAPI(TARGET, "synthetic-token", reader, CONTRACT)
        with self.assertRaises(recovery.RecoveryError):
            api.consumer_proof()
        reader.assert_called_once_with("GET", api.root + "/workers/services", envelope=True)


class MemoryAPI:
    def __init__(self):
        self.target = deepcopy(TARGET)
        self.contract = deepcopy(CONTRACT)
        self.cohort = CHECKPOINT
        self.root = "/accounts/" + ACCOUNT
        self.names = {"backup": TARGET["backupBucketName"], "database": CONTRACT["databaseName"], "objects": CONTRACT["objectsName"]}
        self.journal_prefix = f"production/recovery/{CHECKPOINT}/journal/"
        self.archive_prefix = f"production/checkpoints/{CHECKPOINT}/"
        self.objects = {}
        self.resources = {}
        self.restore_id = self.restore_bucket = None
        self.unknown_create = self.journal_failure = None
        self.calls = []

    def object_or_none(self, bucket, key):
        return self.objects.get((bucket, key)), None

    def journal_entries(self, generation=None):
        prefix = self.journal_prefix + ("" if generation is None else f"{generation:06d}-")
        return [{"key": key} for bucket, key in self.objects if bucket == self.names["backup"] and key.startswith(prefix)]

    def r2(self, method, bucket, key, body=None):
        self.calls.append((method, bucket, key))
        if method == "GET":
            return self.object_or_none(bucket, key)
        if self.journal_failure != "uncommitted":
            self.objects[(bucket, key)] = body
        if self.journal_failure:
            self.journal_failure = None
            raise recovery.RecoveryError(uncertain=True)

    def verify_backup(self):
        pass

    def verify_bucket(self, *_args):
        pass

    def allow_restore(self, database_id=None, keys=None, object_bucket=None):
        if database_id:
            self.restore_id = database_id
        if object_bucket:
            self.restore_bucket = object_bucket

    def json(self, method, path, payload=None):
        self.calls.append((method, path, payload))
        if method == "POST":
            kind = "database" if path.endswith("/d1/database") else "objects"
            value = {"name": self.names[kind], "created_at" if kind == "database" else "creation_date": STAMP}
            value.update({"uuid": DESTINATION} if kind == "database" else {"jurisdiction": "default"})
            self.resources[kind] = value
            if self.unknown_create:
                raise recovery.RecoveryError(uncertain=True)
            return value
        raise AssertionError("Unexpected read")


class EngineTests(unittest.TestCase):
    def test_sealed_source_recheck_precedes_resource_creation(self):
        engine = object.__new__(recovery.RecoveryEngine)
        engine.journal = Mock(value={"backup": {"manifestSha256": "a" * 64}})
        engine.verify_preservation = Mock(side_effect=recovery.RecoveryError("source changed"))
        with patch.object(recovery.native.Rehearsal, "create") as create, self.assertRaises(recovery.RecoveryError):
            engine.create("database")
        create.assert_not_called()

    def test_baseline_preservation_checks_current_referenced_object_bytes_and_metadata(self):
        body = b"synthetic-preserved-object"
        metadata = {"custom": {}, "http": {}}
        for changed in (False, True):
            engine = object.__new__(recovery.RecoveryEngine)
            engine.source = SimpleNamespace(before_write=Mock(), current={"control": {"epoch": 1}})
            engine.journal = Mock(value={"sourcePin": {"observed": engine.source.current}})
            engine.api = Mock(contract={"purpose": "baseline"}, target={"d1Id": SOURCE, "bucketName": "source"})
            engine.api.object_or_none.return_value = (b"changed" if changed else body, None)
            engine.object_metadata = Mock(return_value=metadata)
            entry = {"key": "private-shares/synthetic.txt", "bytes": len(body), "sha256": recovery.digest(body), "metadata": metadata}
            engine.manifest = Mock(return_value=({"layout": {}, "summary": {"rowCount": 1}, "objects": [entry]}, None))
            with self.subTest(changed=changed), patch.object(recovery.native, "remote_summary", return_value={"rowCount": 1}):
                if changed:
                    with self.assertRaises(recovery.RecoveryError):
                        engine.verify_preservation()
                else:
                    engine.verify_preservation()
                    engine.object_metadata.assert_called_once_with("source", entry["key"], len(body))

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.api = MemoryAPI()
        self.source = SimpleNamespace(scope_sha256=PIN["scopeSha256"], before_write=Mock(),
                                      verify=Mock(return_value=PIN), manifest={}, current={})
        self.journal = recovery.RecoveryJournal(self.api, "10/1")
        self.engine = recovery.RecoveryEngine(self.api, self.source, self.journal, Path(self.temp.name))
        self.engine.observe = Mock(side_effect=lambda kind: recovery.native.resource_identity(kind, self.api.resources[kind], self.api.names[kind])
                                  if kind in self.api.resources else None)
        self.engine.prepare(PIN)

    def test_journal_is_private_backup_only_and_reconciles_lost_ack(self):
        self.api.journal_failure = "committed"
        self.journal.update(phase="safe")
        other = recovery.RecoveryJournal(self.api, "10/1")
        self.assertEqual(other.load()["phase"], "safe")
        self.assertTrue(all(bucket == self.api.names["backup"] for bucket, _key in self.api.objects))

    def test_reloading_missing_or_unreadable_journal_clears_prior_observation(self):
        self.assertIsNotNone(self.journal.value)
        self.journal.poisoned = True
        with patch.object(self.journal, "keys", return_value=[]):
            self.assertIsNone(self.journal.load())
        self.assertEqual((self.journal.generation, self.journal.key, self.journal.raw, self.journal.value),
                         (0, None, None, None))
        self.assertTrue(self.journal.poisoned)
        self.journal.generation, self.journal.key, self.journal.raw, self.journal.value = 1, "old", b"old", {"old": True}
        with patch.object(self.journal, "keys", side_effect=OSError("synthetic read error")), self.assertRaises(OSError):
            self.journal.load()
        self.assertEqual((self.journal.generation, self.journal.key, self.journal.raw, self.journal.value),
                         (0, None, None, None))
        self.assertTrue(self.journal.poisoned)

    def test_corrupt_later_generation_never_leaves_partial_journal_state(self):
        self.journal.update(phase="safe")
        keys = self.journal.keys()
        self.assertGreaterEqual(len(keys), 2)
        first = self.api.object_or_none(self.api.names["backup"], keys[0])
        with patch.object(self.api, "object_or_none", side_effect=[first, (b"{}", None)]), \
                self.assertRaises(recovery.RecoveryError):
            self.journal.load()
        self.assertEqual((self.journal.generation, self.journal.key, self.journal.raw, self.journal.value),
                         (0, None, None, None))

    def test_unconfirmed_journal_blocks_all_following_writes(self):
        self.api.journal_failure = "uncommitted"
        with self.assertRaises(recovery.RecoveryError) as caught:
            self.journal.update(phase="unsafe")
        self.assertTrue(caught.exception.uncertain)
        with self.assertRaises(recovery.RecoveryError):
            self.journal.update(phase="later")

    def test_interrupted_create_is_not_repeated_or_silently_adopted(self):
        self.api.unknown_create = True
        with self.assertRaises(recovery.RecoveryError):
            self.engine.create("database")
        self.assertIsNone(self.journal.value["resources"]["database"]["pin"])
        calls = len([call for call in self.api.calls if call[0] == "POST"])
        with self.assertRaises(recovery.RecoveryError):
            self.engine.create("database")
        self.assertEqual(len([call for call in self.api.calls if call[0] == "POST"]), calls)

    def test_repeated_confirmed_create_reads_pin_without_mutation(self):
        self.engine.create("database")
        calls = len(self.api.calls)
        self.engine.create("database")
        self.assertEqual(len(self.api.calls), calls)

    def test_existing_unknown_name_prevents_prepare_before_journal_mutation(self):
        self.api.resources["database"] = {"name": self.api.names["database"], "created_at": STAMP, "uuid": DESTINATION}
        second = recovery.RecoveryJournal(self.api, "20/1")
        engine = recovery.RecoveryEngine(self.api, self.source, second, Path(self.temp.name))
        engine.observe = self.engine.observe
        calls = len(self.api.calls)
        with self.assertRaises(recovery.RecoveryError):
            engine.prepare(PIN)
        self.assertEqual(len(self.api.calls), calls)

    def test_no_current_g1_prevents_recovery_mutations(self):
        self.api.contract["purpose"] = "recovery"
        with self.assertRaises(recovery.RecoveryError):
            self.engine.before_target_write()

    def test_object_resume_checks_confirmed_bytes_and_advances_only_remaining_ordinals(self):
        first, second = b"already-confirmed", b"still-to-restore"
        keys = ["private-shares/11111111-2222-3333-4444-555555555555.txt",
                "private-shares/66666666-7777-8888-9999-aaaaaaaaaaaa.txt"]
        entries = [{"key": key, "bytes": len(body), "sha256": recovery.digest(body), "metadata": {"custom": {}, "http": {}}}
                   for key, body in zip(keys, (first, second))]
        self.api.objects[(self.api.names["objects"], keys[0])] = first
        self.api.objects[(self.api.names["backup"], self.api.archive_prefix + "blobs/" + entries[1]["sha256"])] = second
        self.journal.update(objectConfirmed=1)
        self.engine.verify_resources = Mock()
        self.engine.manifest = Mock(return_value=({"objects": entries}, None))
        self.engine.before_target_write = Mock()
        self.engine.verify_preservation = Mock()
        self.engine.target_objects = Mock(return_value={keys[0]})
        self.engine.verify_object_bytes = Mock()
        self.engine.restore_object = Mock()
        self.api.consumer_proof = Mock()
        self.engine.restore_objects()
        self.engine.restore_object.assert_called_once_with(entries[1], second)
        self.assertEqual(self.journal.value["objectConfirmed"], 2)
        self.assertEqual(self.journal.value["phase"], "objects-restored")
        # A reused ordinal is never trusted after target bytes change.
        self.api.objects[(self.api.names["objects"], keys[0])] = b"changed"
        self.engine.restore_object.reset_mock()
        with self.assertRaises(recovery.RecoveryError):
            self.engine.restore_objects()
        self.engine.restore_object.assert_not_called()


class SourceTests(unittest.TestCase):
    def source(self, result):
        source = object.__new__(recovery.RecoverySource)
        source.scope_sha256 = recovery.digest(recovery.canonical(TARGET))
        source.verify_source = Mock(return_value=result)
        return source

    def observation(self):
        return {"targetSha256": recovery.digest(recovery.canonical(TARGET)),
                "release": {"revision": "b" * 40, "moduleSha256": "c" * 64, "versionId": DESTINATION},
                "control": {"epoch": 1, "admission": "closed", "workers": "frozen"},
                "work": {"invocations": 0, "outbox": 0}, "terminal": {"uncertain": 2, "failed": 1}}

    def test_terminal_evidence_is_retained_without_becoming_work(self):
        value = self.observation()
        self.assertEqual(self.source(value).observe()["terminal"], value["terminal"])

    def test_missing_frozen_pause_nonzero_work_or_wrong_target_stops(self):
        for mutate in (lambda v: v["control"].update(admission="open"),
                       lambda v: v["control"].update(workers="drain"),
                       lambda v: v["work"].update(invocations=1),
                       lambda v: v.update(targetSha256="f" * 64),
                       lambda v: v.update(work={})):
            value = self.observation()
            mutate(value)
            with self.subTest(value=value), self.assertRaises(recovery.RecoveryError):
                self.source(value).observe()


class CodeArchiveTests(unittest.TestCase):
    def fixture(self):
        api = MemoryAPI()
        body = b"synthetic-original-ci-archive-bytes"
        proof = {"revision": "b" * 40, "runId": "10", "runAttempt": "1", "artifactId": "11", "archiveSha256": recovery.digest(body)}
        key = api.archive_prefix + "code/0.zip"
        api.objects[(api.names["backup"], key)] = body
        document = {"codeArtifact": {"proof": proof, "bytes": len(body), "sha256": recovery.digest(body),
            "parts": [{"key": key, "bytes": len(body), "sha256": recovery.digest(body)}]}}
        return api, body, proof, document

    def test_private_archive_readback_retains_original_bytes_and_ci_proof(self):
        api, body, proof, document = self.fixture()
        self.assertEqual(recovery.load_code_archive(api, document, api.archive_prefix), (body, proof))

    def test_missing_tampered_and_cross_checkpoint_parts_are_rejected(self):
        for failure in ("missing", "tampered", "cross-checkpoint"):
            api, _body, _proof, document = self.fixture()
            part = document["codeArtifact"]["parts"][0]
            if failure == "missing":
                api.objects.clear()
            elif failure == "tampered":
                api.objects[(api.names["backup"], part["key"])] = b"tampered"
            else:
                part["key"] = "production/checkpoints/" + "f" * 32 + "/code/0.zip"
            with self.subTest(failure=failure), self.assertRaises(recovery.RecoveryError):
                recovery.load_code_archive(api, document, api.archive_prefix)

    def test_archive_part_count_limit_fails_without_truncation(self):
        api, _body, _proof, document = self.fixture()
        document["codeArtifact"]["parts"] *= 33
        with self.assertRaises(recovery.RecoveryError):
            recovery.load_code_archive(api, document, api.archive_prefix)


if __name__ == "__main__":
    unittest.main()

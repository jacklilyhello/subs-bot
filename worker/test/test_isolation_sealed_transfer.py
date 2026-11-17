"""Hosted synthetic checks for the fixed ciphertext-only transfer."""
import base64
import ctypes
from hashlib import sha256
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import isolation_sealed_transfer as transfer
from production_target import ContractError


def keypair():
    sodium = ctypes.CDLL("/usr/lib/x86_64-linux-gnu/libsodium.so.23")
    sodium.sodium_init.restype = ctypes.c_int
    if sodium.sodium_init() < 0:
        raise AssertionError("Hosted libsodium initialization failed")
    sodium.crypto_box_keypair.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
    sodium.crypto_box_keypair.restype = ctypes.c_int
    public, private = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
    if sodium.crypto_box_keypair(public, private) != 0:
        raise AssertionError("Synthetic keypair creation failed")
    return sodium, public.raw, private.raw


def environment(mapping, public, directory):
    source, destination, source_name, destination_name, _ = transfer.MAPPINGS[mapping]
    encoded = base64.b64encode(public).decode("ascii")
    statement = {"version": 1, "repositoryId": transfer.github.REPOSITORY_ID, "environment": destination, "environmentId": "789",
                 "keyId": "123456", "publicKey": encoded}
    return {"GITHUB_REPOSITORY": transfer.github.REPOSITORY, "GITHUB_REPOSITORY_ID": str(transfer.github.REPOSITORY_ID),
            "GITHUB_REF": transfer.github.MAIN_REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_WORKFLOW_REF": transfer.WORKFLOW, "GITHUB_SHA": "a" * 40, "GITHUB_WORKFLOW_SHA": "a" * 40,
            "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_TEMP": directory,
            "TRANSFER_MAPPING": mapping, "TRANSFER_SOURCE_ENVIRONMENT": source,
            "TRANSFER_DESTINATION_ENVIRONMENT": destination, "TRANSFER_SOURCE_NAME": source_name,
            "TRANSFER_DESTINATION_NAME": destination_name, "TRANSFER_DESTINATION_ENVIRONMENT_ID": "789",
            "TRANSFER_KEY_ID": "123456", "TRANSFER_PUBLIC_KEY": encoded,
            "TRANSFER_DESTINATION_KEY_PIN": sha256(transfer.canonical(statement)).hexdigest()}


class SealedTransferTests(unittest.TestCase):
    def test_fixed_mapping_and_independent_public_key_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            env = environment("backup-bot", b"a" * 32, directory)
            with patch.object(transfer.github, "require_current_main"):
                self.assertEqual(transfer.gate(env)["destinationName"], "SUBS_BOT_TELEGRAM_TEST_CONFIG")
                for change in ({"TRANSFER_MAPPING": "arbitrary-token"}, {"TRANSFER_DESTINATION_ENVIRONMENT": "production"},
                               {"TRANSFER_SOURCE_NAME": "CF_TOKEN_MANAGER_API_TOKEN"}, {"TRANSFER_DESTINATION_KEY_PIN": "0" * 64},
                               {"GITHUB_RUN_ATTEMPT": "2"}, {"GITHUB_REF": "refs/heads/feature"}):
                    with self.subTest(change=change), self.assertRaises(ContractError):
                        transfer.gate({**env, **change})

    def test_key_plan_needs_no_source_secret_or_protected_pin(self):
        with tempfile.TemporaryDirectory() as directory:
            env = environment("backup-target", b"a" * 32, directory)
            source_names = ("TRANSFER_SOURCE_ENVIRONMENT", "TRANSFER_DESTINATION_ENVIRONMENT", "TRANSFER_SOURCE_NAME",
                            "TRANSFER_DESTINATION_NAME")
            source_fields = {name: env[name] for name in source_names}
            for name in (*source_names, "TRANSFER_DESTINATION_KEY_PIN"):
                env.pop(name)
            with patch.object(transfer.github, "require_current_main"):
                result = transfer.key_plan(env)
                with self.assertRaises(ContractError):
                    transfer.gate({**env, **source_fields})
            self.assertEqual(result["destination"], "subs-bot-backup-head-isolation")
            self.assertEqual(len(result["keyPinSha256"]), 64)

    def test_source_metadata_requires_fresh_exact_operator_pin_and_no_fallback(self):
        value = {"version": 1, "repositoryId": transfer.github.REPOSITORY_ID, "environment": "subs-bot-provider-isolation",
                 "environmentId": "456", "branchPolicies": ["main"], "repositoryConflicts": [], "checkedAt": 1000,
                 "environmentSecrets": [{"name": "SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", "updatedAt": "2026-01-01T00:00:00Z"}]}
        digest = sha256(transfer.canonical(value)).hexdigest()
        env = {"TRANSFER_SOURCE_METADATA_JSON": json.dumps(value), "TRANSFER_SOURCE_METADATA_SHA256": digest,
               "TRANSFER_SOURCE_ENVIRONMENT_ID": "456"}
        required = ("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON",)
        self.assertEqual(transfer.operator_source_metadata(env, "subs-bot-provider-isolation", required, now=1001), digest)
        with self.assertRaises(ContractError):
            transfer.operator_source_metadata(env, "subs-bot-provider-isolation", required, now=2801)
        with self.assertRaises(ContractError):
            transfer.operator_source_metadata({**env, "TRANSFER_SOURCE_METADATA_JSON": json.dumps({**value, "repositoryConflicts": [required[0]]})},
                                              "subs-bot-provider-isolation", required, now=1001)
        with self.assertRaises(ContractError):
            transfer.operator_source_metadata({**env, "TRANSFER_SOURCE_ENVIRONMENT_ID": "789"}, "subs-bot-provider-isolation", required, now=1001)

    def test_ciphertext_only_roundtrip_with_synthetic_bot(self):
        sodium, public, private = keypair()
        secret = json.dumps({"botId": transfer.TEST_BOT_ID, "botUsername": "test_cfsubs_bot",
            "botToken": transfer.TEST_BOT_ID + ":SYNTHETIC_TOKEN_VALUE_123456789", "webhookSecret": "S" * 40,
            "adminId": "8813701954", "memberId": "8653767757", "groupId": "-5114255828"}, separators=(",", ":"))
        with tempfile.TemporaryDirectory() as directory:
            metadata = {"version": 1, "repositoryId": transfer.github.REPOSITORY_ID, "environment": "subs-bot-isolation",
                        "environmentId": "456", "branchPolicies": ["main"], "repositoryConflicts": [], "checkedAt": int(time.time()),
                        "environmentSecrets": [{"name": name, "updatedAt": "2026-01-01T00:00:00Z"} for name in
                            ("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "SUBS_BOT_CONTROL_DRILL_KEYS", "SUBS_BOT_TELEGRAM_TEST_CONFIG",
                             "SUBS_BOT_SEALED_WORKER_READ_TOKEN", "SUBS_BOT_SEALED_R2_ACCESS_KEY_ID",
                             "SUBS_BOT_SEALED_R2_SECRET_ACCESS_KEY", "SUBS_BOT_SEALED_SOURCE_EVIDENCE_JSON")]}
            metadata_sha = sha256(transfer.canonical(metadata)).hexdigest()
            env = {**environment("backup-bot", public, directory), "TRANSFER_SOURCE_VALUE": secret,
                   "TRANSFER_SOURCE_METADATA_JSON": json.dumps(metadata), "TRANSFER_SOURCE_METADATA_SHA256": metadata_sha,
                   "TRANSFER_SOURCE_ENVIRONMENT_ID": "456", "TRANSFER_ATTESTED_METADATA_SHA256": metadata_sha,
                   "TRANSFER_ATTESTED_SOURCE_SHA256": sha256(secret.encode()).hexdigest()}
            source_proof = {"metadataSha256": metadata_sha,
                            "sourceHashes": {"SUBS_BOT_TELEGRAM_TEST_CONFIG": sha256(secret.encode()).hexdigest()}}
            with patch.object(transfer.github, "require_current_main"), \
                 patch.object(transfer, "attest_isolation_source", return_value=source_proof):
                result = transfer.payload(env)
            artifact = Path(directory, "isolation-sealed-transfer.json").read_bytes()
        self.assertNotIn(secret.encode(), artifact)
        self.assertNotIn(b"SYNTHETIC_TOKEN_VALUE", artifact)
        self.assertNotIn("SYNTHETIC_TOKEN_VALUE", json.dumps(result))
        body = json.loads(artifact)
        self.assertEqual(set(body), {"encrypted_value", "key_id"})
        ciphertext = base64.b64decode(body["encrypted_value"], validate=True)
        plaintext = ctypes.create_string_buffer(len(ciphertext) - 48)
        sodium.crypto_box_seal_open.argtypes = (ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulonglong, ctypes.c_void_p, ctypes.c_void_p)
        sodium.crypto_box_seal_open.restype = ctypes.c_int
        self.assertEqual(sodium.crypto_box_seal_open(plaintext, ctypes.create_string_buffer(ciphertext), len(ciphertext),
                                                     ctypes.create_string_buffer(public), ctypes.create_string_buffer(private)), 0)
        self.assertEqual(plaintext.raw, secret.encode())

    def test_wrong_bot_is_refused_and_archive_location_is_minimized(self):
        with self.assertRaises(ContractError):
            transfer.checked_source("backup-bot", json.dumps({"botId": "1"}))
        original = {"accountId": "9431815bdb8beb2272f6668e06b7d3be", "workerId": "private-worker",
                    "workerCreatedOn": "2026-01-01T00:00:00Z", "d1Id": "private-db", "d1CreatedAt": "2026-01-01T00:00:00Z",
                    "r2CreatedOn": "2026-01-01T00:00:00Z", "namespace": "lilyya"}
        reduced = json.loads(transfer.checked_source("provider-archive-location", json.dumps(original)))
        self.assertEqual(set(reduced), {"accountId", "namespace", "r2CreatedOn"})

    def test_workflow_uses_only_static_secret_references_and_no_tokens(self):
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/worker-isolation-sealed-transfer.yml").read_text()
        self.assertNotIn("secrets[", workflow)
        self.assertNotIn("CF_TOKEN_MANAGER", workflow)
        self.assertNotIn("SUBS_BOT_CF_BOOTSTRAP_TOKEN", workflow)
        self.assertIn("SUBS_BOT_SEALED_TRANSFER_ENABLED == 'true'", workflow)

    def test_transfer_is_disabled_without_independent_source_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            env = environment("backup-bot", b"a" * 32, directory)
            with patch.object(transfer.github, "require_current_main"), self.assertRaises(ContractError):
                transfer.payload(env)
            self.assertFalse(Path(directory, "isolation-sealed-transfer.json").exists())

    def test_changed_source_value_is_rejected_before_encryption(self):
        with tempfile.TemporaryDirectory() as directory:
            original = "synthetic-original"
            env = {**environment("backup-bot", b"a" * 32, directory), "TRANSFER_SOURCE_VALUE": "synthetic-changed",
                   "TRANSFER_ATTESTED_METADATA_SHA256": "b" * 64,
                   "TRANSFER_ATTESTED_SOURCE_SHA256": sha256(original.encode()).hexdigest()}
            proof = {"metadataSha256": "b" * 64,
                     "sourceHashes": {"SUBS_BOT_TELEGRAM_TEST_CONFIG": sha256(original.encode()).hexdigest()}}
            with patch.object(transfer.github, "require_current_main"), \
                 patch.object(transfer, "attest_isolation_source", return_value=proof), \
                 patch.object(transfer, "seal") as seal, self.assertRaises(ContractError):
                transfer.payload(env)
            seal.assert_not_called()

    def test_registered_configuration_binds_signing_key_digests(self):
        import production_control
        import production_lifecycle_drill
        import production_target
        pins = {key: "registered-" + key for key in
                ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")}
        registered = SimpleNamespace(environment="rehearsal", digest="target-digest",
                                     configuration_digest="configuration-digest",
                                     data={**pins, "botId": transfer.TEST_BOT_ID})
        draft = SimpleNamespace(data={"keyDigests": {"aggregate": "approved"}}, digest="draft-digest")
        previous = {"botId": transfer.TEST_BOT_ID, "botUsername": "test_cfsubs_bot"}
        original = {"accountId": "a" * 32, "workerId": "original-worker", "workerCreatedOn": "worker-created",
                    "d1Id": "original-d1", "d1CreatedAt": "d1-created", "r2CreatedOn": "bucket-created"}
        registration = transfer.canonical({"target": {}, "draftSha256": draft.digest, "targetSha256": registered.digest,
                                           "configurationSha256": registered.configuration_digest})
        required_names = ("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "SUBS_BOT_CONTROL_DRILL_KEYS",
                          "SUBS_BOT_TELEGRAM_TEST_CONFIG")
        env = {name: "synthetic" for name in required_names}
        env.update({"GITHUB_SHA": "a" * 40, "TRANSFER_REGISTRATION_SHA256": sha256(registration).hexdigest()})

        class FakeAPI:
            root = "https://example.invalid"
            def __init__(self, target, token):
                pass
            def __call__(self, method, path):
                if "/workers/" in path:
                    return {"id": original["workerId"], "name": production_lifecycle_drill.ORIGINAL_SERVICE,
                            "created_on": original["workerCreatedOn"]}
                return {"uuid": original["d1Id"], "name": production_lifecycle_drill.ORIGINAL_SERVICE,
                        "created_at": original["d1CreatedAt"]}

        def validate(value):
            if not value:
                return registered
            return SimpleNamespace(configuration_digest="configuration-digest" if
                                   value["keyDigests"]["aggregate"] == "approved" else "different")

        with patch.object(transfer, "operator_source_metadata", return_value="metadata"), \
             patch.object(production_lifecycle_drill, "configuration", return_value=(draft, {}, previous, original)), \
             patch.object(production_control, "API", FakeAPI), \
             patch.object(production_control, "Telegram") as telegram, \
             patch.object(transfer, "operator_resource_evidence", return_value="evidence"), \
             patch.object(transfer, "read_isolation_registration", return_value=registration), \
             patch.object(production_target, "validate_target", side_effect=validate), \
             patch.object(transfer.github, "require_current_main"):
            self.assertEqual(transfer.attest_isolation_source(env)["registrationSha256"], env["TRANSFER_REGISTRATION_SHA256"])
            telegram.return_value.identity.assert_called_once()
            draft.data["keyDigests"]["aggregate"] = "changed"
            with self.assertRaises(ContractError):
                transfer.attest_isolation_source(env)

    def test_resource_observation_is_pinned_fresh_and_never_called_live(self):
        original = {"workerId": "original", "d1Id": "database"}
        evidence = {"version": 1, "checkedAt": 1000, "sourceTarget": original,
                    "databaseName": "subs-bot-cf-dev-01", "bucketName": "subs-bot-cf-dev-01",
                    "bucketPublicAccessDisabled": True, "bucketDeletionRulesDisabled": True, "bucketJurisdiction": "default",
                    "registrationSha256": "c" * 64}
        env = {"SUBS_BOT_SEALED_SOURCE_EVIDENCE_JSON": json.dumps(evidence),
               "TRANSFER_SOURCE_EVIDENCE_SHA256": sha256(transfer.canonical(evidence)).hexdigest()}
        self.assertEqual(transfer.operator_resource_evidence(env, original, "c" * 64, now=1001), env["TRANSFER_SOURCE_EVIDENCE_SHA256"])
        for changed, pin, timestamp in ((original, "c" * 64, 2801), ({**original, "d1Id": "wrong"}, "c" * 64, 1001),
                                        (original, "d" * 64, 1001)):
            with self.assertRaises(ContractError):
                transfer.operator_resource_evidence(env, changed, pin, now=timestamp)
        for field in ("bucketPublicAccessDisabled", "bucketDeletionRulesDisabled"):
            unsafe = {**evidence, field: False}
            changed_env = {"SUBS_BOT_SEALED_SOURCE_EVIDENCE_JSON": json.dumps(unsafe),
                           "TRANSFER_SOURCE_EVIDENCE_SHA256": sha256(transfer.canonical(unsafe)).hexdigest()}
            with self.assertRaises(ContractError):
                transfer.operator_resource_evidence(changed_env, original, "c" * 64, now=1001)

    def test_s3_registration_get_is_fixed_and_bounded(self):
        env = {"SUBS_BOT_SEALED_R2_ACCESS_KEY_ID": "a" * 32, "SUBS_BOT_SEALED_R2_SECRET_ACCESS_KEY": "b" * 64}
        key = "maintenance/production-control/evidence/lifecycle-" + "c" * 64 + "/registration.json"
        with patch.object(transfer, "HTTPSConnection") as client:
            response = client.return_value.getresponse.return_value
            response.status = 200
            response.getheader.return_value = "identity"
            response.read.return_value = b"registration"
            self.assertEqual(transfer.read_isolation_registration(env, "d" * 32, key), b"registration")
            args, kwargs = client.return_value.request.call_args
            self.assertEqual(args[:2], ("GET", "/subs-bot-cf-dev-01/" + key))
            self.assertTrue(kwargs["headers"]["Authorization"].startswith("AWS4-HMAC-SHA256 "))
            response.read.assert_called_once_with(512 * 1024 + 1)
            with self.assertRaises(ContractError):
                transfer.read_isolation_registration(env, "d" * 32, "../other-bucket")


if __name__ == "__main__":
    unittest.main()

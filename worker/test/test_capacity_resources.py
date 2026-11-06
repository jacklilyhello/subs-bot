"""Exercise capacity fixture management with SQLite and an in-memory R2 fake."""

from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import sqlite3
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import capacity_resources as capacity


REVISION = "a" * 40
RUN = "12345678"
TARGET = {
    "accountId": "a" * 32,
    "workerId": "b" * 32,
    "workerCreatedOn": "2026-01-01T00:00:00Z",
    "d1Id": "11111111-1111-4111-8111-111111111111",
    "d1CreatedAt": "2026-01-02T00:00:00Z",
    "r2CreatedOn": "2026-01-03T00:00:00Z",
    "namespace": capacity.NAMESPACE,
}
ACCOUNT = "/accounts/" + TARGET["accountId"]
DATABASE = ACCOUNT + "/d1/database/" + TARGET["d1Id"]
BUCKET = ACCOUNT + "/r2/buckets/" + capacity.WORKER_NAME


def digest(value):
    return sha256(value).hexdigest()


def write_private(path, body):
    path.write_bytes(body)
    path.chmod(0o600)
    return digest(body)


def fixtures(directory):
    share = capacity.SHARE_PREFIX + b"capacity-000000-x"
    line = b'{"share":"' + share + b'","pad":"p"}\n'
    over_line = b'{"share":"' + share + b'x","pad":""}\n'
    rows = []
    for index, (label, status) in enumerate(capacity.STATUS.items(), 1):
        (directory / label).mkdir(mode=0o700)
        snapshot_id = f"{index:08d}-1111-4111-8111-111111111111"
        physical = label != "snapshot-over"
        body = line if label == "at-limits" else over_line
        node_bytes = len(body) if physical else len(line) + 1
        share_bytes = (len(share) + (label == "share-over")) if physical else 0
        descriptor = {"count": 1, "bytes": node_bytes, "sha256": digest(body)}
        chunks = []
        if physical:
            file = f"{label}/0.ndjson"
            write_private(directory / file, body)
            chunks.append({"file": file, **descriptor})
        manifest = f"{label}/manifest.json"
        manifest_sha = write_private(directory / manifest,
                                     json.dumps({"version": 1, "chunks": [descriptor]}).encode())
        rows.append({
            "label": label, "token": "subsbot-synthetic-capacity-" + str(index) * 32,
            "snapshotId": snapshot_id, "nodeCount": 1, "nodeBytes": node_bytes, "shareBytes": share_bytes,
            "exportBytes": len(b64encode(share)) if status == 200 else 0,
            "exportSha256": digest(b64encode(share)) if status == 200 else None,
            "manifestFile": manifest, "manifestSha256": manifest_sha, "status": status, "chunks": chunks,
        })
    write_private(directory / "capacity.json", json.dumps({"version": 1, "revision": REVISION, "fixtures": rows}).encode())
    return rows, len(share), len(line)


class FakeCloud:
    def __init__(self, directory):
        self.directory = directory
        self.db = sqlite3.connect(":memory:")
        self.db.row_factory = sqlite3.Row
        sql = Path(__file__).resolve().parents[1] / "migrations" / "0001_subscriptions.sql"
        self.db.executescript(sql.read_text(encoding="utf-8"))
        self.db.execute(
            "INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at) "
            "VALUES ('10','Other row','https://example.invalid/other','unrelated-dummy-token',1,1)",
        )
        self.db.commit()
        self.objects = {}
        self.writes = []
        self.lose_insert = False
        self.lose_upload = False
        self.lose_publish = False
        self.public_bucket = False
        self.defer_insert = None
        self.defer_put = None
        self.pending_insert = None
        self.pending_put = None

    def __call__(self, method, path, payload=None):
        if method == "GET":
            return {
                DATABASE: {"uuid": TARGET["d1Id"], "name": capacity.WORKER_NAME, "created_at": TARGET["d1CreatedAt"]},
                BUCKET: {"name": capacity.WORKER_NAME, "creation_date": TARGET["r2CreatedOn"], "jurisdiction": "default"},
                BUCKET + "/domains/managed": {"enabled": self.public_bucket},
                BUCKET + "/domains/custom": {"domains": []},
            }[path]
        assert method == "POST" and path == DATABASE + "/query"
        sql = payload["sql"]
        kind = sql.split()[0]
        if kind == "SELECT" and self.pending_insert is not None:
            delay, pending_sql, pending_params = self.pending_insert
            if delay == 0:
                self.db.execute(pending_sql, pending_params)
                self.db.commit()
                self.pending_insert = None
            elif delay > 0:
                self.pending_insert = (delay - 1, pending_sql, pending_params)
        if kind != "SELECT":
            assert (self.directory / capacity.LEDGER_FILE).is_file()
            self.writes.append(kind)
        if kind == "INSERT":
            ledger = json.loads((self.directory / capacity.LEDGER_FILE).read_bytes())
            assert any(entry["reservePending"] for entry in ledger["fixtures"])
            if self.defer_insert is not None:
                self.pending_insert = (self.defer_insert, sql, payload["params"])
                self.defer_insert = None
                raise capacity.CloudflareError("Synthetic delayed insert response.", uncertain=True)
        cursor = self.db.execute(sql, payload["params"])
        rows = [dict(row) for row in cursor] if cursor.description is not None else []
        self.db.commit()
        if kind == "INSERT" and self.lose_insert:
            self.lose_insert = False
            raise capacity.CloudflareError("Synthetic lost insert response.", uncertain=True)
        if kind == "UPDATE" and self.lose_publish:
            self.lose_publish = False
            raise capacity.CloudflareError("Synthetic lost publication response.", uncertain=True)
        return [{"success": True, "results": rows}]

    def request(self, method, key, body=None):
        if method == "GET":
            if self.pending_put is not None and self.pending_put[1] == key:
                delay, _, pending_body = self.pending_put
                if delay == 0:
                    self.objects[key] = pending_body
                    self.pending_put = None
                elif delay > 0:
                    self.pending_put = (delay - 1, key, pending_body)
            return self.objects.get(key)
        self.writes.append(method)
        if method == "PUT":
            assert key not in self.objects
            ledger = json.loads((self.directory / capacity.LEDGER_FILE).read_bytes())
            assert any(capacity.object_key(entry, index) == key
                       for entry in ledger["fixtures"] for index in entry["putPending"])
            assert self.db.execute(
                "SELECT generation FROM subscriptions WHERE id=?", (int(key.split("/")[1]),),
            ).fetchone()[0] == 0
            if self.defer_put is not None:
                self.pending_put = (self.defer_put, key, body)
                self.defer_put = None
                raise capacity.CapacityError("Synthetic delayed upload response.")
            self.objects[key] = body
            if self.lose_upload:
                self.lose_upload = False
                raise capacity.CapacityError("Synthetic lost upload response.")
        elif method == "DELETE":
            assert self.capacity_rows() == []
            self.objects.pop(key, None)
        else:
            raise AssertionError("Unexpected object method.")

    def capacity_rows(self):
        return self.db.execute("SELECT * FROM subscriptions WHERE owner_id=? ORDER BY id", (capacity.OWNER,)).fetchall()


class CapacityTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.fixtures, shares, snapshot = fixtures(self.directory)
        limits = patch.multiple(capacity, NODE_COUNT=1, SHARE_BYTES=shares, SNAPSHOT_BYTES=snapshot)
        limits.start()
        self.addCleanup(limits.stop)
        self.cloud = FakeCloud(self.directory)
        self.addCleanup(self.cloud.db.close)
        self.resources = capacity.Resources(TARGET, self.cloud, self.cloud)
        self.guard = Mock()
        wait = patch.object(capacity, "sleep")
        self.wait = wait.start()
        self.addCleanup(wait.stop)

    def seed(self):
        with capacity.locked_directory(self.directory):
            capacity.seed(self.directory, self.resources, REVISION, RUN, self.guard)

    def cleanup(self):
        with capacity.locked_directory(self.directory):
            capacity.cleanup(self.directory, self.resources)

    def ledger(self):
        return capacity.load_ledger(self.directory, self.resources.scope_hash)

    def test_seed_then_retire_exact_owned_resources(self):
        self.seed()
        self.assertEqual([row["generation"] for row in self.cloud.capacity_rows()], [1, 1, 1])
        for row in self.cloud.capacity_rows():
            self.assertIn(f"/{RUN}/{REVISION}/", row["source_url"])
        journal = self.directory / capacity.LEDGER_FILE
        self.assertEqual(journal.stat().st_mode & 0o777, 0o600)
        for fixture in self.fixtures:
            self.assertNotIn(fixture["token"], journal.read_text(encoding="ascii"))
        self.assertEqual(len(self.cloud.objects), 5)
        self.assertEqual(self.guard.call_count, 2)
        writes = list(self.cloud.writes)
        self.seed()
        self.assertEqual(self.cloud.writes, writes)
        (self.directory / "capacity.json").unlink()  # The journal is sufficient for cleanup.
        self.cleanup()
        self.assertEqual(self.cloud.capacity_rows(), [])
        self.assertEqual(self.cloud.objects, {})
        self.assertEqual(self.cloud.db.execute("SELECT name FROM subscriptions").fetchone()[0], "Other row")
        self.assertEqual(self.ledger()["phase"], "retired")
        writes = list(self.cloud.writes)
        self.cleanup()
        self.assertEqual(self.cloud.writes, writes)

    def test_lost_write_responses_are_reconciled(self):
        self.cloud.lose_insert = self.cloud.lose_upload = self.cloud.lose_publish = True
        self.seed()
        self.assertEqual(self.cloud.writes.count("INSERT"), 3)
        self.assertEqual(self.cloud.writes.count("PUT"), 5)
        self.assertEqual(self.cloud.writes.count("UPDATE"), 3)
        self.cleanup()

    def test_cleanup_retires_a_late_committed_reservation(self):
        self.cloud.defer_insert = 2
        with self.assertRaisesRegex(capacity.CapacityError, "reservation could not be confirmed"):
            self.seed()
        self.assertTrue(self.ledger()["fixtures"][0]["reservePending"])
        self.cleanup()
        self.assertEqual(self.cloud.capacity_rows(), [])
        self.assertFalse(self.ledger()["fixtures"][0]["reservePending"])
        self.assertEqual(self.ledger()["phase"], "retired")
        self.wait.assert_called_once()

    def test_missing_unconfirmed_reservation_keeps_recovery_ledger(self):
        self.cloud.defer_insert = -1
        with self.assertRaisesRegex(capacity.CapacityError, "reservation could not be confirmed"):
            self.seed()
        with self.assertRaisesRegex(capacity.CapacityError, "reservation remains unconfirmed"):
            self.cleanup()
        self.assertEqual(self.cloud.capacity_rows(), [])
        self.assertEqual(self.ledger()["phase"], "cleanup")
        self.assertTrue(self.ledger()["fixtures"][0]["reservePending"])
        self.assertEqual(self.wait.call_count, len(capacity.UNCERTAIN_READBACK_DELAYS))

    def test_cleanup_deletes_a_late_committed_upload(self):
        self.cloud.defer_put = 2
        with self.assertRaisesRegex(capacity.CapacityError, "upload could not be verified"):
            self.seed()
        self.assertEqual(self.ledger()["fixtures"][0]["putPending"], [0])
        self.cleanup()
        self.assertEqual(self.cloud.capacity_rows(), [])
        self.assertEqual(self.cloud.objects, {})
        self.assertEqual(self.ledger()["fixtures"][0]["putPending"], [])
        self.assertEqual(self.ledger()["phase"], "retired")
        self.wait.assert_called_once()

    def test_missing_unconfirmed_upload_keeps_recovery_ledger(self):
        self.cloud.defer_put = -1
        with self.assertRaisesRegex(capacity.CapacityError, "upload could not be verified"):
            self.seed()
        with self.assertRaisesRegex(capacity.CapacityError, "upload remains unconfirmed"):
            self.cleanup()
        self.assertEqual(self.cloud.capacity_rows(), [])
        self.assertEqual(self.ledger()["phase"], "cleanup")
        self.assertEqual(self.ledger()["fixtures"][0]["putPending"], [0])
        self.assertEqual(self.wait.call_count, len(capacity.UNCERTAIN_READBACK_DELAYS))

    def test_stale_main_blocks_publication_but_not_retirement(self):
        self.guard.side_effect = [None, capacity.CapacityError("Revision changed.")]
        with self.assertRaisesRegex(capacity.CapacityError, "Revision changed"):
            self.seed()
        self.assertEqual([row["generation"] for row in self.cloud.capacity_rows()], [0, 0, 0])
        self.assertNotIn("UPDATE", self.cloud.writes)
        self.cleanup()
        self.assertEqual(self.cloud.objects, {})

    def test_foreign_object_collision_is_not_overwritten_or_deleted(self):
        fixture = self.fixtures[0]
        key = f"subscriptions/2/{fixture['snapshotId']}/0.ndjson"
        self.cloud.objects[key] = b"other object"
        with self.assertRaisesRegex(capacity.CapacityError, "occupied"):
            self.seed()
        self.cleanup()
        self.assertEqual(self.cloud.objects, {key: b"other object"})
        self.assertEqual(self.cloud.capacity_rows(), [])

    def test_cleanup_preserves_changed_object_and_retains_ledger(self):
        self.seed()
        key = next(iter(self.cloud.objects))
        original = self.cloud.objects[key]
        self.cloud.objects[key] = b"changed externally"
        with self.assertRaisesRegex(capacity.CapacityError, "changed and was left"):
            self.cleanup()
        self.assertEqual(self.cloud.capacity_rows(), [])
        self.assertEqual(self.cloud.objects[key], b"changed externally")
        self.assertEqual(self.ledger()["phase"], "cleanup")
        self.cloud.objects[key] = original
        self.cleanup()
        self.assertEqual(self.cloud.objects, {})

    def test_wrong_scope_or_bad_bytes_stop_before_any_writes(self):
        self.cloud.public_bucket = True
        with self.assertRaisesRegex(capacity.CapacityError, "privacy"):
            self.seed()
        self.cloud.public_bucket = False
        file = self.directory / self.fixtures[0]["chunks"][0]["file"]
        write_private(file, b"bad fixture")
        with self.assertRaisesRegex(capacity.CapacityError, "digest mismatch"):
            self.seed()
        self.assertEqual(self.cloud.writes, [])
        self.assertIsNone(self.ledger())

    def test_cleanup_rejects_reassigned_row_before_object_deletion(self):
        self.seed()
        first = self.cloud.capacity_rows()[0]["id"]
        self.cloud.db.execute("UPDATE subscriptions SET name='Reassigned' WHERE id=?", (first,))
        self.cloud.db.commit()
        previous = dict(self.cloud.objects)
        with self.assertRaisesRegex(capacity.CapacityError, "ownership"):
            self.cleanup()
        self.assertEqual(self.cloud.objects, previous)
        self.assertEqual(self.ledger()["phase"], "cleanup")

    def test_worker_preflight_fingerprint_is_private_and_must_match_afterward(self):
        deploy_api = Mock()
        active = {"revision": REVISION, "deploymentId": "synthetic-deployment", "versionId": "synthetic-version"}
        with patch.object(capacity, "verify_worker_target", return_value=active) as verify, \
             patch.object(capacity, "_verify_health") as health:
            capacity.verify_worker_fingerprint(self.directory, self.resources, deploy_api, REVISION, before=True)
            capacity.verify_worker_fingerprint(self.directory, self.resources, deploy_api, REVISION, before=False)
            path = self.directory / capacity.FINGERPRINT_FILE
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(active["deploymentId"], path.read_text(encoding="ascii"))
            active["versionId"] = "other-synthetic-version"
            with self.assertRaisesRegex(capacity.CapacityError, "differs from the preflight fingerprint"):
                capacity.verify_worker_fingerprint(self.directory, self.resources, deploy_api, REVISION, before=False)
            verify.assert_called_with(deploy_api, self.resources.api, TARGET)
            health.assert_called_with(REVISION)


if __name__ == "__main__":
    unittest.main()

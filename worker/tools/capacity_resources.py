"""Seed and retire the hosted capacity fixtures in the owned isolation resources."""

import argparse
from contextlib import contextmanager
import fcntl
from hashlib import sha256
from http.client import HTTPException
import json
import os
from pathlib import Path
import re
import stat
import tempfile
from time import sleep
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from capacity_fixtures import (
    CAPACITY_STATUS as STATUS, CHUNK_BYTES, FIXTURE_PROFILES, NODE_COUNT, SHARE_BYTES, SHARE_PREFIX,
    SMOKE_CHUNK_COUNT, SMOKE_OBJECT_LIMIT, SMOKE_PROFILES, SNAPSHOT_BYTES, smoke_fixture,
)
from cloudflare_isolation import (
    API_ORIGIN, DIGEST, HEX_ID, NAMESPACE, REVISION, TIMESTAMP, UUID, WORKER_NAME,
    CloudflareClient, CloudflareError, _NoRedirect, _verify_health, verify_worker_target,
)
from prepare_isolation_artifact import ArtifactError, require_current_main


OWNER = "9223372036854775807"  # Outside Telegram's ID range.
LEDGER_FILE = "capacity-cleanup.json"
FINGERPRINT_FILE = "capacity-worker-fingerprint.json"
MAX_JSON = 256 * 1024
MAX_MANIFEST = 64 * 1024
MAX_CHUNKS = 256
TOKEN = re.compile(r"subsbot-synthetic-capacity-[A-Za-z0-9_-]{32}")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
UNCERTAIN_READBACK_DELAYS = (1, 2, 4)
SYNTHETIC_LINE = re.compile(rb'\{"share":"(' + re.escape(SHARE_PREFIX)
                            + rb'capacity-[0-9]{6}-x*)","pad":"p*"\}\n')
TARGET_KEYS = {"accountId", "workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "r2CreatedOn", "namespace"}


class CapacityError(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise CapacityError(message)


def matches(pattern, value):
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def digest(body):
    return sha256(body).hexdigest()


def json_body(body):
    try:
        result = json.loads(body)
    except (ValueError, RecursionError):
        raise CapacityError("Invalid private capacity metadata.") from None
    require(isinstance(result, dict), "Invalid private capacity metadata.")
    return result


def read_private(path, limit):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            "Capacity files must be owner-only regular files.")
    with path.open("rb") as stream:
        body = stream.read(limit + 1)
    require(0 < len(body) <= limit, "Capacity fixture file size is invalid.")
    return body


def verify_private_directory(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
            "Capacity fixture directories must be owner-only.")


def read_object_file(directory, label, index, objects):
    descriptor = objects[index]
    filename = "manifest.json" if index == len(objects) - 1 else f"{index}.ndjson"
    folder = directory / label
    verify_private_directory(folder)
    body = read_private(folder / filename, descriptor["bytes"])
    require(len(body) == descriptor["bytes"] and digest(body) == descriptor["sha256"],
            "Capacity fixture object digest mismatch.")
    return body


def check_raw_fixture(directory, fixture, node_count, node_bytes, objects):
    label = fixture["label"]
    total_shares = total_records = 0
    for index, chunk in enumerate(fixture["chunks"]):
        body = read_object_file(directory, label, index, objects)
        position = record_count = 0
        while position < len(body):
            record = SYNTHETIC_LINE.match(body, position)
            require(record is not None, "Capacity node data is not the expected synthetic format.")
            total_shares += len(record[1])
            record_count += 1
            position = record.end()
        require(record_count == chunk["count"], "Capacity chunk node count does not match.")
        total_records += record_count
    total_shares += max(0, total_records - 1)
    require(fixture.get("shareBytes") == total_shares, "Capacity share size does not match.")
    if label == "at-limits":
        require((node_count, node_bytes, total_shares) == (NODE_COUNT, SNAPSHOT_BYTES, SHARE_BYTES)
                and fixture.get("exportBytes") == 4 * ((SHARE_BYTES + 2) // 3)
                and matches(DIGEST, fixture.get("exportSha256")), "Capacity boundary fixture is invalid.")
    else:
        require(fixture.get("exportBytes") == 0 and fixture.get("exportSha256") is None
                and ((label == "snapshot-over" and node_bytes == SNAPSHOT_BYTES + 1)
                     or (label == "share-over" and node_bytes <= SNAPSHOT_BYTES and total_shares == SHARE_BYTES + 1)),
                "Capacity over-limit fixture is invalid.")


def check_smoke_fixture(directory, profile, fixture, manifest, objects):
    label = fixture["label"]
    bodies, share_bytes, export = smoke_fixture(profile, label)
    descriptors = [{"bytes": len(body), "sha256": digest(body), "count": 1} for body in bodies]
    expected_manifest = json.dumps({"version": 1, "chunks": descriptors}, separators=(",", ":")).encode("ascii")
    require(manifest == expected_manifest
            and all(row["bytes"] <= SMOKE_OBJECT_LIMIT for row in objects)
            and fixture.get("shareBytes") == share_bytes and fixture.get("exportBytes") == len(export)
            and fixture.get("exportSha256") == (digest(export) if export else None),
            "Export smoke fixture differs from the fixed synthetic plan.")
    for index, body in enumerate(bodies):
        require(read_object_file(directory, label, index, objects) == body,
                "Export smoke fixture records differ from the fixed synthetic plan.")


def read_fixtures(directory, revision, *, profile="capacity"):
    require(profile in FIXTURE_PROFILES, "Unknown synthetic fixture profile.")
    statuses = FIXTURE_PROFILES[profile]
    metadata = json_body(read_private(directory / "capacity.json", MAX_JSON))
    fixtures = metadata.get("fixtures")
    require(metadata.get("version") == 1 and metadata.get("revision") == revision
            and isinstance(fixtures, list) and len(fixtures) == len(statuses),
            "Capacity manifest does not match the requested revision.")
    require(all(isinstance(fixture, dict) for fixture in fixtures)
            and [fixture.get("label") for fixture in fixtures] == list(statuses),
            "Unexpected capacity fixture inventory.")
    entries = []
    for fixture in fixtures:
        label = fixture["label"]
        token, snapshot = fixture.get("token"), fixture.get("snapshotId")
        require(matches(TOKEN, token) and matches(UUID, snapshot)
                and fixture.get("status") == statuses[label] and fixture.get("manifestFile") == f"{label}/manifest.json",
                "Invalid capacity fixture identity.")
        chunk_files = fixture.get("chunks")
        require(isinstance(chunk_files, list) and len(chunk_files) <= MAX_CHUNKS,
                "Invalid capacity fixture object inventory.")
        verify_private_directory(directory / label)
        manifest = read_private(directory / label / "manifest.json", MAX_MANIFEST)
        require(digest(manifest) == fixture.get("manifestSha256"), "Capacity snapshot manifest digest mismatch.")
        snapshot_manifest = json_body(manifest)
        descriptors = snapshot_manifest.get("chunks")
        require(snapshot_manifest.get("version") == 1 and isinstance(descriptors, list)
                and 0 < len(descriptors) <= MAX_CHUNKS
                and all(isinstance(row, dict) and set(row) == {"bytes", "sha256", "count"}
                        and integer(row["bytes"], 1, CHUNK_BYTES) and integer(row["count"], 1, NODE_COUNT)
                        and matches(DIGEST, row["sha256"]) for row in descriptors),
                "Invalid capacity snapshot manifest.")
        node_count = sum(row["count"] for row in descriptors)
        node_bytes = sum(row["bytes"] for row in descriptors)
        require(integer(node_count, 1, NODE_COUNT) and fixture.get("nodeCount") == node_count
                and fixture.get("nodeBytes") == node_bytes, "Capacity snapshot counts do not match.")
        expected_chunks = ([] if label == "snapshot-over" else
                           [{"file": f"{label}/{index}.ndjson", **row} for index, row in enumerate(descriptors)])
        require(chunk_files == expected_chunks, "Capacity chunk files do not match their manifest.")
        objects = [{key: row[key] for key in ("bytes", "sha256")} for row in chunk_files]
        objects.append({"bytes": len(manifest), "sha256": digest(manifest)})
        if profile in SMOKE_PROFILES:
            check_smoke_fixture(directory, profile, fixture, manifest, objects)
        else:
            check_raw_fixture(directory, fixture, node_count, node_bytes, objects)
        entries.append({"label": label, "snapshotId": snapshot, "nodeCount": node_count,
                        "tokenSha256": digest(token.encode("ascii")), "objects": objects,
                        "rowId": None, "armed": [], "reservePending": False, "putPending": []})
    require(len({entry["snapshotId"] for entry in entries}) == len(statuses)
            and len({entry["tokenSha256"] for entry in entries}) == len(statuses),
            "Duplicate capacity fixture identity.")
    return fixtures, entries


@contextmanager
def locked_directory(directory):
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0,
                "Capacity directory must be owner-only.")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def save_private_json(path, value):
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".capacity-")
    try:
        with os.fdopen(fd, "w", encoding="ascii") as output:
            json.dump(value, output, separators=(",", ":"))
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save_ledger(directory, ledger):
    save_private_json(directory / LEDGER_FILE, ledger)


def load_ledger(directory, scope_hash, *, profile="capacity"):
    require(profile in FIXTURE_PROFILES, "Unknown synthetic fixture profile.")
    statuses = FIXTURE_PROFILES[profile]
    path = directory / LEDGER_FILE
    if not path.exists() and not path.is_symlink():
        return None
    ledger = json_body(read_private(path, MAX_JSON))
    entries = ledger.get("fixtures")
    require(set(ledger) == {"version", "scopeSha256", "revision", "runId", "phase", "fixtures"}
            and ledger["version"] == 1 and ledger["scopeSha256"] == scope_hash
            and matches(REVISION, ledger["revision"]) and matches(RUN_ID, ledger["runId"])
            and ledger["phase"] in ("seed", "cleanup", "retired") and isinstance(entries, list)
            and len(entries) == len(statuses) and all(isinstance(entry, dict) for entry in entries)
            and [entry.get("label") for entry in entries] == list(statuses), "Invalid capacity cleanup ledger.")
    for entry in entries:
        require(set(entry) == {"label", "snapshotId", "nodeCount", "tokenSha256", "objects", "rowId", "armed",
                               "reservePending", "putPending"}
                and matches(UUID, entry["snapshotId"]) and matches(DIGEST, entry["tokenSha256"])
                and integer(entry["nodeCount"], 1, NODE_COUNT)
                and (entry["rowId"] is None or integer(entry["rowId"], 1, 9007199254740991))
                and isinstance(entry["objects"], list) and 1 <= len(entry["objects"]) <= MAX_CHUNKS + 1
                and isinstance(entry["armed"], list)
                and all(integer(index, 0, len(entry["objects"]) - 1) for index in entry["armed"])
                and entry["armed"] == list(range(len(entry["armed"])))
                and (not entry["armed"] or entry["rowId"] is not None)
                and type(entry["reservePending"]) is bool and (not entry["reservePending"] or entry["rowId"] is None)
                and isinstance(entry["putPending"], list)
                and all(integer(index, 0, len(entry["armed"]) - 1) for index in entry["putPending"])
                and len(set(entry["putPending"])) == len(entry["putPending"])
                and (ledger["phase"] != "retired" or not (entry["reservePending"] or entry["putPending"]))
                and (entry["label"] != "snapshot-over" or len(entry["objects"]) == 1)
                and (profile not in SMOKE_PROFILES or (entry["nodeCount"] == SMOKE_CHUNK_COUNT
                                                     and len(entry["objects"]) == SMOKE_CHUNK_COUNT + 1)),
                "Invalid capacity cleanup ledger entry.")
        for index, obj in enumerate(entry["objects"]):
            limit = (SMOKE_OBJECT_LIMIT if profile in SMOKE_PROFILES else
                     MAX_MANIFEST if index == len(entry["objects"]) - 1 else CHUNK_BYTES)
            require(isinstance(obj, dict) and set(obj) == {"bytes", "sha256"}
                    and integer(obj["bytes"], 1, limit) and matches(DIGEST, obj["sha256"]),
                    "Invalid capacity cleanup object record.")
    assigned = [entry["rowId"] for entry in entries if entry["rowId"] is not None]
    require(len(set(assigned)) == len(assigned)
            and len({entry["snapshotId"] for entry in entries}) == len(statuses)
            and len({entry["tokenSha256"] for entry in entries}) == len(statuses),
            "Duplicate capacity cleanup ledger identity.")
    return ledger


class R2Objects:
    def __init__(self, account_id, token):
        self.prefix = f"{API_ORIGIN}/accounts/{account_id}/r2/buckets/{WORKER_NAME}/objects/"
        self.token = token
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    def request(self, method, key, body=None):
        require(method in ("GET", "PUT", "DELETE") and (method == "PUT" or body is None)
                and isinstance(key, str)
                and re.fullmatch(r"subscriptions/[1-9][0-9]{0,15}/" + UUID.pattern
                                 + r"/(?:[0-9]{1,3}\.ndjson|manifest\.json)", key),
                "Invalid scoped capacity object request.")
        headers = {"Authorization": "Bearer " + self.token, "cf-r2-jurisdiction": "default",
                   "Accept-Encoding": "identity"}
        if method == "PUT":
            require(isinstance(body, bytes) and 0 < len(body) <= CHUNK_BYTES, "Invalid capacity upload body.")
            headers["Content-Type"] = "application/octet-stream"
        request = Request(self.prefix + key, headers=headers, data=body, method=method)
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(CHUNK_BYTES + 1)
        except HTTPError as error:
            error.close()
            if error.code == 404 and method in ("GET", "DELETE"):
                return None
            raise CapacityError(f"Scoped R2 object request failed (HTTP {error.code}).") from None
        except (OSError, ValueError, HTTPException):
            raise CapacityError("Scoped R2 object request could not be completed.") from None
        require(len(raw) <= CHUNK_BYTES, "Unexpected scoped R2 object size.")
        if method == "GET":
            return raw
        if raw:
            response = json_body(raw)
            result = response.get("result") or {}
            require(response.get("success") is True and isinstance(result, dict) and result.get("key", key) == key,
                    "Scoped R2 object write response could not be verified.")
        return None


class Resources:
    def __init__(self, target, api, objects):
        require(isinstance(target, dict) and set(target) == TARGET_KEYS
                and target.get("namespace") == NAMESPACE and matches(HEX_ID, target.get("accountId"))
                and matches(HEX_ID, target.get("workerId")) and matches(UUID, target.get("d1Id"))
                and all(matches(TIMESTAMP, target.get(key)) for key in ("workerCreatedOn", "d1CreatedAt", "r2CreatedOn")),
                "Invalid owned capacity resource configuration.")
        self.target = target
        self.scope_hash = digest(json.dumps(target, sort_keys=True, separators=(",", ":")).encode("ascii"))
        self.api = api
        self.objects = objects
        root = f"/accounts/{target['accountId']}"
        self.database = f"{root}/d1/database/{target['d1Id']}"
        self.bucket = f"{root}/r2/buckets/{WORKER_NAME}"

    def verify(self):
        db = self.api("GET", self.database)
        r2 = self.api("GET", self.bucket)
        managed = self.api("GET", self.bucket + "/domains/managed")
        custom = self.api("GET", self.bucket + "/domains/custom")
        require(isinstance(db, dict) and (db.get("uuid"), db.get("name"), db.get("created_at"))
                == (self.target["d1Id"], WORKER_NAME, self.target["d1CreatedAt"]),
                "Capacity D1 ownership could not be verified.")
        require(isinstance(r2, dict) and (r2.get("name"), r2.get("creation_date"), r2.get("jurisdiction"))
                == (WORKER_NAME, self.target["r2CreatedOn"], "default")
                and isinstance(managed, dict) and managed.get("enabled") is False and custom in ([], {"domains": []}),
                "Capacity R2 ownership or privacy could not be verified.")

    def query(self, sql, params):
        result = self.api("POST", self.database + "/query", {"sql": sql, "params": [str(value) for value in params]})
        require(isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict)
                and result[0].get("success") is True and isinstance(result[0].get("results"), list),
                "Capacity D1 query could not be verified.")
        return result[0]["results"]

    def row(self, ledger, entry):
        name, source = marker(ledger, entry)
        by_id = entry["rowId"] is not None
        rows = self.query(
            "SELECT id, owner_id, name, source_url, token, generation, snapshot_id, manifest_sha256, node_count "
            "FROM subscriptions WHERE (owner_id=? AND name=? AND source_url=?)"
            + (" OR id=?" if by_id else "") + " LIMIT 2",
            (OWNER, name, source, entry["rowId"]) if by_id else (OWNER, name, source),
        )
        if not rows:
            return None
        require(len(rows) == 1 and isinstance(rows[0], dict), "Capacity subscription ownership is ambiguous.")
        row = rows[0]
        token = row.get("token")
        require((row.get("owner_id"), row.get("name"), row.get("source_url")) == (OWNER, name, source)
                and integer(row.get("id"), 1, 9007199254740991)
                and (not by_id or row["id"] == entry["rowId"])
                and matches(TOKEN, token) and digest(token.encode("ascii")) == entry["tokenSha256"],
                "Capacity subscription ownership could not be verified.")
        state = (row.get("generation"), row.get("snapshot_id"), row.get("manifest_sha256"), row.get("node_count"))
        require(type(state[0]) is int and type(state[3]) is int
                and state in ((0, None, None, 0), (1, entry["snapshotId"], entry["objects"][-1]["sha256"], entry["nodeCount"])),
                "Capacity subscription state changed outside this run.")
        return row

    def reserve(self, ledger, entry, token, before_insert):
        row = self.row(ledger, entry)
        if entry["reservePending"]:
            row = recheck_absent(row, lambda: self.row(ledger, entry))
            require(row is not None, "A prior capacity reservation remains unconfirmed.")
        if row is not None:
            return row
        require(entry["rowId"] is None, "Previously reserved capacity subscription disappeared.")
        name, source = marker(ledger, entry)
        before_insert()
        try:
            self.query(
                "INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at) "
                "SELECT ?,?,?,?,unixepoch(),unixepoch() "
                "WHERE NOT EXISTS (SELECT 1 FROM subscriptions WHERE owner_id=? AND name=? AND source_url=?) "
                "ON CONFLICT(token) DO NOTHING",
                (OWNER, name, source, token, OWNER, name, source),
            )
        except (CloudflareError, CapacityError):
            pass  # Read back an uncertain insert by the journaled marker.
        row = self.row(ledger, entry)
        require(row is not None and row["generation"] == 0, "Capacity subscription reservation could not be confirmed.")
        return row

    def publish(self, ledger, entry):
        row = self.row(ledger, entry)
        require(row is not None, "Reserved capacity subscription is missing.")
        if row["generation"] == 0:
            name, source = marker(ledger, entry)
            try:
                self.query(
                    "UPDATE subscriptions SET generation=1,snapshot_id=?,manifest_sha256=?,node_count=?,updated_at=unixepoch() "
                    "WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=? AND generation=0 "
                    "AND snapshot_id IS NULL AND manifest_sha256 IS NULL AND node_count=0",
                    (entry["snapshotId"], entry["objects"][-1]["sha256"], entry["nodeCount"],
                     row["id"], OWNER, name, source, row["token"]),
                )
            except (CloudflareError, CapacityError):
                pass
        row = self.row(ledger, entry)
        require(row is not None and row["generation"] == 1, "Capacity snapshot publication could not be confirmed.")

    def retire(self, ledger, entry, row):
        if row is None:
            return
        name, source = marker(ledger, entry)
        try:
            self.query(
                "DELETE FROM subscriptions WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=? "
                "AND generation=? AND ((generation=0 AND snapshot_id IS NULL AND manifest_sha256 IS NULL AND node_count=0) "
                "OR (generation=1 AND snapshot_id=? AND manifest_sha256=? AND node_count=?))",
                (row["id"], OWNER, name, source, row["token"], row["generation"],
                 entry["snapshotId"], entry["objects"][-1]["sha256"], entry["nodeCount"]),
            )
        except (CloudflareError, CapacityError):
            pass
        require(self.row(ledger, entry) is None, "Capacity subscription retirement could not be confirmed.")


def marker(ledger, entry):
    label = entry["label"]
    return (f"Capacity fixture {label}",
            f"https://fixture.invalid/subs-bot-capacity/{ledger['runId']}/{ledger['revision']}/{label}/{entry['snapshotId']}")


def object_key(entry, index):
    filename = "manifest.json" if index == len(entry["objects"]) - 1 else f"{index}.ndjson"
    return f"subscriptions/{entry['rowId']}/{entry['snapshotId']}/{filename}"


def matches_object(body, entry, index):
    descriptor = entry["objects"][index]
    return isinstance(body, bytes) and len(body) == descriptor["bytes"] and digest(body) == descriptor["sha256"]


def recheck_absent(value, read):
    for delay in UNCERTAIN_READBACK_DELAYS:
        if value is not None:
            break
        sleep(delay)
        value = read()
    return value


def confirm_row(directory, ledger, entry, row):
    if entry["rowId"] is None:
        entry["rowId"] = row["id"]
        entry["reservePending"] = False
        save_ledger(directory, ledger)


def confirm_object(directory, ledger, entry, index):
    if index in entry["putPending"]:
        entry["putPending"].remove(index)
        save_ledger(directory, ledger)


def seed(directory, resources, revision, run_id, guard, *, profile="capacity"):
    require(matches(REVISION, revision) and matches(RUN_ID, run_id), "A full revision and hosted run ID are required.")
    fixtures, entries = read_fixtures(directory, revision, profile=profile)
    resources.verify()
    guard(revision)
    ledger = load_ledger(directory, resources.scope_hash, profile=profile)
    if ledger is None:
        ledger = {"version": 1, "scopeSha256": resources.scope_hash, "revision": revision,
                  "runId": run_id, "phase": "seed", "fixtures": entries}
        save_ledger(directory, ledger)
    else:
        require(ledger["phase"] == "seed" and (ledger["revision"], ledger["runId"]) == (revision, run_id)
                and [{**entry, "rowId": None, "armed": [], "reservePending": False, "putPending": []}
                     for entry in ledger["fixtures"]] == entries,
                "Existing capacity cleanup ledger belongs to another fixture attempt.")
    for fixture, entry in zip(fixtures, ledger["fixtures"]):
        def before_insert():
            entry["reservePending"] = True
            save_ledger(directory, ledger)
        row = resources.reserve(ledger, entry, fixture["token"], before_insert)
        confirm_row(directory, ledger, entry, row)
        for index in range(len(entry["objects"])):
            key = object_key(entry, index)
            remote = resources.objects.request("GET", key)
            if index in entry["putPending"]:
                remote = recheck_absent(remote, lambda: resources.objects.request("GET", key))
                require(remote is not None, "A prior capacity object upload remains unconfirmed.")
            if remote is not None:
                require(index in entry["armed"] and matches_object(remote, entry, index),
                        "Capacity object key is occupied by unverified content.")
                confirm_object(directory, ledger, entry, index)
                continue
            require(row["generation"] == 0, "A published capacity object is missing.")
            body = read_object_file(directory, entry["label"], index, entry["objects"])
            if index not in entry["armed"]:
                entry["armed"].append(index)
            entry["putPending"].append(index)
            save_ledger(directory, ledger)
            try:
                resources.objects.request("PUT", key, body)
            except CapacityError:
                pass
            require(matches_object(resources.objects.request("GET", key), entry, index),
                    "Capacity object upload could not be verified.")
            confirm_object(directory, ledger, entry, index)
    resources.verify()
    guard(revision)
    for entry in ledger["fixtures"]:
        resources.publish(ledger, entry)


def cleanup(directory, resources, *, profile="capacity"):
    ledger = load_ledger(directory, resources.scope_hash, profile=profile)
    if ledger is None:
        return
    resources.verify()
    if ledger["phase"] == "retired":
        return
    ledger["phase"] = "cleanup"
    save_ledger(directory, ledger)
    for entry in ledger["fixtures"]:
        row = resources.row(ledger, entry)
        if entry["reservePending"]:
            row = recheck_absent(row, lambda: resources.row(ledger, entry))
            require(row is not None, "Capacity reservation remains unconfirmed. Cleanup ledger retained.")
            confirm_row(directory, ledger, entry, row)
        resources.retire(ledger, entry, row)
    for entry in ledger["fixtures"]:
        for index in entry["armed"]:
            key = object_key(entry, index)
            remote = resources.objects.request("GET", key)
            if index in entry["putPending"]:
                remote = recheck_absent(remote, lambda: resources.objects.request("GET", key))
                require(remote is not None, "Capacity object upload remains unconfirmed. Cleanup ledger retained.")
            if remote is None:
                continue
            require(matches_object(remote, entry, index), "Capacity object changed and was left in R2.")
            confirm_object(directory, ledger, entry, index)
            try:
                resources.objects.request("DELETE", key)
            except CapacityError:
                pass
            require(resources.objects.request("GET", key) is None, "Capacity R2 deletion could not be verified.")
    ledger["phase"] = "retired"
    save_ledger(directory, ledger)


def verify_release(revision):
    require_current_main(revision)
    _verify_health(revision)
    require_current_main(revision)


def verify_worker_fingerprint(directory, resources, worker_api, revision, *, before):
    require(matches(REVISION, revision), "A full hosted Worker revision is required.")
    active = verify_worker_target(worker_api, resources.api, resources.target)
    require(active["revision"] == revision, "The isolated Worker does not serve the requested revision.")
    _verify_health(revision)
    fingerprint = {"version": 1, "revision": revision, "scopeSha256": resources.scope_hash,
                   "deploymentSha256": digest(json.dumps(active, sort_keys=True, separators=(",", ":")).encode("ascii"))}
    path = directory / FINGERPRINT_FILE
    if not path.exists() and not path.is_symlink():
        require(before, "The isolated Worker preflight fingerprint is missing.")
        save_private_json(path, fingerprint)
    else:
        require(json_body(read_private(path, MAX_JSON)) == fingerprint,
                "The isolated Worker deployment differs from the preflight fingerprint.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seed", "cleanup", "verify-worker-before", "verify-worker-after"))
    parser.add_argument("directory", type=Path)
    parser.add_argument("--profile", choices=FIXTURE_PROFILES, default="capacity")
    args = parser.parse_args()
    try:
        target = json_body(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "null"))
        token = os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN")
        resources = Resources(target, CloudflareClient(token), R2Objects(target.get("accountId"), token))
        with locked_directory(args.directory):
            if args.action == "seed":
                seed(args.directory, resources, os.environ.get("GITHUB_SHA"), os.environ.get("GITHUB_RUN_ID"),
                     verify_release, profile=args.profile)
                if args.profile in SMOKE_PROFILES:
                    print(f"Published {len(SMOKE_PROFILES[args.profile])} verified isolated export smoke fixtures.")
                else:
                    print("Published three verified isolated capacity fixtures.")
            elif args.action == "cleanup":
                cleanup(args.directory, resources, profile=args.profile)
                print("Isolated capacity fixture cleanup verified.")
            else:
                deploy_token = os.environ.get("SUBS_BOT_CF_DEPLOY_TOKEN")
                require(deploy_token != token, "Separate scoped Worker and data credentials are required.")
                verify_worker_fingerprint(args.directory, resources, CloudflareClient(deploy_token),
                                          os.environ.get("GITHUB_SHA"), before=args.action == "verify-worker-before")
                print("Exact isolated Worker revision, logging settings and scope verified.")
    except (CapacityError, CloudflareError, ArtifactError) as error:
        parser.exit(1, f"{error}\n")
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        parser.exit(1, "Could not verify the private capacity fixture state.\n")


if __name__ == "__main__":
    main()

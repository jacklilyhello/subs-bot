"""Protected acceptance checkpoints; real Telegram commands are sent only in IAB.

The two fixed synthetic subscriptions are the only mutable application data here.
Inbox/outbox, aggregate slots, and revoked links remain as replay/order tombstones.
No Bot API method is called. Secrets and capabilities never enter checkpoints.
"""

from base64 import b64encode, urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
import hmac
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sys
from time import monotonic
from urllib.parse import urlencode
from urllib.request import Request
from urllib.error import HTTPError
from http.client import HTTPException
from uuid import UUID as UUIDValue
from zipfile import ZipFile

from capacity_probe import ProbeError, _check_headers, _request, _small_body
from capacity_resources import CapacityError, R2Objects, Resources, integer, matches, save_private_json
from cloudflare_isolation import (
    CloudflareClient, CloudflareError, DATE, DIGEST, REVISION, UUID, _Isolation, _verify_health,
)
from d1_migrations import _assert_sql
from prepare_isolation_artifact import (
    ArtifactError, MAIN_REF, REPOSITORY, _download, _get_json, _parse_object, _zip_members,
    require_current_main, select_main_artifact,
)
from release_isolation import telegram_release_config
from telegram_view_fixtures import FixtureError, query, statement


WORKFLOW = "worker-isolation-telegram-aggregate-smoke.yml"
ARTIFACT_PREFIX = "subs-bot-telegram-aggregate"
CHECKPOINT = "telegram-aggregate-checkpoint.json"
MIGRATION = "0014_telegram_aggregate_issuance.sql"
ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev"
SOURCE = "https://subs-bot-aggregate-fixtures.invalid/"
MARKER = "aggregate:v1"
COHORT = re.compile(r"[a-f0-9]{16}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
NONCE = re.compile(r"[A-Za-z0-9_-]{22}")
MAX_ID = 9_007_199_254_740_991
MAX_CHECKPOINT = 16384
ROLES = {"admin": "adminId", "member": "memberId"}
OBJECTS = ("0.ndjson", "manifest.json")
SUBSCRIPTION_FIELDS = ("id,owner_id,name,source_url,token,expire_at,traffic_used,traffic_total,last_error,"
                       "created_at,updated_at,generation,snapshot_id,manifest_sha256,node_count")
PHASES = {"prepare": "prepared", "capture-initial": "initial", "verify-member-revoked": "member-revoked",
          "verify-rotated": "rotated", "retire": "retired"}
PREVIOUS = {"capture-initial": {"prepared"}, "verify-member-revoked": {"initial"},
            "verify-rotated": {"member-revoked"}, "retire": {"rotated"}}
EXPECTED = {"prepared": {"admin": [], "member": []},
            "initial": {"admin": ["issued", "ready"], "member": ["issued", "ready"]},
            "member-revoked": {"admin": ["issued", "ready"], "member": ["issued", "ready", "revoked"]},
            "rotated": {"admin": ["issued", "ready"], "member": ["issued", "ready", "revoked", "issued"]},
            "retired": {"admin": ["issued", "ready", "revoked"],
                        "member": ["issued", "ready", "revoked", "issued", "revoked"]}}


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def digest(body):
    return sha256(body).hexdigest()


def key_bytes(encoded):
    require(isinstance(encoded, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", encoded), "Aggregate key encoding differs.")
    raw = urlsafe_b64decode(encoded + "=")
    require(len(raw) == 32 and urlsafe_b64encode(raw).decode().rstrip("=") == encoded, "Aggregate key encoding differs.")
    return raw


def derive_code(encoded, policy, role, nonce):
    require(role in ROLES and canonical_nonce(nonce), "Aggregate nonce identity differs.")
    message = canonical(["subs-bot/telegram-aggregate/all", 1, ORIGIN, policy["botId"], policy[ROLES[role]], nonce])
    return urlsafe_b64encode(hmac.new(key_bytes(encoded), message.encode("utf-8"), sha256).digest()[:16]).decode().rstrip("=")


def canonical_nonce(value):
    if not matches(NONCE, value):
        return False
    raw = urlsafe_b64decode(value + "==")
    return len(raw) == 16 and urlsafe_b64encode(raw).decode().rstrip("=") == value


class SnapshotObjects(R2Objects):
    """Reuse scoped reads/deletes, but never overwrite on fixture publication."""
    def request(self, method, key, body=None):
        if method != "PUT":
            return super().request(method, key, body)
        require(isinstance(key, str) and re.fullmatch(r"subscriptions/[1-9][0-9]{0,15}/" + UUID.pattern
                + r"/(?:0\.ndjson|manifest\.json)", key) and isinstance(body, bytes) and 0 < len(body) <= 4096,
                "Aggregate snapshot PUT scope differs.")
        request = Request(self.prefix + key, data=body, method="PUT", headers={"Authorization": "Bearer " + self.token,
            "cf-r2-jurisdiction": "default", "Content-Type": "application/octet-stream", "If-None-Match": "*"})
        try:
            with self.opener.open(request, timeout=25) as response:
                raw = response.read(4097)
        except HTTPError as error:
            error.close()
            raise CapacityError("Aggregate conditional R2 PUT was not confirmed.") from None
        except (OSError, ValueError, HTTPException):
            raise CapacityError("Aggregate conditional R2 PUT was not confirmed.") from None
        require(len(raw) <= 4096, "Aggregate R2 PUT response exceeds the limit.")
        if raw:
            require(_parse_object(raw, "Aggregate R2 PUT response differs.").get("success") is True,
                    "Aggregate R2 PUT response differs.")


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"action", "cohort", "source_run_id", "confirm_retire"},
            "Aggregate workflow inputs differ.")
    action, cohort = inputs.get("action"), inputs.get("cohort")
    source, confirm = inputs.get("source_run_id", ""), inputs.get("confirm_retire", "")
    require(action in PHASES and matches(COHORT, cohort) and (source == "" if action == "prepare" else matches(DECIMAL, source))
            and confirm == (f"retire {cohort}" if action == "retire" else ""), "Aggregate action or confirmation differs.")
    return action, cohort, source


def read_checkpoint(run_id, revision, token, *, workflow_file=WORKFLOW, artifact_prefix=ARTIFACT_PREFIX,
                    checkpoint_file=CHECKPOINT):
    path = f".github/workflows/{workflow_file}"
    workflow = _get_json(f"/actions/workflows/{workflow_file}", token)
    require(integer(workflow.get("id"), 1, MAX_ID) and workflow.get("path") == path, "Aggregate workflow identity differs.")
    _, artifact_id, archive_sha = select_main_artifact(run_id, revision, token, workflow_id=workflow["id"],
        workflow_path=path, artifact_prefix=artifact_prefix, workflow_label="Telegram export checkpoint")
    raw = _download(artifact_id, token)
    require(len(raw) <= MAX_CHECKPOINT and digest(raw) == archive_sha, "Aggregate checkpoint archive differs.")
    with ZipFile(BytesIO(raw)) as archive:
        members = _zip_members(archive)
        require(set(members) == {checkpoint_file} and members[checkpoint_file].file_size <= MAX_CHECKPOINT,
                "Aggregate checkpoint inventory differs.")
        return _parse_object(archive.read(members[checkpoint_file]), "Aggregate checkpoint JSON differs.")


def validate_release_pin(pin):
    require(isinstance(pin, dict) and set(pin) == {"revision", "versionId", "moduleSha256", "compatibilityDate"}
            and matches(REVISION, pin["revision"]) and matches(UUID, pin["versionId"])
            and matches(DIGEST, pin["moduleSha256"]) and matches(DATE, pin["compatibilityDate"]),
            "Aggregate active release pin differs.")


def verify_checkpoint_release(checkpoint, release_pin, *, retiring=False):
    original = checkpoint.get("releasePin")
    validate_release_pin(original)
    validate_release_pin(release_pin)
    require(original["revision"] == checkpoint["revision"], "Aggregate checkpoint release revision differs.")
    # Cleanup can run on a later reviewed main, but never continues the original acceptance proof.
    require(retiring or original == release_pin, "Aggregate checkpoint active release changed.")


def validate_checkpoint(value, action, cohort, revision, identity, release_pin):
    require(isinstance(value, dict) and set(value) == {"version", "phase", "cohort", "revision", "identity", "afterReceiptId",
            "releasePin", "snapshots", "startingRevisions", "authEpoch", "receipts", "capabilities"} and value["version"] == 1
            and type(value["version"]) is int and value["phase"] in PREVIOUS[action]
            and (value["cohort"], value["revision"], value["identity"]) == (cohort, revision, identity)
            and integer(value["afterReceiptId"], 0, MAX_ID), "Aggregate checkpoint scope or phase differs.")
    verify_checkpoint_release(value, release_pin, retiring=action == "retire")
    require(set(value["snapshots"]) == set(value["startingRevisions"]) == set(value["receipts"]) == set(ROLES)
            and matches(DIGEST, value["authEpoch"]), "Aggregate checkpoint owner inventory differs.")
    for role in ROLES:
        item = value["snapshots"][role]
        require(isinstance(item, dict) and set(item) == {"id", "snapshotId", "manifestSha256", "tokenSha256", "createdAt"}
                and integer(item["id"], 1, MAX_ID) and matches(UUID, item["snapshotId"])
                and matches(DIGEST, item["manifestSha256"]) and matches(DIGEST, item["tokenSha256"])
                and integer(item["createdAt"], 1, MAX_ID) and integer(value["startingRevisions"][role], 0, MAX_ID - 4)
                and isinstance(value["receipts"][role], list)
                and len(value["receipts"][role]) == len(EXPECTED[value["phase"]][role])
                and all(matches(DIGEST, row) for row in value["receipts"][role]), "Aggregate checkpoint pointer or receipt differs.")
    require(value["snapshots"]["member"]["id"] != value["snapshots"]["admin"]["id"], "Aggregate snapshot identities overlap.")
    keys = set() if value["phase"] == "prepared" else {"admin-initial", "member-initial"}
    if value["phase"] == "rotated":
        keys.add("member-rotated")
    require(isinstance(value["capabilities"], dict) and set(value["capabilities"]) == keys, "Aggregate capability inventory differs.")
    for item in value["capabilities"].values():
        # A nonce is noncapability recovery metadata. Only the separately protected HMAC key derives the bearer.
        require(isinstance(item, dict) and set(item) == {"sha256", "nonce", "keyVersion"} and matches(DIGEST, item["sha256"])
                and canonical_nonce(item["nonce"]) and type(item["keyVersion"]) is int and item["keyVersion"] == 1,
                "Aggregate capability recovery differs.")


class Cohort:
    def __init__(self, resources, policy, cohort, encoded, identity):
        self.resources, self.policy, self.cohort, self.encoded, self.identity = resources, policy, cohort, encoded, identity
        self.actors = {role: policy[field] for role, field in ROLES.items()}
        self.prefix = SOURCE + cohort + "/"
        self.name = "CFAG-" + cohort

    def read(self, sql, *params):
        return self.resources.query(sql, params)

    def batch(self, steps):
        return query(self.resources.api, self.resources.database, {"batch": steps}, len(steps))

    def seed_identity(self, role):
        # Different from the application's capability derivation and checkpoint encryption.
        material = hmac.new(key_bytes(self.encoded), canonical(["subs-bot/aggregate-fixture/v1", self.identity,
            self.cohort, role]).encode(), sha256).digest()
        raw_uuid = bytearray(hmac.new(material, b"snapshot", sha256).digest()[:16])
        raw_uuid[6], raw_uuid[8] = (raw_uuid[6] & 15) | 128, (raw_uuid[8] & 63) | 128
        return material.hex(), str(UUIDValue(bytes=bytes(raw_uuid)))

    def node(self, role):
        server, password = ("203.0.113.10", "fixture-admin") if role == "admin" else ("203.0.113.20", "fixture-member")
        name = f"CFAG-{self.cohort}-{role}"
        share = "ss://" + urlsafe_b64encode(f"aes-256-gcm:{password}".encode()).decode().rstrip("=") + f"@{server}:8388#{name}"
        return {"name": name, "type": "ss", "server": server, "port": 8388, "cipher": "aes-256-gcm",
                "password": password, "share": share}

    def bodies(self, role):
        chunk = (canonical(self.node(role)) + "\n").encode("ascii")
        manifest = canonical({"version": 1, "chunks": [{"bytes": len(chunk), "sha256": digest(chunk), "count": 1}]}).encode()
        return {"0.ndjson": chunk, "manifest.json": manifest}

    def row_conditions(self, row, role):
        token, snapshot_id = self.seed_identity(role)
        return (row.get("owner_id"), row.get("name"), row.get("source_url"), row.get("token"), row.get("expire_at"),
                row.get("traffic_used"), row.get("traffic_total"), row.get("last_error")) == (
                self.actors[role], self.name, self.prefix + role, token, None, None, None, None) and (
                (row.get("generation"), row.get("snapshot_id"), row.get("manifest_sha256"), row.get("node_count")) in (
                    (0, None, None, 0), (1, snapshot_id, digest(self.bodies(role)["manifest.json"]), 1)))

    def subscriptions(self, ids=()):
        result = self.read(f"""SELECT {SUBSCRIPTION_FIELDS},0 AS trashed FROM subscriptions
          WHERE substr(source_url,1,length(?))=? OR name=? OR id IN (SELECT value FROM json_each(?))
          UNION ALL SELECT {SUBSCRIPTION_FIELDS},1 AS trashed FROM subscription_trash
          WHERE substr(source_url,1,length(?))=? OR name=? OR id IN (SELECT value FROM json_each(?)) LIMIT 3""",
          self.prefix, self.prefix, self.name, canonical(list(ids)), self.prefix, self.prefix, self.name, canonical(list(ids)))
        mapped = {}
        for row in result:
            role = next((key for key, actor in self.actors.items() if actor == row.get("owner_id")), None)
            require(role is not None and role not in mapped and row.get("trashed") == 0 and self.row_conditions(row, role)
                    and integer(row.get("id"), 1, MAX_ID) and integer(row.get("created_at"), 1, MAX_ID)
                    and row.get("created_at") == row.get("updated_at"), "Aggregate seed identity or pointer differs.")
            mapped[role] = row
        return mapped

    def quiet(self, ids, assertion=False):
        known = canonical(list(ids))
        condition = """NOT EXISTS(SELECT 1 FROM telegram_temp_batch WHERE bot_id=? AND actor_id IN (?,?))
          AND NOT EXISTS(SELECT 1 FROM path_rules WHERE owner_id IN (?,?))
          AND NOT EXISTS(SELECT 1 FROM subscriptions WHERE owner_id IN (?,?) AND id NOT IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_trash WHERE name=? OR id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_jobs WHERE bot_id=? AND actor_id IN (?,?) AND state IN ('pending','leased'))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_reservations WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_stages WHERE subscription_id IN (SELECT value FROM json_each(?)))"""
        return statement(_assert_sql(condition) if assertion else "SELECT (" + condition + ") AS quiet",
            self.policy["botId"], *self.actors.values(), *self.actors.values(), *self.actors.values(), known,
            self.name, known, known, self.policy["botId"], *self.actors.values(), known, known)

    def require_quiet(self, ids):
        item = self.quiet(ids)
        require(self.read(item["sql"], *item["params"]) == [{"quiet": 1}], "Aggregate acceptance has unrelated or in-flight content.")

    def auth(self):
        result = self.read("""SELECT COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id=? AND user_id=?),1) AS allowed,
          COALESCE((SELECT message_date FROM telegram_auth WHERE bot_id=? AND user_id=?),0) AS date,
          COALESCE((SELECT message_id FROM telegram_auth WHERE bot_id=? AND user_id=?),0) AS message""",
          *((self.policy["botId"], self.actors["member"]) * 3))
        require(len(result) == 1 and result[0].get("allowed") == 1 and integer(result[0].get("date"), 0, MAX_ID)
                and integer(result[0].get("message"), 0, MAX_ID), "Aggregate member authorization differs.")
        return digest(canonical(result[0]).encode())

    def slots(self):
        rows = self.read("""SELECT actor_id,revision,code_sha256,nonce,key_version,message_date,message_id
          FROM telegram_aggregate_slots WHERE bot_id=? AND actor_id IN (?,?) LIMIT 3""", self.policy["botId"], *self.actors.values())
        result = {}
        for row in rows:
            role = next((key for key, actor in self.actors.items() if actor == row.get("actor_id")), None)
            require(role is not None and role not in result and integer(row.get("revision"), 1, MAX_ID - 4)
                    and integer(row.get("message_date"), 1, MAX_ID) and integer(row.get("message_id"), 1, MAX_ID)
                    and ((row.get("code_sha256"), row.get("nonce"), row.get("key_version")) == (None, None, None)
                      or (matches(DIGEST, row.get("code_sha256")) and canonical_nonce(row.get("nonce")) and row.get("key_version") == 1)),
                    "Aggregate managed slot differs.")
            result[role] = row
        return result

    def list_objects(self, pointer):
        prefix = f"subscriptions/{pointer['id']}/{pointer['snapshotId']}/"
        listed = self.resources.api("GET", self.resources.bucket + "/objects?" + urlencode({"prefix": prefix, "per_page": 3}))
        require(isinstance(listed, list) and len(listed) <= 2, "Aggregate snapshot inventory differs.")
        result = {}
        for row in listed:
            require(isinstance(row, dict) and row.get("key") in {prefix + name for name in OBJECTS}
                    and row["key"] not in result and integer(row.get("size"), 1, 4096), "Aggregate snapshot has unknown objects.")
            result[row["key"]] = row["size"]
        return prefix, result

    def checked_objects(self, role, pointer, *, missing=False):
        prefix, listed = self.list_objects(pointer)
        for name, body in self.bodies(role).items():
            current = self.resources.objects.request("GET", prefix + name)
            require((current is None and missing and prefix + name not in listed)
                    or (current == body and listed.get(prefix + name) == len(body)), "Aggregate snapshot object differs.")
        return prefix

    def pointer(self, row, role):
        return {"id": row["id"], "snapshotId": self.seed_identity(role)[1],
                "manifestSha256": digest(self.bodies(role)["manifest.json"]),
                "tokenSha256": digest(row["token"].encode("ascii")), "createdAt": row["created_at"]}

    def verify_snapshots(self, checkpoint, *, absent=False):
        pointers = checkpoint["snapshots"]
        current = self.subscriptions([item["id"] for item in pointers.values()])
        require(not current if absent else set(current) == set(ROLES), "Aggregate seed row inventory differs.")
        for role, item in pointers.items():
            if not absent:
                require(current[role]["generation"] == 1 and self.pointer(current[role], role) == item,
                        "Aggregate seed pointer changed after prepare.")
            self.checked_objects(role, item, missing=absent)
        self.require_quiet([item["id"] for item in pointers.values()])


def prepare(cohort, revision, guard, release_pin):
    validate_release_pin(release_pin)
    require(release_pin["revision"] == revision, "Aggregate preparation release revision differs.")
    current = cohort.subscriptions()
    require(not current or set(current) == set(ROLES), "Aggregate preparation found a partial D1 reservation.")
    cohort.require_quiet([row["id"] for row in current.values()])
    slots = cohort.slots()
    require(all(row["code_sha256"] is None for row in slots.values()), "Revoke existing managed aggregates before preparing fixtures.")
    auth = cohort.auth()
    watermark = cohort.read("SELECT COALESCE(max(receipt_id),0) AS highWater FROM telegram_inbox")
    require(len(watermark) == 1 and integer(watermark[0].get("highWater"), 0, MAX_ID), "Aggregate receipt watermark differs.")
    if not current:
        steps = [cohort.quiet((), True)]
        for role in ROLES:
            token, _ = cohort.seed_identity(role)
            steps.append(statement("""INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
              SELECT ?,?,?,?,unixepoch(),unixepoch() WHERE NOT EXISTS(SELECT 1 FROM subscription_trash WHERE token=?)""",
              cohort.actors[role], cohort.name, cohort.prefix + role, token, token))
        steps.append(statement(_assert_sql("(SELECT count(*) FROM subscriptions WHERE substr(source_url,1,length(?))=?)=2"),
                               cohort.prefix, cohort.prefix))
        guard()
        try:
            cohort.batch(steps)
        except (CloudflareError, FixtureError):
            pass
        current = cohort.subscriptions()
        require(set(current) == set(ROLES), "Aggregate D1 reservation could not be confirmed.")
    pointers = {role: cohort.pointer(row, role) for role, row in current.items()}
    # Deterministic, key-scoped identities let an interrupted prepare reconcile without raw tokens in an artifact.
    for role, pointer in pointers.items():
        prefix, listed = cohort.list_objects(pointer)
        for name, body in cohort.bodies(role).items():
            remote = cohort.resources.objects.request("GET", prefix + name)
            require(remote is None or (remote == body and listed.get(prefix + name) == len(body)), "Aggregate seed object is occupied.")
            if remote is None:
                require(current[role]["generation"] == 0, "An already published aggregate snapshot is incomplete.")
                guard()
                try:
                    cohort.resources.objects.request("PUT", prefix + name, body)
                except (CloudflareError, CapacityError):
                    pass
                require(cohort.resources.objects.request("GET", prefix + name) == body, "Aggregate R2 upload could not be confirmed.")
        cohort.checked_objects(role, pointer)
    steps = [cohort.quiet(tuple(item["id"] for item in pointers.values()), True)]
    for role, row in current.items():
        pointer = pointers[role]
        steps.append(statement("""UPDATE subscriptions SET generation=1,snapshot_id=?,manifest_sha256=?,node_count=1
          WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=? AND created_at=? AND updated_at=? AND generation=0
            AND expire_at IS NULL AND traffic_used IS NULL AND traffic_total IS NULL AND last_error IS NULL""",
          pointer["snapshotId"], pointer["manifestSha256"], row["id"], cohort.actors[role], cohort.name,
          cohort.prefix + role, row["token"], row["created_at"], row["updated_at"]))
    guard()
    try:
        cohort.batch(steps)
    except (CloudflareError, FixtureError):
        pass
    checkpoint = {"version": 1, "phase": "prepared", "cohort": cohort.cohort, "revision": revision, "identity": cohort.identity,
        "releasePin": dict(release_pin),
        "afterReceiptId": watermark[0]["highWater"], "snapshots": pointers,
        "startingRevisions": {role: slots.get(role, {}).get("revision", 0) for role in ROLES},
        "authEpoch": auth, "receipts": {role: [] for role in ROLES}, "capabilities": {}}
    cohort.verify_snapshots(checkpoint)
    return checkpoint


def receipt_history(cohort, checkpoint, phase):
    rows = cohort.read("""SELECT i.receipt_id,i.actor_id,i.message_id,i.message_date,a.result,a.revision,a.code_sha256,
      a.auth_message_date,a.auth_message_id,o.sent_message_id,
      (i.chat_type='private' AND i.chat_id=i.actor_id AND i.thread_id IS NULL AND i.command='help'
        AND o.state='sent' AND o.sent_message_id>0) AS safe
      FROM telegram_inbox AS i JOIN telegram_aggregate_actions AS a USING(receipt_id)
      LEFT JOIN telegram_outbox AS o USING(receipt_id)
      WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_nonce=? AND i.receipt_id>CAST(? AS INTEGER)
      ORDER BY i.receipt_id LIMIT 9""", cohort.policy["botId"], *cohort.actors.values(), MARKER, checkpoint["afterReceiptId"])
    history, grouped = {role: [] for role in ROLES}, {role: [] for role in ROLES}
    require(cohort.auth() == checkpoint["authEpoch"], "Aggregate authorization epoch changed during acceptance.")
    for row in rows:
        role = next((key for key, actor in cohort.actors.items() if actor == row.get("actor_id")), None)
        require(role is not None and row.get("safe") == 1 and integer(row.get("receipt_id"), checkpoint["afterReceiptId"] + 1, MAX_ID)
                and integer(row.get("message_id"), 1, MAX_ID) and integer(row.get("message_date"), 1, MAX_ID)
                and integer(row.get("sent_message_id"), 1, MAX_ID), "Aggregate receipt scope or sent state differs.")
        if role == "admin":
            require((row.get("auth_message_date"), row.get("auth_message_id")) == (0, 0), "Aggregate administrator epoch differs.")
        else:
            epoch = {"allowed": 1, "date": row.get("auth_message_date"), "message": row.get("auth_message_id")}
            require(digest(canonical(epoch).encode()) == checkpoint["authEpoch"], "Aggregate receipt authorization epoch differs.")
        grouped[role].append(row)
        # Raw actor IDs and message IDs are never copied into the checkpoint.
        history[role].append(digest(canonical([cohort.cohort, role, row]).encode()))
    for role in ROLES:
        require([row["result"] for row in grouped[role]] == EXPECTED[phase][role]
                and history[role][:len(checkpoint["receipts"][role])] == checkpoint["receipts"][role],
                "Aggregate command count, result order, or prior receipt changed.")
    return history, grouped


def capability(cohort, role, slot):
    nonce = slot.get("nonce")
    code = derive_code(cohort.encoded, cohort.policy, role, nonce)
    require(digest(code.encode()) == slot.get("code_sha256"), "Aggregate key or derived capability differs.")
    return {"sha256": slot["code_sha256"], "nonce": nonce, "keyVersion": 1}


def expected_exports(cohort, role):
    return expected_fixture_exports([cohort.node(role)])


def expected_fixture_exports(nodes):
    # Independent fixed Shadowsocks oracle for the emitted Clash framing.
    proxies = [{"name": node["name"], "type": "ss", "server": node["server"], "port": 8388,
                "cipher": "aes-256-gcm", "password": node["password"]} for node in nodes]
    labels = ",".join(canonical(node["name"]) for node in nodes)
    entries = "".join("  - " + canonical(proxy) + "\n" for proxy in proxies)
    clash = ("proxies:\n" + entries + "proxy-groups:\n"
        '  - {"name":"🚀 节点选择","type":"select","proxies":[' + labels + "]}\n"
        '  - {"name":"♻️ 自动选择","type":"url-test","proxies":[' + labels
        + '],"url":"http://www.gstatic.com/generate_204","interval":300}\nrules:\n  - "MATCH,🚀 节点选择"\n').encode("utf-8")
    return {"clash": clash, "base64": b64encode("\n".join(node["share"] for node in nodes).encode("ascii"))}


def probe_capability(cohort, role, recovery, *, active):
    require(recovery["keyVersion"] == 1 and canonical_nonce(recovery["nonce"]), "Aggregate recovery metadata differs.")
    code = derive_code(cohort.encoded, cohort.policy, role, recovery["nonce"])
    require(digest(code.encode()) == recovery["sha256"], "Aggregate recovery digest differs.")
    return probe_fixture_exports(code, recovery["sha256"], expected_exports(cohort, role), role, active=active)


def probe_fixture_exports(code, code_sha256, exports, label, *, active):
    deadline = monotonic() + 60
    report = {}
    for format_name, body in exports.items():
        for method in ("GET", "HEAD"):
            with _request(method, f"/agg/{code}/{format_name}", deadline, "aggregate " + label) as response:
                _check_headers(response, 200 if active else 404, "aggregate " + label,
                               "text/yaml" if active and format_name == "clash" else "text/plain")
                expected = body if active else b"Not found."
                if method == "HEAD":
                    require(response.read(1) == b"", "Aggregate HEAD returned a body.")
                else:
                    require(_small_body(response) == expected and response.getheader("Transfer-Encoding") is None
                            and response.getheader("Content-Length") == str(len(expected)), "Aggregate export bytes or length differ.")
        report[format_name] = {"status": 200 if active else 404, "bytes": len(body) if active else 0,
                               "sha256": digest(body) if active else code_sha256}
    for method in ("GET", "HEAD"):
        with _request(method, f"/s/{code}", deadline, "aggregate alias " + label) as response:
            if not active:
                _check_headers(response, 404, "aggregate alias " + label, "text/plain")
                require((response.read(1) == b"") if method == "HEAD" else _small_body(response) == b"Not found.",
                        "Revoked aggregate alias denial differs.")
            else:
                cache = {item.strip().lower() for item in response.getheader("Cache-Control", "").split(",")}
                require(response.status == 302 and response.getheader("Location") == f"/agg/{code}/clash"
                        and cache == {"private", "no-store"} and response.getheader("Referrer-Policy") == "no-referrer"
                        and response.getheader("X-Content-Type-Options") == "nosniff" and response.getheader("Set-Cookie") is None
                        and response.getheader("Age") is None and response.getheader("CF-Cache-Status", "").upper() in {"", "DYNAMIC", "BYPASS"}
                        and response.getheader("Content-Encoding", "identity").lower() == "identity" and _small_body(response) == b"",
                        "Aggregate alias target or privacy differs.")
    report["alias"] = {"status": 302 if active else 404, "GET": 302 if active else 404, "HEAD": 302 if active else 404}
    return report


def capture(cohort, checkpoint, action, probe=probe_capability, *, release_pin):
    verify_checkpoint_release(checkpoint, release_pin, retiring=action == "retire")
    phase = PHASES[action]
    ids = [item["id"] for item in checkpoint["snapshots"].values()]
    current = cohort.subscriptions(ids)
    cohort.verify_snapshots(checkpoint, absent=action == "retire" and not current)
    history, grouped = receipt_history(cohort, checkpoint, phase)
    slots, caps = cohort.slots(), dict(checkpoint["capabilities"])
    require(set(slots) == set(ROLES), "Both managed aggregate slots are required.")
    for role in ROLES:
        start, slot, records = checkpoint["startingRevisions"][role], slots[role], grouped[role]
        first = records[0]
        require(first["revision"] == start + 1 and records[1]["revision"] == first["revision"]
                and matches(DIGEST, first["code_sha256"]) and records[1]["code_sha256"] == first["code_sha256"],
                "Repeated aggregate command changed the initial capability.")
        key = role + "-initial"
        if action == "capture-initial":
            require(slot["revision"] == start + 1 and slot["code_sha256"] == first["code_sha256"], "Initial aggregate slot differs.")
            caps[key] = capability(cohort, role, slot)
        require(caps[key]["sha256"] == first["code_sha256"], "Initial aggregate capability hash changed.")
        if role == "member" and phase in {"member-revoked", "rotated", "retired"}:
            require(records[2]["revision"] == start + 2 and records[2]["code_sha256"] == first["code_sha256"],
                    "Member revocation did not target the initial link.")
        if role == "member" and phase in {"rotated", "retired"}:
            require(records[3]["revision"] == start + 3 and matches(DIGEST, records[3]["code_sha256"])
                    and records[3]["code_sha256"] != first["code_sha256"], "Member rotation did not change the capability.")
            if action == "verify-rotated":
                require(slot["revision"] == start + 3 and slot["code_sha256"] == records[3]["code_sha256"], "Rotated member slot differs.")
                caps["member-rotated"] = capability(cohort, role, slot)
            require(caps["member-rotated"]["sha256"] == records[3]["code_sha256"], "Rotated capability hash changed.")
        expected_revision = start + (4 if role == "member" and phase == "retired" else
            3 if role == "member" and phase == "rotated" else
            2 if phase == "retired" or (role == "member" and phase == "member-revoked") else 1)
        active_key = "member-rotated" if role == "member" and phase == "rotated" else key
        active = phase != "retired" and not (role == "member" and phase == "member-revoked")
        require(slot["revision"] == expected_revision and (slot["code_sha256"] == caps[active_key]["sha256"] if active else
                (slot["code_sha256"], slot["nonce"], slot["key_version"]) == (None, None, None)), "Managed aggregate current state differs.")
        if phase == "retired":
            require(records[-1]["revision"] == expected_revision and records[-1]["code_sha256"] == caps[
                    "member-rotated" if role == "member" else key]["sha256"], "Final aggregate revocation differs.")
    require(len({item["sha256"] for item in caps.values()}) == len(caps), "Aggregate actor capabilities overlap.")
    report = {}
    for label, recovery in caps.items():
        role = label.split("-", 1)[0]
        active = (label == "admin-initial" and phase != "retired") or (label == "member-initial" and phase == "initial")
        active = active or (label == "member-rotated" and phase == "rotated")
        links = cohort.read("SELECT owner_id,bot_id,kind,revoked_at FROM aggregate_links WHERE code_sha256=?", recovery["sha256"])
        require(len(links) == 1 and (links[0]["owner_id"], links[0]["bot_id"], links[0]["kind"]) == (
            cohort.actors[role], cohort.policy["botId"], "all") and (links[0]["revoked_at"] is None) == active,
            "Aggregate link ownership or revocation differs.")
        report[label] = probe(cohort, role, recovery, active=active)
    return {**checkpoint, "phase": phase, "receipts": history, "capabilities": caps}, report


def retire(cohort, checkpoint, guard, probe=probe_capability, *, release_pin):
    # Validate new real revocation receipts before retiring synthetic data. Keep every receipt and link tombstone.
    verified, report = capture(cohort, checkpoint, "retire", probe, release_pin=release_pin)
    pointers = checkpoint["snapshots"]
    ids = tuple(item["id"] for item in pointers.values())
    current = cohort.subscriptions(ids)
    require(not current or set(current) == set(ROLES), "Aggregate retirement found a partial D1 cohort.")
    steps = [cohort.quiet(ids, True)]
    for role, row in current.items():
        steps.append(statement("""DELETE FROM subscriptions WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=?
          AND generation=1 AND snapshot_id=? AND manifest_sha256=? AND node_count=1 AND created_at=? AND updated_at=?
          AND NOT EXISTS(SELECT 1 FROM telegram_aggregate_slots WHERE bot_id=? AND actor_id IN (?,?) AND code_sha256 IS NOT NULL)
          AND NOT EXISTS(SELECT 1 FROM telegram_temp_batch WHERE bot_id=? AND actor_id IN (?,?))""",
          row["id"], row["owner_id"], row["name"], row["source_url"], row["token"], row["snapshot_id"], row["manifest_sha256"],
          row["created_at"], row["updated_at"], cohort.policy["botId"], *cohort.actors.values(), cohort.policy["botId"], *cohort.actors.values()))
    steps.append(statement(_assert_sql("NOT EXISTS(SELECT 1 FROM subscriptions WHERE id IN (?,?) OR name=?)"), *ids, cohort.name))
    if current:
        guard()
        try:
            cohort.batch(steps)
        except (CloudflareError, FixtureError):
            pass
    require(not cohort.subscriptions(ids), "Aggregate D1 retirement could not be confirmed.")
    cohort.require_quiet(ids)
    for role, pointer in pointers.items():
        prefix = cohort.checked_objects(role, pointer, missing=True)
        for name in OBJECTS:
            guard()
            cohort.resources.objects.request("DELETE", prefix + name)
        require(not cohort.list_objects(pointer)[1] and all(cohort.resources.objects.request("GET", prefix + name) is None for name in OBJECTS),
                "Aggregate synthetic R2 retirement could not be confirmed.")
    require(not cohort.subscriptions(ids) and receipt_history(cohort, checkpoint, "retired")[0] == verified["receipts"],
            "Aggregate retirement changed receipt evidence.")
    # Preserve the original acceptance pin and separately disclose the release that performed cleanup.
    return {**verified, "retiredAtReleasePin": dict(release_pin)}, report


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "Aggregate acceptance requires a trusted manual main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        body = event.read(65537)
    require(len(body) <= 65536, "Aggregate workflow event exceeds the limit.")
    action, cohort_key, source_run = parse_inputs(_parse_object(body, "Aggregate workflow event differs."))
    require_current_main(revision)
    source_revision = _get_json(f"/actions/runs/{source_run}", os.environ["GH_TOKEN"]).get("head_sha") if action == "retire" else revision
    require(matches(REVISION, source_revision), "Aggregate checkpoint revision differs.")
    checkpoint = read_checkpoint(source_run, source_revision, os.environ["GH_TOKEN"]) if source_run else None
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy, encoded = json.loads(raw_policy), os.environ.get("SUBS_BOT_TELEGRAM_AGGREGATE_KEY", "")
    key_bytes(encoded)
    target = _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), "Aggregate resource configuration differs.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped Cloudflare credentials are required.")
    data = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), data, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    release_pin = {"revision": version.revision, "versionId": active.version,
                   "moduleSha256": version.digest, "compatibilityDate": version.compatibility}
    validate_release_pin(release_pin)
    policy_sha = digest(raw_policy.encode("utf-8"))
    require(scope.cron_enabled() and version.revision == revision and version.telegram_config_sha256 == policy_sha
            and getattr(version, "telegram_aggregate_key_sha256", None) == digest(encoded.encode("ascii")),
            "Active Worker, Telegram policy, or aggregate key differs.")
    _verify_health(revision)
    resources = Resources(target, data, SnapshotObjects(target["accountId"], data_token))
    identity = digest(f"{resources.scope_hash}/{policy_sha}/{digest(encoded.encode())}".encode("ascii"))
    expected = digest((Path(__file__).resolve().parents[1] / "migrations" / MIGRATION).read_bytes())
    require(resources.query("SELECT position,sha256,mode FROM subs_bot_schema_migrations WHERE name=?", (MIGRATION,))
            == [{"position": 14, "sha256": expected, "mode": "applied"}], "Aggregate migration proof differs.")

    def guard():
        require_current_main(revision)
        require(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version
                and scope.cron_enabled(), "Isolation release changed during aggregate acceptance.")

    cohort = Cohort(resources, policy, cohort_key, encoded, identity)
    report = {}
    if checkpoint is None:
        checkpoint = prepare(cohort, revision, guard, release_pin)
    else:
        validate_checkpoint(checkpoint, action, cohort_key, source_revision, identity, release_pin)
        checkpoint, report = (retire(cohort, checkpoint, guard, release_pin=release_pin) if action == "retire"
                              else capture(cohort, checkpoint, action, release_pin=release_pin))
    guard()
    _verify_health(revision)
    save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, checkpoint)
    print(json.dumps({"phase": checkpoint["phase"], "snapshotCount": 2,
        "sentReceiptCount": sum(len(items) for items in checkpoint["receipts"].values()),
        "capabilityCount": len(checkpoint["capabilities"]), "exportEvidence": report,
        "verifiedAbsentObjectCount": 4 if action == "retire" else 0}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CapacityError, CloudflareError, FixtureError, ProbeError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram aggregate checkpoint could not be verified.")

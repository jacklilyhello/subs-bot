"""Verify and retire only fixed synthetic uploads from the two isolation Telegram actors."""

from base64 import b64encode
from hashlib import sha256
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sys
from time import monotonic
from urllib.parse import urlencode
from zipfile import ZipFile

from capacity_probe import MAX_SMALL_BODY_BYTES, ProbeError, _check_headers, _request, _small_body
from capacity_resources import CapacityError, R2Objects, Resources, integer, matches, save_private_json
from cloudflare_isolation import CloudflareClient, CloudflareError, DIGEST, REVISION, UUID, _Isolation, _verify_health
from d1_migrations import _assert_sql
from prepare_isolation_artifact import (
    ArtifactError, MAIN_REF, REPOSITORY, _download, _get_json, _parse_object, _zip_members,
    require_current_main, select_main_artifact,
)
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import validate_release_pin
from telegram_view_fixtures import FixtureError, query, rows, statement


WORKFLOW = "worker-isolation-telegram-documents.yml"
ARTIFACT_PREFIX = "subs-bot-telegram-document"
CHECKPOINT = "telegram-document-checkpoint.json"
MIGRATIONS = ("0011_telegram_document_jobs.sql", "0012_telegram_document_publication.sql")
NODE_MIGRATIONS = ("0018_telegram_subscription_reads.sql", "0022_telegram_subscription_node_pages.sql")
COHORT = re.compile(r"[a-f0-9]{16}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
TOKEN = re.compile(r"[a-f0-9]{32}")
MAX_ID = 9_007_199_254_740_991
MAX_CHECKPOINT = 8192
MAX_OBJECT = 16384
UPLOADED = "uploaded://telegram-document"
MARKER = "document-job:v1"
ROLES = {"member": "memberId", "admin": "adminId"}
DOCUMENT = "document"
NODE_PAGES = "node-pages"
VERSIONS = {"member-first": ("member", 1, ("member-first",)), "admin-first": ("admin", 1, ("admin-first",)),
            "member-second": ("member", 2, ("member-second-1", "member-second-2"))}
NODE_VERSIONS = {"member-first": ("member", 1, ("member-01", "member-02")),
                 "admin-first": ("admin", 1, tuple(f"admin-{index:02d}" for index in range(1, 33)))}
PHASES = {"prepare": "prepared", "capture-created": "created", "verify-replaced": "verified", "retire": "retired"}
PREVIOUS = {"capture-created": {"prepared"}, "verify-replaced": {"created"}, "retire": {"created", "verified"}}
SNAPSHOTS = {"prepared": (), "created": ("member-first", "admin-first"), "verified": tuple(VERSIONS)}
SHARE = "ss://YWVzLTI1Ni1nY206Zml4dHVyZQ@203.0.113.10:8388#"
OBJECTS = ("manifest.json", "0.ndjson")


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def digest(body):
    return sha256(body).hexdigest()


def fixture_name(cohort, profile):
    return ("tgdoc-nodes-" if profile == NODE_PAGES else "tgdoc-") + cohort


def share_lines(cohort, version, profile=DOCUMENT):
    versions = NODE_VERSIONS if profile == NODE_PAGES else VERSIONS
    return [f"{SHARE}{fixture_name(cohort, profile)}-{suffix}" for suffix in versions[version][2]]


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"profile", "action", "cohort", "source_run_id", "negative_message_id", "confirm_retire"},
            "Invalid isolated document workflow inputs.")
    profile = inputs.get("profile", DOCUMENT)
    action, cohort = inputs.get("action"), inputs.get("cohort")
    source, negative, confirmation = (inputs.get(key, "") for key in ("source_run_id", "negative_message_id", "confirm_retire"))
    require(profile in (DOCUMENT, NODE_PAGES) and isinstance(action, str) and action in PHASES and matches(COHORT, cohort)
            and (profile == DOCUMENT or action != "verify-replaced")
            and (source == "" if action == "prepare" else matches(DECIMAL, source))
            and (negative == "" or (action == "verify-replaced" and matches(DECIMAL, negative) and int(negative) <= MAX_ID))
            and confirmation == (f"retire {cohort}" if action == "retire" else ""), "Invalid document action or confirmation.")
    return profile, action, cohort, source, int(negative) if negative else None


def read_checkpoint(run_id, revision, token):
    workflow = _get_json(f"/actions/workflows/{WORKFLOW}", token)
    path = f".github/workflows/{WORKFLOW}"
    require(integer(workflow.get("id"), 1, MAX_ID) and workflow.get("path") == path, "Document workflow identity differs.")
    _, artifact_id, archive_sha = select_main_artifact(run_id, revision, token, workflow_id=workflow["id"],
        workflow_path=path, artifact_prefix=ARTIFACT_PREFIX, workflow_label="Telegram document checkpoint")
    raw = _download(artifact_id, token)
    require(len(raw) <= MAX_CHECKPOINT and digest(raw) == archive_sha, "Document checkpoint archive digest or size differs.")
    with ZipFile(BytesIO(raw)) as archive:
        members = _zip_members(archive)
        require(set(members) == {CHECKPOINT} and members[CHECKPOINT].file_size <= MAX_CHECKPOINT,
                "Document checkpoint archive has an unexpected member.")
        body = archive.read(members[CHECKPOINT])
    return _parse_object(body, "Invalid isolated document checkpoint.")


def validate_checkpoint(checkpoint, action, cohort, revision, identity, profile=DOCUMENT, release_pin=None):
    fields = {"version", "phase", "cohort", "revision", "identity", "afterReceiptId", "snapshots", "receipts", "negativeReceiptBound"}
    node_pages = profile == NODE_PAGES
    if node_pages:
        fields |= {"profile", "releasePin"}
    require(set(checkpoint) == fields and type(checkpoint["version"]) is int
            and checkpoint["version"] == (2 if node_pages else 1) and checkpoint["phase"] in PREVIOUS[action]
            and (checkpoint["cohort"], checkpoint["revision"], checkpoint["identity"]) == (cohort, revision, identity)
            and integer(checkpoint["afterReceiptId"], 0, MAX_ID) and type(checkpoint["negativeReceiptBound"]) is bool,
            "Document checkpoint does not match the requested phase or environment.")
    if node_pages:
        require(checkpoint["profile"] == NODE_PAGES and checkpoint["phase"] in ("prepared", "created")
                and action in ("capture-created", "retire") and not checkpoint["negativeReceiptBound"],
                "Node-page document checkpoint phase or profile differs.")
        original = checkpoint["releasePin"]
        validate_release_pin(original)
        validate_release_pin(release_pin)
        require(original["revision"] == revision and (action == "retire" or original == release_pin),
                "Node-page document checkpoint release differs.")
    versions = NODE_VERSIONS if node_pages else VERSIONS
    snapshots, receipts = checkpoint["snapshots"], checkpoint["receipts"]
    require(isinstance(snapshots, dict) and set(snapshots) == set(SNAPSHOTS[checkpoint["phase"]])
            and isinstance(receipts, dict) and set(receipts) == set(ROLES), "Document checkpoint inventory differs.")
    for role, history in receipts.items():
        expected = sum(versions[label][0] == role for label in snapshots)
        require(isinstance(history, list) and len(history) == expected and all(matches(DIGEST, item) for item in history)
                and len(set(history)) == len(history), "Document checkpoint receipts differ.")
    for label, item in snapshots.items():
        require(isinstance(item, dict) and set(item) == {"id", "generation", "snapshotId", "manifestSha256", "tokenSha256",
                "createdAt", "updatedAt", "objects"} and integer(item["id"], 1, MAX_ID)
                and integer(item["generation"], versions[label][1], versions[label][1])
                and integer(item["createdAt"], 1, MAX_ID) and integer(item["updatedAt"], item["createdAt"], MAX_ID)
                and matches(UUID, item["snapshotId"]) and matches(DIGEST, item["manifestSha256"])
                and matches(DIGEST, item["tokenSha256"]), "Document checkpoint pointer identity differs.")
        objects = item["objects"]
        require(isinstance(objects, dict) and set(objects) == set(OBJECTS)
                and all(isinstance(obj, dict) and set(obj) == {"bytes", "sha256"} and integer(obj["bytes"], 1, MAX_OBJECT)
                        and matches(DIGEST, obj["sha256"]) for obj in objects.values())
                and objects["manifest.json"]["sha256"] == item["manifestSha256"], "Document checkpoint objects differ.")
    if snapshots:
        member, admin = (snapshots[name] for name in ("member-first", "admin-first"))
        require(member["id"] != admin["id"] and member["tokenSha256"] != admin["tokenSha256"], "Document owner identities overlap.")
        if "member-second" in snapshots:
            verify_replacement(member, snapshots["member-second"])


def verify_replacement(first, second):
    require(all(first[key] == second[key] for key in ("id", "tokenSha256", "createdAt"))
            and second["generation"] == 2 and second["snapshotId"] != first["snapshotId"]
            and second["updatedAt"] >= first["updatedAt"], "Document replacement changed the stable subscription identity.")


class Cohort:
    def __init__(self, resources, policy, cohort, profile=DOCUMENT):
        self.resources = resources
        self.policy = policy
        self.profile = profile
        self.versions = NODE_VERSIONS if profile == NODE_PAGES else VERSIONS
        self.name = fixture_name(cohort, profile)
        self.cohort = cohort
        self.actors = {role: policy[key] for role, key in ROLES.items()}

    def read(self, sql, *params):
        return self.resources.query(sql, params)

    def batch(self, statements):
        return query(self.resources.api, self.resources.database, {"batch": statements}, len(statements))

    def subscriptions(self, ids=()):
        known = json.dumps(list(ids))
        fields = ("id,owner_id,name,source_url,CASE WHEN owner_id IN (?,?) THEN token END AS token,"
                  "generation,snapshot_id,manifest_sha256,node_count,created_at,updated_at")
        matches_name = "name=? OR id IN (SELECT value FROM json_each(?))"
        result = self.read(f"""SELECT {fields}, 0 AS trashed,
          EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id=subscriptions.id) AS lifecycle
          FROM subscriptions WHERE {matches_name}
          UNION ALL SELECT {fields}, 1 AS trashed, 1 AS lifecycle FROM subscription_trash WHERE {matches_name} LIMIT 3
        """, *self.actors.values(), self.name, known, *self.actors.values(), self.name, known)
        by_owner = {}
        for row in result:
            role = next((role for role, actor in self.actors.items() if actor == row.get("owner_id")), None)
            require(role is not None and role not in by_owner and row.get("name") == self.name and row.get("source_url") == UPLOADED
                    and row.get("trashed") == row.get("lifecycle") == 0 and integer(row.get("id"), 1, MAX_ID)
                    and matches(TOKEN, row.get("token")) and matches(UUID, row.get("snapshot_id"))
                    and matches(DIGEST, row.get("manifest_sha256")) and integer(row.get("generation"), 1, 2)
                    and integer(row.get("node_count"), 1, max(len(entry[2]) for entry in self.versions.values()))
                    and integer(row.get("created_at"), 1, MAX_ID)
                    and integer(row.get("updated_at"), row["created_at"], MAX_ID), "Document subscription ownership or pointer is ambiguous.")
            by_owner[role] = row
        return by_owner

    def quiet_statement(self, ids, assertion):
        known = json.dumps(list(ids))
        quiet = """NOT EXISTS(SELECT 1 FROM telegram_document_jobs WHERE bot_id=? AND actor_id IN (?,?)
            AND name=? AND state IN ('pending','leased'))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_reservations WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_stages WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_trash WHERE name=? OR id IN (SELECT value FROM json_each(?)))"""
        params = (self.policy["botId"], *self.actors.values(), self.name, known, known, known, self.name, known)
        if self.profile == NODE_PAGES:
            for table in ("telegram_subscription_read", "telegram_subscription_node_page"):
                quiet += f""" AND NOT EXISTS(SELECT 1 FROM {table} AS feature JOIN telegram_outbox USING(receipt_id)
                    WHERE feature.subscription_id IN (SELECT value FROM json_each(?)) AND state IN ('pending','leased','sending'))"""
                params += (known,)
        return statement(_assert_sql(quiet) if assertion else f"SELECT ({quiet}) AS quiet", *params)

    def require_quiet(self, ids):
        data = self.quiet_statement(ids, False)
        require(self.read(data["sql"], *data["params"]) == [{"quiet": 1}], "Document cohort still has a live job or a protected reference.")

    def receipts(self, after, snapshots):
        readback = self.read("""SELECT i.receipt_id, i.actor_id, j.result_code, s.node_count, o.state,
          (i.chat_type='private' AND i.chat_id=i.actor_id AND i.thread_id IS NULL AND i.receipt_nonce=?
             AND j.bot_id=i.bot_id AND j.actor_id=i.actor_id AND j.state='done'
             AND j.file_id IS NULL AND j.name IS NULL AND j.suffix IS NULL AND j.expected_size IS NULL
             AND j.lease_id IS NULL AND j.lease_until IS NULL AND o.sent_message_id IS NOT NULL) AS safe
          FROM telegram_document_saved_counts AS s JOIN telegram_inbox AS i USING(receipt_id)
          JOIN telegram_document_jobs AS j USING(receipt_id) LEFT JOIN telegram_outbox AS o USING(receipt_id)
          WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER) AND s.name_sha256=?
          ORDER BY i.receipt_id LIMIT 4""", MARKER, self.policy["botId"], *self.actors.values(), after, digest(self.name.encode("ascii")))
        result = {role: [] for role in ROLES}
        wanted = {role: [len(nodes) for label, (actor, _, nodes) in self.versions.items()
                         if label in snapshots and actor == role] for role in ROLES}
        for row in readback:
            role = next(role for role, actor in self.actors.items() if actor == row.get("actor_id"))
            index = len(result[role])
            require(index < len(wanted[role]) and integer(row.get("receipt_id"), after + 1, MAX_ID)
                    and (row.get("safe"), row.get("state"), row.get("result_code"), row.get("node_count"))
                    == (1, "sent", "saved", wanted[role][index]), "Document saved receipt or reply differs.")
            result[role].append(digest(f"{self.cohort}/{role}/{row['receipt_id']}".encode("ascii")))
        require(all(len(result[role]) == len(wanted[role]) for role in ROLES), "Document saved receipt inventory differs.")
        return result

    def check_negative(self, after, message_id):
        if message_id is None:
            return False
        require(self.read("""SELECT j.result_code, o.state, (j.state='done' AND j.attempts BETWEEN 1 AND 3
          AND j.file_id IS NULL AND j.name IS NULL
          AND j.suffix IS NULL AND j.expected_size IS NULL AND o.sent_message_id IS NOT NULL AND NOT EXISTS(
            SELECT 1 FROM telegram_document_saved_counts WHERE receipt_id=i.receipt_id)) AS safe
          FROM telegram_inbox AS i JOIN telegram_document_jobs AS j USING(receipt_id)
          JOIN telegram_outbox AS o USING(receipt_id) WHERE i.bot_id=? AND i.actor_id=? AND i.chat_id=i.actor_id
            AND i.chat_type='private' AND i.thread_id IS NULL AND i.receipt_nonce=? AND i.receipt_id>CAST(? AS INTEGER)
            AND i.message_id=CAST(? AS INTEGER) AND j.bot_id=i.bot_id AND j.actor_id=i.actor_id LIMIT 2
        """, self.policy["botId"], self.actors["member"], MARKER, after, message_id)
            == [{"result_code": "invalid-document", "state": "sent", "safe": 1}], "Exact negative document receipt could not be verified.")
        return True

    def list_objects(self, pointer):
        prefix = f"subscriptions/{pointer['id']}/{pointer['snapshotId']}/"
        listed = self.resources.api("GET", self.resources.bucket + "/objects?" + urlencode({"prefix": prefix, "per_page": 3}))
        require(isinstance(listed, list) and len(listed) <= len(OBJECTS), "Document snapshot object inventory differs.")
        result = {}
        for item in listed:
            require(isinstance(item, dict) and item.get("key") in {prefix + name for name in OBJECTS}
                    and integer(item.get("size"), 1, MAX_OBJECT) and item["key"] not in result, "Unknown document snapshot object.")
            result[item["key"]] = item["size"]
        return prefix, result

    def snapshot(self, label, row, probe):
        _, generation, _ = self.versions[label]
        shares = share_lines(self.cohort, label, self.profile)
        require((row["generation"], row["node_count"]) == (generation, len(shares)), "Document generation or node count differs.")
        pointer = {"id": row["id"], "generation": generation, "snapshotId": row["snapshot_id"],
                   "manifestSha256": row["manifest_sha256"], "tokenSha256": digest(row["token"].encode("ascii")),
                   "createdAt": row["created_at"], "updatedAt": row["updated_at"]}
        prefix, listed = self.list_objects(pointer)
        require(set(listed) == {prefix + name for name in OBJECTS}, "Document snapshot is incomplete.")
        bodies = {name: self.resources.objects.request("GET", prefix + name) for name in OBJECTS}
        require(all(isinstance(body, bytes) and len(body) == listed[prefix + name] for name, body in bodies.items()),
                "Document snapshot object size differs.")
        objects = {name: {"bytes": len(body), "sha256": digest(body)} for name, body in bodies.items()}
        require(objects["manifest.json"]["sha256"] == pointer["manifestSha256"], "Document snapshot manifest digest differs.")
        manifest = _parse_object(bodies["manifest.json"].decode("utf-8"), "Invalid document snapshot manifest.")
        require(manifest == {"version": 1, "chunks": [{**objects["0.ndjson"], "count": len(shares)}]},
                "Document snapshot descriptors differ.")
        chunk = bodies["0.ndjson"]
        lines = chunk.split(b"\n")
        require(len(lines) == len(shares) + 1 and lines[-1] == b"", "Document snapshot lines differ.")
        nodes = [_parse_object(line.decode("utf-8"), "Invalid synthetic document node.") for line in lines[:-1]]
        require([node.get("share") for node in nodes] == shares, "Document snapshot contains unexpected links.")
        if self.profile == NODE_PAGES:
            require(nodes == [{"name": share.split("#", 1)[1], "type": "ss", "share": share} for share in shares],
                    "Node-page document snapshot labels or protocol differ.")
        probe(row["token"], shares)
        return {**pointer, "objects": objects}

    def checked_keys(self, pointer, *, allow_missing):
        prefix, listed = self.list_objects(pointer)
        keys = []
        for name, expected in pointer["objects"].items():
            key = prefix + name
            if allow_missing and key not in listed:
                continue
            require(listed.get(key) == expected["bytes"], "Recorded document object size differs.")
            body = self.resources.objects.request("GET", key)
            require(isinstance(body, bytes) and len(body) == expected["bytes"] and digest(body) == expected["sha256"],
                    "Recorded document object digest differs.")
            keys.append(key)
        return keys


def probe_export(token, shares):
    deadline = monotonic() + 20
    expected = b64encode("\n".join(shares).encode("ascii"))
    require(len(expected) <= MAX_OBJECT, "Document Base64 fixture exceeds the probe limit.")
    for method in ("GET", "HEAD"):
        with _request(method, f"/sub/{token}/base64", deadline, "document snapshot") as response:
            _check_headers(response, 200, "document snapshot", "text/plain")
            if method == "GET":
                require(response.getheader("Content-Length") == str(len(expected)), "Document Base64 export differs.")
                body = _small_body(response) if len(expected) <= MAX_SMALL_BODY_BYTES else response.read(len(expected) + 1)
                require(body == expected, "Document Base64 export differs.")
            else:
                require(response.read(1) == b"", "Document Base64 export differs.")


def capture(cohort, checkpoint, action, negative, probe):
    snapshots = checkpoint["snapshots"]
    previous = list({item["id"] for item in snapshots.values()})
    current = cohort.subscriptions(previous)
    require(set(current) == set(ROLES), "Both approved actors must have one matching uploaded subscription.")
    cohort.require_quiet(tuple(row["id"] for row in current.values()))
    if action == "capture-created":
        snapshots = {label: cohort.snapshot(label, current[cohort.versions[label][0]], probe) for label in SNAPSHOTS["created"]}
        require(snapshots["member-first"]["id"] != snapshots["admin-first"]["id"]
                and snapshots["member-first"]["tokenSha256"] != snapshots["admin-first"]["tokenSha256"],
                "Document owner identities overlap.")
    else:
        require(cohort.snapshot("admin-first", current["admin"], probe) == snapshots["admin-first"],
                "The other owner's same-name subscription changed.")
        cohort.checked_keys(snapshots["member-first"], allow_missing=False)
        replacement = cohort.snapshot("member-second", current["member"], probe)
        verify_replacement(snapshots["member-first"], replacement)
        snapshots = {**snapshots, "member-second": replacement}
    receipts = cohort.receipts(checkpoint["afterReceiptId"], snapshots)
    require(all(receipts[role][:len(old)] == old for role, old in checkpoint["receipts"].items()),
            "A previously verified document receipt changed.")
    require(cohort.subscriptions(tuple(row["id"] for row in current.values())) == current,
            "A document pointer changed during readback.")
    return {**checkpoint, "phase": PHASES[action], "snapshots": snapshots, "receipts": receipts,
            "negativeReceiptBound": cohort.check_negative(checkpoint["afterReceiptId"], negative)}


def retire(cohort, checkpoint, guard):
    snapshots = checkpoint["snapshots"]
    selected = {"admin": "admin-first", "member": "member-second" if "member-second" in snapshots else "member-first"}
    ids = tuple(snapshots[label]["id"] for label in selected.values())
    current = cohort.subscriptions(ids)
    cohort.require_quiet(ids)
    require(not current or set(current) == set(ROLES), "A partial document cohort cannot be retired.")
    require(cohort.receipts(checkpoint["afterReceiptId"], snapshots) == checkpoint["receipts"], "Document receipt history changed.")
    keys = [key for pointer in snapshots.values() for key in cohort.checked_keys(pointer, allow_missing=not current)]
    if current:
        checks = [cohort.quiet_statement(ids, True)]
        for role, label in selected.items():
            row, pointer = current[role], snapshots[label]
            require((row["id"], row["generation"], row["snapshot_id"], row["manifest_sha256"], row["created_at"], row["updated_at"],
                    row["node_count"], digest(row["token"].encode("ascii")))
                    == (pointer["id"], pointer["generation"], pointer["snapshotId"], pointer["manifestSha256"],
                        pointer["createdAt"], pointer["updatedAt"], len(cohort.versions[label][2]), pointer["tokenSha256"]),
                    "Current document pointer differs from the retirement checkpoint.")
            checks.append(statement("""DELETE FROM subscriptions WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=?
              AND generation=? AND snapshot_id=? AND manifest_sha256=? AND node_count=? AND created_at=? AND updated_at=?""",
                *(row[key] for key in ("id", "owner_id", "name", "source_url", "token", "generation", "snapshot_id",
                                       "manifest_sha256", "node_count", "created_at", "updated_at"))))
        checks.append(statement(_assert_sql("NOT EXISTS(SELECT 1 FROM subscriptions WHERE name=? OR id IN (?,?))"), cohort.name, *ids))
        guard()
        try:
            cohort.batch(checks)
        except (CloudflareError, FixtureError):
            pass  # The readback, rather than the transport outcome, gates all object deletes.
    require(not cohort.subscriptions(ids), "Document D1 retirement could not be confirmed.")
    cohort.require_quiet(ids)
    guard()
    for key in keys:
        cohort.resources.objects.request("DELETE", key)
    for pointer in snapshots.values():
        prefix, listed = cohort.list_objects(pointer)
        require(not listed and all(cohort.resources.objects.request("GET", prefix + name) is None for name in OBJECTS),
                "Recorded document objects still exist.")
    require(not cohort.subscriptions(ids) and cohort.receipts(checkpoint["afterReceiptId"], snapshots) == checkpoint["receipts"],
            "Document retirement changed the verified scope or receipts.")
    return {**checkpoint, "phase": "retired"}


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "Document acceptance requires the trusted project's manually dispatched main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        body = event.read(65537)
    require(len(body) <= 65536, "Document workflow input is too large.")
    profile, action, cohort_key, source_run, negative = parse_inputs(_parse_object(body, "Invalid document workflow event."))
    require_current_main(revision)
    github_token = os.environ["GH_TOKEN"]
    # A reviewed cleanup can resume after main advances. Acceptance captures stay on one release.
    source_revision = _get_json(f"/actions/runs/{source_run}", github_token).get("head_sha") if action == "retire" else revision
    require(matches(REVISION, source_revision), "Document checkpoint source revision differs.")
    checkpoint = read_checkpoint(source_run, source_revision, github_token) if source_run else None
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy = json.loads(raw_policy)
    target = _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), "Invalid isolated resource configuration.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped Cloudflare credentials are required.")
    data = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), data, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    release_pin = {"revision": version.revision, "versionId": active.version, "moduleSha256": version.digest,
                   "compatibilityDate": version.compatibility}
    policy_sha = digest(raw_policy.encode("utf-8"))
    require(scope.cron_enabled() and version.revision == revision and version.telegram_config_sha256 == policy_sha,
            "The active Worker or Telegram policy differs from the reviewed isolation release.")
    _verify_health(revision)
    resources = Resources(target, data, R2Objects(target["accountId"], data_token))
    identity = digest(f"{resources.scope_hash}/{policy_sha}".encode("ascii"))
    for name in MIGRATIONS + (NODE_MIGRATIONS if profile == NODE_PAGES else ()):
        expected = digest((Path(__file__).resolve().parents[1] / "migrations" / name).read_bytes())
        require(rows(data, resources.database, "SELECT position,sha256,mode FROM subs_bot_schema_migrations WHERE name=?", name)
                == [{"position": int(name[:4]), "sha256": expected, "mode": "applied"}], "Document migration proof differs.")

    def guard():
        require_current_main(revision)
        require(scope.active() == active and scope.worker_config() == config, "Isolated Worker changed during document acceptance.")
        if profile == NODE_PAGES:
            scope.verify_resources()
            require(scope.version(active.version) == version and scope.cron_enabled(),
                    "The node-page Worker version or schedule changed during document acceptance.")

    cohort = Cohort(resources, policy, cohort_key, profile)
    if checkpoint is None:
        require(not cohort.subscriptions(), "The exact synthetic document filename is occupied.")
        cohort.require_quiet(())
        allowed = cohort.read("SELECT COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id=? AND user_id=?),1) AS allowed",
                              policy["botId"], cohort.actors["member"])
        require(allowed == [{"allowed": 1}], "The approved member is not currently authorized for document acceptance.")
        clock = cohort.read("SELECT COALESCE(max(receipt_id),0) AS highWater FROM telegram_inbox")
        require(len(clock) == 1 and integer(clock[0].get("highWater"), 0, MAX_ID), "Document receipt watermark differs.")
        checkpoint = {"version": 1, "phase": "prepared", "cohort": cohort_key, "revision": revision, "identity": identity,
                      "afterReceiptId": clock[0]["highWater"], "snapshots": {}, "receipts": {role: [] for role in ROLES},
                      "negativeReceiptBound": False}
        if profile == NODE_PAGES:
            validate_release_pin(release_pin)
            checkpoint.update(version=2, profile=NODE_PAGES, releasePin=release_pin)
    else:
        validate_checkpoint(checkpoint, action, cohort_key, source_revision, identity, profile, release_pin)
        checkpoint = retire(cohort, checkpoint, guard) if action == "retire" else capture(cohort, checkpoint, action, negative, probe_export)
        if action == "retire" and profile == NODE_PAGES:
            checkpoint["retiredAtReleasePin"] = release_pin
    guard()
    save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, checkpoint)
    report = {"phase": checkpoint["phase"], "snapshotCount": len(checkpoint["snapshots"]),
              "savedReceiptCount": sum(len(items) for items in checkpoint["receipts"].values()),
              "negativeReceiptBound": checkpoint["negativeReceiptBound"],
              "verifiedAbsentObjectCount": len(checkpoint["snapshots"]) * len(OBJECTS) if action == "retire" else 0}
    if profile == NODE_PAGES:
        report["profile"] = NODE_PAGES
        if action == "capture-created":
            report["verifiedNodeCounts"] = {role: len(shares) for role, _, shares in NODE_VERSIONS.values()}
            report["verifiedExportCount"] = len(checkpoint["snapshots"])
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CapacityError, CloudflareError, FixtureError, ProbeError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram document operation could not be verified.")

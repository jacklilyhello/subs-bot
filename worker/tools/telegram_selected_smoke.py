"""Check real IAB selected exports and retire only this synthetic cohort."""

from base64 import urlsafe_b64encode
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import sys
from uuid import UUID as UUIDValue

from capacity_probe import ProbeError
from capacity_resources import CapacityError, Resources, integer, matches, save_private_json
from cloudflare_isolation import CloudflareClient, CloudflareError, DIGEST, REVISION, UUID, _Isolation, _verify_health
from d1_migrations import _assert_sql
from prepare_isolation_artifact import ArtifactError, MAIN_REF, REPOSITORY, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import (
    COHORT, DECIMAL, MAX_ID, ORIGIN, ROLES, SUBSCRIPTION_FIELDS,
    Cohort, SnapshotObjects, canonical, canonical_nonce, digest, expected_fixture_exports, key_bytes,
    probe_fixture_exports, read_checkpoint, require, validate_release_pin,
)
from telegram_view_fixtures import FixtureError, statement


WORKFLOW = "worker-isolation-telegram-selected-smoke.yml"
ARTIFACT_PREFIX = "subs-bot-telegram-selected"
CHECKPOINT = "telegram-selected-checkpoint.json"
MIGRATION = "0017_telegram_selected_export.sql"
MARKER = "selected:v1"
FIRST_SEEDS = ("admin-name", "admin-url", "admin-miss", "member-name")
SEEDS = FIRST_SEEDS + ("admin-late",)
MEMBERS = {
    "admin-first": ("admin-name", "admin-url"),
    "member-first": ("member-name",),
    "admin-second": ("admin-name", "admin-url", "admin-late"),
}
PREVIOUS = {"capture-first-and-extend": "prepared", "capture-independence": "extended", "retire": "independent"}
INPUT_LABELS = {"prepare": (), "capture-first-and-extend": ("admin-first", "member-first"),
                "capture-independence": ("admin-second",), "retire": (), "prepare-abort": (), "abort-retire": ()}
ABORT_ACTIONS = {"prepare-abort", "abort-retire"}
FIRST_ACTIONS = {"admin": (("issued", "admin-first"),), "member": (("issued", "member-first"),)}
INDEPENDENT_ACTIONS = {**FIRST_ACTIONS, "admin": FIRST_ACTIONS["admin"] + (("issued", "admin-second"), ("revoked", "admin-first"))}
FINAL_ACTIONS = {"admin": INDEPENDENT_ACTIONS["admin"] + (("revoked", "admin-second"),),
                 "member": FIRST_ACTIONS["member"] + (("revoked", "member-first"),)}
PHASE_ACTIONS = {"prepared": {role: () for role in ROLES}, "extended": FIRST_ACTIONS, "independent": INDEPENDENT_ACTIONS}


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {"action", "cohort", "source_run_id", "source_revision", "browser_hashes", "confirm_retire"},
            "Selected acceptance workflow inputs differ.")
    action, cohort = inputs.get("action"), inputs.get("cohort")
    source, confirmation = inputs.get("source_run_id", ""), inputs.get("confirm_retire", "")
    expected_confirmation = f"retire {cohort}" if action == "retire" else f"abort {cohort}" if action == "abort-retire" else ""
    require(action in INPUT_LABELS and matches(COHORT, cohort) and
            (source == "" if action == "prepare" else matches(DECIMAL, source)) and
            confirmation == expected_confirmation, "Selected acceptance action or confirmation differs.")
    revision = inputs.get("source_revision", "")
    require(revision == "" or action in ABORT_ACTIONS and matches(REVISION, revision), "Selected recovery source revision differs.")
    hashes = inputs.get("browser_hashes", "")
    require(isinstance(hashes, str) and len(hashes) <= 256, "Selected browser evidence exceeds its limit.")
    evidence = _parse_object(hashes or "{}", "Selected browser evidence is invalid.")
    require(set(evidence) == set(INPUT_LABELS[action]) and all(matches(DIGEST, value) for value in evidence.values()),
            "Selected browser evidence must contain the exact capability digests for this phase.")
    return action, cohort, source, evidence, revision


def validate_checkpoint(value, action, cohort, revision, identity, release):
    phase = PREVIOUS[action]
    require(isinstance(value, dict) and set(value) == {"version", "phase", "cohort", "revision", "identity", "releasePin",
            "afterReceiptId", "snapshots", "authEpoch", "receipts", "browserHashes", "linkIdentities", "tombstones",
            "groupReceipt", "tempReceipts"}
            and type(value["version"]) is int and value["version"] == 1
            and (value["phase"], value["cohort"], value["revision"], value["identity"], value["releasePin"]) ==
                (phase, cohort, revision, identity, release)
            and integer(value["afterReceiptId"], 0, MAX_ID) and matches(DIGEST, value["authEpoch"]),
            "Selected checkpoint identity, phase or active release differs.")
    snapshots = value["snapshots"]
    require(isinstance(snapshots, dict) and set(snapshots) == set(FIRST_SEEDS if phase == "prepared" else SEEDS),
            "Selected checkpoint snapshot inventory differs.")
    for row in snapshots.values():
        require(isinstance(row, dict) and set(row) == {"id", "snapshotId", "manifestSha256", "tokenSha256", "createdAt"}
                and integer(row["id"], 1, MAX_ID) and matches(UUID, row["snapshotId"])
                and matches(DIGEST, row["manifestSha256"]) and matches(DIGEST, row["tokenSha256"])
                and integer(row["createdAt"], 1, MAX_ID), "Selected checkpoint snapshot identity differs.")
    require(len({row["id"] for row in snapshots.values()}) == len(snapshots), "Selected checkpoint snapshot IDs overlap.")
    actions = PHASE_ACTIONS[phase]
    labels = {label for sequence in actions.values() for result, label in sequence if result == "issued"}
    for field in ("browserHashes", "linkIdentities"):
        require(isinstance(value[field], dict) and set(value[field]) == labels
                and all(matches(DIGEST, item) for item in value[field].values()), "Selected checkpoint capability evidence differs.")
    revoked = {label for sequence in actions.values() for result, label in sequence if result == "revoked"}
    require(isinstance(value["tombstones"], dict) and set(value["tombstones"]) == revoked
            and all(matches(DIGEST, item) for item in value["tombstones"].values()), "Selected checkpoint tombstones differ.")
    require(isinstance(value["receipts"], dict) and set(value["receipts"]) == set(ROLES),
            "Selected checkpoint owner receipts differ.")
    for role, sequence in actions.items():
        items = value["receipts"][role]
        require(isinstance(items, list) and len(items) == len(sequence) and all(matches(DIGEST, item) for item in items),
                "Selected checkpoint receipt evidence differs.")
    require((value["groupReceipt"] is None if phase == "prepared" else matches(DIGEST, value["groupReceipt"]))
            and isinstance(value["tempReceipts"], list) and len(value["tempReceipts"]) == (0 if phase == "prepared" else 1)
            and all(matches(DIGEST, item) for item in value["tempReceipts"]), "Selected checkpoint supporting receipt evidence differs.")


def derive_selected_code(encoded, policy, role, nonce, selected_ids):
    require(role in ROLES and canonical_nonce(nonce), "Selected capability nonce differs.")
    message = canonical(["subs-bot/telegram-aggregate/selected", 1, ORIGIN, policy["botId"], policy[ROLES[role]],
                         nonce, selected_ids])
    raw = hmac.new(key_bytes(encoded), message.encode("utf-8"), sha256).digest()[:16]
    return urlsafe_b64encode(raw).decode("ascii").rstrip("=")


class SelectedCohort(Cohort):
    # Inherit only the resource/query, object inventory and auth helpers. All
    # owner/fixture predicates below are specific to selected acceptance.
    def __init__(self, resources, policy, cohort, encoded, identity):
        super().__init__(resources, policy, cohort, encoded, identity)
        self.prefix = f"https://subs-bot-selected-fixtures.invalid/{cohort}/"
        self.name = f"CFSEL-{cohort}"
        provider_table = self.read("SELECT name FROM sqlite_schema WHERE type='table' AND name='telegram_provider_jobs'")
        require(provider_table in ([], [{"name": "telegram_provider_jobs"}]), "Selected provider queue schema differs.")
        self.has_telegram_provider_queue = bool(provider_table)

    def seed_identity(self, label):
        material = hmac.new(key_bytes(self.encoded), canonical(["subs-bot/selected-fixture/v1", self.identity,
            self.cohort, label]).encode(), sha256).digest()
        raw_uuid = bytearray(hmac.new(material, b"snapshot", sha256).digest()[:16])
        raw_uuid[6], raw_uuid[8] = (raw_uuid[6] & 15) | 128, (raw_uuid[8] & 63) | 128
        return material.hex(), str(UUIDValue(bytes=bytes(raw_uuid)))

    def fixture(self, label):
        term = f"{self.cohort}-Straße-AΣ"
        name = {
            "admin-name": f"CFSEL-{term} Name", "admin-url": self.name + "-source-only",
            "admin-miss": self.name + "-STRASSE-AΣ", "member-name": f"CFSEL-{term} Member",
            "admin-late": f"CFSEL-{term} Late",
        }[label]
        source = self.prefix + label + (f"/{term}" if label == "admin-url" else "")
        return self.actors[label.split("-", 1)[0]], name, source, self.seed_identity(label)[0]

    def node(self, label):
        server = f"203.0.113.{40 if label == 'temp' else 31 + SEEDS.index(label)}"
        name = f"{self.name}-{label}-node"
        password = "fixture" if label == "temp" else f"fixture-{label}"
        auth = urlsafe_b64encode(f"aes-256-gcm:{password}".encode()).decode().rstrip("=")
        return {"name": name, "type": "ss", "server": server, "port": 8388, "cipher": "aes-256-gcm",
                "password": password, "share": f"ss://{auth}@{server}:8388#{name}"}

    def subscriptions(self, ids=()):
        tokens = canonical([self.seed_identity(label)[0] for label in SEEDS])
        criteria = """substr(source_url,1,length(?))=? OR substr(name,1,length(?))=?
          OR token IN (SELECT value FROM json_each(?)) OR id IN (SELECT value FROM json_each(?))"""
        arguments = (self.prefix, self.prefix, self.name, self.name, tokens, canonical(list(ids)))
        rows = self.read(f"""SELECT {SUBSCRIPTION_FIELDS},0 AS trashed FROM subscriptions WHERE {criteria}
          UNION ALL SELECT {SUBSCRIPTION_FIELDS},1 AS trashed FROM subscription_trash WHERE {criteria} LIMIT 6""",
          *arguments, *arguments)
        sources = {self.fixture(label)[2]: label for label in SEEDS}
        result = {}
        for row in rows:
            label = sources.get(row.get("source_url"))
            require(label is not None and label not in result and row.get("trashed") == 0 and
                    tuple(row.get(field) for field in ("owner_id", "name", "source_url", "token")) == self.fixture(label)
                    and all(row.get(field) is None for field in ("expire_at", "traffic_used", "traffic_total", "last_error"))
                    and integer(row.get("id"), 1, MAX_ID) and integer(row.get("created_at"), 1, MAX_ID)
                    and row.get("created_at") == row.get("updated_at"), "Selected fixture identity differs.")
            require(tuple(row.get(field) for field in ("generation", "snapshot_id", "manifest_sha256", "node_count")) in
                    ((0, None, None, 0), (1, self.seed_identity(label)[1], digest(self.bodies(label)["manifest.json"]), 1)),
                    "Selected fixture snapshot pointer differs.")
            result[label] = row
        return result

    def quiet(self, ids, temp_id=0, active=(), *, assertion=False):
        bot, actors = self.policy["botId"], tuple(self.actors.values())
        known = canonical(list(ids))
        condition = """(SELECT CASE WHEN count(*)<=1 THEN coalesce(max(receipt_id),0) ELSE -1 END
          FROM telegram_temp_batch WHERE bot_id=? AND actor_id IN (?,?))=CAST(? AS INTEGER)
          AND NOT EXISTS(SELECT 1 FROM path_rules WHERE owner_id IN (?,?))
          AND NOT EXISTS(SELECT 1 FROM subscriptions WHERE owner_id IN (?,?) AND id NOT IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_jobs WHERE bot_id=? AND actor_id IN (?,?) AND state IN ('pending','leased'))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_reservations WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_stages WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_provider_jobs WHERE owner_id IN (?,?) AND state IN ('pending','leased'))
          AND NOT EXISTS(SELECT 1 FROM telegram_aggregate_slots WHERE bot_id=? AND actor_id IN (?,?) AND code_sha256 IS NOT NULL)
          AND NOT EXISTS(SELECT 1 FROM aggregate_links WHERE owner_id IN (?,?) AND revoked_at IS NULL
            AND (kind='selected' OR bot_id=?) AND code_sha256 NOT IN (SELECT value FROM json_each(?)))"""
        provider_params = ()
        if self.has_telegram_provider_queue:
            condition += " AND NOT EXISTS(SELECT 1 FROM telegram_provider_jobs WHERE owner_id IN (?,?) AND state IN ('pending','leased'))"
            provider_params = actors
        else:
            condition += " AND NOT EXISTS(SELECT 1 FROM sqlite_schema WHERE type='table' AND name='telegram_provider_jobs')"
        return statement(_assert_sql(condition) if assertion else "SELECT (" + condition + ") AS quiet",
            bot, *actors, temp_id, *actors, *actors, known, known, bot, *actors, known, known, *actors, bot, *actors, *actors, bot,
            canonical(list(active)), *provider_params)

    def require_quiet(self, ids, temp_id=0, active=()):
        check = self.quiet(ids, temp_id, active)
        require(self.read(check["sql"], *check["params"]) == [{"quiet": 1}], "Selected acceptance has unrelated or in-flight content.")

    def verify_pointers(self, current, pointers, *, absent=False):
        for label, pointer in pointers.items():
            row = current.get(label)
            require((row is None and absent) or (row is not None and not absent and row["generation"] == 1
                    and self.pointer(row, label) == pointer), "Selected fixture pointer changed after publication.")
            self.checked_objects(label, pointer, missing=absent)

    def stage(self, labels, pointers, guard, *, temp_id=0, active=()):
        ids = [item["id"] for item in pointers.values()]
        current = self.subscriptions(ids)
        known, final = set(pointers), set(pointers) | set(labels)
        require(set(current) in (known, final), "Selected preparation found a partial reservation.")
        self.verify_pointers(current, pointers)
        self.require_quiet([row["id"] for row in current.values()], temp_id, active)
        if set(current) == known:
            steps = [self.quiet(ids, temp_id, active, assertion=True)]
            steps.extend(exact_row(current[label]) for label in pointers)
            for label in labels:
                owner, name, source, token = self.fixture(label)
                steps.append(statement("""INSERT INTO subscriptions(owner_id,name,source_url,token,created_at,updated_at)
                  SELECT ?,?,?,?,unixepoch(),unixepoch() WHERE NOT EXISTS(SELECT 1 FROM subscription_trash WHERE token=?)""",
                    owner, name, source, token, token))
            steps.append(statement(_assert_sql("(SELECT count(*) FROM subscriptions WHERE substr(source_url,1,length(?))=?)=CAST(? AS INTEGER)"),
                                   self.prefix, self.prefix, len(final)))
            guarded_batch(self, steps, guard)
            current = self.subscriptions(ids)
            require(set(current) == final, "Selected fixture reservation could not be confirmed.")
        self.verify_pointers(current, pointers)
        published = {label: self.pointer(row, label) for label, row in current.items()}
        for label in labels:
            row, pointer = current[label], published[label]
            prefix, listed = self.list_objects(pointer)
            for name, body in self.bodies(label).items():
                key = prefix + name
                remote = self.resources.objects.request("GET", key)
                require((remote is None and key not in listed) or (remote == body and listed.get(key) == len(body)),
                        "Selected fixture R2 key is occupied.")
                if remote is None:
                    require(row["generation"] == 0, "A published selected fixture object is missing.")
                    guard()
                    present = self.resources.objects.request("GET", key)
                    require(present in (None, body), "Selected fixture R2 key is occupied.")
                    if present is None:
                        try:
                            self.resources.objects.request("PUT", key, body)
                        except (CapacityError, CloudflareError):
                            pass
                    require(self.resources.objects.request("GET", key) == body, "Selected fixture R2 upload could not be confirmed.")
            self.checked_objects(label, pointer)
        steps = [self.quiet([row["id"] for row in current.values()], temp_id, active, assertion=True)]
        steps.extend(exact_row(row) for row in current.values())
        for label in labels:
            pointer = published[label]
            steps.append(statement("""UPDATE subscriptions SET generation=1,snapshot_id=?,manifest_sha256=?,node_count=1
                WHERE id=? AND generation=0""", pointer["snapshotId"], pointer["manifestSha256"], pointer["id"]))
        guarded_batch(self, steps, guard)
        reread = self.subscriptions(item["id"] for item in published.values())
        require(set(reread) == final, "Selected publication inventory differs.")
        self.verify_pointers(reread, published)
        self.require_quiet([row["id"] for row in reread.values()], temp_id, active)
        return published


def exact_row(row):
    return statement(_assert_sql("""EXISTS(SELECT 1 FROM subscriptions WHERE id=? AND owner_id=? AND name=? AND source_url=? AND token=?
      AND created_at=? AND updated_at=? AND generation=? AND COALESCE(snapshot_id,'')=? AND COALESCE(manifest_sha256,'')=?
      AND node_count=? AND expire_at IS NULL AND traffic_used IS NULL AND traffic_total IS NULL AND last_error IS NULL)"""),
        *(row[field] for field in ("id", "owner_id", "name", "source_url", "token", "created_at", "updated_at", "generation")),
        row["snapshot_id"] or "", row["manifest_sha256"] or "", row["node_count"])


def guarded_batch(cohort, steps, guard):
    guard()
    try:
        cohort.batch(steps)
    except (CloudflareError, FixtureError):
        # All callers reconcile the complete exact D1 state before continuing.
        pass


SENT_FIELDS = "i.receipt_id,i.actor_id,i.chat_id,i.chat_type,i.thread_id,i.command,i.message_id,i.message_date," \
              "o.state,o.attempts,o.sent_message_id"


def sent(row, checkpoint, *, private=True):
    require(row["command"] == "help" and row["state"] == "sent" and integer(row["attempts"], 1, 4)
            and integer(row["receipt_id"], checkpoint["afterReceiptId"] + 1, MAX_ID)
            and all(integer(row[field], 1, MAX_ID) for field in ("message_id", "message_date", "sent_message_id"))
            and (not private or (row["chat_type"] == "private" and row["chat_id"] == row["actor_id"] and row["thread_id"] is None)),
            "Selected acceptance receipt scope or sent state differs.")


def row_digest(cohort, purpose, row):
    material = canonical(["subs-bot/selected-fixture-evidence/v1", cohort.identity, cohort.cohort, purpose,
                          dict(sorted(row.items()))])
    return hmac.new(key_bytes(cohort.encoded), material.encode("utf-8"), sha256).hexdigest()


def supporting_receipts(cohort, checkpoint, *, retired):
    bot, actors = cohort.policy["botId"], tuple(cohort.actors.values())
    common = (bot, *actors, checkpoint["afterReceiptId"])
    group = cohort.read(f"""SELECT {SENT_FIELDS},i.receipt_nonce
      FROM telegram_inbox AS i LEFT JOIN telegram_outbox AS o USING(receipt_id)
      WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER) AND i.chat_type<>'private'
      ORDER BY i.receipt_id LIMIT 2""", *common)
    require(len(group) == 1 and group[0]["actor_id"] == cohort.actors["admin"]
            and group[0]["chat_id"] == cohort.policy["groupId"] and group[0]["receipt_nonce"] is None,
            "Selected acceptance needs exactly one sent group control and no selected group receipt.")
    sent(group[0], checkpoint, private=False)
    group_hash = row_digest(cohort, "group-control", group[0])
    require(checkpoint["groupReceipt"] in (None, group_hash), "Selected group control receipt changed.")
    temp = cohort.read(f"""SELECT {SENT_FIELDS},t.kind,t.node_count,t.total_count,
      t.malformed_count,t.unsupported_count,t.ignored_count
      FROM telegram_inbox AS i LEFT JOIN telegram_temp_reply AS t USING(receipt_id)
      LEFT JOIN telegram_outbox AS o USING(receipt_id)
      WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER) AND i.receipt_nonce='temp:v1'
      ORDER BY i.receipt_id LIMIT 3""", *common)
    require([row["kind"] for row in temp] == (["added", "cleared"] if retired else ["added"]),
            "Selected acceptance needs exactly the synthetic paste and, at retirement, its real clear receipt.")
    for index, row in enumerate(temp):
        sent(row, checkpoint)
        require(row["actor_id"] == cohort.actors["admin"] and row["node_count"] == 1 and row["total_count"] == 1 - index
                and (row["malformed_count"], row["unsupported_count"], row["ignored_count"]) == (0, 0, 0),
                "Selected temporary-node receipt differs.")
    temp_hashes = [row_digest(cohort, "temporary-node", row) for row in temp]
    require(temp_hashes[:len(checkpoint["tempReceipts"])] == checkpoint["tempReceipts"], "Selected temporary-node history changed.")
    batches = cohort.read("""SELECT receipt_id,actor_id,message_date,message_id,nodes_json,node_count,payload_bytes
      FROM telegram_temp_batch WHERE bot_id=? AND actor_id IN (?,?) LIMIT 2""", bot, *actors)
    if retired:
        require(not batches, "Temporary nodes must be cleared in IAB before selected retirement.")
        fence = cohort.read("SELECT message_date,message_id FROM telegram_temp_clear_fence WHERE bot_id=? AND actor_id=?",
                            bot, cohort.actors["admin"])
        require(fence == [{field: temp[-1][field] for field in ("message_date", "message_id")}],
                "Selected temporary clear fence differs.")
    else:
        node = cohort.node("temp")
        raw = canonical([{field: node[field] for field in ("name", "type", "share")}])
        expected = {field: temp[0][field] for field in ("receipt_id", "actor_id", "message_date", "message_id")}
        expected.update(nodes_json=raw, node_count=1, payload_bytes=len(raw.encode("ascii")))
        require(batches == [expected], "Selected acceptance found an unexpected temporary payload.")
    return group_hash, temp_hashes, 0 if retired else temp[0]["receipt_id"]


def selected_receipts(cohort, checkpoint, actions, browser_hashes):
    rows = cohort.read(f"""SELECT {SENT_FIELDS},a.result,a.code_sha256,a.auth_message_date,a.auth_message_id
      FROM telegram_inbox AS i LEFT JOIN telegram_selected_actions AS a USING(receipt_id)
      LEFT JOIN telegram_outbox AS o USING(receipt_id)
      WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER) AND i.receipt_nonce=?
      ORDER BY i.receipt_id LIMIT 7""",
      cohort.policy["botId"], *cohort.actors.values(), checkpoint["afterReceiptId"], MARKER)
    require(cohort.auth() == checkpoint["authEpoch"], "Selected authorization epoch changed.")
    issued, revoked, history = {}, {}, {}
    for role, sequence in actions.items():
        owned = [row for row in rows if row["actor_id"] == cohort.actors[role]]
        require(len(owned) == len(sequence), "Selected command or callback count differs.")
        for row, (result, label) in zip(owned, sequence):
            sent(row, checkpoint)
            epoch = {"allowed": 1, "date": row["auth_message_date"], "message": row["auth_message_id"]}
            require((role == "admin" and (epoch["date"], epoch["message"]) == (0, 0)) or
                    (role == "member" and digest(canonical(epoch).encode()) == checkpoint["authEpoch"]),
                    "Selected command authorization epoch differs.")
            require(row["result"] == result and row["code_sha256"] == browser_hashes[label],
                    "Selected action result or browser capability digest differs.")
            (issued if result == "issued" else revoked)[label] = row
        history[role] = [row_digest(cohort, "selected-action", row) for row in owned]
        require(history[role][:len(checkpoint["receipts"][role])] == checkpoint["receipts"][role],
                "Selected receipt history changed.")
    require(len(rows) == len(issued) + len(revoked) and len(set(browser_hashes.values())) == len(issued),
            "Selected receipt or independent capability inventory differs.")
    for label, row in revoked.items():
        require(row["receipt_id"] > issued[label]["receipt_id"] and row["message_id"] == issued[label]["sent_message_id"],
                "Selected revocation is not tied to its original sent IAB button.")
    return history, issued, revoked


def verify_links(cohort, checkpoint, issued, revoked, probe, *, minimum_ticket_seconds=0):
    codes = [row["code_sha256"] for row in issued.values()]
    rows = cohort.read("""SELECT selected.code_sha256,selected.bot_id,selected.actor_id,selected.origin_receipt_id,
      selected.nonce,selected.key_version,selected.generations,link.owner_id,link.kind,link.bot_id AS link_bot_id,
      link.selected_ids,link.created_at,link.revoked_at
      FROM telegram_selected_links AS selected JOIN aggregate_links AS link USING(code_sha256)
      WHERE selected.code_sha256 IN (SELECT value FROM json_each(?)) LIMIT 4""", canonical(codes))
    require(len(rows) == len(issued), "Selected capability companion inventory differs.")
    indexed = {row["code_sha256"]: row for row in rows}
    report, identities, tombstones = {}, {}, {}
    for label, receipt in issued.items():
        row = indexed[receipt["code_sha256"]]
        ids = [checkpoint["snapshots"][fixture]["id"] for fixture in MEMBERS[label]]
        require(ids == sorted(ids) and row["selected_ids"] == canonical(ids)
                and row["generations"] == canonical([[item, 1, 0] for item in ids]), "Selected fixed membership differs.")
        active = label not in revoked
        require((row["bot_id"], row["actor_id"], row["owner_id"], row["kind"], row["link_bot_id"], row["origin_receipt_id"],
                 row["key_version"]) == (cohort.policy["botId"], receipt["actor_id"], receipt["actor_id"], "selected", None,
                                         receipt["receipt_id"], 1)
                and integer(row["created_at"], 1, MAX_ID)
                and (row["revoked_at"] is None if active else integer(row["revoked_at"], row["created_at"], MAX_ID)),
                "Selected capability ownership or revocation differs.")
        tickets = cohort.read("""SELECT origin_receipt_id,origin_attempt,used_by_receipt_id,expires_at-unixepoch() AS seconds
          FROM telegram_selected_revoke_ticket WHERE code_sha256=? LIMIT 2""", row["code_sha256"])
        if active:
            require(len(tickets) == 1 and integer(tickets[0]["seconds"], max(1, minimum_ticket_seconds), 600),
                    "Selected IAB ticket expired or has too little time left. Pause this cohort without cleanup.")
        else:
            # Cron can remove expired tickets. The callback's exact original
            # message link remains verifiable from the durable receipt.
            require(len(tickets) <= 1, "Selected revoked ticket inventory differs.")
        if tickets:
            ticket = tickets[0]
            require((ticket["origin_receipt_id"], ticket["origin_attempt"], ticket["used_by_receipt_id"]) ==
                    (receipt["receipt_id"], receipt["attempts"], None if active else revoked[label]["receipt_id"]),
                    "Selected ticket origin or single consumption differs.")
        code = derive_selected_code(cohort.encoded, cohort.policy, label.split("-", 1)[0], row["nonce"], row["selected_ids"])
        require(digest(code.encode("ascii")) == row["code_sha256"], "Selected browser and derived capability digests differ.")
        identity = row_digest(cohort, "selected-link", {key: value for key, value in row.items() if key != "revoked_at"})
        require(checkpoint["linkIdentities"].get(label, identity) == identity, "Selected link history changed.")
        identities[label] = identity
        if not active:
            tombstones[label] = row_digest(cohort, "selected-tombstone", row)
            require(checkpoint["tombstones"].get(label, tombstones[label]) == tombstones[label],
                    "Selected revocation tombstone changed.")
        if probe is not None:
            exports = expected_fixture_exports([cohort.node(fixture) for fixture in MEMBERS[label]])
            report[label] = probe(code, row["code_sha256"], exports, label, active=active)
    return identities, tombstones, report


def prepare(cohort, revision, release, guard):
    auth = cohort.auth()
    rows = cohort.read("SELECT COALESCE(max(receipt_id),0) AS highWater FROM telegram_inbox")
    require(len(rows) == 1 and integer(rows[0]["highWater"], 0, MAX_ID), "Selected receipt watermark differs.")
    snapshots = cohort.stage(FIRST_SEEDS, {}, guard)
    require(cohort.auth() == auth, "Selected authorization changed during preparation.")
    return {"version": 1, "phase": "prepared", "cohort": cohort.cohort, "revision": revision, "identity": cohort.identity,
            "releasePin": dict(release), "afterReceiptId": rows[0]["highWater"], "snapshots": snapshots, "authEpoch": auth,
            "receipts": {role: [] for role in ROLES}, "browserHashes": {}, "linkIdentities": {}, "groupReceipt": None,
            "tempReceipts": [], "tombstones": {}}


def capture(cohort, checkpoint, action, hashes, guard, probe=probe_fixture_exports):
    first = action == "capture-first-and-extend"
    history, hashes, issued, revoked, group, temp, temp_id = evidence(cohort, checkpoint, hashes,
        FIRST_ACTIONS if first else INDEPENDENT_ACTIONS, retired=False)
    active = [row["code_sha256"] for label, row in issued.items() if label not in revoked]
    pointers = checkpoint["snapshots"]
    current = cohort.subscriptions(item["id"] for item in pointers.values())
    expected = set(pointers)
    require(set(current) == expected or (first and set(current) == expected | {"admin-late"}), "Selected snapshot inventory differs.")
    cohort.require_quiet([row["id"] for row in current.values()], temp_id, active)
    cohort.verify_pointers(current, pointers)
    identities, tombstones, report = verify_links(cohort, checkpoint, issued, revoked, probe, minimum_ticket_seconds=30)
    if first:
        pointers = cohort.stage(("admin-late",), pointers, guard, temp_id=temp_id, active=active)
        _, _, unchanged = verify_links(cohort, {**checkpoint, "linkIdentities": identities}, issued, revoked, probe)
        require(unchanged == report, "Selected original export changed after a new matching subscription.")
    require(evidence(cohort, checkpoint, hashes, FIRST_ACTIONS if first else INDEPENDENT_ACTIONS, retired=False)
            == (history, hashes, issued, revoked, group, temp, temp_id), "Selected Telegram evidence changed during capture.")
    current = cohort.subscriptions(item["id"] for item in pointers.values())
    require(set(current) == set(pointers), "Selected snapshot inventory changed during capture.")
    cohort.require_quiet([row["id"] for row in current.values()], temp_id, active)
    cohort.verify_pointers(current, pointers)
    verify_links(cohort, {**checkpoint, "linkIdentities": identities, "tombstones": tombstones}, issued, revoked, None,
                 minimum_ticket_seconds=30)
    return {**checkpoint, "phase": "extended" if first else "independent", "snapshots": pointers, "receipts": history,
            "browserHashes": hashes, "linkIdentities": identities, "groupReceipt": group, "tempReceipts": temp,
            "tombstones": tombstones}, report


def evidence(cohort, checkpoint, new_hashes, actions, *, retired):
    hashes = {**checkpoint["browserHashes"], **new_hashes}
    history, issued, revoked = selected_receipts(cohort, checkpoint, actions, hashes)
    group, temp, temp_id = supporting_receipts(cohort, checkpoint, retired=retired)
    return history, hashes, issued, revoked, group, temp, temp_id


def retire(cohort, checkpoint, guard, probe=probe_fixture_exports):
    facts = evidence(cohort, checkpoint, {}, FINAL_ACTIONS, retired=True)
    history, _, issued, revoked, group, temp, _ = facts
    identities, tombstones, report = verify_links(cohort, checkpoint, issued, revoked, probe)
    pointers = checkpoint["snapshots"]
    ids = [item["id"] for item in pointers.values()]
    current = cohort.subscriptions(ids)
    require(not current or set(current) == set(pointers), "Selected retirement found a partial D1 cohort.")
    cohort.require_quiet(ids)
    cohort.verify_pointers(current, pointers, absent=not current)
    if current:
        steps = [cohort.quiet(ids, assertion=True)]
        codes = canonical([row["code_sha256"] for row in revoked.values()])
        steps.append(statement(_assert_sql("""(SELECT count(*) FROM aggregate_links WHERE kind='selected' AND revoked_at IS NOT NULL
          AND code_sha256 IN (SELECT value FROM json_each(?)))=3"""), codes))
        steps.extend(exact_row(row) for row in current.values())
        steps.append(statement("DELETE FROM subscriptions WHERE id IN (SELECT value FROM json_each(?))", canonical(ids)))
        steps.append(statement(_assert_sql("NOT EXISTS(SELECT 1 FROM subscriptions WHERE id IN (SELECT value FROM json_each(?)))"),
                               canonical(ids)))
        guarded_batch(cohort, steps, guard)
    require(not cohort.subscriptions(ids), "Selected D1 retirement could not be confirmed.")
    cohort.require_quiet(ids)
    retire_objects(cohort, pointers, guard)
    require(not cohort.subscriptions(ids) and evidence(cohort, checkpoint, {}, FINAL_ACTIONS, retired=True) == facts,
            "Selected retirement changed receipt evidence.")
    require(verify_links(cohort, checkpoint, issued, revoked, None)[:2] == (identities, tombstones),
            "Selected retirement changed link tombstones.")
    return {**checkpoint, "phase": "retired", "receipts": history, "groupReceipt": group, "tempReceipts": temp,
            "tombstones": tombstones}, report


def retire_objects(cohort, pointers, guard, retained=()):
    for label, pointer in pointers.items():
        prefix = cohort.checked_objects(label, pointer, missing=True)
        if label in retained:
            # An unpublished reservation can still have a delayed PUT. Never
            # certify absence or delete anything on that uncertain prefix.
            continue
        for name, body in cohort.bodies(label).items():
            key = prefix + name
            guard()
            remote = cohort.resources.objects.request("GET", key)
            require(remote in (None, body), "Selected retirement found an unexpected R2 object.")
            if remote is None:
                continue
            try:
                cohort.resources.objects.request("DELETE", key)
            except (CapacityError, CloudflareError):
                pass
            require(cohort.resources.objects.request("GET", key) is None, "Selected R2 retirement could not be confirmed.")
        require(not cohort.list_objects(pointer)[1], "Selected retired object inventory differs.")


def abort_history(cohort, checkpoint):
    bot, actors = cohort.policy["botId"], tuple(cohort.actors.values())
    rows = cohort.read(f"""SELECT {SENT_FIELDS},i.receipt_nonce FROM telegram_inbox AS i
      LEFT JOIN telegram_outbox AS o USING(receipt_id)
      WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER)
      ORDER BY i.receipt_id LIMIT 17""", bot, *actors, checkpoint["afterReceiptId"])
    require(len(rows) <= 16 and all(row["state"] in ("sent", "failed", "uncertain") for row in rows),
            "Selected recovery requires settled cohort replies.")
    temp = cohort.read(f"""SELECT {SENT_FIELDS},t.kind,t.node_count,t.total_count,t.malformed_count,t.unsupported_count,t.ignored_count
      FROM telegram_inbox AS i JOIN telegram_temp_reply AS t USING(receipt_id) JOIN telegram_outbox AS o USING(receipt_id)
      WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER) AND i.receipt_nonce='temp:v1'
      ORDER BY i.receipt_id LIMIT 3""", bot, *actors, checkpoint["afterReceiptId"])
    require([row["kind"] for row in temp] in ([], ["added", "cleared"]),
            "Clear the exact temporary fixture in IAB before selected recovery.")
    if temp:
        for index, row in enumerate(temp):
            sent(row, checkpoint)
            require(row["actor_id"] == cohort.actors["admin"] and (row["node_count"], row["total_count"]) == (1, 1 - index)
                    and (row["malformed_count"], row["unsupported_count"], row["ignored_count"]) == (0, 0, 0),
                    "Selected recovery temporary receipts differ.")
        fence = cohort.read("SELECT message_date,message_id FROM telegram_temp_clear_fence WHERE bot_id=? AND actor_id=?", bot, cohort.actors["admin"])
        require(fence == [{field: temp[-1][field] for field in ("message_date", "message_id")}],
                "Selected recovery temporary clear fence differs.")
    temp_hashes = [row_digest(cohort, "temporary-node", row) for row in temp]
    require(temp_hashes[:len(checkpoint["tempReceipts"])] == checkpoint["tempReceipts"], "Selected recovery temporary history differs.")
    actions = cohort.read(f"""SELECT {SENT_FIELDS},a.result,a.code_sha256,a.auth_message_date,a.auth_message_id
      FROM telegram_inbox AS i LEFT JOIN telegram_selected_actions AS a USING(receipt_id)
      LEFT JOIN telegram_outbox AS o USING(receipt_id) WHERE i.bot_id=? AND i.actor_id IN (?,?)
      AND i.receipt_id>CAST(? AS INTEGER) AND i.receipt_nonce=? ORDER BY i.receipt_id LIMIT 9""",
      bot, *actors, checkpoint["afterReceiptId"], MARKER)
    require(len(actions) <= 8 and all(row["result"] is not None for row in actions), "Selected recovery action inventory differs.")
    for role, previous in checkpoint["receipts"].items():
        actual = [row_digest(cohort, "selected-action", row) for row in actions if row["actor_id"] == cohort.actors[role]]
        require(actual[:len(previous)] == previous, "Selected recovery changed previously verified action evidence.")
    return row_digest(cohort, "abort-history", {"inbox": rows, "actions": actions, "temp": temp_hashes})


LINK_FIELDS = ("code_sha256", "bot_id", "actor_id", "origin_receipt_id", "nonce", "key_version", "generations",
               "owner_id", "kind", "link_bot_id", "selected_ids", "created_at", "revoked_at")


def abort_links(cohort, checkpoint, pointers):
    rows = cohort.read("""SELECT selected.code_sha256,selected.bot_id,selected.actor_id,selected.origin_receipt_id,
      selected.nonce,selected.key_version,selected.generations,link.owner_id,link.kind,link.bot_id AS link_bot_id,
      link.selected_ids,link.created_at,link.revoked_at,i.actor_id AS receipt_actor,i.bot_id AS receipt_bot,
      i.chat_id,i.chat_type,i.thread_id,i.command,i.receipt_nonce,o.state,a.result,a.code_sha256 AS action_code
      FROM telegram_selected_links AS selected JOIN aggregate_links AS link USING(code_sha256)
      JOIN telegram_inbox AS i ON i.receipt_id=selected.origin_receipt_id
      LEFT JOIN telegram_outbox AS o ON o.receipt_id=i.receipt_id LEFT JOIN telegram_selected_actions AS a ON a.receipt_id=i.receipt_id
      WHERE selected.bot_id=? AND selected.actor_id IN (?,?) AND selected.origin_receipt_id>CAST(? AS INTEGER)
      ORDER BY selected.origin_receipt_id LIMIT 4""", cohort.policy["botId"], *cohort.actors.values(), checkpoint["afterReceiptId"])
    require(len(rows) <= 3, "Selected recovery found extra capabilities.")
    result = {}
    for row in rows:
        matched = []
        for label, fixtures in MEMBERS.items():
            if all(fixture in pointers for fixture in fixtures) and row["actor_id"] == cohort.actors[label.split("-", 1)[0]]:
                ids = [pointers[fixture]["id"] for fixture in fixtures]
                if row["selected_ids"] == canonical(ids) and row["generations"] == canonical([[item, 1, 0] for item in ids]):
                    matched.append(label)
        require(len(matched) == 1 and matched[0] not in result, "Selected recovery capability membership differs.")
        label = matched[0]
        require(row["actor_id"] == row["receipt_actor"] == row["owner_id"] == row["chat_id"]
                and row["bot_id"] == row["receipt_bot"] == cohort.policy["botId"]
                and (row["kind"], row["link_bot_id"], row["chat_type"], row["thread_id"], row["command"], row["receipt_nonce"], row["key_version"])
                    == ("selected", None, "private", None, "help", MARKER, 1)
                and row["state"] in ("sent", "failed", "uncertain") and integer(row["created_at"], 1, MAX_ID)
                and (row["revoked_at"] is None or integer(row["revoked_at"], row["created_at"], MAX_ID))
                and ((row["result"] == "issued" and row["action_code"] == row["code_sha256"])
                     or (row["result"] == "stale" and row["action_code"] is None and row["revoked_at"] is not None)),
                "Selected recovery capability or origin receipt differs.")
        code = derive_selected_code(cohort.encoded, cohort.policy, label.split("-", 1)[0], row["nonce"], row["selected_ids"])
        require(digest(code.encode("ascii")) == row["code_sha256"], "Selected recovery capability digest differs.")
        facts = {name: row[name] for name in LINK_FIELDS}
        identity = row_digest(cohort, "selected-link", {name: value for name, value in facts.items() if name != "revoked_at"})
        tombstone = None if row["revoked_at"] is None else row_digest(cohort, "selected-tombstone", facts)
        require(checkpoint["linkIdentities"].get(label, identity) == identity
                and checkpoint["tombstones"].get(label, tombstone) == tombstone, "Selected recovery changed previously verified link evidence.")
        result[label] = (facts, code, {"sha256": row["code_sha256"], "identity": identity, "tombstone": tombstone})
    require(set(checkpoint["linkIdentities"]) <= set(result), "Selected recovery lost a verified link.")
    return result


def validate_abort_source(checkpoint, cohort, source_revision):
    require(isinstance(checkpoint, dict) and checkpoint.get("phase") in PHASE_ACTIONS, "Selected recovery needs a successful normal checkpoint.")
    release = checkpoint.get("releasePin")
    validate_release_pin(release)
    require(release["revision"] == source_revision, "Selected recovery source release differs.")
    action = next(action for action, phase in PREVIOUS.items() if phase == checkpoint["phase"])
    validate_checkpoint(checkpoint, action, cohort.cohort, source_revision, cohort.identity, release)


def prepare_abort(cohort, checkpoint, source_revision, release):
    validate_abort_source(checkpoint, cohort, source_revision)
    original = checkpoint["snapshots"]
    current = cohort.subscriptions(item["id"] for item in original.values())
    require(set(current) in (set(original), set(original) | {"admin-late"}), "Selected recovery fixture inventory differs.")
    cohort.verify_pointers(current, original)
    pointers = dict(original)
    retained = []
    if "admin-late" not in original and "admin-late" in current:
        row = current["admin-late"]
        pointers["admin-late"] = cohort.pointer(row, "admin-late")
        if row["generation"] == 0:
            retained.append("admin-late")
        cohort.checked_objects("admin-late", pointers["admin-late"], missing=bool(retained))
    links = abort_links(cohort, checkpoint, pointers)
    require(not retained or "admin-second" not in links, "An unpublished selected fixture cannot have an issued capability.")
    cohort.require_quiet([item["id"] for item in pointers.values()], active=[row["code_sha256"] for row, _, _ in links.values()])
    return {"version": 1, "phase": "abort-ready", "sourceCheckpoint": checkpoint, "abortPreparedAtReleasePin": release,
            "snapshots": pointers, "retainedSnapshots": retained, "links": {label: pin for label, (_, _, pin) in links.items()},
            "receiptEvidence": abort_history(cohort, checkpoint)}


def assert_abort_link(row):
    return statement(_assert_sql("""EXISTS(SELECT 1 FROM aggregate_links AS link JOIN telegram_selected_links AS selected USING(code_sha256)
      WHERE code_sha256=? AND link.owner_id=? AND link.kind='selected' AND link.bot_id IS NULL AND link.selected_ids=?
      AND link.created_at=? AND COALESCE(link.revoked_at,0)=CAST(? AS INTEGER) AND selected.bot_id=? AND selected.actor_id=?
      AND selected.origin_receipt_id=? AND selected.nonce=? AND selected.key_version=1 AND selected.generations=?)"""),
      row["code_sha256"], row["owner_id"], row["selected_ids"], row["created_at"], row["revoked_at"] or 0,
      row["bot_id"], row["actor_id"], row["origin_receipt_id"], row["nonce"], row["generations"])


def abort_retire(cohort, ready, source_revision, release, guard, probe=probe_fixture_exports):
    require(isinstance(ready, dict) and set(ready) == {"version", "phase", "sourceCheckpoint", "abortPreparedAtReleasePin",
            "snapshots", "retainedSnapshots", "links", "receiptEvidence"} and (ready["version"], ready["phase"]) == (1, "abort-ready"),
            "Selected recovery requires a successful abort preparation checkpoint.")
    validate_release_pin(ready["abortPreparedAtReleasePin"])
    require(ready["abortPreparedAtReleasePin"]["revision"] == source_revision, "Selected abort checkpoint release differs.")
    checkpoint = ready["sourceCheckpoint"]
    validate_abort_source(checkpoint, cohort, checkpoint["revision"])
    pointers, retained = ready["snapshots"], ready["retainedSnapshots"]
    original = checkpoint["snapshots"]
    require(isinstance(pointers, dict) and set(pointers) in (set(original), set(original) | {"admin-late"})
            and all(pointers[label] == item for label, item in original.items()) and retained in ([], ["admin-late"])
            and (not retained or "admin-late" in pointers and "admin-late" not in original), "Selected abort checkpoint pointers differ.")
    for label, pointer in pointers.items():
        token, snapshot = cohort.seed_identity(label)
        require(isinstance(pointer, dict) and set(pointer) == {"id", "snapshotId", "manifestSha256", "tokenSha256", "createdAt"}
                and integer(pointer["id"], 1, MAX_ID) and integer(pointer["createdAt"], 1, MAX_ID)
                and pointer["snapshotId"] == snapshot and pointer["tokenSha256"] == digest(token.encode("ascii"))
                and pointer["manifestSha256"] == digest(cohort.bodies(label)["manifest.json"]), "Selected abort checkpoint identity differs.")
    ids = [item["id"] for item in pointers.values()]
    require(len(set(ids)) == len(ids), "Selected abort checkpoint IDs overlap.")
    require(abort_history(cohort, checkpoint) == ready["receiptEvidence"], "Selected recovery receipt evidence changed.")
    links = abort_links(cohort, checkpoint, pointers)
    pins = ready["links"]
    require(isinstance(pins, dict) and set(pins) == set(links), "Selected abort checkpoint link inventory differs.")
    for label, (_, _, pin) in links.items():
        require(isinstance(pins[label], dict) and set(pins[label]) == set(pin)
                and pins[label]["sha256"] == pin["sha256"] and pins[label]["identity"] == pin["identity"]
                and pins[label]["tombstone"] in (None, pin["tombstone"]), "Selected abort checkpoint link identity differs.")
    active = [row["code_sha256"] for row, _, _ in links.values() if row["revoked_at"] is None]
    current = cohort.subscriptions(ids)
    require(not current or set(current) == set(pointers), "Selected recovery found a partial D1 cohort.")
    cohort.require_quiet(ids, active=active)
    for label, pointer in pointers.items():
        if current:
            row = current[label]
            require(cohort.pointer(row, label) == pointer and row["generation"] == (0 if label in retained else 1),
                    "Selected recovery fixture pointer changed.")
        cohort.checked_objects(label, pointer, missing=not current or label in retained)
    if current:
        steps = [cohort.quiet(ids, active=active, assertion=True), statement(_assert_sql("""NOT EXISTS(SELECT 1
          FROM telegram_inbox AS i LEFT JOIN telegram_outbox AS o USING(receipt_id)
          WHERE i.bot_id=? AND i.actor_id IN (?,?) AND i.receipt_id>CAST(? AS INTEGER)
          AND (o.state IS NULL OR o.state NOT IN ('sent','failed','uncertain')))"""),
          cohort.policy["botId"], *cohort.actors.values(), checkpoint["afterReceiptId"])]
        steps.extend(exact_row(row) for row in current.values())
        steps.extend(assert_abort_link(row) for row, _, _ in links.values())
        steps.append(statement("UPDATE aggregate_links SET revoked_at=MAX(created_at,unixepoch()) WHERE revoked_at IS NULL AND code_sha256 IN (SELECT value FROM json_each(?))", canonical(active)))
        steps.append(statement("DELETE FROM subscriptions WHERE id IN (SELECT value FROM json_each(?))", canonical(ids)))
        guarded_batch(cohort, steps, guard)
    require(not cohort.subscriptions(ids), "Selected recovery D1 retirement could not be confirmed.")
    cohort.require_quiet(ids)
    after = abort_links(cohort, checkpoint, pointers)
    require(set(after) == set(links), "Selected recovery link inventory changed.")
    report = {}
    for label, (_, code, pin) in after.items():
        before = links[label][2]
        require(pin["identity"] == before["identity"] and pin["tombstone"] is not None
                and before["tombstone"] in (None, pin["tombstone"]), "Selected recovery revocation could not be confirmed.")
        exports = expected_fixture_exports([cohort.node(fixture) for fixture in MEMBERS[label]])
        report[label] = probe(code, pin["sha256"], exports, label, active=False)
    retire_objects(cohort, pointers, guard, retained)
    require(not cohort.subscriptions(ids) and abort_history(cohort, checkpoint) == ready["receiptEvidence"]
            and abort_links(cohort, checkpoint, pointers) == after, "Selected recovery changed retained evidence.")
    return {**ready, "phase": "aborted", "retiredAtReleasePin": release,
            "tombstones": {label: pin["tombstone"] for label, (_, _, pin) in after.items()}}, report


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "Selected acceptance requires a trusted manual main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        body = event.read(65537)
    require(len(body) <= 65536, "Selected workflow event exceeds the limit.")
    action, key, source_run, hashes, source_revision = parse_inputs(_parse_object(body, "Selected workflow event differs."))
    require_current_main(revision)
    source_revision = source_revision or revision
    previous = read_checkpoint(source_run, source_revision, os.environ["GH_TOKEN"], workflow_file=WORKFLOW,
                               artifact_prefix=ARTIFACT_PREFIX, checkpoint_file=CHECKPOINT) if source_run else None
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy = json.loads(raw_policy)
    encoded = os.environ.get("SUBS_BOT_TELEGRAM_AGGREGATE_KEY", "")
    key_bytes(encoded)
    target = _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), "Selected resource configuration differs.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped Cloudflare credentials are required.")
    data = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), data, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    release = {"revision": version.revision, "versionId": active.version, "moduleSha256": version.digest,
               "compatibilityDate": version.compatibility}
    validate_release_pin(release)
    policy_sha, key_sha = digest(raw_policy.encode("utf-8")), digest(encoded.encode("ascii"))
    require(scope.cron_enabled() and version.revision == revision and version.telegram_config_sha256 == policy_sha
            and version.telegram_aggregate_key_sha256 == key_sha, "Active Worker, Telegram policy, or aggregate key differs.")
    _verify_health(revision)
    resources = Resources(target, data, SnapshotObjects(target["accountId"], data_token))
    identity = digest(f"{resources.scope_hash}/{policy_sha}/{key_sha}".encode("ascii"))
    expected = digest((Path(__file__).resolve().parents[1] / "migrations" / MIGRATION).read_bytes())
    require(resources.query("SELECT position,sha256,mode FROM subs_bot_schema_migrations WHERE name=?", (MIGRATION,))
            == [{"position": 17, "sha256": expected, "mode": "applied"}], "Selected migration proof differs.")

    def guard():
        require(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version
                and scope.cron_enabled(), "Isolation release changed during selected acceptance.")
        if action in ABORT_ACTIONS:
            scope.verify_resources()
        require_current_main(revision)

    cohort = SelectedCohort(resources, policy, key, encoded, identity)
    report = {}
    if previous is None:
        checkpoint = prepare(cohort, revision, release, guard)
    elif action == "prepare-abort":
        checkpoint = prepare_abort(cohort, previous, source_revision, release)
    elif action == "abort-retire":
        checkpoint, report = abort_retire(cohort, previous, source_revision, release, guard)
    else:
        validate_checkpoint(previous, action, key, revision, identity, release)
        if action == "retire":
            checkpoint, report = retire(cohort, previous, guard)
        else:
            checkpoint, report = capture(cohort, previous, action, hashes, guard)
    guard()
    scope.verify_resources()
    _verify_health(revision)
    save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, checkpoint)
    result = {"phase": checkpoint["phase"], "snapshotCount": len(checkpoint["snapshots"]), "exportEvidence": report}
    if action in ABORT_ACTIONS:
        retained = len(checkpoint["retainedSnapshots"])
        result.update(capabilityCount=len(checkpoint["links"]), unresolvedSnapshotCount=retained,
                      verifiedAbsentObjectCount=2 * (len(checkpoint["snapshots"]) - retained) if action == "abort-retire" else 0)
    else:
        result.update(sentSelectedReceiptCount=sum(len(items) for items in checkpoint["receipts"].values()),
                      capabilityCount=len(checkpoint["browserHashes"]), verifiedAbsentObjectCount=10 if action == "retire" else 0)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CapacityError, CloudflareError, FixtureError, ProbeError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram selected checkpoint could not be verified.")

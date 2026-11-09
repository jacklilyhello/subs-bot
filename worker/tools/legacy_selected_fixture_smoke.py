"""Protected D1/R2 fixture checkpoints for the legacy selected HTTP smoke."""

from base64 import urlsafe_b64encode
from contextlib import contextmanager
from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import sys
from time import sleep
from uuid import UUID as UUIDValue

from capacity_resources import CapacityError, Resources, integer, matches, save_private_json
from cloudflare_isolation import CloudflareClient, CloudflareError, REVISION, WORKER_NAME, _Isolation, _verify_health
from d1_migrations import _assert_sql
from legacy_empty_export_smoke import MIGRATION as EMPTY_MIGRATION, MIGRATION_SHA256 as EMPTY_SHA
from legacy_selected_http_smoke import LINKS, fixture_node, verify_legacy_selected_http
from native_restore_rehearsal import COHORT, RehearsalAPI
from prepare_isolation_artifact import MAIN_REF, REPOSITORY, _get_json, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import (
    DECIMAL, MAX_ID, SUBSCRIPTION_FIELDS, SnapshotObjects, canonical, digest, key_bytes,
    read_checkpoint, require, validate_release_pin,
)
from telegram_bulk_trash_smoke import snapshot_assert
from telegram_view_fixtures import FixtureError, query, statement


WORKFLOW = "worker-isolation-legacy-selected-smoke.yml"
ARTIFACT = "subs-bot-legacy-selected-smoke"
CHECKPOINT = "legacy-selected-checkpoint.json"
ERROR = "The isolated legacy selected fixture could not be verified."
OWNER = "9223372036854775807"
LABELS = ("alpha", "beta", "empty")
SNAPSHOTS = LABELS[:2]
CLEAN_INTENTS = ("--", "--")
INTENT_PREFIX = "legacy-selected-r2:v1:"
INTENT = re.compile(re.escape(INTENT_PREFIX) + r"([-ac]{2})")
PHASES = {"prepare": "prepared", "reserve": "reserved", "verify": "verified", "retire": "retired"}
PREDECESSORS = {"reserve": {"prepared"}, "verify": {"reserved"},
                "retire": {"prepared", "reserved", "verified"}}
FIELDS = {
    "subscriptions": tuple(SUBSCRIPTION_FIELDS.split(",")),
    "aggregates": ("code_sha256", "owner_id", "kind", "bot_id", "selected_ids", "created_at", "revoked_at"),
    "markers": ("code_sha256",), "watches": ("id", "retired"),
    "empty": ("subscription_id", "owner_id", "token_sha256"),
}


class UnconfirmedPut(FixtureError):
    def __init__(self):
        super().__init__("An armed isolated fixture PUT remains unconfirmed.")


@contextmanager
def phase(label):
    try:
        yield
    except UnconfirmedPut:
        raise
    except Exception:
        raise FixtureError(f"{ERROR} Failed phase {label}.") from None


def inputs(payload):
    value = payload.get("inputs")
    require(isinstance(value, dict) and set(value) <= {"action", "cohort", "source_run_id", "confirm_retire"}, ERROR)
    action, cohort = value.get("action"), value.get("cohort")
    source, confirm = value.get("source_run_id", ""), value.get("confirm_retire", "")
    require(isinstance(action, str) and action in PHASES and matches(COHORT, cohort)
            and (source == "" if action == "prepare" else matches(DECIMAL, source))
            and confirm == (f"retire {cohort}" if action == "retire" else ""), ERROR)
    return action, cohort, source


def allocator(resources):
    [row] = resources.query("""SELECT COALESCE((SELECT max(seq) FROM sqlite_sequence WHERE name='subscriptions'),0) AS seq,
        (SELECT count(*) FROM sqlite_sequence WHERE name='subscriptions') AS entries,
        COALESCE((SELECT max(id) FROM subscriptions),0) AS activeMax,
        COALESCE((SELECT max(id) FROM subscription_trash),0) AS trashMax,unixepoch() AS now""", ())
    require(integer(row["seq"], 0, MAX_ID) and integer(row["entries"], 0, 1)
            and all(integer(row[key], 0, row["seq"]) for key in ("activeMax", "trashMax"))
            and integer(row["now"], 1, MAX_ID - 1800), ERROR)
    return row["seq"], row["now"]


def validate_checkpoint(value, action, cohort, revision, identity, release_pin):
    fields = {"version", "phase", "cohort", "identity", "revision", "releasePin", "highWater", "createdAt", "reserveUntil"}
    require(isinstance(value, dict) and set(value) == fields
            and type(value["version"]) is int and value["version"] == 1 and value["cohort"] == cohort
            and value["identity"] == identity and value["revision"] == revision
            and integer(value["highWater"], 0, MAX_ID - len(LABELS)) and integer(value["createdAt"], 1, MAX_ID - 1800)
            and integer(value["reserveUntil"], value["createdAt"] + 1800, value["createdAt"] + 1800), ERROR)
    validate_release_pin(value["releasePin"])
    require(value["phase"] in PREDECESSORS[action] and value["releasePin"]["revision"] == revision
            and (action == "retire" or value["releasePin"] == release_pin), ERROR)


class Cohort:
    def __init__(self, resources, listing, checkpoint, key):
        self.resources, self.listing, self.checkpoint = resources, listing, checkpoint
        self.ids = {label: checkpoint["highWater"] + offset for offset, label in enumerate(LABELS, 1)}
        self.stamp = checkpoint["createdAt"]
        self.name = "legacy-selected-fixture-" + checkpoint["cohort"]
        self.sources = {label: f"https://subs-bot-legacy-selected-fixtures.invalid/{checkpoint['cohort']}/{label}"
                        for label in LABELS}

        def material(purpose, label):
            scope = canonical(["subs-bot/legacy-selected-fixture/v1", checkpoint["identity"], checkpoint["cohort"],
                               checkpoint["highWater"], self.stamp, purpose, label]).encode("ascii")
            return hmac.digest(key, scope, "sha256")

        self.tokens = {label: material("token", label).hex() for label in LABELS}
        self.codes = {label: urlsafe_b64encode(material("code", label)[:9]).decode("ascii") for label in LINKS}
        self.hashes = {label: digest(code.encode("ascii")) for label, code in self.codes.items()}
        require(len(set(self.hashes.values())) == len(LINKS) and len(set(self.tokens.values())) == len(LABELS), ERROR)
        self.objects = {}
        for label in SNAPSHOTS:
            snapshot = str(UUIDValue(bytes=material("snapshot", label)[:16], version=4))
            prefix = f"subscriptions/{self.ids[label]}/{snapshot}/"
            chunk = (canonical(fixture_node(label)) + "\n").encode("ascii")
            manifest = canonical({"version": 1, "chunks": [{"bytes": len(chunk), "sha256": digest(chunk), "count": 1}]}).encode("ascii")
            self.objects[label] = (snapshot, prefix, {prefix + "0.ndjson": chunk, prefix + "manifest.json": manifest})

    def inventory(self):
        ids, tokens, sources, hashes = (canonical(list(values)) for values in
            (self.ids.values(), self.tokens.values(), self.sources.values(), self.hashes.values()))
        sub_where = ("id IN (SELECT value FROM json_each(?)) OR token IN (SELECT value FROM json_each(?)) "
                     "OR source_url IN (SELECT value FROM json_each(?)) OR owner_id=? OR name=?")
        code_where = "code_sha256 IN (SELECT value FROM json_each(?))"
        return {
            "subscriptions": (f"SELECT {SUBSCRIPTION_FIELDS} FROM subscriptions WHERE {sub_where} ORDER BY id LIMIT 4",
                              (ids, tokens, sources, OWNER, self.name)),
            "aggregates": (f"SELECT {','.join(FIELDS['aggregates'])} FROM aggregate_links WHERE {code_where} OR owner_id=? "
                           "ORDER BY code_sha256 LIMIT 5", (hashes, OWNER)),
            "markers": (f"SELECT code_sha256 FROM legacy_selected_aggregates WHERE {code_where} ORDER BY code_sha256", (hashes,)),
            "watches": ("SELECT id,retired FROM legacy_selected_members WHERE id IN (SELECT value FROM json_each(?)) ORDER BY id", (ids,)),
            "empty": ("SELECT subscription_id,owner_id,token_sha256 FROM legacy_empty_subscription_exports WHERE owner_id=? "
                      "OR subscription_id IN (SELECT value FROM json_each(?)) OR token_sha256 IN (SELECT value FROM json_each(?)) "
                      "ORDER BY subscription_id LIMIT 4", (OWNER, ids, canonical([digest(token.encode("ascii")) for token in self.tokens.values()]))),
            "trash": (f"SELECT id FROM subscription_trash WHERE {sub_where} LIMIT 1", (ids, tokens, sources, OWNER, self.name)),
            "lifecycle": ("SELECT subscription_id FROM subscription_lifecycle WHERE subscription_id IN (SELECT value FROM json_each(?)) LIMIT 1", (ids,)),
            "rules": ("SELECT id FROM path_rules WHERE owner_id=? LIMIT 1", (OWNER,)),
            "normal": (f"SELECT code_sha256 FROM normal_short_links WHERE {code_where} OR owner_id=? LIMIT 1", (hashes, OWNER)),
            "typed": (f"SELECT code_sha256 FROM legacy_subscription_short_links WHERE {code_where} OR owner_id=? "
                      "OR subscription_id IN (SELECT value FROM json_each(?)) LIMIT 1", (hashes, OWNER, ids)),
            "other_selection": ("SELECT 1 AS present FROM aggregate_links AS link, json_each(link.selected_ids) AS member "
                                 "WHERE link.owner_id<>? AND member.type='integer' AND member.value IN (SELECT value FROM json_each(?)) LIMIT 1",
                                (OWNER, ids)),
            **{table: (f"SELECT code_sha256 FROM {table} WHERE {code_where} LIMIT 1", (hashes,))
               for table in ("telegram_aggregate_slots", "telegram_selected_links")},
            **{table: (f"SELECT subscription_id FROM {table} WHERE subscription_id IN (SELECT value FROM json_each(?)) LIMIT 1", (ids,))
               for table in ("subscription_provider_jobs", "telegram_document_reservations", "telegram_document_stages",
                             "telegram_provider_document_lines", "telegram_provider_jobs", "telegram_provider_batch_jobs",
                             "provider_snapshot_attempts")},
        }

    def expected(self, state, intents=CLEAN_INTENTS):
        value = {name: [] for name in self.inventory()}
        if state == "absent":
            return value
        by_label = dict(zip(SNAPSHOTS, intents, strict=True))
        for label in LABELS:
            published = label in self.objects and state != "reserved"
            snapshot, prefix, bodies = self.objects[label] if published else (None, None, {})
            flags = by_label.get(label, "--")
            value["subscriptions"].append(dict.fromkeys(FIELDS["subscriptions"]) | {
                "id": self.ids[label], "owner_id": OWNER, "name": self.name, "source_url": self.sources[label],
                "token": self.tokens[label], "created_at": self.stamp, "updated_at": self.stamp,
                "generation": int(published), "snapshot_id": snapshot,
                "manifest_sha256": digest(bodies[prefix + "manifest.json"]) if published else None, "node_count": int(published),
                "last_error": INTENT_PREFIX + flags if flags != "--" else None,
            })
        if state == "reserved":
            return value
        alpha, beta, empty = self.ids.values()
        selections = {"marked": [beta, alpha, beta], "marked-empty": [empty], "ordinary": [beta, alpha], "ordinary-empty": [empty]}
        value["aggregates"] = sorted(({"code_sha256": self.hashes[label], "owner_id": OWNER, "kind": "selected", "bot_id": None,
                                      "selected_ids": canonical(ids), "created_at": self.stamp, "revoked_at": None}
                                      for label, ids in selections.items()), key=lambda item: item["code_sha256"])
        value["markers"] = [{"code_sha256": hashed} for hashed in sorted(self.hashes[label] for label in LINKS[:2])]
        value["watches"] = [{"id": sid, "retired": int(label == "beta" and state == "member-retired")} for label, sid in self.ids.items()]
        value["empty"] = [{"subscription_id": empty, "owner_id": OWNER, "token_sha256": digest(self.tokens["empty"].encode("ascii"))}]
        return value

    def batch(self, operations):
        return query(self.resources.api, self.resources.database, {"batch": operations}, len(operations))

    def observe(self):
        inventory = self.inventory()
        results = self.batch([statement(sql, *params) for sql, params in inventory.values()])
        observed = {label: result["results"] for label, result in zip(inventory, results, strict=True)}
        by_id = {row["id"]: row["last_error"] for row in observed["subscriptions"]}
        flags = []
        for label in SNAPSHOTS:
            raw = by_id.get(self.ids[label])
            if raw is None:
                flags.append("--")
            else:
                match = INTENT.fullmatch(raw) if isinstance(raw, str) else None
                require(match is not None and match[1] != "--", ERROR)
                flags.append(match[1])
        intents = tuple(flags)
        for state in ("absent", "reserved", "published", "member-retired"):
            if (state == "reserved" or intents == CLEAN_INTENTS) and observed == self.expected(state, intents):
                return state, intents
        raise FixtureError(ERROR)

    def assertions(self, state):
        expected = self.expected(*state)
        return [snapshot_assert(sql, params, FIELDS[label], expected[label]) if label in FIELDS else
                statement(_assert_sql(f"NOT EXISTS ({sql})"), *params)
                for label, (sql, params) in self.inventory().items()]

    def change(self, before, after, mutations, guard):
        steps = [*self.assertions(before), *mutations, *self.assertions(after)]
        guard()
        try:
            self.batch(steps)
        except (CloudflareError, FixtureError):
            delays = (0, 1, 2, 4)
        else:
            delays = (0,)
        for delay in delays:
            if delay:
                sleep(delay)
            observed = self.observe()
            if observed == after:
                return
            require(observed == before, ERROR)
        raise FixtureError(ERROR)

    def reserve(self, guard):
        state = self.observe()
        if state == ("reserved", CLEAN_INTENTS):
            return
        require(state == ("absent", CLEAN_INTENTS), ERROR)
        seq, now = allocator(self.resources)
        require(seq == self.checkpoint["highWater"] and self.stamp <= now <= self.checkpoint["reserveUntil"], ERROR)
        mutations = [statement(_assert_sql("""COALESCE((SELECT max(seq) FROM sqlite_sequence WHERE name='subscriptions'),0)=CAST(? AS INTEGER)
            AND (SELECT count(*) FROM sqlite_sequence WHERE name='subscriptions')<=1
            AND COALESCE((SELECT max(id) FROM subscriptions),0)<=CAST(? AS INTEGER)
            AND COALESCE((SELECT max(id) FROM subscription_trash),0)<=CAST(? AS INTEGER)
            AND unixepoch() BETWEEN CAST(? AS INTEGER) AND CAST(? AS INTEGER)"""),
            seq, seq, seq, self.stamp, self.checkpoint["reserveUntil"])]
        mutations.extend(statement("""INSERT INTO subscriptions(id,owner_id,name,source_url,token,created_at,updated_at)
            VALUES (?,?,?,?,?,?,?)""", self.ids[label], OWNER, self.name, self.sources[label], self.tokens[label], self.stamp, self.stamp)
            for label in LABELS)
        mutations.append(statement(_assert_sql("(SELECT seq FROM sqlite_sequence WHERE name='subscriptions')=CAST(? AS INTEGER)"), max(self.ids.values())))
        self.change(state, ("reserved", CLEAN_INTENTS), mutations, guard)

    def advance_intent(self, intents, label, object_index, old, new, guard):
        # The reserved generation-zero shell is invisible to export. Keep the
        # four write intentions here without adding a migration or R2 objects.
        index = SNAPSHOTS.index(label)
        flags = intents[index]
        require(flags[object_index] == old and (old, new) in (("-", "a"), ("a", "c")), ERROR)
        updated = flags[:object_index] + new + flags[object_index + 1:]
        after = intents[:index] + (updated,) + intents[index + 1:]
        self.change(("reserved", intents), ("reserved", after), [statement("""UPDATE subscriptions SET last_error=?
            WHERE id=? AND owner_id=? AND token=? AND generation=0""", INTENT_PREFIX + updated,
            self.ids[label], OWNER, self.tokens[label])], guard)
        return after

    def present_objects(self):
        present = {}
        for _, prefix, bodies in self.objects.values():
            listed = {}
            for item in self.listing.list_objects(WORKER_NAME, prefix=prefix, maximum=len(bodies)):
                key = item.get("key")
                require(key in bodies and key not in listed and integer(item.get("size"), 1, 4096)
                        and item["size"] == len(bodies[key]), ERROR)
                listed[key] = item["size"]
            for key, expected in bodies.items():
                observed = self.resources.objects.request("GET", key)
                require((key in listed and observed == expected) or (key not in listed and observed is None), ERROR)
                if key in listed:
                    present[key] = expected
        return present

    def confirm_object(self, key, wanted, previous, uncertain):
        for delay in ((0, 1, 2, 4) if uncertain else (0,)):
            if delay:
                sleep(delay)
            observed = self.resources.objects.request("GET", key)
            if observed == wanted:
                return
            require(observed == previous, ERROR)
        if wanted is not None:
            raise UnconfirmedPut()
        raise FixtureError(ERROR)

    def verify(self, guard):
        state, intents = self.observe()
        require(state in ("reserved", "published"), ERROR)
        present = self.present_objects()
        if state == "reserved":
            for role_index, (label, (_, _, bodies)) in enumerate(self.objects.items()):
                for object_index, (key, body) in enumerate(bodies.items()):
                    flag = intents[role_index][object_index]
                    if flag == "c":
                        require(key in present, ERROR)
                        continue
                    if flag == "-":
                        require(key not in present, ERROR)
                        intents = self.advance_intent(intents, label, object_index, "-", "a", guard)
                        guard()
                        uncertain = False
                        try:
                            self.resources.objects.request("PUT", key, body)
                        except (CloudflareError, CapacityError):
                            uncertain = True
                        self.confirm_object(key, body, None, uncertain)
                    else:
                        # A previous runner armed this PUT. Absence cannot prove
                        # the attempt failed and cannot authorize another write.
                        if key not in present:
                            raise UnconfirmedPut()
                    intents = self.advance_intent(intents, label, object_index, "a", "c", guard)
            require(len(self.present_objects()) == 4, ERROR)
            expected = self.expected("published")
            mutations = [statement("""UPDATE subscriptions SET generation=1,snapshot_id=?,manifest_sha256=?,node_count=1,last_error=NULL
                WHERE id=? AND owner_id=? AND token=? AND generation=0""", row["snapshot_id"], row["manifest_sha256"],
                row["id"], OWNER, row["token"]) for row in expected["subscriptions"] if row["generation"] == 1]
            mutations.extend(statement("""INSERT INTO aggregate_links(code_sha256,owner_id,kind,selected_ids,created_at)
                VALUES (?,?,'selected',?,?)""", row["code_sha256"], OWNER, row["selected_ids"], self.stamp)
                for row in expected["aggregates"])
            mutations.extend(statement("INSERT INTO legacy_selected_aggregates(code_sha256) VALUES (?)", row["code_sha256"])
                             for row in expected["markers"])
            mutations.extend(statement("INSERT INTO legacy_selected_members(id,retired) VALUES (?,0)", row["id"])
                             for row in expected["watches"])
            empty = expected["empty"][0]
            mutations.append(statement("INSERT INTO legacy_empty_subscription_exports(subscription_id,owner_id,token_sha256) VALUES (?,?,?)",
                                       empty["subscription_id"], empty["owner_id"], empty["token_sha256"]))
            self.change(("reserved", intents), ("published", CLEAN_INTENTS), mutations, guard)
        else:
            require(len(present) == 4, ERROR)
        guard()
        published = verify_legacy_selected_http(self.codes, "published")
        # This is a fixture state transition only. Hosted Worker coverage runs actual trash and restore.
        self.change(("published", CLEAN_INTENTS), ("member-retired", CLEAN_INTENTS),
                    [statement("UPDATE legacy_selected_members SET retired=1 WHERE id=? AND retired=0",
                                                             self.ids["beta"])], guard)
        guard()
        retired = verify_legacy_selected_http(self.codes, "member-retired")
        return {"published": published, "memberRetired": retired, "objectsVerified": 4}

    def retire(self, guard):
        state, intents = self.observe()
        seq, now = allocator(self.resources)
        present = self.present_objects()
        if state == "reserved":
            for (_, _, bodies), flags in zip(self.objects.values(), intents, strict=True):
                for key, flag in zip(bodies, flags, strict=True):
                    require(flag != "-" or key not in present, ERROR)
                    if flag == "a" and key not in present:
                        raise UnconfirmedPut()
        if state != "absent":
            last_id = max(self.ids.values())
            require(seq >= last_id, ERROR)
            hashes, ids = canonical(list(self.hashes.values())), canonical(list(self.ids.values()))
            mutations = [statement(_assert_sql("(SELECT seq FROM sqlite_sequence WHERE name='subscriptions')>=CAST(? AS INTEGER)"), last_id)]
            mutations.extend(statement(f"DELETE FROM {table} WHERE code_sha256 IN (SELECT value FROM json_each(?))", hashes)
                             for table in ("legacy_selected_aggregates", "aggregate_links"))
            mutations.extend(statement(f"DELETE FROM {table} WHERE {column} IN (SELECT value FROM json_each(?))", ids)
                             for table, column in (("legacy_selected_members", "id"),
                                                   ("legacy_empty_subscription_exports", "subscription_id"), ("subscriptions", "id")))
            self.change((state, intents), ("absent", CLEAN_INTENTS), mutations, guard)
        else:
            # A still-live, unconsumed reservation could otherwise publish after an empty cleanup readback.
            high_water = self.checkpoint["highWater"]
            require(seq > high_water or (seq == high_water and now > self.checkpoint["reserveUntil"]), ERROR)
        for key, expected in present.items():
            guard()
            require(self.observe() == ("absent", CLEAN_INTENTS) and self.resources.objects.request("GET", key) == expected, ERROR)
            uncertain = False
            try:
                self.resources.objects.request("DELETE", key)
            except (CloudflareError, CapacityError):
                uncertain = True
            self.confirm_object(key, None, expected, uncertain)
        require(self.observe() == ("absent", CLEAN_INTENTS) and not self.present_objects(), ERROR)
        guard()
        return {"retired": verify_legacy_selected_http(self.codes, "cohort-retired"), "objectsAbsent": 4}


def run():
    with phase("workflow inputs"):
        revision = os.environ.get("GITHUB_SHA", "")
        require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
                and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch", ERROR)
        with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
            raw = event.read(65537)
        require(len(raw) <= 65536, ERROR)
        action, cohort, source = inputs(_parse_object(raw, ERROR))
        require_current_main(revision)
        token = os.environ["GH_TOKEN"]
        source_revision = _get_json(f"/actions/runs/{source}", token).get("head_sha") if action == "retire" else revision
        require(matches(REVISION, source_revision), ERROR)
        if source_revision != revision:
            comparison = _get_json(f"/compare/{source_revision}...{revision}?per_page=1", token)
            require(comparison.get("status") == "ahead" and comparison.get("merge_base_commit", {}).get("sha") == source_revision, ERROR)
        checkpoint = read_checkpoint(source, source_revision, token, workflow_file=WORKFLOW, artifact_prefix=ARTIFACT,
                                     checkpoint_file=CHECKPOINT) if source else None

    with phase("exact isolated release and rollback floor"):
        target = _parse_object(os.environ["SUBS_BOT_CF_ISOLATION_TARGET_JSON"], ERROR)
        data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
        require(data_token and deploy_token and data_token != deploy_token, ERROR)
        raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
        policy = json.loads(raw_policy)
        require(OWNER not in (policy["adminId"], policy["memberId"], policy["botId"]), ERROR)
        encoded_key = os.environ["SUBS_BOT_TELEGRAM_AGGREGATE_KEY"]
        key = key_bytes(encoded_key)
        policy_digest, key_digest = digest(raw_policy.encode()), digest(encoded_key.encode("ascii"))
        data = CloudflareClient(data_token)
        scope = _Isolation(CloudflareClient(deploy_token), data, target)
        scope.verify_resources()
        config = scope.worker_config()
        active = scope.active()
        version, capable = scope.version(active.version, with_legacy_selected=True)
        require(capable and version.revision == revision and version.telegram_config_sha256 == policy_digest
                and version.telegram_aggregate_key_sha256 == key_digest, ERROR)
        scope.verify_legacy_selected_floor(allow_rows=True, require_schema=True)
        scope.verify_legacy_subscription_shorts()
        _verify_health(revision)
        release_pin = {"revision": revision, "versionId": active.version, "moduleSha256": version.digest,
                       "compatibilityDate": version.compatibility}
        validate_release_pin(release_pin)
        resources = Resources(target, data, SnapshotObjects(target["accountId"], data_token))
        require(resources.query("SELECT name,sha256,mode FROM subs_bot_schema_migrations WHERE position=26", ())
                == [{"name": EMPTY_MIGRATION, "sha256": EMPTY_SHA, "mode": "applied"}], ERROR)
        identity = sha256(canonical([resources.scope_hash, policy_digest, key_digest]).encode("ascii")).hexdigest()

    def guard():
        require_current_main(revision)
        scope.verify_resources()
        require(scope.active() == active and scope.worker_config() == config, ERROR)
        scope.verify_legacy_selected_floor(allow_rows=True, require_schema=True)

    with phase("sealed cohort identity"):
        if checkpoint is None:
            high_water, created = allocator(resources)
            require(high_water <= MAX_ID - len(LABELS), ERROR)
            checkpoint = {"version": 1, "phase": "prepared", "cohort": cohort, "identity": identity, "revision": revision,
                          "releasePin": release_pin, "highWater": high_water, "createdAt": created, "reserveUntil": created + 1800}
        else:
            validate_checkpoint(checkpoint, action, cohort, source_revision, identity, release_pin)
        fixtures = Cohort(resources, RehearsalAPI(target, data_token, cohort), checkpoint, key)

    with phase(action):
        report = {}
        if action == "prepare":
            require(fixtures.observe() == ("absent", CLEAN_INTENTS) and not fixtures.present_objects(), ERROR)
        elif action == "reserve":
            require(not fixtures.present_objects(), ERROR)
            fixtures.reserve(guard)
        elif action == "verify":
            report = fixtures.verify(guard)
        else:
            report = fixtures.retire(guard)
            checkpoint = {**checkpoint, "retiredAtReleasePin": release_pin}

    with phase("final scoped readback"):
        guard()
        require(scope.version(active.version, with_legacy_selected=True) == (version, True), ERROR)
        _verify_health(revision)
        checkpoint = {**checkpoint, "phase": PHASES[action]}
        save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, checkpoint)
        print(json.dumps({"phase": checkpoint["phase"], "activeVersion": active.version, "httpEvidence": report}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except FixtureError as error:
        sys.exit(str(error))
    except Exception:
        sys.exit(ERROR)

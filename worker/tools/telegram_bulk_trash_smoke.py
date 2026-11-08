"""Protected D1-only evidence for the two-account Telegram bulk-trash flow."""

from hashlib import sha256
import hmac
import json
import os
from pathlib import Path
import re
import sys

from capacity_resources import CapacityError, Resources, integer, matches, save_private_json
from cloudflare_isolation import CloudflareClient, CloudflareError, DIGEST, REVISION, _Isolation, _verify_health
from d1_migrations import _assert_sql
from prepare_isolation_artifact import ArtifactError, MAIN_REF, REPOSITORY, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import (
    DECIMAL, MAX_ID, ROLES, SUBSCRIPTION_FIELDS, canonical, digest, key_bytes,
    read_checkpoint, require, validate_release_pin, verify_checkpoint_release,
)
from telegram_view_fixtures import FixtureError, provider_batch_fixture_quiet, provider_batch_fixture_tables, query, statement


WORKFLOW = "worker-isolation-telegram-fixtures.yml"
ARTIFACT_PREFIX = "subs-bot-telegram-bulk-trash"
CHECKPOINT = "telegram-bulk-trash-checkpoint.json"
MIGRATION = "0024_telegram_bulk_trash.sql"
ORIGIN = "https://subs-bot-bulk-fixtures.invalid/"
COHORT = re.compile(r"[a-z0-9]{16}")
SOURCE_SUFFIX = re.compile(r"([0-9a-f]{64})/(0|[1-9][0-9]{0,15})")
MARKER = "bulktrash:v1"
LABELS = tuple(f"A{index:02}" for index in range(1, 17)) + ("M01",)
ROW_FIELDS = (*SUBSCRIPTION_FIELDS.split(","), "deleted_at", "trash_revision", "trashed", "revision")
RECEIPT_FIELDS = ("receipt_id", "actor_id", "chat_id", "chat_type", "thread_id", "command", "message_id", "message_date",
                  "received_at", "kind", "target_count", "targets", "actor_role", "auth_message_date", "auth_message_id",
                  "token_sha256", "origin_attempt", "expires_at", "confirmed_by_receipt_id", "state", "attempts",
                  "sent_message_id")


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict)
            and set(inputs) <= {"action", "purpose", "cohort", "source_run_id", "source_revision", "confirm_retire"}
            and inputs.get("purpose") == "bulk-trash", "Bulk-trash workflow inputs differ.")
    action, cohort = inputs.get("action"), inputs.get("cohort")
    source, revision, confirmation = (inputs.get(key, "") for key in ("source_run_id", "source_revision", "confirm_retire"))
    require(action in ("seed", "verify", "retire") and matches(COHORT, cohort)
            and (source == "" if action == "seed" else matches(DECIMAL, source))
            and (matches(REVISION, revision) if action == "retire" else revision == "")
            and confirmation == (f"retire {cohort}" if action == "retire" else ""),
            "Bulk-trash workflow phase, source, or confirmation differs.")
    return action, cohort, source, revision


def serialized_rows(result, fields):
    return canonical([[row[field] for field in fields] for row in result])


class BulkCohort:
    def __init__(self, resources, policy, cohort, encoded, identity):
        self.resources, self.bot, self.cohort, self.identity = resources, policy["botId"], cohort, identity
        self.actors = {role: policy[field] for role, field in ROLES.items()}
        self.prefix, self.needle = ORIGIN + cohort + "/", "CFB-" + cohort
        key = key_bytes(encoded)
        self.sign_key = hmac.digest(key, b"subs-bot/bulk-trash-fixture/checkpoint/v1", "sha256")
        token_key = hmac.digest(key, b"subs-bot/bulk-trash-fixture/token/v1", "sha256")
        self.tokens = {label: hmac.new(token_key, canonical([identity, cohort, label]).encode(), sha256).hexdigest()
                       for label in LABELS}
        self.provider_batch_tables = provider_batch_fixture_tables(self.read)

    def read(self, sql, *params):
        return self.resources.query(sql, params)

    def batch(self, steps):
        query(self.resources.api, self.resources.database, {"batch": steps}, len(steps))

    def seed_row(self, label):
        role = "member" if label == "M01" else "admin"
        name = f"CFB source-only {self.cohort}-A16" if label == "A16" else f"{self.needle}-{label}"
        source = self.prefix + label + "/" + (self.needle + "/" if label == "A16" else "")
        return self.actors[role], name, source, self.tokens[label]

    def inventory(self, ids):
        criteria = """(substr(source_url,1,length(?))=? OR name IN (SELECT value FROM json_each(?))
          OR token IN (SELECT value FROM json_each(?)) OR id IN (SELECT value FROM json_each(?)))"""
        params = (self.prefix, self.prefix, canonical([self.seed_row(label)[1] for label in LABELS]),
                  canonical(list(self.tokens.values())), canonical(list(ids)))
        sql = f"""SELECT *, (SELECT revision FROM subscription_lifecycle WHERE subscription_id=inventory.id) AS revision FROM (
          SELECT {SUBSCRIPTION_FIELDS},NULL AS deleted_at,NULL AS trash_revision,0 AS trashed
            FROM subscriptions WHERE {criteria}
          UNION ALL
          SELECT {SUBSCRIPTION_FIELDS},deleted_at,lifecycle_revision,1 FROM subscription_trash WHERE {criteria}
        ) AS inventory ORDER BY id,trashed LIMIT 18"""
        return sql, (*params, *params)

    def subscriptions(self, ids=()):
        sql, params = self.inventory(ids)
        observed = self.read(sql, *params)
        labels = {token: label for label, token in self.tokens.items()}
        by_label, suffixes = {}, set()
        for row in observed:
            label, source = labels.get(row["token"]), row["source_url"]
            require(label is not None and label not in by_label, "Bulk-trash synthetic row identity is ambiguous.")
            owner, name, start, _ = self.seed_row(label)
            suffix = SOURCE_SUFFIX.fullmatch(source[len(start):]) if isinstance(source, str) and source.startswith(start) else None
            require(suffix is not None and integer(int(suffix[2]), 0, MAX_ID)
                    and (row["owner_id"], row["name"]) == (owner, name)
                    and integer(row["id"], 1, MAX_ID) and integer(row["created_at"], 1, MAX_ID)
                    and row["created_at"] == row["updated_at"]
                    and all(row[field] is None for field in ("expire_at", "traffic_used", "traffic_total", "last_error",
                                                           "snapshot_id", "manifest_sha256"))
                    and (row["generation"], row["node_count"]) == (0, 0),
                    "Bulk-trash synthetic metadata or unpublished snapshot differs.")
            require((row["trashed"], row["revision"], row["trash_revision"], row["deleted_at"]) == (0, None, None, None)
                    or (label != "M01" and (row["trashed"], row["revision"], row["trash_revision"]) == (1, 1, 1)
                        and integer(row["deleted_at"], row["created_at"], MAX_ID)),
                    "Bulk-trash synthetic lifecycle state differs.")
            suffixes.add((suffix[1], int(suffix[2]), row["created_at"]))
            by_label[label] = row
        require(not observed or (set(by_label) == set(LABELS) and len(suffixes) == 1
                and len({row["id"] for row in observed}) == len(LABELS)), "Bulk-trash synthetic cohort is partial.")
        return by_label, next(iter(suffixes), None)

    def auth_query(self):
        return ("""SELECT COALESCE(auth.allowed,1) AS allowed,COALESCE(auth.message_date,0) AS date,
          COALESCE(auth.message_id,0) AS message FROM (SELECT 1) AS seed LEFT JOIN telegram_auth AS auth
          ON auth.bot_id=? AND auth.user_id=?""", (self.bot, self.actors["member"]))

    def authorization(self):
        sql, params = self.auth_query()
        result = self.read(sql, *params)
        require(len(result) == 1 and result[0]["allowed"] == 1
                and all(integer(result[0][field], 0, MAX_ID) for field in ("date", "message")),
                "Bulk-trash member authorization differs.")
        return result[0]

    def epoch(self, auth):
        body = canonical(["auth", self.cohort, auth["allowed"], auth["date"], auth["message"]]).encode("ascii")
        return hmac.digest(self.sign_key, body, "sha256").hex()

    def quiet(self, ids, *, isolate_inventory=False):
        actors, known = tuple(self.actors.values()), canonical(list(ids))
        condition = """NOT EXISTS(SELECT 1 FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING(receipt_id)
          WHERE inbox.bot_id=? AND inbox.actor_id IN (?,?) AND reply.state IN ('pending','leased','sending'))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_jobs WHERE bot_id=? AND actor_id IN (?,?) AND state IN ('pending','leased'))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_reservations WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM telegram_document_stages WHERE subscription_id IN (SELECT value FROM json_each(?)))
          AND NOT EXISTS(SELECT 1 FROM subscription_provider_jobs WHERE owner_id IN (?,?) AND state IN ('pending','leased'))
          AND NOT EXISTS(SELECT 1 FROM telegram_provider_jobs WHERE owner_id IN (?,?) AND state IN ('pending','leased'))"""
        params = (self.bot, *actors, self.bot, *actors, known, known, *actors, *actors)
        if isolate_inventory:
            condition += """ AND NOT EXISTS(SELECT 1 FROM subscriptions WHERE owner_id IN (?,?)
              AND id NOT IN (SELECT value FROM json_each(?)))"""
            params += (*actors, known)
        batch, batch_params = provider_batch_fixture_quiet(self.provider_batch_tables, self.bot, actors)
        return condition + " AND " + batch, (*params, *batch_params)

    def require_quiet(self, ids, *, isolate_inventory=False):
        condition, params = self.quiet(ids, isolate_inventory=isolate_inventory)
        require(self.read(f"SELECT ({condition}) AS quiet", *params) == [{"quiet": 1}],
                "Bulk-trash acceptance has unrelated or in-flight work.")

    def history(self, watermark):
        sql = """SELECT inbox.receipt_id,actor_id,chat_id,chat_type,thread_id,command,message_id,message_date,received_at,
          kind,target_count,targets,actor_role,auth_message_date,auth_message_id,token_sha256,origin_attempt,expires_at,
          confirmed_by_receipt_id,state,attempts,sent_message_id
          FROM telegram_inbox AS inbox LEFT JOIN telegram_bulk_trash USING(receipt_id)
          LEFT JOIN telegram_outbox USING(receipt_id)
          WHERE inbox.bot_id=? AND inbox.actor_id IN (?,?) AND inbox.receipt_nonce=? AND inbox.receipt_id>CAST(? AS INTEGER)
          ORDER BY inbox.receipt_id LIMIT 4"""
        return sql, (self.bot, *self.actors.values(), MARKER, watermark)

    def signed(self, payload):
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("ascii")
        return {"payload": payload, "signature": hmac.digest(self.sign_key, body, "sha256").hex()}

    def checkpoint(self, value, action, revision, pin):
        require(isinstance(value, dict) and set(value) == {"payload", "signature"} and isinstance(value["payload"], dict)
                and matches(DIGEST, value["signature"]), "Bulk-trash checkpoint envelope differs.")
        payload = value["payload"]
        require(hmac.compare_digest(value["signature"], self.signed(payload)["signature"]),
                "Bulk-trash checkpoint signature differs.")
        require(set(payload) == {"version", "phase", "cohort", "identity", "revision", "releasePin", "authEpoch",
                "afterReceiptId", "fixtures", "receipts"} and type(payload["version"]) is int and payload["version"] == 1
                and payload["phase"] in (("seeded",) if action == "verify" else ("seeded", "verified"))
                and (payload["cohort"], payload["identity"], payload["revision"]) == (self.cohort, self.identity, revision)
                and matches(DIGEST, payload["authEpoch"]) and integer(payload["afterReceiptId"], 0, MAX_ID),
                "Bulk-trash checkpoint scope or phase differs.")
        verify_checkpoint_release(payload, pin, retiring=action == "retire")
        items = payload["fixtures"]
        require(isinstance(items, dict) and set(items) == set(LABELS), "Bulk-trash checkpoint inventory differs.")
        for label, item in items.items():
            require(isinstance(item, dict) and set(item) == {"id", "tokenSha256", "createdAt"}
                    and integer(item["id"], 1, MAX_ID) and integer(item["createdAt"], 1, MAX_ID)
                    and item["tokenSha256"] == digest(self.tokens[label].encode("ascii")),
                    "Bulk-trash checkpoint fixture pointer differs.")
        require(len({item["id"] for item in items.values()}) == len(LABELS)
                and len({item["createdAt"] for item in items.values()}) == 1, "Bulk-trash checkpoint pointers overlap.")
        evidence = payload["receipts"]
        require(isinstance(evidence, list) and len(evidence) == (3 if payload["phase"] == "verified" else 0)
                and all(matches(DIGEST, value) for value in evidence), "Bulk-trash checkpoint receipt evidence differs.")
        return payload

    def pointers(self, items):
        return {label: {"id": row["id"], "tokenSha256": digest(row["token"].encode("ascii")), "createdAt": row["created_at"]}
                for label, row in items.items()}


def snapshot_assert(sql, params, fields, observed):
    columns = ",".join(fields)
    guard = f"(SELECT json_group_array(json_array({columns})) FROM ({sql}))=?"
    return statement(_assert_sql(guard), *params, serialized_rows(observed, fields))


def seed(cohort, revision, pin, guard):
    before, _ = cohort.subscriptions()
    auth = cohort.authorization()
    epoch = cohort.epoch(auth)
    if not before:
        inventory, params = cohort.inventory(())
        quiet, quiet_params = cohort.quiet((), isolate_inventory=True)
        auth_sql, auth_params = cohort.auth_query()
        watermark = cohort.read("SELECT COALESCE(max(receipt_id),0) AS watermark FROM telegram_inbox")[0]["watermark"]
        require(integer(watermark, 0, MAX_ID), "Bulk-trash receipt watermark differs.")
        values = ",".join(["(?,?,?||?,?,unixepoch(),unixepoch())"] * len(LABELS))
        suffix = f"{epoch}/{watermark}"
        args = [value for label in LABELS for value in (*cohort.seed_row(label)[:3], suffix, cohort.tokens[label])]
        steps = [
            snapshot_assert(inventory, params, ROW_FIELDS, []),
            statement(_assert_sql(quiet), *quiet_params),
            snapshot_assert(auth_sql, auth_params, ("allowed", "date", "message"), [auth]),
            statement(_assert_sql("(SELECT COALESCE(max(receipt_id),0) FROM telegram_inbox)=CAST(? AS INTEGER)"), watermark),
            statement("INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at) VALUES " + values, *args),
            statement(_assert_sql(f"(SELECT count(*) FROM ({inventory}))=17"), *params),
        ]
        guard()
        try:
            cohort.batch(steps)
        except (CloudflareError, FixtureError):
            # Deterministic identities allow adoption only after exact committed readback.
            pass
    current, metadata = cohort.subscriptions()
    require(metadata is not None and metadata[0] == epoch and not any(row["trashed"] for row in current.values()),
            "Bulk-trash seed could not be confirmed as untouched.")
    history, params = cohort.history(metadata[1])
    require(not cohort.read(history, *params), "Bulk-trash seed already has Telegram activity.")
    cohort.require_quiet([row["id"] for row in current.values()], isolate_inventory=True)
    return {"version": 1, "phase": "seeded", "cohort": cohort.cohort, "identity": cohort.identity,
            "revision": revision, "releasePin": pin, "authEpoch": epoch, "afterReceiptId": metadata[1],
            "fixtures": cohort.pointers(current), "receipts": []}


def check_receipts(cohort, checkpoint, history, *, moved, full):
    previews, confirmation = {}, None
    for row in history:
        role = row["actor_role"]
        require(role in ROLES and row["actor_id"] == row["chat_id"] == cohort.actors[role]
                and (row["chat_type"], row["thread_id"], row["command"], row["state"]) == ("private", None, "help", "sent")
                and integer(row["attempts"], 1, 4) and integer(row["sent_message_id"], 1, MAX_ID)
                and integer(row["received_at"], 1, MAX_ID), "Bulk-trash Telegram receipt scope or send differs.")
        date, message = row["auth_message_date"], row["auth_message_id"]
        require(integer(date, 0, MAX_ID) and integer(message, 0, MAX_ID) and integer(row["message_date"], date + 1, MAX_ID)
                and ((date, message) == (0, 0) if role == "admin" else
                     cohort.epoch({"allowed": 1, "date": date, "message": message}) == checkpoint["authEpoch"]),
                "Bulk-trash Telegram receipt authorization differs.")
        if row["kind"] == "preview":
            labels = LABELS[:-1] if role == "admin" else LABELS[-1:]
            expected = canonical([[item, 0, 0] for item in sorted(checkpoint["fixtures"][label]["id"] for label in labels)])
            require(role not in previews and (row["target_count"], row["targets"]) == (len(labels), expected)
                    and matches(DIGEST, row["token_sha256"]) and row["origin_attempt"] == row["attempts"]
                    and integer(row["expires_at"], row["received_at"], MAX_ID),
                    "Bulk-trash preview did not bind the exact owner and target set.")
            previews[role] = row
        else:
            origin = previews.get("admin")
            require(confirmation is None and origin is not None and role == "admin"
                    and (row["kind"], row["target_count"], row["targets"]) == ("trashed", 16, None)
                    and (row["message_id"], row["receipt_id"]) == (origin["sent_message_id"], origin["confirmed_by_receipt_id"])
                    and row["received_at"] < origin["expires_at"], "Bulk-trash confirmation did not bind the sent admin preview.")
            confirmation = row
    require(all(row["confirmed_by_receipt_id"] is None for role, row in previews.items() if role != "admin" or confirmation is None)
            and (confirmation is not None) == moved and (not full or set(previews) == set(ROLES)),
            "Bulk-trash acceptance receipt inventory differs.")
    # HMAC evidence avoids publishing stable digests of real actor IDs or message identifiers.
    return [hmac.digest(cohort.sign_key, canonical(["receipt", cohort.cohort,
            [row[field] for field in RECEIPT_FIELDS]]).encode(), "sha256").hex() for row in history]


def observe(cohort, checkpoint, *, retiring):
    ids = [item["id"] for item in checkpoint["fixtures"].values()]
    current, metadata = cohort.subscriptions(ids)
    cohort.require_quiet(ids, isolate_inventory=not retiring)
    history, params = cohort.history(checkpoint["afterReceiptId"])
    evidence = cohort.read(history, *params)
    confirmed_at = next((row["received_at"] for row in evidence if row["kind"] == "trashed"), None)
    if not current:
        require(retiring, "Bulk-trash synthetic inventory is absent.")
        moved = confirmed_at is not None
    else:
        require(cohort.pointers(current) == checkpoint["fixtures"]
                and metadata[:2] == (checkpoint["authEpoch"], checkpoint["afterReceiptId"]),
                "Bulk-trash checkpoint fixture identity changed.")
        moved = all(current[label]["trashed"] for label in LABELS[:-1])
        require(moved or not any(row["trashed"] for row in current.values()), "Bulk-trash mutation was partial.")
        if moved:
            require(integer(confirmed_at, metadata[2], MAX_ID) and all(
                integer(current[label]["deleted_at"], confirmed_at, confirmed_at + 30) for label in LABELS[:-1]),
                "Bulk-trash move does not match the confirmation time.")
    full = not retiring or checkpoint["phase"] == "verified"
    require(moved or not full, "Bulk-trash admin confirmation has not completed.")
    hashes = check_receipts(cohort, checkpoint, evidence, moved=moved, full=full)
    require(checkpoint["phase"] != "verified" or hashes == checkpoint["receipts"],
            "Bulk-trash previously verified receipt evidence changed.")
    if not retiring:
        require(cohort.epoch(cohort.authorization()) == checkpoint["authEpoch"], "Bulk-trash authorization changed during acceptance.")
    return current, evidence, hashes


def verify(cohort, checkpoint):
    _, _, hashes = observe(cohort, checkpoint, retiring=False)
    return {**checkpoint, "phase": "verified", "receipts": hashes}


def retire(cohort, checkpoint, pin, guard):
    current, evidence, hashes = observe(cohort, checkpoint, retiring=True)
    ids = [item["id"] for item in checkpoint["fixtures"].values()]
    inventory, params = cohort.inventory(ids)
    if current:
        history, history_params = cohort.history(checkpoint["afterReceiptId"])
        quiet, quiet_params = cohort.quiet(ids)
        sorted_rows = sorted(current.values(), key=lambda row: row["id"])
        steps = [
            snapshot_assert(inventory, params, ROW_FIELDS, sorted_rows),
            snapshot_assert(history, history_params, RECEIPT_FIELDS, evidence),
            statement(_assert_sql(quiet), *quiet_params),
            statement(_assert_sql(f"""NOT EXISTS(SELECT 1 FROM ({history})
              WHERE kind='preview' AND confirmed_by_receipt_id IS NULL AND expires_at>unixepoch())"""), *history_params),
            statement("DELETE FROM subscription_lifecycle WHERE subscription_id IN (SELECT value FROM json_each(?))",
                      canonical([row["id"] for row in sorted_rows if row["trashed"]])),
        ]
        for table, trashed in (("subscriptions", 0), ("subscription_trash", 1)):
            steps.append(statement(f"DELETE FROM {table} WHERE id IN (SELECT value FROM json_each(?))",
                         canonical([row["id"] for row in sorted_rows if row["trashed"] == trashed])))
        steps.append(snapshot_assert(inventory, params, ROW_FIELDS, []))
        guard()
        try:
            cohort.batch(steps)
        except (CloudflareError, FixtureError):
            # A rejected or lost batch result is safe only when exact committed absence is observed.
            pass
    remaining, _ = cohort.subscriptions(ids)
    require(not remaining and not cohort.read("""SELECT 1 FROM subscription_lifecycle
        WHERE subscription_id IN (SELECT value FROM json_each(?)) LIMIT 1""", canonical(ids)),
        "Bulk-trash retirement is unconfirmed. Wait for any unconsumed preview to expire and verify the cohort again.")
    _, _, readback = observe(cohort, checkpoint, retiring=True)
    require(readback == hashes, "Bulk-trash Telegram evidence changed during retirement.")
    return {**checkpoint, "phase": "retired", "receipts": hashes, "retiredAtReleasePin": pin}


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "Bulk-trash acceptance requires the trusted manual main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        body = event.read(65537)
    require(len(body) <= 65536, "Bulk-trash workflow event exceeds the limit.")
    action, cohort_key, source_run, source_revision = parse_inputs(_parse_object(body, "Bulk-trash workflow event differs."))
    require_current_main(revision)
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy, encoded = json.loads(raw_policy), os.environ.get("SUBS_BOT_TELEGRAM_AGGREGATE_KEY", "")
    key_bytes(encoded)
    target = _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""), "Bulk-trash resource configuration differs.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped Cloudflare credentials are required.")
    data = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), data, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    pin = {"revision": version.revision, "versionId": active.version,
           "moduleSha256": version.digest, "compatibilityDate": version.compatibility}
    validate_release_pin(pin)
    policy_sha, key_sha = digest(raw_policy.encode("utf-8")), digest(encoded.encode("ascii"))
    require(scope.cron_enabled() and version.revision == revision and version.telegram_config_sha256 == policy_sha
            and version.telegram_aggregate_key_sha256 == key_sha, "Active Worker or protected Telegram configuration differs.")
    _verify_health(revision)
    resources = Resources(target, data, None)
    identity = digest(canonical([resources.scope_hash, policy_sha, key_sha]).encode("ascii"))
    migration = digest((Path(__file__).resolve().parents[1] / "migrations" / MIGRATION).read_bytes())
    require(resources.query("SELECT position,sha256,mode FROM subs_bot_schema_migrations WHERE name=?", (MIGRATION,))
            == [{"position": 24, "sha256": migration, "mode": "applied"}], "Bulk-trash migration proof differs.")

    def guard():
        require_current_main(revision)
        require(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version
                and scope.cron_enabled(), "Isolation release changed during bulk-trash acceptance.")

    cohort = BulkCohort(resources, policy, cohort_key, encoded, identity)
    if action == "seed":
        checkpoint = seed(cohort, revision, pin, guard)
    else:
        original = source_revision or revision
        value = read_checkpoint(source_run, original, os.environ["GH_TOKEN"], workflow_file=WORKFLOW,
                                artifact_prefix=ARTIFACT_PREFIX, checkpoint_file=CHECKPOINT)
        previous = cohort.checkpoint(value, action, original, pin)
        checkpoint = verify(cohort, previous) if action == "verify" else retire(cohort, previous, pin, guard)
    guard()
    _verify_health(revision)
    save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, cohort.signed(checkpoint))
    print(json.dumps({"phase": checkpoint["phase"], "syntheticSubscriptionCount": len(LABELS),
                      "sentReceiptCount": len(checkpoint["receipts"]), "publishedSnapshotCount": 0}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CapacityError, CloudflareError, FixtureError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("The isolated Telegram bulk-trash checkpoint could not be verified.")

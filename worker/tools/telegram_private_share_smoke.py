"""Protected evidence for private shares created and claimed by the two IAB actors."""

from hashlib import sha256
from http.client import HTTPException
from io import BytesIO
import json
import os
from pathlib import Path
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import ZipFile

from capacity_resources import TARGET_KEYS, integer, matches, save_private_json
from cloudflare_isolation import (
    API_ORIGIN, DATE, DIGEST, REVISION, UUID, WORKER_NAME,
    CloudflareClient, CloudflareError, _Isolation, _NoRedirect, _verify_health,
)
from d1_migrations import _assert_sql
from prepare_isolation_artifact import (
    ArtifactError, MAIN_REF, REPOSITORY, _download, _get_json, _parse_object, _zip_members,
    require_current_main, select_main_artifact,
)
from release_isolation import telegram_release_config
from telegram_view_fixtures import FixtureError, query, rows, statement


WORKFLOW = "worker-isolation-private-share-command-smoke.yml"
ARTIFACT_PREFIX = "subs-bot-telegram-private-share"
CHECKPOINT = "telegram-private-share-checkpoint.json"
COHORT = re.compile(r"[a-f0-9]{16}")
RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
PAYLOAD_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
MAX_ID = 9_007_199_254_740_991
MAX_CHECKPOINT = 16_384
MAX_CASE_BODY = 512
MIGRATIONS = ("0005_private_shares.sql", "0007_telegram_private_claims.sql", "0016_telegram_private_share_creation.sql")
CREATE_MARKER = "share-create:v1"
CLAIM_MARKER = "claim:v1"
PURPOSE = "telegram-private-share-creation-v1"
CASES = {"targeted": ("admin", "member", 10), "race": ("member", None, 10), "expired": ("admin", None, 1)}
ROLES = {"admin": "adminId", "member": "memberId"}
HISTORY_COLUMNS = """inbox.receipt_id, inbox.bot_id, inbox.update_id, inbox.actor_id, inbox.chat_id, inbox.chat_type,
    inbox.message_id, inbox.message_date, inbox.thread_id, inbox.command, inbox.receipt_nonce, inbox.received_at,
    reply.state AS reply_state, reply.attempts AS reply_attempts, reply.sent_message_id"""
SHARE_JOIN = """share.id = creation.share_id AND share.bot_id = creation.bot_id AND share.sender_id = creation.actor_id
    AND share.sender_name = creation.sender_name AND share.payload_id = creation.payload_id
    AND share.payload_sha256 = creation.payload_sha256 AND share.payload_bytes = creation.payload_bytes
    AND share.max_claims = creation.max_claims AND share.target_user_id IS creation.target_user_id
    AND share.expire_at = share.created_at + creation.duration_minutes * 60"""
CREATION_FIELDS = ("receipt_id", "bot_id", "actor_id", "message_date", "message_id", "auth_message_date", "auth_message_id",
                   "state", "payload_id", "payload_sha256", "payload_bytes", "sender_name", "max_claims", "target_user_id",
                   "duration_minutes", "installation", "key_version", "reservation_expires_at", "next_check_at",
                   "cleanup_after", "cleaned_at", "share_id")


def require(condition, message):
    if not condition:
        raise FixtureError(message)


def fingerprint(value):
    return sha256(json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")).hexdigest()


def body_for(cohort, case):
    return f"Private share acceptance {cohort}/{case} · 合成\nSecond line.".encode("utf-8")


def body_sha(cohort, case):
    return sha256(body_for(cohort, case)).hexdigest()


def exact(value, keys):
    return isinstance(value, dict) and set(value) == set(keys)


def safe_id(value, minimum=1):
    return integer(value, minimum, MAX_ID)


def parse_observations(value):
    require(exact(value, ("codeHashes", "raceWinner", "groupShareMessageId", "groupControlMessageId")),
            "Private share IAB observation fields differ.")
    codes = value["codeHashes"]
    require(exact(codes, CASES) and all(matches(DIGEST, code) for code in codes.values())
            and len(set(codes.values())) == len(CASES) and value["raceWinner"] in ("admin", "member")
            and safe_id(value["groupShareMessageId"]) and safe_id(value["groupControlMessageId"])
            and value["groupShareMessageId"] < value["groupControlMessageId"],
            "Private share IAB observations are invalid.")
    return value


def parse_inputs(event):
    fields = event.get("inputs")
    require(isinstance(fields, dict) and set(fields) <= {"action", "cohort", "source_run_id", "observations",
                                                        "confirm_verify", "confirm_retire"},
            "Private share workflow input fields differ.")
    action, cohort = fields.get("action"), fields.get("cohort")
    source, raw, confirm = (fields.get(field, "") for field in ("source_run_id", "observations", "confirm_retire"))
    drift = action == "retire" and confirm == f"retire {cohort} on current release"
    confirm_verify = fields.get("confirm_verify", "")
    equivalent = action == "verify" and confirm_verify == f"verify {cohort} on equivalent release"
    require(action in ("prepare", "verify", "retire") and matches(COHORT, cohort)
            and (source == "" if action == "prepare" else matches(RUN_ID, source))
            and (drift or confirm == (f"retire {cohort}" if action == "retire" else ""))
            and (equivalent or confirm_verify == "")
            and (isinstance(raw, str) and 0 < len(raw) <= 1024 if action == "verify" else raw == ""),
            "Private share workflow action or confirmation differs.")
    observed = parse_observations(_parse_object(raw.encode("utf-8"), "Private share observations differ.")) if raw else None
    return action, cohort, source, observed, drift or equivalent


def read_checkpoint(run_id, token):
    run = _get_json(f"/actions/runs/{run_id}", token)
    revision = run.get("head_sha")
    workflow = _get_json(f"/actions/workflows/{WORKFLOW}", token)
    path = f".github/workflows/{WORKFLOW}"
    require(matches(REVISION, revision) and run.get("event") == "workflow_dispatch"
            and safe_id(workflow.get("id")) and workflow.get("path") == path, "Private share checkpoint source differs.")
    _, artifact_id, archive_sha = select_main_artifact(run_id, revision, token, workflow_id=workflow["id"],
        workflow_path=path, artifact_prefix=ARTIFACT_PREFIX, workflow_label="private share checkpoint")
    raw = _download(artifact_id, token)
    require(len(raw) <= MAX_CHECKPOINT and sha256(raw).hexdigest() == archive_sha, "Private share checkpoint archive differs.")
    with ZipFile(BytesIO(raw)) as archive:
        members = _zip_members(archive)
        require(set(members) == {CHECKPOINT} and members[CHECKPOINT].file_size <= MAX_CHECKPOINT,
                "Private share checkpoint inventory differs.")
        return revision, _parse_object(archive.read(members[CHECKPOINT]), "Private share checkpoint JSON differs.")


def release_pin(active, version):
    return {"revision": version.revision, "deploymentId": active.id, "versionId": active.version,
            "moduleSha256": version.digest, "compatibilityDate": version.compatibility}


def valid_release_pin(pin):
    return exact(pin, ("revision", "deploymentId", "versionId", "moduleSha256", "compatibilityDate")) \
        and matches(REVISION, pin["revision"]) and matches(UUID, pin["deploymentId"]) and matches(UUID, pin["versionId"]) \
        and matches(DIGEST, pin["moduleSha256"]) and matches(DATE, pin["compatibilityDate"])


def same_module(left, right):
    return (left["moduleSha256"], left["compatibilityDate"]) == (right["moduleSha256"], right["compatibilityDate"])


def require_successor(earlier, current, token):
    compared = _get_json(f"/compare/{earlier}...{current}", token)
    base = compared.get("merge_base_commit")
    require(compared.get("status") == "ahead" and isinstance(base, dict) and base.get("sha") == earlier,
            "Current main is not a successor of the private share checkpoint release.")


def verify_historic_release(scope, original, active_version):
    historic = scope.version(original["versionId"])
    require((historic.revision, historic.digest, historic.compatibility)
            == (original["revision"], original["moduleSha256"], original["compatibilityDate"])
            and (historic.telegram_config_sha256, historic.telegram_private_share_key_sha256, historic.telegram_aggregate_key_sha256)
            == (active_version.telegram_config_sha256, active_version.telegram_private_share_key_sha256,
                active_version.telegram_aggregate_key_sha256),
            "The historical private share Worker version or key bindings differ.")


def validate_checkpoint(checkpoint, action, cohort, source_revision, identity, pin, *, allow_drift=False, allow_equivalent=False):
    fields = {"version", "phase", "cohort", "identity", "releasePin", "baseline", "cases", "groupProof", "retiredAtReleasePin"}
    require(isinstance(checkpoint, dict) and type(checkpoint.get("version")) is int and checkpoint["version"] in (1, 2),
            "Private share checkpoint version differs.")
    newer = checkpoint["version"] == 2
    if newer:
        fields.add("verifiedAtReleasePin")
    require(exact(checkpoint, fields) and (action == "retire" or not newer)
            and (checkpoint["cohort"], checkpoint["identity"]) == (cohort, identity)
            and checkpoint["phase"] == ("prepared" if action == "verify" else "verified")
            and checkpoint["retiredAtReleasePin"] is None, "Private share checkpoint scope or phase differs.")
    original = checkpoint["releasePin"]
    predecessor = checkpoint["verifiedAtReleasePin"] if newer else original
    require(valid_release_pin(original) and valid_release_pin(predecessor) and valid_release_pin(pin)
            and predecessor["revision"] == source_revision and same_module(original, predecessor),
            "Private share checkpoint release pin differs.")
    if predecessor != pin:
        require(source_revision != pin["revision"] and ((action == "retire" and allow_drift)
                or (action == "verify" and allow_equivalent and same_module(original, pin))),
                "Private share checkpoint active release changed.")
    baseline = checkpoint["baseline"]
    require(exact(baseline, ("receiptId", "shareId", "dbTime", "authSha256"))
            and safe_id(baseline["receiptId"], 0) and safe_id(baseline["shareId"], 0)
            and safe_id(baseline["dbTime"]) and matches(DIGEST, baseline["authSha256"]),
            "Private share checkpoint baseline differs.")
    if action == "verify":
        require(checkpoint["cases"] == {} and checkpoint["groupProof"] is None, "Prepared private share checkpoint is populated.")
        return
    group = checkpoint["groupProof"]
    if newer:
        require(exact(group, ("chatType", "shareMessageId", "controlMessageId", "controlReceiptSha256"))
                and group["chatType"] in ("group", "supergroup") and safe_id(group["shareMessageId"])
                and safe_id(group["controlMessageId"]) and group["shareMessageId"] < group["controlMessageId"]
                and matches(DIGEST, group["controlReceiptSha256"]), "Private share group evidence differs.")
    else:
        require(matches(DIGEST, group), "Private share group evidence differs.")
    require(exact(checkpoint["cases"], CASES), "Private share case inventory differs.")
    for case in checkpoint["cases"].values():
        require(exact(case, ("receiptId", "shareId", "payloadId", "codeSha256", "expireAt", "cleanupAfter",
                             "rowSha256", "historySha256", "claimCount"))
                and safe_id(case["receiptId"], baseline["receiptId"] + 1) and safe_id(case["shareId"], baseline["shareId"] + 1)
                and matches(PAYLOAD_ID, case["payloadId"]) and matches(DIGEST, case["codeSha256"])
                and safe_id(case["expireAt"], baseline["dbTime"]) and safe_id(case["cleanupAfter"], baseline["dbTime"])
                and matches(DIGEST, case["rowSha256"]) and matches(DIGEST, case["historySha256"]),
                "Private share checkpoint row identity differs.")
    for field in ("receiptId", "shareId", "payloadId", "codeSha256"):
        require(len({case[field] for case in checkpoint["cases"].values()}) == len(CASES), "Private share checkpoint identities overlap.")
    require(all(type(case["claimCount"]) is int and case["claimCount"] == int(name != "expired")
                for name, case in checkpoint["cases"].items()), "Private share checkpoint claim counts differ.")


class Objects:
    def __init__(self, api, account, token):
        self.api = api
        self.path = f"{account}/r2/buckets/{WORKER_NAME}/objects"
        self.token = token
        self.opener = build_opener(ProxyHandler({}), _NoRedirect())

    @staticmethod
    def key(payload_id):
        require(matches(PAYLOAD_ID, payload_id), "Invalid private share payload identity.")
        return f"private-shares/{payload_id}.txt"

    def request(self, method, payload_id):
        require(method in ("GET", "DELETE"), "Invalid private share object method.")
        request = Request(API_ORIGIN + self.path + "/" + self.key(payload_id), method=method,
                          headers={"Authorization": "Bearer " + self.token, "cf-r2-jurisdiction": "default",
                                   "Accept-Encoding": "identity"})
        try:
            with self.opener.open(request, timeout=25) as response:
                body = response.read(MAX_CASE_BODY + 1 if method == "GET" else 4097)
        except HTTPError as error:
            error.close()
            if error.code == 404:
                return None
            raise CloudflareError("Private share R2 request failed.", uncertain=method == "DELETE") from None
        except (OSError, ValueError, HTTPException):
            raise CloudflareError("Private share R2 request could not be confirmed.", uncertain=method == "DELETE") from None
        if method == "DELETE":
            require(len(body) <= 4096, "Private share R2 deletion response exceeds the limit.")
            return None
        require(0 < len(body) <= MAX_CASE_BODY, "Private share R2 object size differs.")
        return body

    def check(self, payload_id, receipt_id, expected, *, missing=False):
        key = self.key(payload_id)
        current = self.request("GET", payload_id)
        listed = self.api("GET", self.path + "?" + urlencode({"prefix": key, "per_page": 2}))
        require(isinstance(listed, list), "Private share object metadata is unavailable.")
        if current is None and missing:
            require(listed == [], "Private share object absence could not be confirmed.")
            return False
        require(current == expected and len(listed) == 1 and isinstance(listed[0], dict)
                and listed[0].get("key") == key and listed[0].get("size") == len(expected)
                and listed[0].get("custom_metadata") == {"purpose": PURPOSE, "receipt": str(receipt_id)},
                "Private share object bytes or ownership differ.")
        return True


class Cohort:
    def __init__(self, api, path, objects, policy, cohort):
        self.api, self.path, self.objects, self.policy, self.cohort = api, path, objects, policy, cohort
        self.bot = policy["botId"]

    def read(self, sql, *bindings):
        return rows(self.api, self.path, sql, *bindings)

    def actor(self, role):
        return self.policy[ROLES[role]] if role is not None else None

    def auth(self):
        result = self.read("SELECT user_id,allowed,message_date,message_id FROM telegram_auth WHERE bot_id=? AND user_id IN (?,?) ORDER BY user_id",
                           self.bot, self.actor("admin"), self.actor("member"))
        require(all(row["user_id"] == self.actor("member") and row["allowed"] == 1 and safe_id(row["message_date"])
                    and safe_id(row["message_id"]) for row in result) and len(result) <= 1,
                "Private share IAB actors are not in the expected authorization state.")
        return result

    def prepare(self, identity, pin):
        baseline, = self.read("""SELECT unixepoch() AS dbTime, COALESCE((SELECT max(receipt_id) FROM telegram_inbox),0) AS receiptId,
            COALESCE((SELECT max(id) FROM private_shares),0) AS shareId""")
        for case in (*CASES, "group"):
            require(not self.read("SELECT 1 FROM telegram_private_share_creations WHERE bot_id=? AND payload_sha256=? LIMIT 1",
                                  self.bot, body_sha(self.cohort, case)), "Private share cohort body already exists.")
        return {"version": 1, "phase": "prepared", "cohort": self.cohort, "identity": identity, "releasePin": pin,
                "baseline": {**baseline, "authSha256": fingerprint(self.auth())}, "cases": {},
                "groupProof": None, "retiredAtReleasePin": None}

    def creation(self, case, receipt_min, *, receipt_id=None):
        actor = self.actor(CASES[case][0])
        exact_receipt = "AND creation.receipt_id=CAST(? AS INTEGER)" if receipt_id is not None else ""
        return self.read(f"""SELECT creation.*, share.id AS published_id, share.code_sha256, share.created_at, share.expire_at,
                inbox.received_at FROM telegram_private_share_creations AS creation
            JOIN telegram_inbox AS inbox ON inbox.receipt_id=creation.receipt_id
            LEFT JOIN private_shares AS share ON {SHARE_JOIN}
            WHERE creation.bot_id=? AND creation.actor_id=? AND creation.payload_sha256=?
                AND creation.receipt_id>CAST(? AS INTEGER) {exact_receipt} LIMIT 2""",
            self.bot, actor, body_sha(self.cohort, case), receipt_min, *((receipt_id,) if receipt_id is not None else ()))

    def receipt(self, receipt_id):
        return self.read(f"""SELECT {HISTORY_COLUMNS} FROM telegram_inbox AS inbox
            JOIN telegram_outbox AS reply USING(receipt_id) WHERE inbox.receipt_id=CAST(? AS INTEGER) AND inbox.bot_id=?""",
            receipt_id, self.bot)

    def claim_history(self, code_sha):
        return self.read(f"""SELECT {HISTORY_COLUMNS}, claim.code_sha256 FROM telegram_private_claim AS claim
            JOIN telegram_inbox AS inbox USING(receipt_id) JOIN telegram_outbox AS reply USING(receipt_id)
            WHERE inbox.bot_id=? AND claim.code_sha256=? ORDER BY inbox.receipt_id LIMIT 4""", self.bot, code_sha)

    def private_receipt(self, receipt, actor, marker, baseline):
        require(receipt["bot_id"] == self.bot and receipt["actor_id"] == receipt["chat_id"] == actor
                and receipt["chat_type"] == "private" and receipt["thread_id"] is None
                and receipt["receipt_nonce"] == marker and receipt["command"] == "help"
                and receipt["reply_state"] == "sent" and safe_id(receipt["sent_message_id"])
                and integer(receipt["reply_attempts"], 1, 4) and safe_id(receipt["receipt_id"], baseline["receiptId"] + 1)
                and safe_id(receipt["received_at"], baseline["dbTime"]) and safe_id(receipt["message_date"]),
                "Private share receipt or reply scope differs.")

    def claims(self, share_id):
        return self.read("SELECT actor_id,claimed_at FROM private_share_claims WHERE share_id=CAST(? AS INTEGER) ORDER BY actor_id LIMIT 2", share_id)

    def group_proof(self, observed, baseline):
        scope = f"""SELECT {HISTORY_COLUMNS} FROM telegram_inbox AS inbox
            LEFT JOIN telegram_outbox AS reply USING(receipt_id) WHERE inbox.bot_id=? AND inbox.chat_id=?"""
        bindings = (self.bot, self.policy["groupId"])
        recent = self.read(scope + " AND inbox.receipt_id>CAST(? AS INTEGER) ORDER BY inbox.receipt_id LIMIT 2",
                           *bindings, baseline["receiptId"])

        def lookup(message_id):
            return self.read(scope + " AND inbox.message_id=CAST(? AS INTEGER) LIMIT 2", *bindings, message_id)

        if any(row["chat_type"] == "group" for row in recent):
            # Basic groups assign IDs within each account. The sole new scoped
            # receipt must be the control. IAB keeps both local message IDs.
            require(len(recent) == 1, "The approved basic group has unexpected additional receipts.")
            control, chat_type = recent, "group"
        else:
            require(lookup(observed["groupShareMessageId"]) == [], "The private share command left a group receipt.")
            control, chat_type = lookup(observed["groupControlMessageId"]), "supergroup"
        require(len(control) == 1 and control[0]["actor_id"] == self.actor("admin") and control[0]["thread_id"] is None
                and control[0]["chat_type"] == chat_type and control[0]["command"] == "help"
                and control[0]["receipt_nonce"] is None and control[0]["reply_state"] == "sent"
                and safe_id(control[0]["sent_message_id"]) and safe_id(control[0]["receipt_id"], baseline["receiptId"] + 1)
                and safe_id(control[0]["received_at"], baseline["dbTime"]), "The approved group control reply could not be confirmed.")
        require(not self.read("SELECT 1 FROM telegram_private_share_creations WHERE bot_id=? AND payload_sha256=? LIMIT 1",
                              self.bot, body_sha(self.cohort, "group")), "The private group body was persisted.")
        return {"chatType": chat_type, "shareMessageId": observed["groupShareMessageId"],
                "controlMessageId": observed["groupControlMessageId"], "controlReceiptSha256": fingerprint(control)}

    def verify_case(self, name, observed, baseline, auth):
        creator, target, duration = CASES[name]
        code_sha = observed["codeHashes"][name]
        records = self.creation(name, baseline["receiptId"])
        require(len(records) == 1, "Expected exactly one private share creation per case.")
        row = records[0]
        require(row["state"] == "published" and row["share_id"] == row["published_id"]
                and safe_id(row["share_id"], baseline["shareId"] + 1) and matches(PAYLOAD_ID, row["payload_id"])
                and row["code_sha256"] == code_sha and row["max_claims"] == 1
                and row["target_user_id"] == self.actor(target) and row["duration_minutes"] == duration
                and row["installation"] == WORKER_NAME and row["key_version"] == 1 and row["cleaned_at"] is None
                and row["payload_bytes"] == len(body_for(self.cohort, name))
                and safe_id(row["created_at"], row["received_at"])
                and row["expire_at"] == row["created_at"] + 60 * duration
                and row["reservation_expires_at"] == row["received_at"] + 600
                and row["cleanup_after"] == row["reservation_expires_at"] + 1200,
                "Private share publication, options, or natural lifetime differs.")
        epoch = (auth[0]["message_date"], auth[0]["message_id"]) if creator == "member" and auth else (0, 0)
        require((row["auth_message_date"], row["auth_message_id"]) == epoch, "Private share creation authorization epoch differs.")
        receipt, = self.receipt(row["receipt_id"])
        self.private_receipt(receipt, self.actor(creator), CREATE_MARKER, baseline)
        require((row["message_date"], row["message_id"]) == (receipt["message_date"], receipt["message_id"]),
                "Private share command receipt does not match publication.")
        histories = self.claim_history(code_sha)
        expected = {"targeted": ["admin", "member", "member"], "race": ["admin", "member"], "expired": ["member"]}[name]
        by_actor = {self.actor(role): role for role in ROLES}
        observed_roles = [by_actor.get(item["actor_id"]) for item in histories]
        require((sorted(observed_roles) if name == "race" and all(observed_roles) else observed_roles) == expected,
                "Private share claim receipt counts, actors, or order differ.")
        for item in histories:
            self.private_receipt(item, item["actor_id"], CLAIM_MARKER, baseline)
        require(all(item["receipt_id"] > row["receipt_id"] for item in histories), "A private claim predates creation.")
        claims = self.claims(row["share_id"])
        if name == "expired":
            require(claims == [] and histories[0]["message_date"] > row["expire_at"]
                    and histories[0]["received_at"] > row["expire_at"], "Private share expiry was not observed naturally.")
        else:
            winner = "member" if name == "targeted" else observed["raceWinner"]
            winning_receipt = next(item for item in histories if item["actor_id"] == self.actor(winner))
            require(len(claims) == 1 and claims[0]["actor_id"] == self.actor(winner)
                    and winning_receipt["received_at"] <= claims[0]["claimed_at"] <= row["expire_at"]
                    and all(item["received_at"] <= row["expire_at"] for item in histories),
                    "Private share unique claim or observed race winner differs.")
            if name == "targeted":
                require(histories[1]["message_id"] < histories[2]["message_id"] and claims[0]["claimed_at"] <= histories[2]["received_at"],
                        "Private share repeat is not a later independent Telegram message.")
            else:
                require(abs(histories[0]["message_date"] - histories[1]["message_date"]) <= 5,
                        "Private share race submissions are outside the five-second observation window.")
        self.objects.check(row["payload_id"], row["receipt_id"], body_for(self.cohort, name))
        return {"receiptId": row["receipt_id"], "shareId": row["share_id"], "payloadId": row["payload_id"],
                "codeSha256": code_sha, "expireAt": row["expire_at"], "cleanupAfter": row["cleanup_after"],
                "rowSha256": fingerprint([row, claims]), "historySha256": fingerprint([receipt, histories]), "claimCount": len(claims)}

    def verify(self, checkpoint, observed, pin):
        baseline = checkpoint["baseline"]
        auth = self.auth()
        require(fingerprint(auth) == baseline["authSha256"], "Private share IAB authorization changed during acceptance.")
        cases = {name: self.verify_case(name, observed, baseline, auth) for name in CASES}
        group = self.group_proof(observed, baseline)
        require(self.auth() == auth, "Private share IAB authorization changed during verification.")
        return {**checkpoint, "version": 2, "phase": "verified", "cases": cases, "groupProof": group, "verifiedAtReleasePin": pin}

    def unreferenced(self, item):
        return not self.read("""SELECT 1 FROM private_shares WHERE id=CAST(? AS INTEGER) OR payload_id=? OR (bot_id=? AND code_sha256=?)
            UNION ALL SELECT 1 FROM telegram_private_share_creations
                WHERE receipt_id=CAST(? AS INTEGER) OR payload_id=? OR share_id=CAST(? AS INTEGER)
            UNION ALL SELECT 1 FROM private_share_claims WHERE share_id=CAST(? AS INTEGER) LIMIT 1""",
            item["shareId"], item["payloadId"], self.bot, item["codeSha256"],
            item["receiptId"], item["payloadId"], item["shareId"], item["shareId"])

    def history(self, item):
        receipt = self.receipt(item["receiptId"])
        claims = self.claim_history(item["codeSha256"])
        require(len(receipt) == 1 and fingerprint([receipt[0], claims]) == item["historySha256"],
                "Private share real receipt history differs.")

    def retirement_batch(self, records):
        batch = []
        for row, claims in records:
            terms, parameters = [], []
            for field in CREATION_FIELDS:
                value = row[field]
                if value is None:
                    terms.append(f"creation.{field} IS NULL")
                else:
                    terms.append(f"creation.{field} IS " + ("CAST(? AS INTEGER)" if type(value) is int else "?"))
                    parameters.append(value)
            exact_creation = " AND ".join(terms)
            batch.append(statement(_assert_sql(f"""EXISTS (SELECT 1 FROM telegram_private_share_creations AS creation
                JOIN private_shares AS share ON {SHARE_JOIN} JOIN telegram_outbox AS reply USING(receipt_id)
                WHERE {exact_creation} AND share.code_sha256=? AND share.created_at=CAST(? AS INTEGER)
                    AND share.expire_at=CAST(? AS INTEGER) AND share.expire_at<unixepoch()
                    AND creation.cleanup_after<=unixepoch() AND reply.state='sent')
                AND (SELECT count(*) FROM private_share_claims WHERE share_id=CAST(? AS INTEGER))=CAST(? AS INTEGER)"""),
                *parameters, row["code_sha256"], row["created_at"], row["expire_at"], row["share_id"], len(claims)))
            for claim in claims:
                batch.append(statement("DELETE FROM private_share_claims WHERE share_id=CAST(? AS INTEGER) AND actor_id=? AND claimed_at=CAST(? AS INTEGER)",
                                       row["share_id"], claim["actor_id"], claim["claimed_at"]))
                batch.append(statement(_assert_sql("changes()=1")))
            batch.extend((
                statement("DELETE FROM telegram_private_share_creations WHERE receipt_id=CAST(? AS INTEGER) AND share_id=CAST(? AS INTEGER) AND state='published'",
                          row["receipt_id"], row["share_id"]),
                statement(_assert_sql("changes()=1")),
                statement("DELETE FROM private_shares WHERE id=CAST(? AS INTEGER) AND bot_id=? AND payload_id=? AND code_sha256=? AND expire_at<unixepoch()",
                          row["share_id"], self.bot, row["payload_id"], row["code_sha256"]),
                statement(_assert_sql("changes()=1")),
            ))
        return batch

    def retire(self, checkpoint, guard, pin):
        cases = checkpoint["cases"]
        now, = self.read("SELECT unixepoch() AS now")
        # Keep the creation-order fence until delayed updates are outside the
        # admission window and old conditional PUTs have had the full grace.
        require(all(now["now"] > item["expireAt"] and now["now"] >= item["cleanupAfter"] for item in cases.values()),
                "Private share retirement must wait for expiry and the reservation cleanup grace.")
        records = []
        for name, item in cases.items():
            self.history(item)
            if self.unreferenced(item):
                self.objects.check(item["payloadId"], item["receiptId"], body_for(self.cohort, name), missing=True)
                continue
            found = self.creation(name, checkpoint["baseline"]["receiptId"], receipt_id=item["receiptId"])
            claims = self.claims(item["shareId"])
            require(len(found) == 1 and fingerprint([found[0], claims]) == item["rowSha256"],
                    "Private share retirement row or claim identity differs.")
            self.objects.check(item["payloadId"], item["receiptId"], body_for(self.cohort, name))
            records.append((found[0], claims))
        require(len(records) in (0, len(CASES)), "Private share D1 retirement has a partial state.")
        if records:
            batch = self.retirement_batch(records)
            guard()
            try:
                query(self.api, self.path, {"batch": batch}, len(batch))
            except (CloudflareError, FixtureError):
                pass  # Read back the exact cohort before considering any object deletion.
        require(all(self.unreferenced(item) for item in cases.values()), "Private share D1 retirement could not be confirmed.")
        for name, item in cases.items():
            self.history(item)
            expected = body_for(self.cohort, name)
            if self.objects.check(item["payloadId"], item["receiptId"], expected, missing=True):
                guard()
                require(self.unreferenced(item), "Private share object still has a D1 reference.")
                try:
                    self.objects.request("DELETE", item["payloadId"])
                except CloudflareError:
                    pass  # A lost response is reconciled by scoped object readback.
                require(not self.objects.check(item["payloadId"], item["receiptId"], expected, missing=True),
                        "Private share R2 retirement could not be confirmed.")
        require(all(self.unreferenced(item) for item in cases.values()), "Private share retirement readback differs.")
        return {**checkpoint, "phase": "retired", "retiredAtReleasePin": pin}


def run():
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == MAIN_REF and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch",
            "Private share acceptance requires a trusted manual main workflow.")
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as event:
        raw = event.read(65_537)
    require(len(raw) <= 65_536, "Private share workflow event exceeds the limit.")
    action, cohort, source, observed, allow_release_change = parse_inputs(_parse_object(raw, "Private share workflow event differs."))
    require_current_main(revision)
    source_revision, checkpoint = read_checkpoint(source, os.environ["GH_TOKEN"]) if source else (None, None)
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy, target = json.loads(raw_policy), _parse_object(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", ""),
                                                          "Private share isolation target differs.")
    require(exact(target, TARGET_KEYS), "Private share isolation target fields differ.")
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token, "Separate scoped Cloudflare credentials are required.")
    api = CloudflareClient(data_token)
    scope = _Isolation(CloudflareClient(deploy_token), api, target)
    config = scope.worker_config()
    scope.verify_resources()
    active = scope.active()
    version = scope.version(active.version)
    pin = release_pin(active, version)
    policy_sha = sha256(raw_policy.encode("utf-8")).hexdigest()
    key_sha = version.telegram_private_share_key_sha256
    require(valid_release_pin(pin) and version.revision == revision and version.telegram_config_sha256 == policy_sha
            and matches(DIGEST, key_sha) and scope.cron_enabled(), "Active Worker, Telegram policy, or private share key differs.")
    _verify_health(revision)
    path = f"{scope.account}/d1/database/{target['d1Id']}"
    ledger = []
    for name in MIGRATIONS:
        expected = sha256((Path(__file__).resolve().parents[1] / "migrations" / name).read_bytes()).hexdigest()
        entry = {"position": int(name[:4]), "name": name, "sha256": expected, "mode": "applied"}
        require(rows(api, path, "SELECT position,name,sha256,mode FROM subs_bot_schema_migrations WHERE name=?", name) == [entry],
                "Private share migration proof differs.")
        ledger.append(entry)
    identity = fingerprint([target, policy_sha, key_sha, ledger])

    def guard():
        require_current_main(revision)
        scope.verify_resources()
        require(scope.active() == active and scope.worker_config() == config and scope.version(active.version) == version
                and scope.cron_enabled(), "Isolation release changed during private share acceptance.")

    verifier = Cohort(api, path, Objects(api, scope.account, data_token), policy, cohort)
    if action == "prepare":
        checkpoint = verifier.prepare(identity, pin)
    else:
        validate_checkpoint(checkpoint, action, cohort, source_revision, identity, pin,
                            allow_drift=action == "retire" and allow_release_change,
                            allow_equivalent=action == "verify" and allow_release_change)
        if source_revision != revision:
            require_successor(source_revision, revision, os.environ["GH_TOKEN"])
            if action == "verify":
                verify_historic_release(scope, checkpoint["releasePin"], version)
        checkpoint = verifier.verify(checkpoint, observed, pin) if action == "verify" else verifier.retire(checkpoint, guard, pin)
    guard()
    _verify_health(revision)
    save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, checkpoint)
    verified = checkpoint["phase"] != "prepared"
    print(json.dumps({"phase": checkpoint["phase"], "creationReceipts": len(checkpoint["cases"]),
                      "claimReceipts": 6 if verified else 0,
                      "claimRowsObserved": sum(item["claimCount"] for item in checkpoint["cases"].values()),
                      "groupControlReceipts": 1 if verified else None, "groupShareReceipts": 0 if verified else None,
                      "verifiedObjects": 3 if checkpoint["phase"] == "verified" else 0,
                      "retiredObjects": 3 if checkpoint["phase"] == "retired" else 0,
                      "retireNotBefore": max((max(item["cleanupAfter"], item["expireAt"] + 1)
                                              for item in checkpoint["cases"].values()), default=None)}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except (ArtifactError, CloudflareError, FixtureError) as error:
        sys.exit(str(error))
    except Exception:
        sys.exit("Isolated private share acceptance could not be verified.")

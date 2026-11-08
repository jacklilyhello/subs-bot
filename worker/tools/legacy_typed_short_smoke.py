"""Exercise the live 0029 redirect contract with one synthetic D1 subscription."""

from base64 import urlsafe_b64encode
import hmac
from time import sleep
from urllib.error import HTTPError
from urllib.request import Request

from capacity_resources import integer
from cloudflare_isolation import CloudflareError, ORIGIN
from telegram_aggregate_smoke import MAX_ID, SUBSCRIPTION_FIELDS, canonical, digest, require
from telegram_bulk_trash_smoke import snapshot_assert
from telegram_view_fixtures import FixtureError, query, statement


ERROR = "The isolated typed short-link fixture could not be verified."
OWNER = "9223372036854775807"
FOREIGN_OWNER = "9223372036854775806"
BOT = "9223372036854775805"
STAMP = 1_700_000_000
EXTERNAL_CONTROL = "https://example.com/typed-short-fixture"
FORMATS = {"default": "", "surge": "surge", "mixed": "mixed"}
DENIED = ("wrong-owner", "wrong-token", "revoked", "normal-conflict", "aggregate-conflict")
EXPECTED_CLASH = ("proxies: []\nproxy-groups:\n- name: 🚀 节点选择\n  type: select\n  proxies:\n  - DIRECT\n"
                  "- name: ♻️ 自动选择\n  type: url-test\n  proxies:\n  - DIRECT\n"
                  "  url: http://www.gstatic.com/generate_204\n  interval: 300\nrules:\n- MATCH,🚀 节点选择\n").encode("utf-8")
SUB_FIELDS = tuple(SUBSCRIPTION_FIELDS.split(","))
FIELDS = {
    "subscription": (*SUB_FIELDS, "trashed", "deleted_at", "trash_revision"),
    "lifecycle": ("subscription_id", "revision"),
    "marker": ("subscription_id", "owner_id", "token_sha256"),
    "typed": ("code_sha256", "bot_id", "owner_id", "subscription_id", "token_sha256", "format", "created_at", "revoked_at"),
    "normal": ("code_sha256", "code_length", "bot_id", "owner_id", "origin_receipt_id", "nonce", "key_version",
               "target_url", "created_at", "revoked_at"),
    "aggregate": ("code_sha256", "owner_id", "kind", "bot_id", "selected_ids", "created_at", "revoked_at"),
}


class TypedShortFixtures:
    def __init__(self, resources, policy, key, cohort):
        require({OWNER, FOREIGN_OWNER, BOT}.isdisjoint(policy[field] for field in ("adminId", "memberId", "botId")), ERROR)
        self.resources = resources
        self.source = f"https://subs-bot-typed-short-fixtures.invalid/{cohort}/subscription"
        self.name = f"typed-short-fixture-{cohort}"

        def derive(label):
            return hmac.digest(key, canonical(["subs-bot/typed-short-smoke/v1", resources.scope_hash, cohort, label]).encode("ascii"), "sha256")

        self.token = derive("token").hex()
        self.token_digest = digest(self.token.encode("ascii"))
        self.wrong_token_digest = digest(derive("wrong-token-digest").hex().encode("ascii"))
        self.codes = {label: urlsafe_b64encode(derive(label)[:9]).decode("ascii") for label in (*FORMATS, *DENIED)}
        self.hashes = {label: digest(code.encode("ascii")) for label, code in self.codes.items()}
        require(len(set(self.hashes.values())) == len(self.hashes), ERROR)

    def inventory(self, sid):
        criteria = "id=CAST(? AS INTEGER) OR token=? OR name=? OR source_url=?"
        sub_params = (sid, self.token, self.name, self.source)
        hashes = canonical(sorted(self.hashes.values()))
        matching_hash = "code_sha256 IN (SELECT value FROM json_each(?))"
        return {
            "subscription": (f"""SELECT {SUBSCRIPTION_FIELDS},0 AS trashed,NULL AS deleted_at,NULL AS trash_revision
              FROM subscriptions WHERE {criteria} UNION ALL
              SELECT {SUBSCRIPTION_FIELDS},1,deleted_at,lifecycle_revision FROM subscription_trash WHERE {criteria}
              ORDER BY id,trashed LIMIT 3""", (*sub_params, *sub_params)),
            "lifecycle": ("SELECT subscription_id,revision FROM subscription_lifecycle WHERE subscription_id=CAST(? AS INTEGER)", (sid,)),
            "marker": ("""SELECT subscription_id,owner_id,token_sha256 FROM legacy_empty_subscription_exports
              WHERE subscription_id=CAST(? AS INTEGER) OR token_sha256=? ORDER BY subscription_id LIMIT 3""", (sid, self.token_digest)),
            "typed": (f"""SELECT {','.join(FIELDS['typed'])} FROM legacy_subscription_short_links
              WHERE ({matching_hash}) OR subscription_id=CAST(? AS INTEGER) ORDER BY code_sha256 LIMIT 9""", (hashes, sid)),
            "normal": (f"SELECT {','.join(FIELDS['normal'])} FROM normal_short_links WHERE {matching_hash} ORDER BY code_sha256", (hashes,)),
            "aggregate": (f"SELECT {','.join(FIELDS['aggregate'])} FROM aggregate_links WHERE {matching_hash} ORDER BY code_sha256", (hashes,)),
        }

    def expected(self, sid, stage):
        rows = {kind: [] for kind in FIELDS}
        if stage == "absent":
            return rows
        trashed = stage == "trash"
        rows["subscription"] = [dict.fromkeys(FIELDS["subscription"]) | {
            "id": sid, "owner_id": OWNER, "name": self.name, "source_url": self.source, "token": self.token,
            "created_at": STAMP, "updated_at": STAMP, "generation": 0, "node_count": 0, "trashed": int(trashed),
            "deleted_at": STAMP if trashed else None, "trash_revision": 1 if trashed else None,
        }]
        if stage != "seed":
            rows["lifecycle"] = [{"subscription_id": sid, "revision": 1 if trashed else 2}]
        rows["marker"] = [{"subscription_id": sid, "owner_id": OWNER, "token_sha256": self.token_digest}]
        for label in sorted(self.hashes, key=self.hashes.get):
            revoked = label == "revoked"
            token_digest = self.wrong_token_digest if label == "wrong-token" else self.token_digest
            rows["typed"].append({
                "code_sha256": self.hashes[label], "bot_id": BOT, "owner_id": FOREIGN_OWNER if label == "wrong-owner" else OWNER,
                "subscription_id": None if revoked else sid,
                "token_sha256": None if revoked else token_digest,
                "format": None if revoked else FORMATS.get(label, "surge"), "created_at": STAMP, "revoked_at": STAMP if revoked else None,
            })
        rows["normal"] = [dict.fromkeys(FIELDS["normal"]) | {
            "code_sha256": self.hashes["normal-conflict"], "code_length": 12, "bot_id": BOT, "owner_id": OWNER,
            "target_url": EXTERNAL_CONTROL, "created_at": STAMP,
        }]
        rows["aggregate"] = [dict.fromkeys(FIELDS["aggregate"]) | {
            "code_sha256": self.hashes["aggregate-conflict"], "owner_id": OWNER, "kind": "selected",
            "selected_ids": canonical([sid]), "created_at": STAMP,
        }]
        return rows

    def observe(self, sid=0):
        if not sid:
            sql, params = self.inventory(0)["subscription"]
            matches = self.resources.query(sql, params)
            if matches:
                require(len(matches) == 1 and integer(matches[0]["id"], 1, MAX_ID), ERROR)
                sid = matches[0]["id"]
        inventory = self.inventory(sid)
        responses = query(self.resources.api, self.resources.database, {"batch": [
            statement(sql, *params) for sql, params in inventory.values()
        ]}, len(inventory))
        actual = {kind: result["results"] for kind, result in zip(inventory, responses)}
        for stage in ("absent", "seed", "trash", "restored"):
            if actual == self.expected(sid, stage):
                return sid, stage
        raise FixtureError(ERROR)

    def assertions(self, sid, stage):
        expected = self.expected(sid, stage)
        return [snapshot_assert(sql, params, FIELDS[kind], expected[kind])
                for kind, (sql, params) in self.inventory(sid).items()]

    def apply(self, operations, guard, sid, before, after):
        guard()
        ambiguous = False
        try:
            query(self.resources.api, self.resources.database, {"batch": operations}, len(operations))
        except (CloudflareError, FixtureError):
            # Never resubmit the mutation. A lost acknowledgement is reconciled only by exact readback.
            ambiguous = True
        for attempt in range(3 if ambiguous else 1):
            if attempt:
                sleep(attempt)
            actual_id, stage = self.observe(sid)
            if stage == after and (sid or actual_id):
                return actual_id
            require(stage == before, ERROR)
        raise FixtureError(ERROR)

    def seed(self, guard):
        require(self.observe() == (0, "absent"), ERROR)
        # Each child selects the exact subscription allocated by the first statement in this batch.
        target = "SELECT id FROM subscriptions WHERE owner_id=? AND name=? AND source_url=? AND token=?"
        identity = (OWNER, self.name, self.source, self.token)
        operations = [*self.assertions(0, "absent"), statement(
            "INSERT INTO subscriptions (owner_id,name,source_url,token,created_at,updated_at) VALUES (?,?,?,?,?,?)", *identity, STAMP, STAMP)]
        operations.append(statement(f"""INSERT INTO legacy_empty_subscription_exports (subscription_id,owner_id,token_sha256)
            SELECT id,?,? FROM ({target})""", OWNER, self.token_digest, *identity))
        expected = self.expected(1, "seed")
        for row in expected["typed"]:
            operations.append(statement(f"""INSERT INTO legacy_subscription_short_links ({','.join(FIELDS['typed'])})
                SELECT ?,?,?,CASE WHEN CAST(? AS INTEGER)=1 THEN NULL ELSE id END,NULLIF(?, '-'),NULLIF(?, '-'),
                  CAST(? AS INTEGER),NULLIF(CAST(? AS INTEGER),0) FROM ({target})""",
                row["code_sha256"], BOT, row["owner_id"], int(row["revoked_at"] is not None), row["token_sha256"] or "-",
                row["format"] if row["format"] is not None else "-", STAMP, row["revoked_at"] or 0, *identity))
        operations.extend((
            statement("""INSERT INTO normal_short_links (code_sha256,code_length,bot_id,owner_id,target_url,created_at)
                VALUES (?,12,?,?,?,?)""", self.hashes["normal-conflict"], BOT, OWNER, EXTERNAL_CONTROL, STAMP),
            statement(f"""INSERT INTO aggregate_links (code_sha256,owner_id,kind,selected_ids,created_at)
                SELECT ?,?,'selected',json_array(id),CAST(? AS INTEGER) FROM ({target})""",
                self.hashes["aggregate-conflict"], OWNER, STAMP, *identity),
        ))
        return self.apply(operations, guard, 0, "absent", "seed")

    def move(self, sid, to_trash, guard):
        before, after = ("seed", "trash") if to_trash else ("trash", "restored")
        operations = self.assertions(sid, before)
        if to_trash:
            operations.extend((
                statement(f"""INSERT INTO subscription_trash ({SUBSCRIPTION_FIELDS},deleted_at,lifecycle_revision)
                    SELECT {SUBSCRIPTION_FIELDS},CAST(? AS INTEGER),1 FROM subscriptions WHERE id=CAST(? AS INTEGER)""", STAMP, sid),
                statement("DELETE FROM subscriptions WHERE id=CAST(? AS INTEGER)", sid),
                statement("INSERT INTO subscription_lifecycle (subscription_id,revision) VALUES (CAST(? AS INTEGER),1)", sid),
            ))
        else:
            operations.extend((
                statement(f"""INSERT INTO subscriptions ({SUBSCRIPTION_FIELDS})
                    SELECT {SUBSCRIPTION_FIELDS} FROM subscription_trash WHERE id=CAST(? AS INTEGER)""", sid),
                statement("DELETE FROM subscription_trash WHERE id=CAST(? AS INTEGER)", sid),
                statement("UPDATE subscription_lifecycle SET revision=2 WHERE subscription_id=CAST(? AS INTEGER)", sid),
            ))
        return self.apply([*operations, *self.assertions(sid, after)], guard, sid, before, after)

    def retire(self, guard, sid=0):
        sid, stage = self.observe(sid)
        if stage == "absent":
            return 0
        operations = self.assertions(sid, stage)
        for table, hashes in (
            ("normal_short_links", [self.hashes["normal-conflict"]]),
            ("aggregate_links", [self.hashes["aggregate-conflict"]]),
            ("legacy_subscription_short_links", list(self.hashes.values())),
        ):
            operations.append(statement(f"DELETE FROM {table} WHERE code_sha256 IN (SELECT value FROM json_each(?))", canonical(hashes)))
        table = "subscription_trash" if stage == "trash" else "subscriptions"
        operations.extend((
            statement(f"DELETE FROM {table} WHERE id=CAST(? AS INTEGER) AND owner_id=? AND token=?", sid, OWNER, self.token),
            statement("DELETE FROM legacy_empty_subscription_exports WHERE subscription_id=CAST(? AS INTEGER) AND token_sha256=?", sid, self.token_digest),
            statement("DELETE FROM subscription_lifecycle WHERE subscription_id=CAST(? AS INTEGER)", sid),
        ))
        self.apply([*operations, *self.assertions(sid, "absent")], guard, sid, stage, "absent")
        return 1


def request_short(opener, path, method):
    request = Request(ORIGIN + path, method=method, headers={
        "Cache-Control": "no-cache", "Accept-Encoding": "identity", "User-Agent": "subs-bot-isolation-release/1.0",
    })
    try:
        response = opener.open(request, timeout=8)
    except HTTPError as error:
        response = error
    with response:
        headers = response.headers
        body = response.read(4097)
        require(len(body) <= 4096 and headers.get("Cache-Control") == "private, no-store"
                and headers.get("Referrer-Policy") == "no-referrer" and headers.get("X-Content-Type-Options") == "nosniff"
                and (method != "HEAD" or not body), ERROR)
        return response.status, headers.get("Location"), body


def verify_short_probes(fixtures, opener, export, expected_surge, active):
    for method in ("GET", "HEAD"):
        unavailable = (404, None, b"Not found." if method == "GET" else b"")
        for label, code in fixtures.codes.items():
            suffix = FORMATS.get(label)
            response = request_short(opener, f"/s/{code}", method)
            if active and suffix is not None:
                path = f"/sub/{fixtures.token}" + (f"/{suffix}" if suffix else "")
                require(response == (302, path, b""), ERROR)
                result = export(fixtures.token, suffix, method)
                if not suffix:
                    require(result == (200, "text/yaml", EXPECTED_CLASH if method == "GET" else b"")
                            and result == export(fixtures.token, "clash", method), ERROR)
                else:
                    require(result == (200, "text/plain", expected_surge if suffix == "surge" and method == "GET" else b""), ERROR)
            else:
                require(response == unavailable, ERROR)
        require(request_short(opener, f"/agg/{fixtures.codes['aggregate-conflict']}/base64", method) == unavailable, ERROR)

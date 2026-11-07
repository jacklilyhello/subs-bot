"""Probe aggregate capabilities using only a journaled, isolated synthetic cohort."""

import argparse
from base64 import b64encode
import json
import os
from pathlib import Path
import re
import secrets
from time import monotonic

from capacity_fixtures import AGGREGATE_LABELS, AGGREGATE_SMOKE, aggregate_shares
from capacity_probe import ProbeError, _check_headers, _request, _small_body, _verify_health
from capacity_resources import (
    AGGREGATE_FOREIGN_OWNER, AGGREGATE_OWNER, DIGEST, MAX_JSON, REVISION, RUN_ID, CapacityError,
    R2Objects, Resources, digest, integer, json_body, load_ledger, locked_directory, matches,
    read_private, recheck_absent, require, save_private_json, verify_release,
)
from cloudflare_isolation import CloudflareClient, CloudflareError
from d1_migrations import _assert_sql
from prepare_isolation_artifact import ArtifactError


# IDs outside the Telegram range and distinct from every fixture owner.
BOTS = ("9223372036854775804", "9223372036854775803")
OWNERS = (AGGREGATE_OWNER, AGGREGATE_FOREIGN_OWNER)
STAMP = 1_800_000_000
LINKS = ("all", "selected", "foreign-only", "revoked", "unknown")
TEMPS = (
    ("aggregate-temp", BOTS[0], OWNERS[0]),
    ("aggregate-wrong-owner", BOTS[0], OWNERS[1]),
    ("aggregate-wrong-bot", BOTS[1], OWNERS[0]),
)
JOURNAL = "aggregate-cleanup.json"
REQUESTS = "aggregate-requests.json"


def _statement(sql, *params):
    return {"sql": sql, "params": [str(value) for value in params]}


def _batch(resources, statements):
    results = resources.api("POST", resources.database + "/query", {"batch": statements})
    require(isinstance(results, list) and len(results) == len(statements)
            and all(isinstance(row, dict) and row.get("success") is True for row in results),
            "Aggregate fixture transaction could not be confirmed.")


def _verify_schema(resources):
    directory = Path(__file__).resolve().parents[1] / "migrations"
    files = ("0008_telegram_temp_nodes.sql", "0009_aggregate_links.sql")
    expected = [{"position": int(name[:4]), "name": name, "sha256": digest((directory / name).read_bytes())}
                for name in files]
    rows = resources.query("SELECT position, name, sha256 FROM subs_bot_schema_migrations "
                           "WHERE position IN (8,9) AND mode='applied' ORDER BY position", ())
    require(rows == expected, "Aggregate fixture migrations could not be verified.")


def _load(directory, resources, capacity):
    path = directory / JOURNAL
    if not path.exists() and not path.is_symlink():
        return None
    plan = json_body(read_private(path, MAX_JSON))
    hashes = plan.get("digests")
    require(set(plan) == {"version", "scopeSha256", "revision", "runId", "runAttempt", "phase", "digests", "subscriptionIds"}
            and type(plan["version"]) is int and plan["version"] == 1
            and plan["scopeSha256"] == resources.scope_hash and plan["revision"] == capacity["revision"]
            and plan["runId"] == capacity["runId"] and matches(RUN_ID, plan["runAttempt"])
            and plan["phase"] in ("planned", "seeding", "seeded", "removing-temp", "temp-removed", "retiring", "retired")
            and isinstance(hashes, dict) and set(hashes) == set(LINKS)
            and all(matches(DIGEST, value) for value in hashes.values()) and len(set(hashes.values())) == len(LINKS)
            and isinstance(plan["subscriptionIds"], list)
            and all(integer(value, 1, 9007199254740991) for value in plan["subscriptionIds"])
            and plan["subscriptionIds"] == [entry["rowId"] for entry in capacity["fixtures"]],
            "Invalid aggregate cleanup journal.")
    return plan


def _links(plan):
    first, second, foreign = plan["subscriptionIds"]
    return {
        plan["digests"][label]: (kind, bot, selection, revoked)
        for label, kind, bot, selection, revoked in (
            ("all", "all", BOTS[0], None, None),
            ("selected", "selected", None, json.dumps([second, foreign, first], separators=(",", ":")), None),
            ("foreign-only", "selected", None, f"[{foreign}]", None),
            ("revoked", "all", BOTS[0], None, STAMP),
        )
    }


def _temps(plan):
    result = {}
    for label, bot, owner in TEMPS:
        nonce = f"aggregate-fixture:{plan['runId']}:{plan['runAttempt']}:{label}"
        identifier = int(digest(nonce.encode("ascii"))[:12], 16) + 1
        payload = json.dumps([{"name": label, "share": aggregate_shares(label)[0]}], ensure_ascii=False, separators=(",", ":"))
        result[nonce] = (label, bot, owner, identifier, payload)
    require(len({value[3] for value in result.values()}) == len(TEMPS), "Synthetic aggregate receipt identities collide.")
    return result


def _read(resources, plan):
    links = _links(plan)
    rows = resources.query("SELECT code_sha256, owner_id, kind, bot_id, selected_ids, created_at, revoked_at "
                           "FROM aggregate_links WHERE owner_id IN (?,?) OR code_sha256 IN (?,?,?,?,?) LIMIT 6",
                           (*OWNERS, *(plan["digests"][label] for label in LINKS)))
    present = set()
    for row in rows:
        code = row.get("code_sha256")
        require(code in links and code not in present and row.get("owner_id") == OWNERS[0] and row.get("created_at") == STAMP
                and tuple(row.get(key) for key in ("kind", "bot_id", "selected_ids", "revoked_at")) == links[code],
                "Aggregate fixture link ownership or state is ambiguous.")
        present.add(code)

    planned = _temps(plan)
    rows = resources.query("""
      SELECT i.receipt_id, i.receipt_nonce, i.bot_id, i.update_id, i.actor_id, i.chat_id, i.chat_type,
        i.message_id, i.message_date, i.thread_id, i.command, t.receipt_id AS temp_id,
        t.bot_id AS temp_bot, t.actor_id AS temp_actor, t.message_id AS temp_message,
        t.message_date AS temp_date, t.node_count, t.payload_bytes, t.nodes_json,
        EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=i.receipt_id) AS outbox,
        EXISTS(SELECT 1 FROM telegram_temp_reply WHERE receipt_id=i.receipt_id) AS reply
      FROM telegram_inbox AS i LEFT JOIN telegram_temp_batch AS t USING(receipt_id)
      WHERE i.bot_id IN (?,?) LIMIT 4
    """, BOTS)
    receipts = {}
    for row in rows:
        nonce = row.get("receipt_nonce")
        require(nonce in planned and nonce not in receipts, "Aggregate fixture receipt ownership is ambiguous.")
        _, bot, owner, identifier, payload = planned[nonce]
        receipt = row.get("receipt_id")
        require(integer(receipt, 1, 9007199254740991)
                and tuple(row.get(key) for key in ("bot_id", "actor_id", "chat_id", "chat_type", "update_id", "message_id",
                                                  "message_date", "thread_id", "command", "outbox", "reply"))
                == (bot, owner, owner, "private", identifier, identifier, STAMP, None, "help", 0, 0),
                "Aggregate fixture receipt has an unexpected identity or reply.")
        has_temp = row.get("temp_id") is not None
        require(not has_temp or tuple(row.get(key) for key in ("temp_id", "temp_bot", "temp_actor", "temp_message",
                                                               "temp_date", "node_count", "payload_bytes", "nodes_json"))
                == (receipt, bot, owner, identifier, STAMP, 1, len(payload.encode("utf-8")), payload),
                "Aggregate fixture temporary payload ownership or bytes differ.")
        receipts[nonce] = (receipt, has_temp)
    counts = resources.query("SELECT count(*) AS n FROM telegram_temp_batch WHERE bot_id IN (?,?)", BOTS)
    require(counts == [{"n": sum(has_temp for _, has_temp in receipts.values())}],
            "Aggregate fixture has unowned temporary data.")
    return present, receipts


def _state(resources, plan, *, temp_removed=False):
    links, receipts = _read(resources, plan)
    if not links and not receipts:
        return None
    temps = _temps(plan)
    require(links == set(_links(plan)) and receipts.keys() == temps.keys()
            and all(has_temp == (not temp_removed or temps[nonce][0] != TEMPS[0][0])
                    for nonce, (_, has_temp) in receipts.items()), "Aggregate fixture state is incomplete.")
    return receipts


def _seed_statements(plan):
    statements = [_statement(_assert_sql(
        "NOT EXISTS (SELECT 1 FROM aggregate_links WHERE owner_id IN (?,?) OR code_sha256 IN (?,?,?,?,?)) "
        "AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id IN (?,?)) "
        "AND NOT EXISTS (SELECT 1 FROM telegram_temp_batch WHERE bot_id IN (?,?))"),
        *OWNERS, *(plan["digests"][label] for label in LINKS), *BOTS, *BOTS)]
    for nonce, (_, bot, owner, identifier, payload) in _temps(plan).items():
        statements.extend([
            _statement("INSERT INTO telegram_inbox (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,command,receipt_nonce) "
                       "VALUES (?,?,?,?,'private',?,?,'help',?)", bot, identifier, owner, owner, identifier, STAMP, nonce),
            _statement("INSERT INTO telegram_temp_batch (receipt_id,bot_id,actor_id,message_date,message_id,nodes_json,node_count,payload_bytes) "
                       "SELECT receipt_id,bot_id,actor_id,message_date,message_id,?,1,? FROM telegram_inbox "
                       "WHERE bot_id=? AND update_id=? AND receipt_nonce=?", payload, len(payload.encode("utf-8")), bot, identifier, nonce),
        ])
    for code, (kind, bot, selection, revoked) in _links(plan).items():
        statements.append(_statement(
            "INSERT INTO aggregate_links (code_sha256,owner_id,kind,bot_id,selected_ids,created_at,revoked_at) "
            "VALUES (?,?,?,NULLIF(?,''),NULLIF(?,''),?,NULLIF(?,''))", code, OWNERS[0], kind, bot or "", selection or "", STAMP, revoked or ""))
    return statements


def _save(directory, plan, phase):
    plan["phase"] = phase
    save_private_json(directory / JOURNAL, plan)


def _request_codes(directory, revision):
    data = json_body(read_private(directory / REQUESTS, MAX_JSON))
    codes = data.get("codes")
    require(matches(REVISION, revision) and set(data) == {"revision", "codes"} and data["revision"] == revision
            and isinstance(codes, dict) and set(codes) == set(LINKS)
            and all(isinstance(code, str) and re.fullmatch(r"[A-Za-z0-9_-]{12}" if label == "all" else r"[A-Za-z0-9_-]{22}", code)
                    for label, code in codes.items()) and len(set(codes.values())) == len(LINKS), "Aggregate probe input identity is invalid.")
    return codes


def seed(directory, resources, capacity, revision, run_id, attempt, guard=verify_release):
    require(capacity["phase"] == "seed" and capacity["revision"] == revision and capacity["runId"] == run_id
            and matches(RUN_ID, run_id) and matches(RUN_ID, attempt),
            "Exact aggregate run identity could not be verified.")
    ids = [entry["rowId"] for entry in capacity["fixtures"]]
    require(all(integer(value, 1, 9007199254740991) for value in ids) and ids[0] < ids[1],
            "Published aggregate subscription identities differ.")
    require(all((resources.row(capacity, entry) or {}).get("generation") == 1 for entry in capacity["fixtures"])
            and resources.query("SELECT id FROM subscriptions WHERE owner_id IN (?,?) ORDER BY id LIMIT 4", OWNERS)
            == [{"id": identifier} for identifier in sorted(ids)], "Aggregate fixture owner scope is occupied.")
    guard(revision)
    plan = _load(directory, resources, capacity)
    if plan is None:
        codes = {label: secrets.token_urlsafe(9 if label == "all" else 16) for label in LINKS}
        plan = {"version": 1, "scopeSha256": resources.scope_hash, "revision": revision, "runId": capacity["runId"],
                "runAttempt": attempt, "digests": {label: digest(code.encode("ascii")) for label, code in codes.items()},
                "subscriptionIds": ids}
        require(len(set(plan["digests"].values())) == len(LINKS), "Aggregate fixture codes collide.")
        _save(directory, plan, "planned")
        save_private_json(directory / REQUESTS, {"revision": revision, "codes": codes})
    require(plan["runAttempt"] == attempt and plan["phase"] in ("planned", "seeding", "seeded"),
            "Aggregate journal belongs to another stage or attempt.")
    require({label: digest(code.encode("ascii")) for label, code in _request_codes(directory, revision).items()} == plan["digests"],
            "Aggregate probe capabilities do not match their journal.")
    state = _state(resources, plan)
    if plan["phase"] == "planned":
        require(state is None, "An unstarted aggregate cohort is already occupied.")
        _save(directory, plan, "seeding")
        try:
            _batch(resources, _seed_statements(plan))
        except (CloudflareError, CapacityError):
            pass
        state = _state(resources, plan)
    state = recheck_absent(state, lambda: _state(resources, plan))
    require(state is not None, "Aggregate fixture insertion remains unconfirmed. Cleanup journal retained.")
    _save(directory, plan, "seeded")


def _delete_temp(nonce, receipt, values):
    _, bot, owner, identifier, payload = values
    return _statement("DELETE FROM telegram_temp_batch WHERE receipt_id=? AND bot_id=? AND actor_id=? AND message_id=? "
                      "AND message_date=? AND nodes_json=? AND node_count=1 AND payload_bytes=? AND EXISTS "
                      "(SELECT 1 FROM telegram_inbox WHERE receipt_id=? AND receipt_nonce=?)",
                      receipt, bot, owner, identifier, STAMP, payload, len(payload.encode("utf-8")), receipt, nonce)


def remove_temp(directory, resources, plan, revision, guard=verify_release):
    require(plan is not None and plan["revision"] == revision and plan["phase"] in ("seeded", "removing-temp", "temp-removed"),
            "Aggregate temporary fixture is outside its removal phase.")
    guard(revision)
    links, receipts = _read(resources, plan)
    temps = _temps(plan)
    nonce = next(key for key, value in temps.items() if value[0] == TEMPS[0][0])
    require(links == set(_links(plan)) and receipts.keys() == temps.keys()
            and all(has_temp for key, (_, has_temp) in receipts.items() if key != nonce),
            "Aggregate temporary cohort is incomplete.")
    receipt, present = receipts[nonce]
    if present:
        _save(directory, plan, "removing-temp")
        try:
            _batch(resources, [_delete_temp(nonce, receipt, temps[nonce])])
        except (CloudflareError, CapacityError):
            pass
    require(_state(resources, plan, temp_removed=True) is not None, "Aggregate temporary removal could not be confirmed.")
    _save(directory, plan, "temp-removed")


def cleanup(directory, resources, plan):
    if plan is None:
        return
    if plan["phase"] == "seeding":
        require(recheck_absent(_state(resources, plan), lambda: _state(resources, plan)) is not None,
                "Aggregate fixture insertion remains unconfirmed. Cleanup journal retained.")
    links, receipts = _read(resources, plan)
    require(plan["phase"] not in ("planned", "retired") or not (links or receipts),
            "Aggregate journal phase and owned state differ.")
    if links or receipts:
        _save(directory, plan, "retiring")
        statements = []
        for code in sorted(links):
            kind, bot, selection, revoked = _links(plan)[code]
            statements.append(_statement("DELETE FROM aggregate_links WHERE code_sha256=? AND owner_id=? AND kind=? "
                                         "AND bot_id IS NULLIF(?,'') AND selected_ids IS NULLIF(?,'') AND created_at=? "
                                         "AND revoked_at IS CAST(NULLIF(?,'') AS INTEGER)",
                                         code, OWNERS[0], kind, bot or "", selection or "", STAMP, revoked or ""))
        temps = _temps(plan)
        for nonce, (receipt, has_temp) in receipts.items():
            _, bot, owner, identifier, _ = temps[nonce]
            if has_temp:
                statements.append(_delete_temp(nonce, receipt, temps[nonce]))
            statements.append(_statement("DELETE FROM telegram_inbox WHERE receipt_id=? AND receipt_nonce=? AND bot_id=? AND actor_id=? "
                                         "AND chat_id=actor_id AND chat_type='private' AND update_id=? AND message_id=? AND message_date=? "
                                         "AND command='help' AND thread_id IS NULL", receipt, nonce, bot, owner, identifier, identifier, STAMP))
        statements.append(_statement(_assert_sql("NOT EXISTS (SELECT 1 FROM aggregate_links WHERE owner_id IN (?,?)) "
                                                "AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id IN (?,?)) "
                                                "AND NOT EXISTS (SELECT 1 FROM telegram_temp_batch WHERE bot_id IN (?,?))"),
                                     *OWNERS, *BOTS, *BOTS))
        try:
            _batch(resources, statements)
        except (CloudflareError, CapacityError):
            pass
        links, receipts = _read(resources, plan)
    require(not links and not receipts, "Aggregate fixture retirement could not be confirmed. Cleanup journal retained.")
    _save(directory, plan, "retired")


def _expected(after):
    first, second, _ = map(aggregate_shares, AGGREGATE_LABELS)
    temporary = () if after else aggregate_shares(TEMPS[0][0])
    return {label: b64encode("\n".join(shares).encode("utf-8"))
            for label, shares in (("all", (*first, *second, *temporary)), ("selected", (*second, *first)))}


def probe(directory, revision, *, after=False):
    codes = _request_codes(directory, revision)
    deadline = monotonic() + 75

    def request(method, path, label):
        return _request(method, path, min(monotonic() + 15, deadline), label)

    def health():
        with request("GET", "/health", "aggregate health") as response:
            _check_headers(response, 200, "aggregate health", "application/json")
            _verify_health(response, revision)

    health()
    report = {}
    for label, expected in _expected(after).items():
        format_name = "base64" if label == "all" else "mixed"
        for method in ("GET", "HEAD"):
            with request(method, f"/agg/{codes[label]}/{format_name}", label) as response:
                _check_headers(response, 200, label, "text/plain")
                if method == "GET":
                    require(response.getheader("Transfer-Encoding") is None
                            and response.getheader("Content-Length") == str(len(expected)) and _small_body(response) == expected,
                            "Aggregate export length or exact bytes differ.")
                else:
                    require(response.read(1) == b"", "Aggregate HEAD returned a body.")
        report[label] = {"GET": 200, "HEAD": 200, "bytes": len(expected), "sha256": digest(expected)}
    if not after:
        for method in ("GET", "HEAD"):
            with request(method, f"/s/{codes['all']}", "local aggregate alias") as response:
                cache = {item.strip().lower() for item in response.getheader("Cache-Control", "").split(",")}
                require(response.status == 302 and response.getheader("Location") == f"/agg/{codes['all']}/clash"
                        and cache == {"private", "no-store"} and response.getheader("Referrer-Policy") == "no-referrer"
                        and response.getheader("X-Content-Type-Options") == "nosniff"
                        and response.getheader("CF-Cache-Status", "").upper() in {"", "DYNAMIC", "BYPASS"}
                        and response.getheader("Set-Cookie") is None and response.getheader("Age") is None
                        and _small_body(response) == b"", "Aggregate alias is not a private fixed local redirect.")
        for label in ("foreign-only", "unknown", "revoked"):
            paths = [f"/agg/{codes[label]}/base64"]
            if label != "foreign-only":
                paths.append(f"/s/{codes[label]}")
            for path in paths:
                with request("GET", path, label) as response:
                    _check_headers(response, 404, label, "text/plain")
                    require(_small_body(response) == b"Not found.", "Aggregate denial body differs.")
        report["alias"] = {"GET": 302, "HEAD": 302}
        report["denied"] = {"foreign-only": 404, "unknown": 404, "revoked": 404}
    health()
    return {"revision": revision, "phase": "after-temp-removal" if after else "initial", "results": report}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("seed", "probe", "remove-temp", "probe-after", "cleanup"))
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        revision = os.environ.get("GITHUB_SHA")
        with locked_directory(args.directory):
            if args.action in ("probe", "probe-after"):
                print(json.dumps(probe(args.directory, revision, after=args.action == "probe-after"), sort_keys=True))
                return
            target = json_body(os.environ.get("SUBS_BOT_CF_ISOLATION_TARGET_JSON", "null"))
            token = os.environ.get("SUBS_BOT_CF_BOOTSTRAP_TOKEN")
            resources = Resources(target, CloudflareClient(token), R2Objects(target.get("accountId"), token))
            resources.verify()
            capacity = load_ledger(args.directory, resources.scope_hash, profile=AGGREGATE_SMOKE)
            if args.action == "cleanup" and not (args.directory / JOURNAL).exists() and not (args.directory / JOURNAL).is_symlink():
                return
            require(capacity is not None, "The scoped aggregate subscription journal is missing.")
            _verify_schema(resources)
            if args.action == "seed":
                seed(args.directory, resources, capacity, revision, os.environ.get("GITHUB_RUN_ID"), os.environ.get("GITHUB_RUN_ATTEMPT"))
            elif args.action == "remove-temp":
                remove_temp(args.directory, resources, _load(args.directory, resources, capacity), revision)
            else:
                cleanup(args.directory, resources, _load(args.directory, resources, capacity))
        print("Owned aggregate fixture phase verified.")
    except (CapacityError, ProbeError, ArtifactError, CloudflareError) as error:
        parser.exit(1, f"{error}\n")
    except (OSError, KeyError, TypeError, ValueError, RecursionError):
        parser.exit(1, "Could not verify private aggregate fixture state.\n")


if __name__ == "__main__":
    main()

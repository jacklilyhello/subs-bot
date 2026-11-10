"""Control the two existing isolated actors' private general read rehearsal."""

from dataclasses import asdict
from hashlib import sha256
import json
import os
from pathlib import Path

from cloudflare_isolation import (
    CloudflareClient, CloudflareError, DIGEST, GENERAL_READ_LANE_MARKER as MARKER, REVISION, WORKER_NAME,
    _Isolation, _guard_current, _matches, _require, _verified_module, _verify_health,
)
from d1_migrations import _all_conditions, _assert_sql, _literal
from page_jump_activation import require_clear_for_release
from prepare_isolation_artifact import (
    ArtifactError, MAIN_REF, REPOSITORY, REPOSITORY_ID, VERIFIED_DIRECTORY, prepare, require_current_main,
)
from stage_page_jump_isolation import RUN, _canonical, _digest

TABLE = "telegram_general_read_lane"
MIGRATION = "0049_telegram_general_read_lane.sql"
MIGRATION_SHA256 = "5b1220f36273d74fb14f333066ae70f26022c5abf8a60f2d236c6a23e3bcce88"
WORKFLOW = REPOSITORY + "/.github/workflows/worker-isolation-general-read-rehearsal.yml@" + MAIN_REF
UNSETTLED = "('pending','leased','sending')"
ERROR = "The isolated Telegram read rehearsal could not be confirmed."
ARTIFACT_ERROR = "The verified Worker artifact does not pin the isolated Telegram read rehearsal migration and runtime."
BLOCKED = "Close and drain the isolated Telegram read rehearsal before changing the Worker version."
LIMIT = 2**53 - 1
PINNED = f"""(SELECT count(*) FROM subs_bot_schema_migrations WHERE
    (position=49 OR name='{MIGRATION}'))=1 AND EXISTS (
      SELECT 1 FROM subs_bot_schema_migrations WHERE position=49 AND name='{MIGRATION}'
      AND sha256='{MIGRATION_SHA256}' AND mode='applied')"""
WORK = f"""SELECT 1 FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id)
    JOIN telegram_general_receipt AS authority USING(receipt_id)
    WHERE inbox.receipt_nonce='general-read:v1' AND reply.state IN {UNSETTLED}"""


def _query(scope, sql, size):
    path = f"{scope.account}/d1/database/{scope.target['d1Id']}/query"
    result = scope.data_api("POST", path, {"sql": sql})
    _require(isinstance(result, list) and len(result) == size and all(
        isinstance(entry, dict) and entry.get("success") is True and isinstance(entry.get("results"), list)
        for entry in result
    ), ERROR)
    return result


def _one(scope, sql, fields):
    rows = _query(scope, sql, 1)[0]["results"]
    _require(len(rows) == 1 and isinstance(rows[0], dict) and set(rows[0]) == set(fields), ERROR)
    return rows[0]


def _has_schema(scope, *, required):
    schema = _one(scope, f"""SELECT
        (SELECT CASE WHEN length(CAST(sql AS BLOB))<=1024 THEN sql END
          FROM sqlite_schema WHERE type='table' AND name='{TABLE}') AS definition,
        EXISTS(SELECT 1 FROM sqlite_schema WHERE name='{TABLE}') AS laneTable,
        EXISTS(SELECT 1 FROM sqlite_schema WHERE name='subs_bot_schema_migrations' AND type='table') AS ledger""",
        ("definition", "laneTable", "ledger"))
    _require(all(type(schema[key]) is int and schema[key] in (0, 1) for key in ("laneTable", "ledger")), ERROR)
    if not schema["laneTable"]:
        _require(not required, ERROR)
        if schema["ledger"]:
            row = _one(scope, f"""SELECT EXISTS(SELECT 1 FROM subs_bot_schema_migrations
                WHERE position=49 OR name='{MIGRATION}') AS laneRegistered""", ("laneRegistered",))
            _require(type(row["laneRegistered"]) is int and row["laneRegistered"] == 0, ERROR)
        return False
    definition = schema["definition"]
    _require(schema["ledger"] == 1 and isinstance(definition, str)
             and sha256((definition + ";\n").encode("utf-8")).hexdigest() == MIGRATION_SHA256, ERROR)
    row = _one(scope, f"SELECT ({PINNED}) AS lanePinned", ("lanePinned",))
    _require(type(row["lanePinned"]) is int and row["lanePinned"] == 1, ERROR)
    return True


def require_general_read_lane_clear(scope, *, required=False):
    if _has_schema(scope, required=required):
        result = _one(scope, f"""SELECT EXISTS(SELECT 1 FROM {TABLE} WHERE mode<>'isolated')
            OR EXISTS({WORK}) OR EXISTS(SELECT 1 FROM telegram_general_policy WHERE active=1) AS laneBusy""", ("laneBusy",))
        _require(type(result["laneBusy"]) is int and result["laneBusy"] == 0, BLOCKED)


def general_read_artifact(module, manifest):
    migrations = manifest["migrations"]
    capable = MARKER in module
    if capable or len(migrations) >= 49:
        _require(capable and len(migrations) >= 49 and migrations[48] == {
            "name": MIGRATION, "sha256": MIGRATION_SHA256,
        }, ARTIFACT_ERROR)
    return capable


def verify_general_read_artifact(bundle, manifest):
    return general_read_artifact(_verified_module(bundle, manifest["bundleSha256"]), manifest)


def _state_sql(bot, admin, member):
    bot, admin, member = map(_literal, (bot, admin, member))
    return f"""SELECT COALESCE(lane.epoch,0) AS epoch,COALESCE(lane.mode,'isolated') AS mode,
      lane.generation AS generation,lane.member_date AS member_date,lane.member_message AS member_message,
      COALESCE(policy.generation,0) AS policy_generation,COALESCE(policy.active,0) AS policy_active,
      policy.cutover_at AS cutover,policy.release_revision AS revision,policy.activation_sha256 AS activation,
      auth.allowed AS member_allowed,auth.message_date AS live_date,auth.message_id AS live_message,
      (SELECT count(*) FROM telegram_general_policy WHERE bot_id<>{bot} AND active=1) AS foreign_active,
      (SELECT count(*) FROM {TABLE} WHERE bot_id<>{bot}) AS foreign_lane,
      (SELECT count(*) FROM telegram_general_groups WHERE bot_id={bot} AND generation=policy.generation) AS groups,
      (SELECT count(*) FROM telegram_general_actors WHERE bot_id={bot} AND generation=policy.generation) AS actors,
      (SELECT count(*) FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id)
        WHERE inbox.bot_id={bot} AND inbox.actor_id IN ({admin},{member}) AND reply.state IN {UNSETTLED}) AS pending,
      (SELECT count(*) FROM telegram_general_replies WHERE bot_id={bot} AND state IN {UNSETTLED}) AS old_pending,
      (SELECT count(*) FROM ({WORK}) AS unresolved) AS general_pending,
      COALESCE((SELECT max(receipt_id) FROM telegram_inbox),0) AS high_water
      FROM (SELECT 1) AS singleton LEFT JOIN {TABLE} AS lane ON lane.bot_id={bot}
      LEFT JOIN telegram_general_policy AS policy ON policy.bot_id={bot}
      LEFT JOIN telegram_auth AS auth ON auth.bot_id={bot} AND auth.user_id={member}"""


_FIELDS = (
    "epoch", "mode", "generation", "member_date", "member_message", "policy_generation", "policy_active",
    "cutover", "revision", "activation", "member_allowed", "live_date", "live_message", "foreign_active",
    "foreign_lane", "groups", "actors", "pending", "old_pending", "general_pending", "high_water",
)


def _integer(value, low=0):
    return type(value) is int and low <= value <= LIMIT


def _observe(scope, sql):
    state = _one(scope, sql, _FIELDS)
    _require(state["mode"] in ("isolated", "closed", "general")
             and all(_integer(state[key]) for key in (
                 "epoch", "policy_generation", "pending", "old_pending", "general_pending", "high_water",
                 "foreign_active", "foreign_lane", "groups", "actors"))
             and type(state["policy_active"]) is int and state["policy_active"] in (0, 1)
             and (state["member_allowed"] is None or type(state["member_allowed"]) is int and state["member_allowed"] in (0, 1))
             and all(state[key] is None or _integer(state[key], 1) for key in (
                 "generation", "cutover", "member_date", "member_message", "live_date", "live_message"))
             and (state["revision"] is None or _matches(REVISION, state["revision"]))
             and (state["activation"] is None or _matches(DIGEST, state["activation"])), ERROR)
    return state


def _scalar(value):
    if value is None:
        return "NULL"
    return str(value) if type(value) is int else _literal(value)


def _cas(sql, state, *, quiet):
    fields = ("epoch", "mode", "generation", "member_date", "member_message", "policy_generation", "policy_active",
              "cutover", "revision", "activation", "foreign_lane", "foreign_active", "groups")
    if quiet:
        fields += ("member_allowed", "live_date", "live_message", "pending", "old_pending", "general_pending")
    return f"EXISTS(SELECT 1 FROM ({sql}) WHERE " + _all_conditions(
        [f"{field} IS {_scalar(state[field])}" for field in fields]) + ")"


def _transition(action, state, sql, principals, active_sha, version):
    bot, admin, member = map(_literal, principals)
    epoch, mode, generation = state["epoch"] + 1, state["mode"], state["generation"]
    _require(_integer(epoch, 1) and state["foreign_lane"] == state["foreign_active"] == state["groups"] == 0, ERROR)
    _require((generation is None and state["policy_active"] == 0)
             or (generation == state["policy_generation"] and state["policy_active"] == 1
                 and state["revision"] == version.revision and state["actors"] == 2), ERROR)
    if action == "close":
        _require(mode in ("isolated", "general"), ERROR)
        statements = [f"""INSERT INTO {TABLE}(bot_id,epoch,mode) VALUES ({bot},{epoch},'closed')
            ON CONFLICT(bot_id) DO UPDATE SET epoch=excluded.epoch,mode='closed'"""]
        next_mode, next_generation = "closed", generation
    elif action == "open":
        next_generation = state["policy_generation"] + 1
        _require(mode == "closed" and generation is None and _integer(next_generation, 1)
                 and state["member_allowed"] in (None, 1)
                 and state["pending"] == state["old_pending"] == state["general_pending"] == 0, ERROR)
        activation = _literal(_digest({"activeSha256": active_sha, "epoch": epoch, "generation": next_generation}))
        revision = _literal(version.revision)
        statements = [f"""INSERT INTO telegram_general_policy VALUES ({bot},{next_generation},{revision},{activation},unixepoch(),1)
          ON CONFLICT(bot_id) DO UPDATE SET generation=excluded.generation,release_revision=excluded.release_revision,
            activation_sha256=excluded.activation_sha256,cutover_at=excluded.cutover_at,active=1""",
          f"""INSERT INTO telegram_general_actors
            SELECT bot_id,generation,{admin},1,cutover_at,'admin' FROM telegram_general_policy WHERE bot_id={bot}
            UNION ALL SELECT bot_id,generation,{member},1,cutover_at,'member' FROM telegram_general_policy WHERE bot_id={bot}""",
          f"""UPDATE {TABLE} SET epoch={epoch},mode='general',generation={next_generation},
            member_date={_scalar(state["live_date"])},member_message={_scalar(state["live_message"])} WHERE bot_id={bot}"""]
        next_mode = "general"
    else:
        _require(action == "restore" and mode == "closed" and state["general_pending"] == 0, ERROR)
        statements = ([f"UPDATE telegram_general_policy SET active=0 WHERE bot_id={bot} AND generation={generation}"]
                      if generation is not None else [])
        statements.append(f"""UPDATE {TABLE} SET epoch={epoch},mode='isolated',generation=NULL,
            member_date=NULL,member_message=NULL WHERE bot_id={bot}""")
        next_mode, next_generation = "isolated", None
    before = f"({PINNED}) AND {_cas(sql, state, quiet=action != 'close')}"
    after = f"""EXISTS(SELECT 1 FROM {TABLE} WHERE bot_id={bot} AND epoch={epoch}
        AND mode='{next_mode}' AND generation IS {_scalar(next_generation)})
        AND (SELECT count(*) FROM telegram_general_policy WHERE bot_id={bot} AND active=1)={int(next_generation is not None)}"""
    if action == "open":
        after += f""" AND (SELECT count(*) FROM telegram_general_actors WHERE bot_id={bot}
            AND generation={next_generation})=2"""
    batch = [_assert_sql(before), *statements, _assert_sql(after)]
    return ";\n".join(batch) + ";", len(batch), (epoch, next_mode, next_generation)


def run(scope, config, guard, *, action, expected_active, expected_state, artifact=None):
    scope.verify_resources()
    settings = scope.worker_config()
    _require(scope.cron_enabled(), ERROR)
    require_clear_for_release(scope)
    _has_schema(scope, required=True)
    deployment = scope.active()
    version, capable = scope.version(deployment.version, with_general_read_lane=True)
    _require(capable and version.telegram_config_sha256 == sha256(config.encode("utf-8")).hexdigest(), ERROR)
    active_sha = _digest({"target": scope.target, "deployment": asdict(deployment), "version": asdict(version)})
    _require(expected_active in ("", active_sha), ERROR)
    if artifact is not None:
        _require((version.revision, version.digest, version.compatibility) == artifact, ERROR)
    else:
        _require(expected_active == active_sha and action in ("inspect", "close", "restore"), ERROR)
    policy = json.loads(config)
    principals = tuple(policy[key] for key in ("botId", "adminId", "memberId"))
    sql = _state_sql(*principals)
    state = _observe(scope, sql)
    _require(action == "inspect" or expected_state == _digest(state), ERROR)
    if artifact is None and action == "close":
        _require(state["generation"] is not None, ERROR)

    def recheck():
        _require(scope.worker_config() == settings and scope.cron_enabled() and scope.active() == deployment, ERROR)
        _guard_current(guard)

    recheck()
    if action != "inspect":
        statement, count, successor = _transition(action, state, sql, principals, active_sha, version)
        if action == "open":
            _verify_health(version.revision)
        recheck()
        try:
            _query(scope, statement, count)
        except CloudflareError as exc:
            if not exc.uncertain:
                raise CloudflareError(ERROR) from None
        state = _observe(scope, sql)
        _require(tuple(state[field] for field in ("epoch", "mode", "generation")) == successor
                 and state["policy_active"] == int(successor[2] is not None), ERROR)
        if action == "open":
            _require(state["activation"] == _digest({"activeSha256": active_sha, "epoch": successor[0], "generation": successor[2]})
                     and state["revision"] == version.revision and state["actors"] == 2, ERROR)
        recheck()
    return {"version": 1, "action": action, "activeSha256": active_sha, "revision": version.revision,
            "moduleSha256": version.digest, "deploymentId": deployment.id, "versionId": deployment.version,
            "stateSha256": _digest(state), "mode": state["mode"], "epoch": state["epoch"], "generation": state["generation"],
            "cutoverAt": state["cutover"] if state["generation"] is not None else None, "inboxHighWater": state["high_water"],
            "pending": state["pending"], "legacyPending": state["old_pending"], "generalPending": state["general_pending"]}


def main(env):
    from release_isolation import isolated_telegram_config, isolation_credentials

    _require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
             and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("GITHUB_REF") == MAIN_REF
             and env.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID), ERROR)
    run_identity = (env.get("GITHUB_RUN_ID", ""), env.get("GITHUB_RUN_ATTEMPT", ""))
    _require(all(RUN.fullmatch(value) and _integer(int(value), 1) for value in run_identity), ERROR)
    run_id, attempt = map(int, run_identity)
    action, confirmation, active, state = (env.get(key, "") for key in (
        "GENERAL_READ_ACTION", "GENERAL_READ_CONFIRMATION", "GENERAL_READ_ACTIVE_SHA256", "GENERAL_READ_STATE_SHA256"))
    _require(action in ("inspect", "close", "open", "restore")
             and (active == "" or _matches(DIGEST, active))
             and (action == "inspect" and confirmation == state == ""
                  or _matches(DIGEST, active) and _matches(DIGEST, state)
                  and confirmation == f"{action} private general reads for {WORKER_NAME}"), ERROR)
    revision = env.get("GITHUB_SHA", "")
    guard = lambda: require_current_main(revision)
    guard()
    temp = Path(env["RUNNER_TEMP"])
    artifact = None
    source = None
    if env.get("SUBS_BOT_CI_RUN_ID"):
        source = prepare()
        bundle = temp / VERIFIED_DIRECTORY
        manifest = json.loads((bundle / "isolation.json").read_text(encoding="utf-8"))
        _require(verify_general_read_artifact(bundle, manifest) and manifest["revision"] == revision, ERROR)
        artifact = (revision, manifest["bundleSha256"], manifest["compatibilityDate"])
    target, data_token, deploy_token = isolation_credentials()
    scope = _Isolation(CloudflareClient(deploy_token), CloudflareClient(data_token), target)
    evidence = run(scope, isolated_telegram_config(), guard, action=action, expected_active=active,
                   expected_state=state, artifact=artifact)
    evidence["artifact"] = source
    evidence["controlRevision"] = revision
    evidence["runId"] = run_id
    evidence["runAttempt"] = attempt
    with (temp / "general-read-rehearsal.json").open("xb") as output:
        output.write(_canonical(evidence))


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main(os.environ)
        print("Verified the isolated Telegram read rehearsal checkpoint.")
    except (ArtifactError, CloudflareError, OSError, ValueError, TypeError, KeyError, RecursionError):
        raise SystemExit(ERROR) from None

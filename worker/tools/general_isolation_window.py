"""Protected full-v1 general runtime window on the existing two-actor isolation Bot.

No webhook, domain, production service, business record or credential is changed.
Only a pinned D1 control profile and its temporary authorization generation change.
"""

from hashlib import sha256
import json
import os
from pathlib import Path

import general_read_rehearsal as reads
from cloudflare_isolation import CloudflareClient, CloudflareError, DIGEST, WORKER_NAME, _Isolation, _guard_current, _matches, _require, _verified_module, _verify_health
from d1_migrations import MigrationError, _all_conditions, _assert_sql, _literal, _load_migrations, _read_state
from page_jump_activation import require_clear_for_release
from prepare_isolation_artifact import ArtifactError, MAIN_REF, REPOSITORY, REPOSITORY_ID, VERIFIED_DIRECTORY, prepare, require_current_main
from stage_page_jump_isolation import RUN, _canonical, _digest

PROFILE = "full-v1"
TABLE = "telegram_general_isolation_window"
MIGRATION = "0052_telegram_general_isolation_window.sql"
MIGRATION_SHA256 = "2f31fc9792828fb115f58be7840304ce561c6def36ba92180262ea012b6c2bd7"
MARKER = b"subs-bot:telegram-general-isolation-window:full-v1"
WORKFLOW = REPOSITORY + "/.github/workflows/worker-isolation-general-window.yml@" + MAIN_REF
ERROR = "The isolated full general Telegram window could not be confirmed."
PINNED = f"""(SELECT count(*) FROM subs_bot_schema_migrations WHERE position=52 OR name='{MIGRATION}')=1
  AND EXISTS(SELECT 1 FROM subs_bot_schema_migrations WHERE position=52 AND name='{MIGRATION}'
    AND sha256='{MIGRATION_SHA256}' AND mode='applied')"""


def general_window_artifact(module, manifest):
    _require(len(manifest["migrations"]) >= 52 and manifest["migrations"][51] == {
        "name": MIGRATION, "sha256": MIGRATION_SHA256,
    } and MARKER in module, ERROR)
    return True


def verify_artifact(bundle, manifest):
    return general_window_artifact(_verified_module(bundle, manifest["bundleSha256"]), manifest)


def _schema(scope):
    reads._has_schema(scope, required=True)
    row = reads._one(scope, f"SELECT sql FROM sqlite_schema WHERE type='table' AND name='{TABLE}'", ("sql",))
    _require(isinstance(row["sql"], str) and len(row["sql"]) <= 2048
             and sha256((row["sql"] + ";\n").encode()).hexdigest() == MIGRATION_SHA256, ERROR)
    _require(reads._one(scope, f"SELECT ({PINNED}) AS pinned", ("pinned",)) == {"pinned": 1}, ERROR)


def require_window_clear(scope):
    present = reads._one(scope, f"SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='{TABLE}') AS present", ("present",))
    _require(present["present"] in (0, 1), ERROR)
    if present["present"]:
        _schema(scope)
        _require(reads._one(scope, f"SELECT count(*) AS profiles FROM {TABLE}", ("profiles",)) == {"profiles": 0},
                 "Close, drain and restore the full general isolation window before another lane or deployment operation.")


def work_sql(bot):
    """Count future producers as well as the visible outbox; close never abandons durable work."""
    bot = _literal(bot)
    counts = {
        "outbox": f"SELECT count(*) FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND state IN {reads.UNSETTLED}",
        "legacyReplies": f"SELECT count(*) FROM telegram_general_replies WHERE bot_id={bot} AND state IN {reads.UNSETTLED}",
        "documents": f"SELECT count(*) FROM telegram_document_jobs AS job WHERE bot_id={bot} AND (state IN ('pending','leased') OR (finished_at>unixepoch()-900 AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=job.receipt_id)))",
        "documentStages": f"SELECT count(*) FROM telegram_document_stages JOIN telegram_document_jobs USING(receipt_id) WHERE bot_id={bot}",
        "providerJobs": "SELECT count(*) FROM telegram_provider_jobs WHERE state IN ('pending','leased')",
        "backgroundProviderJobs": "SELECT count(*) FROM subscription_provider_jobs WHERE state IN ('pending','leased')",
        "providerReplies": f"SELECT count(*) FROM telegram_provider_requests AS request JOIN telegram_inbox AS inbox USING(receipt_id) JOIN telegram_provider_jobs AS job USING(job_id) WHERE inbox.bot_id={bot} AND job.finished_at>unixepoch()-900 AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=request.receipt_id)",
        "providerDocuments": f"SELECT count(*) FROM telegram_provider_documents AS document WHERE bot_id={bot} AND (finished_at IS NULL OR (finished_at>unixepoch()-900 AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=document.receipt_id)))",
        "batches": f"SELECT count(*) FROM telegram_provider_batches AS batch WHERE bot_id={bot} AND (finished_at IS NULL OR (finished_at>unixepoch()-900 AND NOT EXISTS(SELECT 1 FROM telegram_provider_batch_interactions WHERE receipt_id=batch.batch_id)))",
        "batchJobs": "SELECT count(*) FROM telegram_provider_batch_jobs WHERE state IN ('waiting','pending','leased')",
        "privateCreations": f"SELECT count(*) FROM telegram_private_share_creations AS creation WHERE bot_id={bot} AND (state='reserved' OR (state='published' AND EXISTS(SELECT 1 FROM private_shares WHERE id=creation.share_id AND expire_at>unixepoch()) AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=creation.receipt_id)) OR (state='abandoned' AND cleaned_at IS NULL))",
        "groupCards": f"SELECT count(*) FROM telegram_group_share_cards AS card JOIN telegram_private_share_creations USING(receipt_id) WHERE bot_id={bot} AND (card.state IN ('pending','sending') OR (card.lease_id IS NOT NULL AND card.lease_until>unixepoch()) OR (card.state='sent' AND card.shown<101 AND card.attempts<4))",
        "inline": f"SELECT count(*) FROM telegram_inline_search_receipts WHERE bot_id={bot} AND state IN ('preflight','sending') AND lease_until>unixepoch()",
        "snapshotLeases": "SELECT count(*) FROM provider_snapshot_attempts WHERE state IN ('open','sealed') AND lease_until>unixepoch()",
        "searches": f"SELECT count(*) FROM telegram_github_search WHERE bot_id={bot} AND state='looking'",
        "apiProbes": f"SELECT count(*) FROM telegram_api_status AS probe JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND (ready_at IS NULL OR (prompt_receipt_id IS NOT NULL AND ready_at>unixepoch()-900 AND NOT EXISTS(SELECT 1 FROM telegram_outbox WHERE receipt_id=probe.receipt_id)))",
    }
    return "SELECT " + ",".join(f"({sql}) AS {name}" for name, sql in counts.items()), tuple(counts)


def terminal_card_sql(bot):
    """Retain terminal evidence separately; these states have no safe automatic retry."""
    source = ("FROM telegram_group_share_cards AS card JOIN telegram_private_share_creations USING(receipt_id) "
              f"WHERE bot_id={_literal(bot)} AND (card.lease_until IS NULL OR card.lease_until<=unixepoch())")
    counts = {
        "terminalUnknown": "card.state='uncertain'",
        # The existing row cannot distinguish a failed edit from an ambiguous edit.
        "terminalEditFailure": "card.state='sent' AND card.shown<101 AND card.attempts>=4",
        "terminalDeliveryFailure": "card.state='failed'",
    }
    return "SELECT " + ",".join(f"(SELECT count(*) {source} AND ({where})) AS {name}"
        for name, where in counts.items()), tuple(counts)


def _terminal_cards(scope, bot):
    sql, fields = terminal_card_sql(bot)
    result = reads._one(scope, sql, fields)
    _require(all(reads._integer(value) for value in result.values()), ERROR)
    return result


def _work(scope, bot):
    sql, fields = work_sql(bot)
    result = reads._one(scope, sql, fields)
    _require(all(reads._integer(value) for value in result.values()), ERROR)
    return result


def _quiet_sql(bot):
    sql, fields = work_sql(bot)
    return "EXISTS(SELECT 1 FROM (" + sql + ") WHERE " + _all_conditions([f"{name}=0" for name in fields]) + ")"


def _state(scope, policy):
    base = reads._observe(scope, reads._state_sql(policy["botId"], policy["adminId"], policy["memberId"]))
    row = reads._query(scope, f"SELECT * FROM {TABLE} WHERE bot_id={_literal(policy['botId'])}", 1)[0]["results"]
    _require(len(row) <= 1, ERROR)
    profile = row[0] if row else None
    if profile:
        _require(set(profile) == {"bot_id", "profile", "release_revision", "active_sha256", "admin_id", "member_id", "group_id", "generation", "opened_epoch"}
                 and (profile["profile"], profile["admin_id"], profile["member_id"], profile["group_id"])
                 == (PROFILE, policy["adminId"], policy["memberId"], policy["groupId"])
                 and _matches(DIGEST, profile["active_sha256"])
                 and base["mode"] in ("closed", "general") and profile["generation"] == base["generation"], ERROR)
        if profile["generation"] is not None:
            bot, admin, member, group = map(_literal, (policy[key] for key in ("botId", "adminId", "memberId", "groupId")))
            generation = profile["generation"]
            scope_pin = reads._one(scope, f"""SELECT
                EXISTS(SELECT 1 FROM telegram_general_actors WHERE bot_id={bot} AND generation={generation}
                  AND actor_id NOT IN({admin},{member})) AS foreignActors,
                EXISTS(SELECT 1 FROM telegram_general_groups WHERE bot_id={bot} AND generation={generation}
                  AND chat_id={group} AND chat_type='group') AS fixedGroup""", ("foreignActors", "fixedGroup"))
            _require(scope_pin == {"foreignActors": 0, "fixedGroup": 1}, ERROR)
            _require(reads._integer(profile["opened_epoch"], 1) and profile["opened_epoch"] <= base["epoch"]
                     and base["revision"] == profile["release_revision"] and base["groups"] == 1, ERROR)
        else:
            _require(profile["opened_epoch"] is None and base["mode"] == "closed" and base["groups"] == 0, ERROR)
    else:
        _require(base["mode"] == "isolated" and base["generation"] is None and base["policy_active"] == 0, ERROR)
    return {"lane": base, "profile": profile, "work": _work(scope, policy["botId"]),
        "terminalCards": _terminal_cards(scope, policy["botId"])}


def _profile_guard(state):
    profile = state["profile"]
    if profile is None:
        return f"NOT EXISTS(SELECT 1 FROM {TABLE})"
    return f"(SELECT count(*) FROM {TABLE})=1 AND EXISTS(SELECT 1 FROM {TABLE} WHERE " + _all_conditions([
        f"{key} IS {reads._scalar(value)}" for key, value in profile.items()]) + ")"


def transition(action, state, policy, active_sha, version):
    lane, profile = state["lane"], state["profile"]
    bot, admin, member, group = map(_literal, (policy[key] for key in ("botId", "adminId", "memberId", "groupId")))
    _require(lane["foreign_lane"] == lane["foreign_active"] == 0 and reads._integer(lane["epoch"] + 1, 1), ERROR)
    sql = reads._state_sql(policy["botId"], policy["adminId"], policy["memberId"])
    before = f"({PINNED}) AND ({reads.PINNED}) AND {reads._cas(sql, lane, quiet=False)} AND {_profile_guard(state)}"
    epoch, generation, mode = lane["epoch"] + 1, lane["generation"], lane["mode"]
    statements = []
    if action == "close":
        _require(mode in ("isolated", "general"), ERROR)
        if profile is None:
            _require(lane["groups"] == 0, ERROR)
            statements.append(f"INSERT INTO {TABLE} VALUES ({bot},'{PROFILE}',{_literal(version.revision)},{_literal(active_sha)},{admin},{member},{group},NULL,NULL)")
        statements.append(f"INSERT INTO {reads.TABLE}(bot_id,epoch,mode) VALUES({bot},{epoch},'closed') ON CONFLICT(bot_id) DO UPDATE SET epoch=excluded.epoch,mode='closed'")
        mode = "closed"
    elif action == "open":
        _require(profile is not None and mode == "closed" and generation is None
                 and lane["member_allowed"] in (None, 1) and all(value == 0 for value in state["work"].values()), ERROR)
        before += f" AND {_quiet_sql(policy['botId'])} AND {reads._cas(sql, lane, quiet=True)}"
        generation = lane["policy_generation"] + 1
        _require(reads._integer(generation, 1), ERROR)
        activation = _digest({"profile": PROFILE, "activeSha256": active_sha, "epoch": epoch, "generation": generation})
        statements += [f"INSERT INTO telegram_general_policy VALUES({bot},{generation},{_literal(version.revision)},{_literal(activation)},unixepoch(),1) ON CONFLICT(bot_id) DO UPDATE SET generation=excluded.generation,release_revision=excluded.release_revision,activation_sha256=excluded.activation_sha256,cutover_at=excluded.cutover_at,active=1",
            f"INSERT INTO telegram_general_actors SELECT bot_id,generation,{admin},1,cutover_at,'admin' FROM telegram_general_policy WHERE bot_id={bot} UNION ALL SELECT bot_id,generation,{member},1,cutover_at,'member' FROM telegram_general_policy WHERE bot_id={bot}",
            f"INSERT INTO telegram_general_groups VALUES({bot},{generation},{group},'group')",
            f"UPDATE {TABLE} SET generation={generation},opened_epoch={epoch} WHERE bot_id={bot}",
            f"UPDATE {reads.TABLE} SET epoch={epoch},mode='general',generation={generation},member_date={reads._scalar(lane['live_date'])},member_message={reads._scalar(lane['live_message'])} WHERE bot_id={bot}"]
        mode = "general"
    else:
        _require(action == "restore" and profile is not None and mode == "closed"
                 and all(value == 0 for value in state["work"].values()), ERROR)
        before += f" AND {_quiet_sql(policy['botId'])}"
        if generation is not None:
            statements += [f"UPDATE telegram_general_policy SET active=0 WHERE bot_id={bot} AND generation={generation}",
                f"DELETE FROM telegram_general_groups WHERE bot_id={bot} AND generation={generation}"]
        statements += [f"UPDATE {reads.TABLE} SET epoch={epoch},mode='isolated',generation=NULL,member_date=NULL,member_message=NULL WHERE bot_id={bot}", f"DELETE FROM {TABLE} WHERE bot_id={bot}"]
        mode, generation = "isolated", None
    after = f"EXISTS(SELECT 1 FROM {reads.TABLE} WHERE bot_id={bot} AND epoch={epoch} AND mode='{mode}' AND generation IS {reads._scalar(generation)})"
    batch = [_assert_sql(before), *statements, _assert_sql(after)]
    return ";\n".join(batch) + ";", len(batch), (epoch, mode, generation)


def run(scope, config, guard, *, action, expected_active, expected_state, artifact=None):
    policy = json.loads(config)
    scope.verify_resources()
    settings = scope.worker_config()
    _require(scope.cron_enabled(), ERROR)
    require_clear_for_release(scope)
    _schema(scope)
    deployment = scope.active()
    version, capable = scope.version(deployment.version, with_general_read_lane=True)
    _require(capable and version.telegram_config_sha256 == sha256(config.encode()).hexdigest(), ERROR)
    active_sha = reads._active_sha256(scope.target, deployment, version)
    _require(expected_active in ("", active_sha), ERROR)
    if artifact:
        _require((version.revision, version.digest, version.compatibility) == artifact, ERROR)
    else:
        _require(expected_active == active_sha and action in ("inspect", "close", "drain", "restore"), ERROR)
    state = _state(scope, policy)
    if action == "close" and state["profile"] is None:
        _require(artifact is not None, ERROR)
    _require(action == "inspect" or expected_state == _digest(state), ERROR)
    if state["profile"]:
        _require(state["profile"]["active_sha256"] == active_sha and state["profile"]["release_revision"] == version.revision, ERROR)

    def recheck():
        _require(scope.worker_config() == settings and scope.cron_enabled() and scope.active() == deployment, ERROR)
        _guard_current(guard)

    recheck()
    if action == "drain":
        _require(state["profile"] is not None and state["lane"]["mode"] == "closed"
                 and all(value == 0 for value in state["work"].values()), "The isolated general window still has durable work; keep Cron running and inspect the categorized counts.")
    elif action != "inspect":
        statement, count, successor = transition(action, state, policy, active_sha, version)
        if action == "open":
            _verify_health(version.revision)
        recheck()
        try:
            reads._query(scope, statement, count)
        except CloudflareError as exc:
            if not exc.uncertain:
                raise CloudflareError(ERROR) from None
        state = _state(scope, policy)
        _require(tuple(state["lane"][key] for key in ("epoch", "mode", "generation")) == successor, ERROR)
        recheck()
    return {"version": 1, "profile": PROFILE, "action": action, "activeSha256": active_sha,
        "stateSha256": _digest(state), "revision": version.revision, "moduleSha256": version.digest,
        "deploymentId": deployment.id, "versionId": deployment.version, "mode": state["lane"]["mode"],
        "epoch": state["lane"]["epoch"], "generation": state["lane"]["generation"],
        "inboxHighWater": state["lane"]["high_water"], "work": state["work"], "terminalCards": state["terminalCards"],
        "terminalCardPolicy": "retained-without-automatic-retry",
        "cutoverAt": state["lane"]["cutover"] if state["lane"]["generation"] is not None else None}


def main(env):
    from release_isolation import isolated_telegram_config, isolation_credentials
    _require(env.get("GITHUB_WORKFLOW_REF") == WORKFLOW and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
        and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch" and env.get("GITHUB_REF") == MAIN_REF
        and env.get("GITHUB_REPOSITORY_ID") == str(REPOSITORY_ID), ERROR)
    identities = [env.get(key, "") for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")]
    _require(all(RUN.fullmatch(value) and reads._integer(int(value), 1) for value in identities), ERROR)
    action, active, state, confirmation = [env.get(key, "") for key in (
        "GENERAL_WINDOW_ACTION", "GENERAL_WINDOW_ACTIVE_SHA256", "GENERAL_WINDOW_STATE_SHA256", "GENERAL_WINDOW_CONFIRMATION")]
    _require(action in ("inspect", "close", "open", "drain", "restore") and (active == "" or _matches(DIGEST, active))
        and (action == "inspect" and state == confirmation == "" or _matches(DIGEST, active) and _matches(DIGEST, state)
            and confirmation == f"{action} full general window for {WORKER_NAME}"), ERROR)
    revision = env.get("GITHUB_SHA", "")
    guard = lambda: require_current_main(revision)
    guard()
    temp = Path(env["RUNNER_TEMP"])
    artifact, source, bundle, manifest = None, None, None, None
    if env.get("SUBS_BOT_CI_RUN_ID"):
        source = prepare()
        bundle = temp / VERIFIED_DIRECTORY
        manifest = json.loads((bundle / "isolation.json").read_text())
        verify_artifact(bundle, manifest)
        artifact = revision, manifest["bundleSha256"], manifest["compatibilityDate"]
    config = isolated_telegram_config()
    policy = json.loads(config)
    _require((policy["adminId"], policy["memberId"], policy["groupId"])
        == ("8813701954", "8653767757", "-5114255828"), ERROR)
    target, data_token, deploy_token = isolation_credentials()
    scope = _Isolation(CloudflareClient(deploy_token), CloudflareClient(data_token), target)
    if bundle is not None:
        migrations = _load_migrations(bundle, manifest)
        kind, history = _read_state(scope.data_api, f"{scope.account}/d1/database/{target['d1Id']}/query", migrations)
        _require(kind == "managed" and len(history) == len(migrations), ERROR)
    evidence = run(scope, config, guard, action=action, expected_active=active, expected_state=state, artifact=artifact)
    evidence.update(controlRevision=revision, runId=int(identities[0]), runAttempt=int(identities[1]), artifact=source)
    with (temp / "general-isolation-window.json").open("xb") as output:
        output.write(_canonical(evidence))


if __name__ == "__main__":
    try:
        os.umask(0o077)
        main(os.environ)
        print("Verified the full general Telegram isolation window checkpoint.")
    except (ArtifactError, CloudflareError, MigrationError, OSError, ValueError, TypeError, KeyError, RecursionError):
        raise SystemExit(ERROR) from None

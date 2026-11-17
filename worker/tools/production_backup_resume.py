"""Explicitly approved continuation of a bounded interrupted backup.

No approval is synthesized here. A caller must first authenticate the private
transaction/intent and the original hosted run, then supply the exact action
envelope and persist the intent before the guarded single CAS.
"""
import d1_migrations as migrations
import production_backup_capacity as capacity
from general_isolation_window import work_sql
from production_control import CONTROL, INVOCATIONS, _mutate_sql
from production_target import NAMES, digest, require
import production_backup_transaction as maintenance


def _target(ctl):
    environment = ctl.target.environment
    require(environment in {"rehearsal", "production"}
            and ctl.target.data["workerName"] == NAMES[environment][0])


def _dependencies(ctl):
    require(ctl.telegram is not None)
    ctl.verify_dependency()
    ctl.telegram.identity()
    ctl.telegram.group_permissions()
    webhook = ctl.telegram.call("getWebhookInfo")
    ctl.telegram.webhook_info(webhook)
    require(webhook.get("url") == "https://" + ctl.target.data["hostname"] + "/telegram/webhook"
            and webhook.get("max_connections") == ctl.target.data["webhook"]["maxConnections"]
            and set(webhook.get("allowed_updates", [])) == set(ctl.target.data["webhook"]["allowedUpdates"])
            and webhook.get("has_custom_certificate") is False)
    ctl.verify_domain()


def _quiet_state(ctl, initial, expected_control):
    current = ctl.inspect()
    require(current["control"] == expected_control and current["release"] == initial.get("release")
            and current["configurationSha256"] == initial.get("configurationSha256")
            and not any(current["work"].values())
            and not any(current["terminal"].get(key, 0) for key in
                        ("uncertain", "terminalUnknown", "terminalEditFailure", "unknownInvocations", "unknownUpdates")),
            "The exact predecessor or external-result state changed.")
    return current


def _stopped_export(journal, target_sha):
    journal.load()
    state = journal.value
    require(isinstance(state, dict) and state.get("scopeSha256") == target_sha,
            "The scoped recovery journal is missing or differs.")
    export = state.get("export")
    require(isinstance(export, dict) and export.get("state") in {"download-ready", "sql-archived", "complete"},
            "Native export is not independently confirmed stopped.")


def plan_failed_backup(ctl, api, source, recovery_journal, *, initial, frozen, fingerprint, session):
    _target(ctl)
    require(maintenance.SESSION.fullmatch(session or "") is not None
            and initial.get("control", {}).get("admission") == "open" and initial["control"].get("workers") == "run"
            and frozen.get("admission") == "closed" and frozen.get("workers") == "frozen")
    _stopped_export(recovery_journal, ctl.target.digest)
    before = _quiet_state(ctl, initial, frozen)
    require(capacity.frozen_fingerprint(api, source) == fingerprint,
            "The complete frozen data or referenced object closure changed.")
    _dependencies(ctl)
    action = "maintenance-resume:" + digest({"session": session, "frozen": frozen, "fingerprint": fingerprint})
    return {"approvalAction": action, "stateSha256": before["stateSha256"]}


def plan_aborted_drain(ctl, *, initial, paused, session):
    _target(ctl)
    require(maintenance.SESSION.fullmatch(session or "") is not None
            and initial.get("control", {}).get("admission") == "open" and initial["control"].get("workers") == "run"
            and paused.get("admission") == "closed" and paused.get("workers") == "run")
    before = _quiet_state(ctl, initial, paused)
    _dependencies(ctl)
    return {"approvalAction": "maintenance-resume-drain:" + digest({"session": session, "paused": paused}),
            "stateSha256": before["stateSha256"]}


def plan_uncaptured_backup(ctl, api, source, recovery_journal, *, initial, frozen, fingerprint, session):
    """Resume only when the full maintenance journal proves capture never started."""
    _target(ctl)
    require(maintenance.SESSION.fullmatch(session or "") is not None
            and initial.get("control", {}).get("admission") == "open" and initial["control"].get("workers") == "run"
            and frozen.get("admission") == "closed" and frozen.get("workers") == "frozen")
    recovery_journal.load()
    require(recovery_journal.value is None, "A recovery journal exists; export initiation cannot be ruled out.")
    before = _quiet_state(ctl, initial, frozen)
    if fingerprint is not None:
        require(capacity.frozen_fingerprint(api, source) == fingerprint,
                "The confirmed frozen data or referenced object closure changed.")
    _dependencies(ctl)
    action = "maintenance-resume-uncaptured:" + digest({"session": session, "frozen": frozen, "fingerprint": fingerprint})
    return {"approvalAction": action, "stateSha256": before["stateSha256"]}


def resume_uncaptured_backup(ctl, api, source, recovery_journal, *, initial, frozen, fingerprint, session,
                             approval_envelope, record_intent):
    kwargs = {"initial": initial, "frozen": frozen, "fingerprint": fingerprint, "session": session}
    plan = plan_uncaptured_backup(ctl, api, source, recovery_journal, **kwargs)
    ctl.approval(approval_envelope, plan["approvalAction"], plan["stateSha256"])
    record_intent(plan["stateSha256"], plan["approvalAction"])
    require(plan_uncaptured_backup(ctl, api, source, recovery_journal, **kwargs) == plan,
            "The approved uncaptured backup predecessor changed after its intent.")
    return _commit(ctl, frozen)


def _commit(ctl, control):
    predicate = " AND ".join(f"{key} IS {migrations._literal(value) if isinstance(value, str) else value}" for key, value in control.items())
    quiet, fields = work_sql(ctl.target.data["botId"])
    bot = migrations._literal(ctl.target.data["botId"])
    conditions = [f"EXISTS(SELECT 1 FROM {CONTROL} WHERE {predicate})",
                  "EXISTS(SELECT 1 FROM (" + quiet + ") WHERE " + " AND ".join(f"{field}=0" for field in fields) + ")",
                  f"NOT EXISTS(SELECT 1 FROM {INVOCATIONS} WHERE state IN ('running','uncertain'))",
                  "NOT EXISTS(SELECT 1 FROM subs_bot_production_updates WHERE state IN ('processing','uncertain'))",
                  f"NOT EXISTS(SELECT 1 FROM telegram_outbox JOIN telegram_inbox USING(receipt_id) WHERE bot_id={bot} AND state='uncertain')",
                  f"NOT EXISTS(SELECT 1 FROM telegram_group_share_cards JOIN telegram_private_share_creations USING(receipt_id) WHERE bot_id={bot} AND (telegram_group_share_cards.state='uncertain' OR (telegram_group_share_cards.state='sent' AND telegram_group_share_cards.shown<101 AND telegram_group_share_cards.attempts>=4)))"]
    ctl.guard()
    _mutate_sql(ctl.data, ctl.database, [migrations._assert_sql(" AND ".join(conditions)),
        f"UPDATE {CONTROL} SET admission='open',workers='run',epoch=epoch+1 WHERE singleton=1"])
    after = ctl.inspect()
    require(after["control"]["epoch"] == control["epoch"] + 1 and after["control"]["admission"] == "open"
            and after["control"]["workers"] == "run", "Maintenance resume needs independent reconciliation.")
    return after


def resume_failed_backup(ctl, api, source, recovery_journal, *, initial, frozen, fingerprint, session,
                         approval_envelope, record_intent):
    plan = plan_failed_backup(ctl, api, source, recovery_journal, initial=initial, frozen=frozen,
                              fingerprint=fingerprint, session=session)
    ctl.approval(approval_envelope, plan["approvalAction"], plan["stateSha256"])
    record_intent(plan["stateSha256"], plan["approvalAction"])
    again = plan_failed_backup(ctl, api, source, recovery_journal, initial=initial, frozen=frozen,
                               fingerprint=fingerprint, session=session)
    require(again == plan, "The approved resume predecessor changed after its intent.")
    return _commit(ctl, frozen)


def resume_aborted_drain(ctl, *, initial, paused, session, approval_envelope, record_intent):
    plan = plan_aborted_drain(ctl, initial=initial, paused=paused, session=session)
    ctl.approval(approval_envelope, plan["approvalAction"], plan["stateSha256"])
    record_intent(plan["stateSha256"], plan["approvalAction"])
    again = plan_aborted_drain(ctl, initial=initial, paused=paused, session=session)
    require(again == plan, "The approved resume predecessor changed after its intent.")
    return _commit(ctl, paused)

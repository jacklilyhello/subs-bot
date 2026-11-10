"""Open an isolated page-jump epoch only after its exact activation is durable."""

from cloudflare_isolation import _require, _verify_health
from page_jump_activation import INTENT_COLUMNS, INTENT_VALUES, JOURNAL, PINS, _release
from page_jump_control import CONTROL, SEQUENCE, _integer
from page_jump_rollback import _active_activation, _active_sha
from stage_page_jump_isolation import _digest, _gate_document

STALE = "The isolated page-jump open checkpoint changed."


def open_admission(scope, telegram_config, guard, *, epoch, stage_sha256, revision, run_id, attempt):
    journal, policy_sha256, current = _release(scope, telegram_config, guard)
    record, active, version, unchanged = _active_activation(scope, journal, policy_sha256, current, epoch, stage_sha256)
    _require(version.revision == revision and _integer(run_id, 1) and run_id > record.intent.intent_run_id, STALE)
    journal.require_clear()
    _verify_health(revision)

    observed = journal.control.observe()
    gate = observed.gate
    _require(gate is not None and gate.epoch == epoch and (gate.enabled or not observed.unsettled) and unchanged(), STALE)
    if not gate.enabled:
        floor = gate.origin_after_receipt
        bot = journal.control.bot_id
        gate = journal.control._write(f"""UPDATE {CONTROL} SET enabled=1,origin_after_receipt={SEQUENCE}
            WHERE bot_id=? AND epoch=? AND enabled=0 AND origin_after_receipt=? AND {SEQUENCE}>=origin_after_receipt
              AND {PINS}
              AND NOT EXISTS(SELECT 1 FROM {JOURNAL} WHERE deployment_id IS NULL)
              AND EXISTS(SELECT 1 FROM {JOURNAL} WHERE bot_id=? AND ({INTENT_COLUMNS}) IS ({INTENT_VALUES})
                AND deployment_id=? AND restores_epoch IS NULL)
              AND NOT EXISTS(SELECT 1 FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id)
                WHERE inbox.bot_id=? AND inbox.receipt_nonce='view-jump:v2' AND reply.state IN ('pending','leased','sending'))
            """, (bot, epoch, floor, bot, *record.intent.sql_values(), active.id, bot),
            lambda result: (result is not None and result.epoch == epoch and result.enabled
                            and result.origin_after_receipt >= floor), unchanged)
    _require(unchanged() and journal.control.observe().gate == gate, STALE)
    return {"version": 1, "phase": "opened", "revision": revision, "operationRunId": run_id,
            "operationRunAttempt": attempt, "epoch": epoch, "stageSha256": stage_sha256,
            "openedGateSha256": _digest(_gate_document(gate)), "activeSha256": _active_sha(scope, active, version)}

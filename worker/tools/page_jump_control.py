"""D1 transitions for a future protected page-jump release.

The caller owns the repository run and active deployment checks. It passes the
trusted run ID, the exact checkpoint from the prior phase, and a guard that
rechecks the isolated release. This module has no CLI.
"""

from dataclasses import dataclass
import re

from cloudflare_isolation import (
    CloudflareError,
    PAGE_JUMP_CONTROL_MIGRATION,
    PAGE_JUMP_CONTROL_MIGRATION_SHA256,
    PAGE_JUMP_MIGRATION,
    PAGE_JUMP_MIGRATION_SHA256,
    _Isolation,
    _require,
)

MAX_SAFE_INTEGER = 2**53 - 1
CONTROL = "telegram_page_jump_controls"
PINNED = f"""(SELECT count(*) FROM subs_bot_schema_migrations WHERE mode='applied' AND (
    (position=42 AND name='{PAGE_JUMP_MIGRATION}' AND sha256='{PAGE_JUMP_MIGRATION_SHA256}') OR
    (position=43 AND name='{PAGE_JUMP_CONTROL_MIGRATION}' AND sha256='{PAGE_JUMP_CONTROL_MIGRATION_SHA256}')
))=2"""
SEQUENCE = "COALESCE((SELECT seq FROM sqlite_sequence WHERE name='telegram_inbox'),0)"
READ_ERROR = "The isolated page-jump gate could not be verified."
STALE = "The isolated page-jump checkpoint is stale."
UNCERTAIN = "The isolated page-jump transition could not be confirmed. Recheck the same operation."


def _integer(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_SAFE_INTEGER


@dataclass(frozen=True)
class PageJumpGate:
    epoch: int
    enabled: bool
    origin_after_receipt: int

    def __post_init__(self):
        _require(_integer(self.epoch, 1) and type(self.enabled) is bool and _integer(self.origin_after_receipt),
                 "The isolated page-jump checkpoint is invalid.")


@dataclass(frozen=True)
class PageJumpObservation:
    gate: PageJumpGate | None
    unsettled: bool


class PageJumpControl:
    def __init__(self, scope: _Isolation, bot_id: str):
        # The release constructs and verifies the existing _Isolation scope.
        _require(isinstance(bot_id, str) and re.fullmatch(r"[1-9][0-9]{0,15}", bot_id) and _integer(int(bot_id), 1),
                 "The isolated page-jump Bot scope is invalid.")
        self.data_api = scope.data_api
        self.path = f"{scope.account}/d1/database/{scope.target['d1Id']}/query"
        self.bot_id = bot_id

    def _query(self, sql, *params):
        result = self.data_api("POST", self.path, {"sql": sql, "params": [str(value) for value in params]})
        _require(isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict)
                 and result[0].get("success") is True and isinstance(result[0].get("results"), list), READ_ERROR)
        return result[0]["results"]

    def observe(self):
        """Read the exact Bot's gate and unresolved deliveries from one D1 statement."""
        try:
            rows = self._query(f"""
                SELECT {PINNED} AS pinned, {SEQUENCE} AS seq,
                  gate.epoch,gate.enabled,gate.origin_after_receipt AS origin,
                  EXISTS(SELECT 1 FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING(receipt_id)
                    WHERE inbox.bot_id=? AND inbox.receipt_nonce='view-jump:v2'
                      AND reply.state IN ('pending','leased','sending')) AS unsettled
                FROM (SELECT 1) AS singleton LEFT JOIN {CONTROL} AS gate ON gate.bot_id=?
            """, self.bot_id, self.bot_id)
            _require(len(rows) == 1 and isinstance(rows[0], dict), READ_ERROR)
            row = rows[0]
            _require(set(row) == {"pinned", "seq", "epoch", "enabled", "origin", "unsettled"}
                     and type(row["pinned"]) is int and row["pinned"] == 1 and _integer(row["seq"])
                     and type(row["unsettled"]) is int and row["unsettled"] in (0, 1), READ_ERROR)
            if (row["epoch"], row["enabled"], row["origin"]) == (None, None, None):
                return PageJumpObservation(None, bool(row["unsettled"]))
            _require(type(row["enabled"]) is int and row["enabled"] in (0, 1)
                     and _integer(row["origin"]) and row["origin"] <= row["seq"], READ_ERROR)
            return PageJumpObservation(PageJumpGate(row["epoch"], bool(row["enabled"]), row["origin"]), bool(row["unsettled"]))
        except (CloudflareError, TypeError, ValueError, KeyError):
            raise CloudflareError(READ_ERROR) from None

    def _guard(self, guard, *, uncertain=False):
        try:
            if guard() is True:
                return
        except Exception:
            pass
        raise CloudflareError("The isolated page-jump release checkpoint could not be verified.", uncertain=uncertain)

    def _write(self, sql, params, confirmed, guard):
        self._guard(guard)
        try:
            self._query(sql, *params)
        except CloudflareError:
            # A failed acknowledgement cannot distinguish a lost reply from a lost write.
            pass
        try:
            after = self.observe().gate
        except CloudflareError:
            raise CloudflareError(UNCERTAIN, uncertain=True) from None
        if not confirmed(after):
            raise CloudflareError(UNCERTAIN, uncertain=True)
        self._guard(guard, uncertain=True)
        return after

    def _advance(self, expected, run_id, guard, *, pause):
        _require(expected is None or isinstance(expected, PageJumpGate), STALE)
        old_epoch = expected.epoch if expected else 0
        old_floor = expected.origin_after_receipt if expected else 0
        _require(_integer(run_id, 1) and run_id > old_epoch,
                 "The protected run ID must be newer than the page-jump checkpoint.")
        _require(pause or expected is None or not expected.enabled, STALE)
        current = self.observe().gate

        def confirmed(gate):
            return (gate is not None and gate.epoch == run_id and not gate.enabled
                    and (gate.origin_after_receipt >= old_floor if pause and expected else gate.origin_after_receipt == old_floor))

        if confirmed(current):
            self._guard(guard)
            return current
        _require(current == expected or (pause and current and expected and current.epoch == old_epoch
                 and current.origin_after_receipt >= old_floor), STALE)
        if expected is None:
            sql = f"""INSERT INTO {CONTROL}(bot_id,epoch,enabled,origin_after_receipt)
                SELECT ?,?,0,0 WHERE {PINNED} ON CONFLICT(bot_id) DO NOTHING"""
            params = (self.bot_id, run_id)
        else:
            # A pause deliberately tolerates a racing open of the expected epoch.
            # Advancing that epoch prevents a delayed open from restoring admission.
            eligible = "origin_after_receipt>=?" if pause else "enabled=0 AND origin_after_receipt=?"
            sql = f"""UPDATE {CONTROL} SET epoch=?,enabled=0
                WHERE bot_id=? AND epoch=? AND {eligible} AND {PINNED}"""
            params = (run_id, self.bot_id, old_epoch, old_floor)
        return self._write(sql, params, confirmed, guard)

    def reserve(self, expected, run_id, guard):
        """Reserve one closed epoch using this exact trusted stage run's unique ID."""
        return self._advance(expected, run_id, guard, pause=False)

    def open(self, reserved, guard):
        """Enable an exact bound active candidate, pinning the inbox watermark in the write."""
        _require(isinstance(reserved, PageJumpGate) and not reserved.enabled, STALE)

        def confirmed(gate):
            return (gate is not None and gate.epoch == reserved.epoch and gate.enabled
                    and gate.origin_after_receipt >= reserved.origin_after_receipt)

        current = self.observe().gate
        if confirmed(current):
            self._guard(guard)
            return current
        _require(current == reserved, STALE)
        return self._write(f"""UPDATE {CONTROL} SET enabled=1,origin_after_receipt={SEQUENCE}
            WHERE bot_id=? AND epoch=? AND enabled=0 AND origin_after_receipt=? AND {SEQUENCE}>=origin_after_receipt
              AND {PINNED}""", (self.bot_id, reserved.epoch, reserved.origin_after_receipt), confirmed, guard)

    def pause(self, expected, run_id, guard):
        """Close the exact old epoch and leave a higher closed tombstone, even if already closed."""
        return self._advance(expected, run_id, guard, pause=True)

    def verify_drained(self, paused, guard):
        _require(isinstance(paused, PageJumpGate) and not paused.enabled, STALE)
        current = self.observe()
        _require(current.gate == paused, STALE)
        _require(not current.unsettled, "The isolated page-jump replies have not drained.")
        self._guard(guard)
        return paused

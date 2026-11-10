"""One-shot closed activation for the protected isolation release coordinator.

The coordinator must verify the current GitHub main revision, serialize with
every protected app deployment, and block ordinary releases on a pending
journal. This source has no CLI. Opening the D1 gate is a separate operation.
"""

from dataclasses import asdict, astuple, dataclass, replace
from hashlib import sha256
import json

from cloudflare_isolation import (
    CloudflareError, DIGEST, READBACK_DELAYS, UUID, WORKER_NAME, _guard_current, _matches, _page_jump_tag, _require,
    _verify_health, sleep,
)
from d1_migrations import _load_migrations, _read_state
from page_jump_control import CONTROL, PINNED, PageJumpControl, _integer
from page_jump_recovery import _source, read_source
from stage_page_jump_isolation import _digest, _gate_document, _unique_fields, artifact_proof

JOURNAL = "telegram_page_jump_activation_journal"
MIGRATION = "0045_telegram_page_jump_activation_journal.sql"
MIGRATION_SHA256 = "0a605a61532c420d35e4e2e19bc12338151d0a4e310ee24cd06c53653e94fe6f"
TABLE_SHA256 = "e4963aacecf45d5dada670f8448d092cb702173ae88ca90cd0f2375feffd8eeb"
PINS = f"""{PINNED} AND EXISTS (
    SELECT 1 FROM subs_bot_schema_migrations WHERE position=45 AND mode='applied'
        AND name='{MIGRATION}' AND sha256='{MIGRATION_SHA256}'
)"""
READ_ERROR = "The isolated page-jump activation journal could not be verified."
PENDING = "An isolated page-jump activation remains unresolved."
UNCERTAIN = "The isolated page-jump activation could not be confirmed. Reconcile the existing intent."
STALE = "The isolated closed page-jump stage changed."
INVALID = "Invalid isolated page-jump activation inputs."


def _require_confirmed(condition):
    if not condition:
        raise CloudflareError(UNCERTAIN, uncertain=True)


def activation_inputs(mode, confirmation, raw):
    _require(mode in ("activate", "reconcile", "pause-durable", "rollback", "open")
             and confirmation == f"{mode} page jump for {WORKER_NAME}"
             and isinstance(raw, str) and 0 < len(raw) <= 1024, INVALID)
    try:
        value = json.loads(raw, object_pairs_hook=_unique_fields)
    except (ValueError, TypeError, RecursionError, CloudflareError):
        raise CloudflareError(INVALID) from None
    _require(isinstance(value, dict), INVALID)
    if mode in ("activate", "rollback"):
        key = "stage" if mode == "activate" else "pause"
        _require(set(value) == {key} and _source(value[key]), INVALID)
    else:
        _require(set(value) == {"epoch", "stageSha256"} and _integer(value["epoch"], 1)
                 and _matches(DIGEST, value["stageSha256"]), INVALID)
    return value


def _pending(read):
    row = read(f"""SELECT {PINS} AS pinned,
        (SELECT sql FROM sqlite_schema WHERE type='table' AND name='{JOURNAL}') AS schema_sql,
        EXISTS(SELECT 1 FROM {JOURNAL} WHERE deployment_id IS NULL) AS pending""",
        {"pinned", "schema_sql", "pending"})
    _require(type(row["pinned"]) is int and row["pinned"] == 1 and isinstance(row["schema_sql"], str)
             and sha256(row["schema_sql"].encode("utf-8")).hexdigest() == TABLE_SHA256
             and type(row["pending"]) is int and row["pending"] in (0, 1), READ_ERROR)
    return bool(row["pending"])


def require_clear_for_release(scope, *, required=False):
    """Fence ordinary deploy and rollback. Only an entirely absent 0045 can be skipped."""
    path = f"{scope.account}/d1/database/{scope.target['d1Id']}/query"

    def read(sql, fields):
        try:
            result = scope.data_api("POST", path, {"sql": sql})
            _require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True, READ_ERROR)
            rows = result[0]["results"]
            _require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict)
                     and set(rows[0]) == fields, READ_ERROR)
            return rows[0]
        except (AttributeError, KeyError, TypeError, ValueError, CloudflareError):
            raise CloudflareError(READ_ERROR) from None

    schema = read(f"""SELECT
        EXISTS (SELECT 1 FROM sqlite_schema WHERE name='{JOURNAL}') AS pageJumpJournal,
        EXISTS (SELECT 1 FROM sqlite_schema WHERE type='table' AND name='subs_bot_schema_migrations') AS ledger""",
        {"pageJumpJournal", "ledger"})
    _require(all(type(value) is int and value in (0, 1) for value in schema.values()), READ_ERROR)
    if not schema["pageJumpJournal"]:
        _require(not required, READ_ERROR)
        if schema["ledger"]:
            row = read(f"""SELECT EXISTS(SELECT 1 FROM subs_bot_schema_migrations
                WHERE position=45 OR name='{MIGRATION}') AS pageJumpJournalRegistered""", {"pageJumpJournalRegistered"})
            _require(type(row["pageJumpJournalRegistered"]) is int and row["pageJumpJournalRegistered"] == 0, READ_ERROR)
        return
    _require(schema["ledger"] == 1, READ_ERROR)
    _require(not _pending(read), PENDING)


@dataclass(frozen=True)
class ActivationIntent:
    epoch: int
    intent_run_id: int
    stage_sha256: str
    prior_sha256: str
    candidate_sha256: str
    prior_deployment_id: str
    prior_version_id: str
    candidate_version_id: str
    restores_epoch: int | None = None

    def __post_init__(self):
        _require(_integer(self.epoch, 1) and _integer(self.intent_run_id, 1) and self.intent_run_id > self.epoch
                 and all(_matches(DIGEST, value) for value in
                         (self.stage_sha256, self.prior_sha256, self.candidate_sha256))
                 and all(_matches(UUID, value) for value in
                         (self.prior_deployment_id, self.prior_version_id, self.candidate_version_id))
                 and self.prior_version_id != self.candidate_version_id
                 and (self.restores_epoch is None or _integer(self.restores_epoch, 1)
                      and self.restores_epoch < self.epoch), READ_ERROR)

    def sql_values(self):
        return (*astuple(self)[:-1], self.restores_epoch or "")

    @property
    def target_epoch(self):
        return self.epoch if self.restores_epoch is None else None

    @property
    def message(self):
        return "page-jump:" + _digest(asdict(self))


INTENT_COLUMNS = ",".join(ActivationIntent.__dataclass_fields__)
INTENT_VALUES = "?,?,?,?,?,?,?,?,CAST(NULLIF(?,'') AS INTEGER)"


@dataclass(frozen=True)
class ActivationRecord:
    intent: ActivationIntent
    deployment_id: str | None


def _reverses(intent, source):
    return (source is not None and source.intent.restores_epoch is None and source.deployment_id is not None
            and intent.restores_epoch == source.intent.epoch and intent.stage_sha256 == source.intent.stage_sha256
            and intent.prior_deployment_id == source.deployment_id
            and intent.prior_version_id == source.intent.candidate_version_id
            and intent.candidate_version_id == source.intent.prior_version_id)


class PageJumpActivationJournal:
    def __init__(self, control):
        self.control = control

    def _query(self, sql, *params):
        try:
            return self.control._query(sql, *params)
        except (CloudflareError, TypeError, ValueError, KeyError):
            raise CloudflareError(READ_ERROR) from None

    def _status(self):
        def read(sql, fields):
            rows = self._query(sql)
            _require(len(rows) == 1 and isinstance(rows[0], dict) and set(rows[0]) == fields, READ_ERROR)
            return rows[0]

        return _pending(read)

    def require_clear(self):
        """Require the pinned journal and no unresolved intent in this isolation database."""
        _require(not self._status(), PENDING)

    @staticmethod
    def _record(row):
        _require(isinstance(row, dict) and set(row) == set(ActivationIntent.__dataclass_fields__) | {"deployment_id"},
                 READ_ERROR)
        values = dict(row)
        deployment_id = values.pop("deployment_id")
        intent = ActivationIntent(**values)
        _require(deployment_id is None or (_matches(UUID, deployment_id)
                 and deployment_id != intent.prior_deployment_id), READ_ERROR)
        return ActivationRecord(intent, deployment_id)

    def read(self, epoch):
        _require(_integer(epoch, 1), READ_ERROR)
        self._status()
        rows = self._query(f"""SELECT {INTENT_COLUMNS},deployment_id FROM {JOURNAL}
            WHERE bot_id=? AND epoch=?""", self.control.bot_id, epoch)
        _require(len(rows) <= 1, READ_ERROR)
        return self._record(rows[0]) if rows else None

    def claim(self, intent, reserved):
        """Only an acknowledged new insert permits this caller to send the POST."""
        _require(reserved.epoch == intent.epoch and not reserved.enabled, STALE)
        self.require_clear()
        try:
            rows = self._query(f"""INSERT INTO {JOURNAL}(bot_id,{INTENT_COLUMNS})
                SELECT ?,{INTENT_VALUES}
                WHERE {PINS} AND NOT EXISTS(SELECT 1 FROM {JOURNAL} WHERE deployment_id IS NULL)
                  AND EXISTS(SELECT 1 FROM {CONTROL} WHERE bot_id=? AND epoch=? AND enabled=0 AND origin_after_receipt=?)
                  AND (NULLIF(?,'') IS NULL OR EXISTS(SELECT 1 FROM {JOURNAL} AS source
                    WHERE source.bot_id=? AND source.epoch=? AND source.restores_epoch IS NULL
                      AND source.deployment_id=? AND source.stage_sha256=?
                      AND source.candidate_version_id=? AND source.prior_version_id=?))
                ON CONFLICT(bot_id,epoch) DO NOTHING
                RETURNING {INTENT_COLUMNS},deployment_id""", self.control.bot_id, *intent.sql_values(),
                self.control.bot_id, intent.epoch, reserved.origin_after_receipt,
                intent.restores_epoch or "", self.control.bot_id, intent.restores_epoch or "", intent.prior_deployment_id,
                intent.stage_sha256, intent.prior_version_id, intent.candidate_version_id)
            expected = ActivationRecord(intent, None)
            _require(len(rows) == 1 and self._record(rows[0]) == expected and self.read(intent.epoch) == expected,
                     READ_ERROR)
        except CloudflareError:
            raise CloudflareError(UNCERTAIN, uncertain=True) from None

    def confirm(self, record, active):
        _require_confirmed(active.version == record.intent.candidate_version_id and active.message == record.intent.message
                           and _matches(UUID, active.id) and active.id != record.intent.prior_deployment_id)
        if record.deployment_id is not None:
            _require_confirmed(record.deployment_id == active.id)
            return record
        intent = record.intent
        try:
            self._query(f"""UPDATE {JOURNAL} SET deployment_id=?
                WHERE bot_id=? AND ({INTENT_COLUMNS}) IS ({INTENT_VALUES}) AND deployment_id IS NULL
                  AND {PINS}
                  AND EXISTS(SELECT 1 FROM {CONTROL} WHERE bot_id=? AND epoch>=? AND enabled=0)""",
                active.id, self.control.bot_id, *intent.sql_values(), self.control.bot_id, intent.epoch)
        except CloudflareError:
            # A lost confirmation can be recovered by exact D1 readback.
            pass
        expected = ActivationRecord(intent, active.id)
        _require_confirmed(self.read(intent.epoch) == expected)
        return expected


def _release(scope, telegram_config, guard):
    scope.verify_resources()
    settings = scope.worker_config()
    _require(scope.cron_enabled(), STALE)
    try:
        policy_sha256 = sha256(telegram_config.encode("utf-8")).hexdigest()
        bot_id = json.loads(telegram_config)["botId"]
    except (AttributeError, TypeError, ValueError, KeyError, RecursionError):
        raise CloudflareError(STALE) from None
    journal = PageJumpActivationJournal(PageJumpControl(scope, bot_id))

    def current():
        _guard_current(guard)
        return scope.worker_config() == settings and scope.cron_enabled()

    return journal, policy_sha256, current


def _reconcile(scope, journal, record, policy_sha256, current, ack=None):
    intent = record.intent
    if intent.restores_epoch is not None:
        _require_confirmed(_reverses(intent, journal.read(intent.restores_epoch)))
    for delay in READBACK_DELAYS:
        if delay:
            sleep(delay)
        try:
            active = scope.active()
        except CloudflareError:
            continue
        if (active.id, active.version) == (intent.prior_deployment_id, intent.prior_version_id):
            continue
        if active.version != intent.candidate_version_id or active.message != intent.message or (ack and active.id != ack):
            break
        version = scope.version(active.version, page_jump_epoch=intent.target_epoch)
        _require_confirmed(version.telegram_config_sha256 == policy_sha256
                           and _digest({"versionId": active.version, "version": asdict(version)}) == intent.candidate_sha256
                           and current() and scope.active() == active)
        confirmed = journal.confirm(record, active)
        _require_confirmed(current() and scope.active() == active)
        return confirmed
    raise CloudflareError(UNCERTAIN, uncertain=True)


def reconcile_activation(scope, telegram_config, guard, *, epoch, stage_sha256):
    """Verify an existing journal entry with no dependence on the stage archive and no Worker POST."""
    journal, policy_sha256, current = _release(scope, telegram_config, guard)
    record = journal.read(epoch)
    _require(record is not None, "No isolated page-jump activation intent exists.")
    _require(stage_sha256 == record.intent.stage_sha256, STALE)
    return _reconcile(scope, journal, record, policy_sha256, current)


def _verify_stage_build(scope, bundle, stage):
    raw = (bundle / "isolation.json").read_bytes()
    manifest = json.loads(raw)
    proof = artifact_proof(bundle.parent, manifest)
    _require((manifest["revision"], sha256(raw).hexdigest(), manifest["bundleSha256"], proof["runId"], proof["runAttempt"],
              proof["artifactId"], proof["archiveSha256"])
             == tuple(stage[name] for name in ("revision", "ciManifestSha256", "bundleSha256", "ciRunId", "ciRunAttempt",
                                               "ciArtifactId", "ciArchiveSha256")), STALE)
    migrations = _load_migrations(bundle, manifest)
    _require(len(migrations) >= 45 and (migrations[44].name, migrations[44].sha256) == (MIGRATION, MIGRATION_SHA256),
             READ_ERROR)
    kind, history = _read_state(scope.data_api, f"{scope.account}/d1/database/{scope.target['d1Id']}", migrations)
    _require(kind == "managed" and len(history) == len(migrations), STALE)


def activate_once(scope, source, telegram_config, guard, *, run_id, revision, bundle):
    """Revalidate the protected stage and activate the exact candidate while the D1 gate stays closed."""
    stage = read_source(source, "stage")
    _require(revision == stage["revision"], STALE)
    journal, policy_sha256, current = _release(scope, telegram_config, guard)
    _verify_stage_build(scope, bundle, stage)
    record = journal.read(stage["epoch"])
    if record is not None:
        _require(record.intent.restores_epoch is None and record.intent.stage_sha256 == source["archiveSha256"]
                 and record.intent.prior_sha256 == stage["checkpoint"]["activeSha256"]
                 and record.intent.candidate_sha256 == stage["candidateSha256"], STALE)
        return _reconcile(scope, journal, record, policy_sha256, current)

    previous = scope.active()
    active = scope.version(previous.version)
    _require(active.telegram_page_jump_control_capable and active.telegram_page_jump_epoch is None
             and (active.revision, active.digest, active.telegram_config_sha256)
             == (stage["revision"], stage["bundleSha256"], policy_sha256)
             and _digest({"scope": scope.target, "deployment": asdict(previous), "version": asdict(active)})
             == stage["checkpoint"]["activeSha256"], STALE)
    desired = replace(active, tag=_page_jump_tag(active.tag, stage["epoch"], active.digest),
                      telegram_page_jump_epoch=stage["epoch"])
    candidate = scope.staged(desired)
    _require(candidate is not None and _digest({"versionId": candidate, "version": asdict(desired)})
             == stage["candidateSha256"], STALE)
    intent = ActivationIntent(stage["epoch"], run_id, source["archiveSha256"], stage["checkpoint"]["activeSha256"],
                              stage["candidateSha256"], previous.id, previous.version, candidate)
    observed = journal.control.observe()
    reserved = observed.gate
    _require(reserved is not None and reserved.epoch == intent.epoch and not reserved.enabled
             and _digest(_gate_document(reserved)) == stage["reservedGateSha256"]
             and not observed.unsettled and current() and scope.active() == previous, STALE)
    _verify_health(active.revision)
    return _deploy_once(scope, journal, intent, observed, previous, policy_sha256, current)


def _deploy_once(scope, journal, intent, observed, previous, policy_sha256, current):
    journal.claim(intent, observed.gate)
    # From here on, failure leaves the durable unresolved intent. Another run
    # can only reconcile this exact POST, including after the gate is paused.
    pending = ActivationRecord(intent, None)
    _require_confirmed(current() and scope.active() == previous and journal.control.observe() == observed
                       and journal.read(intent.epoch) == pending)
    try:
        result = scope.worker_api("POST", scope.deployments, {
            "strategy": "percentage",
            "versions": [{"version_id": intent.candidate_version_id, "percentage": 100}],
            "annotations": {"workers/message": intent.message},
        })
    except CloudflareError:
        result = None
    ack = result.get("id") if isinstance(result, dict) else None
    return _reconcile(scope, journal, pending, policy_sha256, current, ack if _matches(UUID, ack) else None)

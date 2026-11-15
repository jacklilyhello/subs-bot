"""Opt-in, payload-free observation of legacy polling and handler boundaries.

The private sidecar is evidence, not an update queue or a deduplication layer.
It cannot prove business success, recover missing payloads or replay side effects.
Only successful getUpdates responses confirm their submitted positive offset;
calls with an unknown outcome stay recorded even when a later offset reconciles
their acknowledgement boundary. SQLite FULL commits precede handing updates to PTB.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
from uuid import uuid4

try:
    import fcntl
except ImportError:  # Ordinary legacy mode remains available on non-POSIX hosts.
    fcntl = None

from telegram import Update
from telegram.ext import Application, ExtBot


ERROR = "Legacy handoff observation could not be recorded safely."
APPLICATION_ID = 0x53424831
MAX_ID = 2**53 - 1
SCHEMA = """
CREATE TABLE runs (
    run_id TEXT PRIMARY KEY, bot_id INTEGER NOT NULL, revision TEXT NOT NULL,
    invocation_id TEXT NOT NULL, started_at INTEGER NOT NULL,
    closed_at INTEGER, lifecycle TEXT NOT NULL DEFAULT 'active', summary_json TEXT
);
CREATE TABLE polls (
    poll_id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL REFERENCES runs,
    requested_offset INTEGER, state TEXT NOT NULL, returned_count INTEGER,
    returned_ids_sha256 TEXT
);
CREATE TABLE updates (
    run_id TEXT NOT NULL REFERENCES runs, update_id INTEGER NOT NULL, kind TEXT NOT NULL,
    state TEXT NOT NULL, fetches INTEGER NOT NULL DEFAULT 0, dispatches INTEGER NOT NULL DEFAULT 0,
    handler_errors INTEGER NOT NULL DEFAULT 0, aborts INTEGER NOT NULL DEFAULT 0,
    unobserved INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(run_id, update_id)
);
"""


class HandoffError(RuntimeError):
    """Fixed safe error; no source paths, payloads, credentials or API bodies."""


def _require(condition):
    if not condition:
        raise HandoffError(ERROR)


def _id(value, *, zero=False):
    _require(type(value) is int and int(not zero) <= value <= MAX_ID)
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _update(update):
    _require(isinstance(update, Update))
    update_id = _id(update.update_id)
    # Inspect only Telegram's field names, never serialize the Update.
    kind = next((name for name in Update.ALL_TYPES if getattr(update, name, None) is not None), "other")
    return update_id, kind


class HandoffLedger:
    def __init__(self, path: Path, bot_id: int, revision: str, invocation_id: str | None = None):
        self.db = None
        self.fd = None
        self.failed = False
        self.stop_event = None
        self.run_id = uuid4().hex
        self.bot_id = _id(bot_id)
        _require(fcntl is not None)
        _require(isinstance(revision, str) and re.fullmatch(r"[0-9a-f]{40}", revision))
        invocation_id = invocation_id or self.run_id
        _require(isinstance(invocation_id, str) and re.fullmatch(r"[0-9a-f]{32}", invocation_id))
        try:
            path = Path(path)
            _require(path.is_absolute() and ".." not in path.parts)
            parent = path.parent.resolve(strict=True)
            info = parent.stat()
            _require(info.st_uid == os.getuid() and stat.S_ISDIR(info.st_mode) and info.st_mode & 0o077 == 0)
            path = parent / path.name
            created = False
            try:
                self.fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                created = True
            except FileExistsError:
                self.fd = os.open(path, os.O_RDWR | os.O_NOFOLLOW)
            info = os.fstat(self.fd)
            _require(stat.S_ISREG(info.st_mode) and info.st_uid == os.getuid()
                     and info.st_mode & 0o077 == 0 and info.st_nlink == 1)
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.db = sqlite3.connect(path, isolation_level=None)
            if created:
                self.db.execute("PRAGMA synchronous=FULL")
                self.db.executescript(SCHEMA)
                self.db.execute(f"PRAGMA application_id={APPLICATION_ID}")
                self.db.execute("PRAGMA user_version=1")
                os.fsync(self.fd)
                directory = os.open(parent, os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            _require(self.db.execute("PRAGMA application_id").fetchone() == (APPLICATION_ID,)
                     and self.db.execute("PRAGMA user_version").fetchone() == (1,))
            _require(self.db.execute("PRAGMA journal_mode=DELETE").fetchone() == ("delete",))
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA foreign_keys=ON")
            self.db.execute("PRAGMA trusted_schema=OFF")
            _require(self.db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
                     and self.db.execute("PRAGMA foreign_key_check").fetchall() == [])
            _require(all(row == (self.bot_id,) for row in self.db.execute("SELECT DISTINCT bot_id FROM runs")))
            with self.transaction():
                self.db.execute("INSERT INTO runs(run_id,bot_id,revision,invocation_id,started_at) VALUES(?,?,?,?,?)",
                                (self.run_id, self.bot_id, revision, invocation_id, int(time.time())))
        except (OSError, sqlite3.Error, HandoffError):
            self.close()
            raise HandoffError(ERROR) from None

    def fault(self):
        self.failed = True
        if self.stop_event is not None:
            self.stop_event.set()

    @contextmanager
    def transaction(self):
        try:
            _require(not self.failed and self.db is not None)
            self.db.execute("BEGIN IMMEDIATE")
            yield
            self.db.execute("COMMIT")
        except (OSError, sqlite3.Error, HandoffError):
            if self.db is not None:
                try:
                    self.db.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
            self.fault()
            raise HandoffError(ERROR) from None

    def begin_poll(self, offset):
        if offset is not None:
            _id(offset, zero=True)  # Negative offsets discard updates and are never an observation operation.
        with self.transaction():
            cursor = self.db.execute("INSERT INTO polls(run_id,requested_offset,state) VALUES(?,?,'calling')",
                                     (self.run_id, offset))
            return cursor.lastrowid

    def poll_unknown(self, poll_id):
        with self.transaction():
            self.db.execute("UPDATE polls SET state='unknown' WHERE poll_id=? AND run_id=? AND state='calling'",
                            (poll_id, self.run_id))

    def poll_returned(self, poll_id, updates):
        observed = [_update(update) for update in updates]
        ids = [item[0] for item in observed]
        _require(len(ids) == len(set(ids)))
        with self.transaction():
            for update_id, kind in observed:
                self.db.execute("""INSERT INTO updates(run_id,update_id,kind,state,fetches)
                    VALUES(?,?,?,'fetched',1) ON CONFLICT(run_id,update_id)
                    DO UPDATE SET fetches=fetches+1""", (self.run_id, update_id, kind))
            self.db.execute("""UPDATE polls SET state='returned',returned_count=?,returned_ids_sha256=?
                WHERE poll_id=? AND run_id=? AND state='calling'""",
                            (len(ids), sha256(_canonical(ids)).hexdigest(), poll_id, self.run_id))

    def processing_started(self, update):
        update_id, kind = _update(update)
        with self.transaction():
            self.db.execute("""INSERT INTO updates(run_id,update_id,kind,state,dispatches,unobserved)
                VALUES(?,?,?,'started',1,1) ON CONFLICT(run_id,update_id)
                DO UPDATE SET state='started',dispatches=dispatches+1""", (self.run_id, update_id, kind))

    def processing_finished(self, update, *, aborted=False):
        update_id, _ = _update(update)
        with self.transaction():
            self.db.execute("""UPDATE updates SET state=?,aborts=aborts+?
                WHERE run_id=? AND update_id=? AND state='started'""",
                            ("aborted" if aborted else "handler-returned", int(aborted), self.run_id, update_id))

    def handler_error(self, update):
        update_id, _ = _update(update)
        with self.transaction():
            self.db.execute("""UPDATE updates SET state='handler-error',handler_errors=handler_errors+1
                WHERE run_id=? AND update_id=?""", (self.run_id, update_id))

    def summary(self):
        """Private boundary summary. Handler return does not attest to business or Telegram success."""
        try:
            return self._summary()
        except (OSError, sqlite3.Error, HandoffError):
            self.fault()
            raise HandoffError(ERROR) from None

    def _summary(self):
        _require(not self.failed and self.db is not None)
        confirmed = self.db.execute("""SELECT max(requested_offset) FROM polls
            WHERE run_id=? AND state='returned' AND requested_offset>0""", (self.run_id,)).fetchone()[0]
        revision, invocation = self.db.execute("SELECT revision,invocation_id FROM runs WHERE run_id=?", (self.run_id,)).fetchone()
        result = {"version": 1, "runId": self.run_id, "revision": revision, "confirmedOffset": confirmed,
                  "botIdSha256": sha256(_canonical(self.bot_id)).hexdigest(),
                  "invocationIdSha256": sha256(invocation.encode()).hexdigest(), "scope": "observed-run-only",
                  "businessSuccessProven": False, "replayAvailable": False}
        counts = {"fetchedNotStarted": "state='fetched'", "startedNotFinished": "state='started'",
                  "handlerReturned": "state='handler-returned'", "handlerErrorUpdates": "handler_errors>0",
                  "aborted": "aborts>0", "unobservedDispatches": "unobserved=1"}
        for name, condition in counts.items():
            result[name] = self.db.execute(f"SELECT count(*) FROM updates WHERE run_id=? AND {condition}",
                                           (self.run_id,)).fetchone()[0]
        result["fetchedNotStartedConfirmed"] = self.db.execute("""SELECT count(*) FROM updates
            WHERE run_id=? AND state='fetched' AND update_id<?""", (self.run_id, confirmed or 0)).fetchone()[0]
        result["duplicateDispatches"] = self.db.execute("""SELECT coalesce(sum(dispatches-1),0) FROM updates
            WHERE run_id=? AND dispatches>1""", (self.run_id,)).fetchone()[0]
        result["unknownPollOutcomes"] = self.db.execute("""SELECT count(*) FROM polls
            WHERE run_id=? AND state IN ('calling','unknown')""", (self.run_id,)).fetchone()[0]
        result["unconfirmedAckPolls"] = self.db.execute("""SELECT count(*) FROM polls WHERE run_id=?
            AND state IN ('calling','unknown') AND requested_offset>?""", (self.run_id, confirmed or 0)).fetchone()[0]
        result["priorUnclosedRuns"] = self.db.execute("SELECT count(*) FROM runs WHERE run_id<>? AND lifecycle='active'",
                                                     (self.run_id,)).fetchone()[0]
        digest = sha256()
        for row in self.db.execute("""SELECT update_id,kind,state,fetches,dispatches,handler_errors,aborts,unobserved
            FROM updates WHERE run_id=? ORDER BY update_id""", (self.run_id,)):
            digest.update(_canonical(row) + b"\n")
        result["observedUpdatesSha256"] = digest.hexdigest()
        return result

    def finish(self, *, polling_started, failures):
        summary = self.summary()
        summary["lifecycleComplete"] = bool(polling_started and not failures)
        summary["cleanupFailures"] = sorted(failures)
        with self.transaction():
            self.db.execute("UPDATE runs SET closed_at=?,lifecycle=?,summary_json=? WHERE run_id=?",
                            (int(time.time()), "complete" if summary["lifecycleComplete"] else "incomplete",
                             _canonical(summary).decode(), self.run_id))
        return {key: value for key, value in summary.items() if key != "confirmedOffset"} | {
            "confirmedOffsetSha256": sha256(_canonical(summary["confirmedOffset"])).hexdigest()}

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None


def ledger_from_environment(token, database_path):
    path = os.environ.get("TELEGRAM_HANDOFF_LEDGER_PATH")
    if path is None:
        return None
    # Opting in must never clear the very queue whose boundary is being observed.
    _require(os.environ.get("TELEGRAM_PRESERVE_PENDING_UPDATES") == "1")
    try:
        _require(Path(path).resolve() != Path(database_path).resolve())
        token_id = token.split(":", 1)[0]
        _require(token_id.isascii() and token_id.isdigit())
        return HandoffLedger(Path(path), int(token_id), os.environ.get("TELEGRAM_HANDOFF_REVISION", ""),
                             os.environ.get("INVOCATION_ID"))
    except (ValueError, OSError):
        raise HandoffError(ERROR) from None


class HandoffBot(ExtBot):
    __slots__ = ("handoff",)

    def __init__(self, *args, handoff, **kwargs):
        super().__init__(*args, **kwargs)
        with self._unfrozen():
            self.handoff = handoff

    async def initialize(self):
        await super().initialize()
        _require(self.id == self.handoff.bot_id)

    async def get_updates(self, *args, **kwargs):
        try:
            poll_id = self.handoff.begin_poll(kwargs.get("offset", args[0] if args else None))
        except HandoffError:
            self.handoff.fault()
            raise
        try:
            updates = await super().get_updates(*args, **kwargs)
        except BaseException:
            self.handoff.poll_unknown(poll_id)
            raise
        try:
            self.handoff.poll_returned(poll_id, updates)
        except HandoffError:
            self.handoff.fault()
            raise
        return updates


class HandoffApplication(Application):
    __slots__ = ("handoff",)

    def __init__(self, *, handoff, **kwargs):
        super().__init__(**kwargs)
        self.handoff = handoff

    def add_handler(self, handler, group=0):
        # This adapter observes the legacy application's blocking handlers only.
        _require(handler.block is not False)
        return super().add_handler(handler, group)

    async def process_update(self, update):
        if not isinstance(update, Update):
            return await super().process_update(update)
        self.handoff.processing_started(update)
        try:
            await super().process_update(update)
        except BaseException:
            self.handoff.processing_finished(update, aborted=True)
            raise
        else:
            self.handoff.processing_finished(update)

    async def process_error(self, update, error, job=None, coroutine=None):
        if isinstance(update, Update):
            self.handoff.handler_error(update)
        return await super().process_error(update, error, job=job, coroutine=coroutine)

"""Append-only maintenance transaction journal and interruption classifier.

This module does not create approvals or mutate the application. A caller must
independently reconcile any pending intent before it issues another operation.
"""

from datetime import datetime, timezone
from hashlib import sha256
import re

from production_target import canonical, parsed, require


SESSION = re.compile(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,9}")
SHA = re.compile(r"[0-9a-f]{64}")
REVISION = re.compile(r"[0-9a-f]{40}")
STAGES = {"started", "preflight", "pause-intent", "paused", "freeze-intent", "frozen", "frozen-data",
          "capture-intent", "poll-intent", "verified", "resume-intent", "resumed", "preserved-frozen", "failed"}
NEXT = {None: {"started"}, "started": {"preflight", "failed"},
        "preflight": {"pause-intent", "frozen", "failed"}, "pause-intent": {"paused", "failed"},
        "paused": {"freeze-intent", "failed", "resume-intent"}, "freeze-intent": {"frozen", "failed"},
        "frozen": {"frozen-data", "failed"}, "frozen-data": {"capture-intent", "failed", "resume-intent"},
        "capture-intent": {"poll-intent", "verified", "failed", "resume-intent", "preserved-frozen"},
        "poll-intent": {"capture-intent"},
        "verified": {"resume-intent", "preserved-frozen", "failed"}, "resume-intent": {"resumed", "failed"},
        "resumed": set(), "preserved-frozen": set(), "failed": {"resume-intent", "preserved-frozen"}}


def validate_step(previous, event):
    require(event["stage"] in NEXT[previous], "Backup journal phase is out of sequence.")
    details = event["details"]
    if event["stage"] == "preflight":
        require(isinstance(details.get("capacity"), dict))
    if event["stage"] == "verified":
        require(re.fullmatch(r"[0-9a-f]{32}", details.get("checkpointId", "")) is not None
                and SHA.fullmatch(details.get("manifestSha256", "")) is not None)


class Transaction:
    def __init__(self, store, session, day, target_sha256, control_revision):
        require(SESSION.fullmatch(session or "") is not None)
        require(re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", day or "") is not None)
        try:
            datetime.strptime(day, "%Y/%m/%d").replace(tzinfo=timezone.utc)
        except ValueError:
            require(False, "The backup transaction date is invalid.")
        require(SHA.fullmatch(target_sha256 or "") is not None and REVISION.fullmatch(control_revision or "") is not None)
        self.store, self.session, self.day = store, session, day
        self.target_sha256, self.control_revision = target_sha256, control_revision
        self.prefix = "maintenance/production-control/evidence/daily-backup/" + day + "/" + session + "/"

    def load(self):
        keys = self.store.list_backup_session(self.prefix)
        require(len(keys) < 64, "Backup transaction history exceeds its supported bound.")
        events, previous = [], None
        for position, key in enumerate(keys, 1):
            require(key == self.prefix + str(position).zfill(4) + ".json", "Backup journal has a gap or an unknown key.")
            raw = self.store.get(key)
            event = parsed(raw)
            require(canonical(event) == raw and set(event) == {"version", "session", "targetSha256", "controlRevision",
                    "sequence", "previousSha256", "timestamp", "stage", "details"})
            require(event["version"] == 1 and event["session"] == self.session and event["targetSha256"] == self.target_sha256
                    and event["controlRevision"] == self.control_revision and event["sequence"] == position
                    and event["previousSha256"] == previous and type(event["timestamp"]) is int
                    and event["timestamp"] > 0 and event["stage"] in STAGES and isinstance(event["details"], dict))
            if events:
                require(event["timestamp"] >= events[-1]["timestamp"], "Backup journal time moved backwards.")
            validate_step(events[-1]["stage"] if events else None, event)
            if events and events[-1]["stage"] == "failed" and event["stage"] == "resume-intent":
                require(len(events) >= 2 and events[-2]["stage"] in {"paused", "verified", "frozen-data", "capture-intent"},
                        "A failed unresolved operation cannot be automatically retried.")
            if events and events[-1]["stage"] == "failed" and event["stage"] == "preserved-frozen":
                require(len(events) >= 2 and events[-2]["stage"] in {"verified", "capture-intent"})
            previous = sha256(raw).hexdigest()
            events.append(event)
        return events

    def append(self, stage, details, timestamp):
        require(stage in STAGES and isinstance(details, dict) and type(timestamp) is int and timestamp > 0)
        events = self.load()
        require(len(events) < 63)
        previous = sha256(canonical(events[-1])).hexdigest() if events else None
        event = {"version": 1, "session": self.session, "targetSha256": self.target_sha256,
                 "controlRevision": self.control_revision, "sequence": len(events) + 1,
                 "previousSha256": previous, "timestamp": timestamp, "stage": stage, "details": details}
        validate_step(events[-1]["stage"] if events else None, event)
        if events and events[-1]["stage"] == "failed" and stage == "resume-intent":
            require(len(events) >= 2 and events[-2]["stage"] in {"paused", "verified", "frozen-data", "capture-intent"},
                    "A failed unresolved operation cannot be automatically retried.")
        if events and events[-1]["stage"] == "failed" and stage == "preserved-frozen":
            require(len(events) >= 2 and events[-2]["stage"] in {"verified", "capture-intent"})
        body = canonical(event)
        self.store.put(self.prefix + str(len(events) + 1).zfill(4) + ".json", body)
        observed = self.load()
        require(len(observed) == len(events) + 1 and observed[-1] == event,
                "Backup journal append was not independently confirmed.")
        return event


def interruption(events):
    """Classify the last confirmed record without guessing an external result."""
    require(isinstance(events, list))
    if not events:
        return "missing"
    last = events[-1]["stage"]
    if last in {"resumed", "preserved-frozen"}:
        return "complete"
    if last in {"pause-intent", "freeze-intent", "capture-intent", "poll-intent", "resume-intent"}:
        return "reconciliation-required"
    if last == "failed":
        if len(events) > 1 and events[-2]["stage"].endswith("-intent"):
            return "reconciliation-required"
        return "failed-inspection-required"
    return "interrupted-inspection-required"


class Anchor:
    """A single conditional R2 pointer serializes all maintenance sessions."""

    def __init__(self, store, target_sha256, genesis_sha256):
        require(SHA.fullmatch(target_sha256 or "") is not None and SHA.fullmatch(genesis_sha256 or "") is not None,
                "The independently configured backup genesis pin is required.")
        self.store, self.target_sha256 = store, target_sha256
        self.genesis_sha256 = genesis_sha256
        self.key = "maintenance/production-control/registrations/daily-backup-anchor-" + target_sha256 + ".json"
        self.genesis_key = "maintenance/production-control/registrations/daily-backup-genesis-" + target_sha256 + ".json"

    def initial_material(self):
        initial = {"version": 1, "targetSha256": self.target_sha256, "generation": 1, "previousSha256": None,
                   "state": "idle", "session": "1-1", "day": "1970/01/01", "controlRevision": "0" * 40}
        initial_raw = canonical(initial)
        genesis = canonical({"version": 1, "targetSha256": self.target_sha256,
                             "initialAnchorSha256": sha256(initial_raw).hexdigest()})
        return initial_raw, genesis

    def initialize(self):
        """One-time explicit isolated setup; partial creation is not retried."""
        initial, genesis = self.initial_material()
        require(sha256(genesis).hexdigest() == self.genesis_sha256, "The independent genesis pin differs.")
        require(self.store.get(self.genesis_key, absent=True) is None
                and self.store.get_with_etag(self.key) == (None, None)
                and not self.store.list_backup_anchor_history(self.target_sha256)
                and not self.store.list_backup_journals(),
                "The backup anchor was initialized or partially initialized; inspect instead of retrying.")
        self.store.put(self.genesis_key, genesis)
        self.store.put(self.history_key(1, initial), initial)
        self.store.compare_and_put(self.key, None, None, initial)
        self.read()

    def plan_initialization_reconciliation(self):
        """Inspect an interrupted genesis initialization without changing it."""
        initial, expected_genesis = self.initial_material()
        genesis = self.store.get(self.genesis_key, absent=True)
        require(genesis == expected_genesis and sha256(genesis).hexdigest() == self.genesis_sha256,
                "A completed independently pinned genesis record is required.")
        history = self.store.list_backup_anchor_history(self.target_sha256)
        expected_key = self.history_key(1, initial)
        require(history in ([], [expected_key]) and not self.store.list_backup_journals(),
                "Unexpected backup history or journals prevent genesis reconciliation.")
        if history:
            require(self.store.get(expected_key) == initial)
        pointer, etag = self.store.get_with_etag(self.key)
        require(pointer in (None, initial) and (pointer is None or history),
                "The initial pointer differs or its immutable history is absent.")
        return {"version": 1, "kind": "initialization", "targetSha256": self.target_sha256,
                "genesisSha256": self.genesis_sha256, "historyPresent": bool(history),
                "pointerPresent": pointer is not None}, initial, etag

    def reconcile_initialization(self, approved_plan_sha256):
        plan, initial, etag = self.plan_initialization_reconciliation()
        require(sha256(canonical(plan)).hexdigest() == approved_plan_sha256,
                "The exact independently reviewed initialization plan is required.")
        if not plan["historyPresent"]:
            self.store.put(self.history_key(1, initial), initial)
        if not plan["pointerPresent"]:
            self.store.compare_and_put(self.key, None, etag, initial)
        self.read()
        return plan

    def history_key(self, generation, body):
        return self.history_digest_key(generation, sha256(body).hexdigest())

    def history_digest_key(self, generation, digest):
        return ("maintenance/production-control/evidence/daily-backup-anchor/" + self.target_sha256 + "/"
                + str(generation).zfill(12) + "-" + digest + ".json")

    def read(self, *, allow_future=False):
        initial, expected_genesis = self.initial_material()
        genesis = self.store.get(self.genesis_key, absent=True)
        require(genesis == expected_genesis and sha256(genesis).hexdigest() == self.genesis_sha256,
                "The independently pinned backup genesis is missing or differs.")
        history = self.store.list_backup_anchor_history(self.target_sha256)
        self.last_history_count = len(history)
        raw, etag = self.store.get_with_etag(self.key)
        require(raw is not None, "The initialized backup anchor pointer is missing.")
        value = parsed(raw)
        require(canonical(value) == raw and set(value) == {"version", "targetSha256", "generation", "previousSha256",
                "state", "session", "day", "controlRevision"})
        require(value["version"] == 1 and value["targetSha256"] == self.target_sha256
                and type(value["generation"]) is int and 1 <= value["generation"] <= 999999999999
                and (value["previousSha256"] is None if value["generation"] == 1 else SHA.fullmatch(value["previousSha256"] or "") is not None)
                and value["state"] in {"active", "idle"} and SESSION.fullmatch(value["session"] or "") is not None
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", value["day"] or "") is not None
                and REVISION.fullmatch(value["controlRevision"] or "") is not None)
        require(self.history_key(value["generation"], raw) in history
                and self.store.get(self.history_key(value["generation"], raw)) == raw,
                "The committed backup anchor history is missing or changed.")
        require(all(re.fullmatch(re.escape("maintenance/production-control/evidence/daily-backup-anchor/" + self.target_sha256 + "/")
                                + r"[0-9]{12}-[a-f0-9]{64}\.json", key)
                    and (allow_future or int(key.rsplit("/", 1)[1][:12]) <= value["generation"]) for key in history),
                "An unconfirmed future anchor generation requires reconciliation.")
        current = value
        while current["generation"] > 1:
            previous_sha = current["previousSha256"]
            key = self.history_digest_key(current["generation"] - 1, previous_sha)
            require(key in history, "The backup anchor history chain has a missing generation.")
            previous_raw = self.store.get(key)
            require(sha256(previous_raw).hexdigest() == previous_sha)
            previous = parsed(previous_raw)
            require(canonical(previous) == previous_raw and previous.get("version") == 1
                    and previous.get("targetSha256") == self.target_sha256
                    and type(previous.get("generation")) is int and previous["generation"] == current["generation"] - 1
                    and ((current["state"] == "idle" and previous.get("state") == "active"
                          and all(current[key] == previous.get(key) for key in ("session", "day", "controlRevision")))
                         or (current["state"] == "active" and previous.get("state") == "idle"
                             and current["session"] != previous.get("session"))))
            current = previous
        require(canonical(current) == initial and current.get("state") == "idle" and current.get("previousSha256") is None,
                "The backup anchor genesis is invalid.")
        return value, raw, etag

    def plan_reconciliation(self, candidate_sha256):
        """Read an exact future candidate without changing the pointer."""
        require(SHA.fullmatch(candidate_sha256 or "") is not None)
        prior, raw, etag = self.read(allow_future=True)
        generation = prior["generation"] + 1
        history = self.store.list_backup_anchor_history(self.target_sha256)
        key = self.history_digest_key(generation, candidate_sha256)
        candidates = [item for item in history if int(item.rsplit("/", 1)[1][:12]) == generation]
        require(candidates == [key] and all(int(item.rsplit("/", 1)[1][:12]) <= generation for item in history),
                "The exact candidate is missing, ambiguous, or followed by unknown generations.")
        candidate_raw = self.store.get(key)
        candidate = parsed(candidate_raw)
        require(sha256(candidate_raw).hexdigest() == candidate_sha256 and canonical(candidate) == candidate_raw
                and set(candidate) == set(prior) and candidate.get("version") == 1
                and candidate.get("targetSha256") == self.target_sha256 and candidate.get("generation") == generation
                and candidate.get("previousSha256") == sha256(raw).hexdigest()
                and SESSION.fullmatch(candidate.get("session", "")) is not None
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", candidate.get("day", "")) is not None
                and REVISION.fullmatch(candidate.get("controlRevision", "")) is not None
                and ((prior["state"] == "idle" and candidate.get("state") == "active" and candidate["session"] != prior["session"])
                     or (prior["state"] == "active" and candidate.get("state") == "idle"
                         and all(candidate[key] == prior[key] for key in ("session", "day", "controlRevision")))))
        if candidate["state"] == "idle":
            events = Transaction(self.store, prior["session"], prior["day"], self.target_sha256,
                                 prior["controlRevision"]).load()
            require(events and (events[-1]["stage"] in {"resumed", "preserved-frozen"}
                    or (len(events) >= 2 and events[-1]["stage"] == "failed"
                        and events[-2]["stage"] in {"started", "preflight"})),
                    "The candidate release lacks a confirmed non-mutating or completed transaction.")
        plan = {"version": 1, "targetSha256": self.target_sha256, "predecessorSha256": sha256(raw).hexdigest(),
                "candidateSha256": candidate_sha256, "candidate": candidate}
        return plan, raw, etag, candidate_raw

    def reconcile(self, candidate_sha256, approved_plan_sha256):
        plan, prior_raw, prior_etag, candidate_raw = self.plan_reconciliation(candidate_sha256)
        require(sha256(canonical(plan)).hexdigest() == approved_plan_sha256,
                "The exact independent reconciliation plan approval is required.")
        self.store.compare_and_put(self.key, prior_raw, prior_etag, candidate_raw)
        self.read()
        return plan

    def _advance(self, prior, prior_raw, prior_etag, *, state, session, day, revision):
        generation = 1 if prior is None else prior["generation"] + 1
        require(generation <= 999999999999)
        value = {"version": 1, "targetSha256": self.target_sha256, "generation": generation,
                 "previousSha256": None if prior_raw is None else sha256(prior_raw).hexdigest(),
                 "state": state, "session": session, "day": day, "controlRevision": revision}
        body = canonical(value)
        self.store.put(self.history_key(generation, body), body)
        self.store.compare_and_put(self.key, prior_raw, prior_etag, body)
        observed, observed_raw, _ = self.read()
        require(observed == value and observed_raw == body, "The backup anchor write is not confirmed.")
        return value

    def acquire(self, session, day, revision):
        require(SESSION.fullmatch(session or "") is not None and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", day or "")
                and REVISION.fullmatch(revision or "") is not None)
        previous, raw, etag = self.read()
        require(previous["state"] == "idle", "An earlier backup transaction remains unresolved.")
        require(previous["session"] != session, "A maintenance session cannot be replayed.")
        return self._advance(previous, raw, etag, state="active", session=session, day=day, revision=revision)

    def release(self, session):
        previous, raw, etag = self.read()
        require(previous is not None and previous["state"] == "active" and previous["session"] == session,
                "The exact active backup anchor is required.")
        return self._advance(previous, raw, etag, state="idle", session=session, day=previous["day"],
                             revision=previous["controlRevision"])

"""Target-scoped immutable/CAS anchor for the isolated test webhook window.

This deliberately implements only the test Bot lock, independently of the
candidate's application backup transaction module.
"""
from hashlib import sha256
import re

from production_target import canonical, parsed, require

SHA = re.compile(r"[a-f0-9]{64}")
SESSION = re.compile(r"[1-9][0-9]{0,19}-[1-9][0-9]{0,9}")
REVISION = re.compile(r"[a-f0-9]{40}")


class WebhookStore:
    def __init__(self, store, target_sha):
        require(store.objects is not None and re.fullmatch(r"[a-f0-9]{64}", target_sha or ""))
        self.objects = store.objects
        self.prefix = "maintenance/production-control/evidence/phase-webhook-anchor/" + target_sha + "/"

    def _key(self, key):
        require(isinstance(key, str) and key.startswith("maintenance/production-control/")
                and not any(part in {".", ".."} for part in key.split("/")))
        return self.prefix + key

    def get(self, key, *, absent=False):
        return self.objects.get(self._key(key), absent=absent)[0]

    def get_with_etag(self, key):
        return self.objects.get(self._key(key), absent=True)

    def put(self, key, body):
        self.objects.put_once(self._key(key), body)
        return sha256(body).hexdigest()

    def compare_and_put(self, key, expected_body, expected_etag, body):
        return self.objects.compare_and_put(self._key(key), expected_body, expected_etag, body)

    def _list(self, prefix):
        mapped = self._key(prefix)
        keys = self.objects.list(mapped, maximum=10000)
        require(all(key.startswith(mapped) for key in keys))
        return [key[len(self.prefix):] for key in keys]

    def list_backup_anchor_history(self, target_sha):
        require(re.fullmatch(r"[a-f0-9]{64}", target_sha or ""))
        return self._list("maintenance/production-control/evidence/daily-backup-anchor/" + target_sha + "/")

    def list_backup_journals(self):
        return self._list("maintenance/production-control/evidence/daily-backup/")

    def list_backup_session(self, prefix):
        return self._list(prefix)


class WebhookAnchor:
    """The shared anchor wire format, restricted to the test webhook namespace."""
    def __init__(self, store, target_sha, expected_genesis):
        require(SHA.fullmatch(target_sha or "") and SHA.fullmatch(expected_genesis or ""))
        self.store, self.target_sha256, self.genesis_sha256 = store, target_sha, expected_genesis
        self.key = "maintenance/production-control/registrations/daily-backup-anchor-" + target_sha + ".json"
        self.genesis_key = "maintenance/production-control/registrations/daily-backup-genesis-" + target_sha + ".json"

    def initial_material(self):
        value = {"version": 1, "targetSha256": self.target_sha256, "generation": 1, "previousSha256": None,
                 "state": "idle", "session": "1-1", "day": "1970/01/01", "controlRevision": "0" * 40}
        raw = canonical(value)
        return raw, canonical({"version": 1, "targetSha256": self.target_sha256,
                               "initialAnchorSha256": sha256(raw).hexdigest()})

    def history_digest_key(self, generation, digest):
        return ("maintenance/production-control/evidence/daily-backup-anchor/" + self.target_sha256 + "/"
                + str(generation).zfill(12) + "-" + digest + ".json")

    def history_key(self, generation, body):
        return self.history_digest_key(generation, sha256(body).hexdigest())

    def read(self):
        initial, genesis = self.initial_material()
        require(self.store.get(self.genesis_key, absent=True) == genesis
                and sha256(genesis).hexdigest() == self.genesis_sha256)
        keys = self.store.list_backup_anchor_history(self.target_sha256)
        raw, etag = self.store.get_with_etag(self.key)
        require(raw is not None and re.fullmatch(r'"[a-f0-9]{32}"', etag or ""))
        value = parsed(raw)
        require(canonical(value) == raw and set(value) == {"version", "targetSha256", "generation", "previousSha256",
                "state", "session", "day", "controlRevision"} and type(value["version"]) is int and value["version"] == 1
                and value["targetSha256"] == self.target_sha256 and type(value["generation"]) is int
                and 1 <= value["generation"] <= 999999999999 and value["state"] in {"active", "idle"}
                and SESSION.fullmatch(value["session"] or "") and REVISION.fullmatch(value["controlRevision"] or "")
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", value["day"] or ""))
        prefix = "maintenance/production-control/evidence/daily-backup-anchor/" + self.target_sha256 + "/"
        require(all(re.fullmatch(re.escape(prefix) + r"[0-9]{12}-[a-f0-9]{64}\.json", key)
                    and int(key.rsplit("/", 1)[1][:12]) <= value["generation"] for key in keys)
                and len(keys) == value["generation"] and len(set(keys)) == len(keys)
                and self.history_key(value["generation"], raw) in keys
                and self.store.get(self.history_key(value["generation"], raw)) == raw,
                "The webhook anchor history is incomplete, forked or has an unresolved future generation.")
        current = value
        used_sessions = {value["session"]}
        active_sessions = {value["session"]} if value["state"] == "active" else set()
        while current["generation"] > 1:
            prior_sha = current.get("previousSha256")
            require(SHA.fullmatch(prior_sha or ""))
            key = self.history_digest_key(current["generation"] - 1, prior_sha)
            require(key in keys)
            old_raw = self.store.get(key)
            require(sha256(old_raw).hexdigest() == prior_sha)
            old = parsed(old_raw)
            require(canonical(old) == old_raw and set(old) == set(value)
                    and type(old.get("version")) is int and old["version"] == 1
                    and old.get("targetSha256") == self.target_sha256 and type(old.get("generation")) is int
                    and old["generation"] == current["generation"] - 1
                    and SESSION.fullmatch(old.get("session", "")) and REVISION.fullmatch(old.get("controlRevision", ""))
                    and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", old.get("day", ""))
                    and ((current["state"] == "idle" and old.get("state") == "active"
                          and all(current[k] == old.get(k) for k in ("session", "day", "controlRevision")))
                         or (current["state"] == "active" and old.get("state") == "idle"
                             and current["session"] != old.get("session"))))
            if old["state"] == "active":
                require(old["session"] not in active_sessions, "A webhook lock session was reused in its history.")
                active_sessions.add(old["session"])
            used_sessions.add(old["session"])
            current = old
        require(canonical(current) == initial)
        self.used_sessions = used_sessions
        return value, raw, etag

    def initialize(self):
        initial, genesis = self.initial_material()
        require(sha256(genesis).hexdigest() == self.genesis_sha256
                and self.store.get(self.genesis_key, absent=True) is None
                and self.store.get_with_etag(self.key) == (None, None)
                and not self.store.list_backup_anchor_history(self.target_sha256)
                and not self.store.list_backup_journals())
        self.store.put(self.genesis_key, genesis)
        self.store.put(self.history_key(1, initial), initial)
        self.store.compare_and_put(self.key, None, None, initial)
        self.read()

    def _advance(self, previous, raw, etag, *, state, session, day, revision):
        generation = previous["generation"] + 1
        require(generation <= 999999999999)
        value = {"version": 1, "targetSha256": self.target_sha256, "generation": generation,
                 "previousSha256": sha256(raw).hexdigest(), "state": state, "session": session,
                 "day": day, "controlRevision": revision}
        body = canonical(value)
        self.store.put(self.history_key(generation, body), body)
        self.store.compare_and_put(self.key, raw, etag, body)
        observed, observed_raw, _ = self.read()
        require(observed == value and observed_raw == body)
        return value

    def acquire(self, session, day, revision):
        require(SESSION.fullmatch(session or "") and REVISION.fullmatch(revision or "")
                and re.fullmatch(r"[0-9]{4}/[0-9]{2}/[0-9]{2}", day or ""))
        previous, raw, etag = self.read()
        require(previous["state"] == "idle" and session not in self.used_sessions,
                "A prior webhook lock session cannot be replayed.")
        return self._advance(previous, raw, etag, state="active", session=session, day=day, revision=revision)

    def release(self, session):
        previous, raw, etag = self.read()
        require(previous["state"] == "active" and previous["session"] == session)
        return self._advance(previous, raw, etag, state="idle", session=session,
                             day=previous["day"], revision=previous["controlRevision"])


def anchor(store, target_sha, expected_genesis):
    return WebhookAnchor(WebhookStore(store, target_sha), target_sha, expected_genesis)


def genesis_sha(store, target_sha):
    value = anchor(store, target_sha, "0" * 64)
    return sha256(value.initial_material()[1]).hexdigest()


def release_after_verified_restore(env):
    """Release only after the exact frozen target and restored webhook are re-read."""
    from production_backup_webhook_recovery import (context, source_run, open_store, require_exact_freeze,
        probe_original_webhook, webhook_settings, Telegram, SHA, ORIGINAL_ORIGIN)
    from production_target import TEST_BOT_ID, canonical, parsed, validate_target
    automatic = context(env)
    require(automatic and env.get("WEBHOOK_SOURCE_KIND") == "phase-coordinator")
    run_id, attempt, candidate = source_run(env, automatic)
    draft, secrets, previous, store, prefix = open_store(env)
    registration_raw = store.get(prefix + "registration.json")
    require(sha256(registration_raw).hexdigest() == env.get("WEBHOOK_REGISTRATION_SHA256"))
    registration = parsed(registration_raw)
    target = validate_target(registration.get("target"))
    desired = dict(draft.data)
    for key in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt"):
        desired[key] = target.data[key]
    require(target.environment == "rehearsal" and target.data["workerName"] == draft.data["workerName"]
            and target.data["botId"] == previous["botId"] == TEST_BOT_ID and target.data["botUsername"] == "test_cfsubs_bot"
            and validate_target(desired).configuration_digest == target.configuration_digest
            and registration.get("draftSha256") == draft.digest and registration.get("targetSha256") == target.digest
            and registration.get("configurationSha256") == target.configuration_digest)
    suffix = run_id + "-" + attempt
    snapshot_raw = store.get(prefix + "webhook-" + suffix + ".json")
    snapshot = parsed(snapshot_raw)
    require(canonical(snapshot) == snapshot_raw and sha256(snapshot_raw).hexdigest() == env.get("WEBHOOK_SNAPSHOT_SHA256")
            and snapshot.get("runId") == run_id and snapshot.get("runAttempt") == attempt
            and snapshot.get("revision") == candidate and snapshot.get("draftSha256") == draft.digest
            and snapshot.get("botId") == previous["botId"] and snapshot.get("oldWebhookSecret") == previous["webhookSecret"])
    prior = webhook_settings(snapshot["webhookInfo"])
    require(prior["url"] == ORIGINAL_ORIGIN + "/telegram/webhook")
    intent_raw = store.get(prefix + "webhook-recovery-" + suffix + "-intent.json")
    completion_raw = store.get(prefix + "webhook-recovery-" + suffix + "-complete.json")
    intent, completion = parsed(intent_raw), parsed(completion_raw)
    require(canonical(intent) == intent_raw and canonical(completion) == completion_raw
            and intent.get("sourceRunId") == run_id and intent.get("sourceAttempt") == attempt
            and intent.get("candidateRevision") == candidate and intent.get("snapshotSha256") == sha256(snapshot_raw).hexdigest()
            and intent.get("beforeSha256") == sha256(canonical(prior)).hexdigest()
            and completion == {"version": 1, "intentSha256": sha256(intent_raw).hexdigest(),
                "snapshotSha256": sha256(snapshot_raw).hexdigest(), "settingsSha256": sha256(canonical(prior)).hexdigest(),
                "dropPendingUpdates": False, "telegramSecretReadback": "not-available"})
    freeze_raw = store.get(prefix + "backup-admission-" + suffix + "-freeze-confirmed.json")
    require(SHA.fullmatch(env.get("WEBHOOK_FREEZE_CONFIRMATION_SHA256", ""))
            and sha256(freeze_raw).hexdigest() == env["WEBHOOK_FREEZE_CONFIRMATION_SHA256"])
    freeze = parsed(freeze_raw)
    require(canonical(freeze) == freeze_raw and freeze.get("targetSha256") == target.digest
            and freeze.get("candidateRevision") == candidate and freeze.get("dispatcherRevision") == env.get("WEBHOOK_SOURCE_MAIN_SHA"))
    frozen = require_exact_freeze(target, secrets, env, freeze)
    telegram = Telegram(draft, {**secrets, "webhookSecret": previous["webhookSecret"]})
    telegram.identity()
    require(webhook_settings(telegram.call("getWebhookInfo")) == prior and probe_original_webhook(previous["webhookSecret"]) == 400)
    expected_genesis = env.get("SUBS_BOT_PHASE_WEBHOOK_ANCHOR_GENESIS_SHA256", "")
    lock = anchor(store, target.digest, expected_genesis)
    current, _, _ = lock.read()
    require(current["state"] == "active" and current["session"] == suffix and current["controlRevision"] == candidate)
    require(require_exact_freeze(target, secrets, env, freeze) == frozen
            and webhook_settings(telegram.call("getWebhookInfo")) == prior
            and probe_original_webhook(previous["webhookSecret"]) == 400)
    lock.release(suffix)
    final, _, _ = lock.read()
    require(final["state"] == "idle" and final["session"] == suffix and final["controlRevision"] == candidate)
    return {"status": "restored-and-lock-released", "targetSha256": target.digest}


if __name__ == "__main__":
    import json
    import os
    try:
        print(json.dumps(release_after_verified_restore(os.environ), sort_keys=True))
    except Exception:
        print("::error::The test webhook lock remains active or its release is unknown; inspect its private evidence.")
        raise SystemExit(1) from None

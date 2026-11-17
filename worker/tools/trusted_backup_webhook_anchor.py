"""Target-scoped immutable/CAS anchor for the isolated test webhook window.

The production backup Anchor supplies the history chain and uncertain-write
semantics; this adapter only maps it to the test Bot's private namespace.
"""
from hashlib import sha256
import re

from production_target import require


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


def anchor(store, target_sha, expected_genesis):
    from production_backup_transaction import Anchor
    return Anchor(WebhookStore(store, target_sha), target_sha, expected_genesis)


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

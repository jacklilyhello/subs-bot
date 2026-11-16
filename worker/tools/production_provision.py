"""Create only new, explicitly approved project resources; never adopt names.

Partial creation returns pins in a mode-0600 private report. Re-running creation
against an occupied name stops. Recovery requires an independently approved pin;
there is no delete/recreate or automatic name-based adoption path.
"""
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time
from urllib.parse import urlencode

import prepare_isolation_artifact as artifact
from bootstrap_provider_worker import OBSERVABILITY_OFF
from production_control import API, hosted_environment, privacy, OperationError
from production_target import ContractError, approve, canonical, digest, matches, parsed, require, validate_target, HEX, UUID, STAMP
from production_storage import PrivateStore


class ProvisionJournal:
    """An existing explicitly pinned private anchor survives partial creation."""
    def __init__(self, store, draft, guard=lambda: None):
        self.store, self.draft, self.guard = store, draft, guard
        self.prefix = "maintenance/production-control/registrations/provision-" + draft.digest + "/"
        self.value, self.generation, self.previous = None, 0, None
        for key in store.list(self.prefix):
            self.generation += 1
            require(key == self.prefix + f"{self.generation:06d}.json")
            envelope = json.loads(store.get(key))
            require(envelope.get("generation") == self.generation and envelope.get("previousSha256") == self.previous
                    and envelope.get("draftSha256") == draft.digest and isinstance(envelope.get("value"), dict),
                    "Provisioning journal history is inconsistent.")
            self.previous = digest(envelope)
            self.value = envelope["value"]

    def save(self, value):
        self.guard()
        self.generation += 1
        envelope = {"generation": self.generation, "previousSha256": self.previous,
            "draftSha256": self.draft.digest, "value": value}
        self.store.put(self.prefix + f"{self.generation:06d}.json", canonical(envelope))
        self.previous, self.value = digest(envelope), deepcopy(value)


class Provisioner:
    def __init__(self, draft, data_api, worker_api, guard=lambda: None, journal=None):
        self.draft, self.data, self.worker, self.guard = draft, data_api, worker_api, guard
        self.root = "/accounts/" + draft.data["accountId"]
        self.journal = journal

    def available(self):
        t = self.draft.data
        require(all(t[k] is None for k in ("workerId", "workerCreatedOn", "d1Id", "d1CreatedAt", "bucketCreatedAt", "backupBucketCreatedAt")),
                "Creation requires an unregistered draft; existing resources need explicit registration verification.")
        if self.draft.environment == "production":
            account = self.data("GET", self.root)
            zone = self.worker("GET", "/zones/" + t["zoneId"])
            require(account.get("id") == t["accountId"] and zone.get("account", {}).get("id") == t["accountId"])
        worker = self.worker("GET", self.root + "/workers/workers/" + t["workerName"], absent=True)
        require(worker is None, "The Worker name is occupied; unknown same-name resources cannot be adopted.")
        databases = self.data("GET", self.root + "/d1/database?" + urlencode({"name": t["d1Name"], "per_page": 100}), envelope=True)
        require(isinstance(databases.get("result"), list) and len(databases["result"]) < 100
                and databases.get("result_info", {}).get("total_pages", 1) in (0, 1)
                and not any(row.get("name") == t["d1Name"] for row in databases["result"]), "The D1 name is occupied or its inventory is incomplete.")
        for key in ("bucketName", "backupBucketName"):
            listing = self.data("GET", self.root + "/r2/buckets?" + urlencode({"name_contains": t[key], "per_page": 100}), envelope=True)
            result, info = listing.get("result"), listing.get("result_info", {})
            buckets = result.get("buckets") if isinstance(result, dict) else None
            require(isinstance(buckets, list) and len(buckets) < 100 and not info.get("cursor")
                    and not info.get("next_page_token") and info.get("is_truncated") is not True
                    and not any(row.get("name") == t[key] for row in buckets), "The R2 name is occupied or its inventory is incomplete.")
        return {"draftSha256": self.draft.digest, "allNamesAvailable": True}

    def observe_candidate(self, kind):
        t = self.draft.data
        if kind == "worker":
            row = self.worker("GET", self.root + "/workers/workers/" + t["workerName"])
            require(row.get("name") == t["workerName"] and matches(HEX, row.get("id")) and matches(STAMP, row.get("created_on"))
                    and set(row.get("tags", [])) == {"subs-bot", "lifecycle-" + t["environment"]})
            return {"id": row["id"], "name": row["name"], "createdOn": row["created_on"]}
        if kind == "database":
            value = self.data("GET", self.root + "/d1/database?" + urlencode({"name": t["d1Name"], "per_page": 100}), envelope=True)
            listing = value.get("result")
            require(isinstance(listing, list) and len(listing) < 100 and value.get("result_info", {}).get("total_pages", 1) in (0, 1))
            exact = [r for r in listing if r.get("name") == t["d1Name"]]
            require(len(exact) == 1 and matches(UUID, exact[0].get("uuid")))
            row = self.data("GET", self.root + "/d1/database/" + exact[0]["uuid"])
            require(row.get("name") == t["d1Name"] and matches(STAMP, row.get("created_at")))
            return {"id": row["uuid"], "name": row["name"], "createdAt": row["created_at"]}
        require(kind in ("bucketName", "backupBucketName"))
        row = self.data("GET", self.root + "/r2/buckets/" + t[kind])
        require(row.get("name") == t[kind] and matches(STAMP, row.get("creation_date")))
        privacy(self.data, self.root, t[kind], row["creation_date"])
        return {"name": t[kind], "createdAt": row["creation_date"]}

    def reconcile(self, kind, identity_sha, approval, revision, predecessor):
        require(self.journal is not None and self.journal.value is not None)
        value = deepcopy(self.journal.value)
        require(digest(value) == predecessor and kind in value["intents"] and kind not in value["resources"])
        approve(self.draft, approval, "provision-reconcile:" + kind + ":" + identity_sha, revision, predecessor)
        candidate = self.observe_candidate(kind)
        require(digest(candidate) == identity_sha, "Explicit candidate identity differs; no registration changed.")
        created = datetime.fromisoformat(candidate.get("createdAt", candidate.get("createdOn"))).timestamp()
        require(value["intents"][kind]["at"] - 5 <= created <= value["intents"][kind]["at"] + 300,
                "Candidate was not created within the recorded project intent window.")
        value["resources"][kind] = candidate
        value["intents"][kind]["state"] = "independently-confirmed"
        self.journal.save(value)
        return {"reconciled": True, "identitySha256": identity_sha, "stateSha256": digest(value)}

    def create(self, approval, revision, predecessor, save=None):
        require(self.journal is not None, "A verified existing private provisioning anchor is required.")
        prior = self.journal.value
        require(digest(prior if prior is not None else self.available()) == predecessor)
        approve(self.draft, approval, "provision", revision, predecessor)
        t = deepcopy(self.draft.data)
        receipt = deepcopy(prior) if prior else {"schemaVersion": 1, "draftSha256": self.draft.digest, "revision": revision,
            "runId": os.environ.get("GITHUB_RUN_ID"), "runAttempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "startedAt": datetime.now(timezone.utc).isoformat(), "resources": {}, "intents": {}, "state": "intent"}
        save_private = save
        def save(value):
            self.journal.save(value)
            if save_private is not None:
                save_private(value)
        def begin(kind):
            if kind in receipt["resources"]:
                return False
            require(kind not in receipt["intents"], "An unconfirmed provisioning intent must be reconciled explicitly before any retry.")
            receipt["intents"][kind] = {"state": "started", "at": int(time.time())}
            save(receipt)
            return True
        save(receipt)
        self.guard()
        if begin("database"):
            db = self.data("POST", self.root + "/d1/database", {"name": t["d1Name"], "read_replication": {"mode": "disabled"}})
            require(db.get("name") == t["d1Name"] and matches(UUID, db.get("uuid")) and matches(STAMP, db.get("created_at")))
            receipt["resources"]["database"] = {"id": db["uuid"], "name": db["name"], "createdAt": db["created_at"]}
            receipt["intents"]["database"]["state"] = "confirmed"
            save(receipt)
        dbpin = receipt["resources"]["database"]
        readback = self.data("GET", self.root + "/d1/database/" + dbpin["id"])
        require((readback.get("uuid"), readback.get("name"), readback.get("created_at")) == (dbpin["id"], dbpin["name"], dbpin["createdAt"]))
        t.update(d1Id=dbpin["id"], d1CreatedAt=dbpin["createdAt"])
        for key, stamp in (("bucketName", "bucketCreatedAt"), ("backupBucketName", "backupBucketCreatedAt")):
            self.guard()
            if begin(key):
                bucket = self.data("POST", self.root + "/r2/buckets", {"name": t[key], "storageClass": "Standard"})
                require(bucket.get("name") == t[key] and matches(STAMP, bucket.get("creation_date")))
                receipt["resources"][key] = {"name": t[key], "createdAt": bucket["creation_date"]}
                receipt["intents"][key]["state"] = "confirmed"
                save(receipt)
            t[stamp] = receipt["resources"][key]["createdAt"]
            receipt["resources"][key] = privacy(self.data, self.root, t[key], t[stamp])
            save(receipt)
        self.guard()
        if begin("worker"):
            live = self.worker("POST", self.root + "/workers/workers", {
            "name": t["workerName"], "subdomain": {"enabled": True, "previews_enabled": False},
            "logpush": False, "observability": OBSERVABILITY_OFF, "tail_consumers": [],
            "tags": ["subs-bot", "lifecycle-" + t["environment"]],
                "previews_base_config": {"logpush": False, "observability": OBSERVABILITY_OFF, "tail_consumers": []}})
            require(live.get("name") == t["workerName"] and matches(HEX, live.get("id")) and matches(STAMP, live.get("created_on")))
            receipt["resources"]["worker"] = {"id": live["id"], "name": live["name"], "createdOn": live["created_on"]}
            receipt["intents"]["worker"]["state"] = "confirmed"
            save(receipt)
        workerpin = receipt["resources"]["worker"]
        checked = self.worker("GET", self.root + "/workers/workers/" + workerpin["id"])
        require((checked.get("id"), checked.get("name"), checked.get("created_on")) == (workerpin["id"], workerpin["name"], workerpin["createdOn"]))
        t.update(workerId=workerpin["id"], workerCreatedOn=workerpin["createdOn"])
        final = validate_target(t)
        receipt.update(state="created-no-module-no-consumer", targetSha256=final.digest, target=t)
        save(receipt)
        return final, receipt


def main():
    draft = validate_target(os.environ.get("SUBS_BOT_TARGET_JSON", ""), draft=True)
    hosted_environment(draft.environment)
    revision = os.environ.get("GITHUB_SHA", "")
    artifact.require_current_main(revision)
    data = API(draft, os.environ.get("SUBS_BOT_CF_DATA_TOKEN", ""), create=True)
    worker = API(draft, os.environ.get("SUBS_BOT_CF_WORKER_TOKEN", ""), create=True)
    anchor = parsed(os.environ.get("SUBS_BOT_PROVISION_ANCHOR_JSON", ""))
    require(set(anchor) == {"accountId", "bucketName", "bucketCreatedAt"} and anchor["accountId"] == draft.account_id)
    anchor_target = {**draft.data, "backupBucketName": anchor["bucketName"], "backupBucketCreatedAt": anchor["bucketCreatedAt"]}
    anchor_api = API(anchor_target, os.environ.get("SUBS_BOT_CF_DATA_TOKEN", ""))
    journal = ProvisionJournal(PrivateStore(anchor_api, anchor["bucketName"]), draft, lambda: artifact.require_current_main(revision))
    tool = Provisioner(draft, data, worker, lambda: artifact.require_current_main(revision), journal=journal)
    action = os.environ.get("CONTROL_ACTION", "availability")
    if action == "provision-inspect":
        result = {"draftSha256": draft.digest, "stateSha256": digest(journal.value if journal.value is not None else tool.available()),
                  "journalGeneration": journal.generation, "journalSha256": journal.previous}
        if journal.value is not None:
            result["candidates"] = {key: digest(tool.observe_candidate(key)) for key in journal.value["intents"] if key not in journal.value["resources"]}
    elif action == "provision-reconcile":
        result = tool.reconcile(os.environ.get("CONTROL_RESOURCE", ""), os.environ.get("CONTROL_IDENTITY_SHA256", ""),
                os.environ.get("SUBS_BOT_APPROVAL_JSON", ""), revision, os.environ.get("CONTROL_STATE_SHA256", ""))
    elif action == "availability":
        result = tool.available()
        result["stateSha256"] = digest(result)
    else:
        require(action == "provision")
        destination = Path(os.environ["RUNNER_TEMP"]) / "production-private-registration.json"
        def save(value):
            # Kept private. Workflow must persist this receipt to private R2 before
            # publishing only its safe summary. Never upload this raw file.
            destination.write_bytes(canonical(value))
            destination.chmod(0o600)
        final, receipt = tool.create(os.environ.get("SUBS_BOT_APPROVAL_JSON", ""), revision,
                                    os.environ.get("CONTROL_STATE_SHA256", ""), save)
        result = {"created": True, "targetSha256": final.digest, "registrationSha256": digest(receipt), "consumers": 0}
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (ContractError, OperationError, artifact.ArtifactError) as error:
        print(json.dumps({"status": "stopped", "reason": str(error), "uncertain": bool(getattr(error, "uncertain", False))}))
        raise SystemExit(1) from None

"""Read-only proof of the one independently resolved isolated backup incident.

This verifier authorizes no write and accepts no other capture-intent terminal.
It requires both original no-export jobs and fresh readbacks to have succeeded.
"""
from hashlib import sha256
import re

import prepare_isolation_artifact as github
import trusted_backup_no_export_gate as gate
from production_target import canonical, parsed, require

SHA = re.compile(r"[a-f0-9]{64}")
REV = re.compile(r"[a-f0-9]{40}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
OLD_SESSION = gate.OLD_RUN + "-1"
DAY = "2026/11/17"
FAILED_PLAN_LOG_SHA = "06b7dc59ad424d1862233aca9290914bb1c67863569f5ef6908b2f99b3068852"


def _legacy_plan_valid(plan):
    return (isinstance(plan.get("legacyArchives"), dict)
            and plan.get("legacyArchiveSha256") == sha256(canonical(plan["legacyArchives"])).hexdigest())


def _pinned(env, key, pattern):
    value = env.get(key, "")
    require(pattern.fullmatch(value or ""), "An independent no-export proof pin is missing.")
    return value


def _originals(store, prefix, manifest):
    """Read every bounded immutable evidence byte under its exact ordinal key."""
    records = manifest.get("originals")
    require(isinstance(records, list) and 1 <= len(records) <= 64)
    names = [record.get("name") if isinstance(record, dict) else None for record in records]
    require(all(isinstance(name, str) and name for name in names) and names == sorted(set(names)))
    output = {}
    for index, record in enumerate(records, 1):
        require(set(record) == {"name", "bytes", "sha256", "chunks"} and type(record["bytes"]) is int
                and 0 < record["bytes"] <= 4 * 1024 * 1024 and SHA.fullmatch(record["sha256"] or "")
                and isinstance(record["chunks"], list) and 1 <= len(record["chunks"]) <= 8)
        parts = []
        for sequence, part in enumerate(record["chunks"], 1):
            expected = "objects/" + str(index).zfill(3) + "/" + str(sequence).zfill(3)
            require(isinstance(part, dict) and set(part) == {"key", "bytes", "sha256"} and part["key"] == expected
                    and type(part["bytes"]) is int and 0 < part["bytes"] <= 512 * 1024
                    and SHA.fullmatch(part["sha256"] or ""))
            raw = store.get(prefix + expected)
            require(len(raw) == part["bytes"] and sha256(raw).hexdigest() == part["sha256"])
            parts.append(raw)
        body = b"".join(parts)
        require(len(body) == record["bytes"] and sha256(body).hexdigest() == record["sha256"])
        output[record["name"]] = body
    return output


def _original_anchor(store, target, review, genesis_sha):
    from production_backup_admission_recovery import idle_anchor
    anchor_sha = idle_anchor(store, target, OLD_SESSION, gate.OLD_CANDIDATE, genesis_sha, verify_session=False)
    anchor_raw = store.get("maintenance/production-control/registrations/daily-backup-anchor-" + target.digest + ".json")
    anchor = parsed(anchor_raw)
    require(canonical(anchor) == anchor_raw and sha256(anchor_raw).hexdigest() == anchor_sha
            and anchor.get("generation") == 7 and type(anchor.get("generation")) is int
            and anchor.get("previousSha256") == review.get("oldAnchorSha256")
            and anchor.get("state") == "idle" and anchor.get("session") == OLD_SESSION
            and anchor.get("day") == DAY and anchor.get("controlRevision") == gate.OLD_CANDIDATE,
            "The original active anchor was not released as the unique next generation.")
    return anchor_sha


def verify(store, target, genesis_sha, env):
    """Return only hashes after GH provenance, private originals and old chain verify."""
    require(target.environment == "rehearsal" and SHA.fullmatch(target.digest or ""))
    review_sha = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_REVIEW_SHA256", SHA)
    plan_sha = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_PLAN_SHA256", SHA)
    evidence_sha = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_EVIDENCE_SHA256", SHA)
    receipt_sha = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_SHA256", SHA)
    seal_run = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_SEAL_RUN_ID", DECIMAL)
    release_run = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_RELEASE_RUN_ID", DECIMAL)
    main = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_DISPATCHER_SHA", REV)
    candidate = _pinned(env, "SUBS_BOT_BACKUP_NO_EXPORT_CANDIDATE_SHA", REV)
    token = github._github_token()
    jobs = [("resolution", "Plan or apply the no-export resolution", True),
            ("readback", "Independently verify no-export evidence", True)]
    gate.reviewed_run(seal_run, "seal", main, candidate, token, successful=True, jobs_required=jobs)
    gate.reviewed_run(release_run, "release", main, candidate, token, successful=True, jobs_required=jobs)
    comparison = github.compare_commits_metadata(main, env.get("GITHUB_SHA", ""), token)
    require(comparison.get("status") in {"ahead", "identical"} and comparison.get("behind_by") == 0
            and comparison.get("base_commit", {}).get("sha") == main
            and comparison.get("merge_base_commit", {}).get("sha") == main)
    prefix = "maintenance/production-control/evidence/no-export-resolution/" + target.digest + "/" + OLD_SESSION + "/"
    manifest_raw = store.get(prefix + "evidence-manifest.json")
    manifest = parsed(manifest_raw)
    require(canonical(manifest) == manifest_raw and sha256(manifest_raw).hexdigest() == evidence_sha
            and set(manifest) == {"version", "kind", "planSha256", "originalRunId", "originalAttempt", "originalJobId",
                                  "threatModel", "seal", "originals"}
            and type(manifest["version"]) is int and manifest["version"] == 1
            and manifest["kind"] == "no-export-original-evidence" and manifest["planSha256"] == plan_sha
            and manifest["originalRunId"] == gate.OLD_RUN and manifest["originalAttempt"] == "1"
            and manifest["originalJobId"] == gate.OLD_JOB and manifest["threatModel"] == "reviewed-writers-no-unapproved-deletion"
            and manifest["seal"] == {"runId": seal_run, "runAttempt": "1", "dispatcherRevision": main, "controlRevision": candidate})
    evidence_intent = store.get(prefix + "evidence-intent.json")
    require(evidence_intent == canonical({"version": 1, "kind": "no-export-evidence-intent", "planSha256": plan_sha,
                                          "manifestSha256": evidence_sha}))
    originals = _originals(store, prefix, manifest)
    expected_names = ({"candidate/" + path for path in gate.CANDIDATE_PATHS}
                      | {"dispatcher/" + path for path in gate.DISPATCHER_PATHS}
                      | {"original-job-log", "known-preflight-failure-workflow.yml", "known-preflight-failure-gate.py",
                         "known-preflight-failure-job-log", "known-preflight-failure-evidence.json", "protected-custody.json",
                         "writer-inventory.json", "resolution-plan.json", "protected-review.json"})
    require(set(originals) == expected_names and sha256(originals["protected-review.json"]).hexdigest() == review_sha
            and sha256(originals["resolution-plan.json"]).hexdigest() == plan_sha
            and sha256(originals["original-job-log"]).hexdigest() == gate.OLD_LOG)
    review, plan = parsed(originals["protected-review.json"]), parsed(originals["resolution-plan.json"])
    require(canonical(review) == originals["protected-review.json"] and set(review) == gate.REVIEW_KEYS
            and canonical(plan) == originals["resolution-plan.json"]
            and review.get("targetSha256") == target.digest and review.get("oldRunId") == gate.OLD_RUN
            and review.get("oldCandidateSha") == gate.OLD_CANDIDATE and review.get("checkpointId") == gate.CHECKPOINT
            and plan.get("reviewSha256") == review_sha and plan.get("targetSha256") == target.digest
            and plan.get("oldTransactionSha256") == review.get("oldTransactionSha256")
            and plan.get("oldAnchorSha256") == review.get("oldAnchorSha256")
            and _legacy_plan_valid(plan)
            and plan.get("exportDispatchedUnderCustodyAssumption") is False
            and sha256(originals["writer-inventory.json"]).hexdigest() == review.get("writerInventorySha256")
            and sha256(originals["protected-custody.json"]).hexdigest() == review.get("custodySha256"))
    require(set(review["candidateCodeSha256"]) == gate.CANDIDATE_PATHS
            and set(review["dispatcherCodeSha256"]) == gate.DISPATCHER_PATHS
            and sha256(originals["known-preflight-failure-job-log"]).hexdigest() == FAILED_PLAN_LOG_SHA
            and sha256(originals["known-preflight-failure-workflow.yml"]).hexdigest() == gate.FAILED_PLAN_SOURCES[gate.WORKFLOW]
            and sha256(originals["known-preflight-failure-gate.py"]).hexdigest() ==
                gate.FAILED_PLAN_SOURCES["worker/tools/trusted_backup_no_export_gate.py"])
    for path, digest in review.get("candidateCodeSha256", {}).items():
        require(sha256(originals["candidate/" + path]).hexdigest() == digest)
    for path, digest in review.get("dispatcherCodeSha256", {}).items():
        require(sha256(originals["dispatcher/" + path]).hexdigest() == digest)
    release_raw = store.get(prefix + "release-intent.json")
    release = parsed(release_raw)
    require(canonical(release) == release_raw and release == {"version": 1, "kind": "no-export-release-intent",
        "planSha256": plan_sha, "evidenceSha256": evidence_sha, "sealRunId": seal_run, "releaseRunId": release_run,
        "releaseAttempt": "1", "dispatcherRevision": main, "controlRevision": candidate,
        "targetSha256": target.digest, "originalRunId": gate.OLD_RUN, "originalAttempt": "1"})
    receipt_raw = store.get(prefix + "release-complete.json")
    receipt = parsed(receipt_raw)
    require(canonical(receipt) == receipt_raw and sha256(receipt_raw).hexdigest() == receipt_sha)
    from production_backup_admission_recovery import list_history
    anchor_sha = _original_anchor(store, target, review, genesis_sha)
    journal_prefix = "maintenance/production-control/evidence/daily-backup/" + DAY + "/" + OLD_SESSION + "/"
    keys = list_history(store, target.digest, prefix=journal_prefix)
    require(keys == [journal_prefix + str(n).zfill(4) + ".json" for n in range(1, 7)])
    events, previous = [], None
    for number, key in enumerate(keys, 1):
        raw = store.get(key)
        item = parsed(raw)
        require(canonical(item) == raw and set(item) == {"version", "session", "targetSha256", "controlRevision",
                "sequence", "previousSha256", "timestamp", "stage", "details"}
                and type(item["version"]) is int and item["version"] == 1 and item["session"] == OLD_SESSION
                and item["targetSha256"] == target.digest and item["controlRevision"] == gate.OLD_CANDIDATE
                and type(item["sequence"]) is int and item["sequence"] == number and item["previousSha256"] == previous
                and type(item["timestamp"]) is int and item["timestamp"] > 0 and isinstance(item["details"], dict)
                and (not events or item["timestamp"] >= events[-1]["timestamp"]))
        events.append(item)
        previous = sha256(raw).hexdigest()
    require([item["stage"] for item in events] == ["started", "preflight", "frozen", "frozen-data", "capture-intent", "preserved-frozen"]
            and sha256(canonical(events[:5])).hexdigest() == review.get("oldTransactionSha256")
            and events[0]["details"].get("checkpointId") == events[4]["details"].get("checkpointId") == gate.CHECKPOINT
            and events[5]["details"] == {"control": events[0]["details"]["control"], "backupVerified": False,
                "noExportEvidenceSha256": evidence_sha, "releaseIntentSha256": sha256(release_raw).hexdigest(),
                "threatModel": "reviewed-writers-no-unapproved-deletion"})
    require(receipt == {"version": 1, "kind": "no-export-release-complete", "intentSha256": sha256(release_raw).hexdigest(),
        "planSha256": plan_sha, "evidenceSha256": evidence_sha, "originalRunId": gate.OLD_RUN, "releaseRunId": release_run,
        "terminalJournalSha256": sha256(canonical(events)).hexdigest(), "anchorSha256": anchor_sha, "backupVerified": False})
    return {"anchorSha256": anchor_sha, "journalSha256": sha256(canonical(events)).hexdigest(),
            "receiptSha256": receipt_sha, "backupVerified": False}

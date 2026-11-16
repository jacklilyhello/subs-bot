"""Exercise the real application deployment/binding/import/refresh/off controls.

The original registration, credentials and business data are retained. Only the
dedicated registered rehearsal identity is allowed. Provider APIs are GET only.
"""
import base64
import binascii
from copy import deepcopy
from hashlib import sha256
import json
from time import monotonic, sleep, time

from production_control import API, Controller, OperationError, Telegram, one, rows
from production_target import canonical, digest, matches, require, validate_target
from production_lifecycle_fixture import SMALL_TOKEN, seed_fixture
from production_application_provider_source import DependencyReadOnly, load_provider
import production_provider as provider

SERVICE = "subs-bot-cf-control-drill-01"
READY = "IAB ready for subs-bot-cf-control-drill-01 refresh"
UNKNOWN = ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates")


def closed(state):
    require(state["control"]["admission"] == "closed" and state["control"]["workers"] == "frozen"
            and not any(state["work"].values()), "The exact application must be drained and frozen before a configuration release.")


def desired_target(original, config):
    require(original.environment == "rehearsal" and original.data["workerName"] == SERVICE
            and original.data["provider"] is None)
    value = deepcopy(original.data)
    dependency = deepcopy(config)
    require(dependency["environment"] == "rehearsal" and dependency["service"] == "subs-bot-provider-fetch-control-drill-01"
            and dependency["caller"] is None)
    dependency["caller"] = {"id": value["workerId"], "name": value["workerName"]}
    value["provider"] = dependency
    value["features"].update(providerUrlImport=True, providerRefresh=True)
    target = validate_target(value)
    require(target.digest == original.digest and target.data["keyDigests"] == original.data["keyDigests"]
            and target.data["webhook"] == original.data["webhook"])
    return target


def accepted_import(controller, update_id, owner, source_sha):
    # Literal quoting is delegated to the production migration helper rather
    # than interpolating any user supplied text or source URL into SQL.
    from d1_migrations import _literal
    return rows(controller.data, controller.database, f"""SELECT job.job_id,job.subscription_id,job.expected_generation,
        job.state AS job_state,job.result_code,job.source_sha256,reply.outcome,outbox.state AS reply_state,
        outbox.attempts,subscriptions.generation,subscriptions.node_count,subscriptions.owner_id
      FROM telegram_inbox AS inbox JOIN telegram_provider_requests AS request USING(receipt_id)
      JOIN telegram_provider_jobs AS job USING(job_id) JOIN telegram_provider_replies AS reply USING(receipt_id)
      JOIN telegram_outbox AS outbox USING(receipt_id) JOIN subscriptions ON subscriptions.id=job.subscription_id
      WHERE inbox.bot_id={_literal(controller.target.data['botId'])} AND inbox.update_id={update_id}
        AND inbox.actor_id={_literal(owner)} AND request.kind='url-import' AND request.outcome='admitted'
        AND job.kind='url-import' AND job.source_sha256={_literal(source_sha)}""")


def successful(row, *, expected_generation):
    require(row["job_state"] == "done" and row["result_code"] == row["outcome"] == "saved"
            and row["reply_state"] == "sent" and 1 <= row["attempts"] <= 4
            and row["expected_generation"] == expected_generation and row["generation"] == expected_generation + 1
            and row["node_count"] == 3, "The actual Provider request did not save and confirm exactly three nodes.")


def positive_export(runner, controller, subscription_id, expected, wire):
    from d1_migrations import _literal
    record = rows(controller.data, controller.database,
        f"SELECT token FROM subscriptions WHERE id={subscription_id} AND owner_id={_literal(controller.target.data['admins'][0])}")
    require(len(record) == 1 and matches(r"[A-Za-z0-9_-]{1,128}", record[0]["token"]))
    status, body = wire["public_readback"](wire["public_request"](
        wire["origin"] + "/sub/" + record[0]["token"] + "/base64"), 64 * 1024)
    wire["expect_status"](status, 200, "provider-export")
    try:
        wanted, actual = base64.b64decode(expected, validate=True).splitlines(), base64.b64decode(body, validate=True).splitlines()
    except (ValueError, binascii.Error):
        require(False, "The actual imported export is not complete Base64 content.")
    require(len(actual) == 3 and actual == wanted, "The actual Provider export differs from the exact three-node source.")
    return {"bodySha256": sha256(body).hexdigest(), "bodyBytes": len(body), "nodeCount": 3}


def url_and_refresh(runner, controller, anchors, base, expected_body, wire):
    from d1_migrations import _literal
    owner = controller.target.data["admins"][0]
    # A unique harmless query preserves old fixture subscriptions on repeated
    # independently approved runs. The Worker export ignores this query.
    source_url = wire["origin"] + "/sub/" + SMALL_TOKEN + "/base64?provider_fixture=" + runner.run + "-" + runner.attempt
    source_sha = sha256(source_url.encode()).hexdigest()
    require(not rows(controller.data, controller.database,
        "SELECT id FROM subscriptions WHERE owner_id=" + _literal(owner) + " AND source_url=" + _literal(source_url)),
        "The identifiable source already exists; do not repeat an unknown import.")
    name = "Lifecycle Provider binding " + runner.run + "-" + runner.attempt
    date = one(controller.data, controller.database, "SELECT unixepoch() AS n")["n"]
    update = wire["update_payload"](base + 1, owner, anchors["admin"], name + " | " + source_url, date - 5)
    update["message"].pop("entities")
    wire["expect_status"](wire["post_update"](update, runner.secrets["webhookSecret"]), 200, "provider-import")
    runner.quiet(seconds=300)
    imported = accepted_import(controller, base + 1, owner, source_sha)
    require(len(imported) == 1 and imported[0]["owner_id"] == owner)
    successful(imported[0], expected_generation=0)
    identity, generation = imported[0]["subscription_id"], imported[0]["generation"]
    first = positive_export(runner, controller, identity, expected_body, wire)
    detail = wire["update_payload"](base + 2, owner, anchors["admin"], "/s " + name, date - 5)
    wire["expect_status"](wire["post_update"](detail, runner.secrets["webhookSecret"]), 200, "provider-detail")
    runner.quiet()
    window_start = one(controller.data, controller.database, "SELECT unixepoch() AS n")["n"]
    window = {"stage": "provider-refresh-window-open", "deadlineEpoch": int(time()) + runner.human_window,
        "targetSha256": controller.target.digest, "subscriptionId": identity, "expectedGeneration": generation + 1,
        "nodeCount": 3, "humanAcceptance": "requires-independent-IAB-correlation"}
    runner.save("provider-refresh-window-open", window)
    print(json.dumps(window, sort_keys=True), flush=True)
    deadline, refreshed = monotonic() + runner.human_window, []
    while monotonic() < deadline:
        refreshed = rows(controller.data, controller.database, f"""SELECT inbox.actor_id,job.job_id,job.subscription_id,
            job.expected_generation,job.state AS job_state,job.result_code,reply.outcome,outbox.state AS reply_state,
            outbox.attempts,subscriptions.generation,subscriptions.node_count
          FROM telegram_inbox AS inbox JOIN telegram_provider_requests AS request USING(receipt_id)
          JOIN telegram_provider_jobs AS job USING(job_id) JOIN telegram_provider_replies AS reply USING(receipt_id)
          JOIN telegram_outbox AS outbox USING(receipt_id) JOIN subscriptions ON subscriptions.id=job.subscription_id
          JOIN telegram_provider_refresh_tickets AS ticket ON ticket.used_by_receipt_id=inbox.receipt_id
          WHERE inbox.bot_id={_literal(controller.target.data['botId'])} AND inbox.actor_id={_literal(owner)}
            AND inbox.update_id<7000000000000000 AND inbox.message_date>={window_start - 60}
            AND request.kind='refresh' AND request.outcome='admitted' AND job.kind='refresh'
            AND job.subscription_id={identity} AND job.source_sha256={_literal(source_sha)}
            AND ticket.subscription_id={identity} AND ticket.generation={generation}
            AND ticket.source_sha256={_literal(source_sha)} LIMIT 2""")
        require(len(refreshed) <= 1, "More than one real refresh changed the identifiable fixture; preserve all evidence.")
        if refreshed and refreshed[0]["job_state"] == "done":
            require(refreshed[0]["result_code"] == refreshed[0]["outcome"] == "saved",
                    "The real refresh reached an explicit failed terminal result.")
            require(refreshed[0]["reply_state"] not in ("failed", "uncertain"),
                    "The real refresh reply did not reach a confirmed successful send.")
            if refreshed[0]["reply_state"] == "sent":
                successful(refreshed[0], expected_generation=generation)
                break
        sleep(2)
    require(refreshed and refreshed[0]["job_state"] == "done" and refreshed[0]["reply_state"] == "sent",
            "The authorized real refresh did not finish inside its explicit window.")
    runner.quiet()
    refreshed = rows(controller.data, controller.database, f"""SELECT job.expected_generation,job.state AS job_state,
        job.result_code,reply.outcome,outbox.state AS reply_state,outbox.attempts,subscriptions.generation,subscriptions.node_count
      FROM telegram_provider_jobs AS job JOIN telegram_provider_requests AS request USING(job_id)
      JOIN telegram_provider_replies AS reply USING(receipt_id) JOIN telegram_outbox AS outbox USING(receipt_id)
      JOIN subscriptions ON subscriptions.id=job.subscription_id WHERE job.job_id={refreshed[0]['job_id']}""")
    require(len(refreshed) == 1)
    successful(refreshed[0], expected_generation=generation)
    second = positive_export(runner, controller, identity, expected_body, wire)
    runner.report["applicationProviderCases"] = {"syntheticImportSaved": True, "realRefreshSaved": True,
        "humanAcceptance": "requires-independent-IAB-correlation", "subscriptionId": identity,
        "initialGeneration": generation, "refreshedGeneration": generation + 1, "nodeCount": 3,
        "sourceUrlSha256": source_sha, "importExport": first, "refreshExport": second}
    runner.save("provider-import-refresh-verified", runner.report["applicationProviderCases"])


def run(runner, wire):
    require(runner.env.get("DRILL_PROVIDER_READY_ACK") == READY and 60 <= runner.human_window <= 540
            and runner.attempt == "1" and not runner.baseline_checkpoint,
            "Explicit IAB readiness, a bounded window, first attempt and a fresh configuration baseline are required.")
    require(runner.env.get("SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"), "The dedicated read-only dependency credential is required.")
    source_bundle, source_manifest = runner.prepare(active=True)
    original = runner.registration()
    source = runner.bind(original, source_bundle, source_manifest)
    source_state, source_proof = source.inspect(), dict(runner.proof)
    closed(source_state)
    require(not any(source_state["terminal"].get(key, 0) for key in UNKNOWN))
    fixture = seed_fixture(source, source_bundle, source_manifest, runner.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"])
    status, expected_body = wire["public_readback"](wire["public_request"](wire["origin"] + "/sub/" + SMALL_TOKEN + "/base64"), 64 * 1024)
    wire["expect_status"](status, 200, "provider-source")
    snapshot = source_manifest["snapshots"][0]
    require(len(expected_body) == snapshot["bodyBytes"] and sha256(expected_body).hexdigest() == snapshot["bodySha256"])
    loaded = load_provider(runner, runner.env.get("DRILL_PROVIDER_RUN_ID", ""), runner.env.get("DRILL_PROVIDER_RUN_ATTEMPT", ""),
        runner.env.get("DRILL_PROVIDER_MANIFEST_SHA256", ""))
    target = desired_target(original, loaded["config"])
    dependency = DependencyReadOnly(target, runner.env["SUBS_BOT_CF_DEPENDENCY_READ_TOKEN"], target.data["provider"])
    prebind = provider.verify_provider_dependency(dependency, target.data["provider"], allow_unbound_caller=True)
    require(prebind["callerState"] == "unbound", "An application caller is already present; no configuration mutation was attempted.")
    bundle, manifest = runner.prepare()
    require(manifest["revision"] == runner.revision)
    def controller(value, reader=None):
        return Controller(value, API(value, runner.env["SUBS_BOT_CF_BOOTSTRAP_TOKEN"]),
            API(value, runner.env["SUBS_BOT_CF_DEPLOY_TOKEN"]), bundle, manifest, guard=runner.guard,
            telegram=Telegram(value, runner.secrets, rehearsal_previous_url=wire["originalOrigin"] + "/telegram/webhook"),
            secrets=runner.secrets, dependency_api=reader, control_revision=runner.revision)
    on, off = controller(target, dependency), controller(original)
    before = on.plan_deploy(source)
    admission = runner.prefix + "provider-binding/" + provider.digest(loaded["config"]) + "/" + runner.revision + "/admission.json"
    require(runner.store.get(admission, absent=True) is None,
            "This configuration rehearsal has an existing one-shot intent; inspect/reconcile it and never retry a deployment blindly.")
    intent = {"runId": runner.run, "runAttempt": runner.attempt, "sourceTarget": original.data, "desiredTarget": target.data,
        "sourceProof": source_proof, "desiredProof": runner.proof, "before": before, "providerEvidence": loaded["evidence"]}
    runner.guard()
    runner.store.put(admission, canonical(intent))
    runner.save("provider-binding-on-intent", intent)
    runner.report.update(applicationProvider={"providerEvidence": loaded["evidence"], "validatedConfigurationSha256": target.configuration_digest,
        "originalConfigurationSha256": original.configuration_digest, "oneShotIntentSha256": digest(intent)}, fixture=fixture,
        activeSourceProof=source_proof)
    on_state = on.deploy(wire["approval"](target, "deploy", on.revision, before["stateSha256"]), before["stateSha256"], source_controller=source)
    closed(on_state)
    runner.save("provider-binding-on-confirmed", on_state)
    runner.controller = on
    primary = None
    try:
        bound = provider.verify_provider_dependency(dependency, target.data["provider"])
        require(bound["callerState"] == "bound")
        runner.report["applicationProvider"]["boundProof"] = bound
        runner.exercise(provided_controller=on,
            verify_extra=lambda ctl, anchors, base: url_and_refresh(runner, ctl, anchors, base, expected_body, wire))
        require(runner.report.get("applicationProviderCases", {}).get("realRefreshSaved") is True)
        final = on.inspect()
        require(not any(final["terminal"].get(key, 0) for key in UNKNOWN),
                "The application has an unresolved external outcome; retain it without declaring the rehearsal passed.")
        provider.verify_provider_dependency(dependency, target.data["provider"])
    except Exception as error:
        primary = error
        raise
    finally:
        # Only start the distinct off release after original authentication and
        # exact closed/frozen state are confirmed. An unknown deployment is never
        # retried, even during cleanup; both full target contracts remain private.
        recovery = runner.report.get("webhookRecovery", {})
        if "webhookCheckpoint" not in runner.report or (recovery.get("webhookRestored") is True
                and recovery.get("originalWebhookAuthProbe", {}).get("status") == 400):
            try:
                current = on.inspect()
                closed(current)
                plan = off.plan_deploy(on)
                runner.save("provider-binding-off-intent", {"observed": plan, "sourceTarget": target.data, "desiredTarget": original.data})
                restored = off.deploy(wire["approval"](original, "deploy", off.revision, plan["stateSha256"]), plan["stateSha256"], source_controller=on)
                closed(restored)
                runner.save("provider-binding-off-confirmed", restored)
                unbound = provider.verify_provider_dependency(dependency, target.data["provider"], allow_unbound_caller=True)
                require(unbound["callerState"] == "unbound")
                runner.controller = off
                runner.report.update(state=restored, configurationSha256=original.configuration_digest, releaseRevision=off.revision)
                runner.report["applicationProvider"].update(configurationRestored=True, unboundProof=unbound)
            except Exception:
                runner.report["applicationProvider"]["configurationRestored"] = False
                if primary is not None:
                    raise primary from None
                raise
        else:
            runner.report["applicationProvider"]["configurationRestored"] = False
    require(runner.report["applicationProvider"].get("configurationRestored") is True)
    runner.report["status"] = "latest-off-backup-pending"
    runner.activation_baseline(stage_prefix="latest-off-baseline")
    latest = runner.report.get("latestOffBaseline", {}).get("verification", {})
    require(latest.get("baselineVerified") is True and latest.get("sourceRevision") == off.revision
            and latest.get("configurationSha256") == original.configuration_digest,
            "The latest off data and release closure were not independently preserved.")
    runner.report["status"] = "passed"
    runner.save("provider-binding-complete", runner.report["applicationProvider"])

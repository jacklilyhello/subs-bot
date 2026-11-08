"""Read-only hosted checkpoints for the approved two-account IAB batch flow."""

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import sys
from time import monotonic

from capacity_probe import _check_headers, _request, _small_body
from capacity_resources import R2Objects, Resources, integer, matches, save_private_json
from cloudflare_isolation import CloudflareClient, DIGEST, ORIGIN, REVISION, UUID, _Isolation, _verify_health
from prepare_isolation_artifact import MAIN_REF, REPOSITORY, _parse_object, require_current_main
from release_isolation import telegram_release_config
from telegram_aggregate_smoke import canonical, read_checkpoint, validate_release_pin
import telegram_document_smoke as documents
from telegram_view_fixtures import FixtureError, provider_batch_fixture_quiet, provider_batch_fixture_tables


WORKFLOW = "worker-isolation-telegram-provider-batch-smoke.yml"
ARTIFACT = "subs-bot-telegram-provider-batch"
CHECKPOINT = "telegram-provider-batch-checkpoint.json"
ROLES = ("admin", "member")
KINDS = ("positive", "negative")
MAX = documents.MAX_ID
WINDOW_SECONDS = 3600
RECEIPT_LIMIT = 96
SOURCE = re.compile(re.escape(ORIGIN) + r"/sub/([a-f0-9]{32})/base64\Z")
MARKERS = ("provider-batch-preview:v1", "provider-batch-confirm:v1", "provider-batch-status:v1")
ERROR = "The isolated Telegram provider batch acceptance could not be verified."
phase = "workflow inputs"


def require(condition):
    if not condition:
        raise FixtureError(ERROR)


def fingerprint(value):
    return documents.digest(canonical(value).encode("utf-8"))


def parse_inputs(event):
    inputs = event.get("inputs")
    require(isinstance(inputs, dict) and set(inputs) <= {
        "action", "cohort", "positive_document_run_id", "negative_document_run_id", "source_run_id",
    })
    action, cohort, positive, negative, prior = (inputs.get(field, "") for field in (
        "action", "cohort", "positive_document_run_id", "negative_document_run_id", "source_run_id",
    ))
    require(matches(documents.COHORT, cohort) and (
        (action == "preflight" and prior == "" and all(matches(documents.DECIMAL, value) for value in (positive, negative))
         and positive != negative)
        or (action == "capture" and positive == negative == "" and matches(documents.DECIMAL, prior))))
    return action, cohort, {"positive": positive, "negative": negative}, prior


def read_only_api(client, query_path=None):
    def request(method, path, payload=None):
        sql = payload.get("sql") if isinstance(payload, dict) else None
        require((method == "GET" and payload is None) or (
            method == "POST" and path == query_path and isinstance(sql, str) and sql.startswith("SELECT ")
            and ";" not in sql and set(payload) <= {"sql", "params"}))
        return client(method, path, payload)
    return request


class ReadOnlyObjects(R2Objects):
    def request(self, method, key, body=None):
        require(method == "GET" and body is None)
        return super().request(method, key)


def probe_retired(token):
    require(matches(documents.TOKEN, token))
    deadline = monotonic() + 20
    for method in ("GET", "HEAD"):
        with _request(method, f"/sub/{token}/base64", deadline, "retired batch source") as response:
            _check_headers(response, 404, "retired batch source", "text/plain")
            require(_small_body(response) == (b"Not found." if method == "GET" else b""))


def validate_document_sources(checkpoints, cohort, revision, identity, release):
    require(set(checkpoints) == set(KINDS))
    positive, negative = (checkpoints[kind] for kind in KINDS)
    require(positive["cohort"] == cohort and positive["phase"] == "created"
            and matches(documents.COHORT, negative["cohort"]) and negative["cohort"] != cohort
            and negative["phase"] == "retired" and negative["retiredAtReleasePin"] == release)
    documents.validate_checkpoint(positive, "retire", cohort, revision, identity, documents.NODE_PAGES, release)
    retired = {key: value for key, value in negative.items() if key != "retiredAtReleasePin"}
    documents.validate_checkpoint({**retired, "phase": "created"}, "retire", negative["cohort"], revision,
                                  identity, documents.NODE_PAGES, release)
    pointers = [item for value in checkpoints.values() for item in value["snapshots"].values()]
    require(len({item["id"] for item in pointers}) == len({item["tokenSha256"] for item in pointers}) == 4)


def validate_preflight(value, cohort, release, identity):
    require(isinstance(value, dict) and set(value) == {
        "version", "phase", "cohort", "releasePin", "identity", "documentRuns", "documentsSha256",
        "watermark", "observedAt", "authSha256", "imports",
    } and type(value["version"]) is int and value["version"] == 1 and value["phase"] == "preflight"
        and (value["cohort"], value["releasePin"], value["identity"]) == (cohort, release, identity)
        and integer(value["watermark"], 1, MAX) and integer(value["observedAt"], 1, MAX)
        and matches(DIGEST, value["authSha256"]) and matches(DIGEST, value["documentsSha256"])
        and set(value["documentRuns"]) == set(KINDS)
        and all(matches(documents.DECIMAL, item) for item in value["documentRuns"].values())
        and len(set(value["documentRuns"].values())) == 2
        and set(value["imports"]) == {f"{role}-{kind}" for role in ROLES for kind in KINDS})
    for item in value["imports"].values():
        require(set(item) == {"id", "tokenSha256", "sourceSha256", "importReceipt", "generation", "snapshotId",
                              "manifestSha256", "objectsSha256", "nodeCount"}
                and all(matches(DIGEST, item[field]) for field in
                        ("tokenSha256", "sourceSha256", "manifestSha256", "objectsSha256"))
                and matches(UUID, item["snapshotId"]) and item["generation"] == 1
                and integer(item["nodeCount"], 1, 32) and integer(item["id"], 1, MAX)
                and integer(item["importReceipt"], 1, value["watermark"]))
    for field in ("id", "sourceSha256", "tokenSha256", "importReceipt"):
        require(len({item[field] for item in value["imports"].values()}) == 4)


class Acceptance:
    def __init__(self, resources, policy, cohort, source_checkpoints):
        self.resources, self.bot, self.cohort = resources, policy["botId"], cohort
        self.actors = {role: policy[role + "Id"] for role in ROLES}
        self.sources = source_checkpoints
        self.documents = {kind: documents.Cohort(resources, policy, source_checkpoints[kind]["cohort"], documents.NODE_PAGES)
                          for kind in KINDS}
        self.batch_tables = provider_batch_fixture_tables(self.read)
        require(len(self.batch_tables) == 3)

    def read(self, sql, *params):
        return self.resources.query(sql, params)

    def auth(self):
        rows = self.read("""SELECT COALESCE((SELECT allowed FROM telegram_auth WHERE bot_id=? AND user_id=?),1) AS allowed,
          COALESCE((SELECT message_date FROM telegram_auth WHERE bot_id=? AND user_id=?),0) AS date,
          COALESCE((SELECT message_id FROM telegram_auth WHERE bot_id=? AND user_id=?),0) AS message""",
          *((self.bot, self.actors["member"]) * 3))
        require(len(rows) == 1 and rows[0]["allowed"] == 1
                and all(integer(rows[0][key], 0, MAX) for key in ("date", "message"))
                and (rows[0]["date"] == 0) == (rows[0]["message"] == 0))
        return {"admin": (0, 0), "member": (rows[0]["date"], rows[0]["message"])}

    def watermark(self):
        quiet, params = provider_batch_fixture_quiet(self.batch_tables, self.bot, tuple(self.actors.values()))
        result = self.read(f"""SELECT (SELECT COALESCE(max(receipt_id),0) FROM telegram_inbox) AS watermark,
          unixepoch() AS observedAt, ({quiet}) AND NOT EXISTS (SELECT 1 FROM telegram_provider_jobs
            WHERE owner_id IN (?,?) AND state IN ('pending','leased')) AND NOT EXISTS (SELECT 1 FROM subscription_provider_jobs
            WHERE owner_id IN (?,?) AND state IN ('pending','leased')) AS quiet""", *params, *self.actors.values(), *self.actors.values())
        require(len(result) == 1 and result[0].pop("quiet") == 1
                and all(integer(result[0][key], 1, MAX) for key in ("watermark", "observedAt")))
        return result[0]

    def sources_current(self):
        for kind, source in self.sources.items():
            doc = self.documents[kind]
            ids = [row["id"] for row in source["snapshots"].values()]
            rows = doc.subscriptions(ids)
            doc.require_quiet(ids)
            if kind == "positive":
                require(set(rows) == set(ROLES))
                for role, row in rows.items():
                    label = f"{role}-first"
                    require(doc.snapshot(label, row, documents.probe_export) == source["snapshots"][label])
            else:
                require(not rows and all(not doc.checked_keys(pointer, allow_missing=True) for pointer in source["snapshots"].values()))

    def inventory(self):
        imports = {}
        names = {kind: f"CFBATCH-{self.cohort}-{kind}" for kind in KINDS}
        for role, actor in self.actors.items():
            support = self.sources["positive"]["snapshots"][f"{role}-first"]["id"]
            # Qualify the whole inventory before selecting the two exact fixtures' private fields.
            owned = self.read("""SELECT id,name,source_url,token,generation,snapshot_id,manifest_sha256,node_count,last_error,
              COALESCE((SELECT revision FROM subscription_lifecycle WHERE subscription_id=subscriptions.id),0) AS lifecycle
              FROM subscriptions WHERE owner_id=? AND name IN (?,?) AND id<>?
              AND (SELECT count(*) FROM (SELECT 1 FROM subscriptions WHERE owner_id=? LIMIT 4))=3
              AND EXISTS (SELECT 1 FROM subscriptions WHERE id=? AND owner_id=? AND source_url=?)
              ORDER BY id LIMIT 3""", actor, *names.values(), support, actor, support, actor, documents.UPLOADED)
            require(len(owned) == 2)
            for kind in KINDS:
                matches_name = [row for row in owned if row["name"] == names[kind]]
                require(len(matches_name) == 1)
                row = matches_name[0]
                require(matches(SOURCE, row["source_url"]) and matches(documents.TOKEN, row["token"])
                        and integer(row["id"], 1, MAX) and row["lifecycle"] == 0)
                token = SOURCE.fullmatch(row["source_url"]).group(1)
                require(documents.digest(token.encode("ascii")) == self.sources[kind]["snapshots"][f"{role}-first"]["tokenSha256"])
                if kind == "negative":
                    probe_retired(token)
                imports[f"{role}-{kind}"] = row
        return imports

    def import_receipt(self, row, role, kind, auth, source_sha, watermark):
        records = self.read("""SELECT inbox.receipt_id AS id,job.source_sha256 AS sourceSha256,job.attempts,
          request.actor_role AS role,request.auth_message_date AS epochDate,request.auth_message_id AS epochMessage,
          (inbox.bot_id=? AND inbox.actor_id=job.owner_id AND inbox.chat_id=inbox.actor_id AND inbox.chat_type='private'
           AND inbox.thread_id IS NULL AND inbox.command='help' AND inbox.receipt_nonce='provider-request:v1'
           AND inbox.message_date>request.auth_message_date AND request.kind='url-import' AND request.outcome='admitted'
           AND job.kind='url-import' AND job.expected_generation=0 AND job.expected_lifecycle_revision=0
           AND job.state='done' AND job.result_code='saved' AND job.failure_code IS NULL AND job.lease_id IS NULL
           AND reply.outcome='saved' AND sent.state='sent' AND sent.sent_message_id IS NOT NULL) AS valid
          FROM telegram_provider_jobs AS job JOIN telegram_provider_requests AS request USING(job_id)
          JOIN telegram_inbox AS inbox USING(receipt_id) JOIN telegram_provider_replies AS reply USING(receipt_id)
          JOIN telegram_outbox AS sent USING(receipt_id)
          WHERE job.owner_id=? AND job.subscription_id=? LIMIT 2""", self.bot, self.actors[role], row["id"])
        require(len(records) == 1 and integer(records[0]["id"], self.sources[kind]["afterReceiptId"] + 1, watermark)
                and (records[0]["valid"], records[0]["role"], records[0]["epochDate"], records[0]["epochMessage"],
                     records[0]["sourceSha256"]) == (1, role, *auth[role], source_sha)
                and integer(records[0]["attempts"], 1, 3))
        return records[0]["id"]

    def snapshot(self, row, role, kind, auth, watermark):
        shares = documents.share_lines(self.sources[kind]["cohort"], f"{role}-first", documents.NODE_PAGES)
        require(integer(row["generation"], 1, 2) and row["node_count"] == len(shares)
                and matches(UUID, row["snapshot_id"]) and matches(DIGEST, row["manifest_sha256"]))
        pointer = {"id": row["id"], "snapshotId": row["snapshot_id"]}
        prefix, sizes = self.documents[kind].list_objects(pointer)
        require(set(sizes) == {prefix + name for name in documents.OBJECTS})
        bodies = {name: self.resources.objects.request("GET", prefix + name) for name in documents.OBJECTS}
        require(all(isinstance(value, bytes) and len(value) == sizes[prefix + name] for name, value in bodies.items()))
        manifest, chunk = (bodies[name] for name in documents.OBJECTS)
        require(documents.digest(manifest) == row["manifest_sha256"]
                and _parse_object(manifest, ERROR) == {"version": 1, "chunks": [
                    {"bytes": len(chunk), "sha256": documents.digest(chunk), "count": len(shares)}]})
        lines = chunk.split(b"\n")
        require(len(lines) == len(shares) + 1 and not lines[-1]
                and [_parse_object(line, ERROR).get("share") for line in lines[:-1]] == shares)
        documents.probe_export(row["token"], shares)
        source = documents.digest(row["source_url"].encode("ascii"))
        return {**pointer, "generation": row["generation"], "nodeCount": row["node_count"],
                "tokenSha256": documents.digest(row["token"].encode("ascii")), "sourceSha256": source,
                "manifestSha256": row["manifest_sha256"],
                "objectsSha256": fingerprint({name: documents.digest(body) for name, body in bodies.items()}),
                "importReceipt": self.import_receipt(row, role, kind, auth, source, watermark)}

    def snapshots(self, auth, watermark, prior=None):
        rows = self.inventory()
        result = {}
        for label, row in rows.items():
            role, kind = label.split("-")
            current = self.snapshot(row, role, kind, auth, watermark)
            if prior is None:
                require(current["generation"] == 1 and row["last_error"] is None)
            elif kind == "negative":
                require(current == prior[label] and row["last_error"] == "provider-refresh-failed")
            else:
                before = prior[label]
                require(current["generation"] == 2 and current["snapshotId"] != before["snapshotId"]
                        and row["last_error"] is None and all(current[key] == before[key] for key in
                          ("id", "nodeCount", "tokenSha256", "sourceSha256", "importReceipt")))
            result[label] = current
        return result

    def terminal(self, prior, auth):
        low = prior["watermark"]
        now = self.watermark()
        high = now["watermark"]
        require(integer(high - low, 6, RECEIPT_LIMIT) and integer(now["observedAt"] - prior["observedAt"], 1, WINDOW_SECONDS))
        histories = self.read("""SELECT inbox.receipt_id AS id,inbox.actor_id AS actor,inbox.message_id AS messageId,
          inbox.message_date AS date,inbox.received_at AS receivedAt,inbox.receipt_nonce AS marker,
          interaction.kind,interaction.batch_id AS batchId,interaction.actor_role AS role,interaction.targets,
          interaction.skipped_count AS skipped,interaction.auth_message_date AS epochDate,interaction.auth_message_id AS epochMessage,
          interaction.used_by_receipt_id AS usedBy,interaction.origin_attempt AS originAttempt,interaction.ready_at AS readyAt,
          interaction.expires_at AS ticketExpires,(interaction.token_sha256 IS NOT NULL) AS hasTicket,
          sent.state,sent.attempts,sent.sent_message_id AS sentMessage,
          (inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL AND inbox.command='help') AS private
          FROM telegram_inbox AS inbox LEFT JOIN telegram_provider_batch_interactions AS interaction USING(receipt_id)
          LEFT JOIN telegram_outbox AS sent USING(receipt_id)
          WHERE inbox.bot_id=? AND inbox.receipt_id>? AND inbox.receipt_id<=? AND inbox.receipt_nonce IN (?,?,?)
          ORDER BY inbox.receipt_id LIMIT 7""", self.bot, low, high, *MARKERS)
        require(len(histories) == 6)
        parents = self.read("""SELECT batch_id AS id,preview_receipt_id AS preview,origin_attempt AS originAttempt,actor_id AS actor,
          actor_role AS role,auth_message_date AS epochDate,auth_message_id AS epochMessage,target_count AS targetCount,
          skipped_count AS skipped,created_at AS createdAt,expires_at AS expiresAt,finished_at AS finishedAt,
          saved_count AS saved,failed_count AS failed,stale_count AS stale,expired_count AS expired
          FROM telegram_provider_batches WHERE bot_id=? AND batch_id>? AND batch_id<=? ORDER BY batch_id LIMIT 3""",
          self.bot, low, high)
        require(len(parents) == 2)
        proofs = {}
        for role, actor in self.actors.items():
            group = [row for row in histories if row["actor"] == actor]
            batches = [row for row in parents if row["actor"] == actor]
            require(len(group) == 3 and len(batches) == 1 and tuple(row["marker"] for row in group) == MARKERS
                    and all(row["private"] == 1 and row["state"] == "sent" and integer(row["attempts"], 1, 4)
                            and integer(row["sentMessage"], 1, MAX) and row["role"] == role
                            and (row["epochDate"], row["epochMessage"]) == auth[role]
                            and integer(row["receivedAt"], prior["observedAt"], now["observedAt"])
                            and row["date"] > auth[role][0] for row in group))
            preview, confirmation, status = group
            batch = batches[0]
            require((preview["kind"], confirmation["kind"], status["kind"]) == ("preview", "terminal", "status")
                    and (preview["usedBy"], confirmation["batchId"], status["batchId"]) == (batch["id"],) * 3
                    and (batch["id"], batch["preview"], batch["originAttempt"], confirmation["messageId"])
                    == (confirmation["id"], preview["id"], preview["attempts"], preview["sentMessage"])
                    and preview["originAttempt"] == preview["attempts"] and preview["skipped"] == 1
                    and preview["hasTicket"] == 1 and integer(confirmation["receivedAt"], preview["receivedAt"], preview["ticketExpires"])
                    and (batch["role"], batch["epochDate"], batch["epochMessage"]) == (role, *auth[role])
                    and (batch["targetCount"], batch["skipped"], batch["saved"], batch["failed"], batch["stale"], batch["expired"])
                    == (2, 1, 1, 1, 0, 0) and batch["expiresAt"] == batch["createdAt"] + 2700
                    and integer(batch["createdAt"], confirmation["receivedAt"], now["observedAt"])
                    and integer(batch["finishedAt"], batch["createdAt"], min(batch["expiresAt"], now["observedAt"]))
                    and confirmation["readyAt"] == batch["finishedAt"])
            items = sorted(((prior["imports"][f"{role}-{kind}"], kind) for kind in KINDS), key=lambda entry: entry[0]["id"])
            targets = [[item["id"], 1, 0, item["sourceSha256"]] for item, _ in items]
            require(isinstance(preview["targets"], str) and len(preview["targets"]) <= 4096 and json.loads(preview["targets"]) == targets)
            children = self.read("""SELECT ordinal,subscription_id AS id,source_sha256 AS sourceSha256,owner_id AS owner,
              expected_generation AS generation,expected_lifecycle_revision AS lifecycle,kind,state,attempts,result_code AS result,
              failure_code AS failure,lease_id AS lease,lease_until AS leaseUntil,finished_at AS finishedAt,expires_at AS expiresAt
              FROM telegram_provider_batch_jobs WHERE batch_id=? ORDER BY ordinal LIMIT 3""", batch["id"])
            require(len(children) == 2)
            for ordinal, ((item, kind), child) in enumerate(zip(items, children, strict=True), 1):
                result, failure = ("saved", None) if kind == "positive" else ("fetch-rejected", "fetch-rejected")
                require((child["ordinal"], child["id"], child["sourceSha256"], child["owner"], child["generation"], child["lifecycle"],
                         child["kind"], child["state"], child["result"], child["failure"], child["lease"], child["leaseUntil"],
                         child["expiresAt"])
                        == (ordinal, item["id"], item["sourceSha256"], actor, 1, 0, "refresh", "done", result, failure, None, None,
                            batch["expiresAt"]) and integer(child["attempts"], 1, 3)
                        and integer(child["finishedAt"], batch["createdAt"], batch["finishedAt"]))
            require(max(child["finishedAt"] for child in children) == batch["finishedAt"])
            proofs[role] = {"batchSha256": fingerprint([self.cohort, role, batch["id"]]), "childCount": 2,
                            "saved": 1, "failed": 1, "stale": 0, "expired": 0, "statusReply": True}
        return proofs, now


def run():
    global phase
    revision = os.environ.get("GITHUB_SHA", "")
    require(matches(REVISION, revision) and (os.environ.get("GITHUB_REPOSITORY"), os.environ.get("GITHUB_REF"),
            os.environ.get("GITHUB_EVENT_NAME")) == (REPOSITORY, MAIN_REF, "workflow_dispatch"))
    with Path(os.environ["GITHUB_EVENT_PATH"]).open("rb") as file:
        body = file.read(65537)
    require(len(body) <= 65536)
    action, cohort, runs, prior_run = parse_inputs(_parse_object(body, ERROR))
    require_current_main(revision)
    token = os.environ["GH_TOKEN"]
    if prior_run:
        prior = read_checkpoint(prior_run, revision, token, workflow_file=WORKFLOW, artifact_prefix=ARTIFACT, checkpoint_file=CHECKPOINT)
    else:
        prior = None

    phase = "isolated release and resource identity"
    raw_policy = telegram_release_config({"migrations": [{"name": "0002_telegram.sql"}]})
    policy = json.loads(raw_policy)
    target = _parse_object(os.environ["SUBS_BOT_CF_ISOLATION_TARGET_JSON"], ERROR)
    data_token, deploy_token = (os.environ.get(name) for name in ("SUBS_BOT_CF_BOOTSTRAP_TOKEN", "SUBS_BOT_CF_DEPLOY_TOKEN"))
    require(data_token and deploy_token and data_token != deploy_token)
    query_path = f"/accounts/{target['accountId']}/d1/database/{target['d1Id']}/query"
    data = read_only_api(CloudflareClient(data_token), query_path)
    scope = _Isolation(read_only_api(CloudflareClient(deploy_token)), data, target)
    resources = Resources(target, data, ReadOnlyObjects(target["accountId"], data_token))
    policy_sha = documents.digest(raw_policy.encode("utf-8"))
    scope.verify_resources()
    config, active = scope.worker_config(), scope.active()
    version = scope.version(active.version)
    require(version.revision == revision and version.telegram_config_sha256 == policy_sha and scope.cron_enabled()
            and version.telegram_provider_batch_capable and version.telegram_provider_batch
            and version.telegram_provider_url_import and version.provider_binding is not None)
    release = {"revision": version.revision, "versionId": active.version, "moduleSha256": version.digest,
               "compatibilityDate": version.compatibility}
    validate_release_pin(release)
    scope.verify_provider_batch()
    _verify_health(revision)
    identity = fingerprint([resources.scope_hash, policy_sha, active.id, asdict(version.provider_binding), config])

    phase = "protected document and predecessor proofs"
    if prior is not None:
        validate_preflight(prior, cohort, release, identity)
        runs = prior["documentRuns"]
    sources = {kind: documents.read_checkpoint(run_id, revision, token) for kind, run_id in runs.items()}
    doc_identity = documents.digest(f"{resources.scope_hash}/{policy_sha}".encode("ascii"))
    validate_document_sources(sources, cohort, revision, doc_identity, release)
    source_sha = fingerprint(sources)
    acceptance = Acceptance(resources, policy, cohort, sources)
    auth = acceptance.auth()
    epoch_sha = fingerprint(auth)
    if prior is not None:
        require((prior["documentsSha256"], prior["authSha256"]) == (source_sha, epoch_sha))

    phase = "owned sources and snapshots"
    acceptance.sources_current()
    before = acceptance.watermark()
    imports = acceptance.snapshots(auth, before["watermark"] if prior is None else prior["watermark"],
                                   None if prior is None else prior["imports"])
    if prior is None:
        checkpoint = {"version": 1, "phase": "preflight", "cohort": cohort, "releasePin": release, "identity": identity,
                      "documentRuns": runs, "documentsSha256": source_sha, **before, "authSha256": epoch_sha, "imports": imports}
        validate_preflight(checkpoint, cohort, release, identity)
    else:
        phase = "private preview, status and settled batch graph"
        proofs, after = acceptance.terminal(prior, auth)
        require(before["watermark"] == after["watermark"])
        checkpoint = {**prior, "phase": "capture", "afterWatermark": after["watermark"], "batches": proofs, "finalSnapshots": imports}

    phase = "final exact isolation readback"
    require_current_main(revision)
    require(scope.worker_config() == config and scope.active() == active and scope.version(active.version) == version
            and scope.cron_enabled() and acceptance.auth() == auth
            and acceptance.watermark()["watermark"] == before["watermark"])
    scope.verify_resources()
    scope.verify_provider_batch()
    _verify_health(revision)
    save_private_json(Path(os.environ["RUNNER_TEMP"]) / CHECKPOINT, checkpoint)
    print(json.dumps({"phase": action, "verifiedActors": 2, "pinnedImportCount": len(imports),
                      "verifiedBatchCount": 2 if prior is not None else 0,
                      "retainedFailureSnapshots": 2 if prior is not None else 0}, sort_keys=True))


if __name__ == "__main__":
    try:
        run()
    except Exception:
        sys.exit(f"{ERROR} Failed phase {phase}.")

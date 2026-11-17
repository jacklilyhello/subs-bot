"""Read pinned private Provider originals without promoting partial proof to success."""

import json
import hmac
import os
from pathlib import Path
from hashlib import sha256
import tempfile
import re
from datetime import datetime, timezone
from urllib.parse import urlencode, quote
from urllib.request import Request
from xml.etree import ElementTree

import archive_production_provider as sealed
import production_provider as control

SEAL_WORKFLOW = ".github/workflows/worker-production-provider-source.yml"
READBACK_WORKFLOW = ".github/workflows/worker-production-provider-source-readback.yml"
RECONCILE_WORKFLOW = ".github/workflows/worker-production-provider-source-reconcile.yml"


def seal_context(workflow=SEAL_WORKFLOW, *, mutation=True):
    revision = os.environ.get("GITHUB_SHA", "")
    control.require(os.environ.get("GITHUB_REPOSITORY") == control.github.REPOSITORY
                    and os.environ.get("GITHUB_REF") == control.github.MAIN_REF
                    and os.environ.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                    and os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
                    and os.environ.get("GITHUB_WORKFLOW_SHA") == revision
                    and os.environ.get("GITHUB_WORKFLOW_REF") == f"{control.github.REPOSITORY}/{workflow}@{control.github.MAIN_REF}"
                    and (not mutation or os.environ.get("GITHUB_RUN_ATTEMPT") == "1"))
    control.github.require_current_main(revision)


def source_ancestor(build, token):
    current = os.environ["GITHUB_SHA"]
    revision = build["revision"]
    if revision != current:
        comparison = control.github._get_json(f"/compare/{revision}...{current}?per_page=1", token)
        control.require(comparison.get("status") == "ahead" and type(comparison.get("ahead_by")) is int
                        and comparison["ahead_by"] > 0 and comparison.get("behind_by") == 0
                        and all(isinstance(comparison.get(key), dict) and comparison[key].get("sha") == revision
                                for key in ("base_commit", "merge_base_commit")))


def prepare_seal():
    seal_context()
    config = control.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(config["environment"] == "production" and os.environ.get("SUBS_BOT_PROVIDER_CI_RUN_ID") == config["build"]["runId"])
    source_ancestor(config["build"], control.github._github_token())
    evidence = control.provenance.prepare(provider_revision=config["build"]["revision"], provider_attempt=config["build"]["runAttempt"])
    control.require(evidence == config["build"])
    root = Path(os.environ["RUNNER_TEMP"]) / "provider-source-seal-input"
    root.mkdir(mode=0o700)
    control.provenance._download_zip(evidence["artifactId"], control.github._github_token(), evidence["archiveSha256"],
                                    root / "provider-source-archive.zip")
    with control.provenance._write_private(root / "target.sha256") as output:
        output.write((control.digest(config) + "\n").encode("ascii"))


class ProductionStore(sealed.PrivateProofStore):
    """An explicitly registered production backup bucket; never the isolation bucket."""

    def __init__(self, raw, token, run_id, attempt):
        value = control.github._parse_object(raw, sealed.ERROR)
        control.require(set(value) == {"version", "accountId", "namespace", "bucket", "createdOn"}
                        and type(value["version"]) is int and value["version"] == 1
                        and sha256(value["accountId"].encode("ascii")).hexdigest() == control.publication.TARGET_ACCOUNT_SHA256 and value["namespace"] == "lilyya"
                        and value["bucket"] == "subs-bot-cf-prod-backup-01"
                        and control.match(control.bootstrap.TIMESTAMP, value["createdOn"]))
        super().__init__({"accountId": value["accountId"], "namespace": value["namespace"],
                          "r2CreatedOn": value["createdOn"]}, token, run_id, attempt)
        self.bucket = value["bucket"]
        self.base = f"/accounts/{value['accountId']}/r2/buckets/{self.bucket}"


def production_manifest(store, expected):
    store.verify()
    raw = store.read("source-manifest.json")
    control.require(isinstance(raw, bytes) and len(raw) <= 65536 and sha256(raw).hexdigest() == expected)
    manifest = control.github._parse_object(raw, sealed.ERROR)
    control.require(set(manifest) == {"version", "kind", "runId", "runAttempt", "controllerRevision", "target", "files"}
                    and manifest["version"] == 1 and manifest["kind"] == "subs-bot-production-provider-source"
                    and manifest["runId"] == store.run_id and manifest["runAttempt"] == store.attempt
                    and control.match(control.provider.REVISION, manifest["controllerRevision"])
                    and isinstance(manifest["files"], dict) and set(manifest["files"]) == {"provider-source-archive.zip"})
    config = control.validate_config(manifest["target"])
    control.require(config["environment"] == "production")
    entry = manifest["files"]["provider-source-archive.zip"]
    control.require(isinstance(entry, dict) and set(entry) == {"bytes", "sha256", "chunks"}
                    and type(entry["bytes"]) is int and 0 < entry["bytes"] <= control.provenance.MAX_ZIP
                    and entry["sha256"] == config["build"]["archiveSha256"]
                    and isinstance(entry["chunks"], list) and 0 < len(entry["chunks"]) <= sealed.MAX_CHUNKS)
    for chunk in entry["chunks"]:
        control.require(isinstance(chunk, dict) and set(chunk) == {"bytes", "sha256"}
                        and type(chunk["bytes"]) is int and 0 < chunk["bytes"] <= sealed.CHUNK_BYTES
                        and control.match(control.provider.HEX, chunk["sha256"]))
    return manifest, config


def list_private_keys(store, prefix):
    """Bounded S3 listing with an explicit, verified terminal page."""
    store.verify()
    identity = sealed.verified_token_identity(store.api, store.target["accountId"])
    host = store.target["accountId"] + ".r2.cloudflarestorage.com"
    path = "/" + quote(store.bucket, safe="-_.~")
    rows, cursor, seen_cursors = [], None, set()
    for _page in range(16):
        query = {"list-type": "2", "prefix": prefix, "max-keys": "1000"}
        if cursor is not None:
            query["continuation-token"] = cursor
        canonical_query = urlencode(sorted(query.items()), quote_via=quote, safe="-_.~")
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        day = timestamp[:8]
        payload = sha256(b"").hexdigest()
        canonical_headers = f"host:{host}\nx-amz-content-sha256:{payload}\nx-amz-date:{timestamp}\n"
        signed = "host;x-amz-content-sha256;x-amz-date"
        canonical = "\n".join(("GET", path, canonical_query, canonical_headers, signed, payload))
        scope = f"{day}/auto/s3/aws4_request"
        signing = "\n".join(("AWS4-HMAC-SHA256", timestamp, scope, sha256(canonical.encode("ascii")).hexdigest()))
        key = ("AWS4" + sha256(store.token.encode("ascii")).hexdigest()).encode("ascii")
        for part in (day, "auto", "s3", "aws4_request"):
            key = hmac.digest(key, part.encode("ascii"), "sha256")
        signature = hmac.digest(key, signing.encode("ascii"), "sha256").hex()
        authorization = (f"AWS4-HMAC-SHA256 Credential={identity['id']}/{scope}, "
                         f"SignedHeaders={signed}, Signature={signature}")
        request = Request("https://" + host + path + "?" + canonical_query,
                          headers={"Authorization": authorization, "Accept-Encoding": "identity",
                                   "x-amz-content-sha256": payload, "x-amz-date": timestamp})
        with store.opener.open(request, timeout=30) as response:
            control.require(response.status == 200 and response.headers.get("Content-Encoding", "identity") == "identity")
            raw = response.read(2 * 1024 * 1024 + 1)
        control.require(0 < len(raw) <= 2 * 1024 * 1024)
        try:
            root = ElementTree.fromstring(raw)
        except ElementTree.ParseError:
            raise control.ProviderError("The private source inventory returned invalid XML.") from None
        ns = "{http://s3.amazonaws.com/doc/2006-03-01/}"
        control.require(root.tag == ns + "ListBucketResult")
        truncated = root.findall(ns + "IsTruncated")
        prefixes = root.findall(ns + "Prefix")
        control.require(len(truncated) == 1 and truncated[0].text in {"true", "false"}
                        and len(prefixes) == 1 and prefixes[0].text == prefix
                        and not root.findall(ns + "CommonPrefixes"))
        batch = []
        for entry in root.findall(ns + "Contents"):
            keys = entry.findall(ns + "Key")
            control.require(len(keys) == 1 and isinstance(keys[0].text, str))
            batch.append({"key": keys[0].text})
        control.require(len(batch) <= 1000)
        rows.extend(batch)
        tokens = root.findall(ns + "NextContinuationToken")
        if truncated[0].text == "false":
            control.require(not tokens)
            break
        control.require(len(tokens) == 1)
        cursor = tokens[0].text
        control.require(isinstance(cursor, str) and 0 < len(cursor) <= 4096 and cursor not in seen_cursors)
        seen_cursors.add(cursor)
    else:
        raise control.ProviderError("Provider source archive listing exceeds its safe page limit.")
    return [row["key"] for row in rows]


def production_inventory(store, bucket, *, inspect_operation=None):
    """List every registered source intent; an incomplete/unknown entry blocks writes."""
    rows = list_private_keys(store, sealed.BASE)
    grouped = {}
    for row in rows:
        match = re.fullmatch(re.escape(sealed.BASE) + r"([1-9][0-9]*)/1/(source-intent\.json|source-manifest\.json|blobs/[0-9a-f]{64})", row)
        control.require(match is not None)
        grouped.setdefault(match.group(1), set())
        control.require(match.group(2) not in grouped[match.group(1)])
        grouped[match.group(1)].add(match.group(2))
    control.require(len(grouped) <= 32, "Production Provider source archive inventory exceeds its safe bound.")
    completed = {}
    for operation_id, keys in grouped.items():
        if operation_id == inspect_operation:
            continue
        control.require({"source-intent.json", "source-manifest.json"} <= keys,
                        "A previous source seal is incomplete or its result is unknown.")
        existing = ProductionStore(control.canonical(bucket), store.token, operation_id, "1")
        intent_raw, manifest_raw = existing.read("source-intent.json"), existing.read("source-manifest.json")
        control.require(isinstance(intent_raw, bytes) and isinstance(manifest_raw, bytes))
        intent = control.github._parse_object(intent_raw, sealed.ERROR)
        manifest, target = production_manifest(existing, sha256(manifest_raw).hexdigest())
        plan = intent.get("plan")
        control.require(isinstance(plan, dict) and set(plan) == {"version", "action", "operationId", "targetSha256", "build", "bucketSha256", "prefixState", "inventorySha256", "controllersSha256", "controllerRevision"}
                        and {key: value for key, value in plan.items() if key not in {"inventorySha256", "controllersSha256"}}
                        == {key: value for key, value in source_plan(target, bucket, operation_id, {}, [], intent.get("controllerRevision")).items() if key not in {"inventorySha256", "controllersSha256"}}
                        and all(control.match(control.provider.HEX, plan[key]) for key in ("inventorySha256", "controllersSha256"))
                        and intent.get("approvalSha256") == control.digest(plan) and intent.get("status") == "started-unknown"
                        and intent.get("controllerRevision") == manifest["controllerRevision"]
                        and control.match(control.provider.DECIMAL, intent.get("runId")) and intent.get("runAttempt") == "1")
        entry = manifest["files"]["provider-source-archive.zip"]
        control.require(keys == {"source-intent.json", "source-manifest.json", *("blobs/" + item["sha256"] for item in entry["chunks"])})
        with open(os.devnull, "wb") as output:
            control.require(sealed.read_record(existing, manifest, "provider-source-archive.zip", output) == target["build"]["archiveSha256"])
        completed[operation_id] = {"intentSha256": sha256(intent_raw).hexdigest(), "manifestSha256": sha256(manifest_raw).hexdigest(),
                                   "runId": intent["runId"], "controllerRevision": intent["controllerRevision"]}
    if inspect_operation is not None:
        return completed, grouped.get(inspect_operation, set())
    return completed


def source_ledger():
    raw = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_LEDGER_JSON", "")
    value = control.github._parse_object(raw, sealed.ERROR)
    control.require(len(value) <= 32)
    for operation_id, record in value.items():
        control.require(control.match(control.provider.DECIMAL, operation_id) and isinstance(record, dict)
                        and set(record) == {"intentSha256", "manifestSha256", "runId", "controllerRevision"}
                        and all(control.match(control.provider.HEX, record[key]) for key in ("intentSha256", "manifestSha256"))
                        and control.match(control.provider.DECIMAL, record["runId"])
                        and control.match(control.provider.REVISION, record["controllerRevision"]))
    return value


def trusted_controllers():
    raw = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_CONTROLLERS_JSON", "")
    values = json.loads(raw, object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(values, list) and 0 < len(values) <= 16 and len(set(values)) == len(values)
                    and all(control.match(control.provider.REVISION, value) for value in values)
                    and os.environ.get("GITHUB_SHA") in values)
    return values


def seal_history(operation_id, completed, controllers):
    """Reject reuse and block every later seal after an unresolved seal attempt."""
    token = control.github._github_token()
    current = os.environ["GITHUB_RUN_ID"]
    rows = []
    for page in range(1, 11):
        data = control.github._get_json(f"/actions/workflows/worker-production-provider-source.yml/runs?per_page=100&page={page}", token)
        batch = data.get("workflow_runs")
        control.require(isinstance(batch, list) and len(batch) <= 100 and type(data.get("total_count")) is int
                        and 0 <= data["total_count"] <= 1000)
        rows.extend(batch)
        if len(batch) < 100:
            break
    else:
        raise control.ProviderError("Provider source seal history is too large to verify safely.")
    control.require(len(rows) == data["total_count"] and len({str(row.get("id")) for row in rows if isinstance(row, dict)}) == len(rows))
    current_seen, seen = False, set()
    for row in rows:
        control.require(isinstance(row, dict))
        control.require(row.get("head_sha") in controllers and row.get("head_branch") == "main"
                        and row.get("event") == "workflow_dispatch" and row.get("run_attempt") == 1
                        and row.get("path") in (SEAL_WORKFLOW, SEAL_WORKFLOW + "@main", SEAL_WORKFLOW + "@refs/heads/main")
                        and all(isinstance(row.get(key), dict) and row[key].get("id") == control.github.REPOSITORY_ID
                                for key in ("repository", "head_repository")))
        title = row.get("display_title")
        control.require(isinstance(title, str) and re.fullmatch(r"Provider source (?:plan|seal) [1-9][0-9]*", title))
        if title.startswith("Provider source plan "):
            continue
        observed_id = title.removeprefix("Provider source seal ")
        if str(row.get("id")) == current:
            control.require(not current_seen and title == "Provider source seal " + operation_id
                            and row.get("event") == "workflow_dispatch" and row.get("run_attempt") == 1)
            current_seen = True
        else:
            control.require(observed_id != operation_id and observed_id not in seen and observed_id in completed
                            and str(row.get("id")) == completed[observed_id]["runId"]
                            and row.get("head_sha") == completed[observed_id]["controllerRevision"]
                            and (row.get("status"), row.get("conclusion")) == ("completed", "success"),
                            "A prior Provider source seal is unresolved or the operation ID was used; reconcile before any new seal.")
            seen.add(observed_id)
    control.require(seen == set(completed), "Private source archive inventory and seal history disagree.")
    control.require(current_seen, "The current source seal run is not yet independently visible; no write was attempted.")


def source_plan(config, bucket, operation_id, inventory, controllers, controller_revision):
    control.require(control.match(control.provider.DECIMAL, operation_id) and control.match(control.provider.REVISION, controller_revision))
    return {"version": 1, "action": "seal-production-provider-source", "operationId": operation_id,
            "targetSha256": control.digest(config), "build": config["build"],
            "bucketSha256": control.digest(bucket), "prefixState": "intent-and-manifest-absent",
            "inventorySha256": control.digest(inventory), "controllersSha256": control.digest(controllers),
            "controllerRevision": controller_revision}


def verify_seal_origin(operation_id, record):
    run = control.github._get_json(f"/actions/runs/{record['runId']}/attempts/1", control.github._github_token())
    control.require(str(run.get("id")) == record["runId"] and run.get("run_attempt") == 1
                    and run.get("path") in (SEAL_WORKFLOW, SEAL_WORKFLOW + "@main", SEAL_WORKFLOW + "@refs/heads/main")
                    and run.get("event") == "workflow_dispatch" and run.get("display_title") == "Provider source seal " + operation_id
                    and (run.get("status"), run.get("conclusion")) == ("completed", "success")
                    and run.get("head_branch") == "main" and run.get("head_sha") == record["controllerRevision"]
                    and all(isinstance(run.get(key), dict) and run[key].get("id") == control.github.REPOSITORY_ID
                            for key in ("repository", "head_repository")))
    source_ancestor({"revision": record["controllerRevision"]}, control.github._github_token())


def production_seal_action(write):
    seal_context()
    config = control.read_config(os.environ.get("SUBS_BOT_PROVIDER_CONTROL_TARGET_JSON", ""))
    control.require(config["environment"] == "production")
    bucket = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON", ""), sealed.ERROR)
    operation_id = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_OPERATION_ID", "")
    token_name = "SUBS_BOT_CF_PROVIDER_ARCHIVE_WRITE_TOKEN" if write else "SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN"
    store = ProductionStore(control.canonical(bucket), os.environ.get(token_name, ""), operation_id, "1")
    store.verify()
    completed = production_inventory(store, bucket)
    control.require(completed == source_ledger(), "The private source inventory differs from its independently registered ledger.")
    controllers = trusted_controllers()
    control.require(store.read("source-intent.json") is None and store.read("source-manifest.json") is None,
                    "The selected source archive operation is occupied or unconfirmed.")
    plan = source_plan(config, bucket, operation_id, completed, controllers, os.environ["GITHUB_SHA"])
    approval = control.digest(plan)
    if not write:
        print(json.dumps({"status": "plan-only", "approvalSha256": approval, "targetSha256": plan["targetSha256"],
                          "bucketSha256": plan["bucketSha256"], "operationId": operation_id,
                          "archiveCount": len(completed), "archiveLimit": 32}, sort_keys=True))
        return
    control.require(len(completed) < 32, "Source archive registration is full; expand the reviewed inventory mechanism without deleting history.")
    control.require(os.environ.get("SUBS_BOT_PROVIDER_SOURCE_APPROVAL", "") == approval,
                    "The exact source seal plan was not approved.")
    seal_history(operation_id, completed, controllers)
    build = config["build"]
    source = Path(os.environ["RUNNER_TEMP"]) / "provider-source-seal-input" / "provider-source-archive.zip"
    pin = source.with_name("target.sha256")
    control.require(control.provider.checked_file(pin, 128).read_bytes() == (control.digest(config) + "\n").encode("ascii"))
    control.provider.checked_file(source, control.provenance.MAX_ZIP)
    control.require(control.provider.checksum(source) == build["archiveSha256"])
    with tempfile.TemporaryDirectory(prefix=".provider-source-seal-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        staged = Path(temporary) / "verified"
        staged.mkdir(mode=0o700)
        control.provenance._unpack(source, staged)
        with control.provenance.source_requirements(build["revision"]) as requirements:
            release = control.provider.verify_release(staged, build["revision"], ref=control.github.MAIN_REF,
                run_id=build["runId"], run_attempt=build["runAttempt"], requirements=requirements)
        control.require(all(release[key] == build[key] for key in control.publication.MANIFEST_FIELDS))
    control.github.require_current_main(os.environ["GITHUB_SHA"])
    store.verify()
    control.require(store.read("source-intent.json") is None and store.read("source-manifest.json") is None)
    intent = control.canonical({"version": 1, "plan": plan, "approvalSha256": approval,
                                "controllerRevision": os.environ["GITHUB_SHA"], "runId": os.environ["GITHUB_RUN_ID"],
                                "runAttempt": os.environ["GITHUB_RUN_ATTEMPT"], "status": "started-unknown"})
    store.put("source-intent.json", intent)
    control.require(store.read("source-intent.json") == intent)
    chunks, size, hashed = [], 0, sha256()
    with source.open("rb") as file:
        while body := file.read(sealed.CHUNK_BYTES):
            size += len(body)
            control.require(size <= control.provenance.MAX_ZIP and len(chunks) < sealed.MAX_CHUNKS)
            hashed.update(body)
            chunk_sha = sha256(body).hexdigest()
            store.put("blobs/" + chunk_sha, body)
            chunks.append({"bytes": len(body), "sha256": chunk_sha})
    control.require(size > 0 and hashed.hexdigest() == build["archiveSha256"])
    manifest = {"version": 1, "kind": "subs-bot-production-provider-source", "runId": operation_id,
                "runAttempt": "1", "controllerRevision": os.environ["GITHUB_SHA"], "target": config,
                "files": {"provider-source-archive.zip": {"bytes": size, "sha256": hashed.hexdigest(), "chunks": chunks}}}
    raw = control.canonical(manifest)
    control.require(len(raw) <= 65536)
    store.put("source-manifest.json", raw)
    manifest_sha = sha256(raw).hexdigest()
    observed, _ = production_manifest(store, manifest_sha)
    with open(os.devnull, "wb") as output:
        control.require(sealed.read_record(store, observed, "provider-source-archive.zip", output) == build["archiveSha256"])
    print(json.dumps({"status": "sealed", "manifestSha256": manifest_sha, "targetSha256": plan["targetSha256"],
                      "operationId": operation_id, "runAttempt": "1", "intentSha256": sha256(intent).hexdigest()}, sort_keys=True))


def verify_production():
    seal_context(READBACK_WORKFLOW, mutation=False)
    expected = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_MANIFEST_SHA256", "")
    target_sha = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_SHA256", "")
    control.require(control.match(control.provider.HEX, expected) and control.match(control.provider.HEX, target_sha))
    store = ProductionStore(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON", ""),
                            os.environ.get("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_RUN_ID", ""),
                            os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_RUN_ATTEMPT", ""))
    bucket = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON", ""), sealed.ERROR)
    inventory = production_inventory(store, bucket)
    ledger = source_ledger()
    others = {key: value for key, value in inventory.items() if key != store.run_id}
    registered_others = {key: value for key, value in ledger.items() if key != store.run_id}
    control.require(others == registered_others and store.run_id in inventory and inventory[store.run_id]["manifestSha256"] == expected
                    and (store.run_id not in ledger or ledger[store.run_id] == inventory[store.run_id]))
    verify_seal_origin(store.run_id, inventory[store.run_id])
    manifest, config = production_manifest(store, expected)
    control.require(control.digest(config) == target_sha)
    build = config["build"]
    token = control.github._github_token()
    source_ancestor(build, token)
    control.github.verify_main_run(build["runId"], build["revision"], token,
        workflow_id=control.provenance.WORKFLOW_ID, workflow_path=control.provenance.WORKFLOW_PATH,
        workflow_label="Provider Fetch CI", run_attempt=build["runAttempt"])
    with tempfile.TemporaryDirectory(prefix=".provider-source-readback-", dir=os.environ["RUNNER_TEMP"]) as temporary:
        root = Path(temporary)
        original = root / "source.zip"
        with control.provenance._write_private(original) as output:
            control.require(sealed.read_record(store, manifest, "provider-source-archive.zip", output) == build["archiveSha256"])
        staged = root / "verified"
        staged.mkdir(mode=0o700)
        control.provenance._unpack(original, staged)
        with control.provenance.source_requirements(build["revision"]) as requirements:
            release = control.provider.verify_release(staged, build["revision"], ref=control.github.MAIN_REF,
                run_id=build["runId"], run_attempt=build["runAttempt"], requirements=requirements)
        control.require(all(release[key] == build[key] for key in control.publication.MANIFEST_FIELDS))
    store.verify()
    control.github.require_current_main(os.environ["GITHUB_SHA"])
    print(json.dumps({"status": "complete", "readback": "R2-only-complete", "manifestSha256": expected,
                      "targetSha256": target_sha, "operationId": store.run_id, "runAttempt": store.attempt,
                      "ledgerRecord": inventory[store.run_id]}, sort_keys=True))


def failed_seal_origin(operation_id, run_id, controllers):
    """Read the exact failed workflow attempt and its completed source job."""
    control.require(control.match(control.provider.DECIMAL, operation_id) and control.match(control.provider.DECIMAL, run_id))
    token = control.github._github_token()
    run = control.github._get_json(f"/actions/runs/{run_id}/attempts/1", token)
    revision = run.get("head_sha")
    control.require(str(run.get("id")) == run_id and run.get("run_attempt") == 1
                    and run.get("path") in (SEAL_WORKFLOW, SEAL_WORKFLOW + "@main", SEAL_WORKFLOW + "@refs/heads/main")
                    and run.get("event") == "workflow_dispatch" and run.get("display_title") == "Provider source seal " + operation_id
                    and run.get("status") == "completed" and run.get("conclusion") in {"failure", "cancelled", "timed_out"}
                    and run.get("head_branch") == "main" and revision in controllers
                    and all(isinstance(run.get(key), dict) and run[key].get("id") == control.github.REPOSITORY_ID
                            for key in ("repository", "head_repository")))
    source_ancestor({"revision": revision}, token)
    result = control.github._get_json(f"/actions/runs/{run_id}/attempts/1/jobs?per_page=100", token)
    jobs = result.get("jobs")
    control.require(isinstance(jobs, list) and result.get("total_count") == len(jobs) == 1)
    job = jobs[0]
    control.require(isinstance(job, dict) and job.get("name") == "source" and job.get("status") == "completed"
                    and isinstance(job.get("steps"), list))
    steps = [step for step in job["steps"] if isinstance(step, dict)
             and step.get("name") == "Seal once after exact approval and durable intent"]
    control.require(len(steps) == 1 and steps[0].get("status") == "completed"
                    and steps[0].get("conclusion") in {"skipped", "failure", "cancelled", "success"})
    return {"runId": run_id, "controllerRevision": revision, "runConclusion": run["conclusion"],
            "sealStepConclusion": steps[0]["conclusion"]}


def inspect_production_failure():
    """Diagnose an exact failed seal using GET only; never resolve or replay it."""
    seal_context(RECONCILE_WORKFLOW, mutation=False)
    operation_id = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_OPERATION_ID", "")
    run_id = os.environ.get("SUBS_BOT_PROVIDER_SOURCE_FAILED_RUN_ID", "")
    bucket = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON", ""), sealed.ERROR)
    store = ProductionStore(control.canonical(bucket), os.environ.get("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", ""), operation_id, "1")
    completed, keys = production_inventory(store, bucket, inspect_operation=operation_id)
    ledger = source_ledger()
    control.require(completed == {key: value for key, value in ledger.items() if key != operation_id})
    origin = failed_seal_origin(operation_id, run_id, trusted_controllers())
    projection = {"version": 1, "kind": "provider-source-failure-readback", "operationId": operation_id,
                  "bucketSha256": control.digest(bucket), "origin": origin, "objectCount": len(keys)}
    if not keys:
        # A failed step may have an unconfirmed write even if a later GET is empty.
        control.require(origin["sealStepConclusion"] == "skipped",
                        "The seal step ran and its empty prefix is not proof that no write was dispatched.")
        projection["classification"] = "seal-step-not-dispatched"
    elif {"source-intent.json", "source-manifest.json"} <= keys:
        expected = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_MANIFEST_SHA256", "")
        target_sha = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_SHA256", "")
        control.require(control.match(control.provider.HEX, expected) and control.match(control.provider.HEX, target_sha))
        all_completed = production_inventory(store, bucket)
        record = all_completed.get(operation_id)
        control.require(isinstance(record, dict) and record["manifestSha256"] == expected
                        and record["runId"] == run_id and record["controllerRevision"] == origin["controllerRevision"]
                        and (operation_id not in ledger or ledger[operation_id] == record))
        manifest, config = production_manifest(store, expected)
        control.require(control.digest(config) == target_sha)
        build = config["build"]
        token = control.github._github_token()
        source_ancestor(build, token)
        control.github.verify_main_run(build["runId"], build["revision"], token,
            workflow_id=control.provenance.WORKFLOW_ID, workflow_path=control.provenance.WORKFLOW_PATH,
            workflow_label="Provider Fetch CI", run_attempt=build["runAttempt"])
        with tempfile.TemporaryDirectory(prefix=".provider-failure-readback-", dir=os.environ["RUNNER_TEMP"]) as temporary:
            root = Path(temporary)
            original, staged = root / "source.zip", root / "verified"
            with control.provenance._write_private(original) as output:
                control.require(sealed.read_record(store, manifest, "provider-source-archive.zip", output) == build["archiveSha256"])
            staged.mkdir(mode=0o700)
            control.provenance._unpack(original, staged)
            with control.provenance.source_requirements(build["revision"]) as requirements:
                release = control.provider.verify_release(staged, build["revision"], ref=control.github.MAIN_REF,
                    run_id=build["runId"], run_attempt=build["runAttempt"], requirements=requirements)
            control.require(all(release[key] == build[key] for key in control.publication.MANIFEST_FIELDS))
        projection.update({"classification": "complete-original-observed-failed-run", "ledgerRecord": record,
                           "targetSha256": target_sha})
    else:
        projection["classification"] = "incomplete-or-unknown"
        intent = store.read("source-intent.json") if "source-intent.json" in keys else None
        if intent is not None:
            projection["intentSha256"] = sha256(intent).hexdigest()
    store.verify()
    control.github.require_current_main(os.environ["GITHUB_SHA"])
    # A readback is evidence, never authority to replay or to mark a failed run successful.
    print(json.dumps({**projection, "readbackSha256": control.digest(projection), "retryAuthorized": False}, sort_keys=True))


def restore():
    refs = json.loads(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_REFS", ""), object_pairs_hook=control.github._unique_json_object)
    control.require(isinstance(refs, list) and 0 < len(refs) <= 9)
    root = Path(os.environ["RUNNER_TEMP"]) / "provider-durable-sources"
    root.mkdir(mode=0o700)
    builds, inventory = [], None
    for ref in refs:
        control.require(isinstance(ref, dict) and set(ref) == {"runId", "runAttempt", "manifestSha256", "targetSha256", "kind"}
                        and ref["kind"] in {"complete", "partial", "production"}
                        and all(control.match(control.provider.HEX, ref[key]) for key in ("manifestSha256", "targetSha256")))
        environment = os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_ENVIRONMENT", "rehearsal")
        control.require(environment in {"production", "rehearsal"} and (ref["kind"] == "production") == (environment == "production"))
        if environment == "production":
            store = ProductionStore(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON", ""),
                                    os.environ.get("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", ""), ref["runId"], ref["runAttempt"])
            if inventory is None:
                bucket = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_BUCKET_JSON", ""), sealed.ERROR)
                inventory = production_inventory(store, bucket)
                control.require(inventory == source_ledger())
            control.require(ref["runId"] in inventory
                            and inventory[ref["runId"]]["manifestSha256"] == ref["manifestSha256"])
            verify_seal_origin(ref["runId"], inventory[ref["runId"]])
            manifest, config = production_manifest(store, ref["manifestSha256"])
            name = "provider-source-archive.zip"
        else:
            target = control.github._parse_object(os.environ.get("SUBS_BOT_PROVIDER_ARCHIVE_TARGET_JSON", ""), sealed.ERROR)
            store = sealed.PrivateProofStore(target, os.environ.get("SUBS_BOT_CF_PROVIDER_ARCHIVE_READ_TOKEN", ""), ref["runId"], ref["runAttempt"])
        if ref["kind"] == "complete":
            sealed.verify_archive(store, ref["manifestSha256"])
            manifest = control.github._parse_object(store.read("manifest.json"), sealed.ERROR)
            proof = control.github._parse_object(sealed.read_record(store, manifest, "provider-rehearsal-proof.json"), sealed.ERROR)
            config = control.validate_config(proof["target"])
            control.require(proof.get("status") == "complete" and proof.get("productionMutation") is False
                            and proof.get("runId") == ref["runId"] and proof.get("runAttempt") == ref["runAttempt"]
                            and control.digest(proof) == manifest["proofSha256"]
                            and config == control.github._parse_object(sealed.read_record(store, manifest, "provider-rehearsal-target.json"), sealed.ERROR))
            name = "provider-source-archive.zip"
        elif ref["kind"] == "partial":
            sealed.verify_partial(store, ref["manifestSha256"])
            manifest = control.github._parse_object(store.read("partial-manifest.json"), sealed.ERROR)
            latest = manifest.get("latestCheckpoint")
            control.require(isinstance(latest, dict))
            envelope = control.github._parse_object(sealed.read_record(store, manifest, latest["record"]), sealed.ERROR)
            config = control.validate_config(envelope["target"])
            journal = envelope["journal"]
            control.require(envelope.get("version") == 2 and control.digest(config) == latest["targetSha256"]
                            and journal.get("targetSha256") == latest["targetSha256"]
                            and journal.get("source") == config["build"]
                            and journal.get("runId") == ref["runId"] and journal.get("runAttempt") == ref["runAttempt"])
            name = f"subs-bot-provider-attempt-source-{store.run_id}-{store.attempt}/provider-source-archive.zip"
        control.require(config["environment"] == environment and (environment == "production" or config["caller"] is None)
                        and control.digest(config) == ref["targetSha256"])
        build = config["build"]
        control.require(not any(row["build"]["archiveSha256"] == build["archiveSha256"] for row in builds))
        path = root / (build["archiveSha256"] + ".zip")
        with control.provenance._write_private(path) as output:
            control.require(sealed.read_record(store, manifest, name, output) == build["archiveSha256"])
        builds.append({"build": build, "target": config})
        store.verify()
    with control.provenance._write_private(root / "index.json") as output:
        output.write(control.canonical(builds))


if __name__ == "__main__":
    try:
        if os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ACTION") == "prepare-production":
            prepare_seal()
        elif os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ACTION") == "seal-production":
            production_seal_action(True)
        elif os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ACTION") == "plan-production":
            production_seal_action(False)
        elif os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ACTION") == "verify-production":
            verify_production()
        elif os.environ.get("SUBS_BOT_PROVIDER_SOURCE_ACTION") == "inspect-production-failure":
            inspect_production_failure()
        else:
            restore()
    except (ValueError, KeyError, OSError, TypeError):
        raise SystemExit("The pinned private Provider originals could not be read safely.") from None

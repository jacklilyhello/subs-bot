"""Create only the two explicitly approved isolated D1 fixtures once.

The durable intent is the admission record: an unknown result is never retried.
The companion fresh job independently reads the immutable receipt and D1.
"""
from hashlib import sha256
import json
import os
import re
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler

from cloudflare_isolation import API_ORIGIN, CloudflareClient, _NoRedirect
from evidence_archive import verify_lifecycle
from production_target import canonical, parsed, require
import prepare_isolation_artifact as github
import scoped_r2

ACCOUNT = "9431815bdb8beb2272f6668e06b7d3be"
BUCKET = "subs-bot-cf-control-drill-backup-01"
CREATED = "2026-11-16T12:08:33.194Z"
PREFIX = "maintenance/production-control/evidence/fixture-d1-creation/"
NAMES = {"subs-bot-cf-backup-capacity-20261118", "subs-bot-cf-backup-permission-20261118"}
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z")


def guard(env):
    sha, name = env.get("GITHUB_SHA", ""), env.get("FIXTURE_NAME", "")
    require(env.get("GITHUB_REPOSITORY") == github.REPOSITORY
            and env.get("GITHUB_REPOSITORY_ID") == str(github.REPOSITORY_ID)
            and env.get("GITHUB_REF") == github.MAIN_REF and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
            and env.get("GITHUB_WORKFLOW_REF") == github.REPOSITORY + "/.github/workflows/worker-backup-fixture-create.yml@refs/heads/main"
            and env.get("GITHUB_WORKFLOW_SHA") == sha and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("FIXTURE_ENVIRONMENT") == "subs-bot-backup-head-isolation"
            and re.fullmatch(r"[a-f0-9]{40}", sha or "") and env.get("FIXTURE_MAIN_SHA") == sha
            and env.get("FIXTURE_CREATE_ENABLED") == "true" and name in NAMES
            and re.fullmatch(r"[1-9][0-9]{0,19}", env.get("GITHUB_RUN_ID", "")))
    ref = github._get_json("/git/ref/heads/main", env.get("GH_TOKEN", ""))
    require(ref.get("ref") == github.MAIN_REF and ref.get("object", {}).get("sha") == sha)
    return name


def store():
    token = scoped_r2.metadata_token()
    require(bool(token))
    api = CloudflareClient(token)
    base = "/accounts/" + ACCOUNT + "/r2/buckets/" + BUCKET
    bucket = api("GET", base)
    require(isinstance(bucket, dict) and bucket.get("name") == BUCKET
            and bucket.get("creation_date") == CREATED and bucket.get("jurisdiction") == "default")
    require(api("GET", base + "/domains/managed").get("enabled") is False
            and api("GET", base + "/domains/custom") in ([], {"domains": []}))
    verify_lifecycle(api("GET", base + "/lifecycle"), PREFIX)
    objects = scoped_r2.from_environment(ACCOUNT, BUCKET)
    require(objects is not None)
    return objects


def inventory(token, name):
    require(name in NAMES)
    path = "/accounts/" + ACCOUNT + "/d1/database?" + urlencode({"name": name, "per_page": 100})
    request = Request(API_ORIGIN + path, headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
    with build_opener(ProxyHandler({}), _NoRedirect()).open(request, timeout=30) as response:
        raw = response.read(1024 * 1024 + 1)
    require(len(raw) <= 1024 * 1024)
    result = json.loads(raw)
    require(isinstance(result, dict) and result.get("success") is True and isinstance(result.get("result"), list)
            and len(result["result"]) < 100 and isinstance(result.get("result_info"), dict))
    info = result["result_info"]
    require(type(info.get("count")) is int and type(info.get("page")) is int
            and type(info.get("per_page")) is int and type(info.get("total_count")) is int
            and info["count"] == info["total_count"] == len(result["result"])
            and info["page"] == 1 and info["per_page"] == 100
            and info.get("total_pages", 1) in (0, 1) and not info.get("cursor")
            and not info.get("next_page_token") and info.get("is_truncated") in (None, False))
    rows = [row for row in result["result"] if isinstance(row, dict) and row.get("name") == name]
    require(len(rows) <= 1)
    return rows


def identity(value, name):
    require(isinstance(value, dict) and value.get("name") == name and UUID.fullmatch(value.get("uuid", ""))
            and STAMP.fullmatch(value.get("created_at", "")))
    return {"id": value["uuid"], "name": name, "createdAt": value["created_at"]}


def create(env):
    name = guard(env)
    reader, writer = env.get("FIXTURE_D1_READ_TOKEN", ""), env.get("FIXTURE_D1_WRITE_TOKEN", "")
    require(reader and writer and reader != writer)
    objects = store()
    base = PREFIX + name + "/"
    require(not objects.list(base, maximum=10) and not inventory(reader, name),
            "The exact name or immutable intent already exists; stop for independent investigation.")
    intent = {"version": 1, "accountId": ACCOUNT, "name": name, "runId": env["GITHUB_RUN_ID"],
              "runAttempt": "1", "controllerRevision": env["GITHUB_SHA"], "kind": "isolated-d1-create"}
    raw = canonical(intent)
    objects.put_once(base + "intent.json", raw)
    require(objects.get(base + "intent.json")[0] == raw)
    guard(env)
    require(not inventory(reader, name), "The exact name appeared after intent; do not create.")
    # Exactly one POST. Any error, lost response, or later failure remains unknown.
    created = CloudflareClient(writer)("POST", "/accounts/" + ACCOUNT + "/d1/database",
                                        {"name": name, "read_replication": {"mode": "disabled"}})
    result = identity(created, name)
    observed = CloudflareClient(reader)("GET", "/accounts/" + ACCOUNT + "/d1/database/" + result["id"])
    rows = inventory(reader, name)
    require(identity(observed, name) == result and len(rows) == 1 and rows[0].get("uuid") == result["id"])
    receipt = {"version": 1, "intentSha256": sha256(raw).hexdigest(), "resource": result}
    objects.put_once(base + "receipt.json", canonical(receipt))
    return {"status": "created-awaiting-independent-readback", "name": name}


def readback(env):
    name = guard(env)
    objects, base = store(), PREFIX + name + "/"
    raw, _ = objects.get(base + "intent.json")
    saved, _ = objects.get(base + "receipt.json")
    intent, receipt = parsed(raw), parsed(saved)
    require(canonical(intent) == raw and canonical(receipt) == saved
            and intent == {"version": 1, "accountId": ACCOUNT, "name": name, "runId": env["GITHUB_RUN_ID"],
                           "runAttempt": "1", "controllerRevision": env["GITHUB_SHA"], "kind": "isolated-d1-create"}
            and set(receipt) == {"version", "intentSha256", "resource"} and receipt["version"] == 1
            and receipt["intentSha256"] == sha256(raw).hexdigest())
    resource = receipt["resource"]
    require(isinstance(resource, dict) and set(resource) == {"id", "name", "createdAt"}
            and UUID.fullmatch(resource.get("id", "")) and resource.get("name") == name
            and STAMP.fullmatch(resource.get("createdAt", "")))
    reader = env.get("FIXTURE_D1_READ_TOKEN", "")
    require(reader)
    result = CloudflareClient(reader)("GET", "/accounts/" + ACCOUNT + "/d1/database/" + resource["id"])
    rows = inventory(reader, name)
    require(identity(result, name) == resource and len(rows) == 1 and rows[0].get("uuid") == resource["id"])
    proof = {"version": 1, "kind": "isolated-d1-independent-readback", "runId": env["GITHUB_RUN_ID"],
             "runAttempt": "1", "controllerRevision": env["GITHUB_SHA"],
             "receiptSha256": sha256(saved).hexdigest(), "resource": resource,
             "workerBindings": "not-yet-inventoried"}
    objects.put_once(base + "readback.json", canonical(proof))
    require(objects.get(base + "readback.json")[0] == canonical(proof))
    return {"status": "independently-read-back", "name": name,
            "receiptSha256": sha256(saved).hexdigest(), "readbackSha256": sha256(canonical(proof)).hexdigest(),
            "workerBindings": "not-yet-inventoried"}


if __name__ == "__main__":
    try:
        mode = os.environ.get("FIXTURE_ACTION", "")
        require(mode in {"guard", "create", "readback"})
        result = {"status": "guarded"} if mode == "guard" and guard(os.environ) else (create(os.environ) if mode == "create" else readback(os.environ))
        print(json.dumps(result, sort_keys=True))
    except Exception:
        print("::error::Fixture creation or readback is unconfirmed. Preserve any intent; do not retry the POST.")
        raise SystemExit(1) from None

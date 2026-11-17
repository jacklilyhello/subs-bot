"""Exact D1 capacity-boundary fixture for a separately registered empty database.

The trusted hosted entry point supplies a fixture-only API and immutable private
intent store. No method creates, removes, resets or adopts a database. A failed
or ambiguous seed write must be investigated, never repeated automatically.
"""
from hashlib import sha256
import re

import production_backup_capacity as capacity
import native_restore_rehearsal as native
from production_target import ACCOUNT, canonical, require

TARGETS = (16000, 20000, 20001)
PREFIX = "maintenance/production-control/evidence/capacity-fixture/"


def validate_registration(registration, expected_sha256, witness, witness_sha256, *, now, excluded_database_ids):
    """Require independent pins for the dedicated D1 and its binding inventory."""
    require(isinstance(registration, dict) and set(registration) == {"version", "accountId", "databaseId", "databaseName", "createdAt", "bucketName", "bucketCreatedAt"}
            and type(registration["version"]) is int and registration["version"] == 1
            and registration["accountId"] == ACCOUNT
            and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", registration["databaseId"] or "")
            and re.fullmatch(r"subs-bot-capacity-fixture-[a-z0-9-]{1,24}", registration["databaseName"] or "")
            and re.fullmatch(r"subs-bot-capacity-fixture-[a-z0-9-]{1,24}", registration["bucketName"] or "")
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", registration["createdAt"] or "")
            and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z", registration["bucketCreatedAt"] or "")
            and registration["databaseId"] not in excluded_database_ids
            and re.fullmatch(r"[a-f0-9]{64}", expected_sha256 or "")
            and sha256(canonical(registration)).hexdigest() == expected_sha256)
    require(isinstance(witness, dict) and set(witness) == {"version", "accountId", "databaseId", "observedAt", "workerBindingCount"}
            and type(witness["version"]) is int and witness["version"] == 1 and witness["accountId"] == ACCOUNT
            and witness["databaseId"] == registration["databaseId"] and type(witness["observedAt"]) is int
            and type(now) is int and 0 <= now - witness["observedAt"] <= 900
            and type(witness["workerBindingCount"]) is int and witness["workerBindingCount"] == 0
            and re.fullmatch(r"[a-f0-9]{64}", witness_sha256 or "")
            and sha256(canonical(witness)).hexdigest() == witness_sha256,
            "The independent, recent no-binding proof is missing or differs.")
    return expected_sha256


def seed_plan(*, target_sha256, database_id, counts, desired):
    require(re.fullmatch(r"[a-f0-9]{64}", target_sha256 or "")
            and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", database_id or "")
            and type(desired) is int and desired in TARGETS and isinstance(counts, dict)
            and counts and all(isinstance(k, str) and re.fullmatch(r"[a-z][a-z0-9_]*", k)
                               and type(v) is int and v >= 0 for k, v in counts.items())
            and "subs_bot_production_invocations" in counts)
    total = sum(counts.values())
    require(total < desired, "The fixture is already at or beyond this target; do not reseed it.")
    return {"version": 1, "targetSha256": target_sha256, "databaseId": database_id,
            "beforeRows": total, "afterRows": desired, "seedRows": desired - total,
            "beforeInvocationRows": counts["subs_bot_production_invocations"],
            "countsSha256": sha256(canonical(counts)).hexdigest()}


def seed_sql(plan, counts):
    require(plan == seed_plan(target_sha256=plan.get("targetSha256"), database_id=plan.get("databaseId"),
                              counts=counts, desired=plan.get("afterRows")))
    # Exact per-table predicates are evaluated in the same D1 statement as the
    # insert, so a concurrent change fails the entire transaction.
    checks = " AND ".join(f'(SELECT count(*) FROM "{name}")={count}' for name, count in sorted(counts.items()))
    start, end = plan["beforeInvocationRows"] + 1, plan["beforeInvocationRows"] + plan["seedRows"]
    return (f"WITH RECURSIVE guard(ok) AS MATERIALIZED (SELECT CASE WHEN {checks} THEN 1 "
            "ELSE json_extract('fixture guard failed','$') END), "
            f"seq(n) AS (SELECT {start} UNION ALL SELECT n+1 FROM seq WHERE n<{end}) "
            "INSERT INTO subs_bot_production_invocations "
            "(invocation_id,target_sha256,bot_id,epoch,kind,started_at,lease_until,state,finished_at) "
            f"SELECT printf('%032x',n), '{plan['targetSha256']}','capacity-fixture',1,'scheduled',1,1,'finished',1 "
            "FROM seq,guard WHERE guard.ok=1")


def seed_once(api, store, source, *, target_sha256, database_id, desired, now, run_id, guard,
              controller_revision, dispatcher_revision):
    require(re.fullmatch(r"[1-9][0-9]{0,19}", run_id or "") and type(now) is int and now > 0)
    require(re.fullmatch(r"[a-f0-9]{40}", controller_revision or "")
            and re.fullmatch(r"[a-f0-9]{40}", dispatcher_revision or ""))
    guard()
    api.verify_identity()
    observed = capacity.observe(api, source)
    require(isinstance(observed.get("tableCounts"), dict) and observed.get("rowStatus") in {"normal", "warning"}
            and observed.get("objectStatus") in {"normal", "warning"}
            and observed.get("objectBytesStatus") in {"normal", "warning"})
    counts = observed["tableCounts"]
    require(counts.get("subs_bot_schema_migrations") == len(source.migrations)
            and all(count == 0 for table, count in counts.items()
                    if table not in {"subs_bot_schema_migrations", "subs_bot_production_invocations"}),
            "The dedicated fixture contains unexpected non-fixture records.")
    plan = seed_plan(target_sha256=target_sha256, database_id=database_id, counts=counts, desired=desired)
    require(api.fixture_rows_verified(counts["subs_bot_production_invocations"], target_sha256) is True,
            "The dedicated fixture contains unexpected invocation records.")
    sql = seed_sql(plan, counts)
    intent = {"version": 1, "kind": "capacity-fixture-seed", "plan": plan, "statementSha256": sha256(sql.encode()).hexdigest(),
              "runId": run_id, "runAttempt": "1", "controllerRevision": controller_revision,
              "dispatcherRevision": dispatcher_revision, "timestamp": now}
    key = PREFIX + target_sha256 + "/" + str(desired) + "/intent.json"
    require(store.get(key, absent=True) is None, "A fixture seed intent exists; independently inspect it without retrying.")
    store.put_once(key, canonical(intent))
    require(store.get(key) == canonical(intent))
    # One D1 write. The API must be restricted to this exact registered D1 and
    # must never retry a transport or timeout failure.
    api.seed_statement_sha256 = intent["statementSha256"]
    guard()
    api.verify_identity()
    api.seed_fixture(sql)
    guard()
    api.verify_identity()
    after = capacity.observe(api, source)
    expected_counts = {**counts, "subs_bot_production_invocations":
                       counts["subs_bot_production_invocations"] + plan["seedRows"]}
    require(after.get("rows") == desired and after.get("tableCounts") == expected_counts
            and api.fixture_rows_verified(expected_counts["subs_bot_production_invocations"], target_sha256) is True
            and after.get("rowStatus") == ("over-limit" if desired > 20000 else "warning"))
    if desired > 20000:
        require(after.get("objectStatus") == "not-checked")
        try:
            capacity.require_within_limits(after)
        except native.RehearsalError:
            pass
        else:
            require(False, "The over-limit fixture did not fail the shared pre-pause gate.")
    else:
        capacity.require_within_limits(after)
    result = {"version": 1, "rows": desired, "rowStatus": after["rowStatus"],
            "objectStatus": after["objectStatus"], "prePauseRejected": desired > 20000,
            "fixtureOnly": True, "pausePerformed": False, "intentSha256": sha256(canonical(intent)).hexdigest()}
    receipt = {**result, "targetSha256": target_sha256, "runId": run_id, "runAttempt": "1",
               "controllerRevision": controller_revision, "dispatcherRevision": dispatcher_revision,
               "countsSha256": sha256(canonical(expected_counts)).hexdigest()}
    receipt_key = PREFIX + target_sha256 + "/" + str(desired) + "/receipt.json"
    store.put_once(receipt_key, canonical(receipt))
    require(store.get(receipt_key) == canonical(receipt))
    return {**result, "receiptSha256": sha256(canonical(receipt)).hexdigest()}


def verify_seed(api, store, source, *, target_sha256, desired, controller_revision, dispatcher_revision, guard):
    """Independent readback binds the saved receipt to the original hosted run."""
    import prepare_isolation_artifact as github
    require(re.fullmatch(r"[a-f0-9]{64}", target_sha256 or "") and desired in TARGETS
            and re.fullmatch(r"[a-f0-9]{40}", controller_revision or "")
            and re.fullmatch(r"[a-f0-9]{40}", dispatcher_revision or ""))
    base = PREFIX + target_sha256 + "/" + str(desired) + "/"
    raw_intent, raw_receipt = store.get(base + "intent.json"), store.get(base + "receipt.json")
    require(isinstance(raw_intent, bytes) and isinstance(raw_receipt, bytes))
    intent, saved = native.parsed(raw_intent, 32768), native.parsed(raw_receipt, 32768)
    require(canonical(intent) == raw_intent and canonical(saved) == raw_receipt
            and intent.get("kind") == "capacity-fixture-seed" and intent.get("plan", {}).get("targetSha256") == target_sha256
            and intent["plan"].get("afterRows") == desired and saved.get("intentSha256") == sha256(raw_intent).hexdigest()
            and saved.get("targetSha256") == target_sha256 and saved.get("runId") == intent.get("runId")
            and saved.get("runAttempt") == intent.get("runAttempt") == "1"
            and re.fullmatch(r"[1-9][0-9]{0,19}", intent.get("runId", ""))
            and saved.get("controllerRevision") == intent.get("controllerRevision") == controller_revision
            and saved.get("dispatcherRevision") == intent.get("dispatcherRevision") == dispatcher_revision)
    token = github._github_token()
    run = github._get_json("/actions/runs/" + intent["runId"] + "/attempts/1", token)
    workflow = github._get_json("/actions/workflows/worker-backup-reviewed-head.yml", token)
    require(str(run.get("id")) == intent["runId"] and run.get("run_attempt") == 1
            and run.get("workflow_id") == workflow.get("id") and workflow.get("path") == ".github/workflows/worker-backup-reviewed-head.yml"
            and run.get("head_sha") == dispatcher_revision and run.get("head_branch") == "main"
            and run.get("event") == "workflow_dispatch" and (run.get("status"), run.get("conclusion")) == ("completed", "success")
            and all(isinstance(run.get(key), dict) and run[key].get("id") == github.REPOSITORY_ID
                    for key in ("repository", "head_repository")))
    response = github._get_json("/actions/runs/" + intent["runId"] + "/attempts/1/jobs?per_page=100", token)
    jobs = response.get("jobs")
    require(isinstance(jobs, list) and type(response.get("total_count")) is int
            and response["total_count"] == len(jobs) < 100)
    matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == "validate"]
    require(len(matches) == 1)
    job = matches[0]
    require(str(job.get("run_id")) == intent["runId"] and job.get("run_attempt") == 1
            and job.get("head_sha") == dispatcher_revision and (job.get("status"), job.get("conclusion")) == ("completed", "success")
            and isinstance(job.get("steps"), list))
    for name in ("Verify the exact independently reviewed head before checkout",
                 "Independently recheck trusted main and candidate checkout",
                 "Confirm only the authorized isolated test identity",
                 "Run the reviewed candidate against only dedicated isolation"):
        steps = [step for step in job["steps"] if isinstance(step, dict) and step.get("name") == name]
        require(len(steps) == 1 and (steps[0].get("status"), steps[0].get("conclusion")) == ("completed", "success"))
    guard()
    api.verify_identity()
    observed = capacity.observe(api, source)
    counts = observed.get("tableCounts")
    require(isinstance(counts, dict) and observed.get("rows") == desired
            and sha256(canonical(counts)).hexdigest() == saved.get("countsSha256")
            and api.fixture_rows_verified(counts.get("subs_bot_production_invocations"), target_sha256) is True
            and observed.get("rowStatus") == saved.get("rowStatus") and observed.get("objectStatus") == saved.get("objectStatus"))
    if desired > 20000:
        try:
            capacity.require_within_limits(observed)
        except native.RehearsalError:
            pass
        else:
            require(False, "The independently observed over-limit database did not fail the pre-pause gate.")
    else:
        capacity.require_within_limits(observed)
    return {"version": 1, "rows": desired, "rowStatus": observed["rowStatus"], "objectStatus": observed["objectStatus"],
            "prePauseRejected": desired > 20000, "fixtureOnly": True, "pausePerformed": False,
            "receiptSha256": sha256(raw_receipt).hexdigest(), "independentReadback": True}


class FixtureAPI:
    """Fixed D1 identity and a single preplanned INSERT; no Worker API routes."""
    def __init__(self, registration, token):
        from cloudflare_isolation import CloudflareClient
        self.registration = registration
        self.target = {"d1Id": registration["databaseId"], "bucketName": registration["bucketName"]}
        self.root = "/accounts/" + registration["accountId"]
        self.path = self.root + "/d1/database/" + registration["databaseId"]
        self.databases = {registration["databaseId"]}
        self.client = CloudflareClient(token)
        self.seed_statement_sha256 = None
        self.migration_statement_sha256 = None

    def __call__(self, method, path, payload=None):
        if method == "GET":
            require(path == self.path and payload is None)
        else:
            require(method == "POST" and path == self.path + "/query" and isinstance(payload, dict)
                    and set(payload) in ({"sql"}, {"sql", "params"}))
            sql = payload["sql"]
            readonly = native.readonly_sql(sql) or native.readonly_sql(sql, schema_check=True) \
                       or native.readonly_schema_batch(sql) is not None
            if not readonly:
                require(self.migration_statement_sha256 == sha256(sql.encode()).hexdigest(),
                        "The fixture rejected an unapproved schema mutation.")
                self.migration_statement_sha256 = None
        return self.client(method, path, payload)

    def rows(self, database_id, sql, parameters=()):
        require(database_id == self.registration["databaseId"])
        result = self("POST", self.path + "/query", {"sql": sql, "params": [str(value) for value in parameters]})
        require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True
                and isinstance(result[0].get("results"), list))
        return result[0]["results"]

    def verify_identity(self):
        value = self("GET", self.path)
        require(isinstance(value, dict) and value.get("uuid") == self.registration["databaseId"]
                and value.get("name") == self.registration["databaseName"]
                and value.get("created_at") == self.registration["createdAt"],
                "The independently registered fixture database differs.")

    def fixture_rows_verified(self, count, target_sha256):
        require(type(count) is int and count >= 0 and re.fullmatch(r"[a-f0-9]{64}", target_sha256 or ""))
        sql = ("SELECT count(*) AS n FROM subs_bot_production_invocations WHERE "
               f"target_sha256='{target_sha256}' AND bot_id='capacity-fixture' AND epoch=1 AND kind='scheduled' "
               "AND started_at=1 AND lease_until=1 AND state='finished' AND finished_at=1 "
               "AND length(invocation_id)=32 AND invocation_id NOT GLOB '*[^0-9a-f]*'")
        return self.rows(self.registration["databaseId"], sql) == [{"n": count}]

    def seed_fixture(self, sql):
        require(isinstance(sql, str) and self.seed_statement_sha256 == sha256(sql.encode()).hexdigest())
        # Bypass the read-only wrapper for exactly the previously approved SQL.
        # CloudflareClient makes one request; no transport retry is permitted.
        self.seed_statement_sha256 = None
        result = self.client("POST", self.path + "/query", {"sql": sql})
        require(isinstance(result, list) and len(result) == 1 and result[0].get("success") is True)


class FixtureSource:
    def __init__(self, api, bundle, manifest):
        import d1_migrations as migrations
        self.api, self.migrations = api, migrations._load_migrations(bundle, manifest)
        self.tables = sorted(obj.name for obj in migrations._objects(self.migrations, len(self.migrations), managed=True)
                             if obj.type == "table")

    def schema(self):
        import d1_migrations as migrations
        kind, history = migrations._read_state(self.api, self.api.path, self.migrations)
        require(kind == "managed" and len(history) == len(self.migrations), "Fixture schema does not match the exact release.")


def initialize_schema_once(api, store, source, *, target_sha256, run_id, guard):
    """Apply the exact migration chain to a freshly registered, empty fixture."""
    import d1_migrations as migrations
    require(re.fullmatch(r"[a-f0-9]{64}", target_sha256 or "") and re.fullmatch(r"[1-9][0-9]{0,19}", run_id or ""))
    api.verify_identity()
    kind, history = migrations._read_state(api, api.path, source.migrations)
    require(kind == "fresh" and not history, "A nonempty or interrupted fixture schema requires independent inspection.")
    while len(history) < len(source.migrations):
        statements, expected = migrations._plan_one(source.migrations, kind, history)
        sql = ";\n".join(statements) + ";"
        ordinal = len(history) + 1
        intent = {"version": 1, "kind": "capacity-fixture-migration", "targetSha256": target_sha256,
                  "runId": run_id, "runAttempt": "1", "position": ordinal,
                  "migrationSha256": source.migrations[ordinal - 1].sha256, "statementSha256": sha256(sql.encode()).hexdigest()}
        key = PREFIX + target_sha256 + "/schema/" + str(ordinal).zfill(4) + ".json"
        require(store.get(key, absent=True) is None, "A prior fixture migration intent exists; do not replay it.")
        store.put_once(key, canonical(intent))
        require(store.get(key) == canonical(intent))
        guard()
        api.verify_identity()
        api.migration_statement_sha256 = intent["statementSha256"]
        history = migrations._apply_one(api, api.path, source.migrations, kind, history, guard)
        require(history == expected)
        kind = "managed"
    source.schema()
    return {"schemaVerified": True, "migrationCount": len(history), "fixtureOnly": True}

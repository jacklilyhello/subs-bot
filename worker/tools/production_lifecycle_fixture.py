"""A bounded CI-only subscription fixture on the dedicated frozen rehearsal target.

This is not initialization or a migration. It does not copy any isolation data,
replace existing rows, or write to a production resource. Only the exact two
objects already declared by the verified CI small fixture can be published.
"""
from hashlib import sha256
from pathlib import Path

import d1_migrations as migrations
import native_restore_rehearsal as native
from production_control import _mutate_sql, rows
from production_recovery import RecoveryAPI
from production_target import canonical, digest, require

SERVICE = "subs-bot-cf-control-drill-01"
SMALL_TOKEN = "subsbot-synthetic-small-01"
SNAPSHOT = "11111111-1111-4111-8111-111111111111"
REVOKED_ID = 999_000_001
REVOKED_TOKEN = "subsbot-synthetic-control-revoked-01"


def seed_fixture(controller, bundle, manifest, data_token):
    target = controller.target
    require(target.environment == "rehearsal" and target.data["workerName"] == target.data["bucketName"] == SERVICE,
            "Synthetic fixture writes are restricted to the registered dedicated rehearsal target.")
    bundle = Path(bundle).resolve(strict=True)
    require(manifest.get("revision") == controller.revision and isinstance(manifest.get("snapshots"), list) and manifest["snapshots"])
    snapshot = manifest["snapshots"][0]
    require(snapshot.get("id") == 1 and snapshot.get("token") == SMALL_TOKEN and snapshot.get("snapshotId") == SNAPSHOT
            and snapshot.get("nodeCount") == 3 and isinstance(snapshot.get("objects"), list) and len(snapshot["objects"]) == 2,
            "Only the exact three-node CI small fixture is supported.")
    expected_keys = {"subscriptions/1/" + SNAPSHOT + "/0.ndjson", "subscriptions/1/" + SNAPSHOT + "/manifest.json"}
    require({entry.get("key") for entry in snapshot["objects"]} == expected_keys)
    objects = []
    for entry in snapshot["objects"]:
        require(set(entry) == {"key", "file", "bytes", "sha256"} and entry["file"] == "r2/" + entry["key"])
        path = bundle / entry["file"]
        require(path.is_file() and not path.is_symlink() and path.resolve(strict=True).is_relative_to(bundle))
        body = path.read_bytes()
        require(0 < len(body) <= 64 * 1024 and len(body) == entry["bytes"] and sha256(body).hexdigest() == entry["sha256"])
        objects.append((entry, body))
    owner = target.data["admins"][0]
    subscription = {"id": 1, "owner_id": owner, "name": "Lifecycle control synthetic three-node fixture",
        "source_url": "https://fixture.invalid/lifecycle-control/synthetic-small", "token": SMALL_TOKEN,
        "expire_at": None, "traffic_used": None, "traffic_total": None, "last_error": None,
        "created_at": 1, "updated_at": 1, "generation": 1, "snapshot_id": SNAPSHOT,
        "manifest_sha256": snapshot["manifestSha256"], "node_count": 3}
    trashed = {"id": REVOKED_ID, "owner_id": owner, "name": "Lifecycle control revoked synthetic fixture",
        "source_url": "https://fixture.invalid/lifecycle-control/revoked", "token": REVOKED_TOKEN,
        "expire_at": None, "traffic_used": None, "traffic_total": None, "last_error": None,
        "created_at": 1, "updated_at": 1, "generation": 0, "snapshot_id": None,
        "manifest_sha256": None, "node_count": 0, "deleted_at": 1, "lifecycle_revision": 1}
    before = controller.inspect()

    def frozen():
        controller.guard()
        state = controller.inspect()
        require(state["control"] == before["control"] and state["control"]["admission"] == "closed"
                and state["control"]["workers"] == "frozen" and not any(state["work"].values())
                and not any(state["terminal"].get(key, 0) for key in ("uncertain", "terminalUnknown", "unknownInvocations", "unknownUpdates")),
                "Close, reconcile and freeze the dedicated target before publishing a synthetic fixture.")
        return state

    frozen()
    current = rows(controller.data, controller.database, "SELECT * FROM subscriptions WHERE id=1")
    life = rows(controller.data, controller.database, "SELECT * FROM subscription_lifecycle WHERE subscription_id=1")
    revoked_life = rows(controller.data, controller.database,
        f"SELECT * FROM subscription_lifecycle WHERE subscription_id={REVOKED_ID}")
    trash = rows(controller.data, controller.database, f"SELECT * FROM subscription_trash WHERE id={REVOKED_ID}")
    repeated = bool(current or life or revoked_life or trash)
    require((current == [subscription] and life == [{"subscription_id": 1, "revision": 1}]
             and revoked_life == [{"subscription_id": REVOKED_ID, "revision": 1}] and trash == [trashed])
            or (not current and not life and not revoked_life and not trash),
            "The fixture IDs are occupied by different or partial business data.")
    require(not rows(controller.data, controller.database, "SELECT id FROM subscription_trash WHERE id=1")
            and not rows(controller.data, controller.database, f"SELECT id FROM subscriptions WHERE id={REVOKED_ID}"))
    checkpoint = digest({"kind": "lifecycle-ci-fixture", "target": target.digest})[:32]
    unused = "subs-bot-cf-restore-control-" + checkpoint[:16]
    writer = RecoveryAPI(target.data, data_token, controller.worker,
        {"version": 1, "checkpointId": checkpoint, "databaseName": unused, "objectsName": unused, "purpose": "baseline"})
    metadata = {"custom": {}, "http": {}}
    for entry, body in objects:
        frozen()
        existing, _ = writer.object_or_none(SERVICE, entry["key"])
        if existing is None:
            # The recovery writer's conditional transport is reused; the fixture
            # allowlist above is the only source of bucket/key/bytes for this call.
            writer._conditional_put(SERVICE, entry["key"], body, metadata)
        else:
            require(existing == body, "A fixture object is occupied by different bytes; it was not overwritten.")
        observed, _ = writer.object_or_none(SERVICE, entry["key"])
        require(observed == body, "Independent fixture object readback differs.")
        listing = writer.list_objects(SERVICE, prefix=entry["key"], maximum=3)
        exact = [row for row in listing if row.get("key") == entry["key"]]
        require(len(exact) == 1 and exact[0].get("size") == len(body) and native.listed_metadata(exact[0]) == metadata,
                "Fixture object size or metadata differs.")
    frozen()
    if not repeated:
        def scalar(value):
            return "NULL" if value is None else migrations._literal(value) if isinstance(value, str) else str(value)
        control = before["control"]
        exact_control = " AND ".join(key + " IS " + scalar(value) for key, value in control.items())
        conditions = ["EXISTS(SELECT 1 FROM subs_bot_production_control WHERE " + exact_control + ")",
            "NOT EXISTS(SELECT 1 FROM subs_bot_production_invocations WHERE state='running')",
            "NOT EXISTS(SELECT 1 FROM subs_bot_production_updates WHERE state='processing')",
            "NOT EXISTS(SELECT 1 FROM subscriptions WHERE id IN (1," + str(REVOKED_ID) + "))",
            "NOT EXISTS(SELECT 1 FROM subscription_trash WHERE id IN (1," + str(REVOKED_ID) + "))",
            "NOT EXISTS(SELECT 1 FROM subscription_lifecycle WHERE subscription_id IN (1," + str(REVOKED_ID) + "))"]
        def insert(table, row):
            return "INSERT INTO " + table + "(" + ",".join(row) + ") VALUES(" + ",".join(scalar(value) for value in row.values()) + ")"
        _mutate_sql(controller.data, controller.database, [migrations._assert_sql(" AND ".join(conditions)),
            insert("subscriptions", subscription), f"INSERT INTO subscription_lifecycle VALUES(1,1),({REVOKED_ID},1)",
            insert("subscription_trash", trashed)])
    require(rows(controller.data, controller.database, "SELECT * FROM subscriptions WHERE id=1") == [subscription]
            and rows(controller.data, controller.database, "SELECT * FROM subscription_lifecycle WHERE subscription_id=1") == [{"subscription_id": 1, "revision": 1}]
            and rows(controller.data, controller.database,
                f"SELECT * FROM subscription_lifecycle WHERE subscription_id={REVOKED_ID}") == [{"subscription_id": REVOKED_ID, "revision": 1}]
            and rows(controller.data, controller.database, f"SELECT * FROM subscription_trash WHERE id={REVOKED_ID}") == [trashed])
    return {"syntheticOnly": True, "humanAcceptance": False, "repeated": repeated, "nodeCount": 3,
        "referencedObjectCount": 2, "manifestSha256": snapshot["manifestSha256"],
        "fixtureDataSha256": digest({"subscription": subscription, "trash": trashed,
            "lifecycle": [{"subscription_id": 1, "revision": 1}, {"subscription_id": REVOKED_ID, "revision": 1}]}),
        "positiveExportFixture": True, "revokedTokenFixture": True}

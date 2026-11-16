"""Read-only private release loading and full activation-baseline verification.

Source Actions artifacts are never consulted. The current control workflow must
still verify its own main revision and authorization before calling these
helpers. Private configuration, SQL and archive bytes are returned only to the
caller; the activation result is a public-safe digest/count projection.
"""

from contextlib import closing
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace

import d1_migrations as migrations
import native_restore_rehearsal as native
import prepare_isolation_artifact as artifact
import production_recovery as recovery
from production_target import Target, validate_target


require = recovery.require
ERROR = "The private production release or activation baseline was not verified."


class ReadOnlyRecoveryAPI(recovery.RecoveryAPI):
    """Use the target-aware recovery reader without any creation/write path."""

    def json(self, method, path, payload=None, *, envelope=False):
        require(method == "GET" or method == "POST" and path == self.source + "/query",
                "The release-evidence reader rejects all cloud mutation routes.")
        return super().json(method, path, payload, envelope=envelope)

    def r2(self, method, bucket, key, body=None):
        require(method == "GET" and body is None, "The release-evidence reader never writes R2.")
        return super().r2(method, bucket, key)

    def _conditional_put(self, *_args, **_kwargs):
        raise recovery.RecoveryError(ERROR)

    def allow_restore(self, *_args, **_kwargs):
        raise recovery.RecoveryError(ERROR)


def _no_worker_api(*_args, **_kwargs):
    raise recovery.RecoveryError("Release evidence loading does not discover or mutate Workers.")


def _target(value):
    return validate_target(value.data if isinstance(value, Target) else value)


def _reader(target, data_token, checkpoint_id):
    require(recovery.matches(recovery.CHECKPOINT, checkpoint_id), "An explicit checkpoint ID is required.")
    # RecoveryAPI requires inert destination intentions even when used only as a
    # reader. No inventory, creation, registration or target adoption is made.
    name = "subs-bot-cf-restore-evidence-" + checkpoint_id[:16]
    contract = {"version": 1, "checkpointId": checkpoint_id, "databaseName": name, "objectsName": name,
                "purpose": "baseline"}
    return ReadOnlyRecoveryAPI(target.data, data_token, _no_worker_api, contract)


def _observed(state):
    require(isinstance(state, dict))
    result = {key: state.get(key) for key in ("release", "targetSha256", "control", "work", "terminal")}
    require(isinstance(result["release"], dict) and isinstance(result["control"], dict)
            and isinstance(result["work"], dict) and isinstance(result["terminal"], dict))
    control, work = result["control"], result["work"]
    require(control.get("admission") == "closed" and control.get("workers") == "frozen"
            and recovery.integer(control.get("epoch"), 1) and recovery.integer(control.get("generation"), 1)
            and type(control.get("singleton")) is int and control["singleton"] == 1 and "invocations" in work
            and all(type(value) is int and value == 0 for value in work.values()),
            "A baseline requires closed admission, frozen workers and no unfinished work.")
    return result


def _load_release(target, api, checkpoint_id, manifest_sha256, directory):
    require(recovery.matches(recovery.CHECKPOINT, checkpoint_id)
            and recovery.matches(recovery.DIGEST, manifest_sha256), "Exact checkpoint and manifest pins are required.")
    api.verify_backup()
    prefix = "production/checkpoints/" + checkpoint_id + "/"
    raw, _etag = api.object_or_none(target.data["backupBucketName"], prefix + "manifest.json")
    require(isinstance(raw, bytes) and recovery.digest(raw) == manifest_sha256,
            "The private checkpoint manifest differs from its independently supplied pin.")
    document = native.parsed(raw, native.MANIFEST_BYTES)
    require(native.canonical(document) == raw and type(document.get("version")) is int and document["version"] == 2)
    pin = document.get("sourcePin")
    require(isinstance(pin, dict) and type(pin.get("version")) is int and pin["version"] == 1
            and pin.get("scopeSha256") == target.digest and isinstance(pin.get("configuration"), dict)
            and recovery.matches(recovery.DIGEST, pin.get("configurationSha256"))
            and recovery.matches(recovery.REVISION, pin.get("revision"))
            and recovery.matches(recovery.DIGEST, pin.get("moduleSha256"))
            and recovery.matches(recovery.DIGEST, pin.get("schemaSha256")))
    source_target = _target(pin["configuration"])
    require(source_target.digest == target.digest
            and source_target.configuration_digest == pin["configurationSha256"],
            "The private release's immutable ownership or complete configuration differs.")
    observed = _observed(pin.get("observed"))
    require(observed["targetSha256"] == target.digest
            and observed["control"].get("target_sha256") == target.digest
            and observed["control"].get("bot_id") == source_target.data["botId"]
            and observed["control"].get("generation") == source_target.data["generation"]
            and observed["control"].get("release_revision") == pin["revision"]
            and observed["release"].get("revision") == pin["revision"]
            and observed["release"].get("moduleSha256") == pin["moduleSha256"]
            and observed["release"].get("compatibilityDate") == pin.get("compatibilityDate")
            and recovery.matches(recovery.UUID, observed["release"].get("versionId")))
    body, proof = recovery.load_code_archive(api, document, prefix)
    require(proof["revision"] == pin["revision"], "The archived CI source differs from the pinned release.")
    destination = Path(directory)
    require(destination.is_absolute() and destination.is_dir() and not destination.is_symlink()
            and destination.resolve() == destination, "A private absolute scratch directory is required.")
    artifact._unpack(body, proof["archiveSha256"], proof["revision"], proof["runId"], proof["runAttempt"], destination)
    bundle = destination / artifact.VERIFIED_DIRECTORY
    manifest = native.parsed((bundle / "isolation.json").read_bytes(), artifact._MAX_JSON)
    require(manifest.get("revision") == pin["revision"]
            and manifest.get("bundleSha256") == pin["moduleSha256"]
            and manifest.get("compatibilityDate") == pin.get("compatibilityDate"))
    chain = migrations._load_migrations(bundle, manifest)
    objects = migrations._objects(chain, len(chain), managed=True)
    schema_sha = native._schema_digest(objects)
    require(schema_sha == pin["schemaSha256"] == document.get("schemaSha256"),
            "Archived code migrations differ from the pinned source schema.")
    return {"body": body, "proof": proof, "document": document, "bundle": bundle, "manifest": manifest,
            "sourceTarget": source_target}


def load_release(target, data_token, checkpoint_id, manifest_sha256, directory):
    """Load exact private CI bytes/configuration without any source Actions lookup."""
    target = _target(target)
    require(recovery.matches(recovery.DIGEST, manifest_sha256), "An explicit manifest SHA-256 is required.")
    return _load_release(target, _reader(target, data_token, checkpoint_id), checkpoint_id, manifest_sha256, directory)


def _entries(document):
    entries = document.get("objects")
    require(isinstance(entries, list) and len(entries) <= native.MAX_OBJECTS)
    indexed, total = {}, 0
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {"key", "bytes", "sha256", "metadata"}
                and recovery.matches(native.KEY, entry["key"]) and entry["key"] not in indexed
                and recovery.integer(entry["bytes"], 1, native.OBJECT_BYTES)
                and recovery.matches(recovery.DIGEST, entry["sha256"]))
        native.validate_metadata(entry["metadata"])
        total += entry["bytes"]
        require(total <= native.TOTAL_OBJECT_BYTES)
        indexed[entry["key"]] = entry
    return indexed


def _source_object(api, target, key, entry):
    bucket = target.data["bucketName"]
    body, _etag = api.object_or_none(bucket, key)
    require(isinstance(body, bytes) and len(body) == entry["bytes"] and recovery.digest(body) == entry["sha256"],
            "Current R2 bytes differ from the sealed activation baseline.")
    listed = [row for row in api.list_objects(bucket, prefix=key, maximum=2) if row.get("key") == key]
    require(len(listed) == 1 and recovery.integer(listed[0].get("size"), 1, native.OBJECT_BYTES)
            and listed[0]["size"] == len(body))
    metadata = native.listed_metadata(listed[0])
    require(metadata == entry["metadata"], "Current R2 ownership metadata differs from the activation baseline.")
    return body, metadata


def verify_activation_baseline(controller, data_token, checkpoint_id, manifest_sha256):
    """Verify the whole current G0; never create a target or mutate a journal/source.

    Activation must transition directly from this frozen epoch. The controller
    must additionally keep its atomic predecessor fence and explicit approval.
    """
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted",
            "Activation-baseline scratch validation runs only on a GitHub-hosted runner.")
    target = _target(controller.target)
    require(recovery.matches(recovery.CHECKPOINT, checkpoint_id)
            and recovery.matches(recovery.DIGEST, manifest_sha256), "Activation requires explicit persistent baseline pins.")
    controller.guard()
    before = controller.inspect()
    observed = _observed(before)
    require(before.get("targetSha256") == target.digest
            and before.get("configurationSha256") == target.configuration_digest)
    root = Path(os.environ.get("RUNNER_TEMP", ""))
    require(root.is_absolute() and root.is_dir() and not root.is_symlink() and root.resolve() == root)
    api = _reader(target, data_token, checkpoint_id)
    with TemporaryDirectory(prefix="subs-bot-activation-baseline-", dir=root) as temporary:
        directory = Path(temporary)
        loaded = _load_release(target, api, checkpoint_id, manifest_sha256, directory)
        document, manifest, source_target = loaded["document"], loaded["manifest"], loaded["sourceTarget"]
        pin = document["sourcePin"]
        require(source_target.configuration_digest == target.configuration_digest
                and pin["configurationSha256"] == before["configurationSha256"]
                and pin["observed"] == observed,
                "The exact release, configuration or frozen control changed since baseline capture.")
        chain = migrations._load_migrations(loaded["bundle"], manifest)
        objects = migrations._objects(chain, len(chain), managed=True)
        source = SimpleNamespace(objects=objects, tables=sorted(obj.name for obj in objects if obj.type == "table"))
        sql = directory / "baseline.sql"
        # The bounded loader checks each part, complete SHA-256/MD5 and total
        # length; it has no dependency on a journal or destination resource.
        native.Rehearsal.load_sql(SimpleNamespace(api=api), document, sql)
        db, layout, summary = native.open_export(sql, source)
        with closing(db):
            require(native.canonical(layout) == native.canonical(document.get("layout"))
                    and summary == document.get("summary"), "The complete sealed baseline data does not match its manifest.")
            entries = _entries(document)

            def backup_object(key):
                entry = entries.get(key)
                require(entry is not None)
                body, _etag = api.object_or_none(target.data["backupBucketName"], api.archive_prefix + "blobs/" + entry["sha256"])
                require(isinstance(body, bytes) and len(body) == entry["bytes"] and recovery.digest(body) == entry["sha256"],
                        "A baseline R2 object is missing or corrupt.")
                return body, entry["metadata"]

            require(native.object_references(db, backup_object) == document["objects"],
                    "The sealed baseline R2 closure or ownership differs from its D1 references.")
            require(native.remote_summary(api, target.d1_id, layout) == summary,
                    "Production data changed after baseline capture; seal a fresh approved baseline.")
            require(native.object_references(db, lambda key: _source_object(api, target, key, entries[key])) == document["objects"])
            require(native.remote_summary(api, target.d1_id, layout) == summary,
                    "Production data changed while the activation baseline was being verified.")
        api.verify_backup()
        controller.guard()
        require(controller.inspect() == before, "The activation predecessor changed during independent baseline readback.")
        return {"baselineVerified": True, "checkpointId": checkpoint_id, "manifestSha256": manifest_sha256,
                "targetSha256": target.digest, "configurationSha256": target.configuration_digest,
                "dataSha256": summary["dataSha256"], "sourceRevision": pin["revision"],
                "moduleSha256": pin["moduleSha256"], "versionId": observed["release"]["versionId"],
                "rowCount": summary["rowCount"], "objectCount": len(entries), "mutationPerformed": False}

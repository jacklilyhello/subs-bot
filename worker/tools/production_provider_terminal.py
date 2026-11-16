"""Read-only evidence for a pinned failed ProviderFetch release.

Exit 137 is retained as failure, never accepted by the ordinary stopped/smoke
verifier. This evidence alone authorizes no mutation, replay, binding or release.
"""

from copy import deepcopy
from hashlib import sha256

import production_provider as control

ERROR = "The pinned failed ProviderFetch terminal state was not independently confirmed."


class GETOnlyProviderAPI(control.ProviderAPI):
    """Reuse bounded identity readers without retaining credentials or write paths."""

    def __init__(self, api, config):
        self.config = control.validate_config(config)
        control.require(isinstance(api.config, dict) and control.canonical(api.config) == control.canonical(self.config), ERROR)
        self.reader = api
        self.service, self.account = self.config["service"], self.config["accountId"]
        worker = self.config["worker"]
        control.require(worker is not None, ERROR)
        self.identity = control.bootstrap.Identity(worker["workerId"], worker["workerCreatedOn"])
        self.worker_path = "/workers/scripts/" + self.service
        self.beta_path = "/workers/workers/" + self.identity.worker_id + "/versions"
        self.workflow_name = self.service + "-smoke"
        self.workflow_path = "/workflows/" + self.workflow_name
        self.worker = control.Shell(self)

    def _request(self, path, *, container=False, method="GET", body=None, absent=None,
                 limit=control.publication.HTTP_LIMIT):
        control.require(method == "GET" and body is None, ERROR)
        return self.reader._request(path, container=container, method="GET", body=None, absent=absent, limit=limit)

    def _deny_mutation(self, *_args, **_kwargs):
        raise control.ProviderError("Failed-terminal evidence is read-only and cannot authorize a provider mutation.")

    _write = create = upload = deploy = create_container = create_workflow = trigger = _deny_mutation

    def stopped(self, *_args, **_kwargs):
        raise control.ProviderError("A failed-terminal provider is not a verified stopped smoke result.")


def validate_stop_failure(output):
    """Two closed failure schemas, never a successful egress/RPC result."""
    control.require(isinstance(output, dict) and output.get("ok") is False and output.get("stage") == "stop", ERROR)
    if set(output) == {"ok", "stage"}:
        return output
    control.fields(output, {"ok", "stage", "stop"})
    diagnostic = output["stop"]
    control.require(isinstance(diagnostic, dict) and type(diagnostic.get("version")) is int
                    and diagnostic["version"] in {1, 2}, ERROR)
    names = {"version", "phase", "reason", "exitCode", "primaryStage", "runningBeforeCleanup", "inspectNullBeforeCleanup", "forcedCleanup"}
    if diagnostic["version"] == 2:
        names |= {"primaryPhase", "primaryReason", "primaryElapsedMs"}
    control.fields(diagnostic, names)
    if diagnostic["version"] == 2:
        control.require(diagnostic.get("primaryPhase") in {"none", "configuration", "start-call", "inactivity-set", "readiness", "inspect", "use"}
            and diagnostic.get("primaryReason") in {"none", "operation", "timeout"}
            and type(diagnostic.get("primaryElapsedMs")) is int and 0 <= diagnostic["primaryElapsedMs"] <= 300000, ERROR)
        control.require((diagnostic["primaryStage"] == "none") == (diagnostic["primaryPhase"] == "none")
            and (diagnostic["primaryStage"] == "none") == (diagnostic["primaryReason"] == "none")
            and (diagnostic["primaryStage"] != "none" or diagnostic["primaryElapsedMs"] == 0), ERROR)
        phases = {"none": {"none"}, "configuration": {"configuration"}, "start": {"start-call", "inactivity-set"},
                  "readiness": {"readiness"}, "image": {"inspect"}, "edge": {"use"}, "address-policy": {"use"}, "stop": {"use"}}
        control.require(diagnostic["primaryPhase"] in phases.get(diagnostic["primaryStage"], set())
                        and (diagnostic["primaryReason"] != "timeout" or diagnostic["primaryPhase"] != "use"), ERROR)
    control.require(type(diagnostic["version"]) is int
        and diagnostic["phase"] in {"monitor-create", "signal", "monitor-wait", "state-read"}
        and diagnostic["reason"] in {"operation", "timeout", "nonzero-exit"}
        and diagnostic["primaryStage"] in {"none", "configuration", "start", "readiness", "image", "edge", "address-policy", "stop"}
        and diagnostic["forcedCleanup"] in {"returned", "unconfirmed"}
        and all(diagnostic[key] is None or type(diagnostic[key]) is bool
                for key in ("runningBeforeCleanup", "inspectNullBeforeCleanup"))
        and (diagnostic["exitCode"] is None or type(diagnostic["exitCode"]) is int and 0 <= diagnostic["exitCode"] <= 255), ERROR)
    control.require(diagnostic["reason"] != "nonzero-exit" or diagnostic["exitCode"] not in (None, 0), ERROR)
    return output


def _workflow_terminal(config, instance):
    control.require(isinstance(instance, dict) and instance.get("status") == "complete"
        and instance.get("success") is True and instance.get("versionId") == config["workflow"]["versionId"]
        and instance.get("params") == control.smoke_params(config) and instance.get("error") in (None, {})
        and instance.get("trigger") == {"source": "api"} and instance.get("schedule") is None, ERROR)
    start = control.bootstrap._timestamp(instance.get("start"))
    end = control.bootstrap._timestamp(instance.get("end"))
    control.require(end >= start, ERROR)
    output = instance.get("output")
    if isinstance(output, str):
        control.require(len(output) <= 2048, ERROR)
        output = control.github._parse_object(output, ERROR)
    expected = {"ok": True, "stopped": True, "revision": config["build"]["revision"],
        "imageSha256": config["build"]["ociManifestSha256"], "healthRevision": config["smoke"]["healthRevision"],
        "healthSha256": config["smoke"]["healthSha256"], "healthBytes": config["smoke"]["healthBytes"],
        "blockedPrivateTargets": 3, "rpcVerified": True}
    control.require(isinstance(output, dict), ERROR)
    if control.canonical(output) == control.canonical(expected):
        return start, None
    return start, validate_stop_failure(output)


def _snapshot(api, config, current):
    # Ordinary observation checks Worker creation identity, exact CI module,
    # namespace, activation, Container/Workflow pins, consumer refs and privacy.
    # It deliberately does not call the ordinary successful-smoke verifier.
    state = control.observe(api, need_smoke=False)
    control.require(state["container"] == config["container"]
        and state["activation"] in [value for value in (config["activation"], current["activation"]) if value is not None]
        and state["workflow"] in [value for value in (config["workflow"], current["workflow"]) if value is not None], ERROR)
    old_instance = api.smoke_instance({**config["build"], "versionId": config["versionId"]}, config["workflow"])
    started, _failure = _workflow_terminal(config, old_instance)
    namespace = config["activation"]["namespaceId"]
    rows = api.instances(namespace)
    control.require(len(rows) == 1 and isinstance(rows[0], dict)
        and control.match(control.legacy.ACTOR, rows[0].get("id"))
        and rows[0].get("application_id") == namespace, ERROR)
    actor = rows[0]["id"]
    actors = api.actors(namespace)
    control.require(len(actors) == 1 and isinstance(actors[0], dict) and actors[0].get("id") == actor
        and actors[0].get("hasStoredData") is True, ERROR)
    detail = api._request("/containers/applications/" + namespace + "/instances/" + actor, container=True)["result"]
    image = control.image_reference(config)
    for instance in (rows[0], detail):
        control.require(isinstance(instance, dict) and instance.get("id") == actor
            and instance.get("application_id") == namespace and instance.get("image") == image, ERROR)
        status = instance.get("status")
        control.require(isinstance(status, dict) and status.get("state") == "failed"
            and type(status.get("exit_code")) is int and status["exit_code"] == 137, ERROR)
        process_start = control.bootstrap._timestamp(instance.get("started_at"))
        updated = control.bootstrap._timestamp(status.get("updated_at"))
        control.require(started <= process_start <= updated, ERROR)
    control.require(all(rows[0][key] == detail[key] for key in ("image", "started_at"))
                    and all(rows[0]["status"][key] == detail["status"][key]
                            for key in ("state", "exit_code", "updated_at")), ERROR)
    active = api.instances(namespace, active=True)
    control.require(active == [], ERROR)
    return deepcopy({"state": state, "oldWorkflowInstance": old_instance,
                     "actors": actors, "instances": rows, "detail": detail, "active": active})


def verify_forced_terminal(api, config, *, current_config=None, evidence_sink=None):
    """Read twice and preserve exact failed/137 evidence for a separate forward plan."""
    config = control.validate_config(config)
    control.require(config["caller"] is None and all(config[key] is not None
        for key in ("worker", "versionId", "activation", "container", "workflow")), ERROR)
    current = config if current_config is None else control.validate_config(current_config)
    if current_config is not None:
        control.require(current["caller"] is None and control.canonical(current.get("previous")) == control.canonical(config)
            and current["build"]["revision"] != config["build"]["revision"]
            and all(current[key] == config[key] for key in
                    ("environment", "accountId", "service", "workersDevOrigin", "worker", "container")), ERROR)
        control.require(current["activation"] is None or current["activation"]["namespaceId"] == config["activation"]["namespaceId"], ERROR)
        control.require(current["workflow"] is None or all(current["workflow"][key] == config["workflow"][key]
            for key in ("workflowId", "createdOn")), ERROR)
    reader = GETOnlyProviderAPI(api, current)
    first = _snapshot(reader, config, current)
    control.require(control.canonical(_snapshot(reader, config, current)) == control.canonical(first),
                    "The failed ProviderFetch state changed during read-only reconciliation.")
    actor = first["instances"][0]["id"]
    process = first["instances"][0]
    result = {"status": "failed-terminal-preserved", "completion": "not-complete",
        "targetSha256": control.digest(config), "sourceRevision": config["build"]["revision"],
        "instanceIdSha256": sha256(actor.encode("ascii")).hexdigest(), "exitCode": 137, "state": "failed",
        "processSha256": control.digest({"id": actor, "image": process["image"],
            "startedAt": process["started_at"], "status": {key: process["status"][key] for key in ("state", "exit_code", "updated_at")}})}
    workflow = first["oldWorkflowInstance"]
    _started, failure = _workflow_terminal(config, workflow)
    if failure is not None:
        result.update({"smokeFailure": "stop", "workflowFailureSha256": control.digest(failure)})
    if evidence_sink is not None:
        def container_fields(instance):
            return {"applicationId": instance["application_id"], "instanceIdSha256": result["instanceIdSha256"],
                    "image": instance["image"], "startedAt": instance["started_at"],
                    "state": instance["status"]["state"], "exitCode": instance["status"]["exit_code"],
                    "updatedAt": instance["status"]["updated_at"]}
        evidence_sink({"version": 1, "summarySha256": control.digest(result), "targetSha256": control.digest(config),
            "observations": 2, "snapshotSha256": control.digest(first),
            "worker": config["worker"], "versionId": config["versionId"], "activation": config["activation"],
            "container": config["container"], "workflow": config["workflow"],
            "workflowResult": {"status": "complete", "success": True, "versionId": workflow["versionId"],
                               "params": workflow["params"], "start": workflow["start"], "end": workflow["end"],
                               "error": None, "namedRpcVerified": failure is None,
                               **({"output": failure} if failure is not None else {})},
            "inventory": container_fields(first["instances"][0]), "detail": container_fields(first["detail"]),
            "actorStoredData": True, "actorCount": 1, "instanceCount": 1, "activeCount": 0})
    return result

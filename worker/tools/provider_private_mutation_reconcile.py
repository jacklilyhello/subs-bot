"""Read-only state comparison for an interrupted isolated Provider operation.

The caller must independently authenticate the original intent and response-only
R2 evidence. This helper never dispatches or retries a Provider write.
"""
from copy import deepcopy

import production_provider as control
import production_provider_rehearsal as rehearsal
import provider_private_mutation as mutation


class ReadOnlyAPI(control.ProviderAPI):
    def _request(self, path, *, container=False, method="GET", body=None, absent=None, limit=control.publication.HTTP_LIMIT):
        control.require(method == "GET" and body is None)
        return super()._request(path, container=container, method=method, body=body, absent=absent, limit=limit)

    def upload(self, _module):
        raise control.ProviderError("Reconciliation cannot issue Provider writes.")


def confirmed_candidate(target, intent, original, worker_token, container_token):
    target = control.validate_config(target)
    operation = intent.get("operation")
    control.require(operation in {"stage", "activate"} and target["environment"] == "rehearsal" and target["caller"] is None
                    and target.get("previous") is not None and intent.get("status") == "started-unknown"
                    and intent.get("targetSha256") == control.digest(target)
                    and original.get("intentSha256") == control.digest(intent)
                    and original.get("targetSha256") == control.digest(target) and original.get("operation") == operation)
    observation = mutation.checked_observation(target, operation, original.get("observation"))
    previous = target["previous"]
    if operation == "stage":
        control.require(target["versionId"] is None and target["activation"] is None)
        candidate = deepcopy(target)
        candidate["versionId"] = observation["identities"]["versionId"]
        candidate = control.validate_config(candidate)
        api = ReadOnlyAPI(candidate, worker_token, container_token)
        state = control.observe(api)
        control.unbound_upgrade(api, state)
    else:
        control.require(target["versionId"] is not None and target["activation"] is None
                        and control.match(control.stage.VERSION_ID, observation["identities"].get("id")))
        api = ReadOnlyAPI(target, worker_token, container_token)
        state = control.observe(api)
        control.require(isinstance(state["activation"], dict) and state["activation"]["deploymentId"] == observation["identities"]["id"]
                        and state["container"] == previous["container"] and state["instance"] is None and isinstance(state["workflow"], dict)
                        and state["workflow"]["workflowId"] == previous["workflow"]["workflowId"]
                        and state["workflow"]["createdOn"] == previous["workflow"]["createdOn"])
        old_instance = api.smoke_instance({**previous["build"], "versionId": previous["versionId"]}, previous["workflow"])
        control.verify_previous_terminal(api, previous, old_instance)
        candidate = rehearsal.confirmed_target(target, "activate", state)
    control.require(control.caller_state(api, target, allow_unbound=True) == "unbound"
                    and control.observe(api) == state and control.caller_state(api, target, allow_unbound=True) == "unbound")
    if operation == "stage":
        control.unbound_upgrade(api, state)
    else:
        old_instance = api.smoke_instance({**previous["build"], "versionId": previous["versionId"]}, previous["workflow"])
        control.verify_previous_terminal(api, previous, old_instance)
    return candidate, {"status": "observed-by-read-only-reconciliation", "operation": operation,
                       "originalRunId": intent["runId"], "originalRunAttempt": intent["runAttempt"],
                       "intentSha256": control.digest(intent), "responseOriginalSha256": control.digest(original),
                       "targetSha256": control.digest(target), "nextTargetSha256": control.digest(candidate),
                       "stateSha256": control.digest(state), "callerState": "unbound", "originalRunSucceeded": False}

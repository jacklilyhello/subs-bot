"""A read-only Telegram adapter for the registered backup control drill."""
from hashlib import sha256

from production_control import Telegram, rows
from production_lifecycle_drill import HOSTNAME, ORIGINAL_ORIGIN, ORIGIN, SERVICE, public_readback, public_request
from production_target import ACCOUNT, TEST_BOT_ID, canonical, require

MODE = "simulate-webhook-precondition-v1"
WORKER_ID = "7776524f40fb4977ae683f4125867bd4"
DATABASE_ID = "c8653e6c-7209-46f2-b1ca-e917f3f8d7a3"


class BackupRehearsalTelegram(Telegram):
    """Supply only the synthetic webhook prerequisite for real control writes.

    The application controller still verifies Bot identity, group permissions,
    the frozen source, active code, domain, and backup before opening admission.
    This adapter cannot configure Telegram or model pending delivery/retry.
    """

    def __init__(self, target, secrets):
        expected = {"environment": "rehearsal", "accountId": ACCOUNT, "workerName": SERVICE,
                    "workerId": WORKER_ID, "d1Id": DATABASE_ID, "hostname": HOSTNAME,
                    "botId": TEST_BOT_ID, "botUsername": "test_cfsubs_bot"}
        require(target.environment == "rehearsal"
                and all(target.data.get(field) == value for field, value in expected.items()),
                "Simulated webhook prerequisites are restricted to the registered backup drill.")
        super().__init__(target, secrets, rehearsal_previous_url=ORIGINAL_ORIGIN + "/telegram/webhook")

    def observe_original(self):
        """Keep real delivery observations separate from the synthetic input."""
        info = super().call("getWebhookInfo")
        observed = self.webhook_info(info)
        require(observed["settings"]["url"] == self.rehearsal_previous_url,
                "The test Bot must still use its registered original webhook.")
        return observed

    def call(self, method, payload=None):
        require(method in {"getMe", "getWebhookInfo", "getChat", "getChatMember"},
                "The rehearsal Telegram adapter permits no external writes.")
        if method != "getWebhookInfo":
            return super().call(method, payload)
        require(payload is None)
        original = self.observe_original()
        desired = self.target.data["webhook"]
        return {"url": "https://" + HOSTNAME + "/telegram/webhook", "has_custom_certificate": False,
                "max_connections": desired["maxConnections"], "allowed_updates": list(desired["allowedUpdates"]),
                "pending_update_count": original["observation"]["pendingUpdateCount"]}

    def configure(self, expected_before, *, before_write=lambda: None):
        require(False, "The rehearsal Telegram adapter cannot configure a webhook.")

    def plan_webhook(self):
        require(False, "The rehearsal Telegram adapter cannot plan a webhook write.")


def receive_probe(controller, update_id, expected_status, *, guard):
    """Exercise the real Worker fence with a pinned update containing no command or recipient.

    An admitted probe leaves only the normal invocation and disposition. The
    caller must reserve a fresh, single-use identity in its private intent.
    """
    require(type(controller.telegram) is BackupRehearsalTelegram
            and controller.target is controller.telegram.target and controller.secrets is controller.telegram.secrets
            and controller.database == "/accounts/" + ACCOUNT + "/d1/database/" + DATABASE_ID
            and type(update_id) is int and 2**51 <= update_id < 2**52
            and expected_status in {204, 503} and callable(guard))
    before = controller.inspect()
    control = before["control"]
    require((control["admission"] == "open" and control["workers"] == "run") == (expected_status == 204))
    payload = canonical({"update_id": update_id})
    payload_sha256 = sha256(payload).hexdigest()
    completed = {"bot_id": TEST_BOT_ID, "target_sha256": controller.target.digest, "state": "completed",
                 "http_status": 204, "payload_sha256": payload_sha256}
    query = ("SELECT bot_id,target_sha256,state,http_status,payload_sha256 FROM subs_bot_production_updates "
             "WHERE update_id=" + str(update_id))
    previous = rows(controller.data, controller.database, query)
    require(not previous,
            "The synthetic update identity is occupied or its previous effect is unknown.")
    guard()
    request = public_request(ORIGIN + "/telegram/webhook", data=payload, method="POST",
                             secret=controller.secrets["webhookSecret"])
    observed, _body = public_readback(request, 4096, timeout=45)
    require(observed == expected_status, "The real Worker did not return the expected admission result.")
    following = rows(controller.data, controller.database, query)
    after = controller.inspect()
    require(after["control"] == control, "The admission state changed while the probe was being observed.")
    if expected_status == 503:
        require(not following, "The closed Worker unexpectedly reserved the synthetic update.")
    else:
        require(following == [completed], "The real update disposition was not independently confirmed.")
    return {"webhookPreconditionSimulated": True, "mode": MODE, "status": observed,
            "epoch": control["epoch"], "confirmedDisposition": bool(following)}

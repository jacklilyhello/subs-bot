import assert from "node:assert/strict";
import { test } from "node:test";

import { sendTelegramPrivateClaimReply, sendTelegramReply } from "../src/telegram/delivery.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import type { TelegramReplyLease } from "../src/telegram/store.ts";

const policy: TelegramPolicy = {
  botId: "123456789", botUsername: "fixture_subs_bot", adminId: "1001", memberId: "1002",
  groupId: "-1003", botToken: `123456789:${"a".repeat(35)}`, webhookSecret: "fixture-webhook-secret",
};
const lease: TelegramReplyLease = {
  actorId: policy.memberId, chatId: policy.memberId, chatType: "private",
  updateId: 1, messageId: 2, messageDate: 1_785_456_000, threadId: null,
  command: "list", receiptId: 1, leaseId: "fixture-lease", attempts: 1, view: null,
};

test("sends plain text to the approved actor and verifies the Telegram receipt scope", async () => {
  const response = await sendTelegramReply(policy, lease, "合成订阅", 1000, async (url, init) => {
    const destination = new URL(String(url));
    assert.equal(destination.origin, "https://api.telegram.org");
    assert.equal(destination.pathname, `/bot${policy.botToken}/sendMessage`);
    assert.equal(init?.redirect, "manual");
    assert.equal(init?.method, "POST");
    const body = JSON.parse(String(init?.body));
    assert.deepEqual(body, {
      chat_id: policy.memberId,
      reply_parameters: { message_id: 2, allow_sending_without_reply: true },
      link_preview_options: { is_disabled: true },
      text: "合成订阅",
    });
    return Response.json({ ok: true, result: { chat: { id: Number(policy.memberId) }, message_id: 3 } });
  });
  assert.deepEqual(response, { kind: "sent", messageId: 3 });
});

test("never makes a Bot API request for a destination outside the approved group or private chat", async () => {
  let requests = 0;
  const fetcher: typeof fetch = async () => {
    requests += 1;
    return new Response();
  };
  for (const destination of [
    { ...lease, chatId: policy.adminId },
    { ...lease, chatType: "group" as const, chatId: "-999" },
    { ...lease, actorId: "999", chatId: "999" },
  ]) {
    assert.deepEqual(await sendTelegramReply(policy, destination, "test", 1000, fetcher), { kind: "failed" });
  }
  assert.equal(requests, 0);
});

test("retries only verified rate limits and classifies uncertain outcomes separately", async () => {
  const cases = [
    [() => Response.json({ ok: false, error_code: 429, parameters: { retry_after: 7 } }, { status: 429 }),
      { kind: "retry", delaySeconds: 7 }],
    [() => Response.json({ ok: false, error_code: 429, parameters: { retry_after: 901 } }, { status: 429 }),
      { kind: "failed" }],
    [() => Response.json({ ok: false, error_code: 403 }, { status: 403 }), { kind: "failed" }],
    [() => Response.json({ ok: false, error_code: 500 }, { status: 500 }), { kind: "uncertain" }],
    [() => Response.redirect("https://unexpected.example.invalid/"), { kind: "uncertain" }],
    [() => Response.json({ ok: true, result: { chat: { id: 999 }, message_id: 3 } }), { kind: "uncertain" }],
    [() => Response.json({ ok: true, result: { chat: { id: Number(policy.memberId) }, message_id: 0 } }),
      { kind: "uncertain" }],
    [() => new Response("x".repeat(65_537)), { kind: "uncertain" }],
    [() => { throw new Error("fixture transport outcome unknown"); }, { kind: "uncertain" }],
  ] as const;
  for (const [reply, expected] of cases) {
    assert.deepEqual(await sendTelegramReply(policy, lease, "test", 1000, async () => reply()), expected);
  }
});

test("delivers one large private share document with exact bytes and fixed safe metadata", async () => {
  const privateLease = { ...lease, privateClaim: { codeSha256: "a".repeat(64) } };
  const content = "港".repeat(21845) + "\n";
  assert.equal(Buffer.byteLength(content), 65536);
  let requests = 0;
  const outcome = await sendTelegramPrivateClaimReply(policy, privateLease, {
    kind: "claimed", content, senderName: "合成名称\nhttps://example.invalid/private",
    claimCount: 1, maxClaims: 2, expireAt: 1_795_000_000,
  }, 1000, async (url, init) => {
    requests += 1;
    const destination = new URL(String(url));
    assert.equal(destination.origin, "https://api.telegram.org");
    assert.equal(destination.pathname, `/bot${policy.botToken}/sendDocument`);
    assert.equal(init?.redirect, "manual");
    assert.equal(init?.method, "POST");
    const form = init?.body;
    assert.ok(form instanceof FormData);
    assert.equal(form.get("chat_id"), policy.memberId);
    assert.equal(form.get("parse_mode"), null);
    assert.equal(form.get("caption"), "私密分享\n来自：合成名称 [链接已省略]\n领取进度：1/2");
    const document = form.get("document");
    assert.ok(document && typeof document !== "string");
    assert.equal(document.name, "private-share.txt");
    assert.equal(document.size, 65536);
    assert.equal(await document.text(), content);
    return Response.json({ ok: true, result: { chat: { id: Number(policy.memberId) }, message_id: 3 } });
  });
  assert.equal(requests, 1);
  assert.deepEqual(outcome, { kind: "sent", messageId: 3 });
});

test("does not send even a claim denial to the group, a topic or an unapproved user", async () => {
  const privateLease = { ...lease, privateClaim: { codeSha256: "a".repeat(64) } };
  let requests = 0;
  const fetcher: typeof fetch = async () => {
    requests += 1;
    return new Response();
  };
  for (const candidate of [
    lease, { ...privateLease, chatId: policy.groupId, chatType: "group" as const },
    { ...privateLease, threadId: 1 }, { ...privateLease, actorId: "9001", chatId: "9001" },
  ]) {
    assert.deepEqual(await sendTelegramPrivateClaimReply(policy, candidate, { kind: "target" }, 1000, fetcher),
      { kind: "failed" });
  }
  assert.equal(requests, 0);
});

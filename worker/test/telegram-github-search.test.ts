import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import { test } from "node:test";
import { Miniflare } from "miniflare";
import {
  acceptTelegramGitHubSearch, newGitHubSearchObservation, normalizeGitHubSearchQuery, recoverTelegramGitHubSearch, renderTelegramGitHubReply,
  runTelegramGitHubSearch,
} from "../src/telegram/github-search.ts";
import { grepCodeContent } from "../src/telegram/grep-search.ts";
import { GITHUB_SEARCH_PROOF_ARM, scopeGitHubSearchProof, writeGitHubSearchProof } from "../src/telegram/github-search-proof.ts";
import type { TelegramGitHubSearchUpdate, TelegramPolicy } from "../src/telegram/protocol.ts";
import { acceptTelegramCommand, beginTelegramGitHubSearchReply, claimTelegramReply } from "../src/telegram/store.ts";

const policy: TelegramPolicy = {
  botId: "77601", botUsername: "Fixture_Github_Bot", adminId: "77602", memberId: "77603", groupId: "-10077604",
  botToken: "77601:synthetic-token", webhookSecret: "synthetic-webhook-secret",
};

async function withDatabase(run: (db: D1Database, now: number) => Promise<void>): Promise<void> {
  const runtime = new Miniflare({ modules: true, script: "export default { fetch() { return new Response() } }",
    d1Databases: ["DB"], compatibilityDate: "2026-06-01" });
  try {
    const db = await runtime.getD1Database("DB");
    const migrations = new URL("../migrations/", import.meta.url);
    for (const name of (await readdir(migrations)).filter((name) => name.endsWith(".sql")).sort()) {
      const sql = await readFile(new URL(name, migrations), "utf8");
      await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
    }
    const now = await db.prepare("SELECT unixepoch() AS now").first<number>("now");
    assert.ok(now);
    await run(db, now);
  } finally {
    await runtime.dispose();
  }
}

function event(updateId: number, messageDate: number, actorId = policy.memberId): TelegramGitHubSearchUpdate {
  return { updateId, messageDate, actorId, messageId: updateId, chatId: actorId, chatType: "private", threadId: null,
    args: " 合成查询 user:octocat in:name" };
}

function claim(db: D1Database, providerPolicy?: TelegramPolicy) {
  return claimTelegramReply(db, policy.botId, false, false, false, false, false, false, providerPolicy, false, false, policy);
}

test("GitHub search accepts bounded keywords and known qualifiers and rejects external or private syntax", () => {
  assert.equal(normalizeGitHubSearchQuery("  订阅  Hello-World user:octocat in:name "), "订阅 Hello-World user:octocat in:name");
  for (const query of ["", "x".repeat(121), "𐐀".repeat(65), "x https://example.invalid/password", "name private:true",
    "name visibility:private", "name is:internal", "name repo:owner/..", "name org:K", "name in:path", "name OR other",
    "user:octocat", "x\u0000", "x\u200b", "x\ud800", "x\ny", "----"]) assert.equal(normalizeGitHubSearchQuery(query), null);
});

test("GitHub lookup is deduplicated, bounded, anonymous, and keeps only explicit public projections", async () => {
  await withDatabase(async (db, now) => {
    const update = event(1, now);
    const outcomes = await Promise.all([acceptTelegramGitHubSearch(db, policy, update), acceptTelegramGitHubSearch(db, policy, update)]);
    const admitted = outcomes.find((outcome) => outcome.kind === "lookup");
    assert.ok(admitted?.kind === "lookup");
    assert.equal(outcomes.filter((outcome) => outcome.kind === "ignored").length, 1);
    assert.equal(await claim(db), null);
    let calls = 0;
    const request: typeof fetch = async (input, init) => {
      calls++;
      const url = new URL(String(input));
      assert.equal(url.origin + url.pathname, "https://api.github.com/search/repositories");
      assert.equal(url.searchParams.get("q"), "合成查询 user:octocat in:name is:public");
      assert.equal(url.searchParams.get("sort"), "stars");
      assert.equal(url.searchParams.get("per_page"), "5");
      assert.equal(init?.method, "GET");
      assert.equal(init?.redirect, "manual");
      assert.equal(new Headers(init?.headers).get("Authorization"), null);
      return Response.json({ items: [
        { full_name: "octocat/Hello-World", html_url: "https://github.com/octocat/Hello-World", private: false, stargazers_count: 12 },
        { full_name: "hidden/Private", html_url: "https://github.com/hidden/Private", private: true, stargazers_count: 5 },
        { full_name: "hidden/Internal", html_url: "https://github.com/hidden/Internal", private: false, visibility: "internal", stargazers_count: 2 },
        { full_name: "hidden/Unverified", html_url: "https://github.com/hidden/Unverified", stargazers_count: 7 },
        { full_name: "hidden/Forged", html_url: "https://github.com@untrusted.invalid/hidden/Forged", private: false, stargazers_count: 5 },
      ] });
    };
    assert.deepEqual((await Promise.all([
      runTelegramGitHubSearch(db, policy, admitted, request), runTelegramGitHubSearch(db, policy, admitted, request),
    ])).sort(), [false, true]);
    assert.equal(calls, 1);
    assert.equal(await runTelegramGitHubSearch(db, policy, admitted, async () => assert.fail("lookup replay made a request")), false);
    assert.equal(await claimTelegramReply(db, policy.botId), null, "an older Worker must skip the marked carrier");
    const reply = await claim(db, policy);
    assert.ok(reply?.githubSearch);
    assert.deepEqual(renderTelegramGitHubReply(reply.githubSearch), {
      text: "GitHub 公开仓库\noctocat/Hello-World · ★ 12",
      keyboard: [[{ text: "octocat/Hello-World", url: "https://github.com/octocat/Hello-World" }],
        [{ text: "在 GitHub 网页搜索代码", url: "https://github.com/search?type=code" }]],
    });
    assert.equal((await acceptTelegramGitHubSearch(db, policy, event(2, now))).kind, "reply");
    assert.equal(await db.prepare("SELECT state FROM telegram_github_search ORDER BY receipt_id DESC LIMIT 1").first("state"), "limited");
    const stored = JSON.stringify((await db.prepare("SELECT * FROM telegram_github_search").all()).results);
    assert.doesNotMatch(stored, /合成查询|hidden|untrusted/u);
    // Revoke and regrant after the reply lease was claimed. A new grant cannot inherit it.
    await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,1,?,2)")
      .bind(policy.botId, policy.memberId, now - 1).run();
    assert.equal(await beginTelegramGitHubSearchReply(db, policy, reply), false);
    assert.equal(await db.prepare("SELECT state FROM telegram_outbox WHERE receipt_id=?").bind(reply.receiptId).first("state"), "failed");
    assert.equal(await recoverTelegramGitHubSearch(db, policy), 0);
    assert.equal(await db.prepare("SELECT public_results FROM telegram_github_search WHERE receipt_id=?")
      .bind(reply.receiptId).first("public_results"), null);
  });
});

test("abandoned lookups are recovered only while authorized and expired pending search does not block normal work", async () => {
  await withDatabase(async (db, now) => {
    const member = await acceptTelegramGitHubSearch(db, policy, event(1, now));
    const admin = await acceptTelegramGitHubSearch(db, policy, event(2, now, policy.adminId));
    assert.ok(member.kind === "lookup" && admin.kind === "lookup");
    await db.prepare("UPDATE telegram_github_search SET lookup_until = unixepoch() - 1").run();
    await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,0,?,3)")
      .bind(policy.botId, policy.memberId, now).run();
    assert.equal(await recoverTelegramGitHubSearch(db, policy), 1);
    assert.equal(await recoverTelegramGitHubSearch(db, policy), 0);
    assert.deepEqual((await db.prepare("SELECT state FROM telegram_github_search ORDER BY receipt_id").all()).results,
      [{ state: "discarded" }, { state: "unavailable" }]);
    assert.equal(await runTelegramGitHubSearch(db, policy, admin, async () => assert.fail("abandoned lookup was replayed")), false);
    await db.prepare("UPDATE telegram_inbox SET received_at = unixepoch() - 901 WHERE receipt_id=?").bind(admin.receiptId).run();
    await acceptTelegramCommand(db, policy, { ...event(3, now, policy.adminId), command: "help" });
    const reply = await claim(db, policy);
    assert.equal(reply?.updateId, 3);
    assert.equal(reply?.githubSearch, undefined);
  });
});

test("GitHub lookup failures use a fixed fallback without retrying or retaining the response body", async () => {
  await withDatabase(async (db, now) => {
    const responses = [
      () => Response.json({ message: "synthetic upstream private body" }, { status: 403 }),
      () => Response.json({ message: "synthetic upstream private body" }, { status: 429 }),
      () => new Response(new ReadableStream({
        start(controller) { controller.enqueue(new Uint8Array(256 * 1024 + 1)); },
      }), { headers: { "Content-Type": "application/json" } }),
      () => { throw new Error("synthetic upstream private body"); },
    ];
    let calls = 0;
    for (const [index, response] of responses.entries()) {
      await db.prepare("UPDATE telegram_github_search SET started_at=unixepoch()-16 WHERE started_at IS NOT NULL").run();
      const admission = await acceptTelegramGitHubSearch(db, policy, event(index + 1, now));
      assert.ok(admission.kind === "lookup");
      assert.equal(await runTelegramGitHubSearch(db, policy, admission, async () => { calls++; return response(); }), true);
    }
    assert.equal(calls, responses.length);
    assert.deepEqual((await db.prepare("SELECT state,public_results FROM telegram_github_search ORDER BY receipt_id").all()).results,
      responses.map(() => ({ state: "unavailable", public_results: null })));
  });
});

test("Grep verifies file visibility without waiting for the parallel repository search", async () => {
  await withDatabase(async (db, now) => {
    const repo = "public-fixture/Code";
    const url = `https://github.com/${repo}`;
    const publicRepo = { full_name: repo, html_url: url, private: false, visibility: "public", stargazers_count: 1 };
    const cases = [
      { laterRepositoryProof: false, status: 200, files: 2, state: "found" },
      { laterRepositoryProof: true, status: 429, files: 2, state: "found" },
      { laterRepositoryProof: false, status: 403, files: 0, state: "empty" },
    ];
    for (const [index, { laterRepositoryProof, status, files, state }] of cases.entries()) {
      await db.prepare("UPDATE telegram_github_search SET started_at=unixepoch()-16 WHERE started_at IS NOT NULL").run();
      const admission = await acceptTelegramGitHubSearch(db, policy, {
        ...event(index + 1, now), args: `synthetic-code repo:${repo}`,
      });
      assert.ok(admission.kind === "lookup");
      let releaseRepositorySearch!: (response: Response) => void;
      const pendingSearch = new Promise<Response>((resolve) => { releaseRepositorySearch = resolve; });
      let repoSearchReleased = false;
      const verificationOrder: boolean[] = [];
      const request: typeof fetch = async (input, init) => {
        const requested = new URL(String(input));
        if (requested.pathname === "/search/repositories") return pendingSearch;
        if (requested.pathname === `/repos/${repo}`) {
          verificationOrder.push(repoSearchReleased);
          if (repoSearchReleased) throw new DOMException("Synthetic visibility deadline elapsed", "TimeoutError");
          return status === 200 ? Response.json(publicRepo) : new Response(null, { status });
        }
        assert.equal(requested.href, "https://mcp.grep.app/");
        const rpc = JSON.parse(String(init?.body)) as { method: string; id?: number };
        if (rpc.method === "notifications/initialized") return new Response(null, { status: 202 });
        const result = rpc.method === "initialize" ? { protocolVersion: "2025-06-18" } : {
          content: ["first.ts", "second.ts"].map((path) => ({ type: "text",
            text: `Repository: ${repo}
Path: ${path}
URL: ${url}/blob/main/${path}
License: MIT
Snippets:
synthetic excerpt` })),
        };
        if (rpc.method === "tools/call") setImmediate(() => {
          repoSearchReleased = true;
          releaseRepositorySearch(Response.json({ items: laterRepositoryProof ? [publicRepo] : [], incomplete_results: false }));
        });
        return new Response(`data: ${JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result })}

`,
          { headers: { "Content-Type": "text/event-stream" } });
      };
      const observation = newGitHubSearchObservation();
      assert.equal(await runTelegramGitHubSearch(db, policy, admission, request, observation), true);
      assert.deepEqual(observation.visibility, [{ status, outcome: status === 200 ? "public" : "unconfirmed" }]);
      assert.equal(observation.grep.phase, "complete");
      assert.equal(observation.candidates, 2);
      assert.equal(observation.repositoryState, laterRepositoryProof ? "found" : "empty");
      assert.equal(observation.verifiedFiles, files);
      assert.equal(observation.settled, state);
      const row = await db.prepare("SELECT state,public_results FROM telegram_github_search WHERE receipt_id=?")
        .bind(admission.receiptId).first<{ state: string; public_results: string }>();
      assert.ok(row);
      assert.equal(row.state, state);
      if (files) assert.deepEqual(JSON.parse(row.public_results).code.map(({ path }: { path: string }) => path), ["first.ts", "second.ts"]);
      else assert.equal(row.public_results, null);
      assert.deepEqual(verificationOrder, [false], "verify the shared repository once while search is still pending");
    }
  });
});

test("Grep handshake cannot send the query after the member authorization changes", async () => {
  await withDatabase(async (db, now) => {
    const admission = await acceptTelegramGitHubSearch(db, policy, { ...event(1, now), args: "synthetic-lookup repo:octocat/Hello-World" });
    assert.ok(admission.kind === "lookup");
    const methods: string[] = [];
    const request: typeof fetch = async (input, init) => {
      if (String(input).startsWith("https://api.github.com/search/repositories?")) {
        return Response.json({ items: [], incomplete_results: false });
      }
      const rpc = JSON.parse(String(init?.body)) as { method: string; id?: number };
      methods.push(rpc.method);
      if (rpc.method === "initialize") return new Response(
        `data: ${JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result: { protocolVersion: "2025-06-18" } })}\n\n`,
        { headers: { "Content-Type": "text/event-stream" } });
      await db.prepare("INSERT INTO telegram_auth (bot_id,user_id,allowed,message_date,message_id) VALUES (?,?,0,?,1)")
        .bind(policy.botId, policy.memberId, now).run();
      return new Response(null, { status: 202 });
    };
    const observation = newGitHubSearchObservation();
    assert.equal(await runTelegramGitHubSearch(db, policy, admission, request, observation), false);
    assert.equal(observation.grep.phase, "authorization-denied");
    assert.equal(observation.settled, null);
    assert.deepEqual(methods, ["initialize", "notifications/initialized"]);
    assert.equal(await claim(db), null);
  });
});

test("Grep refuses redirects and a session contract not verified by the hosted probe", async () => {
  for (const response of [
    new Response(null, { status: 302, headers: { Location: "https://unexpected.invalid/" } }),
    new Response('data: {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18"}}\n\n',
      { headers: { "Content-Type": "text/event-stream", "Mcp-Session-Id": "unexpected-session" } }),
  ]) {
    const requests: Array<{ url: string; init?: RequestInit }> = [];
    const observation = newGitHubSearchObservation().grep;
    assert.deepEqual(await grepCodeContent(async (input, init) => {
      requests.push({ url: String(input), init });
      return response;
    }, AbortSignal.timeout(1000), "synthetic-lookup", undefined, async () => true, observation), []);
    assert.equal(observation.phase, "initialize-response");
    assert.equal(observation.initializeStatus, response.status);
    assert.equal(observation.toolStatus, null);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].url, "https://mcp.grep.app/");
    assert.equal(requests[0].init?.redirect, "manual");
    assert.doesNotMatch(String(requests[0].init?.body), /synthetic-lookup/u);
  }
});

test("Grep proof accepts only the scoped fixture and writes once per role after a settled lookup", async () => {
  const runtime = new Miniflare({ modules: true, script: "export default { fetch() { return new Response() } }",
    r2Buckets: ["NODES"], compatibilityDate: "2026-06-01" });
  try {
    const bucket = await runtime.getR2Bucket("NODES");
    const now = Math.floor(Date.now() / 1000);
    const origin = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
    const revision = "a".repeat(40);
    const cohort = "b".repeat(32);
    const policySha256 = "d".repeat(64);
    const query = "addClass repo:jquery/jquery";
    const fixturePolicy = { ...policy, botUsername: "test_cfsubs_bot" };
    const fixture = { ...event(1, now), args: query };
    assert.equal(scopeGitHubSearchProof("https://other.invalid", revision, policySha256, query, fixturePolicy, fixture, Date.now()), null);
    assert.equal(scopeGitHubSearchProof(origin, revision, policySha256, "unrelated", fixturePolicy, fixture, Date.now()), null);
    assert.equal(scopeGitHubSearchProof(origin, revision, policySha256, query, policy, fixture, Date.now()), null);
    assert.equal(scopeGitHubSearchProof(origin, revision, policySha256, query, fixturePolicy,
      { ...fixture, chatType: "group", chatId: policy.groupId }, Date.now()), null);
    const scoped = (receivedAt = Date.now()) => {
      const proof = scopeGitHubSearchProof(origin, revision, policySha256, query, fixturePolicy, fixture, receivedAt);
      assert.ok(proof);
      return proof;
    };
    assert.equal(await writeGitHubSearchProof(bucket, scoped(), 20), false);
    const settled = (receivedAt?: number) => {
      const proof = scoped(receivedAt);
      proof.observation.settled = "empty";
      return proof;
    };
    assert.equal(await writeGitHubSearchProof(bucket, settled(), 20), false, "an unarmed request writes nothing");
    const unavailable = { get() { throw new Error("synthetic storage failure"); } } as unknown as R2Bucket;
    assert.equal(await writeGitHubSearchProof(unavailable, settled(), 20), false);
    const arm = { version: 1, revision, policySha256, cohort, opensAt: now - 5, expiresAt: now + 30 };
    await bucket.put(GITHUB_SEARCH_PROOF_ARM, JSON.stringify({ ...arm, policySha256: "e".repeat(64) }));
    assert.equal(await writeGitHubSearchProof(bucket, settled(), 20), false);
    await bucket.put(GITHUB_SEARCH_PROOF_ARM, JSON.stringify({ ...arm, opensAt: now - 2, expiresAt: now - 1 }));
    assert.equal(await writeGitHubSearchProof(bucket, settled(), 20), false);
    await bucket.put(GITHUB_SEARCH_PROOF_ARM, JSON.stringify(arm));
    assert.equal(await writeGitHubSearchProof(bucket, settled((now - 2) * 1000), 20), false, "late arming cannot capture an old receipt");
    assert.equal(await writeGitHubSearchProof(bucket, settled(), 20), true);
    assert.equal(await writeGitHubSearchProof(bucket, settled(), 21), false);
    const item = await bucket.get(`diagnostics/telegram-github-search/v1/${cohort}/member.json`);
    assert.ok(item);
    const payload = await item.text();
    const record = JSON.parse(payload);
    assert.equal(record.role, "member");
    assert.equal(record.receiptId, 20);
    assert.equal(record.settled, "empty");
    assert.doesNotMatch(payload, /addClass|jquery|77603|fixture-isolation|synthetic-token/u);
    assert.equal(item.httpMetadata?.cacheControl, "private, no-store");
  } finally {
    await runtime.dispose();
  }
});

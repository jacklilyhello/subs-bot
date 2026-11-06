import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { after, before, test } from "node:test";

import { Miniflare } from "miniflare";

import { claimPrivateShare, createPrivateShare, MAX_PRIVATE_SHARE_BYTES } from "../src/private-shares.ts";

const miniflare = new Miniflare({
  modules: true,
  script: "export default { fetch() { return new Response(null); } };",
  compatibilityDate: "2026-07-30",
  d1Databases: ["DB"],
  r2Buckets: ["NODES"],
});

let db: D1Database;
let bucket: R2Bucket;
const botId = "9007199254740992";
const otherBotId = "9007199254740993";
const actor = "42002";
const otherActor = "42003";
const senderName = "合成发送者 🔒";
const content = "\uFEFF合成内容 🔑\nhttps://provider.example.invalid/sub?token=synthetic-private-payload\n";

type CreateInput = Parameters<typeof createPrivateShare>[2];
type ClaimInput = Parameters<typeof claimPrivateShare>[2];
type CreatedShare = Awaited<ReturnType<typeof createPrivateShare>>;

const initial: CreateInput = {
  botId, senderId: "9223372036854775807", senderName, content, maxClaims: 1, targetUserId: null, durationMinutes: 10,
};

interface StoredShare {
  id: number;
  bot_id: string;
  code_sha256: string;
  sender_id: string;
  sender_name: string;
  payload_id: string;
  payload_sha256: string;
  payload_bytes: number;
  max_claims: number;
  target_user_id: string | null;
  expire_at: number;
  created_at: number;
}

before(async () => {
  db = await miniflare.getD1Database("DB");
  bucket = await miniflare.getR2Bucket("NODES");
  const sql = await readFile(new URL("../migrations/0005_private_shares.sql", import.meta.url), "utf8");
  await db.batch(sql.trim().split(/;\s*/u).filter(Boolean).map((statement) => db.prepare(statement)));
});

after(() => miniflare.dispose());

function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}

function create(overrides: Partial<CreateInput> = {}, storage = bucket) {
  return createPrivateShare(db, storage, { ...initial, ...overrides });
}

function claim(code: string, overrides: Partial<ClaimInput> = {}, storage = bucket) {
  return claimPrivateShare(db, storage, { botId, actorId: actor, code, ...overrides });
}

async function metadata(code: string): Promise<StoredShare> {
  const row = await db.prepare("SELECT * FROM private_shares WHERE bot_id = ? AND code_sha256 = ?")
    .bind(botId, sha256(code)).first<StoredShare>();
  assert.ok(row);
  return row;
}

function payloadKey(row: StoredShare): string {
  return `private-shares/${row.payload_id}.txt`;
}

async function claimActors(row: StoredShare): Promise<string[]> {
  const result = await db.prepare("SELECT actor_id FROM private_share_claims WHERE share_id = ? ORDER BY actor_id")
    .bind(row.id).all<{ actor_id: string }>();
  return result.results.map(({ actor_id }) => actor_id);
}

function success(kind: "claimed" | "repeated", created: CreatedShare, claimCount = 1, maxClaims = 1) {
  return { kind, content, senderName, claimCount, maxClaims, expireAt: created.expireAt };
}

async function now(): Promise<number> {
  const row = await db.prepare("SELECT unixepoch() AS timestamp").first<{ timestamp: number }>();
  assert.ok(row);
  return row.timestamp;
}

test("binds exact private payload bytes to a separate R2 key and stores only the capability hash", async () => {
  const expected = Buffer.from(content);
  const writes: string[] = [];
  const checkedBucket = {
    put(key: string, value: Uint8Array<ArrayBuffer>, options: R2PutOptions) {
      writes.push(key);
      assert.deepEqual(Buffer.from(value), expected);
      assert.deepEqual(options.onlyIf, { etagDoesNotMatch: "*" });
      const digest = options.sha256;
      assert.ok(digest);
      assert.equal(typeof digest === "string" ? digest : Buffer.from(digest).toString("hex"), sha256(expected));
      return bucket.put(key, value, options);
    },
  } as unknown as R2Bucket;
  const created = await create({ durationMinutes: 1 }, checkedBucket);
  assert.match(created.code, /^[A-Za-z0-9_-]{22}$/u);
  const row = await metadata(created.code);
  assert.equal(row.bot_id, botId);
  assert.equal(row.sender_id, initial.senderId);
  assert.equal(row.sender_name, senderName);
  assert.equal(row.code_sha256, sha256(created.code));
  assert.equal(row.payload_sha256, sha256(expected));
  assert.equal(row.payload_bytes, expected.byteLength);
  assert.equal(row.expire_at, created.expireAt);
  assert.equal(row.expire_at - row.created_at, 60);
  assert.equal(JSON.stringify(row).includes("synthetic-private-payload"), false);
  assert.equal(Object.values(row).includes(created.code), false);
  const key = payloadKey(row);
  assert.match(key, /^private-shares\/[a-f0-9-]{36}\.txt$/u);
  assert.equal(key.includes(created.code), false);
  assert.deepEqual(writes, [key]);
  const object = await bucket.get(key);
  assert.ok(object);
  assert.equal(object.size, expected.byteLength);
  assert.deepEqual(Buffer.from(await object.arrayBuffer()), expected);
  assert.deepEqual(await claim(created.code), success("claimed", created));
});

test("scopes claims to the exact bot and target before reading any private body", async () => {
  const created = await create({ targetUserId: actor });
  const row = await metadata(created.code);
  assert.equal(row.target_user_id, actor);
  const reads: string[] = [];
  const observedBucket = {
    get(key: string) {
      reads.push(key);
      return bucket.get(key);
    },
  } as unknown as R2Bucket;
  assert.deepEqual(await claim(created.code, { botId: otherBotId }, observedBucket), { kind: "unavailable" });
  assert.deepEqual(await claim(created.code, { actorId: otherActor }, observedBucket), { kind: "target" });
  assert.deepEqual(await claim(created.code, { actorId: initial.senderId }, observedBucket), { kind: "target" });
  assert.deepEqual(reads, []);
  assert.deepEqual(await claimActors(row), []);
  assert.deepEqual(await claim(created.code, {}, observedBucket), success("claimed", created));
  assert.deepEqual(reads, [payloadKey(row)]);
  assert.deepEqual(await claimActors(row), [actor]);
});

test("continues to accept the exact legacy capability spelling", async () => {
  const created = await create();
  const row = await metadata(created.code);
  const code = Buffer.from("legacy!!").toString("base64url");
  assert.equal(code.length, 11);
  await db.prepare("UPDATE private_shares SET code_sha256 = ? WHERE id = ?").bind(sha256(code), row.id).run();
  assert.deepEqual(await claim(created.code), { kind: "unavailable" });
  assert.deepEqual(await claim(code), success("claimed", created));
  assert.deepEqual(await claimActors(row), [actor]);
});

async function raceClaims(code: string, actors: [string, string], signal: AbortSignal) {
  const bothReading = Promise.withResolvers<void>();
  const release = Promise.withResolvers<void>();
  let readers = 0;
  const racingBucket = {
    async get(key: string) {
      const body = await bucket.get(key);
      readers += 1;
      if (readers === 2) bothReading.resolve();
      await release.promise;
      return body;
    },
  } as unknown as R2Bucket;
  const unblock = () => release.resolve();
  signal.addEventListener("abort", unblock, { once: true });
  const attempts = actors.map((actorId) => claim(code, { actorId }, racingBucket));
  try {
    await Promise.race([
      bothReading.promise,
      ...attempts.map(async (attempt) => {
        await attempt;
        assert.fail("The claim finished before both requests reached R2.");
      }),
    ]);
  } finally {
    signal.removeEventListener("abort", unblock);
    unblock();
  }
  return Promise.all(attempts);
}

test("different actors race for one last slot, and the winner can repeat after exhaustion", { timeout: 10_000 }, async ({ signal }) => {
  const created = await create({ maxClaims: 2 });
  const row = await metadata(created.code);
  const firstActor = "42004";
  assert.deepEqual(await claim(created.code, { actorId: firstActor }), success("claimed", created, 1, 2));
  const actors: [string, string] = [actor, otherActor];
  const attempts = await raceClaims(created.code, actors, signal);
  assert.deepEqual(attempts.map(({ kind }) => kind).sort(), ["claimed", "exhausted"]);
  const winner = attempts.findIndex(({ kind }) => kind === "claimed");
  assert.deepEqual(attempts[winner], success("claimed", created, 2, 2));
  assert.deepEqual(attempts[1 - winner], { kind: "exhausted" });
  assert.deepEqual(await claim(created.code, { actorId: actors[winner] }), success("repeated", created, 2, 2));
  assert.deepEqual(await claim(created.code, { actorId: firstActor }), success("repeated", created, 2, 2));
  const noRead = { get() { assert.fail("An exhausted claim reached R2."); } } as unknown as R2Bucket;
  assert.deepEqual(await claim(created.code, { actorId: actors[1 - winner] }, noRead), { kind: "exhausted" });
  assert.deepEqual(await claimActors(row), [actors[winner], firstActor].sort());
});

test("concurrent claims by one actor record exactly one slot", { timeout: 10_000 }, async ({ signal }) => {
  const created = await create();
  const row = await metadata(created.code);
  const attempts = await raceClaims(created.code, [actor, actor], signal);
  assert.deepEqual(attempts.toSorted((left, right) => left.kind.localeCompare(right.kind)), [
    success("claimed", created), success("repeated", created),
  ]);
  assert.deepEqual(await claimActors(row), [actor]);
});

test("keeps the inclusive D1 expiry cutoff and rejects all claims after it", async () => {
  const created = await create();
  const row = await metadata(created.code);
  let testedBoundary = false;
  for (let attempt = 0; attempt < 4 && !testedBoundary; attempt += 1) {
    const written = await db.prepare("UPDATE private_shares SET expire_at = unixepoch() WHERE id = ? RETURNING expire_at")
      .bind(row.id).first<{ expire_at: number }>();
    assert.ok(written);
    const actual = await claim(created.code);
    if (actual.kind === "expired") {
      assert.ok(await now() > written.expire_at, "The share is still valid at the exact expiry second.");
    } else {
      assert.deepEqual(actual, success("claimed", { ...created, expireAt: written.expire_at }));
      testedBoundary = true;
    }
  }
  assert.equal(testedBoundary, true);
  await db.prepare("UPDATE private_shares SET created_at = unixepoch() - 60, expire_at = unixepoch() - 1 WHERE id = ?")
    .bind(row.id).run();
  assert.deepEqual(await claim(created.code), { kind: "expired" });
  assert.deepEqual(await claim(created.code, { actorId: otherActor }), { kind: "expired" });
  assert.deepEqual(await claimActors(row), [actor]);
});

test("rechecks expiry after reading the payload and before recording a claim", async () => {
  const created = await create();
  const row = await metadata(created.code);
  const expiringBucket = {
    async get(key: string) {
      assert.equal(key, payloadKey(row));
      const object = await bucket.get(key);
      assert.ok(object);
      await db.prepare("UPDATE private_shares SET created_at = unixepoch() - 60, expire_at = unixepoch() - 1 WHERE id = ?")
        .bind(row.id).run();
      return object;
    },
  } as unknown as R2Bucket;
  assert.deepEqual(await claim(created.code, {}, expiringBucket), { kind: "expired" });
  assert.deepEqual(await claimActors(row), []);
});

test("refuses an invalid UTF-8 body even when its byte count and hash match", async () => {
  const created = await create();
  const row = await metadata(created.code);
  const invalid = Uint8Array.of(0xc3, 0x28);
  await bucket.put(payloadKey(row), invalid);
  await db.prepare("UPDATE private_shares SET payload_sha256 = ?, payload_bytes = ? WHERE id = ?")
    .bind(sha256(invalid), invalid.byteLength, row.id).run();
  assert.deepEqual(await claim(created.code), { kind: "unavailable" });
  assert.deepEqual(await claimActors(row), []);
});

test("keeps a verified R2 candidate when a committed D1 insert loses its response", async () => {
  const isolatedBot = "51022";
  const syntheticError = "synthetic-private-D1-response-detail";
  let lost = 0;
  const responseLost = {
    prepare(sql: string) {
      const prepared = db.prepare(sql);
      return {
        bind(...values: unknown[]) {
          const statement = prepared.bind(...values);
          return {
            async all() {
              const result = await statement.all();
              assert.equal(result.success, true);
              assert.equal(result.meta.changes, 1);
              lost += 1;
              throw new Error(syntheticError);
            },
          };
        },
      };
    },
  } as unknown as D1Database;
  await assert.rejects(createPrivateShare(responseLost, bucket, { ...initial, botId: isolatedBot }), (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message.includes(syntheticError), false);
    return true;
  });
  assert.equal(lost, 1);
  const readBack = await db.prepare("SELECT * FROM private_shares WHERE bot_id = ?")
    .bind(isolatedBot).all<StoredShare>();
  assert.equal(readBack.results.length, 1);
  const [row] = readBack.results;
  assert.equal(row.payload_sha256, sha256(content));
  const kept = await bucket.get(payloadKey(row));
  assert.ok(kept);
  assert.deepEqual(Buffer.from(await kept.arrayBuffer()), Buffer.from(content));
  assert.deepEqual(await claimActors(row), []);
});

test("retries a committed claim with a lost D1 response without charging a second slot", async () => {
  const created = await create();
  const row = await metadata(created.code);
  let committed = false;
  const responseLost = {
    prepare: db.prepare.bind(db),
    async batch(statements: D1PreparedStatement[]) {
      const results = await db.batch(statements);
      committed = results[0]?.success === true && results[0].meta.changes === 1;
      throw new Error("Synthetic private D1 claim detail.");
    },
  } as unknown as D1Database;
  await assert.rejects(claimPrivateShare(responseLost, bucket, { botId, actorId: actor, code: created.code }), {
    message: "Private share claim could not be confirmed.",
  });
  assert.equal(committed, true);
  assert.deepEqual(await claim(created.code), success("repeated", created));
  assert.deepEqual(await claimActors(row), [actor]);
});

test("checks exact UTF-8 sizes, numeric bounds and canonical IDs before writing", async () => {
  const fullContent = "🔒".repeat(MAX_PRIVATE_SHARE_BYTES / 4);
  const fullName = "名".repeat(85) + "A";
  assert.equal(Buffer.byteLength(fullContent), MAX_PRIVATE_SHARE_BYTES);
  assert.equal(Buffer.byteLength(fullName), 256);
  const created = await create({
    content: fullContent, senderName: fullName, maxClaims: 100, durationMinutes: 10080,
  });
  const row = await metadata(created.code);
  assert.equal(row.payload_bytes, MAX_PRIVATE_SHARE_BYTES);
  assert.equal(row.max_claims, 100);
  assert.equal(row.expire_at - row.created_at, 604800);
  assert.deepEqual(await claim(created.code), {
    kind: "claimed", content: fullContent, senderName: fullName, claimCount: 1, maxClaims: 100, expireAt: created.expireAt,
  });

  let unexpectedWrites = 0;
  const rejectingBucket = {
    put() {
      unexpectedWrites += 1;
      throw new Error("An invalid share reached R2.");
    },
  } as unknown as R2Bucket;
  const invalidInputs: Partial<CreateInput>[] = [
    { botId: "0" }, { botId: "051021" }, { senderId: "9223372036854775808" },
    { senderId: "42\n" }, { targetUserId: "-1001234567890" },
    { content: "" }, { content: fullContent + "A" }, { content: "\ud800" },
    { senderName: "" }, { senderName: fullName + "A" }, { senderName: "invalid\u0000name" },
    { maxClaims: 0 }, { maxClaims: 101 }, { maxClaims: 1.5 },
    { durationMinutes: 0 }, { durationMinutes: 10081 }, { durationMinutes: 1.5 },
  ];
  for (const input of invalidInputs) await assert.rejects(create(input, rejectingBucket));
  assert.equal(unexpectedWrites, 0);
});

test("returns a generic unavailable result for invalid codes and malformed claim identities", async () => {
  const created = await create();
  const row = await metadata(created.code);
  let unexpectedReads = 0;
  const rejectingBucket = {
    get() {
      unexpectedReads += 1;
      throw new Error("An invalid claim reached R2.");
    },
  } as unknown as R2Bucket;
  for (const overrides of [
    { botId: "0" }, { botId: "9223372036854775808" }, { actorId: "042002" }, { actorId: "-42002" },
    { actorId: "42002\n" }, { code: "" }, { code: created.code + "\n" }, { code: created.code + "=" },
    { code: "/" + created.code.slice(1) }, { code: created.code.slice(1) },
  ]) {
    assert.deepEqual(await claim(created.code, overrides, rejectingBucket), { kind: "unavailable" });
  }
  assert.equal(unexpectedReads, 0);
  assert.deepEqual(await claimActors(row), []);
});

test("does not consume a slot when the private payload is missing, oversized, or corrupted", { timeout: 10_000 }, async () => {
  const created = await create();
  const row = await metadata(created.code);
  const key = payloadKey(row);
  const original = Buffer.from(content);
  const corrupt = Buffer.from(original);
  corrupt[0] ^= 1;
  await bucket.put(key, corrupt);
  assert.deepEqual(await claim(created.code), { kind: "unavailable" });
  await bucket.put(key, Buffer.alloc(MAX_PRIVATE_SHARE_BYTES + 1, 0x61));
  assert.deepEqual(await claim(created.code), { kind: "unavailable" });
  await bucket.delete(key);
  assert.deepEqual(await claim(created.code), { kind: "unavailable" });
  let canceled = false;
  const oversizedStream = {
    async get() {
      return {
        size: row.payload_bytes,
        body: new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new Uint8Array(row.payload_bytes + 1));
          },
          cancel() {
            canceled = true;
          },
        }),
      };
    },
  } as unknown as R2Bucket;
  assert.deepEqual(await claim(created.code, {}, oversizedStream), { kind: "unavailable" });
  assert.equal(canceled, true);
  assert.deepEqual(await claimActors(row), []);

  await bucket.put(key, original);
  assert.deepEqual(await claim(created.code), success("claimed", created));
  await bucket.put(key, corrupt);
  assert.deepEqual(await claim(created.code), { kind: "unavailable" });
  assert.deepEqual(await claimActors(row), [actor]);
});

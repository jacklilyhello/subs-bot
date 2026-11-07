import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";

import { rawShareBytes, ShareByteLimitError } from "../src/base64-response.ts";
import { MAX_CHUNK_BYTES } from "../src/storage.ts";
import type { TelegramPolicy } from "../src/telegram/protocol.ts";
import { MAX_RAW_FILE_BYTES, MAX_RAW_FILE_NODES, MAX_RAW_FILE_SNAPSHOT_BYTES,
  prepareTelegramSubscriptionRawFile } from "../src/telegram/subscription-raw-file.ts";

test("raw share bytes count UTF-8 and LF separators at the file cap", async () => {
  const prefix = "ssr://synthetic#界";
  const line = (size: number) => prefix + "x".repeat(size - Buffer.byteLength(prefix));
  const full = 256 * 1024;
  const repeated = line(full);
  const measure = async (size: number) => {
    const source = { nodeCount: 16, async *read() {
      for (let index = 0; index < 15; index++) yield { share: repeated };
      yield { share: line(size - 15 * (full + 1)) };
    } };
    let bytes = 0;
    for await (const chunk of rawShareBytes(source, undefined, MAX_RAW_FILE_BYTES)) {
      assert.equal(chunk[0], bytes === 0 ? 0x73 : 0x0a);
      assert.equal(chunk.at(-1), 0x78);
      bytes += chunk.byteLength;
    }
    return bytes;
  };
  assert.equal(await measure(MAX_RAW_FILE_BYTES - 1), MAX_RAW_FILE_BYTES - 1);
  assert.equal(await measure(MAX_RAW_FILE_BYTES), MAX_RAW_FILE_BYTES);
  await assert.rejects(measure(MAX_RAW_FILE_BYTES + 1), ShareByteLimitError);
});

test("the raw file preparation bounds node count and declared snapshot bytes before chunk reads", async () => {
  const policy: TelegramPolicy = { botId: "78501", botUsername: "FixtureRawCapBot", adminId: "78502", memberId: "78503",
    groupId: "-10078504", botToken: "78501:synthetic", webhookSecret: "synthetic" };
  const lease = { receiptId: 1, leaseId: "synthetic", attempts: 1, subscriptionRawFile: true as const,
    actorId: policy.memberId, chatId: policy.memberId, chatType: "private" as const, threadId: null,
    updateId: 2, messageId: 3, messageDate: 4, command: "help" as const };
  const hash = (value: string | Uint8Array) => createHash("sha256").update(value).digest("hex");
  async function prepare(chunkSizes: number[], nodeCount = chunkSizes.length) {
    const bytes = new TextEncoder().encode(JSON.stringify({ version: 1,
      chunks: chunkSizes.map((size) => ({ bytes: size, sha256: "c".repeat(64), count: 1 })) }));
    const pin = { id: 1, generation: 1, lifecycleRevision: 0, snapshotId: "00000000-0000-4000-8000-000000000001",
      manifestSha256: hash(bytes), nodeCount, rulesSha: hash("[]"), rules: "[]", current: 1 };
    const db = { prepare: () => ({ bind: () => ({ first: async () => pin }) }) } as unknown as D1Database;
    const reads: string[] = [];
    const bucket = { async get(key: string) {
      reads.push(key);
      return key.endsWith("/manifest.json") ? { size: bytes.length, arrayBuffer: async () => bytes.buffer } : null;
    } } as unknown as R2Bucket;
    const reply = await prepareTelegramSubscriptionRawFile(db, bucket, policy, lease, Date.now() + 10000);
    return { reply, reads };
  }
  const count = await prepare([], MAX_RAW_FILE_NODES + 1);
  assert.equal(count.reply?.kind === "text" && count.reply.text, "节点文件超过导出上限。");
  assert.deepEqual(count.reads, []);
  const sizes = Array(MAX_RAW_FILE_SNAPSHOT_BYTES / MAX_CHUNK_BYTES).fill(MAX_CHUNK_BYTES);
  const over = await prepare([...sizes, 1]);
  assert.equal(over.reply?.kind === "text" && over.reply.text, "节点文件超过导出上限。");
  assert.equal(over.reads.length, 1);
  assert.ok(over.reads[0].endsWith("/manifest.json"));
  const exact = await prepare(sizes);
  assert.equal(exact.reply?.kind === "text" && exact.reply.text, "暂时无法读取订阅节点。");
  assert.ok(exact.reads.some((key) => key.endsWith("/0.ndjson")));
});

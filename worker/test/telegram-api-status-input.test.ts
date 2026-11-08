import assert from "node:assert/strict";
import test from "node:test";
import { classifyTelegramApiStatusInput } from "../src/telegram/api-status-input.ts";

const base = "https://api.example.invalid";
const key = "synthetic-key|part";
const dispatchBeforeMs = 1234567890;
const pin = { providerRevision: "a".repeat(40), imageSha256: "b".repeat(64) };
const ordinary = (text: string) => classifyTelegramApiStatusInput({ kind: "ordinary", text });
const prompted = (text: string) => classifyTelegramApiStatusInput({ kind: "verified-prompt-reply", text });

test("ordinary subscriptions keep literal and encoded URL pipes", () => {
  for (const text of [
    base,
    `${base}/provider%7Cprofile?signature=one%7ctwo`,
    `  ${base}/provider?signature=one%7Ctwo  `,
    `fixture | ${base}/provider?signature=one|two`,
    `fixture|${base}/provider|profile`,
    `${base}/provider|profile?signature=one|two`,
    `  ${base}/provider?signature=one|two  `,
    `${base}/provider|profile\nss://synthetic-share`,
    `${base}/provider|profile ss://synthetic-share`,
    `${base}/provider%7Cprofile\nss://synthetic-share`,
    `${base}/provider ss://synthetic-share`,
    "ordinary message",
    "/air",
  ]) assert.deepEqual(ordinary(text), { kind: "pass-through" });
});

test("an unverified credential context never opens a prompt or exposes its input", () => {
  for (const text of [
    "/ai",
    `/AI@FixtureBot ${base}|${key}`,
    `${base} ${key}`,
    `${base}| ${key}`,
    `${base} |${key}`,
    `${base} | ${key}`,
    `ss://synthetic-share\n${base} | ${key}\nss://second-share`,
  ]) assert.deepEqual(ordinary(text), { kind: "quarantine", reason: "credential-text" });
  assert.deepEqual(classifyTelegramApiStatusInput({ kind: "unverified-prompt-reply" }),
    { kind: "quarantine", reason: "unverified-prompt" });
  assert.deepEqual(classifyTelegramApiStatusInput({ kind: "ai-command", args: ` ${base}|${key}` }),
    { kind: "quarantine", reason: "command-arguments" });
  assert.deepEqual(ordinary("a".repeat(64 * 1024 + 1)), { kind: "quarantine", reason: "text-limit" });
});

test("a verified bare command opens the prompt and a verified reply can cancel", () => {
  for (const args of ["", " \t "]) {
    assert.deepEqual(classifyTelegramApiStatusInput({ kind: "ai-command", args }), { kind: "open-prompt" });
  }
  assert.deepEqual(classifyTelegramApiStatusInput({ kind: "ai-command", args: "\n" }),
    { kind: "quarantine", reason: "command-arguments" });
  for (const text of ["/cancel", " Cancel ", "取消", "退出"]) assert.deepEqual(prompted(text), { kind: "cancelled" });
  assert.deepEqual(ordinary("cancel"), { kind: "pass-through" });
});

test("only a verified prompt produces exact private RPC credentials", () => {
  for (const [text, url, expectedKey] of [
    [`${base}|${key}`, `${base}/v1/models`, key],
    [`${base}| ${key}`, `${base}/v1/models`, key],
    [`${base} |${key}`, `${base}/v1/models`, key],
    [`\t${base}/ \t${key}  `, `${base}/v1/models`, key],
    [`${base}:443/api/models/ | ${key}`, `${base}:443/api/models`, key],
    [`${base}/api/chat/completions ${key}`, `${base}/api/chat/completions`, key],
    [`${base}/with|pipe/models | ${key}`, `${base}/with|pipe/models`, key],
    [`${base} | |${key}`, `${base}/v1/models`, `|${key}`],
    [`${base}|${"x".repeat(512)}`, `${base}/v1/models`, "x".repeat(512)],
  ]) {
    const decision = prompted(text);
    if (decision.kind !== "batch") assert.fail("Expected a verified batch");
    assert.equal(decision.rows.length, 1);
    const [row] = decision.rows;
    if (row.kind !== "probe") assert.fail("Expected a verified probe");
    assert.equal(JSON.stringify(decision), '{"kind":"batch","rows":[{"kind":"probe","credentials":{}}]}');
    assert.deepEqual(row.credentials.toProviderInput(pin, dispatchBeforeMs), { ...pin, dispatchBeforeMs, url, key: expectedKey });
  }
});

test("invalid verified rows contain no input or credentials", () => {
  for (const text of [
    base,
    `${base}|`,
    `${base} |`,
    `${base} | synthetic key`,
    `${base}|bad\u0000key`,
    `${base}|非ASCII`,
    `${base}|${"x".repeat(513)}`,
    `${base}/${"中".repeat(2800)}|${key}`,
    `http://api.example.invalid|${key}`,
    `https://synthetic-user@api.example.invalid|${key}`,
    `https://api%2eexample.invalid|${key}`,
    `${base}:8443|${key}`,
    `${base}:|${key}`,
    `${base}?|${key}`,
    `${base}/models?example=query|${key}`,
    `${base}/models#fragment|${key}`,
    `${base}\\models|${key}`,
    `${base}/broken%G1|${key}`,
    `${base}/broken\ud800|${key}`,
    `https://[invalid]/models|${key}`,
  ]) assert.deepEqual(prompted(text), { kind: "batch", rows: [{ kind: "invalid" }] });
});

test("verified LF and CRLF batches preserve row order and ignore blank lines", () => {
  const second = `${base}/nested/chat/completions second-synthetic-key`;
  const decision = prompted(`\n${base}|${key}\r\n \t\r\n${second}\n`);
  if (decision.kind !== "batch") assert.fail("Expected an ordered batch");
  assert.equal(decision.rows.length, 2);
  const [firstRow, secondRow] = decision.rows;
  if (firstRow.kind !== "probe" || secondRow.kind !== "probe") assert.fail("Expected two probes");
  assert.deepEqual(firstRow.credentials.toProviderInput(pin, dispatchBeforeMs), { ...pin, dispatchBeforeMs, url: `${base}/v1/models`, key });
  assert.deepEqual(secondRow.credentials.toProviderInput(pin, dispatchBeforeMs), {
    ...pin, dispatchBeforeMs, url: `${base}/nested/chat/completions`, key: "second-synthetic-key",
  });
  assert.equal(JSON.stringify(decision),
    '{"kind":"batch","rows":[{"kind":"probe","credentials":{}},{"kind":"probe","credentials":{}}]}');
});

test("a verified malformed row does not hide or renumber a valid sibling", () => {
  const pair = `${base}|${key}`;
  for (const invalidFirst of [true, false]) {
    const decision = prompted(invalidFirst ? `invalid fixture\n${pair}` : `${pair}\ninvalid fixture`);
    if (decision.kind !== "batch") assert.fail("Expected an ordered batch");
    assert.equal(decision.rows.length, 2);
    const validIndex = invalidFirst ? 1 : 0;
    assert.deepEqual(decision.rows[1 - validIndex], { kind: "invalid" });
    const row = decision.rows[validIndex];
    if (row.kind !== "probe") assert.fail("Expected the valid sibling");
    assert.deepEqual(row.credentials.toProviderInput(pin, dispatchBeforeMs), { ...pin, dispatchBeforeMs, url: `${base}/v1/models`, key });
  }
});

test("whole-batch refusal exposes a closed reason and no credential objects", () => {
  const pair = `${base}|${key}`;
  for (const [text, reason] of [
    ["\n\r\n\t ", "empty"],
    [" ".repeat(4097 - pair.length) + pair, "text-limit"],
    [`${pair}\r${pair}`, "line-break"],
    [`${pair}\u2028${pair}`, "line-break"],
    [`${pair}\u0085${pair}`, "line-break"],
    [`\u00a0${pair}`, "invalid-whitespace"],
    [`${pair}\n${pair}\ninvalid third fixture`, "row-limit"],
    [`取消\n${pair}`, "mixed-cancellation"],
    [`${pair}\n/cancel`, "mixed-cancellation"],
  ]) assert.deepEqual(prompted(text), { kind: "invalid", reason });
  assert.equal(prompted(" ".repeat(4096 - pair.length) + pair).kind, "batch");
  assert.deepEqual(prompted(" \r\n取消\n"), { kind: "cancelled" });
});

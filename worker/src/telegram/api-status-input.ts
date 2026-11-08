import type { ProviderApiStatusV2Input, ProviderPin } from "../provider-fetch-contract.ts";

export const TELEGRAM_API_STATUS_PROMPT = "请直接回复此消息，每行输入 HTTPS API 地址和 Key，使用“地址 | Key”或用空格分隔，最多两行。发送 /cancel 取消。";
const MAX_TEXT_LENGTH = 64 * 1024;
const MAX_PROMPT_LENGTH = 4096;
const MAX_PROMPT_ROWS = 2;
const MAX_URL_BYTES = 8192;
const MAX_RPC_BYTES = 12 * 1024;
const LINE_BREAK = /[\r\n\v\f\u001c-\u001e\u0085\u2028\u2029]/u;
const UNSUPPORTED_PROMPT_BREAK = /\r(?!\n)|[\v\f\u001c-\u001e\u0085\u2028\u2029]/u;
const CANCEL = /^(?:\/cancel|cancel|取消|退出)(?![\s\S])/iu;
const HTTP_START = /^https?:\/\//iu;
const URI_START = /^[a-z][a-z0-9+.-]*:\/\//iu;
const AI_COMMAND = /^\/ai(?:@\S*)?(?:\s|$)/iu;
const AUTHORITY = /^(?:\[[^\[\]]+\]|[^:\[\]]+)(?::[0-9]{1,5})?$/u;
const encoder = new TextEncoder();

export type TelegramApiStatusInput =
  | { kind: "ordinary"; text: string }
  | { kind: "ai-command"; args: string }
  | { kind: "unverified-prompt-reply" }
  | { kind: "verified-prompt-reply"; text: string };

class ApiStatusCredentials {
  #url: string;
  #key: string;

  constructor(url: string, key: string) {
    this.#url = url;
    this.#key = key;
  }

  toProviderInput(pin: ProviderPin, dispatchBeforeMs: number): ProviderApiStatusV2Input {
    return { providerRevision: pin.providerRevision, imageSha256: pin.imageSha256, url: this.#url, key: this.#key, dispatchBeforeMs };
  }
}

export type TelegramApiStatusRow =
  | { kind: "invalid" }
  | { kind: "probe"; credentials: ApiStatusCredentials };

export type TelegramApiStatusDecision =
  | { kind: "pass-through" }
  | { kind: "quarantine"; reason: "credential-text" | "command-arguments" | "unverified-prompt" | "text-limit" }
  | { kind: "open-prompt" }
  | { kind: "cancelled" }
  | { kind: "invalid"; reason: "empty" | "text-limit" | "line-break" | "invalid-whitespace" | "row-limit" | "mixed-cancellation" }
  | { kind: "batch"; rows: readonly TelegramApiStatusRow[] };

function resemblesCredentialText(text: string): boolean {
  return text.split(LINE_BREAK).some((part) => {
    const line = part.trim();
    if (AI_COMMAND.test(line)) return true;
    if (!HTTP_START.test(line)) return false;
    const boundary = line.search(/\s/u);
    // A single URL keeps its original subscription meaning. API status input
    // always separates the address and Key with whitespace.
    if (boundary < 0) return false;
    const rest = line.slice(boundary).trim();
    return rest.startsWith("|") || (!/\s/u.test(rest) && !URI_START.test(rest));
  });
}

function splitPrompt(text: string): [string, string] | null {
  const fields = text.split(/[ \t]+/u);
  if (fields.length === 2) {
    const [address, key] = fields;
    if (address.endsWith("|")) return [address.slice(0, -1), key];
    return [address, key.startsWith("|") ? key.slice(1) : key];
  }
  return fields.length === 3 && fields[1] === "|" ? [fields[0], fields[2]] : null;
}

function endpoint(address: string): string | null {
  if (/[\s\\\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(address) || /%(?![a-f0-9]{2})/iu.test(address)) return null;
  const match = /^https:\/\/([^/?#]+)(\/[^?#]*)?(?![\s\S])/iu.exec(address);
  if (!match || /[@%]/u.test(match[1]) || !AUTHORITY.test(match[1])) return null;
  try {
    if (new URL(address).port !== "") return null;
  } catch {
    return null;
  }
  const base = address.replace(/\/+$/u, "");
  return base.endsWith("/models") || base.endsWith("/chat/completions") ? base : `${base}/v1/models`;
}

function parsePromptRow(line: string): TelegramApiStatusRow {
  const pair = splitPrompt(line);
  if (!pair || URI_START.test(pair[1]) || !/^[!-~]{1,512}(?![\s\S])/u.test(pair[1])) return { kind: "invalid" };
  const [address, key] = pair;
  const url = endpoint(address);
  if (!url || encoder.encode(url).byteLength > MAX_URL_BYTES
    || encoder.encode(JSON.stringify({ url, key })).byteLength > MAX_RPC_BYTES) return { kind: "invalid" };
  return { kind: "probe", credentials: new ApiStatusCredentials(url, key) };
}

function parsePrompt(text: string): TelegramApiStatusDecision {
  if (text.length > MAX_PROMPT_LENGTH) return { kind: "invalid", reason: "text-limit" };
  if (UNSUPPORTED_PROMPT_BREAK.test(text)) return { kind: "invalid", reason: "line-break" };
  if (/[^\S \t\r\n]/u.test(text)) return { kind: "invalid", reason: "invalid-whitespace" };
  const lines = text.split(/\r?\n/u).map((line) => line.trim()).filter(Boolean);
  if (lines.length === 0) return { kind: "invalid", reason: "empty" };
  if (lines.length > MAX_PROMPT_ROWS) return { kind: "invalid", reason: "row-limit" };
  if (lines.some((line) => CANCEL.test(line))) {
    return lines.length === 1 ? { kind: "cancelled" } : { kind: "invalid", reason: "mixed-cancellation" };
  }
  return { kind: "batch", rows: lines.map(parsePromptRow) };
}

// The caller verifies command entities and prompt scope. The Provider independently validates the destination.
export function classifyTelegramApiStatusInput(input: TelegramApiStatusInput): TelegramApiStatusDecision {
  switch (input.kind) {
    case "ordinary":
      if (input.text.length > MAX_TEXT_LENGTH) return { kind: "quarantine", reason: "text-limit" };
      return resemblesCredentialText(input.text) ? { kind: "quarantine", reason: "credential-text" } : { kind: "pass-through" };
    case "ai-command":
      return input.args.length <= MAX_PROMPT_LENGTH && /^[ \t]*(?![\s\S])/u.test(input.args)
        ? { kind: "open-prompt" } : { kind: "quarantine", reason: "command-arguments" };
    case "unverified-prompt-reply":
      return { kind: "quarantine", reason: "unverified-prompt" };
    case "verified-prompt-reply":
      return parsePrompt(input.text);
  }
}

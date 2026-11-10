import { newGitHubSearchObservation, type GitHubSearchObservation } from "./github-search.ts";
import type { TelegramGitHubSearchUpdate, TelegramPolicy } from "./protocol.ts";

const ISOLATED_ORIGIN = "https://subs-bot-cf-dev-01.lilyya.workers.dev";
const FIXTURE = "addClass repo:jquery/jquery";
const PREFIX = "diagnostics/telegram-github-search/v1";
export const GITHUB_SEARCH_PROOF_ARM = `${PREFIX}/arm.json`;
const MAX_ARM_BYTES = 512;
const MAX_WINDOW_SECONDS = 600;

interface SearchProof {
  revision: string;
  policySha256: string;
  role: "admin" | "member";
  messageDate: number;
  receivedAt: number;
  observation: GitHubSearchObservation;
}

export function scopeGitHubSearchProof(
  origin: string, revision: string | undefined, policySha256: string | undefined, query: string,
  policy: TelegramPolicy, event: TelegramGitHubSearchUpdate, receivedAt: number,
): SearchProof | null {
  if (origin !== ISOLATED_ORIGIN || revision === undefined || !/^[0-9a-f]{40}(?![\s\S])/u.test(revision)
    || policySha256 === undefined || !/^[0-9a-f]{64}(?![\s\S])/u.test(policySha256)
    || policy.botUsername !== "test_cfsubs_bot" || query !== FIXTURE || event.args.trim() !== FIXTURE
    || event.chatType !== "private" || event.chatId !== event.actorId || event.threadId !== null) return null;
  const role = event.actorId === policy.adminId ? "admin" : event.actorId === policy.memberId ? "member" : null;
  return role ? { revision, policySha256, role, messageDate: event.messageDate, receivedAt,
    observation: newGitHubSearchObservation() } : null;
}

export async function writeGitHubSearchProof(bucket: R2Bucket, proof: SearchProof, receiptId: number): Promise<boolean> {
  const { observation, revision, policySha256, role, messageDate, receivedAt } = proof;
  if (!Number.isSafeInteger(receiptId) || receiptId < 1
    || (observation.settled !== "found" && observation.settled !== "empty" && observation.settled !== "unavailable")) return false;
  try {
    const object = await bucket.get(GITHUB_SEARCH_PROOF_ARM);
    if (!object) return false;
    if (object.size < 1 || object.size > MAX_ARM_BYTES || !(object.uploaded.getTime() <= receivedAt)) {
      void object.body.cancel().catch(() => {});
      return false;
    }
    const bytes = await object.arrayBuffer();
    if (bytes.byteLength !== object.size) return false;
    const arm = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes)) as Record<string, unknown> | null;
    if (!arm || typeof arm !== "object" || Array.isArray(arm) || Object.keys(arm).length !== 6
      || arm.version !== 1 || arm.revision !== revision || arm.policySha256 !== policySha256 || typeof arm.cohort !== "string"
      || !/^[0-9a-f]{32}(?![\s\S])/u.test(arm.cohort) || typeof arm.opensAt !== "number" || typeof arm.expiresAt !== "number"
      || !Number.isSafeInteger(arm.opensAt) || !Number.isSafeInteger(arm.expiresAt)
      || arm.opensAt < 1 || arm.expiresAt <= arm.opensAt || arm.expiresAt - arm.opensAt > MAX_WINDOW_SECONDS
      || messageDate < arm.opensAt || messageDate >= arm.expiresAt || receivedAt < arm.opensAt * 1000
      || Math.floor(Date.now() / 1000) >= arm.expiresAt) return false;
    const { grep } = observation;
    const evidence = JSON.stringify({ version: 1, cohort: arm.cohort, revision, role, receiptId,
      remainingMs: observation.remainingMs, repositoryStatus: observation.repositoryStatus,
      repositoryState: observation.repositoryState, grep: { phase: grep.phase, initializeStatus: grep.initializeStatus,
        initializedStatus: grep.initializedStatus, toolStatus: grep.toolStatus, timedOut: grep.timedOut, contentBlocks: grep.contentBlocks },
      candidates: observation.candidates, codeTimedOut: observation.codeTimedOut, verifiedFiles: observation.verifiedFiles,
      visibility: observation.visibility.map(({ status, outcome }) => ({ status, outcome })), settled: observation.settled });
    if (evidence.length > 1024) return false;
    const saved = await bucket.put(`${PREFIX}/${arm.cohort}/${role}.json`, evidence, {
      onlyIf: { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/json", cacheControl: "private, no-store" },
    });
    return saved !== null;
  } catch {
    // Diagnostic storage is best effort and cannot change the Telegram result.
    return false;
  }
}

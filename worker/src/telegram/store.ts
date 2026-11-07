import { inTelegramScope, type TelegramCommand, type TelegramPolicy } from "./protocol.ts";
import {
  insertTelegramViewTickets, TELEGRAM_VIEW_MARKER, type TelegramView, type TelegramViewTicket,
} from "./views.ts";
import {
  insertTelegramLifecycleTickets, TELEGRAM_LIFECYCLE_MARKER,
  type TelegramLifecycleReply, type TelegramLifecycleTicket,
} from "./lifecycle-actions.ts";
import { TELEGRAM_PRIVATE_CLAIM_MARKER } from "./private-claims.ts";
import { TELEGRAM_TEMP_MARKER, tempRawMarker, type TelegramTempReply } from "./temp-import.ts";
import type { TelegramTempRawGuard } from "./temp-raw.ts";
import { aggregateLinkDeliveryGuard, TELEGRAM_AGGREGATE_MARKER, type TelegramAggregateReply } from "./aggregate-actions.ts";
import { TELEGRAM_PATH_MARKER, type TelegramPathReply } from "./path-management.ts";
import { TELEGRAM_DOCUMENT_JOB_MARKER, type TelegramDocumentJobResult } from "./document-jobs.ts";
import { TELEGRAM_PRIVATE_SHARE_CREATION_MARKER, type TelegramPrivateShareCreationReply } from "./private-share-creation.ts";
import { insertSelectedRevokeTickets, selectedDeliveryGuard, TELEGRAM_SELECTED_MARKER,
  type SelectedRevokeTicket, type TelegramSelectedReply } from "./selected-export.ts";
import { TELEGRAM_SHORT_LINK_MARKER, type TelegramShortLinkGuard } from "./short-link-actions.ts";
import { insertTelegramSubscriptionReadTickets, TELEGRAM_SUBSCRIPTION_READ_MARKER,
  type TelegramSubscriptionReadTicket } from "./subscription-read.ts";
import { installTelegramBulkTrashTicket, TELEGRAM_BULK_TRASH_MARKER, type BulkTrashGuard } from "./bulk-trash.ts";
import { TELEGRAM_INLINE_SORT_MARKER, type TelegramInlineSortReply } from "./inline-sort.ts";
import { insertTelegramNodePageTickets, TELEGRAM_SUBSCRIPTION_NODE_MARKER, type TelegramNodePageTicket } from "./subscription-node-pages.ts";
import { telegramProviderReplyClock, telegramProviderReplyEligible, telegramProviderReplyMarker, telegramProviderReplySendGuard,
  type TelegramProviderReply } from "./provider-replies.ts";
import { TELEGRAM_INLINE_CONSENT_MARKER, type TelegramInlineConsentReply } from "./inline-search-consent.ts";
import { TELEGRAM_GITHUB_SEARCH_MARKER, telegramGitHubSearchEligible, telegramGitHubSearchMarker, telegramGitHubSendGuard,
  type TelegramGitHubReply } from "./github-search.ts";

export interface TelegramReplyLease extends TelegramCommand {
  receiptId: number;
  leaseId: string;
  attempts: number;
  view: TelegramView | null;
  lifecycle?: TelegramLifecycleReply;
  privateClaim?: { codeSha256: string };
  temp?: TelegramTempReply;
  tempRaw?: true;
  aggregate?: TelegramAggregateReply;
  selected?: TelegramSelectedReply;
  path?: TelegramPathReply;
  document?: { kind: TelegramDocumentJobResult; nodeCount: number | null };
  privateShareCreation?: true;
  shortLink?: true;
  subscriptionRead?: true;
  inlineSort?: TelegramInlineSortReply;
  subscriptionNodes?: true;
  providerOutcome?: TelegramProviderReply;
  bulkTrash?: true;
  inlineConsent?: TelegramInlineConsentReply;
  githubSearch?: TelegramGitHubReply;
}

export type TelegramReplyOutcome =
  | { kind: "sent"; messageId: number }
  | { kind: "retry"; delaySeconds: number }
  | { kind: "failed" | "uncertain" };

const LEASE_SECONDS = 30;
const MAX_REPLY_AGE_SECONDS = 15 * 60;
const MAX_ATTEMPTS = 4;
const REAP_LIMIT = 40;

type ReplyAccess = "allowed" | "denied" | "none";

type ReplyRow = Omit<TelegramReplyLease,
  "view" | "lifecycle" | "privateClaim" | "temp" | "tempRaw" | "aggregate" | "selected" | "path" | "document" |
  "privateShareCreation" | "subscriptionRead" | "shortLink" | "inlineSort" | "subscriptionNodes" | "providerOutcome" |
  "bulkTrash" | "inlineConsent" | "githubSearch"> & {
  viewKind: TelegramView["kind"] | null;
  afterId: number | null;
  afterEpoch: number | null;
  lifecycleKind: TelegramLifecycleReply["kind"] | null;
  lifecycleSubscriptionId: number | null;
  lifecycleExpectedRevision: number | null;
  privateClaimCodeSha256: string | null;
  tempKind: TelegramTempReply["kind"] | null;
  tempNodeCount: number | null;
  tempTotalCount: number | null;
  tempMalformedCount: number | null;
  tempUnsupportedCount: number | null;
  tempIgnoredCount: number | null;
  tempRawMarker: number;
  aggregateResult: TelegramAggregateReply["result"] | null;
  aggregateRevision: number | null;
  aggregateCodeSha256: string | null;
  selectedResult: TelegramSelectedReply["result"] | null;
  selectedCodeSha256: string | null;
  pathKind: TelegramPathReply["kind"] | null;
  pathAfterId: number | null;
  pathAffectedCount: number | null;
  documentKind: TelegramDocumentJobResult | null;
  documentNodeCount: number | null;
  privateShareCreationReceipt: number | null;
  shortLinkReceipt: number | null;
  subscriptionReadReceipt: number | null;
  inlineSortKind: TelegramInlineSortReply["kind"] | null;
  inlineSortMode: TelegramInlineSortReply["mode"];
  subscriptionNodeMarker: number;
  providerResult: TelegramProviderReply | null;
  bulkTrashMarker: number;
  inlineConsentKind: TelegramInlineConsentReply | null;
  githubSearchState: TelegramGitHubReply["state"] | null;
  githubSearchResults: string | null;
};

function supportedReceipt(alias: "inbox" | "earlier", includeAggregate = false, includePrivateShareCreation = false,
  includeSubscriptionRead = false, includeShortLinks = false, includeInlineSort = false, includeSubscriptionNodes = false,
  includeProvider = false, includeBulkTrash = false, includeInlineConsent = false, includeGitHubSearch = false): string {
  return `(${alias}.receipt_nonce IS NULL OR (${alias}.receipt_nonce = '${TELEGRAM_VIEW_MARKER}'
    AND EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id = ${alias}.receipt_id))
    OR (${alias}.receipt_nonce = '${TELEGRAM_LIFECYCLE_MARKER}'
    AND EXISTS (SELECT 1 FROM telegram_lifecycle_action WHERE receipt_id = ${alias}.receipt_id))
    OR (${alias}.receipt_nonce = '${TELEGRAM_PRIVATE_CLAIM_MARKER}'
    AND EXISTS (SELECT 1 FROM telegram_private_claim WHERE receipt_id = ${alias}.receipt_id))
    OR (${alias}.receipt_nonce = '${TELEGRAM_TEMP_MARKER}'
    AND EXISTS (SELECT 1 FROM telegram_temp_reply WHERE receipt_id = ${alias}.receipt_id))
    OR (${tempRawMarker(alias)} AND ${alias}.chat_type='private' AND ${alias}.actor_id=${alias}.chat_id
      AND ${alias}.thread_id IS NULL AND EXISTS (SELECT 1 FROM telegram_temp_reply
        WHERE receipt_id=${alias}.receipt_id AND kind='summary'))
    OR (${alias}.receipt_nonce = '${TELEGRAM_PATH_MARKER}' AND ${alias}.chat_type = 'private'
    AND ${alias}.actor_id = ${alias}.chat_id AND ${alias}.thread_id IS NULL
    AND EXISTS (SELECT 1 FROM telegram_path_reply WHERE receipt_id = ${alias}.receipt_id))
    OR (${alias}.receipt_nonce = '${TELEGRAM_DOCUMENT_JOB_MARKER}' AND ${alias}.chat_type = 'private'
    AND ${alias}.chat_id = ${alias}.actor_id AND ${alias}.thread_id IS NULL AND EXISTS (
      SELECT 1 FROM telegram_document_jobs AS job WHERE job.receipt_id = ${alias}.receipt_id
        AND job.bot_id = ${alias}.bot_id AND job.actor_id = ${alias}.actor_id AND job.state = 'done'
        AND (job.result_code <> 'saved' OR EXISTS (
          SELECT 1 FROM telegram_document_saved_counts WHERE receipt_id = job.receipt_id
        ))))
    ${includeAggregate ? `OR (${alias}.receipt_nonce = '${TELEGRAM_AGGREGATE_MARKER}'
    AND EXISTS (SELECT 1 FROM telegram_aggregate_actions WHERE receipt_id = ${alias}.receipt_id))
    OR (${alias}.receipt_nonce = '${TELEGRAM_SELECTED_MARKER}' AND ${alias}.chat_type = 'private'
    AND ${alias}.chat_id = ${alias}.actor_id AND ${alias}.thread_id IS NULL
    AND EXISTS (SELECT 1 FROM telegram_selected_actions WHERE receipt_id = ${alias}.receipt_id))` : ""}
    ${includePrivateShareCreation ? `OR (${alias}.receipt_nonce = '${TELEGRAM_PRIVATE_SHARE_CREATION_MARKER}'
    AND ${alias}.chat_type = 'private' AND ${alias}.chat_id = ${alias}.actor_id AND ${alias}.thread_id IS NULL
    AND EXISTS (SELECT 1 FROM telegram_private_share_creations AS creation WHERE creation.receipt_id = ${alias}.receipt_id
      AND creation.bot_id = ${alias}.bot_id AND creation.actor_id = ${alias}.actor_id AND creation.state = 'published'))` : ""}
    ${includeSubscriptionRead ? `OR (${alias}.receipt_nonce = '${TELEGRAM_SUBSCRIPTION_READ_MARKER}' AND EXISTS (
      SELECT 1 FROM telegram_subscription_read AS detail WHERE detail.receipt_id=${alias}.receipt_id
        AND (detail.kind NOT IN ('detail','format') OR (${alias}.chat_type='private'
          AND ${alias}.actor_id=${alias}.chat_id AND ${alias}.thread_id IS NULL))))` : ""}
    ${includeShortLinks ? `OR (${alias}.receipt_nonce='${TELEGRAM_SHORT_LINK_MARKER}' AND ${alias}.chat_type='private'
      AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL
      AND EXISTS (SELECT 1 FROM telegram_short_link_actions WHERE receipt_id=${alias}.receipt_id))` : ""}
    ${includeInlineSort ? `OR (${alias}.receipt_nonce = '${TELEGRAM_INLINE_SORT_MARKER}' AND ${alias}.command = 'help'
      AND ${alias}.chat_type = 'private' AND ${alias}.actor_id = ${alias}.chat_id AND ${alias}.thread_id IS NULL
      AND EXISTS (SELECT 1 FROM telegram_inline_sort_reply WHERE receipt_id = ${alias}.receipt_id))` : ""}
    ${includeSubscriptionNodes ? `OR (${alias}.receipt_nonce='${TELEGRAM_SUBSCRIPTION_NODE_MARKER}' AND ${alias}.command='help'
      AND ${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL
      AND EXISTS (SELECT 1 FROM telegram_subscription_node_page WHERE receipt_id=${alias}.receipt_id))` : ""}
    ${includeProvider ? `OR ${telegramProviderReplyMarker(alias)}` : ""}
    ${includeBulkTrash ? `OR (${alias}.receipt_nonce='${TELEGRAM_BULK_TRASH_MARKER}' AND ${alias}.command='help'
      AND ${alias}.chat_type='private' AND ${alias}.actor_id=${alias}.chat_id AND ${alias}.thread_id IS NULL
      AND EXISTS (SELECT 1 FROM telegram_bulk_trash WHERE receipt_id=${alias}.receipt_id))` : ""}
    ${includeInlineConsent ? `OR (${alias}.receipt_nonce='${TELEGRAM_INLINE_CONSENT_MARKER}' AND ${alias}.command='help'
      AND ${alias}.chat_type='private' AND ${alias}.actor_id=${alias}.chat_id AND ${alias}.thread_id IS NULL
      AND EXISTS (SELECT 1 FROM telegram_inline_search_consent AS consent WHERE consent.receipt_id=${alias}.receipt_id
        AND consent.bot_id=${alias}.bot_id AND consent.actor_id=${alias}.actor_id))` : ""}
    ${includeGitHubSearch ? `OR ${telegramGitHubSearchMarker(alias)}` : ""})`;
}

function replyClock(includeProvider: boolean, alias: "inbox" | "earlier" = "inbox"): string {
  return includeProvider ? telegramProviderReplyClock(alias) : `${alias}.received_at`;
}

export async function acceptTelegramCommand(
  db: D1Database,
  policy: TelegramPolicy,
  command: TelegramCommand,
): Promise<"accepted" | "duplicate"> {
  if (!inTelegramScope(policy, command)) throw new RangeError("Telegram command is outside the isolation scope.");

  const receipt = crypto.randomUUID();
  const key = [policy.botId, command.updateId, receipt] as const;
  const steps = [db.prepare(`
    INSERT INTO telegram_inbox
      (bot_id, update_id, actor_id, chat_id, chat_type, message_id, message_date, thread_id, command, receipt_nonce)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT (bot_id, update_id) DO NOTHING
  `).bind(policy.botId, command.updateId, command.actorId, command.chatId, command.chatType,
    command.messageId, command.messageDate, command.threadId, command.command, receipt)];

  if (command.command === "auth-add" || command.command === "auth-remove") {
    // Only the explicit admin's own private command can change the configured member.
    // A delayed older grant cannot undo a newer revocation from that same chat.
    steps.push(db.prepare(`
      INSERT INTO telegram_auth (bot_id, user_id, allowed, message_date, message_id)
      SELECT bot_id, ?, ?, message_date, message_id FROM telegram_inbox
      WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
        AND chat_type = 'private' AND actor_id = ? AND chat_id = actor_id
      ON CONFLICT (bot_id, user_id) DO UPDATE SET
        allowed = excluded.allowed, message_date = excluded.message_date, message_id = excluded.message_id
      WHERE (excluded.message_date, excluded.message_id) > (telegram_auth.message_date, telegram_auth.message_id)
    `).bind(policy.memberId, command.command === "auth-add" ? 1 : 0, ...key, policy.adminId));
  }

  steps.push(
    db.prepare(`
      INSERT INTO telegram_outbox (receipt_id)
      SELECT receipt_id FROM telegram_inbox WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
    `).bind(...key),
    db.prepare(`
      UPDATE telegram_inbox SET receipt_nonce = NULL
      WHERE bot_id = ? AND update_id = ? AND receipt_nonce = ?
      RETURNING receipt_id
    `).bind(...key),
  );
  // Clearing the nonce in the same transaction fences even a replay of the identical batch.
  const results = await db.batch(steps);
  const receiptResult = results.at(-1);
  if (!receiptResult || results.length !== steps.length || results.some((result) => !result.success)) {
    throw new Error("Telegram command receipt could not be confirmed.");
  }
  return receiptResult.results.length ? "accepted" : "duplicate";
}

export async function isTelegramMemberAllowed(db: D1Database, policy: TelegramPolicy): Promise<boolean> {
  const row = await db.prepare("SELECT allowed FROM telegram_auth WHERE bot_id = ? AND user_id = ?")
    .bind(policy.botId, policy.memberId).first<{ allowed: number }>();
  return row === null || row.allowed === 1;
}

export async function claimTelegramReply(db: D1Database, botId: string, includeAggregate = false,
  includePrivateShareCreation = false, includeSubscriptionRead = false, includeShortLinks = false, includeInlineSort = false,
  includeSubscriptionNodes = false, providerPolicy?: TelegramPolicy, includeBulkTrash = false, includeInlineConsent = false,
  gitHubSearch?: TelegramPolicy | "unavailable"): Promise<TelegramReplyLease | null> {
  const gitHubSearchPolicy = gitHubSearch === "unavailable" ? undefined : gitHubSearch;
  if (providerPolicy && providerPolicy.botId !== botId) throw new Error("Telegram provider reply scope differs.");
  if (gitHubSearchPolicy && gitHubSearchPolicy.botId !== botId) throw new Error("Telegram GitHub search reply scope differs.");
  const leaseId = crypto.randomUUID();
  const includeProvider = providerPolicy !== undefined;
  const includeGitHubSearch = gitHubSearchPolicy !== undefined;
  const providerCurrent = telegramProviderReplyEligible(providerPolicy, "inbox");
  const earlierProviderCurrent = telegramProviderReplyEligible(providerPolicy, "earlier");
  const githubCurrent = telegramGitHubSearchEligible(gitHubSearchPolicy, "inbox");
  const earlierGithubCurrent = telegramGitHubSearchEligible(gitHubSearchPolicy, "earlier");
  const earlierActive = "earlier.receipt_id < inbox.receipt_id AND earlier_reply.state IN ('pending', 'leased', 'sending')";
  // A provider reply or search can become ready after a newer reply has started delivery.
  const searchPair = `(inbox.receipt_nonce IS '${TELEGRAM_GITHUB_SEARCH_MARKER}' OR
    earlier.receipt_nonce IS '${TELEGRAM_GITHUB_SEARCH_MARKER}')`;
  const sameChatBlocker = includeProvider ? `(
    (earlier_reply.state = 'sending' AND earlier_reply.lease_until > unixepoch())
    OR ((${earlierProviderCurrent.sql}) AND (${earlierGithubCurrent.sql})
      AND ${replyClock(true, "earlier")} + ${MAX_REPLY_AGE_SECONDS} > unixepoch() AND (
        (earlier_reply.state = 'leased' AND earlier_reply.lease_until > unixepoch())
        OR (earlier.receipt_id < inbox.receipt_id AND earlier_reply.state = 'pending' AND earlier_reply.attempts < ${MAX_ATTEMPTS})
      ))
  )` : includeGitHubSearch ? `(
    (NOT ${searchPair} AND ${earlierActive}) OR (${searchPair} AND (
      (earlier_reply.state IN ('leased', 'sending') AND earlier_reply.lease_until > unixepoch())
      OR (earlier.receipt_id < inbox.receipt_id AND earlier_reply.state = 'pending'
        AND earlier_reply.attempts < ${MAX_ATTEMPTS} AND earlier.received_at + ${MAX_REPLY_AGE_SECONDS} > unixepoch()
        AND ${earlierGithubCurrent.sql}))))` : earlierActive;
  // A ready invocation can still own a GitHub send when a later probe fails.
  // Preserve that same-chat lease without reading the optional companion table.
  const activeGitHubLease = gitHubSearch === "unavailable" ? `OR (
    earlier.receipt_nonce = '${TELEGRAM_GITHUB_SEARCH_MARKER}' AND earlier.command = 'help'
    AND earlier.chat_type = 'private' AND earlier.chat_id = earlier.actor_id AND earlier.thread_id IS NULL
    AND earlier_reply.state IN ('leased', 'sending') AND earlier_reply.lease_until > unixepoch()
  )` : "";
  const aggregateColumns = includeAggregate ? `aggregate.result AS aggregateResult,
    aggregate.revision AS aggregateRevision, aggregate.code_sha256 AS aggregateCodeSha256,
    selected.result AS selectedResult, selected.code_sha256 AS selectedCodeSha256`
    : "NULL AS aggregateResult, NULL AS aggregateRevision, NULL AS aggregateCodeSha256, NULL AS selectedResult, NULL AS selectedCodeSha256";
  const [write, read] = await db.batch<ReplyRow>([
    db.prepare(`
      UPDATE telegram_outbox
      SET state = 'leased', attempts = attempts + 1, lease_id = ?, lease_until = unixepoch() + ${LEASE_SECONDS}
      WHERE receipt_id = (
        SELECT inbox.receipt_id FROM telegram_outbox AS reply
        JOIN telegram_inbox AS inbox USING (receipt_id)
        WHERE inbox.bot_id = ? AND ${supportedReceipt("inbox", includeAggregate, includePrivateShareCreation, includeSubscriptionRead,
          includeShortLinks, includeInlineSort, includeSubscriptionNodes, includeProvider, includeBulkTrash, includeInlineConsent, includeGitHubSearch)}
          AND ${providerCurrent.sql} AND ${githubCurrent.sql}
          AND reply.state = 'pending'
          AND reply.due_at <= unixepoch() AND reply.attempts < ${MAX_ATTEMPTS}
          AND ${replyClock(includeProvider)} + ${MAX_REPLY_AGE_SECONDS} > unixepoch()
          AND NOT EXISTS (
            SELECT 1 FROM telegram_inbox AS earlier
            JOIN telegram_outbox AS earlier_reply USING (receipt_id)
            WHERE earlier.bot_id = inbox.bot_id AND earlier.actor_id = inbox.actor_id AND earlier.chat_id = inbox.chat_id
              AND ((${supportedReceipt("earlier", includeAggregate, includePrivateShareCreation, includeSubscriptionRead,
                includeShortLinks, includeInlineSort, includeSubscriptionNodes, includeProvider, includeBulkTrash, includeInlineConsent, includeGitHubSearch)}
                AND ${sameChatBlocker}) ${activeGitHubLease})
          )
        ORDER BY inbox.receipt_id LIMIT 1
      )
    `).bind(leaseId, botId, ...providerCurrent.bindings, ...githubCurrent.bindings,
      ...earlierProviderCurrent.bindings, ...earlierGithubCurrent.bindings),
    db.prepare(`
      SELECT inbox.receipt_id AS receiptId, inbox.update_id AS updateId, inbox.actor_id AS actorId,
        inbox.chat_id AS chatId, inbox.chat_type AS chatType,
        inbox.message_id AS messageId, inbox.message_date AS messageDate, inbox.thread_id AS threadId,
        inbox.command, reply.lease_id AS leaseId, reply.attempts,
        page.kind AS viewKind, page.after_id AS afterId, page.after_epoch AS afterEpoch,
        action.kind AS lifecycleKind, action.subscription_id AS lifecycleSubscriptionId,
        action.expected_revision AS lifecycleExpectedRevision, claim.code_sha256 AS privateClaimCodeSha256,
        temp.kind AS tempKind, temp.node_count AS tempNodeCount, temp.total_count AS tempTotalCount,
        temp.malformed_count AS tempMalformedCount, temp.unsupported_count AS tempUnsupportedCount,
        temp.ignored_count AS tempIgnoredCount,
        CASE WHEN ${tempRawMarker("inbox")} THEN 1 ELSE 0 END AS tempRawMarker, ${aggregateColumns},
        path.kind AS pathKind, path.after_id AS pathAfterId, path.affected_count AS pathAffectedCount,
        document.result_code AS documentKind, saved.node_count AS documentNodeCount,
        ${includePrivateShareCreation ? "creation.receipt_id" : "NULL"} AS privateShareCreationReceipt,
        ${includeSubscriptionRead ? "detail.receipt_id" : "NULL"} AS subscriptionReadReceipt,
        ${includeShortLinks ? "short.receipt_id" : "NULL"} AS shortLinkReceipt,
        ${includeInlineSort ? "sort.kind" : "NULL"} AS inlineSortKind,
        ${includeInlineSort ? "sort.mode" : "NULL"} AS inlineSortMode,
        CASE WHEN inbox.receipt_nonce='${TELEGRAM_SUBSCRIPTION_NODE_MARKER}' THEN 1 ELSE 0 END AS subscriptionNodeMarker,
        ${includeProvider ? "provider.outcome" : "NULL"} AS providerResult,
        CASE WHEN inbox.receipt_nonce='${TELEGRAM_BULK_TRASH_MARKER}' THEN 1 ELSE 0 END AS bulkTrashMarker,
        ${includeInlineConsent ? "consent.kind" : "NULL"} AS inlineConsentKind,
        ${includeGitHubSearch ? "github.state" : "NULL"} AS githubSearchState,
        ${includeGitHubSearch ? "github.public_results" : "NULL"} AS githubSearchResults
      FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
      LEFT JOIN telegram_view AS page ON page.receipt_id = inbox.receipt_id AND inbox.receipt_nonce = '${TELEGRAM_VIEW_MARKER}'
      LEFT JOIN telegram_lifecycle_action AS action ON action.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_LIFECYCLE_MARKER}'
      LEFT JOIN telegram_private_claim AS claim ON claim.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_PRIVATE_CLAIM_MARKER}'
      LEFT JOIN telegram_temp_reply AS temp ON temp.receipt_id = inbox.receipt_id
        AND (inbox.receipt_nonce = '${TELEGRAM_TEMP_MARKER}' OR ${tempRawMarker("inbox")})
      ${includeAggregate ? `LEFT JOIN telegram_aggregate_actions AS aggregate ON aggregate.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_AGGREGATE_MARKER}'
      LEFT JOIN telegram_selected_actions AS selected ON selected.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_SELECTED_MARKER}'` : ""}
      LEFT JOIN telegram_path_reply AS path ON path.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_PATH_MARKER}'
      LEFT JOIN telegram_document_jobs AS document ON document.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_DOCUMENT_JOB_MARKER}'
      LEFT JOIN telegram_document_saved_counts AS saved ON saved.receipt_id = document.receipt_id
      ${includePrivateShareCreation ? `LEFT JOIN telegram_private_share_creations AS creation ON creation.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_PRIVATE_SHARE_CREATION_MARKER}' AND creation.state = 'published'` : ""}
      ${includeShortLinks ? `LEFT JOIN telegram_short_link_actions AS short ON short.receipt_id=inbox.receipt_id
        AND inbox.receipt_nonce='${TELEGRAM_SHORT_LINK_MARKER}'` : ""}
      ${includeSubscriptionRead ? `LEFT JOIN telegram_subscription_read AS detail ON detail.receipt_id=inbox.receipt_id
        AND inbox.receipt_nonce='${TELEGRAM_SUBSCRIPTION_READ_MARKER}'` : ""}
      ${includeInlineSort ? `LEFT JOIN telegram_inline_sort_reply AS sort ON sort.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_INLINE_SORT_MARKER}'` : ""}
      ${includeProvider ? `LEFT JOIN telegram_provider_replies AS provider ON provider.receipt_id=inbox.receipt_id
        AND ${telegramProviderReplyMarker("inbox")}` : ""}
      ${includeInlineConsent ? `LEFT JOIN telegram_inline_search_consent AS consent ON consent.receipt_id=inbox.receipt_id
        AND inbox.receipt_nonce='${TELEGRAM_INLINE_CONSENT_MARKER}'` : ""}
      ${includeGitHubSearch ? `LEFT JOIN telegram_github_search AS github ON github.receipt_id = inbox.receipt_id
        AND inbox.receipt_nonce = '${TELEGRAM_GITHUB_SEARCH_MARKER}'` : ""}
      WHERE reply.lease_id = ? AND reply.state = 'leased' AND inbox.bot_id = ?
        AND ${supportedReceipt("inbox", includeAggregate, includePrivateShareCreation, includeSubscriptionRead,
          includeShortLinks, includeInlineSort, includeSubscriptionNodes, includeProvider, includeBulkTrash, includeInlineConsent, includeGitHubSearch)}
    `).bind(leaseId, botId),
  ]);
  if (!write?.success || !read?.success) throw new Error("Telegram reply claim could not be confirmed.");
  const row = read.results[0];
  if (!row) return null;
  const { viewKind, afterId, afterEpoch, lifecycleKind, lifecycleSubscriptionId, lifecycleExpectedRevision,
    privateClaimCodeSha256, tempKind, tempNodeCount, tempTotalCount, tempMalformedCount,
    tempUnsupportedCount, tempIgnoredCount, tempRawMarker: rawMarker, aggregateResult, aggregateRevision, aggregateCodeSha256,
    selectedResult, selectedCodeSha256,
    pathKind, pathAfterId, pathAffectedCount,
    documentKind, documentNodeCount, privateShareCreationReceipt, subscriptionReadReceipt, shortLinkReceipt,
    inlineSortKind, inlineSortMode, subscriptionNodeMarker, providerResult, bulkTrashMarker, inlineConsentKind,
    githubSearchState, githubSearchResults, ...lease } = row;
  const lifecycle = lifecycleKind === null || lifecycleSubscriptionId === null || lifecycleExpectedRevision === null
    ? undefined : { kind: lifecycleKind, subscriptionId: lifecycleSubscriptionId, expectedLifecycleRevision: lifecycleExpectedRevision };
  // The joined temp companion declares every count NOT NULL when its kind is present.
  const temp = tempKind === null ? undefined : { kind: tempKind, nodeCount: tempNodeCount!, totalCount: tempTotalCount!,
    malformedCount: tempMalformedCount!, unsupportedCount: tempUnsupportedCount!, ignoredCount: tempIgnoredCount! };
  return { ...lease, view: viewKind === null ? null : { kind: viewKind, afterId, afterEpoch },
    ...(lifecycle ? { lifecycle } : {}),
    ...(temp ? { temp } : {}),
    ...(rawMarker === 1 ? { tempRaw: true as const } : {}),
    ...(aggregateResult === null ? {} : { aggregate: { result: aggregateResult, revision: aggregateRevision,
      codeSha256: aggregateCodeSha256 } }),
    ...(selectedResult === null ? {} : { selected: { result: selectedResult, codeSha256: selectedCodeSha256 } }),
    ...(pathKind === null || pathAffectedCount === null ? {} :
      { path: { kind: pathKind, afterId: pathAfterId, affectedCount: pathAffectedCount } }),
    ...(documentKind === null ? {} : { document: { kind: documentKind, nodeCount: documentNodeCount } }),
    ...(privateShareCreationReceipt === null ? {} : { privateShareCreation: true as const }),
    ...(shortLinkReceipt === null ? {} : { shortLink: true as const }),
    ...(subscriptionReadReceipt === null ? {} : { subscriptionRead: true as const }),
    ...(inlineSortKind === null ? {} : { inlineSort: { kind: inlineSortKind, mode: inlineSortMode } }),
    ...(subscriptionNodeMarker === 1 ? { subscriptionNodes: true as const } : {}),
    ...(providerResult === null ? {} : { providerOutcome: providerResult }),
    ...(bulkTrashMarker === 1 ? { bulkTrash: true as const } : {}),
    ...(inlineConsentKind === null ? {} : { inlineConsent: inlineConsentKind }),
    ...(githubSearchState === null ? {} : { githubSearch: { state: githubSearchState, publicResults: githubSearchResults } }),
    ...(privateClaimCodeSha256 === null ? {} : { privateClaim: { codeSha256: privateClaimCodeSha256 } }) };
}

function beginReplyStatement(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  access: ReplyAccess | "private-claim",
  guard?: { sql: string; bindings: readonly (string | number | null)[] },
): D1PreparedStatement {
  const provider = lease.providerOutcome === undefined ? null : telegramProviderReplySendGuard(policy, lease.providerOutcome);
  const exactDocumentEpoch = lease.document?.kind === "saved" && access === "allowed" && lease.actorId !== policy.adminId
    ? `AND EXISTS (
      SELECT 1 FROM telegram_document_jobs AS job LEFT JOIN telegram_auth AS auth
        ON auth.bot_id = job.bot_id AND auth.user_id = job.actor_id
      WHERE job.receipt_id = inbox.receipt_id AND job.result_code = 'saved'
        AND job.auth_message_date = COALESCE(auth.message_date, 0) AND job.auth_message_id = COALESCE(auth.message_id, 0)
    )` : "";
  return db.prepare(`
    UPDATE telegram_outbox SET state = 'sending', lease_until = unixepoch() + ${LEASE_SECONDS}
    WHERE state = 'leased' AND lease_id = ? AND attempts = ? AND lease_until > unixepoch()
      AND receipt_id = (
        SELECT inbox.receipt_id FROM telegram_inbox AS inbox
        WHERE inbox.bot_id = ? AND inbox.update_id = ? AND inbox.receipt_id = ? AND inbox.actor_id = ? AND inbox.chat_id = ?
          AND inbox.chat_type = ? AND inbox.message_id = ? AND inbox.message_date = ? AND inbox.thread_id IS ?
          AND inbox.command = ? AND ${supportedReceipt("inbox", lease.aggregate !== undefined || lease.selected !== undefined,
            lease.privateShareCreation === true, lease.subscriptionRead === true, lease.shortLink === true,
            lease.inlineSort !== undefined, lease.subscriptionNodes === true, provider !== null, lease.bulkTrash === true,
            lease.inlineConsent !== undefined, lease.githubSearch !== undefined)}
          AND ${replyClock(provider !== null)} + ${MAX_REPLY_AGE_SECONDS} > unixepoch()
          ${provider ? `AND (${provider.sql})` : ""}
          ${guard ? `AND (${guard.sql})` : ""}
          ${exactDocumentEpoch}
          AND (
            (? = 'private-claim' AND inbox.receipt_nonce = '${TELEGRAM_PRIVATE_CLAIM_MARKER}'
              AND inbox.chat_type = 'private' AND inbox.actor_id = inbox.chat_id AND inbox.thread_id IS NULL
              AND EXISTS (SELECT 1 FROM telegram_private_claim WHERE receipt_id = inbox.receipt_id AND code_sha256 = ?))
            OR (inbox.receipt_nonce IS NOT '${TELEGRAM_PRIVATE_CLAIM_MARKER}' AND (
              (? = 'none' AND inbox.command IN ('auth-list', 'auth-add', 'auth-remove', 'auth-usage')) OR (
                CASE WHEN inbox.actor_id = ? THEN 1 ELSE COALESCE((
                  SELECT allowed FROM telegram_auth WHERE bot_id = inbox.bot_id AND user_id = inbox.actor_id
                ), 1) END = CASE ? WHEN 'allowed' THEN 1 WHEN 'denied' THEN 0 ELSE -1 END
              )
            ))
          )
      )
    RETURNING receipt_id
  `).bind(lease.leaseId, lease.attempts, policy.botId, lease.updateId, lease.receiptId, lease.actorId, lease.chatId, lease.chatType,
    lease.messageId, lease.messageDate, lease.threadId, lease.command, ...(provider?.bindings ?? []), ...(guard?.bindings ?? []),
    access, lease.privateClaim?.codeSha256 ?? null,
    access, policy.adminId, access);
}

export function prepareTelegramPrivateClaimBegin(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
): D1PreparedStatement | null {
  if (!inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null || !lease.privateClaim) {
    return null;
  }
  return beginReplyStatement(db, policy, lease, "private-claim");
}

export async function beginTelegramAggregateLinkReply(db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease): Promise<boolean> {
  if (!inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null || !lease.aggregate) return false;
  const guard = aggregateLinkDeliveryGuard(policy, lease.aggregate);
  return guard !== null && await beginReplyStatement(db, policy, lease, "allowed", guard).first() !== null;
}

export async function beginTelegramShortLinkReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, guard: TelegramShortLinkGuard,
): Promise<boolean> {
  if (!lease.shortLink || lease.chatType !== "private" || lease.threadId !== null || !inTelegramScope(policy, lease)) return false;
  return await beginReplyStatement(db, policy, lease, "allowed", guard).first() !== null;
}

export async function beginTelegramTempRawReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, guard: TelegramTempRawGuard,
): Promise<boolean> {
  if (!lease.tempRaw || lease.temp?.kind !== "summary" || lease.chatType !== "private" || lease.threadId !== null
    || !inTelegramScope(policy, lease)) return false;
  return await beginReplyStatement(db, policy, lease, "allowed", guard).first() !== null;
}

export async function beginTelegramBulkTrashReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, guard: BulkTrashGuard, ticketSha256?: string,
): Promise<boolean> {
  if (!lease.bulkTrash || !inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return false;
  if (!ticketSha256) return await beginReplyStatement(db, policy, lease, "allowed", guard).first() !== null;
  // The transition must guarantee exactly the preview row the next statement updates.
  const previewGuard = { sql: `(${guard.sql}) AND EXISTS (SELECT 1 FROM telegram_bulk_trash AS preview
    WHERE preview.receipt_id=inbox.receipt_id AND preview.kind='preview' AND preview.confirmed_by_receipt_id IS NULL)`,
    bindings: guard.bindings };
  const [state, ticket, verified] = await db.batch<{ receipt_id: number }>([
    beginReplyStatement(db, policy, lease, "allowed", previewGuard), installTelegramBulkTrashTicket(db, lease, ticketSha256),
    // Fail the batch if this sending attempt did not retain its exact ticket.
    db.prepare(`UPDATE telegram_inbox AS inbox SET command=CASE WHEN EXISTS (
      SELECT 1 FROM telegram_bulk_trash AS preview WHERE preview.receipt_id=inbox.receipt_id
        AND preview.token_sha256=? AND preview.origin_attempt=? AND preview.confirmed_by_receipt_id IS NULL
    ) THEN command END WHERE inbox.receipt_id=? AND EXISTS (SELECT 1 FROM telegram_outbox AS reply
      WHERE reply.receipt_id=inbox.receipt_id AND reply.state='sending' AND reply.lease_id=? AND reply.attempts=?)`)
      .bind(ticketSha256, lease.attempts, lease.receiptId, lease.leaseId, lease.attempts),
  ]);
  const changed = state?.results.length;
  if (!state?.success || (changed !== 0 && changed !== 1) || (changed === 1 && state.results[0].receipt_id !== lease.receiptId)
    || !ticket?.success || ticket.meta.changes !== changed || !verified?.success || verified.meta.changes !== changed) {
    throw new Error("Telegram bulk trash reply could not begin.");
  }
  return changed === 1;
}

export async function beginTelegramPrivateShareCreationReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, reply: TelegramPrivateShareCreationReply,
): Promise<boolean> {
  if (!inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null || !lease.privateShareCreation) return false;
  return await beginReplyStatement(db, policy, lease, "allowed", reply.guard).first() !== null;
}

export async function beginTelegramSelectedLinkReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, tickets: readonly SelectedRevokeTicket[],
): Promise<boolean> {
  if (!inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null || !lease.selected) return false;
  const guard = selectedDeliveryGuard(policy, lease.selected);
  if (guard === null || (lease.selected.result === "issued" && tickets.length !== 1)) return false;
  const insertTickets = insertSelectedRevokeTickets(db, lease.receiptId, lease.attempts, lease.leaseId, tickets);
  const targets = JSON.stringify(tickets.map(({ codeSha256 }) => codeSha256));
  const exactTargets = {
    sql: `(${guard.sql}) AND ? = (
      SELECT count(*) FROM json_each(?) AS item JOIN telegram_selected_links AS selected ON selected.code_sha256=item.value
      JOIN aggregate_links AS link USING(code_sha256)
      JOIN telegram_selected_actions AS action ON action.receipt_id=inbox.receipt_id
      WHERE selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id
        AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.bot_id IS NULL AND link.revoked_at IS NULL
        AND (action.result='limit' OR (action.result='issued' AND action.code_sha256=selected.code_sha256))
    ) ${lease.selected.result === "limit" ? `AND ? = (
      SELECT count(*) FROM telegram_selected_links AS selected JOIN aggregate_links AS link USING(code_sha256)
      WHERE selected.bot_id=inbox.bot_id AND selected.actor_id=inbox.actor_id AND link.revoked_at IS NULL
        AND link.owner_id=inbox.actor_id AND link.kind='selected' AND link.bot_id IS NULL
    )` : ""}`,
    bindings: [...guard.bindings, tickets.length, targets, ...(lease.selected.result === "limit" ? [tickets.length] : [])],
  };
  const [state, ticket] = await db.batch<{ receipt_id: number }>([
    beginReplyStatement(db, policy, lease, "allowed", exactTargets),
    insertTickets,
  ]);
  const changed = state?.results.length;
  if (!state?.success || (changed !== 0 && changed !== 1) || (changed === 1 && state.results[0].receipt_id !== lease.receiptId)
    || !ticket?.success || ticket.meta.changes !== changed * tickets.length) throw new Error("Selected export reply could not begin.");
  return changed === 1;
}

export async function beginTelegramReply(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  access: ReplyAccess,
  tickets: readonly TelegramViewTicket[] = [],
  lifecycleTickets: readonly TelegramLifecycleTicket[] = [],
  readTickets: readonly TelegramSubscriptionReadTicket[] = [],
  readGuard?: { sql: string; bindings: readonly (string | number | null)[] },
  nodeTickets: readonly TelegramNodePageTicket[] = [],
): Promise<boolean> {
  if (!inTelegramScope(policy, lease) || lease.privateClaim || lease.inlineSort || lease.bulkTrash || lease.inlineConsent || lease.githubSearch
    || ((lease.aggregate || lease.selected || lease.path || lease.privateShareCreation
    || lease.tempRaw || lease.shortLink || lease.subscriptionNodes || lease.providerOutcome !== undefined)
    && (lease.chatType !== "private" || lease.threadId !== null))
    || (lease.providerOutcome !== undefined && access !== "allowed")
    || (tickets.length > 0 && (!lease.view || access !== "allowed"))
    || (lifecycleTickets.length > 0 && (!(lease.view || lease.lifecycle) || access !== "allowed"))
    || (readTickets.length > 0 && (!(lease.view || lease.subscriptionRead || lease.subscriptionNodes) || access !== "allowed"))
    || (readGuard && (!(lease.subscriptionRead || lease.subscriptionNodes) || access !== "allowed"))
    || (nodeTickets.length > 0 && (!readGuard || !(lease.subscriptionRead || lease.subscriptionNodes) || access !== "allowed"))) return false;

  const begin = beginReplyStatement(db, policy, lease, access, readGuard);
  if (tickets.length === 0 && lifecycleTickets.length === 0 && readTickets.length === 0 && nodeTickets.length === 0) {
    return await begin.first() !== null;
  }

  const statements = [begin];
  const ticketCounts: number[] = [];
  if (tickets.length > 0) {
    statements.push(insertTelegramViewTickets(db, lease.receiptId, lease.attempts, lease.leaseId, tickets));
    ticketCounts.push(tickets.length);
  }
  if (lifecycleTickets.length > 0) {
    statements.push(insertTelegramLifecycleTickets(db, lease.receiptId, lease.attempts, lease.leaseId,
      lifecycleTickets, tickets.length || 1));
    ticketCounts.push(lifecycleTickets.length);
  }
  if (readTickets.length > 0) {
    statements.push(insertTelegramSubscriptionReadTickets(db, lease, readTickets, ticketCounts.at(-1) ?? 1, lease.subscriptionNodes));
    ticketCounts.push(readTickets.length);
  }
  if (nodeTickets.length > 0) {
    statements.push(insertTelegramNodePageTickets(db, lease, nodeTickets, ticketCounts.at(-1) ?? 1));
    ticketCounts.push(nodeTickets.length);
  }
  const [state, ...writes] = await db.batch<{ receipt_id: number }>(statements);
  const changed = state?.results.length;
  if (!state?.success || (changed !== 0 && changed !== 1) ||
      (changed === 1 && state.results[0].receipt_id !== lease.receiptId) || writes.length !== ticketCounts.length ||
      writes.some((write, index) => !write.success || write.meta.changes !== changed * ticketCounts[index])) {
    throw new Error("Telegram reply tickets could not be confirmed.");
  }
  return changed === 1;
}

export async function beginTelegramInlineSortReply(db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease): Promise<boolean> {
  if (!lease.inlineSort || !inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return false;
  const guard = {
    sql: `inbox.receipt_nonce = '${TELEGRAM_INLINE_SORT_MARKER}' AND EXISTS (
      SELECT 1 FROM telegram_inline_sort_reply AS sort LEFT JOIN telegram_auth AS auth
        ON auth.bot_id = inbox.bot_id AND auth.user_id = inbox.actor_id AND inbox.actor_id <> ?
      WHERE sort.receipt_id = inbox.receipt_id AND sort.kind = ? AND sort.mode IS ?
        AND sort.auth_message_date = COALESCE(auth.message_date, 0)
        AND sort.auth_message_id = COALESCE(auth.message_id, 0)
    )`,
    bindings: [policy.adminId, lease.inlineSort.kind, lease.inlineSort.mode],
  };
  return beginTelegramInlineReply(db, policy, lease, guard);
}

export async function beginTelegramInlineConsentReply(db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease): Promise<boolean> {
  if (!lease.inlineConsent || !inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return false;
  return beginTelegramInlineReply(db, policy, lease, { sql: `inbox.receipt_nonce='${TELEGRAM_INLINE_CONSENT_MARKER}' AND EXISTS (
    SELECT 1 FROM telegram_inline_search_consent AS consent LEFT JOIN telegram_auth AS auth
      ON auth.bot_id=inbox.bot_id AND auth.user_id=inbox.actor_id AND inbox.actor_id<>?
    WHERE consent.receipt_id=inbox.receipt_id AND consent.bot_id=inbox.bot_id AND consent.actor_id=inbox.actor_id AND consent.kind=?
      AND consent.actor_role=CASE WHEN inbox.actor_id=? THEN 'admin' WHEN inbox.actor_id=? THEN 'member' END
      AND consent.auth_message_date=COALESCE(auth.message_date,0) AND consent.auth_message_id=COALESCE(auth.message_id,0))`,
  bindings: [policy.adminId, lease.inlineConsent, policy.adminId, policy.memberId] });
}

async function beginTelegramInlineReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease, guard: { sql: string; bindings: readonly (string | null)[] },
): Promise<boolean> {
  if (await beginReplyStatement(db, policy, lease, "allowed", guard).first() !== null) return true;

  // A rejected pre-send lease never called Telegram and can be closed without blocking newer replies.
  await db.prepare(`UPDATE telegram_outbox SET state = 'failed', lease_id = NULL, lease_until = NULL
    WHERE receipt_id = ? AND state = 'leased' AND lease_id = ? AND attempts = ?`).bind(
    lease.receiptId, lease.leaseId, lease.attempts,
  ).run();
  return false;
}

export async function beginTelegramGitHubSearchReply(
  db: D1Database, policy: TelegramPolicy, lease: TelegramReplyLease,
): Promise<boolean> {
  if (!lease.githubSearch || !inTelegramScope(policy, lease) || lease.chatType !== "private" || lease.threadId !== null) return false;
  const guard = telegramGitHubSendGuard(policy, lease.githubSearch);
  if (await beginReplyStatement(db, policy, lease, "allowed", guard).first() !== null) return true;
  // The fence failed before a send. Release only this exact lease so later commands can proceed.
  await db.prepare(`UPDATE telegram_outbox SET state = 'failed', lease_id = NULL, lease_until = NULL
    WHERE receipt_id = ? AND state = 'leased' AND lease_id = ? AND attempts = ?`).bind(
    lease.receiptId, lease.leaseId, lease.attempts,
  ).run();
  return false;
}

export async function settleTelegramReply(
  db: D1Database,
  policy: TelegramPolicy,
  lease: TelegramReplyLease,
  outcome: TelegramReplyOutcome,
): Promise<void> {
  const identity = [lease.leaseId, lease.attempts, policy.botId, lease.updateId, lease.receiptId] as const;
  const includeProvider = lease.providerOutcome !== undefined;
  const sameReply = `lease_id = ? AND attempts = ? AND receipt_id = (
    SELECT receipt_id FROM telegram_inbox AS inbox
    WHERE bot_id = ? AND update_id = ? AND receipt_id = ? AND ${supportedReceipt("inbox", lease.aggregate !== undefined || lease.selected !== undefined,
      lease.privateShareCreation === true, lease.subscriptionRead === true, lease.shortLink === true,
      lease.inlineSort !== undefined, lease.subscriptionNodes === true, includeProvider, lease.bulkTrash === true,
      lease.inlineConsent !== undefined, lease.githubSearch !== undefined)}
  )`;
  if (outcome.kind === "sent") {
    if (!Number.isSafeInteger(outcome.messageId) || outcome.messageId <= 0) {
      throw new RangeError("Telegram delivery confirmation is invalid.");
    }
    // A late confirmed success may settle the same uncertain attempt, without resending.
    await db.prepare(`
      UPDATE telegram_outbox SET state = 'sent', sent_message_id = ?, lease_id = NULL, lease_until = NULL
      WHERE ${sameReply} AND state IN ('sending', 'uncertain')
    `).bind(outcome.messageId, ...identity).run();
    return;
  }

  if (outcome.kind === "retry" && Number.isSafeInteger(outcome.delaySeconds) && outcome.delaySeconds > 0
      && outcome.delaySeconds < MAX_REPLY_AGE_SECONDS) {
    // Never shorten Telegram's requested wait to fit the retry lifetime.
    await db.prepare(`
      UPDATE telegram_outbox SET state = CASE
        WHEN attempts < ${MAX_ATTEMPTS} AND unixepoch() + ? < (
          SELECT ${replyClock(includeProvider)} FROM telegram_inbox AS inbox WHERE inbox.receipt_id = telegram_outbox.receipt_id
        ) + ${MAX_REPLY_AGE_SECONDS} THEN 'pending' ELSE 'failed' END,
        due_at = unixepoch() + ?, lease_id = NULL, lease_until = NULL
      WHERE ${sameReply} AND state = 'sending'
    `).bind(outcome.delaySeconds, outcome.delaySeconds, ...identity).run();
    return;
  }

  const state = outcome.kind === "uncertain" ? "uncertain" : "failed";
  await db.prepare(`
    UPDATE telegram_outbox SET state = ?, lease_id = CASE WHEN ? = 'uncertain' THEN lease_id ELSE NULL END,
      lease_until = NULL
    WHERE ${sameReply} AND state = 'sending'
  `).bind(state, state, ...identity).run();
}

export async function reapExpiredTelegramReplies(db: D1Database, botId: string, includeAggregate = false,
  includePrivateShareCreation = false, includeSubscriptionRead = false, includeShortLinks = false, includeInlineSort = false,
  includeSubscriptionNodes = false, includeProvider = false, includeBulkTrash = false, includeInlineConsent = false,
  includeGitHubSearch = false): Promise<void> {
  await db.prepare(`
    UPDATE telegram_outbox SET state = CASE
      WHEN state = 'sending' THEN 'uncertain'
      WHEN state = 'leased' AND attempts < ${MAX_ATTEMPTS} AND (
        SELECT ${replyClock(includeProvider)} FROM telegram_inbox AS inbox WHERE inbox.receipt_id = telegram_outbox.receipt_id
      ) + ${MAX_REPLY_AGE_SECONDS} > unixepoch() THEN 'pending' ELSE 'failed' END,
      lease_id = CASE WHEN state = 'sending' THEN lease_id ELSE NULL END, lease_until = NULL
    WHERE receipt_id IN (
      SELECT reply.receipt_id FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
      WHERE inbox.bot_id = ? AND ${supportedReceipt("inbox", includeAggregate, includePrivateShareCreation, includeSubscriptionRead,
        includeShortLinks, includeInlineSort, includeSubscriptionNodes, includeProvider, includeBulkTrash, includeInlineConsent, includeGitHubSearch)} AND (
        (reply.state IN ('leased', 'sending') AND reply.lease_until <= unixepoch())
        OR (reply.state IN ('pending', 'leased') AND ${replyClock(includeProvider)} + ${MAX_REPLY_AGE_SECONDS} <= unixepoch())
      )
      ORDER BY reply.receipt_id LIMIT ${REAP_LIMIT}
    )
  `).bind(botId).run();
}

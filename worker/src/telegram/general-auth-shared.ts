import type { PublicOrigin } from "../public-origin.ts";
import { readBotDisplayTimeZone } from "./display-time.ts";
import { acceptGeneralTelegramDisplaySettings, readTelegramDisplaySettingsUpdate, renderTelegramDisplaySettings } from "./display-settings.ts";
import { renderTelegramHelp, type TelegramCommandContext } from "./command-catalog.ts";
import type { TelegramMainMenuFeatures } from "./main-menu.ts";
import { GENERAL_TELEGRAM_PROVIDER_MARKER } from "../provider-jobs.ts";
import { acceptTelegramAggregate, GENERAL_AGGREGATE_SCHEMA, GENERAL_TELEGRAM_AGGREGATE_MARKER, prepareTelegramAggregateCode,
  renderTelegramAggregateResult, type TelegramAggregateReply } from "./aggregate-actions.ts";
import { acceptTelegramDocumentJob, generalDocumentReplyEligibility, generalDocumentReplyScope, renderTelegramDocumentOutcome,
  TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER, type TelegramDocumentJobResult } from "./document-jobs.ts";
import { renderTelegramAggregateLinks, sendGeneralTelegramGroupListReply, sendGeneralTelegramPrivateReply,
  sendGeneralTelegramTempRawReply, sendPrivateShareClaimResult, sendTelegramInlineAnswer } from "./delivery.ts";
import { acceptGeneralAuthAction, GENERAL_AUTH_ACTION_MARKER, GENERAL_AUTH_ACTION_SCHEMA, GENERAL_AUTH_LIST_LIMIT,
  prepareGeneralAuthActionReply, readGeneralAuthAction, renderGeneralAuthActionReply,
  type GeneralAuthReply } from "./general-auth-actions.ts";
import {
  generalReadEvent,
  type GeneralReadCommand, type GeneralReadEvent, type GeneralTelegramPin,
} from "./general-auth-runtime.ts";
import { GENERAL_READ_LANE_ROLE, generalReadLaneRoleBindings } from "./general-read-lane.ts";
import { answerTelegramInlineSearch } from "./inline-search.ts";
import { acceptTelegramInlineConsent, GENERAL_INLINE_CONSENT_MARKER, GENERAL_INLINE_SCHEMA, readGeneralInlineConsent,
  renderTelegramInlineConsent, telegramInlineSearchReady, type TelegramInlineConsentReply } from "./inline-search-consent.ts";
import { GENERAL_ACTOR_QUEUE_CAPACITY, GENERAL_LATEST_ACTOR_SQL, GENERAL_NO_LEGACY_WORK, GENERAL_POLICY_ACTORS_SQL, GENERAL_POLICY_PIN_SQL,
  GENERAL_RECEIPT_SCHEMA, GENERAL_REPLY_TTL, generalCurrentAuthoritySql, generalOrdinaryReplyEligibilitySql, generalPolicyBindings, generalRecordedOriginSql,
  approvedGroup, groupSchemaReady, prepareGeneralReceiptAuthority } from "./general-receipt.ts";
import { acceptTelegramGroupShare, GENERAL_GROUP_CARD_SCHEMA, generalGroupShareBindings, generalGroupShareClaimGuard,
  generalGroupShareReady, hasGeneralGroupShare, TELEGRAM_GENERAL_GROUP_CLAIM_MARKER } from "./group-share-actions.ts";
import { acceptGeneralTelegramLifecycle, GENERAL_LIFECYCLE_MARKER, GENERAL_LIFECYCLE_VIEW_MARKER,
  insertTelegramLifecycleTickets, prepareTelegramLifecycleTickets, reapTelegramLifecycle, renderTelegramLifecycle,
  type TelegramLifecycleReply, type TelegramLifecycleTicket } from "./lifecycle-actions.ts";
import { acceptGeneralTelegramSubscriptionRead, renderGeneralSubscriptionRead } from "./general-subscription-read.ts";
import { acceptGeneralProviderRequest, generalProviderAuthority } from "./general-provider.ts";
import { acceptTelegramPrivateClaim, beginTelegramPrivateClaim, GENERAL_PRIVATE_CLAIM_SCHEMA,
  prepareTelegramPrivateClaim, TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER } from "./private-claims.ts";
import { acceptTelegramPrivateShareCreation, acceptTelegramSubscriptionShare, GENERAL_SHARE_CREATION_SCHEMA,
  parseTelegramPrivateShareArgs, parseTelegramSubscriptionShareArgs,
  recoverTelegramPrivateShareCreation, renderTelegramPrivateShareLink, resolveTelegramPrivateShareCreationReply,
  retireAbandonedTelegramPrivateShareCreation, TELEGRAM_GENERAL_SHARE_CREATION_MARKER } from "./private-share-creation.ts";
import type { TelegramPrivateShareRuntime } from "./private-share-runtime.ts";
import { GENERAL_PATH_MARKER, prepareTelegramPathReceipt, renderTelegramPath, type TelegramPathReply } from "./path-management.ts";
import { acceptTelegramProviderUrlMessage, telegramGeneralProviderDocumentsReady } from "./provider-document.ts";
import { parseTelegramProviderUrlMessage } from "./provider-document-input.ts";
import { GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER } from "./provider-document-origin.ts";
import { generalProviderDocumentReplyEligibility, generalProviderDocumentReplyScope,
  renderTelegramProviderDocumentReply } from "./provider-document-replies.ts";
import { acceptTelegramProviderBatchControl, GENERAL_TELEGRAM_PROVIDER_BATCH_REPLY_MARKERS, generalProviderBatchReplyEligible,
  installTelegramProviderBatchTicket, isGeneralProviderBatchReply, renderTelegramProviderBatchReply,
  telegramProviderBatchReplyMarker } from "./provider-batch-controls.ts";
import { generalProviderRefreshReady, insertTelegramProviderRefreshTicket, prepareTelegramProviderRefreshButton,
  reapTelegramProviderRefreshTickets, type TelegramProviderRefreshTicket } from "./provider-refresh.ts";
import { generalProviderReplyEligibility, generalProviderReplyScope, parseTelegramProviderText, renderTelegramProviderReply,
  type TelegramProviderReply, type TelegramProviderRequestKind } from "./provider-replies.ts";
import { acceptTelegramSelected, GENERAL_SELECTED_SCHEMA, GENERAL_TELEGRAM_SELECTED_MARKER, insertSelectedRevokeTickets,
  prepareSelectedLimitTickets, prepareSelectedRevokeTicket, reapTelegramSelected, renderTelegramSelected, resolveTelegramSelectedCode,
  retireUnsentSelectedLink, selectedTicketTargetGuard, type TelegramSelectedReply } from "./selected-export.ts";
import { acceptTelegramShortLink, GENERAL_SHORT_SCHEMA, GENERAL_TELEGRAM_SHORT_MARKER, prepareTelegramShortLinkReply,
  reapFailedTelegramShortLinks, retireUnsentTelegramShortLink } from "./short-link-actions.ts";
import { GROUP_SHARE_PUBLISH_CALLBACK, readGeneralGroupShare, readGeneralPrivateDocumentUpdate, readGeneralPrivateLifecycleUpdate, readGeneralPrivateSubscriptionRead,
  readGeneralInlineQuery, readGeneralPrivateProviderBatch, readGeneralPrivateProviderRefresh, readGeneralPrivateSelectedRevoke, readGeneralPrivateShareClaim, readGeneralPrivateShareCreation,
  readGeneralPrivateTempUpdate, readGeneralPrivateMenuCommand, readPrivateTelegramCommand, readTelegramUpdate } from "./protocol.ts";
import { confirmTelegramSubscriptionReadSend, GENERAL_SUBSCRIPTION_READ_MARKER, insertTelegramSubscriptionReadTickets,
  prepareTelegramSubscriptionReadTickets, reapTelegramSubscriptionReadTickets,
  type TelegramSubscriptionReadTicket } from "./subscription-read.ts";
import { beginSubscriptionShortDelivery, closeUnsentTelegramSubscriptionShort, hasTelegramSubscriptionShort,
  prepareTelegramSubscriptionShort, reapFailedTelegramSubscriptionShorts, subscriptionShortPublicationGuard,
  subscriptionShortSendGuard, telegramSubscriptionShortsReady, type SubscriptionShortCandidate } from "./subscription-shorts.ts";
import { GENERAL_TEMP_SCHEMA, generalTempRawMarker, generalTempRawStamp, prepareGeneralTelegramTempReceipt, renderTelegramTemp,
  TELEGRAM_GENERAL_TEMP_RAW_PREFIX, type TelegramTempReply } from "./temp-import.ts";
import { confirmTelegramTempRawSend, prepareTelegramTempRawReply } from "./temp-raw.ts";
import { readVerifiedTempStorage, TELEGRAM_GENERAL_TEMP_MARKER, tempCutoverAllows, tempSchemaGuard } from "./temp-storage.ts";
import { renderTelegramView } from "./views.ts";
import { prepareTelegramOutboxBegin, settleTelegramOutboxReply, TELEGRAM_OUTBOX_LEASE_SECONDS,
  TELEGRAM_OUTBOX_MAX_ATTEMPTS, type TelegramReplyOutcome } from "./store.ts";

const MARKER = "general-read:v1";
const GROUP_MARKER = "general-group-read:v1";
const PATH_SCHEMA = `EXISTS (SELECT /* subs-bot:telegram-general-private-path:v1 */ 1 FROM subs_bot_schema_migrations
  WHERE position=13 AND name='0013_telegram_path.sql'
    AND sha256='8375e89be0cf3fe1e23b4107f538927a85d2d3ebf9b49eab0bf700ad2c023f15' AND mode='applied')`;
type ReplyGuard = { sql: string; bindings: readonly (string | number | null)[] };
type MetadataReply = ReplyGuard & { tickets: readonly TelegramSubscriptionReadTicket[];
  refreshTicket?: TelegramProviderRefreshTicket };

interface SharedReadLease {
  receiptId: number;
  updateId: number;
  actorId: string;
  chatId: string;
  chatType: "private" | "group" | "supergroup";
  threadId: number | null;
  messageId: number;
  messageDate: number;
  generation: number;
  actorRevision: number;
  actorRole: "admin" | "member";
  command: GeneralReadCommand | "auth-add" | "auth-remove" | "auth-list";
  marker: string;
  viewKind: "list" | "expiry" | "recycle" | null;
  actionKind: TelegramLifecycleReply["kind"] | null;
  actionSubscriptionId: number | null;
  actionRevision: number | null;
  claimCodeSha256: string | null;
  leaseId: string;
  attempts: number;
}

function aggregateFamily(alias: "inbox" | "earlier"): string {
  return `${alias}.receipt_nonce='${GENERAL_TELEGRAM_AGGREGATE_MARKER}' AND ${alias}.command='help'
    AND (${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL)
    AND EXISTS (SELECT 1 FROM telegram_aggregate_actions
      WHERE receipt_id=${alias}.receipt_id AND auth_message_date=0 AND auth_message_id=0)
    AND (${GENERAL_AGGREGATE_SCHEMA})`;
}

function selectedFamily(alias: "inbox" | "earlier"): string {
  return `${alias}.receipt_nonce='${GENERAL_TELEGRAM_SELECTED_MARKER}' AND ${alias}.command='help'
    AND (${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL)
    AND EXISTS (SELECT 1 FROM telegram_selected_actions
      WHERE receipt_id=${alias}.receipt_id AND auth_message_date=0 AND auth_message_id=0)
    AND (${GENERAL_SELECTED_SCHEMA})`;
}

function shortFamily(alias: "inbox" | "earlier"): string {
  return `${alias}.receipt_nonce='${GENERAL_TELEGRAM_SHORT_MARKER}' AND ${alias}.command='help'
    AND (${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL)
    AND EXISTS (SELECT 1 FROM telegram_short_link_actions
      WHERE receipt_id=${alias}.receipt_id AND auth_message_date=0 AND auth_message_id=0)
    AND (${GENERAL_SHORT_SCHEMA})`;
}

function groupClaimFamily(alias: "inbox" | "earlier"): string {
  return `${alias}.receipt_nonce='${TELEGRAM_GENERAL_GROUP_CLAIM_MARKER}' AND ${alias}.command='help'
    AND ${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL
    AND EXISTS (SELECT 1 FROM telegram_private_claim WHERE receipt_id=${alias}.receipt_id)
    AND EXISTS (SELECT 1 FROM telegram_group_share_scopes WHERE receipt_id=${alias}.receipt_id)`;
}

function family(alias: "inbox" | "earlier", group: boolean, pin: GeneralTelegramPin, includeExports = true): string {
  const privateScope = `${alias}.chat_type='private' AND ${alias}.chat_id=${alias}.actor_id AND ${alias}.thread_id IS NULL`;
  const groupScope = group ? ` OR (${alias}.receipt_nonce='${GROUP_MARKER}' AND ${alias}.chat_type IN ('group','supergroup')
    AND ${alias}.command IN ('start','help','list') AND (${alias}.chat_type='supergroup' OR ${alias}.thread_id IS NULL))` : "";
  const view = `EXISTS (SELECT 1 FROM telegram_view AS page WHERE page.receipt_id=${alias}.receipt_id
    AND page.after_id IS NULL AND page.after_epoch IS NULL AND page.kind`;
  const ordinary = `((${alias}.receipt_nonce='${MARKER}' AND ${privateScope})${groupScope})
    AND ((${alias}.command='list' AND ${view} IN ('list','expiry','recycle')))
      OR (${alias}.command IN ('start','help') AND NOT EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id=${alias}.receipt_id)))`;
  const temp = pin.privateTemp ? `OR (${alias}.command='help' AND CASE
    WHEN ${generalTempRawMarker(alias)} THEN EXISTS (SELECT 1 FROM telegram_temp_reply
      WHERE receipt_id=${alias}.receipt_id AND kind='summary')
    WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_TEMP_MARKER}' THEN EXISTS (SELECT 1 FROM telegram_temp_reply
      WHERE receipt_id=${alias}.receipt_id) ELSE 0 END)` : "";
  const document = pin.privateDocument ? `OR (${generalDocumentReplyScope(alias)})` : "";
  const provider = pin.privateProvider ? `OR (${generalProviderReplyScope(alias)})` : "";
  const management = pin.privateManagement ? `((${ordinary}) OR (/* subs-bot:telegram-general-private-lifecycle:v1 */ ${privateScope} AND (
    (${alias}.receipt_nonce='${GENERAL_LIFECYCLE_VIEW_MARKER}' AND ${alias}.command='list' AND ${view} IN ('list','expiry','recycle')))
    OR (${alias}.receipt_nonce='${GENERAL_LIFECYCLE_MARKER}' AND ${alias}.command='help'
      AND EXISTS (SELECT 1 FROM telegram_lifecycle_action WHERE receipt_id=${alias}.receipt_id))
    OR (${alias}.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND ${alias}.command='help'
      AND EXISTS (SELECT /* subs-bot:telegram-general-subscription-read:v1 */ 1 FROM telegram_subscription_read
        WHERE receipt_id=${alias}.receipt_id))
    OR (${alias}.receipt_nonce='${GENERAL_PATH_MARKER}' AND ${alias}.command='help'
      AND EXISTS (SELECT 1 FROM telegram_path_reply WHERE receipt_id=${alias}.receipt_id)) ${temp} ${document} ${provider})))` : ordinary;
  const groupSearch = group && pin.privateManagement ? ` OR (${alias}.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}'
    AND ${alias}.chat_type IN ('group','supergroup') AND ${alias}.command='help'
    AND EXISTS (SELECT 1 FROM telegram_subscription_read WHERE receipt_id=${alias}.receipt_id AND kind IN ('search','usage','limit','stale')))` : "";
  if (pin.rehearsal) return management;
  return `(CASE WHEN ${alias}.receipt_nonce='${GENERAL_AUTH_ACTION_MARKER}'
    THEN (${privateScope} AND ${alias}.command IN ('auth-add','auth-remove','auth-list') AND ${GENERAL_AUTH_ACTION_SCHEMA})
    ${pin.providerDocumentReplies ? `WHEN ${alias}.receipt_nonce='${GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER}'
    THEN (${generalProviderDocumentReplyScope(alias)})` : ""}
    ${pin.providerBatch ? `WHEN ${alias}.receipt_nonce IN (${GENERAL_TELEGRAM_PROVIDER_BATCH_REPLY_MARKERS})
      THEN (${telegramProviderBatchReplyMarker(alias, true)})` : ""}
    ${pin.privateInline ? `WHEN ${alias}.receipt_nonce='${GENERAL_INLINE_CONSENT_MARKER}'
    THEN (${privateScope} AND ${alias}.command='help' AND (${GENERAL_INLINE_SCHEMA})
      AND EXISTS (SELECT 1 FROM telegram_inline_search_consent AS consent
        WHERE consent.receipt_id=${alias}.receipt_id AND consent.bot_id=${alias}.bot_id AND consent.actor_id=${alias}.actor_id))` : ""}
    ${pin.privateClaims ? `WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER}'
      THEN (${privateScope} AND ${alias}.command='help'
        AND EXISTS (SELECT 1 FROM telegram_private_claim WHERE receipt_id=${alias}.receipt_id))` : ""}
    ${hasGeneralGroupShare(pin) ? `WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_GROUP_CLAIM_MARKER}'
      THEN (${groupClaimFamily(alias)})` : ""}
    ${pin.privateShareCreation ? `WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_SHARE_CREATION_MARKER}'
    THEN (${privateScope} AND ${alias}.command='help' AND ${GENERAL_SHARE_CREATION_SCHEMA}
      AND EXISTS (SELECT 1 FROM telegram_private_share_creations AS share WHERE share.receipt_id=${alias}.receipt_id
        AND share.bot_id=${alias}.bot_id AND share.actor_id=${alias}.actor_id AND share.state='published'))` : ""}
    ${includeExports && pin.privateAggregate ? `WHEN ${alias}.receipt_nonce='${GENERAL_TELEGRAM_AGGREGATE_MARKER}'
    THEN (${aggregateFamily(alias)})` : ""}
    ${includeExports && pin.privateSelected ? `WHEN ${alias}.receipt_nonce='${GENERAL_TELEGRAM_SELECTED_MARKER}'
    THEN (${selectedFamily(alias)})` : ""}
    ${includeExports && pin.privateShort ? `WHEN ${alias}.receipt_nonce='${GENERAL_TELEGRAM_SHORT_MARKER}'
    THEN (${shortFamily(alias)})` : ""}
    ELSE ((${management})${groupSearch}) END)`;
}

function queueMarkers(group: boolean, pin: GeneralTelegramPin): string {
  const markers: string[] = [MARKER];
  if (group) markers.push(GROUP_MARKER);
  if (pin.privateManagement) markers.push(GENERAL_LIFECYCLE_MARKER, GENERAL_LIFECYCLE_VIEW_MARKER,
    GENERAL_SUBSCRIPTION_READ_MARKER, GENERAL_PATH_MARKER);
  if (pin.privateTemp) markers.push(TELEGRAM_GENERAL_TEMP_MARKER);
  if (pin.privateDocument) markers.push(TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER);
  if (pin.privateProvider) markers.push(GENERAL_TELEGRAM_PROVIDER_MARKER);
  if (pin.providerDocumentReplies) markers.push(GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER);
  if (pin.privateClaims) markers.push(TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER);
  if (hasGeneralGroupShare(pin)) markers.push(TELEGRAM_GENERAL_GROUP_CLAIM_MARKER);
  if (pin.privateShareCreation) markers.push(TELEGRAM_GENERAL_SHARE_CREATION_MARKER);
  if (pin.privateAggregate) markers.push(GENERAL_TELEGRAM_AGGREGATE_MARKER);
  if (pin.privateSelected) markers.push(GENERAL_TELEGRAM_SELECTED_MARKER);
  if (pin.privateShort) markers.push(GENERAL_TELEGRAM_SHORT_MARKER);
  if (pin.privateInline) markers.push(GENERAL_INLINE_CONSENT_MARKER);
  if (!pin.rehearsal) markers.push(GENERAL_AUTH_ACTION_MARKER);
  const regular = markers.map((marker) => `'${marker}'`).join(",");
  return pin.providerBatch ? `${regular},${GENERAL_TELEGRAM_PROVIDER_BATCH_REPLY_MARKERS}` : regular;
}

function current(alias: "inbox" | "earlier", group: boolean, pin: GeneralTelegramPin): string {
  const groupScope = group ? `(${alias}.chat_type='private' OR (${approvedGroup(alias)}))` : "1";
  const pathScope = pin.privateManagement ? `(${alias}.receipt_nonce<>'${GENERAL_PATH_MARKER}' OR ${PATH_SCHEMA})` : "1";
  const tempScope = pin.privateTemp ? ` AND ((${alias}.receipt_nonce<>'${TELEGRAM_GENERAL_TEMP_MARKER}' AND NOT (${generalTempRawMarker(alias)})) OR (${GENERAL_TEMP_SCHEMA}
    AND ${tempSchemaGuard("legacy-ready")}))` : "";
  const laneScope = pin.rehearsal ? ` AND ${GENERAL_READ_LANE_ROLE}` : "";
  const claimScope = pin.privateClaims ? ` AND (${alias}.receipt_nonce<>'${TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER}'
    OR ${GENERAL_PRIVATE_CLAIM_SCHEMA})` : "";
  const authScope = !pin.rehearsal ? ` AND (${alias}.receipt_nonce<>'${GENERAL_AUTH_ACTION_MARKER}' OR authority.actor_role='admin')` : "";
  const ordinaryClock = generalOrdinaryReplyEligibilitySql(alias);
  const clock = pin.privateDocument ? `(CASE WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER}'
    THEN (${generalDocumentReplyEligibility(alias)}) ${pin.privateProvider ? `WHEN ${alias}.receipt_nonce='${GENERAL_TELEGRAM_PROVIDER_MARKER}'
    THEN (${generalProviderReplyEligibility(alias)})` : ""}
    ${pin.providerDocumentReplies ? `WHEN ${alias}.receipt_nonce='${GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER}'
    THEN (${generalProviderDocumentReplyEligibility(alias)})` : ""} ELSE (${ordinaryClock}) END)` : ordinaryClock;
  const ordinary = `${clock} AND ${generalCurrentAuthoritySql(alias, `${groupScope} AND ${pathScope}${tempScope}${laneScope}${claimScope}${authScope}`)}`;
  const card = hasGeneralGroupShare(pin) ? `WHEN ${alias}.receipt_nonce='${TELEGRAM_GENERAL_GROUP_CLAIM_MARKER}'
    THEN (${ordinaryClock} AND ${generalCurrentAuthoritySql(alias,
      `${GENERAL_PRIVATE_CLAIM_SCHEMA} AND ${GENERAL_GROUP_CARD_SCHEMA} AND ${approvedGroup()}`)})` : "";
  const batch = pin.providerBatch ? `WHEN ${alias}.receipt_nonce IN (${GENERAL_TELEGRAM_PROVIDER_BATCH_REPLY_MARKERS})
    THEN (${generalProviderBatchReplyEligible(alias)} AND ${generalCurrentAuthoritySql(alias)})` : "";
  return card || batch ? `(CASE ${card} ${batch} ELSE (${ordinary}) END)` : ordinary;
}

function currentBindings(pin: GeneralTelegramPin) {
  return [
    ...(hasGeneralGroupShare(pin) ? [...generalPolicyBindings(pin), ...generalGroupShareBindings(pin)] : []),
    ...(pin.providerBatch ? generalPolicyBindings(pin) : []),
    ...generalPolicyBindings(pin), ...generalReadLaneRoleBindings(pin),
  ];
}

function readGeneralTempReply(db: D1Database, receiptId: number) {
  return db.prepare(`SELECT kind,node_count AS nodeCount,total_count AS totalCount,malformed_count AS malformedCount,
    unsupported_count AS unsupportedCount,ignored_count AS ignoredCount FROM telegram_temp_reply WHERE receipt_id=?`)
    .bind(receiptId).first<TelegramTempReply>();
}

export async function acceptGeneralSharedTelegramCommand(
  db: D1Database, pin: GeneralTelegramPin, request: Request, acknowledge?: (callbackId: string, answer?: string) => void,
  providerAvailable?: () => Promise<boolean>, refreshAvailable?: () => Promise<boolean>,
  share?: { bucket: R2Bucket; runtime: TelegramPrivateShareRuntime; publicOrigin: PublicOrigin }, aggregateKey?: CryptoKey | null,
  inlineEnabled = false, providerDocumentsEnabled = false, batchAdmission = false,
): Promise<number> {
  const decoded = await readTelegramUpdate(request, pin.webhookSecret);
  if (decoded.status !== 200) return decoded.status;
  if (!pin.sharedOutbox || pin.rehearsal) return 204;
  const displaySettings = readTelegramDisplaySettingsUpdate(decoded.update, decoded.updateId, pin);
  if (displaySettings) {
    const status = await acceptGeneralTelegramDisplaySettings(db, pin, displaySettings);
    if (displaySettings.callbackId) acknowledge?.(displaySettings.callbackId,
      status === 200 ? "已收到设置操作。" : "此操作暂不可用。");
    return status;
  }
  if (pin.privateInline && inlineEnabled) {
    const inline = readGeneralInlineQuery(decoded.update, decoded.updateId, pin.botId);
    if (inline) {
      if (await telegramInlineSearchReady(db)) await answerTelegramInlineSearch(db, pin, inline, sendTelegramInlineAnswer);
      return 204;
    }
  }
  const consent = readGeneralInlineConsent(decoded.update, decoded.updateId, pin);
  if (consent) {
    if ((!inlineEnabled && consent.kind !== "off") || !await telegramInlineSearchReady(db)) return 204;
    return await acceptTelegramInlineConsent(db, pin, consent) === "accepted" ? 200 : 204;
  }
  const selectedRevoke = pin.privateSelected ? readGeneralPrivateSelectedRevoke(decoded.update, decoded.updateId, pin.botId) : null;
  if (selectedRevoke) {
    if (!aggregateKey) return 204;
    const accepted = await acceptTelegramSelected(db, pin, selectedRevoke, aggregateKey) === "accepted";
    if (accepted) acknowledge?.(selectedRevoke.callbackId);
    return accepted ? 200 : 204;
  }
  if (hasGeneralGroupShare(pin)) {
    const event = readGeneralGroupShare(decoded.update, decoded.updateId, pin.botId, pin.botUsername, pin.groupShare);
    if (event) {
      const accepted = (event.kind !== "publish" || Boolean(share?.runtime.context))
        && await acceptTelegramGroupShare(db, pin, event) === "accepted";
      if (event.kind !== "handoff") acknowledge?.(event.callbackId, !accepted ? "此卡片暂不可用。"
        : event.kind === "publish" ? "已提交到指定群。" : "已选中。请打开机器人私聊领取。");
      return accepted ? 200 : 204;
    }
  }
  const auth = readGeneralAuthAction(pin, decoded.update, decoded.updateId);
  if (auth) return acceptGeneralAuthAction(db, pin, auth);
  const creation = pin.privateShareCreation
    ? readGeneralPrivateShareCreation(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  if (creation) {
    if (!share?.runtime.context) return 204;
    const selection = parseTelegramSubscriptionShareArgs(creation.args);
    if (selection) {
      const outcome = await acceptTelegramSubscriptionShare(db, share.bucket, pin, { ...creation, ...selection },
        share.runtime.context, share.publicOrigin);
      return outcome === "published" || outcome === "pending" ? 200 : 204;
    }
    const draft = parseTelegramPrivateShareArgs(creation.args);
    if (!draft) return 204;
    const outcome = await acceptTelegramPrivateShareCreation(db, share.bucket, pin, { ...creation, ...draft }, share.runtime.context);
    return outcome === "ignored" ? 204 : 200;
  }
  const claim = pin.privateClaims
    ? readGeneralPrivateShareClaim(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  if (claim) return await acceptTelegramPrivateClaim(db, pin, claim) === "accepted" ? 200 : 204;
  const batch = pin.providerBatch ? readGeneralPrivateProviderBatch(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  if (batch) {
    const accepted = await acceptTelegramProviderBatchControl(db, pin, batch, batchAdmission) === "accepted";
    if (batch.kind === "confirm" && accepted) acknowledge?.(batch.callbackId);
    return accepted ? 200 : 204;
  }
  const refresh = pin.privateProvider ? readGeneralPrivateProviderRefresh(decoded.update, decoded.updateId, pin.botId) : null;
  if (refresh) {
    if (!refreshAvailable) return 204;
    if (!await refreshAvailable()) return 503;
    const accepted = await acceptGeneralProviderRequest(db, pin, { ...refresh, kind: "refresh" }, pin.providerBatch === true);
    if (accepted) acknowledge?.(refresh.callbackId);
    return accepted ? 200 : 204;
  }
  const document = pin.privateDocument ? readGeneralPrivateDocumentUpdate(decoded.update, decoded.updateId, pin.botId) : null;
  if (document) return await acceptTelegramDocumentJob(db, pin, document) === "ignored" ? 204 : 200;
  const action = pin.privateManagement ? readGeneralPrivateLifecycleUpdate(decoded.update, decoded.updateId, pin.botId) : null;
  if (action) {
    const accepted = await acceptGeneralTelegramLifecycle(db, pin, action) === "accepted";
    if (accepted && action.kind === "lifecycle-callback") acknowledge?.(action.callbackId);
    return accepted ? 200 : 204;
  }
  const search = pin.privateManagement
    ? readGeneralPrivateSubscriptionRead(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  if (search) {
    const accepted = await acceptGeneralTelegramSubscriptionRead(db, pin, search);
    if (accepted && search.kind === "callback") acknowledge?.(search.callbackId);
    return accepted ? 200 : 204;
  }
  const tempEvent = pin.privateTemp ? readGeneralPrivateTempUpdate(decoded.update, decoded.updateId, pin.botId, pin.botUsername) : null;
  if (pin.privateProvider && providerAvailable && tempEvent?.kind === "temp-text") {
    const { text, ...event } = tempEvent;
    const url = parseTelegramProviderText(text);
    if (url) {
      // A bare pipe can be a compact URL/key pair. An escaped pipe is part of the URL.
      if (url.name === undefined && url.sourceUrl.includes("|")) return 204;
      if (!await providerAvailable()) return 503;
      return await acceptGeneralProviderRequest(db, pin, { ...event, ...url, kind: "url-import" }, pin.providerBatch === true) ? 200 : 204;
    }
    const urls = providerDocumentsEnabled ? parseTelegramProviderUrlMessage(text) : null;
    if (urls) {
      if (!await providerAvailable() || !await telegramGeneralProviderDocumentsReady(db, pin.botId, true).catch(() => false)) return 503;
      const result = await acceptTelegramProviderUrlMessage(db, { ...pin, providerDocumentReplies: true }, event, urls);
      return result === "queued" ? 200 : result === "busy" ? 503 : 204;
    }
  }
  const command = pin.privateManagement && !tempEvent ? readGeneralPrivateMenuCommand(decoded.update, pin.botUsername) : null;
  if (pin.privateShort && command?.name === "short") {
    if (command.remainder !== "" && !/^ /u.test(command.remainder)) return 204;
    const { actorId, messageId, messageDate, remainder: args } = command;
    const accepted = await acceptTelegramShortLink(db, pin, { args, updateId: decoded.updateId,
      actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate }, aggregateKey ?? null);
    return accepted === "accepted" ? 200 : 204;
  }
  if (pin.privateSelected && command?.name === "o") {
    if (!aggregateKey || (command.remainder !== "" && !/^\s/u.test(command.remainder))) return 204;
    const { actorId, messageId, messageDate, remainder: query } = command;
    const accepted = await acceptTelegramSelected(db, pin, { kind: "selected", query, updateId: decoded.updateId,
      actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate }, aggregateKey);
    return accepted === "accepted" ? 200 : 204;
  }
  if (pin.privateAggregate && command?.name === "export") {
    const argument = command.remainder.trim().toLowerCase();
    if (!aggregateKey || (command.remainder !== "" && !/^\s/u.test(command.remainder))
      || (argument !== "" && argument !== "revoke")) return 204;
    const { actorId, messageId, messageDate } = command;
    const result = await acceptTelegramAggregate(db, pin, { kind: argument === "revoke" ? "revoke" : "show",
      updateId: decoded.updateId, actorId, chatId: actorId, chatType: "private", threadId: null, messageId, messageDate }, aggregateKey);
    return result === "accepted" ? 200 : 204;
  }
  const pathCommand = command?.name === "path" && command.actorId !== pin.botId ? command : null;
  const event = tempEvent ? { ...tempEvent, command: "help" as const, viewKind: null }
    : pathCommand ? {
      command: "help" as const, viewKind: null, updateId: decoded.updateId, actorId: pathCommand.actorId,
      chatId: pathCommand.actorId, chatType: "private" as const, threadId: null,
      messageId: pathCommand.messageId, messageDate: pathCommand.messageDate,
    } : generalReadEvent(pin, decoded.update, decoded.updateId, true);
  return event ? acceptSharedRead(db, pin, event, pathCommand, tempEvent) : 204;
}

export function acceptGeneralReadLaneCommand(
  db: D1Database, pin: GeneralTelegramPin, event: GeneralReadEvent, guard: D1PreparedStatement,
): Promise<number> {
  if (!pin.rehearsal || pin.privateManagement || pin.privateFormats || pin.privateTemp || pin.privateDocument || pin.privateProvider
    || pin.privateClaims || pin.privateShareCreation || pin.privateAggregate || pin.privateSelected || pin.privateShort || pin.privateAuthorization
    || event.chatType !== "private" || event.chatId !== event.actorId
    || event.threadId !== null || (event.viewKind !== null && event.viewKind !== "list")) return Promise.resolve(204);
  return acceptSharedRead(db, pin, event, null, null, guard);
}

async function acceptSharedRead(
  db: D1Database, pin: GeneralTelegramPin, event: GeneralReadEvent,
  pathCommand: ReturnType<typeof readPrivateTelegramCommand>, tempEvent: ReturnType<typeof readGeneralPrivateTempUpdate>,
  admissionGuard?: D1PreparedStatement,
): Promise<number> {
  const group = event.chatType !== "private";
  if (group && !await groupSchemaReady(db)) return 204;

  const storage = tempEvent ? await readVerifiedTempStorage(db).catch(() => null) : null;
  const mode = storage?.generalReceipts && storage.mode === "legacy-ready" ? storage.mode : null;
  if (tempEvent && mode === null) return 204;
  const raw = tempEvent?.kind === "temp-raw";
  const rawScope = raw ? `AND NOT EXISTS (SELECT 1 FROM telegram_temp_clear_fence
    WHERE bot_id=policy.bot_id AND actor_id=actor.actor_id AND (message_date,message_id)>=(?,?))` : "";
  const tempScope = mode ? `AND ${GENERAL_TEMP_SCHEMA} AND (${tempSchemaGuard(mode)})
    AND (${tempCutoverAllows(mode, "policy.bot_id", "?")})` : "";
  const admission = `FROM ${GENERAL_POLICY_ACTORS_SQL}
    WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA} AND policy.active=1 AND ${GENERAL_NO_LEGACY_WORK}
      AND actor.actor_id=? AND ${GENERAL_LATEST_ACTOR_SQL}
      AND ?>MAX(policy.cutover_at,actor.effective_at,unixepoch()-${GENERAL_REPLY_TTL}) AND ?<=unixepoch()+60
      ${group ? `AND ${approvedGroup()}` : ""} ${pathCommand ? `AND ${PATH_SCHEMA}` : ""} ${tempScope} ${rawScope}
      AND NOT EXISTS (SELECT 1 FROM telegram_general_replies WHERE bot_id=policy.bot_id AND update_id=?)
      AND ${GENERAL_ACTOR_QUEUE_CAPACITY} ${pin.rehearsal ? `AND ${GENERAL_READ_LANE_ROLE}` : ""}`;
  const bindings = [...generalPolicyBindings(pin), event.actorId, event.messageDate, event.messageDate,
    ...(group ? [event.chatId, event.chatType] : []), ...(mode ? [event.messageDate] : []),
    ...(raw ? [event.messageDate, event.messageId] : []), event.updateId,
    ...generalReadLaneRoleBindings(pin)];
  // Bound the parser to current authorized candidates; the same gate runs again in the write batch.
  if (tempEvent && !await db.prepare(`SELECT 1 ${admission}
    AND NOT EXISTS (SELECT 1 FROM telegram_inbox WHERE bot_id=policy.bot_id AND update_id=?)`)
    .bind(...bindings, event.updateId).first()) return 204;
  const nonce = crypto.randomUUID();
  const key = [pin.botId, event.updateId, nonce] as const;
  const path = pathCommand ? prepareTelegramPathReceipt(db, key, { general: pin }, pathCommand.remainder) : null;
  const temp = tempEvent && mode ? prepareGeneralTelegramTempReceipt(db, key, mode, tempEvent) : null;
  if (tempEvent && !temp) return 204;
  const marker = temp ? TELEGRAM_GENERAL_TEMP_MARKER : path ? GENERAL_PATH_MARKER : group ? GROUP_MARKER
    : pin.privateManagement && event.viewKind !== null ? GENERAL_LIFECYCLE_VIEW_MARKER : MARKER;
  const fresh = "incoming.bot_id=? AND incoming.update_id=? AND incoming.receipt_nonce=?";
  const proof = temp ? `(${temp.proof}) AND ${generalCurrentAuthoritySql("incoming")}` : path?.proof
    ?? `incoming.command IN ('start','help') OR EXISTS (SELECT 1 FROM telegram_view WHERE receipt_id=incoming.receipt_id AND kind=?)`;
  const proofBindings = temp ? generalPolicyBindings(pin) : path?.verification ?? [event.viewKind];
  const steps = [
    ...(admissionGuard ? [admissionGuard] : []),
    db.prepare(`INSERT INTO telegram_inbox
      (bot_id,update_id,actor_id,chat_id,chat_type,message_id,message_date,thread_id,command,receipt_nonce)
      SELECT policy.bot_id,?,actor.actor_id,?,?,?,?,?,?,? ${admission}
      ON CONFLICT (bot_id,update_id) DO NOTHING`)
      .bind(event.updateId, event.chatId, event.chatType, event.messageId, event.messageDate, event.threadId, event.command, nonce, ...bindings),
    prepareGeneralReceiptAuthority(db, pin, key),
    ...(temp?.statements ?? path?.statements ?? [db.prepare(`INSERT INTO telegram_view (receipt_id,kind)
      SELECT incoming.receipt_id,? FROM telegram_inbox AS incoming WHERE ${fresh} AND incoming.command='list'`).bind(event.viewKind, ...key)]),
    db.prepare(`INSERT INTO telegram_outbox (receipt_id)
      SELECT incoming.receipt_id FROM telegram_inbox AS incoming WHERE ${fresh}`).bind(...key),
    db.prepare(`UPDATE telegram_inbox AS incoming SET receipt_nonce=${raw ? generalTempRawStamp("incoming") : "?"}, command=CASE WHEN
        EXISTS (SELECT 1 FROM telegram_general_receipt WHERE receipt_id=incoming.receipt_id)
        AND EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=incoming.receipt_id)
        AND (${proof})
      THEN incoming.command END WHERE ${fresh} RETURNING receipt_id`).bind(...(raw ? [] : [marker]), ...proofBindings, ...key),
  ];
  const results = await db.batch(steps);
  const receipt = results.at(-1);
  if (!receipt || results.length !== steps.length || !results.every(({ success }) => success) || receipt.results.length > 1) {
    throw new Error("General Telegram receipt could not be confirmed.");
  }
  return receipt.results.length === 1 ? 200 : 204;
}

export async function claimGeneralSharedTelegramReply(db: D1Database, pin: GeneralTelegramPin): Promise<SharedReadLease | null> {
  if (!pin.sharedOutbox) return null;
  const group = !pin.rehearsal && await groupSchemaReady(db);
  const leaseId = crypto.randomUUID();
  // Evaluate authorization once per active row, outside the FIFO subquery's expression tree.
  const [claimed, read] = await db.batch<SharedReadLease>([
    db.prepare(`UPDATE telegram_outbox
      SET state='leased',attempts=attempts+1,lease_id=?,lease_until=unixepoch()+${TELEGRAM_OUTBOX_LEASE_SECONDS}
      WHERE receipt_id=(
        WITH active AS MATERIALIZED (
          SELECT inbox.receipt_id,inbox.actor_id,inbox.chat_id,reply.state,reply.attempts,reply.lease_until,reply.due_at,
            (${family("inbox", group, pin)}) AS supported,
            (${current("inbox", group, pin)}) AS eligible
          FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
          WHERE inbox.bot_id=? AND reply.state IN ('pending','leased','sending')
        )
        SELECT candidate.receipt_id FROM active AS candidate
        WHERE candidate.supported AND candidate.eligible AND candidate.attempts<${TELEGRAM_OUTBOX_MAX_ATTEMPTS}
          AND ((candidate.state='pending' AND candidate.due_at<=unixepoch())
            OR (candidate.state='leased' AND candidate.lease_until<=unixepoch()))
          AND NOT EXISTS (
            SELECT 1 FROM active AS earlier
            WHERE earlier.actor_id=candidate.actor_id AND earlier.chat_id=candidate.chat_id
              AND earlier.receipt_id<>candidate.receipt_id AND earlier.supported
              AND ((earlier.state='sending' AND earlier.lease_until>unixepoch()) OR (earlier.eligible
                AND ((earlier.state='leased' AND earlier.lease_until>unixepoch()) OR (
                  earlier.receipt_id<candidate.receipt_id AND earlier.state IN ('pending','leased')
                  AND earlier.attempts<${TELEGRAM_OUTBOX_MAX_ATTEMPTS})))))
        ORDER BY candidate.receipt_id LIMIT 1)`)
      .bind(leaseId, ...currentBindings(pin), pin.botId),
    db.prepare(`SELECT inbox.receipt_id AS receiptId,inbox.update_id AS updateId,inbox.actor_id AS actorId,
      inbox.chat_id AS chatId,inbox.chat_type AS chatType,inbox.thread_id AS threadId,
      inbox.message_id AS messageId,inbox.message_date AS messageDate,inbox.command,inbox.receipt_nonce AS marker,authority.generation,
      authority.actor_revision AS actorRevision,authority.actor_role AS actorRole,reply.attempts,reply.lease_id AS leaseId,
      page.kind AS viewKind,action.kind AS actionKind,action.subscription_id AS actionSubscriptionId,
      action.expected_revision AS actionRevision,
      ${pin.privateClaims ? `(SELECT code_sha256 FROM telegram_private_claim WHERE receipt_id=inbox.receipt_id
        AND inbox.receipt_nonce IN ('${TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER}'
          ${hasGeneralGroupShare(pin) ? `,'${TELEGRAM_GENERAL_GROUP_CLAIM_MARKER}'` : ""}))` : "NULL"} AS claimCodeSha256
      FROM telegram_outbox AS reply JOIN telegram_inbox AS inbox USING (receipt_id)
      JOIN telegram_general_receipt AS authority USING (receipt_id)
      LEFT JOIN telegram_view AS page USING (receipt_id)
      LEFT JOIN telegram_lifecycle_action AS action ON action.receipt_id=inbox.receipt_id
        AND inbox.receipt_nonce='${GENERAL_LIFECYCLE_MARKER}'
      WHERE reply.lease_id=? AND reply.state='leased' AND inbox.bot_id=? AND ${family("inbox", group, pin)}`).bind(leaseId, pin.botId),
  ]);
  if (!claimed?.success || !read?.success || claimed.meta.changes > 1 || read.results.length !== claimed.meta.changes) {
    throw new Error("General Telegram lease could not be confirmed.");
  }
  return read.results[0] ?? null;
}

function selectLease(
  pin: GeneralTelegramPin, lease: SharedReadLease, authorizing: boolean, guard?: ReplyGuard, typedShort?: ReplyGuard,
) {
  const group = !pin.rehearsal && lease.chatType !== "private";
  const groupClaim = hasGeneralGroupShare(pin) && lease.marker === TELEGRAM_GENERAL_GROUP_CLAIM_MARKER;
  const claim = pin.privateClaims && (groupClaim || lease.marker === TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER);
  const aggregate = pin.privateAggregate && lease.marker === GENERAL_TELEGRAM_AGGREGATE_MARKER;
  const selected = pin.privateSelected && lease.marker === GENERAL_TELEGRAM_SELECTED_MARKER;
  const short = pin.privateShort && lease.marker === GENERAL_TELEGRAM_SHORT_MARKER;
  const providerDocument = pin.providerDocumentReplies && lease.marker === GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER;
  const batch = pin.providerBatch && isGeneralProviderBatchReply(lease.marker);
  const supported = batch ? telegramProviderBatchReplyMarker("inbox", true) : groupClaim ? groupClaimFamily("inbox") : aggregate ? aggregateFamily("inbox")
    : selected ? selectedFamily("inbox") : short ? shortFamily("inbox")
    : providerDocument ? generalProviderDocumentReplyScope("inbox") : typedShort
      ? `inbox.receipt_nonce='${GENERAL_SUBSCRIPTION_READ_MARKER}' AND inbox.command='help'
        AND inbox.chat_type='private' AND inbox.chat_id=inbox.actor_id AND inbox.thread_id IS NULL`
      : family("inbox", group, pin, false);
  const claimProof = claim ? ` AND EXISTS (SELECT 1 FROM telegram_private_claim
    WHERE receipt_id=inbox.receipt_id AND code_sha256=?)` : "";
  const exact = `FROM telegram_inbox AS inbox JOIN telegram_general_receipt AS authority USING (receipt_id)
    WHERE inbox.bot_id=? AND inbox.receipt_id=? AND inbox.update_id=? AND inbox.actor_id=?
      AND inbox.chat_id=? AND inbox.chat_type=? AND inbox.thread_id IS ? AND inbox.message_id=? AND inbox.message_date=?
      AND inbox.command=? AND inbox.receipt_nonce=? AND authority.actor_revision=? AND authority.actor_role=?
      AND ${generalRecordedOriginSql("inbox")} AND (${supported})${claimProof}`;
  const exactBindings = [pin.botId, lease.receiptId, lease.updateId, lease.actorId, lease.chatId, lease.chatType, lease.threadId,
    lease.messageId, lease.messageDate, lease.command, lease.marker, lease.actorRevision, lease.actorRole,
    ...generalPolicyBindings(pin, lease.generation), ...(claim ? [lease.claimCodeSha256] : [])];
  const simpleAuthority = aggregate || selected || short || groupClaim || batch || typedShort !== undefined;
  const eligible = !authorizing ? "1" : simpleAuthority
    ? `${batch ? generalProviderBatchReplyEligible("inbox") : generalOrdinaryReplyEligibilitySql("inbox")}
      AND ${generalCurrentAuthoritySql("inbox")}` : current("inbox", group, pin);
  const eligibilityBindings = !authorizing ? [] : simpleAuthority ? generalPolicyBindings(pin) : currentBindings(pin);
  if (guard) {
    // Keep the origin, reply eligibility and payload guard separate inside the atomic begin.
    return { sql: `WITH candidate AS MATERIALIZED (
      SELECT inbox.receipt_id,(${eligible}) AS eligible,(${guard.sql}) AS prepared
        ${typedShort ? `,(${typedShort.sql}) AS typed_short` : ""} ${exact}
    ) SELECT receipt_id FROM candidate WHERE eligible AND prepared ${typedShort ? "AND typed_short" : ""}`,
    bindings: [...eligibilityBindings, ...guard.bindings, ...(typedShort?.bindings ?? []), ...exactBindings] };
  }
  return { sql: `SELECT inbox.receipt_id ${exact} ${authorizing ? `AND ${eligible}` : ""}`,
    bindings: [...exactBindings, ...eligibilityBindings] };
}

async function confirmGuardedGeneralSend(db: D1Database, lease: SharedReadLease, scope: ReplyGuard): Promise<boolean> {
  return await db.prepare(`WITH allowed AS MATERIALIZED (${scope.sql})
    SELECT 1 FROM allowed JOIN telegram_outbox AS reply USING(receipt_id)
    WHERE reply.state='sending' AND reply.attempts=? AND reply.lease_id=? AND reply.lease_until>unixepoch()`)
    .bind(...scope.bindings, lease.attempts, lease.leaseId).first().catch(() => null) !== null;
}

export async function beginGeneralSharedTelegramReply(
  db: D1Database, pin: GeneralTelegramPin, lease: SharedReadLease, tickets: readonly TelegramLifecycleTicket[] = [],
  metadata?: MetadataReply,
): Promise<boolean> {
  if (!pin.sharedOutbox || lease.marker === TELEGRAM_GENERAL_GROUP_CLAIM_MARKER || isGeneralProviderBatchReply(lease.marker)
    || Boolean(metadata) !== (lease.marker === GENERAL_SUBSCRIPTION_READ_MARKER)) return false;
  if ((tickets.length > 0 || metadata) && !pin.privateManagement) return false;
  if ((tickets.length > 0 || (metadata && (metadata.tickets.length > 0 || metadata.refreshTicket)))
    && (lease.chatType !== "private" || lease.threadId !== null)) return false;
  if (!pin.privateFormats && metadata?.tickets.some(({ kind }) => kind === "format")) return false;
  const refresh = metadata?.refreshTicket;
  if (refresh && !pin.privateProvider) return false;
  const begin = prepareTelegramOutboxBegin(db, lease, selectLease(pin, lease, true, metadata));
  const count = metadata?.tickets.length ?? tickets.length;
  if (count === 0 && !refresh) return await begin.first() !== null;
  if (!metadata && lease.marker !== GENERAL_LIFECYCLE_VIEW_MARKER && lease.marker !== GENERAL_LIFECYCLE_MARKER) return false;
  const steps = [begin];
  const expected: number[] = [];
  if (count > 0) {
    steps.push(metadata ? insertTelegramSubscriptionReadTickets(db, lease, metadata.tickets, 1, false, true)
      : insertTelegramLifecycleTickets(db, lease.receiptId, lease.attempts, lease.leaseId, tickets, 1, true));
    expected.push(count);
  }
  if (refresh) {
    steps.push(insertTelegramProviderRefreshTicket(db, pin, lease, refresh, count || 1));
    expected.push(1);
    steps.push(db.prepare(`SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=? AND attempts=?
      AND lease_id=? AND state='sending') OR EXISTS (SELECT 1 FROM telegram_provider_refresh_tickets
      WHERE token_sha256=? AND origin_receipt_id=? AND origin_attempt=?) THEN 1
      ELSE json_extract('general refresh ticket missing','$') END`)
      .bind(lease.receiptId, lease.attempts, lease.leaseId, refresh.tokenSha256, lease.receiptId, lease.attempts));
  }
  const results = await db.batch(steps);
  const changed = results[0]?.results.length;
  if (results.length !== steps.length || !results.every(({ success }) => success) || (changed !== 0 && changed !== 1)
    || expected.some((size, i) => results[i + 1].meta.changes !== changed * size)) {
    throw new Error("General Telegram reply tickets could not be confirmed.");
  }
  return changed === 1;
}

async function drainGeneralSelectedReply(
  db: D1Database, pin: GeneralTelegramPin, lease: SharedReadLease, publicOrigin: PublicOrigin, key: CryptoKey | null,
): Promise<boolean> {
  if (!pin.privateSelected) return false;
  let selected = await db.prepare(`SELECT result,code_sha256 AS codeSha256 FROM telegram_selected_actions
    WHERE receipt_id=? AND auth_message_date=0 AND auth_message_id=0`).bind(lease.receiptId).first<TelegramSelectedReply>();
  if (!selected) return false;
  const code = await resolveTelegramSelectedCode(db, pin, { ...lease, selected }, key);
  if (selected.result === "issued" && code === null) {
    if (!await retireUnsentSelectedLink(db, pin, lease, "leased")) return false;
    selected = { result: "stale", codeSha256: null };
  }
  const tickets = code !== null && selected.codeSha256 !== null
    ? [{ ...await prepareSelectedRevokeTicket(), codeSha256: selected.codeSha256 }]
    : selected.result === "limit" ? await prepareSelectedLimitTickets(db, pin, lease.actorId) : null;
  const guard = tickets ? selectedTicketTargetGuard(pin, selected, tickets) : null;
  if (tickets && !guard) return false;
  const begin = prepareTelegramOutboxBegin(db, lease, selectLease(pin, lease, true, guard ?? undefined));
  if (tickets) {
    const results = await db.batch([
      begin, insertSelectedRevokeTickets(db, lease.receiptId, lease.attempts, lease.leaseId, tickets, true),
      db.prepare(`SELECT CASE WHEN changes()=? OR NOT EXISTS (SELECT 1 FROM telegram_outbox
        WHERE receipt_id=? AND attempts=? AND lease_id=? AND state='sending') THEN 1
        ELSE json_extract('general selected ticket missing','$') END`)
        .bind(tickets.length, lease.receiptId, lease.attempts, lease.leaseId),
    ]);
    const changed = results[0]?.results.length;
    if (results.length !== 3 || results.some(({ success }) => !success) || (changed !== 0 && changed !== 1)
      || results[1].meta.changes !== changed * tickets.length) throw new Error("General selected export reply could not begin.");
    if (changed === 0) return false;
  } else if (await begin.first() === null) return false;
  const confirmed = code === null || await resolveTelegramSelectedCode(db, pin, { ...lease, selected }, key, true) === code;
  if (!confirmed) await retireUnsentSelectedLink(db, pin, lease, "sending");
  const keyboard = tickets?.map((ticket, index) => [{
    text: code === null ? `撤销最近第${index + 1}条链接` : "撤销此链接", callback_data: ticket.token,
  }]);
  const text = code === null ? renderTelegramSelected(selected) : `Clash 所选订阅聚合链接\n${publicOrigin}/agg/${code}/clash`;
  const outcome = confirmed ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text, keyboard)
    : { kind: "failed" as const };
  await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
  return true;
}

export async function drainGeneralSharedTelegramReply(
  db: D1Database, pin: GeneralTelegramPin, bucket: R2Bucket, publicOrigin: PublicOrigin,
  refreshAvailable?: () => Promise<boolean>, share?: TelegramPrivateShareRuntime, aggregateKey: CryptoKey | null = null,
): Promise<boolean> {
  const lease = await claimGeneralSharedTelegramReply(db, pin);
  if (!lease) return false;
  if (lease.marker === GENERAL_TELEGRAM_PROVIDER_DOCUMENT_MARKER) {
    const reply = await renderTelegramProviderDocumentReply(db, generalProviderAuthority(pin), { ...lease, providerDocument: true });
    if (!reply) return false;
    const scope = selectLease(pin, lease, false, reply.guard);
    if (await prepareTelegramOutboxBegin(db, lease, scope).first() === null) return false;
    const confirmed = await confirmGuardedGeneralSend(db, lease, scope);
    const outcome = confirmed ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, reply.text)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (lease.marker === GENERAL_TELEGRAM_SHORT_MARKER) {
    if (!pin.privateShort) return false;
    const short = { ...lease, shortLink: true as const };
    const reply = await prepareTelegramShortLinkReply(db, pin, short, aggregateKey, publicOrigin);
    if (reply.kind === "notice") await retireUnsentTelegramShortLink(db, pin, short);
    const scope = selectLease(pin, lease, true, reply.kind === "link" ? reply.guard : undefined);
    if (await prepareTelegramOutboxBegin(db, lease, scope).first() === null) return false;
    const confirmed = reply.kind === "notice" || await confirmGuardedGeneralSend(db, lease, scope);
    const outcome = confirmed ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, reply.text)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (lease.marker.startsWith(TELEGRAM_GENERAL_TEMP_RAW_PREFIX)) {
    const temp = await readGeneralTempReply(db, lease.receiptId);
    if (!temp || temp.kind !== "summary") return false;
    const deadline = Date.now() + 13_000;
    const raw = { ...lease, temp, tempRaw: true as const };
    const prepared = await prepareTelegramTempRawReply(db, pin, raw, deadline);
    if (Date.now() >= deadline) return false;
    const payload = prepared.kind === "text" || prepared.kind === "document" ? prepared : null;
    const scope = payload ? selectLease(pin, lease, false, payload.guard) : selectLease(pin, lease, true);
    if (await prepareTelegramOutboxBegin(db, lease, scope).first() === null) return false;
    let outcome: TelegramReplyOutcome;
    if (payload) {
      const confirmed = await confirmTelegramTempRawSend(db, pin, raw, payload.guard);
      const remaining = deadline - Date.now();
      outcome = confirmed && remaining > 0
        ? await sendGeneralTelegramTempRawReply(pin.botToken, lease.actorId, lease.messageId, payload, Math.min(5_000, remaining))
        : { kind: "failed" as const };
    } else {
      const text = prepared.kind === "stale" ? "临时列表或授权已变更，请重新发送 /temp raw。" : "暂时无法读取临时节点，请稍后重试。";
      outcome = await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text);
    }
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (lease.marker === GENERAL_TELEGRAM_SELECTED_MARKER) {
    return drainGeneralSelectedReply(db, pin, lease, publicOrigin, aggregateKey);
  }
  if (lease.marker === GENERAL_AUTH_ACTION_MARKER) {
    const [begun, reply] = await db.batch<GeneralAuthReply>([
      prepareTelegramOutboxBegin(db, lease, selectLease(pin, lease, true)), prepareGeneralAuthActionReply(db, lease, pin),
    ]);
    const limit = lease.command === "auth-list" ? GENERAL_AUTH_LIST_LIMIT + 1 : 1;
    if (!begun?.success || !reply?.success || begun.results.length > 1 || reply.results.length > begun.results.length * limit) {
      throw new Error("General Telegram authorization reply could not be confirmed.");
    }
    if (!begun.results.length) return false;
    const text = renderGeneralAuthActionReply(reply.results, lease.command);
    const outcome = text ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (isGeneralProviderBatchReply(lease.marker)) {
    if (!pin.providerBatch) return false;
    const prepared = await renderTelegramProviderBatchReply(db, pin, lease);
    if (!prepared) return false;
    const scope = selectLease(pin, lease, true, prepared.guard);
    const begin = prepareTelegramOutboxBegin(db, lease, scope);
    if (prepared.ticket) {
      const [started, installed] = await db.batch([begin, installTelegramProviderBatchTicket(db, lease, prepared.ticket.sha256),
        db.prepare(`SELECT CASE WHEN NOT EXISTS (SELECT 1 FROM telegram_outbox WHERE receipt_id=? AND attempts=?
          AND lease_id=? AND state='sending') OR EXISTS (SELECT 1 FROM telegram_provider_batch_interactions
          WHERE receipt_id=? AND origin_attempt=? AND token_sha256=?) THEN 1
          ELSE json_extract('general batch ticket missing','$') END`)
          .bind(lease.receiptId, lease.attempts, lease.leaseId, lease.receiptId, lease.attempts, prepared.ticket.sha256)]);
      if (!started?.success || !installed?.success || started.results.length > 1 || installed.meta.changes !== started.results.length) {
        throw new Error("General Telegram provider batch reply could not begin.");
      }
      if (!started.results.length) return false;
    } else if (await begin.first() === null) return false;
    const keyboard = prepared.ticket ? [[{ text: "确认刷新", callback_data: prepared.ticket.value }]] : undefined;
    const outcome = await confirmGuardedGeneralSend(db, lease, scope)
      ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, prepared.text, keyboard)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (lease.marker === TELEGRAM_GENERAL_SHARE_CREATION_MARKER) {
    if (!pin.privateShareCreation || !share?.context) return false;
    const reply = await resolveTelegramPrivateShareCreationReply(db, pin, lease, share.context);
    const recorded = selectLease(pin, lease, false);
    const selection = reply ? selectLease(pin, lease, false, {
      sql: `${generalOrdinaryReplyEligibilitySql("inbox")} AND (${reply.guard.sql})`,
      bindings: reply.guard.bindings,
    }) : selectLease(pin, lease, true);
    const keyboard = reply && hasGeneralGroupShare(pin) && await generalGroupShareReady(db, pin).catch(() => false)
      ? [[{ text: "发到指定群", callback_data: GROUP_SHARE_PUBLISH_CALLBACK }]] : undefined;
    if (!await prepareTelegramOutboxBegin(db, lease, selection).first()) return false;
    const text = reply ? renderTelegramPrivateShareLink(pin.botUsername, reply, await readBotDisplayTimeZone(db, pin.botId))
      : "分享链接已失效或授权已变更，请重新创建。";
    const outcome = await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text, keyboard);
    await settleTelegramOutboxReply(db, lease, recorded, outcome);
    return true;
  }
  if (lease.marker === GENERAL_TELEGRAM_AGGREGATE_MARKER) {
    const aggregate = await db.prepare(`SELECT result,revision,code_sha256 AS codeSha256 FROM telegram_aggregate_actions
      WHERE receipt_id=? AND auth_message_date=0 AND auth_message_id=0`).bind(lease.receiptId).first<TelegramAggregateReply>();
    if (!pin.privateAggregate || !aggregate) return false;
    const prepared = await prepareTelegramAggregateCode(db, pin, { ...lease, aggregate }, aggregateKey);
    const text = prepared ? await renderTelegramAggregateLinks(db, bucket, prepared.code, Date.now() + 13_000, publicOrigin)
      : renderTelegramAggregateResult(aggregate.result);
    const scope = selectLease(pin, lease, true, prepared?.guard);
    if (await prepareTelegramOutboxBegin(db, lease, scope).first() === null) return false;
    const confirmed = !prepared || await confirmGuardedGeneralSend(db, lease, scope);
    const outcome = confirmed ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, text)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (lease.marker === TELEGRAM_GENERAL_PRIVATE_CLAIM_MARKER || lease.marker === TELEGRAM_GENERAL_GROUP_CLAIM_MARKER) {
    if (!pin.privateClaims || !lease.claimCodeSha256) return false;
    const group = lease.marker === TELEGRAM_GENERAL_GROUP_CLAIM_MARKER;
    if (group && !hasGeneralGroupShare(pin)) return false;
    const guard = group && hasGeneralGroupShare(pin) ? generalGroupShareClaimGuard(pin) : undefined;
    const claim = { ...lease, privateClaim: { codeSha256: lease.claimCodeSha256, ...(group ? { group: true as const } : {}) } };
    const prepared = await prepareTelegramPrivateClaim(db, bucket, pin, claim);
    const result = await beginTelegramPrivateClaim(db, pin, claim, prepared,
      prepareTelegramOutboxBegin(db, lease, selectLease(pin, lease, true, guard)));
    if (!result) return false;
    const outcome = await sendPrivateShareClaimResult(pin.botToken, lease.actorId, lease.messageId, result, 5_000);
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  if (lease.marker === GENERAL_SUBSCRIPTION_READ_MARKER) {
    const presentation = await renderGeneralSubscriptionRead(db, pin, lease, bucket, publicOrigin, refreshAvailable,
      pin.privateShareCreation && Boolean(share?.context));
    if (!presentation?.readGuard) return false;
    if (lease.chatType !== "private") {
      if (presentation.readButtons?.length || presentation.refreshTarget || presentation.shortTarget) return false;
      if (!await beginGeneralSharedTelegramReply(db, pin, lease, [], { ...presentation.readGuard, tickets: [] })) return false;
      const confirmed = await confirmTelegramSubscriptionReadSend(db, pin, lease, presentation.readGuard).catch(() => false);
      const outcome = confirmed ? await sendGeneralTelegramGroupListReply(pin.botToken, lease.chatId, lease.messageId,
        lease.threadId, presentation.text) : { kind: "failed" as const };
      await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
      return true;
    }
    const { readGuard, shortTarget } = presentation;
    const issueShort = pin.subscriptionShorts === "issue";
    if (pin.privateFormats && !pin.rehearsal && (lease.attempts > 1 || (issueShort && shortTarget))) {
      const typedLease = { ...lease, subscriptionRead: true as const };
      const exactOnly = { sql: "1", bindings: [] };
      let started: SubscriptionShortCandidate | null = null;
      let beginning = false;
      try {
        if (await telegramSubscriptionShortsReady(db)) {
          if (shortTarget && aggregateKey) {
            const candidate = await prepareTelegramSubscriptionShort(db, pin, typedLease, shortTarget, exactOnly, aggregateKey, issueShort);
            if (candidate) {
              const publication = subscriptionShortPublicationGuard(candidate, exactOnly, true);
              const begin = prepareTelegramOutboxBegin(db, lease, selectLease(pin, lease, true, readGuard, publication));
              beginning = true;
              if (await beginSubscriptionShortDelivery(db, typedLease, candidate, begin,
                subscriptionShortSendGuard(candidate, exactOnly, true))) started = candidate;
            }
          }
          if (!started && await hasTelegramSubscriptionShort(db, pin, typedLease)) {
            await closeUnsentTelegramSubscriptionShort(db, pin, typedLease);
            return true;
          }
        }
      } catch {
        // No Telegram request can have started in this block.
        if (beginning) await closeUnsentTelegramSubscriptionShort(db, pin, typedLease);
        return false;
      }
      if (started && shortTarget) {
        const target = subscriptionShortSendGuard(started, exactOnly, true);
        const confirmed = await confirmGuardedGeneralSend(db, lease, selectLease(pin, lease, true, readGuard, target));
        const outcome = confirmed
          ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId,
            `${shortTarget.label}\n${publicOrigin}/s/${started.code}`)
          : { kind: "failed" as const };
        await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome, "inbox.received_at", GENERAL_REPLY_TTL);
        return true;
      }
      if (issueShort && shortTarget) presentation.text = "暂时无法生成订阅短链，请重新打开订阅详情后重试。";
    }
    const prepared = presentation.readButtons?.length ? await prepareTelegramSubscriptionReadTickets(presentation.readButtons) : undefined;
    const refresh = presentation.refreshTarget ? await prepareTelegramProviderRefreshButton(presentation.refreshTarget) : undefined;
    if (!await beginGeneralSharedTelegramReply(db, pin, lease, [], { ...presentation.readGuard, tickets: prepared?.tickets ?? [],
      refreshTicket: refresh?.ticket })) return false;
    const confirmed = await confirmTelegramSubscriptionReadSend(db, pin, lease, presentation.readGuard).catch(() => false);
    const keyboard = refresh ? [...(prepared?.keyboard ?? []), [refresh.button]] : prepared?.keyboard;
    const outcome = confirmed
      ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, presentation.text, keyboard)
      : { kind: "failed" as const };
    await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
    return true;
  }
  let presentation: ReturnType<typeof renderTelegramLifecycle>;
  let settingsKeyboard: { text: string; callback_data: string }[][] | undefined;
  let commandMenu: TelegramCommandContext | undefined;
  let mainMenu: TelegramMainMenuFeatures | undefined;
  if (lease.marker === GENERAL_LIFECYCLE_MARKER && lease.actionKind !== null && lease.actionSubscriptionId !== null
    && lease.actionRevision !== null) {
    presentation = renderTelegramLifecycle({ kind: lease.actionKind, subscriptionId: lease.actionSubscriptionId,
      expectedLifecycleRevision: lease.actionRevision });
  } else if (lease.marker === GENERAL_LIFECYCLE_VIEW_MARKER && lease.viewKind !== null) {
    const view = await renderTelegramView(db, lease.actorId, { kind: lease.viewKind, afterId: null, afterEpoch: null }, false, false,
      await readBotDisplayTimeZone(db, pin.botId));
    presentation = { text: view.text, buttons: view.lifecycleButtons, forceReply: false };
  } else if (lease.marker === GENERAL_PATH_MARKER) {
    const path = await db.prepare(`SELECT kind,after_id AS afterId,affected_count AS affectedCount
      FROM telegram_path_reply WHERE receipt_id=?`).bind(lease.receiptId).first<TelegramPathReply>();
    if (!path) throw new Error("General Telegram path reply could not be confirmed.");
    presentation = { text: await renderTelegramPath(db, lease.actorId, path), buttons: [], forceReply: false };
  } else if (lease.marker === TELEGRAM_GENERAL_TEMP_MARKER) {
    const temp = await readGeneralTempReply(db, lease.receiptId);
    if (!temp) throw new Error("General Telegram temporary node reply could not be confirmed.");
    presentation = { text: renderTelegramTemp(temp), buttons: [], forceReply: false };
  } else if (lease.marker === GENERAL_INLINE_CONSENT_MARKER) {
    const consent = await db.prepare(`SELECT kind FROM telegram_inline_search_consent
      WHERE receipt_id=? AND bot_id=? AND actor_id=?`).bind(lease.receiptId, pin.botId, lease.actorId)
      .first<TelegramInlineConsentReply>("kind");
    if (!consent) return false;
    const text = consent === "usage"
      ? "用法：/inline on 在自己的私聊搜索订阅，15 分钟内有效。/inline off 关闭。"
      : renderTelegramInlineConsent(consent);
    presentation = { text, buttons: [], forceReply: false };
  } else if (lease.marker === TELEGRAM_GENERAL_DOCUMENT_JOB_MARKER) {
    const document = await db.prepare(`SELECT job.result_code AS kind,saved.node_count AS nodeCount
      FROM telegram_document_jobs AS job LEFT JOIN telegram_document_saved_counts AS saved USING (receipt_id)
      WHERE job.receipt_id=? AND job.bot_id=? AND job.actor_id=? AND job.state='done'`)
      .bind(lease.receiptId, pin.botId, lease.actorId).first<{ kind: TelegramDocumentJobResult; nodeCount: number | null }>();
    if (!document || (document.kind === "saved" && document.nodeCount === null)) {
      throw new Error("General Telegram document reply could not be confirmed.");
    }
    presentation = { text: renderTelegramDocumentOutcome(document.kind, document.nodeCount), buttons: [], forceReply: false };
  } else if (lease.marker === GENERAL_TELEGRAM_PROVIDER_MARKER) {
    const reply = await db.prepare(`SELECT provider.outcome,origin.kind FROM telegram_provider_replies AS provider
      JOIN telegram_provider_requests AS origin USING(receipt_id) WHERE provider.receipt_id=?`)
      .bind(lease.receiptId).first<{ outcome: TelegramProviderReply; kind: TelegramProviderRequestKind }>();
    if (!reply) throw new Error("General Telegram provider reply could not be confirmed.");
    presentation = { text: renderTelegramProviderReply(reply.outcome, reply.kind), buttons: [], forceReply: false };
  } else {
    if (lease.command !== "help" && lease.command !== "list" && lease.command !== "start") return false;
    const settings = lease.command === "help" && lease.chatType === "private" && lease.threadId === null
      ? await renderTelegramDisplaySettings(db, pin.botId, lease.receiptId, lease.actorRole === "admin") : null;
    settingsKeyboard = settings?.keyboard;
    if (settings) {
      presentation = { text: settings.text, buttons: [], forceReply: false };
    } else if (lease.command === "list") {
      const view = await renderTelegramView(db, lease.actorId, { kind: lease.viewKind ?? "list", afterId: null, afterEpoch: null }, false, false,
        await readBotDisplayTimeZone(db, pin.botId));
      presentation = { text: view.text, buttons: [], forceReply: false };
    } else {
      const features: TelegramMainMenuFeatures = {
        management: pin.privateManagement, subscriptionRead: pin.privateManagement, temp: pin.privateTemp,
        path: pin.privateManagement, aggregate: pin.privateAggregate && aggregateKey !== null,
        selected: pin.privateSelected && aggregateKey !== null, short: pin.privateShort && aggregateKey !== null,
        share: pin.privateShareCreation && Boolean(share?.context), batchRefresh: false,
        inlineOff: pin.privateInline, batchStatus: pin.providerBatch, authorization: pin.privateAuthorization, displayTimezone: pin.displayTimezone,
        documentImport: pin.privateDocument, ...pin.commandFeatures,
      };
      commandMenu = { privateChat: lease.chatType === "private", role: lease.actorRole, features };
      const text = renderTelegramHelp(commandMenu);
      presentation = { text: lease.command === "start" ? `欢迎使用 subs-bot。\n${text}` : text, buttons: [], forceReply: false };
      if (commandMenu.privateChat) mainMenu = features;
    }
  }
  const prepared = presentation.buttons.length ? await prepareTelegramLifecycleTickets(presentation.buttons) : undefined;
  if (!await beginGeneralSharedTelegramReply(db, pin, lease, prepared?.tickets)) return false;
  const outcome = lease.chatType === "private"
    ? await sendGeneralTelegramPrivateReply(pin.botToken, lease.actorId, lease.messageId, presentation.text,
      settingsKeyboard ?? prepared?.keyboard, presentation.forceReply, mainMenu)
    : await sendGeneralTelegramGroupListReply(pin.botToken, lease.chatId, lease.messageId, lease.threadId, presentation.text);
  await settleTelegramOutboxReply(db, lease, selectLease(pin, lease, false), outcome);
  return true;
}

export async function recoverGeneralSharedTelegramReplies(
  db: D1Database, pin: GeneralTelegramPin, bucket: R2Bucket, publicOrigin: PublicOrigin,
  refreshAvailable?: () => Promise<boolean>, share?: TelegramPrivateShareRuntime, aggregateKey: CryptoKey | null = null,
): Promise<void> {
  if (!pin.sharedOutbox) return;
  let shareRecoveryFailed = false;
  if (pin.privateShareCreation && share?.schemaReady) {
    try {
      try {
        if (share.context) await recoverTelegramPrivateShareCreation(db, bucket, pin, share.context);
      } finally {
        await retireAbandonedTelegramPrivateShareCreation(db, bucket, pin);
      }
    } catch {
      shareRecoveryFailed = true;
    }
  }
  const group = !pin.rehearsal && await groupSchemaReady(db);
  const markers = queueMarkers(group, pin);
  await db.prepare(`UPDATE telegram_outbox SET state=CASE WHEN state='sending' THEN 'uncertain' ELSE 'failed' END,
      lease_id=CASE WHEN state='sending' THEN lease_id ELSE NULL END,lease_until=NULL
    WHERE receipt_id IN (SELECT inbox.receipt_id FROM telegram_inbox AS inbox JOIN telegram_outbox AS reply USING (receipt_id)
      WHERE inbox.bot_id=? AND (inbox.receipt_nonce IN (${markers})${pin.privateTemp ? ` OR (${generalTempRawMarker("inbox")})` : ""})
        AND ((reply.state='sending' AND reply.lease_until<=unixepoch())
        OR (reply.state IN ('pending','leased') AND (NOT (${current("inbox", group, pin)})
          OR (reply.attempts>=${TELEGRAM_OUTBOX_MAX_ATTEMPTS} AND (reply.state='pending' OR reply.lease_until<=unixepoch())))))
      ORDER BY inbox.receipt_id LIMIT 16)
      AND EXISTS (SELECT 1 FROM telegram_general_policy AS policy WHERE ${GENERAL_POLICY_PIN_SQL} AND ${GENERAL_RECEIPT_SCHEMA})`)
    .bind(pin.botId, ...currentBindings(pin), ...generalPolicyBindings(pin)).run();
  if (pin.privateManagement) {
    await reapTelegramLifecycle(db, pin.botId);
    await reapTelegramSubscriptionReadTickets(db, pin.botId);
  }
  for (let i = 0; i < 4 && await drainGeneralSharedTelegramReply(db, pin, bucket, publicOrigin, refreshAvailable, share, aggregateKey); i++) {
    // Bound scheduled work and preserve the ordinary outbox's lease and settlement semantics.
  }
  if (pin.privateSelected) await reapTelegramSelected(db, pin.botId);
  if (pin.privateFormats) await reapFailedTelegramSubscriptionShorts(db, pin.botId, true);
  if (pin.privateShort) await reapFailedTelegramShortLinks(db, pin.botId, true);
  if (pin.privateProvider && await generalProviderRefreshReady(db).catch(() => false)) {
    await reapTelegramProviderRefreshTickets(db, pin.botId);
  }
  if (shareRecoveryFailed) throw new Error("General Telegram private share recovery could not be confirmed.");
}

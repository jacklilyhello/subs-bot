import { importTelegramPrivateShareCreationKey, type TelegramPrivateShareCreationKey } from "./private-share-creation.ts";

export const PRIVATE_SHARE_CREATION_INSTALLATION = "subs-bot-cf-dev-01";
export const PRIVATE_SHARE_CREATION_MIGRATION = "0016_telegram_private_share_creation.sql";
export const PRIVATE_SHARE_CREATION_SCHEMA_SHA256 = "ad8be2d0034f2272d873cb6accc2927f73199a512447858a8aecd23b2b696a78";

export interface TelegramPrivateShareRuntime {
  readonly schemaReady: boolean;
  readonly context: TelegramPrivateShareCreationKey | null;
  readonly groupCardsEnabled?: boolean;
}

export const PRIVATE_SHARE_DISABLED: TelegramPrivateShareRuntime = Object.freeze({ schemaReady: false, context: null });

/** Read once per invocation. Missing/old schemas and invalid keys disable only this feature. */
export async function telegramPrivateShareRuntime(
  db: D1Database, encoded: unknown, groupCardsEnabled = false, installation = PRIVATE_SHARE_CREATION_INSTALLATION,
): Promise<TelegramPrivateShareRuntime> {
  let schemaReady = false;
  try {
    const ledger = await db.prepare(`SELECT name FROM sqlite_schema WHERE type = 'table' AND name = 'subs_bot_schema_migrations'`).first();
    if (!ledger) return PRIVATE_SHARE_DISABLED;
    const row = await db.prepare(`SELECT position, sha256, mode FROM subs_bot_schema_migrations WHERE name = ?`)
      .bind(PRIVATE_SHARE_CREATION_MIGRATION).first<{ position: number; sha256: string; mode: string }>();
    schemaReady = row?.position === 16 && row.sha256 === PRIVATE_SHARE_CREATION_SCHEMA_SHA256 && row.mode === "applied";
  } catch {
    // Unconfirmed reads need retry; an explicit absence above is an older schema.
    throw new Error("Telegram private share readiness could not be confirmed.");
  }
  if (!schemaReady) return PRIVATE_SHARE_DISABLED;
  const context = await importTelegramPrivateShareCreationKey(encoded, installation);
  return Object.freeze({ schemaReady: true, context, ...(groupCardsEnabled ? { groupCardsEnabled: true } : {}) });
}

/** Presentation only: all persisted instants remain Unix seconds. */
export const DEFAULT_DISPLAY_TIME_ZONE = "UTC";
export const DISPLAY_SETTINGS_MIGRATION = "0051_telegram_display_settings.sql";
export const DISPLAY_SETTINGS_SHA256 = "a244881478a897fc41113699ad5e9b81ad4a00e842bc061f92949af5a3c461b9";

export async function telegramDisplaySettingsReady(db: D1Database): Promise<boolean> {
  const schema = await db.prepare(`SELECT name,type,sql FROM sqlite_schema
    WHERE name IN ('telegram_bot_display_settings','telegram_display_settings_replies','subs_bot_schema_migrations')`)
    .all<{ name: string; type: string; sql: string | null }>();
  if (!schema.success) throw new Error("Telegram display settings schema could not be confirmed.");
  const tables = ["telegram_bot_display_settings", "telegram_display_settings_replies"].map((name) => schema.results.find((row) => row.name === name));
  if (tables.every((row) => row === undefined)) return false;
  if (tables.some((row) => !row || row.type !== "table" || !row.sql)) throw new Error("Telegram display settings schema is incomplete.");
  const source = tables.map((row) => row!.sql).join(";\n\n") + ";\n";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(source));
  if (Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("") !== DISPLAY_SETTINGS_SHA256) {
    throw new Error("Telegram display settings schema differs.");
  }
  if (!schema.results.some((row) => row.name === "subs_bot_schema_migrations" && row.type === "table")) return false;
  const records = await db.prepare(`SELECT name,sha256,mode FROM subs_bot_schema_migrations WHERE position=51 OR name=?`)
    .bind(DISPLAY_SETTINGS_MIGRATION).all<{ name: string; sha256: string; mode: string }>();
  if (!records.success || records.results.length > 1) throw new Error("Telegram display settings migration could not be confirmed.");
  const record = records.results[0];
  if (!record) return false;
  if (record.name !== DISPLAY_SETTINGS_MIGRATION || record.sha256 !== DISPLAY_SETTINGS_SHA256 || record.mode !== "applied") {
    throw new Error("Telegram display settings migration differs.");
  }
  return true;
}

export function parseDisplayTimeZone(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 100 || value.trim() !== value
    || !/^[A-Za-z][A-Za-z0-9_+./-]*$/u.test(value)) return null;
  // Offset identifiers are deliberately excluded: the setting is an IANA zone.
  try {
    return new Intl.DateTimeFormat("en-US", { timeZone: value }).resolvedOptions().timeZone;
  } catch {
    return null;
  }
}

export function displayTelegramDate(epochSeconds: number | null | undefined, timeZone = DEFAULT_DISPLAY_TIME_ZONE): string {
  // Reject accidentally supplied contemporary milliseconds rather than guessing units.
  if (typeof epochSeconds !== "number" || !Number.isSafeInteger(epochSeconds)
    || epochSeconds < -62_135_596_800 || epochSeconds > 253_402_300_799) return "日期未知";
  const zone = parseDisplayTimeZone(timeZone) ?? DEFAULT_DISPLAY_TIME_ZONE;
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: zone, year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(new Date(epochSeconds * 1000));
  const field = (type: Intl.DateTimeFormatPartTypes) => parts.find((part) => part.type === type)?.value;
  const year = field("year");
  if (!year || year.length > 4) return "日期未知";
  return `${year.padStart(4, "0")}-${field("month")}-${field("day")} ${field("hour")}:${field("minute")}:${field("second")}`;
}

export async function readBotDisplayTimeZone(db: D1Database, botId: string): Promise<string> {
  if (!await telegramDisplaySettingsReady(db)) return DEFAULT_DISPLAY_TIME_ZONE;
  const row = await db.prepare("SELECT timezone FROM telegram_bot_display_settings WHERE bot_id=?")
    .bind(botId).first<{ timezone: unknown }>();
  return parseDisplayTimeZone(row?.timezone) ?? DEFAULT_DISPLAY_TIME_ZONE;
}

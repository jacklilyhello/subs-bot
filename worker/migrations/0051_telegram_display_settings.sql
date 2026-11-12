CREATE TABLE telegram_bot_display_settings (
  bot_id TEXT PRIMARY KEY,
  timezone TEXT NOT NULL CHECK(length(timezone) BETWEEN 1 AND 100),
  update_id INTEGER NOT NULL CHECK(update_id>0),
  message_date INTEGER NOT NULL CHECK(message_date>0),
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL DEFAULT(unixepoch())
) STRICT;

CREATE TABLE telegram_display_settings_replies (
  receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox(receipt_id),
  kind TEXT NOT NULL CHECK(kind IN ('current','saved','stale','invalid','denied')),
  timezone TEXT,
  CHECK((kind='saved')=(timezone IS NOT NULL))
) STRICT;

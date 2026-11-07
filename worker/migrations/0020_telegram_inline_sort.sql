CREATE TABLE telegram_inline_sort_preferences (
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    mode TEXT NOT NULL CHECK (mode IN ('default', 'traffic', 'expiry', 'name')),
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    update_id INTEGER NOT NULL CHECK (update_id BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (bot_id, actor_id)
) STRICT;

CREATE TABLE telegram_inline_sort_reply (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('current', 'saved', 'stale', 'usage')),
    mode TEXT CHECK (mode IN ('default', 'traffic', 'expiry', 'name')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((kind IN ('current', 'saved')) = (mode IS NOT NULL))
) STRICT;

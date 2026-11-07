CREATE TABLE telegram_inline_search_consent (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('on', 'off', 'usage', 'stale')),
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    update_id INTEGER NOT NULL CHECK (update_id BETWEEN 1 AND 9007199254740991),
    expires_at INTEGER CHECK (expires_at BETWEEN message_date AND 9007199254740991),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((kind = 'on') = (expires_at IS NOT NULL)),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role <> 'admin' OR auth_message_date = 0)
) STRICT;

CREATE INDEX telegram_inline_search_consent_latest ON telegram_inline_search_consent (bot_id, actor_id, message_date DESC, update_id DESC)
    WHERE kind IN ('on', 'off');

CREATE TABLE telegram_inline_search_receipts (
    bot_id TEXT NOT NULL,
    update_id INTEGER NOT NULL CHECK (update_id BETWEEN 1 AND 9007199254740991),
    actor_id TEXT NOT NULL,
    query_id_sha256 TEXT NOT NULL CHECK (length(query_id_sha256) = 64 AND query_id_sha256 NOT GLOB '*[^0-9a-f]*'),
    consent_receipt_id INTEGER NOT NULL REFERENCES telegram_inline_search_consent (receipt_id),
    sort_mode TEXT NOT NULL CHECK (sort_mode IN ('default', 'traffic', 'expiry', 'name')),
    sort_update_id INTEGER NOT NULL CHECK (sort_update_id BETWEEN 0 AND 9007199254740991),
    received_at INTEGER NOT NULL CHECK (received_at BETWEEN 1 AND 9007199254740991),
    lease_until INTEGER NOT NULL CHECK (lease_until BETWEEN received_at AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('preflight', 'sending', 'sent', 'failed', 'uncertain', 'dropped')),
    result_count INTEGER NOT NULL DEFAULT 0 CHECK (result_count BETWEEN 0 AND 50),
    PRIMARY KEY (bot_id, update_id),
    UNIQUE (bot_id, query_id_sha256)
) STRICT;

CREATE UNIQUE INDEX telegram_inline_search_active ON telegram_inline_search_receipts (bot_id, actor_id)
    WHERE state IN ('preflight', 'sending');

CREATE INDEX telegram_inline_search_rate ON telegram_inline_search_receipts (bot_id, actor_id, received_at);

CREATE INDEX telegram_inline_search_receipts_age ON telegram_inline_search_receipts (bot_id, received_at, update_id);

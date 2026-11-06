CREATE TABLE telegram_lifecycle_action (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (
        kind IN ('rename-prompt', 'trash-prompt', 'renamed', 'trashed', 'restored', 'cancelled', 'invalid', 'stale')
    ),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    expected_revision INTEGER NOT NULL CHECK (expected_revision BETWEEN 0 AND 9007199254740990)
) STRICT;

CREATE TABLE telegram_lifecycle_ticket (
    token_sha256 TEXT NOT NULL PRIMARY KEY CHECK (
        length(token_sha256) = 64 AND length(CAST(token_sha256 AS BLOB)) = 64
        AND token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    origin_receipt_id INTEGER NOT NULL REFERENCES telegram_inbox (receipt_id),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    action TEXT NOT NULL CHECK (action IN ('rename', 'trash-prompt', 'trash', 'restore')),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    expected_revision INTEGER NOT NULL CHECK (expected_revision BETWEEN 0 AND 9007199254740990),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id)
) STRICT;

CREATE TABLE telegram_rename_wait (
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    chat_type TEXT NOT NULL CHECK (chat_type IN ('private', 'group', 'supergroup')),
    thread_key INTEGER NOT NULL CHECK (thread_key BETWEEN 0 AND 9007199254740991),
    origin_receipt_id INTEGER NOT NULL UNIQUE REFERENCES telegram_lifecycle_action (receipt_id),
    last_update_id INTEGER NOT NULL CHECK (last_update_id BETWEEN 1 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    PRIMARY KEY (bot_id, actor_id, chat_id, chat_type, thread_key),
    CHECK (chat_type <> 'private' OR chat_id = actor_id)
) STRICT;

CREATE INDEX telegram_lifecycle_ticket_expiry ON telegram_lifecycle_ticket (expires_at, token_sha256);
CREATE INDEX telegram_rename_wait_expiry ON telegram_rename_wait (expires_at, origin_receipt_id);

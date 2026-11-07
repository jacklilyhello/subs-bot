CREATE TABLE telegram_private_share_creations (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id) CHECK (receipt_id BETWEEN 1 AND 9007199254740991),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('reserved', 'published', 'abandoned')),
    payload_id TEXT NOT NULL UNIQUE CHECK (
        length(payload_id) = 36 AND payload_id NOT GLOB '*[^0-9a-f-]*'
        AND substr(payload_id, 9, 1) = '-' AND substr(payload_id, 14, 1) = '-'
        AND substr(payload_id, 19, 1) = '-' AND substr(payload_id, 24, 1) = '-'
        AND length(replace(payload_id, '-', '')) = 32
    ),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256) = 64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes BETWEEN 1 AND 65536),
    sender_name TEXT NOT NULL CHECK (length(CAST(sender_name AS BLOB)) BETWEEN 1 AND 256 AND instr(sender_name, char(0)) = 0),
    max_claims INTEGER NOT NULL CHECK (max_claims BETWEEN 1 AND 100),
    target_user_id TEXT,
    duration_minutes INTEGER NOT NULL CHECK (duration_minutes BETWEEN 1 AND 10080),
    installation TEXT NOT NULL CHECK (length(installation) BETWEEN 1 AND 64 AND installation NOT GLOB '*[^a-z0-9_-]*'),
    key_version INTEGER NOT NULL CHECK (key_version = 1),
    reservation_expires_at INTEGER NOT NULL CHECK (reservation_expires_at > 0),
    next_check_at INTEGER NOT NULL CHECK (next_check_at > 0),
    cleanup_after INTEGER NOT NULL CHECK (cleanup_after > reservation_expires_at),
    cleaned_at INTEGER,
    share_id INTEGER UNIQUE REFERENCES private_shares (id),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((state = 'published') = (share_id IS NOT NULL)),
    CHECK (cleaned_at IS NULL OR (state = 'abandoned' AND cleaned_at >= cleanup_after))
) STRICT;

CREATE INDEX telegram_private_share_creations_actor_order ON telegram_private_share_creations (bot_id, actor_id, message_date, message_id);

CREATE INDEX telegram_private_share_creations_reserved ON telegram_private_share_creations (bot_id, next_check_at, receipt_id)
    WHERE state = 'reserved';

-- cleaned_at records confirmed absence. Recheck abandoned rows for late R2 commits.
CREATE INDEX telegram_private_share_creations_cleanup ON telegram_private_share_creations (bot_id, next_check_at, receipt_id)
    WHERE state = 'abandoned';

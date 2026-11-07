CREATE TABLE telegram_bulk_trash (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('usage', 'empty', 'limit', 'preview', 'stale', 'trashed')),
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 0 AND 16),
    targets TEXT CHECK (length(CAST(targets AS BLOB)) <= 1024 AND json_valid(targets)
        AND json_type(targets) = 'array' AND json_array_length(targets) = target_count),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    token_sha256 TEXT UNIQUE CHECK (length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_attempt INTEGER CHECK (origin_attempt BETWEEN 1 AND 4),
    expires_at INTEGER CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    confirmed_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    CHECK ((kind = 'preview') = (targets IS NOT NULL)),
    CHECK ((kind IN ('preview', 'trashed')) = (target_count > 0)),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role <> 'admin' OR auth_message_date = 0),
    CHECK ((token_sha256 IS NULL) = (origin_attempt IS NULL) AND (token_sha256 IS NULL) = (expires_at IS NULL)),
    CHECK (token_sha256 IS NULL OR kind = 'preview'),
    CHECK (confirmed_by_receipt_id IS NULL OR token_sha256 IS NOT NULL)
) STRICT;

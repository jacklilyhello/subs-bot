CREATE TABLE telegram_subscription_read (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('search', 'detail', 'format', 'usage', 'limit', 'missing', 'stale')),
    subscription_id INTEGER CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    format TEXT CHECK (format IN ('clash', 'singbox', 'base64', 'surge', 'qx')),
    search_receipt_id INTEGER REFERENCES telegram_subscription_read (receipt_id),
    search_offset INTEGER CHECK (search_offset BETWEEN 0 AND 512),
    matches TEXT CHECK (length(CAST(matches AS BLOB)) <= 16384 AND json_valid(matches)
        AND json_type(matches) = 'array' AND json_array_length(matches) <= 512),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((kind IN ('detail', 'format')) = (subscription_id IS NOT NULL)),
    CHECK ((kind = 'format') = (format IS NOT NULL)),
    CHECK ((kind = 'search') = (search_offset IS NOT NULL)),
    CHECK (kind = 'search' OR search_receipt_id IS NULL),
    CHECK ((kind = 'search' AND search_receipt_id IS NULL) = (matches IS NOT NULL))
) STRICT;

CREATE TABLE telegram_subscription_read_ticket (
    token_sha256 TEXT PRIMARY KEY CHECK (length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_receipt_id INTEGER NOT NULL REFERENCES telegram_inbox (receipt_id),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    kind TEXT NOT NULL CHECK (kind IN ('search', 'detail', 'format')),
    subscription_id INTEGER CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    format TEXT CHECK (format IN ('clash', 'singbox', 'base64', 'surge', 'qx')),
    search_receipt_id INTEGER REFERENCES telegram_subscription_read (receipt_id),
    search_offset INTEGER CHECK (search_offset BETWEEN 0 AND 512),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    CHECK ((kind IN ('detail', 'format')) = (subscription_id IS NOT NULL)),
    CHECK ((kind = 'format') = (format IS NOT NULL)),
    CHECK ((kind = 'search') = (search_receipt_id IS NOT NULL AND search_offset IS NOT NULL)),
    CHECK ((search_receipt_id IS NULL) = (search_offset IS NULL))
) STRICT;

CREATE INDEX telegram_subscription_read_ticket_expiry ON telegram_subscription_read_ticket (expires_at);

CREATE TABLE telegram_view (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('list', 'expiry', 'recycle')),
    after_id INTEGER CHECK (after_id BETWEEN 1 AND 9007199254740991),
    after_epoch INTEGER CHECK (after_epoch BETWEEN 1 AND 9007199254740991),
    CHECK (after_id IS NOT NULL OR after_epoch IS NULL),
    CHECK ((kind <> 'list' AND after_id IS NOT NULL) = (after_epoch IS NOT NULL))
) STRICT;

CREATE TABLE telegram_view_ticket (
    token_sha256 TEXT NOT NULL PRIMARY KEY CHECK (
        length(token_sha256) = 64 AND length(CAST(token_sha256 AS BLOB)) = 64
        AND token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    origin_receipt_id INTEGER NOT NULL REFERENCES telegram_view (receipt_id),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    after_id INTEGER CHECK (after_id BETWEEN 1 AND 9007199254740991),
    after_epoch INTEGER CHECK (after_epoch BETWEEN 1 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    CHECK (after_id IS NOT NULL OR after_epoch IS NULL)
) STRICT;

CREATE INDEX telegram_view_ticket_expiry ON telegram_view_ticket (expires_at, token_sha256);
CREATE INDEX subscriptions_owner_expiry_id ON subscriptions (owner_id, expire_at, id);

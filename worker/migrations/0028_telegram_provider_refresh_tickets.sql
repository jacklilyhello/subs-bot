CREATE TABLE telegram_provider_refresh_tickets (
    token_sha256 TEXT PRIMARY KEY CHECK (length(token_sha256) = 64 AND length(CAST(token_sha256 AS BLOB)) = 64
        AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_receipt_id INTEGER NOT NULL REFERENCES telegram_inbox (receipt_id),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64 AND length(CAST(source_sha256 AS BLOB)) = 64
        AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740990),
    lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision BETWEEN 0 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    UNIQUE (origin_receipt_id, origin_attempt)
) STRICT;

CREATE INDEX telegram_provider_refresh_ticket_expiry ON telegram_provider_refresh_tickets (expires_at);

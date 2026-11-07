CREATE TABLE telegram_subscription_node_page (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision BETWEEN 0 AND 9007199254740991),
    snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) = 36),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 1 AND 100000),
    page_offset INTEGER NOT NULL CHECK (page_offset >= 0 AND page_offset < node_count AND page_offset % 15 = 0),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0))
) STRICT;

CREATE TABLE telegram_subscription_node_ticket (
    token_sha256 TEXT PRIMARY KEY CHECK (length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_receipt_id INTEGER NOT NULL REFERENCES telegram_inbox (receipt_id),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision BETWEEN 0 AND 9007199254740991),
    snapshot_id TEXT NOT NULL CHECK (length(snapshot_id) = 36),
    manifest_sha256 TEXT NOT NULL CHECK (length(manifest_sha256) = 64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'),
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 1 AND 100000),
    page_offset INTEGER NOT NULL CHECK (page_offset >= 0 AND page_offset < node_count AND page_offset % 15 = 0),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id)
) STRICT;

CREATE INDEX telegram_subscription_node_ticket_expiry ON telegram_subscription_node_ticket (expires_at);

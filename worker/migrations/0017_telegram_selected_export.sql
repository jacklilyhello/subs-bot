CREATE TABLE telegram_selected_links (
    code_sha256 TEXT PRIMARY KEY REFERENCES aggregate_links (code_sha256),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    origin_receipt_id INTEGER NOT NULL UNIQUE REFERENCES telegram_inbox (receipt_id),
    nonce TEXT NOT NULL CHECK (length(nonce) = 22 AND nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
    key_version INTEGER NOT NULL CHECK (key_version = 1),
    generations TEXT NOT NULL CHECK (length(CAST(generations AS BLOB)) <= 16384 AND json_valid(generations)
        AND json_type(generations) = 'array' AND json_array_length(generations) BETWEEN 1 AND 128)
) STRICT;

CREATE INDEX telegram_selected_links_owner ON telegram_selected_links (bot_id, actor_id);

CREATE TABLE telegram_selected_actions (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    result TEXT NOT NULL CHECK (result IN ('issued', 'nomatch', 'empty', 'limit', 'stale', 'revoked', 'already-revoked')),
    code_sha256 TEXT CHECK (length(code_sha256) = 64 AND code_sha256 NOT GLOB '*[^0-9a-f]*'),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((result IN ('issued', 'revoked', 'already-revoked')) = (code_sha256 IS NOT NULL))
) STRICT;

CREATE TABLE telegram_selected_revoke_ticket (
    token_sha256 TEXT PRIMARY KEY CHECK (length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_receipt_id INTEGER NOT NULL REFERENCES telegram_inbox (receipt_id),
    code_sha256 TEXT NOT NULL REFERENCES telegram_selected_links (code_sha256),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    expires_at INTEGER NOT NULL,
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id)
) STRICT;

CREATE INDEX telegram_selected_revoke_ticket_expiry ON telegram_selected_revoke_ticket (expires_at);

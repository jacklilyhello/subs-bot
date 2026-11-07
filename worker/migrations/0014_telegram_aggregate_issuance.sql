CREATE TABLE telegram_aggregate_slots (
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    code_sha256 TEXT UNIQUE REFERENCES aggregate_links (code_sha256),
    nonce TEXT CHECK (length(nonce) = 22 AND nonce NOT GLOB '*[^A-Za-z0-9_-]*'),
    key_version INTEGER CHECK (key_version = 1),
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (bot_id, actor_id),
    CHECK ((code_sha256 IS NULL) = (nonce IS NULL) AND (nonce IS NULL) = (key_version IS NULL))
) STRICT;

CREATE TABLE telegram_aggregate_actions (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    result TEXT NOT NULL CHECK (result IN ('issued', 'ready', 'empty', 'limit', 'revoked', 'already-revoked', 'stale')),
    revision INTEGER CHECK (revision BETWEEN 1 AND 9007199254740991),
    code_sha256 TEXT CHECK (length(code_sha256) = 64 AND code_sha256 NOT GLOB '*[^0-9a-f]*'),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((result IN ('issued', 'ready', 'revoked')) = (code_sha256 IS NOT NULL)),
    CHECK ((result IN ('issued', 'ready', 'revoked', 'already-revoked')) = (revision IS NOT NULL))
) STRICT;

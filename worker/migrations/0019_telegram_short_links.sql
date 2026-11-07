CREATE TABLE normal_short_links (
    code_sha256 TEXT PRIMARY KEY CHECK (length(CAST(code_sha256 AS BLOB)) = 64 AND length(code_sha256) = 64
        AND code_sha256 NOT GLOB '*[^0-9a-f]*'),
    code_length INTEGER NOT NULL CHECK (code_length IN (12, 22)),
    bot_id TEXT NOT NULL CHECK (length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id, 1, 1) <> '0'
        AND (length(bot_id) < 19 OR bot_id <= '9223372036854775807')),
    owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')),
    origin_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    nonce TEXT CHECK (length(CAST(nonce AS BLOB)) = 22 AND length(nonce) = 22
        AND nonce NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(nonce, 22, 1) IN ('A', 'Q', 'g', 'w')),
    key_version INTEGER CHECK (key_version = 1),
    target_url TEXT CHECK (length(CAST(target_url AS BLOB)) BETWEEN 1 AND 2048),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK (created_at BETWEEN 1 AND 9007199254740991),
    revoked_at INTEGER CHECK (revoked_at BETWEEN created_at AND 9007199254740991),
    CHECK ((code_length = 22 AND origin_receipt_id IS NOT NULL AND nonce IS NOT NULL AND key_version IS NOT NULL)
        OR (code_length = 12 AND origin_receipt_id IS NULL AND nonce IS NULL AND key_version IS NULL)),
    CHECK ((revoked_at IS NULL) = (target_url IS NOT NULL))
) STRICT;

CREATE INDEX normal_short_links_active_owner ON normal_short_links (bot_id, owner_id) WHERE revoked_at IS NULL;

CREATE TABLE telegram_short_link_actions (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    result TEXT NOT NULL CHECK (result IN ('help', 'invalid', 'issued', 'revoked', 'missing', 'limit', 'unavailable')),
    code_sha256 TEXT CHECK (length(CAST(code_sha256 AS BLOB)) = 64 AND length(code_sha256) = 64
        AND code_sha256 NOT GLOB '*[^0-9a-f]*'),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((result IN ('issued', 'revoked')) = (code_sha256 IS NOT NULL))
) STRICT;

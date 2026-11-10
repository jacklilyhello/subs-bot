CREATE TABLE telegram_subscription_short_links (
    code_sha256 TEXT PRIMARY KEY CHECK (length(code_sha256)=64 AND length(CAST(code_sha256 AS BLOB))=64
        AND code_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_receipt_id INTEGER NOT NULL UNIQUE REFERENCES telegram_subscription_read (receipt_id),
    bot_id TEXT NOT NULL CHECK (length(CAST(bot_id AS BLOB))=length(bot_id)
        AND length(bot_id) BETWEEN 1 AND 16 AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id,1,1)<>'0'),
    owner_id TEXT NOT NULL CHECK (length(CAST(owner_id AS BLOB))=length(owner_id)
        AND length(owner_id) BETWEEN 1 AND 16 AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id,1,1)<>'0'),
    subscription_id INTEGER CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    token_sha256 TEXT CHECK (length(token_sha256)=64 AND length(CAST(token_sha256 AS BLOB))=64
        AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    format TEXT CHECK (format IN ('clash','singbox','base64','surge','qx')),
    nonce TEXT CHECK (length(nonce)=22 AND length(CAST(nonce AS BLOB))=22
        AND nonce NOT GLOB '*[^A-Za-z0-9_-]*' AND substr(nonce,22,1) IN ('A','Q','g','w')),
    key_version INTEGER NOT NULL CHECK (key_version=1),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK (created_at BETWEEN 1 AND 9007199254740991),
    revoked_at INTEGER CHECK (revoked_at BETWEEN created_at AND 9007199254740991),
    CHECK ((revoked_at IS NULL AND subscription_id IS NOT NULL AND token_sha256 IS NOT NULL AND format IS NOT NULL AND nonce IS NOT NULL)
        OR (revoked_at IS NOT NULL AND subscription_id IS NULL AND token_sha256 IS NULL AND format IS NULL AND nonce IS NULL))
) STRICT;

CREATE INDEX telegram_subscription_short_links_active ON telegram_subscription_short_links (bot_id, owner_id) WHERE revoked_at IS NULL;

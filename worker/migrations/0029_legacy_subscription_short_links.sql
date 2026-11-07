CREATE TABLE legacy_subscription_short_links (
    code_sha256 TEXT PRIMARY KEY CHECK (
        length(code_sha256) = 64 AND length(CAST(code_sha256 AS BLOB)) = 64 AND code_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    bot_id TEXT NOT NULL CHECK (
        length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id, 1, 1) <> '0'
        AND (length(bot_id) < 19 OR bot_id <= '9223372036854775807')
    ),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')
    ),
    subscription_id INTEGER CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    token_sha256 TEXT CHECK (
        length(token_sha256) = 64 AND length(CAST(token_sha256 AS BLOB)) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    format TEXT CHECK (format IN ('', 'clash', 'base64', 'v2ray', 'mixed', 'singbox', 'sing-box', 'surge', 'qx', 'quantumult', 'quantumultx')),
    created_at INTEGER NOT NULL CHECK (created_at BETWEEN 1 AND 9007199254740991),
    revoked_at INTEGER CHECK (revoked_at BETWEEN created_at AND 9007199254740991),
    CHECK (
        (revoked_at IS NULL AND subscription_id IS NOT NULL AND token_sha256 IS NOT NULL AND format IS NOT NULL)
        OR (revoked_at IS NOT NULL AND subscription_id IS NULL AND token_sha256 IS NULL AND format IS NULL)
    )
) STRICT;

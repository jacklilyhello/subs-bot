CREATE TABLE private_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (id BETWEEN 1 AND 9007199254740991),
    bot_id TEXT NOT NULL CHECK (
        length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id, 1, 1) <> '0'
        AND (length(bot_id) < 19 OR bot_id <= '9223372036854775807')
    ),
    code_sha256 TEXT NOT NULL CHECK (
        length(code_sha256) = 64 AND length(CAST(code_sha256 AS BLOB)) = 64
        AND code_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    sender_id TEXT NOT NULL CHECK (
        length(sender_id) BETWEEN 1 AND 19 AND length(CAST(sender_id AS BLOB)) = length(sender_id)
        AND sender_id NOT GLOB '*[^0-9]*' AND substr(sender_id, 1, 1) <> '0'
        AND (length(sender_id) < 19 OR sender_id <= '9223372036854775807')
    ),
    sender_name TEXT NOT NULL CHECK (
        length(CAST(sender_name AS BLOB)) BETWEEN 1 AND 256 AND instr(sender_name, char(0)) = 0
    ),
    payload_id TEXT NOT NULL UNIQUE CHECK (
        length(payload_id) = 36 AND length(CAST(payload_id AS BLOB)) = 36
        AND payload_id NOT GLOB '*[^0-9a-f-]*'
        AND substr(payload_id, 9, 1) = '-' AND substr(payload_id, 14, 1) = '-'
        AND substr(payload_id, 19, 1) = '-' AND substr(payload_id, 24, 1) = '-'
        AND length(replace(payload_id, '-', '')) = 32
    ),
    payload_sha256 TEXT NOT NULL CHECK (
        length(payload_sha256) = 64 AND length(CAST(payload_sha256 AS BLOB)) = 64
        AND payload_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes BETWEEN 1 AND 65536),
    max_claims INTEGER NOT NULL CHECK (max_claims BETWEEN 1 AND 100),
    target_user_id TEXT CHECK (target_user_id IS NULL OR (
        length(target_user_id) BETWEEN 1 AND 19 AND length(CAST(target_user_id AS BLOB)) = length(target_user_id)
        AND target_user_id NOT GLOB '*[^0-9]*' AND substr(target_user_id, 1, 1) <> '0'
        AND (length(target_user_id) < 19 OR target_user_id <= '9223372036854775807')
    )),
    expire_at INTEGER NOT NULL CHECK (expire_at BETWEEN created_at AND 9007199254740991),
    created_at INTEGER NOT NULL CHECK (created_at BETWEEN 1 AND 9007199254740991),
    UNIQUE (bot_id, code_sha256)
) STRICT;

CREATE TABLE private_share_claims (
    share_id INTEGER NOT NULL REFERENCES private_shares (id),
    actor_id TEXT NOT NULL CHECK (
        length(actor_id) BETWEEN 1 AND 19 AND length(CAST(actor_id AS BLOB)) = length(actor_id)
        AND actor_id NOT GLOB '*[^0-9]*' AND substr(actor_id, 1, 1) <> '0'
        AND (length(actor_id) < 19 OR actor_id <= '9223372036854775807')
    ),
    claimed_at INTEGER NOT NULL CHECK (claimed_at BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (share_id, actor_id)
) STRICT;

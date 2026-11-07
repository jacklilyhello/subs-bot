CREATE TABLE aggregate_links (
    code_sha256 TEXT PRIMARY KEY CHECK (
        length(code_sha256) = 64 AND length(CAST(code_sha256 AS BLOB)) = 64
        AND code_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')
    ),
    kind TEXT NOT NULL CHECK (kind IN ('all', 'selected')),
    bot_id TEXT CHECK (bot_id IS NULL OR (
        length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id, 1, 1) <> '0'
        AND (length(bot_id) < 19 OR bot_id <= '9223372036854775807')
    )),
    selected_ids TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()) CHECK (created_at BETWEEN 1 AND 9007199254740991),
    revoked_at INTEGER CHECK (revoked_at BETWEEN created_at AND 9007199254740991),
    CHECK (
        (kind = 'all' AND bot_id IS NOT NULL AND selected_ids IS NULL)
        OR (kind = 'selected' AND bot_id IS NULL AND selected_ids IS NOT NULL
            AND length(CAST(selected_ids AS BLOB)) BETWEEN 3 AND 4096
            AND json_valid(selected_ids) AND json_type(selected_ids) = 'array'
            AND json_array_length(selected_ids) BETWEEN 1 AND 128)
    )
) STRICT;

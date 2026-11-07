CREATE TABLE legacy_empty_subscription_exports (
    subscription_id INTEGER PRIMARY KEY CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19
        AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*'
        AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')
    ),
    token_sha256 TEXT NOT NULL UNIQUE CHECK (
        length(token_sha256) = 64 AND length(CAST(token_sha256 AS BLOB)) = 64
        AND token_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

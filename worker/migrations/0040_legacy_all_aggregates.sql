CREATE TABLE legacy_all_aggregates (
    code_sha256 TEXT PRIMARY KEY REFERENCES aggregate_links(code_sha256),
    bot_id TEXT NOT NULL REFERENCES legacy_temp_installations(bot_id),
    owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB))=length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id,1,1)<>'0' AND (length(owner_id)<19 OR owner_id<='9223372036854775807')),
    inventory_sha256 TEXT NOT NULL CHECK (length(inventory_sha256)=64 AND length(CAST(inventory_sha256 AS BLOB))=64
        AND inventory_sha256 NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE INDEX legacy_all_aggregates_owner ON legacy_all_aggregates (owner_id);

CREATE TABLE legacy_all_subscription_order (
    subscription_id INTEGER PRIMARY KEY CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    owner_id TEXT NOT NULL CHECK (length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB))=length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id,1,1)<>'0' AND (length(owner_id)<19 OR owner_id<='9223372036854775807')),
    anchor INTEGER NOT NULL CHECK (anchor BETWEEN subscription_id AND 9007199254740991),
    tie INTEGER NOT NULL CHECK (tie BETWEEN 1 AND 9007199254740991),
    UNIQUE (owner_id,anchor,tie)
) STRICT;

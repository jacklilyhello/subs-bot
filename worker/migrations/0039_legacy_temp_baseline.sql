CREATE TABLE legacy_temp_installations (
    bot_id TEXT PRIMARY KEY CHECK (length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB))=length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id,1,1)<>'0' AND (length(bot_id)<19 OR bot_id<='9223372036854775807')),
    inventory_sha256 TEXT NOT NULL CHECK (length(inventory_sha256)=64 AND length(CAST(inventory_sha256 AS BLOB))=64
        AND inventory_sha256 NOT GLOB '*[^0-9a-f]*'),
    cutover_epoch INTEGER CHECK (cutover_epoch BETWEEN 1 AND 9007199254740991)
) STRICT;

CREATE TABLE legacy_temp_batches (
    bot_id TEXT NOT NULL REFERENCES legacy_temp_installations(bot_id),
    actor_id TEXT NOT NULL CHECK (length(actor_id) BETWEEN 1 AND 19 AND length(CAST(actor_id AS BLOB))=length(actor_id)
        AND actor_id NOT GLOB '*[^0-9]*' AND substr(actor_id,1,1)<>'0' AND (length(actor_id)<19 OR actor_id<='9223372036854775807')),
    first_legacy_id INTEGER NOT NULL CHECK (first_legacy_id BETWEEN 1 AND 9007199254740991),
    last_legacy_id INTEGER NOT NULL CHECK (last_legacy_id BETWEEN first_legacy_id AND 9007199254740991),
    nodes_json TEXT NOT NULL CHECK (json_valid(nodes_json) AND json_type(nodes_json)='array'),
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 1 AND 500 AND node_count=json_array_length(nodes_json)
        AND node_count<=last_legacy_id-first_legacy_id+1),
    payload_bytes INTEGER NOT NULL CHECK (payload_bytes BETWEEN 1 AND 262144 AND payload_bytes=length(CAST(nodes_json AS BLOB))),
    payload_sha256 TEXT NOT NULL CHECK (length(payload_sha256)=64 AND length(CAST(payload_sha256 AS BLOB))=64
        AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
    PRIMARY KEY (bot_id,actor_id,first_legacy_id)
) STRICT;

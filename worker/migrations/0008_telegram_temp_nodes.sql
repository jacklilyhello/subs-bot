CREATE TABLE telegram_temp_reply (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (
        kind IN ('added', 'rejected', 'no-nodes', 'invalid-encoding', 'limit', 'capacity', 'stale', 'summary', 'cleared')
    ),
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 0 AND 5000),
    total_count INTEGER NOT NULL DEFAULT 0 CHECK (total_count BETWEEN 0 AND 5000),
    malformed_count INTEGER NOT NULL DEFAULT 0 CHECK (malformed_count BETWEEN 0 AND 65536),
    unsupported_count INTEGER NOT NULL DEFAULT 0 CHECK (unsupported_count BETWEEN 0 AND 65536),
    ignored_count INTEGER NOT NULL DEFAULT 0 CHECK (ignored_count BETWEEN 0 AND 65536)
) STRICT;

CREATE TABLE telegram_temp_batch (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    nodes_json TEXT NOT NULL CHECK (json_valid(nodes_json) AND json_type(nodes_json) = 'array'),
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 1 AND 500 AND node_count = json_array_length(nodes_json)),
    payload_bytes INTEGER NOT NULL CHECK (
        payload_bytes BETWEEN 1 AND 262144 AND payload_bytes = length(CAST(nodes_json AS BLOB))
    )
) STRICT;

CREATE TABLE telegram_temp_clear_fence (
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (bot_id, actor_id)
) STRICT;

CREATE INDEX telegram_temp_batch_owner ON telegram_temp_batch
    (bot_id, actor_id, message_date, message_id, node_count, payload_bytes);

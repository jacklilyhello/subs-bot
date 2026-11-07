CREATE TABLE telegram_path_reply (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('list', 'usage', 'saved', 'deleted', 'cleared', 'missing', 'capacity', 'stale')),
    after_id INTEGER CHECK (after_id IS NULL OR (after_id BETWEEN 1 AND 9007199254740991 AND kind = 'list')),
    affected_count INTEGER NOT NULL DEFAULT 0 CHECK (
        (kind = 'cleared' AND affected_count BETWEEN 0 AND 64)
        OR (kind IN ('saved', 'deleted') AND affected_count = 1)
        OR (kind NOT IN ('saved', 'deleted', 'cleared') AND affected_count = 0)
    )
) STRICT;

CREATE TABLE telegram_path_fence (
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (bot_id, actor_id)
) STRICT;

CREATE TABLE telegram_page_jumps (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    origin_receipt_id INTEGER NOT NULL UNIQUE REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('prompt', 'page', 'invalid', 'range', 'limit', 'cancelled')),
    max_page INTEGER CHECK (max_page BETWEEN 1 AND 9007199254740991),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    CHECK ((kind = 'range') = (max_page IS NOT NULL)),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role = 'member' OR auth_message_date = 0)
) STRICT;

CREATE INDEX telegram_page_jumps_expiry ON telegram_page_jumps (kind,expires_at,receipt_id);

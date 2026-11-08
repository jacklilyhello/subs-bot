CREATE TABLE telegram_api_status (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    prompt_receipt_id INTEGER UNIQUE REFERENCES telegram_api_status (receipt_id),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin','member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date >= 0),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id >= 0),
    expires_at INTEGER NOT NULL CHECK (expires_at > 0),
    ready_at INTEGER CHECK (ready_at > 0),
    row_one INTEGER CHECK (row_one BETWEEN -7 AND -1 OR row_one BETWEEN 1600000 AND 9599000),
    row_two INTEGER CHECK (row_two BETWEEN -7 AND -1 OR row_two BETWEEN 1600000 AND 9599000),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role <> 'admin' OR auth_message_date = 0),
    CHECK (prompt_receipt_id IS NULL OR prompt_receipt_id < receipt_id),
    CHECK ((prompt_receipt_id IS NULL) = (row_one IS NULL)),
    CHECK (prompt_receipt_id IS NOT NULL OR (row_two IS NULL AND ready_at IS NOT NULL)),
    CHECK (ready_at IS NULL OR (COALESCE(row_one,0) NOT IN (-1,-2) AND COALESCE(row_two,0) NOT IN (-1,-2)))
) STRICT;

CREATE INDEX telegram_api_status_expiry ON telegram_api_status (expires_at,receipt_id) WHERE ready_at IS NULL;

CREATE INDEX telegram_api_status_ready ON telegram_api_status (ready_at,receipt_id) WHERE prompt_receipt_id IS NOT NULL;

CREATE TABLE telegram_provider_batch_interactions (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    kind TEXT NOT NULL CHECK (kind IN ('preview', 'empty', 'limit', 'usage', 'idle', 'status', 'terminal', 'unavailable')),
    batch_id INTEGER REFERENCES telegram_provider_batches (batch_id),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    ready_at INTEGER NOT NULL CHECK (ready_at BETWEEN 1 AND 9007199254740991),
    targets TEXT CHECK (length(CAST(targets AS BLOB)) <= 4096 AND json_valid(targets)
        AND json_type(targets) = 'array' AND json_array_length(targets) BETWEEN 1 AND 16),
    skipped_count INTEGER NOT NULL DEFAULT 0 CHECK (skipped_count BETWEEN 0 AND 100),
    token_sha256 TEXT UNIQUE CHECK (length(token_sha256) = 64 AND token_sha256 NOT GLOB '*[^0-9a-f]*'),
    origin_attempt INTEGER CHECK (origin_attempt BETWEEN 1 AND 4),
    expires_at INTEGER CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    used_by_receipt_id INTEGER UNIQUE REFERENCES telegram_inbox (receipt_id),
    CHECK ((kind IN ('status', 'terminal')) = (batch_id IS NOT NULL)),
    CHECK (kind <> 'terminal' OR batch_id = receipt_id),
    CHECK ((kind = 'preview') = (targets IS NOT NULL)),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role <> 'admin' OR auth_message_date = 0),
    CHECK ((token_sha256 IS NULL) = (origin_attempt IS NULL) AND (token_sha256 IS NULL) = (expires_at IS NULL)),
    CHECK (token_sha256 IS NULL OR kind = 'preview'),
    CHECK (used_by_receipt_id IS NULL OR token_sha256 IS NOT NULL)
) STRICT;

CREATE INDEX telegram_provider_batch_tickets_expiry ON telegram_provider_batch_interactions (expires_at, receipt_id)
    WHERE token_sha256 IS NOT NULL AND used_by_receipt_id IS NULL;

CREATE INDEX telegram_provider_batch_terminal_ready ON telegram_provider_batch_interactions (ready_at, receipt_id)
    WHERE kind = 'terminal';

CREATE INDEX telegram_provider_batches_finished ON telegram_provider_batches (finished_at, batch_id)
    WHERE finished_at IS NOT NULL;

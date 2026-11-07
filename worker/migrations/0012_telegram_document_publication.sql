CREATE TABLE telegram_document_reservations (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_document_jobs (receipt_id),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    new_token TEXT UNIQUE CHECK (length(new_token) = 32 AND new_token NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740990),
    lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision BETWEEN 0 AND 9007199254740991),
    CHECK (new_token IS NULL OR (generation = 0 AND lifecycle_revision = 0))
) STRICT;

CREATE TABLE telegram_document_stages (
    snapshot_id TEXT PRIMARY KEY CHECK (length(snapshot_id) = 36 AND snapshot_id NOT GLOB '*[^0-9a-f-]*'),
    receipt_id INTEGER NOT NULL REFERENCES telegram_document_jobs (receipt_id),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    lease_id TEXT NOT NULL UNIQUE CHECK (length(lease_id) = 36),
    cleanup_after INTEGER NOT NULL CHECK (cleanup_after > 0)
) STRICT;

CREATE INDEX telegram_document_stages_cleanup ON telegram_document_stages (cleanup_after, snapshot_id);

CREATE TABLE telegram_document_saved_counts (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_document_jobs (receipt_id),
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 1 AND 500),
    name_sha256 TEXT NOT NULL CHECK (length(name_sha256) = 64 AND name_sha256 NOT GLOB '*[^0-9a-f]*')
) STRICT;

CREATE INDEX telegram_document_saved_name ON telegram_document_saved_counts (name_sha256, receipt_id);

CREATE INDEX telegram_document_jobs_finished ON telegram_document_jobs (bot_id, finished_at, receipt_id)
    WHERE state = 'done';

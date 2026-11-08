CREATE TABLE telegram_provider_document_opt_in (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_document_jobs (receipt_id)
) STRICT;

CREATE TABLE telegram_provider_documents (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id)
        CHECK (receipt_id BETWEEN 1 AND 9007199254740991),
    bot_id TEXT NOT NULL CHECK (
        length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id, 1, 1) <> '0'
        AND (length(bot_id) < 19 OR bot_id <= '9223372036854775807')
    ),
    actor_id TEXT NOT NULL CHECK (
        length(actor_id) BETWEEN 1 AND 19 AND length(CAST(actor_id AS BLOB)) = length(actor_id)
        AND actor_id NOT GLOB '*[^0-9]*' AND substr(actor_id, 1, 1) <> '0'
        AND (length(actor_id) < 19 OR actor_id <= '9223372036854775807')
    ),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    finished_at INTEGER CHECK (finished_at BETWEEN 1 AND 9007199254740991),
    line_count INTEGER NOT NULL CHECK (line_count BETWEEN 1 AND 20),
    overflow_count INTEGER NOT NULL DEFAULT 0 CHECK (overflow_count BETWEEN 0 AND 10485760),
    CHECK (bot_id <> actor_id),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role <> 'admin' OR auth_message_date = 0)
) STRICT;

CREATE UNIQUE INDEX telegram_provider_documents_active_actor
    ON telegram_provider_documents (bot_id, actor_id) WHERE finished_at IS NULL;

CREATE INDEX telegram_provider_documents_pending
    ON telegram_provider_documents (bot_id, expires_at, receipt_id) WHERE finished_at IS NULL;

CREATE INDEX telegram_provider_documents_finished
    ON telegram_provider_documents (bot_id, finished_at, receipt_id) WHERE finished_at IS NOT NULL;

CREATE TABLE telegram_provider_document_lines (
    receipt_id INTEGER NOT NULL REFERENCES telegram_provider_documents (receipt_id),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 19),
    due_at INTEGER NOT NULL CHECK (due_at BETWEEN 0 AND 9007199254740991),
    source_sha256 TEXT NOT NULL CHECK (
        length(source_sha256) = 64 AND length(CAST(source_sha256 AS BLOB)) = 64
        AND source_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    subscription_id INTEGER CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    expected_generation INTEGER CHECK (expected_generation BETWEEN 0 AND 9007199254740990),
    expected_lifecycle_revision INTEGER CHECK (expected_lifecycle_revision BETWEEN 0 AND 9007199254740991),
    job_id INTEGER UNIQUE REFERENCES telegram_provider_jobs (job_id),
    result_code TEXT,
    PRIMARY KEY (receipt_id, ordinal),
    UNIQUE (receipt_id, source_sha256),
    CHECK (
        (subscription_id IS NULL) = (expected_generation IS NULL)
        AND (subscription_id IS NULL) = (expected_lifecycle_revision IS NULL)
    ),
    CHECK (subscription_id IS NOT NULL OR (job_id IS NULL AND result_code IS NOT NULL)),
    CHECK (
        result_code IS NULL
        OR (job_id IS NULL AND result_code IN ('capacity', 'unavailable', 'conflict', 'stale-target', 'expired', 'access-changed'))
        OR (job_id IS NOT NULL AND result_code IN (
            'saved', 'coalesced', 'stale-target', 'expired', 'access-changed',
            'attempts-exhausted', 'invalid-document', 'fetch-rejected', 'storage-failed'
        ))
    )
) STRICT;

CREATE INDEX telegram_provider_document_lines_waiting
    ON telegram_provider_document_lines (due_at, receipt_id, ordinal) WHERE job_id IS NULL AND result_code IS NULL;

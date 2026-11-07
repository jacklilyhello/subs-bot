CREATE TABLE telegram_document_jobs (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'done')),
    due_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    lease_id TEXT UNIQUE CHECK (length(lease_id) = 36),
    lease_until INTEGER,
    file_id TEXT CHECK (length(file_id) BETWEEN 1 AND 512 AND length(CAST(file_id AS BLOB)) = length(file_id)
        AND file_id NOT GLOB '*[^!-~]*' AND instr(file_id, char(0)) = 0),
    name TEXT CHECK (length(name) BETWEEN 1 AND 64 AND name = trim(name) AND instr(name, char(0)) = 0
        AND instr(name, '/') = 0 AND instr(name, char(92)) = 0),
    suffix TEXT CHECK (suffix IN ('txt', 'log', 'yaml', 'yml', 'json')),
    expected_size INTEGER CHECK (expected_size BETWEEN 0 AND 10485760),
    result_code TEXT CHECK (result_code IN (
        'saved', 'invalid-document', 'download-rejected', 'coalesced', 'capacity', 'expired', 'access-changed', 'attempts-exhausted'
    )),
    finished_at INTEGER,
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((state = 'leased') = (lease_id IS NOT NULL)),
    CHECK (due_at < expires_at AND (lease_until IS NULL OR lease_until <= expires_at)),
    CHECK (
        (state IN ('pending', 'leased') AND file_id IS NOT NULL AND name IS NOT NULL AND suffix IS NOT NULL
            AND result_code IS NULL AND finished_at IS NULL)
        OR (state = 'done' AND file_id IS NULL AND name IS NULL AND suffix IS NULL AND expected_size IS NULL
            AND result_code IS NOT NULL AND finished_at IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX telegram_document_jobs_active_name ON telegram_document_jobs (bot_id, actor_id, name)
    WHERE state IN ('pending', 'leased');

CREATE UNIQUE INDEX telegram_document_jobs_bot_lease ON telegram_document_jobs (bot_id) WHERE state = 'leased';

CREATE INDEX telegram_document_jobs_due ON telegram_document_jobs (bot_id, state, due_at, receipt_id)
    WHERE state IN ('pending', 'leased');

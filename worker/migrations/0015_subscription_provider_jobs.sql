CREATE TABLE subscription_provider_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (job_id BETWEEN 1 AND 9007199254740991),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')
    ),
    request_key TEXT NOT NULL CHECK (length(request_key) = 64 AND length(CAST(request_key AS BLOB)) = 64
        AND request_key NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK (kind IN ('url-import', 'refresh')),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64 AND length(CAST(source_sha256 AS BLOB)) = 64
        AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    expected_generation INTEGER NOT NULL CHECK (expected_generation BETWEEN 0 AND 9007199254740990),
    expected_lifecycle_revision INTEGER NOT NULL CHECK (expected_lifecycle_revision BETWEEN 0 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('pending', 'leased', 'done')),
    created_at INTEGER NOT NULL CHECK (created_at BETWEEN 1 AND 9007199254740991),
    due_at INTEGER NOT NULL CHECK (due_at BETWEEN 1 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    lease_id TEXT UNIQUE CHECK (length(lease_id) = 36 AND length(CAST(lease_id AS BLOB)) = 36
        AND lease_id NOT GLOB '*[^0-9a-f-]*'),
    lease_until INTEGER CHECK (lease_until BETWEEN 1 AND 9007199254740991),
    failure_code TEXT CHECK (failure_code IN (
        'busy', 'timeout', 'dns-failed', 'unavailable', 'upstream-retryable',
        'invalid-document', 'fetch-rejected', 'storage-failed'
    )),
    result_code TEXT CHECK (result_code IN (
        'saved', 'coalesced', 'stale-target', 'expired', 'attempts-exhausted',
        'invalid-document', 'fetch-rejected', 'storage-failed'
    )),
    finished_at INTEGER CHECK (finished_at BETWEEN 1 AND 9007199254740991),
    UNIQUE (owner_id, request_key),
    CHECK (created_at <= due_at AND due_at < expires_at),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((state = 'leased') = (lease_id IS NOT NULL)),
    CHECK (lease_until IS NULL OR (lease_until <= expires_at AND attempts > 0)),
    CHECK ((state = 'done') = (result_code IS NOT NULL)),
    CHECK ((state = 'done') = (finished_at IS NOT NULL)),
    CHECK (finished_at IS NULL OR finished_at >= created_at)
) STRICT;

CREATE UNIQUE INDEX subscription_provider_jobs_active_target ON subscription_provider_jobs (owner_id, subscription_id)
    WHERE state IN ('pending', 'leased');

CREATE UNIQUE INDEX subscription_provider_jobs_global_lease ON subscription_provider_jobs ((1)) WHERE state = 'leased';

CREATE INDEX subscription_provider_jobs_due ON subscription_provider_jobs (due_at, job_id)
    WHERE state IN ('pending', 'leased');

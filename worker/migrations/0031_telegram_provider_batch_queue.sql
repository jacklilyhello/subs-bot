CREATE TABLE telegram_provider_batches (
    batch_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    preview_receipt_id INTEGER NOT NULL UNIQUE REFERENCES telegram_inbox (receipt_id),
    origin_attempt INTEGER NOT NULL CHECK (origin_attempt BETWEEN 1 AND 4),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin', 'member')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    admission_nonce TEXT NOT NULL UNIQUE,
    target_count INTEGER NOT NULL CHECK (target_count BETWEEN 1 AND 16),
    skipped_count INTEGER NOT NULL CHECK (skipped_count BETWEEN 0 AND 100),
    created_at INTEGER NOT NULL CHECK (created_at BETWEEN 1 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at = created_at + 2700),
    finished_at INTEGER CHECK (finished_at >= created_at),
    saved_count INTEGER CHECK (saved_count BETWEEN 0 AND target_count),
    failed_count INTEGER CHECK (failed_count BETWEEN 0 AND target_count),
    stale_count INTEGER CHECK (stale_count BETWEEN 0 AND target_count),
    expired_count INTEGER CHECK (expired_count BETWEEN 0 AND target_count),
    CHECK (batch_id <> preview_receipt_id),
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK (actor_role <> 'admin' OR auth_message_date = 0),
    CHECK ((finished_at IS NULL) = (saved_count IS NULL)),
    CHECK ((finished_at IS NULL) = (failed_count IS NULL)),
    CHECK ((finished_at IS NULL) = (stale_count IS NULL)),
    CHECK ((finished_at IS NULL) = (expired_count IS NULL)),
    CHECK (saved_count + failed_count + stale_count + expired_count = target_count)
) STRICT;

CREATE UNIQUE INDEX telegram_provider_batches_running ON telegram_provider_batches (bot_id, actor_id)
    WHERE finished_at IS NULL;

CREATE INDEX telegram_provider_batches_latest ON telegram_provider_batches (bot_id, actor_id, batch_id DESC);

CREATE INDEX telegram_provider_batch_preview_order ON telegram_inbox (bot_id, actor_id, message_date, message_id, receipt_id)
    WHERE receipt_nonce = 'provider-batch-preview:v1';

CREATE TABLE telegram_provider_batch_jobs (
    job_id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (job_id BETWEEN 1 AND 9007199254740991),
    batch_id INTEGER NOT NULL REFERENCES telegram_provider_batches (batch_id),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 1 AND 16),
    owner_id TEXT NOT NULL,
    request_key TEXT NOT NULL UNIQUE CHECK (length(request_key) = 64 AND request_key NOT GLOB '*[^0-9a-f]*'),
    kind TEXT NOT NULL CHECK (kind = 'refresh'),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    expected_generation INTEGER NOT NULL CHECK (expected_generation BETWEEN 0 AND 9007199254740990),
    expected_lifecycle_revision INTEGER NOT NULL CHECK (expected_lifecycle_revision BETWEEN 0 AND 9007199254740991),
    state TEXT NOT NULL CHECK (state IN ('waiting', 'pending', 'leased', 'done')),
    created_at INTEGER NOT NULL CHECK (created_at BETWEEN 1 AND 9007199254740991),
    due_at INTEGER NOT NULL CHECK (due_at BETWEEN 1 AND 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    lease_id TEXT UNIQUE CHECK (length(lease_id) = 36 AND lease_id NOT GLOB '*[^0-9a-f-]*'),
    lease_until INTEGER CHECK (lease_until BETWEEN 1 AND 9007199254740991),
    failure_code TEXT CHECK (failure_code IN (
        'busy', 'timeout', 'dns-failed', 'unavailable', 'upstream-retryable',
        'invalid-document', 'fetch-rejected', 'storage-failed'
    )),
    result_code TEXT CHECK (result_code IN (
        'saved', 'stale-target', 'expired', 'attempts-exhausted', 'invalid-document', 'fetch-rejected', 'storage-failed'
    )),
    finished_at INTEGER CHECK (finished_at >= created_at),
    UNIQUE (batch_id, ordinal),
    UNIQUE (batch_id, subscription_id),
    CHECK (created_at <= due_at AND due_at < expires_at),
    CHECK (state <> 'waiting' OR (attempts = 0 AND failure_code IS NULL)),
    CHECK ((lease_id IS NULL) = (lease_until IS NULL)),
    CHECK ((state = 'leased') = (lease_id IS NOT NULL)),
    CHECK (lease_until IS NULL OR (lease_until <= expires_at AND attempts > 0)),
    CHECK ((state = 'done') = (result_code IS NOT NULL)),
    CHECK ((state = 'done') = (finished_at IS NOT NULL))
) STRICT;

CREATE UNIQUE INDEX telegram_provider_batch_jobs_active_target ON telegram_provider_batch_jobs (owner_id, subscription_id)
    WHERE state IN ('pending', 'leased');

CREATE UNIQUE INDEX telegram_provider_batch_jobs_global_lease ON telegram_provider_batch_jobs ((1)) WHERE state = 'leased';

CREATE INDEX telegram_provider_batch_jobs_due ON telegram_provider_batch_jobs (due_at, job_id)
    WHERE state IN ('pending', 'leased');

CREATE INDEX telegram_provider_batch_jobs_unsettled ON telegram_provider_batch_jobs (batch_id, ordinal)
    WHERE state IN ('waiting', 'pending', 'leased');

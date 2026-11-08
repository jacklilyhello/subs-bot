CREATE TABLE provider_snapshot_attempts (
    snapshot_id TEXT PRIMARY KEY CHECK (
        length(snapshot_id) = 36 AND length(CAST(snapshot_id AS BLOB)) = 36
        AND substr(snapshot_id,9,1)='-' AND substr(snapshot_id,14,1)='-'
        AND substr(snapshot_id,19,1)='-' AND substr(snapshot_id,24,1)='-'
        AND length(replace(snapshot_id,'-',''))=32 AND replace(snapshot_id,'-','') NOT GLOB '*[^0-9a-f]*'
    ),
    queue TEXT NOT NULL CHECK (queue IN ('subscription_provider_jobs','telegram_provider_jobs','telegram_provider_batch_jobs')),
    job_id INTEGER NOT NULL CHECK (job_id BETWEEN 1 AND 9007199254740991),
    job_attempt INTEGER NOT NULL CHECK (job_attempt BETWEEN 1 AND 3),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB))=length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id,1,1)<>'0'
        AND (length(owner_id)<19 OR owner_id<='9223372036854775807')
    ),
    request_key TEXT NOT NULL CHECK (length(request_key)=64 AND request_key NOT GLOB '*[^0-9a-f]*'
        AND length(CAST(request_key AS BLOB))=64),
    source_sha256 TEXT NOT NULL CHECK (length(source_sha256)=64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(CAST(source_sha256 AS BLOB))=64),
    expected_generation INTEGER NOT NULL CHECK (expected_generation BETWEEN 0 AND 9007199254740990),
    expected_lifecycle_revision INTEGER NOT NULL CHECK (expected_lifecycle_revision BETWEEN 0 AND 9007199254740991),
    lease_until INTEGER NOT NULL CHECK (lease_until BETWEEN 1 AND 9007199254740991),
    bot_id TEXT NOT NULL CHECK (
        (queue='subscription_provider_jobs' AND bot_id='') OR (queue<>'subscription_provider_jobs'
        AND length(bot_id) BETWEEN 1 AND 19 AND length(CAST(bot_id AS BLOB))=length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*' AND substr(bot_id,1,1)<>'0'
        AND (length(bot_id)<19 OR bot_id<='9223372036854775807'))
    ),
    created_at INTEGER NOT NULL CHECK (created_at BETWEEN 1 AND lease_until),
    state TEXT NOT NULL CHECK (state IN ('open','sealed','published')),
    manifest_sha256 TEXT CHECK (length(manifest_sha256)=64 AND manifest_sha256 NOT GLOB '*[^0-9a-f]*'
        AND length(CAST(manifest_sha256 AS BLOB))=64),
    node_count INTEGER CHECK (node_count BETWEEN 1 AND 100000),
    object_count INTEGER CHECK (object_count BETWEEN 2 AND 257),
    published_at INTEGER CHECK (published_at BETWEEN created_at AND lease_until),
    UNIQUE (queue,job_id,job_attempt),
    CHECK ((state='open' AND manifest_sha256 IS NULL AND node_count IS NULL AND object_count IS NULL)
        OR (state IN ('sealed','published') AND manifest_sha256 IS NOT NULL AND node_count IS NOT NULL AND object_count IS NOT NULL)),
    CHECK ((state='published' AND published_at IS NOT NULL) OR (state<>'published' AND published_at IS NULL))
) STRICT;

CREATE INDEX provider_snapshot_open_leases ON provider_snapshot_attempts (lease_until,snapshot_id)
    WHERE state IN ('open','sealed');

CREATE TABLE provider_snapshot_object_intents (
    snapshot_id TEXT NOT NULL REFERENCES provider_snapshot_attempts (snapshot_id),
    ordinal INTEGER NOT NULL CHECK (ordinal BETWEEN 0 AND 256),
    byte_count INTEGER NOT NULL CHECK (byte_count BETWEEN 1 AND 524288 AND (ordinal<>256 OR byte_count<=65536)),
    sha256 TEXT NOT NULL CHECK (length(sha256)=64 AND sha256 NOT GLOB '*[^0-9a-f]*' AND length(CAST(sha256 AS BLOB))=64),
    PRIMARY KEY (snapshot_id,ordinal)
) STRICT;

CREATE TABLE subscription_lifecycle (
    subscription_id INTEGER PRIMARY KEY CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991)
) STRICT;

CREATE TABLE subscription_trash (
    id INTEGER PRIMARY KEY CHECK (id BETWEEN 1 AND 9007199254740991),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19
        AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*'
        AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')
    ),
    name TEXT NOT NULL CHECK (length(name) BETWEEN 1 AND 512 AND instr(name, char(0)) = 0),
    source_url TEXT NOT NULL CHECK (
        length(CAST(source_url AS BLOB)) BETWEEN 1 AND 16384 AND instr(source_url, char(0)) = 0
    ),
    token TEXT NOT NULL UNIQUE CHECK (
        length(token) BETWEEN 16 AND 128
        AND length(CAST(token AS BLOB)) = length(token)
        AND token NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    expire_at INTEGER,
    traffic_used REAL,
    traffic_total REAL,
    last_error TEXT CHECK (length(last_error) <= 256),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9007199254740991),
    snapshot_id TEXT,
    manifest_sha256 TEXT,
    node_count INTEGER NOT NULL CHECK (node_count BETWEEN 0 AND 100000),
    deleted_at INTEGER NOT NULL CHECK (deleted_at BETWEEN 1 AND 9007199254740991),
    lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision BETWEEN 1 AND 9007199254740991),
    CHECK (
        (generation = 0 AND snapshot_id IS NULL AND manifest_sha256 IS NULL AND node_count = 0)
        OR (
            generation > 0 AND snapshot_id IS NOT NULL AND length(snapshot_id) = 36
            AND length(CAST(snapshot_id AS BLOB)) = 36
            AND manifest_sha256 IS NOT NULL AND length(manifest_sha256) = 64
            AND length(CAST(manifest_sha256 AS BLOB)) = 64
            AND manifest_sha256 NOT GLOB '*[^0-9a-f]*' AND node_count > 0
        )
    )
) STRICT;

CREATE INDEX subscription_trash_owner_deleted_id ON subscription_trash (owner_id, deleted_at DESC, id DESC);

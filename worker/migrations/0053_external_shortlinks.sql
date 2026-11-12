CREATE TABLE telegram_external_shortlinks (
    bot_id TEXT NOT NULL,
    local_sha256 TEXT NOT NULL CHECK (length(local_sha256)=64 AND local_sha256 NOT GLOB '*[^0-9a-f]*'),
    operation_id TEXT NOT NULL UNIQUE CHECK (length(operation_id)=36),
    domain TEXT NOT NULL CHECK (domain='gfw.mom'),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    retry_at INTEGER NOT NULL DEFAULT 0 CHECK (retry_at>=0),
    lease_id TEXT,
    lease_until INTEGER,
    short_url TEXT,
    terminal INTEGER NOT NULL DEFAULT 0 CHECK (terminal IN (0,1)),
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    PRIMARY KEY (bot_id,local_sha256),
    CHECK ((lease_id IS NULL)=(lease_until IS NULL)),
    CHECK (short_url IS NULL OR (terminal=1 AND short_url GLOB 'https://gfw.mom/*'))
) STRICT;

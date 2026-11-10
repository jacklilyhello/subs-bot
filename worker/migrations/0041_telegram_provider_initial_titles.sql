CREATE TABLE telegram_provider_initial_titles (
    subscription_id INTEGER PRIMARY KEY CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    request_key TEXT NOT NULL CHECK (length(CAST(request_key AS BLOB)) = 64 AND request_key NOT GLOB '*[^0-9a-f]*'),
    source_sha256 TEXT NOT NULL CHECK (length(CAST(source_sha256 AS BLOB)) = 64 AND source_sha256 NOT GLOB '*[^0-9a-f]*'),
    expires_at INTEGER NOT NULL CHECK (expires_at BETWEEN 1 AND 9007199254740991)
) STRICT;

CREATE INDEX telegram_provider_initial_titles_expiry ON telegram_provider_initial_titles (expires_at,subscription_id);

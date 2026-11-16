CREATE TABLE subs_bot_production_updates (
    bot_id TEXT NOT NULL,
    update_id INTEGER NOT NULL CHECK(update_id BETWEEN 1 AND 9007199254740991),
    target_sha256 TEXT NOT NULL CHECK(length(target_sha256)=64 AND target_sha256 NOT GLOB '*[^0-9a-f]*'),
    payload_sha256 TEXT NOT NULL CHECK(length(payload_sha256)=64 AND payload_sha256 NOT GLOB '*[^0-9a-f]*'),
    invocation_id TEXT NOT NULL REFERENCES subs_bot_production_invocations(invocation_id),
    state TEXT NOT NULL CHECK(state IN ('processing','retryable','completed','uncertain')),
    received_at INTEGER NOT NULL DEFAULT(unixepoch()),
    http_status INTEGER,
    completed_at INTEGER,
    PRIMARY KEY(bot_id,update_id),
    CHECK((state='completed' AND http_status IN (200,204) AND completed_at IS NOT NULL)
        OR (state IN ('processing','retryable','uncertain') AND http_status IS NULL AND completed_at IS NULL))
) STRICT;

CREATE INDEX subs_bot_production_updates_state ON subs_bot_production_updates (state,received_at);

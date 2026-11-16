CREATE TABLE subs_bot_production_control (
    singleton INTEGER PRIMARY KEY NOT NULL CHECK(singleton=1),
    target_sha256 TEXT NOT NULL CHECK(length(target_sha256)=64 AND target_sha256 NOT GLOB '*[^0-9a-f]*'),
    bot_id TEXT NOT NULL,
    release_revision TEXT NOT NULL CHECK(length(release_revision)=40 AND release_revision NOT GLOB '*[^0-9a-f]*'),
    generation INTEGER NOT NULL CHECK(generation BETWEEN 1 AND 9007199254740991),
    epoch INTEGER NOT NULL CHECK(epoch BETWEEN 1 AND 9007199254740991),
    admission TEXT NOT NULL CHECK(admission IN ('closed','open')),
    workers TEXT NOT NULL CHECK(workers IN ('run','frozen')),
    CHECK(admission='closed' OR workers='run')
) STRICT;

CREATE TABLE subs_bot_production_invocations (
    invocation_id TEXT PRIMARY KEY NOT NULL CHECK(length(invocation_id)=32 AND invocation_id NOT GLOB '*[^0-9a-f]*'),
    target_sha256 TEXT NOT NULL,
    bot_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK(epoch BETWEEN 1 AND 9007199254740991),
    kind TEXT NOT NULL CHECK(kind IN ('webhook','scheduled')),
    started_at INTEGER NOT NULL DEFAULT(unixepoch()),
    lease_until INTEGER NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('running','finished','uncertain')),
    finished_at INTEGER,
    CHECK((state='running' AND finished_at IS NULL) OR (state<>'running' AND finished_at IS NOT NULL))
) STRICT;

CREATE INDEX subs_bot_production_invocations_state ON subs_bot_production_invocations (state,lease_until);

CREATE TABLE telegram_general_policy (
    bot_id TEXT PRIMARY KEY NOT NULL CHECK (bot_id GLOB '[1-9]*' AND bot_id NOT GLOB '*[^0-9]*' AND CAST(bot_id AS INTEGER)<4503599627370496),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    release_revision TEXT NOT NULL CHECK (length(CAST(release_revision AS BLOB))=40 AND release_revision NOT GLOB '*[^0-9a-f]*'),
    activation_sha256 TEXT NOT NULL CHECK (length(CAST(activation_sha256 AS BLOB))=64 AND activation_sha256 NOT GLOB '*[^0-9a-f]*'),
    cutover_at INTEGER NOT NULL CHECK (cutover_at BETWEEN 1 AND 9007199254740991),
    active INTEGER NOT NULL DEFAULT 0 CHECK (active IN (0,1))
) STRICT;

CREATE TABLE telegram_general_actors (
    bot_id TEXT NOT NULL REFERENCES telegram_general_policy(bot_id),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9007199254740991),
    actor_id TEXT NOT NULL CHECK (actor_id<>bot_id AND actor_id GLOB '[1-9]*' AND actor_id NOT GLOB '*[^0-9]*' AND CAST(actor_id AS INTEGER)<4503599627370496),
    revision INTEGER NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    effective_at INTEGER NOT NULL CHECK (effective_at BETWEEN 1 AND 9007199254740991),
    role TEXT NOT NULL CHECK (role IN ('admin','member','denied')),
    PRIMARY KEY (bot_id,generation,actor_id,revision)
) STRICT;

CREATE TABLE telegram_general_replies (
    receipt_id INTEGER PRIMARY KEY,
    bot_id TEXT NOT NULL,
    generation INTEGER NOT NULL,
    actor_id TEXT NOT NULL,
    actor_revision INTEGER NOT NULL,
    update_id INTEGER NOT NULL CHECK (update_id BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    command TEXT NOT NULL CHECK (command IN ('help','list')),
    received_at INTEGER NOT NULL DEFAULT (unixepoch()),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending','leased','sending','sent','failed','uncertain','discarded')),
    lease_id TEXT,
    lease_until INTEGER,
    UNIQUE (bot_id,update_id),
    FOREIGN KEY (bot_id,generation,actor_id,actor_revision) REFERENCES telegram_general_actors(bot_id,generation,actor_id,revision),
    CHECK ((state IN ('leased','sending') AND lease_id IS NOT NULL AND lease_until IS NOT NULL)
        OR (state NOT IN ('leased','sending') AND lease_id IS NULL AND lease_until IS NULL))
) STRICT;

CREATE INDEX telegram_general_reply_queue ON telegram_general_replies (bot_id,state,receipt_id);
CREATE INDEX telegram_general_reply_actor ON telegram_general_replies (bot_id,actor_id,receipt_id)
    WHERE state IN ('pending','leased','sending');

CREATE TABLE telegram_github_search (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    bot_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('looking', 'usage', 'limited', 'found', 'empty', 'unavailable', 'discarded')),
    auth_message_date INTEGER NOT NULL CHECK (auth_message_date BETWEEN 0 AND 9007199254740991),
    auth_message_id INTEGER NOT NULL CHECK (auth_message_id BETWEEN 0 AND 9007199254740991),
    started_at INTEGER,
    lookup_nonce TEXT,
    lookup_until INTEGER,
    public_results TEXT,
    CHECK ((auth_message_date = 0) = (auth_message_id = 0)),
    CHECK ((state = 'looking' AND started_at IS NOT NULL AND lookup_nonce IS NOT NULL AND lookup_until IS NOT NULL)
        OR (state <> 'looking' AND lookup_nonce IS NULL AND lookup_until IS NULL)),
    CHECK (public_results IS NULL OR (state = 'found' AND length(CAST(public_results AS BLOB)) BETWEEN 2 AND 1024))
) STRICT;

CREATE INDEX telegram_github_search_cooldown ON telegram_github_search (bot_id, actor_id, started_at);

CREATE INDEX telegram_github_search_expiring ON telegram_github_search (bot_id, lookup_until, receipt_id)
    WHERE state = 'looking';

CREATE INDEX telegram_github_search_recovery ON telegram_github_search (bot_id, lookup_nonce)
    WHERE state = 'looking';

CREATE INDEX telegram_github_search_payload ON telegram_github_search (bot_id, receipt_id)
    WHERE public_results IS NOT NULL;

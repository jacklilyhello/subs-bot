CREATE TABLE telegram_inbox (
    receipt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id TEXT NOT NULL,
    update_id INTEGER NOT NULL CHECK (update_id BETWEEN 1 AND 9007199254740991),
    actor_id TEXT NOT NULL,
    chat_id TEXT NOT NULL,
    chat_type TEXT NOT NULL CHECK (chat_type IN ('private', 'group', 'supergroup')),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    thread_id INTEGER CHECK (thread_id BETWEEN 1 AND 9007199254740991),
    command TEXT NOT NULL CHECK (command IN ('start', 'help', 'list', 'auth-list', 'auth-add', 'auth-remove', 'auth-usage')),
    received_at INTEGER NOT NULL DEFAULT (unixepoch()),
    receipt_nonce TEXT,
    UNIQUE (bot_id, update_id),
    CHECK (chat_type <> 'private' OR chat_id = actor_id)
) STRICT;

CREATE INDEX telegram_inbox_scope ON telegram_inbox (bot_id, actor_id, chat_id, receipt_id);

CREATE TABLE telegram_auth (
    bot_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    allowed INTEGER NOT NULL CHECK (allowed IN (0, 1)),
    message_date INTEGER NOT NULL CHECK (message_date BETWEEN 1 AND 9007199254740991),
    message_id INTEGER NOT NULL CHECK (message_id BETWEEN 1 AND 9007199254740991),
    PRIMARY KEY (bot_id, user_id)
) STRICT;

CREATE TABLE telegram_outbox (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'leased', 'sending', 'sent', 'failed', 'uncertain')),
    due_at INTEGER NOT NULL DEFAULT (unixepoch()),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 4),
    lease_id TEXT UNIQUE,
    lease_until INTEGER,
    sent_message_id INTEGER CHECK (sent_message_id BETWEEN 1 AND 9007199254740991),
    CHECK (
        (state IN ('leased', 'sending') AND lease_id IS NOT NULL AND lease_until IS NOT NULL)
        OR (state = 'uncertain' AND lease_id IS NOT NULL AND lease_until IS NULL)
        OR (state IN ('pending', 'sent', 'failed') AND lease_id IS NULL AND lease_until IS NULL)
    ),
    CHECK ((state = 'sent') = (sent_message_id IS NOT NULL))
) STRICT;

CREATE INDEX telegram_outbox_due ON telegram_outbox (state, due_at, receipt_id);
CREATE INDEX telegram_outbox_lease ON telegram_outbox (state, lease_until, receipt_id);

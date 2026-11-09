CREATE TABLE telegram_group_share_cards (
 receipt_id INTEGER PRIMARY KEY REFERENCES telegram_private_share_creations(receipt_id),
 group_id TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN('pending','sending','sent','failed','uncertain')),
 due_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 4),
 message_id INTEGER,
 lease_id TEXT,
 lease_until INTEGER,
 shown INTEGER NOT NULL DEFAULT 0 CHECK(shown BETWEEN 0 AND 101),
 CHECK((state='sent')=(message_id IS NOT NULL)),
 CHECK((lease_id IS NULL)=(lease_until IS NULL)),
 UNIQUE(group_id,message_id)
) STRICT;
CREATE INDEX telegram_group_share_due ON telegram_group_share_cards (state,due_at,receipt_id);
CREATE TABLE telegram_group_share_scopes (
 receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox(receipt_id),
 card_id INTEGER NOT NULL REFERENCES telegram_group_share_cards(receipt_id),
 auth_date INTEGER NOT NULL,
 auth_id INTEGER NOT NULL,
 picked_at INTEGER NOT NULL
) STRICT;

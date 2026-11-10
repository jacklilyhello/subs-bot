CREATE TABLE telegram_general_receipt (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox(receipt_id),
    generation INTEGER NOT NULL CHECK (generation>0),
    actor_revision INTEGER NOT NULL CHECK (actor_revision>0),
    actor_role TEXT NOT NULL CHECK (actor_role IN ('admin','member')),
    release_revision TEXT NOT NULL CHECK (length(release_revision)=40 AND release_revision NOT GLOB '*[^0-9a-f]*'),
    activation_sha256 TEXT NOT NULL CHECK (length(activation_sha256)=64 AND activation_sha256 NOT GLOB '*[^0-9a-f]*'),
    cutover_at INTEGER NOT NULL CHECK (cutover_at>0)
) STRICT;

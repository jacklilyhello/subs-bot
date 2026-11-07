CREATE TABLE telegram_provider_replies (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_provider_requests (receipt_id),
    outcome TEXT NOT NULL CHECK (outcome IN (
        'invalid-url', 'unavailable', 'conflict', 'capacity', 'saved', 'coalesced', 'stale-target',
        'expired', 'attempts-exhausted', 'invalid-document', 'fetch-rejected', 'storage-failed'
    )),
    ready_at INTEGER NOT NULL CHECK (ready_at BETWEEN 1 AND 9007199254740991)
) STRICT;

CREATE INDEX telegram_provider_replies_ready ON telegram_provider_replies (ready_at, receipt_id);

CREATE INDEX telegram_provider_inbox_reconcile ON telegram_inbox (bot_id, received_at, receipt_id)
    WHERE receipt_nonce = 'provider-request:v1';

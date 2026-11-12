CREATE TABLE telegram_general_subscription_anchor (
    receipt_id INTEGER NOT NULL REFERENCES telegram_general_receipt (receipt_id),
    subscription_id INTEGER NOT NULL CHECK (subscription_id BETWEEN 1 AND 9007199254740991),
    kind TEXT NOT NULL CHECK (kind IN ('view', 'number')),
    lifecycle_revision INTEGER NOT NULL CHECK (lifecycle_revision BETWEEN 0 AND 9007199254740991),
    PRIMARY KEY (receipt_id, subscription_id)
) STRICT;

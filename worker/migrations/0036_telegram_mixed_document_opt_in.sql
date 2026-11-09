CREATE TABLE telegram_mixed_document_opt_in (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_provider_document_opt_in (receipt_id) ON DELETE CASCADE
) STRICT;

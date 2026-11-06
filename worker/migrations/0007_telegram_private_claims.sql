CREATE TABLE telegram_private_claim (
    receipt_id INTEGER PRIMARY KEY REFERENCES telegram_inbox (receipt_id),
    code_sha256 TEXT NOT NULL CHECK (
        length(code_sha256) = 64 AND length(CAST(code_sha256 AS BLOB)) = 64
        AND code_sha256 NOT GLOB '*[^0-9a-f]*'
    )
) STRICT;

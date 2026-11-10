CREATE TABLE telegram_page_jump_controls (
    bot_id TEXT PRIMARY KEY NOT NULL CHECK (
        length(bot_id) BETWEEN 1 AND 16
        AND length(CAST(bot_id AS BLOB)) = length(bot_id)
        AND bot_id NOT GLOB '*[^0-9]*'
        AND substr(bot_id, 1, 1) <> '0'
        AND (length(bot_id) < 16 OR bot_id <= '9007199254740991')
    ),
    epoch INTEGER NOT NULL CHECK (epoch BETWEEN 1 AND 9007199254740991),
    enabled INTEGER NOT NULL CHECK (enabled IN (0,1)),
    origin_after_receipt INTEGER NOT NULL CHECK (origin_after_receipt BETWEEN 0 AND 9007199254740991)
) STRICT;

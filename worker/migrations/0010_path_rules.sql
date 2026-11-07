CREATE TABLE path_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT CHECK (id BETWEEN 1 AND 9007199254740991),
    owner_id TEXT NOT NULL CHECK (
        length(owner_id) BETWEEN 1 AND 19 AND length(CAST(owner_id AS BLOB)) = length(owner_id)
        AND owner_id NOT GLOB '*[^0-9]*' AND substr(owner_id, 1, 1) <> '0'
        AND (length(owner_id) < 19 OR owner_id <= '9223372036854775807')
    ),
    keyword TEXT NOT NULL CHECK (
        length(keyword) BETWEEN 1 AND 128 AND length(CAST(keyword AS BLOB)) BETWEEN 1 AND 512
        AND instr(keyword, char(0)) = 0
    ),
    remark TEXT NOT NULL CHECK (
        length(remark) BETWEEN 1 AND 128 AND length(CAST(remark AS BLOB)) BETWEEN 1 AND 512
        AND instr(remark, char(0)) = 0
    ),
    UNIQUE (owner_id, keyword)
) STRICT;

CREATE INDEX path_rules_owner_order ON path_rules (owner_id, id);

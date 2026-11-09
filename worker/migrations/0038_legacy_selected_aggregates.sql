CREATE TABLE legacy_selected_aggregates (code_sha256 TEXT PRIMARY KEY REFERENCES aggregate_links(code_sha256)) STRICT;
CREATE TABLE legacy_selected_members (id INTEGER PRIMARY KEY CHECK(id>0),retired INTEGER NOT NULL CHECK(retired IN(0,1))) STRICT;
